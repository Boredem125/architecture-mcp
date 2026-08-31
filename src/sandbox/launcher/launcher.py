"""AppLauncher — launches real CLI apps inside a jailed sandbox.

Resolves the app command via the registry, prepares the jail directory,
injects shim PATH, applies Win32 Job Object limits, starts the process,
and streams stdout/stderr to the EventBroadcaster while recording to logs.
"""
from __future__ import annotations

import asyncio
import os
import platform
import sys
import time
import uuid
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any

import structlog

from sandbox.config import LauncherSettings
from sandbox.executor.isolation import IsolationProfile, SubprocessIsolator
from sandbox.launcher.jail import JailManager, JailMode
from sandbox.launcher.recorder import SessionRecorder
from sandbox.launcher.registry import AppRegistry

logger = structlog.get_logger(__name__)


class RunState(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    STOPPED = "stopped"
    FAILED = "failed"


def _resume_process_threads(pid: int) -> int:
    """Resume every thread of *pid* (Windows).

    The process is created with ``CREATE_SUSPENDED`` so it can be assigned to
    the Job Object before it runs. ``OpenThread`` takes a *thread* id, not a
    *process* id, so we enumerate the process's threads via a Toolhelp
    snapshot and resume each one. Returns the number of threads resumed.
    """
    if sys.platform != "win32":
        return 0

    import ctypes
    from ctypes import wintypes

    TH32CS_SNAPTHREAD = 0x00000004
    THREAD_SUSPEND_RESUME = 0x0002
    INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

    class THREADENTRY32(ctypes.Structure):
        _fields_ = [
            ("dwSize", wintypes.DWORD),
            ("cntUsage", wintypes.DWORD),
            ("th32ThreadID", wintypes.DWORD),
            ("th32OwnerProcessID", wintypes.DWORD),
            ("tpBasePri", wintypes.LONG),
            ("tpDeltaPri", wintypes.LONG),
            ("dwFlags", wintypes.DWORD),
        ]

    kernel32 = ctypes.windll.kernel32
    snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
    if snapshot == INVALID_HANDLE_VALUE:
        return 0

    resumed = 0
    try:
        entry = THREADENTRY32()
        entry.dwSize = ctypes.sizeof(THREADENTRY32)
        if not kernel32.Thread32First(snapshot, ctypes.byref(entry)):
            return 0
        while True:
            if entry.th32OwnerProcessID == pid:
                h_thread = kernel32.OpenThread(
                    THREAD_SUSPEND_RESUME, False, entry.th32ThreadID
                )
                if h_thread:
                    kernel32.ResumeThread(h_thread)
                    kernel32.CloseHandle(h_thread)
                    resumed += 1
            if not kernel32.Thread32Next(snapshot, ctypes.byref(entry)):
                break
    finally:
        kernel32.CloseHandle(snapshot)
    return resumed


@dataclass
class LaunchRun:
    run_id: str
    session_id: str
    agent_id: str
    app_type: str
    jail_dir: Path
    jail_mode: JailMode
    state: RunState = RunState.PENDING
    pid: int | None = None
    exit_code: int | None = None
    started_at: float = 0.0
    stopped_at: float = 0.0
    fallback: bool = False
    fallback_reason: str = ""
    _process: asyncio.subprocess.Process | None = field(
        default=None, repr=False
    )
    _job_handle: Any = field(default=None, repr=False)
    _recorder: Any = field(default=None, repr=False)

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "session_id": self.session_id,
            "agent_id": self.agent_id,
            "app_type": self.app_type,
            "jail_dir": str(self.jail_dir),
            "jail_mode": self.jail_mode,
            "state": self.state,
            "pid": self.pid,
            "exit_code": self.exit_code,
            "started_at": self.started_at,
            "stopped_at": self.stopped_at,
            "fallback": self.fallback,
            "fallback_reason": self.fallback_reason,
        }


class AppLauncher:
    """Launches real CLI apps inside a filesystem jail with resource limits."""

    def __init__(
        self,
        settings: LauncherSettings,
        broadcaster: Any = None,
        recorder: Any = None,
    ) -> None:
        self._settings = settings
        self._registry = AppRegistry(overrides=settings.app_commands)
        self._jail = JailManager(
            jail_root=settings.jail_root,
            jail_user=settings.jail_user,
            enforce=settings.enforce_jail,
        )
        self._broadcaster = broadcaster
        self._recorder = recorder
        self._runs: dict[str, LaunchRun] = {}
        self._stream_tasks: dict[str, asyncio.Task] = {}

    @property
    def jail_manager(self) -> JailManager:
        return self._jail

    @property
    def registry(self) -> AppRegistry:
        return self._registry

    async def launch(
        self,
        app_type: str,
        session_id: str,
        agent_id: str,
        extra_args: list[str] | None = None,
        env_overrides: dict[str, str] | None = None,
        task_description: str = "",
    ) -> LaunchRun:
        """Launch a CLI app inside a jail with resource limits.

        If the chosen CLI isn't installed on this host, fall back to a real
        jailed demo agent (a Python process) so the sandbox — jailed launch,
        live streaming, broker, change recording — is still demonstrable
        end-to-end without any API keys or external installs.
        """
        entry = self._registry.resolve(app_type)

        exe_path = self._registry.find_executable(app_type)
        fallback = False
        fallback_reason = ""
        if exe_path is None:
            fallback = True
            fallback_reason = (
                f"{entry.display_name} CLI ({entry.executable!r}) is not "
                f"installed on this host — running a jailed demo agent instead."
            )
            logger.info(
                "launcher.fallback",
                app_type=app_type,
                executable=entry.executable,
            )

        run_id = uuid.uuid4().hex[:16]
        jail_dir = self._jail.create_jail(session_id)

        run = LaunchRun(
            run_id=run_id,
            session_id=session_id,
            agent_id=agent_id,
            app_type=app_type,
            jail_dir=jail_dir,
            jail_mode=self._jail.mode,
            fallback=fallback,
            fallback_reason=fallback_reason,
        )
        # Per-run recorder: logs.txt + modified.txt + .trash/ live in this jail.
        run._recorder = self._recorder or SessionRecorder(jail_dir)
        self._runs[run_id] = run

        profile = IsolationProfile(
            max_memory_mb=self._settings.max_memory_mb,
            max_pids=self._settings.max_pids,
            timeout_seconds=self._settings.default_timeout,
        )
        isolator = SubprocessIsolator(profile)

        env = isolator.sanitize_environment()

        shim_dir = Path(self._settings.shim_dir).resolve()
        if shim_dir.exists():
            env["PATH"] = f"{shim_dir}{os.pathsep}{env.get('PATH', '')}"

        if env_overrides:
            env.update(env_overrides)

        env["SANDBOX_SESSION_ID"] = session_id
        env["SANDBOX_RUN_ID"] = run_id
        env["SANDBOX_JAIL_DIR"] = str(jail_dir)
        env["SANDBOX_BROKER_URL"] = "http://localhost:8000/api/v1/broker"
        env["SANDBOX_APP_TYPE"] = app_type
        env["SANDBOX_APP_DISPLAY"] = entry.display_name
        env["SANDBOX_TASK"] = task_description

        if fallback:
            demo_agent = Path(__file__).with_name("demo_agent.py")
            cmd = [sys.executable, str(demo_agent)]
        else:
            cmd = [exe_path] + entry.default_args + (extra_args or [])

        creation_flags = 0
        if sys.platform == "win32":
            from sandbox.executor.isolation import CREATE_SUSPENDED
            creation_flags = CREATE_SUSPENDED

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                stdin=asyncio.subprocess.DEVNULL,
                cwd=str(jail_dir),
                env=env,
                creationflags=creation_flags,
            )
        except OSError as e:
            run.state = RunState.FAILED
            logger.error("launcher.start_failed", run_id=run_id, error=str(e))
            raise

        run._process = proc
        run.pid = proc.pid
        run.started_at = time.time()

        if sys.platform == "win32":
            job = isolator.create_job_object()
            if job is not None:
                try:
                    import ctypes
                    h_process = ctypes.windll.kernel32.OpenProcess(
                        0x1F0FFF, False, proc.pid
                    )
                    if h_process:
                        isolator.assign_to_job(job, h_process)
                        ctypes.windll.kernel32.CloseHandle(h_process)
                    run._job_handle = job
                except OSError:
                    logger.warning("launcher.job_assign_failed", run_id=run_id)

            resumed = _resume_process_threads(proc.pid)
            if resumed == 0:
                logger.warning("launcher.resume_failed", run_id=run_id, pid=proc.pid)

        run.state = RunState.RUNNING

        await self._emit_event("launch_started", run)

        if run._recorder:
            run._recorder.log_action(
                session_id=session_id,
                agent_id=agent_id,
                action="launch_started",
                details={
                    "run_id": run_id,
                    "app_type": app_type,
                    "cmd": " ".join(cmd),
                    "jail_mode": self._jail.mode,
                    "fallback": fallback,
                    "task": task_description,
                },
            )

        task = asyncio.create_task(self._stream_output(run))
        self._stream_tasks[run_id] = task

        logger.info(
            "launcher.started",
            run_id=run_id,
            app_type=app_type,
            pid=proc.pid,
            jail_mode=self._jail.mode,
        )
        return run

    async def stop(self, run_id: str) -> LaunchRun:
        """Stop a running app."""
        run = self._runs.get(run_id)
        if run is None:
            raise KeyError(f"Run {run_id} not found")

        if run.state != RunState.RUNNING or run._process is None:
            return run

        try:
            run._process.terminate()
            try:
                await asyncio.wait_for(run._process.wait(), timeout=5.0)
            except asyncio.TimeoutError:
                run._process.kill()
                await run._process.wait()
        except ProcessLookupError:
            pass

        run.exit_code = run._process.returncode
        run.stopped_at = time.time()
        run.state = RunState.STOPPED

        if run._job_handle is not None and sys.platform == "win32":
            import ctypes
            ctypes.windll.kernel32.CloseHandle(run._job_handle)
            run._job_handle = None

        task = self._stream_tasks.pop(run_id, None)
        if task and not task.done():
            task.cancel()

        await self._emit_event("launch_exited", run)

        if run._recorder:
            run._recorder.scan_changes()
            run._recorder.log_action(
                session_id=run.session_id,
                agent_id=run.agent_id,
                action="launch_stopped",
                details={
                    "run_id": run_id,
                    "exit_code": run.exit_code,
                    "duration_s": round(run.stopped_at - run.started_at, 2),
                },
            )

        logger.info(
            "launcher.stopped",
            run_id=run_id,
            exit_code=run.exit_code,
        )
        return run

    def get_run(self, run_id: str) -> LaunchRun | None:
        return self._runs.get(run_id)

    def list_runs(self) -> list[LaunchRun]:
        return list(self._runs.values())

    async def _stream_output(self, run: LaunchRun) -> None:
        """Read stdout/stderr and broadcast + record each line."""
        proc = run._process
        if proc is None:
            return

        async def _read_stream(stream: asyncio.StreamReader, name: str) -> None:
            while True:
                line = await stream.readline()
                if not line:
                    break
                text = line.decode("utf-8", errors="replace").rstrip("\n\r")
                await self._emit_output(run, name, text)

        tasks = []
        if proc.stdout:
            tasks.append(_read_stream(proc.stdout, "stdout"))
        if proc.stderr:
            tasks.append(_read_stream(proc.stderr, "stderr"))

        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

        await proc.wait()

        if run.state == RunState.RUNNING:
            run.exit_code = proc.returncode
            run.stopped_at = time.time()
            run.state = RunState.STOPPED

            if run._job_handle is not None and sys.platform == "win32":
                import ctypes
                ctypes.windll.kernel32.CloseHandle(run._job_handle)
                run._job_handle = None

            await self._emit_event("launch_exited", run)

            if run._recorder:
                run._recorder.scan_changes()
                run._recorder.log_action(
                    session_id=run.session_id,
                    agent_id=run.agent_id,
                    action="launch_exited",
                    details={
                        "run_id": run.run_id,
                        "exit_code": run.exit_code,
                        "duration_s": round(
                            run.stopped_at - run.started_at, 2
                        ),
                    },
                )

    async def _emit_output(
        self, run: LaunchRun, stream: str, text: str
    ) -> None:
        """Broadcast a single output line and record it."""
        if self._broadcaster:
            await self._broadcaster.broadcast({
                "event": "launch_output",
                "run_id": run.run_id,
                "session_id": run.session_id,
                "agent_id": run.agent_id,
                "stream": stream,
                "line": text,
            })

        if run._recorder:
            run._recorder.log_output(
                session_id=run.session_id,
                run_id=run.run_id,
                stream=stream,
                line=text,
            )

    async def _emit_event(self, event: str, run: LaunchRun) -> None:
        if self._broadcaster:
            await self._broadcaster.broadcast({
                "event": event,
                "run_id": run.run_id,
                "session_id": run.session_id,
                "agent_id": run.agent_id,
                "app_type": run.app_type,
                "pid": run.pid,
                "exit_code": run.exit_code,
                "jail_mode": run.jail_mode,
                "fallback": run.fallback,
                "fallback_reason": run.fallback_reason,
            })
