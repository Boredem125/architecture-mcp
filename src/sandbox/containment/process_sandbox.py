"""Process-based containment sandbox using Win32 Job Objects / Linux rlimits.

No Docker or external tools required — uses OS-native isolation primitives
already implemented in isolation.py:

  Windows: Win32 Job Objects (memory cap, CPU rate, PID limit, kill-on-close)
  Linux:   setrlimit (CPU time, address space, open FDs, child processes)

Filesystem isolation is workspace-jailed (path validation, not a mount
namespace), so this is weaker than Docker for filesystem/network isolation
but provides real resource containment with zero installs.

Implements the same interface as DockerSandbox so the rest of the system
(SandboxedToolkit, AgentRuntime, E2B API) can use either interchangeably.
"""
from __future__ import annotations

import asyncio
import ctypes
import io
import os
import platform
import subprocess
import sys
import time
from typing import Any

import structlog

from sandbox.config import ContainmentSettings, ExecutorSettings
from sandbox.containment.docker_sandbox import ContainerState, ExecResult, FileInfo
from sandbox.executor.isolation import IsolationProfile, SubprocessIsolator

logger = structlog.get_logger()

_MAX_OUTPUT_BYTES = 100_000


class ProcessSandbox:
    """One isolated process group per agent session — OS-native containment.

    On Windows, every command runs inside a Win32 Job Object with:
      - Memory cap (JobMemoryLimit / ProcessMemoryLimit)
      - CPU rate control (hard cap proportional to allowed cores)
      - Active process limit (PID cap)
      - KILL_ON_JOB_CLOSE (all children die when the sandbox is destroyed)

    On Linux, commands run with setrlimit constraints (CPU, memory, FDs, PIDs).
    """

    def __init__(
        self,
        session_id: str,
        containment_settings: ContainmentSettings,
        executor_settings: ExecutorSettings,
        workspace_host_path: str | None = None,
        capabilities: list[str] | None = None,
    ) -> None:
        self._session_id = session_id
        self._settings = containment_settings
        self._executor = executor_settings
        self._capabilities = set(capabilities or [])
        self._state = ContainerState.CREATING
        self._created_at: float | None = None

        if workspace_host_path:
            self._workspace = os.path.abspath(workspace_host_path)
        else:
            ws_root = os.path.abspath(containment_settings.workspace_mount_root)
            self._workspace = os.path.join(ws_root, session_id)

        self._profile = IsolationProfile(
            max_cpu_cores=executor_settings.max_cpu_cores,
            max_memory_mb=executor_settings.max_memory_mb,
            max_pids=executor_settings.max_pids,
            timeout_seconds=executor_settings.execute_timeout_seconds,
            network_allowed="NETWORK" in self._capabilities,
        )
        self._isolator = SubprocessIsolator(self._profile)

        self._job_handle: Any = None
        self._platform = platform.system()

    @property
    def container_id(self) -> str | None:
        if self._job_handle is not None:
            return f"job-{self._session_id[:12]}"
        return f"proc-{self._session_id[:12]}"

    @property
    def state(self) -> ContainerState:
        return self._state

    @property
    def session_id(self) -> str:
        return self._session_id

    async def create(self) -> str:
        """Initialize the process sandbox — create workspace and Job Object."""
        os.makedirs(self._workspace, exist_ok=True)

        if self._platform == "Windows" and sys.platform == "win32":
            self._job_handle = self._isolator.create_job_object()
            if self._job_handle:
                logger.info(
                    "job_object_created",
                    session_id=self._session_id,
                    mem_limit_mb=self._executor.max_memory_mb,
                    max_pids=self._executor.max_pids,
                    cpu_cores=self._executor.max_cpu_cores,
                )

        self._state = ContainerState.RUNNING
        self._created_at = time.time()

        cid = self.container_id or f"proc-{self._session_id[:12]}"
        logger.info(
            "process_sandbox_created",
            container_id=cid,
            session_id=self._session_id,
            workspace=self._workspace,
            platform=self._platform,
        )
        return cid

    def _validate_path(self, path: str) -> tuple[bool, str]:
        """Ensure path is within workspace root."""
        from sandbox.fs.containment import resolve_under

        resolved = resolve_under(self._workspace, path)
        if resolved is None:
            return False, f"Path traversal blocked: {path}"
        return True, str(resolved)

    async def exec(
        self,
        command: str,
        timeout: int | None = None,
        workdir: str | None = None,
    ) -> ExecResult:
        """Execute a command with Job Object containment."""
        if self._state != ContainerState.RUNNING:
            return ExecResult(exit_code=-1, stdout="", stderr="Sandbox not running")

        effective_timeout = timeout or self._executor.execute_timeout_seconds
        cwd = workdir or self._workspace

        env = self._isolator.sanitize_environment()
        env["SANDBOX_SESSION_ID"] = self._session_id

        try:
            if self._platform == "Windows" and sys.platform == "win32":
                return await self._exec_windows(command, cwd, env, effective_timeout)
            else:
                return await self._exec_posix(command, cwd, env, effective_timeout)
        except Exception as e:
            logger.error("process_exec_error", error=str(e), session_id=self._session_id)
            return ExecResult(exit_code=-1, stdout="", stderr=str(e))

    async def _exec_windows(
        self, command: str, cwd: str, env: dict[str, str], timeout: int
    ) -> ExecResult:
        """Run command in a Win32 Job Object with resource limits."""
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        startupinfo.wShowWindow = 0  # SW_HIDE

        proc = await asyncio.create_subprocess_shell(
            command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            stdin=subprocess.DEVNULL,
            cwd=cwd,
            env=env,
            startupinfo=startupinfo,
        )

        # Assign to Job Object for resource limits
        if self._job_handle is not None and proc.pid:
            try:
                kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
                PROCESS_ALL_ACCESS = 0x1F0FFF
                h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, proc.pid)
                if h_process:
                    self._isolator.assign_to_job(self._job_handle, h_process)
                    kernel32.CloseHandle(h_process)
            except Exception as e:
                logger.warning("job_assign_failed", error=str(e), pid=proc.pid)

        timed_out = False
        try:
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                proc.communicate(), timeout=timeout
            )
        except asyncio.TimeoutError:
            proc.kill()
            timed_out = True
            stdout_bytes, stderr_bytes = b"", b""

        stdout = (stdout_bytes or b"").decode("utf-8", errors="replace")[:_MAX_OUTPUT_BYTES]
        stderr = (stderr_bytes or b"").decode("utf-8", errors="replace")[:_MAX_OUTPUT_BYTES]

        return ExecResult(
            exit_code=proc.returncode or -1 if timed_out else (proc.returncode or 0),
            stdout=stdout,
            stderr=stderr,
            timed_out=timed_out,
        )

    async def _exec_posix(
        self, command: str, cwd: str, env: dict[str, str], timeout: int
    ) -> ExecResult:
        """Run command with rlimit containment on Linux/macOS."""
        from sandbox.executor.isolation import _linux_preexec

        profile = self._profile

        proc = await asyncio.create_subprocess_shell(
            command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            stdin=subprocess.DEVNULL,
            cwd=cwd,
            env=env,
            preexec_fn=lambda: _linux_preexec(profile),
        )

        timed_out = False
        try:
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                proc.communicate(), timeout=timeout
            )
        except asyncio.TimeoutError:
            proc.kill()
            timed_out = True
            stdout_bytes, stderr_bytes = b"", b""

        stdout = (stdout_bytes or b"").decode("utf-8", errors="replace")[:_MAX_OUTPUT_BYTES]
        stderr = (stderr_bytes or b"").decode("utf-8", errors="replace")[:_MAX_OUTPUT_BYTES]

        return ExecResult(
            exit_code=proc.returncode or -1 if timed_out else (proc.returncode or 0),
            stdout=stdout,
            stderr=stderr,
            timed_out=timed_out,
        )

    async def write_file(self, path: str, content: bytes) -> bool:
        """Write a file into the workspace."""
        valid, resolved = self._validate_path(path)
        if not valid:
            logger.warning("write_blocked", reason=resolved, session_id=self._session_id)
            return False

        try:
            os.makedirs(os.path.dirname(resolved), exist_ok=True)
            with open(resolved, "wb") as f:
                f.write(content)
            return True
        except Exception as e:
            logger.error("write_error", error=str(e), path=resolved)
            return False

    async def read_file(self, path: str) -> bytes | None:
        """Read a file from the workspace."""
        valid, resolved = self._validate_path(path)
        if not valid:
            return None

        try:
            with open(resolved, "rb") as f:
                return f.read()
        except FileNotFoundError:
            return None
        except Exception as e:
            logger.error("read_error", error=str(e), path=resolved)
            return None

    async def list_dir(self, path: str) -> list[FileInfo]:
        """List directory contents in the workspace."""
        valid, resolved = self._validate_path(path)
        if not valid:
            return []

        entries: list[FileInfo] = []
        try:
            if not os.path.isdir(resolved):
                return entries
            for entry in os.scandir(resolved):
                entries.append(FileInfo(
                    name=entry.name,
                    type="dir" if entry.is_dir() else "file",
                    size=entry.stat().st_size if entry.is_file() else 0,
                ))
                if len(entries) >= 500:
                    break
        except Exception as e:
            logger.error("list_error", error=str(e), path=resolved)

        return entries

    async def pause(self) -> bool:
        self._state = ContainerState.PAUSED
        return True

    async def resume(self) -> bool:
        self._state = ContainerState.RUNNING
        return True

    async def destroy(self) -> bool:
        """Clean up the Job Object handle."""
        if self._job_handle is not None and sys.platform == "win32":
            try:
                kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
                kernel32.CloseHandle(self._job_handle)
            except Exception:
                pass
            self._job_handle = None

        self._state = ContainerState.DESTROYED
        logger.info(
            "process_sandbox_destroyed",
            session_id=self._session_id,
        )
        return True

    def status(self) -> dict[str, Any]:
        return {
            "session_id": self._session_id,
            "state": self._state.value,
            "container_id": self.container_id,
            "containment_type": "job-object" if self._job_handle else "rlimit",
            "workspace": self._workspace,
            "created_at": self._created_at,
            "mem_limit_mb": self._executor.max_memory_mb,
            "max_pids": self._executor.max_pids,
            "cpu_cores": self._executor.max_cpu_cores,
        }
