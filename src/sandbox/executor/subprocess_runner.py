"""Isolated subprocess execution per AGENT_09 spec.

Each execution launches a fresh, resource-limited subprocess, captures its
output, and returns a structured ``ExecutionOutput``.  Subprocesses are
**never reused** — every call to ``execute`` or ``execute_rollback`` gets
its own process.
"""

from __future__ import annotations

import asyncio
import json
import sys
import time
from typing import Any

from sandbox.executor.isolation import SubprocessIsolator
from sandbox.models.enums import ExecutionResult
from sandbox.models.messages import ExecutionOutput, SignedCommand


# Grace period between SIGTERM-equivalent and hard kill, in seconds.
_KILL_GRACE_SECONDS = 5


class SubprocessRunner:
    """Run signed commands in isolated subprocesses.

    The runner delegates all isolation setup (resource limits, environment
    sanitisation, Job Object creation) to the provided
    :class:`SubprocessIsolator` and focuses on process lifecycle:

    * Start a subprocess (one per call — never reused).
    * Capture stdout / stderr.
    * Enforce the timeout (terminate → grace period → kill).
    * Collect resource usage.
    * Map exit status to :class:`ExecutionResult`.
    """

    def __init__(self, isolator: SubprocessIsolator) -> None:
        self._isolator = isolator

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def execute(self, command: SignedCommand) -> ExecutionOutput:
        """Execute *command* in an isolated subprocess.

        Returns an :class:`ExecutionOutput` populated with stdout, stderr,
        exit code, result status, duration, and (where available) peak
        memory usage.
        """
        cmd_parts = self._isolator.build_command(
            str(command.action_type), command.parameters
        )
        timeout = command.timeout_ms / 1000.0

        return await self._run(
            cmd_parts,
            timeout=timeout,
            request_id=command.request_id,
        )

    async def execute_rollback(
        self, command: str, parameters: dict[str, Any]
    ) -> ExecutionOutput:
        """Execute a rollback command in a separate isolated subprocess.

        Rollback commands bypass the normal signing path but still run
        inside the isolation profile.  The ``ROLLBACK`` capability is
        implied.
        """
        cmd_parts = self._isolator.build_command(command, parameters)
        timeout = float(self._isolator.profile.timeout_seconds)

        return await self._run(
            cmd_parts,
            timeout=timeout,
            request_id=parameters.get("request_id", "rollback"),
        )

    # ------------------------------------------------------------------
    # Internal execution
    # ------------------------------------------------------------------

    async def _run(
        self,
        cmd_parts: list[str],
        *,
        timeout: float,
        request_id: str,
    ) -> ExecutionOutput:
        """Low-level subprocess lifecycle.

        1. Create the subprocess with isolation kwargs.
        2. If on Windows, attach it to a Job Object and resume.
        3. Wait for completion with the configured timeout.
        4. On timeout: terminate → grace period → kill.
        5. Collect and return results.
        """
        kwargs = self._isolator.get_subprocess_kwargs()
        job_handle = None
        start = time.monotonic()

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd_parts, **kwargs
            )

            # On Windows, assign to Job Object and resume the suspended
            # process.
            if sys.platform == "win32":
                job_handle = self._isolator.create_job_object()
                if job_handle is not None and proc.pid is not None:
                    try:
                        import ctypes

                        PROCESS_ALL_ACCESS = 0x001FFFFF
                        h_process = ctypes.windll.kernel32.OpenProcess(
                            PROCESS_ALL_ACCESS, False, proc.pid
                        )
                        if h_process:
                            self._isolator.assign_to_job(
                                job_handle, h_process
                            )
                            # Resume the main thread.
                            _resume_process(proc.pid)
                            ctypes.windll.kernel32.CloseHandle(h_process)
                    except OSError:
                        # If Job Object assignment fails, still let the
                        # process run — isolation is best-effort on Windows
                        # when running without elevated privileges.
                        _resume_process(proc.pid)
                else:
                    # No job object — just resume.
                    if proc.pid is not None:
                        _resume_process(proc.pid)

            stdout, stderr, timed_out = await self._communicate(
                proc, timeout
            )
            elapsed_ms = int((time.monotonic() - start) * 1000)

            if timed_out:
                return ExecutionOutput(
                    request_id=request_id,
                    stdout=stdout,
                    stderr=stderr,
                    exit_code=-1,
                    result=ExecutionResult.TIMEOUT,
                    duration_ms=elapsed_ms,
                    resource_usage={"timeout": True},
                )

            exit_code = proc.returncode if proc.returncode is not None else -1
            result = (
                ExecutionResult.SUCCESS
                if exit_code == 0
                else ExecutionResult.FAILURE
            )

            resource_usage = self._collect_resource_usage(
                elapsed_ms, job_handle
            )

            return ExecutionOutput(
                request_id=request_id,
                stdout=stdout,
                stderr=stderr,
                exit_code=exit_code,
                result=result,
                duration_ms=elapsed_ms,
                resource_usage=resource_usage,
            )

        except Exception as exc:
            elapsed_ms = int((time.monotonic() - start) * 1000)
            return ExecutionOutput(
                request_id=request_id,
                stdout="",
                stderr=f"{type(exc).__name__}: {exc}",
                exit_code=-1,
                result=ExecutionResult.FAILURE,
                duration_ms=elapsed_ms,
                resource_usage={"exception": True},
            )
        finally:
            if job_handle is not None and sys.platform == "win32":
                import ctypes

                ctypes.windll.kernel32.CloseHandle(job_handle)

    # ------------------------------------------------------------------
    # Timeout-aware communicate
    # ------------------------------------------------------------------

    async def _communicate(
        self,
        proc: asyncio.subprocess.Process,
        timeout: float,
    ) -> tuple[str, str, bool]:
        """Read stdout/stderr with timeout enforcement.

        Returns ``(stdout, stderr, timed_out)``.  On timeout the process
        is terminated, given a grace period, and then killed if it has not
        exited.
        """
        try:
            raw_stdout, raw_stderr = await asyncio.wait_for(
                proc.communicate(), timeout=timeout
            )
            stdout = (raw_stdout or b"").decode("utf-8", errors="replace")
            stderr = (raw_stderr or b"").decode("utf-8", errors="replace")
            return stdout, stderr, False

        except asyncio.TimeoutError:
            # Graceful termination attempt.
            await self._terminate_process(proc)
            # Drain whatever output we can.
            stdout = ""
            stderr = ""
            try:
                raw_stdout, raw_stderr = await asyncio.wait_for(
                    proc.communicate(), timeout=_KILL_GRACE_SECONDS
                )
                stdout = (raw_stdout or b"").decode(
                    "utf-8", errors="replace"
                )
                stderr = (raw_stderr or b"").decode(
                    "utf-8", errors="replace"
                )
            except asyncio.TimeoutError:
                # Hard kill.
                await self._kill_process(proc)
            return stdout, stderr, True

    # ------------------------------------------------------------------
    # Process termination helpers
    # ------------------------------------------------------------------

    @staticmethod
    async def _terminate_process(proc: asyncio.subprocess.Process) -> None:
        """Send SIGTERM (Unix) or TerminateProcess (Windows)."""
        try:
            proc.terminate()
        except ProcessLookupError:
            pass

    @staticmethod
    async def _kill_process(proc: asyncio.subprocess.Process) -> None:
        """Send SIGKILL (Unix) or TerminateProcess (Windows)."""
        try:
            proc.kill()
        except ProcessLookupError:
            pass

    # ------------------------------------------------------------------
    # Resource usage collection
    # ------------------------------------------------------------------

    @staticmethod
    def _collect_resource_usage(
        elapsed_ms: int, job_handle: Any = None
    ) -> dict[str, Any]:
        """Best-effort resource usage collection.

        On Windows with a valid Job Object handle, queries peak memory.
        On Linux the caller would use ``/proc`` or ``resource.getrusage``
        (not yet implemented here — left as future work).
        """
        usage: dict[str, Any] = {"duration_ms": elapsed_ms}

        if job_handle is not None and sys.platform == "win32":
            try:
                import ctypes
                import ctypes.wintypes as wintypes

                from sandbox.executor.isolation import (
                    JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
                    JobObjectExtendedLimitInformation,
                )

                info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
                ret_len = wintypes.DWORD(0)
                ok = ctypes.windll.kernel32.QueryInformationJobObject(
                    job_handle,
                    JobObjectExtendedLimitInformation,
                    ctypes.byref(info),
                    ctypes.sizeof(info),
                    ctypes.byref(ret_len),
                )
                if ok:
                    usage["peak_process_memory_bytes"] = (
                        info.PeakProcessMemoryUsed
                    )
                    usage["peak_job_memory_bytes"] = (
                        info.PeakJobMemoryUsed
                    )
            except Exception:
                pass

        return usage


# ---------------------------------------------------------------------------
# Windows thread-resumption helper
# ---------------------------------------------------------------------------

def _resume_process(pid: int) -> None:
    """Resume all threads of a suspended Windows process.

    On non-Windows platforms this is a no-op.
    """
    if sys.platform != "win32":
        return

    import ctypes

    TH32CS_SNAPTHREAD = 0x00000004
    THREAD_SUSPEND_RESUME = 0x0002

    class THREADENTRY32(ctypes.Structure):
        _fields_ = [
            ("dwSize", ctypes.c_ulong),
            ("cntUsage", ctypes.c_ulong),
            ("th32ThreadID", ctypes.c_ulong),
            ("th32OwnerProcessID", ctypes.c_ulong),
            ("tpBasePri", ctypes.c_long),
            ("tpDeltaPri", ctypes.c_long),
            ("dwFlags", ctypes.c_ulong),
        ]

    kernel32 = ctypes.windll.kernel32
    snap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
    if snap == -1:
        return

    try:
        te = THREADENTRY32()
        te.dwSize = ctypes.sizeof(THREADENTRY32)
        if kernel32.Thread32First(snap, ctypes.byref(te)):
            while True:
                if te.th32OwnerProcessID == pid:
                    h_thread = kernel32.OpenThread(
                        THREAD_SUSPEND_RESUME, False, te.th32ThreadID
                    )
                    if h_thread:
                        kernel32.ResumeThread(h_thread)
                        kernel32.CloseHandle(h_thread)
                if not kernel32.Thread32Next(snap, ctypes.byref(te)):
                    break
    finally:
        kernel32.CloseHandle(snap)
