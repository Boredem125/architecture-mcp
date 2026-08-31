"""Subprocess isolation per AGENT_09 spec (cross-platform).

Provides resource-limited, secret-stripped subprocess execution contexts.

Platform strategies
-------------------
**Windows** (primary):
    Uses Win32 Job Objects via ``ctypes`` to enforce memory caps and
    ``KILL_ON_JOB_CLOSE`` semantics.  CPU rate limiting is configured via
    ``JOBOBJECT_CPU_RATE_CONTROL_INFORMATION``.  Processes are created
    suspended (``CREATE_SUSPENDED``), assigned to the job, then resumed.

**Linux** (documented, implemented where possible):
    Uses the ``resource`` module (``setrlimit``) for CPU time, address space,
    open file descriptors, and child process count.  Full sandboxing would
    layer ``seccomp-bpf``, user namespaces, and cgroup v2 controllers — see
    the ``_linux_preexec`` docstring for details.
"""

from __future__ import annotations

import os
import platform
import re
import sys
from dataclasses import dataclass, field
from typing import Any


# ---------------------------------------------------------------------------
# Isolation profile
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class IsolationProfile:
    """Resource limits and constraints for a single subprocess execution."""

    max_cpu_cores: int = 1
    max_memory_mb: int = 256
    max_pids: int = 32
    timeout_seconds: int = 30
    allowed_paths: list[str] = field(default_factory=list)
    network_allowed: bool = False
    action_type: str = ""


# ---------------------------------------------------------------------------
# Secret-stripping patterns
# ---------------------------------------------------------------------------

_SECRET_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"^AWS_", re.IGNORECASE),
    re.compile(r"^GITHUB_", re.IGNORECASE),
    re.compile(r"_KEY$", re.IGNORECASE),
    re.compile(r"_SECRET$", re.IGNORECASE),
    re.compile(r"_TOKEN$", re.IGNORECASE),
    re.compile(r"_PASSWORD$", re.IGNORECASE),
    re.compile(r"^AZURE_", re.IGNORECASE),
    re.compile(r"^GCP_", re.IGNORECASE),
    re.compile(r"^DATABASE_URL$", re.IGNORECASE),
    re.compile(r"^SECRET_", re.IGNORECASE),
    re.compile(r"^API_KEY$", re.IGNORECASE),
    re.compile(r"^PRIVATE_KEY$", re.IGNORECASE),
]

# Minimal allowlist of environment variables that the subprocess may see.
_ENV_ALLOWLIST: set[str] = {
    "PATH",
    "SYSTEMROOT",
    "COMSPEC",
    "TEMP",
    "TMP",
    "HOME",
    "USER",
    "LANG",
    "LC_ALL",
    "TERM",
    "SHELL",
    "LOGNAME",
    "HOSTNAME",
    "WINDIR",
    "PATHEXT",
}


def _is_secret(name: str) -> bool:
    """Return True if *name* matches any secret-like pattern."""
    return any(pat.search(name) for pat in _SECRET_PATTERNS)


# ---------------------------------------------------------------------------
# Windows Job-Object helpers (lazy-loaded)
# ---------------------------------------------------------------------------

if sys.platform == "win32":
    import ctypes
    import ctypes.wintypes as wintypes

    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    # Constants
    CREATE_SUSPENDED = 0x00000004
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
    JOB_OBJECT_LIMIT_PROCESS_MEMORY = 0x00000100
    JOB_OBJECT_LIMIT_JOB_MEMORY = 0x00000200
    JOB_OBJECT_LIMIT_ACTIVE_PROCESS = 0x00000008
    JobObjectExtendedLimitInformation = 9
    JobObjectCpuRateControlInformation = 15
    JOB_OBJECT_CPU_RATE_CONTROL_ENABLE = 0x1
    JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP = 0x4

    class IO_COUNTERS(ctypes.Structure):
        _fields_ = [
            ("ReadOperationCount", ctypes.c_ulonglong),
            ("WriteOperationCount", ctypes.c_ulonglong),
            ("OtherOperationCount", ctypes.c_ulonglong),
            ("ReadTransferCount", ctypes.c_ulonglong),
            ("WriteTransferCount", ctypes.c_ulonglong),
            ("OtherTransferCount", ctypes.c_ulonglong),
        ]

    class JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", ctypes.c_int64),
            ("PerJobUserTimeLimit", ctypes.c_int64),
            ("LimitFlags", wintypes.DWORD),
            ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t),
            ("ActiveProcessLimit", wintypes.DWORD),
            ("Affinity", ctypes.POINTER(ctypes.c_ulong)),
            ("PriorityClass", wintypes.DWORD),
            ("SchedulingClass", wintypes.DWORD),
        ]

    class JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("BasicLimitInformation", JOBOBJECT_BASIC_LIMIT_INFORMATION),
            ("IoInfo", IO_COUNTERS),
            ("ProcessMemoryLimit", ctypes.c_size_t),
            ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t),
            ("PeakJobMemoryUsed", ctypes.c_size_t),
        ]

    class JOBOBJECT_CPU_RATE_CONTROL_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("ControlFlags", wintypes.DWORD),
            ("CpuRate", wintypes.DWORD),
        ]

    def _create_job_object(profile: IsolationProfile) -> ctypes.c_void_p:
        """Create a Win32 Job Object configured per *profile*."""
        h_job = _kernel32.CreateJobObjectW(None, None)
        if not h_job:
            raise OSError(
                f"CreateJobObjectW failed: {ctypes.get_last_error()}"
            )

        # Extended limits: memory + active-process cap + kill-on-close.
        ext_info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
        ext_info.BasicLimitInformation.LimitFlags = (
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            | JOB_OBJECT_LIMIT_JOB_MEMORY
            | JOB_OBJECT_LIMIT_PROCESS_MEMORY
            | JOB_OBJECT_LIMIT_ACTIVE_PROCESS
        )
        mem_bytes = profile.max_memory_mb * 1024 * 1024
        ext_info.ProcessMemoryLimit = mem_bytes
        ext_info.JobMemoryLimit = mem_bytes
        ext_info.BasicLimitInformation.ActiveProcessLimit = profile.max_pids

        ok = _kernel32.SetInformationJobObject(
            h_job,
            JobObjectExtendedLimitInformation,
            ctypes.byref(ext_info),
            ctypes.sizeof(ext_info),
        )
        if not ok:
            _kernel32.CloseHandle(h_job)
            raise OSError(
                f"SetInformationJobObject (extended) failed: "
                f"{ctypes.get_last_error()}"
            )

        # CPU rate control: cap at (max_cpu_cores / total_cores) * 10000.
        total_cores = os.cpu_count() or 1
        rate = min(
            int((profile.max_cpu_cores / total_cores) * 10000), 10000
        )
        if rate < 10000:
            cpu_info = JOBOBJECT_CPU_RATE_CONTROL_INFORMATION()
            cpu_info.ControlFlags = (
                JOB_OBJECT_CPU_RATE_CONTROL_ENABLE
                | JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP
            )
            cpu_info.CpuRate = rate
            _kernel32.SetInformationJobObject(
                h_job,
                JobObjectCpuRateControlInformation,
                ctypes.byref(cpu_info),
                ctypes.sizeof(cpu_info),
            )

        return h_job

    def _assign_process_to_job(
        h_job: ctypes.c_void_p, h_process: int
    ) -> None:
        """Assign a process handle to the given Job Object."""
        ok = _kernel32.AssignProcessToJobObject(h_job, h_process)
        if not ok:
            raise OSError(
                f"AssignProcessToJobObject failed: {ctypes.get_last_error()}"
            )


# ---------------------------------------------------------------------------
# Linux pre-exec helpers
# ---------------------------------------------------------------------------

def _linux_preexec(profile: IsolationProfile) -> None:
    """Set resource limits before exec on Linux.

    This function is called in the child process after ``fork()`` but
    before ``exec()``.  It uses ``resource.setrlimit`` to constrain:

    * ``RLIMIT_CPU``   — wall-clock CPU seconds.
    * ``RLIMIT_AS``    — max virtual-memory address space (bytes).
    * ``RLIMIT_NOFILE``— max open file descriptors.
    * ``RLIMIT_NPROC`` — max user processes (child PIDs).

    For production hardening, this should be combined with:
    * **seccomp-bpf** — restrict system calls to an allowlist.
    * **User namespaces** — remap UID/GID so the child runs as an
      unprivileged user even if the parent is root.
    * **cgroup v2** — enforce memory.max, cpu.max, pids.max via the
      systemd-managed cgroup tree.
    * **Mount namespaces** — present a read-only rootfs overlay with
      only ``allowed_paths`` bind-mounted read-write.
    * **Network namespaces** — place the child in an empty netns to
      block network access when ``network_allowed`` is ``False``.
    """
    import resource  # noqa: F811 — only available on Unix

    # CPU time (seconds).
    resource.setrlimit(
        resource.RLIMIT_CPU,
        (profile.timeout_seconds, profile.timeout_seconds),
    )
    # Virtual memory (bytes).
    mem_bytes = profile.max_memory_mb * 1024 * 1024
    resource.setrlimit(resource.RLIMIT_AS, (mem_bytes, mem_bytes))
    # Open file descriptors.
    resource.setrlimit(resource.RLIMIT_NOFILE, (256, 256))
    # Max child processes.
    resource.setrlimit(
        resource.RLIMIT_NPROC, (profile.max_pids, profile.max_pids)
    )


# ---------------------------------------------------------------------------
# SubprocessIsolator
# ---------------------------------------------------------------------------

class SubprocessIsolator:
    """Build isolated subprocess execution contexts.

    The isolator does not itself run processes — it produces the
    configuration that :class:`SubprocessRunner` consumes to launch and
    constrain each child process.
    """

    def __init__(self, profile: IsolationProfile) -> None:
        self.profile = profile
        self._platform = platform.system()

    # ------------------------------------------------------------------
    # Command construction
    # ------------------------------------------------------------------

    def build_command(self, command: str, parameters: dict[str, Any]) -> list[str]:
        """Construct an isolated command line.

        On **Windows** the command is wrapped in ``cmd /c`` so that shell
        built-ins (``dir``, ``echo``, …) work.  On **Linux** it is passed
        through ``/bin/sh -c`` for the same reason.

        Parameters are serialised as a JSON string argument so that the
        subprocess receives them without shell-quoting issues.
        """
        import json as _json

        params_json = _json.dumps(parameters, default=str)

        if self._platform == "Windows":
            return ["cmd", "/c", command, params_json]
        else:
            return ["/bin/sh", "-c", f"{command} {_shellquote(params_json)}"]

    # ------------------------------------------------------------------
    # Subprocess kwargs
    # ------------------------------------------------------------------

    def get_subprocess_kwargs(self) -> dict[str, Any]:
        """Return keyword arguments for ``asyncio.create_subprocess_exec``.

        The returned dict includes:
        * ``env`` — sanitised environment (no secrets).
        * ``creationflags`` — on Windows, ``CREATE_SUSPENDED`` so the
          process can be assigned to a Job Object before it runs.
        * ``preexec_fn`` — on Linux, the resource-limiting callback.
        * ``stdin`` — always ``subprocess.DEVNULL``.
        * ``stdout`` / ``stderr`` — always ``subprocess.PIPE``.
        """
        import asyncio  # noqa: F811
        import subprocess

        kwargs: dict[str, Any] = {
            "env": self.sanitize_environment(),
            "stdin": subprocess.DEVNULL,
            "stdout": subprocess.PIPE,
            "stderr": subprocess.PIPE,
        }

        if self._platform == "Windows":
            kwargs["creationflags"] = CREATE_SUSPENDED if sys.platform == "win32" else 0
        else:
            kwargs["preexec_fn"] = lambda: _linux_preexec(self.profile)

        return kwargs

    # ------------------------------------------------------------------
    # Environment sanitisation
    # ------------------------------------------------------------------

    def sanitize_environment(self) -> dict[str, str]:
        """Return a clean environment dict stripped of secret-like variables.

        Only variables in the explicit allowlist **or** that do not match
        any secret pattern are kept.  This ensures that credentials like
        ``AWS_SECRET_ACCESS_KEY``, ``GITHUB_TOKEN``, and anything ending
        in ``_KEY``, ``_SECRET``, ``_TOKEN``, or ``_PASSWORD`` never leak
        into a sandboxed subprocess.
        """
        clean: dict[str, str] = {}
        for key, value in os.environ.items():
            if key.upper() in _ENV_ALLOWLIST:
                clean[key] = value
            elif not _is_secret(key):
                clean[key] = value
        return clean

    # ------------------------------------------------------------------
    # Platform-specific job object (Windows only)
    # ------------------------------------------------------------------

    def create_job_object(self) -> Any:
        """Create and return a Win32 Job Object handle, or ``None``.

        Only meaningful on Windows.  Returns ``None`` on other platforms.
        The caller is responsible for closing the handle.
        """
        if self._platform == "Windows" and sys.platform == "win32":
            return _create_job_object(self.profile)
        return None

    def assign_to_job(self, job_handle: Any, process_handle: int) -> None:
        """Assign *process_handle* to *job_handle* (Windows only)."""
        if self._platform == "Windows" and sys.platform == "win32":
            _assign_process_to_job(job_handle, process_handle)


def _shellquote(s: str) -> str:
    """Minimally shell-quote *s* for POSIX ``/bin/sh``."""
    return "'" + s.replace("'", "'\"'\"'") + "'"
