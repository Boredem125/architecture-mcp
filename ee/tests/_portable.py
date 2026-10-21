"""Portable process-group helpers for cross-platform ee/ tests.

Provides:
- ``popen_kwargs()`` -> dict with CREATE_NEW_PROCESS_GROUP on Windows,
  start_new_session=True on POSIX.
- ``group_terminate(proc)`` and ``group_kill(proc)`` that send signals
  to the whole process group.
- ``symlink_privilege_probe()`` -> (bool, str|None): True if symlinks
  can be created, False with a skip reason string.
"""
from __future__ import annotations

import os
import signal
import subprocess
import tempfile
from pathlib import Path


def popen_kwargs() -> dict:
    """Return Popen kwargs for starting a process in a new group."""
    if os.name == "nt":
        return {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP}
    return {"start_new_session": True}


def group_terminate(proc: subprocess.Popen) -> None:
    """Send SIGTERM (or equivalent) to the entire process group."""
    if os.name == "nt":
        # On Windows, CREATE_NEW_PROCESS_GROUP makes the child a group
        # leader.  taskkill /F /T terminates the whole tree.
        try:
            subprocess.call(
                ["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except OSError:
            proc.terminate()
    else:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        except (ProcessLookupError, PermissionError):
            proc.terminate()


def group_kill(proc: subprocess.Popen) -> None:
    """Force-kill the entire process group."""
    if os.name == "nt":
        try:
            subprocess.call(
                ["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except OSError:
            proc.kill()
    else:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            proc.kill()


# Named skip reason for tests that need the symlink privilege.
SYMLINK_SKIP_REASON = (
    "Windows requires SeCreateSymbolicLinkPrivilege for symlinks"
)


def symlink_privilege_probe() -> tuple[bool, str | None]:
    """Check whether the current process can create symlinks.

    Returns ``(True, None)`` when symlinks work, or
    ``(False, reason_string)`` when they do not.
    """
    if os.name != "nt":
        return True, None

    try:
        with tempfile.TemporaryDirectory() as td:
            target = Path(td) / "target"
            target.write_text("probe")
            link = Path(td) / "link"
            link.symlink_to(target)
            return True, None
    except OSError:
        return False, SYMLINK_SKIP_REASON


def child_pids(parent_pid: int) -> list[int]:
    """Return the PIDs of immediate child processes of *parent_pid*.

    Uses ``/proc`` on POSIX and ``wmic`` on Windows.
    """
    if os.name == "nt":
        return _child_pids_windows(parent_pid)
    return _child_pids_posix(parent_pid)


def _child_pids_windows(parent_pid: int) -> list[int]:
    """Windows: use PowerShell to find all descendant processes.

    On Windows, uvicorn --workers spawns an intermediate supervisor;
    the actual workers are grandchildren.  This function walks the full
    tree so the caller sees every descendant.
    """
    try:
        # Fetch (ProcessId, ParentProcessId) for all processes in one call
        result = subprocess.run(
            [
                "powershell", "-NoProfile", "-Command",
                "Get-CimInstance Win32_Process"
                " | ForEach-Object { \"$($_.ProcessId),$($_.ParentProcessId)\" }",
            ],
            capture_output=True,
            text=True,
            timeout=15,
        )
        # Build a parent -> children map
        children_of: dict[int, list[int]] = {}
        for line in result.stdout.strip().splitlines():
            parts = line.strip().split(",")
            if len(parts) != 2:
                continue
            try:
                pid, ppid = int(parts[0]), int(parts[1])
            except ValueError:
                continue
            children_of.setdefault(ppid, []).append(pid)

        # BFS to collect all descendants
        descendants: list[int] = []
        queue = list(children_of.get(parent_pid, []))
        while queue:
            pid = queue.pop(0)
            descendants.append(pid)
            queue.extend(children_of.get(pid, []))
        return descendants
    except (OSError, subprocess.TimeoutExpired):
        return []


def _child_pids_posix(parent_pid: int) -> list[int]:
    """POSIX: read /proc to find child processes."""
    children = []
    try:
        for entry in os.listdir("/proc"):
            if not entry.isdigit():
                continue
            pid = int(entry)
            if pid == parent_pid:
                continue
            try:
                with open(f"/proc/{pid}/stat") as f:
                    stat_line = f.read()
                close_paren = stat_line.rfind(")")
                fields_after = stat_line[close_paren + 2:].split()
                ppid = int(fields_after[1])
                if ppid == parent_pid:
                    children.append(pid)
            except (OSError, ValueError, IndexError):
                continue
    except OSError:
        pass
    return children
