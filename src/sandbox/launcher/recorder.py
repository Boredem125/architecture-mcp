"""Comprehensive session recorder — logs.txt + modified.txt + .trash/.

logs.txt:   Human-readable append log of every action, broker request,
            and approval/denial. Each line stamped with IDs.
modified.txt: Every created/modified/deleted path in the jail.
.trash/:    Originals of modified/deleted files preserved here.
"""
from __future__ import annotations

import hashlib
import os
import shutil
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any, NamedTuple

import structlog

logger = structlog.get_logger(__name__)

_DEFAULT_IGNORE_DIRS = (".sandbox_logs", ".trash", "broker_out")
_DEFAULT_MAX_FILE_BYTES = 10 * 1024 * 1024  # 10 MiB


class FileStat(NamedTuple):
    """Cheap change-detection fingerprint for one file."""

    size: int
    mtime_ns: int
    sha256: str | None  # None when the file exceeds max_file_bytes


class SessionRecorder:
    """Records all actions and file changes for a jailed session."""

    def __init__(
        self,
        jail_dir: str | Path,
        ignore_dirs: "os.PathLike[str] | list[str] | tuple[str, ...] | None" = None,
        max_file_bytes: int = _DEFAULT_MAX_FILE_BYTES,
    ) -> None:
        self._jail_dir = Path(jail_dir)
        self._logs_dir = self._jail_dir / ".sandbox_logs"
        self._logs_dir.mkdir(parents=True, exist_ok=True)
        self._logs_file = self._logs_dir / "logs.txt"
        self._modified_file = self._logs_dir / "modified.txt"
        self._trash_dir = self._jail_dir / ".trash"
        self._trash_dir.mkdir(parents=True, exist_ok=True)
        self._ignore_dirs = frozenset(ignore_dirs or _DEFAULT_IGNORE_DIRS)
        self._max_file_bytes = max_file_bytes
        # relpath -> FileStat, so scan_changes can detect *modification*, not
        # just creation/deletion (bug 2).
        self._known_files: dict[str, FileStat] = {}
        self._scan_initial()

    def _walk(self) -> Iterator[str]:
        """Yield jail-relative paths of every tracked file (shared by the
        initial scan and change scans, so the prune list lives in one place)."""
        for root, dirs, files in os.walk(self._jail_dir):
            dirs[:] = [d for d in dirs if d not in self._ignore_dirs]
            for f in files:
                yield os.path.relpath(os.path.join(root, f), self._jail_dir)

    def _stat_file(self, rel: str) -> FileStat | None:
        abs_path = self._jail_dir / rel
        try:
            st = abs_path.stat()
        except OSError:
            return None
        digest: str | None = None
        if st.st_size <= self._max_file_bytes:
            try:
                h = hashlib.sha256()
                with open(abs_path, "rb") as fh:
                    for chunk in iter(lambda: fh.read(65536), b""):
                        h.update(chunk)
                digest = h.hexdigest()
            except OSError:
                digest = None
        return FileStat(size=st.st_size, mtime_ns=st.st_mtime_ns, sha256=digest)

    def _scan_initial(self) -> None:
        """Record the initial state of the jail directory."""
        for rel in self._walk():
            stat = self._stat_file(rel)
            if stat is not None:
                self._known_files[rel] = stat

    def log_action(
        self,
        session_id: str,
        agent_id: str,
        action: str,
        details: dict[str, Any] | None = None,
        request_id: str = "",
    ) -> None:
        """Append a structured action line to logs.txt."""
        ts = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime())
        parts = [
            ts,
            f"session={session_id}",
            f"agent={agent_id}",
            f"action={action}",
        ]
        if request_id:
            parts.append(f"request={request_id}")
        if details:
            for k, v in details.items():
                parts.append(f"{k}={v}")

        line = " | ".join(parts)
        try:
            with open(self._logs_file, "a", encoding="utf-8") as f:
                f.write(line + "\n")
        except OSError as e:
            logger.warning("recorder.log_failed", error=str(e))

    def log_output(
        self,
        session_id: str,
        run_id: str,
        stream: str,
        line: str,
    ) -> None:
        """Append a process output line to logs.txt."""
        ts = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime())
        entry = f"{ts} | session={session_id} | run={run_id} | {stream}: {line}"
        try:
            with open(self._logs_file, "a", encoding="utf-8") as f:
                f.write(entry + "\n")
        except OSError:
            pass

    def record_file_change(
        self,
        rel_path: str,
        change_type: str,
    ) -> None:
        """Record a file change in modified.txt and preserve originals."""
        ts = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime())

        abs_path = self._jail_dir / rel_path

        if change_type in ("modified", "deleted") and abs_path.exists():
            safe_ts = ts.replace(":", "").replace("-", "")
            trash_dest = self._trash_dir / f"{safe_ts}_{rel_path.replace(os.sep, '_')}"
            trash_dest.parent.mkdir(parents=True, exist_ok=True)
            try:
                shutil.copy2(str(abs_path), str(trash_dest))
            except OSError as e:
                logger.warning(
                    "recorder.trash_failed",
                    path=rel_path,
                    error=str(e),
                )

        entry = f"{ts} | {change_type} | {rel_path}"
        try:
            with open(self._modified_file, "a", encoding="utf-8") as f:
                f.write(entry + "\n")
        except OSError:
            pass

        if change_type == "created":
            stat = self._stat_file(rel_path)
            if stat is not None:
                self._known_files[rel_path] = stat
        elif change_type == "deleted":
            self._known_files.pop(rel_path, None)

    def scan_changes(self) -> list[dict[str, str]]:
        """Scan the jail directory for created / modified / deleted files.

        Detects modification by comparing (size, mtime_ns) and confirming
        with a content hash on mismatch — set membership alone never sees an
        in-place edit (bug 2).
        """
        current: dict[str, FileStat] = {}
        for rel in self._walk():
            stat = self._stat_file(rel)
            if stat is not None:
                current[rel] = stat

        changes: list[dict[str, str]] = []
        known_keys = set(self._known_files)
        current_keys = set(current)

        for rel in current_keys - known_keys:
            self.record_file_change(rel, "created")
            changes.append({"path": rel, "type": "created"})

        for rel in known_keys - current_keys:
            self.record_file_change(rel, "deleted")
            changes.append({"path": rel, "type": "deleted"})

        for rel in current_keys & known_keys:
            before, after = self._known_files[rel], current[rel]
            if before == after:
                continue
            # Stat differs — confirm with hashes when both are available, so a
            # mere mtime touch with identical content isn't flagged.
            if (
                before.sha256 is not None
                and after.sha256 is not None
                and before.sha256 == after.sha256
            ):
                self._known_files[rel] = after  # refresh mtime, no change
                continue
            self.record_file_change(rel, "modified")
            changes.append({"path": rel, "type": "modified"})

        self._known_files = current
        return changes

    def get_logs(self) -> str:
        """Return the full logs.txt content."""
        if self._logs_file.exists():
            return self._logs_file.read_text(encoding="utf-8")
        return ""

    def get_modified(self) -> str:
        """Return the full modified.txt content."""
        if self._modified_file.exists():
            return self._modified_file.read_text(encoding="utf-8")
        return ""
