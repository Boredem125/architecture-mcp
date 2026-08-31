"""FolderRecorder — content-addressed blob storage for file originals.

Subclasses SessionRecorder with `.sandbox/originals/by-hash/<ab>/<sha256>` for
deduplication, collision-free naming, and fast restore. Keeps a `.sandbox/originals/index.jsonl`
timeline of all snapshots per session.

PreToolUse snapshots edit targets to preserve their state *before* the agent's
change; PostToolUse re-hashes to detect and finalize modifications.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any

from sandbox.launcher.recorder import FileStat, SessionRecorder


class FolderRecorder(SessionRecorder):
    """Record file changes with content-addressed originals storage."""

    def __init__(
        self,
        jail_dir: str | Path,
        session_id: str = "",
        originals_dir: str | Path | None = None,
    ):
        super().__init__(jail_dir, session_id)
        self.originals_dir = Path(originals_dir) if originals_dir else None

    def snapshot_file(self, rel_path: str, reason: str = "") -> dict[str, Any] | None:
        """Snapshot a file before an edit, preserving its original.

        Returns a record with the file's stat and hash, or None if the file
        doesn't exist or is outside the jail.

        This is called by PreToolUse for edit tools (Write, Edit, etc.) to
        preserve state before deciding whether to allow the edit.
        """
        abs_path = self._resolve_path(rel_path)
        if not abs_path or not abs_path.is_file():
            return None

        stat = self._stat_file(abs_path)
        if not stat:
            return None

        # Store in content-addressed originals if configured
        original_hash = None
        if self.originals_dir:
            original_hash = self._store_original(abs_path, stat.sha256)

        return {
            "timestamp": self._timestamp(),
            "rel_path": rel_path,
            "abs_path": str(abs_path),
            "size": stat.size,
            "mtime_ns": stat.mtime_ns,
            "sha256": stat.sha256,
            "original_hash": original_hash,
            "reason": reason,
        }

    def _store_original(self, abs_path: Path, sha256: str) -> str:
        """Store file content in `originals/by-hash/<ab>/<sha256>`.

        Returns the stored path relative to originals_dir. Deduplicates by hash
        (same content, same location).
        """
        if not self.originals_dir:
            return ""

        # Two-level hierarchy: ab/sha256 where ab is first two hex chars
        subdir = self.originals_dir / sha256[:2]
        subdir.mkdir(parents=True, exist_ok=True)
        target = subdir / sha256[2:]

        # Already stored? Skip.
        if target.exists():
            return str(target.relative_to(self.originals_dir))

        # Copy atomically: write to tmp, os.replace
        tmp = self.originals_dir / "tmp" / sha256
        tmp.parent.mkdir(parents=True, exist_ok=True)
        try:
            tmp.write_bytes(abs_path.read_bytes())
            os.replace(tmp, target)
        except OSError:
            return ""

        return str(target.relative_to(self.originals_dir))

    def finalize_file(self, rel_path: str, reason: str = "") -> dict[str, Any]:
        """Re-stat a file after an edit to detect modifications.

        Returns a record with the new stat/hash and a 'modified' or 'unchanged' verdict.
        Called by PostToolUse to finalize the snapshot record.
        """
        abs_path = self._resolve_path(rel_path)
        record = {
            "timestamp": self._timestamp(),
            "rel_path": rel_path,
            "abs_path": str(abs_path) if abs_path else "",
            "reason": reason,
        }

        if not abs_path or not abs_path.is_file():
            record["verdict"] = "deleted"
            return record

        stat = self._stat_file(abs_path)
        if not stat:
            record["verdict"] = "inaccessible"
            return record

        record["size"] = stat.size
        record["mtime_ns"] = stat.mtime_ns
        record["sha256"] = stat.sha256
        record["verdict"] = "modified"
        return record

    def list_snapshots(self, limit: int = 100) -> list[dict[str, Any]]:
        """List recent snapshots from the index.jsonl."""
        if not self.originals_dir or not (self.originals_dir / "index.jsonl").exists():
            return []

        snapshots = []
        try:
            with open(self.originals_dir / "index.jsonl", encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        try:
                            snapshots.append(json.loads(line))
                        except json.JSONDecodeError:
                            pass
        except OSError:
            pass

        return snapshots[-limit:]

    def _timestamp(self) -> str:
        """ISO timestamp for audit records."""
        import time

        return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    def _resolve_path(self, rel_path: str) -> Path | None:
        """Resolve rel_path within jail_dir, with containment check."""
        try:
            abs_path = (self._jail_dir / rel_path).resolve()
            jail = self._jail_dir.resolve()
            if abs_path.is_relative_to(jail):
                return abs_path
        except (ValueError, OSError):
            pass
        return None
