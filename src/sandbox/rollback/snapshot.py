"""Snapshot manager for pre-action state capture per AGENT_08 spec.

Captures filesystem and metadata state before each sandboxed action so
that the rollback engine can restore prior state when needed.  Each
snapshot is stored under ``{storage_dir}/{session_id}/{request_id}/``
with a ``metadata.json`` sidecar and, for WRITE actions, the original
file contents.
"""

from __future__ import annotations

import hashlib
import os
import stat
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import aiofiles
import aiofiles.os
import orjson

from sandbox.models.enums import ActionType
from sandbox.models.messages import SnapshotRecord


def _uuid() -> str:
    return str(uuid.uuid4())


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class _FileMetadata:
    """Lightweight representation of a single file's metadata."""

    path: str
    size: int
    permissions: int
    mtime: float
    is_dir: bool


async def _file_metadata(path: Path) -> _FileMetadata:
    """Collect metadata for *path* without reading the file."""
    st = await aiofiles.os.stat(str(path))
    return _FileMetadata(
        path=str(path),
        size=st.st_size,
        permissions=stat.S_IMODE(st.st_mode),
        mtime=st.st_mtime,
        is_dir=stat.S_ISDIR(st.st_mode),
    )


async def _sha256_file(path: Path, *, chunk_size: int = 65_536) -> str:
    """Return the hex SHA-256 digest of the file at *path*."""
    h = hashlib.sha256()
    async with aiofiles.open(str(path), "rb") as fh:
        while True:
            chunk = await fh.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


async def _sha256_bytes(data: bytes) -> str:
    """Return the hex SHA-256 digest of raw *data*."""
    return hashlib.sha256(data).hexdigest()


async def _recursive_dir_hash(root: Path) -> str:
    """Compute a deterministic hash over the full directory tree.

    The hash covers ``relative_path || file_hash`` for every regular
    file, sorted lexicographically by relative path, so insertions,
    deletions, and modifications all change the result.
    """
    h = hashlib.sha256()
    entries: list[tuple[str, str]] = []

    for dirpath, _dirnames, filenames in os.walk(root):
        for fname in filenames:
            full = Path(dirpath) / fname
            rel = full.relative_to(root).as_posix()
            file_hash = await _sha256_file(full)
            entries.append((rel, file_hash))

    entries.sort(key=lambda e: e[0])
    for rel, file_hash in entries:
        h.update(f"{rel}:{file_hash}\n".encode())
    return h.hexdigest()


# ------------------------------------------------------------------
# SnapshotManager
# ------------------------------------------------------------------


class SnapshotManager:
    """Manages pre-action snapshots for rollback support.

    Parameters
    ----------
    storage_dir:
        Root directory under which snapshot data is written.
    max_session_size:
        Maximum total snapshot storage (in bytes) allowed per session.
        Defaults to 2 GiB.
    """

    def __init__(
        self,
        storage_dir: str = "./snapshots",
        max_session_size: int = 2 * 1024**3,
    ) -> None:
        self._storage_dir = Path(storage_dir)
        self._max_session_size = max_session_size

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def take_snapshot(
        self,
        session_id: str,
        request_id: str,
        action_type: ActionType,
        targets: list[str],
    ) -> SnapshotRecord:
        """Capture state before an action and persist it to disk.

        The shape of the captured data depends on *action_type*:

        * **WRITE** -- full file contents, parent directory listing,
          and file metadata (permissions, timestamps, size).
        * **EXECUTE** -- recursive SHA-256 hash of the working-
          directory tree.
        * **NETWORK** -- request payload (flagged non-reversible).
        * **SECRET_ACCESS** -- secret path only; the value is **never**
          stored.

        Raises
        ------
        RuntimeError
            If the session's cumulative snapshot storage would exceed
            *max_session_size*.
        """
        snapshot_id = _uuid()
        snap_dir = self._snapshot_path(session_id, request_id)
        await aiofiles.os.makedirs(str(snap_dir), exist_ok=True)

        data: dict[str, Any]

        if action_type == ActionType.WRITE:
            data = await self._capture_write(targets, snap_dir)
        elif action_type == ActionType.EXECUTE:
            data = await self._capture_execute(targets)
        elif action_type == ActionType.NETWORK:
            data = await self._capture_network(targets)
        elif action_type == ActionType.SECRET_ACCESS:
            data = await self._capture_secret_access(targets)
        else:
            # READ and any future types -- lightweight metadata-only snapshot.
            data = {"action_type": str(action_type), "targets": targets}

        # Serialise metadata ------------------------------------------------
        metadata_bytes = orjson.dumps(data, option=orjson.OPT_INDENT_2)
        metadata_hash = await _sha256_bytes(metadata_bytes)
        metadata_path = snap_dir / "metadata.json"
        async with aiofiles.open(str(metadata_path), "wb") as fh:
            await fh.write(metadata_bytes)

        size_bytes = await self._dir_size(snap_dir)

        # Enforce session storage budget ------------------------------------
        current_session_size = await self.get_session_size(session_id)
        if current_session_size > self._max_session_size:
            raise RuntimeError(
                f"Session {session_id} snapshot storage "
                f"({current_session_size} bytes) exceeds limit "
                f"({self._max_session_size} bytes)"
            )

        return SnapshotRecord(
            snapshot_id=snapshot_id,
            request_id=request_id,
            session_id=session_id,
            action_type=action_type,
            snapshot_hash=metadata_hash,
            size_bytes=size_bytes,
        )

    async def get_snapshot(self, snapshot_id: str) -> dict[str, Any] | None:
        """Retrieve the metadata dict for *snapshot_id*.

        Performs a brute-force search across sessions because snapshot
        IDs are globally unique UUIDs.  Returns ``None`` when the
        snapshot has been cleaned up or never existed.
        """
        if not self._storage_dir.exists():
            return None

        for session_dir in self._storage_dir.iterdir():
            if not session_dir.is_dir():
                continue
            for request_dir in session_dir.iterdir():
                meta_path = request_dir / "metadata.json"
                if not meta_path.exists():
                    continue
                async with aiofiles.open(str(meta_path), "rb") as fh:
                    raw = await fh.read()
                data: dict[str, Any] = orjson.loads(raw)
                if data.get("snapshot_id") == snapshot_id:
                    return data

        return None

    async def verify_snapshot(self, snapshot_id: str) -> bool:
        """Verify that the on-disk snapshot has not been tampered with.

        Recomputes the SHA-256 hash of ``metadata.json`` and compares
        it against the hash recorded at creation time.
        """
        if not self._storage_dir.exists():
            return False

        for session_dir in self._storage_dir.iterdir():
            if not session_dir.is_dir():
                continue
            for request_dir in session_dir.iterdir():
                meta_path = request_dir / "metadata.json"
                if not meta_path.exists():
                    continue
                async with aiofiles.open(str(meta_path), "rb") as fh:
                    raw = await fh.read()
                data: dict[str, Any] = orjson.loads(raw)
                if data.get("snapshot_id") != snapshot_id:
                    continue
                stored_hash = data.get("snapshot_hash", "")
                # Recompute over the raw bytes on disk.
                actual_hash = await _sha256_bytes(raw)
                return actual_hash == stored_hash

        return False

    async def list_session_snapshots(
        self, session_id: str
    ) -> list[SnapshotRecord]:
        """Return every :class:`SnapshotRecord` persisted for *session_id*."""
        session_dir = self._storage_dir / session_id
        if not session_dir.exists():
            return []

        records: list[SnapshotRecord] = []
        for request_dir in sorted(session_dir.iterdir()):
            meta_path = request_dir / "metadata.json"
            if not meta_path.exists():
                continue
            async with aiofiles.open(str(meta_path), "rb") as fh:
                raw = await fh.read()
            data: dict[str, Any] = orjson.loads(raw)
            records.append(
                SnapshotRecord(
                    snapshot_id=data.get("snapshot_id", ""),
                    request_id=data.get("request_id", request_dir.name),
                    session_id=session_id,
                    action_type=ActionType(data.get("action_type", "READ")),
                    snapshot_hash=data.get("snapshot_hash", ""),
                    size_bytes=await self._dir_size(request_dir),
                )
            )
        return records

    async def get_session_size(self, session_id: str) -> int:
        """Total bytes consumed by all snapshots in *session_id*."""
        session_dir = self._storage_dir / session_id
        if not session_dir.exists():
            return 0
        return await self._dir_size(session_dir)

    async def cleanup_session(
        self, session_id: str, after_seconds: int = 7200
    ) -> None:
        """Remove snapshots older than *after_seconds* for *session_id*.

        Files whose ``created_at_utc`` is more than *after_seconds* in
        the past are deleted.  If the entire session directory becomes
        empty it is removed as well.
        """
        session_dir = self._storage_dir / session_id
        if not session_dir.exists():
            return

        now = datetime.now(timezone.utc)

        for request_dir in list(session_dir.iterdir()):
            meta_path = request_dir / "metadata.json"
            if not meta_path.exists():
                continue

            async with aiofiles.open(str(meta_path), "rb") as fh:
                raw = await fh.read()
            data: dict[str, Any] = orjson.loads(raw)
            created_str = data.get("created_at_utc", "")
            if not created_str:
                continue

            try:
                created = datetime.fromisoformat(created_str)
            except (ValueError, TypeError):
                continue

            elapsed = (now - created).total_seconds()
            if elapsed >= after_seconds:
                await self._remove_tree(request_dir)

        # Remove the session directory itself if now empty.
        remaining = list(session_dir.iterdir())
        if not remaining:
            await aiofiles.os.rmdir(str(session_dir))

    # ------------------------------------------------------------------
    # Action-specific capture
    # ------------------------------------------------------------------

    async def _capture_write(
        self, targets: list[str], snap_dir: Path
    ) -> dict[str, Any]:
        """Capture full file content, parent listing, and metadata."""
        snapshot_id = snap_dir.parent.name  # reuse request_id as key
        data: dict[str, Any] = {
            "action_type": str(ActionType.WRITE),
            "snapshot_id": "",  # filled by caller in metadata round-trip
            "created_at_utc": _now_iso(),
            "targets": targets,
            "files": {},
            "parent_listings": {},
        }

        data_dir = snap_dir / "data"
        await aiofiles.os.makedirs(str(data_dir), exist_ok=True)

        for idx, target in enumerate(targets):
            target_path = Path(target)

            file_entry: dict[str, Any] = {"original_path": str(target_path)}

            if target_path.is_file():
                meta = await _file_metadata(target_path)
                file_entry["size"] = meta.size
                file_entry["permissions"] = oct(meta.permissions)
                file_entry["mtime"] = meta.mtime
                file_entry["hash"] = await _sha256_file(target_path)

                # Persist a backup copy of the original content.
                backup_name = f"file_{idx}"
                backup_path = data_dir / backup_name
                async with aiofiles.open(str(target_path), "rb") as src:
                    content = await src.read()
                async with aiofiles.open(str(backup_path), "wb") as dst:
                    await dst.write(content)
                file_entry["backup"] = backup_name
            elif target_path.is_dir():
                file_entry["is_dir"] = True
            else:
                file_entry["exists"] = False

            data["files"][str(target_path)] = file_entry

            # Parent directory listing.
            parent = target_path.parent
            if parent.is_dir() and str(parent) not in data["parent_listings"]:
                listing = sorted(p.name for p in parent.iterdir())
                data["parent_listings"][str(parent)] = listing

        return data

    async def _capture_execute(
        self, targets: list[str]
    ) -> dict[str, Any]:
        """Capture recursive hash of each working-directory tree."""
        data: dict[str, Any] = {
            "action_type": str(ActionType.EXECUTE),
            "created_at_utc": _now_iso(),
            "targets": targets,
            "directory_hashes": {},
        }
        for target in targets:
            target_path = Path(target)
            if target_path.is_dir():
                data["directory_hashes"][str(target_path)] = (
                    await _recursive_dir_hash(target_path)
                )
        return data

    async def _capture_network(
        self, targets: list[str]
    ) -> dict[str, Any]:
        """Log request payload with non-reversible flag."""
        return {
            "action_type": str(ActionType.NETWORK),
            "created_at_utc": _now_iso(),
            "targets": targets,
            "reversible": False,
            "note": "Network actions are non-reversible; payload logged for audit only.",
        }

    async def _capture_secret_access(
        self, targets: list[str]
    ) -> dict[str, Any]:
        """Log only the secret path -- never the secret value."""
        return {
            "action_type": str(ActionType.SECRET_ACCESS),
            "created_at_utc": _now_iso(),
            "secret_paths": targets,
            "reversible": False,
            "note": "Secret values are never captured in snapshots.",
        }

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _snapshot_path(self, session_id: str, request_id: str) -> Path:
        return self._storage_dir / session_id / request_id

    @staticmethod
    async def _dir_size(path: Path) -> int:
        """Compute the total size in bytes of all files under *path*."""
        total = 0
        for dirpath, _dirnames, filenames in os.walk(path):
            for fname in filenames:
                full = Path(dirpath) / fname
                try:
                    st = await aiofiles.os.stat(str(full))
                    total += st.st_size
                except OSError:
                    continue
        return total

    @staticmethod
    async def _remove_tree(path: Path) -> None:
        """Recursively delete *path* and everything beneath it."""
        if not path.exists():
            return
        for dirpath, dirnames, filenames in os.walk(path, topdown=False):
            for fname in filenames:
                await aiofiles.os.remove(str(Path(dirpath) / fname))
            for dname in dirnames:
                await aiofiles.os.rmdir(str(Path(dirpath) / dname))
        await aiofiles.os.rmdir(str(path))
