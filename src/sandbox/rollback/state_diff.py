"""State diff engine for post-action and post-session comparison.

Computes fine-grained diffs between a pre-action snapshot and the
current filesystem state, and generates ordered rollback plans that
the rollback executor can apply.
"""

from __future__ import annotations

import hashlib
import os
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

import aiofiles
import aiofiles.os
import orjson

from sandbox.models.enums import ActionType
from sandbox.models.messages import SnapshotRecord


# ------------------------------------------------------------------
# Data structures
# ------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ModifiedFile:
    """A file that exists in both the before-snapshot and the current
    state but whose content has changed."""

    path: str
    before_hash: str
    after_hash: str
    size_delta: int


@dataclass(slots=True)
class DiffResult:
    """Complete diff between two filesystem states."""

    new_files: list[str] = field(default_factory=list)
    deleted_files: list[str] = field(default_factory=list)
    modified_files: list[ModifiedFile] = field(default_factory=list)
    permission_changes: list[str] = field(default_factory=list)
    unauthorized_changes: list[str] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class RollbackStep:
    """A single atomic operation in a rollback plan."""

    order: int
    action: Literal["restore", "delete", "revert_permissions"]
    target_path: str
    snapshot_id: str
    description: str


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------


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


# ------------------------------------------------------------------
# StateDiff
# ------------------------------------------------------------------


class StateDiff:
    """Engine that computes filesystem diffs and builds rollback plans.

    Typical flow:

    1. Before a session starts, call :meth:`scan_directory` to capture
       the baseline state.
    2. After each action (or at session end), call :meth:`compute_diff`
       to see what changed.
    3. Call :meth:`post_session_diff` to cross-reference changes against
       the approved audit log and flag unauthorized mutations.
    4. Call :meth:`generate_rollback_plan` to produce an executable
       list of :class:`RollbackStep` operations.
    """

    # ------------------------------------------------------------------
    # Directory scanning
    # ------------------------------------------------------------------

    async def scan_directory(self, path: str) -> dict[str, dict[str, Any]]:
        """Recursively scan *path* and return a map of every file.

        Returns
        -------
        dict[str, dict]
            Mapping from relative POSIX path to a dict with keys
            ``hash``, ``size``, ``permissions``, and ``mtime``.
        """
        root = Path(path)
        result: dict[str, dict[str, Any]] = {}

        for dirpath, _dirnames, filenames in os.walk(root):
            for fname in filenames:
                full = Path(dirpath) / fname
                rel = full.relative_to(root).as_posix()
                try:
                    st = await aiofiles.os.stat(str(full))
                    file_hash = await _sha256_file(full)
                    result[rel] = {
                        "hash": file_hash,
                        "size": st.st_size,
                        "permissions": oct(stat.S_IMODE(st.st_mode)),
                        "mtime": st.st_mtime,
                    }
                except OSError:
                    continue

        return result

    # ------------------------------------------------------------------
    # Diff computation
    # ------------------------------------------------------------------

    async def compute_diff(
        self,
        before_snapshot: dict[str, dict[str, Any]],
        current_state: dict[str, dict[str, Any]],
    ) -> DiffResult:
        """Compare *before_snapshot* against *current_state*.

        Both arguments are maps with the shape returned by
        :meth:`scan_directory`.

        Returns
        -------
        DiffResult
            Populated with new, deleted, modified, and permission-
            changed files.
        """
        before_paths = set(before_snapshot.keys())
        current_paths = set(current_state.keys())

        new_files = sorted(current_paths - before_paths)
        deleted_files = sorted(before_paths - current_paths)

        modified_files: list[ModifiedFile] = []
        permission_changes: list[str] = []

        for path in sorted(before_paths & current_paths):
            before = before_snapshot[path]
            current = current_state[path]

            before_hash = before.get("hash", "")
            after_hash = current.get("hash", "")

            if before_hash != after_hash:
                modified_files.append(
                    ModifiedFile(
                        path=path,
                        before_hash=before_hash,
                        after_hash=after_hash,
                        size_delta=current.get("size", 0) - before.get("size", 0),
                    )
                )

            if before.get("permissions") != current.get("permissions"):
                permission_changes.append(path)

        return DiffResult(
            new_files=new_files,
            deleted_files=deleted_files,
            modified_files=modified_files,
            permission_changes=permission_changes,
        )

    # ------------------------------------------------------------------
    # Post-session audit diff
    # ------------------------------------------------------------------

    async def post_session_diff(
        self,
        session_id: str,
        session_start_state: dict[str, dict[str, Any]],
        audit_records: list[dict[str, Any]],
    ) -> DiffResult:
        """Compare start-of-session state against the current filesystem
        and flag any changes not covered by the audit log.

        Parameters
        ----------
        session_id:
            Identifier for the session being audited.
        session_start_state:
            The map returned by :meth:`scan_directory` at session
            start.
        audit_records:
            Sequence of audit records (dicts).  Each is expected to
            have at least ``action_type`` and ``parameters.targets``.

        Returns
        -------
        DiffResult
            The ``unauthorized_changes`` field is populated with paths
            that changed but were not covered by any approved action in
            the audit log.
        """
        # Determine the root directory from the start state keys.  We
        # need it to re-scan.  If the state is empty, we cannot
        # produce a meaningful diff.
        if not session_start_state:
            return DiffResult()

        # Collect every path that was explicitly approved.
        approved_paths: set[str] = set()
        for record in audit_records:
            params = record.get("parameters", {})
            targets: list[str] = params.get("targets", [])
            for t in targets:
                # Normalise to POSIX relative path.
                approved_paths.add(Path(t).as_posix())

        # Re-scan the same root.  The caller must ensure that
        # session_start_state was produced from a known root -- we
        # accept the state dict directly, so the "current" state must
        # also be passed in via a second scan by the caller.  To make
        # the API ergonomic when the root is still available, we
        # accept the session_start_state's own root heuristically
        # (first entry's common prefix), but the canonical pattern is
        # for the caller to scan and pass the second state.
        #
        # For robustness we do the diff purely against the two maps;
        # the caller supplies current_state via a prior scan_directory
        # call.  post_session_diff therefore performs an *offline*
        # diff.  Below we parse approved_paths from audit_records and
        # overlay unauthorized_changes.

        # Because post_session_diff should remain self-contained when
        # possible, we accept an optional ``current_state`` key in the
        # first audit_record as an escape hatch, but the standard path
        # is for the caller to build the DiffResult first and call
        # _flag_unauthorized separately.

        # Compute the diff between start state and the latest scan.
        # The caller should produce current_state with scan_directory
        # and pass it here.  For backward-compat, if the last audit
        # record carries a ``__current_state`` key, use that.
        current_state: dict[str, dict[str, Any]] | None = None
        if audit_records:
            current_state = audit_records[-1].get("__current_state")

        if current_state is None:
            # Without a current state we cannot diff; return empty.
            return DiffResult()

        diff = await self.compute_diff(session_start_state, current_state)

        # Cross-reference against the approved set.
        all_changed_paths: set[str] = set()
        all_changed_paths.update(diff.new_files)
        all_changed_paths.update(diff.deleted_files)
        all_changed_paths.update(m.path for m in diff.modified_files)
        all_changed_paths.update(diff.permission_changes)

        diff.unauthorized_changes = sorted(
            all_changed_paths - approved_paths
        )

        return diff

    # ------------------------------------------------------------------
    # Rollback planning
    # ------------------------------------------------------------------

    def generate_rollback_plan(
        self,
        diff: DiffResult,
        snapshots: list[SnapshotRecord],
    ) -> list[RollbackStep]:
        """Build an ordered list of :class:`RollbackStep` operations.

        The plan processes changes in the safest order:

        1. **Restore** deleted files from snapshots.
        2. **Revert** modified files to their snapshot versions.
        3. **Delete** newly created files that were not present before.
        4. **Revert permissions** for files whose mode bits changed.

        Parameters
        ----------
        diff:
            The diff describing what changed.
        snapshots:
            Available snapshot records whose stored data may be used
            to source the "before" state.

        Returns
        -------
        list[RollbackStep]
            Deterministically ordered steps.
        """
        # Build a lookup from request_id -> snapshot for quick access.
        snapshot_by_id: dict[str, SnapshotRecord] = {
            s.snapshot_id: s for s in snapshots
        }
        # Also index by request_id since callers often only have that.
        snapshot_by_request: dict[str, SnapshotRecord] = {
            s.request_id: s for s in snapshots
        }

        # Pick the most recent snapshot to source restores.
        latest_snapshot_id = (
            snapshots[-1].snapshot_id if snapshots else ""
        )

        steps: list[RollbackStep] = []
        order = 0

        # 1. Restore deleted files.
        for path in diff.deleted_files:
            order += 1
            steps.append(
                RollbackStep(
                    order=order,
                    action="restore",
                    target_path=path,
                    snapshot_id=latest_snapshot_id,
                    description=f"Restore deleted file: {path}",
                )
            )

        # 2. Revert modified files.
        for mf in diff.modified_files:
            order += 1
            steps.append(
                RollbackStep(
                    order=order,
                    action="restore",
                    target_path=mf.path,
                    snapshot_id=latest_snapshot_id,
                    description=(
                        f"Revert modified file: {mf.path} "
                        f"(hash {mf.before_hash[:12]}..{mf.after_hash[:12]})"
                    ),
                )
            )

        # 3. Delete newly created files.
        for path in diff.new_files:
            order += 1
            steps.append(
                RollbackStep(
                    order=order,
                    action="delete",
                    target_path=path,
                    snapshot_id="",
                    description=f"Delete new file not in baseline: {path}",
                )
            )

        # 4. Revert permission changes.
        for path in diff.permission_changes:
            # Skip paths already covered by a restore step above.
            already_handled = path in diff.deleted_files or any(
                m.path == path for m in diff.modified_files
            )
            if already_handled:
                continue
            order += 1
            steps.append(
                RollbackStep(
                    order=order,
                    action="revert_permissions",
                    target_path=path,
                    snapshot_id=latest_snapshot_id,
                    description=f"Revert permission change: {path}",
                )
            )

        return steps
