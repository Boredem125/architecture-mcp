"""FolderLayout — every path inside a project's ``.sandbox/`` in one place.

Keeping all path construction here means the hook stub, the MCP server, the
approver, and the tests never disagree about where something lives.
"""
from __future__ import annotations

import os
from pathlib import Path

FOLDER_NAME = ".sandbox"


class FolderLayout:
    """Resolves the ``.sandbox/`` tree for a project *root*."""

    def __init__(self, root: str | os.PathLike[str]) -> None:
        self.root = Path(root).resolve()
        self.base = self.root / FOLDER_NAME

    # --- top-level files -------------------------------------------------
    @property
    def policy_file(self) -> Path:
        return self.base / "policy.json"

    @property
    def session_file(self) -> Path:
        return self.base / "session.json"

    # --- directories -----------------------------------------------------
    @property
    def hooks_dir(self) -> Path:
        return self.base / "hooks"

    @property
    def state_dir(self) -> Path:
        return self.base / "state"

    @property
    def escalations_dir(self) -> Path:
        return self.base / "escalations"

    @property
    def pending_dir(self) -> Path:
        return self.escalations_dir / "pending"

    @property
    def claimed_dir(self) -> Path:
        return self.escalations_dir / "claimed"

    @property
    def done_dir(self) -> Path:
        return self.escalations_dir / "done"

    @property
    def out_dir(self) -> Path:
        return self.escalations_dir / "out"

    @property
    def audit_dir(self) -> Path:
        return self.base / "audit"

    @property
    def logs_dir(self) -> Path:
        return self.base / "logs"

    @property
    def originals_dir(self) -> Path:
        return self.base / "originals"

    @property
    def changes_dir(self) -> Path:
        # Human-readable, browsable change journal: one file per modification,
        # each showing the diff + a pointer to the preserved old version.
        return self.base / "changes"

    @property
    def tmp_dir(self) -> Path:
        # Must live inside .sandbox so os.replace() from here is same-volume.
        return self.base / "tmp"

    # --- state files -----------------------------------------------------
    @property
    def known_files(self) -> Path:
        return self.state_dir / "known_files.json"

    @property
    def remembered(self) -> Path:
        return self.state_dir / "remembered.json"

    # --- helpers ---------------------------------------------------------
    def exists(self) -> bool:
        return self.base.is_dir()

    def ensure_dirs(self) -> None:
        """Create the full directory skeleton (idempotent)."""
        for d in (
            self.base,
            self.hooks_dir,
            self.state_dir,
            self.pending_dir,
            self.claimed_dir,
            self.done_dir,
            self.out_dir,
            self.audit_dir,
            self.logs_dir,
            self.originals_dir,
            self.changes_dir,
            self.tmp_dir,
        ):
            d.mkdir(parents=True, exist_ok=True)

    @classmethod
    def discover(cls, start: str | os.PathLike[str]) -> "FolderLayout | None":
        """Walk up from *start* looking for a ``.sandbox/`` directory."""
        cur = Path(start).resolve()
        for candidate in (cur, *cur.parents):
            if (candidate / FOLDER_NAME).is_dir():
                return cls(candidate)
        return None
