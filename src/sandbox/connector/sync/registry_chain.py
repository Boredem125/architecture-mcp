"""Shared verify-and-persist helper for the registry chain (R2-2).

Both ``_refresh_registry_chain`` (CLI ``sync_cmds.py``) and
``_fetch_registry`` (connector ``process.py``) need to verify a fetched
chain against the pinned root and persist it atomically.  This module
provides the single implementation.

Security invariants:
  - verify_chain against the pinned root before any write.
  - Rollback floor = max(local registry.json version,
    high_water.json registry_version).
  - A missing or corrupt high_water.json means refuse (S1 fail-closed).
    Never recreate it; never write high_water.json from this helper.
  - Same-version-different-bytes is refused (from process.py).
  - Atomic write (tmp + os.replace).
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Literal

# Status values returned by apply_registry_chain.
RegistryStatus = Literal[
    "updated",
    "unchanged",
    "refused:rollback",
    "refused:verify_failed",
    "refused:missing_hwm",
    "refused:same_version_different_bytes",
    "refused:bad_chain",
    "refused:not_enrolled",
]


def _load_high_water(sync_dir: Path) -> dict | None:
    """Load the high-water mark.  Returns None if missing or corrupt (S1)."""
    hwm_file = sync_dir / "high_water.json"
    if not hwm_file.exists():
        return None
    try:
        data = json.loads(hwm_file.read_text(encoding="utf-8"))
        if isinstance(data, dict) and "registry_version" in data and "bundle_sequence" in data:
            return data
        return None  # malformed
    except (OSError, ValueError):
        return None


def apply_registry_chain(
    layout,
    new_chain: list[dict],
) -> RegistryStatus:
    """Verify and persist a fetched registry chain.

    Returns a status string for the caller to include in its result.

    This function never writes high_water.json.  Only
    ``load_verified_state`` ratchets the high-water mark through
    ``_save_high_water``.
    """
    from sandbox.connector.sync.state import pinned_root as _pinned_root

    fp = _pinned_root(layout)
    if fp is None:
        return "refused:not_enrolled"

    sync_dir = layout.root / ".sandbox" / "state" / "sync"
    reg_file = sync_dir / "registry.json"

    # ------------------------------------------------------------------
    # Floor = max(local registry.json version, hwm registry_version)
    # ------------------------------------------------------------------

    # Local version on disk
    local_version = 0
    if reg_file.exists():
        try:
            cur_chain = json.loads(reg_file.read_text(encoding="utf-8"))
            if isinstance(cur_chain, list) and cur_chain:
                local_version = cur_chain[-1].get(
                    "payload", {},
                ).get("version", 0)
        except (OSError, ValueError):
            pass

    # High-water mark version (S1: missing/corrupt => refuse)
    hwm = _load_high_water(sync_dir)
    if hwm is None:
        return "refused:missing_hwm"

    hwm_version = hwm.get("registry_version", 0)
    floor = max(local_version, hwm_version)

    # ------------------------------------------------------------------
    # Validate the new chain
    # ------------------------------------------------------------------

    if not new_chain or not isinstance(new_chain, list):
        return "refused:bad_chain"

    # Verify against pinned root
    from sandbox.protocol.registry import verify_chain, RegistryError
    from sandbox.protocol.envelope import EnvelopeError

    try:
        verify_chain(new_chain, fp)
    except (RegistryError, EnvelopeError):
        return "refused:verify_failed"

    # New version
    new_version = new_chain[-1].get("payload", {}).get("version", 0)

    # Anti-rollback: new version must be >= floor
    if new_version < floor:
        return "refused:rollback"

    # Serialize for comparison and writing
    new_blob = json.dumps(new_chain, sort_keys=True, separators=(",", ":"))

    # Same-version-different-bytes check (stricter, from process.py)
    if new_version == local_version:
        if reg_file.exists():
            try:
                old_blob = reg_file.read_text(encoding="utf-8")
            except OSError:
                old_blob = ""
            if new_blob == old_blob:
                return "unchanged"
            # Same version, different bytes => refuse
            return "refused:same_version_different_bytes"
        # No local file but same version as floor from hwm => refuse
        return "refused:rollback"

    # new_version > floor (or > local_version): persist atomically
    sync_dir.mkdir(parents=True, exist_ok=True)
    reg_tmp = sync_dir / "registry.json.tmp"
    try:
        reg_tmp.write_text(new_blob, encoding="utf-8")
        os.replace(str(reg_tmp), str(reg_file))
    except Exception:
        try:
            reg_tmp.unlink(missing_ok=True)
        except Exception:  # noqa: BLE001
            pass
        return "refused:bad_chain"

    return "updated"
