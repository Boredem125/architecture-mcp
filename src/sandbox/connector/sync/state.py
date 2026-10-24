"""Connector sync state: managed mode, locked mode, pinned root (D1.7, D7.4).

Managed mode is sticky: once enrolled, the workspace stays managed until an
admin-quorum-signed ``agg/unenroll/v1`` decision removes the marker.  If the
sync state or policy_history is missing while the marker exists, the connector
enters *locked* mode: every call except reads inside the root is denied, and
non-removable protections and default read denies still apply (N7).

An unenrolled workspace (no managed marker) behaves exactly as today (D7.4).
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def _workspace_id(layout) -> str | None:
    """Read workspace_id without creating one."""
    ws_id_file = layout.base / "workspace_id"
    try:
        text = ws_id_file.read_text(encoding="utf-8").strip() if ws_id_file.exists() else ""
    except OSError:
        return None
    return text if text else None


def is_managed(layout) -> bool:
    """True if the workspace has a managed marker (D1.7, D7.4).

    Checks both the key-home marker and the sync-dir marker.  If either
    exists the workspace is managed and can never fall back to standalone.
    """
    # Check key-home marker
    ws_id = _workspace_id(layout)
    if ws_id:
        try:
            from sandbox.connector.keyhome import key_home_root

            kh = key_home_root()
            if kh is not None and (kh / ws_id / "managed").exists():
                return True
        except Exception:  # noqa: BLE001
            pass

    # Check sync-dir marker
    sync_dir = layout.root / ".sandbox" / "state" / "sync"
    try:
        if (sync_dir / "managed").exists():
            return True
    except OSError:
        pass

    return False


def is_locked(layout) -> bool:
    """True if managed but both sync state and policy_history are gone (D1.7).

    Locked mode denies every call except reads inside the root.  Reads
    still go through non-removable protections and default read denies (N7).
    """
    if not is_managed(layout):
        return False

    # If we have a valid bundle in sync state, not locked
    sync_dir = layout.root / ".sandbox" / "state" / "sync"
    try:
        if (sync_dir / "bundle.json").exists():
            return False
    except OSError:
        pass

    # If we have any bundle in policy_history, not locked
    hist = layout.root / ".sandbox" / "policy_history"
    try:
        if hist.is_dir():
            for child in hist.iterdir():
                if child.name.startswith("bundle_") and child.name.endswith(".json"):
                    return False
    except OSError:
        pass

    return True


def pinned_root(layout) -> str | None:
    """The fingerprint of the pinned registry root, or None (F2).

    Only ``sandbox enroll --expect-fingerprint`` writes this file.
    ``sandbox sync`` never re-pins it.
    """
    sync_dir = layout.root / ".sandbox" / "state" / "sync"
    pr_file = sync_dir / "pinned_root.json"
    if not pr_file.exists():
        return None
    try:
        data = json.loads(pr_file.read_text(encoding="utf-8"))
        return data.get("fingerprint")
    except (OSError, ValueError, KeyError):
        return None


def last_valid_bundle(layout) -> dict[str, Any] | None:
    """The last valid bundle, from sync state or policy_history."""
    # First check current sync state
    sync_dir = layout.root / ".sandbox" / "state" / "sync"
    bundle_file = sync_dir / "bundle.json"
    try:
        if bundle_file.exists():
            return json.loads(bundle_file.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        pass

    # Fall back to policy_history
    hist = layout.root / ".sandbox" / "policy_history"
    try:
        if hist.is_dir():
            bundles = sorted(
                (f for f in hist.iterdir()
                 if f.name.startswith("bundle_") and f.name.endswith(".json")),
                key=lambda f: f.name,
                reverse=True,
            )
            for b in bundles:
                try:
                    return json.loads(b.read_text(encoding="utf-8"))
                except (OSError, ValueError):
                    continue
    except OSError:
        pass

    return None


def current_sequence(layout) -> int | None:
    """The sequence number of the last valid bundle, or None if no bundle."""
    lvb = last_valid_bundle(layout)
    if lvb is None:
        return None
    return lvb.get("payload", {}).get("sequence")


def current_environment(layout) -> str:
    """The environment from the last valid bundle; absent = 'prod' (D2.4)."""
    lvb = last_valid_bundle(layout)
    if lvb is None:
        return "prod"
    return lvb.get("payload", {}).get("environment", "prod")


def can_accept_bundles(layout) -> bool:
    """True if the workspace has a pinned root (F2).

    Until ``sandbox enroll --expect-fingerprint`` writes a pinned root,
    bundles and remote approvals are refused.
    """
    return pinned_root(layout) is not None


# -- Server time state (F1, D4.3) ------------------------------------------


def read_server_time_state(layout) -> dict | None:
    """Read the last recorded server time measurement.

    Returns ``{"server_time": float, "local_time": float}`` or ``None``
    if the state is missing or corrupt.  Written by ``sync/process.py``
    on every HTTP response that carries a ``Date`` header.
    """
    sync_dir = layout.root / ".sandbox" / "state" / "sync"
    state_file = sync_dir / "server_time_state.json"
    if not state_file.exists():
        return None
    try:
        data = json.loads(state_file.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            return None
        st = data.get("server_time")
        lt = data.get("local_time")
        if not isinstance(st, (int, float)) or not isinstance(lt, (int, float)):
            return None
        return {"server_time": float(st), "local_time": float(lt)}
    except (OSError, ValueError):
        return None


def write_server_time_state(layout, server_time: float, local_time: float) -> None:
    """Persist a server-time measurement (atomic temp-file + rename).

    Called by ``sync/process.py`` after every HTTP response that carries
    a ``Date`` header.
    """
    import os

    sync_dir = layout.root / ".sandbox" / "state" / "sync"
    state_file = sync_dir / "server_time_state.json"
    tmp = sync_dir / "server_time_state.json.tmp"
    try:
        sync_dir.mkdir(parents=True, exist_ok=True)
        tmp.write_text(
            json.dumps({"server_time": server_time, "local_time": local_time}),
            encoding="utf-8",
        )
        os.replace(str(tmp), str(state_file))
    except Exception:  # noqa: BLE001
        try:
            tmp.unlink(missing_ok=True)
        except Exception:  # noqa: BLE001
            pass
