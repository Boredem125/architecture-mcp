"""Verified-state accessor: one shared reader for the signed bundle and registry.

Every decision path reads the bundle and registry through this accessor,
which re-verifies the signed envelope against the pinned root on every call.
No decision path reads ``bundle.json``, ``registry.json``, ``enrollment.json``
or ``last_valid_bundle`` directly (C6, H2, ADR 0010 s2).

Returns ``None`` when any part fails: no approvals, denies still apply, prod,
deny-all.
"""
from __future__ import annotations

import json
from typing import Any, NamedTuple


class VerifiedState(NamedTuple):
    """Frozen snapshot of verified managed-workspace state."""
    bundle_payload: dict[str, Any]
    registry: Any  # sandbox.protocol.registry.Registry
    device_id: str
    project_id: str
    org_id: str
    operator_user_id: str | None
    environment: str
    policy_sequence: int
    enforced_approval: dict[str, Any]
    registry_version: int


def load_verified_state(layout) -> VerifiedState | None:
    """Load and verify the bundle + registry against the pinned root.

    Re-verifies on every call (ruling-A precedent).  Returns ``None`` if
    any part fails (missing, corrupt, or verification failure).
    """
    from sandbox.connector.policy_versions import _verified_bundle_payload
    from sandbox.connector.sync.state import pinned_root

    sync_dir = layout.root / ".sandbox" / "state" / "sync"

    # 1. Pinned root
    fp = pinned_root(layout)
    if fp is None:
        return None

    # 2. Verify registry chain
    registry = _verify_registry(sync_dir, fp)
    if registry is None:
        return None

    # 3. Verify bundle
    bundle_payload = _verified_bundle_payload(layout)
    if bundle_payload is None:
        return None

    # 4. Read enrollment
    enrollment = _read_enrollment(sync_dir)

    # 5. Read device_id
    device_id = _read_device_id(sync_dir)
    if not device_id:
        # Try enrollment
        if enrollment:
            device_id = enrollment.get("device_id", "")

    # Extract fields
    project_id = bundle_payload.get("project_id", "")
    org_id = bundle_payload.get("org_id", "")
    environment = bundle_payload.get("environment", "prod")
    policy_sequence = bundle_payload.get("sequence", 0)
    enforced_approval = bundle_payload.get("approval", {})
    registry_version = _get_registry_version(sync_dir)

    operator_user_id = None
    if enrollment:
        operator_user_id = enrollment.get("operator_user_id")
        # Cross-check org_id from enrollment
        enroll_org = enrollment.get("org_id")
        if enroll_org and org_id and enroll_org != org_id:
            return None  # org mismatch

    if not isinstance(policy_sequence, int):
        return None

    # S1/R3b: high-water mark -- refuse anything below the previously seen
    # registry version or bundle sequence (prevents rollback, C6).
    # Fail closed: a corrupt or missing file on a managed workspace means
    # None (no approvals), because the floor cannot be determined.
    hwm = _load_high_water(sync_dir)
    if hwm is None:
        return None  # S1: corrupt or missing => fail closed
    if registry_version < hwm.get("registry_version", 0):
        return None
    if policy_sequence < hwm.get("bundle_sequence", 0):
        return None
    # Update the high-water mark if current values are higher
    _save_high_water(sync_dir, registry_version, policy_sequence)

    return VerifiedState(
        bundle_payload=bundle_payload,
        registry=registry,
        device_id=device_id or "",
        project_id=project_id,
        org_id=org_id,
        operator_user_id=operator_user_id,
        environment=environment,
        policy_sequence=policy_sequence,
        enforced_approval=enforced_approval,
        registry_version=registry_version,
    )


def _verify_registry(sync_dir, fingerprint: str) -> Any:
    """Verify registry chain against pinned root, return Registry or None."""
    from sandbox.protocol.registry import verify_chain

    reg_file = sync_dir / "registry.json"
    if not reg_file.exists():
        return None
    try:
        data = json.loads(reg_file.read_text(encoding="utf-8"))
        chain = data if isinstance(data, list) else [data]
        return verify_chain(chain, fingerprint)
    except Exception:
        return None


def _read_enrollment(sync_dir) -> dict[str, Any] | None:
    """Read enrollment.json (unverified local file, F3 named limit)."""
    enroll_file = sync_dir / "enrollment.json"
    if not enroll_file.exists():
        return None
    try:
        data = json.loads(enroll_file.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            return data
    except (OSError, ValueError):
        pass
    return None


def _read_device_id(sync_dir) -> str:
    """Read device_id from the sync dir."""
    did_file = sync_dir / "device_id"
    if not did_file.exists():
        return ""
    try:
        return did_file.read_text(encoding="utf-8").strip()
    except OSError:
        return ""


def _get_registry_version(sync_dir) -> int:
    """Get the registry version from the chain."""
    reg_file = sync_dir / "registry.json"
    if not reg_file.exists():
        return 0
    try:
        data = json.loads(reg_file.read_text(encoding="utf-8"))
        chain = data if isinstance(data, list) else [data]
        if chain:
            return chain[-1].get("payload", {}).get("version", 0)
    except (OSError, ValueError):
        pass
    return 0


def _load_high_water(sync_dir) -> dict[str, int] | None:
    """Load the high-water mark from sync state.

    S1: returns None (fail closed) if the file is missing or corrupt on a
    managed workspace.  A missing file means the floor cannot be determined;
    enroll writes the initial high-water so it is always present after a
    valid enrollment.
    """
    hwm_file = sync_dir / "high_water.json"
    if not hwm_file.exists():
        return None  # S1: missing => fail closed
    try:
        data = json.loads(hwm_file.read_text(encoding="utf-8"))
        if isinstance(data, dict) and "registry_version" in data and "bundle_sequence" in data:
            return data
        return None  # malformed
    except (OSError, ValueError):
        return None  # S1: corrupt => fail closed


def _save_high_water(sync_dir, registry_version: int, bundle_sequence: int) -> None:
    """Save the high-water mark (atomic write)."""
    import os as _os
    hwm_file = sync_dir / "high_water.json"
    current = _load_high_water(sync_dir)
    new_rv = max(registry_version, current.get("registry_version", 0))
    new_bs = max(bundle_sequence, current.get("bundle_sequence", 0))
    if new_rv == current.get("registry_version", 0) and new_bs == current.get("bundle_sequence", 0):
        return  # no change
    tmp = sync_dir / "high_water.json.tmp"
    try:
        tmp.write_text(json.dumps({"registry_version": new_rv, "bundle_sequence": new_bs}),
                       encoding="utf-8")
        _os.replace(str(tmp), str(hwm_file))
    except OSError:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass
