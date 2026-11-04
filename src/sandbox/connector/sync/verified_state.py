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


# ---------------------------------------------------------------------------
# Bootstrap loader (T16g G7-A): the first bundle after enrolment only
# ---------------------------------------------------------------------------
#
# ``load_verified_state`` needs a verified bundle, so right after
# ``sandbox enroll`` every decision path gets ``None`` (deny-all, prod, no
# approvals) and ``_fetch_bundle`` could never apply the first bundle.
# This loader is used ONLY by ``_fetch_bundle`` and ONLY when no bundle
# exists at all (no ``bundle.json``, nothing in ``policy_history/``).  It
# never relaxes ``load_verified_state`` and it is never a decision input.
#
# Trust root (security L ruling, HANDOFF 4 Nov 2026): ``pinned_root.json``
# plus ``verify_chain(registry.json)``; the bundle signer comes from that
# verified registry.  org_id comes from the root-signed genesis and must
# equal the non-empty ``enrollment.json`` org_id; project_id comes from
# ``enrollment.json`` (F3 named limit).  Nothing is read from the server
# body, no re-pin, no keys from the bundle, no marker file.


class BootstrapError(Exception):
    """Refusal from :func:`load_bootstrap_state`; ``reason`` is audited."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


class BootstrapState(NamedTuple):
    """Verified inputs for the first bundle (no bundle exists yet)."""
    registry: Any  # sandbox.protocol.registry.Registry
    registry_version: int
    org_id: str
    project_id: str


def _any_bundle_file(layout) -> bool:
    """True if ``bundle.json`` exists at all (even unparseable) or any
    ``policy_history/bundle_*.json`` exists."""
    sync_dir = layout.root / ".sandbox" / "state" / "sync"
    try:
        if (sync_dir / "bundle.json").exists():
            return True
    except OSError:
        return True  # cannot tell: fail closed
    hist = layout.root / ".sandbox" / "policy_history"
    try:
        if hist.is_dir():
            for child in hist.iterdir():
                if child.name.startswith("bundle_") and child.name.endswith(".json"):
                    return True
    except OSError:
        return True
    return False


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def load_bootstrap_state(layout) -> BootstrapState:
    """Verify the local trust root for a first bundle; raise on any gap.

    Checks, in order (each refusal is a :class:`BootstrapError` whose
    ``reason`` the caller audits as ``bundle_refused``):

    1. the workspace carries a managed marker (never a standalone fallback);
    2. no bundle exists (``bundle.json`` or ``policy_history/``): with one
       present the caller must go through ``load_verified_state``;
    3. ``pinned_root.json`` holds a fingerprint (only enroll writes it);
    4. ``registry.json`` is a well-formed chain that verifies against it;
    5. the latest registry version is an int >= 1, not expired, and its
       ``not_before`` (when present) is not in the future;
    6. the root-signed genesis ``org_id`` is a non-empty string;
    7. ``enrollment.json`` exists with a non-empty ``org_id`` equal to the
       genesis org_id and a non-empty ``project_id``;
    8. ``high_water.json`` exists and is well formed; ``bundle_sequence``
       must be 0 (a higher value with no bundle means the state was
       deleted: refuse ``state_deleted`` and stay locked, ADR 0001 A1.8);
       ``registry_version`` must not exceed the verified registry version.
    """
    import time as _time

    from sandbox.connector.sync.state import (
        is_managed, last_valid_bundle, pinned_root,
    )
    from sandbox.protocol.registry import verify_chain

    sync_dir = layout.root / ".sandbox" / "state" / "sync"

    # 1. Managed marker
    if not is_managed(layout):
        raise BootstrapError("bootstrap_not_managed")

    # 2. No bundle at all: any bundle.json (parseable or not) or any
    #    policy_history/bundle_*.json means the verified-state path owns
    #    this workspace; never bootstrap over it (security R2).
    if _any_bundle_file(layout) or last_valid_bundle(layout) is not None:
        raise BootstrapError("bootstrap_bundle_present")

    # 3. Pinned root
    fp = pinned_root(layout)
    if not isinstance(fp, str) or not fp:
        raise BootstrapError("no_pinned_root")

    # 4. Registry chain verified against the pinned root
    reg_file = sync_dir / "registry.json"
    if not reg_file.is_file():
        raise BootstrapError("no_registry")
    try:
        data = json.loads(reg_file.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        raise BootstrapError("registry_malformed") from None
    chain = data if isinstance(data, list) else [data]
    if not chain or not all(
        isinstance(env, dict) and isinstance(env.get("payload"), dict)
        for env in chain
    ):
        raise BootstrapError("registry_malformed")
    try:
        registry = verify_chain(chain, fp)
    except Exception as exc:  # RegistryError, EnvelopeError, anything else
        raise BootstrapError(
            f"registry_verify_failed: {type(exc).__name__}"
        ) from None

    # 5. Latest version, expiry, not_before
    latest = chain[-1]["payload"]
    registry_version = getattr(registry, "version", None)
    if not _is_int(registry_version) or registry_version < 1:
        raise BootstrapError("registry_version_invalid")
    expires_at = latest.get("expires_at")
    now = _time.time()
    if (
        not isinstance(expires_at, (int, float))
        or isinstance(expires_at, bool)
        or now > float(expires_at)
    ):
        raise BootstrapError("registry_expired")
    not_before = latest.get("not_before")
    if not_before is not None:
        if (
            not isinstance(not_before, (int, float))
            or isinstance(not_before, bool)
            or float(not_before) > now
        ):
            raise BootstrapError("registry_not_before")

    # 6. org_id from the root-signed genesis
    genesis_org = chain[0]["payload"].get("org_id")
    if not isinstance(genesis_org, str) or not genesis_org:
        raise BootstrapError("registry_org_missing")

    # 7. enrollment.json: org must match the genesis; project from here
    enrollment = _read_enrollment(sync_dir)
    if enrollment is None:
        raise BootstrapError("enrollment_missing")
    enroll_org = enrollment.get("org_id")
    if not isinstance(enroll_org, str) or not enroll_org:
        raise BootstrapError("enrollment_org_missing")
    if enroll_org != genesis_org:
        raise BootstrapError(
            "org_id mismatch: enrollment.json org_id does not match the "
            "root-signed genesis org_id"
        )
    project_id = enrollment.get("project_id")
    if not isinstance(project_id, str) or not project_id:
        raise BootstrapError("enrollment_project_missing")

    # 8. high_water.json: bundle_sequence must be 0 (A1.8), registry floor
    hwm = _load_high_water(sync_dir)
    if hwm is None:
        raise BootstrapError("high_water_missing")
    hw_seq = hwm.get("bundle_sequence")
    hw_reg = hwm.get("registry_version")
    if not _is_int(hw_seq) or not _is_int(hw_reg) or hw_seq < 0 or hw_reg < 0:
        raise BootstrapError("high_water_malformed")
    if hw_seq > 0:
        raise BootstrapError(
            f"state_deleted: high_water bundle_sequence {hw_seq} but no "
            "verified bundle exists (ADR 0001 A1.8); re-enroll"
        )
    if hw_reg > registry_version:
        raise BootstrapError(
            f"registry_rollback: high_water registry_version {hw_reg} "
            f"above verified registry version {registry_version}"
        )

    return BootstrapState(
        registry=registry,
        registry_version=registry_version,
        org_id=genesis_org,
        project_id=project_id,
    )
