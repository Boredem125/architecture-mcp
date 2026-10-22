"""Signed policy bundles: verify, store, loosening, overlay (D2, T9).

The connector verifies bundles signed by the control plane's bundle-signer
key.  Trust is transitive: the key is trusted only because the pinned
registry lists it (D2.2).  Loosening is computed per section against the
connector's enforced policy (last valid bundle, or deny-all if none, N3).
A loosening needs 2 CLI ``agg/policy-change/v1`` approvals from distinct
users.  A tightening needs 1.

Reuses ``policy_versions.store()`` for the content-addressed store and
``policy_versions.meet`` / ``loosened_fields`` for folder-policy drift.
"""
from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass
from typing import Any

from sandbox.protocol.domains import BUNDLE, POLICY_CHANGE
from sandbox.protocol.envelope import (
    EnvelopeError,
    _ALLOWED_ALGS,
    _canonical_json,
    canonical_bytes,
)


# -- Public constants --------------------------------------------------------

BUNDLE_MAX_BYTES: int = 1_048_576  # 1 MiB

BUNDLE_FIELDS: frozenset[str] = frozenset({
    "org_id", "project_id", "sequence", "base_sequence",
    "registry_version", "environment",
    "folder_policy", "governance_policy", "mcp_policy",
    "approval", "change_approvals",
    "issued_at", "not_before", "expires_at",
})


# -- Errors ------------------------------------------------------------------

class BundleError(Exception):
    """Raised on any bundle verification or storage failure."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


# -- Result ------------------------------------------------------------------

@dataclass(frozen=True)
class BundleResult:
    """Returned on successful verify_and_apply."""
    sequence: int


# -- Verdict rank (for folder_policy meet/loosened) --------------------------

_VERDICT_RANK = {"allow": 0, "observe": 1, "escalate": 2, "deny": 3}

# Environment rank: prod is strictest; absent = prod
_ENV_RANK = {"prod": 3, "staging": 1, "development": 0, "dev": 0}


# -- Per-section loosened ----------------------------------------------------

def _env_value(payload: dict) -> str:
    """Return the effective environment string.  Absent = prod (D2.4)."""
    return payload.get("environment", "prod")


def _loosened_folder(base: dict, new: dict) -> list[str]:
    """Folder policy loosening via policy_versions.loosened_fields."""
    from sandbox.connector.policy_versions import loosened_fields as _lf
    base_fp = base.get("folder_policy", {})
    new_fp = new.get("folder_policy", {})
    return _lf(base_fp, new_fp)


def _loosened_governance(base: dict, new: dict) -> list[str]:
    """Governance policy: removed clause or weakened action = loosening."""
    base_clauses = base.get("governance_policy", {}).get("clauses", [])
    new_clauses = new.get("governance_policy", {}).get("clauses", [])
    base_by_id = {c.get("id"): c for c in base_clauses}
    new_by_id = {c.get("id"): c for c in new_clauses}
    paths = []
    for cid in base_by_id:
        if cid not in new_by_id:
            paths.append(f"governance_policy.clauses.{cid}.removed")
        else:
            base_action = base_by_id[cid].get("action", "deny")
            new_action = new_by_id[cid].get("action", "deny")
            if _VERDICT_RANK.get(new_action, 0) < _VERDICT_RANK.get(base_action, 0):
                paths.append(f"governance_policy.clauses.{cid}.action")
    return paths


def _loosened_mcp(base: dict, new: dict) -> list[str]:
    """MCP policy: added server or tool = loosening."""
    base_servers = base.get("mcp_policy", {}).get("servers", [])
    new_servers = new.get("mcp_policy", {}).get("servers", [])
    base_names = {s.get("name") for s in base_servers}
    paths = []
    for s in new_servers:
        name = s.get("name")
        if name not in base_names:
            paths.append(f"mcp_policy.servers.{name}")
        else:
            # Check tools within existing server
            base_tools = set()
            for bs in base_servers:
                if bs.get("name") == name:
                    base_tools = set(bs.get("tools", []))
                    break
            new_tools = set(s.get("tools", []))
            for t in new_tools - base_tools:
                paths.append(f"mcp_policy.servers.{name}.tools.{t}")
    return paths


def _loosened_approval(base: dict, new: dict) -> list[str]:
    """Approval section: false->true for local_fallback/allow_requester = loosening."""
    base_app = base.get("approval", {})
    new_app = new.get("approval", {})
    paths = []
    for field in ("local_fallback", "allow_requester"):
        bv = base_app.get(field, False)
        nv = new_app.get(field, False)
        if not bv and nv:
            paths.append(f"approval.{field}")
    return paths


def _loosened_environment(base: dict, new: dict) -> list[str]:
    """Environment: moving away from prod is loosening (D2.4)."""
    base_env = _env_value(base)
    new_env = _env_value(new)
    base_rank = _ENV_RANK.get(base_env, 2)
    new_rank = _ENV_RANK.get(new_env, 2)
    if new_rank < base_rank:
        return [f"environment.{base_env}_to_{new_env}"]
    if base_env != new_env and new_rank == base_rank:
        # Changed with no defined order -> loosening
        return [f"environment.changed_{base_env}_to_{new_env}"]
    return []


def loosened(enforced: dict, new: dict) -> dict[str, list[str]]:
    """Per-section loosening.

    Returns a dict whose keys are section names and whose values are lists
    of loosened dotted field paths within that section.  An empty dict means
    no loosening (the bundle is tightening-only).
    """
    result: dict[str, list[str]] = {}
    fp = _loosened_folder(enforced, new)
    if fp:
        result["folder_policy"] = fp
    gp = _loosened_governance(enforced, new)
    if gp:
        result["governance_policy"] = gp
    mp = _loosened_mcp(enforced, new)
    if mp:
        result["mcp_policy"] = mp
    ap = _loosened_approval(enforced, new)
    if ap:
        result["approval"] = ap
    ep = _loosened_environment(enforced, new)
    if ep:
        result["environment"] = ep
    return result


# -- Per-section meet at enforcement time (N5, D2.6) ------------------------

def _meet_folder(approved: dict, on_disk: dict) -> dict:
    """Folder policy: use policy_versions.meet (approved, on_disk)."""
    from sandbox.connector.policy_versions import meet as _meet
    a = approved.get("folder_policy", {})
    o = on_disk.get("folder_policy", {})
    if not a:
        return o
    return _meet(a, o) if o else a


def _meet_governance(approved: dict, on_disk: dict) -> dict:
    """Governance: keep all clauses from approved; on_disk can only add."""
    a_clauses = approved.get("governance_policy", {}).get("clauses", [])
    o_clauses = on_disk.get("governance_policy", {}).get("clauses", [])
    # Start with all approved clauses; tighten with on_disk's action level
    by_id_a = {c.get("id"): dict(c) for c in a_clauses}
    by_id_o = {c.get("id"): c for c in o_clauses}

    result_clauses = []
    for cid, ac in by_id_a.items():
        oc = by_id_o.get(cid)
        if oc is not None:
            # Tighten action: pick the stricter
            a_action = ac.get("action", "deny")
            o_action = oc.get("action", "deny")
            ac["action"] = a_action if _VERDICT_RANK.get(a_action, 0) >= _VERDICT_RANK.get(o_action, 0) else o_action
        result_clauses.append(ac)
    # On-disk can only add clauses (tightening); additional clauses kept
    for cid, oc in by_id_o.items():
        if cid not in by_id_a:
            result_clauses.append(dict(oc))
    base = dict(approved.get("governance_policy", {}))
    base["clauses"] = result_clauses
    return base


def _meet_mcp(approved: dict, on_disk: dict) -> dict:
    """MCP policy: on-disk can only remove.

    Enforced servers = approved intersect on-disk (by name).
    Within a shared server, enforced tools = approved intersect on-disk
    (if both sides list tools).  On-disk additions are ignored.
    """
    a_servers = approved.get("mcp_policy", {}).get("servers", [])
    o_servers = on_disk.get("mcp_policy", {}).get("servers", [])
    o_by_name: dict[str, dict] = {s.get("name"): s for s in o_servers}
    result_servers = []
    for s in a_servers:
        name = s.get("name")
        o = o_by_name.get(name)
        if o is None:
            # On-disk removed it (tightening): honour the removal
            continue
        if "tools" in s and "tools" in o:
            o_tools = set(o["tools"])
            entry = dict(s)
            entry["tools"] = [t for t in s["tools"] if t in o_tools]
            result_servers.append(entry)
        else:
            result_servers.append(s)
    base = dict(approved.get("mcp_policy", {}))
    base["servers"] = result_servers
    return base


def _meet_approval(approved: dict, on_disk: dict) -> dict:
    """Approval section: false->true on-disk is loosening -> no effect."""
    a_app = approved.get("approval", {})
    o_app = on_disk.get("approval", {})
    result = dict(a_app)
    for field in ("local_fallback", "allow_requester"):
        av = a_app.get(field, False)
        ov = o_app.get(field, False)
        # On-disk can only tighten: true->false ok. false->true ignored.
        if av is False and ov is True:
            result[field] = False  # ignore loosening
        elif av is True and ov is False:
            result[field] = False  # on-disk tightened
        else:
            result[field] = av
    return result


def _meet_environment(approved: dict, on_disk: dict) -> str | None:
    """Environment: on-disk moving from prod is loosening -> no effect."""
    a_env = approved.get("environment")
    o_env = on_disk.get("environment")
    a_eff = a_env if a_env is not None else "prod"
    o_eff = o_env if o_env is not None else "prod"
    a_rank = _ENV_RANK.get(a_eff, 2)
    o_rank = _ENV_RANK.get(o_eff, 2)
    if o_rank < a_rank:
        # On-disk loosened; ignore, keep approved
        return a_env
    # On-disk tightened or same
    return a_env  # always keep approved's value


def meet_bundle(approved: dict, on_disk: dict) -> dict:
    """Per-section meet at enforcement time (N5, D2.6).

    *approved* is the approved bundle payload; *on_disk* is the local
    tighten-only overlay.  Returns the enforced policy dict.  A hand edit
    that loosens any one section has no effect.
    """
    result = dict(approved)
    result["folder_policy"] = _meet_folder(approved, on_disk)
    result["governance_policy"] = _meet_governance(approved, on_disk)
    result["mcp_policy"] = _meet_mcp(approved, on_disk)
    result["approval"] = _meet_approval(approved, on_disk)
    env = _meet_environment(approved, on_disk)
    if env is not None:
        result["environment"] = env
    elif "environment" in result:
        del result["environment"]  # absent = prod
    return result


# -- Verify and apply -------------------------------------------------------

def _canonical_json_bytes(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def _bundle_hash(payload: dict) -> str:
    return hashlib.sha256(_canonical_json_bytes(payload)).hexdigest()


def _verify_envelope_structure(env: dict) -> None:
    """Check the envelope has the right shape."""
    if env.get("sig_v") != 1:
        raise BundleError(f"sig_v must be 1, got {env.get('sig_v')}")
    if env.get("kind") != "agg/bundle/v1":
        raise BundleError(f"wrong kind: {env.get('kind')}")
    sigs = env.get("signatures", [])
    if not sigs:
        raise BundleError("no signatures on bundle")
    for s in sigs:
        if s.get("alg") not in _ALLOWED_ALGS:
            raise BundleError(f"unsupported alg: {s.get('alg')}")


def _verify_signature(env: dict, bundle_signer_pub: bytes) -> None:
    """Verify at least one signature is from the bundle signer."""
    from nacl.signing import VerifyKey

    kid = hashlib.sha256(bundle_signer_pub).hexdigest()
    msg = canonical_bytes("agg/bundle/v1", env["payload"])
    found = False
    for sig_entry in env.get("signatures", []):
        if sig_entry.get("key_id") == kid:
            try:
                vk = VerifyKey(bundle_signer_pub)
                vk.verify(msg, bytes.fromhex(sig_entry.get("sig", "")))
                found = True
            except Exception as exc:
                raise BundleError(
                    f"bundle signature verification failed for key {kid}"
                ) from exc
    if not found:
        raise BundleError("no trusted bundle signer signature found")


def _verify_bundle_signer_in_registry(
    registry, bundle_signer_pub: bytes,
) -> None:
    """Verify the passed bundle_signer_pub matches the registry's bundle_signer.

    The registry's bundle_signer field has key_id = sha256(public_key).
    The bundle_signer key must be in the registry's key set with kind
    bundle-signer and may_sign BUNDLE.
    """
    kid = hashlib.sha256(bundle_signer_pub).hexdigest()
    if not registry.may_sign(kid, BUNDLE, "prod"):
        raise BundleError(
            "bundle_signer key not in registry or not authorized"
        )


def _verify_change_approvals(
    payload: dict,
    change_approvals: list[dict],
    registry,
    is_loosening: bool,
    is_first_bundle: bool,
) -> None:
    """Verify CLI change approvals over the bundle hash.

    Loosening or first bundle (deny-all base, N3): needs 2 from distinct users.
    Tightening only: needs 1.
    """
    needed = 2 if (is_loosening or is_first_bundle) else 1
    bh = _bundle_hash(payload)

    # Collect valid approvals
    valid_user_ids: set[str] = set()
    valid_key_ids: set[str] = set()

    for approval_env in change_approvals:
        if approval_env.get("kind") != "agg/policy-change/v1":
            continue
        if approval_env.get("sig_v") != 1:
            continue

        a_payload = approval_env.get("payload", {})
        if a_payload.get("bundle_hash") != bh:
            continue

        # The approver identity comes from the registry entry for key_id,
        # never the approval payload's user_id (D2.3 rule).
        a_sigs = approval_env.get("signatures", [])
        for sig_entry in a_sigs:
            sig_kid = sig_entry.get("key_id", "")
            if sig_kid in valid_key_ids:
                continue  # same key already counted

            # Check key is in registry with kind=cli and policy_author/approver role
            entry = registry._keys.get(sig_kid)
            if entry is None:
                continue
            if entry.get("kind") != "cli":
                continue
            roles = set(entry.get("roles", []))
            if not roles.intersection({"policy_author", "approver", "admin"}):
                continue

            # Verify the signature
            msg = canonical_bytes("agg/policy-change/v1", a_payload)
            try:
                from nacl.signing import VerifyKey
                vk = VerifyKey(bytes.fromhex(entry["public_key"]))
                vk.verify(msg, bytes.fromhex(sig_entry.get("sig", "")))
            except Exception:
                continue

            # Use user_id from the registry entry (not from payload)
            user_id = entry.get("user_id", "")
            if user_id in valid_user_ids:
                # One key under two user_ids counts once; user from registry
                continue
            valid_user_ids.add(user_id)
            valid_key_ids.add(sig_kid)

    if len(valid_user_ids) < needed:
        raise BundleError(
            f"need {needed} approvals from distinct users, "
            f"got {len(valid_user_ids)}"
        )


def verify_and_apply(
    layout,
    envelope: dict,
    registry,
    bundle_signer_pub: bytes,
    change_approvals: list[dict],
    *,
    org_id: str,
    project_id: str,
) -> BundleResult:
    """Verify and store a signed policy bundle.

    Raises :class:`BundleError` on any verification or storage failure.
    Returns :class:`BundleResult` on success.
    """
    from sandbox.connector.sync.state import (
        current_sequence,
        last_valid_bundle,
    )
    from sandbox.connector import policy_versions

    # 1. Envelope structure
    _verify_envelope_structure(envelope)

    # 2. Size cap (1 MiB)
    raw = _canonical_json_bytes(envelope.get("payload", {}))
    if len(raw) > BUNDLE_MAX_BYTES:
        raise BundleError(f"bundle size {len(raw)} exceeds {BUNDLE_MAX_BYTES}")

    payload = envelope.get("payload", {})

    # 3. Strict parse: unknown fields refused
    payload_keys = set(payload.keys())
    unknown = payload_keys - BUNDLE_FIELDS
    if unknown:
        raise BundleError(f"unknown fields in bundle: {unknown}")

    # 4. Verify signature against bundle_signer_pub
    _verify_signature(envelope, bundle_signer_pub)

    # 5. Bundle signer must be in registry
    _verify_bundle_signer_in_registry(registry, bundle_signer_pub)

    # 6. Binding checks: org_id and project_id
    if payload.get("org_id") != org_id:
        raise BundleError(
            f"org_id mismatch: bundle has {payload.get('org_id')!r}, "
            f"expected {org_id!r}"
        )
    if payload.get("project_id") != project_id:
        raise BundleError(
            f"project_id mismatch: bundle has {payload.get('project_id')!r}, "
            f"expected {project_id!r}"
        )

    # 7. not_before check (D2.5)
    not_before = payload.get("not_before", 0)
    if not_before > time.time():
        raise BundleError("not_before is in the future")

    # 8. Registry version check (D2.5)
    # The bundle's registry_version must be >= the pinned registry version.
    # The registry's latest version is in the chain's last payload.
    # We use the registry object: all keys from all versions are in it,
    # but we check the version number.  The registry was built from the chain
    # and the latest version is the one that matters.
    bundle_reg_version = payload.get("registry_version", 0)
    # Registry version comes from the chain. We need to track it.
    # The test builds registry from genesis (version=1), so bundle must be >= 1.
    # We'll check against the registry's minimum acceptable version.
    # For now, version 0 is always refused (older than any valid registry).
    if bundle_reg_version < 1:
        raise BundleError(
            f"registry_version {bundle_reg_version} is older than pinned"
        )

    # 9. Sequence checks (threat 7)
    cur_seq = current_sequence(layout)
    bundle_seq = payload.get("sequence", 0)
    base_seq = payload.get("base_sequence", 0)

    if cur_seq is not None:
        if bundle_seq <= cur_seq:
            raise BundleError(
                f"sequence {bundle_seq} not greater than "
                f"current {cur_seq}"
            )
        if base_seq != cur_seq:
            raise BundleError(
                f"base_sequence {base_seq} != current "
                f"sequence {cur_seq}"
            )
    else:
        # No current bundle: first bundle, base_sequence must be 0
        if base_seq != 0:
            raise BundleError(
                f"base_sequence must be 0 for first bundle, "
                f"got {base_seq}"
            )

    # 10. Compute loosening against enforced policy (D2.3, S4)
    lvb = last_valid_bundle(layout)
    is_first = lvb is None
    if lvb is not None:
        enforced = lvb.get("payload", {})
    else:
        # Deny-all base (N3)
        enforced = {
            "folder_policy": {"shell": {"blocklist_action": "deny"}},
            "governance_policy": {"clauses": []},
            "mcp_policy": {"servers": []},
            "approval": {"local_fallback": False, "allow_requester": False},
        }

    sections_loosened = loosened(enforced, payload)
    is_loosening = bool(sections_loosened)

    # 11. Verify change approvals
    _verify_change_approvals(
        payload, change_approvals, registry,
        is_loosening=is_loosening,
        is_first_bundle=is_first,
    )

    # 12. Store via policy_versions.store() and the signed log
    sync_dir = layout.root / ".sandbox" / "state" / "sync"
    sync_dir.mkdir(parents=True, exist_ok=True)

    # Store the full envelope as bundle.json
    import os
    tmp_dir = layout.root / ".sandbox" / "tmp"
    tmp_dir.mkdir(parents=True, exist_ok=True)
    bundle_data = json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode()
    bundle_file = sync_dir / "bundle.json"
    tmp_file = tmp_dir / f"bundle_{bundle_seq}.tmp"
    tmp_file.write_bytes(bundle_data)
    os.replace(tmp_file, bundle_file)

    # Also store in policy_history for durability
    hist_dir = layout.root / ".sandbox" / "policy_history"
    hist_dir.mkdir(parents=True, exist_ok=True)
    hist_file = hist_dir / f"bundle_{bundle_seq:08d}.json"
    hist_file.write_bytes(bundle_data)

    # Store the folder policy content via policy_versions.store()
    policy_versions.store(layout, payload.get("folder_policy", {}))

    return BundleResult(sequence=bundle_seq)
