"""The one approval path for every approver surface (CLI, watch, REST API, remote).

Dual control is enforced here, so no surface can skip it. A request flagged
``requires_dual`` (critical risk, command exfiltration) needs two approvals:

1. The first approver signs an approval with their own key; the request goes
   back to pending, marked 1 of 2. Nothing runs.
2. A second approval runs it only if it comes from a different reviewer id
   with a different key. Both signed approvals are kept in the done-record,
   which the second approver signs as a whole.

Each step claims the request first (an atomic rename), so two approvers
can't race. A denial needs only one reviewer: denying is the safe direction.

Remote approvals (T12, ``apply_external``) go through the same claim/dual/
execute/finish path.  They are verified against the pinned registry and the
fixed D5.6 field set, and they never mix with local approvals for dual
control (D6.3, S7).

Limit: two distinct reviewer ids and keys are enforced, not that they are two
different people; keys live in the control plane (docs/TCB.md). Binding them
to humans needs per-person credentials (HSM, SSO).
"""
from __future__ import annotations

import hashlib
import json
import time
from typing import Any, Callable

from sandbox.connector.layout import FolderLayout
from sandbox.connector.queue import EscalationQueue


def default_reviewer() -> str:
    import getpass
    import os

    return os.environ.get("SANDBOX_REVIEWER") or getpass.getuser() or "cli"


def _valid_for(approval: dict[str, Any], record: dict[str, Any], layout: FolderLayout | None = None) -> bool:
    from sandbox.connector.signing import verify_approval

    if not (verify_approval(approval)
            and all(approval.get(k) == record.get(k) for k in ("request_id", "command", "fingerprint"))):
        return False
    # SEC-30: live decision paths require domain-tagged signatures (sig_v: 1).
    # A legacy (untagged) approval is rejected even when it crypto-verifies.
    if approval.get("sig_v") != 1:
        return False
    # ADR 0007 2.5: check approval against pinned key, not embedded key.
    # Derive layout from the record's root when not given explicitly.
    effective_layout = layout
    if effective_layout is None:
        root = record.get("root")
        if root:
            from pathlib import Path

            root_path = Path(root)
            if root_path.is_dir() and (root_path / ".sandbox").is_dir():
                effective_layout = FolderLayout(root_path)
    if effective_layout is not None:
        from sandbox.connector import keyhome

        try:
            reviewer_id = approval.get("reviewer_id")
            pinned = keyhome.get_pinned_key(effective_layout, reviewer_id)
            if pinned is None:
                return False  # unpinned key: invalid
            if approval.get("signer_public_key") != pinned:
                return False  # key mismatch: invalid
        except keyhome.KeyHomeError:
            return False  # key home unavailable: fail closed
    return True


async def approve(layout: FolderLayout, request_id: str, reviewer_id: str, reason: str = "") -> dict[str, Any]:
    """Approve a pending request. Returns {"status": ...}:

    executed        it ran (or, for a tool_call, the grant was issued); "result" holds the done-record
    awaiting_second first of two approvals recorded; nothing ran
    same_reviewer   refused: this reviewer (or key) already gave the first approval
    reason_required refused: reviewer flagged for approval fatigue gave no written reason
    not_pending     no such pending request (taken, finished or unknown)
    key_unavailable refused: the key home cannot be resolved or written, so nothing can be
                    signed and nothing runs (ADR 0007 1.3); "reason" says why
    managed_refused refused: managed workspace, local approve not allowed (S7, D6.3)

    Approval fatigue (connector/oversight.py) only adds scrutiny: a flagged
    reviewer must give a reason, and their approval of an ordinary request
    makes it dual control. The outcome then carries an "oversight" entry.
    """
    from sandbox.connector.broker import FolderBroker
    from sandbox.connector.oversight import check_approval
    from sandbox.connector.keyhome import KeyHomeError, NotEnrolledError
    from sandbox.connector.signing import _pin_and_audit, ensure_signing_key, sign_approval

    # S7 / D6.3: in managed mode, refuse local approve() unless the SIGNED
    # bundle sets approval.local_fallback.  The enforced_approval is read
    # from the bundle (hook_eval ~282), never from the on-disk policy.json.
    try:
        from sandbox.connector.sync.state import is_managed as _is_managed
        if _is_managed(layout):
            # Read the enforced approval from the bundle, not on-disk policy
            _enforced = _get_enforced_approval(layout)
            if not _enforced.get("local_fallback", False):
                return {"status": "managed_refused",
                        "reason": "managed workspace: local approve not allowed "
                                  "unless the signed bundle sets approval.local_fallback"}
    except ImportError:
        pass  # sync module not available; not managed

    # Fail closed before anything is claimed or run: an approval that cannot be signed is invalid.
    try:
        pub_hex = ensure_signing_key(layout, reviewer_id)
    except KeyHomeError as exc:
        return {"status": "key_unavailable", "reason": str(exc)}

    # ADR 0007 2.2: pin the key on first use from a human surface (CLI/REST API approve).
    # ADR 0007 2.4: _pin_and_audit raises NotEnrolledError under keys.enrol: explicit
    # for an unpinned reviewer; that is the single enforcement point.
    # Fail closed: if the audit record cannot be written, the pin is not created
    # and the approval is refused (mirrors _audit_rotation).
    try:
        _pin_and_audit(layout, reviewer_id, pub_hex)
    except NotEnrolledError as exc:
        return {"status": "not_enrolled", "reason": str(exc)}
    except KeyHomeError as exc:
        return {"status": "key_unavailable", "reason": str(exc)}

    queue = EscalationQueue(layout)
    rec = queue.claim(request_id, reviewer_id)
    if rec is None:
        return {"status": "not_pending"}
    approved_at = time.time()

    oversight = check_approval(layout, rec, reviewer_id, reason)
    extra = {"oversight": oversight} if oversight else {}
    if oversight and oversight["reason_required"]:
        queue.release(request_id, rec)
        return {"status": "reason_required", **extra}
    if oversight and oversight["second_reviewer"]:
        rec["requires_dual"] = True
        rec["dual_reason"] = "approval_fatigue"

    # Only approvals that verify AND are for exactly this request count: an
    # altered approval, or a request changed after it was approved, drops out.
    approvals = [a for a in rec.get("approvals") or [] if _valid_for(a, rec, layout)]
    if rec.get("requires_dual"):
        mine = sign_approval(layout, reviewer_id, rec, time.time())
        if any(a.get("reviewer_id") == reviewer_id or a.get("signer_public_key") == mine["signer_public_key"]
               for a in approvals):
            queue.release(request_id, rec)
            return {"status": "same_reviewer", "approvals": len(approvals), **extra}
        approvals.append(mine)
        if len(approvals) < 2:
            queue.release(request_id, rec | {"approvals": approvals})
            queue._activity(f"APPROVED 1/2  {request_id}  by {reviewer_id}  (dual control: needs a second reviewer)")
            return {"status": "awaiting_second", "approvals": len(approvals), **extra}

    result = await FolderBroker().execute(rec, reviewer_id, reason)
    result.setdefault("approved_at", approved_at)
    if approvals:
        result["approvals"] = approvals
        result["requires_dual"] = True
    queue.finish(request_id, result)
    return {"status": "executed", "result": result, **extra}


# ---------------------------------------------------------------------------
# Managed-mode helpers (T12)
# ---------------------------------------------------------------------------


def _get_enforced_approval(layout: FolderLayout) -> dict[str, Any]:
    """Read the approval section from the enforced bundle, never from on-disk policy.

    A hand-edited ``local_fallback`` or ``allow_requester`` in ``policy.json``
    is never honoured (N5, S7).  Only the signed bundle's value counts.
    """
    from sandbox.connector.sync.state import last_valid_bundle

    bundle = last_valid_bundle(layout)
    if bundle is None:
        return {}
    payload = bundle.get("payload", {})
    return payload.get("approval", {})


def _verify_registry_for_approvals(
    layout: FolderLayout,
    envelopes: list[dict[str, Any]] | None,
) -> Any:
    """Verify a registry chain against the pinned root and return a Registry.

    Re-verifies on every call (ruling-A precedent: re-verify on every
    enforcement).  Returns ``None`` if there is no pin, the chain is
    missing or corrupt, or verification fails.  Never trusts a chain
    as-is, whether from the caller or from disk.
    """
    from sandbox.protocol.registry import verify_chain, RegistryError
    from sandbox.protocol.envelope import EnvelopeError
    from sandbox.connector.sync.state import pinned_root

    fp = pinned_root(layout)
    if fp is None:
        return None  # no pin: can't verify

    chain = envelopes
    if chain is None:
        # Read from disk
        try:
            sync_dir = layout.root / ".sandbox" / "state" / "sync"
            reg_file = sync_dir / "registry.json"
            if reg_file.exists():
                chain = json.loads(reg_file.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None

    if not chain or not isinstance(chain, list):
        return None

    try:
        return verify_chain(chain, fp)
    except Exception:
        return None  # F3: any parse/verify failure → fail closed (no approvals, no denies counted)


# -- Skew measurement (F1) --------------------------------------------------

def _measure_skew(layout: FolderLayout, clock_fn: Callable[[], float]) -> float | None:
    """Estimate clock skew from the best available server time reference.

    Returns the estimated skew in seconds, or ``None`` if no measurement
    is available.

    Primary source: ``server_time_state.json`` written by
    ``sync/process.py`` on every HTTP response with a ``Date`` header.
    The server's time now is estimated as ``server_time`` plus the wall
    time elapsed since the measurement, and compared with the connector
    clock (``clock_fn``).  With ``clock_fn = time.time`` this equals
    ``|local_time - server_time|``.  There is no fallback (F8).
    """
    from sandbox.connector.sync.state import read_server_time_state

    sts = read_server_time_state(layout)
    if sts is not None:
        server_now = sts["server_time"] + (time.time() - sts["local_time"])
        return abs(clock_fn() - server_now)

    # No server-time record: no measurement.  A bundle's issued_at is not
    # a skew proxy (it measures bundle age), so there is no fallback; the
    # managed-mode caller fails closed on None (F8).
    return None


# -- Nonce persistence (F2) -------------------------------------------------

def _load_seen_nonces(layout: FolderLayout) -> tuple[dict[str, float], bool]:
    """Load persisted nonces from disk.

    Returns ``(nonce_dict, corrupt_flag)``.  ``nonce_dict`` maps
    nonce -> ``not_after``.  If the file is corrupt, returns
    ``({}, True)``; the caller must refuse all approvals (fail closed).
    A missing file is normal on first use and returns ``({}, False)``.
    """
    sync_dir = layout.root / ".sandbox" / "state" / "sync"
    nonce_file = sync_dir / "seen_nonces.json"
    if not nonce_file.exists():
        return {}, False
    try:
        data = json.loads(nonce_file.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            return {}, True
        # Values must be numeric
        for v in data.values():
            if not isinstance(v, (int, float)):
                return {}, True
        return data, False
    except (OSError, ValueError):
        return {}, True


def _save_seen_nonces(
    layout: FolderLayout,
    nonces: dict[str, float],
    clock_fn: Callable[[], float],
) -> None:
    """Save seen nonces to disk (atomic temp-file + rename).

    Prunes entries past ``not_after + 2 min grace``.
    """
    import os

    now = clock_fn()
    pruned = {n: na for n, na in nonces.items() if now <= na + _NOT_AFTER_GRACE_S}
    sync_dir = layout.root / ".sandbox" / "state" / "sync"
    nonce_file = sync_dir / "seen_nonces.json"
    tmp = sync_dir / "seen_nonces.json.tmp"
    try:
        sync_dir.mkdir(parents=True, exist_ok=True)
        tmp.write_text(
            json.dumps(pruned, separators=(",", ":")),
            encoding="utf-8",
        )
        os.replace(str(tmp), str(nonce_file))
    except Exception:  # noqa: BLE001
        try:
            tmp.unlink(missing_ok=True)
        except Exception:  # noqa: BLE001
            pass


# -- Fixed D5.6 remote-approval field set -----------------------------------

_REMOTE_APPROVAL_FIELDS = frozenset({
    "request_id", "command", "fingerprint", "reviewer_id", "decision",
    "approved_at", "org_id", "project_id", "device_id",
    "registry_version", "policy_sequence", "user_id", "key_id",
    "nonce", "not_after",
})

# Grace period for not_after expiry (D4.1)
_NOT_AFTER_GRACE_S = 120  # 2 minutes

# Clock skew threshold (D4.3, S15)
_SKEW_THRESHOLD_S = 120  # 2 minutes


def _verify_remote_approval(
    envelope: dict[str, Any],
    registry: Any,
    *,
    policy_sequence: int,
    environment: str,
    operator_user_id: str | None,
    enforced_approval: dict[str, Any] | None,
    clock: Callable[[], float],
    seen_nonces: dict[str, float],
) -> dict[str, Any] | None:
    """Verify one remote approval envelope.  Returns the parsed approval
    dict with ``user_id``, ``iss``, ``sub``, ``key_kind`` on success,
    or ``None`` if the approval must be dropped.
    """
    from sandbox.protocol.domains import REMOTE_APPROVAL

    # 1. Tag check
    if envelope.get("kind") != "agg/remote-approval/v1":
        return None

    payload = envelope.get("payload")
    if not isinstance(payload, dict):
        return None

    # 2. Field-set check
    payload_keys = frozenset(payload.keys())
    if not _REMOTE_APPROVAL_FIELDS.issubset(payload_keys):
        return None

    # 3. Signature verification
    sigs = envelope.get("signatures", [])
    if not sigs:
        return None
    sig_entry = sigs[0]
    key_id = sig_entry.get("key_id", "")

    # Look up key in the registry
    entry = registry._keys.get(key_id) if registry is not None else None
    if entry is None:
        return None

    # 4. Kind matrix: device and bundle-signer keys refused (D5.1, threat 31)
    key_kind = entry.get("kind", "")
    if key_kind in ("device", "bundle-signer"):
        return None

    # 5. Approver role required
    roles = entry.get("roles", [])
    if "approver" not in roles and "admin" not in roles:
        return None

    # 6. Prod refusal for all key kinds in M2 (N9, threat 36)
    effective_env = environment if environment else "prod"
    decision = payload.get("decision", "approve")
    if not registry.may_sign(key_id, REMOTE_APPROVAL, effective_env, decision=decision):
        # may_sign returns False for prod approvals; denies are still allowed
        if decision == "approve":
            return None

    # 7. policy_sequence must match (D5.6, threat 13)
    if payload.get("policy_sequence") != policy_sequence:
        return None

    # 7b. Removed: the old code compared clock() with the signer-controlled
    # approved_at.  F1 fix: skew is now measured at the apply_external level
    # against the server-provided time (from sync replies or bundle issued_at).
    # The per-approval check is removed entirely; apply_external drops all
    # approvals when measured skew > _SKEW_THRESHOLD_S.

    # 8. not_after expiry + 2 min grace (D4.1)
    now = clock()
    not_after = payload.get("not_after")
    if not_after is not None and decision == "approve":
        if now > not_after + _NOT_AFTER_GRACE_S:
            return None

    # 9. Nonce replay (D4.1, threat 13) -- F2: uses a persistent dict
    # Recorded only after the signature verifies (step 11), so a forged
    # envelope cannot burn a real approval's nonce (F6).
    nonce = payload.get("nonce", "")
    if nonce in seen_nonces:
        return None

    # 10. Operator exclusion (D6.4, threat 28)
    user_id = payload.get("user_id", "")
    ea = enforced_approval or {}
    if operator_user_id and user_id == operator_user_id:
        if not ea.get("allow_requester", False):
            return None

    # 11. Crypto verification
    try:
        from nacl.signing import VerifyKey

        pub_hex = entry.get("public_key", "")
        vk = VerifyKey(bytes.fromhex(pub_hex))
        tag = REMOTE_APPROVAL.encode("utf-8")
        canonical = json.dumps(
            payload, sort_keys=True, separators=(",", ":")
        ).encode()
        msg = tag + b"\x00" + canonical
        sig_bytes = bytes.fromhex(sig_entry.get("sig", ""))
        vk.verify(msg, sig_bytes)
    except Exception:
        return None

    not_after_val = payload.get("not_after", 0)
    seen_nonces[nonce] = not_after_val if isinstance(not_after_val, (int, float)) else 0

    return {
        "user_id": user_id,
        "key_id": key_id,
        "iss": entry.get("iss", ""),
        "sub": entry.get("sub", ""),
        "key_kind": key_kind,
        "decision": decision,
        "envelope": envelope,
    }


def _find_pending(layout: FolderLayout, request_id: str) -> Any:
    """Find a pending record across both standard and sync pending directories.

    The EscalationQueue pending dir is ``.sandbox/escalations/pending/``.
    The sync process writes to ``.sandbox/pending/`` (flat).  This helper
    checks both so that ``apply_external`` works regardless of which path
    the record was created through.
    """
    import os
    from pathlib import Path

    candidates = [
        layout.root / ".sandbox" / "pending" / f"{request_id}.json",
        layout.pending_dir / f"{request_id}.json",
    ]
    for p in candidates:
        if p.is_file():
            return p
    return None


def _claim_pending(layout: FolderLayout, request_id: str) -> tuple[Any, Any] | None:
    """Atomically claim a pending record.  Returns (record_dict, done_path) or None."""
    import os

    src = _find_pending(layout, request_id)
    if src is None:
        return None

    # Claim by atomic rename into a claimed dir
    claimed_dir = src.parent.parent / "claimed"
    claimed_dir.mkdir(parents=True, exist_ok=True)
    dst = claimed_dir / src.name
    try:
        os.rename(src, dst)
    except OSError:
        return None

    try:
        rec = json.loads(dst.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None

    # Return the record and the source parent (for done dir resolution)
    return rec, dst


def _finish_external(
    layout: FolderLayout,
    request_id: str,
    claimed_path: Any,
    result: dict[str, Any],
) -> None:
    """Move a claimed record to done (terminal)."""
    import os

    done_dir = claimed_path.parent.parent / "done"
    done_dir.mkdir(parents=True, exist_ok=True)
    done_path = done_dir / f"{request_id}.json"
    result.setdefault("request_id", request_id)
    result.setdefault("decided_at", time.time())
    claimed_path.write_text(
        json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    os.replace(claimed_path, done_path)


def _release_external(
    layout: FolderLayout,
    request_id: str,
    claimed_path: Any,
    record: dict[str, Any],
) -> None:
    """Move a claimed record back to pending (for awaiting_second)."""
    import os

    pending_dir = claimed_path.parent.parent / "pending"
    pending_dir.mkdir(parents=True, exist_ok=True)
    dst = pending_dir / f"{request_id}.json"
    # Strip claim metadata
    record.pop("reviewer_id", None)
    record.pop("claimed_at", None)
    claimed_path.write_text(
        json.dumps(record, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    os.replace(claimed_path, dst)


async def apply_external(
    layout: FolderLayout,
    request_id: str,
    approvals: list[dict[str, Any]],
    *,
    registry: list[dict[str, Any]] | None = None,
    policy_sequence: int | None = None,
    environment: str | None = None,
    operator_user_id: str | None = None,
    enforced_approval: dict[str, Any] | None = None,
    clock: Callable[[], float] | None = None,
) -> dict[str, Any]:
    """Apply remote decisions to a pending escalation (D6.3, T12 TCB).

    Reuses the ``approve()`` path: claim, dual check, FolderBroker.execute,
    finish.  Drops every approval that is not a registry-verified
    ``agg/remote-approval/v1`` with the exact D5.6 field set.

    A mix of local and remote approvals never meets dual control (S7, threat 27).
    One approval out of two needed runs nothing (D6.4).
    A deny needs one valid signed decision (D6.5).

    Returns ``{"status": ...}`` like ``approve()``.
    """
    from sandbox.connector.broker import FolderBroker

    effective_clock = clock or time.time

    # Verify the registry chain against the pinned root on every call
    # (ruling-A precedent: re-verify on every enforcement).  Never trust
    # a chain as-is.  Returns None if verification fails.
    reg = _verify_registry_for_approvals(layout, registry)

    # Determine environment from bundle if not provided
    effective_env = environment
    if effective_env is None:
        effective_env = "prod"  # D2.4: absent = prod

    # Determine enforced approval from bundle if not provided
    effective_ea = enforced_approval
    if effective_ea is None:
        effective_ea = _get_enforced_approval(layout)

    # Determine policy_sequence from bundle if not provided
    effective_seq = policy_sequence
    if effective_seq is None:
        from sandbox.connector.sync.state import current_sequence
        effective_seq = current_sequence(layout) or 0

    # F2: Load persisted nonces for cross-call replay detection.
    seen_nonces, nonces_corrupt = _load_seen_nonces(layout)

    # Verify each remote approval against the registry
    valid_approvals: list[dict[str, Any]] = []
    valid_denies: list[dict[str, Any]] = []

    if nonces_corrupt:
        # F2 fail-closed: corrupt nonce file means we cannot tell which
        # nonces have been used.  Refuse all approvals; denies bypass
        # nonce check so we still process them below.
        for a in approvals:
            verified = _verify_remote_approval(
                a, reg,
                policy_sequence=effective_seq,
                environment=effective_env,
                operator_user_id=operator_user_id,
                enforced_approval=effective_ea,
                clock=effective_clock,
                seen_nonces=seen_nonces,
            )
            if verified is not None and verified["decision"] == "deny":
                valid_denies.append(verified)
    else:
        for a in approvals:
            verified = _verify_remote_approval(
                a, reg,
                policy_sequence=effective_seq,
                environment=effective_env,
                operator_user_id=operator_user_id,
                enforced_approval=effective_ea,
                clock=effective_clock,
                seen_nonces=seen_nonces,
            )
            if verified is None:
                continue
            if verified["decision"] == "deny":
                valid_denies.append(verified)
            else:
                valid_approvals.append(verified)

    # F2: Persist nonces after verification (atomic write, prune expired).
    _save_seen_nonces(layout, seen_nonces, effective_clock)

    # F1: Skew check — measured against server time, not signer-controlled
    # approved_at.  Skew > 2 min refuses approvals; denies still apply.
    measured_skew = _measure_skew(layout, effective_clock)
    if measured_skew is not None and measured_skew > _SKEW_THRESHOLD_S:
        if valid_approvals:
            from sandbox.connector.policy_versions import audit as _audit
            _audit(layout, {
                "event": "clock_skew", "ts": time.time(),
                "reason_code": "CLOCK_SKEW", "request_id": request_id,
                "skew_s": round(measured_skew, 1),
                "reason": "clock skew over 2 min; remote approvals refused, "
                          "denies still apply (D4.3)",
            })
        valid_approvals.clear()  # drop all approvals
    elif measured_skew is None:
        # No measurement: in managed mode, fail closed for approvals.
        from sandbox.connector.sync.state import is_managed as _check_managed
        if _check_managed(layout):
            valid_approvals.clear()

    # Deny needs only one valid signed decision (D6.5)
    if valid_denies:
        claimed = _claim_pending(layout, request_id)
        if claimed is None:
            return {"status": "not_pending"}
        rec, claimed_path = claimed
        result = {
            "request_id": request_id,
            "decision": "deny",
            "state": "denied",
            "reviewer_id": valid_denies[0]["user_id"],
            "command": rec.get("command", ""),
            "fingerprint": rec.get("fingerprint", ""),
        }
        _finish_external(layout, request_id, claimed_path, result)
        return {"status": "denied"}

    # Registry expired: refuse approvals (D8, D6.5)
    if reg is not None and time.time() > reg._expires_at:
        return {"status": "awaiting_second", "approvals": 0}

    # Dedup by user_id: one user_id with two keys counts once (D5.6, threat 14)
    seen_users: dict[str, dict[str, Any]] = {}
    deduped: list[dict[str, Any]] = []
    for va in valid_approvals:
        uid = va["user_id"]
        if uid in seen_users:
            continue
        seen_users[uid] = va
        deduped.append(va)

    # Dedup by (iss, sub): distinct identities required (threat 14)
    seen_identity: dict[tuple[str, str], str] = {}
    identity_deduped: list[dict[str, Any]] = []
    for va in deduped:
        iss_sub = (va["iss"], va["sub"])
        if iss_sub in seen_identity:
            continue
        seen_identity[iss_sub] = va["user_id"]
        identity_deduped.append(va)

    # S9: single_admin_registry keys don't count for dual control
    dual_eligible: list[dict[str, Any]] = []
    for va in identity_deduped:
        if reg is not None and not reg.counts_for_dual(va["key_id"]):
            continue
        dual_eligible.append(va)

    # Claim the pending record
    claimed = _claim_pending(layout, request_id)
    if claimed is None:
        return {"status": "not_pending"}
    rec, claimed_path = claimed

    requires_dual = rec.get("requires_dual", True)
    if requires_dual and len(dual_eligible) < 2:
        # Release back to pending with the count
        _release_external(layout, request_id, claimed_path, rec)
        return {"status": "awaiting_second", "approvals": len(dual_eligible)}

    # A single approval may come from a single_admin_registry key (S9).
    # Nothing runs without at least one valid approval (F7).
    approvers = dual_eligible if requires_dual else identity_deduped
    if not approvers:
        _release_external(layout, request_id, claimed_path, rec)
        return {"status": "awaiting_second", "approvals": 0}

    # Execute via the broker (reuses the approve() path)
    reviewer_id = approvers[0]["user_id"]
    result = await FolderBroker().execute(rec, reviewer_id, "")
    result.setdefault("approved_at", time.time())
    result["remote_approvals"] = [d["envelope"] for d in approvers]
    result["requires_dual"] = requires_dual
    _finish_external(layout, request_id, claimed_path, result)
    return {"status": "executed", "result": result}
