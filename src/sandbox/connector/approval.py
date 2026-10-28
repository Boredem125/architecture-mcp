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

T12b (ADR 0010): binding fingerprint, request_id validation, verified-state
accessor, nonce redesign with (key_id, nonce) scope, done-record signing
through queue.finish with connector:<device_id> key, and removal of trust
kwargs (F1=A).

Limit: two distinct reviewer ids and keys are enforced, not that they are two
different people; keys live in the control plane (docs/TCB.md). Binding them
to humans needs per-person credentials (HSM, SSO).
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import re
import time
from typing import Any, Callable

from sandbox.connector.layout import FolderLayout
from sandbox.connector.queue import EscalationQueue


# ---------------------------------------------------------------------------
# H3: strict request_id regex (ADR 0010 s3)
# ---------------------------------------------------------------------------
_REQUEST_ID_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9_-]{0,127}\Z")


# ---------------------------------------------------------------------------
# H1: binding fingerprint (ADR 0010 s1, C4)
# ---------------------------------------------------------------------------
def _binding_fingerprint(record: dict[str, Any]) -> str:
    """Compute the binding fingerprint for a pending record.

    sha256(canonical{kind, tool_name, command, exec_cwd, root,
                     requires_dual, bundle_sequence, request_id,
                     fp_v, script, script_unbound, preview_sha256})

    T12c (ADR 0010 s9 9.2): adds fp_v, script, script_unbound and
    script_preview.sha256 to the canonical object.  The preview's hash
    is covered, not its text.  tool_name (which sets the shell family) is
    already covered.  There is no v1 fallback.
    """
    # Extract preview sha256 (covers the preview hash, not text)
    _preview = record.get("script_preview")
    _preview_sha = ""
    if isinstance(_preview, dict):
        _preview_sha = _preview.get("sha256", "")

    binding_data = json.dumps({
        "kind": record.get("kind", ""),
        "tool_name": record.get("tool_name", ""),
        "command": record.get("command", ""),
        "exec_cwd": record.get("exec_cwd", ""),
        "root": record.get("root", ""),
        "requires_dual": record.get("requires_dual", True),
        "bundle_sequence": record.get("bundle_sequence", 0),
        "request_id": record.get("request_id", ""),
        "fp_v": record.get("fp_v", None),
        "script": record.get("script", None),
        "script_unbound": record.get("script_unbound", ""),
        "preview_sha256": _preview_sha,
    }, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(binding_data).hexdigest()


def default_reviewer() -> str:
    import getpass

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
    # from the verified bundle (H2: via verified_state), never on-disk policy.
    try:
        from sandbox.connector.sync.state import is_managed as _is_managed
        if _is_managed(layout):
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
    # T12c: a refusal from the broker (SCRIPT_CHANGED, SHELL_UNAVAILABLE) is
    # terminal; return its state rather than "executed".
    broker_state = result.get("state", "executed")
    if broker_state == "refused":
        return {"status": broker_state, "result": result, **extra}
    return {"status": "executed", "result": result, **extra}


# ---------------------------------------------------------------------------
# Managed-mode helpers (T12, T12b)
# ---------------------------------------------------------------------------


def _get_enforced_approval(layout: FolderLayout) -> dict[str, Any]:
    """Read the approval section from the verified bundle, never from on-disk policy.

    H2 fix (ADR 0010 s2): uses _verified_bundle_payload (verified against
    the pinned root), never last_valid_bundle.  A hand-edited
    local_fallback or allow_requester in the on-disk files or policy.json
    is never honoured (N5, S7).
    """
    from sandbox.connector.policy_versions import _verified_bundle_payload

    payload = _verified_bundle_payload(layout)
    if payload is None:
        return {}
    return payload.get("approval", {})


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


# -- Nonce persistence (C1-C3, ADR 0010 s4) --------------------------------
# Replay key is (key_id, nonce) -> {request_id, payload_sha256, not_after}.

def _load_seen_nonces(layout: FolderLayout) -> tuple[dict[str, dict[str, Any]], bool]:
    """Load persisted nonces from disk.

    Returns ``(nonce_dict, corrupt_flag)``.  ``nonce_dict`` maps
    ``"key_id:nonce"`` -> ``{request_id, payload_sha256, not_after}``.
    If the file is corrupt, returns ``({}, True)``; the caller must
    refuse all approvals (fail closed).
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
        # Validate entries: old float-valued entries count as replays (fail closed)
        result: dict[str, dict[str, Any]] = {}
        for k, v in data.items():
            if isinstance(v, dict) and "request_id" in v and "not_after" in v:
                result[k] = v
            elif isinstance(v, (int, float)):
                # Old format: treat as replay (fail closed per ADR 0010)
                result[k] = {"request_id": "__old__", "payload_sha256": "", "not_after": v}
            else:
                return {}, True
        return result, False
    except (OSError, ValueError):
        return {}, True


def _save_seen_nonces(
    layout: FolderLayout,
    nonces: dict[str, dict[str, Any]],
    clock_fn: Callable[[], float],
) -> bool:
    """Save seen nonces to disk (atomic temp-file + rename).

    C1: write-ahead -- the caller must NOT claim or execute if this returns False.
    C2: prunes entries past ``not_after + grace``.
    Returns True on success, False if the save failed.
    """
    # L C7: prune with real time, not the injected clock
    now = max(clock_fn(), time.time())
    pruned: dict[str, dict[str, Any]] = {}
    for k, v in nonces.items():
        na = v.get("not_after", 0)
        if isinstance(na, (int, float)) and now <= na + _NOT_AFTER_GRACE_S:
            pruned[k] = v
    sync_dir = layout.root / ".sandbox" / "state" / "sync"
    nonce_file = sync_dir / "seen_nonces.json"
    tmp = sync_dir / "seen_nonces.json.tmp"
    try:
        sync_dir.mkdir(parents=True, exist_ok=True)
        tmp.write_text(
            json.dumps(pruned, separators=(",", ":")),
            encoding="utf-8",
        )
        # fsync for durability; best-effort on Windows
        try:
            fd = os.open(str(tmp), os.O_RDWR)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        except OSError:
            pass  # fsync failure is not fatal on Windows
        os.replace(str(tmp), str(nonce_file))
        return True
    except Exception:  # noqa: BLE001
        try:
            tmp.unlink(missing_ok=True)
        except Exception:  # noqa: BLE001
            pass
        return False


def _check_nonce(
    seen_nonces: dict[str, dict[str, Any]],
    key_id: str,
    nonce: str,
    request_id: str,
    payload_sha256: str,
    not_after: float,
) -> bool:
    """Check a (key_id, nonce) pair and return True if accepted.

    ADR 0010 s4: the replay key is (key_id, nonce).  A re-send for the
    same request_id with the same payload_sha256 is idempotent (counted
    once).  Any other use is a replay and is dropped.
    """
    nonce_key = f"{key_id}:{nonce}"
    existing = seen_nonces.get(nonce_key)
    if existing is not None:
        # Same request_id and payload hash -> idempotent re-delivery
        if (existing.get("request_id") == request_id
                and existing.get("payload_sha256") == payload_sha256):
            return True
        # Different request or payload -> replay
        return False
    # New entry
    seen_nonces[nonce_key] = {
        "request_id": request_id,
        "payload_sha256": payload_sha256,
        "not_after": not_after,
    }
    return True


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
    seen_nonces: dict[str, dict[str, Any]],
    pending_record: dict[str, Any] | None = None,
    device_id: str = "",
    project_id: str = "",
    org_id: str = "",
) -> dict[str, Any] | None:
    """Verify one remote approval envelope.  Returns the parsed approval
    dict with ``user_id``, ``iss``, ``sub``, ``key_kind`` on success,
    or ``None`` if the approval must be dropped.

    T12b: uses registry user_id (not payload), checks binding, validates
    not_after is required and finite (M1), uses (key_id, nonce) scope.
    """
    from sandbox.protocol.domains import REMOTE_APPROVAL

    # L2: type-check each envelope; drop a bad one
    if not isinstance(envelope, dict):
        return None

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

    # 3. Signature: exactly one, and it must be in the registry
    sigs = envelope.get("signatures", [])
    if not isinstance(sigs, list) or len(sigs) != 1:
        return None
    sig_entry = sigs[0]
    if not isinstance(sig_entry, dict):
        return None
    sig_key_id = sig_entry.get("key_id", "")

    # Check payload.key_id == signatures[0].key_id
    if payload.get("key_id") != sig_key_id:
        return None

    # Look up key in the registry
    if registry is None:
        return None
    entry = registry._keys.get(sig_key_id)
    if entry is None:
        return None

    # R3a: a key removed in a signed later registry version is not in the
    # latest version's key map (the Registry now uses only the latest keys).
    # The dead "status" check is removed: the schema has no status field;
    # revocation means the key is absent from the latest version.

    # 4. Kind matrix: device and bundle-signer keys refused (D5.1, threat 31)
    key_kind = entry.get("kind", "")
    if key_kind in ("device", "bundle-signer"):
        return None

    # 5. Approver role required
    roles = entry.get("roles", [])
    if "approver" not in roles and "admin" not in roles:
        return None

    # H1: user_id from registry entry, not payload (ADR 0010 s1)
    registry_user_id = entry.get("user_id", "")

    # H1: payload.user_id must match registry entry user_id
    payload_user_id = payload.get("user_id", "")
    if payload_user_id != registry_user_id:
        return None

    # 6. Prod refusal for all key kinds in M2 (N9, threat 36)
    effective_env = environment if environment else "prod"
    decision = payload.get("decision", "approve")
    if decision not in ("approve", "deny"):
        return None
    if not registry.may_sign(sig_key_id, REMOTE_APPROVAL, effective_env, decision=decision):
        if decision == "approve":
            return None

    # 7. policy_sequence must match (D5.6, threat 13)
    if payload.get("policy_sequence") != policy_sequence:
        return None

    # M1: not_after must be a finite int/float (ADR 0010)
    not_after = payload.get("not_after")
    if not isinstance(not_after, (int, float)):
        return None
    if math.isinf(not_after) or math.isnan(not_after):
        return None

    # 8. not_after expiry + 2 min grace (D4.1)
    # L C7: use the later of clock() and real time (a test clock in the past
    # must not make an expired envelope look valid)
    now = max(clock(), time.time())
    if decision == "approve":
        if now > not_after + _NOT_AFTER_GRACE_S:
            return None

    # M1: nonce must be a non-empty string of at most 128 chars
    nonce = payload.get("nonce", "")
    if not isinstance(nonce, str) or not nonce or len(nonce) > 128:
        return None

    # 11. Crypto verification (before recording nonce -- F6)
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

    # Compute payload_sha256 for nonce dedup
    canonical_payload = json.dumps(
        payload, sort_keys=True, separators=(",", ":")
    ).encode()
    payload_sha256 = hashlib.sha256(canonical_payload).hexdigest()

    # 9. Nonce replay with (key_id, nonce) scope (C1-C3, ADR 0010 s4)
    if not _check_nonce(seen_nonces, sig_key_id, nonce,
                        payload.get("request_id", ""), payload_sha256,
                        not_after):
        # Deny still wins even if nonce conflicts
        if decision == "deny":
            pass  # let it through
        else:
            return None

    # 10. Operator exclusion (D6.4, threat 28) -- uses registry user_id
    ea = enforced_approval or {}
    if operator_user_id and registry_user_id == operator_user_id:
        if not ea.get("allow_requester", False):
            return None

    # H1 binding checks (ADR 0010 s1, C4)
    if pending_record is not None:
        # R1: recompute the binding fingerprint from the record -- never trust
        # the stored value (an attacker who edits exec_cwd/root/kind after
        # stamping can bypass binding if we compare to the stored hash).
        recomputed_fp = _binding_fingerprint(pending_record)
        if not recomputed_fp:
            return None
        # payload.request_id must match
        if payload.get("request_id") != pending_record.get("request_id"):
            return None
        # payload.fingerprint must match the RECOMPUTED binding fingerprint
        if payload.get("fingerprint") != recomputed_fp:
            return None
        # command must match
        if payload.get("command") != pending_record.get("command"):
            return None
        # device_id must match enrolled device_id
        if device_id and payload.get("device_id") != device_id:
            return None
        # project_id must match
        if project_id and payload.get("project_id") != project_id:
            return None
        # org_id must match
        if org_id and payload.get("org_id") != org_id:
            return None

    return {
        "user_id": registry_user_id,  # H1: from registry, not payload
        "key_id": sig_key_id,
        "iss": entry.get("iss", ""),
        "sub": entry.get("sub", ""),
        "key_kind": key_kind,
        "decision": decision,
        "envelope": envelope,
    }


# -- H3: request_id validation -----------------------------------------------

def _validate_request_id(layout: FolderLayout, request_id: str) -> str | None:
    """Validate request_id and return an error status string, or None if valid.

    H3 (ADR 0010 s3): strict charset and length; the path is resolved
    under the pending directory; symlinks and reparse points are refused.
    """
    if not isinstance(request_id, str):
        return "invalid_id"
    if not _REQUEST_ID_RE.fullmatch(request_id):
        return "invalid_id"
    # Resolve path and ensure it stays under pending_dir
    pending_dir = layout.pending_dir
    try:
        candidate = (pending_dir / f"{request_id}.json").resolve()
        parent_resolved = pending_dir.resolve()
        if not str(candidate).startswith(str(parent_resolved)):
            return "invalid_id"
    except (OSError, ValueError):
        return "invalid_id"
    # Refuse symlinks
    pending_file = pending_dir / f"{request_id}.json"
    if pending_file.exists() and pending_file.is_symlink():
        return "invalid_id"
    return None


# -- apply_external (T12b rewrite, ADR 0010) --------------------------------

async def apply_external(
    layout: FolderLayout,
    request_id: str,
    approvals: list[dict[str, Any]],
    *,
    clock: Callable[[], float] | None = None,
) -> dict[str, Any]:
    """Apply remote decisions to a pending escalation (D6.3, T12b TCB).

    T12b (ADR 0010): trust kwargs removed (F1=A).  Registry, environment,
    policy_sequence, operator and enforced approval all come from
    ``verified_state``.  H1 binding, H3 id validation, nonce redesign,
    done-record signing via queue.finish with connector:<device_id> key.

    Returns ``{"status": ...}`` like ``approve()``.
    """
    from sandbox.connector.broker import FolderBroker

    effective_clock = clock or time.time

    # H3: validate request_id before any file access
    id_error = _validate_request_id(layout, request_id)
    if id_error is not None:
        return {"status": id_error}

    # C3: check if already done or claimed (done is terminal)
    queue = EscalationQueue(layout)
    req_status = queue.status(request_id)
    if req_status == "done":
        return {"status": "not_pending"}
    if req_status == "claimed":
        return {"status": "not_pending"}

    # Load verified state (H2, M2, C6, C7 -- ADR 0010 s2)
    from sandbox.connector.sync.verified_state import load_verified_state
    vs = load_verified_state(layout)

    # Verified state required for approvals; denies may still apply without it
    reg = vs.registry if vs else None
    effective_env = vs.environment if vs else "prod"
    effective_seq = vs.policy_sequence if vs else 0
    effective_ea = vs.enforced_approval if vs else {}
    operator_uid = vs.operator_user_id if vs else None
    device_id_val = vs.device_id if vs else ""
    project_id_val = vs.project_id if vs else ""
    org_id_val = vs.org_id if vs else ""

    # Fail closed: a missing enrollment on a managed workspace means
    # remote approvals are refused (no silent skip of operator exclusion).
    # Security round 4 (Q6): either missing value refuses; an operator id
    # that cannot be read must never skip the operator exclusion (S8).
    if vs is None or operator_uid is None or not device_id_val:
        return {"status": "awaiting_second", "approvals": 0}

    # Read the pending record (no claim yet -- count approvals first)
    # Check .sandbox/pending/ first (where the hook writes), then escalations/pending/
    pending_file = None
    for candidate in [
        layout.root / ".sandbox" / "pending" / f"{request_id}.json",
        layout.pending_dir / f"{request_id}.json",
    ]:
        if candidate.exists():
            pending_file = candidate
            break
    if pending_file is None:
        return {"status": "not_pending"}

    # H3: refuse symlinks
    if pending_file.is_symlink():
        return {"status": "invalid_id"}

    try:
        pending_rec = json.loads(pending_file.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"status": "not_pending"}

    # H1: recompute the binding fingerprint from the pending record
    expected_fp = _binding_fingerprint(pending_rec)
    if not expected_fp:
        return {"status": "not_pending"}

    # T12c (ADR 0010 s9): refuse records that cannot be remotely approved.
    # The fp_v check is implicit: a record without fp_v produces a different
    # fingerprint (the recompute in _binding_fingerprint includes fp_v), so
    # the payload.fingerprint won't match and the approval is dropped.
    # An explicit refuse for records with non-empty script_unbound:
    _su = pending_rec.get("script_unbound", "")
    if _su:
        return {"status": "refused",
                "reason": f"script_unbound: {_su}"}
    # A record with script set while preview.shown is false is refused
    _script_rec = pending_rec.get("script")
    _preview_rec = pending_rec.get("script_preview")
    if _script_rec is not None and isinstance(_preview_rec, dict):
        if not _preview_rec.get("shown", False):
            return {"status": "refused",
                    "reason": "script preview not shown"}

    # R3b: policy_sequence must be >= the record's bundle_sequence
    rec_bundle_seq = pending_rec.get("bundle_sequence", 0)
    if isinstance(rec_bundle_seq, int) and effective_seq < rec_bundle_seq:
        return {"status": "awaiting_second", "approvals": 0}

    # Load persisted nonces for cross-call replay detection (C1-C3)
    seen_nonces, nonces_corrupt = _load_seen_nonces(layout)

    # Verify each remote approval against the registry and pending record
    valid_approvals: list[dict[str, Any]] = []
    valid_denies: list[dict[str, Any]] = []

    for a in approvals:
        try:
            verified = _verify_remote_approval(
                a, reg,
                policy_sequence=effective_seq,
                environment=effective_env,
                operator_user_id=operator_uid,
                enforced_approval=effective_ea,
                clock=effective_clock,
                seen_nonces=seen_nonces,
                pending_record=pending_rec,
                device_id=device_id_val,
                project_id=project_id_val,
                org_id=org_id_val,
            )
        except Exception:  # noqa: BLE001 -- L2: one bad envelope must not block others
            continue

        if verified is None:
            continue
        if nonces_corrupt and verified["decision"] != "deny":
            continue  # Corrupt nonces: refuse all approvals, allow denies
        if verified["decision"] == "deny":
            valid_denies.append(verified)
        else:
            valid_approvals.append(verified)

    # C1: write-ahead -- persist nonces BEFORE any claim or execution
    if not _save_seen_nonces(layout, seen_nonces, effective_clock):
        # Nonce save failed: nothing executes (C1)
        return {"status": "nonce_save_failed"}

    # F1: Skew check -- measured against server time
    measured_skew = _measure_skew(layout, effective_clock)
    if measured_skew is not None and measured_skew > _SKEW_THRESHOLD_S:
        if valid_approvals:
            try:
                from sandbox.connector.policy_versions import audit as _audit
                _audit(layout, {
                    "event": "clock_skew", "ts": time.time(),
                    "reason_code": "CLOCK_SKEW", "request_id": request_id,
                    "skew_s": round(measured_skew, 1),
                    "reason": "clock skew over 2 min; remote approvals refused, "
                              "denies still apply (D4.3)",
                })
            except Exception:  # noqa: BLE001
                pass
        valid_approvals.clear()
    elif measured_skew is None:
        from sandbox.connector.sync.state import is_managed as _check_managed
        if _check_managed(layout):
            valid_approvals.clear()

    # Deny needs only one valid signed decision (D6.5)
    if valid_denies:
        claimed = queue.claim(request_id, valid_denies[0]["user_id"])
        if claimed is None:
            # Try old pending dir
            old_src = layout.root / ".sandbox" / "pending" / f"{request_id}.json"
            if old_src.exists() and not old_src.is_symlink():
                try:
                    claimed_dir = layout.claimed_dir
                    claimed_dir.mkdir(parents=True, exist_ok=True)
                    dst = claimed_dir / f"{request_id}.json"
                    os.rename(str(old_src), str(dst))
                    claimed = json.loads(dst.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError):
                    return {"status": "not_pending"}
            else:
                return {"status": "not_pending"}
        result = {
            "request_id": request_id,
            "decision": "deny",
            "state": "denied",
            "reviewer_id": valid_denies[0]["user_id"],
            "command": claimed.get("command", ""),
            "fingerprint": claimed.get("fingerprint", ""),
        }
        queue.finish(request_id, result)
        return {"status": "denied"}

    # No verified state and no denies: fail closed
    if vs is None:
        return {"status": "awaiting_second", "approvals": 0}

    # Registry expired: refuse approvals (D8, D6.5)
    if reg is not None and time.time() > reg._expires_at:
        return {"status": "awaiting_second", "approvals": 0}

    # H1: dedup by registry user_id (ADR 0010 s1)
    seen_users: dict[str, dict[str, Any]] = {}
    deduped: list[dict[str, Any]] = []
    for va in valid_approvals:
        uid = va["user_id"]  # This is the registry user_id
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

    # requires_dual = classify(command, verified folder_policy).requires_dual
    # OR record.requires_dual.  If the bundle cannot classify the command,
    # default to dual (fail closed).  S9 only decides which keys count
    # toward dual (dual_eligible vs identity_deduped), never the floor.
    rec_requires_dual = pending_rec.get("requires_dual", True)
    policy_requires_dual = True  # fail closed default
    if vs is not None:
        fp = vs.bundle_payload.get("folder_policy", {})
        # The folder_policy may have per-command rules; for M2, the bundle
        # doesn't classify commands, so the policy floor is the default (dual).
        # If the folder_policy is empty, dual is the floor.
        if not fp:
            policy_requires_dual = True
        # Future: classify(command, fp) here
    effective_requires_dual = policy_requires_dual or rec_requires_dual
    if effective_requires_dual and len(dual_eligible) < 2:
        return {"status": "awaiting_second", "approvals": len(dual_eligible)}

    # Nothing runs without at least one valid approval (F7)
    approvers_list = dual_eligible if effective_requires_dual else identity_deduped
    if not approvers_list:
        return {"status": "awaiting_second", "approvals": 0}

    # C8: load the connector key BEFORE the claim; if unavailable, nothing runs.
    # The connector key must already exist (created at enroll time); we do
    # not create it on-the-fly because that would mask a missing key.
    connector_reviewer_id = f"connector:{device_id_val}" if device_id_val else "connector:unknown"
    try:
        from sandbox.connector.signing import _seed_path
        from sandbox.connector.keyhome import KeyHomeError
        seed = _seed_path(layout, connector_reviewer_id, create=False)
        if not seed.exists():
            return {"status": "key_unavailable",
                    "reason": "connector key not found; nothing executes"}
    except Exception:
        return {"status": "key_unavailable",
                "reason": "connector key unavailable; nothing executes"}

    # NOW claim the pending record (try canonical dir first, then old dir)
    claimed_rec = queue.claim(request_id, connector_reviewer_id)
    if claimed_rec is None:
        # Try claiming from old pending dir
        old_src = layout.root / ".sandbox" / "pending" / f"{request_id}.json"
        if old_src.exists() and not old_src.is_symlink():
            try:
                claimed_dir = layout.claimed_dir
                claimed_dir.mkdir(parents=True, exist_ok=True)
                dst = claimed_dir / f"{request_id}.json"
                os.rename(str(old_src), str(dst))
                claimed_rec = json.loads(dst.read_text(encoding="utf-8"))
                claimed_rec["reviewer_id"] = connector_reviewer_id
                claimed_rec["claimed_at"] = time.time()
            except (OSError, json.JSONDecodeError):
                return {"status": "not_pending"}
        else:
            return {"status": "not_pending"}

    # H1 C4: recompute fingerprint on the CLAIMED copy
    claimed_fp = _binding_fingerprint(claimed_rec)
    if claimed_fp != expected_fp:
        # TOCTOU: record was edited between read and claim
        queue.release(request_id, claimed_rec)
        return {"status": "changed"}

    # Execute via the broker (C8: uses the record's cwd and root)
    reviewer_id = approvers_list[0]["user_id"]
    result = await FolderBroker().execute(claimed_rec, reviewer_id, "")
    result.setdefault("approved_at", time.time())
    result["remote_approvals"] = [d["envelope"] for d in approvers_list]
    result["approved_by"] = [
        {"user_id": d["user_id"], "key_kind": d["key_kind"]}
        for d in approvers_list
        if not d["user_id"].startswith("connector:")
    ]
    result["requires_dual"] = effective_requires_dual
    result["environment"] = effective_env

    # M3/C8: finish via queue.finish (scrub + sign with connector key)
    result["reviewer_id"] = connector_reviewer_id
    queue.finish(request_id, result)

    # C8: write the done-record hash to the audit chain
    try:
        from sandbox.connector.audit import FolderAudit
        done_file = layout.done_dir / f"{request_id}.json"
        if done_file.exists():
            done_bytes = done_file.read_bytes()
            done_hash = hashlib.sha256(done_bytes).hexdigest()
            audit = FolderAudit(layout.audit_dir, session_id="remote")
            entry = {
                "event": "remote_done",
                "request_id": request_id,
                "done_hash": done_hash,
                "reviewer_id": connector_reviewer_id,
                "ts": time.time(),
            }
            audit.append(entry)
            # Also write to top-level audit chain for grepping
            chain_file = layout.audit_dir / "remote_done.jsonl"
            try:
                layout.audit_dir.mkdir(parents=True, exist_ok=True)
                with open(chain_file, "a", encoding="utf-8") as f:
                    f.write(json.dumps(entry) + "\n")
            except OSError:
                pass
    except Exception:  # noqa: BLE001 -- audit is additive
        pass

    # T12c: a refusal from the broker is terminal
    broker_state = result.get("state", "executed")
    if broker_state == "refused":
        return {"status": broker_state, "result": result}
    return {"status": "executed", "result": result}
