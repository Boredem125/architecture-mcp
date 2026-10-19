"""The one approval path for every approver surface (CLI, watch, REST API).

Dual control is enforced here, so no surface can skip it. A request flagged
``requires_dual`` (critical risk, command exfiltration) needs two approvals:

1. The first approver signs an approval with their own key; the request goes
   back to pending, marked 1 of 2. Nothing runs.
2. A second approval runs it only if it comes from a different reviewer id
   with a different key. Both signed approvals are kept in the done-record,
   which the second approver signs as a whole.

Each step claims the request first (an atomic rename), so two approvers
can't race. A denial needs only one reviewer: denying is the safe direction.

Limit: two distinct reviewer ids and keys are enforced, not that they are two
different people; keys live in the control plane (docs/TCB.md). Binding them
to humans needs per-person credentials (HSM, SSO).
"""
from __future__ import annotations

import time
from typing import Any

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

    Approval fatigue (connector/oversight.py) only adds scrutiny: a flagged
    reviewer must give a reason, and their approval of an ordinary request
    makes it dual control. The outcome then carries an "oversight" entry.
    """
    from sandbox.connector.broker import FolderBroker
    from sandbox.connector.oversight import check_approval
    from sandbox.connector.keyhome import KeyHomeError, NotEnrolledError
    from sandbox.connector.signing import _pin_and_audit, ensure_signing_key, sign_approval

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
