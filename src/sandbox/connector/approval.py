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


def _valid_for(approval: dict[str, Any], record: dict[str, Any]) -> bool:
    from sandbox.connector.signing import verify_approval

    return (verify_approval(approval)
            and all(approval.get(k) == record.get(k) for k in ("request_id", "command", "fingerprint")))


async def approve(layout: FolderLayout, request_id: str, reviewer_id: str, reason: str = "") -> dict[str, Any]:
    """Approve a pending request. Returns {"status": ...}:

    executed        it ran (or, for a tool_call, the grant was issued); "result" holds the done-record
    awaiting_second first of two approvals recorded; nothing ran
    same_reviewer   refused: this reviewer (or key) already gave the first approval
    not_pending     no such pending request (taken, finished or unknown)
    """
    from sandbox.connector.broker import FolderBroker
    from sandbox.connector.signing import sign_approval

    queue = EscalationQueue(layout)
    rec = queue.claim(request_id, reviewer_id)
    if rec is None:
        return {"status": "not_pending"}

    # Only approvals that verify AND are for exactly this request count: an
    # altered approval, or a request changed after it was approved, drops out.
    approvals = [a for a in rec.get("approvals") or [] if _valid_for(a, rec)]
    if rec.get("requires_dual"):
        mine = sign_approval(layout, reviewer_id, rec, time.time())
        if any(a.get("reviewer_id") == reviewer_id or a.get("signer_public_key") == mine["signer_public_key"]
               for a in approvals):
            queue.release(request_id, rec)
            return {"status": "same_reviewer", "approvals": len(approvals)}
        approvals.append(mine)
        if len(approvals) < 2:
            queue.release(request_id, rec | {"approvals": approvals})
            queue._activity(f"APPROVED 1/2  {request_id}  by {reviewer_id}  (dual control: needs a second reviewer)")
            return {"status": "awaiting_second", "approvals": len(approvals)}

    result = await FolderBroker().execute(rec, reviewer_id, reason)
    if approvals:
        result["approvals"] = approvals
        result["requires_dual"] = True
    queue.finish(request_id, result)
    return {"status": "executed", "result": result}
