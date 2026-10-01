"""One-time approvals for non-shell tool calls ("approve, then retry").

The sandbox can run an approved shell command or fetch an approved URL
itself, but it can't make a third-party MCP call (it has no Stripe or Slack
connection). So a governance hit on such a call escalates as a ``tool_call``
record; a human approves it out of band (``sandbox approve``), which writes a
signed done-record; and the agent's *identical* retry is allowed once.

A grant counts only if all hold:
- the done-record is a ``tool_call`` approval whose fingerprint (tool name +
  canonical arguments) matches the retried call exactly,
- its Ed25519 signature verifies AND the signer is this folder's approver key
  (verify_record alone trusts the key embedded in the record),
- it was decided within ``GRANT_TTL_SECONDS``, and
- it hasn't been used (a consumed marker is written in the control plane,
  which the agent can't write).
"""
from __future__ import annotations

import hashlib
import json
import time
from typing import Any

from sandbox.connector.layout import FolderLayout

GRANT_TTL_SECONDS = 15 * 60


def fingerprint(tool_name: str, tool_input: dict[str, Any]) -> str:
    canonical = json.dumps({"tool": tool_name, "input": tool_input or {}}, sort_keys=True,
                           separators=(",", ":"), ensure_ascii=False, default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _consumed_dir(layout: FolderLayout):
    return layout.state_dir / "grants_used"


def find_grant(layout: FolderLayout, fp: str, now: float | None = None) -> dict[str, Any] | None:
    """The valid, unused approval for this exact call, or None."""
    from sandbox.connector.signing import distinct_approvals, reviewer_public_key, verify_record

    now = time.time() if now is None else now
    used = _consumed_dir(layout)
    for path in sorted(layout.done_dir.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True):
        try:
            rec = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if rec.get("kind") != "tool_call" or rec.get("fingerprint") != fp or rec.get("decision") != "approved":
            continue
        if now - float(rec.get("decided_at", 0)) > GRANT_TTL_SECONDS:
            continue
        if (used / f"{rec.get('request_id')}.used").exists():
            continue
        if not verify_record(rec) or rec.get("signer_public_key") != reviewer_public_key(layout, rec.get("reviewer_id", "cli")):
            continue
        if rec.get("requires_dual") and not distinct_approvals(rec.get("approvals") or []):
            continue
        return rec
    return None


def consume(layout: FolderLayout, request_id: str) -> None:
    used = _consumed_dir(layout)
    used.mkdir(parents=True, exist_ok=True)
    (used / f"{request_id}.used").write_text(str(time.time()), encoding="utf-8")


def pending_for(layout: FolderLayout, fp: str) -> str | None:
    """Request id of an already-pending tool_call for this exact call (no duplicates)."""
    for path in layout.pending_dir.glob("*.json"):
        try:
            rec = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if rec.get("kind") == "tool_call" and rec.get("fingerprint") == fp:
            return rec.get("request_id")
    return None
