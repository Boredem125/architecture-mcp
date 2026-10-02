"""Audit-log retention for the folder connector (AIUC-1 E015.3).

Each session's chain is kept for the longest tier any of its records reaches:

- ``incident``  (policy.audit.retention_days_incident, default 7 years): a
  denial, an injection hit, a governance violation or a rate-limit trip;
- ``reviewed``  (retention_days_reviewed, default 1 year): a human decided
  something, or an action was critical or needed dual control;
- ``standard``  (retention_days, default 90 days): everything else.

The clock starts at the session's last record. Nothing is deleted unless a
human runs ``sandbox retention --apply``; the active session is never
deleted; and each deletion is itself recorded in the active session's chain
with the deleted chain's head hash and length, so a purge is never silent.
Take an evidence pack first if the records may be needed later.
"""
from __future__ import annotations

import json
import shutil
import time
from pathlib import Path
from typing import Any

from sandbox.connector.audit import FolderAudit, session_ids, verify_records_bytes
from sandbox.connector.layout import FolderLayout

_INCIDENT_EVENTS = {
    "denied", "governance_denied", "semantic_injection_detected", "rate_limited",
    "policy_drift", "policy_changed_unversioned",
}
_REVIEWED_EVENTS = {
    "shell_escalated", "shell_decided", "tool_call_escalated", "tool_call_grant_used",
    "escalate_redirect", "auto_allowed_remembered", "hitl_decided", "broker_decision",
    "policy_version_accepted", "policy_change_proposed", "policy_change_approved",
    "policy_change_rejected", "oversight_fatigue", "taint_cleared",
    "semantic_trust_added", "semantic_trust_removed", "retention_purged",
}
_DAY = 86400.0


def record_tier(rec: dict[str, Any]) -> str:
    event = rec.get("event")
    if event in _INCIDENT_EVENTS or rec.get("reason_code") == "EXFIL":
        return "incident"
    band = (rec.get("risk") or {}).get("band")
    if event in _REVIEWED_EVENTS or rec.get("requires_dual") or band == "critical":
        return "reviewed"
    return "standard"


_ORDER = {"standard": 0, "reviewed": 1, "incident": 2}


def assess_session(path: Path, audit_policy: Any, now: float) -> dict[str, Any]:
    """Tier, last activity and expiry for one session's records.jsonl."""
    tier, last = "standard", None
    with open(path, encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            try:
                rec = json.loads(line)
            except ValueError:
                tier = "incident"  # an unreadable record is kept as long as possible
                continue
            t = record_tier(rec)
            if _ORDER[t] > _ORDER[tier]:
                tier = t
            ts = rec.get("ts")
            if isinstance(ts, (int, float)):
                last = ts if last is None else max(last, ts)
    if last is None:  # records written before timestamps were added
        last = path.stat().st_mtime
    days = {
        "standard": audit_policy.retention_days,
        "reviewed": audit_policy.retention_days_reviewed,
        "incident": audit_policy.retention_days_incident,
    }[tier]
    expires = last + days * _DAY
    return {"tier": tier, "days": days, "last_activity": last, "expires": expires, "expired": now >= expires}


def plan(layout: FolderLayout, audit_policy: Any, now: float | None = None) -> list[dict[str, Any]]:
    """Every session with its retention status; ``active`` marks the live one."""
    now = time.time() if now is None else now
    active = _active_session(layout)
    out = []
    for sid in session_ids(layout.audit_dir):
        info = assess_session(layout.audit_dir / sid / "records.jsonl", audit_policy, now)
        out.append({"session_id": sid, "active": sid == active, **info})
    return out


def apply(layout: FolderLayout, rows: list[dict[str, Any]], by: str) -> list[str]:
    """Delete the expired, inactive sessions in *rows*; record each deletion."""
    active = _active_session(layout) or "default"
    removed = []
    for row in rows:
        if not row["expired"] or row["active"]:
            continue
        sid = row["session_id"]
        d = layout.audit_dir / sid
        chain = verify_records_bytes((d / "records.jsonl").read_bytes())
        FolderAudit(layout.audit_dir, active).append({
            "event": "retention_purged", "ts": time.time(), "by": by,
            "session": sid, "tier": row["tier"], "retention_days": row["days"],
            "last_activity": row["last_activity"], "records": chain["records"],
            "head_hash": chain["head_hash"], "chain_valid": chain["ok"],
        })
        shutil.rmtree(d)
        removed.append(sid)
    return removed


def _active_session(layout: FolderLayout) -> str:
    try:
        return json.loads(layout.session_file.read_text(encoding="utf-8")).get("session_id", "")
    except (OSError, ValueError):
        return ""
