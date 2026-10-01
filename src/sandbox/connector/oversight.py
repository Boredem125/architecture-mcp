"""Oversight indicators and approval-fatigue detection.

A human who approves everything within two seconds is a click, not oversight.
This module reads the folder's own records and reports how reviewers decide:
approvals, denials, how long after a request was created each decision came,
how many approvals were very fast, and bursts of approvals. It also flags a
reviewer whose recent approvals look like rubber-stamping, and
:func:`check_approval` (called from the one approval path,
``connector/approval.py``) then raises scrutiny for that reviewer: a written
reason, and/or a second reviewer. It never lowers scrutiny.

Sources:
- done-records (``escalations/done``): denials, single approvals
  (``approved_at``, else ``decided_at``) and each signed approval of a
  dual-control request (``approvals[].approved_at``);
- pending records: first approvals still waiting for a second, and requests
  nobody decided before the policy's escalation timeout;
- the audit log: ``oversight_fatigue`` events.

These numbers are indicators, not proof of good or bad oversight. A careful
reviewer can be fast on an obvious request; a slow reviewer can still approve
without reading. Latency is measured from request creation, so it includes
time the request sat unseen. The thresholds (policy ``oversight``) are
starting points, not values validated on real reviewer data.
"""
from __future__ import annotations

import json
import math
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from sandbox.connector.layout import FolderLayout


@dataclass(frozen=True)
class Act:
    """One reviewer decision: an approval (one signature) or a denial."""

    reviewer: str
    decision: str  # "approve" | "deny"
    at: float
    latency: float | None  # seconds from request creation; None if unknown
    request_id: str


# --- reading records -----------------------------------------------------

def _num(value: Any) -> float | None:
    try:
        f = float(value)
    except (TypeError, ValueError):
        return None
    return f if math.isfinite(f) else None


def _latency(created: float | None, at: float) -> float | None:
    if created is None or at < created:
        return None
    return at - created


def _records(directory: Path, min_mtime: float | None = None) -> Iterable[dict[str, Any]]:
    try:
        entries = list(os.scandir(directory))
    except OSError:
        return
    for entry in entries:
        if not entry.name.endswith(".json"):
            continue
        if min_mtime is not None:
            try:
                if entry.stat().st_mtime < min_mtime:
                    continue
            except OSError:
                continue
        try:
            rec = json.loads(Path(entry.path).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if isinstance(rec, dict):
            yield rec


def acts_from_record(rec: dict[str, Any]) -> list[Act]:
    """The decisions recorded in one done or pending record."""
    created = _num(rec.get("created_at"))
    rid = str(rec.get("request_id", ""))
    approvals = [a for a in rec.get("approvals") or [] if isinstance(a, dict)]
    out: list[Act] = []
    for a in approvals:
        at = _num(a.get("approved_at"))
        if at is not None:
            out.append(Act(str(a.get("reviewer_id") or "?"), "approve", at, _latency(created, at), rid))
    decision = str(rec.get("decision") or "")
    reviewer = str(rec.get("reviewer_id") or "?")
    if decision == "denied":
        at = _num(rec.get("decided_at"))
        if at is not None:
            out.append(Act(reviewer, "deny", at, _latency(created, at), rid))
    elif decision == "approved" and not approvals:
        at = _num(rec.get("approved_at"))
        if at is None:
            at = _num(rec.get("decided_at"))
        if at is not None:
            out.append(Act(reviewer, "approve", at, _latency(created, at), rid))
    return out


def collect_acts(layout: FolderLayout, min_mtime: float | None = None) -> list[Act]:
    """Every decision in the done and pending records (optionally only files
    modified since *min_mtime*: a record is rewritten at or after each decision
    it holds, so older files cannot hold newer decisions)."""
    acts: list[Act] = []
    for d in (layout.done_dir, layout.pending_dir):
        for rec in _records(d, min_mtime):
            acts.extend(acts_from_record(rec))
    acts.sort(key=lambda a: a.at)
    return acts


# --- fatigue -------------------------------------------------------------

@dataclass
class Fatigue:
    reviewer: str
    fatigued: bool = False
    reasons: list[str] = field(default_factory=list)
    approvals_in_window: int = 0
    fast_in_window: int = 0
    timed_in_window: int = 0  # approvals in the window with a known latency

    def as_dict(self) -> dict[str, Any]:
        return {"reviewer": self.reviewer, "fatigued": self.fatigued, "reasons": list(self.reasons),
                "approvals_in_window": self.approvals_in_window,
                "fast_in_window": self.fast_in_window, "timed_in_window": self.timed_in_window}


def _cfg(layout: FolderLayout, policy: Any = None) -> Any:
    if policy is None:
        from sandbox.connector.policy import load_policy

        policy = load_policy(layout.policy_file)
    return policy.oversight


def evaluate(reviewer: str, approvals: list[Act], cfg: Any) -> Fatigue:
    """Apply the fatigue rule to *approvals* (this reviewer's, inside the window).

    Flagged when either holds:
    - burst: at least ``burst_approvals`` approvals in the window;
    - fast share: at least ``fast_min_approvals`` approvals with a known
      latency, and at least ``fast_share`` of them under ``fast_seconds``.
    """
    timed = [a for a in approvals if a.latency is not None]
    fast = [a for a in timed if a.latency < cfg.fast_seconds]
    f = Fatigue(reviewer, approvals_in_window=len(approvals),
                fast_in_window=len(fast), timed_in_window=len(timed))
    window = f"{cfg.window_minutes:g} min"
    if len(approvals) >= cfg.burst_approvals:
        f.reasons.append(f"{len(approvals)} approvals in the last {window} "
                         f"(threshold {cfg.burst_approvals})")
    if len(timed) >= cfg.fast_min_approvals and len(fast) / len(timed) >= cfg.fast_share:
        f.reasons.append(f"{len(fast)} of {len(timed)} approvals in the last {window} came under "
                         f"{cfg.fast_seconds:g} s after the request (threshold {cfg.fast_share:.0%})")
    f.fatigued = bool(f.reasons)
    return f


def assess_fatigue(layout: FolderLayout, reviewer_id: str, policy: Any = None,
                   now: float | None = None) -> Fatigue:
    """Is *reviewer_id* flagged right now? Looks at their approvals in the window."""
    cfg = _cfg(layout, policy)
    if not cfg.enabled:
        return Fatigue(reviewer_id)
    now = time.time() if now is None else now
    start = now - cfg.window_minutes * 60
    mine = [a for a in collect_acts(layout, min_mtime=start - 60)
            if a.reviewer == reviewer_id and a.decision == "approve" and a.at >= start]
    return evaluate(reviewer_id, mine, cfg)


def response_text(cfg: Any) -> str:
    parts = []
    if cfg.require_reason:
        parts.append(f"a written reason (at least {cfg.min_reason_chars} characters)")
    if cfg.require_second_reviewer:
        parts.append("a second, different reviewer")
    return " and ".join(parts) if parts else "nothing extra (warning only)"


def _audit(layout: FolderLayout, record: dict[str, Any]) -> None:
    """Best-effort append to the folder's audit chain."""
    try:
        from sandbox.connector.audit import FolderAudit

        try:
            session_id = json.loads(layout.session_file.read_text(encoding="utf-8")).get("session_id", "")
        except (OSError, ValueError, AttributeError):
            session_id = ""
        FolderAudit(layout.audit_dir, session_id).append(record)
    except Exception:  # noqa: BLE001 — auditing must not break approval
        pass


def check_approval(layout: FolderLayout, rec: dict[str, Any], reviewer_id: str,
                   reason: str = "", now: float | None = None) -> dict[str, Any] | None:
    """Called by ``approval.approve`` before an approval counts.

    Returns None when the reviewer is not flagged (nothing changes). Otherwise
    audits an ``oversight_fatigue`` event and returns what to apply:

    reason_required  refuse this approval: no adequate written reason given
    second_reviewer  treat the request as dual control from now on
    """
    from sandbox.connector.policy import load_policy

    policy = load_policy(layout.policy_file)
    cfg = policy.oversight
    fatigue = assess_fatigue(layout, reviewer_id, policy, now) if cfg.enabled else None
    if fatigue is None or not fatigue.fatigued:
        return None
    reason_required = cfg.require_reason and len((reason or "").strip()) < cfg.min_reason_chars
    second = cfg.require_second_reviewer and not reason_required and not rec.get("requires_dual")
    if reason_required:
        outcome = "refused_no_reason"
    elif second:
        outcome = "second_reviewer_required"
    else:  # request already dual, or the second-reviewer response is off
        outcome = "reason_given" if cfg.require_reason else "flagged_only"
    _audit(layout, {
        "event": "oversight_fatigue", "request_id": rec.get("request_id"), "reviewer_id": reviewer_id,
        "reasons": fatigue.reasons, "outcome": outcome, "reason": reason or "",
        "approvals_in_window": fatigue.approvals_in_window, "fast_in_window": fatigue.fast_in_window,
        "window_minutes": cfg.window_minutes, "at": time.time() if now is None else now,
    })
    return {"fatigue": fatigue.as_dict(), "reason_required": reason_required, "second_reviewer": second,
            "min_reason_chars": cfg.min_reason_chars, "outcome": outcome, "response": response_text(cfg)}


# --- metrics -------------------------------------------------------------

def _percentile(sorted_vals: list[float], q: float) -> float | None:
    """Nearest-rank percentile."""
    if not sorted_vals:
        return None
    k = max(0, math.ceil(q * len(sorted_vals)) - 1)
    return sorted_vals[k]


def _bursts(times: list[float], n: int, window_s: float) -> tuple[int, int]:
    """(episodes, most approvals in any window). An episode is counted when
    *n* approvals fall inside one window; counting restarts after it."""
    most, episodes, lo, start = 0, 0, 0, 0
    for hi, t in enumerate(times):
        while times[lo] < t - window_s:
            lo += 1
        most = max(most, hi - lo + 1)
        if hi - max(lo, start) + 1 >= n:
            episodes += 1
            start = hi + 1
    return episodes, most


def _summary(acts: list[Act], cfg: Any) -> dict[str, Any]:
    approvals = [a for a in acts if a.decision == "approve"]
    denials = len(acts) - len(approvals)
    latencies = sorted(a.latency for a in acts if a.latency is not None)
    timed_approvals = [a for a in approvals if a.latency is not None]
    fast = sum(1 for a in timed_approvals if a.latency < cfg.fast_seconds)
    episodes, most = _bursts([a.at for a in approvals], cfg.burst_approvals, cfg.window_minutes * 60)
    return {
        "approvals": len(approvals),
        "denials": denials,
        "approval_rate": round(len(approvals) / len(acts), 3) if acts else None,
        "decision_seconds": {
            "count": len(latencies),
            "median": _round(_percentile(latencies, 0.5)),
            "p90": _round(_percentile(latencies, 0.9)),
        },
        "fast_approvals": fast,
        "fast_approval_share": round(fast / len(timed_approvals), 3) if timed_approvals else None,
        "bursts": episodes,
        "max_approvals_in_window": most,
    }


def _round(v: float | None) -> float | None:
    return None if v is None else round(v, 2)


def _fatigue_events(layout: FolderLayout, since: float | None) -> dict[str, int]:
    counts: dict[str, int] = {}
    try:
        files = list(layout.audit_dir.glob("*/records.jsonl"))
    except OSError:
        return counts
    for f in files:
        try:
            lines = f.read_text(encoding="utf-8").splitlines()
        except OSError:
            continue
        for line in lines:
            try:
                ev = json.loads(line)
            except ValueError:
                continue
            if not isinstance(ev, dict) or ev.get("event") != "oversight_fatigue":
                continue
            if since is not None and (_num(ev.get("at")) or 0) < since:
                continue
            who = str(ev.get("reviewer_id") or "?")
            counts[who] = counts.get(who, 0) + 1
    return counts


def compute_metrics(layout: FolderLayout, since: float | None = None, now: float | None = None,
                    policy: Any = None) -> dict[str, Any]:
    """Oversight indicators for the folder, per reviewer and overall.

    *since* (epoch seconds) limits decisions to those made at or after it, and
    pending requests to those created at or after it.
    """
    if policy is None:
        from sandbox.connector.policy import load_policy

        policy = load_policy(layout.policy_file)
    cfg = policy.oversight
    now = time.time() if now is None else now

    all_acts = collect_acts(layout)
    acts = [a for a in all_acts if since is None or a.at >= since]

    # Request-level view: decided vs left pending past the escalation timeout.
    timeout = float(policy.escalation_timeout_seconds)
    approved = denied = late = 0
    for rec in _records(layout.done_dir):
        decided = _num(rec.get("decided_at"))
        if since is not None and (decided is None or decided < since):
            continue
        if rec.get("decision") == "denied":
            denied += 1
        elif rec.get("decision") == "approved":
            approved += 1
        else:
            continue
        created = _num(rec.get("created_at"))
        if created is not None and decided is not None and decided - created > timeout:
            late += 1
    pending = timed_out = 0
    for rec in _records(layout.pending_dir):
        created = _num(rec.get("created_at"))
        if since is not None and (created is None or created < since):
            continue
        pending += 1
        if created is not None and now - created > timeout:
            timed_out += 1
    decided = approved + denied

    events = _fatigue_events(layout, since)
    reviewers: dict[str, Any] = {}
    for name in sorted({a.reviewer for a in acts} | set(events)):
        mine = [a for a in acts if a.reviewer == name]
        row = _summary(mine, cfg)
        start = now - cfg.window_minutes * 60
        recent = [a for a in all_acts if a.reviewer == name and a.decision == "approve" and a.at >= start]
        flag = evaluate(name, recent, cfg) if cfg.enabled else Fatigue(name)
        row["fatigue_events"] = events.get(name, 0)
        row["flagged_now"] = flag.fatigued
        row["flagged_reasons"] = flag.reasons
        reviewers[name] = row

    overall = _summary(acts, cfg)
    overall["bursts"] = sum(r["bursts"] for r in reviewers.values())
    overall["max_approvals_in_window"] = max((r["max_approvals_in_window"] for r in reviewers.values()), default=0)
    overall["fatigue_events"] = sum(events.values())
    overall["reviewers_flagged_now"] = sorted(n for n, r in reviewers.items() if r["flagged_now"])

    return {
        "root": str(layout.root),
        "generated_at": now,
        "since": since,
        "thresholds": cfg.model_dump(),
        "escalation_timeout_seconds": timeout,
        "requests": {
            "decided": decided, "approved": approved, "denied": denied,
            "decided_after_timeout": late, "pending": pending, "timed_out": timed_out,
            "timeout_share": round(timed_out / (decided + timed_out), 3) if decided + timed_out else None,
        },
        "overall": overall,
        "reviewers": reviewers,
        "note": "Indicators only: they do not show that oversight was effective or ineffective.",
    }
