"""Alerts on boundary violations (AIUC-1 B006.2, B002.1).

Some audit records are also alerts: a denial, a governance denial, a prompt
injection hit, a rate-limit trip, and an escalation that is critical or
needs dual control. Each alert is appended to ``.sandbox/logs/alerts.jsonl``
(read it with ``sandbox alerts``) and, if the env var named in
``policy.alerts.webhook_url_env`` holds an http(s) URL, POSTed there as JSON
(Slack/Teams-style incoming webhooks, or any collector).

Best-effort by design: the hook's decision never waits on, or fails
because of, an alert. The webhook gets a short timeout; a failed delivery
is noted in the local alert line.
"""
from __future__ import annotations

import json
import os
import time
import urllib.request
from typing import Any

from sandbox.connector.layout import FolderLayout

# audit event -> alert kind
_ALWAYS = {
    "denied": "denied",
    "governance_denied": "governance",
    "semantic_injection_detected": "injection",
    "rate_limited": "rate_limit",
    "policy_drift": "policy_drift",
}
# Escalations alert only when critical or dual control.
_ESCALATIONS = {"shell_escalated", "tool_call_escalated", "escalate_redirect"}
_MAX_FIELD = 300


def alert_kind(record: dict[str, Any]) -> str | None:
    """The alert kind for an audit record, or None if it is not an alert."""
    event = record.get("event")
    if event in _ALWAYS:
        return _ALWAYS[event]
    if event in _ESCALATIONS:
        band = (record.get("risk") or {}).get("band")
        if record.get("requires_dual") or band == "critical":
            return "critical"
    return None


def _short(value: Any) -> str:
    text = "" if value is None else str(value)
    return text if len(text) <= _MAX_FIELD else text[: _MAX_FIELD - 1] + "…"


def build(layout: FolderLayout, session_id: str, record: dict[str, Any], kind: str) -> dict[str, Any]:
    """The alert payload: enough to triage, never file contents or command output."""
    risk = record.get("risk") or {}
    sem = record.get("semantic") or {}
    return {
        "ts": time.time(),
        "kind": kind,
        "event": record.get("event"),
        "folder": layout.root.name,
        "session_id": session_id,
        "request_id": record.get("request_id"),
        "tool": record.get("tool"),
        "reason_code": record.get("reason_code"),
        "reason": _short(record.get("reason") or sem.get("top_check") or record.get("clause")),
        "command": _short(record.get("command") or record.get("target")),
        "risk_score": risk.get("score"),
        "risk_band": risk.get("band"),
    }


def _post(url: str, payload: dict[str, Any], timeout: float) -> str:
    """POST JSON; return "" on success or a short error."""
    if not url.lower().startswith(("https://", "http://")):
        return "webhook URL must be http(s)"
    body = json.dumps({"text": _summary(payload), "alert": payload}).encode("utf-8")
    # The URL is the operator's own env var, never policy.json or agent input.
    req = urllib.request.Request(url, data=body, method="POST", headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 — scheme checked above
            return "" if 200 <= resp.status < 300 else f"HTTP {resp.status}"
    except Exception as exc:  # noqa: BLE001 — delivery is best-effort
        return type(exc).__name__


def _summary(a: dict[str, Any]) -> str:
    risk = f" risk {a['risk_score']}" if a.get("risk_score") is not None else ""
    what = a.get("command") or a.get("tool") or ""
    return f"[sandbox:{a['folder']}] {a['kind'].upper()}{risk}: {what} {a.get('reason') or ''}".strip()


def emit(layout: FolderLayout, session_id: str, record: dict[str, Any],
         alert_policy: Any = None) -> dict[str, Any] | None:
    """Raise an alert for *record* if it is one. Returns the alert, or None.

    ``alert_policy`` is passed by callers that are themselves computing the
    enforced policy (drift reporting), so this never reads it back.
    """
    kind = alert_kind(record)
    if kind is None:
        return None
    policy = alert_policy
    if policy is None:
        try:
            from sandbox.connector.policy_versions import enforced_policy

            policy = enforced_policy(layout)[0].alerts
        except Exception:  # noqa: BLE001 — fall back to the defaults
            from sandbox.connector.policy import AlertPolicy

            policy = AlertPolicy()
    if not policy.enabled:
        return None
    alert = build(layout, session_id, record, kind)
    url = os.environ.get(policy.webhook_url_env, "").strip()
    if url:
        error = _post(url, alert, policy.timeout_seconds)
        alert["webhook"] = "delivered" if not error else f"failed: {error}"
    try:
        layout.logs_dir.mkdir(parents=True, exist_ok=True)
        with open(layout.logs_dir / "alerts.jsonl", "a", encoding="utf-8") as f:
            f.write(json.dumps(alert) + "\n")
    except OSError:
        pass
    return alert


def read_alerts(layout: FolderLayout, limit: int = 20) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    try:
        with open(layout.logs_dir / "alerts.jsonl", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    try:
                        out.append(json.loads(line))
                    except ValueError:
                        pass
    except OSError:
        pass
    return out[-limit:]
