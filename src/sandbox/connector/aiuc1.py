"""AIUC-1 evidence index for an evidence pack.

Maps what the gateway recorded (audit events, signed decisions, alerts) and
how it is configured (policy settings) to the AIUC-1 controls each one is
evidence for, so a reviewer, or a governance platform, can go from a control
id to the exact records that support it.

Scope and honesty, as in docs/AIUC-1_MAP.md:

- mapped against the AIUC-1 release of 15 July 2026;
- ``self_assessed_status`` is the author's own assessment, not an audit or a
  certification, and AIUC-1 certifies an organisation's agent, not a tool;
- only controls the gateway produces evidence for are listed; the
  requirements it does not cover are in the mapping document.
"""
from __future__ import annotations

from collections import defaultdict
from typing import Any

STANDARD = "AIUC-1"
STANDARD_RELEASE = "2026-07-15"
MAPPING_DOC = "docs/AIUC-1_MAP.md"

# requirement id -> (title, self-assessed status in docs/AIUC-1_MAP.md)
REQUIREMENTS: dict[str, tuple[str, str]] = {
    "A008": ("Prevent leakage of credentials and secrets", "partial"),
    "B002": ("Detect adversarial input", "partial"),
    "B006": ("Prevent unauthorized AI agent actions", "supports"),
    "C005": ("Prevent agent-specific high risk outputs", "partial"),
    "C006": ("Prevent output vulnerabilities", "partial"),
    "C007": ("Flag high risk outputs for human review", "supports"),
    "C009": ("Enable real-time feedback and intervention", "supports"),
    "D003": ("Restrict unsafe tool calls", "supports"),
    "E004": ("Assign accountability", "partial"),
    "E009": ("Monitor third-party access", "supports"),
    "E013": ("Implement quality management system", "partial"),
    "E015": ("Log AI system activity", "partial"),
}

# control id -> what it is about (short, for the index)
CONTROLS: dict[str, str] = {
    "A008.5": "secrets kept out of logs, history and stored artifacts",
    "B002.1": "adversarial input detected and alerted",
    "B006.1": "technical limits on agent capabilities",
    "B006.2": "monitoring and alerting on boundary violations",
    "C005.1": "detection and blocking aligned with the organisation's rules",
    "C006.2": "untrusted content labelled by trust level",
    "C007.3": "human review workflow for flagged actions",
    "C009.1": "human intervention before or after an action",
    "D003.1": "tool call validation and authorisation",
    "D003.2": "rate limits on autonomous tool use",
    "D003.3": "every tool call logged",
    "D003.4": "human approval for sensitive tool operations",
    "D003.5": "review of tool usage patterns",
    "E004.1": "changes to the rules need a named, signed approval",
    "E009.1": "third-party (MCP, web) calls logged",
    "E013.2": "change management and approval records",
    "E015.1": "system activity captured for investigation",
    "E015.2": "agent execution chain with approval records",
    "E015.3": "log retention and data sanitation",
    "E015.4": "tamper-evident, independently verifiable logs",
}

_EVENT_CONTROLS: dict[str, tuple[str, ...]] = {
    "allowed": ("D003.3", "E015.1"),
    "observed": ("D003.3", "E015.1"),
    "denied": ("B006.1", "D003.1", "E015.1"),
    "rate_limited": ("D003.2", "B006.2"),
    "shell_escalated": ("D003.4", "C007.3"),
    "tool_call_escalated": ("D003.4", "C007.3"),
    "escalate_redirect": ("D003.4", "C007.3"),
    "shell_decided": ("D003.4", "C009.1", "E015.2"),
    "tool_call_grant_used": ("D003.4", "E015.2"),
    "auto_allowed_remembered": ("D003.4", "E015.2"),
    "semantic_injection_detected": ("B002.1", "C006.2"),
    "taint_cleared": ("C009.1",),
    "governance_denied": ("C005.1", "B006.1"),
    "policy_version_accepted": ("E004.1", "E013.2"),
    "policy_change_proposed": ("E004.1", "E013.2"),
    "policy_change_approved": ("E004.1", "E013.2"),
    "policy_change_rejected": ("E004.1", "E013.2"),
    "policy_drift": ("E004.1", "B006.2"),
    "policy_changed_unversioned": ("E004.1",),
    "oversight_fatigue": ("D003.5",),
    "retention_purged": ("E015.3",),
}
_EXAMPLES = 5


def _requirement(control: str) -> str:
    return control.split(".", 1)[0]


def record_controls(rec: dict[str, Any]) -> set[str]:
    """The AIUC-1 controls one audit record is evidence for."""
    out = set(_EVENT_CONTROLS.get(str(rec.get("event") or ""), ()))
    tool = str(rec.get("tool") or "")
    if tool == "WebFetch" or (tool.startswith("mcp__") and not tool.startswith("mcp__sandbox")):
        out.add("E009.1")
    if rec.get("governance") or rec.get("governance_violations"):
        out.add("C005.1")
    if rec.get("requires_dual") or rec.get("reason_code") == "EXFIL":
        out.add("B006.1")
    return out


def decision_controls(rec: dict[str, Any]) -> set[str]:
    """The AIUC-1 controls one signed done-record is evidence for."""
    out = {"D003.4", "C007.3", "C009.1", "E015.2"}
    if rec.get("requires_dual"):
        out.add("B006.1")
    if rec.get("secrets_redacted"):
        out.add("A008.5")
    if rec.get("governance") or rec.get("governance_violations"):
        out.add("C005.1")
    return out


def configuration(policy: Any) -> dict[str, list[str]]:
    """Controls supported by how the folder is configured, with the setting."""
    cfg: dict[str, list[str]] = defaultdict(list)
    t = policy.triggers
    cfg["B006.1"].append(f"triggers: shell={t.shell}, write_outside={t.write_outside}, "
                         f"network={t.network}; protected paths {', '.join(policy.write.deny_globs)}")
    cfg["D003.1"].append(f"MCP server allowlist: {policy.network.allow_mcp_servers or 'none'}")
    if policy.limits.enabled:
        lim = policy.limits
        cfg["D003.2"].append(f"rate limits per {lim.window_seconds}s: shell {lim.shell}, write {lim.write}, "
                             f"network {lim.network}, total {lim.total}")
    if policy.audit.log_allowed:
        cfg["D003.3"].append("audit.log_allowed: every tool call is recorded")
    if policy.output.scrub_secrets:
        cfg["A008.5"].append("output.scrub_secrets: credentials replaced in output, audit and activity log")
        cfg["E015.3"].append("credentials scrubbed from records")
    if policy.alerts.enabled:
        cfg["B006.2"].append(f"alerts on; webhook from ${policy.alerts.webhook_url_env}")
    a = policy.audit
    cfg["E015.3"].append(f"retention: {a.retention_days} d standard, {a.retention_days_reviewed} d reviewed, "
                         f"{a.retention_days_incident} d incident")
    if policy.semantic.enabled:
        cfg["B002.1"].append("injection scan of tool output on (semantic.enabled)")
        if policy.semantic.governance_policy:
            cfg["C005.1"].append(f"governance policy: {policy.semantic.governance_policy}")
    return dict(cfg)


def build_index(audit_files: dict[str, list[dict[str, Any]]], decisions: dict[str, dict[str, Any]],
                alerts: list[dict[str, Any]], chains_valid: bool, policy: Any) -> dict[str, Any]:
    """The pack's ``aiuc1/controls.json``.

    ``audit_files`` maps a pack path to its records in order (line n is index
    n-1); ``decisions`` maps a pack path to its done-record.
    """
    counts: dict[str, dict[str, int]] = defaultdict(lambda: {"audit_records": 0, "decisions": 0, "alerts": 0})
    examples: dict[str, list[str]] = defaultdict(list)

    def note(control: str, kind: str, ref: str) -> None:
        counts[control][kind] += 1
        if len(examples[control]) < _EXAMPLES:
            examples[control].append(ref)

    for path, records in sorted(audit_files.items()):
        for line, rec in enumerate(records, start=1):
            for c in sorted(record_controls(rec)):
                note(c, "audit_records", f"{path}#L{line} ({rec.get('event')})")
    for path, rec in sorted(decisions.items()):
        for c in sorted(decision_controls(rec)):
            note(c, "decisions", f"{path} ({rec.get('state') or rec.get('decision')})")
    for n, a in enumerate(alerts, start=1):
        note("B006.2", "alerts", f"alerts/alerts.jsonl#L{n} ({a.get('kind')})")
    total_records = sum(len(r) for r in audit_files.values())
    if total_records:
        counts["E015.4"]["audit_records"] = total_records
        examples["E015.4"] = [f"audit/chains.json: hash chains {'all valid' if chains_valid else 'NOT all valid'}"]
    config = configuration(policy)

    controls: dict[str, Any] = {}
    for control in sorted(set(counts) | set(config)):
        req = _requirement(control)
        title, status = REQUIREMENTS.get(req, ("", "not mapped"))
        controls[control] = {
            "requirement": req,
            "requirement_title": title,
            "self_assessed_status": status,
            "about": CONTROLS.get(control, ""),
            "evidence": dict(counts.get(control, {"audit_records": 0, "decisions": 0, "alerts": 0})),
            "examples": examples.get(control, []),
            "configuration": config.get(control, []),
        }
    by_requirement: dict[str, Any] = {}
    for control, entry in controls.items():
        r = by_requirement.setdefault(entry["requirement"], {
            "title": entry["requirement_title"], "self_assessed_status": entry["self_assessed_status"],
            "controls": [], "evidence_items": 0})
        r["controls"].append(control)
        r["evidence_items"] += sum(entry["evidence"].values())
    return {
        "standard": STANDARD,
        "release": STANDARD_RELEASE,
        "mapping": MAPPING_DOC,
        "note": ("Self-assessment by the gateway's author, not an audit or certification. AIUC-1 "
                 "certifies an organisation's agent product; this lists the controls the gateway "
                 "produced evidence for in this folder. Requirements it does not cover are in the mapping."),
        "by_requirement": dict(sorted(by_requirement.items())),
        "controls": controls,
    }