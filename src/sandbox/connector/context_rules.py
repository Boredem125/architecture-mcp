"""Environment and data-classification rules for one classified tool call.

Called from ``hook_eval.pre_tool_use`` after the classifier and the risk score.
Both functions only raise scrutiny: every effect is an itemized risk factor
added through ``RiskAssessment.raise_by`` (which rejects negative points), a
verdict is only ever moved up the order allow < observe < escalate < deny, and
a ``deny`` is never touched. With the defaults (no ``environment``, no
``classification`` rules) both are no-ops. See docs/DATA_AND_ENVIRONMENT.md.

Data classification (``apply_classification``), by the highest level among the
paths a call names. Points are added to the score; the floor is the minimum
verdict the call gets (the risk band can still raise it, as for any call):

    level         points  read floor          write / shell / tool-call floor  sent out
    public           0    -                   -                                -
    internal        +5    -                   -                                -
    confidential   +15    -                   observe                          dual control
    restricted     +30    observe (escalate   escalate                         dual control
                          outside the folder)

"Sent out" is a shell command with a network-egress shape (``safety/exfil.py``)
or an MCP/WebFetch call tagged ``sends_data`` (``safety/tool_actions.py``).
Shell commands are treated as reads *and* writes: whether ``cmd file`` reads or
deletes the file is not reliably parseable. Because a shell command is scored as
one (45 + 10), CONFIDENTIAL in a shell command lands in the escalate band and
RESTRICTED in the critical band (dual control), even for an allowlisted ``cat``.

Environment (``apply_environment``), after the tier upgrades:

    staging: allowlisted network calls (WebFetch, allowlisted MCP servers) -> observe
    prod:    allowlisted shell and network calls -> observe
             (plus, in risk.assess: +20 points and dual control from 70, not 80)
"""
from __future__ import annotations

from typing import Any

from sandbox.connector.risk import RiskFactor, canonical_environment

_ORDER = {"allow": 0, "observe": 1, "escalate": 2, "deny": 3}

LEVEL_POINTS = {"public": 0, "internal": 5, "confidential": 15, "restricted": 30}
EXFIL_POINTS = 45  # same weight as the command exfiltration factor in hook_eval

# Allowlisted action classes that an environment audits (allow -> observe).
ENV_AUDITED = {"staging": ("network",), "prod": ("shell", "network")}

_SHELL_TOOLS = {"Bash", "PowerShell"}
_WRITE_TOOLS = {"Write", "Edit", "MultiEdit", "NotebookEdit"}
_READ_TOOLS = {"Read", "Glob", "Grep"}


def raise_verdict(current: str, floor: str) -> str:
    """The stricter of *current* and *floor*; an unknown verdict is left alone."""
    if current not in _ORDER or floor not in _ORDER:
        return current
    return floor if _ORDER[floor] > _ORDER[current] else current


def _is_own_tool(tool_name: str) -> bool:
    return tool_name.startswith(("mcp__sandbox__", "mcp__sandbox_"))


def _is_governed(tool_name: str) -> bool:
    if tool_name == "WebFetch":
        return True
    return tool_name.startswith("mcp__") and not _is_own_tool(tool_name)


def _action_class(tool_name: str) -> str:
    if tool_name in _SHELL_TOOLS:
        return "shell"
    if tool_name in ("WebFetch", "WebSearch") or _is_governed(tool_name):
        return "network"
    return ""


def _target(tool_input: dict[str, Any], result: Any) -> str:
    if result.target_path:
        return result.target_path
    for key in ("file_path", "path", "notebook_path"):
        if tool_input.get(key):
            return str(tool_input[key])
    return ""


def apply_classification(
    result: Any,
    assessment: Any,
    policy: Any,
    layout: Any,
    tool_name: str,
    tool_input: dict[str, Any],
    *,
    cwd: str | None = None,
) -> None:
    """Tag the paths this call names and raise risk/verdict by their level."""
    rules = getattr(policy, "classification", None) or []
    if not rules or _is_own_tool(tool_name):
        return
    from sandbox.safety import classification as dc

    command = ""
    if tool_name in _SHELL_TOOLS:
        op = "shell"
        command = result.command or str(tool_input.get("command", "") or "")
        paths = dc.command_paths(command)
    elif tool_name in _WRITE_TOOLS:
        op, paths = "write", [_target(tool_input, result)]
    elif tool_name in _READ_TOOLS:
        op, paths = "read", [_target(tool_input, result)]
    elif _is_governed(tool_name):
        op, paths = "tool", dc.argument_paths(tool_input)
    else:
        return

    best, found = dc.highest(paths, layout.root, rules, base=cwd or str(layout.root))
    if best is None:
        return
    level = best.level

    points = LEVEL_POINTS.get(level, 0)
    assessment.raise_by(RiskFactor("data-classification", points, best.detail()))
    levels = sorted({m.level for m in found}, key=dc.rank)
    result.metadata["data_classification"] = {
        "level": level, "path": best.path, "pattern": best.pattern,
    }
    # Governance tool-call tags (clauses can gate on requires_tool_actions: ["data_restricted"]).
    result.metadata["data_tags"] = [f"data_{lvl}" for lvl in levels]
    result.metadata["data_actions"] = [
        {"tag": f"data_{m.level}", "label": f"names a {m.level.upper()} file ({m.path})"}
        for m in found
    ]

    if result.verdict == "deny":
        return  # already the strictest verdict; the factor above is the record

    # Sending a CONFIDENTIAL/RESTRICTED file out: exfiltration, dual control.
    if dc.at_least(level, "confidential"):
        egress = ""
        if op == "shell":
            from sandbox.safety.exfil import egress_technique

            egress = egress_technique(command) or ""
        elif op == "tool":
            from sandbox.safety.tool_actions import describe_call

            if any(t == "sends_data" for t, _ in describe_call(tool_name, tool_input)):
                egress = "sends_data"
        if egress:
            if result.reason_code != "EXFIL":  # don't count the same exfil twice
                assessment.raise_by(RiskFactor(
                    "exfiltration", EXFIL_POINTS,
                    f"sends a {level.upper()} file out ({best.path}, {egress})",
                ))
                result.reason_code = "EXFIL"
                result.reason = (f"possible data exfiltration: {level.upper()} file "
                                 f"{best.path} sent out ({egress})")
            result.verdict = "escalate"
            result.requires_dual = True
            return

    floor = "allow"
    if level == "restricted":
        if op == "read":
            floor = "escalate" if result.trigger == "read_outside" else "observe"
        else:
            floor = "escalate"
    elif level == "confidential" and op != "read":
        floor = "observe"

    raised = raise_verdict(result.verdict, floor)
    if raised != result.verdict:
        result.verdict = raised
        result.reason_code = "DATA_CLASS"
        result.reason = f"{tool_name} names classified data: {best.detail()}"


def apply_environment(result: Any, assessment: Any, policy: Any, tool_name: str) -> None:
    """In staging/prod, audit (observe) allowlisted calls of the audited classes.

    Runs after the risk-band tier upgrades on purpose: the score of an
    allowlisted command is computed as if it were not allowlisted, so letting
    the band act on it would escalate every ``ls`` in prod.
    """
    env = canonical_environment(getattr(policy, "environment", None))
    classes = ENV_AUDITED.get(env or "", ())
    if not classes or result.verdict != "allow" or _is_own_tool(tool_name):
        return
    effective = result.trigger or _action_class(tool_name)
    if effective not in classes:
        return
    assessment.raise_by(RiskFactor(
        "environment-audit", 0, f"{env}: allowlisted {effective} actions are audited",
    ))
    result.verdict = "observe"
    result.trigger = effective
    result.reason_code = "ENV_AUDIT"
    result.reason = f"{env}: allowlisted {effective} action, audited ({result.reason})"
    result.risk = assessment.to_dict()
