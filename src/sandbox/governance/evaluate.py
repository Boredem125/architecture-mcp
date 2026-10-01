"""Evaluate governance clauses against an action.

A clause fires when its jev-os check passes AND (if it lists required actions)
the command deterministically does one of them. The deterministic gate keeps a
noisy zero-shot check from firing on unrelated text.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from sandbox.governance.policy import Clause, GovernancePolicy
from sandbox.safety.command_actions import describe as _describe_command
from sandbox.safety.tool_actions import describe_call as _describe_call
from sandbox.safety.tool_actions import render as _render_call
from sandbox.semantic.client import SemanticClient


@dataclass
class Violation:
    clause_id: str
    title: str
    description: str
    action: str            # escalate | deny
    score: float
    framework_refs: list[str]

    def evidence(self) -> dict[str, Any]:
        return {
            "clause_id": self.clause_id,
            "title": self.title,
            "action": self.action,
            "score": round(self.score, 4),
            "framework_refs": self.framework_refs,
        }


def _gate_ok(clause: Clause, command: str) -> bool:
    if not clause.requires_actions:
        return True
    tags = {t for t, _ in _describe_command(command or "")}
    return bool(tags & set(clause.requires_actions))


def evaluate(
    policy: GovernancePolicy,
    text: str,
    client: SemanticClient,
    *,
    command: str = "",
    tool_call: tuple[str, dict[str, Any]] | None = None,
) -> list[Violation]:
    """Clauses violated by this action, worst `action` first. Empty on any
    service failure (no extra scrutiny, never less).

    With ``tool_call=(tool_name, tool_input)`` the action is a non-shell call:
    only clauses whose ``requires_tool_actions`` match what the call does are
    checked, against the call rendered as text (``text`` is ignored).
    """
    students = {}
    if tool_call is not None:
        tags = {t for t, _ in _describe_call(*tool_call)}
        gated = [c for c in policy.clauses if set(c.requires_tool_actions) & tags]
        text = _render_call(*tool_call)
    else:
        gated = [c for c in policy.clauses if _gate_ok(c, command or text)]
        # Distilled clause students (governance/student.py) are trained on
        # shell commands, so they apply to this path only.
        from sandbox.governance.student import load_students

        students = load_students(policy, policy._source or None)
    if not gated:
        return []
    result = client.ask(text, {c.id: c.question() for c in gated})
    if result is None and not any(c.id in students for c in gated):
        return []
    violations = []
    for c in gated:
        score = result.scores.get(c.id, 0.0) if result is not None else 0.0
        fires = result is not None and score >= c.threshold
        student = students.get(c.id)
        if student is not None:
            p = student.probability(text)
            hit = p >= student.threshold
            fires = hit if c.student_mode == "replace" else (fires or hit)
            score = max(score, p) if hit else score
        if fires:
            violations.append(Violation(c.id, c.title, c.description, c.action, score, c.framework_refs))
    violations.sort(key=lambda v: 0 if v.action == "deny" else 1)
    return violations
