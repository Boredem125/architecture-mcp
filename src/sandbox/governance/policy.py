"""The governance policy model and loader."""
from __future__ import annotations

import json
from pathlib import Path

from pydantic import BaseModel, Field


class Clause(BaseModel):
    """One governance rule, in plain language plus how to enforce it."""

    id: str
    title: str
    description: str  # plain language, shown to humans and written to the audit
    # The semantic condition, as a jev-os yes/no statement about the action.
    check: str
    threshold: float = 0.5
    # Optional deterministic gate: the action must also do one of these (tags
    # from safety/command_actions.describe). Makes a noisy check robust, e.g.
    # "no data to external services" only fires when egress is actually present.
    requires_actions: list[str] = Field(default_factory=list)
    # The same for non-shell tool calls (MCP tools, WebFetch): tags from
    # safety/tool_actions.describe_call. A clause without any is not evaluated
    # on tool calls: the check alone false-alarmed on 17 of 24 benign calls
    # (benchmarks/tool_calls/README.md).
    requires_tool_actions: list[str] = Field(default_factory=list)
    # Optional distilled classifier for this clause (governance/student.py),
    # relative to the policy file. Fires alongside the check, behind the gate.
    student_model: str = ""
    action: str = "escalate"  # escalate | deny (never "allow": clauses only raise scrutiny)
    framework_refs: list[str] = Field(default_factory=list)  # e.g. "EU AI Act Art. 14"
    # Labelled examples for `sandbox governance test`: does the clause fire?
    examples_violating: list[str] = Field(default_factory=list)
    examples_allowed: list[str] = Field(default_factory=list)

    def question(self) -> dict[str, str]:
        return {"type": "noul", "instructions": self.check}


class GovernancePolicy(BaseModel):
    name: str = "governance policy"
    clauses: list[Clause] = Field(default_factory=list)

    def questions(self) -> dict[str, dict[str, str]]:
        return {c.id: c.question() for c in self.clauses}


def load(path: str | Path) -> GovernancePolicy:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return GovernancePolicy.model_validate(data)


def example_policy_path() -> Path:
    return Path(__file__).resolve().parent / "examples" / "policy.json"
