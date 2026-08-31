"""Agent identity as a first-class object.

The north-star thesis is *capability ≠ authority*. Authority is granted to an
**identity**, not to a raw command. So every escalation and every audit record
carries a fully-resolved ``AgentIdentity`` — who the agent is, what model backs
it, which human operates it, in which project, at what trust level. Policy can
then say "Claude Code session X, operated by user Y, may run npm in project Z"
rather than the weaker "npm is allowed."

Nothing here is a security boundary on its own — a hostile agent can put any
string in the payload. Identity is an *attribution and authorization* layer: it
scopes what policy grants and it makes the audit trail examiner-grade. The hard
boundary remains the broker running approved actions outside the agent.
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

# Trust levels, lowest → highest authority. A higher trust level lowers the
# identity-risk contribution (see risk.py); it never bypasses a hard deny.
TRUST_LEVELS = ("untrusted", "low", "standard", "high")
_DEFAULT_TRUST = "standard"


@dataclass
class AgentIdentity:
    """Who is acting, resolved once per tool call and threaded everywhere."""

    agent_id: str = ""          # stable id for this agent instance/session
    agent_type: str = ""        # claude-code | codex | cursor | mcp | ...
    model: str = ""             # backing model, when the surface reports it
    version: str = ""           # connector/agent version, when known
    session_id: str = ""        # the sandbox session (from session.json)
    project: str = ""           # project/root name
    user: str = ""              # the human the agent is operating on behalf of
    trust_level: str = _DEFAULT_TRUST

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def label(self) -> str:
        """Compact human label for watch panels and logs."""
        who = self.user or "unknown-user"
        what = self.agent_type or "agent"
        return f"{what}({self.model or '?'})/{who}"


def _load_session(layout) -> dict[str, Any]:
    try:
        return json.loads(layout.session_file.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def _default_user() -> str:
    import getpass

    try:
        return getpass.getuser()
    except Exception:  # noqa: BLE001
        import os

        return os.environ.get("USERNAME") or os.environ.get("USER") or ""


def from_payload(payload: dict[str, Any], layout, policy: Any = None) -> AgentIdentity:
    """Resolve the acting identity from a hook/MCP payload + session.json.

    Precedence for each field: explicit payload ``agent`` block → session.json →
    environment/default. The trust level comes from policy (per-agent-type map)
    when available, else the shipped default.
    """
    session = _load_session(layout)
    agent = payload.get("agent") or {}
    if not isinstance(agent, dict):
        agent = {}

    agent_type = (
        agent.get("kind")
        or agent.get("agent_type")
        or payload.get("agent_type")
        or "claude-code"
    )
    session_id = (
        agent.get("agent_session_id")
        or payload.get("session_id")
        or session.get("session_id", "")
    )
    root = getattr(layout, "root", "")
    project = session.get("project") or (Path(str(root)).name if root else "")

    trust = _resolve_trust(agent_type, policy)

    return AgentIdentity(
        agent_id=agent.get("agent_id") or session_id or agent_type,
        agent_type=agent_type,
        model=agent.get("model") or payload.get("model") or "",
        version=agent.get("version") or session.get("connector_version") or "",
        session_id=session_id,
        project=project,
        user=agent.get("user") or session.get("user") or _default_user(),
        trust_level=trust,
    )


def _resolve_trust(agent_type: str, policy: Any) -> str:
    """Per-agent-type trust from policy, if configured; else the default."""
    if policy is not None:
        trust_map = getattr(getattr(policy, "identity", None), "trust", None)
        if isinstance(trust_map, dict):
            lvl = trust_map.get(agent_type)
            if lvl in TRUST_LEVELS:
                return lvl
    return _DEFAULT_TRUST
