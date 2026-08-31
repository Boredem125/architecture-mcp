from __future__ import annotations
import secrets
from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, HTTPException
from sandbox.models.security import (
    AgentConnection, AgentRegistrationRequest, AgentType, ConnectionStatus,
    TrustLevel, OAuth2TokenRequest, OAuth2TokenResponse,
)

router = APIRouter(prefix="/api/v1/agents", tags=["agents"])

_agents: dict[str, AgentConnection] = {}
_tokens: dict[str, str] = {}  # token -> agent_id

# Pre-seed some well-known agent types
_KNOWN_AGENTS = {
    "claude-code": {"name": "Claude Code", "type": AgentType.CLAUDE_CODE},
    "codex": {"name": "OpenAI Codex", "type": AgentType.CODEX},
    "hermes": {"name": "Hermes", "type": AgentType.HERMES},
    "antigravity": {"name": "Antigravity", "type": AgentType.ANTIGRAVITY},
}


@router.post("/register")
def register_agent(req: AgentRegistrationRequest) -> AgentConnection:
    agent = AgentConnection(
        name=req.name,
        type=req.type,
        capabilities=req.capabilities,
        trust_level=req.trust_level,
        client_secret=secrets.token_hex(32),
        metadata=req.metadata,
    )
    _agents[agent.id] = agent
    return agent


@router.post("/oauth2/token")
def oauth2_token(req: OAuth2TokenRequest) -> OAuth2TokenResponse:
    agent = None
    for a in _agents.values():
        if a.client_id == req.client_id and a.client_secret == req.client_secret:
            agent = a
            break
    if agent is None:
        raise HTTPException(status_code=401, detail="Invalid client credentials")

    token = secrets.token_hex(32)
    _tokens[token] = agent.id
    agent.status = ConnectionStatus.CONNECTED
    agent.connected_at = datetime.now(timezone.utc).isoformat()

    return OAuth2TokenResponse(
        access_token=token,
        expires_in=3600,
        scope=" ".join(f"sandbox:{c.lower()}" for c in agent.capabilities),
    )


@router.get("/")
def list_agents() -> list[AgentConnection]:
    return list(_agents.values())


@router.get("/available")
def available_agents() -> list[dict]:
    return [
        {"id": k, "name": v["name"], "type": v["type"], "connected": any(
            a.type == v["type"] and a.status == ConnectionStatus.CONNECTED
            for a in _agents.values()
        )}
        for k, v in _KNOWN_AGENTS.items()
    ]


@router.get("/{agent_id}")
def get_agent(agent_id: str) -> AgentConnection:
    agent = _agents.get(agent_id)
    if agent is None:
        raise HTTPException(status_code=404, detail="Agent not found")
    return agent


@router.post("/{agent_id}/disconnect")
def disconnect_agent(agent_id: str) -> AgentConnection:
    agent = _agents.get(agent_id)
    if agent is None:
        raise HTTPException(status_code=404, detail="Agent not found")
    agent.status = ConnectionStatus.DISCONNECTED
    _tokens = {k: v for k, v in _tokens.items() if v != agent_id}
    return agent


@router.delete("/{agent_id}")
def remove_agent(agent_id: str) -> dict:
    if agent_id not in _agents:
        raise HTTPException(status_code=404, detail="Agent not found")
    del _agents[agent_id]
    return {"status": "removed", "agent_id": agent_id}
