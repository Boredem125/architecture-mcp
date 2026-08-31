from __future__ import annotations
from fastapi import APIRouter

router = APIRouter(prefix="/api/v1/dashboard", tags=["dashboard"])


@router.get("/stats")
def get_stats() -> dict:
    from sandbox.api.routes.agents import _agents
    from sandbox.api.routes.policies import _policies
    from sandbox.api.routes.security import _jit_grants, _roles

    connected_agents = sum(1 for a in _agents.values() if a.status == "connected")
    active_jit = sum(1 for g in _jit_grants.values() if g.active)

    return {
        "active_sessions": 0,
        "connected_agents": connected_agents,
        "total_agents": len(_agents),
        "pending_hitl": 0,
        "policy_rules": len(_policies),
        "active_jit_grants": active_jit,
        "rbac_roles": len(_roles),
    }
