from __future__ import annotations
from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, HTTPException
from sandbox.models.security import (
    JITAccessGrant, JITAccessRequest,
    RBACRole, RBACRoleRequest,
    ConditionalAccessPolicy, ConditionalAccessRequest,
    ZeroTrustScore,
)

router = APIRouter(prefix="/api/v1/security", tags=["security"])

_jit_grants: dict[str, JITAccessGrant] = {}
_roles: dict[str, RBACRole] = {}
_conditional_policies: dict[str, ConditionalAccessPolicy] = {}

# Pre-seed default RBAC roles
_DEFAULT_ROLES = [
    RBACRole(
        name="reader",
        description="Read-only access to workspace files",
        permissions=["READ"],
        max_risk_tier="LOW",
        requires_mfa=False,
    ),
    RBACRole(
        name="writer",
        description="Read and write access within workspace",
        permissions=["READ", "WRITE"],
        max_risk_tier="MEDIUM",
        requires_mfa=False,
    ),
    RBACRole(
        name="operator",
        description="Can execute commands within sandbox limits",
        permissions=["READ", "WRITE", "EXECUTE"],
        max_risk_tier="HIGH",
        requires_mfa=True,
    ),
    RBACRole(
        name="admin",
        description="Full access including secrets - requires MFA",
        permissions=["READ", "WRITE", "EXECUTE", "NETWORK", "SECRET_ACCESS"],
        max_risk_tier="CRITICAL",
        requires_mfa=True,
    ),
]

for role in _DEFAULT_ROLES:
    _roles[role.id] = role


# --- JIT Access ---

@router.post("/jit/grant")
def grant_jit_access(req: JITAccessRequest) -> JITAccessGrant:
    now = datetime.now(timezone.utc)
    expires = now + timedelta(minutes=req.duration_minutes)
    grant = JITAccessGrant(
        agent_id=req.agent_id,
        elevated_actions=req.elevated_actions,
        reason=req.reason,
        duration_minutes=req.duration_minutes,
        expires_at=expires.isoformat(),
    )
    _jit_grants[grant.id] = grant
    return grant


@router.get("/jit/grants")
def list_jit_grants() -> list[JITAccessGrant]:
    now = datetime.now(timezone.utc)
    for grant in _jit_grants.values():
        if grant.expires_at and grant.active:
            exp = datetime.fromisoformat(grant.expires_at)
            if now >= exp:
                grant.active = False
    return list(_jit_grants.values())


@router.post("/jit/revoke/{grant_id}")
def revoke_jit_access(grant_id: str) -> JITAccessGrant:
    grant = _jit_grants.get(grant_id)
    if grant is None:
        raise HTTPException(status_code=404, detail="JIT grant not found")
    grant.active = False
    return grant


# --- RBAC ---

@router.get("/rbac/roles")
def list_roles() -> list[RBACRole]:
    return list(_roles.values())


@router.post("/rbac/roles")
def create_role(req: RBACRoleRequest) -> RBACRole:
    role = RBACRole(
        name=req.name,
        description=req.description,
        permissions=req.permissions,
        max_risk_tier=req.max_risk_tier,
        requires_mfa=req.requires_mfa,
    )
    _roles[role.id] = role
    return role


@router.delete("/rbac/roles/{role_id}")
def delete_role(role_id: str) -> dict:
    if role_id not in _roles:
        raise HTTPException(status_code=404, detail="Role not found")
    del _roles[role_id]
    return {"status": "deleted", "role_id": role_id}


# --- Conditional Access ---

@router.get("/conditional-access")
def list_conditional_policies() -> list[ConditionalAccessPolicy]:
    return list(_conditional_policies.values())


@router.post("/conditional-access")
def create_conditional_policy(req: ConditionalAccessRequest) -> ConditionalAccessPolicy:
    policy = ConditionalAccessPolicy(
        name=req.name,
        conditions=req.conditions,
        actions=req.actions,
    )
    _conditional_policies[policy.id] = policy
    return policy


@router.put("/conditional-access/{policy_id}/toggle")
def toggle_conditional_policy(policy_id: str) -> ConditionalAccessPolicy:
    policy = _conditional_policies.get(policy_id)
    if policy is None:
        raise HTTPException(status_code=404, detail="Policy not found")
    policy.enabled = not policy.enabled
    return policy


@router.delete("/conditional-access/{policy_id}")
def delete_conditional_policy(policy_id: str) -> dict:
    if policy_id not in _conditional_policies:
        raise HTTPException(status_code=404, detail="Policy not found")
    del _conditional_policies[policy_id]
    return {"status": "deleted", "policy_id": policy_id}


# --- Zero Trust Score ---

@router.get("/zero-trust/score")
def get_zero_trust_score() -> ZeroTrustScore:
    checks = []
    score = 0

    # Identity checks
    identity_checks = [
        {"name": "OAuth2 agent authentication", "status": True, "category": "identity"},
        {"name": "Capability token validation", "status": True, "category": "identity"},
        {"name": "Session-scoped access", "status": True, "category": "identity"},
        {"name": "MFA for HITL approvals", "status": False, "category": "identity"},
    ]
    identity_score = sum(1 for c in identity_checks if c["status"]) * 25
    checks.extend(identity_checks)

    # Network checks
    network_checks = [
        {"name": "Zone isolation (3-zone model)", "status": True, "category": "network"},
        {"name": "Inter-zone message signing", "status": True, "category": "network"},
        {"name": "Network allowlist enforcement", "status": True, "category": "network"},
        {"name": "mTLS between services", "status": False, "category": "network"},
    ]
    network_score = sum(1 for c in network_checks if c["status"]) * 25
    checks.extend(network_checks)

    # Data checks
    data_checks = [
        {"name": "Secret scanning & redaction", "status": True, "category": "data"},
        {"name": "Output scrubbing", "status": True, "category": "data"},
        {"name": "Hash-chained audit log", "status": True, "category": "data"},
        {"name": "Encryption at rest", "status": False, "category": "data"},
    ]
    data_score = sum(1 for c in data_checks if c["status"]) * 25
    checks.extend(data_checks)

    # Device checks (agent trust)
    device_checks = [
        {"name": "Agent identity verification", "status": True, "category": "device"},
        {"name": "Deny-by-default policy", "status": True, "category": "device"},
        {"name": "Behavioral anomaly detection", "status": True, "category": "device"},
        {"name": "Prompt injection detection", "status": True, "category": "device"},
    ]
    device_score = sum(1 for c in device_checks if c["status"]) * 25
    checks.extend(device_checks)

    overall = (identity_score + network_score + data_score + device_score) // 4

    return ZeroTrustScore(
        overall_score=overall,
        identity_score=identity_score,
        network_score=network_score,
        data_score=data_score,
        device_score=device_score,
        checks=checks,
    )
