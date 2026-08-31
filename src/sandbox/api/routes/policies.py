from __future__ import annotations
from fastapi import APIRouter, HTTPException
from sandbox.models.security import PolicyFile, PolicyUploadRequest

router = APIRouter(prefix="/api/v1/policies", tags=["policies"])

_policies: dict[str, PolicyFile] = {}


@router.post("/upload")
def upload_policy(req: PolicyUploadRequest) -> PolicyFile:
    policy = PolicyFile(name=req.name, content=req.content, category=req.category)
    _policies[policy.id] = policy
    return policy


@router.get("/")
def list_policies() -> list[PolicyFile]:
    return list(_policies.values())


@router.get("/{policy_id}")
def get_policy(policy_id: str) -> PolicyFile:
    policy = _policies.get(policy_id)
    if policy is None:
        raise HTTPException(status_code=404, detail="Policy not found")
    return policy


@router.put("/{policy_id}/toggle")
def toggle_policy(policy_id: str) -> PolicyFile:
    policy = _policies.get(policy_id)
    if policy is None:
        raise HTTPException(status_code=404, detail="Policy not found")
    policy.active = not policy.active
    return policy


@router.put("/{policy_id}")
def update_policy(policy_id: str, req: PolicyUploadRequest) -> PolicyFile:
    policy = _policies.get(policy_id)
    if policy is None:
        raise HTTPException(status_code=404, detail="Policy not found")
    policy.name = req.name
    policy.content = req.content
    policy.category = req.category
    policy.version += 1
    return policy


@router.delete("/{policy_id}")
def delete_policy(policy_id: str) -> dict:
    if policy_id not in _policies:
        raise HTTPException(status_code=404, detail="Policy not found")
    del _policies[policy_id]
    return {"status": "deleted", "policy_id": policy_id}
