from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field

from sandbox.models.enums import ActionType, SessionEndReason


def _uuid() -> str:
    return str(uuid.uuid4())


def _now() -> datetime:
    return datetime.now(timezone.utc)


class CapabilityToken(BaseModel):
    """Scoped capability token issued at session start."""

    agent_id: str
    session_id: str
    allowed_actions: list[ActionType]
    workspace_root: str = "/tmp/workspace"
    allowed_network_hosts: list[str] = Field(default_factory=list)
    allowed_secrets: list[str] = Field(default_factory=list)
    max_writes: int = 100
    max_requests: int = 1000
    expires_at_utc: str = ""
    issued_by: str = ""
    token_fingerprint: str = ""
    signature: str = ""


class SessionState(BaseModel):
    """Full session state stored in session registry."""

    session_id: str = Field(default_factory=_uuid)
    agent_id: str
    capability_token: CapabilityToken
    declared_task: str = ""
    started_at: datetime = Field(default_factory=_now)
    expires_at: datetime | None = None
    ended_at: datetime | None = None
    end_reason: SessionEndReason | None = None

    # Counters
    total_requests: int = 0
    read_count: int = 0
    write_count: int = 0
    execute_count: int = 0
    network_count: int = 0
    secret_access_count: int = 0
    deny_count: int = 0
    hitl_count: int = 0

    # Action history for anomaly detection
    action_history: list[str] = Field(default_factory=list)
    target_resources: set[str] = Field(default_factory=set)
    request_timestamps: list[float] = Field(default_factory=list)

    # State flags
    is_active: bool = True
    is_killed: bool = False
    audit_gap: bool = False
    baseline_established: bool = False

    model_config = {"arbitrary_types_allowed": True}

    def increment_action(self, action_type: ActionType) -> None:
        self.total_requests += 1
        counter_map = {
            ActionType.READ: "read_count",
            ActionType.WRITE: "write_count",
            ActionType.EXECUTE: "execute_count",
            ActionType.NETWORK: "network_count",
            ActionType.SECRET_ACCESS: "secret_access_count",
        }
        attr = counter_map.get(action_type)
        if attr:
            setattr(self, attr, getattr(self, attr) + 1)
        self.action_history.append(action_type.value)
        self.request_timestamps.append(datetime.now(timezone.utc).timestamp())


class SessionStartRequest(BaseModel):
    agent_id: str
    declared_task: str = ""
    allowed_actions: list[ActionType] = Field(default_factory=lambda: [ActionType.READ])
    workspace_root: str = "/tmp/workspace"
    allowed_network_hosts: list[str] = Field(default_factory=list)
    allowed_secrets: list[str] = Field(default_factory=list)
    max_writes: int = 100
    ttl_seconds: int = 1800


class SessionEndRequest(BaseModel):
    session_id: str
    reason: SessionEndReason = SessionEndReason.DONE


class SessionSummary(BaseModel):
    """Summary generated at session end for audit sealing."""

    session_id: str
    agent_id: str
    total_requests: int
    total_denies: int
    total_hitl: int
    session_duration_ms: int
    end_reason: SessionEndReason
    summary_hash: str = ""
