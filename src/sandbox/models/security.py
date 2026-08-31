from __future__ import annotations
from datetime import datetime, timezone
from enum import StrEnum
from pydantic import BaseModel, Field
import uuid


class TrustLevel(StrEnum):
    UNTRUSTED = "untrusted"
    BASIC = "basic"
    ELEVATED = "elevated"


class AgentType(StrEnum):
    CLAUDE_CODE = "claude-code"
    CODEX = "codex"
    HERMES = "hermes"
    ANTIGRAVITY = "antigravity"
    CUSTOM = "custom"


class ConnectionStatus(StrEnum):
    CONNECTED = "connected"
    DISCONNECTED = "disconnected"
    PENDING = "pending"


class AgentConnection(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    type: AgentType
    status: ConnectionStatus = ConnectionStatus.PENDING
    session_id: str | None = None
    capabilities: list[str] = Field(default_factory=list)
    trust_level: TrustLevel = TrustLevel.UNTRUSTED
    client_id: str = Field(default_factory=lambda: f"agent-{uuid.uuid4().hex[:12]}")
    client_secret: str | None = None
    connected_at: str | None = None
    metadata: dict = Field(default_factory=dict)


class AgentRegistrationRequest(BaseModel):
    name: str
    type: AgentType
    capabilities: list[str] = Field(default_factory=lambda: ["READ"])
    trust_level: TrustLevel = TrustLevel.UNTRUSTED
    metadata: dict = Field(default_factory=dict)


class OAuth2TokenRequest(BaseModel):
    grant_type: str = "client_credentials"
    client_id: str
    client_secret: str
    scope: str = "sandbox:read"


class OAuth2TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int = 3600
    scope: str = "sandbox:read"


class PolicyFile(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    content: str
    category: str = "custom"
    uploaded_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    uploaded_by: str = "admin"
    active: bool = True
    version: int = 1


class PolicyUploadRequest(BaseModel):
    name: str
    content: str
    category: str = "custom"


class JITAccessGrant(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    agent_id: str
    elevated_actions: list[str]
    reason: str
    approved_by: str = "admin"
    granted_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    expires_at: str = ""
    duration_minutes: int = 30
    active: bool = True


class JITAccessRequest(BaseModel):
    agent_id: str
    elevated_actions: list[str]
    reason: str
    duration_minutes: int = 30


class RBACRole(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    description: str = ""
    permissions: list[str] = Field(default_factory=list)
    max_risk_tier: str = "MEDIUM"
    requires_mfa: bool = False
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class RBACRoleRequest(BaseModel):
    name: str
    description: str = ""
    permissions: list[str] = Field(default_factory=list)
    max_risk_tier: str = "MEDIUM"
    requires_mfa: bool = False


class ConditionalAccessPolicy(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    conditions: dict = Field(default_factory=dict)
    actions: dict = Field(default_factory=dict)
    enabled: bool = True
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class ConditionalAccessRequest(BaseModel):
    name: str
    conditions: dict = Field(default_factory=dict)
    actions: dict = Field(default_factory=dict)


class ZeroTrustScore(BaseModel):
    overall_score: int = 0
    identity_score: int = 0
    device_score: int = 0
    network_score: int = 0
    data_score: int = 0
    checks: list[dict] = Field(default_factory=list)
