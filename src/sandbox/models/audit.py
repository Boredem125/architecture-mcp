from __future__ import annotations

import uuid
from datetime import datetime, timezone

from pydantic import BaseModel, Field

from sandbox.models.enums import (
    ActionType,
    ContentDecision,
    ExecutionResult,
    HITLDecision,
    PolicyDecision,
    RiskTier,
    ZoneSource,
)


def _uuid() -> str:
    return str(uuid.uuid4())


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class AuditRecord(BaseModel):
    """Full audit record covering one request lifecycle per AGENT_07 spec."""

    record_id: str = Field(default_factory=_uuid)
    session_id: str
    agent_id: str
    timestamp_utc: str = Field(default_factory=_now)
    zone_source: ZoneSource = ZoneSource.SANDBOX
    action_type: ActionType
    risk_tier: RiskTier
    schema_valid: bool = True
    intent_class: str = ""
    policy_decision: PolicyDecision | None = None
    policy_version: str = ""
    matched_rule: str = ""
    content_safety_decision: ContentDecision | None = None
    injection_flags: list[str] = Field(default_factory=list)
    secret_redaction_count: int = 0
    hitl_invoked: bool = False
    hitl_reviewer_id: str | None = None
    hitl_decision: HITLDecision | None = None
    hitl_latency_ms: int | None = None
    anomaly_flags: list[str] = Field(default_factory=list)
    anomaly_score: float = 0.0
    command_hash: str = ""
    execution_result: ExecutionResult | None = None
    output_hash: str = ""
    scrubbed: bool = False
    rollback_snapshot_id: str | None = None
    total_pipeline_latency_ms: int = 0
    evaluator_versions: dict[str, str] = Field(default_factory=dict)
    incomplete: bool = False
    previous_record_hash: str = ""
    record_hash: str = ""


class AuditFragment(BaseModel):
    """Partial audit data contributed by one pipeline step."""

    request_id: str
    session_id: str
    step_name: str
    step_number: int
    agent_name: str
    timestamp_utc: str = Field(default_factory=_now)
    data: dict = Field(default_factory=dict)


class SessionSealRecord(BaseModel):
    """Written at session end to seal the audit log segment."""

    session_id: str
    event: str = "SESSION_END"
    reason: str
    total_requests: int
    total_denies: int
    total_hitl: int
    session_duration_ms: int
    summary_hash: str
    sealed_at_utc: str = Field(default_factory=_now)
