from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field

from sandbox.models.enums import (
    ActionType,
    AnomalyType,
    ContentDecision,
    ExecutionResult,
    HITLDecision,
    PolicyDecision,
    RiskTier,
)


def _uuid() -> str:
    return str(uuid.uuid4())


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class MessageEnvelope(BaseModel):
    """Inter-agent message envelope per AGENTS.md contract."""

    msg_id: str = Field(default_factory=_uuid)
    session_id: str
    request_id: str
    sender: str
    recipient: str
    timestamp_utc: str = Field(default_factory=_now)
    payload: dict[str, Any] = Field(default_factory=dict)
    signature: str = ""


# --- Zone 1 → Zone 2 ---


class ActionRequest(BaseModel):
    """Raw request from Task Agent to sandbox pipeline."""

    action_type: ActionType
    parameters: dict[str, Any] = Field(default_factory=dict)
    session_token: str
    request_id: str = Field(default_factory=_uuid)


# --- Request Evaluator output ---


class EnrichedRequest(BaseModel):
    """Output of Request Evaluator — request with classification attached."""

    action_type: ActionType
    parameters: dict[str, Any]
    session_token: str
    request_id: str
    intent_class: ActionType
    risk_tier: RiskTier
    schema_valid: bool = True
    escalation_flags: list[str] = Field(default_factory=list)


# --- Policy Engine output ---


class PolicyResult(BaseModel):
    request_id: str
    decision: PolicyDecision
    policy_version: str = "1.0.0"
    matched_rule: str = ""
    reason: str = ""


# --- Content Safety output ---


class ContentSafetyResult(BaseModel):
    request_id: str
    decision: ContentDecision
    injection_flags: list[str] = Field(default_factory=list)
    secret_redaction_count: int = 0
    scanner_id: str = "content-safety-v1"
    reason: str = ""


# --- HITL output ---


class HITLResult(BaseModel):
    request_id: str
    decision: HITLDecision
    reviewer_id: str | None = None
    reason: str = ""
    latency_ms: int | None = None


class HITLContextPackage(BaseModel):
    """Decision context assembled for human reviewer."""

    request_id: str
    session_id: str
    agent_id: str
    action_type: ActionType
    risk_tier: RiskTier
    parameters: dict[str, Any]
    escalation_reason: str
    policy_decision: PolicyDecision
    content_safety_flags: list[str] = Field(default_factory=list)
    anomaly_flags: list[str] = Field(default_factory=list)
    session_history_summary: str = ""
    timeout_at_utc: str = ""
    reviewer_guidance: str = ""


# --- Command Signing ---


class SignedCommand(BaseModel):
    """Signed command ready for executor."""

    request_id: str
    session_id: str
    action_type: ActionType
    parameters: dict[str, Any]
    scope: list[str] = Field(default_factory=list)
    timeout_ms: int = 30000
    command_hash: str = ""
    signature: str = ""
    signed_at_utc: str = Field(default_factory=_now)


# --- Executor output ---


class ExecutionOutput(BaseModel):
    request_id: str
    stdout: str = ""
    stderr: str = ""
    exit_code: int = 0
    result: ExecutionResult = ExecutionResult.SUCCESS
    resource_usage: dict[str, Any] = Field(default_factory=dict)
    duration_ms: int = 0


class ScrubbedOutput(BaseModel):
    """Output after content safety scrubbing."""

    request_id: str
    stdout: str = ""
    stderr: str = ""
    exit_code: int = 0
    result: ExecutionResult = ExecutionResult.SUCCESS
    scrubbed: bool = True
    redaction_count: int = 0
    output_hash: str = ""
    signature: str = ""


# --- Rollback ---


class SnapshotRecord(BaseModel):
    snapshot_id: str = Field(default_factory=_uuid)
    request_id: str
    session_id: str
    action_type: ActionType
    snapshot_hash: str = ""
    created_at_utc: str = Field(default_factory=_now)
    size_bytes: int = 0


class RollbackRequest(BaseModel):
    session_id: str
    scope: str = "single"  # single | range | full
    request_ids: list[str] = Field(default_factory=list)
    reason: str = ""
    requester: str = ""


class RollbackResult(BaseModel):
    session_id: str
    scope: str
    actions_rolled_back: int = 0
    actions_failed: int = 0
    final_state_hash: str = ""


# --- Anomaly ---


class AnomalySignal(BaseModel):
    session_id: str
    anomaly_type: AnomalyType
    evidence_summary: str = ""
    anomaly_score: float = 0.0
    recommended_action: str = ""


class KillSwitchEvent(BaseModel):
    session_id: str
    reason: str
    evidence: dict[str, Any] = Field(default_factory=dict)
    triggered_by: str = "anomaly-detector"
    timestamp_utc: str = Field(default_factory=_now)


# --- Pipeline status ---


class PipelineStatus(BaseModel):
    request_id: str
    session_id: str
    status: str  # PROCESSING | COMPLETED | DENIED | HALTED | ESCALATED
    current_step: int = 0
    step_name: str = ""
    decision: str = ""
    reason: str = ""
    total_latency_ms: int = 0
