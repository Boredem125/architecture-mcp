from __future__ import annotations

from sandbox.models.enums import ActionType, RiskTier, PolicyDecision
from sandbox.models.messages import (
    ActionRequest,
    EnrichedRequest,
    MessageEnvelope,
    PolicyResult,
    SignedCommand,
)


class TestEnums:
    def test_risk_tier_ordering(self):
        assert RiskTier.LOW < RiskTier.MEDIUM  # type: ignore[operator]
        assert RiskTier.MEDIUM < RiskTier.HIGH  # type: ignore[operator]
        assert RiskTier.HIGH < RiskTier.CRITICAL  # type: ignore[operator]

    def test_risk_tier_upgrade(self):
        assert RiskTier.LOW.upgrade() == RiskTier.MEDIUM
        assert RiskTier.MEDIUM.upgrade() == RiskTier.HIGH
        assert RiskTier.HIGH.upgrade() == RiskTier.CRITICAL
        assert RiskTier.CRITICAL.upgrade() == RiskTier.CRITICAL


class TestActionRequest:
    def test_create(self):
        req = ActionRequest(
            action_type=ActionType.READ,
            parameters={"path": "/tmp/workspace/file.txt"},
            session_token="token-123",
        )
        assert req.action_type == ActionType.READ
        assert req.request_id is not None

    def test_serialization(self):
        req = ActionRequest(
            action_type=ActionType.WRITE,
            parameters={"path": "/tmp/workspace/out.txt", "content": "hello"},
            session_token="token-456",
        )
        data = req.model_dump()
        assert data["action_type"] == "WRITE"
        restored = ActionRequest(**data)
        assert restored.action_type == ActionType.WRITE


class TestMessageEnvelope:
    def test_envelope_creation(self):
        env = MessageEnvelope(
            session_id="sess-001",
            request_id="req-001",
            sender="task-agent:1.0.0",
            recipient="request-evaluator",
            payload={"action_type": "READ"},
        )
        assert env.msg_id is not None
        assert env.timestamp_utc is not None
        assert env.sender == "task-agent:1.0.0"


class TestEnrichedRequest:
    def test_enriched_fields(self):
        enriched = EnrichedRequest(
            action_type=ActionType.EXECUTE,
            parameters={"command": "ls -la"},
            session_token="token",
            request_id="req-001",
            intent_class=ActionType.EXECUTE,
            risk_tier=RiskTier.HIGH,
            escalation_flags=["new_action_type_upgrade:EXECUTE"],
        )
        assert enriched.risk_tier == RiskTier.HIGH
        assert len(enriched.escalation_flags) == 1


class TestPolicyResult:
    def test_allow(self):
        result = PolicyResult(
            request_id="req-001",
            decision=PolicyDecision.ALLOW,
            matched_rule="default_allow",
        )
        assert result.decision == PolicyDecision.ALLOW

    def test_deny(self):
        result = PolicyResult(
            request_id="req-001",
            decision=PolicyDecision.DENY,
            reason="Action not in session allowlist",
        )
        assert result.decision == PolicyDecision.DENY
