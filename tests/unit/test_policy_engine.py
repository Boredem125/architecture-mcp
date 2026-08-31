from __future__ import annotations

import pytest

from sandbox.agents.policy_engine import PolicyEngineAgent
from sandbox.models.enums import ActionType, PolicyDecision, RiskTier
from sandbox.models.messages import EnrichedRequest, MessageEnvelope


@pytest.fixture
def policy_agent():
    return PolicyEngineAgent()


def _make_envelope(
    intent_class: str = "READ",
    risk_tier: str = "LOW",
    session_context: dict | None = None,
) -> MessageEnvelope:
    payload = {
        "action_type": intent_class,
        "parameters": {},
        "session_token": "token",
        "request_id": "req-001",
        "intent_class": intent_class,
        "risk_tier": risk_tier,
        "schema_valid": True,
        "escalation_flags": [],
    }
    if session_context:
        payload["session_context"] = session_context
    return MessageEnvelope(
        session_id="sess-001",
        request_id="req-001",
        sender="request-evaluator:1.0.0",
        recipient="policy-engine",
        payload=payload,
    )


class TestPolicyEngine:
    @pytest.mark.asyncio
    async def test_allowed_action_passes(self, policy_agent):
        env = _make_envelope(
            "READ", "LOW",
            session_context={"allowed_actions": ["READ", "WRITE"], "write_count": 0,
                             "max_writes": 100, "total_requests": 0, "max_requests": 1000},
        )
        result = await policy_agent.process(env)
        assert result is not None
        assert result.payload["decision"] == "ALLOW"

    @pytest.mark.asyncio
    async def test_disallowed_action_denied(self, policy_agent):
        env = _make_envelope(
            "EXECUTE", "HIGH",
            session_context={"allowed_actions": ["READ"], "write_count": 0,
                             "max_writes": 100, "total_requests": 0, "max_requests": 1000},
        )
        result = await policy_agent.process(env)
        assert result is not None
        assert result.payload["decision"] == "DENY"

    @pytest.mark.asyncio
    async def test_critical_tier_escalates(self, policy_agent):
        env = _make_envelope(
            "READ", "CRITICAL",
            session_context={"allowed_actions": ["READ"], "write_count": 0,
                             "max_writes": 100, "total_requests": 0, "max_requests": 1000},
        )
        result = await policy_agent.process(env)
        assert result is not None
        assert result.payload["decision"] == "ESCALATE"

    @pytest.mark.asyncio
    async def test_write_budget_exhausted(self, policy_agent):
        env = _make_envelope(
            "WRITE", "MEDIUM",
            session_context={"allowed_actions": ["WRITE"], "write_count": 100,
                             "max_writes": 100, "total_requests": 50, "max_requests": 1000},
        )
        result = await policy_agent.process(env)
        assert result is not None
        assert result.payload["decision"] == "DENY"
        assert "budget" in result.payload["reason"].lower() or "exhausted" in result.payload["reason"].lower()
