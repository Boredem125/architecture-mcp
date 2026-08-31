from __future__ import annotations

import pytest

from sandbox.agents.request_evaluator import RequestEvaluatorAgent
from sandbox.models.enums import ActionType, RiskTier
from sandbox.models.messages import MessageEnvelope


@pytest.fixture
def evaluator():
    return RequestEvaluatorAgent()


def _make_envelope(action_type: str, parameters: dict | None = None) -> MessageEnvelope:
    return MessageEnvelope(
        session_id="sess-001",
        request_id="req-001",
        sender="task-agent:1.0.0",
        recipient="request-evaluator",
        payload={
            "action_type": action_type,
            "parameters": parameters or {},
            "session_token": "valid-token",
            "request_id": "req-001",
        },
    )


class TestRequestEvaluator:
    @pytest.mark.asyncio
    async def test_read_classified_as_low(self, evaluator):
        env = _make_envelope("READ", {"path": "/tmp/workspace/file.txt"})
        result = await evaluator.process(env)
        assert result is not None
        assert result.payload["risk_tier"] in ("LOW", "MEDIUM")

    @pytest.mark.asyncio
    async def test_execute_classified_as_high(self, evaluator):
        env = _make_envelope("EXECUTE", {"command": "ls"})
        result = await evaluator.process(env)
        assert result is not None
        assert result.payload["risk_tier"] in ("HIGH", "CRITICAL")

    @pytest.mark.asyncio
    async def test_secret_access_classified_critical(self, evaluator):
        env = _make_envelope("SECRET_ACCESS", {"secret": "db-password"})
        result = await evaluator.process(env)
        assert result is not None
        assert result.payload["risk_tier"] == "CRITICAL"

    @pytest.mark.asyncio
    async def test_missing_token_rejected(self, evaluator):
        env = MessageEnvelope(
            session_id="sess-001",
            request_id="req-001",
            sender="task-agent:1.0.0",
            recipient="request-evaluator",
            payload={
                "action_type": "READ",
                "parameters": {},
                "session_token": "",
                "request_id": "req-001",
            },
        )
        result = await evaluator.process(env)
        assert result is not None
        assert result.payload["decision"] == "REJECT"
        assert result.payload["reason"] == "NO_TOKEN"

    @pytest.mark.asyncio
    async def test_shell_metacharacters_escalate(self, evaluator):
        env = _make_envelope("WRITE", {"path": "/tmp/workspace/$(whoami).txt"})
        result = await evaluator.process(env)
        assert result is not None
        flags = result.payload.get("escalation_flags", [])
        assert any("shell_metacharacters" in f for f in flags)

    @pytest.mark.asyncio
    async def test_malformed_json_rejected(self, evaluator):
        env = MessageEnvelope(
            session_id="sess-001",
            request_id="req-001",
            sender="task-agent:1.0.0",
            recipient="request-evaluator",
            payload={"bad": "data"},
        )
        result = await evaluator.process(env)
        assert result is not None
        assert result.payload["decision"] == "REJECT"
