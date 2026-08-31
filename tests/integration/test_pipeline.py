from __future__ import annotations

import pytest

from sandbox.config import SessionSettings
from sandbox.crypto.tokens import TokenIssuer
from sandbox.models.enums import ActionType
from sandbox.models.messages import ActionRequest
from sandbox.models.session import SessionStartRequest
from sandbox.pipeline.orchestrator import PipelineOrchestrator
from sandbox.pipeline.session_manager import SessionManager


@pytest.fixture
def session_manager():
    issuer = TokenIssuer(secret="test-secret-key-for-integration-tests")
    return SessionManager(issuer, SessionSettings())


@pytest.fixture
def pipeline(session_manager):
    return PipelineOrchestrator(session_manager=session_manager)


@pytest.fixture
def active_session(session_manager):
    req = SessionStartRequest(
        agent_id="test-agent",
        declared_task="integration testing",
        allowed_actions=[ActionType.READ, ActionType.WRITE],
        workspace_root="/tmp/workspace",
        max_writes=50,
        ttl_seconds=1800,
    )
    return session_manager.create_session(req)


class TestPipelineEndToEnd:
    @pytest.mark.asyncio
    async def test_allowed_read_completes(self, pipeline, active_session):
        request = ActionRequest(
            action_type=ActionType.READ,
            parameters={"path": "/tmp/workspace/file.txt"},
            session_token=active_session.capability_token.signature,
        )
        status = await pipeline.process_request(request, active_session)
        assert status.status == "COMPLETED"
        assert status.decision == "ALLOW"

    @pytest.mark.asyncio
    async def test_disallowed_execute_denied(self, pipeline, active_session):
        request = ActionRequest(
            action_type=ActionType.EXECUTE,
            parameters={"command": "ls -la"},
            session_token=active_session.capability_token.signature,
        )
        status = await pipeline.process_request(request, active_session)
        assert status.status == "DENIED"

    @pytest.mark.asyncio
    async def test_invalid_token_halted(self, pipeline, active_session):
        request = ActionRequest(
            action_type=ActionType.READ,
            parameters={"path": "/tmp/workspace/file.txt"},
            session_token="invalid-token-12345",
        )
        status = await pipeline.process_request(request, active_session)
        assert status.status == "HALTED"

    @pytest.mark.asyncio
    async def test_session_tracks_requests(self, pipeline, active_session):
        assert active_session.total_requests == 0
        request = ActionRequest(
            action_type=ActionType.READ,
            parameters={"path": "/tmp/workspace/file.txt"},
            session_token=active_session.capability_token.signature,
        )
        await pipeline.process_request(request, active_session)
        assert active_session.total_requests == 1

    @pytest.mark.asyncio
    async def test_write_budget_enforcement(self, pipeline, session_manager):
        req = SessionStartRequest(
            agent_id="test-agent",
            declared_task="write test",
            allowed_actions=[ActionType.WRITE],
            max_writes=1,
            ttl_seconds=300,
        )
        session = session_manager.create_session(req)

        write_req = ActionRequest(
            action_type=ActionType.WRITE,
            parameters={"path": "/tmp/workspace/out.txt"},
            session_token=session.capability_token.signature,
        )

        status1 = await pipeline.process_request(write_req, session)
        assert status1.status == "COMPLETED"

        status2 = await pipeline.process_request(write_req, session)
        assert status2.status == "DENIED"


class TestSessionLifecycle:
    def test_create_and_end(self, session_manager):
        req = SessionStartRequest(
            agent_id="lifecycle-agent",
            declared_task="test lifecycle",
            allowed_actions=[ActionType.READ],
        )
        session = session_manager.create_session(req)
        assert session.is_active

        from sandbox.models.session import SessionEndRequest
        from sandbox.models.enums import SessionEndReason

        summary = session_manager.end_session(
            SessionEndRequest(session_id=session.session_id, reason=SessionEndReason.DONE)
        )
        assert summary is not None
        assert summary.end_reason == SessionEndReason.DONE
        assert not session.is_active

    def test_kill_session(self, session_manager):
        req = SessionStartRequest(
            agent_id="kill-agent",
            declared_task="test kill",
            allowed_actions=[ActionType.READ],
        )
        session = session_manager.create_session(req)
        summary = session_manager.kill_session(session.session_id, "anomaly")
        assert summary is not None
        assert session.is_killed
        assert not session.is_active

    def test_validate_ended_session(self, session_manager):
        req = SessionStartRequest(
            agent_id="validate-agent",
            declared_task="test",
            allowed_actions=[ActionType.READ],
        )
        session = session_manager.create_session(req)
        from sandbox.models.session import SessionEndRequest
        from sandbox.models.enums import SessionEndReason

        session_manager.end_session(
            SessionEndRequest(session_id=session.session_id, reason=SessionEndReason.DONE)
        )
        valid, reason = session_manager.validate_session(session.session_id)
        assert not valid
        assert reason == "SESSION_INACTIVE"
