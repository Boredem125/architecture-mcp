from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

import structlog

from sandbox.config import SessionSettings
from sandbox.crypto.tokens import TokenIssuer
from sandbox.models.enums import ActionType, SessionEndReason
from sandbox.models.session import (
    CapabilityToken,
    SessionEndRequest,
    SessionStartRequest,
    SessionState,
    SessionSummary,
)

logger = structlog.get_logger()


class SessionManager:
    """Manages session lifecycle: creation, validation, termination, registry."""

    def __init__(
        self,
        token_issuer: TokenIssuer,
        settings: SessionSettings | None = None,
    ) -> None:
        self._token_issuer = token_issuer
        self._settings = settings or SessionSettings()
        self._sessions: dict[str, SessionState] = {}

    def create_session(self, request: SessionStartRequest) -> SessionState:
        session_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc)
        ttl = min(request.ttl_seconds, self._settings.max_ttl_seconds)
        expires_at = now + timedelta(seconds=ttl)

        token_str = self._token_issuer.issue_token(
            agent_id=request.agent_id,
            session_id=session_id,
            allowed_actions=[a.value for a in request.allowed_actions],
            workspace_root=request.workspace_root,
            expires_in_seconds=ttl,
            allowed_network_hosts=request.allowed_network_hosts,
            allowed_secrets=request.allowed_secrets,
            max_writes=request.max_writes,
            max_requests=self._settings.max_requests_per_minute * (ttl // 60),
        )

        cap_token = CapabilityToken(
            agent_id=request.agent_id,
            session_id=session_id,
            allowed_actions=request.allowed_actions,
            workspace_root=request.workspace_root,
            allowed_network_hosts=request.allowed_network_hosts,
            allowed_secrets=request.allowed_secrets,
            max_writes=request.max_writes,
            max_requests=self._settings.max_requests_per_minute * (ttl // 60),
            expires_at_utc=expires_at.isoformat(),
            issued_by="sandbox-session-manager",
            token_fingerprint=token_str[:16],
            signature=token_str,
        )

        session = SessionState(
            session_id=session_id,
            agent_id=request.agent_id,
            capability_token=cap_token,
            declared_task=request.declared_task,
            started_at=now,
            expires_at=expires_at,
        )

        self._sessions[session_id] = session
        logger.info(
            "session_created",
            session_id=session_id,
            agent_id=request.agent_id,
            ttl_seconds=ttl,
            allowed_actions=[a.value for a in request.allowed_actions],
        )
        return session

    def get_session(self, session_id: str) -> SessionState | None:
        return self._sessions.get(session_id)

    def validate_session(self, session_id: str) -> tuple[bool, str]:
        session = self._sessions.get(session_id)
        if session is None:
            return False, "SESSION_NOT_FOUND"
        if not session.is_active:
            return False, "SESSION_INACTIVE"
        if session.is_killed:
            return False, "SESSION_KILLED"
        now = datetime.now(timezone.utc)
        if session.expires_at and now >= session.expires_at:
            self.end_session(
                SessionEndRequest(session_id=session_id, reason=SessionEndReason.TTL_EXPIRED)
            )
            return False, "SESSION_EXPIRED"
        return True, "OK"

    def validate_token(self, session_id: str, token: str) -> tuple[bool, str]:
        session = self._sessions.get(session_id)
        if session is None:
            return False, "SESSION_NOT_FOUND"
        if session.capability_token.signature != token:
            return False, "TOKEN_MISMATCH"
        try:
            self._token_issuer.validate_token(token)
        except Exception as e:
            return False, f"TOKEN_INVALID: {e}"
        return True, "OK"

    def end_session(self, request: SessionEndRequest) -> SessionSummary | None:
        session = self._sessions.get(request.session_id)
        if session is None:
            return None

        session.is_active = False
        session.ended_at = datetime.now(timezone.utc)
        session.end_reason = request.reason

        self._token_issuer.revoke_token(session.capability_token.signature)

        duration_ms = int(
            (session.ended_at - session.started_at).total_seconds() * 1000
        )

        summary = SessionSummary(
            session_id=session.session_id,
            agent_id=session.agent_id,
            total_requests=session.total_requests,
            total_denies=session.deny_count,
            total_hitl=session.hitl_count,
            session_duration_ms=duration_ms,
            end_reason=request.reason,
        )

        logger.info(
            "session_ended",
            session_id=request.session_id,
            reason=request.reason.value,
            total_requests=session.total_requests,
            duration_ms=duration_ms,
        )
        return summary

    def kill_session(self, session_id: str, reason: str = "kill_switch") -> SessionSummary | None:
        session = self._sessions.get(session_id)
        if session is None:
            return None
        session.is_killed = True
        return self.end_session(
            SessionEndRequest(session_id=session_id, reason=SessionEndReason.KILL_SWITCH)
        )

    def get_active_sessions(self) -> list[SessionState]:
        return [s for s in self._sessions.values() if s.is_active]

    def get_session_context(self, session_id: str) -> dict[str, Any] | None:
        """Build OPA-compatible session context dict."""
        session = self._sessions.get(session_id)
        if session is None:
            return None
        return {
            "session_id": session.session_id,
            "agent_id": session.agent_id,
            "allowed_actions": [a.value for a in session.capability_token.allowed_actions],
            "workspace_root": session.capability_token.workspace_root,
            "allowed_network_hosts": session.capability_token.allowed_network_hosts,
            "allowed_secrets": session.capability_token.allowed_secrets,
            "max_writes": session.capability_token.max_writes,
            "max_requests": session.capability_token.max_requests,
            "write_count": session.write_count,
            "total_requests": session.total_requests,
            "expires_at_ns": int(
                session.expires_at.timestamp() * 1e9
            ) if session.expires_at else 0,
        }
