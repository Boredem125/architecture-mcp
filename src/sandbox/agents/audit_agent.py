from __future__ import annotations

import structlog

from sandbox.agents.base import BaseAgent
from sandbox.audit.sink import AuditSink
from sandbox.config import AuditSettings
from sandbox.models.audit import AuditRecord, SessionSealRecord
from sandbox.models.enums import SessionEndReason
from sandbox.models.messages import MessageEnvelope

logger = structlog.get_logger()


class AuditAgentImpl(BaseAgent):
    """A07 — Zone 2. Append-only audit log writer.

    Writes and seals the audit log for every inter-zone event. Monitors log
    health. A log write failure is a P0 incident that triggers session termination.
    Stateful — log index, write buffer, chain hash state.
    """

    agent_name = "audit-agent"
    agent_version = "1.0.0"
    zone = 2
    pipeline_step = 8

    def __init__(self, settings: AuditSettings | None = None) -> None:
        super().__init__()
        self._settings = settings or AuditSettings()
        self._sink = AuditSink(
            log_dir=self._settings.log_dir,
            worm_endpoint=self._settings.worm_endpoint,
        )
        self._write_failures = 0

    async def process(self, envelope: MessageEnvelope) -> MessageEnvelope | None:
        payload = envelope.payload
        request_id = envelope.request_id
        session_id = envelope.session_id

        event_type = payload.get("event_type")

        if event_type == "seal_session":
            return await self._seal_session(envelope)

        if event_type == "health_check":
            health = await self._sink.health_check()
            return self.create_envelope(
                session_id=session_id,
                request_id=request_id,
                recipient=envelope.sender,
                payload=health,
            )

        if event_type == "verify_chain":
            is_valid = await self._sink.verify_chain(session_id)
            return self.create_envelope(
                session_id=session_id,
                request_id=request_id,
                recipient=envelope.sender,
                payload={"chain_valid": is_valid},
            )

        try:
            record = AuditRecord(**payload)
        except Exception as e:
            logger.error("audit_record_invalid", request_id=request_id, error=str(e))
            record = AuditRecord(
                session_id=session_id,
                agent_id=payload.get("agent_id", "unknown"),
                action_type=payload.get("action_type", "READ"),
                risk_tier=payload.get("risk_tier", "LOW"),
                incomplete=True,
            )

        success = await self._sink.write(record)

        if not success:
            self._write_failures += 1
            logger.critical(
                "audit_write_failed",
                request_id=request_id,
                session_id=session_id,
                consecutive_failures=self._write_failures,
            )
            return self.create_envelope(
                session_id=session_id,
                request_id=request_id,
                recipient="session-manager",
                payload={
                    "kill_switch": True,
                    "reason": "AUDIT_WRITE_FAILURE",
                    "session_id": session_id,
                },
            )

        self._write_failures = 0
        logger.debug("audit_record_written", request_id=request_id, record_id=record.record_id)

        return self.create_envelope(
            session_id=session_id,
            request_id=request_id,
            recipient=envelope.sender,
            payload={"audit_written": True, "record_id": record.record_id},
        )

    async def _seal_session(self, envelope: MessageEnvelope) -> MessageEnvelope | None:
        payload = envelope.payload
        session_id = envelope.session_id

        seal_record = SessionSealRecord(
            session_id=session_id,
            reason=payload.get("reason", "done"),
            total_requests=payload.get("total_requests", 0),
            total_denies=payload.get("total_denies", 0),
            total_hitl=payload.get("total_hitl", 0),
            session_duration_ms=payload.get("session_duration_ms", 0),
            summary_hash="",
        )

        await self._sink.seal_session(session_id, seal_record)

        logger.info("session_sealed", session_id=session_id)

        return self.create_envelope(
            session_id=session_id,
            request_id=envelope.request_id,
            recipient=envelope.sender,
            payload={"sealed": True, "session_id": session_id},
        )
