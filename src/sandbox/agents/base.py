from __future__ import annotations

import abc
import time
import uuid
from typing import Any

import structlog

from sandbox.models.audit import AuditFragment
from sandbox.models.messages import MessageEnvelope

logger = structlog.get_logger()


class BaseAgent(abc.ABC):
    """Abstract base for all sandbox agents."""

    agent_name: str = "base-agent"
    agent_version: str = "1.0.0"
    zone: int = 2
    pipeline_step: int | None = None

    def __init__(self) -> None:
        self._started = False

    @property
    def identity(self) -> str:
        return f"{self.agent_name}:{self.agent_version}"

    async def start(self) -> None:
        self._started = True
        await self._on_start()
        logger.info("agent_started", agent=self.identity, zone=self.zone)

    async def stop(self) -> None:
        self._started = False
        await self._on_stop()
        logger.info("agent_stopped", agent=self.identity)

    async def _on_start(self) -> None:
        pass

    async def _on_stop(self) -> None:
        pass

    @abc.abstractmethod
    async def process(self, envelope: MessageEnvelope) -> MessageEnvelope | None:
        """Process an incoming message and return an outbound message or None."""
        ...

    def create_envelope(
        self,
        session_id: str,
        request_id: str,
        recipient: str,
        payload: dict[str, Any],
    ) -> MessageEnvelope:
        return MessageEnvelope(
            session_id=session_id,
            request_id=request_id,
            sender=self.identity,
            recipient=recipient,
            payload=payload,
        )

    def create_audit_fragment(
        self,
        request_id: str,
        session_id: str,
        data: dict[str, Any],
    ) -> AuditFragment:
        return AuditFragment(
            request_id=request_id,
            session_id=session_id,
            step_name=self.agent_name,
            step_number=self.pipeline_step or 0,
            agent_name=self.identity,
            data=data,
        )
