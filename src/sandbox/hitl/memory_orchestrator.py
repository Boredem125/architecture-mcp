"""In-memory HITL orchestrator — no Redis needed.

Replaces the auto-deny gap in PipelineOrchestrator._step_hitl() by
providing a real HITL agent that enqueues escalations for human review
and resolves them when a decision arrives via the API.
"""
from __future__ import annotations

import asyncio
import time
import uuid
from typing import Any

import structlog

from sandbox.models.enums import HITLDecision
from sandbox.models.messages import (
    HITLContextPackage,
    HITLResult,
    MessageEnvelope,
)

logger = structlog.get_logger(__name__)


class MemoryHITLOrchestrator:
    """In-memory HITL orchestrator with async waiter pattern.

    When a pipeline request hits the HITL step, this orchestrator:
    1. Parks the request in an in-memory queue.
    2. Broadcasts a "hitl_pending" event so the UI can show it.
    3. Blocks (with timeout) until a human submits a decision via
       submit_decision().

    The PipelineOrchestrator calls process(envelope) and expects back
    a MessageEnvelope with HITLResult payload.
    """

    def __init__(
        self,
        broadcaster: Any = None,
        default_timeout: float = 300.0,
    ) -> None:
        self._broadcaster = broadcaster
        self._default_timeout = default_timeout
        self._pending: dict[str, HITLContextPackage] = {}
        self._waiters: dict[str, asyncio.Event] = {}
        self._decisions: dict[str, HITLResult] = {}

    async def process(self, envelope: MessageEnvelope) -> MessageEnvelope | None:
        """Called by PipelineOrchestrator._step_hitl().

        Enqueues the request for human review and blocks until decided.
        """
        context = HITLContextPackage(**envelope.payload)
        request_id = context.request_id
        session_id = envelope.session_id

        self._pending[request_id] = context
        self._waiters[request_id] = asyncio.Event()

        if self._broadcaster:
            await self._broadcaster.broadcast({
                "event": "hitl_pending",
                "request_id": request_id,
                "session_id": session_id,
                "agent_id": context.agent_id,
                "action_type": context.action_type,
                "risk_tier": context.risk_tier,
                "escalation_reason": context.escalation_reason,
            })

        logger.info(
            "memory_hitl.enqueued",
            request_id=request_id,
            risk_tier=context.risk_tier,
        )

        try:
            await asyncio.wait_for(
                self._waiters[request_id].wait(),
                timeout=self._default_timeout,
            )
        except asyncio.TimeoutError:
            result = HITLResult(
                request_id=request_id,
                decision=HITLDecision.TIMEOUT,
                reason="Review window expired — auto-denied per timeout policy",
            )
            self._cleanup(request_id)
            return MessageEnvelope(
                session_id=session_id,
                request_id=request_id,
                sender="hitl-orchestrator",
                recipient="pipeline-orchestrator:1.0.0",
                payload=result.model_dump(),
            )

        result = self._decisions.pop(request_id, None)
        self._cleanup(request_id)

        if result is None:
            result = HITLResult(
                request_id=request_id,
                decision=HITLDecision.DENY,
                reason="Decision lost — fail closed",
            )

        return MessageEnvelope(
            session_id=session_id,
            request_id=request_id,
            sender="hitl-orchestrator",
            recipient="pipeline-orchestrator:1.0.0",
            payload=result.model_dump(),
        )

    async def submit_decision(
        self,
        request_id: str,
        decision: HITLDecision,
        reviewer_id: str,
        reason: str = "",
    ) -> HITLResult:
        """Called by the API when a human approves/denies."""
        if request_id not in self._pending:
            raise KeyError(f"Request {request_id} not pending")

        result = HITLResult(
            request_id=request_id,
            decision=decision,
            reviewer_id=reviewer_id,
            reason=reason,
            latency_ms=int(
                (time.time() - self._pending[request_id].created_at_epoch) * 1000
            ) if hasattr(self._pending[request_id], "created_at_epoch") else None,
        )
        self._decisions[request_id] = result

        event = self._waiters.get(request_id)
        if event:
            event.set()

        if self._broadcaster:
            await self._broadcaster.broadcast({
                "event": "hitl_decided",
                "request_id": request_id,
                "decision": decision,
                "reviewer_id": reviewer_id,
            })

        logger.info(
            "memory_hitl.decided",
            request_id=request_id,
            decision=decision,
            reviewer_id=reviewer_id,
        )
        return result

    def list_pending(self) -> list[dict[str, Any]]:
        """Return all pending requests as dicts for the API."""
        items = []
        for req_id, ctx in self._pending.items():
            items.append({
                "request_id": req_id,
                "session_id": ctx.session_id,
                "agent_id": ctx.agent_id,
                "action_type": ctx.action_type,
                "risk_tier": ctx.risk_tier,
                "escalation_reason": ctx.escalation_reason,
                "parameters": ctx.parameters,
            })
        return items

    @property
    def pending_count(self) -> int:
        return len(self._pending)

    def _cleanup(self, request_id: str) -> None:
        self._pending.pop(request_id, None)
        self._waiters.pop(request_id, None)
