from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

import structlog

from sandbox.agents.base import BaseAgent
from sandbox.config import HITLSettings
from sandbox.models.enums import HITLDecision, RiskTier
from sandbox.models.messages import HITLContextPackage, HITLResult, MessageEnvelope
from sandbox.hitl.queue import HITLQueue
from sandbox.hitl.reviewer import ReviewerRegistry

logger = structlog.get_logger()


class HITLOrchestratorAgent(BaseAgent):
    """A05 — Zone 2. Human-in-the-loop gate.

    Routes CRITICAL-tier requests to human reviewers. Enforces timeout-equals-deny.
    Stateful — maintains pending request queue in durable storage.
    """

    agent_name = "hitl-orchestrator"
    agent_version = "1.0.0"
    zone = 2
    pipeline_step = 5

    def __init__(
        self,
        queue: HITLQueue | None = None,
        reviewer_registry: ReviewerRegistry | None = None,
        settings: HITLSettings | None = None,
    ) -> None:
        super().__init__()
        self._queue = queue
        self._registry = reviewer_registry or ReviewerRegistry()
        self._settings = settings or HITLSettings()
        self._pending_decisions: dict[str, HITLResult] = {}

    async def process(self, envelope: MessageEnvelope) -> MessageEnvelope | None:
        payload = envelope.payload
        request_id = envelope.request_id
        session_id = envelope.session_id

        if payload.get("hitl_action") == "submit_decision":
            return await self._handle_decision(envelope)

        try:
            context = HITLContextPackage(**payload)
        except Exception as e:
            logger.error("hitl_context_invalid", request_id=request_id, error=str(e))
            return self._deny_envelope(session_id, request_id, "Invalid escalation context")

        timeout_seconds = self._get_timeout(context.risk_tier, context.parameters)
        timeout_at = datetime.now(timezone.utc) + timedelta(seconds=timeout_seconds)
        context.timeout_at_utc = timeout_at.isoformat()
        context.reviewer_guidance = self._generate_guidance(context)

        if self._queue is not None:
            await self._queue.enqueue(context)

        if not self._registry.is_available():
            logger.warning("no_reviewers_available", request_id=request_id)

        logger.info(
            "hitl_escalated",
            request_id=request_id,
            risk_tier=context.risk_tier.value,
            timeout_seconds=timeout_seconds,
        )

        if self._queue is None:
            return self._deny_envelope(
                session_id, request_id, "HITL queue not configured — auto-deny"
            )

        start = time.monotonic()
        while True:
            elapsed = time.monotonic() - start
            if elapsed >= timeout_seconds:
                logger.info("hitl_timeout", request_id=request_id)
                result = HITLResult(
                    request_id=request_id,
                    decision=HITLDecision.TIMEOUT,
                    reason="Review timed out — auto-deny",
                    latency_ms=int(elapsed * 1000),
                )
                return self.create_envelope(
                    session_id=session_id,
                    request_id=request_id,
                    recipient="task-agent",
                    payload=result.model_dump(),
                )

            if request_id in self._pending_decisions:
                result = self._pending_decisions.pop(request_id)
                result.latency_ms = int(elapsed * 1000)
                logger.info(
                    "hitl_decision_received",
                    request_id=request_id,
                    decision=result.decision.value,
                    reviewer=result.reviewer_id,
                    latency_ms=result.latency_ms,
                )

                recipient = (
                    "content-safety"
                    if result.decision == HITLDecision.APPROVE
                    else "task-agent"
                )
                return self.create_envelope(
                    session_id=session_id,
                    request_id=request_id,
                    recipient=recipient,
                    payload=result.model_dump(),
                )

            import asyncio
            await asyncio.sleep(0.5)

    async def _handle_decision(self, envelope: MessageEnvelope) -> MessageEnvelope | None:
        payload = envelope.payload
        request_id = payload.get("request_id", envelope.request_id)
        decision = HITLDecision(payload["decision"])
        reviewer_id = payload.get("reviewer_id", "")
        reason = payload.get("reason", "")

        if decision == HITLDecision.APPROVE and not reason:
            logger.warning("approve_without_reason", request_id=request_id)
            return None

        result = HITLResult(
            request_id=request_id,
            decision=decision,
            reviewer_id=reviewer_id,
            reason=reason,
        )
        self._pending_decisions[request_id] = result
        return None

    def _get_timeout(self, risk_tier: RiskTier, parameters: dict) -> int:
        is_irreversible = parameters.get("irreversible", False)
        if risk_tier == RiskTier.CRITICAL and is_irreversible:
            return self._settings.critical_irreversible_timeout_seconds
        if risk_tier == RiskTier.CRITICAL:
            return self._settings.critical_timeout_seconds
        return self._settings.high_timeout_seconds

    def _generate_guidance(self, context: HITLContextPackage) -> str:
        parts = [f"Action: {context.action_type.value} (risk: {context.risk_tier.value})"]
        parts.append(f"Escalation reason: {context.escalation_reason}")
        if context.anomaly_flags:
            parts.append(f"Anomaly flags: {', '.join(context.anomaly_flags)}")
        params = context.parameters
        if params.get("command"):
            parts.append(f"Command: {params['command']}")
        if params.get("path"):
            parts.append(f"Target: {params['path']}")
        if params.get("irreversible"):
            parts.append("WARNING: This action is irreversible.")
        return " | ".join(parts)

    def _deny_envelope(
        self, session_id: str, request_id: str, reason: str
    ) -> MessageEnvelope:
        result = HITLResult(
            request_id=request_id,
            decision=HITLDecision.DENY,
            reason=reason,
        )
        return self.create_envelope(
            session_id=session_id,
            request_id=request_id,
            recipient="task-agent",
            payload=result.model_dump(),
        )
