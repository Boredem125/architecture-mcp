from __future__ import annotations

import structlog

from sandbox.agents.base import BaseAgent
from sandbox.models.enums import PolicyDecision, RiskTier
from sandbox.models.messages import EnrichedRequest, MessageEnvelope, PolicyResult
from sandbox.policy.opa_client import OPAClient

logger = structlog.get_logger()


class PolicyEngineAgent(BaseAgent):
    """A03 — Zone 2. OPA deny-by-default authorization.

    Stateless. Policy logic lives in Rego files, not in this agent's code.
    """

    agent_name = "policy-engine"
    agent_version = "1.0.0"
    zone = 2
    pipeline_step = 3

    def __init__(self, opa_client: OPAClient | None = None) -> None:
        super().__init__()
        self._opa = opa_client
        self._policy_version = "1.0.0"

    async def process(self, envelope: MessageEnvelope) -> MessageEnvelope | None:
        payload = envelope.payload
        request_id = envelope.request_id
        session_id = envelope.session_id

        try:
            enriched = EnrichedRequest(**payload)
        except Exception as e:
            logger.error("policy_input_invalid", request_id=request_id, error=str(e))
            return self._decision_envelope(
                session_id, request_id, PolicyDecision.DENY, "POLICY_INPUT_INVALID"
            )

        session_context = payload.get("session_context")
        if session_context is None:
            session_context = self._build_session_context(enriched)

        if self._opa is not None:
            result = await self._evaluate_with_opa(enriched, session_context, request_id)
        else:
            result = self._evaluate_locally(enriched, session_context, request_id)

        audit_fragment = self.create_audit_fragment(
            request_id=request_id,
            session_id=session_id,
            data={
                "policy_decision": result.decision.value,
                "policy_version": result.policy_version,
                "matched_rule": result.matched_rule,
                "reason": result.reason,
            },
        )

        logger.info(
            "policy_evaluated",
            request_id=request_id,
            decision=result.decision.value,
            rule=result.matched_rule,
        )

        recipient = "content-safety" if result.decision == PolicyDecision.ALLOW else (
            "hitl-orchestrator" if result.decision == PolicyDecision.ESCALATE else "task-agent"
        )

        return self.create_envelope(
            session_id=session_id,
            request_id=request_id,
            recipient=recipient,
            payload=result.model_dump(),
        )

    async def _evaluate_with_opa(
        self,
        enriched: EnrichedRequest,
        session_context: dict,
        request_id: str,
    ) -> PolicyResult:
        assert self._opa is not None
        try:
            return await self._opa.evaluate_all(
                enriched.model_dump(),
                session_context,
            )
        except Exception as e:
            logger.error("opa_evaluation_error", request_id=request_id, error=str(e))
            return PolicyResult(
                request_id=request_id,
                decision=PolicyDecision.DENY,
                policy_version=self._policy_version,
                reason=f"POLICY_ERROR: {e}",
            )

    def _evaluate_locally(
        self,
        enriched: EnrichedRequest,
        session_context: dict,
        request_id: str,
    ) -> PolicyResult:
        """Fallback local policy evaluation when OPA is not available."""
        allowed_actions = session_context.get("allowed_actions", [])
        if enriched.intent_class.value not in allowed_actions:
            return PolicyResult(
                request_id=request_id,
                decision=PolicyDecision.DENY,
                policy_version=self._policy_version,
                matched_rule="session_scope",
                reason=f"{enriched.intent_class.value} not in session allowlist",
            )

        write_count = session_context.get("write_count", 0)
        max_writes = session_context.get("max_writes", 100)
        if write_count >= max_writes:
            return PolicyResult(
                request_id=request_id,
                decision=PolicyDecision.DENY,
                policy_version=self._policy_version,
                matched_rule="blast_radius",
                reason="Write budget exhausted",
            )

        total_requests = session_context.get("total_requests", 0)
        max_requests = session_context.get("max_requests", 1000)
        if total_requests >= max_requests:
            return PolicyResult(
                request_id=request_id,
                decision=PolicyDecision.DENY,
                policy_version=self._policy_version,
                matched_rule="blast_radius",
                reason="Request budget exhausted",
            )

        if enriched.risk_tier == RiskTier.CRITICAL:
            return PolicyResult(
                request_id=request_id,
                decision=PolicyDecision.ESCALATE,
                policy_version=self._policy_version,
                matched_rule="critical_escalation",
                reason="CRITICAL tier requires HITL review",
            )

        params = enriched.parameters
        if params.get("irreversible"):
            return PolicyResult(
                request_id=request_id,
                decision=PolicyDecision.ESCALATE,
                policy_version=self._policy_version,
                matched_rule="reversibility",
                reason="Irreversible action requires HITL review",
            )

        return PolicyResult(
            request_id=request_id,
            decision=PolicyDecision.ALLOW,
            policy_version=self._policy_version,
            matched_rule="default_allow",
        )

    def _build_session_context(self, enriched: EnrichedRequest) -> dict:
        return {
            "allowed_actions": [enriched.intent_class.value],
            "workspace_root": "/tmp/workspace",
            "write_count": 0,
            "max_writes": 100,
            "total_requests": 0,
            "max_requests": 1000,
        }

    def _decision_envelope(
        self,
        session_id: str,
        request_id: str,
        decision: PolicyDecision,
        reason: str,
    ) -> MessageEnvelope:
        result = PolicyResult(
            request_id=request_id,
            decision=decision,
            policy_version=self._policy_version,
            reason=reason,
        )
        return self.create_envelope(
            session_id=session_id,
            request_id=request_id,
            recipient="task-agent",
            payload=result.model_dump(),
        )
