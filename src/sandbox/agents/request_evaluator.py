from __future__ import annotations

import structlog

from sandbox.agents.base import BaseAgent
from sandbox.models.enums import ActionType, RiskTier
from sandbox.models.messages import ActionRequest, EnrichedRequest, MessageEnvelope

logger = structlog.get_logger()

IRREVERSIBLE_PATTERNS = {"rm ", "drop ", "delete ", "format ", "mkfs", "truncate ", "destroy"}
SHELL_METACHARACTERS = {"|", ";", "&&", "||", "$(", "`", ">>", "<<"}


class RequestEvaluatorAgent(BaseAgent):
    """A02 — Zone 2. Schema validation + intent classification.

    Stateless. Every decision independently replayable from inputs alone.
    No LLM calls — rule-based classification only.
    """

    agent_name = "request-evaluator"
    agent_version = "1.0.0"
    zone = 2
    pipeline_step = 2

    def __init__(self) -> None:
        super().__init__()
        self._session_action_history: dict[str, set[str]] = {}
        self._session_request_counts: dict[str, int] = {}

    async def process(self, envelope: MessageEnvelope) -> MessageEnvelope | None:
        payload = envelope.payload
        session_id = envelope.session_id
        request_id = envelope.request_id

        # Step 1: Schema validation
        if not self._validate_schema(payload):
            logger.warning("schema_invalid", request_id=request_id)
            return self.create_envelope(
                session_id=session_id,
                request_id=request_id,
                recipient="task-agent",
                payload={"request_id": request_id, "decision": "REJECT", "reason": "SCHEMA_INVALID"},
            )

        try:
            request = ActionRequest(**payload)
        except Exception:
            return self.create_envelope(
                session_id=session_id,
                request_id=request_id,
                recipient="task-agent",
                payload={"request_id": request_id, "decision": "REJECT", "reason": "SCHEMA_INVALID"},
            )

        if not request.session_token:
            logger.warning("no_token", request_id=request_id)
            return self.create_envelope(
                session_id=session_id,
                request_id=request_id,
                recipient="task-agent",
                payload={"request_id": request_id, "decision": "REJECT", "reason": "NO_TOKEN"},
            )

        # Step 2: Intent classification
        intent_class = request.action_type
        risk_tier = self._classify_risk_tier(request, session_id)
        escalation_flags = self._check_escalation(request, session_id)

        if escalation_flags:
            for flag in escalation_flags:
                if "upgrade" in flag:
                    risk_tier = risk_tier.upgrade()

        # Track session history
        history = self._session_action_history.setdefault(session_id, set())
        history.add(request.action_type.value)
        self._session_request_counts[session_id] = (
            self._session_request_counts.get(session_id, 0) + 1
        )

        enriched = EnrichedRequest(
            action_type=request.action_type,
            parameters=request.parameters,
            session_token=request.session_token,
            request_id=request_id,
            intent_class=intent_class,
            risk_tier=risk_tier,
            schema_valid=True,
            escalation_flags=escalation_flags,
        )

        logger.info(
            "request_classified",
            request_id=request_id,
            intent=intent_class.value,
            risk_tier=risk_tier.value,
            flags=escalation_flags,
        )

        return self.create_envelope(
            session_id=session_id,
            request_id=request_id,
            recipient="policy-engine",
            payload=enriched.model_dump(),
        )

    def _validate_schema(self, payload: dict) -> bool:
        required = {"action_type", "session_token", "request_id"}
        return required.issubset(payload.keys())

    def _classify_risk_tier(self, request: ActionRequest, session_id: str) -> RiskTier:
        action = request.action_type
        if action == ActionType.READ:
            tier = RiskTier.LOW
        elif action == ActionType.WRITE:
            tier = RiskTier.MEDIUM
        elif action in (ActionType.EXECUTE, ActionType.NETWORK):
            tier = RiskTier.HIGH
        elif action == ActionType.SECRET_ACCESS:
            tier = RiskTier.CRITICAL
        else:
            tier = RiskTier.CRITICAL

        params_str = str(request.parameters).lower()
        if any(p in params_str for p in IRREVERSIBLE_PATTERNS):
            tier = RiskTier.CRITICAL

        return tier

    def _check_escalation(self, request: ActionRequest, session_id: str) -> list[str]:
        flags = []
        history = self._session_action_history.get(session_id, set())

        if request.action_type.value not in history:
            flags.append(f"new_action_type_upgrade:{request.action_type.value}")

        count = self._session_request_counts.get(session_id, 0)
        if count > 10:
            flags.append("high_request_rate")

        params_str = str(request.parameters)
        if any(mc in params_str for mc in SHELL_METACHARACTERS):
            flags.append("shell_metacharacters_upgrade")

        import base64
        for val in request.parameters.values():
            if isinstance(val, str) and len(val) > 50:
                try:
                    base64.b64decode(val, validate=True)
                    flags.append("base64_blob_detected")
                    break
                except Exception:
                    pass

        return flags
