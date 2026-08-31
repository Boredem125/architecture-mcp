from __future__ import annotations

from typing import Any

import structlog

from sandbox.agents.base import BaseAgent
from sandbox.models.enums import ActionType
from sandbox.models.messages import ActionRequest, MessageEnvelope, ScrubbedOutput

logger = structlog.get_logger()


class TaskAgent(BaseAgent):
    """A01 — Zone 1 agent. Issues action requests on behalf of the user.

    Zero trust. Assumed fully compromised at all times. Communicates only
    with the Zone 2 request queue — never directly with any named Zone 2 agent.
    """

    agent_name = "task-agent"
    agent_version = "1.0.0"
    zone = 1
    pipeline_step = None

    def __init__(self, session_token: str = "") -> None:
        super().__init__()
        self._session_token = session_token
        self._pending_requests: dict[str, Any] = {}
        self._results: dict[str, ScrubbedOutput] = {}

    def set_session_token(self, token: str) -> None:
        self._session_token = token

    def create_action_request(
        self,
        action_type: ActionType,
        parameters: dict[str, Any] | None = None,
    ) -> ActionRequest:
        return ActionRequest(
            action_type=action_type,
            parameters=parameters or {},
            session_token=self._session_token,
        )

    async def process(self, envelope: MessageEnvelope) -> MessageEnvelope | None:
        """Process results returning from the sandbox pipeline."""
        payload = envelope.payload
        request_id = envelope.request_id

        if payload.get("scrubbed"):
            result = ScrubbedOutput(**payload)
            self._results[request_id] = result
            logger.info(
                "result_received",
                request_id=request_id,
                result=result.result.value,
                redactions=result.redaction_count,
            )
            return None

        status = payload.get("status", "")
        if status in ("DENIED", "HALTED"):
            logger.warning(
                "request_denied",
                request_id=request_id,
                reason=payload.get("reason", ""),
            )
            return None

        if status == "PENDING_REVIEW":
            logger.info("request_pending_hitl", request_id=request_id)
            self._pending_requests[request_id] = payload
            return None

        logger.debug("task_agent_received", request_id=request_id, payload_keys=list(payload.keys()))
        return None

    async def submit_request(self, request: ActionRequest, session_id: str) -> MessageEnvelope:
        """Package an action request into a message envelope for the pipeline."""
        envelope = self.create_envelope(
            session_id=session_id,
            request_id=request.request_id,
            recipient="request-evaluator",
            payload=request.model_dump(),
        )
        self._pending_requests[request.request_id] = request
        logger.info(
            "request_submitted",
            request_id=request.request_id,
            action_type=request.action_type.value,
        )
        return envelope

    def get_result(self, request_id: str) -> ScrubbedOutput | None:
        return self._results.get(request_id)

    def get_pending(self) -> dict[str, Any]:
        return dict(self._pending_requests)
