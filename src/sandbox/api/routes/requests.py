from __future__ import annotations

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from sandbox.models.enums import ActionType
from sandbox.models.messages import ActionRequest

router = APIRouter(prefix="/api/v1/requests", tags=["requests"])


class SubmitRequest(BaseModel):
    session_id: str
    session_token: str
    action_type: ActionType
    parameters: dict = {}


def _get_session_manager():
    from sandbox.api.app import get_session_manager
    return get_session_manager()


@router.post("/")
async def submit_action_request(body: SubmitRequest) -> dict:
    sm = _get_session_manager()

    valid, reason = sm.validate_session(body.session_id)
    if not valid:
        raise HTTPException(status_code=403, detail=reason)

    token_valid, token_reason = sm.validate_token(body.session_id, body.session_token)
    if not token_valid:
        raise HTTPException(status_code=401, detail=token_reason)

    session = sm.get_session(body.session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found")

    action_request = ActionRequest(
        action_type=body.action_type,
        parameters=body.parameters,
        session_token=body.session_token,
    )

    from sandbox.api.websocket import broadcaster
    from sandbox.pipeline.orchestrator import PipelineOrchestrator
    orchestrator = PipelineOrchestrator(session_manager=sm, event_broadcaster=broadcaster)
    status = await orchestrator.process_request(action_request, session)

    return status.model_dump()
