from __future__ import annotations

from fastapi import APIRouter, HTTPException

from sandbox.models.enums import ActionType, SessionEndReason
from sandbox.models.session import SessionEndRequest, SessionStartRequest

router = APIRouter(prefix="/api/v1/sessions", tags=["sessions"])


def _get_session_manager():
    from sandbox.api.app import get_session_manager
    return get_session_manager()


@router.post("/")
async def create_session(request: SessionStartRequest) -> dict:
    sm = _get_session_manager()
    session = sm.create_session(request)
    return {
        "session_id": session.session_id,
        "agent_id": session.agent_id,
        "expires_at": session.expires_at.isoformat() if session.expires_at else None,
        "capability_token": session.capability_token.signature,
        "allowed_actions": [a.value for a in session.capability_token.allowed_actions],
        "workspace_root": session.capability_token.workspace_root,
    }


@router.get("/{session_id}")
async def get_session(session_id: str) -> dict:
    sm = _get_session_manager()
    session = sm.get_session(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found")
    return {
        "session_id": session.session_id,
        "agent_id": session.agent_id,
        "is_active": session.is_active,
        "started_at": session.started_at.isoformat(),
        "expires_at": session.expires_at.isoformat() if session.expires_at else None,
        "total_requests": session.total_requests,
        "write_count": session.write_count,
        "execute_count": session.execute_count,
        "deny_count": session.deny_count,
        "hitl_count": session.hitl_count,
    }


@router.post("/{session_id}/end")
async def end_session(session_id: str, reason: str = "done") -> dict:
    sm = _get_session_manager()
    try:
        end_reason = SessionEndReason(reason)
    except ValueError:
        end_reason = SessionEndReason.DONE
    summary = sm.end_session(SessionEndRequest(session_id=session_id, reason=end_reason))
    if summary is None:
        raise HTTPException(status_code=404, detail="Session not found")
    return summary.model_dump()


@router.get("/")
async def list_sessions(active_only: bool = True) -> dict:
    sm = _get_session_manager()
    if active_only:
        sessions = sm.get_active_sessions()
    else:
        sessions = sm.get_active_sessions()
    return {
        "count": len(sessions),
        "sessions": [
            {
                "session_id": s.session_id,
                "agent_id": s.agent_id,
                "is_active": s.is_active,
                "total_requests": s.total_requests,
                "started_at": s.started_at.isoformat(),
            }
            for s in sessions
        ],
    }
