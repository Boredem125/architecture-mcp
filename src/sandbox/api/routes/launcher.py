"""API routes for the jailed CLI launcher and privilege broker.

Launcher:
  POST   /api/v1/launch         — start a jailed CLI app
  POST   /api/v1/launch/{id}/stop — stop a running app
  GET    /api/v1/launch/{id}    — get run status
  GET    /api/v1/launch         — list all runs

Broker:
  POST   /api/v1/broker/request — submit a privileged command (called by shims)
  GET    /api/v1/broker/pending — list pending broker requests
  POST   /api/v1/broker/{id}/approve — approve a request
  POST   /api/v1/broker/{id}/deny   — deny a request

HITL (in-memory):
  GET    /api/v1/hitl-mem/pending    — list pending HITL escalations
  POST   /api/v1/hitl-mem/{id}/approve — approve
  POST   /api/v1/hitl-mem/{id}/deny    — deny
"""
from __future__ import annotations

from typing import Any

import structlog
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

logger = structlog.get_logger(__name__)

router = APIRouter(tags=["launcher"])


# ------------------------------------------------------------------
# Lazy singletons (wired at import time via app.py)
# ------------------------------------------------------------------

def _get_launcher():
    from sandbox.api.app import get_launcher
    return get_launcher()


def _get_broker():
    from sandbox.api.app import get_broker
    return get_broker()


def _get_hitl_orchestrator():
    from sandbox.api.app import get_memory_hitl
    return get_memory_hitl()


def _get_translator():
    from sandbox.api.app import get_translator
    return get_translator()


# ------------------------------------------------------------------
# Request/Response models
# ------------------------------------------------------------------

class LaunchRequest(BaseModel):
    app_type: str
    session_id: str = ""
    agent_id: str = ""
    extra_args: list[str] = []
    env_overrides: dict[str, str] = {}
    task_description: str = ""


class StopRequest(BaseModel):
    pass


class BrokerSubmitRequest(BaseModel):
    session_id: str
    run_id: str
    command: str
    jail_dir: str
    agent_id: str = ""


class BrokerDecisionRequest(BaseModel):
    reviewer_id: str
    reason: str = ""


class HITLDecisionRequest(BaseModel):
    reviewer_id: str
    reason: str = ""


# ------------------------------------------------------------------
# Launcher routes
# ------------------------------------------------------------------

@router.post("/api/v1/launch")
async def launch_app(req: LaunchRequest) -> dict:
    launcher = _get_launcher()
    import uuid
    session_id = req.session_id or uuid.uuid4().hex[:16]
    agent_id = req.agent_id or f"{req.app_type}-{session_id[:8]}"

    try:
        run = await launcher.launch(
            app_type=req.app_type,
            session_id=session_id,
            agent_id=agent_id,
            extra_args=req.extra_args,
            env_overrides=req.env_overrides,
            task_description=req.task_description,
        )
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    return run.to_dict()


@router.get("/api/v1/launch")
async def list_runs() -> dict:
    launcher = _get_launcher()
    runs = launcher.list_runs()
    return {
        "count": len(runs),
        "runs": [r.to_dict() for r in runs],
    }


@router.get("/api/v1/launch/apps")
async def list_apps() -> dict:
    launcher = _get_launcher()
    all_apps = launcher.registry.list_all()
    available = launcher.registry.list_available()
    available_types = {a.app_type for a in available}
    return {
        "apps": [
            {
                "app_type": a.app_type,
                "display_name": a.display_name,
                "executable": a.executable,
                "available": a.app_type in available_types,
                "needs_api_key": a.needs_api_key,
            }
            for a in all_apps
        ],
    }


@router.get("/api/v1/launch/{run_id}")
async def get_run(run_id: str) -> dict:
    launcher = _get_launcher()
    run = launcher.get_run(run_id)
    if run is None:
        raise HTTPException(status_code=404, detail=f"Run {run_id} not found")
    return run.to_dict()


@router.post("/api/v1/launch/{run_id}/stop")
async def stop_app(run_id: str) -> dict:
    launcher = _get_launcher()
    try:
        run = await launcher.stop(run_id)
    except KeyError:
        raise HTTPException(status_code=404, detail=f"Run {run_id} not found")
    return run.to_dict()


# ------------------------------------------------------------------
# Broker routes
# ------------------------------------------------------------------

@router.post("/api/v1/broker/request")
async def broker_request(req: BrokerSubmitRequest) -> dict:
    broker = _get_broker()
    br = await broker.submit_request(
        session_id=req.session_id,
        run_id=req.run_id,
        agent_id=req.agent_id,
        command=req.command,
        jail_dir=req.jail_dir,
    )
    return br.to_dict()


@router.get("/api/v1/broker/pending")
async def broker_pending() -> dict:
    broker = _get_broker()
    pending = broker.list_pending()
    return {
        "count": len(pending),
        "requests": [r.to_dict() for r in pending],
    }


@router.post("/api/v1/broker/{request_id}/approve")
async def broker_approve(request_id: str, req: BrokerDecisionRequest) -> dict:
    broker = _get_broker()
    try:
        br = await broker.approve(request_id, req.reviewer_id, req.reason)
    except KeyError:
        raise HTTPException(status_code=404, detail=f"Request {request_id} not found")
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return br.to_dict()


@router.post("/api/v1/broker/{request_id}/deny")
async def broker_deny(request_id: str, req: BrokerDecisionRequest) -> dict:
    broker = _get_broker()
    try:
        br = await broker.deny(request_id, req.reviewer_id, req.reason)
    except KeyError:
        raise HTTPException(status_code=404, detail=f"Request {request_id} not found")
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return br.to_dict()


# ------------------------------------------------------------------
# In-memory HITL routes (for pipeline escalations)
# ------------------------------------------------------------------

@router.get("/api/v1/hitl-mem/pending")
async def hitl_mem_pending() -> dict:
    hitl = _get_hitl_orchestrator()
    pending = hitl.list_pending()
    return {
        "count": len(pending),
        "requests": pending,
    }


@router.post("/api/v1/hitl-mem/{request_id}/approve")
async def hitl_mem_approve(
    request_id: str, req: HITLDecisionRequest
) -> dict:
    from sandbox.models.enums import HITLDecision
    hitl = _get_hitl_orchestrator()
    try:
        result = await hitl.submit_decision(
            request_id=request_id,
            decision=HITLDecision.APPROVE,
            reviewer_id=req.reviewer_id,
            reason=req.reason,
        )
    except KeyError:
        raise HTTPException(status_code=404, detail=f"Request {request_id} not found")
    return result.model_dump()


@router.post("/api/v1/hitl-mem/{request_id}/deny")
async def hitl_mem_deny(
    request_id: str, req: HITLDecisionRequest
) -> dict:
    from sandbox.models.enums import HITLDecision
    hitl = _get_hitl_orchestrator()
    try:
        result = await hitl.submit_decision(
            request_id=request_id,
            decision=HITLDecision.DENY,
            reviewer_id=req.reviewer_id,
            reason=req.reason,
        )
    except KeyError:
        raise HTTPException(status_code=404, detail=f"Request {request_id} not found")
    return result.model_dump()


# ------------------------------------------------------------------
# Translation route
# ------------------------------------------------------------------

@router.post("/api/v1/translate")
async def translate_event(event: dict) -> dict:
    translator = _get_translator()
    text = await translator.translate(event)
    return {"translation": text}
