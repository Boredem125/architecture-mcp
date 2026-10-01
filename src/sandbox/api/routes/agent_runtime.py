"""API routes for the Agent Runtime — spawn, monitor, and kill real AI agents."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from sandbox.models.enums import ActionType

router = APIRouter(prefix="/api/v1/runtime", tags=["agent-runtime"])


class SpawnAgentRequest(BaseModel):
    agent_type: str  # claude-code, codex, hermes, antigravity, custom
    task: str
    # Typed and bounded: an unknown capability used to crash the route (HTTP 500).
    capabilities: list[ActionType] = [ActionType.READ]
    workspace_root: str = "/tmp/workspace"
    max_writes: int = Field(50, ge=0, le=100_000)
    ttl_seconds: int = Field(1800, ge=1, le=7 * 24 * 3600)
    api_key: str | None = None
    model: str | None = None
    metadata: dict[str, Any] | None = None


def _get_runtime():
    from sandbox.api.app import get_agent_runtime
    return get_agent_runtime()


@router.post("/spawn")
async def spawn_agent(req: SpawnAgentRequest) -> dict:
    """Spawn a real AI agent with sandboxed tool execution.

    The agent's every tool call goes through the 8-step mediation pipeline.
    Returns a run_id to track the agent's progress.
    """
    runtime = _get_runtime()
    run = await runtime.spawn_agent(
        agent_type=req.agent_type,
        task=req.task,
        capabilities=req.capabilities,
        workspace_root=req.workspace_root,
        max_writes=req.max_writes,
        ttl_seconds=req.ttl_seconds,
        api_key=req.api_key,
        model=req.model,
        metadata=req.metadata,
    )
    return run.to_dict()


@router.get("/runs")
async def list_runs() -> dict:
    runtime = _get_runtime()
    runs = runtime.list_runs()
    return {
        "count": len(runs),
        "runs": runs,
    }


@router.get("/runs/{run_id}")
async def get_run(run_id: str) -> dict:
    runtime = _get_runtime()
    run = runtime.get_run(run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Run not found")
    return run.to_dict()


@router.get("/runs/{run_id}/messages")
async def get_run_messages(run_id: str) -> dict:
    runtime = _get_runtime()
    run = runtime.get_run(run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Run not found")
    return {
        "run_id": run_id,
        "messages": run.messages,
    }


@router.get("/runs/{run_id}/tool-calls")
async def get_run_tool_calls(run_id: str) -> dict:
    runtime = _get_runtime()
    run = runtime.get_run(run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Run not found")
    return {
        "run_id": run_id,
        "tool_calls": run.tool_calls,
    }


@router.post("/runs/{run_id}/kill")
async def kill_agent(run_id: str) -> dict:
    runtime = _get_runtime()
    killed = await runtime.kill_agent(run_id)
    if not killed:
        raise HTTPException(status_code=404, detail="Run not found")
    return {"status": "killed", "run_id": run_id}
