"""E2B-compatible API — drop-in sandbox backend for E2B SDK agents.

Any E2B-SDK agent pointed at E2B_API_URL=http://localhost:8000/e2b/v1 gets
sandboxed through our pipeline + Docker containment.

Minimal E2B surface:
  POST   /sandboxes              → create session + container
  POST   /sandboxes/{id}/commands → exec through pipeline + container
  POST   /sandboxes/{id}/files   → write file
  GET    /sandboxes/{id}/files   → read / list files
  DELETE /sandboxes/{id}         → destroy container + end session
"""
from __future__ import annotations

import uuid
from typing import Any

import structlog
from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel

from sandbox.config import ContainmentSettings, ExecutorSettings
from sandbox.containment.docker_sandbox import DockerSandbox, _check_docker_available
from sandbox.containment.process_sandbox import ProcessSandbox
from sandbox.models.enums import ActionType
from sandbox.models.messages import ActionRequest
from sandbox.models.session import SessionStartRequest

logger = structlog.get_logger()

router = APIRouter(prefix="/e2b/v1", tags=["e2b-compat"])

_e2b_sandboxes: dict[str, dict[str, Any]] = {}


def _get_session_manager():
    from sandbox.api.app import get_session_manager
    return get_session_manager()


def _get_config():
    from sandbox.api.app import get_config
    return get_config()


def _get_broadcaster():
    from sandbox.api.websocket import broadcaster
    return broadcaster


def _parse_tenant(api_key: str | None) -> str:
    if not api_key:
        return "anonymous"
    if api_key.startswith("testuser-"):
        return api_key
    return api_key[:16]


# ------------------------------------------------------------------
# Models
# ------------------------------------------------------------------

class CreateSandboxRequest(BaseModel):
    template: str = "python:3.12-slim"
    timeout: int = 1800
    metadata: dict[str, str] = {}


class ExecCommandRequest(BaseModel):
    cmd: str
    timeout: int = 120
    workdir: str | None = None


class WriteFileRequest(BaseModel):
    path: str
    content: str


class ReadFileRequest(BaseModel):
    path: str


# ------------------------------------------------------------------
# Routes
# ------------------------------------------------------------------

@router.post("/sandboxes")
async def create_sandbox(
    req: CreateSandboxRequest,
    x_e2b_api_key: str | None = Header(None, alias="X-E2B-API-Key"),
) -> dict:
    """Create a new sandbox (session + container/process)."""
    config = _get_config()
    sm = _get_session_manager()
    broadcaster = _get_broadcaster()
    tenant = _parse_tenant(x_e2b_api_key)

    sandbox_id = uuid.uuid4().hex[:16]
    agent_id = f"e2b-{sandbox_id}"

    session = sm.create_session(
        SessionStartRequest(
            agent_id=agent_id,
            declared_task=f"E2B sandbox ({tenant})",
            allowed_actions=[ActionType.READ, ActionType.WRITE, ActionType.EXECUTE],
            workspace_root=f"./workspaces/{sandbox_id}",
            max_writes=100,
            ttl_seconds=req.timeout,
        )
    )

    containment = ContainmentSettings(
        base_image=req.template,
        enable_docker=True,
    )

    # Try Docker first, fall back to ProcessSandbox
    sandbox: DockerSandbox | ProcessSandbox
    containment_type: str
    if _check_docker_available():
        sandbox = DockerSandbox(
            session_id=session.session_id,
            containment_settings=containment,
            executor_settings=config.executor,
            capabilities=["READ", "WRITE", "EXECUTE"],
        )
        containment_type = "docker"
    else:
        sandbox = ProcessSandbox(
            session_id=session.session_id,
            containment_settings=containment,
            executor_settings=config.executor,
            capabilities=["READ", "WRITE", "EXECUTE"],
        )
        containment_type = "process"

    container_id = await sandbox.create()

    _e2b_sandboxes[sandbox_id] = {
        "sandbox": sandbox,
        "session": session,
        "session_token": session.capability_token.signature,
        "tenant": tenant,
        "container_id": container_id,
        "template": req.template,
        "metadata": req.metadata,
    }

    await broadcaster.broadcast({
        "event": "e2b_sandbox_created",
        "sandbox_id": sandbox_id,
        "session_id": session.session_id,
        "tenant": tenant,
        "template": req.template,
    })

    return {
        "sandbox_id": sandbox_id,
        "session_id": session.session_id,
        "container_id": container_id[:12],
        "template": req.template,
        "containment": containment_type,
        "status": "running",
    }


def _get_sandbox(sandbox_id: str) -> dict[str, Any]:
    entry = _e2b_sandboxes.get(sandbox_id)
    if entry is None:
        raise HTTPException(status_code=404, detail=f"Sandbox {sandbox_id} not found")
    return entry


async def _pipeline_check(
    entry: dict[str, Any],
    action_type: ActionType,
    parameters: dict[str, Any],
) -> None:
    """Run the action through the pipeline. Raises HTTPException on DENY."""
    from sandbox.pipeline.orchestrator import PipelineOrchestrator

    sm = _get_session_manager()
    broadcaster = _get_broadcaster()

    orchestrator = PipelineOrchestrator(
        session_manager=sm,
        event_broadcaster=broadcaster,
    )

    request = ActionRequest(
        action_type=action_type,
        parameters=parameters,
        session_token=entry["session_token"],
    )

    status = await orchestrator.process_request(request, entry["session"])

    if status.decision != "ALLOW":
        raise HTTPException(
            status_code=403,
            detail={
                "decision": status.decision,
                "reason": status.reason,
                "step": status.step_name,
            },
        )


@router.post("/sandboxes/{sandbox_id}/commands")
async def exec_command(sandbox_id: str, req: ExecCommandRequest) -> dict:
    """Execute a command inside the sandbox container."""
    entry = _get_sandbox(sandbox_id)
    sandbox: DockerSandbox = entry["sandbox"]

    await _pipeline_check(entry, ActionType.EXECUTE, {
        "command": req.cmd,
        "tool": "e2b_exec",
        "timeout": req.timeout,
    })

    result = await sandbox.exec(
        command=req.cmd,
        timeout=req.timeout,
        workdir=req.workdir,
    )

    return {
        "exit_code": result.exit_code,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "timed_out": result.timed_out,
    }


@router.post("/sandboxes/{sandbox_id}/files")
async def write_file(sandbox_id: str, req: WriteFileRequest) -> dict:
    """Write a file into the sandbox container."""
    entry = _get_sandbox(sandbox_id)
    sandbox: DockerSandbox = entry["sandbox"]

    await _pipeline_check(entry, ActionType.WRITE, {
        "path": req.path,
        "tool": "e2b_write",
        "content_length": len(req.content),
    })

    ok = await sandbox.write_file(req.path, req.content.encode("utf-8"))
    if not ok:
        raise HTTPException(status_code=500, detail="Failed to write file")

    return {"path": req.path, "bytes_written": len(req.content)}


@router.get("/sandboxes/{sandbox_id}/files")
async def read_files(sandbox_id: str, path: str = ".") -> dict:
    """Read a file or list a directory inside the sandbox."""
    entry = _get_sandbox(sandbox_id)
    sandbox: DockerSandbox = entry["sandbox"]

    await _pipeline_check(entry, ActionType.READ, {
        "path": path,
        "tool": "e2b_read",
    })

    data = await sandbox.read_file(path)
    if data is not None:
        return {
            "type": "file",
            "path": path,
            "content": data.decode("utf-8", errors="replace"),
        }

    entries = await sandbox.list_dir(path)
    return {
        "type": "directory",
        "path": path,
        "entries": [{"name": e.name, "type": e.type, "size": e.size} for e in entries],
    }


@router.delete("/sandboxes/{sandbox_id}")
async def destroy_sandbox(sandbox_id: str) -> dict:
    """Destroy the sandbox container and end the session."""
    entry = _get_sandbox(sandbox_id)
    sandbox: DockerSandbox = entry["sandbox"]
    session = entry["session"]

    await sandbox.destroy()

    sm = _get_session_manager()
    from sandbox.models.enums import SessionEndReason
    from sandbox.models.session import SessionEndRequest
    sm.end_session(SessionEndRequest(session_id=session.session_id, reason=SessionEndReason.DONE))

    broadcaster = _get_broadcaster()
    await broadcaster.broadcast({
        "event": "e2b_sandbox_destroyed",
        "sandbox_id": sandbox_id,
        "session_id": session.session_id,
    })

    del _e2b_sandboxes[sandbox_id]

    return {"sandbox_id": sandbox_id, "status": "destroyed"}


@router.get("/sandboxes")
async def list_sandboxes(
    x_e2b_api_key: str | None = Header(None, alias="X-E2B-API-Key"),
) -> dict:
    """List active sandboxes, optionally filtered by tenant."""
    tenant = _parse_tenant(x_e2b_api_key)
    sandboxes = []
    for sid, entry in _e2b_sandboxes.items():
        if tenant != "anonymous" and entry["tenant"] != tenant:
            continue
        sandboxes.append({
            "sandbox_id": sid,
            "session_id": entry["session"].session_id,
            "template": entry["template"],
            "status": entry["sandbox"].state.value,
            "tenant": entry["tenant"],
        })
    return {"count": len(sandboxes), "sandboxes": sandboxes}
