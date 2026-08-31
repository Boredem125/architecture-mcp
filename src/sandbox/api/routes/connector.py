"""Folder-connector REST view — a thin window over a project's ``.sandbox/``.

Every endpoint reads the folder on each call via the same primitives the hook,
MCP server, and CLI use (``FolderLayout`` / ``EscalationQueue`` / ``FolderAudit``
/ ``FolderRecorder``). There is deliberately **no** in-memory cache or singleton
here: the folder is the single source of truth, and a second one is exactly how
the launcher ended up with ``recorder=None``.

Because the connector is folder-scoped (not a global service), every endpoint
takes a ``root`` query parameter naming the project folder to inspect. A folder
without ``.sandbox/`` yields 404.

  GET  /api/v1/connector/status?root=…      — policy, triggers, pending count
  GET  /api/v1/connector/pending?root=…     — pending escalations
  POST /api/v1/connector/{id}/approve?root=… — claim, run, finish
  POST /api/v1/connector/{id}/deny?root=…    — claim, deny, finish
  GET  /api/v1/connector/changes?root=…     — file-change timeline
  GET  /api/v1/connector/audit?root=…       — audit records (tail)
  GET  /api/v1/connector/verify?root=…      — chain integrity
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import structlog
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/api/v1/connector", tags=["connector"])


# ------------------------------------------------------------------
# Helpers — resolve the folder fresh on every request
# ------------------------------------------------------------------

def _layout(root: str):
    """Resolve a FolderLayout for *root*, or raise 404 if not initialized."""
    from sandbox.connector.layout import FolderLayout

    layout = FolderLayout(root)
    if not layout.exists():
        raise HTTPException(
            status_code=404,
            detail=f"No .sandbox/ found in {root}. Run `sandbox init` there first.",
        )
    return layout


def _session_id(layout) -> str:
    try:
        return json.loads(layout.session_file.read_text(encoding="utf-8")).get(
            "session_id", ""
        )
    except (OSError, json.JSONDecodeError):
        return ""


# ------------------------------------------------------------------
# Response models
# ------------------------------------------------------------------

class DecisionRequest(BaseModel):
    reason: str = ""


# ------------------------------------------------------------------
# Read endpoints
# ------------------------------------------------------------------

@router.get("/status")
async def connector_status(root: str = Query(...)) -> dict[str, Any]:
    """Policy, triggers, and pending count for a folder."""
    from sandbox.connector.policy import load_policy
    from sandbox.connector.queue import EscalationQueue

    layout = _layout(root)
    policy = load_policy(layout.policy_file)
    pending = EscalationQueue(layout).list_pending()
    return {
        "root": str(layout.root),
        "session_id": _session_id(layout),
        "mode": policy.mode,
        "triggers": policy.triggers.model_dump(),
        "pending_count": len(pending),
        "auto_allow": policy.auto_allow,
    }


@router.get("/pending")
async def connector_pending(root: str = Query(...)) -> dict[str, Any]:
    """List pending escalations awaiting a human decision."""
    from sandbox.connector.queue import EscalationQueue

    layout = _layout(root)
    pending = EscalationQueue(layout).list_pending()
    return {"root": str(layout.root), "pending": pending}


@router.get("/changes")
async def connector_changes(root: str = Query(...)) -> dict[str, Any]:
    """The file-change timeline (originals/index.jsonl)."""
    layout = _layout(root)
    changes: list[dict[str, Any]] = []
    index_file = layout.originals_dir / "index.jsonl"
    if index_file.exists():
        try:
            with open(index_file, encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        try:
                            changes.append(json.loads(line))
                        except json.JSONDecodeError:
                            pass
        except OSError:
            pass
    return {"root": str(layout.root), "changes": changes}


@router.get("/audit")
async def connector_audit(
    root: str = Query(...), limit: int = Query(50, ge=1, le=1000)
) -> dict[str, Any]:
    """The tail of the current session's audit records."""
    from sandbox.connector.audit import FolderAudit

    layout = _layout(root)
    audit = FolderAudit(layout.audit_dir, _session_id(layout))
    return {"root": str(layout.root), "records": audit.list_records(limit=limit)}


@router.get("/verify")
async def connector_verify(root: str = Query(...)) -> dict[str, Any]:
    """Verify the audit chain integrity."""
    from sandbox.connector.audit import FolderAudit

    layout = _layout(root)
    audit = FolderAudit(layout.audit_dir, _session_id(layout))
    valid, message = audit.verify_chain()
    return {"root": str(layout.root), "valid": valid, "message": message}


# ------------------------------------------------------------------
# Decision endpoints (write — mutate the folder queue)
# ------------------------------------------------------------------

@router.post("/{request_id}/approve")
async def connector_approve(
    request_id: str, root: str = Query(...), body: DecisionRequest | None = None
) -> dict[str, Any]:
    """Claim, execute, and finish a pending escalation."""
    from sandbox.connector.broker import FolderBroker
    from sandbox.connector.queue import EscalationQueue

    layout = _layout(root)
    queue = EscalationQueue(layout)
    rec = queue.claim(request_id, "api")
    if rec is None:
        raise HTTPException(
            status_code=409,
            detail=f"Could not claim {request_id} (already taken or not pending).",
        )
    reason = body.reason if body else ""
    result = await FolderBroker().execute(rec, "api", reason)
    queue.finish(request_id, result)
    return {
        "request_id": request_id,
        "state": result.get("state"),
        "exit_code": result.get("exit_code"),
    }


@router.post("/{request_id}/deny")
async def connector_deny(
    request_id: str, root: str = Query(...), body: DecisionRequest | None = None
) -> dict[str, Any]:
    """Claim and deny a pending escalation."""
    from sandbox.connector.broker import FolderBroker
    from sandbox.connector.queue import EscalationQueue

    layout = _layout(root)
    queue = EscalationQueue(layout)
    rec = queue.claim(request_id, "api")
    if rec is None:
        raise HTTPException(
            status_code=409,
            detail=f"Could not claim {request_id}.",
        )
    reason = body.reason if body else "denied via API"
    queue.finish(request_id, FolderBroker.denial(rec, "api", reason))
    return {"request_id": request_id, "state": "denied"}
