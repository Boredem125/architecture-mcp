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
import os
from pathlib import Path
from typing import Any

import structlog
from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel

logger = structlog.get_logger(__name__)

MAX_ROOT_CHARS = 1024

router = APIRouter(prefix="/api/v1/connector", tags=["connector"])


# ------------------------------------------------------------------
# Helpers — resolve the folder fresh on every request
# ------------------------------------------------------------------

def _layout(request: Request, root: str):
    """Resolve a FolderLayout for *root*: 400 bad string, 403 not listed, 404 not initialized.

    Only roots configured with ``sandbox serve --root`` / SANDBOX_CONNECTOR_ROOTS
    are served (SEC-10, D1). The request value is compared as a pure string and
    is never used to touch the filesystem; after a match the *configured* root
    is used, never the request string.
    """
    from sandbox.connector.layout import FolderLayout

    if "\x00" in root or len(root) > MAX_ROOT_CHARS or not os.path.isabs(root):
        raise HTTPException(status_code=400, detail="root must be an absolute path (at most 1024 characters)")
    allowed: dict[str, str] = getattr(request.app.state, "connector_roots", {})
    stored = allowed.get(os.path.normcase(os.path.normpath(root)))
    if stored is None:
        raise HTTPException(status_code=403, detail="This folder is not served by this API (see sandbox serve --root).")
    # A configured root the OS can't stat is a bad request, not a crash.
    try:
        layout = FolderLayout(stored)
        found = layout.exists()
    except (OSError, ValueError):
        raise HTTPException(status_code=400, detail="root is not a usable path")
    if not found:
        raise HTTPException(
            status_code=404,
            detail="No .sandbox/ found in that folder. Run `sandbox init` there first.",
        )
    return layout


def _request_id(request_id: str) -> str:
    """400 for an id that is not a well-formed request id (SEC-26)."""
    from sandbox.connector.queue import valid_request_id

    if not valid_request_id(request_id):
        raise HTTPException(status_code=400, detail="malformed request id")
    return request_id


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
async def connector_status(request: Request, root: str = Query(...)) -> dict[str, Any]:
    """Policy, triggers, and pending count for a folder."""
    from sandbox.connector.policy import load_policy
    from sandbox.connector.queue import EscalationQueue

    layout = _layout(request, root)
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
async def connector_pending(request: Request, root: str = Query(...)) -> dict[str, Any]:
    """List pending escalations awaiting a human decision."""
    from sandbox.connector.queue import EscalationQueue

    layout = _layout(request, root)
    pending = EscalationQueue(layout).list_pending()
    return {"root": str(layout.root), "pending": pending}


@router.get("/changes")
async def connector_changes(request: Request, root: str = Query(...)) -> dict[str, Any]:
    """The file-change timeline (originals/index.jsonl)."""
    layout = _layout(request, root)
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
    request: Request, root: str = Query(...), limit: int = Query(50, ge=1, le=1000)
) -> dict[str, Any]:
    """The tail of the current session's audit records."""
    from sandbox.connector.audit import FolderAudit

    layout = _layout(request, root)
    audit = FolderAudit(layout.audit_dir, _session_id(layout))
    return {"root": str(layout.root), "records": audit.list_records(limit=limit)}


@router.get("/verify")
async def connector_verify(request: Request, root: str = Query(...)) -> dict[str, Any]:
    """Verify the audit chain integrity."""
    from sandbox.connector.audit import FolderAudit

    layout = _layout(request, root)
    audit = FolderAudit(layout.audit_dir, _session_id(layout))
    valid, message = audit.verify_chain()
    return {"root": str(layout.root), "valid": valid, "message": message}


# ------------------------------------------------------------------
# Decision endpoints (write — mutate the folder queue)
# ------------------------------------------------------------------

@router.post("/{request_id}/approve")
async def connector_approve(
    request: Request, request_id: str, root: str = Query(...), body: DecisionRequest | None = None
) -> dict[str, Any]:
    """Claim, execute, and finish a pending escalation."""
    from sandbox.connector.broker import FolderBroker
    from sandbox.connector.queue import EscalationQueue

    from sandbox.connector.approval import approve

    layout = _layout(request, root)
    _request_id(request_id)
    # The API acts as one reviewer, "api": a dual-control request approved
    # here still needs a second, different reviewer (e.g. the CLI).
    outcome = await approve(layout, request_id, "api", body.reason if body else "")
    status = outcome["status"]
    if status == "not_pending":
        raise HTTPException(status_code=409,
                            detail=f"Could not claim {request_id} (already taken or not pending).")
    if status == "key_unavailable":  # ADR 0007 1.3: no key home, no signature, no approval
        raise HTTPException(status_code=503, detail="No signing key available on the server; nothing was approved.")
    if status == "same_reviewer":
        raise HTTPException(status_code=409,
                            detail=f"{request_id} needs dual control; the API already gave the first approval.")
    if status == "reason_required":  # approval fatigue (connector/oversight.py)
        raise HTTPException(status_code=422, detail=(
            f"Approval fatigue flagged for reviewer 'api': a reason of at least "
            f"{outcome['oversight']['min_reason_chars']} characters is required."))
    if status == "awaiting_second":
        return {"request_id": request_id, "state": "awaiting_second_approval", "approvals": outcome["approvals"]}
    result = outcome["result"]
    return {
        "request_id": request_id,
        "state": result.get("state"),
        "exit_code": result.get("exit_code"),
    }


@router.post("/{request_id}/deny")
async def connector_deny(
    request: Request, request_id: str, root: str = Query(...), body: DecisionRequest | None = None
) -> dict[str, Any]:
    """Claim and deny a pending escalation."""
    from sandbox.connector.broker import FolderBroker
    from sandbox.connector.queue import EscalationQueue

    layout = _layout(request, root)
    _request_id(request_id)
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
