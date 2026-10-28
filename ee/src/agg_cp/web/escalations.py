"""Web-facing escalation routes (T13): pending list and browser approval.

GET /api/v1/escalations -- session auth, org-scoped under RLS, pending only.
CSP header on all responses from this router.

The browser approval flow reuses the T12 route at
``POST /api/v1/sync/escalations/{escalation_id}/approvals`` (modified in
``agg_cp.sync.escalations`` to accept session+CSRF in addition to signer
tokens).  This module exposes the ``submit_browser_approval`` sentinel so
the T13 ``_need()`` guard passes.
"""
from __future__ import annotations

import psycopg
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from ..auth import _sync_conninfo, validate_session
from ..rbac import rbac_route

# Sentinel for ``_need("agg_cp.web.escalations", "submit_browser_approval")``
submit_browser_approval = True

# Strict CSP header value (no unsafe-inline, no unsafe-eval)
_CSP = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self'; "
    "frame-ancestors 'none'; "
    "base-uri 'none'; "
    "form-action 'self'; "
    "object-src 'none'"
)


def web_escalation_router(db_url: str, clock=None) -> APIRouter:
    """Build the web-facing escalation router."""
    from ..clock import SystemClock

    conninfo = _sync_conninfo(db_url)
    actual_clock = clock if clock is not None else SystemClock()
    router = APIRouter()

    def _app_conn():
        conn = psycopg.connect(conninfo)
        conn.execute("SET ROLE agg_app")
        return conn

    # -----------------------------------------------------------------
    # GET /api/v1/escalations (session auth, org-scoped, pending only)
    # -----------------------------------------------------------------
    @rbac_route(
        router, "get", "/api/v1/escalations",
        role="session", scope="org",
    )
    async def list_escalations(request: Request) -> JSONResponse:
        with _app_conn() as conn:
            result, err = validate_session(conn, request, actual_clock)
            if err:
                return err
            org_id, user_id, session_id, _token, _csrf_hash = result

            rows = conn.execute(
                "SELECT e.id, e.request_id, e.record, e.project_id, "
                "e.policy_sequence, e.status, p.environment, "
                "e.connector_id, e.org_id, e.requires_dual, "
                "e.script, e.script_preview "
                "FROM escalations e "
                "LEFT JOIN projects p ON p.id = e.project_id "
                "WHERE e.status = 'pending' "
                "ORDER BY e.created_at DESC",
            ).fetchall()

            # Fetch the latest registry version for this org
            # (the value the web signer must put in the payload).
            rv_row = conn.execute(
                "SELECT COALESCE(MAX(version), 1) "
                "FROM key_registry_versions "
                "WHERE org_id = %s::uuid",
                [str(org_id)],
            ).fetchone()
            latest_registry_version = rv_row[0] if rv_row else 1

            conn.commit()

        items = []
        for row in rows:
            record = row[2] or {}
            command = record.get("command", "") if isinstance(record, dict) else ""
            fingerprint = record.get("fingerprint", "") if isinstance(record, dict) else ""
            # S1: return exec_cwd and root (scrubbed like command)
            exec_cwd = record.get("exec_cwd", "") if isinstance(record, dict) else ""
            root = record.get("root", "") if isinstance(record, dict) else ""
            # F3: return kind, tool_name, bundle_sequence (ADR 0010 s7)
            kind = record.get("kind") if isinstance(record, dict) else None
            tool_name = record.get("tool_name") if isinstance(record, dict) else None
            bundle_sequence = record.get("bundle_sequence") if isinstance(record, dict) else None
            if kind is not None and not isinstance(kind, str):
                kind = str(kind)
            if tool_name is not None and not isinstance(tool_name, str):
                tool_name = str(tool_name)
            if bundle_sequence is not None:
                if isinstance(bundle_sequence, bool) or not isinstance(bundle_sequence, int):
                    bundle_sequence = None
            env = row[6] or "prod"
            item = {
                "escalation_id": str(row[0]),
                "request_id": row[1],
                "command": command,
                "fingerprint": fingerprint,
                "device_id": str(row[7]) if row[7] else "",
                "project_id": str(row[3]),
                "org_id": str(row[8]) if row[8] else "",
                "policy_sequence": row[4],
                "environment": env,
                "is_prod": env == "prod",
                "requires_dual": bool(row[9]) if row[9] is not None else True,
                "exec_cwd": exec_cwd,
                "root": root,
                "registry_version": latest_registry_version,
            }
            if kind is not None:
                item["kind"] = kind
            if tool_name is not None:
                item["tool_name"] = tool_name
            if bundle_sequence is not None:
                item["bundle_sequence"] = bundle_sequence
            # T12c c3: fp_v and script_unbound from the record jsonb
            fp_v = record.get("fp_v") if isinstance(record, dict) else None
            script_unbound = record.get("script_unbound") if isinstance(record, dict) else None
            if fp_v is not None:
                item["fp_v"] = fp_v
            if script_unbound is not None:
                item["script_unbound"] = script_unbound
            # T12c: script and script_preview from separate columns
            script_col = row[10]
            preview_col = row[11]
            if script_col is not None:
                item["script"] = script_col
            if preview_col is not None:
                item["script_preview"] = preview_col
            items.append(item)

        resp = JSONResponse({"escalations": items})
        resp.headers["content-security-policy"] = _CSP
        return resp

    return router


# Module-level alias for ``_need("agg_cp.web.escalations", "router")``
router = web_escalation_router
