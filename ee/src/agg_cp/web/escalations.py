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
                "e.policy_sequence, e.status, p.environment "
                "FROM escalations e "
                "LEFT JOIN projects p ON p.id = e.project_id "
                "WHERE e.status = 'pending' "
                "ORDER BY e.created_at DESC",
            ).fetchall()

            conn.commit()

        items = []
        for row in rows:
            record = row[2] or {}
            command = record.get("command", "") if isinstance(record, dict) else ""
            env = row[6] or "prod"
            items.append({
                "escalation_id": str(row[0]),
                "request_id": row[1],
                "command": command,
                "project_id": str(row[3]),
                "policy_sequence": row[4],
                "environment": env,
                "is_prod": env == "prod",
            })

        resp = JSONResponse({"escalations": items})
        resp.headers["content-security-policy"] = _CSP
        return resp

    return router


# Module-level alias for ``_need("agg_cp.web.escalations", "router")``
router = web_escalation_router
