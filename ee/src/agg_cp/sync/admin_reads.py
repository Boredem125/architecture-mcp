"""M3 T1: admin read routes for devices, codes, bundles, alerts, verify, export.

Routes:
  GET /api/v1/devices?project=          -- session auth, cursor pagination
  GET /api/v1/devices/{id}              -- session auth (checkpoints, sessions,
                                           open_escalations, quarantine_rows)
  GET /api/v1/admin/enrollment-codes?project= -- admin, cursor pagination
  GET /api/v1/admin/bundles?project=    -- admin, cursor pagination
  GET /api/v1/admin/bundles/{seq}       -- admin, envelope, approvals, diff,
                                           verification, applied_by
  GET /api/v1/alerts?project=&since=    -- session auth, cursor pagination
  GET /api/v1/audit/verify?project=     -- auditor (project admin, org admin,
                                           org auditor, project auditor)
  GET /api/v1/audit/export?project=&since=&until= -- auditor, JSONL,
                                           byte cap, bounded buffering,
                                           Content-Length, stable order

Every route:
  - ``x-agg-rbac`` via :func:`rbac_route`
  - session auth via :func:`validate_session`
  - FORCE RLS via ``SET ROLE agg_app`` + ``set_config('app.org_id', ...)``
  - uniform 404 for foreign org, missing project, non-member
  - parameterised SQL only
  - cursor tokens UUID-based, org-bound, no per-process key (T1-5)

Server TCB (security L reviews every diff).
"""
from __future__ import annotations

import datetime as dt
import json
import uuid
from typing import Any

import psycopg
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, Response

from agg_cp.auth import validate_session, _sync_conninfo, _app_conn
from agg_cp.clock import Clock
from agg_cp.rbac import rbac_route
from agg_cp.sync.audit import MAX_NESTING_DEPTH, json_nesting_depth


# ---------------------------------------------------------------------------
# Cursor pagination (UUID-based, org-bound, no per-process key -- T1-5)
# ---------------------------------------------------------------------------

_PAGE_SIZE = 20  # Bound page sizes
_MAX_SESSIONS = 100  # T1-18: bound sessions list on /devices/{id}


def _encode_cursor(org_id: str, after_id: str) -> str:
    """Produce an opaque cursor token.

    The token is ``<org_id>:<after_id>`` -- a simple, deterministic
    encoding that every worker can decode without a shared secret.
    RLS and the project filter already bound what a forged position
    can reach (T1-5).  Foreign and garbage cursors are identical:
    strict UUID parse + org compare.
    """
    return f"{org_id}:{after_id}"


def _decode_cursor(token: str, org_id: str) -> str | None:
    """Decode and verify a cursor token.  Returns after_id or None.

    Foreign-org and garbage cursors are indistinguishable (T1-5).
    T1-19: strict UUID parse -- str(uuid.UUID(x)) == x for both parts.
    """
    try:
        parts = token.split(":", 1)
        if len(parts) != 2:
            return None
        cursor_org, cursor_after = parts
        # Strict UUID parse (T1-19: urn:uuid:, braces, no-hyphens all rejected)
        org_parsed = uuid.UUID(cursor_org)
        after_parsed = uuid.UUID(cursor_after)
        if str(org_parsed) != cursor_org:
            return None
        if str(after_parsed) != cursor_after:
            return None
        if cursor_org != org_id:
            return None  # foreign-org -> indistinguishable from garbage
        return cursor_after
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Shared helpers (T1-25)
# ---------------------------------------------------------------------------

def _page_after(conn, sql_base: str, params: list, after_id: str | None,
                page_size: int = _PAGE_SIZE):
    """Execute a paginated query.  Returns (page_rows, has_more).

    Appends ``AND id > %s::uuid`` when ``after_id`` is set,
    ``ORDER BY id ASC LIMIT %s``, and fetches.  The caller builds
    ``sql_base`` up to the WHERE clause (inclusive).
    """
    p = list(params)
    clauses = sql_base
    if after_id:
        clauses += " AND id > %s::uuid"
        p.append(after_id)
    clauses += " ORDER BY id ASC LIMIT %s"
    p.append(page_size + 1)
    rows = list(conn.execute(clauses, p))
    has_more = len(rows) > page_size
    return rows[:page_size], has_more


def _project_for(conn, project_id_str: str, user_id) -> uuid.UUID | None:
    """Return parsed project UUID if the project exists in the caller's
    org AND the user can read it; None otherwise (T1-25).
    Uses strict UUID parse (T1-9, T1-19)."""
    pid = _parse_project_id(project_id_str)
    if pid is None:
        return None
    proj = conn.execute(
        "SELECT id FROM projects WHERE id = %s",
        [pid],
    ).fetchone()
    if proj is None:
        return None
    # Check user has at least viewer access
    role_row = conn.execute(
        "SELECT 1 FROM role_bindings WHERE user_id = %s AND ("
        "(scope_type = 'org' AND role IN "
        "('admin','viewer','policy_author','approver','auditor'))"
        " OR "
        "(scope_type = 'project' AND scope_id = %s AND role IN "
        "('admin','viewer','policy_author','approver','auditor'))"
        ") LIMIT 1",
        [user_id, pid],
    ).fetchone()
    if role_row is None:
        return None
    return pid


def _parse_project_id(raw: str) -> uuid.UUID | None:
    """Strict UUID parse (T1-9, T1-19: urn:uuid: and other spellings refused)."""
    try:
        pid = uuid.UUID(raw)
    except ValueError:
        return None
    if str(pid) != raw:
        return None
    return pid


def _refuse_json_constant(token: str):
    """``parse_constant`` hook: ``NaN``, ``Infinity`` and ``-Infinity``
    are not JSON and ``JSONResponse`` cannot render them (T1-27)."""
    raise ValueError(f"non-finite JSON constant refused: {token}")


def _parse_bundle_blob(blob) -> tuple[dict | None, bool]:
    """Parse a bundle blob.  Returns (envelope_or_None, is_corrupt).

    Handles memoryview, bytes, str, non-UTF-8 (T1-21).  Refuses
    ``NaN`` / ``Infinity`` (``parse_constant``), a blob nested deeper
    than the parser allows (``RecursionError``) and, platform
    independently, one deeper than ``MAX_NESTING_DEPTH`` (the same
    limit as record bodies; checked without recursion so neither the
    diff nor the response renderer can recurse on it).  Every form is
    ``corrupt_bundle`` on the blob and ``diff_base_corrupt`` on its
    successor, never a 500 (T1-27).
    """
    if isinstance(blob, memoryview):
        blob = bytes(blob)
    if isinstance(blob, bytes):
        try:
            blob = blob.decode("utf-8")
        except (UnicodeDecodeError, ValueError):
            return None, True
    if not isinstance(blob, str):
        return None, True
    try:
        envelope = json.loads(blob, parse_constant=_refuse_json_constant)
    except (ValueError, TypeError, RecursionError):
        return None, True
    if not isinstance(envelope, dict):
        return None, True
    if json_nesting_depth(envelope, limit=MAX_NESTING_DEPTH) > MAX_NESTING_DEPTH:
        return None, True
    return envelope, False


# ---------------------------------------------------------------------------
# Route factory
# ---------------------------------------------------------------------------


def build_admin_reads_router(*, db_url: str, clock: Clock) -> APIRouter:
    """Build and return the admin-reads router for T1."""
    conninfo = _sync_conninfo(db_url)
    router = APIRouter(prefix="/api/v1")

    # ---------------------------------------------------------------
    # Shared helpers
    # ---------------------------------------------------------------

    def _validate(conn, request):
        return validate_session(conn, request, clock)

    def _is_project_admin_or_auditor(
        conn, user_id, project_id: uuid.UUID,
    ) -> bool:
        """True if the user is project admin, org admin, org auditor,
        or project auditor (T1-4, T1-22)."""
        row = conn.execute(
            "SELECT 1 FROM role_bindings WHERE user_id = %s AND ("
            "(scope_type = 'org' AND role IN ('admin', 'auditor'))"
            " OR "
            "(scope_type = 'project' AND scope_id = %s AND role IN ('admin', 'auditor'))"
            ") LIMIT 1",
            [user_id, project_id],
        ).fetchone()
        return row is not None

    def _is_project_admin(conn, user_id, project_id: uuid.UUID) -> bool:
        """True if the user is project admin or org admin (T1-3)."""
        row = conn.execute(
            "SELECT 1 FROM role_bindings WHERE user_id = %s AND ("
            "(scope_type = 'org' AND role = 'admin')"
            " OR "
            "(scope_type = 'project' AND scope_id = %s AND role = 'admin')"
            ") LIMIT 1",
            [user_id, project_id],
        ).fetchone()
        return row is not None

    def _validate_since(since_str: str | None) -> dt.datetime | None | str:
        """Parse a ``since`` query param.  Returns datetime, None, or
        ``"bad"`` string on a parse error (T1-9, T1-20)."""
        if not since_str:
            return None
        try:
            parsed = dt.datetime.fromisoformat(since_str)
            return parsed
        except (ValueError, TypeError):
            return "bad"

    # =================================================================
    # GET /devices?project=
    # =================================================================

    @rbac_route(router, "get", "/devices", role="session", scope="project")
    def list_devices(request: Request):
        with _app_conn(conninfo) as conn:
            session, err = _validate(conn, request)
            if err:
                return err
            org_id, user_id, _, _, _ = session

            project_id_raw = request.query_params.get("project", "")
            if not project_id_raw:
                return JSONResponse({"error": "missing_project"}, status_code=400)

            cursor_param = request.query_params.get("cursor")
            if cursor_param:
                after_id = _decode_cursor(cursor_param, str(org_id))
                if after_id is None:
                    conn.commit()
                    return JSONResponse({"error": "bad_cursor"}, status_code=400)
            else:
                after_id = None

            pid = _project_for(conn, project_id_raw, user_id)
            if pid is None:
                return JSONResponse({"error": "not_found"}, status_code=404)
            project_id = str(pid)

            page, has_more = _page_after(
                conn,
                "SELECT id, device_public_key, hostname, operator_user_id, "
                "last_seen, revoked_at, created_at "
                "FROM connectors "
                "WHERE project_id = %s::uuid",
                [project_id],
                after_id,
            )

            items = []
            for r in page:
                items.append({
                    "id": str(r[0]),
                    "device_public_key": r[1],
                    "hostname": r[2],
                    "operator_user_id": str(r[3]) if r[3] else None,
                    "revoked_at": r[5].isoformat() if r[5] else None,
                    "created_at": r[6].isoformat() if r[6] else None,
                })

            cursor_out = None
            if has_more and page:
                cursor_out = _encode_cursor(str(org_id), str(page[-1][0]))
            result: dict[str, Any] = {"items": items, "cursor": cursor_out}

            conn.commit()
        return JSONResponse(result)

    # =================================================================
    # GET /devices/{id}  (T1-10, T1-18, T1-25)
    # =================================================================

    @rbac_route(router, "get", "/devices/{device_id}",
                role="session", scope="project")
    def get_device(request: Request, device_id: str):
        with _app_conn(conninfo) as conn:
            session, err = _validate(conn, request)
            if err:
                return err
            org_id, user_id, _, _, _ = session

            try:
                did = uuid.UUID(device_id)
            except ValueError:
                return JSONResponse({"error": "not_found"}, status_code=404)

            row = conn.execute(
                "SELECT c.id, c.project_id, c.device_public_key, c.hostname, "
                "c.operator_user_id, c.last_seen, c.revoked_at, c.created_at "
                "FROM connectors c "
                "WHERE c.id = %s::uuid",
                [str(did)],
            ).fetchone()
            if row is None:
                return JSONResponse({"error": "not_found"}, status_code=404)

            project_id_str = str(row[1])
            pid = _project_for(conn, project_id_str, user_id)
            if pid is None:
                return JSONResponse({"error": "not_found"}, status_code=404)

            # T1-10: checkpoints (audit_heads)
            checkpoint_rows = list(conn.execute(
                "SELECT upload_seq, head_hash, created_at "
                "FROM audit_heads "
                "WHERE connector_id = %s::uuid "
                "ORDER BY upload_seq DESC LIMIT 10",
                [str(did)],
            ))
            checkpoints = [
                {"upload_seq": cp[0], "head_hash": cp[1],
                 "created_at": cp[2].isoformat() if cp[2] else None}
                for cp in checkpoint_rows
            ]

            # T1-10/T1-18: sessions limited with truncated flag
            session_rows = list(conn.execute(
                "SELECT DISTINCT session_id FROM audit_records "
                "WHERE connector_id = %s::uuid "
                "LIMIT %s",
                [str(did), _MAX_SESSIONS + 1],
            ))
            sessions = [sr[0] for sr in session_rows[:_MAX_SESSIONS]]
            sessions_truncated = len(session_rows) > _MAX_SESSIONS

            # T1-10/T1-25: open escalations with status = 'pending'
            esc_rows = list(conn.execute(
                "SELECT id, status, created_at FROM escalations "
                "WHERE connector_id = %s::uuid AND status = 'pending' "
                "ORDER BY created_at DESC LIMIT 20",
                [str(did)],
            ))
            open_escalations = [
                {"id": str(e[0]), "status": e[1],
                 "created_at": e[2].isoformat() if e[2] else None}
                for e in esc_rows
            ]

            # T1-10: quarantine rows
            q_rows = list(conn.execute(
                "SELECT id, kind, detail, created_at FROM audit_quarantine "
                "WHERE connector_id = %s::uuid "
                "ORDER BY created_at DESC LIMIT 20",
                [str(did)],
            ))
            quarantine_rows = [
                {"id": str(q[0]), "kind": q[1],
                 "detail": q[2] if isinstance(q[2], dict) else
                           (json.loads(q[2]) if isinstance(q[2], str) else q[2]),
                 "created_at": q[3].isoformat() if q[3] else None}
                for q in q_rows
            ]

            conn.commit()

        result: dict[str, Any] = {
            "id": str(row[0]),
            "project_id": str(pid),
            "device_public_key": row[2],
            "hostname": row[3],
            "operator_user_id": str(row[4]) if row[4] else None,
            "revoked_at": row[6].isoformat() if row[6] else None,
            "created_at": row[7].isoformat() if row[7] else None,
            "checkpoints": checkpoints,
            "sessions": sessions,
            "sessions_truncated": sessions_truncated,
            "open_escalations": open_escalations,
            "quarantine_rows": quarantine_rows,
        }
        return JSONResponse(result)

    # =================================================================
    # GET /admin/enrollment-codes?project=  (T1-3: admin only; T1-9: cursor)
    # =================================================================

    @rbac_route(router, "get", "/admin/enrollment-codes",
                role="admin", scope="project")
    def list_enrollment_codes(request: Request):
        with _app_conn(conninfo) as conn:
            session, err = _validate(conn, request)
            if err:
                return err
            org_id, user_id, _, _, _ = session

            project_id_raw = request.query_params.get("project", "")
            if not project_id_raw:
                return JSONResponse({"error": "missing_project"}, status_code=400)

            cursor_param = request.query_params.get("cursor")
            if cursor_param:
                after_id = _decode_cursor(cursor_param, str(org_id))
                if after_id is None:
                    conn.commit()
                    return JSONResponse({"error": "bad_cursor"}, status_code=400)
            else:
                after_id = None

            pid = _project_for(conn, project_id_raw, user_id)
            if pid is None:
                return JSONResponse({"error": "not_found"}, status_code=404)
            project_id = str(pid)

            # T1-3: admin-only check
            if not _is_project_admin(conn, user_id, pid):
                return JSONResponse({"error": "not_found"}, status_code=404)

            page, has_more = _page_after(
                conn,
                "SELECT id, project_id, operator_user_id, expires_at, "
                "used_at, code_read_at, created_at "
                "FROM enrollment_codes "
                "WHERE project_id = %s::uuid",
                [project_id],
                after_id,
            )

            items = []
            for r in page:
                if r[4] is not None:      # used_at
                    status = "used"
                elif r[3] and r[3] < clock.now():  # expires_at
                    status = "expired"
                elif r[5] is not None:    # code_read_at
                    status = "issued"
                else:
                    status = "pending"

                items.append({
                    "id": str(r[0]),
                    "project_id": str(r[1]),
                    "operator_user_id": str(r[2]) if r[2] else None,
                    "status": status,
                    "expires_at": r[3].isoformat() if r[3] else None,
                    "created_at": r[6].isoformat() if r[6] else None,
                })

            cursor_out = None
            if has_more and page:
                cursor_out = _encode_cursor(str(org_id), str(page[-1][0]))
            result: dict[str, Any] = {"items": items, "cursor": cursor_out}

            conn.commit()
        return JSONResponse(result)

    # =================================================================
    # GET /admin/bundles?project=  (T1-3: admin only; T1-9: cursor)
    # =================================================================

    @rbac_route(router, "get", "/admin/bundles",
                role="admin", scope="project")
    def list_bundles(request: Request):
        with _app_conn(conninfo) as conn:
            session, err = _validate(conn, request)
            if err:
                return err
            org_id, user_id, _, _, _ = session

            project_id_raw = request.query_params.get("project", "")
            if not project_id_raw:
                return JSONResponse({"error": "missing_project"}, status_code=400)

            cursor_param = request.query_params.get("cursor")
            if cursor_param:
                after_id = _decode_cursor(cursor_param, str(org_id))
                if after_id is None:
                    conn.commit()
                    return JSONResponse({"error": "bad_cursor"}, status_code=400)
            else:
                after_id = None

            pid = _project_for(conn, project_id_raw, user_id)
            if pid is None:
                return JSONResponse({"error": "not_found"}, status_code=404)
            project_id = str(pid)

            # T1-3: admin-only check
            if not _is_project_admin(conn, user_id, pid):
                return JSONResponse({"error": "not_found"}, status_code=404)

            page, has_more = _page_after(
                conn,
                "SELECT id, sequence, verification, verified_at, created_at "
                "FROM policy_bundles "
                "WHERE project_id = %s::uuid",
                [project_id],
                after_id,
            )

            items = []
            for r in page:
                items.append({
                    "id": str(r[0]),
                    "sequence": r[1],
                    "verification": r[2],
                    "verified_at": r[3].isoformat() if r[3] else None,
                    "created_at": r[4].isoformat() if r[4] else None,
                })

            cursor_out = None
            if has_more and page:
                cursor_out = _encode_cursor(str(org_id), str(page[-1][0]))
            result: dict[str, Any] = {"items": items, "cursor": cursor_out}

            conn.commit()
        return JSONResponse(result)

    # =================================================================
    # GET /admin/bundles/{seq}  (T1-3, T1-6, T1-7, T1-9, T1-21)
    # =================================================================

    @rbac_route(router, "get", "/admin/bundles/{seq}",
                role="admin", scope="project")
    def get_bundle_detail(request: Request, seq: str):
        with _app_conn(conninfo) as conn:
            session, err = _validate(conn, request)
            if err:
                return err
            org_id, user_id, _, _, _ = session

            project_id_raw = request.query_params.get("project", "")
            if not project_id_raw:
                return JSONResponse({"error": "missing_project"}, status_code=400)

            pid = _project_for(conn, project_id_raw, user_id)
            if pid is None:
                return JSONResponse({"error": "not_found"}, status_code=404)
            project_id = str(pid)

            # T1-3: admin-only check
            if not _is_project_admin(conn, user_id, pid):
                return JSONResponse({"error": "not_found"}, status_code=404)

            try:
                seq_int = int(seq)
            except (ValueError, TypeError):
                return JSONResponse({"error": "not_found"}, status_code=404)

            row = conn.execute(
                "SELECT id, sequence, bundle_blob, verification, "
                "verified_at, created_at "
                "FROM policy_bundles "
                "WHERE project_id = %s::uuid AND sequence = %s",
                [project_id, seq_int],
            ).fetchone()
            if row is None:
                return JSONResponse({"error": "not_found"}, status_code=404)

            bundle_id = str(row[0])
            blob = row[2]

            # T1-21: use shared parser that handles all corrupt forms
            envelope, corrupt = _parse_bundle_blob(blob)
            if envelope is None:
                envelope = {}

            # T1-7: Approvals by user and kind; signature_verified false
            approval_rows = list(conn.execute(
                "SELECT pca.user_id, pca.key_id, pca.signature, "
                "pca.signed_at, ak.kind "
                "FROM policy_change_approvals pca "
                "LEFT JOIN approver_keys ak ON ak.key_id = pca.key_id "
                "  AND ak.org_id = pca.org_id "
                "WHERE pca.change_request_id = %s::uuid "
                "ORDER BY pca.signed_at",
                [bundle_id],
            ))

            approvals = []
            for ar in approval_rows:
                approvals.append({
                    "user_id": str(ar[0]),
                    "key_id": ar[1],
                    "kind": ar[4] or "unknown",
                    "signed_at": ar[3].isoformat() if ar[3] else None,
                    "signature_verified": False,  # T1-7: until T4
                })

            # T1-9: Per-section diff using the highest lower sequence
            payload = envelope.get("payload", {}) if not corrupt else {}
            if not isinstance(payload, dict):
                payload = {}
                corrupt = True  # payload is not an object -> corrupt
            diff_sections, diff_base_seq, diff_base_corrupt = \
                _compute_section_diff(conn, project_id, seq_int, payload)

            # T1-6 / T0b-12: applied_by null, applied_by_status not_reported
            conn.commit()

        result: dict[str, Any] = {
            "id": bundle_id,
            "sequence": row[1],
            "envelope": envelope,
            "verification": row[3],
            "verified_at": row[4].isoformat() if row[4] else None,
            "approvals": approvals,
            "diff": diff_sections,
            "diff_base_sequence": diff_base_seq,
            "applied_by": None,
            "applied_by_status": "not_reported",
            "created_at": row[5].isoformat() if row[5] else None,
        }
        if corrupt:
            result["corrupt_bundle"] = True
        if diff_base_corrupt:
            result["diff_base_corrupt"] = True
        return JSONResponse(result)

    # =================================================================
    # GET /alerts?project=&since=  (T1-9: cursor pagination, bad since 400)
    # =================================================================

    @rbac_route(router, "get", "/alerts", role="session", scope="project")
    def list_alerts(request: Request):
        with _app_conn(conninfo) as conn:
            session, err = _validate(conn, request)
            if err:
                return err
            org_id, user_id, _, _, _ = session

            project_id_raw = request.query_params.get("project", "")
            if not project_id_raw:
                return JSONResponse({"error": "missing_project"}, status_code=400)

            # Cursor before project
            cursor_param = request.query_params.get("cursor")
            if cursor_param:
                after_id = _decode_cursor(cursor_param, str(org_id))
                if after_id is None:
                    conn.commit()
                    return JSONResponse({"error": "bad_cursor"}, status_code=400)
            else:
                after_id = None

            # T1-9/T1-20: bad since -> 400, send parsed value
            since_raw = request.query_params.get("since")
            since_val = _validate_since(since_raw)
            if since_val == "bad":
                conn.commit()
                return JSONResponse({"error": "bad_since"}, status_code=400)

            pid = _project_for(conn, project_id_raw, user_id)
            if pid is None:
                return JSONResponse({"error": "not_found"}, status_code=404)
            project_id = str(pid)

            params: list[Any] = [project_id]
            where_parts = ["project_id = %s::uuid"]

            if since_val is not None:
                where_parts.append("created_at >= %s")
                params.append(since_val)

            if after_id:
                where_parts.append("id > %s::uuid")
                params.append(after_id)

            where = " AND ".join(where_parts)
            params.append(_PAGE_SIZE + 1)

            rows = list(conn.execute(
                "SELECT id, connector_id, kind, detail, acked_at, created_at "
                "FROM sync_alerts "
                f"WHERE {where} "
                "ORDER BY id ASC "
                f"LIMIT %s",
                params,
            ))

            has_more = len(rows) > _PAGE_SIZE
            page = rows[:_PAGE_SIZE]

            items = []
            for r in page:
                items.append({
                    "id": str(r[0]),
                    "connector_id": str(r[1]) if r[1] else None,
                    "kind": r[2],
                    "detail": r[3],
                    "acked_at": r[4].isoformat() if r[4] else None,
                    "created_at": r[5].isoformat() if r[5] else None,
                })

            cursor_out = None
            if has_more and page:
                cursor_out = _encode_cursor(str(org_id), str(page[-1][0]))
            result: dict[str, Any] = {"items": items, "cursor": cursor_out}

            conn.commit()
        return JSONResponse(result)

    # =================================================================
    # GET /audit/verify?project=  (T1-4, T1-10, T1-18, T1-22)
    # =================================================================

    @rbac_route(router, "get", "/audit/verify",
                role="auditor", scope="project")
    def audit_verify_project(request: Request):
        with _app_conn(conninfo) as conn:
            session, err = _validate(conn, request)
            if err:
                return err
            org_id, user_id, _, _, _ = session

            project_id_raw = request.query_params.get("project", "")
            if not project_id_raw:
                return JSONResponse({"error": "missing_project"}, status_code=400)

            pid = _project_for(conn, project_id_raw, user_id)
            if pid is None:
                return JSONResponse({"error": "not_found"}, status_code=404)
            project_id = str(pid)

            # T1-4/T1-22: project admin, org admin, org auditor, project auditor
            if not _is_project_admin_or_auditor(conn, user_id, pid):
                return JSONResponse({"error": "not_found"}, status_code=404)

            from agg_cp.sync.audit import verify_project, _MAX_GAPS

            ok, gaps = verify_project(conn, project_id)
            gaps_truncated = len(gaps) >= _MAX_GAPS

            # T1-10: record count, session count, quarantine_rows
            rc_row = conn.execute(
                "SELECT count(*) FROM audit_records ar "
                "JOIN connectors c ON c.id = ar.connector_id "
                "WHERE c.project_id = %s::uuid",
                [project_id],
            ).fetchone()
            record_count = rc_row[0] if rc_row else 0

            sc_row = conn.execute(
                "SELECT count(DISTINCT (ar.connector_id, ar.session_id)) "
                "FROM audit_records ar "
                "JOIN connectors c ON c.id = ar.connector_id "
                "WHERE c.project_id = %s::uuid",
                [project_id],
            ).fetchone()
            session_count = sc_row[0] if sc_row else 0

            q_rows = list(conn.execute(
                "SELECT aq.id, aq.kind, aq.created_at "
                "FROM audit_quarantine aq "
                "JOIN connectors c ON c.id = aq.connector_id "
                "WHERE c.project_id = %s::uuid "
                "ORDER BY aq.created_at DESC LIMIT 100",
                [project_id],
            ))
            quarantine_rows = [
                {"id": str(q[0]), "kind": q[1],
                 "created_at": q[2].isoformat() if q[2] else None}
                for q in q_rows
            ]

            conn.commit()

        resp: dict[str, Any] = {
            "ok": ok,
            "gaps": gaps,
            "checked": "stored_chains_only",
            "record_count": record_count,
            "session_count": session_count,
            "quarantine_rows": quarantine_rows,
        }
        if gaps_truncated:
            resp["gaps_truncated"] = True
            # T1-18: ok must stay False when gaps were cut off
            resp["ok"] = False
        return JSONResponse(resp)

    # =================================================================
    # GET /audit/export?project=&since=&until=  (T1-4, T1-8, T1-16,
    #     T1-17, T1-20, T1-22, T1-25)
    # =================================================================

    _EXPORT_BYTE_CAP = 10_000_000  # 10 MB
    _EXPORT_ROW_LIMIT = 10_000  # T1-16
    # T1-17: rows per FETCH on the named cursor.  One record body can be
    # about 1 MiB, so the per-request working set is roughly
    # _EXPORT_FETCH_ROWS MiB of result plus the body being built (up to
    # the 10 MB cap).  4 keeps the measured export peak well under the
    # 64 MB target; pinned at most 16 by test_t1_17_fetch_count_pinned.
    _EXPORT_FETCH_ROWS = 4  # literal 'FETCH 4' below so the pin sees it

    def _meta_line_bytes(truncated: bool, row_count: int,
                         byte_count: int) -> bytes:
        """The final ``_meta`` line of a truncated export, as bytes."""
        return (json.dumps(
            {"_meta": {
                "truncated": truncated,
                "row_count": row_count,
                "byte_count": byte_count,
                "byte_cap": _EXPORT_BYTE_CAP,
            }},
            separators=(",", ":"),
        ) + "\n").encode("utf-8")

    # T1-17: the widest ``_meta`` line that can ever be emitted (every
    # counter at its maximum).  Reserved before each row is accepted so
    # the body, ``_meta`` line included, never exceeds the byte cap.
    _META_RESERVE = len(_meta_line_bytes(
        True, _EXPORT_ROW_LIMIT, _EXPORT_BYTE_CAP,
    ))

    @rbac_route(router, "get", "/audit/export",
                role="auditor", scope="project")
    def audit_export(request: Request):
        with _app_conn(conninfo) as conn:
            session, err = _validate(conn, request)
            if err:
                return err
            org_id, user_id, _, _, _ = session

            project_id_raw = request.query_params.get("project", "")
            if not project_id_raw:
                return JSONResponse({"error": "missing_project"}, status_code=400)

            pid = _project_for(conn, project_id_raw, user_id)
            if pid is None:
                return JSONResponse({"error": "not_found"}, status_code=404)
            project_id = str(pid)

            # T1-4/T1-22: project admin, org admin, org auditor, project auditor
            if not _is_project_admin_or_auditor(conn, user_id, pid):
                return JSONResponse({"error": "not_found"}, status_code=404)

            # T1-9/T1-20: bad since/until -> 400, send parsed value
            since = request.query_params.get("since")
            until = request.query_params.get("until")
            since_val = _validate_since(since)
            until_val = _validate_since(until)
            if since_val == "bad":
                conn.commit()
                return JSONResponse({"error": "bad_since"}, status_code=400)
            if until_val == "bad":
                conn.commit()
                return JSONResponse({"error": "bad_until"}, status_code=400)

            params: list[Any] = [project_id]
            clauses = ["c.project_id = %s::uuid"]

            if since_val:
                clauses.append("ar.created_at >= %s")
                params.append(since_val)
            if until_val:
                clauses.append("ar.created_at <= %s")
                params.append(until_val)

            where = " AND ".join(clauses)

            # T1-17: read through a named server-side cursor,
            # _EXPORT_FETCH_ROWS rows per FETCH, one row alive at a
            # time, bounded by the byte cap and row limit.  The body
            # is built once, as bytes, in one buffer allocated at the
            # cap up front: no list of lines, no str join, no second
            # encode, and no reallocation copy while it grows.  The
            # _meta line's bytes are reserved before every row.  No
            # StreamingResponse; plain Response with Content-Length.
            # conn.transaction() ensures DECLARE works on both
            # autocommit and non-autocommit connections (savepoint
            # when a transaction is already open).
            buf = bytearray(_EXPORT_BYTE_CAP)
            byte_count = 0
            row_count = 0
            truncated = False
            budget = _EXPORT_BYTE_CAP - _META_RESERVE

            with conn.transaction():
                cursor_name = f"export_{uuid.uuid4().hex[:8]}"
                conn.execute(
                    f"DECLARE {cursor_name} CURSOR FOR "
                    "SELECT ar.connector_id, ar.session_id, ar.chain_length, "
                    "ar.previous_hash, ar.record_hash, ar.body, ar.created_at "
                    "FROM audit_records ar "
                    "JOIN connectors c ON c.id = ar.connector_id "
                    f"WHERE {where} "
                    "ORDER BY ar.connector_id, ar.session_id, "
                    "ar.chain_length ASC",
                    params,
                )

                while True:
                    # Iterate the FETCH result directly: psycopg builds
                    # each row (and parses its json body) only when the
                    # row is reached, so one body is alive at a time
                    # on the Python side (T1-17).
                    fetch_cur = conn.execute(
                        f"FETCH 4 FROM {cursor_name}"
                    )
                    if fetch_cur.rowcount == 0:
                        fetch_cur.close()
                        break
                    for r in fetch_cur:
                        if row_count >= _EXPORT_ROW_LIMIT:
                            truncated = True
                            break
                        body_val = r[5]
                        if isinstance(body_val, str):
                            try:
                                body_val = json.loads(body_val)
                            except (ValueError, TypeError):
                                body_val = None
                        record = {
                            "connector_id": str(r[0]),
                            "session_id": r[1],
                            "chain_length": r[2],
                            "previous_hash": r[3],
                            "record_hash": r[4],
                            "body": body_val,
                            "created_at": r[6].isoformat() if r[6] else None,
                        }
                        line = (json.dumps(
                            record, separators=(",", ":"), sort_keys=True,
                            ensure_ascii=True,
                        ) + "\n").encode("utf-8")
                        record = None
                        body_val = None

                        if byte_count + len(line) > budget:
                            truncated = True
                            break

                        buf[byte_count:byte_count + len(line)] = line
                        byte_count += len(line)
                        row_count += 1
                        line = None

                    # Release this batch before the next FETCH so two
                    # batches are never alive at once (T1-17).
                    r = None
                    fetch_cur.close()
                    fetch_cur = None

                    if truncated:
                        break

                conn.execute(f"CLOSE {cursor_name}")

            # T1-17 SHOULD: emit final line with truncated, row
            # and byte counts when the export is truncated.  Its
            # bytes were reserved above, so the body stays at or
            # under the cap.
            body_len = byte_count
            if truncated:
                meta_line = _meta_line_bytes(truncated, row_count, byte_count)
                buf[body_len:body_len + len(meta_line)] = meta_line
                body_len += len(meta_line)

            conn.commit()

        # No copy: the response reads the buffer through a memoryview
        # slice (Starlette's Response.render passes bytes and memoryview
        # through untouched), so the body exists once (T1-17).
        content_bytes = memoryview(buf)[:body_len]

        # T1-17: plain Response with Content-Length (not StreamingResponse)
        return Response(
            content=content_bytes,
            media_type="application/x-ndjson",
            headers={
                "Cache-Control": "no-store",
                "Content-Disposition": (
                    f'attachment; filename="audit-export-{str(pid)[:8]}.jsonl"'
                ),
                "X-Export-Truncated": "true" if truncated else "false",
                "X-Export-Byte-Cap": str(_EXPORT_BYTE_CAP),
                "Content-Length": str(len(content_bytes)),
            },
        )

    return router


# ---------------------------------------------------------------------------
# Helpers (module-level, stateless)
# ---------------------------------------------------------------------------

_DIFF_SECTIONS = (
    "folder_policy", "governance_policy", "mcp_policy",
    "approval", "environment",
)


def _compute_section_diff(
    conn, project_id: str, current_seq: int, current_payload: dict,
) -> tuple[dict, int | None, bool]:
    """Compute per-section diff between the current bundle and its predecessor.

    T1-9: uses the highest lower sequence (not ``sequence - 1``, which
    may skip).  Returns ``(diff, base_sequence, diff_base_corrupt)``
    where ``base_sequence`` is the sequence compared against (or None
    for the first), and ``diff_base_corrupt`` is True when the
    predecessor blob could not be parsed (T1-21).
    """
    diff: dict[str, Any] = {}
    base_seq: int | None = None
    diff_base_corrupt = False

    # T1-9: find the highest sequence strictly below current_seq
    prev_row = conn.execute(
        "SELECT sequence, bundle_blob FROM policy_bundles "
        "WHERE project_id = %s::uuid AND sequence < %s "
        "ORDER BY sequence DESC LIMIT 1",
        [project_id, current_seq],
    ).fetchone()

    prev_payload: dict = {}
    if prev_row:
        base_seq = prev_row[0]
        blob = prev_row[1]
        envelope, corrupt = _parse_bundle_blob(blob)
        if corrupt or envelope is None:
            diff_base_corrupt = True
        else:
            p = envelope.get("payload", {})
            if isinstance(p, dict):
                prev_payload = p
            else:
                diff_base_corrupt = True

    for section in _DIFF_SECTIONS:
        old_val = prev_payload.get(section)
        new_val = current_payload.get(section)
        changed = old_val != new_val
        entry: dict[str, Any] = {"changed": changed}
        if changed:
            entry["old"] = old_val
            entry["new"] = new_val
        diff[section] = entry

    return diff, base_seq, diff_base_corrupt
