"""T9 API routes: /me, projects, org users/members, audit verify.

Routes are registered via :func:`rbac_route` so every ``/api`` route
declares ``x-agg-rbac``.  All dependencies (db_url, clock) are closed
over by :func:`build_api_router`; no module-level mutable state.

Session/CSRF validation reuses the invariants from :mod:`agg_cp.auth`
(cookie format, sha256 token hash, hmac.compare_digest, idle/expiry).
Every DB access as ``agg_app`` via :func:`_app_conn` with
``app.org_id`` set transaction-locally.
"""
from __future__ import annotations

import hmac as _hmac
import json as _json
import uuid
from typing import Literal

import psycopg

from fastapi import APIRouter, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from agg_cp.auth import (
    _app_conn,
    _sha256_hex,
    _sync_conninfo,
    csrf_token_for,
    validate_session,
)
from agg_cp.clock import Clock
from agg_cp.rbac import rbac_route


# ---------------------------------------------------------------------------
# Pydantic request models (extra="forbid" rejects unknown fields -> 422)
# ---------------------------------------------------------------------------


class CreateProjectBody(BaseModel):
    model_config = {"extra": "forbid"}

    name: str
    environment: Literal["dev", "staging", "prod"]


class AddMemberBody(BaseModel):
    model_config = {"extra": "forbid"}

    user_id: str
    role: Literal["admin", "policy_author", "approver", "auditor", "viewer"]


class AddOrgUserBody(BaseModel):
    model_config = {"extra": "forbid"}

    oidc_subject: str
    email: str


class AddOrgMemberBody(BaseModel):
    model_config = {"extra": "forbid"}

    user_id: str
    role: Literal["admin", "policy_author", "approver", "auditor", "viewer"]


# ---------------------------------------------------------------------------
# Route factory
# ---------------------------------------------------------------------------


def build_api_router(*, db_url: str, clock: Clock) -> APIRouter:
    """Build and return the /api/v1 router for T9 routes.

    All dependencies are closed over; no module-level mutable state.
    """
    conninfo = _sync_conninfo(db_url)
    router = APIRouter(prefix="/api/v1")

    # -------------------------------------------------------------------
    # Session / CSRF helpers (closed over conninfo, clock)
    # -------------------------------------------------------------------

    def _validate_session(conn, request):
        """Validate session cookie on *conn*.

        Delegates to :func:`validate_session` (auth.py).
        Returns ``((org_id, user_id, session_id, session_token,
        csrf_hash), None)`` on success or ``(None, error_response)``
        on failure.
        """
        return validate_session(conn, request, clock)

    def _check_csrf(request, stored_csrf_hash):
        """Validate X-CSRF-Token header (constant-time compare).

        Returns an error Response or ``None``.
        """
        csrf_header = request.headers.get("x-csrf-token")
        if not csrf_header:
            return JSONResponse({"error": "csrf_missing"}, status_code=403)

        provided_hash = _sha256_hex(csrf_header)
        if not _hmac.compare_digest(stored_csrf_hash, provided_hash):
            return JSONResponse({"error": "csrf_invalid"}, status_code=403)

        return None

    # -------------------------------------------------------------------
    # RBAC helpers
    # -------------------------------------------------------------------

    def _can_read_project(conn, user_id, project_id):
        row = conn.execute(
            "SELECT 1 FROM role_bindings WHERE user_id = %s AND ("
            "(scope_type = 'org' AND role IN "
            "('admin','viewer','policy_author','approver'))"
            " OR "
            "(scope_type = 'project' AND scope_id = %s AND role IN "
            "('admin','viewer','policy_author','approver'))"
            ") LIMIT 1",
            [user_id, project_id],
        ).fetchone()
        return row is not None

    def _is_org_admin(conn, user_id):
        row = conn.execute(
            "SELECT 1 FROM role_bindings "
            "WHERE user_id = %s AND scope_type = 'org' AND role = 'admin' "
            "LIMIT 1",
            [user_id],
        ).fetchone()
        return row is not None

    def _is_project_admin(conn, user_id, project_id):
        """True if caller is org admin OR project-scope admin."""
        row = conn.execute(
            "SELECT 1 FROM role_bindings WHERE user_id = %s AND ("
            "(scope_type = 'org' AND role = 'admin')"
            " OR "
            "(scope_type = 'project' AND scope_id = %s AND role = 'admin')"
            ") LIMIT 1",
            [user_id, project_id],
        ).fetchone()
        return row is not None

    def _is_org_auditor_or_admin(conn, user_id):
        row = conn.execute(
            "SELECT 1 FROM role_bindings "
            "WHERE user_id = %s AND scope_type = 'org' "
            "AND role IN ('admin', 'auditor') LIMIT 1",
            [user_id],
        ).fetchone()
        return row is not None

    def _get_project(conn, project_id_str):
        """Get project row if it exists in the caller's org (RLS)."""
        try:
            pid = uuid.UUID(str(project_id_str))
        except ValueError:
            return None
        return conn.execute(
            "SELECT id, name, environment, created_at "
            "FROM projects WHERE id = %s",
            [pid],
        ).fetchone()

    # ===================================================================
    # GET /me
    # ===================================================================

    @rbac_route(router, "get", "/me", role="session", scope="session")
    def get_me(request: Request):
        with _app_conn(conninfo) as conn:
            session, err = _validate_session(conn, request)
            if err:
                return err
            org_id, user_id, _, session_token, _ = session

            user_row = conn.execute(
                "SELECT email FROM users WHERE id = %s", [user_id],
            ).fetchone()
            display_name = user_row[0] if user_row else ""

            org_row = conn.execute(
                "SELECT id, slug, name FROM orgs WHERE id = %s", [org_id],
            ).fetchone()

            roles = []
            for rb in conn.execute(
                "SELECT role, scope_type, scope_id "
                "FROM role_bindings WHERE user_id = %s",
                [user_id],
            ).fetchall():
                roles.append({
                    "role": rb[0],
                    "scope_type": rb[1],
                    "scope_id": str(rb[2]),
                })

            csrf_token = csrf_token_for(session_token)
            conn.commit()

        return JSONResponse({
            "user_id": str(user_id),
            "display_name": display_name,
            "org": {
                "id": str(org_row[0]),
                "slug": org_row[1],
                "name": org_row[2],
            } if org_row else {},
            "roles": roles,
            "csrf_token": csrf_token,
        })

    # ===================================================================
    # GET /projects
    # ===================================================================

    @rbac_route(router, "get", "/projects", role="session", scope="session")
    def list_projects(request: Request):
        with _app_conn(conninfo) as conn:
            session, err = _validate_session(conn, request)
            if err:
                return err
            _, user_id, _, _, _ = session

            projects = conn.execute(
                "SELECT p.id, p.name, p.environment, p.created_at "
                "FROM projects p "
                "WHERE EXISTS ("
                "  SELECT 1 FROM role_bindings rb "
                "  WHERE rb.user_id = %s AND ("
                "    (rb.scope_type = 'org' AND rb.role IN "
                "     ('admin','viewer','policy_author','approver'))"
                "    OR "
                "    (rb.scope_type = 'project' AND rb.scope_id = p.id "
                "     AND rb.role IN "
                "     ('admin','viewer','policy_author','approver'))"
                "  )"
                ")",
                [user_id],
            ).fetchall()

            conn.commit()

        return JSONResponse([
            {
                "id": str(p[0]),
                "name": p[1],
                "environment": p[2],
                "created_at": p[3].isoformat() if p[3] else None,
            }
            for p in projects
        ])

    # ===================================================================
    # POST /projects
    # ===================================================================

    @rbac_route(router, "post", "/projects",
                role="admin", scope="org", status_code=201)
    def create_project(request: Request, body: CreateProjectBody):
        with _app_conn(conninfo) as conn:
            session, err = _validate_session(conn, request)
            if err:
                return err
            org_id, user_id, _, _, csrf_hash = session

            csrf_err = _check_csrf(request, csrf_hash)
            if csrf_err:
                return csrf_err

            if not _is_org_admin(conn, user_id):
                return JSONResponse(
                    {"error": "forbidden"}, status_code=403,
                )

            project_id = uuid.uuid4()
            now = clock.now()
            conn.execute(
                "INSERT INTO projects "
                "(id, org_id, name, environment, created_at) "
                "VALUES (%s, %s, %s, %s, %s)",
                [project_id, org_id, body.name, body.environment, now],
            )
            conn.execute(
                "INSERT INTO admin_audit (id, org_id, action, detail) "
                "VALUES (%s, %s, 'project_created', %s)",
                [uuid.uuid4(), org_id,
                 _json.dumps({
                     "project_id": str(project_id),
                     "name": body.name,
                     "environment": body.environment,
                 })],
            )
            conn.commit()

        return JSONResponse(
            {
                "id": str(project_id),
                "name": body.name,
                "environment": body.environment,
            },
            status_code=201,
        )

    # ===================================================================
    # GET /projects/{id}
    # ===================================================================

    @rbac_route(router, "get", "/projects/{id}",
                role="viewer", scope="project")
    def get_project(request: Request, id: str):
        with _app_conn(conninfo) as conn:
            session, err = _validate_session(conn, request)
            if err:
                return err
            _, user_id, _, _, _ = session

            project = _get_project(conn, id)
            if project is None:
                return JSONResponse(
                    {"error": "not_found"}, status_code=404,
                )

            if not _can_read_project(conn, user_id, project[0]):
                return JSONResponse(
                    {"error": "not_found"}, status_code=404,
                )

            conn.commit()

        return JSONResponse({
            "id": str(project[0]),
            "name": project[1],
            "environment": project[2],
            "created_at": project[3].isoformat() if project[3] else None,
        })

    # ===================================================================
    # GET /projects/{id}/members
    # ===================================================================

    @rbac_route(router, "get", "/projects/{id}/members",
                role="viewer", scope="project")
    def get_project_members(request: Request, id: str):
        with _app_conn(conninfo) as conn:
            session, err = _validate_session(conn, request)
            if err:
                return err
            _, user_id, _, _, _ = session

            project = _get_project(conn, id)
            if project is None:
                return JSONResponse(
                    {"error": "not_found"}, status_code=404,
                )
            project_id = project[0]

            if not _can_read_project(conn, user_id, project_id):
                return JSONResponse(
                    {"error": "not_found"}, status_code=404,
                )

            members = conn.execute(
                "SELECT u.id, u.email, rb.role "
                "FROM role_bindings rb "
                "JOIN users u ON u.id = rb.user_id "
                "WHERE rb.scope_type = 'project' AND rb.scope_id = %s",
                [project_id],
            ).fetchall()

            conn.commit()

        return JSONResponse([
            {
                "user_id": str(m[0]),
                "display_name": m[1],
                "role": m[2],
            }
            for m in members
        ])

    # ===================================================================
    # POST /projects/{id}/members
    # ===================================================================

    @rbac_route(router, "post", "/projects/{id}/members",
                role="admin", scope="project", status_code=201)
    def add_project_member(request: Request, id: str, body: AddMemberBody):
        with _app_conn(conninfo) as conn:
            session, err = _validate_session(conn, request)
            if err:
                return err
            org_id, user_id, _, _, csrf_hash = session

            csrf_err = _check_csrf(request, csrf_hash)
            if csrf_err:
                return csrf_err

            project = _get_project(conn, id)
            if project is None:
                return JSONResponse(
                    {"error": "not_found"}, status_code=404,
                )
            project_id = project[0]

            if not _can_read_project(conn, user_id, project_id):
                return JSONResponse(
                    {"error": "not_found"}, status_code=404,
                )

            if not _is_project_admin(conn, user_id, project_id):
                return JSONResponse(
                    {"error": "forbidden"}, status_code=403,
                )

            try:
                target_uid = uuid.UUID(body.user_id)
            except ValueError:
                return JSONResponse(
                    {"error": "invalid_user_id"}, status_code=422,
                )

            # Target user must exist in the org (RLS)
            if conn.execute(
                "SELECT 1 FROM users WHERE id = %s", [target_uid],
            ).fetchone() is None:
                return JSONResponse(
                    {"error": "user_not_found"}, status_code=404,
                )

            binding_id = uuid.uuid4()
            now = clock.now()
            conn.execute(
                "INSERT INTO role_bindings "
                "(id, org_id, user_id, scope_type, scope_id, role, "
                "created_at) "
                "VALUES (%s, %s, %s, 'project', %s, %s, %s) "
                "ON CONFLICT (org_id, user_id, scope_type, scope_id, role) "
                "DO NOTHING",
                [binding_id, org_id, target_uid,
                 project_id, body.role, now],
            )
            conn.execute(
                "INSERT INTO admin_audit (id, org_id, action, detail) "
                "VALUES (%s, %s, 'role_granted', %s)",
                [uuid.uuid4(), org_id,
                 _json.dumps({
                     "user_id": str(target_uid),
                     "project_id": str(project_id),
                     "role": body.role,
                     "scope_type": "project",
                 })],
            )
            conn.commit()

        return JSONResponse({"id": str(binding_id)}, status_code=201)

    # ===================================================================
    # DELETE /projects/{id}/members/{user_id}/{role}
    # ===================================================================

    @rbac_route(
        router, "delete",
        "/projects/{id}/members/{user_id}/{role}",
        role="admin", scope="project",
    )
    def delete_project_member(
        request: Request, id: str, user_id: str, role: str,
    ):
        with _app_conn(conninfo) as conn:
            session, err = _validate_session(conn, request)
            if err:
                return err
            org_id, caller_id, _, _, csrf_hash = session

            csrf_err = _check_csrf(request, csrf_hash)
            if csrf_err:
                return csrf_err

            project = _get_project(conn, id)
            if project is None:
                return JSONResponse(
                    {"error": "not_found"}, status_code=404,
                )
            project_id = project[0]

            if not _can_read_project(conn, caller_id, project_id):
                return JSONResponse(
                    {"error": "not_found"}, status_code=404,
                )
            if not _is_project_admin(conn, caller_id, project_id):
                return JSONResponse(
                    {"error": "forbidden"}, status_code=403,
                )

            try:
                target_uid = uuid.UUID(user_id)
            except ValueError:
                return JSONResponse(
                    {"error": "not_found"}, status_code=404,
                )

            valid_roles = (
                "admin", "policy_author", "approver",
                "auditor", "viewer",
            )
            if role not in valid_roles:
                return JSONResponse(
                    {"error": "not_found"}, status_code=404,
                )

            deleted = conn.execute(
                "DELETE FROM role_bindings "
                "WHERE scope_type = 'project' AND scope_id = %s "
                "AND user_id = %s AND role = %s "
                "RETURNING id",
                [project_id, target_uid, role],
            ).fetchone()

            if deleted:
                conn.execute(
                    "INSERT INTO admin_audit "
                    "(id, org_id, action, detail) "
                    "VALUES (%s, %s, 'role_revoked', %s)",
                    [uuid.uuid4(), org_id,
                     _json.dumps({
                         "user_id": str(target_uid),
                         "project_id": str(project_id),
                         "role": role,
                         "scope_type": "project",
                     })],
                )

            conn.commit()

        return Response(status_code=204)

    # ===================================================================
    # GET /org/users
    # ===================================================================

    @rbac_route(router, "get", "/org/users", role="admin", scope="org")
    def get_org_users(request: Request):
        with _app_conn(conninfo) as conn:
            session, err = _validate_session(conn, request)
            if err:
                return err
            _, user_id, _, _, _ = session

            if not _is_org_admin(conn, user_id):
                return JSONResponse(
                    {"error": "not_found"}, status_code=404,
                )

            users = conn.execute(
                "SELECT id, email, status, created_at FROM users",
            ).fetchall()

            conn.commit()

        return JSONResponse([
            {
                "id": str(u[0]),
                "email": u[1],
                "status": u[2],
                "created_at": u[3].isoformat() if u[3] else None,
            }
            for u in users
        ])

    # ===================================================================
    # POST /org/users
    # ===================================================================

    @rbac_route(router, "post", "/org/users",
                role="admin", scope="org", status_code=201)
    def add_org_user(request: Request, body: AddOrgUserBody):
        with _app_conn(conninfo) as conn:
            session, err = _validate_session(conn, request)
            if err:
                return err
            org_id, user_id, _, _, csrf_hash = session

            csrf_err = _check_csrf(request, csrf_hash)
            if csrf_err:
                return csrf_err

            if not _is_org_admin(conn, user_id):
                return JSONResponse(
                    {"error": "not_found"}, status_code=404,
                )

            # Resolve the org's configured OIDC issuer
            issuer_row = conn.execute(
                "SELECT issuer FROM org_oidc_config LIMIT 1",
            ).fetchone()
            if not issuer_row:
                return JSONResponse(
                    {"error": "oidc_not_configured"}, status_code=500,
                )
            issuer = issuer_row[0]

            new_user_id = uuid.uuid4()
            now = clock.now()
            try:
                conn.execute(
                    "INSERT INTO users "
                    "(id, org_id, oidc_issuer, oidc_subject, email, "
                    "status, created_at) "
                    "VALUES (%s, %s, %s, %s, %s, 'active', %s)",
                    [new_user_id, org_id, issuer,
                     body.oidc_subject, body.email, now],
                )
            except psycopg.errors.UniqueViolation:
                conn.rollback()
                return JSONResponse(
                    {"error": "identity_in_use"}, status_code=409,
                )

            conn.execute(
                "INSERT INTO admin_audit (id, org_id, action, detail) "
                "VALUES (%s, %s, 'user_added', %s)",
                [uuid.uuid4(), org_id,
                 _json.dumps({
                     "user_id": str(new_user_id),
                     "email": body.email,
                 })],
            )
            conn.commit()

        return JSONResponse(
            {"id": str(new_user_id), "email": body.email},
            status_code=201,
        )

    # ===================================================================
    # POST /org/members
    # ===================================================================

    @rbac_route(router, "post", "/org/members",
                role="admin", scope="org", status_code=201)
    def add_org_member(request: Request, body: AddOrgMemberBody):
        with _app_conn(conninfo) as conn:
            session, err = _validate_session(conn, request)
            if err:
                return err
            org_id, user_id, _, _, csrf_hash = session

            csrf_err = _check_csrf(request, csrf_hash)
            if csrf_err:
                return csrf_err

            if not _is_org_admin(conn, user_id):
                return JSONResponse(
                    {"error": "not_found"}, status_code=404,
                )

            try:
                target_uid = uuid.UUID(body.user_id)
            except ValueError:
                return JSONResponse(
                    {"error": "invalid_user_id"}, status_code=422,
                )

            if conn.execute(
                "SELECT 1 FROM users WHERE id = %s", [target_uid],
            ).fetchone() is None:
                return JSONResponse(
                    {"error": "user_not_found"}, status_code=404,
                )

            binding_id = uuid.uuid4()
            now = clock.now()
            conn.execute(
                "INSERT INTO role_bindings "
                "(id, org_id, user_id, scope_type, scope_id, role, "
                "created_at) "
                "VALUES (%s, %s, %s, 'org', %s, %s, %s) "
                "ON CONFLICT (org_id, user_id, scope_type, scope_id, role) "
                "DO NOTHING",
                [binding_id, org_id, target_uid, org_id, body.role, now],
            )
            conn.execute(
                "INSERT INTO admin_audit (id, org_id, action, detail) "
                "VALUES (%s, %s, 'role_granted', %s)",
                [uuid.uuid4(), org_id,
                 _json.dumps({
                     "user_id": str(target_uid),
                     "role": body.role,
                     "scope_type": "org",
                 })],
            )
            conn.commit()

        return JSONResponse({"id": str(binding_id)}, status_code=201)

    # ===================================================================
    # DELETE /org/members/{user_id}/{role}
    # ===================================================================

    @rbac_route(
        router, "delete",
        "/org/members/{user_id}/{role}",
        role="admin", scope="org",
    )
    def delete_org_member(
        request: Request, user_id: str, role: str,
    ):
        with _app_conn(conninfo) as conn:
            session, err = _validate_session(conn, request)
            if err:
                return err
            org_id, caller_id, _, _, csrf_hash = session

            csrf_err = _check_csrf(request, csrf_hash)
            if csrf_err:
                return csrf_err

            try:
                target_uid = uuid.UUID(user_id)
            except ValueError:
                return JSONResponse(
                    {"error": "not_found"}, status_code=404,
                )

            valid_roles = (
                "admin", "policy_author", "approver",
                "auditor", "viewer",
            )
            if role not in valid_roles:
                return JSONResponse(
                    {"error": "not_found"}, status_code=404,
                )

            # Per-org advisory lock serialises admin-role mutations so
            # the RBAC + count reads see committed state.
            if role == "admin":
                conn.execute(
                    "SELECT pg_advisory_xact_lock("
                    "hashtext('agg-admin:' || %s::text))",
                    [str(org_id)],
                )

            # RBAC: caller must be org admin (fresh read under lock).
            if not _is_org_admin(conn, caller_id):
                return JSONResponse(
                    {"error": "not_found"}, status_code=404,
                )

            # Last-admin protection (under advisory lock).
            if role == "admin":
                admin_count = conn.execute(
                    "SELECT count(*) FROM role_bindings "
                    "WHERE scope_type = 'org' AND role = 'admin'",
                ).fetchone()[0]
                if admin_count <= 1:
                    target_is_org_admin = conn.execute(
                        "SELECT 1 FROM role_bindings "
                        "WHERE user_id = %s AND scope_type = 'org' "
                        "AND role = 'admin'",
                        [target_uid],
                    ).fetchone()
                    if target_is_org_admin:
                        conn.commit()
                        return JSONResponse(
                            {"error": "last_admin"}, status_code=409,
                        )

            deleted = conn.execute(
                "DELETE FROM role_bindings "
                "WHERE scope_type = 'org' AND scope_id = %s "
                "AND user_id = %s AND role = %s "
                "RETURNING id",
                [org_id, target_uid, role],
            ).fetchone()

            if deleted:
                conn.execute(
                    "INSERT INTO admin_audit "
                    "(id, org_id, action, detail) "
                    "VALUES (%s, %s, 'role_revoked', %s)",
                    [uuid.uuid4(), org_id,
                     _json.dumps({
                         "user_id": str(target_uid),
                         "role": role,
                         "scope_type": "org",
                     })],
                )

            conn.commit()

        return Response(status_code=204)

    # ===================================================================
    # GET /org/audit/verify
    # ===================================================================

    @rbac_route(router, "get", "/org/audit/verify",
                role="auditor", scope="org")
    def audit_verify(request: Request):
        with _app_conn(conninfo) as conn:
            session, err = _validate_session(conn, request)
            if err:
                return err
            org_id, user_id, _, _, _ = session

            if not _is_org_auditor_or_admin(conn, user_id):
                return JSONResponse(
                    {"error": "not_found"}, status_code=404,
                )

            from agg_cp.audit import verify_chain

            ok, reason = verify_chain(conn, org_id)
            conn.commit()

        return JSONResponse({"ok": ok, "reason": reason})

    return router
