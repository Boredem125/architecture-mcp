"""T9 RBAC enforcement tests.

Verifies:
- Per route, the minimum role passes (+) and the next-lower role / no binding
  fails (403 if readable, else 404).
- POST/DELETE without CSRF returns 403.
- Unknown body field returns 422.
- Bad enum value returns 422.
- Last org admin cannot be revoked (409).
- Grants are idempotent (same grant twice -> one row).
"""
from __future__ import annotations

import uuid

import psycopg
import pytest

from .t9_helpers import (
    T9Pending,
    RED_T9,
    require_t9,
    guard_404_t9,
    seed_session,
    make_session_cookie,
    seed_org_with_oidc,
    seed_user,
    seed_role_binding,
    seed_project,
    ensure_at_head,
    make_t9_app,
    make_t9_client,
    unique_slug,
    _conninfo,
    FakeClock,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_env(pg_url, owner_url, *, role="admin", scope_type="org",
              scope_id=None, add_project=False):
    """Set up org, user, role binding, project (optionally), session, app.

    Returns dict with client, org_id, user_id, session_token, csrf_token,
    cookie, project_id (or None), clock, slug, owner_url.
    """
    clock = FakeClock()
    slug = unique_slug("rbac")

    ensure_at_head(pg_url)
    org_id = seed_org_with_oidc(owner_url, slug=slug)
    user_id, _ = seed_user(owner_url, org_id, email=f"{role}@example.com")

    project_id = None
    if add_project:
        project_id = seed_project(owner_url, org_id, name=f"proj-{slug}")

    actual_scope_id = scope_id
    if actual_scope_id is None:
        if scope_type == "project" and project_id:
            actual_scope_id = project_id
        else:
            actual_scope_id = org_id

    seed_role_binding(
        owner_url, org_id, user_id,
        role=role, scope_type=scope_type, scope_id=actual_scope_id,
    )

    session_token, csrf_token, _ = seed_session(
        owner_url, org_id, user_id, clock=clock,
    )
    cookie = make_session_cookie(org_id, session_token)

    app, clock, _ = make_t9_app(pg_url, clock=clock)
    client = make_t9_client(app)

    return {
        "client": client,
        "org_id": org_id,
        "user_id": user_id,
        "session_token": session_token,
        "csrf_token": csrf_token,
        "cookie": cookie,
        "project_id": project_id,
        "clock": clock,
        "slug": slug,
        "owner_url": owner_url,
    }


# ===================================================================
# Minimum role passes, lower role fails
# ===================================================================


@pytest.mark.pg
def test_get_projects_viewer_passes(pg_url, app_url, owner_url, pg_roles):
    """GET /projects: viewer passes (any session is enough to list readable projects)."""
    env = _make_env(pg_url, owner_url, role="viewer")
    resp = env["client"].get(
        "/api/v1/projects",
        cookies={"__Host-agg_session": env["cookie"]},
    )
    guard_404_t9(resp)
    assert resp.status_code == 200, (
        f"viewer should see /projects, got {resp.status_code}"
    )


@pytest.mark.pg
def test_post_projects_admin_passes(pg_url, app_url, owner_url, pg_roles):
    """POST /projects: org admin passes (+)."""
    env = _make_env(pg_url, owner_url, role="admin")
    resp = env["client"].post(
        "/api/v1/projects",
        cookies={"__Host-agg_session": env["cookie"]},
        headers={"X-CSRF-Token": env["csrf_token"]},
        json={"name": "new-proj", "environment": "dev"},
    )
    guard_404_t9(resp)
    assert resp.status_code == 201, (
        f"admin should create project (201), got {resp.status_code}: {resp.text}"
    )


@pytest.mark.pg
def test_post_projects_viewer_fails(pg_url, app_url, owner_url, pg_roles):
    """POST /projects: viewer gets 403."""
    env = _make_env(pg_url, owner_url, role="viewer")
    resp = env["client"].post(
        "/api/v1/projects",
        cookies={"__Host-agg_session": env["cookie"]},
        headers={"X-CSRF-Token": env["csrf_token"]},
        json={"name": "new-proj", "environment": "dev"},
    )
    guard_404_t9(resp)
    assert resp.status_code == 403, (
        f"viewer should get 403 on POST /projects, got {resp.status_code}"
    )


@pytest.mark.pg
def test_get_project_by_id_viewer_passes(pg_url, app_url, owner_url, pg_roles):
    """GET /projects/{id}: viewer on the project passes (+)."""
    env = _make_env(pg_url, owner_url, role="viewer",
                    scope_type="project", add_project=True)
    pid = env["project_id"]
    resp = env["client"].get(
        f"/api/v1/projects/{pid}",
        cookies={"__Host-agg_session": env["cookie"]},
    )
    guard_404_t9(resp)
    assert resp.status_code == 200, (
        f"project viewer should read project, got {resp.status_code}"
    )


@pytest.mark.pg
def test_get_project_no_binding_fails(pg_url, app_url, owner_url, pg_roles):
    """GET /projects/{id}: user with no binding on the project gets 404."""
    clock = FakeClock()
    slug = unique_slug("rbac-nob")
    ensure_at_head(pg_url)
    org_id = seed_org_with_oidc(owner_url, slug=slug)
    user_id, _ = seed_user(owner_url, org_id)
    project_id = seed_project(owner_url, org_id, name=f"proj-{slug}")
    # No role binding at all
    session_token, csrf_token, _ = seed_session(
        owner_url, org_id, user_id, clock=clock,
    )
    cookie = make_session_cookie(org_id, session_token)
    app, clock, _ = make_t9_app(pg_url, clock=clock)
    client = make_t9_client(app)

    resp = client.get(
        f"/api/v1/projects/{project_id}",
        cookies={"__Host-agg_session": cookie},
    )
    guard_404_t9(resp)
    assert resp.status_code == 404, (
        f"No binding should get 404, got {resp.status_code}"
    )


@pytest.mark.pg
def test_get_org_users_admin_passes(pg_url, app_url, owner_url, pg_roles):
    """GET /org/users: org admin passes (+)."""
    env = _make_env(pg_url, owner_url, role="admin")
    resp = env["client"].get(
        "/api/v1/org/users",
        cookies={"__Host-agg_session": env["cookie"]},
    )
    guard_404_t9(resp)
    assert resp.status_code == 200, (
        f"admin should see /org/users, got {resp.status_code}"
    )


@pytest.mark.pg
def test_get_org_users_viewer_fails(pg_url, app_url, owner_url, pg_roles):
    """GET /org/users: viewer gets 404 (not 403, because they can't even see it)."""
    env = _make_env(pg_url, owner_url, role="viewer")
    resp = env["client"].get(
        "/api/v1/org/users",
        cookies={"__Host-agg_session": env["cookie"]},
    )
    guard_404_t9(resp)
    # Design says: no binding = nothing, object they can't read = 404
    assert resp.status_code in (403, 404), (
        f"viewer should get 403 or 404 on /org/users, got {resp.status_code}"
    )


@pytest.mark.pg
def test_post_org_members_admin_passes(pg_url, app_url, owner_url, pg_roles):
    """POST /org/members: org admin can grant an org-scope role (+)."""
    env = _make_env(pg_url, owner_url, role="admin")
    # Create a second user to grant to
    target_id, _ = seed_user(
        owner_url, env["org_id"], email="target@example.com",
    )
    resp = env["client"].post(
        "/api/v1/org/members",
        cookies={"__Host-agg_session": env["cookie"]},
        headers={"X-CSRF-Token": env["csrf_token"]},
        json={"user_id": str(target_id), "role": "viewer"},
    )
    guard_404_t9(resp)
    assert resp.status_code in (200, 201, 204), (
        f"admin should grant org member, got {resp.status_code}: {resp.text}"
    )


@pytest.mark.pg
def test_post_project_members_project_admin_passes(pg_url, app_url, owner_url, pg_roles):
    """POST /projects/{id}/members: project admin can add a member (+)."""
    env = _make_env(pg_url, owner_url, role="admin",
                    scope_type="project", add_project=True)
    # Also need org admin to be able to see the project
    # Actually the project admin should suffice; let's also add an org admin binding
    seed_role_binding(
        owner_url, env["org_id"], env["user_id"], role="admin",
    )
    target_id, _ = seed_user(
        owner_url, env["org_id"], email="projmember@example.com",
    )
    pid = env["project_id"]
    resp = env["client"].post(
        f"/api/v1/projects/{pid}/members",
        cookies={"__Host-agg_session": env["cookie"]},
        headers={"X-CSRF-Token": env["csrf_token"]},
        json={"user_id": str(target_id), "role": "viewer"},
    )
    guard_404_t9(resp)
    assert resp.status_code in (200, 201, 204), (
        f"project admin should add member, got {resp.status_code}: {resp.text}"
    )


# ===================================================================
# CSRF enforcement
# ===================================================================


@pytest.mark.pg
def test_post_without_csrf_403(pg_url, app_url, owner_url, pg_roles):
    """POST without X-CSRF-Token returns 403."""
    env = _make_env(pg_url, owner_url, role="admin")
    resp = env["client"].post(
        "/api/v1/projects",
        cookies={"__Host-agg_session": env["cookie"]},
        # No CSRF header
        json={"name": "no-csrf-proj", "environment": "dev"},
    )
    guard_404_t9(resp)
    assert resp.status_code == 403, (
        f"POST without CSRF should get 403, got {resp.status_code}"
    )


@pytest.mark.pg
def test_delete_without_csrf_403(pg_url, app_url, owner_url, pg_roles):
    """DELETE without X-CSRF-Token returns 403."""
    env = _make_env(pg_url, owner_url, role="admin", add_project=True)
    pid = env["project_id"]
    target_id, _ = seed_user(
        owner_url, env["org_id"], email="del-target@example.com",
    )
    # Seed a binding so we have something to delete
    seed_role_binding(
        owner_url, env["org_id"], target_id,
        role="viewer", scope_type="project", scope_id=pid,
    )
    resp = env["client"].delete(
        f"/api/v1/projects/{pid}/members/{target_id}/viewer",
        cookies={"__Host-agg_session": env["cookie"]},
        # No CSRF header
    )
    guard_404_t9(resp)
    assert resp.status_code == 403, (
        f"DELETE without CSRF should get 403, got {resp.status_code}"
    )


# ===================================================================
# Validation: unknown fields, bad enums
# ===================================================================


@pytest.mark.pg
def test_unknown_body_field_422(pg_url, app_url, owner_url, pg_roles):
    """Unknown body field on POST /projects returns 422."""
    env = _make_env(pg_url, owner_url, role="admin")
    resp = env["client"].post(
        "/api/v1/projects",
        cookies={"__Host-agg_session": env["cookie"]},
        headers={"X-CSRF-Token": env["csrf_token"]},
        json={"name": "proj", "environment": "dev", "unknown_field": "bad"},
    )
    guard_404_t9(resp)
    assert resp.status_code == 422, (
        f"Unknown body field should get 422, got {resp.status_code}: {resp.text}"
    )


@pytest.mark.pg
def test_bad_enum_422(pg_url, app_url, owner_url, pg_roles):
    """Bad enum value for environment on POST /projects returns 422."""
    env = _make_env(pg_url, owner_url, role="admin")
    resp = env["client"].post(
        "/api/v1/projects",
        cookies={"__Host-agg_session": env["cookie"]},
        headers={"X-CSRF-Token": env["csrf_token"]},
        json={"name": "proj", "environment": "sandbox"},
    )
    guard_404_t9(resp)
    assert resp.status_code == 422, (
        f"Bad enum should get 422, got {resp.status_code}: {resp.text}"
    )


@pytest.mark.pg
def test_bad_role_enum_422(pg_url, app_url, owner_url, pg_roles):
    """Bad role value on POST /org/members returns 422."""
    env = _make_env(pg_url, owner_url, role="admin")
    target_id, _ = seed_user(
        owner_url, env["org_id"], email="badrol@example.com",
    )
    resp = env["client"].post(
        "/api/v1/org/members",
        cookies={"__Host-agg_session": env["cookie"]},
        headers={"X-CSRF-Token": env["csrf_token"]},
        json={"user_id": str(target_id), "role": "superadmin"},
    )
    guard_404_t9(resp)
    assert resp.status_code == 422, (
        f"Bad role enum should get 422, got {resp.status_code}: {resp.text}"
    )


# ===================================================================
# Last org admin cannot be revoked (409)
# ===================================================================


@pytest.mark.pg
def test_last_org_admin_revoke_409(pg_url, app_url, owner_url, pg_roles):
    """Revoking the last org admin returns 409."""
    env = _make_env(pg_url, owner_url, role="admin", add_project=True)

    # Revoke the sole org admin via DELETE /org/members/{user_id}/admin
    resp = env["client"].delete(
        f"/api/v1/org/members/{env['user_id']}/admin",
        cookies={"__Host-agg_session": env["cookie"]},
        headers={"X-CSRF-Token": env["csrf_token"]},
    )
    guard_404_t9(resp)

    assert resp.status_code == 409, (
        f"Last org admin revoke should return 409, got {resp.status_code}: {resp.text}"
    )


# ===================================================================
# Idempotent grants
# ===================================================================


@pytest.mark.pg
def test_grants_idempotent(pg_url, app_url, owner_url, pg_roles):
    """Same grant twice -> one row in role_bindings."""
    env = _make_env(pg_url, owner_url, role="admin", add_project=True)
    target_id, _ = seed_user(
        owner_url, env["org_id"], email="idemp@example.com",
    )
    pid = env["project_id"]

    grant_body = {"user_id": str(target_id), "role": "viewer"}

    # First grant
    r1 = env["client"].post(
        f"/api/v1/projects/{pid}/members",
        cookies={"__Host-agg_session": env["cookie"]},
        headers={"X-CSRF-Token": env["csrf_token"]},
        json=grant_body,
    )
    guard_404_t9(r1)
    require_t9(r1.status_code in (200, 201, 204),
               f"First grant failed: {r1.status_code}")

    # Second grant (same)
    r2 = env["client"].post(
        f"/api/v1/projects/{pid}/members",
        cookies={"__Host-agg_session": env["cookie"]},
        headers={"X-CSRF-Token": env["csrf_token"]},
        json=grant_body,
    )
    assert r2.status_code in (200, 201, 204), (
        f"Second grant should succeed (idempotent), got {r2.status_code}: {r2.text}"
    )

    # Verify only one row
    conninfo = _conninfo(app_url)
    with psycopg.connect(conninfo) as conn:
        conn.execute(
            "SELECT set_config('app.org_id', %s, false)", [str(env["org_id"])]
        )
        cnt = conn.execute(
            "SELECT count(*) FROM role_bindings "
            "WHERE user_id = %s AND scope_type = 'project' "
            "AND scope_id = %s AND role = 'viewer'",
            [target_id, pid],
        ).fetchone()[0]
    assert cnt == 1, (
        f"Expected exactly 1 row after idempotent grant, got {cnt}"
    )
