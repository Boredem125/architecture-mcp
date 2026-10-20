"""T9 security-review tests (orchestrator ruling 20 Oct 2026).

Verifies:
- Removing a project-admin binding for the sole org admin -> 204;
  org admin binding intact.
- Concurrent self-revoke of 2 org admins (2 threads, each revokes
  themselves) -> exactly one succeeds (204), one gets 409, one admin left.
- Non-admin on DELETE /org/members/{user_id}/{role} -> 404.
- Viewer on DELETE /org/members/{sole_admin}/admin -> 404, admin binding
  intact; positive control: admin on second admin -> 204.
"""
from __future__ import annotations

import threading
import uuid

import psycopg
import pytest

from .t9_helpers import (
    T9Pending,
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

def _review_env(pg_url, owner_url, *, role="admin"):
    """Set up org, user, role binding, project, session, app."""
    clock = FakeClock()
    slug = unique_slug("rev")

    ensure_at_head(pg_url)
    org_id = seed_org_with_oidc(owner_url, slug=slug)
    user_id, _ = seed_user(owner_url, org_id, email=f"{role}-rev@example.com")
    project_id = seed_project(owner_url, org_id, name=f"proj-{slug}")

    seed_role_binding(
        owner_url, org_id, user_id,
        role=role, scope_type="org",
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
        "project_id": project_id,
        "csrf_token": csrf_token,
        "cookie": cookie,
        "clock": clock,
        "slug": slug,
        "owner_url": owner_url,
        "pg_url": pg_url,
    }


# ===================================================================
# Project-admin removal on sole org admin -> 204, org binding intact
# ===================================================================


@pytest.mark.pg
def test_project_admin_removal_sole_org_admin_204(pg_url, app_url, owner_url, pg_roles):
    """Removing a project-admin binding for the sole org admin returns 204
    and the org admin binding remains intact."""
    env = _review_env(pg_url, owner_url)
    pid = env["project_id"]

    # Seed a project-scope admin binding for the sole org admin
    seed_role_binding(
        owner_url, env["org_id"], env["user_id"],
        role="admin", scope_type="project", scope_id=pid,
    )

    # Delete the project-scope admin binding
    resp = env["client"].delete(
        f"/api/v1/projects/{pid}/members/{env['user_id']}/admin",
        cookies={"__Host-agg_session": env["cookie"]},
        headers={"X-CSRF-Token": env["csrf_token"]},
    )
    guard_404_t9(resp)
    assert resp.status_code == 204, (
        f"Project-admin removal should succeed (204), got {resp.status_code}: {resp.text}"
    )

    # Verify org admin binding is still intact
    conninfo = _conninfo(app_url)
    with psycopg.connect(conninfo) as conn:
        conn.execute(
            "SELECT set_config('app.org_id', %s, false)", [str(env["org_id"])]
        )
        org_admin_row = conn.execute(
            "SELECT 1 FROM role_bindings "
            "WHERE user_id = %s AND scope_type = 'org' AND role = 'admin'",
            [env["user_id"]],
        ).fetchone()

    assert org_admin_row is not None, (
        "Org admin binding should still exist after project-admin removal"
    )


# ===================================================================
# Concurrent revoke of 2 org admins -> exactly one 409
# ===================================================================


@pytest.mark.pg
def test_concurrent_org_admin_revoke(pg_url, app_url, owner_url, pg_roles):
    """Concurrent self-revoke of 2 org admins: exactly one succeeds (204),
    one gets 409, one admin left.

    Each admin revokes *themselves* so the loser's RBAC check (fresh
    read under the advisory lock) always passes -- the winner only
    deleted its own binding, not the loser's.
    """
    clock = FakeClock()
    slug = unique_slug("conc")

    ensure_at_head(pg_url)
    org_id = seed_org_with_oidc(owner_url, slug=slug)

    # Create two org admins
    admin1_id, _ = seed_user(owner_url, org_id, email="admin1-conc@example.com")
    admin2_id, _ = seed_user(owner_url, org_id, email="admin2-conc@example.com")
    seed_role_binding(owner_url, org_id, admin1_id, role="admin")
    seed_role_binding(owner_url, org_id, admin2_id, role="admin")

    # Separate sessions
    tok1, csrf1, _ = seed_session(owner_url, org_id, admin1_id, clock=clock)
    tok2, csrf2, _ = seed_session(owner_url, org_id, admin2_id, clock=clock)
    cookie1 = make_session_cookie(org_id, tok1)
    cookie2 = make_session_cookie(org_id, tok2)

    app, clock, _ = make_t9_app(pg_url, clock=clock)

    # Each admin revokes themselves; advisory lock serializes
    results = [None, None]
    barrier = threading.Barrier(2, timeout=10)

    def revoke_self(idx, self_id, cookie, csrf):
        client = make_t9_client(app)
        barrier.wait()
        resp = client.delete(
            f"/api/v1/org/members/{self_id}/admin",
            cookies={"__Host-agg_session": cookie},
            headers={"X-CSRF-Token": csrf},
        )
        results[idx] = resp.status_code

    t1 = threading.Thread(
        target=revoke_self, args=(0, admin1_id, cookie1, csrf1),
    )
    t2 = threading.Thread(
        target=revoke_self, args=(1, admin2_id, cookie2, csrf2),
    )
    t1.start()
    t2.start()
    t1.join(timeout=15)
    t2.join(timeout=15)

    status_codes = sorted(results)
    assert status_codes == [204, 409], (
        f"Expected exactly one 204 and one 409, got {results}"
    )

    # Verify exactly one org admin remains
    conninfo = _conninfo(app_url)
    with psycopg.connect(conninfo) as conn:
        conn.execute(
            "SELECT set_config('app.org_id', %s, false)", [str(org_id)]
        )
        admin_count = conn.execute(
            "SELECT count(*) FROM role_bindings "
            "WHERE scope_type = 'org' AND role = 'admin'",
        ).fetchone()[0]

    assert admin_count == 1, (
        f"Expected exactly 1 org admin remaining, got {admin_count}"
    )


# ===================================================================
# Non-admin on DELETE /org/members -> 404
# ===================================================================


@pytest.mark.pg
def test_delete_org_member_non_admin_404(pg_url, app_url, owner_url, pg_roles):
    """Non-admin caller on DELETE /org/members/{user_id}/{role} gets 404."""
    env = _review_env(pg_url, owner_url, role="viewer")

    # Target: some user_id (doesn't matter, the RBAC check fires first)
    target_id = uuid.uuid4()

    resp = env["client"].delete(
        f"/api/v1/org/members/{target_id}/viewer",
        cookies={"__Host-agg_session": env["cookie"]},
        headers={"X-CSRF-Token": env["csrf_token"]},
    )
    guard_404_t9(resp)
    assert resp.status_code == 404, (
        f"Non-admin should get 404, got {resp.status_code}: {resp.text}"
    )


# ===================================================================
# Viewer on sole admin's admin binding -> 404, admin binding intact;
# positive control: admin removes second admin -> 204
# ===================================================================


@pytest.mark.pg
def test_viewer_delete_sole_admin_binding_404(pg_url, app_url, owner_url, pg_roles):
    """Viewer calling DELETE /org/members/{sole_admin}/admin gets 404;
    the sole admin binding stays intact.  Positive control: an admin
    calling the same route on a second admin gets 204."""
    clock = FakeClock()
    slug = unique_slug("vadm")

    ensure_at_head(pg_url)
    org_id = seed_org_with_oidc(owner_url, slug=slug)

    admin_id, _ = seed_user(owner_url, org_id, email="admin-vadm@example.com")
    viewer_id, _ = seed_user(owner_url, org_id, email="viewer-vadm@example.com")
    seed_role_binding(owner_url, org_id, admin_id, role="admin")
    seed_role_binding(owner_url, org_id, viewer_id, role="viewer")

    # Viewer session
    vtok, vcsrf, _ = seed_session(owner_url, org_id, viewer_id, clock=clock)
    vcookie = make_session_cookie(org_id, vtok)

    app, clock, _ = make_t9_app(pg_url, clock=clock)
    client = make_t9_client(app)

    # Viewer attempts to delete sole admin's admin binding -> 404
    resp = client.delete(
        f"/api/v1/org/members/{admin_id}/admin",
        cookies={"__Host-agg_session": vcookie},
        headers={"X-CSRF-Token": vcsrf},
    )
    guard_404_t9(resp)
    assert resp.status_code == 404, (
        f"Viewer should get 404, got {resp.status_code}: {resp.text}"
    )

    # Admin binding must still be intact
    conninfo = _conninfo(app_url)
    with psycopg.connect(conninfo) as conn:
        conn.execute(
            "SELECT set_config('app.org_id', %s, false)", [str(org_id)]
        )
        row = conn.execute(
            "SELECT 1 FROM role_bindings "
            "WHERE user_id = %s AND scope_type = 'org' AND role = 'admin'",
            [admin_id],
        ).fetchone()
    assert row is not None, "Sole admin binding must survive viewer's attempt"

    # Positive control: add a second admin, then admin removes them -> 204
    admin2_id, _ = seed_user(owner_url, org_id, email="admin2-vadm@example.com")
    seed_role_binding(owner_url, org_id, admin2_id, role="admin")

    atok, acsrf, _ = seed_session(owner_url, org_id, admin_id, clock=clock)
    acookie = make_session_cookie(org_id, atok)

    resp = client.delete(
        f"/api/v1/org/members/{admin2_id}/admin",
        cookies={"__Host-agg_session": acookie},
        headers={"X-CSRF-Token": acsrf},
    )
    guard_404_t9(resp)
    assert resp.status_code == 204, (
        f"Admin removing second admin should get 204, got {resp.status_code}: {resp.text}"
    )
