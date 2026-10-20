"""T9 IDOR (Insecure Direct Object Reference) tests.

Verifies:
- Org B admin gets 404 on org A project GET / members / POST members /
  DELETE member (+ org A admin succeeds on the same ids).
- Project-scoped viewer in org A cannot read another project in org A (404)
  (+ reads own).
- Forged org id in cookie gives 401.
"""
from __future__ import annotations

import uuid

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

def _two_org_env(pg_url, owner_url):
    """Set up two orgs (A and B) each with an admin, a project in A, and one app.

    Returns a dict with all the pieces.
    """
    clock = FakeClock()

    ensure_at_head(pg_url)

    # Org A
    slug_a = unique_slug("idor-a")
    org_a = seed_org_with_oidc(owner_url, slug=slug_a)
    user_a, _ = seed_user(owner_url, org_a, email="admin-a@example.com")
    seed_role_binding(owner_url, org_a, user_a, role="admin")
    project_a = seed_project(owner_url, org_a, name=f"proj-{slug_a}")
    token_a, csrf_a, _ = seed_session(owner_url, org_a, user_a, clock=clock)
    cookie_a = make_session_cookie(org_a, token_a)

    # Org B
    slug_b = unique_slug("idor-b")
    org_b = seed_org_with_oidc(owner_url, slug=slug_b)
    user_b, _ = seed_user(owner_url, org_b, email="admin-b@example.com")
    seed_role_binding(owner_url, org_b, user_b, role="admin")
    token_b, csrf_b, _ = seed_session(owner_url, org_b, user_b, clock=clock)
    cookie_b = make_session_cookie(org_b, token_b)

    # A third user in org A as target for member operations
    target_a, _ = seed_user(owner_url, org_a, email="target-a@example.com")

    app, clock, _ = make_t9_app(pg_url, clock=clock)
    client = make_t9_client(app)

    return {
        "client": client,
        "org_a": org_a, "user_a": user_a, "cookie_a": cookie_a, "csrf_a": csrf_a,
        "project_a": project_a, "target_a": target_a,
        "org_b": org_b, "user_b": user_b, "cookie_b": cookie_b, "csrf_b": csrf_b,
        "clock": clock,
        "owner_url": owner_url,
    }


# ===================================================================
# Org B admin cannot see org A resources (404), org A admin can (+)
# ===================================================================


@pytest.mark.pg
def test_idor_org_b_404_on_org_a_project_get(pg_url, app_url, owner_url, pg_roles):
    """Org B admin gets 404 when reading org A's project."""
    e = _two_org_env(pg_url, owner_url)

    resp = e["client"].get(
        f"/api/v1/projects/{e['project_a']}",
        cookies={"__Host-agg_session": e["cookie_b"]},
    )
    guard_404_t9(resp)
    assert resp.status_code == 404, (
        f"Org B should get 404 on org A project, got {resp.status_code}"
    )


@pytest.mark.pg
def test_idor_org_a_admin_reads_own_project(pg_url, app_url, owner_url, pg_roles):
    """Positive control: org A admin reads org A's project."""
    e = _two_org_env(pg_url, owner_url)

    resp = e["client"].get(
        f"/api/v1/projects/{e['project_a']}",
        cookies={"__Host-agg_session": e["cookie_a"]},
    )
    guard_404_t9(resp)
    assert resp.status_code == 200, (
        f"Org A admin should read own project (200), got {resp.status_code}"
    )


@pytest.mark.pg
def test_idor_org_b_404_on_org_a_project_members(pg_url, app_url, owner_url, pg_roles):
    """Org B admin gets 404 when reading org A project members."""
    e = _two_org_env(pg_url, owner_url)

    resp = e["client"].get(
        f"/api/v1/projects/{e['project_a']}/members",
        cookies={"__Host-agg_session": e["cookie_b"]},
    )
    guard_404_t9(resp)
    assert resp.status_code == 404, (
        f"Org B should get 404 on org A project members, got {resp.status_code}"
    )


@pytest.mark.pg
def test_idor_org_b_404_on_org_a_post_member(pg_url, app_url, owner_url, pg_roles):
    """Org B admin gets 404 when POSTing a member to org A project."""
    e = _two_org_env(pg_url, owner_url)

    resp = e["client"].post(
        f"/api/v1/projects/{e['project_a']}/members",
        cookies={"__Host-agg_session": e["cookie_b"]},
        headers={"X-CSRF-Token": e["csrf_b"]},
        json={"user_id": str(e["target_a"]), "role": "viewer"},
    )
    guard_404_t9(resp)
    assert resp.status_code == 404, (
        f"Org B should get 404 on POST member to org A project, got {resp.status_code}"
    )


@pytest.mark.pg
def test_idor_org_b_404_on_org_a_delete_member(pg_url, app_url, owner_url, pg_roles):
    """Org B admin gets 404 when DELETEing a member from org A project."""
    e = _two_org_env(pg_url, owner_url)

    # Seed a binding so there's something to delete (from org A's perspective)
    seed_role_binding(
        owner_url, e["org_a"], e["target_a"],
        role="viewer", scope_type="project", scope_id=e["project_a"],
    )

    resp = e["client"].delete(
        f"/api/v1/projects/{e['project_a']}/members/{e['target_a']}/viewer",
        cookies={"__Host-agg_session": e["cookie_b"]},
        headers={"X-CSRF-Token": e["csrf_b"]},
    )
    guard_404_t9(resp)
    assert resp.status_code == 404, (
        f"Org B should get 404 on DELETE member from org A project, got {resp.status_code}"
    )


@pytest.mark.pg
def test_idor_org_a_admin_deletes_own_member(pg_url, app_url, owner_url, pg_roles):
    """Positive control: org A admin deletes a member from org A project."""
    e = _two_org_env(pg_url, owner_url)

    # Seed the binding
    seed_role_binding(
        owner_url, e["org_a"], e["target_a"],
        role="viewer", scope_type="project", scope_id=e["project_a"],
    )

    resp = e["client"].delete(
        f"/api/v1/projects/{e['project_a']}/members/{e['target_a']}/viewer",
        cookies={"__Host-agg_session": e["cookie_a"]},
        headers={"X-CSRF-Token": e["csrf_a"]},
    )
    guard_404_t9(resp)
    assert resp.status_code == 204, (
        f"Org A admin should delete member (204), got {resp.status_code}: {resp.text}"
    )


# ===================================================================
# Project-scoped viewer cannot read another project (404) + reads own
# ===================================================================


@pytest.mark.pg
def test_idor_project_viewer_cannot_read_other_project(pg_url, app_url, owner_url, pg_roles):
    """Project-scoped viewer in org A gets 404 on another project in org A."""
    clock = FakeClock()
    slug = unique_slug("idor-pv")

    ensure_at_head(pg_url)
    org_id = seed_org_with_oidc(owner_url, slug=slug)

    proj1 = seed_project(owner_url, org_id, name="proj1")
    proj2 = seed_project(owner_url, org_id, name="proj2")

    user_id, _ = seed_user(owner_url, org_id, email="projviewer@example.com")
    # Only give viewer on proj1
    seed_role_binding(
        owner_url, org_id, user_id,
        role="viewer", scope_type="project", scope_id=proj1,
    )

    session_token, csrf_token, _ = seed_session(
        owner_url, org_id, user_id, clock=clock,
    )
    cookie = make_session_cookie(org_id, session_token)

    app, clock, _ = make_t9_app(pg_url, clock=clock)
    client = make_t9_client(app)

    # Cannot read proj2
    resp2 = client.get(
        f"/api/v1/projects/{proj2}",
        cookies={"__Host-agg_session": cookie},
    )
    guard_404_t9(resp2)
    assert resp2.status_code == 404, (
        f"Project viewer should get 404 on other project, got {resp2.status_code}"
    )


@pytest.mark.pg
def test_idor_project_viewer_reads_own_project(pg_url, app_url, owner_url, pg_roles):
    """Positive control: project-scoped viewer in org A reads their own project."""
    clock = FakeClock()
    slug = unique_slug("idor-pvown")

    ensure_at_head(pg_url)
    org_id = seed_org_with_oidc(owner_url, slug=slug)

    proj1 = seed_project(owner_url, org_id, name="proj1")

    user_id, _ = seed_user(owner_url, org_id, email="projviewer2@example.com")
    seed_role_binding(
        owner_url, org_id, user_id,
        role="viewer", scope_type="project", scope_id=proj1,
    )

    session_token, csrf_token, _ = seed_session(
        owner_url, org_id, user_id, clock=clock,
    )
    cookie = make_session_cookie(org_id, session_token)

    app, clock, _ = make_t9_app(pg_url, clock=clock)
    client = make_t9_client(app)

    resp = client.get(
        f"/api/v1/projects/{proj1}",
        cookies={"__Host-agg_session": cookie},
    )
    guard_404_t9(resp)
    assert resp.status_code == 200, (
        f"Project viewer should read own project (200), got {resp.status_code}"
    )


# ===================================================================
# Forged org id in cookie -> 401
# ===================================================================


@pytest.mark.pg
def test_idor_forged_org_id_cookie_401(pg_url, app_url, owner_url, pg_roles):
    """Forged org id in the session cookie gives 401."""
    clock = FakeClock()
    slug = unique_slug("idor-forge")

    ensure_at_head(pg_url)
    org_id = seed_org_with_oidc(owner_url, slug=slug)
    user_id, _ = seed_user(owner_url, org_id)
    seed_role_binding(owner_url, org_id, user_id, role="admin")

    session_token, csrf_token, _ = seed_session(
        owner_url, org_id, user_id, clock=clock,
    )

    # Forge cookie with wrong org id
    forged_cookie = make_session_cookie(uuid.uuid4(), session_token)

    app, clock, _ = make_t9_app(pg_url, clock=clock)
    client = make_t9_client(app)

    resp = client.get(
        "/api/v1/me",
        cookies={"__Host-agg_session": forged_cookie},
    )
    guard_404_t9(resp)
    assert resp.status_code == 401, (
        f"Forged org id should get 401, got {resp.status_code}"
    )
