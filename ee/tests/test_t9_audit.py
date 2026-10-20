"""T9 audit tests.

Verifies:
- Each write route appends the documented admin_audit action
  (project_created, role_granted, role_revoked, user_added).
- GET /org/audit/verify ok for auditor (+), 404/403 for viewer.
- CLI ``agg_cp.cli:main(["audit","verify","--org",slug])`` prints one
  JSON line and exits 0.
- After a superuser flips one byte in ``detail`` with
  ``SET session_replication_role = replica`` the CLI exits 1 and the
  other org still verifies (+).
"""
from __future__ import annotations

import json
import subprocess
import sys
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

def _audit_env(pg_url, owner_url):
    """Set up an org with admin, project, session, app.

    Returns dict with all pieces needed for audit tests.
    """
    clock = FakeClock()
    slug = unique_slug("audit")

    ensure_at_head(pg_url)
    org_id = seed_org_with_oidc(owner_url, slug=slug)
    admin_id, _ = seed_user(owner_url, org_id, email="audit-admin@example.com")
    seed_role_binding(owner_url, org_id, admin_id, role="admin")

    session_token, csrf_token, _ = seed_session(
        owner_url, org_id, admin_id, clock=clock,
    )
    cookie = make_session_cookie(org_id, session_token)

    app, clock, _ = make_t9_app(pg_url, clock=clock)
    client = make_t9_client(app)

    return {
        "client": client,
        "org_id": org_id,
        "admin_id": admin_id,
        "cookie": cookie,
        "csrf_token": csrf_token,
        "clock": clock,
        "slug": slug,
        "owner_url": owner_url,
        "pg_url": pg_url,
    }


def _count_audit_action(app_url, org_id, action):
    """Count admin_audit rows for a given action in an org."""
    conninfo = _conninfo(app_url)
    with psycopg.connect(conninfo) as conn:
        conn.execute(
            "SELECT set_config('app.org_id', %s, false)", [str(org_id)]
        )
        return conn.execute(
            "SELECT count(*) FROM admin_audit WHERE action = %s",
            [action],
        ).fetchone()[0]


# ===================================================================
# Write routes append documented audit actions
# ===================================================================


@RED_T9
@pytest.mark.pg
def test_audit_project_created(pg_url, app_url, owner_url, pg_roles):
    """POST /projects appends admin_audit action 'project_created'."""
    e = _audit_env(pg_url, owner_url)

    before = _count_audit_action(app_url, e["org_id"], "project_created")

    resp = e["client"].post(
        "/api/v1/projects",
        cookies={"__Host-agg_session": e["cookie"]},
        headers={"X-CSRF-Token": e["csrf_token"]},
        json={"name": "audit-proj", "environment": "dev"},
    )
    guard_404_t9(resp)
    require_t9(resp.status_code == 201,
               f"POST /projects failed: {resp.status_code}")

    after = _count_audit_action(app_url, e["org_id"], "project_created")
    assert after > before, (
        "admin_audit should have a new 'project_created' row"
    )


@RED_T9
@pytest.mark.pg
def test_audit_role_granted(pg_url, app_url, owner_url, pg_roles):
    """POST /projects/{id}/members appends admin_audit action 'role_granted'."""
    e = _audit_env(pg_url, owner_url)

    # Create a project
    resp = e["client"].post(
        "/api/v1/projects",
        cookies={"__Host-agg_session": e["cookie"]},
        headers={"X-CSRF-Token": e["csrf_token"]},
        json={"name": "grant-proj", "environment": "dev"},
    )
    guard_404_t9(resp)
    require_t9(resp.status_code == 201,
               f"POST /projects failed: {resp.status_code}")
    project_id = resp.json().get("id")
    require_t9(project_id is not None, "POST /projects did not return id")

    # Seed a target user
    target_id, _ = seed_user(
        owner_url, e["org_id"], email="grant-target@example.com",
    )

    before = _count_audit_action(app_url, e["org_id"], "role_granted")

    resp2 = e["client"].post(
        f"/api/v1/projects/{project_id}/members",
        cookies={"__Host-agg_session": e["cookie"]},
        headers={"X-CSRF-Token": e["csrf_token"]},
        json={"user_id": str(target_id), "role": "viewer"},
    )
    guard_404_t9(resp2)
    require_t9(resp2.status_code in (200, 201, 204),
               f"POST members failed: {resp2.status_code}")

    after = _count_audit_action(app_url, e["org_id"], "role_granted")
    assert after > before, (
        "admin_audit should have a new 'role_granted' row"
    )


@RED_T9
@pytest.mark.pg
def test_audit_role_revoked(pg_url, app_url, owner_url, pg_roles):
    """DELETE /projects/{id}/members/{user_id}/{role} appends 'role_revoked'."""
    e = _audit_env(pg_url, owner_url)

    # Create a project and add a member
    resp = e["client"].post(
        "/api/v1/projects",
        cookies={"__Host-agg_session": e["cookie"]},
        headers={"X-CSRF-Token": e["csrf_token"]},
        json={"name": "revoke-proj", "environment": "dev"},
    )
    guard_404_t9(resp)
    require_t9(resp.status_code == 201,
               f"POST /projects failed: {resp.status_code}")
    project_id = resp.json().get("id")
    require_t9(project_id is not None, "POST /projects did not return id")

    target_id, _ = seed_user(
        owner_url, e["org_id"], email="revoke-target@example.com",
    )
    resp2 = e["client"].post(
        f"/api/v1/projects/{project_id}/members",
        cookies={"__Host-agg_session": e["cookie"]},
        headers={"X-CSRF-Token": e["csrf_token"]},
        json={"user_id": str(target_id), "role": "viewer"},
    )
    guard_404_t9(resp2)
    require_t9(resp2.status_code in (200, 201, 204),
               f"POST members failed: {resp2.status_code}")

    before = _count_audit_action(app_url, e["org_id"], "role_revoked")

    resp3 = e["client"].delete(
        f"/api/v1/projects/{project_id}/members/{target_id}/viewer",
        cookies={"__Host-agg_session": e["cookie"]},
        headers={"X-CSRF-Token": e["csrf_token"]},
    )
    guard_404_t9(resp3)
    require_t9(resp3.status_code == 204,
               f"DELETE member failed: {resp3.status_code}")

    after = _count_audit_action(app_url, e["org_id"], "role_revoked")
    assert after > before, (
        "admin_audit should have a new 'role_revoked' row"
    )


@RED_T9
@pytest.mark.pg
def test_audit_user_added(pg_url, app_url, owner_url, pg_roles):
    """POST /org/users appends admin_audit action 'user_added'."""
    e = _audit_env(pg_url, owner_url)

    before = _count_audit_action(app_url, e["org_id"], "user_added")

    resp = e["client"].post(
        "/api/v1/org/users",
        cookies={"__Host-agg_session": e["cookie"]},
        headers={"X-CSRF-Token": e["csrf_token"]},
        json={"oidc_subject": f"sub-{uuid.uuid4().hex[:8]}",
              "email": "newuser@example.com"},
    )
    guard_404_t9(resp)
    require_t9(resp.status_code in (200, 201),
               f"POST /org/users failed: {resp.status_code}")

    after = _count_audit_action(app_url, e["org_id"], "user_added")
    assert after > before, (
        "admin_audit should have a new 'user_added' row"
    )


# ===================================================================
# GET /org/audit/verify: auditor passes, viewer fails
# ===================================================================


@RED_T9
@pytest.mark.pg
def test_audit_verify_auditor_passes(pg_url, app_url, owner_url, pg_roles):
    """GET /org/audit/verify: auditor gets 200 with {ok: true} (+)."""
    clock = FakeClock()
    slug = unique_slug("audver")

    ensure_at_head(pg_url)
    org_id = seed_org_with_oidc(owner_url, slug=slug)
    auditor_id, _ = seed_user(owner_url, org_id, email="auditor@example.com")
    seed_role_binding(owner_url, org_id, auditor_id, role="auditor")

    session_token, csrf_token, _ = seed_session(
        owner_url, org_id, auditor_id, clock=clock,
    )
    cookie = make_session_cookie(org_id, session_token)

    app, clock, _ = make_t9_app(pg_url, clock=clock)
    client = make_t9_client(app)

    resp = client.get(
        "/api/v1/org/audit/verify",
        cookies={"__Host-agg_session": cookie},
    )
    guard_404_t9(resp)
    assert resp.status_code == 200, (
        f"auditor should get 200 on /org/audit/verify, got {resp.status_code}"
    )
    body = resp.json()
    assert body.get("ok") is True, f"Expected ok: true, got {body}"


@RED_T9
@pytest.mark.pg
def test_audit_verify_viewer_fails(pg_url, app_url, owner_url, pg_roles):
    """GET /org/audit/verify: viewer gets 404 or 403."""
    clock = FakeClock()
    slug = unique_slug("audvfail")

    ensure_at_head(pg_url)
    org_id = seed_org_with_oidc(owner_url, slug=slug)
    viewer_id, _ = seed_user(owner_url, org_id, email="viewer@example.com")
    seed_role_binding(owner_url, org_id, viewer_id, role="viewer")

    session_token, csrf_token, _ = seed_session(
        owner_url, org_id, viewer_id, clock=clock,
    )
    cookie = make_session_cookie(org_id, session_token)

    app, clock, _ = make_t9_app(pg_url, clock=clock)
    client = make_t9_client(app)

    resp = client.get(
        "/api/v1/org/audit/verify",
        cookies={"__Host-agg_session": cookie},
    )
    guard_404_t9(resp)
    assert resp.status_code in (403, 404), (
        f"viewer should get 403 or 404 on /org/audit/verify, got {resp.status_code}"
    )


# ===================================================================
# CLI: agg_cp.cli:main(["audit", "verify", "--org", slug])
# ===================================================================


@RED_T9
@pytest.mark.pg
def test_cli_audit_verify_exits_0(pg_url, app_url, owner_url, pg_roles):
    """CLI audit verify prints one JSON line and exits 0."""
    clock = FakeClock()
    slug = unique_slug("cliaud")

    ensure_at_head(pg_url)
    org_id = seed_org_with_oidc(owner_url, slug=slug)

    # We need to seed at least one audit row for the chain to verify
    conninfo = _conninfo(owner_url)
    with psycopg.connect(conninfo) as conn:
        conn.execute(
            "SELECT set_config('app.org_id', %s, false)", [str(org_id)]
        )
        conn.execute(
            "INSERT INTO admin_audit (id, org_id, action, detail) "
            "VALUES (%s, %s, 'test_event', %s)",
            [uuid.uuid4(), org_id,
             json.dumps({"test": True})],
        )
        conn.commit()

    # Try importing the CLI module
    try:
        from agg_cp.cli import main as cli_main
    except ImportError as exc:
        raise T9Pending(f"agg_cp.cli not importable: {exc}") from exc

    # Run the CLI in-process
    import io
    from contextlib import redirect_stdout

    buf = io.StringIO()
    try:
        with redirect_stdout(buf):
            exit_code = cli_main(["audit", "verify", "--org", slug])
    except SystemExit as se:
        exit_code = se.code

    output = buf.getvalue().strip()
    require_t9(exit_code == 0,
               f"CLI exited with {exit_code}, output: {output}")

    # Output should be one JSON line
    parsed = json.loads(output)
    assert "ok" in parsed, f"CLI output missing 'ok': {parsed}"
    assert "org" in parsed, f"CLI output missing 'org': {parsed}"
    assert parsed["ok"] is True, f"Expected ok=true, got {parsed}"


@RED_T9
@pytest.mark.pg
def test_cli_audit_verify_tampered_exits_1(pg_url, app_url, owner_url, pg_roles):
    """After flipping one byte in detail, CLI exits 1; other org still verifies (+)."""
    clock = FakeClock()

    ensure_at_head(pg_url)

    # Org A (will be tampered)
    slug_a = unique_slug("cliaud-a")
    org_a = seed_org_with_oidc(owner_url, slug=slug_a)

    # Org B (control, untampered)
    slug_b = unique_slug("cliaud-b")
    org_b = seed_org_with_oidc(owner_url, slug=slug_b)

    conninfo = _conninfo(owner_url)

    # Seed audit rows in both orgs
    for oid in (org_a, org_b):
        with psycopg.connect(conninfo) as conn:
            conn.execute(
                "SELECT set_config('app.org_id', %s, false)", [str(oid)]
            )
            conn.execute(
                "INSERT INTO admin_audit (id, org_id, action, detail) "
                "VALUES (%s, %s, 'test_event', %s)",
                [uuid.uuid4(), oid,
                 json.dumps({"key": "value"})],
            )
            conn.commit()

    # Tamper org A's detail: flip one byte using replica role to bypass triggers
    with psycopg.connect(_conninfo(pg_url)) as conn:
        conn.autocommit = True
        conn.execute("SET session_replication_role = replica")
        conn.execute(
            "UPDATE admin_audit SET detail = %s "
            "WHERE org_id = %s",
            [json.dumps({"key": "TAMPERED"}), org_a],
        )
        conn.execute("SET session_replication_role = DEFAULT")

    try:
        from agg_cp.cli import main as cli_main
    except ImportError as exc:
        raise T9Pending(f"agg_cp.cli not importable: {exc}") from exc

    import io
    from contextlib import redirect_stdout

    # Org A should fail
    buf_a = io.StringIO()
    try:
        with redirect_stdout(buf_a):
            exit_a = cli_main(["audit", "verify", "--org", slug_a])
    except SystemExit as se:
        exit_a = se.code

    assert exit_a == 1, (
        f"Tampered org should exit 1, got {exit_a}. "
        f"Output: {buf_a.getvalue()}"
    )

    # Org B should still pass (+)
    buf_b = io.StringIO()
    try:
        with redirect_stdout(buf_b):
            exit_b = cli_main(["audit", "verify", "--org", slug_b])
    except SystemExit as se:
        exit_b = se.code

    assert exit_b == 0, (
        f"Untampered org should exit 0, got {exit_b}. "
        f"Output: {buf_b.getvalue()}"
    )
