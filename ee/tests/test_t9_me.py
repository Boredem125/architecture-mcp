"""T9 /me endpoint tests.

Verifies:
- /me without session returns 401.
- /me with session returns the documented shape including roles and
  a csrf_token whose sha256 equals the stored csrf_hash.
- CSRF from /me works on a POST (positive control).
- Wrong CSRF returns 403.
"""
from __future__ import annotations

import hashlib
import uuid

import pytest

from .t9_helpers import (
    T9Pending,
    RED_T9,
    require_t9,
    guard_404_t9,
    compute_csrf,
    _sha256_hex,
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

def _build_me_env(pg_url, owner_url):
    """Set up an org, user, admin binding, and session.

    Returns (client, org_id, user_id, session_token, csrf_token, clock, slug).
    """
    clock = FakeClock()
    slug = unique_slug("me")

    ensure_at_head(pg_url)
    org_id = seed_org_with_oidc(owner_url, slug=slug)
    user_id, _ = seed_user(owner_url, org_id, email="admin@example.com")
    seed_role_binding(owner_url, org_id, user_id, role="admin")

    session_token, csrf_token, _ = seed_session(
        owner_url, org_id, user_id, clock=clock,
    )

    app, clock, _ = make_t9_app(pg_url, clock=clock)
    client = make_t9_client(app)
    return client, org_id, user_id, session_token, csrf_token, clock, slug


# ===================================================================
# Tests
# ===================================================================


@pytest.mark.pg
def test_me_without_session_401(pg_url, app_url, owner_url, pg_roles):
    """/me without a session cookie returns 401."""
    clock = FakeClock()
    ensure_at_head(pg_url)
    app, clock, _ = make_t9_app(pg_url, clock=clock)
    client = make_t9_client(app)

    resp = client.get("/api/v1/me")
    guard_404_t9(resp)
    assert resp.status_code == 401, (
        f"Expected 401 for /me without session, got {resp.status_code}"
    )


@pytest.mark.pg
def test_me_returns_documented_shape(pg_url, app_url, owner_url, pg_roles):
    """/me with session returns {user_id, display_name, org, roles, csrf_token}."""
    client, org_id, user_id, session_token, csrf_token, clock, slug = \
        _build_me_env(pg_url, owner_url)

    cookie = make_session_cookie(org_id, session_token)
    resp = client.get(
        "/api/v1/me",
        cookies={"__Host-agg_session": cookie},
    )
    guard_404_t9(resp)
    require_t9(resp.status_code == 200,
               f"Expected 200 from /me, got {resp.status_code}")

    body = resp.json()
    # Check required top-level keys
    assert "user_id" in body, f"Missing user_id in /me response: {body}"
    assert "org" in body, f"Missing org in /me response: {body}"
    assert "roles" in body, f"Missing roles in /me response: {body}"
    assert "csrf_token" in body, f"Missing csrf_token in /me response: {body}"

    # user_id matches
    assert body["user_id"] == str(user_id), (
        f"user_id mismatch: {body['user_id']} != {user_id}"
    )

    # org shape
    org = body["org"]
    assert "id" in org, f"Missing org.id: {org}"
    assert "slug" in org, f"Missing org.slug: {org}"
    assert "name" in org, f"Missing org.name: {org}"

    # roles is a list of dicts with role, scope_type, scope_id
    assert isinstance(body["roles"], list), f"roles not a list: {body['roles']}"
    assert len(body["roles"]) > 0, "Expected at least one role binding"
    for rb in body["roles"]:
        assert "role" in rb, f"Missing role in role binding: {rb}"
        assert "scope_type" in rb, f"Missing scope_type in role binding: {rb}"
        assert "scope_id" in rb, f"Missing scope_id in role binding: {rb}"


@pytest.mark.pg
def test_me_csrf_token_hash_matches_stored(pg_url, app_url, owner_url, pg_roles):
    """sha256 of the csrf_token from /me equals the stored csrf_hash."""
    import psycopg

    client, org_id, user_id, session_token, csrf_token, clock, slug = \
        _build_me_env(pg_url, owner_url)

    cookie = make_session_cookie(org_id, session_token)
    resp = client.get(
        "/api/v1/me",
        cookies={"__Host-agg_session": cookie},
    )
    guard_404_t9(resp)
    require_t9(resp.status_code == 200,
               f"Expected 200 from /me, got {resp.status_code}")

    body = resp.json()
    returned_csrf = body["csrf_token"]

    # Verify sha256 of returned csrf equals the stored csrf_hash
    token_hash = _sha256_hex(session_token)
    conninfo = _conninfo(app_url)
    with psycopg.connect(conninfo) as conn:
        conn.execute(
            "SELECT set_config('app.org_id', %s, false)", [str(org_id)]
        )
        row = conn.execute(
            "SELECT csrf_hash FROM web_sessions WHERE token_hash = %s",
            [token_hash],
        ).fetchone()
        assert row is not None, "Session not found in DB"
        stored_csrf_hash = row[0]

    computed_hash = _sha256_hex(returned_csrf)
    assert computed_hash == stored_csrf_hash, (
        f"CSRF hash mismatch: sha256({returned_csrf!r}) = {computed_hash}, "
        f"stored = {stored_csrf_hash}"
    )


@pytest.mark.pg
def test_me_csrf_works_on_post(pg_url, app_url, owner_url, pg_roles):
    """Positive control: csrf_token from GET /me works on a POST route."""
    client, org_id, user_id, session_token, csrf_token, clock, slug = \
        _build_me_env(pg_url, owner_url)

    cookie = make_session_cookie(org_id, session_token)

    # GET /me to obtain CSRF
    me_resp = client.get(
        "/api/v1/me",
        cookies={"__Host-agg_session": cookie},
    )
    guard_404_t9(me_resp)
    require_t9(me_resp.status_code == 200,
               f"Expected 200 from /me, got {me_resp.status_code}")

    live_csrf = me_resp.json()["csrf_token"]

    # Use it on POST /projects (admin should be allowed)
    resp = client.post(
        "/api/v1/projects",
        cookies={"__Host-agg_session": cookie},
        headers={"X-CSRF-Token": live_csrf},
        json={"name": "csrf-test-project", "environment": "dev"},
    )
    guard_404_t9(resp)
    # Should be 201 (created) -- not 403 (CSRF failure)
    assert resp.status_code != 403, (
        f"CSRF from /me should work on POST, got 403"
    )
    assert resp.status_code == 201, (
        f"Expected 201 from POST /projects, got {resp.status_code}: {resp.text}"
    )


@pytest.mark.pg
def test_me_wrong_csrf_403(pg_url, app_url, owner_url, pg_roles):
    """Wrong CSRF token on a POST returns 403."""
    client, org_id, user_id, session_token, csrf_token, clock, slug = \
        _build_me_env(pg_url, owner_url)

    cookie = make_session_cookie(org_id, session_token)

    resp = client.post(
        "/api/v1/projects",
        cookies={"__Host-agg_session": cookie},
        headers={"X-CSRF-Token": "totally-wrong-csrf-value"},
        json={"name": "bad-csrf-project", "environment": "dev"},
    )
    guard_404_t9(resp)
    assert resp.status_code == 403, (
        f"Wrong CSRF should get 403, got {resp.status_code}"
    )
