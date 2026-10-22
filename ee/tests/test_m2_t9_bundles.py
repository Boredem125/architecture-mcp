"""T9 ee tests-first: bundle routes through the real agg_cp app.

Interface contract (pinned -- the build removes only xfail markers)
-------------------------------------------------------------------
Server routes (agg_cp.sync.bundles):

    GET /api/v1/sync/bundle?after=<seq>
        Auth: device token (Authorization: Bearer <token>).
        The server hashes the token and calls device_token_lookup(hash)
        to get (org_id, project_id, connector_id).  It then returns
        the latest policy_bundles row for (org_id, project_id) with
        sequence > after.
        200: the stored envelope dict (keys: kind, sig_v, payload,
             signatures -- same shape as sign_envelope output).
        204: no newer bundle (empty body).
        401: missing, invalid or expired token; revoked device.

    POST /api/v1/admin/bundles
        Auth: admin session cookie (__Host-agg_session) + CSRF
              (X-CSRF-Token header).  Org from the session.
        The server signs the bundle with its bundle-signer key (D2.2,
        D5.1: private key in a server secret file).  The connector, not
        the server, validates loosening and CLI approvals (D2.3).
        Request:  {project_id: str, bundle_payload: dict,
                   change_approvals: list[dict]}
        200:  {bundle_id: str, sequence: int}
        403:  missing or invalid CSRF
        404:  project not found / cross-org
        409:  sequence conflict (UNIQUE (project_id, sequence))

Schema tables and columns touched (all from 0007_m2_tables.py):
    policy_bundles: id, org_id, project_id, sequence, bundle_blob,
                    server_signature, created_at
    device_tokens:  id, org_id, project_id, connector_id, token_hash,
                    expires_at, created_at
    connectors:     id, org_id, project_id, device_public_key,
                    operator_user_id, created_at, revoked_at
    projects:       id, org_id, name, environment, created_at

Uses the T5 tables via ee conftest fixtures (pg_url, pg_roles, owner_url,
app_url).

RED tests xfail on M2T9Pending.  Guards verify the T5 schema baseline.

Node-id patterns follow M2_BASELINE.md section 5.

Threat coverage (server side): 29 (cross-project 204, cross-org 204
via RLS), bundle storage and retrieval, device-token auth on GET,
session+CSRF auth on admin POST, sequence conflict 409.
"""
from __future__ import annotations

import hashlib
import json
import secrets
import time
import uuid

import psycopg
import pytest
from nacl.signing import SigningKey

from .m2_pending import M2T9Pending
from .m2_sync_server import (
    ensure_at_head, create_org, create_project,
    keygen, sign_envelope, canonical_json,
)
from .t8p2_helpers import (
    seed_org_with_oidc, seed_user, seed_admin_binding,
)
from .t9_helpers import seed_session, make_session_cookie
from .fake_idp import FakeClock


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _need(module: str, attr: str) -> None:
    """Raise M2T9Pending if *module*.*attr* is absent."""
    try:
        mod = __import__(module, fromlist=[attr])
    except ImportError:
        raise M2T9Pending(f"{module} not importable")
    if not hasattr(mod, attr):
        raise M2T9Pending(f"{module}.{attr} not found")


def _conninfo(url: str) -> str:
    return url.replace("+psycopg", "")


def _seed_device(conn, org_id, project_id, operator_user_id=None):
    """Seed a connector + device_tokens row.  Returns (device_id, token).

    Column names match 0007_m2_tables.py:
        connectors: id, org_id, project_id, device_public_key,
                    operator_user_id, created_at
        device_tokens: id, org_id, project_id, connector_id,
                       token_hash, expires_at, created_at
    """
    device_id = str(uuid.uuid4())
    sk, pub, kid = keygen()
    conn.execute(
        "INSERT INTO connectors "
        "(id, org_id, project_id, device_public_key, operator_user_id, created_at) "
        "VALUES (%s, %s::uuid, %s::uuid, %s, %s, now())",
        [device_id, org_id, project_id, pub.hex(), operator_user_id],
    )
    token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    conn.execute(
        "INSERT INTO device_tokens "
        "(id, org_id, project_id, connector_id, token_hash, expires_at, created_at) "
        "VALUES (%s, %s::uuid, %s::uuid, %s::uuid, %s, "
        "now() + interval '10 minutes', now())",
        [str(uuid.uuid4()), org_id, project_id, device_id, token_hash],
    )
    return device_id, token


def _seed_bundle(conn, org_id, project_id, sequence, bundle_signer_sk):
    """Seed a policy_bundles row.  Returns (bundle_id, envelope).

    Column names match 0007_m2_tables.py:
        policy_bundles: id, org_id, project_id, sequence,
                        bundle_blob, server_signature, created_at
    """
    payload = {
        "org_id": org_id,
        "project_id": project_id,
        "sequence": sequence,
        "base_sequence": max(0, sequence - 1),
        "registry_version": 1,
        "folder_policy": {"shell": {"blocklist_action": "deny"}},
        "governance_policy": {},
        "mcp_policy": {},
        "approval": {"local_fallback": False, "allow_requester": False},
        "change_approvals": [],
        "issued_at": time.time(),
        "not_before": time.time() - 60,
        "expires_at": time.time() + 7 * 86400,
    }
    envelope = sign_envelope("agg/bundle/v1", payload, bundle_signer_sk)
    blob = json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode()
    sig = envelope["signatures"][0]["sig"]
    bundle_id = str(uuid.uuid4())
    conn.execute(
        "INSERT INTO policy_bundles "
        "(id, org_id, project_id, sequence, bundle_blob, "
        "server_signature, created_at) "
        "VALUES (%s, %s::uuid, %s::uuid, %s, %s, %s, now())",
        [bundle_id, org_id, project_id, sequence, blob, sig],
    )
    return bundle_id, envelope


def _make_app(pg_url, *, clock=None):
    """Build a test app using the existing T9 helper.  Raises M2T9Pending."""
    from .t9_helpers import make_t9_app
    try:
        app, clock_out, _ = make_t9_app(pg_url, clock=clock)
    except Exception as exc:
        if "T9Pending" in type(exc).__name__ or "T8P2Pending" in type(exc).__name__:
            raise M2T9Pending(str(exc)) from exc
        raise
    return app, clock_out


def _make_client(app):
    """Build a Starlette TestClient.  Raises M2T9Pending on import."""
    try:
        from starlette.testclient import TestClient
    except ImportError as exc:
        raise M2T9Pending(str(exc)) from exc
    return TestClient(app, base_url="https://testserver")


# ===================================================================
# Guards (pass now -- T5 schema baseline)
# ===================================================================


@pytest.mark.pg
def test_policy_bundles_table_exists(pg_url, pg_roles, owner_url):
    """Guard: policy_bundles table exists (T5 prerequisite)."""
    ensure_at_head(pg_url)
    with psycopg.connect(_conninfo(owner_url)) as conn:
        row = conn.execute(
            "SELECT 1 FROM information_schema.tables "
            "WHERE table_schema = 'public' AND table_name = 'policy_bundles'"
        ).fetchone()
    assert row is not None, "policy_bundles table not found"


@pytest.mark.pg
def test_device_tokens_table_exists(pg_url, pg_roles, owner_url):
    """Guard: device_tokens table exists (T5 prerequisite)."""
    ensure_at_head(pg_url)
    with psycopg.connect(_conninfo(owner_url)) as conn:
        row = conn.execute(
            "SELECT 1 FROM information_schema.tables "
            "WHERE table_schema = 'public' AND table_name = 'device_tokens'"
        ).fetchone()
    assert row is not None, "device_tokens table not found"


# ===================================================================
# RED: GET /api/v1/sync/bundle -- device token auth, retrieval
# ===================================================================


@pytest.mark.pg
def test_get_bundle_returns_latest(pg_url, pg_roles, app_url, owner_url):
    """GET /api/v1/sync/bundle?after=0 returns 200 with the envelope."""
    _need("agg_cp.sync.bundles", "bundle_router")
    ensure_at_head(pg_url)
    org_id = str(seed_org_with_oidc(owner_url, slug=f"t9b-{uuid.uuid4().hex[:6]}"))
    project_id = str(uuid.uuid4())
    bsk, _, _ = keygen()
    with psycopg.connect(_conninfo(owner_url), autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        create_project(conn, org_id, project_id)
        _seed_bundle(conn, org_id, project_id, 1, bsk)
        _, token = _seed_device(conn, org_id, project_id)

    app, _ = _make_app(pg_url)
    client = _make_client(app)
    resp = client.get(
        "/api/v1/sync/bundle",
        params={"after": "0"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["kind"] == "agg/bundle/v1"
    assert body["sig_v"] == 1
    assert "payload" in body
    assert "signatures" in body


@pytest.mark.pg
def test_get_bundle_204_when_none(pg_url, pg_roles, app_url, owner_url):
    """GET /api/v1/sync/bundle?after=99 returns 204 when no newer bundle."""
    _need("agg_cp.sync.bundles", "bundle_router")
    ensure_at_head(pg_url)
    org_id = str(seed_org_with_oidc(owner_url, slug=f"t9bn-{uuid.uuid4().hex[:6]}"))
    project_id = str(uuid.uuid4())
    bsk, _, _ = keygen()
    with psycopg.connect(_conninfo(owner_url), autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        create_project(conn, org_id, project_id)
        _seed_bundle(conn, org_id, project_id, 1, bsk)
        _, token = _seed_device(conn, org_id, project_id)

    app, _ = _make_app(pg_url)
    client = _make_client(app)
    resp = client.get(
        "/api/v1/sync/bundle",
        params={"after": "99"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 204


@pytest.mark.pg
def test_get_bundle_no_auth_401(pg_url, pg_roles, app_url, owner_url):
    """GET /api/v1/sync/bundle without a token returns 401."""
    _need("agg_cp.sync.bundles", "bundle_router")
    ensure_at_head(pg_url)
    app, _ = _make_app(pg_url)
    client = _make_client(app)
    resp = client.get("/api/v1/sync/bundle", params={"after": "0"})
    assert resp.status_code == 401


@pytest.mark.pg
def test_get_bundle_bad_token_401(pg_url, pg_roles, app_url, owner_url):
    """GET /api/v1/sync/bundle with an invalid token returns 401."""
    _need("agg_cp.sync.bundles", "bundle_router")
    ensure_at_head(pg_url)
    app, _ = _make_app(pg_url)
    client = _make_client(app)
    resp = client.get(
        "/api/v1/sync/bundle",
        params={"after": "0"},
        headers={"Authorization": "Bearer fake-token-invalid"},
    )
    assert resp.status_code == 401


# ===================================================================
# RED: cross-project/cross-org on GET (threat 29, RLS)
# ===================================================================


@pytest.mark.pg
def test_cross_project_bundle_get_204(pg_url, pg_roles, app_url, owner_url):
    """A device for project A gets 204 for project B bundles (threat 29)."""
    _need("agg_cp.sync.bundles", "bundle_router")
    ensure_at_head(pg_url)
    org_id = str(seed_org_with_oidc(owner_url, slug=f"t9cp-{uuid.uuid4().hex[:6]}"))
    project_a = str(uuid.uuid4())
    project_b = str(uuid.uuid4())
    bsk, _, _ = keygen()
    with psycopg.connect(_conninfo(owner_url), autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        create_project(conn, org_id, project_a)
        create_project(conn, org_id, project_b)
        _seed_bundle(conn, org_id, project_b, 1, bsk)
        _, token = _seed_device(conn, org_id, project_a)

    app, _ = _make_app(pg_url)
    client = _make_client(app)
    resp = client.get(
        "/api/v1/sync/bundle",
        params={"after": "0"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 204


@pytest.mark.pg
def test_cross_org_bundle_get_204(pg_url, pg_roles, app_url, owner_url):
    """A device in org A gets 204 for org B bundles (threat 29, RLS)."""
    _need("agg_cp.sync.bundles", "bundle_router")
    ensure_at_head(pg_url)
    org_a = str(seed_org_with_oidc(owner_url, slug=f"t9oa-{uuid.uuid4().hex[:6]}"))
    org_b = str(seed_org_with_oidc(owner_url, slug=f"t9ob-{uuid.uuid4().hex[:6]}"))
    project_a = str(uuid.uuid4())
    project_b = str(uuid.uuid4())
    bsk, _, _ = keygen()
    with psycopg.connect(_conninfo(owner_url), autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_a])
        create_project(conn, org_a, project_a)
        _, token = _seed_device(conn, org_a, project_a)
    with psycopg.connect(_conninfo(owner_url), autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_b])
        create_project(conn, org_b, project_b)
        _seed_bundle(conn, org_b, project_b, 1, bsk)

    app, _ = _make_app(pg_url)
    client = _make_client(app)
    resp = client.get(
        "/api/v1/sync/bundle",
        params={"after": "0"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 204


# ===================================================================
# RED: POST /api/v1/admin/bundles -- admin creates a bundle
# ===================================================================


@pytest.fixture(autouse=True)
def _bundle_signer_key_env(tmp_path_factory, monkeypatch):
    """F2 setup: provide AGG_BUNDLE_SIGNER_KEY_FILE for admin-create tests.

    Writes a hex-encoded Ed25519 seed to a tmp file in the format that
    ``_load_bundle_signer_key`` in ``ee/src/agg_cp/sync/bundles.py`` reads.
    Autouse so that existing admin-create tests keep their assertions
    unchanged (the server signs with this key instead of an ephemeral one).

    Node ids touched (setup-only fixture):
        test_admin_create_bundle
        test_admin_create_bundle_no_csrf_403
        test_admin_bundle_sequence_conflict_409
    """
    from nacl.signing import SigningKey as _SK
    key_dir = tmp_path_factory.mktemp("bundle_signer")
    key_file = key_dir / "bundle_signer.key"
    sk = _SK.generate()
    key_file.write_bytes(bytes(sk).hex().encode("ascii"))
    monkeypatch.setenv("AGG_BUNDLE_SIGNER_KEY_FILE", str(key_file))


@pytest.mark.pg
def test_admin_create_bundle_no_signer_key_500(
    pg_url, pg_roles, app_url, owner_url, monkeypatch,
):
    """F2: POST /api/v1/admin/bundles with no AGG_BUNDLE_SIGNER_KEY_FILE
    returns 500 {error: bundle_signer_key_not_configured}; no ephemeral
    key path."""
    _need("agg_cp.sync.bundles", "bundle_router")
    monkeypatch.delenv("AGG_BUNDLE_SIGNER_KEY_FILE", raising=False)
    ensure_at_head(pg_url)
    org_id = seed_org_with_oidc(owner_url, slug=f"t9nk-{uuid.uuid4().hex[:6]}")
    admin_id, _ = seed_user(owner_url, org_id)
    seed_admin_binding(owner_url, org_id, admin_id)
    project_id = str(uuid.uuid4())
    with psycopg.connect(_conninfo(owner_url), autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [str(org_id)])
        create_project(conn, str(org_id), project_id)

    clock = FakeClock()
    session_token, csrf_token, _ = seed_session(
        owner_url, org_id, admin_id, clock=clock
    )
    cookie = make_session_cookie(org_id, session_token)

    app, _ = _make_app(pg_url, clock=clock)
    client = _make_client(app)

    resp = client.post(
        "/api/v1/admin/bundles",
        json={"project_id": project_id, "bundle_payload": {},
              "change_approvals": []},
        headers={"X-CSRF-Token": csrf_token},
        cookies={"__Host-agg_session": cookie},
    )
    assert resp.status_code == 500
    assert resp.json().get("error") == "bundle_signer_key_not_configured"


@pytest.mark.pg
def test_admin_create_bundle(pg_url, pg_roles, app_url, owner_url):
    """POST /api/v1/admin/bundles returns 200 {bundle_id, sequence}."""
    _need("agg_cp.sync.bundles", "bundle_router")
    ensure_at_head(pg_url)
    org_id = seed_org_with_oidc(owner_url, slug=f"t9ab-{uuid.uuid4().hex[:6]}")
    admin_id, _ = seed_user(owner_url, org_id)
    seed_admin_binding(owner_url, org_id, admin_id)
    project_id = str(uuid.uuid4())
    with psycopg.connect(_conninfo(owner_url), autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [str(org_id)])
        create_project(conn, str(org_id), project_id)

    clock = FakeClock()
    session_token, csrf_token, _ = seed_session(
        owner_url, org_id, admin_id, clock=clock
    )
    cookie = make_session_cookie(org_id, session_token)

    app, _ = _make_app(pg_url, clock=clock)
    client = _make_client(app)

    bundle_payload = {
        "org_id": str(org_id),
        "project_id": project_id,
        "sequence": 1,
        "base_sequence": 0,
        "registry_version": 1,
        "folder_policy": {"shell": {"blocklist_action": "deny"}},
        "governance_policy": {},
        "mcp_policy": {},
        "approval": {"local_fallback": False, "allow_requester": False},
        "change_approvals": [],
        "issued_at": time.time(),
        "not_before": time.time() - 60,
        "expires_at": time.time() + 7 * 86400,
    }

    resp = client.post(
        "/api/v1/admin/bundles",
        json={"project_id": project_id, "bundle_payload": bundle_payload,
              "change_approvals": []},
        headers={"X-CSRF-Token": csrf_token},
        cookies={"__Host-agg_session": cookie},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert isinstance(body["bundle_id"], str)
    assert body["sequence"] == 1


@pytest.mark.pg
def test_admin_create_bundle_no_csrf_403(pg_url, pg_roles, app_url, owner_url):
    """POST /api/v1/admin/bundles without CSRF token returns 403."""
    _need("agg_cp.sync.bundles", "bundle_router")
    ensure_at_head(pg_url)
    org_id = seed_org_with_oidc(owner_url, slug=f"t9ac-{uuid.uuid4().hex[:6]}")
    admin_id, _ = seed_user(owner_url, org_id)
    seed_admin_binding(owner_url, org_id, admin_id)

    clock = FakeClock()
    session_token, csrf_token, _ = seed_session(
        owner_url, org_id, admin_id, clock=clock
    )
    cookie = make_session_cookie(org_id, session_token)

    app, _ = _make_app(pg_url, clock=clock)
    client = _make_client(app)

    resp = client.post(
        "/api/v1/admin/bundles",
        json={"project_id": str(uuid.uuid4()), "bundle_payload": {},
              "change_approvals": []},
        cookies={"__Host-agg_session": cookie},
    )
    assert resp.status_code == 403


# ===================================================================
# RED: sequence conflict (threat 7, server side)
# ===================================================================


@pytest.mark.pg
def test_admin_bundle_sequence_conflict_409(pg_url, pg_roles, app_url, owner_url):
    """POST /api/v1/admin/bundles with existing sequence returns 409."""
    _need("agg_cp.sync.bundles", "bundle_router")
    ensure_at_head(pg_url)
    org_id = seed_org_with_oidc(owner_url, slug=f"t9sc-{uuid.uuid4().hex[:6]}")
    admin_id, _ = seed_user(owner_url, org_id)
    seed_admin_binding(owner_url, org_id, admin_id)
    project_id = str(uuid.uuid4())
    bsk, _, _ = keygen()
    with psycopg.connect(_conninfo(owner_url), autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [str(org_id)])
        create_project(conn, str(org_id), project_id)
        _seed_bundle(conn, str(org_id), project_id, 1, bsk)

    clock = FakeClock()
    session_token, csrf_token, _ = seed_session(
        owner_url, org_id, admin_id, clock=clock
    )
    cookie = make_session_cookie(org_id, session_token)

    app, _ = _make_app(pg_url, clock=clock)
    client = _make_client(app)

    bundle_payload = {
        "org_id": str(org_id),
        "project_id": project_id,
        "sequence": 1,
        "base_sequence": 0,
        "registry_version": 1,
        "folder_policy": {},
        "governance_policy": {},
        "mcp_policy": {},
        "approval": {},
        "change_approvals": [],
        "issued_at": time.time(),
        "not_before": time.time() - 60,
        "expires_at": time.time() + 86400,
    }

    resp = client.post(
        "/api/v1/admin/bundles",
        json={"project_id": project_id, "bundle_payload": bundle_payload,
              "change_approvals": []},
        headers={"X-CSRF-Token": csrf_token},
        cookies={"__Host-agg_session": cookie},
    )
    assert resp.status_code == 409
