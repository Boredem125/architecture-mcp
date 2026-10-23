"""Enroll-persistence follow-up: GET /api/v1/sync/registry route tests.

The route returns the org's registry chain (version order) to enrolled
devices authenticated by a device bearer token.  Auth pattern matches
GET /api/v1/sync/bundle in ``ee/src/agg_cp/sync/bundles.py``.

RED tests xfail on M2EnrollPersistPending.

Covers:
- Valid device token returns the org's chain in version order.
- Cross-org device never gets another org's rows.
- No token / bad token / revoked device gives 401.
- Session cookie without a device token gives 401.
"""
from __future__ import annotations

import hashlib
import json
import secrets
import time
import uuid

import psycopg
import pytest
from starlette.testclient import TestClient

from .m2_pending import M2EnrollPersistPending
from .m2_sync_server import (
    ensure_at_head, create_org, create_project,
    keygen, sign_envelope, canonical_json,
)
from .t8p2_helpers import (
    seed_org_with_oidc, seed_user, seed_admin_binding,
)
from .t9_helpers import seed_session, make_session_cookie


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _need(module: str, attr: str) -> None:
    try:
        mod = __import__(module, fromlist=[attr])
    except ImportError:
        raise M2EnrollPersistPending(f"{module} not importable")
    if not hasattr(mod, attr):
        raise M2EnrollPersistPending(f"{module}.{attr} not found")


def _conninfo(url: str) -> str:
    return url.replace("+psycopg", "")


def _seed_device(conn, org_id, project_id):
    """Seed a connector + device_tokens row.  Returns (device_id, token)."""
    device_id = str(uuid.uuid4())
    sk, pub, kid = keygen()
    conn.execute(
        "INSERT INTO connectors "
        "(id, org_id, project_id, device_public_key, operator_user_id, created_at) "
        "VALUES (%s, %s::uuid, %s::uuid, %s, %s, now())",
        [device_id, org_id, project_id, pub.hex(), None],
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


def _seed_genesis(conn, org_id):
    """Store a genesis registry version.  Returns the envelope and admin sk.

    Uses separate keys for admin and bundle_signer (F3: no collision).
    """
    from agg_cp.sync.registry import store_registry_version

    sk_admin, pub_admin, kid_admin = keygen()
    sk_bs, pub_bs, kid_bs = keygen()
    key_entry = {
        "key_id": kid_admin, "public_key": pub_admin.hex(), "user_id": "admin-0",
        "iss": "https://idp", "sub": "admin-0", "alg": "ed25519",
        "kind": "cli", "roles": ["admin", "approver"], "added_in": 1,
    }
    payload = {
        "org_id": org_id, "version": 1, "prev_hash": "",
        "threshold": 1, "admins": [kid_admin], "keys": [key_entry],
        "bundle_signer": {"key_id": kid_bs, "public_key": pub_bs.hex(), "alg": "ed25519"},
        "expires_at": time.time() + 7 * 86400,
    }
    envelope = sign_envelope("agg/registry/v1", payload, sk_admin)
    store_registry_version(conn, org_id, envelope)
    return envelope, sk_admin


def _make_app(pg_url):
    """Build an app; raises M2EnrollPersistPending if the route is absent."""
    try:
        from agg_cp.app import create_app
        app = create_app(database_url=pg_url)
        return app
    except Exception as exc:
        raise M2EnrollPersistPending(f"create_app failed: {exc}") from exc


# ===================================================================
# RED: device token returns org's chain in version order
# ===================================================================


@pytest.mark.pg
def test_registry_returns_chain_in_version_order(pg_url, pg_roles, app_url, owner_url):
    """GET /api/v1/sync/registry with valid device token returns the chain."""
    _need("agg_cp.sync.enroll", "enroll_router")
    ensure_at_head(pg_url)
    app = _make_app(app_url)

    org_id = str(uuid.uuid4())
    project_id = str(uuid.uuid4())

    with psycopg.connect(_conninfo(owner_url), autocommit=True) as oconn:
        oconn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        create_org(oconn, org_id)
        create_project(oconn, org_id, project_id)
        genesis_env, admin_sk = _seed_genesis(oconn, org_id)
        device_id, token = _seed_device(oconn, org_id, project_id)

    client = TestClient(app)
    resp = client.get(
        "/api/v1/sync/registry",
        headers={"Authorization": f"Bearer {token}"},
    )
    if resp.status_code == 404:
        raise M2EnrollPersistPending("GET /api/v1/sync/registry route not found")

    assert resp.status_code == 200, f"expected 200, got {resp.status_code}: {resp.text}"
    body = resp.json()
    registry = body.get("registry")
    assert isinstance(registry, list), "response must have a 'registry' list"
    assert len(registry) >= 1, "chain must have at least the genesis"
    # Genesis must be version 1
    assert registry[0].get("payload", {}).get("version") == 1
    # Chain must be in version order
    versions = [e.get("payload", {}).get("version") for e in registry]
    assert versions == sorted(versions), f"chain not in version order: {versions}"


# ===================================================================
# RED: cross-org device never gets another org's rows
# ===================================================================


@pytest.mark.pg
def test_registry_cross_org_device_gets_own_chain(pg_url, pg_roles, app_url, owner_url):
    """A device in org_a never sees org_b's registry chain."""
    _need("agg_cp.sync.enroll", "enroll_router")
    ensure_at_head(pg_url)
    app = _make_app(app_url)

    org_a, org_b = str(uuid.uuid4()), str(uuid.uuid4())
    proj_a, proj_b = str(uuid.uuid4()), str(uuid.uuid4())

    with psycopg.connect(_conninfo(owner_url), autocommit=True) as oconn:
        for oid, pid in [(org_a, proj_a), (org_b, proj_b)]:
            oconn.execute("SELECT set_config('app.org_id', %s, false)", [oid])
            create_org(oconn, oid)
            create_project(oconn, oid, pid)
            _seed_genesis(oconn, oid)

        oconn.execute("SELECT set_config('app.org_id', %s, false)", [org_a])
        _, token_a = _seed_device(oconn, org_a, proj_a)

    client = TestClient(app)
    resp = client.get(
        "/api/v1/sync/registry",
        headers={"Authorization": f"Bearer {token_a}"},
    )
    if resp.status_code == 404:
        raise M2EnrollPersistPending("GET /api/v1/sync/registry route not found")

    assert resp.status_code == 200
    body = resp.json()
    registry = body.get("registry", [])
    for i, env in enumerate(registry):
        env_org = str(env.get("payload", {}).get("org_id", ""))
        assert env_org == org_a, (
            f"chain entry {i} has org_id={env_org!r}, expected {org_a!r}"
        )


# ===================================================================
# RED: no token gives 401
# ===================================================================


@pytest.mark.pg
def test_registry_no_token_401(pg_url, pg_roles, app_url, owner_url):
    """GET /api/v1/sync/registry without Authorization header returns 401."""
    _need("agg_cp.sync.enroll", "enroll_router")
    ensure_at_head(pg_url)
    app = _make_app(app_url)

    client = TestClient(app)
    resp = client.get("/api/v1/sync/registry")
    if resp.status_code == 404:
        raise M2EnrollPersistPending("GET /api/v1/sync/registry route not found")

    assert resp.status_code == 401


# ===================================================================
# RED: bad token gives 401
# ===================================================================


@pytest.mark.pg
def test_registry_bad_token_401(pg_url, pg_roles, app_url, owner_url):
    """GET /api/v1/sync/registry with an invalid token returns 401."""
    _need("agg_cp.sync.enroll", "enroll_router")
    ensure_at_head(pg_url)
    app = _make_app(app_url)

    client = TestClient(app)
    resp = client.get(
        "/api/v1/sync/registry",
        headers={"Authorization": "Bearer fake-token-invalid"},
    )
    if resp.status_code == 404:
        raise M2EnrollPersistPending("GET /api/v1/sync/registry route not found")

    assert resp.status_code == 401


# ===================================================================
# RED: revoked device gives 401
# ===================================================================


@pytest.mark.pg
def test_registry_revoked_device_401(pg_url, pg_roles, app_url, owner_url):
    """GET /api/v1/sync/registry with a revoked device's token returns 401."""
    _need("agg_cp.sync.enroll", "enroll_router")
    ensure_at_head(pg_url)
    app = _make_app(app_url)

    org_id = str(uuid.uuid4())
    project_id = str(uuid.uuid4())

    with psycopg.connect(_conninfo(owner_url), autocommit=True) as oconn:
        oconn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        create_org(oconn, org_id)
        create_project(oconn, org_id, project_id)
        _seed_genesis(oconn, org_id)
        device_id, token = _seed_device(oconn, org_id, project_id)
        # Revoke the device by deleting its token
        oconn.execute(
            "DELETE FROM device_tokens WHERE connector_id = %s::uuid",
            [device_id],
        )

    client = TestClient(app)
    resp = client.get(
        "/api/v1/sync/registry",
        headers={"Authorization": f"Bearer {token}"},
    )
    if resp.status_code == 404:
        raise M2EnrollPersistPending("GET /api/v1/sync/registry route not found")

    assert resp.status_code == 401


# ===================================================================
# RED: session cookie without device token gives 401
# ===================================================================


@pytest.mark.pg
def test_registry_session_cookie_no_device_token_401(pg_url, pg_roles, app_url, owner_url):
    """GET /api/v1/sync/registry with only a session cookie (no Bearer) returns 401."""
    _need("agg_cp.sync.enroll", "enroll_router")
    ensure_at_head(pg_url)
    app = _make_app(app_url)

    from .fake_idp import FakeClock
    org_id = str(uuid.uuid4())
    with psycopg.connect(_conninfo(owner_url), autocommit=True) as oconn:
        oconn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        create_org(oconn, org_id)

    admin_id = seed_org_with_oidc(owner_url, slug=f"reg-{uuid.uuid4().hex[:6]}")
    # Use a session cookie but no Bearer token
    user_id, _ = seed_user(owner_url, admin_id)
    seed_admin_binding(owner_url, admin_id, user_id)
    clock = FakeClock()
    token, csrf, _ = seed_session(owner_url, admin_id, user_id, clock=clock)
    cookie = make_session_cookie(admin_id, token)

    client = TestClient(app)
    resp = client.get(
        "/api/v1/sync/registry",
        cookies={"__Host-agg_session": cookie},
    )
    if resp.status_code == 404:
        raise M2EnrollPersistPending("GET /api/v1/sync/registry route not found")

    assert resp.status_code == 401, (
        f"expected 401 for session-cookie-only auth, got {resp.status_code}"
    )
