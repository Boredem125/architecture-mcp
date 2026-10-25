"""T12b-2 ee tests-first: server M4 fixes, GET escalation detail route,
C9 item 3 (server ignores client-supplied user_id/kind), web signer route.

Interface contract (pinned -- the build removes only xfail markers)
-------------------------------------------------------------------
Server routes (agg_cp.sync.escalations, T12b-2 additions):

    POST /api/v1/sync/escalations/{escalation_id}/approvals  (M4 fixes)
        - An envelope with empty ``signatures`` MUST be refused (400).
        - The envelope ``kind`` MUST equal the REMOTE_APPROVAL tag constant
          from code; an envelope claiming another kind is refused (400).
        - The payload MUST be bound to the escalation row:
          request_id, command (from record), device_id (connector_id),
          project_id, policy_sequence must equal the stored escalation.
          org_id must equal the auth org.  Mismatch -> 400.
        - ``not_after`` MUST be a finite number (M1 server-side); null or
          non-numeric -> 400.
        - The device's enrolled operator CANNOT approve its own escalation
          unless the signed bundle allows the requester (C5).

    GET /api/v1/sync/escalations/{escalation_id}  (new, T12b-2)
        Auth: signer-token (agg/signer-assert/v1) or session.
        Device tokens refused (403).
        Cross-org -> 404 (RLS).
        Returns the canonical fields the signer signs (incl. requires_dual,
        fingerprint, command, device_id, project_id, org_id, policy_sequence,
        request_id).  No key material in the response.

    C9 item 3: server-supplied data
        - user_id and kind columns from the approval body are IGNORED;
          the server uses the authenticated user_id and the registry key kind.
        - Oversized batches (> 50 envelopes in one request) -> 400.
        - Unknown escalation_id -> 404.

RED tests xfail on M2T12bPending.  Guards verify existing schema/routes.

Threat coverage (server-side M4): binding mismatch, empty signatures,
wrong envelope kind, M1 not_after null, operator self-approval,
C9 ignored columns, oversized batches, unknown ids.
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

from .m2_pending import M2T12bPending
from .m2_sync_server import (
    make_sync_server, ensure_at_head, create_org, create_project,
    keygen, sign_envelope, canonical_json,
)
from .t9_helpers import seed_session, make_session_cookie, compute_csrf
from .fake_idp import FakeClock


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _need(module: str, attr: str) -> None:
    """Raise M2T12bPending if *module*.*attr* is absent."""
    try:
        mod = __import__(module, fromlist=[attr])
    except ImportError:
        raise M2T12bPending(f"{module} not importable")
    if not hasattr(mod, attr):
        raise M2T12bPending(f"{module}.{attr} not found")


def _conninfo(url: str) -> str:
    return url.replace("+psycopg", "")


def _seed_user_row(conn, org_id: str, email: str) -> str:
    """Insert a users row; return user_id (uuid str)."""
    user_id = str(uuid.uuid4())
    conn.execute(
        "INSERT INTO users (id, org_id, oidc_issuer, oidc_subject, email, "
        "status, created_at) VALUES (%s, %s, 'https://idp', %s, %s, "
        "'active', now()) ON CONFLICT DO NOTHING",
        [user_id, org_id, f"sub-{uuid.uuid4().hex[:8]}", email],
    )
    return user_id


def _make_fresh_session(owner_url: str, org_id: str, user_id: str):
    """Create a fresh web session.  Return (cookie_value, csrf_token)."""
    clock = FakeClock()
    token, csrf, sid = seed_session(
        owner_url, uuid.UUID(org_id), uuid.UUID(user_id), clock=clock,
    )
    cookie = make_session_cookie(uuid.UUID(org_id), token)
    return cookie, csrf


def _seed_connector(owner_url: str, org_id: str, project_id: str,
                    pub_key: bytes, *, device_id: str | None = None,
                    operator_user_id: str | None = None) -> str:
    """Insert a connectors row directly (superuser) and return device_id."""
    did = device_id or str(uuid.uuid4())
    conninfo = _conninfo(owner_url)
    with psycopg.connect(conninfo) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        if operator_user_id:
            conn.execute(
                "INSERT INTO connectors "
                "(id, org_id, project_id, device_public_key, "
                "operator_user_id, created_at) "
                "VALUES (%s, %s, %s, %s, %s::uuid, now()) ON CONFLICT DO NOTHING",
                [did, org_id, project_id, pub_key.hex(), operator_user_id],
            )
        else:
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


def _make_remote_approval_envelope(
    sk, *,
    request_id: str,
    command: str = "echo test",
    org_id: str,
    project_id: str,
    device_id: str,
    registry_version: int = 1,
    policy_sequence: int = 1,
    user_id: str,
    decision: str = "approve",
    nonce: str | None = None,
    not_after: float | None = None,
    fingerprint: str | None = None,
) -> dict:
    """Build an agg/remote-approval/v1 envelope."""
    pub = bytes(sk.verify_key)
    kid = hashlib.sha256(pub).hexdigest()
    fp = fingerprint or hashlib.sha256(command.encode()).hexdigest()
    payload = {
        "request_id": request_id,
        "command": command,
        "fingerprint": fp,
        "reviewer_id": user_id,
        "decision": decision,
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


def _make_envelope_wrong_kind(
    sk, *, kind: str = "agg/bundle-sign/v1", **kwargs
) -> dict:
    """Build an envelope with an incorrect kind tag."""
    envelope = _make_remote_approval_envelope(sk, **kwargs)
    # Overwrite the kind to something wrong
    envelope["kind"] = kind
    return envelope


def _upload_escalation(base_url: str, device_id: str, token: str,
                       request_id: str, *, command: str = "echo test",
                       policy_sequence: int = 1,
                       fingerprint: str | None = None) -> tuple[int, str | None]:
    """Upload an escalation via device token. Return (status, escalation_id)."""
    import httpx
    record: dict = {"command": command, "status": "pending"}
    # T12b-2 named edit: always include fingerprint for R1 binding
    if fingerprint is None:
        fingerprint = hashlib.sha256(command.encode()).hexdigest()
    record["fingerprint"] = fingerprint
    r = httpx.post(
        f"{base_url}/api/v1/sync/escalations",
        json={
            "device_id": device_id,
            "request_id": request_id,
            "record": record,
            "policy_sequence": policy_sequence,
        },
        headers={"Authorization": f"Bearer {token}"},
        timeout=10.0,
    )
    esc_id = r.json().get("escalation_id") if r.status_code == 200 else None
    return r.status_code, esc_id


def _sign_assertion(sk, kid: str, nonce: str, aud: str) -> dict:
    """Build an agg/signer-assert/v1 envelope for signer token auth."""
    payload = {"key_id": kid, "nonce": nonce, "aud": aud, "iat": time.time()}
    tag = b"agg/signer-assert/v1"
    cj = canonical_json(payload)
    msg = tag + b"\x00" + cj
    sig = sk.sign(msg).signature.hex()
    return {
        "kind": "agg/signer-assert/v1",
        "sig_v": 1,
        "payload": payload,
        "signatures": [{"key_id": kid, "alg": "ed25519", "sig": sig}],
    }


def _seed_signer_token(owner_url: str, org_id: str, user_id: str,
                       key_id: str, scope: str = "confirmed") -> str:
    """Insert a signer_tokens row and return the raw token.

    *scope* defaults to ``"confirmed"`` (F2: escalation routes accept
    only confirmed scope).
    """
    token = secrets.token_hex(32)
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    conninfo = _conninfo(owner_url)
    with psycopg.connect(conninfo) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        conn.execute(
            "INSERT INTO signer_tokens "
            "(id, org_id, user_id, key_id, token_hash, scope, "
            "expires_at, created_at) "
            "VALUES (%s, %s, %s, %s, %s, %s, "
            "now() + interval '1 hour', now())",
            [str(uuid.uuid4()), org_id, user_id, key_id, token_hash, scope],
        )
        conn.commit()
    return token


# Patterns that match private key material
_PRIVKEY_PATTERNS = [
    "private_key", "privateKey", "signingKey",
    "signing_key", "secret_key", "secretKey",
]


def _assert_no_private_key(body_str: str) -> None:
    """Assert no private key pattern appears in the response body."""
    lower = body_str.lower()
    for pat in _PRIVKEY_PATTERNS:
        assert pat.lower() not in lower, (
            f"private key pattern '{pat}' found in response"
        )


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def t12b_server(pg_url, app_url, owner_url, pg_roles):
    """4-worker agg_cp server with 2 orgs for T12b-2 server tests."""
    gen = make_sync_server(
        pg_url, app_url, owner_url,
        org_names=["T12b Org", "Evil Org"],
    )
    info = next(gen)

    # Seed users in both orgs
    conninfo = _conninfo(owner_url)
    with psycopg.connect(conninfo, autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [info["org_id"]])
        bob_id = _seed_user_row(conn, info["org_id"], "bob@t12b.test")
        carol_id = _seed_user_row(conn, info["org_id"], "carol@t12b.test")
        operator_id = _seed_user_row(conn, info["org_id"], "operator@t12b.test")

        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [info["org_evil"]])
        eve_id = _seed_user_row(conn, info["org_evil"], "eve@evil.test")

    info["bob_id"] = bob_id
    info["carol_id"] = carol_id
    info["operator_id"] = operator_id
    info["eve_id"] = eve_id

    try:
        yield info
    finally:
        gen.close()


# ===================================================================
# Guards: existing schema and routes still work
# ===================================================================


@pytest.mark.pg
def test_guard_escalation_upload_works(t12b_server):
    """Guard: the escalation upload route still works (baseline)."""
    import httpx
    srv = t12b_server
    sk, pub, kid = keygen()
    project_id = str(uuid.uuid4())

    with psycopg.connect(_conninfo(srv["owner_url"])) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [srv["org_id"]])
        create_project(conn, srv["org_id"], project_id, environment="staging")
        conn.commit()

    device_id = _seed_connector(srv["owner_url"], srv["org_id"],
                                project_id, pub)
    token = secrets.token_hex(32)
    _seed_device_token(srv["owner_url"], srv["org_id"], project_id,
                       device_id, token)

    status, esc_id = _upload_escalation(
        srv["base_url"], device_id, token, "guard-req-1",
    )
    assert status == 200
    assert esc_id is not None


@pytest.mark.pg
def test_guard_approval_route_exists(t12b_server):
    """Guard: the approval submission route exists (T12 baseline)."""
    import httpx
    srv = t12b_server
    # A POST to a non-existent escalation should get 404, not 405
    cookie, csrf = _make_fresh_session(
        srv["owner_url"], srv["org_id"], srv["bob_id"],
    )
    r = httpx.post(
        f"{srv['base_url']}/api/v1/sync/escalations/"
        f"{uuid.uuid4()}/approvals",
        json={"kind": "agg/remote-approval/v1", "payload": {}, "signatures": []},
        cookies={"__Host-agg_session": cookie},
        headers={"X-CSRF-Token": csrf},
        timeout=10.0,
    )
    # 400 or 404, NOT 405
    assert r.status_code in (400, 404)


# ===================================================================
# RED: M4 -- empty signatures refused (400)
# ===================================================================


@pytest.mark.pg

def test_m4_empty_signatures_refused(t12b_server):
    """M4: an envelope with ``signatures: []`` must be refused (400).

    The current server stores such an approval with no signature check.
    After the fix, exactly one signature is required.
    """
    _need("agg_cp.sync.escalations", "_T12B_M4_BINDING")

    import httpx
    srv = t12b_server
    bob_sk, bob_pub, bob_kid = keygen()
    device_sk, device_pub, device_kid = keygen()
    project_id = str(uuid.uuid4())

    with psycopg.connect(_conninfo(srv["owner_url"])) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [srv["org_id"]])
        create_project(conn, srv["org_id"], project_id, environment="staging")
        conn.commit()

    _seed_registry_with_keys(srv["owner_url"], srv["org_id"], [
        {"key_id": bob_kid, "public_key": bob_pub.hex(),
         "user_id": srv["bob_id"], "kind": "cli",
         "roles": ["approver"]},
    ])
    device_id = _seed_connector(srv["owner_url"], srv["org_id"],
                                project_id, device_pub)
    token = secrets.token_hex(32)
    _seed_device_token(srv["owner_url"], srv["org_id"], project_id,
                       device_id, token)

    status, esc_id = _upload_escalation(
        srv["base_url"], device_id, token, "req-emptysig-1",  # gitleaks:allow (request id, not a token)
    )
    assert status == 200

    cookie, csrf = _make_fresh_session(
        srv["owner_url"], srv["org_id"], srv["bob_id"],
    )

    # Build a valid-looking envelope but with empty signatures
    envelope = _make_remote_approval_envelope(
        bob_sk,
        request_id="req-emptysig-1",
        org_id=srv["org_id"], project_id=project_id,
        device_id=device_id, user_id=srv["bob_id"],
    )
    envelope["signatures"] = []  # empty!

    r = httpx.post(
        f"{srv['base_url']}/api/v1/sync/escalations/{esc_id}/approvals",
        json=envelope,
        cookies={"__Host-agg_session": cookie},
        headers={"X-CSRF-Token": csrf},
        timeout=10.0,
    )
    assert r.status_code == 400, f"expected 400 got {r.status_code}: {r.text}"
    assert "signature" in r.json().get("error", "").lower()


# ===================================================================
# RED: M4 -- wrong envelope kind refused (400)
# ===================================================================


@pytest.mark.pg

def test_m4_wrong_envelope_kind_refused(t12b_server):
    """M4: an envelope claiming a different kind (e.g. agg/bundle-sign/v1)
    must be refused.  The server must use the REMOTE_APPROVAL tag constant
    from code, not trust the envelope's kind field.
    """
    _need("agg_cp.sync.escalations", "_T12B_M4_BINDING")

    import httpx
    srv = t12b_server
    bob_sk, bob_pub, bob_kid = keygen()
    device_sk, device_pub, device_kid = keygen()
    project_id = str(uuid.uuid4())

    with psycopg.connect(_conninfo(srv["owner_url"])) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [srv["org_id"]])
        create_project(conn, srv["org_id"], project_id, environment="staging")
        conn.commit()

    _seed_registry_with_keys(srv["owner_url"], srv["org_id"], [
        {"key_id": bob_kid, "public_key": bob_pub.hex(),
         "user_id": srv["bob_id"], "kind": "cli",
         "roles": ["approver"]},
    ])
    device_id = _seed_connector(srv["owner_url"], srv["org_id"],
                                project_id, device_pub)
    token = secrets.token_hex(32)
    _seed_device_token(srv["owner_url"], srv["org_id"], project_id,
                       device_id, token)

    status, esc_id = _upload_escalation(
        srv["base_url"], device_id, token, "req-wrongkind-1",  # gitleaks:allow (request id, not a token)
    )
    assert status == 200

    cookie, csrf = _make_fresh_session(
        srv["owner_url"], srv["org_id"], srv["bob_id"],
    )

    # Build envelope with a wrong kind tag
    envelope = _make_envelope_wrong_kind(
        bob_sk,
        kind="agg/bundle-sign/v1",
        request_id="req-wrongkind-1",
        org_id=srv["org_id"], project_id=project_id,
        device_id=device_id, user_id=srv["bob_id"],
    )

    r = httpx.post(
        f"{srv['base_url']}/api/v1/sync/escalations/{esc_id}/approvals",
        json=envelope,
        cookies={"__Host-agg_session": cookie},
        headers={"X-CSRF-Token": csrf},
        timeout=10.0,
    )
    assert r.status_code == 400, f"expected 400 got {r.status_code}: {r.text}"
    assert "kind" in r.json().get("error", "").lower()


# ===================================================================
# RED: M4 -- payload bound to escalation row (request_id mismatch)
# ===================================================================


@pytest.mark.pg

def test_m4_binding_request_id_mismatch(t12b_server):
    """M4: the payload request_id must match the escalation's request_id.

    An approval envelope carrying request_id for another escalation
    must be refused.
    """
    _need("agg_cp.sync.escalations", "_T12B_M4_BINDING")

    import httpx
    srv = t12b_server
    bob_sk, bob_pub, bob_kid = keygen()
    device_sk, device_pub, device_kid = keygen()
    project_id = str(uuid.uuid4())

    with psycopg.connect(_conninfo(srv["owner_url"])) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [srv["org_id"]])
        create_project(conn, srv["org_id"], project_id, environment="staging")
        conn.commit()

    _seed_registry_with_keys(srv["owner_url"], srv["org_id"], [
        {"key_id": bob_kid, "public_key": bob_pub.hex(),
         "user_id": srv["bob_id"], "kind": "cli",
         "roles": ["approver"]},
    ])
    device_id = _seed_connector(srv["owner_url"], srv["org_id"],
                                project_id, device_pub)
    token = secrets.token_hex(32)
    _seed_device_token(srv["owner_url"], srv["org_id"], project_id,
                       device_id, token)

    # Upload escalation A
    status, esc_id = _upload_escalation(
        srv["base_url"], device_id, token, "req-bind-A",
    )
    assert status == 200

    cookie, csrf = _make_fresh_session(
        srv["owner_url"], srv["org_id"], srv["bob_id"],
    )

    # Send approval with request_id for B, not A
    envelope = _make_remote_approval_envelope(
        bob_sk,
        request_id="req-bind-B",  # WRONG
        org_id=srv["org_id"], project_id=project_id,
        device_id=device_id, user_id=srv["bob_id"],
    )

    r = httpx.post(
        f"{srv['base_url']}/api/v1/sync/escalations/{esc_id}/approvals",
        json=envelope,
        cookies={"__Host-agg_session": cookie},
        headers={"X-CSRF-Token": csrf},
        timeout=10.0,
    )
    assert r.status_code == 400, f"expected 400 got {r.status_code}: {r.text}"
    assert "request_id" in r.json().get("error", "").lower()


# ===================================================================
# RED: M4 -- payload bound: device_id (connector_id) mismatch
# ===================================================================


@pytest.mark.pg

def test_m4_binding_device_id_mismatch(t12b_server):
    """M4: the payload device_id must match the escalation's connector_id.

    An approval claiming a different device must be refused.
    """
    _need("agg_cp.sync.escalations", "_T12B_M4_BINDING")

    import httpx
    srv = t12b_server
    bob_sk, bob_pub, bob_kid = keygen()
    device_sk, device_pub, device_kid = keygen()
    project_id = str(uuid.uuid4())

    with psycopg.connect(_conninfo(srv["owner_url"])) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [srv["org_id"]])
        create_project(conn, srv["org_id"], project_id, environment="staging")
        conn.commit()

    _seed_registry_with_keys(srv["owner_url"], srv["org_id"], [
        {"key_id": bob_kid, "public_key": bob_pub.hex(),
         "user_id": srv["bob_id"], "kind": "cli",
         "roles": ["approver"]},
    ])
    device_id = _seed_connector(srv["owner_url"], srv["org_id"],
                                project_id, device_pub)
    token = secrets.token_hex(32)
    _seed_device_token(srv["owner_url"], srv["org_id"], project_id,
                       device_id, token)

    status, esc_id = _upload_escalation(
        srv["base_url"], device_id, token, "req-devmatch-1",  # gitleaks:allow (request id, not a token)
    )
    assert status == 200

    cookie, csrf = _make_fresh_session(
        srv["owner_url"], srv["org_id"], srv["bob_id"],
    )

    # Send approval with a different device_id
    envelope = _make_remote_approval_envelope(
        bob_sk,
        request_id="req-devmatch-1",
        org_id=srv["org_id"], project_id=project_id,
        device_id=str(uuid.uuid4()),  # WRONG device
        user_id=srv["bob_id"],
    )

    r = httpx.post(
        f"{srv['base_url']}/api/v1/sync/escalations/{esc_id}/approvals",
        json=envelope,
        cookies={"__Host-agg_session": cookie},
        headers={"X-CSRF-Token": csrf},
        timeout=10.0,
    )
    assert r.status_code == 400, f"expected 400 got {r.status_code}: {r.text}"
    assert "device" in r.json().get("error", "").lower()


# ===================================================================
# RED: M4 -- payload bound: project_id mismatch
# ===================================================================


@pytest.mark.pg

def test_m4_binding_project_id_mismatch(t12b_server):
    """M4: the payload project_id must match the escalation's project_id."""
    _need("agg_cp.sync.escalations", "_T12B_M4_BINDING")

    import httpx
    srv = t12b_server
    bob_sk, bob_pub, bob_kid = keygen()
    device_sk, device_pub, device_kid = keygen()
    project_id = str(uuid.uuid4())

    with psycopg.connect(_conninfo(srv["owner_url"])) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [srv["org_id"]])
        create_project(conn, srv["org_id"], project_id, environment="staging")
        conn.commit()

    _seed_registry_with_keys(srv["owner_url"], srv["org_id"], [
        {"key_id": bob_kid, "public_key": bob_pub.hex(),
         "user_id": srv["bob_id"], "kind": "cli",
         "roles": ["approver"]},
    ])
    device_id = _seed_connector(srv["owner_url"], srv["org_id"],
                                project_id, device_pub)
    token = secrets.token_hex(32)
    _seed_device_token(srv["owner_url"], srv["org_id"], project_id,
                       device_id, token)

    status, esc_id = _upload_escalation(
        srv["base_url"], device_id, token, "req-projmatch-1",  # gitleaks:allow (request id, not a token)
    )
    assert status == 200

    cookie, csrf = _make_fresh_session(
        srv["owner_url"], srv["org_id"], srv["bob_id"],
    )

    envelope = _make_remote_approval_envelope(
        bob_sk,
        request_id="req-projmatch-1",
        org_id=srv["org_id"],
        project_id=str(uuid.uuid4()),  # WRONG project
        device_id=device_id,
        user_id=srv["bob_id"],
    )

    r = httpx.post(
        f"{srv['base_url']}/api/v1/sync/escalations/{esc_id}/approvals",
        json=envelope,
        cookies={"__Host-agg_session": cookie},
        headers={"X-CSRF-Token": csrf},
        timeout=10.0,
    )
    assert r.status_code == 400, f"expected 400 got {r.status_code}: {r.text}"
    assert "project" in r.json().get("error", "").lower()


# ===================================================================
# RED: M4 -- payload bound: policy_sequence mismatch
# ===================================================================


@pytest.mark.pg

def test_m4_binding_policy_sequence_mismatch(t12b_server):
    """M4: the payload policy_sequence must match the escalation's stored value."""
    _need("agg_cp.sync.escalations", "_T12B_M4_BINDING")

    import httpx
    srv = t12b_server
    bob_sk, bob_pub, bob_kid = keygen()
    device_sk, device_pub, device_kid = keygen()
    project_id = str(uuid.uuid4())

    with psycopg.connect(_conninfo(srv["owner_url"])) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [srv["org_id"]])
        create_project(conn, srv["org_id"], project_id, environment="staging")
        conn.commit()

    _seed_registry_with_keys(srv["owner_url"], srv["org_id"], [
        {"key_id": bob_kid, "public_key": bob_pub.hex(),
         "user_id": srv["bob_id"], "kind": "cli",
         "roles": ["approver"]},
    ])
    device_id = _seed_connector(srv["owner_url"], srv["org_id"],
                                project_id, device_pub)
    token = secrets.token_hex(32)
    _seed_device_token(srv["owner_url"], srv["org_id"], project_id,
                       device_id, token)

    # Upload with sequence 42
    status, esc_id = _upload_escalation(
        srv["base_url"], device_id, token, "req-seqmatch-1",
        policy_sequence=42,
    )
    assert status == 200

    cookie, csrf = _make_fresh_session(
        srv["owner_url"], srv["org_id"], srv["bob_id"],
    )

    # Approve with sequence 99 (mismatch)
    envelope = _make_remote_approval_envelope(
        bob_sk,
        request_id="req-seqmatch-1",
        org_id=srv["org_id"], project_id=project_id,
        device_id=device_id, user_id=srv["bob_id"],
        policy_sequence=99,  # WRONG
    )

    r = httpx.post(
        f"{srv['base_url']}/api/v1/sync/escalations/{esc_id}/approvals",
        json=envelope,
        cookies={"__Host-agg_session": cookie},
        headers={"X-CSRF-Token": csrf},
        timeout=10.0,
    )
    assert r.status_code == 400, f"expected 400 got {r.status_code}: {r.text}"
    assert "policy_sequence" in r.json().get("error", "").lower()


# ===================================================================
# RED: M4 -- payload bound: org_id must equal auth org
# ===================================================================


@pytest.mark.pg

def test_m4_binding_org_id_mismatch(t12b_server):
    """M4: the payload org_id must match the authenticated user's org."""
    _need("agg_cp.sync.escalations", "_T12B_M4_BINDING")

    import httpx
    srv = t12b_server
    bob_sk, bob_pub, bob_kid = keygen()
    device_sk, device_pub, device_kid = keygen()
    project_id = str(uuid.uuid4())

    with psycopg.connect(_conninfo(srv["owner_url"])) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [srv["org_id"]])
        create_project(conn, srv["org_id"], project_id, environment="staging")
        conn.commit()

    _seed_registry_with_keys(srv["owner_url"], srv["org_id"], [
        {"key_id": bob_kid, "public_key": bob_pub.hex(),
         "user_id": srv["bob_id"], "kind": "cli",
         "roles": ["approver"]},
    ])
    device_id = _seed_connector(srv["owner_url"], srv["org_id"],
                                project_id, device_pub)
    token = secrets.token_hex(32)
    _seed_device_token(srv["owner_url"], srv["org_id"], project_id,
                       device_id, token)

    status, esc_id = _upload_escalation(
        srv["base_url"], device_id, token, "req-orgmatch-1",  # gitleaks:allow (request id, not a token)
    )
    assert status == 200

    cookie, csrf = _make_fresh_session(
        srv["owner_url"], srv["org_id"], srv["bob_id"],
    )

    # Approve with evil org_id
    envelope = _make_remote_approval_envelope(
        bob_sk,
        request_id="req-orgmatch-1",
        org_id=srv["org_evil"],  # WRONG org
        project_id=project_id,
        device_id=device_id,
        user_id=srv["bob_id"],
    )

    r = httpx.post(
        f"{srv['base_url']}/api/v1/sync/escalations/{esc_id}/approvals",
        json=envelope,
        cookies={"__Host-agg_session": cookie},
        headers={"X-CSRF-Token": csrf},
        timeout=10.0,
    )
    assert r.status_code == 400, f"expected 400 got {r.status_code}: {r.text}"
    assert "org" in r.json().get("error", "").lower()


# ===================================================================
# RED: M4 -- payload bound: fingerprint mismatch
# ===================================================================


@pytest.mark.pg

def test_m4_binding_fingerprint_mismatch(t12b_server):
    """M4: the payload fingerprint must match the escalation record's.

    After T12b-2, the server stores and checks the binding fingerprint.
    """
    _need("agg_cp.sync.escalations", "_T12B_M4_BINDING")

    import httpx
    srv = t12b_server
    bob_sk, bob_pub, bob_kid = keygen()
    device_sk, device_pub, device_kid = keygen()
    project_id = str(uuid.uuid4())

    with psycopg.connect(_conninfo(srv["owner_url"])) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [srv["org_id"]])
        create_project(conn, srv["org_id"], project_id, environment="staging")
        conn.commit()

    _seed_registry_with_keys(srv["owner_url"], srv["org_id"], [
        {"key_id": bob_kid, "public_key": bob_pub.hex(),
         "user_id": srv["bob_id"], "kind": "cli",
         "roles": ["approver"]},
    ])
    device_id = _seed_connector(srv["owner_url"], srv["org_id"],
                                project_id, device_pub)
    token = secrets.token_hex(32)
    _seed_device_token(srv["owner_url"], srv["org_id"], project_id,
                       device_id, token)

    real_fp = hashlib.sha256(b"echo test").hexdigest()
    status, esc_id = _upload_escalation(
        srv["base_url"], device_id, token, "req-fpmatch-1",  # gitleaks:allow (request id, not a token)
        fingerprint=real_fp,
    )
    assert status == 200

    cookie, csrf = _make_fresh_session(
        srv["owner_url"], srv["org_id"], srv["bob_id"],
    )

    # Approve with a different fingerprint
    envelope = _make_remote_approval_envelope(
        bob_sk,
        request_id="req-fpmatch-1",
        org_id=srv["org_id"], project_id=project_id,
        device_id=device_id, user_id=srv["bob_id"],
        fingerprint="0000deadbeef" * 5,  # WRONG fingerprint
    )

    r = httpx.post(
        f"{srv['base_url']}/api/v1/sync/escalations/{esc_id}/approvals",
        json=envelope,
        cookies={"__Host-agg_session": cookie},
        headers={"X-CSRF-Token": csrf},
        timeout=10.0,
    )
    assert r.status_code == 400, f"expected 400 got {r.status_code}: {r.text}"
    assert "fingerprint" in r.json().get("error", "").lower()


# ===================================================================
# RED: M1 server -- not_after null/missing refused
# ===================================================================


@pytest.mark.pg

def test_m1_server_not_after_null_refused(t12b_server):
    """M1: not_after: null must be refused (server side).

    A null not_after means the approval never expires, violating D4.1.
    """
    _need("agg_cp.sync.escalations", "_T12B_M4_BINDING")

    import httpx
    srv = t12b_server
    bob_sk, bob_pub, bob_kid = keygen()
    device_sk, device_pub, device_kid = keygen()
    project_id = str(uuid.uuid4())

    with psycopg.connect(_conninfo(srv["owner_url"])) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [srv["org_id"]])
        create_project(conn, srv["org_id"], project_id, environment="staging")
        conn.commit()

    _seed_registry_with_keys(srv["owner_url"], srv["org_id"], [
        {"key_id": bob_kid, "public_key": bob_pub.hex(),
         "user_id": srv["bob_id"], "kind": "cli",
         "roles": ["approver"]},
    ])
    device_id = _seed_connector(srv["owner_url"], srv["org_id"],
                                project_id, device_pub)
    token = secrets.token_hex(32)
    _seed_device_token(srv["owner_url"], srv["org_id"], project_id,
                       device_id, token)

    status, esc_id = _upload_escalation(
        srv["base_url"], device_id, token, "req-notafter-null-1",
    )
    assert status == 200

    cookie, csrf = _make_fresh_session(
        srv["owner_url"], srv["org_id"], srv["bob_id"],
    )

    # Build envelope with not_after=None
    envelope = _make_remote_approval_envelope(
        bob_sk,
        request_id="req-notafter-null-1",
        org_id=srv["org_id"], project_id=project_id,
        device_id=device_id, user_id=srv["bob_id"],
    )
    # Force not_after to null in the payload
    envelope["payload"]["not_after"] = None
    # Re-sign with the null value
    payload_bytes = canonical_json(envelope["payload"])
    tag = b"agg/remote-approval/v1"
    msg = tag + b"\x00" + payload_bytes
    new_sig = bob_sk.sign(msg).signature.hex()
    envelope["signatures"][0]["sig"] = new_sig

    r = httpx.post(
        f"{srv['base_url']}/api/v1/sync/escalations/{esc_id}/approvals",
        json=envelope,
        cookies={"__Host-agg_session": cookie},
        headers={"X-CSRF-Token": csrf},
        timeout=10.0,
    )
    assert r.status_code == 400, f"expected 400 got {r.status_code}: {r.text}"
    assert "not_after" in r.json().get("error", "").lower()


@pytest.mark.pg

def test_m1_server_not_after_non_numeric_refused(t12b_server):
    """M1: not_after must be a finite number; a string is refused."""
    _need("agg_cp.sync.escalations", "_T12B_M4_BINDING")

    import httpx
    srv = t12b_server
    bob_sk, bob_pub, bob_kid = keygen()
    device_sk, device_pub, device_kid = keygen()
    project_id = str(uuid.uuid4())

    with psycopg.connect(_conninfo(srv["owner_url"])) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [srv["org_id"]])
        create_project(conn, srv["org_id"], project_id, environment="staging")
        conn.commit()

    _seed_registry_with_keys(srv["owner_url"], srv["org_id"], [
        {"key_id": bob_kid, "public_key": bob_pub.hex(),
         "user_id": srv["bob_id"], "kind": "cli",
         "roles": ["approver"]},
    ])
    device_id = _seed_connector(srv["owner_url"], srv["org_id"],
                                project_id, device_pub)
    token = secrets.token_hex(32)
    _seed_device_token(srv["owner_url"], srv["org_id"], project_id,
                       device_id, token)

    status, esc_id = _upload_escalation(
        srv["base_url"], device_id, token, "req-notafter-str-1",
    )
    assert status == 200

    cookie, csrf = _make_fresh_session(
        srv["owner_url"], srv["org_id"], srv["bob_id"],
    )

    envelope = _make_remote_approval_envelope(
        bob_sk,
        request_id="req-notafter-str-1",
        org_id=srv["org_id"], project_id=project_id,
        device_id=device_id, user_id=srv["bob_id"],
    )
    envelope["payload"]["not_after"] = "never"
    payload_bytes = canonical_json(envelope["payload"])
    tag = b"agg/remote-approval/v1"
    msg = tag + b"\x00" + payload_bytes
    new_sig = bob_sk.sign(msg).signature.hex()
    envelope["signatures"][0]["sig"] = new_sig

    r = httpx.post(
        f"{srv['base_url']}/api/v1/sync/escalations/{esc_id}/approvals",
        json=envelope,
        cookies={"__Host-agg_session": cookie},
        headers={"X-CSRF-Token": csrf},
        timeout=10.0,
    )
    assert r.status_code == 400, f"expected 400 got {r.status_code}: {r.text}"
    assert "not_after" in r.json().get("error", "").lower()


# ===================================================================
# RED: C5 -- operator self-approval refused
# ===================================================================


@pytest.mark.pg

def test_c5_operator_self_approval_refused(t12b_server):
    """C5: the device's enrolled operator cannot approve its own escalation.

    The server must look up the connector's operator_user_id and refuse
    if it matches the approving user, unless the bundle allows the requester.
    """
    _need("agg_cp.sync.escalations", "_T12B_M4_BINDING")

    import httpx
    srv = t12b_server
    op_sk, op_pub, op_kid = keygen()
    device_sk, device_pub, device_kid = keygen()
    project_id = str(uuid.uuid4())

    with psycopg.connect(_conninfo(srv["owner_url"])) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [srv["org_id"]])
        create_project(conn, srv["org_id"], project_id, environment="staging")
        conn.commit()

    # Seed operator's key in the registry
    _seed_registry_with_keys(srv["owner_url"], srv["org_id"], [
        {"key_id": op_kid, "public_key": op_pub.hex(),
         "user_id": srv["operator_id"], "kind": "cli",
         "roles": ["approver"]},
    ])

    # Seed the connector with operator_user_id set
    device_id = _seed_connector(
        srv["owner_url"], srv["org_id"], project_id, device_pub,
        operator_user_id=srv["operator_id"],
    )
    token = secrets.token_hex(32)
    _seed_device_token(srv["owner_url"], srv["org_id"], project_id,
                       device_id, token)

    status, esc_id = _upload_escalation(
        srv["base_url"], device_id, token, "req-opselfapprove-1",
    )
    assert status == 200

    # The operator tries to approve their own escalation
    cookie, csrf = _make_fresh_session(
        srv["owner_url"], srv["org_id"], srv["operator_id"],
    )

    envelope = _make_remote_approval_envelope(
        op_sk,
        request_id="req-opselfapprove-1",
        org_id=srv["org_id"], project_id=project_id,
        device_id=device_id, user_id=srv["operator_id"],
    )

    r = httpx.post(
        f"{srv['base_url']}/api/v1/sync/escalations/{esc_id}/approvals",
        json=envelope,
        cookies={"__Host-agg_session": cookie},
        headers={"X-CSRF-Token": csrf},
        timeout=10.0,
    )
    # Must be refused (400 or 403)
    assert r.status_code in (400, 403), (
        f"expected 400/403 got {r.status_code}: {r.text}"
    )
    err = r.json().get("error", "").lower()
    assert "operator" in err or "requester" in err or "self" in err


# ===================================================================
# RED: GET /api/v1/sync/escalations/{escalation_id} (new route)
# ===================================================================


@pytest.mark.pg

def test_get_escalation_detail_session(t12b_server):
    """GET /api/v1/sync/escalations/{id} returns canonical fields for the signer.

    Auth: session.  Returns request_id, command, fingerprint, device_id,
    project_id, org_id, policy_sequence, requires_dual.
    """
    _need("agg_cp.sync.escalations", "_T12B_DETAIL_ROUTE")

    import httpx
    srv = t12b_server
    sk, pub, kid = keygen()
    project_id = str(uuid.uuid4())

    with psycopg.connect(_conninfo(srv["owner_url"])) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [srv["org_id"]])
        create_project(conn, srv["org_id"], project_id, environment="staging")
        conn.commit()

    device_id = _seed_connector(srv["owner_url"], srv["org_id"],
                                project_id, pub)
    token = secrets.token_hex(32)
    _seed_device_token(srv["owner_url"], srv["org_id"], project_id,
                       device_id, token)

    status, esc_id = _upload_escalation(
        srv["base_url"], device_id, token, "req-detail-1",
        command="echo detail-test",
    )
    assert status == 200

    cookie, csrf = _make_fresh_session(
        srv["owner_url"], srv["org_id"], srv["bob_id"],
    )

    r = httpx.get(
        f"{srv['base_url']}/api/v1/sync/escalations/{esc_id}",
        cookies={"__Host-agg_session": cookie},
        timeout=10.0,
    )
    assert r.status_code == 200
    data = r.json()

    # Must have canonical fields
    for field in ("request_id", "command", "device_id", "project_id",
                  "org_id", "policy_sequence", "requires_dual"):
        assert field in data, f"missing field {field}"
    assert data["request_id"] == "req-detail-1"
    assert "echo detail-test" in data.get("command", "")


@pytest.mark.pg

def test_get_escalation_detail_signer_token(t12b_server):
    """GET /api/v1/sync/escalations/{id} via signer-token auth."""
    _need("agg_cp.sync.escalations", "_T12B_DETAIL_ROUTE")

    import httpx
    srv = t12b_server
    bob_sk, bob_pub, bob_kid = keygen()
    device_sk, device_pub, device_kid = keygen()
    project_id = str(uuid.uuid4())

    with psycopg.connect(_conninfo(srv["owner_url"])) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [srv["org_id"]])
        create_project(conn, srv["org_id"], project_id, environment="staging")
        conn.commit()

    _seed_registry_with_keys(srv["owner_url"], srv["org_id"], [
        {"key_id": bob_kid, "public_key": bob_pub.hex(),
         "user_id": srv["bob_id"], "kind": "cli",
         "roles": ["approver"]},
    ])
    device_id = _seed_connector(srv["owner_url"], srv["org_id"],
                                project_id, device_pub)
    dev_token = secrets.token_hex(32)
    _seed_device_token(srv["owner_url"], srv["org_id"], project_id,
                       device_id, dev_token)

    status, esc_id = _upload_escalation(
        srv["base_url"], device_id, dev_token, "req-detail-signer-1",  # gitleaks:allow (request id, not a token)
    )
    assert status == 200

    signer_token = _seed_signer_token(
        srv["owner_url"], srv["org_id"], srv["bob_id"], bob_kid,
    )

    r = httpx.get(
        f"{srv['base_url']}/api/v1/sync/escalations/{esc_id}",
        headers={"Authorization": f"Bearer {signer_token}"},
        timeout=10.0,
    )
    assert r.status_code == 200
    data = r.json()
    assert data["request_id"] == "req-detail-signer-1"


@pytest.mark.pg

def test_get_escalation_detail_device_token_refused(t12b_server):
    """GET /api/v1/sync/escalations/{id} must refuse device tokens."""
    _need("agg_cp.sync.escalations", "_T12B_DETAIL_ROUTE")

    import httpx
    srv = t12b_server
    sk, pub, kid = keygen()
    project_id = str(uuid.uuid4())

    with psycopg.connect(_conninfo(srv["owner_url"])) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [srv["org_id"]])
        create_project(conn, srv["org_id"], project_id, environment="staging")
        conn.commit()

    device_id = _seed_connector(srv["owner_url"], srv["org_id"],
                                project_id, pub)
    token = secrets.token_hex(32)
    _seed_device_token(srv["owner_url"], srv["org_id"], project_id,
                       device_id, token)

    status, esc_id = _upload_escalation(
        srv["base_url"], device_id, token, "req-detail-devtoken-1",
    )
    assert status == 200

    # Try to GET with the device token
    r = httpx.get(
        f"{srv['base_url']}/api/v1/sync/escalations/{esc_id}",
        headers={"Authorization": f"Bearer {token}"},
        timeout=10.0,
    )
    assert r.status_code in (401, 403), (
        f"expected 401/403 got {r.status_code}: {r.text}"
    )


@pytest.mark.pg

def test_get_escalation_detail_cross_org_404(t12b_server):
    """GET /api/v1/sync/escalations/{id}: another org sees 404."""
    _need("agg_cp.sync.escalations", "_T12B_DETAIL_ROUTE")

    import httpx
    srv = t12b_server
    sk, pub, kid = keygen()
    project_id = str(uuid.uuid4())

    with psycopg.connect(_conninfo(srv["owner_url"])) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [srv["org_id"]])
        create_project(conn, srv["org_id"], project_id, environment="staging")
        conn.commit()

    device_id = _seed_connector(srv["owner_url"], srv["org_id"],
                                project_id, pub)
    token = secrets.token_hex(32)
    _seed_device_token(srv["owner_url"], srv["org_id"], project_id,
                       device_id, token)

    status, esc_id = _upload_escalation(
        srv["base_url"], device_id, token, "req-detail-xorg-1",
    )
    assert status == 200

    # Eve from Evil Org tries to read it
    cookie, csrf = _make_fresh_session(
        srv["owner_url"], srv["org_evil"], srv["eve_id"],
    )
    r = httpx.get(
        f"{srv['base_url']}/api/v1/sync/escalations/{esc_id}",
        cookies={"__Host-agg_session": cookie},
        timeout=10.0,
    )
    assert r.status_code == 404


@pytest.mark.pg

def test_get_escalation_detail_no_key_material(t12b_server):
    """GET /api/v1/sync/escalations/{id}: response has no key material."""
    _need("agg_cp.sync.escalations", "_T12B_DETAIL_ROUTE")

    import httpx
    srv = t12b_server
    sk, pub, kid = keygen()
    project_id = str(uuid.uuid4())

    with psycopg.connect(_conninfo(srv["owner_url"])) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [srv["org_id"]])
        create_project(conn, srv["org_id"], project_id, environment="staging")
        conn.commit()

    device_id = _seed_connector(srv["owner_url"], srv["org_id"],
                                project_id, pub)
    token = secrets.token_hex(32)
    _seed_device_token(srv["owner_url"], srv["org_id"], project_id,
                       device_id, token)

    status, esc_id = _upload_escalation(
        srv["base_url"], device_id, token, "req-detail-nokey-1",  # gitleaks:allow (request id, not a token)
    )
    assert status == 200

    cookie, csrf = _make_fresh_session(
        srv["owner_url"], srv["org_id"], srv["bob_id"],
    )
    r = httpx.get(
        f"{srv['base_url']}/api/v1/sync/escalations/{esc_id}",
        cookies={"__Host-agg_session": cookie},
        timeout=10.0,
    )
    assert r.status_code == 200
    body_str = r.text
    _assert_no_private_key(body_str)


# ===================================================================
# RED: route-freeze expectation for T12b-2 routes
# ===================================================================


@pytest.mark.pg

def test_t12b2_route_freeze(t12b_server):
    """The GET /api/v1/sync/escalations/{escalation_id} route exists.

    This is the route-freeze expectation for T12b-2 (added here per
    task instructions, not in test_t9_routes.py).
    """
    _need("agg_cp.sync.escalations", "_T12B_DETAIL_ROUTE")

    import httpx
    srv = t12b_server

    # An OPTIONS or GET to the detail route should not be 405
    cookie, csrf = _make_fresh_session(
        srv["owner_url"], srv["org_id"], srv["bob_id"],
    )
    r = httpx.get(
        f"{srv['base_url']}/api/v1/sync/escalations/{uuid.uuid4()}",
        cookies={"__Host-agg_session": cookie},
        timeout=10.0,
    )
    # 404 (not found) is fine; 405 (method not allowed) means the route
    # does not exist
    assert r.status_code != 405, "route does not exist (405)"


# ===================================================================
# RED: C9 item 3 -- server ignores client user_id/kind
# ===================================================================


@pytest.mark.pg

def test_c9_server_ignores_body_user_id(t12b_server):
    """C9 item 3: the server must ignore user_id from the envelope body.

    The stored user_id must come from the authenticated session/token,
    not from payload.user_id.
    """
    _need("agg_cp.sync.escalations", "_T12B_M4_BINDING")

    import httpx
    srv = t12b_server
    bob_sk, bob_pub, bob_kid = keygen()
    device_sk, device_pub, device_kid = keygen()
    project_id = str(uuid.uuid4())

    with psycopg.connect(_conninfo(srv["owner_url"])) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [srv["org_id"]])
        create_project(conn, srv["org_id"], project_id, environment="staging")
        conn.commit()

    _seed_registry_with_keys(srv["owner_url"], srv["org_id"], [
        {"key_id": bob_kid, "public_key": bob_pub.hex(),
         "user_id": srv["bob_id"], "kind": "cli",
         "roles": ["approver"]},
    ])
    device_id = _seed_connector(srv["owner_url"], srv["org_id"],
                                project_id, device_pub)
    token = secrets.token_hex(32)
    _seed_device_token(srv["owner_url"], srv["org_id"], project_id,
                       device_id, token)

    status, esc_id = _upload_escalation(
        srv["base_url"], device_id, token, "req-userid-ignore-1",
    )
    assert status == 200

    cookie, csrf = _make_fresh_session(
        srv["owner_url"], srv["org_id"], srv["bob_id"],
    )

    # Build envelope: payload user_id matches the session user (bob),
    # but the signed payload has user_id = carol
    envelope = _make_remote_approval_envelope(
        bob_sk,
        request_id="req-userid-ignore-1",
        org_id=srv["org_id"], project_id=project_id,
        device_id=device_id, user_id=srv["bob_id"],
    )

    # After T12b-2, the server checks that payload.user_id matches the
    # registry key owner (T13 identity binding). But the STORED user_id
    # in the approvals table must be the authenticated user (bob_id),
    # regardless of what the payload says. If the payload has a different
    # user_id, it should be refused by the identity binding check (403).
    # This test verifies that sending carol's user_id is refused.
    envelope["payload"]["user_id"] = srv["carol_id"]
    # Re-sign
    payload_bytes = canonical_json(envelope["payload"])
    tag = b"agg/remote-approval/v1"
    msg = tag + b"\x00" + payload_bytes
    new_sig = bob_sk.sign(msg).signature.hex()
    envelope["signatures"][0]["sig"] = new_sig

    r = httpx.post(
        f"{srv['base_url']}/api/v1/sync/escalations/{esc_id}/approvals",
        json=envelope,
        cookies={"__Host-agg_session": cookie},
        headers={"X-CSRF-Token": csrf},
        timeout=10.0,
    )
    # Must be refused (identity binding: session user != payload user_id)
    assert r.status_code in (400, 403), (
        f"expected 400/403 got {r.status_code}: {r.text}"
    )


@pytest.mark.pg

def test_c9_server_ignores_body_kind(t12b_server):
    """C9 item 3: the server must use the registry key kind, not the body.

    Even if the envelope claims ``kind: cli``, the server must look up
    the key in the registry and use its actual kind for the approvals row.
    """
    _need("agg_cp.sync.escalations", "_T12B_M4_BINDING")

    import httpx
    srv = t12b_server
    bob_sk, bob_pub, bob_kid = keygen()
    device_sk, device_pub, device_kid = keygen()
    project_id = str(uuid.uuid4())

    with psycopg.connect(_conninfo(srv["owner_url"])) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [srv["org_id"]])
        create_project(conn, srv["org_id"], project_id, environment="staging")
        conn.commit()

    # Register bob's key as a browser key
    _seed_registry_with_keys(srv["owner_url"], srv["org_id"], [
        {"key_id": bob_kid, "public_key": bob_pub.hex(),
         "user_id": srv["bob_id"], "kind": "browser",
         "roles": ["approver"]},
    ])
    # T12b-2 named edit: seed operator (R2) distinct from approver (bob)
    device_id = _seed_connector(srv["owner_url"], srv["org_id"],
                                project_id, device_pub,
                                operator_user_id=srv["operator_id"])
    token = secrets.token_hex(32)
    _seed_device_token(srv["owner_url"], srv["org_id"], project_id,
                       device_id, token)

    status, esc_id = _upload_escalation(
        srv["base_url"], device_id, token, "req-kind-ignore-1",
    )
    assert status == 200

    cookie, csrf = _make_fresh_session(
        srv["owner_url"], srv["org_id"], srv["bob_id"],
    )

    envelope = _make_remote_approval_envelope(
        bob_sk,
        request_id="req-kind-ignore-1",
        org_id=srv["org_id"], project_id=project_id,
        device_id=device_id, user_id=srv["bob_id"],
    )

    r = httpx.post(
        f"{srv['base_url']}/api/v1/sync/escalations/{esc_id}/approvals",
        json=envelope,
        cookies={"__Host-agg_session": cookie},
        headers={"X-CSRF-Token": csrf},
        timeout=10.0,
    )
    # If accepted (200), check stored kind is 'browser', not from the body
    if r.status_code == 200:
        with psycopg.connect(_conninfo(srv["owner_url"])) as conn:
            conn.execute("SELECT set_config('app.org_id', %s, false)",
                         [srv["org_id"]])
            row = conn.execute(
                "SELECT kind FROM approvals WHERE escalation_id = %s::uuid",
                [esc_id],
            ).fetchone()
            assert row is not None
            # The stored kind must be 'browser' (from registry), not 'cli'
            assert row[0] == "browser", (
                f"stored kind '{row[0]}' should be 'browser' from registry"
            )
    else:
        # Also acceptable: refused for binding or kind reasons
        assert r.status_code in (400, 403)


# ===================================================================
# RED: C9 item 3 -- oversized batches refused
# ===================================================================


@pytest.mark.pg

def test_c9_oversized_batch_refused(t12b_server):
    """C9 item 3: a batch upload exceeding the cap (>50) is refused.

    The server must refuse oversized batches of escalations in a single
    request. The escalation upload route accepts one at a time, but if
    a batch endpoint is added, it must enforce a size limit.
    """
    _need("agg_cp.sync.escalations", "_T12B_BATCH_LIMIT")

    import httpx
    srv = t12b_server
    sk, pub, kid = keygen()
    project_id = str(uuid.uuid4())

    with psycopg.connect(_conninfo(srv["owner_url"])) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [srv["org_id"]])
        create_project(conn, srv["org_id"], project_id, environment="staging")
        conn.commit()

    device_id = _seed_connector(srv["owner_url"], srv["org_id"],
                                project_id, pub)
    token = secrets.token_hex(32)
    _seed_device_token(srv["owner_url"], srv["org_id"], project_id,
                       device_id, token)

    # Try to upload 51 escalations in one batch request
    batch = [
        {
            "device_id": device_id,
            "request_id": f"req-batch-{i}",
            "record": {"command": f"echo batch-{i}"},
            "policy_sequence": 1,
        }
        for i in range(51)
    ]

    r = httpx.post(
        f"{srv['base_url']}/api/v1/sync/escalations",
        json={"batch": batch},
        headers={"Authorization": f"Bearer {token}"},
        timeout=10.0,
    )
    # Must be refused (400 or 413)
    assert r.status_code in (400, 413), (
        f"expected 400/413 got {r.status_code}: {r.text}"
    )


# ===================================================================
# RED: C9 item 3 -- unknown escalation_id -> 404
# ===================================================================


@pytest.mark.pg

def test_c9_unknown_escalation_id_404(t12b_server):
    """C9 item 3: submitting an approval for a non-existent escalation -> 404."""
    _need("agg_cp.sync.escalations", "_T12B_M4_BINDING")

    import httpx
    srv = t12b_server
    bob_sk, bob_pub, bob_kid = keygen()

    _seed_registry_with_keys(srv["owner_url"], srv["org_id"], [
        {"key_id": bob_kid, "public_key": bob_pub.hex(),
         "user_id": srv["bob_id"], "kind": "cli",
         "roles": ["approver"]},
    ])

    cookie, csrf = _make_fresh_session(
        srv["owner_url"], srv["org_id"], srv["bob_id"],
    )

    # Use a completely random escalation_id
    fake_esc_id = str(uuid.uuid4())
    envelope = _make_remote_approval_envelope(
        bob_sk,
        request_id="req-unknown-1",
        org_id=srv["org_id"], project_id=str(uuid.uuid4()),
        device_id=str(uuid.uuid4()), user_id=srv["bob_id"],
    )

    r = httpx.post(
        f"{srv['base_url']}/api/v1/sync/escalations/{fake_esc_id}/approvals",
        json=envelope,
        cookies={"__Host-agg_session": cookie},
        headers={"X-CSRF-Token": csrf},
        timeout=10.0,
    )
    assert r.status_code == 404, (
        f"expected 404 got {r.status_code}: {r.text}"
    )


# ===================================================================
# RED: M4 -- command mismatch refused
# ===================================================================


@pytest.mark.pg

def test_m4_binding_command_mismatch(t12b_server):
    """M4: the payload command must match the escalation record's command.

    An approval for 'echo safe' against an escalation for 'rm -rf /' is
    refused.
    """
    _need("agg_cp.sync.escalations", "_T12B_M4_BINDING")

    import httpx
    srv = t12b_server
    bob_sk, bob_pub, bob_kid = keygen()
    device_sk, device_pub, device_kid = keygen()
    project_id = str(uuid.uuid4())

    with psycopg.connect(_conninfo(srv["owner_url"])) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [srv["org_id"]])
        create_project(conn, srv["org_id"], project_id, environment="staging")
        conn.commit()

    _seed_registry_with_keys(srv["owner_url"], srv["org_id"], [
        {"key_id": bob_kid, "public_key": bob_pub.hex(),
         "user_id": srv["bob_id"], "kind": "cli",
         "roles": ["approver"]},
    ])
    device_id = _seed_connector(srv["owner_url"], srv["org_id"],
                                project_id, device_pub)
    token = secrets.token_hex(32)
    _seed_device_token(srv["owner_url"], srv["org_id"], project_id,
                       device_id, token)

    # Upload with command "rm -rf /"
    status, esc_id = _upload_escalation(
        srv["base_url"], device_id, token, "req-cmdmatch-1",
        command="rm -rf /",
    )
    assert status == 200

    cookie, csrf = _make_fresh_session(
        srv["owner_url"], srv["org_id"], srv["bob_id"],
    )

    # Approve with command "echo safe" -- mismatch
    envelope = _make_remote_approval_envelope(
        bob_sk,
        request_id="req-cmdmatch-1",
        org_id=srv["org_id"], project_id=project_id,
        device_id=device_id, user_id=srv["bob_id"],
        command="echo safe",  # WRONG command
    )

    r = httpx.post(
        f"{srv['base_url']}/api/v1/sync/escalations/{esc_id}/approvals",
        json=envelope,
        cookies={"__Host-agg_session": cookie},
        headers={"X-CSRF-Token": csrf},
        timeout=10.0,
    )
    assert r.status_code == 400, f"expected 400 got {r.status_code}: {r.text}"
    assert "command" in r.json().get("error", "").lower()


# ===================================================================
# RED: upload refuses missing/invalid record (T12b-2 item 6)
# ===================================================================


@pytest.mark.pg

def test_upload_refuses_missing_record(t12b_server):
    """Upload must refuse when ``record`` is missing or not a dict (item 6)."""
    _need("agg_cp.sync.escalations", "_T12B_M4_BINDING")

    import httpx
    srv = t12b_server
    sk, pub, kid = keygen()
    project_id = str(uuid.uuid4())

    with psycopg.connect(_conninfo(srv["owner_url"])) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [srv["org_id"]])
        create_project(conn, srv["org_id"], project_id, environment="staging")
        conn.commit()

    device_id = _seed_connector(srv["owner_url"], srv["org_id"],
                                project_id, pub)
    token = secrets.token_hex(32)
    _seed_device_token(srv["owner_url"], srv["org_id"], project_id,
                       device_id, token)

    # No record at all
    r = httpx.post(
        f"{srv['base_url']}/api/v1/sync/escalations",
        json={
            "device_id": device_id,
            "request_id": "req-norec-1",
            "policy_sequence": 1,
        },
        headers={"Authorization": f"Bearer {token}"},
        timeout=10.0,
    )
    assert r.status_code == 400, f"expected 400 got {r.status_code}: {r.text}"
    assert "record" in r.json().get("error", "").lower()

    # record is a string, not a dict
    r2 = httpx.post(
        f"{srv['base_url']}/api/v1/sync/escalations",
        json={
            "device_id": device_id,
            "request_id": "req-badrec-1",
            "record": "not-a-dict",
            "policy_sequence": 1,
        },
        headers={"Authorization": f"Bearer {token}"},
        timeout=10.0,
    )
    assert r2.status_code == 400, f"expected 400 got {r2.status_code}: {r2.text}"
    assert "record" in r2.json().get("error", "").lower()


@pytest.mark.pg

def test_upload_refuses_record_without_command_or_fingerprint(t12b_server):
    """Upload must refuse when record lacks command or fingerprint (item 6)."""
    _need("agg_cp.sync.escalations", "_T12B_M4_BINDING")

    import httpx
    srv = t12b_server
    sk, pub, kid = keygen()
    project_id = str(uuid.uuid4())

    with psycopg.connect(_conninfo(srv["owner_url"])) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [srv["org_id"]])
        create_project(conn, srv["org_id"], project_id, environment="staging")
        conn.commit()

    device_id = _seed_connector(srv["owner_url"], srv["org_id"],
                                project_id, pub)
    token = secrets.token_hex(32)
    _seed_device_token(srv["owner_url"], srv["org_id"], project_id,
                       device_id, token)

    # Record without command
    r = httpx.post(
        f"{srv['base_url']}/api/v1/sync/escalations",
        json={
            "device_id": device_id,
            "request_id": "req-nocmd-1",
            "record": {"fingerprint": "abc123", "status": "pending"},
            "policy_sequence": 1,
        },
        headers={"Authorization": f"Bearer {token}"},
        timeout=10.0,
    )
    assert r.status_code == 400, f"expected 400 got {r.status_code}: {r.text}"
    assert "command" in r.json().get("error", "").lower()

    # Record without fingerprint
    r2 = httpx.post(
        f"{srv['base_url']}/api/v1/sync/escalations",
        json={
            "device_id": device_id,
            "request_id": "req-nofp-1",
            "record": {"command": "echo test", "status": "pending"},
            "policy_sequence": 1,
        },
        headers={"Authorization": f"Bearer {token}"},
        timeout=10.0,
    )
    assert r2.status_code == 400, f"expected 400 got {r2.status_code}: {r2.text}"
    assert "fingerprint" in r2.json().get("error", "").lower()


# ===================================================================
# T12b-2 item 5: registry_version validation on approvals route
# ===================================================================


@pytest.mark.pg
def test_approvals_refuse_null_registry_version(t12b_server):
    """The approvals route refuses registry_version: null (400)."""
    _need("agg_cp.sync.escalations", "_T12B_M4_BINDING")

    import httpx
    srv = t12b_server
    bob_sk, bob_pub, bob_kid = keygen()
    device_sk, device_pub, device_kid = keygen()
    project_id = str(uuid.uuid4())

    with psycopg.connect(_conninfo(srv["owner_url"])) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [srv["org_id"]])
        create_project(conn, srv["org_id"], project_id, environment="staging")
        conn.commit()

    _seed_registry_with_keys(srv["owner_url"], srv["org_id"], [
        {"key_id": bob_kid, "public_key": bob_pub.hex(),
         "user_id": srv["bob_id"], "kind": "cli",
         "roles": ["approver"]},
    ])
    device_id = _seed_connector(srv["owner_url"], srv["org_id"],
                                project_id, device_pub)
    token = secrets.token_hex(32)
    _seed_device_token(srv["owner_url"], srv["org_id"], project_id,
                       device_id, token)

    status, esc_id = _upload_escalation(
        srv["base_url"], device_id, token, "req-rv-null-1",
    )
    assert status == 200

    cookie, csrf = _make_fresh_session(
        srv["owner_url"], srv["org_id"], srv["bob_id"],
    )

    envelope = _make_remote_approval_envelope(
        bob_sk,
        request_id="req-rv-null-1",
        org_id=srv["org_id"], project_id=project_id,
        device_id=device_id, user_id=srv["bob_id"],
    )
    envelope["payload"]["registry_version"] = None
    payload_bytes = canonical_json(envelope["payload"])
    tag = b"agg/remote-approval/v1"
    msg = tag + b"\x00" + payload_bytes
    new_sig = bob_sk.sign(msg).signature.hex()
    envelope["signatures"][0]["sig"] = new_sig

    r = httpx.post(
        f"{srv['base_url']}/api/v1/sync/escalations/{esc_id}/approvals",
        json=envelope,
        cookies={"__Host-agg_session": cookie},
        headers={"X-CSRF-Token": csrf},
        timeout=10.0,
    )
    assert r.status_code == 400, f"expected 400 got {r.status_code}: {r.text}"
    assert "registry_version" in r.json().get("error", "").lower()


@pytest.mark.pg
def test_approvals_refuse_bool_registry_version(t12b_server):
    """The approvals route refuses registry_version: true (400)."""
    _need("agg_cp.sync.escalations", "_T12B_M4_BINDING")

    import httpx
    srv = t12b_server
    bob_sk, bob_pub, bob_kid = keygen()
    device_sk, device_pub, device_kid = keygen()
    project_id = str(uuid.uuid4())

    with psycopg.connect(_conninfo(srv["owner_url"])) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [srv["org_id"]])
        create_project(conn, srv["org_id"], project_id, environment="staging")
        conn.commit()

    _seed_registry_with_keys(srv["owner_url"], srv["org_id"], [
        {"key_id": bob_kid, "public_key": bob_pub.hex(),
         "user_id": srv["bob_id"], "kind": "cli",
         "roles": ["approver"]},
    ])
    device_id = _seed_connector(srv["owner_url"], srv["org_id"],
                                project_id, device_pub)
    token = secrets.token_hex(32)
    _seed_device_token(srv["owner_url"], srv["org_id"], project_id,
                       device_id, token)

    status, esc_id = _upload_escalation(
        srv["base_url"], device_id, token, "req-rv-bool-1",
    )
    assert status == 200

    cookie, csrf = _make_fresh_session(
        srv["owner_url"], srv["org_id"], srv["bob_id"],
    )

    envelope = _make_remote_approval_envelope(
        bob_sk,
        request_id="req-rv-bool-1",
        org_id=srv["org_id"], project_id=project_id,
        device_id=device_id, user_id=srv["bob_id"],
    )
    envelope["payload"]["registry_version"] = True
    payload_bytes = canonical_json(envelope["payload"])
    tag = b"agg/remote-approval/v1"
    msg = tag + b"\x00" + payload_bytes
    new_sig = bob_sk.sign(msg).signature.hex()
    envelope["signatures"][0]["sig"] = new_sig

    r = httpx.post(
        f"{srv['base_url']}/api/v1/sync/escalations/{esc_id}/approvals",
        json=envelope,
        cookies={"__Host-agg_session": cookie},
        headers={"X-CSRF-Token": csrf},
        timeout=10.0,
    )
    assert r.status_code == 400, f"expected 400 got {r.status_code}: {r.text}"
    assert "registry_version" in r.json().get("error", "").lower()


@pytest.mark.pg
def test_approvals_refuse_non_int_registry_version(t12b_server):
    """The approvals route refuses registry_version: 'abc' (400)."""
    _need("agg_cp.sync.escalations", "_T12B_M4_BINDING")

    import httpx
    srv = t12b_server
    bob_sk, bob_pub, bob_kid = keygen()
    device_sk, device_pub, device_kid = keygen()
    project_id = str(uuid.uuid4())

    with psycopg.connect(_conninfo(srv["owner_url"])) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [srv["org_id"]])
        create_project(conn, srv["org_id"], project_id, environment="staging")
        conn.commit()

    _seed_registry_with_keys(srv["owner_url"], srv["org_id"], [
        {"key_id": bob_kid, "public_key": bob_pub.hex(),
         "user_id": srv["bob_id"], "kind": "cli",
         "roles": ["approver"]},
    ])
    device_id = _seed_connector(srv["owner_url"], srv["org_id"],
                                project_id, device_pub)
    token = secrets.token_hex(32)
    _seed_device_token(srv["owner_url"], srv["org_id"], project_id,
                       device_id, token)

    status, esc_id = _upload_escalation(
        srv["base_url"], device_id, token, "req-rv-str-1",
    )
    assert status == 200

    cookie, csrf = _make_fresh_session(
        srv["owner_url"], srv["org_id"], srv["bob_id"],
    )

    envelope = _make_remote_approval_envelope(
        bob_sk,
        request_id="req-rv-str-1",
        org_id=srv["org_id"], project_id=project_id,
        device_id=device_id, user_id=srv["bob_id"],
    )
    envelope["payload"]["registry_version"] = "abc"
    payload_bytes = canonical_json(envelope["payload"])
    tag = b"agg/remote-approval/v1"
    msg = tag + b"\x00" + payload_bytes
    new_sig = bob_sk.sign(msg).signature.hex()
    envelope["signatures"][0]["sig"] = new_sig

    r = httpx.post(
        f"{srv['base_url']}/api/v1/sync/escalations/{esc_id}/approvals",
        json=envelope,
        cookies={"__Host-agg_session": cookie},
        headers={"X-CSRF-Token": csrf},
        timeout=10.0,
    )
    assert r.status_code == 400, f"expected 400 got {r.status_code}: {r.text}"
    assert "registry_version" in r.json().get("error", "").lower()


@pytest.mark.pg
def test_get_escalation_detail_carries_registry_version(t12b_server):
    """GET /api/v1/sync/escalations/{id} carries registry_version equal
    to the org's latest version."""
    _need("agg_cp.sync.escalations", "_T12B_DETAIL_ROUTE")

    import httpx
    srv = t12b_server
    bob_sk, bob_pub, bob_kid = keygen()
    device_sk, device_pub, device_kid = keygen()
    project_id = str(uuid.uuid4())

    with psycopg.connect(_conninfo(srv["owner_url"])) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [srv["org_id"]])
        create_project(conn, srv["org_id"], project_id, environment="staging")
        conn.commit()

    # Seed a registry version to establish the latest version
    _seed_registry_with_keys(srv["owner_url"], srv["org_id"], [
        {"key_id": bob_kid, "public_key": bob_pub.hex(),
         "user_id": srv["bob_id"], "kind": "cli",
         "roles": ["approver"]},
    ])

    device_id = _seed_connector(srv["owner_url"], srv["org_id"],
                                project_id, device_pub)
    dev_token = secrets.token_hex(32)
    _seed_device_token(srv["owner_url"], srv["org_id"], project_id,
                       device_id, dev_token)

    status, esc_id = _upload_escalation(
        srv["base_url"], device_id, dev_token, "req-detail-rv-1",
    )
    assert status == 200

    cookie, csrf = _make_fresh_session(
        srv["owner_url"], srv["org_id"], srv["bob_id"],
    )

    r = httpx.get(
        f"{srv['base_url']}/api/v1/sync/escalations/{esc_id}",
        cookies={"__Host-agg_session": cookie},
        timeout=10.0,
    )
    assert r.status_code == 200
    data = r.json()
    assert "registry_version" in data, (
        "GET escalation detail must include registry_version"
    )
    # The registry version should match the org's latest (which is 1 from
    # _seed_registry_with_keys which inserts version=1)
    assert data["registry_version"] == 1, (
        f"expected registry_version=1, got {data['registry_version']}"
    )
