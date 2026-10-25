"""Security review tests for M2 T13 (security-engineer, 24 Oct 2026).

Finding 1 (Critical): test_device_key_approval_refused_server is vacuous.
    The test in test_m2_t12_remote.py does NOT seed the device key into
    the approver_keys registry.  The server refuses with 400
    "key not found in registry" -- not the kind refusal (403
    "key kind 'device' not allowed for approvals").  REVIEW_M2 item 7
    requires the device key be present and refused for its kind.

    This test seeds the device key into the registry as kind=device and
    proves the server returns a kind-specific refusal, then contrasts
    that with the existing test's "key not found" path.

Finding 2 (High): missing key-owner binding on the approval route.
    The code checks auth_user_id == payload.user_id (line ~424-429 of
    escalations.py), but never checks that the signing key's registry
    user_id == auth_user_id.  Bob's session can submit an envelope with
    payload.user_id=bob, signed by Carol's registered key, and the
    server accepts it.  This violates the three-way identity binding
    (session user == payload user_id == key owner).

    The existing test_approval_user_mismatch_refused only tests the
    first leg (session != payload).  This test covers the second leg.
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

from .m2_pending import M2T13Pending
from .m2_sync_server import (
    make_sync_server, ensure_at_head, create_org, create_project,
    keygen, sign_envelope, canonical_json,
)
from .t8p2_helpers import (
    seed_org_with_oidc, seed_user, seed_admin_binding,
    make_test_app,
)
from .t9_helpers import seed_session, make_session_cookie, compute_csrf
from .fake_idp import FakeClock


# ---------------------------------------------------------------------------
# Helpers (copied from test_m2_t13_web.py for isolation)
# ---------------------------------------------------------------------------


def _conninfo(url: str) -> str:
    return url.replace("+psycopg", "")


def _seed_user_row(conn, org_id: str, email: str) -> str:
    user_id = str(uuid.uuid4())
    conn.execute(
        "INSERT INTO users (id, org_id, oidc_issuer, oidc_subject, email, "
        "status, created_at) VALUES (%s, %s, 'https://idp', %s, %s, "
        "'active', now()) ON CONFLICT DO NOTHING",
        [user_id, org_id, f"sub-{uuid.uuid4().hex[:8]}", email],
    )
    return user_id


def _seed_connector(owner_url: str, org_id: str, project_id: str,
                    pub_key: bytes, *,
                    operator_user_id: str | None = None) -> str:
    did = str(uuid.uuid4())
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


def _make_fresh_session(owner_url: str, org_id: str, user_id: str):
    clock = FakeClock()
    token, csrf, sid = seed_session(
        owner_url, uuid.UUID(org_id), uuid.UUID(user_id), clock=clock,
    )
    cookie = make_session_cookie(uuid.UUID(org_id), token)
    return cookie, csrf


def _upload_escalation(base_url: str, device_id: str, token: str,
                       request_id: str, *,
                       command: str = "echo test") -> tuple[int, str | None]:
    import httpx
    # T12b-2 named edit: always include fingerprint (item 6)
    fp = hashlib.sha256(command.encode()).hexdigest()
    r = httpx.post(
        f"{base_url}/api/v1/sync/escalations",
        json={
            "device_id": device_id,
            "request_id": request_id,
            "record": {"command": command, "status": "pending",
                        "fingerprint": fp},
            "policy_sequence": 1,
        },
        headers={"Authorization": f"Bearer {token}"},
        timeout=10.0,
    )
    esc_id = r.json().get("escalation_id") if r.status_code == 200 else None
    return r.status_code, esc_id


def _make_remote_approval_envelope(
    sk, *,
    request_id: str,
    command: str = "echo test",
    org_id: str,
    project_id: str,
    device_id: str,
    user_id: str,
    decision: str = "approve",
) -> dict:
    pub = bytes(sk.verify_key)
    kid = hashlib.sha256(pub).hexdigest()
    fp = hashlib.sha256(command.encode()).hexdigest()
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
        "registry_version": 1,
        "policy_sequence": 1,
        "user_id": user_id,
        "key_id": kid,
        "nonce": secrets.token_hex(16),
        "not_after": time.time() + 900,
    }
    return sign_envelope("agg/remote-approval/v1", payload, sk)


# ---------------------------------------------------------------------------
# Fixture
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def review_server(pg_url, app_url, owner_url, pg_roles):
    """Agg_cp server for security review tests."""
    gen = make_sync_server(
        pg_url, app_url, owner_url,
        org_names=["Review Org"],
    )
    info = next(gen)

    conninfo = _conninfo(owner_url)
    with psycopg.connect(conninfo, autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [info["org_id"]])
        alice_id = _seed_user_row(conn, info["org_id"], "alice@review.test")
        bob_id = _seed_user_row(conn, info["org_id"], "bob@review.test")
        carol_id = _seed_user_row(conn, info["org_id"], "carol@review.test")

    info["alice_id"] = alice_id
    info["bob_id"] = bob_id
    info["carol_id"] = carol_id

    try:
        yield info
    finally:
        gen.close()


# ===================================================================
# Finding 1: test_device_key_approval_refused_server is vacuous
#
# The T12 test does NOT seed the device key into the registry, so the
# server returns 400 "key not found" rather than 403 "kind refused".
# This test proves the gap by seeding the device key with kind=device
# and asserting the kind-specific refusal message.
# ===================================================================


@pytest.mark.pg
def test_review_device_key_in_registry_refused_for_kind(review_server):
    """A device key PRESENT in the registry must be refused for its kind,
    not for being absent.  This is the correct test for REVIEW_M2 item 7.

    The test seeds the device key into approver_keys with kind='device',
    then submits an approval signed by that key.  The expected refusal
    is 403 with an error message mentioning the kind, not 400 "key not
    found in registry".
    """
    import httpx
    srv = review_server
    device_sk = SigningKey.generate()
    device_pub = bytes(device_sk.verify_key)
    device_kid = hashlib.sha256(device_pub).hexdigest()
    project_id = str(uuid.uuid4())

    # Seed a user for the session and as the key owner
    bob_id = srv["bob_id"]

    with psycopg.connect(_conninfo(srv["owner_url"])) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [srv["org_id"]])
        create_project(conn, srv["org_id"], project_id, environment="staging")
        conn.commit()

    # Seed the device key INTO THE REGISTRY as kind=device, owned by bob
    _seed_registry_with_keys(srv["owner_url"], srv["org_id"], [
        {"key_id": device_kid, "public_key": device_pub.hex(),
         "user_id": bob_id, "kind": "device",
         "roles": ["approver"]},
    ])

    # Set up connector + device token for escalation upload
    other_sk, other_pub, _ = keygen()
    device_id = _seed_connector(
        srv["owner_url"], srv["org_id"], project_id, other_pub,
    )
    dev_token = secrets.token_hex(32)
    _seed_device_token(
        srv["owner_url"], srv["org_id"], project_id, device_id, dev_token,
    )

    status, esc_id = _upload_escalation(
        srv["base_url"], device_id, dev_token, "req-review-devkey-1",
    )
    assert status == 200

    # Create session for bob
    cookie, csrf = _make_fresh_session(
        srv["owner_url"], srv["org_id"], bob_id,
    )

    # Build approval signed with device key, payload user_id = bob
    envelope = _make_remote_approval_envelope(
        device_sk,
        request_id="req-review-devkey-1",
        org_id=srv["org_id"], project_id=project_id,
        device_id=device_id, user_id=bob_id,
    )

    r = httpx.post(
        f"{srv['base_url']}/api/v1/sync/escalations/{esc_id}/approvals",
        cookies={"__Host-agg_session": cookie},
        headers={"X-CSRF-Token": csrf},
        json=envelope,
        timeout=10.0,
    )

    # The server MUST refuse with a kind-specific message, NOT "key not found"
    assert r.status_code == 403, (
        f"Expected 403 (kind refusal), got {r.status_code}: {r.text}"
    )
    body = r.json()
    assert "kind" in body.get("error", "").lower() or "device" in body.get("error", "").lower(), (
        f"Expected kind-specific refusal message, got: {body}"
    )
    # Confirm it is NOT the "key not found" path
    assert "not found" not in body.get("error", "").lower(), (
        f"Got 'key not found' instead of kind refusal: {body}"
    )


# ===================================================================
# Finding 2: missing key-owner binding (key registry user_id != session user)
#
# Bob's session submits an envelope with payload.user_id=bob, signed
# by Carol's registered key.  The auth check (session==payload) passes,
# but the key's registry user_id is Carol, not Bob.  The server should
# refuse because the signing key does not belong to the authenticated
# user.
# ===================================================================


@pytest.mark.pg
def test_review_key_owner_mismatch_refused(review_server):
    """Session user Bob submits an envelope signed by Carol's key.

    Payload.user_id = Bob (matches session).
    Signing key belongs to Carol in the registry.
    The server must refuse because key owner != authenticated user.

    If this test PASSES (the server accepts), the identity binding is
    incomplete: only session==payload is checked, not key_owner==session.
    """
    import httpx
    srv = review_server
    bob_id = srv["bob_id"]
    carol_id = srv["carol_id"]

    carol_sk = SigningKey.generate()
    carol_pub = bytes(carol_sk.verify_key)
    carol_kid = hashlib.sha256(carol_pub).hexdigest()

    project_id = str(uuid.uuid4())
    with psycopg.connect(_conninfo(srv["owner_url"])) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [srv["org_id"]])
        create_project(conn, srv["org_id"], project_id, environment="staging")
        conn.commit()

    # Register Carol's key under Carol's user_id
    _seed_registry_with_keys(srv["owner_url"], srv["org_id"], [
        {"key_id": carol_kid, "public_key": carol_pub.hex(),
         "user_id": carol_id, "kind": "cli",
         "roles": ["approver"]},
    ])

    # Connector + device token -- seed operator_user_id so R2
    # ("operator unknown") cannot mask the key-owner error
    dev_sk, dev_pub, _ = keygen()
    device_id = _seed_connector(
        srv["owner_url"], srv["org_id"], project_id, dev_pub,
        operator_user_id=carol_id,
    )
    dev_token = secrets.token_hex(32)
    _seed_device_token(
        srv["owner_url"], srv["org_id"], project_id, device_id, dev_token,
    )

    status, esc_id = _upload_escalation(
        srv["base_url"], device_id, dev_token, "req-review-keyowner-1",
    )
    assert status == 200

    # Bob's session
    cookie, csrf = _make_fresh_session(
        srv["owner_url"], srv["org_id"], bob_id,
    )

    # Envelope: payload.user_id = Bob, but signed by Carol's key.
    # We need to craft this manually because _make_remote_approval_envelope
    # derives key_id from the signing key.  Here key_id matches Carol's key
    # in the registry, but payload.user_id says Bob.
    fp = hashlib.sha256(b"echo test").hexdigest()
    payload = {
        "request_id": "req-review-keyowner-1",
        "command": "echo test",
        "fingerprint": fp,
        "reviewer_id": bob_id,
        "decision": "approve",
        "approved_at": time.time(),
        "org_id": srv["org_id"],
        "project_id": project_id,
        "device_id": device_id,
        "registry_version": 1,
        "policy_sequence": 1,
        "user_id": bob_id,       # <-- Bob in the payload
        "key_id": carol_kid,     # <-- Carol's key_id
        "nonce": secrets.token_hex(16),
        "not_after": time.time() + 900,
    }
    envelope = sign_envelope("agg/remote-approval/v1", payload, carol_sk)

    r = httpx.post(
        f"{srv['base_url']}/api/v1/sync/escalations/{esc_id}/approvals",
        cookies={"__Host-agg_session": cookie},
        headers={"X-CSRF-Token": csrf},
        json=envelope,
        timeout=10.0,
    )

    # The server MUST refuse: key owner (Carol) != session user (Bob).
    # Assert the specific key-owner error text from the server.
    assert r.status_code == 403, (
        f"Expected 403 (key owner mismatch), got {r.status_code}: {r.text}. "
        "The server accepted an envelope where the signing key belongs to "
        "a different user than the authenticated session."
    )
    body = r.json()
    assert "key owner mismatch" in body.get("error", "").lower(), (
        f"Expected 'key owner mismatch' error, got: {body}. "
        "The server should return 'key owner mismatch: signing key does "
        "not belong to user_id' (escalations.py T13 identity binding)."
    )
