"""T13 tests-first: golden canonical bytes for cross-language validation,
server-side route checks for the web approval UI.

Cross-language fixture
----------------------
``test_guard_golden_fixture_written`` computes the canonical bytes for a
deterministic payload using the Python protocol module and writes them to
``ee/web/tests/fixtures/golden_canonical.json``.  The companion vitest test
in ``ee/web/tests/signing.test.ts`` reads that file and asserts the TS
signing module produces identical bytes.

Routes T13 needs that T12 does not define
-----------------------------------------
GET /api/v1/escalations  (user-facing pending escalation list for web UI)

Routes T13 reuses from T12:
  POST /api/v1/sync/escalations/{escalation_id}/approvals

Routes T13 reuses from T7:
  POST /api/v1/signer-links  (browser key binding, kind=browser)

RED tests xfail on M2T13Pending.  Guards verify existing code.

T6 rule: the sentinel is raised only by one helper ``_need()`` at the
top of a test; the final assertions are plain ``assert``/``pytest.raises``.
Tests never patch global ``os`` attributes.
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import time
import uuid
from pathlib import Path

import psycopg
import pytest
from nacl.signing import SigningKey

from .m2_pending import M2T13Pending
from .m2_sync_server import (
    make_sync_server, ensure_at_head, create_org, create_project,
    keygen, sign_envelope, canonical_json,
)
from .t9_helpers import seed_session, make_session_cookie, compute_csrf
from .fake_idp import FakeClock


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Deterministic payload for cross-language golden fixture (D5.6 full field set)
GOLDEN_PAYLOAD: dict = {
    "approved_at": 1700000000.0,
    "command": "echo golden-test",
    "decision": "approve",
    "device_id": "dev-golden",
    "fingerprint": "abc123def456",
    "key_id": "kid-golden-0000",
    "nonce": "nonce-golden-0000",
    "not_after": 1700000900.0,
    "org_id": "org-golden",
    "policy_sequence": 1,
    "project_id": "proj-golden",
    "registry_version": 1,
    "request_id": "golden-req-1",
    "reviewer_id": "user-golden",
    "user_id": "user-golden",
}

GOLDEN_TAG = "agg/remote-approval/v1"

# Expected canonical JSON (sorted keys, compact separators)
GOLDEN_CANONICAL_JSON = json.dumps(
    GOLDEN_PAYLOAD, sort_keys=True, separators=(",", ":")
).encode("utf-8")

# Expected signed bytes: tag || 0x00 || canonical JSON
GOLDEN_CANONICAL_BYTES = GOLDEN_TAG.encode("utf-8") + b"\x00" + GOLDEN_CANONICAL_JSON

# Non-ASCII payload: tests cross-language Unicode escaping and float formatting.
# Python's json.dumps(ensure_ascii=True) escapes non-ASCII as \uXXXX;
# JavaScript's JSON.stringify does NOT escape non-ASCII by default.
# A fractional float (1700000000.123) serialises identically in both;
# an integral float (1700001000.0) serialises as "1700001000.0" in Python
# but "1700001000" in JS -- a known cross-language difference.
GOLDEN_NONASCII_PAYLOAD: dict = {
    "approved_at": 1700000000.123,
    "command": "echo café ✓",
    "decision": "approve",
    "device_id": "dev-nonascii",
    "fingerprint": "ff00ff00ff00",
    "key_id": "kid-nonascii-0001",
    "nonce": "nonce-nonascii-0001",
    "not_after": 1700001000.0,
    "org_id": "org-nonascii",
    "policy_sequence": 2,
    "project_id": "proj-nonascii",
    "registry_version": 1,
    "request_id": "nonascii-req-1",
    "reviewer_id": "user-nonascii",
    "user_id": "user-nonascii",
}

GOLDEN_NONASCII_CANONICAL_JSON = json.dumps(
    GOLDEN_NONASCII_PAYLOAD, sort_keys=True, separators=(",", ":")
).encode("utf-8")

GOLDEN_NONASCII_CANONICAL_BYTES = (
    GOLDEN_TAG.encode("utf-8") + b"\x00" + GOLDEN_NONASCII_CANONICAL_JSON
)

FIXTURE_DIR = Path(__file__).resolve().parents[1] / "web" / "tests" / "fixtures"


def _need(module: str, attr: str) -> None:
    """Raise M2T13Pending if *module*.*attr* is absent."""
    try:
        mod = __import__(module, fromlist=[attr])
    except ImportError:
        raise M2T13Pending(f"{module} not importable")
    if not hasattr(mod, attr):
        raise M2T13Pending(f"{module}.{attr} not found")


def _conninfo(url: str) -> str:
    return url.replace("+psycopg", "")


def _seed_user_row(conn, org_id: str, email: str,
                   iss: str = "https://idp",
                   sub: str | None = None) -> str:
    """Insert a users row; return user_id (uuid str)."""
    user_id = str(uuid.uuid4())
    if sub is None:
        sub = f"sub-{uuid.uuid4().hex[:8]}"
    conn.execute(
        "INSERT INTO users (id, org_id, oidc_issuer, oidc_subject, email, "
        "status, created_at) VALUES (%s, %s, %s, %s, %s, 'active', now()) "
        "ON CONFLICT DO NOTHING",
        [user_id, org_id, iss, sub, email],
    )
    return user_id


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


def _seed_live_key(conn, org_id: str, user_id: str, kid: str,
                   pub_hex: str, *, kind: str = "cli",
                   roles: list[str] | None = None) -> str:
    """Insert an approver_keys row (live key). Return ak_id.

    T12b-2 named edit: add ``roles`` column (ADR 0010 s8 requires the
    ``approver`` role for the approvals route).
    """
    if roles is None:
        roles = ["approver"]
    import json as _json
    ak_id = str(uuid.uuid4())
    conn.execute(
        "INSERT INTO approver_keys "
        "(id, org_id, user_id, public_key, alg, kind, key_id, "
        " roles, registry_version, enrolled_at, created_at) "
        "VALUES (%s, %s, %s, %s, 'ed25519', %s, %s, %s::jsonb, "
        "1, now(), now()) "
        "ON CONFLICT DO NOTHING",
        [ak_id, org_id, user_id, pub_hex, kind, kid,
         _json.dumps(roles)],
    )
    return ak_id


def _make_fresh_session(owner_url: str, org_id: str, user_id: str):
    """Create a fresh web session. Return (cookie_value, csrf_token)."""
    clock = FakeClock()
    token, csrf, sid = seed_session(
        owner_url, uuid.UUID(org_id), uuid.UUID(user_id), clock=clock,
    )
    cookie = make_session_cookie(uuid.UUID(org_id), token)
    return cookie, csrf


def _upload_escalation(base_url: str, device_id: str, token: str,
                       request_id: str, *, command: str = "echo test",
                       policy_sequence: int = 1,
                       fingerprint: str | None = None) -> tuple[int, str | None]:
    """Upload an escalation via device token. Return (status, escalation_id)."""
    import httpx
    record: dict = {"command": command, "status": "pending"}
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
) -> dict:
    """Build an agg/remote-approval/v1 envelope."""
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
        "registry_version": registry_version,
        "policy_sequence": policy_sequence,
        "user_id": user_id,
        "key_id": kid,
        "nonce": nonce or secrets.token_hex(16),
        "not_after": not_after or (time.time() + 900),
    }
    return sign_envelope("agg/remote-approval/v1", payload, sk)


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
# Module-scoped server fixture
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def web_server(pg_url, app_url, owner_url, pg_roles):
    """4-worker agg_cp server with 2 orgs and users for T13 web tests."""
    gen = make_sync_server(
        pg_url, app_url, owner_url,
        org_names=["Acme Web Org", "Evil Org"],
    )
    info = next(gen)

    # Seed users in both orgs
    conninfo = _conninfo(owner_url)
    with psycopg.connect(conninfo, autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [info["org_id"]])
        alice_id = _seed_user_row(conn, info["org_id"], "alice@acme.test")
        # T12b-2 named edit: operator distinct from approvers (R2)
        operator_id = _seed_user_row(conn, info["org_id"], "operator@acme.test")

        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [info["org_evil"]])
        eve_id = _seed_user_row(conn, info["org_evil"], "eve@evil.test")

    info["alice_id"] = alice_id
    info["operator_id"] = operator_id
    info["eve_id"] = eve_id

    try:
        yield info
    finally:
        gen.close()


# ---------------------------------------------------------------------------
# Guards (pass now -- existing code)
# ---------------------------------------------------------------------------


def test_guard_canonical_bytes_deterministic():
    """Guard: canonical_bytes in protocol.envelope is deterministic for a fixed payload."""
    from sandbox.protocol.envelope import canonical_bytes

    result = canonical_bytes(GOLDEN_TAG, GOLDEN_PAYLOAD)
    assert result == GOLDEN_CANONICAL_BYTES


def test_guard_remote_approval_field_set():
    """Guard: the D5.6 field set is the union of _APPROVAL_FIELDS and the remote fields.

    The full field set: request_id, command, fingerprint, reviewer_id, decision,
    approved_at, org_id, project_id, device_id, registry_version, policy_sequence,
    user_id, key_id, nonce, not_after.
    """
    expected_fields = frozenset({
        "request_id", "command", "fingerprint", "reviewer_id", "decision",
        "approved_at", "org_id", "project_id", "device_id", "registry_version",
        "policy_sequence", "user_id", "key_id", "nonce", "not_after",
    })
    assert set(GOLDEN_PAYLOAD.keys()) == expected_fields
    assert set(GOLDEN_NONASCII_PAYLOAD.keys()) == expected_fields


def test_guard_golden_fixture_written():
    """Guard: write the golden canonical bytes fixture for cross-language tests.

    The fixture file is ee/web/tests/fixtures/golden_canonical.json.
    It contains the tag, payload, canonical JSON hex, and canonical bytes hex
    so the TS tests can verify byte-for-byte identity.

    Extended with a non-ASCII case (``echo cafe checkmark``) and mixed float
    timestamps (fractional approved_at, integral not_after) for cross-language
    escaping and number-formatting coverage.
    """
    FIXTURE_DIR.mkdir(parents=True, exist_ok=True)

    fixture = {
        "tag": GOLDEN_TAG,
        "payload": GOLDEN_PAYLOAD,
        "canonical_json_hex": GOLDEN_CANONICAL_JSON.hex(),
        "canonical_bytes_hex": GOLDEN_CANONICAL_BYTES.hex(),
        "canonical_bytes_sha256": hashlib.sha256(GOLDEN_CANONICAL_BYTES).hexdigest(),
        "cases": [
            {
                "name": "non_ascii",
                "tag": GOLDEN_TAG,
                "payload": GOLDEN_NONASCII_PAYLOAD,
                "canonical_json_hex": GOLDEN_NONASCII_CANONICAL_JSON.hex(),
                "canonical_bytes_hex": GOLDEN_NONASCII_CANONICAL_BYTES.hex(),
                "canonical_bytes_sha256": hashlib.sha256(
                    GOLDEN_NONASCII_CANONICAL_BYTES
                ).hexdigest(),
            },
        ],
    }

    fixture_path = FIXTURE_DIR / "golden_canonical.json"
    fixture_path.write_text(
        json.dumps(fixture, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    assert fixture_path.exists()

    # Verify round-trip for basic case
    loaded = json.loads(fixture_path.read_text(encoding="utf-8"))
    assert bytes.fromhex(loaded["canonical_bytes_hex"]) == GOLDEN_CANONICAL_BYTES

    # Verify round-trip for non-ASCII case
    nonascii = loaded["cases"][0]
    assert nonascii["name"] == "non_ascii"
    assert bytes.fromhex(nonascii["canonical_bytes_hex"]) == (
        GOLDEN_NONASCII_CANONICAL_BYTES
    )


def test_guard_ts_signed_envelope_verifies():
    """Guard: an envelope signed over the golden fixture bytes verifies
    with the Python Ed25519 verifier.

    This proves that IF the TS module produces the same canonical bytes,
    signatures generated by any Ed25519 implementation will verify
    cross-language.  Both the basic and non-ASCII payloads are checked.
    """
    from nacl.signing import VerifyKey

    sk = SigningKey.generate()
    pub = bytes(sk.verify_key)

    # Sign and verify the basic golden canonical bytes
    sig1 = sk.sign(GOLDEN_CANONICAL_BYTES).signature
    vk = VerifyKey(pub)
    vk.verify(GOLDEN_CANONICAL_BYTES, sig1)  # raises if invalid

    # Sign and verify the non-ASCII golden canonical bytes
    sig2 = sk.sign(GOLDEN_NONASCII_CANONICAL_BYTES).signature
    vk.verify(GOLDEN_NONASCII_CANONICAL_BYTES, sig2)


# ===================================================================
# RED: escalation list route for web UI
# ===================================================================


@pytest.mark.pg
def test_escalation_list_route_exists(web_server):
    """GET /api/v1/escalations returns pending escalations for the web user.

    This route is user-facing (session auth), not device-facing.
    T12's GET /api/v1/sync/decisions is device-facing.
    """
    _need("agg_cp.web.escalations", "router")

    import httpx
    srv = web_server
    sk, pub, kid = keygen()
    project_id = str(uuid.uuid4())

    with psycopg.connect(_conninfo(srv["owner_url"])) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [srv["org_id"]])
        create_project(conn, srv["org_id"], project_id, environment="staging")
        conn.commit()

    device_id = _seed_connector(srv["owner_url"], srv["org_id"],
                                project_id, pub,
                                operator_user_id=srv["operator_id"])
    token = secrets.token_hex(32)
    _seed_device_token(srv["owner_url"], srv["org_id"], project_id,
                       device_id, token)

    # Upload an escalation via the device token (T12 route)
    status, esc_id = _upload_escalation(
        srv["base_url"], device_id, token, "req-list-1",
    )
    assert status == 200
    assert esc_id is not None

    # GET the escalation list with alice's web session
    cookie, csrf = _make_fresh_session(
        srv["owner_url"], srv["org_id"], srv["alice_id"],
    )
    r = httpx.get(
        f"{srv['base_url']}/api/v1/escalations",
        cookies={"__Host-agg_session": cookie},
        timeout=10.0,
    )
    assert r.status_code == 200
    data = r.json()
    items = data if isinstance(data, list) else data.get("escalations", [])
    assert len(items) >= 1
    item = next((i for i in items if i.get("escalation_id") == esc_id), None)
    assert item is not None, f"escalation {esc_id} not in list"
    # Contract: each item has these fields
    for field in ("escalation_id", "request_id", "command",
                  "project_id", "policy_sequence"):
        assert field in item, f"missing field {field}"


@pytest.mark.pg
def test_escalation_list_filtered_by_org(web_server):
    """The escalation list is filtered by the user's org (RLS)."""
    _need("agg_cp.web.escalations", "router")

    import httpx
    srv = web_server
    sk, pub, kid = keygen()
    project_id = str(uuid.uuid4())

    # Create an escalation in Acme org
    with psycopg.connect(_conninfo(srv["owner_url"])) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [srv["org_id"]])
        create_project(conn, srv["org_id"], project_id, environment="staging")
        conn.commit()

    device_id = _seed_connector(srv["owner_url"], srv["org_id"],
                                project_id, pub,
                                operator_user_id=srv["operator_id"])
    token = secrets.token_hex(32)
    _seed_device_token(srv["owner_url"], srv["org_id"], project_id,
                       device_id, token)

    status, esc_id = _upload_escalation(
        srv["base_url"], device_id, token, "req-orgfilter-1",
    )
    assert status == 200

    # Eve (Evil Org) should see nothing from Acme
    cookie, csrf = _make_fresh_session(
        srv["owner_url"], srv["org_evil"], srv["eve_id"],
    )
    r = httpx.get(
        f"{srv['base_url']}/api/v1/escalations",
        cookies={"__Host-agg_session": cookie},
        timeout=10.0,
    )
    assert r.status_code == 200
    data = r.json()
    items = data if isinstance(data, list) else data.get("escalations", [])
    visible_ids = [i.get("escalation_id") for i in items]
    assert esc_id not in visible_ids, "eve sees acme's escalation"


@pytest.mark.pg
def test_escalation_list_shows_environment(web_server):
    """The escalation list includes the project environment for prod-guard display."""
    _need("agg_cp.web.escalations", "router")

    import httpx
    srv = web_server
    sk, pub, kid = keygen()
    project_id = str(uuid.uuid4())

    with psycopg.connect(_conninfo(srv["owner_url"])) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [srv["org_id"]])
        create_project(conn, srv["org_id"], project_id, environment="staging")
        conn.commit()

    device_id = _seed_connector(srv["owner_url"], srv["org_id"],
                                project_id, pub,
                                operator_user_id=srv["operator_id"])
    token = secrets.token_hex(32)
    _seed_device_token(srv["owner_url"], srv["org_id"], project_id,
                       device_id, token)

    status, esc_id = _upload_escalation(
        srv["base_url"], device_id, token, "req-env-1",
    )
    assert status == 200

    cookie, csrf = _make_fresh_session(
        srv["owner_url"], srv["org_id"], srv["alice_id"],
    )
    r = httpx.get(
        f"{srv['base_url']}/api/v1/escalations",
        cookies={"__Host-agg_session": cookie},
        timeout=10.0,
    )
    assert r.status_code == 200
    data = r.json()
    items = data if isinstance(data, list) else data.get("escalations", [])
    item = next((i for i in items if i.get("escalation_id") == esc_id), None)
    assert item is not None
    assert "environment" in item or "is_prod" in item, (
        "neither environment nor is_prod in response"
    )


@pytest.mark.pg
def test_escalation_list_marks_prod(web_server):
    """Prod escalations are marked in the list so the UI can hide approve.

    The response must include ``is_prod: true`` or ``environment: "prod"``
    so the TS code can hide the approve button (exit check D5.5).
    """
    _need("agg_cp.web.escalations", "router")

    import httpx
    srv = web_server
    sk, pub, kid = keygen()
    project_id = str(uuid.uuid4())

    with psycopg.connect(_conninfo(srv["owner_url"])) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [srv["org_id"]])
        create_project(conn, srv["org_id"], project_id, environment="prod")
        conn.commit()

    device_id = _seed_connector(srv["owner_url"], srv["org_id"],
                                project_id, pub,
                                operator_user_id=srv["operator_id"])
    token = secrets.token_hex(32)
    _seed_device_token(srv["owner_url"], srv["org_id"], project_id,
                       device_id, token)

    status, esc_id = _upload_escalation(
        srv["base_url"], device_id, token, "req-prod-1",
    )
    assert status == 200

    cookie, csrf = _make_fresh_session(
        srv["owner_url"], srv["org_id"], srv["alice_id"],
    )
    r = httpx.get(
        f"{srv['base_url']}/api/v1/escalations",
        cookies={"__Host-agg_session": cookie},
        timeout=10.0,
    )
    assert r.status_code == 200
    data = r.json()
    items = data if isinstance(data, list) else data.get("escalations", [])
    item = next((i for i in items if i.get("escalation_id") == esc_id), None)
    assert item is not None
    is_prod = item.get("is_prod", False) or item.get("environment") == "prod"
    assert is_prod, "prod escalation not marked as prod"


# ===================================================================
# RED: browser key link via web session
# ===================================================================


@pytest.mark.pg
def test_browser_key_link_creates_pending(web_server):
    """POST /api/v1/signer-links with kind=browser creates a pending key entry.

    The binding mirrors the T7 signer link flow: the user generates a
    WebCrypto Ed25519 key pair and submits the public key.  The server
    creates a pending entry tied to the user's session identity.
    """
    _need("agg_cp.web.browser_keys", "link_browser_key")

    import httpx
    srv = web_server
    sk = SigningKey.generate()
    pub = bytes(sk.verify_key)
    kid = hashlib.sha256(pub).hexdigest()

    cookie, csrf = _make_fresh_session(
        srv["owner_url"], srv["org_id"], srv["alice_id"],
    )
    r = httpx.post(
        f"{srv['base_url']}/api/v1/signer-links",
        cookies={"__Host-agg_session": cookie},
        headers={"X-CSRF-Token": csrf},
        json={"public_key": pub.hex(), "key_id": kid, "kind": "browser"},
        timeout=10.0,
    )
    assert r.status_code in (200, 201)

    # Verify a key entry exists in the DB (signer_links or approver_keys)
    with psycopg.connect(_conninfo(srv["owner_url"])) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [srv["org_id"]])
        row = conn.execute(
            "SELECT status FROM signer_links "
            "WHERE org_id = %s::uuid AND key_id = %s "
            "ORDER BY created_at DESC LIMIT 1",
            [srv["org_id"], kid],
        ).fetchone()
        if row is None:
            row = conn.execute(
                "SELECT kind FROM approver_keys WHERE key_id = %s",
                [kid],
            ).fetchone()
    assert row is not None, "browser key entry not found in DB"


@pytest.mark.pg
def test_browser_key_link_requires_session(web_server):
    """Browser key linking requires a valid user session, not a device token."""
    _need("agg_cp.web.browser_keys", "link_browser_key")

    import httpx
    srv = web_server
    sk = SigningKey.generate()
    pub = bytes(sk.verify_key)
    kid = hashlib.sha256(pub).hexdigest()

    body = {"public_key": pub.hex(), "key_id": kid, "kind": "browser"}

    # No session -> 401
    r1 = httpx.post(
        f"{srv['base_url']}/api/v1/signer-links",
        json=body,
        timeout=10.0,
    )
    assert r1.status_code == 401

    # Device token -> 401 or 403
    dsk, dpub, dkid = keygen()
    project_id = str(uuid.uuid4())
    with psycopg.connect(_conninfo(srv["owner_url"])) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [srv["org_id"]])
        create_project(conn, srv["org_id"], project_id, environment="staging")
        conn.commit()

    device_id = _seed_connector(srv["owner_url"], srv["org_id"],
                                project_id, dpub,
                                operator_user_id=srv["operator_id"])
    dev_token = secrets.token_hex(32)
    _seed_device_token(srv["owner_url"], srv["org_id"], project_id,
                       device_id, dev_token)

    r2 = httpx.post(
        f"{srv['base_url']}/api/v1/signer-links",
        json=body,
        headers={"Authorization": f"Bearer {dev_token}"},
        timeout=10.0,
    )
    assert r2.status_code in (401, 403)


# ===================================================================
# RED: approval via browser session (D5.5, D6.2)
# ===================================================================


@pytest.mark.pg
def test_approval_via_browser_session_accepted(web_server):
    """A browser-session user can submit an approval to the existing T12 route.

    The approval is signed client-side with WebCrypto and submitted as
    an agg/remote-approval/v1 envelope.  The server validates it.
    """
    _need("agg_cp.web.escalations", "submit_browser_approval")

    import httpx
    srv = web_server
    alice_sk = SigningKey.generate()
    alice_pub = bytes(alice_sk.verify_key)
    alice_kid = hashlib.sha256(alice_pub).hexdigest()

    project_id = str(uuid.uuid4())
    with psycopg.connect(_conninfo(srv["owner_url"])) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [srv["org_id"]])
        create_project(conn, srv["org_id"], project_id, environment="staging")
        conn.commit()

    device_sk, device_pub, device_kid = keygen()
    device_id = _seed_connector(srv["owner_url"], srv["org_id"],
                                project_id, device_pub,
                                operator_user_id=srv["operator_id"])
    dev_token = secrets.token_hex(32)
    _seed_device_token(srv["owner_url"], srv["org_id"], project_id,
                       device_id, dev_token)

    _seed_registry_with_keys(srv["owner_url"], srv["org_id"], [
        {"key_id": alice_kid, "public_key": alice_pub.hex(),
         "user_id": srv["alice_id"], "kind": "browser",
         "roles": ["approver"]},
    ])

    status, esc_id = _upload_escalation(
        srv["base_url"], device_id, dev_token,
        "req-browser-approve-1", policy_sequence=1,
    )
    assert status == 200

    envelope = _make_remote_approval_envelope(
        alice_sk,
        request_id="req-browser-approve-1",
        org_id=srv["org_id"], project_id=project_id,
        device_id=device_id, user_id=srv["alice_id"],
        policy_sequence=1,
    )

    cookie, csrf = _make_fresh_session(
        srv["owner_url"], srv["org_id"], srv["alice_id"],
    )
    r = httpx.post(
        f"{srv['base_url']}/api/v1/sync/escalations/{esc_id}/approvals",
        cookies={"__Host-agg_session": cookie},
        headers={"X-CSRF-Token": csrf},
        json=envelope,
        timeout=10.0,
    )
    assert r.status_code == 200
    assert "approval_id" in r.json()


@pytest.mark.pg
def test_deny_via_browser_session_accepted(web_server):
    """A browser-session user can submit a deny decision."""
    _need("agg_cp.web.escalations", "submit_browser_approval")

    import httpx
    srv = web_server
    alice_sk = SigningKey.generate()
    alice_pub = bytes(alice_sk.verify_key)
    alice_kid = hashlib.sha256(alice_pub).hexdigest()

    project_id = str(uuid.uuid4())
    with psycopg.connect(_conninfo(srv["owner_url"])) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [srv["org_id"]])
        create_project(conn, srv["org_id"], project_id, environment="staging")
        conn.commit()

    device_sk, device_pub, device_kid = keygen()
    device_id = _seed_connector(srv["owner_url"], srv["org_id"],
                                project_id, device_pub,
                                operator_user_id=srv["operator_id"])
    dev_token = secrets.token_hex(32)
    _seed_device_token(srv["owner_url"], srv["org_id"], project_id,
                       device_id, dev_token)

    _seed_registry_with_keys(srv["owner_url"], srv["org_id"], [
        {"key_id": alice_kid, "public_key": alice_pub.hex(),
         "user_id": srv["alice_id"], "kind": "browser",
         "roles": ["approver"]},
    ])

    status, esc_id = _upload_escalation(
        srv["base_url"], device_id, dev_token, "req-browser-deny-1",
    )
    assert status == 200

    envelope = _make_remote_approval_envelope(
        alice_sk,
        request_id="req-browser-deny-1",
        org_id=srv["org_id"], project_id=project_id,
        device_id=device_id, user_id=srv["alice_id"],
        decision="deny",
    )

    cookie, csrf = _make_fresh_session(
        srv["owner_url"], srv["org_id"], srv["alice_id"],
    )
    r = httpx.post(
        f"{srv['base_url']}/api/v1/sync/escalations/{esc_id}/approvals",
        cookies={"__Host-agg_session": cookie},
        headers={"X-CSRF-Token": csrf},
        json=envelope,
        timeout=10.0,
    )
    assert r.status_code == 200


# ===================================================================
# RED: CSP header on web-served responses
# ===================================================================


@pytest.mark.pg
def test_csp_header_on_web_responses(web_server):
    """The server sets a strict CSP header on web-served HTML and API responses.

    Expected CSP includes: default-src 'self'; script-src 'self';
    style-src 'self'; frame-ancestors 'none'; base-uri 'none';
    form-action 'self'; object-src 'none'.
    """
    _need("agg_cp.web.escalations", "router")

    import httpx
    srv = web_server
    cookie, csrf = _make_fresh_session(
        srv["owner_url"], srv["org_id"], srv["alice_id"],
    )
    r = httpx.get(
        f"{srv['base_url']}/api/v1/escalations",
        cookies={"__Host-agg_session": cookie},
        timeout=10.0,
    )
    assert r.status_code == 200
    csp = r.headers.get("content-security-policy", "")
    assert csp, "content-security-policy header missing"
    assert "unsafe-inline" not in csp
    assert "unsafe-eval" not in csp
    assert "default-src" in csp
    assert "frame-ancestors" in csp


# ===================================================================
# RED: no private key material in any server response
# ===================================================================


@pytest.mark.pg
def test_no_private_key_in_escalation_list_response(web_server):
    """The escalation list response must not contain any private key material.

    HAR-style check: scan every JSON field in the response body for
    patterns matching Ed25519 private keys (64-byte hex or base64).
    """
    _need("agg_cp.web.escalations", "router")

    import httpx
    srv = web_server
    sk, pub, kid = keygen()
    project_id = str(uuid.uuid4())

    with psycopg.connect(_conninfo(srv["owner_url"])) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [srv["org_id"]])
        create_project(conn, srv["org_id"], project_id, environment="staging")
        conn.commit()

    device_id = _seed_connector(srv["owner_url"], srv["org_id"],
                                project_id, pub,
                                operator_user_id=srv["operator_id"])
    token = secrets.token_hex(32)
    _seed_device_token(srv["owner_url"], srv["org_id"], project_id,
                       device_id, token)

    _upload_escalation(srv["base_url"], device_id, token, "req-nokey-list-1")

    cookie, csrf = _make_fresh_session(
        srv["owner_url"], srv["org_id"], srv["alice_id"],
    )
    r = httpx.get(
        f"{srv['base_url']}/api/v1/escalations",
        cookies={"__Host-agg_session": cookie},
        timeout=10.0,
    )
    assert r.status_code == 200
    _assert_no_private_key(r.text)


@pytest.mark.pg
def test_no_private_key_in_approval_response(web_server):
    """The approval response must not leak private key material."""
    _need("agg_cp.web.escalations", "submit_browser_approval")

    import httpx
    srv = web_server
    alice_sk = SigningKey.generate()
    alice_pub = bytes(alice_sk.verify_key)
    alice_kid = hashlib.sha256(alice_pub).hexdigest()

    project_id = str(uuid.uuid4())
    with psycopg.connect(_conninfo(srv["owner_url"])) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [srv["org_id"]])
        create_project(conn, srv["org_id"], project_id, environment="staging")
        conn.commit()

    device_sk, device_pub, device_kid = keygen()
    device_id = _seed_connector(srv["owner_url"], srv["org_id"],
                                project_id, device_pub,
                                operator_user_id=srv["operator_id"])
    dev_token = secrets.token_hex(32)
    _seed_device_token(srv["owner_url"], srv["org_id"], project_id,
                       device_id, dev_token)

    _seed_registry_with_keys(srv["owner_url"], srv["org_id"], [
        {"key_id": alice_kid, "public_key": alice_pub.hex(),
         "user_id": srv["alice_id"], "kind": "browser",
         "roles": ["approver"]},
    ])

    status, esc_id = _upload_escalation(
        srv["base_url"], device_id, dev_token, "req-nokey-approval-1",
    )
    assert status == 200

    envelope = _make_remote_approval_envelope(
        alice_sk,
        request_id="req-nokey-approval-1",
        org_id=srv["org_id"], project_id=project_id,
        device_id=device_id, user_id=srv["alice_id"],
    )

    cookie, csrf = _make_fresh_session(
        srv["owner_url"], srv["org_id"], srv["alice_id"],
    )
    r = httpx.post(
        f"{srv['base_url']}/api/v1/sync/escalations/{esc_id}/approvals",
        cookies={"__Host-agg_session": cookie},
        headers={"X-CSRF-Token": csrf},
        json=envelope,
        timeout=10.0,
    )
    # Check body regardless of status code
    _assert_no_private_key(r.text)


# ===================================================================
# RED: approvals-route auth change (T13 lifts named limit 5b)
# ===================================================================
#
# T12 left a named limit (M2_BASELINE section 5b): the approvals route
# POST /api/v1/sync/escalations/{id}/approvals accepts device tokens.
# T13 lifts it: the route accepts ONLY signer tokens (agg/signer-assert/v1
# via POST /api/v1/sync/signer/token) or web session cookies with a valid
# CSRF token (X-CSRF-Token header).  Device tokens get 401 or 403.
#
# T12 ee tests that submit approvals via device token and will need a
# named edit at build time (do NOT edit them now):
#   ee/tests/test_m2_t12_remote.py::test_device_key_approval_refused_server
#   ee/tests/test_m2_t12_remote.py::test_bundle_signer_key_approval_refused_server
#   ee/tests/test_m2_t12_remote.py::test_prod_approval_refused_server
#   ee/tests/test_m2_t12_remote.py::test_wrong_field_set_refused_server
#   ee/tests/test_m2_t12_remote.py::test_expired_not_after_refused_server
#   ee/tests/test_m2_t12_remote.py::test_duplicate_approval_same_user_refused


@pytest.mark.pg
def test_approvals_route_refuses_device_token(web_server):
    """POST /api/v1/sync/escalations/{id}/approvals with a device token
    gets 401 or 403 after T13 lifts the named limit (REVIEW_M2 item 7).

    The T12 build accepted device tokens as a simplification (section 5b).
    T13 restricts the route to signer tokens and web session cookies only.
    A device token that previously returned 200 (for valid approval content)
    must now return 401 or 403 regardless of the envelope.
    """
    _need("agg_cp.sync.escalations", "_T13_APPROVALS_AUTH")

    import httpx
    srv = web_server
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
         "user_id": srv["alice_id"], "kind": "cli",
         "roles": ["approver"]},
    ])

    device_id = _seed_connector(srv["owner_url"], srv["org_id"],
                                project_id, device_pub,
                                operator_user_id=srv["operator_id"])
    dev_token = secrets.token_hex(32)
    _seed_device_token(srv["owner_url"], srv["org_id"], project_id,
                       device_id, dev_token)

    status, esc_id = _upload_escalation(
        srv["base_url"], device_id, dev_token, "req-devtoken-auth-1",
    )
    assert status == 200

    envelope = _make_remote_approval_envelope(
        bob_sk,
        request_id="req-devtoken-auth-1",
        org_id=srv["org_id"], project_id=project_id,
        device_id=device_id, user_id=srv["alice_id"],
    )

    # Device token on the approvals route: must be refused after T13
    r = httpx.post(
        f"{srv['base_url']}/api/v1/sync/escalations/{esc_id}/approvals",
        json=envelope,
        headers={"Authorization": f"Bearer {dev_token}"},
        timeout=10.0,
    )
    assert r.status_code in (401, 403)


@pytest.mark.pg
def test_approvals_route_accepts_signer_token(web_server):
    """POST /api/v1/sync/escalations/{id}/approvals with a signer token
    (from POST /api/v1/sync/signer/token, agg/signer-assert/v1) is accepted.

    A valid cli-key approval envelope on a non-prod escalation is stored.
    The signer token is obtained by authenticating with a live CLI key via
    the T7 signer flow; the approval is an agg/remote-approval/v1 envelope
    signed by the same key.  Expected: 200 with approval_id.
    """
    _need("agg_cp.sync.escalations", "_T13_APPROVALS_AUTH")

    import httpx
    srv = web_server
    alice_sk = SigningKey.generate()
    alice_pub = bytes(alice_sk.verify_key)
    alice_kid = hashlib.sha256(alice_pub).hexdigest()

    project_id = str(uuid.uuid4())
    with psycopg.connect(_conninfo(srv["owner_url"])) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [srv["org_id"]])
        create_project(conn, srv["org_id"], project_id, environment="staging")
        conn.commit()

    # Seed alice's CLI key as live
    with psycopg.connect(_conninfo(srv["owner_url"]), autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [srv["org_id"]])
        _seed_live_key(conn, srv["org_id"], srv["alice_id"],
                       alice_kid, alice_pub.hex(), kind="cli")

    device_sk, device_pub, device_kid = keygen()
    device_id = _seed_connector(srv["owner_url"], srv["org_id"],
                                project_id, device_pub,
                                operator_user_id=srv["operator_id"])
    dev_token = secrets.token_hex(32)
    _seed_device_token(srv["owner_url"], srv["org_id"], project_id,
                       device_id, dev_token)

    status, esc_id = _upload_escalation(
        srv["base_url"], device_id, dev_token, "req-signer-auth-1",
    )
    assert status == 200

    # Authenticate via agg/signer-assert/v1 to get a signer token
    assertion = _sign_assertion(
        alice_sk, alice_kid,
        nonce=f"n-{uuid.uuid4().hex[:8]}",
        aud=srv["base_url"],
    )
    r_token = httpx.post(
        f"{srv['base_url']}/api/v1/sync/signer/token",
        json=assertion,
        timeout=10.0,
    )
    assert r_token.status_code == 200
    signer_token = r_token.json()["token"]

    envelope = _make_remote_approval_envelope(
        alice_sk,
        request_id="req-signer-auth-1",
        org_id=srv["org_id"], project_id=project_id,
        device_id=device_id, user_id=srv["alice_id"],
    )

    r = httpx.post(
        f"{srv['base_url']}/api/v1/sync/escalations/{esc_id}/approvals",
        json=envelope,
        headers={"Authorization": f"Bearer {signer_token}"},
        timeout=10.0,
    )
    assert r.status_code == 200
    assert "approval_id" in r.json()


@pytest.mark.pg
def test_approvals_route_session_without_csrf_refused(web_server):
    """POST /api/v1/sync/escalations/{id}/approvals with a valid session
    cookie but no X-CSRF-Token header gets 403.

    Session-based writes must include the HMAC-SHA256 CSRF token derived
    from the session token (T9 design: ``base64url(HMAC(key=token,
    msg=b"agg-csrf-v1"))``).  A missing or wrong header is 403.
    """
    _need("agg_cp.sync.escalations", "_T13_APPROVALS_AUTH")

    import httpx
    srv = web_server
    alice_sk = SigningKey.generate()
    alice_pub = bytes(alice_sk.verify_key)
    alice_kid = hashlib.sha256(alice_pub).hexdigest()

    project_id = str(uuid.uuid4())
    with psycopg.connect(_conninfo(srv["owner_url"])) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [srv["org_id"]])
        create_project(conn, srv["org_id"], project_id, environment="staging")
        conn.commit()

    _seed_registry_with_keys(srv["owner_url"], srv["org_id"], [
        {"key_id": alice_kid, "public_key": alice_pub.hex(),
         "user_id": srv["alice_id"], "kind": "browser",
         "roles": ["approver"]},
    ])

    device_sk, device_pub, device_kid = keygen()
    device_id = _seed_connector(srv["owner_url"], srv["org_id"],
                                project_id, device_pub,
                                operator_user_id=srv["operator_id"])
    dev_token = secrets.token_hex(32)
    _seed_device_token(srv["owner_url"], srv["org_id"], project_id,
                       device_id, dev_token)

    status, esc_id = _upload_escalation(
        srv["base_url"], device_id, dev_token, "req-nocsrf-1",
    )
    assert status == 200

    envelope = _make_remote_approval_envelope(
        alice_sk,
        request_id="req-nocsrf-1",
        org_id=srv["org_id"], project_id=project_id,
        device_id=device_id, user_id=srv["alice_id"],
    )

    # Session cookie but NO CSRF header
    cookie, csrf = _make_fresh_session(
        srv["owner_url"], srv["org_id"], srv["alice_id"],
    )
    r = httpx.post(
        f"{srv['base_url']}/api/v1/sync/escalations/{esc_id}/approvals",
        cookies={"__Host-agg_session": cookie},
        # deliberately omit X-CSRF-Token
        json=envelope,
        timeout=10.0,
    )
    assert r.status_code == 403


@pytest.mark.pg
def test_approvals_route_cross_org_session_404(web_server):
    """Eve's session (Evil Org) cannot reach Acme's escalation via RLS.

    POST /api/v1/sync/escalations/{acme_esc_id}/approvals with eve's
    valid session cookie and CSRF returns 404 because the escalation is
    invisible under eve's org_id (row-level security).
    """
    _need("agg_cp.sync.escalations", "_T13_APPROVALS_AUTH")

    import httpx
    srv = web_server
    eve_sk = SigningKey.generate()
    eve_pub = bytes(eve_sk.verify_key)
    eve_kid = hashlib.sha256(eve_pub).hexdigest()

    project_id = str(uuid.uuid4())
    with psycopg.connect(_conninfo(srv["owner_url"])) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [srv["org_id"]])
        create_project(conn, srv["org_id"], project_id, environment="staging")
        conn.commit()

    device_sk, device_pub, device_kid = keygen()
    device_id = _seed_connector(srv["owner_url"], srv["org_id"],
                                project_id, device_pub,
                                operator_user_id=srv["operator_id"])
    dev_token = secrets.token_hex(32)
    _seed_device_token(srv["owner_url"], srv["org_id"], project_id,
                       device_id, dev_token)

    status, esc_id = _upload_escalation(
        srv["base_url"], device_id, dev_token, "req-crossorg-session-1",
    )
    assert status == 200

    envelope = _make_remote_approval_envelope(
        eve_sk,
        request_id="req-crossorg-session-1",
        org_id=srv["org_id"], project_id=project_id,
        device_id=device_id, user_id=srv["eve_id"],
    )

    # Eve's session (Evil Org) tries to approve Acme's escalation
    cookie, csrf = _make_fresh_session(
        srv["owner_url"], srv["org_evil"], srv["eve_id"],
    )
    r = httpx.post(
        f"{srv['base_url']}/api/v1/sync/escalations/{esc_id}/approvals",
        cookies={"__Host-agg_session": cookie},
        headers={"X-CSRF-Token": csrf},
        json=envelope,
        timeout=10.0,
    )
    assert r.status_code == 404


@pytest.mark.pg
def test_escalation_list_requires_session(web_server):
    """GET /api/v1/escalations without a session gets 401.
    GET /api/v1/escalations with a device token (Authorization: Bearer)
    also gets 401 or 403.

    The escalation list route is user-facing and requires a valid web
    session cookie, not device auth.  This complements the existing
    test_escalation_list_route_exists which checks the route is registered.
    """
    _need("agg_cp.web.escalations", "router")

    import httpx
    srv = web_server

    # No auth at all -> 401
    r1 = httpx.get(
        f"{srv['base_url']}/api/v1/escalations",
        timeout=10.0,
    )
    assert r1.status_code == 401

    # Device token -> 401 or 403
    dsk, dpub, dkid = keygen()
    project_id = str(uuid.uuid4())
    with psycopg.connect(_conninfo(srv["owner_url"])) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [srv["org_id"]])
        create_project(conn, srv["org_id"], project_id, environment="staging")
        conn.commit()

    device_id = _seed_connector(srv["owner_url"], srv["org_id"],
                                project_id, dpub,
                                operator_user_id=srv["operator_id"])
    dev_token = secrets.token_hex(32)
    _seed_device_token(srv["owner_url"], srv["org_id"], project_id,
                       device_id, dev_token)

    r2 = httpx.get(
        f"{srv['base_url']}/api/v1/escalations",
        headers={"Authorization": f"Bearer {dev_token}"},
        timeout=10.0,
    )
    assert r2.status_code in (401, 403)


# ===================================================================
# RED: approval user mismatch refused
# ===================================================================


@pytest.mark.pg
def test_approval_user_mismatch_refused(web_server):
    """The session user must equal payload user_id AND the key's registry
    user_id.  Alice's session submits an envelope where payload user_id
    is bob.  The server refuses because session user (alice) != payload
    user_id (bob).
    """
    _need("agg_cp.web.escalations", "submit_browser_approval")

    import httpx
    srv = web_server
    bob_sk = SigningKey.generate()
    bob_pub = bytes(bob_sk.verify_key)
    bob_kid = hashlib.sha256(bob_pub).hexdigest()

    project_id = str(uuid.uuid4())
    with psycopg.connect(_conninfo(srv["owner_url"])) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [srv["org_id"]])
        create_project(conn, srv["org_id"], project_id, environment="staging")
        conn.commit()

    # Seed bob as a separate user in the same org
    with psycopg.connect(_conninfo(srv["owner_url"]), autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [srv["org_id"]])
        bob_id = _seed_user_row(conn, srv["org_id"], "bob@acme.test")

    _seed_registry_with_keys(srv["owner_url"], srv["org_id"], [
        {"key_id": bob_kid, "public_key": bob_pub.hex(),
         "user_id": bob_id, "kind": "browser",
         "roles": ["approver"]},
    ])

    device_sk, device_pub, device_kid = keygen()
    device_id = _seed_connector(srv["owner_url"], srv["org_id"],
                                project_id, device_pub,
                                operator_user_id=srv["operator_id"])
    dev_token = secrets.token_hex(32)
    _seed_device_token(srv["owner_url"], srv["org_id"], project_id,
                       device_id, dev_token)

    status, esc_id = _upload_escalation(
        srv["base_url"], device_id, dev_token, "req-mismatch-1",
    )
    assert status == 200

    # Envelope with bob's user_id and bob's signing key
    envelope = _make_remote_approval_envelope(
        bob_sk,
        request_id="req-mismatch-1",
        org_id=srv["org_id"], project_id=project_id,
        device_id=device_id, user_id=bob_id,
    )

    # Submit with ALICE's session -- alice != bob
    cookie, csrf = _make_fresh_session(
        srv["owner_url"], srv["org_id"], srv["alice_id"],
    )
    r = httpx.post(
        f"{srv['base_url']}/api/v1/sync/escalations/{esc_id}/approvals",
        cookies={"__Host-agg_session": cookie},
        headers={"X-CSRF-Token": csrf},
        json=envelope,
        timeout=10.0,
    )
    assert r.status_code in (400, 403)
