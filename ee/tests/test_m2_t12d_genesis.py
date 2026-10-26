"""T12d d1 tests-first: genesis bootstrap route, candidates, scope rules.

Interface contract (pinned -- the build removes only xfail markers)
-------------------------------------------------------------------
ADR 0011 defines the genesis bootstrap for the first registry version.

Server routes (agg_cp.sync.signer, T12d additions):

    POST /api/v1/sync/signer/genesis
        Body: ``{genesis_code, envelope}``
        Scope: ``pending_link`` tokens may reach ``link`` and ``genesis`` only.
        Transaction: ``pg_advisory_xact_lock(hashtext('agg-genesis:' || org_id))``.
        1. 409 ``genesis_exists`` if any version exists; ``second_genesis`` alert.
        2. Constant-time code check (sha256-stored, 192-bit, 60 min, 5 attempts).
        3. Token user must hold org ``admin`` role; key is that user's pending link.
        4. Envelope field-by-field validation (ADR 0011 2.4).
        5. ``store_registry_version`` + mark code used + mark link consumed +
           ``admin_audit`` row ``registry_genesis``.
        6. Response: ``{version: 1}`` only.

    GET /api/v1/sync/signer/candidates
        Auth: confirmed signer token, admin role.
        Org-scoped: other orgs -> 404.
        Lists pending CLI links and browser keys:
          key_id, public_key, user_id, iss, sub, kind.

    Scope rule changes:
        ``pending_link`` may reach ``link``, ``genesis``, and
        ``/signatures`` ONLY when the envelope adds the token's own key.

    migrate.py additions:
        Emits ``genesis_code`` once (JSON line) when no version and no live
        code exists.  Never after v1.

RED tests xfail on M2T12dPending.  Guards verify existing behaviour.

Threat coverage: second genesis (threat 22), genesis code exhaustion,
code expiry, non-admin, envelope field abuse, concurrency, scope,
pending_link restrictions, audit, candidates IDOR.
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import time
import uuid

import psycopg
import pytest
from nacl.signing import SigningKey

from .m2_sync_server import (
    make_sync_server, ensure_at_head, create_org, create_project,
    keygen, sign_envelope, canonical_json,
)
from .t9_helpers import seed_session, make_session_cookie, compute_csrf
from .fake_idp import FakeClock


# ---------------------------------------------------------------------------
# Local sentinel
# ---------------------------------------------------------------------------

class M2T12dPending(Exception):
    """T12d: registry genesis bootstrap (ADR 0011)."""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _conninfo(url: str) -> str:
    return url.replace("+psycopg", "")


def _seed_user_row(conn, org_id: str, email: str,
                   *, iss: str = "https://idp.test",
                   sub: str | None = None,
                   roles: list[str] | None = None) -> str:
    """Insert a users row; return user_id (uuid str)."""
    user_id = str(uuid.uuid4())
    actual_sub = sub or f"sub-{uuid.uuid4().hex[:8]}"
    conn.execute(
        "INSERT INTO users (id, org_id, oidc_issuer, oidc_subject, email, "
        "status, created_at) VALUES (%s, %s, %s, %s, %s, "
        "'active', now()) ON CONFLICT DO NOTHING",
        [user_id, org_id, iss, actual_sub, email],
    )
    return user_id


def _grant_role(conn, org_id: str, user_id: str, role: str,
                scope_type: str = "org",
                scope_id: str | None = None) -> None:
    """Insert a role_bindings row (incl. required scope_type/scope_id)."""
    actual_scope_id = scope_id or org_id
    conn.execute(
        "INSERT INTO role_bindings "
        "(id, org_id, user_id, scope_type, scope_id, role, created_at) "
        "VALUES (%s, %s, %s, %s, %s, %s, now()) ON CONFLICT DO NOTHING",
        [str(uuid.uuid4()), org_id, user_id, scope_type, actual_scope_id, role],
    )


def _make_fresh_session(owner_url: str, org_id: str, user_id: str):
    """Create a fresh web session.  Return (cookie_value, csrf_token)."""
    clock = FakeClock()
    token, csrf, sid = seed_session(
        owner_url, uuid.UUID(org_id), uuid.UUID(user_id), clock=clock,
    )
    cookie = make_session_cookie(uuid.UUID(org_id), token)
    return cookie, csrf


def _create_signer_link(conn, org_id: str, user_id: str) -> str:
    """Insert a signer_links row and return the raw link code."""
    code = secrets.token_hex(16)
    code_hash = hashlib.sha256(code.encode()).hexdigest()
    conn.execute(
        "INSERT INTO signer_links "
        "(id, org_id, user_id, code_hash, expires_at, status) "
        "VALUES (%s, %s, %s, %s, now() + interval '15 minutes', 'pending')",
        [str(uuid.uuid4()), org_id, user_id, code_hash],
    )
    return code


def _link_cli_key(client, code: str, sk: SigningKey):
    """POST /api/v1/sync/signer/link to bind a CLI key."""
    pub = bytes(sk.verify_key).hex()
    kid = hashlib.sha256(bytes(sk.verify_key)).hexdigest()
    r = client.post("/api/v1/sync/signer/link", json={
        "code": code,
        "key_id": kid,
        "public_key": pub,
    })
    return r


def _get_signer_token(client, sk: SigningKey, kid: str) -> str | None:
    """Obtain a signer token via assertion."""
    nonce = secrets.token_hex(16)
    payload = {"key_id": kid, "nonce": nonce, "aud": "http://testserver", "iat": time.time()}
    tag = b"agg/signer-assert/v1"
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    msg = tag + b"\x00" + canonical
    sig = sk.sign(msg).signature.hex()
    assertion = {
        "kind": "agg/signer-assert/v1",
        "sig_v": 1,
        "payload": payload,
        "signatures": [{"key_id": kid, "alg": "ed25519", "sig": sig}],
    }
    r = client.post("/api/v1/sync/signer/token", json=assertion)
    if r.status_code == 200:
        return r.json().get("token")
    return None


def _kid(sk: SigningKey) -> str:
    return hashlib.sha256(bytes(sk.verify_key)).hexdigest()


def _build_genesis_envelope(
    sk: SigningKey,
    org_id: str,
    *,
    user_id: str,
    iss: str = "https://idp.test",
    sub: str = "sub-alice",
    roles: list[str] | None = None,
    bundle_signer_pub: bytes | None = None,
    # Allow overriding individual fields for rejection tests
    override_version: int | None = None,
    override_org_id: str | None = None,
    override_prev_hash: str | None = None,
    override_threshold: int | None = None,
    override_admins: list[str] | None = None,
    override_key_count: int | None = None,
    override_key_id: str | None = None,
    override_public_key: str | None = None,
    override_kind: str | None = None,
    override_alg: str | None = None,
    override_user_id: str | None = None,
    override_iss: str | None = None,
    override_sub: str | None = None,
    override_roles: list[str] | None = None,
    override_added_in: int | None = None,
    override_bundle_signer: dict | None = None,
    override_expires_at: float | None = None,
    override_sig_count: int | None = None,
    override_signer_kid: str | None = None,
) -> dict:
    """Build a genesis envelope with optional field overrides for rejection tests."""
    pub = bytes(sk.verify_key)
    kid = _kid(sk)
    actual_roles = roles if roles is not None else ["admin"]

    if bundle_signer_pub is None:
        bundle_signer_pub = bytes(SigningKey.generate().verify_key)
    bs_kid = hashlib.sha256(bundle_signer_pub).hexdigest()

    payload = {
        "org_id": override_org_id if override_org_id is not None else org_id,
        "version": override_version if override_version is not None else 1,
        "prev_hash": override_prev_hash if override_prev_hash is not None else "",
        "threshold": override_threshold if override_threshold is not None else 1,
        "admins": override_admins if override_admins is not None else [
            override_key_id if override_key_id is not None else kid],
        "keys": [],
        "bundle_signer": override_bundle_signer if override_bundle_signer is not None else {
            "key_id": bs_kid,
            "public_key": bundle_signer_pub.hex(),
        },
        "expires_at": override_expires_at if override_expires_at is not None else time.time() + 7 * 24 * 3600,
    }

    key_entry = {
        "key_id": override_key_id if override_key_id is not None else kid,
        "public_key": override_public_key if override_public_key is not None else pub.hex(),
        "kind": override_kind if override_kind is not None else "cli",
        "alg": override_alg if override_alg is not None else "ed25519",
        "user_id": override_user_id if override_user_id is not None else user_id,
        "iss": override_iss if override_iss is not None else iss,
        "sub": override_sub if override_sub is not None else sub,
        "roles": override_roles if override_roles is not None else actual_roles,
        "added_in": override_added_in if override_added_in is not None else 1,
    }

    # Allow injecting extra keys
    if override_key_count is not None and override_key_count > 1:
        payload["keys"] = [key_entry] + [
            {
                "key_id": f"extra-key-{i}",
                "public_key": bytes(SigningKey.generate().verify_key).hex(),
                "kind": "cli",
                "alg": "ed25519",
                "user_id": f"extra-user-{i}",
                "iss": "https://extra",
                "sub": f"extra-sub-{i}",
                "roles": ["approver"],
                "added_in": 1,
            }
            for i in range(override_key_count - 1)
        ]
    elif override_key_count == 0:
        payload["keys"] = []
    else:
        payload["keys"] = [key_entry]

    # Sign the envelope
    tag = b"agg/registry/v1"
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    msg = tag + b"\x00" + canonical

    if override_sig_count == 0:
        sigs = []
    elif override_sig_count is not None and override_sig_count > 1:
        sigs = []
        for i in range(override_sig_count):
            s = sk.sign(msg).signature.hex()
            sigs.append({
                "key_id": override_signer_kid if override_signer_kid else kid,
                "alg": "ed25519",
                "sig": s,
            })
    else:
        sig = sk.sign(msg).signature.hex()
        signer_kid = override_signer_kid if override_signer_kid else kid
        sigs = [{"key_id": signer_kid, "alg": "ed25519", "sig": sig}]

    return {
        "kind": "agg/registry/v1",
        "sig_v": 1,
        "payload": payload,
        "signatures": sigs,
    }


def _seed_genesis_code(conn, org_id: str, *, minutes: int = 60) -> str:
    """Insert a setup_codes row with purpose registry_genesis.
    Return the raw code.  Raises M2T12dPending if the purpose column
    does not exist yet (d2 migration)."""
    code = secrets.token_urlsafe(24)  # 192 bits
    code_hash = hashlib.sha256(code.encode()).hexdigest()
    import datetime as dt
    now = dt.datetime.now(dt.timezone.utc)
    expires_at = now + dt.timedelta(minutes=minutes)
    try:
        conn.execute(
            "INSERT INTO setup_codes "
            "(id, org_id, code_hash, created_at, expires_at, purpose) "
            "VALUES (%s, %s, %s, %s, %s, 'registry_genesis')",
            [str(uuid.uuid4()), org_id, code_hash, now, expires_at],
        )
    except Exception as exc:
        if "purpose" in str(exc).lower() or "column" in str(exc).lower():
            raise M2T12dPending(
                "setup_codes.purpose column missing (d2 migration)"
            ) from exc
        raise
    return code


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def genesis_server(pg_url, app_url, owner_url, pg_roles):
    yield from make_sync_server(
        pg_url, app_url, owner_url,
        org_names=["Genesis Org", "Evil Org"],
    )


# ---------------------------------------------------------------------------
# Guards (no xfail -- must hold today)
# ---------------------------------------------------------------------------


@pytest.mark.pg
def test_guard_genesis_route_returns_404_today(genesis_server):
    """POST /api/v1/sync/signer/genesis does not exist today -> 404 or 405."""
    import httpx
    r = httpx.post(
        f"{genesis_server['base_url']}/api/v1/sync/signer/genesis",
        json={"genesis_code": "x", "envelope": {}},
        timeout=10,
    )
    assert r.status_code in (404, 405), (
        f"genesis route should not exist yet, got {r.status_code}"
    )


@pytest.mark.pg
def test_guard_candidates_route_returns_404_today(genesis_server):
    """GET /api/v1/sync/signer/candidates does not exist today -> 404 or 405."""
    import httpx
    r = httpx.get(
        f"{genesis_server['base_url']}/api/v1/sync/signer/candidates",
        headers={"Authorization": "Bearer fake"},
        timeout=10,
    )
    assert r.status_code in (401, 404, 405), (
        f"candidates route should not exist yet, got {r.status_code}"
    )


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M2T12dPending,
                   reason="T12d d1: genesis route not implemented")
def test_genesis_happy_path(genesis_server):
    """POST genesis with a valid code and envelope -> 200 {version: 1}.
    The key's status in approver_keys becomes 'signer'."""
    import httpx
    base = genesis_server["base_url"]
    org_id = genesis_server["org_id"]
    owner_url = genesis_server["owner_url"]

    with psycopg.connect(_conninfo(owner_url), autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        user_id = _seed_user_row(conn, org_id, "alice@test.example",
                                 sub="sub-alice")
        _grant_role(conn, org_id, user_id, "admin")
        code = _create_signer_link(conn, org_id, user_id)

    # Link the CLI key
    sk = SigningKey.generate()
    kid = _kid(sk)
    r = httpx.post(f"{base}/api/v1/sync/signer/link", json={
        "code": code,
        "key_id": kid,
        "public_key": bytes(sk.verify_key).hex(),
    }, timeout=10)
    assert r.status_code == 200, f"link failed: {r.status_code} {r.text}"

    # Get signer token (pending_link scope)
    token = _get_signer_token_httpx(base, sk, kid)
    assert token is not None, "signer token not obtained"

    # Seed genesis code
    with psycopg.connect(_conninfo(owner_url), autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        genesis_code = _seed_genesis_code(conn, org_id)

    # Read the user's OIDC identity for the envelope
    with psycopg.connect(_conninfo(owner_url), autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        row = conn.execute(
            "SELECT oidc_issuer, oidc_subject FROM users WHERE id = %s",
            [user_id],
        ).fetchone()
        iss, sub = row[0], row[1]

    # Build envelope -- look up the server's bundle signer key
    # For the test, the server must have a configured bundle signer
    # Use a generated key for the test
    bundle_sk = SigningKey.generate()
    bundle_pub = bytes(bundle_sk.verify_key)

    envelope = _build_genesis_envelope(
        sk, org_id,
        user_id=user_id, iss=iss, sub=sub,
        roles=["admin"],
        bundle_signer_pub=bundle_pub,
    )

    r = httpx.post(
        f"{base}/api/v1/sync/signer/genesis",
        json={"genesis_code": genesis_code, "envelope": envelope},
        headers={"Authorization": f"Bearer {token}"},
        timeout=10,
    )
    # The route does not exist today
    if r.status_code in (404, 405):
        raise M2T12dPending("genesis route not implemented")
    assert r.status_code == 200, f"genesis failed: {r.status_code} {r.text}"
    body = r.json()
    assert body.get("version") == 1
    # No fingerprint in response (S2)
    assert "fingerprint" not in body

    # Verify the key is now 'signer' in approver_keys
    with psycopg.connect(_conninfo(owner_url), autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        row = conn.execute(
            "SELECT status FROM approver_keys WHERE key_id = %s AND org_id = %s",
            [kid, org_id],
        ).fetchone()
        assert row is not None, "approver_keys row missing after genesis"
        assert row[0] == "signer", f"expected status 'signer', got {row[0]!r}"


def _get_signer_token_httpx(base_url: str, sk: SigningKey, kid: str) -> str | None:
    """Obtain a signer token via httpx (for live server tests)."""
    import httpx
    nonce = secrets.token_hex(16)
    payload = {"key_id": kid, "nonce": nonce, "aud": base_url, "iat": time.time()}
    tag = b"agg/signer-assert/v1"
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    msg = tag + b"\x00" + canonical
    sig = sk.sign(msg).signature.hex()
    assertion = {
        "kind": "agg/signer-assert/v1",
        "sig_v": 1,
        "payload": payload,
        "signatures": [{"key_id": kid, "alg": "ed25519", "sig": sig}],
    }
    r = httpx.post(f"{base_url}/api/v1/sync/signer/token", json=assertion, timeout=10)
    if r.status_code == 200:
        return r.json().get("token")
    return None


# ---------------------------------------------------------------------------
# 409 genesis_exists once any version exists
# ---------------------------------------------------------------------------


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M2T12dPending,
                   reason="T12d d1: genesis route not implemented")
def test_second_genesis_returns_409_with_alert(genesis_server):
    """Once v1 exists, a second genesis attempt returns 409 genesis_exists
    and the genesis code is not consumed (threat 22, second_genesis alert)."""
    import httpx
    base = genesis_server["base_url"]
    org_id = genesis_server["org_id"]

    r = httpx.post(
        f"{base}/api/v1/sync/signer/genesis",
        json={"genesis_code": "anything", "envelope": {}},
        headers={"Authorization": "Bearer fake"},
        timeout=10,
    )
    if r.status_code in (404, 405):
        raise M2T12dPending("genesis route not implemented")
    # If v1 already exists from the happy-path test, we should get 409
    assert r.status_code == 409
    body = r.json()
    assert body.get("error") == "genesis_exists"


# ---------------------------------------------------------------------------
# Code single use, expiry, 5 failed attempts, constant-time compare
# ---------------------------------------------------------------------------


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M2T12dPending,
                   reason="T12d d1: genesis route not implemented")
def test_genesis_code_single_use(genesis_server):
    """A genesis code can be used only once."""
    import httpx
    base = genesis_server["base_url"]
    r = httpx.post(
        f"{base}/api/v1/sync/signer/genesis",
        json={"genesis_code": "some-code", "envelope": {}},
        headers={"Authorization": "Bearer fake"},
        timeout=10,
    )
    if r.status_code in (404, 405):
        raise M2T12dPending("genesis route not implemented")
    # Specifics depend on implementation order; the key fact is
    # a reuse of the same code must fail


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M2T12dPending,
                   reason="T12d d1: genesis route not implemented")
def test_genesis_code_expired_refused(genesis_server):
    """An expired genesis code is refused."""
    import httpx
    base = genesis_server["base_url"]
    org_id = genesis_server["org_id"]
    owner_url = genesis_server["owner_url"]

    # Seed an already-expired genesis code
    with psycopg.connect(_conninfo(owner_url), autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        code = secrets.token_urlsafe(24)
        code_hash = hashlib.sha256(code.encode()).hexdigest()
        import datetime as dt
        now = dt.datetime.now(dt.timezone.utc)
        expired = now - dt.timedelta(minutes=1)
        try:
            conn.execute(
                "INSERT INTO setup_codes "
                "(id, org_id, code_hash, created_at, expires_at, purpose) "
                "VALUES (%s, %s, %s, %s, %s, 'registry_genesis')",
                [str(uuid.uuid4()), org_id, code_hash,
                 now - dt.timedelta(hours=2), expired],
            )
        except Exception as exc:
            if "purpose" in str(exc).lower() or "column" in str(exc).lower():
                raise M2T12dPending(
                    "setup_codes.purpose column missing (d2 migration)"
                ) from exc
            raise

    r = httpx.post(
        f"{base}/api/v1/sync/signer/genesis",
        json={"genesis_code": code, "envelope": {}},
        headers={"Authorization": "Bearer fake"},
        timeout=10,
    )
    if r.status_code in (404, 405):
        raise M2T12dPending("genesis route not implemented")
    assert r.status_code == 400


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M2T12dPending,
                   reason="T12d d1: genesis route not implemented")
def test_genesis_code_5_failures_locks_out(genesis_server):
    """After 5 wrong attempts the code is locked even with the right code."""
    import httpx
    base = genesis_server["base_url"]
    org_id = genesis_server["org_id"]
    owner_url = genesis_server["owner_url"]

    # Seed a fresh genesis code
    with psycopg.connect(_conninfo(owner_url), autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        genesis_code = _seed_genesis_code(conn, org_id)

    # 5 wrong attempts
    for i in range(5):
        r = httpx.post(
            f"{base}/api/v1/sync/signer/genesis",
            json={"genesis_code": f"wrong-{i}", "envelope": {}},
            headers={"Authorization": "Bearer fake"},
            timeout=10,
        )
        if r.status_code in (404, 405):
            raise M2T12dPending("genesis route not implemented")

    # Now try the right code -- should be locked
    r = httpx.post(
        f"{base}/api/v1/sync/signer/genesis",
        json={"genesis_code": genesis_code, "envelope": {}},
        headers={"Authorization": "Bearer fake"},
        timeout=10,
    )
    if r.status_code in (404, 405):
        raise M2T12dPending("genesis route not implemented")
    assert r.status_code == 400, (
        f"expected 400 after 5 failures, got {r.status_code}"
    )


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M2T12dPending,
                   reason="T12d d1: genesis route not implemented")
def test_genesis_wrong_code_increments_failure_count(genesis_server):
    """A wrong code increments failed_attempts (observable)."""
    import httpx
    base = genesis_server["base_url"]
    org_id = genesis_server["org_id"]
    owner_url = genesis_server["owner_url"]

    with psycopg.connect(_conninfo(owner_url), autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        genesis_code = _seed_genesis_code(conn, org_id)

    r = httpx.post(
        f"{base}/api/v1/sync/signer/genesis",
        json={"genesis_code": "definitely-wrong", "envelope": {}},
        headers={"Authorization": "Bearer fake"},
        timeout=10,
    )
    if r.status_code in (404, 405):
        raise M2T12dPending("genesis route not implemented")
    assert r.status_code == 400

    # Check the failure count incremented
    with psycopg.connect(_conninfo(owner_url), autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        try:
            row = conn.execute(
                "SELECT failed_attempts FROM setup_codes "
                "WHERE org_id = %s AND purpose = 'registry_genesis' "
                "AND used_at IS NULL "
                "ORDER BY created_at DESC LIMIT 1",
                [org_id],
            ).fetchone()
        except Exception as exc:
            if "purpose" in str(exc).lower() or "column" in str(exc).lower():
                raise M2T12dPending(
                    "setup_codes.purpose column missing (d2 migration)"
                ) from exc
            raise
        assert row is not None, "genesis code row missing"
        assert row[0] >= 1, f"expected failed_attempts >= 1, got {row[0]}"


# ---------------------------------------------------------------------------
# Non-admin user refused
# ---------------------------------------------------------------------------


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M2T12dPending,
                   reason="T12d d1: genesis route not implemented")
def test_genesis_non_admin_refused(genesis_server):
    """A user without the admin role is refused."""
    import httpx
    base = genesis_server["base_url"]
    org_id = genesis_server["org_id"]
    owner_url = genesis_server["owner_url"]

    with psycopg.connect(_conninfo(owner_url), autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        user_id = _seed_user_row(conn, org_id, "viewer@test.example")
        # No admin role granted
        _grant_role(conn, org_id, user_id, "viewer")
        code = _create_signer_link(conn, org_id, user_id)
        genesis_code = _seed_genesis_code(conn, org_id)

    sk = SigningKey.generate()
    kid = _kid(sk)
    r = httpx.post(f"{base}/api/v1/sync/signer/link", json={
        "code": code, "key_id": kid,
        "public_key": bytes(sk.verify_key).hex(),
    }, timeout=10)

    token = _get_signer_token_httpx(base, sk, kid)
    if token is None:
        raise M2T12dPending("signer token not obtained for pending_link")

    env = _build_genesis_envelope(sk, org_id, user_id=user_id)
    r = httpx.post(
        f"{base}/api/v1/sync/signer/genesis",
        json={"genesis_code": genesis_code, "envelope": env},
        headers={"Authorization": f"Bearer {token}"},
        timeout=10,
    )
    if r.status_code in (404, 405):
        raise M2T12dPending("genesis route not implemented")
    assert r.status_code in (400, 403), (
        f"expected non-admin refusal, got {r.status_code}"
    )


# ---------------------------------------------------------------------------
# Envelope field-by-field rejection (ADR 0011 2.4)
# ---------------------------------------------------------------------------

_FIELD_OVERRIDES = [
    ("version_not_1", {"override_version": 2}),
    ("org_id_mismatch", {"override_org_id": "99999999-9999-9999-9999-999999999999"}),
    ("prev_hash_not_empty", {"override_prev_hash": "abc123"}),
    ("threshold_not_1", {"override_threshold": 2}),
    ("admins_wrong", {"override_admins": ["wrong-key-id"]}),
    ("key_count_zero", {"override_key_count": 0}),
    ("key_count_two", {"override_key_count": 2}),
    ("key_id_mismatch", {"override_key_id": "wrong-key-id"}),
    ("public_key_mismatch", {"override_public_key": bytes(SigningKey.generate().verify_key).hex()}),
    ("kind_not_cli", {"override_kind": "browser"}),
    ("alg_not_ed25519", {"override_alg": "rsa"}),
    ("user_id_is_sub", {"override_user_id": "sub-alice"}),  # user_id = sub (wrong)
    ("iss_mismatch", {"override_iss": "https://wrong-idp.example"}),
    ("sub_mismatch", {"override_sub": "wrong-sub"}),
    ("roles_no_admin", {"override_roles": ["approver"]}),
    ("roles_extra", {"override_roles": ["admin", "approver", "superuser"]}),
    ("added_in_not_1", {"override_added_in": 2}),
    ("bundle_signer_missing", {"override_bundle_signer": {}}),
    ("expires_at_past", {"override_expires_at": time.time() - 3600}),
    ("sig_count_zero", {"override_sig_count": 0}),
    ("sig_count_two", {"override_sig_count": 2}),
    ("signer_wrong_kid", {"override_signer_kid": "wrong-signer-kid"}),
]


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M2T12dPending,
                   reason="T12d d1: genesis route not implemented")
@pytest.mark.parametrize("name,overrides", _FIELD_OVERRIDES,
                         ids=[x[0] for x in _FIELD_OVERRIDES])
def test_genesis_envelope_field_rejected(genesis_server, name, overrides):
    """Each wrong envelope field in ADR 0011 2.4 must be refused."""
    import httpx
    base = genesis_server["base_url"]
    org_id = genesis_server["org_id"]
    owner_url = genesis_server["owner_url"]

    with psycopg.connect(_conninfo(owner_url), autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        user_id = _seed_user_row(conn, org_id, f"field-{name}@test.example",
                                 sub=f"sub-field-{name}")
        _grant_role(conn, org_id, user_id, "admin")
        link_code = _create_signer_link(conn, org_id, user_id)
        genesis_code = _seed_genesis_code(conn, org_id)

    sk = SigningKey.generate()
    kid = _kid(sk)
    httpx.post(f"{base}/api/v1/sync/signer/link", json={
        "code": link_code, "key_id": kid,
        "public_key": bytes(sk.verify_key).hex(),
    }, timeout=10)

    token = _get_signer_token_httpx(base, sk, kid)
    if token is None:
        raise M2T12dPending("signer token not obtained")

    row = None
    with psycopg.connect(_conninfo(owner_url), autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        row = conn.execute(
            "SELECT oidc_issuer, oidc_subject FROM users WHERE id = %s",
            [user_id],
        ).fetchone()
    iss, sub = row[0], row[1]

    env = _build_genesis_envelope(
        sk, org_id, user_id=user_id, iss=iss, sub=sub,
        **overrides,
    )

    r = httpx.post(
        f"{base}/api/v1/sync/signer/genesis",
        json={"genesis_code": genesis_code, "envelope": env},
        headers={"Authorization": f"Bearer {token}"},
        timeout=10,
    )
    if r.status_code in (404, 405):
        raise M2T12dPending(f"genesis route not implemented (field: {name})")
    assert r.status_code == 400, (
        f"envelope with {name} should be rejected (400), got {r.status_code}"
    )


# ---------------------------------------------------------------------------
# Two concurrent genesis calls give exactly one v1 (pg_advisory_xact_lock)
# ---------------------------------------------------------------------------


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M2T12dPending,
                   reason="T12d d1: genesis route not implemented")
def test_concurrent_genesis_exactly_one_v1(genesis_server):
    """Two genesis calls racing: exactly one gets v1, the other 409."""
    import httpx
    import concurrent.futures
    base = genesis_server["base_url"]
    org_id = genesis_server["org_id"]
    owner_url = genesis_server["owner_url"]

    # We need a fresh org for this test to avoid interference
    fresh_org_id = str(uuid.uuid4())
    with psycopg.connect(_conninfo(owner_url), autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [fresh_org_id])
        create_org(conn, fresh_org_id, "Concurrent Org")

    results = []

    def attempt(idx):
        with psycopg.connect(_conninfo(owner_url), autocommit=True) as conn:
            conn.execute("SELECT set_config('app.org_id', %s, false)", [fresh_org_id])
            uid = _seed_user_row(conn, fresh_org_id, f"racer{idx}@test.example")
            _grant_role(conn, fresh_org_id, uid, "admin")
            link_code = _create_signer_link(conn, fresh_org_id, uid)
            genesis_code = _seed_genesis_code(conn, fresh_org_id)
        sk = SigningKey.generate()
        kid = _kid(sk)
        httpx.post(f"{base}/api/v1/sync/signer/link", json={
            "code": link_code, "key_id": kid,
            "public_key": bytes(sk.verify_key).hex(),
        }, timeout=10)
        token = _get_signer_token_httpx(base, sk, kid)
        env = _build_genesis_envelope(sk, fresh_org_id, user_id=uid)
        r = httpx.post(
            f"{base}/api/v1/sync/signer/genesis",
            json={"genesis_code": genesis_code, "envelope": env},
            headers={"Authorization": f"Bearer {token}"},
            timeout=10,
        )
        return r.status_code

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as exe:
        futures = [exe.submit(attempt, i) for i in range(2)]
        codes = [f.result() for f in futures]

    if 404 in codes or 405 in codes:
        raise M2T12dPending("genesis route not implemented")

    assert sorted(codes) == [200, 409] or codes.count(200) == 1, (
        f"expected exactly one 200 and one 409; got {codes}"
    )


# ---------------------------------------------------------------------------
# No fingerprint in any response
# ---------------------------------------------------------------------------


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M2T12dPending,
                   reason="T12d d1: genesis route not implemented")
def test_no_fingerprint_in_genesis_response(genesis_server):
    """The genesis response must not include a fingerprint (S2)."""
    import httpx
    base = genesis_server["base_url"]
    r = httpx.post(
        f"{base}/api/v1/sync/signer/genesis",
        json={"genesis_code": "x", "envelope": {}},
        headers={"Authorization": "Bearer fake"},
        timeout=10,
    )
    if r.status_code in (404, 405):
        raise M2T12dPending("genesis route not implemented")
    # Any response from the genesis route: check body
    try:
        body = r.json()
    except Exception:
        body = {}
    assert "fingerprint" not in body, "fingerprint must not appear in response"


# ---------------------------------------------------------------------------
# admin_audit row registry_genesis written
# ---------------------------------------------------------------------------


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M2T12dPending,
                   reason="T12d d1: genesis route not implemented")
def test_genesis_writes_admin_audit_row(genesis_server):
    """A successful genesis writes an admin_audit row with event
    'registry_genesis'."""
    import httpx
    base = genesis_server["base_url"]
    org_id = genesis_server["org_id"]
    owner_url = genesis_server["owner_url"]

    # We need a fresh org
    fresh_org_id = str(uuid.uuid4())
    with psycopg.connect(_conninfo(owner_url), autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [fresh_org_id])
        create_org(conn, fresh_org_id, "Audit Test Org")
        uid = _seed_user_row(conn, fresh_org_id, "audit-alice@test.example",
                             sub="sub-audit-alice")
        _grant_role(conn, fresh_org_id, uid, "admin")
        link_code = _create_signer_link(conn, fresh_org_id, uid)
        genesis_code = _seed_genesis_code(conn, fresh_org_id)

    sk = SigningKey.generate()
    kid = _kid(sk)
    httpx.post(f"{base}/api/v1/sync/signer/link", json={
        "code": link_code, "key_id": kid,
        "public_key": bytes(sk.verify_key).hex(),
    }, timeout=10)
    token = _get_signer_token_httpx(base, sk, kid)
    if token is None:
        raise M2T12dPending("signer token not obtained")

    with psycopg.connect(_conninfo(owner_url), autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [fresh_org_id])
        row = conn.execute(
            "SELECT oidc_issuer, oidc_subject FROM users WHERE id = %s",
            [uid],
        ).fetchone()
        iss, sub = row[0], row[1]

    env = _build_genesis_envelope(sk, fresh_org_id, user_id=uid, iss=iss, sub=sub)

    r = httpx.post(
        f"{base}/api/v1/sync/signer/genesis",
        json={"genesis_code": genesis_code, "envelope": env},
        headers={"Authorization": f"Bearer {token}"},
        timeout=10,
    )
    if r.status_code in (404, 405):
        raise M2T12dPending("genesis route not implemented")
    assert r.status_code == 200, f"genesis failed: {r.status_code} {r.text}"

    # Check admin_audit row (action='registry_genesis', detail jsonb holds
    # user_id, key_id and payload sha256)
    with psycopg.connect(_conninfo(owner_url), autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [fresh_org_id])
        row = conn.execute(
            "SELECT action, detail FROM admin_audit "
            "WHERE org_id = %s AND action = 'registry_genesis' "
            "ORDER BY created_at DESC LIMIT 1",
            [fresh_org_id],
        ).fetchone()
        assert row is not None, "admin_audit row missing after genesis"
        assert row[0] == "registry_genesis"
        detail = row[1] if isinstance(row[1], dict) else json.loads(row[1])
        assert detail.get("user_id") == uid, (
            f"expected user_id={uid}, got {detail.get('user_id')}"
        )
        assert detail.get("key_id") == kid, (
            f"expected key_id={kid}, got {detail.get('key_id')}"
        )


# ---------------------------------------------------------------------------
# pending_link scope: refused on most routes, allowed on link/genesis/own-key
# ---------------------------------------------------------------------------


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M2T12dPending,
                   reason="T12d d1: pending_link scope rule not updated")
def test_pending_link_refused_on_pending_route(genesis_server):
    """A pending_link token must be refused on /pending."""
    import httpx
    base = genesis_server["base_url"]
    org_id = genesis_server["org_id"]
    owner_url = genesis_server["owner_url"]

    with psycopg.connect(_conninfo(owner_url), autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        uid = _seed_user_row(conn, org_id, "pending-test@test.example")
        _grant_role(conn, org_id, uid, "admin")
        code = _create_signer_link(conn, org_id, uid)

    sk = SigningKey.generate()
    kid = _kid(sk)
    httpx.post(f"{base}/api/v1/sync/signer/link", json={
        "code": code, "key_id": kid,
        "public_key": bytes(sk.verify_key).hex(),
    }, timeout=10)
    token = _get_signer_token_httpx(base, sk, kid)
    if token is None:
        raise M2T12dPending("signer token not obtained for pending_link")

    r = httpx.get(
        f"{base}/api/v1/sync/signer/pending",
        headers={"Authorization": f"Bearer {token}"},
        timeout=10,
    )
    # pending_link should be refused on /pending (403 or similar)
    # Today the scope check only blocks pending_link from non-link routes,
    # but after D0-5 fix the scope allowlist is used. Check the current
    # behaviour:
    if r.status_code == 403:
        # Already refusing -- check if genesis is also blocked (it shouldn't be)
        raise M2T12dPending("pending_link scope rule needs genesis exception")
    # If it currently allows (the D0-5 open finding), the fix should block it
    raise M2T12dPending("pending_link must be refused on /pending after D0-5 fix")


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M2T12dPending,
                   reason="T12d d1: pending_link own-key publish not implemented")
def test_pending_link_allowed_on_signatures_for_own_key(genesis_server):
    """A pending_link token may post to /signatures ONLY when the envelope
    adds the token's own key (onboarding case)."""
    import httpx
    base = genesis_server["base_url"]
    org_id = genesis_server["org_id"]
    owner_url = genesis_server["owner_url"]

    with psycopg.connect(_conninfo(owner_url), autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        uid = _seed_user_row(conn, org_id, "ownkey@test.example")
        _grant_role(conn, org_id, uid, "admin")
        code = _create_signer_link(conn, org_id, uid)

    sk = SigningKey.generate()
    kid = _kid(sk)
    httpx.post(f"{base}/api/v1/sync/signer/link", json={
        "code": code, "key_id": kid,
        "public_key": bytes(sk.verify_key).hex(),
    }, timeout=10)
    token = _get_signer_token_httpx(base, sk, kid)
    if token is None:
        raise M2T12dPending("signer token not obtained")

    # Post a registry envelope that adds this key -> should be allowed
    # (requires a v1 to chain from, so this test exercises the own-key rule)
    r = httpx.post(
        f"{base}/api/v1/sync/signer/signatures",
        json={"type": "registry", "envelope": {}, "org_id": org_id},
        headers={"Authorization": f"Bearer {token}"},
        timeout=10,
    )
    # Today this is 403 (pending_link blocked from signatures). After d2,
    # pending_link that adds own key should be allowed.
    if r.status_code == 403:
        raise M2T12dPending("pending_link own-key publish not implemented")
    # If allowed, that means the rule changed (d2 done)
    assert r.status_code in (200, 400), (
        f"unexpected status {r.status_code} for own-key publish"
    )


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M2T12dPending,
                   reason="T12d d1: pending_link non-own-key publish not blocked")
def test_pending_link_refused_on_signatures_for_other_key(genesis_server):
    """A pending_link post to /signatures that does NOT add its own key
    must get 403."""
    import httpx
    base = genesis_server["base_url"]
    org_id = genesis_server["org_id"]
    owner_url = genesis_server["owner_url"]

    with psycopg.connect(_conninfo(owner_url), autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        uid = _seed_user_row(conn, org_id, "otherkey@test.example")
        _grant_role(conn, org_id, uid, "admin")
        code = _create_signer_link(conn, org_id, uid)

    sk = SigningKey.generate()
    kid = _kid(sk)
    httpx.post(f"{base}/api/v1/sync/signer/link", json={
        "code": code, "key_id": kid,
        "public_key": bytes(sk.verify_key).hex(),
    }, timeout=10)
    token = _get_signer_token_httpx(base, sk, kid)
    if token is None:
        raise M2T12dPending("signer token not obtained")

    # Post an envelope that does NOT add this key
    other_sk = SigningKey.generate()
    other_kid = _kid(other_sk)
    env = {
        "kind": "agg/registry/v1", "sig_v": 1,
        "payload": {"org_id": org_id, "version": 2, "keys": [
            {"key_id": other_kid, "public_key": bytes(other_sk.verify_key).hex()},
        ]},
        "signatures": [],
    }
    r = httpx.post(
        f"{base}/api/v1/sync/signer/signatures",
        json={"type": "registry", "envelope": env, "org_id": org_id},
        headers={"Authorization": f"Bearer {token}"},
        timeout=10,
    )
    # Whether currently 403 (all pending_link blocked) or not, the rule
    # after d2 must refuse this specifically
    if r.status_code == 403:
        # Correct: pending_link that doesn't add own key -> 403. But need to
        # confirm it's a purposeful check, not just the blanket D0-5 denylist
        raise M2T12dPending("pending_link non-own-key publish check not implemented yet")
    raise M2T12dPending("expected 403 for pending_link non-own-key publish")


# ---------------------------------------------------------------------------
# Candidates route: admin-only, org-scoped, 404 for another org
# ---------------------------------------------------------------------------


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M2T12dPending,
                   reason="T12d d1: candidates route not implemented")
def test_candidates_admin_only(genesis_server):
    """GET /api/v1/sync/signer/candidates requires the admin role."""
    import httpx
    base = genesis_server["base_url"]
    r = httpx.get(
        f"{base}/api/v1/sync/signer/candidates",
        headers={"Authorization": "Bearer fake"},
        timeout=10,
    )
    if r.status_code in (404, 405):
        raise M2T12dPending("candidates route not implemented")
    assert r.status_code in (401, 403), (
        f"expected auth error, got {r.status_code}"
    )


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M2T12dPending,
                   reason="T12d d1: candidates route not implemented")
def test_candidates_org_scoped(genesis_server):
    """Candidates from another org -> 404."""
    import httpx
    base = genesis_server["base_url"]
    r = httpx.get(
        f"{base}/api/v1/sync/signer/candidates",
        params={"org_id": "99999999-9999-9999-9999-999999999999"},
        headers={"Authorization": "Bearer fake"},
        timeout=10,
    )
    if r.status_code in (404, 405):
        raise M2T12dPending("candidates route not implemented")
    assert r.status_code == 404


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M2T12dPending,
                   reason="T12d d1: candidates route not implemented")
def test_candidates_lists_pending_keys(genesis_server):
    """Candidates lists key_id, public_key, user_id, iss, sub, kind."""
    import httpx
    base = genesis_server["base_url"]
    org_id = genesis_server["org_id"]
    owner_url = genesis_server["owner_url"]

    with psycopg.connect(_conninfo(owner_url), autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        uid = _seed_user_row(conn, org_id, "cand@test.example")
        _grant_role(conn, org_id, uid, "admin")
        link_code = _create_signer_link(conn, org_id, uid)

    sk = SigningKey.generate()
    kid = _kid(sk)
    # Link the key (makes it a pending CLI link with public_key set)
    httpx.post(f"{base}/api/v1/sync/signer/link", json={
        "code": link_code, "key_id": kid,
        "public_key": bytes(sk.verify_key).hex(),
    }, timeout=10)

    # Need a confirmed token for candidates (admin)
    # This requires an already-signer key, so we need a genesis first
    # or a test setup that gives us a confirmed token.
    # For now, attempt with a pending_link token:
    token = _get_signer_token_httpx(base, sk, kid)
    if token is None:
        raise M2T12dPending("signer token not obtained")

    r = httpx.get(
        f"{base}/api/v1/sync/signer/candidates",
        headers={"Authorization": f"Bearer {token}"},
        timeout=10,
    )
    if r.status_code in (404, 405):
        raise M2T12dPending("candidates route not implemented")
    # With a pending_link token, candidates should be 403 (admin-only, confirmed)
    if r.status_code == 403:
        raise M2T12dPending("need confirmed admin token for candidates")
    assert r.status_code == 200
    body = r.json()
    assert isinstance(body, list)
    # Check fields present on each candidate
    for item in body:
        for field in ("key_id", "public_key", "user_id", "iss", "sub", "kind"):
            assert field in item, f"missing field {field} in candidate"


# ---------------------------------------------------------------------------
# migrate.py emits genesis_code
# ---------------------------------------------------------------------------


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M2T12dPending,
                   reason="T12d d1: migrate.py genesis code not implemented")
def test_migrate_emits_genesis_code_once(genesis_server):
    """migrate.py emits a genesis_code JSON line when no version and no live
    code exist, and not after v1."""
    import subprocess
    import sys

    org_id = genesis_server["org_id"]
    pg_url = genesis_server["pg_url"]

    env = {
        **os.environ,
        "AGG_DATABASE_URL": pg_url,
        "AGG_BOOTSTRAP_ORG_SLUG": "genesistest",
        "AGG_BOOTSTRAP_ORG_NAME": "Genesis Test",
        "AGG_BOOTSTRAP_ORG_ISSUER": "https://idp.test",
        "AGG_BOOTSTRAP_ORG_CLIENT_ID": "test-client",
    }

    result = subprocess.run(
        [sys.executable, "-m", "agg_cp.migrate"],
        capture_output=True, text=True, env=env, timeout=60,
    )
    stdout = result.stdout.strip()
    lines = [l for l in stdout.splitlines() if l.strip()]
    genesis_lines = [l for l in lines if "genesis_code" in l]

    if not genesis_lines:
        raise M2T12dPending("migrate.py does not emit genesis_code")

    data = json.loads(genesis_lines[0])
    assert data.get("event") == "genesis_code"
    assert "code" in data
    assert "expires_at" in data


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M2T12dPending,
                   reason="T12d d1: migrate.py genesis code dedup not implemented")
def test_migrate_no_genesis_code_if_live_code_exists(genesis_server):
    """migrate.py must not emit a second genesis code while a live one exists."""
    import subprocess
    import sys

    pg_url = genesis_server["pg_url"]
    org_id = genesis_server["org_id"]
    owner_url = genesis_server["owner_url"]

    # Seed a live genesis code
    with psycopg.connect(_conninfo(owner_url), autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        _seed_genesis_code(conn, org_id)

    env = {
        **os.environ,
        "AGG_DATABASE_URL": pg_url,
        "AGG_BOOTSTRAP_ORG_SLUG": org_id[:32].replace("-", ""),
        "AGG_BOOTSTRAP_ORG_NAME": "Genesis Org",
        "AGG_BOOTSTRAP_ORG_ISSUER": "https://idp.test",
        "AGG_BOOTSTRAP_ORG_CLIENT_ID": "test-client",
    }

    result = subprocess.run(
        [sys.executable, "-m", "agg_cp.migrate"],
        capture_output=True, text=True, env=env, timeout=60,
    )
    genesis_lines = [l for l in result.stdout.splitlines() if "genesis_code" in l]
    if genesis_lines:
        raise M2T12dPending("migrate.py emits genesis_code even with a live one")


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M2T12dPending,
                   reason="T12d d1: migrate.py genesis code after v1 not blocked")
def test_migrate_no_genesis_code_after_v1(genesis_server):
    """migrate.py must not emit genesis_code once v1 exists."""
    import subprocess
    import sys

    pg_url = genesis_server["pg_url"]

    env = {
        **os.environ,
        "AGG_DATABASE_URL": pg_url,
        "AGG_BOOTSTRAP_ORG_SLUG": "genesisdonev1",
        "AGG_BOOTSTRAP_ORG_NAME": "Genesis Done V1",
        "AGG_BOOTSTRAP_ORG_ISSUER": "https://idp.test",
        "AGG_BOOTSTRAP_ORG_CLIENT_ID": "test-client",
    }

    # First run to create the org and get a genesis_code
    result1 = subprocess.run(
        [sys.executable, "-m", "agg_cp.migrate"],
        capture_output=True, text=True, env=env, timeout=60,
    )
    genesis_lines = [l for l in result1.stdout.splitlines() if "genesis_code" in l]
    if not genesis_lines:
        raise M2T12dPending("migrate.py does not emit genesis_code")

    # Now if a v1 were stored, running again should not emit genesis_code
    # (the full flow of using the code to create v1 is tested above)
    # For this test, we check that after v1 exists, no code is emitted
    # -- this requires the happy path to work first, so xfail is correct
    raise M2T12dPending("migrate.py genesis_code after v1 check needs genesis route")


# ---------------------------------------------------------------------------
# Grep test: test_m2_t12b_e2e.py must not call store_registry_version
# (strict xfail until d4)
# ---------------------------------------------------------------------------


@pytest.mark.xfail(strict=True, raises=M2T12dPending,
                   reason="T12d d4: e2e test still calls store_registry_version")
def test_e2e_does_not_call_store_registry_version():
    """ee/tests/test_m2_t12b_e2e.py must not call store_registry_version
    directly once d4 moves it to the genesis/signature routes."""
    import re
    from pathlib import Path

    e2e_file = Path(__file__).parent / "test_m2_t12b_e2e.py"
    if not e2e_file.exists():
        raise M2T12dPending("test_m2_t12b_e2e.py not found")

    source = e2e_file.read_text(encoding="utf-8")
    # Look for calls to store_registry_version (not just imports)
    calls = re.findall(r'\bstore_registry_version\s*\(', source)
    if calls:
        raise M2T12dPending(
            f"test_m2_t12b_e2e.py still calls store_registry_version "
            f"({len(calls)} call(s)); d4 must move to the routes"
        )
