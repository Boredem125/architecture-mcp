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
# Module-level bundle-signer public key (set by the fixture, read by helpers)
# ---------------------------------------------------------------------------

_SERVER_BUNDLE_SIGNER_PUB: bytes | None = None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _conninfo(url: str) -> str:
    return url.replace("+psycopg", "")


def _seed_user_row(conn, org_id: str, email: str,
                   *, iss: str = "https://idp.test",
                   sub: str | None = None,
                   roles: list[str] | None = None) -> tuple[str, str, str]:
    """Insert a users row; return (user_id, iss, sub) as strings."""
    user_id = str(uuid.uuid4())
    actual_sub = sub or f"sub-{uuid.uuid4().hex[:8]}"
    conn.execute(
        "INSERT INTO users (id, org_id, oidc_issuer, oidc_subject, email, "
        "status, created_at) VALUES (%s, %s, %s, %s, %s, "
        "'active', now()) ON CONFLICT DO NOTHING",
        [user_id, org_id, iss, actual_sub, email],
    )
    return user_id, iss, actual_sub


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


def _kid(sk: SigningKey) -> str:
    return hashlib.sha256(bytes(sk.verify_key)).hexdigest()


def _link_and_token_httpx(base_url: str, owner_url: str, org_id: str,
                          user_id: str) -> tuple[SigningKey, str, str]:
    """Create link, link CLI key, get signer token.
    Returns (sk, kid, token).  Uses httpx against the live server."""
    import httpx
    with psycopg.connect(_conninfo(owner_url), autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        code = _create_signer_link(conn, org_id, user_id)
    sk = SigningKey.generate()
    kid = _kid(sk)
    r = httpx.post(f"{base_url}/api/v1/sync/signer/link", json={
        "code": code, "key_id": kid,
        "public_key": bytes(sk.verify_key).hex(),
    }, timeout=10)
    assert r.status_code == 200, f"link failed: {r.status_code} {r.text}"
    token = _get_signer_token_httpx(base_url, sk, kid)
    assert token is not None, "signer token not obtained"
    return sk, kid, token


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
        bundle_signer_pub = _SERVER_BUNDLE_SIGNER_PUB or bytes(SigningKey.generate().verify_key)
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


def _fresh_org(owner_url: str, name: str = "Fresh Org") -> str:
    """Create a brand-new org and return its id (uuid str)."""
    org_id = str(uuid.uuid4())
    with psycopg.connect(_conninfo(owner_url), autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        create_org(conn, org_id, name)
    return org_id


def _seed_admin_with_link_and_code(
    base_url: str,
    owner_url: str,
    org_id: str,
    email: str,
    *,
    iss: str = "https://idp.test",
    sub: str | None = None,
) -> tuple[str, str, str, SigningKey, str, str, str]:
    """Full bootstrap: user + admin role + signer link + linked CLI key +
    pending_link signer token + genesis code.

    Returns (user_id, iss, sub, sk, kid, token, genesis_code).
    """
    import httpx
    with psycopg.connect(_conninfo(owner_url), autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        user_id, act_iss, act_sub = _seed_user_row(
            conn, org_id, email, iss=iss, sub=sub,
        )
        _grant_role(conn, org_id, user_id, "admin")
        link_code = _create_signer_link(conn, org_id, user_id)
        genesis_code = _seed_genesis_code(conn, org_id)

    sk = SigningKey.generate()
    kid = _kid(sk)
    r = httpx.post(f"{base_url}/api/v1/sync/signer/link", json={
        "code": link_code, "key_id": kid,
        "public_key": bytes(sk.verify_key).hex(),
    }, timeout=10)
    assert r.status_code == 200, f"link failed: {r.status_code} {r.text}"

    token = _get_signer_token_httpx(base_url, sk, kid)
    assert token is not None, "signer token not obtained"

    return user_id, act_iss, act_sub, sk, kid, token, genesis_code


def _do_genesis(base_url: str, owner_url: str, org_id: str,
                email: str = "gen@test.example") -> tuple[str, SigningKey, str, str]:
    """Run a full genesis on a fresh org.
    Returns (user_id, sk, kid, token_after_genesis).
    The token returned is a *confirmed* signer token (after genesis
    the key is in approver_keys)."""
    import httpx
    uid, iss, sub, sk, kid, token, gcode = _seed_admin_with_link_and_code(
        base_url, owner_url, org_id, email,
    )
    env = _build_genesis_envelope(sk, org_id, user_id=uid, iss=iss, sub=sub)
    r = httpx.post(
        f"{base_url}/api/v1/sync/signer/genesis",
        json={"genesis_code": gcode, "envelope": env},
        headers={"Authorization": f"Bearer {token}"},
        timeout=10,
    )
    assert r.status_code == 200, f"genesis failed: {r.status_code} {r.text}"
    # After genesis the key is in approver_keys; get a confirmed token
    confirmed_token = _get_signer_token_httpx(base_url, sk, kid)
    assert confirmed_token is not None, "confirmed signer token not obtained"
    return uid, sk, kid, confirmed_token


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def bundle_signer_info(tmp_path_factory):
    """Provide a bundle-signer key file and set AGG_BUNDLE_SIGNER_KEY_FILE.

    Module-scoped: runs before genesis_server starts its subprocess,
    so the server inherits the env var.  The public key is also stored
    in the module-level _SERVER_BUNDLE_SIGNER_PUB so that
    _build_genesis_envelope uses it by default (R1 fix).
    """
    global _SERVER_BUNDLE_SIGNER_PUB
    key_dir = tmp_path_factory.mktemp("bundle_signer_genesis")
    key_file = key_dir / "bundle_signer.key"
    sk = SigningKey.generate()
    key_file.write_bytes(bytes(sk).hex().encode("ascii"))
    old_env = os.environ.get("AGG_BUNDLE_SIGNER_KEY_FILE")
    os.environ["AGG_BUNDLE_SIGNER_KEY_FILE"] = str(key_file)
    _SERVER_BUNDLE_SIGNER_PUB = bytes(sk.verify_key)
    yield {
        "key_file": str(key_file),
        "signing_key": sk,
        "public_key_bytes": bytes(sk.verify_key),
        "public_key_hex": bytes(sk.verify_key).hex(),
    }
    _SERVER_BUNDLE_SIGNER_PUB = None
    if old_env is None:
        os.environ.pop("AGG_BUNDLE_SIGNER_KEY_FILE", None)
    else:
        os.environ["AGG_BUNDLE_SIGNER_KEY_FILE"] = old_env


@pytest.fixture(scope="module")
def genesis_server(pg_url, app_url, owner_url, pg_roles, bundle_signer_info):
    yield from make_sync_server(
        pg_url, app_url, owner_url,
        org_names=["Genesis Org", "Evil Org"],
    )


# ---------------------------------------------------------------------------
# Guards (no xfail -- must hold today)
# ---------------------------------------------------------------------------


@pytest.mark.pg
def test_guard_genesis_unauthenticated_post_refused(genesis_server):
    """An unauthenticated POST to /genesis gets 401 (not 404)."""
    import httpx
    r = httpx.post(
        f"{genesis_server['base_url']}/api/v1/sync/signer/genesis",
        json={"genesis_code": "x", "envelope": {}},
        timeout=10,
    )
    assert r.status_code == 401, (
        f"unauthenticated genesis POST should be 401, got {r.status_code}"
    )


@pytest.mark.pg
def test_guard_candidates_unauthenticated_refused(genesis_server):
    """An unauthenticated GET to /candidates gets 401 (not 404)."""
    import httpx
    r = httpx.get(
        f"{genesis_server['base_url']}/api/v1/sync/signer/candidates",
        headers={"Authorization": "Bearer fake"},
        timeout=10,
    )
    assert r.status_code == 401, (
        f"candidates with fake token should be 401, got {r.status_code}"
    )


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


@pytest.mark.pg
def test_genesis_happy_path(genesis_server):
    """POST genesis with a valid code and envelope -> 200 {version: 1}.
    The key appears in approver_keys with the admin role and
    signer_links is consumed."""
    import httpx
    base = genesis_server["base_url"]
    owner_url = genesis_server["owner_url"]

    # Fresh org so no prior v1
    org_id = _fresh_org(owner_url, "Happy Org")

    uid, iss, sub, sk, kid, token, genesis_code = _seed_admin_with_link_and_code(
        base, owner_url, org_id, "alice@test.example",
    )

    envelope = _build_genesis_envelope(
        sk, org_id,
        user_id=uid, iss=iss, sub=sub,
        roles=["admin"],
    )

    r = httpx.post(
        f"{base}/api/v1/sync/signer/genesis",
        json={"genesis_code": genesis_code, "envelope": envelope},
        headers={"Authorization": f"Bearer {token}"},
        timeout=10,
    )
    if r.status_code in (404, 405):
        raise M2T12dPending("genesis route not implemented")
    assert r.status_code == 200, f"genesis failed: {r.status_code} {r.text}"
    body = r.json()
    assert body.get("version") == 1
    # No fingerprint in response (S2)
    assert "fingerprint" not in body

    # Verify: approver_keys row exists with admin role (projection)
    # Schema: id, org_id, user_id, public_key, alg, kind, key_id,
    #         registry_version, enrolled_at, revoked_at,
    #         enrollment_signatures, created_at, roles (jsonb, 0010)
    with psycopg.connect(_conninfo(owner_url), autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        row = conn.execute(
            "SELECT key_id, roles, revoked_at "
            "FROM approver_keys WHERE key_id = %s AND org_id = %s::uuid",
            [kid, org_id],
        ).fetchone()
        assert row is not None, "approver_keys row missing after genesis"
        roles_val = row[1] if isinstance(row[1], list) else json.loads(row[1])
        assert "admin" in roles_val, f"expected admin in roles, got {roles_val}"
        assert row[2] is None, "revoked_at should be NULL for active key"

    # Verify: signer_links row is consumed
    with psycopg.connect(_conninfo(owner_url), autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        link_row = conn.execute(
            "SELECT status FROM signer_links "
            "WHERE org_id = %s::uuid AND key_id = %s",
            [org_id, kid],
        ).fetchone()
        assert link_row is not None, "signer_links row missing"
        assert link_row[0] == "consumed", (
            f"expected link status 'consumed', got {link_row[0]!r}"
        )


# ---------------------------------------------------------------------------
# 409 genesis_exists once any version exists
# ---------------------------------------------------------------------------


@pytest.mark.pg
def test_second_genesis_returns_409_with_alert(genesis_server):
    """Once v1 exists, a second genesis attempt returns 409 genesis_exists
    and the genesis code is not consumed (threat 22, second_genesis alert)."""
    import httpx
    base = genesis_server["base_url"]
    owner_url = genesis_server["owner_url"]

    # Create a fresh org and run genesis to completion
    org_id = _fresh_org(owner_url, "SecondGenesis Org")
    _do_genesis(base, owner_url, org_id, "first@test.example")

    # Now attempt a second genesis with a real pending_link token
    uid2, iss2, sub2, sk2, kid2, token2, gcode2 = _seed_admin_with_link_and_code(
        base, owner_url, org_id, "second@test.example",
    )
    env2 = _build_genesis_envelope(sk2, org_id, user_id=uid2, iss=iss2, sub=sub2)

    r = httpx.post(
        f"{base}/api/v1/sync/signer/genesis",
        json={"genesis_code": gcode2, "envelope": env2},
        headers={"Authorization": f"Bearer {token2}"},
        timeout=10,
    )
    if r.status_code in (404, 405):
        raise M2T12dPending("genesis route not implemented")
    assert r.status_code == 409
    body = r.json()
    assert body.get("error") == "genesis_exists"


# ---------------------------------------------------------------------------
# Code single use, expiry, 5 failed attempts, constant-time compare
# ---------------------------------------------------------------------------


@pytest.mark.pg
def test_genesis_code_single_use(genesis_server):
    """A genesis code can be used only once."""
    import httpx
    base = genesis_server["base_url"]
    owner_url = genesis_server["owner_url"]

    org_id = _fresh_org(owner_url, "SingleUse Org")
    uid, iss, sub, sk, kid, token, genesis_code = _seed_admin_with_link_and_code(
        base, owner_url, org_id, "once@test.example",
    )
    env = _build_genesis_envelope(sk, org_id, user_id=uid, iss=iss, sub=sub)

    r = httpx.post(
        f"{base}/api/v1/sync/signer/genesis",
        json={"genesis_code": genesis_code, "envelope": env},
        headers={"Authorization": f"Bearer {token}"},
        timeout=10,
    )
    if r.status_code in (404, 405):
        raise M2T12dPending("genesis route not implemented")
    assert r.status_code == 200, f"first genesis failed: {r.status_code}"

    # Attempt reuse -- should fail (409 because v1 exists now)
    r2 = httpx.post(
        f"{base}/api/v1/sync/signer/genesis",
        json={"genesis_code": genesis_code, "envelope": env},
        headers={"Authorization": f"Bearer {token}"},
        timeout=10,
    )
    assert r2.status_code == 409, (
        f"second use of genesis code should be refused, got {r2.status_code}"
    )


@pytest.mark.pg
def test_genesis_code_expired_refused(genesis_server):
    """An expired genesis code is refused."""
    import httpx
    import datetime as dt
    base = genesis_server["base_url"]
    owner_url = genesis_server["owner_url"]

    org_id = _fresh_org(owner_url, "Expired Org")

    with psycopg.connect(_conninfo(owner_url), autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        uid, iss, sub_val = _seed_user_row(conn, org_id, "exp@test.example")
        _grant_role(conn, org_id, uid, "admin")
        link_code = _create_signer_link(conn, org_id, uid)

        # Seed an already-expired genesis code
        exp_code = secrets.token_urlsafe(24)
        exp_hash = hashlib.sha256(exp_code.encode()).hexdigest()
        now = dt.datetime.now(dt.timezone.utc)
        try:
            conn.execute(
                "INSERT INTO setup_codes "
                "(id, org_id, code_hash, created_at, expires_at, purpose) "
                "VALUES (%s, %s, %s, %s, %s, 'registry_genesis')",
                [str(uuid.uuid4()), org_id, exp_hash,
                 now - dt.timedelta(hours=2),
                 now - dt.timedelta(minutes=1)],
            )
        except Exception as exc:
            if "purpose" in str(exc).lower() or "column" in str(exc).lower():
                raise M2T12dPending("setup_codes.purpose column missing") from exc
            raise

    sk = SigningKey.generate()
    kid = _kid(sk)
    httpx.post(f"{base}/api/v1/sync/signer/link", json={
        "code": link_code, "key_id": kid,
        "public_key": bytes(sk.verify_key).hex(),
    }, timeout=10)
    token = _get_signer_token_httpx(base, sk, kid)
    assert token is not None

    env = _build_genesis_envelope(sk, org_id, user_id=uid, iss=iss, sub=sub_val)
    r = httpx.post(
        f"{base}/api/v1/sync/signer/genesis",
        json={"genesis_code": exp_code, "envelope": env},
        headers={"Authorization": f"Bearer {token}"},
        timeout=10,
    )
    if r.status_code in (404, 405):
        raise M2T12dPending("genesis route not implemented")
    assert r.status_code == 400


@pytest.mark.pg
def test_genesis_code_5_failures_locks_out(genesis_server):
    """After 5 wrong attempts the code is locked even with the right code."""
    import httpx
    base = genesis_server["base_url"]
    owner_url = genesis_server["owner_url"]

    org_id = _fresh_org(owner_url, "Lockout Org")
    uid, iss, sub_val, sk, kid, token, genesis_code = _seed_admin_with_link_and_code(
        base, owner_url, org_id, "lock@test.example",
    )

    # 5 wrong attempts (with a real token so the route doesn't bail at auth)
    for i in range(5):
        r = httpx.post(
            f"{base}/api/v1/sync/signer/genesis",
            json={"genesis_code": f"wrong-{i}", "envelope": {}},
            headers={"Authorization": f"Bearer {token}"},
            timeout=10,
        )
        if r.status_code in (404, 405):
            raise M2T12dPending("genesis route not implemented")

    # Now try the right code -- should be locked
    env = _build_genesis_envelope(sk, org_id, user_id=uid, iss=iss, sub=sub_val)
    r = httpx.post(
        f"{base}/api/v1/sync/signer/genesis",
        json={"genesis_code": genesis_code, "envelope": env},
        headers={"Authorization": f"Bearer {token}"},
        timeout=10,
    )
    assert r.status_code == 400, (
        f"expected 400 after 5 failures, got {r.status_code}"
    )


@pytest.mark.pg
def test_genesis_wrong_code_increments_failure_count(genesis_server):
    """A wrong code increments failed_attempts (observable)."""
    import httpx
    base = genesis_server["base_url"]
    owner_url = genesis_server["owner_url"]

    org_id = _fresh_org(owner_url, "FailCount Org")
    uid, iss, sub_val, sk, kid, token, genesis_code = _seed_admin_with_link_and_code(
        base, owner_url, org_id, "fail@test.example",
    )

    r = httpx.post(
        f"{base}/api/v1/sync/signer/genesis",
        json={"genesis_code": "definitely-wrong", "envelope": {}},
        headers={"Authorization": f"Bearer {token}"},
        timeout=10,
    )
    if r.status_code in (404, 405):
        raise M2T12dPending("genesis route not implemented")
    assert r.status_code == 400

    # Check the failure count incremented
    with psycopg.connect(_conninfo(owner_url), autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        row = conn.execute(
            "SELECT failed_attempts FROM setup_codes "
            "WHERE org_id = %s AND purpose = 'registry_genesis' "
            "AND used_at IS NULL "
            "ORDER BY created_at DESC LIMIT 1",
            [org_id],
        ).fetchone()
        assert row is not None, "genesis code row missing"
        assert row[0] >= 1, f"expected failed_attempts >= 1, got {row[0]}"


# ---------------------------------------------------------------------------
# Non-admin user refused
# ---------------------------------------------------------------------------


@pytest.mark.pg
def test_genesis_non_admin_refused(genesis_server):
    """A user without the admin role is refused."""
    import httpx
    base = genesis_server["base_url"]
    owner_url = genesis_server["owner_url"]

    # Fresh org so no v1
    org_id = _fresh_org(owner_url, "NonAdmin Org")

    with psycopg.connect(_conninfo(owner_url), autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        uid, iss, sub_val = _seed_user_row(conn, org_id, "viewer@test.example")
        # Viewer only -- no admin
        _grant_role(conn, org_id, uid, "viewer")
        link_code = _create_signer_link(conn, org_id, uid)
        genesis_code = _seed_genesis_code(conn, org_id)

    sk = SigningKey.generate()
    kid = _kid(sk)
    httpx.post(f"{base}/api/v1/sync/signer/link", json={
        "code": link_code, "key_id": kid,
        "public_key": bytes(sk.verify_key).hex(),
    }, timeout=10)
    token = _get_signer_token_httpx(base, sk, kid)
    if token is None:
        raise M2T12dPending("signer token not obtained for pending_link")

    env = _build_genesis_envelope(sk, org_id, user_id=uid, iss=iss, sub=sub_val)
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
    ("bundle_signer_wrong_key", {
        "bundle_signer_pub": bytes(SigningKey.generate().verify_key),
    }),
    ("expires_at_past", {"override_expires_at": time.time() - 3600}),
    ("expires_at_exceeds_ceiling", {
        "override_expires_at": time.time() + 7 * 24 * 3600 + 7200,
    }),
    ("sig_count_zero", {"override_sig_count": 0}),
    ("sig_count_two", {"override_sig_count": 2}),
    ("signer_wrong_kid", {"override_signer_kid": "wrong-signer-kid"}),
]


@pytest.mark.pg
@pytest.mark.parametrize("name,overrides", _FIELD_OVERRIDES,
                         ids=[x[0] for x in _FIELD_OVERRIDES])
def test_genesis_envelope_field_rejected(genesis_server, name, overrides):
    """Each wrong envelope field in ADR 0011 2.4 must be refused.
    Uses a fresh org per test so no 409 interference."""
    import httpx
    base = genesis_server["base_url"]
    owner_url = genesis_server["owner_url"]

    # Fresh org per parametrized case
    org_id = _fresh_org(owner_url, f"Field-{name}")

    uid, iss, sub_val, sk, kid, token, genesis_code = _seed_admin_with_link_and_code(
        base, owner_url, org_id, f"field-{name}@test.example",
    )

    env = _build_genesis_envelope(
        sk, org_id, user_id=uid, iss=iss, sub=sub_val,
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
# R1: bundle_signer must match server config; refuse if not configured
# ---------------------------------------------------------------------------


@pytest.mark.pg
def test_genesis_no_bundle_signer_configured_refused(
    genesis_server, bundle_signer_info,
):
    """If AGG_BUNDLE_SIGNER_KEY_FILE is absent, genesis must refuse 400."""
    import httpx
    base = genesis_server["base_url"]
    owner_url = genesis_server["owner_url"]

    org_id = _fresh_org(owner_url, "NoBundleSigner Org")
    uid, iss, sub, sk, kid, token, gcode = _seed_admin_with_link_and_code(
        base, owner_url, org_id, "nobundle@test.example",
    )
    env = _build_genesis_envelope(sk, org_id, user_id=uid, iss=iss, sub=sub)

    # Temporarily hide the key file so the server can't load it
    key_file = bundle_signer_info["key_file"]
    hidden = key_file + ".hidden"
    os.rename(key_file, hidden)
    try:
        r = httpx.post(
            f"{base}/api/v1/sync/signer/genesis",
            json={"genesis_code": gcode, "envelope": env},
            headers={"Authorization": f"Bearer {token}"},
            timeout=10,
        )
    finally:
        os.rename(hidden, key_file)
    assert r.status_code == 400, (
        f"expected 400 when bundle signer not configured, got {r.status_code}"
    )
    assert "bundle_signer_not_configured" in r.text


# ---------------------------------------------------------------------------
# R3: store_registry_version failure returns generic body, not str(exc)
# ---------------------------------------------------------------------------


@pytest.mark.pg
def test_genesis_verify_chain_error_returns_generic_body(genesis_server):
    """An envelope that passes the route checks but fails in verify_chain
    must return a generic error body, not str(exc) (R3)."""
    import httpx
    base = genesis_server["base_url"]
    owner_url = genesis_server["owner_url"]

    org_id = _fresh_org(owner_url, "R3 Org")
    uid, iss, sub, sk, kid, token, gcode = _seed_admin_with_link_and_code(
        base, owner_url, org_id, "r3@test.example",
    )
    env = _build_genesis_envelope(sk, org_id, user_id=uid, iss=iss, sub=sub)
    # Sabotage the envelope kind so verify_chain rejects it; the genesis
    # route does not check envelope.kind, only payload fields.
    env["kind"] = "wrong/kind"

    r = httpx.post(
        f"{base}/api/v1/sync/signer/genesis",
        json={"genesis_code": gcode, "envelope": env},
        headers={"Authorization": f"Bearer {token}"},
        timeout=10,
    )
    assert r.status_code == 400
    body = r.json()
    assert body.get("error") == "envelope_rejected", (
        f"expected generic 'envelope_rejected', got {body}"
    )


# ---------------------------------------------------------------------------
# Two concurrent genesis calls give exactly one v1 (pg_advisory_xact_lock)
# ---------------------------------------------------------------------------


@pytest.mark.pg
def test_concurrent_genesis_exactly_one_v1(genesis_server):
    """Two genesis calls racing: exactly one gets v1, the other 409."""
    import httpx
    import concurrent.futures
    base = genesis_server["base_url"]
    owner_url = genesis_server["owner_url"]

    fresh_org_id = _fresh_org(owner_url, "Concurrent Org")

    def attempt(idx):
        with psycopg.connect(_conninfo(owner_url), autocommit=True) as conn:
            conn.execute("SELECT set_config('app.org_id', %s, false)", [fresh_org_id])
            uid, iss, sub_val = _seed_user_row(
                conn, fresh_org_id, f"racer{idx}@test.example",
            )
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
        # Pass the seeded iss/sub into the envelope (ADR 2.4 requires equality)
        env = _build_genesis_envelope(
            sk, fresh_org_id, user_id=uid, iss=iss, sub=sub_val,
        )
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
def test_no_fingerprint_in_genesis_response(genesis_server):
    """The genesis response must not include a fingerprint (S2)."""
    import httpx
    base = genesis_server["base_url"]
    owner_url = genesis_server["owner_url"]

    org_id = _fresh_org(owner_url, "NoFP Org")
    uid, iss, sub_val, sk, kid, token, gcode = _seed_admin_with_link_and_code(
        base, owner_url, org_id, "nofp@test.example",
    )
    env = _build_genesis_envelope(sk, org_id, user_id=uid, iss=iss, sub=sub_val)
    r = httpx.post(
        f"{base}/api/v1/sync/signer/genesis",
        json={"genesis_code": gcode, "envelope": env},
        headers={"Authorization": f"Bearer {token}"},
        timeout=10,
    )
    if r.status_code in (404, 405):
        raise M2T12dPending("genesis route not implemented")
    try:
        body = r.json()
    except Exception:
        body = {}
    assert "fingerprint" not in body, "fingerprint must not appear in response"


# ---------------------------------------------------------------------------
# admin_audit row registry_genesis written
# ---------------------------------------------------------------------------


@pytest.mark.pg
def test_genesis_writes_admin_audit_row(genesis_server):
    """A successful genesis writes an admin_audit row with action
    'registry_genesis'."""
    import httpx
    base = genesis_server["base_url"]
    owner_url = genesis_server["owner_url"]

    fresh_org_id = _fresh_org(owner_url, "Audit Test Org")

    uid, iss, sub_val, sk, kid, token, gcode = _seed_admin_with_link_and_code(
        base, owner_url, fresh_org_id, "audit-alice@test.example",
    )
    env = _build_genesis_envelope(sk, fresh_org_id, user_id=uid, iss=iss, sub=sub_val)

    r = httpx.post(
        f"{base}/api/v1/sync/signer/genesis",
        json={"genesis_code": gcode, "envelope": env},
        headers={"Authorization": f"Bearer {token}"},
        timeout=10,
    )
    if r.status_code in (404, 405):
        raise M2T12dPending("genesis route not implemented")
    assert r.status_code == 200, f"genesis failed: {r.status_code} {r.text}"

    # Check admin_audit row (action='registry_genesis', detail jsonb holds
    # user_id, key_id and payload_sha256)
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
def test_pending_link_refused_on_pending_route(genesis_server):
    """A pending_link token must be refused on /pending."""
    import httpx
    base = genesis_server["base_url"]
    org_id = genesis_server["org_id"]
    owner_url = genesis_server["owner_url"]

    with psycopg.connect(_conninfo(owner_url), autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        uid, _iss, _sub = _seed_user_row(conn, org_id, "pending-test@test.example")
        _grant_role(conn, org_id, uid, "admin")

    sk, kid, token = _link_and_token_httpx(base, owner_url, org_id, uid)

    r = httpx.get(
        f"{base}/api/v1/sync/signer/pending",
        headers={"Authorization": f"Bearer {token}"},
        timeout=10,
    )
    # pending_link must be refused on /pending (403)
    assert r.status_code == 403, (
        f"pending_link should be refused on /pending, got {r.status_code}"
    )
    # genesis must NOT be blocked for pending_link (the D0-5 allowlist
    # exception):  a POST to /genesis with a bad body still gets through
    # the scope check (returns 400 from the route, not 403 from scope).
    r2 = httpx.post(
        f"{base}/api/v1/sync/signer/genesis",
        json={"genesis_code": "", "envelope": {}},
        headers={"Authorization": f"Bearer {token}"},
        timeout=10,
    )
    assert r2.status_code != 403, (
        "pending_link should be allowed to reach /genesis (scope exception)"
    )


@pytest.mark.pg
def test_pending_link_allowed_on_signatures_for_own_key(genesis_server):
    """A pending_link token may post to /signatures ONLY when the envelope
    adds the token's own key (onboarding case)."""
    import httpx
    base = genesis_server["base_url"]
    org_id = genesis_server["org_id"]
    owner_url = genesis_server["owner_url"]

    with psycopg.connect(_conninfo(owner_url), autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        uid, _iss, _sub = _seed_user_row(conn, org_id, "ownkey@test.example")
        _grant_role(conn, org_id, uid, "admin")

    sk, kid, token = _link_and_token_httpx(base, owner_url, org_id, uid)

    # Envelope that adds the token's own key (the onboarding case).
    # The content is structurally incomplete so store_registry_version
    # will reject it with 400, but the scope/own-key gate must let it
    # through (not 403).
    env = {
        "kind": "agg/registry/v1", "sig_v": 1,
        "payload": {"org_id": org_id, "version": 2, "keys": [
            {"key_id": kid, "public_key": bytes(sk.verify_key).hex()},
        ]},
        "signatures": [],
    }
    r = httpx.post(
        f"{base}/api/v1/sync/signer/signatures",
        json={"type": "registry", "envelope": env, "org_id": org_id},
        headers={"Authorization": f"Bearer {token}"},
        timeout=10,
    )
    assert r.status_code in (200, 400), (
        f"unexpected status {r.status_code} for own-key publish"
    )


@pytest.mark.pg
def test_pending_link_refused_on_signatures_for_other_key(genesis_server):
    """A pending_link post to /signatures that does NOT add its own key
    must get 403."""
    import httpx
    base = genesis_server["base_url"]
    org_id = genesis_server["org_id"]
    owner_url = genesis_server["owner_url"]

    with psycopg.connect(_conninfo(owner_url), autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        uid, _iss, _sub = _seed_user_row(conn, org_id, "otherkey@test.example")
        _grant_role(conn, org_id, uid, "admin")

    sk, kid, token = _link_and_token_httpx(base, owner_url, org_id, uid)

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
    assert r.status_code == 403, (
        f"pending_link non-own-key publish must be 403, got {r.status_code}"
    )


# ---------------------------------------------------------------------------
# Candidates route: admin-only, org-scoped, 404 for another org
# ---------------------------------------------------------------------------


@pytest.mark.pg
def test_candidates_admin_only(genesis_server):
    """GET /api/v1/sync/signer/candidates with a confirmed NON-admin
    token returns 403."""
    import httpx
    base = genesis_server["base_url"]
    owner_url = genesis_server["owner_url"]

    # Create an org with genesis so we can get a confirmed token
    org_id = _fresh_org(owner_url, "CandAdmin Org")
    _do_genesis(base, owner_url, org_id, "admin-cand@test.example")

    # Create a non-admin user, link, run through genesis won't work for
    # non-admin, so instead: seed a viewer user and manually put their
    # key in approver_keys to get a confirmed token.
    with psycopg.connect(_conninfo(owner_url), autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        viewer_id, _iss, _sub = _seed_user_row(
            conn, org_id, "viewer-cand@test.example",
        )
        _grant_role(conn, org_id, viewer_id, "viewer")
        link_code = _create_signer_link(conn, org_id, viewer_id)

    viewer_sk = SigningKey.generate()
    viewer_kid = _kid(viewer_sk)
    httpx.post(f"{base}/api/v1/sync/signer/link", json={
        "code": link_code, "key_id": viewer_kid,
        "public_key": bytes(viewer_sk.verify_key).hex(),
    }, timeout=10)

    # Put the viewer key in approver_keys so cli_key_lookup returns
    # status=signer and the token scope is "confirmed"
    with psycopg.connect(_conninfo(owner_url), autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        conn.execute(
            "INSERT INTO approver_keys "
            "(id, org_id, user_id, key_id, public_key, alg, kind, "
            " roles, registry_version, created_at) "
            "VALUES (%s::uuid, %s::uuid, %s, %s, %s, 'ed25519', 'cli', "
            " '[]'::jsonb, 1, now()) "
            "ON CONFLICT (org_id, key_id) DO NOTHING",
            [str(uuid.uuid4()), org_id, viewer_id, viewer_kid,
             bytes(viewer_sk.verify_key).hex()],
        )

    viewer_token = _get_signer_token_httpx(base, viewer_sk, viewer_kid)
    if viewer_token is None:
        raise M2T12dPending("confirmed non-admin signer token not obtained")

    r = httpx.get(
        f"{base}/api/v1/sync/signer/candidates",
        headers={"Authorization": f"Bearer {viewer_token}"},
        timeout=10,
    )
    if r.status_code in (404, 405):
        raise M2T12dPending("candidates route not implemented")
    assert r.status_code == 403, (
        f"non-admin confirmed token should get 403, got {r.status_code}"
    )


@pytest.mark.pg
def test_candidates_org_scoped(genesis_server):
    """Candidates from another org -> 404."""
    import httpx
    base = genesis_server["base_url"]
    owner_url = genesis_server["owner_url"]

    org_id = _fresh_org(owner_url, "CandScope Org")
    _uid, _sk, _kid_val, confirmed_token = _do_genesis(
        base, owner_url, org_id, "scope@test.example",
    )

    r = httpx.get(
        f"{base}/api/v1/sync/signer/candidates",
        params={"org_id": "99999999-9999-9999-9999-999999999999"},
        headers={"Authorization": f"Bearer {confirmed_token}"},
        timeout=10,
    )
    if r.status_code in (405,):
        raise M2T12dPending("candidates route not implemented")
    assert r.status_code == 404


@pytest.mark.pg
def test_candidates_lists_pending_keys(genesis_server):
    """Candidates lists key_id, public_key, user_id, iss, sub, kind."""
    import httpx
    base = genesis_server["base_url"]
    owner_url = genesis_server["owner_url"]

    org_id = _fresh_org(owner_url, "CandList Org")
    _uid, _sk, _kid_val, confirmed_token = _do_genesis(
        base, owner_url, org_id, "list@test.example",
    )

    # Add a new pending link (the candidate)
    with psycopg.connect(_conninfo(owner_url), autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        cand_uid, _iss, _sub = _seed_user_row(
            conn, org_id, "candidate@test.example",
        )
        _grant_role(conn, org_id, cand_uid, "admin")
        cand_link_code = _create_signer_link(conn, org_id, cand_uid)

    cand_sk = SigningKey.generate()
    cand_kid = _kid(cand_sk)
    httpx.post(f"{base}/api/v1/sync/signer/link", json={
        "code": cand_link_code, "key_id": cand_kid,
        "public_key": bytes(cand_sk.verify_key).hex(),
    }, timeout=10)

    r = httpx.get(
        f"{base}/api/v1/sync/signer/candidates",
        headers={"Authorization": f"Bearer {confirmed_token}"},
        timeout=10,
    )
    if r.status_code in (404, 405):
        raise M2T12dPending("candidates route not implemented")
    if r.status_code == 403:
        raise M2T12dPending("confirmed admin token refused on candidates")
    assert r.status_code == 200
    body = r.json()
    assert isinstance(body, list)
    for item in body:
        for field in ("key_id", "public_key", "user_id", "iss", "sub", "kind"):
            assert field in item, f"missing field {field} in candidate"


# ---------------------------------------------------------------------------
# migrate.py emits genesis_code
# ---------------------------------------------------------------------------


@pytest.mark.pg
def test_migrate_emits_genesis_code_once(genesis_server):
    """migrate.py emits a genesis_code JSON line when no version and no live
    code exist, and not after v1."""
    import subprocess
    import sys

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
    assert genesis_lines, "migrate.py must emit genesis_code on first run"

    # Look up the org and insert a dummy v1 into key_registry_versions
    # so that migrate.py sees an existing registry version.
    conninfo = pg_url.replace("+psycopg", "").replace("postgresql+psycopg", "postgresql")
    if not conninfo.startswith("postgresql"):
        conninfo = pg_url.replace("+psycopg", "")
    with psycopg.connect(conninfo, autocommit=True) as conn:
        row = conn.execute(
            "SELECT id FROM orgs WHERE slug = %s", ["genesisdonev1"]
        ).fetchone()
        assert row is not None, "org genesisdonev1 must exist after first migrate"
        v1_org_id = str(row[0])
        conn.execute(
            "SELECT set_config('app.org_id', %s, false)", [v1_org_id]
        )
        conn.execute(
            "INSERT INTO key_registry_versions "
            "(id, org_id, version, registry_blob, signatures, created_at) "
            "VALUES (%s::uuid, %s::uuid, 1, %s, '[]'::jsonb, now())",
            [str(uuid.uuid4()), v1_org_id, b'{"payload":{"version":1}}'],
        )

    # Second run: must NOT emit genesis_code because v1 exists
    result2 = subprocess.run(
        [sys.executable, "-m", "agg_cp.migrate"],
        capture_output=True, text=True, env=env, timeout=60,
    )
    genesis_lines2 = [l for l in result2.stdout.splitlines() if "genesis_code" in l]
    assert not genesis_lines2, (
        f"migrate.py must not emit genesis_code after v1 exists, "
        f"got: {genesis_lines2}"
    )


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
    calls = re.findall(r'\bstore_registry_version\s*\(', source)
    if calls:
        raise M2T12dPending(
            f"test_m2_t12b_e2e.py still calls store_registry_version "
            f"({len(calls)} call(s)); d4 must move to the routes"
        )
