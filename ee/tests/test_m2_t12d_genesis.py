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
# d4: GET /api/v1/sync/signer/registry (stub ruling 2 -- server side)
# Full chain, org-scoped, confirmed and pending_link read, refused without auth
# ---------------------------------------------------------------------------


@pytest.mark.pg
def test_d4_registry_route_returns_full_chain(genesis_server):
    """GET /api/v1/sync/signer/registry with a confirmed signer token
    returns the full chain as a JSON list with at least one envelope."""
    import httpx
    base = genesis_server["base_url"]
    owner_url = genesis_server["owner_url"]

    org_id = _fresh_org(owner_url, "RegRoute Org")
    _uid, sk, kid, confirmed_token = _do_genesis(base, owner_url, org_id)

    r = httpx.get(
        f"{base}/api/v1/sync/signer/registry",
        headers={"Authorization": f"Bearer {confirmed_token}"},
        timeout=10,
    )
    if r.status_code in (404, 405):
        raise M2T12dPending("GET /signer/registry route not implemented")
    assert r.status_code == 200, (
        f"expected 200 for confirmed signer, got {r.status_code}: {r.text}"
    )
    body = r.json()
    assert isinstance(body, list), f"expected list, got {type(body)}"
    assert len(body) >= 1, "chain should contain at least v1"
    # v1 must have payload.version == 1
    assert body[0].get("payload", {}).get("version") == 1


@pytest.mark.pg
def test_d4_registry_route_org_scoped(genesis_server):
    """GET /signer/registry with a confirmed token from org A must not see
    org B's chain (404, not another org's data)."""
    import httpx
    base = genesis_server["base_url"]
    owner_url = genesis_server["owner_url"]

    org_a = _fresh_org(owner_url, "RegScope A")
    _do_genesis(base, owner_url, org_a)

    org_b = _fresh_org(owner_url, "RegScope B")
    _uid_b, sk_b, kid_b, token_b = _do_genesis(base, owner_url, org_b)

    # token_b is scoped to org_b; the route must return org_b's chain only
    r = httpx.get(
        f"{base}/api/v1/sync/signer/registry",
        headers={"Authorization": f"Bearer {token_b}"},
        timeout=10,
    )
    if r.status_code in (404, 405):
        raise M2T12dPending("GET /signer/registry route not implemented")
    assert r.status_code == 200
    chain = r.json()
    # Every entry must belong to org_b, never org_a
    for env in chain:
        env_org = env.get("payload", {}).get("org_id", "")
        assert env_org == org_b, (
            f"chain contains org {env_org}, expected only {org_b}"
        )


@pytest.mark.pg
def test_d4_registry_route_pending_link_read_only(genesis_server):
    """A pending_link token can GET /signer/registry (read-only)."""
    import httpx
    base = genesis_server["base_url"]
    owner_url = genesis_server["owner_url"]

    org_id = _fresh_org(owner_url, "PendRead Org")
    _do_genesis(base, owner_url, org_id)

    # Create a second user with a pending link (not in the registry yet)
    with psycopg.connect(_conninfo(owner_url), autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        uid2, _iss, _sub = _seed_user_row(conn, org_id, "carol@pend.test")
        _grant_role(conn, org_id, uid2, "admin")

    sk2, kid2, pending_token = _link_and_token_httpx(
        base, owner_url, org_id, uid2,
    )

    r = httpx.get(
        f"{base}/api/v1/sync/signer/registry",
        headers={"Authorization": f"Bearer {pending_token}"},
        timeout=10,
    )
    if r.status_code in (404, 405):
        raise M2T12dPending("GET /signer/registry route not implemented")
    assert r.status_code == 200, (
        f"pending_link should read /signer/registry, got {r.status_code}"
    )
    chain = r.json()
    assert isinstance(chain, list) and len(chain) >= 1


@pytest.mark.pg
def test_d4_registry_route_refused_without_auth(genesis_server):
    """GET /signer/registry without auth -> 401."""
    import httpx
    base = genesis_server["base_url"]
    owner_url = genesis_server["owner_url"]

    org_id = _fresh_org(owner_url, "NoAuth Org")
    _do_genesis(base, owner_url, org_id)

    r = httpx.get(
        f"{base}/api/v1/sync/signer/registry",
        timeout=10,
    )
    if r.status_code in (404, 405):
        raise M2T12dPending("GET /signer/registry route not implemented")
    assert r.status_code == 401, (
        f"expected 401 without auth, got {r.status_code}"
    )


# ---------------------------------------------------------------------------
# d4: migrate.py emits bundle_signer public key next to genesis_code
# (stub ruling 1 -- out-of-band source for the CLI)
# ---------------------------------------------------------------------------


@pytest.mark.pg
def test_d4_migrate_emits_bundle_signer(genesis_server, bundle_signer_info):
    """migrate.py must print a bundle_signer JSON line with key_id and
    public_key derived from AGG_BUNDLE_SIGNER_KEY_FILE, next to the
    genesis_code line."""
    import subprocess
    import sys

    pg_url = genesis_server["pg_url"]

    env = {
        **os.environ,
        "AGG_DATABASE_URL": pg_url,
        "AGG_BOOTSTRAP_ORG_SLUG": "bundlesignertest",
        "AGG_BOOTSTRAP_ORG_NAME": "BundleSigner Test",
        "AGG_BOOTSTRAP_ORG_ISSUER": "https://idp.test",
        "AGG_BOOTSTRAP_ORG_CLIENT_ID": "test-client",
        "AGG_BUNDLE_SIGNER_KEY_FILE": bundle_signer_info["key_file"],
    }

    result = subprocess.run(
        [sys.executable, "-m", "agg_cp.migrate"],
        capture_output=True, text=True, env=env, timeout=60,
    )
    stdout = result.stdout.strip()
    lines = [l for l in stdout.splitlines() if l.strip()]

    bs_lines = [l for l in lines if "bundle_signer" in l]
    if not bs_lines:
        raise M2T12dPending(
            "migrate.py does not emit a bundle_signer JSON line"
        )

    data = json.loads(bs_lines[0])
    assert data.get("event") == "bundle_signer", (
        f"expected event=bundle_signer, got {data.get('event')}"
    )
    assert "key_id" in data, "bundle_signer line missing key_id"
    assert "public_key" in data, "bundle_signer line missing public_key"
    # key_id must be sha256(public_key bytes)
    expected_kid = hashlib.sha256(
        bytes.fromhex(data["public_key"])
    ).hexdigest()
    assert data["key_id"] == expected_kid, (
        f"key_id mismatch: {data['key_id']} != {expected_kid}"
    )
    # Must match the configured bundle signer
    assert data["public_key"] == bundle_signer_info["public_key_hex"], (
        "bundle_signer public_key does not match AGG_BUNDLE_SIGNER_KEY_FILE"
    )


# ---------------------------------------------------------------------------
# D4-1 CRITICAL: /signatures must refuse v1 and any post for org with no chain
# ---------------------------------------------------------------------------


@pytest.mark.pg
def test_d4_1_guard_signatures_refuses_v1_when_chain_exists(genesis_server):
    """D4-1 guard: POST /signatures with version=1 when v1 already exists
    returns 409 (store_registry_version refuses duplicate v1)."""
    import httpx
    base = genesis_server["base_url"]
    owner_url = genesis_server["owner_url"]

    org_id = _fresh_org(owner_url, "D41Guard Org")
    uid, sk, kid, confirmed_token = _do_genesis(base, owner_url, org_id)

    env = _build_genesis_envelope(sk, org_id, user_id=uid)
    r = httpx.post(
        f"{base}/api/v1/sync/signer/signatures",
        json={"type": "registry", "envelope": env, "org_id": org_id},
        headers={"Authorization": f"Bearer {confirmed_token}"},
        timeout=10,
    )
    assert r.status_code == 409, (
        f"v1 to /signatures with existing chain should be 409, "
        f"got {r.status_code}"
    )


@pytest.mark.pg
def test_d4_1_guard_second_genesis_alert_committed(genesis_server):
    """R2-1: when /signatures returns 409 for a second v1, the
    second_genesis alert row must be committed (threat 22 detection)."""
    import httpx
    base = genesis_server["base_url"]
    owner_url = genesis_server["owner_url"]

    org_id = _fresh_org(owner_url, "D41Alert Org")
    uid, sk, kid, confirmed_token = _do_genesis(base, owner_url, org_id)

    env = _build_genesis_envelope(sk, org_id, user_id=uid)
    r = httpx.post(
        f"{base}/api/v1/sync/signer/signatures",
        json={"type": "registry", "envelope": env, "org_id": org_id},
        headers={"Authorization": f"Bearer {confirmed_token}"},
        timeout=10,
    )
    assert r.status_code == 409

    # R2-1: the guard must commit a second_genesis alert row
    with psycopg.connect(_conninfo(owner_url), autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        alert_row = conn.execute(
            "SELECT kind FROM sync_alerts "
            "WHERE org_id = %s::uuid AND kind = 'second_genesis'",
            [org_id],
        ).fetchone()
    assert alert_row is not None, (
        "R2-1: second v1 on /signatures did not commit a "
        "second_genesis alert row"
    )


@pytest.mark.pg
def test_d4_1_signatures_refuses_v1_no_chain(genesis_server):
    """D4-1: POST /signatures with version=1 for an org with no registry
    must be 409 genesis_only_via_genesis_route, and must store nothing."""
    import httpx
    base = genesis_server["base_url"]
    owner_url = genesis_server["owner_url"]

    org_id = _fresh_org(owner_url, "D41NoChain Org")

    uid, iss, sub, sk, kid, token, _gcode = _seed_admin_with_link_and_code(
        base, owner_url, org_id, "d41@test.example",
    )

    env = _build_genesis_envelope(sk, org_id, user_id=uid, iss=iss, sub=sub)
    r = httpx.post(
        f"{base}/api/v1/sync/signer/signatures",
        json={"type": "registry", "envelope": env, "org_id": org_id},
        headers={"Authorization": f"Bearer {token}"},
        timeout=10,
    )

    if r.status_code == 200:
        raise M2T12dPending(
            "D4-1: /signatures accepted v1 for org with no chain "
            "(should be 409 genesis_only_via_genesis_route)"
        )
    assert r.status_code == 409, (
        f"expected 409, got {r.status_code}: {r.text}"
    )

    # Verify nothing stored
    with psycopg.connect(_conninfo(owner_url), autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        ver_row = conn.execute(
            "SELECT COUNT(*) FROM key_registry_versions "
            "WHERE org_id = %s::uuid",
            [org_id],
        ).fetchone()
        assert ver_row[0] == 0, "key_registry_versions row stored despite refusal"
        ak_row = conn.execute(
            "SELECT COUNT(*) FROM approver_keys WHERE org_id = %s::uuid",
            [org_id],
        ).fetchone()
        assert ak_row[0] == 0, "approver_keys row stored despite refusal"


@pytest.mark.pg
def test_d4_1_non_admin_cannot_create_root_via_signatures(genesis_server):
    """D4-1: A non-admin session user with no genesis code cannot create a
    registry root via any route (neither /genesis nor /signatures)."""
    import httpx
    base = genesis_server["base_url"]
    owner_url = genesis_server["owner_url"]

    org_id = _fresh_org(owner_url, "D41NonAdmin Org")

    # Viewer user -- no admin role
    with psycopg.connect(_conninfo(owner_url), autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        uid, iss, sub = _seed_user_row(conn, org_id, "viewer@d41.test")
        _grant_role(conn, org_id, uid, "viewer")

    sk, kid, token = _link_and_token_httpx(base, owner_url, org_id, uid)

    env = _build_genesis_envelope(sk, org_id, user_id=uid, iss=iss, sub=sub)

    # /genesis must refuse (non-admin) -- this already works
    r_gen = httpx.post(
        f"{base}/api/v1/sync/signer/genesis",
        json={"genesis_code": "fake", "envelope": env},
        headers={"Authorization": f"Bearer {token}"},
        timeout=10,
    )
    assert r_gen.status_code in (400, 403), (
        f"/genesis should refuse non-admin, got {r_gen.status_code}"
    )

    # /signatures must also refuse (D4-1 fix)
    r_sig = httpx.post(
        f"{base}/api/v1/sync/signer/signatures",
        json={"type": "registry", "envelope": env, "org_id": org_id},
        headers={"Authorization": f"Bearer {token}"},
        timeout=10,
    )
    if r_sig.status_code == 200:
        raise M2T12dPending(
            "D4-1: non-admin created root via /signatures"
        )
    assert r_sig.status_code in (403, 409), (
        f"expected 403 or 409 for non-admin /signatures, got {r_sig.status_code}"
    )


@pytest.mark.pg
def test_d4_1_confirmed_other_org_refuses_v1_no_chain(genesis_server):
    """D4-1: A confirmed signer token from org A must not create a v1
    registry for org B (which has no chain) via /signatures.  The token
    scope check prevents cross-org access (404), and the genesis gate
    (409) provides defence in depth.  Either refusal is correct."""
    import httpx
    base = genesis_server["base_url"]
    owner_url = genesis_server["owner_url"]

    # Org A: fully bootstrapped (has a genesis)
    org_a = _fresh_org(owner_url, "D41 OrgA")
    uid_a, sk_a, kid_a, confirmed_token_a = _do_genesis(
        base, owner_url, org_a, "d41a@test.example",
    )

    # Org B: no chain at all
    org_b = _fresh_org(owner_url, "D41 OrgB")

    # Use org A's confirmed token to try posting a v1 envelope for org B
    env_b = _build_genesis_envelope(sk_a, org_b, user_id=uid_a)
    r = httpx.post(
        f"{base}/api/v1/sync/signer/signatures",
        json={"type": "registry", "envelope": env_b, "org_id": org_b},
        headers={"Authorization": f"Bearer {confirmed_token_a}"},
        timeout=10,
    )

    # The attack must be prevented.  Today the token scope check fires
    # first and returns 404 (the token is org-A-scoped, so org B's
    # resource is "not found").  After the D4-1 genesis gate lands the
    # version-1 check (409) or an explicit org mismatch (403) may fire
    # instead.  All three are correct refusals.
    assert r.status_code in (403, 404, 409), (
        f"D4-1: expected 403/404/409, got {r.status_code}: {r.text}"
    )

    # Verify nothing stored for org B
    with psycopg.connect(_conninfo(owner_url), autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_b])
        ver_row = conn.execute(
            "SELECT COUNT(*) FROM key_registry_versions "
            "WHERE org_id = %s::uuid",
            [org_b],
        ).fetchone()
        assert ver_row[0] == 0, "key_registry_versions row stored for org B"
        ak_row = conn.execute(
            "SELECT COUNT(*) FROM approver_keys WHERE org_id = %s::uuid",
            [org_b],
        ).fetchone()
        assert ak_row[0] == 0, "approver_keys row stored for org B"


@pytest.mark.pg
def test_d4_1_positive_genesis_then_v2_via_signatures(genesis_server):
    """D4-1 positive control: genesis via /genesis then v2 via /signatures
    works end to end.  The genesis key appears in approver_keys, and v2
    adds a second key."""
    import httpx
    base = genesis_server["base_url"]
    owner_url = genesis_server["owner_url"]

    org_id = _fresh_org(owner_url, "D41Pos Org")
    uid, sk, kid, confirmed_token = _do_genesis(
        base, owner_url, org_id, "d41pos@test.example",
    )

    # Build v2 adding a second admin key
    second_sk = SigningKey.generate()
    second_kid = _kid(second_sk)
    with psycopg.connect(_conninfo(owner_url), autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        uid2, iss2, sub2 = _seed_user_row(conn, org_id, "bob@d41.test")
        _grant_role(conn, org_id, uid2, "admin")
        link_code2 = _create_signer_link(conn, org_id, uid2)

    r_link = httpx.post(f"{base}/api/v1/sync/signer/link", json={
        "code": link_code2, "key_id": second_kid,
        "public_key": bytes(second_sk.verify_key).hex(),
    }, timeout=10)
    assert r_link.status_code == 200

    # Get v1 chain to compute prev_hash
    r_chain = httpx.get(
        f"{base}/api/v1/sync/signer/registry",
        headers={"Authorization": f"Bearer {confirmed_token}"},
        timeout=10,
    )
    if r_chain.status_code in (404, 405):
        raise M2T12dPending("GET /signer/registry not implemented")
    assert r_chain.status_code == 200
    chain = r_chain.json()
    v1_payload = chain[0]["payload"]

    v1_canonical = json.dumps(
        v1_payload, sort_keys=True, separators=(",", ":"),
    ).encode()
    prev_hash = hashlib.sha256(
        org_id.encode() + b":" + v1_canonical,
    ).hexdigest()

    bs_pub = _SERVER_BUNDLE_SIGNER_PUB or bytes(SigningKey.generate().verify_key)
    bs_kid = hashlib.sha256(bs_pub).hexdigest()

    v2_payload = {
        "org_id": org_id,
        "version": 2,
        "prev_hash": prev_hash,
        "threshold": 1,
        "admins": [kid, second_kid],
        "keys": v1_payload["keys"] + [{
            "key_id": second_kid,
            "public_key": bytes(second_sk.verify_key).hex(),
            "kind": "cli",
            "alg": "ed25519",
            "user_id": uid2,
            "iss": iss2,
            "sub": sub2,
            "roles": ["admin", "approver"],
            "added_in": 2,
        }],
        "bundle_signer": {"key_id": bs_kid, "public_key": bs_pub.hex()},
        "expires_at": v1_payload.get("expires_at", time.time() + 86400),
    }

    tag = b"agg/registry/v1"
    v2_canonical = json.dumps(
        v2_payload, sort_keys=True, separators=(",", ":"),
    ).encode()
    msg = tag + b"\x00" + v2_canonical
    sig = sk.sign(msg).signature.hex()
    v2_env = {
        "kind": "agg/registry/v1",
        "sig_v": 1,
        "payload": v2_payload,
        "signatures": [{"key_id": kid, "alg": "ed25519", "sig": sig}],
    }

    # Carol's pending_link token includes her own key, so she can post
    second_token = _get_signer_token_httpx(base, second_sk, second_kid)
    if second_token is None:
        # Use confirmed token from genesis admin instead
        second_token = confirmed_token

    r_v2 = httpx.post(
        f"{base}/api/v1/sync/signer/signatures",
        json={"type": "registry", "envelope": v2_env, "org_id": org_id},
        headers={"Authorization": f"Bearer {second_token}"},
        timeout=10,
    )
    assert r_v2.status_code == 200, (
        f"v2 via /signatures failed: {r_v2.status_code} {r_v2.text}"
    )

    # Verify approver_keys now has both keys
    with psycopg.connect(_conninfo(owner_url), autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        ak_count = conn.execute(
            "SELECT COUNT(*) FROM approver_keys "
            "WHERE org_id = %s::uuid AND revoked_at IS NULL",
            [org_id],
        ).fetchone()[0]
        assert ak_count >= 2, (
            f"expected >= 2 active keys after v2, got {ak_count}"
        )


# ---------------------------------------------------------------------------
# Ruling 5 (ee): link route returns iss and sub
# ---------------------------------------------------------------------------


@pytest.mark.pg
def test_d4_ruling5_link_returns_iss_sub(genesis_server):
    """Ruling 5 ee: POST /signer/link must return iss == users.oidc_issuer
    and sub == users.oidc_subject of the linked user."""
    import httpx
    base = genesis_server["base_url"]
    owner_url = genesis_server["owner_url"]

    org_id = _fresh_org(owner_url, "R5Link Org")
    _do_genesis(base, owner_url, org_id)

    with psycopg.connect(_conninfo(owner_url), autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        uid, iss, sub = _seed_user_row(conn, org_id, "r5link@test.example")
        _grant_role(conn, org_id, uid, "admin")
        link_code = _create_signer_link(conn, org_id, uid)

    sk = SigningKey.generate()
    kid = _kid(sk)
    r = httpx.post(f"{base}/api/v1/sync/signer/link", json={
        "code": link_code, "key_id": kid,
        "public_key": bytes(sk.verify_key).hex(),
    }, timeout=10)
    assert r.status_code == 200, f"link failed: {r.status_code} {r.text}"
    body = r.json()

    if "iss" not in body or not body.get("iss"):
        raise M2T12dPending(
            "link response does not contain iss"
        )
    if "sub" not in body or not body.get("sub"):
        raise M2T12dPending(
            "link response does not contain sub"
        )

    assert body["iss"] == iss, (
        f"iss mismatch: got {body['iss']!r}, expected {iss!r}"
    )
    assert body["sub"] == sub, (
        f"sub mismatch: got {body['sub']!r}, expected {sub!r}"
    )


# ---------------------------------------------------------------------------
# D4-7: link route returns error for missing user, never ""
# ---------------------------------------------------------------------------


@pytest.mark.pg
def test_d4_7_link_missing_user_returns_error(genesis_server):
    """D4-7: If the signer_links user_id has no matching users row, the
    link route must return an error (500), never iss='' or sub=''."""
    import httpx
    base = genesis_server["base_url"]
    owner_url = genesis_server["owner_url"]

    org_id = _fresh_org(owner_url, "D47 Org")
    _do_genesis(base, owner_url, org_id)

    # Create a signer_links row pointing to a non-existent user_id
    ghost_user_id = str(uuid.uuid4())
    with psycopg.connect(_conninfo(owner_url), autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        code = secrets.token_hex(16)
        code_hash = hashlib.sha256(code.encode()).hexdigest()
        conn.execute(
            "INSERT INTO signer_links "
            "(id, org_id, user_id, code_hash, expires_at, status) "
            "VALUES (%s, %s, %s, %s, now() + interval '15 minutes', 'pending')",
            [str(uuid.uuid4()), org_id, ghost_user_id, code_hash],
        )

    sk = SigningKey.generate()
    kid = _kid(sk)
    r = httpx.post(f"{base}/api/v1/sync/signer/link", json={
        "code": code, "key_id": kid,
        "public_key": bytes(sk.verify_key).hex(),
    }, timeout=10)

    if r.status_code == 200:
        body = r.json()
        if body.get("iss", "") == "" or body.get("sub", "") == "":
            raise M2T12dPending(
                f"D4-7: link returned empty iss/sub for missing user: {body}"
            )
        # If iss/sub are non-empty despite no user row, that's unexpected
        raise M2T12dPending(
            f"D4-7: link returned 200 for missing user row: {body}"
        )
    # Expected: 500 or 400 error
    assert r.status_code in (400, 500), (
        f"expected error for missing user, got {r.status_code}"
    )


# ---------------------------------------------------------------------------
# D4-4: migrate fails closed on bad or missing bundle signer key
# ---------------------------------------------------------------------------


@pytest.mark.pg
def test_d4_4_migrate_fails_closed_bad_bundle_key(genesis_server, tmp_path):
    """D4-4: When AGG_BUNDLE_SIGNER_KEY_FILE is set but the key cannot be
    loaded (bad format), migrate must exit non-zero with a clear message
    and print no private material."""
    import subprocess
    import sys

    pg_url = genesis_server["pg_url"]

    # Write a bad key file
    bad_key_file = tmp_path / "bad_bundle_key"
    bad_key_file.write_text("not-a-valid-hex-key", encoding="utf-8")

    env = {
        **os.environ,
        "AGG_DATABASE_URL": pg_url,
        "AGG_BOOTSTRAP_ORG_SLUG": "d44badkey",
        "AGG_BOOTSTRAP_ORG_NAME": "D44 Bad Key",
        "AGG_BOOTSTRAP_ORG_ISSUER": "https://idp.test",
        "AGG_BOOTSTRAP_ORG_CLIENT_ID": "test-client",
        "AGG_BUNDLE_SIGNER_KEY_FILE": str(bad_key_file),
    }

    result = subprocess.run(
        [sys.executable, "-m", "agg_cp.migrate"],
        capture_output=True, text=True, env=env, timeout=60,
    )

    combined = result.stdout + result.stderr
    # Must not print private material
    assert "not-a-valid-hex-key" not in combined, (
        "migrate printed the bad key file contents"
    )

    if result.returncode == 0:
        # Check if it silently ignored the bad key
        if "bundle_signer_error" not in result.stdout:
            raise M2T12dPending(
                "D4-4: migrate exited 0 with bad bundle key file "
                "and no error event"
            )
    else:
        # Non-zero exit is correct; check for clear message
        assert "bundle_signer" in combined.lower() or "key" in combined.lower(), (
            f"migrate failed but message unclear: {combined[:300]}"
        )


# ---------------------------------------------------------------------------
# D4-3: compose.yml gives migrate jobs the bundle_signer_key secret
# ---------------------------------------------------------------------------


def test_d4_3_compose_gives_migrate_bundle_signer():
    """D4-3: ee/deploy/compose.yml must mount bundle_signer_key into the
    migrate and migrate-demo services, with AGG_BUNDLE_SIGNER_KEY_FILE
    pointing to the mounted secret."""
    import yaml
    from pathlib import Path

    compose_file = Path(__file__).parent.parent / "deploy" / "compose.yml"
    assert compose_file.exists(), f"compose.yml not found at {compose_file}"

    with open(compose_file, encoding="utf-8") as f:
        compose = yaml.safe_load(f)

    services = compose.get("services", {})

    for svc_name in ("migrate", "migrate-demo"):
        svc = services.get(svc_name)
        if svc is None:
            continue
        svc_secrets = svc.get("secrets", [])
        if "bundle_signer_key" not in svc_secrets:
            raise M2T12dPending(
                f"D4-3: {svc_name} service does not mount bundle_signer_key secret"
            )
        svc_env = svc.get("environment", {})
        env_val = svc_env.get("AGG_BUNDLE_SIGNER_KEY_FILE", "")
        if not env_val:
            raise M2T12dPending(
                f"D4-3: {svc_name} service does not set "
                f"AGG_BUNDLE_SIGNER_KEY_FILE env var"
            )


# Positive control: api service already has bundle_signer_key
def test_d4_3_positive_api_has_bundle_signer():
    """D4-3 positive control: the api service already mounts bundle_signer_key."""
    import yaml
    from pathlib import Path

    compose_file = Path(__file__).parent.parent / "deploy" / "compose.yml"
    with open(compose_file, encoding="utf-8") as f:
        compose = yaml.safe_load(f)

    api = compose["services"]["api"]
    assert "bundle_signer_key" in api.get("secrets", []), (
        "api service must mount bundle_signer_key"
    )


# ---------------------------------------------------------------------------
# D4-8: AST check replaces grep (store_registry_version)
# ---------------------------------------------------------------------------


def test_e2e_does_not_call_store_registry_version():
    """ee/tests/test_m2_t12b_e2e.py must not call store_registry_version
    directly once d4 moves it to the genesis/signature routes.

    D4-8: Uses AST walk instead of regex to ignore comments and strings."""
    import ast
    from pathlib import Path

    e2e_file = Path(__file__).parent / "test_m2_t12b_e2e.py"
    if not e2e_file.exists():
        raise M2T12dPending("test_m2_t12b_e2e.py not found")

    source = e2e_file.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(e2e_file))

    # Walk AST looking for calls to store_registry_version
    # or imports of that name
    calls_found = []
    imports_found = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            # Direct call: store_registry_version(...)
            if isinstance(func, ast.Name) and func.id == "store_registry_version":
                calls_found.append(node.lineno)
            # Attribute call: module.store_registry_version(...)
            elif isinstance(func, ast.Attribute) and func.attr == "store_registry_version":
                calls_found.append(node.lineno)
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            names = [alias.name for alias in getattr(node, "names", [])]
            if "store_registry_version" in names:
                imports_found.append(node.lineno)
            # Check aliased imports
            for alias in getattr(node, "names", []):
                if alias.asname == "store_registry_version":
                    imports_found.append(node.lineno)

    if calls_found:
        raise M2T12dPending(
            f"test_m2_t12b_e2e.py calls store_registry_version "
            f"at line(s) {calls_found}; d4 must move to the routes"
        )
    if imports_found:
        raise M2T12dPending(
            f"test_m2_t12b_e2e.py imports store_registry_version "
            f"at line(s) {imports_found}; d4 must remove the import"
        )


# ---------------------------------------------------------------------------
# D2-8: migrate.py unreadable / directory bundle_signer key
# ---------------------------------------------------------------------------


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M2T12dPending,
                    reason="d5: D2-8 unreadable bundle_signer label")
@pytest.mark.parametrize("kind", ["missing", "directory"],
                         ids=["missing_path", "directory_path"])
def test_d5_d4_4_unreadable_label(genesis_server, tmp_path, kind):
    """D2-8: migrate with unreadable bundle_signer key -> exit != 0,
    stdout has reason='unreadable', path string absent."""
    import subprocess
    import sys

    pg_url = genesis_server["pg_url"]

    if kind == "missing":
        bad_path = str(tmp_path / "nonexistent_key_file")
    else:
        bad_dir = tmp_path / "a_directory"
        bad_dir.mkdir()
        bad_path = str(bad_dir)

    env = {
        **os.environ,
        "AGG_DATABASE_URL": pg_url,
        "AGG_BOOTSTRAP_ORG_SLUG": f"d58{kind}",
        "AGG_BOOTSTRAP_ORG_NAME": f"D58 {kind}",
        "AGG_BOOTSTRAP_ORG_ISSUER": "https://idp.test",
        "AGG_BOOTSTRAP_ORG_CLIENT_ID": "test-client",
        "AGG_BUNDLE_SIGNER_KEY_FILE": bad_path,
    }

    result = subprocess.run(
        [sys.executable, "-m", "agg_cp.migrate"],
        capture_output=True, text=True, env=env, timeout=60,
    )

    combined = result.stdout + result.stderr
    if result.returncode == 0:
        raise M2T12dPending(
            f"D2-8 {kind}: migrate exited 0; d5 unreadable check not built"
        )
    # d5 adds the "unreadable" vs "bad_format" distinction
    if '"reason":"unreadable"' not in result.stdout and "unreadable" not in result.stdout:
        raise M2T12dPending(
            f"D2-8 {kind}: expected 'unreadable' in stdout but got: "
            f"{result.stdout[:200]}"
        )
    # The path string must not appear
    assert bad_path not in combined, (
        f"path string {bad_path!r} leaked into output"
    )


# ---------------------------------------------------------------------------
# D2-9: migrate.py bad format bundle_signer key
# ---------------------------------------------------------------------------


@pytest.mark.pg
def test_d5_d4_4_bad_format_label(genesis_server, tmp_path):
    """D2-9: migrate with bad-format bundle_signer key -> exit != 0,
    reason=='bad_format', file text absent. Plain pass."""
    import subprocess
    import sys

    pg_url = genesis_server["pg_url"]

    bad_key_file = tmp_path / "bad_format_key"
    bad_key_file.write_text("not-a-valid-hex-key", encoding="utf-8")

    env = {
        **os.environ,
        "AGG_DATABASE_URL": pg_url,
        "AGG_BOOTSTRAP_ORG_SLUG": "d59badfmt",
        "AGG_BOOTSTRAP_ORG_NAME": "D59 Bad Format",
        "AGG_BOOTSTRAP_ORG_ISSUER": "https://idp.test",
        "AGG_BOOTSTRAP_ORG_CLIENT_ID": "test-client",
        "AGG_BUNDLE_SIGNER_KEY_FILE": str(bad_key_file),
    }

    result = subprocess.run(
        [sys.executable, "-m", "agg_cp.migrate"],
        capture_output=True, text=True, env=env, timeout=60,
    )

    combined = result.stdout + result.stderr
    assert result.returncode != 0, (
        f"expected non-zero exit for bad format, got 0"
    )
    assert "bad_format" in result.stdout or "bad_format" in combined, (
        f"expected 'bad_format' in output: {result.stdout[:300]}"
    )
    assert "not-a-valid-hex-key" not in combined, (
        "bad key file text leaked into output"
    )


# ---------------------------------------------------------------------------
# D2-10: /signatures version type shapes
# ---------------------------------------------------------------------------


@pytest.mark.pg
@pytest.mark.parametrize("version_val,has_chain,expected_status", [
    pytest.param(2, False, 400, id="int_2_no_chain"),
    pytest.param("1", False, 400, id="str_1_no_chain"),
    pytest.param("2", False, 400, id="str_2_no_chain"),
    pytest.param(1.0, False, 409, id="float_1_0_no_chain"),
    pytest.param(True, False, 409, id="bool_True_no_chain"),
    pytest.param("2", True, 400, id="str_2_with_chain"),
    pytest.param(2.0, True, 400, id="float_2_0_with_chain"),
])
def test_d5_d4_1_signatures_version_shapes(
    genesis_server, version_val, has_chain, expected_status,
):
    """D2-10: POST /signatures with various version types.
    Check key_registry_versions and approver_keys unchanged.
    No-chain cases add no sync_alerts row."""
    import httpx
    base = genesis_server["base_url"]
    owner_url = genesis_server["owner_url"]

    org_id = _fresh_org(owner_url, f"D510-{version_val!r:.10}-{has_chain}")

    if has_chain:
        uid, sk, kid, confirmed_token = _do_genesis(
            base, owner_url, org_id,
        )
    else:
        uid, iss, sub, sk, kid, token, _gcode = _seed_admin_with_link_and_code(
            base, owner_url, org_id, "d510@test.example",
        )
        confirmed_token = token

    # Build a minimal envelope with the version_val
    env = {
        "kind": "agg/registry/v1", "sig_v": 1,
        "payload": {
            "org_id": org_id,
            "version": version_val,
            "keys": [{"key_id": kid, "public_key": bytes(sk.verify_key).hex()}],
        },
        "signatures": [],
    }

    # Snap before
    with psycopg.connect(_conninfo(owner_url), autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        ver_before = conn.execute(
            "SELECT count(*) FROM key_registry_versions WHERE org_id = %s::uuid",
            [org_id],
        ).fetchone()[0]
        ak_before = conn.execute(
            "SELECT count(*) FROM approver_keys WHERE org_id = %s::uuid",
            [org_id],
        ).fetchone()[0]

    r = httpx.post(
        f"{base}/api/v1/sync/signer/signatures",
        json={"type": "registry", "envelope": env, "org_id": org_id},
        headers={"Authorization": f"Bearer {confirmed_token}"},
        timeout=15,
    )

    assert r.status_code == expected_status, (
        f"expected {expected_status}, got {r.status_code}: {r.text}"
    )

    # Verify no side effects
    with psycopg.connect(_conninfo(owner_url), autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        ver_after = conn.execute(
            "SELECT count(*) FROM key_registry_versions WHERE org_id = %s::uuid",
            [org_id],
        ).fetchone()[0]
        ak_after = conn.execute(
            "SELECT count(*) FROM approver_keys WHERE org_id = %s::uuid",
            [org_id],
        ).fetchone()[0]

    assert ver_after == ver_before, (
        f"key_registry_versions count changed: {ver_before} -> {ver_after}"
    )
    # For no-chain cases, approver_keys should be unchanged
    if not has_chain:
        assert ak_after == ak_before

    # No-chain cases: no sync_alerts row added
    if not has_chain:
        with psycopg.connect(_conninfo(owner_url), autocommit=True) as conn:
            conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
            alerts = conn.execute(
                "SELECT count(*) FROM sync_alerts "
                "WHERE org_id = %s::uuid",
                [org_id],
            ).fetchone()[0]
        assert alerts == 0, (
            f"no-chain case should not add sync_alerts, got {alerts}"
        )
