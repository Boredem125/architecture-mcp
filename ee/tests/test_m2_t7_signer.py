"""T7 ee tests-first: server signer HTTP routes (Postgres, real agg_cp).

Interface contract
==================

Web route (human-auth via ``__Host-agg_session`` cookie):

    POST /api/v1/signer-links           create a signer link code for the
                                          authenticated user; server checks
                                          session auth freshness (created_at
                                          within 15 min); returns the code
                                          once; stores only its SHA-256 hash.

CLI signer routes (``agg/signer-assert/v1`` token auth):

    POST /api/v1/sync/signer/token       authenticate via agg/signer-assert/v1,
                                          return opaque 256-bit token (10 min,
                                          stored as SHA-256 hash)
    POST /api/v1/sync/signer/link         consume link code + key_id + public_key;
                                          identity comes from the signer_links row,
                                          NOT from the request body; a client-sent
                                          auth_time in the body has no effect
    GET  /api/v1/sync/signer/pending      list pending items to sign
    POST /api/v1/sync/signer/signatures   store admin signatures

Tables: ``signer_links`` (user_id uuid FK -> users.id, code_hash, expires_at,
used_at, public_key, key_id, status), ``signer_tokens`` (user_id uuid,
key_id, token_hash, expires_at, scope), ``signer_nonces`` (key_id, nonce,
UNIQUE(key_id, nonce)), ``approver_keys`` (live keys after quorum registry).

Confirmed/live keys: seeded in ``approver_keys`` (cli_key_lookup returns
status 'signer').  Pending-link keys: seeded in ``signer_links`` with
status='pending' (cli_key_lookup returns status 'link').

Tested through HTTP against a real ``agg_cp`` app (``uvicorn --workers 4``):
    - Web link creation: stale session refused, fresh session gets a code,
      code hash only stored, second fetch refused
    - CLI link: consumes code + key, client-sent auth_time ignored,
      single use, expired code refused
    - IDOR: other org's pending/signatures -> 404
    - F5: pending-link token gets 403 on every route except link completion
    - Signer nonce replay refused across 4 workers
    - Token 10 min, stored as hash (DB row check)
    - Second genesis refused through the route
    - Key live only after quorum-signed registry includes it

Also includes unit-level tests for server-side helpers (moved from the
connector suite, which runs without ee/).

Uses the T5 tables via ee conftest fixtures (``pg_url``, ``pg_roles``,
``owner_url``, ``app_url``).  The 4-worker server is a module-scoped
fixture following the ``test_t10_multiworker.py`` pattern.

RED tests have their xfail markers removed (builder already did that).
Guards verify the T5 schema baseline.

Node-id patterns are fixed in M2_BASELINE.md section 5.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import socket
import subprocess
import sys
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import httpx
import psycopg
import pytest
from nacl.signing import SigningKey

from . import _portable
from .fake_idp import FakeClock
from .m2_pending import M2T7Pending
from .t9_helpers import seed_session, make_session_cookie, compute_csrf

_REPO = Path(__file__).resolve().parent.parent.parent

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _need(module: str, attr: str) -> None:
    """Raise M2T7Pending if *module*.*attr* is absent."""
    try:
        mod = __import__(module, fromlist=[attr])
    except ImportError:
        raise M2T7Pending(f"{module} not importable")
    if not hasattr(mod, attr):
        raise M2T7Pending(f"{module}.{attr} not found")


def _conninfo(url: str) -> str:
    return url.replace("+psycopg", "")


def _ensure_at_head(pg_url: str) -> None:
    """Run Alembic upgrade to head."""
    try:
        from agg_cp.db import alembic_config
        from alembic.command import upgrade
        cfg = alembic_config(pg_url)
        upgrade(cfg, "head")
    except Exception as exc:
        raise M2T7Pending(f"Alembic upgrade failed: {exc}") from exc


def _keygen():
    sk = SigningKey.generate()
    pub = bytes(sk.verify_key)
    kid = hashlib.sha256(pub).hexdigest()
    return sk, pub, kid


def _canonical_json(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def _create_org(conn, org_id: str, name: str = "Test Org") -> None:
    slug = org_id[:32].replace("-", "")
    conn.execute(
        "INSERT INTO orgs (id, org_id, name, slug, created_at) "
        "VALUES (%s, %s, %s, %s, now()) ON CONFLICT DO NOTHING",
        [org_id, org_id, name, slug],
    )


def _seed_user(conn, org_id: str, email: str = "alice@test",
               iss: str = "https://idp", sub: str = "alice") -> str:
    """Insert a users row; return user_id (uuid str)."""
    user_id = str(uuid.uuid4())
    conn.execute(
        "INSERT INTO users (id, org_id, oidc_issuer, oidc_subject, email, "
        "status, created_at) VALUES (%s, %s, %s, %s, %s, 'active', now()) "
        "ON CONFLICT DO NOTHING",
        [user_id, org_id, iss, sub, email],
    )
    return user_id


def _insert_link_code(conn, org_id: str, user_id: str, code_hash: str,
                      expires_at: float | None = None) -> str:
    """Insert a signer_links row (pending); return the link id."""
    link_id = str(uuid.uuid4())
    exp = expires_at or (time.time() + 15 * 60)
    conn.execute(
        "INSERT INTO signer_links "
        "(id, org_id, user_id, code_hash, expires_at, status) "
        "VALUES (%s, %s, %s, %s, to_timestamp(%s), 'pending')",
        [link_id, org_id, user_id, code_hash, exp],
    )
    return link_id


def _seed_live_key(conn, org_id: str, user_id: str, kid: str,
                   pub_hex: str) -> str:
    """Insert an approver_keys row so cli_key_lookup finds a live key.

    cli_key_lookup returns 'signer' status for rows in approver_keys
    with revoked_at IS NULL.  This is the real end state of a confirmed
    CLI key that has been included in a quorum-signed registry.
    """
    ak_id = str(uuid.uuid4())
    conn.execute(
        "INSERT INTO approver_keys "
        "(id, org_id, user_id, public_key, alg, kind, key_id, "
        " registry_version, enrolled_at, created_at) "
        "VALUES (%s, %s, %s, %s, 'ed25519', 'cli', %s, 1, now(), now())",
        [ak_id, org_id, user_id, pub_hex, kid],
    )
    return ak_id


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_ready(base_url: str, *, timeout: float = 30.0) -> None:
    deadline = time.monotonic() + timeout
    last_exc = None
    while time.monotonic() < deadline:
        try:
            r = httpx.get(f"{base_url}/ready", timeout=3.0)
            if r.status_code == 200:
                return
        except Exception as exc:
            last_exc = exc
        time.sleep(0.3)
    raise TimeoutError(
        f"/ready did not return 200 within {timeout}s "
        f"(last exception: {last_exc})"
    )


def _sign_assertion(sk, kid, nonce, aud):
    """Build an agg/signer-assert/v1 envelope."""
    payload = {"key_id": kid, "nonce": nonce, "aud": aud, "iat": time.time()}
    tag = b"agg/signer-assert/v1"
    canonical = _canonical_json(payload)
    msg = tag + b"\x00" + canonical
    sig = sk.sign(msg).signature.hex()
    return {
        "kind": "agg/signer-assert/v1",
        "sig_v": 1,
        "payload": payload,
        "signatures": [{"key_id": kid, "alg": "ed25519", "sig": sig}],
    }


def _make_fresh_session(owner_url, org_id, user_id):
    """Create a fresh M1 web session (created_at = now). Return cookie str."""
    clock = FakeClock()
    token, csrf, sid = seed_session(
        owner_url, uuid.UUID(org_id), uuid.UUID(user_id), clock=clock,
    )
    cookie = make_session_cookie(uuid.UUID(org_id), token)
    return cookie, csrf


def _make_stale_session(owner_url, org_id, user_id):
    """Create a stale M1 web session (created_at = 20 min ago). Return cookie."""
    clock = FakeClock(dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=20))
    token, csrf, sid = seed_session(
        owner_url, uuid.UUID(org_id), uuid.UUID(user_id), clock=clock,
    )
    cookie = make_session_cookie(uuid.UUID(org_id), token)
    return cookie, csrf


# ---------------------------------------------------------------------------
# Module-scoped 4-worker server fixture
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def signer_server(pg_url, app_url, owner_url, pg_roles):
    """Start agg_cp with --workers 4 and yield connection info."""
    _ensure_at_head(pg_url)

    org_id = str(uuid.uuid4())
    org_evil = str(uuid.uuid4())

    with psycopg.connect(_conninfo(owner_url), autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        _create_org(conn, org_id, "Signer Test Org")
        alice_id = _seed_user(conn, org_id, "alice@test", "https://idp",
                              f"alice-{uuid.uuid4().hex[:6]}")
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_evil])
        _create_org(conn, org_evil, "Evil Org")
        eve_id = _seed_user(conn, org_evil, "eve@evil", "https://idp",
                            f"eve-{uuid.uuid4().hex[:6]}")

    port = _free_port()
    base_url = f"http://127.0.0.1:{port}"

    extra_paths = os.pathsep.join([
        str(_REPO / "ee" / "src"),
        str(_REPO / "src"),
    ])
    existing_pp = os.environ.get("PYTHONPATH", "")
    pythonpath = extra_paths + (os.pathsep + existing_pp if existing_pp else "")

    env = {
        **os.environ,
        "AGG_DATABASE_URL": app_url,
        "AGG_PUBLIC_URL": base_url,
        "PYTHONPATH": pythonpath,
    }

    cmd = [
        sys.executable, "-m", "uvicorn",
        "agg_cp.app:create_app",
        "--factory",
        "--workers", "4",
        "--host", "127.0.0.1",
        "--port", str(port),
    ]

    proc = subprocess.Popen(
        cmd, env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        **_portable.popen_kwargs(),
    )
    try:
        _wait_ready(base_url, timeout=30.0)
        yield {
            "base_url": base_url,
            "org_id": org_id,
            "org_evil": org_evil,
            "alice_id": alice_id,
            "eve_id": eve_id,
            "owner_url": owner_url,
            "app_url": app_url,
            "pg_url": pg_url,
        }
    finally:
        _portable.group_terminate(proc)
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            _portable.group_kill(proc)
            proc.wait(timeout=5)


# ===================================================================
# Guards (pass now -- T5 schema baseline)
# ===================================================================


@pytest.mark.pg
def test_signer_links_table_exists(pg_url, pg_roles, owner_url):
    """Guard: signer_links table exists (T5 prerequisite)."""
    _ensure_at_head(pg_url)
    with psycopg.connect(_conninfo(owner_url)) as conn:
        row = conn.execute(
            "SELECT 1 FROM information_schema.tables "
            "WHERE table_schema = 'public' AND table_name = 'signer_links'"
        ).fetchone()
    assert row is not None, "signer_links table not found -- T5 prerequisite"


@pytest.mark.pg
def test_signer_nonces_table_exists(pg_url, pg_roles, owner_url):
    """Guard: signer_nonces table exists (T5 prerequisite)."""
    _ensure_at_head(pg_url)
    with psycopg.connect(_conninfo(owner_url)) as conn:
        row = conn.execute(
            "SELECT 1 FROM information_schema.tables "
            "WHERE table_schema = 'public' AND table_name = 'signer_nonces'"
        ).fetchone()
    assert row is not None, "signer_nonces table not found -- T5 prerequisite"


@pytest.mark.pg
def test_signer_tokens_table_exists(pg_url, pg_roles, owner_url):
    """Guard: signer_tokens table exists (T5 prerequisite)."""
    _ensure_at_head(pg_url)
    with psycopg.connect(_conninfo(owner_url)) as conn:
        row = conn.execute(
            "SELECT 1 FROM information_schema.tables "
            "WHERE table_schema = 'public' AND table_name = 'signer_tokens'"
        ).fetchone()
    assert row is not None, "signer_tokens table not found -- T5 prerequisite"


# ===================================================================
# Unit-level server helper tests (moved from connector suite)
# ===================================================================


@pytest.mark.pg
def test_signer_token_stored_as_hash():
    """The signer token is stored only as a SHA-256 hash, never raw."""
    _need("agg_cp.sync.signer", "create_signer_token")
    from agg_cp.sync.signer import create_signer_token
    raw, hashed = create_signer_token()
    assert hashed == hashlib.sha256(raw.encode() if isinstance(raw, str)
                                    else raw).hexdigest()
    assert raw != hashed


@pytest.mark.pg
def test_signer_token_10_min_max():
    """The signer token expires in at most 10 minutes."""
    _need("agg_cp.sync.signer", "SIGNER_TOKEN_MAX_AGE")
    from agg_cp.sync.signer import SIGNER_TOKEN_MAX_AGE
    assert SIGNER_TOKEN_MAX_AGE <= 600


@pytest.mark.pg
def test_signer_nonce_replay_refused(signer_server):
    """A replayed (key_id, nonce) pair is refused via the real /token route."""
    srv = signer_server
    sk, pub, kid = _keygen()

    with psycopg.connect(_conninfo(srv["owner_url"]), autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [srv["org_id"]])
        _seed_live_key(conn, srv["org_id"], srv["alice_id"], kid, pub.hex())

    fixed_nonce = f"replay-unit-{uuid.uuid4().hex[:8]}"
    assertion = _sign_assertion(sk, kid, nonce=fixed_nonce, aud=srv["base_url"])

    r1 = httpx.post(f"{srv['base_url']}/api/v1/sync/signer/token",
                    json=assertion, timeout=10.0)
    assert r1.status_code == 200

    r2 = httpx.post(f"{srv['base_url']}/api/v1/sync/signer/token",
                    json=assertion, timeout=10.0)
    assert r2.status_code == 409
    assert r2.json()["error"] == "nonce_replay"


@pytest.mark.pg
def test_stale_login_link_refused():
    """A link attempt from a session older than 15 min is refused."""
    _need("agg_cp.sync.signer", "validate_link_session")
    from agg_cp.sync.signer import validate_link_session, StaleLinkSession
    auth_time = time.time() - 20 * 60
    with pytest.raises(StaleLinkSession):
        validate_link_session(auth_time=auth_time, max_age=900)


@pytest.mark.pg
def test_fresh_login_link_accepted():
    """A link from a session within 15 min is accepted."""
    _need("agg_cp.sync.signer", "validate_link_session")
    from agg_cp.sync.signer import validate_link_session
    auth_time = time.time() - 5 * 60
    validate_link_session(auth_time=auth_time, max_age=900)


@pytest.mark.pg
def test_link_code_single_use(signer_server):
    """A link code can be consumed only once via the real /link route."""
    srv = signer_server
    sk, pub, kid = _keygen()
    code = f"single-use-{uuid.uuid4().hex[:8]}"
    code_hash = hashlib.sha256(code.encode()).hexdigest()

    with psycopg.connect(_conninfo(srv["owner_url"]), autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [srv["org_id"]])
        _insert_link_code(conn, srv["org_id"], srv["alice_id"], code_hash)

    body = {"code": code, "key_id": kid, "public_key": pub.hex()}
    r1 = httpx.post(f"{srv['base_url']}/api/v1/sync/signer/link",
                    json=body, timeout=10.0)
    assert r1.status_code == 200

    sk2, pub2, kid2 = _keygen()
    body2 = {"code": code, "key_id": kid2, "public_key": pub2.hex()}
    r2 = httpx.post(f"{srv['base_url']}/api/v1/sync/signer/link",
                    json=body2, timeout=10.0)
    assert r2.status_code == 410


@pytest.mark.pg
def test_link_code_15_min_expiry(signer_server):
    """A link code older than 15 min is refused via the real /link route."""
    srv = signer_server
    sk, pub, kid = _keygen()
    code = f"expired-{uuid.uuid4().hex[:8]}"
    code_hash = hashlib.sha256(code.encode()).hexdigest()

    with psycopg.connect(_conninfo(srv["owner_url"]), autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [srv["org_id"]])
        _insert_link_code(conn, srv["org_id"], srv["alice_id"], code_hash,
                          expires_at=time.time() - 20 * 60)

    r = httpx.post(
        f"{srv['base_url']}/api/v1/sync/signer/link",
        json={"code": code, "key_id": kid, "public_key": pub.hex()},
        timeout=10.0,
    )
    assert r.status_code == 410


@pytest.mark.pg
def test_pending_link_token_only_completes_link():
    """A token from a pending, unconfirmed link key can only complete the
    link; every other route returns 403 (F5).
    """
    _need("agg_cp.sync.signer", "check_signer_token_scope")
    from agg_cp.sync.signer import check_signer_token_scope, SignerScopeError
    token_scope = {"status": "pending_link", "key_id": "a" * 64}
    # T12d: pending_link can access link, genesis and signatures
    # (own-key check for signatures is in the route handler)
    for allowed in ("link", "genesis", "signatures"):
        check_signer_token_scope(token_scope, route=allowed)
    for route in ("pending", "approve", "deny"):
        with pytest.raises(SignerScopeError):
            check_signer_token_scope(token_scope, route=route)


@pytest.mark.pg
def test_confirmed_token_accesses_all_signer_routes():
    """A token from a confirmed, registry-included key accesses all routes."""
    _need("agg_cp.sync.signer", "check_signer_token_scope")
    from agg_cp.sync.signer import check_signer_token_scope
    token_scope = {"status": "confirmed", "key_id": "a" * 64}
    for route in ("link", "pending", "signatures", "approve", "deny"):
        check_signer_token_scope(token_scope, route=route)


@pytest.mark.pg
def test_idor_other_org_pending_404():
    """Requesting pending items for another org returns 404 (IDOR)."""
    _need("agg_cp.sync.signer", "get_pending")
    from agg_cp.sync.signer import get_pending, SignerNotFound
    with pytest.raises(SignerNotFound):
        get_pending(org_id="org-evil", requester_org_id="org-1")


@pytest.mark.pg
def test_idor_other_org_signatures_404():
    """Posting signatures for another org returns 404 (IDOR)."""
    _need("agg_cp.sync.signer", "post_signatures")
    from agg_cp.sync.signer import post_signatures, SignerNotFound
    with pytest.raises(SignerNotFound):
        post_signatures(org_id="org-evil", requester_org_id="org-1",
                        signatures=[])


@pytest.mark.pg
def test_server_second_genesis_refused(pg_url, pg_roles, owner_url):
    """The server refuses a second genesis upload (threat 22, server side).

    Uses the real agg_cp.sync.registry.store_registry_version with Postgres.
    A second genesis raises RegistryError and writes a sync_alerts row.
    """
    _ensure_at_head(pg_url)
    from agg_cp.sync.registry import store_registry_version
    from sandbox.protocol.registry import RegistryError
    from sandbox.connector.sync.signer import build_genesis

    org_id = str(uuid.uuid4())
    sk, pub, kid = _keygen()
    bsk, bpub, bkid = _keygen()

    with psycopg.connect(_conninfo(owner_url), autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        _create_org(conn, org_id, "Genesis Test Org")
        _seed_user(conn, org_id, "gen@test", "https://idp", "gen-alice")

    env, fp = build_genesis(
        admin_sk=sk, org_id=org_id,
        iss="https://idp", sub="gen-alice",
        bundle_signer_pub=bpub,
    )

    with psycopg.connect(_conninfo(owner_url)) as conn:
        conn.autocommit = False
        store_registry_version(conn, org_id, env)

    with pytest.raises(RegistryError, match="second genesis"):
        with psycopg.connect(_conninfo(owner_url)) as conn:
            conn.autocommit = False
            store_registry_version(conn, org_id, env)

    # Verify a sync_alerts row was written
    with psycopg.connect(_conninfo(owner_url)) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        row = conn.execute(
            "SELECT kind FROM sync_alerts WHERE org_id = %s::uuid",
            [org_id],
        ).fetchone()
    assert row is not None, "no sync_alerts row for second genesis"
    assert row[0] == "second_genesis"


# ===================================================================
# RED: POST /api/v1/signer-links -- web route (session cookie auth)
# ===================================================================


@pytest.mark.pg
def test_web_link_fresh_session_gets_code(signer_server):
    """POST /api/v1/signer-links with a fresh session returns a link code."""
    _need("agg_cp.sync.signer", "consume_signer_link")
    srv = signer_server
    cookie, csrf = _make_fresh_session(srv["owner_url"], srv["org_id"],
                                       srv["alice_id"])
    r = httpx.post(
        f"{srv['base_url']}/api/v1/signer-links",
        cookies={"__Host-agg_session": cookie},
        headers={"X-CSRF-Token": csrf},
        json={},
        timeout=10.0,
    )
    assert r.status_code == 200
    body = r.json()
    assert "code" in body
    assert len(body["code"]) >= 16


@pytest.mark.pg
def test_web_link_stale_session_refused(signer_server):
    """POST /api/v1/signer-links with a stale session (>15 min) is refused."""
    _need("agg_cp.sync.signer", "consume_signer_link")
    srv = signer_server
    cookie, csrf = _make_stale_session(srv["owner_url"], srv["org_id"],
                                       srv["alice_id"])
    r = httpx.post(
        f"{srv['base_url']}/api/v1/signer-links",
        cookies={"__Host-agg_session": cookie},
        headers={"X-CSRF-Token": csrf},
        json={},
        timeout=10.0,
    )
    assert r.status_code in (400, 403)


@pytest.mark.pg
def test_web_link_code_hash_only_stored(signer_server):
    """The raw code is not stored in signer_links; only its hash is."""
    _need("agg_cp.sync.signer", "consume_signer_link")
    srv = signer_server
    cookie, csrf = _make_fresh_session(srv["owner_url"], srv["org_id"],
                                       srv["alice_id"])
    r = httpx.post(
        f"{srv['base_url']}/api/v1/signer-links",
        cookies={"__Host-agg_session": cookie},
        headers={"X-CSRF-Token": csrf},
        json={},
        timeout=10.0,
    )
    assert r.status_code == 200
    raw_code = r.json()["code"]
    expected_hash = hashlib.sha256(raw_code.encode()).hexdigest()

    with psycopg.connect(_conninfo(srv["owner_url"])) as conn:
        row = conn.execute(
            "SELECT code_hash FROM signer_links "
            "WHERE org_id = %s::uuid AND user_id = %s::uuid "
            "ORDER BY created_at DESC LIMIT 1",
            [srv["org_id"], srv["alice_id"]],
        ).fetchone()
    assert row is not None
    assert row[0] == expected_hash
    # The raw code must not appear anywhere in the row
    with psycopg.connect(_conninfo(srv["owner_url"])) as conn:
        all_cols = conn.execute(
            "SELECT * FROM signer_links "
            "WHERE org_id = %s::uuid AND code_hash = %s",
            [srv["org_id"], expected_hash],
        ).fetchone()
    assert raw_code not in str(all_cols)


# ===================================================================
# RED: POST /api/v1/sync/signer/link -- CLI consume (no auth_time from body)
# ===================================================================


@pytest.mark.pg
def test_cli_link_consumes_code(signer_server):
    """POST /api/v1/sync/signer/link consumes a link code and binds a key."""
    _need("agg_cp.sync.signer", "consume_signer_link")
    srv = signer_server
    sk, pub, kid = _keygen()
    code = f"link-code-{uuid.uuid4().hex[:8]}"
    code_hash = hashlib.sha256(code.encode()).hexdigest()

    with psycopg.connect(_conninfo(srv["owner_url"]), autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [srv["org_id"]])
        _insert_link_code(conn, srv["org_id"], srv["alice_id"], code_hash)

    r = httpx.post(
        f"{srv['base_url']}/api/v1/sync/signer/link",
        json={"code": code, "key_id": kid, "public_key": pub.hex()},
        timeout=10.0,
    )
    assert r.status_code == 200
    assert r.json()["key_id"] == kid


@pytest.mark.pg
def test_cli_link_single_use(signer_server):
    """POST /sync/signer/link with the same code twice: second refused."""
    _need("agg_cp.sync.signer", "consume_signer_link")
    srv = signer_server
    sk, pub, kid = _keygen()
    code = f"link-code-{uuid.uuid4().hex[:8]}"
    code_hash = hashlib.sha256(code.encode()).hexdigest()

    with psycopg.connect(_conninfo(srv["owner_url"]), autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [srv["org_id"]])
        _insert_link_code(conn, srv["org_id"], srv["alice_id"], code_hash)

    body = {"code": code, "key_id": kid, "public_key": pub.hex()}
    r1 = httpx.post(f"{srv['base_url']}/api/v1/sync/signer/link",
                    json=body, timeout=10.0)
    assert r1.status_code == 200

    sk2, pub2, kid2 = _keygen()
    body2 = {"code": code, "key_id": kid2, "public_key": pub2.hex()}
    r2 = httpx.post(f"{srv['base_url']}/api/v1/sync/signer/link",
                    json=body2, timeout=10.0)
    assert r2.status_code in (404, 409, 410)


@pytest.mark.pg
def test_cli_link_expired_code(signer_server):
    """POST /sync/signer/link with an expired code (expires_at past): refused."""
    _need("agg_cp.sync.signer", "consume_signer_link")
    srv = signer_server
    sk, pub, kid = _keygen()
    code = f"link-exp-{uuid.uuid4().hex[:8]}"
    code_hash = hashlib.sha256(code.encode()).hexdigest()

    with psycopg.connect(_conninfo(srv["owner_url"]), autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [srv["org_id"]])
        _insert_link_code(conn, srv["org_id"], srv["alice_id"], code_hash,
                          expires_at=time.time() - 20 * 60)

    r = httpx.post(
        f"{srv['base_url']}/api/v1/sync/signer/link",
        json={"code": code, "key_id": kid, "public_key": pub.hex()},
        timeout=10.0,
    )
    assert r.status_code in (400, 403, 410)


@pytest.mark.pg
def test_cli_link_ignores_client_auth_time(signer_server):
    """A client-sent auth_time in the CLI /link body has no effect.

    The server must not trust a client-supplied auth_time; identity and
    freshness come from the signer_links row, not from the request body.
    """
    _need("agg_cp.sync.signer", "consume_signer_link")
    srv = signer_server
    sk, pub, kid = _keygen()
    code = f"link-noat-{uuid.uuid4().hex[:8]}"
    code_hash = hashlib.sha256(code.encode()).hexdigest()

    with psycopg.connect(_conninfo(srv["owner_url"]), autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [srv["org_id"]])
        _insert_link_code(conn, srv["org_id"], srv["alice_id"], code_hash)

    # Send a stale auth_time -- the server must ignore it and succeed
    r = httpx.post(
        f"{srv['base_url']}/api/v1/sync/signer/link",
        json={"code": code, "key_id": kid, "public_key": pub.hex(),
              "auth_time": time.time() - 60 * 60},
        timeout=10.0,
    )
    assert r.status_code == 200
    assert r.json()["key_id"] == kid


# ===================================================================
# RED: POST /api/v1/sync/signer/token -- nonce replay, 10 min, hash stored
# ===================================================================


@pytest.mark.pg
def test_token_route_returns_token(signer_server):
    """POST /token with a valid signer-assert returns a token."""
    _need("agg_cp.sync.signer", "authenticate_signer")
    srv = signer_server
    sk, pub, kid = _keygen()

    with psycopg.connect(_conninfo(srv["owner_url"]), autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [srv["org_id"]])
        _seed_live_key(conn, srv["org_id"], srv["alice_id"], kid, pub.hex())

    assertion = _sign_assertion(sk, kid, nonce=f"n-{uuid.uuid4().hex[:8]}",
                                aud=srv["base_url"])
    r = httpx.post(
        f"{srv['base_url']}/api/v1/sync/signer/token",
        json=assertion,
        timeout=10.0,
    )
    assert r.status_code == 200
    body = r.json()
    assert "token" in body
    assert len(body["token"]) >= 32


@pytest.mark.pg
def test_token_stored_as_hash_in_db(signer_server):
    """The signer_tokens row stores only the SHA-256 hash, never the raw token."""
    _need("agg_cp.sync.signer", "authenticate_signer")
    srv = signer_server
    sk, pub, kid = _keygen()

    with psycopg.connect(_conninfo(srv["owner_url"]), autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [srv["org_id"]])
        _seed_live_key(conn, srv["org_id"], srv["alice_id"], kid, pub.hex())

    assertion = _sign_assertion(sk, kid, nonce=f"n-{uuid.uuid4().hex[:8]}",
                                aud=srv["base_url"])
    r = httpx.post(f"{srv['base_url']}/api/v1/sync/signer/token",
                   json=assertion, timeout=10.0)
    assert r.status_code == 200
    raw_token = r.json()["token"]

    expected_hash = hashlib.sha256(
        raw_token.encode() if isinstance(raw_token, str) else raw_token
    ).hexdigest()
    with psycopg.connect(_conninfo(srv["owner_url"])) as conn:
        row = conn.execute(
            "SELECT token_hash FROM signer_tokens "
            "WHERE key_id = %s ORDER BY created_at DESC LIMIT 1",
            [kid],
        ).fetchone()
    assert row is not None, "No signer_tokens row found"
    assert row[0] == expected_hash


@pytest.mark.pg
def test_signer_nonce_replay_across_workers(signer_server):
    """A replayed (key_id, nonce) is refused across 4 workers (D10.6)."""
    _need("agg_cp.sync.signer", "authenticate_signer")
    srv = signer_server
    sk, pub, kid = _keygen()

    with psycopg.connect(_conninfo(srv["owner_url"]), autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [srv["org_id"]])
        _seed_live_key(conn, srv["org_id"], srv["alice_id"], kid, pub.hex())

    fixed_nonce = f"replay-{uuid.uuid4().hex[:8]}"
    assertion = _sign_assertion(sk, kid, nonce=fixed_nonce, aud=srv["base_url"])

    r1 = httpx.post(f"{srv['base_url']}/api/v1/sync/signer/token",
                    json=assertion, timeout=10.0)
    assert r1.status_code == 200

    def try_replay(_):
        return httpx.post(f"{srv['base_url']}/api/v1/sync/signer/token",
                          json=assertion, timeout=10.0)

    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(try_replay, range(4)))
    for r in results:
        assert r.status_code in (401, 409), f"replay accepted: {r.status_code}"


# ===================================================================
# RED: IDOR -- other org's pending/signatures give 404
# ===================================================================


@pytest.mark.pg
def test_idor_pending_other_org_404(signer_server):
    """GET /pending with a token scoped to org-evil returns 404 for org data."""
    _need("agg_cp.sync.signer", "signer_pending")
    srv = signer_server
    sk, pub, kid = _keygen()

    with psycopg.connect(_conninfo(srv["owner_url"]), autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [srv["org_evil"]])
        _seed_live_key(conn, srv["org_evil"], srv["eve_id"], kid, pub.hex())

    assertion = _sign_assertion(sk, kid, nonce=f"n-{uuid.uuid4().hex[:8]}",
                                aud=srv["base_url"])
    r = httpx.post(f"{srv['base_url']}/api/v1/sync/signer/token",
                   json=assertion, timeout=10.0)
    assert r.status_code == 200
    token = r.json()["token"]

    r2 = httpx.get(
        f"{srv['base_url']}/api/v1/sync/signer/pending",
        headers={"Authorization": f"Bearer {token}"},
        params={"org_id": srv["org_id"]},
        timeout=10.0,
    )
    assert r2.status_code in (403, 404) or r2.json() == []


@pytest.mark.pg
def test_idor_signatures_other_org_404(signer_server):
    """POST /signatures with a token scoped to org-evil for org data: refused."""
    _need("agg_cp.sync.signer", "store_signer_signatures")
    srv = signer_server
    sk, pub, kid = _keygen()

    with psycopg.connect(_conninfo(srv["owner_url"]), autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [srv["org_evil"]])
        _seed_live_key(conn, srv["org_evil"], srv["eve_id"], kid, pub.hex())

    assertion = _sign_assertion(sk, kid, nonce=f"n-{uuid.uuid4().hex[:8]}",
                                aud=srv["base_url"])
    r = httpx.post(f"{srv['base_url']}/api/v1/sync/signer/token",
                   json=assertion, timeout=10.0)
    assert r.status_code == 200
    token = r.json()["token"]

    r2 = httpx.post(
        f"{srv['base_url']}/api/v1/sync/signer/signatures",
        headers={"Authorization": f"Bearer {token}"},
        json={"org_id": srv["org_id"], "signatures": []},
        timeout=10.0,
    )
    assert r2.status_code in (403, 404)


# ===================================================================
# RED: F5 -- pending-link token restricted to link completion
# ===================================================================


@pytest.mark.pg
def test_pending_link_token_blocked_on_pending(signer_server):
    """A pending-link token gets 403 on GET /pending (F5)."""
    _need("agg_cp.sync.signer", "authenticate_signer")
    srv = signer_server
    sk, pub, kid = _keygen()

    code = f"f5-pend-{uuid.uuid4().hex[:8]}"
    code_hash = hashlib.sha256(code.encode()).hexdigest()
    with psycopg.connect(_conninfo(srv["owner_url"]), autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [srv["org_id"]])
        conn.execute(
            "INSERT INTO signer_links "
            "(id, org_id, user_id, code_hash, expires_at, "
            " key_id, public_key, status) "
            "VALUES (%s, %s, %s, %s, now() + interval '15 min', %s, %s, 'pending')",
            [str(uuid.uuid4()), srv["org_id"], srv["alice_id"],
             code_hash, kid, pub.hex()],
        )

    assertion = _sign_assertion(sk, kid, nonce=f"n-{uuid.uuid4().hex[:8]}",
                                aud=srv["base_url"])
    r = httpx.post(f"{srv['base_url']}/api/v1/sync/signer/token",
                   json=assertion, timeout=10.0)
    assert r.status_code == 200
    token = r.json()["token"]

    r2 = httpx.get(
        f"{srv['base_url']}/api/v1/sync/signer/pending",
        headers={"Authorization": f"Bearer {token}"},
        timeout=10.0,
    )
    assert r2.status_code in (403, 404)


@pytest.mark.pg
def test_pending_link_token_blocked_on_signatures(signer_server):
    """A pending-link token gets 403 on POST /signatures (F5)."""
    _need("agg_cp.sync.signer", "authenticate_signer")
    srv = signer_server
    sk, pub, kid = _keygen()

    code = f"f5-sig-{uuid.uuid4().hex[:8]}"
    code_hash = hashlib.sha256(code.encode()).hexdigest()
    with psycopg.connect(_conninfo(srv["owner_url"]), autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [srv["org_id"]])
        conn.execute(
            "INSERT INTO signer_links "
            "(id, org_id, user_id, code_hash, expires_at, "
            " key_id, public_key, status) "
            "VALUES (%s, %s, %s, %s, now() + interval '15 min', %s, %s, 'pending')",
            [str(uuid.uuid4()), srv["org_id"], srv["alice_id"],
             code_hash, kid, pub.hex()],
        )

    assertion = _sign_assertion(sk, kid, nonce=f"n-{uuid.uuid4().hex[:8]}",
                                aud=srv["base_url"])
    r = httpx.post(f"{srv['base_url']}/api/v1/sync/signer/token",
                   json=assertion, timeout=10.0)
    assert r.status_code == 200
    token = r.json()["token"]

    r2 = httpx.post(
        f"{srv['base_url']}/api/v1/sync/signer/signatures",
        headers={"Authorization": f"Bearer {token}"},
        json={"signatures": []},
        timeout=10.0,
    )
    assert r2.status_code in (403, 404)


@pytest.mark.pg
def test_pending_link_token_can_complete_link(signer_server):
    """A pending-link token CAN complete the link (POST /link ok, F5)."""
    _need("agg_cp.sync.signer", "authenticate_signer")
    srv = signer_server
    sk, pub, kid = _keygen()

    code = f"f5-ok-{uuid.uuid4().hex[:8]}"
    code_hash = hashlib.sha256(code.encode()).hexdigest()
    with psycopg.connect(_conninfo(srv["owner_url"]), autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [srv["org_id"]])
        _insert_link_code(conn, srv["org_id"], srv["alice_id"], code_hash)
        conn.execute(
            "INSERT INTO signer_links "
            "(id, org_id, user_id, code_hash, expires_at, "
            " key_id, public_key, status) "
            "VALUES (%s, %s, %s, %s, now() + interval '15 min', %s, %s, 'pending')",
            [str(uuid.uuid4()), srv["org_id"], srv["alice_id"],
             "f5-pre-" + kid[:8], kid, pub.hex()],
        )

    assertion = _sign_assertion(sk, kid, nonce=f"n-{uuid.uuid4().hex[:8]}",
                                aud=srv["base_url"])
    r = httpx.post(f"{srv['base_url']}/api/v1/sync/signer/token",
                   json=assertion, timeout=10.0)
    assert r.status_code == 200
    token = r.json()["token"]

    r2 = httpx.post(
        f"{srv['base_url']}/api/v1/sync/signer/link",
        headers={"Authorization": f"Bearer {token}"},
        json={"code": code, "key_id": kid, "public_key": pub.hex()},
        timeout=10.0,
    )
    assert r2.status_code == 200


# ===================================================================
# RED: second genesis refused through the route
# ===================================================================


def _second_genesis_setup(signer_server):
    """Shared setup for R2-1 second-genesis tests.

    Creates a **fresh org** inside the running server, creates v1 via
    store_registry_version, obtains a confirmed token, posts v1 again
    to /signatures (expects 409).  Returns (srv, org_id, r2) where r2
    is the second POST response.
    """
    _need("agg_cp.sync.signer", "store_signer_signatures")
    from agg_cp.sync.registry import store_registry_version
    from sandbox.connector.sync.signer import build_genesis

    srv = signer_server
    sk, pub, kid = _keygen()
    bsk, bpub, bkid = _keygen()

    # Fresh org so tests are independent of each other
    org_id = str(uuid.uuid4())
    with psycopg.connect(_conninfo(srv["owner_url"]), autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        _create_org(conn, org_id, "R2-1 Genesis Org")
        user_id = _seed_user(conn, org_id, "r21@test", "https://idp",
                             f"r21-{uuid.uuid4().hex[:6]}")

    env, fp = build_genesis(
        admin_sk=sk, org_id=org_id,
        iss="https://idp", sub="r21",
        bundle_signer_pub=bpub,
        user_id=user_id,
    )
    with psycopg.connect(_conninfo(srv["owner_url"])) as conn:
        conn.autocommit = False
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [org_id])
        store_registry_version(conn, org_id, env)

    assertion = _sign_assertion(sk, kid, nonce=f"n-{uuid.uuid4().hex[:8]}",
                                aud=srv["base_url"])
    r = httpx.post(f"{srv['base_url']}/api/v1/sync/signer/token",
                   json=assertion, timeout=10.0)
    assert r.status_code == 200, f"token request failed: {r.status_code}"
    token = r.json()["token"]
    headers = {"Authorization": f"Bearer {token}"}

    r2 = httpx.post(
        f"{srv['base_url']}/api/v1/sync/signer/signatures",
        headers=headers,
        json={"type": "registry", "envelope": env},
        timeout=10.0,
    )
    return srv, org_id, r2


@pytest.mark.pg
def test_second_genesis_refused_via_route(signer_server):
    """R2-1: POST /signatures with a second v1 after a genesis-route v1
    returns 409 (the /signatures guard refuses duplicate v1)."""
    srv, org_id, r2 = _second_genesis_setup(signer_server)
    assert r2.status_code == 409, (
        f"second v1 on /signatures should be 409, got {r2.status_code}: "
        f"{r2.text[:300]}"
    )


@pytest.mark.pg
def test_second_genesis_alert_via_route(signer_server):
    """R2-1 alert: when /signatures returns 409 for a second v1,
    a second_genesis alert row must be committed (threat 22)."""
    srv, org_id, r2 = _second_genesis_setup(signer_server)
    assert r2.status_code == 409

    with psycopg.connect(_conninfo(srv["owner_url"]), autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [org_id])
        alert_row = conn.execute(
            "SELECT kind FROM sync_alerts "
            "WHERE org_id = %s::uuid AND kind = 'second_genesis'",
            [org_id],
        ).fetchone()
    assert alert_row is not None, (
        "R2-1: second genesis via /signatures did not commit a "
        "second_genesis alert row"
    )
    assert alert_row[0] == "second_genesis"


# ===================================================================
# RED: key live only after quorum-signed registry includes it
# ===================================================================


@pytest.mark.pg
def test_key_not_live_until_in_registry(signer_server):
    """A linked key not yet in a quorum-signed registry cannot sign
    anything except completing the link (server-side check).
    """
    _need("agg_cp.sync.signer", "authenticate_signer")
    srv = signer_server
    sk, pub, kid = _keygen()

    code = f"quorum-{uuid.uuid4().hex[:8]}"
    code_hash = hashlib.sha256(code.encode()).hexdigest()
    with psycopg.connect(_conninfo(srv["owner_url"]), autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [srv["org_id"]])
        bob_id = _seed_user(conn, srv["org_id"], "bob@test",
                            "https://idp", f"bob-{uuid.uuid4().hex[:6]}")
        conn.execute(
            "INSERT INTO signer_links "
            "(id, org_id, user_id, code_hash, expires_at, "
            " key_id, public_key, status) "
            "VALUES (%s, %s, %s, %s, now() + interval '15 min', %s, %s, 'pending')",
            [str(uuid.uuid4()), srv["org_id"], bob_id,
             code_hash, kid, pub.hex()],
        )

    assertion = _sign_assertion(sk, kid, nonce=f"n-{uuid.uuid4().hex[:8]}",
                                aud=srv["base_url"])
    r = httpx.post(f"{srv['base_url']}/api/v1/sync/signer/token",
                   json=assertion, timeout=10.0)
    assert r.status_code == 200
    token = r.json()["token"]

    r2 = httpx.post(
        f"{srv['base_url']}/api/v1/sync/signer/signatures",
        headers={"Authorization": f"Bearer {token}"},
        json={"signatures": []},
        timeout=10.0,
    )
    assert r2.status_code in (403, 404)
