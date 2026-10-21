"""T7 ee tests-first: server signer HTTP routes (Postgres, real agg_cp).

Interface contract
==================

Server module ``agg_cp.sync.signer`` (routes under ``/api/v1/sync/signer/``):

    POST /api/v1/sync/signer/token       authenticate via agg/signer-assert/v1,
                                          return opaque 256-bit token (10 min,
                                          stored as SHA-256 hash)
    POST /api/v1/sync/signer/link         consume link code, bind CLI key to user
    GET  /api/v1/sync/signer/pending      list pending items to sign
    POST /api/v1/sync/signer/signatures   store admin signatures

Tables: ``signer_links``, ``signer_tokens``, ``signer_nonces``.

Tested through HTTP against a real ``agg_cp`` app (``uvicorn --workers 4``):
    - IDOR: other org's pending/signatures -> 404
    - F5:   pending-link token gets 403 on every route except link completion
    - Stale-login link refused (session > 15 min)
    - Link code single use, 15 min expiry
    - Signer nonce replay refused across 4 workers
    - Token 10 min, stored as hash (DB row check)
    - Second genesis refused through the route
    - Key live only after quorum-signed registry includes it

Uses the T5 tables via ee conftest fixtures (``pg_url``, ``pg_roles``,
``owner_url``, ``app_url``).  The 4-worker server is a module-scoped
fixture following the ``test_t10_multiworker.py`` pattern.

RED tests xfail on M2T7Pending.  Guards verify the T5 schema baseline.

Node-id patterns are fixed in M2_BASELINE.md section 5.
"""
from __future__ import annotations

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
from .m2_pending import M2T7Pending

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


def _insert_link_code(conn, org_id: str, code_hash: str,
                      user_id: str, iss: str, sub: str,
                      issued_at: float | None = None) -> str:
    """Insert a signer link code row; return the link id."""
    link_id = str(uuid.uuid4())
    ts = issued_at or time.time()
    conn.execute(
        "INSERT INTO signer_links "
        "(id, org_id, code_hash, user_id, iss, sub, issued_at) "
        "VALUES (%s, %s, %s, %s, %s, %s, to_timestamp(%s))",
        [link_id, org_id, code_hash, user_id, iss, sub, ts],
    )
    return link_id


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
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_evil])
        _create_org(conn, org_evil, "Evil Org")

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
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        **_portable.popen_kwargs(),
    )
    try:
        _wait_ready(base_url, timeout=30.0)
        yield {
            "base_url": base_url,
            "org_id": org_id,
            "org_evil": org_evil,
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
# RED: POST /api/v1/sync/signer/link -- single use, 15 min, stale session
# ===================================================================


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M2T7Pending)
def test_link_route_consumes_code(signer_server):
    """POST /api/v1/sync/signer/link binds a CLI key to a user."""
    _need("agg_cp.sync.signer", "consume_signer_link")
    srv = signer_server
    sk, pub, kid = _keygen()
    code = f"link-code-{uuid.uuid4().hex[:8]}"
    code_hash = hashlib.sha256(code.encode()).hexdigest()

    with psycopg.connect(_conninfo(srv["owner_url"]), autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [srv["org_id"]])
        _insert_link_code(conn, srv["org_id"], code_hash,
                          user_id="alice", iss="https://idp", sub="alice")

    r = httpx.post(
        f"{srv['base_url']}/api/v1/sync/signer/link",
        json={"code": code, "key_id": kid, "public_key": pub.hex(),
              "iss": "https://idp", "sub": "alice"},
        timeout=10.0,
    )
    assert r.status_code == 200
    assert r.json()["key_id"] == kid


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M2T7Pending)
def test_link_route_single_use(signer_server):
    """POST /link with the same code twice: second returns 409 or 404."""
    _need("agg_cp.sync.signer", "consume_signer_link")
    srv = signer_server
    sk, pub, kid = _keygen()
    code = f"link-code-{uuid.uuid4().hex[:8]}"
    code_hash = hashlib.sha256(code.encode()).hexdigest()

    with psycopg.connect(_conninfo(srv["owner_url"]), autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [srv["org_id"]])
        _insert_link_code(conn, srv["org_id"], code_hash,
                          user_id="alice", iss="https://idp", sub="alice")

    body = {"code": code, "key_id": kid, "public_key": pub.hex(),
            "iss": "https://idp", "sub": "alice"}
    r1 = httpx.post(f"{srv['base_url']}/api/v1/sync/signer/link",
                    json=body, timeout=10.0)
    assert r1.status_code == 200

    sk2, pub2, kid2 = _keygen()
    body2 = {"code": code, "key_id": kid2, "public_key": pub2.hex(),
             "iss": "https://idp", "sub": "alice"}
    r2 = httpx.post(f"{srv['base_url']}/api/v1/sync/signer/link",
                    json=body2, timeout=10.0)
    assert r2.status_code in (404, 409, 410)


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M2T7Pending)
def test_link_route_expired_code(signer_server):
    """POST /link with a code issued >15 min ago: refused."""
    _need("agg_cp.sync.signer", "consume_signer_link")
    srv = signer_server
    sk, pub, kid = _keygen()
    code = f"link-exp-{uuid.uuid4().hex[:8]}"
    code_hash = hashlib.sha256(code.encode()).hexdigest()

    with psycopg.connect(_conninfo(srv["owner_url"]), autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [srv["org_id"]])
        _insert_link_code(conn, srv["org_id"], code_hash,
                          user_id="alice", iss="https://idp", sub="alice",
                          issued_at=time.time() - 20 * 60)

    r = httpx.post(
        f"{srv['base_url']}/api/v1/sync/signer/link",
        json={"code": code, "key_id": kid, "public_key": pub.hex(),
              "iss": "https://idp", "sub": "alice"},
        timeout=10.0,
    )
    assert r.status_code in (400, 403, 410)


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M2T7Pending)
def test_link_route_stale_session_refused(signer_server):
    """POST /link with auth_time >15 min ago is refused (stale session)."""
    _need("agg_cp.sync.signer", "consume_signer_link")
    srv = signer_server
    sk, pub, kid = _keygen()
    code = f"link-stale-{uuid.uuid4().hex[:8]}"
    code_hash = hashlib.sha256(code.encode()).hexdigest()

    with psycopg.connect(_conninfo(srv["owner_url"]), autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [srv["org_id"]])
        _insert_link_code(conn, srv["org_id"], code_hash,
                          user_id="alice", iss="https://idp", sub="alice")

    r = httpx.post(
        f"{srv['base_url']}/api/v1/sync/signer/link",
        json={"code": code, "key_id": kid, "public_key": pub.hex(),
              "iss": "https://idp", "sub": "alice",
              "auth_time": time.time() - 20 * 60},
        timeout=10.0,
    )
    assert r.status_code in (400, 403)


# ===================================================================
# RED: POST /api/v1/sync/signer/token -- nonce replay, 10 min, hash stored
# ===================================================================


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M2T7Pending)
def test_token_route_returns_token(signer_server):
    """POST /token with a valid signer-assert returns a token."""
    _need("agg_cp.sync.signer", "authenticate_signer")
    srv = signer_server
    sk, pub, kid = _keygen()

    # Seed the key into signer_links as confirmed
    with psycopg.connect(_conninfo(srv["owner_url"]), autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [srv["org_id"]])
        conn.execute(
            "INSERT INTO signer_links "
            "(id, org_id, code_hash, user_id, iss, sub, issued_at, "
            " key_id, public_key, consumed_at) "
            "VALUES (%s, %s, %s, %s, %s, %s, now(), %s, %s, now())",
            [str(uuid.uuid4()), srv["org_id"], "seed-hash-" + kid[:8],
             "alice", "https://idp", "alice", kid, pub.hex()],
        )

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
    assert len(body["token"]) >= 32  # 256-bit opaque token


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M2T7Pending)
def test_token_stored_as_hash_in_db(signer_server):
    """The signer_tokens row stores only the SHA-256 hash, never the raw token."""
    _need("agg_cp.sync.signer", "authenticate_signer")
    srv = signer_server
    sk, pub, kid = _keygen()

    with psycopg.connect(_conninfo(srv["owner_url"]), autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [srv["org_id"]])
        conn.execute(
            "INSERT INTO signer_links "
            "(id, org_id, code_hash, user_id, iss, sub, issued_at, "
            " key_id, public_key, consumed_at) "
            "VALUES (%s, %s, %s, %s, %s, %s, now(), %s, %s, now())",
            [str(uuid.uuid4()), srv["org_id"], "hash-store-" + kid[:8],
             "alice", "https://idp", "alice", kid, pub.hex()],
        )

    assertion = _sign_assertion(sk, kid, nonce=f"n-{uuid.uuid4().hex[:8]}",
                                aud=srv["base_url"])
    r = httpx.post(f"{srv['base_url']}/api/v1/sync/signer/token",
                   json=assertion, timeout=10.0)
    assert r.status_code == 200
    raw_token = r.json()["token"]

    # Check DB row
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
@pytest.mark.xfail(strict=True, raises=M2T7Pending)
def test_signer_nonce_replay_across_workers(signer_server):
    """A replayed (key_id, nonce) is refused across 4 workers (D10.6)."""
    _need("agg_cp.sync.signer", "authenticate_signer")
    srv = signer_server
    sk, pub, kid = _keygen()

    with psycopg.connect(_conninfo(srv["owner_url"]), autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [srv["org_id"]])
        conn.execute(
            "INSERT INTO signer_links "
            "(id, org_id, code_hash, user_id, iss, sub, issued_at, "
            " key_id, public_key, consumed_at) "
            "VALUES (%s, %s, %s, %s, %s, %s, now(), %s, %s, now())",
            [str(uuid.uuid4()), srv["org_id"], "nonce-replay-" + kid[:8],
             "alice", "https://idp", "alice", kid, pub.hex()],
        )

    fixed_nonce = f"replay-{uuid.uuid4().hex[:8]}"
    assertion = _sign_assertion(sk, kid, nonce=fixed_nonce, aud=srv["base_url"])

    # First request: accepted
    r1 = httpx.post(f"{srv['base_url']}/api/v1/sync/signer/token",
                    json=assertion, timeout=10.0)
    assert r1.status_code == 200

    # Replay across all 4 workers: all must refuse
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
@pytest.mark.xfail(strict=True, raises=M2T7Pending)
def test_idor_pending_other_org_404(signer_server):
    """GET /pending with a token scoped to org-evil returns 404 for org data."""
    _need("agg_cp.sync.signer", "signer_pending")
    srv = signer_server
    sk, pub, kid = _keygen()

    # Seed key in evil org
    with psycopg.connect(_conninfo(srv["owner_url"]), autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [srv["org_evil"]])
        conn.execute(
            "INSERT INTO signer_links "
            "(id, org_id, code_hash, user_id, iss, sub, issued_at, "
            " key_id, public_key, consumed_at) "
            "VALUES (%s, %s, %s, %s, %s, %s, now(), %s, %s, now())",
            [str(uuid.uuid4()), srv["org_evil"], "idor-pend-" + kid[:8],
             "eve", "https://idp", "eve", kid, pub.hex()],
        )

    # Get a token for the evil org
    assertion = _sign_assertion(sk, kid, nonce=f"n-{uuid.uuid4().hex[:8]}",
                                aud=srv["base_url"])
    r = httpx.post(f"{srv['base_url']}/api/v1/sync/signer/token",
                   json=assertion, timeout=10.0)
    assert r.status_code == 200
    token = r.json()["token"]

    # Try to read the good org's pending items
    r2 = httpx.get(
        f"{srv['base_url']}/api/v1/sync/signer/pending",
        headers={"Authorization": f"Bearer {token}"},
        params={"org_id": srv["org_id"]},
        timeout=10.0,
    )
    # Must get 404 or empty (no cross-org access)
    assert r2.status_code in (403, 404) or r2.json() == []


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M2T7Pending)
def test_idor_signatures_other_org_404(signer_server):
    """POST /signatures with a token scoped to org-evil for org data: refused."""
    _need("agg_cp.sync.signer", "store_signer_signatures")
    srv = signer_server
    sk, pub, kid = _keygen()

    with psycopg.connect(_conninfo(srv["owner_url"]), autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [srv["org_evil"]])
        conn.execute(
            "INSERT INTO signer_links "
            "(id, org_id, code_hash, user_id, iss, sub, issued_at, "
            " key_id, public_key, consumed_at) "
            "VALUES (%s, %s, %s, %s, %s, %s, now(), %s, %s, now())",
            [str(uuid.uuid4()), srv["org_evil"], "idor-sig-" + kid[:8],
             "eve", "https://idp", "eve", kid, pub.hex()],
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
        json={"org_id": srv["org_id"], "signatures": []},
        timeout=10.0,
    )
    assert r2.status_code in (403, 404)


# ===================================================================
# RED: F5 -- pending-link token restricted to link completion
# ===================================================================


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M2T7Pending)
def test_pending_link_token_blocked_on_pending(signer_server):
    """A pending-link token gets 403 on GET /pending (F5)."""
    _need("agg_cp.sync.signer", "authenticate_signer")
    srv = signer_server
    sk, pub, kid = _keygen()

    # Seed an unconsumed (pending) link
    code = f"f5-pend-{uuid.uuid4().hex[:8]}"
    code_hash = hashlib.sha256(code.encode()).hexdigest()
    with psycopg.connect(_conninfo(srv["owner_url"]), autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [srv["org_id"]])
        conn.execute(
            "INSERT INTO signer_links "
            "(id, org_id, code_hash, user_id, iss, sub, issued_at, "
            " key_id, public_key) "
            "VALUES (%s, %s, %s, %s, %s, %s, now(), %s, %s)",
            [str(uuid.uuid4()), srv["org_id"], code_hash,
             "alice", "https://idp", "alice", kid, pub.hex()],
        )

    # Get a token for this pending key
    assertion = _sign_assertion(sk, kid, nonce=f"n-{uuid.uuid4().hex[:8]}",
                                aud=srv["base_url"])
    r = httpx.post(f"{srv['base_url']}/api/v1/sync/signer/token",
                   json=assertion, timeout=10.0)
    assert r.status_code == 200
    token = r.json()["token"]

    # Try pending route: must get 403
    r2 = httpx.get(
        f"{srv['base_url']}/api/v1/sync/signer/pending",
        headers={"Authorization": f"Bearer {token}"},
        timeout=10.0,
    )
    assert r2.status_code in (403, 404)


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M2T7Pending)
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
            "(id, org_id, code_hash, user_id, iss, sub, issued_at, "
            " key_id, public_key) "
            "VALUES (%s, %s, %s, %s, %s, %s, now(), %s, %s)",
            [str(uuid.uuid4()), srv["org_id"], code_hash,
             "alice", "https://idp", "alice", kid, pub.hex()],
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
@pytest.mark.xfail(strict=True, raises=M2T7Pending)
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
        _insert_link_code(conn, srv["org_id"], code_hash,
                          user_id="alice", iss="https://idp", sub="alice")
        # Also seed the pending key row (pre-link)
        conn.execute(
            "INSERT INTO signer_links "
            "(id, org_id, code_hash, user_id, iss, sub, issued_at, "
            " key_id, public_key) "
            "VALUES (%s, %s, %s, %s, %s, %s, now(), %s, %s)",
            [str(uuid.uuid4()), srv["org_id"], "f5-pre-" + kid[:8],
             "alice", "https://idp", "alice", kid, pub.hex()],
        )

    assertion = _sign_assertion(sk, kid, nonce=f"n-{uuid.uuid4().hex[:8]}",
                                aud=srv["base_url"])
    r = httpx.post(f"{srv['base_url']}/api/v1/sync/signer/token",
                   json=assertion, timeout=10.0)
    assert r.status_code == 200
    token = r.json()["token"]

    # Use the pending token to complete the link
    r2 = httpx.post(
        f"{srv['base_url']}/api/v1/sync/signer/link",
        headers={"Authorization": f"Bearer {token}"},
        json={"code": code, "key_id": kid, "public_key": pub.hex(),
              "iss": "https://idp", "sub": "alice"},
        timeout=10.0,
    )
    assert r2.status_code == 200


# ===================================================================
# RED: second genesis refused through the route
# ===================================================================


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M2T7Pending)
def test_second_genesis_refused_via_route(signer_server):
    """POST /signatures with a second v1 genesis is refused (threat 22)."""
    _need("agg_cp.sync.signer", "store_signer_signatures")
    srv = signer_server
    sk, pub, kid = _keygen()

    # Seed a confirmed key
    with psycopg.connect(_conninfo(srv["owner_url"]), autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [srv["org_id"]])
        conn.execute(
            "INSERT INTO signer_links "
            "(id, org_id, code_hash, user_id, iss, sub, issued_at, "
            " key_id, public_key, consumed_at) "
            "VALUES (%s, %s, %s, %s, %s, %s, now(), %s, %s, now())",
            [str(uuid.uuid4()), srv["org_id"], "genesis-" + kid[:8],
             "alice", "https://idp", "alice", kid, pub.hex()],
        )

    # Get a token
    assertion = _sign_assertion(sk, kid, nonce=f"n-{uuid.uuid4().hex[:8]}",
                                aud=srv["base_url"])
    r = httpx.post(f"{srv['base_url']}/api/v1/sync/signer/token",
                   json=assertion, timeout=10.0)
    assert r.status_code == 200
    token = r.json()["token"]

    # Build genesis v1
    bsk, bpub, bkid = _keygen()
    from sandbox.connector.sync.signer import build_genesis
    env, fp = build_genesis(
        admin_sk=sk, org_id=srv["org_id"],
        iss="https://idp", sub="alice",
        bundle_signer_pub=bpub,
    )

    headers = {"Authorization": f"Bearer {token}"}

    # First genesis: ok
    r1 = httpx.post(
        f"{srv['base_url']}/api/v1/sync/signer/signatures",
        headers=headers,
        json={"type": "registry", "envelope": env},
        timeout=10.0,
    )
    assert r1.status_code == 200

    # Second genesis: refused
    r2 = httpx.post(
        f"{srv['base_url']}/api/v1/sync/signer/signatures",
        headers=headers,
        json={"type": "registry", "envelope": env},
        timeout=10.0,
    )
    assert r2.status_code in (409, 400)


# ===================================================================
# RED: key live only after quorum-signed registry includes it
# ===================================================================


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M2T7Pending)
def test_key_not_live_until_in_registry(signer_server):
    """A linked key that is not yet in a quorum-signed registry cannot
    sign registry versions or policy changes (only link completion).
    The server should refuse signature submissions from such a key
    for anything other than the link route.
    """
    _need("agg_cp.sync.signer", "authenticate_signer")
    srv = signer_server
    sk, pub, kid = _keygen()

    # Seed as pending (no consumed_at)
    code = f"quorum-{uuid.uuid4().hex[:8]}"
    code_hash = hashlib.sha256(code.encode()).hexdigest()
    with psycopg.connect(_conninfo(srv["owner_url"]), autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [srv["org_id"]])
        conn.execute(
            "INSERT INTO signer_links "
            "(id, org_id, code_hash, user_id, iss, sub, issued_at, "
            " key_id, public_key) "
            "VALUES (%s, %s, %s, %s, %s, %s, now(), %s, %s)",
            [str(uuid.uuid4()), srv["org_id"], code_hash,
             "bob", "https://idp", "bob", kid, pub.hex()],
        )

    assertion = _sign_assertion(sk, kid, nonce=f"n-{uuid.uuid4().hex[:8]}",
                                aud=srv["base_url"])
    r = httpx.post(f"{srv['base_url']}/api/v1/sync/signer/token",
                   json=assertion, timeout=10.0)
    assert r.status_code == 200
    token = r.json()["token"]

    # Try to post a signature (not link): must be blocked
    r2 = httpx.post(
        f"{srv['base_url']}/api/v1/sync/signer/signatures",
        headers={"Authorization": f"Bearer {token}"},
        json={"signatures": []},
        timeout=10.0,
    )
    assert r2.status_code in (403, 404)
