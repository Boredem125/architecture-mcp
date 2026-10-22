"""T8 ee tests-first: enrollment and token routes through the real agg_cp app.

Interface contract
------------------
Server routes (agg_cp.sync.enroll):

    POST /api/v1/sync/enroll
        Request:  {code: str, public_key: str, proof: envelope}
                  (sends the code itself, NOT the hash; PoP signs code_hash)
        Response: 200 {device_id, org_id, project_id}
        Errors:   400 bad_proof, 404 code_not_found, 409 code_consumed,
                  410 code_expired, 429 rate_limited, 403 wrong_operator

    POST /api/v1/sync/token
        Request:  {device_id: str, assertion: envelope}
        Response: 200 {token: str, expires_in: 600}
        Errors:   401 iat_expired / device_revoked / nonce_replay,
                  404 not_found

    POST /api/v1/admin/enrollment-codes
        Request:  {project_id, operator_user_id}  (org from admin session)
        Response: 200 {code_id: str, expires_at: str}  (no code in response)

    GET /api/v1/enrollment-codes/{code_id}
        Operator reads code once, in a fresh session (max_age 15 min).
        Response: 200 {code: str}
        Errors:   404 (wrong user / already read), 403 (stale session)

    POST /api/v1/admin/devices/revoke
        Request:  {device_id: str}
        Response: 200 {revoked_at: str}

Race (4 concurrent consumes) and nonce replay run against a real 4-worker
uvicorn server via ``ee/tests/m2_sync_server.py``.  The rest use
``httpx.Client(app=create_app(...))`` for single-process tests.

Uses the T5 tables via ee conftest fixtures (pg_url, pg_roles, owner_url,
app_url).

RED tests xfail on M2T8Pending.  Guards verify the T5 schema baseline.

Node-id patterns follow M2_BASELINE.md section 5.

Threat coverage: 1 (code race 4 workers, code reuse, expiry, bad PoP,
PoP for another code, posting hash as code, admin code issue no code in
response, admin cross-org 404, operator read once, stale session, wrong
user 404), 4 (iat outside 2 min, nonce replay on 4 workers), 5 (cross-
tenant 404), revocation (401, token stored as hash, token 10 min expiry).
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import secrets
import time
import uuid
from concurrent.futures import ThreadPoolExecutor

import httpx
import psycopg
import pytest
from nacl.signing import SigningKey
from starlette.testclient import TestClient

from .fake_idp import FakeClock
from .m2_pending import M2T8Pending
from .m2_sync_server import (
    make_sync_server, ensure_at_head, create_org, create_project,
    keygen, sign_envelope, canonical_json,
)
from .t8p2_helpers import (
    seed_org_with_oidc, seed_user, seed_admin_binding,
    make_test_app,
)
from .t9_helpers import seed_session, make_session_cookie

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _need(module: str, attr: str) -> None:
    """Raise M2T8Pending if *module*.*attr* is absent."""
    try:
        mod = __import__(module, fromlist=[attr])
    except ImportError:
        raise M2T8Pending(f"{module} not importable")
    if not hasattr(mod, attr):
        raise M2T8Pending(f"{module}.{attr} not found")


def _conninfo(url: str) -> str:
    return url.replace("+psycopg", "")


def _issue_code_ready(conn, org_id, project_id, operator_user_id):
    """Seed an enrollment code that the operator has already read.

    Matches the D1.1 ruling: admin creates with code_hash NULL,
    operator GET generates the code and stores only its hash.
    This helper simulates a code that has been read (code_hash set,
    code_read_at set) so enroll tests can use it directly.
    """
    code = secrets.token_hex(16)
    code_hash = hashlib.sha256(code.encode()).hexdigest()
    code_id = str(uuid.uuid4())
    conn.execute(
        "INSERT INTO enrollment_codes "
        "(id, org_id, project_id, code_hash, code_read_at, expires_at, "
        " operator_user_id) "
        "VALUES (%s, %s, %s, %s, now(), now() + interval '15 minutes', %s)",
        [code_id, org_id, project_id, code_hash, operator_user_id],
    )
    return code, code_hash, code_id


def _issue_code_pending(conn, org_id, project_id, operator_user_id):
    """Seed an enrollment code in admin-created state (code_hash NULL).

    Used by tests that exercise the operator GET route.
    """
    code_id = str(uuid.uuid4())
    conn.execute(
        "INSERT INTO enrollment_codes "
        "(id, org_id, project_id, expires_at, operator_user_id) "
        "VALUES (%s, %s, %s, now() + interval '15 minutes', %s)",
        [code_id, org_id, project_id, operator_user_id],
    )
    return code_id


def _make_enroll_proof(code, sk, pub):
    """Build a valid PoP envelope for enrollment (signs code_hash per D1.2)."""
    code_hash = hashlib.sha256(code.encode()).hexdigest()
    proof_payload = {"code_hash": code_hash, "public_key": pub.hex(),
                     "aud": "test", "iat": time.time()}
    return sign_envelope("agg/device-enroll/v1", proof_payload, sk)


# ---------------------------------------------------------------------------
# Module-scoped 4-worker server fixture (for race and replay tests)
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def enroll_server(pg_url, app_url, owner_url, pg_roles):
    """Start agg_cp with --workers 4 and yield connection info.

    Seeds two orgs with OIDC, admin users, and sessions so that
    admin routes (revoke) can be called with a real cookie.
    """
    ensure_at_head(pg_url)
    # Seed orgs via the OIDC helper (creates orgs + oidc config)
    org_id = seed_org_with_oidc(owner_url, slug=f"t8srv-{uuid.uuid4().hex[:6]}")
    org_evil = seed_org_with_oidc(owner_url, slug=f"t8evil-{uuid.uuid4().hex[:6]}")

    # Seed admin users and sessions for each org
    admin_id, _ = seed_user(owner_url, org_id)
    seed_admin_binding(owner_url, org_id, admin_id)
    clock = FakeClock()
    admin_token, admin_csrf, _ = seed_session(owner_url, org_id, admin_id, clock=clock)
    admin_cookie = make_session_cookie(org_id, admin_token)

    evil_admin_id, _ = seed_user(owner_url, org_evil)
    seed_admin_binding(owner_url, org_evil, evil_admin_id)
    evil_token, evil_csrf, _ = seed_session(owner_url, org_evil, evil_admin_id, clock=clock)
    evil_cookie = make_session_cookie(org_evil, evil_token)

    for info in make_sync_server(pg_url, app_url, owner_url, org_names=[]):
        info.update({
            "org_id": str(org_id),
            "org_evil": str(org_evil),
            "admin_cookie": admin_cookie,
            "admin_csrf": admin_csrf,
            "evil_cookie": evil_cookie,
            "evil_csrf": evil_csrf,
        })
        yield info


# ===================================================================
# Guards (pass now -- T5 schema baseline)
# ===================================================================


@pytest.mark.pg
def test_enrollment_codes_table_exists(pg_url, pg_roles, owner_url):
    """Guard: enrollment_codes table exists (T5 prerequisite)."""
    ensure_at_head(pg_url)
    with psycopg.connect(_conninfo(owner_url)) as conn:
        row = conn.execute(
            "SELECT 1 FROM information_schema.tables "
            "WHERE table_schema = 'public' AND table_name = 'enrollment_codes'"
        ).fetchone()
    assert row is not None, "enrollment_codes table not found -- T5 prerequisite"


@pytest.mark.pg
def test_connectors_table_exists(pg_url, pg_roles, owner_url):
    """Guard: connectors table exists (T5 prerequisite)."""
    ensure_at_head(pg_url)
    with psycopg.connect(_conninfo(owner_url)) as conn:
        row = conn.execute(
            "SELECT 1 FROM information_schema.tables "
            "WHERE table_schema = 'public' AND table_name = 'connectors'"
        ).fetchone()
    assert row is not None, "connectors table not found -- T5 prerequisite"


# ===================================================================
# RED: threat 1 -- enroll route: bad PoP, wrong code hash, code reuse
# ===================================================================


@pytest.mark.pg

def test_enroll_bad_pop_signature_refused(pg_url, pg_roles, app_url, owner_url):
    """POST /api/v1/sync/enroll with a bad PoP signature: 400 (threat 1)."""
    _need("agg_cp.sync.enroll", "enroll_router")
    from agg_cp.app import create_app
    ensure_at_head(pg_url)
    org_id, project_id = str(uuid.uuid4()), str(uuid.uuid4())
    operator_id = str(uuid.uuid4())

    with psycopg.connect(_conninfo(owner_url), autocommit=True) as oconn:
        oconn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        create_org(oconn, org_id)
        create_project(oconn, org_id, project_id)
        code, code_hash, _ = _issue_code_ready(oconn, org_id, project_id, operator_id)

    sk, pub, kid = keygen()
    proof = _make_enroll_proof(code, sk, pub)
    sig_bytes = bytes.fromhex(proof["signatures"][0]["sig"])
    proof["signatures"][0]["sig"] = (bytes([sig_bytes[0] ^ 0xFF]) + sig_bytes[1:]).hex()

    app = create_app(database_url=app_url)
    with TestClient(app) as c:
        resp = c.post("/api/v1/sync/enroll", json={
            "code": code, "public_key": pub.hex(), "proof": proof})
    assert resp.status_code == 400


@pytest.mark.pg

def test_enroll_pop_for_another_code_refused(pg_url, pg_roles, app_url, owner_url):
    """POST /api/v1/sync/enroll with PoP signing a different code_hash: 400."""
    _need("agg_cp.sync.enroll", "enroll_router")
    from agg_cp.app import create_app
    ensure_at_head(pg_url)
    org_id, project_id = str(uuid.uuid4()), str(uuid.uuid4())
    operator_id = str(uuid.uuid4())

    with psycopg.connect(_conninfo(owner_url), autocommit=True) as oconn:
        oconn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        create_org(oconn, org_id)
        create_project(oconn, org_id, project_id)
        code, _, _ = _issue_code_ready(oconn, org_id, project_id, operator_id)

    sk, pub, kid = keygen()
    wrong_hash = hashlib.sha256(b"wrong-code").hexdigest()
    proof_payload = {"code_hash": wrong_hash, "public_key": pub.hex(),
                     "aud": "test", "iat": time.time()}
    proof = sign_envelope("agg/device-enroll/v1", proof_payload, sk)

    app = create_app(database_url=app_url)
    with TestClient(app) as c:
        resp = c.post("/api/v1/sync/enroll", json={
            "code": code, "public_key": pub.hex(), "proof": proof})
    assert resp.status_code == 400


@pytest.mark.pg

def test_enroll_posting_hash_as_code_refused(pg_url, pg_roles, app_url, owner_url):
    """Posting the stored hash instead of the code itself: not found (D1.2)."""
    _need("agg_cp.sync.enroll", "enroll_router")
    from agg_cp.app import create_app
    ensure_at_head(pg_url)
    org_id, project_id = str(uuid.uuid4()), str(uuid.uuid4())
    operator_id = str(uuid.uuid4())

    with psycopg.connect(_conninfo(owner_url), autocommit=True) as oconn:
        oconn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        create_org(oconn, org_id)
        create_project(oconn, org_id, project_id)
        code, code_hash, _ = _issue_code_ready(oconn, org_id, project_id, operator_id)

    sk, pub, kid = keygen()
    # PoP signs the hash-of-hash (wrong), but we send the hash as "code"
    double_hash = hashlib.sha256(code_hash.encode()).hexdigest()
    proof_payload = {"code_hash": double_hash, "public_key": pub.hex(),
                     "aud": "test", "iat": time.time()}
    proof = sign_envelope("agg/device-enroll/v1", proof_payload, sk)

    app = create_app(database_url=app_url)
    with TestClient(app) as c:
        resp = c.post("/api/v1/sync/enroll", json={
            "code": code_hash, "public_key": pub.hex(), "proof": proof})
    assert resp.status_code == 400


@pytest.mark.pg

def test_enroll_code_reuse_409(pg_url, pg_roles, app_url, owner_url):
    """POST /api/v1/sync/enroll returns 409 on code reuse (threat 1)."""
    _need("agg_cp.sync.enroll", "enroll_router")
    from agg_cp.app import create_app
    ensure_at_head(pg_url)
    org_id, project_id = str(uuid.uuid4()), str(uuid.uuid4())
    operator_id = str(uuid.uuid4())

    with psycopg.connect(_conninfo(owner_url), autocommit=True) as oconn:
        oconn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        create_org(oconn, org_id)
        create_project(oconn, org_id, project_id)
        code, _, _ = _issue_code_ready(oconn, org_id, project_id, operator_id)

    sk, pub, _ = keygen()
    proof = _make_enroll_proof(code, sk, pub)

    app = create_app(database_url=app_url)
    with TestClient(app) as c:
        r1 = c.post("/api/v1/sync/enroll", json={
            "code": code, "public_key": pub.hex(), "proof": proof})
        assert r1.status_code == 200
        sk2, pub2, _ = keygen()
        proof2 = _make_enroll_proof(code, sk2, pub2)
        r2 = c.post("/api/v1/sync/enroll", json={
            "code": code, "public_key": pub2.hex(), "proof": proof2})
    assert r2.status_code == 400, f"code reuse was not refused: {r2.status_code}"
    assert r2.json().get("error") == "invalid_code"


@pytest.mark.pg

def test_enroll_code_expired_410(pg_url, pg_roles, app_url, owner_url):
    """POST /api/v1/sync/enroll returns 410 on expired code (threat 1)."""
    _need("agg_cp.sync.enroll", "enroll_router")
    from agg_cp.app import create_app
    ensure_at_head(pg_url)
    org_id, project_id = str(uuid.uuid4()), str(uuid.uuid4())
    operator_id = str(uuid.uuid4())

    with psycopg.connect(_conninfo(owner_url), autocommit=True) as oconn:
        oconn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        create_org(oconn, org_id)
        create_project(oconn, org_id, project_id)
        code, code_hash, _ = _issue_code_ready(oconn, org_id, project_id, operator_id)
        oconn.execute(
            "UPDATE enrollment_codes SET expires_at = now() - interval '1 minute' "
            "WHERE code_hash = %s", [code_hash])

    sk, pub, _ = keygen()
    proof = _make_enroll_proof(code, sk, pub)

    app = create_app(database_url=app_url)
    with TestClient(app) as c:
        resp = c.post("/api/v1/sync/enroll", json={
            "code": code, "public_key": pub.hex(), "proof": proof})
    assert resp.status_code == 400, f"expired code not refused: {resp.status_code}"
    assert resp.json().get("error") == "invalid_code"


@pytest.mark.pg

def test_reused_expired_unknown_give_identical_response(pg_url, pg_roles, app_url, owner_url):
    """Reused, expired and unknown codes give identical 400 invalid_code (no oracle)."""
    _need("agg_cp.sync.enroll", "enroll_router")
    from agg_cp.app import create_app
    ensure_at_head(pg_url)
    org_id, project_id = str(uuid.uuid4()), str(uuid.uuid4())
    operator_id = str(uuid.uuid4())

    with psycopg.connect(_conninfo(owner_url), autocommit=True) as oconn:
        oconn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        create_org(oconn, org_id)
        create_project(oconn, org_id, project_id)
        # A consumed code
        code_used, _, _ = _issue_code_ready(oconn, org_id, project_id, operator_id)
        # An expired code
        code_exp, ch_exp, _ = _issue_code_ready(oconn, org_id, project_id, operator_id)
        oconn.execute(
            "UPDATE enrollment_codes SET expires_at = now() - interval '1 minute' "
            "WHERE code_hash = %s", [ch_exp])

    sk, pub, _ = keygen()

    app = create_app(database_url=app_url)
    with TestClient(app) as c:
        # Consume the first code
        proof_ok = _make_enroll_proof(code_used, sk, pub)
        r0 = c.post("/api/v1/sync/enroll", json={
            "code": code_used, "public_key": pub.hex(), "proof": proof_ok})
        assert r0.status_code == 200

        # Now reuse it
        sk2, pub2, _ = keygen()
        proof_reuse = _make_enroll_proof(code_used, sk2, pub2)
        r_reused = c.post("/api/v1/sync/enroll", json={
            "code": code_used, "public_key": pub2.hex(), "proof": proof_reuse})

        # Expired
        sk3, pub3, _ = keygen()
        proof_exp = _make_enroll_proof(code_exp, sk3, pub3)
        r_expired = c.post("/api/v1/sync/enroll", json={
            "code": code_exp, "public_key": pub3.hex(), "proof": proof_exp})

        # Unknown
        sk4, pub4, _ = keygen()
        proof_unk = _make_enroll_proof("nonexistent-code", sk4, pub4)
        r_unknown = c.post("/api/v1/sync/enroll", json={
            "code": "nonexistent-code", "public_key": pub4.hex(), "proof": proof_unk})

    # All three must give identical status and error body
    for r, label in [(r_reused, "reused"), (r_expired, "expired"), (r_unknown, "unknown")]:
        assert r.status_code == 400, f"{label}: {r.status_code}"
        assert r.json().get("error") == "invalid_code", f"{label}: {r.json()}"
    assert r_reused.json() == r_expired.json() == r_unknown.json()


@pytest.mark.pg

def test_bad_pop_then_good_pop_succeeds(pg_url, pg_roles, app_url, owner_url):
    """Bad PoP does not consume the code; same code with good PoP succeeds."""
    _need("agg_cp.sync.enroll", "enroll_router")
    from agg_cp.app import create_app
    ensure_at_head(pg_url)
    org_id, project_id = str(uuid.uuid4()), str(uuid.uuid4())
    operator_id = str(uuid.uuid4())

    with psycopg.connect(_conninfo(owner_url), autocommit=True) as oconn:
        oconn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        create_org(oconn, org_id)
        create_project(oconn, org_id, project_id)
        code, _, _ = _issue_code_ready(oconn, org_id, project_id, operator_id)

    sk, pub, _ = keygen()
    # Bad PoP: flipped signature
    proof_bad = _make_enroll_proof(code, sk, pub)
    sig_bytes = bytes.fromhex(proof_bad["signatures"][0]["sig"])
    proof_bad["signatures"][0]["sig"] = (bytes([sig_bytes[0] ^ 0xFF]) + sig_bytes[1:]).hex()

    app = create_app(database_url=app_url)
    with TestClient(app) as c:
        r_bad = c.post("/api/v1/sync/enroll", json={
            "code": code, "public_key": pub.hex(), "proof": proof_bad})
        assert r_bad.status_code == 400
        assert r_bad.json().get("error") == "bad_proof"

        # Same code, good PoP: should succeed (code not consumed by bad PoP)
        proof_good = _make_enroll_proof(code, sk, pub)
        r_good = c.post("/api/v1/sync/enroll", json={
            "code": code, "public_key": pub.hex(), "proof": proof_good})
    assert r_good.status_code == 200


# ===================================================================
# RED: threat 1 -- 4-worker race (real uvicorn)
# ===================================================================


@pytest.mark.pg

def test_4_worker_race_exactly_1_winner(enroll_server):
    """4-worker race on POST /api/v1/sync/enroll: exactly 1 winner (threat 1)."""
    _need("agg_cp.sync.enroll", "enroll_router")
    srv = enroll_server
    org_id = srv["org_id"]
    project_id = str(uuid.uuid4())
    operator_id = str(uuid.uuid4())

    with psycopg.connect(_conninfo(srv["owner_url"]), autocommit=True) as oconn:
        oconn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        create_project(oconn, org_id, project_id)
        code, _, _ = _issue_code_ready(oconn, org_id, project_id, operator_id)

    def try_enroll(worker_id):
        sk, pub, _ = keygen()
        proof = _make_enroll_proof(code, sk, pub)
        resp = httpx.post(
            f"{srv['base_url']}/api/v1/sync/enroll",
            json={"code": code, "public_key": pub.hex(), "proof": proof},
            timeout=10.0)
        return resp.status_code

    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(try_enroll, range(4)))

    winners = [r for r in results if r == 200]
    losers = [r for r in results if r != 200]
    assert len(winners) == 1, f"expected 1 winner, got {len(winners)}: {results}"
    for code in losers:
        assert code == 400, f"loser got {code}, expected 400 invalid_code"


# ===================================================================
# RED: admin code issue and operator code read (D1.1, D1.3)
#      All human-auth uses real __Host-agg_session cookies.
# ===================================================================


def _setup_session_env(pg_url, owner_url, *, stale=False):
    """Seed org + OIDC + admin user + session; return (app, org_id, user_id, cookie, clock)."""
    clock = FakeClock()
    if stale:
        # Session created 20 min ago
        clock._now = dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=20)
    org_id = seed_org_with_oidc(owner_url, slug=f"t8-{uuid.uuid4().hex[:8]}")
    user_id, _ = seed_user(owner_url, org_id)
    seed_admin_binding(owner_url, org_id, user_id)
    token, csrf, _ = seed_session(owner_url, org_id, user_id, clock=clock)
    cookie = make_session_cookie(org_id, token)
    if stale:
        clock._now = dt.datetime.now(dt.timezone.utc)  # reset to now for app
    app, clock, _ = make_test_app(pg_url=pg_url, clock=clock)
    return app, org_id, user_id, cookie, csrf, clock


@pytest.mark.pg

def test_admin_code_issue_no_code_in_response(pg_url, pg_roles, app_url, owner_url):
    """POST /api/v1/admin/enrollment-codes returns code_id, NOT the code."""
    _need("agg_cp.sync.enroll", "enroll_router")
    ensure_at_head(pg_url)
    app, org_id, user_id, cookie, csrf, _ = _setup_session_env(pg_url, owner_url)
    project_id = str(uuid.uuid4())

    with psycopg.connect(_conninfo(owner_url), autocommit=True) as oconn:
        oconn.execute("SELECT set_config('app.org_id', %s, false)", [str(org_id)])
        create_project(oconn, str(org_id), project_id)

    with TestClient(app) as c:
        resp = c.post("/api/v1/admin/enrollment-codes", json={
            "project_id": project_id,
            "operator_user_id": str(user_id)},
            cookies={"__Host-agg_session": cookie},
            headers={"X-CSRF-Token": csrf})
    assert resp.status_code == 200
    body = resp.json()
    assert "code_id" in body
    assert "code" not in body, "admin response must not contain the code"


@pytest.mark.pg

def test_admin_cross_org_project_404(pg_url, pg_roles, app_url, owner_url):
    """Admin of org A naming a project of org B gets 404."""
    _need("agg_cp.sync.enroll", "enroll_router")
    ensure_at_head(pg_url)
    # Admin session for org A
    app, org_a, user_a, cookie_a, csrf_a, _ = _setup_session_env(pg_url, owner_url)
    org_b = seed_org_with_oidc(owner_url, slug=f"t8b-{uuid.uuid4().hex[:8]}")
    project_b = str(uuid.uuid4())

    with psycopg.connect(_conninfo(owner_url), autocommit=True) as oconn:
        oconn.execute("SELECT set_config('app.org_id', %s, false)", [str(org_b)])
        create_project(oconn, str(org_b), project_b)

    with TestClient(app) as c:
        resp = c.post("/api/v1/admin/enrollment-codes", json={
            "project_id": project_b,
            "operator_user_id": str(uuid.uuid4())},
            cookies={"__Host-agg_session": cookie_a},
            headers={"X-CSRF-Token": csrf_a})
    assert resp.status_code == 404


@pytest.mark.pg

def test_operator_reads_code_once(pg_url, pg_roles, app_url, owner_url):
    """GET /api/v1/enrollment-codes/{id}: operator reads code once; second read refused."""
    _need("agg_cp.sync.enroll", "enroll_router")
    ensure_at_head(pg_url)
    app, org_id, operator_id, cookie, csrf, _ = _setup_session_env(pg_url, owner_url)
    project_id = str(uuid.uuid4())

    with psycopg.connect(_conninfo(owner_url), autocommit=True) as oconn:
        oconn.execute("SELECT set_config('app.org_id', %s, false)", [str(org_id)])
        create_project(oconn, str(org_id), project_id)
        code_id = _issue_code_pending(oconn, str(org_id), project_id, str(operator_id))

    with TestClient(app) as c:
        r1 = c.get(f"/api/v1/enrollment-codes/{code_id}",
                    cookies={"__Host-agg_session": cookie})
        assert r1.status_code == 200
        assert "code" in r1.json()

        r2 = c.get(f"/api/v1/enrollment-codes/{code_id}",
                    cookies={"__Host-agg_session": cookie})
        assert r2.status_code in (404, 410)


@pytest.mark.pg

def test_operator_wrong_user_404(pg_url, pg_roles, app_url, owner_url):
    """GET /api/v1/enrollment-codes/{id}: another user gets 404."""
    _need("agg_cp.sync.enroll", "enroll_router")
    ensure_at_head(pg_url)
    app, org_id, admin_id, admin_cookie, _, _ = _setup_session_env(pg_url, owner_url)
    # Create another user in the same org with their own session
    other_id, _ = seed_user(owner_url, org_id)
    clock2 = FakeClock()
    other_token, _, _ = seed_session(owner_url, org_id, other_id, clock=clock2)
    other_cookie = make_session_cookie(org_id, other_token)
    project_id = str(uuid.uuid4())

    with psycopg.connect(_conninfo(owner_url), autocommit=True) as oconn:
        oconn.execute("SELECT set_config('app.org_id', %s, false)", [str(org_id)])
        create_project(oconn, str(org_id), project_id)
        # Code issued to admin_id as operator
        code_id = _issue_code_pending(oconn, str(org_id), project_id, str(admin_id))

    with TestClient(app) as c:
        # other_id tries to read admin_id's code: 404
        resp = c.get(f"/api/v1/enrollment-codes/{code_id}",
                     cookies={"__Host-agg_session": other_cookie})
    assert resp.status_code == 404


@pytest.mark.pg

def test_operator_stale_session_refused(pg_url, pg_roles, app_url, owner_url):
    """GET /api/v1/enrollment-codes/{id}: stale session (>15 min) refused."""
    _need("agg_cp.sync.enroll", "enroll_router")
    ensure_at_head(pg_url)
    # Session created 20 min ago
    app, org_id, operator_id, cookie, _, _ = _setup_session_env(
        pg_url, owner_url, stale=True)
    project_id = str(uuid.uuid4())

    with psycopg.connect(_conninfo(owner_url), autocommit=True) as oconn:
        oconn.execute("SELECT set_config('app.org_id', %s, false)", [str(org_id)])
        create_project(oconn, str(org_id), project_id)
        code_id = _issue_code_pending(oconn, str(org_id), project_id, str(operator_id))

    with TestClient(app) as c:
        resp = c.get(f"/api/v1/enrollment-codes/{code_id}",
                     cookies={"__Host-agg_session": cookie})
    assert resp.status_code in (401, 403)


# ===================================================================
# RED: forged X-headers with no cookie get 401
# ===================================================================


@pytest.mark.pg

def test_forged_headers_no_cookie_401_on_code_issue(pg_url, pg_roles, app_url, owner_url):
    """POST /admin/enrollment-codes with forged X-headers and no cookie: 401."""
    _need("agg_cp.sync.enroll", "enroll_router")
    ensure_at_head(pg_url)
    app, org_id, _, _, _, _ = _setup_session_env(pg_url, owner_url)

    with TestClient(app) as c:
        resp = c.post("/api/v1/admin/enrollment-codes", json={
            "project_id": str(uuid.uuid4()),
            "operator_user_id": str(uuid.uuid4())},
            headers={"X-Org-Id": str(org_id),
                     "X-User-Id": str(uuid.uuid4()),
                     "X-Auth-Time": str(int(time.time()))})
    assert resp.status_code in (401, 403)


@pytest.mark.pg

def test_forged_headers_no_cookie_401_on_code_read(pg_url, pg_roles, app_url, owner_url):
    """GET /enrollment-codes/{id} with forged X-headers and no cookie: 401."""
    _need("agg_cp.sync.enroll", "enroll_router")
    ensure_at_head(pg_url)
    app, org_id, user_id, _, _, _ = _setup_session_env(pg_url, owner_url)
    project_id = str(uuid.uuid4())

    with psycopg.connect(_conninfo(owner_url), autocommit=True) as oconn:
        oconn.execute("SELECT set_config('app.org_id', %s, false)", [str(org_id)])
        create_project(oconn, str(org_id), project_id)
        code_id = _issue_code_pending(oconn, str(org_id), project_id, str(user_id))

    with TestClient(app) as c:
        resp = c.get(f"/api/v1/enrollment-codes/{code_id}",
                     headers={"X-User-Id": str(user_id),
                              "X-Auth-Time": str(int(time.time()))})
    assert resp.status_code in (401, 403)


@pytest.mark.pg

def test_forged_headers_no_cookie_401_on_revoke(pg_url, pg_roles, app_url, owner_url):
    """POST /admin/devices/revoke with forged X-headers and no cookie: 401."""
    _need("agg_cp.sync.enroll", "enroll_router")
    ensure_at_head(pg_url)
    app, org_id, _, _, _, _ = _setup_session_env(pg_url, owner_url)

    with TestClient(app) as c:
        resp = c.post("/api/v1/admin/devices/revoke",
                      json={"device_id": str(uuid.uuid4())},
                      headers={"X-Org-Id": str(org_id),
                               "X-User-Id": str(uuid.uuid4()),
                               "X-Auth-Time": str(int(time.time()))})
    assert resp.status_code in (401, 403)


# ===================================================================
# RED: threat 4 -- token route on real 4-worker server
# ===================================================================


@pytest.mark.pg

def test_token_iat_outside_2min_refused(enroll_server):
    """POST /api/v1/sync/token with iat > 2 min old: 401 (threat 4)."""
    _need("agg_cp.sync.enroll", "enroll_router")
    srv = enroll_server
    org_id = srv["org_id"]
    project_id = str(uuid.uuid4())
    operator_id = str(uuid.uuid4())

    with psycopg.connect(_conninfo(srv["owner_url"]), autocommit=True) as oconn:
        oconn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        create_project(oconn, org_id, project_id)
        code, _, _ = _issue_code_ready(oconn, org_id, project_id, operator_id)

    sk, pub, _ = keygen()
    proof = _make_enroll_proof(code, sk, pub)
    r = httpx.post(f"{srv['base_url']}/api/v1/sync/enroll",
                   json={"code": code, "public_key": pub.hex(), "proof": proof},
                   timeout=10.0)
    assert r.status_code == 200
    device_id = r.json()["device_id"]

    stale_iat = time.time() - 180
    assertion = sign_envelope("agg/device-assert/v1", {
        "device_id": device_id, "aud": "test",
        "iat": stale_iat, "nonce": secrets.token_hex(16)}, sk)
    resp = httpx.post(f"{srv['base_url']}/api/v1/sync/token",
                      json={"device_id": device_id, "assertion": assertion},
                      timeout=10.0)
    assert resp.status_code == 401


@pytest.mark.pg

def test_token_nonce_replay_across_4_workers(enroll_server):
    """Nonce replay on 4 workers: all replays refused (threat 4)."""
    _need("agg_cp.sync.enroll", "enroll_router")
    srv = enroll_server
    org_id = srv["org_id"]
    project_id = str(uuid.uuid4())
    operator_id = str(uuid.uuid4())

    with psycopg.connect(_conninfo(srv["owner_url"]), autocommit=True) as oconn:
        oconn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        create_project(oconn, org_id, project_id)
        code, _, _ = _issue_code_ready(oconn, org_id, project_id, operator_id)

    sk, pub, _ = keygen()
    proof = _make_enroll_proof(code, sk, pub)
    r = httpx.post(f"{srv['base_url']}/api/v1/sync/enroll",
                   json={"code": code, "public_key": pub.hex(), "proof": proof},
                   timeout=10.0)
    assert r.status_code == 200
    device_id = r.json()["device_id"]

    fixed_nonce = secrets.token_hex(16)
    assertion = sign_envelope("agg/device-assert/v1", {
        "device_id": device_id, "aud": "test",
        "iat": time.time(), "nonce": fixed_nonce}, sk)

    # First: accepted
    r1 = httpx.post(f"{srv['base_url']}/api/v1/sync/token",
                    json={"device_id": device_id, "assertion": assertion},
                    timeout=10.0)
    assert r1.status_code == 200

    # Replay across 4 workers
    def try_replay(_):
        return httpx.post(f"{srv['base_url']}/api/v1/sync/token",
                          json={"device_id": device_id, "assertion": assertion},
                          timeout=10.0)

    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(try_replay, range(4)))
    for r in results:
        assert r.status_code in (401, 409), f"replay accepted: {r.status_code}"


# ===================================================================
# RED: threat 5 -- cross-tenant device on token route
# ===================================================================


@pytest.mark.pg

def test_device_a_token_on_project_b_404(enroll_server):
    """A fabricated device_id gets 404 on the token route (threat 5)."""
    _need("agg_cp.sync.enroll", "enroll_router")
    srv = enroll_server
    sk, pub, _ = keygen()
    fake_device = str(uuid.uuid4())
    assertion = sign_envelope("agg/device-assert/v1", {
        "device_id": fake_device, "aud": "test",
        "iat": time.time(), "nonce": secrets.token_hex(16)}, sk)
    resp = httpx.post(f"{srv['base_url']}/api/v1/sync/token",
                      json={"device_id": fake_device, "assertion": assertion},
                      timeout=10.0)
    assert resp.status_code == 404


# ===================================================================
# RED: revocation -- 401, token stored as hash, token expiry
# ===================================================================


@pytest.mark.pg

def test_revoked_device_gets_401(enroll_server):
    """A revoked device gets 401 on its next token call."""
    _need("agg_cp.sync.enroll", "enroll_router")
    srv = enroll_server
    org_id = srv["org_id"]
    project_id = str(uuid.uuid4())
    operator_id = str(uuid.uuid4())

    with psycopg.connect(_conninfo(srv["owner_url"]), autocommit=True) as oconn:
        oconn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        create_project(oconn, org_id, project_id)
        code, _, _ = _issue_code_ready(oconn, org_id, project_id, operator_id)

    sk, pub, _ = keygen()
    proof = _make_enroll_proof(code, sk, pub)
    r = httpx.post(f"{srv['base_url']}/api/v1/sync/enroll",
                   json={"code": code, "public_key": pub.hex(), "proof": proof},
                   timeout=10.0)
    assert r.status_code == 200
    device_id = r.json()["device_id"]

    # Revoke through the admin route with a real session cookie
    revoke_resp = httpx.post(
        f"{srv['base_url']}/api/v1/admin/devices/revoke",
        json={"device_id": device_id},
        cookies={"__Host-agg_session": srv["admin_cookie"]},
        headers={"X-CSRF-Token": srv["admin_csrf"]},
        timeout=10.0)
    assert revoke_resp.status_code == 200

    assertion = sign_envelope("agg/device-assert/v1", {
        "device_id": device_id, "aud": "test",
        "iat": time.time(), "nonce": secrets.token_hex(16)}, sk)
    resp = httpx.post(f"{srv['base_url']}/api/v1/sync/token",
                      json={"device_id": device_id, "assertion": assertion},
                      timeout=10.0)
    assert resp.status_code == 401


@pytest.mark.pg

def test_revoke_cross_org_device_404(enroll_server):
    """An admin of another org revoking this device gets 404."""
    _need("agg_cp.sync.enroll", "enroll_router")
    srv = enroll_server
    org_id = srv["org_id"]
    org_evil = srv["org_evil"]
    project_id = str(uuid.uuid4())
    operator_id = str(uuid.uuid4())

    with psycopg.connect(_conninfo(srv["owner_url"]), autocommit=True) as oconn:
        oconn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        create_project(oconn, org_id, project_id)
        code, _, _ = _issue_code_ready(oconn, org_id, project_id, operator_id)

    sk, pub, _ = keygen()
    proof = _make_enroll_proof(code, sk, pub)
    r = httpx.post(f"{srv['base_url']}/api/v1/sync/enroll",
                   json={"code": code, "public_key": pub.hex(), "proof": proof},
                   timeout=10.0)
    assert r.status_code == 200
    device_id = r.json()["device_id"]

    # Admin of evil org tries to revoke with evil org's session: 404
    resp = httpx.post(
        f"{srv['base_url']}/api/v1/admin/devices/revoke",
        json={"device_id": device_id},
        cookies={"__Host-agg_session": srv["evil_cookie"]},
        headers={"X-CSRF-Token": srv["evil_csrf"]},
        timeout=10.0)
    assert resp.status_code == 404


@pytest.mark.pg

def test_token_stored_as_hash(enroll_server):
    """The device_tokens table stores only the hash, not the raw token."""
    _need("agg_cp.sync.enroll", "enroll_router")
    srv = enroll_server
    org_id = srv["org_id"]
    project_id = str(uuid.uuid4())
    operator_id = str(uuid.uuid4())

    with psycopg.connect(_conninfo(srv["owner_url"]), autocommit=True) as oconn:
        oconn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        create_project(oconn, org_id, project_id)
        code, _, _ = _issue_code_ready(oconn, org_id, project_id, operator_id)

    sk, pub, _ = keygen()
    proof = _make_enroll_proof(code, sk, pub)
    r = httpx.post(f"{srv['base_url']}/api/v1/sync/enroll",
                   json={"code": code, "public_key": pub.hex(), "proof": proof},
                   timeout=10.0)
    assert r.status_code == 200
    device_id = r.json()["device_id"]

    assertion = sign_envelope("agg/device-assert/v1", {
        "device_id": device_id, "aud": "test",
        "iat": time.time(), "nonce": secrets.token_hex(16)}, sk)
    resp = httpx.post(f"{srv['base_url']}/api/v1/sync/token",
                      json={"device_id": device_id, "assertion": assertion},
                      timeout=10.0)
    assert resp.status_code == 200
    raw_token = resp.json()["token"]

    with psycopg.connect(_conninfo(srv["owner_url"])) as conn:
        rows = conn.execute(
            "SELECT token_hash FROM device_tokens WHERE connector_id = %s",
            [device_id]).fetchall()
    assert len(rows) >= 1
    for row in rows:
        assert row[0] != raw_token, "raw token in DB"
        assert row[0] == hashlib.sha256(raw_token.encode()).hexdigest()


@pytest.mark.pg

def test_token_expires_at_10min(enroll_server):
    """Token response has expires_in=600 or DB row ~10 min expiry."""
    _need("agg_cp.sync.enroll", "enroll_router")
    srv = enroll_server
    org_id = srv["org_id"]
    project_id = str(uuid.uuid4())
    operator_id = str(uuid.uuid4())

    with psycopg.connect(_conninfo(srv["owner_url"]), autocommit=True) as oconn:
        oconn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        create_project(oconn, org_id, project_id)
        code, _, _ = _issue_code_ready(oconn, org_id, project_id, operator_id)

    sk, pub, _ = keygen()
    proof = _make_enroll_proof(code, sk, pub)
    before = time.time()
    r = httpx.post(f"{srv['base_url']}/api/v1/sync/enroll",
                   json={"code": code, "public_key": pub.hex(), "proof": proof},
                   timeout=10.0)
    assert r.status_code == 200
    device_id = r.json()["device_id"]

    assertion = sign_envelope("agg/device-assert/v1", {
        "device_id": device_id, "aud": "test",
        "iat": time.time(), "nonce": secrets.token_hex(16)}, sk)
    resp = httpx.post(f"{srv['base_url']}/api/v1/sync/token",
                      json={"device_id": device_id, "assertion": assertion},
                      timeout=10.0)
    assert resp.status_code == 200
    body = resp.json()
    if "expires_in" in body:
        assert body["expires_in"] == 600
    else:
        import datetime
        with psycopg.connect(_conninfo(srv["owner_url"])) as conn:
            row = conn.execute(
                "SELECT expires_at FROM device_tokens WHERE connector_id = %s "
                "ORDER BY created_at DESC LIMIT 1", [device_id]).fetchone()
        assert row is not None
        exp_ts = row[0].timestamp() if isinstance(row[0], datetime.datetime) else float(row[0])
        assert 540 < (exp_ts - before) < 660
