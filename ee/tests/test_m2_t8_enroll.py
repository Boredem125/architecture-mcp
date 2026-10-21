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

from .m2_pending import M2T8Pending
from .m2_sync_server import (
    make_sync_server, ensure_at_head, create_org, create_project,
    keygen, sign_envelope, canonical_json,
)

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


def _issue_code_sql(conn, org_id, project_id, operator_user_id):
    """Issue an enrollment code directly via SQL (admin action)."""
    code = secrets.token_hex(16)
    code_hash = hashlib.sha256(code.encode()).hexdigest()
    code_id = str(uuid.uuid4())
    conn.execute(
        "INSERT INTO enrollment_codes "
        "(id, org_id, project_id, code_hash, expires_at, operator_user_id) "
        "VALUES (%s, %s, %s, %s, now() + interval '15 minutes', %s)",
        [code_id, org_id, project_id, code_hash, operator_user_id],
    )
    return code, code_hash, code_id


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
    """Start agg_cp with --workers 4 and yield connection info."""
    yield from make_sync_server(
        pg_url, app_url, owner_url,
        org_names=["Enroll Org", "Evil Org"],
    )


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
@pytest.mark.xfail(strict=True, raises=M2T8Pending)
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
        code, code_hash, _ = _issue_code_sql(oconn, org_id, project_id, operator_id)

    sk, pub, kid = keygen()
    proof = _make_enroll_proof(code, sk, pub)
    sig_bytes = bytes.fromhex(proof["signatures"][0]["sig"])
    proof["signatures"][0]["sig"] = (bytes([sig_bytes[0] ^ 0xFF]) + sig_bytes[1:]).hex()

    app = create_app(database_url=app_url)
    with httpx.Client(app=app, base_url="http://test") as c:
        resp = c.post("/api/v1/sync/enroll", json={
            "code": code, "public_key": pub.hex(), "proof": proof})
    assert resp.status_code == 400


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M2T8Pending)
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
        code, _, _ = _issue_code_sql(oconn, org_id, project_id, operator_id)

    sk, pub, kid = keygen()
    wrong_hash = hashlib.sha256(b"wrong-code").hexdigest()
    proof_payload = {"code_hash": wrong_hash, "public_key": pub.hex(),
                     "aud": "test", "iat": time.time()}
    proof = sign_envelope("agg/device-enroll/v1", proof_payload, sk)

    app = create_app(database_url=app_url)
    with httpx.Client(app=app, base_url="http://test") as c:
        resp = c.post("/api/v1/sync/enroll", json={
            "code": code, "public_key": pub.hex(), "proof": proof})
    assert resp.status_code == 400


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M2T8Pending)
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
        code, code_hash, _ = _issue_code_sql(oconn, org_id, project_id, operator_id)

    sk, pub, kid = keygen()
    # PoP signs the hash-of-hash (wrong), but we send the hash as "code"
    double_hash = hashlib.sha256(code_hash.encode()).hexdigest()
    proof_payload = {"code_hash": double_hash, "public_key": pub.hex(),
                     "aud": "test", "iat": time.time()}
    proof = sign_envelope("agg/device-enroll/v1", proof_payload, sk)

    app = create_app(database_url=app_url)
    with httpx.Client(app=app, base_url="http://test") as c:
        resp = c.post("/api/v1/sync/enroll", json={
            "code": code_hash, "public_key": pub.hex(), "proof": proof})
    assert resp.status_code in (400, 404)


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M2T8Pending)
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
        code, _, _ = _issue_code_sql(oconn, org_id, project_id, operator_id)

    sk, pub, _ = keygen()
    proof = _make_enroll_proof(code, sk, pub)

    app = create_app(database_url=app_url)
    with httpx.Client(app=app, base_url="http://test") as c:
        r1 = c.post("/api/v1/sync/enroll", json={
            "code": code, "public_key": pub.hex(), "proof": proof})
        assert r1.status_code == 200
        sk2, pub2, _ = keygen()
        proof2 = _make_enroll_proof(code, sk2, pub2)
        r2 = c.post("/api/v1/sync/enroll", json={
            "code": code, "public_key": pub2.hex(), "proof": proof2})
    assert r2.status_code == 409


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M2T8Pending)
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
        code, code_hash, _ = _issue_code_sql(oconn, org_id, project_id, operator_id)
        oconn.execute(
            "UPDATE enrollment_codes SET expires_at = now() - interval '1 minute' "
            "WHERE code_hash = %s", [code_hash])

    sk, pub, _ = keygen()
    proof = _make_enroll_proof(code, sk, pub)

    app = create_app(database_url=app_url)
    with httpx.Client(app=app, base_url="http://test") as c:
        resp = c.post("/api/v1/sync/enroll", json={
            "code": code, "public_key": pub.hex(), "proof": proof})
    assert resp.status_code in (410, 409)


# ===================================================================
# RED: threat 1 -- 4-worker race (real uvicorn)
# ===================================================================


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M2T8Pending)
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
        code, _, _ = _issue_code_sql(oconn, org_id, project_id, operator_id)

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
    assert len(winners) == 1, f"expected 1 winner, got {len(winners)}: {results}"


# ===================================================================
# RED: admin code issue and operator code read (D1.1, D1.3)
# ===================================================================


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M2T8Pending)
def test_admin_code_issue_no_code_in_response(pg_url, pg_roles, app_url, owner_url):
    """POST /api/v1/admin/enrollment-codes returns code_id, NOT the code."""
    _need("agg_cp.sync.enroll", "enroll_router")
    from agg_cp.app import create_app
    ensure_at_head(pg_url)
    org_id, project_id = str(uuid.uuid4()), str(uuid.uuid4())
    operator_id = str(uuid.uuid4())

    with psycopg.connect(_conninfo(owner_url), autocommit=True) as oconn:
        oconn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        create_org(oconn, org_id)
        create_project(oconn, org_id, project_id)

    app = create_app(database_url=app_url)
    with httpx.Client(app=app, base_url="http://test") as c:
        resp = c.post("/api/v1/admin/enrollment-codes", json={
            "project_id": project_id, "operator_user_id": operator_id},
            headers={"X-Org-Id": org_id})  # org from session
    assert resp.status_code == 200
    body = resp.json()
    assert "code_id" in body
    assert "code" not in body, "admin response must not contain the code"


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M2T8Pending)
def test_admin_cross_org_project_404(pg_url, pg_roles, app_url, owner_url):
    """Admin of org A naming a project of org B gets 404."""
    _need("agg_cp.sync.enroll", "enroll_router")
    from agg_cp.app import create_app
    ensure_at_head(pg_url)
    org_a, org_b = str(uuid.uuid4()), str(uuid.uuid4())
    project_b = str(uuid.uuid4())

    with psycopg.connect(_conninfo(owner_url), autocommit=True) as oconn:
        oconn.execute("SELECT set_config('app.org_id', %s, false)", [org_a])
        create_org(oconn, org_a)
        oconn.execute("SELECT set_config('app.org_id', %s, false)", [org_b])
        create_org(oconn, org_b)
        create_project(oconn, org_b, project_b)

    app = create_app(database_url=app_url)
    with httpx.Client(app=app, base_url="http://test") as c:
        resp = c.post("/api/v1/admin/enrollment-codes", json={
            "project_id": project_b, "operator_user_id": str(uuid.uuid4())},
            headers={"X-Org-Id": org_a})  # session org = A
    assert resp.status_code == 404


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M2T8Pending)
def test_operator_reads_code_once(pg_url, pg_roles, app_url, owner_url):
    """GET /api/v1/enrollment-codes/{id}: operator reads code once; second read refused."""
    _need("agg_cp.sync.enroll", "enroll_router")
    from agg_cp.app import create_app
    ensure_at_head(pg_url)
    org_id, project_id = str(uuid.uuid4()), str(uuid.uuid4())
    operator_id = str(uuid.uuid4())

    with psycopg.connect(_conninfo(owner_url), autocommit=True) as oconn:
        oconn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        create_org(oconn, org_id)
        create_project(oconn, org_id, project_id)
        _, _, code_id = _issue_code_sql(oconn, org_id, project_id, operator_id)

    app = create_app(database_url=app_url)
    with httpx.Client(app=app, base_url="http://test") as c:
        # First read by the named operator: 200 with code
        r1 = c.get(f"/api/v1/enrollment-codes/{code_id}",
                    headers={"X-User-Id": operator_id,
                             "X-Auth-Time": str(int(time.time()))})
        assert r1.status_code == 200
        assert "code" in r1.json()

        # Second read: refused
        r2 = c.get(f"/api/v1/enrollment-codes/{code_id}",
                    headers={"X-User-Id": operator_id,
                             "X-Auth-Time": str(int(time.time()))})
        assert r2.status_code in (404, 410)


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M2T8Pending)
def test_operator_wrong_user_404(pg_url, pg_roles, app_url, owner_url):
    """GET /api/v1/enrollment-codes/{id}: another user gets 404."""
    _need("agg_cp.sync.enroll", "enroll_router")
    from agg_cp.app import create_app
    ensure_at_head(pg_url)
    org_id, project_id = str(uuid.uuid4()), str(uuid.uuid4())
    operator_id = str(uuid.uuid4())
    other_user = str(uuid.uuid4())

    with psycopg.connect(_conninfo(owner_url), autocommit=True) as oconn:
        oconn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        create_org(oconn, org_id)
        create_project(oconn, org_id, project_id)
        _, _, code_id = _issue_code_sql(oconn, org_id, project_id, operator_id)

    app = create_app(database_url=app_url)
    with httpx.Client(app=app, base_url="http://test") as c:
        resp = c.get(f"/api/v1/enrollment-codes/{code_id}",
                     headers={"X-User-Id": other_user,
                              "X-Auth-Time": str(int(time.time()))})
    assert resp.status_code == 404


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M2T8Pending)
def test_operator_stale_session_refused(pg_url, pg_roles, app_url, owner_url):
    """GET /api/v1/enrollment-codes/{id}: stale session (>15 min) refused."""
    _need("agg_cp.sync.enroll", "enroll_router")
    from agg_cp.app import create_app
    ensure_at_head(pg_url)
    org_id, project_id = str(uuid.uuid4()), str(uuid.uuid4())
    operator_id = str(uuid.uuid4())

    with psycopg.connect(_conninfo(owner_url), autocommit=True) as oconn:
        oconn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        create_org(oconn, org_id)
        create_project(oconn, org_id, project_id)
        _, _, code_id = _issue_code_sql(oconn, org_id, project_id, operator_id)

    app = create_app(database_url=app_url)
    with httpx.Client(app=app, base_url="http://test") as c:
        resp = c.get(f"/api/v1/enrollment-codes/{code_id}",
                     headers={"X-User-Id": operator_id,
                              "X-Auth-Time": str(int(time.time() - 20 * 60))})
    assert resp.status_code in (403, 401)


# ===================================================================
# RED: threat 4 -- token route on real 4-worker server
# ===================================================================


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M2T8Pending)
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
        code, _, _ = _issue_code_sql(oconn, org_id, project_id, operator_id)

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
@pytest.mark.xfail(strict=True, raises=M2T8Pending)
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
        code, _, _ = _issue_code_sql(oconn, org_id, project_id, operator_id)

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
@pytest.mark.xfail(strict=True, raises=M2T8Pending)
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
@pytest.mark.xfail(strict=True, raises=M2T8Pending)
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
        code, _, _ = _issue_code_sql(oconn, org_id, project_id, operator_id)

    sk, pub, _ = keygen()
    proof = _make_enroll_proof(code, sk, pub)
    r = httpx.post(f"{srv['base_url']}/api/v1/sync/enroll",
                   json={"code": code, "public_key": pub.hex(), "proof": proof},
                   timeout=10.0)
    assert r.status_code == 200
    device_id = r.json()["device_id"]

    with psycopg.connect(_conninfo(srv["owner_url"]), autocommit=True) as oconn:
        oconn.execute("UPDATE connectors SET revoked_at = now() WHERE id = %s",
                       [device_id])

    assertion = sign_envelope("agg/device-assert/v1", {
        "device_id": device_id, "aud": "test",
        "iat": time.time(), "nonce": secrets.token_hex(16)}, sk)
    resp = httpx.post(f"{srv['base_url']}/api/v1/sync/token",
                      json={"device_id": device_id, "assertion": assertion},
                      timeout=10.0)
    assert resp.status_code == 401


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M2T8Pending)
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
        code, _, _ = _issue_code_sql(oconn, org_id, project_id, operator_id)

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
@pytest.mark.xfail(strict=True, raises=M2T8Pending)
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
        code, _, _ = _issue_code_sql(oconn, org_id, project_id, operator_id)

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
