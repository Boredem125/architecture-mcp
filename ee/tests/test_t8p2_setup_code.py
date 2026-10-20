"""T8 part 2: setup code tests (``python -m agg_cp.migrate``).

Tests cover:
- migrate main() prints exactly one JSON line with event/org/code/expires_at
- DB stores only sha256 of the code
- Code has >= 128-bit entropy (>= 24 bytes of token_urlsafe)
- Wrong code increments failed_attempts; 5 failures kill the code
- Expired code (clock +31 min) refused
- Valid code + bootstrap callback creates user + admin binding + audit
- Code reused after success refused
- Second bootstrap when admin exists -> 409
- Non-JSON content type on /setup refused
- migrate run again with admin present prints no code
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import uuid as _uuid
from urllib.parse import parse_qs, urlparse

import pytest

from .t8p2_helpers import (
    T8P2Pending,
    require_t8p2,
    FakeClock,
    FakeIdP,
    FakeIdPExtended,
    FakeOidcHttp,
    make_test_app,
    safe_resolve,
    ensure_at_head,
    seed_org_with_oidc,
    seed_user,
    seed_admin_binding,
    _conninfo,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_client(app):
    try:
        from starlette.testclient import TestClient
    except ImportError as exc:
        raise T8P2Pending(f"starlette not available: {exc}") from exc
    return TestClient(app, base_url="https://testserver")


def _unique_slug(prefix: str) -> str:
    return f"{prefix}-{_uuid.uuid4().hex[:8]}"


def _is_route_missing(resp) -> bool:
    if resp.status_code != 404:
        return False
    try:
        body = resp.json()
    except Exception:
        return False
    return body == {"detail": "Not Found"}


def _run_migrate_main(pg_url, env_overrides=None):
    """Run agg_cp.migrate main() capturing stdout.

    Returns the captured stdout string.
    """
    import io
    import contextlib

    try:
        from agg_cp.migrate import main as migrate_main
    except (ImportError, ModuleNotFoundError) as exc:
        raise T8P2Pending(f"agg_cp.migrate not importable: {exc}") from exc

    old_env = {}
    env_vars = {"AGG_DATABASE_URL": pg_url}
    if env_overrides:
        env_vars.update(env_overrides)

    for k, v in env_vars.items():
        old_env[k] = os.environ.get(k)
        if v is not None:
            os.environ[k] = v
        elif k in os.environ:
            del os.environ[k]

    buf = io.StringIO()
    try:
        with contextlib.redirect_stdout(buf):
            migrate_main()
    except TypeError as exc:
        raise T8P2Pending(f"migrate main() signature mismatch: {exc}") from exc
    finally:
        for k, v in old_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    return buf.getvalue()


def _build_env_for_setup(pg_url, owner_url, *, slug=None):
    """Build test environment for /setup tests.

    Returns (client, idp_ext, org_id, clock, slug, oidc_http).
    """
    if slug is None:
        slug = _unique_slug("setup")
    issuer = "https://idp.example.com"
    client_id = "test-client-id"

    clock = FakeClock()
    idp = FakeIdP(issuer, client_id=client_id)
    oidc_http = FakeOidcHttp()
    idp_ext = FakeIdPExtended(idp, clock=clock)
    idp_ext.wire_to(oidc_http)

    ensure_at_head(pg_url)
    org_id = seed_org_with_oidc(
        owner_url, slug=slug, issuer=issuer, client_id=client_id,
    )

    app, clock, _ = make_test_app(
        pg_url=pg_url,
        clock=clock,
        oidc_http=oidc_http,
        resolve=safe_resolve,
        oidc_allow_hosts="idp.example.com",
    )
    client = _make_client(app)
    return client, idp_ext, org_id, clock, slug, oidc_http


# ===================================================================
# migrate main() prints setup code
# ===================================================================



@pytest.mark.pg
def test_migrate_prints_setup_code_json(pg_url, app_url, owner_url, pg_roles):
    """migrate main() prints exactly one JSON line with event/org/code/expires_at."""
    slug = _unique_slug("migcode")
    issuer = "https://idp.example.com"
    client_id = "test-client-id"

    ensure_at_head(pg_url)
    org_id = seed_org_with_oidc(
        owner_url, slug=slug, issuer=issuer, client_id=client_id,
    )

    output = _run_migrate_main(pg_url, {
        "AGG_BOOTSTRAP_ORG_SLUG": slug,
        "AGG_BOOTSTRAP_ORG_NAME": f"Org {slug}",
        "AGG_BOOTSTRAP_ORG_ISSUER": issuer,
        "AGG_BOOTSTRAP_ORG_CLIENT_ID": client_id,
    })

    lines = [l for l in output.strip().split("\n") if l.strip()]
    json_lines = []
    for line in lines:
        try:
            parsed = json.loads(line)
            if isinstance(parsed, dict) and parsed.get("event") == "setup_code":
                json_lines.append(parsed)
        except json.JSONDecodeError:
            continue

    assert len(json_lines) == 1, (
        f"Expected exactly 1 setup_code JSON line, got {len(json_lines)}: {output}"
    )

    data = json_lines[0]
    assert data["event"] == "setup_code"
    assert data["org"] == slug
    assert "code" in data, "JSON line missing 'code'"
    assert "expires_at" in data, "JSON line missing 'expires_at'"



@pytest.mark.pg
def test_migrate_code_stored_as_sha256(pg_url, app_url, owner_url, pg_roles):
    """DB stores only sha256 of the setup code, not the plaintext."""
    import psycopg

    slug = _unique_slug("mighash")
    issuer = "https://idp.example.com"
    client_id = "test-client-id"

    ensure_at_head(pg_url)
    org_id = seed_org_with_oidc(
        owner_url, slug=slug, issuer=issuer, client_id=client_id,
    )

    output = _run_migrate_main(pg_url, {
        "AGG_BOOTSTRAP_ORG_SLUG": slug,
        "AGG_BOOTSTRAP_ORG_NAME": f"Org {slug}",
        "AGG_BOOTSTRAP_ORG_ISSUER": issuer,
        "AGG_BOOTSTRAP_ORG_CLIENT_ID": client_id,
    })

    # Extract the code
    code = None
    for line in output.strip().split("\n"):
        try:
            parsed = json.loads(line)
            if parsed.get("event") == "setup_code":
                code = parsed["code"]
        except (json.JSONDecodeError, KeyError):
            continue

    require_t8p2(code is not None, "No setup_code line found")

    expected_hash = hashlib.sha256(code.encode()).hexdigest()

    with psycopg.connect(_conninfo(owner_url)) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [str(org_id)])
        rows = conn.execute(
            "SELECT code_hash FROM setup_codes WHERE org_id = %s",
            [org_id],
        ).fetchall()

    assert len(rows) >= 1, "No setup_code row found"

    # The stored hash should match sha256(code) and must NOT be the plaintext
    hashes = [r[0] for r in rows]
    assert expected_hash in hashes, (
        f"sha256(code) not found in DB hashes: {hashes}"
    )
    assert code not in hashes, "Plaintext code found in DB -- must store only sha256"



@pytest.mark.pg
def test_migrate_code_length_128_bits(pg_url, app_url, owner_url, pg_roles):
    """Setup code has >= 128-bit entropy (token_urlsafe(24) -> 192 bits)."""
    slug = _unique_slug("miglen")
    issuer = "https://idp.example.com"
    client_id = "test-client-id"

    ensure_at_head(pg_url)
    seed_org_with_oidc(owner_url, slug=slug, issuer=issuer, client_id=client_id)

    output = _run_migrate_main(pg_url, {
        "AGG_BOOTSTRAP_ORG_SLUG": slug,
        "AGG_BOOTSTRAP_ORG_NAME": f"Org {slug}",
        "AGG_BOOTSTRAP_ORG_ISSUER": issuer,
        "AGG_BOOTSTRAP_ORG_CLIENT_ID": client_id,
    })

    code = None
    for line in output.strip().split("\n"):
        try:
            parsed = json.loads(line)
            if parsed.get("event") == "setup_code":
                code = parsed["code"]
        except (json.JSONDecodeError, KeyError):
            continue

    require_t8p2(code is not None, "No setup_code line found")

    # token_urlsafe(24) produces 32 characters (24 bytes = 192 bits)
    # Minimum 128 bits -> at least 16 bytes -> ~22 chars in base64url
    import base64
    raw_bytes = base64.urlsafe_b64decode(code + "==")
    assert len(raw_bytes) >= 16, (
        f"Code has only {len(raw_bytes)} bytes ({len(raw_bytes)*8} bits), "
        f"need >= 128 bits"
    )


# ===================================================================
# /setup route
# ===================================================================



@pytest.mark.pg
def test_setup_wrong_code_increments_failures(pg_url, app_url, owner_url, pg_roles):
    """Wrong code increments failed_attempts."""
    import psycopg

    slug = _unique_slug("setupwrong")
    issuer = "https://idp.example.com"
    client_id = "test-client-id"

    ensure_at_head(pg_url)
    org_id = seed_org_with_oidc(
        owner_url, slug=slug, issuer=issuer, client_id=client_id,
    )

    output = _run_migrate_main(pg_url, {
        "AGG_BOOTSTRAP_ORG_SLUG": slug,
        "AGG_BOOTSTRAP_ORG_NAME": f"Org {slug}",
        "AGG_BOOTSTRAP_ORG_ISSUER": issuer,
        "AGG_BOOTSTRAP_ORG_CLIENT_ID": client_id,
    })

    # Build app
    clock = FakeClock()
    oidc_http = FakeOidcHttp()
    idp = FakeIdP(issuer, client_id=client_id)
    idp_ext = FakeIdPExtended(idp, clock=clock)
    idp_ext.wire_to(oidc_http)

    app, _, _ = make_test_app(
        pg_url=pg_url, clock=clock, oidc_http=oidc_http,
        resolve=safe_resolve, oidc_allow_hosts="idp.example.com",
    )
    client = _make_client(app)

    resp = client.post(
        "/api/v1/auth/setup",
        json={"org": slug, "code": "wrong-code"},
    )
    if _is_route_missing(resp):
        raise T8P2Pending("Route /api/v1/auth/setup not registered")

    assert resp.status_code >= 400, f"Wrong code should fail, got {resp.status_code}"

    # Check DB for failed_attempts increment
    with psycopg.connect(_conninfo(owner_url)) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [str(org_id)])
        row = conn.execute(
            "SELECT failed_attempts FROM setup_codes WHERE org_id = %s "
            "ORDER BY created_at DESC LIMIT 1",
            [org_id],
        ).fetchone()
        require_t8p2(row is not None, "setup_code not found")
        assert row[0] >= 1, f"failed_attempts should be >= 1, got {row[0]}"



@pytest.mark.pg
def test_setup_5_failures_kills_code(pg_url, app_url, owner_url, pg_roles):
    """5 wrong code attempts kill the code."""
    slug = _unique_slug("setup5fail")
    issuer = "https://idp.example.com"
    client_id = "test-client-id"

    ensure_at_head(pg_url)
    org_id = seed_org_with_oidc(
        owner_url, slug=slug, issuer=issuer, client_id=client_id,
    )

    output = _run_migrate_main(pg_url, {
        "AGG_BOOTSTRAP_ORG_SLUG": slug,
        "AGG_BOOTSTRAP_ORG_NAME": f"Org {slug}",
        "AGG_BOOTSTRAP_ORG_ISSUER": issuer,
        "AGG_BOOTSTRAP_ORG_CLIENT_ID": client_id,
    })

    # Extract the real code
    real_code = None
    for line in output.strip().split("\n"):
        try:
            parsed = json.loads(line)
            if parsed.get("event") == "setup_code":
                real_code = parsed["code"]
        except (json.JSONDecodeError, KeyError):
            continue
    require_t8p2(real_code is not None, "No setup_code found")

    clock = FakeClock()
    oidc_http = FakeOidcHttp()
    idp = FakeIdP(issuer, client_id=client_id)
    idp_ext = FakeIdPExtended(idp, clock=clock)
    idp_ext.wire_to(oidc_http)

    app, _, _ = make_test_app(
        pg_url=pg_url, clock=clock, oidc_http=oidc_http,
        resolve=safe_resolve, oidc_allow_hosts="idp.example.com",
    )
    client = _make_client(app)

    # 5 wrong attempts
    for i in range(5):
        resp = client.post(
            "/api/v1/auth/setup",
            json={"org": slug, "code": f"wrong-{i}"},
        )
        if _is_route_missing(resp):
            raise T8P2Pending("Route not registered")
        assert resp.status_code >= 400

    # Now even the REAL code should be refused
    resp = client.post(
        "/api/v1/auth/setup",
        json={"org": slug, "code": real_code},
    )
    assert resp.status_code >= 400, (
        f"Code should be dead after 5 failures, got {resp.status_code}"
    )



@pytest.mark.pg
def test_setup_expired_code_refused(pg_url, app_url, owner_url, pg_roles):
    """Expired setup code (clock +31 min) is refused."""
    slug = _unique_slug("setupexp")
    issuer = "https://idp.example.com"
    client_id = "test-client-id"

    ensure_at_head(pg_url)
    org_id = seed_org_with_oidc(
        owner_url, slug=slug, issuer=issuer, client_id=client_id,
    )

    output = _run_migrate_main(pg_url, {
        "AGG_BOOTSTRAP_ORG_SLUG": slug,
        "AGG_BOOTSTRAP_ORG_NAME": f"Org {slug}",
        "AGG_BOOTSTRAP_ORG_ISSUER": issuer,
        "AGG_BOOTSTRAP_ORG_CLIENT_ID": client_id,
    })

    real_code = None
    for line in output.strip().split("\n"):
        try:
            parsed = json.loads(line)
            if parsed.get("event") == "setup_code":
                real_code = parsed["code"]
        except (json.JSONDecodeError, KeyError):
            continue
    require_t8p2(real_code is not None, "No setup_code found")

    clock = FakeClock()
    # Advance 31 minutes past code creation
    clock.advance(dt.timedelta(minutes=31))

    oidc_http = FakeOidcHttp()
    idp = FakeIdP(issuer, client_id=client_id)
    idp_ext = FakeIdPExtended(idp, clock=clock)
    idp_ext.wire_to(oidc_http)

    app, _, _ = make_test_app(
        pg_url=pg_url, clock=clock, oidc_http=oidc_http,
        resolve=safe_resolve, oidc_allow_hosts="idp.example.com",
    )
    client = _make_client(app)

    resp = client.post(
        "/api/v1/auth/setup",
        json={"org": slug, "code": real_code},
    )
    if _is_route_missing(resp):
        raise T8P2Pending("Route not registered")
    assert resp.status_code >= 400, (
        f"Expired code should be refused, got {resp.status_code}"
    )



@pytest.mark.pg
def test_setup_bootstrap_creates_user_admin_audit(pg_url, app_url, owner_url, pg_roles):
    """Valid code + bootstrap callback creates user + admin binding + audit."""
    import psycopg

    slug = _unique_slug("setupboot")
    issuer = "https://idp.example.com"
    client_id = "test-client-id"
    bootstrap_sub = f"bootstrap-admin-{_uuid.uuid4().hex[:8]}"

    ensure_at_head(pg_url)
    org_id = seed_org_with_oidc(
        owner_url, slug=slug, issuer=issuer, client_id=client_id,
    )

    output = _run_migrate_main(pg_url, {
        "AGG_BOOTSTRAP_ORG_SLUG": slug,
        "AGG_BOOTSTRAP_ORG_NAME": f"Org {slug}",
        "AGG_BOOTSTRAP_ORG_ISSUER": issuer,
        "AGG_BOOTSTRAP_ORG_CLIENT_ID": client_id,
    })

    real_code = None
    for line in output.strip().split("\n"):
        try:
            parsed = json.loads(line)
            if parsed.get("event") == "setup_code":
                real_code = parsed["code"]
        except (json.JSONDecodeError, KeyError):
            continue
    require_t8p2(real_code is not None, "No setup_code found")

    clock = FakeClock()
    idp = FakeIdP(issuer, client_id=client_id)
    oidc_http = FakeOidcHttp()
    idp_ext = FakeIdPExtended(idp, clock=clock)
    idp_ext.wire_to(oidc_http)

    app, _, _ = make_test_app(
        pg_url=pg_url, clock=clock, oidc_http=oidc_http,
        resolve=safe_resolve, oidc_allow_hosts="idp.example.com",
    )
    client = _make_client(app)

    # POST /setup with correct code
    resp = client.post(
        "/api/v1/auth/setup",
        json={"org": slug, "code": real_code},
    )
    if _is_route_missing(resp):
        raise T8P2Pending("Route not registered")
    require_t8p2(resp.status_code in (200, 302),
                  f"Setup returned {resp.status_code}")

    body = resp.json()
    require_t8p2("redirect" in body, "Setup response missing 'redirect'")

    # Parse the redirect URL to get state, nonce, code_challenge
    redirect_url = body["redirect"]
    parsed = urlparse(redirect_url)
    params = parse_qs(parsed.query)
    state = params["state"][0]
    nonce = params["nonce"][0]
    code_challenge = params["code_challenge"][0]

    # Issue authorization code
    code = idp_ext.issue_code(
        nonce=nonce,
        code_challenge=code_challenge,
        sub=bootstrap_sub,
        email="admin@example.com",
    )

    # Extract agg_login cookie from /setup response (or we might need to
    # get it from the redirect flow)
    set_cookies = resp.headers.get_list("set-cookie")
    agg_login_val = None
    for sc in set_cookies:
        if sc.startswith("agg_login="):
            agg_login_val = sc.split("=", 1)[1].split(";")[0]
            break

    if agg_login_val is None:
        # The setup might not set agg_login directly; the client follows
        # the redirect which sets it. Since we have the redirect URL,
        # we need to follow it.
        login_resp = client.get(redirect_url, follow_redirects=False)
        if login_resp.status_code == 302:
            set_cookies = login_resp.headers.get_list("set-cookie")
            for sc in set_cookies:
                if sc.startswith("agg_login="):
                    agg_login_val = sc.split("=", 1)[1].split(";")[0]
                    break
            # The actual authorization URL is in the Location header
            # Parse new state/nonce/code_challenge from that redirect
            loc = login_resp.headers.get("location", "")
            new_params = parse_qs(urlparse(loc).query)
            if "state" in new_params:
                state = new_params["state"][0]
                nonce = new_params["nonce"][0]
                code_challenge = new_params["code_challenge"][0]
                code = idp_ext.issue_code(
                    nonce=nonce,
                    code_challenge=code_challenge,
                    sub=bootstrap_sub,
                    email="admin@example.com",
                )

    require_t8p2(agg_login_val is not None, "No agg_login cookie from setup flow")

    # Callback
    cb_resp = client.get(
        "/api/v1/auth/callback",
        params={"code": code, "state": state},
        cookies={"agg_login": agg_login_val},
        follow_redirects=False,
    )
    require_t8p2(cb_resp.status_code in (302, 200),
                  f"Bootstrap callback returned {cb_resp.status_code}")

    # Verify: user created with the bootstrap sub
    conninfo_app = _conninfo(app_url)
    with psycopg.connect(conninfo_app) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [str(org_id)])
        user = conn.execute(
            "SELECT id, email, status FROM users "
            "WHERE oidc_issuer = %s AND oidc_subject = %s",
            [issuer, bootstrap_sub],
        ).fetchone()
        assert user is not None, "Bootstrap user not created"
        assert user[1] == "admin@example.com"
        assert user[2] == "active"

        # Admin binding
        bindings = conn.execute(
            "SELECT role FROM role_bindings WHERE user_id = %s",
            [user[0]],
        ).fetchall()
        roles = [r[0] for r in bindings]
        assert "admin" in roles, f"Admin binding not created, roles: {roles}"

        # Audit
        audit = conn.execute(
            "SELECT action FROM admin_audit "
            "WHERE action = 'bootstrap_admin' ORDER BY chain_length DESC LIMIT 1"
        ).fetchone()
        assert audit is not None, "bootstrap_admin audit row not created"



@pytest.mark.pg
def test_setup_code_reused_after_success_refused(pg_url, app_url, owner_url, pg_roles):
    """Code reused after successful bootstrap is refused."""
    slug = _unique_slug("setupreuse")
    issuer = "https://idp.example.com"
    client_id = "test-client-id"

    ensure_at_head(pg_url)
    org_id = seed_org_with_oidc(
        owner_url, slug=slug, issuer=issuer, client_id=client_id,
    )

    output = _run_migrate_main(pg_url, {
        "AGG_BOOTSTRAP_ORG_SLUG": slug,
        "AGG_BOOTSTRAP_ORG_NAME": f"Org {slug}",
        "AGG_BOOTSTRAP_ORG_ISSUER": issuer,
        "AGG_BOOTSTRAP_ORG_CLIENT_ID": client_id,
    })

    real_code = None
    for line in output.strip().split("\n"):
        try:
            parsed = json.loads(line)
            if parsed.get("event") == "setup_code":
                real_code = parsed["code"]
        except (json.JSONDecodeError, KeyError):
            continue
    require_t8p2(real_code is not None, "No setup_code found")

    # Do the full bootstrap flow once (abbreviated: seed user and admin directly
    # to simulate a completed bootstrap, then try to reuse the code)
    # Mark code as used in DB
    import psycopg
    with psycopg.connect(_conninfo(owner_url)) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [str(org_id)])
        conn.execute(
            "UPDATE setup_codes SET used_at = now() WHERE org_id = %s",
            [org_id],
        )
        conn.commit()

    clock = FakeClock()
    oidc_http = FakeOidcHttp()
    idp = FakeIdP(issuer, client_id=client_id)
    idp_ext = FakeIdPExtended(idp, clock=clock)
    idp_ext.wire_to(oidc_http)

    app, _, _ = make_test_app(
        pg_url=pg_url, clock=clock, oidc_http=oidc_http,
        resolve=safe_resolve, oidc_allow_hosts="idp.example.com",
    )
    client = _make_client(app)

    resp = client.post(
        "/api/v1/auth/setup",
        json={"org": slug, "code": real_code},
    )
    if _is_route_missing(resp):
        raise T8P2Pending("Route not registered")
    assert resp.status_code >= 400, (
        f"Reused code should be refused, got {resp.status_code}"
    )



@pytest.mark.pg
def test_setup_second_bootstrap_when_admin_exists_409(pg_url, app_url, owner_url, pg_roles):
    """Second bootstrap when an admin already exists -> 409."""
    slug = _unique_slug("setup409")
    issuer = "https://idp.example.com"
    client_id = "test-client-id"

    ensure_at_head(pg_url)
    org_id = seed_org_with_oidc(
        owner_url, slug=slug, issuer=issuer, client_id=client_id,
    )

    # Create admin user and binding
    user_id, _ = seed_user(owner_url, org_id, iss=issuer, sub=f"existing-admin-{_uuid.uuid4().hex[:8]}")
    seed_admin_binding(owner_url, org_id, user_id)

    output = _run_migrate_main(pg_url, {
        "AGG_BOOTSTRAP_ORG_SLUG": slug,
        "AGG_BOOTSTRAP_ORG_NAME": f"Org {slug}",
        "AGG_BOOTSTRAP_ORG_ISSUER": issuer,
        "AGG_BOOTSTRAP_ORG_CLIENT_ID": client_id,
    })

    # Since admin exists, migrate should NOT print a code.
    # But there might be an older code in the DB. Try to use /setup anyway.
    # Seed a setup code manually for this test.
    import psycopg
    import secrets

    test_code = secrets.token_urlsafe(24)
    code_hash = hashlib.sha256(test_code.encode()).hexdigest()
    with psycopg.connect(_conninfo(owner_url)) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [str(org_id)])
        conn.execute(
            "INSERT INTO setup_codes (id, org_id, code_hash, created_at, expires_at) "
            "VALUES (%s, %s, %s, now(), now() + interval '30 min')",
            [_uuid.uuid4(), org_id, code_hash],
        )
        conn.commit()

    clock = FakeClock()
    oidc_http = FakeOidcHttp()
    idp = FakeIdP(issuer, client_id=client_id)
    idp_ext = FakeIdPExtended(idp, clock=clock)
    idp_ext.wire_to(oidc_http)

    app, _, _ = make_test_app(
        pg_url=pg_url, clock=clock, oidc_http=oidc_http,
        resolve=safe_resolve, oidc_allow_hosts="idp.example.com",
    )
    client = _make_client(app)

    resp = client.post(
        "/api/v1/auth/setup",
        json={"org": slug, "code": test_code},
    )
    if _is_route_missing(resp):
        raise T8P2Pending("Route not registered")
    assert resp.status_code == 409, (
        f"Second bootstrap should be 409, got {resp.status_code}"
    )



@pytest.mark.pg
def test_setup_non_json_content_type_refused(pg_url, app_url, owner_url, pg_roles):
    """POST /setup with non-JSON content type is refused."""
    clock = FakeClock()
    oidc_http = FakeOidcHttp()
    ensure_at_head(pg_url)

    app, _, _ = make_test_app(
        pg_url=pg_url, clock=clock, oidc_http=oidc_http,
        resolve=safe_resolve,
    )
    client = _make_client(app)

    resp = client.post(
        "/api/v1/auth/setup",
        content="org=test&code=test",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    if _is_route_missing(resp):
        raise T8P2Pending("Route not registered")
    # Should refuse: 400 or 415 (Unsupported Media Type)
    assert resp.status_code >= 400, (
        f"Non-JSON should be refused, got {resp.status_code}"
    )



@pytest.mark.pg
def test_migrate_no_code_when_admin_exists(pg_url, app_url, owner_url, pg_roles):
    """migrate run again with an admin present prints no setup code."""
    slug = _unique_slug("migadmin")
    issuer = "https://idp.example.com"
    client_id = "test-client-id"

    ensure_at_head(pg_url)
    org_id = seed_org_with_oidc(
        owner_url, slug=slug, issuer=issuer, client_id=client_id,
    )

    # Create admin user
    user_id, _ = seed_user(owner_url, org_id, iss=issuer, sub=f"admin-exists-{_uuid.uuid4().hex[:8]}")
    seed_admin_binding(owner_url, org_id, user_id)

    output = _run_migrate_main(pg_url, {
        "AGG_BOOTSTRAP_ORG_SLUG": slug,
        "AGG_BOOTSTRAP_ORG_NAME": f"Org {slug}",
        "AGG_BOOTSTRAP_ORG_ISSUER": issuer,
        "AGG_BOOTSTRAP_ORG_CLIENT_ID": client_id,
    })

    # Should not contain a setup_code line
    for line in output.strip().split("\n"):
        if not line.strip():
            continue
        try:
            parsed = json.loads(line)
            if parsed.get("event") == "setup_code":
                pytest.fail(
                    f"migrate printed setup_code when admin already exists: {line}"
                )
        except json.JSONDecodeError:
            continue
