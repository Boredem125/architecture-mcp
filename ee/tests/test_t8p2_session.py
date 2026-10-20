"""T8 part 2: callback, session, CSRF, and logout tests.

Tests cover:
- Callback happy path: sets __Host-agg_session (Secure, HttpOnly, SameSite=Strict,
  Path=/, no Domain) and clears agg_login.
- Replay same callback refused; wrong state refused; expired transaction refused;
  missing cookie refused; wrong nonce id_token refused; PKCE verifier mismatch
  refused; unknown (iss,sub) -> 403 not_provisioned (even with same email);
  session id differs across two logins.
- admin_audit gets a login row on successful callback.
- Session: valid cookie passes require_session; idle 30 min refused;
  absolute 12h refused; revoked refused; forged org_id refused;
  token never stored in plaintext (DB has only sha256).
- CSRF: logout without header 403; wrong header 403; right header 204;
  after logout the session is refused; cookie cleared.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import uuid as _uuid
from urllib.parse import parse_qs, urlparse

import pytest

from .t8p2_helpers import (
    T8P2Pending,
    RED_T8P2,
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
    unique_sub,
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


def _is_route_missing_404(resp) -> bool:
    if resp.status_code != 404:
        return False
    try:
        body = resp.json()
    except Exception:
        return False
    return body == {"detail": "Not Found"}


def _full_login_flow(client, idp_ext, slug, *, sub, email="user@example.com"):
    """Drive login -> callback and return (session_cookie_header, csrf_token, response).

    The caller must have already seeded the user in the DB.
    """
    # Step 1: GET /login -> 302 with agg_login cookie
    resp = client.get("/api/v1/auth/login", params={"org": slug},
                      follow_redirects=False)
    if _is_route_missing_404(resp):
        raise T8P2Pending("Route /api/v1/auth/login not registered")
    require_t8p2(resp.status_code == 302,
                  f"Expected 302 from /login, got {resp.status_code}")

    location = resp.headers["location"]
    params = parse_qs(urlparse(location).query)
    state = params["state"][0]
    nonce = params["nonce"][0]
    code_challenge = params["code_challenge"][0]

    # Extract agg_login cookie value
    set_cookies = resp.headers.get_list("set-cookie")
    agg_login_val = None
    for sc in set_cookies:
        if sc.startswith("agg_login="):
            agg_login_val = sc.split("=", 1)[1].split(";")[0]
            break
    require_t8p2(agg_login_val is not None, "agg_login cookie not set")

    # Step 2: Issue a code at the fake IdP
    code = idp_ext.issue_code(
        nonce=nonce,
        code_challenge=code_challenge,
        sub=sub,
        email=email,
    )

    # Step 3: GET /callback with the code and state, passing the agg_login cookie
    cb_resp = client.get(
        "/api/v1/auth/callback",
        params={"code": code, "state": state},
        cookies={"agg_login": agg_login_val},
        follow_redirects=False,
    )
    return cb_resp, agg_login_val, state, code


def _extract_session_cookie(resp):
    """Extract __Host-agg_session cookie value from a response."""
    set_cookies = resp.headers.get_list("set-cookie")
    for sc in set_cookies:
        if sc.startswith("__Host-agg_session="):
            return sc.split("=", 1)[1].split(";")[0]
    return None


def _extract_session_cookie_header(resp):
    """Return the full Set-Cookie header for __Host-agg_session."""
    set_cookies = resp.headers.get_list("set-cookie")
    for sc in set_cookies:
        if sc.startswith("__Host-agg_session="):
            return sc
    return None


def _build_env(pg_url, owner_url, *, slug=None, sub=None,
               email="user@example.com", seed_user_flag=True):
    """Build a full test environment.

    Returns (client, idp_ext, org_id, clock, slug, user_id, sub).
    Each call gets a unique slug, sub, and org to avoid collisions.
    """
    if slug is None:
        slug = _unique_slug("sess")
    if sub is None:
        sub = unique_sub()
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

    user_id = None
    if seed_user_flag:
        user_id, sub = seed_user(
            owner_url, org_id, iss=issuer, sub=sub, email=email,
        )

    app, clock, _ = make_test_app(
        pg_url=pg_url,
        clock=clock,
        oidc_http=oidc_http,
        resolve=safe_resolve,
        oidc_allow_hosts="idp.example.com",
    )
    client = _make_client(app)
    return client, idp_ext, org_id, clock, slug, user_id, sub


# ===================================================================
# Callback happy path
# ===================================================================


@RED_T8P2
@pytest.mark.pg
def test_callback_happy_path_session_cookie(pg_url, app_url, owner_url, pg_roles):
    """Happy-path callback sets __Host-agg_session with correct attributes."""
    client, idp_ext, org_id, clock, slug, user_id, sub = _build_env(pg_url, owner_url)

    cb_resp, _, _, _ = _full_login_flow(client, idp_ext, slug, sub=sub)
    require_t8p2(cb_resp.status_code in (302, 200),
                  f"Callback returned {cb_resp.status_code}")

    sc = _extract_session_cookie_header(cb_resp)
    assert sc is not None, "Session cookie __Host-agg_session not set"

    sc_lower = sc.lower()
    assert "secure" in sc_lower, "__Host-agg_session must be Secure"
    assert "httponly" in sc_lower, "__Host-agg_session must be HttpOnly"
    assert "samesite=strict" in sc_lower, "__Host-agg_session must be SameSite=Strict"
    assert "path=/" in sc_lower, "__Host-agg_session must have Path=/"
    # Must NOT have a Domain attribute
    # (domain= in the cookie string, but Path=/ is fine)
    parts = [p.strip().lower() for p in sc.split(";")]
    domain_parts = [p for p in parts if p.startswith("domain=")]
    assert len(domain_parts) == 0, (
        f"__Host-agg_session must not have Domain attribute: {sc}"
    )


@RED_T8P2
@pytest.mark.pg
def test_callback_clears_agg_login(pg_url, app_url, owner_url, pg_roles):
    """Callback clears the agg_login cookie."""
    client, idp_ext, org_id, clock, slug, user_id, sub = _build_env(pg_url, owner_url)

    cb_resp, _, _, _ = _full_login_flow(client, idp_ext, slug, sub=sub)
    require_t8p2(cb_resp.status_code in (302, 200),
                  f"Callback returned {cb_resp.status_code}")

    set_cookies = cb_resp.headers.get_list("set-cookie")
    cleared = False
    for sc in set_cookies:
        if sc.startswith("agg_login="):
            # Cookie should be cleared (empty value or max-age=0)
            sc_lower = sc.lower()
            if "max-age=0" in sc_lower or 'agg_login=""' in sc_lower or "agg_login=;" in sc:
                cleared = True
    assert cleared, (
        f"agg_login cookie not cleared in callback response: {set_cookies}"
    )


# ===================================================================
# Callback refusals
# ===================================================================


@RED_T8P2
@pytest.mark.pg
def test_callback_replay_refused(pg_url, app_url, owner_url, pg_roles):
    """Replaying the same callback (same code/state/cookie) is refused."""
    client, idp_ext, org_id, clock, slug, user_id, sub = _build_env(pg_url, owner_url)

    # First login succeeds
    resp1 = client.get("/api/v1/auth/login", params={"org": slug},
                       follow_redirects=False)
    if _is_route_missing_404(resp1):
        raise T8P2Pending("Route not registered")
    require_t8p2(resp1.status_code == 302, f"Expected 302, got {resp1.status_code}")

    location = resp1.headers["location"]
    params = parse_qs(urlparse(location).query)
    state = params["state"][0]
    nonce = params["nonce"][0]
    code_challenge = params["code_challenge"][0]

    set_cookies = resp1.headers.get_list("set-cookie")
    agg_login_val = None
    for sc in set_cookies:
        if sc.startswith("agg_login="):
            agg_login_val = sc.split("=", 1)[1].split(";")[0]
            break

    code = idp_ext.issue_code(nonce=nonce, code_challenge=code_challenge, sub=sub)

    # First callback
    cb1 = client.get("/api/v1/auth/callback",
                     params={"code": code, "state": state},
                     cookies={"agg_login": agg_login_val},
                     follow_redirects=False)
    require_t8p2(cb1.status_code in (302, 200),
                  f"First callback failed: {cb1.status_code}")

    # Replay: same code, state, cookie -> must be refused
    cb2 = client.get("/api/v1/auth/callback",
                     params={"code": code, "state": state},
                     cookies={"agg_login": agg_login_val},
                     follow_redirects=False)
    assert cb2.status_code >= 400, (
        f"Replay should be refused, got {cb2.status_code}"
    )


@RED_T8P2
@pytest.mark.pg
def test_callback_wrong_state_refused(pg_url, app_url, owner_url, pg_roles):
    """Callback with wrong state is refused."""
    client, idp_ext, org_id, clock, slug, user_id, sub = _build_env(pg_url, owner_url)

    resp = client.get("/api/v1/auth/login", params={"org": slug},
                      follow_redirects=False)
    if _is_route_missing_404(resp):
        raise T8P2Pending("Route not registered")
    require_t8p2(resp.status_code == 302, f"Expected 302, got {resp.status_code}")

    location = resp.headers["location"]
    params = parse_qs(urlparse(location).query)
    nonce = params["nonce"][0]
    code_challenge = params["code_challenge"][0]

    set_cookies = resp.headers.get_list("set-cookie")
    agg_login_val = None
    for sc in set_cookies:
        if sc.startswith("agg_login="):
            agg_login_val = sc.split("=", 1)[1].split(";")[0]
            break

    code = idp_ext.issue_code(nonce=nonce, code_challenge=code_challenge, sub=sub)

    cb = client.get("/api/v1/auth/callback",
                    params={"code": code, "state": "wrong-state-value"},
                    cookies={"agg_login": agg_login_val},
                    follow_redirects=False)
    assert cb.status_code >= 400, f"Wrong state should be refused, got {cb.status_code}"


@RED_T8P2
@pytest.mark.pg
def test_callback_expired_transaction_refused(pg_url, app_url, owner_url, pg_roles):
    """Callback after 11 minutes (transaction expired at 10 min) is refused."""
    client, idp_ext, org_id, clock, slug, user_id, sub = _build_env(pg_url, owner_url)

    resp = client.get("/api/v1/auth/login", params={"org": slug},
                      follow_redirects=False)
    if _is_route_missing_404(resp):
        raise T8P2Pending("Route not registered")
    require_t8p2(resp.status_code == 302, f"Expected 302, got {resp.status_code}")

    location = resp.headers["location"]
    params = parse_qs(urlparse(location).query)
    state = params["state"][0]
    nonce = params["nonce"][0]
    code_challenge = params["code_challenge"][0]

    set_cookies = resp.headers.get_list("set-cookie")
    agg_login_val = None
    for sc in set_cookies:
        if sc.startswith("agg_login="):
            agg_login_val = sc.split("=", 1)[1].split(";")[0]
            break

    code = idp_ext.issue_code(nonce=nonce, code_challenge=code_challenge, sub=sub)

    # Advance clock by 11 minutes
    clock.advance(dt.timedelta(minutes=11))

    cb = client.get("/api/v1/auth/callback",
                    params={"code": code, "state": state},
                    cookies={"agg_login": agg_login_val},
                    follow_redirects=False)
    assert cb.status_code >= 400, (
        f"Expired transaction should be refused, got {cb.status_code}"
    )


@RED_T8P2
@pytest.mark.pg
def test_callback_missing_cookie_refused(pg_url, app_url, owner_url, pg_roles):
    """Callback without the agg_login cookie is refused."""
    client, idp_ext, org_id, clock, slug, user_id, sub = _build_env(pg_url, owner_url)

    resp = client.get("/api/v1/auth/login", params={"org": slug},
                      follow_redirects=False)
    if _is_route_missing_404(resp):
        raise T8P2Pending("Route not registered")
    require_t8p2(resp.status_code == 302, f"Expected 302, got {resp.status_code}")

    location = resp.headers["location"]
    params = parse_qs(urlparse(location).query)
    state = params["state"][0]
    nonce = params["nonce"][0]
    code_challenge = params["code_challenge"][0]

    code = idp_ext.issue_code(nonce=nonce, code_challenge=code_challenge, sub=sub)

    # No cookie
    cb = client.get("/api/v1/auth/callback",
                    params={"code": code, "state": state},
                    follow_redirects=False)
    assert cb.status_code >= 400, (
        f"Missing cookie should be refused, got {cb.status_code}"
    )


@RED_T8P2
@pytest.mark.pg
def test_callback_wrong_nonce_refused(pg_url, app_url, owner_url, pg_roles):
    """id_token with wrong nonce is refused."""
    client, idp_ext, org_id, clock, slug, user_id, sub = _build_env(pg_url, owner_url)

    resp = client.get("/api/v1/auth/login", params={"org": slug},
                      follow_redirects=False)
    if _is_route_missing_404(resp):
        raise T8P2Pending("Route not registered")
    require_t8p2(resp.status_code == 302, f"Expected 302, got {resp.status_code}")

    location = resp.headers["location"]
    params = parse_qs(urlparse(location).query)
    state = params["state"][0]
    nonce = params["nonce"][0]
    code_challenge = params["code_challenge"][0]

    set_cookies = resp.headers.get_list("set-cookie")
    agg_login_val = None
    for sc in set_cookies:
        if sc.startswith("agg_login="):
            agg_login_val = sc.split("=", 1)[1].split(";")[0]
            break

    # Issue code with WRONG nonce so the id_token has a mismatched nonce
    code = idp_ext.issue_code(
        nonce="totally-wrong-nonce",
        code_challenge=code_challenge,
        sub=sub,
    )

    cb = client.get("/api/v1/auth/callback",
                    params={"code": code, "state": state},
                    cookies={"agg_login": agg_login_val},
                    follow_redirects=False)
    assert cb.status_code >= 400, (
        f"Wrong nonce should be refused, got {cb.status_code}"
    )


@RED_T8P2
@pytest.mark.pg
def test_callback_pkce_mismatch_refused(pg_url, app_url, owner_url, pg_roles):
    """PKCE verifier mismatch at the token endpoint is refused."""
    slug = _unique_slug("pkcemm")
    issuer = "https://idp.example.com"
    client_id = "test-client-id"

    clock = FakeClock()
    idp = FakeIdP(issuer, client_id=client_id)
    oidc_http = FakeOidcHttp()
    idp_ext = FakeIdPExtended(idp, clock=clock)

    # Wire discovery and JWKS normally, but make token endpoint always fail PKCE
    oidc_http.set_get_json(idp_ext.discovery_url, idp_ext.discovery_doc())
    oidc_http.set_get_json(idp_ext.jwks_uri, idp.jwks())
    oidc_http.set_post_handler(
        idp_ext.token_endpoint,
        idp_ext.handle_token_request_wrong_pkce,
    )

    ensure_at_head(pg_url)
    org_id = seed_org_with_oidc(
        owner_url, slug=slug, issuer=issuer, client_id=client_id,
    )
    pkce_sub = unique_sub()
    seed_user(owner_url, org_id, iss=issuer, sub=pkce_sub)  # returns (id, sub), ignored

    app, clock, _ = make_test_app(
        pg_url=pg_url, clock=clock, oidc_http=oidc_http,
        resolve=safe_resolve, oidc_allow_hosts="idp.example.com",
    )
    client = _make_client(app)

    resp = client.get("/api/v1/auth/login", params={"org": slug},
                      follow_redirects=False)
    if _is_route_missing_404(resp):
        raise T8P2Pending("Route not registered")
    require_t8p2(resp.status_code == 302, f"Expected 302, got {resp.status_code}")

    location = resp.headers["location"]
    params = parse_qs(urlparse(location).query)
    state = params["state"][0]
    nonce = params["nonce"][0]
    code_challenge = params["code_challenge"][0]

    set_cookies = resp.headers.get_list("set-cookie")
    agg_login_val = None
    for sc in set_cookies:
        if sc.startswith("agg_login="):
            agg_login_val = sc.split("=", 1)[1].split(";")[0]
            break

    code = idp_ext.issue_code(nonce=nonce, code_challenge=code_challenge, sub=pkce_sub)

    cb = client.get("/api/v1/auth/callback",
                    params={"code": code, "state": state},
                    cookies={"agg_login": agg_login_val},
                    follow_redirects=False)
    assert cb.status_code >= 400, (
        f"PKCE mismatch should be refused, got {cb.status_code}"
    )


@RED_T8P2
@pytest.mark.pg
def test_callback_unknown_user_403_not_provisioned(pg_url, app_url, owner_url, pg_roles):
    """Unknown (iss,sub) -> 403 not_provisioned even when a user with same email exists."""
    slug = _unique_slug("notprov")
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

    # Seed a user with same email but DIFFERENT (iss, sub)
    existing_sub = unique_sub()
    seed_user(
        owner_url, org_id,
        iss=issuer, sub=existing_sub,
        email="user@example.com",
    )

    app, clock, _ = make_test_app(
        pg_url=pg_url, clock=clock, oidc_http=oidc_http,
        resolve=safe_resolve, oidc_allow_hosts="idp.example.com",
    )
    client = _make_client(app)

    # Login with a different sub that does not exist in the DB
    unknown_sub = unique_sub()
    cb_resp, _, _, _ = _full_login_flow(
        client, idp_ext, slug,
        sub=unknown_sub, email="user@example.com",
    )
    assert cb_resp.status_code == 403, (
        f"Unknown user should get 403, got {cb_resp.status_code}"
    )
    body = cb_resp.json()
    assert "not_provisioned" in str(body).lower(), (
        f"Expected not_provisioned in body: {body}"
    )


@RED_T8P2
@pytest.mark.pg
def test_callback_session_id_differs_across_logins(pg_url, app_url, owner_url, pg_roles):
    """Session id differs across two logins of the same user."""
    client, idp_ext, org_id, clock, slug, user_id, sub = _build_env(pg_url, owner_url)

    cb1, _, _, _ = _full_login_flow(client, idp_ext, slug, sub=sub)
    require_t8p2(cb1.status_code in (302, 200),
                  f"First login failed: {cb1.status_code}")
    session1 = _extract_session_cookie(cb1)
    assert session1 is not None, "First login: no session cookie"

    cb2, _, _, _ = _full_login_flow(client, idp_ext, slug, sub=sub)
    require_t8p2(cb2.status_code in (302, 200),
                  f"Second login failed: {cb2.status_code}")
    session2 = _extract_session_cookie(cb2)
    assert session2 is not None, "Second login: no session cookie"

    assert session1 != session2, "Session tokens must differ between logins"


@RED_T8P2
@pytest.mark.pg
def test_callback_admin_audit_login_row(pg_url, app_url, owner_url, pg_roles):
    """admin_audit gets a 'login' row after successful callback."""
    import psycopg

    client, idp_ext, org_id, clock, slug, user_id, sub = _build_env(pg_url, owner_url)

    # Count audit rows before
    conninfo = _conninfo(app_url)
    with psycopg.connect(conninfo) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [str(org_id)])
        before = conn.execute(
            "SELECT count(*) FROM admin_audit WHERE action = 'login'"
        ).fetchone()[0]

    cb_resp, _, _, _ = _full_login_flow(client, idp_ext, slug, sub=sub)
    require_t8p2(cb_resp.status_code in (302, 200),
                  f"Callback failed: {cb_resp.status_code}")

    with psycopg.connect(conninfo) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [str(org_id)])
        after = conn.execute(
            "SELECT count(*) FROM admin_audit WHERE action = 'login'"
        ).fetchone()[0]

    assert after > before, "admin_audit should have a new 'login' row"


# ===================================================================
# Session: require_session behaviour
# ===================================================================


@RED_T8P2
@pytest.mark.pg
def test_session_valid_cookie_passes(pg_url, app_url, owner_url, pg_roles):
    """A valid session cookie passes require_session (via logout route existence check)."""
    client, idp_ext, org_id, clock, slug, user_id, sub = _build_env(pg_url, owner_url)

    cb_resp, _, _, _ = _full_login_flow(client, idp_ext, slug, sub=sub)
    require_t8p2(cb_resp.status_code in (302, 200),
                  f"Login failed: {cb_resp.status_code}")

    session_val = _extract_session_cookie(cb_resp)
    assert session_val is not None

    # Use POST /logout to test session validity (it requires a session)
    # Without CSRF it should fail with 403 (CSRF), not 401 (no session)
    resp = client.post(
        "/api/v1/auth/logout",
        cookies={"__Host-agg_session": session_val},
        follow_redirects=False,
    )
    # 403 = CSRF check failed (session IS valid) or 204 = success
    # 401 would mean session was not recognized
    assert resp.status_code != 401, (
        f"Valid session should not get 401, got {resp.status_code}"
    )


@RED_T8P2
@pytest.mark.pg
def test_session_idle_30min_refused(pg_url, app_url, owner_url, pg_roles):
    """Session idle for 30 minutes is refused."""
    client, idp_ext, org_id, clock, slug, user_id, sub = _build_env(pg_url, owner_url)

    cb_resp, _, _, _ = _full_login_flow(client, idp_ext, slug, sub=sub)
    require_t8p2(cb_resp.status_code in (302, 200),
                  f"Login failed: {cb_resp.status_code}")

    session_val = _extract_session_cookie(cb_resp)
    assert session_val is not None

    # Advance clock by 30 minutes (idle timeout)
    clock.advance(dt.timedelta(minutes=30))

    resp = client.post(
        "/api/v1/auth/logout",
        cookies={"__Host-agg_session": session_val},
        headers={"X-CSRF-Token": "anything"},
        follow_redirects=False,
    )
    assert resp.status_code == 401, (
        f"Idle session should get 401, got {resp.status_code}"
    )


@RED_T8P2
@pytest.mark.pg
def test_session_absolute_12h_refused(pg_url, app_url, owner_url, pg_roles):
    """Absolute 12h expiry is enforced even with activity."""
    client, idp_ext, org_id, clock, slug, user_id, sub = _build_env(pg_url, owner_url)

    cb_resp, _, _, _ = _full_login_flow(client, idp_ext, slug, sub=sub)
    require_t8p2(cb_resp.status_code in (302, 200),
                  f"Login failed: {cb_resp.status_code}")

    session_val = _extract_session_cookie(cb_resp)
    assert session_val is not None

    # Simulate activity: advance 25 min at a time, accessing each time
    for _ in range(29):  # 29 * 25 min = 725 min = 12h 5min
        clock.advance(dt.timedelta(minutes=25))
        resp = client.post(
            "/api/v1/auth/logout",
            cookies={"__Host-agg_session": session_val},
            headers={"X-CSRF-Token": "anything"},
            follow_redirects=False,
        )
        # Early iterations should still work (within 12h)

    # After 12h+ the session must be expired
    assert resp.status_code == 401, (
        f"Absolute 12h session should be refused, got {resp.status_code}"
    )


@RED_T8P2
@pytest.mark.pg
def test_session_revoked_refused(pg_url, app_url, owner_url, pg_roles):
    """A revoked session is refused."""
    client, idp_ext, org_id, clock, slug, user_id, sub = _build_env(pg_url, owner_url)

    cb_resp, _, _, _ = _full_login_flow(client, idp_ext, slug, sub=sub)
    require_t8p2(cb_resp.status_code in (302, 200),
                  f"Login failed: {cb_resp.status_code}")

    session_val = _extract_session_cookie(cb_resp)
    assert session_val is not None

    # Revoke by logging out (need CSRF token -- extract from the cookie value)
    # The session cookie is org_id.token; we need the CSRF token
    # For now, just revoke directly via DB
    import psycopg

    # Parse the token from the session cookie: <org_id>.<token>
    token = session_val.split(".", 1)[1] if "." in session_val else session_val
    token_hash = hashlib.sha256(token.encode()).hexdigest()

    with psycopg.connect(_conninfo(owner_url)) as conn:
        conn.execute(
            "SELECT set_config('app.org_id', %s, false)", [str(org_id)]
        )
        conn.execute(
            "UPDATE web_sessions SET revoked_at = now() WHERE token_hash = %s",
            [token_hash],
        )
        conn.commit()

    resp = client.post(
        "/api/v1/auth/logout",
        cookies={"__Host-agg_session": session_val},
        headers={"X-CSRF-Token": "anything"},
        follow_redirects=False,
    )
    assert resp.status_code == 401, (
        f"Revoked session should get 401, got {resp.status_code}"
    )


@RED_T8P2
@pytest.mark.pg
def test_session_forged_org_id_refused(pg_url, app_url, owner_url, pg_roles):
    """A forged org_id in the session cookie finds no row."""
    client, idp_ext, org_id, clock, slug, user_id, sub = _build_env(pg_url, owner_url)

    cb_resp, _, _, _ = _full_login_flow(client, idp_ext, slug, sub=sub)
    require_t8p2(cb_resp.status_code in (302, 200),
                  f"Login failed: {cb_resp.status_code}")

    session_val = _extract_session_cookie(cb_resp)
    assert session_val is not None

    # Replace the org_id portion with a different UUID
    parts = session_val.split(".", 1)
    forged = str(_uuid.uuid4()) + "." + parts[1]

    resp = client.post(
        "/api/v1/auth/logout",
        cookies={"__Host-agg_session": forged},
        headers={"X-CSRF-Token": "anything"},
        follow_redirects=False,
    )
    assert resp.status_code == 401, (
        f"Forged org_id should get 401, got {resp.status_code}"
    )


@RED_T8P2
@pytest.mark.pg
def test_session_token_not_stored_plaintext(pg_url, app_url, owner_url, pg_roles):
    """The session token is never stored in plaintext; DB has only sha256."""
    import psycopg

    client, idp_ext, org_id, clock, slug, user_id, sub = _build_env(pg_url, owner_url)

    cb_resp, _, _, _ = _full_login_flow(client, idp_ext, slug, sub=sub)
    require_t8p2(cb_resp.status_code in (302, 200),
                  f"Login failed: {cb_resp.status_code}")

    session_val = _extract_session_cookie(cb_resp)
    assert session_val is not None

    token = session_val.split(".", 1)[1] if "." in session_val else session_val
    expected_hash = hashlib.sha256(token.encode()).hexdigest()

    with psycopg.connect(_conninfo(app_url)) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [str(org_id)])
        rows = conn.execute(
            "SELECT token_hash FROM web_sessions WHERE token_hash = %s",
            [expected_hash],
        ).fetchall()
        assert len(rows) >= 1, "Session not found by token_hash"

        # Ensure no column contains the raw token
        all_sessions = conn.execute(
            "SELECT * FROM web_sessions"
        ).fetchall()
        for row in all_sessions:
            for val in row:
                if isinstance(val, str) and val == token:
                    pytest.fail(
                        "Raw session token found in web_sessions -- "
                        "must store only sha256"
                    )


# ===================================================================
# CSRF: logout
# ===================================================================


@RED_T8P2
@pytest.mark.pg
def test_csrf_logout_no_header_403(pg_url, app_url, owner_url, pg_roles):
    """POST /logout without X-CSRF-Token header returns 403."""
    client, idp_ext, org_id, clock, slug, user_id, sub = _build_env(pg_url, owner_url)

    cb_resp, _, _, _ = _full_login_flow(client, idp_ext, slug, sub=sub)
    require_t8p2(cb_resp.status_code in (302, 200),
                  f"Login failed: {cb_resp.status_code}")

    session_val = _extract_session_cookie(cb_resp)
    assert session_val is not None

    resp = client.post(
        "/api/v1/auth/logout",
        cookies={"__Host-agg_session": session_val},
        follow_redirects=False,
    )
    assert resp.status_code == 403, (
        f"Missing CSRF header should get 403, got {resp.status_code}"
    )


@RED_T8P2
@pytest.mark.pg
def test_csrf_logout_wrong_header_403(pg_url, app_url, owner_url, pg_roles):
    """POST /logout with wrong X-CSRF-Token returns 403."""
    client, idp_ext, org_id, clock, slug, user_id, sub = _build_env(pg_url, owner_url)

    cb_resp, _, _, _ = _full_login_flow(client, idp_ext, slug, sub=sub)
    require_t8p2(cb_resp.status_code in (302, 200),
                  f"Login failed: {cb_resp.status_code}")

    session_val = _extract_session_cookie(cb_resp)
    assert session_val is not None

    resp = client.post(
        "/api/v1/auth/logout",
        cookies={"__Host-agg_session": session_val},
        headers={"X-CSRF-Token": "wrong-csrf-value"},
        follow_redirects=False,
    )
    assert resp.status_code == 403, (
        f"Wrong CSRF should get 403, got {resp.status_code}"
    )


@RED_T8P2
@pytest.mark.pg
def test_csrf_logout_correct_header_204(pg_url, app_url, owner_url, pg_roles):
    """POST /logout with correct X-CSRF-Token returns 204."""
    import psycopg

    client, idp_ext, org_id, clock, slug, user_id, sub = _build_env(pg_url, owner_url)

    cb_resp, _, _, _ = _full_login_flow(client, idp_ext, slug, sub=sub)
    require_t8p2(cb_resp.status_code in (302, 200),
                  f"Login failed: {cb_resp.status_code}")

    session_val = _extract_session_cookie(cb_resp)
    assert session_val is not None

    # Extract the CSRF token: it is the pre-image of csrf_hash stored in the session
    # The token is returned at login (in the callback response body or via /me).
    # Since /me is T9, we read the csrf token from DB.
    token = session_val.split(".", 1)[1] if "." in session_val else session_val
    token_hash = hashlib.sha256(token.encode()).hexdigest()

    with psycopg.connect(_conninfo(app_url)) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [str(org_id)])
        row = conn.execute(
            "SELECT csrf_hash FROM web_sessions WHERE token_hash = %s",
            [token_hash],
        ).fetchone()
        require_t8p2(row is not None, "Session not found in DB")
        csrf_hash = row[0]

    # We need the CSRF token whose SHA-256 equals csrf_hash.
    # The implementation generates it at login. We need to find it.
    # Strategy: check if the callback response has a body with csrf_token,
    # or extract from the DB by finding the pre-image.
    # Since we cannot reverse a hash, the CSRF token must be communicated
    # to the client somehow. Check the callback response body.
    try:
        body = cb_resp.json()
        csrf_token = body.get("csrf_token")
    except Exception:
        csrf_token = None

    if csrf_token is None:
        # The CSRF token might be in a response header or
        # we might need to call GET /me. For now, we'll read it from
        # the session: the build should store csrf_token alongside csrf_hash
        # or return it. Let's try to find it from the raw session data.
        # This is a test constraint: we need the CSRF token.
        # Since we can't reverse hash, and /me is T9, the callback
        # must return the csrf_token.
        raise T8P2Pending(
            "Cannot determine CSRF token: callback response "
            "does not contain csrf_token field"
        )

    resp = client.post(
        "/api/v1/auth/logout",
        cookies={"__Host-agg_session": session_val},
        headers={"X-CSRF-Token": csrf_token},
        follow_redirects=False,
    )
    assert resp.status_code == 204, (
        f"Correct CSRF should get 204, got {resp.status_code}"
    )


@RED_T8P2
@pytest.mark.pg
def test_logout_session_refused_after(pg_url, app_url, owner_url, pg_roles):
    """After logout the session is refused."""
    import psycopg

    client, idp_ext, org_id, clock, slug, user_id, sub = _build_env(pg_url, owner_url)

    cb_resp, _, _, _ = _full_login_flow(client, idp_ext, slug, sub=sub)
    require_t8p2(cb_resp.status_code in (302, 200),
                  f"Login failed: {cb_resp.status_code}")

    session_val = _extract_session_cookie(cb_resp)
    assert session_val is not None

    # Get CSRF token from callback response
    try:
        body = cb_resp.json()
        csrf_token = body.get("csrf_token")
    except Exception:
        csrf_token = None

    if csrf_token is None:
        raise T8P2Pending("Cannot determine CSRF token from callback")

    # Logout
    resp = client.post(
        "/api/v1/auth/logout",
        cookies={"__Host-agg_session": session_val},
        headers={"X-CSRF-Token": csrf_token},
        follow_redirects=False,
    )
    require_t8p2(resp.status_code == 204, f"Logout failed: {resp.status_code}")

    # Try to use the same session again
    resp2 = client.post(
        "/api/v1/auth/logout",
        cookies={"__Host-agg_session": session_val},
        headers={"X-CSRF-Token": csrf_token},
        follow_redirects=False,
    )
    assert resp2.status_code == 401, (
        f"Session should be refused after logout, got {resp2.status_code}"
    )


@RED_T8P2
@pytest.mark.pg
def test_logout_clears_cookie(pg_url, app_url, owner_url, pg_roles):
    """Logout clears the __Host-agg_session cookie."""
    client, idp_ext, org_id, clock, slug, user_id, sub = _build_env(pg_url, owner_url)

    cb_resp, _, _, _ = _full_login_flow(client, idp_ext, slug, sub=sub)
    require_t8p2(cb_resp.status_code in (302, 200),
                  f"Login failed: {cb_resp.status_code}")

    session_val = _extract_session_cookie(cb_resp)
    assert session_val is not None

    try:
        body = cb_resp.json()
        csrf_token = body.get("csrf_token")
    except Exception:
        csrf_token = None

    if csrf_token is None:
        raise T8P2Pending("Cannot determine CSRF token from callback")

    resp = client.post(
        "/api/v1/auth/logout",
        cookies={"__Host-agg_session": session_val},
        headers={"X-CSRF-Token": csrf_token},
        follow_redirects=False,
    )
    require_t8p2(resp.status_code == 204, f"Logout failed: {resp.status_code}")

    # Check that __Host-agg_session is cleared
    set_cookies = resp.headers.get_list("set-cookie")
    cleared = False
    for sc in set_cookies:
        if "__Host-agg_session" in sc:
            sc_lower = sc.lower()
            if "max-age=0" in sc_lower or '__host-agg_session=""' in sc_lower or "__host-agg_session=;" in sc_lower:
                cleared = True
    assert cleared, (
        f"__Host-agg_session not cleared in logout: {set_cookies}"
    )
