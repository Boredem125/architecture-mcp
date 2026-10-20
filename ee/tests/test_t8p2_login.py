"""T8 part 2: login route tests.

Injection contract for the build
=================================

``create_app(settings=..., clock=FakeClock, oidc_http=<object with
get_json(url)->dict and post_form(url, data)->dict>,
resolve=<callable host->list[str]>)``

Settings gains ``public_url``, ``oidc_secrets_dir``, ``oidc_allow_hosts``.

Tests cover:
- Unknown slug returns 404, same body as another unknown slug (no info leak)
- 302 Location has exact redirect_uri, S256 challenge, state, nonce
- ``agg_login`` cookie: Secure, HttpOnly, SameSite=Lax, Path, Max-Age 600
- HTTP discovery issuer or private-address issuer refused
"""
from __future__ import annotations

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
    private_resolve,
    ensure_at_head,
    seed_org_with_oidc,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_client(app):
    """Return an httpx TestClient with base_url='https://testserver'."""
    try:
        from starlette.testclient import TestClient
    except ImportError as exc:
        raise T8P2Pending(f"starlette not available: {exc}") from exc
    return TestClient(app, base_url="https://testserver")


def _unique_slug(prefix: str) -> str:
    return f"{prefix}-{_uuid.uuid4().hex[:8]}"


def _build_app_with_idp(pg_url, owner_url, *, slug=None, resolve=None):
    """Wire up a fake IdP, seed an org, build the app. Returns (client, idp_ext, org_id, clock)."""
    if slug is None:
        slug = _unique_slug("login")
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
        resolve=resolve or safe_resolve,
        oidc_allow_hosts="idp.example.com",
    )
    client = _make_client(app)
    return client, idp_ext, org_id, clock, slug


def _is_route_missing_404(resp) -> bool:
    """Return True if the 404 is FastAPI's default (route not registered)."""
    if resp.status_code != 404:
        return False
    try:
        body = resp.json()
    except Exception:
        return False
    return body == {"detail": "Not Found"}


# ===================================================================
# Unknown slug
# ===================================================================



@pytest.mark.pg
def test_login_unknown_slug_404(pg_url, app_url, owner_url, pg_roles):
    """GET /api/v1/auth/login?org=nonexistent returns 404."""
    clock = FakeClock()
    oidc_http = FakeOidcHttp()
    ensure_at_head(pg_url)

    app, _, _ = make_test_app(
        pg_url=pg_url, clock=clock, oidc_http=oidc_http,
        resolve=safe_resolve,
    )
    client = _make_client(app)

    resp = client.get(
        "/api/v1/auth/login", params={"org": "nonexistent-slug"},
        follow_redirects=False,
    )
    if _is_route_missing_404(resp):
        raise T8P2Pending("Route /api/v1/auth/login not registered")
    assert resp.status_code == 404



@pytest.mark.pg
def test_login_unknown_slug_same_body(pg_url, app_url, owner_url, pg_roles):
    """Two different unknown slugs return the same 404 body (no info leak)."""
    clock = FakeClock()
    oidc_http = FakeOidcHttp()
    ensure_at_head(pg_url)

    app, _, _ = make_test_app(
        pg_url=pg_url, clock=clock, oidc_http=oidc_http,
        resolve=safe_resolve,
    )
    client = _make_client(app)

    resp1 = client.get("/api/v1/auth/login", params={"org": "unknown-aaa"},
                       follow_redirects=False)
    resp2 = client.get("/api/v1/auth/login", params={"org": "unknown-bbb"},
                       follow_redirects=False)
    if _is_route_missing_404(resp1):
        raise T8P2Pending("Route /api/v1/auth/login not registered")

    assert resp1.status_code == 404
    assert resp2.status_code == 404
    assert resp1.json() == resp2.json(), (
        "Different unknown slugs must return identical bodies"
    )


# ===================================================================
# Successful login -> 302 with correct parameters
# ===================================================================



@pytest.mark.pg
def test_login_302_redirect_uri(pg_url, app_url, owner_url, pg_roles):
    """302 Location has exact redirect_uri matching AGG_PUBLIC_URL + callback path."""
    client, _, _, _, slug = _build_app_with_idp(pg_url, owner_url)

    resp = client.get("/api/v1/auth/login", params={"org": slug},
                      follow_redirects=False)
    if _is_route_missing_404(resp):
        raise T8P2Pending("Route /api/v1/auth/login not registered")
    assert resp.status_code == 302, f"Expected 302, got {resp.status_code}"

    location = resp.headers["location"]
    params = parse_qs(urlparse(location).query)
    assert params["redirect_uri"] == ["https://testserver/api/v1/auth/callback"]



@pytest.mark.pg
def test_login_302_s256_challenge(pg_url, app_url, owner_url, pg_roles):
    """302 Location has code_challenge_method=S256 and a code_challenge."""
    client, _, _, _, slug = _build_app_with_idp(pg_url, owner_url)

    resp = client.get("/api/v1/auth/login", params={"org": slug},
                      follow_redirects=False)
    if _is_route_missing_404(resp):
        raise T8P2Pending("Route /api/v1/auth/login not registered")
    assert resp.status_code == 302

    params = parse_qs(urlparse(resp.headers["location"]).query)
    assert params["code_challenge_method"] == ["S256"]
    assert "code_challenge" in params
    assert len(params["code_challenge"][0]) > 20



@pytest.mark.pg
def test_login_302_state_nonce(pg_url, app_url, owner_url, pg_roles):
    """302 Location has state and nonce query parameters."""
    client, _, _, _, slug = _build_app_with_idp(pg_url, owner_url)

    resp = client.get("/api/v1/auth/login", params={"org": slug},
                      follow_redirects=False)
    if _is_route_missing_404(resp):
        raise T8P2Pending("Route /api/v1/auth/login not registered")
    assert resp.status_code == 302

    params = parse_qs(urlparse(resp.headers["location"]).query)
    assert "state" in params, "state missing"
    assert "nonce" in params, "nonce missing"
    assert params["response_type"] == ["code"]
    assert "openid" in params["scope"][0]


# ===================================================================
# agg_login cookie attributes
# ===================================================================



@pytest.mark.pg
def test_login_cookie_attributes(pg_url, app_url, owner_url, pg_roles):
    """agg_login cookie: Secure, HttpOnly, SameSite=Lax, Path=/api/v1/auth, Max-Age=600."""
    client, _, _, _, slug = _build_app_with_idp(pg_url, owner_url)

    resp = client.get("/api/v1/auth/login", params={"org": slug},
                      follow_redirects=False)
    if _is_route_missing_404(resp):
        raise T8P2Pending("Route /api/v1/auth/login not registered")
    assert resp.status_code == 302

    # Find agg_login cookie in raw Set-Cookie headers
    set_cookies = resp.headers.get_list("set-cookie")
    agg_login_cookie = None
    for sc in set_cookies:
        if sc.startswith("agg_login="):
            agg_login_cookie = sc
            break

    assert agg_login_cookie is not None, (
        f"agg_login cookie not found in: {set_cookies}"
    )

    sc_lower = agg_login_cookie.lower()
    assert "secure" in sc_lower, "agg_login must be Secure"
    assert "httponly" in sc_lower, "agg_login must be HttpOnly"
    assert "samesite=lax" in sc_lower, "agg_login must be SameSite=Lax"
    assert "path=/api/v1/auth" in sc_lower, (
        f"agg_login Path must be /api/v1/auth: {agg_login_cookie}"
    )
    assert "max-age=600" in sc_lower, "agg_login Max-Age must be 600"


# ===================================================================
# HTTP discovery or private-address issuer refused
# ===================================================================



@pytest.mark.pg
def test_login_http_issuer_refused(pg_url, app_url, owner_url, pg_roles):
    """An org with an http:// (not https) issuer is refused during login."""
    slug = _unique_slug("httpiss")
    http_issuer = "http://insecure.example.com"
    client_id = "test-client-id"

    clock = FakeClock()
    oidc_http = FakeOidcHttp()
    ensure_at_head(pg_url)
    seed_org_with_oidc(owner_url, slug=slug, issuer=http_issuer, client_id=client_id)

    app, _, _ = make_test_app(
        pg_url=pg_url, clock=clock, oidc_http=oidc_http,
        resolve=safe_resolve,
    )
    client = _make_client(app)

    resp = client.get("/api/v1/auth/login", params={"org": slug},
                      follow_redirects=False)
    if _is_route_missing_404(resp):
        raise T8P2Pending("Route /api/v1/auth/login not registered")
    assert resp.status_code >= 400, (
        f"HTTP issuer should be refused, got {resp.status_code}"
    )



@pytest.mark.pg
def test_login_private_address_issuer_refused(pg_url, app_url, owner_url, pg_roles):
    """An issuer that resolves to a private address is refused."""
    slug = _unique_slug("priviss")
    issuer = "https://internal.corp.local"
    client_id = "test-client-id"

    clock = FakeClock()
    oidc_http = FakeOidcHttp()
    disc_url = issuer + "/.well-known/openid-configuration"
    oidc_http.set_get_json(disc_url, {
        "issuer": issuer,
        "authorization_endpoint": issuer + "/authorize",
        "token_endpoint": issuer + "/token",
        "jwks_uri": issuer + "/jwks",
    })

    ensure_at_head(pg_url)
    seed_org_with_oidc(owner_url, slug=slug, issuer=issuer, client_id=client_id)

    app, _, _ = make_test_app(
        pg_url=pg_url, clock=clock, oidc_http=oidc_http,
        resolve=private_resolve,
    )
    client = _make_client(app)

    resp = client.get("/api/v1/auth/login", params={"org": slug},
                      follow_redirects=False)
    if _is_route_missing_404(resp):
        raise T8P2Pending("Route /api/v1/auth/login not registered")
    assert resp.status_code >= 400, (
        f"Private-address issuer should be refused, got {resp.status_code}"
    )
