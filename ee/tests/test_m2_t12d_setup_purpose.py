"""T12d d4 exit: /auth/setup consumes only the admin bootstrap code.

Kept apart from the frozen ``test_t8p2_setup_code.py`` (M2 freeze rule);
reuses its helpers.
"""
from __future__ import annotations

import json
import uuid as _uuid
from urllib.parse import parse_qs, urlparse

import pytest

from .t8p2_helpers import (
    FakeClock,
    FakeIdP,
    FakeIdPExtended,
    FakeOidcHttp,
    make_test_app,
    safe_resolve,
    ensure_at_head,
    seed_org_with_oidc,
    _conninfo,
)
from .test_t8p2_setup_code import (
    _make_client,
    _run_migrate_main,
    _unique_slug,
)


# ===================================================================
# T12d d4 exit: /auth/setup consumes only the admin bootstrap code
# ===================================================================

def _migrate_and_bootstrap(pg_url, owner_url):
    """Run migrate, then the full /setup + callback bootstrap flow.

    Returns ``org_id``.
    """
    slug = _unique_slug("setuppurp")
    issuer = "https://idp.example.com"
    client_id = "test-client-id"
    sub = f"bootstrap-admin-{_uuid.uuid4().hex[:8]}"

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
    events = {}
    for line in output.strip().split("\n"):
        try:
            parsed = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict) and "event" in parsed:
            events[parsed["event"]] = parsed
    assert "setup_code" in events, "migrate printed no setup_code"
    assert "genesis_code" in events, "migrate printed no genesis_code"

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

    resp = client.post(
        "/api/v1/auth/setup",
        json={"org": slug, "code": events["setup_code"]["code"]},
    )
    assert resp.status_code in (200, 302), resp.text
    redirect_url = resp.json()["redirect"]
    params = parse_qs(urlparse(redirect_url).query)
    state = params["state"][0]
    agg_login_val = None
    for sc in resp.headers.get_list("set-cookie"):
        if sc.startswith("agg_login="):
            agg_login_val = sc.split("=", 1)[1].split(";")[0]
    if agg_login_val is None:
        login_resp = client.get(redirect_url, follow_redirects=False)
        for sc in login_resp.headers.get_list("set-cookie"):
            if sc.startswith("agg_login="):
                agg_login_val = sc.split("=", 1)[1].split(";")[0]
        new_params = parse_qs(
            urlparse(login_resp.headers.get("location", "")).query)
        if "state" in new_params:
            params = new_params
            state = params["state"][0]
    assert agg_login_val is not None, "no agg_login cookie"
    code = idp_ext.issue_code(
        nonce=params["nonce"][0],
        code_challenge=params["code_challenge"][0],
        sub=sub, email="admin@example.com",
    )
    cb_resp = client.get(
        "/api/v1/auth/callback",
        params={"code": code, "state": state},
        cookies={"agg_login": agg_login_val},
        follow_redirects=False,
    )
    assert cb_resp.status_code in (200, 302), cb_resp.text
    return org_id


def _code_rows(app_url, org_id):
    import psycopg
    with psycopg.connect(_conninfo(app_url)) as conn:
        conn.execute(
            "SELECT set_config('app.org_id', %s, false)", [str(org_id)])
        return conn.execute(
            "SELECT purpose, used_at FROM setup_codes WHERE org_id = %s",
            [org_id],
        ).fetchall()


@pytest.mark.pg
def test_auth_setup_consumes_only_admin_bootstrap_code(
        pg_url, app_url, owner_url, pg_roles):
    """Admin bootstrap leaves the org's registry_genesis code unused."""
    org_id = _migrate_and_bootstrap(pg_url, owner_url)
    rows = _code_rows(app_url, org_id)
    genesis = [r for r in rows if r[0] == "registry_genesis"]
    admin = [r for r in rows if r[0] == "admin_bootstrap"]
    assert len(genesis) == 1 and genesis[0][1] is None, rows
    assert len(admin) == 1 and admin[0][1] is not None, rows


@pytest.mark.pg
def test_auth_setup_refuses_genesis_code(
        pg_url, app_url, owner_url, pg_roles):
    """Twin: the registry_genesis code is refused at /auth/setup."""
    slug = _unique_slug("setupgen")
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
    genesis_code = None
    for line in output.strip().split("\n"):
        try:
            parsed = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict) and parsed.get("event") == "genesis_code":
            genesis_code = parsed["code"]
    assert genesis_code is not None, "migrate printed no genesis_code"

    app, _, _ = make_test_app(
        pg_url=pg_url, clock=FakeClock(), oidc_http=FakeOidcHttp(),
        resolve=safe_resolve, oidc_allow_hosts="idp.example.com",
    )
    client = _make_client(app)
    resp = client.post(
        "/api/v1/auth/setup", json={"org": slug, "code": genesis_code},
    )
    assert 400 <= resp.status_code < 500, resp.status_code
    rows = _code_rows(app_url, org_id)
    genesis = [r for r in rows if r[0] == "registry_genesis"]
    admin = [r for r in rows if r[0] == "admin_bootstrap"]
    assert len(genesis) == 1 and genesis[0][1] is None, rows
    assert len(admin) == 1 and admin[0][1] is None, rows
