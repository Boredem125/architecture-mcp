"""Shared helpers for T8 part 2 tests.

Provides:
- ``T8P2Pending`` -- named exception for strict xfail.
- ``RED_T8P2`` -- pytest marker for strict xfail on T8P2Pending.
- ``require_t8p2`` -- guard that raises T8P2Pending when a condition fails.
- ``try_import_auth`` -- lazy import of ``agg_cp.auth`` with graceful T8P2Pending.
- ``FakeOidcHttp`` -- fake oidc_http object with ``get_json``/``post_form``.
- ``FakeIdPExtended`` -- extends FakeIdP with discovery, authorization, and token endpoints.
- ``make_test_app`` -- build a test FastAPI app with the T8P2 injection contract.
- ``safe_resolve`` -- public-IP resolver that refuses private addresses.
"""
from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
import secrets
import uuid
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse

import pytest

from .fake_idp import FakeClock, FakeIdP


# ---------------------------------------------------------------------------
# Named exception + xfail marker
# ---------------------------------------------------------------------------

class T8P2Pending(Exception):
    """T8 part 2 auth routes / migration not built yet."""


RED_T8P2 = pytest.mark.xfail(
    raises=(T8P2Pending,),
    strict=True,
    reason="T8 part 2 not implemented yet",
)


def require_t8p2(cond: bool, msg: str) -> None:
    """Raise T8P2Pending if *cond* is false."""
    if not cond:
        raise T8P2Pending(msg)


def guard_import(exc: Exception) -> None:
    """Convert ImportError / AttributeError into T8P2Pending."""
    if isinstance(exc, (ImportError, AttributeError, ModuleNotFoundError)):
        raise T8P2Pending(str(exc)) from exc
    raise exc


# ---------------------------------------------------------------------------
# Fake OIDC HTTP transport
# ---------------------------------------------------------------------------

class FakeOidcHttp:
    """Fake HTTP transport satisfying the ``oidc_http`` injection contract.

    Stores canned responses for ``get_json(url)`` and ``post_form(url, data)``.
    """

    def __init__(self) -> None:
        self._get_responses: dict[str, dict] = {}
        self._post_responses: dict[str, Any] = {}
        self._post_handler: dict[str, Any] = {}

    def set_get_json(self, url: str, response: dict) -> None:
        self._get_responses[url] = response

    def set_post_form(self, url: str, response: dict) -> None:
        self._post_responses[url] = response

    def set_post_handler(self, url: str, handler) -> None:
        """Set a callable handler for POST to *url*. handler(data) -> dict."""
        self._post_handler[url] = handler

    def get_json(self, url: str) -> dict:
        if url in self._get_responses:
            return self._get_responses[url]
        raise RuntimeError(f"FakeOidcHttp: no canned GET for {url}")

    def post_form(self, url: str, data: dict) -> dict:
        if url in self._post_handler:
            return self._post_handler[url](data)
        if url in self._post_responses:
            return self._post_responses[url]
        raise RuntimeError(f"FakeOidcHttp: no canned POST for {url}")


# ---------------------------------------------------------------------------
# Extended fake IdP: discovery + authorization + token endpoint
# ---------------------------------------------------------------------------

class FakeIdPExtended:
    """Wraps a FakeIdP and adds discovery doc, authorization endpoint
    semantics, and token endpoint with PKCE verification.

    The ``issuer`` must be https for the URL-safety checks.
    """

    def __init__(
        self,
        idp: FakeIdP,
        *,
        clock: FakeClock,
        client_secret: str | None = None,
    ) -> None:
        self.idp = idp
        self.clock = clock
        self.client_secret = client_secret
        # Endpoints
        self.issuer = idp.issuer
        self.discovery_url = idp.issuer.rstrip("/") + "/.well-known/openid-configuration"
        self.authorization_endpoint = idp.issuer.rstrip("/") + "/authorize"
        self.token_endpoint = idp.issuer.rstrip("/") + "/token"
        self.jwks_uri = idp.issuer.rstrip("/") + "/jwks"
        # Track issued codes for the token endpoint
        self._codes: dict[str, dict] = {}

    def discovery_doc(self) -> dict:
        return {
            "issuer": self.issuer,
            "authorization_endpoint": self.authorization_endpoint,
            "token_endpoint": self.token_endpoint,
            "jwks_uri": self.jwks_uri,
            "response_types_supported": ["code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
        }

    def issue_code(
        self,
        *,
        nonce: str,
        code_challenge: str,
        code_challenge_method: str = "S256",
        sub: str = "user-1",
        email: str = "user@example.com",
    ) -> str:
        """Issue an authorization code and store its parameters."""
        code = secrets.token_urlsafe(32)
        self._codes[code] = {
            "nonce": nonce,
            "code_challenge": code_challenge,
            "code_challenge_method": code_challenge_method,
            "sub": sub,
            "email": email,
        }
        return code

    def handle_token_request(self, data: dict) -> dict:
        """Handle a token endpoint request. Checks PKCE and returns id_token."""
        code = data.get("code", "")
        code_verifier = data.get("code_verifier", "")

        if code not in self._codes:
            return {"error": "invalid_grant"}

        code_data = self._codes.pop(code)

        # Verify PKCE S256
        if code_data["code_challenge_method"] == "S256":
            digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
            computed = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
            if computed != code_data["code_challenge"]:
                return {"error": "invalid_grant", "error_description": "PKCE mismatch"}

        # Mint the id_token
        now = self.clock.now()
        id_token = self.idp.mint(
            now=now,
            nonce=code_data["nonce"],
            sub=code_data["sub"],
            email=code_data["email"],
        )

        return {
            "access_token": secrets.token_urlsafe(16),
            "token_type": "Bearer",
            "id_token": id_token,
        }

    def handle_token_request_wrong_pkce(self, data: dict) -> dict:
        """Token endpoint that always fails PKCE verification."""
        return {"error": "invalid_grant", "error_description": "PKCE mismatch"}

    def wire_to(self, http: FakeOidcHttp) -> None:
        """Register this IdP's endpoints on the fake HTTP transport."""
        http.set_get_json(self.discovery_url, self.discovery_doc())
        http.set_get_json(self.jwks_uri, self.idp.jwks())
        http.set_post_handler(self.token_endpoint, self.handle_token_request)


# ---------------------------------------------------------------------------
# resolve helper
# ---------------------------------------------------------------------------

def safe_resolve(host: str) -> list[str]:
    """Resolve that returns a public IP for known test hosts.

    For test hosts matching our fake IdP (idp.example.com, etc.),
    returns a safe public IP.
    """
    # Return a safe public IP for any host
    return ["93.184.216.34"]


def private_resolve(host: str) -> list[str]:
    """Resolve that returns a private IP (for testing refusal)."""
    return ["127.0.0.1"]


# ---------------------------------------------------------------------------
# Test app builder
# ---------------------------------------------------------------------------

def make_test_app(
    *,
    pg_url: str,
    clock: FakeClock | None = None,
    oidc_http: FakeOidcHttp | None = None,
    resolve=None,
    public_url: str = "https://testserver",
    oidc_secrets_dir: str | None = None,
    oidc_allow_hosts: str | None = None,
):
    """Build a test app using the T8P2 injection contract.

    Returns (app, clock, oidc_http).  Raises T8P2Pending if the
    contract is not yet implemented.
    """
    if clock is None:
        clock = FakeClock()
    if oidc_http is None:
        oidc_http = FakeOidcHttp()
    if resolve is None:
        resolve = safe_resolve

    try:
        from agg_cp.app import Settings, create_app
    except (ImportError, ModuleNotFoundError) as exc:
        raise T8P2Pending(f"agg_cp.app not importable: {exc}") from exc

    try:
        settings = Settings(
            db_url=pg_url,
            public_url=public_url,
            oidc_secrets_dir=oidc_secrets_dir,
            oidc_allow_hosts=oidc_allow_hosts,
        )
    except TypeError as exc:
        raise T8P2Pending(
            f"Settings does not accept T8P2 fields yet: {exc}"
        ) from exc

    try:
        app = create_app(
            settings=settings,
            clock=clock,
            oidc_http=oidc_http,
            resolve=resolve,
        )
    except TypeError as exc:
        raise T8P2Pending(
            f"create_app does not accept T8P2 params yet: {exc}"
        ) from exc

    return app, clock, oidc_http


def _conninfo(url: str) -> str:
    """Strip +psycopg for raw psycopg connect."""
    return url.replace("+psycopg", "")


def ensure_at_head(pg_url: str) -> None:
    """Run alembic upgrade head (idempotent)."""
    from agg_cp.db import alembic_config
    from alembic import command as alembic_cmd

    cfg = alembic_config(pg_url)
    alembic_cmd.upgrade(cfg, "head")


def seed_org_with_oidc(
    owner_url: str,
    *,
    slug: str = "test-org",
    issuer: str = "https://idp.example.com",
    client_id: str = "test-client-id",
) -> uuid.UUID:
    """Seed an org with OIDC config and return the org_id."""
    import psycopg

    org_id = uuid.uuid4()
    conninfo = _conninfo(owner_url)
    try:
        with psycopg.connect(conninfo) as conn:
            conn.execute(
                "SELECT set_config('app.org_id', %s, false)", [str(org_id)]
            )
            conn.execute(
                "INSERT INTO orgs (id, org_id, name, slug, created_at) "
                "VALUES (%s, %s, %s, %s, now())",
                [org_id, org_id, f"Org {slug}", slug],
            )
            conn.execute(
                "INSERT INTO org_oidc_config "
                "(id, org_id, issuer, client_id, created_at) "
                "VALUES (%s, %s, %s, %s, now())",
                [uuid.uuid4(), org_id, issuer, client_id],
            )
            conn.commit()
    except Exception as exc:
        raise T8P2Pending(f"Cannot seed org: {exc}") from exc
    return org_id


def unique_sub() -> str:
    """Return a unique OIDC subject identifier."""
    return f"user-{uuid.uuid4().hex[:12]}"


def seed_user(
    owner_url: str,
    org_id: uuid.UUID,
    *,
    iss: str = "https://idp.example.com",
    sub: str | None = None,
    email: str = "user@example.com",
    status: str = "active",
) -> tuple[uuid.UUID, str]:
    """Seed a user and return (user_id, sub)."""
    import psycopg

    if sub is None:
        sub = unique_sub()
    user_id = uuid.uuid4()
    conninfo = _conninfo(owner_url)
    with psycopg.connect(conninfo) as conn:
        conn.execute(
            "SELECT set_config('app.org_id', %s, false)", [str(org_id)]
        )
        conn.execute(
            "INSERT INTO users (id, org_id, oidc_issuer, oidc_subject, "
            "email, status, created_at) "
            "VALUES (%s, %s, %s, %s, %s, %s, now())",
            [user_id, org_id, iss, sub, email, status],
        )
        conn.commit()
    return user_id, sub


def seed_admin_binding(
    owner_url: str,
    org_id: uuid.UUID,
    user_id: uuid.UUID,
) -> uuid.UUID:
    """Seed an admin role binding and return its id."""
    import psycopg

    binding_id = uuid.uuid4()
    conninfo = _conninfo(owner_url)
    with psycopg.connect(conninfo) as conn:
        conn.execute(
            "SELECT set_config('app.org_id', %s, false)", [str(org_id)]
        )
        conn.execute(
            "INSERT INTO role_bindings "
            "(id, org_id, user_id, scope_type, scope_id, role, created_at) "
            "VALUES (%s, %s, %s, 'org', %s, 'admin', now())",
            [binding_id, org_id, user_id, org_id],
        )
        conn.commit()
    return binding_id
