"""Authentication routes and session/CSRF dependencies for the control plane.

Routes: /api/v1/auth/{login,callback,setup,logout}
Dependencies: require_session, require_csrf

Security invariants:
- Time only from the injected Clock; no module-level mutable state.
- Every DB access as agg_app inside a transaction that sets app.org_id
  with set_config(..., true).
- Pre-auth org lookup only via org_login_config(slug).
- Tokens from secrets, stored as sha256 hex; all secret compares via
  hmac.compare_digest.
- Callback atomically consumes the login transaction with
  DELETE ... RETURNING (no separate SELECT).
- Cookies exactly as the design.
- Error bodies carry only short non-secret reason codes.
- No token/code/secret in logs.
- Outbound OIDC HTTP only through the injected oidc_http after
  check_fetch_url; token_endpoint checked before POST.
- authorization_endpoint required to be https (browser redirect).
- Bootstrap guarded by pg_advisory_xact_lock; setup_code marked used
  atomically with UPDATE ... WHERE used_at IS NULL RETURNING.
"""
from __future__ import annotations

import base64
import datetime as dt
import hashlib
import hmac
import json as _json
import os as _os
import secrets
import uuid
from typing import Any, Callable
from urllib.parse import urlencode, urlparse

import psycopg

from fastapi import APIRouter, Request, Response
from fastapi.responses import JSONResponse

from agg_cp.clock import Clock
from agg_cp.oidc import (
    HttpJWKSProvider,
    IdTokenVerifier,
    OrgOIDCConfig,
    check_fetch_url,
    fetch_discovery,
    OIDCError,
    IdTokenError,
    UnsafeURLError,
)


# ---------------------------------------------------------------------------
# Constants (immutable module-level state only)
# ---------------------------------------------------------------------------

_SESSION_ABSOLUTE_S = 12 * 60 * 60   # 12 hours
_SESSION_IDLE_S = 30 * 60            # 30 minutes
_LOGIN_TXN_TTL_S = 600               # 10 minutes


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _sha256_hex(value: str) -> str:
    """Return hex SHA-256 of a UTF-8 string."""
    return hashlib.sha256(value.encode()).hexdigest()


def _pkce_challenge_s256(verifier: str) -> str:
    """Compute S256 PKCE code_challenge from verifier."""
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _sync_conninfo(db_url: str) -> str:
    """Convert async SQLAlchemy URL to psycopg conninfo."""
    return db_url.replace("+psycopg", "")


def _app_conn(conninfo: str):
    """Open a psycopg connection and SET ROLE agg_app for RLS enforcement."""
    conn = psycopg.connect(conninfo)
    conn.execute("SET ROLE agg_app")
    return conn


def csrf_token_for(session_token: str) -> str:
    """Derive the CSRF token deterministically from a session token.

    csrf_token = base64url_nopad(HMAC-SHA256(key=session_token bytes,
    msg=b"agg-csrf-v1")).  Knowing the CSRF token does not reveal the
    session token.  Exported so tests can compute it without the body.
    """
    mac = hmac.new(
        session_token.encode(), b"agg-csrf-v1", hashlib.sha256,
    ).digest()
    return base64.urlsafe_b64encode(mac).rstrip(b"=").decode("ascii")


def validate_session(conn, request, clock):
    """Validate the ``__Host-agg_session`` cookie on *conn*.

    Sets ``app.org_id`` transaction-locally, checks token hash, expiry,
    idle timeout, revocation, and touches ``last_seen_at``.

    Returns ``((org_id, user_id, session_id, session_token, csrf_hash), None)``
    on success or ``(None, error_response)`` on failure.

    Does **not** commit; the caller is responsible for commit/rollback.
    Used by both the auth router (logout) and the api router (all T9
    routes), eliminating duplicate session validation logic.
    """
    cookie = request.cookies.get("__Host-agg_session")
    if not cookie:
        return None, JSONResponse({"error": "no_session"}, status_code=401)

    parts = cookie.split(".", 1)
    if len(parts) != 2:
        return None, JSONResponse({"error": "bad_session"}, status_code=401)

    try:
        org_id = uuid.UUID(parts[0])
    except ValueError:
        return None, JSONResponse({"error": "bad_session"}, status_code=401)

    token = parts[1]
    token_hash = _sha256_hex(token)
    now = clock.now()

    conn.execute(
        "SELECT set_config('app.org_id', %s, true)", [str(org_id)],
    )
    row = conn.execute(
        "SELECT id, user_id, expires_at, last_seen_at, revoked_at, "
        "csrf_hash FROM web_sessions WHERE token_hash = %s",
        [token_hash],
    ).fetchone()

    if row is None:
        return None, JSONResponse(
            {"error": "session_not_found"}, status_code=401,
        )

    session_id, user_id, expires_at, last_seen_at, revoked_at, csrf_hash = row

    if revoked_at is not None:
        return None, JSONResponse(
            {"error": "session_revoked"}, status_code=401,
        )
    if now >= expires_at:
        return None, JSONResponse(
            {"error": "session_expired"}, status_code=401,
        )
    idle = (now - last_seen_at).total_seconds()
    if idle >= _SESSION_IDLE_S:
        return None, JSONResponse(
            {"error": "session_idle"}, status_code=401,
        )

    conn.execute(
        "UPDATE web_sessions SET last_seen_at = %s WHERE id = %s",
        [now, session_id],
    )

    return (org_id, user_id, session_id, token, csrf_hash), None


# ---------------------------------------------------------------------------
# Route factory
# ---------------------------------------------------------------------------

def build_auth_router(
    *,
    db_url: str,
    clock: Clock,
    oidc_http: Any,
    resolve: Callable[[str], list[str]],
    public_url: str,
    oidc_secrets_dir: str | None = None,
    oidc_allow_hosts: frozenset[str] = frozenset(),
) -> APIRouter:
    """Build and return the /api/v1/auth router.

    All dependencies are closed over; no module-level mutable state.
    """
    conninfo = _sync_conninfo(db_url)
    router = APIRouter(prefix="/api/v1/auth")
    redirect_uri = public_url.rstrip("/") + "/api/v1/auth/callback"

    # ---------------------------------------------------------------
    # GET /login?org=<slug>
    # ---------------------------------------------------------------
    @router.get("/login")
    def login(org: str) -> Response:
        # Pre-auth org lookup via org_login_config (SECURITY DEFINER)
        with _app_conn(conninfo) as conn:
            row = conn.execute(
                "SELECT org_id, issuer, client_id FROM org_login_config(%s)",
                [org],
            ).fetchone()

        if row is None:
            return JSONResponse({"error": "not_found"}, status_code=404)

        org_id, issuer, client_id = row
        config = OrgOIDCConfig(issuer=issuer, client_id=client_id)

        # Fetch OIDC discovery (SSRF-safe)
        try:
            disc = fetch_discovery(
                config,
                get_json=oidc_http.get_json,
                resolve=resolve,
                allow_hosts=oidc_allow_hosts,
            )
        except (OIDCError, UnsafeURLError):
            return JSONResponse({"error": "idp_error"}, status_code=502)

        authorization_endpoint = disc.get("authorization_endpoint")
        if not authorization_endpoint:
            return JSONResponse({"error": "idp_error"}, status_code=502)

        # M1: authorization_endpoint must be https (browser redirect)
        if urlparse(authorization_endpoint).scheme != "https":
            return JSONResponse({"error": "idp_error"}, status_code=502)

        # Generate PKCE verifier, state, nonce
        pkce_verifier = secrets.token_urlsafe(32)
        code_challenge = _pkce_challenge_s256(pkce_verifier)
        state = secrets.token_urlsafe(32)
        nonce = secrets.token_urlsafe(32)
        state_hash = _sha256_hex(state)

        now = clock.now()
        expires_at = now + dt.timedelta(seconds=_LOGIN_TXN_TTL_S)
        txn_id = uuid.uuid4()

        # Store login transaction
        with _app_conn(conninfo) as conn:
            conn.execute(
                "SELECT set_config('app.org_id', %s, true)", [str(org_id)]
            )
            conn.execute(
                "INSERT INTO login_transactions "
                "(id, org_id, state_hash, nonce, pkce_verifier, bootstrap, "
                "created_at, expires_at) "
                "VALUES (%s, %s, %s, %s, %s, false, %s, %s)",
                [txn_id, org_id, state_hash, nonce, pkce_verifier,
                 now, expires_at],
            )
            conn.commit()

        # Build IdP authorization URL
        params = {
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "scope": "openid email profile",
            "state": state,
            "nonce": nonce,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        }
        auth_url = authorization_endpoint + "?" + urlencode(params)

        # Set agg_login cookie and redirect
        cookie_value = f"{org_id}.{txn_id}"
        resp = Response(status_code=302)
        resp.headers["location"] = auth_url
        resp.set_cookie(
            key="agg_login",
            value=cookie_value,
            secure=True,
            httponly=True,
            samesite="lax",
            path="/api/v1/auth",
            max_age=600,
        )
        return resp

    # ---------------------------------------------------------------
    # GET /callback?code=&state=
    # ---------------------------------------------------------------
    @router.get("/callback")
    def callback(code: str, state: str, request: Request) -> Response:
        # Parse agg_login cookie
        agg_login = request.cookies.get("agg_login")
        if not agg_login:
            return JSONResponse({"error": "missing_cookie"}, status_code=400)

        parts = agg_login.split(".", 1)
        if len(parts) != 2:
            return JSONResponse({"error": "bad_cookie"}, status_code=400)

        try:
            cookie_org_id = uuid.UUID(parts[0])
        except ValueError:
            return JSONResponse({"error": "bad_cookie"}, status_code=400)

        try:
            txn_uuid = uuid.UUID(parts[1])
        except ValueError:
            return JSONResponse({"error": "bad_cookie"}, status_code=400)

        state_hash = _sha256_hex(state)
        now = clock.now()

        # H1: Atomically consume the login transaction with
        # DELETE ... RETURNING (no separate SELECT).
        with _app_conn(conninfo) as conn:
            conn.execute(
                "SELECT set_config('app.org_id', %s, true)",
                [str(cookie_org_id)],
            )
            txn_row = conn.execute(
                "DELETE FROM login_transactions WHERE id = %s "
                "RETURNING id, org_id, state_hash, nonce, pkce_verifier, "
                "bootstrap, expires_at",
                [txn_uuid],
            ).fetchone()
            conn.commit()

        if txn_row is None:
            return JSONResponse(
                {"error": "invalid_transaction"}, status_code=400,
            )

        (_, txn_org_id, txn_state_hash, txn_nonce, txn_pkce_verifier,
         txn_bootstrap, txn_expires_at) = txn_row

        # Check expiry
        if now >= txn_expires_at:
            return JSONResponse({"error": "transaction_expired"}, status_code=400)

        # Check state (constant-time)
        if not hmac.compare_digest(txn_state_hash, state_hash):
            return JSONResponse({"error": "state_mismatch"}, status_code=400)

        # Look up org OIDC config
        with _app_conn(conninfo) as conn:
            conn.execute(
                "SELECT set_config('app.org_id', %s, true)",
                [str(txn_org_id)],
            )
            oidc_row = conn.execute(
                "SELECT issuer, client_id FROM org_oidc_config "
                "WHERE org_id = %s LIMIT 1",
                [txn_org_id],
            ).fetchone()

        if oidc_row is None:
            return JSONResponse({"error": "oidc_config_missing"}, status_code=500)

        issuer, client_id = oidc_row
        config = OrgOIDCConfig(issuer=issuer, client_id=client_id)

        # Fetch discovery for token/JWKS endpoints
        try:
            disc = fetch_discovery(
                config,
                get_json=oidc_http.get_json,
                resolve=resolve,
                allow_hosts=oidc_allow_hosts,
            )
        except (OIDCError, UnsafeURLError):
            return JSONResponse({"error": "idp_error"}, status_code=502)

        token_endpoint = disc.get("token_endpoint")
        jwks_uri = disc.get("jwks_uri")
        if not token_endpoint or not jwks_uri:
            return JSONResponse({"error": "idp_error"}, status_code=502)

        # M1: check_fetch_url on token_endpoint before POST
        try:
            check_fetch_url(
                token_endpoint,
                resolve=resolve,
                allow_hosts=oidc_allow_hosts,
            )
        except UnsafeURLError:
            return JSONResponse({"error": "idp_error"}, status_code=502)

        # Check for client secret file
        client_secret = None
        if oidc_secrets_dir:
            with _app_conn(conninfo) as conn:
                conn.execute(
                    "SELECT set_config('app.org_id', %s, true)",
                    [str(txn_org_id)],
                )
                slug_row = conn.execute(
                    "SELECT slug FROM orgs WHERE id = %s", [txn_org_id],
                ).fetchone()
            if slug_row:
                secret_path = _os.path.join(oidc_secrets_dir, slug_row[0])
                if _os.path.isfile(secret_path):
                    with open(secret_path) as f:
                        client_secret = f.read().strip()

        # Exchange code at token endpoint
        token_data: dict[str, str] = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "code_verifier": txn_pkce_verifier,
            "client_id": client_id,
        }
        if client_secret:
            token_data["client_secret"] = client_secret

        try:
            token_resp = oidc_http.post_form(token_endpoint, token_data)
        except Exception:
            return JSONResponse(
                {"error": "token_exchange_failed"}, status_code=502,
            )

        if "error" in token_resp:
            return JSONResponse(
                {"error": "token_exchange_failed"}, status_code=400,
            )

        id_token_str = token_resp.get("id_token")
        if not id_token_str:
            return JSONResponse({"error": "no_id_token"}, status_code=502)

        # Verify the id_token
        jwks_provider = HttpJWKSProvider(
            jwks_uri,
            get_json=oidc_http.get_json,
            resolve=resolve,
            allow_hosts=oidc_allow_hosts,
        )
        verifier = IdTokenVerifier(clock=clock, jwks=jwks_provider)

        try:
            identity = verifier.verify(
                id_token_str, config=config, nonce=txn_nonce,
            )
        except IdTokenError:
            return JSONResponse({"error": "id_token_invalid"}, status_code=400)

        iss = identity.iss
        sub = identity.sub
        email = identity.claims.get("email", "")

        # Look up user by (iss, sub) under RLS
        with _app_conn(conninfo) as conn:
            conn.execute(
                "SELECT set_config('app.org_id', %s, true)",
                [str(txn_org_id)],
            )
            user_row = conn.execute(
                "SELECT id, email, status FROM users "
                "WHERE oidc_issuer = %s AND oidc_subject = %s",
                [iss, sub],
            ).fetchone()

        if user_row is None:
            if txn_bootstrap:
                return _handle_bootstrap_callback(
                    org_id=txn_org_id, iss=iss, sub=sub, email=email,
                )
            return JSONResponse({"error": "not_provisioned"}, status_code=403)

        user_id = user_row[0]
        return _create_session_response(org_id=txn_org_id, user_id=user_id,
                                         audit_action="login")

    # ---------------------------------------------------------------
    # Helper: create session + response
    # ---------------------------------------------------------------
    def _create_session_response(
        *,
        org_id: uuid.UUID,
        user_id: uuid.UUID,
        audit_action: str,
    ) -> Response:
        session_token = secrets.token_urlsafe(32)
        # CSRF: derive deterministically from session token
        csrf_token = csrf_token_for(session_token)
        token_hash = _sha256_hex(session_token)
        csrf_hash = _sha256_hex(csrf_token)
        session_id = uuid.uuid4()
        now = clock.now()
        expires = now + dt.timedelta(seconds=_SESSION_ABSOLUTE_S)

        with _app_conn(conninfo) as conn:
            conn.execute(
                "SELECT set_config('app.org_id', %s, true)", [str(org_id)],
            )
            conn.execute(
                "INSERT INTO web_sessions "
                "(id, org_id, user_id, token_hash, csrf_hash, "
                "created_at, expires_at, last_seen_at) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
                [session_id, org_id, user_id, token_hash, csrf_hash,
                 now, expires, now],
            )
            conn.execute(
                "INSERT INTO admin_audit (id, org_id, action, detail) "
                "VALUES (%s, %s, %s, %s)",
                [uuid.uuid4(), org_id, audit_action,
                 _json.dumps({"user_id": str(user_id),
                              "session_id": str(session_id)})],
            )
            conn.commit()

        session_cookie = f"{org_id}.{session_token}"
        # Callback 302 carries no JSON body (CSRF ruling)
        resp = Response(status_code=302)
        resp.headers["location"] = "/"
        resp.set_cookie(
            key="__Host-agg_session",
            value=session_cookie,
            secure=True,
            httponly=True,
            samesite="strict",
            path="/",
        )
        # Clear agg_login
        resp.set_cookie(
            key="agg_login",
            value="",
            secure=True,
            httponly=True,
            samesite="lax",
            path="/api/v1/auth",
            max_age=0,
        )
        return resp

    # ---------------------------------------------------------------
    # Helper: bootstrap callback
    # ---------------------------------------------------------------
    def _handle_bootstrap_callback(
        *,
        org_id: uuid.UUID,
        iss: str,
        sub: str,
        email: str,
    ) -> Response:
        # H2: Single transaction guarded by advisory lock
        user_id = uuid.uuid4()
        binding_id = uuid.uuid4()
        session_id = uuid.uuid4()
        session_token = secrets.token_urlsafe(32)
        csrf_token = csrf_token_for(session_token)
        token_hash = _sha256_hex(session_token)
        csrf_hash = _sha256_hex(csrf_token)
        now = clock.now()
        expires = now + dt.timedelta(seconds=_SESSION_ABSOLUTE_S)

        with _app_conn(conninfo) as conn:
            conn.execute(
                "SELECT set_config('app.org_id', %s, true)", [str(org_id)],
            )
            # Advisory lock scoped to bootstrap for this org
            conn.execute(
                "SELECT pg_advisory_xact_lock("
                "hashtext('agg-bootstrap:' || %s::text))",
                [org_id],
            )
            # Check if admin already exists (inside lock)
            admin_row = conn.execute(
                "SELECT id FROM role_bindings WHERE role = 'admin' LIMIT 1",
            ).fetchone()
            if admin_row is not None:
                conn.rollback()
                return JSONResponse({"error": "admin_exists"}, status_code=409)

            # Mark setup code as used atomically
            used_row = conn.execute(
                "UPDATE setup_codes SET used_at = %s "
                "WHERE org_id = %s AND used_at IS NULL "
                "RETURNING id",
                [now, org_id],
            ).fetchone()
            if used_row is None:
                conn.rollback()
                return JSONResponse({"error": "admin_exists"}, status_code=409)

            # Create user (plain INSERT under RLS; unique violation
            # on (oidc_issuer, oidc_subject) means the identity is
            # already bound to another org -- 409 identity_in_use).
            try:
                conn.execute(
                    "INSERT INTO users "
                    "(id, org_id, oidc_issuer, oidc_subject, email, status, "
                    "created_at) "
                    "VALUES (%s, %s, %s, %s, %s, 'active', %s)",
                    [user_id, org_id, iss, sub, email, now],
                )
            except psycopg.errors.UniqueViolation:
                conn.rollback()
                return JSONResponse(
                    {"error": "identity_in_use"}, status_code=409,
                )
            # Create admin role binding
            conn.execute(
                "INSERT INTO role_bindings "
                "(id, org_id, user_id, scope_type, scope_id, role, "
                "created_at) "
                "VALUES (%s, %s, %s, 'org', %s, 'admin', %s)",
                [binding_id, org_id, user_id, org_id, now],
            )
            # Create session
            conn.execute(
                "INSERT INTO web_sessions "
                "(id, org_id, user_id, token_hash, csrf_hash, "
                "created_at, expires_at, last_seen_at) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
                [session_id, org_id, user_id, token_hash, csrf_hash,
                 now, expires, now],
            )
            # Audit: bootstrap_admin
            conn.execute(
                "INSERT INTO admin_audit (id, org_id, action, detail) "
                "VALUES (%s, %s, 'bootstrap_admin', %s)",
                [uuid.uuid4(), org_id,
                 _json.dumps({"user_id": str(user_id)})],
            )
            conn.commit()

        session_cookie = f"{org_id}.{session_token}"
        resp = Response(status_code=302)
        resp.headers["location"] = "/"
        resp.set_cookie(
            key="__Host-agg_session",
            value=session_cookie,
            secure=True,
            httponly=True,
            samesite="strict",
            path="/",
        )
        resp.set_cookie(
            key="agg_login",
            value="",
            secure=True,
            httponly=True,
            samesite="lax",
            path="/api/v1/auth",
            max_age=0,
        )
        return resp

    # ---------------------------------------------------------------
    # POST /setup (JSON {org, code})
    # ---------------------------------------------------------------
    @router.post("/setup")
    async def setup(request: Request) -> Response:
        # Content-type check (JSON only)
        content_type = request.headers.get("content-type", "")
        if "application/json" not in content_type:
            return JSONResponse(
                {"error": "content_type_required"}, status_code=415,
            )

        # Read body
        body_bytes = await request.body()
        try:
            body = _json.loads(body_bytes)
        except (ValueError, TypeError):
            return JSONResponse({"error": "bad_request"}, status_code=400)

        org_slug = body.get("org")
        code_value = body.get("code")
        if not org_slug or not code_value:
            return JSONResponse({"error": "bad_request"}, status_code=400)

        # Look up org via org_login_config
        with _app_conn(conninfo) as conn:
            org_row = conn.execute(
                "SELECT org_id, issuer, client_id FROM org_login_config(%s)",
                [org_slug],
            ).fetchone()

        if org_row is None:
            return JSONResponse({"error": "not_found"}, status_code=404)

        org_id, issuer, client_id = org_row

        # Check if org already has an admin
        with _app_conn(conninfo) as conn:
            conn.execute(
                "SELECT set_config('app.org_id', %s, true)", [str(org_id)],
            )
            admin_exists = conn.execute(
                "SELECT id FROM role_bindings WHERE role = 'admin' LIMIT 1",
            ).fetchone()

        if admin_exists is not None:
            return JSONResponse({"error": "admin_exists"}, status_code=409)

        # L1: Find live setup code with FOR UPDATE in one transaction
        now = clock.now()
        code_hash = _sha256_hex(code_value)

        with _app_conn(conninfo) as conn:
            conn.execute(
                "SELECT set_config('app.org_id', %s, true)", [str(org_id)],
            )
            code_row = conn.execute(
                "SELECT id, code_hash, expires_at, used_at, failed_attempts "
                "FROM setup_codes WHERE org_id = %s "
                "AND used_at IS NULL AND failed_attempts < 5 "
                "ORDER BY created_at DESC LIMIT 1 "
                "FOR UPDATE",
                [org_id],
            ).fetchone()

            if code_row is None:
                conn.rollback()
                return JSONResponse({"error": "invalid_code"}, status_code=400)

            sc_id, stored_hash, sc_expires, _, sc_failures = code_row

            # Check expiry
            if now >= sc_expires:
                conn.rollback()
                return JSONResponse({"error": "code_expired"}, status_code=400)

            # Compare code (constant-time)
            if not hmac.compare_digest(stored_hash, code_hash):
                # L1: atomic increment with guard
                conn.execute(
                    "UPDATE setup_codes "
                    "SET failed_attempts = failed_attempts + 1 "
                    "WHERE id = %s AND failed_attempts < 5 "
                    "RETURNING failed_attempts",
                    [sc_id],
                )
                conn.commit()
                return JSONResponse({"error": "invalid_code"}, status_code=400)

            conn.commit()

        # Code valid -- start bootstrap login transaction
        config = OrgOIDCConfig(issuer=issuer, client_id=client_id)

        try:
            disc = fetch_discovery(
                config,
                get_json=oidc_http.get_json,
                resolve=resolve,
                allow_hosts=oidc_allow_hosts,
            )
        except (OIDCError, UnsafeURLError):
            return JSONResponse({"error": "idp_error"}, status_code=502)

        authorization_endpoint = disc.get("authorization_endpoint")
        if not authorization_endpoint:
            return JSONResponse({"error": "idp_error"}, status_code=502)

        # M1: authorization_endpoint must be https
        if urlparse(authorization_endpoint).scheme != "https":
            return JSONResponse({"error": "idp_error"}, status_code=502)

        pkce_verifier = secrets.token_urlsafe(32)
        code_challenge = _pkce_challenge_s256(pkce_verifier)
        state = secrets.token_urlsafe(32)
        nonce = secrets.token_urlsafe(32)
        state_hash = _sha256_hex(state)

        txn_now = clock.now()
        txn_expires = txn_now + dt.timedelta(seconds=_LOGIN_TXN_TTL_S)
        txn_id = uuid.uuid4()

        with _app_conn(conninfo) as conn:
            conn.execute(
                "SELECT set_config('app.org_id', %s, true)", [str(org_id)],
            )
            conn.execute(
                "INSERT INTO login_transactions "
                "(id, org_id, state_hash, nonce, pkce_verifier, bootstrap, "
                "created_at, expires_at) "
                "VALUES (%s, %s, %s, %s, %s, true, %s, %s)",
                [txn_id, org_id, state_hash, nonce, pkce_verifier,
                 txn_now, txn_expires],
            )
            conn.commit()

        params = {
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "scope": "openid email profile",
            "state": state,
            "nonce": nonce,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        }
        auth_url = authorization_endpoint + "?" + urlencode(params)

        cookie_value = f"{org_id}.{txn_id}"
        resp = JSONResponse({"redirect": auth_url})
        resp.set_cookie(
            key="agg_login",
            value=cookie_value,
            secure=True,
            httponly=True,
            samesite="lax",
            path="/api/v1/auth",
            max_age=600,
        )
        return resp

    # ---------------------------------------------------------------
    # POST /logout
    # ---------------------------------------------------------------
    @router.post("/logout", openapi_extra={"x-agg-rbac": {"role": "session", "scope": "session"}})
    def logout(request: Request) -> Response:
        # require_session
        session_result = _do_require_session(request)
        if isinstance(session_result, Response):
            return session_result
        org_id, user_id, session_id = session_result

        # require_csrf
        csrf_result = _do_require_csrf(request, org_id, session_id)
        if isinstance(csrf_result, Response):
            return csrf_result

        # Revoke session
        now = clock.now()
        with _app_conn(conninfo) as conn:
            conn.execute(
                "SELECT set_config('app.org_id', %s, true)", [str(org_id)],
            )
            conn.execute(
                "UPDATE web_sessions SET revoked_at = %s WHERE id = %s",
                [now, session_id],
            )
            conn.execute(
                "INSERT INTO admin_audit (id, org_id, action, detail) "
                "VALUES (%s, %s, 'logout', %s)",
                [uuid.uuid4(), org_id,
                 _json.dumps({"user_id": str(user_id),
                              "session_id": str(session_id)})],
            )
            conn.commit()

        resp = Response(status_code=204)
        resp.set_cookie(
            key="__Host-agg_session",
            value="",
            secure=True,
            httponly=True,
            samesite="strict",
            path="/",
            max_age=0,
        )
        return resp

    # ---------------------------------------------------------------
    # require_session (internal)
    # ---------------------------------------------------------------
    def _do_require_session(
        request: Request,
    ) -> tuple[uuid.UUID, uuid.UUID, uuid.UUID] | Response:
        """Parse session cookie, validate, update last_seen_at.

        Returns (org_id, user_id, session_id) or a 401 Response.
        Delegates to :func:`validate_session` for the actual checks.
        """
        with _app_conn(conninfo) as conn:
            result, err = validate_session(conn, request, clock)
            if err:
                return err
            org_id, user_id, session_id, _token, _csrf_hash = result
            conn.commit()
        return (org_id, user_id, session_id)

    # ---------------------------------------------------------------
    # require_csrf (internal)
    # ---------------------------------------------------------------
    def _do_require_csrf(
        request: Request,
        org_id: uuid.UUID,
        session_id: uuid.UUID,
    ) -> Response | None:
        """Validate X-CSRF-Token header. Returns 403 Response or None."""
        csrf_header = request.headers.get("x-csrf-token")
        if not csrf_header:
            return JSONResponse({"error": "csrf_missing"}, status_code=403)

        csrf_hash = _sha256_hex(csrf_header)

        with _app_conn(conninfo) as conn:
            conn.execute(
                "SELECT set_config('app.org_id', %s, true)", [str(org_id)],
            )
            row = conn.execute(
                "SELECT csrf_hash FROM web_sessions WHERE id = %s",
                [session_id],
            ).fetchone()

        if row is None:
            return JSONResponse({"error": "csrf_invalid"}, status_code=403)

        if not hmac.compare_digest(row[0], csrf_hash):
            return JSONResponse({"error": "csrf_invalid"}, status_code=403)

        return None

    return router
