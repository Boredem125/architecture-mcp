"""Shared helpers for T9 tests.

Provides:
- ``T9Pending`` -- named exception for strict xfail.
- ``RED_T9`` -- pytest marker for strict xfail on T9Pending.
- ``require_t9`` -- guard that raises T9Pending when a condition fails.
- ``guard_import_t9`` -- convert ImportError/AttributeError into T9Pending.
- ``guard_404_t9`` -- convert route-not-registered 404 into T9Pending.
- ``seed_session`` -- insert a web_sessions row with known token and HMAC csrf.
- ``compute_csrf`` -- HMAC-SHA256 CSRF token from session token.
- ``make_session_cookie`` -- build the ``__Host-agg_session`` cookie value.
- ``make_t9_app`` -- build a test app for T9 (delegates to t8p2 make_test_app).
- Seeding helpers reused from t8p2_helpers.
"""
from __future__ import annotations

import base64
import datetime as dt
import hashlib
import hmac
import secrets
import uuid
from typing import Any

import pytest

from .fake_idp import FakeClock
from .t8p2_helpers import (
    T8P2Pending,
    FakeOidcHttp,
    FakeIdP,
    FakeIdPExtended,
    safe_resolve,
    seed_org_with_oidc as _t8p2_seed_org,
    seed_user as _t8p2_seed_user,
    seed_admin_binding as _t8p2_seed_admin,
    unique_sub,
    _conninfo,
    ensure_at_head as _t8p2_ensure_at_head,
    make_test_app,
)


# ---------------------------------------------------------------------------
# Named exception + xfail marker
# ---------------------------------------------------------------------------

class T9Pending(Exception):
    """T9 RBAC / routes / /me not built yet."""


RED_T9 = pytest.mark.xfail(
    raises=(T9Pending,),
    strict=True,
    reason="T9 not implemented yet",
)


def require_t9(cond: bool, msg: str) -> None:
    """Raise T9Pending if *cond* is false."""
    if not cond:
        raise T9Pending(msg)


def guard_import_t9(exc: Exception) -> None:
    """Convert ImportError / AttributeError / ModuleNotFoundError into T9Pending."""
    if isinstance(exc, (ImportError, AttributeError, ModuleNotFoundError)):
        raise T9Pending(str(exc)) from exc
    raise exc


def _wrap_t8p2(func, *args, **kwargs):
    """Call *func* and convert T8P2Pending into T9Pending."""
    try:
        return func(*args, **kwargs)
    except T8P2Pending as exc:
        raise T9Pending(str(exc)) from exc


def ensure_at_head(pg_url: str) -> None:
    """Run alembic upgrade head, converting T8P2Pending -> T9Pending."""
    _wrap_t8p2(_t8p2_ensure_at_head, pg_url)


def seed_org_with_oidc(owner_url: str, **kwargs) -> uuid.UUID:
    """Seed an org with OIDC config, converting T8P2Pending -> T9Pending."""
    return _wrap_t8p2(_t8p2_seed_org, owner_url, **kwargs)


def seed_user(owner_url: str, org_id: uuid.UUID, **kwargs):
    """Seed a user, converting T8P2Pending -> T9Pending."""
    return _wrap_t8p2(_t8p2_seed_user, owner_url, org_id, **kwargs)


def seed_admin_binding(owner_url: str, org_id: uuid.UUID,
                       user_id: uuid.UUID) -> uuid.UUID:
    """Seed admin role binding, converting T8P2Pending -> T9Pending."""
    return _wrap_t8p2(_t8p2_seed_admin, owner_url, org_id, user_id)


def guard_404_t9(resp: Any) -> None:
    """Raise T9Pending if *resp* is a FastAPI 404 for a missing route."""
    if resp.status_code == 404:
        try:
            body = resp.json()
        except Exception:
            return
        if body == {"detail": "Not Found"}:
            raise T9Pending(f"Route not registered (404: {body})")


# ---------------------------------------------------------------------------
# CSRF helpers (T9 design: HMAC-based)
# ---------------------------------------------------------------------------

def compute_csrf(session_token: str) -> str:
    """Compute the T9-design CSRF token.

    ``csrf_token = base64url_nopad(HMAC-SHA256(key=session_token, msg=b"agg-csrf-v1"))``
    """
    mac = hmac.new(session_token.encode(), b"agg-csrf-v1", hashlib.sha256).digest()
    return base64.urlsafe_b64encode(mac).rstrip(b"=").decode("ascii")


def _sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


# ---------------------------------------------------------------------------
# Session seeding
# ---------------------------------------------------------------------------

def seed_session(
    owner_url: str,
    org_id: uuid.UUID,
    user_id: uuid.UUID,
    *,
    clock: FakeClock,
    session_token: str | None = None,
) -> tuple[str, str, uuid.UUID]:
    """Insert a web_sessions row directly (superuser) and return
    ``(session_token, csrf_token, session_id)``.

    Uses the T9 HMAC CSRF formula.
    """
    import psycopg

    if session_token is None:
        session_token = secrets.token_urlsafe(32)

    csrf_token = compute_csrf(session_token)
    token_hash = _sha256_hex(session_token)
    csrf_hash = _sha256_hex(csrf_token)
    session_id = uuid.uuid4()
    now = clock.now()
    expires = now + dt.timedelta(hours=12)

    conninfo = _conninfo(owner_url)
    # Before T8 part 2 (migration 0003) web_sessions lacks these columns:
    # that is "not built yet", so it must surface as the named exception.
    try:
        _insert_session(psycopg, conninfo, org_id, user_id, session_id,
                        token_hash, csrf_hash, now, expires)
    except (psycopg.errors.UndefinedColumn, psycopg.errors.UndefinedTable) as exc:
        raise T9Pending(f"web_sessions schema not at T8 part 2: {exc}") from exc

    return session_token, csrf_token, session_id


def _insert_session(psycopg, conninfo, org_id, user_id, session_id,
                    token_hash, csrf_hash, now, expires) -> None:
    with psycopg.connect(conninfo) as conn:
        conn.execute(
            "SELECT set_config('app.org_id', %s, false)", [str(org_id)]
        )
        conn.execute(
            "INSERT INTO web_sessions "
            "(id, org_id, user_id, token_hash, csrf_hash, "
            "created_at, expires_at, last_seen_at) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
            [session_id, org_id, user_id, token_hash, csrf_hash,
             now, expires, now],
        )
        conn.commit()


def make_session_cookie(org_id: uuid.UUID, session_token: str) -> str:
    """Build the ``__Host-agg_session`` cookie value."""
    return f"{org_id}.{session_token}"


# ---------------------------------------------------------------------------
# Role binding seeding
# ---------------------------------------------------------------------------

def seed_role_binding(
    owner_url: str,
    org_id: uuid.UUID,
    user_id: uuid.UUID,
    *,
    role: str,
    scope_type: str = "org",
    scope_id: uuid.UUID | None = None,
) -> uuid.UUID:
    """Seed a role_binding and return its id."""
    import psycopg

    binding_id = uuid.uuid4()
    if scope_id is None:
        scope_id = org_id
    conninfo = _conninfo(owner_url)
    with psycopg.connect(conninfo) as conn:
        conn.execute(
            "SELECT set_config('app.org_id', %s, false)", [str(org_id)]
        )
        conn.execute(
            "INSERT INTO role_bindings "
            "(id, org_id, user_id, scope_type, scope_id, role, created_at) "
            "VALUES (%s, %s, %s, %s, %s, %s, now())",
            [binding_id, org_id, user_id, scope_type, scope_id, role],
        )
        conn.commit()
    return binding_id


def seed_project(
    owner_url: str,
    org_id: uuid.UUID,
    *,
    name: str = "test-project",
    environment: str = "dev",
) -> uuid.UUID:
    """Seed a project and return its id."""
    import psycopg

    project_id = uuid.uuid4()
    conninfo = _conninfo(owner_url)
    with psycopg.connect(conninfo) as conn:
        conn.execute(
            "SELECT set_config('app.org_id', %s, false)", [str(org_id)]
        )
        conn.execute(
            "INSERT INTO projects "
            "(id, org_id, name, environment, created_at) "
            "VALUES (%s, %s, %s, %s, now())",
            [project_id, org_id, name, environment],
        )
        conn.commit()
    return project_id


# ---------------------------------------------------------------------------
# Test app and client builders
# ---------------------------------------------------------------------------

def make_t9_app(
    pg_url: str,
    *,
    clock: FakeClock | None = None,
    oidc_http: FakeOidcHttp | None = None,
):
    """Build a test app wired for T9.

    Returns (app, clock, oidc_http).  Raises T9Pending on ImportError.
    """
    if clock is None:
        clock = FakeClock()
    if oidc_http is None:
        oidc_http = FakeOidcHttp()

    try:
        app, clock, oidc_http = make_test_app(
            pg_url=pg_url,
            clock=clock,
            oidc_http=oidc_http,
            resolve=safe_resolve,
            oidc_allow_hosts="idp.example.com",
        )
    except T8P2Pending as exc:
        raise T9Pending(str(exc)) from exc
    except Exception as exc:
        guard_import_t9(exc)
        raise
    return app, clock, oidc_http


def make_t9_client(app):
    """Build a Starlette TestClient for T9. Raises T9Pending on import."""
    try:
        from starlette.testclient import TestClient
    except ImportError as exc:
        raise T9Pending(f"starlette not available: {exc}") from exc
    return TestClient(app, base_url="https://testserver")


def unique_slug(prefix: str = "t9") -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}"
