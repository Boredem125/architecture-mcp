"""T9 route-declaration tests.

Verifies:
- Walking ``create_app(...).routes`` produces the frozen (method, path) set
  from the T9 design plus the T8 auth routes and /health, /ready.
- Every /api route except the 3 pre-auth auth routes declares ``x-agg-rbac``.
- Positive control: a planted undeclared route is detected by the same checker.
"""
from __future__ import annotations

import pytest

from .t9_helpers import (
    T9Pending,
    RED_T9,
    require_t9,
)


# ---------------------------------------------------------------------------
# Expected frozen route set
# ---------------------------------------------------------------------------

# T8 auth routes (pre-auth, no RBAC needed)
_AUTH_PRE_AUTH = frozenset({
    ("GET", "/api/v1/auth/login"),
    ("GET", "/api/v1/auth/callback"),
    ("POST", "/api/v1/auth/setup"),
})

# T8 auth routes (session-gated)
_AUTH_SESSION = frozenset({
    ("POST", "/api/v1/auth/logout"),
})

# T9 routes
_T9_ROUTES = frozenset({
    ("GET", "/api/v1/me"),
    ("GET", "/api/v1/projects"),
    ("POST", "/api/v1/projects"),
    ("GET", "/api/v1/projects/{id}"),
    ("GET", "/api/v1/projects/{id}/members"),
    ("POST", "/api/v1/projects/{id}/members"),
    ("DELETE", "/api/v1/projects/{id}/members/{user_id}/{role}"),
    ("GET", "/api/v1/org/users"),
    ("POST", "/api/v1/org/users"),
    ("POST", "/api/v1/org/members"),
    ("DELETE", "/api/v1/org/members/{user_id}/{role}"),
    ("GET", "/api/v1/org/audit/verify"),
})

# M2 T7/T8 named exception (M2_BASELINE.md section 3)
_M2_T7_T8_ROUTES = frozenset({
    ("POST", "/api/v1/signer-links"),
    ("POST", "/api/v1/sync/signer/token"),
    ("POST", "/api/v1/sync/signer/link"),
    ("GET", "/api/v1/sync/signer/pending"),
    ("POST", "/api/v1/sync/signer/signatures"),
    ("POST", "/api/v1/sync/enroll"),
    ("POST", "/api/v1/sync/token"),
    ("POST", "/api/v1/admin/enrollment-codes"),
    ("GET", "/api/v1/enrollment-codes/{code_id}"),
    ("POST", "/api/v1/admin/devices/revoke"),
})

# M2 T9 named exception (M2_BASELINE.md section 3)
_M2_T9_ROUTES = frozenset({
    ("GET", "/api/v1/sync/bundle"),
    ("POST", "/api/v1/admin/bundles"),
})

# M2 enroll-persist named exception (M2_BASELINE.md section 3)
_M2_ENROLL_PERSIST_ROUTES = frozenset({
    ("GET", "/api/v1/sync/registry"),
})

# M2 T11 named exception (M2_BASELINE.md section 3)
_M2_T11_ROUTES = frozenset({
    ("POST", "/api/v1/sync/audit"),
    ("POST", "/api/v1/sync/checkpoint"),
})

# Infrastructure routes
_INFRA_ROUTES = frozenset({
    ("GET", "/health"),
    ("GET", "/ready"),
})

EXPECTED_ROUTES = _AUTH_PRE_AUTH | _AUTH_SESSION | _T9_ROUTES | _M2_T7_T8_ROUTES | _M2_T9_ROUTES | _M2_ENROLL_PERSIST_ROUTES | _M2_T11_ROUTES | _INFRA_ROUTES


# ---------------------------------------------------------------------------
# Route extraction helper
# ---------------------------------------------------------------------------

def _extract_routes(app) -> set[tuple[str, str]]:
    """Walk ``app.routes`` and return a set of ``(METHOD, path)`` tuples."""
    from starlette.routing import Route

    result: set[tuple[str, str]] = set()
    for route in app.routes:
        if not isinstance(route, Route):
            # May be a Mount (sub-router) -- walk its routes too
            sub_routes = getattr(route, "routes", None)
            if sub_routes:
                prefix = getattr(route, "path", "")
                for sub in sub_routes:
                    if isinstance(sub, Route) and sub.methods:
                        for method in sub.methods:
                            if method in ("GET", "POST", "PUT", "DELETE", "PATCH"):
                                result.add((method, prefix + sub.path))
            continue
        if route.methods:
            for method in route.methods:
                if method in ("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD"):
                    # Skip HEAD if GET is also present
                    if method == "HEAD":
                        continue
                    result.add((method, route.path))
    return result


def _routes_with_rbac(app) -> set[tuple[str, str]]:
    """Return routes that have ``x-agg-rbac`` declared."""
    from starlette.routing import Route

    result: set[tuple[str, str]] = set()
    for route in app.routes:
        sub_routes_list = []
        if isinstance(route, Route):
            sub_routes_list = [(route, "")]
        else:
            sub = getattr(route, "routes", None)
            prefix = getattr(route, "path", "")
            if sub:
                sub_routes_list = [(r, prefix) for r in sub if isinstance(r, Route)]

        for r, prefix in sub_routes_list:
            extra = getattr(r, "openapi_extra", None) or {}
            if "x-agg-rbac" in extra:
                if r.methods:
                    for method in r.methods:
                        if method in ("GET", "POST", "PUT", "DELETE", "PATCH"):
                            result.add((method, prefix + r.path))
    return result


def _api_routes(routes: set[tuple[str, str]]) -> set[tuple[str, str]]:
    """Filter to /api routes only."""
    return {(m, p) for m, p in routes if p.startswith("/api")}


def _check_all_api_routes_declare_rbac(app) -> list[tuple[str, str]]:
    """Return /api routes that lack x-agg-rbac, excluding pre-auth auth routes."""
    all_routes = _extract_routes(app)
    rbac_routes = _routes_with_rbac(app)
    api_routes = _api_routes(all_routes)
    # Pre-auth routes are exempt
    exempt = _AUTH_PRE_AUTH
    undeclared = []
    for route in api_routes:
        if route in exempt:
            continue
        if route not in rbac_routes:
            undeclared.append(route)
    return sorted(undeclared)


# ===================================================================
# Tests
# ===================================================================


def test_frozen_route_set():
    """The full (method, path) set equals the design table + T8 auth + infra."""
    try:
        from agg_cp.app import create_app, Settings
    except ImportError as exc:
        raise T9Pending(f"Cannot import agg_cp.app: {exc}") from exc

    # Build app without DB (routes still register if the code is there)
    # For T9 routes to register we may need a db_url; use a dummy.
    # The routes should be registered at import time via include_router.
    # Try with a fake db_url first -- create_app doesn't connect in sync.
    try:
        app = create_app(db_url="postgresql+psycopg://fake:fake@localhost/fake")
    except Exception as exc:
        raise T9Pending(f"create_app failed: {exc}") from exc

    actual = _extract_routes(app)
    require_t9(
        actual == EXPECTED_ROUTES,
        f"Route set mismatch.\n"
        f"  Missing: {EXPECTED_ROUTES - actual}\n"
        f"  Extra:   {actual - EXPECTED_ROUTES}",
    )


def test_all_api_routes_declare_rbac():
    """Every /api route except the 3 pre-auth auth routes declares x-agg-rbac."""
    try:
        from agg_cp.app import create_app
    except ImportError as exc:
        raise T9Pending(f"Cannot import agg_cp.app: {exc}") from exc

    try:
        app = create_app(db_url="postgresql+psycopg://fake:fake@localhost/fake")
    except Exception as exc:
        raise T9Pending(f"create_app failed: {exc}") from exc

    undeclared = _check_all_api_routes_declare_rbac(app)

    # First check that T9 routes even exist
    actual = _extract_routes(app)
    t9_present = _T9_ROUTES & actual
    require_t9(len(t9_present) > 0, "No T9 routes registered yet")

    assert undeclared == [], (
        f"API routes without x-agg-rbac declaration: {undeclared}"
    )


def test_planted_undeclared_route_detected():
    """Positive control: a planted route without x-agg-rbac is detected."""
    try:
        from agg_cp.app import create_app
        from fastapi import APIRouter
    except ImportError as exc:
        raise T9Pending(f"Cannot import: {exc}") from exc

    try:
        app = create_app(db_url="postgresql+psycopg://fake:fake@localhost/fake")
    except Exception as exc:
        raise T9Pending(f"create_app failed: {exc}") from exc

    # First ensure T9 routes exist
    actual = _extract_routes(app)
    t9_present = _T9_ROUTES & actual
    require_t9(len(t9_present) > 0, "No T9 routes registered yet")

    # Plant an undeclared route
    @app.get("/api/v1/planted-no-rbac")
    def planted():
        return {"planted": True}

    undeclared = _check_all_api_routes_declare_rbac(app)
    assert ("GET", "/api/v1/planted-no-rbac") in undeclared, (
        f"Planted route without x-agg-rbac was NOT detected. Undeclared: {undeclared}"
    )
