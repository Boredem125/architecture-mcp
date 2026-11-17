"""T9 route-declaration tests.

Verifies:
- Walking ``create_app(...).routes`` produces the frozen (method, path) set
  from the T9 design plus the T8 auth routes and /health, /ready.
- Every /api route except the 3 pre-auth auth routes declares ``x-agg-rbac``.
- Positive control: a planted undeclared route is detected by the same checker.
- (M3 T1) Routes from reviewed data files match ``x-agg-rbac`` role and scope,
  do not overlap the earlier frozen sets, and any ``/admin/`` entry is ``admin``.
- Planted-extra and planted-removed controls detect drift.
"""
from __future__ import annotations

import json
from pathlib import Path

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

# M2 T12 named exception (M2_BASELINE.md section 3)
_M2_T12_ROUTES = frozenset({
    ("POST", "/api/v1/sync/escalations"),
    ("GET", "/api/v1/sync/decisions"),
    ("POST", "/api/v1/sync/escalations/{escalation_id}/approvals"),
})

# M2 T13 named exception (M2_BASELINE.md section 5b)
_M2_T13_ROUTES = frozenset({
    ("GET", "/api/v1/escalations"),
})

# M2 T12b-2 named exception: escalation detail route
_M2_T12B_ROUTES = frozenset({
    ("GET", "/api/v1/sync/escalations/{escalation_id}"),
})

# M2 T12c named exception: sync escalations list (ADR 0010 s9)
_M2_T12C_ROUTES = frozenset({
    ("GET", "/api/v1/sync/escalations"),
})

# M2 T12d named exception: genesis bootstrap routes (ADR 0011)
_M2_T12D_ROUTES = frozenset({
    ("POST", "/api/v1/sync/signer/genesis"),
    ("GET", "/api/v1/sync/signer/candidates"),
    ("GET", "/api/v1/sync/signer/registry"),
})

# Infrastructure routes
_INFRA_ROUTES = frozenset({
    ("GET", "/health"),
    ("GET", "/ready"),
})

# ---------------------------------------------------------------------------
# M3 T1 routes loaded from reviewed data file (ruling T0b-11)
# ---------------------------------------------------------------------------

_FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"


def _load_reviewed_routes(filename: str) -> tuple[
    frozenset[tuple[str, str]],
    list[dict],
]:
    """Load literal (METHOD, path) pairs from a reviewed JSON data file.

    Returns ``(frozenset of pairs, list of entry dicts with task/role/scope)``.
    """
    path = _FIXTURES_DIR / filename
    data = json.loads(path.read_text(encoding="utf-8"))
    entries = data["routes"]
    pairs: set[tuple[str, str]] = set()
    for e in entries:
        pairs.add((e["method"], e["path"]))
    return frozenset(pairs), entries


_M3_T1_ROUTES, _M3_T1_ENTRIES = _load_reviewed_routes("t1_frozen_routes.json")

# The earlier frozen sets (everything before T1)
_EARLIER_FROZEN = (
    _AUTH_PRE_AUTH | _AUTH_SESSION | _T9_ROUTES | _M2_T7_T8_ROUTES
    | _M2_T9_ROUTES | _M2_ENROLL_PERSIST_ROUTES | _M2_T11_ROUTES
    | _M2_T12_ROUTES | _M2_T13_ROUTES | _M2_T12B_ROUTES
    | _M2_T12C_ROUTES | _M2_T12D_ROUTES | _INFRA_ROUTES
)

EXPECTED_ROUTES = _EARLIER_FROZEN | _M3_T1_ROUTES


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


def _get_rbac_metadata(app) -> dict[tuple[str, str], dict]:
    """Return ``{(METHOD, path): {"role": ..., "scope": ...}}`` for all routes."""
    from starlette.routing import Route

    result: dict[tuple[str, str], dict] = {}
    for route in app.routes:
        sub_routes_list = []
        if isinstance(route, Route):
            sub_routes_list = [(route, "")]
        else:
            sub = getattr(route, "routes", None)
            prefix = getattr(route, "path", "")
            if sub:
                sub_routes_list = [(r, prefix) for r in sub
                                   if isinstance(r, Route)]

        for r, prefix in sub_routes_list:
            extra = getattr(r, "openapi_extra", None) or {}
            rbac = extra.get("x-agg-rbac")
            if rbac and r.methods:
                for method in r.methods:
                    if method in ("GET", "POST", "PUT", "DELETE", "PATCH"):
                        result[(method, prefix + r.path)] = rbac
    return result


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


# ===================================================================
# M3 T1: reviewed data file route/role/scope checks (ruling T0b-11)
# ===================================================================


def test_reviewed_routes_role_scope_match_rbac():
    """Each entry in the reviewed data file must match the route's
    ``x-agg-rbac`` role and scope."""
    try:
        from agg_cp.app import create_app
    except ImportError as exc:
        raise T9Pending(f"Cannot import agg_cp.app: {exc}") from exc

    try:
        app = create_app(db_url="postgresql+psycopg://fake:fake@localhost/fake")
    except Exception as exc:
        raise T9Pending(f"create_app failed: {exc}") from exc

    rbac_map = _get_rbac_metadata(app)
    actual = _extract_routes(app)

    errors = []
    for entry in _M3_T1_ENTRIES:
        key = (entry["method"], entry["path"])
        if key not in actual:
            errors.append(f"  {key}: not registered")
            continue
        if key not in rbac_map:
            errors.append(f"  {key}: no x-agg-rbac metadata")
            continue
        actual_rbac = rbac_map[key]
        if actual_rbac.get("role") != entry["role"]:
            errors.append(
                f"  {key}: role={actual_rbac.get('role')!r}, "
                f"expected={entry['role']!r}"
            )
        if actual_rbac.get("scope") != entry["scope"]:
            errors.append(
                f"  {key}: scope={actual_rbac.get('scope')!r}, "
                f"expected={entry['scope']!r}"
            )

    assert not errors, (
        f"Reviewed data file role/scope mismatches:\n" + "\n".join(errors)
    )


def test_reviewed_routes_no_overlap_with_earlier_frozen():
    """Entries in the reviewed data file must not overlap the earlier
    frozen route sets."""
    overlap = _M3_T1_ROUTES & _EARLIER_FROZEN
    assert not overlap, (
        f"T1 routes overlap earlier frozen sets: {overlap}"
    )


def test_reviewed_routes_admin_entries_are_admin():
    """Any reviewed entry whose path contains ``/admin/`` must have
    role ``admin``, except the five T3 proposal routes which are
    ``signer_or_session`` (S-1, founder row 16 Nov; FR-3, founder
    row 17 Nov).
    """
    # S-1 / FR-3: exactly these five T3 proposal routes use
    # signer_or_session instead of admin.
    _T3_SIGNER_OR_SESSION_ROUTES = frozenset({
        ("POST", "/api/v1/admin/bundle-proposals"),
        ("GET", "/api/v1/admin/bundle-proposals"),
        ("GET", "/api/v1/admin/bundle-proposals/{proposal_id}"),
        ("POST", "/api/v1/admin/bundle-proposals/{proposal_id}/approvals"),
        ("POST", "/api/v1/admin/bundle-proposals/{proposal_id}/publish"),
    })
    errors = []
    for entry in _M3_T1_ENTRIES:
        key = (entry["method"], entry["path"])
        if "/admin/" not in entry["path"]:
            continue
        if key in _T3_SIGNER_OR_SESSION_ROUTES:
            if entry["role"] != "signer_or_session":
                errors.append(
                    f"  {entry['method']} {entry['path']}: "
                    f"role={entry['role']!r}, must be 'signer_or_session' (S-1/FR-3)"
                )
        else:
            if entry["role"] != "admin":
                errors.append(
                    f"  {entry['method']} {entry['path']}: "
                    f"role={entry['role']!r}, must be 'admin'"
                )
    assert not errors, (
        f"/admin/ entries must all be admin (except T3 S-1/FR-3 routes):\n"
        + "\n".join(errors)
    )


def test_planted_extra_route_detected():
    """Positive control: a route added to the app but NOT in any frozen
    set is detected as Extra by the frozen-set check."""
    try:
        from agg_cp.app import create_app
    except ImportError as exc:
        raise T9Pending(f"Cannot import agg_cp.app: {exc}") from exc

    try:
        app = create_app(db_url="postgresql+psycopg://fake:fake@localhost/fake")
    except Exception as exc:
        raise T9Pending(f"create_app failed: {exc}") from exc

    # Plant an extra route directly on the app (not via include_router,
    # which may not register in _extract_routes correctly)
    @app.get("/api/v1/planted-extra-t1")
    def planted_extra():
        return {"planted": True}

    actual = _extract_routes(app)
    extra = actual - EXPECTED_ROUTES
    assert ("GET", "/api/v1/planted-extra-t1") in extra, (
        f"Planted extra route was NOT detected. Extra: {extra}"
    )


def test_planted_removed_route_detected():
    """Positive control: removing a route from EXPECTED_ROUTES causes a
    Missing difference (proves exact equality)."""
    # Simulate by checking that removing one entry from EXPECTED_ROUTES
    # is detected
    shrunk = EXPECTED_ROUTES - {("GET", "/ready")}
    try:
        from agg_cp.app import create_app
    except ImportError as exc:
        raise T9Pending(f"Cannot import agg_cp.app: {exc}") from exc

    try:
        app = create_app(db_url="postgresql+psycopg://fake:fake@localhost/fake")
    except Exception as exc:
        raise T9Pending(f"create_app failed: {exc}") from exc

    actual = _extract_routes(app)
    missing = shrunk - actual
    extra = actual - shrunk
    # ("GET", "/ready") should show up as extra
    assert ("GET", "/ready") in extra, (
        f"Removing ('/ready') from expected was NOT detected. Extra: {extra}"
    )
