"""M3 T3 tests-first: CSRF catalog test over ``x-agg-rbac``.

Spec: M3_PLAN.md threat 48, S5, ADR 0001 A9 item 12.

Every session or admin POST and DELETE refuses 403 without ``X-CSRF-Token``,
driven from the real OpenAPI, not a hand list.  The catalog is non-empty
and includes the two named routes (enrollment-codes and devices/revoke).

The CSRF check on enrollment-codes and devices/revoke is a T3 addition.
Everything else already checks CSRF.  The test targets the two routes
that do NOT check today; a guard twin proves the fixture works on a route
that already checks.

Marked ``pg``.
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import uuid

import psycopg
import pytest
from nacl.signing import SigningKey

from .m3_pending import M3T3Pending, require_m3
from .m2_sync_server import (
    make_sync_server, ensure_at_head, create_org, create_project,
    keygen,
)
from .t9_helpers import (
    seed_session, make_session_cookie, compute_csrf, _conninfo,
)
from .fake_idp import FakeClock


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _seed_user_row(conn, org_id: str, email: str) -> str:
    user_id = str(uuid.uuid4())
    conn.execute(
        "INSERT INTO users (id, org_id, oidc_issuer, oidc_subject, email, "
        "status, created_at) VALUES (%s, %s, 'https://idp.test', %s, %s, "
        "'active', now()) ON CONFLICT DO NOTHING",
        [user_id, org_id, f"sub-{uuid.uuid4().hex[:8]}", email],
    )
    return user_id


def _bind_admin(conn, org_id: str, user_id: str) -> None:
    conn.execute(
        "INSERT INTO role_bindings "
        "(id, org_id, user_id, scope_type, scope_id, role, created_at) "
        "VALUES (%s, %s, %s, 'org', %s, 'admin', now())",
        [str(uuid.uuid4()), org_id, user_id, org_id],
    )


def _make_fresh_session(owner_url: str, org_id: str, user_id: str):
    clock = FakeClock()
    token, csrf, sid = seed_session(
        owner_url, uuid.UUID(org_id), uuid.UUID(user_id), clock=clock,
    )
    cookie = make_session_cookie(uuid.UUID(org_id), token)
    return cookie, csrf, sid


# ---------------------------------------------------------------------------
# Module-scoped server fixture
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def csrf_server(pg_url, app_url, owner_url, pg_roles, tmp_path_factory):
    """4-worker agg_cp server for CSRF catalog tests."""
    bundle_signer_sk = SigningKey.generate()
    key_dir = tmp_path_factory.mktemp("csrf_bundle_signer")
    key_file = key_dir / "bundle_signer.key"
    key_file.write_bytes(bytes(bundle_signer_sk).hex().encode("ascii"))
    old_bs = os.environ.get("AGG_BUNDLE_SIGNER_KEY_FILE")
    os.environ["AGG_BUNDLE_SIGNER_KEY_FILE"] = str(key_file)

    gen = make_sync_server(
        pg_url, app_url, owner_url,
        org_names=["CSRF Org"],
    )
    info = next(gen)
    conninfo = _conninfo(owner_url)
    org_id = info["org_id"]

    with psycopg.connect(conninfo, autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        admin_id = _seed_user_row(conn, org_id, "admin@csrf.test")
        _bind_admin(conn, org_id, admin_id)
        project_id = str(uuid.uuid4())
        create_project(conn, org_id, project_id, "CSRF Project")

    cookie, csrf, _ = _make_fresh_session(owner_url, org_id, admin_id)

    info.update({
        "admin_id": admin_id,
        "project_id": project_id,
        "cookie": cookie,
        "csrf": csrf,
    })

    try:
        yield info
    finally:
        gen.close()
        if old_bs is None:
            os.environ.pop("AGG_BUNDLE_SIGNER_KEY_FILE", None)
        else:
            os.environ["AGG_BUNDLE_SIGNER_KEY_FILE"] = old_bs


# ---------------------------------------------------------------------------
# OpenAPI catalog extraction
# ---------------------------------------------------------------------------

def _build_real_app():
    """Build the real app using the production code path.

    Uses a dummy ``postgresql+psycopg://`` URL to trigger full route
    registration (some routes register only for Postgres, not sqlite).
    The app is never started, so the URL does not need to be reachable.
    """
    from agg_cp.app import create_app
    app = create_app(db_url="postgresql+psycopg://dummy:dummy@localhost:5432/dummy")
    return app


def _get_csrf_catalog_from_app() -> list[dict]:
    """Extract every session/admin POST and DELETE route from the real
    app's route objects and their ``x-agg-rbac`` metadata.

    Built from the real app so it cannot be a subset.
    """
    app = _build_real_app()

    catalog = []
    for route in app.routes:
        openapi_extra = getattr(route, "openapi_extra", None) or {}
        rbac = openapi_extra.get("x-agg-rbac")
        if rbac is None:
            continue
        methods = getattr(route, "methods", set())
        path = getattr(route, "path", "")
        role = rbac.get("role", "")
        for method in methods:
            if method.upper() not in ("POST", "DELETE"):
                continue
            if role in ("session", "admin", "signer_or_session"):
                catalog.append({
                    "path": path,
                    "method": method.upper(),
                    "role": role,
                    "scope": rbac.get("scope", ""),
                })
    return catalog


# ---------------------------------------------------------------------------
# Route-level allowlist for POST/DELETE without x-agg-rbac
# ---------------------------------------------------------------------------

# Every POST/DELETE route that lacks ``x-agg-rbac`` must be listed here
# with a reason why CSRF is not required.  A new untagged route will
# break the test.
_UNTAGGED_POST_DELETE_ALLOWLIST: dict[str, str] = {
    # Bootstrap route: no session exists yet; consumed by a one-time code
    "/api/v1/auth/setup": "bootstrap route, no session, one-time code auth",
}


def _get_untagged_post_delete_routes() -> list[dict]:
    """Return every POST/DELETE route that does NOT have ``x-agg-rbac``."""
    app = _build_real_app()
    untagged = []
    for route in app.routes:
        openapi_extra = getattr(route, "openapi_extra", None) or {}
        rbac = openapi_extra.get("x-agg-rbac")
        methods = getattr(route, "methods", set())
        path = getattr(route, "path", "")
        for method in methods:
            if method.upper() not in ("POST", "DELETE"):
                continue
            if rbac is None:
                untagged.append({"path": path, "method": method.upper()})
    return untagged


# ===================================================================
# GUARD TWIN: fixture works, one existing CSRF-protected route
# ===================================================================

@pytest.mark.pg
def test_guard_csrf_existing_route_with_token(csrf_server):
    """Guard: POST /api/v1/admin/enrollment-codes WITH the CSRF token succeeds."""
    import httpx
    info = csrf_server
    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        r = c.post(
            "/api/v1/admin/enrollment-codes",
            json={"project_id": info["project_id"],
                  "operator_user_id": info["admin_id"]},
            cookies={"__Host-agg_session": info["cookie"]},
            headers={"X-CSRF-Token": info["csrf"]},
        )
    assert r.status_code == 200, f"guard failed: {r.status_code} {r.text}"


def test_guard_csrf_catalog_from_app():
    """Guard: the CSRF catalog from app routes is non-empty.

    Floor: 12 session-write routes registered at HEAD:
      POST /projects, POST /projects/{id}/members,
      DELETE /projects/{id}/members/{user_id}/{role},
      POST /org/users, POST /org/members,
      DELETE /org/members/{user_id}/{role},
      POST /logout,
      POST /api/v1/admin/bundles,
      POST /api/v1/admin/enrollment-codes,
      POST /api/v1/admin/devices/revoke,
      POST /api/v1/signer-links,
      POST /api/v1/sync/escalations/{escalation_id}/approvals.
    """
    catalog = _get_csrf_catalog_from_app()
    assert len(catalog) >= 12, \
        f"CSRF catalog must have at least 12 session-write routes, got {len(catalog)}"


# ===================================================================
# T3 TARGETS
# ===================================================================

@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M3T3Pending)
def test_csrf_catalog_is_non_empty_and_includes_named_routes(csrf_server):
    """The CSRF catalog from the app is non-empty and includes
    POST /api/v1/admin/enrollment-codes and POST /api/v1/admin/devices/revoke.

    Every route in the catalog must refuse 403 without X-CSRF-Token."""
    import httpx
    info = csrf_server
    catalog = _get_csrf_catalog_from_app()
    # Floor: 12 session-write routes at HEAD (see guard docstring)
    assert len(catalog) >= 12, \
        f"CSRF catalog must have at least 12 session-write routes, got {len(catalog)}"

    paths = {(e["path"], e["method"]) for e in catalog}
    assert ("/api/v1/admin/enrollment-codes", "POST") in paths, \
        "enrollment-codes not in CSRF catalog"
    assert ("/api/v1/admin/devices/revoke", "POST") in paths, \
        "devices/revoke not in CSRF catalog"

    # Check the two named routes refuse 403 without the token
    r1 = httpx.post(
        f"{info['base_url']}/api/v1/admin/enrollment-codes",
        json={"project_id": info["project_id"],
              "operator_user_id": info["admin_id"]},
        cookies={"__Host-agg_session": info["cookie"]},
        timeout=10,
    )
    r2 = httpx.post(
        f"{info['base_url']}/api/v1/admin/devices/revoke",
        json={"device_id": str(uuid.uuid4())},
        cookies={"__Host-agg_session": info["cookie"]},
        timeout=10,
    )

    require_m3(3, r1.status_code == 403,
               f"POST /admin/enrollment-codes without CSRF not refused 403 "
               f"(got {r1.status_code})")
    require_m3(3, r2.status_code == 403,
               f"POST /admin/devices/revoke without CSRF not refused 403 "
               f"(got {r2.status_code})")

    # Now verify every catalog route refuses 403
    failures = []
    for entry in catalog:
        path = entry["path"]
        method = entry["method"]
        test_path = path
        for param in ("{id}", "{escalation_id}", "{code_id}", "{user_id}",
                      "{role}", "{proposal_id}"):
            test_path = test_path.replace(param, str(uuid.uuid4()))

        fn = getattr(httpx, method.lower())
        if method in ("POST", "PUT", "PATCH"):
            r = fn(f"{info['base_url']}{test_path}", json={},
                   cookies={"__Host-agg_session": info["cookie"]},
                   timeout=10)
        else:
            r = fn(f"{info['base_url']}{test_path}",
                   cookies={"__Host-agg_session": info["cookie"]},
                   timeout=10)

        if r.status_code != 403:
            failures.append(f"{method} {path} -> {r.status_code} (expected 403)")

    assert not failures, \
        f"CSRF catalog routes that accepted without token:\n" + \
        "\n".join(failures)


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M3T3Pending)
def test_enrollment_codes_no_csrf_403(csrf_server):
    """POST /api/v1/admin/enrollment-codes without X-CSRF-Token is 403."""
    import httpx
    info = csrf_server
    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        r = c.post(
            "/api/v1/admin/enrollment-codes",
            json={"project_id": info["project_id"],
                  "operator_user_id": info["admin_id"]},
            cookies={"__Host-agg_session": info["cookie"]},
            # No X-CSRF-Token header
        )
    require_m3(3, r.status_code == 403,
               f"enrollment-codes without CSRF not 403: got {r.status_code}")
    assert r.status_code == 403


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M3T3Pending)
def test_devices_revoke_no_csrf_403(csrf_server):
    """POST /api/v1/admin/devices/revoke without X-CSRF-Token is 403."""
    import httpx
    info = csrf_server
    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        r = c.post(
            "/api/v1/admin/devices/revoke",
            json={"device_id": str(uuid.uuid4())},
            cookies={"__Host-agg_session": info["cookie"]},
            # No X-CSRF-Token header
        )
    require_m3(3, r.status_code == 403,
               f"devices/revoke without CSRF not 403: got {r.status_code}")
    assert r.status_code == 403


# ===================================================================
# T3 TARGET: untagged POST/DELETE routes must be in the allowlist
# ===================================================================

def test_untagged_post_delete_routes_in_allowlist():
    """Every POST/DELETE route in ``app.routes`` lacking ``x-agg-rbac``
    must be in an explicit allowlist.  A new untagged route fails.

    The allowlist also must not be stale: every allowlisted route must
    exist in the app.
    """
    untagged = _get_untagged_post_delete_routes()

    # Check: every untagged route must be in the allowlist
    missing = []
    for entry in untagged:
        key = entry["path"]
        if key not in _UNTAGGED_POST_DELETE_ALLOWLIST:
            missing.append(f"{entry['method']} {entry['path']}")
    assert not missing, \
        (f"POST/DELETE routes without x-agg-rbac and not in allowlist "
         f"(add them with a reason or tag them):\n"
         + "\n".join(missing))

    # Check: the allowlist must not be stale (every entry exists)
    app = _build_real_app()
    registered = set()
    for route in app.routes:
        path = getattr(route, "path", "")
        methods = getattr(route, "methods", set())
        for method in methods:
            if method.upper() in ("POST", "DELETE"):
                registered.add(path)

    stale = []
    for path, reason in _UNTAGGED_POST_DELETE_ALLOWLIST.items():
        if path not in registered:
            stale.append(f"{path} ({reason})")
    assert not stale, \
        (f"Allowlisted routes that no longer exist in the app (stale):\n"
         + "\n".join(stale))
