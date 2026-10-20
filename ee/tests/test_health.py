"""M1 T5: ``/health`` and ``/ready`` endpoints on the ``agg_cp`` app.

T5 done-when: ``agg_cp`` app has ``/health`` and ``/ready``.

For T5, ``/ready`` has no DB yet -- T6 adds the Postgres harness and
schema checks.  The tests here assert only what the plan says for T5:
the routes exist and return JSON.

Tests are marked ``xfail(strict=True)`` because the ``agg_cp`` package
does not exist yet.  The fix commit (T5 implementation) removes the
decorator.
"""
from __future__ import annotations

import pytest

# ---------------------------------------------------------------------------
# Named exception for the xfail marker (M0 T1b pattern)
# ---------------------------------------------------------------------------


class EESkeletonOpen(Exception):
    """The ee/ skeleton is not built yet (M1 T5)."""


RED_T5 = pytest.mark.xfail(
    raises=EESkeletonOpen, strict=True,
    reason="M1 T5: ee/ skeleton not yet built",
)


def _require(cond: bool, msg: str) -> None:
    if not cond:
        raise EESkeletonOpen(msg)


# ---------------------------------------------------------------------------
# Helpers -- import the app lazily so the xfail catches the ImportError
# ---------------------------------------------------------------------------

def _get_app():
    """Import and return the agg_cp FastAPI application."""
    try:
        from agg_cp.app import create_app  # noqa: F811
    except (ImportError, ModuleNotFoundError) as exc:
        raise EESkeletonOpen(f"agg_cp is not importable: {exc}") from exc
    return create_app()


def _get_test_client():
    """Return an httpx-based TestClient for the agg_cp app."""
    try:
        from starlette.testclient import TestClient
    except ImportError as exc:
        raise EESkeletonOpen(f"starlette not available: {exc}") from exc
    app = _get_app()
    return TestClient(app)


# ---------------------------------------------------------------------------
# /health
# ---------------------------------------------------------------------------


@RED_T5
def test_health_returns_200():
    """GET /health returns 200."""
    client = _get_test_client()
    resp = client.get("/health")
    _require(resp.status_code == 200, f"/health returned {resp.status_code}, expected 200")


@RED_T5
def test_health_returns_json():
    """GET /health returns a JSON body."""
    client = _get_test_client()
    resp = client.get("/health")
    _require(resp.status_code == 200, f"/health returned {resp.status_code}")
    body = resp.json()
    _require(isinstance(body, dict), f"/health body is not a dict: {type(body)}")


@RED_T5
def test_health_has_status_field():
    """GET /health JSON contains a ``status`` key."""
    client = _get_test_client()
    resp = client.get("/health")
    _require(resp.status_code == 200, f"/health returned {resp.status_code}")
    body = resp.json()
    _require("status" in body, f"/health JSON missing 'status': {body}")


# ---------------------------------------------------------------------------
# /ready
# ---------------------------------------------------------------------------


@RED_T5
def test_ready_route_exists():
    """GET /ready returns an HTTP response (not 404/405)."""
    client = _get_test_client()
    resp = client.get("/ready")
    _require(
        resp.status_code not in (404, 405),
        f"/ready returned {resp.status_code} (route missing or method not allowed)",
    )


@RED_T5
def test_ready_returns_json():
    """GET /ready returns a JSON body."""
    client = _get_test_client()
    resp = client.get("/ready")
    _require(resp.status_code not in (404, 405), f"/ready returned {resp.status_code}")
    body = resp.json()
    _require(isinstance(body, dict), f"/ready body is not a dict: {type(body)}")


@RED_T5
def test_ready_has_status_field():
    """GET /ready JSON contains a ``status`` key."""
    client = _get_test_client()
    resp = client.get("/ready")
    _require(resp.status_code not in (404, 405), f"/ready returned {resp.status_code}")
    body = resp.json()
    _require("status" in body, f"/ready JSON missing 'status': {body}")
