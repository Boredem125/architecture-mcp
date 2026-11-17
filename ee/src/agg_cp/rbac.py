"""RBAC route-registration helper for the control plane.

T3: CSRF dependency on POST/PUT/PATCH/DELETE for session/admin/signer_or_session.
Cookie parsing and csrf_token_for imported from auth.py (T3-R1-13).
"""
from __future__ import annotations

import hmac as _hmac
from typing import Any

from fastapi import APIRouter, Depends, Request

from agg_cp.auth import csrf_token_for


# ---------------------------------------------------------------------------
# Shared predicates (M-1)
# ---------------------------------------------------------------------------

def _has_bearer(request: Request) -> bool:
    """True when the request has ``Authorization: Bearer``."""
    return request.headers.get("Authorization", "").startswith("Bearer ")


def _parse_session_token(request: Request) -> str | None:
    """Return the token part of __Host-agg_session, or None.

    Same split as auth.validate_session: ``org_id.token``.
    """
    cookie = request.cookies.get("__Host-agg_session")
    if not cookie:
        return None
    parts = cookie.split(".", 1)
    return parts[1] if len(parts) == 2 else None


# ---------------------------------------------------------------------------
# CSRF dependency factory
# ---------------------------------------------------------------------------

class _CSRFError(Exception):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _make_csrf_dep(role: str):
    async def _csrf(request: Request):
        token = _parse_session_token(request)
        if token is None:
            # No cookie.  Bearer-only on signer_or_session -> skip.
            if role == "signer_or_session" and _has_bearer(request):
                return
            return  # handler's 401 will fire
        # Cookie present -> CSRF required, even with Bearer (M-1).
        hdr = request.headers.get("x-csrf-token")
        if not hdr:
            raise _CSRFError("csrf_missing")
        expected = csrf_token_for(token)
        if not _hmac.compare_digest(expected, hdr):
            raise _CSRFError("csrf_invalid")
    return _csrf


def install_csrf_handler(app):
    from starlette.requests import Request as _SR
    from starlette.responses import JSONResponse as _SJ

    @app.exception_handler(_CSRFError)
    async def _h(request: _SR, exc: _CSRFError):
        return _SJ({"error": exc.code}, status_code=403)


# ---------------------------------------------------------------------------
# rbac_route
# ---------------------------------------------------------------------------

_CSRF_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
_CSRF_ROLES = frozenset({"session", "admin", "signer_or_session"})


def rbac_route(
    router: APIRouter,
    method: str,
    path: str,
    *,
    role: str,
    scope: str,
    **kwargs: Any,
):
    extra = dict(kwargs.pop("openapi_extra", None) or {})
    extra["x-agg-rbac"] = {"role": role, "scope": scope}
    kwargs["openapi_extra"] = extra

    if method.upper() in _CSRF_METHODS and role in _CSRF_ROLES:
        deps = list(kwargs.get("dependencies", []))
        deps.append(Depends(_make_csrf_dep(role)))
        kwargs["dependencies"] = deps

    handler = getattr(router, method.lower())
    return handler(path, **kwargs)
