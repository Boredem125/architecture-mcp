"""RBAC route-registration helper for the control plane.

Provides a single :func:`rbac_route` function that registers a route on
an :class:`~fastapi.APIRouter` and records its role/scope requirement
in ``openapi_extra["x-agg-rbac"]``.

No module-level mutable state.
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter


def rbac_route(
    router: APIRouter,
    method: str,
    path: str,
    *,
    role: str,
    scope: str,
    **kwargs: Any,
):
    """Return a decorator that registers a route with ``x-agg-rbac`` metadata.

    Usage::

        @rbac_route(router, "get", "/me", role="session", scope="session")
        def get_me(request: Request):
            ...

    The ``openapi_extra`` dict on the resulting route will contain::

        {"x-agg-rbac": {"role": role, "scope": scope}}
    """
    extra = dict(kwargs.pop("openapi_extra", None) or {})
    extra["x-agg-rbac"] = {"role": role, "scope": scope}
    kwargs["openapi_extra"] = extra
    handler = getattr(router, method.lower())
    return handler(path, **kwargs)
