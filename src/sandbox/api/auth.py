"""Bearer-token authentication for the HTTP API, with two roles.

Capability is not authority, over HTTP too: the agent may never *decide*.

- approver token  every non-public route: the connector view, including
                  approve/deny. Never handed to an agent.
- agent token     no route today (AGENT_ROUTES is empty since M0 removed the
                  legacy broker, hook and e2b routes). It is still generated
                  and checked, so it is refused (403) everywhere rather than
                  being mistaken for no token; M1 sync may give it routes.

Unauthenticated: /health, /ready, the OpenAPI schema and the docs pages.
WebSocket connections are refused (there are no WebSocket routes).

Tokens come from SANDBOX_AGENT_TOKEN / SANDBOX_APPROVER_TOKEN. When unset,
random ones are generated per process (``ensure_tokens``), so a server is
never open by default. Before this, every route was unauthenticated and the
server bound 0.0.0.0: anyone on the network, or the jailed agent itself,
could submit a command to the broker, approve it and have it run outside the
jail.
"""
from __future__ import annotations

import hmac
import ipaddress
import os
import secrets

from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

AGENT_ENV = "SANDBOX_AGENT_TOKEN"
APPROVER_ENV = "SANDBOX_APPROVER_TOKEN"

PUBLIC_ROUTES = ("/health", "/ready", "/openapi.json", "/docs", "/redoc")
# (method, path prefix) the agent token may call. Empty since M0 (SEC-08):
# anything not listed needs the approver token.
AGENT_ROUTES: tuple[tuple[str, str], ...] = ()


def ensure_tokens() -> tuple[str, str]:
    """Return (agent, approver) tokens, generating any that are unset.

    Generated tokens are stored in this process's environment so that
    workers and the launcher see the same values.
    """
    for name in (AGENT_ENV, APPROVER_ENV):
        if not os.environ.get(name):
            os.environ[name] = secrets.token_urlsafe(32)
    agent, approver = os.environ[AGENT_ENV], os.environ[APPROVER_ENV]
    if hmac.compare_digest(agent, approver):
        raise RuntimeError("SANDBOX_AGENT_TOKEN and SANDBOX_APPROVER_TOKEN must differ")
    return agent, approver


def is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def check_bind(host: str) -> None:
    """Refuse a non-loopback bind unless both tokens were set explicitly."""
    if not is_loopback(host) and not (os.environ.get(AGENT_ENV) and os.environ.get(APPROVER_ENV)):
        raise SystemExit(
            f"Refusing to listen on {host}: set {AGENT_ENV} and {APPROVER_ENV} "
            "first, or bind 127.0.0.1."
        )


def role_for(token: str | None) -> str | None:
    if not token:
        return None
    agent, approver = ensure_tokens()
    if hmac.compare_digest(token, approver):
        return "approver"
    if hmac.compare_digest(token, agent):
        return "agent"
    return None


def is_public(path: str) -> bool:
    return any(path == p or path.startswith(p + "/") for p in PUBLIC_ROUTES)


def is_agent_route(method: str, path: str) -> bool:
    return any((m == "*" or m == method) and path.startswith(p) for m, p in AGENT_ROUTES)


def _bearer(request: Request) -> str | None:
    auth = request.headers.get("authorization", "")
    scheme, _, value = auth.partition(" ")
    return value.strip() if scheme.lower() == "bearer" else None


class TokenAuthMiddleware:
    """Pure ASGI middleware: HTTP requests need a token for their role.

    WebSocket connections are closed before accept (fail closed: a WebSocket
    route added later must not be reachable without a token check).
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "websocket":
            await send({"type": "websocket.close", "code": 1008})
            return
        if scope["type"] != "http" or scope["method"] == "OPTIONS" or is_public(scope["path"]):
            await self.app(scope, receive, send)
            return
        request = Request(scope)
        role = role_for(_bearer(request))
        if role is None:
            response = JSONResponse({"detail": "Missing or invalid API token"}, status_code=401,
                                    headers={"WWW-Authenticate": "Bearer"})
        elif role == "agent" and not is_agent_route(scope["method"], scope["path"]):
            response = JSONResponse({"detail": "This route needs the approver token"}, status_code=403)
        else:
            await self.app(scope, receive, send)
            return
        await response(scope, receive, send)
