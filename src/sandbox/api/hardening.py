"""HTTP hardening: security headers and error bodies that reveal nothing.

Both came from the ZAP API scan in CI: responses lacked X-Content-Type-Options
and Cross-Origin-Resource-Policy, and unhandled exceptions produced error
responses ZAP reads as application error disclosure. An unexpected error now
returns a fixed body with an error id; the traceback goes to the server log
under the same id, never to the client.
"""
from __future__ import annotations

import uuid

import structlog
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

logger = structlog.get_logger()

SECURITY_HEADERS = {
    b"x-content-type-options": b"nosniff",
    b"cross-origin-resource-policy": b"same-origin",
    b"x-frame-options": b"DENY",
    b"referrer-policy": b"no-referrer",
    # API responses carry approvals, audit records and tokens: never cache them.
    b"cache-control": b"no-store",
}


class SecurityHeadersMiddleware:
    """Pure ASGI middleware: adds SECURITY_HEADERS to every HTTP response."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                present = {k.lower() for k, _ in message.get("headers", [])}
                message.setdefault("headers", [])
                message["headers"] = list(message["headers"]) + [
                    (k, v) for k, v in SECURITY_HEADERS.items() if k not in present
                ]
            await send(message)

        await self.app(scope, receive, send_with_headers)


def install_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(Exception)
    async def _unexpected(request: Request, exc: Exception) -> JSONResponse:  # noqa: ARG001
        error_id = uuid.uuid4().hex[:12]
        logger.exception("unhandled_error", error_id=error_id, path=request.url.path, method=request.method)
        return JSONResponse({"detail": "Internal error", "error_id": error_id}, status_code=500)
