"""Shared fake server helpers for M2 Postgres-free tests.

This module provides lightweight fake HTTP server plumbing that mimics the
``agg_cp`` sync routes.  Tests configure the fake's responses and then
exercise the connector or CLI code against it.

Shared across T7, T8, T9, T10.  Each task adds only what it needs.
"""
from __future__ import annotations

import json
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Any


class FakeResponse:
    """Canned HTTP response."""
    __slots__ = ("status", "body", "headers")

    def __init__(self, status: int = 200, body: Any = None,
                 headers: dict[str, str] | None = None):
        self.status = status
        self.body = body
        self.headers = headers or {}


class FakeSyncHandler(BaseHTTPRequestHandler):
    """Handler whose responses are driven by the server's ``routes`` dict.

    ``routes`` maps ``(method, path)`` to either a ``FakeResponse`` or a
    callable ``(handler, body_bytes) -> FakeResponse``.  Unmatched paths
    return 404.  The server records every request in ``requests``.
    """

    def _respond(self) -> None:
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length) if content_length else b""

        key = (self.command, self.path.split("?")[0])
        # Record the request for assertions
        self.server.requests.append({  # type: ignore[attr-defined]
            "method": self.command,
            "path": self.path,
            "headers": dict(self.headers),
            "body": body,
        })

        route = self.server.routes.get(key)  # type: ignore[attr-defined]
        if route is None:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b'{"error":"not found"}')
            return

        resp = route(self, body) if callable(route) else route
        self.send_response(resp.status)
        self.send_header("Content-Type", "application/json")
        for k, v in resp.headers.items():
            self.send_header(k, v)
        self.end_headers()
        if resp.body is not None:
            payload = json.dumps(resp.body).encode() if not isinstance(resp.body, bytes) else resp.body
            self.wfile.write(payload)

    do_GET = _respond
    do_POST = _respond
    do_PUT = _respond
    do_DELETE = _respond

    def log_message(self, format, *args):  # noqa: A002
        pass  # silence request logs during tests


class FakeSyncServer:
    """A threaded HTTP server for testing sync endpoints.

    Usage::

        with FakeSyncServer() as srv:
            srv.routes[("POST", "/api/v1/sync/signer/link")] = FakeResponse(200, {"ok": True})
            # ... exercise client code against srv.base_url ...
            assert len(srv.requests) == 1
    """

    def __init__(self, host: str = "127.0.0.1", port: int = 0):
        self._server = HTTPServer((host, port), FakeSyncHandler)
        self._server.routes = {}  # type: ignore[attr-defined]
        self._server.requests = []  # type: ignore[attr-defined]
        self._thread: threading.Thread | None = None

    @property
    def routes(self) -> dict:
        return self._server.routes  # type: ignore[attr-defined]

    @property
    def requests(self) -> list[dict]:
        return self._server.requests  # type: ignore[attr-defined]

    @property
    def base_url(self) -> str:
        host, port = self._server.server_address
        return f"http://{host}:{port}"

    def start(self) -> "FakeSyncServer":
        self._thread = threading.Thread(target=self._server.serve_forever,
                                        daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        self._server.shutdown()
        if self._thread:
            self._thread.join(timeout=5)

    def __enter__(self) -> "FakeSyncServer":
        return self.start()

    def __exit__(self, *exc) -> None:
        self.stop()
