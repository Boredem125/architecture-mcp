"""WebSocket connections are refused before accept, whatever the token.

M0 removed the only WebSocket route (/ws/events) and its test
(test_websocket_needs_approver_token). TokenAuthMiddleware now closes every
WebSocket scope with code 1008 before the app sees it, so a WebSocket route
added later cannot be reachable without a token check (fail closed).
Condition of security-engineer's T4 sign-off.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from sandbox.api import auth
from sandbox.api.app import create_app

AGENT = "agent-token-ws"
APPROVER = "approver-token-ws"


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv(auth.AGENT_ENV, AGENT)
    monkeypatch.setenv(auth.APPROVER_ENV, APPROVER)
    return TestClient(create_app())


def test_every_websocket_is_closed_before_accept(client):
    app = client.app

    # A WebSocket route mounted on the app must still be refused: the
    # middleware runs before routing.
    @app.websocket("/ws/added-later")
    async def added_later(ws):  # pragma: no cover - must never run
        await ws.accept()
        await ws.send_json({"leak": True})

    paths = ("/ws/events", "/ws/added-later", "/api/v1/connector/anything", "/health")
    for path in paths:
        for token in ("", AGENT, APPROVER, "wrong"):
            for how in ("query", "header"):
                url = f"{path}?token={token}" if how == "query" else path
                headers = {"Authorization": f"Bearer {token}"} if how == "header" and token else {}
                with pytest.raises(WebSocketDisconnect) as exc:
                    with client.websocket_connect(url, headers=headers) as ws:
                        ws.receive_json()
                assert exc.value.code == 1008, (path, token, how)
