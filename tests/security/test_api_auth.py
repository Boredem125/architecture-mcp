"""HTTP API authentication: agents can ask, only approvers can decide.

Regression for the unauthenticated broker: before, anyone who could reach the
API (it bound 0.0.0.0) could submit a shell command and approve it themselves,
and the broker ran it outside the jail with shell=True.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from sandbox.api import auth
from sandbox.api.app import create_app


@pytest.fixture
def tokens(monkeypatch):
    monkeypatch.setenv(auth.AGENT_ENV, "agent-token-for-tests")
    monkeypatch.setenv(auth.APPROVER_ENV, "approver-token-for-tests")
    return "agent-token-for-tests", "approver-token-for-tests"


@pytest.fixture
def client(tokens):
    return TestClient(create_app())


def bearer(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def test_public_routes_need_no_token(client):
    assert client.get("/health").status_code == 200
    assert client.get("/openapi.json").status_code == 200


def test_no_token_is_rejected(client):
    r = client.get("/api/v1/broker/pending")
    assert r.status_code == 401
    assert client.post("/api/v1/broker/request", json={}).status_code == 401


def test_wrong_token_is_rejected(client):
    assert client.get("/api/v1/broker/pending", headers=bearer("nope")).status_code == 401


def test_agent_can_submit_but_not_approve(client, tokens):
    agent, _ = tokens
    body = {"session_id": "s", "run_id": "r", "agent_id": "a", "command": "echo hi", "jail_dir": "."}
    r = client.post("/api/v1/broker/request", json=body, headers=bearer(agent))
    assert r.status_code == 200
    rid = r.json()["request_id"]
    decision = {"reviewer_id": "agent-pretending", "reason": "self-approve"}
    r = client.post(f"/api/v1/broker/{rid}/approve", json=decision, headers=bearer(agent))
    assert r.status_code == 403
    assert client.get("/api/v1/broker/pending", headers=bearer(agent)).status_code == 403


def test_approver_reaches_approver_and_agent_routes(client, tokens):
    _, approver = tokens
    assert client.get("/api/v1/broker/pending", headers=bearer(approver)).status_code == 200
    body = {"session_id": "s", "run_id": "r", "agent_id": "a", "command": "echo hi", "jail_dir": "."}
    assert client.post("/api/v1/broker/request", json=body, headers=bearer(approver)).status_code == 200


def test_agent_cannot_install_or_remove_hooks(client, tokens):
    agent, _ = tokens
    assert client.post("/api/v1/hook/connect", json={}, headers=bearer(agent)).status_code == 403
    assert client.post("/api/v1/hook/disconnect/x", headers=bearer(agent)).status_code == 403


def test_websocket_needs_approver_token(client, tokens):
    agent, approver = tokens
    from starlette.websockets import WebSocketDisconnect

    for bad in ("", agent):
        with pytest.raises(WebSocketDisconnect):
            with client.websocket_connect(f"/ws/events?token={bad}") as ws:
                ws.receive_json()
    with client.websocket_connect(f"/ws/events?token={approver}"):
        pass


def test_generated_tokens_differ(monkeypatch):
    monkeypatch.delenv(auth.AGENT_ENV, raising=False)
    monkeypatch.delenv(auth.APPROVER_ENV, raising=False)
    agent, approver = auth.ensure_tokens()
    assert agent and approver and agent != approver


def test_non_loopback_bind_needs_explicit_tokens(monkeypatch):
    monkeypatch.delenv(auth.AGENT_ENV, raising=False)
    monkeypatch.delenv(auth.APPROVER_ENV, raising=False)
    auth.check_bind("127.0.0.1")
    auth.check_bind("localhost")
    with pytest.raises(SystemExit):
        auth.check_bind("0.0.0.0")
    monkeypatch.setenv(auth.AGENT_ENV, "a")
    monkeypatch.setenv(auth.APPROVER_ENV, "b")
    auth.check_bind("0.0.0.0")


def test_same_token_for_both_roles_is_refused(monkeypatch):
    monkeypatch.setenv(auth.AGENT_ENV, "same")
    monkeypatch.setenv(auth.APPROVER_ENV, "same")
    with pytest.raises(RuntimeError):
        auth.ensure_tokens()
