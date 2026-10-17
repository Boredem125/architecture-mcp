"""HTTP API authentication: only approvers can decide.

Regression for the unauthenticated broker: before, anyone who could reach the
API (it bound 0.0.0.0) could submit a shell command and approve it themselves,
and the broker ran it outside the jail with shell=True. Since M0 the API is
the connector view only; the agent token's 403 on every route is in
tests/security/test_m0_routes.py (R3).
"""
from __future__ import annotations

import sys

import pytest
from fastapi.testclient import TestClient

from sandbox.api import auth
from sandbox.api.app import create_app
from sandbox.connector.install import init
from sandbox.connector.layout import FolderLayout
from sandbox.connector.queue import EscalationQueue


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
    # R1: no token on a connector read and a connector decision is 401.
    r = client.get("/api/v1/connector/pending", params={"root": "."})
    assert r.status_code == 401
    assert r.headers["www-authenticate"] == "Bearer"
    r = client.post("/api/v1/connector/x/approve", params={"root": "."}, json={})
    assert r.status_code == 401
    assert r.headers["www-authenticate"] == "Bearer"


def test_wrong_token_is_rejected(client):
    # R2: same routes, wrong token.
    assert client.get("/api/v1/connector/pending", params={"root": "."},
                      headers=bearer("nope")).status_code == 401
    assert client.post("/api/v1/connector/x/approve", params={"root": "."}, json={},
                       headers=bearer("nope")).status_code == 401


def test_approver_reaches_approver_and_agent_routes(client, tokens, tmp_path):
    # R4: the approver reads status and pending, and approve moves a queued
    # request on (executed, or awaiting a second approver under dual control).
    # There are no agent routes left (AGENT_ROUTES is empty since M0).
    _, approver = tokens
    init(tmp_path, claude=False, mcp=False)
    rid = EscalationQueue(FolderLayout(tmp_path)).submit({
        "root": str(tmp_path), "origin": "hook", "trigger": ["shell"],
        "command": f'"{sys.executable}" -c "print(1)"',
        "exec_cwd": str(tmp_path), "kind": "command",
    })
    root = {"root": str(tmp_path)}
    assert client.get("/api/v1/connector/status", params=root, headers=bearer(approver)).status_code == 200
    r = client.get("/api/v1/connector/pending", params=root, headers=bearer(approver))
    assert r.status_code == 200
    assert rid in r.text
    r = client.post(f"/api/v1/connector/{rid}/approve", params=root, json={"reason": "R4"},
                    headers=bearer(approver))
    assert r.status_code == 200, r.text
    assert r.json()["state"] in ("executed", "awaiting_second_approval")


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
