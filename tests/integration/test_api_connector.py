"""Connector REST view — first create_app + TestClient test in the repo.

Also guards the M1 regression: /api/v1/launch and /api/v1/hook/* must still
exist after we mounted the connector router.
"""
from __future__ import annotations

import asyncio

import pytest
from fastapi.testclient import TestClient

from sandbox.api.app import create_app
from sandbox.connector.broker import FolderBroker
from sandbox.connector.install import init
from sandbox.connector.layout import FolderLayout
from sandbox.connector.queue import EscalationQueue


@pytest.fixture
def client():
    from sandbox.api.auth import ensure_tokens

    app = create_app()
    return TestClient(app, headers={"Authorization": f"Bearer {ensure_tokens()[1]}"})


@pytest.fixture
def folder(tmp_path):
    init(tmp_path, claude=False, mcp=False)
    return tmp_path


# --- M1 regression guard ---------------------------------------------------

def test_m1_routes_still_exist(client):
    paths = set(client.get("/openapi.json").json()["paths"].keys())
    assert "/api/v1/launch" in paths
    assert any(p.startswith("/api/v1/hook") for p in paths)
    assert any(p.startswith("/api/v1/connector") for p in paths)


# --- connector view --------------------------------------------------------

def test_status_404_without_sandbox(client, tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()
    resp = client.get("/api/v1/connector/status", params={"root": str(empty)})
    assert resp.status_code == 404


def test_status_returns_triggers(client, folder):
    resp = client.get("/api/v1/connector/status", params={"root": str(folder)})
    assert resp.status_code == 200
    data = resp.json()
    assert data["triggers"]["shell"] == "escalate"
    assert data["pending_count"] == 0


def test_pending_reflects_queue(client, folder):
    layout = FolderLayout(folder)
    queue = EscalationQueue(layout)
    queue.submit({
        "root": str(folder), "origin": "hook", "trigger": ["shell"],
        "command": "echo hi", "exec_cwd": str(folder), "kind": "command",
    })
    resp = client.get("/api/v1/connector/pending", params={"root": str(folder)})
    assert resp.status_code == 200
    assert len(resp.json()["pending"]) == 1


def test_approve_runs_and_finishes(client, folder):
    import sys

    layout = FolderLayout(folder)
    queue = EscalationQueue(layout)
    rid = queue.submit({
        "root": str(folder), "origin": "hook", "trigger": ["shell"],
        "command": f'{sys.executable} -c "print(123)"',
        "exec_cwd": str(folder), "kind": "command",
    })
    resp = client.post(
        f"/api/v1/connector/{rid}/approve", params={"root": str(folder)},
        json={"reason": "test"},
    )
    assert resp.status_code == 200
    assert resp.json()["state"] == "executed"

    # Queue no longer lists it as pending.
    pending = client.get("/api/v1/connector/pending", params={"root": str(folder)})
    assert pending.json()["pending"] == []


def test_deny_marks_denied(client, folder):
    layout = FolderLayout(folder)
    queue = EscalationQueue(layout)
    rid = queue.submit({
        "root": str(folder), "origin": "hook", "trigger": ["shell"],
        "command": "rm -rf /", "exec_cwd": str(folder), "kind": "command",
    })
    resp = client.post(
        f"/api/v1/connector/{rid}/deny", params={"root": str(folder)},
        json={"reason": "nope"},
    )
    assert resp.status_code == 200
    assert resp.json()["state"] == "denied"


def test_verify_valid_chain(client, folder):
    from sandbox.connector.audit import FolderAudit

    layout = FolderLayout(folder)
    session_id = "s-test"
    audit = FolderAudit(layout.audit_dir, session_id)
    audit.append({"event": "e1"})
    audit.append({"event": "e2"})

    # The endpoint uses the session.json session_id; write one so it matches.
    import json

    sess = json.loads(layout.session_file.read_text())
    sess["session_id"] = session_id
    layout.session_file.write_text(json.dumps(sess))

    resp = client.get("/api/v1/connector/verify", params={"root": str(folder)})
    assert resp.status_code == 200
    assert resp.json()["valid"] is True
