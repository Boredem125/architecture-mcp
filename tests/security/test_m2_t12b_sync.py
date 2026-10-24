"""T12b sync integration test: run_once with FakeSyncServer.

Drives one full sync cycle: two approvals posted to the fake server
lead to exactly one broker run via apply_external.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import secrets
import time

import pytest

from tests.m2_fakes import FakeSyncServer, FakeResponse
from tests.security.test_m2_t12_remote import (
    _create_pending_request,
    _keygen,
    _make_remote_approval,
    _setup_managed_workspace,
    _ws,
)


def test_run_once_two_approvals_execute_once(tmp_path, monkeypatch):
    """run_once: two approvals from the fake server execute the command once."""
    bob = _keygen()
    carol = _keygen()
    ctx = _setup_managed_workspace(
        tmp_path, monkeypatch,
        approver_sks=[
            (bob[0], bob[1], bob[2], "user-bob", "cli"),
            (carol[0], carol[1], carol[2], "user-carol", "cli"),
        ],
    )
    lay = ctx["lay"]
    rec = _create_pending_request(lay, "req-sync-1", command="echo synced")

    # Build two approval envelopes
    common = dict(request_id="req-sync-1", command=rec["command"],
                  fingerprint=rec["fingerprint"],
                  policy_sequence=ctx["policy_sequence"])
    a_bob = _make_remote_approval(bob[0], user_id="user-bob", **common)
    a_carol = _make_remote_approval(carol[0], user_id="user-carol", **common)

    # The fake server returns both approvals as decision rows
    decisions = [
        {
            "request_id": "req-sync-1",
            "payload": a_bob["payload"],
            "signatures": a_bob["signatures"],
        },
        {
            "request_id": "req-sync-1",
            "payload": a_carol["payload"],
            "signatures": a_carol["signatures"],
        },
    ]

    with FakeSyncServer() as srv:
        srv.routes[("GET", "/api/v1/sync/decisions")] = FakeResponse(200, decisions)
        # Write server_url to enrollment so run_once can find it
        sync_dir = lay.root / ".sandbox" / "state" / "sync"
        enroll_data = json.loads((sync_dir / "enrollment.json").read_text(encoding="utf-8"))
        enroll_data["server_url"] = srv.base_url
        (sync_dir / "enrollment.json").write_text(json.dumps(enroll_data), encoding="utf-8")

        from sandbox.cli.sync_cmds import run_once
        result = run_once(lay, server=srv.base_url)

    # The command must have executed exactly once
    assert result["applied"].get("req-sync-1") == "executed", \
        f"expected 'executed', got {result['applied']}"

    # The done-record must exist
    from sandbox.connector.queue import EscalationQueue
    queue = EscalationQueue(lay)
    assert queue.status("req-sync-1") == "done"


def test_run_once_unknown_request_id_ignored(tmp_path, monkeypatch):
    """run_once: a decision for an unknown request_id is ignored."""
    ctx = _setup_managed_workspace(tmp_path, monkeypatch)
    lay = ctx["lay"]

    decisions = [{"request_id": "req-unknown", "payload": {}, "signatures": []}]

    with FakeSyncServer() as srv:
        srv.routes[("GET", "/api/v1/sync/decisions")] = FakeResponse(200, decisions)
        from sandbox.cli.sync_cmds import run_once
        result = run_once(lay, server=srv.base_url)

    assert "req-unknown" not in result["applied"]
