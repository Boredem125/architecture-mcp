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


def test_signer_client_uses_signer_token_and_get_route(tmp_path, monkeypatch):
    """T12b-2: signer approve calls GET detail then POSTs with a signer token.

    The signer client must:
    1. POST /api/v1/sync/signer/token to get a signer token
    2. GET /api/v1/sync/escalations/{id} with the signer token
    3. POST /api/v1/sync/escalations/{id}/approvals with the signer token
    """
    bob = _keygen()
    ctx = _setup_managed_workspace(
        tmp_path, monkeypatch,
        approver_sks=[
            (bob[0], bob[1], bob[2], "user-bob", "cli"),
        ],
    )
    lay = ctx["lay"]

    # Write a CLI key seed so _load_signer_key can find it
    from sandbox.connector.keyhome import key_home_root, workspace_id as _wsid
    kh = key_home_root()
    ws_id = _wsid(lay, create=True)
    ws_dir = kh / ws_id
    ws_dir.mkdir(parents=True, exist_ok=True)
    seed_path = ws_dir / f"{bob[2][:16]}.seed"
    seed_path.write_bytes(bytes(bob[0]))

    # Write enrollment with server_url
    sync_dir = lay.root / ".sandbox" / "state" / "sync"
    enroll_data = json.loads((sync_dir / "enrollment.json").read_text(encoding="utf-8"))

    esc_id = "esc-fake-123"
    fake_detail = {
        "escalation_id": esc_id,
        "request_id": "req-signer-1",
        "command": "echo signer-test",
        "fingerprint": hashlib.sha256(b"echo signer-test").hexdigest(),
        "device_id": ctx.get("device_id", "dev-1"),
        "project_id": ctx.get("project_id", "proj-1"),
        "org_id": ctx.get("org_id", "org-1"),
        "policy_sequence": ctx["policy_sequence"],
        "requires_dual": True,
        "status": "pending",
    }

    signer_token_value = "fake-signer-token-abc123"  # gitleaks:allow

    with FakeSyncServer() as srv:
        enroll_data["server_url"] = srv.base_url
        (sync_dir / "enrollment.json").write_text(
            json.dumps(enroll_data), encoding="utf-8",
        )

        # 1. Signer token route
        srv.routes[("POST", "/api/v1/sync/signer/token")] = FakeResponse(
            200, {"token": signer_token_value},
        )
        # 2. GET escalation detail
        srv.routes[("GET", f"/api/v1/sync/escalations/{esc_id}")] = FakeResponse(
            200, fake_detail,
        )
        # 3. POST approval
        srv.routes[("POST", f"/api/v1/sync/escalations/{esc_id}/approvals")] = FakeResponse(
            200, {"approval_id": "appr-1"},
        )

        from sandbox.cli.sync_cmds import _get_signer_token, _fetch_escalation, _post_approval
        from sandbox.cli.sync_cmds import _load_signer_key, _build_and_sign_envelope

        # Get signer token
        from sandbox.connector.sync.verified_state import load_verified_state
        vs = load_verified_state(lay)
        sk, kid, user_id = _load_signer_key(lay, vs)
        st = _get_signer_token(srv.base_url, sk, kid)
        assert st == signer_token_value, f"expected signer token, got {st}"

        # GET detail with signer token
        rec = _fetch_escalation(srv.base_url, esc_id, st)
        assert rec is not None
        assert rec["request_id"] == "req-signer-1"

        # POST approval with signer token
        envelope = _build_and_sign_envelope("req-signer-1", rec, vs, kid, sk, "approve")
        _post_approval(srv.base_url, esc_id, envelope, st)

    # Verify the requests used the signer token (not a device token)
    reqs = srv.requests
    # Should have: POST signer/token, GET detail, POST approval
    assert len(reqs) >= 3, f"expected >= 3 requests, got {len(reqs)}"

    # The GET detail request should have the signer token
    get_reqs = [r for r in reqs if r["method"] == "GET"
                and "escalations" in r["path"]]
    assert len(get_reqs) == 1
    assert f"Bearer {signer_token_value}" in get_reqs[0]["headers"].get("Authorization", "")

    # The POST approval request should have the signer token
    post_approval_reqs = [r for r in reqs if r["method"] == "POST"
                          and "approvals" in r["path"]]
    assert len(post_approval_reqs) == 1
    assert f"Bearer {signer_token_value}" in post_approval_reqs[0]["headers"].get("Authorization", "")
