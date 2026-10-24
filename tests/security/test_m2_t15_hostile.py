"""M2 T15 hostile review: proof tests for cross-task findings.

Each test asserts the SECURE behaviour and is marked
``xfail(strict=True)`` while the finding is open, so the suite stays green
and the marker must be removed in the same change that fixes the finding
(an XPASS fails the run).  Finding ids refer to
``docs/control-plane/M2_SECURITY_SIGNOFF.md``.

Postgres-free (Q2): everything runs against the connector TCB directly.
"""
from __future__ import annotations

import asyncio
import json
import secrets
import time

import pytest

from tests.security.test_m2_t12_remote import (
    _create_pending_request,
    _keygen,
    _make_remote_approval,
    _setup_managed_workspace,
    _sign_envelope,
)


def _two_approvers(tmp_path, monkeypatch, **kw):
    bob = _keygen()
    carol = _keygen()
    ctx = _setup_managed_workspace(
        tmp_path, monkeypatch,
        approver_sks=[
            (bob[0], bob[1], bob[2], "user-bob", "cli"),
            (carol[0], carol[1], carol[2], "user-carol", "cli"),
        ],
        **kw,
    )
    return ctx, bob, carol


# -- H1: approvals are not bound to the request, device, project or org ------

@pytest.mark.xfail(strict=True, reason="T15 H1 open: apply_external does not bind the payload to the pending record")
def test_h1_approvals_for_another_request_do_not_execute(tmp_path, monkeypatch):
    """Two genuine approvals signed for request A on ANOTHER device and
    project must not execute pending request B on this device."""
    ctx, bob, carol = _two_approvers(tmp_path, monkeypatch)
    lay = ctx["lay"]
    rec_b = _create_pending_request(lay, "req-B", command="echo victim")

    other = dict(request_id="req-A", command="ls harmless", fingerprint="f" * 64,
                 device_id="dev-OTHER", project_id="proj-OTHER",
                 policy_sequence=ctx["policy_sequence"])
    a1 = _make_remote_approval(bob[0], user_id="user-bob", **other)
    a2 = _make_remote_approval(carol[0], user_id="user-carol", **other)
    assert rec_b["fingerprint"] != other["fingerprint"]

    from sandbox.connector.approval import apply_external
    result = asyncio.run(apply_external(
        lay, "req-B", [a1, a2],
        registry=ctx["envelopes"], policy_sequence=ctx["policy_sequence"],
        environment=ctx["environment"],
    ))
    assert result["status"] != "executed"


@pytest.mark.xfail(strict=True, reason="T15 H1 open: payload user_id is not bound to the key's registry user_id")
def test_h1_operator_cannot_dodge_exclusion_with_another_user_id(tmp_path, monkeypatch):
    """The operator signs with HER registered key but claims user_id
    'user-zed'.  Operator exclusion (S8, threat 28) must still drop it."""
    op = _keygen()
    carol = _keygen()
    ctx = _setup_managed_workspace(
        tmp_path, monkeypatch,
        approver_sks=[
            (op[0], op[1], op[2], "operator-alice", "cli"),
            (carol[0], carol[1], carol[2], "user-carol", "cli"),
        ],
        operator_user_id="operator-alice", allow_requester=False,
    )
    lay = ctx["lay"]
    rec = _create_pending_request(lay, "req-op")
    common = dict(request_id="req-op", command=rec["command"],
                  fingerprint=rec["fingerprint"],
                  policy_sequence=ctx["policy_sequence"])
    forged_uid = _make_remote_approval(op[0], user_id="user-zed", **common)
    carol_a = _make_remote_approval(carol[0], user_id="user-carol", **common)

    from sandbox.connector.approval import apply_external
    result = asyncio.run(apply_external(
        lay, "req-op", [forged_uid, carol_a],
        registry=ctx["envelopes"], policy_sequence=ctx["policy_sequence"],
        environment=ctx["environment"], operator_user_id="operator-alice",
    ))
    assert result["status"] == "awaiting_second"


# -- H2: approval settings read from the UNVERIFIED bundle.json --------------

@pytest.mark.xfail(strict=True, reason="T15 H2 open: _get_enforced_approval reads bundle.json without verifying it")
def test_h2_hand_edited_bundle_json_does_not_enable_local_fallback(tmp_path, monkeypatch):
    """A hand edit of .sandbox/state/sync/bundle.json (no valid signature)
    must not turn on approval.local_fallback in managed mode (S7, N5)."""
    ctx, _, _ = _two_approvers(tmp_path, monkeypatch, local_fallback=False)
    lay = ctx["lay"]
    bf = lay.root / ".sandbox" / "state" / "sync" / "bundle.json"
    data = json.loads(bf.read_text(encoding="utf-8"))
    data["payload"]["approval"]["local_fallback"] = True
    data["payload"]["approval"]["allow_requester"] = True
    bf.write_text(json.dumps(data), encoding="utf-8")  # unsigned hand edit

    _create_pending_request(lay, "req-h2", requires_dual=False)
    from sandbox.connector.approval import approve
    result = asyncio.run(approve(lay, "req-h2", "reviewer-local"))
    assert result["status"] == "managed_refused"


# -- H3: request_id path traversal in the TCB claim --------------------------

@pytest.mark.xfail(strict=True, reason="T15 H3 open: apply_external does not validate request_id")
def test_h3_request_id_traversal_cannot_move_sync_state(tmp_path, monkeypatch):
    """A server-supplied request_id like '../state/sync/seen_nonces' must not
    claim (rename) seen_nonces.json, with ZERO valid approvals."""
    ctx, _, _ = _two_approvers(tmp_path, monkeypatch)
    lay = ctx["lay"]
    sync_dir = lay.root / ".sandbox" / "state" / "sync"
    (lay.root / ".sandbox" / "pending").mkdir(parents=True, exist_ok=True)
    nonce_file = sync_dir / "seen_nonces.json"
    nonce_file.write_text(json.dumps({"used-nonce": time.time() + 10**6}), encoding="utf-8")

    from sandbox.connector.approval import apply_external
    try:
        asyncio.run(apply_external(
            lay, "../state/sync/seen_nonces", [],
            registry=ctx["envelopes"], policy_sequence=ctx["policy_sequence"],
            environment=ctx["environment"],
        ))
    except Exception:  # noqa: BLE001 -- a fix may raise "malformed request id";
        pass           # today the release step crashes AFTER the rename
    assert nonce_file.is_file(), "seen_nonces.json was moved: replay memory erased"


# -- M1: not_after null never expires and its nonce is never remembered ------

@pytest.mark.xfail(strict=True, reason="T15 M1 open: not_after null accepted")
def test_m1_null_not_after_refused(tmp_path, monkeypatch):
    ctx, bob, _ = _two_approvers(tmp_path, monkeypatch)
    lay = ctx["lay"]
    rec = _create_pending_request(lay, "req-m1", requires_dual=False)
    payload = {
        "request_id": "req-m1", "command": rec["command"],
        "fingerprint": rec["fingerprint"], "reviewer_id": "user-bob",
        "decision": "approve", "approved_at": time.time(),
        "org_id": "org-1", "project_id": "proj-1", "device_id": "dev-1",
        "registry_version": 1, "policy_sequence": ctx["policy_sequence"],
        "user_id": "user-bob", "key_id": bob[2],
        "nonce": secrets.token_hex(16), "not_after": None,
    }
    env = _sign_envelope("agg/remote-approval/v1", payload, bob[0])

    from sandbox.connector.approval import apply_external
    result = asyncio.run(apply_external(
        lay, "req-m1", [env],
        registry=ctx["envelopes"], policy_sequence=ctx["policy_sequence"],
        environment=ctx["environment"],
    ))
    assert result["status"] != "executed"
