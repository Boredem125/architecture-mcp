"""Cryptographic maker-checker — signed, verifiable approvals."""
from __future__ import annotations

import pytest

from sandbox.connector.install import init
from sandbox.connector.layout import FolderLayout
from sandbox.connector.signing import sign_record, verify_record


@pytest.fixture
def layout(tmp_path):
    init(tmp_path, claude=False, mcp=False)
    return FolderLayout(tmp_path)


def test_sign_and_verify_roundtrip(layout):
    rec = {
        "request_id": "r1", "command": "npm install",
        "identity": {"user": "alice", "agent_type": "claude-code"},
        "trigger": ["shell"], "reason_code": "SHELL", "decision": "approved",
        "reviewer_id": "dell", "exit_code": 0,
    }
    sign_record(layout, "dell", rec)
    assert rec["signature"]
    assert rec["signer_public_key"]
    assert verify_record(rec) is True


def test_tamper_breaks_verification(layout):
    rec = {
        "request_id": "r2", "command": "npm install",
        "decision": "approved", "reviewer_id": "dell", "exit_code": 0,
    }
    sign_record(layout, "dell", rec)
    assert verify_record(rec) is True

    # Tamper with a signed field — the command the approver authorized.
    rec["command"] = "rm -rf /"
    assert verify_record(rec) is False


def test_unsigned_record_fails_verification():
    assert verify_record({"request_id": "x", "command": "ls"}) is False


def test_finish_signs_the_record(layout):
    """queue.finish is the chokepoint — every terminal record comes out signed."""
    from sandbox.connector.queue import EscalationQueue

    queue = EscalationQueue(layout)
    rid = queue.submit({
        "root": str(layout.root), "trigger": ["shell"], "kind": "command",
        "command": "echo hi", "identity": {"user": "alice"}, "reason_code": "SHELL",
    })
    rec = queue.claim(rid, "dell")
    queue.finish(rid, {
        **{k: rec[k] for k in ("identity", "trigger", "reason_code") if k in rec},
        "state": "executed", "decision": "approved", "reviewer_id": "dell",
        "exit_code": 0,
    })
    done = queue.get(rid)
    assert done["signature"]
    assert verify_record(done) is True


def test_reviewer_key_is_stable(layout):
    """The same reviewer signs with the same key across calls (persisted seed)."""
    r1 = {"request_id": "a", "command": "x", "reviewer_id": "dell"}
    r2 = {"request_id": "b", "command": "y", "reviewer_id": "dell"}
    sign_record(layout, "dell", r1)
    sign_record(layout, "dell", r2)
    assert r1["signer_public_key"] == r2["signer_public_key"]
