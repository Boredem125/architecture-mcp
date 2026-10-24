"""M2 T12b-1 security review round 4: proof tests (strict xfail = open finding).

  Q6  deleting enrollment.json (device_id file kept) silently drops the
      operator exclusion: the operator plus one other approver execute.
  Q2  without an out-of-band root, verify_evidence still reports ok=True and
      dual_control ok=True for a pack whose dual control rests only on the
      pack's own (self-asserted) registry root.
"""
from __future__ import annotations

import asyncio
import time

import pytest

from tests.security.test_m2_t12_remote import (
    _create_pending_request, _keygen, _make_remote_approval, _setup_managed_workspace,
)


def test_q6_missing_enrollment_does_not_drop_operator_exclusion(tmp_path, monkeypatch):
    op, carol = _keygen(), _keygen()
    ctx = _setup_managed_workspace(
        tmp_path, monkeypatch,
        approver_sks=[(op[0], op[1], op[2], "operator-alice", "cli"),
                      (carol[0], carol[1], carol[2], "user-carol", "cli")],
        operator_user_id="operator-alice", allow_requester=False)
    lay = ctx["lay"]
    (lay.root / ".sandbox" / "state" / "sync" / "enrollment.json").unlink()
    rec = _create_pending_request(lay, "req-q6")
    common = dict(request_id="req-q6", command=rec["command"],
                  fingerprint=rec["fingerprint"], policy_sequence=ctx["policy_sequence"])
    approvals = [_make_remote_approval(op[0], user_id="operator-alice", **common),
                 _make_remote_approval(carol[0], user_id="user-carol", **common)]
    from sandbox.connector.approval import apply_external
    result = asyncio.run(apply_external(lay, "req-q6", approvals, clock=lambda: time.time()))
    assert result["status"] != "executed"


def test_q2_remote_dual_without_expected_root_is_not_ok(tmp_path, monkeypatch):
    from tests.security.test_m2_t12b_remote import _two_approvers
    ctx, bob, carol = _two_approvers(tmp_path, monkeypatch)
    lay = ctx["lay"]
    rec = _create_pending_request(lay, "req-q2")
    common = dict(request_id="req-q2", command=rec["command"],
                  fingerprint=rec["fingerprint"], policy_sequence=ctx["policy_sequence"])
    approvals = [_make_remote_approval(bob[0], user_id="user-bob", **common),
                 _make_remote_approval(carol[0], user_id="user-carol", **common)]
    from sandbox.connector.approval import apply_external
    assert asyncio.run(apply_external(lay, "req-q2", approvals,
                                      clock=lambda: time.time()))["status"] == "executed"
    from sandbox.connector.evidence import export_evidence, verify_evidence
    pack = tmp_path / "pack.zip"
    export_evidence(lay, pack)
    vr = verify_evidence(pack)  # no out-of-band root
    assert vr.get("remote_root_unverified") is True  # precondition
    assert vr["ok"] is not True
