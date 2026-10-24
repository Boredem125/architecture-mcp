"""M2 T12b-1 security review round 3: proof tests.

Each strict xfail is a finding: it asserts the safe behaviour and fails today
because the attack works.  The fix flips it to XPASS (strict), so the builder
must remove the marker in the fixing change.

  S1  the R3b high-water mark fails open: delete or corrupt
      ``high_water.json`` and an older signed registry prefix (with a key
      revoked in v2) is accepted again (C6, C9 item 5).
  S2  evidence re-verification counts a signed ``deny`` envelope as an
      approver (decision is not re-bound; C9 item 9).
  S3  ``verify_evidence`` trusts the pack's own ``keys/pinned_root.json``;
      there is no out-of-band root check, so the device holder can ship a
      self-made registry with two fake approvers (C9 item 9).
"""
from __future__ import annotations

import asyncio
import json
import time

import pytest

from tests.security.test_m2_t12_remote import _create_pending_request, _keygen
from tests.security.test_m2_t12b_review import (
    _approvals,
    _registry_v2_without,
    _three_approvers,
)


def _rollback_after(tmp_path, monkeypatch, hwm_action):
    ctx, bob, _carol, mallory = _three_approvers(tmp_path, monkeypatch)
    lay = ctx["lay"]
    sync_dir = lay.root / ".sandbox" / "state" / "sync"
    (sync_dir / "registry.json").write_text(
        json.dumps(_registry_v2_without(ctx, mallory[2])), encoding="utf-8")
    from sandbox.connector.sync.verified_state import load_verified_state
    vs = load_verified_state(lay)
    assert vs is not None and mallory[2] not in vs.registry._keys  # v2 in force
    assert (sync_dir / "high_water.json").exists()  # precondition: hwm written
    hwm_action(sync_dir / "high_water.json")
    (sync_dir / "registry.json").write_text(
        json.dumps(ctx["envelopes"][:1]), encoding="utf-8")
    rec = _create_pending_request(lay, "req-s1")
    approvals = _approvals(ctx, rec, "req-s1",
                           (mallory[0], "user-mallory"), (bob[0], "user-bob"))
    from sandbox.connector.approval import apply_external
    return asyncio.run(apply_external(lay, "req-s1", approvals,
                                      clock=lambda: time.time()))


def test_s1_hwm_deleted_rollback_refused(tmp_path, monkeypatch):
    result = _rollback_after(tmp_path, monkeypatch, lambda p: p.unlink())
    assert result["status"] != "executed"


def test_s1_hwm_corrupt_rollback_refused(tmp_path, monkeypatch):
    result = _rollback_after(
        tmp_path, monkeypatch, lambda p: p.write_text("{not json", encoding="utf-8"))
    assert result["status"] != "executed"


def _remote_env(sk, kid, payload):
    tag = b"agg/remote-approval/v1"
    msg = tag + b"\x00" + json.dumps(payload, sort_keys=True,
                                     separators=(",", ":")).encode()
    return {"kind": "agg/remote-approval/v1", "sig_v": 1, "payload": payload,
            "signatures": [{"key_id": kid, "alg": "ed25519",
                            "sig": sk.sign(msg).signature.hex()}]}


def test_s2_evidence_deny_envelope_not_counted(tmp_path):
    from tests.security.test_m2_t12_remote import _ws
    from sandbox.connector.evidence import check_decision
    from sandbox.connector.signing import reviewer_public_key, sign_record

    lay = _ws(tmp_path / "ws")
    bob, carol = _keygen(), _keygen()
    reg_keys = {
        bob[2]: {"user_id": "user-bob", "public_key": bytes(bob[0].verify_key).hex()},
        carol[2]: {"user_id": "user-carol",
                   "public_key": bytes(carol[0].verify_key).hex()},
    }
    base = {"request_id": "req-s2", "command": "deploy prod"}
    envs = [_remote_env(bob[0], bob[2], {**base, "decision": "approve"}),
            _remote_env(carol[0], carol[2], {**base, "decision": "deny"})]
    rec = {"request_id": "req-s2", "command": "deploy prod", "decision": "approved",
           "state": "executed", "requires_dual": True, "reviewer_id": "cli",
           "remote_approvals": envs}
    signed = sign_record(lay, "cli", rec)
    checks = check_decision(signed, "req-s2", {"cli": reviewer_public_key(lay, "cli")},
                            registry_keys=reg_keys)
    dual = [c for c in checks if c["check"] == "dual_control"]
    assert dual and not any(c["ok"] for c in dual), dual


def test_s3_verify_evidence_checks_root_out_of_band(tmp_path, monkeypatch):
    ctx, _bob, _carol, _mallory = _three_approvers(tmp_path, monkeypatch)
    from sandbox.connector.evidence import export_evidence, verify_evidence
    out = tmp_path / "pack"
    export_evidence(ctx["lay"], out)
    result = verify_evidence(out, expected_root="0" * 64)
    assert result["ok"] is False
