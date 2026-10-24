"""M2 T12b-1 security review (C9 round 2): proof tests.

Each strict xfail is a finding: it asserts the safe behaviour and fails today
because the attack works.  The fix flips it to XPASS (strict), so the builder
must remove the marker in the fixing change.  Plain tests (no marker) close a
coverage gap and must stay green.

Findings (see the review report):
  R1  apply_external compares the approval fingerprint with the STORED one,
      never with the recomputed one: exec_cwd, root, kind, tool_name and
      requires_dual are not bound (C4).
  R1c the hook never stamps the binding fingerprint on real records (C4).
  R2  verify_evidence counts dual control from the unsigned-by-humans
      ``approved_by`` list; envelopes are not re-verified (C8, C9 item 9).
  R3a a key removed in a signed later registry version still approves (C4).
  R3b an older signed registry prefix is accepted (no high-water; C6, C9 item 5).
  R4  the broker inherits the caller's environment (C9 item 6).
  R5  enroll accepts a server org_id that differs from the genesis org (C9 item 7).
"""
from __future__ import annotations

import asyncio
import json
import sys
import time

import pytest

from tests.security.test_m2_t12_remote import (
    _create_pending_request,
    _keygen,
    _make_remote_approval,
    _setup_managed_workspace,
    _ws,
)


def _approvals(ctx, rec, request_id, *signers):
    common = dict(request_id=request_id, command=rec["command"],
                  fingerprint=rec["fingerprint"],
                  policy_sequence=ctx["policy_sequence"])
    return [_make_remote_approval(sk, user_id=uid, **common) for sk, uid in signers]


def _edit_both_copies(lay, request_id, **changes):
    """Edit the pending record in both pending dirs, leaving the stored
    fingerprint untouched (an attacker who can write .sandbox/)."""
    for d in (lay.root / ".sandbox" / "pending", lay.pending_dir):
        f = d / f"{request_id}.json"
        data = json.loads(f.read_text(encoding="utf-8"))
        data.update(changes)
        f.write_text(json.dumps(data), encoding="utf-8")


# ---------------------------------------------------------------------------
# R1: the stored fingerprint is trusted; the recomputed one is never compared
# ---------------------------------------------------------------------------

def test_r1_exec_cwd_edited_after_stamp_refused(tmp_path, monkeypatch):
    bob, carol = _keygen(), _keygen()
    ctx = _setup_managed_workspace(
        tmp_path, monkeypatch,
        approver_sks=[(bob[0], bob[1], bob[2], "user-bob", "cli"),
                      (carol[0], carol[1], carol[2], "user-carol", "cli")])
    lay = ctx["lay"]
    rec = _create_pending_request(lay, "req-r1-cwd")
    approvals = _approvals(ctx, rec, "req-r1-cwd",
                           (bob[0], "user-bob"), (carol[0], "user-carol"))
    other = tmp_path / "attacker-dir"
    other.mkdir()
    _edit_both_copies(lay, "req-r1-cwd", exec_cwd=str(other))

    from sandbox.connector.approval import apply_external
    result = asyncio.run(apply_external(lay, "req-r1-cwd", approvals,
                                        clock=lambda: time.time()))
    assert result["status"] != "executed", result.get("result", {}).get("exec_cwd")


def test_r1_requires_dual_flip_does_not_lower_count(tmp_path, monkeypatch):
    bob = _keygen()
    ctx = _setup_managed_workspace(
        tmp_path, monkeypatch, single_admin=True,
        approver_sks=[(bob[0], bob[1], bob[2], "user-bob", "cli")])
    lay = ctx["lay"]
    rec = _create_pending_request(lay, "req-r1-dual", requires_dual=True)
    approvals = _approvals(ctx, rec, "req-r1-dual", (bob[0], "user-bob"))
    _edit_both_copies(lay, "req-r1-dual", requires_dual=False)

    from sandbox.connector.approval import apply_external
    result = asyncio.run(apply_external(lay, "req-r1-dual", approvals,
                                        clock=lambda: time.time()))
    assert result["status"] != "executed"


def test_r1c_hook_stamps_binding_fingerprint(tmp_path, monkeypatch):
    kh = tmp_path / "keyhome"
    kh.mkdir()
    monkeypatch.setenv("SANDBOX_KEY_HOME", str(kh))
    lay = _ws(tmp_path / "ws")
    from sandbox.connector.queue import EscalationQueue

    async def _no_wait(self, request_id, timeout=0, **_kw):  # do not block on a human
        return None
    monkeypatch.setattr(EscalationQueue, "wait", _no_wait)
    from sandbox.connector.hook_eval import pre_tool_use
    asyncio.run(pre_tool_use(
        {"tool_name": "Bash", "tool_input": {"command": "python /tmp/x.py"},
         "cwd": str(lay.root), "session_id": "r1c"}, lay))
    recs = [json.loads(f.read_text(encoding="utf-8"))
            for f in lay.pending_dir.glob("*.json")]
    assert len(recs) == 1  # precondition: the hook escalated it
    from sandbox.connector.approval import _binding_fingerprint
    rec = recs[0]
    assert rec.get("fingerprint") and rec["fingerprint"] == _binding_fingerprint(rec)


# ---------------------------------------------------------------------------
# R2: evidence trusts approved_by
# ---------------------------------------------------------------------------

def test_r2_evidence_forged_approved_by_fails_dual(tmp_path):
    lay = _ws(tmp_path / "ws")
    from sandbox.connector.evidence import check_decision
    from sandbox.connector.signing import reviewer_public_key, sign_record

    rec = {
        "request_id": "req-r2", "command": "deploy prod", "decision": "approved",
        "state": "executed", "requires_dual": True, "reviewer_id": "cli",
        "remote_approvals": [{"forged": 1}, {"forged": 2}],
        "approved_by": [{"user_id": "alice"}, {"user_id": "bob"}],
    }
    signed = sign_record(lay, "cli", rec)
    keys = {"cli": reviewer_public_key(lay, "cli")}
    checks = check_decision(signed, "req-r2", keys)
    dual = [c for c in checks if c["check"] == "dual_control"]
    assert dual and not any(c["ok"] for c in dual), dual


# ---------------------------------------------------------------------------
# R3: registry rollback to an older signed prefix
# ---------------------------------------------------------------------------

def _sign_registry(payload, admin_sks):
    tag = b"agg/registry/v1"
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    msg = tag + b"\x00" + canonical
    return {"kind": "agg/registry/v1", "sig_v": 1, "payload": payload,
            "signatures": [{"key_id": kid, "alg": "ed25519",
                            "sig": sk.sign(msg).signature.hex()}
                           for sk, _pub, kid in admin_sks]}


def _registry_v2_without(ctx, removed_kid):
    """Signed registry v2 that removes one approver key (the plan's
    revocation: keys "added or removed"; the schema has no status field)."""
    from sandbox.protocol.registry import _payload_hash
    genesis = ctx["envelopes"][0]
    v2 = dict(genesis["payload"])
    v2["version"] = 2
    v2["prev_hash"] = _payload_hash(genesis["payload"])
    v2["keys"] = [k for k in genesis["payload"]["keys"] if k["key_id"] != removed_kid]
    return [genesis, _sign_registry(v2, ctx["admin_sks"])]


def _three_approvers(tmp_path, monkeypatch):
    bob, carol, mallory = _keygen(), _keygen(), _keygen()
    ctx = _setup_managed_workspace(
        tmp_path, monkeypatch,
        approver_sks=[(bob[0], bob[1], bob[2], "user-bob", "cli"),
                      (carol[0], carol[1], carol[2], "user-carol", "cli"),
                      (mallory[0], mallory[1], mallory[2], "user-mallory", "cli")])
    return ctx, bob, carol, mallory


def test_r3a_key_removed_in_v2_cannot_approve(tmp_path, monkeypatch):
    ctx, bob, _carol, mallory = _three_approvers(tmp_path, monkeypatch)
    lay = ctx["lay"]
    sync_dir = lay.root / ".sandbox" / "state" / "sync"
    (sync_dir / "registry.json").write_text(
        json.dumps(_registry_v2_without(ctx, mallory[2])), encoding="utf-8")
    from sandbox.connector.sync.verified_state import load_verified_state
    assert load_verified_state(lay) is not None  # precondition: v2 verifies
    rec = _create_pending_request(lay, "req-r3a")
    approvals = _approvals(ctx, rec, "req-r3a",
                           (mallory[0], "user-mallory"), (bob[0], "user-bob"))
    from sandbox.connector.approval import apply_external
    result = asyncio.run(apply_external(lay, "req-r3a", approvals,
                                        clock=lambda: time.time()))
    assert result["status"] != "executed"


def test_r3b_registry_prefix_rollback_refused(tmp_path, monkeypatch):
    ctx, bob, _carol, mallory = _three_approvers(tmp_path, monkeypatch)
    lay = ctx["lay"]
    sync_dir = lay.root / ".sandbox" / "state" / "sync"
    (sync_dir / "registry.json").write_text(
        json.dumps(_registry_v2_without(ctx, mallory[2])), encoding="utf-8")
    from sandbox.connector.sync.verified_state import load_verified_state
    vs = load_verified_state(lay)
    # Precondition (fails today because of R3a): v2 is in force without mallory.
    assert vs is not None and mallory[2] not in vs.registry._keys
    # The operator truncates the file back to the genesis prefix.
    (sync_dir / "registry.json").write_text(
        json.dumps(ctx["envelopes"][:1]), encoding="utf-8")
    rec = _create_pending_request(lay, "req-r3b")
    approvals = _approvals(ctx, rec, "req-r3b",
                           (mallory[0], "user-mallory"), (bob[0], "user-bob"))
    from sandbox.connector.approval import apply_external
    result = asyncio.run(apply_external(lay, "req-r3b", approvals,
                                        clock=lambda: time.time()))
    assert result["status"] != "executed"


# ---------------------------------------------------------------------------
# R4: the broker inherits the caller's environment
# ---------------------------------------------------------------------------

def test_r4_broker_uses_clean_env(tmp_path, monkeypatch):
    bob, carol = _keygen(), _keygen()
    ctx = _setup_managed_workspace(
        tmp_path, monkeypatch,
        approver_sks=[(bob[0], bob[1], bob[2], "user-bob", "cli"),
                      (carol[0], carol[1], carol[2], "user-carol", "cli")])
    lay = ctx["lay"]
    monkeypatch.setenv("AGG_POISON", "POISONED7f3")
    cmd = f'"{sys.executable}" -c "import os;print(os.environ.get(\'AGG_POISON\',\'clean\'))"'
    rec = _create_pending_request(lay, "req-r4", command=cmd)
    approvals = _approvals(ctx, rec, "req-r4",
                           (bob[0], "user-bob"), (carol[0], "user-carol"))
    from sandbox.connector.approval import apply_external
    result = asyncio.run(apply_external(lay, "req-r4", approvals,
                                        clock=lambda: time.time()))
    assert result["status"] == "executed"  # precondition: it ran
    assert "POISONED7f3" not in (result["result"].get("stdout") or "")


# ---------------------------------------------------------------------------
# R5: enroll org_id must equal the genesis org
# ---------------------------------------------------------------------------

def test_r5_enroll_org_must_equal_genesis_org(tmp_path, monkeypatch):
    from tests.m2_fakes import FakeResponse, FakeSyncServer
    from tests.security.test_m2_enroll_persist import (
        _enroll_response, _make_genesis_and_fingerprint,
    )
    kh = tmp_path / "keyhome"
    kh.mkdir()
    monkeypatch.setenv("SANDBOX_KEY_HOME", str(kh))
    lay = _ws(tmp_path / "ws")
    monkeypatch.chdir(lay.root)
    fp, genesis_env = _make_genesis_and_fingerprint(org_id="org-1")
    from sandbox.connector.sync.enroll import EnrollError, enroll
    raised = False
    with FakeSyncServer() as srv:
        srv.routes[("POST", "/api/v1/sync/enroll")] = FakeResponse(
            200, _enroll_response(genesis_env, org_id="org-evil"))
        try:
            enroll(srv.base_url, "CODE-OK", fp)
        except EnrollError:
            raised = True
    assert raised


# ---------------------------------------------------------------------------
# Coverage gap: C1 failed nonce save, on every OS (the T12b test is POSIX-only)
# ---------------------------------------------------------------------------

def test_c1_nonce_save_failure_runs_nothing_any_os(tmp_path, monkeypatch):
    bob, carol = _keygen(), _keygen()
    ctx = _setup_managed_workspace(
        tmp_path, monkeypatch,
        approver_sks=[(bob[0], bob[1], bob[2], "user-bob", "cli"),
                      (carol[0], carol[1], carol[2], "user-carol", "cli")])
    lay = ctx["lay"]
    rec = _create_pending_request(lay, "req-c1")
    approvals = _approvals(ctx, rec, "req-c1",
                           (bob[0], "user-bob"), (carol[0], "user-carol"))
    import sandbox.connector.approval as appr
    monkeypatch.setattr(appr, "_save_seen_nonces", lambda *a, **k: False)
    result = asyncio.run(appr.apply_external(lay, "req-c1", approvals,
                                             clock=lambda: time.time()))
    assert result["status"] == "nonce_save_failed"
    assert (lay.pending_dir / "req-c1.json").exists()
    assert not (lay.done_dir / "req-c1.json").exists()
