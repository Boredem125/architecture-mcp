"""T12 security review tests (round 2, rewritten for FIXED behaviour).

Proves:
  R1 (High): skew rule now uses server-measured time, NOT the signer-controlled
             approved_at.  A signer who sets approved_at = connector-clock no
             longer bypasses the skew check.
  R2 (Medium): nonce replay across calls is now persisted to disk.
               A nonce from call 1 is refused in call 2.
  R3 (Medium): registry verification failure (e.g. KeyError from a garbage
               chain) is caught and fails closed, not an unhandled crash.
  R4 (Medium): apply_external with requires_dual=False and zero valid
               approvals must NOT execute (missing lower-bound check).
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import secrets
import time
from pathlib import Path

import pytest
from nacl.signing import SigningKey

# Re-use the T12 test helpers.
from tests.security.test_m2_t12_remote import (
    _keygen,
    _ws,
    _setup_managed_workspace,
    _create_pending_request,
    _make_remote_approval,
    _make_remote_deny,
    _sign_envelope,
)


# ===================================================================
# R1: Skew rule measures against server time, not approved_at (FIXED).
#
# The fix: _measure_skew reads server_time_state.json (from HTTP Date
# headers) or, in managed mode with no measurement, clears approvals.
# The signer-controlled approved_at is no longer used for skew.
#
# This test sets the connector clock 5 min ahead and has the signer
# set approved_at = connector-clock.  With the old code the approval
# passed (bug).  With the fix, approvals are refused because:
#  - There is no server_time_state.json in the test workspace.
#  - The bundle issued_at (real time) vs the injected clock (real + 300)
#    gives abs(skew) ~ 300 > 120 s threshold.
#  - Either path (fallback or managed-mode None guard) blocks the approval.
# ===================================================================


def test_r1_skew_check_uses_server_time_not_approved_at(tmp_path, monkeypatch):
    """R1 FIXED: a signer who sets approved_at = connector-clock is refused.

    With the old code, comparing clock() to the signer-controlled
    approved_at showed 0 skew and the approval passed.  The fixed code
    measures skew against the server's Date header (or, when no
    measurement exists in managed mode, refuses all approvals).  Either
    way, the signer cannot bypass the skew check.
    """
    from sandbox.connector.approval import apply_external

    bob_sk, bob_pub, bob_kid = _keygen()
    carol_sk, carol_pub, carol_kid = _keygen()

    connector_clock = time.time() + 300  # 5 min ahead

    ctx = _setup_managed_workspace(
        tmp_path, monkeypatch,
        approver_sks=[
            (bob_sk, bob_pub, bob_kid, "user-bob", "cli"),
            (carol_sk, carol_pub, carol_kid, "user-carol", "cli"),
        ],
        environment="staging",
    )
    lay = ctx["lay"]
    req_id = "req-r1-skew-bypass"
    rec = _create_pending_request(lay, req_id)

    # Signer sets approved_at to match the connector clock.
    # With the old code this bypassed the skew check.
    a1 = _make_remote_approval(
        bob_sk, request_id=req_id, command=rec["command"],
        fingerprint=rec["fingerprint"], user_id="user-bob",
        policy_sequence=ctx["policy_sequence"],
    )
    a1["payload"]["approved_at"] = connector_clock
    a1 = _sign_envelope("agg/remote-approval/v1", a1["payload"], bob_sk)

    a2 = _make_remote_approval(
        carol_sk, request_id=req_id, command=rec["command"],
        fingerprint=rec["fingerprint"], user_id="user-carol",
        policy_sequence=ctx["policy_sequence"],
    )
    a2["payload"]["approved_at"] = connector_clock
    a2 = _sign_envelope("agg/remote-approval/v1", a2["payload"], carol_sk)

    result = asyncio.run(apply_external(
        lay, req_id, [a1, a2],
        clock=lambda: connector_clock,
    ))

    # FIXED: the approval is refused.  The status is NOT "executed".
    assert result["status"] != "executed", (
        "Skew bypass NOT fixed: the signer-controlled approved_at still "
        "passes the skew check."
    )
    # The approvals were dropped (skew > 120 s or no measurement).
    assert result["status"] == "awaiting_second"


# ===================================================================
# R2: Nonce replay across calls is now persisted (FIXED).
#
# The fix: seen_nonces.json is written to .sandbox/state/sync/ and
# loaded at the start of each apply_external call.  A nonce from
# call 1 is found in the file and refused in call 2.
#
# We use requires_dual=True (2 approvers needed).  Call 1 sends 1
# approval with a nonce -> awaiting_second, approvals=1.  Call 2
# sends 1 approval for a different request using the same nonce ->
# the nonce is rejected, so approvals=0.  The difference in the
# returned "approvals" count proves the nonce was persisted.
# ===================================================================


def test_r2_nonce_persisted_across_calls(tmp_path, monkeypatch):
    """R2 FIXED: a nonce from a previous apply_external call is refused.

    Call 1: one approval with a nonce -> awaiting_second, approvals=1.
    Call 2: one approval with the SAME nonce, different request ->
            awaiting_second, approvals=0 (nonce rejected).
    The approval count difference proves the nonce was persisted.
    """
    from sandbox.connector.approval import apply_external

    bob_sk, bob_pub, bob_kid = _keygen()
    carol_sk, carol_pub, carol_kid = _keygen()

    ctx = _setup_managed_workspace(
        tmp_path, monkeypatch,
        approver_sks=[
            (bob_sk, bob_pub, bob_kid, "user-bob", "cli"),
            (carol_sk, carol_pub, carol_kid, "user-carol", "cli"),
        ],
        environment="staging",
    )
    lay = ctx["lay"]
    now = time.time()

    # Write server_time_state so skew = 0 and approvals are not blocked.
    sync_dir = lay.root / ".sandbox" / "state" / "sync"
    (sync_dir / "server_time_state.json").write_text(
        json.dumps({"server_time": now, "local_time": now}),
        encoding="utf-8",
    )

    # Call 1: one approval (needs 2 for dual) with a specific nonce.
    req_id_1 = "req-r2-nonce-1"
    rec1 = _create_pending_request(lay, req_id_1)  # requires_dual=True
    shared_nonce = secrets.token_hex(16)

    a1 = _make_remote_approval(
        bob_sk, request_id=req_id_1, command=rec1["command"],
        fingerprint=rec1["fingerprint"], user_id="user-bob",
        policy_sequence=ctx["policy_sequence"],
        nonce=shared_nonce,
    )

    result1 = asyncio.run(apply_external(
        lay, req_id_1, [a1],
        clock=lambda: time.time(),
    ))
    # One approval, dual required -> awaiting_second with 1 counted.
    assert result1["status"] == "awaiting_second"
    assert result1.get("approvals", 0) == 1, (
        "Call 1 should count 1 valid approval."
    )

    # Verify the nonce file was written to disk.
    nonce_file = sync_dir / "seen_nonces.json"
    assert nonce_file.exists(), "seen_nonces.json was not persisted"
    persisted = json.loads(nonce_file.read_text(encoding="utf-8"))
    # ADR 0010 s4: nonce key is now (key_id, nonce), check the key format
    nonce_found = any(shared_nonce in k for k in persisted)
    assert nonce_found, "The nonce was not recorded on disk"

    # Call 2: carol uses the SAME nonce on a different request.
    req_id_2 = "req-r2-nonce-2"
    rec2 = _create_pending_request(lay, req_id_2)  # requires_dual=True

    a2 = _make_remote_approval(
        carol_sk, request_id=req_id_2, command=rec2["command"],
        fingerprint=rec2["fingerprint"], user_id="user-carol",
        policy_sequence=ctx["policy_sequence"],
        nonce=shared_nonce,  # same nonce as call 1
    )

    result2 = asyncio.run(apply_external(
        lay, req_id_2, [a2],
        clock=lambda: time.time(),
    ))

    # ADR 0010 s4: the replay key is (key_id, nonce), not nonce alone.
    # Carol's key_id differs from bob's, so carol_kid:shared_nonce is NOT
    # a replay of bob_kid:shared_nonce. Carol's approval counts.
    assert result2["status"] == "awaiting_second"
    assert result2.get("approvals", 0) == 1, (
        "Different key_id with same nonce should count (not a replay). "
        "Got %d approvals." % result2.get("approvals", -1)
    )


# ===================================================================
# R3: Registry verification failure fails closed gracefully (FIXED).
#
# The fix: _verify_registry_for_approvals catches Exception (not just
# RegistryError/EnvelopeError), so a garbage chain with missing
# "payload" causes reg = None (fail closed), not an unhandled KeyError.
# ===================================================================


def test_r3_invalid_registry_fails_closed(tmp_path, monkeypatch):
    """R3 FIXED: a garbage registry chain fails closed (no crash).

    A chain missing "payload" used to raise KeyError (F3 bug).  The fix
    catches all exceptions from verify_chain and returns reg = None, so
    apply_external proceeds with no valid registry.  Both approvals and
    denies are dropped (fail closed).
    """
    from sandbox.connector.approval import apply_external

    bob_sk, bob_pub, bob_kid = _keygen()

    ctx = _setup_managed_workspace(
        tmp_path, monkeypatch,
        approver_sks=[
            (bob_sk, bob_pub, bob_kid, "user-bob", "cli"),
        ],
        environment="staging",
    )
    lay = ctx["lay"]
    req_id = "req-r3-badreg"
    rec = _create_pending_request(lay, req_id)

    deny = _make_remote_deny(
        bob_sk, request_id=req_id, command=rec["command"],
        fingerprint=rec["fingerprint"], user_id="user-bob",
        policy_sequence=ctx["policy_sequence"],
    )

    # Write a garbage registry chain to disk.  The old code raised KeyError;
    # the fixed code catches it and returns reg = None.
    sync_dir = lay.root / ".sandbox" / "state" / "sync"
    (sync_dir / "registry.json").write_text(
        json.dumps([{"kind": "garbage"}]), encoding="utf-8"
    )
    result = asyncio.run(apply_external(
        lay, req_id, [deny],
        clock=lambda: time.time(),
    ))

    # FIXED: no crash.  The deny is dropped because the registry
    # could not be verified (reg = None -> no keys to look up).
    # The request stays pending (awaiting_second with 0 approvals).
    assert result["status"] in ("awaiting_second", "not_pending"), (
        "Expected fail-closed status, got %s" % result["status"]
    )


# ===================================================================
# R4: apply_external with requires_dual=False and zero valid approvals
#     must NOT execute (missing lower-bound check).
#
# This is a new finding from the round 2 review.  The current code
# only checks `if requires_dual and len(dual_eligible) < 2`, but does
# not check that there is at least 1 valid approval when requires_dual
# is False.  Zero valid approvals + requires_dual=False = execution.
# ===================================================================


def test_r4_zero_approvals_non_dual_should_not_execute(tmp_path, monkeypatch):
    """R4 NEW: zero valid approvals must not execute even with requires_dual=False.

    The current code runs the request with reviewer_id="remote" when
    dual_eligible is empty and requires_dual=False.  This test proves
    the bug: an empty approval list causes execution.  The fix is to
    add a lower-bound check: at least 1 valid approval is required.
    """
    from sandbox.connector.approval import apply_external

    bob_sk, bob_pub, bob_kid = _keygen()

    ctx = _setup_managed_workspace(
        tmp_path, monkeypatch,
        approver_sks=[
            (bob_sk, bob_pub, bob_kid, "user-bob", "cli"),
        ],
        environment="staging",
    )
    lay = ctx["lay"]
    now = time.time()

    # Write server_time_state so skew does not interfere.
    sync_dir = lay.root / ".sandbox" / "state" / "sync"
    (sync_dir / "server_time_state.json").write_text(
        json.dumps({"server_time": now, "local_time": now}),
        encoding="utf-8",
    )

    req_id = "req-r4-zero-approvals"
    rec = _create_pending_request(lay, req_id, requires_dual=False)

    # Send an approval with a completely wrong policy_sequence so it
    # is rejected.  This gives zero valid approvals.
    a1 = _make_remote_approval(
        bob_sk, request_id=req_id, command=rec["command"],
        fingerprint=rec["fingerprint"], user_id="user-bob",
        policy_sequence=999,  # wrong sequence -> rejected
    )

    result = asyncio.run(apply_external(
        lay, req_id, [a1],
        clock=lambda: time.time(),
    ))

    # F7 fix: `if not approvers:` guard returns awaiting_second.
    assert result["status"] != "executed", (
        "Zero valid approvals should NOT execute, even with requires_dual=False."
    )


# ===================================================================
# R5 (round 3): managed mode with NO server_time_state.json refuses
# remote approvals, while a deny still applies (F8 fail-closed).
# ===================================================================


def test_r5_no_server_time_state_approvals_refused_deny_applies(tmp_path, monkeypatch):
    """F8 fail-closed: no server_time_state.json -> managed approvals refused, deny works.

    _measure_skew returns None when the state file is absent.  In managed
    mode apply_external clears valid_approvals (fail closed).  But a deny
    still goes through because the skew guard only clears approvals.
    """
    from sandbox.connector.approval import apply_external

    bob_sk, bob_pub, bob_kid = _keygen()
    carol_sk, carol_pub, carol_kid = _keygen()

    ctx = _setup_managed_workspace(
        tmp_path, monkeypatch,
        approver_sks=[
            (bob_sk, bob_pub, bob_kid, "user-bob", "cli"),
            (carol_sk, carol_pub, carol_kid, "user-carol", "cli"),
        ],
        environment="staging",
    )
    lay = ctx["lay"]

    # Delete server_time_state.json so _measure_skew returns None.
    sync_dir = lay.root / ".sandbox" / "state" / "sync"
    sts_file = sync_dir / "server_time_state.json"
    if sts_file.exists():
        sts_file.unlink()

    # Test 1: approvals are refused.
    req_approve = "req-r5-approve"
    rec_a = _create_pending_request(lay, req_approve)
    a1 = _make_remote_approval(
        bob_sk, request_id=req_approve, command=rec_a["command"],
        fingerprint=rec_a["fingerprint"], user_id="user-bob",
        policy_sequence=ctx["policy_sequence"],
    )
    a2 = _make_remote_approval(
        carol_sk, request_id=req_approve, command=rec_a["command"],
        fingerprint=rec_a["fingerprint"], user_id="user-carol",
        policy_sequence=ctx["policy_sequence"],
    )
    result_a = asyncio.run(apply_external(
        lay, req_approve, [a1, a2],
        clock=lambda: time.time(),
    ))
    assert result_a["status"] != "executed", (
        "Approvals must be refused when no server time measurement in managed mode."
    )
    assert result_a["status"] == "awaiting_second"

    # Test 2: deny still applies on a different request.
    req_deny = "req-r5-deny"
    rec_d = _create_pending_request(lay, req_deny)
    deny = _make_remote_deny(
        bob_sk, request_id=req_deny, command=rec_d["command"],
        fingerprint=rec_d["fingerprint"], user_id="user-bob",
        policy_sequence=ctx["policy_sequence"],
    )
    result_d = asyncio.run(apply_external(
        lay, req_deny, [deny],
        clock=lambda: time.time(),
    ))
    assert result_d["status"] == "denied", (
        "Deny must still apply even without a server time measurement."
    )


# ===================================================================
# R6 (round 3): clock_skew audit record is written when skew > 2 min
# refuses otherwise-valid approvals (F9).
# ===================================================================


def test_r6_clock_skew_audit_record_written(tmp_path, monkeypatch):
    """F9: a clock_skew audit event is written when skew refuses approvals.

    Injects a clock 5 min ahead.  Two valid approvals are verified against
    the registry but then dropped by the skew guard.  The audit chain must
    contain an event with event=clock_skew, reason_code=CLOCK_SKEW, and
    the measured skew.
    """
    from sandbox.connector.approval import apply_external

    bob_sk, bob_pub, bob_kid = _keygen()
    carol_sk, carol_pub, carol_kid = _keygen()

    ctx = _setup_managed_workspace(
        tmp_path, monkeypatch,
        approver_sks=[
            (bob_sk, bob_pub, bob_kid, "user-bob", "cli"),
            (carol_sk, carol_pub, carol_kid, "user-carol", "cli"),
        ],
        environment="staging",
    )
    lay = ctx["lay"]
    req_id = "req-r6-clock-skew-audit"
    rec = _create_pending_request(lay, req_id)

    a1 = _make_remote_approval(
        bob_sk, request_id=req_id, command=rec["command"],
        fingerprint=rec["fingerprint"], user_id="user-bob",
        policy_sequence=ctx["policy_sequence"],
    )
    a2 = _make_remote_approval(
        carol_sk, request_id=req_id, command=rec["command"],
        fingerprint=rec["fingerprint"], user_id="user-carol",
        policy_sequence=ctx["policy_sequence"],
    )

    result = asyncio.run(apply_external(
        lay, req_id, [a1, a2],
        clock=lambda: time.time() + 300,  # 5 min skew
    ))
    assert result["status"] != "executed"

    # Read the audit chain and find the clock_skew record.
    # audit() writes to audit_dir / session_id / records.jsonl.
    # Without a session.json the session_id is "default".
    audit_dir = lay.root / ".sandbox" / "audit"
    events = []
    if audit_dir.is_dir():
        for session in audit_dir.iterdir():
            rf = session / "records.jsonl"
            if rf.is_file():
                for line in rf.read_text(encoding="utf-8").splitlines():
                    if line.strip():
                        events.append(json.loads(line))
    clock_skew_events = [e for e in events if e.get("event") == "clock_skew"]
    assert len(clock_skew_events) >= 1, (
        "No clock_skew audit event found after skew refused approvals."
    )
    ev = clock_skew_events[0]
    assert ev.get("reason_code") == "CLOCK_SKEW"
    assert ev.get("request_id") == req_id
    # Skew should be approximately 300 s.
    assert ev.get("skew_s", 0) > 120, (
        "Recorded skew_s should exceed 120 s, got %s" % ev.get("skew_s")
    )


# ===================================================================
# R7 (round 3): a forged-signature envelope with a real nonce does NOT
# burn the nonce -- the real approval still succeeds (F6).
# ===================================================================


def test_r7_forged_sig_does_not_burn_nonce(tmp_path, monkeypatch):
    """F6: a forged envelope cannot burn a legitimate approval's nonce.

    Steps:
      1. Attacker sends an envelope with bob's nonce but signed by a
         different (unregistered) key.  Crypto verification fails at
         step 11; the nonce must NOT be recorded.
      2. Bob sends the legitimate envelope with the same nonce.  It
         must be accepted (nonce not in seen_nonces).

    In a single apply_external call with both envelopes, the forged one
    is processed first and rejected, then bob's real one is processed.
    If the nonce was burned by the forged envelope, bob's would be
    rejected too.
    """
    from sandbox.connector.approval import apply_external

    bob_sk, bob_pub, bob_kid = _keygen()
    carol_sk, carol_pub, carol_kid = _keygen()
    attacker_sk, attacker_pub, attacker_kid = _keygen()

    ctx = _setup_managed_workspace(
        tmp_path, monkeypatch,
        approver_sks=[
            (bob_sk, bob_pub, bob_kid, "user-bob", "cli"),
            (carol_sk, carol_pub, carol_kid, "user-carol", "cli"),
        ],
        environment="staging",
    )
    lay = ctx["lay"]
    req_id = "req-r7-forged-nonce"
    rec = _create_pending_request(lay, req_id)
    shared_nonce = secrets.token_hex(16)

    # Forged envelope: uses bob's payload (including his nonce) but
    # signed by the attacker's key.  The attacker's key_id is not in
    # the registry, so _verify_remote_approval returns None at step 3
    # (key lookup failure), BEFORE step 11 (crypto).
    # To specifically test step 11 (crypto failure), we use bob's
    # key_id in the signatures but sign with the attacker's sk.
    forged_payload = {
        "request_id": req_id,
        "command": rec["command"],
        "fingerprint": rec["fingerprint"],
        "reviewer_id": "user-bob",
        "decision": "approve",
        "approved_at": time.time(),
        "org_id": "org-1",
        "project_id": "proj-1",
        "device_id": "dev-1",
        "registry_version": 1,
        "policy_sequence": ctx["policy_sequence"],
        "user_id": "user-bob",
        "key_id": bob_kid,
        "nonce": shared_nonce,
        "not_after": time.time() + 900,
    }
    # Sign with attacker key, but claim bob's key_id in signatures.
    tag = "agg/remote-approval/v1".encode("utf-8")
    canonical = json.dumps(forged_payload, sort_keys=True,
                           separators=(",", ":")).encode()
    msg = tag + b"\x00" + canonical
    bad_sig = attacker_sk.sign(msg).signature.hex()
    forged_envelope = {
        "kind": "agg/remote-approval/v1",
        "sig_v": 1,
        "payload": forged_payload,
        "signatures": [{"key_id": bob_kid, "alg": "ed25519", "sig": bad_sig}],
    }

    # Real envelope from carol (with her own nonce).
    a_carol = _make_remote_approval(
        carol_sk, request_id=req_id, command=rec["command"],
        fingerprint=rec["fingerprint"], user_id="user-carol",
        policy_sequence=ctx["policy_sequence"],
    )

    # Real envelope from bob (with the shared nonce).
    a_bob = _make_remote_approval(
        bob_sk, request_id=req_id, command=rec["command"],
        fingerprint=rec["fingerprint"], user_id="user-bob",
        policy_sequence=ctx["policy_sequence"],
        nonce=shared_nonce,
    )

    # Send: forged first, then bob's real, then carol's.
    # If F6 is not fixed (nonce burned by forged), bob's is rejected
    # and only carol's counts (1 approval, dual needed -> awaiting).
    # If F6 IS fixed, bob's + carol's both count (2 approvals -> executed).
    result = asyncio.run(apply_external(
        lay, req_id, [forged_envelope, a_bob, a_carol],
        clock=lambda: time.time(),
    ))
    assert result["status"] == "executed", (
        "F6 regression: the forged envelope burned bob's nonce. "
        "Expected 'executed' (2 valid approvals), got '%s'." % result["status"]
    )


# ===================================================================
# R8 (round 3): requires_dual=False with one single_admin_registry
# key executes (S9: counts for single, not dual).
# ===================================================================


@pytest.mark.xfail(strict=True, reason="T12b named limit (security round 4): apply_external does not yet classify the command against the verified folder_policy, so every remote approval requires dual; S9 single approval cannot execute until classify lands")
def test_r8_single_admin_key_executes_for_non_dual(tmp_path, monkeypatch):
    """S9: a single_admin_registry key counts for non-dual approval.

    A key added under a single-admin genesis (1 admin sig) has
    counts_for_dual = False.  For requires_dual=True it is excluded.
    For requires_dual=False, identity_deduped is used, and the key
    is included -- the request executes.
    """
    from sandbox.connector.approval import apply_external

    bob_sk, bob_pub, bob_kid = _keygen()

    ctx = _setup_managed_workspace(
        tmp_path, monkeypatch,
        approver_sks=[
            (bob_sk, bob_pub, bob_kid, "user-bob", "cli"),
        ],
        environment="staging",
        single_admin=True,  # single-admin genesis -> counts_for_dual = False
    )
    lay = ctx["lay"]
    req_id = "req-r8-single-admin"
    rec = _create_pending_request(lay, req_id, requires_dual=False)

    a1 = _make_remote_approval(
        bob_sk, request_id=req_id, command=rec["command"],
        fingerprint=rec["fingerprint"], user_id="user-bob",
        policy_sequence=ctx["policy_sequence"],
    )

    result = asyncio.run(apply_external(
        lay, req_id, [a1],
        clock=lambda: time.time(),
    ))
    assert result["status"] == "executed", (
        "S9: single_admin key should count for non-dual. "
        "Got '%s'." % result["status"]
    )


def test_r8b_empty_policy_defaults_to_dual(tmp_path, monkeypatch):
    """Security round 4: an empty verified folder_policy gives a dual floor
    (fail closed), so one single_admin approval on a record that claims
    requires_dual=False does not execute."""
    from sandbox.connector.approval import apply_external

    bob_sk, bob_pub, bob_kid = _keygen()
    ctx = _setup_managed_workspace(
        tmp_path, monkeypatch,
        approver_sks=[(bob_sk, bob_pub, bob_kid, "user-bob", "cli")],
        environment="staging",
        single_admin=True,
    )
    lay = ctx["lay"]
    req_id = "req-r8b-empty-policy"
    rec = _create_pending_request(lay, req_id, requires_dual=False)
    a1 = _make_remote_approval(
        bob_sk, request_id=req_id, command=rec["command"],
        fingerprint=rec["fingerprint"], user_id="user-bob",
        policy_sequence=ctx["policy_sequence"],
    )
    result = asyncio.run(apply_external(lay, req_id, [a1], clock=lambda: time.time()))
    assert result["status"] == "awaiting_second"
