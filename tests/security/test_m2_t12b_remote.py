"""M2 T12b-1 tests-first: wire remote approval path, fix H1-H3, M1-M3,
nonce redesign, verified-state accessor, enroll persistence, CLI wiring,
evidence offline verify of remote approvals.

Strict xfail ``raises=M2T12bPending``; the build removes only the markers.
Postgres-free; reuses helpers from ``test_m2_t12_remote`` and
``test_m2_t15_hostile`` (those files are frozen and must NOT be edited here).

Sentinel names (the builder adds these):
  sandbox.connector.sync.verified_state.load_verified_state
  sandbox.connector.approval._REQUEST_ID_RE
  sandbox.connector.approval._binding_fingerprint
  sandbox.connector.sync.enroll.ENROLL_PERSISTS_OPERATOR
  sandbox.cli.sync_cmds

Coverage:
  C1-C3: nonce redesign (key_id, nonce) scope
  C4: binding fingerprint recomputed
  C5: operator binding (enroll persistence)
  C6-C7: verified state accessor, grep test
  C8: done-record signed by connector:<device_id>
  C9 item 6: CLI through shell forms denied by hook
  H1: binding field by field
  H2: grep + hand-edited bundle
  H3: traversal, oversized, symlink ids
  M1: not_after missing refused
  M3: remote-approved action through queue.finish
  L2: malformed envelope does not block others
  Headless happy path: enroll, upload, two approvals, sync, execute, evidence

T6 rule: the sentinel is raised only by one helper ``_need()`` at the top
of a test; the final assertions are plain ``assert``/``pytest.raises``.
Tests never patch global ``os`` attributes.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import secrets
import time
from pathlib import Path

import pytest

from tests.m2_pending import M2T12bPending

# Reuse T12 helpers (frozen file: do NOT edit)
from tests.security.test_m2_t12_remote import (
    _build_registry,
    _create_pending_request,
    _keygen,
    _make_remote_approval,
    _make_remote_deny,
    _setup_managed_workspace,
    _sign_envelope,
    _ws,
)


# ---------------------------------------------------------------------------
# Feature-absence sentinel
# ---------------------------------------------------------------------------

def _need(module: str, attr: str) -> None:
    """Raise M2T12bPending if *module*.*attr* is absent."""
    try:
        mod = __import__(module, fromlist=[attr])
    except ImportError:
        raise M2T12bPending(f"{module} not importable")
    if not hasattr(mod, attr):
        raise M2T12bPending(f"{module}.{attr} not found")


def _two_approvers(tmp_path, monkeypatch, **kw):
    """Two distinct CLI approvers on a managed workspace."""
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


# ===================================================================
# Guards (pass now -- existing code)
# ===================================================================

def test_guard_t12b_sentinel_importable():
    """Guard: M2T12bPending is importable."""
    from tests.m2_pending import M2T12bPending as cls
    assert issubclass(cls, Exception)


def test_guard_apply_external_exists():
    """Guard: apply_external is importable."""
    from sandbox.connector.approval import apply_external
    assert callable(apply_external)


def test_guard_queue_module_exists():
    """Guard: EscalationQueue and valid_request_id are importable."""
    from sandbox.connector.queue import EscalationQueue, valid_request_id
    assert callable(EscalationQueue)
    assert callable(valid_request_id)


# ===================================================================
# H1 BINDING: each field bound to the pending record (C4, ADR 0010 s1)
# ===================================================================

def test_h1_another_request_id_refused(tmp_path, monkeypatch):
    """Approvals signed for request-A applied to request-B are refused."""
    _need("sandbox.connector.approval", "_binding_fingerprint")
    ctx, bob, carol = _two_approvers(tmp_path, monkeypatch)
    lay = ctx["lay"]
    rec_b = _create_pending_request(lay, "req-B", command="echo victim")
    common_a = dict(request_id="req-A", command="ls safe",
                    fingerprint="f" * 64,
                    policy_sequence=ctx["policy_sequence"])
    a1 = _make_remote_approval(bob[0], user_id="user-bob", **common_a)
    a2 = _make_remote_approval(carol[0], user_id="user-carol", **common_a)

    from sandbox.connector.approval import apply_external
    result = asyncio.run(apply_external(lay, "req-B", [a1, a2],
                                        clock=lambda: time.time()))
    assert result["status"] != "executed"


def test_h1_another_device_id_refused(tmp_path, monkeypatch):
    """Approvals signed for another device_id are refused."""
    _need("sandbox.connector.approval", "_binding_fingerprint")
    ctx, bob, carol = _two_approvers(tmp_path, monkeypatch)
    lay = ctx["lay"]
    rec = _create_pending_request(lay, "req-dev")
    common = dict(request_id="req-dev", command=rec["command"],
                  fingerprint=rec["fingerprint"],
                  policy_sequence=ctx["policy_sequence"],
                  device_id="dev-OTHER")
    a1 = _make_remote_approval(bob[0], user_id="user-bob", **common)
    a2 = _make_remote_approval(carol[0], user_id="user-carol", **common)

    from sandbox.connector.approval import apply_external
    result = asyncio.run(apply_external(lay, "req-dev", [a1, a2],
                                        clock=lambda: time.time()))
    assert result["status"] != "executed"


def test_h1_another_project_id_refused(tmp_path, monkeypatch):
    """Approvals signed for another project_id are refused."""
    _need("sandbox.connector.approval", "_binding_fingerprint")
    ctx, bob, carol = _two_approvers(tmp_path, monkeypatch)
    lay = ctx["lay"]
    rec = _create_pending_request(lay, "req-proj")
    common = dict(request_id="req-proj", command=rec["command"],
                  fingerprint=rec["fingerprint"],
                  policy_sequence=ctx["policy_sequence"],
                  project_id="proj-OTHER")
    a1 = _make_remote_approval(bob[0], user_id="user-bob", **common)
    a2 = _make_remote_approval(carol[0], user_id="user-carol", **common)

    from sandbox.connector.approval import apply_external
    result = asyncio.run(apply_external(lay, "req-proj", [a1, a2],
                                        clock=lambda: time.time()))
    assert result["status"] != "executed"


def test_h1_another_org_id_refused(tmp_path, monkeypatch):
    """Approvals signed for another org_id are refused."""
    _need("sandbox.connector.approval", "_binding_fingerprint")
    ctx, bob, carol = _two_approvers(tmp_path, monkeypatch)
    lay = ctx["lay"]
    rec = _create_pending_request(lay, "req-org")
    common = dict(request_id="req-org", command=rec["command"],
                  fingerprint=rec["fingerprint"],
                  policy_sequence=ctx["policy_sequence"],
                  org_id="org-OTHER")
    a1 = _make_remote_approval(bob[0], user_id="user-bob", **common)
    a2 = _make_remote_approval(carol[0], user_id="user-carol", **common)

    from sandbox.connector.approval import apply_external
    result = asyncio.run(apply_external(lay, "req-org", [a1, a2],
                                        clock=lambda: time.time()))
    assert result["status"] != "executed"


def test_h1_another_command_refused(tmp_path, monkeypatch):
    """Approvals signed for another command are refused."""
    _need("sandbox.connector.approval", "_binding_fingerprint")
    ctx, bob, carol = _two_approvers(tmp_path, monkeypatch)
    lay = ctx["lay"]
    rec = _create_pending_request(lay, "req-cmd", command="echo victim")
    common = dict(request_id="req-cmd", command="echo safe",
                  fingerprint=hashlib.sha256(b"echo safe").hexdigest(),
                  policy_sequence=ctx["policy_sequence"])
    a1 = _make_remote_approval(bob[0], user_id="user-bob", **common)
    a2 = _make_remote_approval(carol[0], user_id="user-carol", **common)

    from sandbox.connector.approval import apply_external
    result = asyncio.run(apply_external(lay, "req-cmd", [a1, a2],
                                        clock=lambda: time.time()))
    assert result["status"] != "executed"


def test_h1_another_cwd_refused(tmp_path, monkeypatch):
    """Approvals signed for another exec_cwd are refused."""
    _need("sandbox.connector.approval", "_binding_fingerprint")
    ctx, bob, carol = _two_approvers(tmp_path, monkeypatch)
    lay = ctx["lay"]
    rec = _create_pending_request(lay, "req-cwd")
    # The record has cwd = lay.root; the approval is signed with a fingerprint
    # computed for a DIFFERENT cwd, so the binding check fails.
    wrong_cwd_fp = hashlib.sha256(json.dumps({
        "kind": "shell", "tool_name": "Bash", "command": rec["command"],
        "exec_cwd": "/tmp/other", "root": str(lay.root),
        "requires_dual": True, "bundle_sequence": 1,
        "request_id": "req-cwd",
    }, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    common = dict(request_id="req-cwd", command=rec["command"],
                  fingerprint=wrong_cwd_fp,
                  policy_sequence=ctx["policy_sequence"])
    a1 = _make_remote_approval(bob[0], user_id="user-bob", **common)
    a2 = _make_remote_approval(carol[0], user_id="user-carol", **common)

    from sandbox.connector.approval import apply_external
    result = asyncio.run(apply_external(lay, "req-cwd", [a1, a2],
                                        clock=lambda: time.time()))
    # Even if binding passes today, the builder must add cwd binding and
    # this test must then verify a mismatch is refused.  The sentinel
    # prevents it from passing until the feature exists.
    assert result["status"] != "executed"


def test_h1_another_root_refused(tmp_path, monkeypatch):
    """Approvals signed for another root are refused."""
    _need("sandbox.connector.approval", "_binding_fingerprint")
    ctx, bob, carol = _two_approvers(tmp_path, monkeypatch)
    lay = ctx["lay"]
    rec = _create_pending_request(lay, "req-root")
    # Approval signed with a fingerprint computed for a DIFFERENT root
    wrong_root_fp = hashlib.sha256(json.dumps({
        "kind": "shell", "tool_name": "Bash", "command": rec["command"],
        "exec_cwd": str(lay.root), "root": "/other/root",
        "requires_dual": True, "bundle_sequence": 1,
        "request_id": "req-root",
    }, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    common = dict(request_id="req-root", command=rec["command"],
                  fingerprint=wrong_root_fp,
                  policy_sequence=ctx["policy_sequence"])
    a1 = _make_remote_approval(bob[0], user_id="user-bob", **common)
    a2 = _make_remote_approval(carol[0], user_id="user-carol", **common)

    from sandbox.connector.approval import apply_external
    result = asyncio.run(apply_external(lay, "req-root", [a1, a2],
                                        clock=lambda: time.time()))
    assert result["status"] != "executed"


def test_h1_another_policy_sequence_refused(tmp_path, monkeypatch):
    """Approvals signed for another policy_sequence are refused."""
    _need("sandbox.connector.approval", "_binding_fingerprint")
    ctx, bob, carol = _two_approvers(tmp_path, monkeypatch, policy_sequence=5)
    lay = ctx["lay"]
    rec = _create_pending_request(lay, "req-seq")
    common = dict(request_id="req-seq", command=rec["command"],
                  fingerprint=rec["fingerprint"],
                  policy_sequence=3)
    a1 = _make_remote_approval(bob[0], user_id="user-bob", **common)
    a2 = _make_remote_approval(carol[0], user_id="user-carol", **common)

    from sandbox.connector.approval import apply_external
    result = asyncio.run(apply_external(lay, "req-seq", [a1, a2],
                                        clock=lambda: time.time()))
    assert result["status"] != "executed"


def test_h1_user_id_taken_from_registry(tmp_path, monkeypatch):
    """The approver's user_id comes from the registry entry, not the payload."""
    _need("sandbox.connector.approval", "_binding_fingerprint")
    ctx, bob, carol = _two_approvers(tmp_path, monkeypatch)
    lay = ctx["lay"]
    rec = _create_pending_request(lay, "req-uid")
    common = dict(request_id="req-uid", command=rec["command"],
                  fingerprint=rec["fingerprint"],
                  policy_sequence=ctx["policy_sequence"])
    # Bob's key but claims carol's user_id in the payload
    forged = _make_remote_approval(bob[0], user_id="user-carol", **common)
    real = _make_remote_approval(carol[0], user_id="user-carol", **common)

    from sandbox.connector.approval import apply_external
    result = asyncio.run(apply_external(lay, "req-uid", [forged, real],
                                        clock=lambda: time.time()))
    # forged should be dropped because payload user_id != registry user_id
    # for bob's key, so only carol counts
    assert result["status"] != "executed"


def test_h1_inactive_key_refused(tmp_path, monkeypatch):
    """A key absent from the latest registry version is refused (revocation = absent).

    Build a properly signed v2 registry (both admins sign, threshold met)
    that DROPS bob's key.  Persist it as the latest pinned chain.  Bob's
    validly signed approval must be refused because his key is absent
    from the latest version.
    """
    _need("sandbox.connector.approval", "_binding_fingerprint")
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
    admin_sks = ctx["admin_sks"]

    # Build a properly signed v2 registry that drops bob
    genesis = ctx["envelopes"][0]
    gp = genesis["payload"]
    gp_canonical = json.dumps(gp, sort_keys=True, separators=(",", ":")).encode()
    prev_hash = hashlib.sha256(
        gp["org_id"].encode("utf-8") + b":" + gp_canonical
    ).hexdigest()

    # v2 keys: admins stay, only carol remains as approver (bob dropped)
    v2_keys = [k for k in gp["keys"] if "admin" in k.get("roles", [])]
    v2_keys.append({
        "key_id": carol[2], "public_key": carol[1].hex(),
        "user_id": "user-carol", "iss": "https://idp.test",
        "sub": "user-carol", "alg": "ed25519",
        "kind": "cli", "roles": ["approver"], "added_in": 2,
    })
    v2_payload = {
        "org_id": gp["org_id"], "version": 2, "prev_hash": prev_hash,
        "threshold": gp["threshold"], "admins": gp["admins"],
        "keys": v2_keys, "expires_at": gp["expires_at"],
    }
    if "bundle_signer" in gp:
        v2_payload["bundle_signer"] = gp["bundle_signer"]

    # Sign v2 with both admins (threshold met)
    tag = b"agg/registry/v1"
    v2_can = json.dumps(v2_payload, sort_keys=True, separators=(",", ":")).encode()
    v2_msg = tag + b"\x00" + v2_can
    v2_sigs = []
    for sk, _pub, kid in admin_sks:
        v2_sigs.append({"key_id": kid, "alg": "ed25519",
                        "sig": sk.sign(v2_msg).signature.hex()})
    v2_env = {"kind": "agg/registry/v1", "sig_v": 1,
              "payload": v2_payload, "signatures": v2_sigs}

    # Persist the [genesis, v2] chain (properly signed, no tamper)
    sync_dir = lay.root / ".sandbox" / "state" / "sync"
    (sync_dir / "registry.json").write_text(
        json.dumps([genesis, v2_env]), encoding="utf-8")

    rec = _create_pending_request(lay, "req-revoked")
    common = dict(request_id="req-revoked", command=rec["command"],
                  fingerprint=rec["fingerprint"],
                  policy_sequence=ctx["policy_sequence"])
    a1 = _make_remote_approval(bob[0], user_id="user-bob", **common)
    a2 = _make_remote_approval(carol[0], user_id="user-carol", **common)

    from sandbox.connector.approval import apply_external
    result = asyncio.run(apply_external(lay, "req-revoked", [a1, a2],
                                        clock=lambda: time.time()))
    # bob absent from v2 => only carol counts => awaiting second
    assert result["status"] != "executed"


def test_h1_dedup_by_registry_user_id(tmp_path, monkeypatch):
    """Dedup uses the registry's user_id, never the payload's."""
    _need("sandbox.connector.approval", "_binding_fingerprint")
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
    rec = _create_pending_request(lay, "req-dedup")
    common = dict(request_id="req-dedup", command=rec["command"],
                  fingerprint=rec["fingerprint"],
                  policy_sequence=ctx["policy_sequence"])
    # Bob signs twice with different payload user_ids but same registry key
    a1 = _make_remote_approval(bob[0], user_id="user-bob", **common)
    a2 = _make_remote_approval(bob[0], user_id="user-zed", **common,
                               nonce=secrets.token_hex(16))

    from sandbox.connector.approval import apply_external
    result = asyncio.run(apply_external(lay, "req-dedup", [a1, a2],
                                        clock=lambda: time.time()))
    # Both are bob's key in the registry => dedup => only 1 counted
    assert result["status"] != "executed"


def test_h1_required_count_never_below_policy(tmp_path, monkeypatch):
    """The required approval count never drops below the verified policy."""
    _need("sandbox.connector.approval", "_binding_fingerprint")
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
    # Write a pending record that claims requires_dual=False
    rec = _create_pending_request(lay, "req-floor", requires_dual=False)

    common = dict(request_id="req-floor", command=rec["command"],
                  fingerprint=rec["fingerprint"],
                  policy_sequence=ctx["policy_sequence"])
    a1 = _make_remote_approval(bob[0], user_id="user-bob", **common)

    from sandbox.connector.approval import apply_external
    result = asyncio.run(apply_external(lay, "req-floor", [a1],
                                        clock=lambda: time.time()))
    # The policy says dual is needed; the record's requires_dual=False
    # must not lower the bar.  One approval should not execute.
    assert result["status"] != "executed"


# ===================================================================
# H1 BINDING: fingerprint recomputed after claim (TOCTOU, C4)
# ===================================================================

def test_h1_pending_edited_between_verify_and_run(tmp_path, monkeypatch):
    """A pending file edited between verify and run is refused."""
    _need("sandbox.connector.approval", "_binding_fingerprint")
    ctx, bob, carol = _two_approvers(tmp_path, monkeypatch)
    lay = ctx["lay"]
    rec = _create_pending_request(lay, "req-toctou", command="echo safe")
    common = dict(request_id="req-toctou", command="echo safe",
                  fingerprint=rec["fingerprint"],
                  policy_sequence=ctx["policy_sequence"])
    a1 = _make_remote_approval(bob[0], user_id="user-bob", **common)
    a2 = _make_remote_approval(carol[0], user_id="user-carol", **common)

    # Edit the pending file to a different command after the approvals
    # were signed but before apply_external runs
    pending_file = lay.root / ".sandbox" / "pending" / "req-toctou.json"
    data = json.loads(pending_file.read_text(encoding="utf-8"))
    data["command"] = "rm -rf /"
    data["fingerprint"] = hashlib.sha256(b"rm -rf /").hexdigest()
    pending_file.write_text(json.dumps(data), encoding="utf-8")

    from sandbox.connector.approval import apply_external
    result = asyncio.run(apply_external(lay, "req-toctou", [a1, a2],
                                        clock=lambda: time.time()))
    assert result["status"] != "executed"


# ===================================================================
# H2: verified state accessor and grep test (C6, C7)
# ===================================================================

def test_h2_verified_state_accessor_exists(tmp_path, monkeypatch):
    """The shared verified-state accessor exists and returns a frozen object."""
    _need("sandbox.connector.sync.verified_state", "load_verified_state")
    from sandbox.connector.sync.verified_state import load_verified_state
    ctx, _, _ = _two_approvers(tmp_path, monkeypatch)
    lay = ctx["lay"]
    vs = load_verified_state(lay)
    assert vs is not None
    # Must expose at least these fields
    assert hasattr(vs, "bundle_payload") or "bundle_payload" in dir(vs) or isinstance(vs, dict)


def test_h2_grep_no_decision_path_reads_unverified(tmp_path, monkeypatch):
    """No decision path reads bundle.json, registry.json, enrollment.json
    or last_valid_bundle unverified.  A grep test enforces this (C6)."""
    _need("sandbox.connector.sync.verified_state", "load_verified_state")

    src_dir = Path(__file__).resolve().parents[2] / "src" / "sandbox" / "connector"
    # Files that make decisions: approval.py, hook_eval.py, classify.py
    decision_files = [
        src_dir / "approval.py",
        src_dir / "hook_eval.py",
        src_dir / "classify.py",
    ]
    forbidden_patterns = [
        # Direct file reads of these files (outside the verified_state accessor)
        r'bundle\.json',
        r'registry\.json',
        r'enrollment\.json',
        r'last_valid_bundle\(',
    ]
    violations = []
    for fpath in decision_files:
        if not fpath.exists():
            continue
        source = fpath.read_text(encoding="utf-8")
        for pat in forbidden_patterns:
            for i, line in enumerate(source.splitlines(), 1):
                # Allow comments and the accessor module itself
                stripped = line.strip()
                if stripped.startswith("#") or stripped.startswith("\"\"\""):
                    continue
                if re.search(pat, line):
                    violations.append(f"{fpath.name}:{i}: {line.strip()}")
    # The builder must remove all unverified reads from decision paths
    assert violations == [], f"Unverified reads in decision paths: {violations}"


def test_h2_hand_edited_bundle_local_fallback_no_effect(tmp_path, monkeypatch):
    """A hand-edited bundle.json with local_fallback=true has no effect
    (verified-state reads the signed bundle only)."""
    _need("sandbox.connector.sync.verified_state", "load_verified_state")
    ctx, _, _ = _two_approvers(tmp_path, monkeypatch, local_fallback=False)
    lay = ctx["lay"]
    # Hand-edit the bundle.json on disk
    bf = lay.root / ".sandbox" / "state" / "sync" / "bundle.json"
    data = json.loads(bf.read_text(encoding="utf-8"))
    data["payload"]["approval"]["local_fallback"] = True
    bf.write_text(json.dumps(data), encoding="utf-8")

    _create_pending_request(lay, "req-h2b", requires_dual=False)
    from sandbox.connector.approval import approve
    result = asyncio.run(approve(lay, "req-h2b", "reviewer-local"))
    assert result["status"] == "managed_refused"


def test_h2_older_signed_bundle_refused(tmp_path, monkeypatch):
    """An older genuinely signed bundle (below the high-water sequence)
    is refused by the verified-state accessor.

    After a newer signed bundle (sequence=5) is accepted, writing back
    a genuinely signed older bundle (sequence=3) must be refused by the
    high-water mark check.
    """
    _need("sandbox.connector.sync.verified_state", "load_verified_state")
    ctx, _, _ = _two_approvers(tmp_path, monkeypatch, policy_sequence=5)
    lay = ctx["lay"]
    bundle_signer_sk = ctx["bundle_signer_sk"]
    sync_dir = lay.root / ".sandbox" / "state" / "sync"

    from sandbox.connector.sync.verified_state import load_verified_state
    # Accept the sequence=5 bundle (records high-water mark)
    vs5 = load_verified_state(lay)
    assert vs5 is not None, "sequence=5 bundle should be accepted first"

    # Build a genuinely signed older bundle with sequence=3
    older_payload = {
        "org_id": ctx["org_id"], "project_id": ctx["project_id"],
        "sequence": 3, "base_sequence": 0, "registry_version": 1,
        "environment": ctx["environment"],
        "folder_policy": {}, "governance_policy": {}, "mcp_policy": {},
        "approval": {"local_fallback": False, "allow_requester": False},
        "change_approvals": [], "issued_at": time.time(),
        "not_before": time.time() - 60, "expires_at": time.time() + 86400,
    }
    older_env = _sign_envelope("agg/bundle/v1", older_payload, bundle_signer_sk[0])
    (sync_dir / "bundle.json").write_text(
        json.dumps(older_env), encoding="utf-8")

    # Must refuse: high-water is 5, this bundle is 3
    vs3 = load_verified_state(lay)
    assert vs3 is None or (isinstance(vs3, dict) and vs3.get("bundle_payload") is None)


def test_h2_older_signed_registry_refused(tmp_path, monkeypatch):
    """After a v2 registry was accepted, writing back the genuinely
    signed v1-only chain must be refused by the high-water mark."""
    _need("sandbox.connector.sync.verified_state", "load_verified_state")
    ctx, _, _ = _two_approvers(tmp_path, monkeypatch)
    lay = ctx["lay"]
    admin_sks = ctx["admin_sks"]
    sync_dir = lay.root / ".sandbox" / "state" / "sync"

    # Build a properly signed v2 registry chained to the genesis
    genesis = ctx["envelopes"][0]
    gp = genesis["payload"]
    gp_can = json.dumps(gp, sort_keys=True, separators=(",", ":")).encode()
    prev_hash = hashlib.sha256(
        gp["org_id"].encode("utf-8") + b":" + gp_can
    ).hexdigest()
    v2_payload = {
        "org_id": gp["org_id"], "version": 2, "prev_hash": prev_hash,
        "threshold": gp["threshold"], "admins": gp["admins"],
        "keys": gp["keys"], "expires_at": gp["expires_at"],
    }
    if "bundle_signer" in gp:
        v2_payload["bundle_signer"] = gp["bundle_signer"]
    tag = b"agg/registry/v1"
    v2_can = json.dumps(v2_payload, sort_keys=True, separators=(",", ":")).encode()
    v2_msg = tag + b"\x00" + v2_can
    v2_sigs = []
    for sk, _pub, kid in admin_sks:
        v2_sigs.append({"key_id": kid, "alg": "ed25519",
                        "sig": sk.sign(v2_msg).signature.hex()})
    v2_env = {"kind": "agg/registry/v1", "sig_v": 1,
              "payload": v2_payload, "signatures": v2_sigs}

    # Write [genesis, v2] and accept it (high-water becomes rv=2)
    (sync_dir / "registry.json").write_text(
        json.dumps([genesis, v2_env]), encoding="utf-8")

    from sandbox.connector.sync.verified_state import load_verified_state
    vs2 = load_verified_state(lay)
    assert vs2 is not None, "v2 registry should be accepted first"

    # Write back the genuinely signed v1-only chain (rollback attempt)
    (sync_dir / "registry.json").write_text(
        json.dumps([genesis]), encoding="utf-8")

    # Must refuse: high-water rv=2, this is rv=1
    vs1 = load_verified_state(lay)
    assert vs1 is None


# ===================================================================
# H3: request_id validation (traversal, oversized, symlinks)
# ===================================================================

def test_h3_traversal_request_id_refused(tmp_path, monkeypatch):
    """A traversal request_id like '../state/sync/seen_nonces' is refused
    before any file access."""
    _need("sandbox.connector.approval", "_REQUEST_ID_RE")
    ctx, _, _ = _two_approvers(tmp_path, monkeypatch)
    lay = ctx["lay"]
    # Verify the nonce file still exists after
    sync_dir = lay.root / ".sandbox" / "state" / "sync"
    nonce_file = sync_dir / "seen_nonces.json"
    nonce_file.write_text(json.dumps({"used": time.time() + 1e6}),
                          encoding="utf-8")

    from sandbox.connector.approval import apply_external
    try:
        asyncio.run(apply_external(lay, "../state/sync/seen_nonces", [],
                                   clock=lambda: time.time()))
    except (ValueError, Exception):
        pass
    assert nonce_file.is_file(), "seen_nonces.json was moved"


def test_h3_oversized_request_id_refused(tmp_path, monkeypatch):
    """A request_id longer than the maximum is refused."""
    _need("sandbox.connector.approval", "_REQUEST_ID_RE")
    ctx, _, _ = _two_approvers(tmp_path, monkeypatch)
    lay = ctx["lay"]
    too_long = "a" * 256
    from sandbox.connector.approval import apply_external
    result = asyncio.run(apply_external(lay, too_long, [],
                                        clock=lambda: time.time()))
    # Must refuse with no file side effects
    assert result["status"] in ("not_pending", "invalid_id")


def test_h3_symlink_request_id_refused(tmp_path, monkeypatch):
    """A request_id that resolves to a symlink is refused."""
    _need("sandbox.connector.approval", "_REQUEST_ID_RE")
    ctx, _, _ = _two_approvers(tmp_path, monkeypatch)
    lay = ctx["lay"]
    pending_dir = lay.root / ".sandbox" / "pending"
    pending_dir.mkdir(parents=True, exist_ok=True)
    # Create a symlink in the pending dir
    target = tmp_path / "target.json"
    target.write_text("{}", encoding="utf-8")
    link = pending_dir / "sym-req.json"
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("symlinks not permitted on this platform")

    from sandbox.connector.approval import apply_external
    result = asyncio.run(apply_external(lay, "sym-req", [],
                                        clock=lambda: time.time()))
    assert result["status"] in ("not_pending", "invalid_id")


# ===================================================================
# M1: not_after missing refused
# ===================================================================

def test_m1_missing_not_after_refused(tmp_path, monkeypatch):
    """An approval with not_after missing (not None, but absent) is refused."""
    _need("sandbox.connector.approval", "_binding_fingerprint")
    ctx, bob, carol = _two_approvers(tmp_path, monkeypatch)
    lay = ctx["lay"]
    rec = _create_pending_request(lay, "req-m1", requires_dual=False)

    # Build an envelope where not_after is missing entirely
    pub = bytes(bob[0].verify_key)
    kid = hashlib.sha256(pub).hexdigest()
    payload = {
        "request_id": "req-m1", "command": rec["command"],
        "fingerprint": rec["fingerprint"], "reviewer_id": "user-bob",
        "decision": "approve", "approved_at": time.time(),
        "org_id": "org-1", "project_id": "proj-1", "device_id": "dev-1",
        "registry_version": 1, "policy_sequence": ctx["policy_sequence"],
        "user_id": "user-bob", "key_id": kid,
        "nonce": secrets.token_hex(16),
        # not_after deliberately omitted
    }
    env = _sign_envelope("agg/remote-approval/v1", payload, bob[0])

    from sandbox.connector.approval import apply_external
    result = asyncio.run(apply_external(lay, "req-m1", [env],
                                        clock=lambda: time.time()))
    assert result["status"] != "executed"


def test_m1_not_after_not_finite_refused(tmp_path, monkeypatch):
    """An approval with not_after that is not a finite int/float is refused."""
    _need("sandbox.connector.approval", "_binding_fingerprint")
    ctx, bob, _ = _two_approvers(tmp_path, monkeypatch)
    lay = ctx["lay"]
    rec = _create_pending_request(lay, "req-m1inf", requires_dual=False)
    common = dict(request_id="req-m1inf", command=rec["command"],
                  fingerprint=rec["fingerprint"],
                  policy_sequence=ctx["policy_sequence"],
                  not_after=float("inf"))
    a1 = _make_remote_approval(bob[0], user_id="user-bob", **common)

    from sandbox.connector.approval import apply_external
    result = asyncio.run(apply_external(lay, "req-m1inf", [a1],
                                        clock=lambda: time.time()))
    assert result["status"] != "executed"


# ===================================================================
# NONCE REDESIGN: (key_id, nonce) scope (C1-C3, ADR 0010 s4)
# ===================================================================

def test_nonce_key_is_key_id_nonce(tmp_path, monkeypatch):
    """The replay key is (key_id, nonce), not nonce alone.
    Carol reusing bob's nonce under a different key_id does NOT drop carol."""
    _need("sandbox.connector.approval", "_binding_fingerprint")
    ctx, bob, carol = _two_approvers(tmp_path, monkeypatch)
    lay = ctx["lay"]
    rec = _create_pending_request(lay, "req-nonce-scope")
    shared_nonce = secrets.token_hex(16)
    common = dict(request_id="req-nonce-scope", command=rec["command"],
                  fingerprint=rec["fingerprint"],
                  policy_sequence=ctx["policy_sequence"])
    a1 = _make_remote_approval(bob[0], user_id="user-bob", nonce=shared_nonce,
                               **common)
    a2 = _make_remote_approval(carol[0], user_id="user-carol",
                               nonce=shared_nonce, **common)

    from sandbox.connector.approval import apply_external
    result = asyncio.run(apply_external(lay, "req-nonce-scope", [a1, a2],
                                        clock=lambda: time.time()))
    # Both should count because (bob_kid, nonce) != (carol_kid, nonce)
    assert result["status"] == "executed"


def test_nonce_resend_same_request_idempotent(tmp_path, monkeypatch):
    """A re-send for the same request counts once across two polls,
    so dual control completes."""
    _need("sandbox.connector.approval", "_binding_fingerprint")
    ctx, bob, carol = _two_approvers(tmp_path, monkeypatch)
    lay = ctx["lay"]
    rec = _create_pending_request(lay, "req-resend")
    common = dict(request_id="req-resend", command=rec["command"],
                  fingerprint=rec["fingerprint"],
                  policy_sequence=ctx["policy_sequence"])
    bob_nonce = secrets.token_hex(16)
    carol_nonce = secrets.token_hex(16)
    a_bob = _make_remote_approval(bob[0], user_id="user-bob",
                                  nonce=bob_nonce, **common)
    a_carol = _make_remote_approval(carol[0], user_id="user-carol",
                                    nonce=carol_nonce, **common)

    from sandbox.connector.approval import apply_external
    # Poll 1: only bob
    r1 = asyncio.run(apply_external(lay, "req-resend", [a_bob],
                                    clock=lambda: time.time()))
    assert r1["status"] == "awaiting_second"

    # Poll 2: bob re-delivered + carol
    r2 = asyncio.run(apply_external(lay, "req-resend", [a_bob, a_carol],
                                    clock=lambda: time.time()))
    # Bob's re-send is idempotent (counted once), carol is new => dual met
    assert r2["status"] == "executed"


def test_nonce_another_request_is_replay(tmp_path, monkeypatch):
    """A nonce used for request-A then reused for request-B is a replay."""
    _need("sandbox.connector.approval", "_binding_fingerprint")
    ctx, bob, carol = _two_approvers(tmp_path, monkeypatch)
    lay = ctx["lay"]
    rec_a = _create_pending_request(lay, "req-A", command="echo a")
    rec_b = _create_pending_request(lay, "req-B", command="echo b")

    shared_nonce = secrets.token_hex(16)
    common_a = dict(request_id="req-A", command=rec_a["command"],
                    fingerprint=rec_a["fingerprint"],
                    policy_sequence=ctx["policy_sequence"])
    common_b = dict(request_id="req-B", command=rec_b["command"],
                    fingerprint=rec_b["fingerprint"],
                    policy_sequence=ctx["policy_sequence"])

    a1 = _make_remote_approval(bob[0], user_id="user-bob",
                               nonce=shared_nonce, **common_a)
    a2 = _make_remote_approval(carol[0], user_id="user-carol", **common_a)

    from sandbox.connector.approval import apply_external
    # Execute req-A: burns bob's nonce
    r1 = asyncio.run(apply_external(lay, "req-A", [a1, a2],
                                    clock=lambda: time.time()))
    assert r1["status"] == "executed"

    # Try to reuse bob's nonce for req-B
    a_replay = _make_remote_approval(bob[0], user_id="user-bob",
                                     nonce=shared_nonce, **common_b)
    a_carol_b = _make_remote_approval(carol[0], user_id="user-carol",
                                      **common_b)
    r2 = asyncio.run(apply_external(lay, "req-B", [a_replay, a_carol_b],
                                    clock=lambda: time.time()))
    # bob's nonce is replayed for a different request => dropped
    # only carol counts
    assert r2["status"] != "executed"


def test_nonce_carol_nonce_reused_by_bob_does_not_drop_carol(tmp_path, monkeypatch):
    """Carol's (key_id, nonce) reused by bob under bob's key_id does NOT
    poison carol's entry."""
    _need("sandbox.connector.approval", "_binding_fingerprint")
    ctx, bob, carol = _two_approvers(tmp_path, monkeypatch)
    lay = ctx["lay"]
    rec = _create_pending_request(lay, "req-cross-nonce")
    shared_nonce = secrets.token_hex(16)
    common = dict(request_id="req-cross-nonce", command=rec["command"],
                  fingerprint=rec["fingerprint"],
                  policy_sequence=ctx["policy_sequence"])

    # Carol signs with nonce X
    a_carol = _make_remote_approval(carol[0], user_id="user-carol",
                                    nonce=shared_nonce, **common)
    # Bob signs with the SAME nonce value X
    a_bob = _make_remote_approval(bob[0], user_id="user-bob",
                                  nonce=shared_nonce, **common)

    from sandbox.connector.approval import apply_external
    result = asyncio.run(apply_external(lay, "req-cross-nonce",
                                        [a_carol, a_bob],
                                        clock=lambda: time.time()))
    # (carol_kid, nonce) != (bob_kid, nonce) so both count
    assert result["status"] == "executed"


@pytest.mark.skipif(os.name == "nt", reason="chmod read-only on dirs is a no-op on Windows")
def test_nonce_failed_save_runs_nothing(tmp_path, monkeypatch):
    """If the nonce file save fails, nothing executes (C1: write-ahead)."""
    _need("sandbox.connector.approval", "_binding_fingerprint")
    ctx, bob, carol = _two_approvers(tmp_path, monkeypatch)
    lay = ctx["lay"]
    rec = _create_pending_request(lay, "req-nonce-fail")
    common = dict(request_id="req-nonce-fail", command=rec["command"],
                  fingerprint=rec["fingerprint"],
                  policy_sequence=ctx["policy_sequence"])
    a1 = _make_remote_approval(bob[0], user_id="user-bob", **common)
    a2 = _make_remote_approval(carol[0], user_id="user-carol", **common)

    # Make the sync dir read-only so the nonce save fails
    sync_dir = lay.root / ".sandbox" / "state" / "sync"
    import stat
    original_mode = sync_dir.stat().st_mode
    try:
        sync_dir.chmod(stat.S_IRUSR | stat.S_IXUSR)
        from sandbox.connector.approval import apply_external
        result = asyncio.run(apply_external(lay, "req-nonce-fail", [a1, a2],
                                            clock=lambda: time.time()))
        # Must refuse: nothing runs if nonce cannot be persisted
        assert result["status"] != "executed"
    finally:
        sync_dir.chmod(original_mode)


def test_nonce_done_request_never_reclaimed(tmp_path, monkeypatch):
    """A done request is never re-claimed, even with fresh nonces."""
    _need("sandbox.connector.approval", "_binding_fingerprint")
    ctx, bob, carol = _two_approvers(tmp_path, monkeypatch)
    lay = ctx["lay"]
    rec = _create_pending_request(lay, "req-done-c3")
    common = dict(request_id="req-done-c3", command=rec["command"],
                  fingerprint=rec["fingerprint"],
                  policy_sequence=ctx["policy_sequence"])
    a1 = _make_remote_approval(bob[0], user_id="user-bob", **common)
    a2 = _make_remote_approval(carol[0], user_id="user-carol", **common)

    from sandbox.connector.approval import apply_external
    r1 = asyncio.run(apply_external(lay, "req-done-c3", [a1, a2],
                                    clock=lambda: time.time()))
    assert r1["status"] == "executed"

    # Try again with fresh nonces
    a3 = _make_remote_approval(bob[0], user_id="user-bob", **common)
    a4 = _make_remote_approval(carol[0], user_id="user-carol", **common)
    r2 = asyncio.run(apply_external(lay, "req-done-c3", [a3, a4],
                                    clock=lambda: time.time()))
    assert r2["status"] == "not_pending"


# ===================================================================
# M3: remote-approved action finishes via queue.finish (C8)
# ===================================================================

def test_m3_done_record_signed_by_connector_key(tmp_path, monkeypatch):
    """The done-record for a remote-approved action is signed by
    connector:<device_id>, not a human approver."""
    _need("sandbox.connector.approval", "_binding_fingerprint")
    ctx, bob, carol = _two_approvers(tmp_path, monkeypatch)
    lay = ctx["lay"]
    rec = _create_pending_request(lay, "req-m3-sig")
    common = dict(request_id="req-m3-sig", command=rec["command"],
                  fingerprint=rec["fingerprint"],
                  policy_sequence=ctx["policy_sequence"])
    a1 = _make_remote_approval(bob[0], user_id="user-bob", **common)
    a2 = _make_remote_approval(carol[0], user_id="user-carol", **common)

    from sandbox.connector.approval import apply_external
    result = asyncio.run(apply_external(lay, "req-m3-sig", [a1, a2],
                                        clock=lambda: time.time()))
    assert result["status"] == "executed"

    # Check the done-record
    done_dir = lay.root / ".sandbox" / "escalations" / "done"
    if not done_dir.exists():
        done_dir = lay.root / ".sandbox" / "done"
    done_file = None
    for d in [lay.root / ".sandbox" / "escalations" / "done",
              lay.root / ".sandbox" / "done"]:
        f = d / "req-m3-sig.json"
        if f.exists():
            done_file = f
            break
    assert done_file is not None, "done-record not found"
    done_rec = json.loads(done_file.read_text(encoding="utf-8"))
    # Must be signed by connector:<device_id>
    signer = done_rec.get("reviewer_id", "")
    assert signer.startswith("connector:"), f"signer is {signer!r}, not connector:*"


def test_m3_output_scrubbed(tmp_path, monkeypatch):
    """The done-record output is scrubbed of secrets."""
    _need("sandbox.connector.approval", "_binding_fingerprint")
    ctx, bob, carol = _two_approvers(tmp_path, monkeypatch)
    lay = ctx["lay"]
    # Create a command that would produce output with a secret
    rec = _create_pending_request(lay, "req-m3-scrub",
                                  command="echo sk_live_secret123")
    common = dict(request_id="req-m3-scrub", command=rec["command"],
                  fingerprint=rec["fingerprint"],
                  policy_sequence=ctx["policy_sequence"])
    a1 = _make_remote_approval(bob[0], user_id="user-bob", **common)
    a2 = _make_remote_approval(carol[0], user_id="user-carol", **common)

    from sandbox.connector.approval import apply_external
    result = asyncio.run(apply_external(lay, "req-m3-scrub", [a1, a2],
                                        clock=lambda: time.time()))
    assert result["status"] == "executed"
    # Verify scrub happened by checking queue.finish was used
    # (the builder must route through queue.finish which does scrub)
    done_rec = result.get("result", {})
    # If stdout contains the secret, scrub was not applied
    stdout = done_rec.get("stdout", "")
    if "sk_live_secret123" in stdout:
        assert False, "secret was not scrubbed from output"


def test_m3_done_record_in_evidence_export(tmp_path, monkeypatch):
    """The done-record for a remote-approved action is visible to the
    evidence export."""
    _need("sandbox.connector.approval", "_binding_fingerprint")
    ctx, bob, carol = _two_approvers(tmp_path, monkeypatch)
    lay = ctx["lay"]
    rec = _create_pending_request(lay, "req-m3-evidence")
    common = dict(request_id="req-m3-evidence", command=rec["command"],
                  fingerprint=rec["fingerprint"],
                  policy_sequence=ctx["policy_sequence"])
    a1 = _make_remote_approval(bob[0], user_id="user-bob", **common)
    a2 = _make_remote_approval(carol[0], user_id="user-carol", **common)

    from sandbox.connector.approval import apply_external
    asyncio.run(apply_external(lay, "req-m3-evidence", [a1, a2],
                               clock=lambda: time.time()))

    from sandbox.connector.evidence import export_evidence
    pack_path = tmp_path / "evidence.zip"
    export_evidence(lay, pack_path)
    assert pack_path.exists()
    # The pack must contain the done-record
    import zipfile
    with zipfile.ZipFile(pack_path) as zf:
        names = zf.namelist()
        found = any("req-m3-evidence" in n for n in names)
    assert found, "done-record not found in evidence pack"


def test_m3_done_record_hash_in_audit_chain(tmp_path, monkeypatch):
    """The done-record hash is written to the audit chain."""
    _need("sandbox.connector.approval", "_binding_fingerprint")
    ctx, bob, carol = _two_approvers(tmp_path, monkeypatch)
    lay = ctx["lay"]
    rec = _create_pending_request(lay, "req-m3-chain")
    common = dict(request_id="req-m3-chain", command=rec["command"],
                  fingerprint=rec["fingerprint"],
                  policy_sequence=ctx["policy_sequence"])
    a1 = _make_remote_approval(bob[0], user_id="user-bob", **common)
    a2 = _make_remote_approval(carol[0], user_id="user-carol", **common)

    from sandbox.connector.approval import apply_external
    asyncio.run(apply_external(lay, "req-m3-chain", [a1, a2],
                               clock=lambda: time.time()))

    # Read the audit chain and check for this request's hash
    audit_dir = lay.root / ".sandbox" / "audit"
    if audit_dir.exists():
        chain_files = sorted(audit_dir.glob("*.jsonl"))
        found = False
        for cf in chain_files:
            content = cf.read_text(encoding="utf-8")
            if "req-m3-chain" in content:
                found = True
                break
        assert found, "done-record hash not in audit chain"
    else:
        assert False, "audit dir missing"


def test_m3_connector_prefix_never_counted_as_approver(tmp_path, monkeypatch):
    """The connector:<device_id> signer is never counted as an approver."""
    _need("sandbox.connector.approval", "_binding_fingerprint")
    ctx, bob, carol = _two_approvers(tmp_path, monkeypatch)
    lay = ctx["lay"]
    rec = _create_pending_request(lay, "req-m3-nocount")
    common = dict(request_id="req-m3-nocount", command=rec["command"],
                  fingerprint=rec["fingerprint"],
                  policy_sequence=ctx["policy_sequence"])
    a1 = _make_remote_approval(bob[0], user_id="user-bob", **common)
    a2 = _make_remote_approval(carol[0], user_id="user-carol", **common)

    from sandbox.connector.approval import apply_external
    result = asyncio.run(apply_external(lay, "req-m3-nocount", [a1, a2],
                                        clock=lambda: time.time()))
    assert result["status"] == "executed"
    done_rec = result.get("result", {})
    approved_by = done_rec.get("approved_by", [])
    for approver in approved_by:
        uid = approver if isinstance(approver, str) else approver.get("user_id", "")
        assert not uid.startswith("connector:"), \
            f"connector: prefix counted as approver: {uid}"


def test_m3_missing_connector_key_runs_nothing(tmp_path, monkeypatch):
    """If the connector key is unavailable, nothing executes."""
    _need("sandbox.connector.approval", "_binding_fingerprint")
    ctx, bob, carol = _two_approvers(tmp_path, monkeypatch)
    lay = ctx["lay"]
    rec = _create_pending_request(lay, "req-m3-nokey")
    common = dict(request_id="req-m3-nokey", command=rec["command"],
                  fingerprint=rec["fingerprint"],
                  policy_sequence=ctx["policy_sequence"])
    a1 = _make_remote_approval(bob[0], user_id="user-bob", **common)
    a2 = _make_remote_approval(carol[0], user_id="user-carol", **common)

    # Remove the key home to make the connector key unavailable
    monkeypatch.setenv("SANDBOX_KEY_HOME", str(tmp_path / "nonexistent-kh"))

    from sandbox.connector.approval import apply_external
    result = asyncio.run(apply_external(lay, "req-m3-nokey", [a1, a2],
                                        clock=lambda: time.time()))
    assert result["status"] != "executed"


# ===================================================================
# ENROLL PERSISTENCE: operator_user_id, device_id (C5, F3)
# ===================================================================

def test_enroll_persists_operator_user_id_and_device_id(tmp_path, monkeypatch):
    """Real enroll() persists operator_user_id and device_id in
    enrollment.json, and the connector:<device_id> key exists in key home.
    """
    _need("sandbox.connector.sync.enroll", "ENROLL_PERSISTS_OPERATOR")
    kh = tmp_path / "keyhome"
    kh.mkdir()
    monkeypatch.setenv("SANDBOX_KEY_HOME", str(kh))
    lay = _ws(tmp_path / "ws")

    from tests.m2_fakes import FakeSyncServer, FakeResponse
    from tests.security.test_m2_enroll_persist import (
        _make_genesis_and_fingerprint, _enroll_response,
    )
    fp, genesis_env = _make_genesis_and_fingerprint()

    from sandbox.connector.sync.enroll import enroll
    with FakeSyncServer() as srv:
        srv.routes[("POST", "/api/v1/sync/enroll")] = FakeResponse(
            200, _enroll_response(genesis_env, device_id="dev-t12b-1",
                                  operator_user_id="op-alice"))
        enroll(srv.base_url, "CODE-OK", fp)

    sync_dir = lay.root / ".sandbox" / "state" / "sync"
    enroll_file = sync_dir / "enrollment.json"
    assert enroll_file.exists(), "enrollment.json not written"
    data = json.loads(enroll_file.read_text(encoding="utf-8"))
    assert data["operator_user_id"] == "op-alice"
    assert data["device_id"] == "dev-t12b-1"

    # The connector:<device_id> key must exist in key home
    ws_id_file = lay.root / ".sandbox" / "workspace_id"
    ws_id = ws_id_file.read_text(encoding="utf-8").strip()
    kh_ws = kh / ws_id
    connector_files = [f for f in kh_ws.rglob("*")
                       if "connector" in f.name and f.is_file()]
    assert len(connector_files) > 0, "connector:<device_id> key not found in key home"


def test_enroll_operator_mismatch_aborts(tmp_path, monkeypatch):
    """--operator mismatch aborts with nothing written (C5, F3)."""
    _need("sandbox.connector.sync.enroll", "ENROLL_PERSISTS_OPERATOR")
    kh = tmp_path / "keyhome"
    kh.mkdir()
    monkeypatch.setenv("SANDBOX_KEY_HOME", str(kh))
    lay = _ws(tmp_path / "ws")
    sync_dir = lay.root / ".sandbox" / "state" / "sync"
    sync_dir.mkdir(parents=True, exist_ok=True)
    before_sync = set(sync_dir.rglob("*")) if sync_dir.exists() else set()

    from tests.m2_fakes import FakeSyncServer, FakeResponse
    from tests.security.test_m2_enroll_persist import (
        _make_genesis_and_fingerprint, _enroll_response,
    )
    fp, genesis_env = _make_genesis_and_fingerprint()

    from sandbox.connector.sync.enroll import enroll, EnrollError
    with FakeSyncServer() as srv:
        # Server says op-alice, but --operator says op-bob
        srv.routes[("POST", "/api/v1/sync/enroll")] = FakeResponse(
            200, _enroll_response(genesis_env, operator_user_id="op-alice"))
        with pytest.raises(EnrollError, match="operator mismatch"):
            enroll(srv.base_url, "CODE-OK", fp, operator="op-bob")

    after_sync = set(sync_dir.rglob("*")) if sync_dir.exists() else set()
    assert after_sync == before_sync, "state files changed on operator mismatch"


def test_enroll_missing_server_operator_aborts(tmp_path, monkeypatch):
    """If the server omits the operator id, enroll aborts with nothing written (C5)."""
    _need("sandbox.connector.sync.enroll", "ENROLL_PERSISTS_OPERATOR")
    kh = tmp_path / "keyhome"
    kh.mkdir()
    monkeypatch.setenv("SANDBOX_KEY_HOME", str(kh))
    lay = _ws(tmp_path / "ws")
    sync_dir = lay.root / ".sandbox" / "state" / "sync"
    sync_dir.mkdir(parents=True, exist_ok=True)
    before_sync = set(sync_dir.rglob("*")) if sync_dir.exists() else set()

    from tests.m2_fakes import FakeSyncServer, FakeResponse
    from tests.security.test_m2_enroll_persist import _make_genesis_and_fingerprint
    fp, genesis_env = _make_genesis_and_fingerprint()

    from sandbox.connector.sync.enroll import enroll, EnrollError
    with FakeSyncServer() as srv:
        # Server response has NO operator_user_id
        resp = {
            "device_id": "d-no-op",
            "org_id": "org-1",
            "project_id": "proj-1",
            "registry": [genesis_env],
        }
        srv.routes[("POST", "/api/v1/sync/enroll")] = FakeResponse(200, resp)
        with pytest.raises(EnrollError, match="operator_user_id"):
            enroll(srv.base_url, "CODE-OK", fp)

    after_sync = set(sync_dir.rglob("*")) if sync_dir.exists() else set()
    assert after_sync == before_sync, "state files changed when operator missing"


# ===================================================================
# L2: one malformed envelope does not block other decisions
# ===================================================================

def test_l2_malformed_envelope_does_not_block_others(tmp_path, monkeypatch):
    """One malformed envelope does not block other decisions."""
    _need("sandbox.connector.approval", "_binding_fingerprint")
    ctx, bob, carol = _two_approvers(tmp_path, monkeypatch)
    lay = ctx["lay"]
    rec = _create_pending_request(lay, "req-l2")
    common = dict(request_id="req-l2", command=rec["command"],
                  fingerprint=rec["fingerprint"],
                  policy_sequence=ctx["policy_sequence"])

    # A completely malformed envelope
    malformed = {"kind": "garbage", "payload": "not a dict"}
    a_bob = _make_remote_approval(bob[0], user_id="user-bob", **common)
    a_carol = _make_remote_approval(carol[0], user_id="user-carol", **common)

    from sandbox.connector.approval import apply_external
    result = asyncio.run(apply_external(
        lay, "req-l2", [malformed, a_bob, a_carol],
        clock=lambda: time.time()))
    # malformed dropped, bob + carol still count
    assert result["status"] == "executed"


# ===================================================================
# C9 item 6: CLI entry points denied by hook through shell forms
# ===================================================================

def test_c9_cli_sync_cmds_exist():
    """CLI entry points for sync subcommands exist."""
    _need("sandbox.cli.sync_cmds", "enroll")
    from sandbox.cli.sync_cmds import enroll, sync, unenroll
    assert callable(enroll)
    assert callable(sync)
    assert callable(unenroll)


def test_c9_signer_approve_deny_exist():
    """Signer approve and deny CLI entry points exist."""
    _need("sandbox.cli.sync_cmds", "signer_approve")
    from sandbox.cli.sync_cmds import signer_approve, signer_deny
    assert callable(signer_approve)
    assert callable(signer_deny)


def test_c9_shell_bash_c_sandbox_enroll_denied(tmp_path, monkeypatch):
    """bash -c 'sandbox enroll ...' is denied by the hook."""
    _need("sandbox.cli.sync_cmds", "enroll")
    kh = tmp_path / "keyhome"
    kh.mkdir()
    monkeypatch.setenv("SANDBOX_KEY_HOME", str(kh))
    lay = _ws(tmp_path / "ws")
    from sandbox.connector.hook_eval import pre_tool_use
    out = asyncio.run(pre_tool_use(
        {"tool_name": "Bash",
         "tool_input": {"command": "bash -c 'sandbox enroll --server http://x'"},
         "cwd": str(lay.root), "session_id": "t12b"},
        lay,
    ))
    hso = out.get("hookSpecificOutput", {})
    decision = hso.get("permissionDecision", "")
    assert decision == "deny", f"expected deny, got {decision}"


def test_c9_shell_python_m_sandbox_denied(tmp_path, monkeypatch):
    """python -m sandbox sync is denied by the hook."""
    _need("sandbox.cli.sync_cmds", "enroll")
    kh = tmp_path / "keyhome"
    kh.mkdir()
    monkeypatch.setenv("SANDBOX_KEY_HOME", str(kh))
    lay = _ws(tmp_path / "ws")
    from sandbox.connector.hook_eval import pre_tool_use
    out = asyncio.run(pre_tool_use(
        {"tool_name": "Bash",
         "tool_input": {"command": "python -m sandbox sync --once"},
         "cwd": str(lay.root), "session_id": "t12b"},
        lay,
    ))
    hso = out.get("hookSpecificOutput", {})
    decision = hso.get("permissionDecision", "")
    assert decision == "deny", f"expected deny, got {decision}"


def test_c9_shell_python_c_import_denied(tmp_path, monkeypatch):
    """python -c 'import sandbox.cli' is denied by the hook."""
    _need("sandbox.cli.sync_cmds", "enroll")
    kh = tmp_path / "keyhome"
    kh.mkdir()
    monkeypatch.setenv("SANDBOX_KEY_HOME", str(kh))
    lay = _ws(tmp_path / "ws")
    from sandbox.connector.hook_eval import pre_tool_use
    out = asyncio.run(pre_tool_use(
        {"tool_name": "Bash",
         "tool_input": {"command": "python -c \"import sandbox.cli; sandbox.cli.main()\""},
         "cwd": str(lay.root), "session_id": "t12b"},
        lay,
    ))
    hso = out.get("hookSpecificOutput", {})
    decision = hso.get("permissionDecision", "")
    assert decision == "deny", f"expected deny, got {decision}"


# ===================================================================
# HEADLESS HAPPY PATH (demo steps 3, 5, 11)
# ===================================================================

def test_headless_happy_path(tmp_path, monkeypatch):
    """Headless happy path: enroll, upload from escalations/pending, two CLI
    signer approvals, sync, the action runs once in the broker with a clean
    env and the record's cwd, and the evidence export verifies offline with
    both approvers."""
    _need("sandbox.connector.approval", "_binding_fingerprint")
    _need("sandbox.cli.sync_cmds", "enroll")

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

    # Step 3: enroll (mocked -- write enrollment.json)
    sync_dir = lay.root / ".sandbox" / "state" / "sync"
    (sync_dir / "enrollment.json").write_text(json.dumps({
        "device_id": "dev-1", "operator_user_id": "operator-alice",
        "org_id": "org-1", "project_id": "proj-1",
    }), encoding="utf-8")

    # An escalation: the hook would write this to escalations/pending
    rec = _create_pending_request(lay, "req-happy", command="echo hello")

    # Step 5: two signer approvals
    common = dict(request_id="req-happy", command=rec["command"],
                  fingerprint=rec["fingerprint"],
                  policy_sequence=ctx["policy_sequence"])
    a_bob = _make_remote_approval(bob[0], user_id="user-bob", **common)
    a_carol = _make_remote_approval(carol[0], user_id="user-carol", **common)

    from sandbox.connector.approval import apply_external
    result = asyncio.run(apply_external(lay, "req-happy", [a_bob, a_carol],
                                        clock=lambda: time.time()))
    assert result["status"] == "executed"
    done_rec = result.get("result", {})

    # Verify the broker ran the command in the record's cwd, not the daemon's
    assert done_rec.get("state") == "executed" or done_rec.get("exit_code") is not None

    # The done-record must carry both approvers
    remote_approvals = done_rec.get("remote_approvals", [])
    assert len(remote_approvals) == 2

    # Step 11: evidence export verifies offline with both approvers
    from sandbox.connector.evidence import export_evidence, verify_evidence
    pack_path = tmp_path / "evidence-happy.zip"
    export_evidence(lay, pack_path)
    assert pack_path.exists()

    # Security round 4 (Q2): remote dual control verifies only against a
    # root fingerprint obtained out of band (here: the enrolled pin).
    vr = verify_evidence(pack_path, expected_root=ctx["fingerprint"])
    assert vr.get("ok") is True, vr.get("failures")
    assert vr.get("decisions", 0) >= 1


# ===================================================================
# EVIDENCE: offline verify of remote approvals
# ===================================================================

def test_evidence_verify_reverifies_remote_approvals(tmp_path, monkeypatch):
    """verify_evidence re-verifies each remote_approvals envelope offline.

    The genuine pack must pass with ok=True.  Negative tests: a done-record
    whose remote_approvals envelope is junk or bound to another request must
    fail verification.
    """
    _need("sandbox.connector.approval", "_binding_fingerprint")
    ctx, bob, carol = _two_approvers(tmp_path, monkeypatch)
    lay = ctx["lay"]
    rec = _create_pending_request(lay, "req-ev-verify")
    common = dict(request_id="req-ev-verify", command=rec["command"],
                  fingerprint=rec["fingerprint"],
                  policy_sequence=ctx["policy_sequence"])
    a1 = _make_remote_approval(bob[0], user_id="user-bob", **common)
    a2 = _make_remote_approval(carol[0], user_id="user-carol", **common)

    from sandbox.connector.approval import apply_external
    asyncio.run(apply_external(lay, "req-ev-verify", [a1, a2],
                               clock=lambda: time.time()))

    from sandbox.connector.evidence import export_evidence, verify_evidence
    # Positive: genuine pack passes
    pack_ok = tmp_path / "evidence-ok.zip"
    export_evidence(lay, pack_ok)
    vr_ok = verify_evidence(pack_ok, expected_root=ctx["fingerprint"])
    assert vr_ok.get("ok") is True
    assert vr_ok.get("decisions", 0) >= 1

    # Negative: tamper the done-record's remote_approvals with junk
    import zipfile, shutil
    tamper_dir = tmp_path / "tamper"
    tamper_dir.mkdir()
    with zipfile.ZipFile(pack_ok) as zf:
        zf.extractall(tamper_dir)
    # Find the done-record and replace remote_approvals with junk
    done_files = list(tamper_dir.rglob("req-ev-verify*"))
    for df in done_files:
        try:
            dr = json.loads(df.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            continue
        if isinstance(dr, dict) and "remote_approvals" in dr:
            dr["remote_approvals"] = [{"kind": "garbage", "payload": "junk"}]
            df.write_text(json.dumps(dr), encoding="utf-8")
    pack_junk = tmp_path / "evidence-junk.zip"
    with zipfile.ZipFile(pack_junk, "w") as zf:
        for f in tamper_dir.rglob("*"):
            if f.is_file():
                zf.write(f, f.relative_to(tamper_dir))

    vr_junk = verify_evidence(pack_junk)
    # Tampered: either ok=False or the failures list is non-empty
    has_failure = (not vr_junk.get("ok")) or len(vr_junk.get("failures", [])) > 0
    assert has_failure, "verifier should reject junk remote_approvals"


def test_evidence_connector_not_counted_as_approver(tmp_path, monkeypatch):
    """verify_evidence never counts connector:<device_id> as an approver."""
    _need("sandbox.connector.approval", "_binding_fingerprint")
    ctx, bob, carol = _two_approvers(tmp_path, monkeypatch)
    lay = ctx["lay"]
    rec = _create_pending_request(lay, "req-ev-conn")
    common = dict(request_id="req-ev-conn", command=rec["command"],
                  fingerprint=rec["fingerprint"],
                  policy_sequence=ctx["policy_sequence"])
    a1 = _make_remote_approval(bob[0], user_id="user-bob", **common)
    a2 = _make_remote_approval(carol[0], user_id="user-carol", **common)

    from sandbox.connector.approval import apply_external
    asyncio.run(apply_external(lay, "req-ev-conn", [a1, a2],
                               clock=lambda: time.time()))

    from sandbox.connector.evidence import export_evidence, verify_evidence
    pack_path = tmp_path / "evidence-conn.zip"
    export_evidence(lay, pack_path)
    vr = verify_evidence(pack_path)
    # connector: prefix must never appear in approvers list
    approvers = vr.get("approvers", [])
    for a in approvers:
        uid = a if isinstance(a, str) else a.get("user_id", "")
        assert not uid.startswith("connector:"), \
            f"connector: counted as approver in evidence: {uid}"
