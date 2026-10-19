"""M1 T4b: no-downgrade for live decisions (SEC-30) and evidence manifest tagging (SEC-31).

SEC-30: live decision paths reject any signature without sig_v:1 and any
key that isn't pinned:
  - approval.py ``_valid_for`` / ``distinct_approvals`` (dual control)
  - tool_grants.py ``find_grant``
  - policy_versions.py ``verify_proposal`` when accepting a change
  - ``verify_approval(..., expected_tag=POLICY_CHANGE)`` inside ``verify_change``
History paths still accept untagged legacy records and label them ``legacy``:
  - ``verify_entry`` (used by ``policy log``, connector_cmds.py ~1340)
  - ``sandbox verify``
  - the evidence pack
A half-done pre-T4 dual approval must be re-approved (fails closed).

SEC-31: evidence.py ``sign_manifest`` signs with the EVIDENCE tag
(agg/evidence/v1) and sets sig_v:1.  A tagged manifest verifies; an
untagged (pre-T4) manifest still verifies but is labelled legacy; a
tagged manifest re-signed or checked untagged (downgrade) fails.

Each RED test fails today and is marked ``strict xfail(raises=DowngradeOpen)``.
Guards pass today and must keep passing after the fix.

Helpers mirror ``test_m1_t4_domains.py`` and ``test_m1_t4_followup.py``.
"""
from __future__ import annotations

import asyncio
import json
import os
import time
from pathlib import Path, PurePosixPath
from typing import Any

import pytest
from nacl.signing import SigningKey

from sandbox.connector.approval import _valid_for, approve
from sandbox.connector.evidence import (
    EXPORTER_KEY,
    _canon,
    _sha256,
    build_pack,
    export_evidence,
    sign_manifest,
    verify_evidence,
)
from sandbox.connector.install import init
from sandbox.connector.layout import FolderLayout
from sandbox.connector.policy import load_policy
from sandbox.connector.queue import EscalationQueue
from sandbox.connector.signing import (
    _APPROVAL_FIELDS,
    _SIGNED_FIELDS,
    _canonical,
    _load_or_create_key,
    distinct_approvals,
    sign_approval,
    verify_approval,
    verify_record,
)
from sandbox.crypto.signing import sign_message, verify_signature


# ---------------------------------------------------------------------------
# exception and marker
# ---------------------------------------------------------------------------

class DowngradeOpen(AssertionError):
    """SEC-30/SEC-31 downgrade protections not implemented yet (M1 T4b)."""


def _require(cond: bool, msg: str) -> None:
    if not cond:
        raise DowngradeOpen(msg)


RED_T4b = pytest.mark.xfail(
    raises=DowngradeOpen, strict=True,
    reason="T4b open: no-downgrade / manifest tagging not yet implemented",
)


# ---------------------------------------------------------------------------
# helpers (mirrored from test_m1_t4_domains.py / test_m1_t4_followup.py)
# ---------------------------------------------------------------------------

def _ws(path: Path) -> FolderLayout:
    path.mkdir(parents=True, exist_ok=True)
    init(path, claude=False, mcp=False)
    return FolderLayout(path)


def _submit(layout: FolderLayout, command: str = "echo t4b", **extra) -> str:
    return EscalationQueue(layout).submit({
        "kind": "command", "command": command, "exec_cwd": str(layout.root),
        "root": str(layout.root), "trigger": ["shell"], **extra,
    })


def _approve_req(
    layout: FolderLayout, rid: str, reviewer: str, reason: str = "t4b test",
) -> dict[str, Any]:
    return asyncio.run(approve(layout, rid, reviewer, reason))


def _done_record(layout: FolderLayout, rid: str) -> dict[str, Any]:
    return json.loads(
        (layout.done_dir / f"{rid}.json").read_text(encoding="utf-8")
    )


def _get_reviewer_key(layout: FolderLayout, reviewer: str) -> SigningKey:
    """Retrieve the signing key for *reviewer* from the key home."""
    from sandbox.connector import keyhome

    wsdir = keyhome.workspace_key_dir(layout, create=False)
    return SigningKey((wsdir / f"{reviewer}.seed").read_bytes())


def _forge_legacy_approval(
    layout: FolderLayout,
    reviewer: str,
    subject: dict[str, Any],
    approved_at: float,
) -> dict[str, Any]:
    """Forge a legacy (pre-T4) approval: no sig_v, no domain tag.

    *subject* must carry ``request_id``, ``command`` and ``fingerprint``
    (a pending record or a policy-change subject).
    """
    key = _get_reviewer_key(layout, reviewer)
    pub_hex = bytes(key.verify_key).hex()
    approval: dict[str, Any] = {
        "request_id": subject.get("request_id"),
        "command": subject.get("command"),
        "fingerprint": subject.get("fingerprint"),
        "reviewer_id": reviewer,
        "decision": "approve",
        "approved_at": approved_at,
        "signer_public_key": pub_hex,
        # deliberately NO sig_v -- legacy format
    }
    data = _canonical(approval, _APPROVAL_FIELDS)
    approval["signature"] = sign_message(data, key)
    return approval


@pytest.fixture
def key_home(tmp_path, monkeypatch):
    kh = tmp_path / "keyhome"
    monkeypatch.setenv("SANDBOX_KEY_HOME", str(kh))
    return kh


# ===========================================================================
# GUARDS -- pass today, must keep passing after the fix
# ===========================================================================


def test_guard_distinct_approvals_rejects_legacy_approval(tmp_path, key_home):
    """distinct_approvals already filters sig_v: 1 (T4 code).  A pair of
    legacy approvals (no sig_v) signed by pinned keys is rejected."""
    lay = _ws(tmp_path / "ws")
    _approve_req(lay, _submit(lay), "alice")
    _approve_req(lay, _submit(lay), "bob")
    rid = _submit(lay, command="echo dc-guard", requires_dual=True)
    rec = EscalationQueue(lay).get(rid)
    forged = [
        _forge_legacy_approval(lay, "alice", rec, time.time()),
        _forge_legacy_approval(lay, "bob", rec, time.time()),
    ]
    assert all(verify_approval(a) for a in forged), "crypto should pass"
    assert not distinct_approvals(forged, layout=lay), (
        "distinct_approvals should reject approvals without sig_v: 1"
    )


def test_guard_find_grant_rejects_legacy_grant(tmp_path, key_home):
    """find_grant already filters sig_v: 1 (T4 code).  A legacy tool_call
    record (no sig_v) is rejected as a grant."""
    from sandbox.connector.tool_grants import find_grant, fingerprint as grant_fp

    lay = _ws(tmp_path / "ws")
    _approve_req(lay, _submit(lay), "alice")
    alice_key = _get_reviewer_key(lay, "alice")
    alice_pub = bytes(alice_key.verify_key).hex()
    fp = grant_fp("payment_refund", {"amount": 500})
    rec: dict[str, Any] = {
        "request_id": f"grant-legacy-{os.urandom(8).hex()}",
        "kind": "tool_call",
        "command": "payment_refund",
        "fingerprint": fp,
        "decision": "approved",
        "state": "done",
        "reviewer_id": "alice",
        "decided_at": time.time(),
        "signer_public_key": alice_pub,
        "signed_fields": list(_SIGNED_FIELDS),
        # no sig_v -- legacy
    }
    rec["signature"] = sign_message(_canonical(rec), alice_key)
    lay.done_dir.mkdir(parents=True, exist_ok=True)
    (lay.done_dir / f"{rec['request_id']}.json").write_text(
        json.dumps(rec), encoding="utf-8",
    )
    assert find_grant(lay, fp) is None, (
        "find_grant should reject a tool_call record without sig_v: 1"
    )


def test_guard_verify_entry_accepts_legacy_entry(tmp_path, key_home):
    """verify_entry (history path) must still verify an untagged (legacy)
    policy-log entry for backward compatibility (policy log display)."""
    from sandbox.connector.policy_versions import (
        _accept,
        _approval_subject,
        verify_entry,
    )

    lay = _ws(tmp_path / "ws")
    _approve_req(lay, _submit(lay), "alice")
    alice_key = _get_reviewer_key(lay, "alice")
    # bootstrap a policy version so the history dir exists
    policy = load_policy(lay.policy_file)
    content = json.loads(policy.model_dump_json())
    _accept(lay, "folder", content, by="bootstrap", reason="init", how="init")
    # forge a legacy log entry with an untagged approval
    subject = _approval_subject("legacy-001", "folder", None, "ab" * 32)
    approval: dict[str, Any] = {
        "request_id": subject["request_id"],
        "command": subject["command"],
        "fingerprint": subject.get("fingerprint"),
        "reviewer_id": "alice",
        "decision": "approve",
        "approved_at": time.time(),
        "signer_public_key": bytes(alice_key.verify_key).hex(),
    }
    approval["signature"] = sign_message(
        _canonical(approval, _APPROVAL_FIELDS), alice_key,
    )
    entry: dict[str, Any] = {
        "kind": "folder",
        "change_id": "legacy-001",
        "sha256": "ab" * 32,
        "previous": None,
        "by": "alice",
        "reason": "legacy entry",
        "approval": approval,
    }
    assert verify_entry(entry), (
        "verify_entry must accept a legacy (untagged) log entry"
    )


def test_guard_untagged_evidence_pack_verifies(tmp_path, key_home):
    """An evidence pack with the current (untagged) manifest format must
    pass verify_evidence.  Pre-T4 backward compatibility."""
    lay = _ws(tmp_path / "ws")
    rid = _submit(lay)
    _approve_req(lay, rid, "alice")
    pack_dir = tmp_path / "pack"
    summary = export_evidence(lay, pack_dir)
    r = verify_evidence(pack_dir, summary.get("exporter_public_key"))
    assert r["ok"], f"untagged pack should verify: {r['failures']}"


def test_guard_legacy_change_verified_legacy_in_history(tmp_path, key_home):
    """A legacy (untagged) policy change shows as verified-legacy through
    verify_change_history (the history / policy-log path)."""
    from sandbox.connector.policy_versions import (
        _accept,
        _approval_subject,
        _PROPOSAL_FIELDS,
        read_head,
        store,
        verify_change_history,
    )

    lay = _ws(tmp_path / "ws")
    _approve_req(lay, _submit(lay), "alice")
    _approve_req(lay, _submit(lay), "bob")
    alice_key = _get_reviewer_key(lay, "alice")
    bob_key = _get_reviewer_key(lay, "bob")
    policy = load_policy(lay.policy_file)
    content = json.loads(policy.model_dump_json())
    _accept(lay, "folder", content, by="bootstrap", reason="init", how="init")
    policy.escalation_timeout_seconds = 444
    new_content = json.loads(policy.model_dump_json())
    new_sha = store(lay, new_content)
    base = read_head(lay).get("folder")
    change_id = f"guard-hist-{os.urandom(4).hex()}"
    change: dict[str, Any] = {
        "change_id": change_id,
        "kind": "folder",
        "base": base,
        "new_sha256": new_sha,
        "governance_sha256": None,
        "proposer": "alice",
        "reason": "guard history test",
        "proposed_at": time.time(),
        "status": "approved",
        "proposer_public_key": bytes(alice_key.verify_key).hex(),
        # no sig_v -- legacy
    }
    data = _canonical(change, _PROPOSAL_FIELDS)
    change["proposal_signature"] = sign_message(data, alice_key)
    # legacy approval by bob
    subject = _approval_subject(change_id, "folder", base, new_sha)
    approval: dict[str, Any] = {
        "request_id": subject["request_id"],
        "command": subject["command"],
        "fingerprint": subject.get("fingerprint"),
        "reviewer_id": "bob",
        "decision": "approve",
        "approved_at": time.time(),
        "signer_public_key": bytes(bob_key.verify_key).hex(),
        # no sig_v -- legacy
    }
    from sandbox.connector.signing import _APPROVAL_FIELDS as _AF

    approval["signature"] = sign_message(_canonical(approval, _AF), bob_key)
    change["approval"] = approval
    ok, label = verify_change_history(change)
    assert ok, "legacy change should verify in history path"
    assert label == "legacy", f"expected label 'legacy', got {label!r}"


def test_guard_legacy_change_refused_by_live_path(tmp_path, key_home):
    """The same legacy (untagged) policy change is refused by the live path
    (verify_change) -- SEC-30 no-downgrade."""
    from sandbox.connector.policy_versions import (
        _accept,
        _approval_subject,
        _PROPOSAL_FIELDS,
        read_head,
        store,
        verify_change,
    )

    lay = _ws(tmp_path / "ws")
    _approve_req(lay, _submit(lay), "alice")
    _approve_req(lay, _submit(lay), "bob")
    alice_key = _get_reviewer_key(lay, "alice")
    bob_key = _get_reviewer_key(lay, "bob")
    policy = load_policy(lay.policy_file)
    content = json.loads(policy.model_dump_json())
    _accept(lay, "folder", content, by="bootstrap", reason="init", how="init")
    policy.escalation_timeout_seconds = 333
    new_content = json.loads(policy.model_dump_json())
    new_sha = store(lay, new_content)
    base = read_head(lay).get("folder")
    change_id = f"guard-live-{os.urandom(4).hex()}"
    change: dict[str, Any] = {
        "change_id": change_id,
        "kind": "folder",
        "base": base,
        "new_sha256": new_sha,
        "governance_sha256": None,
        "proposer": "alice",
        "reason": "guard live test",
        "proposed_at": time.time(),
        "status": "approved",
        "proposer_public_key": bytes(alice_key.verify_key).hex(),
        # no sig_v -- legacy
    }
    data = _canonical(change, _PROPOSAL_FIELDS)
    change["proposal_signature"] = sign_message(data, alice_key)
    subject = _approval_subject(change_id, "folder", base, new_sha)
    approval: dict[str, Any] = {
        "request_id": subject["request_id"],
        "command": subject["command"],
        "fingerprint": subject.get("fingerprint"),
        "reviewer_id": "bob",
        "decision": "approve",
        "approved_at": time.time(),
        "signer_public_key": bytes(bob_key.verify_key).hex(),
    }
    from sandbox.connector.signing import _APPROVAL_FIELDS as _AF

    approval["signature"] = sign_message(_canonical(approval, _AF), bob_key)
    change["approval"] = approval
    assert not verify_change(change), (
        "verify_change (live path) must reject a legacy change without sig_v: 1"
    )


def test_guard_tampered_legacy_change_fails_history(tmp_path, key_home):
    """A tampered legacy change (reason altered after signing) fails even on
    the history path (verify_change_history)."""
    from sandbox.connector.policy_versions import (
        _accept,
        _approval_subject,
        _PROPOSAL_FIELDS,
        read_head,
        store,
        verify_change_history,
    )

    lay = _ws(tmp_path / "ws")
    _approve_req(lay, _submit(lay), "alice")
    _approve_req(lay, _submit(lay), "bob")
    alice_key = _get_reviewer_key(lay, "alice")
    bob_key = _get_reviewer_key(lay, "bob")
    policy = load_policy(lay.policy_file)
    content = json.loads(policy.model_dump_json())
    _accept(lay, "folder", content, by="bootstrap", reason="init", how="init")
    policy.escalation_timeout_seconds = 222
    new_content = json.loads(policy.model_dump_json())
    new_sha = store(lay, new_content)
    base = read_head(lay).get("folder")
    change_id = f"guard-tamp-{os.urandom(4).hex()}"
    change: dict[str, Any] = {
        "change_id": change_id,
        "kind": "folder",
        "base": base,
        "new_sha256": new_sha,
        "governance_sha256": None,
        "proposer": "alice",
        "reason": "guard tamper test",
        "proposed_at": time.time(),
        "status": "approved",
        "proposer_public_key": bytes(alice_key.verify_key).hex(),
    }
    data = _canonical(change, _PROPOSAL_FIELDS)
    change["proposal_signature"] = sign_message(data, alice_key)
    subject = _approval_subject(change_id, "folder", base, new_sha)
    approval: dict[str, Any] = {
        "request_id": subject["request_id"],
        "command": subject["command"],
        "fingerprint": subject.get("fingerprint"),
        "reviewer_id": "bob",
        "decision": "approve",
        "approved_at": time.time(),
        "signer_public_key": bytes(bob_key.verify_key).hex(),
    }
    from sandbox.connector.signing import _APPROVAL_FIELDS as _AF

    approval["signature"] = sign_message(_canonical(approval, _AF), bob_key)
    change["approval"] = approval
    # tamper: alter a signed field after signing
    change["reason"] = "TAMPERED"
    ok, label = verify_change_history(change)
    assert not ok, "tampered legacy change must fail the history check"
    assert label == "invalid", f"expected label 'invalid', got {label!r}"


# ===========================================================================
# SEC-30 RED: live decision paths reject legacy signatures
# ===========================================================================


def test_sec30_valid_for_rejects_legacy_approval(tmp_path, key_home):
    """_valid_for must reject an approval without sig_v: 1, even when it
    crypto-verifies and is signed by a pinned key (SEC-30)."""
    lay = _ws(tmp_path / "ws")
    _approve_req(lay, _submit(lay), "alice")
    rid = _submit(lay, command="echo sec30-vf")
    rec = EscalationQueue(lay).get(rid)
    legacy = _forge_legacy_approval(lay, "alice", rec, time.time())
    assert verify_approval(legacy), "legacy should crypto-verify"
    _require(
        not _valid_for(legacy, rec, lay),
        "_valid_for accepted a legacy approval without sig_v: 1; "
        "live decision paths must reject untagged signatures (SEC-30)",
    )


def test_sec30_half_done_dual_pre_t4_re_approved(tmp_path, key_home):
    """A half-done pre-T4 dual approval must be re-approved (fails closed).

    When the first approval was legacy (no sig_v), _valid_for filters it
    out, so the second approver becomes the first and gets awaiting_second.
    """
    lay = _ws(tmp_path / "ws")
    _approve_req(lay, _submit(lay), "alice")
    _approve_req(lay, _submit(lay), "bob")
    rid = _submit(lay, command="echo dual-re", requires_dual=True)
    # claim, inject alice's legacy first approval, release back to pending
    rec = EscalationQueue(lay).claim(rid, "setup")
    assert rec is not None
    legacy_alice = _forge_legacy_approval(lay, "alice", rec, time.time())
    assert verify_approval(legacy_alice), "legacy should crypto-verify"
    rec["approvals"] = [legacy_alice]
    EscalationQueue(lay).release(rid, rec)
    # bob tries to complete the dual control
    result = _approve_req(lay, rid, "bob")
    _require(
        result["status"] == "awaiting_second",
        f"expected 'awaiting_second' (legacy first approval filtered out), "
        f"got '{result['status']}'; pre-T4 dual approval not re-approved",
    )


def test_sec30_verify_proposal_rejects_untagged(tmp_path, key_home):
    """verify_proposal must reject a proposal without sig_v: 1 (SEC-30).
    Currently it accepts untagged proposals through the legacy path."""
    from sandbox.connector.policy_versions import (
        _accept,
        _PROPOSAL_FIELDS,
        read_head,
        store,
        verify_proposal,
    )

    lay = _ws(tmp_path / "ws")
    _approve_req(lay, _submit(lay), "alice")
    alice_key = _get_reviewer_key(lay, "alice")
    policy = load_policy(lay.policy_file)
    content = json.loads(policy.model_dump_json())
    _accept(lay, "folder", content, by="bootstrap", reason="init", how="init")
    # forge a legacy proposal
    policy.escalation_timeout_seconds = 888
    new_content = json.loads(policy.model_dump_json())
    new_sha = store(lay, new_content)
    change: dict[str, Any] = {
        "change_id": f"sec30-vp-{os.urandom(4).hex()}",
        "kind": "folder",
        "base": read_head(lay).get("folder"),
        "new_sha256": new_sha,
        "governance_sha256": None,
        "proposer": "alice",
        "reason": "sec30 test",
        "proposed_at": time.time(),
        "status": "open",
        "proposer_public_key": bytes(alice_key.verify_key).hex(),
        # no sig_v -- legacy
    }
    data = _canonical(change, _PROPOSAL_FIELDS)
    change["proposal_signature"] = sign_message(data, alice_key)
    _require(
        not verify_proposal(change, lay),
        "verify_proposal accepted a legacy proposal without sig_v: 1; "
        "the acceptance path must reject untagged proposals (SEC-30)",
    )


def test_sec30_verify_change_rejects_untagged_proposal(tmp_path, key_home):
    """verify_change must reject a change whose proposal lacks sig_v: 1,
    even when the approval is properly tagged."""
    from sandbox.connector.policy_versions import (
        _accept,
        _approval_subject,
        _PROPOSAL_FIELDS,
        read_head,
        store,
        verify_change,
    )

    lay = _ws(tmp_path / "ws")
    _approve_req(lay, _submit(lay), "alice")
    _approve_req(lay, _submit(lay), "bob")
    alice_key = _get_reviewer_key(lay, "alice")
    policy = load_policy(lay.policy_file)
    content = json.loads(policy.model_dump_json())
    _accept(lay, "folder", content, by="bootstrap", reason="init", how="init")
    policy.escalation_timeout_seconds = 777
    new_content = json.loads(policy.model_dump_json())
    new_sha = store(lay, new_content)
    base = read_head(lay).get("folder")
    change: dict[str, Any] = {
        "change_id": f"sec30-vc1-{os.urandom(4).hex()}",
        "kind": "folder",
        "base": base,
        "new_sha256": new_sha,
        "governance_sha256": None,
        "proposer": "alice",
        "reason": "sec30 verify_change test",
        "proposed_at": time.time(),
        "status": "open",
        "proposer_public_key": bytes(alice_key.verify_key).hex(),
        # no sig_v -- legacy
    }
    data = _canonical(change, _PROPOSAL_FIELDS)
    change["proposal_signature"] = sign_message(data, alice_key)
    subject = _approval_subject(
        change["change_id"], change["kind"], base, new_sha,
    )
    from sandbox.protocol.domains import POLICY_CHANGE

    change["approval"] = sign_approval(
        lay, "bob", subject, time.time(), tag=POLICY_CHANGE,
    )
    _require(
        not verify_change(change),
        "verify_change accepted a change with an untagged proposal (SEC-30)",
    )


def test_sec30_verify_change_rejects_untagged_approval(tmp_path, key_home):
    """verify_change must reject a change whose approval lacks sig_v: 1,
    even when the proposal is properly tagged."""
    from sandbox.connector.policy_versions import (
        _accept,
        _approval_subject,
        propose,
        verify_change,
    )

    lay = _ws(tmp_path / "ws")
    _approve_req(lay, _submit(lay), "alice")
    _approve_req(lay, _submit(lay), "bob")
    policy = load_policy(lay.policy_file)
    content = json.loads(policy.model_dump_json())
    _accept(lay, "folder", content, by="bootstrap", reason="init", how="init")
    policy.escalation_timeout_seconds = 666
    new_content = json.loads(policy.model_dump_json())
    change = propose(lay, "folder", new_content, "alice", "sec30 approval test")
    assert change.get("sig_v") == 1, "propose should produce sig_v: 1"
    subject = _approval_subject(
        change["change_id"], change["kind"],
        change.get("base"), change["new_sha256"],
    )
    legacy_approval = _forge_legacy_approval(lay, "bob", subject, time.time())
    change["approval"] = legacy_approval
    _require(
        not verify_change(change),
        "verify_change accepted a change with an untagged approval (SEC-30)",
    )


def test_sec30_accept_change_rejects_untagged_proposal(tmp_path, key_home):
    """The approve_change path must reject an untagged proposal as
    'not_open' because verify_proposal fails (SEC-30)."""
    from sandbox.connector.policy_versions import (
        _accept,
        _changes_dir,
        _PROPOSAL_FIELDS,
        approve_change,
        read_head,
        store,
    )

    lay = _ws(tmp_path / "ws")
    _approve_req(lay, _submit(lay), "alice")
    _approve_req(lay, _submit(lay), "bob")
    alice_key = _get_reviewer_key(lay, "alice")
    policy = load_policy(lay.policy_file)
    content = json.loads(policy.model_dump_json())
    _accept(lay, "folder", content, by="bootstrap", reason="init", how="init")
    policy.escalation_timeout_seconds = 555
    new_content = json.loads(policy.model_dump_json())
    new_sha = store(lay, new_content)
    base = read_head(lay).get("folder")
    change_id = f"sec30-ac-{os.urandom(4).hex()}"
    change: dict[str, Any] = {
        "change_id": change_id,
        "kind": "folder",
        "base": base,
        "new_sha256": new_sha,
        "governance_sha256": None,
        "proposer": "alice",
        "reason": "sec30 accept test",
        "proposed_at": time.time(),
        "status": "open",
        "proposer_public_key": bytes(alice_key.verify_key).hex(),
        # no sig_v -- legacy
    }
    data = _canonical(change, _PROPOSAL_FIELDS)
    change["proposal_signature"] = sign_message(data, alice_key)
    changes_dir = _changes_dir(lay)
    changes_dir.mkdir(parents=True, exist_ok=True)
    (changes_dir / f"{change_id}.json").write_text(
        json.dumps(change), encoding="utf-8",
    )
    result = approve_change(lay, change_id, "bob", "sec30 test")
    _require(
        result["status"] == "not_open",
        f"approve_change accepted an untagged proposal; "
        f"got status '{result['status']}' instead of 'not_open' (SEC-30)",
    )


# ===========================================================================
# SEC-31 RED: evidence manifest tagging
# ===========================================================================


def test_sec31_sign_manifest_sets_sig_v_1(tmp_path, key_home):
    """sign_manifest must set sig_v: 1 in the manifest body (SEC-31)."""
    lay = _ws(tmp_path / "ws")
    _approve_req(lay, _submit(lay), "alice")
    pack_dir = tmp_path / "pack"
    export_evidence(lay, pack_dir)
    manifest = json.loads(
        (pack_dir / "manifest.json").read_text(encoding="utf-8"),
    )
    _require(
        manifest.get("sig_v") == 1,
        f"sign_manifest did not set sig_v: 1; got sig_v={manifest.get('sig_v')}",
    )


def test_sec31_sign_manifest_uses_evidence_tag(tmp_path, key_home):
    """sign_manifest must sign with EVIDENCE || 0x00 || canonical (SEC-31)."""
    from nacl.signing import VerifyKey
    from sandbox.protocol.domains import EVIDENCE

    lay = _ws(tmp_path / "ws")
    _approve_req(lay, _submit(lay), "alice")
    pack_dir = tmp_path / "pack"
    export_evidence(lay, pack_dir)
    manifest = json.loads(
        (pack_dir / "manifest.json").read_text(encoding="utf-8"),
    )
    pub = manifest["exporter_public_key"]
    sig = manifest["signature"]
    body = {k: v for k, v in manifest.items() if k != "signature"}
    vk = VerifyKey(bytes.fromhex(pub))
    tagged_data = EVIDENCE.encode("utf-8") + b"\x00" + _canon(body)
    _require(
        verify_signature(tagged_data, sig, vk),
        "sign_manifest signature does not verify with the EVIDENCE domain tag",
    )


def test_sec31_untagged_manifest_labelled_legacy(tmp_path, key_home):
    """verify_evidence on an untagged (pre-T4) pack must report the manifest
    as not tagged (legacy) via a manifest_tagged field (SEC-31)."""
    lay = _ws(tmp_path / "ws")
    _approve_req(lay, _submit(lay), "alice")
    pack_dir = tmp_path / "pack"
    summary = export_evidence(lay, pack_dir)
    # Rewrite the manifest as untagged (pre-T4 format): drop sig_v, re-sign
    # with the exporter key using untagged canonical bytes.
    manifest_path = pack_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    exporter_key = _load_or_create_key(lay, EXPORTER_KEY)
    manifest.pop("sig_v", None)
    manifest.pop("signature", None)
    body = {k: v for k, v in manifest.items() if k != "signature"}
    manifest["signature"] = sign_message(_canon(body), exporter_key)
    manifest_path.write_text(
        json.dumps(manifest, sort_keys=True, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    r = verify_evidence(pack_dir, summary.get("exporter_public_key"))
    assert r["ok"], f"pack should verify: {r['failures']}"
    _require(
        "manifest_tagged" in r,
        "verify_evidence does not report 'manifest_tagged'; "
        "untagged manifests should be labelled legacy",
    )
    _require(
        r["manifest_tagged"] is False,
        f"expected manifest_tagged=False for untagged pack; "
        f"got {r.get('manifest_tagged')}",
    )


def test_sec31_downgrade_tagged_manifest_fails(tmp_path, key_home):
    """A manifest with sig_v: 1 but whose signature was made without the
    EVIDENCE tag prefix (a downgrade attack) must fail verification.

    Today verify_evidence does not check sig_v, so the tagless signature
    passes.  After the fix, sig_v: 1 triggers the tagged path and the
    tagless signature is rejected.
    """
    lay = _ws(tmp_path / "ws")
    _approve_req(lay, _submit(lay), "alice")
    files = build_pack(lay)
    meta = {
        "created_at": "2026-10-19T00:00:00+00:00",
        "source_root": str(lay.root),
    }
    key = _load_or_create_key(lay, EXPORTER_KEY)
    body: dict[str, Any] = {
        **meta,
        "format": "sandbox-evidence/1",
        "files": {p: _sha256(b) for p, b in sorted(files.items())},
        "exporter_public_key": bytes(key.verify_key).hex(),
        "sig_v": 1,
    }
    # sign WITHOUT tag -- the downgrade
    body["signature"] = sign_message(
        _canon({k: v for k, v in body.items() if k != "signature"}), key,
    )
    manifest_bytes = json.dumps(
        body, sort_keys=True, indent=2, ensure_ascii=False,
    ).encode("utf-8") + b"\n"
    files["manifest.json"] = manifest_bytes
    pack_dir = tmp_path / "pack"
    pack_dir.mkdir()
    for p, data in sorted(files.items()):
        dest = pack_dir.joinpath(*PurePosixPath(p).parts)
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(data)
    r = verify_evidence(pack_dir)
    _require(
        not r["ok"],
        "verify_evidence accepted a manifest with sig_v: 1 but signature "
        "made without the EVIDENCE tag; downgrade should fail (SEC-31)",
    )
