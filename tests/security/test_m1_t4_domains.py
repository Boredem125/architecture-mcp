"""M1 T4 (D3.2-4, ADR 0007 section 3): domain-tagged signatures.

Domain tags separate signing contexts so an approval signature cannot be
replayed as a grant, record or policy-change signature, and vice versa.
New records carry ``sig_v: 1`` and the verifier picks the tag and the
signed-field set from code (kind + sig_v), not from the record.  Legacy
(untagged) records verify only against code-defined historical
``_SIGNED_FIELDS`` sets; a claimed arbitrary subset is not legacy.

Tags live in ``src/sandbox/protocol/domains.py`` (MIT, ADR 0004 layout):
  in use:    agg/approval/v1, agg/record/v1, agg/grant/v1,
             agg/policy-change/v1, agg/evidence/v1
  reserved:  agg/registry/v1, agg/bundle/v1, agg/device-assert/v1,
             agg/audit-head/v1

SEC-24 closed: a record claiming ``signed_fields=["request_id"]`` with
``decision`` and ``command`` tampered is refused.

No downgrade: dual control, tool grants and ``policy approve-change``
reject a new decision lacking ``sig_v: 1`` or a pinned key.

ADR 0007 1.6: a legacy record signed by a retired seed verifies as
``legacy`` only when covered by the audit-chain head recorded in the
``key_rotated`` event; a record appended after rotation (even with a
backdated ``ts``) is ``unverifiable``.

Each RED test raises ``DomainsOpen`` for the stated reason only; the
strict xfail accepts that exception and nothing else.  The fix commit
deletes the decorator.  Guards pass today and must keep passing.
"""
from __future__ import annotations

import asyncio
import json
import os
import time
from pathlib import Path
from typing import Any

import pytest
from nacl.signing import SigningKey

from sandbox.connector.approval import approve
from sandbox.connector.evidence import export_evidence, verify_evidence
from sandbox.connector.install import init
from sandbox.connector.layout import FolderLayout
from sandbox.connector.policy import load_policy, save_policy
from sandbox.connector.queue import EscalationQueue
from sandbox.connector.signing import (
    _APPROVAL_FIELDS,
    _SIGNED_FIELDS,
    _canonical,
    _load_or_create_key,
    distinct_approvals,
    sign_approval,
    sign_record,
    verify_approval,
    verify_record,
)
from sandbox.crypto.signing import sign_message, verify_signature

WINDOWS = os.name == "nt"


class DomainsOpen(AssertionError):
    """Domain-tagged signatures are not implemented yet (M1 T4 open)."""


def _require(cond: bool, msg: str) -> None:
    if not cond:
        raise DomainsOpen(msg)


RED_T4 = pytest.mark.xfail(
    raises=DomainsOpen, strict=True,
    reason="T4 open: domain-tagged signatures not yet implemented",
)


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _ws(path: Path) -> FolderLayout:
    path.mkdir(parents=True, exist_ok=True)
    init(path, claude=False, mcp=False)
    return FolderLayout(path)


def _submit(layout: FolderLayout, command: str = "echo t4", **extra) -> str:
    # Named test-setup edit (T12c c2): fp_v=2 and tool_name required by broker
    return EscalationQueue(layout).submit({
        "kind": "command", "command": command, "exec_cwd": str(layout.root),
        "root": str(layout.root), "trigger": ["shell"],
        "tool_name": "Bash", "fp_v": 2,
        "script": None, "script_unbound": "", "script_preview": None,
        **extra,
    })


def _approve_req(layout: FolderLayout, rid: str, reviewer: str, reason: str = "t4 test") -> dict[str, Any]:
    return asyncio.run(approve(layout, rid, reviewer, reason))


def _done_record(layout: FolderLayout, rid: str) -> dict[str, Any]:
    return json.loads((layout.done_dir / f"{rid}.json").read_text(encoding="utf-8"))


def _audit_events(layout: FolderLayout) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for f in layout.audit_dir.rglob("*.jsonl"):
        for line in f.read_text(encoding="utf-8").splitlines():
            if line.strip():
                out.append(json.loads(line))
    return out


@pytest.fixture
def key_home(tmp_path, monkeypatch):
    kh = tmp_path / "keyhome"
    monkeypatch.setenv("SANDBOX_KEY_HOME", str(kh))
    return kh


# ===========================================================================
#  1. SCOPE: src/sandbox/protocol/domains.py exists with the 5 active tags
#     and 4 reserved tags named in ADR 0007 section 3
# ===========================================================================


def test_domains_module_has_active_tags():
    """The 5 in-use domain tags must be defined in domains.py (ADR 0007 3.1)."""
    try:
        from sandbox.protocol import domains
    except ImportError:
        raise DomainsOpen("src/sandbox/protocol/domains.py does not exist")
    expected = {
        "agg/approval/v1", "agg/record/v1", "agg/grant/v1",
        "agg/policy-change/v1", "agg/evidence/v1",
    }
    found = set()
    for name in dir(domains):
        val = getattr(domains, name, None)
        if isinstance(val, str) and val in expected:
            found.add(val)
    _require(expected.issubset(found),
             f"active tags missing from domains.py; expected {expected}, found {found}")


def test_domains_module_has_reserved_tags():
    """The 4 reserved domain tags must be defined in domains.py (ADR 0007 3.1)."""
    try:
        from sandbox.protocol import domains
    except ImportError:
        raise DomainsOpen("src/sandbox/protocol/domains.py does not exist")
    expected = {
        "agg/registry/v1", "agg/bundle/v1", "agg/device-assert/v1",
        "agg/audit-head/v1",
    }
    found = set()
    for name in dir(domains):
        val = getattr(domains, name, None)
        if isinstance(val, str) and val in expected:
            found.add(val)
    _require(expected.issubset(found),
             f"reserved tags missing from domains.py; expected {expected}, found {found}")


# ===========================================================================
#  2. Signed bytes = tag || 0x00 || canonical JSON; records carry sig_v: 1
# ===========================================================================


def test_sign_record_carries_sig_v_1(tmp_path, key_home):
    """sign_record must set sig_v: 1 in the done-record (ADR 0007 3.2)."""
    lay = _ws(tmp_path / "ws")
    rid = _submit(lay)
    res = _approve_req(lay, rid, "alice")
    assert res["status"] == "executed"
    done = _done_record(lay, rid)
    _require(done.get("sig_v") == 1,
             f"done record missing sig_v: 1; got sig_v={done.get('sig_v')}")


def test_sign_approval_carries_sig_v_1(tmp_path, key_home):
    """Individual approvals (from sign_approval) must carry sig_v: 1."""
    lay = _ws(tmp_path / "ws")
    rid = _submit(lay, command="echo dual-sig", requires_dual=True)
    _approve_req(lay, rid, "alice")
    res = _approve_req(lay, rid, "bob")
    assert res["status"] == "executed"
    done = _done_record(lay, rid)
    approvals = done.get("approvals", [])
    assert approvals, "dual-control record has no approvals"
    for a in approvals:
        _require(a.get("sig_v") == 1,
                 f"approval by {a.get('reviewer_id')} missing sig_v: 1")


def test_signature_is_over_tag_separator_canonical_json(tmp_path, key_home):
    """After T4, the signature must be over tag || 0x00 || canonical JSON,
    not plain canonical JSON.  Verifying the old way (no tag prefix) must fail."""
    from nacl.signing import VerifyKey

    lay = _ws(tmp_path / "ws")
    rid = _submit(lay)
    res = _approve_req(lay, rid, "alice")
    assert res["status"] == "executed"
    done = _done_record(lay, rid)
    vk = VerifyKey(bytes.fromhex(done["signer_public_key"]))
    fields = done.get("signed_fields") or _SIGNED_FIELDS
    old_style_bytes = _canonical(done, fields)
    old_ok = verify_signature(old_style_bytes, done["signature"], vk)
    _require(not old_ok,
             "signature still verifies over plain canonical JSON (no tag prefix); "
             "expected tag || 0x00 || canonical JSON")


# ===========================================================================
#  3. SEC-24: a record claiming a short signed_fields (e.g. ["request_id"])
#     with decision/command tampered is refused
# ===========================================================================


def test_sec24_short_signed_fields_tampered_record_refused(tmp_path, key_home):
    """A record claiming signed_fields=["request_id"] with decision/command
    tampered must be refused by verify_record (SEC-24)."""
    lay = _ws(tmp_path / "ws")
    key = _load_or_create_key(lay, "attacker")
    forged = {
        "request_id": "sec24-test-123",
        "command": "echo harmless",
        "decision": "denied",
        "state": "done",
        "reviewer_id": "attacker",
        "signed_fields": ["request_id"],
        "signer_public_key": bytes(key.verify_key).hex(),
    }
    forged["signature"] = sign_message(_canonical(forged, ["request_id"]), key)
    # Tamper the unsigned fields
    forged["command"] = "rm -rf /"
    forged["decision"] = "approved"
    ok = verify_record(forged)
    _require(not ok,
             "verify_record accepted a record with signed_fields=['request_id'] "
             "and tampered command/decision (SEC-24 open)")


def test_sec24_forgery_labelled_unverifiable_in_evidence(tmp_path, key_home):
    """A SEC-24 forgery (short signed_fields, tampered command) must be
    labelled 'unverifiable' in the evidence pack, not 'pinned'."""
    lay = _ws(tmp_path / "ws")
    key = _load_or_create_key(lay, "forger")
    from sandbox.connector.signing import _pin_and_audit
    _pin_and_audit(lay, "forger", bytes(key.verify_key).hex())
    rid = _submit(lay, command="echo safe")
    rec = EscalationQueue(lay).claim(rid, "forger")
    assert rec is not None
    rec["decision"] = "approved"
    rec["state"] = "done"
    rec["reviewer_id"] = "forger"
    rec["decided_at"] = time.time()
    short_fields = ("request_id",)
    rec["signed_fields"] = list(short_fields)
    rec["signer_public_key"] = bytes(key.verify_key).hex()
    rec["signature"] = sign_message(_canonical(rec, short_fields), key)
    rec["command"] = "rm -rf /"  # tamper after signing
    EscalationQueue(lay).finish(rid, rec)
    pack_dir = tmp_path / "pack"
    summary = export_evidence(lay, pack_dir)
    checks = summary.get("checks", [])
    forged_entry = None
    for entry in checks:
        if isinstance(entry, dict) and entry.get("request_id") == rid:
            forged_entry = entry
            break
    _require(forged_entry is not None and forged_entry.get("key_status") == "unverifiable",
             f"SEC-24 forged record not labelled 'unverifiable' in evidence; "
             f"got key_status={forged_entry.get('key_status') if forged_entry else 'not found'}")


# ===========================================================================
#  4. Cross-kind replay refused: an approval signature presented as a
#     record (and vice versa where field sets overlap)
# ===========================================================================


def test_cross_kind_approval_replayed_as_record(tmp_path, key_home):
    """An approval signature replayed as a done-record by claiming
    signed_fields equal to the approval fields must be refused.

    Today verify_record trusts the claimed field set, so the approval
    signature verifies on a record claiming _APPROVAL_FIELDS.  After T4
    the domain tag mismatch and the legacy-only historical-set check
    both refuse it.
    """
    lay = _ws(tmp_path / "ws")
    rid = _submit(lay, command="echo replay", requires_dual=True)
    _approve_req(lay, rid, "alice")
    res = _approve_req(lay, rid, "bob")
    assert res["status"] == "executed"
    done = _done_record(lay, rid)
    approvals = done.get("approvals", [])
    assert approvals
    alice_approval = next(a for a in approvals if a["reviewer_id"] == "alice")
    # Forge a done-record using alice's approval signature and fields
    forged = {
        "request_id": alice_approval["request_id"],
        "command": alice_approval.get("command"),
        "fingerprint": alice_approval.get("fingerprint"),
        "reviewer_id": alice_approval["reviewer_id"],
        "decision": alice_approval["decision"],
        "approved_at": alice_approval.get("approved_at"),
        "state": "done",
        "exit_code": 0,
        "kind": "command",
        "signer_public_key": alice_approval["signer_public_key"],
        "signature": alice_approval["signature"],
        "signed_fields": list(_APPROVAL_FIELDS),
    }
    ok = verify_record(forged)
    _require(not ok,
             "an approval signature was accepted as a done-record via "
             "claimed signed_fields=_APPROVAL_FIELDS (cross-kind replay)")


def test_cross_kind_record_replayed_as_tool_grant(tmp_path, key_home):
    """A record signature (over _SIGNED_FIELDS) presented as a tool_call
    grant must be refused by find_grant.

    'kind' is not in _SIGNED_FIELDS, so setting kind='tool_call' does
    not change the canonical or the signature.  After T4 the domain tag
    (agg/record/v1 != agg/grant/v1) refuses the replay: verify_record
    infers the tag from ``kind``, so the RECORD-tagged signature does
    not verify when the record claims ``kind=tool_call`` (GRANT tag).
    """
    from sandbox.connector.tool_grants import find_grant, fingerprint as grant_fp
    from sandbox.protocol.domains import RECORD

    lay = _ws(tmp_path / "ws")
    _approve_req(lay, _submit(lay), "alice")          # pin alice
    from sandbox.connector import keyhome
    wsdir = keyhome.workspace_key_dir(lay, create=False)
    alice_key = SigningKey((wsdir / "alice.seed").read_bytes())
    alice_pub = bytes(alice_key.verify_key).hex()
    fp = grant_fp("stripe_refund", {"amount": 100})
    # Build a done-record signed as a command (RECORD domain tag)
    rec = {
        "request_id": f"replay-{os.urandom(8).hex()}",
        "kind": "command",       # signed as a record, not a grant
        "command": "stripe_refund",
        "fingerprint": fp,
        "decision": "approved",
        "state": "done",
        "reviewer_id": "alice",
        "decided_at": time.time(),
        "signer_public_key": alice_pub,
        "signed_fields": list(_SIGNED_FIELDS),
        "sig_v": 1,
    }
    rec["signature"] = sign_message(
        RECORD.encode() + b"\x00" + _canonical(rec), alice_key)
    assert verify_record(rec), "record signature should verify with RECORD tag"
    # Flip kind to tool_call (kind is not in _SIGNED_FIELDS, signature intact,
    # but verify_record now infers the GRANT tag from kind=tool_call, so the
    # RECORD-tagged signature no longer matches).
    rec["kind"] = "tool_call"
    lay.done_dir.mkdir(parents=True, exist_ok=True)
    (lay.done_dir / f"{rec['request_id']}.json").write_text(
        json.dumps(rec), encoding="utf-8")
    grant = find_grant(lay, fp)
    assert grant is None, (
        "find_grant accepted a record whose signature was made over "
        "the record domain but presented as a tool_call grant "
        "(cross-kind replay: kind is not in _SIGNED_FIELDS)"
    )


def test_cross_kind_approval_replayed_as_policy_change_acceptance(tmp_path, key_home):
    """A regular command approval replayed as a policy-change acceptance
    must be refused by verify_entry.

    sign_approval produces the same _APPROVAL_FIELDS canonical for both
    a command approval and a policy-change acceptance when the subject
    fields match.  Today verify_entry calls verify_approval without a
    domain context, so the replay verifies.  After T4 the domain tag
    (agg/approval/v1 != agg/policy-change/v1) refuses it.
    """
    from sandbox.connector.policy_versions import (
        _accept, _approval_subject, propose, verify_entry,
    )

    lay = _ws(tmp_path / "ws")
    # Pin alice and bob
    _approve_req(lay, _submit(lay), "alice")
    _approve_req(lay, _submit(lay), "bob")
    # Bootstrap a policy version
    policy = load_policy(lay.policy_file)
    content = json.loads(policy.model_dump_json())
    _accept(lay, "folder", content, by="bootstrap", reason="initial", how="init")
    # Propose a change so we know the _approval_subject
    policy.escalation_timeout_seconds = 777
    new_content = json.loads(policy.model_dump_json())
    change = propose(lay, "folder", new_content, "alice", "cross-kind test")
    subject = _approval_subject(
        change["change_id"], change["kind"],
        change.get("base"), change["new_sha256"],
        change.get("governance_sha256"))
    # Create a regular command approval with the same subject fields
    regular_approval = sign_approval(lay, "bob", subject, time.time())
    assert verify_approval(regular_approval), "regular approval should verify"
    # Inject into a fake version-log entry
    fake_entry = {
        "kind": change["kind"],
        "change_id": change["change_id"],
        "sha256": change["new_sha256"],
        "previous": change.get("base"),
        "governance_sha256": change.get("governance_sha256"),
        "by": "bob",
        "reason": "cross-kind replay",
        "approval": regular_approval,
    }
    ok = verify_entry(fake_entry)
    _require(not ok,
             "a regular command approval was accepted as a policy-change "
             "acceptance by verify_entry (cross-kind replay; only the "
             "domain tag should prevent this)")


def test_guard_cross_kind_record_signature_not_valid_as_approval(tmp_path, key_home):
    """A done-record's signature (over _SIGNED_FIELDS) must not verify as
    an individual approval (over _APPROVAL_FIELDS).  Already fails today
    because the canonical bytes differ: the field sets are different."""
    lay = _ws(tmp_path / "ws")
    rid = _submit(lay)
    res = _approve_req(lay, rid, "alice")
    assert res["status"] == "executed"
    done = _done_record(lay, rid)
    fake_approval = {
        "request_id": done.get("request_id"),
        "command": done.get("command"),
        "fingerprint": done.get("fingerprint"),
        "reviewer_id": done.get("reviewer_id"),
        "decision": done.get("decision"),
        "approved_at": done.get("approved_at") or done.get("decided_at"),
        "signer_public_key": done.get("signer_public_key"),
        "signature": done.get("signature"),
    }
    assert not verify_approval(fake_approval), (
        "a done-record signature should not verify as an approval"
    )


# ===========================================================================
#  5. No downgrade: dual control, tool grants and policy approve-change
#     reject a new decision lacking sig_v: 1 or a pinned key
# ===========================================================================


def test_no_downgrade_dual_control_rejects_untagged(tmp_path, key_home):
    """distinct_approvals must refuse hand-forged approvals that lack
    sig_v: 1, even when signed by pinned keys."""
    lay = _ws(tmp_path / "ws")
    _approve_req(lay, _submit(lay), "alice")
    _approve_req(lay, _submit(lay), "bob")
    from sandbox.connector import keyhome
    wsdir = keyhome.workspace_key_dir(lay, create=False)
    alice_key = SigningKey((wsdir / "alice.seed").read_bytes())
    bob_key = SigningKey((wsdir / "bob.seed").read_bytes())
    rid = _submit(lay, command="echo dc-no-downgrade", requires_dual=True)
    rec = EscalationQueue(lay).get(rid)
    forged_approvals = []
    for name, key in [("alice", alice_key), ("bob", bob_key)]:
        a = {
            "request_id": rec["request_id"],
            "command": rec.get("command"),
            "fingerprint": rec.get("fingerprint"),
            "reviewer_id": name,
            "decision": "approve",
            "approved_at": time.time(),
            "signer_public_key": bytes(key.verify_key).hex(),
        }
        # Sign without domain tag (old format, no sig_v)
        a["signature"] = sign_message(_canonical(a, _APPROVAL_FIELDS), key)
        forged_approvals.append(a)
    assert all(verify_approval(a) for a in forged_approvals), "crypto check should pass"
    _require(not distinct_approvals(forged_approvals, layout=lay),
             "distinct_approvals accepted approvals without sig_v: 1 (no-downgrade)")


def test_no_downgrade_tool_grants_reject_missing_sig_v(tmp_path, key_home):
    """find_grant must refuse a tool_call done-record lacking sig_v: 1."""
    from sandbox.connector.tool_grants import find_grant, fingerprint as grant_fp

    lay = _ws(tmp_path / "ws")
    _approve_req(lay, _submit(lay), "alice")  # pin alice
    from sandbox.connector import keyhome
    wsdir = keyhome.workspace_key_dir(lay, create=False)
    alice_key = SigningKey((wsdir / "alice.seed").read_bytes())
    alice_pub = bytes(alice_key.verify_key).hex()
    fp = grant_fp("stripe_refund", {"amount": 100})
    rec = {
        "request_id": f"grant-{os.urandom(8).hex()}",
        "kind": "tool_call",
        "command": "stripe_refund",
        "fingerprint": fp,
        "decision": "approved",
        "state": "done",
        "reviewer_id": "alice",
        "decided_at": time.time(),
        "signer_public_key": alice_pub,
        "signed_fields": list(_SIGNED_FIELDS),
    }
    rec["signature"] = sign_message(_canonical(rec), alice_key)
    # No sig_v in the record -- old format
    lay.done_dir.mkdir(parents=True, exist_ok=True)
    (lay.done_dir / f"{rec['request_id']}.json").write_text(
        json.dumps(rec), encoding="utf-8")
    grant = find_grant(lay, fp)
    _require(grant is None,
             "find_grant accepted a tool_call record without sig_v: 1 (no-downgrade)")


def test_no_downgrade_policy_approve_change_requires_sig_v(tmp_path, key_home):
    """A policy proposal must carry sig_v: 1 after T4."""
    from sandbox.connector.policy_versions import _accept, propose

    lay = _ws(tmp_path / "ws")
    _approve_req(lay, _submit(lay), "alice")  # pin alice
    policy = load_policy(lay.policy_file)
    content = json.loads(policy.model_dump_json())
    _accept(lay, "folder", content, by="bootstrap", reason="initial", how="init")
    policy.escalation_timeout_seconds = 999
    new_content = json.loads(policy.model_dump_json())
    change = propose(lay, "folder", new_content, "alice", "test T4 sig_v")
    _require(change.get("sig_v") == 1,
             f"propose() did not produce sig_v: 1; keys present: {sorted(change.keys())}")


# ===========================================================================
#  6. Legacy: untagged records verify only against code-defined historical
#     _SIGNED_FIELDS sets; an arbitrary claimed subset is not legacy
# ===========================================================================


def test_guard_legacy_untagged_with_historical_fields_still_verifies(tmp_path, key_home):
    """An untagged (pre-T4) record using the exact historical _SIGNED_FIELDS
    set must still verify.  This is the backward-compatible legacy path."""
    lay = _ws(tmp_path / "ws")
    key = _load_or_create_key(lay, "oldreviewer")
    rec = {
        "request_id": f"legacy-{os.urandom(8).hex()}",
        "command": "echo legacy",
        "decision": "approved",
        "state": "done",
        "reviewer_id": "oldreviewer",
        "signed_fields": list(_SIGNED_FIELDS),
        "signer_public_key": bytes(key.verify_key).hex(),
    }
    rec["signature"] = sign_message(_canonical(rec), key)
    assert verify_record(rec), (
        "untagged record with the exact historical _SIGNED_FIELDS does not verify"
    )


def test_legacy_arbitrary_claimed_subset_is_not_legacy(tmp_path, key_home):
    """An untagged record claiming signed_fields that is NOT one of the
    historical _SIGNED_FIELDS versions must not verify as legacy."""
    lay = _ws(tmp_path / "ws")
    key = _load_or_create_key(lay, "trickster")
    arbitrary_fields = ("request_id", "reviewer_id")
    rec = {
        "request_id": f"arb-{os.urandom(8).hex()}",
        "command": "echo trick",
        "decision": "approved",
        "state": "done",
        "reviewer_id": "trickster",
        "signed_fields": list(arbitrary_fields),
        "signer_public_key": bytes(key.verify_key).hex(),
    }
    rec["signature"] = sign_message(_canonical(rec, arbitrary_fields), key)
    ok = verify_record(rec)
    _require(not ok,
             "verify_record accepted an untagged record with an arbitrary "
             "claimed subset; only historical _SIGNED_FIELDS sets are valid")


# ===========================================================================
#  7. ADR 0007 1.6: a legacy record signed by a retired seed verifies as
#     'legacy' when covered by the audit-chain head in key_rotated; a
#     record appended after rotation (even backdated) is 'unverifiable'
# ===========================================================================


def test_guard_legacy_record_under_chain_head_labelled_legacy(tmp_path, key_home):
    """A pre-rotation record covered by the key_rotated chain head must
    show key_status='legacy' in the evidence pack (T3 property, still holds)."""
    lay = _ws(tmp_path / "ws")
    old_key = SigningKey.generate()
    seed_path = lay.state_dir / "keys" / "cli.seed"
    seed_path.parent.mkdir(parents=True, exist_ok=True)
    seed_path.write_bytes(bytes(old_key))
    # Create a done record BEFORE rotation
    rid_old = _submit(lay, command="echo legacy-under-head")
    rec_old = EscalationQueue(lay).claim(rid_old, "cli")
    assert rec_old is not None
    rec_old["decision"] = "approved"
    rec_old["reviewer_id"] = "cli"
    rec_old["state"] = "done"
    rec_old["decided_at"] = time.time()
    rec_old["signer_public_key"] = bytes(old_key.verify_key).hex()
    rec_old["signed_fields"] = list(_SIGNED_FIELDS)
    rec_old["signature"] = sign_message(_canonical(rec_old), old_key)
    EscalationQueue(lay).finish(rid_old, rec_old)
    # Trigger rotation
    rid_new = _submit(lay, command="echo trigger-rotation")
    _approve_req(lay, rid_new, "cli")
    # Export evidence and check the old record
    pack_dir = tmp_path / "pack"
    summary = export_evidence(lay, pack_dir)
    checks = summary.get("checks", [])
    old_entry = None
    for entry in checks:
        if isinstance(entry, dict) and entry.get("request_id") == rid_old:
            old_entry = entry
            break
    assert old_entry is not None, f"old record {rid_old} not in evidence checks"
    assert old_entry.get("key_status") == "legacy", (
        f"pre-rotation record not labelled 'legacy'; "
        f"got key_status={old_entry.get('key_status')}"
    )


def test_adr0007_1_6_backdated_record_after_rotation_is_unverifiable(tmp_path, key_home):
    """A record signed with a retired key, with decided_at backdated to
    before rotation, must be 'unverifiable' because it is not covered by
    the audit-chain head recorded in key_rotated (ADR 0007 1.6).

    The current timestamp-only check in _key_status_for would incorrectly
    label this as 'legacy'; the T4 fix uses audit_heads instead."""
    lay = _ws(tmp_path / "ws")
    old_key = SigningKey.generate()
    seed_path = lay.state_dir / "keys" / "cli.seed"
    seed_path.parent.mkdir(parents=True, exist_ok=True)
    seed_path.write_bytes(bytes(old_key))
    old_pub = bytes(old_key.verify_key).hex()
    # Trigger rotation
    rid_rotate = _submit(lay, command="echo rotate")
    _approve_req(lay, rid_rotate, "cli")
    events = _audit_events(lay)
    rot_events = [e for e in events if e.get("event") == "key_rotated"]
    assert rot_events, "no key_rotated event found"
    rot_ts = rot_events[0]["ts"]
    # Forge a record AFTER rotation but BACKDATE its decided_at
    rid_forged = _submit(lay, command="echo backdated")
    rec_forged = EscalationQueue(lay).claim(rid_forged, "cli")
    assert rec_forged is not None
    rec_forged["decision"] = "approved"
    rec_forged["reviewer_id"] = "cli"
    rec_forged["state"] = "done"
    rec_forged["decided_at"] = rot_ts - 100  # backdate to before rotation
    rec_forged["signer_public_key"] = old_pub
    rec_forged["signed_fields"] = list(_SIGNED_FIELDS)
    rec_forged["signature"] = sign_message(_canonical(rec_forged), old_key)
    EscalationQueue(lay).finish(rid_forged, rec_forged)
    # Export evidence
    pack_dir = tmp_path / "pack"
    summary = export_evidence(lay, pack_dir)
    checks = summary.get("checks", [])
    forged_entry = None
    for entry in checks:
        if isinstance(entry, dict) and entry.get("request_id") == rid_forged:
            forged_entry = entry
            break
    _require(forged_entry is not None and forged_entry.get("key_status") == "unverifiable",
             f"backdated record was not labelled 'unverifiable'; "
             f"got key_status={forged_entry.get('key_status') if forged_entry else 'not found'}; "
             f"the current timestamp-only check lets backdated records slip through")


# ===========================================================================
#  8. End-to-end paths: verify_record, verify_approval, evidence export +
#     verify_evidence, sandbox verify CLI via CliRunner
# ===========================================================================


def test_guard_verify_record_roundtrip(tmp_path, key_home):
    """A legitimate approval's done-record verifies through verify_record."""
    lay = _ws(tmp_path / "ws")
    rid = _submit(lay)
    res = _approve_req(lay, rid, "alice")
    assert res["status"] == "executed"
    done = _done_record(lay, rid)
    assert verify_record(done), "a legitimate done-record does not verify"


def test_guard_verify_approval_roundtrip(tmp_path, key_home):
    """A legitimate individual approval verifies through verify_approval."""
    lay = _ws(tmp_path / "ws")
    rid = _submit(lay, command="echo dual-guard", requires_dual=True)
    _approve_req(lay, rid, "alice")
    res = _approve_req(lay, rid, "bob")
    assert res["status"] == "executed"
    done = _done_record(lay, rid)
    approvals = done.get("approvals", [])
    assert approvals, "dual-control record has no approvals"
    for a in approvals:
        assert verify_approval(a), (
            f"legitimate approval by {a.get('reviewer_id')} does not verify"
        )


def test_guard_evidence_export_and_verify_via_cli(tmp_path, key_home):
    """sandbox verify-evidence, via CliRunner, passes on a clean evidence pack."""
    from click.testing import CliRunner
    from sandbox.cli.main import cli

    lay = _ws(tmp_path / "ws")
    rid = _submit(lay)
    _approve_req(lay, rid, "alice")
    pack_dir = tmp_path / "pack"
    export_evidence(lay, pack_dir)
    runner = CliRunner()
    result = runner.invoke(cli, ["verify-evidence", str(pack_dir)])
    assert result.exit_code == 0, f"verify-evidence failed: {result.output}"


def test_guard_sandbox_verify_cli_via_clirunner(tmp_path, key_home):
    """sandbox verify, via CliRunner, passes for a workspace with valid chains."""
    from click.testing import CliRunner
    from sandbox.cli.main import cli

    lay = _ws(tmp_path / "ws")
    rid = _submit(lay)
    _approve_req(lay, rid, "alice")
    runner = CliRunner()
    result = runner.invoke(cli, ["verify", str(lay.root)])
    assert result.exit_code == 0, f"sandbox verify failed: {result.output}"
