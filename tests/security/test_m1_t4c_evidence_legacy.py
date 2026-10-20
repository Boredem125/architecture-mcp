"""M1 T4c: offline pack verifier handles legacy (pre-M1) records (ADR 0007 1.6).

The regression (found by e2e, T2/T3): ``verify_evidence`` fails every M0-era
record (31 problems on the demo copy; M0 code passes) because
``check_decision`` in ``evidence.py`` compares against the reviewer's *current*
key only and ignores ``legacy``.  The exporter computes ``key_status`` via
``_key_status_for`` but the offline verifier does not use it.

Contract (orchestrator ruling, ADR 0007 Decision 1.6, M1_PLAN D1 item 4):
  1. The offline pack verifier recomputes legacy from the pack itself: the
     record's signer key equals ``retired_public_key`` of a ``key_rotated``
     event for that reviewer in the pack's audit chain, the chain verifies,
     and the record's request_id and canonical sha256 match that event's
     ``done_at_rotation``.  Then the record passes and is labelled legacy.
     Same for each approval in dual_control.
  2. The verifier never trusts a key_status/legacy label written by the
     exporter.
  3. Pre-M1 key never rotated (no key_rotated for that reviewer): the record
     is not verified, and the failure message says the reviewer's pre-M1 key
     has not been rotated and how to fix it.  Assert the message names the
     reviewer and contains "rotat".  Fail closed.

Each RED test fails today and is marked ``strict xfail(raises=LegacyVerifyOpen)``.
Guards pass today and must keep passing after the fix.

Helpers mirror ``test_m1_t4_followup.py`` / ``test_m1_t4b_downgrade.py``.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import time
from pathlib import Path
from typing import Any

import pytest
from nacl.signing import SigningKey

from sandbox.connector.approval import approve
from sandbox.connector.evidence import (
    EXPORTER_KEY,
    _canon,
    _sha256,
    export_evidence,
    verify_evidence,
)
from sandbox.connector.install import init
from sandbox.connector.layout import FolderLayout
from sandbox.connector.queue import EscalationQueue
from sandbox.connector.signing import (
    _APPROVAL_FIELDS,
    _SIGNED_FIELDS,
    _canonical,
    _load_or_create_key,
    ensure_signing_key,
    sign_approval,
    sign_record,
    verify_record,
)
from sandbox.crypto.signing import sign_message


# ---------------------------------------------------------------------------
# exception and marker
# ---------------------------------------------------------------------------

class LegacyVerifyOpen(AssertionError):
    """T4c: offline verifier does not handle legacy records yet."""


def _require(cond: bool, msg: str) -> None:
    if not cond:
        raise LegacyVerifyOpen(msg)


RED_T4c = pytest.mark.xfail(
    raises=LegacyVerifyOpen, strict=True,
    reason="RED_T4c: verify_evidence does not handle legacy records",
)


# ---------------------------------------------------------------------------
# helpers (mirrored from test_m1_t4_followup.py / test_m1_t4b_downgrade.py)
# ---------------------------------------------------------------------------

def _ws(path: Path) -> FolderLayout:
    path.mkdir(parents=True, exist_ok=True)
    init(path, claude=False, mcp=False)
    return FolderLayout(path)


def _submit(layout: FolderLayout, command: str = "echo t4c", **extra) -> str:
    return EscalationQueue(layout).submit({
        "kind": "command", "command": command, "exec_cwd": str(layout.root),
        "root": str(layout.root), "trigger": ["shell"], **extra,
    })


def _approve_req(
    layout: FolderLayout, rid: str, reviewer: str, reason: str = "t4c test",
) -> dict[str, Any]:
    return asyncio.run(approve(layout, rid, reviewer, reason))


def _done_record(layout: FolderLayout, rid: str) -> dict[str, Any]:
    return json.loads(
        (layout.done_dir / f"{rid}.json").read_text(encoding="utf-8")
    )


@pytest.fixture
def key_home(tmp_path, monkeypatch):
    kh = tmp_path / "keyhome"
    monkeypatch.setenv("SANDBOX_KEY_HOME", str(kh))
    return kh


def _place_m0_seed(layout: FolderLayout, reviewer_id: str, key: SigningKey) -> None:
    """Place an in-tree seed at the M0 location (.sandbox/state/keys/<id>.seed)."""
    seed_path = layout.state_dir / "keys" / f"{reviewer_id}.seed"
    seed_path.parent.mkdir(parents=True, exist_ok=True)
    seed_path.write_bytes(bytes(key))


def _m0_sign_record(record: dict[str, Any], key: SigningKey) -> dict[str, Any]:
    """Sign a record in M0 style: untagged, no sig_v, historical _SIGNED_FIELDS."""
    pub_hex = bytes(key.verify_key).hex()
    record["signer_public_key"] = pub_hex
    record["signed_fields"] = list(_SIGNED_FIELDS)
    record["signature"] = sign_message(_canonical(record), key)
    return record


def _m0_sign_approval(
    record: dict[str, Any], reviewer_id: str, key: SigningKey, approved_at: float,
) -> dict[str, Any]:
    """Create an M0-style approval: untagged, no sig_v."""
    pub_hex = bytes(key.verify_key).hex()
    approval: dict[str, Any] = {
        "request_id": record.get("request_id"),
        "command": record.get("command"),
        "fingerprint": record.get("fingerprint"),
        "reviewer_id": reviewer_id,
        "decision": "approve",
        "approved_at": approved_at,
        "signer_public_key": pub_hex,
        # deliberately NO sig_v -- M0 format
    }
    approval["signature"] = sign_message(
        _canonical(approval, _APPROVAL_FIELDS), key,
    )
    return approval


def _create_m0_folder_single(tmp_path: Path) -> tuple[FolderLayout, SigningKey, str, list[str]]:
    """Build a synthetic M0-style folder with single-control done records.

    Returns (layout, old_key, old_pub_hex, list_of_request_ids).
    """
    ws_dir = tmp_path / "m0ws"
    lay = _ws(ws_dir)
    old_key = SigningKey.generate()
    old_pub = bytes(old_key.verify_key).hex()

    # Place the in-tree seed (M0 location)
    _place_m0_seed(lay, "cli", old_key)

    # Create 3 done records signed M0-style
    rids: list[str] = []
    for i in range(3):
        rid = _submit(lay, command=f"echo m0-single-{i}")
        rec = EscalationQueue(lay).claim(rid, "cli")
        assert rec is not None
        rec["decision"] = "approved"
        rec["reviewer_id"] = "cli"
        rec["state"] = "done"
        rec["decided_at"] = time.time() - 1000 + i
        _m0_sign_record(rec, old_key)
        EscalationQueue(lay).finish(rid, rec)
        rids.append(rid)

    return lay, old_key, old_pub, rids


def _create_m0_folder_dual(tmp_path: Path) -> tuple[
    FolderLayout, SigningKey, SigningKey, str, str, list[str],
]:
    """Build a synthetic M0-style folder with dual-control done records.

    Returns (layout, alice_key, bob_key, alice_pub, bob_pub, list_of_request_ids).
    """
    ws_dir = tmp_path / "m0ws_dual"
    lay = _ws(ws_dir)
    alice_key = SigningKey.generate()
    bob_key = SigningKey.generate()
    alice_pub = bytes(alice_key.verify_key).hex()
    bob_pub = bytes(bob_key.verify_key).hex()

    # Place in-tree seeds (M0 location)
    _place_m0_seed(lay, "alice", alice_key)
    _place_m0_seed(lay, "bob", bob_key)

    # Create 2 dual-control done records signed M0-style
    rids: list[str] = []
    for i in range(2):
        rid = _submit(lay, command=f"echo m0-dual-{i}", requires_dual=True)
        rec = EscalationQueue(lay).claim(rid, "alice")
        assert rec is not None
        rec["decision"] = "approved"
        rec["reviewer_id"] = "alice"
        rec["state"] = "done"
        rec["decided_at"] = time.time() - 500 + i
        rec["requires_dual"] = True

        # Two M0-style approvals
        now = time.time()
        a_alice = _m0_sign_approval(rec, "alice", alice_key, now - 10)
        a_bob = _m0_sign_approval(rec, "bob", bob_key, now - 5)
        rec["approvals"] = [a_alice, a_bob]
        _m0_sign_record(rec, alice_key)
        EscalationQueue(lay).finish(rid, rec)
        rids.append(rid)

    return lay, alice_key, bob_key, alice_pub, bob_pub, rids


def _rotate_reviewer(layout: FolderLayout, reviewer_id: str) -> str:
    """Trigger rotation for a reviewer by calling ensure_signing_key.

    This will detect the in-tree seed, audit key_rotated with done_at_rotation,
    and create a new key in the key home.

    Returns the new public key hex.
    """
    from sandbox.connector.signing import ensure_signing_key
    return ensure_signing_key(layout, reviewer_id)


def _audit_events(layout: FolderLayout) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for f in layout.audit_dir.rglob("*.jsonl"):
        for line in f.read_text(encoding="utf-8").splitlines():
            if line.strip():
                out.append(json.loads(line))
    return out


# ===========================================================================
# GUARD -- passes today, must keep passing after the fix
# ===========================================================================


def test_guard_current_pinned_key_record_verifies(tmp_path, key_home):
    """(f) A record signed with the current pinned key passes verify_evidence
    today and must continue to pass after the fix."""
    lay = _ws(tmp_path / "ws")
    rid = _submit(lay)
    _approve_req(lay, rid, "alice")
    pack_dir = tmp_path / "pack"
    summary = export_evidence(lay, pack_dir)
    r = verify_evidence(pack_dir, summary.get("exporter_public_key"))
    assert r["ok"], f"current-key pack should verify: {r['failures']}"


# ===========================================================================
# RED tests -- all fail today (verify_evidence does not handle legacy)
# ===========================================================================


def test_rotated_m0_single_control_verifies(tmp_path, key_home):
    """(a) After rotation, an M0 folder's single-control records should pass
    verify_evidence and be labelled legacy."""
    lay, _old_key, old_pub, rids = _create_m0_folder_single(tmp_path)

    # Rotate
    _rotate_reviewer(lay, "cli")

    # Verify rotation happened
    events = _audit_events(lay)
    rot_events = [e for e in events if e.get("event") == "key_rotated"
                  and e.get("reviewer_id") == "cli"]
    assert rot_events, "no key_rotated event for cli"

    # Export and verify
    pack_dir = tmp_path / "pack"
    summary = export_evidence(lay, pack_dir)
    r = verify_evidence(pack_dir, summary.get("exporter_public_key"))
    _require(
        r["ok"],
        f"rotated M0 single-control pack should verify; "
        f"failures: {r['failures']}"
    )


def test_rotated_m0_single_labelled_legacy(tmp_path, key_home):
    """(a continued) Each legacy record in the pack result should be labelled
    with key_status='legacy' and the result should include a legacy count."""
    lay, _old_key, old_pub, rids = _create_m0_folder_single(tmp_path)
    _rotate_reviewer(lay, "cli")

    pack_dir = tmp_path / "pack"
    summary = export_evidence(lay, pack_dir)
    r = verify_evidence(pack_dir, summary.get("exporter_public_key"))
    _require(
        r["ok"],
        f"rotated M0 single-control pack should verify; "
        f"failures: {r['failures']}"
    )
    # The result should report per-record key_status or a legacy count.
    legacy_count = r.get("legacy_count", 0)
    decisions_detail = r.get("decisions_detail", [])
    # Accept either: a 'legacy_count' field, or per-record detail with key_status
    has_legacy_info = (
        legacy_count >= len(rids)
        or any(d.get("key_status") == "legacy" for d in decisions_detail)
    )
    _require(
        has_legacy_info,
        f"verify_evidence should report legacy records; "
        f"got legacy_count={legacy_count}, decisions_detail has "
        f"{len(decisions_detail)} entries"
    )


def test_rotated_m0_dual_control_verifies(tmp_path, key_home):
    """(a) After rotation, an M0 folder's dual-control records should pass
    verify_evidence -- both the signer_is_folder_key and dual_control checks."""
    lay, alice_key, bob_key, alice_pub, bob_pub, rids = _create_m0_folder_dual(
        tmp_path,
    )

    # Rotate both reviewers
    _rotate_reviewer(lay, "alice")
    _rotate_reviewer(lay, "bob")

    # Export and verify
    pack_dir = tmp_path / "pack"
    summary = export_evidence(lay, pack_dir)
    r = verify_evidence(pack_dir, summary.get("exporter_public_key"))
    _require(
        r["ok"],
        f"rotated M0 dual-control pack should verify; "
        f"failures: {r['failures']}"
    )


def test_rotated_m0_dual_control_labelled_legacy(tmp_path, key_home):
    """(a continued) Dual-control legacy records should carry legacy labels."""
    lay, alice_key, bob_key, alice_pub, bob_pub, rids = _create_m0_folder_dual(
        tmp_path,
    )
    _rotate_reviewer(lay, "alice")
    _rotate_reviewer(lay, "bob")

    pack_dir = tmp_path / "pack"
    summary = export_evidence(lay, pack_dir)
    r = verify_evidence(pack_dir, summary.get("exporter_public_key"))
    _require(
        r["ok"],
        f"rotated M0 dual-control pack should verify; "
        f"failures: {r['failures']}"
    )
    legacy_count = r.get("legacy_count", 0)
    decisions_detail = r.get("decisions_detail", [])
    has_legacy_info = (
        legacy_count >= len(rids)
        or any(d.get("key_status") == "legacy" for d in decisions_detail)
    )
    _require(
        has_legacy_info,
        f"verify_evidence should report dual-control legacy records; "
        f"got legacy_count={legacy_count}"
    )


def test_retired_key_missing_from_done_at_rotation_fails(tmp_path, key_home):
    """(b) A record signed by the retired key but whose request_id is NOT in
    done_at_rotation must fail verification.  GUARD: the current code already
    rejects all non-current-key records; after the fix this record should still
    fail (now for the specific reason: not in done_at_rotation)."""
    lay, old_key, old_pub, rids = _create_m0_folder_single(tmp_path)

    # Create one more done record AFTER the initial batch, but don't re-create
    # the rotation snapshot -- manually add a record after rotation.
    extra_rid = _submit(lay, command="echo extra-after-rotation")
    rec_extra = EscalationQueue(lay).claim(extra_rid, "cli")
    assert rec_extra is not None
    rec_extra["decision"] = "approved"
    rec_extra["reviewer_id"] = "cli"
    rec_extra["state"] = "done"
    rec_extra["decided_at"] = time.time()
    _m0_sign_record(rec_extra, old_key)
    EscalationQueue(lay).finish(extra_rid, rec_extra)

    # Now rotate -- this will snapshot the done dir which has all rids + extra_rid
    _rotate_reviewer(lay, "cli")

    # Tamper the rotation event to remove extra_rid from done_at_rotation
    events = _audit_events(lay)
    rot_events = [e for e in events if e.get("event") == "key_rotated"
                  and e.get("reviewer_id") == "cli"]
    assert rot_events, "need rotation event"
    rot = rot_events[-1]
    dar = rot.get("done_at_rotation", {})
    assert extra_rid in dar, "extra_rid should be in done_at_rotation"

    # Rewrite the audit chain to remove extra_rid from done_at_rotation.
    # We need to overwrite the chain file, removing just extra_rid.
    for f in lay.audit_dir.rglob("*.jsonl"):
        lines = f.read_text(encoding="utf-8").splitlines()
        new_lines: list[str] = []
        for line in lines:
            if not line.strip():
                new_lines.append(line)
                continue
            evt = json.loads(line)
            if (evt.get("event") == "key_rotated"
                    and evt.get("reviewer_id") == "cli"
                    and isinstance(evt.get("done_at_rotation"), dict)
                    and extra_rid in evt["done_at_rotation"]):
                # Remove the extra_rid from done_at_rotation
                evt["done_at_rotation"] = {
                    k: v for k, v in evt["done_at_rotation"].items()
                    if k != extra_rid
                }
                new_lines.append(json.dumps(evt, sort_keys=True, separators=(",", ":")))
            else:
                new_lines.append(line)
        f.write_text("\n".join(new_lines) + "\n", encoding="utf-8")

    # Export and verify -- the extra record should fail
    pack_dir = tmp_path / "pack"
    summary = export_evidence(lay, pack_dir)
    r = verify_evidence(pack_dir, summary.get("exporter_public_key"))
    # The pack should either fail entirely or at least not label this as verified
    assert not r["ok"], (
        f"a record NOT in done_at_rotation should fail verification; "
        f"ok={r['ok']}, failures={r['failures']}"
    )


def test_content_swapped_after_rotation_fails(tmp_path, key_home):
    """(c) A record whose content was changed after rotation (same request_id,
    new body, re-signed with the retired key) must fail verification.
    GUARD: the current code already rejects all non-current-key records;
    after the fix, the content hash mismatch in done_at_rotation catches it."""
    lay, old_key, old_pub, rids = _create_m0_folder_single(tmp_path)

    # Rotate
    _rotate_reviewer(lay, "cli")

    # Overwrite one done record with tampered content, re-signed with retired key
    target_rid = rids[0]
    tampered = {
        "request_id": target_rid,
        "command": "rm -rf /",  # attacker payload
        "kind": "command",
        "decision": "approved",
        "reviewer_id": "cli",
        "state": "done",
        "decided_at": time.time() - 2000,
        "exec_cwd": str(lay.root),
        "root": str(lay.root),
        "trigger": ["shell"],
    }
    _m0_sign_record(tampered, old_key)
    (lay.done_dir / f"{target_rid}.json").write_text(
        json.dumps(tampered, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )

    # Export and verify -- the tampered record should fail
    pack_dir = tmp_path / "pack"
    summary = export_evidence(lay, pack_dir)
    r = verify_evidence(pack_dir, summary.get("exporter_public_key"))
    assert not r["ok"], (
        f"content-swapped record should fail verification; "
        f"ok={r['ok']}, failures={r['failures']}"
    )


def test_unrotated_folder_fails_with_rotation_message(tmp_path, key_home):
    """(d) An un-rotated folder (no key_rotated for that reviewer) fails
    with a message that names the reviewer and contains 'rotat'.

    Setup: build an M0-style folder and export WITHOUT calling
    ensure_signing_key for the reviewer (export creates only the exporter
    key).  No audit-chain tampering needed -- the chain stays intact.
    """
    ws_dir = tmp_path / "m0ws_unrotated"
    lay = _ws(ws_dir)
    orphan_key = SigningKey.generate()

    # Create a done record signed by orphan_key as reviewer "alice"
    rid = _submit(lay, command="echo unrotated")
    rec = EscalationQueue(lay).claim(rid, "alice")
    assert rec is not None
    rec["decision"] = "approved"
    rec["reviewer_id"] = "alice"
    rec["state"] = "done"
    rec["decided_at"] = time.time()
    _m0_sign_record(rec, orphan_key)
    EscalationQueue(lay).finish(rid, rec)

    # Do NOT rotate alice -- no ensure_signing_key call.
    # Export creates only the exporter key; reviewer_public_key("alice")
    # returns None because no key exists in the key home.
    pack_dir = tmp_path / "pack_unrot"
    summary = export_evidence(lay, pack_dir)
    r = verify_evidence(pack_dir, summary.get("exporter_public_key"))
    assert not r["ok"], (
        f"un-rotated folder should fail verification; "
        f"ok={r['ok']}, failures={r['failures']}"
    )
    # The failure message should name the reviewer and mention rotation
    failure_text = " ".join(r.get("failures", []))
    assert "alice" in failure_text.lower() and "rotat" in failure_text.lower(), (
        f"failure message should name reviewer 'alice' and contain 'rotat'; "
        f"got: {r['failures']}"
    )


def test_exporter_claimed_legacy_for_uncovered_record_still_fails(tmp_path, key_home):
    """(e) Even if the exporter writes key_status='legacy' in the decisions
    index for a record NOT covered by done_at_rotation, the offline verifier
    must independently recompute and still fail.  GUARD: the current code
    already rejects all non-current-key records and does not read the decisions
    index for key_status."""
    lay, old_key, old_pub, rids = _create_m0_folder_single(tmp_path)

    # Create an extra record signed by old_key
    extra_rid = _submit(lay, command="echo fake-legacy")
    rec_extra = EscalationQueue(lay).claim(extra_rid, "cli")
    assert rec_extra is not None
    rec_extra["decision"] = "approved"
    rec_extra["reviewer_id"] = "cli"
    rec_extra["state"] = "done"
    rec_extra["decided_at"] = time.time()
    _m0_sign_record(rec_extra, old_key)
    EscalationQueue(lay).finish(extra_rid, rec_extra)

    # Rotate (this snapshots all done records INCLUDING extra_rid)
    _rotate_reviewer(lay, "cli")

    # Now tamper: remove extra_rid from the done_at_rotation in the audit.
    # The exporter would still label it "legacy" if it sees the retired key,
    # but the verifier should independently verify the chain.
    for f in lay.audit_dir.rglob("*.jsonl"):
        lines = f.read_text(encoding="utf-8").splitlines()
        new_lines: list[str] = []
        for line in lines:
            if not line.strip():
                new_lines.append(line)
                continue
            evt = json.loads(line)
            if (evt.get("event") == "key_rotated"
                    and evt.get("reviewer_id") == "cli"
                    and isinstance(evt.get("done_at_rotation"), dict)
                    and extra_rid in evt["done_at_rotation"]):
                evt["done_at_rotation"] = {
                    k: v for k, v in evt["done_at_rotation"].items()
                    if k != extra_rid
                }
                new_lines.append(json.dumps(evt, sort_keys=True, separators=(",", ":")))
            else:
                new_lines.append(line)
        f.write_text("\n".join(new_lines) + "\n", encoding="utf-8")

    # Now export.  The exporter's _key_status_for will see the retired key
    # and the missing done_at_rotation entry, so it might label it "unverifiable".
    # But even if the exporter claimed "legacy" in the decisions index, the
    # offline verifier should NOT trust that label.
    pack_dir = tmp_path / "pack_fake_legacy"
    summary = export_evidence(lay, pack_dir)

    # Tamper the decisions index: set key_status to "legacy" for extra_rid
    idx_path = pack_dir / "decisions" / "index.json"
    idx = json.loads(idx_path.read_text(encoding="utf-8"))
    for entry in idx:
        if entry.get("request_id") == extra_rid:
            entry["key_status"] = "legacy"
    idx_path.write_text(
        json.dumps(idx, sort_keys=True, indent=2) + "\n", encoding="utf-8",
    )

    # Re-verify -- the verifier should NOT trust the exporter's claim
    r = verify_evidence(pack_dir)
    assert not r["ok"], (
        f"verifier should not trust exporter-claimed legacy for uncovered "
        f"record; ok={r['ok']}, failures={r['failures']}"
    )


def test_rotated_m0_mixed_legacy_and_current(tmp_path, key_home):
    """A pack with both legacy M0 records and current (pinned-key) records
    should verify OK: legacy records pass as legacy, current records pass
    as pinned."""
    lay, old_key, old_pub, rids = _create_m0_folder_single(tmp_path)

    # Rotate (legacy records exist)
    _rotate_reviewer(lay, "cli")

    # Create a new record with the current (post-rotation) key
    new_rid = _submit(lay, command="echo current-key")
    _approve_req(lay, new_rid, "cli")

    # Export and verify
    pack_dir = tmp_path / "pack_mixed"
    summary = export_evidence(lay, pack_dir)
    r = verify_evidence(pack_dir, summary.get("exporter_public_key"))
    _require(
        r["ok"],
        f"mixed legacy+current pack should verify; "
        f"failures: {r['failures']}"
    )


# ===========================================================================
# T4c follow-up: task 1 -- dual control per approval
# Each approval counts only if strict-valid (sig_v 1, matching current key)
# or legacy-valid (_check_legacy_key).  Distinct reviewers required.
# ===========================================================================


def test_dual_legacy_plus_unpinned_new_fails(tmp_path, key_home):
    """T4c-f1a: one legacy approval (rotated) + one approval matching the
    folder's current key but without sig_v 1 -> fails dual control.
    The non-legacy approval is not strict-valid."""
    ws_dir = tmp_path / "m0ws_dual_unpinned"
    lay = _ws(ws_dir)
    alice_key = SigningKey.generate()
    bob_key = SigningKey.generate()

    _place_m0_seed(lay, "alice", alice_key)
    _place_m0_seed(lay, "bob", bob_key)

    # Dual-control done record signed M0-style
    rid = _submit(lay, command="echo dual-unpinned", requires_dual=True)
    rec = EscalationQueue(lay).claim(rid, "alice")
    assert rec is not None
    rec["decision"] = "approved"
    rec["reviewer_id"] = "alice"
    rec["state"] = "done"
    rec["decided_at"] = time.time() - 500
    rec["requires_dual"] = True

    now = time.time()
    a_alice = _m0_sign_approval(rec, "alice", alice_key, now - 10)
    a_bob = _m0_sign_approval(rec, "bob", bob_key, now - 5)
    rec["approvals"] = [a_alice, a_bob]
    _m0_sign_record(rec, alice_key)
    EscalationQueue(lay).finish(rid, rec)

    # Rotate alice only; bob stays unrotated.
    _rotate_reviewer(lay, "alice")

    # Place bob's M0 seed in the key home directly (not through rotation
    # or pinning).  reviewer_public_key("bob") returns bob's pub -> the
    # approval key matches, but there is no sig_v and no key_pinned event.
    from sandbox.connector import keyhome

    bob_kh_path = keyhome.workspace_key_dir(lay, create=True) / "bob.seed"
    bob_kh_path.write_bytes(bytes(bob_key))

    pack_dir = tmp_path / "pack_dual_unpinned"
    summary = export_evidence(lay, pack_dir)
    r = verify_evidence(pack_dir, summary.get("exporter_public_key"))

    assert not r["ok"], (
        f"legacy + unpinned new approval should fail dual control; "
        f"ok={r['ok']}, failures={r['failures']}"
    )
    dual_failures = [
        f for f in r.get("failures", [])
        if "dual_control" in f or "2 required" in f
    ]
    assert dual_failures, f"expected dual_control failure, got: {r['failures']}"


def test_dual_legacy_plus_strict_different_reviewer_passes(tmp_path, key_home):
    """T4c-f1b: one legacy approval + one strict approval (sig_v 1, matching
    current key) from a different reviewer -> passes dual control."""
    ws_dir = tmp_path / "m0ws_dual_strict"
    lay = _ws(ws_dir)
    alice_key = SigningKey.generate()

    _place_m0_seed(lay, "alice", alice_key)

    # Bob: create a proper M1 key (key home, no legacy seed -> no rotation).
    bob_pub = ensure_signing_key(lay, "bob")

    rid = _submit(lay, command="echo dual-strict", requires_dual=True)
    rec = EscalationQueue(lay).claim(rid, "alice")
    assert rec is not None
    rec["decision"] = "approved"
    rec["reviewer_id"] = "alice"
    rec["state"] = "done"
    rec["decided_at"] = time.time() - 500
    rec["requires_dual"] = True

    now = time.time()
    a_alice = _m0_sign_approval(rec, "alice", alice_key, now - 10)
    a_bob = sign_approval(lay, "bob", rec, now - 5)

    rec["approvals"] = [a_alice, a_bob]
    _m0_sign_record(rec, alice_key)
    EscalationQueue(lay).finish(rid, rec)

    # Rotate alice so her approval becomes legacy-valid.
    _rotate_reviewer(lay, "alice")

    pack_dir = tmp_path / "pack_dual_strict"
    summary = export_evidence(lay, pack_dir)
    r = verify_evidence(pack_dir, summary.get("exporter_public_key"))

    assert r["ok"], (
        f"legacy + strict approval from different reviewer should pass; "
        f"failures: {r['failures']}"
    )


def test_dual_two_legacy_same_reviewer_fails(tmp_path, key_home):
    """T4c-f1c: two legacy approvals from the same reviewer -> fails.
    Even if both pass _check_legacy_key, distinct reviewers are required."""
    ws_dir = tmp_path / "m0ws_dual_same"
    lay = _ws(ws_dir)
    alice_key = SigningKey.generate()

    _place_m0_seed(lay, "alice", alice_key)

    rid = _submit(lay, command="echo dual-same", requires_dual=True)
    rec = EscalationQueue(lay).claim(rid, "alice")
    assert rec is not None
    rec["decision"] = "approved"
    rec["reviewer_id"] = "alice"
    rec["state"] = "done"
    rec["decided_at"] = time.time() - 500
    rec["requires_dual"] = True

    now = time.time()
    a1 = _m0_sign_approval(rec, "alice", alice_key, now - 10)
    a2 = _m0_sign_approval(rec, "alice", alice_key, now - 5)
    rec["approvals"] = [a1, a2]
    _m0_sign_record(rec, alice_key)
    EscalationQueue(lay).finish(rid, rec)

    _rotate_reviewer(lay, "alice")

    pack_dir = tmp_path / "pack_dual_same"
    summary = export_evidence(lay, pack_dir)
    r = verify_evidence(pack_dir, summary.get("exporter_public_key"))

    assert not r["ok"], (
        f"two legacy approvals from same reviewer should fail; "
        f"ok={r['ok']}, failures={r['failures']}"
    )


# ===========================================================================
# T4c follow-up: task 2 -- export index uses the same legacy check
# Export and verify must agree on every record's status.
# ===========================================================================


def test_export_index_status_matches_verify_status(tmp_path, key_home):
    """T4c-f2: the export decisions index per-record ok must equal the
    verify_evidence per-record ok for every record in a legacy pack."""
    lay, old_key, old_pub, rids = _create_m0_folder_single(tmp_path)
    _rotate_reviewer(lay, "cli")

    pack_dir = tmp_path / "pack_status"
    summary = export_evidence(lay, pack_dir)

    idx_path = pack_dir / "decisions" / "index.json"
    export_index = json.loads(idx_path.read_text(encoding="utf-8"))

    r = verify_evidence(pack_dir, summary.get("exporter_public_key"))
    verify_by_rid = {d["request_id"]: d for d in r.get("decisions_detail", [])}

    for entry in export_index:
        rid = entry.get("request_id")
        assert rid in verify_by_rid, f"{rid} not in verify result"
        assert entry["ok"] == verify_by_rid[rid]["ok"], (
            f"export ok={entry['ok']} != verify ok={verify_by_rid[rid]['ok']} "
            f"for {rid}"
        )


# ===========================================================================
# T4c follow-up: task 3 -- shared canonical-hash helper
# signing._audit_rotation and evidence._canonical_record_hash must agree.
# ===========================================================================


def test_canonical_hash_rotation_byte_identical(tmp_path, key_home):
    """T4c-f3: the hash in done_at_rotation (written by signing._audit_rotation)
    must be byte-identical to evidence._canonical_record_hash applied to the
    same record.  An existing rotation record still verifies after the helper
    is shared."""
    lay, old_key, old_pub, rids = _create_m0_folder_single(tmp_path)
    _rotate_reviewer(lay, "cli")

    events = _audit_events(lay)
    rot = next(
        e for e in events
        if e.get("event") == "key_rotated" and e.get("reviewer_id") == "cli"
    )
    dar = rot["done_at_rotation"]

    from sandbox.connector.evidence import _canonical_record_hash

    for rid in rids:
        rec = json.loads(
            (lay.done_dir / f"{rid}.json").read_text(encoding="utf-8")
        )
        expected = _canonical_record_hash(rec)
        assert rid in dar, f"{rid} not in done_at_rotation"
        assert dar[rid] == expected, (
            f"hash mismatch for {rid}: done_at_rotation={dar[rid]}, "
            f"_canonical_record_hash={expected}"
        )

    # The pack must still verify after sharing the helper.
    pack_dir = tmp_path / "pack_hash"
    summary = export_evidence(lay, pack_dir)
    r = verify_evidence(pack_dir, summary.get("exporter_public_key"))
    assert r["ok"], f"pack should still verify: {r['failures']}"


# ===========================================================================
# T4c follow-up: security review -- not_covered path coverage
# ===========================================================================


def test_post_rotation_record_not_covered_fails(tmp_path, key_home):
    """A done-record created AFTER rotation and signed with the saved old
    key is absent from done_at_rotation.  The audit chain stays intact (no
    tampering), so the failure must come from _check_legacy_key returning
    'not_covered', not from a chain break."""
    lay, old_key, old_pub, rids = _create_m0_folder_single(tmp_path)

    # Rotate -- snapshots only the 3 pre-existing done records.
    _rotate_reviewer(lay, "cli")

    # Verify the chain is intact before we add the new record.
    events = _audit_events(lay)
    rot_events = [
        e for e in events
        if e.get("event") == "key_rotated" and e.get("reviewer_id") == "cli"
    ]
    assert rot_events, "need key_rotated event"

    # Create a NEW done-record signed with the OLD (retired) key.
    # Its request_id will NOT be in done_at_rotation.
    post_rid = _submit(lay, command="echo post-rotation")
    rec = EscalationQueue(lay).claim(post_rid, "cli")
    assert rec is not None
    rec["decision"] = "approved"
    rec["reviewer_id"] = "cli"
    rec["state"] = "done"
    rec["decided_at"] = time.time()
    _m0_sign_record(rec, old_key)
    EscalationQueue(lay).finish(post_rid, rec)

    # Export and verify -- chain is intact, but the new record is not covered.
    pack_dir = tmp_path / "pack_not_covered"
    summary = export_evidence(lay, pack_dir)
    r = verify_evidence(pack_dir, summary.get("exporter_public_key"))

    assert not r["ok"], (
        f"post-rotation record should fail verification; "
        f"ok={r['ok']}, failures={r['failures']}"
    )
    # The failure must mention 'not_covered' or 'not in done_at_rotation',
    # NOT a chain break.
    failure_text = " ".join(r.get("failures", []))
    assert "not in done_at_rotation" in failure_text or "not_covered" in failure_text, (
        f"failure should be about not_covered, not a chain break; "
        f"got: {r['failures']}"
    )
    # Confirm no audit chain failures.
    chain_failures = [
        f for f in r.get("failures", []) if "audit chain" in f.lower()
    ]
    assert not chain_failures, (
        f"chain should be intact; got chain failures: {chain_failures}"
    )
