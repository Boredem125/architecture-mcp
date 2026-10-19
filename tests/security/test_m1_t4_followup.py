"""M1 T4 follow-up: done_at_rotation content-hash integrity (orchestrator ruling 19 Oct 2026).

done_at_rotation in key_rotated is {request_id: sha256_hex_of_canonical_json}.
_key_status_for returns "legacy" only when the id is present AND the current
record's canonical hash matches.  Three cases:

(a) Content swap under an existing request_id after rotation, re-signed with
    the retired key -> unverifiable.
(b) Unchanged pre-rotation record -> legacy.
(c) key_rotated event without done_at_rotation -> unverifiable (fail closed).
"""
from __future__ import annotations

import hashlib
import json
import time
from typing import Any

import pytest
from nacl.signing import SigningKey

from sandbox.connector.evidence import _key_status_for, export_evidence
from sandbox.connector.install import init
from sandbox.connector.layout import FolderLayout
from sandbox.connector.queue import EscalationQueue
from sandbox.connector.signing import (
    _SIGNED_FIELDS,
    _canonical,
    _load_or_create_key,
    sign_record,
    verify_record,
)
from sandbox.crypto.signing import sign_message


def _ws(path):
    path.mkdir(parents=True, exist_ok=True)
    init(path, claude=False, mcp=False)
    return FolderLayout(path)


def _submit(layout, command="echo followup", **extra):
    return EscalationQueue(layout).submit({
        "kind": "command", "command": command, "exec_cwd": str(layout.root),
        "root": str(layout.root), "trigger": ["shell"], **extra,
    })


def _audit_events(layout):
    out = []
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


def _setup_rotation(tmp_path, key_home):
    """Set up a workspace with a legacy key, create a done record, then rotate.

    Returns (layout, old_key, old_pub, rid_pre, rotation_events).
    """
    lay = _ws(tmp_path / "ws")
    old_key = SigningKey.generate()
    seed_path = lay.state_dir / "keys" / "cli.seed"
    seed_path.parent.mkdir(parents=True, exist_ok=True)
    seed_path.write_bytes(bytes(old_key))
    old_pub = bytes(old_key.verify_key).hex()

    # Create a done record BEFORE rotation
    rid_pre = _submit(lay, command="echo pre-rotation")
    rec_pre = EscalationQueue(lay).claim(rid_pre, "cli")
    assert rec_pre is not None
    rec_pre["decision"] = "approved"
    rec_pre["reviewer_id"] = "cli"
    rec_pre["state"] = "done"
    rec_pre["decided_at"] = time.time()
    rec_pre["signer_public_key"] = old_pub
    rec_pre["signed_fields"] = list(_SIGNED_FIELDS)
    rec_pre["signature"] = sign_message(_canonical(rec_pre), old_key)
    EscalationQueue(lay).finish(rid_pre, rec_pre)

    # Trigger rotation by using the new key home key
    from sandbox.connector.approval import approve
    import asyncio
    rid_rot = _submit(lay, command="echo trigger-rotation")
    asyncio.run(approve(lay, rid_rot, "cli", "rotate"))

    events = _audit_events(lay)
    rot_events = [e for e in events if e.get("event") == "key_rotated"]
    assert rot_events, "no key_rotated event"

    return lay, old_key, old_pub, rid_pre, rot_events


def test_content_swap_after_rotation_unverifiable(tmp_path, key_home):
    """(a) A done record whose request_id existed at rotation but whose content
    was swapped and re-signed with the retired key must be 'unverifiable'."""
    lay, old_key, old_pub, rid_pre, rot_events = _setup_rotation(tmp_path, key_home)

    # Swap the content of the pre-rotation done record (re-sign with retired key)
    swapped = {
        "request_id": rid_pre,
        "command": "rm -rf /",  # attacker's payload
        "decision": "approved",
        "reviewer_id": "cli",
        "state": "done",
        "decided_at": time.time() - 1000,  # backdate
        "signer_public_key": old_pub,
        "signed_fields": list(_SIGNED_FIELDS),
    }
    swapped["signature"] = sign_message(_canonical(swapped), old_key)
    assert verify_record(swapped), "swapped record should still crypto-verify"

    # Overwrite the done file
    (lay.done_dir / f"{rid_pre}.json").write_text(
        json.dumps(swapped, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )

    # Check key_status
    all_audit = _audit_events(lay)
    status = _key_status_for(swapped, lay, all_audit)
    assert status == "unverifiable", (
        f"content-swapped record should be 'unverifiable', got '{status}'"
    )


def test_unchanged_pre_rotation_record_legacy(tmp_path, key_home):
    """(b) An unchanged pre-rotation record must be labelled 'legacy'."""
    lay, old_key, old_pub, rid_pre, rot_events = _setup_rotation(tmp_path, key_home)

    # Read the done record as-is (unchanged since before rotation)
    rec = json.loads(
        (lay.done_dir / f"{rid_pre}.json").read_text(encoding="utf-8")
    )

    all_audit = _audit_events(lay)
    status = _key_status_for(rec, lay, all_audit)
    assert status == "legacy", (
        f"unchanged pre-rotation record should be 'legacy', got '{status}'"
    )


def test_key_rotated_without_done_at_rotation_unverifiable(tmp_path, key_home):
    """(c) A key_rotated event missing done_at_rotation (or with the old list
    form) must make all retired-key records 'unverifiable' (fail closed)."""
    lay = _ws(tmp_path / "ws2")
    old_key = SigningKey.generate()
    old_pub = bytes(old_key.verify_key).hex()

    # Create a done record signed with old_key
    rid = _submit(lay, command="echo no-dar")
    rec = EscalationQueue(lay).claim(rid, "cli")
    assert rec is not None
    rec["decision"] = "approved"
    rec["reviewer_id"] = "cli"
    rec["state"] = "done"
    rec["decided_at"] = time.time()
    rec["signer_public_key"] = old_pub
    rec["signed_fields"] = list(_SIGNED_FIELDS)
    rec["signature"] = sign_message(_canonical(rec), old_key)
    EscalationQueue(lay).finish(rid, rec)

    # Re-read the done record (finish may have re-signed it)
    rec = json.loads(
        (lay.done_dir / f"{rid}.json").read_text(encoding="utf-8")
    )

    # Manually craft a key_rotated event WITHOUT done_at_rotation
    fake_rotation = {
        "event": "key_rotated",
        "ts": time.time(),
        "reviewer_id": "cli",
        "retired_public_key": old_pub,
        "new_public_key": "deadbeef" * 8,
    }
    # Also test the old list form
    fake_rotation_list = dict(fake_rotation)
    fake_rotation_list["done_at_rotation"] = [rid]  # old list form

    for label, rot_event in [("missing", fake_rotation),
                             ("list_form", fake_rotation_list)]:
        status = _key_status_for(rec, lay, [rot_event])
        assert status == "unverifiable", (
            f"key_rotated with {label} done_at_rotation should yield "
            f"'unverifiable', got '{status}'"
        )
