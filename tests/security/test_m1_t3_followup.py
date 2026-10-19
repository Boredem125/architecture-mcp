"""M1 T3 follow-up: fail-closed pin audit and keys.enrol: explicit.

Task 1: _pin_and_audit must write the key_pinned audit record BEFORE writing
the pin. If the audit cannot be written, the approval is refused (KeyHomeError
propagates) and no pin file entry exists.

Task 2 (ADR 0007 section 2.4): when ``keys.enrol`` is ``"explicit"`` in the
folder policy, a reviewer id that is not already pinned (enrolled) must not be
pinned and its approval must be refused. Already-pinned reviewers proceed as
normal. Default behaviour (``"first_use"``) is unchanged.
"""
from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from sandbox.connector.approval import approve
from sandbox.connector.install import init
from sandbox.connector.layout import FolderLayout
from sandbox.connector.policy import load_policy, save_policy
from sandbox.connector.queue import EscalationQueue


def _ws(path: Path) -> FolderLayout:
    path.mkdir(parents=True, exist_ok=True)
    init(path, claude=False, mcp=False)
    return FolderLayout(path)


def _submit(layout: FolderLayout, command: str = "echo t3f", **extra) -> str:
    return EscalationQueue(layout).submit({
        "kind": "command", "command": command, "exec_cwd": str(layout.root),
        "root": str(layout.root), "trigger": ["shell"], **extra,
    })


def _approve_req(layout: FolderLayout, rid: str, reviewer: str, reason: str = "t3f test") -> dict[str, Any]:
    return asyncio.run(approve(layout, rid, reviewer, reason))


def _read_pins(layout: FolderLayout) -> dict[str, Any]:
    from sandbox.connector import keyhome
    try:
        wsdir = keyhome.workspace_key_dir(layout, create=False)
    except keyhome.KeyHomeError:
        return {}
    p = wsdir / "pins.json"
    if not p.exists():
        return {}
    return json.loads(p.read_text(encoding="utf-8"))


@pytest.fixture
def key_home(tmp_path, monkeypatch):
    kh = tmp_path / "keyhome"
    monkeypatch.setenv("SANDBOX_KEY_HOME", str(kh))
    return kh


# ===========================================================================
#  Task 1: fail-closed pin audit
# ===========================================================================


def test_audit_failure_refuses_approval_and_leaves_no_pin(tmp_path, key_home):
    """When FolderAudit.append raises, approve() must refuse and no pin must exist."""
    lay = _ws(tmp_path / "ws")
    rid = _submit(lay)
    with patch("sandbox.connector.audit.FolderAudit.append", side_effect=OSError("disk full")):
        res = _approve_req(lay, rid, "alice")
    assert res["status"] == "key_unavailable", f"expected refusal, got {res}"
    pins = _read_pins(lay)
    assert "alice" not in pins, f"pin was written despite audit failure: {pins}"


def test_audit_dir_unwritable_refuses_approval(tmp_path, key_home):
    """If the audit directory is unwritable the approval is refused and no pin exists."""
    lay = _ws(tmp_path / "ws")
    rid = _submit(lay)
    # Make the audit dir read-only (best effort on Windows)
    lay.audit_dir.mkdir(parents=True, exist_ok=True)
    sentinel = lay.audit_dir / "_guard"
    sentinel.write_text("x", encoding="utf-8")

    def _broken_append(self, record):
        raise OSError("permission denied")

    with patch("sandbox.connector.audit.FolderAudit.append", _broken_append):
        res = _approve_req(lay, rid, "bob")
    assert res["status"] == "key_unavailable", f"expected refusal, got {res}"
    pins = _read_pins(lay)
    assert "bob" not in pins, f"pin was written despite audit dir being unwritable: {pins}"


def test_pin_written_after_audit_succeeds(tmp_path, key_home):
    """Normal path: audit succeeds, then pin is written, then approval proceeds."""
    lay = _ws(tmp_path / "ws")
    rid = _submit(lay)
    res = _approve_req(lay, rid, "carol")
    assert res["status"] == "executed"
    pins = _read_pins(lay)
    assert "carol" in pins, "pin was not written after successful audit"
    # Verify audit has key_pinned event
    events = []
    for f in lay.audit_dir.rglob("*.jsonl"):
        for line in f.read_text(encoding="utf-8").splitlines():
            if line.strip():
                events.append(json.loads(line))
    assert any(e.get("event") == "key_pinned" and e.get("reviewer_id") == "carol" for e in events)


# ===========================================================================
#  Task 2: keys.enrol: explicit (ADR 0007 section 2.4)
# ===========================================================================


def test_explicit_enrol_refuses_unenrolled_reviewer(tmp_path, key_home):
    """With keys.enrol: explicit, a reviewer not already pinned is refused."""
    lay = _ws(tmp_path / "ws")
    policy = load_policy(lay.policy_file)
    policy.keys.enrol = "explicit"
    save_policy(policy, lay.policy_file)
    rid = _submit(lay)
    res = _approve_req(lay, rid, "new_reviewer")
    assert res["status"] == "not_enrolled", f"expected not_enrolled, got {res}"
    assert "not enrolled" in res.get("reason", "").lower()
    pins = _read_pins(lay)
    assert "new_reviewer" not in pins, f"unenrolled reviewer was pinned: {pins}"


def test_explicit_enrol_allows_already_pinned_reviewer(tmp_path, key_home):
    """With keys.enrol: explicit, an already-pinned reviewer can approve."""
    lay = _ws(tmp_path / "ws")
    # First, pin alice under the default policy (first_use)
    rid1 = _submit(lay)
    res1 = _approve_req(lay, rid1, "alice")
    assert res1["status"] == "executed"
    pins = _read_pins(lay)
    assert "alice" in pins, "alice should be pinned"
    # Now set keys.enrol: explicit
    policy = load_policy(lay.policy_file)
    policy.keys.enrol = "explicit"
    save_policy(policy, lay.policy_file)
    # alice (already pinned) should still be able to approve
    rid2 = _submit(lay)
    res2 = _approve_req(lay, rid2, "alice")
    assert res2["status"] == "executed", f"already-pinned reviewer was refused: {res2}"


def test_default_enrol_behaviour_unchanged(tmp_path, key_home):
    """Default keys.enrol (first_use) still allows pin-on-first-use."""
    lay = _ws(tmp_path / "ws")
    policy = load_policy(lay.policy_file)
    assert policy.keys.enrol == "first_use", "default should be first_use"
    rid = _submit(lay)
    res = _approve_req(lay, rid, "new_reviewer")
    assert res["status"] == "executed", f"first_use should allow new reviewers: {res}"
    pins = _read_pins(lay)
    assert "new_reviewer" in pins, "reviewer should be pinned on first use"


def test_explicit_enrol_no_pin_created_for_refused_reviewer(tmp_path, key_home):
    """With keys.enrol: explicit, no pin file entry should be created when the reviewer is refused."""
    lay = _ws(tmp_path / "ws")
    policy = load_policy(lay.policy_file)
    policy.keys.enrol = "explicit"
    save_policy(policy, lay.policy_file)
    rid = _submit(lay)
    _approve_req(lay, rid, "unenrolled")
    pins = _read_pins(lay)
    assert "unenrolled" not in pins, f"pin created for unenrolled reviewer under explicit: {pins}"


def test_explicit_enrol_tighten_only_in_meet(tmp_path, key_home):
    """Setting keys.enrol to explicit is tightening; reverting is loosening."""
    from sandbox.connector.policy_versions import meet, only_tightens

    base = {"keys": {"enrol": "first_use"}, "version": 1, "mode": "enforce"}
    tight = {"keys": {"enrol": "explicit"}, "version": 1, "mode": "enforce"}
    # first_use -> explicit is tightening
    assert only_tightens(base, tight), "explicit should be a tightening of first_use"
    # explicit -> first_use is loosening
    assert not only_tightens(tight, base), "first_use should NOT be a tightening of explicit"


def test_explicit_to_first_use_detected_as_loosening(tmp_path, key_home):
    """loosened_fields reports keys.enrol when switching explicit -> first_use."""
    from sandbox.connector.policy_versions import loosened_fields

    old = {"keys": {"enrol": "explicit"}, "version": 1, "mode": "enforce"}
    new = {"keys": {"enrol": "first_use"}, "version": 1, "mode": "enforce"}
    loose = loosened_fields(old, new)
    assert any("keys.enrol" in f for f in loose), f"keys.enrol not in loosened_fields: {loose}"


# ===========================================================================
#  Task 3: _pin_and_audit is the single enforcement point (signing.py)
# ===========================================================================


def test_sign_approval_refuses_unenrolled_under_explicit(tmp_path, key_home):
    """sign_approval (the path used by policy_versions) raises NotEnrolledError
    when keys.enrol is explicit and the reviewer is not pinned."""
    from sandbox.connector.keyhome import NotEnrolledError
    from sandbox.connector.signing import sign_approval

    lay = _ws(tmp_path / "ws")
    policy = load_policy(lay.policy_file)
    policy.keys.enrol = "explicit"
    save_policy(policy, lay.policy_file)
    with pytest.raises(NotEnrolledError):
        sign_approval(lay, "unpinned_reviewer", {"request_id": "test"}, 1.0)
    pins = _read_pins(lay)
    assert "unpinned_reviewer" not in pins, "unpinned reviewer was pinned by sign_approval"


def test_propose_refuses_unenrolled_under_explicit(tmp_path, key_home):
    """An unpinned proposer cannot create a policy change under explicit enrol."""
    from sandbox.connector.keyhome import NotEnrolledError
    from sandbox.connector.policy_versions import baseline, propose, FOLDER

    lay = _ws(tmp_path / "ws")
    # Pin alice under first_use so she can baseline
    rid = _submit(lay)
    res = _approve_req(lay, rid, "alice")
    assert res["status"] == "executed"
    baseline(lay, "alice", "initial baseline")
    # Switch to explicit
    policy = load_policy(lay.policy_file)
    policy.keys.enrol = "explicit"
    save_policy(policy, lay.policy_file)
    # An unpinned proposer is refused
    new_content = load_policy(lay.policy_file).model_dump()
    new_content["triggers"]["shell"] = "deny"
    with pytest.raises(NotEnrolledError):
        propose(lay, FOLDER, new_content, "unenrolled_proposer", "testing")
    pins = _read_pins(lay)
    assert "unenrolled_proposer" not in pins


def test_approve_change_refuses_unenrolled_reviewer_under_explicit(tmp_path, key_home):
    """An unpinned reviewer cannot approve a policy change under explicit enrol."""
    from sandbox.connector.policy_versions import approve_change, baseline, propose, FOLDER

    lay = _ws(tmp_path / "ws")
    # Pin alice under first_use
    rid = _submit(lay)
    res = _approve_req(lay, rid, "alice")
    assert res["status"] == "executed"
    baseline(lay, "alice", "initial baseline")
    # alice proposes a tightening change (she is pinned)
    new_content = load_policy(lay.policy_file).model_dump()
    new_content["triggers"]["shell"] = "deny"
    change = propose(lay, FOLDER, new_content, "alice", "tighten shell")
    # Switch to explicit
    policy = load_policy(lay.policy_file)
    policy.keys.enrol = "explicit"
    save_policy(policy, lay.policy_file)
    # An unpinned reviewer cannot approve
    result = approve_change(lay, change["change_id"], "unenrolled_reviewer", "try to approve")
    assert result["status"] == "not_enrolled", f"expected not_enrolled, got {result}"
    pins = _read_pins(lay)
    assert "unenrolled_reviewer" not in pins
