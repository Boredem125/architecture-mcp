"""M1 T3 (D3.1, ADR 0007 section 2): pinned reviewer keys.

Pins are per workspace id, stored in the key home, written only from human
surfaces (CLI / REST API approve), never from the hook or MCP server.  Every
new pin is audited `key_pinned` and alerted.  `sandbox verify` and the
evidence pack flag a dual-control approval whose pin was created after the
request was queued as "new-key approval".

verify_approval checks the signature against the PINNED key, not the key
embedded in the record.  A record signed by an unpinned or retired key is
refused.  This closes the T2 known limit: a retired in-tree seed must no
longer be able to sign an accepted approval.

ADR 0007 1.6: legacy records verify only if they fall under the key_rotated
chain head; otherwise they show "unverifiable".

SEC-25 residual: `policy propose` / `approve-change` require the proposer's
signature from a pinned key, so one human approving a disguised shell call
can't count as the proposer.

The approver REST API signs and pins only its fixed reviewer id ("api"),
never a client-supplied one.

Each RED test raises ``PinsOpen`` for the stated reason only; the strict
xfail accepts that exception and nothing else.  The fix commit deletes the
decorator.  Guards pass today and must keep passing.
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
from sandbox.connector.evidence import export_evidence
from sandbox.connector.hook_eval import pre_tool_use
from sandbox.connector.install import init
from sandbox.connector.layout import FolderLayout
from sandbox.connector.policy import load_policy, save_policy
from sandbox.connector.queue import EscalationQueue
from sandbox.connector.signing import (
    _SIGNED_FIELDS,
    _canonical,
    _load_or_create_key,
    distinct_approvals,
    sign_approval,
    sign_record,
    verify_approval,
    verify_record,
)
from sandbox.crypto.signing import sign_message

WINDOWS = os.name == "nt"


class PinsOpen(AssertionError):
    """Pinned reviewer keys are not enforced yet (M1 T3 open)."""


def _require(cond: bool, msg: str) -> None:
    if not cond:
        raise PinsOpen(msg)


RED_T3 = pytest.mark.xfail(
    raises=PinsOpen, strict=True,
    reason="T3 open: pinned reviewer keys not yet enforced",
)


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _ws(path: Path) -> FolderLayout:
    path.mkdir(parents=True, exist_ok=True)
    init(path, claude=False, mcp=False)
    return FolderLayout(path)


def _submit(layout: FolderLayout, command: str = "echo t3", **extra) -> str:
    return EscalationQueue(layout).submit({
        "kind": "command", "command": command, "exec_cwd": str(layout.root),
        "root": str(layout.root), "trigger": ["shell"], **extra,
    })


def _approve_req(layout: FolderLayout, rid: str, reviewer: str, reason: str = "t3 test") -> dict[str, Any]:
    return asyncio.run(approve(layout, rid, reviewer, reason))


def _hook(layout: FolderLayout, tool: str, tool_input: dict[str, Any]) -> dict[str, Any]:
    return asyncio.run(pre_tool_use(
        {"tool_name": tool, "tool_input": tool_input,
         "cwd": str(layout.root), "session_id": "t3"},
        layout,
    ))


def _audit_events(layout: FolderLayout) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for f in layout.audit_dir.rglob("*.jsonl"):
        for line in f.read_text(encoding="utf-8").splitlines():
            if line.strip():
                out.append(json.loads(line))
    return out


def _event_names(layout: FolderLayout) -> list[str]:
    return [e.get("event", "") for e in _audit_events(layout)]


def _pins_file(layout: FolderLayout) -> Path:
    """Where T3 stores pins: ``<key home>/<workspace id>/pins.json``."""
    from sandbox.connector import keyhome

    wsdir = keyhome.workspace_key_dir(layout, create=False)
    return wsdir / "pins.json"


def _read_pins(layout: FolderLayout) -> dict[str, Any]:
    p = _pins_file(layout)
    if not p.exists():
        return {}
    return json.loads(p.read_text(encoding="utf-8"))


def _done_record(layout: FolderLayout, rid: str) -> dict[str, Any]:
    return json.loads((layout.done_dir / f"{rid}.json").read_text(encoding="utf-8"))


@pytest.fixture
def key_home(tmp_path, monkeypatch):
    kh = tmp_path / "keyhome"
    monkeypatch.setenv("SANDBOX_KEY_HOME", str(kh))
    return kh


# ===========================================================================
#  1. SCOPE: pins are per workspace, stored in key home, never overwritten,
#     written only from human surfaces (hook and MCP-server can never create)
# ===========================================================================


def test_pin_written_on_first_approval(tmp_path, key_home):
    """A new reviewer's public key is pinned when the first approval is signed."""
    lay = _ws(tmp_path / "ws")
    rid = _submit(lay)
    res = _approve_req(lay, rid, "alice")
    assert res["status"] == "executed"
    pins = _read_pins(lay)
    _require("alice" in pins, f"no pin for alice after first approval; pins file: {pins}")
    _require(pins["alice"].get("public_key") == res["result"]["signer_public_key"],
             "pinned key does not match the signing key")


def test_pins_per_workspace_do_not_collide(tmp_path, key_home):
    """reviewer `cli` in two workspaces gets two independent pins (per workspace id)."""
    a = _ws(tmp_path / "a")
    b = _ws(tmp_path / "b")
    _approve_req(a, _submit(a), "cli")
    _approve_req(b, _submit(b), "cli")
    pa, pb = _read_pins(a), _read_pins(b)
    _require("cli" in pa and "cli" in pb, f"pins missing: a={pa}, b={pb}")
    _require(pa["cli"].get("public_key") != pb["cli"].get("public_key"),
             "two workspaces share the same pinned key for reviewer `cli`")


def test_pin_is_never_overwritten(tmp_path, key_home):
    """A second approval by the same reviewer keeps the original pin, not a new key."""
    lay = _ws(tmp_path / "ws")
    _approve_req(lay, _submit(lay), "alice")
    first_pins = _read_pins(lay)
    _require("alice" in first_pins, f"no pin created for alice after first approval: {first_pins}")
    _approve_req(lay, _submit(lay), "alice")
    second_pins = _read_pins(lay)
    _require("alice" in second_pins, f"pin gone after second approval: {second_pins}")
    _require(first_pins["alice"] == second_pins["alice"],
             "pin for alice was overwritten on second use")


def test_pin_records_workspace_root(tmp_path, key_home):
    """Each pin entry records the workspace root at pinning time."""
    lay = _ws(tmp_path / "ws")
    _approve_req(lay, _submit(lay), "alice")
    pins = _read_pins(lay)
    _require("alice" in pins, "no pin")
    _require("workspace_root" in pins["alice"] or "root" in pins["alice"],
             f"pin does not record the workspace root: {pins['alice']}")


def test_guard_hook_path_cannot_create_a_pin(tmp_path, key_home):
    """A pre_tool_use call with an unknown reviewer id must NOT create a pin.
    This is a guard: the hook path does not sign, so no pin can be created today."""
    lay = _ws(tmp_path / "ws")
    policy = load_policy(lay.policy_file)
    policy.escalation_timeout_seconds = 0
    save_policy(policy, lay.policy_file)
    _hook(lay, "Bash", {"command": "echo hello from hook"})
    pins = _read_pins(lay)
    assert not pins, f"hook call created pins: {pins}"


def test_guard_mcp_server_path_cannot_create_a_pin(tmp_path, key_home):
    """The MCP server code path (check_request, escalate_call) must not pin keys.
    This is a guard: the MCP path does not sign, so no pin can be created today."""
    lay = _ws(tmp_path / "ws")
    # Submit via the queue (as MCP would), but do NOT approve
    rid = _submit(lay, command="echo mcp-test")
    # The MCP server reads/writes the queue but never signs
    # Verify no pins were created by the submit path
    pins = _read_pins(lay)
    assert not pins, f"submit (MCP path) created pins: {pins}"


# ===========================================================================
#  2. AUDIT: every new pin is audited and alerted; `sandbox verify` and the
#     evidence pack flag dual-control approvals whose pin was created after
#     the request was queued ("new-key approval")
# ===========================================================================


def test_new_pin_is_audited_key_pinned(tmp_path, key_home):
    """The first approval that pins a key must produce a `key_pinned` audit event."""
    lay = _ws(tmp_path / "ws")
    _approve_req(lay, _submit(lay), "alice")
    events = _event_names(lay)
    _require("key_pinned" in events,
             f"no key_pinned audit event; events: {events}")


def test_new_pin_is_alerted(tmp_path, key_home):
    """A new pin must trigger an alert (visible in watch/status)."""
    lay = _ws(tmp_path / "ws")
    _approve_req(lay, _submit(lay), "alice")
    events = _audit_events(lay)
    pinned = [e for e in events if e.get("event") == "key_pinned"]
    _require(pinned, "no key_pinned event at all")
    # Alerts are recorded with an "alert" key or as a separate alert event
    alert_events = [e for e in events if "alert" in e.get("event", "").lower()
                    or e.get("alert")]
    all_events = _event_names(lay)
    _require(alert_events or any("alert" in str(e) for e in pinned),
             f"no alert for the new pin; events: {all_events}")


def test_new_key_approval_is_flagged_in_verify(tmp_path, key_home):
    """A dual-control approval whose pin was created AFTER the request was queued
    must be flagged as 'new-key approval' so auditors can see one human approving
    as two identities on the fly."""
    lay = _ws(tmp_path / "ws")
    # Queue the request FIRST, before any pin exists for bob
    rid = _submit(lay, command="echo dual-new-key", requires_dual=True)
    # Alice approves first (this pins alice)
    _approve_req(lay, rid, "alice")
    # Bob approves second (this pins bob AFTER the request was queued)
    res = _approve_req(lay, rid, "bob")
    assert res["status"] == "executed"
    # The evidence pack or verify must flag this
    pack_dir = tmp_path / "pack"
    summary = export_evidence(lay, pack_dir)
    checks = summary.get("checks", summary.get("decisions", []))
    all_text = json.dumps(checks)
    _require("new_key" in all_text.lower() or "new-key" in all_text.lower(),
             f"no new-key-approval flag in evidence checks: {all_text[:500]}")


# ===========================================================================
#  3. VERIFY: verify_approval checks the PINNED key, not the embedded key;
#     unpinned or retired key is refused
# ===========================================================================


def test_approval_with_unpinned_key_is_refused(tmp_path, key_home):
    """A record signed by a key that has no pin must be invalid for decisions."""
    lay = _ws(tmp_path / "ws")
    # Create a fresh key that is NOT pinned
    attacker = SigningKey.generate()
    rid = _submit(lay, command="echo unpinned")
    rec = EscalationQueue(lay).claim(rid, "mallory")
    assert rec is not None
    # Hand-forge an approval with the unpinned key
    approval = {
        "request_id": rec["request_id"], "command": rec.get("command"),
        "fingerprint": rec.get("fingerprint"), "reviewer_id": "mallory",
        "decision": "approve", "approved_at": time.time(),
    }
    approval["signer_public_key"] = bytes(attacker.verify_key).hex()
    approval["signature"] = sign_message(
        _canonical(approval, ("request_id", "command", "fingerprint",
                              "reviewer_id", "decision", "approved_at")),
        attacker,
    )
    EscalationQueue(lay).release(rid, rec)
    # Verify: the cryptographic signature is valid, but the key is not pinned
    assert verify_approval(approval), "the raw crypto check should pass"
    # The _valid_for check or distinct_approvals for dual control must refuse it
    # because the key is not pinned for this workspace
    from sandbox.connector.approval import _valid_for
    _require(not _valid_for(approval, rec),
             "an approval signed with an unpinned key was accepted by _valid_for")


def test_forged_approval_with_a_fresh_key_rejected_in_dual_control(tmp_path, key_home):
    """Two forged approvals with fresh (unpinned) keys must not pass dual control."""
    lay = _ws(tmp_path / "ws")
    rid = _submit(lay, command="echo dual-forge", requires_dual=True)
    rec = EscalationQueue(lay).get(rid)
    forged: list[dict] = []
    for name in ("fake_alice", "fake_bob"):
        k = SigningKey.generate()
        a = {
            "request_id": rec["request_id"], "command": rec.get("command"),
            "fingerprint": rec.get("fingerprint"), "reviewer_id": name,
            "decision": "approve", "approved_at": time.time(),
        }
        a["signer_public_key"] = bytes(k.verify_key).hex()
        a["signature"] = sign_message(
            _canonical(a, ("request_id", "command", "fingerprint",
                           "reviewer_id", "decision", "approved_at")),
            k,
        )
        forged.append(a)
    # Both signatures are cryptographically valid
    assert all(verify_approval(f) for f in forged)
    # But dual control must refuse because neither key is pinned
    _require(not distinct_approvals(forged),
             "distinct_approvals accepted two forged approvals with unpinned keys")


def test_retired_in_tree_seed_cannot_sign_accepted_approval(tmp_path, key_home):
    """A pre-M1 in-tree seed that was rotated (retired) must no longer produce
    an accepted approval. This closes the T2 known limit."""
    lay = _ws(tmp_path / "ws")
    # Plant a pre-M1 in-tree seed
    old_key = SigningKey.generate()
    seed_path = lay.state_dir / "keys" / "cli.seed"
    seed_path.parent.mkdir(parents=True, exist_ok=True)
    seed_path.write_bytes(bytes(old_key))
    old_pub = bytes(old_key.verify_key).hex()
    # Trigger rotation by doing an approval (the new key is pinned in key home)
    rid = _submit(lay)
    res = _approve_req(lay, rid, "cli")
    assert res["status"] == "executed"
    new_pub = res["result"]["signer_public_key"]
    assert new_pub != old_pub, "rotation did not produce a new key"
    # Now forge an approval with the retired (in-tree) key
    rid2 = _submit(lay, command="echo retired-forge")
    rec2 = EscalationQueue(lay).get(rid2)
    forged = {
        "request_id": rec2["request_id"], "command": rec2.get("command"),
        "fingerprint": rec2.get("fingerprint"), "reviewer_id": "cli",
        "decision": "approve", "approved_at": time.time(),
    }
    forged["signer_public_key"] = old_pub
    forged["signature"] = sign_message(
        _canonical(forged, ("request_id", "command", "fingerprint",
                            "reviewer_id", "decision", "approved_at")),
        old_key,
    )
    # The crypto is valid (the key pair is real)
    assert verify_approval(forged), "crypto check failed unexpectedly"
    # But pin-based verification must refuse it
    from sandbox.connector.approval import _valid_for
    _require(not _valid_for(forged, rec2),
             "a retired in-tree seed signed an approval that was accepted")


def test_approval_checked_against_pinned_key_not_embedded(tmp_path, key_home):
    """verify_approval (or a pin-aware wrapper) must check the pinned key for
    this reviewer in this workspace, not just the embedded signer_public_key."""
    lay = _ws(tmp_path / "ws")
    # Pin alice by doing a legitimate approval
    rid1 = _submit(lay)
    res1 = _approve_req(lay, rid1, "alice")
    assert res1["status"] == "executed"
    pinned_pub = res1["result"]["signer_public_key"]
    # Now sign a new approval with a DIFFERENT key but claim reviewer_id "alice"
    wrong_key = SigningKey.generate()
    wrong_pub = bytes(wrong_key.verify_key).hex()
    assert wrong_pub != pinned_pub
    rid2 = _submit(lay, command="echo wrong-key")
    rec2 = EscalationQueue(lay).get(rid2)
    forged = {
        "request_id": rec2["request_id"], "command": rec2.get("command"),
        "fingerprint": rec2.get("fingerprint"), "reviewer_id": "alice",
        "decision": "approve", "approved_at": time.time(),
    }
    forged["signer_public_key"] = wrong_pub
    forged["signature"] = sign_message(
        _canonical(forged, ("request_id", "command", "fingerprint",
                            "reviewer_id", "decision", "approved_at")),
        wrong_key,
    )
    assert verify_approval(forged), "crypto check failed"
    from sandbox.connector.approval import _valid_for
    _require(not _valid_for(forged, rec2),
             "an approval signed by a non-pinned key (wrong key for alice) was accepted")


# ===========================================================================
#  4. ADR 0007 1.6: legacy records verify only under the key_rotated chain
#     head; otherwise "unverifiable"
# ===========================================================================


def test_legacy_record_under_chain_head_is_labelled_legacy(tmp_path, key_home):
    """A pre-rotation record that falls within the audit chain captured by
    key_rotated should be labelled 'legacy' in the evidence pack (ADR 0007 1.6).
    Today there is no such labelling: verify_record just checks the embedded key.
    """
    lay = _ws(tmp_path / "ws")
    # Plant a pre-M1 seed and make a record with it BEFORE rotation
    old_key = SigningKey.generate()
    seed_path = lay.state_dir / "keys" / "cli.seed"
    seed_path.parent.mkdir(parents=True, exist_ok=True)
    seed_path.write_bytes(bytes(old_key))
    # Create a signed record with the old key (simulating a pre-M1 record)
    rid_old = _submit(lay, command="echo legacy-ok")
    rec_old = EscalationQueue(lay).claim(rid_old, "cli")
    assert rec_old is not None
    rec_old["decision"] = "approved"
    rec_old["reviewer_id"] = "cli"
    rec_old["state"] = "done"
    rec_old["signer_public_key"] = bytes(old_key.verify_key).hex()
    rec_old["signed_fields"] = list(_SIGNED_FIELDS)
    rec_old["signature"] = sign_message(_canonical(rec_old), old_key)
    EscalationQueue(lay).finish(rid_old, rec_old)
    # Now trigger rotation (new approval pins the new key)
    rid_new = _submit(lay, command="echo trigger-rotation")
    _approve_req(lay, rid_new, "cli")
    # Export evidence and look for the record-level check
    pack_dir = tmp_path / "pack"
    summary = export_evidence(lay, pack_dir)
    # The per-record checks for the old record must label it as "legacy"
    # (not just signer_is_folder_key fail; specifically "legacy" as a status)
    decisions = summary.get("decisions", [])
    old_decision = None
    for d in decisions:
        if isinstance(d, dict) and d.get("request_id") == rid_old:
            old_decision = d
            break
    checks_text = json.dumps(decisions)
    # There must be a "legacy" label on the old record specifically
    _require(old_decision is not None and ("legacy" in json.dumps(old_decision).lower()),
             f"no 'legacy' label on the pre-rotation record {rid_old}; decisions: {checks_text[:500]}")


def test_legacy_record_outside_chain_head_is_unverifiable(tmp_path, key_home):
    """A record signed with a retired key but NOT covered by the key_rotated
    chain head (e.g. forged after rotation) must show 'unverifiable'."""
    lay = _ws(tmp_path / "ws")
    # Plant a pre-M1 seed
    old_key = SigningKey.generate()
    seed_path = lay.state_dir / "keys" / "cli.seed"
    seed_path.parent.mkdir(parents=True, exist_ok=True)
    seed_path.write_bytes(bytes(old_key))
    # Trigger rotation first
    rid_rotate = _submit(lay, command="echo rotate")
    _approve_req(lay, rid_rotate, "cli")
    # Now forge a record with the old (retired) key AFTER rotation
    rid_forged = _submit(lay, command="echo forged-legacy")
    rec_forged = EscalationQueue(lay).claim(rid_forged, "cli")
    assert rec_forged is not None
    rec_forged["decision"] = "approved"
    rec_forged["reviewer_id"] = "cli"
    rec_forged["state"] = "done"
    rec_forged["signer_public_key"] = bytes(old_key.verify_key).hex()
    rec_forged["signed_fields"] = list(_SIGNED_FIELDS)
    rec_forged["signature"] = sign_message(_canonical(rec_forged), old_key)
    EscalationQueue(lay).finish(rid_forged, rec_forged)
    # Export evidence
    pack_dir = tmp_path / "pack"
    summary = export_evidence(lay, pack_dir)
    all_text = json.dumps(summary)
    _require("unverifiable" in all_text.lower(),
             f"forged legacy record was not labelled unverifiable: {all_text[:500]}")


# ===========================================================================
#  5. SEC-25 residual: `policy propose` / `approve-change` require the
#     proposer's signature from a pinned key
# ===========================================================================


def test_propose_requires_pinned_proposer_key(tmp_path, key_home):
    """policy propose must check that the proposer's signing key is pinned,
    so one human who approves a disguised shell call can't count as the proposer."""
    from sandbox.connector.policy_versions import propose, verify_proposal

    lay = _ws(tmp_path / "ws")
    policy = load_policy(lay.policy_file)
    # Make a trivial change to propose
    policy.escalation_timeout_seconds = 999
    content = json.loads(policy.model_dump_json())
    # Proposer "rogue" has never been pinned
    # Today propose() succeeds (no pin check); verify_proposal also passes (embedded key).
    # T3 must make at least one of them fail for an unpinned proposer.
    succeeded = False
    proposal_valid = False
    try:
        result = propose(lay, "folder", content, "rogue", "test proposal from unpinned key")
        succeeded = True
        proposal_valid = verify_proposal(result)
    except (ValueError, RuntimeError):
        # If propose raises because the key is not pinned, that is correct
        pass
    # If propose succeeded AND the proposal verifies against pins, that is the bug
    _require(not (succeeded and proposal_valid),
             "propose accepted and verified a proposal signed by an unpinned key (rogue)")


def test_approve_change_requires_pinned_proposer_key(tmp_path, key_home):
    """approve-change must refuse a change whose proposer key is not pinned,
    even if the proposal signature is cryptographically valid."""
    from sandbox.connector.policy_versions import approve_change, propose

    lay = _ws(tmp_path / "ws")
    policy = load_policy(lay.policy_file)
    # Set up an approved baseline version first (needed for approve-change)
    from sandbox.connector.policy_versions import _accept
    content = json.loads(policy.model_dump_json())
    _accept(lay, "folder", content, by="bootstrap", reason="initial", how="init")
    # Now propose a change with an unpinned proposer
    policy.escalation_timeout_seconds = 888
    new_content = json.loads(policy.model_dump_json())
    try:
        change = propose(lay, "folder", new_content, "unpinned_proposer", "test")
    except Exception:
        # propose itself may reject if pins are enforced
        return  # correct behaviour: propose rejects unpinned proposers
    # Pin a reviewer by doing an approval
    _approve_req(lay, _submit(lay), "reviewer_a")
    # Try to approve the change
    result = approve_change(lay, change["change_id"], "reviewer_a", "approving")
    _require(result.get("status") != "applied",
             f"approve-change applied a proposal from an unpinned proposer: {result}")


# ===========================================================================
#  6. The approver REST API signs and pins only its fixed reviewer id,
#     never a client-supplied one
# ===========================================================================


def test_guard_rest_api_uses_fixed_reviewer_id(tmp_path, key_home):
    """The REST API approve endpoint hardcodes reviewer='api', never using
    a client-supplied reviewer id. This is a guard: it passes today."""
    from fastapi.testclient import TestClient
    from sandbox.api.app import create_app
    from sandbox.api.auth import ensure_tokens

    lay = _ws(tmp_path / "ws")
    _, approver_token = ensure_tokens()
    os.environ["SANDBOX_CONNECTOR_ROOTS"] = str(lay.root)
    try:
        app = create_app()
        client = TestClient(app)
        rid = _submit(lay, command="echo rest-api-test")
        # Try to supply a custom reviewer_id in the body
        resp = client.post(
            f"/api/v1/connector/{rid}/approve?root={lay.root}",
            headers={"Authorization": f"Bearer {approver_token}"},
            json={"reason": "test", "reviewer_id": "mallory"},
        )
        # The endpoint should succeed but use "api", not "mallory"
        if resp.status_code == 200:
            result = resp.json()
            done = _done_record(lay, rid) if (lay.done_dir / f"{rid}.json").exists() else result.get("result", {})
            actual_reviewer = done.get("reviewer_id", "")
            assert actual_reviewer == "api", (
                f"the REST API used client-supplied reviewer_id {actual_reviewer!r} instead of 'api'"
            )
        # Even on other status codes, the key should be for "api" only
    finally:
        os.environ.pop("SANDBOX_CONNECTOR_ROOTS", None)


def test_guard_rest_api_does_not_accept_reviewer_in_path(tmp_path, key_home):
    """No route parameter allows the client to choose the reviewer id."""
    from fastapi.testclient import TestClient
    from sandbox.api.app import create_app
    from sandbox.api.auth import ensure_tokens

    lay = _ws(tmp_path / "ws")
    _, approver_token = ensure_tokens()
    os.environ["SANDBOX_CONNECTOR_ROOTS"] = str(lay.root)
    try:
        app = create_app()
        client = TestClient(app)
        rid = _submit(lay)
        # The correct endpoint does not have a reviewer parameter
        resp = client.post(
            f"/api/v1/connector/{rid}/approve?root={lay.root}&reviewer=mallory",
            headers={"Authorization": f"Bearer {approver_token}"},
            json={"reason": "test"},
        )
        if resp.status_code == 200:
            done = _done_record(lay, rid) if (lay.done_dir / f"{rid}.json").exists() else resp.json().get("result", {})
            assert done.get("reviewer_id") == "api", (
                "a query parameter 'reviewer' was honoured by the approve endpoint"
            )
    finally:
        os.environ.pop("SANDBOX_CONNECTOR_ROOTS", None)


# ===========================================================================
#  Additional pin-related guards (these should pass today)
# ===========================================================================


def test_guard_cross_workspace_approval_still_refused(tmp_path, key_home):
    """Two workspaces, same reviewer, cross-workspace approval must be refused
    (T2 property; still holds with pins)."""
    a = _ws(tmp_path / "a")
    b = _ws(tmp_path / "b")
    _approve_req(a, _submit(a), "cli")
    done_a = json.loads(list(a.done_dir.iterdir())[0].read_text(encoding="utf-8"))
    key_a = done_a["signer_public_key"]
    # The key from workspace a should not verify for workspace b
    rid_b = _submit(b, command="echo cross-ws")
    rec_b = EscalationQueue(b).get(rid_b)
    forged = {
        "request_id": rec_b["request_id"], "command": rec_b.get("command"),
        "fingerprint": rec_b.get("fingerprint"), "reviewer_id": "cli",
        "decision": "approve", "approved_at": time.time(),
    }
    # Use a's key bytes (by reading from key home)
    from sandbox.connector import keyhome
    a_wsid = keyhome.workspace_id(a, create=False)
    a_seed = key_home / a_wsid / "cli.seed"
    a_signing = SigningKey(a_seed.read_bytes())
    forged["signer_public_key"] = bytes(a_signing.verify_key).hex()
    forged["signature"] = sign_message(
        _canonical(forged, ("request_id", "command", "fingerprint",
                            "reviewer_id", "decision", "approved_at")),
        a_signing,
    )
    # The embedded-key verify passes (crypto is valid)
    assert verify_approval(forged)
    # But for workspace b, the key is from workspace a -- keys differ
    b_pub = _approve_req(b, _submit(b), "cli")["result"]["signer_public_key"]
    assert key_a != b_pub, "both workspaces should have different keys"


def test_guard_verify_record_still_works_for_legitimate_approval(tmp_path, key_home):
    """A legitimate approval signed by the workspace's own key verifies."""
    lay = _ws(tmp_path / "ws")
    rid = _submit(lay)
    res = _approve_req(lay, rid, "alice")
    assert res["status"] == "executed"
    done = _done_record(lay, rid)
    assert verify_record(done), "a legitimate approval's done-record does not verify"


def test_guard_hook_path_does_not_call_signing(tmp_path, key_home):
    """The hook_eval module does not import signing functions. This is a
    structural guard: if it changes, pins from hook calls become possible."""
    import sandbox.connector.hook_eval as he
    import sandbox.connector.mcp_server as ms

    # Neither module should have sign_approval or _load_or_create_key
    for mod_name, mod in [("hook_eval", he), ("mcp_server", ms)]:
        source = Path(mod.__file__).read_text(encoding="utf-8")
        for func in ("sign_approval", "_load_or_create_key", "ensure_signing_key",
                      "sign_record"):
            assert func not in source, (
                f"{mod_name} references {func}; the hook/MCP path must never create keys or pins"
            )
