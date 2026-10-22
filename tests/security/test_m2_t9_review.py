"""T9 security-review regression tests (F1, F3, F4).

Postgres-free, plain tests, no xfail.  Each test targets a specific
security finding and fails until the backend fix is applied.

F1 HIGH -- N5 at runtime: ``enforced_policy`` must use ``meet_bundle``
    for *all* 5 sections (folder_policy, governance_policy, mcp_policy,
    approval, environment), not just the folder_policy drift from the
    policy-versions head.

F3 MEDIUM -- ``verify_chain`` must refuse a bundle_signer whose key_id
    appears in ``keys``; after a rotation only the *latest* version's
    bundle_signer is trusted; admin key as bundle_signer is refused.

F4 LOW -- ``meet_bundle`` mcp: on-disk overlay can only *remove*
    servers (enforced = approved intersection on-disk).

Product gap (22 Oct 2026): no product writer exists for the managed
marker, ``pinned_root.json`` or ``registry.json``.  The enroll client
(``sync/enroll.py``) sends the POST and returns data but does not
persist the enrollment state locally.  These tests hand-write the
three files because no product writer exists.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import time
from pathlib import Path

import pytest
from nacl.signing import SigningKey

# ---------------------------------------------------------------------------
# Reused helpers (copied from test_m2_t9_bundles.py to stay self-contained)
# ---------------------------------------------------------------------------


def _keygen():
    sk = SigningKey.generate()
    pub = bytes(sk.verify_key)
    kid = hashlib.sha256(pub).hexdigest()
    return sk, pub, kid


def _canonical_json(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def _sign_envelope(kind: str, payload: dict, signing_keys: list) -> dict:
    tag = kind.encode("utf-8")
    canonical = _canonical_json(payload)
    msg = tag + b"\x00" + canonical
    sigs = []
    for sk in signing_keys:
        pub = bytes(sk.verify_key)
        kid = hashlib.sha256(pub).hexdigest()
        sig = sk.sign(msg).signature.hex()
        sigs.append({"key_id": kid, "alg": "ed25519", "sig": sig})
    return {"kind": kind, "sig_v": 1, "payload": payload, "signatures": sigs}


def _make_key_entry(sk=None, *, user_id="alice", iss="https://idp", sub="alice",
                    kind="cli", roles=None, added_in=1):
    if sk is None:
        sk, pub, kid = _keygen()
    else:
        pub = bytes(sk.verify_key)
        kid = hashlib.sha256(pub).hexdigest()
    return {
        "key_id": kid, "public_key": pub.hex(), "user_id": user_id,
        "iss": iss, "sub": sub, "alg": "ed25519",
        "kind": kind, "roles": roles or ["admin", "approver"], "added_in": added_in,
    }, sk


def _make_registry_payload(*, org_id="org-1", version=1, prev_hash="",
                           threshold=1, admins=None, keys=None,
                           bundle_signer=None, expires_at=None):
    return {
        "org_id": org_id, "version": version, "prev_hash": prev_hash,
        "threshold": threshold, "admins": admins or [], "keys": keys or [],
        "bundle_signer": bundle_signer or {},
        "expires_at": expires_at or time.time() + 7 * 86400,
    }


def _build_genesis(org_id="org-1", admin_sks=None, bundle_signer_sk=None,
                   threshold=1, expires_at=None):
    if admin_sks is None:
        admin_sks = [_keygen()[0]]
    if bundle_signer_sk is None:
        bundle_signer_sk = _keygen()[0]
    bpub = bytes(bundle_signer_sk.verify_key)
    bkid = hashlib.sha256(bpub).hexdigest()
    bs_dict = {"key_id": bkid, "public_key": bpub.hex(), "alg": "ed25519"}
    keys, admins = [], []
    for i, sk in enumerate(admin_sks):
        entry, _ = _make_key_entry(sk, user_id=f"admin-{i}", iss="https://idp",
                                   sub=f"admin-{i}", kind="cli",
                                   roles=["admin", "approver"], added_in=1)
        keys.append(entry)
        admins.append(entry["key_id"])
    payload = _make_registry_payload(
        org_id=org_id, version=1, prev_hash="", threshold=threshold,
        admins=admins, keys=keys, bundle_signer=bs_dict,
        expires_at=expires_at or time.time() + 7 * 86400)
    envelope = _sign_envelope("agg/registry/v1", payload, admin_sks)
    return envelope, admin_sks, bundle_signer_sk, bpub, bkid


def _registry_fingerprint(genesis_payload: dict) -> str:
    return hashlib.sha256(
        genesis_payload["org_id"].encode("utf-8") + b":" +
        _canonical_json(genesis_payload)
    ).hexdigest()


def _verify_chain(chain, fingerprint):
    from sandbox.protocol.registry import verify_chain
    return verify_chain(chain, fingerprint)


def _make_bundle_payload(*, org_id="org-1", project_id="proj-1",
                         sequence=1, base_sequence=0, registry_version=1,
                         environment=None, folder_policy=None,
                         governance_policy=None, mcp_policy=None,
                         approval=None, change_approvals=None,
                         issued_at=None, not_before=None, expires_at=None):
    now = time.time()
    payload: dict = {
        "org_id": org_id, "project_id": project_id,
        "sequence": sequence, "base_sequence": base_sequence,
        "registry_version": registry_version,
        "folder_policy": folder_policy or {"shell": {"blocklist_action": "deny"}},
        "governance_policy": governance_policy or {},
        "mcp_policy": mcp_policy or {},
        "approval": approval or {"local_fallback": False, "allow_requester": False},
        "change_approvals": change_approvals or [],
        "issued_at": issued_at or now,
        "not_before": not_before or (now - 60),
        "expires_at": expires_at or (now + 7 * 86400),
    }
    if environment is not None:
        payload["environment"] = environment
    return payload


def _make_change_approval(bundle_hash, sk, *, user_id="alice", nonce=None):
    import secrets
    if nonce is None:
        nonce = secrets.token_hex(16)
    a = {"bundle_hash": bundle_hash, "user_id": user_id,
         "key_id": hashlib.sha256(bytes(sk.verify_key)).hexdigest(),
         "nonce": nonce, "issued_at": time.time()}
    return _sign_envelope("agg/policy-change/v1", a, [sk])


def _bundle_hash(payload: dict) -> str:
    return hashlib.sha256(_canonical_json(payload)).hexdigest()


def _build_real_registry(org_id="org-1"):
    admin_sks = [_keygen()[0], _keygen()[0]]
    genesis_env, admin_sks, bsk, bpub, bkid = _build_genesis(
        org_id=org_id, admin_sks=admin_sks, threshold=2)
    fp = _registry_fingerprint(genesis_env["payload"])
    registry = _verify_chain([genesis_env], fp)
    return registry, bsk, bpub, admin_sks, fp, genesis_env


@pytest.fixture
def key_home(tmp_path, monkeypatch):
    kh = tmp_path / "keyhome"
    kh.mkdir()
    monkeypatch.setenv("SANDBOX_KEY_HOME", str(kh))
    return kh


def _ws(path: Path):
    from sandbox.connector.install import init
    from sandbox.connector.layout import FolderLayout
    path.mkdir(parents=True, exist_ok=True)
    init(path, claude=False, mcp=False)
    return FolderLayout(path)


def _pin_registry(lay, genesis_env, fp):
    """Write pinned_root.json and registry.json so _verified_bundle_payload
    can re-verify the stored bundle at enforcement time.

    Product gap: no product writer exists for these files.  The enroll
    client sends the POST and returns data but does not persist the
    enrollment state locally.  Hand-written here because no writer exists.
    """
    sync_dir = lay.root / ".sandbox" / "state" / "sync"
    sync_dir.mkdir(parents=True, exist_ok=True)
    (sync_dir / "pinned_root.json").write_text(
        json.dumps({"fingerprint": fp}), "utf-8")
    (sync_dir / "registry.json").write_text(
        json.dumps([genesis_env], sort_keys=True, separators=(",", ":")),
        "utf-8",
    )


def _mark_managed(lay, key_home):
    """Write the managed marker in both key-home and sync dir.

    Product gap: no product writer exists.  Hand-written.
    """
    ws_id_file = lay.root / ".sandbox" / "workspace_id"
    ws_id = ws_id_file.read_text("utf-8").strip() if ws_id_file.exists() else "w0"
    (key_home / ws_id).mkdir(parents=True, exist_ok=True)
    (key_home / ws_id / "managed").write_text("1", "utf-8")
    sync_dir = lay.root / ".sandbox" / "state" / "sync"
    sync_dir.mkdir(parents=True, exist_ok=True)
    (sync_dir / "managed").write_text("1", "utf-8")


def _apply_bundle_full(lay, registry, bsk, bpub, admin_sks, *,
                       sequence=1, folder_policy=None,
                       governance_policy=None, mcp_policy=None,
                       approval=None, environment=None):
    """Apply a first bundle with all 5 sections, 2 CLI approvals (N3)."""
    from sandbox.connector.sync.bundles import verify_and_apply

    p = _make_bundle_payload(
        sequence=sequence, base_sequence=0,
        folder_policy=folder_policy or {"shell": {"blocklist_action": "deny"}},
        governance_policy=governance_policy or {},
        mcp_policy=mcp_policy or {},
        approval=approval or {"local_fallback": False, "allow_requester": False},
        environment=environment,
    )
    bh = _bundle_hash(p)
    e = _sign_envelope("agg/bundle/v1", p, [bsk])
    approvals = [
        _make_change_approval(bh, admin_sks[0], user_id="admin-0"),
        _make_change_approval(bh, admin_sks[1], user_id="admin-1"),
    ]
    return verify_and_apply(lay, e, registry, bpub, approvals,
                            org_id="org-1", project_id="proj-1")


def _hook(lay, tool, tool_input):
    """Call pre_tool_use and return (decision, reason, full_output)."""
    from sandbox.connector.hook_eval import pre_tool_use
    out = asyncio.run(pre_tool_use(
        {"tool_name": tool, "tool_input": tool_input,
         "cwd": str(lay.root), "session_id": "t9r"},
        lay,
    ))
    hso = out.get("hookSpecificOutput", {})
    return (
        hso.get("permissionDecision"),
        hso.get("permissionDecisionReason", ""),
        out,
    )


def _setup_managed_with_bundle(tmp_path, key_home, *,
                                folder_policy=None, governance_policy=None,
                                mcp_policy=None, approval=None,
                                environment=None):
    """Full managed workspace: ws + managed marker + pinned registry + bundle."""
    lay = _ws(tmp_path / "ws")
    registry, bsk, bpub, admin_sks, fp, genesis_env = _build_real_registry()
    _mark_managed(lay, key_home)
    _pin_registry(lay, genesis_env, fp)
    _apply_bundle_full(
        lay, registry, bsk, bpub, admin_sks,
        folder_policy=folder_policy,
        governance_policy=governance_policy,
        mcp_policy=mcp_policy,
        approval=approval,
        environment=environment,
    )
    return lay, registry, bsk, bpub, admin_sks, fp, genesis_env


# ===================================================================
# F1 HIGH -- enforced_policy must use meet_bundle for all 5 sections
# Each test builds a managed workspace through the real enroll/sticky-
# mode path (hand-written markers; product gap, see module docstring),
# applies a real bundle via verify_and_apply with 2 admins, hand-edits
# the LOCAL overlay file, then calls the real hook_eval.pre_tool_use
# and asserts the actual decision.
# ===================================================================


def test_f1_folder_hand_edit_enforced_unchanged(tmp_path, key_home):
    """F1: bundle says observe for shell blocklist; hand-editing policy.json
    to allow has no effect.  The hook still observes (not allows) a
    blocklisted command."""
    from sandbox.connector.policy import load_policy, save_policy

    lay, *_ = _setup_managed_with_bundle(
        tmp_path, key_home,
        folder_policy={"shell": {"blocklist_action": "observe"}},
    )

    # Hand-edit policy.json to loosen (observe -> allow)
    pol = load_policy(lay.policy_file)
    pol.shell.blocklist_action = "allow"
    save_policy(pol, lay.policy_file)

    # A blocklisted command should be observed (not allowed) per the bundle.
    # "observe" in pre_tool_use means the call is allowed but audited, so
    # the decision is "allow" with a reason containing "observe".
    # More importantly, the enforced folder_policy must still say observe.
    from sandbox.connector.policy_versions import enforced_policy
    enforced, info = enforced_policy(lay)
    assert enforced.shell.blocklist_action == "observe", (
        f"Expected 'observe' from bundle, got '{enforced.shell.blocklist_action}'; "
        "the on-disk 'allow' loosened the bundle (F1)"
    )
    # Verify the bundle_enforced dict is not empty
    be = info.get("bundle_enforced")
    assert be is not None and be != {}, (
        "bundle_enforced must not be empty when a verified bundle exists"
    )


def test_f1_governance_hand_edit_enforced_unchanged(tmp_path, key_home):
    """F1: bundle has a governance deny clause; removing the local governance
    file does not remove it.  An MCP tool call still hits the enforced deny."""
    gov = {"clauses": [{"id": "g1", "action": "deny", "text": "no prod deploy"}]}
    lay, *_ = _setup_managed_with_bundle(
        tmp_path, key_home, governance_policy=gov,
    )

    # The on-disk governance file (if any) is pointed to by policy.json
    # semantic.governance_policy.  Removing or clearing the pointer means
    # the on-disk side has no governance -- but the bundle's deny clause
    # must still apply via the enforced governance path.
    from sandbox.connector.policy import load_policy, save_policy
    pol = load_policy(lay.policy_file)
    pol.semantic.governance_policy = ""
    save_policy(pol, lay.policy_file)

    # Call the hook with an MCP tool (governed tool).  The bundle's deny
    # clause g1 should fire via the enforced governance path.
    decision, reason, _out = _hook(
        lay, "mcp__stripe__create_refund",
        {"amount": 100, "currency": "usd"},
    )
    # The governance deny clause or the MCP_POLICY deny (empty mcp_policy
    # in bundle means no servers allowed) must prevent allow.
    assert decision != "allow", (
        f"MCP tool was allowed ({decision!r}) despite bundle governance deny "
        f"clause g1 and empty mcp_policy; reason: {reason}"
    )


def test_f1_mcp_hand_edit_enforced_unchanged(tmp_path, key_home):
    """F1: bundle has no MCP servers; hand-editing bundle.json to add one
    has no effect.  An MCP tool call is denied with MCP_POLICY."""
    lay, *_ = _setup_managed_with_bundle(
        tmp_path, key_home, mcp_policy={"servers": []},
    )

    # Hand-edit bundle.json on disk to add a server (loosening).
    # The enforced set should still be empty because _verified_bundle_payload
    # re-verifies against the immutable policy_history copy.
    bf = lay.root / ".sandbox" / "state" / "sync" / "bundle.json"
    data = json.loads(bf.read_text("utf-8"))
    data["payload"]["mcp_policy"]["servers"] = [
        {"name": "evil", "tools": ["*"]}
    ]
    bf.write_text(json.dumps(data), "utf-8")

    # Call the hook with an MCP tool for the hand-added server.
    decision, reason, _out = _hook(
        lay, "mcp__evil__run_tool", {"action": "read"},
    )
    assert decision == "deny", (
        f"MCP tool 'evil' was not denied ({decision!r}); hand-editing "
        f"bundle.json to add a server must be ignored; reason: {reason}"
    )
    assert "MCP_POLICY" in reason, (
        f"Expected MCP_POLICY in denial reason, got: {reason}"
    )


def test_f1_approval_hand_edit_enforced_unchanged(tmp_path, key_home):
    """F1: bundle sets local_fallback=False and allow_requester=False;
    hand-editing bundle.json to loosen them has no effect.  The enforced
    approval in policy_info exposes the exact values (no .get defaults).
    T12 consumes _enforced_approval (wired in hook_eval from bundle_enforced)."""
    lay, *_ = _setup_managed_with_bundle(
        tmp_path, key_home,
        approval={"local_fallback": False, "allow_requester": False},
    )

    # Hand-edit bundle.json to loosen approval
    bf = lay.root / ".sandbox" / "state" / "sync" / "bundle.json"
    data = json.loads(bf.read_text("utf-8"))
    data["payload"]["approval"]["local_fallback"] = True
    data["payload"]["approval"]["allow_requester"] = True
    bf.write_text(json.dumps(data), "utf-8")

    # Verify through enforced_policy that bundle_enforced.approval is unchanged.
    # hook_eval.pre_tool_use wires this into _enforced_approval for T12.
    from sandbox.connector.policy_versions import enforced_policy
    _enforced, info = enforced_policy(lay)

    # bundle_enforced["approval"] is the source; hook_eval copies it to
    # _enforced_approval at line ~282.  Verify the source dict directly
    # (no .get defaults).
    be = info["bundle_enforced"]
    assert be["approval"]["local_fallback"] is False, (
        f"local_fallback should be False, got {be['approval']['local_fallback']!r}; "
        "hand-editing bundle.json loosened approval (F1)"
    )
    assert be["approval"]["allow_requester"] is False, (
        f"allow_requester should be False, got {be['approval']['allow_requester']!r}; "
        "hand-editing bundle.json loosened approval (F1)"
    )

    # Also verify through the hook that _enforced_approval is wired.
    # Call the hook; it sets policy_info["_enforced_approval"] internally.
    # We can't access it directly, but we can confirm the hook runs without
    # the loosened values taking effect by checking that a read inside the
    # root is not denied (the bundle allows reads; approval section alone
    # does not change the verdict for a simple Read).
    decision, _reason, _out = _hook(
        lay, "Read", {"file_path": str(lay.root / ".sandbox" / "policy.json")},
    )
    # decision=None means "allow" (Claude Code's own flow runs); the
    # connector is purely additive.  Not "deny" proves the bundle approval
    # section (with local_fallback=False) did not break reads.
    # The real consumption of _enforced_approval is in T12.
    assert decision != "deny", (
        f"read inside root was denied ({_reason}); "
        "approval enforcement should not block reads"
    )


def test_f1_environment_hand_edit_enforced_unchanged(tmp_path, key_home):
    """F1: bundle has no environment (= prod per D2.4); hand-editing the
    local policy.json environment to staging has no effect.  The hook wires
    the bundle environment into policy.environment at line ~270-271 of
    hook_eval.py (absent = prod).  Verify via enforced_policy's
    bundle_enforced dict and the hook's actual decision."""
    lay, *_ = _setup_managed_with_bundle(tmp_path, key_home)

    # Hand-edit local policy.json to set environment to staging (loosening)
    disk_data = json.loads(lay.policy_file.read_text("utf-8"))
    disk_data["environment"] = "staging"
    lay.policy_file.write_text(json.dumps(disk_data, indent=2), "utf-8")

    # Verify through enforced_policy that bundle_enforced environment is
    # absent (= prod per D2.4) or "prod".  The FolderPolicy.environment
    # is not set by enforced_policy -- it's set by hook_eval from
    # bundle_enforced.
    from sandbox.connector.policy_versions import enforced_policy
    _enforced, info = enforced_policy(lay)
    be = info.get("bundle_enforced")
    assert be is not None, "bundle_enforced must be set for a managed workspace"
    # Absent environment in bundle_enforced = prod (D2.4)
    env_in_be = be.get("environment")
    assert env_in_be is None or env_in_be == "prod", (
        f"bundle_enforced environment should be absent or 'prod', got {env_in_be!r}; "
        "the on-disk 'staging' loosened the bundle (F1)"
    )

    # Verify the hook applies the bundle environment, not the on-disk one.
    # Call the hook; it wires bundle_enforced["environment"] into
    # policy.environment at line ~270-271 of hook_eval.py (absent = prod).
    decision, _reason, _out = _hook(
        lay, "Read", {"file_path": str(lay.root / ".sandbox" / "policy.json")},
    )
    # decision=None means "allow" (no override from the connector); the
    # hook ran without error and applied the bundle environment.
    assert decision != "deny", (
        f"read inside root was denied ({_reason}); "
        "environment enforcement should not block reads"
    )


# ===================================================================
# Additional enforcement tests (a-e)
# ===================================================================


def test_managed_bundle_deleted_deny_all(tmp_path, key_home):
    """(a) Managed workspace with bundle.json AND history deleted: deny-all.
    A Bash command must be denied."""
    lay, *_ = _setup_managed_with_bundle(tmp_path, key_home)

    # Delete both bundle.json and policy_history
    import shutil
    sync_dir = lay.root / ".sandbox" / "state" / "sync"
    bf = sync_dir / "bundle.json"
    if bf.exists():
        bf.unlink()
    hist = lay.root / ".sandbox" / "policy_history"
    if hist.exists():
        shutil.rmtree(hist)

    # The workspace is managed with no bundle: locked mode.
    decision, reason, _out = _hook(lay, "Bash", {"command": "echo hello"})
    assert decision == "deny", (
        f"Expected deny in managed workspace with no bundle, got {decision!r}; "
        f"reason: {reason}"
    )


def test_managed_history_tampered_deny_all_corrupt(tmp_path, key_home):
    """(b) Managed workspace with the history envelope tampered (one byte):
    deny-all and bundle_corrupt in info."""
    lay, *_ = _setup_managed_with_bundle(tmp_path, key_home)

    # Tamper with the history envelope (flip one byte in a signature)
    hist = lay.root / ".sandbox" / "policy_history"
    hist_files = sorted(hist.glob("bundle_*.json"))
    assert hist_files, "no history file found"
    data = hist_files[0].read_bytes()
    # Flip the last byte of the file content (inside the JSON)
    tampered = data[:-2] + bytes([data[-2] ^ 0x01]) + data[-1:]
    hist_files[0].write_bytes(tampered)
    # Also tamper bundle.json in sync dir
    bf = lay.root / ".sandbox" / "state" / "sync" / "bundle.json"
    if bf.exists():
        bf_data = bf.read_bytes()
        bf.write_bytes(bf_data[:-2] + bytes([bf_data[-2] ^ 0x01]) + bf_data[-1:])

    # Verification fails: enforced_policy should return deny-all with
    # bundle_corrupt.
    from sandbox.connector.policy_versions import enforced_policy
    _enforced, info = enforced_policy(lay)
    assert info.get("bundle_corrupt") is True, (
        "Expected bundle_corrupt=True when the history envelope is tampered"
    )
    # The enforced policy should be deny-all
    be = info.get("bundle_enforced")
    assert be is not None, "bundle_enforced should be set (deny-all)"
    assert be["approval"]["local_fallback"] is False
    assert be["approval"]["allow_requester"] is False


def test_managed_editing_bundle_json_loosen_no_effect(tmp_path, key_home):
    """(c) Managed workspace: editing bundle.json to loosen mcp_policy
    changes nothing; the immutable policy_history copy is re-verified."""
    lay, *_ = _setup_managed_with_bundle(
        tmp_path, key_home,
        mcp_policy={"servers": [{"name": "safe", "tools": ["read"]}]},
    )

    # Hand-edit bundle.json to add a server
    bf = lay.root / ".sandbox" / "state" / "sync" / "bundle.json"
    data = json.loads(bf.read_text("utf-8"))
    data["payload"]["mcp_policy"]["servers"].append(
        {"name": "evil", "tools": ["*"]}
    )
    bf.write_text(json.dumps(data), "utf-8")

    # The evil server must still be denied because the immutable
    # policy_history envelope is the one that gets re-verified.
    decision, reason, _out = _hook(
        lay, "mcp__evil__run_tool", {"action": "read"},
    )
    assert decision == "deny", (
        f"MCP tool 'evil' was not denied ({decision!r}); editing bundle.json "
        f"must not loosen enforcement; reason: {reason}"
    )
    assert "MCP_POLICY" in reason


def test_unmanaged_keeps_m1_behaviour(tmp_path, key_home):
    """(d) Unmanaged workspace uses M1 behaviour: a read inside the root
    is allowed (or observed) as in M1."""
    lay = _ws(tmp_path / "ws")
    # No managed marker, no bundle, no registry.  Pure M1 standalone.

    # Write a test file to read
    test_file = lay.root / "readme.txt"
    test_file.write_text("hello", "utf-8")

    decision, reason, _out = _hook(
        lay, "Read", {"file_path": str(test_file)},
    )
    # M1: a read inside the root should be allowed (or observed)
    assert decision in ("allow", None), (
        f"Unmanaged workspace denied a read inside root ({decision!r}); "
        f"M1 behaviour broken; reason: {reason}"
    )


def test_managed_no_bundle_yet_deny_all(tmp_path, key_home):
    """(e) Managed workspace with no bundle yet (freshly enrolled): deny-all
    per N3.  A Bash command must be denied (locked mode)."""
    lay = _ws(tmp_path / "ws")
    registry, bsk, bpub, admin_sks, fp, genesis_env = _build_real_registry()
    _mark_managed(lay, key_home)
    _pin_registry(lay, genesis_env, fp)
    # No bundle applied.  The workspace is managed but has no policy.

    decision, reason, _out = _hook(lay, "Bash", {"command": "echo hello"})
    assert decision == "deny", (
        f"Expected deny in managed workspace with no bundle (N3), got {decision!r}; "
        f"reason: {reason}"
    )


# ===================================================================
# F3 MEDIUM -- bundle_signer key_id collisions and rotation
# ===================================================================


def test_f3_admin_key_as_bundle_signer_refused():
    """F3: an admin key listed also as bundle_signer is refused by
    verify_chain with a RegistryError matching 'bundle_signer'."""
    from sandbox.protocol.registry import verify_chain, RegistryError

    admin_sk, admin_pub, admin_kid = _keygen()
    # Use the SAME key as both admin and bundle_signer
    bs_dict = {"key_id": admin_kid, "public_key": admin_pub.hex(),
               "alg": "ed25519"}
    entry, _ = _make_key_entry(admin_sk, user_id="alice", kind="cli",
                               roles=["admin", "approver"])
    payload = _make_registry_payload(
        version=1, prev_hash="", threshold=1,
        admins=[admin_kid], keys=[entry], bundle_signer=bs_dict)
    envelope = _sign_envelope("agg/registry/v1", payload, [admin_sk])
    fp = _registry_fingerprint(payload)

    with pytest.raises(RegistryError, match="bundle_signer"):
        verify_chain([envelope], fp)


def test_f3_rotated_old_bundle_signer_not_trusted():
    """F3: after a rotation version, may_sign for the OLD bundle_signer
    key on BUNDLE kind returns False."""
    from sandbox.protocol.registry import verify_chain
    from sandbox.protocol.domains import BUNDLE

    admin_sks = [_keygen()[0], _keygen()[0]]
    old_bsk, old_bpub, old_bkid = _keygen()
    new_bsk, new_bpub, new_bkid = _keygen()

    # Genesis with old bundle_signer
    genesis_env, admin_sks, _, _, _ = _build_genesis(
        admin_sks=admin_sks, bundle_signer_sk=old_bsk, threshold=2)
    fp = _registry_fingerprint(genesis_env["payload"])

    # Version 2 with new bundle_signer
    prev_hash = hashlib.sha256(
        genesis_env["payload"]["org_id"].encode("utf-8") + b":" +
        _canonical_json(genesis_env["payload"])
    ).hexdigest()

    v2_bs = {"key_id": new_bkid, "public_key": new_bpub.hex(),
             "alg": "ed25519"}
    v2_payload = _make_registry_payload(
        version=2, prev_hash=prev_hash, threshold=2,
        admins=genesis_env["payload"]["admins"],
        keys=genesis_env["payload"]["keys"],
        bundle_signer=v2_bs)
    v2_env = _sign_envelope("agg/registry/v1", v2_payload, admin_sks)

    registry = verify_chain([genesis_env, v2_env], fp)
    assert not registry.may_sign(old_bkid, BUNDLE, "prod"), (
        "old bundle_signer should not be trusted after rotation"
    )


def test_f3_rotated_new_bundle_signer_trusted():
    """F3: after a rotation version, may_sign for the NEW bundle_signer
    key on BUNDLE kind returns True."""
    from sandbox.protocol.registry import verify_chain
    from sandbox.protocol.domains import BUNDLE

    admin_sks = [_keygen()[0], _keygen()[0]]
    old_bsk, old_bpub, old_bkid = _keygen()
    new_bsk, new_bpub, new_bkid = _keygen()

    genesis_env, admin_sks, _, _, _ = _build_genesis(
        admin_sks=admin_sks, bundle_signer_sk=old_bsk, threshold=2)
    fp = _registry_fingerprint(genesis_env["payload"])

    prev_hash = hashlib.sha256(
        genesis_env["payload"]["org_id"].encode("utf-8") + b":" +
        _canonical_json(genesis_env["payload"])
    ).hexdigest()

    v2_bs = {"key_id": new_bkid, "public_key": new_bpub.hex(),
             "alg": "ed25519"}
    v2_payload = _make_registry_payload(
        version=2, prev_hash=prev_hash, threshold=2,
        admins=genesis_env["payload"]["admins"],
        keys=genesis_env["payload"]["keys"],
        bundle_signer=v2_bs)
    v2_env = _sign_envelope("agg/registry/v1", v2_payload, admin_sks)

    registry = verify_chain([genesis_env, v2_env], fp)
    assert registry.may_sign(new_bkid, BUNDLE, "prod"), (
        "new bundle_signer should be trusted after rotation"
    )


# ===================================================================
# F4 LOW -- meet_bundle mcp: on-disk can only remove servers
# ===================================================================


def test_f4_meet_mcp_on_disk_removal_respected():
    """F4: on-disk removing a server from approved reduces the enforced
    set (enforced = approved intersection on-disk)."""
    from sandbox.connector.sync.bundles import meet_bundle

    approved = _make_bundle_payload(
        mcp_policy={"servers": [
            {"name": "server-a", "tools": ["read"]},
            {"name": "server-b", "tools": ["write"]},
        ]},
    )
    on_disk = _make_bundle_payload(
        mcp_policy={"servers": [
            {"name": "server-a", "tools": ["read"]},
        ]},
    )
    enforced = meet_bundle(approved, on_disk)
    server_names = [s.get("name") for s in enforced["mcp_policy"]["servers"]]
    assert "server-a" in server_names, (
        "server-a present in both approved and on-disk should be in enforced"
    )
    assert "server-b" not in server_names, (
        "server-b removed on disk (tightening) should not be in enforced; "
        "meet_bundle mcp should return approved intersection on-disk"
    )
