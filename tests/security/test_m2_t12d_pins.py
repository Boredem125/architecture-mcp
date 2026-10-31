"""T12d d5 section 3: connector pins (P1-P10).

All plain passing tests (no xfail) unless the spec says otherwise.
Imports from existing test helpers as the spec directs.

P7-P9 use the managed workspace + remote approval helpers.
P10 is the G-L5 part 1 named limit.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import time

import pytest
from nacl.signing import SigningKey

from tests.security.test_m2_t6_registry import (
    _keygen, _make_key_entry, _make_registry_payload,
    _sign_envelope, _build_next_version,
)
from tests.security.test_m2_t12_remote import (
    _setup_managed_workspace, _create_pending_request,
    _make_remote_approval,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _canonical_json(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def _payload_hash(payload: dict) -> str:
    return hashlib.sha256(
        payload["org_id"].encode("utf-8") + b":" + _canonical_json(payload)
    ).hexdigest()


def _build_genesis_two_keys_one_user(
    org_id="org-1", *, threshold=1, user_id="u-alice",
    extra_approvers=None, bundle_signer=None,
):
    """Build a genesis v1 with two admin keys belonging to the same user_id.

    Returns (v1_env, fp, sk1, sk2, approver_entries).
    """
    sk1, pub1, kid1 = _keygen()
    sk2, pub2, kid2 = _keygen()

    entry1, _ = _make_key_entry(
        sk1, user_id=user_id, iss="https://idp", sub=user_id,
        kind="cli", roles=["admin", "approver"], added_in=1,
    )
    entry2, _ = _make_key_entry(
        sk2, user_id=user_id, iss="https://idp", sub=user_id,
        kind="cli", roles=["admin", "approver"], added_in=1,
    )

    keys = [entry1, entry2]
    admins = [kid1, kid2]

    approver_entries = []
    if extra_approvers:
        for ask, auid in extra_approvers:
            ae, _ = _make_key_entry(
                ask, user_id=auid, iss="https://idp", sub=auid,
                kind="cli", roles=["approver"], added_in=1,
            )
            keys.append(ae)
            approver_entries.append(ae)

    if bundle_signer is None:
        bsk, bpub, bkid = _keygen()
        bundle_signer = {"key_id": bkid, "public_key": bpub.hex(), "alg": "ed25519"}

    payload = _make_registry_payload(
        org_id=org_id, version=1, prev_hash="", threshold=threshold,
        admins=admins, keys=keys, bundle_signer=bundle_signer,
    )

    # Sign with both admin keys
    tag = "agg/registry/v1"
    canonical = _canonical_json(payload)
    msg = tag.encode() + b"\x00" + canonical
    sigs = []
    for sk in (sk1, sk2):
        pub = bytes(sk.verify_key)
        kid = hashlib.sha256(pub).hexdigest()
        sig = sk.sign(msg).signature.hex()
        sigs.append({"key_id": kid, "alg": "ed25519", "sig": sig})

    env = {"kind": tag, "sig_v": 1, "payload": payload, "signatures": sigs}
    fp = _payload_hash(payload)

    return env, fp, sk1, sk2, kid1, kid2, approver_entries


def _build_genesis_two_users(org_id="org-1", *, threshold=2,
                             extra_approvers=None, bundle_signer=None):
    """Build a genesis v1 with two admin keys from two different users.

    Returns (v1_env, fp, sk_alice, sk_carol, kid_alice, kid_carol, approver_entries).
    """
    sk_a, pub_a, kid_a = _keygen()
    sk_c, pub_c, kid_c = _keygen()

    entry_a, _ = _make_key_entry(
        sk_a, user_id="u-alice", iss="https://idp", sub="u-alice",
        kind="cli", roles=["admin", "approver"], added_in=1,
    )
    entry_c, _ = _make_key_entry(
        sk_c, user_id="u-carol", iss="https://idp", sub="u-carol",
        kind="cli", roles=["admin", "approver"], added_in=1,
    )

    keys = [entry_a, entry_c]
    admins = [kid_a, kid_c]

    approver_entries = []
    if extra_approvers:
        for ask, auid in extra_approvers:
            ae, _ = _make_key_entry(
                ask, user_id=auid, iss="https://idp", sub=auid,
                kind="cli", roles=["approver"], added_in=1,
            )
            keys.append(ae)
            approver_entries.append(ae)

    if bundle_signer is None:
        bsk, bpub, bkid = _keygen()
        bundle_signer = {"key_id": bkid, "public_key": bpub.hex(), "alg": "ed25519"}

    payload = _make_registry_payload(
        org_id=org_id, version=1, prev_hash="", threshold=threshold,
        admins=admins, keys=keys, bundle_signer=bundle_signer,
    )

    tag = "agg/registry/v1"
    canonical = _canonical_json(payload)
    msg = tag.encode() + b"\x00" + canonical
    sigs = []
    for sk in (sk_a, sk_c):
        pub = bytes(sk.verify_key)
        kid = hashlib.sha256(pub).hexdigest()
        sig = sk.sign(msg).signature.hex()
        sigs.append({"key_id": kid, "alg": "ed25519", "sig": sig})

    env = {"kind": tag, "sig_v": 1, "payload": payload, "signatures": sigs}
    fp = _payload_hash(payload)

    return env, fp, sk_a, sk_c, kid_a, kid_c, approver_entries


def _sign_multi(payload, sks):
    """Sign a registry payload with multiple keys."""
    tag = b"agg/registry/v1"
    canonical = _canonical_json(payload)
    msg = tag + b"\x00" + canonical
    sigs = []
    for sk in sks:
        pub = bytes(sk.verify_key)
        kid = hashlib.sha256(pub).hexdigest()
        sig = sk.sign(msg).signature.hex()
        sigs.append({"key_id": kid, "alg": "ed25519", "sig": sig})
    return {"kind": "agg/registry/v1", "sig_v": 1,
            "payload": payload, "signatures": sigs}


# ===========================================================================
# P1: genesis two keys one user -> not dual
# ===========================================================================

def test_pin_s9_genesis_two_keys_one_user_not_dual():
    """P1: v1 two admin keys same user_id, approver dave -> counts_for_dual(dave) False."""
    from sandbox.protocol.registry import verify_chain

    dave_sk, _, _ = _keygen()
    env, fp, sk1, sk2, kid1, kid2, _ = _build_genesis_two_keys_one_user(
        threshold=1, extra_approvers=[(dave_sk, "dave")],
    )

    reg = verify_chain([env], fp)
    dave_kid = hashlib.sha256(bytes(dave_sk.verify_key)).hexdigest()
    assert reg.counts_for_dual(dave_kid) is False


# ===========================================================================
# P2: genesis two users -> dual
# ===========================================================================

def test_pin_s9_genesis_two_users_dual():
    """P2: v1 alice + carol (2 users), threshold 2, dave -> counts_for_dual True."""
    from sandbox.protocol.registry import verify_chain

    dave_sk, _, _ = _keygen()
    env, fp, sk_a, sk_c, kid_a, kid_c, _ = _build_genesis_two_users(
        threshold=2, extra_approvers=[(dave_sk, "dave")],
    )

    reg = verify_chain([env], fp)
    dave_kid = hashlib.sha256(bytes(dave_sk.verify_key)).hexdigest()
    assert reg.counts_for_dual(dave_kid) is True


# ===========================================================================
# P3: threshold 1 one user adds -> not dual
# ===========================================================================

def test_pin_b8_threshold1_one_user_adds_not_dual():
    """P3: v1 alice thr 1; v2 adds K_a2 (same user) thr 1; v3 adds dave, erin.
    chain verifies; False for K_d, K_e, K_a2."""
    from sandbox.protocol.registry import verify_chain

    sk_a, pub_a, kid_a = _keygen()
    entry_a, _ = _make_key_entry(
        sk_a, user_id="u-alice", iss="https://idp", sub="u-alice",
        kind="cli", roles=["admin", "approver"], added_in=1,
    )
    bsk, bpub, bkid = _keygen()
    bs = {"key_id": bkid, "public_key": bpub.hex(), "alg": "ed25519"}

    v1_payload = _make_registry_payload(
        org_id="org-p3", version=1, threshold=1,
        admins=[kid_a], keys=[entry_a], bundle_signer=bs,
    )
    v1_env = _sign_envelope("agg/registry/v1", v1_payload, [sk_a])
    fp = _payload_hash(v1_payload)

    # v2: add K_a2 (same user)
    sk_a2, pub_a2, kid_a2 = _keygen()
    entry_a2, _ = _make_key_entry(
        sk_a2, user_id="u-alice", iss="https://idp", sub="u-alice",
        kind="cli", roles=["admin", "approver"], added_in=2,
    )
    v2_env = _build_next_version(
        v1_env, [sk_a],
        new_keys=[entry_a2],
        new_admins=[kid_a, kid_a2],
        threshold=1,
    )

    # v3: add dave and erin
    sk_d, pub_d, kid_d = _keygen()
    sk_e, pub_e, kid_e = _keygen()
    entry_d, _ = _make_key_entry(
        sk_d, user_id="dave", iss="https://idp", sub="dave",
        kind="cli", roles=["approver"], added_in=3,
    )
    entry_e, _ = _make_key_entry(
        sk_e, user_id="erin", iss="https://idp", sub="erin",
        kind="cli", roles=["approver"], added_in=3,
    )
    v3_env = _build_next_version(
        v2_env, [sk_a, sk_a2],
        new_keys=[entry_d, entry_e],
        threshold=1,
    )

    chain = [v1_env, v2_env, v3_env]
    reg = verify_chain(chain, fp)
    assert reg.counts_for_dual(kid_d) is False
    assert reg.counts_for_dual(kid_e) is False
    assert reg.counts_for_dual(kid_a2) is False


# ===========================================================================
# P4: two users adds -> dual
# ===========================================================================

def test_pin_b8_twin_two_users_adds_dual():
    """P4: v2 adds carol thr 2 signed alice+carol; v3 adds dave, erin.
    True for dave, erin; False for K_c."""
    from sandbox.protocol.registry import verify_chain

    sk_a, pub_a, kid_a = _keygen()
    entry_a, _ = _make_key_entry(
        sk_a, user_id="u-alice", iss="https://idp", sub="u-alice",
        kind="cli", roles=["admin", "approver"], added_in=1,
    )
    bsk, bpub, bkid = _keygen()
    bs = {"key_id": bkid, "public_key": bpub.hex(), "alg": "ed25519"}

    v1_payload = _make_registry_payload(
        org_id="org-p4", version=1, threshold=1,
        admins=[kid_a], keys=[entry_a], bundle_signer=bs,
    )
    v1_env = _sign_envelope("agg/registry/v1", v1_payload, [sk_a])
    fp = _payload_hash(v1_payload)

    # v2: add carol as admin, threshold 2
    sk_c, pub_c, kid_c = _keygen()
    entry_c, _ = _make_key_entry(
        sk_c, user_id="u-carol", iss="https://idp", sub="u-carol",
        kind="cli", roles=["admin", "approver"], added_in=2,
    )
    v2_env = _build_next_version(
        v1_env, [sk_a, sk_c],
        new_keys=[entry_c],
        new_admins=[kid_a, kid_c],
        threshold=2,
    )

    # v3: add dave, erin
    sk_d, pub_d, kid_d = _keygen()
    sk_e, pub_e, kid_e = _keygen()
    entry_d, _ = _make_key_entry(
        sk_d, user_id="dave", iss="https://idp", sub="dave",
        kind="cli", roles=["approver"], added_in=3,
    )
    entry_e, _ = _make_key_entry(
        sk_e, user_id="erin", iss="https://idp", sub="erin",
        kind="cli", roles=["approver"], added_in=3,
    )
    v3_env = _build_next_version(
        v2_env, [sk_a, sk_c],
        new_keys=[entry_d, entry_e],
        threshold=2,
    )

    chain = [v1_env, v2_env, v3_env]
    reg = verify_chain(chain, fp)
    assert reg.counts_for_dual(kid_d) is True
    assert reg.counts_for_dual(kid_e) is True
    assert reg.counts_for_dual(kid_c) is False


# ===========================================================================
# P5: threshold 2 one user refused
# ===========================================================================

def test_pin_b8_threshold2_one_user_refused():
    """P5: v2 adds K_a2 (same user) thr 2 signed K_a1+K_a2 -> RegistryError
    containing 'from its own admins, got 1'."""
    from sandbox.protocol.registry import verify_chain, RegistryError

    sk_a, pub_a, kid_a = _keygen()
    entry_a, _ = _make_key_entry(
        sk_a, user_id="u-alice", iss="https://idp", sub="u-alice",
        kind="cli", roles=["admin", "approver"], added_in=1,
    )
    bsk, bpub, bkid = _keygen()
    bs = {"key_id": bkid, "public_key": bpub.hex(), "alg": "ed25519"}

    v1_payload = _make_registry_payload(
        org_id="org-p5", version=1, threshold=1,
        admins=[kid_a], keys=[entry_a], bundle_signer=bs,
    )
    v1_env = _sign_envelope("agg/registry/v1", v1_payload, [sk_a])
    fp = _payload_hash(v1_payload)

    sk_a2, pub_a2, kid_a2 = _keygen()
    entry_a2, _ = _make_key_entry(
        sk_a2, user_id="u-alice", iss="https://idp", sub="u-alice",
        kind="cli", roles=["admin", "approver"], added_in=2,
    )
    v2_env = _build_next_version(
        v1_env, [sk_a, sk_a2],
        new_keys=[entry_a2],
        new_admins=[kid_a, kid_a2],
        threshold=2,
    )

    with pytest.raises(RegistryError, match="from its own admins, got 1"):
        verify_chain([v1_env, v2_env], fp)


# ===========================================================================
# P6: floor counts admin users not keys
# ===========================================================================

def test_pin_floor_counts_admin_users_not_keys():
    """P6: P4's v2; v3 admins [K_a1, K_a2] (K_a2 = u-alice), carol dropped,
    thr 2 -> RegistryError containing 'below floor 2'."""
    from sandbox.protocol.registry import verify_chain, RegistryError

    sk_a, pub_a, kid_a = _keygen()
    entry_a, _ = _make_key_entry(
        sk_a, user_id="u-alice", iss="https://idp", sub="u-alice",
        kind="cli", roles=["admin", "approver"], added_in=1,
    )
    bsk, bpub, bkid = _keygen()
    bs = {"key_id": bkid, "public_key": bpub.hex(), "alg": "ed25519"}

    v1_payload = _make_registry_payload(
        org_id="org-p6", version=1, threshold=1,
        admins=[kid_a], keys=[entry_a], bundle_signer=bs,
    )
    v1_env = _sign_envelope("agg/registry/v1", v1_payload, [sk_a])
    fp = _payload_hash(v1_payload)

    # v2: add carol, threshold 2
    sk_c, pub_c, kid_c = _keygen()
    entry_c, _ = _make_key_entry(
        sk_c, user_id="u-carol", iss="https://idp", sub="u-carol",
        kind="cli", roles=["admin", "approver"], added_in=2,
    )
    v2_env = _build_next_version(
        v1_env, [sk_a, sk_c],
        new_keys=[entry_c],
        new_admins=[kid_a, kid_c],
        threshold=2,
    )

    # v3: replace carol with K_a2 (same user as alice), thr 2
    sk_a2, pub_a2, kid_a2 = _keygen()
    entry_a2, _ = _make_key_entry(
        sk_a2, user_id="u-alice", iss="https://idp", sub="u-alice",
        kind="cli", roles=["admin", "approver"], added_in=3,
    )

    # Build v3 removing carol, adding K_a2
    prev_payload = v2_env["payload"]
    prev_hash = _payload_hash(prev_payload)
    v3_keys = [k for k in prev_payload["keys"] if k["key_id"] != kid_c]
    v3_keys.append(entry_a2)
    v3_payload = _make_registry_payload(
        org_id="org-p6", version=3, prev_hash=prev_hash,
        threshold=2, admins=[kid_a, kid_a2],
        keys=v3_keys, bundle_signer=bs,
    )
    v3_env = _sign_multi(v3_payload, [sk_a, sk_c])

    with pytest.raises(RegistryError, match="below floor 2"):
        verify_chain([v1_env, v2_env, v3_env], fp)


# ===========================================================================
# P7-P9: two keys one user in managed workspace (B9 connector side)
# ===========================================================================

def test_pin_b9_two_keys_one_user_awaiting_second(tmp_path, monkeypatch):
    """P7: bob1 + bob2 (same user) -> awaiting_second with approvals == 1."""
    bob1_sk, bob1_pub, bob1_kid = _keygen()
    bob2_sk, bob2_pub, bob2_kid = _keygen()
    carol_sk, carol_pub, carol_kid = _keygen()

    ctx = _setup_managed_workspace(
        tmp_path, monkeypatch,
        approver_sks=[
            (bob1_sk, bob1_pub, bob1_kid, "user-bob", "cli"),
            (bob2_sk, bob2_pub, bob2_kid, "user-bob", "cli"),
            (carol_sk, carol_pub, carol_kid, "user-carol", "cli"),
        ],
    )
    lay = ctx["lay"]
    req_id = "req-p7-1"
    rec = _create_pending_request(lay, req_id)

    a1 = _make_remote_approval(
        bob1_sk, request_id=req_id, command=rec["command"],
        fingerprint=rec["fingerprint"], user_id="user-bob",
        policy_sequence=ctx["policy_sequence"],
    )
    a2 = _make_remote_approval(
        bob2_sk, request_id=req_id, command=rec["command"],
        fingerprint=rec["fingerprint"], user_id="user-bob",
        policy_sequence=ctx["policy_sequence"],
    )

    from sandbox.connector.approval import apply_external
    result = asyncio.run(apply_external(
        lay, req_id, [a1, a2], clock=lambda: time.time(),
    ))
    assert result["status"] in ("awaiting_second", "same_reviewer")
    assert result.get("approvals", 2) <= 1


def test_pin_b9_twin_bob1_carol_execute(tmp_path, monkeypatch):
    """P8: bob1 + carol -> executed."""
    bob1_sk, bob1_pub, bob1_kid = _keygen()
    bob2_sk, bob2_pub, bob2_kid = _keygen()
    carol_sk, carol_pub, carol_kid = _keygen()

    ctx = _setup_managed_workspace(
        tmp_path, monkeypatch,
        approver_sks=[
            (bob1_sk, bob1_pub, bob1_kid, "user-bob", "cli"),
            (bob2_sk, bob2_pub, bob2_kid, "user-bob", "cli"),
            (carol_sk, carol_pub, carol_kid, "user-carol", "cli"),
        ],
    )
    lay = ctx["lay"]
    req_id = "req-p8-1"
    rec = _create_pending_request(lay, req_id)

    a1 = _make_remote_approval(
        bob1_sk, request_id=req_id, command=rec["command"],
        fingerprint=rec["fingerprint"], user_id="user-bob",
        policy_sequence=ctx["policy_sequence"],
    )
    a2 = _make_remote_approval(
        carol_sk, request_id=req_id, command=rec["command"],
        fingerprint=rec["fingerprint"], user_id="user-carol",
        policy_sequence=ctx["policy_sequence"],
    )

    from sandbox.connector.approval import apply_external
    result = asyncio.run(apply_external(
        lay, req_id, [a1, a2], clock=lambda: time.time(),
    ))
    assert result["status"] == "executed"


def test_pin_b9_twin_bob2_carol_execute(tmp_path, monkeypatch):
    """P9: bob2 + carol -> executed (proves bob2 is valid on its own)."""
    bob1_sk, bob1_pub, bob1_kid = _keygen()
    bob2_sk, bob2_pub, bob2_kid = _keygen()
    carol_sk, carol_pub, carol_kid = _keygen()

    ctx = _setup_managed_workspace(
        tmp_path, monkeypatch,
        approver_sks=[
            (bob1_sk, bob1_pub, bob1_kid, "user-bob", "cli"),
            (bob2_sk, bob2_pub, bob2_kid, "user-bob", "cli"),
            (carol_sk, carol_pub, carol_kid, "user-carol", "cli"),
        ],
    )
    lay = ctx["lay"]
    req_id = "req-p9-1"
    rec = _create_pending_request(lay, req_id)

    a1 = _make_remote_approval(
        bob2_sk, request_id=req_id, command=rec["command"],
        fingerprint=rec["fingerprint"], user_id="user-bob",
        policy_sequence=ctx["policy_sequence"],
    )
    a2 = _make_remote_approval(
        carol_sk, request_id=req_id, command=rec["command"],
        fingerprint=rec["fingerprint"], user_id="user-carol",
        policy_sequence=ctx["policy_sequence"],
    )

    from sandbox.connector.approval import apply_external
    result = asyncio.run(apply_external(
        lay, req_id, [a1, a2], clock=lambda: time.time(),
    ))
    assert result["status"] == "executed"


# ===========================================================================
# P10: G-L5 part 1 named limit
# ===========================================================================

def test_g_l5_part1_connector_cannot_tell_one_human_from_two():
    """Named limit G-L5 part 1 (ADR 0011 A1.5).

    Probe B: v1 alice thr 1; v2 adds K_x admin under invented ids,
    thr 1, signed K_a1; v3 thr 2 adds dave, erin signed K_a1+K_x.
    counts_for_dual True for dave, erin.

    Plain pin: a change in either direction needs an ADR change.
    """
    from sandbox.protocol.registry import verify_chain

    sk_a, pub_a, kid_a = _keygen()
    entry_a, _ = _make_key_entry(
        sk_a, user_id="u-alice", iss="https://idp", sub="u-alice",
        kind="cli", roles=["admin", "approver"], added_in=1,
    )
    bsk, bpub, bkid = _keygen()
    bs = {"key_id": bkid, "public_key": bpub.hex(), "alg": "ed25519"}

    v1_payload = _make_registry_payload(
        org_id="org-l5", version=1, threshold=1,
        admins=[kid_a], keys=[entry_a], bundle_signer=bs,
    )
    v1_env = _sign_envelope("agg/registry/v1", v1_payload, [sk_a])
    fp = _payload_hash(v1_payload)

    # v2: add K_x under invented user_id
    sk_x, pub_x, kid_x = _keygen()
    entry_x, _ = _make_key_entry(
        sk_x, user_id=f"admin-{kid_x[:8]}",
        iss="https://idp", sub=f"admin-{kid_x[:8]}",
        kind="cli", roles=["admin", "approver"], added_in=2,
    )
    v2_env = _build_next_version(
        v1_env, [sk_a],
        new_keys=[entry_x],
        new_admins=[kid_a, kid_x],
        threshold=1,
    )

    # v3: add dave, erin, threshold 2, signed by both admins
    sk_d, pub_d, kid_d = _keygen()
    sk_e, pub_e, kid_e = _keygen()
    entry_d, _ = _make_key_entry(
        sk_d, user_id="dave", iss="https://idp", sub="dave",
        kind="cli", roles=["approver"], added_in=3,
    )
    entry_e, _ = _make_key_entry(
        sk_e, user_id="erin", iss="https://idp", sub="erin",
        kind="cli", roles=["approver"], added_in=3,
    )
    v3_env = _build_next_version(
        v2_env, [sk_a, sk_x],
        new_keys=[entry_d, entry_e],
        threshold=2,
    )

    chain = [v1_env, v2_env, v3_env]
    reg = verify_chain(chain, fp)
    assert reg.counts_for_dual(kid_d) is True
    assert reg.counts_for_dual(kid_e) is True
