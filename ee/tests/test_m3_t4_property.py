"""M3 T4 property tests: server row applied unchanged, verdicts equal.

Spec: T4_SPEC.md section 3.2.  5 nodes; the exit.
All 5 fail today (publish_verify missing).
Marked ``pg`` only for test_property_routes_sample.
"""
from __future__ import annotations

import ast
import copy
import hashlib
import importlib
import importlib.util
import json
import os
import random
import shutil
import time
import uuid
from pathlib import Path

import pytest

from .m3_pending import M3T4Pending, require_m3

# Helpers from the publish_verify test file (fixtures and route helpers).
# The t4_server fixture is imported so pytest discovers it in this module.
from .test_m3_t4_publish_verify import (
    t4_server,
    _assert_nothing_written,
    _propose,
    _approve,
    _publish,
    _sign_approval as _route_sign_approval,
    _counts,
    _g1_gate,
    _kid,
    _owner_insert_bundle,
    _make_bundle_envelope,
    _seed_device,
    _make_fresh_session,
)
from .m2_sync_server import create_project
from .t9_helpers import _conninfo

_SRC = Path(__file__).resolve().parent.parent.parent / "src"


# ---------------------------------------------------------------------------
# Helpers: registry building
# ---------------------------------------------------------------------------

def _make_key(sk, user_id, kind="cli", roles=None, added_in=1):
    pub = bytes(sk.verify_key)
    kid = hashlib.sha256(pub).hexdigest()
    return {
        "key_id": kid,
        "public_key": pub.hex(),
        "user_id": user_id,
        "iss": "test", "sub": f"s-{user_id[:8]}",
        "alg": "ed25519",
        "kind": kind,
        "roles": roles or ["approver"],
        "added_in": added_in,
    }


def _sign_genesis(payload, sks):
    from sandbox.protocol.envelope import canonical_bytes
    msg = canonical_bytes("agg/registry/v1", payload)
    sigs = []
    for sk in sks:
        pub = bytes(sk.verify_key)
        kid = hashlib.sha256(pub).hexdigest()
        sig = sk.sign(msg).signature.hex()
        sigs.append({"key_id": kid, "alg": "ed25519", "sig": sig})
    return {
        "kind": "agg/registry/v1", "sig_v": 1,
        "payload": payload,
        "signatures": sigs,
    }


def _build_registry(org_id, keys, bundle_signer_pub, bundle_signer_kid,
                     admin_sks, threshold=2):
    from sandbox.protocol.registry import verify_chain
    payload = {
        "org_id": org_id,
        "version": 1,
        "prev_hash": "",
        "threshold": threshold,
        "admins": [hashlib.sha256(bytes(sk.verify_key)).hexdigest()
                   for sk in admin_sks],
        "keys": keys,
        "bundle_signer": {
            "key_id": bundle_signer_kid,
            "public_key": bundle_signer_pub.hex(),
            "alg": "ed25519",
        },
        "expires_at": time.time() + 7 * 86400,
    }
    genesis = _sign_genesis(payload, admin_sks)
    fp = hashlib.sha256(
        org_id.encode() + b":" +
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    registry = verify_chain([genesis], fp)
    return registry, [genesis], fp


def _sign_approval(sk, bundle_hash):
    from sandbox.protocol.envelope import canonical_bytes
    a_payload = {"bundle_hash": bundle_hash}
    msg = canonical_bytes("agg/policy-change/v1", a_payload)
    pub = bytes(sk.verify_key)
    kid = hashlib.sha256(pub).hexdigest()
    sig = sk.sign(msg).signature.hex()
    return {
        "kind": "agg/policy-change/v1", "sig_v": 1,
        "payload": a_payload,
        "signatures": [{"key_id": kid, "alg": "ed25519", "sig": sig}],
    }


def _random_payload(rng, org_id, project_id, sequence, base_sequence,
                    registry_version=1):
    sections = {}
    if rng.random() > 0.2:
        actions = ["deny", "escalate", "observe", "allow"]
        sections["folder_policy"] = {
            "shell": {"blocklist_action": rng.choice(actions)}
        }
    if rng.random() > 0.2:
        clause_ids = ["c1", "c2", "c3", "c4"]
        clauses = []
        for cid in rng.sample(clause_ids, rng.randint(0, len(clause_ids))):
            clauses.append({
                "id": cid,
                "action": rng.choice(["deny", "escalate", "observe", "allow"]),
            })
        sections["governance_policy"] = {"clauses": clauses}
    if rng.random() > 0.2:
        servers_pool = ["s1", "s2", "s3"]
        servers = []
        for s in rng.sample(servers_pool, rng.randint(0, len(servers_pool))):
            tools_pool = ["t1", "t2"]
            servers.append({
                "name": s,
                "tools": rng.sample(tools_pool, rng.randint(0, len(tools_pool))),
            })
        sections["mcp_policy"] = {"servers": servers}
    if rng.random() > 0.2:
        sections["approval"] = {
            "local_fallback": rng.choice([True, False]),
            "allow_requester": rng.choice([True, False]),
        }

    env_choices = [None, "prod", "staging", "dev"]
    env = rng.choice(env_choices)

    p = {
        **sections,
        "org_id": org_id,
        "project_id": project_id,
        "sequence": sequence,
        "base_sequence": base_sequence,
        "registry_version": registry_version,
        "issued_at": 1_700_000_000,
        "not_before": 1_700_000_000,
    }
    if env is not None:
        p["environment"] = env
    return p


def _sign_bundle_envelope(payload, bundle_signer_sk):
    """Sign a bundle payload, producing a full agg/bundle/v1 envelope."""
    from sandbox.protocol.envelope import canonical_bytes
    bs_pub = bytes(bundle_signer_sk.verify_key)
    bs_kid = hashlib.sha256(bs_pub).hexdigest()
    msg = canonical_bytes("agg/bundle/v1", payload)
    sig = bundle_signer_sk.sign(msg).signature.hex()
    return {
        "kind": "agg/bundle/v1", "sig_v": 1,
        "payload": payload,
        "signatures": [{"key_id": bs_kid, "alg": "ed25519", "sig": sig}],
    }


def _key_id(sk):
    return hashlib.sha256(bytes(sk.verify_key)).hexdigest()


# ---------------------------------------------------------------------------
# Module-scoped key setup
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def property_keys():
    from nacl.signing import SigningKey

    org_id = str(uuid.uuid4())
    project_id = str(uuid.uuid4())

    # Users u1-u6
    users = [str(uuid.uuid4()) for _ in range(6)]
    sks = [SigningKey.generate() for _ in range(6)]

    bundle_signer_sk = SigningKey.generate()
    bs_pub = bytes(bundle_signer_sk.verify_key)
    bs_kid = hashlib.sha256(bs_pub).hexdigest()

    # Keys: u1-u6 each with one cli key, plus browser(u1), viewer(u2),
    # second cli(u3)
    keys = []
    for i, (sk, uid) in enumerate(zip(sks, users)):
        keys.append(_make_key(sk, uid, "cli", ["approver"], added_in=1))

    # Browser key for u1
    browser_sk = SigningKey.generate()
    keys.append(_make_key(browser_sk, users[0], "browser", ["approver"],
                          added_in=1))
    # Viewer key for u2
    viewer_sk = SigningKey.generate()
    keys.append(_make_key(viewer_sk, users[1], "cli", ["viewer"], added_in=1))
    # Second cli key for u3
    u3_sk2 = SigningKey.generate()
    keys.append(_make_key(u3_sk2, users[2], "cli", ["approver"], added_in=1))

    # Build R_dual (threshold 2)
    admin_sks = sks[:2]  # u1 and u2 are admins
    for k in keys[:2]:
        k["roles"] = ["admin", "approver"]
    r_dual, chain_dual, fp_dual = _build_registry(
        org_id, keys, bs_pub, bs_kid, admin_sks, threshold=2)

    # Build R_single (threshold 1)
    r_single, chain_single, fp_single = _build_registry(
        org_id, keys, bs_pub, bs_kid, [sks[0]], threshold=1)

    return {
        "org_id": org_id,
        "project_id": project_id,
        "users": users,
        "sks": sks,
        "bundle_signer_sk": bundle_signer_sk,
        "bs_pub": bs_pub,
        "bs_kid": bs_kid,
        "browser_sk": browser_sk,
        "viewer_sk": viewer_sk,
        "u3_sk2": u3_sk2,
        "r_dual": r_dual,
        "r_single": r_single,
        "chain_dual": chain_dual,
        "chain_single": chain_single,
        "fp_dual": fp_dual,
        "fp_single": fp_single,
        "keys": keys,
    }


# ---------------------------------------------------------------------------
# Generator: draw a class, build a candidate to hit it
# ---------------------------------------------------------------------------

# P1 classes and expected codes per spec 3.2 rule 1
_P1_CLASSES = {
    "accept": 201,
    "single": "approvals_insufficient",
    "forged": "approvals_insufficient",
    "wrong_hash": "approvals_insufficient",
    "wrong_kind": "approvals_insufficient",
    "non_counting_role": "approvals_insufficient",
    "head_m2_loosening": "approvals_insufficient",
    "single_admin_key": "approvals_insufficient",
    "loosened_vs_server_base_only": "approvals_insufficient",
    "first_server_after_m2": "approvals_insufficient",
    "proposer_in_approvals": "proposer_in_approvals",
    "publisher_in_approvals": "publisher_in_approvals",
}

# Weighted class pools.  Weights chosen so the 20% acceptance, the
# 30 / 10 m2-head / smaller-copied thresholds, and at least 1 of
# every refusal class all hold over 300 seeds on a correct build.
# No pre-build measured numbers are stated here.
_P1_POOL = (
    ["accept"] * 5
    + [c for c in _P1_CLASSES if c != "accept"]
)
_P2_CLASSES = {
    "accept": 201,
    "single": "approvals_insufficient",
    "forged": "approvals_insufficient",
    "wrong_hash": "approvals_insufficient",
    "wrong_kind": "approvals_insufficient",
    "non_counting_role": "approvals_insufficient",
}
_P2_POOL = (
    ["accept"] * 2
    + [c for c in _P2_CLASSES if c != "accept"]
)


def _generate_candidate(rng, pk, cls, is_p2=False):
    """Build a candidate for the given class label.

    Returns a dict with keys:
      class_label, payload, approvals (list of envelopes),
      registry, chain, fp, server_base (payload or None),
      head (payload or None), proposer_id, publisher_id,
      earlier_rows (list of dicts with keys payload, label),
      use_single (bool), stored_hash, payload_bytes,
      m2_head (bool: whether head is m2_unverified)
    """
    from sandbox.connector.sync.bundles import (
        _bundle_hash, _canonical_json_bytes, loosened, BundleError,
    )

    users = pk["users"]
    sks = pk["sks"]
    bs_sk = pk["bundle_signer_sk"]
    org_id = pk["org_id"]
    project_id = pk["project_id"]

    # Choose registry
    use_single = False
    if cls == "single_admin_key":
        use_single = True

    if use_single:
        registry = pk["r_single"]
        chain = pk["chain_single"]
        fp = pk["fp_single"]
    else:
        registry = pk["r_dual"]
        chain = pk["chain_dual"]
        fp = pk["fp_dual"]

    # Choose proposer and publisher (u3-u5 by default, distinct from each
    # other and from the approvers u0-u2 except in the exclusion classes)
    if cls == "proposer_in_approvals":
        # Proposer = u2, who is also one of the approvers
        proposer_idx = 2
        publisher_idx = 3
    elif cls == "publisher_in_approvals":
        # Publisher = u2, who is also one of the approvers
        proposer_idx = 3
        publisher_idx = 2
    else:
        proposer_idx = rng.choice([3, 4, 5])
        publisher_idx = rng.choice([i for i in [3, 4, 5] if i != proposer_idx])

    proposer_id = users[proposer_idx]
    publisher_id = users[publisher_idx]

    # Build earlier rows.  P1: each is m2_unverified with p=0.3, else
    # server.  P2: all server.  Each row gets two valid R_dual approvals
    # and is kept only if the reference connector would accept it.
    # server_base = last server row; head = last row when it is m2.
    earlier_rows = []  # list of {"payload": ..., "label": "server"|"m2_unverified"}

    if cls not in ("head_m2_loosening", "loosened_vs_server_base_only",
                    "first_server_after_m2", "single_admin_key"):
        n_earlier = rng.randint(0, 4)
        # For P1 accept, force at least 1 earlier row to increase
        # the m2-head acceptance rate
        if cls == "accept" and not is_p2 and n_earlier == 0:
            n_earlier = rng.randint(1, 3)
        for i in range(n_earlier):
            seq = len(earlier_rows) + 1
            base_seq = seq - 1
            ep = _random_payload(rng, org_id, project_id, seq, base_seq)
            if is_p2:
                label = "server"
            else:
                # p=0.5 for m2 on accept class, p=0.3 otherwise
                m2_prob = 0.5 if cls == "accept" else 0.3
                label = "m2_unverified" if rng.random() < m2_prob else "server"
            earlier_rows.append({"payload": ep, "label": label})

    # For head_m2_loosening: server row 1 (permissive) + m2 row 2 (strict)
    if cls == "head_m2_loosening":
        sb_payload = _random_payload(rng, org_id, project_id, 1, 0)
        sb_payload["approval"] = {"local_fallback": True,
                                  "allow_requester": True}
        sb_payload.pop("environment", None)
        sb_payload["environment"] = "prod"

        m2_payload = _random_payload(rng, org_id, project_id, 2, 1)
        m2_payload["folder_policy"] = {"shell": {"blocklist_action": "deny"}}
        m2_payload["approval"] = {"local_fallback": False,
                                  "allow_requester": False}
        m2_payload.pop("environment", None)
        m2_payload["environment"] = "prod"

        earlier_rows = [
            {"payload": sb_payload, "label": "server"},
            {"payload": m2_payload, "label": "m2_unverified"},
        ]

    # For loosened_vs_server_base_only: server row 1 (strict) + m2 row 2 (permissive)
    if cls == "loosened_vs_server_base_only":
        sb_payload = _random_payload(rng, org_id, project_id, 1, 0)
        sb_payload["folder_policy"] = {"shell": {"blocklist_action": "deny"}}
        sb_payload["approval"] = {"local_fallback": False,
                                  "allow_requester": False}
        sb_payload.pop("environment", None)
        sb_payload["environment"] = "prod"

        m2_payload = _random_payload(rng, org_id, project_id, 2, 1)
        m2_payload["folder_policy"] = {"shell": {"blocklist_action": "allow"}}
        m2_payload["approval"] = {"local_fallback": True,
                                  "allow_requester": True}
        m2_payload.pop("environment", None)
        m2_payload["environment"] = "prod"

        earlier_rows = [
            {"payload": sb_payload, "label": "server"},
            {"payload": m2_payload, "label": "m2_unverified"},
        ]

    # For first_server_after_m2: only m2 rows, no server row
    if cls == "first_server_after_m2":
        if not earlier_rows:
            ep = _random_payload(rng, org_id, project_id, 1, 0)
            earlier_rows = [{"payload": ep, "label": "m2_unverified"}]
        else:
            # Force all to m2
            for row in earlier_rows:
                row["label"] = "m2_unverified"

    # Compute server_base and head from the earlier_rows list
    server_base = None
    head = None
    m2_head = False
    for row in earlier_rows:
        if row["label"] == "server":
            server_base = row["payload"]

    # head is the last row when it differs from server_base
    if earlier_rows:
        last_row = earlier_rows[-1]
        if last_row["label"] == "m2_unverified":
            head = last_row["payload"]
            m2_head = True
        elif last_row["payload"] is not server_base:
            # Last row is server but not the same object as server_base
            # (happens when multiple server rows exist and the last one
            # is also the latest server row, so server_base == last_row
            # and head is None)
            pass

    # Determine sequence
    sequence = len(earlier_rows) + 1
    base_sequence = sequence - 1

    # Build the candidate payload
    payload = _random_payload(rng, org_id, project_id, sequence, base_sequence)

    # For the forced-structure classes, override the payload
    if cls == "head_m2_loosening":
        m2_payload = earlier_rows[1]["payload"]
        payload = dict(m2_payload)
        payload["sequence"] = 3
        payload["base_sequence"] = 2
        payload["approval"] = {"local_fallback": True,
                               "allow_requester": False}

    elif cls == "loosened_vs_server_base_only":
        m2_payload = earlier_rows[1]["payload"]
        payload = dict(m2_payload)
        payload["sequence"] = 3
        payload["base_sequence"] = 2

    elif cls == "first_server_after_m2":
        payload["sequence"] = len(earlier_rows) + 1
        payload["base_sequence"] = len(earlier_rows)
        # Use prod environment to avoid an inadvertent loosening
        payload.pop("environment", None)
        payload["environment"] = "prod"

    # For R_single accept: only when a server base exists and the payload
    # tightens both the base and head.  Then one approval suffices (need 1).
    if cls == "accept" and not is_p2 and rng.random() < 0.25:
        if server_base is not None:
            # Build a tightening from the server base
            use_single = True
            registry = pk["r_single"]
            chain = pk["chain_single"]
            fp = pk["fp_single"]
            # Make the payload a strict tightening: deny everything
            payload["folder_policy"] = {"shell": {"blocklist_action": "deny"}}
            payload["approval"] = {"local_fallback": False,
                                   "allow_requester": False}
            payload.pop("environment", None)
            payload["environment"] = "prod"
            payload["governance_policy"] = {"clauses": []}
            payload["mcp_policy"] = {"servers": []}

    stored_hash = _bundle_hash(payload)
    payload_bytes = _canonical_json_bytes(payload)

    # Build approvals
    approvals = []
    if cls == "accept":
        if use_single and server_base is not None:
            # R_single with a server base: one approval, need 1
            approvals = [_sign_approval(sks[0], stored_hash)]
        else:
            # Two valid approvals from u0 and u1 (distinct users)
            a0 = _sign_approval(sks[0], stored_hash)
            a1 = _sign_approval(sks[1], stored_hash)
            approvals = [a0, a1]
        # With p=0.4, append a forged/other-hash/repeat/u3_second_key
        # for the "copied set smaller than stored" threshold
        if rng.random() < 0.4:
            choice = rng.choice(["forged", "other_hash", "repeat",
                                 "u3_second_key"])
            if choice == "forged":
                from nacl.signing import SigningKey as SK
                rogue = SK.generate()
                approvals.append(_sign_approval(rogue, stored_hash))
            elif choice == "other_hash":
                approvals.append(_sign_approval(sks[2], "0" * 64))
            elif choice == "u3_second_key":
                # Both cli keys of u3 -- same user, two keys
                approvals.append(
                    _sign_approval(sks[2], stored_hash))
                approvals.append(
                    _sign_approval(pk["u3_sk2"], stored_hash))
            else:  # repeat
                approvals.append(copy.deepcopy(approvals[0]))

    elif cls == "single":
        # One valid approval only (need >= 2 for loosening/first)
        approvals = [_sign_approval(sks[0], stored_hash)]

    elif cls == "forged":
        # One valid + one forged (wrong key, not in registry)
        from nacl.signing import SigningKey as SK
        rogue = SK.generate()
        approvals = [
            _sign_approval(sks[0], stored_hash),
            _sign_approval(rogue, stored_hash),
        ]

    elif cls == "wrong_hash":
        # Two approvals but one signs a different hash
        approvals = [
            _sign_approval(sks[0], stored_hash),
            _sign_approval(sks[1], "0" * 64),
        ]

    elif cls == "wrong_kind":
        # One valid cli + one browser key approval
        approvals = [
            _sign_approval(sks[1], stored_hash),
            _sign_approval(pk["browser_sk"], stored_hash),
        ]

    elif cls == "non_counting_role":
        # One valid cli + one viewer-role key
        approvals = [
            _sign_approval(sks[0], stored_hash),
            _sign_approval(pk["viewer_sk"], stored_hash),
        ]

    elif cls == "head_m2_loosening":
        # One approval (need 2 because head loosens)
        approvals = [_sign_approval(sks[0], stored_hash)]

    elif cls == "single_admin_key":
        # R_single: a loosening with two approvals fails counts_for_dual
        # Make payload a loosening
        payload["approval"] = {"local_fallback": True,
                               "allow_requester": True}
        payload.pop("environment", None)
        payload["environment"] = "dev"
        stored_hash = _bundle_hash(payload)
        payload_bytes = _canonical_json_bytes(payload)
        approvals = [
            _sign_approval(sks[0], stored_hash),
            _sign_approval(sks[1], stored_hash),
        ]

    elif cls == "loosened_vs_server_base_only":
        # One approval (need 2: loosened against server base)
        approvals = [_sign_approval(sks[0], stored_hash)]

    elif cls == "first_server_after_m2":
        # One approval (need 2: is_first for server)
        approvals = [_sign_approval(sks[0], stored_hash)]

    elif cls == "proposer_in_approvals":
        # Proposer (u2) signs an approval
        approvals = [
            _sign_approval(sks[0], stored_hash),
            _sign_approval(sks[2], stored_hash),  # u2 = proposer
        ]

    elif cls == "publisher_in_approvals":
        # Publisher (u2) signs an approval
        approvals = [
            _sign_approval(sks[0], stored_hash),
            _sign_approval(sks[2], stored_hash),  # u2 = publisher
        ]

    return {
        "class_label": cls,
        "payload": payload,
        "approvals": approvals,
        "registry": registry,
        "chain": chain,
        "fp": fp,
        "server_base": server_base,
        "head": head,
        "proposer_id": proposer_id,
        "publisher_id": publisher_id,
        "earlier_rows": earlier_rows,
        "use_single": use_single,
        "stored_hash": stored_hash,
        "payload_bytes": payload_bytes,
        "m2_head": m2_head,
    }


def _apply_earlier_rows_to_connector(layout, earlier_rows, pk, registry,
                                     chain, fp):
    """Apply earlier rows through verify_and_apply on the connector.

    *earlier_rows* is a list of dicts with keys ``payload`` and ``label``.
    Returns the list of row payloads that the connector accepted.
    """
    from sandbox.connector.sync.bundles import (
        verify_and_apply, BundleError, _bundle_hash,
    )
    from sandbox.connector.sync.process import _bundle_signer_pub

    bs_pub = _bundle_signer_pub(registry)
    org_id = pk["org_id"]
    project_id = pk["project_id"]
    accepted = []

    for row in earlier_rows:
        row_payload = row["payload"]
        envelope = _sign_bundle_envelope(row_payload, pk["bundle_signer_sk"])
        h = _bundle_hash(row_payload)
        # Build approvals: two valid ones from u0 and u1
        a0 = _sign_approval(pk["sks"][0], h)
        a1 = _sign_approval(pk["sks"][1], h)
        try:
            verify_and_apply(
                layout, envelope, registry, bs_pub, [a0, a1],
                org_id=org_id, project_id=project_id,
            )
            accepted.append(row_payload)
        except BundleError:
            # Row rejected by the connector -- skip it
            pass

    return accepted


def _run_verify_publish(candidate, pk):
    """Run verify_publish on the candidate, return (payload, counted) or raise."""
    from agg_cp.sync.publish_verify import verify_publish

    c = candidate
    now = int(time.time())
    return verify_publish(
        payload_bytes=c["payload_bytes"],
        stored_hash=c["stored_hash"],
        org_id=pk["org_id"],
        project_id=pk["project_id"],
        base_sequence=c["payload"]["base_sequence"],
        sequence=c["payload"]["sequence"],
        approvals=[(a, now) for a in c["approvals"]],
        registry=c["registry"],
        server_base=c["server_base"],
        head=c["head"],
        proposer_id=c["proposer_id"],
        publisher_id=c["publisher_id"],
        now=now,
    )


def _run_sign_and_check(payload, pk, registry):
    """Run sign_and_check with the bundle signer key."""
    from agg_cp.sync.publish_verify import sign_and_check
    return sign_and_check(payload, pk["bundle_signer_sk"], registry)


# ---------------------------------------------------------------------------
# P1: server row applied unchanged
# ---------------------------------------------------------------------------

@pytest.mark.xfail(strict=True, raises=M3T4Pending)
def test_property_server_row_applied_unchanged(property_keys, tmp_path):
    """P1: over 300 seeds, every candidate the server accepts is accepted
    by a connector that applied every earlier row, with the approvals
    the server copies, and that connector's bundle.json bytes equal the
    server's envelope."""
    require_m3(
        4,
        importlib.util.find_spec("agg_cp.sync.publish_verify") is not None,
        "publish_verify module missing (T4)",
    )

    from agg_cp.sync.publish_verify import (
        verify_publish, sign_and_check, deny_all_base, PublishRefused,
    )
    from sandbox.connector.sync.bundles import (
        _bundle_hash, _canonical_json_bytes, verify_and_apply, BundleError,
    )
    from sandbox.connector.sync.process import _bundle_signer_pub
    from sandbox.protocol.registry import verify_chain

    pk = property_keys
    extra_seeds = int(os.environ.get("AGG_T4_PROPERTY_SEEDS", "0"))
    total_seeds = 300 + extra_seeds

    for seed in range(total_seeds):
        rng = random.Random(seed)
        cls = rng.choice(_P1_POOL)

        candidate = _generate_candidate(rng, pk, cls, is_p2=False)

        # Run verify_publish
        try:
            payload, counted = _run_verify_publish(candidate, pk)
            # Server accepted -- verify P1 claim
            envelope = _run_sign_and_check(payload, pk, candidate["registry"])

            # Build a fresh connector layout under tmp_path
            trial_dir = tmp_path / f"p1_s{seed}"
            trial_dir.mkdir(parents=True, exist_ok=True)
            layout_dir = trial_dir / "workspace"
            layout_dir.mkdir(exist_ok=True)
            sb_dir = layout_dir / ".sandbox"
            sb_dir.mkdir(exist_ok=True)

            from sandbox.connector.layout import FolderLayout as Layout
            layout = Layout(layout_dir)

            # Build the connector's registry from its own verify_chain
            ref_registry = verify_chain(
                candidate["chain"], candidate["fp"])
            bs_pub = _bundle_signer_pub(ref_registry)

            # Apply earlier rows through verify_and_apply (trial on a copy)
            _apply_earlier_rows_to_connector(
                layout, candidate["earlier_rows"], pk,
                ref_registry, candidate["chain"], candidate["fp"],
            )

            # Build the approvals list from counted
            counted_envs = [env for env, _, _, _ in counted]

            # --- N7 assertions (MUST 1): copied set invariants ---
            from sandbox.connector.sync.bundles import (
                _verify_change_approvals,
            )
            from agg_cp.sync.publish_verify import (
                approvals_needed, canon_user,
            )

            # (a) Every counted envelope individually verifies
            for ce_idx, (c_env, _, c_cu, c_kid) in enumerate(counted):
                try:
                    _verify_change_approvals(
                        payload, [c_env], candidate["registry"],
                        is_loosening=False, is_first_bundle=False,
                    )
                except BundleError as exc:
                    raise AssertionError(
                        f"seed={seed} class={cls}: counted envelope "
                        f"{ce_idx} (kid={c_kid}) fails individual "
                        f"verify: {exc}"
                    ) from exc

            # (b) Copied canon_users are distinct
            canon_users = [cu for _, _, cu, _ in counted]
            assert len(canon_users) == len(set(canon_users)), (
                f"seed={seed} class={cls}: duplicate canon_user in "
                f"counted: {canon_users}"
            )

            # (c) When need is 2, every counted key counts_for_dual
            need, _ = approvals_needed(
                payload, candidate["server_base"], candidate["head"])
            if need == 2:
                for _, _, _, c_kid in counted:
                    assert candidate["registry"].counts_for_dual(c_kid), (
                        f"seed={seed} class={cls}: counted key "
                        f"{c_kid} does not count for dual (need=2)"
                    )

            # (d) Every counted envelope was in the stored approvals
            stored_envs_canon = [
                json.dumps(a, sort_keys=True, separators=(",", ":"))
                for a in candidate["approvals"]
            ]
            for c_env, _, _, c_kid in counted:
                c_canon = json.dumps(
                    c_env, sort_keys=True, separators=(",", ":"))
                assert c_canon in stored_envs_canon, (
                    f"seed={seed} class={cls}: counted envelope "
                    f"(kid={c_kid}) not in stored approvals"
                )

            # Apply the server's envelope
            try:
                verify_and_apply(
                    layout, envelope, ref_registry, bs_pub, counted_envs,
                    org_id=pk["org_id"], project_id=pk["project_id"],
                )
            except BundleError as e:
                raise AssertionError(
                    f"seed={seed} class={cls}: connector refused server-"
                    f"accepted bundle: {e}"
                ) from e

            # Check bundle.json bytes equal the server envelope
            # Uses _canonical_json_bytes which is how the connector
            # serialises the envelope to bundle.json (bundles.py:570).
            bundle_file = layout_dir / ".sandbox" / "state" / "sync" / "bundle.json"
            assert bundle_file.exists(), (
                f"seed={seed} class={cls}: bundle.json not written"
            )
            stored_bytes = bundle_file.read_bytes()
            envelope_bytes = _canonical_json_bytes(envelope)
            assert stored_bytes == envelope_bytes, (
                f"seed={seed} class={cls}: bundle.json bytes differ from "
                f"server envelope"
            )

            # Clean up the trial dir to save disk
            shutil.rmtree(trial_dir, ignore_errors=True)

        except PublishRefused:
            # Server refused -- ok for non-accept classes
            pass


# ---------------------------------------------------------------------------
# P2: verdicts equal at all-server head
# ---------------------------------------------------------------------------

@pytest.mark.xfail(strict=True, raises=M3T4Pending)
def test_property_verdicts_equal_all_server_at_head(property_keys, tmp_path):
    """P2: over 300 seeds, server accepts iff connector accepts,
    over sequences of only server rows with a connector at the head."""
    require_m3(
        4,
        importlib.util.find_spec("agg_cp.sync.publish_verify") is not None,
        "publish_verify module missing (T4)",
    )

    from agg_cp.sync.publish_verify import (
        verify_publish, sign_and_check, deny_all_base, PublishRefused,
    )
    from sandbox.connector.sync.bundles import (
        _bundle_hash, _canonical_json_bytes, verify_and_apply, BundleError,
    )
    from sandbox.connector.sync.process import _bundle_signer_pub
    from sandbox.protocol.registry import verify_chain

    pk = property_keys
    extra_seeds = int(os.environ.get("AGG_T4_PROPERTY_SEEDS", "0"))
    total_seeds = 300 + extra_seeds

    for seed in range(total_seeds):
        rng = random.Random(seed)
        cls = rng.choice(_P2_POOL)

        candidate = _generate_candidate(rng, pk, cls, is_p2=True)

        # For P2: all-server history, R_dual only, no m2 rows
        # server_base is last server row, head is None (all server)
        # The candidate generator already handles this for is_p2=True

        server_accepted = False
        server_payload = None
        server_counted = None
        server_refused_code = None

        try:
            server_payload, server_counted = _run_verify_publish(candidate, pk)
            server_accepted = True
        except PublishRefused as e:
            server_refused_code = e.code

        # Build a fresh connector layout
        trial_dir = tmp_path / f"p2_s{seed}"
        trial_dir.mkdir(parents=True, exist_ok=True)
        layout_dir = trial_dir / "workspace"
        layout_dir.mkdir(exist_ok=True)
        sb_dir = layout_dir / ".sandbox"
        sb_dir.mkdir(exist_ok=True)

        from sandbox.connector.layout import FolderLayout as Layout
        layout = Layout(layout_dir)

        ref_registry = verify_chain(candidate["chain"], candidate["fp"])
        bs_pub = _bundle_signer_pub(ref_registry)

        # Apply earlier rows (all server rows) through verify_and_apply
        _apply_earlier_rows_to_connector(
            layout, candidate["earlier_rows"], pk,
            ref_registry, candidate["chain"], candidate["fp"],
        )

        if server_accepted:
            # Server accepted: connector must accept too
            envelope = _run_sign_and_check(
                server_payload, pk, candidate["registry"])
            counted_envs = [env for env, _, _, _ in server_counted]
            try:
                verify_and_apply(
                    layout, envelope, ref_registry, bs_pub, counted_envs,
                    org_id=pk["org_id"], project_id=pk["project_id"],
                )
            except BundleError as e:
                raise AssertionError(
                    f"seed={seed} class={cls}: server accepted but connector "
                    f"refused: {e}"
                ) from e
        else:
            # Server refused: connector must refuse too (rule 3)
            # Test signs an envelope with the bundle-signer key
            envelope = _sign_bundle_envelope(
                candidate["payload"], pk["bundle_signer_sk"])
            full_approvals = candidate["approvals"]
            try:
                verify_and_apply(
                    layout, envelope, ref_registry, bs_pub, full_approvals,
                    org_id=pk["org_id"], project_id=pk["project_id"],
                )
                raise AssertionError(
                    f"seed={seed} class={cls}: server refused "
                    f"({server_refused_code}) but connector accepted"
                )
            except BundleError:
                pass  # connector also refused -- correct

        shutil.rmtree(trial_dir, ignore_errors=True)


# ---------------------------------------------------------------------------
# Non-vacuity
# ---------------------------------------------------------------------------

@pytest.mark.xfail(strict=True, raises=M3T4Pending)
def test_property_generator_non_vacuous(property_keys, tmp_path):
    """Rule 2: per refusal class, at least one candidate refused with that
    class's expected code; at least 20% accepted/refused in each property;
    P1 at least 30 accepted with m2 head, at least 10 with smaller copied set."""
    require_m3(
        4,
        importlib.util.find_spec("agg_cp.sync.publish_verify") is not None,
        "publish_verify module missing (T4)",
    )

    from agg_cp.sync.publish_verify import (
        verify_publish, sign_and_check, deny_all_base, PublishRefused,
    )
    from sandbox.connector.sync.bundles import _bundle_hash, _canonical_json_bytes

    pk = property_keys
    extra_seeds = int(os.environ.get("AGG_T4_PROPERTY_SEEDS", "0"))
    total_seeds = 300 + extra_seeds

    # --- P1 tracking ---
    p1_accepted = 0
    p1_refused = 0
    p1_refusal_by_class = {c: 0 for c in _P1_CLASSES if c != "accept"}
    p1_m2_head_accepted = 0
    p1_smaller_copied = 0

    for seed in range(total_seeds):
        rng = random.Random(seed)
        cls = rng.choice(_P1_POOL)
        candidate = _generate_candidate(rng, pk, cls, is_p2=False)

        try:
            payload, counted = _run_verify_publish(candidate, pk)
            p1_accepted += 1
            # Track m2 head
            if candidate["m2_head"]:
                p1_m2_head_accepted += 1
            # Track smaller copied set
            if len(counted) < len(candidate["approvals"]):
                p1_smaller_copied += 1
        except PublishRefused as e:
            p1_refused += 1
            expected = _P1_CLASSES.get(cls)
            if expected != 201 and e.code == expected:
                p1_refusal_by_class[cls] += 1

    # Assert P1 non-vacuity
    total_p1 = p1_accepted + p1_refused
    assert p1_accepted >= total_p1 * 0.2, (
        f"P1 accepted {p1_accepted}/{total_p1} < 20%"
    )
    assert p1_refused >= total_p1 * 0.2, (
        f"P1 refused {p1_refused}/{total_p1} < 20%"
    )
    for cls, count in p1_refusal_by_class.items():
        assert count >= 1, (
            f"P1 class '{cls}': 0 candidates refused with expected code "
            f"{_P1_CLASSES[cls]}"
        )
    assert p1_m2_head_accepted >= 30, (
        f"P1 m2_head accepted {p1_m2_head_accepted} < 30"
    )
    assert p1_smaller_copied >= 10, (
        f"P1 smaller copied set {p1_smaller_copied} < 10"
    )

    # --- P2 tracking ---
    p2_accepted = 0
    p2_refused = 0
    p2_refusal_by_class = {c: 0 for c in _P2_CLASSES if c != "accept"}

    for seed in range(total_seeds):
        rng = random.Random(seed)
        cls = rng.choice(_P2_POOL)
        candidate = _generate_candidate(rng, pk, cls, is_p2=True)

        try:
            _run_verify_publish(candidate, pk)
            p2_accepted += 1
        except PublishRefused as e:
            p2_refused += 1
            expected = _P2_CLASSES.get(cls)
            if expected != 201 and e.code == expected:
                p2_refusal_by_class[cls] += 1

    total_p2 = p2_accepted + p2_refused
    assert p2_accepted >= total_p2 * 0.2, (
        f"P2 accepted {p2_accepted}/{total_p2} < 20%"
    )
    assert p2_refused >= total_p2 * 0.2, (
        f"P2 refused {p2_refused}/{total_p2} < 20%"
    )
    for cls, count in p2_refusal_by_class.items():
        assert count >= 1, (
            f"P2 class '{cls}': 0 candidates refused with expected code "
            f"{_P2_CLASSES[cls]}"
        )


# ---------------------------------------------------------------------------
# P1 through routes (pg, 20-seed sample)
# ---------------------------------------------------------------------------

@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M3T4Pending)
def test_property_routes_sample(t4_server, property_keys, tmp_path):
    """P1 through the real routes: seeds 0-19, up to 3 candidates each.
    Approvals by route; owner-inserted m2_unverified rows with p=0.3.
    Every 201 is fetched with GET /sync/bundle at the published sequence,
    applied unchanged on a fresh layout with the full connector history,
    and its served approvals equal verify_publish's counted set for the
    same input.  Every refusal passes _assert_nothing_written and the
    route error code equals verify_publish's refusal code and the class's
    expected code (spec 3.2 rule 1); a refused accept fails the test.

    dave publishes every candidate.
    The forged row and the two exclusion-class rows are owner-inserted
    with stored user_id frank (so the classes reach the check they are
    named for, not the approval route).  Candidates of one seed share
    one project so server base rows are exercised.
    """
    import httpx
    import psycopg

    info = t4_server
    base_url = info["base_url"]
    conninfo = _conninfo(info["owner_url"])
    org_id = info["org_id"]

    from sandbox.connector.sync.bundles import (
        _bundle_hash, _canonical_json_bytes, verify_and_apply, BundleError,
    )
    from sandbox.connector.sync.process import _bundle_signer_pub
    from sandbox.protocol.registry import verify_chain
    from sandbox.connector.layout import FolderLayout as Layout

    pk = property_keys
    _ROUTE_CLASSES = [
        "accept", "accept", "accept",   # weighted for acceptance
        "single", "forged", "wrong_hash", "non_counting_role",
        "proposer_in_approvals", "publisher_in_approvals",
    ]

    n_201 = 0
    n_refused = 0
    n_reached = 0

    with httpx.Client(base_url=base_url, timeout=30) as client:
        for seed in range(20):
            rng = random.Random(seed)
            n_candidates = rng.randint(1, 3)

            # One project per seed (shared across candidates)
            env_choices = [None, "prod", "staging", "dev"]
            proj_env = rng.choice(env_choices)
            proj_env_str = proj_env or "prod"

            proj_id = str(uuid.uuid4())
            with psycopg.connect(conninfo, autocommit=True) as conn:
                conn.execute(
                    "SELECT set_config('app.org_id', %s, false)",
                    [org_id])
                create_project(conn, org_id, proj_id,
                               f"prop_rs_s{seed}",
                               environment=proj_env_str)
                dev_id, dev_token = _seed_device(
                    conn, org_id, proj_id)

            # Insert m2_unverified earlier rows with p=0.3
            m2_rows_inserted = []
            # Per-seed history: (envelope, approvals, sequence)
            history = []
            n_m2 = rng.randint(0, 2)
            m2_seq = 0
            for mi in range(n_m2):
                if rng.random() < 0.3:
                    m2_seq += 1
                    rp = _random_payload(
                        rng, org_id, proj_id, m2_seq,
                        m2_seq - 1)
                    rp.pop("environment", None)
                    rp["environment"] = proj_env_str
                    with psycopg.connect(conninfo,
                                         autocommit=True) as conn:
                        conn.execute(
                            "SELECT set_config('app.org_id', %s, "
                            "false)", [org_id])
                        _owner_insert_bundle(
                            conn, org_id, proj_id, m2_seq,
                            info["bundle_signer_sk"], rp,
                            verification="m2_unverified")
                    m2_rows_inserted.append(rp)
                    # Build history item for connector replay
                    m_env = _make_bundle_envelope(
                        rp, info["bundle_signer_sk"])
                    m_hash = _bundle_hash(rp)
                    m_a0 = _route_sign_approval(
                        info["alice_sk"], m_hash)
                    m_a1 = _route_sign_approval(
                        info["bob_sk"], m_hash)
                    history.append((m_env, [m_a0, m_a1], m2_seq))

            for ci in range(n_candidates):
                cls = rng.choice(_ROUTE_CLASSES)

                # Build a payload (without server-owned fields)
                payload_sections = {}
                actions = ["deny", "escalate", "observe", "allow"]
                if rng.random() > 0.2:
                    payload_sections["folder_policy"] = {
                        "shell": {
                            "blocklist_action": rng.choice(actions)
                        }
                    }
                if rng.random() > 0.2:
                    payload_sections["approval"] = {
                        "local_fallback": rng.choice([True, False]),
                        "allow_requester": rng.choice([True, False]),
                    }
                propose_body = dict(payload_sections)

                # carol proposes for all classes
                proposer_cookie = info["carol_cookie"]
                proposer_csrf = info["carol_csrf"]
                proposer_id = info["carol_id"]

                # Propose -- assert success, no continue
                r_prop = _propose(
                    client, base_url, proj_id, propose_body,
                    proposer_cookie, proposer_csrf)
                assert r_prop.status_code == 201, (
                    f"seed={seed} ci={ci} class={cls}: propose "
                    f"{r_prop.status_code} {r_prop.text[:200]}")
                prop_id = (r_prop.json().get("id")
                           or r_prop.json().get("proposal_id"))
                bh = (r_prop.json().get("hash")
                      or r_prop.json().get("bundle_hash")
                      or r_prop.json().get("new_sha"))

                # Approve based on class.
                # Owner-inserted rows use user_id frank.
                if cls == "accept":
                    env_a = _route_sign_approval(info["alice_sk"], bh)
                    ra = _approve(client, base_url, prop_id, env_a,
                                  info["alice_cookie"], info["alice_csrf"])
                    assert ra.status_code == 201, (
                        f"seed={seed} ci={ci}: alice approve "
                        f"{ra.status_code}")
                    env_b = _route_sign_approval(info["bob_sk"], bh)
                    rb = _approve(client, base_url, prop_id, env_b,
                                  info["bob_cookie"], info["bob_csrf"])
                    assert rb.status_code == 201, (
                        f"seed={seed} ci={ci}: bob approve "
                        f"{rb.status_code}")
                elif cls == "single":
                    env_a = _route_sign_approval(info["alice_sk"], bh)
                    ra = _approve(client, base_url, prop_id, env_a,
                                  info["alice_cookie"], info["alice_csrf"])
                    assert ra.status_code == 201, (
                        f"seed={seed} ci={ci}: alice approve "
                        f"{ra.status_code}")
                elif cls == "forged":
                    env_a = _route_sign_approval(info["alice_sk"], bh)
                    ra = _approve(client, base_url, prop_id, env_a,
                                  info["alice_cookie"], info["alice_csrf"])
                    assert ra.status_code == 201, (
                        f"seed={seed} ci={ci}: alice approve "
                        f"{ra.status_code}")
                    from nacl.signing import SigningKey as SK
                    rogue = SK.generate()
                    forged_env = _sign_approval(rogue, bh)
                    with psycopg.connect(conninfo,
                                         autocommit=True) as conn:
                        conn.execute(
                            "SELECT set_config('app.org_id', %s, "
                            "false)", [org_id])
                        forged_blob = json.dumps(
                            forged_env, sort_keys=True,
                            separators=(",", ":")).encode()
                        conn.execute(
                            "INSERT INTO policy_change_approvals "
                            "(id, org_id, change_request_id, user_id, "
                            "key_id, signature, signed_at, created_at) "
                            "VALUES (%s, %s::uuid, %s::uuid, %s::uuid, "
                            "%s, %s, now(), now())",
                            [str(uuid.uuid4()), org_id, prop_id,
                             info["frank_id"],
                             _key_id(rogue),
                             forged_blob.decode()])
                elif cls == "wrong_hash":
                    env_a = _route_sign_approval(info["alice_sk"], bh)
                    ra = _approve(client, base_url, prop_id, env_a,
                                  info["alice_cookie"], info["alice_csrf"])
                    assert ra.status_code == 201, (
                        f"seed={seed} ci={ci}: alice approve "
                        f"{ra.status_code}")
                    wrong_env = _sign_approval(
                        info["bob_sk"], "0" * 64)
                    with psycopg.connect(conninfo,
                                         autocommit=True) as conn:
                        conn.execute(
                            "SELECT set_config('app.org_id', %s, "
                            "false)", [org_id])
                        w_blob = json.dumps(
                            wrong_env, sort_keys=True,
                            separators=(",", ":")).encode()
                        conn.execute(
                            "INSERT INTO policy_change_approvals "
                            "(id, org_id, change_request_id, user_id, "
                            "key_id, signature, signed_at, created_at) "
                            "VALUES (%s, %s::uuid, %s::uuid, %s::uuid, "
                            "%s, %s, now(), now())",
                            [str(uuid.uuid4()), org_id, prop_id,
                             info["frank_id"],
                             _kid(info["bob_sk"]),
                             w_blob.decode()])
                elif cls == "non_counting_role":
                    env_a = _route_sign_approval(info["alice_sk"], bh)
                    ra = _approve(client, base_url, prop_id, env_a,
                                  info["alice_cookie"], info["alice_csrf"])
                    assert ra.status_code == 201, (
                        f"seed={seed} ci={ci}: alice approve "
                        f"{ra.status_code}")
                    erin_env = _sign_approval(info["erin_sk"], bh)
                    with psycopg.connect(conninfo,
                                         autocommit=True) as conn:
                        conn.execute(
                            "SELECT set_config('app.org_id', %s, "
                            "false)", [org_id])
                        e_blob = json.dumps(
                            erin_env, sort_keys=True,
                            separators=(",", ":")).encode()
                        conn.execute(
                            "INSERT INTO policy_change_approvals "
                            "(id, org_id, change_request_id, user_id, "
                            "key_id, signature, signed_at, created_at) "
                            "VALUES (%s, %s::uuid, %s::uuid, %s::uuid, "
                            "%s, %s, now(), now())",
                            [str(uuid.uuid4()), org_id, prop_id,
                             info["frank_id"],
                             _kid(info["erin_sk"]),
                             e_blob.decode()])
                elif cls == "proposer_in_approvals":
                    # carol proposes; alice approves; carol's key
                    # approval owner-inserted with user_id frank
                    env_a = _route_sign_approval(info["alice_sk"], bh)
                    ra = _approve(client, base_url, prop_id, env_a,
                                  info["alice_cookie"],
                                  info["alice_csrf"])
                    assert ra.status_code == 201, (
                        f"seed={seed} ci={ci}: alice approve "
                        f"{ra.status_code}")
                    carol_env = _sign_approval(info["carol_sk"], bh)
                    with psycopg.connect(conninfo,
                                         autocommit=True) as conn:
                        conn.execute(
                            "SELECT set_config('app.org_id', %s, "
                            "false)", [org_id])
                        c_blob = json.dumps(
                            carol_env, sort_keys=True,
                            separators=(",", ":")).encode()
                        conn.execute(
                            "INSERT INTO policy_change_approvals "
                            "(id, org_id, change_request_id, user_id, "
                            "key_id, signature, signed_at, created_at) "
                            "VALUES (%s, %s::uuid, %s::uuid, %s::uuid, "
                            "%s, %s, now(), now())",
                            [str(uuid.uuid4()), org_id, prop_id,
                             info["frank_id"],
                             _kid(info["carol_sk"]),
                             c_blob.decode()])
                elif cls == "publisher_in_approvals":
                    # carol proposes; alice approves; dave's key
                    # approval owner-inserted with user_id frank
                    env_a = _route_sign_approval(info["alice_sk"], bh)
                    ra = _approve(client, base_url, prop_id, env_a,
                                  info["alice_cookie"],
                                  info["alice_csrf"])
                    assert ra.status_code == 201, (
                        f"seed={seed} ci={ci}: alice approve "
                        f"{ra.status_code}")
                    dave_env = _sign_approval(info["dave_sk"], bh)
                    with psycopg.connect(conninfo,
                                         autocommit=True) as conn:
                        conn.execute(
                            "SELECT set_config('app.org_id', %s, "
                            "false)", [org_id])
                        d_blob = json.dumps(
                            dave_env, sort_keys=True,
                            separators=(",", ":")).encode()
                        conn.execute(
                            "INSERT INTO policy_change_approvals "
                            "(id, org_id, change_request_id, user_id, "
                            "key_id, signature, signed_at, created_at) "
                            "VALUES (%s, %s::uuid, %s::uuid, %s::uuid, "
                            "%s, %s, now(), now())",
                            [str(uuid.uuid4()), org_id, prop_id,
                             info["frank_id"],
                             _kid(info["dave_sk"]),
                             d_blob.decode()])

                # dave publishes every class except publisher_in_approvals
                pub_cookie = info["dave_cookie"]
                pub_csrf = info["dave_csrf"]
                publisher_id = info["dave_id"]

                # Count before publish
                bc_before = _counts(info["owner_url"], org_id, proj_id)

                # Publish
                rp = _publish(client, base_url, prop_id,
                              pub_cookie, pub_csrf)

                # G1 gate
                _g1_gate(rp)

                n_reached += 1

                # Read pure-verifier input from route-stored data
                with psycopg.connect(conninfo) as conn:
                    conn.execute(
                        "SELECT set_config('app.org_id', %s, "
                        "false)", [org_id])
                    req_row = conn.execute(
                        "SELECT payload, new_sha "
                        "FROM policy_change_requests "
                        "WHERE id = %s::uuid",
                        [prop_id]).fetchone()
                    appr_rows = conn.execute(
                        "SELECT signature, signed_at, key_id "
                        "FROM policy_change_approvals "
                        "WHERE change_request_id = %s::uuid "
                        "ORDER BY key_id",
                        [prop_id]).fetchall()
                    pub_seq = (rp.json().get("sequence")
                               if rp.status_code == 201 else None)
                    sb_q = (
                        "SELECT bundle_blob, sequence "
                        "FROM policy_bundles "
                        "WHERE org_id = %s::uuid "
                        "AND project_id = %s::uuid "
                        "AND verification = 'server' "
                    )
                    if pub_seq is not None:
                        sb_q += "AND sequence < %s "
                        sb_q += "ORDER BY sequence DESC LIMIT 1"
                        sb_row = conn.execute(
                            sb_q, [org_id, proj_id, pub_seq]
                        ).fetchone()
                    else:
                        sb_q += "ORDER BY sequence DESC LIMIT 1"
                        sb_row = conn.execute(
                            sb_q, [org_id, proj_id]).fetchone()
                    req_payload = json.loads(bytes(req_row[0]))
                    base_seq = req_payload["base_sequence"]
                    next_seq = req_payload["sequence"]
                    head_row = None
                    if base_seq > 0:
                        head_row = conn.execute(
                            "SELECT bundle_blob, sequence "
                            "FROM policy_bundles "
                            "WHERE org_id = %s::uuid "
                            "AND project_id = %s::uuid "
                            "AND sequence = %s",
                            [org_id, proj_id, base_seq],
                        ).fetchone()

                stored_payload_bytes = bytes(req_row[0])
                stored_hash = req_row[1]
                stored_approvals = [
                    (json.loads(r[0] if isinstance(r[0], str)
                                else bytes(r[0]).decode()),
                     r[1])
                    for r in appr_rows
                ]
                p_server_base = None
                p_head = None
                if sb_row is not None:
                    try:
                        sb_env = json.loads(bytes(sb_row[0]))
                        p_server_base = sb_env.get("payload")
                    except (json.JSONDecodeError, KeyError):
                        pass
                if (head_row is not None
                        and (sb_row is None
                             or head_row[1] != sb_row[1])):
                    try:
                        h_env = json.loads(bytes(head_row[0]))
                        p_head = h_env.get("payload")
                    except (json.JSONDecodeError, KeyError):
                        pass

                # Registry from stored chain
                with psycopg.connect(conninfo) as conn:
                    conn.execute(
                        "SELECT set_config('app.org_id', %s, "
                        "false)", [org_id])
                    chain_rows = conn.execute(
                        "SELECT registry_blob FROM "
                        "key_registry_versions "
                        "WHERE org_id = %s::uuid "
                        "ORDER BY version",
                        [org_id],
                    ).fetchall()
                stored_chain = [json.loads(bytes(r[0]))
                                for r in chain_rows]
                ref_registry = verify_chain(
                    stored_chain, info["chain_fingerprint"])

                # Run verify_publish (pure) after every publish
                from agg_cp.sync.publish_verify import (
                    verify_publish, PublishRefused,
                )
                pure_accepted = False
                pure_refused_code = None
                try:
                    _, pure_counted = verify_publish(
                        payload_bytes=stored_payload_bytes,
                        stored_hash=stored_hash,
                        org_id=org_id,
                        project_id=proj_id,
                        base_sequence=base_seq,
                        sequence=next_seq,
                        approvals=stored_approvals,
                        registry=ref_registry,
                        server_base=p_server_base,
                        head=p_head,
                        proposer_id=proposer_id,
                        publisher_id=publisher_id,
                        now=int(time.time()),
                    )
                    pure_accepted = True
                except PublishRefused as exc:
                    pure_refused_code = exc.code

                expected_code = _P1_CLASSES[cls]

                if rp.status_code == 201:
                    n_201 += 1
                    # The class label is the independent check: route and
                    # pure verifier share code, so agreement alone proves
                    # nothing.  Only the accept class may publish.
                    assert expected_code == 201, (
                        f"seed={seed} ci={ci} class={cls}: published 201 "
                        f"but class expects {expected_code}")
                    assert pure_accepted, (
                        f"seed={seed} ci={ci} class={cls}: route "
                        f"201 but verify_publish refused "
                        f"({pure_refused_code})")

                    # Served approvals equal the pure counted set
                    pure_kids = sorted(
                        kid for _, _, _, kid in pure_counted)

                    # GET /sync/bundle at the published sequence
                    rb2 = client.get(
                        f"{base_url}/api/v1/sync/bundle",
                        params={"after": str(pub_seq - 1)},
                        headers={
                            "Authorization": f"Bearer {dev_token}"},
                        timeout=10,
                    )
                    assert rb2.status_code == 200, (
                        f"seed={seed} ci={ci} class={cls}: "
                        f"sync/bundle {rb2.status_code}")
                    sb = rb2.json()
                    served_env = sb["envelope"]
                    # Assert served payload sequence matches pub_seq
                    assert served_env["payload"]["sequence"] == pub_seq, (
                        f"seed={seed} ci={ci}: served sequence "
                        f"{served_env['payload']['sequence']} "
                        f"!= pub_seq {pub_seq}")
                    served_approvals = sb.get(
                        "change_approvals", [])
                    served_kids = sorted(
                        a["signatures"][0]["key_id"]
                        for a in served_approvals
                        if a.get("signatures"))
                    assert served_kids == pure_kids, (
                        f"seed={seed} ci={ci} class={cls}: "
                        f"served {served_kids} != "
                        f"pure {pure_kids}")

                    # Read the stored bundle blob from DB
                    resp_data = rp.json()
                    bundle_id = resp_data.get("bundle_id")
                    with psycopg.connect(conninfo) as conn:
                        conn.execute(
                            "SELECT set_config('app.org_id', %s, "
                            "false)", [org_id])
                        blob_row = conn.execute(
                            "SELECT bundle_blob "
                            "FROM policy_bundles "
                            "WHERE id = %s::uuid",
                            [bundle_id]).fetchone()
                    assert blob_row is not None

                    # Build a fresh layout; apply full history
                    # below pub_seq, then the new bundle
                    trial_dir = tmp_path / f"rs_s{seed}_c{ci}"
                    trial_dir.mkdir(parents=True, exist_ok=True)
                    layout_dir = trial_dir / "workspace"
                    layout_dir.mkdir(exist_ok=True)
                    (layout_dir / ".sandbox").mkdir(
                        exist_ok=True)
                    layout = Layout(layout_dir)
                    bs_pub = _bundle_signer_pub(ref_registry)

                    # Apply every history item below pub_seq
                    for h_env, h_app, h_seq in history:
                        if h_seq < pub_seq:
                            try:
                                verify_and_apply(
                                    layout, h_env,
                                    ref_registry,
                                    bs_pub, h_app,
                                    org_id=org_id,
                                    project_id=proj_id,
                                )
                            except BundleError as e:
                                raise AssertionError(
                                    f"seed={seed} ci={ci}: "
                                    f"history seq={h_seq} "
                                    f"apply failed: {e}"
                                ) from e

                    # Apply the served envelope
                    try:
                        verify_and_apply(
                            layout, served_env, ref_registry,
                            bs_pub, served_approvals,
                            org_id=org_id, project_id=proj_id,
                        )
                    except BundleError as e:
                        raise AssertionError(
                            f"seed={seed} ci={ci} class={cls}: "
                            f"connector refused served bundle: "
                            f"{e}"
                        ) from e

                    # bundle.json bytes equal the DB-stored blob
                    bundle_file = (
                        layout_dir / ".sandbox" / "state"
                        / "sync" / "bundle.json"
                    )
                    assert bundle_file.exists(), (
                        f"seed={seed} ci={ci}: bundle.json "
                        f"missing")
                    stored_bytes = bundle_file.read_bytes()
                    db_blob_bytes = bytes(blob_row[0])
                    assert stored_bytes == db_blob_bytes, (
                        f"seed={seed} ci={ci} class={cls}: "
                        f"bundle.json bytes differ from DB blob")

                    shutil.rmtree(trial_dir, ignore_errors=True)

                    # Add to history for subsequent candidates
                    history.append(
                        (served_env, served_approvals, pub_seq))

                else:
                    n_refused += 1
                    route_error = rp.json().get("error", "unknown")
                    # A refused accept must fail the test
                    assert expected_code != 201, (
                        f"seed={seed} ci={ci} class={cls}: "
                        f"accept refused ({route_error})")
                    assert not pure_accepted, (
                        f"seed={seed} ci={ci} class={cls}: route "
                        f"refused ({route_error}) but "
                        f"verify_publish accepted")
                    assert route_error == pure_refused_code, (
                        f"seed={seed} ci={ci} class={cls}: route "
                        f"error={route_error} != pure "
                        f"code={pure_refused_code}")
                    assert route_error == expected_code, (
                        f"seed={seed} ci={ci} class={cls}: "
                        f"route error={route_error} != "
                        f"expected {expected_code}")
                    _assert_nothing_written(
                        info["owner_url"], org_id, proj_id,
                        prop_id, route_error, bc_before)

    # Non-vacuity: at least one 201, at least one refusal,
    # and every candidate reached publish
    assert n_reached > 0, "no candidate reached publish"
    assert n_201 >= 1, f"route sample: 0 accepted (of {n_reached})"
    assert n_refused >= 1, f"route sample: 0 refused (of {n_reached})"


# ---------------------------------------------------------------------------
# AST pin: deny_all_base matches connector literal
# ---------------------------------------------------------------------------

@pytest.mark.xfail(strict=True, raises=M3T4Pending)
def test_server_deny_all_matches_connector_literal():
    """Parse bundles.py, take the dict literal in verify_and_apply's
    no-bundle branch; ast.literal_eval it; equals
    publish_verify.deny_all_base(); no other dict literal with that value
    in ee/src."""
    require_m3(
        4,
        importlib.util.find_spec("agg_cp.sync.publish_verify") is not None,
        "publish_verify module missing (T4)",
    )

    bundles_path = _SRC / "sandbox" / "connector" / "sync" / "bundles.py"
    source = bundles_path.read_text(encoding="utf-8")
    tree = ast.parse(source)

    # Find the dict literal assigned to 'enforced' in verify_and_apply's
    # no-bundle branch
    connector_literal = None
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == "verify_and_apply":
            for child in ast.walk(node):
                if isinstance(child, ast.Assign):
                    for t in child.targets:
                        if isinstance(t, ast.Name) and t.id == "enforced":
                            if isinstance(child.value, ast.Dict):
                                connector_literal = ast.literal_eval(child.value)
    assert connector_literal is not None, (
        "could not extract enforced dict from verify_and_apply"
    )

    from agg_cp.sync.publish_verify import deny_all_base
    assert deny_all_base() == connector_literal

    # No other dict literal with that value in ee/src
    ee_src = Path(__file__).resolve().parent.parent / "src"
    for pyfile in ee_src.rglob("*.py"):
        if "migrations" in str(pyfile):
            continue
        s = pyfile.read_text(encoding="utf-8")
        try:
            t = ast.parse(s)
        except SyntaxError:
            continue
        for n in ast.walk(t):
            if isinstance(n, ast.Dict):
                try:
                    val = ast.literal_eval(n)
                    if val == connector_literal:
                        # Only publish_verify.deny_all_base should have it
                        rel = str(pyfile.relative_to(ee_src))
                        if "publish_verify" not in rel:
                            raise AssertionError(
                                f"deny-all literal found in {rel}:{n.lineno}"
                            )
                except (ValueError, TypeError):
                    pass
