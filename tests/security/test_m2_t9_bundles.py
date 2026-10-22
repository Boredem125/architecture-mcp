"""T9 tests-first: signed policy bundles, per-section loosening, connector
base, ``environment``, store, overlay.

Interface contract (pinned -- the build removes only xfail markers)
-------------------------------------------------------------------
Client (connector, MIT):
    sandbox.connector.sync.bundles
        verify_and_apply(
            layout: FolderLayout,
            envelope: dict,
            registry: Registry,          # real T6 Registry from verify_chain
            bundle_signer_pub: bytes,    # raw Ed25519 pub extracted from the
                                         # registry chain's bundle_signer field
            change_approvals: list[dict], # agg/policy-change/v1 envelopes
            *,
            org_id: str,                 # expected binding
            project_id: str,
        ) -> BundleResult
            Verifies the bundle envelope signature against *bundle_signer_pub*
            (trusted only because the pinned registry lists it, D2.2).
            Checks: sequence > current, base_sequence == current, 1 MiB cap,
            strict parse (unknown fields refused), org_id + project_id binding,
            not_before <= now, registry_version >= pinned version.
            Computes per-section loosening against the connector's enforced
            policy (last valid bundle or deny-all if none, N3).
            Loosening needs 2 CLI agg/policy-change/v1 approvals over the
            bundle hash from distinct users with policy_author or approver
            roles.  A tightening needs 1 CLI approval.
            Stores via policy_versions.store() and the signed log.
            Raises BundleError on any failure.

        BundleError  -- raised on any verification or storage failure
        BundleResult -- returned on success; BundleResult.sequence is int

        BUNDLE_MAX_BYTES = 1_048_576  (1 MiB)
        BUNDLE_FIELDS = frozenset({
            "org_id", "project_id", "sequence", "base_sequence",
            "registry_version", "environment",
            "folder_policy", "governance_policy", "mcp_policy",
            "approval", "change_approvals",
            "issued_at", "not_before", "expires_at",
        })

        loosened(enforced: dict, new: dict) -> dict[str, list[str]]
            Per-section loosening.  Returns a dict whose keys are section
            names ("folder_policy", "governance_policy", "mcp_policy",
            "approval", "environment") and whose values are lists of
            loosened dotted field paths within that section.  An empty dict
            means no loosening (the bundle is tightening-only).

        meet_bundle(approved: dict, on_disk: dict) -> dict
            Per-section meet at enforcement time (N5, D2.6).  *approved* is
            the approved bundle payload; *on_disk* is the local tighten-only
            overlay.  Returns the enforced policy dict.  A hand edit that
            loosens any one section has no effect.

    sandbox.connector.sync.state  (existing, extended in T9)
        current_sequence(layout) -> int | None
        current_environment(layout) -> str
        last_valid_bundle(layout) -> dict | None  (existing, T8)

Postgres-free.  Uses ``tests.m2_fakes.FakeSyncServer`` for HTTP, and
test-generated keys for signing.  Registry objects are built with the
REAL committed ``sandbox.protocol.registry.verify_chain``.

Covers threats 6 (forged), 7 (rollback/replay), 8 (downgrade),
9 (server loosens), 10 (expired/withheld), 11 (malformed/huge),
24 (older-looser as tightening), 25 (per-section loosening incl.
environment), 29 (cross-project/org).

Plus: property test "enforced never looser than approved base over
random bundle sequences" (D2.3, S4); per-section hand-edit loosening
has no effect (N5); deny-all first base needs 2 approvals (N3).

RED tests xfail on M2T9Pending.  Guards verify existing code.

T6 rule: the sentinel is raised only by one helper ``_need()`` at the
top of a test; the final assertions are plain ``assert``/``pytest.raises``.
Tests never patch global ``os`` attributes.

Node-id patterns are fixed in M2_BASELINE.md section 5.
"""
from __future__ import annotations

import hashlib
import json
import secrets
import time
from pathlib import Path

import pytest
from nacl.signing import SigningKey

from tests.m2_pending import M2T9Pending
from tests.m2_fakes import FakeSyncServer, FakeResponse

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _need(module: str, attr: str) -> None:
    """Raise M2T9Pending if *module*.*attr* is absent."""
    try:
        mod = __import__(module, fromlist=[attr])
    except ImportError:
        raise M2T9Pending(f"{module} not importable")
    if not hasattr(mod, attr):
        raise M2T9Pending(f"{module}.{attr} not found")


def _keygen():
    """Return (signing_key, pub_bytes, key_id)."""
    sk = SigningKey.generate()
    pub = bytes(sk.verify_key)
    kid = hashlib.sha256(pub).hexdigest()
    return sk, pub, kid


def _canonical_json(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def _sign_envelope(kind: str, payload: dict, signing_keys: list) -> dict:
    """Sign an envelope for test use (same format as protocol.envelope)."""
    tag = kind.encode("utf-8")
    canonical = _canonical_json(payload)
    msg = tag + b"\x00" + canonical
    sigs = []
    for sk in signing_keys:
        pub = bytes(sk.verify_key)
        kid = hashlib.sha256(pub).hexdigest()
        sig = sk.sign(msg).signature.hex()
        sigs.append({"key_id": kid, "alg": "ed25519", "sig": sig})
    return {
        "kind": kind,
        "sig_v": 1,
        "payload": payload,
        "signatures": sigs,
    }


def _make_key_entry(sk=None, *, user_id="alice", iss="https://idp", sub="alice",
                    kind="cli", roles=None, added_in=1):
    """Build a key entry for the registry payload (same as T6)."""
    if sk is None:
        sk, pub, kid = _keygen()
    else:
        pub = bytes(sk.verify_key)
        kid = hashlib.sha256(pub).hexdigest()
    return {
        "key_id": kid,
        "public_key": pub.hex(),
        "user_id": user_id,
        "iss": iss,
        "sub": sub,
        "alg": "ed25519",
        "kind": kind,
        "roles": roles or ["admin", "approver"],
        "added_in": added_in,
    }, sk


def _make_registry_payload(
    *,
    org_id: str = "org-1",
    version: int = 1,
    prev_hash: str = "",
    threshold: int = 1,
    admins: list[str] | None = None,
    keys: list[dict] | None = None,
    bundle_signer: dict | None = None,
    expires_at: float | None = None,
):
    """Build a minimal registry payload dict (same as T6)."""
    return {
        "org_id": org_id,
        "version": version,
        "prev_hash": prev_hash,
        "threshold": threshold,
        "admins": admins or [],
        "keys": keys or [],
        "bundle_signer": bundle_signer or {},
        "expires_at": expires_at or time.time() + 7 * 86400,
    }


def _build_genesis(org_id="org-1", admin_sks=None, bundle_signer_sk=None,
                   threshold=1, expires_at=None):
    """Build a signed genesis and return (envelope, admin_sks, bsk, bpub, bkid).

    Uses the same pattern as test_m2_t6_registry.py.
    """
    if admin_sks is None:
        sk1, _, _ = _keygen()
        admin_sks = [sk1]
    if bundle_signer_sk is None:
        bundle_signer_sk, _, _ = _keygen()
    bpub = bytes(bundle_signer_sk.verify_key)
    bkid = hashlib.sha256(bpub).hexdigest()
    bs_dict = {"key_id": bkid, "public_key": bpub.hex(), "alg": "ed25519"}

    keys = []
    admins = []
    for i, sk in enumerate(admin_sks):
        entry, _ = _make_key_entry(
            sk, user_id=f"admin-{i}", iss="https://idp", sub=f"admin-{i}",
            kind="cli", roles=["admin", "approver"], added_in=1,
        )
        keys.append(entry)
        admins.append(entry["key_id"])
    payload = _make_registry_payload(
        org_id=org_id, version=1, prev_hash="", threshold=threshold,
        admins=admins, keys=keys, bundle_signer=bs_dict,
        expires_at=expires_at or time.time() + 7 * 86400,
    )
    envelope = _sign_envelope("agg/registry/v1", payload, admin_sks)
    return envelope, admin_sks, bundle_signer_sk, bpub, bkid


def _registry_fingerprint(genesis_payload: dict) -> str:
    """Compute the genesis fingerprint (same as registry._payload_hash)."""
    return hashlib.sha256(
        genesis_payload["org_id"].encode("utf-8") + b":" +
        _canonical_json(genesis_payload)
    ).hexdigest()


def _verify_chain(chain: list[dict], fingerprint: str):
    """Call the REAL T6 verify_chain.  Returns a Registry."""
    from sandbox.protocol.registry import verify_chain
    return verify_chain(chain, fingerprint)


def _make_bundle_payload(
    *,
    org_id: str = "org-1",
    project_id: str = "proj-1",
    sequence: int = 1,
    base_sequence: int = 0,
    registry_version: int = 1,
    environment: str | None = None,
    folder_policy: dict | None = None,
    governance_policy: dict | None = None,
    mcp_policy: dict | None = None,
    approval: dict | None = None,
    change_approvals: list | None = None,
    issued_at: float | None = None,
    not_before: float | None = None,
    expires_at: float | None = None,
) -> dict:
    """Build a minimal bundle payload dict.

    When *environment* is None the key is omitted (absent means prod, D2.4).
    """
    now = time.time()
    payload: dict = {
        "org_id": org_id,
        "project_id": project_id,
        "sequence": sequence,
        "base_sequence": base_sequence,
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


def _make_change_approval(bundle_hash: str, sk, *, user_id: str = "alice",
                          nonce: str | None = None) -> dict:
    """Build a policy-change approval envelope over a bundle hash."""
    if nonce is None:
        nonce = secrets.token_hex(16)
    approval_payload = {
        "bundle_hash": bundle_hash,
        "user_id": user_id,
        "key_id": hashlib.sha256(bytes(sk.verify_key)).hexdigest(),
        "nonce": nonce,
        "issued_at": time.time(),
    }
    return _sign_envelope("agg/policy-change/v1", approval_payload, [sk])


def _bundle_hash(payload: dict) -> str:
    """SHA-256 hex of canonical JSON of the bundle payload."""
    return hashlib.sha256(_canonical_json(payload)).hexdigest()


def _build_real_registry(org_id="org-1"):
    """Build a real verified registry and return (registry, bsk, bpub, admin_sks, fingerprint).

    Two admins (admin-0, admin-1), threshold 2, so dual-control tests use
    two distinct users with two distinct keys.
    """
    admin_sks = [_keygen()[0], _keygen()[0]]
    genesis_env, admin_sks, bsk, bpub, bkid = _build_genesis(
        org_id=org_id, admin_sks=admin_sks, threshold=2)
    fp = _registry_fingerprint(genesis_env["payload"])
    registry = _verify_chain([genesis_env], fp)
    return registry, bsk, bpub, admin_sks, fp


@pytest.fixture
def key_home(tmp_path, monkeypatch):
    kh = tmp_path / "keyhome"
    kh.mkdir()
    monkeypatch.setenv("SANDBOX_KEY_HOME", str(kh))
    return kh


def _ws(path: Path):
    """Create a workspace and return the FolderLayout."""
    from sandbox.connector.install import init
    from sandbox.connector.layout import FolderLayout
    path.mkdir(parents=True, exist_ok=True)
    init(path, claude=False, mcp=False)
    return FolderLayout(path)


# ===================================================================
# Guards (pass now -- existing code)
# ===================================================================


def test_guard_envelope_importable():
    """Guard: sandbox.protocol.envelope is importable."""
    from sandbox.protocol.envelope import sign_envelope, verify_envelope, key_id
    assert callable(sign_envelope)
    assert callable(verify_envelope)
    assert callable(key_id)


def test_guard_registry_verify_chain():
    """Guard: the real T6 verify_chain accepts the 2-admin genesis, and the
    genesis lists the bundle signer by key_id = sha256(public key)."""
    genesis_env, admin_sks, bsk, bpub, bkid = _build_genesis(
        admin_sks=[_keygen()[0], _keygen()[0]], threshold=2)
    registry = _verify_chain(
        [genesis_env], _registry_fingerprint(genesis_env["payload"]))
    assert callable(registry.may_sign)
    bs = genesis_env["payload"]["bundle_signer"]
    assert bs["key_id"] == hashlib.sha256(bytes.fromhex(bs["public_key"])).hexdigest()


def test_guard_policy_versions_meet_exists():
    """Guard: policy_versions.meet and loosened_fields exist."""
    from sandbox.connector.policy_versions import meet, loosened_fields
    assert callable(meet)
    assert callable(loosened_fields)


# ===================================================================
# RED: threat 6 -- forged bundle (signature, foreign key, flipped byte)
# ===================================================================


def test_forged_bundle_bad_signature_refused(tmp_path, key_home):
    """A bundle signed by an untrusted key is refused (threat 6)."""
    _need("sandbox.connector.sync.bundles", "verify_and_apply")
    from sandbox.connector.sync.bundles import verify_and_apply, BundleError
    lay = _ws(tmp_path / "ws")
    registry, bsk, bpub, admin_sks, fp = _build_real_registry()
    rogue_sk, _, _ = _keygen()
    payload = _make_bundle_payload()
    envelope = _sign_envelope("agg/bundle/v1", payload, [rogue_sk])
    with pytest.raises(BundleError, match="sign"):
        verify_and_apply(lay, envelope, registry, bpub, [],
                         org_id="org-1", project_id="proj-1")


def test_forged_bundle_flipped_byte_refused(tmp_path, key_home):
    """A bundle with a flipped byte in the payload is refused (threat 6)."""
    _need("sandbox.connector.sync.bundles", "verify_and_apply")
    from sandbox.connector.sync.bundles import verify_and_apply, BundleError
    lay = _ws(tmp_path / "ws")
    registry, bsk, bpub, admin_sks, fp = _build_real_registry()
    payload = _make_bundle_payload()
    envelope = _sign_envelope("agg/bundle/v1", payload, [bsk])
    envelope["payload"]["org_id"] = "org-TAMPERED"
    with pytest.raises(BundleError, match="sign"):
        verify_and_apply(lay, envelope, registry, bpub, [],
                         org_id="org-1", project_id="proj-1")


def test_forged_bundle_embedded_key_ignored(tmp_path, key_home):
    """A key carried inside the bundle payload is ignored (threat 6, strict parse)."""
    _need("sandbox.connector.sync.bundles", "verify_and_apply")
    from sandbox.connector.sync.bundles import verify_and_apply, BundleError
    lay = _ws(tmp_path / "ws")
    registry, bsk, bpub, admin_sks, fp = _build_real_registry()
    rogue_sk, rogue_pub, rogue_kid = _keygen()
    payload = _make_bundle_payload()
    payload["embedded_key"] = {"key_id": rogue_kid, "public_key": rogue_pub.hex()}
    envelope = _sign_envelope("agg/bundle/v1", payload, [rogue_sk])
    with pytest.raises(BundleError, match="field|unknown"):
        verify_and_apply(lay, envelope, registry, bpub, [],
                         org_id="org-1", project_id="proj-1")


def test_bundle_signer_not_in_registry_refused(tmp_path, key_home):
    """A bundle signed by a key that is not the registry's bundle_signer is
    refused, even when the caller passes that key's public key (D2.2)."""
    _need("sandbox.connector.sync.bundles", "verify_and_apply")
    from sandbox.connector.sync.bundles import verify_and_apply, BundleError
    lay = _ws(tmp_path / "ws")
    registry, bsk, bpub, admin_sks, fp = _build_real_registry()
    rogue_sk, rogue_pub, _ = _keygen()
    payload = _make_bundle_payload()
    bh = _bundle_hash(payload)
    envelope = _sign_envelope("agg/bundle/v1", payload, [rogue_sk])
    approvals = [
        _make_change_approval(bh, admin_sks[0], user_id="admin-0"),
        _make_change_approval(bh, admin_sks[1], user_id="admin-1"),
    ]
    with pytest.raises(BundleError, match="signer|bundle_signer"):
        verify_and_apply(lay, envelope, registry, rogue_pub, approvals,
                         org_id="org-1", project_id="proj-1")


def test_one_key_two_user_ids_counts_once(tmp_path, key_home):
    """Two approvals signed by one key under two user_ids count as one user;
    the user comes from the registry entry for key_id, not the payload."""
    _need("sandbox.connector.sync.bundles", "verify_and_apply")
    from sandbox.connector.sync.bundles import verify_and_apply, BundleError
    lay = _ws(tmp_path / "ws")
    registry, bsk, bpub, admin_sks, fp = _build_real_registry()
    p1 = _make_bundle_payload(sequence=1, base_sequence=0)
    bh1 = _bundle_hash(p1)
    e1 = _sign_envelope("agg/bundle/v1", p1, [bsk])
    same_key = [
        _make_change_approval(bh1, admin_sks[0], user_id="admin-0"),
        _make_change_approval(bh1, admin_sks[0], user_id="admin-1"),
    ]
    with pytest.raises(BundleError, match="approv|dual|distinct"):
        verify_and_apply(lay, e1, registry, bpub, same_key,
                         org_id="org-1", project_id="proj-1")


# ===================================================================
# RED: threat 7 -- bundle rollback or replay (sequence, base_sequence)
# ===================================================================


def _apply_first_bundle(lay, registry, bsk, bpub, admin_sks, *,
                        sequence=1, folder_policy=None):
    """Apply a first bundle with 2 CLI approvals (for deny-all base, N3)."""
    from sandbox.connector.sync.bundles import verify_and_apply
    p = _make_bundle_payload(
        sequence=sequence, base_sequence=0,
        folder_policy=folder_policy or {"shell": {"blocklist_action": "deny"}},
    )
    bh = _bundle_hash(p)
    e = _sign_envelope("agg/bundle/v1", p, [bsk])
    approvals = [
        _make_change_approval(bh, admin_sks[0], user_id="admin-0"),
        _make_change_approval(bh, admin_sks[1], user_id="admin-1"),
    ]
    return verify_and_apply(lay, e, registry, bpub, approvals,
                            org_id="org-1", project_id="proj-1")


def test_bundle_sequence_equal_refused(tmp_path, key_home):
    """A bundle with sequence == current is refused (threat 7)."""
    _need("sandbox.connector.sync.bundles", "verify_and_apply")
    from sandbox.connector.sync.bundles import verify_and_apply, BundleError
    lay = _ws(tmp_path / "ws")
    registry, bsk, bpub, admin_sks, fp = _build_real_registry()
    _apply_first_bundle(lay, registry, bsk, bpub, admin_sks, sequence=1)
    p2 = _make_bundle_payload(sequence=1, base_sequence=1)
    e2 = _sign_envelope("agg/bundle/v1", p2, [bsk])
    with pytest.raises(BundleError, match="sequence"):
        verify_and_apply(lay, e2, registry, bpub, [],
                         org_id="org-1", project_id="proj-1")


def test_bundle_sequence_lower_refused(tmp_path, key_home):
    """A bundle with sequence < current is refused (threat 7)."""
    _need("sandbox.connector.sync.bundles", "verify_and_apply")
    from sandbox.connector.sync.bundles import verify_and_apply, BundleError
    lay = _ws(tmp_path / "ws")
    registry, bsk, bpub, admin_sks, fp = _build_real_registry()
    _apply_first_bundle(lay, registry, bsk, bpub, admin_sks, sequence=5)
    p2 = _make_bundle_payload(sequence=3, base_sequence=5)
    e2 = _sign_envelope("agg/bundle/v1", p2, [bsk])
    with pytest.raises(BundleError, match="sequence"):
        verify_and_apply(lay, e2, registry, bpub, [],
                         org_id="org-1", project_id="proj-1")


def test_bundle_stale_base_sequence_refused(tmp_path, key_home):
    """A bundle with base_sequence != current sequence is refused (threat 7)."""
    _need("sandbox.connector.sync.bundles", "verify_and_apply")
    from sandbox.connector.sync.bundles import verify_and_apply, BundleError
    lay = _ws(tmp_path / "ws")
    registry, bsk, bpub, admin_sks, fp = _build_real_registry()
    _apply_first_bundle(lay, registry, bsk, bpub, admin_sks, sequence=2)
    p2 = _make_bundle_payload(sequence=3, base_sequence=1)
    e2 = _sign_envelope("agg/bundle/v1", p2, [bsk])
    with pytest.raises(BundleError, match="base_sequence"):
        verify_and_apply(lay, e2, registry, bpub, [],
                         org_id="org-1", project_id="proj-1")


# ===================================================================
# RED: threat 8 -- downgrade (sig_v, alg)
# ===================================================================


def test_bundle_sig_v_zero_refused(tmp_path, key_home):
    """sig_v: 0 is refused (threat 8)."""
    _need("sandbox.connector.sync.bundles", "verify_and_apply")
    from sandbox.connector.sync.bundles import verify_and_apply, BundleError
    lay = _ws(tmp_path / "ws")
    registry, bsk, bpub, admin_sks, fp = _build_real_registry()
    payload = _make_bundle_payload()
    envelope = _sign_envelope("agg/bundle/v1", payload, [bsk])
    envelope["sig_v"] = 0
    with pytest.raises(BundleError, match="sig_v"):
        verify_and_apply(lay, envelope, registry, bpub, [],
                         org_id="org-1", project_id="proj-1")


def test_bundle_alg_none_refused(tmp_path, key_home):
    """alg: none is refused (threat 8)."""
    _need("sandbox.connector.sync.bundles", "verify_and_apply")
    from sandbox.connector.sync.bundles import verify_and_apply, BundleError
    lay = _ws(tmp_path / "ws")
    registry, bsk, bpub, admin_sks, fp = _build_real_registry()
    payload = _make_bundle_payload()
    envelope = _sign_envelope("agg/bundle/v1", payload, [bsk])
    envelope["signatures"][0]["alg"] = "none"
    with pytest.raises(BundleError, match="alg"):
        verify_and_apply(lay, envelope, registry, bpub, [],
                         org_id="org-1", project_id="proj-1")


# ===================================================================
# RED: threat 9 -- server loosens policy (connector-side base, S4)
# ===================================================================


def test_server_signed_loosening_no_approvals_refused(tmp_path, key_home):
    """A loosening bundle with no change approvals is refused (threat 9)."""
    _need("sandbox.connector.sync.bundles", "verify_and_apply")
    from sandbox.connector.sync.bundles import verify_and_apply, BundleError
    lay = _ws(tmp_path / "ws")
    registry, bsk, bpub, admin_sks, fp = _build_real_registry()
    _apply_first_bundle(lay, registry, bsk, bpub, admin_sks,
                        folder_policy={"shell": {"blocklist_action": "deny"}})
    p2 = _make_bundle_payload(
        sequence=2, base_sequence=1,
        folder_policy={"shell": {"blocklist_action": "allow"}},
    )
    e2 = _sign_envelope("agg/bundle/v1", p2, [bsk])
    with pytest.raises(BundleError, match="approv"):
        verify_and_apply(lay, e2, registry, bpub, [],
                         org_id="org-1", project_id="proj-1")


def test_server_loosening_one_approval_refused(tmp_path, key_home):
    """A loosening bundle with only one CLI approval is refused (threat 9)."""
    _need("sandbox.connector.sync.bundles", "verify_and_apply")
    from sandbox.connector.sync.bundles import verify_and_apply, BundleError
    lay = _ws(tmp_path / "ws")
    registry, bsk, bpub, admin_sks, fp = _build_real_registry()
    _apply_first_bundle(lay, registry, bsk, bpub, admin_sks,
                        folder_policy={"shell": {"blocklist_action": "deny"}})
    p2 = _make_bundle_payload(
        sequence=2, base_sequence=1,
        folder_policy={"shell": {"blocklist_action": "allow"}},
    )
    bh2 = _bundle_hash(p2)
    e2 = _sign_envelope("agg/bundle/v1", p2, [bsk])
    only_one = [_make_change_approval(bh2, admin_sks[0], user_id="admin-0")]
    with pytest.raises(BundleError, match="2.*approv|dual"):
        verify_and_apply(lay, e2, registry, bpub, only_one,
                         org_id="org-1", project_id="proj-1")


def test_tightening_bundle_one_approval_accepted(tmp_path, key_home):
    """A tightening-only bundle needs just one CLI approval (D2.3)."""
    _need("sandbox.connector.sync.bundles", "verify_and_apply")
    from sandbox.connector.sync.bundles import verify_and_apply
    lay = _ws(tmp_path / "ws")
    registry, bsk, bpub, admin_sks, fp = _build_real_registry()
    _apply_first_bundle(lay, registry, bsk, bpub, admin_sks,
                        folder_policy={"shell": {"blocklist_action": "escalate"}})
    p2 = _make_bundle_payload(
        sequence=2, base_sequence=1,
        folder_policy={"shell": {"blocklist_action": "deny"}},
    )
    bh2 = _bundle_hash(p2)
    e2 = _sign_envelope("agg/bundle/v1", p2, [bsk])
    tighten_approvals = [_make_change_approval(bh2, admin_sks[0], user_id="admin-0")]
    result = verify_and_apply(lay, e2, registry, bpub, tighten_approvals,
                              org_id="org-1", project_id="proj-1")
    assert result.sequence == 2


# ===================================================================
# RED: threat 10 -- freeze / expired bundle / rejected bundle
# ===================================================================


def test_bundle_expired_stays_enforced(tmp_path, key_home):
    """An expired bundle stays enforced and alerts policy_stale (threat 10)."""
    _need("sandbox.connector.sync.bundles", "verify_and_apply")
    from sandbox.connector.sync.bundles import verify_and_apply
    lay = _ws(tmp_path / "ws")
    registry, bsk, bpub, admin_sks, fp = _build_real_registry()
    p1 = _make_bundle_payload(
        sequence=1, base_sequence=0,
        expires_at=time.time() - 3600,
    )
    bh1 = _bundle_hash(p1)
    e1 = _sign_envelope("agg/bundle/v1", p1, [bsk])
    approvals1 = [
        _make_change_approval(bh1, admin_sks[0], user_id="admin-0"),
        _make_change_approval(bh1, admin_sks[1], user_id="admin-1"),
    ]
    result = verify_and_apply(lay, e1, registry, bpub, approvals1,
                              org_id="org-1", project_id="proj-1")
    assert result.sequence == 1


def test_bundle_rejected_last_valid_kept(tmp_path, key_home):
    """An invalid bundle is refused; last valid bundle kept (threat 10)."""
    _need("sandbox.connector.sync.bundles", "verify_and_apply")
    _need("sandbox.connector.sync.state", "last_valid_bundle")
    from sandbox.connector.sync.bundles import verify_and_apply, BundleError
    from sandbox.connector.sync.state import last_valid_bundle
    lay = _ws(tmp_path / "ws")
    registry, bsk, bpub, admin_sks, fp = _build_real_registry()
    _apply_first_bundle(lay, registry, bsk, bpub, admin_sks, sequence=1)
    rogue_sk, _, _ = _keygen()
    p2 = _make_bundle_payload(sequence=2, base_sequence=1)
    e2 = _sign_envelope("agg/bundle/v1", p2, [rogue_sk])
    with pytest.raises(BundleError, match="sign"):
        verify_and_apply(lay, e2, registry, bpub, [],
                         org_id="org-1", project_id="proj-1")
    lvb = last_valid_bundle(lay)
    assert lvb is not None, "last_valid_bundle returned None after valid bundle"
    assert lvb["payload"]["sequence"] == 1


# ===================================================================
# RED: threat 11 -- malformed or huge bundle (1 MiB cap, strict parse)
# ===================================================================


def test_oversized_bundle_refused(tmp_path, key_home):
    """A bundle over 1 MiB is refused (threat 11)."""
    _need("sandbox.connector.sync.bundles", "verify_and_apply")
    from sandbox.connector.sync.bundles import verify_and_apply, BundleError, BUNDLE_MAX_BYTES
    lay = _ws(tmp_path / "ws")
    registry, bsk, bpub, admin_sks, fp = _build_real_registry()
    big_data = "x" * (BUNDLE_MAX_BYTES + 1)
    payload = _make_bundle_payload(
        folder_policy={"shell": {"blocklist_action": "deny"}, "_pad": big_data}
    )
    envelope = _sign_envelope("agg/bundle/v1", payload, [bsk])
    with pytest.raises(BundleError, match="size|1048576"):
        verify_and_apply(lay, envelope, registry, bpub, [],
                         org_id="org-1", project_id="proj-1")


def test_malformed_bundle_unknown_fields_refused(tmp_path, key_home):
    """A bundle with unknown fields is refused (threat 11, strict parse)."""
    _need("sandbox.connector.sync.bundles", "verify_and_apply")
    from sandbox.connector.sync.bundles import verify_and_apply, BundleError
    lay = _ws(tmp_path / "ws")
    registry, bsk, bpub, admin_sks, fp = _build_real_registry()
    payload = _make_bundle_payload()
    payload["surprise_field"] = "evil"
    envelope = _sign_envelope("agg/bundle/v1", payload, [bsk])
    with pytest.raises(BundleError, match="unknown|field"):
        verify_and_apply(lay, envelope, registry, bpub, [],
                         org_id="org-1", project_id="proj-1")


# ===================================================================
# RED: threat 24 -- property test: enforced never looser than base
# ===================================================================


def test_property_enforced_never_looser_bundle_sequences(tmp_path, key_home):
    """Property: enforced is never looser than the last authorised base over
    random bundle sequences (D2.3, S4, threat 24).

    Each step picks a random verdict and 0, 1 or 2 approvals from distinct
    admins.  A loosening with <2 approvals raises BundleError and leaves
    the enforced sequence unchanged.  A tightening with >=1 is accepted,
    with 0 refused.  The first bundle loosens the deny-all base (N3) and
    needs 2.
    After every step the stored enforced verdict is never looser than the
    model's last authorised base.  Fixed seed; at least 5 loosening
    refusals and 3 accepted bundles (no vacuous pass).
    """
    _need("sandbox.connector.sync.bundles", "verify_and_apply")
    _need("sandbox.connector.sync.bundles", "loosened")
    _need("sandbox.connector.sync.state", "current_sequence")
    _need("sandbox.connector.sync.state", "last_valid_bundle")
    from sandbox.connector.sync.bundles import verify_and_apply, BundleError
    from sandbox.connector.sync.state import current_sequence, last_valid_bundle
    import random

    rng = random.Random(42)
    registry, bsk, bpub, admin_sks, fp = _build_real_registry()

    verdicts = ["allow", "observe", "escalate", "deny"]
    # 0 = loosest (allow), 3 = strictest (deny)
    verdict_rank = {v: i for i, v in enumerate(verdicts)}

    loosening_refused = 0
    bundles_accepted = 0

    for trial in range(10):
        lay = _ws(tmp_path / f"ws-{trial}")
        model_seq = 0
        model_verdict = "deny"  # deny-all base (N3)

        for step in range(8):
            new_verdict = verdicts[rng.randint(0, 3)]
            new_seq = model_seq + 1
            is_loosening = verdict_rank[new_verdict] < verdict_rank[model_verdict]
            n_approvals = rng.randint(0, 2)

            p = _make_bundle_payload(
                sequence=new_seq,
                base_sequence=model_seq,
                folder_policy={"shell": {"blocklist_action": new_verdict}},
            )
            bh = _bundle_hash(p)
            e = _sign_envelope("agg/bundle/v1", p, [bsk])
            approvals = []
            if n_approvals >= 1:
                approvals.append(
                    _make_change_approval(bh, admin_sks[0], user_id="admin-0"))
            if n_approvals >= 2:
                approvals.append(
                    _make_change_approval(bh, admin_sks[1], user_id="admin-1"))

            # Deny-all first base (N3): the first bundle loosens it, so it
            # needs 2 approvals.  Later: loosening 2, tightening/equal 1.
            needed = 2 if (model_seq == 0 or is_loosening) else 1

            if n_approvals < needed:
                with pytest.raises(BundleError, match="approv|dual"):
                    verify_and_apply(lay, e, registry, bpub, approvals,
                                     org_id="org-1", project_id="proj-1")
                expected_seq = model_seq if model_seq > 0 else None
                assert current_sequence(lay) == expected_seq, (
                    f"trial {trial} step {step}: sequence changed on "
                    f"refused bundle")
                if needed == 2:
                    loosening_refused += 1
            else:
                result = verify_and_apply(lay, e, registry, bpub, approvals,
                                          org_id="org-1", project_id="proj-1")
                assert result.sequence == new_seq
                model_seq = new_seq
                model_verdict = new_verdict
                bundles_accepted += 1

            # After every step: the stored bundle is exactly the last
            # authorised one, so enforced is never looser than the model.
            lvb = last_valid_bundle(lay)
            if model_seq == 0:
                assert lvb is None, (
                    f"trial {trial} step {step}: a bundle was stored with "
                    f"no authorised bundle")
            else:
                assert lvb is not None
                assert lvb["payload"]["sequence"] == model_seq
                enforced_v = lvb["payload"]["folder_policy"]["shell"][
                    "blocklist_action"]
                assert verdict_rank[enforced_v] >= verdict_rank[model_verdict], (
                    f"trial {trial} step {step}: enforced '{enforced_v}' is "
                    f"looser than model base '{model_verdict}'")

    assert loosening_refused >= 5, (
        f"Only {loosening_refused} loosening refusals checked (vacuous)")
    assert bundles_accepted >= 3, (
        f"Only {bundles_accepted} bundles accepted (vacuous)")


# ===================================================================
# RED: threat 25 -- per-section loosening incl. environment
# ===================================================================


def test_loosening_governance_section(tmp_path, key_home):
    """Removing a governance clause is loosening (threat 25, D2.4)."""
    _need("sandbox.connector.sync.bundles", "loosened")
    from sandbox.connector.sync.bundles import loosened
    base = _make_bundle_payload(
        governance_policy={"clauses": [{"id": "g1", "action": "deny", "text": "no prod"}]},
    )
    new = _make_bundle_payload(governance_policy={"clauses": []})
    result = loosened(base, new)
    assert "governance_policy" in result
    assert len(result["governance_policy"]) > 0


def test_loosening_governance_action_weakened(tmp_path, key_home):
    """Weakening a governance clause from deny to escalate is loosening (D2.4)."""
    _need("sandbox.connector.sync.bundles", "loosened")
    from sandbox.connector.sync.bundles import loosened
    base = _make_bundle_payload(
        governance_policy={"clauses": [{"id": "g1", "action": "deny", "text": "no prod"}]},
    )
    new = _make_bundle_payload(
        governance_policy={"clauses": [{"id": "g1", "action": "escalate", "text": "no prod"}]},
    )
    result = loosened(base, new)
    assert "governance_policy" in result
    assert len(result["governance_policy"]) > 0


def test_loosening_mcp_section(tmp_path, key_home):
    """Adding an MCP server or tool is loosening (threat 25, D2.4)."""
    _need("sandbox.connector.sync.bundles", "loosened")
    from sandbox.connector.sync.bundles import loosened
    base = _make_bundle_payload(mcp_policy={"servers": []})
    new = _make_bundle_payload(
        mcp_policy={"servers": [{"name": "evil-server", "tools": ["*"]}]},
    )
    result = loosened(base, new)
    assert "mcp_policy" in result
    assert len(result["mcp_policy"]) > 0


def test_loosening_approval_section(tmp_path, key_home):
    """local_fallback going false to true is loosening (threat 25, D2.4)."""
    _need("sandbox.connector.sync.bundles", "loosened")
    from sandbox.connector.sync.bundles import loosened
    base = _make_bundle_payload(
        approval={"local_fallback": False, "allow_requester": False},
    )
    new = _make_bundle_payload(
        approval={"local_fallback": True, "allow_requester": False},
    )
    result = loosened(base, new)
    assert "approval" in result
    assert len(result["approval"]) > 0


def test_loosening_allow_requester_section(tmp_path, key_home):
    """allow_requester going false to true is loosening (D2.4)."""
    _need("sandbox.connector.sync.bundles", "loosened")
    from sandbox.connector.sync.bundles import loosened
    base = _make_bundle_payload(
        approval={"local_fallback": False, "allow_requester": False},
    )
    new = _make_bundle_payload(
        approval={"local_fallback": False, "allow_requester": True},
    )
    result = loosened(base, new)
    assert "approval" in result
    assert len(result["approval"]) > 0


def test_prod_to_nonprod_is_loosening(tmp_path, key_home):
    """Absent environment (= prod) to staging is loosening (D2.4)."""
    _need("sandbox.connector.sync.bundles", "loosened")
    from sandbox.connector.sync.bundles import loosened
    base = _make_bundle_payload()  # no environment key -> prod
    new = _make_bundle_payload(environment="staging")
    result = loosened(base, new)
    assert "environment" in result
    assert len(result["environment"]) > 0


def test_loosening_folder_section(tmp_path, key_home):
    """Loosening the folder policy section is detected (threat 25)."""
    _need("sandbox.connector.sync.bundles", "loosened")
    from sandbox.connector.sync.bundles import loosened
    base = _make_bundle_payload(
        folder_policy={"shell": {"blocklist_action": "deny"}},
    )
    new = _make_bundle_payload(
        folder_policy={"shell": {"blocklist_action": "allow"}},
    )
    result = loosened(base, new)
    assert "folder_policy" in result
    assert len(result["folder_policy"]) > 0


# ===================================================================
# RED: threat 29 -- cross-project / cross-org bundle refused
# ===================================================================


def test_cross_project_bundle_refused(tmp_path, key_home):
    """A bundle for project B is refused on project A (threat 29)."""
    _need("sandbox.connector.sync.bundles", "verify_and_apply")
    from sandbox.connector.sync.bundles import verify_and_apply, BundleError
    lay = _ws(tmp_path / "ws")
    registry, bsk, bpub, admin_sks, fp = _build_real_registry()
    payload = _make_bundle_payload(project_id="proj-B")
    envelope = _sign_envelope("agg/bundle/v1", payload, [bsk])
    with pytest.raises(BundleError, match="project"):
        verify_and_apply(lay, envelope, registry, bpub, [],
                         org_id="org-1", project_id="proj-A")


def test_cross_org_bundle_refused(tmp_path, key_home):
    """A bundle for org B is refused on org A (threat 29)."""
    _need("sandbox.connector.sync.bundles", "verify_and_apply")
    from sandbox.connector.sync.bundles import verify_and_apply, BundleError
    lay = _ws(tmp_path / "ws")
    registry, bsk, bpub, admin_sks, fp = _build_real_registry()
    payload = _make_bundle_payload(org_id="org-B")
    envelope = _sign_envelope("agg/bundle/v1", payload, [bsk])
    with pytest.raises(BundleError, match="org"):
        verify_and_apply(lay, envelope, registry, bpub, [],
                         org_id="org-A", project_id="proj-1")


# ===================================================================
# RED: N5 -- per-section hand-edit loosening has no effect
# ===================================================================


def test_hand_edit_loosening_folder_no_effect(tmp_path, key_home):
    """A hand edit that loosens the folder section has no effect (N5)."""
    _need("sandbox.connector.sync.bundles", "meet_bundle")
    from sandbox.connector.sync.bundles import meet_bundle
    approved = _make_bundle_payload(
        folder_policy={"shell": {"blocklist_action": "deny"}},
    )
    on_disk = _make_bundle_payload(
        folder_policy={"shell": {"blocklist_action": "allow"}},
    )
    enforced = meet_bundle(approved, on_disk)
    assert enforced["folder_policy"]["shell"]["blocklist_action"] == "deny"


def test_hand_edit_loosening_governance_no_effect(tmp_path, key_home):
    """A hand edit that removes a governance clause has no effect (N5)."""
    _need("sandbox.connector.sync.bundles", "meet_bundle")
    from sandbox.connector.sync.bundles import meet_bundle
    approved = _make_bundle_payload(
        governance_policy={"clauses": [{"id": "g1", "action": "deny", "text": "no prod"}]},
    )
    on_disk = _make_bundle_payload(governance_policy={"clauses": []})
    enforced = meet_bundle(approved, on_disk)
    assert len(enforced["governance_policy"]["clauses"]) == 1


def test_hand_edit_loosening_mcp_no_effect(tmp_path, key_home):
    """A hand edit that adds an MCP server has no effect (N5)."""
    _need("sandbox.connector.sync.bundles", "meet_bundle")
    from sandbox.connector.sync.bundles import meet_bundle
    approved = _make_bundle_payload(mcp_policy={"servers": []})
    on_disk = _make_bundle_payload(
        mcp_policy={"servers": [{"name": "evil", "tools": ["*"]}]},
    )
    enforced = meet_bundle(approved, on_disk)
    assert len(enforced["mcp_policy"]["servers"]) == 0


def test_hand_edit_loosening_approval_no_effect(tmp_path, key_home):
    """A hand edit that sets local_fallback true has no effect (N5)."""
    _need("sandbox.connector.sync.bundles", "meet_bundle")
    from sandbox.connector.sync.bundles import meet_bundle
    approved = _make_bundle_payload(
        approval={"local_fallback": False, "allow_requester": False},
    )
    on_disk = _make_bundle_payload(
        approval={"local_fallback": True, "allow_requester": False},
    )
    enforced = meet_bundle(approved, on_disk)
    assert enforced["approval"]["local_fallback"] is False


def test_hand_edit_loosening_environment_no_effect(tmp_path, key_home):
    """A hand edit that changes environment from prod has no effect (N5)."""
    _need("sandbox.connector.sync.bundles", "meet_bundle")
    from sandbox.connector.sync.bundles import meet_bundle
    approved = _make_bundle_payload()  # absent environment = prod
    on_disk = _make_bundle_payload(environment="staging")
    enforced = meet_bundle(approved, on_disk)
    env = enforced.get("environment")
    assert env is None or env == "prod"


# ===================================================================
# RED: N3 -- deny-all first base needs 2 approvals
# ===================================================================


def test_deny_all_first_base_needs_two_approvals(tmp_path, key_home):
    """No local policy -> deny-all base; first bundle needs 2 CLI approvals (N3)."""
    _need("sandbox.connector.sync.bundles", "verify_and_apply")
    from sandbox.connector.sync.bundles import verify_and_apply, BundleError
    lay = _ws(tmp_path / "ws")
    registry, bsk, bpub, admin_sks, fp = _build_real_registry()
    p1 = _make_bundle_payload(sequence=1, base_sequence=0)
    bh1 = _bundle_hash(p1)
    e1 = _sign_envelope("agg/bundle/v1", p1, [bsk])
    only_one = [_make_change_approval(bh1, admin_sks[0], user_id="admin-0")]
    with pytest.raises(BundleError, match="2.*approv|dual"):
        verify_and_apply(lay, e1, registry, bpub, only_one,
                         org_id="org-1", project_id="proj-1")


def test_deny_all_first_base_two_approvals_accepted(tmp_path, key_home):
    """First bundle with 2 CLI approvals succeeds (N3)."""
    _need("sandbox.connector.sync.bundles", "verify_and_apply")
    from sandbox.connector.sync.bundles import verify_and_apply
    lay = _ws(tmp_path / "ws")
    registry, bsk, bpub, admin_sks, fp = _build_real_registry()
    p1 = _make_bundle_payload(sequence=1, base_sequence=0)
    bh1 = _bundle_hash(p1)
    e1 = _sign_envelope("agg/bundle/v1", p1, [bsk])
    two = [
        _make_change_approval(bh1, admin_sks[0], user_id="admin-0"),
        _make_change_approval(bh1, admin_sks[1], user_id="admin-1"),
    ]
    result = verify_and_apply(lay, e1, registry, bpub, two,
                              org_id="org-1", project_id="proj-1")
    assert result.sequence == 1


# ===================================================================
# RED: not_before in the future (D2.5), older registry version (D2.5)
# ===================================================================


def test_bundle_not_before_future_refused(tmp_path, key_home):
    """A bundle with not_before in the future is refused (D2.5)."""
    _need("sandbox.connector.sync.bundles", "verify_and_apply")
    from sandbox.connector.sync.bundles import verify_and_apply, BundleError
    lay = _ws(tmp_path / "ws")
    registry, bsk, bpub, admin_sks, fp = _build_real_registry()
    payload = _make_bundle_payload(not_before=time.time() + 3600)
    envelope = _sign_envelope("agg/bundle/v1", payload, [bsk])
    with pytest.raises(BundleError, match="not_before"):
        verify_and_apply(lay, envelope, registry, bpub, [],
                         org_id="org-1", project_id="proj-1")


def test_bundle_older_registry_version_refused(tmp_path, key_home):
    """A bundle referencing an older registry version is refused (D2.5)."""
    _need("sandbox.connector.sync.bundles", "verify_and_apply")
    from sandbox.connector.sync.bundles import verify_and_apply, BundleError
    lay = _ws(tmp_path / "ws")
    # Registry at version 1; bundle claims version 0 (older)
    registry, bsk, bpub, admin_sks, fp = _build_real_registry()
    payload = _make_bundle_payload(registry_version=0)
    envelope = _sign_envelope("agg/bundle/v1", payload, [bsk])
    with pytest.raises(BundleError, match="registry.*version"):
        verify_and_apply(lay, envelope, registry, bpub, [],
                         org_id="org-1", project_id="proj-1")
