"""T6 tests-first: envelope, tags, kind matrix, registry chain and threshold.

Postgres-free.  All keys are generated in the test.  Covers threats 8,
21-23, 29-31 and the registry half of the kind matrix (D5.1), plus N8.

RED tests xfail on M2T6Pending.  Guards verify existing code (domains, signing).

Node-id patterns are fixed in M2_BASELINE.md section 5.

T6 rule: the sentinel is raised only by one helper ``_need()`` at the
top of a test; the final assertions are plain ``assert``/``pytest.raises``.
Tests never patch global ``os`` attributes.
"""
from __future__ import annotations

import hashlib
import json
import time

import pytest
from nacl.signing import SigningKey

from tests.m2_pending import M2T6Pending

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _need(module: str, attr: str) -> None:
    """Raise M2T6Pending if *module*.*attr* is absent."""
    try:
        mod = __import__(module, fromlist=[attr])
    except ImportError:
        raise M2T6Pending(f"{module} not importable")
    if not hasattr(mod, attr):
        raise M2T6Pending(f"{module}.{attr} not found")


def _keygen():
    """Return (signing_key, pub_bytes, key_id)."""
    sk = SigningKey.generate()
    pub = bytes(sk.verify_key)
    kid = hashlib.sha256(pub).hexdigest()
    return sk, pub, kid


def _canonical_json(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


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
    """Build a minimal registry v1 payload dict."""
    if expires_at is None:
        expires_at = time.time() + 7 * 86400
    if admins is None:
        admins = []
    if keys is None:
        keys = []
    if bundle_signer is None:
        sk, pub, kid = _keygen()
        bundle_signer = {"key_id": kid, "public_key": pub.hex(), "alg": "ed25519"}
    return {
        "org_id": org_id,
        "version": version,
        "prev_hash": prev_hash,
        "threshold": threshold,
        "admins": admins,
        "keys": keys,
        "bundle_signer": bundle_signer,
        "expires_at": expires_at,
    }


def _make_key_entry(sk=None, *, user_id="alice", iss="https://idp", sub="alice",
                    kind="cli", roles=None, added_in=1):
    """Build a key entry for the registry payload."""
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


def _sign_envelope(kind, payload, keys):
    """Sign an envelope the way the module should.
    For bootstrapping test helpers only; the real function is under test."""
    tag = kind.encode("utf-8")
    canonical = _canonical_json(payload)
    msg = tag + b"\x00" + canonical
    sigs = []
    for sk in keys:
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


def _build_genesis(org_id="org-1", admin_sks=None, extra_keys=None,
                   threshold=1, expires_at=None, bundle_signer=None):
    """Build a signed registry v1 (genesis)."""
    if admin_sks is None:
        sk1, _, _ = _keygen()
        admin_sks = [sk1]
    keys = []
    admins = []
    for i, sk in enumerate(admin_sks):
        entry, _ = _make_key_entry(
            sk, user_id=f"admin-{i}", iss="https://idp", sub=f"admin-{i}",
            kind="cli", roles=["admin", "approver"], added_in=1
        )
        keys.append(entry)
        admins.append(entry["key_id"])
    if extra_keys:
        keys.extend(extra_keys)
    if bundle_signer is None:
        bsk, bpub, bkid = _keygen()
        bundle_signer = {"key_id": bkid, "public_key": bpub.hex(), "alg": "ed25519"}
    payload = _make_registry_payload(
        org_id=org_id,
        version=1,
        prev_hash="",
        threshold=threshold,
        admins=admins,
        keys=keys,
        bundle_signer=bundle_signer,
        expires_at=expires_at or time.time() + 7 * 86400,
    )
    return _sign_envelope("agg/registry/v1", payload, admin_sks), admin_sks


def _build_next_version(prev_env, prev_sks, *, new_sks=None, new_keys=None,
                        new_admins=None, version=None, threshold=None,
                        org_id=None, extra_payload=None, expires_at=None,
                        bundle_signer=None):
    """Build a signed registry version chaining from *prev_env*."""
    prev_payload = prev_env["payload"]
    prev_hash = hashlib.sha256(
        prev_payload["org_id"].encode("utf-8") + b":" +
        _canonical_json(prev_payload)
    ).hexdigest()
    v = version if version is not None else prev_payload["version"] + 1
    t = threshold if threshold is not None else prev_payload["threshold"]
    oid = org_id if org_id is not None else prev_payload["org_id"]
    bs = bundle_signer if bundle_signer is not None else prev_payload["bundle_signer"]
    exp = expires_at if expires_at is not None else time.time() + 7 * 86400

    # Build keys and admins for the new version
    all_keys = list(prev_payload.get("keys", []))
    all_admins = list(prev_payload.get("admins", []))
    if new_keys:
        for k in new_keys:
            all_keys.append(k)
    if new_admins:
        all_admins = new_admins

    payload = _make_registry_payload(
        org_id=oid,
        version=v,
        prev_hash=prev_hash,
        threshold=t,
        admins=all_admins,
        keys=all_keys,
        bundle_signer=bs,
        expires_at=exp,
    )
    if extra_payload:
        payload.update(extra_payload)

    signing_keys = new_sks if new_sks is not None else prev_sks
    return _sign_envelope("agg/registry/v1", payload, signing_keys)


# ===================================================================
# Guards (pass now -- existing code)
# ===================================================================


def test_domains_importable():
    """Guard: sandbox.protocol.domains has existing tags."""
    from sandbox.protocol.domains import REGISTRY, BUNDLE, DEVICE_ASSERT, AUDIT_HEAD
    assert REGISTRY == "agg/registry/v1"
    assert BUNDLE == "agg/bundle/v1"
    assert DEVICE_ASSERT == "agg/device-assert/v1"
    assert AUDIT_HEAD == "agg/audit-head/v1"


def test_signing_canonical_json():
    """Guard: signing._canonical produces deterministic JSON."""
    from sandbox.connector.signing import _canonical
    data = {"b": 2, "a": 1}
    result = _canonical(data, ("a", "b"))
    assert result == b'{"a":1,"b":2}'


def test_nacl_ed25519_roundtrip():
    """Guard: Ed25519 sign/verify works."""
    sk = SigningKey.generate()
    msg = b"test-message"
    sig = sk.sign(msg)
    vk = sk.verify_key
    vk.verify(sig.message, sig.signature)


# ===================================================================
# RED: new domain tags (D5.7, ADR 0007 M2 amendment 2)
# ===================================================================


@pytest.mark.xfail(strict=True, raises=M2T6Pending)
def test_domain_tag_remote_approval():
    """agg/remote-approval/v1 tag exists."""
    _need("sandbox.protocol.domains", "REMOTE_APPROVAL")
    from sandbox.protocol.domains import REMOTE_APPROVAL
    assert REMOTE_APPROVAL == "agg/remote-approval/v1"


@pytest.mark.xfail(strict=True, raises=M2T6Pending)
def test_domain_tag_device_enroll():
    """agg/device-enroll/v1 tag exists."""
    _need("sandbox.protocol.domains", "DEVICE_ENROLL")
    from sandbox.protocol.domains import DEVICE_ENROLL
    assert DEVICE_ENROLL == "agg/device-enroll/v1"


@pytest.mark.xfail(strict=True, raises=M2T6Pending)
def test_domain_tag_signer_assert():
    """agg/signer-assert/v1 tag exists."""
    _need("sandbox.protocol.domains", "SIGNER_ASSERT")
    from sandbox.protocol.domains import SIGNER_ASSERT
    assert SIGNER_ASSERT == "agg/signer-assert/v1"


@pytest.mark.xfail(strict=True, raises=M2T6Pending)
def test_domain_tag_unenroll():
    """agg/unenroll/v1 tag exists."""
    _need("sandbox.protocol.domains", "UNENROLL")
    from sandbox.protocol.domains import UNENROLL
    assert UNENROLL == "agg/unenroll/v1"


# ===================================================================
# RED: envelope -- sign_envelope, verify_envelope, key_id, canonical_bytes
# ===================================================================


@pytest.mark.xfail(strict=True, raises=M2T6Pending)
def test_sign_envelope_roundtrip():
    """sign_envelope + verify_envelope round-trips."""
    _need("sandbox.protocol.envelope", "sign_envelope")
    from sandbox.protocol.envelope import sign_envelope, verify_envelope, key_id
    sk, pub, kid = _keygen()
    payload = {"org_id": "org-1", "version": 1}
    env = sign_envelope("agg/registry/v1", payload, [sk])
    assert env["kind"] == "agg/registry/v1"
    assert env["sig_v"] == 1
    assert len(env["signatures"]) == 1
    assert env["signatures"][0]["key_id"] == kid
    result = verify_envelope(env, {kid: pub})
    assert result == payload


@pytest.mark.xfail(strict=True, raises=M2T6Pending)
def test_key_id_is_sha256_hex():
    """key_id(pub_bytes) == sha256(pub_bytes).hex()."""
    _need("sandbox.protocol.envelope", "key_id")
    from sandbox.protocol.envelope import key_id
    sk, pub, _ = _keygen()
    assert key_id(pub) == hashlib.sha256(pub).hexdigest()


@pytest.mark.xfail(strict=True, raises=M2T6Pending)
def test_canonical_bytes_format():
    """canonical_bytes = tag || 0x00 || canonical JSON."""
    _need("sandbox.protocol.envelope", "canonical_bytes")
    from sandbox.protocol.envelope import canonical_bytes
    payload = {"b": 2, "a": 1}
    result = canonical_bytes("agg/registry/v1", payload)
    expected = b"agg/registry/v1\x00" + _canonical_json(payload)
    assert result == expected


@pytest.mark.xfail(strict=True, raises=M2T6Pending)
def test_verify_envelope_flipped_byte():
    """A flipped byte in the signature is refused (threat 6 partial)."""
    _need("sandbox.protocol.envelope", "sign_envelope")
    from sandbox.protocol.envelope import sign_envelope, verify_envelope, EnvelopeError
    sk, pub, kid = _keygen()
    payload = {"org_id": "org-1", "version": 1}
    env = sign_envelope("agg/registry/v1", payload, [sk])
    # Flip one byte in the signature
    sig_bytes = bytes.fromhex(env["signatures"][0]["sig"])
    flipped = bytes([sig_bytes[0] ^ 0xFF]) + sig_bytes[1:]
    env["signatures"][0]["sig"] = flipped.hex()
    with pytest.raises(EnvelopeError) as exc_info:
        verify_envelope(env, {kid: pub})
    assert exc_info.value.reason


@pytest.mark.xfail(strict=True, raises=M2T6Pending)
def test_verify_envelope_foreign_key():
    """A signature from an untrusted key is refused."""
    _need("sandbox.protocol.envelope", "sign_envelope")
    from sandbox.protocol.envelope import sign_envelope, verify_envelope, EnvelopeError
    sk, pub, kid = _keygen()
    other_sk, other_pub, other_kid = _keygen()
    payload = {"org_id": "org-1", "version": 1}
    env = sign_envelope("agg/registry/v1", payload, [sk])
    # Verify with a different trusted set that does not include the signer
    with pytest.raises(EnvelopeError) as exc_info:
        verify_envelope(env, {other_kid: other_pub})
    assert exc_info.value.reason


@pytest.mark.xfail(strict=True, raises=M2T6Pending)
def test_verify_envelope_embedded_key_ignored():
    """A key carried in the payload (embedded) is not used for verification."""
    _need("sandbox.protocol.envelope", "sign_envelope")
    from sandbox.protocol.envelope import sign_envelope, verify_envelope, EnvelopeError
    sk, pub, kid = _keygen()
    payload = {"org_id": "org-1", "version": 1, "embedded_key": pub.hex()}
    env = sign_envelope("agg/registry/v1", payload, [sk])
    # Verify with an empty trusted set -- embedded key must not help
    with pytest.raises(EnvelopeError):
        verify_envelope(env, {})


# ===================================================================
# RED: threat 8 -- downgrade (sig_v 0, alg none, short/extra fields)
# ===================================================================


@pytest.mark.xfail(strict=True, raises=M2T6Pending)
def test_sig_v_zero_refused():
    """sig_v: 0 is refused (threat 8)."""
    _need("sandbox.protocol.envelope", "verify_envelope")
    from sandbox.protocol.envelope import verify_envelope, EnvelopeError
    sk, pub, kid = _keygen()
    env = {"kind": "agg/registry/v1", "sig_v": 0, "payload": {}, "signatures": []}
    with pytest.raises(EnvelopeError) as exc_info:
        verify_envelope(env, {kid: pub})
    assert "sig_v" in str(exc_info.value.reason).lower() or exc_info.value.reason


@pytest.mark.xfail(strict=True, raises=M2T6Pending)
def test_alg_none_refused():
    """alg: 'none' in a signature is refused (threat 8)."""
    _need("sandbox.protocol.envelope", "verify_envelope")
    from sandbox.protocol.envelope import verify_envelope, EnvelopeError
    sk, pub, kid = _keygen()
    # Build a valid-looking envelope but with alg: none
    payload = {"org_id": "org-1", "version": 1}
    env = {
        "kind": "agg/registry/v1",
        "sig_v": 1,
        "payload": payload,
        "signatures": [{"key_id": kid, "alg": "none", "sig": "deadbeef" * 8}],
    }
    with pytest.raises(EnvelopeError) as exc_info:
        verify_envelope(env, {kid: pub})
    assert exc_info.value.reason


@pytest.mark.xfail(strict=True, raises=M2T6Pending)
def test_unknown_kind_refused():
    """An unknown kind is refused (threat 8)."""
    _need("sandbox.protocol.envelope", "verify_envelope")
    from sandbox.protocol.envelope import verify_envelope, EnvelopeError
    sk, pub, kid = _keygen()
    env = {"kind": "agg/evil/v1", "sig_v": 1, "payload": {}, "signatures": []}
    with pytest.raises(EnvelopeError) as exc_info:
        verify_envelope(env, {kid: pub})
    assert exc_info.value.reason


@pytest.mark.xfail(strict=True, raises=M2T6Pending)
def test_extra_field_in_envelope_refused():
    """An extra top-level field in the envelope is refused (threat 8)."""
    _need("sandbox.protocol.envelope", "verify_envelope")
    from sandbox.protocol.envelope import verify_envelope, EnvelopeError
    sk, pub, kid = _keygen()
    payload = {"org_id": "org-1", "version": 1}
    env = {
        "kind": "agg/registry/v1",
        "sig_v": 1,
        "payload": payload,
        "signatures": [{"key_id": kid, "alg": "ed25519", "sig": "aa" * 64}],
        "extra_field": "bad",
    }
    with pytest.raises(EnvelopeError):
        verify_envelope(env, {kid: pub})


@pytest.mark.xfail(strict=True, raises=M2T6Pending)
def test_missing_field_in_envelope_refused():
    """A missing required field (no 'signatures') is refused (threat 8)."""
    _need("sandbox.protocol.envelope", "verify_envelope")
    from sandbox.protocol.envelope import verify_envelope, EnvelopeError
    sk, pub, kid = _keygen()
    env = {"kind": "agg/registry/v1", "sig_v": 1, "payload": {}}
    with pytest.raises(EnvelopeError):
        verify_envelope(env, {kid: pub})


# ===================================================================
# RED: registry -- verify_chain, Registry.may_sign, check_binding
# ===================================================================


@pytest.mark.xfail(strict=True, raises=M2T6Pending)
def test_verify_chain_single_genesis():
    """verify_chain accepts a valid single-version chain."""
    _need("sandbox.protocol.registry", "verify_chain")
    from sandbox.protocol.registry import verify_chain
    sk1, pub1, kid1 = _keygen()
    genesis, sks = _build_genesis(admin_sks=[sk1])
    fp = hashlib.sha256(
        genesis["payload"]["org_id"].encode("utf-8") + b":" +
        _canonical_json(genesis["payload"])
    ).hexdigest()
    reg = verify_chain([genesis], fp)
    assert reg is not None


@pytest.mark.xfail(strict=True, raises=M2T6Pending)
def test_verify_chain_two_versions():
    """verify_chain accepts a valid 2-version chain."""
    _need("sandbox.protocol.registry", "verify_chain")
    from sandbox.protocol.registry import verify_chain
    sk1, pub1, kid1 = _keygen()
    sk2, pub2, kid2 = _keygen()
    genesis, sks = _build_genesis(admin_sks=[sk1])
    entry2, _ = _make_key_entry(sk2, user_id="admin-1", iss="https://idp",
                                sub="admin-1", kind="cli",
                                roles=["admin", "approver"], added_in=2)
    v2 = _build_next_version(
        genesis, sks,
        new_keys=[entry2],
        new_admins=[kid1, kid2],
        threshold=2,
        new_sks=[sk1, sk2],
    )
    fp = hashlib.sha256(
        genesis["payload"]["org_id"].encode("utf-8") + b":" +
        _canonical_json(genesis["payload"])
    ).hexdigest()
    reg = verify_chain([genesis, v2], fp)
    assert reg is not None


# ===================================================================
# RED: threat 22 -- second genesis refused (and alerted)
# ===================================================================


@pytest.mark.xfail(strict=True, raises=M2T6Pending)
def test_second_genesis_refused():
    """A second v1 in the chain is refused (threat 22)."""
    _need("sandbox.protocol.registry", "verify_chain")
    from sandbox.protocol.registry import verify_chain, RegistryError
    sk1, _, _ = _keygen()
    genesis1, sks1 = _build_genesis(admin_sks=[sk1])
    genesis2, sks2 = _build_genesis(admin_sks=[sk1])
    fp = hashlib.sha256(
        genesis1["payload"]["org_id"].encode("utf-8") + b":" +
        _canonical_json(genesis1["payload"])
    ).hexdigest()
    with pytest.raises(RegistryError) as exc_info:
        verify_chain([genesis1, genesis2], fp)
    assert exc_info.value.reason


@pytest.mark.xfail(strict=True, raises=M2T6Pending)
def test_genesis_fingerprint_mismatch_refused():
    """A genesis with wrong fingerprint is refused (threat 22)."""
    _need("sandbox.protocol.registry", "verify_chain")
    from sandbox.protocol.registry import verify_chain, RegistryError
    sk1, _, _ = _keygen()
    genesis, _ = _build_genesis(admin_sks=[sk1])
    with pytest.raises(RegistryError) as exc_info:
        verify_chain([genesis], "wrong-fingerprint")
    assert exc_info.value.reason


# ===================================================================
# RED: threat 23 -- threshold downgrade, duplicate identity, shared key
# ===================================================================


@pytest.mark.xfail(strict=True, raises=M2T6Pending)
def test_threshold_downgrade_refused():
    """Dropping the threshold from 2 to 1 once 2 admins exist is refused (threat 23)."""
    _need("sandbox.protocol.registry", "verify_chain")
    from sandbox.protocol.registry import verify_chain, RegistryError
    sk1, _, kid1 = _keygen()
    sk2, _, kid2 = _keygen()
    genesis, _ = _build_genesis(admin_sks=[sk1], threshold=1)
    entry2, _ = _make_key_entry(sk2, user_id="admin-1", iss="https://idp",
                                sub="admin-1", kind="cli",
                                roles=["admin", "approver"], added_in=2)
    # v2: threshold=2, 2 admins
    v2 = _build_next_version(
        genesis, [sk1],
        new_keys=[entry2],
        new_admins=[kid1, kid2],
        threshold=2,
        new_sks=[sk1, sk2],
    )
    # v3: try to drop back to threshold=1
    v3 = _build_next_version(
        v2, [sk1, sk2],
        threshold=1,
    )
    fp = hashlib.sha256(
        genesis["payload"]["org_id"].encode("utf-8") + b":" +
        _canonical_json(genesis["payload"])
    ).hexdigest()
    with pytest.raises(RegistryError) as exc_info:
        verify_chain([genesis, v2, v3], fp)
    assert exc_info.value.reason


@pytest.mark.xfail(strict=True, raises=M2T6Pending)
def test_threshold_floor_never_below_2_once_2_admins():
    """Once 2 admins exist, threshold can never go below 2 (threat 23)."""
    _need("sandbox.protocol.registry", "verify_chain")
    from sandbox.protocol.registry import verify_chain, RegistryError
    sk1, _, kid1 = _keygen()
    sk2, _, kid2 = _keygen()
    sk3, _, kid3 = _keygen()
    genesis, _ = _build_genesis(admin_sks=[sk1], threshold=1)
    entry2, _ = _make_key_entry(sk2, user_id="admin-1", iss="https://idp",
                                sub="admin-1", kind="cli",
                                roles=["admin", "approver"], added_in=2)
    v2 = _build_next_version(
        genesis, [sk1],
        new_keys=[entry2],
        new_admins=[kid1, kid2],
        threshold=2,
        new_sks=[sk1, sk2],
    )
    # v3: try threshold=1 even though we still have 2 admins
    entry3, _ = _make_key_entry(sk3, user_id="admin-2", iss="https://idp",
                                sub="admin-2", kind="cli",
                                roles=["admin", "approver"], added_in=3)
    v3 = _build_next_version(
        v2, [sk1, sk2],
        new_keys=[entry3],
        new_admins=[kid1, kid2, kid3],
        threshold=1,
        new_sks=[sk1, sk2],
    )
    fp = hashlib.sha256(
        genesis["payload"]["org_id"].encode("utf-8") + b":" +
        _canonical_json(genesis["payload"])
    ).hexdigest()
    with pytest.raises(RegistryError):
        verify_chain([genesis, v2, v3], fp)


@pytest.mark.xfail(strict=True, raises=M2T6Pending)
def test_admins_cut_to_1_refused():
    """Cutting admins from 2 to 1 is refused by double threshold (threat 23)."""
    _need("sandbox.protocol.registry", "verify_chain")
    from sandbox.protocol.registry import verify_chain, RegistryError
    sk1, _, kid1 = _keygen()
    sk2, _, kid2 = _keygen()
    genesis, _ = _build_genesis(admin_sks=[sk1], threshold=1)
    entry2, _ = _make_key_entry(sk2, user_id="admin-1", iss="https://idp",
                                sub="admin-1", kind="cli",
                                roles=["admin", "approver"], added_in=2)
    v2 = _build_next_version(
        genesis, [sk1],
        new_keys=[entry2],
        new_admins=[kid1, kid2],
        threshold=2,
        new_sks=[sk1, sk2],
    )
    # v3: remove admin-1, only kid1 left, threshold 1
    # Rebuild keys without entry2
    v3_payload = dict(v2["payload"])
    v3_payload["version"] = 3
    v3_payload["prev_hash"] = hashlib.sha256(
        v2["payload"]["org_id"].encode("utf-8") + b":" +
        _canonical_json(v2["payload"])
    ).hexdigest()
    v3_payload["threshold"] = 1
    v3_payload["admins"] = [kid1]
    v3_payload["keys"] = [k for k in v2["payload"]["keys"] if k["key_id"] == kid1]
    v3_payload["expires_at"] = time.time() + 7 * 86400
    v3 = _sign_envelope("agg/registry/v1", v3_payload, [sk1, sk2])
    fp = hashlib.sha256(
        genesis["payload"]["org_id"].encode("utf-8") + b":" +
        _canonical_json(genesis["payload"])
    ).hexdigest()
    with pytest.raises(RegistryError):
        verify_chain([genesis, v2, v3], fp)


@pytest.mark.xfail(strict=True, raises=M2T6Pending)
def test_double_threshold_old_and_new_set():
    """Each version needs the threshold of BOTH the previous and its own admin set (threat 23)."""
    _need("sandbox.protocol.registry", "verify_chain")
    from sandbox.protocol.registry import verify_chain, RegistryError
    sk1, _, kid1 = _keygen()
    sk2, _, kid2 = _keygen()
    sk3, _, kid3 = _keygen()
    genesis, _ = _build_genesis(admin_sks=[sk1], threshold=1)
    entry2, _ = _make_key_entry(sk2, user_id="admin-1", iss="https://idp",
                                sub="admin-1", kind="cli",
                                roles=["admin", "approver"], added_in=2)
    v2 = _build_next_version(
        genesis, [sk1],
        new_keys=[entry2],
        new_admins=[kid1, kid2],
        threshold=2,
        new_sks=[sk1, sk2],
    )
    # v3: signed only by sk1 (1 sig), but new threshold is 1
    # Needs 2 (the old threshold) -- only 1 provided
    entry3, _ = _make_key_entry(sk3, user_id="admin-2", iss="https://idp",
                                sub="admin-2", kind="cli",
                                roles=["admin", "approver"], added_in=3)
    v3 = _build_next_version(
        v2, [sk1],  # only 1 signer -- below old threshold of 2
        new_keys=[entry3],
        new_admins=[kid1, kid2, kid3],
        threshold=2,
        new_sks=[sk1],
    )
    fp = hashlib.sha256(
        genesis["payload"]["org_id"].encode("utf-8") + b":" +
        _canonical_json(genesis["payload"])
    ).hexdigest()
    with pytest.raises(RegistryError):
        verify_chain([genesis, v2, v3], fp)


@pytest.mark.xfail(strict=True, raises=M2T6Pending)
def test_duplicate_iss_sub_refused():
    """Duplicate (iss, sub) across keys is refused (threat 23)."""
    _need("sandbox.protocol.registry", "verify_chain")
    from sandbox.protocol.registry import verify_chain, RegistryError
    sk1, _, kid1 = _keygen()
    sk2, _, kid2 = _keygen()
    genesis, _ = _build_genesis(admin_sks=[sk1], threshold=1)
    # Add a key with the same (iss, sub) as admin-0
    entry_dup, _ = _make_key_entry(sk2, user_id="admin-dup",
                                   iss="https://idp", sub="admin-0",
                                   kind="cli", roles=["approver"], added_in=2)
    v2 = _build_next_version(
        genesis, [sk1],
        new_keys=[entry_dup],
    )
    fp = hashlib.sha256(
        genesis["payload"]["org_id"].encode("utf-8") + b":" +
        _canonical_json(genesis["payload"])
    ).hexdigest()
    with pytest.raises(RegistryError):
        verify_chain([genesis, v2], fp)


@pytest.mark.xfail(strict=True, raises=M2T6Pending)
def test_shared_key_refused():
    """One public key under two user_ids is refused (threat 23)."""
    _need("sandbox.protocol.registry", "verify_chain")
    from sandbox.protocol.registry import verify_chain, RegistryError
    sk1, pub1, kid1 = _keygen()
    genesis, _ = _build_genesis(admin_sks=[sk1], threshold=1)
    # Same public key, different user_id
    entry_dup = {
        "key_id": kid1,
        "public_key": pub1.hex(),
        "user_id": "other-user",
        "iss": "https://other",
        "sub": "other",
        "alg": "ed25519",
        "kind": "cli",
        "roles": ["approver"],
        "added_in": 2,
    }
    v2 = _build_next_version(
        genesis, [sk1],
        new_keys=[entry_dup],
    )
    fp = hashlib.sha256(
        genesis["payload"]["org_id"].encode("utf-8") + b":" +
        _canonical_json(genesis["payload"])
    ).hexdigest()
    with pytest.raises(RegistryError):
        verify_chain([genesis, v2], fp)


# ===================================================================
# RED: threat 21 -- browser-key signature refused for registry/policy-change
# ===================================================================


@pytest.mark.xfail(strict=True, raises=M2T6Pending)
def test_browser_key_registry_refused():
    """A browser-key signature on a registry version is refused (threat 21)."""
    _need("sandbox.protocol.registry", "verify_chain")
    from sandbox.protocol.registry import verify_chain, RegistryError
    browser_sk, browser_pub, browser_kid = _keygen()
    # Build a genesis with a browser key as admin
    entry, _ = _make_key_entry(browser_sk, user_id="browser-user",
                               iss="https://idp", sub="browser-user",
                               kind="browser", roles=["admin", "approver"],
                               added_in=1)
    payload = _make_registry_payload(
        org_id="org-1", version=1, threshold=1,
        admins=[entry["key_id"]],
        keys=[entry],
    )
    env = _sign_envelope("agg/registry/v1", payload, [browser_sk])
    fp = hashlib.sha256(
        payload["org_id"].encode("utf-8") + b":" +
        _canonical_json(payload)
    ).hexdigest()
    with pytest.raises(RegistryError):
        verify_chain([env], fp)


@pytest.mark.xfail(strict=True, raises=M2T6Pending)
def test_browser_key_policy_change_refused():
    """A browser key may not sign policy-change (threat 21)."""
    _need("sandbox.protocol.registry", "Registry")
    from sandbox.protocol.registry import verify_chain, Registry
    sk1, _, kid1 = _keygen()
    browser_sk, _, browser_kid = _keygen()
    # Build a valid genesis with a cli admin + a browser key user
    browser_entry, _ = _make_key_entry(browser_sk, user_id="browser-user",
                                       iss="https://idp", sub="browser-user",
                                       kind="browser", roles=["approver"],
                                       added_in=1)
    genesis, sks = _build_genesis(admin_sks=[sk1], extra_keys=[browser_entry])
    fp = hashlib.sha256(
        genesis["payload"]["org_id"].encode("utf-8") + b":" +
        _canonical_json(genesis["payload"])
    ).hexdigest()
    reg = verify_chain([genesis], fp)
    # browser key should NOT be allowed to sign policy-change
    assert not reg.may_sign(browser_kid, "agg/policy-change/v1", "staging")


@pytest.mark.xfail(strict=True, raises=M2T6Pending)
def test_browser_key_prod_approval_refused():
    """Browser-key remote-approval on prod is refused by may_sign (threat 21)."""
    _need("sandbox.protocol.registry", "Registry")
    from sandbox.protocol.registry import verify_chain
    sk1, _, kid1 = _keygen()
    browser_sk, _, browser_kid = _keygen()
    browser_entry, _ = _make_key_entry(browser_sk, user_id="browser-user",
                                       iss="https://idp", sub="browser-user",
                                       kind="browser", roles=["approver"],
                                       added_in=1)
    genesis, sks = _build_genesis(admin_sks=[sk1], extra_keys=[browser_entry])
    fp = hashlib.sha256(
        genesis["payload"]["org_id"].encode("utf-8") + b":" +
        _canonical_json(genesis["payload"])
    ).hexdigest()
    reg = verify_chain([genesis], fp)
    assert not reg.may_sign(browser_kid, "agg/remote-approval/v1", "prod")


@pytest.mark.xfail(strict=True, raises=M2T6Pending)
def test_cli_key_prod_remote_approval_refused():
    """CLI-key remote-approval on prod is refused in M2 (threat 21, N9)."""
    _need("sandbox.protocol.registry", "Registry")
    from sandbox.protocol.registry import verify_chain
    sk1, _, kid1 = _keygen()
    genesis, sks = _build_genesis(admin_sks=[sk1])
    fp = hashlib.sha256(
        genesis["payload"]["org_id"].encode("utf-8") + b":" +
        _canonical_json(genesis["payload"])
    ).hexdigest()
    reg = verify_chain([genesis], fp)
    assert not reg.may_sign(kid1, "agg/remote-approval/v1", "prod")


# ===================================================================
# RED: threat 29 -- cross-org registry refused
# ===================================================================


@pytest.mark.xfail(strict=True, raises=M2T6Pending)
def test_cross_org_registry_refused():
    """A registry for org-B is refused when checking binding to org-A (threat 29)."""
    _need("sandbox.protocol.registry", "check_binding")
    from sandbox.protocol.registry import check_binding, RegistryError
    payload = {"org_id": "org-B", "project_id": "proj-1"}
    with pytest.raises(RegistryError):
        check_binding(payload, "org-A", "proj-1")


@pytest.mark.xfail(strict=True, raises=M2T6Pending)
def test_cross_project_registry_refused():
    """A registry for project-B is refused when bound to project-A (threat 29)."""
    _need("sandbox.protocol.registry", "check_binding")
    from sandbox.protocol.registry import check_binding, RegistryError
    payload = {"org_id": "org-1", "project_id": "proj-B"}
    with pytest.raises(RegistryError):
        check_binding(payload, "org-1", "proj-A")


# ===================================================================
# RED: threat 30 -- single_admin_registry (S9)
# ===================================================================


@pytest.mark.xfail(strict=True, raises=M2T6Pending)
def test_single_admin_registry_label():
    """A key added by a version with < 2 admin sigs has counts_for_dual=False (threat 30)."""
    _need("sandbox.protocol.registry", "verify_chain")
    from sandbox.protocol.registry import verify_chain
    sk1, _, kid1 = _keygen()
    sk2, _, kid2 = _keygen()
    # Genesis with 1 admin -- only 1 sig
    genesis, sks = _build_genesis(admin_sks=[sk1], threshold=1)
    # v2: add an approver key, but only 1 admin sig (still sk1 alone)
    approver_entry, _ = _make_key_entry(sk2, user_id="approver-1",
                                        iss="https://idp", sub="approver-1",
                                        kind="cli", roles=["approver"],
                                        added_in=2)
    v2 = _build_next_version(
        genesis, [sk1],
        new_keys=[approver_entry],
    )
    fp = hashlib.sha256(
        genesis["payload"]["org_id"].encode("utf-8") + b":" +
        _canonical_json(genesis["payload"])
    ).hexdigest()
    reg = verify_chain([genesis, v2], fp)
    # The approver added under single admin must not count for dual
    assert not reg.counts_for_dual(kid2)


@pytest.mark.xfail(strict=True, raises=M2T6Pending)
def test_single_admin_registry_key_does_not_count_dual_even_with_role():
    """Even with approver role, a single-admin-registry key never counts for dual (threat 30)."""
    _need("sandbox.protocol.registry", "verify_chain")
    from sandbox.protocol.registry import verify_chain
    sk1, _, kid1 = _keygen()
    sk2, _, kid2 = _keygen()
    sk3, _, kid3 = _keygen()
    genesis, _ = _build_genesis(admin_sks=[sk1], threshold=1)
    # v2: add both sk2 (approver) and sk3 (admin), but only 1 admin sig
    entry2, _ = _make_key_entry(sk2, user_id="approver-1",
                                iss="https://idp", sub="approver-1",
                                kind="cli", roles=["approver"], added_in=2)
    entry3, _ = _make_key_entry(sk3, user_id="admin-1",
                                iss="https://idp", sub="admin-1",
                                kind="cli", roles=["admin", "approver"], added_in=2)
    v2 = _build_next_version(
        genesis, [sk1],
        new_keys=[entry2, entry3],
        new_admins=[kid1, kid3],
        threshold=2,
    )
    fp = hashlib.sha256(
        genesis["payload"]["org_id"].encode("utf-8") + b":" +
        _canonical_json(genesis["payload"])
    ).hexdigest()
    reg = verify_chain([genesis, v2], fp)
    # Both keys added in v2 with only 1 admin sig -> single_admin_registry
    assert not reg.counts_for_dual(kid2)
    assert not reg.counts_for_dual(kid3)


# ===================================================================
# RED: threat 31 -- device and bundle-signer keys refused for human kinds
# ===================================================================


@pytest.mark.xfail(strict=True, raises=M2T6Pending)
def test_device_key_approval_refused():
    """A device-kind key cannot sign remote-approval (threat 31)."""
    _need("sandbox.protocol.registry", "Registry")
    from sandbox.protocol.registry import verify_chain
    sk1, _, kid1 = _keygen()
    device_sk, _, device_kid = _keygen()
    device_entry, _ = _make_key_entry(device_sk, user_id="device-1",
                                      iss="https://idp", sub="device-1",
                                      kind="device", roles=["approver"],
                                      added_in=1)
    genesis, sks = _build_genesis(admin_sks=[sk1], extra_keys=[device_entry])
    fp = hashlib.sha256(
        genesis["payload"]["org_id"].encode("utf-8") + b":" +
        _canonical_json(genesis["payload"])
    ).hexdigest()
    reg = verify_chain([genesis], fp)
    assert not reg.may_sign(device_kid, "agg/remote-approval/v1", "staging")


@pytest.mark.xfail(strict=True, raises=M2T6Pending)
def test_bundle_signer_approval_refused():
    """A bundle-signer-kind key cannot sign remote-approval (threat 31)."""
    _need("sandbox.protocol.registry", "Registry")
    from sandbox.protocol.registry import verify_chain
    sk1, _, kid1 = _keygen()
    bs_sk, _, bs_kid = _keygen()
    bs_entry, _ = _make_key_entry(bs_sk, user_id="bundle-signer",
                                  iss="https://idp", sub="bundle-signer",
                                  kind="bundle-signer", roles=["approver"],
                                  added_in=1)
    genesis, sks = _build_genesis(admin_sks=[sk1], extra_keys=[bs_entry])
    fp = hashlib.sha256(
        genesis["payload"]["org_id"].encode("utf-8") + b":" +
        _canonical_json(genesis["payload"])
    ).hexdigest()
    reg = verify_chain([genesis], fp)
    assert not reg.may_sign(bs_kid, "agg/remote-approval/v1", "staging")


# ===================================================================
# RED: N8 -- forged count field refused
# ===================================================================


@pytest.mark.xfail(strict=True, raises=M2T6Pending)
def test_forged_count_field_refused():
    """An entry carrying a count field is refused (N8)."""
    _need("sandbox.protocol.registry", "verify_chain")
    from sandbox.protocol.registry import verify_chain, RegistryError
    sk1, _, kid1 = _keygen()
    genesis, sks = _build_genesis(admin_sks=[sk1], threshold=1)
    # v2 with a forged 'count' field on a key entry
    sk2, pub2, kid2 = _keygen()
    forged_entry = {
        "key_id": kid2,
        "public_key": pub2.hex(),
        "user_id": "bad-actor",
        "iss": "https://idp",
        "sub": "bad-actor",
        "alg": "ed25519",
        "kind": "cli",
        "roles": ["approver"],
        "added_in": 2,
        "count": 99,
    }
    v2 = _build_next_version(
        genesis, [sk1],
        new_keys=[forged_entry],
    )
    fp = hashlib.sha256(
        genesis["payload"]["org_id"].encode("utf-8") + b":" +
        _canonical_json(genesis["payload"])
    ).hexdigest()
    with pytest.raises(RegistryError):
        verify_chain([genesis, v2], fp)


# ===================================================================
# RED: may_sign kind matrix (D5.1)
# ===================================================================


@pytest.mark.xfail(strict=True, raises=M2T6Pending)
def test_cli_may_sign_registry():
    """CLI keys can sign registry versions."""
    _need("sandbox.protocol.registry", "Registry")
    from sandbox.protocol.registry import verify_chain
    sk1, _, kid1 = _keygen()
    genesis, _ = _build_genesis(admin_sks=[sk1])
    fp = hashlib.sha256(
        genesis["payload"]["org_id"].encode("utf-8") + b":" +
        _canonical_json(genesis["payload"])
    ).hexdigest()
    reg = verify_chain([genesis], fp)
    assert reg.may_sign(kid1, "agg/registry/v1", "staging")
    assert reg.may_sign(kid1, "agg/registry/v1", "prod")


@pytest.mark.xfail(strict=True, raises=M2T6Pending)
def test_cli_may_sign_policy_change():
    """CLI keys can sign policy-change."""
    _need("sandbox.protocol.registry", "Registry")
    from sandbox.protocol.registry import verify_chain
    sk1, _, kid1 = _keygen()
    genesis, _ = _build_genesis(admin_sks=[sk1])
    fp = hashlib.sha256(
        genesis["payload"]["org_id"].encode("utf-8") + b":" +
        _canonical_json(genesis["payload"])
    ).hexdigest()
    reg = verify_chain([genesis], fp)
    assert reg.may_sign(kid1, "agg/policy-change/v1", "staging")
    assert reg.may_sign(kid1, "agg/policy-change/v1", "prod")


@pytest.mark.xfail(strict=True, raises=M2T6Pending)
def test_cli_nonprod_remote_approval_allowed():
    """CLI keys can sign remote-approval on non-prod (N9)."""
    _need("sandbox.protocol.registry", "Registry")
    from sandbox.protocol.registry import verify_chain
    sk1, _, kid1 = _keygen()
    genesis, _ = _build_genesis(admin_sks=[sk1])
    fp = hashlib.sha256(
        genesis["payload"]["org_id"].encode("utf-8") + b":" +
        _canonical_json(genesis["payload"])
    ).hexdigest()
    reg = verify_chain([genesis], fp)
    assert reg.may_sign(kid1, "agg/remote-approval/v1", "staging")


@pytest.mark.xfail(strict=True, raises=M2T6Pending)
def test_browser_nonprod_remote_approval_allowed():
    """Browser keys can sign remote-approval on non-prod."""
    _need("sandbox.protocol.registry", "Registry")
    from sandbox.protocol.registry import verify_chain
    sk1, _, kid1 = _keygen()
    browser_sk, _, browser_kid = _keygen()
    browser_entry, _ = _make_key_entry(browser_sk, user_id="browser-user",
                                       iss="https://idp", sub="browser-user",
                                       kind="browser", roles=["approver"],
                                       added_in=1)
    genesis, _ = _build_genesis(admin_sks=[sk1], extra_keys=[browser_entry])
    fp = hashlib.sha256(
        genesis["payload"]["org_id"].encode("utf-8") + b":" +
        _canonical_json(genesis["payload"])
    ).hexdigest()
    reg = verify_chain([genesis], fp)
    assert reg.may_sign(browser_kid, "agg/remote-approval/v1", "staging")


# ===================================================================
# RED: expiry (7 days; 72 h with a prod project)
# ===================================================================


@pytest.mark.xfail(strict=True, raises=M2T6Pending)
def test_expired_registry_refuses_remote_approvals():
    """An expired registry refuses remote approvals."""
    _need("sandbox.protocol.registry", "verify_chain")
    from sandbox.protocol.registry import verify_chain
    sk1, _, kid1 = _keygen()
    genesis, _ = _build_genesis(admin_sks=[sk1],
                                expires_at=time.time() - 1)
    fp = hashlib.sha256(
        genesis["payload"]["org_id"].encode("utf-8") + b":" +
        _canonical_json(genesis["payload"])
    ).hexdigest()
    reg = verify_chain([genesis], fp)
    # Expired registry: remote approvals refused, even on non-prod
    assert not reg.may_sign(kid1, "agg/remote-approval/v1", "staging")


# ===================================================================
# RED: older registry version in chain is refused
# ===================================================================


@pytest.mark.xfail(strict=True, raises=M2T6Pending)
def test_older_registry_version_refused():
    """A registry version with a lower version number than the previous is refused."""
    _need("sandbox.protocol.registry", "verify_chain")
    from sandbox.protocol.registry import verify_chain, RegistryError
    sk1, _, kid1 = _keygen()
    genesis, sks = _build_genesis(admin_sks=[sk1])
    # v2 valid
    v2 = _build_next_version(genesis, sks)
    # Then try to insert a version with version=1 again (lower than v2)
    bad_v = _build_next_version(v2, sks, version=1)
    fp = hashlib.sha256(
        genesis["payload"]["org_id"].encode("utf-8") + b":" +
        _canonical_json(genesis["payload"])
    ).hexdigest()
    with pytest.raises(RegistryError):
        verify_chain([genesis, v2, bad_v], fp)
