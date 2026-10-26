"""T12d d0 fix review, proof tests (security-engineer, leader tier, 26 Oct).

Reviews the uncommitted D0-1, D0-2 and D0-4 fix in
``src/sandbox/protocol/registry.py``.  Pure Python, no Postgres.

Each strict xfail asserts the safe behaviour and raises
``T12dD0ReviewFinding`` while the unsafe behaviour is present.  Any other
error does not match ``raises=`` and fails the run.  Remove the marker in
the fixing change.  The unmarked tests confirm the D0-1/D0-2 counting sites
the fix covers and must stay green.

R1 (Low, regression of this diff): an empty ``user_id`` is accepted.  Two
   different humans labelled ``""`` collapse into one user, so the 2-admin
   floor is never reached and one admin removes the other alone.  The old
   key-count floor refused this chain.
R2 (Low): a missing or non-string ``user_id`` raises KeyError or
   AttributeError, not RegistryError (``enroll.py`` and ``process.py``
   catch only RegistryError and EnvelopeError).
R3 (Medium, pre-existing, a T12d prerequisite): ``threshold`` is not
   checked to be an int >= 1.  In a single-admin registry, one signed
   ``threshold: 0`` version lets the next version pass with no previous
   admin signature, so anyone who may post a version (ADR 0011 pending_link
   self-publish) takes over the registry.
R4 (Low, pre-existing): ``admins[]`` membership counts without the
   ``admin`` role that ADR 0011 and the candidates route use.
R5 (Low, pre-existing): ``bundle_signer.public_key`` non-hex raises
   ValueError, and a public key that is not 32 bytes is accepted.
R6 (Low, pre-existing, latent): a ``keys[]`` entry with
   ``kind=bundle-signer`` removed in a later version is re-added to the
   returned Registry from ``all_keys`` (revocation, R3a).
"""
from __future__ import annotations

import hashlib
import json
import time

import pytest
from nacl.signing import SigningKey

from sandbox.protocol.domains import BUNDLE, REGISTRY
from sandbox.protocol.envelope import sign_envelope
from sandbox.protocol.registry import RegistryError, verify_chain


class T12dD0ReviewFinding(AssertionError):
    """Raised while an open T12d d0 review finding is exploitable."""


ORG = "22222222-2222-2222-2222-222222222222"


def _kid(sk: SigningKey) -> str:
    return hashlib.sha256(bytes(sk.verify_key)).hexdigest()


def _entry(sk: SigningKey, user, roles: list[str], added_in: int,
           *, sub: str | None = None, kind: str = "cli") -> dict:
    return {
        "key_id": _kid(sk),
        "public_key": bytes(sk.verify_key).hex(),
        "user_id": user,
        "iss": "https://idp.example",
        "sub": sub or f"sub-{user}",
        "alg": "ed25519",
        "kind": kind,
        "roles": roles,
        "added_in": added_in,
    }


def _payload_hash(p: dict) -> str:
    return hashlib.sha256(
        p["org_id"].encode() + b":"
        + json.dumps(p, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


_BUNDLE_SK = SigningKey.generate()


def _bundle(sk: SigningKey = _BUNDLE_SK) -> dict:
    return {"key_id": _kid(sk), "public_key": bytes(sk.verify_key).hex()}


def _payload(version: int, prev: dict | None, threshold, admins: list[str],
             keys: list[dict], bundle: dict | None = None) -> dict:
    return {
        "org_id": ORG,
        "version": version,
        "prev_hash": "" if prev is None else _payload_hash(prev),
        "threshold": threshold,
        "admins": admins,
        "keys": keys,
        "bundle_signer": bundle or _bundle(),
        "expires_at": time.time() + 3600,
    }


def _verify(chain: list[dict]):
    return verify_chain(chain, _payload_hash(chain[0]["payload"]))


# ---------------------------------------------------------------------------
# Confirmations (must pass): D0-1 carried keys, D0-2 counting sites
# ---------------------------------------------------------------------------

def test_d0_1_carried_forward_key_rebound_is_refused():
    alice = SigningKey.generate()
    server = SigningKey.generate()
    v1 = sign_envelope(REGISTRY, _payload(
        1, None, 1, [_kid(alice)], [_entry(alice, "u-a", ["admin"], 1)]),
        [alice])
    carried = dict(v1["payload"]["keys"][0])
    carried["public_key"] = bytes(server.verify_key).hex()
    v2 = sign_envelope(REGISTRY, _payload(
        2, v1["payload"], 1, [_kid(alice)], [carried]), [alice])
    with pytest.raises(RegistryError):
        _verify([v1, v2])
    bad = dict(carried, public_key="zz")
    v2b = sign_envelope(REGISTRY, _payload(
        2, v1["payload"], 1, [_kid(alice)], [bad]), [alice])
    with pytest.raises(RegistryError):
        _verify([v1, v2b])


def test_d0_2_genesis_threshold_counts_users():
    a1, a2 = SigningKey.generate(), SigningKey.generate()
    p = _payload(1, None, 2, [_kid(a1), _kid(a2)], [
        _entry(a1, "u-a", ["admin"], 1), _entry(a2, "u-a", ["admin"], 1)])
    with pytest.raises(RegistryError):
        _verify([sign_envelope(REGISTRY, p, [a1, a2, a1])])


def test_d0_2_prev_threshold_counts_users():
    a1, a2, bob = (SigningKey.generate() for _ in range(3))
    keys = [_entry(a1, "u-a", ["admin"], 1), _entry(a2, "u-a", ["admin"], 1),
            _entry(bob, "u-b", ["admin"], 1)]
    admins = [_kid(a1), _kid(a2), _kid(bob)]
    v1 = sign_envelope(REGISTRY, _payload(1, None, 2, admins, keys),
                       [a1, bob])
    _verify([v1])
    v2 = sign_envelope(REGISTRY, _payload(2, v1["payload"], 2, admins, keys),
                       [a1, a2])
    with pytest.raises(RegistryError):
        _verify([v1, v2])


def test_d0_2_counts_for_dual_counts_users():
    a1, a2, carol = (SigningKey.generate() for _ in range(3))
    keys = [_entry(a1, "u-a", ["admin"], 1), _entry(a2, "u-a", ["admin"], 1)]
    admins = [_kid(a1), _kid(a2)]
    v1 = sign_envelope(REGISTRY, _payload(1, None, 1, admins, keys), [a1, a2])
    v2 = sign_envelope(REGISTRY, _payload(
        2, v1["payload"], 1, admins,
        keys + [_entry(carol, "u-c", ["approver"], 2)]), [a1, a2])
    reg = _verify([v1, v2])
    assert not reg.counts_for_dual(_kid(carol))
    assert not reg.counts_for_dual(_kid(a1))


# ---------------------------------------------------------------------------
# R1, R2: user_id must be a non-empty string
# ---------------------------------------------------------------------------

def test_r1_empty_user_id_refused():
    alice, bob = SigningKey.generate(), SigningKey.generate()
    keys = [_entry(alice, "", ["admin"], 1, sub="sub-alice"),
            _entry(bob, "", ["admin"], 1, sub="sub-bob")]
    v1 = sign_envelope(REGISTRY, _payload(
        1, None, 1, [_kid(alice), _kid(bob)], keys), [alice])
    # alice alone removes bob from the admins (the old floor refused this)
    v2 = sign_envelope(REGISTRY, _payload(
        2, v1["payload"], 1, [_kid(alice)], keys), [alice])
    try:
        _verify([v1, v2])
    except RegistryError:
        return
    raise T12dD0ReviewFinding(
        "empty user_id accepted: two admins collapsed to one user and one "
        "admin cut the other below the 2-admin floor alone")


def test_r2_missing_or_nonstring_user_id_raises_registry_error():
    alice = SigningKey.generate()
    for bad in ("missing", None, 7):
        entry = _entry(alice, "u-a", ["admin"], 1)
        if bad == "missing":
            del entry["user_id"]
        else:
            entry["user_id"] = bad
        v1 = sign_envelope(REGISTRY, _payload(
            1, None, 1, [_kid(alice)], [entry]), [alice])
        try:
            _verify([v1])
        except RegistryError:
            continue
        except Exception as exc:  # noqa: BLE001
            raise T12dD0ReviewFinding(
                f"user_id {bad!r}: {type(exc).__name__}, not RegistryError")
        raise T12dD0ReviewFinding(f"user_id {bad!r} accepted")


# ---------------------------------------------------------------------------
# R3: threshold must be an int >= 1
# ---------------------------------------------------------------------------

def test_r3_threshold_below_one_refused():
    alice, mallory = SigningKey.generate(), SigningKey.generate()
    a = _entry(alice, "u-a", ["admin"], 1)
    v1 = sign_envelope(REGISTRY, _payload(1, None, 1, [_kid(alice)], [a]),
                       [alice])
    v2 = sign_envelope(REGISTRY, _payload(
        2, v1["payload"], 0, [_kid(alice)], [a]), [alice])
    # mallory (any pending key that may post a version) signs only her own
    m = _entry(mallory, "u-m", ["admin", "approver"], 3)
    v3 = sign_envelope(REGISTRY, _payload(
        3, v2["payload"], 1, [_kid(mallory)], [m]), [mallory])
    try:
        _verify([v1, v2, v3])
    except RegistryError:
        return
    raise T12dD0ReviewFinding(
        "threshold 0 accepted; v3 signed only by a key the previous admins "
        "never approved replaced the admin set")


# ---------------------------------------------------------------------------
# R4: admins[] must carry the admin role
# ---------------------------------------------------------------------------

def test_r4_admin_without_admin_role_not_counted():
    alice, bob = SigningKey.generate(), SigningKey.generate()
    keys = [_entry(alice, "u-a", ["admin"], 1),
            _entry(bob, "u-b", ["approver"], 1)]
    v1 = sign_envelope(REGISTRY, _payload(
        1, None, 2, [_kid(alice), _kid(bob)], keys), [alice, bob])
    try:
        _verify([v1])
    except RegistryError:
        return
    raise T12dD0ReviewFinding(
        "a key without the admin role met a registry threshold")


# ---------------------------------------------------------------------------
# R5: bundle_signer public key decode and length
# ---------------------------------------------------------------------------

def test_r5_bundle_signer_bad_public_key_raises_registry_error():
    alice = SigningKey.generate()
    a = _entry(alice, "u-a", ["admin"], 1)
    short = bytes(31)
    for bs in ({"key_id": "00", "public_key": "zz"},
               {"key_id": hashlib.sha256(short).hexdigest(),
                "public_key": short.hex()}):
        v1 = sign_envelope(REGISTRY, _payload(
            1, None, 1, [_kid(alice)], [a], bundle=bs), [alice])
        try:
            _verify([v1])
        except RegistryError:
            continue
        except Exception as exc:  # noqa: BLE001
            raise T12dD0ReviewFinding(
                f"bundle_signer: {type(exc).__name__}, not RegistryError")
        raise T12dD0ReviewFinding(
            "bundle_signer public key of 31 bytes accepted")


# ---------------------------------------------------------------------------
# R6: a removed bundle-signer-kind key is resurrected
# ---------------------------------------------------------------------------

def test_r6_removed_bundle_signer_kind_key_is_revoked():
    alice, old_bs = SigningKey.generate(), SigningKey.generate()
    a = _entry(alice, "u-a", ["admin"], 1)
    bs_entry = _entry(old_bs, "u-bs", [], 1, kind="bundle-signer")
    v1 = sign_envelope(REGISTRY, _payload(
        1, None, 1, [_kid(alice)], [a, bs_entry]), [alice])
    v2 = sign_envelope(REGISTRY, _payload(
        2, v1["payload"], 1, [_kid(alice)], [a]), [alice])
    reg = _verify([v1, v2])
    if reg.may_sign(_kid(old_bs), BUNDLE, "prod"):
        raise T12dD0ReviewFinding(
            "a bundle-signer key removed in v2 may still sign bundles")


# ---------------------------------------------------------------------------
# R4b (re-review): the R4 role check is a substring match on a str roles
# ---------------------------------------------------------------------------

def test_r4b_roles_must_be_a_list_of_strings():
    alice, bob = SigningKey.generate(), SigningKey.generate()
    keys = [_entry(alice, "u-a", ["admin"], 1),
            _entry(bob, "u-b", "sysadmin", 1)]   # type: ignore[arg-type]
    v1 = sign_envelope(REGISTRY, _payload(
        1, None, 2, [_kid(alice), _kid(bob)], keys), [alice, bob])
    try:
        _verify([v1])
    except RegistryError:
        return
    raise T12dD0ReviewFinding(
        "roles='sysadmin' (a str) passed the admin role check by substring "
        "and met a registry threshold")
