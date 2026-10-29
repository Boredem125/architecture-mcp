"""T12d d0 security ruling, proof tests (security-engineer, leader tier).

ADR 0011 makes ``verify_chain`` "the real gate" for registry versions that
a pending (never-registered) key posts, and the candidates route hands the
CLI server-reported public keys.  These tests prove gaps in the gate and in
the code T12d builds on.  Pure Python, no Postgres.

Each strict xfail asserts the safe behaviour and raises ``T12dD0Finding``
while the unsafe behaviour is present.  Any other error does not match
``raises=`` and fails the run.  When the fix lands the test XPASSes and the
strict marker fails the run: remove the marker in the fixing change.

D0-1 (High, ADR 0003 M2 3.1 and 2.4 N1): ``verify_chain`` never checks
     ``key_id == sha256(public_key)`` for ``keys[]`` entries (only for
     ``bundle_signer``).  The N1 typed confirmation is of a key_id, and
     ``compute_diff`` shows key_id and user_id but not the public key.  A
     compromised server can list a candidate with carol's real key_id and
     its own public key; alice types carol's key_id, signs, and the server
     then signs as carol.
D0-2 (High, ADR 0003 M2 3.3 "only kind=cli admin keys count, one per
     user"): thresholds and the 2-admin floor count key_ids, not users.
     One admin with two linked CLI keys meets threshold 2 alone, and keys
     added that way count for dual control (S9).  T12d's own-key publish
     makes this a one-person flow: alice links a second key, signs v2 with
     both, and posts it with the second key's pending_link token.
D0-3 (Medium, ADR 0003 M2 2.6, threat 33): ``compute_diff`` omits changes
     to an existing key (public_key, roles, kind, iss, sub, user_id) and to
     ``bundle_signer`` and ``expires_at``.  ``sign-registry`` shows this
     diff before signing, so a bundle-signer swap (who may sign policy
     bundles) is signed blind.
D0-4 (Low, defence in depth): ``verify_chain`` does not check that every
     envelope's ``kind`` is ``agg/registry/v1``.
D0-5 (Low, fail closed): ``check_signer_token_scope`` is a denylist; any
     scope other than the literal ``pending_link`` (empty, unknown,
     'revoked') reaches every route.
"""
from __future__ import annotations

import hashlib
import json
import time

import pytest
from nacl.signing import SigningKey

from sandbox.protocol.domains import POLICY_CHANGE, REGISTRY
from sandbox.protocol.envelope import sign_envelope
from sandbox.protocol.registry import RegistryError, verify_chain


class T12dD0Finding(AssertionError):
    """Raised while an open T12d d0 finding is exploitable."""


ORG = "11111111-1111-1111-1111-111111111111"


def _kid(sk: SigningKey) -> str:
    return hashlib.sha256(bytes(sk.verify_key)).hexdigest()


def _entry(sk: SigningKey, user: str, roles: list[str], added_in: int,
           *, public_key: str | None = None, key_id: str | None = None) -> dict:
    return {
        "key_id": key_id or _kid(sk),
        "public_key": public_key or bytes(sk.verify_key).hex(),
        "user_id": user,
        "iss": "https://idp.example",
        "sub": f"sub-{user}",
        "alg": "ed25519",
        "kind": "cli",
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


def _payload(version: int, prev: dict | None, threshold: int,
             admins: list[str], keys: list[dict],
             bundle: dict | None = None) -> dict:
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


def _genesis(alice: SigningKey, kind: str = REGISTRY) -> dict:
    p = _payload(1, None, 1, [_kid(alice)],
                 [_entry(alice, "user-alice", ["admin", "approver"], 1)])
    return sign_envelope(kind, p, [alice])


# ---------------------------------------------------------------------------
# D0-1: key_id is not bound to public_key
# ---------------------------------------------------------------------------

def test_d0_1_key_id_must_equal_sha256_public_key():
    alice = SigningKey.generate()
    carol_real = SigningKey.generate()      # carol tells alice this key_id
    server_sk = SigningKey.generate()       # the compromised server's key

    v1 = _genesis(alice)
    # Candidate as listed by a compromised server: carol's real key_id,
    # the server's public key.
    swapped = _entry(carol_real, "user-carol", ["approver"], 2,
                     public_key=bytes(server_sk.verify_key).hex())
    p2 = _payload(2, v1["payload"], 1, [_kid(alice)],
                  v1["payload"]["keys"] + [swapped])
    v2 = sign_envelope(REGISTRY, p2, [alice])

    try:
        reg = verify_chain([v1, v2], _payload_hash(v1["payload"]))
    except RegistryError:
        return  # safe: the mismatched entry is refused
    entry = reg._keys.get(_kid(carol_real), {})
    if entry.get("public_key") == bytes(server_sk.verify_key).hex():
        raise T12dD0Finding(
            "verify_chain accepted key_id=sha256(carol) bound to the server's "
            "public key; N1 typed key_id confirmation is bypassed")


# ---------------------------------------------------------------------------
# D0-2: thresholds count keys, not users
# ---------------------------------------------------------------------------

def test_d0_2_one_user_two_admin_keys_is_not_two_admins():
    alice = SigningKey.generate()
    alice_second = SigningKey.generate()    # a second CLI key alice linked

    v1 = _genesis(alice)
    p2 = _payload(
        2, v1["payload"], 2, [_kid(alice), _kid(alice_second)],
        v1["payload"]["keys"]
        + [_entry(alice_second, "user-alice", ["admin"], 2)],
    )
    v2 = sign_envelope(REGISTRY, p2, [alice, alice_second])

    try:
        reg = verify_chain([v1, v2], _payload_hash(v1["payload"]))
    except RegistryError:
        return  # safe: one user's two keys count once, threshold 2 unmet
    raise T12dD0Finding(
        "one user with two admin keys met threshold 2 alone "
        f"(admins={len(reg._admins)}); dual control of the registry is "
        "one human")


# ---------------------------------------------------------------------------
# D0-3: compute_diff omits changes the admin is signing
# ---------------------------------------------------------------------------

def test_d0_3_diff_shows_bundle_signer_and_key_field_changes():
    from sandbox.connector.sync.signer import compute_diff

    def b(p: dict) -> bytes:
        return json.dumps(p, sort_keys=True, separators=(",", ":")).encode()

    alice = SigningKey.generate()
    bob = SigningKey.generate()
    v1 = _payload(1, None, 1, [_kid(alice)], [
        _entry(alice, "user-alice", ["admin"], 1),
        _entry(bob, "user-bob", ["approver"], 1),
    ])
    # No-op successor: only version and prev_hash change.
    noop = _payload(2, v1, 1, [_kid(alice)], v1["keys"])
    # Hostile successor: swap the bundle signer and give bob admin role
    # material (roles) without making him an admin.
    keys = [dict(k) for k in v1["keys"]]
    keys[1]["roles"] = ["approver", "admin"]
    hostile = _payload(2, v1, 1, [_kid(alice)], keys,
                       bundle=_bundle(SigningKey.generate()))
    hostile["expires_at"] = noop["expires_at"] + 10 * 365 * 24 * 3600

    if compute_diff(b(v1), b(hostile)) == compute_diff(b(v1), b(noop)):
        raise T12dD0Finding(
            "compute_diff shows the same text for a bundle_signer swap, a "
            "roles change and a 10-year expiry as for a no-op version")


# ---------------------------------------------------------------------------
# D0-4: envelope kind not checked
# ---------------------------------------------------------------------------

def test_d0_4_registry_envelope_kind_is_checked():
    alice = SigningKey.generate()
    v1 = _genesis(alice, kind=POLICY_CHANGE)
    try:
        verify_chain([v1], _payload_hash(v1["payload"]))
    except RegistryError:
        return
    raise T12dD0Finding(
        "verify_chain accepted a genesis signed under agg/policy-change/v1")


# ---------------------------------------------------------------------------
# D0-5: scope check is a denylist
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("scope", ["", "revoked", "link", "CONFIRMED"])
def test_d0_5_unknown_scope_fails_closed(scope):
    from agg_cp.sync.signer import SignerScopeError, check_signer_token_scope

    try:
        check_signer_token_scope({"status": scope}, "signatures")
    except SignerScopeError:
        return
    raise T12dD0Finding(
        f"scope {scope!r} reached /signatures; only 'confirmed' may")
