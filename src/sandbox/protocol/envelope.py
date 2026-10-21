"""Protocol envelope: sign, verify, canonical bytes (ADR 0007 D7.1).

Signed bytes are ``tag || 0x00 || canonical JSON(payload)``.  The tag and
field set come from ``kind`` in code (SEC-24 rule).

Reuses the Ed25519 primitives from ``sandbox.crypto.signing`` and the same
canonical JSON form as ``sandbox.connector.signing`` (``json.dumps`` with
``sort_keys=True, separators=(",", ":")``).  No second canonicaliser.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any

from nacl.signing import SigningKey, VerifyKey

from sandbox.crypto.signing import sign_message, verify_signature
from sandbox.protocol.domains import ALL_TAGS


# -- Errors ----------------------------------------------------------------

class EnvelopeError(Exception):
    """Raised when an envelope fails structural or cryptographic checks."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


# -- Constants -------------------------------------------------------------

_ENVELOPE_FIELDS = frozenset({"kind", "sig_v", "payload", "signatures"})
_ALLOWED_ALGS = frozenset({"ed25519"})


# -- Public API ------------------------------------------------------------

def key_id(pub_bytes: bytes) -> str:
    """SHA-256 hex digest of a raw Ed25519 public key."""
    return hashlib.sha256(pub_bytes).hexdigest()


def canonical_bytes(tag: str, payload: dict[str, Any]) -> bytes:
    """``tag || 0x00 || canonical JSON(payload)``."""
    return tag.encode("utf-8") + b"\x00" + _canonical_json(payload)


def sign_envelope(
    kind: str,
    payload: dict[str, Any],
    signing_keys: list[SigningKey],
) -> dict[str, Any]:
    """Build a signed envelope dict."""
    msg = canonical_bytes(kind, payload)
    sigs: list[dict[str, str]] = []
    for sk in signing_keys:
        pub = bytes(sk.verify_key)
        kid = key_id(pub)
        sig = sign_message(msg, sk)
        sigs.append({"key_id": kid, "alg": "ed25519", "sig": sig})
    return {
        "kind": kind,
        "sig_v": 1,
        "payload": payload,
        "signatures": sigs,
    }


def verify_envelope(
    env: dict[str, Any],
    trusted_keys: dict[str, bytes],
) -> dict[str, Any]:
    """Verify *env* and return its payload.

    *trusted_keys* maps ``key_id`` to raw public-key bytes.
    Raises :class:`EnvelopeError` on any structural or cryptographic failure.
    Never trusts a key carried in the payload.
    """
    verified = _verify_sigs(env, trusted_keys)
    if not verified:
        raise EnvelopeError("no trusted signature found")
    return env["payload"]


# -- Internal --------------------------------------------------------------

def _canonical_json(payload: dict[str, Any]) -> bytes:
    """Canonical JSON: sorted keys, compact separators, UTF-8."""
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":")
    ).encode()


def _validate_structure(env: dict[str, Any]) -> None:
    """Check field set, sig_v, kind.  Raises :class:`EnvelopeError`."""
    env_keys = set(env.keys())
    if env_keys != _ENVELOPE_FIELDS:
        extra = env_keys - _ENVELOPE_FIELDS
        missing = _ENVELOPE_FIELDS - env_keys
        parts: list[str] = []
        if extra:
            parts.append(f"extra fields: {extra}")
        if missing:
            parts.append(f"missing fields: {missing}")
        raise EnvelopeError("; ".join(parts))

    if env["sig_v"] != 1:
        raise EnvelopeError(f"sig_v must be 1, got {env['sig_v']}")

    if env["kind"] not in ALL_TAGS:
        raise EnvelopeError(f"unknown kind: {env['kind']}")


def _verify_sigs(
    env: dict[str, Any],
    trusted_keys: dict[str, bytes],
) -> set[str]:
    """Validate structure, verify sigs.  Return the set of verified key_ids.

    Every signature with ``alg`` outside the allow-list is refused
    regardless of whether its ``key_id`` is trusted.  A trusted key whose
    signature does not verify is an immediate error (not silently skipped).
    """
    _validate_structure(env)

    msg = canonical_bytes(env["kind"], env["payload"])
    verified: set[str] = set()

    for sig_entry in env.get("signatures", []):
        alg = sig_entry.get("alg")
        if alg not in _ALLOWED_ALGS:
            raise EnvelopeError(f"unsupported alg: {alg}")

        kid = sig_entry.get("key_id", "")
        if kid in trusted_keys:
            try:
                vk = VerifyKey(trusted_keys[kid])
                vk.verify(msg, bytes.fromhex(sig_entry.get("sig", "")))
                verified.add(kid)
            except Exception as exc:
                raise EnvelopeError(
                    f"signature verification failed for key {kid}"
                ) from exc

    return verified
