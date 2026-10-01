"""Cryptographic maker-checker — every approval is signed and verifiable.

An examiner-grade audit needs *non-repudiation*: proof that a specific human
approver authorized a specific agent action under a specific policy, and that
the record has not been altered since. We reuse the repo's Ed25519 primitives
([crypto/signing.py](src/sandbox/crypto/signing.py)) to sign a canonical bundle
binding:

    identity → action → policy_version → decision → outcome hash

The signed bundle and the approver's public key are written into the done-record,
so anyone can verify it later with no shared secret.

Key custody note (see docs/TCB.md): for this proof-of-work the approver's seed
lives at ``.sandbox/state/keys/<reviewer>.seed``. In a bank this key would be a
per-human credential in an HSM / smartcard, never on disk in the workspace — the
signing *interface* here is the part that transfers; the custody is not.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from nacl.signing import SigningKey, VerifyKey

from sandbox.crypto.signing import sign_message, verify_signature

# The fields that are bound into the signature. Anything not listed is
# presentation-only and not covered — keep the security-relevant fields here.
_SIGNED_FIELDS = (
    "request_id",
    "identity",
    "command",
    "path",
    "url",
    "trigger",
    "reason_code",
    "policy_version",
    "decision",
    "state",
    "reviewer_id",
    "exit_code",
    "fingerprint",  # tool-call grants: binds the approval to one exact call
)


def _canonical(record: dict[str, Any], fields: list[str] | tuple[str, ...] = _SIGNED_FIELDS) -> bytes:
    bundle = {k: record.get(k) for k in fields}
    return json.dumps(bundle, sort_keys=True, separators=(",", ":"), default=str).encode()


def _seed_path(layout, reviewer_id: str) -> Path:
    safe = "".join(c if c.isalnum() or c in "-_." else "_" for c in reviewer_id) or "cli"
    return layout.state_dir / "keys" / f"{safe}.seed"


def _load_or_create_key(layout, reviewer_id: str) -> SigningKey:
    path = _seed_path(layout, reviewer_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        try:
            return SigningKey(path.read_bytes())
        except (OSError, ValueError):
            pass
    key = SigningKey.generate()
    try:
        path.write_bytes(bytes(key))
    except OSError:
        pass
    return key


def sign_record(layout, reviewer_id: str, record: dict[str, Any]) -> dict[str, Any]:
    """Sign a terminal (done) record in place; returns the same dict.

    Adds ``signature`` (hex), ``signer_public_key`` (hex), and ``signed_fields``
    so a verifier knows exactly what was covered.
    """
    key = _load_or_create_key(layout, reviewer_id)
    record["signer_public_key"] = bytes(key.verify_key).hex()
    record["signed_fields"] = list(_SIGNED_FIELDS)
    record["signature"] = sign_message(_canonical(record), key)
    return record


def verify_record(record: dict[str, Any]) -> bool:
    """Verify a signed done-record against its embedded public key."""
    sig = record.get("signature")
    pub = record.get("signer_public_key")
    if not sig or not pub:
        return False
    try:
        vk = VerifyKey(bytes.fromhex(pub))
    except (ValueError, TypeError):
        return False
    # Verify over the fields the record says were signed, so records signed
    # before a field was added still verify.
    fields = record.get("signed_fields") or _SIGNED_FIELDS
    return verify_signature(_canonical(record, fields), sig, vk)


def reviewer_public_key(layout, reviewer_id: str = "cli") -> str | None:
    """Hex public key of this folder's approver key, or None if there is none yet."""
    path = _seed_path(layout, reviewer_id)
    if not path.exists():
        return None
    try:
        return bytes(SigningKey(path.read_bytes()).verify_key).hex()
    except (OSError, ValueError):
        return None
