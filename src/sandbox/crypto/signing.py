from __future__ import annotations

import hashlib
import json
from typing import Any

from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey


class KeyManager:
    """Manages Ed25519 keypairs for inter-agent message signing."""

    def __init__(self) -> None:
        self._keys: dict[str, SigningKey] = {}

    def generate_keypair(self, identity: str) -> tuple[SigningKey, VerifyKey]:
        signing_key = SigningKey.generate()
        self._keys[identity] = signing_key
        return signing_key, signing_key.verify_key

    def load_keypair(self, identity: str, seed: bytes) -> tuple[SigningKey, VerifyKey]:
        signing_key = SigningKey(seed)
        self._keys[identity] = signing_key
        return signing_key, signing_key.verify_key

    def get_signing_key(self, identity: str) -> SigningKey:
        try:
            return self._keys[identity]
        except KeyError:
            raise KeyError(f"No signing key registered for identity '{identity}'")

    def get_verify_key(self, identity: str) -> VerifyKey:
        return self.get_signing_key(identity).verify_key

    def has_identity(self, identity: str) -> bool:
        return identity in self._keys

    def remove_identity(self, identity: str) -> None:
        self._keys.pop(identity, None)

    def export_seed(self, identity: str) -> bytes:
        return bytes(self.get_signing_key(identity))

    def export_verify_key(self, identity: str) -> bytes:
        return bytes(self.get_verify_key(identity))


def sign_message(data: bytes, signing_key: SigningKey) -> str:
    signed = signing_key.sign(data)
    return signed.signature.hex()


def verify_signature(data: bytes, signature: str, verify_key: VerifyKey) -> bool:
    try:
        verify_key.verify(data, bytes.fromhex(signature))
        return True
    except (BadSignatureError, ValueError):
        return False


def compute_hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical_payload(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode()


def sign_envelope(envelope_dict: dict[str, Any], signing_key: SigningKey) -> dict[str, Any]:
    payload = envelope_dict.get("payload", {})
    canonical = _canonical_payload(payload)
    envelope_dict["signature"] = sign_message(canonical, signing_key)
    return envelope_dict


def verify_envelope(envelope_dict: dict[str, Any], verify_key: VerifyKey) -> bool:
    signature = envelope_dict.get("signature", "")
    if not signature:
        return False
    payload = envelope_dict.get("payload", {})
    canonical = _canonical_payload(payload)
    return verify_signature(canonical, signature, verify_key)
