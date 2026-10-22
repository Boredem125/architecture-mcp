"""Connector-side CLI signer: genesis, diff, confirmation, assertion (D5.2).

MIT.  No ``agg_cp`` imports.  Reuses ``sandbox.protocol.envelope`` and
``sandbox.protocol.domains``.
"""
from __future__ import annotations

import hashlib
import json
import time
from typing import Any

from nacl.signing import SigningKey

from sandbox.protocol.domains import REGISTRY, SIGNER_ASSERT
from sandbox.protocol.envelope import (
    canonical_bytes,
    key_id as compute_key_id,
    sign_envelope,
)


# -- Internal helpers -------------------------------------------------------

def _canonical_json(payload: dict[str, Any]) -> bytes:
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":")
    ).encode()


# -- Public API -------------------------------------------------------------

def build_genesis(
    admin_sk: SigningKey,
    org_id: str,
    iss: str,
    sub: str,
    bundle_signer_pub: bytes,
) -> tuple[dict[str, Any], str]:
    """Build registry v1 locally and return (envelope, fingerprint).

    The fingerprint is SHA-256 of ``org_id + ":" + canonical_json(payload)``.
    """
    admin_pub = bytes(admin_sk.verify_key)
    admin_kid = compute_key_id(admin_pub)
    bundle_kid = compute_key_id(bundle_signer_pub)

    payload: dict[str, Any] = {
        "org_id": org_id,
        "version": 1,
        "prev_hash": "",
        "threshold": 1,
        "admins": [admin_kid],
        "keys": [
            {
                "key_id": admin_kid,
                "public_key": admin_pub.hex(),
                "user_id": sub,
                "iss": iss,
                "sub": sub,
                "alg": "ed25519",
                "kind": "cli",
                "roles": ["admin", "approver"],
                "added_in": 1,
            },
        ],
        "bundle_signer": {
            "key_id": bundle_kid,
            "public_key": bundle_signer_pub.hex(),
        },
        "expires_at": time.time() + 7 * 24 * 3600,
    }

    env = sign_envelope(REGISTRY, payload, [admin_sk])

    fp = hashlib.sha256(
        org_id.encode("utf-8") + b":" + _canonical_json(payload)
    ).hexdigest()

    return env, fp


def compute_diff(
    prev_payload_bytes: bytes | None,
    new_payload_bytes: bytes,
) -> str:
    """Human-readable diff computed from the canonical payload *bytes*.

    Always works from the bytes themselves, never from a server-sent
    summary (D5.2, threat 33).  *prev_payload_bytes* is ``None`` for
    genesis (all keys shown as added).
    """
    new = json.loads(new_payload_bytes)

    if prev_payload_bytes is None:
        lines = [f"Genesis registry v{new.get('version', '?')}"]
        lines.append(f"org_id: {new.get('org_id', '?')}")
        lines.append(f"threshold: {new.get('threshold', '?')}")
        for key in new.get("keys", []):
            lines.append(
                f"+ key_id={key.get('key_id', '?')} "
                f"user_id={key.get('user_id', '?')} "
                f"kind={key.get('kind', '?')}"
            )
        return "\n".join(lines)

    prev = json.loads(prev_payload_bytes)
    lines = [
        f"Registry v{prev.get('version', '?')} -> v{new.get('version', '?')}"
    ]

    old_t = prev.get("threshold")
    new_t = new.get("threshold")
    if old_t != new_t:
        lines.append(f"threshold: {old_t} -> {new_t}")

    old_keys = {k["key_id"]: k for k in prev.get("keys", [])}
    new_keys = {k["key_id"]: k for k in new.get("keys", [])}

    for kid, key in new_keys.items():
        if kid not in old_keys:
            lines.append(
                f"+ key_id={kid} "
                f"user_id={key.get('user_id', '?')} "
                f"kind={key.get('kind', '?')}"
            )
    for kid, key in old_keys.items():
        if kid not in new_keys:
            lines.append(
                f"- key_id={kid} "
                f"user_id={key.get('user_id', '?')} "
                f"kind={key.get('kind', '?')}"
            )

    old_admins = set(prev.get("admins", []))
    new_admins = set(new.get("admins", []))
    for kid in sorted(new_admins - old_admins):
        lines.append(f"+ admin: {kid}")
    for kid in sorted(old_admins - new_admins):
        lines.append(f"- admin: {kid}")

    return "\n".join(lines)


def confirm_key_ids(
    added_key_ids: list[str],
    confirmed_ids: set[str],
) -> list[str]:
    """Return only *added_key_ids* present in *confirmed_ids*.

    An unconfirmed key_id (not typed by the admin out of band) is
    excluded (N1, threat 33).
    """
    return [kid for kid in added_key_ids if kid in confirmed_ids]


def create_signer_assertion(
    signing_key: SigningKey,
    key_id: str,
    nonce: str,
    aud: str,
) -> dict[str, Any]:
    """Build an ``agg/signer-assert/v1`` signed envelope for CLI auth."""
    payload: dict[str, Any] = {
        "key_id": key_id,
        "nonce": nonce,
        "aud": aud,
        "iat": time.time(),
    }
    return sign_envelope(SIGNER_ASSERT, payload, [signing_key])
