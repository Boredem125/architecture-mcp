"""Server-side registry storage and retrieval.

Uses the T5 tables (``key_registry_versions``, ``sync_alerts``) under
RLS with ``app.org_id``.  Verification reuses
``sandbox.protocol.registry.verify_chain``.
"""
from __future__ import annotations

import hashlib
import json
import uuid
from typing import Any

from sandbox.protocol.registry import RegistryError, verify_chain

# T12b-2 sentinel: store_registry_version writes approver_keys (ADR 0010 s8).
_T12B2_APPROVER_KEYS = True


def _canonical_json(payload: dict[str, Any]) -> bytes:
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":")
    ).encode()


def _payload_hash(payload: dict[str, Any]) -> str:
    return hashlib.sha256(
        payload["org_id"].encode("utf-8") + b":" + _canonical_json(payload)
    ).hexdigest()


def store_registry_version(
    conn: Any,
    org_id: str,
    envelope: dict[str, Any],
) -> int:
    """Verify and store a registry version.  Returns the version number.

    Sets ``app.org_id`` for the transaction and commits on success (or
    on alert).  Raises :class:`RegistryError` on any failure.
    """
    conn.execute(
        "SELECT set_config('app.org_id', %s, true)", [org_id]
    )

    payload = envelope.get("payload", {})

    # Org binding check
    if str(payload.get("org_id", "")) != str(org_id):
        raise RegistryError(
            f"envelope org_id {payload.get('org_id')} != {org_id}"
        )

    version = payload.get("version")
    if version is None:
        raise RegistryError("missing version in payload")

    # Check for second genesis (threat 22)
    if version == 1:
        existing = conn.execute(
            "SELECT 1 FROM key_registry_versions "
            "WHERE org_id = %s::uuid AND version = 1",
            [org_id],
        ).fetchone()
        if existing is not None:
            # Write sync_alerts row and commit it
            conn.execute(
                "INSERT INTO sync_alerts "
                "(id, org_id, project_id, kind, created_at) "
                "VALUES (%s::uuid, %s::uuid, "
                "'00000000-0000-0000-0000-000000000000'::uuid, "
                "'second_genesis', now())",
                [str(uuid.uuid4()), org_id],
            )
            conn.commit()
            raise RegistryError("second genesis refused")

    # Fetch existing chain
    rows = conn.execute(
        "SELECT registry_blob FROM key_registry_versions "
        "WHERE org_id = %s::uuid ORDER BY version",
        [org_id],
    ).fetchall()
    existing_chain = [json.loads(bytes(r[0])) for r in rows]

    # Build full chain for verification
    chain = existing_chain + [envelope]

    # Compute genesis fingerprint
    genesis_payload = chain[0]["payload"]
    fp = _payload_hash(genesis_payload)

    # Verify the entire chain (raises RegistryError or EnvelopeError)
    try:
        verify_chain(chain, fp)
    except Exception as exc:
        if isinstance(exc, RegistryError):
            raise
        raise RegistryError(str(exc)) from exc

    # Store the new version
    blob = json.dumps(envelope).encode("utf-8")
    sigs = json.dumps(envelope.get("signatures", []))
    conn.execute(
        "INSERT INTO key_registry_versions "
        "(id, org_id, version, registry_blob, signatures, created_at) "
        "VALUES (%s::uuid, %s::uuid, %s, %s, %s::jsonb, now())",
        [str(uuid.uuid4()), org_id, version, blob, sigs],
    )

    # ----------------------------------------------------------------
    # ADR 0010 s8: upsert approver_keys projection in the same txn
    # ----------------------------------------------------------------
    keys = payload.get("keys", [])
    key_ids_in_version: set[str] = set()

    # F5/F7: refuse a key_id that is live (not revoked) in another org.
    # Uses check_key_id_cross_org SECURITY DEFINER function (0012/0013)
    # which checks ONLY other orgs' live approver_keys rows (not
    # unverified signer_links).  The function is STRICT (NULL-safe).
    for key in keys:
        kid = key.get("key_id", "")
        if not kid:
            continue
        conflict = conn.execute(
            "SELECT check_key_id_cross_org(%s, %s::uuid)",
            [kid, org_id],
        ).fetchone()
        if conflict is not None and conflict[0]:
            raise RegistryError(
                f"key_id {kid[:16]}... cannot be published"
            )

    for key in keys:
        kid = key.get("key_id", "")
        if not kid:
            continue
        key_ids_in_version.add(kid)
        conn.execute(
            "INSERT INTO approver_keys "
            "(id, org_id, user_id, key_id, public_key, alg, kind, roles, "
            "registry_version, revoked_at, created_at) "
            "VALUES (%s::uuid, %s::uuid, %s, %s, %s, %s, %s, %s::jsonb, "
            "%s, NULL, now()) "
            "ON CONFLICT (org_id, key_id) DO UPDATE SET "
            "user_id = EXCLUDED.user_id, "
            "public_key = EXCLUDED.public_key, "
            "alg = EXCLUDED.alg, "
            "kind = EXCLUDED.kind, "
            "roles = EXCLUDED.roles, "
            "registry_version = EXCLUDED.registry_version, "
            "revoked_at = NULL",
            [
                str(uuid.uuid4()), org_id,
                key.get("user_id", ""),
                kid,
                key.get("public_key", ""),
                key.get("alg", "ed25519"),
                key.get("kind", "cli"),
                json.dumps(key.get("roles", [])),
                version,
            ],
        )

    # Mark keys absent from this version as revoked
    if key_ids_in_version:
        placeholders = ", ".join(["%s"] * len(key_ids_in_version))
        conn.execute(
            f"UPDATE approver_keys SET revoked_at = now() "
            f"WHERE org_id = %s::uuid "
            f"AND key_id NOT IN ({placeholders}) "
            f"AND revoked_at IS NULL",
            [org_id] + sorted(key_ids_in_version),
        )
    else:
        # No keys in the new version: revoke all
        conn.execute(
            "UPDATE approver_keys SET revoked_at = now() "
            "WHERE org_id = %s::uuid AND revoked_at IS NULL",
            [org_id],
        )

    conn.commit()

    return version


def get_chain(
    conn: Any,
    org_id: str,
) -> list[dict[str, Any]]:
    """Return the full registry chain for *org_id* in version order.

    Sets ``app.org_id`` for the query so RLS filters correctly.
    Returns an empty list if no registry versions exist.
    """
    conn.execute(
        "SELECT set_config('app.org_id', %s, true)", [org_id]
    )
    rows = conn.execute(
        "SELECT registry_blob FROM key_registry_versions "
        "WHERE org_id = %s::uuid ORDER BY version",
        [org_id],
    ).fetchall()
    return [json.loads(bytes(r[0])) for r in rows]


def latest(
    conn: Any,
    org_id: str,
    after: int = 0,
) -> dict[str, Any] | None:
    """Return the latest registry envelope with version > *after*, or None."""
    conn.execute(
        "SELECT set_config('app.org_id', %s, true)", [org_id]
    )
    row = conn.execute(
        "SELECT registry_blob FROM key_registry_versions "
        "WHERE org_id = %s::uuid AND version > %s "
        "ORDER BY version DESC LIMIT 1",
        [org_id, after],
    ).fetchone()
    if row is None:
        return None
    return json.loads(bytes(row[0]))
