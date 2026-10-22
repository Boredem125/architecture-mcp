"""Key registry: chain verification, kind matrix, dual-control label (D5).

The registry is a hash-chained sequence of signed versions.  Each version
lists the admin quorum, the approver keys and the bundle signer.  The
verifier walks the chain from genesis and computes:

* Whether the chain is valid (signatures, thresholds, prev_hash).
* Which keys may sign which kinds on which environments (``may_sign``).
* Which keys count toward dual control (``counts_for_dual`` -- S9).

The signature count is always computed from the chain walk, never read
from a key entry (N8).
"""
from __future__ import annotations

import hashlib
import json
import time as _time
from typing import Any

from sandbox.protocol.domains import (
    AUDIT_HEAD,
    BUNDLE,
    DEVICE_ASSERT,
    DEVICE_ENROLL,
    POLICY_CHANGE,
    REGISTRY,
    REMOTE_APPROVAL,
    SIGNER_ASSERT,
    UNENROLL,
)
from sandbox.protocol.envelope import EnvelopeError, _verify_sigs


# -- Errors ----------------------------------------------------------------

class RegistryError(Exception):
    """Raised when a registry chain or binding check fails."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


# -- Constants -------------------------------------------------------------

_KEY_ENTRY_FIELDS = frozenset({
    "key_id", "public_key", "user_id", "iss", "sub",
    "alg", "kind", "roles", "added_in",
})

# Key kinds that may sign registry versions (D5.1).
_REGISTRY_SIGNING_KINDS = frozenset({"cli"})


# -- Public API ------------------------------------------------------------

class Registry:
    """An in-memory validated registry, produced by :func:`verify_chain`."""

    def __init__(
        self,
        keys: dict[str, dict[str, Any]],
        admins: set[str],
        expires_at: float,
        admin_sigs_at_add: dict[str, int],
    ) -> None:
        self._keys = keys                    # key_id -> key entry dict
        self._admins = admins                # set of admin key_ids
        self._expires_at = expires_at        # latest version's expires_at
        self._admin_sigs_at_add = admin_sigs_at_add  # key_id -> admin sigs on version that added it

    # -- kind matrix (D5.1) ------------------------------------------------

    def may_sign(
        self,
        kid: str,
        kind_tag: str,
        environment: str,
        *,
        decision: str = "approve",
    ) -> bool:
        """Whether key *kid* may sign *kind_tag* on *environment*.

        *decision* is ``"approve"`` (default) or ``"deny"``.  An expired
        registry refuses approvals but denies stay allowed (D6.5).
        """
        if decision not in ("approve", "deny"):
            return False

        entry = self._keys.get(kid)
        if entry is None:
            return False

        key_kind = entry["kind"]
        is_prod = environment == "prod"

        # Expired registry: only approvals refused; denies stay (D6.5)
        if (
            kind_tag == REMOTE_APPROVAL
            and decision == "approve"
            and _time.time() > self._expires_at
        ):
            return False

        if key_kind == "cli":
            if kind_tag in (REGISTRY, POLICY_CHANGE, UNENROLL, SIGNER_ASSERT):
                return True
            if kind_tag == REMOTE_APPROVAL:
                return not is_prod          # N9: non-prod only in M2
            return False

        if key_kind == "browser":
            if kind_tag == REMOTE_APPROVAL:
                return not is_prod          # non-prod only
            return False

        if key_kind == "device":
            return kind_tag in (DEVICE_ENROLL, DEVICE_ASSERT, AUDIT_HEAD)

        if key_kind == "bundle-signer":
            return kind_tag == BUNDLE

        return False

    # -- S9: single-admin-registry label -----------------------------------

    def counts_for_dual(self, kid: str) -> bool:
        """True only if the version that added *kid* had >= 2 admin sigs."""
        count = self._admin_sigs_at_add.get(kid)
        if count is None:
            return False
        return count >= 2


def verify_chain(
    envelopes: list[dict[str, Any]],
    fingerprint: str,
) -> Registry:
    """Walk a registry chain and return a :class:`Registry`.

    Raises :class:`RegistryError` on any chain violation.
    """
    if not envelopes:
        raise RegistryError("empty chain")

    # -- Genesis -----------------------------------------------------------

    genesis = envelopes[0]
    genesis_payload = genesis["payload"]

    if genesis_payload.get("version") != 1:
        raise RegistryError("first envelope must be version 1 (genesis)")

    # Fingerprint check (threat 22)
    computed_fp = _payload_hash(genesis_payload)
    if computed_fp != fingerprint:
        raise RegistryError("genesis fingerprint mismatch")

    # Validate key entries in genesis
    _validate_key_entries(genesis_payload.get("keys", []))

    # Build trusted key map from genesis admins
    genesis_keys = _key_map(genesis_payload)
    genesis_admins = set(genesis_payload.get("admins", []))
    genesis_threshold = genesis_payload.get("threshold", 1)

    # Check that all genesis admins are CLI keys
    _check_admin_kinds(genesis_keys, genesis_admins)

    # Verify genesis signatures against its own admins
    trusted = _trusted_for(genesis_keys, genesis_admins)
    try:
        verified = _verify_sigs(genesis, trusted)
    except EnvelopeError as exc:
        raise RegistryError(str(exc)) from exc

    admin_verified = verified & genesis_admins
    if len(admin_verified) < genesis_threshold:
        raise RegistryError(
            f"genesis needs {genesis_threshold} admin sigs, got {len(admin_verified)}"
        )

    # Track admin sig counts per version (for counts_for_dual)
    admin_sigs_at_add: dict[str, int] = {}
    genesis_admin_sig_count = len(admin_verified)
    for k in genesis_payload.get("keys", []):
        admin_sigs_at_add[k["key_id"]] = genesis_admin_sig_count

    # Track the floor (once 2+ admins exist, threshold >= 2)
    max_admin_count = len(genesis_admins)

    prev_payload = genesis_payload
    prev_admins = genesis_admins
    prev_threshold = genesis_threshold
    prev_keys = genesis_keys

    all_keys = dict(genesis_keys)

    # Check duplicates in genesis
    _check_duplicates(genesis_payload.get("keys", []))

    # -- Subsequent versions -----------------------------------------------

    for i, env in enumerate(envelopes[1:], start=2):
        payload = env["payload"]
        version = payload.get("version")

        # Second genesis refused (threat 22)
        if version == 1:
            raise RegistryError("second genesis refused")

        # Version must be strictly increasing
        if version is None or version <= prev_payload.get("version", 0):
            raise RegistryError(
                f"version {version} not greater than {prev_payload.get('version')}"
            )

        # Validate key entries (N8: no forged count field)
        _validate_key_entries(payload.get("keys", []))

        # Check prev_hash chains
        expected_prev = _payload_hash(prev_payload)
        if payload.get("prev_hash") != expected_prev:
            raise RegistryError("prev_hash mismatch")

        # org_id must match genesis
        if payload.get("org_id") != genesis_payload.get("org_id"):
            raise RegistryError("org_id changed across versions")

        cur_keys = _key_map(payload)
        cur_admins = set(payload.get("admins", []))
        cur_threshold = payload.get("threshold", 1)

        # Check admin kinds (only CLI may sign registry)
        _check_admin_kinds(cur_keys, cur_admins)

        # Floor rule: once 2+ admins existed, threshold >= 2
        if max_admin_count >= 2 and cur_threshold < 2:
            raise RegistryError(
                f"threshold {cur_threshold} below floor 2 "
                f"(max admin count reached {max_admin_count})"
            )

        # Floor rule: cannot cut admins below 2 once 2+ existed
        if max_admin_count >= 2 and len(cur_admins) < 2:
            raise RegistryError(
                f"admins cut to {len(cur_admins)}, below floor 2"
            )

        # Verify signatures: need prev_threshold from prev_admins
        #                    AND cur_threshold from cur_admins (D5.3, S3)
        all_trusted_keys: dict[str, bytes] = {}
        for kid in prev_admins | cur_admins:
            entry = prev_keys.get(kid) or cur_keys.get(kid)
            if entry is not None:
                all_trusted_keys[kid] = bytes.fromhex(entry["public_key"])
        try:
            verified = _verify_sigs(env, all_trusted_keys)
        except EnvelopeError as exc:
            raise RegistryError(str(exc)) from exc

        admin_verified_prev = verified & prev_admins
        if len(admin_verified_prev) < prev_threshold:
            raise RegistryError(
                f"version {version} needs {prev_threshold} admin sigs "
                f"from previous admins, got {len(admin_verified_prev)}"
            )

        admin_verified_cur = verified & cur_admins
        if len(admin_verified_cur) < cur_threshold:
            raise RegistryError(
                f"version {version} needs {cur_threshold} admin sigs "
                f"from its own admins, got {len(admin_verified_cur)}"
            )

        # Check duplicates across all keys in this version
        _check_duplicates(payload.get("keys", []))

        # Track admin sig counts for new keys (S9)
        prev_key_ids = set(prev_keys.keys())
        for k in payload.get("keys", []):
            kid = k["key_id"]
            if kid not in prev_key_ids:
                # New key added in this version
                admin_sigs_at_add[kid] = len(admin_verified_prev)

        # Update tracking
        max_admin_count = max(max_admin_count, len(cur_admins))
        prev_payload = payload
        prev_admins = cur_admins
        prev_threshold = cur_threshold
        prev_keys = cur_keys
        all_keys.update(cur_keys)

    # Honour bundle_signer field from the LATEST version only (F3).
    # An earlier version's signer is not in the key map after rotation.
    latest_bs = envelopes[-1]["payload"].get("bundle_signer")
    if latest_bs and isinstance(latest_bs, dict):
        bs_kid = latest_bs.get("key_id", "")
        bs_pub = latest_bs.get("public_key", "")
        bs_alg = latest_bs.get("alg", "ed25519")
        if bs_pub:
            # Verify key_id == sha256(public_key)
            expected_kid = hashlib.sha256(
                bytes.fromhex(bs_pub)
            ).hexdigest()
            if bs_kid != expected_kid:
                raise RegistryError(
                    f"bundle_signer key_id mismatch: "
                    f"{bs_kid} != sha256(public_key)"
                )
            # F3: bundle_signer key_id must not collide with any admin/cli key
            if bs_kid in all_keys:
                raise RegistryError(
                    f"bundle_signer key_id {bs_kid} collides with "
                    f"a key in keys"
                )
            # Add as a key entry with kind=bundle-signer
            all_keys[bs_kid] = {
                "key_id": bs_kid,
                "public_key": bs_pub,
                "user_id": "__bundle_signer__",
                "iss": "",
                "sub": "",
                "alg": bs_alg,
                "kind": "bundle-signer",
                "roles": [],
                "added_in": envelopes[-1]["payload"].get("version", 1),
            }

    # Build the Registry object from the latest version
    latest = envelopes[-1]["payload"]
    return Registry(
        keys=all_keys,
        admins=set(latest.get("admins", [])),
        expires_at=latest.get("expires_at", 0),
        admin_sigs_at_add=admin_sigs_at_add,
    )


def check_binding(
    payload: dict[str, Any],
    expected_org: str,
    expected_project: str,
) -> None:
    """Check org_id and project_id binding.  Raises :class:`RegistryError`."""
    if payload.get("org_id") != expected_org:
        raise RegistryError(
            f"org_id mismatch: {payload.get('org_id')} != {expected_org}"
        )
    if payload.get("project_id") != expected_project:
        raise RegistryError(
            f"project_id mismatch: {payload.get('project_id')} != {expected_project}"
        )


# -- Internal helpers ------------------------------------------------------

def _canonical_json(payload: dict[str, Any]) -> bytes:
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":")
    ).encode()


def _payload_hash(payload: dict[str, Any]) -> str:
    """SHA-256 hex of ``org_id || ':' || canonical_json(payload)``."""
    return hashlib.sha256(
        payload["org_id"].encode("utf-8") + b":" + _canonical_json(payload)
    ).hexdigest()


def _key_map(payload: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Build key_id -> key entry dict from a registry payload."""
    return {k["key_id"]: k for k in payload.get("keys", [])}


def _trusted_for(
    keys: dict[str, dict[str, Any]],
    admins: set[str],
) -> dict[str, bytes]:
    """Build a trusted-key dict (key_id -> pub bytes) for the given admins."""
    trusted: dict[str, bytes] = {}
    for kid in admins:
        entry = keys.get(kid)
        if entry is not None:
            trusted[kid] = bytes.fromhex(entry["public_key"])
    return trusted


def _check_admin_kinds(
    keys: dict[str, dict[str, Any]],
    admins: set[str],
) -> None:
    """Ensure all admin keys have a kind that may sign registry versions."""
    for kid in admins:
        entry = keys.get(kid)
        if entry is None:
            continue
        if entry.get("kind") not in _REGISTRY_SIGNING_KINDS:
            raise RegistryError(
                f"admin key {kid} has kind={entry.get('kind')!r}, "
                f"only {_REGISTRY_SIGNING_KINDS} may sign registry versions"
            )


def _validate_key_entries(entries: list[dict[str, Any]]) -> None:
    """Check that key entries have exactly the allowed fields (N8)."""
    for entry in entries:
        extra = set(entry.keys()) - _KEY_ENTRY_FIELDS
        if extra:
            raise RegistryError(
                f"key entry has extra fields: {extra} (forged count?)"
            )


def _check_duplicates(entries: list[dict[str, Any]]) -> None:
    """Refuse duplicate (iss, sub) or shared public key across user_ids."""
    seen_identity: dict[tuple[str, str], str] = {}
    seen_key: dict[str, str] = {}

    for entry in entries:
        iss_sub = (entry["iss"], entry["sub"])
        kid = entry["key_id"]
        uid = entry["user_id"]

        if iss_sub in seen_identity and seen_identity[iss_sub] != uid:
            raise RegistryError(
                f"duplicate (iss, sub) {iss_sub} across users "
                f"{seen_identity[iss_sub]} and {uid}"
            )
        seen_identity[iss_sub] = uid

        if kid in seen_key and seen_key[kid] != uid:
            raise RegistryError(
                f"shared public key {kid} across users "
                f"{seen_key[kid]} and {uid}"
            )
        seen_key[kid] = uid
