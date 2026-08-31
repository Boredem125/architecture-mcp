"""Command signature verification per AGENT_09 spec.

Verifies Ed25519 signatures, timestamp freshness, command hash integrity,
and session validity before a SignedCommand is allowed to execute.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone

from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey

from sandbox.models.messages import SignedCommand


@dataclass(frozen=True, slots=True)
class VerificationResult:
    """Outcome of a multi-check command verification."""

    valid: bool
    reason: str
    command_hash_match: bool
    session_active: bool
    scope_match: bool
    timestamp_valid: bool


def _compute_command_hash(action_type: str, parameters: dict) -> str:
    """Reproduce the canonical SHA-256 hash of action_type + parameters.

    The canonical form concatenates the action_type string with the
    deterministic JSON serialisation of the parameters dict, then
    SHA-256-hashes the result.  This MUST match the signing side.
    """
    canonical = action_type + json.dumps(
        parameters, sort_keys=True, separators=(",", ":"), default=str
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class SignatureVerifier:
    """Verifies signed commands against the AGENT_09 security contract.

    Checks performed (in order, short-circuiting on first failure):
      1. Ed25519 signature validity.
      2. Timestamp within *max_age_seconds* of current UTC time.
      3. SHA-256 command hash matches recomputed hash of action_type +
         parameters.
      4. Session ID is present and non-empty.
    """

    def __init__(self, verify_key_hex: str, max_age_seconds: int = 30) -> None:
        """Initialise the verifier.

        Args:
            verify_key_hex: Hex-encoded Ed25519 public key (32 bytes → 64 hex
                chars).
            max_age_seconds: Maximum age (in seconds) of the ``signed_at_utc``
                timestamp before the command is considered stale.  Defaults to
                30 s per spec.
        """
        self._verify_key = VerifyKey(bytes.fromhex(verify_key_hex))
        self._max_age = max_age_seconds

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def verify(self, command: SignedCommand) -> VerificationResult:
        """Run all verification checks on *command* and return the result.

        The method never raises on verification failure — it returns a
        ``VerificationResult`` with ``valid=False`` and a human-readable
        ``reason``.  Unexpected exceptions (e.g. malformed key material)
        are allowed to propagate.
        """
        sig_ok = self._check_signature(command)
        ts_ok = self._check_timestamp(command)
        hash_ok = self._check_command_hash(command)
        session_ok = self._check_session(command)

        # Short-circuit: report first failing check as the reason.
        if not sig_ok:
            return VerificationResult(
                valid=False,
                reason="Ed25519 signature verification failed",
                command_hash_match=hash_ok,
                session_active=session_ok,
                scope_match=True,  # scope not separately checked here
                timestamp_valid=ts_ok,
            )

        if not ts_ok:
            return VerificationResult(
                valid=False,
                reason=(
                    f"Command timestamp outside allowed window "
                    f"({self._max_age}s)"
                ),
                command_hash_match=hash_ok,
                session_active=session_ok,
                scope_match=True,
                timestamp_valid=False,
            )

        if not hash_ok:
            return VerificationResult(
                valid=False,
                reason="Command hash does not match content hash",
                command_hash_match=False,
                session_active=session_ok,
                scope_match=True,
                timestamp_valid=True,
            )

        if not session_ok:
            return VerificationResult(
                valid=False,
                reason="Session ID is missing or empty",
                command_hash_match=True,
                session_active=False,
                scope_match=True,
                timestamp_valid=True,
            )

        return VerificationResult(
            valid=True,
            reason="All checks passed",
            command_hash_match=True,
            session_active=True,
            scope_match=True,
            timestamp_valid=True,
        )

    # ------------------------------------------------------------------
    # Individual checks
    # ------------------------------------------------------------------

    def _check_signature(self, command: SignedCommand) -> bool:
        """Verify the Ed25519 signature over the command hash."""
        if not command.signature or not command.command_hash:
            return False
        try:
            # The signature is produced over the raw command_hash bytes.
            self._verify_key.verify(
                command.command_hash.encode("utf-8"),
                bytes.fromhex(command.signature),
            )
            return True
        except (BadSignatureError, ValueError):
            return False

    def _check_timestamp(self, command: SignedCommand) -> bool:
        """Ensure ``signed_at_utc`` is within the allowed age window."""
        try:
            signed_at = datetime.fromisoformat(command.signed_at_utc)
            # Ensure timezone-aware comparison.
            if signed_at.tzinfo is None:
                signed_at = signed_at.replace(tzinfo=timezone.utc)
            now = datetime.now(timezone.utc)
            delta = abs((now - signed_at).total_seconds())
            return delta <= self._max_age
        except (ValueError, TypeError):
            return False

    def _check_command_hash(self, command: SignedCommand) -> bool:
        """Recompute the SHA-256 hash and compare to the stored hash."""
        if not command.command_hash:
            return False
        expected = _compute_command_hash(
            str(command.action_type), command.parameters
        )
        return expected == command.command_hash

    def _check_session(self, command: SignedCommand) -> bool:
        """Verify the session ID is provided and non-empty."""
        return bool(command.session_id and command.session_id.strip())
