from __future__ import annotations

import hashlib
import secrets
import time
from datetime import datetime, timezone
from typing import Any

import jwt

from sandbox.models.enums import ActionType
from sandbox.models.session import CapabilityToken


_DEFAULT_SECRET = secrets.token_hex(32)
_DEFAULT_ALGORITHM = "HS256"
_DEFAULT_EXPIRY_SECONDS = 1800


class TokenIssuer:
    """Issues and validates JWT capability tokens for sandbox sessions."""

    def __init__(self, secret: str | None = None, algorithm: str = _DEFAULT_ALGORITHM) -> None:
        self._secret = secret or _DEFAULT_SECRET
        self._algorithm = algorithm
        self._revoked: set[str] = set()

    def issue_token(
        self,
        agent_id: str,
        session_id: str,
        allowed_actions: list[ActionType],
        workspace_root: str = "/tmp/workspace",
        expires_in_seconds: int = _DEFAULT_EXPIRY_SECONDS,
        allowed_network_hosts: list[str] | None = None,
        allowed_secrets: list[str] | None = None,
        max_writes: int = 100,
        max_requests: int = 1000,
        issued_by: str = "sandbox-authority",
    ) -> str:
        now = datetime.now(timezone.utc)
        expires_at = now.timestamp() + expires_in_seconds

        payload: dict[str, Any] = {
            "agent_id": agent_id,
            "session_id": session_id,
            "allowed_actions": [a.value if hasattr(a, "value") else a for a in allowed_actions],
            "workspace_root": workspace_root,
            "allowed_network_hosts": allowed_network_hosts or [],
            "allowed_secrets": allowed_secrets or [],
            "max_writes": max_writes,
            "max_requests": max_requests,
            "expires_at": expires_at,
            "issued_by": issued_by,
            "iat": now.timestamp(),
            "exp": expires_at,
        }

        token_fingerprint = self._compute_fingerprint(payload)
        payload["token_fingerprint"] = token_fingerprint

        return jwt.encode(payload, self._secret, algorithm=self._algorithm)

    def validate_token(self, token: str) -> CapabilityToken:
        if self.is_revoked(token):
            raise jwt.InvalidTokenError("Token has been revoked")

        try:
            payload = jwt.decode(token, self._secret, algorithms=[self._algorithm])
        except jwt.ExpiredSignatureError:
            raise
        except jwt.InvalidTokenError:
            raise

        stored_fingerprint = payload.get("token_fingerprint", "")
        check_payload = {k: v for k, v in payload.items() if k != "token_fingerprint"}
        expected_fingerprint = self._compute_fingerprint(check_payload)
        if stored_fingerprint != expected_fingerprint:
            raise jwt.InvalidTokenError("Token fingerprint mismatch — possible tampering")

        expires_at_utc = datetime.fromtimestamp(payload["expires_at"], tz=timezone.utc).isoformat()

        return CapabilityToken(
            agent_id=payload["agent_id"],
            session_id=payload["session_id"],
            allowed_actions=[ActionType(a) for a in payload["allowed_actions"]],
            workspace_root=payload["workspace_root"],
            allowed_network_hosts=payload.get("allowed_network_hosts", []),
            allowed_secrets=payload.get("allowed_secrets", []),
            max_writes=payload.get("max_writes", 100),
            max_requests=payload.get("max_requests", 1000),
            expires_at_utc=expires_at_utc,
            issued_by=payload.get("issued_by", ""),
            token_fingerprint=stored_fingerprint,
        )

    def revoke_token(self, token: str) -> None:
        fingerprint = self._extract_fingerprint(token)
        if fingerprint:
            self._revoked.add(fingerprint)

    def is_revoked(self, token: str) -> bool:
        fingerprint = self._extract_fingerprint(token)
        if not fingerprint:
            return False
        return fingerprint in self._revoked

    def _extract_fingerprint(self, token: str) -> str:
        try:
            payload = jwt.decode(
                token, self._secret, algorithms=[self._algorithm], options={"verify_exp": False}
            )
            return payload.get("token_fingerprint", "")
        except jwt.InvalidTokenError:
            return ""

    @staticmethod
    def _compute_fingerprint(payload: dict[str, Any]) -> str:
        canonical = str(sorted(payload.items())).encode()
        return hashlib.sha256(canonical).hexdigest()[:16]
