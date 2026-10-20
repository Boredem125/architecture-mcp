"""In-process fake IdP and helpers for T8 OIDC tests.

Provides:
- ``FakeIdP`` -- signs id_tokens with controllable claims and JWKS rotation.
- ``FakeJWKSProvider`` -- implements the JWKSProvider protocol, counts fetches.
- ``FakeClock`` -- settable/advanceable, tz-aware UTC, satisfies ``agg_cp.clock.Clock``.
- ``REMOVE`` -- sentinel to remove a claim from a minted token.
"""
from __future__ import annotations

import base64
import copy
import datetime as dt
import hashlib
import hmac
import json
import uuid
from typing import Any

import warnings

warnings.filterwarnings("ignore", category=DeprecationWarning, module="authlib")

from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives import serialization

from authlib.jose import JsonWebKey, jwt


# ---------------------------------------------------------------------------
# Sentinel for removing claims
# ---------------------------------------------------------------------------

class _Remove:
    """Sentinel: ``claim=REMOVE`` removes the claim from the minted token."""
    _instance = None

    def __new__(cls) -> "_Remove":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __repr__(self) -> str:
        return "REMOVE"


REMOVE = _Remove()


# ---------------------------------------------------------------------------
# FakeClock -- satisfies agg_cp.clock.Clock
# ---------------------------------------------------------------------------

class FakeClock:
    """Settable and advanceable clock returning tz-aware UTC datetimes.

    Satisfies ``agg_cp.clock.Clock`` (``now() -> datetime``).
    """

    def __init__(self, now: dt.datetime | None = None) -> None:
        if now is None:
            now = dt.datetime.now(dt.timezone.utc)
        if now.tzinfo is None:
            now = now.replace(tzinfo=dt.timezone.utc)
        self._now = now

    def now(self) -> dt.datetime:
        return self._now

    def set(self, when: dt.datetime) -> None:
        if when.tzinfo is None:
            when = when.replace(tzinfo=dt.timezone.utc)
        self._now = when

    def advance(self, delta: dt.timedelta) -> None:
        self._now = self._now + delta


# ---------------------------------------------------------------------------
# FakeIdP -- in-process IdP using cryptography + authlib.jose
# ---------------------------------------------------------------------------

_DEFAULT_CLIENT_ID = "fake-client-id"
_DEFAULT_NONCE = "test-nonce"


def _new_kid() -> str:
    return f"kid-{uuid.uuid4().hex[:8]}"


def _generate_key_pair(alg: str) -> tuple[Any, bytes]:
    """Return (private_key_object, private_pem_bytes) for the given alg family."""
    if alg in ("RS256", "PS256"):
        priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    elif alg == "ES256":
        priv = ec.generate_private_key(ec.SECP256R1())
    else:
        raise ValueError(f"Unsupported alg for key generation: {alg}")
    pem = priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    return priv, pem


class FakeIdP:
    """In-process fake IdP that signs id_tokens.

    Parameters
    ----------
    issuer : str
        The ``iss`` claim value.
    alg : str
        Default signing algorithm (RS256, PS256, or ES256).
    client_id : str
        Default ``aud`` claim value.
    """

    def __init__(
        self,
        issuer: str,
        *,
        alg: str = "RS256",
        client_id: str = _DEFAULT_CLIENT_ID,
    ) -> None:
        self.issuer = issuer
        self.default_alg = alg
        self.client_id = client_id

        # Key management: list of (kid, alg, authlib_jwk, is_current)
        self._keys: list[dict[str, Any]] = []
        self._add_key(alg)

    def _add_key(self, alg: str) -> str:
        kid = _new_kid()
        _priv_obj, pem = _generate_key_pair(alg)
        jwk = JsonWebKey.import_key(pem, {"kid": kid, "use": "sig", "alg": alg})
        # Mark all existing as not current
        for entry in self._keys:
            entry["current"] = False
        self._keys.append({"kid": kid, "alg": alg, "jwk": jwk, "current": True})
        return kid

    @property
    def current_kid(self) -> str:
        for entry in self._keys:
            if entry["current"]:
                return entry["kid"]
        raise RuntimeError("No current key")

    @property
    def current_jwk(self) -> Any:
        for entry in self._keys:
            if entry["current"]:
                return entry["jwk"]
        raise RuntimeError("No current key")

    def jwks(self) -> dict:
        """Return the public JWKS dict (only current keys)."""
        keys = []
        for entry in self._keys:
            if entry["current"]:
                pub = entry["jwk"].as_dict(is_private=False)
                keys.append(pub)
        return {"keys": keys}

    def all_jwks(self) -> dict:
        """Return JWKS dict with ALL keys (including retired), for testing."""
        keys = []
        for entry in self._keys:
            pub = entry["jwk"].as_dict(is_private=False)
            keys.append(pub)
        return {"keys": keys}

    def rotate(self, alg: str | None = None) -> str:
        """Add a new key, make it current, drop old from jwks(). Returns new kid."""
        if alg is None:
            alg = self.default_alg
        return self._add_key(alg)

    def get_rsa_public_pem(self) -> bytes:
        """Return the current RSA public key as PEM bytes (for alg-confusion tests)."""
        for entry in self._keys:
            if entry["current"] and entry["alg"] in ("RS256", "PS256"):
                # Extract the raw key from authlib JWK
                raw_key = entry["jwk"].get_public_key()
                return raw_key.public_bytes(
                    serialization.Encoding.PEM,
                    serialization.PublicFormat.SubjectPublicKeyInfo,
                )
        raise RuntimeError("No current RSA key for PEM export")

    def mint(
        self,
        *,
        now: dt.datetime | None = None,
        **overrides: Any,
    ) -> str:
        """Return a signed id_token (str) with defaults, overridable claims.

        Use ``claim=REMOVE`` to remove a claim entirely.
        Special overrides:
        - ``_alg``: override header ``alg`` (default: current key's alg)
        - ``_kid``: override header ``kid`` (default: current key's kid)
        - ``_jwk``: override signing key (authlib JWK)
        """
        if now is None:
            now = dt.datetime.now(dt.timezone.utc)
        if now.tzinfo is None:
            now = now.replace(tzinfo=dt.timezone.utc)

        iat = int(now.timestamp())
        exp = iat + 3600

        claims: dict[str, Any] = {
            "iss": self.issuer,
            "sub": "user-1",
            "aud": self.client_id,
            "nonce": _DEFAULT_NONCE,
            "iat": iat,
            "exp": exp,
            "auth_time": iat,
        }

        # Extract header overrides
        alg = overrides.pop("_alg", None)
        kid = overrides.pop("_kid", None)
        signing_jwk = overrides.pop("_jwk", None)

        # Apply claim overrides
        for key, val in overrides.items():
            if val is REMOVE:
                claims.pop(key, None)
            else:
                claims[key] = val

        # Determine signing key and header
        if signing_jwk is None:
            signing_jwk = self.current_jwk
        if alg is None:
            for entry in self._keys:
                if entry["current"]:
                    alg = entry["alg"]
                    break
            else:
                alg = self.default_alg
        if kid is None:
            kid = self.current_kid

        header = {"alg": alg, "kid": kid}
        token_bytes = jwt.encode(header, claims, signing_jwk)
        if isinstance(token_bytes, bytes):
            return token_bytes.decode("ascii")
        return token_bytes

    def mint_unsigned(self, *, now: dt.datetime | None = None, **overrides: Any) -> str:
        """Return an unsigned id_token (alg=none)."""
        if now is None:
            now = dt.datetime.now(dt.timezone.utc)
        if now.tzinfo is None:
            now = now.replace(tzinfo=dt.timezone.utc)

        iat = int(now.timestamp())
        exp = iat + 3600

        claims: dict[str, Any] = {
            "iss": self.issuer,
            "sub": "user-1",
            "aud": self.client_id,
            "nonce": _DEFAULT_NONCE,
            "iat": iat,
            "exp": exp,
            "auth_time": iat,
        }

        for key, val in overrides.items():
            if val is REMOVE:
                claims.pop(key, None)
            else:
                claims[key] = val

        header = _b64url_encode(json.dumps({"alg": "none", "typ": "JWT"}).encode())
        payload = _b64url_encode(json.dumps(claims).encode())
        return f"{header}.{payload}."

    def mint_hs256(
        self,
        secret: bytes | str,
        *,
        now: dt.datetime | None = None,
        **overrides: Any,
    ) -> str:
        """Return an HS256-signed id_token.

        For the alg-confusion attack, pass ``secret=idp.get_rsa_public_pem()``.
        """
        if now is None:
            now = dt.datetime.now(dt.timezone.utc)
        if now.tzinfo is None:
            now = now.replace(tzinfo=dt.timezone.utc)

        iat = int(now.timestamp())
        exp = iat + 3600

        claims: dict[str, Any] = {
            "iss": self.issuer,
            "sub": "user-1",
            "aud": self.client_id,
            "nonce": _DEFAULT_NONCE,
            "iat": iat,
            "exp": exp,
            "auth_time": iat,
        }

        for key, val in overrides.items():
            if val is REMOVE:
                claims.pop(key, None)
            else:
                claims[key] = val

        if isinstance(secret, str):
            secret = secret.encode()

        header_b64 = _b64url_encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
        payload_b64 = _b64url_encode(json.dumps(claims).encode())
        signing_input = f"{header_b64}.{payload_b64}".encode()
        sig = hmac.new(secret, signing_input, hashlib.sha256).digest()
        sig_b64 = _b64url_encode(sig)
        return f"{header_b64}.{payload_b64}.{sig_b64}"

    def _find_key_by_kid(self, kid: str) -> dict[str, Any] | None:
        for entry in self._keys:
            if entry["kid"] == kid:
                return entry
        return None


# ---------------------------------------------------------------------------
# FakeJWKSProvider -- satisfies JWKSProvider protocol
# ---------------------------------------------------------------------------

class FakeJWKSProvider:
    """Provider backed by a FakeIdP, counting ``get_jwks`` calls."""

    def __init__(self, idp: FakeIdP) -> None:
        self._idp = idp
        self.fetches = 0
        self._cached: dict | None = None

    def get_jwks(self, *, force_refresh: bool = False) -> dict:
        if force_refresh or self._cached is None:
            self.fetches += 1
            self._cached = copy.deepcopy(self._idp.jwks())
        return self._cached


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(data: str) -> bytes:
    padding = 4 - len(data) % 4
    if padding != 4:
        data += "=" * padding
    return base64.urlsafe_b64decode(data)


def decode_token_unverified(token: str) -> tuple[dict, dict]:
    """Decode a JWT without verification. Returns (header, payload)."""
    parts = token.split(".")
    if len(parts) < 2:
        raise ValueError("Not a valid JWT")
    header = json.loads(_b64url_decode(parts[0]))
    payload = json.loads(_b64url_decode(parts[1]))
    return header, payload


def tamper_payload(token: str, **updates: Any) -> str:
    """Alter payload claims in a signed token (invalidates the signature)."""
    parts = token.split(".")
    payload = json.loads(_b64url_decode(parts[1]))
    payload.update(updates)
    parts[1] = _b64url_encode(json.dumps(payload).encode())
    return ".".join(parts)


def swap_header(token: str, **updates: Any) -> str:
    """Alter header fields in a signed token (invalidates the signature)."""
    parts = token.split(".")
    header = json.loads(_b64url_decode(parts[0]))
    header.update(updates)
    parts[0] = _b64url_encode(json.dumps(header).encode())
    return ".".join(parts)
