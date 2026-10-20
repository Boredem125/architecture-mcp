"""OIDC ID-token verification and discovery for the control plane (SEC-13).

Provides:
- ``IdTokenVerifier``: verifies OIDC id_tokens against a JWKS.
- ``check_fetch_url``: URL safety checks for discovery/JWKS fetches.
- ``fetch_discovery``: fetches and validates OIDC discovery documents.
- ``HttpJWKSProvider``: a JWKSProvider that fetches JWKS from a URL.

Security invariants (D5.4 / SEC-13):
- Header ``alg`` is checked against ``ALLOWED_ALGS`` before any key use.
- Key is selected by ``kid`` from the JWKS; ``kty`` must match the alg family.
- ``jwk``, ``jku``, ``x5u`` header params are ignored (key source is always
  our JWKS, never the token).
- Nonce comparison uses ``hmac.compare_digest``.
- Time comes only from the injected ``Clock``; never ``time.time`` etc.
- No module-level mutable state.
- Errors carry only short reason codes; never token contents or keys.
"""
from __future__ import annotations

import base64
import datetime as dt
import hmac
import ipaddress
import json
import uuid
from dataclasses import dataclass
from typing import Any, Callable, Mapping, Protocol, runtime_checkable
from urllib.parse import urlparse

from authlib.jose import JsonWebKey
from authlib.jose import jwt as _authlib_jwt

from agg_cp.clock import Clock


# ---------------------------------------------------------------------------
# Constants (immutable module-level state only)
# ---------------------------------------------------------------------------

ALLOWED_ALGS = frozenset({"RS256", "PS256", "ES256"})
SENSITIVE_MAX_AGE_S = 900

# Algorithm -> expected JWK key type.  Tuple of tuples (immutable).
_ALG_KTY = (
    ("RS256", "RSA"),
    ("PS256", "RSA"),
    ("ES256", "EC"),
)


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

class OIDCError(Exception):
    """OIDC-related error carrying a short, non-secret reason code."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


class IdTokenError(OIDCError):
    """ID-token verification failed."""


class UnsafeURLError(OIDCError):
    """URL failed the SSRF safety check."""


# ---------------------------------------------------------------------------
# OrgOIDCConfig
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class OrgOIDCConfig:
    """Per-organisation OIDC configuration.

    ``issuer`` may contain ``{tenantid}`` (Entra ID template); if so,
    ``tenant_id`` is required.
    """

    issuer: str
    client_id: str
    tenant_id: str | None = None

    def expected_issuer(self) -> str:
        """Return the issuer with ``{tenantid}`` rendered, if templated."""
        if "{tenantid}" in self.issuer:
            if self.tenant_id is None:
                raise OIDCError("issuer_template_without_tenant")
            # Entra tenant ids are GUIDs; anything else could reshape the issuer.
            try:
                canonical = str(uuid.UUID(self.tenant_id))
            except ValueError:
                raise OIDCError("bad_tenant_id") from None
            if canonical != self.tenant_id.lower():
                raise OIDCError("bad_tenant_id")
            return self.issuer.replace("{tenantid}", self.tenant_id)
        return self.issuer


# ---------------------------------------------------------------------------
# JWKSProvider protocol
# ---------------------------------------------------------------------------

@runtime_checkable
class JWKSProvider(Protocol):
    """Protocol: supplies a JWKS dict (``{"keys": [...]}``).

    Implementations must support ``force_refresh`` to bypass caching.
    """

    def get_jwks(self, *, force_refresh: bool = False) -> dict: ...


# ---------------------------------------------------------------------------
# VerifiedIdentity
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class VerifiedIdentity:
    """Successful verification result.  ``link_key`` is always ``(iss, sub)``."""

    iss: str
    sub: str
    auth_time: dt.datetime | None
    claims: Mapping[str, Any]

    @property
    def link_key(self) -> tuple[str, str]:
        """Identity link key: ``(iss, sub)``.  Never email."""
        return (self.iss, self.sub)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _b64url_decode(s: str) -> bytes:
    """Base64url-decode without padding."""
    rem = len(s) % 4
    if rem:
        s += "=" * (4 - rem)
    return base64.urlsafe_b64decode(s)


def _kty_for_alg(alg: str) -> str:
    """Return the expected JWK ``kty`` for *alg*."""
    for a, kty in _ALG_KTY:
        if a == alg:
            return kty
    raise IdTokenError("alg_not_allowed")


# ---------------------------------------------------------------------------
# IdTokenVerifier
# ---------------------------------------------------------------------------

class IdTokenVerifier:
    """Verifies OIDC ID tokens.

    All time checks use the injected *clock*; the system clock is never read.
    JWKS forced-refresh is rate-limited to at most once per
    *min_refresh_interval_s* (per verifier instance, clock-based).
    """

    def __init__(
        self,
        *,
        clock: Clock,
        jwks: JWKSProvider,
        leeway_s: int = 60,
        min_refresh_interval_s: int = 60,
    ) -> None:
        self._clock = clock
        self._jwks = jwks
        self._leeway_s = leeway_s
        self._min_refresh_interval_s = min_refresh_interval_s
        # Instance-level mutable cache (not module-level).
        self._last_forced_refresh: dt.datetime | None = None

    # -- public API --------------------------------------------------------

    def verify(
        self,
        id_token: str,
        *,
        config: OrgOIDCConfig,
        nonce: str,
        max_age_s: int | None = None,
    ) -> VerifiedIdentity:
        """Verify *id_token* and return a ``VerifiedIdentity``."""

        # 1. Structural parse -----------------------------------------------
        parts = id_token.split(".")
        if len(parts) != 3:
            raise IdTokenError("malformed")

        try:
            header = json.loads(_b64url_decode(parts[0]))
        except Exception:
            raise IdTokenError("malformed")

        # 2. alg gate (BEFORE any key use) ----------------------------------
        alg = header.get("alg")
        if alg not in ALLOWED_ALGS:
            raise IdTokenError("alg_not_allowed")

        # 3. kid -------------------------------------------------------------
        kid = header.get("kid")
        if kid is None:
            raise IdTokenError("malformed")

        # 4. Key lookup by kid -----------------------------------------------
        key_dict = self._lookup_key(kid)
        if key_dict is None:
            key_dict = self._refresh_and_lookup(kid)
        if key_dict is None:
            raise IdTokenError("unknown_kid")

        # 5. kty must match alg family --------------------------------------
        required_kty = _kty_for_alg(alg)
        if key_dict.get("kty") != required_kty:
            raise IdTokenError("alg_not_allowed")

        # 6. Signature verification (authlib) --------------------------------
        try:
            jwk_obj = JsonWebKey.import_key(key_dict)
            claims_obj = _authlib_jwt.decode(id_token, jwk_obj)
        except Exception:
            raise IdTokenError("bad_signature")

        payload = dict(claims_obj)

        # 7. Claim validation -----------------------------------------------
        self._validate_claims(payload, config, nonce, max_age_s)

        # 8. Build result ----------------------------------------------------
        raw_auth_time = payload.get("auth_time")
        auth_time_dt: dt.datetime | None = None
        if raw_auth_time is not None:
            auth_time_dt = dt.datetime.fromtimestamp(
                int(raw_auth_time), tz=dt.timezone.utc,
            )

        return VerifiedIdentity(
            iss=payload["iss"],
            sub=payload["sub"],
            auth_time=auth_time_dt,
            claims=payload,
        )

    # -- key lookup --------------------------------------------------------

    def _lookup_key(self, kid: str) -> dict[str, Any] | None:
        jwks = self._jwks.get_jwks()
        for k in jwks.get("keys", ()):
            if k.get("kid") == kid:
                return dict(k)
        return None

    def _refresh_and_lookup(self, kid: str) -> dict[str, Any] | None:
        """Force-refresh (rate-limited) and try to find *kid*."""
        now = self._clock.now()
        if self._last_forced_refresh is not None:
            elapsed = (now - self._last_forced_refresh).total_seconds()
            if elapsed < self._min_refresh_interval_s:
                return None  # rate-limited
        self._last_forced_refresh = now
        jwks = self._jwks.get_jwks(force_refresh=True)
        for k in jwks.get("keys", ()):
            if k.get("kid") == kid:
                return dict(k)
        return None

    # -- claim validation --------------------------------------------------

    def _validate_claims(
        self,
        payload: dict[str, Any],
        config: OrgOIDCConfig,
        nonce: str,
        max_age_s: int | None,
    ) -> None:
        now = self._clock.now()
        now_ts = now.timestamp()

        # sub required
        if "sub" not in payload:
            raise IdTokenError("malformed")

        # iss: exact string match
        expected_iss = config.expected_issuer()
        if payload.get("iss") != expected_iss:
            raise IdTokenError("iss_mismatch")

        # Entra tid
        if config.tenant_id is not None:
            if payload.get("tid") != config.tenant_id:
                raise IdTokenError("tid_mismatch")

        # aud: str or list must contain client_id
        raw_aud = payload.get("aud")
        if isinstance(raw_aud, str):
            aud_list = (raw_aud,)
        elif isinstance(raw_aud, list):
            aud_list = tuple(raw_aud)
        else:
            raise IdTokenError("aud_mismatch")

        if config.client_id not in aud_list:
            raise IdTokenError("aud_mismatch")

        # azp: must equal client_id if present; required when aud has >1 value
        raw_azp = payload.get("azp")
        if len(aud_list) > 1 and raw_azp is None:
            raise IdTokenError("azp_required")
        if raw_azp is not None and raw_azp != config.client_id:
            raise IdTokenError("azp_mismatch")

        # nonce: constant-time compare
        raw_nonce = payload.get("nonce")
        if raw_nonce is None:
            raise IdTokenError("nonce_missing")
        if not hmac.compare_digest(str(raw_nonce), nonce):
            raise IdTokenError("nonce_mismatch")

        # exp required
        raw_exp = payload.get("exp")
        if raw_exp is None:
            raise IdTokenError("exp_missing")
        if now_ts > float(raw_exp) + self._leeway_s:
            raise IdTokenError("expired")

        # iat in the future beyond leeway
        raw_iat = payload.get("iat")
        if raw_iat is not None:
            if float(raw_iat) > now_ts + self._leeway_s:
                raise IdTokenError("iat_in_future")

        # auth_time: required and within max_age_s when max_age_s given
        if max_age_s is not None:
            raw_auth_time = payload.get("auth_time")
            if raw_auth_time is None:
                raise IdTokenError("auth_time_missing")
            age = now_ts - float(raw_auth_time)
            if age > max_age_s:
                raise IdTokenError("auth_too_old")


# ---------------------------------------------------------------------------
# URL safety (SSRF guard for discovery / JWKS fetches)
# ---------------------------------------------------------------------------

def _is_addr_unsafe(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Return ``True`` if *addr* must be blocked (private/loopback/etc.)."""
    # Check IPv4-mapped and 6to4 tunnels first.
    if isinstance(addr, ipaddress.IPv6Address):
        mapped = addr.ipv4_mapped
        if mapped is not None:
            return _is_addr_unsafe(mapped)
        sixtofour = addr.sixtofour
        if sixtofour is not None:
            return _is_addr_unsafe(sixtofour)
    return (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
    )


def check_fetch_url(
    url: str,
    *,
    resolve: Callable[[str], list[str]],
    allow_hosts: frozenset[str] = frozenset(),
) -> None:
    """Validate *url* for OIDC discovery or JWKS fetching.

    Raises ``UnsafeURLError`` with a short reason code on failure.
    """
    parsed = urlparse(url)

    # Scheme must be https (even for allow_hosts)
    if parsed.scheme != "https":
        raise UnsafeURLError("scheme_not_https")

    # Reject userinfo (user:pass@host)
    if parsed.username is not None:
        raise UnsafeURLError("address_not_allowed")

    hostname = parsed.hostname
    if not hostname:
        raise UnsafeURLError("address_not_allowed")

    # If host is allow-listed, skip address resolution
    if hostname in allow_hosts:
        return

    # Resolve and check every address
    try:
        addrs = resolve(hostname)
    except Exception:
        raise UnsafeURLError("resolve_failed")
    if not addrs:
        raise UnsafeURLError("resolve_failed")

    for addr_str in addrs:
        try:
            addr = ipaddress.ip_address(addr_str)
        except ValueError:
            raise UnsafeURLError("address_not_allowed")
        if _is_addr_unsafe(addr):
            raise UnsafeURLError("address_not_allowed")


# ---------------------------------------------------------------------------
# OIDC discovery
# ---------------------------------------------------------------------------

def fetch_discovery(
    config: OrgOIDCConfig,
    *,
    get_json: Callable[[str], dict],
    resolve: Callable[[str], list[str]],
    allow_hosts: frozenset[str] = frozenset(),
) -> dict:
    """Fetch ``<issuer>/.well-known/openid-configuration`` and validate it.

    - Runs ``check_fetch_url`` on both the discovery URL and the ``jwks_uri``.
    - Requires the document ``issuer`` to match the expected issuer exactly.
    """
    expected_iss = config.expected_issuer()
    discovery_url = expected_iss.rstrip("/") + "/.well-known/openid-configuration"

    # Check the discovery URL itself
    check_fetch_url(discovery_url, resolve=resolve, allow_hosts=allow_hosts)

    # Fetch
    doc = get_json(discovery_url)

    # Issuer must match exactly
    if doc.get("issuer") != expected_iss:
        raise OIDCError("discovery_issuer_mismatch")

    # Validate jwks_uri safety
    jwks_uri = doc.get("jwks_uri")
    if not isinstance(jwks_uri, str) or not jwks_uri:
        raise UnsafeURLError("jwks_uri_unsafe")
    else:
        try:
            check_fetch_url(jwks_uri, resolve=resolve, allow_hosts=allow_hosts)
        except UnsafeURLError:
            raise UnsafeURLError("jwks_uri_unsafe")

    return doc


# ---------------------------------------------------------------------------
# HttpJWKSProvider
# ---------------------------------------------------------------------------

class HttpJWKSProvider:
    """``JWKSProvider`` that fetches JWKS from a URL with safety checks.

    The caller's HTTP transport must not follow redirects; this class runs
    ``check_fetch_url`` before each fetch but cannot enforce the no-redirect
    constraint itself.  The resolve-then-connect gap (DNS rebinding) must
    also be closed at the transport layer, e.g. by connecting to the address
    that was checked.
    """

    def __init__(
        self,
        jwks_uri: str,
        *,
        get_json: Callable[[str], dict],
        resolve: Callable[[str], list[str]],
        allow_hosts: frozenset[str] = frozenset(),
    ) -> None:
        self._jwks_uri = jwks_uri
        self._get_json = get_json
        self._resolve = resolve
        self._allow_hosts = allow_hosts
        # Instance-level cache (not module-level).
        self._cached: dict | None = None

    def get_jwks(self, *, force_refresh: bool = False) -> dict:
        """Return the JWKS dict, re-fetching if *force_refresh*."""
        if force_refresh or self._cached is None:
            check_fetch_url(
                self._jwks_uri,
                resolve=self._resolve,
                allow_hosts=self._allow_hosts,
            )
            self._cached = self._get_json(self._jwks_uri)
        return self._cached
