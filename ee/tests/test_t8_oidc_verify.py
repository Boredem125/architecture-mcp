"""M1 T8 part 1: ID-token verification tests (SEC-13).

Interface the build will implement
===================================

::

    agg_cp.oidc
      ALLOWED_ALGS = frozenset({"RS256","PS256","ES256"})
      SENSITIVE_MAX_AGE_S = 900
      class OIDCError(Exception): .reason: str   # short non-secret code
      class IdTokenError(OIDCError)
      class UnsafeURLError(OIDCError)
      @dataclass(frozen=True) OrgOIDCConfig(issuer: str, client_id: str, tenant_id: str | None = None)
          # issuer may contain "{tenantid}" (Entra); then tenant_id is required
          # and expected_issuer() renders it
          .expected_issuer() -> str
              # raises OIDCError("issuer_template_without_tenant") if template and no tenant_id
      class JWKSProvider(Protocol): get_jwks(*, force_refresh: bool = False) -> dict
      @dataclass(frozen=True) VerifiedIdentity(iss: str, sub: str,
                                                auth_time: datetime | None,
                                                claims: Mapping)
          .link_key -> tuple[str, str]   # (iss, sub); never email
      class IdTokenVerifier(*, clock: Clock, jwks: JWKSProvider,
                            leeway_s: int = 60, min_refresh_interval_s: int = 60)
          .verify(id_token: str, *, config: OrgOIDCConfig, nonce: str,
                  max_age_s: int | None = None) -> VerifiedIdentity

Reason codes (exact strings)
==============================

iss_mismatch, tid_mismatch, aud_mismatch, azp_mismatch, azp_required,
alg_not_allowed, bad_signature, unknown_kid, nonce_mismatch, nonce_missing,
expired, exp_missing, iat_in_future, auth_time_missing, auth_too_old,
malformed, issuer_template_without_tenant
"""
from __future__ import annotations

import datetime as dt
import importlib
import json
import base64

import pytest

# ---------------------------------------------------------------------------
# Import helpers and xfail marker
# ---------------------------------------------------------------------------

from .fake_idp import (
    FakeClock,
    FakeIdP,
    FakeJWKSProvider,
    REMOVE,
    decode_token_unverified,
    tamper_payload,
    swap_header,
)


class T8Pending(Exception):
    """Raised when agg_cp.oidc is not yet built."""


def _import_oidc():
    """Import agg_cp.oidc, converting ImportError/AttributeError to T8Pending."""
    try:
        mod = importlib.import_module("agg_cp.oidc")
    except (ImportError, ModuleNotFoundError) as exc:
        raise T8Pending(f"agg_cp.oidc not importable: {exc}") from exc
    return mod


def _get_attr(mod, name):
    try:
        return getattr(mod, name)
    except AttributeError as exc:
        raise T8Pending(f"agg_cp.oidc.{name} not found: {exc}") from exc


def _build_verifier(clock, provider, **kwargs):
    """Build an IdTokenVerifier from the not-yet-built module."""
    mod = _import_oidc()
    cls = _get_attr(mod, "IdTokenVerifier")
    return cls(clock=clock, jwks=provider, **kwargs)


def _build_config(issuer, client_id, tenant_id=None):
    """Build an OrgOIDCConfig from the not-yet-built module."""
    mod = _import_oidc()
    cls = _get_attr(mod, "OrgOIDCConfig")
    return cls(issuer=issuer, client_id=client_id, tenant_id=tenant_id)


def _get_error_classes():
    """Return (OIDCError, IdTokenError) from the not-yet-built module."""
    mod = _import_oidc()
    return _get_attr(mod, "OIDCError"), _get_attr(mod, "IdTokenError")


# ---------------------------------------------------------------------------
# Shared test fixtures (module-level)
# ---------------------------------------------------------------------------

_ISSUER = "https://idp.example.com"
_CLIENT_ID = "my-client-id"
_NONCE = "test-nonce"
_NOW = dt.datetime(2025, 6, 1, 12, 0, 0, tzinfo=dt.timezone.utc)


# ---------------------------------------------------------------------------
# Self-tests (positive controls): these PASS now, no xfail
# ---------------------------------------------------------------------------

class TestFakeIdPSelfTests:
    """Guards: the fake mints what it claims."""

    def test_default_claims_present(self):
        idp = FakeIdP(_ISSUER, client_id=_CLIENT_ID)
        token = idp.mint(now=_NOW)
        _, pay = decode_token_unverified(token)
        assert pay["iss"] == _ISSUER
        assert pay["sub"] == "user-1"
        assert pay["aud"] == _CLIENT_ID
        assert "nonce" in pay
        assert "iat" in pay
        assert "exp" in pay
        assert "auth_time" in pay

    def test_override_claim(self):
        idp = FakeIdP(_ISSUER, client_id=_CLIENT_ID)
        token = idp.mint(now=_NOW, sub="user-42")
        _, pay = decode_token_unverified(token)
        assert pay["sub"] == "user-42"

    def test_remove_claim(self):
        idp = FakeIdP(_ISSUER, client_id=_CLIENT_ID)
        token = idp.mint(now=_NOW, auth_time=REMOVE)
        _, pay = decode_token_unverified(token)
        assert "auth_time" not in pay

    def test_rotate_drops_old_kid(self):
        idp = FakeIdP(_ISSUER)
        old_kid = idp.current_kid
        new_kid = idp.rotate()
        assert new_kid != old_kid
        jwks = idp.jwks()
        kids_in_jwks = {k["kid"] for k in jwks["keys"]}
        assert old_kid not in kids_in_jwks
        assert new_kid in kids_in_jwks

    def test_unsigned_token_has_alg_none(self):
        idp = FakeIdP(_ISSUER, client_id=_CLIENT_ID)
        token = idp.mint_unsigned(now=_NOW)
        hdr, _ = decode_token_unverified(token)
        assert hdr["alg"] == "none"

    def test_hs256_token_has_correct_alg(self):
        idp = FakeIdP(_ISSUER, client_id=_CLIENT_ID)
        token = idp.mint_hs256("secret", now=_NOW)
        hdr, _ = decode_token_unverified(token)
        assert hdr["alg"] == "HS256"

    def test_fake_clock_satisfies_protocol(self):
        from agg_cp.clock import Clock

        clock = FakeClock(_NOW)
        assert isinstance(clock, Clock)
        assert clock.now() == _NOW

    def test_fake_clock_advance(self):
        clock = FakeClock(_NOW)
        clock.advance(dt.timedelta(hours=1))
        assert clock.now() == _NOW + dt.timedelta(hours=1)

    def test_fake_clock_set(self):
        clock = FakeClock(_NOW)
        new_time = dt.datetime(2030, 1, 1, tzinfo=dt.timezone.utc)
        clock.set(new_time)
        assert clock.now() == new_time

    def test_provider_counts_fetches(self):
        idp = FakeIdP(_ISSUER)
        prov = FakeJWKSProvider(idp)
        assert prov.fetches == 0
        prov.get_jwks()
        assert prov.fetches == 1
        prov.get_jwks()  # cached
        assert prov.fetches == 1
        prov.get_jwks(force_refresh=True)
        assert prov.fetches == 2

    def test_tamper_payload_changes_claim(self):
        idp = FakeIdP(_ISSUER, client_id=_CLIENT_ID)
        token = idp.mint(now=_NOW)
        tampered = tamper_payload(token, sub="evil")
        _, pay = decode_token_unverified(tampered)
        assert pay["sub"] == "evil"


# ---------------------------------------------------------------------------
# T8 verify tests -- all RED_T8 (strict xfail)
# ---------------------------------------------------------------------------

class TestHappyPath:
    """Successful verification cases."""

    def test_valid_rs256_token(self):
        idp = FakeIdP(_ISSUER, client_id=_CLIENT_ID)
        clock = FakeClock(_NOW)
        prov = FakeJWKSProvider(idp)
        verifier = _build_verifier(clock, prov)
        config = _build_config(_ISSUER, _CLIENT_ID)
        token = idp.mint(now=_NOW)
        result = verifier.verify(token, config=config, nonce=_NONCE)
        assert result.iss == _ISSUER
        assert result.sub == "user-1"
        assert result.link_key == (_ISSUER, "user-1")

    @pytest.mark.parametrize("alg", ["RS256", "PS256", "ES256"])
    def test_allowed_algs_pass(self, alg):
        idp = FakeIdP(_ISSUER, alg=alg, client_id=_CLIENT_ID)
        clock = FakeClock(_NOW)
        prov = FakeJWKSProvider(idp)
        verifier = _build_verifier(clock, prov)
        config = _build_config(_ISSUER, _CLIENT_ID)
        token = idp.mint(now=_NOW)
        result = verifier.verify(token, config=config, nonce=_NONCE)
        assert result.sub == "user-1"

    def test_aud_as_list_with_azp(self):
        """aud is a list containing client_id, azp present and equals client_id."""
        idp = FakeIdP(_ISSUER, client_id=_CLIENT_ID)
        clock = FakeClock(_NOW)
        prov = FakeJWKSProvider(idp)
        verifier = _build_verifier(clock, prov)
        config = _build_config(_ISSUER, _CLIENT_ID)
        token = idp.mint(
            now=_NOW,
            aud=[_CLIENT_ID, "other-client"],
            azp=_CLIENT_ID,
        )
        result = verifier.verify(token, config=config, nonce=_NONCE)
        assert result.sub == "user-1"

    def test_exp_within_leeway_passes(self):
        """Token expired 30s ago but leeway is 60s: should pass."""
        idp = FakeIdP(_ISSUER, client_id=_CLIENT_ID)
        exp_time = int(_NOW.timestamp()) - 30  # 30s in the past
        clock = FakeClock(_NOW)
        prov = FakeJWKSProvider(idp)
        verifier = _build_verifier(clock, prov, leeway_s=60)
        config = _build_config(_ISSUER, _CLIENT_ID)
        token = idp.mint(
            now=_NOW,
            exp=exp_time,
            iat=int(_NOW.timestamp()) - 90,
        )
        result = verifier.verify(token, config=config, nonce=_NONCE)
        assert result.sub == "user-1"

    def test_auth_time_14min_with_sensitive_max_age(self):
        """auth_time 14 min ago, max_age_s=900 (15 min): passes."""
        mod = _import_oidc()
        SENSITIVE_MAX_AGE_S = _get_attr(mod, "SENSITIVE_MAX_AGE_S")
        assert SENSITIVE_MAX_AGE_S == 900

        idp = FakeIdP(_ISSUER, client_id=_CLIENT_ID)
        clock = FakeClock(_NOW)
        prov = FakeJWKSProvider(idp)
        verifier = _build_verifier(clock, prov)
        config = _build_config(_ISSUER, _CLIENT_ID)
        auth_time = int(_NOW.timestamp()) - 14 * 60  # 14 min ago
        token = idp.mint(now=_NOW, auth_time=auth_time)
        result = verifier.verify(
            token, config=config, nonce=_NONCE, max_age_s=SENSITIVE_MAX_AGE_S,
        )
        assert result.sub == "user-1"

    def test_missing_auth_time_without_max_age_passes(self):
        """Without max_age_s, a missing auth_time is allowed."""
        idp = FakeIdP(_ISSUER, client_id=_CLIENT_ID)
        clock = FakeClock(_NOW)
        prov = FakeJWKSProvider(idp)
        verifier = _build_verifier(clock, prov)
        config = _build_config(_ISSUER, _CLIENT_ID)
        token = idp.mint(now=_NOW, auth_time=REMOVE)
        result = verifier.verify(token, config=config, nonce=_NONCE)
        assert result.sub == "user-1"


class TestIssuerChecks:
    """iss claim validation."""

    def test_iss_trailing_slash_mismatch(self):
        idp = FakeIdP(_ISSUER, client_id=_CLIENT_ID)
        clock = FakeClock(_NOW)
        prov = FakeJWKSProvider(idp)
        verifier = _build_verifier(clock, prov)
        config = _build_config(_ISSUER + "/", _CLIENT_ID)  # trailing slash
        token = idp.mint(now=_NOW)
        _, IdTokenError = _get_error_classes()
        with pytest.raises(IdTokenError) as exc_info:
            verifier.verify(token, config=config, nonce=_NONCE)
        assert exc_info.value.reason == "iss_mismatch"

    def test_iss_case_mismatch(self):
        idp = FakeIdP(_ISSUER, client_id=_CLIENT_ID)
        clock = FakeClock(_NOW)
        prov = FakeJWKSProvider(idp)
        verifier = _build_verifier(clock, prov)
        config = _build_config(_ISSUER.upper(), _CLIENT_ID)
        token = idp.mint(now=_NOW)
        _, IdTokenError = _get_error_classes()
        with pytest.raises(IdTokenError) as exc_info:
            verifier.verify(token, config=config, nonce=_NONCE)
        assert exc_info.value.reason == "iss_mismatch"

    def test_iss_different_org(self):
        idp = FakeIdP(_ISSUER, client_id=_CLIENT_ID)
        clock = FakeClock(_NOW)
        prov = FakeJWKSProvider(idp)
        verifier = _build_verifier(clock, prov)
        config = _build_config("https://other-idp.example.com", _CLIENT_ID)
        token = idp.mint(now=_NOW)
        _, IdTokenError = _get_error_classes()
        with pytest.raises(IdTokenError) as exc_info:
            verifier.verify(token, config=config, nonce=_NONCE)
        assert exc_info.value.reason == "iss_mismatch"


class TestEntraIssuer:
    """Entra ID tenant-templated issuer."""

    _ENTRA_TEMPLATE = "https://login.microsoftonline.com/{tenantid}/v2.0"
    _TENANT_ID = "aaaabbbb-cccc-dddd-eeee-ffffffffffff"

    def test_entra_happy_path(self):
        expected_iss = self._ENTRA_TEMPLATE.replace("{tenantid}", self._TENANT_ID)
        idp = FakeIdP(expected_iss, client_id=_CLIENT_ID)
        clock = FakeClock(_NOW)
        prov = FakeJWKSProvider(idp)
        verifier = _build_verifier(clock, prov)
        config = _build_config(
            self._ENTRA_TEMPLATE, _CLIENT_ID, tenant_id=self._TENANT_ID,
        )
        token = idp.mint(now=_NOW, tid=self._TENANT_ID)
        result = verifier.verify(token, config=config, nonce=_NONCE)
        assert result.iss == expected_iss

    def test_entra_iss_wrong_tenant(self):
        """iss rendered with another tenant -> iss_mismatch."""
        other_tenant = "11112222-3333-4444-5555-666677778888"
        wrong_iss = self._ENTRA_TEMPLATE.replace("{tenantid}", other_tenant)
        correct_iss = self._ENTRA_TEMPLATE.replace("{tenantid}", self._TENANT_ID)
        idp = FakeIdP(wrong_iss, client_id=_CLIENT_ID)
        clock = FakeClock(_NOW)
        prov = FakeJWKSProvider(idp)
        verifier = _build_verifier(clock, prov)
        config = _build_config(
            self._ENTRA_TEMPLATE, _CLIENT_ID, tenant_id=self._TENANT_ID,
        )
        token = idp.mint(now=_NOW, tid=other_tenant)
        _, IdTokenError = _get_error_classes()
        with pytest.raises(IdTokenError) as exc_info:
            verifier.verify(token, config=config, nonce=_NONCE)
        assert exc_info.value.reason == "iss_mismatch"

    def test_entra_tid_claim_differs(self):
        """iss correct but tid claim different -> tid_mismatch."""
        expected_iss = self._ENTRA_TEMPLATE.replace("{tenantid}", self._TENANT_ID)
        idp = FakeIdP(expected_iss, client_id=_CLIENT_ID)
        clock = FakeClock(_NOW)
        prov = FakeJWKSProvider(idp)
        verifier = _build_verifier(clock, prov)
        config = _build_config(
            self._ENTRA_TEMPLATE, _CLIENT_ID, tenant_id=self._TENANT_ID,
        )
        other_tenant = "11112222-3333-4444-5555-666677778888"
        token = idp.mint(now=_NOW, tid=other_tenant)
        _, IdTokenError = _get_error_classes()
        with pytest.raises(IdTokenError) as exc_info:
            verifier.verify(token, config=config, nonce=_NONCE)
        assert exc_info.value.reason == "tid_mismatch"

    def test_entra_tid_claim_missing(self):
        """iss correct but tid claim absent -> tid_mismatch."""
        expected_iss = self._ENTRA_TEMPLATE.replace("{tenantid}", self._TENANT_ID)
        idp = FakeIdP(expected_iss, client_id=_CLIENT_ID)
        clock = FakeClock(_NOW)
        prov = FakeJWKSProvider(idp)
        verifier = _build_verifier(clock, prov)
        config = _build_config(
            self._ENTRA_TEMPLATE, _CLIENT_ID, tenant_id=self._TENANT_ID,
        )
        token = idp.mint(now=_NOW)  # no tid claim
        _, IdTokenError = _get_error_classes()
        with pytest.raises(IdTokenError) as exc_info:
            verifier.verify(token, config=config, nonce=_NONCE)
        assert exc_info.value.reason == "tid_mismatch"

    def test_entra_template_without_tenant_id(self):
        """Issuer template without tenant_id in config -> OIDCError."""
        OIDCError, _ = _get_error_classes()
        config = _build_config(self._ENTRA_TEMPLATE, _CLIENT_ID)  # no tenant_id
        with pytest.raises(OIDCError) as exc_info:
            config.expected_issuer()
        assert exc_info.value.reason == "issuer_template_without_tenant"


class TestAudienceChecks:
    """aud claim validation."""

    def test_aud_mismatch_string(self):
        idp = FakeIdP(_ISSUER, client_id=_CLIENT_ID)
        clock = FakeClock(_NOW)
        prov = FakeJWKSProvider(idp)
        verifier = _build_verifier(clock, prov)
        config = _build_config(_ISSUER, _CLIENT_ID)
        token = idp.mint(now=_NOW, aud="wrong-client")
        _, IdTokenError = _get_error_classes()
        with pytest.raises(IdTokenError) as exc_info:
            verifier.verify(token, config=config, nonce=_NONCE)
        assert exc_info.value.reason == "aud_mismatch"

    def test_aud_list_missing_client_id(self):
        idp = FakeIdP(_ISSUER, client_id=_CLIENT_ID)
        clock = FakeClock(_NOW)
        prov = FakeJWKSProvider(idp)
        verifier = _build_verifier(clock, prov)
        config = _build_config(_ISSUER, _CLIENT_ID)
        token = idp.mint(now=_NOW, aud=["other-a", "other-b"], azp=_CLIENT_ID)
        _, IdTokenError = _get_error_classes()
        with pytest.raises(IdTokenError) as exc_info:
            verifier.verify(token, config=config, nonce=_NONCE)
        assert exc_info.value.reason == "aud_mismatch"


class TestAzpChecks:
    """azp claim validation."""

    def test_azp_present_not_client_id(self):
        idp = FakeIdP(_ISSUER, client_id=_CLIENT_ID)
        clock = FakeClock(_NOW)
        prov = FakeJWKSProvider(idp)
        verifier = _build_verifier(clock, prov)
        config = _build_config(_ISSUER, _CLIENT_ID)
        token = idp.mint(now=_NOW, azp="wrong-party")
        _, IdTokenError = _get_error_classes()
        with pytest.raises(IdTokenError) as exc_info:
            verifier.verify(token, config=config, nonce=_NONCE)
        assert exc_info.value.reason == "azp_mismatch"

    def test_multi_aud_without_azp(self):
        idp = FakeIdP(_ISSUER, client_id=_CLIENT_ID)
        clock = FakeClock(_NOW)
        prov = FakeJWKSProvider(idp)
        verifier = _build_verifier(clock, prov)
        config = _build_config(_ISSUER, _CLIENT_ID)
        token = idp.mint(now=_NOW, aud=[_CLIENT_ID, "other-client"])
        _, IdTokenError = _get_error_classes()
        with pytest.raises(IdTokenError) as exc_info:
            verifier.verify(token, config=config, nonce=_NONCE)
        assert exc_info.value.reason == "azp_required"


class TestAlgChecks:
    """alg validation and signature verification."""

    def test_alg_none_rejected(self):
        idp = FakeIdP(_ISSUER, client_id=_CLIENT_ID)
        clock = FakeClock(_NOW)
        prov = FakeJWKSProvider(idp)
        verifier = _build_verifier(clock, prov)
        config = _build_config(_ISSUER, _CLIENT_ID)
        token = idp.mint_unsigned(now=_NOW)
        _, IdTokenError = _get_error_classes()
        with pytest.raises(IdTokenError) as exc_info:
            verifier.verify(token, config=config, nonce=_NONCE)
        assert exc_info.value.reason == "alg_not_allowed"

    def test_hs256_arbitrary_secret_rejected(self):
        idp = FakeIdP(_ISSUER, client_id=_CLIENT_ID)
        clock = FakeClock(_NOW)
        prov = FakeJWKSProvider(idp)
        verifier = _build_verifier(clock, prov)
        config = _build_config(_ISSUER, _CLIENT_ID)
        token = idp.mint_hs256("arbitrary-secret", now=_NOW)
        _, IdTokenError = _get_error_classes()
        with pytest.raises(IdTokenError) as exc_info:
            verifier.verify(token, config=config, nonce=_NONCE)
        assert exc_info.value.reason == "alg_not_allowed"

    def test_hs256_alg_confusion_rsa_pubkey(self):
        """HS256 signed with the RSA public key PEM as secret (alg confusion)."""
        idp = FakeIdP(_ISSUER, client_id=_CLIENT_ID)
        clock = FakeClock(_NOW)
        prov = FakeJWKSProvider(idp)
        verifier = _build_verifier(clock, prov)
        config = _build_config(_ISSUER, _CLIENT_ID)
        pub_pem = idp.get_rsa_public_pem()
        token = idp.mint_hs256(pub_pem, now=_NOW)
        _, IdTokenError = _get_error_classes()
        with pytest.raises(IdTokenError) as exc_info:
            verifier.verify(token, config=config, nonce=_NONCE)
        assert exc_info.value.reason == "alg_not_allowed"

    def test_rs384_rejected(self):
        """RS384 is not in ALLOWED_ALGS."""
        idp = FakeIdP(_ISSUER, client_id=_CLIENT_ID)
        clock = FakeClock(_NOW)
        prov = FakeJWKSProvider(idp)
        verifier = _build_verifier(clock, prov)
        config = _build_config(_ISSUER, _CLIENT_ID)
        # Manually construct a token with RS384 in the header
        token = idp.mint(now=_NOW)
        token = swap_header(token, alg="RS384")
        _, IdTokenError = _get_error_classes()
        with pytest.raises(IdTokenError) as exc_info:
            verifier.verify(token, config=config, nonce=_NONCE)
        assert exc_info.value.reason == "alg_not_allowed"

    def test_header_rs256_but_ec_key_in_jwks(self):
        """Header says RS256 but the kid's key in JWKS is EC -> bad_signature or alg_not_allowed."""
        idp = FakeIdP(_ISSUER, alg="ES256", client_id=_CLIENT_ID)
        clock = FakeClock(_NOW)
        prov = FakeJWKSProvider(idp)
        verifier = _build_verifier(clock, prov)
        config = _build_config(_ISSUER, _CLIENT_ID)
        # Sign with ES256, then swap header to RS256 (keeping the EC kid)
        token = idp.mint(now=_NOW)
        token = swap_header(token, alg="RS256")
        _, IdTokenError = _get_error_classes()
        with pytest.raises(IdTokenError) as exc_info:
            verifier.verify(token, config=config, nonce=_NONCE)
        assert exc_info.value.reason in ("bad_signature", "alg_not_allowed")

    def test_tampered_payload_bad_signature(self):
        idp = FakeIdP(_ISSUER, client_id=_CLIENT_ID)
        clock = FakeClock(_NOW)
        prov = FakeJWKSProvider(idp)
        verifier = _build_verifier(clock, prov)
        config = _build_config(_ISSUER, _CLIENT_ID)
        token = idp.mint(now=_NOW)
        token = tamper_payload(token, sub="evil")
        _, IdTokenError = _get_error_classes()
        with pytest.raises(IdTokenError) as exc_info:
            verifier.verify(token, config=config, nonce=_NONCE)
        assert exc_info.value.reason == "bad_signature"


class TestNonceChecks:
    """nonce claim validation."""

    def test_nonce_mismatch(self):
        idp = FakeIdP(_ISSUER, client_id=_CLIENT_ID)
        clock = FakeClock(_NOW)
        prov = FakeJWKSProvider(idp)
        verifier = _build_verifier(clock, prov)
        config = _build_config(_ISSUER, _CLIENT_ID)
        token = idp.mint(now=_NOW, nonce="wrong-nonce")
        _, IdTokenError = _get_error_classes()
        with pytest.raises(IdTokenError) as exc_info:
            verifier.verify(token, config=config, nonce=_NONCE)
        assert exc_info.value.reason == "nonce_mismatch"

    def test_nonce_missing(self):
        idp = FakeIdP(_ISSUER, client_id=_CLIENT_ID)
        clock = FakeClock(_NOW)
        prov = FakeJWKSProvider(idp)
        verifier = _build_verifier(clock, prov)
        config = _build_config(_ISSUER, _CLIENT_ID)
        token = idp.mint(now=_NOW, nonce=REMOVE)
        _, IdTokenError = _get_error_classes()
        with pytest.raises(IdTokenError) as exc_info:
            verifier.verify(token, config=config, nonce=_NONCE)
        assert exc_info.value.reason == "nonce_missing"


class TestExpiryChecks:
    """exp / iat time validation."""

    def test_expired_beyond_leeway(self):
        """Token expired 120s ago, leeway is 60s -> expired."""
        idp = FakeIdP(_ISSUER, client_id=_CLIENT_ID)
        exp_time = int(_NOW.timestamp()) - 120
        clock = FakeClock(_NOW)
        prov = FakeJWKSProvider(idp)
        verifier = _build_verifier(clock, prov, leeway_s=60)
        config = _build_config(_ISSUER, _CLIENT_ID)
        token = idp.mint(now=_NOW, exp=exp_time, iat=int(_NOW.timestamp()) - 180)
        _, IdTokenError = _get_error_classes()
        with pytest.raises(IdTokenError) as exc_info:
            verifier.verify(token, config=config, nonce=_NONCE)
        assert exc_info.value.reason == "expired"

    def test_exp_missing(self):
        idp = FakeIdP(_ISSUER, client_id=_CLIENT_ID)
        clock = FakeClock(_NOW)
        prov = FakeJWKSProvider(idp)
        verifier = _build_verifier(clock, prov)
        config = _build_config(_ISSUER, _CLIENT_ID)
        token = idp.mint(now=_NOW, exp=REMOVE)
        _, IdTokenError = _get_error_classes()
        with pytest.raises(IdTokenError) as exc_info:
            verifier.verify(token, config=config, nonce=_NONCE)
        assert exc_info.value.reason == "exp_missing"

    def test_iat_in_future(self):
        """iat is beyond leeway in the future -> iat_in_future."""
        idp = FakeIdP(_ISSUER, client_id=_CLIENT_ID)
        clock = FakeClock(_NOW)
        prov = FakeJWKSProvider(idp)
        verifier = _build_verifier(clock, prov, leeway_s=60)
        config = _build_config(_ISSUER, _CLIENT_ID)
        future_iat = int(_NOW.timestamp()) + 120  # 2 min in the future
        token = idp.mint(now=_NOW, iat=future_iat)
        _, IdTokenError = _get_error_classes()
        with pytest.raises(IdTokenError) as exc_info:
            verifier.verify(token, config=config, nonce=_NONCE)
        assert exc_info.value.reason == "iat_in_future"


class TestAuthTimeChecks:
    """auth_time validation with max_age_s."""

    def test_auth_too_old(self):
        """auth_time 16 min ago, max_age_s=900 (15 min) -> auth_too_old."""
        mod = _import_oidc()
        SENSITIVE_MAX_AGE_S = _get_attr(mod, "SENSITIVE_MAX_AGE_S")

        idp = FakeIdP(_ISSUER, client_id=_CLIENT_ID)
        clock = FakeClock(_NOW)
        prov = FakeJWKSProvider(idp)
        verifier = _build_verifier(clock, prov)
        config = _build_config(_ISSUER, _CLIENT_ID)
        auth_time = int(_NOW.timestamp()) - 16 * 60  # 16 min ago
        token = idp.mint(now=_NOW, auth_time=auth_time)
        _, IdTokenError = _get_error_classes()
        with pytest.raises(IdTokenError) as exc_info:
            verifier.verify(
                token, config=config, nonce=_NONCE, max_age_s=SENSITIVE_MAX_AGE_S,
            )
        assert exc_info.value.reason == "auth_too_old"

    def test_auth_time_missing_with_max_age(self):
        """max_age_s set but auth_time missing -> auth_time_missing."""
        idp = FakeIdP(_ISSUER, client_id=_CLIENT_ID)
        clock = FakeClock(_NOW)
        prov = FakeJWKSProvider(idp)
        verifier = _build_verifier(clock, prov)
        config = _build_config(_ISSUER, _CLIENT_ID)
        token = idp.mint(now=_NOW, auth_time=REMOVE)
        _, IdTokenError = _get_error_classes()
        with pytest.raises(IdTokenError) as exc_info:
            verifier.verify(
                token, config=config, nonce=_NONCE, max_age_s=900,
            )
        assert exc_info.value.reason == "auth_time_missing"


class TestJWKSRotation:
    """JWKS key rotation and refresh behaviour."""

    def test_rotation_forces_one_refresh(self):
        """After rotate(), a token with new kid verifies and causes exactly 1 forced refresh."""
        idp = FakeIdP(_ISSUER, client_id=_CLIENT_ID)
        clock = FakeClock(_NOW)
        prov = FakeJWKSProvider(idp)
        verifier = _build_verifier(clock, prov)
        config = _build_config(_ISSUER, _CLIENT_ID)

        # Prime the cache
        token1 = idp.mint(now=_NOW)
        verifier.verify(token1, config=config, nonce=_NONCE)
        fetches_before = prov.fetches

        # Rotate
        idp.rotate()
        token2 = idp.mint(now=_NOW, nonce=_NONCE)
        result = verifier.verify(token2, config=config, nonce=_NONCE)
        assert result.sub == "user-1"
        assert prov.fetches == fetches_before + 1

    def test_unknown_kid_after_refresh(self):
        """A token with a completely unknown kid, even after refresh -> unknown_kid."""
        idp = FakeIdP(_ISSUER, client_id=_CLIENT_ID)
        clock = FakeClock(_NOW)
        prov = FakeJWKSProvider(idp)
        verifier = _build_verifier(clock, prov)
        config = _build_config(_ISSUER, _CLIENT_ID)

        # Token with a bogus kid
        token = idp.mint(now=_NOW, _kid="nonexistent-kid")
        _, IdTokenError = _get_error_classes()
        with pytest.raises(IdTokenError) as exc_info:
            verifier.verify(token, config=config, nonce=_NONCE)
        assert exc_info.value.reason == "unknown_kid"

    def test_rate_limited_refresh(self):
        """Two unknown-kid tokens within min_refresh_interval_s cause at most one forced refresh."""
        idp = FakeIdP(_ISSUER, client_id=_CLIENT_ID)
        clock = FakeClock(_NOW)
        prov = FakeJWKSProvider(idp)
        verifier = _build_verifier(clock, prov, min_refresh_interval_s=60)
        config = _build_config(_ISSUER, _CLIENT_ID)

        # Prime
        token1 = idp.mint(now=_NOW)
        verifier.verify(token1, config=config, nonce=_NONCE)

        # First unknown kid
        token_bad1 = idp.mint(now=_NOW, _kid="bogus-1")
        _, IdTokenError = _get_error_classes()
        fetches_before = prov.fetches
        with pytest.raises(IdTokenError):
            verifier.verify(token_bad1, config=config, nonce=_NONCE)

        fetches_after_first = prov.fetches
        # Should have refreshed once
        assert fetches_after_first == fetches_before + 1

        # Second unknown kid immediately (no clock advance)
        token_bad2 = idp.mint(now=_NOW, _kid="bogus-2")
        with pytest.raises(IdTokenError):
            verifier.verify(token_bad2, config=config, nonce=_NONCE)

        fetches_after_second = prov.fetches
        # Should NOT have refreshed again (rate limited)
        assert fetches_after_second == fetches_after_first

    def test_rate_limit_resets_after_interval(self):
        """After advancing the clock past min_refresh_interval_s, a refresh is allowed again."""
        idp = FakeIdP(_ISSUER, client_id=_CLIENT_ID)
        clock = FakeClock(_NOW)
        prov = FakeJWKSProvider(idp)
        verifier = _build_verifier(clock, prov, min_refresh_interval_s=60)
        config = _build_config(_ISSUER, _CLIENT_ID)

        # Prime
        token1 = idp.mint(now=_NOW)
        verifier.verify(token1, config=config, nonce=_NONCE)

        # First unknown kid -> triggers refresh
        token_bad = idp.mint(now=_NOW, _kid="bogus-1")
        _, IdTokenError = _get_error_classes()
        with pytest.raises(IdTokenError):
            verifier.verify(token_bad, config=config, nonce=_NONCE)
        fetches_after_first = prov.fetches

        # Advance past interval
        clock.advance(dt.timedelta(seconds=61))

        # Another unknown kid -> should refresh again
        token_bad2 = idp.mint(now=_NOW, _kid="bogus-3")
        with pytest.raises(IdTokenError):
            verifier.verify(token_bad2, config=config, nonce=_NONCE)
        assert prov.fetches == fetches_after_first + 1

    def test_retired_key_rejected(self):
        """A token signed by the retired (pre-rotation) key -> unknown_kid."""
        idp = FakeIdP(_ISSUER, client_id=_CLIENT_ID)
        clock = FakeClock(_NOW)
        prov = FakeJWKSProvider(idp)
        verifier = _build_verifier(clock, prov)
        config = _build_config(_ISSUER, _CLIENT_ID)

        # Sign with current key
        old_kid = idp.current_kid
        old_jwk = idp.current_jwk
        token_old = idp.mint(now=_NOW)

        # Rotate
        idp.rotate()

        # Try to verify token signed with the old key (old kid no longer in JWKS)
        _, IdTokenError = _get_error_classes()
        with pytest.raises(IdTokenError) as exc_info:
            verifier.verify(token_old, config=config, nonce=_NONCE)
        assert exc_info.value.reason == "unknown_kid"


class TestLinkKey:
    """VerifiedIdentity.link_key: (iss, sub), never email."""

    def test_different_sub_same_email_different_link_key(self):
        """Two tokens with same email but different sub have different link_key."""
        idp = FakeIdP(_ISSUER, client_id=_CLIENT_ID)
        clock = FakeClock(_NOW)
        prov = FakeJWKSProvider(idp)
        verifier = _build_verifier(clock, prov)
        config = _build_config(_ISSUER, _CLIENT_ID)

        token1 = idp.mint(now=_NOW, sub="user-a", email="shared@example.com")
        token2 = idp.mint(now=_NOW, sub="user-b", email="shared@example.com", nonce=_NONCE)

        result1 = verifier.verify(token1, config=config, nonce=_NONCE)
        result2 = verifier.verify(token2, config=config, nonce=_NONCE)

        assert result1.link_key != result2.link_key

    def test_same_sub_different_email_same_link_key(self):
        """Two tokens with same iss+sub but different email have same link_key."""
        idp = FakeIdP(_ISSUER, client_id=_CLIENT_ID)
        clock = FakeClock(_NOW)
        prov = FakeJWKSProvider(idp)
        verifier = _build_verifier(clock, prov)
        config = _build_config(_ISSUER, _CLIENT_ID)

        token1 = idp.mint(now=_NOW, sub="user-1", email="alice@example.com")
        token2 = idp.mint(now=_NOW, sub="user-1", email="bob@example.com", nonce=_NONCE)

        result1 = verifier.verify(token1, config=config, nonce=_NONCE)
        result2 = verifier.verify(token2, config=config, nonce=_NONCE)

        assert result1.link_key == result2.link_key

    def test_link_key_contains_no_email(self):
        """link_key tuple should not contain any email value."""
        idp = FakeIdP(_ISSUER, client_id=_CLIENT_ID)
        clock = FakeClock(_NOW)
        prov = FakeJWKSProvider(idp)
        verifier = _build_verifier(clock, prov)
        config = _build_config(_ISSUER, _CLIENT_ID)

        email = "alice@example.com"
        token = idp.mint(now=_NOW, email=email)
        result = verifier.verify(token, config=config, nonce=_NONCE)
        assert email not in result.link_key
        assert result.link_key == (_ISSUER, "user-1")


class TestMalformed:
    """Malformed token handling."""

    def test_not_three_parts(self):
        _, IdTokenError = _get_error_classes()
        idp = FakeIdP(_ISSUER, client_id=_CLIENT_ID)
        clock = FakeClock(_NOW)
        prov = FakeJWKSProvider(idp)
        verifier = _build_verifier(clock, prov)
        config = _build_config(_ISSUER, _CLIENT_ID)
        with pytest.raises(IdTokenError) as exc_info:
            verifier.verify("only.two", config=config, nonce=_NONCE)
        assert exc_info.value.reason == "malformed"

    def test_bad_base64(self):
        _, IdTokenError = _get_error_classes()
        idp = FakeIdP(_ISSUER, client_id=_CLIENT_ID)
        clock = FakeClock(_NOW)
        prov = FakeJWKSProvider(idp)
        verifier = _build_verifier(clock, prov)
        config = _build_config(_ISSUER, _CLIENT_ID)
        with pytest.raises(IdTokenError) as exc_info:
            verifier.verify("!!!.@@@.###", config=config, nonce=_NONCE)
        assert exc_info.value.reason == "malformed"


class TestInjectedClock:
    """Prove the verifier uses the injected clock, not the system clock."""

    def test_fake_clock_one_year_ahead_causes_expired(self):
        """With FakeClock set 1 year ahead, a fresh-looking token is 'expired'
        (proves the injected clock is used, no monkeypatching needed)."""
        idp = FakeIdP(_ISSUER, client_id=_CLIENT_ID)
        future = _NOW + dt.timedelta(days=365)
        clock = FakeClock(future)
        prov = FakeJWKSProvider(idp)
        verifier = _build_verifier(clock, prov)
        config = _build_config(_ISSUER, _CLIENT_ID)
        # Token minted at _NOW with exp = _NOW + 3600s
        token = idp.mint(now=_NOW)
        _, IdTokenError = _get_error_classes()
        with pytest.raises(IdTokenError) as exc_info:
            verifier.verify(token, config=config, nonce=_NONCE)
        assert exc_info.value.reason == "expired"


class TestAllowedAlgsConstant:
    """Verify the ALLOWED_ALGS constant."""

    def test_allowed_algs_value(self):
        mod = _import_oidc()
        algs = _get_attr(mod, "ALLOWED_ALGS")
        assert algs == frozenset({"RS256", "PS256", "ES256"})

    def test_sensitive_max_age_s_value(self):
        mod = _import_oidc()
        val = _get_attr(mod, "SENSITIVE_MAX_AGE_S")
        assert val == 900
