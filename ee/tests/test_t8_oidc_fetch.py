"""M1 T8 part 1: URL safety and discovery fetch tests (SEC-13).

Interface under test::

    agg_cp.oidc.check_fetch_url(
        url: str,
        *,
        resolve: Callable[[str], list[str]],
        allow_hosts: frozenset[str] = frozenset(),
    ) -> None

    agg_cp.oidc.fetch_discovery(
        config: OrgOIDCConfig,
        *,
        get_json: Callable[[str], dict],
        resolve: Callable[[str], list[str]],
        allow_hosts: frozenset[str] = frozenset(),
    ) -> dict

Reason codes: scheme_not_https, address_not_allowed, resolve_failed,
              discovery_issuer_mismatch, jwks_uri_unsafe
"""
from __future__ import annotations

import importlib
from typing import Any

import pytest


# ---------------------------------------------------------------------------
# T8Pending exception and RED_T8 marker
# ---------------------------------------------------------------------------

class T8Pending(Exception):
    """Raised when agg_cp.oidc is not yet built."""


def _import_oidc():
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


def _check_fetch_url(url, *, resolve, allow_hosts=frozenset()):
    mod = _import_oidc()
    fn = _get_attr(mod, "check_fetch_url")
    return fn(url, resolve=resolve, allow_hosts=allow_hosts)


def _fetch_discovery(config, *, get_json, resolve, allow_hosts=frozenset()):
    mod = _import_oidc()
    fn = _get_attr(mod, "fetch_discovery")
    return fn(config, get_json=get_json, resolve=resolve, allow_hosts=allow_hosts)


def _build_config(issuer, client_id, tenant_id=None):
    mod = _import_oidc()
    cls = _get_attr(mod, "OrgOIDCConfig")
    return cls(issuer=issuer, client_id=client_id, tenant_id=tenant_id)


def _get_error_classes():
    mod = _import_oidc()
    return _get_attr(mod, "UnsafeURLError"), _get_attr(mod, "OIDCError")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _resolver(*addrs):
    """Return a resolve callable that always returns the given addresses."""
    def resolve(host):
        return list(addrs)
    return resolve


def _failing_resolver(exc=None):
    """Return a resolve callable that always raises."""
    def resolve(host):
        if exc:
            raise exc
        raise OSError("DNS failed")
    return resolve


_PUBLIC_IP = "93.184.216.34"  # example.com


# ---------------------------------------------------------------------------
# check_fetch_url tests
# ---------------------------------------------------------------------------

class TestSchemeCheck:
    """Only HTTPS is allowed."""

    def test_http_rejected(self):
        UnsafeURLError, _ = _get_error_classes()
        with pytest.raises(UnsafeURLError) as exc_info:
            _check_fetch_url(
                "http://example.com/.well-known/openid-configuration",
                resolve=_resolver(_PUBLIC_IP),
            )
        assert exc_info.value.reason == "scheme_not_https"

    def test_https_public_passes(self):
        """Public address over HTTPS should pass."""
        _check_fetch_url(
            "https://example.com/.well-known/openid-configuration",
            resolve=_resolver(_PUBLIC_IP),
        )


class TestPrivateAddressBlocking:
    """Private, loopback, and link-local addresses are blocked."""

    @pytest.mark.parametrize(
        "addr,label",
        [
            ("127.0.0.1", "loopback-v4"),
            ("::1", "loopback-v6"),
            ("10.0.0.1", "private-10.x"),
            ("172.16.0.1", "private-172.16.x"),
            ("192.168.1.1", "private-192.168.x"),
            ("169.254.169.254", "link-local-metadata"),
            ("fe80::1", "link-local-v6"),
            ("::ffff:127.0.0.1", "mapped-loopback"),
            ("0.0.0.0", "unspecified-v4"),
            ("fc00::1", "unique-local-v6"),
        ],
        ids=[
            "loopback-v4",
            "loopback-v6",
            "private-10.x",
            "private-172.16.x",
            "private-192.168.x",
            "link-local-metadata",
            "link-local-v6",
            "mapped-loopback",
            "unspecified-v4",
            "unique-local-v6",
        ],
    )
    def test_private_address_blocked(self, addr, label):
        UnsafeURLError, _ = _get_error_classes()
        with pytest.raises(UnsafeURLError) as exc_info:
            _check_fetch_url(
                "https://evil.example.com/.well-known/openid-configuration",
                resolve=_resolver(addr),
            )
        assert exc_info.value.reason == "address_not_allowed"

    def test_any_one_private_in_multiple_results_refused(self):
        """If any resolved address is private, the URL is refused."""
        UnsafeURLError, _ = _get_error_classes()
        with pytest.raises(UnsafeURLError) as exc_info:
            _check_fetch_url(
                "https://example.com/oidc",
                resolve=_resolver(_PUBLIC_IP, "10.0.0.1"),
            )
        assert exc_info.value.reason == "address_not_allowed"


class TestAllowHosts:
    """The allow_hosts parameter."""

    def test_allowed_host_private_address_passes(self):
        """A host in allow_hosts with a private address passes."""
        _check_fetch_url(
            "https://keycloak.local/.well-known/openid-configuration",
            resolve=_resolver("192.168.1.100"),
            allow_hosts=frozenset({"keycloak.local"}),
        )

    def test_allowed_host_http_still_rejected(self):
        """Even an allowed host rejects http://."""
        UnsafeURLError, _ = _get_error_classes()
        with pytest.raises(UnsafeURLError) as exc_info:
            _check_fetch_url(
                "http://keycloak.local/.well-known/openid-configuration",
                resolve=_resolver("192.168.1.100"),
                allow_hosts=frozenset({"keycloak.local"}),
            )
        assert exc_info.value.reason == "scheme_not_https"


class TestResolverFailure:
    """DNS resolution failure."""

    def test_resolver_raises_resolve_failed(self):
        UnsafeURLError, _ = _get_error_classes()
        with pytest.raises(UnsafeURLError) as exc_info:
            _check_fetch_url(
                "https://example.com/.well-known/openid-configuration",
                resolve=_failing_resolver(),
            )
        assert exc_info.value.reason == "resolve_failed"


class TestGetJsonNotCalledForRefusedURL:
    """get_json must never be called for a refused URL."""

    def test_get_json_not_called_on_http(self):
        calls = []

        def fake_get_json(url):
            calls.append(url)
            return {}

        UnsafeURLError, _ = _get_error_classes()
        issuer = "http://evil.example.com"
        config = _build_config(issuer, "client-id")
        with pytest.raises(UnsafeURLError):
            _fetch_discovery(
                config,
                get_json=fake_get_json,
                resolve=_resolver(_PUBLIC_IP),
            )
        assert calls == [], f"get_json was called for a refused URL: {calls}"

    def test_get_json_not_called_on_private(self):
        calls = []

        def fake_get_json(url):
            calls.append(url)
            return {}

        UnsafeURLError, _ = _get_error_classes()
        issuer = "https://evil.internal"
        config = _build_config(issuer, "client-id")
        with pytest.raises(UnsafeURLError):
            _fetch_discovery(
                config,
                get_json=fake_get_json,
                resolve=_resolver("10.0.0.1"),
            )
        assert calls == [], f"get_json was called for a refused URL: {calls}"


# ---------------------------------------------------------------------------
# fetch_discovery tests
# ---------------------------------------------------------------------------

_ISSUER = "https://idp.example.com"


class TestFetchDiscovery:
    """fetch_discovery validation."""

    def test_happy_path(self):
        """Valid discovery doc returns the dict."""
        config = _build_config(_ISSUER, "client-id")
        doc = {
            "issuer": _ISSUER,
            "jwks_uri": "https://idp.example.com/.well-known/jwks.json",
            "authorization_endpoint": "https://idp.example.com/authorize",
            "token_endpoint": "https://idp.example.com/token",
        }
        calls = []

        def fake_get_json(url):
            calls.append(url)
            return doc

        result = _fetch_discovery(
            config,
            get_json=fake_get_json,
            resolve=_resolver(_PUBLIC_IP),
        )
        assert result["issuer"] == _ISSUER
        assert len(calls) >= 1

    def test_discovery_issuer_mismatch(self):
        """Discovery doc issuer does not match config -> discovery_issuer_mismatch."""
        _, OIDCError = _get_error_classes()
        config = _build_config(_ISSUER, "client-id")
        doc = {
            "issuer": "https://other-idp.example.com",
            "jwks_uri": "https://idp.example.com/.well-known/jwks.json",
        }

        with pytest.raises(OIDCError) as exc_info:
            _fetch_discovery(
                config,
                get_json=lambda url: doc,
                resolve=_resolver(_PUBLIC_IP),
            )
        assert exc_info.value.reason == "discovery_issuer_mismatch"

    def test_jwks_uri_http_rejected(self):
        """jwks_uri is http -> jwks_uri_unsafe."""
        _, OIDCError = _get_error_classes()
        config = _build_config(_ISSUER, "client-id")
        doc = {
            "issuer": _ISSUER,
            "jwks_uri": "http://idp.example.com/.well-known/jwks.json",
        }

        with pytest.raises(OIDCError) as exc_info:
            _fetch_discovery(
                config,
                get_json=lambda url: doc,
                resolve=_resolver(_PUBLIC_IP),
            )
        assert exc_info.value.reason == "jwks_uri_unsafe"

    def test_jwks_uri_private_address_rejected(self):
        """jwks_uri resolves to private address -> jwks_uri_unsafe."""
        _, OIDCError = _get_error_classes()
        config = _build_config(_ISSUER, "client-id")
        doc = {
            "issuer": _ISSUER,
            "jwks_uri": "https://internal.example.com/.well-known/jwks.json",
        }

        def resolve(host):
            if host == "internal.example.com":
                return ["10.0.0.1"]
            return [_PUBLIC_IP]

        with pytest.raises(OIDCError) as exc_info:
            _fetch_discovery(
                config,
                get_json=lambda url: doc,
                resolve=resolve,
            )
        assert exc_info.value.reason == "jwks_uri_unsafe"
