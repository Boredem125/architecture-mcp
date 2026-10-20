"""M1 T8 part 1: tests added in the build for the security review findings.

Medium-1: an empty resolver answer must not pass the address guard.
Medium-2: a discovery document without a usable ``jwks_uri`` is refused.
Low-1: an Entra ``tenant_id`` must be a canonical GUID, so it cannot reshape
the expected issuer.
"""
from __future__ import annotations

import pytest

from agg_cp.oidc import OIDCError, OrgOIDCConfig, UnsafeURLError, check_fetch_url, fetch_discovery

_ISS = "https://idp.example.com"
_PUBLIC = lambda host: ["93.184.216.34"]  # noqa: E731


def test_empty_resolver_answer_refused():
    with pytest.raises(UnsafeURLError) as exc:
        check_fetch_url("https://idp.example.com/jwks", resolve=lambda host: [])
    assert exc.value.reason == "resolve_failed"


def test_positive_control_public_answer_passes():
    check_fetch_url("https://idp.example.com/jwks", resolve=_PUBLIC)


@pytest.mark.parametrize("jwks_uri", [None, "", 0, ["https://idp.example.com/jwks"]])
def test_discovery_without_usable_jwks_uri_refused(jwks_uri):
    doc = {"issuer": _ISS}
    if jwks_uri is not None:
        doc["jwks_uri"] = jwks_uri
    with pytest.raises(UnsafeURLError) as exc:
        fetch_discovery(OrgOIDCConfig(issuer=_ISS, client_id="c"), get_json=lambda url: doc, resolve=_PUBLIC)
    assert exc.value.reason == "jwks_uri_unsafe"


def test_positive_control_discovery_with_jwks_uri_passes():
    doc = {"issuer": _ISS, "jwks_uri": _ISS + "/jwks"}
    got = fetch_discovery(OrgOIDCConfig(issuer=_ISS, client_id="c"), get_json=lambda url: doc, resolve=_PUBLIC)
    assert got["jwks_uri"] == _ISS + "/jwks"


_ENTRA = "https://login.microsoftonline.com/{tenantid}/v2.0"


@pytest.mark.parametrize(
    "tenant_id",
    [
        "evil.example/x",
        "{tenantid}",
        "0123456789abcdef0123456789abcdef",  # GUID without dashes
        "{{{{0123456789abcdef0123456789abcdef",  # parses after brace stripping
        "11111111-2222-3333-4444-555555555555/../x",
    ],
)
def test_entra_tenant_id_must_be_canonical_guid(tenant_id):
    with pytest.raises(OIDCError) as exc:
        OrgOIDCConfig(issuer=_ENTRA, client_id="c", tenant_id=tenant_id).expected_issuer()
    assert exc.value.reason == "bad_tenant_id"


def test_positive_control_canonical_guid_renders():
    tid = "11111111-2222-3333-4444-555555555555"
    cfg = OrgOIDCConfig(issuer=_ENTRA, client_id="c", tenant_id=tid)
    assert cfg.expected_issuer() == f"https://login.microsoftonline.com/{tid}/v2.0"
