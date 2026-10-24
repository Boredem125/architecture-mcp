"""T13 tests-first: golden canonical bytes for cross-language validation,
server-side route checks for the web approval UI.

Cross-language fixture
----------------------
``test_guard_golden_fixture_written`` computes the canonical bytes for a
deterministic payload using the Python protocol module and writes them to
``ee/web/tests/fixtures/golden_canonical.json``.  The companion vitest test
in ``ee/web/tests/signing.test.ts`` reads that file and asserts the TS
signing module produces identical bytes.

Routes T13 needs that T12 does not define
-----------------------------------------
GET /api/v1/escalations  (user-facing pending escalation list for web UI)

Routes T13 reuses from T12:
  POST /api/v1/sync/escalations/{escalation_id}/approvals

Routes T13 reuses from T7:
  POST /api/v1/signer-links  (browser key binding, kind=browser)

RED tests xfail on M2T13Pending.  Guards verify existing code.

T6 rule: the sentinel is raised only by one helper ``_need()`` at the
top of a test; the final assertions are plain ``assert``/``pytest.raises``.
Tests never patch global ``os`` attributes.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path

import pytest

from .m2_pending import M2T13Pending


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Deterministic payload for cross-language golden fixture (D5.6 full field set)
GOLDEN_PAYLOAD: dict = {
    "approved_at": 1700000000.0,
    "command": "echo golden-test",
    "decision": "approve",
    "device_id": "dev-golden",
    "fingerprint": "abc123def456",
    "key_id": "kid-golden-0000",
    "nonce": "nonce-golden-0000",
    "not_after": 1700000900.0,
    "org_id": "org-golden",
    "policy_sequence": 1,
    "project_id": "proj-golden",
    "registry_version": 1,
    "request_id": "golden-req-1",
    "reviewer_id": "user-golden",
    "user_id": "user-golden",
}

GOLDEN_TAG = "agg/remote-approval/v1"

# Expected canonical JSON (sorted keys, compact separators)
GOLDEN_CANONICAL_JSON = json.dumps(
    GOLDEN_PAYLOAD, sort_keys=True, separators=(",", ":")
).encode("utf-8")

# Expected signed bytes: tag || 0x00 || canonical JSON
GOLDEN_CANONICAL_BYTES = GOLDEN_TAG.encode("utf-8") + b"\x00" + GOLDEN_CANONICAL_JSON

FIXTURE_DIR = Path(__file__).resolve().parents[1] / "web" / "tests" / "fixtures"


def _need(module: str, attr: str) -> None:
    """Raise M2T13Pending if *module*.*attr* is absent."""
    try:
        mod = __import__(module, fromlist=[attr])
    except ImportError:
        raise M2T13Pending(f"{module} not importable")
    if not hasattr(mod, attr):
        raise M2T13Pending(f"{module}.{attr} not found")


# ---------------------------------------------------------------------------
# Guards (pass now -- existing code)
# ---------------------------------------------------------------------------


def test_guard_canonical_bytes_deterministic():
    """Guard: canonical_bytes in protocol.envelope is deterministic for a fixed payload."""
    from sandbox.protocol.envelope import canonical_bytes

    result = canonical_bytes(GOLDEN_TAG, GOLDEN_PAYLOAD)
    assert result == GOLDEN_CANONICAL_BYTES


def test_guard_remote_approval_field_set():
    """Guard: the D5.6 field set is the union of _APPROVAL_FIELDS and the remote fields.

    The full field set: request_id, command, fingerprint, reviewer_id, decision,
    approved_at, org_id, project_id, device_id, registry_version, policy_sequence,
    user_id, key_id, nonce, not_after.
    """
    expected_fields = frozenset({
        "request_id", "command", "fingerprint", "reviewer_id", "decision",
        "approved_at", "org_id", "project_id", "device_id", "registry_version",
        "policy_sequence", "user_id", "key_id", "nonce", "not_after",
    })
    assert set(GOLDEN_PAYLOAD.keys()) == expected_fields


def test_guard_golden_fixture_written():
    """Guard: write the golden canonical bytes fixture for cross-language tests.

    The fixture file is ee/web/tests/fixtures/golden_canonical.json.
    It contains the tag, payload, canonical JSON hex, and canonical bytes hex
    so the TS tests can verify byte-for-byte identity.
    """
    FIXTURE_DIR.mkdir(parents=True, exist_ok=True)

    fixture = {
        "tag": GOLDEN_TAG,
        "payload": GOLDEN_PAYLOAD,
        "canonical_json_hex": GOLDEN_CANONICAL_JSON.hex(),
        "canonical_bytes_hex": GOLDEN_CANONICAL_BYTES.hex(),
        "canonical_bytes_sha256": hashlib.sha256(GOLDEN_CANONICAL_BYTES).hexdigest(),
    }

    fixture_path = FIXTURE_DIR / "golden_canonical.json"
    fixture_path.write_text(
        json.dumps(fixture, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    assert fixture_path.exists()

    # Verify round-trip
    loaded = json.loads(fixture_path.read_text(encoding="utf-8"))
    assert bytes.fromhex(loaded["canonical_bytes_hex"]) == GOLDEN_CANONICAL_BYTES


# ===================================================================
# RED: escalation list route for web UI
# ===================================================================


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M2T13Pending)
def test_escalation_list_route_exists(pg_url, pg_roles, owner_url):
    """GET /api/v1/escalations returns pending escalations for the web user.

    This route is user-facing (session auth), not device-facing.
    T12's GET /api/v1/sync/decisions is device-facing.
    """
    _need("agg_cp.web.escalations", "router")


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M2T13Pending)
def test_escalation_list_filtered_by_org(pg_url, pg_roles, owner_url):
    """The escalation list is filtered by the user's org (RLS)."""
    _need("agg_cp.web.escalations", "router")


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M2T13Pending)
def test_escalation_list_shows_environment(pg_url, pg_roles, owner_url):
    """The escalation list includes the project environment for prod-guard display."""
    _need("agg_cp.web.escalations", "router")


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M2T13Pending)
def test_escalation_list_marks_prod(pg_url, pg_roles, owner_url):
    """Prod escalations are marked in the list so the UI can hide approve.

    The response must include ``is_prod: true`` or ``environment: "prod"``
    so the TS code can hide the approve button (exit check D5.5).
    """
    _need("agg_cp.web.escalations", "router")


# ===================================================================
# RED: browser key link via web session
# ===================================================================


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M2T13Pending)
def test_browser_key_link_creates_pending(pg_url, pg_roles, owner_url):
    """POST /api/v1/signer-links with kind=browser creates a pending key entry.

    The binding mirrors the T7 signer link flow: the user generates a
    WebCrypto Ed25519 key pair and submits the public key.  The server
    creates a pending entry tied to the user's session identity.
    """
    _need("agg_cp.web.browser_keys", "link_browser_key")


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M2T13Pending)
def test_browser_key_link_requires_session(pg_url, pg_roles, owner_url):
    """Browser key linking requires a valid user session, not a device token."""
    _need("agg_cp.web.browser_keys", "link_browser_key")


# ===================================================================
# RED: approval via browser session (D5.5, D6.2)
# ===================================================================


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M2T13Pending)
def test_approval_via_browser_session_accepted(pg_url, pg_roles, owner_url):
    """A browser-session user can submit an approval to the existing T12 route.

    The approval is signed client-side with WebCrypto and submitted as
    an agg/remote-approval/v1 envelope.  The server validates it.
    """
    _need("agg_cp.web.escalations", "submit_browser_approval")


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M2T13Pending)
def test_deny_via_browser_session_accepted(pg_url, pg_roles, owner_url):
    """A browser-session user can submit a deny decision."""
    _need("agg_cp.web.escalations", "submit_browser_approval")


# ===================================================================
# RED: CSP header on web-served responses
# ===================================================================


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M2T13Pending)
def test_csp_header_on_web_responses(pg_url, pg_roles, owner_url):
    """The server sets a strict CSP header on web-served HTML and API responses.

    Expected CSP includes: default-src 'self'; script-src 'self';
    style-src 'self'; frame-ancestors 'none'; base-uri 'none';
    form-action 'self'; object-src 'none'.
    """
    _need("agg_cp.web.escalations", "router")


# ===================================================================
# RED: no private key material in any server response
# ===================================================================


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M2T13Pending)
def test_no_private_key_in_escalation_list_response(pg_url, pg_roles, owner_url):
    """The escalation list response must not contain any private key material.

    HAR-style check: scan every JSON field in the response body for
    patterns matching Ed25519 private keys (64-byte hex or base64).
    """
    _need("agg_cp.web.escalations", "router")


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M2T13Pending)
def test_no_private_key_in_approval_response(pg_url, pg_roles, owner_url):
    """The approval response must not leak private key material."""
    _need("agg_cp.web.escalations", "submit_browser_approval")
