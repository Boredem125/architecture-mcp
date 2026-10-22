"""T7 tests-first: sandbox signer (link, genesis, diff view, sign-registry,
approve-change, approve, deny, unenroll --out) and server signer routes.

Postgres-free.  All keys are generated in the test.  Uses a fake server
(``tests/m2_fakes.py``) where integration needs arise.

Interface contract
==================

Connector module ``sandbox.connector.sync.signer`` (MIT, no ``agg_cp`` import):

    build_genesis(admin_sk, org_id, iss, sub, bundle_signer_pub)
        -> (envelope, fingerprint)
        Build registry v1 locally and return the signed envelope plus the
        root fingerprint (SHA-256 of ``org_id + ":" + canonical_json(payload)``).

    compute_diff(prev_payload_bytes: bytes | None, new_payload_bytes: bytes)
        -> str
        Human-readable diff of two canonical registry payloads.  The diff
        is always computed from the *bytes*, not from any server-sent
        summary.  ``None`` for genesis.

    confirm_key_ids(added_key_ids: list[str], confirmed_ids: set[str])
        -> list[str]
        Return only the key_ids present in *confirmed_ids*.  An unconfirmed
        key_id (not typed by the admin out of band) is excluded.

    create_signer_assertion(signing_key, key_id: str, nonce: str, aud: str)
        -> dict
        Build an ``agg/signer-assert/v1`` signed envelope for CLI auth.

CLI (in the existing ``sandbox`` CLI package):

    sandbox signer link --code CODE --server URL
    sandbox signer genesis --server URL
    sandbox signer sign-registry --server URL
    sandbox signer approve-change ESCALATION_ID --server URL
    sandbox signer approve ESCALATION_ID --server URL
    sandbox signer deny ESCALATION_ID --server URL
    sandbox signer unenroll --out FILE --server URL

Server module ``agg_cp.sync.signer`` (routes under ``/api/v1/sync/signer/``):

    POST /api/v1/sync/signer/token       authenticate via agg/signer-assert/v1
    POST /api/v1/sync/signer/link         consume link code, bind CLI key
    GET  /api/v1/sync/signer/pending      list pending items to sign
    POST /api/v1/sync/signer/signatures   store signatures

Signer auth: ``agg/signer-assert/v1`` tokens, 10 min, stored as SHA-256 hash.

Node-id patterns are fixed in M2_BASELINE.md section 5.  Covers threats 33
and 37 (signer subcommands through shell forms).

T6 rules apply: the sentinel is raised only by one helper ``_need()`` at the
top of a test; the final assertions are plain ``assert``/``pytest.raises``.
Tests never patch global ``os`` attributes.
"""
from __future__ import annotations

import hashlib
import json
import time

import pytest
from nacl.signing import SigningKey

from tests.m2_pending import M2T7Pending

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _need(module: str, attr: str) -> None:
    """Raise M2T7Pending if *module*.*attr* is absent."""
    try:
        mod = __import__(module, fromlist=[attr])
    except ImportError:
        raise M2T7Pending(f"{module} not importable")
    if not hasattr(mod, attr):
        raise M2T7Pending(f"{module}.{attr} not found")


def _keygen():
    """Return (signing_key, pub_bytes, key_id)."""
    sk = SigningKey.generate()
    pub = bytes(sk.verify_key)
    kid = hashlib.sha256(pub).hexdigest()
    return sk, pub, kid


def _canonical_json(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


# ---------------------------------------------------------------------------
# Layout fixture (same as test_t0_hotfix.py)
# ---------------------------------------------------------------------------

from sandbox.connector.classify import classify
from sandbox.connector.layout import FolderLayout
from sandbox.connector.policy import default_policy, save_policy
from sandbox.safety.blocklist import CommandBlocklist
import os


@pytest.fixture
def layout(tmp_path):
    lo = FolderLayout(tmp_path)
    lo.ensure_dirs()
    policy = default_policy()
    policy.escalation_timeout_seconds = 0
    save_policy(policy, lo.policy_file)
    lo.session_file.write_text(json.dumps({"session_id": "s-t7"}), encoding="utf-8")
    keys = lo.state_dir / "keys"
    keys.mkdir(parents=True, exist_ok=True)
    (keys / "a.seed").write_bytes(b"\x00" * 32)
    (tmp_path / "app.py").write_text('print("ok")\n')
    return lo


def _classify_cmd(layout, command):
    return classify("Bash", {"command": command}, default_policy(), layout,
                    cwd=str(layout.root), blocklist=CommandBlocklist())


# ===================================================================
# Guards (pass now -- existing code)
# ===================================================================


def test_approver_subcommands_importable():
    """Guard: _APPROVER_SUBCOMMANDS is importable and non-empty."""
    from sandbox.connector.classify import _APPROVER_SUBCOMMANDS
    assert len(_APPROVER_SUBCOMMANDS) >= 6


def test_existing_approve_denied(layout):
    """Guard: 'sandbox approve ID' is denied by the classifier."""
    c = _classify_cmd(layout, "sandbox approve req-1 --reviewer bob")
    assert c.verdict == "deny"


def test_nacl_keygen_guard():
    """Guard: Ed25519 keygen and signing work."""
    sk, pub, kid = _keygen()
    assert len(pub) == 32
    assert len(kid) == 64


# ===================================================================
# RED: genesis builds v1 locally and prints the fingerprint
# ===================================================================


def test_genesis_builds_v1_locally():
    """build_genesis returns a valid v1 registry envelope built locally."""
    _need("sandbox.connector.sync.signer", "build_genesis")
    from sandbox.connector.sync.signer import build_genesis
    sk, pub, kid = _keygen()
    bsk, bpub, bkid = _keygen()
    env, fp = build_genesis(
        admin_sk=sk, org_id="org-1",
        iss="https://idp", sub="alice",
        bundle_signer_pub=bpub,
    )
    assert env["kind"] == "agg/registry/v1"
    assert env["sig_v"] == 1
    assert env["payload"]["version"] == 1
    assert env["payload"]["org_id"] == "org-1"
    assert len(env["signatures"]) == 1
    assert env["signatures"][0]["key_id"] == kid


def test_genesis_prints_fingerprint_matching_payload():
    """The fingerprint from build_genesis matches SHA-256 of org:canonical."""
    _need("sandbox.connector.sync.signer", "build_genesis")
    from sandbox.connector.sync.signer import build_genesis
    sk, pub, kid = _keygen()
    bsk, bpub, bkid = _keygen()
    env, fp = build_genesis(
        admin_sk=sk, org_id="org-1",
        iss="https://idp", sub="alice",
        bundle_signer_pub=bpub,
    )
    expected_fp = hashlib.sha256(
        env["payload"]["org_id"].encode("utf-8") + b":" +
        _canonical_json(env["payload"])
    ).hexdigest()
    assert fp == expected_fp


# ===================================================================
# RED: diff computed from the payload bytes, not a server-sent summary
# ===================================================================


def test_diff_computed_from_bytes_not_summary():
    """compute_diff uses the canonical bytes, not a server-supplied summary.

    Scenario: the server sends a lying summary ("no changes") but the
    payload bytes show added keys.  The diff must reflect the bytes.
    """
    _need("sandbox.connector.sync.signer", "compute_diff")
    from sandbox.connector.sync.signer import compute_diff
    sk1, pub1, kid1 = _keygen()
    sk2, pub2, kid2 = _keygen()

    prev = {
        "org_id": "org-1", "version": 1, "threshold": 1,
        "admins": [kid1],
        "keys": [{"key_id": kid1, "user_id": "alice", "kind": "cli"}],
    }
    new = {
        "org_id": "org-1", "version": 2, "threshold": 1,
        "admins": [kid1],
        "keys": [
            {"key_id": kid1, "user_id": "alice", "kind": "cli"},
            {"key_id": kid2, "user_id": "bob", "kind": "cli"},
        ],
    }
    prev_bytes = _canonical_json(prev)
    new_bytes = _canonical_json(new)
    diff_text = compute_diff(prev_bytes, new_bytes)
    # The diff must mention the added key_id -- proof it reads the bytes
    assert kid2 in diff_text
    # It must NOT blindly trust a server-supplied summary
    assert "no changes" not in diff_text.lower()


def test_diff_genesis_from_none():
    """compute_diff with prev=None (genesis) shows all keys as added."""
    _need("sandbox.connector.sync.signer", "compute_diff")
    from sandbox.connector.sync.signer import compute_diff
    sk1, pub1, kid1 = _keygen()
    payload = {
        "org_id": "org-1", "version": 1, "threshold": 1,
        "admins": [kid1],
        "keys": [{"key_id": kid1, "user_id": "alice", "kind": "cli"}],
    }
    diff_text = compute_diff(None, _canonical_json(payload))
    assert kid1 in diff_text


# ===================================================================
# RED: threat 33 -- substituted key_id not confirmed (N1)
# ===================================================================


def test_substituted_key_not_confirmed():
    """A substituted, unconfirmed key_id is excluded (threat 33, N1).

    sign-registry lists every added CLI key_id and needs a typed
    confirmation.  A key_id the admin did not confirm is not signed.
    """
    _need("sandbox.connector.sync.signer", "confirm_key_ids")
    from sandbox.connector.sync.signer import confirm_key_ids
    real_kid = "a" * 64       # the real key_id from the owner out of band
    server_kid = "b" * 64     # substituted by a compromised server
    added = [real_kid, server_kid]
    confirmed = {real_kid}    # admin typed only the real one
    result = confirm_key_ids(added, confirmed)
    assert real_kid in result
    assert server_kid not in result


def test_confirm_key_ids_all_confirmed():
    """All confirmed key_ids pass through."""
    _need("sandbox.connector.sync.signer", "confirm_key_ids")
    from sandbox.connector.sync.signer import confirm_key_ids
    kid_a = "a" * 64
    kid_b = "b" * 64
    result = confirm_key_ids([kid_a, kid_b], {kid_a, kid_b})
    assert kid_a in result
    assert kid_b in result


def test_confirm_key_ids_none_confirmed():
    """No confirmed key_ids means nothing is signed."""
    _need("sandbox.connector.sync.signer", "confirm_key_ids")
    from sandbox.connector.sync.signer import confirm_key_ids
    result = confirm_key_ids(["a" * 64, "b" * 64], set())
    assert result == []


# ===================================================================
# RED: signer assertion (agg/signer-assert/v1)
# ===================================================================


def test_signer_assertion_roundtrip():
    """create_signer_assertion produces a verifiable agg/signer-assert/v1."""
    _need("sandbox.connector.sync.signer", "create_signer_assertion")
    from sandbox.connector.sync.signer import create_signer_assertion
    from sandbox.protocol.envelope import verify_envelope
    sk, pub, kid = _keygen()
    env = create_signer_assertion(sk, kid, nonce="n-1", aud="https://server")
    assert env["kind"] == "agg/signer-assert/v1"
    assert env["sig_v"] == 1
    result = verify_envelope(env, {kid: pub})
    assert result["nonce"] == "n-1"
    assert result["aud"] == "https://server"


def test_signer_assertion_has_iat():
    """The signer assertion includes an iat within 2 min of now."""
    _need("sandbox.connector.sync.signer", "create_signer_assertion")
    from sandbox.connector.sync.signer import create_signer_assertion
    sk, pub, kid = _keygen()
    env = create_signer_assertion(sk, kid, nonce="n-2", aud="https://server")
    iat = env["payload"]["iat"]
    assert abs(iat - time.time()) < 120


# ===================================================================
# RED: key live only after quorum-signed registry includes it
# ===================================================================


def test_key_live_only_after_quorum_registry():
    """A linked CLI key is only a proposal until a quorum-signed registry
    version includes it.  Before that, the key cannot sign anything
    except completing its own link.
    """
    _need("sandbox.connector.sync.signer", "build_genesis")
    from sandbox.protocol.registry import verify_chain, Registry
    sk_admin, pub_admin, kid_admin = _keygen()
    sk_pending, pub_pending, kid_pending = _keygen()

    # Build genesis with only the admin
    bsk, bpub, bkid = _keygen()
    from sandbox.connector.sync.signer import build_genesis
    env, fp = build_genesis(
        admin_sk=sk_admin, org_id="org-1",
        iss="https://idp", sub="admin-0",
        bundle_signer_pub=bpub,
    )
    reg = verify_chain([env], fp)
    # The pending key is not in the registry -> cannot sign anything
    assert not reg.may_sign(kid_pending, "agg/remote-approval/v1", "staging")
    assert not reg.may_sign(kid_pending, "agg/registry/v1", "staging")
    assert not reg.may_sign(kid_pending, "agg/policy-change/v1", "staging")


# ===================================================================
# RED: threat 37 -- every signer subcommand denied through shell forms
#
# Reuse the same parametrisation pattern as the existing approve denial
# tests in test_t0_hotfix.py (APPROVER_CLI / test_t0e_approver_cli_denied_classify).
# ===================================================================

SIGNER_CLI_COMMANDS = [
    # Direct invocations of each signer subcommand
    "sandbox signer link --code ABC123 --server https://server.invalid",
    "sandbox signer genesis --server https://server.invalid",
    "sandbox signer sign-registry --server https://server.invalid",
    "sandbox signer approve-change req-1 --server https://server.invalid",
    "sandbox signer approve req-1 --server https://server.invalid",
    "sandbox signer deny req-1 --server https://server.invalid",
    "sandbox signer unenroll --out /tmp/unenroll.json --server https://server.invalid",
    # Shell forms: chained, piped, multi-line, substitution, module
    "echo ok && sandbox signer link --code X",
    "echo ok; sandbox signer approve req-1",
    "echo ok\nsandbox signer genesis",
    "echo $(sandbox signer sign-registry)",
    "python -m sandbox.cli signer approve req-1",
]


@pytest.mark.parametrize("command", SIGNER_CLI_COMMANDS)
def test_signer_subcommand_denied_classify(layout, command):
    """Every ``sandbox signer`` subcommand is denied for the agent (threat 37).

    Uses the same shell forms the existing ``approve`` denial tests use.
    """
    _need("sandbox.connector.sync.signer", "build_genesis")
    c = _classify_cmd(layout, command)
    assert c.verdict == "deny", (command, c.verdict, c.reason)
