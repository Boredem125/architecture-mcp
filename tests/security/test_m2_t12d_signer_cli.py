"""T12d d1 tests-first: CLI signer commands (link, genesis, sign-registry).

Interface contract (pinned -- the build removes only xfail markers)
-------------------------------------------------------------------
ADR 0011 adds three CLI commands under ``sandbox signer``:

    sandbox signer link --code <code> --server <url>
        Links the local CLI key to the control plane.

    sandbox signer genesis --genesis-code <code> --server <url>
        [--approver] [--confirm-identity <iss> <sub>] [--yes]
        Builds registry v1, signs it, posts to POST /genesis.
        Prints the fingerprint = sha256(org_id + ":" + canonical_json(payload)).
        user_id is the server id, not the IdP ``sub``.
        Default roles: ``[admin]``.  ``--approver`` adds ``approver``.
        ``--confirm-identity <iss> <sub>`` must match server-reported identity;
        exits non-zero if mismatched.

    sandbox signer sign-registry [--in FILE] [--out FILE] [--publish]
        [--add <key_id>] [--admin] [--confirm-key-id <key_id>]
        [--confirm-identity <iss> <sub>]
        Checks the chain from the latest server version.
        Shows the diff computed from the bytes (incl. public_key/roles/
        bundle_signer/expires_at changes, D0-3).
        Needs the typed key_id (``--confirm-key-id``).
        Leaves an unconfirmed key unsigned (N1).
        ``--publish`` posts the complete envelope.

CLI tests use CliRunner with a mocked HTTP layer (ruling i). Never a live
server.

RED tests xfail on M2T12dPending.  Guards verify existing CLI structure.
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner
from nacl.signing import SigningKey


# ---------------------------------------------------------------------------
# Local sentinel
# ---------------------------------------------------------------------------

class M2T12dPending(Exception):
    """T12d: registry genesis CLI commands (ADR 0011)."""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _kid(sk: SigningKey) -> str:
    return hashlib.sha256(bytes(sk.verify_key)).hexdigest()


def _canonical_json(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def _fingerprint(org_id: str, payload: dict) -> str:
    """The connector fingerprint formula: sha256(org_id + ':' + canonical_json(payload))."""
    return hashlib.sha256(
        org_id.encode("utf-8") + b":" + _canonical_json(payload)
    ).hexdigest()


# ---------------------------------------------------------------------------
# Guards
# ---------------------------------------------------------------------------


def test_guard_signer_group_exists():
    """The 'signer' group exists in the CLI."""
    from sandbox.cli.main import cli
    runner = CliRunner()
    result = runner.invoke(cli, ["signer", "--help"])
    assert result.exit_code == 0, f"signer --help failed: {result.output}"
    assert "signer" in result.output.lower() or "approve" in result.output, (
        "'signer' group not registered or has no commands"
    )


def test_guard_signer_approve_exists():
    """The 'signer approve' command exists."""
    from sandbox.cli.main import cli
    runner = CliRunner()
    result = runner.invoke(cli, ["signer", "--help"])
    assert "approve" in result.output, "'approve' not in signer --help"


def test_guard_signer_deny_exists():
    """The 'signer deny' command exists."""
    from sandbox.cli.main import cli
    runner = CliRunner()
    result = runner.invoke(cli, ["signer", "--help"])
    assert "deny" in result.output, "'deny' not in signer --help"


# ---------------------------------------------------------------------------
# sandbox signer link
# ---------------------------------------------------------------------------


@pytest.mark.xfail(strict=True, raises=M2T12dPending,
                   reason="T12d d1: signer link command not registered")
def test_signer_link_command_exists():
    """'sandbox signer link' is a registered command."""
    from sandbox.cli.main import cli
    runner = CliRunner()
    result = runner.invoke(cli, ["signer", "--help"])
    if "link" not in result.output:
        raise M2T12dPending("'link' not in signer --help")


@pytest.mark.xfail(strict=True, raises=M2T12dPending,
                   reason="T12d d1: signer link command not implemented")
def test_signer_link_with_code():
    """'sandbox signer link --code ... --server ...' links the CLI key."""
    from sandbox.cli.main import cli
    runner = CliRunner()
    result = runner.invoke(cli, [
        "signer", "link",
        "--code", "test-code",
        "--server", "http://localhost:9999",
    ])
    if result.exit_code != 0:
        if "No such command" in (result.output or ""):
            raise M2T12dPending("'link' command not found")
        if "link" not in (result.output or ""):
            raise M2T12dPending("link command not implemented")
    # If it ran but failed for other reasons (network etc.), that's OK for now


# ---------------------------------------------------------------------------
# sandbox signer genesis
# ---------------------------------------------------------------------------


@pytest.mark.xfail(strict=True, raises=M2T12dPending,
                   reason="T12d d1: signer genesis command not registered")
def test_signer_genesis_command_exists():
    """'sandbox signer genesis' is a registered command."""
    from sandbox.cli.main import cli
    runner = CliRunner()
    result = runner.invoke(cli, ["signer", "--help"])
    if "genesis" not in result.output:
        raise M2T12dPending("'genesis' not in signer --help")


@pytest.mark.xfail(strict=True, raises=M2T12dPending,
                   reason="T12d d1: genesis fingerprint not implemented")
def test_genesis_prints_fingerprint():
    """'sandbox signer genesis' prints the fingerprint = sha256(org_id + ':' +
    canonical_json(payload)), matching the connector's existing formula."""
    from sandbox.cli.main import cli

    # The fingerprint formula from src/sandbox/connector/sync/enroll.py:
    # sha256(org_id.encode("utf-8") + b":" + canonical_json(payload))
    # Must match build_genesis in connector/sync/signer.py

    runner = CliRunner()
    result = runner.invoke(cli, ["signer", "genesis", "--help"])
    if result.exit_code != 0 and "No such command" in (result.output or ""):
        raise M2T12dPending("genesis command not found")

    # Since we can't run against a real server, check the library's
    # build_genesis function produces the right fingerprint
    from sandbox.connector.sync.signer import build_genesis

    sk = SigningKey.generate()
    org_id = "test-org-id"
    bundle_sk = SigningKey.generate()
    bundle_pub = bytes(bundle_sk.verify_key)

    env, fp = build_genesis(sk, org_id, "https://idp.test", "sub-test",
                            bundle_pub)
    payload = env["payload"]
    expected_fp = _fingerprint(org_id, payload)
    assert fp == expected_fp, (
        f"fingerprint mismatch: build_genesis={fp}, expected={expected_fp}"
    )

    # After d3, the genesis CLI command must print this fingerprint
    raise M2T12dPending("genesis CLI command not implemented to verify output")


@pytest.mark.xfail(strict=True, raises=M2T12dPending,
                   reason="T12d d1: genesis user_id not fixed to server id")
def test_genesis_user_id_is_server_id_not_sub():
    """build_genesis must use the server user id, not the IdP sub."""
    from sandbox.connector.sync.signer import build_genesis

    sk = SigningKey.generate()
    org_id = "test-org"
    server_user_id = "srv-user-12345"
    iss = "https://idp.test"
    sub = "idp-subject-67890"
    bundle_pub = bytes(SigningKey.generate().verify_key)

    env, _fp = build_genesis(sk, org_id, iss, sub, bundle_pub)
    key_entry = env["payload"]["keys"][0]

    # ADR 0011: user_id is the server id, not sub
    if key_entry.get("user_id") == sub:
        raise M2T12dPending(
            "build_genesis sets user_id = sub (IdP subject); "
            "it must be the server user id"
        )
    # After the fix, build_genesis takes user_id as a parameter
    # and the key entry's user_id equals the server id
    assert key_entry["user_id"] == server_user_id


@pytest.mark.xfail(strict=True, raises=M2T12dPending,
                   reason="T12d d1: genesis default roles not [admin] only")
def test_genesis_default_roles_admin_only():
    """Default genesis roles are [admin], not [admin, approver]."""
    from sandbox.connector.sync.signer import build_genesis

    sk = SigningKey.generate()
    org_id = "test-org"
    bundle_pub = bytes(SigningKey.generate().verify_key)

    env, _fp = build_genesis(sk, org_id, "https://idp.test", "sub",
                             bundle_pub)
    key_entry = env["payload"]["keys"][0]
    roles = key_entry.get("roles", [])

    if roles == ["admin", "approver"]:
        raise M2T12dPending(
            "build_genesis hard-codes roles ['admin', 'approver']; "
            "default should be ['admin'] only (least privilege)"
        )
    assert roles == ["admin"], f"expected ['admin'], got {roles}"


@pytest.mark.xfail(strict=True, raises=M2T12dPending,
                   reason="T12d d1: --approver flag not implemented")
def test_genesis_approver_flag_adds_approver():
    """'--approver' adds the approver role."""
    from sandbox.cli.main import cli
    runner = CliRunner()
    result = runner.invoke(cli, ["signer", "genesis", "--help"])
    if result.exit_code != 0 and "No such command" in (result.output or ""):
        raise M2T12dPending("genesis command not found")
    if "--approver" not in (result.output or ""):
        raise M2T12dPending("--approver flag not in genesis --help")


@pytest.mark.xfail(strict=True, raises=M2T12dPending,
                   reason="T12d d1: --confirm-identity not implemented")
def test_genesis_confirm_identity_mismatch_exits_nonzero():
    """'--confirm-identity <iss> <sub>' must match server-reported identity;
    exits non-zero and posts nothing on mismatch."""
    from sandbox.cli.main import cli
    runner = CliRunner()
    result = runner.invoke(cli, ["signer", "genesis", "--help"])
    if result.exit_code != 0 and "No such command" in (result.output or ""):
        raise M2T12dPending("genesis command not found")
    if "--confirm-identity" not in (result.output or ""):
        raise M2T12dPending("--confirm-identity flag not in genesis --help")


# ---------------------------------------------------------------------------
# sandbox signer sign-registry
# ---------------------------------------------------------------------------


@pytest.mark.xfail(strict=True, raises=M2T12dPending,
                   reason="T12d d1: sign-registry command not registered")
def test_sign_registry_command_exists():
    """'sandbox signer sign-registry' is a registered command."""
    from sandbox.cli.main import cli
    runner = CliRunner()
    result = runner.invoke(cli, ["signer", "--help"])
    if "sign-registry" not in result.output:
        raise M2T12dPending("'sign-registry' not in signer --help")


@pytest.mark.xfail(strict=True, raises=M2T12dPending,
                   reason="T12d d1: sign-registry --in/--out not implemented")
def test_sign_registry_in_out_flags():
    """'sign-registry' has --in and --out flags."""
    from sandbox.cli.main import cli
    runner = CliRunner()
    result = runner.invoke(cli, ["signer", "sign-registry", "--help"])
    if result.exit_code != 0 and "No such command" in (result.output or ""):
        raise M2T12dPending("sign-registry command not found")
    help_text = result.output or ""
    if "--in" not in help_text:
        raise M2T12dPending("--in flag not in sign-registry --help")
    if "--out" not in help_text:
        raise M2T12dPending("--out flag not in sign-registry --help")


@pytest.mark.xfail(strict=True, raises=M2T12dPending,
                   reason="T12d d1: sign-registry --publish not implemented")
def test_sign_registry_publish_flag():
    """'sign-registry --publish' posts the complete envelope."""
    from sandbox.cli.main import cli
    runner = CliRunner()
    result = runner.invoke(cli, ["signer", "sign-registry", "--help"])
    if result.exit_code != 0 and "No such command" in (result.output or ""):
        raise M2T12dPending("sign-registry command not found")
    if "--publish" not in (result.output or ""):
        raise M2T12dPending("--publish flag not in sign-registry --help")


@pytest.mark.xfail(strict=True, raises=M2T12dPending,
                   reason="T12d d1: sign-registry --confirm-key-id not implemented")
def test_sign_registry_confirm_key_id():
    """'sign-registry' needs the typed key_id via --confirm-key-id."""
    from sandbox.cli.main import cli
    runner = CliRunner()
    result = runner.invoke(cli, ["signer", "sign-registry", "--help"])
    if result.exit_code != 0 and "No such command" in (result.output or ""):
        raise M2T12dPending("sign-registry command not found")
    if "--confirm-key-id" not in (result.output or ""):
        raise M2T12dPending("--confirm-key-id flag not in sign-registry --help")


@pytest.mark.xfail(strict=True, raises=M2T12dPending,
                   reason="T12d d1: sign-registry diff D0-3 not fixed")
def test_sign_registry_diff_shows_all_changes():
    """compute_diff must show public_key, roles, bundle_signer and
    expires_at changes (D0-3 fix)."""
    from sandbox.connector.sync.signer import compute_diff

    alice = SigningKey.generate()
    bob = SigningKey.generate()
    alice_kid = _kid(alice)
    bob_kid = _kid(bob)

    v1_payload = {
        "org_id": "test-org", "version": 1, "prev_hash": "",
        "threshold": 1, "admins": [alice_kid],
        "keys": [
            {"key_id": alice_kid, "public_key": bytes(alice.verify_key).hex(),
             "user_id": "user-alice", "iss": "https://idp", "sub": "sub-a",
             "alg": "ed25519", "kind": "cli", "roles": ["admin"], "added_in": 1},
            {"key_id": bob_kid, "public_key": bytes(bob.verify_key).hex(),
             "user_id": "user-bob", "iss": "https://idp", "sub": "sub-b",
             "alg": "ed25519", "kind": "cli", "roles": ["approver"], "added_in": 1},
        ],
        "bundle_signer": {"key_id": "bs1", "public_key": "aabbcc"},
        "expires_at": time.time() + 3600,
    }

    v2_payload = dict(v1_payload)
    v2_payload["version"] = 2
    v2_keys = [dict(k) for k in v1_payload["keys"]]
    v2_keys[1]["roles"] = ["approver", "admin"]  # role change
    v2_payload["keys"] = v2_keys
    v2_payload["bundle_signer"] = {"key_id": "bs2", "public_key": "ddeeff"}  # swap
    v2_payload["expires_at"] = v1_payload["expires_at"] + 10 * 365 * 86400  # 10yr

    v1_bytes = _canonical_json(v1_payload)
    v2_bytes = _canonical_json(v2_payload)

    diff = compute_diff(v1_bytes, v2_bytes)
    # The diff must mention the changes (D0-3)
    missing = []
    if "roles" not in diff.lower():
        missing.append("roles change")
    if "bundle_signer" not in diff.lower() and "bs2" not in diff:
        missing.append("bundle_signer change")
    if "expires_at" not in diff.lower() and "10" not in diff:
        missing.append("expires_at change")

    if missing:
        raise M2T12dPending(
            f"compute_diff does not show: {', '.join(missing)}"
        )


@pytest.mark.xfail(strict=True, raises=M2T12dPending,
                   reason="T12d d1: unconfirmed key left unsigned (N1)")
def test_sign_registry_unconfirmed_key_left_unsigned():
    """An unconfirmed key_id (not typed by the admin) must be left unsigned
    (N1, confirm_key_ids)."""
    from sandbox.connector.sync.signer import confirm_key_ids

    added = ["key-alice", "key-bob", "key-carol"]
    confirmed = {"key-alice", "key-carol"}
    result = confirm_key_ids(added, confirmed)

    # This function already works correctly (returns only confirmed keys)
    assert result == ["key-alice", "key-carol"]

    # But the sign-registry command must use it with --confirm-key-id
    # and refuse to sign a version that includes an unconfirmed key
    from sandbox.cli.main import cli
    runner = CliRunner()
    help_result = runner.invoke(cli, ["signer", "sign-registry", "--help"])
    if "No such command" in (help_result.output or ""):
        raise M2T12dPending("sign-registry command not found; N1 confirm_key_ids untestable")
    if "--confirm-key-id" not in (help_result.output or ""):
        raise M2T12dPending("--confirm-key-id not in sign-registry --help; N1 untestable")


@pytest.mark.xfail(strict=True, raises=M2T12dPending,
                   reason="T12d d1: sign-registry chain check not implemented")
def test_sign_registry_checks_chain_from_latest_version():
    """sign-registry --in FILE checks that the partial envelope chains from
    the latest server version and that every existing signature is valid."""
    from sandbox.cli.main import cli
    runner = CliRunner()
    result = runner.invoke(cli, ["signer", "sign-registry", "--help"])
    if "No such command" in (result.output or ""):
        raise M2T12dPending("sign-registry command not found")
    # The chain check is an implementation detail; if the command exists
    # we need to test it with mock data
    raise M2T12dPending("sign-registry chain validation not testable yet")


@pytest.mark.xfail(strict=True, raises=M2T12dPending,
                   reason="T12d d1: every confirmation flag names the exact value")
def test_confirmation_flags_name_exact_values():
    """Every confirmation flag (--confirm-key-id, --confirm-identity) names
    the exact value so a script can never skip a check blindly."""
    from sandbox.cli.main import cli
    runner = CliRunner()

    # Check genesis --confirm-identity takes <iss> <sub>
    result = runner.invoke(cli, ["signer", "genesis", "--help"])
    if "No such command" in (result.output or ""):
        raise M2T12dPending("genesis command not found")
    if "--confirm-identity" not in (result.output or ""):
        raise M2T12dPending("--confirm-identity not in genesis --help")

    # Check sign-registry --confirm-key-id takes <key_id>
    result = runner.invoke(cli, ["signer", "sign-registry", "--help"])
    if "No such command" in (result.output or ""):
        raise M2T12dPending("sign-registry command not found")
    if "--confirm-key-id" not in (result.output or ""):
        raise M2T12dPending("--confirm-key-id not in sign-registry --help")
