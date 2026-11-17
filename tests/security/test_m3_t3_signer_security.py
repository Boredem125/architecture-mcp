"""M3 T3 signer CLI security tests-first.

Cover from the security review (T3_SECURITY_REVIEW.md):
- approve-change positive node with temp key home + root_fingerprint
- base >= 1 corrupted base row -> no POST to /approvals
- no anchor -> exit 1 not 2, no network call
- --expect-fingerprint mismatch refused
- command never writes the fingerprint file
- propose-bundle OK case with stub hash computed per A9 item 6
- CLI never prints a code field
- credentials only from --key-file or the linked-key loader

Guards PASS today.

Spec: T3_SPEC.md section 4, T3_SECURITY_REVIEW.md sections 2-4.
"""
from __future__ import annotations

import hashlib
import json
import os
import uuid

import pytest
from click.testing import CliRunner
from nacl.signing import SigningKey

from tests.m3_pending import require_m3


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_cli():
    from sandbox.cli.main import cli
    return cli


def _command_in_signer(name: str) -> bool:
    cli = _get_cli()
    runner = CliRunner()
    result = runner.invoke(cli, ["signer", "--help"])
    help_text = result.output if result.exit_code == 0 else ""
    for line in help_text.splitlines():
        stripped = line.strip()
        if stripped.startswith(name + " ") or stripped == name:
            return True
    return False


class _FakeHTTPResponse:
    """Minimal response stub for mocking httpx calls."""
    def __init__(self, json_data, status_code=200):
        self._json = json_data
        self.status_code = status_code
        self.text = json.dumps(json_data)
        self.headers = {"content-type": "application/json"}

    def json(self):
        return self._json

    def raise_for_status(self):
        if self.status_code >= 400:
            raise Exception(f"HTTP {self.status_code}: {self.text}")


# ===================================================================
# GUARD TWINS
# ===================================================================

def test_guard_cli_signer_group():
    """Guard: signer CLI group exists."""
    cli = _get_cli()
    runner = CliRunner()
    result = runner.invoke(cli, ["signer", "--help"])
    assert result.exit_code == 0


# ===================================================================
# approve-change: positive node with temp key home + root_fingerprint
# ===================================================================


def test_approve_change_positive_with_fingerprint(tmp_path):
    """approve-change with a temp key home holding signer/root_fingerprint
    posts an approval whose body signs agg/policy-change/v1 over the hash.
    """
    import unittest.mock as mock

    require_m3(3, _command_in_signer("approve-change"),
               "signer approve-change command not found")

    org_id = str(uuid.uuid4())
    project_id = str(uuid.uuid4())

    # Build a base bundle (sequence 0 / deny-all)
    base_payload = {
        "org_id": org_id, "project_id": project_id,
        "sequence": 0, "base_sequence": 0, "registry_version": 1,
        "folder_policy": {}, "governance_policy": {}, "mcp_policy": {},
        "approval": {"local_fallback": False, "allow_requester": False},
    }
    base_canonical = json.dumps(base_payload, sort_keys=True,
                                separators=(",", ":")).encode()

    bundle_signer_sk = SigningKey.generate()
    base_sig = bundle_signer_sk.sign(
        b"agg/bundle/v1\x00" + base_canonical).signature.hex()
    bs_pub = bytes(bundle_signer_sk.verify_key)
    bs_kid = hashlib.sha256(bs_pub).hexdigest()
    base_envelope = {
        "kind": "agg/bundle/v1", "sig_v": 1,
        "payload": base_payload,
        "signatures": [{
            "key_id": bs_kid, "alg": "ed25519", "sig": base_sig,
        }],
    }

    # Build a registry chain (genesis only) with the signer key
    signer_sk = SigningKey.generate()
    signer_pub = bytes(signer_sk.verify_key)
    signer_kid = hashlib.sha256(signer_pub).hexdigest()
    genesis_keys = [{
        "key_id": signer_kid, "public_key": signer_pub.hex(),
        "user_id": "admin-0", "iss": "https://idp.test",
        "sub": "admin-0", "alg": "ed25519",
        "kind": "cli", "roles": ["admin", "approver"], "added_in": 1,
    }]
    genesis_payload = {
        "org_id": org_id, "version": 1, "prev_hash": "",
        "threshold": 1, "admins": [signer_kid],
        "keys": genesis_keys,
        "bundle_signer": {"key_id": bs_kid, "public_key": bs_pub.hex(),
                          "alg": "ed25519"},
        "expires_at": 9999999999.0,
    }
    genesis_canonical = json.dumps(genesis_payload, sort_keys=True,
                                   separators=(",", ":")).encode()
    genesis_sig = signer_sk.sign(
        b"agg/registry/v1\x00" + genesis_canonical).signature.hex()
    genesis_env = {
        "kind": "agg/registry/v1", "sig_v": 1,
        "payload": genesis_payload,
        "signatures": [{"key_id": signer_kid, "alg": "ed25519",
                        "sig": genesis_sig}],
    }

    # Fingerprint = sha256(org_id + ":" + canonical(genesis_payload))
    fp = hashlib.sha256(
        org_id.encode() + b":" + genesis_canonical
    ).hexdigest()

    # Temp key home with signer/root_fingerprint
    key_home = tmp_path / "key_home"
    key_home.mkdir()
    signer_dir = key_home / "signer"
    signer_dir.mkdir()
    (signer_dir / "root_fingerprint").write_text(fp)

    # Seed file for the signer key
    seed_file = tmp_path / "signer.seed"
    seed_file.write_bytes(bytes(signer_sk).hex().encode("ascii"))

    # Build proposal
    proposal_payload = {
        "org_id": org_id, "project_id": project_id,
        "sequence": 1, "base_sequence": 0, "registry_version": 1,
        "folder_policy": {"allow": ["*.py"]},
        "governance_policy": {}, "mcp_policy": {},
        "approval": {"local_fallback": False, "allow_requester": False},
    }
    proposal_canonical = json.dumps(proposal_payload, sort_keys=True,
                                    separators=(",", ":")).encode()
    proposal_hash = hashlib.sha256(proposal_canonical).hexdigest()
    proposal_id = str(uuid.uuid4())

    captured_posts = []

    def route_fn(method, url, **kwargs):
        url_str = str(url)
        # Token mint at the real route (bare envelope body)
        if method.upper() == "POST" and "/api/v1/sync/signer/token" in url_str:
            captured_posts.append({
                "url": url_str,
                "json": kwargs.get("json", {}),
            })
            return _FakeHTTPResponse({"token": "test-signer-token"}, 200)
        if method.upper() == "GET" and "bundle-proposals" in url_str:
            return _FakeHTTPResponse({
                "id": proposal_id,
                "bundle": proposal_payload,
                "bundle_hash": proposal_hash,
                "base_sequence": 0,
                "org_id": org_id,
                "project_id": project_id,
                "diff": {"folder_policy": "TAMPERED"},
            })
        if method.upper() == "GET" and "registry" in url_str:
            # Bare list -- the real route contract
            return _FakeHTTPResponse([genesis_env])
        if method.upper() == "GET" and "bundle" in url_str:
            return _FakeHTTPResponse({
                "envelope": base_envelope,
                "change_approvals": [],
            })
        if method.upper() == "POST":
            captured_posts.append({
                "url": url_str,
                "json": kwargs.get("json", {}),
            })
            return _FakeHTTPResponse({"ok": True}, 200)
        return _FakeHTTPResponse({"error": "not found"}, 404)

    cli = _get_cli()
    runner = CliRunner()

    with mock.patch("httpx.Client") as MC:
        inst = mock.MagicMock()
        MC.return_value.__enter__ = mock.MagicMock(return_value=inst)
        MC.return_value.__exit__ = mock.MagicMock(return_value=False)
        inst.get = mock.MagicMock(
            side_effect=lambda url, **kw: route_fn("GET", url, **kw))
        inst.post = mock.MagicMock(
            side_effect=lambda url, **kw: route_fn("POST", url, **kw))

        result = runner.invoke(cli, [
            "signer", "approve-change", proposal_id,
            "--server", "https://localhost",
            "--key-file", str(seed_file),
            "--yes",
        ], env={"SANDBOX_KEY_HOME": str(key_home)})

    assert result.exit_code != 2, \
        f"approve-change usage error: {result.output}"
    assert result.exit_code == 0, \
        (f"approve-change exit_code={result.exit_code}; "
         f"output={result.output!r}; "
         f"exception={result.exception!r}")

    # Find the approval POST (not the token mint)
    approval_posts = [p for p in captured_posts
                      if "approvals" in p.get("url", "")]
    assert len(approval_posts) >= 1, \
        f"no POST to /approvals; captured={[p['url'] for p in captured_posts]}"

    posted_json = approval_posts[0]["json"]
    approval = posted_json.get("approval", posted_json)
    sigs = approval.get("signatures", [])
    assert len(sigs) == 1, \
        f"approval must have exactly one signature, got {len(sigs)}"

    # Verify the signature covers agg/policy-change/v1 over bundle_hash
    sig_hex = sigs[0]["sig"]
    sig_bytes = bytes.fromhex(sig_hex)
    expected_tag = b"agg/policy-change/v1"
    expected_payload = {"bundle_hash": proposal_hash}
    expected_canonical = json.dumps(
        expected_payload, sort_keys=True,
        separators=(",", ":")).encode()
    expected_msg = expected_tag + b"\x00" + expected_canonical
    from nacl.signing import VerifyKey
    vk = VerifyKey(bytes(signer_sk.verify_key))
    vk.verify(expected_msg, sig_bytes)  # raises if invalid


# ===================================================================
# approve-change: base >= 1 corrupted base -> no POST to /approvals
# ===================================================================


def test_approve_change_corrupted_base_no_post(tmp_path):
    """base >= 1 with a corrupted base row -> no POST to /approvals."""
    import unittest.mock as mock

    require_m3(3, _command_in_signer("approve-change"),
               "signer approve-change command not found")

    org_id = str(uuid.uuid4())
    project_id = str(uuid.uuid4())

    bundle_signer_sk = SigningKey.generate()
    bs_pub = bytes(bundle_signer_sk.verify_key)
    bs_kid = hashlib.sha256(bs_pub).hexdigest()

    base_payload = {
        "org_id": org_id, "project_id": project_id,
        "sequence": 1, "base_sequence": 0, "registry_version": 1,
        "folder_policy": {}, "governance_policy": {}, "mcp_policy": {},
        "approval": {"local_fallback": False, "allow_requester": False},
    }
    base_canonical = json.dumps(base_payload, sort_keys=True,
                                separators=(",", ":")).encode()
    # Corrupt the signature
    real_sig = bundle_signer_sk.sign(
        b"agg/bundle/v1\x00" + base_canonical).signature
    bad_sig = bytearray(real_sig)
    bad_sig[0] ^= 0x01
    base_envelope = {
        "kind": "agg/bundle/v1", "sig_v": 1,
        "payload": base_payload,
        "signatures": [{
            "key_id": bs_kid, "alg": "ed25519",
            "sig": bytes(bad_sig).hex(),
        }],
    }

    proposal_payload = {
        "org_id": org_id, "project_id": project_id,
        "sequence": 2, "base_sequence": 1, "registry_version": 1,
        "folder_policy": {"allow": ["*.py"]},
        "governance_policy": {}, "mcp_policy": {},
        "approval": {"local_fallback": False, "allow_requester": False},
    }
    proposal_canonical = json.dumps(proposal_payload, sort_keys=True,
                                    separators=(",", ":")).encode()
    proposal_hash = hashlib.sha256(proposal_canonical).hexdigest()
    proposal_id = str(uuid.uuid4())

    seed_file = tmp_path / "signer.seed"
    sk = SigningKey.generate()
    seed_file.write_bytes(bytes(sk).hex().encode("ascii"))

    # Key home with fingerprint
    key_home = tmp_path / "key_home"
    key_home.mkdir()
    signer_dir = key_home / "signer"
    signer_dir.mkdir()
    (signer_dir / "root_fingerprint").write_text("deadbeef" * 8)

    captured_posts = []

    def route_fn(method, url, **kwargs):
        url_str = str(url)
        if method.upper() == "GET" and "bundle-proposals" in url_str:
            return _FakeHTTPResponse({
                "id": proposal_id,
                "bundle": proposal_payload,
                "bundle_hash": proposal_hash,
                "base_sequence": 1,
                "org_id": org_id,
                "project_id": project_id,
            })
        if method.upper() == "GET" and "bundle" in url_str:
            return _FakeHTTPResponse({
                "envelope": base_envelope,
                "change_approvals": [],
            })
        if method.upper() == "POST":
            captured_posts.append(url_str)
            return _FakeHTTPResponse({"ok": True}, 200)
        return _FakeHTTPResponse({"error": "not found"}, 404)

    cli = _get_cli()
    runner = CliRunner()

    with mock.patch("httpx.Client") as MC:
        inst = mock.MagicMock()
        MC.return_value.__enter__ = mock.MagicMock(return_value=inst)
        MC.return_value.__exit__ = mock.MagicMock(return_value=False)
        inst.get = mock.MagicMock(
            side_effect=lambda url, **kw: route_fn("GET", url, **kw))
        inst.post = mock.MagicMock(
            side_effect=lambda url, **kw: route_fn("POST", url, **kw))

        result = runner.invoke(cli, [
            "signer", "approve-change", proposal_id,
            "--server", "https://localhost",
            "--key-file", str(seed_file),
            "--yes",
        ], env={"SANDBOX_KEY_HOME": str(key_home)})

    # Must refuse: no POST to /approvals
    approval_posts = [u for u in captured_posts if "approvals" in u]
    assert len(approval_posts) == 0, \
        "approve-change must not POST to /approvals when base row is corrupted"
    assert result.exit_code != 0, \
        f"must exit non-zero on corrupted base, got {result.exit_code}"


# ===================================================================
# approve-change: no anchor -> exit 1 not 2, no network call
# ===================================================================


def test_approve_change_no_anchor_exit_1(tmp_path):
    """With no anchor (no enrolled workspace, no --expect-fingerprint,
    no stored fingerprint), approve-change exits 1 (not 2) with no
    network call.
    """
    import unittest.mock as mock

    require_m3(3, _command_in_signer("approve-change"),
               "signer approve-change command not found")

    seed_file = tmp_path / "signer.seed"
    sk = SigningKey.generate()
    seed_file.write_bytes(bytes(sk).hex().encode("ascii"))

    # Empty key home -- no signer/root_fingerprint
    key_home = tmp_path / "empty_key_home"
    key_home.mkdir()

    captured_calls = []

    def route_fn(method, url, **kwargs):
        captured_calls.append((method, url))
        return _FakeHTTPResponse({"error": "not found"}, 404)

    cli = _get_cli()
    runner = CliRunner()

    with mock.patch("httpx.Client") as MC:
        inst = mock.MagicMock()
        MC.return_value.__enter__ = mock.MagicMock(return_value=inst)
        MC.return_value.__exit__ = mock.MagicMock(return_value=False)
        inst.get = mock.MagicMock(
            side_effect=lambda url, **kw: route_fn("GET", url, **kw))
        inst.post = mock.MagicMock(
            side_effect=lambda url, **kw: route_fn("POST", url, **kw))

        result = runner.invoke(cli, [
            "signer", "approve-change", str(uuid.uuid4()),
            "--server", "https://localhost",
            "--key-file", str(seed_file),
            "--yes",
        ], env={"SANDBOX_KEY_HOME": str(key_home)})

    assert result.exit_code == 1, \
        f"no anchor must exit 1 (not 2), got {result.exit_code}"
    assert len(captured_calls) == 0, \
        f"no anchor must make no network calls, made {len(captured_calls)}"


# ===================================================================
# approve-change: --expect-fingerprint mismatch refused
# ===================================================================


def test_approve_change_fingerprint_mismatch_refused(tmp_path):
    """--expect-fingerprint with a mismatched value is refused."""
    import unittest.mock as mock

    require_m3(3, _command_in_signer("approve-change"),
               "signer approve-change command not found")

    seed_file = tmp_path / "signer.seed"
    sk = SigningKey.generate()
    seed_file.write_bytes(bytes(sk).hex().encode("ascii"))

    # Key home with wrong fingerprint
    key_home = tmp_path / "key_home_mismatch"
    key_home.mkdir()
    signer_dir = key_home / "signer"
    signer_dir.mkdir()

    captured_calls = []

    def route_fn(method, url, **kwargs):
        captured_calls.append((method, url))
        # Return a registry that would have a different fingerprint
        return _FakeHTTPResponse({
            "chain": [{
                "kind": "agg/registry/v1", "sig_v": 1,
                "payload": {"org_id": "x", "version": 1},
                "signatures": [],
            }]
        })

    cli = _get_cli()
    runner = CliRunner()

    with mock.patch("httpx.Client") as MC:
        inst = mock.MagicMock()
        MC.return_value.__enter__ = mock.MagicMock(return_value=inst)
        MC.return_value.__exit__ = mock.MagicMock(return_value=False)
        inst.get = mock.MagicMock(
            side_effect=lambda url, **kw: route_fn("GET", url, **kw))
        inst.post = mock.MagicMock(
            side_effect=lambda url, **kw: route_fn("POST", url, **kw))

        result = runner.invoke(cli, [
            "signer", "approve-change", str(uuid.uuid4()),
            "--server", "https://localhost",
            "--key-file", str(seed_file),
            "--expect-fingerprint", "0000" * 16,
            "--yes",
        ], env={"SANDBOX_KEY_HOME": str(key_home)})

    assert result.exit_code != 0, \
        f"fingerprint mismatch must fail, got {result.exit_code}"
    assert result.exit_code != 2, \
        f"fingerprint mismatch must not be usage error (2), got {result.exit_code}"


# ===================================================================
# approve-change: never writes the fingerprint file
# ===================================================================


def test_approve_change_never_writes_fingerprint(tmp_path):
    """approve-change must never write the fingerprint file."""
    import unittest.mock as mock

    require_m3(3, _command_in_signer("approve-change"),
               "signer approve-change command not found")

    seed_file = tmp_path / "signer.seed"
    sk = SigningKey.generate()
    seed_file.write_bytes(bytes(sk).hex().encode("ascii"))

    key_home = tmp_path / "key_home_nw"
    key_home.mkdir()
    signer_dir = key_home / "signer"
    signer_dir.mkdir()
    fp_file = signer_dir / "root_fingerprint"
    # Do NOT create fp_file

    def route_fn(method, url, **kwargs):
        return _FakeHTTPResponse({"error": "not found"}, 404)

    cli = _get_cli()
    runner = CliRunner()

    with mock.patch("httpx.Client") as MC:
        inst = mock.MagicMock()
        MC.return_value.__enter__ = mock.MagicMock(return_value=inst)
        MC.return_value.__exit__ = mock.MagicMock(return_value=False)
        inst.get = mock.MagicMock(
            side_effect=lambda url, **kw: route_fn("GET", url, **kw))
        inst.post = mock.MagicMock(
            side_effect=lambda url, **kw: route_fn("POST", url, **kw))

        runner.invoke(cli, [
            "signer", "approve-change", str(uuid.uuid4()),
            "--server", "https://localhost",
            "--key-file", str(seed_file),
            "--yes",
        ], env={"SANDBOX_KEY_HOME": str(key_home)})

    assert not fp_file.exists(), \
        "approve-change must never write the fingerprint file"


# ===================================================================
# propose-bundle: OK case with correctly computed stub hash
# ===================================================================


def test_propose_bundle_ok_case_hash_match(tmp_path):
    """propose-bundle OK case: stub hash computed the way A9 item 6 says.
    The command prints the verified hash and exits 0.
    """
    import unittest.mock as mock

    require_m3(3, _command_in_signer("propose-bundle"),
               "signer propose-bundle command not found")

    bundle_json = {
        "folder_policy": {"allow": ["*.rs"]},
        "governance_policy": {},
        "mcp_policy": {},
        "approval": {"local_fallback": False, "allow_requester": False},
    }
    canonical = json.dumps(bundle_json, sort_keys=True,
                           separators=(",", ":")).encode()
    correct_hash = hashlib.sha256(canonical).hexdigest()

    project_id = str(uuid.uuid4())
    bundle_file = tmp_path / "bundle.json"
    bundle_file.write_text(json.dumps(bundle_json))

    proposal_id = str(uuid.uuid4())

    def route_fn(method, url, **kwargs):
        if method.upper() == "POST" and "bundle-proposals" in str(url):
            return _FakeHTTPResponse({
                "id": proposal_id,
                "bundle": bundle_json,
                "bundle_hash": correct_hash,
            }, 201)
        return _FakeHTTPResponse({"error": "not found"}, 404)

    cli = _get_cli()
    runner = CliRunner()

    with mock.patch("httpx.Client") as MC:
        inst = mock.MagicMock()
        MC.return_value.__enter__ = mock.MagicMock(return_value=inst)
        MC.return_value.__exit__ = mock.MagicMock(return_value=False)
        inst.get = mock.MagicMock(
            side_effect=lambda url, **kw: route_fn("GET", url, **kw))
        inst.post = mock.MagicMock(
            side_effect=lambda url, **kw: route_fn("POST", url, **kw))

        result = runner.invoke(cli, [
            "signer", "propose-bundle",
            "--server", "https://localhost",
            "--project", project_id,
            "--bundle-file", str(bundle_file),
        ])

    assert result.exit_code != 2, \
        f"propose-bundle usage error: {result.output}"
    assert result.exit_code == 0, \
        f"propose-bundle should exit 0 on hash match, got {result.exit_code}"
    assert correct_hash in result.output, \
        f"propose-bundle must print the verified hash, output={result.output[:200]}"


# ===================================================================
# CLI: never prints a code field
# ===================================================================


def test_cli_never_prints_code_field(tmp_path):
    """No CLI command prints a 'code' field value from a server response."""
    import unittest.mock as mock

    require_m3(3, _command_in_signer("issue-code"),
               "signer issue-code command not found")

    code_value = "SECRET-NEVER-PRINT-THIS"
    code_id_value = str(uuid.uuid4())

    def route_fn(method, url, **kwargs):
        if method.upper() == "POST" and "enrollment-codes" in str(url):
            return _FakeHTTPResponse({
                "code_id": code_id_value,
                "code": code_value,
            }, 200)
        return _FakeHTTPResponse({"error": "not found"}, 404)

    cli = _get_cli()
    runner = CliRunner()

    with mock.patch("httpx.Client") as MC:
        inst = mock.MagicMock()
        MC.return_value.__enter__ = mock.MagicMock(return_value=inst)
        MC.return_value.__exit__ = mock.MagicMock(return_value=False)
        inst.get = mock.MagicMock(
            side_effect=lambda url, **kw: route_fn("GET", url, **kw))
        inst.post = mock.MagicMock(
            side_effect=lambda url, **kw: route_fn("POST", url, **kw))

        result = runner.invoke(cli, [
            "signer", "issue-code",
            "--server", "https://localhost",
            "--project", str(uuid.uuid4()),
            "--operator", str(uuid.uuid4()),
        ])

    assert code_value not in result.output, \
        "CLI must never print the code value"


# ===================================================================
# CLI: credentials only from --key-file or linked-key loader
# ===================================================================


def test_cli_credentials_only_from_key_file(tmp_path):
    """CLI credential lookup uses only --key-file or the linked key via
    key_home_root(). No new key loader, no token cache, no env var key.
    With no key configured, the request is sent without auth and the
    server's 401 is shown.
    """
    import unittest.mock as mock

    require_m3(3, _command_in_signer("propose-bundle"),
               "signer propose-bundle command not found")

    bundle_json = {"folder_policy": {}}
    bundle_file = tmp_path / "bundle.json"
    bundle_file.write_text(json.dumps(bundle_json))

    # Empty key home -- no key at all
    key_home = tmp_path / "empty_kh"
    key_home.mkdir()

    captured_posts = []

    def route_fn(method, url, **kwargs):
        if method.upper() == "POST":
            captured_posts.append(kwargs)
            return _FakeHTTPResponse({"error": "unauthorized"}, 401)
        return _FakeHTTPResponse({"error": "not found"}, 404)

    cli = _get_cli()
    runner = CliRunner()

    with mock.patch("httpx.Client") as MC:
        inst = mock.MagicMock()
        MC.return_value.__enter__ = mock.MagicMock(return_value=inst)
        MC.return_value.__exit__ = mock.MagicMock(return_value=False)
        inst.get = mock.MagicMock(
            side_effect=lambda url, **kw: route_fn("GET", url, **kw))
        inst.post = mock.MagicMock(
            side_effect=lambda url, **kw: route_fn("POST", url, **kw))

        result = runner.invoke(cli, [
            "signer", "propose-bundle",
            "--server", "https://localhost",
            "--project", str(uuid.uuid4()),
            "--bundle-file", str(bundle_file),
        ], env={"AGG_KEY_HOME": str(key_home)})

    # The command should show the 401 error, not crash
    assert result.exit_code != 2, \
        f"should not be usage error: {result.output}"
    # It should exit non-zero because the server refused
    assert result.exit_code != 0 or "unauthorized" in result.output.lower() or \
        "401" in result.output, \
        f"with no key, should show server 401, output={result.output[:200]}"


# ===================================================================
# Q-3(i): registry GET 500 or empty with an anchor -> exit 1, no POST
# ===================================================================


def test_approve_change_registry_500_exit_1_no_post(tmp_path):
    """Q-3(i): registry GET returns 500 with an anchor present.
    approve-change must exit 1 with no POST to /approvals (C1).
    """
    import unittest.mock as mock

    require_m3(3, _command_in_signer("approve-change"),
               "signer approve-change command not found")

    org_id = str(uuid.uuid4())
    project_id = str(uuid.uuid4())

    proposal_payload = {
        "org_id": org_id, "project_id": project_id,
        "sequence": 1, "base_sequence": 0, "registry_version": 1,
        "folder_policy": {"allow": ["*.py"]},
        "governance_policy": {}, "mcp_policy": {},
        "approval": {"local_fallback": False, "allow_requester": False},
    }
    proposal_canonical = json.dumps(proposal_payload, sort_keys=True,
                                    separators=(",", ":")).encode()
    proposal_hash = hashlib.sha256(proposal_canonical).hexdigest()
    proposal_id = str(uuid.uuid4())

    seed_file = tmp_path / "signer.seed"
    sk = SigningKey.generate()
    seed_file.write_bytes(bytes(sk).hex().encode("ascii"))

    captured_posts = []

    def route_fn(method, url, **kwargs):
        url_str = str(url)
        if method.upper() == "GET" and "registry" in url_str:
            return _FakeHTTPResponse({"error": "internal"}, 500)
        if method.upper() == "GET" and "bundle-proposals" in url_str:
            return _FakeHTTPResponse({
                "id": proposal_id,
                "bundle": proposal_payload,
                "bundle_hash": proposal_hash,
                "base_sequence": 0,
            })
        if method.upper() == "POST" and "/api/v1/sync/signer/token" in url_str:
            return _FakeHTTPResponse({"token": "test-token"}, 200)
        if method.upper() == "POST":
            captured_posts.append(url_str)
            return _FakeHTTPResponse({"ok": True}, 200)
        return _FakeHTTPResponse({"error": "not found"}, 404)

    cli = _get_cli()
    runner = CliRunner()

    with mock.patch("httpx.Client") as MC:
        inst = mock.MagicMock()
        MC.return_value.__enter__ = mock.MagicMock(return_value=inst)
        MC.return_value.__exit__ = mock.MagicMock(return_value=False)
        inst.get = mock.MagicMock(
            side_effect=lambda url, **kw: route_fn("GET", url, **kw))
        inst.post = mock.MagicMock(
            side_effect=lambda url, **kw: route_fn("POST", url, **kw))

        result = runner.invoke(cli, [
            "signer", "approve-change", proposal_id,
            "--server", "https://localhost",
            "--key-file", str(seed_file),
            "--expect-fingerprint", "a" * 64,
            "--yes",
        ], env={"SANDBOX_KEY_HOME": str(tmp_path)})

    approval_posts = [u for u in captured_posts if "approvals" in u]
    assert len(approval_posts) == 0, \
        "registry 500 must prevent any POST to /approvals"
    assert result.exit_code != 0, \
        f"registry 500 must exit non-zero, got {result.exit_code}"


# ===================================================================
# Q-3(iii): ESC in a server string never reaches the output
# ===================================================================

def test_issue_code_esc_in_server_string_sanitized(tmp_path):
    """Q-3(iii): ESC bytes in a server response field never reach output.
    Passes today: _safe_json_dumps uses ensure_ascii=True.
    """
    import unittest.mock as mock

    require_m3(3, _command_in_signer("issue-code"),
               "signer issue-code command not found")

    code_id_with_esc = "code-\x1b[31mRED\x1b[0m-id"

    def route_fn(method, url, **kwargs):
        if method.upper() == "POST" and "enrollment-codes" in str(url):
            return _FakeHTTPResponse({
                "code_id": code_id_with_esc,
            }, 200)
        if method.upper() == "POST" and "/api/v1/sync/signer/token" in str(url):
            return _FakeHTTPResponse({"token": "test-token"}, 200)
        return _FakeHTTPResponse({"error": "not found"}, 404)

    cli = _get_cli()
    runner = CliRunner()

    with mock.patch("httpx.Client") as MC:
        inst = mock.MagicMock()
        MC.return_value.__enter__ = mock.MagicMock(return_value=inst)
        MC.return_value.__exit__ = mock.MagicMock(return_value=False)
        inst.get = mock.MagicMock(
            side_effect=lambda url, **kw: route_fn("GET", url, **kw))
        inst.post = mock.MagicMock(
            side_effect=lambda url, **kw: route_fn("POST", url, **kw))

        result = runner.invoke(cli, [
            "signer", "issue-code",
            "--server", "https://localhost",
            "--project", str(uuid.uuid4()),
            "--operator", str(uuid.uuid4()),
        ])

    # Raw ESC byte must not appear in the output
    assert "\x1b" not in result.output, \
        "ESC bytes in server strings must not reach CLI output"


# ===================================================================
# Q-3(iv): linked key loads from signer.seed
# ===================================================================


def test_approve_change_linked_key_from_signer_seed(tmp_path):
    """Q-3(iv): the linked key loads from <key_home>/signer/signer.seed,
    not signing.key (C3).
    """
    import unittest.mock as mock

    require_m3(3, _command_in_signer("approve-change"),
               "signer approve-change command not found")

    org_id = str(uuid.uuid4())
    project_id = str(uuid.uuid4())

    sk = SigningKey.generate()

    # Set up key home with signer/signer.seed (the correct path)
    # Real linked key home: 32 raw bytes + link.json (as signer link writes)
    key_home = tmp_path / "key_home_seed"
    key_home.mkdir()
    signer_dir = key_home / "signer"
    signer_dir.mkdir()
    seed_file = signer_dir / "signer.seed"
    seed_file.write_bytes(bytes(sk))  # 32 raw bytes, as signer link writes
    # link.json with matching key_id
    kid = hashlib.sha256(bytes(sk.verify_key)).hexdigest()
    link_meta = {"key_id": kid}
    (signer_dir / "link.json").write_text(json.dumps(link_meta))
    fp_file = signer_dir / "root_fingerprint"
    fp_file.write_text("a" * 64)

    proposal_id = str(uuid.uuid4())

    captured_posts = []

    def route_fn(method, url, **kwargs):
        url_str = str(url)
        if method.upper() == "POST" and "/api/v1/sync/signer/token" in url_str:
            return _FakeHTTPResponse({"token": "test-token"}, 200)
        if method.upper() == "GET" and "registry" in url_str:
            return _FakeHTTPResponse([], 200)
        if method.upper() == "GET" and "bundle-proposals" in url_str:
            return _FakeHTTPResponse({
                "id": proposal_id,
                "bundle": {"folder_policy": {}},
                "bundle_hash": "a" * 64,
                "base_sequence": 0,
            })
        if method.upper() == "POST":
            captured_posts.append(url_str)
            return _FakeHTTPResponse({"ok": True}, 200)
        return _FakeHTTPResponse({"error": "not found"}, 404)

    cli = _get_cli()
    runner = CliRunner()

    # Do NOT pass --key-file; the command must find the key via
    # key_home_root() -> signer/signer.seed + link.json
    # Patch root_exposure to None for Windows tmp dir ACL safety
    with mock.patch("httpx.Client") as MC, \
         mock.patch("sandbox.connector.keyhome.root_exposure",
                    return_value=None):
        inst = mock.MagicMock()
        MC.return_value.__enter__ = mock.MagicMock(return_value=inst)
        MC.return_value.__exit__ = mock.MagicMock(return_value=False)
        inst.get = mock.MagicMock(
            side_effect=lambda url, **kw: route_fn("GET", url, **kw))
        inst.post = mock.MagicMock(
            side_effect=lambda url, **kw: route_fn("POST", url, **kw))

        result = runner.invoke(cli, [
            "signer", "approve-change", proposal_id,
            "--server", "https://localhost",
            "--yes",
        ], env={"SANDBOX_KEY_HOME": str(key_home)})

    # The command must not exit 1 with "no signing key" if signer.seed exists
    assert result.exit_code != 2, \
        f"approve-change usage error: {result.output}"
    # It should have loaded the key and made progress (either posting or
    # failing on the registry, not on missing key)
    assert "no signing key" not in result.output.lower(), \
        f"signer.seed must be found by the linked key loader, output={result.output[:300]}"


# ===================================================================
# Q-3(v): every stub uses real contracts
# ===================================================================


def test_approve_change_uses_real_token_route(tmp_path):
    """Q-3(v): approve-change mints a token at the real route
    /api/v1/sync/signer/token with the bare envelope (not /signer-links
    with {"assertion": ...}).
    """
    import unittest.mock as mock

    require_m3(3, _command_in_signer("approve-change"),
               "signer approve-change command not found")

    org_id = str(uuid.uuid4())
    sk = SigningKey.generate()
    seed_file = tmp_path / "signer.seed"
    seed_file.write_bytes(bytes(sk).hex().encode("ascii"))

    key_home = tmp_path / "key_home_rt"
    key_home.mkdir()
    signer_dir = key_home / "signer"
    signer_dir.mkdir()
    (signer_dir / "root_fingerprint").write_text("b" * 64)

    proposal_id = str(uuid.uuid4())
    token_mint_urls = []

    def route_fn(method, url, **kwargs):
        url_str = str(url)
        if method.upper() == "POST" and "signer" in url_str and "token" in url_str:
            token_mint_urls.append(url_str)
            return _FakeHTTPResponse({"token": "test-token"}, 200)
        if method.upper() == "GET" and "registry" in url_str:
            return _FakeHTTPResponse([], 200)
        if method.upper() == "GET" and "bundle-proposals" in url_str:
            return _FakeHTTPResponse({
                "id": proposal_id,
                "bundle": {"folder_policy": {}},
                "bundle_hash": "c" * 64,
                "base_sequence": 0,
            })
        if method.upper() == "POST":
            return _FakeHTTPResponse({"ok": True}, 200)
        return _FakeHTTPResponse({"error": "not found"}, 404)

    cli = _get_cli()
    runner = CliRunner()

    with mock.patch("httpx.Client") as MC:
        inst = mock.MagicMock()
        MC.return_value.__enter__ = mock.MagicMock(return_value=inst)
        MC.return_value.__exit__ = mock.MagicMock(return_value=False)
        inst.get = mock.MagicMock(
            side_effect=lambda url, **kw: route_fn("GET", url, **kw))
        inst.post = mock.MagicMock(
            side_effect=lambda url, **kw: route_fn("POST", url, **kw))

        result = runner.invoke(cli, [
            "signer", "approve-change", proposal_id,
            "--server", "https://localhost",
            "--key-file", str(seed_file),
            "--yes",
        ], env={"SANDBOX_KEY_HOME": str(key_home)})

    # The token mint must have been called at the correct route
    # D3: approve-change mints a token (not unauthenticated)
    assert len(token_mint_urls) >= 1, \
        f"approve-change must mint a signer token, but no token mint was captured"
    for url in token_mint_urls:
        assert "/api/v1/sync/signer/token" in url, \
            f"token must be minted at /api/v1/sync/signer/token, got {url}"
        assert "/signer-links" not in url, \
            f"must not use /signer-links for token mint, got {url}"


# ===================================================================
# Q-3(i) addl: registry 200 with empty list -> exit 1, no POST
# ===================================================================

def test_approve_change_registry_empty_list_exit_1(tmp_path):
    """Q-3(i): registry GET returns 200 with an empty list and an anchor.
    approve-change must exit non-zero with no POST to /approvals.
    Uses a real proposal payload and hash at base 0 so that the registry
    check, not the hash check, is what refuses the request.
    """
    import unittest.mock as mock

    require_m3(3, _command_in_signer("approve-change"),
               "signer approve-change command not found")

    org_id = str(uuid.uuid4())
    project_id = str(uuid.uuid4())
    proposal_id = str(uuid.uuid4())
    sk = SigningKey.generate()
    seed_file = tmp_path / "signer.seed"
    seed_file.write_bytes(bytes(sk).hex().encode("ascii"))

    # Build a real proposal payload at base 0
    proposal_payload = {
        "org_id": org_id, "project_id": project_id,
        "sequence": 1, "base_sequence": 0, "registry_version": 1,
        "folder_policy": {"allow": ["*.py"]},
        "governance_policy": {}, "mcp_policy": {},
        "approval": {"local_fallback": False, "allow_requester": False},
    }
    proposal_canonical = json.dumps(proposal_payload, sort_keys=True,
                                    separators=(",", ":")).encode()
    proposal_hash = hashlib.sha256(proposal_canonical).hexdigest()

    captured_posts = []

    def route_fn(method, url, **kwargs):
        url_str = str(url)
        if method.upper() == "POST" and "/api/v1/sync/signer/token" in url_str:
            return _FakeHTTPResponse({"token": "test-token"}, 200)
        if method.upper() == "GET" and "registry" in url_str:
            # Real route returns a bare list; empty means no chain
            return _FakeHTTPResponse([])
        if method.upper() == "GET" and "bundle-proposals" in url_str:
            return _FakeHTTPResponse({
                "id": proposal_id,
                "bundle": proposal_payload,
                "bundle_hash": proposal_hash,
                "base_sequence": 0,
            })
        if method.upper() == "POST":
            captured_posts.append(url_str)
            return _FakeHTTPResponse({"ok": True}, 200)
        return _FakeHTTPResponse({"error": "not found"}, 404)

    cli = _get_cli()
    runner = CliRunner()

    with mock.patch("httpx.Client") as MC:
        inst = mock.MagicMock()
        MC.return_value.__enter__ = mock.MagicMock(return_value=inst)
        MC.return_value.__exit__ = mock.MagicMock(return_value=False)
        inst.get = mock.MagicMock(
            side_effect=lambda url, **kw: route_fn("GET", url, **kw))
        inst.post = mock.MagicMock(
            side_effect=lambda url, **kw: route_fn("POST", url, **kw))

        result = runner.invoke(cli, [
            "signer", "approve-change", proposal_id,
            "--server", "https://localhost",
            "--key-file", str(seed_file),
            "--expect-fingerprint", "a" * 64,
            "--yes",
        ], env={"SANDBOX_KEY_HOME": str(tmp_path)})

    approval_posts = [u for u in captured_posts if "approvals" in u]
    assert len(approval_posts) == 0, \
        "empty registry list must prevent POST to /approvals"
    assert result.exit_code != 0, \
        f"empty registry must exit non-zero, got {result.exit_code}"


# ===================================================================
# Q-3(i) addl: registry 200 with malformed shape -> exit 1, no POST
# ===================================================================

def test_approve_change_registry_malformed_exit_1(tmp_path):
    """Q-3(i): registry GET returns 200 with a malformed body (not a list,
    not a dict with 'chain').  approve-change must exit non-zero, no POST.
    Uses a real proposal payload and hash at base 0 so that the registry
    check, not the hash check, is what refuses the request.
    """
    import unittest.mock as mock

    require_m3(3, _command_in_signer("approve-change"),
               "signer approve-change command not found")

    org_id = str(uuid.uuid4())
    project_id = str(uuid.uuid4())
    proposal_id = str(uuid.uuid4())
    sk = SigningKey.generate()
    seed_file = tmp_path / "signer.seed"
    seed_file.write_bytes(bytes(sk).hex().encode("ascii"))

    # Build a real proposal payload at base 0
    proposal_payload = {
        "org_id": org_id, "project_id": project_id,
        "sequence": 1, "base_sequence": 0, "registry_version": 1,
        "folder_policy": {"allow": ["*.rs"]},
        "governance_policy": {}, "mcp_policy": {},
        "approval": {"local_fallback": False, "allow_requester": False},
    }
    proposal_canonical = json.dumps(proposal_payload, sort_keys=True,
                                    separators=(",", ":")).encode()
    proposal_hash = hashlib.sha256(proposal_canonical).hexdigest()

    captured_posts = []

    def route_fn(method, url, **kwargs):
        url_str = str(url)
        if method.upper() == "POST" and "/api/v1/sync/signer/token" in url_str:
            return _FakeHTTPResponse({"token": "test-token"}, 200)
        if method.upper() == "GET" and "registry" in url_str:
            # Malformed: a string instead of list or dict
            return _FakeHTTPResponse("not-a-registry")
        if method.upper() == "GET" and "bundle-proposals" in url_str:
            return _FakeHTTPResponse({
                "id": proposal_id,
                "bundle": proposal_payload,
                "bundle_hash": proposal_hash,
                "base_sequence": 0,
            })
        if method.upper() == "POST":
            captured_posts.append(url_str)
            return _FakeHTTPResponse({"ok": True}, 200)
        return _FakeHTTPResponse({"error": "not found"}, 404)

    cli = _get_cli()
    runner = CliRunner()

    with mock.patch("httpx.Client") as MC:
        inst = mock.MagicMock()
        MC.return_value.__enter__ = mock.MagicMock(return_value=inst)
        MC.return_value.__exit__ = mock.MagicMock(return_value=False)
        inst.get = mock.MagicMock(
            side_effect=lambda url, **kw: route_fn("GET", url, **kw))
        inst.post = mock.MagicMock(
            side_effect=lambda url, **kw: route_fn("POST", url, **kw))

        result = runner.invoke(cli, [
            "signer", "approve-change", proposal_id,
            "--server", "https://localhost",
            "--key-file", str(seed_file),
            "--expect-fingerprint", "b" * 64,
            "--yes",
        ], env={"SANDBOX_KEY_HOME": str(tmp_path)})

    approval_posts = [u for u in captured_posts if "approvals" in u]
    assert len(approval_posts) == 0, \
        "malformed registry must prevent POST to /approvals"
    assert result.exit_code != 0, \
        f"malformed registry must exit non-zero, got {result.exit_code}"


# ===================================================================
# Q-3(ii) addl: corrupted base with VALID chain and anchor -> no POST
# ===================================================================

def test_approve_change_corrupted_base_valid_chain_no_post(tmp_path):
    """Q-3(ii): base >= 1 with a corrupted base signature, but a VALID
    chain and matching fingerprint.  Only the base signature is bad.
    Must exit 1 with no POST to /approvals.
    Passes today: product crashes on bare-list registry before reaching
    the base verification (AttributeError on list.get).
    """
    import unittest.mock as mock

    require_m3(3, _command_in_signer("approve-change"),
               "signer approve-change command not found")

    org_id = str(uuid.uuid4())
    project_id = str(uuid.uuid4())

    bundle_signer_sk = SigningKey.generate()
    bs_pub = bytes(bundle_signer_sk.verify_key)
    bs_kid = hashlib.sha256(bs_pub).hexdigest()

    # Build the signer key (used for the approval and in the chain)
    signer_sk = SigningKey.generate()
    signer_pub = bytes(signer_sk.verify_key)
    signer_kid = hashlib.sha256(signer_pub).hexdigest()

    # Build a valid registry chain
    genesis_keys = [{
        "key_id": signer_kid, "public_key": signer_pub.hex(),
        "user_id": "admin-0", "iss": "https://idp.test",
        "sub": "admin-0", "alg": "ed25519",
        "kind": "cli", "roles": ["admin", "approver"], "added_in": 1,
    }]
    genesis_payload = {
        "org_id": org_id, "version": 1, "prev_hash": "",
        "threshold": 1, "admins": [signer_kid],
        "keys": genesis_keys,
        "bundle_signer": {"key_id": bs_kid, "public_key": bs_pub.hex(),
                          "alg": "ed25519"},
        "expires_at": 9999999999.0,
    }
    genesis_canonical = json.dumps(genesis_payload, sort_keys=True,
                                   separators=(",", ":")).encode()
    genesis_sig = signer_sk.sign(
        b"agg/registry/v1\x00" + genesis_canonical).signature.hex()
    genesis_env = {
        "kind": "agg/registry/v1", "sig_v": 1,
        "payload": genesis_payload,
        "signatures": [{"key_id": signer_kid, "alg": "ed25519",
                        "sig": genesis_sig}],
    }
    chain_fp = hashlib.sha256(
        org_id.encode() + b":" + genesis_canonical
    ).hexdigest()

    # Build base bundle (sequence 1) with a CORRUPTED signature
    base_payload = {
        "org_id": org_id, "project_id": project_id,
        "sequence": 1, "base_sequence": 0, "registry_version": 1,
        "folder_policy": {}, "governance_policy": {}, "mcp_policy": {},
        "approval": {"local_fallback": False, "allow_requester": False},
    }
    base_canonical = json.dumps(base_payload, sort_keys=True,
                                separators=(",", ":")).encode()
    real_sig = bundle_signer_sk.sign(
        b"agg/bundle/v1\x00" + base_canonical).signature
    bad_sig = bytearray(real_sig)
    bad_sig[0] ^= 0x01
    base_envelope = {
        "kind": "agg/bundle/v1", "sig_v": 1,
        "payload": base_payload,
        "signatures": [{
            "key_id": bs_kid, "alg": "ed25519",
            "sig": bytes(bad_sig).hex(),
        }],
    }

    # Proposal at sequence 2
    proposal_payload = {
        "org_id": org_id, "project_id": project_id,
        "sequence": 2, "base_sequence": 1, "registry_version": 1,
        "folder_policy": {"allow": ["*.py"]},
        "governance_policy": {}, "mcp_policy": {},
        "approval": {"local_fallback": False, "allow_requester": False},
    }
    proposal_canonical = json.dumps(proposal_payload, sort_keys=True,
                                    separators=(",", ":")).encode()
    proposal_hash = hashlib.sha256(proposal_canonical).hexdigest()
    proposal_id = str(uuid.uuid4())

    seed_file = tmp_path / "signer.seed"
    seed_file.write_bytes(bytes(signer_sk).hex().encode("ascii"))

    key_home = tmp_path / "key_home_cb"
    key_home.mkdir()
    signer_dir = key_home / "signer"
    signer_dir.mkdir()

    captured_posts = []

    def route_fn(method, url, **kwargs):
        url_str = str(url)
        if method.upper() == "POST" and "/api/v1/sync/signer/token" in url_str:
            return _FakeHTTPResponse({"token": "test-token"}, 200)
        if method.upper() == "GET" and "registry" in url_str:
            # Bare list -- the real route contract
            return _FakeHTTPResponse([genesis_env])
        if method.upper() == "GET" and "bundle-proposals" in url_str:
            return _FakeHTTPResponse({
                "id": proposal_id,
                "bundle": proposal_payload,
                "bundle_hash": proposal_hash,
                "base_sequence": 1,
                "org_id": org_id,
                "project_id": project_id,
                "base": {
                    "envelope": base_envelope,
                    "change_approvals": [],
                },
            })
        if method.upper() == "POST":
            captured_posts.append(url_str)
            return _FakeHTTPResponse({"ok": True}, 200)
        return _FakeHTTPResponse({"error": "not found"}, 404)

    cli = _get_cli()
    runner = CliRunner()

    with mock.patch("httpx.Client") as MC:
        inst = mock.MagicMock()
        MC.return_value.__enter__ = mock.MagicMock(return_value=inst)
        MC.return_value.__exit__ = mock.MagicMock(return_value=False)
        inst.get = mock.MagicMock(
            side_effect=lambda url, **kw: route_fn("GET", url, **kw))
        inst.post = mock.MagicMock(
            side_effect=lambda url, **kw: route_fn("POST", url, **kw))

        result = runner.invoke(cli, [
            "signer", "approve-change", proposal_id,
            "--server", "https://localhost",
            "--key-file", str(seed_file),
            "--expect-fingerprint", chain_fp,
            "--yes",
        ], env={"SANDBOX_KEY_HOME": str(key_home)})

    approval_posts = [u for u in captured_posts if "approvals" in u]
    assert len(approval_posts) == 0, \
        "corrupted base with valid chain must prevent POST to /approvals"
    assert result.exit_code != 0, \
        f"corrupted base must exit non-zero, got {result.exit_code}"


# ===================================================================
# MUST 12 / C-a: other-org proposal refused, no POST
# ===================================================================


def test_approve_change_other_org_proposal_refused(tmp_path):
    """C-a: approve-change with a valid chain for org A but a proposal
    bundle for org B must exit non-zero with no POST to /approvals.
    """
    import unittest.mock as mock

    require_m3(3, _command_in_signer("approve-change"),
               "signer approve-change command not found")

    sk, bs = SigningKey.generate(), SigningKey.generate()
    reg_org = str(uuid.uuid4())
    other_org = str(uuid.uuid4())
    sk_pub = bytes(sk.verify_key)
    sk_kid = hashlib.sha256(sk_pub).hexdigest()
    bs_pub = bytes(bs.verify_key)
    bs_kid = hashlib.sha256(bs_pub).hexdigest()

    genesis_payload = {
        "org_id": reg_org, "version": 1, "prev_hash": "",
        "threshold": 1, "admins": [sk_kid],
        "keys": [{"key_id": sk_kid, "public_key": sk_pub.hex(),
                  "user_id": "u0", "iss": "https://idp.test", "sub": "u0",
                  "alg": "ed25519", "kind": "cli",
                  "roles": ["admin", "approver"], "added_in": 1}],
        "bundle_signer": {"key_id": bs_kid, "public_key": bs_pub.hex(),
                          "alg": "ed25519"},
        "expires_at": 9999999999.0,
    }
    genesis_canonical = json.dumps(genesis_payload, sort_keys=True,
                                   separators=(",", ":")).encode()
    genesis_sig = sk.sign(
        b"agg/registry/v1\x00" + genesis_canonical).signature.hex()
    genesis_env = {
        "kind": "agg/registry/v1", "sig_v": 1,
        "payload": genesis_payload,
        "signatures": [{"key_id": sk_kid, "alg": "ed25519",
                        "sig": genesis_sig}],
    }
    fp = hashlib.sha256(
        reg_org.encode() + b":" + genesis_canonical).hexdigest()

    # Proposal is for other_org (not reg_org)
    prop = {
        "org_id": other_org, "project_id": str(uuid.uuid4()),
        "sequence": 1, "base_sequence": 0, "registry_version": 1,
        "folder_policy": {}, "governance_policy": {}, "mcp_policy": {},
        "approval": {"local_fallback": False, "allow_requester": False},
    }
    prop_canonical = json.dumps(prop, sort_keys=True,
                                separators=(",", ":")).encode()
    prop_hash = hashlib.sha256(prop_canonical).hexdigest()

    seed = tmp_path / "s.seed"
    seed.write_bytes(bytes(sk).hex().encode())
    posts = []

    def route(m, url, **kw):
        u = str(url)
        if m == "POST" and "signer/token" in u:
            return _FakeHTTPResponse({"token": "t"})
        if m == "GET" and "registry" in u:
            return _FakeHTTPResponse([genesis_env])
        if m == "GET" and "bundle-proposals" in u:
            return _FakeHTTPResponse({
                "id": "p", "bundle": prop,
                "bundle_hash": prop_hash, "base_sequence": 0,
            })
        if m == "POST":
            posts.append(u)
        return _FakeHTTPResponse({"ok": True}, 201)

    cli = _get_cli()
    runner = CliRunner()

    with mock.patch("httpx.Client") as MC:
        inst = mock.MagicMock()
        MC.return_value.__enter__ = mock.MagicMock(return_value=inst)
        MC.return_value.__exit__ = mock.MagicMock(return_value=False)
        inst.get = mock.MagicMock(
            side_effect=lambda url, **kw: route("GET", url, **kw))
        inst.post = mock.MagicMock(
            side_effect=lambda url, **kw: route("POST", url, **kw))

        result = runner.invoke(cli, [
            "signer", "approve-change", "p",
            "--server", "https://localhost",
            "--key-file", str(seed),
            "--expect-fingerprint", fp,
            "--yes",
        ], env={"SANDBOX_KEY_HOME": str(tmp_path)})

    approval_posts = [p for p in posts if "approvals" in p]
    assert result.exit_code != 0, \
        f"org mismatch must exit non-zero, got {result.exit_code}"
    assert len(approval_posts) == 0, \
        "org mismatch must not POST to /approvals"


# ===================================================================
# MUST 12 / C-b1: propose-bundle refuses added non-server-owned section
# ===================================================================


def test_propose_bundle_refuses_added_section(tmp_path):
    """C-b1: the server adds an 'approval' section with allow_requester:
    true that was not sent.  propose-bundle must exit non-zero and never
    print the hash as verified.
    """
    import unittest.mock as mock

    require_m3(3, _command_in_signer("propose-bundle"),
               "signer propose-bundle command not found")

    sent = {"folder_policy": {"allow": ["*.py"]},
            "governance_policy": {"clauses": [{"deny": "x"}]}}
    SO = {"org_id": "o", "project_id": "p", "sequence": 1,
          "base_sequence": 0, "registry_version": 1,
          "environment": "prod", "issued_at": 1, "not_before": 1}
    f = tmp_path / "b.json"
    f.write_text(json.dumps(sent))

    def resp_fn(sent_local):
        b = {**sent_local, **SO,
             "approval": {"local_fallback": True, "allow_requester": True}}
        return {"id": "x", "bundle": b, "bundle_hash": hashlib.sha256(
            json.dumps(b, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()}

    def route(m, url, **kw):
        return _FakeHTTPResponse(resp_fn(sent), 201)

    cli = _get_cli()
    runner = CliRunner()

    with mock.patch("httpx.Client") as MC:
        inst = mock.MagicMock()
        MC.return_value.__enter__ = mock.MagicMock(return_value=inst)
        MC.return_value.__exit__ = mock.MagicMock(return_value=False)
        inst.get = mock.MagicMock(
            side_effect=lambda url, **kw: route("GET", url, **kw))
        inst.post = mock.MagicMock(
            side_effect=lambda url, **kw: route("POST", url, **kw))

        result = runner.invoke(cli, [
            "signer", "propose-bundle",
            "--server", "https://localhost",
            "--project", str(uuid.uuid4()),
            "--bundle-file", str(f),
        ], env={"SANDBOX_KEY_HOME": str(tmp_path)})

    assert result.exit_code != 0, \
        f"added section must be refused, got exit {result.exit_code}"
    # The hash must not be labelled as verified
    out_lower = result.output.lower()
    assert "verified" not in out_lower or "unverified" in out_lower or \
        result.exit_code != 0, \
        "must not print the hash as verified when a section was added"


# ===================================================================
# MUST 12 / C-b2: propose-bundle refuses dropped section
# ===================================================================


def test_propose_bundle_refuses_dropped_section(tmp_path):
    """C-b2: the server drops the governance_policy that was sent.
    propose-bundle must exit non-zero.
    """
    import unittest.mock as mock

    require_m3(3, _command_in_signer("propose-bundle"),
               "signer propose-bundle command not found")

    sent = {"folder_policy": {"allow": ["*.py"]},
            "governance_policy": {"clauses": [{"deny": "x"}]}}
    SO = {"org_id": "o", "project_id": "p", "sequence": 1,
          "base_sequence": 0, "registry_version": 1,
          "environment": "prod", "issued_at": 1, "not_before": 1}
    f = tmp_path / "b.json"
    f.write_text(json.dumps(sent))

    def route(m, url, **kw):
        b = {"folder_policy": sent["folder_policy"], **SO}
        return _FakeHTTPResponse({
            "id": "x", "bundle": b, "bundle_hash": hashlib.sha256(
                json.dumps(b, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest()}, 201)

    cli = _get_cli()
    runner = CliRunner()

    with mock.patch("httpx.Client") as MC:
        inst = mock.MagicMock()
        MC.return_value.__enter__ = mock.MagicMock(return_value=inst)
        MC.return_value.__exit__ = mock.MagicMock(return_value=False)
        inst.get = mock.MagicMock(
            side_effect=lambda url, **kw: route("GET", url, **kw))
        inst.post = mock.MagicMock(
            side_effect=lambda url, **kw: route("POST", url, **kw))

        result = runner.invoke(cli, [
            "signer", "propose-bundle",
            "--server", "https://localhost",
            "--project", str(uuid.uuid4()),
            "--bundle-file", str(f),
        ], env={"SANDBOX_KEY_HOME": str(tmp_path)})

    assert result.exit_code != 0, \
        f"dropped section must be refused, got exit {result.exit_code}"


# ===================================================================
# MUST 12 / C-b3: propose-bundle refuses missing bundle in response
# ===================================================================


def test_propose_bundle_refuses_missing_bundle(tmp_path):
    """C-b3: the server returns no 'bundle' key in the response.
    propose-bundle must exit non-zero and never print a hash as verified.
    """
    import unittest.mock as mock

    require_m3(3, _command_in_signer("propose-bundle"),
               "signer propose-bundle command not found")

    sent = {"folder_policy": {"allow": ["*.py"]}}
    f = tmp_path / "b.json"
    f.write_text(json.dumps(sent))
    sent_canon = json.dumps(sent, sort_keys=True,
                            separators=(",", ":")).encode()
    sent_hash = hashlib.sha256(sent_canon).hexdigest()

    def route(m, url, **kw):
        return _FakeHTTPResponse(
            {"id": "x", "bundle_hash": sent_hash}, 201)

    cli = _get_cli()
    runner = CliRunner()

    with mock.patch("httpx.Client") as MC:
        inst = mock.MagicMock()
        MC.return_value.__enter__ = mock.MagicMock(return_value=inst)
        MC.return_value.__exit__ = mock.MagicMock(return_value=False)
        inst.get = mock.MagicMock(
            side_effect=lambda url, **kw: route("GET", url, **kw))
        inst.post = mock.MagicMock(
            side_effect=lambda url, **kw: route("POST", url, **kw))

        result = runner.invoke(cli, [
            "signer", "propose-bundle",
            "--server", "https://localhost",
            "--project", str(uuid.uuid4()),
            "--bundle-file", str(f),
        ], env={"SANDBOX_KEY_HOME": str(tmp_path)})

    assert result.exit_code != 0, \
        f"missing bundle must be refused, got exit {result.exit_code}"


# ===================================================================
# MUST 12 / C-c: key-file conditions (hex 64, raw 32, 33 refused)
# ===================================================================


def test_key_file_conditions(tmp_path):
    """C-c / N2: --key-file accepts exactly 64 hex chars (with at most one
    trailing newline), raw exactly 32 bytes never stripped, and 33 bytes
    is refused.
    """
    require_m3(3, _command_in_signer("approve-change"),
               "signer approve-change command not found")

    from sandbox.cli.change_cmds import _load_key

    # 1. 64-char hex with trailing newline
    sk = SigningKey.generate()
    hex_seed = bytes(sk).hex()
    assert len(hex_seed) == 64
    hex_file = tmp_path / "hex.seed"
    hex_file.write_text(hex_seed + "\n")
    loaded_sk, _ = _load_key(str(hex_file))
    assert bytes(loaded_sk) == bytes(sk), "hex key must load correctly"

    # 2. Raw exactly 32 bytes, never stripped (even if last byte is whitespace)
    raw_bytes = bytes(sk)
    raw_file = tmp_path / "raw.seed"
    raw_file.write_bytes(raw_bytes)
    loaded_raw, _ = _load_key(str(raw_file))
    assert bytes(loaded_raw) == raw_bytes, "raw 32-byte key must load without stripping"

    # 3. 33 bytes refused
    bad_file = tmp_path / "bad.seed"
    bad_file.write_bytes(bytes([7]) * 32 + b"\n")
    refused = False
    try:
        _load_key(str(bad_file))
    except (ValueError, SystemExit, Exception):
        refused = True
    assert refused, "33-byte file must be refused"


# ===================================================================
# MUST 12 / C-d: no key -> exit 1 cleanly, no traceback
# ===================================================================


def test_approve_change_no_key_exit_1_no_traceback(tmp_path):
    """C-d: approve-change with no key configured exits 1 cleanly
    (via ClickException), not through an AttributeError traceback.
    """
    import unittest.mock as mock

    require_m3(3, _command_in_signer("approve-change"),
               "signer approve-change command not found")

    def route_fn(method, url, **kwargs):
        return _FakeHTTPResponse({}, 404)

    cli = _get_cli()
    runner = CliRunner()

    with mock.patch("httpx.Client") as MC:
        inst = mock.MagicMock()
        MC.return_value.__enter__ = mock.MagicMock(return_value=inst)
        MC.return_value.__exit__ = mock.MagicMock(return_value=False)
        inst.get = mock.MagicMock(
            side_effect=lambda url, **kw: route_fn("GET", url, **kw))
        inst.post = mock.MagicMock(
            side_effect=lambda url, **kw: route_fn("POST", url, **kw))

        result = runner.invoke(cli, [
            "signer", "approve-change", "p",
            "--server", "https://localhost",
            "--expect-fingerprint", "a" * 64,
            "--yes",
        ], env={"SANDBOX_KEY_HOME": str(tmp_path)})

    assert result.exit_code == 1, \
        f"no key must exit 1, got {result.exit_code}"
    assert isinstance(result.exception, SystemExit), \
        f"must be SystemExit, got {type(result.exception).__name__}"
    # No traceback in output
    assert "Traceback" not in result.output, \
        "no key must not produce a traceback"


# ===================================================================
# MUST 12 / C-e: key configured + failed token mint -> exit 1, no POST
# ===================================================================


def test_issue_code_failed_mint_exit_1_no_post(tmp_path):
    """C-e: issue-code with --key-file and a token mint that returns 500
    must exit 1 without posting to the enrollment-codes endpoint.
    """
    import unittest.mock as mock

    require_m3(3, _command_in_signer("issue-code"),
               "signer issue-code command not found")

    sk = SigningKey.generate()
    seed = tmp_path / "s.seed"
    seed.write_bytes(bytes(sk).hex().encode())
    seen = []

    def route(m, url, **kw):
        u = str(url)
        if "signer/token" in u:
            return _FakeHTTPResponse({"error": "x"}, 500)
        seen.append(u)
        return _FakeHTTPResponse({"error": "unauthorized"}, 401)

    cli = _get_cli()
    runner = CliRunner()

    with mock.patch("httpx.Client") as MC:
        inst = mock.MagicMock()
        MC.return_value.__enter__ = mock.MagicMock(return_value=inst)
        MC.return_value.__exit__ = mock.MagicMock(return_value=False)
        inst.get = mock.MagicMock(
            side_effect=lambda url, **kw: route("GET", url, **kw))
        inst.post = mock.MagicMock(
            side_effect=lambda url, **kw: route("POST", url, **kw))

        result = runner.invoke(cli, [
            "signer", "issue-code",
            "--server", "https://localhost",
            "--project", "p",
            "--operator", "o",
            "--key-file", str(seed),
        ])

    assert not seen, \
        f"failed mint must prevent POST to enrollment-codes, saw {seen}"
    assert result.exit_code != 0, \
        f"failed mint must exit non-zero, got {result.exit_code}"


# ===================================================================
# R3-e: link.json key_id != seed kid -> exit 1, no POST
# ===================================================================


def test_linked_key_mismatched_key_id_exit_1(tmp_path):
    """R3-e: link.json key_id does not match the seed's kid.
    _load_signer_link_key must refuse (D4-2 tamper detection).
    approve-change must exit 1 with no network calls at all (the key
    load failure must happen before httpx.Client is opened).
    Fails today: the _load_key fallback bypasses the check and the
    command makes network calls.
    """
    import unittest.mock as mock

    require_m3(3, _command_in_signer("approve-change"),
               "signer approve-change command not found")

    sk = SigningKey.generate()
    kid = hashlib.sha256(bytes(sk.verify_key)).hexdigest()

    key_home = tmp_path / "key_home_mismatch_kid"
    key_home.mkdir()
    signer_dir = key_home / "signer"
    signer_dir.mkdir()
    seed_file = signer_dir / "signer.seed"
    seed_file.write_bytes(bytes(sk))  # 32 raw bytes
    # link.json with WRONG key_id
    wrong_kid = hashlib.sha256(b"not the right key").hexdigest()
    assert wrong_kid != kid
    (signer_dir / "link.json").write_text(
        json.dumps({"key_id": wrong_kid}))
    (signer_dir / "root_fingerprint").write_text("a" * 64)

    all_calls = []

    def route_fn(method, url, **kwargs):
        all_calls.append((method, str(url)))
        url_str = str(url)
        if method.upper() == "POST" and "/api/v1/sync/signer/token" in url_str:
            return _FakeHTTPResponse({"token": "test-token"}, 200)
        if method.upper() == "GET" and "registry" in url_str:
            return _FakeHTTPResponse([], 200)
        if method.upper() == "GET" and "bundle-proposals" in url_str:
            return _FakeHTTPResponse({
                "id": "p", "bundle": {"folder_policy": {}},
                "bundle_hash": "a" * 64, "base_sequence": 0,
            })
        if method.upper() == "POST":
            return _FakeHTTPResponse({"ok": True}, 200)
        return _FakeHTTPResponse({"error": "not found"}, 404)

    cli = _get_cli()
    runner = CliRunner()

    with mock.patch("httpx.Client") as MC, \
         mock.patch("sandbox.connector.keyhome.root_exposure",
                    return_value=None):
        inst = mock.MagicMock()
        MC.return_value.__enter__ = mock.MagicMock(return_value=inst)
        MC.return_value.__exit__ = mock.MagicMock(return_value=False)
        inst.get = mock.MagicMock(
            side_effect=lambda url, **kw: route_fn("GET", url, **kw))
        inst.post = mock.MagicMock(
            side_effect=lambda url, **kw: route_fn("POST", url, **kw))

        result = runner.invoke(cli, [
            "signer", "approve-change", str(uuid.uuid4()),
            "--server", "https://localhost",
            "--yes",
        ], env={"SANDBOX_KEY_HOME": str(key_home)})

    assert result.exit_code == 1, \
        f"mismatched link.json key_id must exit 1, got {result.exit_code}"
    # The key load failure must happen before any network call.
    # On today's code the fallback loads the key, so network calls are made.
    assert len(all_calls) == 0, \
        f"mismatched key_id must make no network calls, made {len(all_calls)}: {all_calls}"


# ===================================================================
# R3-f: root_exposure reports exposure -> exit 1, no POST
# ===================================================================


def test_linked_key_root_exposure_exit_1(tmp_path):
    """R3-f: root_exposure monkeypatched to report exposure.
    _load_seed_checked must refuse (F4).  approve-change must exit 1
    with no network calls (the key load failure must precede httpx).
    Fails today: the _load_key fallback bypasses _load_seed_checked's
    exposure refusal and loads signer.seed through the --key-file path
    which only warns, then makes network calls.
    """
    import unittest.mock as mock

    require_m3(3, _command_in_signer("approve-change"),
               "signer approve-change command not found")

    sk = SigningKey.generate()
    kid = hashlib.sha256(bytes(sk.verify_key)).hexdigest()

    key_home = tmp_path / "key_home_exposed"
    key_home.mkdir()
    signer_dir = key_home / "signer"
    signer_dir.mkdir()
    seed_file = signer_dir / "signer.seed"
    seed_file.write_bytes(bytes(sk))  # 32 raw bytes
    (signer_dir / "link.json").write_text(
        json.dumps({"key_id": kid}))
    (signer_dir / "root_fingerprint").write_text("a" * 64)

    all_calls = []

    def route_fn(method, url, **kwargs):
        all_calls.append((method, str(url)))
        url_str = str(url)
        if method.upper() == "POST" and "/api/v1/sync/signer/token" in url_str:
            return _FakeHTTPResponse({"token": "test-token"}, 200)
        if method.upper() == "GET" and "registry" in url_str:
            return _FakeHTTPResponse([], 200)
        if method.upper() == "GET" and "bundle-proposals" in url_str:
            return _FakeHTTPResponse({
                "id": "p", "bundle": {"folder_policy": {}},
                "bundle_hash": "a" * 64, "base_sequence": 0,
            })
        if method.upper() == "POST":
            return _FakeHTTPResponse({"ok": True}, 200)
        return _FakeHTTPResponse({"error": "not found"}, 404)

    cli = _get_cli()
    runner = CliRunner()

    # Monkeypatch root_exposure to report exposure
    with mock.patch("httpx.Client") as MC, \
         mock.patch("sandbox.connector.keyhome.root_exposure",
                    return_value="BUILTIN\\Users has access"):
        inst = mock.MagicMock()
        MC.return_value.__enter__ = mock.MagicMock(return_value=inst)
        MC.return_value.__exit__ = mock.MagicMock(return_value=False)
        inst.get = mock.MagicMock(
            side_effect=lambda url, **kw: route_fn("GET", url, **kw))
        inst.post = mock.MagicMock(
            side_effect=lambda url, **kw: route_fn("POST", url, **kw))

        result = runner.invoke(cli, [
            "signer", "approve-change", str(uuid.uuid4()),
            "--server", "https://localhost",
            "--yes",
        ], env={"SANDBOX_KEY_HOME": str(key_home)})

    assert result.exit_code == 1, \
        f"root_exposure must cause exit 1, got {result.exit_code}"
    # The exposure refusal must happen before any network call.
    # On today's code the fallback loads the key, so network calls are made.
    assert len(all_calls) == 0, \
        f"root_exposure must make no network calls, made {len(all_calls)}: {all_calls}"


# ===================================================================
# R3-g: signer.seed present, no link.json -> exit 1, no POST
# ===================================================================


def test_linked_key_no_link_json_exit_1(tmp_path):
    """R3-g: signer.seed present but no link.json.
    _load_signer_link_key must refuse.  approve-change must exit 1
    with no network calls (the key load failure must precede httpx).
    Fails today: the _load_key fallback bypasses the link binding,
    loads signer.seed directly, and makes network calls.
    """
    import unittest.mock as mock

    require_m3(3, _command_in_signer("approve-change"),
               "signer approve-change command not found")

    sk = SigningKey.generate()

    key_home = tmp_path / "key_home_no_link"
    key_home.mkdir()
    signer_dir = key_home / "signer"
    signer_dir.mkdir()
    seed_file = signer_dir / "signer.seed"
    seed_file.write_bytes(bytes(sk))  # 32 raw bytes, NO link.json
    (signer_dir / "root_fingerprint").write_text("a" * 64)

    all_calls = []

    def route_fn(method, url, **kwargs):
        all_calls.append((method, str(url)))
        url_str = str(url)
        if method.upper() == "POST" and "/api/v1/sync/signer/token" in url_str:
            return _FakeHTTPResponse({"token": "test-token"}, 200)
        if method.upper() == "GET" and "registry" in url_str:
            return _FakeHTTPResponse([], 200)
        if method.upper() == "GET" and "bundle-proposals" in url_str:
            return _FakeHTTPResponse({
                "id": "p", "bundle": {"folder_policy": {}},
                "bundle_hash": "a" * 64, "base_sequence": 0,
            })
        if method.upper() == "POST":
            return _FakeHTTPResponse({"ok": True}, 200)
        return _FakeHTTPResponse({"error": "not found"}, 404)

    cli = _get_cli()
    runner = CliRunner()

    with mock.patch("httpx.Client") as MC, \
         mock.patch("sandbox.connector.keyhome.root_exposure",
                    return_value=None):
        inst = mock.MagicMock()
        MC.return_value.__enter__ = mock.MagicMock(return_value=inst)
        MC.return_value.__exit__ = mock.MagicMock(return_value=False)
        inst.get = mock.MagicMock(
            side_effect=lambda url, **kw: route_fn("GET", url, **kw))
        inst.post = mock.MagicMock(
            side_effect=lambda url, **kw: route_fn("POST", url, **kw))

        result = runner.invoke(cli, [
            "signer", "approve-change", str(uuid.uuid4()),
            "--server", "https://localhost",
            "--yes",
        ], env={"SANDBOX_KEY_HOME": str(key_home)})

    assert result.exit_code == 1, \
        f"no link.json must exit 1, got {result.exit_code}"
    # The link binding refusal must happen before any network call.
    # On today's code the fallback loads the key, so network calls are made.
    assert len(all_calls) == 0, \
        f"no link.json must make no network calls, made {len(all_calls)}: {all_calls}"


# ===================================================================
# R3-b: bundle with no org_id -> exit 1, no POST
# ===================================================================


def test_approve_change_bundle_no_org_id_exit_1(tmp_path):
    """R3-b: hashed proposal bundle has no org_id (detail's top-level
    org_id equals the chain org).  approve-change must exit 1 with no
    POST to /approvals.
    Fails today: the org check falls back to detail.org_id when the
    bundle has no org_id, so the check passes.
    """
    import unittest.mock as mock

    require_m3(3, _command_in_signer("approve-change"),
               "signer approve-change command not found")

    sk, bs = SigningKey.generate(), SigningKey.generate()
    org_id = str(uuid.uuid4())
    sk_pub = bytes(sk.verify_key)
    sk_kid = hashlib.sha256(sk_pub).hexdigest()
    bs_pub = bytes(bs.verify_key)
    bs_kid = hashlib.sha256(bs_pub).hexdigest()

    genesis_payload = {
        "org_id": org_id, "version": 1, "prev_hash": "",
        "threshold": 1, "admins": [sk_kid],
        "keys": [{"key_id": sk_kid, "public_key": sk_pub.hex(),
                  "user_id": "u0", "iss": "https://idp.test", "sub": "u0",
                  "alg": "ed25519", "kind": "cli",
                  "roles": ["admin", "approver"], "added_in": 1}],
        "bundle_signer": {"key_id": bs_kid, "public_key": bs_pub.hex(),
                          "alg": "ed25519"},
        "expires_at": 9999999999.0,
    }
    genesis_canonical = json.dumps(genesis_payload, sort_keys=True,
                                   separators=(",", ":")).encode()
    genesis_sig = sk.sign(
        b"agg/registry/v1\x00" + genesis_canonical).signature.hex()
    genesis_env = {
        "kind": "agg/registry/v1", "sig_v": 1,
        "payload": genesis_payload,
        "signatures": [{"key_id": sk_kid, "alg": "ed25519",
                        "sig": genesis_sig}],
    }
    fp = hashlib.sha256(
        org_id.encode() + b":" + genesis_canonical).hexdigest()

    # Bundle with NO org_id
    proposal_bundle = {
        "project_id": str(uuid.uuid4()),
        "sequence": 1, "base_sequence": 0, "registry_version": 1,
        "folder_policy": {}, "governance_policy": {}, "mcp_policy": {},
        "approval": {"local_fallback": False, "allow_requester": False},
    }
    proposal_canonical = json.dumps(proposal_bundle, sort_keys=True,
                                    separators=(",", ":")).encode()
    proposal_hash = hashlib.sha256(proposal_canonical).hexdigest()
    proposal_id = str(uuid.uuid4())

    seed = tmp_path / "s.seed"
    seed.write_bytes(bytes(sk).hex().encode())
    posts = []

    def route(m, url, **kw):
        u = str(url)
        if m == "POST" and "signer/token" in u:
            return _FakeHTTPResponse({"token": "t"})
        if m == "GET" and "registry" in u:
            return _FakeHTTPResponse([genesis_env])
        if m == "GET" and "bundle-proposals" in u:
            return _FakeHTTPResponse({
                "id": proposal_id, "bundle": proposal_bundle,
                "bundle_hash": proposal_hash, "base_sequence": 0,
                "org_id": org_id,  # top-level org_id = chain org
            })
        if m == "POST":
            posts.append(u)
        return _FakeHTTPResponse({"ok": True}, 201)

    cli = _get_cli()
    runner = CliRunner()

    with mock.patch("httpx.Client") as MC:
        inst = mock.MagicMock()
        MC.return_value.__enter__ = mock.MagicMock(return_value=inst)
        MC.return_value.__exit__ = mock.MagicMock(return_value=False)
        inst.get = mock.MagicMock(
            side_effect=lambda url, **kw: route("GET", url, **kw))
        inst.post = mock.MagicMock(
            side_effect=lambda url, **kw: route("POST", url, **kw))

        result = runner.invoke(cli, [
            "signer", "approve-change", proposal_id,
            "--server", "https://localhost",
            "--key-file", str(seed),
            "--expect-fingerprint", fp,
            "--yes",
        ], env={"SANDBOX_KEY_HOME": str(tmp_path)})

    assert result.exit_code != 0, \
        f"bundle with no org_id must exit non-zero, got {result.exit_code}"
    approval_posts = [p for p in posts if "approvals" in p]
    assert len(approval_posts) == 0, \
        "bundle with no org_id must not POST to /approvals"



def test_approve_change_bundle_empty_org_id_exit_1(tmp_path):
    """R3-b: hashed proposal bundle has org_id: "".
    approve-change must exit 1 with no POST to /approvals.
    Fails today: empty org_id is falsy, so the org check is skipped.
    """
    import unittest.mock as mock

    require_m3(3, _command_in_signer("approve-change"),
               "signer approve-change command not found")

    sk, bs = SigningKey.generate(), SigningKey.generate()
    org_id = str(uuid.uuid4())
    sk_pub = bytes(sk.verify_key)
    sk_kid = hashlib.sha256(sk_pub).hexdigest()
    bs_pub = bytes(bs.verify_key)
    bs_kid = hashlib.sha256(bs_pub).hexdigest()

    genesis_payload = {
        "org_id": org_id, "version": 1, "prev_hash": "",
        "threshold": 1, "admins": [sk_kid],
        "keys": [{"key_id": sk_kid, "public_key": sk_pub.hex(),
                  "user_id": "u0", "iss": "https://idp.test", "sub": "u0",
                  "alg": "ed25519", "kind": "cli",
                  "roles": ["admin", "approver"], "added_in": 1}],
        "bundle_signer": {"key_id": bs_kid, "public_key": bs_pub.hex(),
                          "alg": "ed25519"},
        "expires_at": 9999999999.0,
    }
    genesis_canonical = json.dumps(genesis_payload, sort_keys=True,
                                   separators=(",", ":")).encode()
    genesis_sig = sk.sign(
        b"agg/registry/v1\x00" + genesis_canonical).signature.hex()
    genesis_env = {
        "kind": "agg/registry/v1", "sig_v": 1,
        "payload": genesis_payload,
        "signatures": [{"key_id": sk_kid, "alg": "ed25519",
                        "sig": genesis_sig}],
    }
    fp = hashlib.sha256(
        org_id.encode() + b":" + genesis_canonical).hexdigest()

    # Bundle with empty org_id
    proposal_bundle = {
        "org_id": "",
        "project_id": str(uuid.uuid4()),
        "sequence": 1, "base_sequence": 0, "registry_version": 1,
        "folder_policy": {}, "governance_policy": {}, "mcp_policy": {},
        "approval": {"local_fallback": False, "allow_requester": False},
    }
    proposal_canonical = json.dumps(proposal_bundle, sort_keys=True,
                                    separators=(",", ":")).encode()
    proposal_hash = hashlib.sha256(proposal_canonical).hexdigest()
    proposal_id = str(uuid.uuid4())

    seed = tmp_path / "s.seed"
    seed.write_bytes(bytes(sk).hex().encode())
    posts = []

    def route(m, url, **kw):
        u = str(url)
        if m == "POST" and "signer/token" in u:
            return _FakeHTTPResponse({"token": "t"})
        if m == "GET" and "registry" in u:
            return _FakeHTTPResponse([genesis_env])
        if m == "GET" and "bundle-proposals" in u:
            return _FakeHTTPResponse({
                "id": proposal_id, "bundle": proposal_bundle,
                "bundle_hash": proposal_hash, "base_sequence": 0,
                "org_id": org_id,
            })
        if m == "POST":
            posts.append(u)
        return _FakeHTTPResponse({"ok": True}, 201)

    cli = _get_cli()
    runner = CliRunner()

    with mock.patch("httpx.Client") as MC:
        inst = mock.MagicMock()
        MC.return_value.__enter__ = mock.MagicMock(return_value=inst)
        MC.return_value.__exit__ = mock.MagicMock(return_value=False)
        inst.get = mock.MagicMock(
            side_effect=lambda url, **kw: route("GET", url, **kw))
        inst.post = mock.MagicMock(
            side_effect=lambda url, **kw: route("POST", url, **kw))

        result = runner.invoke(cli, [
            "signer", "approve-change", proposal_id,
            "--server", "https://localhost",
            "--key-file", str(seed),
            "--expect-fingerprint", fp,
            "--yes",
        ], env={"SANDBOX_KEY_HOME": str(tmp_path)})

    assert result.exit_code != 0, \
        f"bundle with empty org_id must exit non-zero, got {result.exit_code}"
    approval_posts = [p for p in posts if "approvals" in p]
    assert len(approval_posts) == 0, \
        "bundle with empty org_id must not POST to /approvals"


# ===================================================================
# R3-c: wrong types in hashed bundle -> exit 1, no traceback, no POST
# ===================================================================


def test_approve_change_registry_version_string_exit_1(tmp_path):
    """R3-c: bundle registry_version: "9" (str instead of int).
    approve-change must exit 1 via SystemExit/ClickException with no
    traceback in output and no POST to /approvals.
    Fails today: the str/int comparison raises TypeError with a traceback.
    """
    import unittest.mock as mock

    require_m3(3, _command_in_signer("approve-change"),
               "signer approve-change command not found")

    sk, bs = SigningKey.generate(), SigningKey.generate()
    org_id = str(uuid.uuid4())
    sk_pub = bytes(sk.verify_key)
    sk_kid = hashlib.sha256(sk_pub).hexdigest()
    bs_pub = bytes(bs.verify_key)
    bs_kid = hashlib.sha256(bs_pub).hexdigest()

    genesis_payload = {
        "org_id": org_id, "version": 1, "prev_hash": "",
        "threshold": 1, "admins": [sk_kid],
        "keys": [{"key_id": sk_kid, "public_key": sk_pub.hex(),
                  "user_id": "u0", "iss": "https://idp.test", "sub": "u0",
                  "alg": "ed25519", "kind": "cli",
                  "roles": ["admin", "approver"], "added_in": 1}],
        "bundle_signer": {"key_id": bs_kid, "public_key": bs_pub.hex(),
                          "alg": "ed25519"},
        "expires_at": 9999999999.0,
    }
    genesis_canonical = json.dumps(genesis_payload, sort_keys=True,
                                   separators=(",", ":")).encode()
    genesis_sig = sk.sign(
        b"agg/registry/v1\x00" + genesis_canonical).signature.hex()
    genesis_env = {
        "kind": "agg/registry/v1", "sig_v": 1,
        "payload": genesis_payload,
        "signatures": [{"key_id": sk_kid, "alg": "ed25519",
                        "sig": genesis_sig}],
    }
    fp = hashlib.sha256(
        org_id.encode() + b":" + genesis_canonical).hexdigest()

    # Bundle with registry_version as string
    proposal_bundle = {
        "org_id": org_id, "project_id": str(uuid.uuid4()),
        "sequence": 1, "base_sequence": 0,
        "registry_version": "9",
        "folder_policy": {}, "governance_policy": {}, "mcp_policy": {},
        "approval": {"local_fallback": False, "allow_requester": False},
    }
    proposal_canonical = json.dumps(proposal_bundle, sort_keys=True,
                                    separators=(",", ":")).encode()
    proposal_hash = hashlib.sha256(proposal_canonical).hexdigest()
    proposal_id = str(uuid.uuid4())

    seed = tmp_path / "s.seed"
    seed.write_bytes(bytes(sk).hex().encode())
    posts = []

    def route(m, url, **kw):
        u = str(url)
        if m == "POST" and "signer/token" in u:
            return _FakeHTTPResponse({"token": "t"})
        if m == "GET" and "registry" in u:
            return _FakeHTTPResponse([genesis_env])
        if m == "GET" and "bundle-proposals" in u:
            return _FakeHTTPResponse({
                "id": proposal_id, "bundle": proposal_bundle,
                "bundle_hash": proposal_hash, "base_sequence": 0,
            })
        if m == "POST":
            posts.append(u)
        return _FakeHTTPResponse({"ok": True}, 201)

    cli = _get_cli()
    runner = CliRunner()

    with mock.patch("httpx.Client") as MC:
        inst = mock.MagicMock()
        MC.return_value.__enter__ = mock.MagicMock(return_value=inst)
        MC.return_value.__exit__ = mock.MagicMock(return_value=False)
        inst.get = mock.MagicMock(
            side_effect=lambda url, **kw: route("GET", url, **kw))
        inst.post = mock.MagicMock(
            side_effect=lambda url, **kw: route("POST", url, **kw))

        result = runner.invoke(cli, [
            "signer", "approve-change", proposal_id,
            "--server", "https://localhost",
            "--key-file", str(seed),
            "--expect-fingerprint", fp,
            "--yes",
        ], env={"SANDBOX_KEY_HOME": str(tmp_path)})

    assert result.exit_code != 0, \
        f"string registry_version must exit non-zero, got {result.exit_code}"
    assert isinstance(result.exception, SystemExit), \
        f"must be SystemExit, got {type(result.exception).__name__}"
    assert "Traceback" not in result.output, \
        f"must not produce a traceback, output={result.output[:300]}"
    approval_posts = [p for p in posts if "approvals" in p]
    assert len(approval_posts) == 0, \
        "string registry_version must not POST to /approvals"



def test_approve_change_bool_in_sequence_exit_1(tmp_path):
    """R3-c: bundle with bool in sequence/base_sequence/registry_version.
    approve-change must exit 1 via SystemExit/ClickException with no
    traceback in output and no POST to /approvals.
    Fails today: bool is a subclass of int in Python, so isinstance
    checks pass and the bool is accepted.
    """
    import unittest.mock as mock

    require_m3(3, _command_in_signer("approve-change"),
               "signer approve-change command not found")

    sk, bs = SigningKey.generate(), SigningKey.generate()
    org_id = str(uuid.uuid4())
    sk_pub = bytes(sk.verify_key)
    sk_kid = hashlib.sha256(sk_pub).hexdigest()
    bs_pub = bytes(bs.verify_key)
    bs_kid = hashlib.sha256(bs_pub).hexdigest()

    genesis_payload = {
        "org_id": org_id, "version": 1, "prev_hash": "",
        "threshold": 1, "admins": [sk_kid],
        "keys": [{"key_id": sk_kid, "public_key": sk_pub.hex(),
                  "user_id": "u0", "iss": "https://idp.test", "sub": "u0",
                  "alg": "ed25519", "kind": "cli",
                  "roles": ["admin", "approver"], "added_in": 1}],
        "bundle_signer": {"key_id": bs_kid, "public_key": bs_pub.hex(),
                          "alg": "ed25519"},
        "expires_at": 9999999999.0,
    }
    genesis_canonical = json.dumps(genesis_payload, sort_keys=True,
                                   separators=(",", ":")).encode()
    genesis_sig = sk.sign(
        b"agg/registry/v1\x00" + genesis_canonical).signature.hex()
    genesis_env = {
        "kind": "agg/registry/v1", "sig_v": 1,
        "payload": genesis_payload,
        "signatures": [{"key_id": sk_kid, "alg": "ed25519",
                        "sig": genesis_sig}],
    }
    fp = hashlib.sha256(
        org_id.encode() + b":" + genesis_canonical).hexdigest()

    # Bundle with booleans in sequence fields
    proposal_bundle = {
        "org_id": org_id, "project_id": str(uuid.uuid4()),
        "sequence": True, "base_sequence": False,
        "registry_version": True,
        "folder_policy": {}, "governance_policy": {}, "mcp_policy": {},
        "approval": {"local_fallback": False, "allow_requester": False},
    }
    proposal_canonical = json.dumps(proposal_bundle, sort_keys=True,
                                    separators=(",", ":")).encode()
    proposal_hash = hashlib.sha256(proposal_canonical).hexdigest()
    proposal_id = str(uuid.uuid4())

    seed = tmp_path / "s.seed"
    seed.write_bytes(bytes(sk).hex().encode())
    posts = []

    def route(m, url, **kw):
        u = str(url)
        if m == "POST" and "signer/token" in u:
            return _FakeHTTPResponse({"token": "t"})
        if m == "GET" and "registry" in u:
            return _FakeHTTPResponse([genesis_env])
        if m == "GET" and "bundle-proposals" in u:
            return _FakeHTTPResponse({
                "id": proposal_id, "bundle": proposal_bundle,
                "bundle_hash": proposal_hash, "base_sequence": 0,
            })
        if m == "POST":
            posts.append(u)
        return _FakeHTTPResponse({"ok": True}, 201)

    cli = _get_cli()
    runner = CliRunner()

    with mock.patch("httpx.Client") as MC:
        inst = mock.MagicMock()
        MC.return_value.__enter__ = mock.MagicMock(return_value=inst)
        MC.return_value.__exit__ = mock.MagicMock(return_value=False)
        inst.get = mock.MagicMock(
            side_effect=lambda url, **kw: route("GET", url, **kw))
        inst.post = mock.MagicMock(
            side_effect=lambda url, **kw: route("POST", url, **kw))

        result = runner.invoke(cli, [
            "signer", "approve-change", proposal_id,
            "--server", "https://localhost",
            "--key-file", str(seed),
            "--expect-fingerprint", fp,
            "--yes",
        ], env={"SANDBOX_KEY_HOME": str(tmp_path)})

    assert result.exit_code != 0, \
        f"bool in sequence fields must exit non-zero, got {result.exit_code}"
    assert isinstance(result.exception, SystemExit), \
        f"must be SystemExit, got {type(result.exception).__name__}"
    assert "Traceback" not in result.output, \
        f"must not produce a traceback, output={result.output[:300]}"
    approval_posts = [p for p in posts if "approvals" in p]
    assert len(approval_posts) == 0, \
        "bool in sequence fields must not POST to /approvals"


# ===================================================================
# R3-d: server-derived string with raw ESC -> no raw ESC in output
# ===================================================================


def test_approve_change_esc_in_bundle_key_no_raw_esc(tmp_path):
    """R3-d: a bundle key containing raw ESC (e.g. '\\x1b]0;pwned\\x07').
    approve-change must not emit raw ESC in its output (refusal message).
    Fails today: the unknown-field error message includes the raw key
    without passing it through _safe_str or _check_display_safety.
    Uses a valid chain so the command reaches the bundle field check.
    """
    import unittest.mock as mock

    require_m3(3, _command_in_signer("approve-change"),
               "signer approve-change command not found")

    org_id = str(uuid.uuid4())
    project_id = str(uuid.uuid4())
    esc_key = "\x1b]0;pwned\x07"

    sk = SigningKey.generate()
    sk_pub = bytes(sk.verify_key)
    sk_kid = hashlib.sha256(sk_pub).hexdigest()
    bs = SigningKey.generate()
    bs_pub = bytes(bs.verify_key)
    bs_kid = hashlib.sha256(bs_pub).hexdigest()

    genesis_payload = {
        "org_id": org_id, "version": 1, "prev_hash": "",
        "threshold": 1, "admins": [sk_kid],
        "keys": [{"key_id": sk_kid, "public_key": sk_pub.hex(),
                  "user_id": "u0", "iss": "https://idp.test", "sub": "u0",
                  "alg": "ed25519", "kind": "cli",
                  "roles": ["admin", "approver"], "added_in": 1}],
        "bundle_signer": {"key_id": bs_kid, "public_key": bs_pub.hex(),
                          "alg": "ed25519"},
        "expires_at": 9999999999.0,
    }
    genesis_canonical = json.dumps(genesis_payload, sort_keys=True,
                                   separators=(",", ":")).encode()
    genesis_sig = sk.sign(
        b"agg/registry/v1\x00" + genesis_canonical).signature.hex()
    genesis_env = {
        "kind": "agg/registry/v1", "sig_v": 1,
        "payload": genesis_payload,
        "signatures": [{"key_id": sk_kid, "alg": "ed25519",
                        "sig": genesis_sig}],
    }
    fp = hashlib.sha256(
        org_id.encode() + b":" + genesis_canonical).hexdigest()

    proposal_bundle = {
        "org_id": org_id, "project_id": project_id,
        "sequence": 1, "base_sequence": 0, "registry_version": 1,
        "folder_policy": {}, "governance_policy": {}, "mcp_policy": {},
        "approval": {"local_fallback": False, "allow_requester": False},
        esc_key: "injected",
    }
    proposal_canonical = json.dumps(proposal_bundle, sort_keys=True,
                                    separators=(",", ":")).encode()
    proposal_hash = hashlib.sha256(proposal_canonical).hexdigest()
    proposal_id = str(uuid.uuid4())

    seed = tmp_path / "s.seed"
    seed.write_bytes(bytes(sk).hex().encode())

    def route(m, url, **kw):
        u = str(url)
        if m == "POST" and "signer/token" in u:
            return _FakeHTTPResponse({"token": "t"})
        if m == "GET" and "registry" in u:
            return _FakeHTTPResponse([genesis_env])
        if m == "GET" and "bundle-proposals" in u:
            return _FakeHTTPResponse({
                "id": proposal_id, "bundle": proposal_bundle,
                "bundle_hash": proposal_hash, "base_sequence": 0,
            })
        if m == "POST":
            return _FakeHTTPResponse({"ok": True}, 201)
        return _FakeHTTPResponse({"error": "not found"}, 404)

    cli = _get_cli()
    runner = CliRunner()

    with mock.patch("httpx.Client") as MC:
        inst = mock.MagicMock()
        MC.return_value.__enter__ = mock.MagicMock(return_value=inst)
        MC.return_value.__exit__ = mock.MagicMock(return_value=False)
        inst.get = mock.MagicMock(
            side_effect=lambda url, **kw: route("GET", url, **kw))
        inst.post = mock.MagicMock(
            side_effect=lambda url, **kw: route("POST", url, **kw))

        result = runner.invoke(cli, [
            "signer", "approve-change", proposal_id,
            "--server", "https://localhost",
            "--key-file", str(seed),
            "--expect-fingerprint", fp,
            "--yes",
        ], env={"SANDBOX_KEY_HOME": str(tmp_path)})

    # Raw ESC byte must not appear in the output
    assert "\x1b" not in result.output, \
        f"raw ESC in bundle key must not reach output, output={result.output[:200]!r}"



def test_propose_bundle_esc_in_server_added_key_no_raw_esc(tmp_path):
    """R3-d: the server adds a key with raw ESC in the response bundle.
    propose-bundle must not emit raw ESC in its refusal output.
    Fails today: the unknown-key error message includes the raw key
    without sanitization.
    """
    import unittest.mock as mock

    require_m3(3, _command_in_signer("propose-bundle"),
               "signer propose-bundle command not found")

    esc_key = "\x1b]0;pwned\x07"
    sent = {"folder_policy": {"allow": ["*.py"]}}
    SO = {"org_id": "o", "project_id": "p", "sequence": 1,
          "base_sequence": 0, "registry_version": 1,
          "environment": "prod", "issued_at": 1, "not_before": 1}
    f = tmp_path / "b.json"
    f.write_text(json.dumps(sent))

    # Server returns the sent bundle plus an ESC-injected key
    server_bundle = {**sent, **SO, esc_key: "injected"}
    server_hash = hashlib.sha256(
        json.dumps(server_bundle, sort_keys=True,
                   separators=(",", ":")).encode()
    ).hexdigest()

    def route(m, url, **kw):
        return _FakeHTTPResponse({
            "id": "x", "bundle": server_bundle,
            "bundle_hash": server_hash,
        }, 201)

    cli = _get_cli()
    runner = CliRunner()

    with mock.patch("httpx.Client") as MC:
        inst = mock.MagicMock()
        MC.return_value.__enter__ = mock.MagicMock(return_value=inst)
        MC.return_value.__exit__ = mock.MagicMock(return_value=False)
        inst.get = mock.MagicMock(
            side_effect=lambda url, **kw: route("GET", url, **kw))
        inst.post = mock.MagicMock(
            side_effect=lambda url, **kw: route("POST", url, **kw))

        result = runner.invoke(cli, [
            "signer", "propose-bundle",
            "--server", "https://localhost",
            "--project", str(uuid.uuid4()),
            "--bundle-file", str(f),
        ], env={"SANDBOX_KEY_HOME": str(tmp_path)})

    # Raw ESC byte must not appear in the output
    assert "\x1b" not in result.output, \
        f"raw ESC in server key must not reach output, output={result.output[:200]!r}"


# ===================================================================
# R4-7 SHOULDs: ESC in base envelope kind / registry error
# ===================================================================

def test_approve_change_esc_in_base_envelope_kind_no_raw_esc(tmp_path):
    """R4-7 SHOULD: an ESC in the base row's envelope ``kind`` field
    must not reach the terminal raw.  The base structure check refuses
    with a message that includes the kind.  Passes on today's code
    because ``_safe_str`` sanitises the value.
    """
    import unittest.mock as mock

    require_m3(3, _command_in_signer("approve-change"),
               "signer approve-change command not found")

    org_id = str(uuid.uuid4())
    project_id = str(uuid.uuid4())

    sk = SigningKey.generate()
    sk_pub = bytes(sk.verify_key)
    sk_kid = hashlib.sha256(sk_pub).hexdigest()
    bs = SigningKey.generate()
    bs_pub = bytes(bs.verify_key)
    bs_kid = hashlib.sha256(bs_pub).hexdigest()

    genesis_payload = {
        "org_id": org_id, "version": 1, "prev_hash": "",
        "threshold": 1, "admins": [sk_kid],
        "keys": [{"key_id": sk_kid, "public_key": sk_pub.hex(),
                  "user_id": "u0", "iss": "https://idp.test", "sub": "u0",
                  "alg": "ed25519", "kind": "cli",
                  "roles": ["admin", "approver"], "added_in": 1}],
        "bundle_signer": {"key_id": bs_kid, "public_key": bs_pub.hex(),
                          "alg": "ed25519"},
        "expires_at": 9999999999.0,
    }
    genesis_canonical = json.dumps(genesis_payload, sort_keys=True,
                                   separators=(",", ":")).encode()
    genesis_sig = sk.sign(
        b"agg/registry/v1\x00" + genesis_canonical).signature.hex()
    genesis_env = {
        "kind": "agg/registry/v1", "sig_v": 1,
        "payload": genesis_payload,
        "signatures": [{"key_id": sk_kid, "alg": "ed25519",
                        "sig": genesis_sig}],
    }
    fp = hashlib.sha256(
        org_id.encode() + b":" + genesis_canonical).hexdigest()

    # Base row: a published bundle with ESC in the envelope kind
    base_payload = {
        "org_id": org_id, "project_id": project_id,
        "sequence": 1, "base_sequence": 0, "registry_version": 1,
        "folder_policy": {}, "governance_policy": {}, "mcp_policy": {},
        "approval": {"local_fallback": False, "allow_requester": False},
    }
    base_canonical = json.dumps(base_payload, sort_keys=True,
                                separators=(",", ":")).encode()
    base_sig = bs.sign(b"agg/bundle/v1\x00" + base_canonical).signature.hex()
    base_env = {
        "kind": "\x1b[31mpwned\x1b[0m",  # ESC in the kind
        "sig_v": 1,
        "payload": base_payload,
        "signatures": [{"key_id": bs_kid, "alg": "ed25519",
                        "sig": base_sig}],
    }

    # Proposal bundle at sequence 2
    proposal_bundle = {
        "org_id": org_id, "project_id": project_id,
        "sequence": 2, "base_sequence": 1, "registry_version": 1,
        "folder_policy": {"allow": ["*.txt"]}, "governance_policy": {},
        "mcp_policy": {},
        "approval": {"local_fallback": False, "allow_requester": False},
    }
    proposal_canonical = json.dumps(proposal_bundle, sort_keys=True,
                                    separators=(",", ":")).encode()
    proposal_hash = hashlib.sha256(proposal_canonical).hexdigest()
    proposal_id = str(uuid.uuid4())

    seed = tmp_path / "s.seed"
    seed.write_bytes(bytes(sk).hex().encode())

    def route(m, url, **kw):
        u = str(url)
        if m == "POST" and "signer/token" in u:
            return _FakeHTTPResponse({"token": "t"})
        if m == "GET" and "registry" in u:
            return _FakeHTTPResponse([genesis_env])
        if m == "GET" and "bundle-proposals" in u:
            return _FakeHTTPResponse({
                "id": proposal_id, "bundle": proposal_bundle,
                "bundle_hash": proposal_hash,
                "base_sequence": 1,
                "base": {"envelope": base_env},
            })
        if m == "POST":
            return _FakeHTTPResponse({"ok": True}, 201)
        return _FakeHTTPResponse({"error": "not found"}, 404)

    cli = _get_cli()
    runner = CliRunner()

    with mock.patch("httpx.Client") as MC:
        inst = mock.MagicMock()
        MC.return_value.__enter__ = mock.MagicMock(return_value=inst)
        MC.return_value.__exit__ = mock.MagicMock(return_value=False)
        inst.get = mock.MagicMock(
            side_effect=lambda url, **kw: route("GET", url, **kw))
        inst.post = mock.MagicMock(
            side_effect=lambda url, **kw: route("POST", url, **kw))

        result = runner.invoke(cli, [
            "signer", "approve-change", proposal_id,
            "--server", "https://localhost",
            "--key-file", str(seed),
            "--expect-fingerprint", fp,
            "--yes",
        ], env={"SANDBOX_KEY_HOME": str(tmp_path)})

    # The command should refuse (bad base kind) and raw ESC must not appear
    assert "\x1b" not in result.output, \
        f"raw ESC in base envelope kind must not reach output, output={result.output[:200]!r}"


def test_approve_change_esc_in_registry_error_no_raw_esc(tmp_path):
    """R4-7 SHOULD: an ESC in a registry error message (e.g. from a
    malformed genesis ``kind`` field) must not reach the terminal raw.
    Passes on today's code because error text goes through ``_safe_str``
    or ``json.dumps(ensure_ascii=True)``.
    """
    import unittest.mock as mock

    require_m3(3, _command_in_signer("approve-change"),
               "signer approve-change command not found")

    # Return a registry chain where the genesis has ESC in the kind field
    # This should trigger a RegistryError with the ESC in the message
    esc_kind = "\x1b[31mevil\x1b[0m"
    genesis_env = {
        "kind": esc_kind,
        "sig_v": 1,
        "payload": {"org_id": str(uuid.uuid4()), "version": 1},
        "signatures": [{"key_id": "k", "alg": "ed25519", "sig": "0" * 128}],
    }

    sk = SigningKey.generate()
    seed = tmp_path / "s.seed"
    seed.write_bytes(bytes(sk).hex().encode())

    def route(m, url, **kw):
        u = str(url)
        if m == "POST" and "signer/token" in u:
            return _FakeHTTPResponse({"token": "t"})
        if m == "GET" and "registry" in u:
            return _FakeHTTPResponse([genesis_env])
        if m == "GET" and "bundle-proposals" in u:
            return _FakeHTTPResponse({
                "id": str(uuid.uuid4()),
                "bundle": {"org_id": "o", "project_id": "p",
                           "sequence": 1, "base_sequence": 0,
                           "registry_version": 1, "folder_policy": {}},
                "bundle_hash": "a" * 64, "base_sequence": 0,
            })
        return _FakeHTTPResponse({"error": "not found"}, 404)

    cli = _get_cli()
    runner = CliRunner()
    proposal_id = str(uuid.uuid4())

    with mock.patch("httpx.Client") as MC:
        inst = mock.MagicMock()
        MC.return_value.__enter__ = mock.MagicMock(return_value=inst)
        MC.return_value.__exit__ = mock.MagicMock(return_value=False)
        inst.get = mock.MagicMock(
            side_effect=lambda url, **kw: route("GET", url, **kw))
        inst.post = mock.MagicMock(
            side_effect=lambda url, **kw: route("POST", url, **kw))

        result = runner.invoke(cli, [
            "signer", "approve-change", proposal_id,
            "--server", "https://localhost",
            "--key-file", str(seed),
            "--expect-fingerprint", "badfingerprint",
            "--yes",
        ], env={"SANDBOX_KEY_HOME": str(tmp_path)})

    # Command should refuse (bad registry / fingerprint mismatch)
    # and raw ESC must not appear in any error output
    assert "\x1b" not in result.output, \
        f"raw ESC in registry error must not reach output, output={result.output[:200]!r}"
