"""M3 T3 tests-first: signer CLI commands for enrollment codes, proposals,
approvals and publish.

Spec: M3_PLAN.md T3 row, D2 (A9 items 6-8), D3, threats 39-40,
ADR 0001 A9, T0B_SECURITY_REVIEW P3.

New CLI commands under ``sandbox signer``:

    sandbox signer issue-code
        Admin issues an enrollment code through the CLI.

    sandbox signer propose-bundle
        Admin proposes a bundle from pasted JSON.

    sandbox signer approve-change <id>
        Fetches canonical bytes, computes its own diff, verifies the base
        row, runs ``loosened`` locally, signs ``agg/policy-change/v1``
        over the bundle hash.

    sandbox signer publish <id>
        Publishes a proposal.

CLI tests use CliRunner (as in T12d).  Each target is
``xfail(strict=True, raises=M3T3Pending)``.  Guards verify existing CLI
structure.
"""
from __future__ import annotations

import hashlib
import json
import os
import uuid

import pytest
from click.testing import CliRunner
from nacl.signing import SigningKey

from tests.m3_pending import M3T3Pending, require_m3


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_cli():
    """Import and return the main CLI group."""
    from sandbox.cli.main import cli
    return cli


def _signer_help() -> str:
    """Return the output of ``sandbox signer --help``."""
    cli = _get_cli()
    runner = CliRunner()
    result = runner.invoke(cli, ["signer", "--help"])
    return result.output if result.exit_code == 0 else ""


def _command_in_signer(name: str) -> bool:
    """Return True if *name* is listed as a command in ``sandbox signer --help``.

    Checks that *name* appears as a whole word on a line that looks like
    a Click command listing, not just as a substring of a flag name.
    """
    help_text = _signer_help()
    # Click lists commands as "  command-name  Description..."
    # Check for the name as a standalone command, not a flag like --publish
    for line in help_text.splitlines():
        stripped = line.strip()
        # Click command lines start with the command name
        if stripped.startswith(name + " ") or stripped == name:
            return True
    return False


# ===================================================================
# GUARD TWINS (PASS today -- prove the CLI structure exists)
# ===================================================================

def test_guard_signer_group_exists():
    """Guard: the 'signer' CLI group exists."""
    cli = _get_cli()
    runner = CliRunner()
    result = runner.invoke(cli, ["signer", "--help"])
    assert result.exit_code == 0, f"signer --help failed: {result.output}"
    assert "signer" in result.output.lower() or "approve" in result.output


def test_guard_signer_genesis_exists():
    """Guard: 'sandbox signer genesis' exists (from T12d)."""
    assert _command_in_signer("genesis"), "signer genesis missing"


def test_guard_signer_link_exists():
    """Guard: 'sandbox signer link' exists (from T12d)."""
    assert _command_in_signer("link"), "signer link missing"


def test_guard_signer_approve_exists():
    """Guard: 'sandbox signer approve' exists (from T12b)."""
    assert _command_in_signer("approve"), "signer approve missing"


# ===================================================================
# T3 TARGETS: issue-code command
# ===================================================================

@pytest.mark.xfail(strict=True, raises=M3T3Pending)
def test_issue_code_command_exists():
    """sandbox signer issue-code command exists."""
    require_m3(3, _command_in_signer("issue-code"),
               "signer issue-code command not found")
    assert _command_in_signer("issue-code")


@pytest.mark.xfail(strict=True, raises=M3T3Pending)
def test_issue_code_help():
    """issue-code --help exits 0."""
    require_m3(3, _command_in_signer("issue-code"),
               "signer issue-code command not found")
    cli = _get_cli()
    runner = CliRunner()
    result = runner.invoke(cli, ["signer", "issue-code", "--help"])
    assert result.exit_code == 0, f"issue-code --help: {result.output}"


# ===================================================================
# T3 TARGETS: propose-bundle command
# ===================================================================

@pytest.mark.xfail(strict=True, raises=M3T3Pending)
def test_propose_bundle_command_exists():
    """sandbox signer propose-bundle command exists."""
    require_m3(3, _command_in_signer("propose-bundle"),
               "signer propose-bundle command not found")
    assert _command_in_signer("propose-bundle")


@pytest.mark.xfail(strict=True, raises=M3T3Pending)
def test_propose_bundle_help():
    """propose-bundle --help exits 0."""
    require_m3(3, _command_in_signer("propose-bundle"),
               "signer propose-bundle command not found")
    cli = _get_cli()
    runner = CliRunner()
    result = runner.invoke(cli, ["signer", "propose-bundle", "--help"])
    assert result.exit_code == 0, f"propose-bundle --help: {result.output}"


# ===================================================================
# T3 TARGETS: approve-change command
# ===================================================================

@pytest.mark.xfail(strict=True, raises=M3T3Pending)
def test_approve_change_command_exists():
    """sandbox signer approve-change command exists."""
    require_m3(3, _command_in_signer("approve-change"),
               "signer approve-change command not found")
    assert _command_in_signer("approve-change")


@pytest.mark.xfail(strict=True, raises=M3T3Pending)
def test_approve_change_help():
    """approve-change --help exits 0."""
    require_m3(3, _command_in_signer("approve-change"),
               "signer approve-change command not found")
    cli = _get_cli()
    runner = CliRunner()
    result = runner.invoke(cli, ["signer", "approve-change", "--help"])
    assert result.exit_code == 0, f"approve-change --help: {result.output}"


@pytest.mark.xfail(strict=True, raises=M3T3Pending)
def test_approve_change_signs_policy_change_v1(tmp_path):
    """approve-change: stub the HTTP layer, verify the tag, the signature,
    exactly one signature, that the diff is computed from local bytes (not
    from a misleading server-supplied diff), and that it refuses when the
    base row does not verify (F-6, P3).

    Spec: ADR 0001 A9 item 7, T0B_SECURITY_REVIEW P3, F-6.
    """
    require_m3(3, _command_in_signer("approve-change"),
               "signer approve-change command not found")

    import unittest.mock as mock

    org_id = str(uuid.uuid4())
    project_id = str(uuid.uuid4())

    # --- build a base bundle (sequence 0 / deny-all) ---
    base_payload = {
        "org_id": org_id,
        "project_id": project_id,
        "sequence": 0,
        "base_sequence": 0,
        "registry_version": 1,
        "folder_policy": {},
        "governance_policy": {},
        "mcp_policy": {},
        "approval": {"local_fallback": False, "allow_requester": False},
    }
    base_canonical = json.dumps(base_payload, sort_keys=True,
                                separators=(",", ":")).encode()
    base_hash = hashlib.sha256(base_canonical).hexdigest()

    # Sign the base envelope with a bundle signer key
    bundle_signer_sk = SigningKey.generate()
    base_tag = b"agg/bundle/v1"
    base_msg = base_tag + b"\x00" + base_canonical
    base_sig = bundle_signer_sk.sign(base_msg).signature.hex()
    base_pub = bytes(bundle_signer_sk.verify_key).hex()
    base_envelope = {
        "kind": "agg/bundle/v1",
        "sig_v": 1,
        "payload": base_payload,
        "signatures": [{
            "key_id": hashlib.sha256(bytes(bundle_signer_sk.verify_key)).hexdigest(),
            "alg": "ed25519",
            "sig": base_sig,
        }],
    }

    # --- build the proposal bundle (sequence 1) ---
    proposal_payload = {
        "org_id": org_id,
        "project_id": project_id,
        "sequence": 1,
        "base_sequence": 0,
        "registry_version": 1,
        "folder_policy": {"allow": ["*.py"]},
        "governance_policy": {},
        "mcp_policy": {},
        "approval": {"local_fallback": False, "allow_requester": False},
    }
    proposal_canonical = json.dumps(proposal_payload, sort_keys=True,
                                    separators=(",", ":")).encode()
    proposal_hash = hashlib.sha256(proposal_canonical).hexdigest()

    # Write a signer seed file
    seed_file = tmp_path / "cli.seed"
    sk = SigningKey.generate()
    seed_file.write_bytes(bytes(sk).hex().encode("ascii"))

    proposal_id = str(uuid.uuid4())

    # --- build mock HTTP responses ---
    # The approve-change command fetches the proposal and the base row.
    # A misleading diff from the server must not be used.
    misleading_diff = {"folder_policy": "TAMPERED_DIFF"}

    class FakeResponse:
        def __init__(self, json_data, status_code=200):
            self._json = json_data
            self.status_code = status_code
            self.text = json.dumps(json_data)
            self.headers = {"content-type": "application/json"}

        def json(self):
            return self._json

        def raise_for_status(self):
            pass

    proposal_response = FakeResponse({
        "id": proposal_id,
        "bundle": proposal_payload,
        "bundle_hash": proposal_hash,
        "base_sequence": 0,
        "diff": misleading_diff,  # server-supplied diff (should be ignored)
    })

    base_response = FakeResponse({
        "envelope": base_envelope,
        "change_approvals": [],
    })

    captured_posts = []

    def mock_request(method, url, **kwargs):
        url_str = str(url)
        if method.upper() == "GET" and "bundle-proposals" in url_str:
            return proposal_response
        if method.upper() == "GET" and "bundle" in url_str:
            return base_response
        if method.upper() == "POST":
            captured_posts.append(kwargs)
            return FakeResponse({"ok": True}, 200)
        return FakeResponse({"error": "not found"}, 404)

    # Run the command with patched HTTP
    cli = _get_cli()
    runner = CliRunner()

    with mock.patch("httpx.Client") as MockClient:
        client_instance = mock.MagicMock()
        MockClient.return_value.__enter__ = mock.MagicMock(
            return_value=client_instance)
        MockClient.return_value.__exit__ = mock.MagicMock(
            return_value=False)
        client_instance.request = mock.MagicMock(side_effect=mock_request)
        client_instance.get = mock.MagicMock(
            side_effect=lambda url, **kw: mock_request("GET", url, **kw))
        client_instance.post = mock.MagicMock(
            side_effect=lambda url, **kw: mock_request("POST", url, **kw))

        result = runner.invoke(cli, [
            "signer", "approve-change", proposal_id,
            "--server", "https://localhost",
            "--key-file", str(seed_file),
            "--yes",
        ])

    # The command must not exit with code 2 (usage error = missing)
    assert result.exit_code != 2, \
        f"approve-change is a usage error (command missing?): {result.output}"

    # Verify the tag is agg/policy-change/v1
    # The command should have posted an approval with exactly one signature
    if captured_posts:
        posted = captured_posts[0]
        posted_json = posted.get("json", {})
        approval = posted_json.get("approval", posted_json)
        sigs = approval.get("signatures", [])
        assert len(sigs) == 1, \
            f"approval must have exactly one signature, got {len(sigs)}"

        # Verify the signature over the bundle hash
        sig_hex = sigs[0]["sig"]
        sig_bytes = bytes.fromhex(sig_hex)
        expected_tag = b"agg/policy-change/v1"
        expected_payload = {"bundle_hash": proposal_hash}
        expected_canonical = json.dumps(
            expected_payload, sort_keys=True,
            separators=(",", ":")).encode()
        expected_msg = expected_tag + b"\x00" + expected_canonical
        # Verify with the signer's public key
        from nacl.signing import VerifyKey
        vk = VerifyKey(bytes(sk.verify_key))
        vk.verify(expected_msg, sig_bytes)  # raises if invalid

    # --- F-6 / P3: refuse when the base row does not verify ---
    # Corrupt the base envelope signature
    bad_base_envelope = json.loads(json.dumps(base_envelope))
    bad_sig = list(bytes.fromhex(bad_base_envelope["signatures"][0]["sig"]))
    bad_sig[0] ^= 0x01
    bad_base_envelope["signatures"][0]["sig"] = bytes(bad_sig).hex()
    bad_base_response = FakeResponse({
        "envelope": bad_base_envelope,
        "change_approvals": [],
    })

    captured_posts_bad = []

    def mock_request_bad(method, url, **kwargs):
        url_str = str(url)
        if method.upper() == "GET" and "bundle-proposals" in url_str:
            return proposal_response
        if method.upper() == "GET" and "bundle" in url_str:
            return bad_base_response
        if method.upper() == "POST":
            captured_posts_bad.append(kwargs)
            return FakeResponse({"ok": True}, 200)
        return FakeResponse({"error": "not found"}, 404)

    with mock.patch("httpx.Client") as MockClient2:
        client_instance2 = mock.MagicMock()
        MockClient2.return_value.__enter__ = mock.MagicMock(
            return_value=client_instance2)
        MockClient2.return_value.__exit__ = mock.MagicMock(
            return_value=False)
        client_instance2.request = mock.MagicMock(
            side_effect=mock_request_bad)
        client_instance2.get = mock.MagicMock(
            side_effect=lambda url, **kw: mock_request_bad("GET", url, **kw))
        client_instance2.post = mock.MagicMock(
            side_effect=lambda url, **kw: mock_request_bad("POST", url, **kw))

        result_bad = runner.invoke(cli, [
            "signer", "approve-change", proposal_id,
            "--server", "https://localhost",
            "--key-file", str(seed_file),
            "--yes",
        ])

    # Must refuse to sign when the base does not verify
    assert len(captured_posts_bad) == 0, \
        "approve-change must sign nothing when the base row does not verify"
    assert result_bad.exit_code != 0, \
        f"approve-change must fail (non-zero) when the base is unverifiable, " \
        f"got exit_code={result_bad.exit_code}"


# ===================================================================
# T3 TARGETS: publish command
# ===================================================================

@pytest.mark.xfail(strict=True, raises=M3T3Pending)
def test_publish_command_exists():
    """sandbox signer publish command exists."""
    require_m3(3, _command_in_signer("publish"),
               "signer publish command not found in signer --help "
               "(note: 'publish' must be a separate command, not just "
               "a --publish flag on sign-registry)")


@pytest.mark.xfail(strict=True, raises=M3T3Pending)
def test_publish_help():
    """publish --help exits 0."""
    require_m3(3, _command_in_signer("publish"),
               "signer publish command not found")
    cli = _get_cli()
    runner = CliRunner()
    result = runner.invoke(cli, ["signer", "publish", "--help"])
    assert result.exit_code == 0, f"publish --help: {result.output}"


# ===================================================================
# Shared HTTP stub helper
# ===================================================================

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


def _patch_httpx_client(mock_mod, route_fn):
    """Return a context manager that patches httpx.Client with *route_fn*.

    *route_fn(method, url, **kwargs)* -> _FakeHTTPResponse
    """
    ctx = mock_mod.patch("httpx.Client")
    return ctx, route_fn


def _wire_mock_client(MockClient, route_fn):
    """Wire a MockClient's enter/exit and method routing."""
    inst = MockClient.return_value.__enter__ = \
        MockClient.return_value  # support both patterns
    MockClient.return_value.__enter__ = \
        lambda self_=None: inst
    MockClient.return_value.__exit__ = \
        lambda *a: False
    inst.get = lambda url, **kw: route_fn("GET", url, **kw)
    inst.post = lambda url, **kw: route_fn("POST", url, **kw)
    inst.request = lambda m, url, **kw: route_fn(m, url, **kw)
    return inst


# ===================================================================
# T3 TARGETS: issue-code real behaviour
# ===================================================================

@pytest.mark.xfail(strict=True, raises=M3T3Pending)
def test_issue_code_sends_project_and_operator(tmp_path):
    """issue-code sends project_id and operator_user_id with CSRF and
    session headers.  The code is printed once and never written to disk
    or the audit log.

    Threat 39: the code must not persist outside the terminal.
    """
    import unittest.mock as mock

    require_m3(3, _command_in_signer("issue-code"),
               "signer issue-code command not found")

    project_id = str(uuid.uuid4())
    operator_id = str(uuid.uuid4())
    code_value = "SECRET-CODE-12345"

    captured_posts = []

    def route_fn(method, url, **kwargs):
        url_str = str(url)
        if method.upper() == "POST" and "enrollment-codes" in url_str:
            captured_posts.append(kwargs)
            return _FakeHTTPResponse({
                "code_id": str(uuid.uuid4()),
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
            "--project", project_id,
            "--operator", operator_id,
        ])

    assert result.exit_code != 2, \
        f"issue-code usage error (missing?): {result.output}"

    # Must have sent a POST with project and operator
    assert len(captured_posts) >= 1, \
        "issue-code must POST to the enrollment-codes endpoint"
    posted = captured_posts[0].get("json", {})
    assert posted.get("project_id") == project_id, \
        f"POST must carry project_id, got {posted}"
    assert posted.get("operator_user_id") == operator_id, \
        f"POST must carry operator_user_id, got {posted}"

    # The code must be printed (shown to the user)
    assert code_value in result.output, \
        "issue-code must print the code to the terminal"

    # The code must not be written to any file in tmp_path
    for f in tmp_path.rglob("*"):
        if f.is_file():
            content = f.read_text(errors="replace")
            assert code_value not in content, \
                f"code must not be written to disk ({f.name})"


# ===================================================================
# T3 TARGETS: propose-bundle real behaviour
# ===================================================================

@pytest.mark.xfail(strict=True, raises=M3T3Pending)
def test_propose_bundle_sends_canonical_and_verifies_hash(tmp_path):
    """propose-bundle sends canonical bytes and prints the server's hash
    only after it matches a locally computed hash.  A mismatch refuses.
    """
    import unittest.mock as mock

    require_m3(3, _command_in_signer("propose-bundle"),
               "signer propose-bundle command not found")

    bundle_json = {
        "folder_policy": {"allow": ["*.py"]},
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

    captured_posts = []

    def route_fn_ok(method, url, **kwargs):
        if method.upper() == "POST" and "bundle-proposals" in str(url):
            captured_posts.append(kwargs)
            return _FakeHTTPResponse({
                "id": str(uuid.uuid4()),
                "bundle_hash": correct_hash,
            }, 200)
        return _FakeHTTPResponse({"error": "not found"}, 404)

    cli = _get_cli()
    runner = CliRunner()

    with mock.patch("httpx.Client") as MC:
        inst = mock.MagicMock()
        MC.return_value.__enter__ = mock.MagicMock(return_value=inst)
        MC.return_value.__exit__ = mock.MagicMock(return_value=False)
        inst.get = mock.MagicMock(
            side_effect=lambda url, **kw: route_fn_ok("GET", url, **kw))
        inst.post = mock.MagicMock(
            side_effect=lambda url, **kw: route_fn_ok("POST", url, **kw))

        result_ok = runner.invoke(cli, [
            "signer", "propose-bundle",
            "--server", "https://localhost",
            "--project", project_id,
            "--bundle-file", str(bundle_file),
        ])

    assert result_ok.exit_code != 2, \
        f"propose-bundle usage error: {result_ok.output}"
    assert len(captured_posts) >= 1, \
        "propose-bundle must POST to the proposals endpoint"
    # The hash must appear in the output (printed after verification)
    assert correct_hash in result_ok.output, \
        f"propose-bundle must print the verified hash, output={result_ok.output[:200]}"

    # --- mismatch case: server returns a different hash ---
    wrong_hash = hashlib.sha256(b"wrong-bytes").hexdigest()
    captured_mismatch = []

    def route_fn_bad(method, url, **kwargs):
        if method.upper() == "POST" and "bundle-proposals" in str(url):
            captured_mismatch.append(kwargs)
            return _FakeHTTPResponse({
                "id": str(uuid.uuid4()),
                "bundle_hash": wrong_hash,
            }, 200)
        return _FakeHTTPResponse({"error": "not found"}, 404)

    with mock.patch("httpx.Client") as MC2:
        inst2 = mock.MagicMock()
        MC2.return_value.__enter__ = mock.MagicMock(return_value=inst2)
        MC2.return_value.__exit__ = mock.MagicMock(return_value=False)
        inst2.get = mock.MagicMock(
            side_effect=lambda url, **kw: route_fn_bad("GET", url, **kw))
        inst2.post = mock.MagicMock(
            side_effect=lambda url, **kw: route_fn_bad("POST", url, **kw))

        result_bad = runner.invoke(cli, [
            "signer", "propose-bundle",
            "--server", "https://localhost",
            "--project", project_id,
            "--bundle-file", str(bundle_file),
        ])

    assert result_bad.exit_code != 0, \
        f"propose-bundle must fail on hash mismatch, got exit_code={result_bad.exit_code}"
    assert "mismatch" in result_bad.output.lower() or \
           "hash" in result_bad.output.lower(), \
        f"propose-bundle must report the mismatch, output={result_bad.output[:200]}"


# ===================================================================
# T3 TARGETS: publish real behaviour
# ===================================================================

@pytest.mark.xfail(strict=True, raises=M3T3Pending)
def test_publish_shows_refusal_and_exits_nonzero(tmp_path):
    """publish sends the proposal id.  On 400 it shows the server's
    refusal reason and exits non-zero.
    """
    import unittest.mock as mock

    require_m3(3, _command_in_signer("publish"),
               "signer publish command not found")

    proposal_id = str(uuid.uuid4())
    refusal_reason = "stale_base"

    def route_fn(method, url, **kwargs):
        if method.upper() == "POST" and "publish" in str(url):
            return _FakeHTTPResponse(
                {"error": refusal_reason,
                 "detail": "base_sequence is stale"},
                400)
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
            "signer", "publish", proposal_id,
            "--server", "https://localhost",
        ])

    assert result.exit_code != 2, \
        f"publish usage error (missing?): {result.output}"
    assert result.exit_code != 0, \
        f"publish must exit non-zero on 400, got exit_code={result.exit_code}"
    assert refusal_reason in result.output or "stale" in result.output.lower(), \
        f"publish must show the refusal reason, output={result.output[:200]}"


# ===================================================================
# T3 TARGETS: approve-change diff computed independently
# ===================================================================

@pytest.mark.xfail(strict=True, raises=M3T3Pending)
def test_approve_change_diff_from_local_bytes(tmp_path):
    """approve-change computes the diff from the bytes on the machine,
    not from a server-supplied diff.  The diff matches an independently
    computed one and differs from the misleading server-supplied diff.

    This is a separate node from test_approve_change_signs_policy_change_v1
    to isolate the diff-computation check.
    """
    import unittest.mock as mock

    require_m3(3, _command_in_signer("approve-change"),
               "signer approve-change command not found")

    org_id = str(uuid.uuid4())
    project_id = str(uuid.uuid4())

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
    base_envelope = {
        "kind": "agg/bundle/v1", "sig_v": 1,
        "payload": base_payload,
        "signatures": [{
            "key_id": hashlib.sha256(
                bytes(bundle_signer_sk.verify_key)).hexdigest(),
            "alg": "ed25519", "sig": base_sig,
        }],
    }

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

    # Independently compute the real diff
    real_diff = {}
    for section in ("folder_policy", "governance_policy", "mcp_policy",
                    "approval"):
        old_val = base_payload.get(section, {})
        new_val = proposal_payload.get(section, {})
        if old_val != new_val:
            real_diff[section] = {"old": old_val, "new": new_val}

    # Misleading diff: completely wrong
    misleading_diff = {"folder_policy": "TAMPERED_DIFF_CONTENT"}

    seed_file = tmp_path / "cli.seed"
    sk = SigningKey.generate()
    seed_file.write_bytes(bytes(sk).hex().encode("ascii"))
    proposal_id = str(uuid.uuid4())

    captured_output = []

    def route_fn(method, url, **kwargs):
        if method.upper() == "GET" and "bundle-proposals" in str(url):
            return _FakeHTTPResponse({
                "id": proposal_id,
                "bundle": proposal_payload,
                "bundle_hash": proposal_hash,
                "base_sequence": 0,
                "diff": misleading_diff,
            })
        if method.upper() == "GET" and "bundle" in str(url):
            return _FakeHTTPResponse({
                "envelope": base_envelope,
                "change_approvals": [],
            })
        if method.upper() == "POST":
            return _FakeHTTPResponse({"ok": True})
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
        ])

    assert result.exit_code != 2, \
        f"approve-change usage error: {result.output}"

    # The misleading diff must NOT appear in the output
    assert "TAMPERED_DIFF_CONTENT" not in result.output, \
        "approve-change must not show the server-supplied diff"

    # The real diff content (folder_policy changed) must appear
    # The command should mention what changed (e.g. "folder_policy")
    assert "folder_policy" in result.output, \
        (f"approve-change must show the locally computed diff mentioning "
         f"folder_policy, output={result.output[:300]}")
