"""T12d d1/d3 tests: CLI signer commands (link, genesis, sign-registry).

Interface contract (pinned -- the build removes only xfail markers)
-------------------------------------------------------------------
ADR 0011 adds three CLI commands under ``sandbox signer``:

    sandbox signer link --code <code> --server <url>
        Links the local CLI key to the control plane.

    sandbox signer genesis --genesis-code <code> --server <url>
        [--approver] [--confirm-identity <iss> <sub>]
        [--bundle-signer-key <64-hex>] [--yes]
        Builds registry v1, signs it, posts to POST /genesis.
        Prints the fingerprint = sha256(org_id + ":" + canonical_json(payload)).
        user_id is the server id, not the IdP ``sub``.
        Default roles: ``[admin]``.  ``--approver`` adds ``approver``.
        ``--confirm-identity <iss> <sub>`` must match server-reported identity;
        exits non-zero if mismatched.
        ``--bundle-signer-key <hex>`` is required (stub ruling 1); no /config
        call is ever made.

    sandbox signer sign-registry [--in FILE] [--out FILE] [--publish]
        [--add <key_id>] [--admin] [--confirm-key-id <key_id>]
        [--confirm-identity <iss> <sub>] [--threshold N]
        [--expect-fingerprint <fp>] [--server <url>] [--yes]
        Fetches GET /api/v1/sync/signer/registry (full chain, org-scoped)
        and runs verify_chain against --expect-fingerprint or stored root
        fingerprint.
        Shows the diff (incl. all field changes: user_id, iss, sub, kind,
        roles, bundle_signer, expires_at, threshold).
        Needs typed --confirm-key-id equal to the added set exactly.
        ``--threshold N`` sets the threshold in build mode.
        ``--publish`` posts the complete envelope.

CLI tests use CliRunner with a mocked HTTP layer (ruling i). Never a live
server.  Refusal tests assert ``exit_code == 1`` (ClickException), never
accept exit 2 (click usage error).  Each refusal family has a positive
control that exits 0 and publishes exactly once.

RED tests xfail on M2T12dPending.  Guards verify existing CLI structure.
"""
from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import platform
import secrets
import socket
import stat
import threading
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from unittest.mock import MagicMock, patch, call
from urllib.error import HTTPError, URLError

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


def _payload_hash(payload: dict) -> str:
    """Same as registry._payload_hash."""
    return hashlib.sha256(
        payload["org_id"].encode("utf-8") + b":" + _canonical_json(payload)
    ).hexdigest()


def _make_key_home(tmp_path: Path, sk: SigningKey, meta: dict) -> Path:
    """Create a key home with signer/signer.seed and signer/link.json."""
    signer_dir = tmp_path / "signer"
    signer_dir.mkdir(parents=True, exist_ok=True)
    seed_path = signer_dir / "signer.seed"
    seed_path.write_bytes(bytes(sk))
    (signer_dir / "link.json").write_text(
        json.dumps(meta, indent=2), encoding="utf-8"
    )
    # R2-2: on POSIX, tighten modes so product root_exposure check passes.
    # Without this, umask 022 creates 0755 dirs and the product correctly
    # refuses with "key home exposure" -- masking the real test reason.
    if os.name != "nt":
        os.chmod(signer_dir, 0o700)
        os.chmod(seed_path, 0o600)
    return tmp_path


def _build_valid_chain_v1(admin_sk: SigningKey, org_id: str, iss: str,
                          sub: str, bundle_pub: bytes,
                          user_id: str = "user-1") -> tuple[dict, str]:
    """Build a valid genesis envelope+fingerprint using the real library."""
    from sandbox.connector.sync.signer import build_genesis
    env, fp = build_genesis(admin_sk, org_id, iss, sub, bundle_pub,
                            user_id=user_id)
    return env, fp


def _detect_unknown_option(result) -> str | None:
    """If the CLI exited 2 with 'No such option', return the option name."""
    if result.exit_code == 2 and "No such option" in (result.output or ""):
        return result.output.strip().split("No such option")[-1].strip(" .'\"")
    return None


class _MockTracker:
    """Tracks every request URL and captures POST bodies."""

    def __init__(self, routes: dict):
        """*routes* maps a URL substring to a JSON-serialisable response
        (dict/list for 200, an HTTPError/URLError to raise, or None for
        a generic URLError).
        """
        self.routes = routes
        self.requested_urls: list[str] = []
        self.post_bodies: list[dict] = []
        self._request_data: list[tuple[str, bytes | None]] = []

    def urlopen(self, req, **kwargs):
        url = req.full_url if hasattr(req, "full_url") else str(req)
        data = req.data if hasattr(req, "data") else None
        self.requested_urls.append(url)
        self._request_data.append((url, data))
        if data is not None:
            try:
                self.post_bodies.append(json.loads(data))
            except Exception:
                pass
        for pattern, response in self.routes.items():
            if pattern in url:
                if isinstance(response, (HTTPError, URLError)):
                    raise response
                if response is None:
                    raise URLError("connection refused")
                resp = MagicMock()
                resp.read.return_value = json.dumps(response).encode()
                resp.status = 200
                resp.getcode.return_value = 200
                return resp
        raise URLError(f"no mock for {url}")

    @property
    def post_count(self) -> int:
        return len(self.post_bodies)

    def posts_to(self, substr: str) -> list[dict]:
        """Return POST bodies whose URL contained *substr*."""
        out = []
        body_idx = 0
        for url, data in self._request_data:
            if data is not None:
                if body_idx < len(self.post_bodies) and substr in url:
                    out.append(self.post_bodies[body_idx])
                if data is not None:
                    body_idx += 1
        return out

    def any_post(self) -> bool:
        """True if any request carried a body."""
        return len(self.post_bodies) > 0


def _genesis_tracker(admin_sk, meta, *, extra_routes=None):
    """Build a _MockTracker suitable for genesis calls."""
    routes = {
        "/signer/token": {"token": "tok-genesis"},
        "/signer/genesis": {"version": 1},
    }
    if extra_routes:
        routes.update(extra_routes)
    return _MockTracker(routes)


def _signreg_tracker(v1_env, *, candidates=None, extra_routes=None):
    """Build a _MockTracker suitable for sign-registry calls."""
    routes = {
        "/signer/token": {"token": "tok-signreg"},
        "/signer/registry": [v1_env],
        "/signer/candidates": candidates or [],
        "/signer/signatures": {"version": 2},
    }
    if extra_routes:
        routes.update(extra_routes)
    return _MockTracker(routes)


# ---------------------------------------------------------------------------
# R2-3: real HTTP server helpers (redirect + spy)
# ---------------------------------------------------------------------------


def _find_free_port() -> int:
    """Find a free TCP port on 127.0.0.1."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _make_signer_redirect_handler(redirect_code: int, target_url: str):
    """Create a handler that serves /signer/token normally but redirects
    /signer/genesis and /signer/signatures to *target_url*."""

    class _H(BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802
            length = int(self.headers.get("Content-Length", 0))
            self.rfile.read(length)
            if "/signer/token" in self.path:
                self._json_ok({"token": "tok-redirect-test"})
            else:
                self.send_response(redirect_code)
                self.send_header("Location", target_url + self.path)
                self.end_headers()

        def do_GET(self):  # noqa: N802
            self.send_response(redirect_code)
            self.send_header("Location", target_url + self.path)
            self.end_headers()

        def _json_ok(self, obj):
            body = json.dumps(obj).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, fmt, *args):  # noqa: D102
            pass  # suppress server logging in test output

    return _H


def _make_spy_handler():
    """Create a handler that records every request it receives."""

    class _Spy(BaseHTTPRequestHandler):
        requests: list[tuple[str, str]] = []
        auth_headers: list[str] = []

        def do_GET(self):  # noqa: N802
            self._record()
            self._json_ok({"spy": True})

        def do_POST(self):  # noqa: N802
            length = int(self.headers.get("Content-Length", 0))
            self.rfile.read(length)
            self._record()
            self._json_ok({"spy": True})

        def _record(self):
            _Spy.requests.append((self.command, self.path))
            auth = self.headers.get("Authorization")
            if auth:
                _Spy.auth_headers.append(auth)

        def _json_ok(self, obj):
            body = json.dumps(obj).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, fmt, *args):  # noqa: D102
            pass

    # Reset class-level state before each use
    _Spy.requests = []
    _Spy.auth_headers = []
    return _Spy


@contextlib.contextmanager
def _local_server(handler_class, host="127.0.0.1"):
    """Run an HTTPServer in a daemon thread; yield ``http://<host>:<port>``."""
    port = _find_free_port()
    server = HTTPServer((host, port), handler_class)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://{host}:{port}"
    finally:
        server.shutdown()
        thread.join(timeout=5)


# ---------------------------------------------------------------------------
# Guards (unchanged from d1)
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


def test_signer_link_command_exists():
    """'sandbox signer link' is a registered command."""
    from sandbox.cli.main import cli
    runner = CliRunner()
    result = runner.invoke(cli, ["signer", "--help"])
    if "link" not in result.output:
        raise M2T12dPending("'link' not in signer --help")


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


# ---------------------------------------------------------------------------
# sandbox signer genesis
# ---------------------------------------------------------------------------


def test_signer_genesis_command_exists():
    """'sandbox signer genesis' is a registered command."""
    from sandbox.cli.main import cli
    runner = CliRunner()
    result = runner.invoke(cli, ["signer", "--help"])
    if "genesis" not in result.output:
        raise M2T12dPending("'genesis' not in signer --help")


# ---------------------------------------------------------------------------
# Genesis positive control (covers F3, F7-https, F9-match, F12-nonempty)
# ---------------------------------------------------------------------------



def test_genesis_prints_fingerprint(tmp_path):
    """Positive control for genesis: all flags valid, exits 0, posts to
    /genesis exactly once, and the printed fingerprint equals
    sha256(org_id + ':' + canonical_json(payload)) of the posted envelope.
    Also the positive control for F3/F7/F9/F12."""
    from sandbox.cli.main import cli

    admin_sk = SigningKey.generate()
    bundle_sk = SigningKey.generate()
    bundle_pub_hex = bytes(bundle_sk.verify_key).hex()
    org_id = "org-fp-test"
    user_id = "user-fp-1"
    iss = "https://idp.test"
    sub_val = "sub-fp-1"

    meta = {
        "server": "https://localhost:9000",
        "key_id": _kid(admin_sk),
        "org_id": org_id,
        "user_id": user_id,
        "iss": iss,
        "sub": sub_val,
    }
    kh = _make_key_home(tmp_path, admin_sk, meta)
    tracker = _genesis_tracker(admin_sk, meta)

    with patch.dict(os.environ, {"SANDBOX_KEY_HOME": str(kh)}):
        with patch("urllib.request.urlopen", side_effect=tracker.urlopen):
            result = CliRunner().invoke(cli, [
                "signer", "genesis",
                "--genesis-code", "code-1",
                "--bundle-signer-key", bundle_pub_hex,
                "--confirm-identity", iss, sub_val,
                "--yes",
            ])

    bad_opt = _detect_unknown_option(result)
    if bad_opt:
        raise M2T12dPending(f"genesis flag not implemented: {bad_opt}")

    # Must exit 0
    assert result.exit_code == 0, (
        f"genesis positive exit {result.exit_code}: {result.output}"
    )
    # Must have posted exactly one genesis envelope
    genesis_posts = [b for u, b in zip(tracker.requested_urls,
                                       tracker.post_bodies)
                     if "/signer/genesis" in u]
    assert len(genesis_posts) == 1, (
        f"expected exactly 1 POST to /genesis, got {len(genesis_posts)}"
    )
    # The printed fingerprint must match the formula
    envelope = genesis_posts[0].get("envelope", {})
    payload = envelope.get("payload", {})
    expected_fp = _fingerprint(payload.get("org_id", ""), payload)
    assert expected_fp in result.output, (
        f"expected fingerprint {expected_fp} not in output: {result.output}"
    )
    # No /config call (F3)
    config_calls = [u for u in tracker.requested_urls if "/config" in u]
    assert config_calls == [], f"genesis called /config: {config_calls}"


def test_genesis_user_id_is_server_id_not_sub():
    """build_genesis must use the server user id, not the IdP sub."""
    from sandbox.connector.sync.signer import build_genesis

    sk = SigningKey.generate()
    org_id = "test-org"
    server_user_id = "srv-user-12345"
    iss = "https://idp.test"
    sub = "idp-subject-67890"
    bundle_pub = bytes(SigningKey.generate().verify_key)

    env, _fp = build_genesis(sk, org_id, iss, sub, bundle_pub,
                             user_id=server_user_id)
    key_entry = env["payload"]["keys"][0]

    assert key_entry["user_id"] != sub, (
        "build_genesis should not use the IdP sub as user_id"
    )
    assert key_entry["user_id"] == server_user_id


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


def test_genesis_approver_flag_adds_approver():
    """'--approver' adds the approver role."""
    from sandbox.cli.main import cli
    runner = CliRunner()
    result = runner.invoke(cli, ["signer", "genesis", "--help"])
    if result.exit_code != 0 and "No such command" in (result.output or ""):
        raise M2T12dPending("genesis command not found")
    if "--approver" not in (result.output or ""):
        raise M2T12dPending("--approver flag not in genesis --help")


# ---------------------------------------------------------------------------
# F3 + stub ruling 1: genesis --bundle-signer-key, no /config
# ---------------------------------------------------------------------------



def test_f3_genesis_requires_bundle_signer_key_flag(tmp_path):
    """F3/stub-ruling-1: genesis without --bundle-signer-key exits 1
    with a message mentioning 'bundle'.  No envelope is posted."""
    from sandbox.cli.main import cli

    # First check if the flag exists at all
    help_result = CliRunner().invoke(cli, ["signer", "genesis", "--help"])
    if "--bundle-signer-key" not in (help_result.output or ""):
        raise M2T12dPending("--bundle-signer-key flag not added to genesis")

    admin_sk = SigningKey.generate()
    meta = {
        "server": "https://localhost:9000",
        "key_id": _kid(admin_sk),
        "org_id": "org-1",
        "user_id": "user-1",
        "iss": "https://idp.test",
        "sub": "sub-1",
    }
    kh = _make_key_home(tmp_path, admin_sk, meta)
    tracker = _genesis_tracker(admin_sk, meta)

    with patch.dict(os.environ, {"SANDBOX_KEY_HOME": str(kh)}):
        with patch("urllib.request.urlopen", side_effect=tracker.urlopen):
            result = CliRunner().invoke(cli, [
                "signer", "genesis",
                "--genesis-code", "code-1",
                "--confirm-identity", "https://idp.test", "sub-1",
                "--yes",
                # NO --bundle-signer-key
            ])

    assert result.exit_code == 1, (
        f"expected exit 1 for missing --bundle-signer-key, "
        f"got {result.exit_code}: {result.output}"
    )
    out = (result.output or "").lower()
    assert "bundle" in out, (
        f"refusal should mention 'bundle': {result.output}"
    )
    genesis_posts = [u for u in tracker.requested_urls
                     if "/signer/genesis" in u]
    assert genesis_posts == [], "posted despite missing --bundle-signer-key"



def test_f3_genesis_never_calls_config(tmp_path):
    """F3/stub-ruling-1: genesis with --bundle-signer-key must never
    request any /config path.  Exits 0 (positive path)."""
    from sandbox.cli.main import cli

    admin_sk = SigningKey.generate()
    bundle_sk = SigningKey.generate()
    bundle_pub_hex = bytes(bundle_sk.verify_key).hex()
    meta = {
        "server": "https://localhost:9000",
        "key_id": _kid(admin_sk),
        "org_id": "org-1",
        "user_id": "user-1",
        "iss": "https://idp.test",
        "sub": "sub-1",
    }
    kh = _make_key_home(tmp_path, admin_sk, meta)
    tracker = _genesis_tracker(admin_sk, meta)

    with patch.dict(os.environ, {"SANDBOX_KEY_HOME": str(kh)}):
        with patch("urllib.request.urlopen", side_effect=tracker.urlopen):
            result = CliRunner().invoke(cli, [
                "signer", "genesis",
                "--genesis-code", "code-1",
                "--bundle-signer-key", bundle_pub_hex,
                "--confirm-identity", "https://idp.test", "sub-1",
                "--yes",
            ])

    bad_opt = _detect_unknown_option(result)
    if bad_opt:
        raise M2T12dPending(f"genesis flag not implemented: {bad_opt}")

    assert result.exit_code == 0, (
        f"genesis with valid --bundle-signer-key should exit 0, "
        f"got {result.exit_code}: {result.output}"
    )
    config_calls = [u for u in tracker.requested_urls if "/config" in u]
    assert config_calls == [], (
        f"genesis must never call /config; called: {config_calls}"
    )


# ---------------------------------------------------------------------------
# F9 + stub ruling 3: genesis identity confirmation
# ---------------------------------------------------------------------------



def test_f9_genesis_refuses_when_link_lacks_iss_sub(tmp_path):
    """F9/stub-ruling-3: genesis exits 1 when link.json lacks iss/sub,
    even with --confirm-identity.  Output mentions 'iss' or 'sub' or
    're-link'.  Nothing posted."""
    from sandbox.cli.main import cli

    admin_sk = SigningKey.generate()
    bundle_sk = SigningKey.generate()
    bundle_pub_hex = bytes(bundle_sk.verify_key).hex()
    meta = {
        "server": "https://localhost:9000",
        "key_id": _kid(admin_sk),
        "org_id": "org-1",
        "user_id": "user-1",
        # no iss, no sub
    }
    kh = _make_key_home(tmp_path, admin_sk, meta)
    tracker = _genesis_tracker(admin_sk, meta)

    with patch.dict(os.environ, {"SANDBOX_KEY_HOME": str(kh)}):
        with patch("urllib.request.urlopen", side_effect=tracker.urlopen):
            result = CliRunner().invoke(cli, [
                "signer", "genesis",
                "--genesis-code", "code-1",
                "--bundle-signer-key", bundle_pub_hex,
                "--confirm-identity", "https://idp.test", "sub-1",
                "--yes",
            ])

    bad_opt = _detect_unknown_option(result)
    if bad_opt:
        raise M2T12dPending(f"genesis flag not implemented: {bad_opt}")

    assert result.exit_code == 1, (
        f"expected exit 1 for missing iss/sub in link.json, "
        f"got {result.exit_code}: {result.output}"
    )
    out = (result.output or "").lower()
    # R2-2: removed bare "link" which could match unrelated messages;
    # kept "re-link" plus the identity-specific keywords.
    assert ("iss" in out or "sub" in out or "re-link" in out
            or "identity" in out), (
        f"refusal should mention identity fields: {result.output}"
    )
    genesis_posts = [u for u in tracker.requested_urls
                     if "/signer/genesis" in u]
    assert genesis_posts == [], "posted despite missing iss/sub"



def test_f9_genesis_refuses_identity_mismatch(tmp_path):
    """F9: --confirm-identity differs from link.json iss/sub -> exit 1,
    output mentions 'identity' or 'mismatch', nothing posted."""
    from sandbox.cli.main import cli

    admin_sk = SigningKey.generate()
    bundle_sk = SigningKey.generate()
    bundle_pub_hex = bytes(bundle_sk.verify_key).hex()
    meta = {
        "server": "https://localhost:9000",
        "key_id": _kid(admin_sk),
        "org_id": "org-1",
        "user_id": "user-1",
        "iss": "https://idp.test",
        "sub": "sub-1",
    }
    kh = _make_key_home(tmp_path, admin_sk, meta)
    tracker = _genesis_tracker(admin_sk, meta)

    with patch.dict(os.environ, {"SANDBOX_KEY_HOME": str(kh)}):
        with patch("urllib.request.urlopen", side_effect=tracker.urlopen):
            result = CliRunner().invoke(cli, [
                "signer", "genesis",
                "--genesis-code", "code-1",
                "--bundle-signer-key", bundle_pub_hex,
                "--confirm-identity", "https://wrong-idp.test", "wrong-sub",
                "--yes",
            ])

    bad_opt = _detect_unknown_option(result)
    if bad_opt:
        raise M2T12dPending(f"genesis flag not implemented: {bad_opt}")

    assert result.exit_code == 1, (
        f"expected exit 1 for identity mismatch, "
        f"got {result.exit_code}: {result.output}"
    )
    out = (result.output or "").lower()
    assert "identity" in out or "mismatch" in out, (
        f"refusal should mention 'identity' or 'mismatch': {result.output}"
    )
    genesis_posts = [u for u in tracker.requested_urls
                     if "/signer/genesis" in u]
    assert genesis_posts == [], "posted despite identity mismatch"


# ---------------------------------------------------------------------------
# F7: token transport safety
# ---------------------------------------------------------------------------



def test_f7_http_non_loopback_refused(tmp_path):
    """F7: http:// to a non-loopback host -> exit 1, output mentions
    'https' or 'http' or 'loopback', nothing posted."""
    from sandbox.cli.main import cli

    admin_sk = SigningKey.generate()
    bundle_pub_hex = bytes(SigningKey.generate().verify_key).hex()
    meta = {
        "server": "http://evil.example.com:9000",  # non-loopback http
        "key_id": _kid(admin_sk),
        "org_id": "org-1",
        "user_id": "u-1",
        "iss": "https://idp",
        "sub": "sub-1",
    }
    kh = _make_key_home(tmp_path, admin_sk, meta)
    tracker = _MockTracker({
        "/signer/token": {"token": "tok"},
        "/signer/genesis": {"version": 1},
    })

    with patch.dict(os.environ, {"SANDBOX_KEY_HOME": str(kh)}):
        with patch("urllib.request.urlopen", side_effect=tracker.urlopen):
            result = CliRunner().invoke(cli, [
                "signer", "genesis",
                "--genesis-code", "code-1",
                "--bundle-signer-key", bundle_pub_hex,
                "--confirm-identity", "https://idp", "sub-1",
                "--yes",
            ])

    bad_opt = _detect_unknown_option(result)
    if bad_opt:
        raise M2T12dPending(f"genesis flag not implemented: {bad_opt}")

    assert result.exit_code == 1, (
        f"expected exit 1 for http non-loopback, "
        f"got {result.exit_code}: {result.output}"
    )
    out = (result.output or "").lower()
    assert "https" in out or "http" in out or "loopback" in out, (
        f"refusal should mention transport: {result.output}"
    )
    genesis_posts = [u for u in tracker.requested_urls
                     if "/signer/genesis" in u]
    assert genesis_posts == [], "posted over http non-loopback"



def test_f7_redirect_refused(tmp_path):
    """F7: a 3xx redirect on the genesis POST -> exit 1, output mentions
    'redirect', 'Published' never printed.  R2-2: the redirect is on
    /genesis (not /token) so the assertion tests the redirect reason,
    not a swallowed-token failure."""
    from sandbox.cli.main import cli

    admin_sk = SigningKey.generate()
    bundle_pub_hex = bytes(SigningKey.generate().verify_key).hex()
    meta = {
        "server": "https://localhost:9000",
        "key_id": _kid(admin_sk),
        "org_id": "org-1",
        "user_id": "u-1",
        "iss": "https://idp",
        "sub": "sub-1",
    }
    kh = _make_key_home(tmp_path, admin_sk, meta)
    tracker = _MockTracker({
        "/signer/token": {"token": "tok-redir"},
        "/signer/genesis": HTTPError(
            "https://localhost:9000/api/v1/sync/signer/genesis",
            302, "Found",
            {"Location": "https://evil.example.com/genesis"},
            io.BytesIO(b""),
        ),
    })

    with patch.dict(os.environ, {"SANDBOX_KEY_HOME": str(kh)}):
        with patch("urllib.request.urlopen", side_effect=tracker.urlopen):
            result = CliRunner().invoke(cli, [
                "signer", "genesis",
                "--genesis-code", "code-1",
                "--bundle-signer-key", bundle_pub_hex,
                "--confirm-identity", "https://idp", "sub-1",
                "--yes",
            ])

    bad_opt = _detect_unknown_option(result)
    if bad_opt:
        raise M2T12dPending(f"genesis flag not implemented: {bad_opt}")

    assert result.exit_code == 1, (
        f"expected exit 1 for redirect, "
        f"got {result.exit_code}: {result.output}"
    )
    out = (result.output or "").lower()
    # R2-2: assert the redirect-specific reason, not "token" which an
    # exposure or swallowed-error refusal would also match.
    assert "redirect" in out, (
        f"refusal should mention 'redirect': {result.output}"
    )
    assert "published" not in out, (
        f"'Published' should never appear after a redirect: {result.output}"
    )


# ---------------------------------------------------------------------------
# F12: genesis hygiene
# ---------------------------------------------------------------------------



def test_f12_genesis_refuses_empty_org_id(tmp_path):
    """F12: genesis with empty org_id -> exit 1, output mentions 'org',
    nothing posted."""
    from sandbox.cli.main import cli

    admin_sk = SigningKey.generate()
    bundle_pub_hex = bytes(SigningKey.generate().verify_key).hex()
    meta = {
        "server": "https://localhost:9000",
        "key_id": _kid(admin_sk),
        "org_id": "",  # empty
        "user_id": "u-1",
        "iss": "https://idp",
        "sub": "sub-1",
    }
    kh = _make_key_home(tmp_path, admin_sk, meta)
    tracker = _genesis_tracker(admin_sk, meta)

    with patch.dict(os.environ, {"SANDBOX_KEY_HOME": str(kh)}):
        with patch("urllib.request.urlopen", side_effect=tracker.urlopen):
            result = CliRunner().invoke(cli, [
                "signer", "genesis",
                "--genesis-code", "code-1",
                "--bundle-signer-key", bundle_pub_hex,
                "--confirm-identity", "https://idp", "sub-1",
                "--yes",
            ])

    bad_opt = _detect_unknown_option(result)
    if bad_opt:
        raise M2T12dPending(f"genesis flag not implemented: {bad_opt}")

    assert result.exit_code == 1, (
        f"expected exit 1 for empty org_id, "
        f"got {result.exit_code}: {result.output}"
    )
    out = (result.output or "").lower()
    assert "org" in out or "empty" in out, (
        f"refusal should mention 'org': {result.output}"
    )
    genesis_posts = [u for u in tracker.requested_urls
                     if "/signer/genesis" in u]
    assert genesis_posts == [], "posted despite empty org_id"



def test_f12_genesis_refuses_empty_user_id(tmp_path):
    """F12: genesis with empty user_id -> exit 1, output mentions 'user',
    nothing posted."""
    from sandbox.cli.main import cli

    admin_sk = SigningKey.generate()
    bundle_pub_hex = bytes(SigningKey.generate().verify_key).hex()
    meta = {
        "server": "https://localhost:9000",
        "key_id": _kid(admin_sk),
        "org_id": "org-1",
        "user_id": "",  # empty
        "iss": "https://idp",
        "sub": "sub-1",
    }
    kh = _make_key_home(tmp_path, admin_sk, meta)
    tracker = _genesis_tracker(admin_sk, meta)

    with patch.dict(os.environ, {"SANDBOX_KEY_HOME": str(kh)}):
        with patch("urllib.request.urlopen", side_effect=tracker.urlopen):
            result = CliRunner().invoke(cli, [
                "signer", "genesis",
                "--genesis-code", "code-1",
                "--bundle-signer-key", bundle_pub_hex,
                "--confirm-identity", "https://idp", "sub-1",
                "--yes",
            ])

    bad_opt = _detect_unknown_option(result)
    if bad_opt:
        raise M2T12dPending(f"genesis flag not implemented: {bad_opt}")

    assert result.exit_code == 1, (
        f"expected exit 1 for empty user_id, "
        f"got {result.exit_code}: {result.output}"
    )
    out = (result.output or "").lower()
    assert "user" in out or "empty" in out, (
        f"refusal should mention 'user': {result.output}"
    )
    genesis_posts = [u for u in tracker.requested_urls
                     if "/signer/genesis" in u]
    assert genesis_posts == [], "posted despite empty user_id"


# ---------------------------------------------------------------------------
# F4: seed file hardening
# ---------------------------------------------------------------------------


@pytest.mark.skipif(platform.system() == "Windows",
                    reason="POSIX mode checks only")
def test_f4_seed_file_mode_posix(tmp_path):
    """F4: on POSIX the signer seed must be 0o600 in a 0o700 directory."""
    from sandbox.cli.main import cli

    tracker = _MockTracker({
        "/signer/link": {
            "org_id": "org-1", "user_id": "u-1",
            "iss": "https://idp", "sub": "sub-1",
        },
    })

    kh = tmp_path / "keyhome"
    kh.mkdir()

    with patch.dict(os.environ, {"SANDBOX_KEY_HOME": str(kh)}):
        with patch("urllib.request.urlopen", side_effect=tracker.urlopen):
            result = CliRunner().invoke(cli, [
                "signer", "link",
                "--code", "test-code",
                "--server", "https://localhost:9000",
            ])

    if result.exit_code != 0:
        pytest.fail(f"link command failed (exit {result.exit_code}): {result.output}")

    signer_dir = kh / "signer"
    seed_path = signer_dir / "signer.seed"

    if not seed_path.exists():
        pytest.fail("seed file not created")

    dir_mode = signer_dir.stat().st_mode & 0o777
    file_mode = seed_path.stat().st_mode & 0o777

    assert dir_mode == 0o700, (
        f"signer dir mode {oct(dir_mode)} should be 0o700"
    )
    assert file_mode == 0o600, (
        f"seed file mode {oct(file_mode)} should be 0o600"
    )



def test_f4_seed_load_refuses_wrong_length(tmp_path):
    """F4: loading a non-32-byte seed -> exit 1, output mentions 'length'
    or '32', nothing posted.  R2-2: the signer dir is 0o700 on POSIX so
    the refusal is the length check, not exposure."""
    from sandbox.cli.main import cli

    signer_dir = tmp_path / "signer"
    signer_dir.mkdir(parents=True)
    seed_path = signer_dir / "signer.seed"
    seed_path.write_bytes(b"short")
    (signer_dir / "link.json").write_text(json.dumps({
        "server": "https://localhost:9000",
        "key_id": "dummy",
        "org_id": "org-1",
        "user_id": "u-1",
        "iss": "https://idp",
        "sub": "sub-1",
    }), encoding="utf-8")
    # R2-2: tighten POSIX modes so exposure check passes
    if os.name != "nt":
        os.chmod(signer_dir, 0o700)
        os.chmod(seed_path, 0o600)
    tracker = _genesis_tracker(None, {})

    with patch.dict(os.environ, {"SANDBOX_KEY_HOME": str(tmp_path)}):
        with patch("urllib.request.urlopen", side_effect=tracker.urlopen):
            result = CliRunner().invoke(cli, [
                "signer", "genesis",
                "--genesis-code", "code-1",
                "--bundle-signer-key", "aa" * 32,
                "--confirm-identity", "https://idp", "sub-1",
                "--yes",
            ])

    bad_opt = _detect_unknown_option(result)
    if bad_opt:
        raise M2T12dPending(f"genesis flag not implemented: {bad_opt}")

    assert result.exit_code == 1, (
        f"expected exit 1 for non-32-byte seed, "
        f"got {result.exit_code}: {result.output}"
    )
    out = (result.output or "").lower()
    # R2-2: assert the length-specific reason, not a generic keyword
    # that an exposure refusal ("key home exposure") would also match.
    assert "length" in out or "32" in out, (
        f"refusal should mention 'length' or '32': {result.output}"
    )
    genesis_posts = [u for u in tracker.requested_urls
                     if "/signer/genesis" in u]
    assert genesis_posts == [], "posted despite bad seed"



def test_f4_seed_load_refuses_exposed(tmp_path):
    """F4: loading seed from an exposed directory -> exit 1, output
    mentions 'exposure' or 'permission', nothing posted."""
    from sandbox.cli.main import cli

    sk = SigningKey.generate()
    signer_dir = tmp_path / "signer"
    signer_dir.mkdir(parents=True)
    (signer_dir / "signer.seed").write_bytes(bytes(sk))
    (signer_dir / "link.json").write_text(json.dumps({
        "server": "https://localhost:9000",
        "key_id": _kid(sk),
        "org_id": "org-1",
        "user_id": "u-1",
        "iss": "https://idp",
        "sub": "sub-1",
    }), encoding="utf-8")
    tracker = _genesis_tracker(sk, {})

    with patch.dict(os.environ, {"SANDBOX_KEY_HOME": str(tmp_path)}):
        with patch("sandbox.connector.keyhome.root_exposure",
                   return_value="mode 0o755 lets group or others in"):
            with patch("urllib.request.urlopen",
                       side_effect=tracker.urlopen):
                result = CliRunner().invoke(cli, [
                    "signer", "genesis",
                    "--genesis-code", "code-1",
                    "--bundle-signer-key", "aa" * 32,
                    "--confirm-identity", "https://idp", "sub-1",
                    "--yes",
                ])

    bad_opt = _detect_unknown_option(result)
    if bad_opt:
        raise M2T12dPending(f"genesis flag not implemented: {bad_opt}")

    assert result.exit_code == 1, (
        f"expected exit 1 for exposed key home, "
        f"got {result.exit_code}: {result.output}"
    )
    out = (result.output or "").lower()
    assert ("expos" in out or "permission" in out or "mode" in out
            or "acl" in out), (
        f"refusal should mention exposure: {result.output}"
    )
    genesis_posts = [u for u in tracker.requested_urls
                     if "/signer/genesis" in u]
    assert genesis_posts == [], "posted despite exposed key home"


# ---------------------------------------------------------------------------
# F1: --confirm-key-id must equal added set exactly
# Positive control first, then refusals.
# ---------------------------------------------------------------------------



def test_f1_positive_build_correct_confirm(tmp_path):
    """F1 positive: sign-registry build mode with correct --confirm-key-id
    for the added key exits 0 and publishes exactly once."""
    from sandbox.cli.main import cli

    admin_sk = SigningKey.generate()
    bundle_sk = SigningKey.generate()
    org_id = "org-f1pos"
    bundle_pub = bytes(bundle_sk.verify_key)

    v1_env, fp = _build_valid_chain_v1(
        admin_sk, org_id, "https://idp", "sub-1", bundle_pub, user_id="u1"
    )

    carol_sk = SigningKey.generate()
    carol_kid = _kid(carol_sk)

    meta = {
        "server": "https://localhost:9000",
        "key_id": _kid(admin_sk),
        "org_id": org_id,
        "user_id": "u1",
        "iss": "https://idp",
        "sub": "sub-1",
    }
    kh = _make_key_home(tmp_path, admin_sk, meta)
    tracker = _signreg_tracker(v1_env, candidates=[{
        "key_id": carol_kid,
        "public_key": bytes(carol_sk.verify_key).hex(),
        "user_id": "carol-u",
        "iss": "https://idp",
        "sub": "sub-carol",
        "kind": "cli",
    }])

    with patch.dict(os.environ, {"SANDBOX_KEY_HOME": str(kh)}):
        with patch("urllib.request.urlopen", side_effect=tracker.urlopen):
            result = CliRunner().invoke(cli, [
                "signer", "sign-registry",
                "--add", carol_kid,
                "--confirm-key-id", carol_kid,
                "--expect-fingerprint", fp,
                "--publish",
                "--yes",
            ])

    bad_opt = _detect_unknown_option(result)
    if bad_opt:
        raise M2T12dPending(
            f"sign-registry flag not implemented: {bad_opt}"
        )

    assert result.exit_code == 0, (
        f"F1 positive exit {result.exit_code}: {result.output}"
    )
    sig_posts = [u for u in tracker.requested_urls
                 if "/signer/signatures" in u]
    assert len(sig_posts) == 1, (
        f"expected exactly 1 POST to /signatures, got {len(sig_posts)}"
    )



def test_f1_sign_registry_missing_confirm_key_id_refuses(tmp_path):
    """F1: no --confirm-key-id when keys are added -> exit 1, output
    mentions 'confirm' or 'key_id', nothing published."""
    from sandbox.cli.main import cli

    admin_sk = SigningKey.generate()
    bundle_sk = SigningKey.generate()
    org_id = "org-f1"
    bundle_pub = bytes(bundle_sk.verify_key)
    v1_env, fp = _build_valid_chain_v1(
        admin_sk, org_id, "https://idp", "sub-1", bundle_pub, user_id="u1"
    )

    carol_sk = SigningKey.generate()
    carol_kid = _kid(carol_sk)

    meta = {
        "server": "https://localhost:9000",
        "key_id": _kid(admin_sk),
        "org_id": org_id,
        "user_id": "u1",
        "iss": "https://idp",
        "sub": "sub-1",
    }
    kh = _make_key_home(tmp_path, admin_sk, meta)
    tracker = _signreg_tracker(v1_env, candidates=[{
        "key_id": carol_kid,
        "public_key": bytes(carol_sk.verify_key).hex(),
        "user_id": "carol-u",
        "iss": "https://idp",
        "sub": "sub-carol",
        "kind": "cli",
    }])

    with patch.dict(os.environ, {"SANDBOX_KEY_HOME": str(kh)}):
        with patch("urllib.request.urlopen", side_effect=tracker.urlopen):
            result = CliRunner().invoke(cli, [
                "signer", "sign-registry",
                "--add", carol_kid,
                "--expect-fingerprint", fp,
                "--publish",
                "--yes",
                # NO --confirm-key-id
            ])

    bad_opt = _detect_unknown_option(result)
    if bad_opt:
        raise M2T12dPending(
            f"sign-registry flag not implemented: {bad_opt}"
        )

    assert result.exit_code == 1, (
        f"expected exit 1 for missing --confirm-key-id, "
        f"got {result.exit_code}: {result.output}"
    )
    out = (result.output or "").lower()
    assert "confirm" in out or "key_id" in out or "key-id" in out, (
        f"refusal should mention confirm/key_id: {result.output}"
    )
    sig_posts = [u for u in tracker.requested_urls
                 if "/signer/signatures" in u]
    assert sig_posts == [], "published despite missing --confirm-key-id"



def test_f1_sign_registry_wrong_confirm_key_id_refuses(tmp_path):
    """F1: wrong --confirm-key-id -> exit 1, output mentions 'confirm' or
    'key_id', nothing written or published."""
    from sandbox.cli.main import cli

    admin_sk = SigningKey.generate()
    bundle_sk = SigningKey.generate()
    org_id = "org-f1b"
    bundle_pub = bytes(bundle_sk.verify_key)
    v1_env, fp = _build_valid_chain_v1(
        admin_sk, org_id, "https://idp", "sub-1", bundle_pub, user_id="u1"
    )

    carol_sk = SigningKey.generate()
    carol_kid = _kid(carol_sk)

    meta = {
        "server": "https://localhost:9000",
        "key_id": _kid(admin_sk),
        "org_id": org_id,
        "user_id": "u1",
        "iss": "https://idp",
        "sub": "sub-1",
    }
    kh = _make_key_home(tmp_path, admin_sk, meta)
    out_file = tmp_path / "out.json"
    tracker = _signreg_tracker(v1_env, candidates=[{
        "key_id": carol_kid,
        "public_key": bytes(carol_sk.verify_key).hex(),
        "user_id": "carol-u",
        "iss": "https://idp",
        "sub": "sub-carol",
        "kind": "cli",
    }])

    with patch.dict(os.environ, {"SANDBOX_KEY_HOME": str(kh)}):
        with patch("urllib.request.urlopen", side_effect=tracker.urlopen):
            result = CliRunner().invoke(cli, [
                "signer", "sign-registry",
                "--add", carol_kid,
                "--confirm-key-id", "deadbeef",  # wrong
                "--expect-fingerprint", fp,
                "--out", str(out_file),
                "--publish",
                "--yes",
            ])

    bad_opt = _detect_unknown_option(result)
    if bad_opt:
        raise M2T12dPending(
            f"sign-registry flag not implemented: {bad_opt}"
        )

    assert result.exit_code == 1, (
        f"expected exit 1 for wrong --confirm-key-id, "
        f"got {result.exit_code}: {result.output}"
    )
    out = (result.output or "").lower()
    assert "confirm" in out or "key_id" in out or "key-id" in out, (
        f"refusal should mention confirm/key_id: {result.output}"
    )
    assert not out_file.exists(), "--out written despite wrong confirm"
    sig_posts = [u for u in tracker.requested_urls
                 if "/signer/signatures" in u]
    assert sig_posts == [], "published despite wrong --confirm-key-id"



def test_f1_sign_registry_confirm_set_must_equal_added(tmp_path):
    """F1: extra --confirm-key-id beyond the added set -> exit 1,
    output mentions 'confirm' or 'key_id', nothing published."""
    from sandbox.cli.main import cli

    admin_sk = SigningKey.generate()
    bundle_sk = SigningKey.generate()
    org_id = "org-f1c"
    bundle_pub = bytes(bundle_sk.verify_key)
    v1_env, fp = _build_valid_chain_v1(
        admin_sk, org_id, "https://idp", "sub-1", bundle_pub, user_id="u1"
    )

    carol_sk = SigningKey.generate()
    carol_kid = _kid(carol_sk)

    meta = {
        "server": "https://localhost:9000",
        "key_id": _kid(admin_sk),
        "org_id": org_id,
        "user_id": "u1",
        "iss": "https://idp",
        "sub": "sub-1",
    }
    kh = _make_key_home(tmp_path, admin_sk, meta)
    tracker = _signreg_tracker(v1_env, candidates=[{
        "key_id": carol_kid,
        "public_key": bytes(carol_sk.verify_key).hex(),
        "user_id": "carol-u",
        "iss": "https://idp",
        "sub": "sub-carol",
        "kind": "cli",
    }])

    with patch.dict(os.environ, {"SANDBOX_KEY_HOME": str(kh)}):
        with patch("urllib.request.urlopen", side_effect=tracker.urlopen):
            result = CliRunner().invoke(cli, [
                "signer", "sign-registry",
                "--add", carol_kid,
                "--confirm-key-id", carol_kid,
                "--confirm-key-id", "phantom-extra",  # extra
                "--expect-fingerprint", fp,
                "--publish",
                "--yes",
            ])

    bad_opt = _detect_unknown_option(result)
    if bad_opt:
        raise M2T12dPending(
            f"sign-registry flag not implemented: {bad_opt}"
        )

    assert result.exit_code == 1, (
        f"expected exit 1 for extra --confirm-key-id, "
        f"got {result.exit_code}: {result.output}"
    )
    out = (result.output or "").lower()
    assert "confirm" in out or "key_id" in out or "key-id" in out, (
        f"refusal should mention confirm/key_id: {result.output}"
    )
    sig_posts = [u for u in tracker.requested_urls
                 if "/signer/signatures" in u]
    assert sig_posts == [], "published despite extra --confirm-key-id"


# ---------------------------------------------------------------------------
# F2 + stub ruling 2: co-sign chain verification
# Positive control first, then refusals.
# ---------------------------------------------------------------------------



def test_f2_positive_cosign_valid_chain(tmp_path):
    """F2 positive: co-sign --in with a valid partial that chains correctly
    from the verified latest exits 0 and writes --out."""
    from sandbox.cli.main import cli
    from sandbox.protocol.envelope import canonical_bytes
    from sandbox.protocol.domains import REGISTRY

    admin_sk = SigningKey.generate()
    carol_sk = SigningKey.generate()
    bundle_sk = SigningKey.generate()
    org_id = "org-f2pos"
    bundle_pub = bytes(bundle_sk.verify_key)
    v1_env, fp = _build_valid_chain_v1(
        admin_sk, org_id, "https://idp", "sub-1", bundle_pub, user_id="u1"
    )

    # Build a valid v2 partial (no signatures yet) that chains from v1
    v2_payload = {
        "org_id": org_id, "version": 2,
        "prev_hash": _payload_hash(v1_env["payload"]),
        "threshold": 1,
        "admins": v1_env["payload"]["admins"],
        "keys": v1_env["payload"]["keys"],
        "bundle_signer": v1_env["payload"]["bundle_signer"],
        "expires_at": v1_env["payload"]["expires_at"],
    }
    partial = {
        "kind": REGISTRY,
        "sig_v": 1,
        "payload": v2_payload,
        "signatures": [],  # no sigs yet, carol will co-sign
    }
    in_file = tmp_path / "partial.json"
    in_file.write_text(json.dumps(partial), encoding="utf-8")

    # Carol is the co-signer (different from admin)
    meta = {
        "server": "https://localhost:9000",
        "key_id": _kid(admin_sk),
        "org_id": org_id,
        "user_id": "u1",
        "iss": "https://idp",
        "sub": "sub-1",
    }
    kh = _make_key_home(tmp_path / "kh", admin_sk, meta)
    tracker = _signreg_tracker(v1_env)

    out_file = tmp_path / "out.json"

    with patch.dict(os.environ, {"SANDBOX_KEY_HOME": str(kh)}):
        with patch("urllib.request.urlopen", side_effect=tracker.urlopen):
            result = CliRunner().invoke(cli, [
                "signer", "sign-registry",
                "--in", str(in_file),
                "--out", str(out_file),
                "--expect-fingerprint", fp,
                "--yes",
            ])

    bad_opt = _detect_unknown_option(result)
    if bad_opt:
        raise M2T12dPending(
            f"sign-registry flag not implemented: {bad_opt}"
        )

    assert result.exit_code == 0, (
        f"F2 positive co-sign exit {result.exit_code}: {result.output}"
    )
    assert out_file.exists(), "co-sign did not write --out"



def test_f2_cosign_unfetchable_latest_refuses(tmp_path):
    """F2: chain fetch fails -> exit 1, output mentions 'chain' or 'fetch'
    or 'registry', nothing written."""
    from sandbox.cli.main import cli
    from sandbox.protocol.domains import REGISTRY

    admin_sk = SigningKey.generate()
    bundle_sk = SigningKey.generate()
    org_id = "org-f2"
    bundle_pub = bytes(bundle_sk.verify_key)
    v1_env, fp = _build_valid_chain_v1(
        admin_sk, org_id, "https://idp", "sub-1", bundle_pub, user_id="u1"
    )

    partial = {
        "kind": REGISTRY, "sig_v": 1,
        "payload": {
            "org_id": org_id, "version": 2,
            "prev_hash": _payload_hash(v1_env["payload"]),
            "threshold": 1,
            "admins": v1_env["payload"]["admins"],
            "keys": v1_env["payload"]["keys"],
            "bundle_signer": v1_env["payload"]["bundle_signer"],
            "expires_at": v1_env["payload"]["expires_at"],
        },
        "signatures": [],
    }
    in_file = tmp_path / "partial.json"
    in_file.write_text(json.dumps(partial), encoding="utf-8")

    meta = {
        "server": "https://localhost:9000",
        "key_id": _kid(admin_sk),
        "org_id": org_id,
        "user_id": "u1",
        "iss": "https://idp",
        "sub": "sub-1",
    }
    kh = _make_key_home(tmp_path / "kh", admin_sk, meta)
    tracker = _MockTracker({
        "/signer/token": {"token": "tok"},
        "/signer/registry": URLError("connection refused"),
    })

    out_file = tmp_path / "out.json"

    with patch.dict(os.environ, {"SANDBOX_KEY_HOME": str(kh)}):
        with patch("urllib.request.urlopen", side_effect=tracker.urlopen):
            result = CliRunner().invoke(cli, [
                "signer", "sign-registry",
                "--in", str(in_file),
                "--out", str(out_file),
                "--expect-fingerprint", fp,
                "--yes",
            ])

    bad_opt = _detect_unknown_option(result)
    if bad_opt:
        raise M2T12dPending(
            f"sign-registry flag not implemented: {bad_opt}"
        )

    assert result.exit_code == 1, (
        f"expected exit 1 for unfetchable chain, "
        f"got {result.exit_code}: {result.output}"
    )
    out = (result.output or "").lower()
    assert ("chain" in out or "fetch" in out or "registry" in out
            or "connect" in out), (
        f"refusal should mention chain fetch: {result.output}"
    )
    assert not out_file.exists(), "--out written despite unfetchable chain"



def test_f2_cosign_bad_prev_hash_refuses(tmp_path):
    """F2: prev_hash mismatch -> exit 1, output mentions 'prev_hash' or
    'hash', nothing written."""
    from sandbox.cli.main import cli
    from sandbox.protocol.domains import REGISTRY

    admin_sk = SigningKey.generate()
    bundle_sk = SigningKey.generate()
    org_id = "org-f2b"
    bundle_pub = bytes(bundle_sk.verify_key)
    v1_env, fp = _build_valid_chain_v1(
        admin_sk, org_id, "https://idp", "sub-1", bundle_pub, user_id="u1"
    )

    partial = {
        "kind": REGISTRY, "sig_v": 1,
        "payload": {
            "org_id": org_id, "version": 2,
            "prev_hash": "0000bogus",  # wrong
            "threshold": 1,
            "admins": v1_env["payload"]["admins"],
            "keys": v1_env["payload"]["keys"],
            "bundle_signer": v1_env["payload"]["bundle_signer"],
            "expires_at": v1_env["payload"]["expires_at"],
        },
        "signatures": [],
    }
    in_file = tmp_path / "partial.json"
    in_file.write_text(json.dumps(partial), encoding="utf-8")

    meta = {
        "server": "https://localhost:9000",
        "key_id": _kid(admin_sk),
        "org_id": org_id,
        "user_id": "u1",
        "iss": "https://idp",
        "sub": "sub-1",
    }
    kh = _make_key_home(tmp_path / "kh", admin_sk, meta)
    tracker = _signreg_tracker(v1_env)

    out_file = tmp_path / "out.json"

    with patch.dict(os.environ, {"SANDBOX_KEY_HOME": str(kh)}):
        with patch("urllib.request.urlopen", side_effect=tracker.urlopen):
            result = CliRunner().invoke(cli, [
                "signer", "sign-registry",
                "--in", str(in_file),
                "--out", str(out_file),
                "--expect-fingerprint", fp,
                "--yes",
            ])

    bad_opt = _detect_unknown_option(result)
    if bad_opt:
        raise M2T12dPending(
            f"sign-registry flag not implemented: {bad_opt}"
        )

    assert result.exit_code == 1, (
        f"expected exit 1 for bad prev_hash, "
        f"got {result.exit_code}: {result.output}"
    )
    out = (result.output or "").lower()
    assert "prev_hash" in out or "hash" in out or "chain" in out, (
        f"refusal should mention hash: {result.output}"
    )
    assert not out_file.exists(), "--out written despite bad prev_hash"



def test_f2_cosign_wrong_version_refuses(tmp_path):
    """F2: version != latest+1 -> exit 1, output mentions 'version',
    nothing written."""
    from sandbox.cli.main import cli
    from sandbox.protocol.domains import REGISTRY

    admin_sk = SigningKey.generate()
    bundle_sk = SigningKey.generate()
    org_id = "org-f2c"
    bundle_pub = bytes(bundle_sk.verify_key)
    v1_env, fp = _build_valid_chain_v1(
        admin_sk, org_id, "https://idp", "sub-1", bundle_pub, user_id="u1"
    )

    partial = {
        "kind": REGISTRY, "sig_v": 1,
        "payload": {
            "org_id": org_id, "version": 5,  # should be 2
            "prev_hash": _payload_hash(v1_env["payload"]),
            "threshold": 1,
            "admins": v1_env["payload"]["admins"],
            "keys": v1_env["payload"]["keys"],
            "bundle_signer": v1_env["payload"]["bundle_signer"],
            "expires_at": v1_env["payload"]["expires_at"],
        },
        "signatures": [],
    }
    in_file = tmp_path / "partial.json"
    in_file.write_text(json.dumps(partial), encoding="utf-8")

    meta = {
        "server": "https://localhost:9000",
        "key_id": _kid(admin_sk),
        "org_id": org_id,
        "user_id": "u1",
        "iss": "https://idp",
        "sub": "sub-1",
    }
    kh = _make_key_home(tmp_path / "kh", admin_sk, meta)
    tracker = _signreg_tracker(v1_env)

    out_file = tmp_path / "out.json"

    with patch.dict(os.environ, {"SANDBOX_KEY_HOME": str(kh)}):
        with patch("urllib.request.urlopen", side_effect=tracker.urlopen):
            result = CliRunner().invoke(cli, [
                "signer", "sign-registry",
                "--in", str(in_file),
                "--out", str(out_file),
                "--expect-fingerprint", fp,
                "--yes",
            ])

    bad_opt = _detect_unknown_option(result)
    if bad_opt:
        raise M2T12dPending(
            f"sign-registry flag not implemented: {bad_opt}"
        )

    assert result.exit_code == 1, (
        f"expected exit 1 for wrong version, "
        f"got {result.exit_code}: {result.output}"
    )
    out = (result.output or "").lower()
    assert "version" in out, (
        f"refusal should mention 'version': {result.output}"
    )
    assert not out_file.exists(), "--out written despite wrong version"



def test_f2_cosign_wrong_org_refuses(tmp_path):
    """F2: org_id mismatch -> exit 1, output mentions 'org', nothing
    written."""
    from sandbox.cli.main import cli
    from sandbox.protocol.domains import REGISTRY

    admin_sk = SigningKey.generate()
    bundle_sk = SigningKey.generate()
    org_id = "org-f2d"
    bundle_pub = bytes(bundle_sk.verify_key)
    v1_env, fp = _build_valid_chain_v1(
        admin_sk, org_id, "https://idp", "sub-1", bundle_pub, user_id="u1"
    )

    partial = {
        "kind": REGISTRY, "sig_v": 1,
        "payload": {
            "org_id": "WRONG-ORG", "version": 2,
            "prev_hash": _payload_hash(v1_env["payload"]),
            "threshold": 1,
            "admins": v1_env["payload"]["admins"],
            "keys": v1_env["payload"]["keys"],
            "bundle_signer": v1_env["payload"]["bundle_signer"],
            "expires_at": v1_env["payload"]["expires_at"],
        },
        "signatures": [],
    }
    in_file = tmp_path / "partial.json"
    in_file.write_text(json.dumps(partial), encoding="utf-8")

    meta = {
        "server": "https://localhost:9000",
        "key_id": _kid(admin_sk),
        "org_id": org_id,
        "user_id": "u1",
        "iss": "https://idp",
        "sub": "sub-1",
    }
    kh = _make_key_home(tmp_path / "kh", admin_sk, meta)
    tracker = _signreg_tracker(v1_env)

    out_file = tmp_path / "out.json"

    with patch.dict(os.environ, {"SANDBOX_KEY_HOME": str(kh)}):
        with patch("urllib.request.urlopen", side_effect=tracker.urlopen):
            result = CliRunner().invoke(cli, [
                "signer", "sign-registry",
                "--in", str(in_file),
                "--out", str(out_file),
                "--expect-fingerprint", fp,
                "--yes",
            ])

    bad_opt = _detect_unknown_option(result)
    if bad_opt:
        raise M2T12dPending(
            f"sign-registry flag not implemented: {bad_opt}"
        )

    assert result.exit_code == 1, (
        f"expected exit 1 for wrong org, "
        f"got {result.exit_code}: {result.output}"
    )
    out = (result.output or "").lower()
    assert "org" in out, (
        f"refusal should mention 'org': {result.output}"
    )
    assert not out_file.exists(), "--out written despite wrong org"



def test_f2_cosign_bad_existing_signature_refuses(tmp_path):
    """F2: invalid existing signature -> exit 1, output mentions
    'signature' or 'sig', nothing written."""
    from sandbox.cli.main import cli
    from sandbox.protocol.domains import REGISTRY

    admin_sk = SigningKey.generate()
    bundle_sk = SigningKey.generate()
    org_id = "org-f2e"
    bundle_pub = bytes(bundle_sk.verify_key)
    v1_env, fp = _build_valid_chain_v1(
        admin_sk, org_id, "https://idp", "sub-1", bundle_pub, user_id="u1"
    )

    v2_payload = {
        "org_id": org_id, "version": 2,
        "prev_hash": _payload_hash(v1_env["payload"]),
        "threshold": 1,
        "admins": v1_env["payload"]["admins"],
        "keys": v1_env["payload"]["keys"],
        "bundle_signer": v1_env["payload"]["bundle_signer"],
        "expires_at": v1_env["payload"]["expires_at"],
    }
    partial = {
        "kind": REGISTRY, "sig_v": 1,
        "payload": v2_payload,
        "signatures": [{
            "key_id": _kid(admin_sk),
            "alg": "ed25519",
            "sig": "00" * 64,  # forged
        }],
    }
    in_file = tmp_path / "partial.json"
    in_file.write_text(json.dumps(partial), encoding="utf-8")

    meta = {
        "server": "https://localhost:9000",
        "key_id": _kid(admin_sk),
        "org_id": org_id,
        "user_id": "u1",
        "iss": "https://idp",
        "sub": "sub-1",
    }
    kh = _make_key_home(tmp_path / "kh", admin_sk, meta)
    tracker = _signreg_tracker(v1_env)

    out_file = tmp_path / "out.json"

    with patch.dict(os.environ, {"SANDBOX_KEY_HOME": str(kh)}):
        with patch("urllib.request.urlopen", side_effect=tracker.urlopen):
            result = CliRunner().invoke(cli, [
                "signer", "sign-registry",
                "--in", str(in_file),
                "--out", str(out_file),
                "--expect-fingerprint", fp,
                "--yes",
            ])

    bad_opt = _detect_unknown_option(result)
    if bad_opt:
        raise M2T12dPending(
            f"sign-registry flag not implemented: {bad_opt}"
        )

    assert result.exit_code == 1, (
        f"expected exit 1 for bad existing sig, "
        f"got {result.exit_code}: {result.output}"
    )
    out = (result.output or "").lower()
    assert "sig" in out, (
        f"refusal should mention 'sig': {result.output}"
    )
    assert not out_file.exists(), "--out written despite bad sig"



def test_sign_registry_checks_chain_from_latest_version(tmp_path):
    """F6 replacement: own key_id already in signatures -> exit 1, output
    mentions 'duplicate' or 'already' or 'own', nothing written/published."""
    from sandbox.cli.main import cli
    from sandbox.protocol.envelope import canonical_bytes
    from sandbox.protocol.domains import REGISTRY

    admin_sk = SigningKey.generate()
    bundle_sk = SigningKey.generate()
    org_id = "org-chain"
    bundle_pub = bytes(bundle_sk.verify_key)
    v1_env, fp = _build_valid_chain_v1(
        admin_sk, org_id, "https://idp", "sub-1", bundle_pub, user_id="u1"
    )

    v2_payload = {
        "org_id": org_id, "version": 2,
        "prev_hash": _payload_hash(v1_env["payload"]),
        "threshold": 1,
        "admins": v1_env["payload"]["admins"],
        "keys": v1_env["payload"]["keys"],
        "bundle_signer": v1_env["payload"]["bundle_signer"],
        "expires_at": v1_env["payload"]["expires_at"],
    }

    msg = canonical_bytes(REGISTRY, v2_payload)
    own_sig = admin_sk.sign(msg).signature.hex()

    partial = {
        "kind": REGISTRY, "sig_v": 1,
        "payload": v2_payload,
        "signatures": [{
            "key_id": _kid(admin_sk),
            "alg": "ed25519",
            "sig": own_sig,
        }],
    }
    in_file = tmp_path / "partial.json"
    in_file.write_text(json.dumps(partial), encoding="utf-8")

    meta = {
        "server": "https://localhost:9000",
        "key_id": _kid(admin_sk),
        "org_id": org_id,
        "user_id": "u1",
        "iss": "https://idp",
        "sub": "sub-1",
    }
    kh = _make_key_home(tmp_path / "kh", admin_sk, meta)
    tracker = _signreg_tracker(v1_env)

    out_file = tmp_path / "out.json"

    with patch.dict(os.environ, {"SANDBOX_KEY_HOME": str(kh)}):
        with patch("urllib.request.urlopen", side_effect=tracker.urlopen):
            result = CliRunner().invoke(cli, [
                "signer", "sign-registry",
                "--in", str(in_file),
                "--out", str(out_file),
                "--expect-fingerprint", fp,
                "--publish",
                "--yes",
            ])

    bad_opt = _detect_unknown_option(result)
    if bad_opt:
        raise M2T12dPending(
            f"sign-registry flag not implemented: {bad_opt}"
        )

    assert result.exit_code == 1, (
        f"expected exit 1 for duplicate own sig, "
        f"got {result.exit_code}: {result.output}"
    )
    out = (result.output or "").lower()
    assert "duplicate" in out or "already" in out or "own" in out, (
        f"refusal should mention duplicate: {result.output}"
    )
    assert not out_file.exists(), "--out written despite duplicate own sig"
    sig_posts = [u for u in tracker.requested_urls
                 if "/signer/signatures" in u]
    assert sig_posts == [], "published despite duplicate own sig"


# ---------------------------------------------------------------------------
# F5: diff completeness (library tests, not CLI refusals)
# ---------------------------------------------------------------------------



def test_f5_diff_shows_user_id_change():
    """F5: changing user_id on an existing key must appear in the diff."""
    from sandbox.connector.sync.signer import compute_diff

    alice = SigningKey.generate()
    kid = _kid(alice)

    v1 = {
        "org_id": "o", "version": 1, "prev_hash": "", "threshold": 1,
        "admins": [kid],
        "keys": [{"key_id": kid, "public_key": bytes(alice.verify_key).hex(),
                  "user_id": "alice", "iss": "https://idp", "sub": "sub-a",
                  "alg": "ed25519", "kind": "cli", "roles": ["admin"],
                  "added_in": 1}],
        "bundle_signer": {"key_id": "bs1", "public_key": "aa" * 32},
        "expires_at": 1000,
    }

    v2 = json.loads(json.dumps(v1))
    v2["version"] = 2
    v2["keys"][0]["user_id"] = "bob"

    diff = compute_diff(_canonical_json(v1), _canonical_json(v2))
    if "user_id" not in diff.lower() and "bob" not in diff:
        raise M2T12dPending(
            "compute_diff does not show user_id change"
        )



def test_f5_diff_shows_iss_change():
    """F5: changing iss on an existing key must appear in the diff."""
    from sandbox.connector.sync.signer import compute_diff

    alice = SigningKey.generate()
    kid = _kid(alice)

    v1 = {
        "org_id": "o", "version": 1, "prev_hash": "", "threshold": 1,
        "admins": [kid],
        "keys": [{"key_id": kid, "public_key": bytes(alice.verify_key).hex(),
                  "user_id": "alice", "iss": "https://idp-a", "sub": "sub-a",
                  "alg": "ed25519", "kind": "cli", "roles": ["admin"],
                  "added_in": 1}],
        "bundle_signer": {"key_id": "bs1", "public_key": "aa" * 32},
        "expires_at": 1000,
    }

    v2 = json.loads(json.dumps(v1))
    v2["version"] = 2
    v2["keys"][0]["iss"] = "https://idp-b"

    diff = compute_diff(_canonical_json(v1), _canonical_json(v2))
    if "iss" not in diff.lower() and "idp-b" not in diff:
        raise M2T12dPending(
            "compute_diff does not show iss change"
        )



def test_f5_diff_shows_sub_change():
    """F5: changing sub on an existing key must appear in the diff."""
    from sandbox.connector.sync.signer import compute_diff

    alice = SigningKey.generate()
    kid = _kid(alice)

    v1 = {
        "org_id": "o", "version": 1, "prev_hash": "", "threshold": 1,
        "admins": [kid],
        "keys": [{"key_id": kid, "public_key": bytes(alice.verify_key).hex(),
                  "user_id": "alice", "iss": "https://idp", "sub": "sub-a",
                  "alg": "ed25519", "kind": "cli", "roles": ["admin"],
                  "added_in": 1}],
        "bundle_signer": {"key_id": "bs1", "public_key": "aa" * 32},
        "expires_at": 1000,
    }

    v2 = json.loads(json.dumps(v1))
    v2["version"] = 2
    v2["keys"][0]["sub"] = "sub-b"

    diff = compute_diff(_canonical_json(v1), _canonical_json(v2))
    if "sub" not in diff.lower() and "sub-b" not in diff:
        raise M2T12dPending(
            "compute_diff does not show sub change"
        )



def test_f5_diff_shows_kind_change():
    """F5: changing kind on an existing key must appear in the diff."""
    from sandbox.connector.sync.signer import compute_diff

    alice = SigningKey.generate()
    kid = _kid(alice)

    v1 = {
        "org_id": "o", "version": 1, "prev_hash": "", "threshold": 1,
        "admins": [kid],
        "keys": [{"key_id": kid, "public_key": bytes(alice.verify_key).hex(),
                  "user_id": "alice", "iss": "https://idp", "sub": "sub-a",
                  "alg": "ed25519", "kind": "cli", "roles": ["admin"],
                  "added_in": 1}],
        "bundle_signer": {"key_id": "bs1", "public_key": "aa" * 32},
        "expires_at": 1000,
    }

    v2 = json.loads(json.dumps(v1))
    v2["version"] = 2
    v2["keys"][0]["kind"] = "browser"

    diff = compute_diff(_canonical_json(v1), _canonical_json(v2))
    if "kind" not in diff.lower() and "browser" not in diff:
        raise M2T12dPending(
            "compute_diff does not show kind change"
        )



def test_f5_added_key_shows_all_fields():
    """F5: an added key must print roles, iss, sub in the diff."""
    from sandbox.connector.sync.signer import compute_diff

    alice = SigningKey.generate()
    bob = SigningKey.generate()
    alice_kid = _kid(alice)
    bob_kid = _kid(bob)

    v1 = {
        "org_id": "o", "version": 1, "prev_hash": "", "threshold": 1,
        "admins": [alice_kid],
        "keys": [{"key_id": alice_kid,
                  "public_key": bytes(alice.verify_key).hex(),
                  "user_id": "alice", "iss": "https://idp", "sub": "sub-a",
                  "alg": "ed25519", "kind": "cli", "roles": ["admin"],
                  "added_in": 1}],
        "bundle_signer": {"key_id": "bs1", "public_key": "aa" * 32},
        "expires_at": 1000,
    }

    v2 = json.loads(json.dumps(v1))
    v2["version"] = 2
    v2["keys"].append({
        "key_id": bob_kid,
        "public_key": bytes(bob.verify_key).hex(),
        "user_id": "bob", "iss": "https://idp", "sub": "sub-b",
        "alg": "ed25519", "kind": "browser", "roles": ["approver"],
        "added_in": 2,
    })

    diff = compute_diff(_canonical_json(v1), _canonical_json(v2))
    missing = []
    if "roles" not in diff.lower() and "approver" not in diff:
        missing.append("roles")
    if "iss" not in diff.lower() and "idp" not in diff:
        missing.append("iss")
    if "sub" not in diff.lower() and "sub-b" not in diff:
        missing.append("sub")
    if missing:
        raise M2T12dPending(
            f"compute_diff does not show: {', '.join(missing)}"
        )


def test_f5_diff_shows_roles_change():
    """F5: changing roles on an existing key must appear in the diff."""
    from sandbox.connector.sync.signer import compute_diff

    alice = SigningKey.generate()
    kid = _kid(alice)

    v1 = {
        "org_id": "o", "version": 1, "prev_hash": "", "threshold": 1,
        "admins": [kid],
        "keys": [{"key_id": kid, "public_key": bytes(alice.verify_key).hex(),
                  "user_id": "alice", "iss": "https://idp", "sub": "sub-a",
                  "alg": "ed25519", "kind": "cli", "roles": ["admin"],
                  "added_in": 1}],
        "bundle_signer": {"key_id": "bs1", "public_key": "aa" * 32},
        "expires_at": 1000,
    }

    v2 = json.loads(json.dumps(v1))
    v2["version"] = 2
    v2["keys"][0]["roles"] = ["admin", "approver"]

    diff = compute_diff(_canonical_json(v1), _canonical_json(v2))
    assert "roles" in diff.lower(), (
        f"diff should show roles change: {diff}"
    )


# ---------------------------------------------------------------------------
# F8: build mode prev_hash uses org prefix
# ---------------------------------------------------------------------------



def test_f8_build_mode_passes_verify_chain(tmp_path):
    """F8: the envelope built by build mode must pass verify_chain."""
    from sandbox.cli.main import cli
    from sandbox.protocol.registry import verify_chain, RegistryError

    admin_sk = SigningKey.generate()
    bundle_sk = SigningKey.generate()
    org_id = "org-f8"
    bundle_pub = bytes(bundle_sk.verify_key)
    v1_env, fp = _build_valid_chain_v1(
        admin_sk, org_id, "https://idp", "sub-1", bundle_pub, user_id="u1"
    )

    meta = {
        "server": "https://localhost:9000",
        "key_id": _kid(admin_sk),
        "org_id": org_id,
        "user_id": "u1",
        "iss": "https://idp",
        "sub": "sub-1",
    }
    kh = _make_key_home(tmp_path, admin_sk, meta)
    tracker = _signreg_tracker(v1_env)

    out_file = tmp_path / "v2.json"

    with patch.dict(os.environ, {"SANDBOX_KEY_HOME": str(kh)}):
        with patch("urllib.request.urlopen", side_effect=tracker.urlopen):
            result = CliRunner().invoke(cli, [
                "signer", "sign-registry",
                "--out", str(out_file),
                "--expect-fingerprint", fp,
                "--yes",
            ])

    bad_opt = _detect_unknown_option(result)
    if bad_opt:
        raise M2T12dPending(
            f"sign-registry flag not implemented: {bad_opt}"
        )

    if result.exit_code != 0:
        raise M2T12dPending(
            f"build mode exit {result.exit_code}: {result.output}"
        )

    assert out_file.exists(), "build mode did not write --out"
    v2_env = json.loads(out_file.read_text(encoding="utf-8"))

    try:
        verify_chain([v1_env, v2_env], fp)
    except RegistryError as exc:
        pytest.fail(f"build mode envelope fails verify_chain: {exc}")


# ---------------------------------------------------------------------------
# F10: --threshold
# ---------------------------------------------------------------------------



def test_f10_sign_registry_threshold_flag(tmp_path):
    """F10: sign-registry --threshold N sets the threshold in the new
    version payload.  D2-1: also adds a carol candidate and verifies the
    output threshold is 2."""
    from sandbox.cli.main import cli

    admin_sk = SigningKey.generate()
    bundle_sk = SigningKey.generate()
    org_id = "org-f10"
    bundle_pub = bytes(bundle_sk.verify_key)
    v1_env, fp = _build_valid_chain_v1(
        admin_sk, org_id, "https://idp", "sub-1", bundle_pub, user_id="u1"
    )

    # D2-1: add a carol candidate (u2, sub-2)
    carol_sk = SigningKey.generate()
    carol_kid = _kid(carol_sk)
    carol_pub = bytes(carol_sk.verify_key).hex()
    candidates = [{
        "key_id": carol_kid,
        "public_key": carol_pub,
        "user_id": "u2",
        "iss": "https://idp",
        "sub": "sub-2",
        "kind": "cli",
    }]

    meta = {
        "server": "https://localhost:9000",
        "key_id": _kid(admin_sk),
        "org_id": org_id,
        "user_id": "u1",
        "iss": "https://idp",
        "sub": "sub-1",
    }
    kh = _make_key_home(tmp_path, admin_sk, meta)
    tracker = _signreg_tracker(v1_env, candidates=candidates)

    out_file = tmp_path / "v2.json"

    with patch.dict(os.environ, {"SANDBOX_KEY_HOME": str(kh)}):
        with patch("urllib.request.urlopen", side_effect=tracker.urlopen):
            help_result = CliRunner().invoke(
                cli, ["signer", "sign-registry", "--help"]
            )
            if "--threshold" not in (help_result.output or ""):
                raise M2T12dPending(
                    "--threshold flag not in sign-registry --help"
                )

            result = CliRunner().invoke(cli, [
                "signer", "sign-registry",
                "--add", carol_kid,
                "--admin",
                "--confirm-key-id", carol_kid,
                "--confirm-identity", "https://idp", "sub-2",
                "--threshold", "2",
                "--out", str(out_file),
                "--expect-fingerprint", fp,
                "--yes",
            ])

    bad_opt = _detect_unknown_option(result)
    if bad_opt:
        raise M2T12dPending(
            f"sign-registry flag not implemented: {bad_opt}"
        )

    if result.exit_code != 0:
        raise M2T12dPending(
            f"sign-registry --threshold 2 failed: "
            f"exit {result.exit_code}, {result.output}"
        )

    assert out_file.exists(), "sign-registry did not write --out"
    v2_env = json.loads(out_file.read_text(encoding="utf-8"))
    assert v2_env["payload"]["threshold"] == 2, (
        f"expected threshold 2, got {v2_env['payload'].get('threshold')}"
    )


# ---------------------------------------------------------------------------
# D4-6: threshold bound = distinct admin user_ids, not keys+1
# ---------------------------------------------------------------------------


def test_d4_6_threshold_bound_distinct_admins(tmp_path):
    """D4-6: --threshold bound must be count of distinct admin user_ids,
    not len(keys)+1.

    Setup: v1 with admin key A (user_id u1). sign-registry --add B
    (same user_id u1, --admin). Two admin keys but one distinct admin.
    --threshold 2 must be refused (bound = 1 distinct admin).
    Current code: max(len(keys)+1, 2) = max(3,2) = 3, so threshold 2
    passes. The fix: bound = count of distinct admin user_ids."""
    from sandbox.cli.main import cli

    admin_sk = SigningKey.generate()
    bundle_sk = SigningKey.generate()
    org_id = "org-d46"
    bundle_pub = bytes(bundle_sk.verify_key)
    v1_env, fp = _build_valid_chain_v1(
        admin_sk, org_id, "https://idp", "sub-1", bundle_pub, user_id="u1"
    )

    # Second admin key for the same user
    admin2_sk = SigningKey.generate()
    admin2_kid = _kid(admin2_sk)
    admin2_pub = bytes(admin2_sk.verify_key).hex()

    # Candidate from server: same user_id "u1"
    candidates = [{
        "key_id": admin2_kid,
        "public_key": admin2_pub,
        "user_id": "u1",
        "iss": "https://idp",
        "sub": "sub-1",
        "kind": "cli",
    }]

    meta = {
        "server": "https://localhost:9000",
        "key_id": _kid(admin_sk),
        "org_id": org_id,
        "user_id": "u1",
        "iss": "https://idp",
        "sub": "sub-1",
    }
    kh = _make_key_home(tmp_path, admin_sk, meta)
    tracker = _signreg_tracker(v1_env, candidates=candidates)

    out_file = tmp_path / "v2.json"

    with patch.dict(os.environ, {"SANDBOX_KEY_HOME": str(kh)}):
        with patch("urllib.request.urlopen", side_effect=tracker.urlopen):
            result = CliRunner().invoke(cli, [
                "signer", "sign-registry",
                "--add", admin2_kid,
                "--admin",
                "--confirm-key-id", admin2_kid,
                "--confirm-identity", "https://idp", "sub-1",
                "--threshold", "2",
                "--out", str(out_file),
                "--expect-fingerprint", fp,
                "--yes",
            ])

    bad_opt = _detect_unknown_option(result)
    if bad_opt:
        raise M2T12dPending(
            f"sign-registry flag not implemented: {bad_opt}"
        )

    # With the fix, threshold 2 > 1 distinct admin should be refused.
    # With the bug, threshold 2 <= max(2+1, 2) = 3 is accepted.
    if result.exit_code == 0:
        raise M2T12dPending(
            "D4-6: threshold 2 accepted despite only 1 distinct admin user_id; "
            "bound should be count of distinct admin user_ids, not keys+1"
        )
    assert result.exit_code == 1, (
        f"expected exit 1 for threshold > distinct admins, "
        f"got {result.exit_code}: {result.output}"
    )


# ---------------------------------------------------------------------------
# D4-6: genesis identity block printed also with --yes
# ---------------------------------------------------------------------------


def test_d4_6_genesis_identity_block_printed_with_yes(tmp_path):
    """D4-6 / R1 F12: genesis must always print the identity block
    (org_id, user_id, iss, sub) even when --yes is given, so the operator
    can verify the identity before the key is published."""
    from sandbox.cli.main import cli

    admin_sk = SigningKey.generate()
    bundle_sk = SigningKey.generate()
    bundle_pub_hex = bytes(bundle_sk.verify_key).hex()
    org_id = "org-d46id"
    user_id = "u-d46id"
    iss = "https://idp.test"
    sub_val = "sub-d46id"

    meta = {
        "server": "https://localhost:9000",
        "key_id": _kid(admin_sk),
        "org_id": org_id,
        "user_id": user_id,
        "iss": iss,
        "sub": sub_val,
    }
    kh = _make_key_home(tmp_path, admin_sk, meta)
    tracker = _genesis_tracker(admin_sk, meta)

    with patch.dict(os.environ, {"SANDBOX_KEY_HOME": str(kh)}):
        with patch("urllib.request.urlopen", side_effect=tracker.urlopen):
            result = CliRunner().invoke(cli, [
                "signer", "genesis",
                "--genesis-code", "code-d46id",
                "--bundle-signer-key", bundle_pub_hex,
                "--confirm-identity", iss, sub_val,
                "--yes",
            ])

    bad_opt = _detect_unknown_option(result)
    if bad_opt:
        raise M2T12dPending(f"genesis flag not implemented: {bad_opt}")

    if result.exit_code != 0:
        raise M2T12dPending(
            f"genesis failed: exit {result.exit_code}: {result.output}"
        )

    # The identity block must appear in output even with --yes
    out = result.output or ""
    identity_fields_present = (
        org_id in out
        and user_id in out
        and iss in out
        and sub_val in out
    )
    if not identity_fields_present:
        missing = []
        if org_id not in out:
            missing.append("org_id")
        if user_id not in out:
            missing.append("user_id")
        if iss not in out:
            missing.append("iss")
        if sub_val not in out:
            missing.append("sub")
        raise M2T12dPending(
            f"D4-6: genesis with --yes does not print identity block; "
            f"missing: {missing}"
        )


# ---------------------------------------------------------------------------
# Stub ruling 2: GET /api/v1/sync/signer/registry (not /latest)
# ---------------------------------------------------------------------------



def test_stub2_registry_route_is_full_chain(tmp_path):
    """Stub ruling 2: CLI must GET /api/v1/sync/signer/registry (full
    chain, not /registry/latest) and run verify_chain."""
    from sandbox.cli.main import cli

    admin_sk = SigningKey.generate()
    bundle_sk = SigningKey.generate()
    org_id = "org-s2"
    bundle_pub = bytes(bundle_sk.verify_key)
    v1_env, fp = _build_valid_chain_v1(
        admin_sk, org_id, "https://idp", "sub-1", bundle_pub, user_id="u1"
    )

    meta = {
        "server": "https://localhost:9000",
        "key_id": _kid(admin_sk),
        "org_id": org_id,
        "user_id": "u1",
        "iss": "https://idp",
        "sub": "sub-1",
    }
    kh = _make_key_home(tmp_path, admin_sk, meta)
    tracker = _signreg_tracker(v1_env)

    with patch.dict(os.environ, {"SANDBOX_KEY_HOME": str(kh)}):
        with patch("urllib.request.urlopen", side_effect=tracker.urlopen):
            result = CliRunner().invoke(cli, [
                "signer", "sign-registry",
                "--expect-fingerprint", fp,
                "--yes",
            ])

    bad_opt = _detect_unknown_option(result)
    if bad_opt:
        raise M2T12dPending(
            f"sign-registry flag not implemented: {bad_opt}"
        )

    registry_calls = [u for u in tracker.requested_urls
                      if "/signer/registry" in u]
    latest_calls = [u for u in registry_calls if "latest" in u]
    assert registry_calls, "no request to /signer/registry"
    assert latest_calls == [], (
        f"should use /signer/registry (full chain), not /registry/latest; "
        f"called: {registry_calls}"
    )


# ---------------------------------------------------------------------------
# Existing tests (not weakened, unchanged)
# ---------------------------------------------------------------------------


def test_sign_registry_command_exists():
    """'sandbox signer sign-registry' is a registered command."""
    from sandbox.cli.main import cli
    runner = CliRunner()
    result = runner.invoke(cli, ["signer", "--help"])
    if "sign-registry" not in result.output:
        raise M2T12dPending("'sign-registry' not in signer --help")


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


def test_sign_registry_publish_flag():
    """'sign-registry --publish' posts the complete envelope."""
    from sandbox.cli.main import cli
    runner = CliRunner()
    result = runner.invoke(cli, ["signer", "sign-registry", "--help"])
    if result.exit_code != 0 and "No such command" in (result.output or ""):
        raise M2T12dPending("sign-registry command not found")
    if "--publish" not in (result.output or ""):
        raise M2T12dPending("--publish flag not in sign-registry --help")


def test_sign_registry_confirm_key_id():
    """'sign-registry' needs the typed key_id via --confirm-key-id."""
    from sandbox.cli.main import cli
    runner = CliRunner()
    result = runner.invoke(cli, ["signer", "sign-registry", "--help"])
    if result.exit_code != 0 and "No such command" in (result.output or ""):
        raise M2T12dPending("sign-registry command not found")
    if "--confirm-key-id" not in (result.output or ""):
        raise M2T12dPending(
            "--confirm-key-id flag not in sign-registry --help"
        )


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
            {"key_id": alice_kid,
             "public_key": bytes(alice.verify_key).hex(),
             "user_id": "user-alice", "iss": "https://idp", "sub": "sub-a",
             "alg": "ed25519", "kind": "cli", "roles": ["admin"],
             "added_in": 1},
            {"key_id": bob_kid,
             "public_key": bytes(bob.verify_key).hex(),
             "user_id": "user-bob", "iss": "https://idp", "sub": "sub-b",
             "alg": "ed25519", "kind": "cli", "roles": ["approver"],
             "added_in": 1},
        ],
        "bundle_signer": {"key_id": "bs1", "public_key": "aabbcc"},
        "expires_at": time.time() + 3600,
    }

    v2_payload = dict(v1_payload)
    v2_payload["version"] = 2
    v2_keys = [dict(k) for k in v1_payload["keys"]]
    v2_keys[1]["roles"] = ["approver", "admin"]
    v2_payload["keys"] = v2_keys
    v2_payload["bundle_signer"] = {"key_id": "bs2", "public_key": "ddeeff"}
    v2_payload["expires_at"] = v1_payload["expires_at"] + 10 * 365 * 86400

    v1_bytes = _canonical_json(v1_payload)
    v2_bytes = _canonical_json(v2_payload)

    diff = compute_diff(v1_bytes, v2_bytes)
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


def test_sign_registry_unconfirmed_key_left_unsigned():
    """An unconfirmed key_id (not typed by the admin) must be left unsigned
    (N1, confirm_key_ids)."""
    from sandbox.connector.sync.signer import confirm_key_ids

    added = ["key-alice", "key-bob", "key-carol"]
    confirmed = {"key-alice", "key-carol"}
    result = confirm_key_ids(added, confirmed)
    assert result == ["key-alice", "key-carol"]

    from sandbox.cli.main import cli
    runner = CliRunner()
    help_result = runner.invoke(cli, ["signer", "sign-registry", "--help"])
    if "No such command" in (help_result.output or ""):
        raise M2T12dPending(
            "sign-registry command not found; N1 untestable"
        )
    if "--confirm-key-id" not in (help_result.output or ""):
        raise M2T12dPending("--confirm-key-id not in sign-registry --help")


def test_confirmation_flags_name_exact_values():
    """Every confirmation flag names the exact value."""
    from sandbox.cli.main import cli
    runner = CliRunner()

    result = runner.invoke(cli, ["signer", "genesis", "--help"])
    if "No such command" in (result.output or ""):
        raise M2T12dPending("genesis command not found")
    if "--confirm-identity" not in (result.output or ""):
        raise M2T12dPending("--confirm-identity not in genesis --help")

    result = runner.invoke(cli, ["signer", "sign-registry", "--help"])
    if "No such command" in (result.output or ""):
        raise M2T12dPending("sign-registry command not found")
    if "--confirm-key-id" not in (result.output or ""):
        raise M2T12dPending("--confirm-key-id not in sign-registry --help")


# ---------------------------------------------------------------------------
# F14: --admin scope (testable)
# ---------------------------------------------------------------------------


def test_f14_admin_flag_help_exists():
    """F14: --admin flag exists in sign-registry --help."""
    from sandbox.cli.main import cli
    runner = CliRunner()
    result = runner.invoke(cli, ["signer", "sign-registry", "--help"])
    assert "--admin" in (result.output or ""), (
        "--admin flag not in sign-registry --help"
    )


# ---------------------------------------------------------------------------
# d4 tests: ruling 5 + D4-7 -- iss/sub in the signer link response
# ---------------------------------------------------------------------------


def test_d4_ruling5_link_refuses_missing_iss(tmp_path):
    """Ruling 5: CLI must exit 1 when server link response omits iss.
    No link.json or seed must be written."""
    from sandbox.cli.main import cli

    link_response_no_iss = {
        "org_id": "org-r5a",
        "user_id": "u-r5a",
        "sub": "sub-r5a",
        # no iss
    }
    tracker = _MockTracker({"/signer/link": link_response_no_iss})

    kh = tmp_path / "keyhome"
    kh.mkdir()

    with patch.dict(os.environ, {"SANDBOX_KEY_HOME": str(kh)}):
        with patch("urllib.request.urlopen", side_effect=tracker.urlopen):
            result = CliRunner().invoke(cli, [
                "signer", "link",
                "--code", "test-code",
                "--server", "https://localhost:9000",
            ])

    # If the CLI accepted the response and wrote files, that is the bug.
    link_json_path = kh / "signer" / "link.json"
    seed_path = kh / "signer" / "signer.seed"
    if result.exit_code == 0:
        # CLI accepted -- check if it silently stored empty iss
        if link_json_path.exists():
            data = json.loads(link_json_path.read_text(encoding="utf-8"))
            if not data.get("iss"):
                raise M2T12dPending(
                    "CLI link stored empty/missing iss instead of refusing"
                )
        raise M2T12dPending(
            "CLI link exit 0 for response without iss"
        )
    assert result.exit_code == 1, (
        f"expected exit 1 for missing iss, got {result.exit_code}"
    )
    assert not link_json_path.exists(), "link.json written despite missing iss"
    assert not seed_path.exists(), "seed written despite missing iss"
    # Ruling 5: message must name the field
    out = (result.output or "").lower()
    assert "iss" in out, (
        f"refusal message should name the 'iss' field: {result.output}"
    )


def test_d4_ruling5_link_refuses_empty_sub(tmp_path):
    """Ruling 5: CLI must exit 1 when server link response has sub=''."""
    from sandbox.cli.main import cli

    link_response_empty_sub = {
        "org_id": "org-r5b",
        "user_id": "u-r5b",
        "iss": "https://idp.test",
        "sub": "",
    }
    tracker = _MockTracker({"/signer/link": link_response_empty_sub})

    kh = tmp_path / "keyhome"
    kh.mkdir()

    with patch.dict(os.environ, {"SANDBOX_KEY_HOME": str(kh)}):
        with patch("urllib.request.urlopen", side_effect=tracker.urlopen):
            result = CliRunner().invoke(cli, [
                "signer", "link",
                "--code", "test-code",
                "--server", "https://localhost:9000",
            ])

    link_json_path = kh / "signer" / "link.json"
    seed_path = kh / "signer" / "signer.seed"
    if result.exit_code == 0:
        if link_json_path.exists():
            data = json.loads(link_json_path.read_text(encoding="utf-8"))
            if not data.get("sub"):
                raise M2T12dPending(
                    "CLI link stored empty sub instead of refusing"
                )
        raise M2T12dPending(
            "CLI link exit 0 for response with empty sub"
        )
    assert result.exit_code == 1, (
        f"expected exit 1 for empty sub, got {result.exit_code}"
    )
    assert not link_json_path.exists(), "link.json written despite empty sub"
    assert not seed_path.exists(), "seed written despite empty sub"
    # Ruling 5: message must name the field
    out = (result.output or "").lower()
    assert "sub" in out, (
        f"refusal message should name the 'sub' field: {result.output}"
    )


def test_d4_ruling5_link_refuses_missing_org_id(tmp_path):
    """Ruling 5: CLI must exit 1 when server link response omits org_id.
    No link.json must be written; output names the field."""
    from sandbox.cli.main import cli

    link_response_no_org = {
        "user_id": "u-r5org",
        "iss": "https://idp.test",
        "sub": "sub-r5org",
        # no org_id
    }
    tracker = _MockTracker({"/signer/link": link_response_no_org})

    kh = tmp_path / "keyhome"
    kh.mkdir()

    with patch.dict(os.environ, {"SANDBOX_KEY_HOME": str(kh)}):
        with patch("urllib.request.urlopen", side_effect=tracker.urlopen):
            result = CliRunner().invoke(cli, [
                "signer", "link",
                "--code", "test-code",
                "--server", "https://localhost:9000",
            ])

    link_json_path = kh / "signer" / "link.json"
    if result.exit_code == 0:
        if link_json_path.exists():
            data = json.loads(link_json_path.read_text(encoding="utf-8"))
            if not data.get("org_id"):
                raise M2T12dPending(
                    "CLI link stored empty/missing org_id instead of refusing"
                )
        raise M2T12dPending(
            "CLI link exit 0 for response without org_id"
        )
    assert result.exit_code == 1, (
        f"expected exit 1 for missing org_id, got {result.exit_code}"
    )
    assert not link_json_path.exists(), "link.json written despite missing org_id"
    out = (result.output or "").lower()
    assert "org_id" in out or "org" in out, (
        f"refusal message should name the 'org_id' field: {result.output}"
    )


def test_d4_ruling5_link_refuses_empty_user_id(tmp_path):
    """Ruling 5: CLI must exit 1 when server link response has user_id=''.
    No link.json must be written; output names the field."""
    from sandbox.cli.main import cli

    link_response_empty_uid = {
        "org_id": "org-r5uid",
        "user_id": "",
        "iss": "https://idp.test",
        "sub": "sub-r5uid",
    }
    tracker = _MockTracker({"/signer/link": link_response_empty_uid})

    kh = tmp_path / "keyhome"
    kh.mkdir()

    with patch.dict(os.environ, {"SANDBOX_KEY_HOME": str(kh)}):
        with patch("urllib.request.urlopen", side_effect=tracker.urlopen):
            result = CliRunner().invoke(cli, [
                "signer", "link",
                "--code", "test-code",
                "--server", "https://localhost:9000",
            ])

    link_json_path = kh / "signer" / "link.json"
    if result.exit_code == 0:
        if link_json_path.exists():
            data = json.loads(link_json_path.read_text(encoding="utf-8"))
            if not data.get("user_id"):
                raise M2T12dPending(
                    "CLI link stored empty user_id instead of refusing"
                )
        raise M2T12dPending(
            "CLI link exit 0 for response with empty user_id"
        )
    assert result.exit_code == 1, (
        f"expected exit 1 for empty user_id, got {result.exit_code}"
    )
    assert not link_json_path.exists(), "link.json written despite empty user_id"
    out = (result.output or "").lower()
    assert "user_id" in out or "user" in out, (
        f"refusal message should name the 'user_id' field: {result.output}"
    )


def test_d4_ruling5_link_positive_complete(tmp_path):
    """Positive control: link with complete response (org_id, user_id, iss,
    sub) succeeds and stores iss/sub in link.json."""
    from sandbox.cli.main import cli

    link_response_ok = {
        "org_id": "org-r5ok",
        "user_id": "u-r5ok",
        "iss": "https://idp.test",
        "sub": "sub-r5ok",
    }
    tracker = _MockTracker({"/signer/link": link_response_ok})

    kh = tmp_path / "keyhome"
    kh.mkdir()

    with patch.dict(os.environ, {"SANDBOX_KEY_HOME": str(kh)}):
        with patch("urllib.request.urlopen", side_effect=tracker.urlopen):
            result = CliRunner().invoke(cli, [
                "signer", "link",
                "--code", "test-code",
                "--server", "https://localhost:9000",
            ])

    if result.exit_code != 0:
        raise M2T12dPending(
            f"link failed unexpectedly: exit {result.exit_code}: {result.output}"
        )

    link_json_path = kh / "signer" / "link.json"
    assert link_json_path.exists(), "link.json not written"
    data = json.loads(link_json_path.read_text(encoding="utf-8"))
    assert data.get("iss") == "https://idp.test", (
        f"iss mismatch: {data.get('iss')}"
    )
    assert data.get("sub") == "sub-r5ok", (
        f"sub mismatch: {data.get('sub')}"
    )


# ---------------------------------------------------------------------------
# d4 tests: F11 -- setup codes read from stdin '-'
# ---------------------------------------------------------------------------


def test_d4_f11_genesis_code_from_stdin(tmp_path):
    """F11: 'sandbox signer genesis --genesis-code -' reads the code from
    stdin, not from argv.  Exits 0 with a valid code on stdin."""
    from sandbox.cli.main import cli

    admin_sk = SigningKey.generate()
    bundle_sk = SigningKey.generate()
    bundle_pub_hex = bytes(bundle_sk.verify_key).hex()
    org_id = "org-f11"
    user_id = "u-f11"
    iss = "https://idp.test"
    sub_val = "sub-f11"
    meta = {
        "server": "https://localhost:9000",
        "key_id": _kid(admin_sk),
        "org_id": org_id,
        "user_id": user_id,
        "iss": iss,
        "sub": sub_val,
    }
    kh = _make_key_home(tmp_path, admin_sk, meta)
    tracker = _genesis_tracker(admin_sk, meta)

    with patch.dict(os.environ, {"SANDBOX_KEY_HOME": str(kh)}):
        with patch("urllib.request.urlopen", side_effect=tracker.urlopen):
            result = CliRunner().invoke(cli, [
                "signer", "genesis",
                "--genesis-code", "-",
                "--bundle-signer-key", bundle_pub_hex,
                "--confirm-identity", iss, sub_val,
                "--yes",
            ], input="my-secret-code\n")

    bad_opt = _detect_unknown_option(result)
    if bad_opt:
        raise M2T12dPending(f"genesis flag not implemented: {bad_opt}")

    # The code "-" should trigger stdin read; exit 0 means it worked
    if result.exit_code != 0:
        raise M2T12dPending(
            f"genesis --genesis-code - failed: "
            f"exit {result.exit_code}: {result.output}"
        )

    # Verify the genesis code in the POST body is the stdin value, not "-"
    genesis_posts = tracker.posts_to("/signer/genesis")
    assert len(genesis_posts) == 1, "expected 1 POST to /genesis"
    posted_code = genesis_posts[0].get("genesis_code", "")
    if posted_code == "-":
        raise M2T12dPending(
            "genesis --genesis-code - sends literal '-' instead of reading stdin"
        )
    assert posted_code == "my-secret-code", (
        f"expected stdin code, got {posted_code!r}"
    )


def test_d4_f11_link_code_from_stdin(tmp_path):
    """F11: 'sandbox signer link --code -' reads the code from stdin."""
    from sandbox.cli.main import cli

    tracker = _MockTracker({
        "/signer/link": {
            "org_id": "org-f11lk",
            "user_id": "u-f11lk",
            "iss": "https://idp.test",
            "sub": "sub-f11lk",
        },
    })

    kh = tmp_path / "keyhome"
    kh.mkdir()

    with patch.dict(os.environ, {"SANDBOX_KEY_HOME": str(kh)}):
        with patch("urllib.request.urlopen", side_effect=tracker.urlopen):
            result = CliRunner().invoke(cli, [
                "signer", "link",
                "--code", "-",
                "--server", "https://localhost:9000",
            ], input="stdin-link-code\n")

    if result.exit_code != 0:
        raise M2T12dPending(
            f"link --code - failed: exit {result.exit_code}: {result.output}"
        )

    # The code sent to the server must be the stdin value, not "-"
    link_posts = tracker.posts_to("/signer/link")
    assert len(link_posts) == 1
    posted_code = link_posts[0].get("code", "")
    if posted_code == "-":
        raise M2T12dPending(
            "link --code - sends literal '-' instead of reading stdin"
        )
    assert posted_code == "stdin-link-code", (
        f"expected stdin code 'stdin-link-code', got {posted_code!r}"
    )


# ---------------------------------------------------------------------------
# d4 tests: F13 -- one seed location that signer approve reads
# ---------------------------------------------------------------------------


def test_d4_f13_approve_reads_linked_seed(tmp_path, monkeypatch):
    """Ruling 1 + D4-2: signer approve reads the seed from signer/signer.seed
    (same location link writes), posts key_id matching linked key, and
    user_id must be the linked user (not '').

    R2-3: compare against the seed that signer link actually created (read
    from keyhome/signer/signer.seed), not a key the test generated itself.
    Read key_id and user_id from envelope["payload"].  Assert
    signatures[0]["key_id"].  Verify with the linked public key."""
    from sandbox.cli.main import cli

    monkeypatch.chdir(tmp_path)

    # Mock link to write the seed -- signer link generates its own seed
    link_resp = {
        "org_id": "org-f13",
        "user_id": "u-f13",
        "iss": "https://idp.test",
        "sub": "sub-f13",
    }
    link_tracker = _MockTracker({"/signer/link": link_resp})

    kh = tmp_path / "keyhome"
    kh.mkdir()

    with patch.dict(os.environ, {"SANDBOX_KEY_HOME": str(kh)}):
        with patch("urllib.request.urlopen", side_effect=link_tracker.urlopen):
            link_result = CliRunner().invoke(cli, [
                "signer", "link",
                "--code", "f13-code",
                "--server", "https://localhost:9000",
            ])

    if link_result.exit_code != 0:
        raise M2T12dPending(
            f"link failed: exit {link_result.exit_code}: {link_result.output}"
        )

    # R2-3: read the seed that signer link actually wrote, derive kid from it
    seed_path = kh / "signer" / "signer.seed"
    assert seed_path.exists(), "signer link did not write signer.seed"
    linked_sk = SigningKey(seed_path.read_bytes())
    linked_kid = _kid(linked_sk)
    linked_pub = bytes(linked_sk.verify_key)

    # Now try approve with the same key home.  The escalation is a full v2
    # record (fp_v 2 plus its binding fingerprint), as GET-by-id returns it:
    # the signer refuses records without fp_v (T12c c3), so the fixture must
    # be a valid record for the seed-location check to be reached.
    from sandbox.connector.approval import _binding_fingerprint
    esc_record = {
        "request_id": "esc-1",
        "command": "echo test",
        "status": "pending",
        "requires_dual": False,
        "policy_sequence": 1,
        "risk": {"band": "high"},
        "root": str(tmp_path),
        "kind": "shell",
        "tool_name": "Bash",
        "exec_cwd": str(tmp_path),
        "bundle_sequence": 1,
        "fp_v": 2,
        "script": None,
        "script_unbound": "",
        "script_preview": None,
    }
    esc_record["fingerprint"] = _binding_fingerprint(esc_record)
    approve_tracker = _MockTracker({
        "/signer/token": {"token": "tok-f13"},
        "/escalations": esc_record,
        "/approvals": {"ok": True},
    })

    with patch.dict(os.environ, {"SANDBOX_KEY_HOME": str(kh)}):
        with patch("urllib.request.urlopen",
                   side_effect=approve_tracker.urlopen):
            approve_result = CliRunner().invoke(cli, [
                "signer", "approve", "esc-1",
                "--server", "https://localhost:9000",
                "--yes",
            ])

    # If approve cannot find the seed, it fails. The fix makes them use the
    # same location.
    if approve_result.exit_code != 0:
        out = (approve_result.output or "").lower()
        if "seed" in out or "key" in out or "not found" in out:
            raise M2T12dPending(
                f"signer approve cannot read the linked seed: "
                f"{approve_result.output[:300]}"
            )
        raise M2T12dPending(
            f"signer approve failed for unknown reason: "
            f"exit {approve_result.exit_code}: {approve_result.output[:300]}"
        )

    # D4-2: the posted approval must carry key_id matching the linked key
    # and user_id == "u-f13" (not "").
    approval_posts = approve_tracker.posts_to("/approvals")
    if not approval_posts:
        raise M2T12dPending("approve did not POST to /approvals")
    posted = approval_posts[0]
    envelope = posted.get("envelope", posted)
    payload = envelope["payload"]
    posted_kid = payload["key_id"]
    posted_uid = payload["user_id"]
    assert posted_kid == linked_kid, (
        f"approve posted wrong key_id: expected {linked_kid[:16]}... "
        f"(from signer.seed), got {posted_kid[:16]}..."
    )
    assert posted_uid == "u-f13", (
        f"D4-2: approve posted user_id {posted_uid!r}; expected 'u-f13'"
    )
    # signatures[0].key_id must also match
    assert envelope["signatures"][0]["key_id"] == linked_kid, (
        f"signatures[0].key_id mismatch: expected {linked_kid[:16]}..."
    )

    # Ruling 1: signature must be valid under the linked public key.
    from sandbox.protocol.envelope import verify_envelope, EnvelopeError
    trusted = {linked_kid: linked_pub}
    try:
        verify_envelope(envelope, trusted)
    except EnvelopeError as exc:
        raise M2T12dPending(
            f"approval envelope signature invalid under linked key: {exc}"
        )


# ---------------------------------------------------------------------------
# D4-2: link.json key_id != seed kid refusal
# ---------------------------------------------------------------------------


def test_d4_2_link_key_id_mismatch_refused(tmp_path, monkeypatch):
    """D4-2: If link.json key_id does not match the seed's kid, the CLI
    must refuse to use the key (exit 1 on approve/deny).  This prevents
    a tampered link.json from making the CLI sign with a misattributed kid."""
    from sandbox.cli.main import cli

    monkeypatch.chdir(tmp_path)

    admin_sk = SigningKey.generate()
    kid = _kid(admin_sk)

    # Link normally to write the seed and link.json
    link_resp = {
        "org_id": "org-kidmm",
        "user_id": "u-kidmm",
        "iss": "https://idp.test",
        "sub": "sub-kidmm",
    }
    link_tracker = _MockTracker({"/signer/link": link_resp})

    kh = tmp_path / "keyhome"
    kh.mkdir()

    with patch.dict(os.environ, {"SANDBOX_KEY_HOME": str(kh)}):
        with patch("urllib.request.urlopen", side_effect=link_tracker.urlopen):
            link_result = CliRunner().invoke(cli, [
                "signer", "link",
                "--code", "kidmm-code",
                "--server", "https://localhost:9000",
            ])

    if link_result.exit_code != 0:
        raise M2T12dPending(
            f"link failed: exit {link_result.exit_code}: {link_result.output}"
        )

    # Tamper with link.json: change key_id to a different value
    link_json_path = kh / "signer" / "link.json"
    assert link_json_path.exists(), "link.json not written"
    link_data = json.loads(link_json_path.read_text(encoding="utf-8"))
    original_kid = link_data.get("key_id", "")
    assert original_kid, "link.json has no key_id"
    # Set a wrong key_id
    link_data["key_id"] = "0" * 64
    link_json_path.write_text(json.dumps(link_data), encoding="utf-8")

    # Now try to approve -- must refuse because key_id != seed kid
    from sandbox.connector.approval import _binding_fingerprint
    esc_record = {
        "request_id": "esc-kidmm",
        "command": "echo test",
        "status": "pending",
        "requires_dual": False,
        "policy_sequence": 1,
        "risk": {"band": "high"},
        "root": str(tmp_path),
        "kind": "shell",
        "tool_name": "Bash",
        "exec_cwd": str(tmp_path),
        "bundle_sequence": 1,
        "fp_v": 2,
        "script": None,
        "script_unbound": "",
        "script_preview": None,
    }
    esc_record["fingerprint"] = _binding_fingerprint(esc_record)
    approve_tracker = _MockTracker({
        "/signer/token": {"token": "tok-kidmm"},
        "/escalations": esc_record,
        "/approvals": {"ok": True},
    })

    with patch.dict(os.environ, {"SANDBOX_KEY_HOME": str(kh)}):
        with patch("urllib.request.urlopen",
                   side_effect=approve_tracker.urlopen):
            result = CliRunner().invoke(cli, [
                "signer", "approve", "esc-kidmm",
                "--server", "https://localhost:9000",
                "--yes",
            ])

    if result.exit_code == 0:
        # Check if it posted with the wrong key_id
        posts = approve_tracker.posts_to("/approvals")
        if posts:
            env = posts[0].get("envelope", posts[0])
            if env.get("key_id") == "0" * 64:
                raise M2T12dPending(
                    "D4-2: approve used tampered key_id from link.json "
                    "instead of the seed's actual kid"
                )
        raise M2T12dPending(
            "D4-2: approve succeeded with mismatched link.json key_id"
        )
    assert result.exit_code == 1, (
        f"expected exit 1 for key_id mismatch, got {result.exit_code}"
    )


def test_d4_2_deny_reads_linked_seed(tmp_path, monkeypatch):
    """D4-2: signer deny must read the seed from signer/signer.seed
    (the same location link writes). It must not require verified state
    beyond the key home.

    R2-3: add the same payload assertions as the approve test -- key_id
    and user_id from the linked seed, verified signature."""
    from sandbox.cli.main import cli

    monkeypatch.chdir(tmp_path)

    link_resp = {
        "org_id": "org-d42d",
        "user_id": "u-d42d",
        "iss": "https://idp.test",
        "sub": "sub-d42d",
    }
    link_tracker = _MockTracker({"/signer/link": link_resp})

    kh = tmp_path / "keyhome"
    kh.mkdir()

    with patch.dict(os.environ, {"SANDBOX_KEY_HOME": str(kh)}):
        with patch("urllib.request.urlopen", side_effect=link_tracker.urlopen):
            link_result = CliRunner().invoke(cli, [
                "signer", "link",
                "--code", "d42d-code",
                "--server", "https://localhost:9000",
            ])

    if link_result.exit_code != 0:
        raise M2T12dPending(
            f"link failed: exit {link_result.exit_code}: {link_result.output}"
        )

    # R2-3: read the seed that signer link actually wrote
    seed_path = kh / "signer" / "signer.seed"
    assert seed_path.exists(), "signer link did not write signer.seed"
    linked_sk = SigningKey(seed_path.read_bytes())
    linked_kid = _kid(linked_sk)
    linked_pub = bytes(linked_sk.verify_key)

    from sandbox.connector.approval import _binding_fingerprint
    esc_record = {
        "request_id": "esc-deny-1",
        "command": "rm -rf /",
        "status": "pending",
        "requires_dual": False,
        "policy_sequence": 1,
        "risk": {"band": "critical"},
        "root": str(tmp_path),
        "kind": "shell",
        "tool_name": "Bash",
        "exec_cwd": str(tmp_path),
        "bundle_sequence": 1,
        "fp_v": 2,
        "script": None,
        "script_unbound": "",
        "script_preview": None,
    }
    esc_record["fingerprint"] = _binding_fingerprint(esc_record)
    deny_tracker = _MockTracker({
        "/signer/token": {"token": "tok-d42d"},
        "/escalations": esc_record,
        "/approvals": {"ok": True},
    })

    with patch.dict(os.environ, {"SANDBOX_KEY_HOME": str(kh)}):
        with patch("urllib.request.urlopen",
                   side_effect=deny_tracker.urlopen):
            deny_result = CliRunner().invoke(cli, [
                "signer", "deny", "esc-deny-1",
                "--server", "https://localhost:9000",
                "--yes",
            ])

    if deny_result.exit_code != 0:
        out = (deny_result.output or "").lower()
        if "seed" in out or "key" in out or "verified" in out:
            raise M2T12dPending(
                f"signer deny cannot read linked seed or requires "
                f"verified state: {deny_result.output[:300]}"
            )
        raise M2T12dPending(
            f"signer deny failed: exit {deny_result.exit_code}: "
            f"{deny_result.output[:300]}"
        )

    # R2-3: payload assertions (same as the approve test).
    # Both approve and deny post to /approvals (via _post_approval).
    denial_posts = deny_tracker.posts_to("/approvals")
    if not denial_posts:
        raise M2T12dPending("deny did not POST to /denials")
    posted = denial_posts[0]
    envelope = posted.get("envelope", posted)
    payload = envelope["payload"]
    posted_kid = payload["key_id"]
    posted_uid = payload["user_id"]
    assert posted_kid == linked_kid, (
        f"deny posted wrong key_id: expected {linked_kid[:16]}... "
        f"(from signer.seed), got {posted_kid[:16]}..."
    )
    assert posted_uid == "u-d42d", (
        f"D4-2: deny posted user_id {posted_uid!r}; expected 'u-d42d'"
    )
    assert envelope["signatures"][0]["key_id"] == linked_kid, (
        f"signatures[0].key_id mismatch: expected {linked_kid[:16]}..."
    )

    # Verify signature under the linked public key
    from sandbox.protocol.envelope import verify_envelope, EnvelopeError
    trusted = {linked_kid: linked_pub}
    try:
        verify_envelope(envelope, trusted)
    except EnvelopeError as exc:
        raise M2T12dPending(
            f"denial envelope signature invalid under linked key: {exc}"
        )


# ---------------------------------------------------------------------------
# d4 tests: R2-4 -- --confirm-key-id with no added keys
# ---------------------------------------------------------------------------


def test_d4_r2_4_confirm_key_id_no_adds_refused(tmp_path):
    """R2-4: --confirm-key-id X with no --add is refused (the set check must
    be unconditional).  Exit 1, output mentions 'confirm' or 'key_id',
    nothing published."""
    from sandbox.cli.main import cli

    admin_sk = SigningKey.generate()
    bundle_sk = SigningKey.generate()
    org_id = "org-r24"
    bundle_pub = bytes(bundle_sk.verify_key)
    v1_env, fp = _build_valid_chain_v1(
        admin_sk, org_id, "https://idp", "sub-1", bundle_pub, user_id="u1"
    )

    meta = {
        "server": "https://localhost:9000",
        "key_id": _kid(admin_sk),
        "org_id": org_id,
        "user_id": "u1",
        "iss": "https://idp",
        "sub": "sub-1",
    }
    kh = _make_key_home(tmp_path, admin_sk, meta)
    tracker = _signreg_tracker(v1_env)

    with patch.dict(os.environ, {"SANDBOX_KEY_HOME": str(kh)}):
        with patch("urllib.request.urlopen", side_effect=tracker.urlopen):
            result = CliRunner().invoke(cli, [
                "signer", "sign-registry",
                # NO --add, but --confirm-key-id supplied
                "--confirm-key-id", "phantom-key",
                "--expect-fingerprint", fp,
                "--publish",
                "--yes",
            ])

    bad_opt = _detect_unknown_option(result)
    if bad_opt:
        raise M2T12dPending(
            f"sign-registry flag not implemented: {bad_opt}"
        )

    if result.exit_code == 0:
        raise M2T12dPending(
            "R2-4: --confirm-key-id with no adds was accepted (should refuse)"
        )
    assert result.exit_code == 1, (
        f"expected exit 1 for extra --confirm-key-id with no adds, "
        f"got {result.exit_code}: {result.output}"
    )
    out = (result.output or "").lower()
    assert "confirm" in out or "key_id" in out or "key-id" in out, (
        f"refusal should mention confirm/key_id: {result.output}"
    )
    sig_posts = [u for u in tracker.requested_urls
                 if "/signer/signatures" in u]
    assert sig_posts == [], "published despite extra --confirm-key-id"


# ---------------------------------------------------------------------------
# d4 tests: R2-5 -- --add of a key already in the registry
# ---------------------------------------------------------------------------


def test_d4_r2_5_add_existing_key_refused(tmp_path):
    """R2-5: --add of a key_id already in the latest registry is refused
    (or needs explicit confirmation).  Exit 1, nothing published."""
    from sandbox.cli.main import cli

    admin_sk = SigningKey.generate()
    bundle_sk = SigningKey.generate()
    org_id = "org-r25"
    bundle_pub = bytes(bundle_sk.verify_key)
    v1_env, fp = _build_valid_chain_v1(
        admin_sk, org_id, "https://idp", "sub-1", bundle_pub, user_id="u1"
    )

    existing_kid = _kid(admin_sk)  # already in the v1 registry

    meta = {
        "server": "https://localhost:9000",
        "key_id": existing_kid,
        "org_id": org_id,
        "user_id": "u1",
        "iss": "https://idp",
        "sub": "sub-1",
    }
    kh = _make_key_home(tmp_path, admin_sk, meta)
    tracker = _signreg_tracker(v1_env)

    with patch.dict(os.environ, {"SANDBOX_KEY_HOME": str(kh)}):
        with patch("urllib.request.urlopen", side_effect=tracker.urlopen):
            result = CliRunner().invoke(cli, [
                "signer", "sign-registry",
                "--add", existing_kid,
                "--confirm-key-id", existing_kid,
                "--expect-fingerprint", fp,
                "--publish",
                "--yes",
            ])

    bad_opt = _detect_unknown_option(result)
    if bad_opt:
        raise M2T12dPending(
            f"sign-registry flag not implemented: {bad_opt}"
        )

    if result.exit_code == 0:
        raise M2T12dPending(
            "R2-5: --add of an existing key was accepted (should refuse)"
        )
    assert result.exit_code == 1, (
        f"expected exit 1 for --add existing key, "
        f"got {result.exit_code}: {result.output}"
    )
    out = (result.output or "").lower()
    # R2-5: the refusal may say "already in registry", "duplicate", "exists",
    # or currently "candidate key not found" (since the key is not a candidate).
    # d4 should specifically refuse with an "already" or "exist" message.
    if "not found" in out or "candidate" in out:
        raise M2T12dPending(
            "R2-5: --add of existing key refused as 'not found' instead of "
            "'already in registry' (needs specific refusal message)"
        )
    assert ("exist" in out or "already" in out or "duplicate" in out), (
        f"refusal should mention existing/duplicate: {result.output}"
    )
    sig_posts = [u for u in tracker.requested_urls
                 if "/signer/signatures" in u]
    assert sig_posts == [], "published despite --add existing key"


# ---------------------------------------------------------------------------
# d4 tests: R2-6 -- co-sign trust set no wider than verify_chain
# ---------------------------------------------------------------------------


def test_d4_r2_6_cosign_trust_set_matches_verify_chain(tmp_path):
    """R2-6: existing signatures in co-sign mode are accepted only from
    keys in prev_admins | cur_admins (same as verify_chain), not from
    non-admins or keys newly added in this version.

    A signature from a non-admin key in the partial must be refused."""
    from sandbox.cli.main import cli
    from sandbox.protocol.envelope import canonical_bytes
    from sandbox.protocol.domains import REGISTRY

    admin_sk = SigningKey.generate()
    non_admin_sk = SigningKey.generate()
    bundle_sk = SigningKey.generate()
    org_id = "org-r26"
    bundle_pub = bytes(bundle_sk.verify_key)

    # v1 has only admin_sk as admin; non_admin_sk is approver only
    from sandbox.connector.sync.signer import build_genesis
    v1_env, fp = build_genesis(
        admin_sk, org_id, "https://idp", "sub-1", bundle_pub,
        user_id="u1",
    )
    # Patch in a second key as approver-only in v1
    non_admin_kid = _kid(non_admin_sk)
    v1_env["payload"]["keys"].append({
        "key_id": non_admin_kid,
        "public_key": bytes(non_admin_sk.verify_key).hex(),
        "user_id": "u2",
        "iss": "https://idp",
        "sub": "sub-2",
        "alg": "ed25519",
        "kind": "cli",
        "roles": ["approver"],  # NOT admin
        "added_in": 1,
    })
    # Re-sign v1 with updated payload
    tag = b"agg/registry/v1"
    canonical = json.dumps(v1_env["payload"], sort_keys=True,
                           separators=(",", ":")).encode()
    msg = tag + b"\x00" + canonical
    sig = admin_sk.sign(msg).signature.hex()
    v1_env["signatures"] = [
        {"key_id": _kid(admin_sk), "alg": "ed25519", "sig": sig}
    ]

    # Build v2 with a signature from non_admin_sk (should be refused)
    v2_payload = {
        "org_id": org_id,
        "version": 2,
        "prev_hash": _payload_hash(v1_env["payload"]),
        "threshold": 1,
        "admins": v1_env["payload"]["admins"],
        "keys": v1_env["payload"]["keys"],
        "bundle_signer": v1_env["payload"]["bundle_signer"],
        "expires_at": v1_env["payload"]["expires_at"],
    }
    v2_msg = canonical_bytes(REGISTRY, v2_payload)
    non_admin_sig = non_admin_sk.sign(v2_msg).signature.hex()

    partial = {
        "kind": REGISTRY,
        "sig_v": 1,
        "payload": v2_payload,
        "signatures": [{
            "key_id": non_admin_kid,
            "alg": "ed25519",
            "sig": non_admin_sig,
        }],
    }
    in_file = tmp_path / "partial.json"
    in_file.write_text(json.dumps(partial), encoding="utf-8")

    meta = {
        "server": "https://localhost:9000",
        "key_id": _kid(admin_sk),
        "org_id": org_id,
        "user_id": "u1",
        "iss": "https://idp",
        "sub": "sub-1",
    }
    kh = _make_key_home(tmp_path / "kh", admin_sk, meta)
    tracker = _signreg_tracker(v1_env)

    out_file = tmp_path / "out.json"

    with patch.dict(os.environ, {"SANDBOX_KEY_HOME": str(kh)}):
        with patch("urllib.request.urlopen", side_effect=tracker.urlopen):
            result = CliRunner().invoke(cli, [
                "signer", "sign-registry",
                "--in", str(in_file),
                "--out", str(out_file),
                "--expect-fingerprint", fp,
                "--yes",
            ])

    bad_opt = _detect_unknown_option(result)
    if bad_opt:
        raise M2T12dPending(
            f"sign-registry flag not implemented: {bad_opt}"
        )

    if result.exit_code == 0:
        raise M2T12dPending(
            "R2-6: signature from non-admin accepted (trust set too wide)"
        )
    assert result.exit_code == 1, (
        f"expected exit 1 for non-admin sig in co-sign, "
        f"got {result.exit_code}: {result.output}"
    )
    assert not out_file.exists(), "--out written despite non-admin sig"


# ---------------------------------------------------------------------------
# d4 tests: R2-7 -- threshold bound, root fingerprint, --yes/--confirm-identity
# ---------------------------------------------------------------------------


def test_d4_r2_7_threshold_upper_bound(tmp_path):
    """R2-7: --threshold N must satisfy 1 <= N <= admin count.  Setting
    threshold > admin count -> exit 1, nothing written."""
    from sandbox.cli.main import cli

    admin_sk = SigningKey.generate()
    bundle_sk = SigningKey.generate()
    org_id = "org-r27t"
    bundle_pub = bytes(bundle_sk.verify_key)
    v1_env, fp = _build_valid_chain_v1(
        admin_sk, org_id, "https://idp", "sub-1", bundle_pub, user_id="u1"
    )

    meta = {
        "server": "https://localhost:9000",
        "key_id": _kid(admin_sk),
        "org_id": org_id,
        "user_id": "u1",
        "iss": "https://idp",
        "sub": "sub-1",
    }
    kh = _make_key_home(tmp_path, admin_sk, meta)
    tracker = _signreg_tracker(v1_env)
    out_file = tmp_path / "v2.json"

    with patch.dict(os.environ, {"SANDBOX_KEY_HOME": str(kh)}):
        with patch("urllib.request.urlopen", side_effect=tracker.urlopen):
            result = CliRunner().invoke(cli, [
                "signer", "sign-registry",
                "--threshold", "99",  # way above admin count (1)
                "--out", str(out_file),
                "--expect-fingerprint", fp,
                "--yes",
            ])

    bad_opt = _detect_unknown_option(result)
    if bad_opt:
        raise M2T12dPending(
            f"sign-registry flag not implemented: {bad_opt}"
        )

    if result.exit_code == 0:
        raise M2T12dPending(
            "R2-7: --threshold 99 with 1 admin accepted (no upper bound)"
        )
    assert result.exit_code == 1, (
        f"expected exit 1 for threshold > admin count, "
        f"got {result.exit_code}: {result.output}"
    )
    out = (result.output or "").lower()
    assert "threshold" in out or "admin" in out, (
        f"refusal should mention threshold/admin: {result.output}"
    )
    assert not out_file.exists(), "--out written despite invalid threshold"


def test_d4_r2_7_threshold_lower_bound(tmp_path):
    """R2-7: --threshold 0 -> exit 1, nothing written."""
    from sandbox.cli.main import cli

    admin_sk = SigningKey.generate()
    bundle_sk = SigningKey.generate()
    org_id = "org-r27lo"
    bundle_pub = bytes(bundle_sk.verify_key)
    v1_env, fp = _build_valid_chain_v1(
        admin_sk, org_id, "https://idp", "sub-1", bundle_pub, user_id="u1"
    )

    meta = {
        "server": "https://localhost:9000",
        "key_id": _kid(admin_sk),
        "org_id": org_id,
        "user_id": "u1",
        "iss": "https://idp",
        "sub": "sub-1",
    }
    kh = _make_key_home(tmp_path, admin_sk, meta)
    tracker = _signreg_tracker(v1_env)
    out_file = tmp_path / "v2.json"

    with patch.dict(os.environ, {"SANDBOX_KEY_HOME": str(kh)}):
        with patch("urllib.request.urlopen", side_effect=tracker.urlopen):
            result = CliRunner().invoke(cli, [
                "signer", "sign-registry",
                "--threshold", "0",
                "--out", str(out_file),
                "--expect-fingerprint", fp,
                "--yes",
            ])

    bad_opt = _detect_unknown_option(result)
    if bad_opt:
        raise M2T12dPending(
            f"sign-registry flag not implemented: {bad_opt}"
        )

    if result.exit_code == 0:
        raise M2T12dPending(
            "R2-7: --threshold 0 accepted (no lower bound)"
        )
    assert result.exit_code == 1, (
        f"expected exit 1 for threshold 0, "
        f"got {result.exit_code}: {result.output}"
    )
    assert not out_file.exists(), "--out written despite threshold 0"


def test_d4_r2_7_genesis_stores_root_fingerprint(tmp_path):
    """R2-7: after genesis, the root fingerprint is stored in
    signer/root_fingerprint so later sign-registry can use it
    without --expect-fingerprint."""
    from sandbox.cli.main import cli

    admin_sk = SigningKey.generate()
    bundle_sk = SigningKey.generate()
    bundle_pub_hex = bytes(bundle_sk.verify_key).hex()
    org_id = "org-r27fp"
    user_id = "u-r27fp"
    iss = "https://idp.test"
    sub_val = "sub-r27fp"

    meta = {
        "server": "https://localhost:9000",
        "key_id": _kid(admin_sk),
        "org_id": org_id,
        "user_id": user_id,
        "iss": iss,
        "sub": sub_val,
    }
    kh = _make_key_home(tmp_path, admin_sk, meta)
    tracker = _genesis_tracker(admin_sk, meta)

    with patch.dict(os.environ, {"SANDBOX_KEY_HOME": str(kh)}):
        with patch("urllib.request.urlopen", side_effect=tracker.urlopen):
            result = CliRunner().invoke(cli, [
                "signer", "genesis",
                "--genesis-code", "code-r27fp",
                "--bundle-signer-key", bundle_pub_hex,
                "--confirm-identity", iss, sub_val,
                "--yes",
            ])

    bad_opt = _detect_unknown_option(result)
    if bad_opt:
        raise M2T12dPending(f"genesis flag not implemented: {bad_opt}")

    if result.exit_code != 0:
        raise M2T12dPending(
            f"genesis failed: exit {result.exit_code}: {result.output}"
        )

    # Check that root_fingerprint was stored
    fp_file = kh / "signer" / "root_fingerprint"
    if not fp_file.exists():
        raise M2T12dPending(
            "genesis does not store signer/root_fingerprint"
        )
    stored_fp = fp_file.read_text(encoding="utf-8").strip()
    assert len(stored_fp) == 64, (
        f"stored fingerprint has wrong length: {len(stored_fp)}"
    )
    # The stored fingerprint should appear in the genesis output
    assert stored_fp in (result.output or ""), (
        "stored fingerprint not in genesis output"
    )


def test_d4_r2_7_yes_without_confirm_identity_refused(tmp_path):
    """R2-7: --yes without --confirm-identity exits 1 (--yes confirms
    nothing if there is no typed identity).  Output mentions 'identity'
    or 'confirm'.  Nothing posted."""
    from sandbox.cli.main import cli

    admin_sk = SigningKey.generate()
    bundle_sk = SigningKey.generate()
    bundle_pub_hex = bytes(bundle_sk.verify_key).hex()
    meta = {
        "server": "https://localhost:9000",
        "key_id": _kid(admin_sk),
        "org_id": "org-r27y",
        "user_id": "u-r27y",
        "iss": "https://idp.test",
        "sub": "sub-r27y",
    }
    kh = _make_key_home(tmp_path, admin_sk, meta)
    tracker = _genesis_tracker(admin_sk, meta)

    with patch.dict(os.environ, {"SANDBOX_KEY_HOME": str(kh)}):
        with patch("urllib.request.urlopen", side_effect=tracker.urlopen):
            result = CliRunner().invoke(cli, [
                "signer", "genesis",
                "--genesis-code", "code-r27y",
                "--bundle-signer-key", bundle_pub_hex,
                "--yes",
                # NO --confirm-identity
            ])

    bad_opt = _detect_unknown_option(result)
    if bad_opt:
        raise M2T12dPending(f"genesis flag not implemented: {bad_opt}")

    if result.exit_code == 0:
        raise M2T12dPending(
            "R2-7: --yes without --confirm-identity accepted "
            "(should refuse in non-interactive mode)"
        )
    assert result.exit_code == 1, (
        f"expected exit 1 for --yes without --confirm-identity, "
        f"got {result.exit_code}: {result.output}"
    )
    out = (result.output or "").lower()
    assert "identity" in out or "confirm" in out, (
        f"refusal should mention identity/confirm: {result.output}"
    )
    genesis_posts = [u for u in tracker.requested_urls
                     if "/signer/genesis" in u]
    assert genesis_posts == [], "posted despite --yes without --confirm-identity"


# ---------------------------------------------------------------------------
# d4 tests: F14 -- per-key roles (not global --admin)
# ---------------------------------------------------------------------------


def test_d4_f14_admin_with_multiple_adds_refused(tmp_path):
    """F14: --admin gives admin+approver to every --add in the run.
    With multiple --add keys, refuse (or require per-key roles).
    Exit 1, nothing published."""
    from sandbox.cli.main import cli

    admin_sk = SigningKey.generate()
    bundle_sk = SigningKey.generate()
    org_id = "org-f14"
    bundle_pub = bytes(bundle_sk.verify_key)
    v1_env, fp = _build_valid_chain_v1(
        admin_sk, org_id, "https://idp", "sub-1", bundle_pub, user_id="u1"
    )

    carol_sk = SigningKey.generate()
    carol_kid = _kid(carol_sk)
    dave_sk = SigningKey.generate()
    dave_kid = _kid(dave_sk)

    meta = {
        "server": "https://localhost:9000",
        "key_id": _kid(admin_sk),
        "org_id": org_id,
        "user_id": "u1",
        "iss": "https://idp",
        "sub": "sub-1",
    }
    kh = _make_key_home(tmp_path, admin_sk, meta)
    tracker = _signreg_tracker(v1_env, candidates=[
        {
            "key_id": carol_kid,
            "public_key": bytes(carol_sk.verify_key).hex(),
            "user_id": "carol-u",
            "iss": "https://idp",
            "sub": "sub-carol",
            "kind": "cli",
        },
        {
            "key_id": dave_kid,
            "public_key": bytes(dave_sk.verify_key).hex(),
            "user_id": "dave-u",
            "iss": "https://idp",
            "sub": "sub-dave",
            "kind": "cli",
        },
    ])

    with patch.dict(os.environ, {"SANDBOX_KEY_HOME": str(kh)}):
        with patch("urllib.request.urlopen", side_effect=tracker.urlopen):
            result = CliRunner().invoke(cli, [
                "signer", "sign-registry",
                "--add", carol_kid,
                "--add", dave_kid,
                "--admin",  # applies to both -- F14 says refuse or per-key
                "--confirm-key-id", carol_kid,
                "--confirm-key-id", dave_kid,
                "--expect-fingerprint", fp,
                "--publish",
                "--yes",
            ])

    bad_opt = _detect_unknown_option(result)
    if bad_opt:
        raise M2T12dPending(
            f"sign-registry flag not implemented: {bad_opt}"
        )

    if result.exit_code == 0:
        raise M2T12dPending(
            "F14: --admin with multiple --add accepted (should refuse "
            "or require per-key roles)"
        )
    assert result.exit_code == 1, (
        f"expected exit 1 for --admin with multiple adds, "
        f"got {result.exit_code}: {result.output}"
    )


# ---------------------------------------------------------------------------
# R2-1: seed with 0x0A / 0x0D bytes roundtrips correctly
# ---------------------------------------------------------------------------


def test_r2_1_seed_with_newline_bytes_roundtrips(tmp_path):
    """R2-1: a 32-byte seed containing 0x0A and 0x0D, written by
    ``signer link``, is exactly 32 bytes on disk and a subsequent
    ``signer genesis`` loads it successfully.  Runs on both OSes.

    The bug (Windows without O_BINARY): os.write through a text-mode fd
    converts 0x0A to 0x0D 0x0A, making the file 33+ bytes and every
    later load refuse it.
    """
    from sandbox.cli.main import cli

    # Build a 32-byte seed that contains both problematic bytes.
    controlled_seed = bytearray(secrets.token_bytes(32))
    controlled_seed[5] = 0x0A   # \n
    controlled_seed[13] = 0x0D  # \r
    controlled_seed = bytes(controlled_seed)
    controlled_sk = SigningKey(controlled_seed)

    link_tracker = _MockTracker({
        "/signer/link": {
            "org_id": "org-r21",
            "user_id": "u-r21",
            "iss": "https://idp.test",
            "sub": "sub-r21",
        },
    })

    kh = tmp_path / "keyhome"
    kh.mkdir()

    with patch.dict(os.environ, {"SANDBOX_KEY_HOME": str(kh)}):
        with patch("nacl.signing.SigningKey.generate",
                   return_value=controlled_sk):
            with patch("urllib.request.urlopen",
                       side_effect=link_tracker.urlopen):
                link_result = CliRunner().invoke(cli, [
                    "signer", "link",
                    "--code", "test-code",
                    "--server", "https://localhost:9000",
                ])

    if link_result.exit_code != 0:
        raise M2T12dPending(
            f"signer link failed (exit {link_result.exit_code}): "
            f"{link_result.output}"
        )

    seed_path = kh / "signer" / "signer.seed"
    assert seed_path.exists(), "seed file not created by signer link"
    raw = seed_path.read_bytes()
    assert len(raw) == 32, (
        f"seed file is {len(raw)} bytes, expected 32; "
        "0x0A was likely expanded to CRLF (missing O_BINARY)"
    )
    assert raw == controlled_seed, "seed content changed during write"

    # Now verify genesis can load the seed and complete successfully.
    bundle_sk = SigningKey.generate()
    bundle_pub_hex = bytes(bundle_sk.verify_key).hex()

    genesis_tracker = _MockTracker({
        "/signer/token": {"token": "tok-r21"},
        "/signer/genesis": {"version": 1},
    })

    with patch.dict(os.environ, {"SANDBOX_KEY_HOME": str(kh)}):
        with patch("urllib.request.urlopen",
                   side_effect=genesis_tracker.urlopen):
            gen_result = CliRunner().invoke(cli, [
                "signer", "genesis",
                "--genesis-code", "code-r21",
                "--bundle-signer-key", bundle_pub_hex,
                "--confirm-identity", "https://idp.test", "sub-r21",
                "--yes",
            ])

    bad_opt = _detect_unknown_option(gen_result)
    if bad_opt:
        raise M2T12dPending(f"genesis flag not implemented: {bad_opt}")

    assert gen_result.exit_code == 0, (
        f"genesis with 0x0A/0x0D seed failed: exit {gen_result.exit_code}: "
        f"{gen_result.output}"
    )


# ---------------------------------------------------------------------------
# R2-3: redirect tests against a real local http.server (not mocked)
# ---------------------------------------------------------------------------


def test_r2_3_redirect_302_real_server(tmp_path):
    """R2-3: a real 302 from the signer endpoint -> exit 1 with 'redirect'
    in the output, 'Published' never printed, and the redirect target
    receives no request and no Authorization header.

    Uses two real ``http.server`` instances on 127.0.0.1 in threads:
    one that returns 302, one that records incoming requests (spy).
    """
    from sandbox.cli.main import cli

    admin_sk = SigningKey.generate()
    bundle_pub_hex = bytes(SigningKey.generate().verify_key).hex()

    spy_cls = _make_spy_handler()

    with _local_server(spy_cls) as spy_url:
        redir_cls = _make_signer_redirect_handler(302, spy_url)
        with _local_server(redir_cls) as redir_url:
            meta = {
                "server": redir_url,
                "key_id": _kid(admin_sk),
                "org_id": "org-r23",
                "user_id": "u-r23",
                "iss": "https://idp.test",
                "sub": "sub-r23",
            }
            kh = _make_key_home(tmp_path, admin_sk, meta)

            with patch.dict(os.environ, {"SANDBOX_KEY_HOME": str(kh)}):
                result = CliRunner().invoke(cli, [
                    "signer", "genesis",
                    "--genesis-code", "code-r23",
                    "--bundle-signer-key", bundle_pub_hex,
                    "--confirm-identity", "https://idp.test", "sub-r23",
                    "--yes",
                ])

    assert result.exit_code == 1, (
        f"expected exit 1 for 302 redirect, "
        f"got {result.exit_code}: {result.output}"
    )
    out = (result.output or "").lower()
    assert "redirect" in out, (
        f"output should mention 'redirect': {result.output}"
    )
    assert "published" not in out, (
        f"'Published' must never appear: {result.output}"
    )
    assert spy_cls.requests == [], (
        f"redirect target received requests: {spy_cls.requests}"
    )
    assert spy_cls.auth_headers == [], (
        f"redirect target received Authorization: {spy_cls.auth_headers}"
    )


def test_r2_3_redirect_307_real_server(tmp_path):
    """R2-3: a real 307 (Temporary Redirect) from the signer endpoint ->
    exit 1 with 'redirect', 'Published' never printed, redirect target
    receives nothing.  Same structure as the 302 test."""
    from sandbox.cli.main import cli

    admin_sk = SigningKey.generate()
    bundle_pub_hex = bytes(SigningKey.generate().verify_key).hex()

    spy_cls = _make_spy_handler()

    with _local_server(spy_cls) as spy_url:
        redir_cls = _make_signer_redirect_handler(307, spy_url)
        with _local_server(redir_cls) as redir_url:
            meta = {
                "server": redir_url,
                "key_id": _kid(admin_sk),
                "org_id": "org-r23b",
                "user_id": "u-r23b",
                "iss": "https://idp.test",
                "sub": "sub-r23b",
            }
            kh = _make_key_home(tmp_path, admin_sk, meta)

            with patch.dict(os.environ, {"SANDBOX_KEY_HOME": str(kh)}):
                result = CliRunner().invoke(cli, [
                    "signer", "genesis",
                    "--genesis-code", "code-r23b",
                    "--bundle-signer-key", bundle_pub_hex,
                    "--confirm-identity", "https://idp.test", "sub-r23b",
                    "--yes",
                ])

    assert result.exit_code == 1, (
        f"expected exit 1 for 307 redirect, "
        f"got {result.exit_code}: {result.output}"
    )
    out = (result.output or "").lower()
    assert "redirect" in out, (
        f"output should mention 'redirect': {result.output}"
    )
    assert "published" not in out, (
        f"'Published' must never appear: {result.output}"
    )
    assert spy_cls.requests == [], (
        f"redirect target received requests: {spy_cls.requests}"
    )
    assert spy_cls.auth_headers == [], (
        f"redirect target received Authorization: {spy_cls.auth_headers}"
    )


def test_r2_3_link_non_loopback_http_refuses(tmp_path):
    """R2-3: ``signer link`` to a non-loopback http:// URL exits 1 and
    sends nothing.  The transport check runs before any network call,
    so the spy server on 127.0.0.1 must receive zero requests."""
    from sandbox.cli.main import cli

    spy_cls = _make_spy_handler()

    with _local_server(spy_cls) as spy_url:
        # Extract the port from the spy URL and build a non-loopback URL
        # using the same port.  _check_transport_safety refuses based on
        # hostname, so 'evil.test' fails even though the port is local.
        port = spy_url.rsplit(":", 1)[-1]
        evil_url = f"http://evil.test:{port}"

        kh = tmp_path / "keyhome"
        kh.mkdir()

        with patch.dict(os.environ, {"SANDBOX_KEY_HOME": str(kh)}):
            result = CliRunner().invoke(cli, [
                "signer", "link",
                "--code", "test-code",
                "--server", evil_url,
            ])

    assert result.exit_code == 1, (
        f"expected exit 1 for non-loopback http, "
        f"got {result.exit_code}: {result.output}"
    )
    out = (result.output or "").lower()
    assert "https" in out or "http" in out or "loopback" in out, (
        f"refusal should mention transport: {result.output}"
    )
    assert spy_cls.requests == [], (
        f"spy server received requests despite non-loopback refusal: "
        f"{spy_cls.requests}"
    )


# ---------------------------------------------------------------------------
# R2-2: _refresh_registry_chain security invariants
# ---------------------------------------------------------------------------


def _r2_setup_enrolled_workspace(tmp_path, org_id="org-r22"):
    """Create a minimal enrolled workspace with pinned root, registry v3
    chain, and high_water.json at version 3.  Returns (lay, sync_dir, fp,
    v3_chain_blob)."""
    from sandbox.connector.layout import FolderLayout
    from sandbox.connector.sync.signer import build_genesis
    from sandbox.protocol.registry import verify_chain

    ws = tmp_path / "ws"
    ws.mkdir(parents=True, exist_ok=True)
    (ws / ".sandbox").mkdir(exist_ok=True)
    lay = FolderLayout(ws)
    sync_dir = ws / ".sandbox" / "state" / "sync"
    sync_dir.mkdir(parents=True, exist_ok=True)

    # Build a real verifiable v1 chain
    admin_sk = SigningKey.generate()
    bsk = SigningKey.generate()
    bundle_pub = bytes(bsk.verify_key)
    v1_env, fp = build_genesis(
        admin_sk, org_id, "https://idp", "sub-1", bundle_pub,
        user_id="u-r22",
    )

    # Build v2 and v3 by extending the chain (signed by admin)
    from sandbox.protocol.envelope import canonical_bytes
    from sandbox.protocol.domains import REGISTRY

    def _extend(prev_envs, version, admin_sk_local):
        prev_payload = prev_envs[-1]["payload"]
        kid = hashlib.sha256(bytes(admin_sk_local.verify_key)).hexdigest()
        prev_canonical = json.dumps(
            prev_payload, sort_keys=True, separators=(",", ":"),
        ).encode()
        prev_hash = hashlib.sha256(
            prev_payload["org_id"].encode("utf-8") + b":" + prev_canonical,
        ).hexdigest()
        new_payload = dict(prev_payload)
        new_payload["version"] = version
        new_payload["prev_hash"] = prev_hash
        new_canonical = json.dumps(
            new_payload, sort_keys=True, separators=(",", ":"),
        ).encode()
        msg = b"agg/registry/v1\x00" + new_canonical
        sig = admin_sk_local.sign(msg).signature.hex()
        return {
            "kind": "agg/registry/v1", "sig_v": 1,
            "payload": new_payload,
            "signatures": [{"key_id": kid, "alg": "ed25519", "sig": sig}],
        }

    v2_env = _extend([v1_env], 2, admin_sk)
    v3_env = _extend([v1_env, v2_env], 3, admin_sk)
    chain_v3 = [v1_env, v2_env, v3_env]

    # Verify the chain is actually valid
    verify_chain(chain_v3, fp)

    # Write enrolled state
    (sync_dir / "pinned_root.json").write_text(
        json.dumps({"fingerprint": fp}), encoding="utf-8",
    )
    chain_blob = json.dumps(chain_v3, sort_keys=True, separators=(",", ":"))
    (sync_dir / "registry.json").write_text(chain_blob, encoding="utf-8")
    (sync_dir / "high_water.json").write_text(
        json.dumps({"registry_version": 3, "bundle_sequence": 1}),
        encoding="utf-8",
    )
    (sync_dir / "managed").write_text("1", encoding="utf-8")

    return lay, sync_dir, fp, chain_v3, admin_sk


def test_r2_2a_rollback_floor_uses_max_of_local_and_hwm(tmp_path):
    """R2-2(a): the rollback floor is max(local registry.json version,
    high_water.json registry_version).  A server serving v2 when the floor
    is 3 must be refused and nothing written."""
    lay, sync_dir, fp, chain_v3, admin_sk = _r2_setup_enrolled_workspace(
        tmp_path,
    )

    # Delete local registry.json -- leaves only high_water at 3
    (sync_dir / "registry.json").unlink()

    # The server serves v2 (below the floor of 3)
    chain_v2 = chain_v3[:2]  # v1 + v2 only
    server_response = json.dumps({"registry": chain_v2}).encode()

    from unittest.mock import MagicMock
    mock_resp = MagicMock()
    mock_resp.read.return_value = server_response
    mock_resp.status = 200
    mock_resp.getcode.return_value = 200

    from sandbox.cli.sync_cmds import _refresh_registry_chain

    with patch("urllib.request.urlopen", return_value=mock_resp):
        _refresh_registry_chain(lay, "https://localhost:9000", "tok-test")

    # Nothing should be written
    assert not (sync_dir / "registry.json").exists(), (
        "R2-2(a): _refresh_registry_chain wrote registry.json for v2 "
        "when the floor (hwm) was 3"
    )

    # Verified state must stay None (fail closed)
    from sandbox.connector.sync.verified_state import load_verified_state
    vs = load_verified_state(lay)
    assert vs is None, (
        "R2-2(a): load_verified_state returned non-None after rollback attempt"
    )


def test_r2_2b_missing_high_water_refuses_not_recreates(tmp_path):
    """R2-2(b): a missing or corrupt high_water.json gives a refusal
    (the function returns without writing), not a recreated file with
    bundle_sequence 0.

    Scenario: local registry at v2, hwm deleted, server serves v3.  The
    function must refuse because the floor cannot be determined (hwm is
    missing).  It must NOT persist v3 or recreate hwm."""
    lay, sync_dir, fp, chain_v3, admin_sk = _r2_setup_enrolled_workspace(
        tmp_path,
    )

    # Set local registry to v2 so the server's v3 would normally be persisted
    chain_v2 = chain_v3[:2]
    (sync_dir / "registry.json").write_text(
        json.dumps(chain_v2, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )

    # Delete high_water.json -- the floor cannot be determined
    (sync_dir / "high_water.json").unlink()

    # The server serves v3 (higher than local v2)
    server_response = json.dumps({"registry": chain_v3}).encode()

    from unittest.mock import MagicMock
    mock_resp = MagicMock()
    mock_resp.read.return_value = server_response
    mock_resp.status = 200
    mock_resp.getcode.return_value = 200

    from sandbox.cli.sync_cmds import _refresh_registry_chain

    with patch("urllib.request.urlopen", return_value=mock_resp):
        _refresh_registry_chain(lay, "https://localhost:9000", "tok-test")

    # The function must NOT recreate high_water.json
    assert not (sync_dir / "high_water.json").exists(), (
        "R2-2(b): _refresh_registry_chain recreated high_water.json when it "
        "was missing (should refuse, not recreate with bundle_sequence 0)"
    )

    # Registry must stay at v2 (the update should be refused)
    reg_data = json.loads(
        (sync_dir / "registry.json").read_text(encoding="utf-8"),
    )
    if isinstance(reg_data, list) and reg_data:
        cur_ver = reg_data[-1].get("payload", {}).get("version", 0)
    else:
        cur_ver = 0
    assert cur_ver == 2, (
        f"R2-2(b): registry was updated to v{cur_ver} despite missing hwm "
        f"(should have refused)"
    )


def test_r2_2c_refresh_never_writes_high_water(tmp_path):
    """R2-2(c): the function never writes high_water.json.  Only
    load_verified_state ratchets it through _save_high_water.

    Scenario: server serves v3 over a local v2.  After refresh, the
    registry is updated to v3, but high_water.json stays at its original
    value (the next load_verified_state call ratchets it)."""
    lay, sync_dir, fp, chain_v3, admin_sk = _r2_setup_enrolled_workspace(
        tmp_path,
    )

    # Set local state to v2
    chain_v2 = chain_v3[:2]
    (sync_dir / "registry.json").write_text(
        json.dumps(chain_v2, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )
    (sync_dir / "high_water.json").write_text(
        json.dumps({"registry_version": 2, "bundle_sequence": 1}),
        encoding="utf-8",
    )

    # Server serves v3
    server_response = json.dumps({"registry": chain_v3}).encode()

    from unittest.mock import MagicMock
    mock_resp = MagicMock()
    mock_resp.read.return_value = server_response
    mock_resp.status = 200
    mock_resp.getcode.return_value = 200

    from sandbox.cli.sync_cmds import _refresh_registry_chain

    with patch("urllib.request.urlopen", return_value=mock_resp):
        _refresh_registry_chain(lay, "https://localhost:9000", "tok-test")

    # Registry should be updated to v3
    reg_data = json.loads(
        (sync_dir / "registry.json").read_text(encoding="utf-8"),
    )
    if isinstance(reg_data, list) and reg_data:
        new_ver = reg_data[-1].get("payload", {}).get("version", 0)
    else:
        new_ver = 0
    assert new_ver == 3, (
        f"expected registry to be updated to v3, got v{new_ver}"
    )

    # high_water.json must NOT have been written by _refresh_registry_chain
    hwm = json.loads(
        (sync_dir / "high_water.json").read_text(encoding="utf-8"),
    )
    assert hwm["registry_version"] == 2, (
        f"R2-2(c): _refresh_registry_chain wrote high_water.json "
        f"(registry_version went from 2 to {hwm['registry_version']}); "
        f"only load_verified_state should ratchet it"
    )


def test_r2_2_run_once_carries_registry_status(tmp_path, monkeypatch):
    """R2-2 item 4(b): the run_once result must carry a 'registry' status
    (refused | updated | unchanged | fetch_failed | verify_failed |
    rollback_refused)."""
    lay, sync_dir, fp, chain_v3, admin_sk = _r2_setup_enrolled_workspace(
        tmp_path,
    )

    monkeypatch.chdir(tmp_path / "ws")

    # Write enrollment.json with a server URL
    (sync_dir / "enrollment.json").write_text(
        json.dumps({
            "server_url": "https://localhost:9999",
            "device_id": "dev-r22",
            "org_id": "org-r22",
        }),
        encoding="utf-8",
    )

    # Mock all network calls to return empty/error
    from unittest.mock import MagicMock

    def _mock_urlopen(req, **kwargs):
        raise urllib.error.URLError("connection refused")

    from sandbox.cli.sync_cmds import run_once

    with patch("urllib.request.urlopen", side_effect=_mock_urlopen):
        result = run_once(lay, server="https://localhost:9999")

    assert "registry" in result, (
        f"R2-2: run_once result has no 'registry' key: {list(result.keys())}"
    )
    assert result["registry"] in (
        "refused", "updated", "unchanged", "current",
        "fetch_failed", "verify_failed", "rollback_refused",
    ), (
        f"R2-2: run_once registry status {result['registry']!r} is not "
        f"one of the expected values"
    )


def test_r2_2_shared_verify_persist_helper(tmp_path):
    """R2-2 item 4(c): the CLI _refresh_registry_chain and the connector
    process._fetch_registry both verify-and-persist a fetched chain.  Test
    through behaviour: after a successful update, both callers must produce
    the same high_water.json state.

    process._fetch_registry does NOT write high_water.json (verified_state
    ratchets it).  _refresh_registry_chain currently writes it, proving
    they use different code paths.  A shared helper would not write it.

    Scenario: local v2, server v3.  After refresh, registry is v3.  But
    high_water.json must NOT be updated by the refresh -- only
    load_verified_state should ratchet it.  (Overlaps with test_r2_2c
    but framed as a shared-helper divergence test.)"""
    lay, sync_dir, fp, chain_v3, admin_sk = _r2_setup_enrolled_workspace(
        tmp_path,
    )

    # Set local state to v2
    chain_v2 = chain_v3[:2]
    (sync_dir / "registry.json").write_text(
        json.dumps(chain_v2, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )
    (sync_dir / "high_water.json").write_text(
        json.dumps({"registry_version": 2, "bundle_sequence": 1}),
        encoding="utf-8",
    )

    # Server serves v3
    server_response = json.dumps({"registry": chain_v3}).encode()

    from unittest.mock import MagicMock
    mock_resp = MagicMock()
    mock_resp.read.return_value = server_response
    mock_resp.status = 200
    mock_resp.getcode.return_value = 200

    from sandbox.cli.sync_cmds import _refresh_registry_chain

    with patch("urllib.request.urlopen", return_value=mock_resp):
        _refresh_registry_chain(lay, "https://localhost:9000", "tok-test")

    # The registry should be updated to v3
    reg_data = json.loads(
        (sync_dir / "registry.json").read_text(encoding="utf-8"),
    )
    if isinstance(reg_data, list) and reg_data:
        new_ver = reg_data[-1].get("payload", {}).get("version", 0)
    else:
        new_ver = 0
    assert new_ver == 3, (
        f"expected registry to be updated to v3, got v{new_ver}"
    )

    # A shared helper would NOT write high_water.json (process._fetch_registry
    # does not).  _refresh_registry_chain currently writes it, which proves
    # the code paths diverge.
    hwm = json.loads(
        (sync_dir / "high_water.json").read_text(encoding="utf-8"),
    )
    assert hwm["registry_version"] == 2, (
        f"R2-2 item 4(c): _refresh_registry_chain wrote high_water.json "
        f"(registry_version went from 2 to {hwm['registry_version']}), "
        f"which process._fetch_registry would not do -- proves they are "
        f"separate implementations, not a shared helper"
    )
    assert hwm["bundle_sequence"] == 1, (
        f"R2-2 item 4(c): _refresh_registry_chain changed bundle_sequence "
        f"from 1 to {hwm['bundle_sequence']}"
    )


# ===========================================================================
# D2-2: threshold bound unconditional
# ===========================================================================


@pytest.mark.xfail(strict=True, raises=M2T12dPending,
                    reason="d5: D2-2 threshold bound unconditional")
def test_d5_threshold_bound_unconditional(tmp_path):
    """D2-2: v1 one admin u1; sign-registry --threshold 2 with no --add
    -> exit 1; message names 'distinct admin'; v2.json not written."""
    from sandbox.cli.main import cli

    admin_sk = SigningKey.generate()
    bundle_sk = SigningKey.generate()
    org_id = "org-d52"
    bundle_pub = bytes(bundle_sk.verify_key)
    v1_env, fp = _build_valid_chain_v1(
        admin_sk, org_id, "https://idp", "sub-1", bundle_pub, user_id="u1"
    )

    meta = {
        "server": "https://localhost:9000",
        "key_id": _kid(admin_sk),
        "org_id": org_id,
        "user_id": "u1",
        "iss": "https://idp",
        "sub": "sub-1",
    }
    kh = _make_key_home(tmp_path, admin_sk, meta)
    tracker = _signreg_tracker(v1_env)
    out_file = tmp_path / "v2.json"

    with patch.dict(os.environ, {"SANDBOX_KEY_HOME": str(kh)}):
        with patch("urllib.request.urlopen", side_effect=tracker.urlopen):
            result = CliRunner().invoke(cli, [
                "signer", "sign-registry",
                "--threshold", "2",
                "--out", str(out_file),
                "--expect-fingerprint", fp,
                "--yes",
            ])

    if result.exit_code == 0:
        raise M2T12dPending(
            "D2-2: sign-registry --threshold 2 with no --add exited 0"
        )
    assert result.exit_code == 1, (
        f"expected exit 1, got {result.exit_code}: {result.output}"
    )
    assert "distinct admin" in result.output.lower(), (
        f"expected 'distinct admin' in output: {result.output[:300]}"
    )
    assert not out_file.exists(), "v2.json should not have been written"


# ===========================================================================
# D2-3: link token failure reason class (parametrised)
# ===========================================================================


@pytest.mark.xfail(strict=True, raises=M2T12dPending,
                    reason="d5: D2-3 link token failure reason class")
@pytest.mark.parametrize("scenario,mock_response,expected_reason,forbidden_text", [
    (
        "http_401",
        "401_body",
        "(HTTP 401)",
        "SECRET-BODY-123",
    ),
    (
        "redirect",
        "302_redirect",
        "(redirect refused)",
        None,
    ),
    (
        "transport",
        "transport_error",
        "(transport refused)",
        None,
    ),
], ids=["http_401", "redirect", "transport"])
def test_d5_link_token_failure_reason_class(
    tmp_path, scenario, mock_response, expected_reason, forbidden_text,
):
    """D2-3: _get_link_signer_token returns a reason class; the CLI
    prints it; never prints SECRET-BODY-123."""
    from sandbox.cli.main import cli

    admin_sk = SigningKey.generate()
    org_id = "org-d53"
    meta = {
        "server": "https://localhost:9000",
        "key_id": _kid(admin_sk),
        "org_id": org_id,
        "user_id": "u1",
        "iss": "https://idp",
        "sub": "sub-1",
    }
    kh = _make_key_home(tmp_path, admin_sk, meta)

    # Build mock routes based on scenario
    if mock_response == "401_body":
        token_resp = HTTPError(
            "http://localhost:9000/api/v1/sync/signer/token",
            401, "Unauthorized", {},
            io.BytesIO(b"SECRET-BODY-123"),
        )
    elif mock_response == "302_redirect":
        token_resp = HTTPError(
            "http://localhost:9000/api/v1/sync/signer/token",
            302, "Redirect", {"Location": "http://evil.test/phish"},
            io.BytesIO(b""),
        )
    elif mock_response == "transport_error":
        # Use example.com (transport error)
        token_resp = URLError("connection refused")

    # The link command first POSTs to /signer/link (must succeed),
    # then calls _get_link_signer_token which hits /signer/token.
    link_response = {
        "status": "linked", "key_id": _kid(admin_sk),
        "iss": "https://idp", "sub": "sub-1",
    }
    routes = {
        "/signer/link": link_response,
        "/signer/token": token_resp,
    }
    tracker = _MockTracker(routes)

    with patch.dict(os.environ, {"SANDBOX_KEY_HOME": str(kh)}):
        with patch("urllib.request.urlopen", side_effect=tracker.urlopen):
            result = CliRunner().invoke(cli, [
                "signer", "link",
                "--code", "test-code",
                "--server", "http://localhost:9000",
            ])

    # Today the link command does not print the reason class from
    # _get_link_signer_token; d5 adds that.
    if expected_reason not in (result.output or ""):
        raise M2T12dPending(
            f"D2-3 {scenario}: expected reason {expected_reason!r} not in "
            f"output: {result.output[:300]}"
        )
    assert result.exit_code == 1, (
        f"expected exit 1, got {result.exit_code}: {result.output}"
    )
    if forbidden_text:
        assert forbidden_text not in result.output, (
            f"forbidden text {forbidden_text!r} found in output"
        )


# ===========================================================================
# D2-4: _get_link_signer_token log format (static AST check)
# ===========================================================================


@pytest.mark.xfail(strict=True, raises=M2T12dPending,
                    reason="d5: D2-4 _get_link_signer_token log format")
def test_d5_link_token_log_format_has_no_token_word():
    """D2-4: AST walk of _get_link_signer_token: no 'token' in log strings,
    no exc argument in log calls."""
    import ast
    import inspect
    from sandbox.cli.sync_cmds import _get_link_signer_token

    source = inspect.getsource(_get_link_signer_token)
    tree = ast.parse(source)

    log_methods = {"debug", "info", "warning", "error", "exception"}
    violations = []

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if not isinstance(func, ast.Attribute):
            continue
        if func.attr not in log_methods:
            continue

        # Check first arg for 'token' word
        if node.args:
            first_arg = node.args[0]
            if isinstance(first_arg, ast.Constant):
                val = first_arg.value
                if isinstance(val, str) and "token" in val.lower():
                    violations.append(
                        f"line ~{node.lineno}: log string contains 'token'"
                    )

        # Check for exc_info or exc keyword argument
        for kw in node.keywords:
            if kw.arg in ("exc_info", "exc"):
                violations.append(
                    f"line ~{node.lineno}: log call has '{kw.arg}' argument"
                )

    if violations:
        raise M2T12dPending(
            f"D2-4: _get_link_signer_token log violations: {violations}"
        )
    # The function must also return a reason class, not just None.
    # Today it returns None on failure with no reason.
    # Check if the function returns a reason string or just None.
    # If the function signature lacks the reason class return,
    # the product has not been updated.
    sig = inspect.signature(_get_link_signer_token)
    ret_annotation = sig.return_annotation
    # Today the function returns str | None (token or None);
    # d5 changes it to return a reason class.
    # Detect by checking source for "reason" pattern.
    if "reason" not in source.lower() or "redirect refused" not in source:
        raise M2T12dPending(
            "D2-4: _get_link_signer_token does not return reason classes yet"
        )


# ===========================================================================
# D2-5: registry verify_failed writes audit
# ===========================================================================


@pytest.mark.xfail(strict=True, raises=M2T12dPending,
                    reason="d5: D2-5 registry verify_failed audit")
def test_d5_registry_verify_failed_writes_audit(tmp_path):
    """D2-5: offer a v4 signed by a stranger key -> refused:verify_failed;
    exactly one registry_refused audit event with reason_code
    REGISTRY_VERIFY_FAILED."""
    lay, sync_dir, fp, chain_v3, admin_sk = _r2_setup_enrolled_workspace(
        tmp_path,
    )

    # Build a v4 signed by a stranger key
    stranger_sk = SigningKey.generate()
    stranger_kid = hashlib.sha256(
        bytes(stranger_sk.verify_key)
    ).hexdigest()

    prev_payload = chain_v3[-1]["payload"]
    prev_canonical = json.dumps(
        prev_payload, sort_keys=True, separators=(",", ":"),
    ).encode()
    prev_hash = hashlib.sha256(
        prev_payload["org_id"].encode("utf-8") + b":" + prev_canonical,
    ).hexdigest()

    v4_payload = dict(prev_payload, version=4, prev_hash=prev_hash)
    v4_canonical = json.dumps(
        v4_payload, sort_keys=True, separators=(",", ":"),
    ).encode()
    msg = b"agg/registry/v1\x00" + v4_canonical
    sig = stranger_sk.sign(msg).signature.hex()
    v4_env = {
        "kind": "agg/registry/v1", "sig_v": 1,
        "payload": v4_payload,
        "signatures": [{"key_id": stranger_kid, "alg": "ed25519", "sig": sig}],
    }

    bad_chain = chain_v3 + [v4_env]

    from sandbox.connector.sync.registry_chain import apply_registry_chain
    status = apply_registry_chain(lay, bad_chain)
    assert status == "refused:verify_failed", f"got {status!r}"

    # Check audit
    events = _audit_events_from_layout(lay)
    refused_events = [
        e for e in events if e.get("event") == "registry_refused"
    ]

    if not refused_events:
        raise M2T12dPending("D2-5: no registry_refused audit event")

    assert len(refused_events) == 1
    ev = refused_events[0]
    assert ev.get("reason_code") == "REGISTRY_VERIFY_FAILED"
    assert ev.get("offered_version") == 4
    assert ev.get("floor") == 3

    # registry.json unchanged
    reg_data = json.loads(
        (sync_dir / "registry.json").read_text(encoding="utf-8")
    )
    assert reg_data[-1]["payload"]["version"] == 3


# ===========================================================================
# D2-6: registry rollback writes audit
# ===========================================================================


@pytest.mark.xfail(strict=True, raises=M2T12dPending,
                    reason="d5: D2-6 registry rollback audit")
def test_d5_registry_rollback_writes_audit(tmp_path):
    """D2-6: offer chain_v3[:2] -> refused:rollback; one registry_refused
    event with REGISTRY_ROLLBACK."""
    lay, sync_dir, fp, chain_v3, admin_sk = _r2_setup_enrolled_workspace(
        tmp_path,
    )

    from sandbox.connector.sync.registry_chain import apply_registry_chain
    status = apply_registry_chain(lay, chain_v3[:2])
    assert status == "refused:rollback", f"got {status!r}"

    events = _audit_events_from_layout(lay)
    refused_events = [
        e for e in events if e.get("event") == "registry_refused"
    ]

    if not refused_events:
        raise M2T12dPending("D2-6: no registry_refused audit event")

    assert len(refused_events) == 1
    ev = refused_events[0]
    assert ev.get("reason_code") == "REGISTRY_ROLLBACK"


# ===========================================================================
# D2-7: registry update no refusal audit (twin, plain pass)
# ===========================================================================


def test_d5_registry_update_no_refusal_audit(tmp_path):
    """D2-7 twin: offer a correctly signed v4 -> updated; no registry_refused
    event."""
    lay, sync_dir, fp, chain_v3, admin_sk = _r2_setup_enrolled_workspace(
        tmp_path,
    )

    # Build a valid v4
    prev_payload = chain_v3[-1]["payload"]
    prev_canonical = json.dumps(
        prev_payload, sort_keys=True, separators=(",", ":"),
    ).encode()
    prev_hash = hashlib.sha256(
        prev_payload["org_id"].encode("utf-8") + b":" + prev_canonical,
    ).hexdigest()

    admin_kid = hashlib.sha256(bytes(admin_sk.verify_key)).hexdigest()
    v4_payload = dict(prev_payload, version=4, prev_hash=prev_hash)
    v4_canonical = json.dumps(
        v4_payload, sort_keys=True, separators=(",", ":"),
    ).encode()
    msg = b"agg/registry/v1\x00" + v4_canonical
    sig = admin_sk.sign(msg).signature.hex()
    v4_env = {
        "kind": "agg/registry/v1", "sig_v": 1,
        "payload": v4_payload,
        "signatures": [{"key_id": admin_kid, "alg": "ed25519", "sig": sig}],
    }

    good_chain = chain_v3 + [v4_env]

    from sandbox.connector.sync.registry_chain import apply_registry_chain
    status = apply_registry_chain(lay, good_chain)
    assert status == "updated", f"got {status!r}"

    events = _audit_events_from_layout(lay)
    refused_events = [
        e for e in events if e.get("event") == "registry_refused"
    ]
    assert len(refused_events) == 0, (
        f"expected no registry_refused events, got {len(refused_events)}"
    )


# ===========================================================================
# Audit reader helper (D2-5..7)
# ===========================================================================


def _audit_events_from_layout(layout) -> list[dict]:
    """Read all audit events from the layout's audit_dir."""
    out = []
    if not layout.audit_dir.is_dir():
        return out
    for f in layout.audit_dir.rglob("*.jsonl"):
        for line in f.read_text(encoding="utf-8").splitlines():
            if line.strip():
                out.append(json.loads(line))
    return out
