"""T15b-2 tests-first: approve/deny/sync and the connector daemon must use
the hardened transport (T15B_SECURITY_REVIEW.md, T15b-2).

Interface contract (pinned -- the build removes only xfail markers)
-------------------------------------------------------------------
* ``sandbox signer approve|deny`` and ``sandbox sync`` go through the
  ``_signer_safe_*`` / ``_check_transport_safety`` rules:
  - ``http://`` to a non-loopback host is refused before any socket;
  - a 3xx is refused (exit 1, output names "redirect"), nothing is POSTed
    and no Authorization header ever reaches the redirect target, even
    when another module has reinstalled urllib's default opener;
  - the token text never appears in output or exception text.
* ``src/sandbox/connector/sync/process.py::_default_connect`` (the
  ``SyncProcess._connect`` default) applies the same scheme and redirect
  rules.
* The dead helpers ``_signer_http_get`` / ``_signer_http_post`` are gone.

Pattern: CliRunner plus real local ``http.server`` instances on
127.0.0.1 (a redirecting server and a spy), as in
``tests/security/test_m2_t12d_signer_cli.py`` R2-3.  RED tests carry
``xfail(strict=True, raises=M2T15bTransportPending)``.
"""
from __future__ import annotations

import contextlib
import json
import os
import urllib.request
from http.server import BaseHTTPRequestHandler
from unittest.mock import patch

import pytest
from click.testing import CliRunner
from nacl.signing import SigningKey

from tests.security.test_m2_t12d_signer_cli import (
    _MockTracker,
    _kid,
    _local_server,
    _make_spy_handler,
    _r2_setup_enrolled_workspace,
)


# ---------------------------------------------------------------------------
# Sentinel
# ---------------------------------------------------------------------------

class M2T15bTransportPending(Exception):
    """T15b-2: approve/deny/sync/daemon still use raw urlopen transport."""


_TOKEN = "tok-t15b2-secret-never-printed"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _esc_record(root: str) -> dict:
    """A valid fp_v 2 escalation record, as GET-by-id returns it."""
    from sandbox.connector.approval import _binding_fingerprint
    rec = {
        "request_id": "esc-t15b2",
        "command": "echo test",
        "status": "pending",
        "requires_dual": False,
        "policy_sequence": 1,
        "risk": {"band": "high"},
        "root": root,
        "kind": "shell",
        "tool_name": "Bash",
        "exec_cwd": root,
        "bundle_sequence": 1,
        "fp_v": 2,
        "script": None,
        "script_unbound": "",
        "script_preview": None,
    }
    rec["fingerprint"] = _binding_fingerprint(rec)
    return rec


def _make_signer_server_handler(esc: dict, *, redirect_on: str,
                                redirect_code: int, target_url: str):
    """Serve /signer/token (200) and /escalations/<id> (200) normally,
    but answer *redirect_on* (a path substring) with a 3xx to *target_url*."""

    class _H(BaseHTTPRequestHandler):
        requests: list[tuple[str, str]] = []

        def _maybe_redirect(self) -> bool:
            if redirect_on in self.path:
                self.send_response(redirect_code)
                self.send_header("Location", target_url + self.path)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return True
            return False

        def do_POST(self):  # noqa: N802
            length = int(self.headers.get("Content-Length", 0))
            self.rfile.read(length)
            _H.requests.append(("POST", self.path))
            if self._maybe_redirect():
                return
            if "/signer/token" in self.path:
                self._json_ok({"token": _TOKEN})
            else:
                self._json_ok({"ok": True})

        def do_GET(self):  # noqa: N802
            _H.requests.append(("GET", self.path))
            if self._maybe_redirect():
                return
            self._json_ok(esc)

        def _json_ok(self, obj):
            body = json.dumps(obj).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, fmt, *args):  # noqa: D102
            pass

    _H.requests = []
    return _H


def _link_key_home(tmp_path):
    """Run ``signer link`` against a mocked server so signer.seed and
    link.json exist (the same key home approve/deny read)."""
    from sandbox.cli.main import cli

    kh = tmp_path / "keyhome"
    kh.mkdir()
    tracker = _MockTracker({"/signer/link": {
        "org_id": "org-t15b2", "user_id": "u-t15b2",
        "iss": "https://idp.test", "sub": "sub-t15b2",
    }})
    with patch.dict(os.environ, {"SANDBOX_KEY_HOME": str(kh)}):
        with patch("urllib.request.urlopen", side_effect=tracker.urlopen):
            r = CliRunner().invoke(cli, [
                "signer", "link", "--code", "c-t15b2",
                "--server", "https://localhost:9000",
            ])
    assert r.exit_code == 0, f"link setup failed: {r.output}"
    return kh


@contextlib.contextmanager
def _plain_default_opener():
    """Simulate another module reinstalling urllib's default opener (no
    no-redirect guard).  Restores the previous opener afterwards."""
    saved = urllib.request._opener  # noqa: SLF001
    urllib.request.install_opener(urllib.request.build_opener())
    try:
        yield
    finally:
        urllib.request._opener = saved  # noqa: SLF001


def _invoke_signer(verb: str, kh, server: str):
    from sandbox.cli.main import cli
    with patch.dict(os.environ, {"SANDBOX_KEY_HOME": str(kh)}):
        return CliRunner().invoke(cli, [
            "signer", verb, "esc-t15b2", "--server", server, "--yes",
        ])


def _assert_redirect_refused(result, spy_cls, label: str):
    out = (result.output or "")
    low = out.lower()
    assert _TOKEN not in out, f"{label}: token text leaked into output"
    if result.exit_code == 0 or "redirect" not in low:
        raise M2T15bTransportPending(
            f"{label}: expected exit 1 naming 'redirect', got "
            f"exit {result.exit_code}: {out[:200]!r}"
        )
    assert result.exit_code == 1
    assert "published" not in low and "approved" not in low
    assert spy_cls.requests == [], (
        f"{label}: redirect target received {spy_cls.requests}"
    )
    assert spy_cls.auth_headers == [], (
        f"{label}: redirect target received Authorization"
    )


# ---------------------------------------------------------------------------
# 302 on the approval POST and on the detail GET
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("verb", ["approve", "deny"])
def test_t15b2_302_on_approval_post_refused(tmp_path, verb):
    """A 302 on POST .../approvals: exit 1 naming 'redirect', the redirect
    target gets no request and no Authorization, token never printed."""
    kh = _link_key_home(tmp_path)
    spy_cls = _make_spy_handler()
    with _local_server(spy_cls) as spy_url:
        h = _make_signer_server_handler(
            _esc_record(str(tmp_path)), redirect_on="/approvals",
            redirect_code=302, target_url=spy_url,
        )
        with _local_server(h) as srv_url:
            result = _invoke_signer(verb, kh, srv_url)
    _assert_redirect_refused(result, spy_cls, f"{verb} 302 on POST")


@pytest.mark.parametrize("verb", ["approve", "deny"])
def test_t15b2_302_on_detail_get_refused(tmp_path, verb):
    """A 302 on GET /escalations/<id>: exit 1 naming 'redirect' (not a
    swallowed 'not found'), nothing POSTed, spy gets nothing."""
    kh = _link_key_home(tmp_path)
    spy_cls = _make_spy_handler()
    with _local_server(spy_cls) as spy_url:
        h = _make_signer_server_handler(
            _esc_record(str(tmp_path)), redirect_on="/escalations/",
            redirect_code=302, target_url=spy_url,
        )
        with _local_server(h) as srv_url:
            result = _invoke_signer(verb, kh, srv_url)
    _assert_redirect_refused(result, spy_cls, f"{verb} 302 on GET")
    assert not [r for r in h.requests if r[0] == "POST" and "/approvals" in r[1]], (
        "approval POSTed after a redirected detail fetch"
    )


@pytest.mark.parametrize("verb", ["approve", "deny"])
def test_t15b2_no_token_forwarded_when_default_opener_reinstalled(tmp_path, verb):
    """Belt and suspenders: with urllib's plain default opener (as if an
    imported module replaced the global no-redirect guard), a 302 on the
    approval POST must still never carry the Bearer token to the target
    (``add_unredirected_header``) and the command must exit 1."""
    kh = _link_key_home(tmp_path)
    spy_cls = _make_spy_handler()
    with _local_server(spy_cls) as spy_url:
        h = _make_signer_server_handler(
            _esc_record(str(tmp_path)), redirect_on="/approvals",
            redirect_code=302, target_url=spy_url,
        )
        with _local_server(h) as srv_url, _plain_default_opener():
            result = _invoke_signer(verb, kh, srv_url)
    out = result.output or ""
    assert _TOKEN not in out, "token text leaked into output"
    if spy_cls.auth_headers or result.exit_code == 0:
        raise M2T15bTransportPending(
            f"{verb}: Bearer forwarded on redirect "
            f"(auth_headers={len(spy_cls.auth_headers)}, "
            f"exit={result.exit_code})"
        )
    assert spy_cls.auth_headers == []
    assert result.exit_code == 1


# ---------------------------------------------------------------------------
# http:// to a non-loopback host: refused before any socket
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("verb", ["approve", "deny"])
def test_t15b2_http_non_loopback_refused_before_socket(tmp_path, verb):
    """``--server http://evil.test`` -> exit 1 naming the transport and
    zero urlopen calls (the token request must not go out in clear)."""
    kh = _link_key_home(tmp_path)
    tracker = _MockTracker({
        "/signer/token": {"token": _TOKEN},
        "/escalations": _esc_record(str(tmp_path)),
        "/approvals": {"ok": True},
    })
    from sandbox.cli.main import cli
    with patch.dict(os.environ, {"SANDBOX_KEY_HOME": str(kh)}):
        with patch("urllib.request.urlopen", side_effect=tracker.urlopen):
            result = CliRunner().invoke(cli, [
                "signer", verb, "esc-t15b2",
                "--server", "http://evil.test:9000", "--yes",
            ])
    out = (result.output or "")
    assert _TOKEN not in out
    if tracker.requested_urls or result.exit_code == 0:
        raise M2T15bTransportPending(
            f"{verb}: http non-loopback not refused before the socket: "
            f"exit={result.exit_code} urls={tracker.requested_urls}"
        )
    assert result.exit_code == 1
    low = out.lower()
    assert "https" in low or "loopback" in low, f"no transport reason: {out}"


def test_t15b2_sync_http_non_loopback_refused_before_socket(tmp_path, monkeypatch):
    """``sandbox sync --once --server http://evil.test`` in a managed
    workspace exits non-zero before any urlopen (device token, decisions,
    registry: none may travel in clear)."""
    lay, sync_dir, fp, chain_v3, admin_sk = _r2_setup_enrolled_workspace(
        tmp_path, org_id="org-t15b2",
    )
    (sync_dir / "enrollment.json").write_text(json.dumps({
        "server_url": "http://evil.test:9000", "device_id": "dev-t15b2",
        "org_id": "org-t15b2",
    }), encoding="utf-8")
    monkeypatch.chdir(tmp_path / "ws")

    tracker = _MockTracker({})
    from sandbox.cli.main import cli
    with patch("urllib.request.urlopen", side_effect=tracker.urlopen):
        result = CliRunner().invoke(cli, [
            "sync", "--once", "--server", "http://evil.test:9000",
        ])
    if tracker.requested_urls or result.exit_code == 0:
        raise M2T15bTransportPending(
            f"sync: http non-loopback not refused before the socket: "
            f"exit={result.exit_code} urls={tracker.requested_urls}"
        )
    assert result.exit_code == 1
    low = (result.output or "").lower()
    assert "https" in low or "loopback" in low, f"no transport reason: {result.output}"


def test_t15b2_twin_sync_loopback_http_still_allowed(tmp_path, monkeypatch):
    """Positive twin (holds today): loopback http is accepted by the sync
    path; the network calls are attempted (and fail harmlessly here)."""
    lay, sync_dir, fp, chain_v3, admin_sk = _r2_setup_enrolled_workspace(
        tmp_path, org_id="org-t15b2b",
    )
    (sync_dir / "enrollment.json").write_text(json.dumps({
        "server_url": "http://127.0.0.1:9", "device_id": "dev-t15b2b",
        "org_id": "org-t15b2b",
    }), encoding="utf-8")
    monkeypatch.chdir(tmp_path / "ws")
    tracker = _MockTracker({})
    from sandbox.cli.main import cli
    with patch("urllib.request.urlopen", side_effect=tracker.urlopen):
        result = CliRunner().invoke(cli, ["sync", "--once", "--server", "http://127.0.0.1:9"])
    low = (result.output or "").lower()
    assert "loopback" not in low and "use https" not in low, (
        f"loopback http wrongly refused: {result.output}"
    )
    assert tracker.requested_urls, "sync made no network call on loopback http"


# ---------------------------------------------------------------------------
# Enroll (re-review MUST-2)
# ---------------------------------------------------------------------------

def test_t15b2_enroll_http_non_loopback_refused_before_socket(tmp_path, monkeypatch):
    """T15b re-review MUST-2: ``sandbox enroll --server http://<remote>``
    exits non-zero before any socket, so the one-time code never travels
    in clear."""
    monkeypatch.chdir(tmp_path)
    tracker = _MockTracker({})
    from sandbox.cli.main import cli
    with patch("urllib.request.urlopen", side_effect=tracker.urlopen):
        result = CliRunner().invoke(cli, [
            "enroll", "--server", "http://203.0.113.5:9", "--code", "code-t15b2",
            "--expect-fingerprint", "0" * 64,
        ])
    assert result.exit_code != 0, result.output
    low = (result.output or "").lower()
    assert "use https" in low, f"no transport refusal in output: {result.output}"
    assert "code-t15b2" not in (result.output or ""), "enrollment code leaked to output"
    assert not tracker.requested_urls, (
        f"enroll opened a socket on http non-loopback: {tracker.requested_urls}"
    )


def test_t15b2_twin_enroll_loopback_http_still_attempted(tmp_path, monkeypatch):
    """Positive twin: loopback http passes the transport check and the
    enroll request is attempted (it fails harmlessly against the mock)."""
    monkeypatch.chdir(tmp_path)
    tracker = _MockTracker({})
    from sandbox.cli.main import cli
    with patch("urllib.request.urlopen", side_effect=tracker.urlopen):
        result = CliRunner().invoke(cli, [
            "enroll", "--server", "http://127.0.0.1:9", "--code", "code-t15b2b",
            "--expect-fingerprint", "0" * 64,
        ])
    low = (result.output or "").lower()
    assert "loopback" not in low and "use https" not in low, (
        f"loopback http wrongly refused: {result.output}"
    )
    assert tracker.requested_urls, "enroll made no network call on loopback http"


# ---------------------------------------------------------------------------
# Dead helpers
# ---------------------------------------------------------------------------

def test_t15b2_dead_raw_helpers_removed():
    """``_signer_http_get`` / ``_signer_http_post`` (raw urlopen with the
    token in a redirectable header) no longer exist in sync_cmds."""
    import ast
    import inspect
    from sandbox.cli import sync_cmds

    tree = ast.parse(inspect.getsource(sync_cmds))
    defs = {n.name for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)}
    present = sorted(defs & {"_signer_http_get", "_signer_http_post"})
    if present:
        raise M2T15bTransportPending(f"dead helpers still defined: {present}")
    assert not hasattr(sync_cmds, "_signer_http_get")
    assert not hasattr(sync_cmds, "_signer_http_post")


# ---------------------------------------------------------------------------
# Connector daemon transport: process.py::_default_connect
# ---------------------------------------------------------------------------

def test_t15b2_process_connect_http_non_loopback_refused_before_socket():
    """The daemon transport refuses http:// to a non-loopback host before
    urlopen is called, with the token absent from the exception text."""
    from sandbox.connector.sync.process import _default_connect

    tracker = _MockTracker({})
    raised: Exception | None = None
    with patch("urllib.request.urlopen", side_effect=tracker.urlopen):
        try:
            _default_connect("GET", "http://evil.test:9000/api/v1/sync/decisions",
                             token=_TOKEN)
        except Exception as exc:  # noqa: BLE001
            raised = exc
    if tracker.requested_urls or raised is None:
        raise M2T15bTransportPending(
            f"_default_connect reached urlopen on http non-loopback: "
            f"urls={tracker.requested_urls} raised={raised!r}"
        )
    assert _TOKEN not in str(raised), "token text in exception"


def test_t15b2_process_connect_302_never_forwards_token():
    """With urllib's plain default opener, a real 302 from the server must
    not deliver the Bearer token to the redirect target, and the call must
    not report a 200 from the target as success."""
    from sandbox.connector.sync.process import _default_connect

    spy_cls = _make_spy_handler()
    with _local_server(spy_cls) as spy_url:
        h = _make_signer_server_handler({}, redirect_on="/decisions",
                                        redirect_code=302, target_url=spy_url)
        with _local_server(h) as srv_url, _plain_default_opener():
            status = None
            raised = None
            try:
                status, _body, _hdrs = _default_connect(
                    "GET", srv_url + "/api/v1/sync/decisions", token=_TOKEN,
                )
            except Exception as exc:  # noqa: BLE001
                raised = exc
    if spy_cls.auth_headers or status == 200:
        raise M2T15bTransportPending(
            f"daemon forwarded Bearer on redirect: auth_headers="
            f"{len(spy_cls.auth_headers)} status={status}"
        )
    assert spy_cls.auth_headers == []
    if raised is not None:
        assert _TOKEN not in str(raised), "token text in exception"
    else:
        assert status is not None and 300 <= status < 400


def test_t15b2_twin_process_connect_loopback_ok():
    """Positive twin (holds today): the daemon transport talks to a
    loopback http server and returns its status and JSON body."""
    from sandbox.connector.sync.process import _default_connect

    spy_cls = _make_spy_handler()
    with _local_server(spy_cls) as spy_url:
        status, body, _hdrs = _default_connect(
            "GET", spy_url + "/api/v1/sync/decisions", token=_TOKEN,
        )
    assert status == 200
    assert body == {"spy": True}
    assert spy_cls.auth_headers == [f"Bearer {_TOKEN}"]
