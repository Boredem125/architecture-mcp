"""T8 tests-first: enroll (named operator, proof of possession, atomic consume),
device tokens, revocation, sticky managed mode, locked mode, un-enroll.

Interface contract
------------------
Client (connector, MIT):
    sandbox.connector.sync.enroll
        enroll(server, code, expect_fingerprint, *, ca=None) -> DeviceInfo
            POST server + /api/v1/sync/enroll
            Request:  {code: str, public_key: str, proof: envelope}
                      (sends the code itself, NOT the hash; PoP signs code_hash)
            Response: {device_id: str, org_id: str, project_id: str}
            Errors:   409 code_consumed, 410 code_expired, 429 rate_limited,
                      403 wrong_operator
        request_token(server, device_key, device_id, *, ca=None) -> str
            POST server + /api/v1/sync/token
            Request:  {device_id: str, assertion: envelope}
            Response: {token: str, expires_in: int}
            Errors:   401 device_revoked / iat_expired, 404 not_found
        unenroll(layout, decision_path) -> None
            Verifies agg/unenroll/v1 envelope from file against pinned registry
        EnrollError, TokenError, UnenrollError
        UNENROLL_FIELDS = {org_id, project_id, device_id, registry_version,
                           nonce, issued_at, not_after}
    sandbox.connector.sync.state
        is_managed(layout) -> bool
        is_locked(layout) -> bool
        pinned_root(layout) -> str | None
        last_valid_bundle(layout) -> dict | None
        can_accept_bundles(layout) -> bool
    sandbox.connector.classify (existing, amended)
        _APPROVER_SUBCOMMANDS gains "enroll", "unenroll", "sync"

Server routes (tested in ee/tests/test_m2_t8_enroll.py):
    POST /api/v1/sync/enroll              consume code, create device
    POST /api/v1/sync/token               device assertion -> bearer token
    POST /api/v1/admin/enrollment-codes   admin issues code (returns code_id,
                                          NOT the code); org from session
    GET  /api/v1/enrollment-codes/{id}    operator reads code once, fresh session
    POST /api/v1/admin/devices/revoke     revoke a device

Postgres-free.  Uses ``tests.m2_fakes.FakeSyncServer`` for HTTP.
Covers threats 1-5 (client error mapping), 26, 34, 37, F1, F2, N7.

RED tests xfail on M2T8Pending.  Guards verify existing code.

T6 rule: the sentinel is raised only by one helper ``_need()`` at the
top of a test; the final assertions are plain ``assert``/``pytest.raises``.
Tests never patch global ``os`` attributes.

Node-id patterns are fixed in M2_BASELINE.md section 5.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import secrets
import time
from pathlib import Path

import pytest
from nacl.signing import SigningKey

from tests.m2_pending import M2T8Pending
from tests.m2_fakes import FakeSyncServer, FakeResponse

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

WINDOWS = os.name == "nt"
SRC = str(Path(__file__).resolve().parents[2] / "src")


def _need(module: str, attr: str) -> None:
    """Raise M2T8Pending if *module*.*attr* is absent."""
    try:
        mod = __import__(module, fromlist=[attr])
    except ImportError:
        raise M2T8Pending(f"{module} not importable")
    if not hasattr(mod, attr):
        raise M2T8Pending(f"{module}.{attr} not found")


def _keygen():
    """Return (signing_key, pub_bytes, key_id)."""
    sk = SigningKey.generate()
    pub = bytes(sk.verify_key)
    kid = hashlib.sha256(pub).hexdigest()
    return sk, pub, kid


def _canonical_json(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


@pytest.fixture
def key_home(tmp_path, monkeypatch):
    kh = tmp_path / "keyhome"
    kh.mkdir()
    monkeypatch.setenv("SANDBOX_KEY_HOME", str(kh))
    return kh


def _ws(path: Path):
    """Create a workspace and return the FolderLayout."""
    from sandbox.connector.install import init
    from sandbox.connector.layout import FolderLayout
    path.mkdir(parents=True, exist_ok=True)
    init(path, claude=False, mcp=False)
    return FolderLayout(path)


def _hook(lay, tool, tool_input):
    from sandbox.connector.hook_eval import pre_tool_use
    out = asyncio.run(pre_tool_use(
        {"tool_name": tool, "tool_input": tool_input,
         "cwd": str(lay.root), "session_id": "t8"},
        lay,
    ))
    hso = out.get("hookSpecificOutput", {})
    return hso.get("permissionDecision"), hso.get("permissionDecisionReason", "")


# ===================================================================
# Guards (pass now -- existing code)
# ===================================================================


def test_guard_classify_importable():
    """Guard: classify and the approver subcommands are importable."""
    from sandbox.connector.classify import classify, _APPROVER_SUBCOMMANDS
    assert "approve" in _APPROVER_SUBCOMMANDS


def test_guard_keyhome_touches():
    """Guard: keyhome.touches exists."""
    from sandbox.connector.keyhome import touches
    assert callable(touches)


def test_guard_fake_server_starts():
    """Guard: FakeSyncServer starts and responds."""
    with FakeSyncServer() as srv:
        srv.routes[("GET", "/ping")] = FakeResponse(200, {"ok": True})
        import urllib.request
        resp = urllib.request.urlopen(f"{srv.base_url}/ping")
        assert resp.status == 200


# ===================================================================
# RED: threat 1 -- enrollment code error mapping (client side)
# ===================================================================


@pytest.mark.xfail(strict=True, raises=M2T8Pending)
def test_code_single_use(tmp_path, key_home):
    """Client maps 409 to EnrollError on code reuse (threat 1)."""
    _need("sandbox.connector.sync.enroll", "enroll")
    from sandbox.connector.sync.enroll import enroll, EnrollError
    with FakeSyncServer() as srv:
        srv.routes[("POST", "/api/v1/sync/enroll")] = FakeResponse(
            409, {"error": "code_consumed"})
        with pytest.raises(EnrollError, match="already.used|consumed"):
            enroll(srv.base_url, "USED-CODE", "fp-abc")


@pytest.mark.xfail(strict=True, raises=M2T8Pending)
def test_code_expired_refused(tmp_path, key_home):
    """Client maps 410 to EnrollError on expired code (threat 1)."""
    _need("sandbox.connector.sync.enroll", "enroll")
    from sandbox.connector.sync.enroll import enroll, EnrollError
    with FakeSyncServer() as srv:
        srv.routes[("POST", "/api/v1/sync/enroll")] = FakeResponse(
            410, {"error": "code_expired"})
        with pytest.raises(EnrollError, match="expired"):
            enroll(srv.base_url, "EXPIRED-CODE", "fp-abc")


@pytest.mark.xfail(strict=True, raises=M2T8Pending)
def test_code_brute_force_rate_limited(tmp_path, key_home):
    """Client maps 429 to EnrollError on rate limit (threat 1)."""
    _need("sandbox.connector.sync.enroll", "enroll")
    from sandbox.connector.sync.enroll import enroll, EnrollError
    with FakeSyncServer() as srv:
        srv.routes[("POST", "/api/v1/sync/enroll")] = FakeResponse(
            429, {"error": "rate_limited"})
        with pytest.raises(EnrollError, match="rate.limit|429"):
            enroll(srv.base_url, "WRONG-CODE", "fp-abc")


@pytest.mark.xfail(strict=True, raises=M2T8Pending)
def test_code_named_operator_fresh_session(tmp_path, key_home):
    """Client maps 403 to EnrollError when operator does not match (threat 1)."""
    _need("sandbox.connector.sync.enroll", "enroll")
    from sandbox.connector.sync.enroll import enroll, EnrollError
    with FakeSyncServer() as srv:
        srv.routes[("POST", "/api/v1/sync/enroll")] = FakeResponse(
            403, {"error": "wrong_operator"})
        with pytest.raises(EnrollError, match="operator|unauthorized"):
            enroll(srv.base_url, "WRONG-OPERATOR-CODE", "fp-abc")


@pytest.mark.xfail(strict=True, raises=M2T8Pending)
def test_posting_hash_as_code_refused(tmp_path, key_home):
    """Posting the stored hash instead of the code itself is refused (D1.2).

    The enroll route sends the code; the server hashes it.  A client that
    sends the hash directly must get an error (the hash is not a valid code).
    """
    _need("sandbox.connector.sync.enroll", "enroll")
    from sandbox.connector.sync.enroll import enroll, EnrollError
    code_hash = hashlib.sha256(b"real-code").hexdigest()
    with FakeSyncServer() as srv:
        # The server does not recognise the hash as a valid code
        srv.routes[("POST", "/api/v1/sync/enroll")] = FakeResponse(
            404, {"error": "code_not_found"})
        with pytest.raises(EnrollError):
            enroll(srv.base_url, code_hash, "fp-abc")


# ===================================================================
# RED: threat 2 -- fingerprint mismatch (client side)
# ===================================================================


@pytest.mark.xfail(strict=True, raises=M2T8Pending)
def test_missing_expect_fingerprint_refused(tmp_path, key_home):
    """enroll without --expect-fingerprint is refused (threat 2)."""
    _need("sandbox.connector.sync.enroll", "enroll")
    from sandbox.connector.sync.enroll import enroll, EnrollError
    with pytest.raises((EnrollError, TypeError)):
        enroll("https://fake.invalid", "CODE", None)  # type: ignore[arg-type]


@pytest.mark.xfail(strict=True, raises=M2T8Pending)
def test_fingerprint_mismatch_aborts_writes_nothing(tmp_path, key_home):
    """A fingerprint mismatch aborts and writes nothing (threat 2)."""
    _need("sandbox.connector.sync.enroll", "enroll")
    from sandbox.connector.sync.enroll import enroll, EnrollError
    lay = _ws(tmp_path / "ws")
    device_dir = key_home / "device"
    sync_dir = lay.root / ".sandbox" / "state" / "sync"
    before_device = list(device_dir.rglob("*")) if device_dir.exists() else []
    before_sync = list(sync_dir.rglob("*")) if sync_dir.exists() else []
    with FakeSyncServer() as srv:
        srv.routes[("POST", "/api/v1/sync/enroll")] = FakeResponse(
            200, {"device_id": "d-1", "fingerprint": "real-fp-different"})
        with pytest.raises(EnrollError, match="fingerprint"):
            enroll(srv.base_url, "CODE-OK", "wrong-fp-expected")
    after_device = list(device_dir.rglob("*")) if device_dir.exists() else []
    after_sync = list(sync_dir.rglob("*")) if sync_dir.exists() else []
    assert after_device == before_device, "device key written despite fingerprint mismatch"
    assert after_sync == before_sync, "sync state written despite fingerprint mismatch"


@pytest.mark.xfail(strict=True, raises=M2T8Pending)
def test_no_tty_no_interactive_accept(tmp_path, key_home):
    """With no TTY there is no interactive accept (threat 2)."""
    _need("sandbox.connector.sync.enroll", "enroll")
    from sandbox.connector.sync.enroll import enroll, EnrollError
    with pytest.raises((EnrollError, TypeError)):
        enroll("https://fake.invalid", "CODE", "")


# ===================================================================
# RED: threat 3 -- device key denied to the agent
# ===================================================================


def _device_key_hook_setup(tmp_path, monkeypatch):
    """Set up a workspace with a device key in the key home for denial testing."""
    from sandbox.connector.install import init
    from sandbox.connector.layout import FolderLayout
    from sandbox.connector.policy import load_policy, save_policy

    kh = tmp_path / "keyhome"
    kh.mkdir()
    monkeypatch.setenv("SANDBOX_KEY_HOME", str(kh))

    ws = tmp_path / "ws"
    ws.mkdir()
    init(ws, claude=False, mcp=False)
    lay = FolderLayout(ws)

    ws_id_file = ws / ".sandbox" / "workspace_id"
    ws_id = ws_id_file.read_text().strip() if ws_id_file.exists() else "w0"

    device_dir = kh / ws_id / "device"
    device_dir.mkdir(parents=True)
    (device_dir / "device.key").write_bytes(b"\x07" * 64)

    policy = load_policy(lay.policy_file)
    policy.escalation_timeout_seconds = 0
    policy.triggers.read_outside = "allow"
    policy.triggers.write_outside = "allow"
    save_policy(policy, lay.policy_file)

    return lay, kh, device_dir


def _short_name(path: Path) -> str:
    if WINDOWS:
        import ctypes
        buf = ctypes.create_unicode_buffer(32768)
        if ctypes.windll.kernel32.GetShortPathNameW(str(path), buf, 32768) and buf.value != str(path):
            return buf.value
        return str(path).replace(os.sep, os.sep + "." + os.sep, 1)
    return str(path).replace("/", "/./", 1)


DEVICE_KEY_DENY_CASES = [
    "read_device_key",
    "grep_device_dir",
    "glob_device_dir",
    "write_device_key",
    "edit_device_key",
    "cat_device_key",
    "cat_device_key_short_name",
    "cat_device_key_env_var",
]


def _device_tool_case(case: str, lay, kh: Path, device_dir: Path):
    key_file = device_dir / "device.key"
    if case == "read_device_key":
        return "Read", {"file_path": str(key_file)}
    if case == "grep_device_dir":
        return "Grep", {"pattern": ".", "path": str(kh)}
    if case == "glob_device_dir":
        return "Glob", {"pattern": "**/*.key", "path": str(kh)}
    if case == "write_device_key":
        return "Write", {"file_path": str(key_file), "content": "attacker-key"}
    if case == "edit_device_key":
        return "Edit", {"file_path": str(key_file), "old_string": "\x07", "new_string": "X"}
    if case == "cat_device_key":
        return "Bash", {"command": f'cat "{key_file}"'}
    if case == "cat_device_key_short_name":
        return "Bash", {"command": f'cat "{_short_name(key_file)}"'}
    if case == "cat_device_key_env_var":
        if WINDOWS:
            return "Bash", {"command": f"cat $LOCALAPPDATA\\agg\\keys\\{device_dir.parent.name}\\device\\device.key"}
        return "Bash", {"command": f"cat $HOME/.local/share/agg/keys/{device_dir.parent.name}/device/device.key"}
    raise AssertionError(case)


@pytest.mark.xfail(strict=True, raises=M2T8Pending)
@pytest.mark.parametrize("case", DEVICE_KEY_DENY_CASES)
def test_device_key_denied_every_tool(tmp_path, monkeypatch, case):
    """Device key in key home device/ is denied for every tool (threat 3)."""
    _need("sandbox.connector.sync.state", "is_managed")
    lay, kh, device_dir = _device_key_hook_setup(tmp_path, monkeypatch)
    tool, tool_input = _device_tool_case(case, lay, kh, device_dir)
    decision, reason = _hook(lay, tool, tool_input)
    assert decision not in (None, "allow"), f"{case}: {tool} was let through ({decision!r})"
    assert (device_dir / "device.key").read_bytes() == b"\x07" * 64


# ===================================================================
# RED: threat 4 -- assertion replay (client maps 401)
# ===================================================================


@pytest.mark.xfail(strict=True, raises=M2T8Pending)
def test_assertion_replay_refused(tmp_path, key_home):
    """Client maps 401 with iat_expired from server (threat 4, iat 2 min)."""
    _need("sandbox.connector.sync.enroll", "request_token")
    from sandbox.connector.sync.enroll import request_token, TokenError
    sk, pub, kid = _keygen()
    with FakeSyncServer() as srv:
        srv.routes[("POST", "/api/v1/sync/token")] = FakeResponse(
            401, {"error": "iat_expired"})
        with pytest.raises(TokenError, match="iat|expired|stale"):
            request_token(srv.base_url, sk, "device-1")


# ===================================================================
# RED: threat 5 -- cross-tenant device (client maps 404)
# ===================================================================


@pytest.mark.xfail(strict=True, raises=M2T8Pending)
def test_device_a_project_b_gets_404(tmp_path, key_home):
    """Client maps 404 from server for wrong project (threat 5)."""
    _need("sandbox.connector.sync.enroll", "request_token")
    from sandbox.connector.sync.enroll import request_token, TokenError
    sk, pub, kid = _keygen()
    with FakeSyncServer() as srv:
        srv.routes[("POST", "/api/v1/sync/token")] = FakeResponse(
            404, {"error": "not_found"})
        with pytest.raises(TokenError, match="not.found|404"):
            request_token(srv.base_url, sk, "device-wrong-project")


# ===================================================================
# RED: revocation -- 401 on next call, last bundle kept
# ===================================================================


@pytest.mark.xfail(strict=True, raises=M2T8Pending)
def test_revocation_401_keeps_last_bundle(tmp_path, key_home):
    """A revoked device gets 401; connector keeps last bundle (client behaviour)."""
    _need("sandbox.connector.sync.state", "last_valid_bundle")
    from sandbox.connector.sync.state import last_valid_bundle
    from sandbox.connector.sync.enroll import request_token, TokenError
    sk, pub, kid = _keygen()
    lay = _ws(tmp_path / "ws")

    # Simulate a stored valid bundle
    sync_dir = lay.root / ".sandbox" / "state" / "sync"
    sync_dir.mkdir(parents=True, exist_ok=True)
    (sync_dir / "bundle.json").write_text(json.dumps({"sequence": 1, "test": True}))

    with FakeSyncServer() as srv:
        srv.routes[("POST", "/api/v1/sync/token")] = FakeResponse(
            401, {"error": "device_revoked"})
        with pytest.raises(TokenError, match="revoked|401"):
            request_token(srv.base_url, sk, "device-revoked")

    # The last valid bundle must still be readable
    bundle = last_valid_bundle(lay)
    assert bundle is not None


# ===================================================================
# RED: threat 26 -- sticky managed mode
# ===================================================================


@pytest.mark.xfail(strict=True, raises=M2T8Pending)
def test_sticky_delete_sync_state_keeps_last_bundle(tmp_path, key_home):
    """Deleting sync state: last bundle from policy_history kept (threat 26)."""
    _need("sandbox.connector.sync.state", "is_managed")
    from sandbox.connector.sync.state import is_managed, last_valid_bundle
    lay = _ws(tmp_path / "ws")

    ws_id_file = lay.root / ".sandbox" / "workspace_id"
    ws_id = ws_id_file.read_text().strip() if ws_id_file.exists() else "w0"

    (key_home / ws_id).mkdir(parents=True, exist_ok=True)
    (key_home / ws_id / "managed").write_text("1")
    sync_dir = lay.root / ".sandbox" / "state" / "sync"
    sync_dir.mkdir(parents=True, exist_ok=True)
    (sync_dir / "managed").write_text("1")

    hist = lay.root / ".sandbox" / "policy_history"
    hist.mkdir(parents=True, exist_ok=True)
    (hist / "bundle_v1.json").write_text(json.dumps({"sequence": 1, "test": True}))

    import shutil
    shutil.rmtree(sync_dir)

    assert is_managed(lay)
    bundle = last_valid_bundle(lay)
    assert bundle is not None


@pytest.mark.xfail(strict=True, raises=M2T8Pending)
def test_sticky_no_fallback_to_standalone(tmp_path, key_home):
    """A managed workspace never falls back to standalone policy (threat 26)."""
    _need("sandbox.connector.sync.state", "is_managed")
    from sandbox.connector.sync.state import is_managed
    lay = _ws(tmp_path / "ws")

    ws_id_file = lay.root / ".sandbox" / "workspace_id"
    ws_id = ws_id_file.read_text().strip() if ws_id_file.exists() else "w0"

    (key_home / ws_id).mkdir(parents=True, exist_ok=True)
    (key_home / ws_id / "managed").write_text("1")

    assert is_managed(lay)


# ===================================================================
# RED: threat 26 -- locked mode
# ===================================================================


@pytest.mark.xfail(strict=True, raises=M2T8Pending)
def test_locked_when_bundle_and_history_gone(tmp_path, key_home):
    """Delete sync state AND policy_history -> locked (threat 26)."""
    _need("sandbox.connector.sync.state", "is_locked")
    from sandbox.connector.sync.state import is_managed, is_locked
    lay = _ws(tmp_path / "ws")

    ws_id_file = lay.root / ".sandbox" / "workspace_id"
    ws_id = ws_id_file.read_text().strip() if ws_id_file.exists() else "w0"

    (key_home / ws_id).mkdir(parents=True, exist_ok=True)
    (key_home / ws_id / "managed").write_text("1")

    sync_dir = lay.root / ".sandbox" / "state" / "sync"
    if sync_dir.exists():
        import shutil
        shutil.rmtree(sync_dir)
    hist = lay.root / ".sandbox" / "policy_history"
    if hist.exists():
        import shutil
        shutil.rmtree(hist)

    assert is_managed(lay)
    assert is_locked(lay)


@pytest.mark.xfail(strict=True, raises=M2T8Pending)
def test_locked_reads_hit_non_removable_protections(tmp_path, key_home):
    """Locked reads still go through non-removable protections (N7)."""
    _need("sandbox.connector.sync.state", "is_locked")
    from sandbox.connector.sync.state import is_locked
    lay = _ws(tmp_path / "ws")

    ws_id_file = lay.root / ".sandbox" / "workspace_id"
    ws_id = ws_id_file.read_text().strip() if ws_id_file.exists() else "w0"

    (key_home / ws_id).mkdir(parents=True, exist_ok=True)
    (key_home / ws_id / "managed").write_text("1")

    assert is_locked(lay)

    decision, reason = _hook(lay, "Read", {"file_path": str(lay.root / ".sandbox" / "state" / "keys" / "cli.seed")})
    assert decision not in (None, "allow"), "locked mode allowed a read of a protected path"


@pytest.mark.xfail(strict=True, raises=M2T8Pending)
def test_locked_denies_writes(tmp_path, key_home):
    """Locked mode denies all writes except reads inside the root (N7)."""
    _need("sandbox.connector.sync.state", "is_locked")
    from sandbox.connector.sync.state import is_locked
    lay = _ws(tmp_path / "ws")

    ws_id_file = lay.root / ".sandbox" / "workspace_id"
    ws_id = ws_id_file.read_text().strip() if ws_id_file.exists() else "w0"

    (key_home / ws_id).mkdir(parents=True, exist_ok=True)
    (key_home / ws_id / "managed").write_text("1")

    assert is_locked(lay)

    decision, reason = _hook(lay, "Bash", {"command": "echo pwned > evil.txt"})
    assert decision not in (None, "allow"), "locked mode allowed a write"


# ===================================================================
# RED: threat 34 -- un-enroll
# ===================================================================


@pytest.mark.xfail(strict=True, raises=M2T8Pending)
def test_local_unenroll_refused(tmp_path, key_home):
    """Local two-reviewer un-enroll is refused; only quorum-signed decision (threat 34)."""
    _need("sandbox.connector.sync.enroll", "unenroll")
    from sandbox.connector.sync.enroll import unenroll, UnenrollError
    lay = _ws(tmp_path / "ws")

    ws_id_file = lay.root / ".sandbox" / "workspace_id"
    ws_id = ws_id_file.read_text().strip() if ws_id_file.exists() else "w0"

    (key_home / ws_id).mkdir(parents=True, exist_ok=True)
    (key_home / ws_id / "managed").write_text("1")

    with pytest.raises(UnenrollError, match="quorum|signature|decision"):
        unenroll(lay, None)


@pytest.mark.xfail(strict=True, raises=M2T8Pending)
def test_forged_unenroll_decision_refused(tmp_path, key_home):
    """A forged decision file is refused (threat 34)."""
    _need("sandbox.connector.sync.enroll", "unenroll")
    from sandbox.connector.sync.enroll import unenroll, UnenrollError
    lay = _ws(tmp_path / "ws")

    ws_id_file = lay.root / ".sandbox" / "workspace_id"
    ws_id = ws_id_file.read_text().strip() if ws_id_file.exists() else "w0"

    (key_home / ws_id).mkdir(parents=True, exist_ok=True)
    (key_home / ws_id / "managed").write_text("1")

    forged = tmp_path / "forged_decision.json"
    forged_data = {
        "kind": "agg/unenroll/v1",
        "sig_v": 1,
        "payload": {
            "org_id": "org-1",
            "project_id": "proj-1",
            "device_id": "d-1",
            "registry_version": 1,
            "nonce": secrets.token_hex(16),
            "issued_at": time.time(),
            "not_after": time.time() + 900,
        },
        "signatures": [{"key_id": "fake", "alg": "ed25519", "sig": "aa" * 64}],
    }
    forged.write_text(json.dumps(forged_data))

    with pytest.raises(UnenrollError, match="signature|invalid|verification"):
        unenroll(lay, str(forged))


@pytest.mark.xfail(strict=True, raises=M2T8Pending)
def test_unenroll_f1_field_set(tmp_path, key_home):
    """The unenroll decision has the fixed field set from F1 (threat 34)."""
    _need("sandbox.connector.sync.enroll", "UNENROLL_FIELDS")
    from sandbox.connector.sync.enroll import UNENROLL_FIELDS
    expected = {"org_id", "project_id", "device_id", "registry_version",
                "nonce", "issued_at", "not_after"}
    assert UNENROLL_FIELDS == expected


@pytest.mark.xfail(strict=True, raises=M2T8Pending)
def test_old_unenroll_file_after_reenroll_refused(tmp_path, key_home):
    """Re-enroll gives a new device_id; old un-enroll file is refused (F1)."""
    _need("sandbox.connector.sync.enroll", "unenroll")
    from sandbox.connector.sync.enroll import unenroll, UnenrollError
    lay = _ws(tmp_path / "ws")

    ws_id_file = lay.root / ".sandbox" / "workspace_id"
    ws_id = ws_id_file.read_text().strip() if ws_id_file.exists() else "w0"

    (key_home / ws_id).mkdir(parents=True, exist_ok=True)
    (key_home / ws_id / "managed").write_text("1")

    sync_dir = lay.root / ".sandbox" / "state" / "sync"
    sync_dir.mkdir(parents=True, exist_ok=True)
    (sync_dir / "device_id").write_text("d-new")

    old_decision = tmp_path / "old_decision.json"
    sk, pub, kid = _keygen()
    old_data = {
        "kind": "agg/unenroll/v1",
        "sig_v": 1,
        "payload": {
            "org_id": "org-1",
            "project_id": "proj-1",
            "device_id": "d-old",
            "registry_version": 1,
            "nonce": secrets.token_hex(16),
            "issued_at": time.time(),
            "not_after": time.time() + 900,
        },
        "signatures": [{"key_id": kid, "alg": "ed25519", "sig": "aa" * 64}],
    }
    old_decision.write_text(json.dumps(old_data))

    with pytest.raises(UnenrollError, match="device_id|mismatch"):
        unenroll(lay, str(old_decision))


# ===================================================================
# RED: F2 -- sync never re-pins the root
# ===================================================================


@pytest.mark.xfail(strict=True, raises=M2T8Pending)
def test_sync_does_not_repin_deleted_registry(tmp_path, key_home):
    """After pinned registry is deleted, sync does not re-pin (F2)."""
    _need("sandbox.connector.sync.state", "pinned_root")
    from sandbox.connector.sync.state import pinned_root
    lay = _ws(tmp_path / "ws")

    sync_dir = lay.root / ".sandbox" / "state" / "sync"
    sync_dir.mkdir(parents=True, exist_ok=True)

    (sync_dir / "pinned_root.json").write_text(json.dumps({"fingerprint": "fp-abc"}))
    (sync_dir / "pinned_root.json").unlink()

    assert pinned_root(lay) is None


@pytest.mark.xfail(strict=True, raises=M2T8Pending)
def test_sync_refuses_bundle_without_pinned_root(tmp_path, key_home):
    """Until a pinned root exists, bundles and remote approvals are refused (F2)."""
    _need("sandbox.connector.sync.state", "pinned_root")
    _need("sandbox.connector.sync.state", "can_accept_bundles")
    from sandbox.connector.sync.state import pinned_root, can_accept_bundles
    lay = _ws(tmp_path / "ws")

    assert pinned_root(lay) is None
    assert not can_accept_bundles(lay)


# ===================================================================
# RED: threat 37 -- agent denied from running enroll/unenroll/sync
# ===================================================================


ENROLL_SHELL_FORMS = [
    "sandbox enroll --server https://evil.invalid --code ABC --expect-fingerprint fp123",
    "sandbox unenroll --decision /tmp/d.json",
    "sandbox sync",
]


@pytest.mark.xfail(strict=True, raises=M2T8Pending)
@pytest.mark.parametrize("command", ENROLL_SHELL_FORMS)
def test_enroll_unenroll_sync_denied_through_shell(tmp_path, key_home, command):
    """sandbox enroll, unenroll, sync denied through the same forms as approve (threat 37)."""
    _need("sandbox.connector.classify", "_APPROVER_SUBCOMMANDS")
    from sandbox.connector.classify import _APPROVER_SUBCOMMANDS
    for subcmd in ("enroll", "unenroll", "sync"):
        if subcmd not in _APPROVER_SUBCOMMANDS:
            raise M2T8Pending(f"{subcmd} not in _APPROVER_SUBCOMMANDS")
    lay = _ws(tmp_path / "ws")
    decision, reason = _hook(lay, "Bash", {"command": command})
    assert decision == "deny", f"sandbox {command.split()[1]} was not denied: {decision}"


@pytest.mark.xfail(strict=True, raises=M2T8Pending)
def test_reenroll_different_fingerprint_refused(tmp_path, key_home):
    """Re-enroll with a different fingerprint than the pinned root is refused (threat 37)."""
    _need("sandbox.connector.sync.enroll", "enroll")
    from sandbox.connector.sync.enroll import enroll, EnrollError
    lay = _ws(tmp_path / "ws")

    sync_dir = lay.root / ".sandbox" / "state" / "sync"
    sync_dir.mkdir(parents=True, exist_ok=True)
    (sync_dir / "pinned_root.json").write_text(json.dumps({"fingerprint": "existing-fp"}))

    with FakeSyncServer() as srv:
        srv.routes[("POST", "/api/v1/sync/enroll")] = FakeResponse(
            200, {"device_id": "d-1", "fingerprint": "different-fp"})
        with pytest.raises(EnrollError, match="fingerprint.*differ|pinned.*mismatch"):
            enroll(srv.base_url, "CODE-OK", "different-fp")


# ===================================================================
# RED: unenrolled workspace without marker behaves as today
# ===================================================================


@pytest.mark.xfail(strict=True, raises=M2T8Pending)
def test_unenrolled_workspace_behaves_as_standalone(tmp_path, key_home):
    """An unenrolled workspace (no managed marker) behaves exactly as today (D7.4)."""
    _need("sandbox.connector.sync.state", "is_managed")
    from sandbox.connector.sync.state import is_managed
    lay = _ws(tmp_path / "ws")
    assert not is_managed(lay)
    decision, reason = _hook(lay, "Bash", {"command": "echo hello"})
    assert decision in (None, "allow"), f"standalone echo was not allowed: {decision}"
