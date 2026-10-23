"""T10 tests-first: sandbox sync process, backoff, state denies, socket guard.

Interface contract
------------------
Client (connector, MIT):
    sandbox.connector.sync.process
        SyncProcess(layout, server_url, device_key, device_id, *,
                    clock=None, connect=None)
            Constructor seams (documented here as the contract):

              clock : callable() -> float
                  Returns the current monotonic time in seconds.
                  Default: ``time.monotonic``.
                  Injected in tests to control time without patching globals.

              connect : callable(method, url, body=None, headers=None, token=None)
                            -> (status, body_dict, headers_dict)
                  Makes an HTTP request and returns the response triple.
                  Default: the real ``urllib.request``-based implementation.
                  Injected in tests to simulate offline / error / delay
                  without opening a real socket.

            Neither seam changes security behaviour: they select the time
            source and transport, not the policy, keys, or decision logic.
            The product default is the real clock and the real HTTP client.

        run_once(sync: SyncProcess) -> None
            Execute one poll cycle: token refresh, fetch decisions,
            fetch registry and bundles (on the 60 s cadence), upload
            pending escalations and audit records.

        next_backoff(sync: SyncProcess) -> float
            Return the delay (in seconds) until the next poll.  On success
            the delay is the base interval (10 s for decisions).  On failure
            the delay doubles each time with jitter, capped at 300 s (5 min).

        SyncError

Postgres-free.  Uses ``tests.m2_fakes.FakeSyncServer`` for HTTP where needed.

Covers threats 12 (offline/no network in the hook/no timeout approve) and
20 (agent edits sync state: Write/Edit/shell denied).

RED tests xfail on M2T10Pending.  Guards verify existing code.

T6 rule: the sentinel is raised only by one helper ``_need()`` at the
top of a test; the final assertions are plain ``assert``/``pytest.raises``.
Tests never patch global ``os`` attributes.

State-deny tests go through the real hook path (hook_eval) for Write,
Edit, Bash shell forms, like the key-home tests.
"""
from __future__ import annotations

import asyncio
import json
import os
import time
from pathlib import Path

import pytest

from tests.m2_pending import M2T10Pending
from tests.m2_fakes import FakeSyncServer, FakeResponse

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

SRC = str(Path(__file__).resolve().parents[2] / "src")


def _need(module: str, attr: str) -> None:
    """Raise M2T10Pending if *module*.*attr* is absent."""
    try:
        mod = __import__(module, fromlist=[attr])
    except ImportError:
        raise M2T10Pending(f"{module} not importable")
    if not hasattr(mod, attr):
        raise M2T10Pending(f"{module}.{attr} not found")


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
         "cwd": str(lay.root), "session_id": "t10"},
        lay,
    ))
    hso = out.get("hookSpecificOutput", {})
    return hso.get("permissionDecision"), hso.get("permissionDecisionReason", "")


# ===================================================================
# Guards (pass now -- existing code)
# ===================================================================


def test_guard_hook_eval_importable():
    """Guard: hook_eval and pre_tool_use are importable."""
    from sandbox.connector.hook_eval import pre_tool_use
    assert callable(pre_tool_use)


def test_guard_state_module_importable():
    """Guard: sync.state module is importable."""
    from sandbox.connector.sync.state import is_managed, is_locked
    assert callable(is_managed)
    assert callable(is_locked)


def test_guard_classify_denies_sync_subcommand():
    """Guard: classify has 'sync' in _APPROVER_SUBCOMMANDS."""
    from sandbox.connector.classify import _APPROVER_SUBCOMMANDS
    assert "sync" in _APPROVER_SUBCOMMANDS


# ===================================================================
# Guards: threat 20 -- agent edits sync state (non-removable deny)
# These pass now because .sandbox/ is a protected sequence.
# ===================================================================


def test_guard_write_sync_state_denied(tmp_path, monkeypatch):
    """Guard: Write tool to .sandbox/state/sync/ is denied (threat 20)."""
    kh = tmp_path / "keyhome"
    kh.mkdir()
    monkeypatch.setenv("SANDBOX_KEY_HOME", str(kh))
    lay = _ws(tmp_path / "ws")
    target = str(lay.root / ".sandbox" / "state" / "sync" / "cursor.json")
    decision, reason = _hook(lay, "Write", {"file_path": target, "content": "{}"})
    assert decision == "deny", f"Write to sync state was not denied: {decision}"


def test_guard_edit_sync_state_denied(tmp_path, monkeypatch):
    """Guard: Edit tool on .sandbox/state/sync/ is denied (threat 20)."""
    kh = tmp_path / "keyhome"
    kh.mkdir()
    monkeypatch.setenv("SANDBOX_KEY_HOME", str(kh))
    lay = _ws(tmp_path / "ws")
    sync_dir = lay.root / ".sandbox" / "state" / "sync"
    sync_dir.mkdir(parents=True, exist_ok=True)
    cursor = sync_dir / "cursor.json"
    cursor.write_text('{"seq": 1}')
    target = str(cursor)
    decision, reason = _hook(lay, "Edit", {
        "file_path": target, "old_string": '"seq": 1', "new_string": '"seq": 999'
    })
    assert decision == "deny", f"Edit on sync state was not denied: {decision}"


SHELL_SYNC_STATE_FORMS = [
    'echo "{}" > .sandbox/state/sync/cursor.json',
    "rm -rf .sandbox/state/sync/",
    "mv .sandbox/state/sync/cursor.json /tmp/stolen.json",
    "cat attacker_data > .sandbox/state/sync/bundle.json",
    "cp /tmp/evil.json .sandbox/state/sync/managed",
]


@pytest.mark.parametrize("command", SHELL_SYNC_STATE_FORMS)
def test_guard_shell_sync_state_denied(tmp_path, monkeypatch, command):
    """Guard: shell writes to .sandbox/state/sync/ denied (threat 20)."""
    kh = tmp_path / "keyhome"
    kh.mkdir()
    monkeypatch.setenv("SANDBOX_KEY_HOME", str(kh))
    lay = _ws(tmp_path / "ws")
    decision, reason = _hook(lay, "Bash", {"command": command})
    assert decision == "deny", (
        f"Shell write to sync state was not denied: {command!r} -> {decision}"
    )


# ===================================================================
# Guard: threat 12 -- hook does not import or call sync.process
# ===================================================================


def test_guard_hook_does_not_import_sync_process(tmp_path, monkeypatch):
    """Guard: pre_tool_use does not import sandbox.connector.sync.process (threat 12).

    The sync process runs as a separate ``sandbox sync`` command.  The hook
    evaluates purely locally and must never call the sync process module.
    If the module is not yet created, that is also fine (no import = no socket).
    """
    import sys
    kh = tmp_path / "keyhome"
    kh.mkdir()
    monkeypatch.setenv("SANDBOX_KEY_HOME", str(kh))
    lay = _ws(tmp_path / "ws")

    # Remove the module if cached so we can detect a fresh import
    sys.modules.pop("sandbox.connector.sync.process", None)
    _hook(lay, "Bash", {"command": "echo safe"})
    assert "sandbox.connector.sync.process" not in sys.modules, (
        "hook_eval imported sandbox.connector.sync.process during evaluation"
    )


# ===================================================================
# RED: backoff grows exponentially, caps at 5 min (injected clock)
# ===================================================================


def test_backoff_grows_exponentially(monkeypatch):
    """Backoff intervals grow after consecutive failures.

    Deterministic: patches the jitter to a fixed fraction (0.9) so that
    the exponential growth is observable without random overlap between
    the success interval (failures=0, ~10 s) and the first backoff
    (failures=1, ~18 s at 0.9 jitter).
    """
    _need("sandbox.connector.sync.process", "SyncProcess")
    _need("sandbox.connector.sync.process", "next_backoff")
    from sandbox.connector.sync import process as _proc
    from sandbox.connector.sync.process import SyncProcess, next_backoff

    # Fixed jitter: always return 90% of the range
    monkeypatch.setattr(_proc.random, "uniform", lambda a, b: a + 0.9 * (b - a))

    fake_time = [0.0]

    def clock():
        return fake_time[0]

    sync = SyncProcess(
        layout=None, server_url="http://localhost:0",
        device_key=b"k", device_id="d-1",
        clock=clock,
        connect=lambda *a, **kw: (503, {"error": "unavailable"}, {}),
    )
    # Simulate consecutive failures (skip 0 = success interval)
    delays = []
    for i in range(1, 7):
        sync._consecutive_failures = i
        delay = next_backoff(sync)
        delays.append(delay)
        fake_time[0] += delay

    # Growth: each delay >= the previous.  Strictly greater until the cap
    # is reached; at the cap, consecutive values are equal.
    for i in range(1, len(delays)):
        assert delays[i] >= delays[i - 1], (
            f"backoff shrank: delays[{i+1}]={delays[i]} < delays[{i}]={delays[i-1]}"
        )

    # At least one pair must show strict growth (before the cap flattens)
    grew = any(delays[i] > delays[i - 1] for i in range(1, len(delays)))
    assert grew, "no exponential growth at all"

    # The sequence must show clear exponential growth from the base
    assert delays[0] > 10, f"first backoff too small: {delays[0]}"
    assert delays[-1] > delays[0] * 2, "no exponential growth visible"
    # Cap respected
    assert all(d <= 300 for d in delays), "delay exceeded 5 min cap"


def test_backoff_caps_at_5_min():
    """Backoff never exceeds 300 seconds (5 minutes)."""
    _need("sandbox.connector.sync.process", "SyncProcess")
    _need("sandbox.connector.sync.process", "next_backoff")
    from sandbox.connector.sync.process import SyncProcess, next_backoff

    sync = SyncProcess(
        layout=None, server_url="http://localhost:0",
        device_key=b"k", device_id="d-1",
        clock=time.monotonic,
        connect=lambda *a, **kw: (503, {"error": "unavailable"}, {}),
    )
    # Simulate many consecutive failures
    for n_failures in (10, 20, 50, 100):
        sync._consecutive_failures = n_failures
        delay = next_backoff(sync)
        assert delay <= 300, (
            f"backoff at {n_failures} failures = {delay}s, exceeds 5 min cap"
        )


def test_backoff_resets_on_success():
    """Backoff resets to base interval after a successful cycle."""
    _need("sandbox.connector.sync.process", "SyncProcess")
    _need("sandbox.connector.sync.process", "next_backoff")
    from sandbox.connector.sync.process import SyncProcess, next_backoff

    sync = SyncProcess(
        layout=None, server_url="http://localhost:0",
        device_key=b"k", device_id="d-1",
        clock=time.monotonic,
        connect=lambda *a, **kw: (503, {"error": "unavailable"}, {}),
    )
    # After failures, backoff is large
    sync._consecutive_failures = 10
    delay_after_failures = next_backoff(sync)
    assert delay_after_failures > 30, "expected large backoff after 10 failures"

    # After success, backoff resets
    sync._consecutive_failures = 0
    delay_after_success = next_backoff(sync)
    assert delay_after_success <= 15, (
        f"backoff did not reset after success: {delay_after_success}s"
    )


def test_backoff_includes_jitter():
    """Backoff includes jitter so retries from multiple connectors do not thundering-herd."""
    _need("sandbox.connector.sync.process", "SyncProcess")
    _need("sandbox.connector.sync.process", "next_backoff")
    from sandbox.connector.sync.process import SyncProcess, next_backoff

    delays = set()
    for _ in range(20):
        sync = SyncProcess(
            layout=None, server_url="http://localhost:0",
            device_key=b"k", device_id="d-1",
            clock=time.monotonic,
            connect=lambda *a, **kw: (503, {}, {}),
        )
        sync._consecutive_failures = 5
        delays.add(next_backoff(sync))

    # With jitter, we expect at least a few distinct values out of 20 samples
    assert len(delays) >= 3, (
        f"no jitter detected: only {len(delays)} distinct delay(s) in 20 samples"
    )


# ===================================================================
# RED: sync process constructor and seams
# ===================================================================


def test_sync_process_constructor_accepts_seams():
    """SyncProcess accepts clock and connect seams."""
    _need("sandbox.connector.sync.process", "SyncProcess")
    from sandbox.connector.sync.process import SyncProcess

    calls = []

    def fake_clock():
        return 1000.0

    def fake_connect(method, url, body=None, headers=None, token=None):
        calls.append((method, url))
        return (200, {}, {})

    sync = SyncProcess(
        layout=None, server_url="http://localhost:0",
        device_key=b"k", device_id="d-1",
        clock=fake_clock, connect=fake_connect,
    )
    assert sync._clock() == 1000.0
    assert callable(sync._connect)


def test_sync_process_run_once_uses_injected_connect():
    """run_once routes HTTP calls through the injected connect seam."""
    _need("sandbox.connector.sync.process", "SyncProcess")
    _need("sandbox.connector.sync.process", "run_once")
    from sandbox.connector.sync.process import SyncProcess, run_once

    calls = []

    def fake_connect(method, url, body=None, headers=None, token=None):
        calls.append((method, url))
        return (200, {"token": "t", "expires_in": 600}, {})

    sync = SyncProcess(
        layout=None, server_url="http://fake.invalid",
        device_key=b"k", device_id="d-1",
        clock=time.monotonic,
        connect=fake_connect,
    )
    run_once(sync)
    assert len(calls) > 0, "run_once made no HTTP calls through the connect seam"
    for method, url in calls:
        assert "fake.invalid" in url, f"call went to {url}, not the injected server"


# ===================================================================
# RED: threat 12 -- server down, escalated call never auto-approves
# ===================================================================


def test_server_down_escalated_call_stays_pending(tmp_path, monkeypatch):
    """When the server is down, an escalated call never auto-approves (threat 12).

    The sync process must not convert a pending escalation into an approval
    just because the server is unreachable or timed out.
    """
    _need("sandbox.connector.sync.process", "SyncProcess")
    _need("sandbox.connector.sync.process", "run_once")
    from sandbox.connector.sync.process import SyncProcess, run_once, SyncError

    kh = tmp_path / "keyhome"
    kh.mkdir()
    monkeypatch.setenv("SANDBOX_KEY_HOME", str(kh))
    lay = _ws(tmp_path / "ws")

    # Create a pending escalation
    pending_dir = lay.root / ".sandbox" / "pending"
    pending_dir.mkdir(parents=True, exist_ok=True)
    escalation = {
        "request_id": "req-1",
        "tool": "Bash",
        "command": "deploy-to-prod",
        "status": "pending",
    }
    (pending_dir / "req-1.json").write_text(json.dumps(escalation))

    def failing_connect(method, url, body=None, headers=None, token=None):
        raise ConnectionError("server is down")

    sync = SyncProcess(
        layout=lay, server_url="http://dead.invalid",
        device_key=b"k", device_id="d-1",
        clock=time.monotonic,
        connect=failing_connect,
    )
    # run_once should handle the error gracefully (or raise SyncError),
    # but must NOT approve the pending request
    try:
        run_once(sync)
    except (SyncError, ConnectionError):
        pass  # expected when server is down

    # The pending escalation must still be pending, never approved
    pending_file = pending_dir / "req-1.json"
    assert pending_file.exists(), "pending escalation file was removed"
    data = json.loads(pending_file.read_text())
    assert data.get("status") != "approved", (
        "pending escalation was auto-approved while server was down"
    )


def test_no_timeout_auto_approve(tmp_path, monkeypatch):
    """No escalation is ever auto-approved on timeout (threat 12).

    Even after the escalation timeout, the connector must not approve
    the call.  It stays pending until a human decides or the session ends.
    """
    _need("sandbox.connector.sync.process", "SyncProcess")
    _need("sandbox.connector.sync.process", "run_once")
    from sandbox.connector.sync.process import SyncProcess, run_once

    kh = tmp_path / "keyhome"
    kh.mkdir()
    monkeypatch.setenv("SANDBOX_KEY_HOME", str(kh))
    lay = _ws(tmp_path / "ws")

    pending_dir = lay.root / ".sandbox" / "pending"
    pending_dir.mkdir(parents=True, exist_ok=True)
    escalation = {
        "request_id": "req-2",
        "tool": "Bash",
        "command": "refund 40000",
        "status": "pending",
        "created_at": 0,  # a long time ago
    }
    (pending_dir / "req-2.json").write_text(json.dumps(escalation))

    fake_time = [86400.0]  # 1 day after creation

    def clock():
        return fake_time[0]

    def silent_connect(method, url, body=None, headers=None, token=None):
        return (200, {"decisions": []}, {})  # no decisions from server

    sync = SyncProcess(
        layout=lay, server_url="http://fake.invalid",
        device_key=b"k", device_id="d-1",
        clock=clock,
        connect=silent_connect,
    )
    try:
        run_once(sync)
    except Exception:
        pass

    data = json.loads((pending_dir / "req-2.json").read_text())
    assert data.get("status") != "approved", (
        "escalation was auto-approved after timeout"
    )


# ===================================================================
# RED: sync process polls at correct intervals
# ===================================================================


def test_decision_poll_interval_10s():
    """Decisions are polled every 10 seconds on a healthy connection."""
    _need("sandbox.connector.sync.process", "SyncProcess")
    _need("sandbox.connector.sync.process", "next_backoff")
    from sandbox.connector.sync.process import SyncProcess, next_backoff

    sync = SyncProcess(
        layout=None, server_url="http://localhost:0",
        device_key=b"k", device_id="d-1",
        clock=time.monotonic,
        connect=lambda *a, **kw: (200, {}, {}),
    )
    sync._consecutive_failures = 0
    delay = next_backoff(sync)
    assert 5 <= delay <= 15, f"base poll interval is {delay}s, expected ~10s"


# ===================================================================
# RED: sync process does not open sockets during hook evaluation
# (the sync process is a separate process; the hook must not call it)
# ===================================================================


def test_sync_module_exists():
    """The sync process module exists at sandbox.connector.sync.process."""
    _need("sandbox.connector.sync.process", "SyncProcess")
    from sandbox.connector.sync.process import SyncProcess
    assert SyncProcess is not None
