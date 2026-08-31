"""M4 hook behavior: SessionStart context, observe-audits, memory short-circuit."""
from __future__ import annotations

import asyncio
import json

import pytest

from sandbox.connector.hook_eval import pre_tool_use, session_start_context
from sandbox.connector.install import init
from sandbox.connector.layout import FolderLayout
from sandbox.connector.memory import DecisionMemory
from sandbox.connector.policy import load_policy, save_policy


@pytest.fixture
def layout(tmp_path):
    init(tmp_path, claude=False, mcp=False)
    return FolderLayout(tmp_path)


def test_session_start_context_mentions_tools(layout):
    ctx = session_start_context(layout)
    assert "SANDBOX CONNECTOR ACTIVE" in ctx
    assert "run_privileged" in ctx
    assert "request_path_access" in ctx
    assert "fetch_url" in ctx


def test_read_outside_is_observed_not_blocked(layout):
    """A read outside the folder is allowed additively (observe) and audited."""
    payload = {
        "tool_name": "Read",
        "tool_input": {"file_path": "C:\\Windows\\System32\\drivers\\etc\\hosts"},
        "cwd": str(layout.root),
    }
    result = asyncio.run(pre_tool_use(payload, layout))
    # observe → additive, no permissionDecision
    assert "permissionDecision" not in result["hookSpecificOutput"]

    # And it left an audit trail.
    from sandbox.connector.audit import FolderAudit

    session = json.loads(layout.session_file.read_text())
    audit = FolderAudit(layout.audit_dir, session["session_id"])
    records = audit.list_records()
    assert any(r.get("event") == "observed" for r in records)


def test_write_outside_denied_with_pointer(layout):
    payload = {
        "tool_name": "Write",
        "tool_input": {"file_path": "C:\\Windows\\evil.txt", "content": "x"},
        "cwd": str(layout.root),
    }
    result = asyncio.run(pre_tool_use(payload, layout))
    hso = result["hookSpecificOutput"]
    assert hso["permissionDecision"] == "deny"
    assert "request_path_access" in hso["permissionDecisionReason"]


def test_network_escalate_redirects_to_fetch_url(layout):
    payload = {
        "tool_name": "WebFetch",
        "tool_input": {"url": "https://evil.example.com/data"},
        "cwd": str(layout.root),
    }
    result = asyncio.run(pre_tool_use(payload, layout))
    hso = result["hookSpecificOutput"]
    assert hso["permissionDecision"] == "deny"
    assert "fetch_url" in hso["permissionDecisionReason"]


def test_remembered_command_short_circuits_escalation(layout):
    """A remembered command is auto-allowed without hitting the queue."""
    session = json.loads(layout.session_file.read_text())
    mem = DecisionMemory(layout.remembered, session["session_id"])
    mem.remember("command", "some-privileged-cmd --flag")

    payload = {
        "tool_name": "Bash",
        "tool_input": {"command": "some-privileged-cmd --flag"},
        "cwd": str(layout.root),
    }
    # No approver is running; if this escalated, it would block until timeout.
    # Because it's remembered, it returns immediately (additive allow).
    policy = load_policy(layout.policy_file)
    policy.escalation_timeout_seconds = 30
    save_policy(policy, layout.policy_file)

    result = asyncio.run(asyncio.wait_for(pre_tool_use(payload, layout), timeout=5))
    assert "permissionDecision" not in result["hookSpecificOutput"]


def test_blocklisted_command_denied_before_escalation(layout):
    payload = {
        "tool_name": "Bash",
        "tool_input": {"command": "rm -rf /"},
        "cwd": str(layout.root),
    }
    result = asyncio.run(pre_tool_use(payload, layout))
    hso = result["hookSpecificOutput"]
    assert hso["permissionDecision"] == "deny"


def test_risk_upgrades_sensitive_read_from_observe_to_escalate(layout):
    """A plain out-of-folder read is observed; reading credentials escalates."""
    # Plain read outside the folder → observe (additive, no decision).
    plain = asyncio.run(pre_tool_use({
        "tool_name": "Read",
        "tool_input": {"file_path": "C:\\Users\\dell\\notes.txt"},
        "cwd": str(layout.root),
    }, layout))
    assert "permissionDecision" not in plain["hookSpecificOutput"]

    # Reading private key material outside the folder → risk spikes → escalate.
    sensitive = asyncio.run(pre_tool_use({
        "tool_name": "Read",
        "tool_input": {"file_path": "C:\\Users\\dell\\.ssh\\id_rsa"},
        "cwd": str(layout.root),
    }, layout))
    hso = sensitive["hookSpecificOutput"]
    # read_outside can't run in the hook, so an escalate becomes a redirect deny.
    assert hso.get("permissionDecision") == "deny"


def test_escalation_record_carries_identity_and_risk(layout):
    """The escalation record threads identity + risk (for signing + explain)."""
    import json as _json
    import threading
    import time as _time

    from sandbox.connector.broker import FolderBroker
    from sandbox.connector.policy import load_policy, save_policy
    from sandbox.connector.queue import EscalationQueue

    policy = load_policy(layout.policy_file)
    policy.escalation_timeout_seconds = 10
    save_policy(policy, layout.policy_file)

    queue = EscalationQueue(layout)
    broker = FolderBroker()

    captured = {}

    def approver():
        import asyncio as _a
        for _ in range(200):
            pend = queue.list_pending()
            if pend:
                captured.update(pend[0])
                rec = queue.claim(pend[0]["request_id"], "cli:tester")
                res = _a.new_event_loop().run_until_complete(
                    broker.execute(rec, "cli:tester"))
                queue.finish(rec["request_id"], res)
                return
            _time.sleep(0.05)

    t = threading.Thread(target=approver)
    t.start()
    asyncio.run(pre_tool_use({
        "tool_name": "Bash",
        "tool_input": {"command": "pip install something"},
        "cwd": str(layout.root),
        "agent": {"kind": "codex", "model": "gpt-x"},
    }, layout))
    t.join()

    assert captured.get("identity", {}).get("agent_type") == "codex"
    assert "risk" in captured and captured["risk"].get("score") is not None
