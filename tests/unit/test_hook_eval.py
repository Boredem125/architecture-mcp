"""hook_eval PreToolUse contract — the exact stdout for each decision path."""
from __future__ import annotations

import asyncio
import json

import pytest

from sandbox.connector.hook_eval import pre_tool_use
from sandbox.connector.layout import FolderLayout
from sandbox.connector.policy import default_policy, save_policy
from sandbox.connector.queue import EscalationQueue


@pytest.fixture
def layout(tmp_path):
    lo = FolderLayout(tmp_path)
    lo.ensure_dirs()
    policy = default_policy()
    policy.escalation_timeout_seconds = 2  # keep tests fast
    save_policy(policy, lo.policy_file)
    lo.session_file.write_text(json.dumps({"session_id": "s-test"}), encoding="utf-8")
    return lo


def _pre(tool_name: str, tool_input: dict, cwd: str) -> dict:
    return {"tool_name": tool_name, "tool_input": tool_input, "cwd": cwd,
            "session_id": "abc", "hook_event_name": "PreToolUse"}


async def test_non_shell_tool_is_additive(layout):
    out = await pre_tool_use(_pre("Read", {"file_path": "x.txt"}, str(layout.root)), layout)
    # No permissionDecision → Claude Code's own flow runs.
    assert "permissionDecision" not in out["hookSpecificOutput"]


async def test_allowlisted_shell_passes(layout):
    out = await pre_tool_use(_pre("Bash", {"command": "git status"}, str(layout.root)), layout)
    assert "permissionDecision" not in out["hookSpecificOutput"]


async def test_sandbox_touch_denied(layout):
    out = await pre_tool_use(
        _pre("Bash", {"command": "rm -rf .sandbox"}, str(layout.root)), layout
    )
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny"


async def test_escalation_times_out_to_pending(layout):
    out = await pre_tool_use(
        _pre("Bash", {"command": "npm install -g typescript"}, str(layout.root)), layout
    )
    hso = out["hookSpecificOutput"]
    assert hso["permissionDecision"] == "deny"
    assert "check_request" in hso["permissionDecisionReason"]


async def test_escalation_approved_returns_output(layout):
    """The crux: deny the tool, but the reason carries the command output."""
    queue = EscalationQueue(layout)

    async def approver():
        # Wait for the request to appear, then approve+finish it.
        for _ in range(50):
            pending = queue.list_pending()
            if pending:
                rid = pending[0]["request_id"]
                queue.claim(rid, "cli:tester")
                queue.finish(rid, {
                    "state": "executed", "decision": "approved",
                    "reviewer_id": "cli:tester", "exit_code": 0,
                    "stdout": "added 1 package\n", "stderr": "",
                    "command": "npm install -g typescript",
                })
                return
            await asyncio.sleep(0.05)

    task = asyncio.create_task(approver())
    out = await pre_tool_use(
        _pre("Bash", {"command": "npm install -g typescript"}, str(layout.root)), layout
    )
    await task

    hso = out["hookSpecificOutput"]
    assert hso["permissionDecision"] == "deny"  # tool never runs
    reason = hso["permissionDecisionReason"]
    assert "added 1 package" in reason           # but output reached the model
    assert "exit_code: 0" in reason


async def test_escalation_denied_returns_reason(layout):
    queue = EscalationQueue(layout)

    async def denier():
        for _ in range(50):
            pending = queue.list_pending()
            if pending:
                rid = pending[0]["request_id"]
                queue.claim(rid, "cli:tester")
                queue.finish(rid, {
                    "state": "denied", "decision": "denied",
                    "reviewer_id": "cli:tester",
                    "reason": "we don't install globals",
                })
                return
            await asyncio.sleep(0.05)

    task = asyncio.create_task(denier())
    out = await pre_tool_use(
        _pre("Bash", {"command": "npm install -g typescript"}, str(layout.root)), layout
    )
    await task

    hso = out["hookSpecificOutput"]
    assert hso["permissionDecision"] == "deny"
    assert "we don't install globals" in hso["permissionDecisionReason"]
