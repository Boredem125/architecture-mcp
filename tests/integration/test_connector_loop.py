"""End-to-end connector loop, no Claude Code subprocess.

hook_eval submits an escalation → a programmatic approver claims it and runs
the REAL command via FolderBroker → hook_eval returns the output JSON that
would reach the model. This is the whole "paste it back" loop.
"""
from __future__ import annotations

import asyncio
import json
import sys

import pytest

from sandbox.connector.broker import FolderBroker
from sandbox.connector.hook_eval import pre_tool_use
from sandbox.connector.layout import FolderLayout
from sandbox.connector.policy import default_policy, save_policy
from sandbox.connector.queue import EscalationQueue


@pytest.fixture
def layout(tmp_path):
    lo = FolderLayout(tmp_path)
    lo.ensure_dirs()
    policy = default_policy()
    policy.escalation_timeout_seconds = 5
    save_policy(policy, lo.policy_file)
    lo.session_file.write_text(json.dumps({"session_id": "s-e2e"}), encoding="utf-8")
    return lo


async def test_full_loop_executes_and_returns_output(layout):
    queue = EscalationQueue(layout)
    broker = FolderBroker()
    # A command that really runs and prints a known marker.
    command = f'{sys.executable} -c "print(\'LOOP_MARKER_42\')"'

    async def approver():
        for _ in range(100):
            pending = queue.list_pending()
            if pending:
                rec = queue.claim(pending[0]["request_id"], "cli:tester")
                result = await broker.execute(rec, "cli:tester")
                queue.finish(rec["request_id"], result)
                return
            await asyncio.sleep(0.05)

    task = asyncio.create_task(approver())
    out = await pre_tool_use(
        {"tool_name": "Bash", "tool_input": {"command": command},
         "cwd": str(layout.root), "session_id": "abc"},
        layout,
    )
    await task

    reason = out["hookSpecificOutput"]["permissionDecisionReason"]
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert "LOOP_MARKER_42" in reason
    assert "exit_code: 0" in reason
