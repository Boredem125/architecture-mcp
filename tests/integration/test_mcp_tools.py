"""MCP tools driven in-process against a real client session.

Proves the MCP channel shares the folder queue with the hook: run_privileged
blocks, a concurrent approver executes the command, and the tool result
carries the output back — the same loop as the hook, different surface.
"""
from __future__ import annotations

import asyncio
import json
import sys

import pytest
from mcp.shared.memory import create_connected_server_and_client_session

from sandbox.connector.broker import FolderBroker
from sandbox.connector.install import init
from sandbox.connector.layout import FolderLayout
from sandbox.connector.mcp_server import build_server
from sandbox.connector.policy import load_policy, save_policy
from sandbox.connector.queue import EscalationQueue


@pytest.fixture
def root(tmp_path):
    init(tmp_path, claude=False, mcp=False)
    layout = FolderLayout(tmp_path)
    policy = load_policy(layout.policy_file)
    policy.escalation_timeout_seconds = 5
    save_policy(policy, layout.policy_file)
    return layout.root


def _payload(result) -> dict:
    """Extract the tool's dict result from a CallToolResult."""
    if getattr(result, "structuredContent", None):
        sc = result.structuredContent
        # FastMCP wraps a bare dict under "result" sometimes; unwrap.
        return sc.get("result", sc) if isinstance(sc, dict) else sc
    # Fallback: parse the first text content block.
    return json.loads(result.content[0].text)


async def test_sandbox_status_lists_triggers(root):
    server = build_server(root)
    async with create_connected_server_and_client_session(server) as client:
        await client.initialize()
        result = await client.call_tool("sandbox_status", {})
        data = _payload(result)
        assert data["root"] == str(root)
        assert data["triggers"]["shell"] == "escalate"


async def test_run_privileged_returns_output_on_approval(root):
    server = build_server(root)
    layout = FolderLayout(root)
    queue = EscalationQueue(layout)
    broker = FolderBroker()
    command = f'{sys.executable} -c "print(\'MCP_MARKER_99\')"'

    async def approver():
        for _ in range(100):
            pending = queue.list_pending()
            if pending:
                rec = queue.claim(pending[0]["request_id"], "cli:tester")
                res = await broker.execute(rec, "cli:tester")
                queue.finish(rec["request_id"], res)
                return
            await asyncio.sleep(0.05)

    async with create_connected_server_and_client_session(server) as client:
        await client.initialize()
        task = asyncio.create_task(approver())
        result = await client.call_tool(
            "run_privileged", {"command": command, "reason": "test"}
        )
        await task
        data = _payload(result)
        assert data["status"] == "executed"
        assert data["exit_code"] == 0
        assert "MCP_MARKER_99" in data["stdout"]


async def test_run_privileged_pending_then_check_request(root):
    """No approver: run_privileged returns pending; check_request picks it up."""
    server = build_server(root)
    layout = FolderLayout(root)
    # Force a fast pending by setting a tiny block window via policy.
    policy = load_policy(layout.policy_file)
    policy.escalation_timeout_seconds = 1
    save_policy(policy, layout.policy_file)

    queue = EscalationQueue(layout)
    broker = FolderBroker()

    async with create_connected_server_and_client_session(server) as client:
        await client.initialize()
        result = await client.call_tool(
            "run_privileged", {"command": f'{sys.executable} -c "print(1)"'}
        )
        data = _payload(result)
        assert data["status"] == "pending"
        rid = data["request_id"]

        # Now a human approves out of band.
        rec = queue.claim(rid, "cli")
        res = await broker.execute(rec, "cli")
        queue.finish(rid, res)

        # check_request retrieves the resolved output.
        result2 = await client.call_tool("check_request", {"request_id": rid})
        data2 = _payload(result2)
        assert data2["status"] == "executed"
        assert data2["exit_code"] == 0


async def test_hook_request_visible_over_mcp(root):
    """A request raised by the hook origin is retrievable via check_request."""
    layout = FolderLayout(root)
    queue = EscalationQueue(layout)
    # Simulate a hook-origin pending request.
    rid = queue.submit({
        "root": str(root), "origin": "hook", "trigger": ["shell"],
        "command": f'{sys.executable} -c "print(2)"', "exec_cwd": str(root),
    })
    broker = FolderBroker()
    rec = queue.claim(rid, "cli")
    res = await broker.execute(rec, "cli")
    queue.finish(rid, res)

    server = build_server(root)
    async with create_connected_server_and_client_session(server) as client:
        await client.initialize()
        result = await client.call_tool("check_request", {"request_id": rid})
        data = _payload(result)
        assert data["status"] == "executed"
