"""MCP server — the universal escalation/return channel.

An MCP tool *result* goes straight into the model's context, so a tool that
blocks on human approval and returns the captured output *is* the paste-back
loop, natively — for Claude Code, Codex, Cursor, and Windsurf alike.

It shares the exact same folder queue as the Claude Code hook, so a request
raised by the hook can be retrieved over MCP and vice versa (``check_request``
resolves either origin).

Root resolution order: ``--root`` argv → ``SANDBOX_CONNECTOR_ROOT`` env → walk
up from cwd for ``.sandbox/`` → cwd.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any

from sandbox.connector.layout import FolderLayout
from sandbox.connector.queue import EscalationQueue

_SERVER_BLOCK_SECONDS = 55  # degrade to `pending` past this, never hang forever


def _resolve_root(explicit: str | None = None) -> Path:
    if explicit:
        return Path(explicit).resolve()
    env = os.environ.get("SANDBOX_CONNECTOR_ROOT")
    if env:
        return Path(env).resolve()
    found = FolderLayout.discover(os.getcwd())
    if found is not None:
        return found.root
    return Path(os.getcwd()).resolve()


def _truncate(text: str, max_chars: int) -> tuple[str, bool]:
    if len(text) <= max_chars:
        return text, False
    head = text[: max_chars // 2]
    tail = text[-max_chars // 2 :]
    elided = len(text) - len(head) - len(tail)
    return f"{head}\n… [{elided} chars elided] …\n{tail}", True


def _done_to_result(rec: dict[str, Any], layout: FolderLayout, policy) -> dict[str, Any]:
    """Shape a done-record into the tool result the model sees."""
    state = rec.get("state") or rec.get("decision")
    request_id = rec.get("request_id", "")
    if state in ("executed", "approved"):
        max_chars = policy.output.max_chars
        stdout, t1 = _truncate(rec.get("stdout", ""), max_chars)
        stderr, t2 = _truncate(rec.get("stderr", ""), max_chars)
        return {
            "status": "executed",
            "request_id": request_id,
            "command": rec.get("command", ""),
            "exit_code": rec.get("exit_code"),
            "stdout": stdout,
            "stderr": stderr,
            "truncated": t1 or t2,
            "output_file": str(layout.out_dir / f"{request_id}.txt"),
            "decided_by": rec.get("reviewer_id", ""),
        }
    if state == "denied":
        return {"status": "denied", "request_id": request_id,
                "reason": rec.get("reason", "")}
    # failed / unknown — surface the actual error so the model isn't told a bare
    # "denied" when the human approved but the operation itself failed.
    return {"status": state or "unknown", "request_id": request_id,
            "reason": rec.get("reason", ""),
            "exit_code": rec.get("exit_code"),
            "stderr": rec.get("stderr", "")}


def build_server(root: Path | None = None) -> Any:
    """Construct the FastMCP server bound to a folder. Importable for tests."""
    from mcp.server.fastmcp import FastMCP

    resolved_root = root or _resolve_root()
    layout = FolderLayout(resolved_root)
    layout.ensure_dirs()

    mcp = FastMCP(
        "sandbox",
        instructions=(
            "This sandbox mediates privileged access for the current project "
            "folder. When you need to run a shell/root command, use "
            "run_privileged — a human approves it, the sandbox runs it outside "
            "the folder, and you receive the output. Never try to bypass this."
        ),
    )

    def _queue() -> EscalationQueue:
        return EscalationQueue(layout)

    async def _submit_and_wait(record: dict[str, Any]) -> dict[str, Any]:
        policy = _enforced(layout)
        queue = _queue()
        request_id = queue.submit(record)
        block = min(policy.escalation_timeout_seconds, _SERVER_BLOCK_SECONDS)
        done = await queue.wait(request_id, timeout=block)
        if done is None:
            return {
                "status": "pending",
                "request_id": request_id,
                "hint": (
                    "A human has not decided yet. Tell the user to approve it "
                    f"in their `sandbox watch` terminal, then call "
                    f"check_request('{request_id}')."
                ),
            }
        return _done_to_result(done, layout, policy)

    @mcp.tool()
    async def run_privileged(command: str, reason: str = "") -> dict[str, Any]:
        """Request a privileged shell command. A human approves; you get the output.

        The command runs OUTSIDE the sandbox on your behalf — you never receive
        root yourself. Returns the captured stdout/stderr on approval.
        """
        record = {
            "root": str(layout.root),
            "origin": "mcp",
            "trigger": ["shell"],
            "kind": "command",
            "command": command,
            "exec_cwd": str(layout.root),
            "reason": reason or "MCP run_privileged",
            "agent": {"kind": "mcp"},
            "execute_on_approve": True,
        }
        return await _submit_and_wait(record)

    @mcp.tool()
    async def request_path_access(
        path: str, mode: str = "read", reason: str = "", content: str = ""
    ) -> dict[str, Any]:
        """Request a file operation OUTSIDE the sandbox folder.

        A human approves; the sandbox performs the read or write on your behalf
        (you never receive the capability). mode is "read" or "write"; for
        "write", pass the file content in `content`.
        """
        record = {
            "root": str(layout.root),
            "origin": "mcp",
            "trigger": ["write_outside" if mode == "write" else "read_outside"],
            "kind": "path_access",
            "path": path,
            "mode": mode,
            "content": content,
            "exec_cwd": str(layout.root),
            "reason": reason or f"MCP request_path_access ({mode})",
            "agent": {"kind": "mcp"},
            "execute_on_approve": True,
        }
        return await _submit_and_wait(record)

    @mcp.tool()
    async def fetch_url(url: str, reason: str = "") -> dict[str, Any]:
        """Fetch a URL through the sandbox. A human approves; you get the body.

        Network access is gated — the sandbox performs the fetch outside your
        context so you never make the request directly.
        """
        record = {
            "root": str(layout.root),
            "origin": "mcp",
            "trigger": ["network"],
            "kind": "fetch",
            "url": url,
            "exec_cwd": str(layout.root),
            "reason": reason or "MCP fetch_url",
            "agent": {"kind": "mcp"},
            "execute_on_approve": True,
        }
        return await _submit_and_wait(record)

    @mcp.tool()
    async def check_request(request_id: str, wait_seconds: int = 30) -> dict[str, Any]:
        """Retrieve the outcome of an escalation (from MCP OR the hook).

        Use this after run_privileged returns 'pending', or to pick up a
        request the Claude Code hook raised.
        """
        policy = _enforced(layout)
        queue = _queue()
        rec = queue.get(request_id)
        if rec is None:
            return {"status": "not_found", "request_id": request_id}
        # Already decided?
        if queue.status(request_id) == "done":
            return _done_to_result(rec, layout, policy)
        # Still pending — block briefly.
        done = await queue.wait(request_id, timeout=max(0, wait_seconds))
        if done is None:
            return {"status": "pending", "request_id": request_id,
                    "hint": "Still awaiting a human decision."}
        return _done_to_result(done, layout, policy)

    @mcp.tool()
    async def sandbox_status() -> dict[str, Any]:
        """Show the sandbox root, triggers, and any pending escalations."""
        policy = _enforced(layout)
        queue = _queue()
        pending = queue.list_pending()
        return {
            "root": str(layout.root),
            "policy_mode": policy.mode,
            "triggers": policy.triggers.model_dump(),
            "policy_version": _version(layout),
            "pending": [
                {"request_id": r["request_id"], "command": r.get("command", "")}
                for r in pending
            ],
        }

    return mcp


def _enforced(layout: FolderLayout):
    """The approved policy version (stricter of approved and on-disk if drifted)."""
    from sandbox.connector.policy_versions import enforced_policy

    return enforced_policy(layout)[0]


def _version(layout: FolderLayout) -> dict[str, Any]:
    from sandbox.connector.policy_versions import current_version

    return current_version(layout)


def main() -> int:
    root = None
    argv = sys.argv[1:]
    if "--root" in argv:
        i = argv.index("--root")
        if i + 1 < len(argv):
            root = Path(argv[i + 1]).resolve()
    server = build_server(root)
    server.run("stdio")
    return 0


if __name__ == "__main__":
    sys.exit(main())
