"""FolderBroker — executes an approved escalation via the reused PrivilegeBroker.

The approver claims a pending record, hands it here, and gets back a terminal
result dict ready for :meth:`EscalationQueue.finish`. Execution itself is the
battle-tested :class:`PrivilegeBroker._execute_approved` primitive — this class
only adapts the folder's record shape to it.
"""
from __future__ import annotations

from typing import Any

from sandbox.broker.privilege_broker import BrokerRequestState, PrivilegeBroker

# Provenance fields carried from the claimed request into the done-record so the
# signature covers who/what/why, not just the outcome.
_PROVENANCE_FIELDS = (
    "identity", "trigger", "reason_code", "risk", "requires_dual",
    "policy_version", "session_id", "tool_name",
)


def _provenance(record: dict[str, Any]) -> dict[str, Any]:
    return {k: record[k] for k in _PROVENANCE_FIELDS if k in record}


class FolderBroker:
    def __init__(self, exec_timeout: int = 120) -> None:
        self._broker = PrivilegeBroker(exec_timeout=exec_timeout)

    async def execute(
        self, record: dict[str, Any], reviewer_id: str, reason: str = ""
    ) -> dict[str, Any]:
        """Run the approved escalation and return a done-record dict.

        Dispatches on ``kind``: shell ``command`` runs via PrivilegeBroker;
        ``path_access`` performs the file op directly; ``fetch`` retrieves a URL.
        """
        kind = record.get("kind", "command")
        if kind == "tool_call":
            return self._approve_tool_call(record, reviewer_id, reason)
        if kind == "path_access":
            return self._execute_path_access(record, reviewer_id, reason)
        if kind == "fetch":
            return await self._execute_fetch(record, reviewer_id, reason)

        command = record.get("command", "")
        exec_cwd = record.get("exec_cwd") or record.get("root", "")
        req = await self._broker.submit_request(
            session_id=record.get("session_id", ""),
            run_id=record.get("request_id", ""),
            agent_id=record.get("agent", {}).get("kind", "") if isinstance(record.get("agent"), dict) else "",
            command=command,
            jail_dir=exec_cwd,
            exec_cwd=exec_cwd,
        )
        await self._broker.approve(req.request_id, reviewer_id, reason)

        executed = req.state == BrokerRequestState.EXECUTED
        return {
            **_provenance(record),
            "request_id": record.get("request_id", ""),
            "state": "executed" if executed else "failed",
            "decision": "approved",
            "reviewer_id": reviewer_id,
            "reason": reason,
            "exit_code": req.exit_code,
            "stdout": req.stdout,
            "stderr": req.stderr,
            "command": command,
            "command_original": record.get("command_original", command),
            "exec_cwd": exec_cwd,
            "root": record.get("root", ""),
        }

    def _approve_tool_call(
        self, record: dict[str, Any], reviewer_id: str, reason: str
    ) -> dict[str, Any]:
        """Approve a non-shell tool call. Nothing runs here: the sandbox can't
        make the agent's MCP call, so the signed approval lets the agent's
        identical retry through once (connector/tool_grants.py)."""
        from sandbox.connector.tool_grants import GRANT_TTL_SECONDS

        return {
            **_provenance(record),
            "request_id": record.get("request_id", ""),
            "kind": "tool_call",
            "state": "approved",
            "decision": "approved",
            "reviewer_id": reviewer_id,
            "reason": reason,
            "command": record.get("command", ""),
            "fingerprint": record.get("fingerprint", ""),
            "governance": record.get("governance", []),
            "exit_code": 0,
            "stdout": (f"Approved. Retry the identical {record.get('tool_name', 'tool')} call within "
                       f"{GRANT_TTL_SECONDS // 60} minutes; it will be allowed once."),
            "stderr": "",
            "root": record.get("root", ""),
        }

    def _execute_path_access(
        self, record: dict[str, Any], reviewer_id: str, reason: str
    ) -> dict[str, Any]:
        """Perform an approved out-of-folder read or write directly.

        A read of a *directory* lists its contents (the common "show me what's
        in E:\\x" case); a read of a *file* returns its text.
        """
        import os
        from pathlib import Path

        path = record.get("path", "")
        mode = record.get("mode", "read")
        content = record.get("content", "")
        base = {
            **_provenance(record),
            "request_id": record.get("request_id", ""),
            "decision": "approved",
            "reviewer_id": reviewer_id,
            "reason": reason,
            "command": f"{mode} {path}",
            "path": path,
            "root": record.get("root", ""),
            "exec_cwd": record.get("exec_cwd", ""),
        }
        try:
            p = Path(path)
            if mode == "write":
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text(content, encoding="utf-8")
                base.update(state="executed", exit_code=0,
                            stdout=f"wrote {len(content)} chars to {path}", stderr="")
            elif not p.exists():
                base.update(state="failed", exit_code=1, stdout="",
                            stderr=f"path does not exist: {path}")
            elif p.is_dir():
                names = sorted(os.listdir(p))
                lines = []
                for name in names:
                    child = p / name
                    tag = "<DIR>" if child.is_dir() else "     "
                    try:
                        size = "" if child.is_dir() else f"  {child.stat().st_size} bytes"
                    except OSError:
                        size = ""
                    lines.append(f"  {tag}  {name}{size}")
                listing = "\n".join(lines) if lines else "  (empty directory)"
                base.update(state="executed", exit_code=0,
                            stdout=f"Directory {path} ({len(names)} entries):\n{listing}",
                            stderr="")
            else:
                data = p.read_text(encoding="utf-8", errors="replace")
                base.update(state="executed", exit_code=0, stdout=data, stderr="")
        except OSError as exc:
            base.update(state="failed", exit_code=1, stdout="", stderr=str(exc))
        return base

    async def _execute_fetch(
        self, record: dict[str, Any], reviewer_id: str, reason: str
    ) -> dict[str, Any]:
        """Fetch an approved URL and return its body."""
        url = record.get("url", "")
        base = {
            **_provenance(record),
            "request_id": record.get("request_id", ""),
            "decision": "approved",
            "reviewer_id": reviewer_id,
            "reason": reason,
            "command": f"fetch {url}",
            "url": url,
            "root": record.get("root", ""),
            "exec_cwd": record.get("exec_cwd", ""),
        }
        try:
            import httpx

            async with httpx.AsyncClient(follow_redirects=True, timeout=30) as client:
                resp = await client.get(url)
                body = resp.text
            base.update(state="executed", exit_code=0,
                        stdout=body, stderr=f"HTTP {resp.status_code}")
        except Exception as exc:  # noqa: BLE001
            base.update(state="failed", exit_code=1, stdout="", stderr=str(exc))
        return base

    @staticmethod
    def denial(record: dict[str, Any], reviewer_id: str, reason: str) -> dict[str, Any]:
        """Build a done-record for a human denial (nothing executes)."""
        return {
            **_provenance(record),
            "request_id": record.get("request_id", ""),
            "state": "denied",
            "decision": "denied",
            "reviewer_id": reviewer_id,
            "reason": reason,
            "command": record.get("command", ""),
            "root": record.get("root", ""),
        }
