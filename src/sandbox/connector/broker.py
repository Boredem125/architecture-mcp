"""FolderBroker -- executes an approved escalation (T12c: no shell).

The approver claims a pending record, hands it here, and gets back a terminal
result dict ready for :meth:`EscalationQueue.finish`. T12c (ADR 0010 s9):
the broker runs the lexed argv without a shell, through the recorded shell
binary (bash or pwsh) from session.json, after pinning the script file if
the command is bound.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from sandbox.broker.privilege_broker import PrivilegeBroker

# Provenance fields carried from the claimed request into the done-record so the
# signature covers who/what/why, not just the outcome.
_PROVENANCE_FIELDS = (
    "identity", "trigger", "reason_code", "risk", "requires_dual",
    "policy_version", "session_id", "tool_name",
    "created_at",  # oversight metrics: time from request to decision
    # Governance clause hits on the request, so they survive into the signed
    # done-record (evidence packs count them; they were dropped before).
    "governance", "governance_violations",
)


def _provenance(record: dict[str, Any]) -> dict[str, Any]:
    return {k: record[k] for k in _PROVENANCE_FIELDS if k in record}


def _read_session(root: str) -> dict[str, Any]:
    """Read session.json from the workspace."""
    try:
        sf = Path(root) / ".sandbox" / "session.json"
        return json.loads(sf.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def _refusal_record(
    record: dict[str, Any],
    reviewer_id: str,
    reason_code: str,
    reason: str,
    *,
    expected_sha256: str = "",
    actual_sha256: str = "",
) -> dict[str, Any]:
    """Build a terminal refusal done-record."""
    result = {
        **_provenance(record),
        "request_id": record.get("request_id", ""),
        "state": "refused",
        "decision": "refused",
        "reviewer_id": reviewer_id,
        "reason": reason,
        "reason_code": reason_code,
        "command": record.get("command", ""),
        "root": record.get("root", ""),
        "exec_cwd": record.get("exec_cwd", ""),
        "exit_code": None,
        "stdout": "",
        "stderr": reason,
    }
    if expected_sha256:
        result["expected_sha256"] = expected_sha256
    if actual_sha256:
        result["actual_sha256"] = actual_sha256
    # Carry script fields into the refusal record
    if record.get("script"):
        result["script"] = record["script"]
    return result


class FolderBroker:
    def __init__(self, exec_timeout: int = 120) -> None:
        self._exec_timeout = exec_timeout

    async def execute(
        self, record: dict[str, Any], reviewer_id: str, reason: str = ""
    ) -> dict[str, Any]:
        """Run the approved escalation and return a done-record dict.

        Dispatches on ``kind``: shell ``command`` runs with shell=False
        through the recorded shell; ``path_access`` performs the file op
        directly; ``fetch`` retrieves a URL.
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
        root = record.get("root", exec_cwd)
        tool_name = record.get("tool_name", "")

        # T12c (ADR 0010 s9, C-c0-6): no v1 fallback.  A record without
        # fp_v == 2 or without tool_name is refused with RECORD_UNVERSIONED.
        if record.get("fp_v") != 2 or not tool_name:
            return _refusal_record(
                record, reviewer_id, "RECORD_UNVERSIONED",
                "record missing fp_v=2 or tool_name; re-run sandbox init",
            )
        has_fp_v2 = True

        # Read session for shell paths
        session = _read_session(root)

        # T12c: resolve the shell binary (ADR 0010 s9 9.4)
        from sandbox.connector.script_pin import (
            resolve_shell,
            build_shell_argv,
            resolve as _resolve_script,
            pin_script,
            posix_rehash,
            ScriptPin,
        )

        shell_path, shell_err = resolve_shell(tool_name, session)

        # Check if the shell path is under root (refused)
        if shell_path:
            try:
                root_resolved = Path(root).resolve()
                shell_resolved = Path(shell_path).resolve()
                shell_resolved.relative_to(root_resolved)
                # If we get here, the shell is under root -- refuse
                shell_path = None
                shell_err = "SHELL_UNAVAILABLE: shell path is under root"
            except (ValueError, OSError):
                pass  # Good, not under root

        if shell_path is None:
            return _refusal_record(
                record, reviewer_id, "SHELL_UNAVAILABLE", shell_err,
            )

        # T12c: re-resolve the command (ADR 0010 s9 9.4)
        # Only apply script checks for fp_v=2 records (T12c onwards)
        has_fp_v2 = record.get("fp_v") == 2
        script_res = None
        if has_fp_v2:
            script_res = _resolve_script(
                command, tool_name, exec_cwd, root,
                key_home=os.environ.get("SANDBOX_KEY_HOME", ""),
            )

        # Re-resolve check: must match the record's script field
        rec_script = record.get("script") if has_fp_v2 else None
        if has_fp_v2 and rec_script is None and script_res is not None and script_res.script is not None:
            # Record has no script, but resolve found one -> refuse
            return _refusal_record(
                record, reviewer_id, "SCRIPT_CHANGED",
                "re-resolve mismatch: record has no script but command resolves to one",
            )
        if has_fp_v2 and rec_script is not None and script_res is not None and script_res.script is None:
            return _refusal_record(
                record, reviewer_id, "SCRIPT_CHANGED",
                "re-resolve mismatch: record has script but command no longer resolves",
            )
        if has_fp_v2 and rec_script is not None and script_res is not None and script_res.script is not None:
            # Compare key fields
            if rec_script.get("rel") != script_res.script.get("rel"):
                return _refusal_record(
                    record, reviewer_id, "SCRIPT_CHANGED",
                    "re-resolve mismatch: script rel path changed",
                )

        # If bound: pin and verify the script
        pin: ScriptPin | None = None
        script_changed_during_run = False

        if rec_script is not None:
            cwd_path = Path(exec_cwd).resolve()
            # Get the script path from the resolved script operand
            script_index = rec_script.get("script_index", 1)
            argv = rec_script.get("argv", [])
            if script_index is not None and script_index < len(argv):
                script_operand = argv[script_index]
            else:
                script_operand = rec_script.get("rel", "")

            script_path = cwd_path / script_operand

            try:
                pin = pin_script(
                    script_path,
                    Path(root).resolve(),
                    rec_script.get("sha256", ""),
                    rec_script.get("size", 0),
                )
            except OSError as exc:
                err_msg = str(exc)
                actual_sha = ""
                if "SCRIPT_CHANGED" in err_msg:
                    # Extract actual hash if present
                    import re
                    m = re.search(r"got sha256=(\w+)", err_msg)
                    if m:
                        actual_sha = m.group(1)
                    return _refusal_record(
                        record, reviewer_id, "SCRIPT_CHANGED", err_msg,
                        expected_sha256=rec_script.get("sha256", ""),
                        actual_sha256=actual_sha,
                    )
                return _refusal_record(
                    record, reviewer_id, "SCRIPT_CHANGED",
                    f"pin failed: {err_msg}",
                    expected_sha256=rec_script.get("sha256", ""),
                )

        # Build the argv and run with shell=False
        argv_exec = build_shell_argv(command, tool_name, shell_path)

        # Use the clean env from PrivilegeBroker
        clean_env = PrivilegeBroker._clean_env()

        try:
            proc_result = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: subprocess.run(
                    argv_exec,
                    shell=False,
                    capture_output=True,
                    text=True,
                    timeout=self._exec_timeout,
                    cwd=exec_cwd,
                    env=clean_env,
                ),
            )
            exit_code = proc_result.returncode
            stdout = proc_result.stdout
            stderr = proc_result.stderr
            state = "executed"
        except subprocess.TimeoutExpired:
            exit_code = -1
            stdout = ""
            stderr = f"Command timed out after {self._exec_timeout}s"
            state = "failed"
        except Exception as exc:
            exit_code = -1
            stdout = ""
            stderr = str(exc)
            state = "failed"
        finally:
            # POSIX after-run re-hash
            if pin is not None:
                if sys.platform != "win32" and rec_script is not None:
                    script_index = rec_script.get("script_index", 1)
                    argv = rec_script.get("argv", [])
                    if script_index is not None and script_index < len(argv):
                        sp = Path(exec_cwd).resolve() / argv[script_index]
                    else:
                        sp = Path(exec_cwd).resolve() / rec_script.get("rel", "")
                    post_hash = posix_rehash(sp)
                    if post_hash and post_hash != rec_script.get("sha256", ""):
                        script_changed_during_run = True
                pin.release()

        done = {
            **_provenance(record),
            "request_id": record.get("request_id", ""),
            "state": state,
            "decision": "approved",
            "reviewer_id": reviewer_id,
            "reason": reason,
            "exit_code": exit_code,
            "stdout": stdout,
            "stderr": stderr,
            "command": command,
            "command_original": record.get("command_original", command),
            "exec_cwd": exec_cwd,
            "root": root,
        }
        # Carry script fields into the done-record
        if rec_script is not None:
            done["script"] = rec_script
        if script_changed_during_run:
            done["script_changed_during_run"] = True
        # R3: record the exact argv that was executed
        done["exec_argv"] = argv_exec
        return done

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
