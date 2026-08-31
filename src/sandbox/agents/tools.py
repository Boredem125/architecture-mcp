"""Sandboxed tool definitions for AI agents.

Each tool maps to an ActionType and goes through the full 8-step pipeline
before execution. The agent SDK receives these as callable tools — from
the agent's perspective, it's just calling file_read() or shell_exec(),
but every call is intercepted, evaluated, and audited.
"""
from __future__ import annotations

import asyncio
import os
import subprocess
import time
from pathlib import Path
from typing import Any

import structlog

from sandbox.models.enums import ActionType, ExecutionResult
from sandbox.models.messages import ActionRequest, PipelineStatus
from sandbox.models.session import SessionState
from sandbox.pipeline.orchestrator import PipelineOrchestrator

if __import__("typing").TYPE_CHECKING:
    from sandbox.containment.docker_sandbox import DockerSandbox

logger = structlog.get_logger()

# Maximum bytes to return from file reads or command output
_MAX_OUTPUT_BYTES = 100_000
_MAX_WRITE_BYTES = 500_000


class SandboxedToolkit:
    """Tools that route through the sandbox pipeline before executing.

    Each tool:
    1. Builds an ActionRequest with the appropriate ActionType
    2. Submits it to the PipelineOrchestrator
    3. If ALLOW: executes the action in a restricted context
    4. If DENY: returns the denial reason to the agent

    When a DockerSandbox is provided, file and shell operations execute
    inside the container instead of on the host — pipeline = decision,
    container = execution.
    """

    def __init__(
        self,
        session: SessionState,
        orchestrator: PipelineOrchestrator,
        workspace_root: str = "/tmp/workspace",
        event_broadcaster: Any = None,
        sandbox: DockerSandbox | None = None,
    ) -> None:
        self._session = session
        self._orchestrator = orchestrator
        self._workspace_root = os.path.abspath(workspace_root)
        self._broadcaster = event_broadcaster
        self._sandbox = sandbox

    def _validate_path(self, path: str) -> tuple[bool, str]:
        """Ensure path is within workspace root. Prevents path traversal."""
        from sandbox.fs.containment import resolve_under

        resolved = resolve_under(self._workspace_root, path)
        if resolved is None:
            return False, f"Path traversal blocked: {path} resolves outside workspace"
        return True, str(resolved)

    async def execute_tool(self, tool_name: str, tool_input: dict[str, Any]) -> dict[str, Any]:
        """Execute a tool call through the sandbox pipeline."""
        tool_map = {
            "file_read": self._tool_file_read,
            "file_write": self._tool_file_write,
            "file_list": self._tool_file_list,
            "shell_exec": self._tool_shell_exec,
            "http_request": self._tool_http_request,
        }

        handler = tool_map.get(tool_name)
        if handler is None:
            return {"status": "error", "error": f"Unknown tool: {tool_name}"}

        return await handler(tool_input)

    # ------------------------------------------------------------------
    # Pipeline submission
    # ------------------------------------------------------------------

    async def _submit_to_pipeline(
        self,
        action_type: ActionType,
        parameters: dict[str, Any],
    ) -> PipelineStatus:
        request = ActionRequest(
            action_type=action_type,
            parameters=parameters,
            session_token=self._session.capability_token.signature,
        )
        return await self._orchestrator.process_request(request, self._session)

    # ------------------------------------------------------------------
    # Tool: file_read
    # ------------------------------------------------------------------

    async def _tool_file_read(self, input: dict[str, Any]) -> dict[str, Any]:
        path = input.get("path", "")
        valid, resolved = self._validate_path(path)
        if not valid:
            return {"status": "denied", "error": resolved, "pipeline_decision": "DENY"}

        status = await self._submit_to_pipeline(
            ActionType.READ,
            {"path": resolved, "tool": "file_read"},
        )

        if status.decision != "ALLOW":
            return {
                "status": "denied",
                "error": status.reason or "Pipeline denied this action",
                "pipeline_decision": status.decision,
                "pipeline_step": status.step_name,
            }

        try:
            if self._sandbox is not None:
                data = await self._sandbox.read_file(path)
                if data is None:
                    return {"status": "error", "error": f"File not found: {path}", "pipeline_decision": "ALLOW"}
                content = data.decode("utf-8", errors="replace")[:_MAX_OUTPUT_BYTES]
            else:
                if not os.path.exists(resolved):
                    return {"status": "error", "error": f"File not found: {path}", "pipeline_decision": "ALLOW"}
                with open(resolved, "r", encoding="utf-8", errors="replace") as f:
                    content = f.read(_MAX_OUTPUT_BYTES)
            return {
                "status": "success",
                "output": content,
                "pipeline_decision": "ALLOW",
                "bytes_read": len(content),
            }
        except Exception as e:
            return {"status": "error", "error": str(e), "pipeline_decision": "ALLOW"}

    # ------------------------------------------------------------------
    # Tool: file_write
    # ------------------------------------------------------------------

    async def _tool_file_write(self, input: dict[str, Any]) -> dict[str, Any]:
        path = input.get("path", "")
        content = input.get("content", "")

        valid, resolved = self._validate_path(path)
        if not valid:
            return {"status": "denied", "error": resolved, "pipeline_decision": "DENY"}

        if len(content.encode("utf-8")) > _MAX_WRITE_BYTES:
            return {"status": "denied", "error": f"Content exceeds max write size ({_MAX_WRITE_BYTES} bytes)", "pipeline_decision": "DENY"}

        status = await self._submit_to_pipeline(
            ActionType.WRITE,
            {"path": resolved, "tool": "file_write", "content_length": len(content)},
        )

        if status.decision != "ALLOW":
            return {
                "status": "denied",
                "error": status.reason or "Pipeline denied this action",
                "pipeline_decision": status.decision,
                "pipeline_step": status.step_name,
            }

        try:
            if self._sandbox is not None:
                ok = await self._sandbox.write_file(path, content.encode("utf-8"))
                if not ok:
                    return {"status": "error", "error": f"Failed to write {path} in container", "pipeline_decision": "ALLOW"}
            else:
                os.makedirs(os.path.dirname(resolved), exist_ok=True)
                with open(resolved, "w", encoding="utf-8") as f:
                    f.write(content)
            return {
                "status": "success",
                "output": f"Written {len(content)} bytes to {path}",
                "pipeline_decision": "ALLOW",
                "bytes_written": len(content),
            }
        except Exception as e:
            return {"status": "error", "error": str(e), "pipeline_decision": "ALLOW"}

    # ------------------------------------------------------------------
    # Tool: file_list
    # ------------------------------------------------------------------

    async def _tool_file_list(self, input: dict[str, Any]) -> dict[str, Any]:
        path = input.get("path", ".")

        valid, resolved = self._validate_path(path)
        if not valid:
            return {"status": "denied", "error": resolved, "pipeline_decision": "DENY"}

        status = await self._submit_to_pipeline(
            ActionType.READ,
            {"path": resolved, "tool": "file_list"},
        )

        if status.decision != "ALLOW":
            return {
                "status": "denied",
                "error": status.reason or "Pipeline denied this action",
                "pipeline_decision": status.decision,
            }

        try:
            if self._sandbox is not None:
                file_infos = await self._sandbox.list_dir(path)
                entries = [{"name": fi.name, "type": fi.type, "size": fi.size} for fi in file_infos[:500]]
            else:
                if not os.path.isdir(resolved):
                    return {"status": "error", "error": f"Not a directory: {path}", "pipeline_decision": "ALLOW"}
                entries = []
                for entry in os.scandir(resolved):
                    entries.append({
                        "name": entry.name,
                        "type": "dir" if entry.is_dir() else "file",
                        "size": entry.stat().st_size if entry.is_file() else 0,
                    })
                    if len(entries) >= 500:
                        break
            return {
                "status": "success",
                "output": entries,
                "pipeline_decision": "ALLOW",
                "entry_count": len(entries),
            }
        except Exception as e:
            return {"status": "error", "error": str(e), "pipeline_decision": "ALLOW"}

    # ------------------------------------------------------------------
    # Tool: shell_exec
    # ------------------------------------------------------------------

    async def _tool_shell_exec(self, input: dict[str, Any]) -> dict[str, Any]:
        command = input.get("command", "")
        timeout = min(input.get("timeout", 30), 120)

        if not command.strip():
            return {"status": "error", "error": "Empty command", "pipeline_decision": "DENY"}

        status = await self._submit_to_pipeline(
            ActionType.EXECUTE,
            {"command": command, "tool": "shell_exec", "timeout": timeout},
        )

        if status.decision != "ALLOW":
            return {
                "status": "denied",
                "error": status.reason or "Pipeline denied this action",
                "pipeline_decision": status.decision,
                "pipeline_step": status.step_name,
            }

        try:
            if self._sandbox is not None:
                result = await self._sandbox.exec(command, timeout=timeout)
                return {
                    "status": "success" if result.exit_code == 0 else "error",
                    "output": result.stdout[:_MAX_OUTPUT_BYTES],
                    "stderr": result.stderr[:_MAX_OUTPUT_BYTES],
                    "exit_code": result.exit_code,
                    "pipeline_decision": "ALLOW",
                    "containment": "docker",
                }
            else:
                env = _sanitized_env()
                proc = await asyncio.create_subprocess_shell(
                    command,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    cwd=self._workspace_root,
                    env=env,
                )
                try:
                    stdout_bytes, stderr_bytes = await asyncio.wait_for(
                        proc.communicate(), timeout=timeout
                    )
                except asyncio.TimeoutError:
                    proc.kill()
                    return {
                        "status": "timeout",
                        "error": f"Command timed out after {timeout}s",
                        "pipeline_decision": "ALLOW",
                    }

                stdout = (stdout_bytes or b"").decode("utf-8", errors="replace")[:_MAX_OUTPUT_BYTES]
                stderr = (stderr_bytes or b"").decode("utf-8", errors="replace")[:_MAX_OUTPUT_BYTES]

                return {
                    "status": "success" if proc.returncode == 0 else "error",
                    "output": stdout,
                    "stderr": stderr,
                    "exit_code": proc.returncode,
                    "pipeline_decision": "ALLOW",
                }
        except Exception as e:
            return {"status": "error", "error": str(e), "pipeline_decision": "ALLOW"}

    # ------------------------------------------------------------------
    # Tool: http_request
    # ------------------------------------------------------------------

    async def _tool_http_request(self, input: dict[str, Any]) -> dict[str, Any]:
        url = input.get("url", "")
        method = input.get("method", "GET").upper()

        status = await self._submit_to_pipeline(
            ActionType.NETWORK,
            {"url": url, "method": method, "tool": "http_request"},
        )

        if status.decision != "ALLOW":
            return {
                "status": "denied",
                "error": status.reason or "Pipeline denied this action",
                "pipeline_decision": status.decision,
            }

        try:
            import httpx
            async with httpx.AsyncClient(timeout=30) as client:
                response = await client.request(
                    method, url,
                    json=input.get("body"),
                    headers=input.get("headers", {}),
                )
            body = response.text[:_MAX_OUTPUT_BYTES]
            return {
                "status": "success",
                "output": body,
                "status_code": response.status_code,
                "pipeline_decision": "ALLOW",
            }
        except Exception as e:
            return {"status": "error", "error": str(e), "pipeline_decision": "ALLOW"}

    # ------------------------------------------------------------------
    # Tool definitions for Anthropic SDK
    # ------------------------------------------------------------------

    def get_anthropic_tool_definitions(self) -> list[dict[str, Any]]:
        tools = [
            {
                "name": "file_read",
                "description": "Read the contents of a file. Path is relative to the workspace root.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string", "description": "File path relative to workspace root"},
                    },
                    "required": ["path"],
                },
            },
            {
                "name": "file_list",
                "description": "List files and directories at the given path.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string", "description": "Directory path relative to workspace root. Defaults to '.'"},
                    },
                },
            },
        ]

        allowed = [a.value for a in self._session.capability_token.allowed_actions]

        if "WRITE" in allowed:
            tools.append({
                "name": "file_write",
                "description": "Write content to a file. Creates parent directories if needed.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string", "description": "File path relative to workspace root"},
                        "content": {"type": "string", "description": "Content to write"},
                    },
                    "required": ["path", "content"],
                },
            })

        if "EXECUTE" in allowed:
            tools.append({
                "name": "shell_exec",
                "description": "Execute a shell command in the workspace directory. Output is captured.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "command": {"type": "string", "description": "Shell command to execute"},
                        "timeout": {"type": "integer", "description": "Timeout in seconds (max 120)", "default": 30},
                    },
                    "required": ["command"],
                },
            })

        if "NETWORK" in allowed:
            tools.append({
                "name": "http_request",
                "description": "Make an HTTP request to an allowed host.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "url": {"type": "string", "description": "The URL to request"},
                        "method": {"type": "string", "description": "HTTP method", "default": "GET"},
                        "body": {"type": "object", "description": "JSON body for POST/PUT"},
                        "headers": {"type": "object", "description": "Request headers"},
                    },
                    "required": ["url"],
                },
            })

        return tools

    # ------------------------------------------------------------------
    # Tool definitions for OpenAI SDK
    # ------------------------------------------------------------------

    def get_openai_tool_definitions(self) -> list[dict[str, Any]]:
        anthropic_tools = self.get_anthropic_tool_definitions()
        return [
            {
                "type": "function",
                "function": {
                    "name": t["name"],
                    "description": t["description"],
                    "parameters": t["input_schema"],
                },
            }
            for t in anthropic_tools
        ]


# Secret-stripping environment for subprocesses
_SECRET_PATTERNS = {"KEY", "SECRET", "TOKEN", "PASSWORD", "CREDENTIAL"}


def _sanitized_env() -> dict[str, str]:
    env = {}
    for k, v in os.environ.items():
        upper = k.upper()
        if any(p in upper for p in _SECRET_PATTERNS):
            continue
        if upper.startswith(("AWS_", "AZURE_", "GCP_", "GITHUB_", "ANTHROPIC_", "OPENAI_")):
            continue
        env[k] = v
    return env
