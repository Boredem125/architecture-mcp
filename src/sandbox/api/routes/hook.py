"""Hook-based integration for Claude Code.

Instead of spawning a new agent, this intercepts the CURRENT Claude Code
instance's tool calls via its PreToolUse/PostToolUse hook system. Every
tool call gets evaluated through the 8-step sandbox pipeline.

Claude Code hook config calls our `/api/v1/hook/evaluate` endpoint before
each tool execution. If the pipeline denies it, the hook returns an error
that blocks the tool call.
"""
from __future__ import annotations

import json
import os
import time
import uuid
from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from sandbox.models.enums import ActionType
from sandbox.models.messages import ActionRequest
from sandbox.models.session import SessionStartRequest

# Claude Code settings files to patch (checked in order, first found wins)
_SETTINGS_CANDIDATES = [
    ".claude/settings.local.json",
    ".claude/settings.json",
]

router = APIRouter(prefix="/api/v1/hook", tags=["hook-integration"])

_hook_sessions: dict[str, dict[str, Any]] = {}

# Map Claude Code tool names to our ActionTypes
_TOOL_ACTION_MAP: dict[str, ActionType] = {
    "Read": ActionType.READ,
    "Glob": ActionType.READ,
    "Grep": ActionType.READ,
    "Edit": ActionType.WRITE,
    "Write": ActionType.WRITE,
    "NotebookEdit": ActionType.WRITE,
    "Bash": ActionType.EXECUTE,
    "PowerShell": ActionType.EXECUTE,
    "WebFetch": ActionType.NETWORK,
    "WebSearch": ActionType.NETWORK,
}


class HookEvaluateRequest(BaseModel):
    session_id: str
    tool_name: str
    tool_input: dict[str, Any] = {}


class HookConnectRequest(BaseModel):
    agent_name: str = "claude-code"
    workspace_root: str = ""
    capabilities: list[str] = ["READ", "WRITE", "EXECUTE"]
    max_writes: int = 100
    ttl_seconds: int = 3600


def _get_session_manager():
    from sandbox.api.app import get_session_manager
    return get_session_manager()


def _get_broadcaster():
    from sandbox.api.websocket import broadcaster
    return broadcaster


@router.post("/connect")
async def hook_connect(req: HookConnectRequest) -> dict:
    """Create a sandbox session for a Claude Code hook integration.

    Returns the session_id and hook configuration to install.
    """
    sm = _get_session_manager()
    broadcaster = _get_broadcaster()

    workspace = req.workspace_root or os.getcwd()
    allowed_actions = [ActionType(c) for c in req.capabilities]

    session = sm.create_session(
        SessionStartRequest(
            agent_id=f"claude-code-hook-{uuid.uuid4().hex[:8]}",
            declared_task="Claude Code (hooked) — live tool interception",
            allowed_actions=allowed_actions,
            workspace_root=workspace,
            max_writes=req.max_writes,
            ttl_seconds=req.ttl_seconds,
        )
    )

    _hook_sessions[session.session_id] = {
        "session_token": session.capability_token.signature,
        "agent_name": req.agent_name,
        "created_at": time.time(),
    }

    await broadcaster.broadcast({
        "event": "hook_connected",
        "session_id": session.session_id,
        "agent_id": session.agent_id,
        "agent_type": "claude-code-hook",
        "capabilities": req.capabilities,
    })

    hook_script = _generate_hook_script()
    hooks_json = _generate_hooks_config()

    # Auto-install: write the hook script, session config, and patch Claude Code settings
    auto_install_result = _auto_install(workspace, session.session_id, hook_script, hooks_json)

    return {
        "session_id": session.session_id,
        "agent_id": session.agent_id,
        "status": "connected",
        "capabilities": req.capabilities,
        "ttl_seconds": req.ttl_seconds,
        "hook_script": hook_script,
        "hooks_config": hooks_json,
        "auto_installed": auto_install_result["success"],
        "hook_script_path": auto_install_result.get("script_path"),
        "settings_path": auto_install_result.get("settings_path"),
        "install_instructions": auto_install_result["instructions"],
    }


@router.post("/evaluate")
async def hook_evaluate(req: HookEvaluateRequest) -> dict:
    """Evaluate a tool call through the sandbox pipeline.

    Called by Claude Code's PreToolUse hook before each tool execution.
    Returns {"decision": "ALLOW"} or {"decision": "DENY", "reason": "..."}.
    """
    sm = _get_session_manager()
    broadcaster = _get_broadcaster()

    session = sm.get_session(req.session_id)
    if session is None or not session.is_active:
        return {
            "decision": "NO_SESSION",
            "reason": "No active sandbox session — failing open",
            "action_type": _TOOL_ACTION_MAP.get(req.tool_name, ActionType.READ).value,
        }

    hook_data = _hook_sessions.get(req.session_id)
    if hook_data is None:
        return {
            "decision": "NO_SESSION",
            "reason": "Hook session not registered — failing open",
            "action_type": _TOOL_ACTION_MAP.get(req.tool_name, ActionType.READ).value,
        }

    action_type = _TOOL_ACTION_MAP.get(req.tool_name, ActionType.READ)

    action_request = ActionRequest(
        action_type=action_type,
        parameters={
            "tool": req.tool_name,
            **req.tool_input,
        },
        session_token=hook_data["session_token"],
    )

    from sandbox.pipeline.orchestrator import PipelineOrchestrator
    orchestrator = PipelineOrchestrator(
        session_manager=sm,
        event_broadcaster=broadcaster,
    )
    status = await orchestrator.process_request(action_request, session)

    return {
        "decision": status.decision or status.status,
        "reason": status.reason,
        "step": status.step_name,
        "request_id": status.request_id,
        "latency_ms": status.total_latency_ms,
        "action_type": action_type.value,
        "risk_tier": getattr(status, "risk_tier", None),
    }


@router.post("/audit")
async def hook_audit(body: dict) -> dict:
    """Log a PostToolUse event to the audit trail."""
    broadcaster = _get_broadcaster()
    await broadcaster.broadcast({
        "event": "hook_tool_completed",
        "session_id": body.get("session_id", ""),
        "tool": body.get("tool_name", ""),
        "exit_code": body.get("exit_code"),
    })
    return {"status": "logged"}


@router.get("/sessions")
async def list_hook_sessions() -> dict:
    sm = _get_session_manager()
    sessions = []
    for sid, data in _hook_sessions.items():
        session = sm.get_session(sid)
        if session and session.is_active:
            sessions.append({
                "session_id": sid,
                "agent_id": session.agent_id,
                "agent_name": data["agent_name"],
                "total_requests": session.total_requests,
                "deny_count": session.deny_count,
                "created_at": data["created_at"],
            })
    return {"count": len(sessions), "sessions": sessions}


@router.post("/disconnect/{session_id}")
async def hook_disconnect(session_id: str) -> dict:
    sm = _get_session_manager()
    from sandbox.models.enums import SessionEndReason
    from sandbox.models.session import SessionEndRequest
    summary = sm.end_session(SessionEndRequest(session_id=session_id, reason=SessionEndReason.DONE))
    _hook_sessions.pop(session_id, None)
    broadcaster = _get_broadcaster()
    await broadcaster.broadcast({
        "event": "hook_disconnected",
        "session_id": session_id,
    })
    return {"status": "disconnected", "session_id": session_id}


def _auto_install(workspace: str, session_id: str, hook_script: str, hooks_config: dict) -> dict:
    """Write sandbox_hook.py + sandbox_session.json and patch .claude/settings*.json."""
    workspace_path = Path(workspace)
    results: dict[str, Any] = {"success": False, "instructions": []}

    # 1. Write sandbox_hook.py (static — never changes, no session_id inside)
    script_path = workspace_path / "sandbox_hook.py"
    try:
        if not script_path.exists():
            script_path.write_text(hook_script, encoding="utf-8")
        results["script_path"] = str(script_path)
        results["instructions"].append(f"Hook script at {script_path}")
    except Exception as e:
        results["instructions"].append(f"Could not write hook script: {e}")
        return results

    # 2. Write sandbox_session.json — updated on every "Activate Sandbox"
    session_config_path = workspace_path / "sandbox_session.json"
    try:
        session_config_path.write_text(
            json.dumps({"session_id": session_id, "sandbox_url": "http://localhost:8000/api/v1/hook/evaluate"}, indent=2),
            encoding="utf-8",
        )
    except Exception as e:
        results["instructions"].append(f"Could not write session config: {e}")
        return results

    # 2. Find or create the Claude Code settings file
    settings_path: Path | None = None
    for candidate in _SETTINGS_CANDIDATES:
        p = workspace_path / candidate
        if p.exists():
            settings_path = p
            break
    if settings_path is None:
        # Create settings.local.json
        settings_path = workspace_path / ".claude" / "settings.local.json"
        settings_path.parent.mkdir(parents=True, exist_ok=True)

    # 3. Read existing settings (tolerate missing or malformed)
    existing: dict = {}
    if settings_path.exists():
        try:
            existing = json.loads(settings_path.read_text(encoding="utf-8"))
            if not isinstance(existing, dict):
                existing = {}
        except json.JSONDecodeError:
            existing = {}

    # 4. Merge PreToolUse hook — replace any existing sandbox hook entry
    hook_entry = {
        "matcher": ".*",
        "hooks": [
            {
                "type": "command",
                "command": f'python "{script_path}"',
            }
        ],
    }
    hooks_section = existing.setdefault("hooks", {})
    pre_tool_use: list = hooks_section.setdefault("PreToolUse", [])
    # Remove any previous sandbox hook entries, then prepend fresh one
    pre_tool_use[:] = [
        h for h in pre_tool_use
        if not any("sandbox_hook" in str(hook.get("command", "")) for hook in h.get("hooks", []))
    ]
    pre_tool_use.insert(0, hook_entry)

    # 5. Write back
    try:
        settings_path.write_text(json.dumps(existing, indent=2), encoding="utf-8")
        results["settings_path"] = str(settings_path)
        results["success"] = True
        results["instructions"].append(
            f"Patched {settings_path} — hook is now active. Restart Claude Code if it was already running."
        )
        results["instructions"].append("Every tool call now routes through the sandbox pipeline.")
        results["instructions"].append("Watch real-time activity on the Dashboard.")
    except Exception as e:
        results["instructions"].append(f"Could not patch settings: {e}")

    return results


def _generate_hook_script() -> str:
    """Generate the static hook script — reads tool call from stdin (Claude Code contract)."""
    return r'''#!/usr/bin/env python3
"""Sandbox hook for Claude Code — routes tool calls through the security pipeline.

Claude Code sends {"tool_name", "tool_input"} as JSON on stdin for PreToolUse hooks.
Session ID is read from sandbox_session.json at runtime, so re-activating the
sandbox from the UI automatically updates which session is enforced — no restart needed.

Decisions:
  ALLOW      — tool proceeds
  DENY       — exit 2, tool blocked (fail-closed)
  NO_SESSION — no active sandbox session, tool proceeds (fail-open with notice)
"""
import json, os, sys, urllib.request

_DIR = os.path.dirname(os.path.abspath(__file__))
_SESSION_FILE = os.path.join(_DIR, "sandbox_session.json")


def _load_session():
    try:
        with open(_SESSION_FILE, encoding="utf-8") as f:
            cfg = json.load(f)
        return cfg["session_id"], cfg.get("sandbox_url", "http://localhost:8000/api/v1/hook/evaluate")
    except Exception as e:
        print(f"SANDBOX: could not read session config ({e}) — failing open", file=sys.stderr)
        return "", ""


def _read_stdin():
    """Read tool call JSON from stdin (Claude Code hook contract)."""
    try:
        raw = sys.stdin.read()
        if raw.strip():
            data = json.loads(raw)
            return data.get("tool_name", ""), data.get("tool_input", {})
    except Exception:
        pass
    return "", {}


def _extract_tool_input(tool_name, tool_input):
    """Extract meaningful parameters per tool type for pipeline evaluation."""
    if tool_name in ("Read", "Glob", "Grep"):
        return {"path": tool_input.get("file_path") or tool_input.get("path", ""),
                "pattern": tool_input.get("pattern", "")}
    if tool_name in ("Edit", "Write"):
        return {"path": tool_input.get("file_path", ""),
                "content_length": len(tool_input.get("content", ""))}
    if tool_name in ("Bash", "PowerShell"):
        return {"command": tool_input.get("command", "")}
    if tool_name == "NotebookEdit":
        return {"path": tool_input.get("notebook_path", "")}
    if tool_name in ("WebFetch", "WebSearch"):
        return {"url": tool_input.get("url", ""), "query": tool_input.get("query", "")}
    return tool_input


def evaluate(tool_name, tool_input):
    session_id, sandbox_url = _load_session()
    if not session_id:
        return

    mapped_input = _extract_tool_input(tool_name, tool_input)

    payload = json.dumps({
        "session_id": session_id,
        "tool_name": tool_name,
        "tool_input": mapped_input,
    }).encode()

    req = urllib.request.Request(
        sandbox_url,
        data=payload,
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            result = json.loads(resp.read())
            decision = result.get("decision", "")
            if decision == "DENY":
                print(f"SANDBOX DENIED: {result.get('reason', 'Policy violation')}", file=sys.stderr)
                sys.exit(2)
            elif decision == "NO_SESSION":
                print(f"SANDBOX: {result.get('reason', 'No active session')} — tool allowed", file=sys.stderr)
    except Exception as e:
        print(f"SANDBOX ERROR: {e} — failing open", file=sys.stderr)


if __name__ == "__main__":
    tool_name, tool_input = _read_stdin()
    if not tool_name and len(sys.argv) >= 3 and sys.argv[1] == "evaluate":
        tool_name = sys.argv[2]
        try:
            tool_input = json.loads(sys.argv[3]) if len(sys.argv) > 3 else {}
        except json.JSONDecodeError:
            tool_input = {"raw": sys.argv[3]} if len(sys.argv) > 3 else {}
    if tool_name:
        evaluate(tool_name, tool_input if isinstance(tool_input, dict) else {})
'''


def _generate_hooks_config() -> dict:
    """Generate the hooks.json config for Claude Code (stdin contract)."""
    return {
        "hooks": {
            "PreToolUse": [
                {
                    "matcher": ".*",
                    "hooks": [
                        {
                            "type": "command",
                            "command": "python sandbox_hook.py",
                        }
                    ],
                }
            ]
        }
    }
