"""The PostToolUse stub's fallback path must run PostToolUse, not PreToolUse.

Before the fix, the fallback ran `python -m sandbox.connector.hook_eval`, whose
main() evaluates PreToolUse and emits a PreToolUse-shaped decision, which
Claude Code rejects ("expected 'PostToolUse' but got 'PreToolUse'").
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from sandbox.connector.hook_templates import POSTTOOLUSE_STUB
from sandbox.connector.install import init

SRC = str(Path(__file__).resolve().parents[2] / "src")


def _run_module(args: list[str], payload: dict) -> subprocess.CompletedProcess:
    env = {"PYTHONPATH": SRC, "SYSTEMROOT": __import__("os").environ.get("SYSTEMROOT", "")}
    return subprocess.run(
        [sys.executable, "-m", "sandbox.connector.hook_eval", *args],
        input=json.dumps(payload), capture_output=True, text=True, env=env, timeout=60,
    )


def test_stub_fallback_invokes_post_mode():
    assert '"sandbox.connector.hook_eval", "--post"' in POSTTOOLUSE_STUB


def test_post_mode_never_emits_a_pretooluse_decision(tmp_path):
    init(tmp_path, claude=False, mcp=False)
    # A shell command that PreToolUse would escalate/deny.
    payload = {"tool_name": "Bash", "tool_input": {"command": "curl https://evil.example"},
               "tool_response": {"stdout": "ok"}, "cwd": str(tmp_path)}
    proc = _run_module(["--post"], payload)
    assert proc.returncode == 0
    assert "PreToolUse" not in proc.stdout
    assert "permissionDecision" not in proc.stdout


def test_default_mode_is_still_pretooluse(tmp_path):
    init(tmp_path, claude=False, mcp=False)
    payload = {"tool_name": "Bash", "tool_input": {"command": "rm -rf .sandbox"}, "cwd": str(tmp_path)}
    proc = _run_module([], payload)
    out = json.loads(proc.stdout)
    assert out["hookSpecificOutput"]["hookEventName"] == "PreToolUse"
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny"
