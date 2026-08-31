#!/usr/bin/env python3
"""Sandbox hook for Claude Code — routes tool calls through the security pipeline.

Claude Code sends hook data via stdin as JSON:
  {"tool_name": "Edit", "tool_input": {...}}

Session ID is read from sandbox_session.json at runtime — re-activating the
sandbox from the UI automatically updates which session is enforced.
"""
import json
import os
import sys
import urllib.request

_DIR = os.path.dirname(os.path.abspath(__file__))
_SESSION_FILE = os.path.join(_DIR, "sandbox_session.json")


def _load_session() -> tuple[str, str]:
    try:
        with open(_SESSION_FILE, encoding="utf-8") as f:
            cfg = json.load(f)
        return cfg["session_id"], cfg.get("sandbox_url", "http://localhost:8000/api/v1/hook/evaluate")
    except Exception as e:
        print(f"SANDBOX: could not read session config ({e})", file=sys.stderr)
        return "", ""


def evaluate(tool_name: str, tool_input: dict) -> None:
    session_id, sandbox_url = _load_session()
    if not session_id:
        return  # No active session

    payload = json.dumps({
        "session_id": session_id,
        "tool_name": tool_name,
        "tool_input": tool_input,
    }).encode()

    req = urllib.request.Request(
        sandbox_url,
        data=payload,
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            result = json.loads(resp.read())
            if result.get("decision") == "DENY":
                # Exit code 2 tells Claude Code to block the tool call
                print(f"SANDBOX DENIED: {result.get('reason', 'Policy violation')}", file=sys.stderr)
                sys.exit(2)
    except urllib.error.URLError as e:
        # Backend unreachable — fail CLOSED (block the action)
        print(f"SANDBOX UNREACHABLE: {e} — blocking action", file=sys.stderr)
        sys.exit(2)
    except Exception as e:
        print(f"SANDBOX ERROR: {e} — blocking action", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    # Claude Code sends hook data via stdin as JSON
    try:
        data = json.loads(sys.stdin.read())
        tool_name = data.get("tool_name", "")
        tool_input = data.get("tool_input", {})
    except Exception:
        # Fallback: read from command-line args (for manual testing)
        if len(sys.argv) >= 3 and sys.argv[1] == "evaluate":
            tool_name = sys.argv[2]
            try:
                tool_input = json.loads(sys.argv[3]) if len(sys.argv) > 3 else {}
            except json.JSONDecodeError:
                tool_input = {}
        else:
            sys.exit(0)

    evaluate(tool_name, tool_input)
