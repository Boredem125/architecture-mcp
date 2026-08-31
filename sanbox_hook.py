#!/usr/bin/env python3
"""Sandbox hook for Claude Code — routes tool calls through the security pipeline."""
import json, sys, urllib.request

SANDBOX_URL = "http://localhost:8000/api/v1/hook/evaluate"
SESSION_ID = "2ba97ab8-167e-46a5-bcdc-f25e962bed2e"

def evaluate(tool_name: str, tool_input_json: str = "{}") -> None:
    try:
        tool_input = json.loads(tool_input_json) if tool_input_json else {}
    except json.JSONDecodeError:
        tool_input = {"raw": tool_input_json}

    payload = json.dumps({
        "session_id": SESSION_ID,
        "tool_name": tool_name,
        "tool_input": tool_input,
    }).encode()

    req = urllib.request.Request(
        SANDBOX_URL,
        data=payload,
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            result = json.loads(resp.read())
            if result.get("decision") == "DENY":
                print(f"SANDBOX DENIED: {result.get('reason', 'Policy violation')}", file=sys.stderr)
                sys.exit(2)
    except Exception as e:
        print(f"SANDBOX ERROR: {e} — failing open", file=sys.stderr)

if __name__ == "__main__":
    if len(sys.argv) >= 3 and sys.argv[1] == "evaluate":
        tool = sys.argv[2]
        inp = sys.argv[3] if len(sys.argv) > 3 else "{}"
        evaluate(tool, inp)
