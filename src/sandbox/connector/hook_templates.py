"""Stdlib-only hook stubs written into ``.sandbox/hooks/``.

The stub carries no policy and is never regenerated — it only reads stdin,
locates ``.sandbox/``, and delegates to ``sandbox.connector.hook_eval``. The
delegation ladder: in-process import (fast) → subprocess with the captured
interpreter → fail-closed. ``session.json`` supplies the absolute python and
``package_src`` so the stub works even when ``python`` on PATH is a Store shim.
"""
from __future__ import annotations

PRETOOLUSE_STUB = r'''#!/usr/bin/env python3
"""Sandbox connector PreToolUse hook (stub — do not edit; logic lives in the package)."""
import json
import os
import subprocess
import sys


def _find_sandbox(start):
    cur = os.path.abspath(start)
    while True:
        if os.path.isdir(os.path.join(cur, ".sandbox")):
            return cur
        parent = os.path.dirname(cur)
        if parent == cur:
            return None
        cur = parent


def _fail_closed(msg):
    sys.stderr.write("SANDBOX: %s (fail-closed)" % msg)
    sys.stderr.flush()
    sys.exit(2)


def main():
    raw = sys.stdin.read()
    try:
        payload = json.loads(raw) if raw.strip() else {}
    except Exception:
        payload = {}

    cwd = payload.get("cwd") or os.getcwd()
    root = _find_sandbox(cwd) or _find_sandbox(os.path.dirname(os.path.abspath(__file__)))
    if root is None:
        # No sandbox — do nothing, let the agent proceed.
        sys.exit(0)

    session_path = os.path.join(root, ".sandbox", "session.json")
    session = {}
    try:
        with open(session_path, "r", encoding="utf-8") as fh:
            session = json.load(fh)
    except Exception:
        session = {}

    package_src = session.get("package_src")
    python = session.get("python") or sys.executable

    # 1) in-process import (fastest)
    try:
        if package_src and package_src not in sys.path:
            sys.path.insert(0, package_src)
        import asyncio
        from sandbox.connector.hook_eval import pre_tool_use
        from sandbox.connector.layout import FolderLayout
        layout = FolderLayout(root)
        result = asyncio.run(pre_tool_use(payload, layout))
        sys.stdout.write(json.dumps(result))
        sys.stdout.flush()
        sys.exit(0)
    except Exception:
        pass

    # 2) subprocess fallback with the captured interpreter
    try:
        env = dict(os.environ)
        if package_src:
            existing = env.get("PYTHONPATH", "")
            env["PYTHONPATH"] = package_src + (os.pathsep + existing if existing else "")
        proc = subprocess.run(
            [python, "-m", "sandbox.connector.hook_eval"],
            input=raw, capture_output=True, text=True, env=env, timeout=120,
        )
        if proc.stdout:
            sys.stdout.write(proc.stdout)
            sys.stdout.flush()
        sys.exit(proc.returncode)
    except Exception as exc:
        # 3) fail closed
        _fail_closed("cannot evaluate hook: %s" % exc)


if __name__ == "__main__":
    main()
'''


POSTTOOLUSE_STUB = r'''#!/usr/bin/env python3
"""Sandbox connector PostToolUse hook (stub — do not edit; logic lives in the package)."""
import json
import os
import subprocess
import sys


def _find_sandbox(start):
    cur = os.path.abspath(start)
    while True:
        if os.path.isdir(os.path.join(cur, ".sandbox")):
            return cur
        parent = os.path.dirname(cur)
        if parent == cur:
            return None
        cur = parent


def _fail_closed(msg):
    sys.stderr.write("SANDBOX: %s (fail-closed)" % msg)
    sys.stderr.flush()
    sys.exit(2)


def main():
    raw = sys.stdin.read()
    try:
        payload = json.loads(raw) if raw.strip() else {}
    except Exception:
        payload = {}

    cwd = payload.get("cwd") or os.getcwd()
    root = _find_sandbox(cwd) or _find_sandbox(os.path.dirname(os.path.abspath(__file__)))
    if root is None:
        sys.exit(0)

    session_path = os.path.join(root, ".sandbox", "session.json")
    session = {}
    try:
        with open(session_path, "r", encoding="utf-8") as fh:
            session = json.load(fh)
    except Exception:
        session = {}

    package_src = session.get("package_src")
    python = session.get("python") or sys.executable

    try:
        if package_src and package_src not in sys.path:
            sys.path.insert(0, package_src)
        import asyncio
        from sandbox.connector.hook_eval import post_tool_use
        from sandbox.connector.layout import FolderLayout
        layout = FolderLayout(root)
        result = asyncio.run(post_tool_use(payload, layout))
        if result:
            sys.stdout.write(json.dumps(result))
            sys.stdout.flush()
        sys.exit(0)
    except Exception:
        pass

    try:
        env = dict(os.environ)
        if package_src:
            existing = env.get("PYTHONPATH", "")
            env["PYTHONPATH"] = package_src + (os.pathsep + existing if existing else "")
        proc = subprocess.run(
            [python, "-m", "sandbox.connector.hook_eval"],
            input=raw, capture_output=True, text=True, env=env, timeout=120,
        )
        if proc.stdout:
            sys.stdout.write(proc.stdout)
            sys.stdout.flush()
        sys.exit(proc.returncode)
    except Exception as exc:
        _fail_closed("cannot evaluate hook: %s" % exc)


if __name__ == "__main__":
    main()
'''


SESSIONSTART_STUB = r'''#!/usr/bin/env python3
"""Sandbox connector SessionStart hook — injects sandbox awareness into context.

The highest-leverage tokens in the system: one paragraph telling the agent the
sandbox is active and which tools exist prevents ~5 blocked calls per session.
Never fails the session — on any error it stays silent (exit 0, no output).
"""
import json
import os
import sys


def _find_sandbox(start):
    cur = os.path.abspath(start)
    while True:
        if os.path.isdir(os.path.join(cur, ".sandbox")):
            return cur
        parent = os.path.dirname(cur)
        if parent == cur:
            return None
        cur = parent


def main():
    raw = sys.stdin.read()
    try:
        payload = json.loads(raw) if raw.strip() else {}
    except Exception:
        payload = {}

    cwd = payload.get("cwd") or os.getcwd()
    root = _find_sandbox(cwd) or _find_sandbox(os.path.dirname(os.path.abspath(__file__)))
    if root is None:
        sys.exit(0)

    session_path = os.path.join(root, ".sandbox", "session.json")
    session = {}
    try:
        with open(session_path, "r", encoding="utf-8") as fh:
            session = json.load(fh)
    except Exception:
        session = {}

    package_src = session.get("package_src")
    try:
        if package_src and package_src not in sys.path:
            sys.path.insert(0, package_src)
        from sandbox.connector.hook_eval import session_start_context
        from sandbox.connector.layout import FolderLayout
        context = session_start_context(FolderLayout(root))
    except Exception:
        # Fallback minimal message if the package can't be imported.
        context = (
            "A sandbox connector is active in this folder. Privileged shell "
            "commands are escalated to a human approver; their output is "
            "returned to you. Do not try to bypass it."
        )

    out = {
        "hookSpecificOutput": {
            "hookEventName": "SessionStart",
            "additionalContext": context,
        }
    }
    sys.stdout.write(json.dumps(out))
    sys.stdout.flush()
    sys.exit(0)


if __name__ == "__main__":
    main()
'''
