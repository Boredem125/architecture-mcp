"""Stdlib-only hook stubs written into ``.sandbox/hooks/``.

The stub carries no policy (``sandbox init`` rewrites it each run) — it only reads stdin,
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

_BOOT = (
    "import os, sys\n"
    "src = os.path.realpath(sys.argv[1])\n"
    "sys.path.insert(0, src)\n"
    "import sandbox\n"
    "f = os.path.normcase(os.path.realpath(sandbox.__file__))\n"
    "if not f.startswith(os.path.normcase(src) + os.sep):\n"
    "    sys.stderr.write('SANDBOX: package origin mismatch (fail-closed)')\n"
    "    sys.exit(2)\n"
    "from sandbox.connector import hook_eval\n"
    "sys.exit(hook_eval.main(sys.argv[2:]))\n"
)


def _verify_origin(package_src):
    """Exit 2 unless the imported `sandbox` package lives under package_src."""
    import sandbox
    src = os.path.normcase(os.path.realpath(package_src)) + os.sep
    if not os.path.normcase(os.path.realpath(sandbox.__file__)).startswith(src):
        _fail_closed("package origin mismatch")


def _prepend_trusted(package_src):
    """Put the trusted package dir first on sys.path (cwd/script dir never trusted)."""
    sys.path[:] = [p for p in sys.path if p != package_src]
    sys.path.insert(0, package_src)


def main():
    raw = sys.stdin.read()
    # Parsed only to locate .sandbox/. Malformed input is judged by the
    # package (pre_tool_use_raw), which denies it: the stub never allows.
    try:
        payload = json.loads(raw) if raw.strip() else {}
    except Exception:
        payload = {}
    if not isinstance(payload, dict):
        payload = {}

    cwd = payload.get("cwd") or os.getcwd()
    if not isinstance(cwd, str):
        cwd = os.getcwd()
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
        if package_src:
            _prepend_trusted(package_src)
        import asyncio
        from sandbox.connector.hook_eval import pre_tool_use_raw
        from sandbox.connector.layout import FolderLayout
        if package_src:
            _verify_origin(package_src)
        layout = FolderLayout(root)
        result = asyncio.run(pre_tool_use_raw(raw, layout))
        sys.stdout.write(json.dumps(result))
        sys.stdout.flush()
        sys.exit(0)
    except Exception:
        pass

    # 2) subprocess fallback: isolated launch (-I: no cwd/script dir on sys.path),
    #    the package must come from package_src, and only rc 0 + a well-formed
    #    PreToolUse JSON (or rc 2) is passed on. Everything else is exit 2.
    if not package_src or not os.path.isabs(python):
        _fail_closed("cannot evaluate hook: no trusted interpreter/package")
    try:
        env = dict(os.environ)
        env["PYTHONPATH"] = package_src
        proc = subprocess.run(
            [python, "-I", "-c", _BOOT, package_src, "sandbox.connector.hook_eval"],
            input=raw, capture_output=True, text=True, env=env, timeout=120,
        )
    except Exception as exc:
        # 3) fail closed
        _fail_closed("cannot evaluate hook: %s" % exc)
    if proc.returncode == 0:
        try:
            out = json.loads(proc.stdout)
            hso = out["hookSpecificOutput"]
            ok = isinstance(hso, dict) and hso.get("hookEventName") == "PreToolUse"
        except Exception:
            ok = False
        if ok:
            sys.stdout.write(proc.stdout)
            sys.stdout.flush()
            sys.exit(0)
    if proc.stdout and proc.returncode == 2:
        sys.stdout.write(proc.stdout)
    sys.stderr.write(proc.stderr or "")
    _fail_closed("hook evaluator failed (rc %s)" % proc.returncode)


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

_BOOT = (
    "import os, sys\n"
    "src = os.path.realpath(sys.argv[1])\n"
    "sys.path.insert(0, src)\n"
    "import sandbox\n"
    "f = os.path.normcase(os.path.realpath(sandbox.__file__))\n"
    "if not f.startswith(os.path.normcase(src) + os.sep):\n"
    "    sys.stderr.write('SANDBOX: package origin mismatch (fail-closed)')\n"
    "    sys.exit(2)\n"
    "from sandbox.connector import hook_eval\n"
    "sys.exit(hook_eval.main(sys.argv[2:]))\n"
)


def _verify_origin(package_src):
    """Exit 2 unless the imported `sandbox` package lives under package_src."""
    import sandbox
    src = os.path.normcase(os.path.realpath(package_src)) + os.sep
    if not os.path.normcase(os.path.realpath(sandbox.__file__)).startswith(src):
        _fail_closed("package origin mismatch")


def _prepend_trusted(package_src):
    """Put the trusted package dir first on sys.path (cwd/script dir never trusted)."""
    sys.path[:] = [p for p in sys.path if p != package_src]
    sys.path.insert(0, package_src)


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
        if package_src:
            _prepend_trusted(package_src)
        import asyncio
        from sandbox.connector.hook_eval import post_tool_use
        from sandbox.connector.layout import FolderLayout
        if package_src:
            _verify_origin(package_src)
        layout = FolderLayout(root)
        result = asyncio.run(post_tool_use(payload, layout))
        if result:
            sys.stdout.write(json.dumps(result))
            sys.stdout.flush()
        sys.exit(0)
    except Exception:
        pass

    if not package_src or not os.path.isabs(python):
        _fail_closed("cannot evaluate hook: no trusted interpreter/package")
    try:
        env = dict(os.environ)
        env["PYTHONPATH"] = package_src
        proc = subprocess.run(
            [python, "-I", "-c", _BOOT, package_src, "sandbox.connector.hook_eval", "--post"],
            input=raw, capture_output=True, text=True, env=env, timeout=120,
        )
        if proc.stdout:
            sys.stdout.write(proc.stdout)
            sys.stdout.flush()
        sys.stderr.write(proc.stderr or "")
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
