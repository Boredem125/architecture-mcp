"""Jailed demo agent — runs when a chosen CLI isn't installed on this machine.

This is NOT a fake of any AI product. It is a small real process that runs
*inside the same jail, Job Object, and streaming pipeline* a real CLI would,
so the sandbox (jailed launch + live streaming + broker + change recording)
is demonstrable end-to-end on a machine with none of the AI CLIs installed.

It reads its context from the SANDBOX_* env vars the launcher injects,
identifies itself clearly as a fallback, writes a file inside the jail
(so it shows up in modified.txt), and exits. Everything it prints streams
live to the UI exactly like a real app's output.
"""
from __future__ import annotations

import os
import sys
import time
from pathlib import Path


def _emit(line: str) -> None:
    print(line, flush=True)
    time.sleep(0.15)  # small pacing so the live stream is visibly incremental


def main() -> int:
    app_type = os.environ.get("SANDBOX_APP_TYPE", "unknown")
    display = os.environ.get("SANDBOX_APP_DISPLAY", app_type)
    jail_dir = os.environ.get("SANDBOX_JAIL_DIR", os.getcwd())
    run_id = os.environ.get("SANDBOX_RUN_ID", "?")
    session_id = os.environ.get("SANDBOX_SESSION_ID", "?")
    task = os.environ.get("SANDBOX_TASK", "")

    _emit(f"[sandbox] Jailed demo agent for '{display}' ({app_type})")
    _emit(f"[sandbox] The real '{display}' CLI is not installed on this host,")
    _emit("[sandbox] so a jailed demo process is running in its place.")
    _emit(f"[sandbox] run_id={run_id} session_id={session_id}")
    _emit(f"[sandbox] jail={jail_dir}")
    if task:
        _emit(f"[sandbox] task: {task}")

    _emit("")
    _emit("[agent] Inspecting my jail (I can only see inside this folder)...")
    jail = Path(jail_dir)
    try:
        entries = sorted(p.name for p in jail.iterdir())
        _emit(f"[agent] jail contents: {entries or '(empty)'}")
    except OSError as exc:
        _emit(f"[agent] could not list jail: {exc}")

    _emit("[agent] Writing a work file inside the jail...")
    out = jail / "demo_agent_output.txt"
    try:
        out.write_text(
            f"Demo agent for {display} ({app_type})\n"
            f"run_id={run_id}\nsession_id={session_id}\n"
            f"task={task}\nwritten_at={time.time()}\n",
            encoding="utf-8",
        )
        _emit(f"[agent] wrote {out.name} ({out.stat().st_size} bytes)")
    except OSError as exc:
        _emit(f"[agent] write failed (jail may be read-only): {exc}")

    _emit("")
    _emit("[agent] If I needed PowerShell or access outside this folder,")
    _emit("[agent] the request would route to the privilege broker for a")
    _emit("[agent] human to approve — the agent never gets root directly.")
    _emit("")
    _emit("[sandbox] Demo run complete. Install the real CLI to launch it here.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
