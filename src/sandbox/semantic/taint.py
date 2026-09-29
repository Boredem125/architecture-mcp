"""Folder-wide "taint" after untrusted content tried to instruct the agent.

Once an injection is seen, the agent's next actions may be carrying it out, so
for a while the actions that could do damage need a human, even ones that are
normally allowlisted. The state lives in `.sandbox/state/`, which the agent
cannot write (non-removable deny), so it can't clear its own taint.
"""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

TAINT_FILE = "taint.json"
MAX_EVENTS = 20


def _path(state_dir: Path) -> Path:
    return Path(state_dir) / TAINT_FILE


def mark(state_dir: Path, event: dict[str, Any], ttl_seconds: int, now: float | None = None) -> dict[str, Any]:
    now = time.time() if now is None else now
    current = read(state_dir, now=now) or {"events": []}
    state = {
        "until": max(current.get("until", 0.0), now + ttl_seconds),
        "events": (current.get("events", []) + [{**event, "at": now}])[-MAX_EVENTS:],
    }
    p = _path(state_dir)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(state), encoding="utf-8")
    tmp.replace(p)
    return state


def read(state_dir: Path, now: float | None = None) -> dict[str, Any] | None:
    """The active taint, or None if there is none or it has expired."""
    now = time.time() if now is None else now
    try:
        state = json.loads(_path(state_dir).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if float(state.get("until", 0)) <= now:
        return None
    return state


def clear(state_dir: Path) -> bool:
    try:
        _path(state_dir).unlink()
        return True
    except OSError:
        return False
