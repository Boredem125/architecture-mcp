"""Rate limits on tool calls (AIUC-1 D003.2): a circuit breaker for an agent
that loops, or that a hijack is driving fast.

Each PreToolUse call is counted in ``.sandbox/state/rate.json`` (timestamps
in a sliding window, shared by every hook process via a lock file). A call
that would exceed its class limit, or the total, is denied and not counted.

Classes: ``shell`` (Bash, PowerShell), ``write`` (Write, Edit, ...),
``network`` (WebFetch, WebSearch, third-party MCP tools). Everything counts
toward ``total``. If the lock can't be taken the call is let through: the
limiter is a brake, not a gate the agent should stall on.
"""
from __future__ import annotations

import json
import os
import time
from typing import Any

from sandbox.connector.layout import FolderLayout

_SHELL = {"Bash", "PowerShell"}
_WRITE = {"Write", "Edit", "MultiEdit", "NotebookEdit"}
_NETWORK = {"WebFetch", "WebSearch"}


def call_class(tool_name: str) -> str | None:
    if tool_name in _SHELL:
        return "shell"
    if tool_name in _WRITE:
        return "write"
    if tool_name in _NETWORK or (
        tool_name.startswith("mcp__") and not tool_name.startswith(("mcp__sandbox__", "mcp__sandbox_"))
    ):
        return "network"
    return None


class _Lock:
    def __init__(self, path: os.PathLike[str]) -> None:
        self.path = path
        self.held = False

    def __enter__(self) -> bool:
        for _ in range(100):
            try:
                with open(self.path, "x"):
                    self.held = True
                    return True
            except FileExistsError:
                # A lock left by a crashed hook goes stale after 5 s.
                try:
                    if time.time() - os.path.getmtime(self.path) > 5:
                        os.unlink(self.path)
                        continue
                except OSError:
                    pass
                time.sleep(0.01)
        return False

    def __exit__(self, *exc: Any) -> None:
        if self.held:
            try:
                os.unlink(self.path)
            except OSError:
                pass


def check(layout: FolderLayout, limits: Any, tool_name: str, now: float | None = None) -> dict[str, Any] | None:
    """Count this call. Return None if it is within limits, else a description
    of the limit it hit ({"class", "count", "limit", "window_seconds"})."""
    if not limits.enabled:
        return None
    now = time.time() if now is None else now
    cls = call_class(tool_name)
    state_file = layout.state_dir / "rate.json"
    layout.state_dir.mkdir(parents=True, exist_ok=True)
    with _Lock(layout.state_dir / "rate.lock") as held:
        if not held:
            return None
        try:
            calls = json.loads(state_file.read_text(encoding="utf-8")).get("calls", [])
        except (OSError, ValueError, AttributeError):
            calls = []
        cutoff = now - limits.window_seconds
        calls = [c for c in calls if isinstance(c, list) and len(c) == 2 and c[0] > cutoff]
        if len(calls) >= limits.total:
            return {"class": "total", "count": len(calls), "limit": limits.total,
                    "window_seconds": limits.window_seconds}
        if cls is not None:
            n = sum(1 for _, c in calls if c == cls)
            limit = getattr(limits, cls)
            if n >= limit:
                return {"class": cls, "count": n, "limit": limit, "window_seconds": limits.window_seconds}
        calls.append([now, cls])
        try:
            tmp = state_file.with_suffix(".tmp")
            tmp.write_text(json.dumps({"calls": calls}), encoding="utf-8")
            os.replace(tmp, state_file)
        except OSError:
            pass
    return None
