"""Remembered decisions — per-session approvals so a human isn't re-prompted.

Stored in ``.sandbox/state/remembered.json``, keyed by the current
``session_id``. When the session changes, the whole store is invalidated —
"remember for a session" literally. This is deliberately *not* persistent:
persistent grants belong in ``policy.json`` allowlists (``--persist``), which
are git-diffable and survive restarts.

Scopes:

* ``once``    — a single request (never actually stored; the default)
* ``command`` — an exact shell command string
* ``prefix``  — the first **two** tokens of a shell command (e.g. ``npm run``);
                one token (``git``) is refused — that is how ``git push --force``
                gets silently auto-approved
* ``dir``     — a directory subtree (for read/write-outside)
* ``host``    — a network host

A remembered entry only ever upgrades a verdict toward ``allow``; it can never
turn an ``allow`` into a ``deny``. Blocklist and self-protection denials are
checked *before* memory in the hook, so memory can't resurrect a blocked
command.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

_VALID_SCOPES = {"once", "command", "prefix", "dir", "host"}


class DecisionMemory:
    """Load/query/record remembered decisions for one session."""

    def __init__(self, path: str | Path, session_id: str) -> None:
        self.path = Path(path)
        self.session_id = session_id or "default"
        self._data = self._load()

    def _load(self) -> dict[str, Any]:
        if not self.path.exists():
            return {"session_id": self.session_id, "entries": []}
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {"session_id": self.session_id, "entries": []}
        # Session changed → wipe (remember-for-a-session semantics).
        if data.get("session_id") != self.session_id:
            return {"session_id": self.session_id, "entries": []}
        return data

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(self._data, indent=2), encoding="utf-8")

    # --- recording -------------------------------------------------------
    def remember(
        self, scope: str, value: str, *, trigger: str = "", verdict: str = "allow"
    ) -> None:
        """Record a remembered decision. ``once`` is a no-op (nothing stored)."""
        if scope == "once" or scope not in _VALID_SCOPES:
            return
        if scope == "prefix" and len(value.split()) < 2:
            raise ValueError(
                "prefix scope requires at least two tokens "
                "(one-token prefixes like 'git' are unsafe)"
            )
        entry = {"scope": scope, "value": value, "trigger": trigger, "verdict": verdict}
        # De-dup.
        if entry not in self._data["entries"]:
            self._data["entries"].append(entry)
            self._save()

    def forget_all(self) -> None:
        self._data["entries"] = []
        self._save()

    # --- querying --------------------------------------------------------
    def recall(
        self, *, command: str = "", target_path: str = "", host: str = ""
    ) -> dict[str, Any] | None:
        """Return a matching remembered entry, or None."""
        for entry in self._data["entries"]:
            if self._matches(entry, command, target_path, host):
                return entry
        return None

    def _matches(
        self, entry: dict[str, Any], command: str, target_path: str, host: str
    ) -> bool:
        scope, value = entry.get("scope"), entry.get("value", "")
        if scope == "command":
            return bool(command) and command.strip() == value.strip()
        if scope == "prefix":
            return bool(command) and _shares_prefix(command, value)
        if scope == "dir":
            return bool(target_path) and _under_dir(target_path, value)
        if scope == "host":
            return bool(host) and host.lower() == value.lower()
        return False

    def entries(self) -> list[dict[str, Any]]:
        return list(self._data["entries"])


def _shares_prefix(command: str, prefix: str) -> bool:
    cmd_tokens = command.split()
    pre_tokens = prefix.split()
    if len(cmd_tokens) < len(pre_tokens):
        return False
    return cmd_tokens[: len(pre_tokens)] == pre_tokens


def _under_dir(target_path: str, directory: str) -> bool:
    try:
        t = os.path.normcase(os.path.abspath(target_path))
        d = os.path.normcase(os.path.abspath(directory))
        return t == d or t.startswith(d + os.sep)
    except (ValueError, OSError):
        return False
