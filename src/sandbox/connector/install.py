"""`sandbox init` / `uninstall` — write the folder, stub, and settings merge.

The settings merge is idempotent and marker-tagged: re-init replaces only the
connector's own entries and preserves everything else, including the M1
``sandbox_hook`` entry.
"""
from __future__ import annotations

import json
import sys
import time
import uuid
from pathlib import Path
from typing import Any

from sandbox.connector.hook_templates import (
    PRETOOLUSE_STUB,
    POSTTOOLUSE_STUB,
    SESSIONSTART_STUB,
)
from sandbox.connector.layout import FolderLayout
from sandbox.connector.policy import default_policy, save_policy

_MARKER = "_sandbox_connector"
_SETTINGS_CANDIDATES = (".claude/settings.local.json", ".claude/settings.json")


def _package_src() -> str:
    """Directory that must be on sys.path to import `sandbox` (src layout)."""
    import sandbox

    return str(Path(sandbox.__file__).resolve().parent.parent)


def _new_session_id() -> str:
    return "s-" + time.strftime("%Y-%m-%d-") + uuid.uuid4().hex[:6]


def _mcp_command() -> tuple[str, list[str]]:
    """The interpreter + args that launch the MCP server for a root.

    Uses the absolute interpreter so a Store-shim `python` on PATH can't break
    stdio launch; `--root` is filled in per-folder by the caller.
    """
    return sys.executable, ["-m", "sandbox.connector.mcp_server", "--root"]


def write_mcp_json(layout: FolderLayout) -> Path:
    """Write project-scope `.mcp.json` for Claude Code (merged, non-clobbering)."""
    path = layout.root / ".mcp.json"
    try:
        existing = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
    except (OSError, json.JSONDecodeError):
        existing = {}
    servers = existing.setdefault("mcpServers", {})
    cmd, args = _mcp_command()
    servers["sandbox"] = {
        "type": "stdio",
        "command": cmd,
        "args": [*args, str(layout.root)],
    }
    path.write_text(json.dumps(existing, indent=2), encoding="utf-8")
    return path


def codex_config_snippet(layout: FolderLayout) -> str:
    """A TOML block to add to ~/.codex/config.toml (Codex needs absolute root).

    Backslashes are invalid escapes in TOML basic strings, so every Windows
    path is emitted with forward slashes (which Windows accepts).
    """
    cmd, args = _mcp_command()
    full_args = [*args, str(layout.root)]
    args_toml = ", ".join(f'"{a.replace(chr(92), "/")}"' for a in full_args)
    cmd_toml = cmd.replace("\\", "/")
    return (
        "[mcp_servers.sandbox]\n"
        f'command = "{cmd_toml}"\n'
        f"args = [{args_toml}]\n"
    )


def init(
    root: str | Path,
    *,
    claude: bool = True,
    mcp: bool = True,
    codex: bool = False,
    auto_allow: bool = False,
) -> dict[str, Any]:
    """Initialize `.sandbox/` in *root*. Returns a summary dict."""
    layout = FolderLayout(root)
    layout.ensure_dirs()

    # policy.json (only write if absent, so re-init preserves tuning)
    if not layout.policy_file.exists():
        policy = default_policy()
        policy.auto_allow = auto_allow
        save_policy(policy, layout.policy_file)

    # session.json — capture the absolute interpreter + package src.
    session = {
        "schema": 1,
        "root": str(layout.root),
        "session_id": _new_session_id(),
        "started_at": time.time(),
        "python": sys.executable,
        "package_src": _package_src(),
        "connector_version": "1.0.0",
    }
    layout.session_file.write_text(
        json.dumps(session, indent=2), encoding="utf-8"
    )

    # hook stubs
    stub_path = layout.hooks_dir / "pretooluse.py"
    stub_path.write_text(PRETOOLUSE_STUB, encoding="utf-8")

    post_stub_path = layout.hooks_dir / "posttooluse.py"
    post_stub_path.write_text(POSTTOOLUSE_STUB, encoding="utf-8")

    session_stub_path = layout.hooks_dir / "sessionstart.py"
    session_stub_path.write_text(SESSIONSTART_STUB, encoding="utf-8")

    settings_path = None
    if claude:
        settings_path = _merge_settings(layout, stub_path)

    mcp_json_path = None
    if mcp:
        mcp_json_path = write_mcp_json(layout)

    codex_snippet = codex_config_snippet(layout) if codex else None

    return {
        "root": str(layout.root),
        "session_id": session["session_id"],
        "stub": str(stub_path),
        "settings": str(settings_path) if settings_path else None,
        "mcp_json": str(mcp_json_path) if mcp_json_path else None,
        "codex_snippet": codex_snippet,
        "policy": str(layout.policy_file),
    }


def _merge_settings(layout: FolderLayout, stub_path: Path) -> Path:
    """Merge marker-tagged PreToolUse and PostToolUse entries into Claude Code settings."""
    target = None
    for rel in _SETTINGS_CANDIDATES:
        cand = layout.root / rel
        if cand.exists():
            target = cand
            break
    if target is None:
        target = layout.root / ".claude" / "settings.local.json"
        target.parent.mkdir(parents=True, exist_ok=True)

    try:
        existing = json.loads(target.read_text(encoding="utf-8")) if target.exists() else {}
    except (OSError, json.JSONDecodeError):
        existing = {}

    hooks = existing.setdefault("hooks", {})

    # PreToolUse hook
    pre = hooks.setdefault("PreToolUse", [])
    pre[:] = [h for h in pre if not h.get(_MARKER)]
    pre_entry = {
        _MARKER: True,
        "matcher": "*",
        "hooks": [
            {
                "type": "command",
                "command": f'python "{stub_path}"',
                "timeout": 600,
            }
        ],
    }
    pre.insert(0, pre_entry)

    # PostToolUse hook (M3)
    post_stub = layout.hooks_dir / "posttooluse.py"
    post = hooks.setdefault("PostToolUse", [])
    post[:] = [h for h in post if not h.get(_MARKER)]
    post_entry = {
        _MARKER: True,
        "matcher": "*",
        "hooks": [
            {
                "type": "command",
                "command": f'python "{post_stub}"',
                "timeout": 120,
            }
        ],
    }
    post.insert(0, post_entry)

    # SessionStart hook (M4) — inject sandbox awareness into context.
    session_stub = layout.hooks_dir / "sessionstart.py"
    start = hooks.setdefault("SessionStart", [])
    start[:] = [h for h in start if not h.get(_MARKER)]
    start_entry = {
        _MARKER: True,
        "matcher": "*",
        "hooks": [
            {
                "type": "command",
                "command": f'python "{session_stub}"',
                "timeout": 30,
            }
        ],
    }
    start.insert(0, start_entry)

    target.write_text(json.dumps(existing, indent=2), encoding="utf-8")
    return target


def uninstall(root: str | Path, *, keep_data: bool = False) -> dict[str, Any]:
    """Remove the connector's settings entry (and optionally its data)."""
    layout = FolderLayout(root)
    removed_entry = False

    for rel in _SETTINGS_CANDIDATES:
        target = layout.root / rel
        if not target.exists():
            continue
        try:
            existing = json.loads(target.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        hooks = existing.get("hooks", {})
        changed = False
        for event in ("PreToolUse", "PostToolUse", "SessionStart"):
            entries = hooks.get(event, [])
            kept = [h for h in entries if not h.get(_MARKER)]
            if len(kept) != len(entries):
                hooks[event] = kept
                changed = True
        if changed:
            target.write_text(json.dumps(existing, indent=2), encoding="utf-8")
            removed_entry = True

    data_removed = False
    if not keep_data and layout.base.exists():
        import shutil

        shutil.rmtree(layout.base, ignore_errors=True)
        data_removed = True

    return {
        "root": str(layout.root),
        "settings_entry_removed": removed_entry,
        "data_removed": data_removed,
    }
