"""`sandbox init` / `uninstall` — write the folder, stub, and settings merge.

The settings merge is idempotent and marker-tagged: re-init replaces only the
connector's own entries and preserves everything else, including the M1
``sandbox_hook`` entry.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
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


class InstallLayoutError(ValueError):
    """The connector's code would live inside the governed (agent-writable) root."""


def _interpreter_dirs() -> list[str]:
    import site

    dirs = [sys.prefix, sys.base_prefix, *site.getsitepackages()]
    try:
        dirs.append(site.getusersitepackages())
    except Exception:  # noqa: BLE001
        pass
    return dirs


def _refuse_in_root(root: Path) -> None:
    """SEC-27: a .pth file, sitecustomize or package inside the project would run
    in (or replace) the hook, so the connector must be installed outside it."""
    import os

    base = os.path.normcase(os.path.realpath(root))
    for d in [*_interpreter_dirs(), _package_src()]:
        real = os.path.normcase(os.path.realpath(d))
        if real == base or real.startswith(base + os.sep):
            raise InstallLayoutError(
                f"refusing to install: {d} is inside the governed folder {root}. The agent "
                "can write there and take over the hook. Install the connector outside the "
                "project (for example pipx, or a virtualenv in another directory) and re-run."
            )


def _new_session_id() -> str:
    return "s-" + time.strftime("%Y-%m-%d-") + uuid.uuid4().hex[:6]


def _mcp_command() -> tuple[str, list[str]]:
    """The interpreter + args that launch the MCP server for a root.

    Uses the absolute interpreter so a Store-shim `python` on PATH can't break
    stdio launch; `--root` is filled in per-folder by the caller.
    """
    # -I (isolated): no cwd/script dir on sys.path, PYTHON* env and user site
    # ignored, so files in the agent-writable project cannot shadow the package.
    return sys.executable, ["-I", "-m", "sandbox.connector.mcp_server", "--root"]


_MIN_CLAUDE = (2, 1, 295)  # first release with hook "onFailure": "block"


def _claude_code_version() -> tuple[int, int, int] | None:
    """Installed Claude Code version, best effort (None when unknown)."""
    exe = shutil.which("claude")
    if not exe:
        return None
    out = subprocess.run([exe, "--version"], capture_output=True, text=True, timeout=5).stdout
    m = re.search(r"(\d+)\.(\d+)\.(\d+)", out)
    return (int(m[1]), int(m[2]), int(m[3])) if m else None


def _version_warnings() -> list[str]:
    try:
        v = _claude_code_version()
    except Exception:  # noqa: BLE001 - best effort, never fail init
        return []
    if v is not None and v < _MIN_CLAUDE:
        return [
            "Claude Code %s is older than 2.1.295: PreToolUse onFailure=block is not "
            "honoured, so a hook timeout or crash lets the tool call proceed. Upgrade."
            % ".".join(map(str, v))
        ]
    return []


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
        "env": {"PYTHONPATH": _package_src(), "SANDBOX_PACKAGE_SRC": _package_src()},
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
    _src_toml = _package_src().replace("\\", "/")
    return (
        "[mcp_servers.sandbox]\n"
        f'command = "{cmd_toml}"\n'
        f"args = [{args_toml}]\n"
        f'env = {{ PYTHONPATH = "{_src_toml}", SANDBOX_PACKAGE_SRC = "{_src_toml}" }}\n'
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
    _refuse_in_root(layout.root)
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
    warnings: list[str] = []
    if claude:
        settings_path = _merge_settings(layout, stub_path, session["python"])
        warnings = _version_warnings()

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
        "warnings": warnings,
    }


def _merge_settings(layout: FolderLayout, stub_path: Path, python: str | None = None) -> Path:
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
    py = python or sys.executable  # absolute interpreter recorded in session.json

    def _cmd(stub: Path) -> str:
        return f'"{py}" -I "{stub}"'

    # PreToolUse hook
    pre = hooks.setdefault("PreToolUse", [])
    pre[:] = [h for h in pre if not h.get(_MARKER)]
    pre_entry = {
        _MARKER: True,
        "matcher": "*",
        "hooks": [
            {
                "type": "command",
                "command": _cmd(stub_path),
                "timeout": 600,
                "onFailure": "block",  # SEC-28: PreToolUse only
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
                "command": _cmd(post_stub),
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
                "command": _cmd(session_stub),
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


def diagnose_layout(root: str | Path) -> list[str]:
    """Problems that leave the hook takeover-able (empty list = safe layout)."""
    import os

    layout = FolderLayout(root)
    base = os.path.normcase(os.path.realpath(layout.root))

    def inside(p: str) -> bool:
        r = os.path.normcase(os.path.realpath(p))
        return r == base or r.startswith(base + os.sep)

    problems: list[str] = []
    try:
        session = json.loads(layout.session_file.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return ["UNSAFE LAYOUT: no readable .sandbox/session.json; run `sandbox init`"]
    py = session.get("python") or ""
    dirs = [py, str(Path(py).parent), str(Path(py).parent.parent), session.get("package_src") or ""]
    if py and Path(py).resolve() == Path(sys.executable).resolve():
        dirs += _interpreter_dirs()
    for d in dirs:
        if d and inside(d):
            problems.append(f"UNSAFE LAYOUT: {d} is inside the governed folder (install the connector outside it, then re-run `sandbox init`)")
            break
    found = False
    for rel in _SETTINGS_CANDIDATES:
        f = layout.root / rel
        if not f.exists():
            continue
        try:
            hooks = json.loads(f.read_text(encoding="utf-8")).get("hooks", {})
        except (OSError, ValueError):
            continue
        for entry in hooks.get("PreToolUse", []):
            if entry.get(_MARKER):
                found = True
                h = (entry.get("hooks") or [{}])[0]
                cmd = h.get("command", "")
                if " -I " not in cmd or not cmd.startswith('"') or h.get("onFailure") != "block":
                    problems.append(
                        "UNSAFE LAYOUT: installed PreToolUse hook lacks an absolute interpreter, -I or "
                        "onFailure=block; re-run `sandbox init`")
    if not found:
        problems.append("UNSAFE LAYOUT: no connector PreToolUse hook found in .claude settings (run `sandbox init`)")
    return problems
