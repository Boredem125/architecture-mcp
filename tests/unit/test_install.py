"""`sandbox init` / `uninstall` — settings merge idempotency & preservation."""
from __future__ import annotations

import json

from sandbox.connector.install import init, uninstall
from sandbox.connector.layout import FolderLayout


def test_init_creates_layout_and_stub(tmp_path):
    result = init(tmp_path, claude=True)
    layout = FolderLayout(tmp_path)
    assert layout.exists()
    assert (layout.hooks_dir / "pretooluse.py").exists()
    assert layout.policy_file.exists()
    assert layout.session_file.exists()
    session = json.loads(layout.session_file.read_text())
    assert session["python"]
    assert session["package_src"]


def test_settings_merge_is_idempotent(tmp_path):
    init(tmp_path, claude=True)
    init(tmp_path, claude=True)  # second time must not duplicate
    settings = json.loads((tmp_path / ".claude" / "settings.local.json").read_text())
    pre = settings["hooks"]["PreToolUse"]
    connector_entries = [h for h in pre if h.get("_sandbox_connector")]
    assert len(connector_entries) == 1


def test_merge_preserves_existing_and_m1_hook(tmp_path):
    # Pre-seed settings with an unrelated hook AND the M1 sandbox_hook entry.
    claude_dir = tmp_path / ".claude"
    claude_dir.mkdir(parents=True)
    (claude_dir / "settings.local.json").write_text(json.dumps({
        "hooks": {"PreToolUse": [
            {"matcher": "*", "hooks": [{"type": "command", "command": "python sandbox_hook.py"}]},
            {"matcher": "Bash", "hooks": [{"type": "command", "command": "echo other"}]},
        ]}
    }), encoding="utf-8")

    init(tmp_path, claude=True)
    pre = json.loads((claude_dir / "settings.local.json").read_text())["hooks"]["PreToolUse"]
    cmds = [h["hooks"][0]["command"] for h in pre]
    assert any("sandbox_hook.py" in c for c in cmds)  # M1 entry survives
    assert any("echo other" in c for c in cmds)        # unrelated entry survives
    assert any("pretooluse.py" in c for c in cmds)     # connector entry added


def test_uninstall_removes_only_connector_entry(tmp_path):
    claude_dir = tmp_path / ".claude"
    claude_dir.mkdir(parents=True)
    (claude_dir / "settings.local.json").write_text(json.dumps({
        "hooks": {"PreToolUse": [
            {"matcher": "Bash", "hooks": [{"type": "command", "command": "echo other"}]},
        ]}
    }), encoding="utf-8")

    init(tmp_path, claude=True)
    uninstall(tmp_path, keep_data=True)
    pre = json.loads((claude_dir / "settings.local.json").read_text())["hooks"]["PreToolUse"]
    cmds = [h["hooks"][0]["command"] for h in pre]
    assert any("echo other" in c for c in cmds)          # preserved
    assert not any("pretooluse.py" in c for c in cmds)   # removed
