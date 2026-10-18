"""M1 T2 extras beyond QA's key-home tests: what rotation records, `sandbox keys`, fail-closed edges."""
from __future__ import annotations

import asyncio
import json

import pytest
from click.testing import CliRunner
from nacl.signing import SigningKey

from sandbox.cli.main import cli
from sandbox.connector import keyhome
from sandbox.connector.approval import approve
from sandbox.connector.hook_eval import pre_tool_use
from sandbox.connector.install import init
from sandbox.connector.layout import FolderLayout
from sandbox.connector.queue import EscalationQueue


def _ws(path):
    path.mkdir(parents=True, exist_ok=True)
    init(path, claude=False, mcp=False)
    return FolderLayout(path)


def _events(layout, name):
    out = []
    for f in layout.audit_dir.rglob("*.jsonl"):
        out += [r for r in map(json.loads, filter(str.strip, f.read_text(encoding="utf-8").splitlines()))
                if r.get("event") == name]
    return out


def _legacy_seed(layout, name="cli"):
    old = SigningKey.generate()
    p = layout.state_dir / "keys" / f"{name}.seed"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(bytes(old))
    return p, bytes(old.verify_key).hex()


def _approve(layout, reviewer="cli"):
    rid = EscalationQueue(layout).submit({"kind": "command", "command": "echo x", "exec_cwd": str(layout.root),
                                          "root": str(layout.root), "trigger": ["shell"]})
    return asyncio.run(approve(layout, rid, reviewer, "t"))


def test_init_writes_a_random_workspace_id(tmp_path):
    a, b = _ws(tmp_path / "a"), _ws(tmp_path / "b")
    ia, ib = keyhome.workspace_id(a, create=False), keyhome.workspace_id(b, create=False)
    assert len(ia) == 32 and ia != ib


def test_malformed_workspace_id_fails_closed(tmp_path):
    lay = _ws(tmp_path / "ws")
    (lay.base / keyhome.WORKSPACE_ID_FILE).write_text("../../evil", encoding="utf-8")
    assert _approve(lay)["status"] == "key_unavailable"


def test_key_home_inside_the_workspace_is_refused(tmp_path, monkeypatch):
    lay = _ws(tmp_path / "ws")
    monkeypatch.setenv("SANDBOX_KEY_HOME", str(lay.root / "keys"))
    assert _approve(lay)["status"] == "key_unavailable"
    assert not (lay.root / "keys").exists()


def test_relative_key_home_is_refused(tmp_path, monkeypatch):
    lay = _ws(tmp_path / "ws")
    monkeypatch.setenv("SANDBOX_KEY_HOME", "relative/keys")
    monkeypatch.chdir(tmp_path)
    assert _approve(lay)["status"] == "key_unavailable"
    assert not (tmp_path / "relative").exists()


def test_rotation_audits_the_retired_key_and_the_chain_heads(tmp_path):
    lay = _ws(tmp_path / "ws")
    from sandbox.connector.audit import FolderAudit
    FolderAudit(lay.audit_dir, "s1").append({"event": "earlier", "ts": 1})
    _, old_pub = _legacy_seed(lay)
    res = _approve(lay)["result"]
    (ev,) = _events(lay, "key_rotated")
    assert ev["retired_public_key"] == old_pub and ev["new_public_key"] == res["signer_public_key"]
    assert ev["audit_heads"]["s1"]["records"] == 1 and ev["audit_heads"]["s1"]["head_hash"]
    _approve(lay)  # second use: no second rotation
    assert len(_events(lay, "key_rotated")) == 1


def test_keys_purge_legacy_deletes_only_retired_seeds_and_audits(tmp_path):
    lay = _ws(tmp_path / "ws")
    p1, _ = _legacy_seed(lay, "alice")
    p2, _ = _legacy_seed(lay, "bob")
    out = CliRunner().invoke(cli, ["keys", "purge-legacy", "--path", str(lay.root), "--yes", "--by", "tester"])
    assert out.exit_code == 0, out.output
    assert not p1.exists() and not p2.exists()
    assert len(_events(lay, "key_rotated")) == 2  # rotated first, so the heads are on record
    (ev,) = _events(lay, "legacy_seeds_purged")
    assert sorted(ev["removed"]) == ["alice.seed", "bob.seed"] and ev["by"] == "tester"


def test_keys_purge_legacy_without_confirmation_deletes_nothing(tmp_path):
    lay = _ws(tmp_path / "ws")
    p, _ = _legacy_seed(lay)
    out = CliRunner().invoke(cli, ["keys", "purge-legacy", "--path", str(lay.root)], input="n\n")
    assert out.exit_code == 1 and p.exists()


def test_the_agent_cannot_run_sandbox_keys(tmp_path):
    lay = _ws(tmp_path / "ws")
    for cmd in ("sandbox keys purge-legacy --yes", "python -m sandbox.cli.main keys purge-legacy"):
        out = asyncio.run(pre_tool_use({"tool_name": "Bash", "tool_input": {"command": cmd}, "cwd": str(lay.root),
                                        "session_id": "t"}, lay))
        assert out["hookSpecificOutput"]["permissionDecision"] == "deny", cmd


@pytest.mark.parametrize("tool, tool_input", [
    ("Write", {"file_path": "{kh}/x.seed", "content": "x"}),
    ("Edit", {"file_path": "{kh}/pins.json", "old_string": "a", "new_string": "b"}),
])
def test_write_tools_are_denied_on_the_key_home_even_when_write_outside_is_allow(tmp_path, tool, tool_input):
    import os
    lay = _ws(tmp_path / "ws")
    from sandbox.connector.policy import load_policy, save_policy
    pol = load_policy(lay.policy_file)
    pol.triggers.write_outside = "allow"
    save_policy(pol, lay.policy_file)
    kh = os.environ["SANDBOX_KEY_HOME"]
    ti = {k: v.format(kh=kh) if isinstance(v, str) else v for k, v in tool_input.items()}
    out = asyncio.run(pre_tool_use({"tool_name": tool, "tool_input": ti, "cwd": str(lay.root), "session_id": "t"}, lay))
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny"


@pytest.mark.parametrize("cmd", ["rg foo {parent}", "grep -r foo {parent}", "find {parent} -name x"])
def test_recursive_search_from_a_directory_above_the_key_home_is_denied(tmp_path, cmd):
    import os
    from pathlib import Path
    lay = _ws(tmp_path / "ws")
    parent = str(Path(os.environ["SANDBOX_KEY_HOME"]).parent)
    out = asyncio.run(pre_tool_use({"tool_name": "Bash", "tool_input": {"command": cmd.format(parent=parent)},
                                    "cwd": str(lay.root), "session_id": "t"}, lay))
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_cd_into_the_key_home_then_a_relative_read_is_denied(tmp_path):
    import os
    lay = _ws(tmp_path / "ws")
    kh = os.environ["SANDBOX_KEY_HOME"]
    out = asyncio.run(pre_tool_use({"tool_name": "Bash", "tool_input": {"command": f'cd "{kh}" && cat x.seed'},
                                    "cwd": str(lay.root), "session_id": "t"}, lay))
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny"
