"""M1 T2 follow-up (security review of da58fc3): device-path prefixes, lookup DoS, SEC-29,
`keys status` exposure warning, workspace id audit. Written before the fix."""
from __future__ import annotations

import asyncio
import json
import os
import subprocess
import time
from pathlib import Path

import pytest
from click.testing import CliRunner

from sandbox.cli.main import cli
from sandbox.connector import keyhome
from sandbox.connector.approval import approve
from sandbox.connector.classify import analyse_shell, classify
from sandbox.connector.hook_eval import pre_tool_use
from sandbox.connector.install import init
from sandbox.connector.layout import FolderLayout
from sandbox.connector.policy import default_policy
from sandbox.connector.queue import EscalationQueue

WINDOWS = os.name == "nt"
CORPUS = [json.loads(line) for line in
          Path(__file__).with_name("read_outside_root_corpus.jsonl").read_text(encoding="utf-8").splitlines()
          if line.strip()]


def _ws(path):
    path.mkdir(parents=True, exist_ok=True)
    init(path, claude=False, mcp=False)
    return FolderLayout(path)


def _hook(lay, tool, tool_input):
    out = asyncio.run(pre_tool_use({"tool_name": tool, "tool_input": tool_input, "cwd": str(lay.root),
                                    "session_id": "t"}, lay))
    return out.get("hookSpecificOutput", {}).get("permissionDecision")


def _submit(lay, cmd="echo x"):
    return EscalationQueue(lay).submit({"kind": "command", "command": cmd, "exec_cwd": str(lay.root),
                                        "root": str(lay.root), "trigger": ["shell"]})


@pytest.fixture
def seed(tmp_path):
    d = Path(os.environ["SANDBOX_KEY_HOME"]) / "w0"
    d.mkdir(parents=True)
    (d / "alice.seed").write_bytes(b"\x07" * 32)
    return d / "alice.seed"


# --- 1. device-path prefixes -------------------------------------------------------------

def _forms(p: Path) -> list[str]:
    s = str(p)
    return ["\\\\?\\" + s, "\\??\\" + s, "//?/" + s.replace("\\", "/"), "\\\\.\\" + s]


@pytest.mark.skipif(not WINDOWS, reason="device-path prefixes are Windows forms")
@pytest.mark.parametrize("tool, what", [("Read", "file"), ("Read", "dir"), ("Glob", "dir"), ("Grep", "dir"),
                                        ("Grep", "file")])
def test_device_prefixed_key_home_paths_are_denied(tmp_path, seed, tool, what):
    lay = _ws(tmp_path / "ws")
    target = seed if what == "file" else seed.parent
    field = "file_path" if tool == "Read" else "path"
    for form in _forms(target) + _forms(Path(os.environ["SANDBOX_KEY_HOME"])):
        ti = {field: form}
        if tool in ("Glob", "Grep"):
            ti["pattern"] = "**/*" if tool == "Glob" else "."
        assert _hook(lay, tool, ti) == "deny", (tool, form)


def test_device_prefixes_are_stripped_by_the_normaliser():
    for raw in ("\\\\?\\C:\\a\\b", "\\??\\C:\\a\\b", "//?/C:/a/b", "\\\\.\\C:\\a\\b"):
        assert keyhome._comps(raw) == ["c:", "a", "b"], raw
    assert keyhome._comps("\\\\?\\UNC\\host\\share\\x")[:2] == ["host", "share"]


# --- 2. lookup DoS -------------------------------------------------------------------------

@pytest.mark.skipif(not WINDOWS, reason="UNC paths are a Windows form")
def test_unc_paths_cause_no_filesystem_lookup(tmp_path, monkeypatch):
    lay = _ws(tmp_path / "ws")
    real = os.path.realpath

    def guard(p, *a, **k):
        assert not str(p).replace("\\", "/").startswith("//"), f"lookup on a network path: {p}"
        return real(p, *a, **k)
    monkeypatch.setattr(os.path, "realpath", guard)
    for cmd in ("cat //10.255.255.1/x/y", "cat \\\\10.255.255.1\\x\\y", "cat \\\\?\\UNC\\10.255.255.1\\x\\y"):
        a = analyse_shell(cmd, cwd=str(lay.root))
        assert a.deny or a.unresolvable, cmd


def test_lookups_have_a_wall_clock_budget(tmp_path, monkeypatch):
    lay = _ws(tmp_path / "ws")
    real = os.path.realpath

    def slow(p, *a, **k):
        time.sleep(0.4)
        return real(p, *a, **k)
    monkeypatch.setattr(os.path, "realpath", slow)
    cmd = "cat " + " ".join(f"d{i}/f{i}" for i in range(40))
    t = time.monotonic()
    a = analyse_shell(cmd, cwd=str(lay.root))
    assert time.monotonic() - t < 6.0
    assert a.deny or a.unresolvable  # never a silent allow once the budget is gone


# --- 3. SEC-29 -----------------------------------------------------------------------------

@pytest.mark.parametrize("case", CORPUS, ids=[c["id"] for c in CORPUS])
def test_sec29_allowlist_counts_only_for_paths_inside_the_root(tmp_path, case):
    lay = _ws(tmp_path / "ws")
    (lay.root / "src").mkdir()
    (lay.root / "README.md").write_text("x", encoding="utf-8")
    c = classify("Bash", {"command": case["command"]}, default_policy(), lay, cwd=str(lay.root))
    if case["expected"] == "allow":
        assert c.verdict == "allow", (case, c)
    else:
        assert c.verdict in ("escalate", "deny"), (case, c)


def test_sec29_junction_or_symlink_inside_the_root_pointing_out_escalates(tmp_path):
    lay = _ws(tmp_path / "ws")
    outside = tmp_path / "outside"
    outside.mkdir()
    link = lay.root / "lnk"
    if WINDOWS:
        subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(outside)], capture_output=True)
    else:
        os.symlink(outside, link, target_is_directory=True)
    assert link.exists()
    c = classify("Bash", {"command": "ls lnk"}, default_policy(), lay, cwd=str(lay.root))
    assert c.verdict in ("escalate", "deny")


# --- 4. keys status warns on an exposed key home ------------------------------------------

def _expose(path: Path) -> None:
    if WINDOWS:
        subprocess.run(["icacls", str(path), "/grant", "*S-1-1-0:(OI)(CI)R"], capture_output=True, check=True)
    else:
        os.chmod(path, 0o755)


def test_keys_status_warns_when_the_key_home_is_readable_by_others(tmp_path):
    lay = _ws(tmp_path / "ws")
    root = Path(os.environ["SANDBOX_KEY_HOME"])
    _expose(root)
    out = CliRunner().invoke(cli, ["keys", "status", "--path", str(lay.root)])
    assert "readable by other" in out.output, out.output


def test_keys_status_is_quiet_for_a_key_home_this_tool_created(tmp_path, monkeypatch):
    lay = _ws(tmp_path / "ws")
    monkeypatch.setenv("SANDBOX_KEY_HOME", str(tmp_path / "fresh" / "keys"))
    keyhome.workspace_key_dir(lay)
    out = CliRunner().invoke(cli, ["keys", "status", "--path", str(lay.root)])
    assert "readable by other" not in out.output, out.output


# --- 6. a recreated workspace id is audited ------------------------------------------------

def test_a_deleted_workspace_id_is_recreated_with_an_audit_record(tmp_path):
    lay = _ws(tmp_path / "ws")
    asyncio.run(approve(lay, _submit(lay), "alice", "t"))
    (lay.base / keyhome.WORKSPACE_ID_FILE).unlink()
    asyncio.run(approve(lay, _submit(lay, "echo y"), "alice", "t"))
    events = [json.loads(line).get("event") for f in lay.audit_dir.rglob("*.jsonl")
              for line in f.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert "workspace_id_created" in events
