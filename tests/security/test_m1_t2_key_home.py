"""M1 T2 (D2, ADR 0007 section 1): signing keys leave the workspace. Tests first.

Seeds and pins live in a key home outside every workspace (`SANDBOX_KEY_HOME`,
default the per-user OS data dir), one subfolder per workspace id. The key
home is a non-removable deny for read, write, delete and rename through every
tool, shell variants included. Rotate, never migrate: an in-tree pre-M1 seed is
retired in place, never copied, moved or deleted. Fail closed when the key home
cannot be resolved or written: no signing, approvals invalid, never a fallback
to `.sandbox/state/keys`, the cwd or a relative path.

RED tests raise ``KeyHomeOpen`` for the stated reason only (strict xfail); the
fix commit deletes the decorator. Guards pass today and must keep passing.
"""
from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from sandbox.connector.approval import approve
from sandbox.connector.evidence import export_evidence
from sandbox.connector.hook_eval import pre_tool_use
from sandbox.connector.install import init
from sandbox.connector.layout import FolderLayout
from sandbox.connector.policy import load_policy, save_policy
from sandbox.connector.queue import EscalationQueue

WINDOWS = os.name == "nt"
SRC = str(Path(__file__).resolve().parents[2] / "src")


class KeyHomeOpen(AssertionError):
    """Keys still live in the workspace, or the key home is not protected (M1 T2 open)."""


RED_T2 = pytest.mark.xfail(raises=KeyHomeOpen, strict=True,
                           reason="M1 T2 open: seeds are still in .sandbox/state/keys")


def _require(cond: bool, msg: str) -> None:
    if not cond:
        raise KeyHomeOpen(msg)


def _ws(path: Path) -> FolderLayout:
    path.mkdir(parents=True, exist_ok=True)
    init(path, claude=False, mcp=False)
    return FolderLayout(path)


def _submit(layout, command="echo t2", **extra) -> str:
    return EscalationQueue(layout).submit({"kind": "command", "command": command, "exec_cwd": str(layout.root),
                                           "root": str(layout.root), "trigger": ["shell"], **extra})


def _approve(layout, rid, reviewer):
    return asyncio.run(approve(layout, rid, reviewer, "t2 test approval"))


def _marker_command(marker: Path) -> str:
    return f'"{sys.executable}" -c "open(r\'{marker}\', \'w\').write(\'ran\')"'


def _seeds(where: Path) -> list[Path]:
    return sorted(where.rglob("*.seed")) if where.exists() else []


def _audit_events(layout) -> list[str]:
    out = []
    for f in layout.audit_dir.rglob("*.jsonl"):
        for line in f.read_text(encoding="utf-8").splitlines():
            if line.strip():
                out.append(json.loads(line).get("event", ""))
    return out


@pytest.fixture
def key_home(tmp_path, monkeypatch):
    kh = tmp_path / "keyhome"
    monkeypatch.setenv("SANDBOX_KEY_HOME", str(kh))
    return kh


# --- seeds are not in the workspace -------------------------------------------------

@RED_T2
def test_no_seed_bytes_in_the_workspace_after_approvals_grants_and_export(tmp_path, key_home):
    lay = _ws(tmp_path / "ws")
    _approve(lay, _submit(lay), "alice")
    dual = _submit(lay, command="echo dual", requires_dual=True)
    _approve(lay, dual, "alice")
    _approve(lay, dual, "bob")
    tool = EscalationQueue(lay).submit({"kind": "tool_call", "tool_name": "mcp__bank__send", "command": "send",
                                        "fingerprint": "f" * 64, "root": str(lay.root), "trigger": ["network"]})
    _approve(lay, tool, "carol")
    export_evidence(lay, tmp_path / "pack")

    seeds = _seeds(key_home)
    _require(len(seeds) >= 4, f"expected the alice, bob, carol and exporter seeds in the key home, found {seeds}")
    in_tree = _seeds(lay.root)
    _require(not in_tree, f"seed files inside the workspace: {in_tree}")
    secrets = [p.read_bytes() for p in seeds]
    needles = secrets + [s.hex().encode() for s in secrets] + [s.hex().upper().encode() for s in secrets]
    leaks = [str(f) for f in lay.root.rglob("*") if f.is_file()
             and any(n in f.read_bytes() for n in needles)]
    _require(not leaks, f"seed bytes (raw or hex) found in workspace files: {leaks}")


@RED_T2
def test_two_workspaces_get_separate_keys_for_the_same_reviewer(tmp_path, key_home):
    a, b = _ws(tmp_path / "a"), _ws(tmp_path / "b")
    ra = _approve(a, _submit(a), "cli")["result"]
    rb = _approve(b, _submit(b), "cli")["result"]
    assert ra["signer_public_key"] != rb["signer_public_key"]
    seeds = _seeds(key_home)
    _require(len(seeds) >= 2 and len({p.parent for p in seeds}) >= 2,
             f"expected one key-home subfolder per workspace id, found {seeds}")


# --- default location and fail closed -------------------------------------------------

def _default_home_env(monkeypatch, tmp_path) -> Path:
    """Point the per-user OS data dir at tmp; return the expected key home."""
    monkeypatch.delenv("SANDBOX_KEY_HOME", raising=False)
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.delenv("XDG_DATA_HOME", raising=False)
    if WINDOWS:
        lad = home / "AppData" / "Local"
        lad.mkdir(parents=True)
        monkeypatch.setenv("LOCALAPPDATA", str(lad))
        return lad / "agg" / "keys"
    if sys.platform == "darwin":
        return home / "Library" / "Application Support" / "agg" / "keys"
    return home / ".local" / "share" / "agg" / "keys"


@RED_T2
def test_default_key_home_is_the_per_user_os_data_dir(tmp_path, monkeypatch):
    expected = _default_home_env(monkeypatch, tmp_path)
    lay = _ws(tmp_path / "ws")
    _approve(lay, _submit(lay), "alice")
    _require(bool(_seeds(expected)), f"no seed under the default key home {expected}")
    _require(not _seeds(lay.root), f"seed files inside the workspace: {_seeds(lay.root)}")


@RED_T2
def test_unresolvable_key_home_fails_closed(tmp_path, monkeypatch):
    for name in ("SANDBOX_KEY_HOME", "LOCALAPPDATA", "APPDATA", "HOME", "USERPROFILE", "XDG_DATA_HOME"):
        monkeypatch.delenv(name, raising=False)

    def no_home(*a, **k):
        raise RuntimeError("no home directory")
    monkeypatch.setattr(Path, "home", classmethod(no_home))
    monkeypatch.setattr(os.path, "expanduser", lambda p: p)
    cwd = tmp_path / "cwd"
    cwd.mkdir()
    monkeypatch.chdir(cwd)
    lay = _ws(cwd / "ws")
    marker = tmp_path / "ran.txt"
    rid = _submit(lay, command=_marker_command(marker))
    try:
        _approve(lay, rid, "alice")
    except Exception:  # noqa: BLE001 - failing closed by raising is acceptable
        pass
    found = _seeds(cwd)
    _require(not found, f"keys were written under the cwd/workspace with no key home: {found}")
    _require(not marker.exists(), "an approval ran with no key home (no signing should mean no valid approval)")


@RED_T2
def test_minimal_env_child_never_writes_keys_in_tree(tmp_path):
    """The env shape of test_posttooluse_fallback.py's child (M0 T11's %SystemDrive% bug class)."""
    cwd = tmp_path / "cwd"
    cwd.mkdir()
    marker = tmp_path / "ran.txt"
    script = (
        "import asyncio, json, sys\n"
        "from pathlib import Path\n"
        "from sandbox.connector.install import init\n"
        "from sandbox.connector.layout import FolderLayout\n"
        "from sandbox.connector.queue import EscalationQueue\n"
        "from sandbox.connector.approval import approve\n"
        "ws = Path('ws'); ws.mkdir(); init(ws, claude=False, mcp=False); lay = FolderLayout(ws)\n"
        "rid = EscalationQueue(lay).submit({'kind': 'command', 'command': sys.argv[1], 'exec_cwd': str(lay.root),"
        " 'root': str(lay.root), 'trigger': ['shell']})\n"
        "try:\n"
        "    asyncio.run(approve(lay, rid, 'alice', 'minimal env'))\n"
        "except Exception as e:\n"
        "    print('raised', type(e).__name__)\n"
    )
    env = {"PYTHONPATH": SRC}
    if WINDOWS:
        env.update(SYSTEMROOT=os.environ.get("SYSTEMROOT", ""), SYSTEMDRIVE=os.environ.get("SYSTEMDRIVE", ""))
    else:
        env["HOME"] = "/nonexistent-agg-test-home"  # unresolvable and unwritable, so nothing lands in a real home
    proc = subprocess.run([sys.executable, "-c", script, _marker_command(marker)], cwd=cwd, env=env,
                          capture_output=True, text=True, timeout=120)
    assert "Traceback" not in proc.stderr or "raised" in proc.stdout, proc.stderr[-1500:]
    found = _seeds(cwd)
    _require(not found, f"the minimal-env child wrote keys under its cwd: {found}")
    _require(not marker.exists(), "the minimal-env child ran an approval it could not sign")


# --- the key home is denied to the agent ----------------------------------------------

def _hook_setup(tmp_path, monkeypatch, *, relax=True):
    """Default key home under tmp, a fake workspace-id subfolder with a seed and pins,
    and a workspace whose read_outside/write_outside triggers are relaxed to allow,
    to prove the key-home deny is not those configurable triggers."""
    kh = _default_home_env(monkeypatch, tmp_path)
    w = kh / "w0"
    w.mkdir(parents=True)
    (w / "cli.seed").write_bytes(b"\x07" * 32)
    (w / "pins.json").write_text("{}", encoding="utf-8")
    lay = _ws(tmp_path / "ws")
    policy = load_policy(lay.policy_file)
    policy.escalation_timeout_seconds = 0
    if relax:
        policy.triggers.read_outside = "allow"
        policy.triggers.write_outside = "allow"
    save_policy(policy, lay.policy_file)
    link = lay.root / "link"
    if WINDOWS:
        subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(kh)], capture_output=True)
    else:
        os.symlink(kh, link, target_is_directory=True)
    assert link.exists(), "could not create the in-tree link to the key home"
    return lay, kh, w


def _hook(lay, tool, tool_input):
    out = asyncio.run(pre_tool_use({"tool_name": tool, "tool_input": tool_input, "cwd": str(lay.root),
                                    "session_id": "t2"}, lay))
    hso = out.get("hookSpecificOutput", {})
    return hso.get("permissionDecision"), hso.get("permissionDecisionReason", "")


def _short_name(path: Path) -> str:
    if WINDOWS:
        import ctypes

        buf = ctypes.create_unicode_buffer(32768)
        if ctypes.windll.kernel32.GetShortPathNameW(str(path), buf, 32768) and buf.value != str(path):
            return buf.value
        return str(path).replace(os.sep, os.sep + "." + os.sep, 1)  # no 8.3 names on this volume
    return str(path).replace("/", "/./", 1)


def _tool_case(case: str, lay, kh: Path, w: Path):
    seed, pins = w / "cli.seed", w / "pins.json"
    rel = f"{w.name}/cli.seed"
    if case == "read":
        return "Read", {"file_path": str(seed)}
    if case == "read_via_link":
        return "Read", {"file_path": str(lay.root / "link" / w.name / "cli.seed")}
    if case == "grep":
        return "Grep", {"pattern": ".", "path": str(kh)}
    if case == "glob":
        return "Glob", {"pattern": "**/*.seed", "path": str(kh)}
    if case == "write_pins":
        return "Write", {"file_path": str(pins), "content": '{"cli": "attacker"}'}
    if case == "edit_pins":
        return "Edit", {"file_path": str(pins), "old_string": "{}", "new_string": '{"cli": "attacker"}'}
    if case == "cat_abs":
        return "Bash", {"command": f'cat "{seed}"'}
    if case == "cat_dollar_var":
        return "Bash", {"command": (f"cat $LOCALAPPDATA/agg/keys/{rel}" if WINDOWS
                                    else f"cat $HOME/.local/share/agg/keys/{rel}")}
    if case == "type_percent_var":
        return "Bash", {"command": (f"type %LOCALAPPDATA%\\agg\\keys\\{w.name}\\cli.seed" if WINDOWS
                                    else f"cat ${{HOME}}/.local/share/agg/keys/{rel}")}
    if case == "cat_ps_env":
        return "Bash", {"command": (f"cat $env:LOCALAPPDATA\\agg\\keys\\{w.name}\\cli.seed" if WINDOWS
                                    else f'cat "$HOME"/.local/share/agg/keys/{rel}')}
    if case == "cat_tilde":
        return "Bash", {"command": (f"cat ~\\AppData\\Local\\agg\\keys\\{w.name}\\cli.seed" if WINDOWS
                                    else f"cat ~/.local/share/agg/keys/{rel}")}
    if case == "cat_case_variant":
        return "Bash", {"command": (f'cat "{str(seed).upper()}"' if WINDOWS
                                    else f'cat "{str(seed).replace("/", "//")}"')}
    if case == "cat_short_name":
        return "Bash", {"command": f'cat "{_short_name(seed)}"'}
    if case == "cat_via_link":
        return "Bash", {"command": f"cat link/{rel}"}
    raise AssertionError(case)


RED_CASES = ["read", "read_via_link", "grep", "glob", "write_pins", "edit_pins", "cat_abs",
             "cat_case_variant", "cat_short_name", "cat_via_link"]
# Any $VAR already makes a shell command unsafe (escalate) since T0a: guards, not RED.
# T0f: `%VAR%` and a leading `~` are outside the static subset, so they escalate too
# (moved here from RED_CASES, same assertion; T2 still has to deny them outright).
GUARD_CASES = ["cat_dollar_var", "cat_ps_env", "type_percent_var", "cat_tilde"]


@RED_T2
@pytest.mark.parametrize("case", RED_CASES)
def test_key_home_is_denied_to_every_tool(tmp_path, monkeypatch, case):
    lay, kh, w = _hook_setup(tmp_path, monkeypatch)
    tool, tool_input = _tool_case(case, lay, kh, w)
    decision, reason = _hook(lay, tool, tool_input)
    _require(decision not in (None, "allow"), f"{case}: {tool} {tool_input} was let through ({decision!r})")
    assert (w / "cli.seed").read_bytes() == b"\x07" * 32 and (w / "pins.json").read_text() == "{}"


@pytest.mark.parametrize("case", GUARD_CASES)
def test_guard_env_var_reads_of_the_key_home_never_allow(tmp_path, monkeypatch, case):
    lay, kh, w = _hook_setup(tmp_path, monkeypatch)
    tool, tool_input = _tool_case(case, lay, kh, w)
    decision, _ = _hook(lay, tool, tool_input)
    assert decision not in (None, "allow"), tool_input


@pytest.mark.parametrize("command", ["rm {pins}", "mv {pins} {pins}.bak", "Remove-Item {pins}",
                                     "Get-Content {seed}"])
def test_guard_shell_delete_rename_and_ps_read_of_the_key_home_never_allow(tmp_path, monkeypatch, command):
    lay, kh, w = _hook_setup(tmp_path, monkeypatch)
    cmd = command.format(pins=f'"{w / "pins.json"}"', seed=f'"{w / "cli.seed"}"')
    decision, _ = _hook(lay, "Bash", {"command": cmd})
    assert decision not in (None, "allow"), cmd
    assert (w / "pins.json").exists()


def test_guard_ordinary_outside_read_is_unchanged(tmp_path, monkeypatch):
    lay, kh, w = _hook_setup(tmp_path, monkeypatch, relax=False)
    other = tmp_path / "notes.txt"
    other.write_text("hello", encoding="utf-8")
    decision, _ = _hook(lay, "Read", {"file_path": str(other)})
    assert decision in (None, "allow")  # read_outside defaults to observe


# --- rotate, never migrate ---------------------------------------------------------

@RED_T2
def test_pre_m1_in_tree_seed_is_rotated_and_left_in_place(tmp_path, key_home):
    from nacl.signing import SigningKey

    lay = _ws(tmp_path / "ws")
    old = SigningKey.generate()
    seed_path = lay.state_dir / "keys" / "cli.seed"
    seed_path.parent.mkdir(parents=True, exist_ok=True)
    seed_path.write_bytes(bytes(old))
    old_pub = bytes(old.verify_key).hex()

    rec = _approve(lay, _submit(lay), "cli")["result"]
    _require(rec["signer_public_key"] != old_pub, "the exposed pre-M1 in-tree key was used for a new decision")
    _require(bool(_seeds(key_home)), "no new key was generated in the key home")
    assert seed_path.read_bytes() == bytes(old), "the in-tree seed must stay in place, byte-identical"
    _require("key_rotated" in _audit_events(lay), "no key_rotated audit record")


def test_guard_fake_in_tree_seed_survives_the_hook(tmp_path):
    """test_t0_hotfix.py's fixture shape: hook calls never move or delete in-tree seeds."""
    lay = _ws(tmp_path / "ws")
    keys = lay.state_dir / "keys"
    keys.mkdir(parents=True, exist_ok=True)
    (keys / "a.seed").write_bytes(b"\x00" * 32)
    policy = load_policy(lay.policy_file)
    policy.escalation_timeout_seconds = 0
    save_policy(policy, lay.policy_file)
    for tool, tool_input in (("Read", {"file_path": ".sandbox/state/keys/a.seed"}),
                             ("Grep", {"pattern": "x"}), ("Bash", {"command": "git status"})):
        _hook(lay, tool, tool_input)
    assert (keys / "a.seed").read_bytes() == b"\x00" * 32
