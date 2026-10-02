"""Malformed PreToolUse input fails closed, on every path.

Before the fix the stub turned unparseable stdin into ``{}``; pre_tool_use then
saw tool_name "" and classify() applied unknown_tool_action (allow), so the
call went through with an `allowed` record for an empty tool. A JSON array
crashed the stub on ``payload.get`` (exit 1, which Claude Code treats as a
non-blocking error), so it went through as well.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from sandbox.connector.audit import FolderAudit
from sandbox.connector.hook_eval import BAD_INPUT_REASON, pre_tool_use, pre_tool_use_raw
from sandbox.connector.hook_templates import PRETOOLUSE_STUB
from sandbox.connector.install import init
from sandbox.connector.layout import FolderLayout

SRC = str(Path(__file__).resolve().parents[2] / "src")

BAD_INPUTS = {
    "invalid_json": "{not json",
    "json_array": '[{"tool_name": "Bash"}]',
    "no_tool_name": '{"tool_input": {"command": "rm -rf /"}}',
}


@pytest.fixture
def root(tmp_path):
    init(tmp_path, claude=False, mcp=False)
    return tmp_path


def _records(root: Path) -> list[dict]:
    layout = FolderLayout(root)
    sid = json.loads(layout.session_file.read_text(encoding="utf-8"))["session_id"]
    return FolderAudit(layout.audit_dir, sid).list_records(limit=1000)


def _assert_denied_bad_input(out: dict, root: Path) -> None:
    hso = out["hookSpecificOutput"]
    assert hso["hookEventName"] == "PreToolUse"
    assert hso["permissionDecision"] == "deny"
    assert hso["permissionDecisionReason"] == BAD_INPUT_REASON
    recs = _records(root)
    assert [r["event"] for r in recs] == ["denied"]
    assert recs[0]["reason_code"] == "BAD_INPUT"


def _env() -> dict:
    return {"PYTHONPATH": SRC, "SYSTEMROOT": os.environ.get("SYSTEMROOT", "")}


# -- in-process (the stub's first path) --------------------------------------

@pytest.mark.parametrize("raw", BAD_INPUTS.values(), ids=BAD_INPUTS.keys())
async def test_in_process_denies_bad_input(root, raw):
    out = await pre_tool_use_raw(raw, FolderLayout(root))
    _assert_denied_bad_input(out, root)


async def test_literal_empty_object_is_bad_input(root):
    out = await pre_tool_use_raw("{}", FolderLayout(root))
    _assert_denied_bad_input(out, root)


@pytest.mark.parametrize("payload", [["Bash"], {"cwd": "."}, {"tool_name": ""}, {"tool_name": 7}])
async def test_pre_tool_use_rejects_malformed_payload(root, payload):
    """Direct callers (and stubs installed before this fix) get the same check."""
    out = await pre_tool_use(payload, FolderLayout(root))
    _assert_denied_bad_input(out, root)


async def test_empty_stdin_is_unchanged(root):
    out = await pre_tool_use_raw("  \n", FolderLayout(root))
    assert "permissionDecision" not in out["hookSpecificOutput"]
    assert all(r.get("reason_code") != "BAD_INPUT" for r in _records(root))


async def test_valid_payload_still_evaluated(root):
    raw = json.dumps({"tool_name": "Read", "tool_input": {"file_path": "x.txt"}, "cwd": str(root)})
    out = await pre_tool_use_raw(raw, FolderLayout(root))
    assert "permissionDecision" not in out["hookSpecificOutput"]


# -- subprocess fallback: python -m sandbox.connector.hook_eval ---------------

@pytest.mark.parametrize("raw", BAD_INPUTS.values(), ids=BAD_INPUTS.keys())
def test_module_fallback_denies_bad_input(root, raw):
    proc = subprocess.run(
        [sys.executable, "-m", "sandbox.connector.hook_eval"],
        input=raw, capture_output=True, text=True, env=_env(), cwd=root, timeout=60,
    )
    assert proc.returncode == 0, proc.stderr
    _assert_denied_bad_input(json.loads(proc.stdout), root)


# -- the stub that `sandbox init` installs ------------------------------------

def test_init_installs_the_fixed_stub(root):
    stub = (root / ".sandbox" / "hooks" / "pretooluse.py").read_text(encoding="utf-8")
    assert stub == PRETOOLUSE_STUB
    assert "pre_tool_use_raw(raw, layout)" in stub


@pytest.mark.parametrize("raw", BAD_INPUTS.values(), ids=BAD_INPUTS.keys())
def test_installed_stub_denies_bad_input(root, raw):
    proc = subprocess.run(
        [sys.executable, str(root / ".sandbox" / "hooks" / "pretooluse.py")],
        input=raw, capture_output=True, text=True, env=_env(), cwd=root, timeout=60,
    )
    assert proc.returncode == 0, proc.stderr
    _assert_denied_bad_input(json.loads(proc.stdout), root)


# -- PostToolUse and SessionStart are unaffected ------------------------------

@pytest.mark.parametrize("raw", ["{not json", "", '{"tool_input": {}}'])
def test_post_mode_unaffected(root, raw):
    proc = subprocess.run(
        [sys.executable, "-m", "sandbox.connector.hook_eval", "--post"],
        input=raw, capture_output=True, text=True, env=_env(), cwd=root, timeout=60,
    )
    assert proc.returncode == 0
    assert "permissionDecision" not in proc.stdout
    assert all(r.get("reason_code") != "BAD_INPUT" for r in _records(root))


def test_session_start_stub_unaffected(root):
    proc = subprocess.run(
        [sys.executable, str(root / ".sandbox" / "hooks" / "sessionstart.py")],
        input="{not json", capture_output=True, text=True, env=_env(), cwd=root, timeout=60,
    )
    assert proc.returncode == 0
    hso = json.loads(proc.stdout)["hookSpecificOutput"]
    assert hso["hookEventName"] == "SessionStart"
    assert hso["additionalContext"]
