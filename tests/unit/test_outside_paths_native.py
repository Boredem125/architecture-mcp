"""OS-native twins of 5 Class C outside-folder tests (T12).

The originals hard-code Windows paths ("C:\\Windows\\evil.txt", ...). On
POSIX those are relative names, so they resolve *inside* the folder and the
tests fail on Linux CI. The originals stay byte-identical (Class C) and are
deselected on ubuntu only; these twins assert the same verdicts and reasons
with an absolute path outside the folder on the running OS, so they run and
pass on Windows and Linux.

| Twin | Original (Class C) |
|---|---|
| test_native_write_outside_folder_denied_by_default | test_classify.py::test_write_outside_folder_denied_by_default |
| test_native_read_outside_folder_observed | test_classify.py::test_read_outside_folder_observed |
| test_native_read_outside_is_observed_not_blocked | test_hook_eval_m4.py::test_read_outside_is_observed_not_blocked |
| test_native_write_outside_denied_with_pointer | test_hook_eval_m4.py::test_write_outside_denied_with_pointer |
| test_native_risk_upgrades_sensitive_read_from_observe_to_escalate | test_hook_eval_m4.py::test_risk_upgrades_sensitive_read_from_observe_to_escalate |
"""
from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path

import pytest

from sandbox.connector.audit import FolderAudit
from sandbox.connector.classify import classify
from sandbox.connector.hook_eval import pre_tool_use
from sandbox.connector.install import init
from sandbox.connector.layout import FolderLayout
from sandbox.connector.policy import default_policy

if os.name == "nt":
    OUTSIDE = {
        "write": "C:\\Windows\\evil.txt",
        "read": "C:\\Windows\\System32\\drivers\\etc\\hosts",
        "plain": "C:\\Users\\dell\\notes.txt",
        "key": "C:\\Users\\dell\\.ssh\\id_rsa",
    }
else:
    OUTSIDE = {
        "write": "/etc/evil.txt",
        "read": "/etc/hosts",
        "plain": "/home/dell/notes.txt",
        "key": "/root/.ssh/id_rsa",
    }


def _outside(kind: str, root: Path) -> str:
    """The path for this OS, checked to be absolute and outside ``root``."""
    path = OUTSIDE[kind]
    p = Path(path)
    assert p.is_absolute(), f"{path!r} is not absolute on {os.name}"
    resolved_root = root.resolve()
    assert resolved_root not in p.resolve().parents and p.resolve() != resolved_root, \
        f"{path!r} is inside the test folder {root}"
    return path


@pytest.fixture
def layout(tmp_path):
    lay = FolderLayout(tmp_path)
    lay.ensure_dirs()
    return lay


@pytest.fixture
def installed(tmp_path):
    init(tmp_path, claude=False, mcp=False)
    return FolderLayout(tmp_path)


# --- classify (twins of test_classify.py) -----------------------------------

def test_native_write_outside_folder_denied_by_default(layout):
    c = classify("Write", {"file_path": _outside("write", layout.root)}, default_policy(), layout)
    assert c.verdict == "deny"
    assert c.trigger == "write_outside"
    assert "request_path_access" in c.reason


def test_native_read_outside_folder_observed(layout):
    c = classify("Read", {"file_path": _outside("read", layout.root)}, default_policy(), layout)
    assert c.verdict == "observe"
    assert c.trigger == "read_outside"


# --- hook (twins of test_hook_eval_m4.py) -----------------------------------

def test_native_read_outside_is_observed_not_blocked(installed):
    payload = {
        "tool_name": "Read",
        "tool_input": {"file_path": _outside("read", installed.root)},
        "cwd": str(installed.root),
    }
    result = asyncio.run(pre_tool_use(payload, installed))
    assert "permissionDecision" not in result["hookSpecificOutput"]

    session = json.loads(installed.session_file.read_text())
    records = FolderAudit(installed.audit_dir, session["session_id"]).list_records()
    assert any(r.get("event") == "observed" for r in records)


def test_native_write_outside_denied_with_pointer(installed):
    payload = {
        "tool_name": "Write",
        "tool_input": {"file_path": _outside("write", installed.root), "content": "x"},
        "cwd": str(installed.root),
    }
    result = asyncio.run(pre_tool_use(payload, installed))
    hso = result["hookSpecificOutput"]
    assert hso["permissionDecision"] == "deny"
    assert "request_path_access" in hso["permissionDecisionReason"]


def test_native_risk_upgrades_sensitive_read_from_observe_to_escalate(installed):
    plain = asyncio.run(pre_tool_use({
        "tool_name": "Read",
        "tool_input": {"file_path": _outside("plain", installed.root)},
        "cwd": str(installed.root),
    }, installed))
    assert "permissionDecision" not in plain["hookSpecificOutput"]

    sensitive = asyncio.run(pre_tool_use({
        "tool_name": "Read",
        "tool_input": {"file_path": _outside("key", installed.root)},
        "cwd": str(installed.root),
    }, installed))
    # read_outside can't run in the hook, so an escalate becomes a redirect deny.
    assert sensitive["hookSpecificOutput"].get("permissionDecision") == "deny"
