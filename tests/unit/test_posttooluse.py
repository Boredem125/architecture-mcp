"""PostToolUse must never emit a PreToolUse-shaped payload.

Regression for the live bug: Claude Code rejected the hook with
"expected 'PostToolUse' but got 'PreToolUse'" because post_tool_use returned
_pre_output(...), which hard-codes hookEventName='PreToolUse'. PostToolUse is a
pure side-effect hook and must emit nothing.
"""
from __future__ import annotations

import asyncio

import pytest

from sandbox.connector.hook_eval import post_tool_use
from sandbox.connector.install import init
from sandbox.connector.layout import FolderLayout


@pytest.fixture
def layout(tmp_path):
    init(tmp_path, claude=False, mcp=False)
    return FolderLayout(tmp_path)


def test_posttooluse_on_bash_emits_nothing(layout):
    """A Bash tool call (not a write) must produce an empty result."""
    result = asyncio.run(post_tool_use({
        "tool_name": "Bash",
        "tool_input": {"command": "ls"},
        "cwd": str(layout.root),
    }, layout))
    assert result == {}
    # Never carries a PreToolUse event name.
    assert "hookSpecificOutput" not in result


def test_posttooluse_on_read_emits_nothing(layout):
    result = asyncio.run(post_tool_use({
        "tool_name": "Read",
        "tool_input": {"file_path": str(layout.root / "x.txt")},
        "cwd": str(layout.root),
    }, layout))
    assert result == {}


def test_posttooluse_on_write_records_but_emits_nothing(layout):
    """A write is recorded to the timeline, but the hook still emits nothing."""
    target = layout.root / "app.py"
    target.write_text("v2")

    result = asyncio.run(post_tool_use({
        "tool_name": "Write",
        "tool_input": {"file_path": str(target)},
        "session_id": "s-1",
        "cwd": str(layout.root),
    }, layout))
    assert result == {}
    assert "hookSpecificOutput" not in result
    # The change was logged to the originals timeline.
    assert (layout.originals_dir / "index.jsonl").exists()


def test_posttooluse_stub_writes_nothing_for_empty_result():
    """The stub's `if result:` gate means an empty dict prints nothing."""
    from sandbox.connector.hook_templates import POSTTOOLUSE_STUB

    # The stub only writes stdout when the result is truthy.
    assert "if result:" in POSTTOOLUSE_STUB
