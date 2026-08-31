"""The human-readable change journal (.sandbox/changes/).

Each file modification produces one readable entry: what changed (unified diff),
who/when, old->new hashes, a pointer to the preserved old version, and the
restore command. Regression for the NameError('Path') bug that silently
swallowed every entry.
"""
from __future__ import annotations

import asyncio

import pytest

from sandbox.connector.hook_eval import post_tool_use, pre_tool_use
from sandbox.connector.install import init
from sandbox.connector.layout import FolderLayout


@pytest.fixture
def layout(tmp_path):
    init(tmp_path, claude=False, mcp=False)
    return FolderLayout(tmp_path)


def _edit(layout, rel, before, after, tool="Edit", agent="claude-code"):
    target = layout.root / rel
    if before is not None:
        target.write_text(before)
    payload = {"tool_name": tool, "tool_input": {"file_path": str(target)},
               "cwd": str(layout.root), "agent": {"kind": agent}}
    asyncio.run(pre_tool_use(payload, layout))
    target.write_text(after)
    asyncio.run(post_tool_use(payload, layout))


def test_modification_writes_readable_diff(layout):
    _edit(layout, "app.py", "a\nb\n", "a\nc\n")
    entries = sorted(layout.changes_dir.glob("*.txt"))
    assert len(entries) == 1
    body = entries[0].read_text()
    assert "File    : app.py" in body
    assert "Action  : modified" in body
    assert "-b" in body and "+c" in body          # the unified diff
    assert "Old copy: .sandbox/originals/" in body  # preserved old version
    assert 'sandbox restore "app.py"' in body


def test_new_file_marks_no_prior_version(layout):
    _edit(layout, "fresh.py", None, "x = 1\n", tool="Write", agent="codex")
    body = sorted(layout.changes_dir.glob("*.txt"))[0].read_text()
    assert "Old sha : (new file)" in body
    assert "codex" in body


def test_no_op_write_creates_no_entry(layout):
    """Writing identical content must not spam the journal."""
    _edit(layout, "same.py", "unchanged\n", "unchanged\n")
    assert list(layout.changes_dir.glob("*.txt")) == []


def test_entries_are_sequentially_numbered(layout):
    _edit(layout, "a.py", "1\n", "2\n")
    _edit(layout, "b.py", "1\n", "2\n")
    names = sorted(p.name for p in layout.changes_dir.glob("*.txt"))
    assert names[0].startswith("0001__")
    assert names[1].startswith("0002__")


def test_old_version_is_recoverable_from_pointer(layout):
    _edit(layout, "recover.py", "original\n", "changed\n")
    body = sorted(layout.changes_dir.glob("*.txt"))[0].read_text()
    ptr = next(l for l in body.splitlines() if l.startswith("Old copy:"))
    rel = ptr.split("Old copy:")[1].strip()
    old_blob = layout.root / rel
    assert old_blob.read_text() == "original\n"
