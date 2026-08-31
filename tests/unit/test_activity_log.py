"""The human-readable activity log — the friendly companion to the audit chain.

Regression for "why aren't logs getting saved?": the .sandbox/logs/ dir was
created but nothing ever wrote to it, so the obvious place looked empty.
"""
from __future__ import annotations

import pytest

from sandbox.connector.broker import FolderBroker
from sandbox.connector.install import init
from sandbox.connector.layout import FolderLayout
from sandbox.connector.queue import EscalationQueue


@pytest.fixture
def layout(tmp_path):
    init(tmp_path, claude=False, mcp=False)
    return FolderLayout(tmp_path)


def test_submit_and_finish_write_activity_log(layout):
    queue = EscalationQueue(layout)
    rid = queue.submit({
        "root": str(layout.root), "trigger": ["shell"], "kind": "command",
        "command": "pip install cowsay",
        "identity": {"agent_type": "claude-code"}, "risk": {"score": 55},
    })
    rec = queue.claim(rid, "cli:dell")
    queue.finish(rid, FolderBroker.denial(rec, "cli:dell", "nope"))

    log = (layout.logs_dir / "activity.log").read_text(encoding="utf-8")
    assert "ESCALATED" in log
    assert "DENIED" in log
    assert "pip install cowsay" in log
    assert "claude-code" in log
    assert "cli:dell" in log


def test_logs_dir_not_empty_after_activity(layout):
    """The obvious place (.sandbox/logs/) actually contains something now."""
    queue = EscalationQueue(layout)
    queue.submit({
        "root": str(layout.root), "trigger": ["shell"], "kind": "command",
        "command": "whoami",
    })
    assert (layout.logs_dir / "activity.log").exists()
    assert list(layout.logs_dir.iterdir())  # non-empty
