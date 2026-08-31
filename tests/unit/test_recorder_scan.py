"""SessionRecorder change detection: created / modified / deleted (bugs 2 & 3)."""
from __future__ import annotations

import os
import time

from sandbox.launcher.recorder import SessionRecorder


def _touch(p, content: str) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")


def test_detects_created(tmp_path):
    rec = SessionRecorder(tmp_path)
    _touch(tmp_path / "a.txt", "hello")
    changes = rec.scan_changes()
    assert {"path": "a.txt", "type": "created"} in changes


def test_detects_modified(tmp_path):
    _touch(tmp_path / "a.txt", "hello")
    rec = SessionRecorder(tmp_path)
    time.sleep(0.01)
    _touch(tmp_path / "a.txt", "hello world")  # same path, new content
    changes = rec.scan_changes()
    assert {"path": "a.txt", "type": "modified"} in changes


def test_detects_deleted(tmp_path):
    _touch(tmp_path / "a.txt", "hello")
    rec = SessionRecorder(tmp_path)
    (tmp_path / "a.txt").unlink()
    changes = rec.scan_changes()
    assert {"path": "a.txt", "type": "deleted"} in changes


def test_same_size_different_content_is_modified(tmp_path):
    _touch(tmp_path / "a.txt", "aaaa")
    rec = SessionRecorder(tmp_path)
    time.sleep(0.01)
    _touch(tmp_path / "a.txt", "bbbb")  # identical size, different bytes
    changes = rec.scan_changes()
    assert {"path": "a.txt", "type": "modified"} in changes


def test_ignore_dirs_pruned(tmp_path):
    _touch(tmp_path / "node_modules" / "junk.js", "x")
    _touch(tmp_path / "src" / "real.py", "y")
    rec = SessionRecorder(tmp_path, ignore_dirs=["node_modules", ".sandbox_logs", ".trash", "broker_out"])
    _touch(tmp_path / "node_modules" / "more.js", "z")
    _touch(tmp_path / "src" / "new.py", "w")
    changes = rec.scan_changes()
    paths = {c["path"] for c in changes}
    assert os.path.join("src", "new.py") in paths
    assert not any("node_modules" in p for p in paths)


def test_modified_preserved_to_trash(tmp_path):
    _touch(tmp_path / "a.txt", "original")
    rec = SessionRecorder(tmp_path)
    time.sleep(0.01)
    _touch(tmp_path / "a.txt", "changed")
    rec.scan_changes()
    trash = list((tmp_path / ".trash").iterdir())
    assert trash, "modified file should leave a copy in .trash"
