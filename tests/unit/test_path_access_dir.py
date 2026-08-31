"""request_path_access read must handle directories, not just files.

Regression: asking the sandbox to "show what's in E:\\x" (a directory) failed
with exit 1 because the read handler only did read_text() — and that failure
was reported to the model as a misleading "denied".
"""
from __future__ import annotations

import asyncio

from sandbox.connector.broker import FolderBroker


def test_read_directory_lists_contents(tmp_path):
    (tmp_path / "a.txt").write_text("hi")
    (tmp_path / "sub").mkdir()

    res = asyncio.run(FolderBroker().execute({
        "request_id": "r1", "kind": "path_access",
        "path": str(tmp_path), "mode": "read",
    }, "cli:dell"))

    assert res["state"] == "executed"
    assert res["exit_code"] == 0
    assert "a.txt" in res["stdout"]
    assert "sub" in res["stdout"]
    assert "<DIR>" in res["stdout"]


def test_read_file_still_returns_text(tmp_path):
    f = tmp_path / "note.txt"
    f.write_text("secret contents")
    res = asyncio.run(FolderBroker().execute({
        "request_id": "r2", "kind": "path_access",
        "path": str(f), "mode": "read",
    }, "cli"))
    assert res["state"] == "executed"
    assert "secret contents" in res["stdout"]


def test_read_missing_path_gives_clear_error(tmp_path):
    res = asyncio.run(FolderBroker().execute({
        "request_id": "r3", "kind": "path_access",
        "path": str(tmp_path / "nope.txt"), "mode": "read",
    }, "cli"))
    assert res["state"] == "failed"
    assert res["exit_code"] == 1
    assert "does not exist" in res["stderr"]


def test_empty_directory_read(tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()
    res = asyncio.run(FolderBroker().execute({
        "request_id": "r4", "kind": "path_access",
        "path": str(empty), "mode": "read",
    }, "cli"))
    assert res["state"] == "executed"
    assert "empty directory" in res["stdout"]
