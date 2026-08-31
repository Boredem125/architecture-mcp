"""FolderBroker dispatch on record kind — path_access and fetch."""
from __future__ import annotations

import asyncio

from sandbox.connector.broker import FolderBroker


def test_path_access_write(tmp_path):
    target = tmp_path / "outside" / "note.txt"
    record = {
        "request_id": "r1",
        "kind": "path_access",
        "path": str(target),
        "mode": "write",
        "content": "hello world",
    }
    broker = FolderBroker()
    result = asyncio.run(broker.execute(record, "cli"))
    assert result["state"] == "executed"
    assert target.read_text() == "hello world"


def test_path_access_read(tmp_path):
    target = tmp_path / "data.txt"
    target.write_text("secret contents")
    record = {
        "request_id": "r2",
        "kind": "path_access",
        "path": str(target),
        "mode": "read",
    }
    broker = FolderBroker()
    result = asyncio.run(broker.execute(record, "cli"))
    assert result["state"] == "executed"
    assert "secret contents" in result["stdout"]


def test_path_access_read_missing_file_fails(tmp_path):
    record = {
        "request_id": "r3",
        "kind": "path_access",
        "path": str(tmp_path / "nope.txt"),
        "mode": "read",
    }
    broker = FolderBroker()
    result = asyncio.run(broker.execute(record, "cli"))
    assert result["state"] == "failed"
    assert result["exit_code"] == 1
