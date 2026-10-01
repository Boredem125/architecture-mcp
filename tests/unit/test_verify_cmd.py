"""`sandbox verify`: every session's chain, links AND record contents.

Before, it checked only the "default" session and only the links between
records, so an edited record (with links intact) and every real session's
chain went unchecked.
"""
from __future__ import annotations

import json

import pytest
from click.testing import CliRunner

from sandbox.cli.main import cli
from sandbox.connector.audit import FolderAudit
from sandbox.connector.install import init
from sandbox.connector.layout import FolderLayout


@pytest.fixture
def folder(tmp_path):
    init(tmp_path, claude=False, mcp=False)
    layout = FolderLayout(tmp_path)
    for sid in ("s1", "s2"):
        audit = FolderAudit(layout.audit_dir, sid)
        for n in range(3):
            audit.append({"event": "test", "n": n, "session_id": sid})
    return layout


def verify(layout, *args):
    return CliRunner().invoke(cli, ["verify", str(layout.root), *args])


def edit_line(layout, sid, index, **changes):
    path = layout.audit_dir / sid / "records.jsonl"
    lines = path.read_text(encoding="utf-8").splitlines()
    rec = json.loads(lines[index])
    rec.update(changes)
    lines[index] = json.dumps(rec)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def test_every_session_is_checked(folder):
    r = verify(folder)
    assert r.exit_code == 0, r.output
    assert "s1: chain valid (3 records)" in r.output and "s2: chain valid (3 records)" in r.output


def test_edited_content_with_intact_links_is_caught(folder):
    edit_line(folder, "s2", 1, n=99)  # links (previous_hash, chain_length, record_hash) untouched
    r = verify(folder)
    assert r.exit_code == 1
    assert "s2: line 2: record content does not match its record_hash" in r.output
    assert "s1: chain valid" in r.output


def test_records_removed_from_the_end_need_a_recorded_head(folder):
    head = json.loads(verify(folder, "--json").output)["sessions"]["s1"]["head_hash"]
    path = folder.audit_dir / "s1" / "records.jsonl"
    path.write_text("\n".join(path.read_text(encoding="utf-8").splitlines()[:2]) + "\n", encoding="utf-8")
    assert verify(folder).exit_code == 0  # truncation alone is invisible in the file
    r = verify(folder, "--expect-head", f"s1={head}")
    assert r.exit_code == 1 and "records removed or rewritten at the end" in r.output


def test_single_session_and_json(folder):
    edit_line(folder, "s2", 0, n=5)
    assert verify(folder, "--session", "s1").exit_code == 0
    out = json.loads(verify(folder, "--json").output)
    assert out["ok"] is False and out["sessions"]["s1"]["ok"] and not out["sessions"]["s2"]["ok"]
    assert verify(folder, "--session", "nope").exit_code == 1
