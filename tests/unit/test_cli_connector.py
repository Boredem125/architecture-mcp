"""Smoke tests for the connector CLI via click's CliRunner."""
from __future__ import annotations

import sys

from click.testing import CliRunner

from sandbox.cli.main import cli


def test_init_and_status(tmp_path):
    runner = CliRunner()
    r = runner.invoke(cli, ["init", str(tmp_path), "--no-claude"])
    assert r.exit_code == 0, r.output
    assert "initialized" in r.output

    r2 = runner.invoke(cli, ["status", str(tmp_path)])
    assert r2.exit_code == 0, r2.output
    assert "Pending:  0" in r2.output


def test_status_without_init_fails_cleanly(tmp_path):
    runner = CliRunner()
    r = runner.invoke(cli, ["status", str(tmp_path)])
    assert r.exit_code == 1
    assert "No .sandbox/" in r.output


def test_approve_runs_a_queued_command(tmp_path):
    from sandbox.connector.layout import FolderLayout
    from sandbox.connector.queue import EscalationQueue

    runner = CliRunner()
    runner.invoke(cli, ["init", str(tmp_path), "--no-claude"])

    queue = EscalationQueue(FolderLayout(tmp_path))
    # Named test-setup edit (T12c c2): fp_v=2, tool_name required by broker;
    # POSIX-form path for bash -c (T12c: broker runs through bash, not cmd.exe)
    from pathlib import Path as _P
    rid = queue.submit({
        "command": f"'{_P(sys.executable).as_posix()}' -c \"print(7)\"",
        "trigger": ["shell"], "root": str(tmp_path),
        "exec_cwd": str(tmp_path),
        "kind": "command", "tool_name": "Bash", "fp_v": 2,
        "script": None, "script_unbound": "", "script_preview": None,
    })

    r = runner.invoke(cli, ["approve", rid, str(tmp_path)])
    assert r.exit_code == 0, r.output
    assert "exit 0" in r.output
    assert queue.status(rid) == "done"
    assert "7" in (queue._layout.out_dir / f"{rid}.txt").read_text()


# ---------------------------------------------------------------------------
# T16c-1: status_cmd must surface managed / locked from sync/state.py
# ---------------------------------------------------------------------------
# Product gap: status_cmd does not yet call is_managed / is_locked.
# These strict-xfail tests prove that once it does, the output contains
# the expected fields in both text and --json modes.

import json as _json
import pytest


class M2T16StatusPending(Exception):
    """Raised when status_cmd does not yet include managed/locked fields."""


def _make_managed(tmp_path):
    """Create a .sandbox workspace that is_managed() recognises as managed."""
    runner = CliRunner()
    r = runner.invoke(cli, ["init", str(tmp_path), "--no-claude"])
    assert r.exit_code == 0, r.output
    # Write the sync-dir managed marker so is_managed() returns True
    sync_dir = tmp_path / ".sandbox" / "state" / "sync"
    sync_dir.mkdir(parents=True, exist_ok=True)
    (sync_dir / "managed").write_text("1", encoding="utf-8")
    return runner


def test_t16_status_text_shows_managed(tmp_path):
    """Text output must contain a 'Managed: yes' (or similar) line."""
    runner = _make_managed(tmp_path)
    r = runner.invoke(cli, ["status", str(tmp_path)])
    assert r.exit_code == 0, r.output
    lower = r.output.lower()
    if "managed" not in lower:
        raise M2T16StatusPending("text output lacks 'managed' field")
    assert "yes" in lower or "true" in lower, f"managed present but not affirmative: {r.output}"


def test_t16_status_json_shows_managed(tmp_path):
    """JSON output must contain a 'managed' key set to true."""
    runner = _make_managed(tmp_path)
    r = runner.invoke(cli, ["status", str(tmp_path), "--json"])
    assert r.exit_code == 0, r.output
    data = _json.loads(r.output)
    if "managed" not in data:
        raise M2T16StatusPending("JSON output lacks 'managed' key")
    assert data["managed"] is True, f"managed key present but not True: {data}"


def test_t16_status_text_shows_locked(tmp_path):
    """Text output must contain a 'Locked: yes' line when managed + no bundle."""
    runner = _make_managed(tmp_path)
    # managed marker exists but NO bundle.json and NO policy_history
    # so is_locked() returns True
    r = runner.invoke(cli, ["status", str(tmp_path)])
    assert r.exit_code == 0, r.output
    lower = r.output.lower()
    if "locked" not in lower:
        raise M2T16StatusPending("text output lacks 'locked' field")
    assert "yes" in lower or "true" in lower, f"locked present but not affirmative: {r.output}"


def test_t16_status_json_shows_locked(tmp_path):
    """JSON output must contain a 'locked' key set to true when managed + no bundle."""
    runner = _make_managed(tmp_path)
    r = runner.invoke(cli, ["status", str(tmp_path), "--json"])
    assert r.exit_code == 0, r.output
    data = _json.loads(r.output)
    if "locked" not in data:
        raise M2T16StatusPending("JSON output lacks 'locked' key")
    assert data["locked"] is True, f"locked key present but not True: {data}"


def test_t16_status_unmanaged_no_managed_field(tmp_path):
    """Guard twin: unmanaged workspace must NOT claim managed in --json."""
    runner = CliRunner()
    r = runner.invoke(cli, ["init", str(tmp_path), "--no-claude"])
    assert r.exit_code == 0, r.output
    r2 = runner.invoke(cli, ["status", str(tmp_path), "--json"])
    assert r2.exit_code == 0, r2.output
    data = _json.loads(r2.output)
    # managed may be absent or False; must not be True
    assert data.get("managed") is not True, f"unmanaged workspace claims managed: {data}"
