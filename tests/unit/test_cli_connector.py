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
    rid = queue.submit({
        "command": f'{sys.executable} -c "print(7)"',
        "trigger": ["shell"], "root": str(tmp_path),
        "exec_cwd": str(tmp_path),
    })

    r = runner.invoke(cli, ["approve", rid, str(tmp_path)])
    assert r.exit_code == 0, r.output
    assert "exit 0" in r.output
    assert queue.status(rid) == "done"
    assert "7" in (queue._layout.out_dir / f"{rid}.txt").read_text()
