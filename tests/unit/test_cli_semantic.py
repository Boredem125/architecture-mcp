from __future__ import annotations

import json

from click.testing import CliRunner

from sandbox.cli.main import cli
from sandbox.connector.install import init
from sandbox.connector.layout import FolderLayout
from sandbox.connector.policy import load_policy
from sandbox.semantic import taint


def _layout(tmp_path):
    init(tmp_path, claude=False, mcp=False)
    return FolderLayout(tmp_path)


def test_enable_disable(tmp_path):
    layout = _layout(tmp_path)
    runner = CliRunner()
    r = runner.invoke(cli, ["semantic", "enable", str(tmp_path), "--url", "http://127.0.0.1:9999"])
    assert r.exit_code == 0, r.output
    sem = load_policy(layout.policy_file).semantic
    assert sem.enabled and sem.url == "http://127.0.0.1:9999"
    assert runner.invoke(cli, ["semantic", "disable", str(tmp_path)]).exit_code == 0
    assert load_policy(layout.policy_file).semantic.enabled is False


def test_status_reports_unreachable_service_and_taint(tmp_path):
    layout = _layout(tmp_path)
    runner = CliRunner()
    runner.invoke(cli, ["semantic", "enable", str(tmp_path), "--url", "http://127.0.0.1:9"])
    taint.mark(layout.state_dir, {"tool": "WebFetch", "top_check": "instructs_ai", "top_score": 0.99,
                                  "segment_index": 2, "segment_count": 5, "text_sha256": "ab" * 32}, ttl_seconds=60)
    r = runner.invoke(cli, ["semantic", "status", str(tmp_path)])
    assert r.exit_code == 0, r.output
    assert "Reachable: no" in r.output
    assert "ACTIVE" in r.output and "WebFetch" in r.output


def test_clear_taint_requires_reviewer_and_is_audited(tmp_path):
    layout = _layout(tmp_path)
    taint.mark(layout.state_dir, {"tool": "Read", "top_check": "override", "top_score": 0.9}, ttl_seconds=60)
    runner = CliRunner()
    assert runner.invoke(cli, ["semantic", "clear-taint", str(tmp_path)]).exit_code != 0  # reviewer + reason required
    r = runner.invoke(cli, ["semantic", "clear-taint", str(tmp_path), "--reviewer", "alice", "--reason", "checked, false positive"])
    assert r.exit_code == 0, r.output
    assert taint.read(layout.state_dir) is None

    from sandbox.connector.audit import FolderAudit

    session_id = json.loads(layout.session_file.read_text())["session_id"]
    events = [e for e in FolderAudit(layout.audit_dir, session_id).list_records() if e.get("event") == "taint_cleared"]
    assert events and events[0]["reviewer"] == "alice"
