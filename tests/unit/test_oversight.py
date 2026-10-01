"""Oversight indicators and approval-fatigue detection (connector/oversight.py).

Records are made through the real queue and approval path; timestamps are
then set to known values where a test needs exact numbers.
"""
from __future__ import annotations

import asyncio
import json
import time

import pytest
from click.testing import CliRunner

from sandbox.connector.approval import approve
from sandbox.connector.audit import FolderAudit
from sandbox.connector.broker import FolderBroker
from sandbox.connector.install import init
from sandbox.connector.layout import FolderLayout
from sandbox.connector.oversight import _bursts, assess_fatigue, compute_metrics
from sandbox.connector.policy import load_policy, save_policy
from sandbox.connector.queue import EscalationQueue


@pytest.fixture
def layout(tmp_path):
    init(tmp_path, claude=False, mcp=False)
    return FolderLayout(tmp_path)


def configure(layout, **kw):
    p = load_policy(layout.policy_file)
    for k, v in kw.items():
        setattr(p.oversight, k, v)
    save_policy(p, layout.policy_file)


_n = 0


def submit_tool_call(layout, **extra) -> str:
    """A request that needs no subprocess to approve (issues a grant)."""
    global _n
    _n += 1
    return EscalationQueue(layout).submit({
        "kind": "tool_call", "tool_name": "mcp__t__op", "command": f"op {_n}",
        "fingerprint": f"fp-{_n}-{time.time()}", "root": str(layout.root), **extra,
    })


def submit_command(layout, **extra) -> str:
    return EscalationQueue(layout).submit({
        "kind": "command", "command": "echo oversight-test", "exec_cwd": str(layout.root),
        "root": str(layout.root), "trigger": ["shell"], **extra,
    })


def run(layout, rid, reviewer, reason=""):
    return asyncio.run(approve(layout, rid, reviewer, reason))


def deny(layout, rid, reviewer):
    queue = EscalationQueue(layout)
    rec = queue.claim(rid, reviewer)
    queue.finish(rid, FolderBroker.denial(rec, reviewer, "no"))


def set_times(layout, rid, **fields):
    path = layout.done_dir / f"{rid}.json"
    rec = json.loads(path.read_text(encoding="utf-8"))
    rec.update(fields)
    path.write_text(json.dumps(rec), encoding="utf-8")


def approvals_by(layout, reviewer, n, age=0.0):
    """n approvals by *reviewer*; each request was created *age* seconds earlier."""
    for _ in range(n):
        rid = submit_tool_call(layout, created_at=time.time() - age)
        assert run(layout, rid, reviewer)["status"] == "executed"


def audit_events(layout):
    out = []
    for f in layout.audit_dir.glob("*/records.jsonl"):
        out += [json.loads(line) for line in f.read_text(encoding="utf-8").splitlines() if line.strip()]
    return [e for e in out if e.get("event") == "oversight_fatigue"]


# --- metrics ---------------------------------------------------------------

def test_metrics_on_records_with_known_timestamps(layout):
    t0 = time.time() - 3600
    plan = [("alice", t0, t0 + 2), ("alice", t0 + 100, t0 + 130), ("alice", t0 + 200, t0 + 210)]
    for reviewer, created, decided in plan:
        rid = submit_tool_call(layout)
        run(layout, rid, reviewer)
        set_times(layout, rid, created_at=created, approved_at=decided, decided_at=decided)
    rid = submit_tool_call(layout)
    deny(layout, rid, "bob")
    set_times(layout, rid, created_at=t0 + 300, decided_at=t0 + 360)
    submit_tool_call(layout, created_at=time.time() - 1000)  # past the 300 s timeout
    submit_tool_call(layout)  # fresh, still within it

    m = compute_metrics(layout)
    alice, bob = m["reviewers"]["alice"], m["reviewers"]["bob"]
    assert (alice["approvals"], alice["denials"], alice["approval_rate"]) == (3, 0, 1.0)
    assert alice["decision_seconds"] == {"count": 3, "median": 10.0, "p90": 30.0}
    assert (alice["fast_approvals"], alice["fast_approval_share"]) == (1, 0.333)
    assert (bob["approvals"], bob["denials"], bob["approval_rate"]) == (0, 1, 0.0)
    assert bob["decision_seconds"]["median"] == 60.0
    overall = m["overall"]
    assert (overall["approvals"], overall["denials"], overall["approval_rate"]) == (3, 1, 0.75)
    assert overall["decision_seconds"] == {"count": 4, "median": 10.0, "p90": 60.0}  # nearest rank
    assert m["requests"] == {"decided": 4, "approved": 3, "denied": 1, "decided_after_timeout": 0,
                             "pending": 2, "timed_out": 1, "timeout_share": 0.2}
    assert not alice["flagged_now"] and not bob["flagged_now"]


def test_each_signed_approval_of_a_dual_request_counts_for_its_reviewer(layout):
    rid = submit_command(layout, requires_dual=True)
    run(layout, rid, "alice")
    first = compute_metrics(layout)  # the pending 1-of-2 approval already counts
    assert first["reviewers"]["alice"]["approvals"] == 1
    run(layout, rid, "bob")
    m = compute_metrics(layout)
    assert m["reviewers"]["alice"]["approvals"] == 1 and m["reviewers"]["bob"]["approvals"] == 1
    assert m["requests"]["approved"] == 1


def test_since_limits_the_decisions_counted(layout):
    old = submit_tool_call(layout)
    run(layout, old, "alice")
    set_times(layout, old, created_at=time.time() - 7200, approved_at=time.time() - 7190,
              decided_at=time.time() - 7190)
    approvals_by(layout, "alice", 2)
    assert compute_metrics(layout)["reviewers"]["alice"]["approvals"] == 3
    recent = compute_metrics(layout, since=time.time() - 3600)
    assert recent["reviewers"]["alice"]["approvals"] == 2 and recent["requests"]["decided"] == 2


def test_burst_episodes_and_peak():
    times = [0, 10, 20, 30, 40, 1000, 1010]
    assert _bursts(times, 3, 60) == (1, 5)   # 5 inside one minute is one episode of >= 3
    assert _bursts(times, 2, 60) == (3, 5)   # 0-10, 20-30, 1000-1010 (40 alone after the reset)
    assert _bursts([], 3, 60) == (0, 0)


def test_fatigue_events_from_the_audit_log_are_counted(layout):
    FolderAudit(layout.audit_dir, "s").append({"event": "oversight_fatigue", "reviewer_id": "alice",
                                              "at": time.time()})
    m = compute_metrics(layout)
    assert m["reviewers"]["alice"]["fatigue_events"] == 1 and m["overall"]["fatigue_events"] == 1


# --- fatigue rule ------------------------------------------------------------

def test_burst_rule_triggers_at_the_threshold_and_not_below(layout):
    configure(layout, burst_approvals=3, fast_min_approvals=100)
    approvals_by(layout, "alice", 2)
    assert not assess_fatigue(layout, "alice").fatigued
    approvals_by(layout, "alice", 1)
    f = assess_fatigue(layout, "alice")
    assert f.fatigued and f.approvals_in_window == 3 and "3 approvals" in f.reasons[0]
    assert not assess_fatigue(layout, "bob").fatigued  # per reviewer


def test_fast_share_rule_triggers_at_the_threshold_and_not_below(layout):
    configure(layout, burst_approvals=100, fast_min_approvals=4, fast_share=0.75, fast_seconds=5)
    approvals_by(layout, "alice", 3)               # 3 fast, but fewer than 4 approvals
    assert not assess_fatigue(layout, "alice").fatigued
    approvals_by(layout, "alice", 1, age=60)       # 3 of 4 fast = 75%
    f = assess_fatigue(layout, "alice")
    assert f.fatigued and (f.fast_in_window, f.timed_in_window) == (3, 4)

    approvals_by(layout, "bob", 2)
    approvals_by(layout, "bob", 2, age=60)         # 2 of 4 fast = 50%
    assert not assess_fatigue(layout, "bob").fatigued


def test_approvals_outside_the_window_do_not_count(layout):
    configure(layout, burst_approvals=3, fast_min_approvals=100, window_minutes=10)
    for _ in range(3):
        rid = submit_tool_call(layout)
        run(layout, rid, "alice")
        old = time.time() - 11 * 60
        set_times(layout, rid, created_at=old - 1, approved_at=old, decided_at=old)
    assert not assess_fatigue(layout, "alice").fatigued


def test_disabled_detection_never_flags(layout):
    configure(layout, enabled=False, burst_approvals=1)
    approvals_by(layout, "alice", 2)
    assert not assess_fatigue(layout, "alice").fatigued
    rid = submit_command(layout)
    out = run(layout, rid, "alice")
    assert out["status"] == "executed" and "oversight" not in out


# --- the response actually applies -------------------------------------------

def test_flagged_reviewers_single_approval_no_longer_runs_the_request(layout):
    configure(layout, burst_approvals=3, fast_min_approvals=100)
    approvals_by(layout, "alice", 3)
    rid = submit_command(layout)
    queue = EscalationQueue(layout)

    refused = run(layout, rid, "alice")  # no reason
    assert refused["status"] == "reason_required"
    assert queue.status(rid) == "pending" and not (layout.done_dir / f"{rid}.json").exists()

    out = run(layout, rid, "alice", "checked: it only echoes a string")
    assert out["status"] == "awaiting_second" and out["oversight"]["second_reviewer"]
    rec = queue.get(rid)
    assert queue.status(rid) == "pending" and rec["requires_dual"] and rec["dual_reason"] == "approval_fatigue"
    assert run(layout, rid, "alice", "checked again, still fine")["status"] == "same_reviewer"

    done = run(layout, rid, "bob")  # bob is not flagged
    assert done["status"] == "executed" and done["result"]["exit_code"] == 0 and "oversight" not in done
    assert [a["reviewer_id"] for a in done["result"]["approvals"]] == ["alice", "bob"]

    outcomes = [e["outcome"] for e in audit_events(layout)]
    assert outcomes == ["refused_no_reason", "second_reviewer_required", "reason_given"]
    assert audit_events(layout)[1]["reason"] == "checked: it only echoes a string"


def test_reason_only_response_lets_a_reasoned_approval_run(layout):
    configure(layout, burst_approvals=2, fast_min_approvals=100, require_second_reviewer=False)
    approvals_by(layout, "alice", 2)
    rid = submit_command(layout)
    assert run(layout, rid, "alice", "short")["status"] == "reason_required"  # under 10 characters
    out = run(layout, rid, "alice", "reviewed the echo, harmless")
    assert out["status"] == "executed" and out["oversight"]["outcome"] == "reason_given"


def test_a_dual_request_still_needs_exactly_two_when_the_approver_is_flagged(layout):
    configure(layout, burst_approvals=2, fast_min_approvals=100)
    approvals_by(layout, "alice", 2)
    rid = submit_command(layout, requires_dual=True)
    run(layout, rid, "bob")
    out = run(layout, rid, "alice", "second look: harmless echo")
    assert out["status"] == "executed"


def test_below_the_threshold_nothing_changes(layout):
    configure(layout, burst_approvals=3, fast_min_approvals=100)
    approvals_by(layout, "alice", 2)
    rid = submit_command(layout)
    out = run(layout, rid, "alice")
    assert out["status"] == "executed" and set(out) == {"status", "result"}
    assert not out["result"].get("requires_dual") and audit_events(layout) == []


def test_default_thresholds_are_in_the_policy(layout):
    o = load_policy(layout.policy_file).oversight
    assert (o.enabled, o.window_minutes, o.burst_approvals, o.fast_seconds, o.fast_share,
            o.fast_min_approvals, o.require_reason, o.require_second_reviewer) == (
        True, 10.0, 20, 5.0, 0.8, 8, True, True)


# --- CLI ---------------------------------------------------------------------

def test_cli_oversight_reports_and_approve_explains_the_refusal(layout):
    from sandbox.cli.main import cli

    configure(layout, burst_approvals=2, fast_min_approvals=100)
    approvals_by(layout, "alice", 2)
    runner = CliRunner()

    text = runner.invoke(cli, ["oversight", str(layout.root)])
    assert text.exit_code == 0, text.output
    assert "Indicators only" in text.output and "alice" in text.output and "FLAGGED" in text.output

    data = json.loads(runner.invoke(cli, ["oversight", str(layout.root), "--json", "--since", "1h"]).output)
    assert data["reviewers"]["alice"]["approvals"] == 2 and data["reviewers"]["alice"]["flagged_now"]
    assert runner.invoke(cli, ["oversight", str(layout.root), "--since", "soon"]).exit_code != 0

    rid = submit_command(layout)
    refused = runner.invoke(cli, ["approve", rid, str(layout.root), "--reviewer", "alice"])
    assert refused.exit_code == 1 and "--reason" in refused.output
    first = runner.invoke(cli, ["approve", rid, str(layout.root), "--reviewer", "alice",
                                "--reason", "looked at it: harmless echo"])
    assert first.exit_code == 0 and "approval fatigue" in first.output


def test_api_asks_for_a_reason_when_flagged(layout, monkeypatch):
    from fastapi.testclient import TestClient

    from sandbox.api import auth
    from sandbox.api.app import create_app

    configure(layout, burst_approvals=1, fast_min_approvals=100)
    approvals_by(layout, "api", 1)
    monkeypatch.setenv(auth.AGENT_ENV, "agent-t")
    monkeypatch.setenv(auth.APPROVER_ENV, "approver-t")
    client = TestClient(create_app(), headers={"Authorization": "Bearer approver-t"})
    rid = submit_command(layout)
    url = f"/api/v1/connector/{rid}/approve?root={layout.root}"
    assert client.post(url).status_code == 422
    assert EscalationQueue(layout).status(rid) == "pending"


def test_watch_warns_and_asks_a_flagged_reviewer_for_a_reason(layout):
    from sandbox.cli.main import cli

    configure(layout, burst_approvals=2, fast_min_approvals=100)
    approvals_by(layout, "alice", 2)
    rid = submit_command(layout)
    out = CliRunner().invoke(cli, ["watch", str(layout.root), "--reviewer", "alice", "--once"],
                             input="a\nread it: it only echoes text\n")
    assert out.exit_code == 0, out.output
    assert "WARNING : approval fatigue" in out.output and "approval 1 of 2" in out.output
    assert EscalationQueue(layout).status(rid) == "pending"
