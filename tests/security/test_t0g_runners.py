"""T0g (ADR 0009): workspace code runners escalate by default; opt-in only through an
approved two-reviewer policy version (`shell.allow_runners`).

All through the real ``hook_eval.pre_tool_use``. ``python -m pytest`` and ``npm run`` run code
the agent can write, so a default "allow" would be a two-step bypass of every other rule.
"""
from __future__ import annotations

import asyncio
import json
import sys

import pytest
from click.testing import CliRunner

from sandbox.connector import policy_versions as pv
from sandbox.connector.hook_eval import pre_tool_use
from sandbox.connector.install import init
from sandbox.connector.layout import FolderLayout
from sandbox.connector.memory import DecisionMemory
from sandbox.connector.policy import default_policy, load_policy, save_policy

OLD_PATTERNS = [r"^(npm|pnpm|yarn) (run|test|ci)\b", r"^python -m pytest\b"]

RUNNER_FORMS = [
    "python -m pytest", "python -m pytest -q tests/unit", "python3 -m pytest", "python3.12 -m pytest",
    "py -m pytest", "python -Im pytest", "python -m py.test", "pytest", "pytest -q", "py.test",
    "Python.EXE -m pytest", "PYTEST", "npm run build", "npm test", "npm ci", "npm install", "npm i",
    "pnpm test", "pnpm run x", "pnpm install", "yarn", "yarn test", "yarn run x", "yarn install",
    "bun run x", "bun test", "NPM.CMD test", "npm.exe run x", "npm exec x", "pnpm exec x", "bun x y",
    "npx cowsay", "pnpm dlx x", "yarn dlx x", "bunx x", "npm --prefix web run build",
]


def _folder(tmp_path, *, edit=None, baseline=True):
    init(tmp_path, claude=False, mcp=False)
    lay = FolderLayout(tmp_path)
    policy = load_policy(lay.policy_file)
    policy.escalation_timeout_seconds = 0  # an escalation answers "deny: escalated" at once
    if edit:
        edit(policy)
    save_policy(policy, lay.policy_file)
    if baseline:
        pv.baseline(lay, "alice", "initial")
    return lay


def _call(lay, command, tool="Bash"):
    out = asyncio.run(pre_tool_use({"tool_name": tool, "tool_input": {"command": command},
                                    "cwd": str(lay.root), "session_id": "t0g"}, lay))
    hso = out.get("hookSpecificOutput", {})
    return hso.get("permissionDecision"), hso.get("permissionDecisionReason", "")


def _audit(lay):
    recs = []
    for f in sorted(lay.audit_dir.rglob("*.jsonl")):
        for line in f.read_text(encoding="utf-8").splitlines():
            if line.strip():
                recs.append(json.loads(line))
    return recs


def _escalated(decision, reason):
    return decision == "deny" and "escalated" in reason


def _allowed(decision):
    return decision in (None, "allow")


def _opt_in(lay, runners, proposer="alice", reviewer="bob"):
    new = json.loads(json.dumps(pv.folder_content(lay)))
    new["shell"]["allow_runners"] = list(runners)
    change = pv.propose(lay, pv.FOLDER, new, proposer, "CI runs tests")
    return change, pv.approve_change(lay, change["change_id"], reviewer, "checked the test setup")


# --- defaults ---------------------------------------------------------------------------

def test_default_policy_has_no_runner_patterns_and_no_opt_in():
    p = default_policy()
    for pat in OLD_PATTERNS:
        assert pat not in p.shell.allow_patterns
    assert p.shell.allow_runners == []


@pytest.mark.parametrize("command", RUNNER_FORMS)
def test_every_runner_form_escalates_by_default(tmp_path, command):
    lay = _folder(tmp_path)
    decision, reason = _call(lay, command)
    assert _escalated(decision, reason), (command, decision, reason)
    assert any(r.get("reason_code") == "WORKSPACE_RUNNER" for r in _audit(lay)), command


def test_runner_escalation_tells_the_approver_why(tmp_path):
    from sandbox.connector.queue import EscalationQueue

    lay = _folder(tmp_path)
    _call(lay, "python -m pytest")
    pending = EscalationQueue(lay).list_pending()
    assert pending and "WORKSPACE_RUNNER" in pending[0]["reason"] and "git diff" in pending[0]["reason"]


@pytest.mark.parametrize("baseline", [False, True])
def test_m0_era_policy_listing_the_old_patterns_still_escalates(tmp_path, baseline):
    lay = _folder(tmp_path, edit=lambda p: p.shell.allow_patterns.extend(OLD_PATTERNS), baseline=baseline)
    for command in ("python -m pytest -q", "npm test", "yarn run x", "pnpm ci"):
        decision, reason = _call(lay, command)
        assert _escalated(decision, reason), (command, decision, reason)


def test_auto_allow_and_environment_rules_do_not_allow_a_runner(tmp_path):
    def edit(p):
        p.auto_allow = True
        p.environment = "dev"
        p.shell.allow_patterns.extend(OLD_PATTERNS)
    lay = _folder(tmp_path, edit=edit)
    for env in ("dev", "staging", "prod"):
        policy = load_policy(lay.policy_file)
        policy.environment = env
        save_policy(policy, lay.policy_file)
        decision, reason = _call(lay, "python -m pytest")
        assert not _allowed(decision), (env, decision, reason)


def test_a_remembered_prefix_does_not_upgrade_a_runner(tmp_path):
    lay = _folder(tmp_path)
    DecisionMemory(lay.remembered, "t0g").remember("prefix", "npm run", trigger="shell")
    DecisionMemory(lay.remembered, "t0g").remember("command", "python -m pytest", trigger="shell")
    for command in ("npm run build", "python -m pytest"):
        decision, reason = _call(lay, command)
        assert _escalated(decision, reason), (command, decision, reason)


def test_positive_controls_are_unchanged(tmp_path):
    lay = _folder(tmp_path)
    for command in ("git status", "ls", "git log --oneline -3"):
        decision, _ = _call(lay, command)
        assert _allowed(decision), command
    decision, reason = _call(lay, "npm --version")
    assert not _allowed(decision)
    assert not any(r.get("reason_code") == "WORKSPACE_RUNNER" for r in _audit(lay))


# --- the opt-in cannot be set by hand, by drift or by a one-person baseline ---------------

def test_hand_added_opt_in_is_ignored_unversioned_drift_and_corrupt(tmp_path):
    lay = _folder(tmp_path, edit=lambda p: setattr(p.shell, "allow_runners", ["pytest", "npm"]), baseline=False)
    assert not _allowed(_call(lay, "python -m pytest")[0])  # unversioned
    (tmp_path / "v").mkdir()
    lay2 = _folder(tmp_path / "v", baseline=True)
    policy = load_policy(lay2.policy_file)
    policy.shell.allow_runners = ["pytest", "npm"]  # drift: on-disk edit after the baseline
    save_policy(policy, lay2.policy_file)
    assert not _allowed(_call(lay2, "python -m pytest")[0])
    assert not _allowed(_call(lay2, "npm test")[0])
    lay2.policy_file.write_text("{ not json", encoding="utf-8")  # corrupt
    assert not _allowed(_call(lay2, "python -m pytest")[0])


def test_baseline_refuses_a_non_empty_opt_in(tmp_path):
    lay = _folder(tmp_path, edit=lambda p: setattr(p.shell, "allow_runners", ["pytest"]), baseline=False)
    with pytest.raises(ValueError, match="allow_runners"):
        pv.baseline(lay, "alice", "initial")


def test_unknown_opt_in_values_are_ignored():
    from sandbox.connector.policy import FolderPolicy

    p = FolderPolicy.model_validate({"shell": {"allow_runners": ["make", "PyTest", "npx", "bun", "npm", "npm"]}})
    assert p.shell.allow_runners == ["pytest", "npm"]


def test_opt_in_is_a_loosening_and_the_meet_keeps_only_the_common_entries(tmp_path):
    lay = _folder(tmp_path)
    approved = pv.folder_content(lay)
    looser = json.loads(json.dumps(approved))
    looser["shell"]["allow_runners"] = ["pytest"]
    assert not pv.only_tightens(approved, looser)
    assert "shell.allow_runners" in pv.loosened_fields(approved, looser)
    assert pv.only_tightens(looser, approved)
    assert pv.meet(looser, approved)["shell"]["allow_runners"] == []
    assert pv.meet(approved, looser)["shell"]["allow_runners"] == []


# --- the real opt-in: two distinct reviewers -------------------------------------------------

def test_opt_in_needs_two_distinct_reviewers_then_raises_an_alert_and_audits_each_run(tmp_path):
    lay = _folder(tmp_path)
    new = json.loads(json.dumps(pv.folder_content(lay)))
    new["shell"]["allow_runners"] = ["pytest"]
    change = pv.propose(lay, pv.FOLDER, new, "alice", "CI runs tests")
    assert pv.approve_change(lay, change["change_id"], "alice")["status"] == "same_reviewer"
    assert not _allowed(_call(lay, "python -m pytest")[0])  # still not approved
    assert pv.approve_change(lay, change["change_id"], "bob", "ok")["status"] == "applied"

    alerts = (lay.logs_dir / "alerts.jsonl").read_text(encoding="utf-8")
    assert "runners_allowed" in alerts or '"runners"' in alerts
    assert any(r.get("event") == "runners_allowed" and "pytest" in json.dumps(r) for r in _audit(lay))

    decision, _ = _call(lay, "python -m pytest -q")
    assert _allowed(decision)
    recs = [r for r in _audit(lay) if r.get("event") == "runner_allowed"]
    assert recs and recs[-1].get("runner") == "pytest" and "pytest" in recs[-1].get("command", "")


def test_opting_in_to_pytest_leaves_every_other_runner_escalated(tmp_path):
    lay = _folder(tmp_path)
    assert _opt_in(lay, ["pytest"])[1]["status"] == "applied"
    for command in ("npm test", "pnpm test", "yarn test", "bun test", "python -m pytest && ls",
                    "python -m pytest; python deploy.py", "python -m pytest | tee out.txt"):
        decision, reason = _call(lay, command)
        assert _escalated(decision, reason), (command, decision, reason)
    assert _allowed(_call(lay, "pytest -q")[0])
    assert _allowed(_call(lay, "py.test")[0])


def test_opting_in_to_npm_allows_run_and_test_only(tmp_path):
    lay = _folder(tmp_path)
    assert _opt_in(lay, ["npm"])[1]["status"] == "applied"
    for command in ("npm run build", "npm test"):
        assert _allowed(_call(lay, command)[0]), command
    for command in ("npm ci", "pnpm ci", "yarn ci", "npm install", "npm exec x", "npm publish", "npx foo", "pnpm test", "yarn test"):
        decision, reason = _call(lay, command)
        assert _escalated(decision, reason), (command, decision, reason)


def test_npx_dlx_and_bunx_always_escalate_even_when_everything_is_opted_in(tmp_path):
    lay = _folder(tmp_path)
    assert _opt_in(lay, ["pytest", "npm", "pnpm", "yarn"])[1]["status"] == "applied"
    for command in ("npx cowsay", "pnpm dlx x", "yarn dlx x", "bunx x", "bun run x", "uvx x"):
        decision, reason = _call(lay, command)
        assert _escalated(decision, reason), (command, decision, reason)


def test_a_tainted_session_escalates_even_an_opted_in_runner(tmp_path):
    from sandbox.semantic import taint

    lay = _folder(tmp_path, edit=lambda p: setattr(p.semantic, "enabled", True))
    assert _opt_in(lay, ["pytest"])[1]["status"] == "applied"
    assert _allowed(_call(lay, "python -m pytest")[0])
    taint.mark(lay.state_dir, {"tool": "Read", "top_check": "override", "top_score": 0.9}, ttl_seconds=60)
    decision, reason = _call(lay, "python -m pytest")
    assert _escalated(decision, reason), (decision, reason)


def test_if_the_runner_audit_cannot_be_written_the_call_is_denied(tmp_path, monkeypatch):
    from sandbox.connector.audit import FolderAudit

    lay = _folder(tmp_path)
    assert _opt_in(lay, ["pytest"])[1]["status"] == "applied"
    real = FolderAudit.append

    def failing(self, record):
        if record.get("event") == "runner_allowed":
            raise OSError("disk full")
        return real(self, record)

    monkeypatch.setattr(FolderAudit, "append", failing)
    decision, reason = _call(lay, "python -m pytest")
    assert decision == "deny" and not _allowed(decision), (decision, reason)


def test_the_evidence_pack_records_the_opt_in(tmp_path):
    from sandbox.connector.evidence import build_pack

    lay = _folder(tmp_path)
    _opt_in(lay, ["pytest"])
    _call(lay, "python -m pytest")
    summary = json.loads(build_pack(lay)["summary.json"])
    assert summary["runners"]["allow_runners"] == ["pytest"]
    assert summary["runners"]["runner_allowed_events"] >= 1


# --- doctor ---------------------------------------------------------------------------------

def test_doctor_flags_stale_runner_patterns_but_does_not_rewrite_policy(tmp_path):
    from sandbox.cli.connector_cmds import doctor_cmd

    lay = _folder(tmp_path, edit=lambda p: p.shell.allow_patterns.extend(OLD_PATTERNS), baseline=False)
    before = lay.policy_file.read_bytes()
    out = CliRunner().invoke(doctor_cmd, [str(tmp_path)])
    assert "inert" in out.output and "python -m pytest" in out.output
    assert lay.policy_file.read_bytes() == before


# --- security's second pass: the opt-in is an allowlist of forms -------------------------------

@pytest.mark.parametrize("command", [
    "python evil.py -m pytest", "python -m pip install ./x -m pytest", "python -m evilmod -m pytest",
    "python -m http.server -m pytest", "python3 -m coverage run -m pytest", "python -c x -m pytest",
    "python -X importtime evil.py -m pytest", "python -m pytest.evil", "python --foo -m pytest",
])
def test_pytest_opt_in_needs_the_first_dash_m_to_be_pytest(tmp_path, command):
    lay = _folder(tmp_path)
    assert _opt_in(lay, ["pytest"])[1]["status"] == "applied"
    decision, reason = _call(lay, command)
    assert _escalated(decision, reason), (command, decision, reason)


@pytest.mark.parametrize("command", [
    "python -m pytest", "python -B -m pytest -q", "python -X dev -m pytest", "python -W ignore -m pytest",
    "python -u -O -m pytest tests", "python -Im pytest", "python -m pytest -m slow", "pytest -m slow",
])
def test_pytest_opt_in_accepts_interpreter_flags_before_the_module(tmp_path, command):
    lay = _folder(tmp_path)
    assert _opt_in(lay, ["pytest"])[1]["status"] == "applied"
    assert _allowed(_call(lay, command)[0]), command


@pytest.mark.parametrize("command", [
    "npm test --script-shell=./evil.sh", "npm run x --prefix ..", "npm test --userconfig=x",
    "npm test --globalconfig=x", "npm run x --cache=/tmp/c", "npm run x --registry=http://x",
    "npm run x --workspace=a", "npm run x --workspaces", "npm run x --ignore-scripts=false",
    "npm --prefix .. run x", "npm -C .. test", "npm run x extra", "npm test extra", "npm run",
    "npm run -- x", "npm run --script-shell=x y", "pnpm test --dir ..", "yarn run x --cwd ..",
    "npm ci --prefix ..",
])
def test_npm_opt_in_is_an_allowlist_of_forms_so_any_option_before_dashdash_escalates(tmp_path, command):
    lay = _folder(tmp_path)
    assert _opt_in(lay, ["npm", "pnpm", "yarn"])[1]["status"] == "applied"
    decision, reason = _call(lay, command)
    assert _escalated(decision, reason), (command, decision, reason)


@pytest.mark.parametrize("command", [
    "npm test", "npm run build", "npm run build -- --watch", "npm test -- --script-shell=x",
    "pnpm run lint", "yarn test",
])
def test_npm_opt_in_accepts_the_plain_forms_and_args_after_dashdash(tmp_path, command):
    lay = _folder(tmp_path)
    assert _opt_in(lay, ["npm", "pnpm", "yarn"])[1]["status"] == "applied"
    assert _allowed(_call(lay, command)[0]), command


def test_evidence_records_the_opt_in_state_at_the_start_of_the_period(tmp_path):
    import time

    from sandbox.connector.evidence import build_pack

    lay = _folder(tmp_path)
    _opt_in(lay, ["pytest"])
    since = time.time() + 1  # the period starts after the opt-in: no change inside it
    summary = json.loads(build_pack(lay, since=since)["summary.json"])
    assert summary["runners"]["opt_in_changes"] == []
    assert summary["runners"]["allow_runners_at_since"] == ["pytest"]
    early = json.loads(build_pack(lay, since=1.0)["summary.json"])
    assert early["runners"]["allow_runners_at_since"] == []


def test_the_dead_shell_verdict_helper_is_gone():
    from sandbox.connector import hook_eval

    assert not hasattr(hook_eval, "_shell_verdict")


def test_ci_is_never_opt_in_eligible(tmp_path):
    lay = _folder(tmp_path)
    assert _opt_in(lay, ["npm", "pnpm", "yarn"])[1]["status"] == "applied"
    for command in ("npm ci", "pnpm ci", "yarn ci", "npm ci -- --foreground-scripts"):
        decision, reason = _call(lay, command)
        assert _escalated(decision, reason), (command, decision, reason)


@pytest.mark.parametrize("command", [
    "python -m pytest ../x", "python -m pytest /etc", "python -m pytest --junitxml=../x.xml",
    "python -m pytest --basetemp=../x", "pytest --rootdir=/", "pytest ../x/test_a.py::test_b",
    "python -m pytest tests/../../x", "pytest ~/x", "pytest -p x --junitxml=/tmp/r.xml",
    pytest.param("pytest C:/Windows/x",
                 marks=pytest.mark.skipif(sys.platform != "win32",
                                          reason="C: drive letter is only absolute on Windows")),
])
def test_pytest_opt_in_is_lost_when_a_path_leaves_the_root(tmp_path, command):
    lay = _folder(tmp_path)
    assert _opt_in(lay, ["pytest"])[1]["status"] == "applied"
    decision, reason = _call(lay, command)
    assert _escalated(decision, reason), (command, decision, reason)


@pytest.mark.parametrize("command", [
    "python -m pytest tests", "python -m pytest tests/unit/test_a.py::test_b -q",
    "pytest --junitxml=reports/out.xml", "pytest --basetemp=.tmp/x", "python -m pytest ./tests -k slow",
    "pytest -k 'a and b'",
])
def test_pytest_opt_in_keeps_in_root_paths(tmp_path, command):
    lay = _folder(tmp_path)
    assert _opt_in(lay, ["pytest"])[1]["status"] == "applied"
    assert _allowed(_call(lay, command)[0]), command
