"""SEC-25 (High): the agent must not run `sandbox policy propose`.

`policy propose --proposer alice` by the agent, then `policy approve-change` by a
human, would count as two people. Propose is an approver-CLI action: a non-removable
APPROVER_CLI deny, never an escalation.
"""
from __future__ import annotations

import json

import pytest

from sandbox.connector.classify import classify
from sandbox.connector.hook_eval import pre_tool_use
from sandbox.connector.layout import FolderLayout
from sandbox.connector.policy import default_policy, save_policy
from sandbox.connector.queue import EscalationQueue
from sandbox.safety.blocklist import CommandBlocklist



@pytest.fixture
def layout(tmp_path):
    lo = FolderLayout(tmp_path)
    lo.ensure_dirs()
    policy = default_policy()
    policy.escalation_timeout_seconds = 0
    save_policy(policy, lo.policy_file)
    lo.session_file.write_text(json.dumps({"session_id": "s-25"}), encoding="utf-8")
    return lo


def _classify(layout, command):
    return classify("Bash", {"command": command}, default_policy(), layout,
                    cwd=str(layout.root), blocklist=CommandBlocklist())


async def _hook(layout, command):
    payload = {"tool_name": "Bash", "tool_input": {"command": command}, "cwd": str(layout.root),
               "session_id": "abc", "hook_event_name": "PreToolUse"}
    out = await pre_tool_use(payload, layout)
    hso = out.get("hookSpecificOutput", {})
    return hso.get("permissionDecision"), hso.get("permissionDecisionReason", "")


PROPOSE = [
    "sandbox policy propose x.json --proposer alice",
    "echo ok && sandbox policy propose x.json --proposer alice",
    "echo ok; sandbox policy propose x.json --proposer alice",
    "ls | sandbox policy propose x.json --proposer alice",
    "echo ok\nsandbox policy propose x.json --proposer alice",
    "python -m sandbox.cli policy propose x.json --proposer alice",
    "python -m sandbox.cli.main policy propose x.json",
    ".venv/Scripts/sandbox.exe policy propose x.json",
    "SANDBOX policy PROPOSE x.json --proposer alice",
    "sandbox Policy Propose x.json --proposer alice",
    "sandbox policy propose --gov x.json",
]



@pytest.mark.parametrize("command", PROPOSE)
def test_sec25_policy_propose_denied_classify(layout, command):
    c = _classify(layout, command)
    assert c.verdict == "deny", (command, c.verdict, c.reason)
    assert "approver" in c.reason.lower(), c.reason



@pytest.mark.parametrize("command", PROPOSE)
async def test_sec25_policy_propose_denied_hook(layout, command):
    decision, reason = await _hook(layout, command)
    assert decision == "deny", (command, decision, reason)
    assert EscalationQueue(layout).list_pending() == [], "must be denied, not sent to a human"


@pytest.mark.parametrize("command", ["sandbox policy show", "echo propose", "git commit -m propose"])
def test_sec25_guard_readonly_not_denied_by_propose_rule(layout, command):
    c = _classify(layout, command)
    assert "approver" not in (c.reason or "").lower(), (command, c.reason)


async def test_sec25_guard_command_substitution_denied_hook(layout):
    decision, reason = await _hook(layout, "echo $(sandbox policy propose x.json --proposer alice)")
    assert decision == "deny", (decision, reason)
