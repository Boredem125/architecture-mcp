"""T0f (M1_PLAN.md, D0b): the shell-bypass corpus, one test per case.

Written before the fix (test first). ``bypass_corpus.jsonl`` holds one case per line
(id, class, shell, command, expected, why). Every case goes through both the pure
classifier (``classify`` with ``default_policy()``) and the real hook path
(``hook_eval.pre_tool_use`` on a temp folder), the same way as ``test_t0_hotfix.py``.

Expected outcomes
- ``deny``     : the command could reach the approver CLI or a protected path. Classifier
                 verdict ``deny`` and hook decision ``deny``.
- ``escalate`` : cannot be resolved statically. Never allowed: classifier verdict
                 ``escalate`` or ``deny``, and the hook does not let it through.
- ``allow``    : benign positive control (class ``benign``). Classifier verdict ``allow``
                 and the hook lets it through.
- ``benign_unchanged`` : benign commands that escalate as ordinary shell today; the verdict
                 must stay exactly ``escalate`` (no allow, no approver-CLI deny).

``RED_TODAY`` lists the cases that fail on the current parser. They are strict xfails
(``raises=AssertionError``) so main stays green; the T0f fix commit deletes ids from
that set (a strict xfail that starts passing fails the run, so none can linger). The
set may only shrink. A corpus is not a proof: it describes these cases only.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from sandbox.connector.classify import classify
from sandbox.connector.hook_eval import pre_tool_use
from sandbox.connector.layout import FolderLayout
from sandbox.connector.policy import default_policy, save_policy
from sandbox.safety.blocklist import CommandBlocklist

CORPUS = Path(__file__).with_name("bypass_corpus.jsonl")
CLASSES = {
    "glob_command_word", "substitution", "variable_command", "eval_exec_source",
    "interpreter_c", "newline_continuation", "quoting_split", "alias_function",
    "protected_path", "sec25_residual", "benign", "benign_unchanged", "bounds",
}
SHELLS = {"bash", "cmd", "pwsh"}
EXPECTED = {"deny", "escalate", "allow"}


def _load():
    cases = []
    for line in CORPUS.read_text(encoding="utf-8").splitlines():
        if line.strip():
            cases.append(json.loads(line))
    return cases


CASES = _load()

# Cases that fail on the parser as it is today (measured, see M1_BASELINE.md section 3).
RED_TODAY = frozenset({
    "alias_function-001",
    "alias_function-002",
    "alias_function-005",
    "alias_function-007",
    "benign-012",
    "benign-013",
    "benign-014",
    "benign_unchanged-004",
    "benign_unchanged-005",
    "bounds-001",
    "bounds-004",
    "bounds-005",
    "bounds-006",
    "bounds-007",
    "bounds-008",
    "glob_command_word-001",
    "glob_command_word-002",
    "glob_command_word-003",
    "glob_command_word-004",
    "glob_command_word-005",
    "glob_command_word-006",
    "glob_command_word-007",
    "glob_command_word-008",
    "glob_command_word-009",
    "glob_command_word-010",
    "interpreter_c-001",
    "interpreter_c-002",
    "interpreter_c-003",
    "interpreter_c-007",
    "interpreter_c-024",
    "interpreter_c-025",
    "interpreter_c-028",
    "interpreter_c-029",
    "interpreter_c-030",
    "interpreter_c-031",
    "interpreter_c-032",
    "interpreter_c-034",
    "interpreter_c-045",
    "interpreter_c-051",
    "interpreter_c-052",
    "interpreter_c-053",
    "interpreter_c-054",
    "interpreter_c-055",
    "interpreter_c-056",
    "newline_continuation-001",
    "newline_continuation-002",
    "newline_continuation-003",
    "newline_continuation-004",
    "newline_continuation-010",
    "protected_path-025",
    "protected_path-026",
    "protected_path-027",
    "quoting_split-007",
    "quoting_split-008",
    "quoting_split-009",
    "quoting_split-014",
    "quoting_split-015",
    "sec25_residual-001",
    "sec25_residual-002",
    "sec25_residual-004",
    "sec25_residual-005",
    "sec25_residual-006",
    "sec25_residual-007",
    "substitution-003",
    "substitution-004",
    "variable_command-001",
    "variable_command-002",
    "variable_command-003",
    "variable_command-004",
    "variable_command-006",
    "variable_command-007",
    "variable_command-008",
    "variable_command-009",
    "variable_command-010",
})


@pytest.fixture
def layout(tmp_path):
    lo = FolderLayout(tmp_path)
    lo.ensure_dirs()
    policy = default_policy()
    policy.escalation_timeout_seconds = 0  # an escalation returns "pending" at once
    save_policy(policy, lo.policy_file)
    lo.session_file.write_text(json.dumps({"session_id": "s-t0f"}), encoding="utf-8")
    keys = lo.state_dir / "keys"
    keys.mkdir(parents=True, exist_ok=True)
    (keys / "a.seed").write_bytes(b"\x00" * 32)
    (tmp_path / "README.md").write_text("hi\n")
    (tmp_path / "src").mkdir()
    return lo


def _tool(case):
    return "PowerShell" if case["shell"] == "pwsh" else "Bash"


def _classify(layout, case):
    return classify(_tool(case), {"command": case["command"]}, default_policy(), layout,
                    cwd=str(layout.root), blocklist=CommandBlocklist())


async def _hook(layout, case):
    payload = {"tool_name": _tool(case), "tool_input": {"command": case["command"]},
               "cwd": str(layout.root), "session_id": "abc", "hook_event_name": "PreToolUse"}
    out = await pre_tool_use(payload, layout)
    hso = out.get("hookSpecificOutput", {})
    return hso.get("permissionDecision"), hso.get("permissionDecisionReason", "")


_HOOK_CHILD = """
import asyncio, json, sys
from pathlib import Path
from sandbox.connector.hook_eval import pre_tool_use
from sandbox.connector.layout import FolderLayout
root, cmd_file = Path(sys.argv[1]), Path(sys.argv[2])
payload = {"tool_name": "Bash", "tool_input": {"command": cmd_file.read_text(encoding="utf-8")},
           "cwd": str(root), "session_id": "abc", "hook_event_name": "PreToolUse"}
out = asyncio.run(pre_tool_use(payload, FolderLayout(root)))
print(json.dumps(out.get("hookSpecificOutput", {}).get("permissionDecision")))
"""
HOOK_BUDGET_SECONDS = 5  # the plan's bound is 100 ms; this only stops a hang from stalling CI


def _hook_in_child(layout, case):
    """Oversize commands take minutes in today's hook (the DoS in D0b.5): run them in a
    child process with a hard timeout so the suite cannot hang."""
    cmd_file = layout.root / "cmd.txt"
    cmd_file.write_text(case["command"], encoding="utf-8")
    try:
        r = subprocess.run([sys.executable, "-c", _HOOK_CHILD, str(layout.root), str(cmd_file)],
                           capture_output=True, text=True, timeout=HOOK_BUDGET_SECONDS)
    except subprocess.TimeoutExpired:
        raise AssertionError((case["id"], "hook did not answer within", HOOK_BUDGET_SECONDS, "s"))
    assert r.returncode == 0, (case["id"], r.stderr[-300:])
    return json.loads(r.stdout.strip().splitlines()[-1]), ""


def _param(case):
    marks = []
    if case["id"] in RED_TODAY:
        marks.append(pytest.mark.xfail(strict=True, raises=AssertionError,
                                       reason="T0f: parser not yet bash-faithful"))
    return pytest.param(case, id=case["id"], marks=marks)


@pytest.mark.parametrize("case", [_param(c) for c in CASES])
async def test_t0f_bypass_case(layout, case):
    cmd, want = case["command"], case["expected"]
    c = _classify(layout, case)
    if len(cmd.encode("utf-8")) > 32 * 1024:
        decision, reason = _hook_in_child(layout, case)
    else:
        decision, reason = await _hook(layout, case)
    where = (case["id"], cmd, c.verdict, decision, reason)
    if case["class"] == "benign_unchanged":
        # Today's verdict is an ordinary escalation: it must stay exactly that, not become
        # an allow and not become a deny (no approver-CLI or protected-path false positive).
        assert c.verdict == "escalate", where
        assert decision == "deny" and "escalated" in reason, where  # timeout 0 => pending
    elif want == "deny":
        assert c.verdict == "deny", where
        assert decision == "deny", where
    elif want == "escalate":
        assert c.verdict in ("escalate", "deny"), where
        assert decision == "deny", where  # an escalation at timeout 0 is answered "deny"
    else:
        assert c.verdict == "allow", where
        assert decision in (None, "allow"), where


# --- corpus integrity: guards that pass today and keep the suite honest -------------

def test_t0f_corpus_is_well_formed():
    ids = [c["id"] for c in CASES]
    assert len(ids) == len(set(ids)), "duplicate case ids"
    for c in CASES:
        assert set(c) == {"id", "class", "shell", "command", "expected", "why"}, c["id"]
        assert c["class"] in CLASSES, c["id"]
        assert c["shell"] in SHELLS, c["id"]
        assert c["expected"] in EXPECTED, c["id"]
        assert c["command"].strip() and c["why"].strip(), c["id"]
    assert {c["class"] for c in CASES} == CLASSES, "every class must be present"


def test_t0f_only_benign_cases_expect_allow():
    for c in CASES:
        assert (c["expected"] == "allow") == (c["class"] == "benign"), c["id"]
        if c["class"] == "benign_unchanged":
            assert c["expected"] == "escalate", c["id"]


def test_t0f_sec25_residual_has_the_eight_forms():
    assert len([c for c in CASES if c["class"] == "sec25_residual"]) == 8


def test_t0f_red_set_names_real_cases():
    assert RED_TODAY <= {c["id"] for c in CASES}
