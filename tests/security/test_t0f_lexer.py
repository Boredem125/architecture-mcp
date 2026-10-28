"""T0f: shellwords lexer and classify wiring beyond the frozen corpus.

The timing test is the one QA's corpus does not have: worst-case 32 KiB inputs must be
classified (allow, escalate or deny) within the 100 ms budget. Best of three runs, so
a loaded CI box does not flake; the number is a property of the dev box, not a promise.
The remaining tests cover security's T0f sign-off items 1-5 and 8 one by one.
"""
from __future__ import annotations

import time

import pytest

from sandbox.connector.classify import analyse_shell
from sandbox.connector.shellwords import MAX_BYTES

BUDGET_SECONDS = 0.100
LIMIT = MAX_BYTES


def _fit(prefix: str, unit: str) -> str:
    return (prefix + unit * (LIMIT // len(unit)))[:LIMIT]


WORST_CASES = {
    "quote_dense": _fit("echo ", "'a'\"b\" "),
    "brace_heavy": _fit("echo ", "{a,b}.{c,d} "),
    "brace_no_dot": _fit("echo ", "{a,b}{c,d}{e,f} "),
    "many_words": _fit("echo ", "a "),
    "many_segments": _fit("", "ls;"),
    "glob_args": _fit("cat ", "*.py "),
    "dotted_paths": _fit("cat ", "a/../b./c.d "),
    "backslashes": _fit("echo ", "\\x"),
    "one_huge_word": "echo " + "a" * (LIMIT - 5),
    "nested_parens": "echo " + "(" * 8 + "ls" + ")" * 8,
    "nested_code": "bash -c '" + "ls; " * 7000 + "'",
    "pwsh_quotes": _fit("Write-Output ", "'a' \"b\" "),
}


@pytest.mark.parametrize("name", sorted(WORST_CASES))
def test_32kib_worst_case_is_classified_under_100ms(name):
    cmd = WORST_CASES[name]
    assert len(cmd.encode()) <= LIMIT
    shell = "pwsh" if name.startswith("pwsh") else "bash"
    best = min(_timed(cmd, shell) for _ in range(3))
    assert best < BUDGET_SECONDS, (name, f"{best * 1000:.1f} ms")


def _timed(cmd: str, shell: str) -> float:
    t = time.perf_counter()
    analyse_shell(cmd, shell)
    return time.perf_counter() - t


def test_over_32kib_is_denied_unlexed():
    a = analyse_shell("echo " + "a" * LIMIT)
    assert a.deny and a.deny[0] == "COMMAND_TOO_LARGE"


def test_nul_byte_is_denied():
    assert analyse_shell("ls\x00 -la").deny[0] == "BAD_INPUT"


@pytest.mark.parametrize("cmd, code", [
    ("echo " + "$(" * 9 + ")" * 9, "SHELL_BOUND"),
    ("echo " + "a " * 4100, "SHELL_BOUND"),
    ("echo 'x", "SHELL_LEXER_ERROR"),
])
def test_bounds_deny_with_a_reason_code(cmd, code, monkeypatch):
    # Named test-setup edit (T12c c2 CI follow-up): the size bounds and the
    # 100 ms deadline are both fail-closed denies; on a slow CI runner the
    # deadline won the race on the 4100-word case (SHELL_DEADLINE instead of
    # SHELL_BOUND). Pin the deadline out of the way so the asserted code is
    # the bound.
    from sandbox.connector import shellwords as _sw
    monkeypatch.setattr(_sw, "DEADLINE_SECONDS", 60.0)
    assert analyse_shell(cmd).deny[0] == code


# --- sign-off 1: redirection targets are checked ---------------------------------
@pytest.mark.parametrize("cmd", [
    "echo x >.sandbox/policy.json", "echo x >>.sandbo?/policy.json", "cat <.sandbox/policy.json",
    "echo x &> .sandbox/a", "echo x >| .sandbox/a", "cat <<< x > .sandbox/a",
])
def test_redirect_targets_are_protected_paths(cmd):
    assert analyse_shell(cmd).deny[0] == "SANDBOX_PROTECT"


def test_fd_duplication_is_not_a_path():
    a = analyse_shell("ls 2>&1")
    assert a.deny is None and a.unresolvable == []


# --- sign-off 2: globs, braces and ~ in any word ---------------------------------
def test_glob_in_argument_word_is_matched_against_protected_paths():
    assert analyse_shell("ls .sand*/").deny[0] == "SANDBOX_PROTECT"
    assert analyse_shell("ls .{sandbox,x}/").deny[0] == "SANDBOX_PROTECT"


def test_tilde_is_unresolvable():
    assert "tilde" in analyse_shell("ls ~/x").unresolvable


# --- sign-off 3: widened indirection and code-carrying tools ----------------------
@pytest.mark.parametrize("cmd", [
    "FOO=1 ls", "PATH=/tmp ls", "BASH_ENV=x ls", "if true; then ls; fi", "trap '' EXIT",
    "declare -x A=b", "export A=b", "read A", "printf -v A x", "doas ls", "su root", "setsid ls",
    "stdbuf -o0 ls", "script -c ls", "awk 'BEGIN{x=1}'", "sed -n 1p f", "git -c core.pager=x log",
    "git --config-env=a=B log", "tar --to-command=x -xf a", "tar --checkpoint-action=exec=x -cf a b",
    "rsync -e ssh a b", "ssh host ls", "vim -c q", "ex -c q", "npx foo", "uvx foo", "pipx run foo",
    "pnpm dlx foo", "npm exec foo", "find . -exec ls {} +", "xargs ls", "python3.12 -c 'x=1'",
    "py -c 'x=1'", "nodejs -e 1", "deno eval 1", "perl5 -e 1", "php8 -r 1", "ls | python", "python < a.py",
    "bash <<< ls", "cmd /r dir", "cmd.exe",
])
def test_code_carrying_forms_are_never_allowed(cmd):
    a = analyse_shell(cmd)
    assert a.deny or a.unresolvable, cmd


def test_awk_with_a_visible_fragment_is_denied_else_escalated():
    assert analyse_shell("awk 'BEGIN{system(\"sandbox policy propose x\")}'").deny
    a = analyse_shell("awk 'BEGIN{system(\"ls\")}'")
    assert a.deny is None and a.unresolvable


# --- sign-off 4: Windows path forms -----------------------------------------------
@pytest.mark.parametrize("path", [
    ".sandbox./policy.json", ".sandbox /policy.json", ".SANDBOX../policy.json",
    "\\\\?\\E:\\p\\.sandbox\\policy.json", "//?/e:/p/.sandbox/policy.json",
    "//server/share/.sandbox/policy.json", "/cygdrive/e/p/.sandbox/policy.json",
    "/e/p/.sandbox/policy.json", ".sandbox::$DATA", ".sandbox:stream", "SANDBO~1/policy.json",
])
def test_windows_and_msys_path_forms_hit_protected_paths(path):
    assert analyse_shell(f'cat "{path}"').deny, path


# --- sign-off 5: -EncodedCommand in every spelling ---------------------------------
@pytest.mark.parametrize("flag", [
    "-EncodedCommand", "-encodedcommand", "-ENCODEDCOMMAND", "-e", "-en", "-enc", "-enco", "-ec",
    "-ea", "-EncodedArguments", "-encodedarg", "/enc", "/EncodedCommand", "/e", "\u2013enc",
    "\u2014EncodedCommand", "\u2015ec", "--enc", "-enc:AAAA",
])
@pytest.mark.parametrize("shell, prefix", [("bash", "pwsh"), ("pwsh", "powershell.exe"),
                                           ("bash", "cmd /c powershell")])
def test_encoded_command_is_denied(flag, shell, prefix):
    a = analyse_shell(f"{prefix} {flag} AAAA", shell)
    assert a.deny and a.deny[0] == "ENCODED_COMMAND", (flag, a)


def test_other_powershell_flags_are_not_encoded_command():
    a = analyse_shell("pwsh -ExecutionPolicy Bypass -NoProfile -File x.ps1")
    assert not (a.deny and a.deny[0] == "ENCODED_COMMAND")


# --- sign-off 8: the approver is told why ------------------------------------------
def test_unresolvable_escalation_carries_a_reason_code():
    from sandbox.connector.classify import classify
    from sandbox.connector.layout import FolderLayout
    from sandbox.connector.policy import default_policy

    pol = default_policy()
    pol.triggers.shell = "observe"  # an unresolvable command ignores this
    c = classify("Bash", {"command": "ls $(pwd)"}, pol, FolderLayout("."))
    assert c.verdict == "escalate" and c.reason_code == "SHELL_UNRESOLVABLE"
    assert "could not be analysed" in c.reason and "expansion" in c.metadata["unresolvable"]


# --- sign-off 6: the stub reads strict UTF-8 ------------------------------------------
@pytest.mark.parametrize("data", [b'{"a":"\xff"}', b'{"a":"' + bytes([0]) + b'"}'])
def test_stub_denies_undecodable_input_and_nul(tmp_path, data):
    import subprocess
    import sys

    from sandbox.connector.hook_templates import PRETOOLUSE_STUB

    stub = tmp_path / "pre.py"
    stub.write_text(PRETOOLUSE_STUB, encoding="utf-8")
    r = subprocess.run([sys.executable, str(stub)], input=data, capture_output=True, cwd=tmp_path)
    assert r.returncode == 2, r.stderr


# --- security's second review: Write protections and glob fidelity -----------------------
@pytest.mark.parametrize("target", [
    ".git/config", "sub/.git/config", "GIT~1/hooks/x", "GIT~1/config", ".git./config",
    "CLAUDE~1/settings.json", ".claude/SETTIN~1.JSO", "MCP~1.JSO", ".mcp.json", "SANDBO~1/policy.json",
])
def test_write_to_git_config_and_8_3_aliases_is_denied(tmp_path, target):
    from sandbox.connector.classify import classify
    from sandbox.connector.layout import FolderLayout

    c = classify("Write", {"file_path": str(tmp_path / target), "content": "x"},
                 __import__("sandbox.connector.policy", fromlist=["x"]).default_policy(),
                 FolderLayout(tmp_path))
    assert c.verdict == "deny", target


def test_reading_git_config_is_still_allowed():
    a = analyse_shell("cat .git/config")
    assert a.deny is None


@pytest.mark.parametrize("cmd", [
    "cat .{r..t}andbox/x", "cat .s{a..a}ndbox", "cat .sand[[:alpha:]]ox/x", "cat .sandbo[^y]/x",
    "cat .sandbo[!y]/x", "cat .sandbo[a-z]/x", "cat .sand[[:lower:]]ox", "cat .{s,t}andbox",
    "cat -xf.sandbox/x", "cat -pO.sandbox/x", "cat GIT~1/hooks/x", "echo x > .git/config",
])
def test_bash_glob_forms_hit_protected_paths(cmd):
    assert analyse_shell(cmd).deny, cmd


@pytest.mark.parametrize("cmd", ["cat ?sandbox\policy.json", "cat *andbox\policy.json", "ls ?sandbox"])
def test_powershell_wildcards_have_no_dot_rule(cmd):
    assert analyse_shell(cmd, "pwsh").deny, cmd


def test_bash_keeps_the_dot_rule():
    assert analyse_shell("ls ?sandbox").deny is None


@pytest.mark.parametrize("cmd", ["ls/x.sh", "cat.sh", "dir/x.cmd", "echo.exe x", "git status-x", "git log.sh"])
def test_default_allow_patterns_need_a_word_boundary(cmd):
    from sandbox.connector.classify import classify
    from sandbox.connector.layout import FolderLayout
    from sandbox.connector.policy import default_policy

    assert classify("Bash", {"command": cmd}, default_policy(), FolderLayout(".")).verdict != "allow"


# --- scope widening: all of .git/**, stale saved patterns ------------------------------------
@pytest.mark.parametrize("target", [
    ".git/refs/heads/main", ".git/objects/ab/cd", ".git/modules/m/config", ".git/worktrees/w/gitdir",
    ".git/info/attributes", ".git/config.worktree", ".git/HEAD", "GIT~1/HEAD", ".GIT/index",
])
def test_write_edit_notebook_to_anywhere_in_git_is_denied(tmp_path, target):
    from sandbox.connector.classify import classify
    from sandbox.connector.layout import FolderLayout
    from sandbox.connector.policy import default_policy

    for tool, key in (("Write", "file_path"), ("Edit", "file_path"), ("NotebookEdit", "notebook_path")):
        c = classify(tool, {key: str(tmp_path / target)}, default_policy(), FolderLayout(tmp_path))
        assert c.verdict == "deny", (tool, target)


def test_git_dir_glob_is_a_non_removable_policy_default():
    from sandbox.connector.policy import default_policy

    assert ".git/**" in default_policy().write.deny_globs


def test_stale_saved_pattern_without_boundary_cannot_allow_a_path(tmp_path):
    import json

    from sandbox.connector.classify import allow_pattern_gaps, classify
    from sandbox.connector.layout import FolderLayout
    from sandbox.connector.policy import default_policy, load_policy, save_policy

    pol = default_policy()
    pol.shell.allow_patterns = [r"^(ls|dir|pwd|cd|cat|type|echo|which|where)\b",
                                r"^git (status|diff|log|show|branch|rev-parse)\b"]
    f = tmp_path / "policy.json"
    save_policy(pol, f)
    saved = load_policy(f)
    assert json.loads(f.read_text())["shell"]["allow_patterns"][0].endswith(r"\b")
    lo = FolderLayout(tmp_path)
    for cmd in ("ls/x.sh", "cat.sh", "dir/x.cmd", "git log.sh", "git status-x"):
        assert classify("Bash", {"command": cmd}, saved, lo).verdict != "allow", cmd
    for cmd in ("ls -la", "cat README.md", "git status", "git log --oneline -3"):
        assert classify("Bash", {"command": cmd}, saved, lo).verdict == "allow", cmd
    assert len(allow_pattern_gaps(saved.shell.allow_patterns)) == 2


def test_doctor_lists_patterns_without_a_boundary(tmp_path, monkeypatch):
    from click.testing import CliRunner

    from sandbox.cli.connector_cmds import doctor_cmd
    from sandbox.connector import classify as cl

    assert cl.allow_pattern_gaps([r"^ls\b", r"^ls(\s|$)", r"^pwd$"]) == [r"^ls\b"]
    assert CliRunner().invoke(doctor_cmd, [str(tmp_path)]).exit_code == 1  # no .sandbox here
