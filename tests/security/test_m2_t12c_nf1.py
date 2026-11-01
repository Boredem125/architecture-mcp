"""T12c NF-1 proof (rebuilt in c6): bash-lexed command, bash-run command.

NF-1: the hook lexes a Bash-tool command with bash semantics
(``shellwords.lex(..., "bash")``), but before T12c c2 (``dca1873``) the broker
ran the approved string via ``subprocess.run(command, shell=True)``, which on
Windows is ``cmd.exe /c``.  cmd.exe and bash split a command differently, so
an approved command could run with a different meaning than the reviewer
analysed.  In bash ``foo '&echo x&'`` is one word passed to ``foo``; in cmd.exe
the unquoted ``&`` (single quotes are not cmd quoting) starts a second command.

c6 test gap (T12B_PLAN c6, found drafting docs/NF1.md): the previous two
marker tests built an old-format record (no ``fp_v``, no ``tool_name``).  At
HEAD the broker refuses such a record with ``RECORD_UNVERSIONED`` before any
exec, so "no marker" proved refusal, not shell parity.  Every test here runs a
**v2 record** (``fp_v`` 2, ``tool_name``) through the broker under the shell
recorded in ``session.json`` by ``sandbox init`` (Git bash; System32
powershell.exe when pwsh 7 is absent) and asserts the command actually ran
(``state == "executed"``, ``exec_argv[0]`` is the recorded shell) with bash
or pwsh meaning.

Red on ``dca1873^`` (shell=True broker), green at HEAD:
  1. hook view guard (parametrized over both NF-1 forms): one benign segment;
  2. local approve path (hook -> ``approve()`` -> broker): marker form, no marker;
  3. the shared choke point ``FolderBroker.execute`` that ``apply_external``
     calls (remote path): marker form as a direct v2 record, no marker;
  4. the APPROVER_CLI variant from extra test 13: the hidden cmd.exe segment
     would redirect ``sandbox approve ...`` output into MARKER; no marker;
  5. corpus round-trip, bash: ``printf '%s' "$BASH_EXECUTION_STRING"`` returns
     the command byte for byte for each corpus entry with cmd.exe-hostile
     characters (``&``, ``|``, ``%VAR%``, ``^``, ``\\d+``);
  6. corpus round-trip, pwsh (Windows): ``$MyInvocation.MyCommand.Definition``
     returns the command byte for byte and the ``-EncodedCommand`` operand
     decodes (UTF-16LE) to the same bytes.

Markers are relative to the workspace root (the broker's cwd) so neither
shell needs a drive-letter path and nothing outside ``tmp_path`` is touched.
"""
from __future__ import annotations

import asyncio
import base64
import json
import sys
from pathlib import Path

import pytest

from sandbox.connector.broker import FolderBroker
from sandbox.connector.classify import analyse_shell


windows_only = pytest.mark.skipif(
    sys.platform != "win32",
    reason="NF-1 is the bash-hook / cmd.exe-broker split; Windows-specific",
)

_MARKER = "nf1_marker.txt"

# The two NF-1 forms from T12B_PLAN extra test 13.  In bash each is ONE word
# handed to the (unknown, escalated) command ``nf1-noop``; nothing else runs.
# Under cmd.exe the unquoted ``&`` splits them and the middle segment writes
# MARKER (echo, or the redirect of the approver CLI call, which cmd.exe opens
# before it resolves the program name).
_ECHO_FORM = f"nf1-noop '&echo pwned> {_MARKER}&'"
_APPROVER_CLI_FORM = (
    f"nf1-noop '&sandbox approve nf1-req --reviewer bob > {_MARKER} 2>&1&'"
)

# Corpus: every entry prints its own command string under bash.  cmd.exe would
# print the literal operands, expand ``%PATH%`` or split on ``&`` / ``|``.
_BASH_CORPUS = [
    "printf '%s' \"$BASH_EXECUTION_STRING\"",
    "true '&echo x&' && printf '%s' \"$BASH_EXECUTION_STRING\"",
    "printf '%s' \"$BASH_EXECUTION_STRING\" # %PATH% ^ | \\d+ \\n",
    ": 'a | b' ; printf '%s' \"$BASH_EXECUTION_STRING\"",
]

_PWSH_CORPUS = [
    "[Console]::Out.Write($MyInvocation.MyCommand.Definition)",
    "[Console]::Out.Write($MyInvocation.MyCommand.Definition) # & | %PATH% ^ \"q\"",
]


# ---------------------------------------------------------------------------
# Helpers (self-contained so the file can be dropped into a worktree alone)
# ---------------------------------------------------------------------------

def _ws(path: Path):
    """``sandbox init`` a workspace; init records ``shells`` in session.json."""
    from sandbox.connector.install import init
    from sandbox.connector.layout import FolderLayout
    path.mkdir(parents=True, exist_ok=True)
    init(path, claude=False, mcp=False)
    return FolderLayout(path)


def _shells(lay) -> dict:
    sf = lay.root / ".sandbox" / "session.json"
    return json.loads(sf.read_text(encoding="utf-8")).get("shells") or {}


def _v2_record(lay, command: str, request_id: str, tool_name: str = "Bash") -> dict:
    """A fp_v 2 record as the hook stamps it for an unbound command."""
    return {
        "kind": "command",
        "request_id": request_id,
        "command": command,
        "exec_cwd": str(lay.root),
        "root": str(lay.root),
        "tool_name": tool_name,
        "fp_v": 2,
        "script": None,
        "requires_dual": False,
    }


def _run(lay, command: str, request_id: str, tool_name: str = "Bash") -> dict:
    """Run a v2 record through the broker choke point ``apply_external`` uses."""
    return asyncio.run(FolderBroker().execute(
        _v2_record(lay, command, request_id, tool_name), "bob",
    ))


async def _async_none(self, request_id, timeout=0, **_kw):
    return None


def _hook_escalate(lay, command: str, monkeypatch) -> str:
    """Escalate *command* through the real hook; return the request id."""
    from sandbox.connector.queue import EscalationQueue
    monkeypatch.setattr(EscalationQueue, "wait", _async_none)
    from sandbox.connector.hook_eval import pre_tool_use
    asyncio.run(pre_tool_use(
        {"tool_name": "Bash", "tool_input": {"command": command},
         "cwd": str(lay.root), "session_id": "nf1"},
        lay,
    ))
    pending = sorted(lay.pending_dir.glob("*.json"), key=lambda p: p.stat().st_mtime)
    assert pending, f"hook did not escalate {command!r}"
    return json.loads(pending[-1].read_text(encoding="utf-8"))["request_id"]


def _done_record(lay, request_id: str) -> dict:
    f = lay.done_dir / f"{request_id}.json"
    assert f.exists(), f"no done-record for {request_id}"
    return json.loads(f.read_text(encoding="utf-8"))


def _assert_ran_under(done: dict, shell_path: str) -> None:
    """The command really ran (not refused) and under the recorded shell."""
    assert done.get("state") == "executed", (
        f"expected the broker to run the command, got state={done.get('state')!r} "
        f"reason={done.get('reason_code') or done.get('reason')!r}"
    )
    assert done.get("exec_argv"), "done-record has no exec_argv"
    assert done["exec_argv"][0] == shell_path, (
        f"ran under {done['exec_argv'][0]!r}, not the recorded shell {shell_path!r}"
    )


# ---------------------------------------------------------------------------
# 1. Reviewer view guard
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("command", [_ECHO_FORM, _APPROVER_CLI_FORM],
                         ids=["echo-form", "approver-cli-form"])
def test_nf1_reviewer_view_is_single_benign_bash_segment(tmp_path, command):
    """What the reviewer is shown: bash semantics give one segment, no deny,
    nothing unresolvable from the hidden ``&``.  A human approves what looks
    like a single ``nf1-noop <arg>`` call, so the broker must keep that meaning."""
    a = analyse_shell(command, "bash", cwd=str(tmp_path))
    assert a.deny is None
    assert a.segments == 1
    assert a.unresolvable == []


# ---------------------------------------------------------------------------
# 2. Local approve path: hook -> approve() -> broker (approval.py:199)
# ---------------------------------------------------------------------------

@windows_only
def test_nf1_local_approve_runs_bash_meaning_no_cmd_split(tmp_path, monkeypatch):
    kh = tmp_path / "keyhome"
    kh.mkdir()
    monkeypatch.setenv("SANDBOX_KEY_HOME", str(kh))
    lay = _ws(tmp_path / "ws")
    marker = lay.root / _MARKER

    req_id = _hook_escalate(lay, _ECHO_FORM, monkeypatch)

    from sandbox.connector.approval import approve
    result = asyncio.run(approve(lay, req_id, "reviewer-1"))
    if result.get("status") == "awaiting_second":
        result = asyncio.run(approve(lay, req_id, "reviewer-2"))
    assert result.get("status") == "executed", f"approve did not run: {result}"

    assert not marker.exists(), (
        "cmd.exe ran the hidden second command: the broker executed a "
        "different command than the hook analysed"
    )
    done = _done_record(lay, req_id)
    _assert_ran_under(done, _shells(lay)["bash"])
    # The ``-c`` operand is the approved line byte for byte.
    assert done["exec_argv"][-1] == _ECHO_FORM


# ---------------------------------------------------------------------------
# 3. Remote path choke point: FolderBroker.execute as apply_external calls it
# ---------------------------------------------------------------------------

@windows_only
def test_nf1_remote_choke_point_v2_record_no_cmd_split(tmp_path):
    lay = _ws(tmp_path / "ws")
    marker = lay.root / _MARKER

    done = _run(lay, _ECHO_FORM, "nf1-remote")

    assert not marker.exists(), (
        "remote-approved command split by cmd.exe in the broker"
    )
    _assert_ran_under(done, _shells(lay)["bash"])
    # The whole bash word reached bash untouched: bash could not find
    # ``nf1-noop`` (127), so nothing in the approved line ran at all.
    assert done.get("exit_code") == 127, done


# ---------------------------------------------------------------------------
# 4. APPROVER_CLI variant (extra test 13)
# ---------------------------------------------------------------------------

@windows_only
def test_nf1_approver_cli_variant_writes_no_marker(tmp_path):
    """Under cmd.exe the hidden segment is ``sandbox approve ... > MARKER
    2>&1``: cmd.exe opens MARKER for the redirect before it resolves the
    program, so MARKER appears whether or not ``sandbox`` is on PATH.  Under
    bash the whole quoted word is one operand of ``nf1-noop``."""
    lay = _ws(tmp_path / "ws")
    marker = lay.root / _MARKER

    done = _run(lay, _APPROVER_CLI_FORM, "nf1-approver-cli")

    assert not marker.exists(), (
        "cmd.exe ran the hidden approver-CLI segment (MARKER written)"
    )
    _assert_ran_under(done, _shells(lay)["bash"])
    assert done.get("exit_code") == 127, done


# ---------------------------------------------------------------------------
# 5. Corpus round-trip, bash: byte-exact
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("command", _BASH_CORPUS, ids=["plain", "amp-word", "comment-hostile", "pipe-word"])
def test_nf1_corpus_bash_round_trip_is_byte_exact(tmp_path, command):
    lay = _ws(tmp_path / "ws")

    done = _run(lay, command, "nf1-corpus-bash")

    # Byte-exact first: this is the parity property itself.
    assert done.get("stdout") == command, (
        f"bash did not get the approved bytes:\n  sent {command!r}\n  got  {done.get('stdout')!r}"
    )
    assert done.get("exit_code") == 0, done
    shells = _shells(lay)
    assert shells.get("bash"), "sandbox init recorded no bash in session.json"
    _assert_ran_under(done, shells["bash"])


# ---------------------------------------------------------------------------
# 6. Corpus round-trip, pwsh (Windows): byte-exact and decoded operand
# ---------------------------------------------------------------------------

@windows_only
@pytest.mark.parametrize("command", _PWSH_CORPUS, ids=["plain", "comment-hostile"])
def test_nf1_corpus_pwsh_round_trip_is_byte_exact(tmp_path, command):
    lay = _ws(tmp_path / "ws")

    done = _run(lay, command, "nf1-corpus-pwsh", tool_name="PowerShell")

    # Byte-exact first: this is the parity property itself.
    assert done.get("stdout") == command, (
        f"pwsh did not get the approved bytes:\n  sent {command!r}\n  got  {done.get('stdout')!r}"
    )
    assert done.get("exit_code") == 0, done
    shells = _shells(lay)
    assert shells.get("pwsh"), "sandbox init recorded no PowerShell in session.json"
    _assert_ran_under(done, shells["pwsh"])
    argv = done["exec_argv"]
    assert "-EncodedCommand" in argv and "-NoProfile" in argv and "-NonInteractive" in argv, argv
    decoded = base64.b64decode(argv[argv.index("-EncodedCommand") + 1]).decode("utf-16-le")
    assert decoded == command, "EncodedCommand operand does not decode to the approved command"
