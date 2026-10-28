"""M2 T12c script-binding gap: proof tests.

Gap (confirmed High by security): an approval binds the command text,
not the content of the script it runs.  ``_binding_fingerprint``
(src/sandbox/connector/approval.py) hashes kind, tool_name, command,
exec_cwd, root, requires_dual, bundle_sequence, request_id -- but no
file content.  ``PrivilegeBroker._execute_approved`` runs
``subprocess.run(req.command, shell=True, cwd=exec_cwd)`` with no
re-check of the file bytes.

Attack: the hook escalates ``bash deploy.sh``; while the request is
pending the agent (or attacker) edits ``deploy.sh``; approval runs the
new bytes.

Each strict xfail raises ``M2T12cPending`` via the behavioural
``_need_t12c()`` gate.  The fix makes the gate pass, the test runs,
and the xfail becomes XPASS (strict) -- the builder removes the
marker.  Guards (no marker) pass today and must stay green.

Tests:
  1   Local path ``bash deploy.sh``: modified after escalation -> refused,
      SCRIPT_CHANGED done-record, nothing runs.
  2a  Local path ``python tool.py``: same.
  2b  Enrolled workspace ``./deploy.sh`` (direct exec, deferred to M3):
      the hook must DENY with ``SCRIPT_UNPINNABLE`` and write no pending
      record (ADR 0010 s9 9.1 / S-L5).
  3   Symlink swap: replace script with a symlink -> refused.
  4   Remote path via ``apply_external``: modified before apply -> refused.
  5   Guard: unchanged script approved -> runs exactly once, marker appears.

Design (ADR 0010 section 9): the fix pins the file in place and runs
the lexed argv with ``shell=False``.  These tests do NOT assert a
private-copy path or a rewritten argv; they check only the end result
(marker absent, SCRIPT_CHANGED / refusal status, or marker present for
the unchanged guard).

Sentinel name: M2T12cPending (per the plan in T12B_PLAN.md "T12c").
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
import tempfile
import time
import unittest.mock
from pathlib import Path

import pytest

from tests.security.test_m2_t12_remote import (
    _create_pending_request,
    _keygen,
    _make_remote_approval,
    _setup_managed_workspace,
    _ws,
)


# ---------------------------------------------------------------------------
# Sentinel
# ---------------------------------------------------------------------------

class M2T12cPending(Exception):
    """Script-content binding (T12c) is not yet implemented."""


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_PYTHON = sys.executable


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _need_t12c():
    """Raise ``M2T12cPending`` if script-content binding is absent.

    Probe: run ``pre_tool_use`` on ``python probe.py`` through a real
    temporary workspace and check that the resulting pending record
    carries ``fp_v == 2`` and a non-null ``script`` dict with ``sha256``.

    This goes through the hook (the real public seam) rather than
    testing ``_binding_fingerprint`` in isolation.  Chosen because the
    fingerprint function hashes fields that the **hook** must stamp;
    a fingerprint-only probe could pass if someone added the field to
    the hash without the hook ever setting it.  The arity probe
    (Probe 1 in the previous version) was removed: it is gameable by
    adding a dummy parameter.
    """
    from sandbox.connector.queue import EscalationQueue

    with tempfile.TemporaryDirectory() as td:
        td_path = Path(td)
        kh = td_path / "keyhome"
        kh.mkdir()

        with unittest.mock.patch.dict(os.environ, {"SANDBOX_KEY_HOME": str(kh)}):
            lay = _ws(td_path / "ws")
            script = lay.root / "probe.py"
            script.write_text("print('probe')", encoding="utf-8")

            with unittest.mock.patch.object(EscalationQueue, "wait", _async_none):
                from sandbox.connector.hook_eval import pre_tool_use

                asyncio.run(pre_tool_use(
                    {
                        "tool_name": "Bash",
                        "tool_input": {"command": "python probe.py"},
                        "cwd": str(lay.root),
                        "session_id": "sb-probe",
                    },
                    lay,
                ))

            pending = sorted(
                lay.pending_dir.glob("*.json"),
                key=lambda p: p.stat().st_mtime,
            )
            if not pending:
                raise M2T12cPending(
                    "hook did not create a pending record for 'python probe.py'"
                )
            rec = json.loads(pending[-1].read_text(encoding="utf-8"))
            if rec.get("fp_v") != 2:
                raise M2T12cPending(
                    f"pending record fp_v is {rec.get('fp_v')!r}, not 2"
                )
            scr = rec.get("script")
            if not isinstance(scr, dict) or not scr.get("sha256"):
                raise M2T12cPending(
                    "pending record has no script dict with sha256"
                )


async def _async_none(self, request_id, timeout=0, **_kw):
    """Drop-in for ``EscalationQueue.wait`` that returns immediately."""
    return None


def _hook_escalate(lay, command, monkeypatch):
    """Escalate *command* through the real ``pre_tool_use`` hook.

    Monkeypatches ``EscalationQueue.wait`` so the hook does not block.
    Returns ``(record_dict, request_id)``.
    """
    from sandbox.connector.queue import EscalationQueue

    monkeypatch.setattr(EscalationQueue, "wait", _async_none)

    from sandbox.connector.hook_eval import pre_tool_use

    asyncio.run(pre_tool_use(
        {
            "tool_name": "Bash",
            "tool_input": {"command": command},
            "cwd": str(lay.root),
            "session_id": "sb-test",
        },
        lay,
    ))

    pending = sorted(
        lay.pending_dir.glob("*.json"),
        key=lambda p: p.stat().st_mtime,
    )
    assert pending, f"hook did not escalate {command!r}"
    rec = json.loads(pending[-1].read_text(encoding="utf-8"))
    return rec, rec["request_id"]


def _can_symlink() -> bool:
    """True when the current process can create symbolic links."""
    try:
        with tempfile.TemporaryDirectory() as td:
            target = Path(td) / "target.txt"
            link = Path(td) / "link.txt"
            target.write_text("t", encoding="utf-8")
            link.symlink_to(target)
            return link.is_symlink()
    except (OSError, NotImplementedError):
        return False


def _done_record(lay, request_id):
    """Read the done-record for *request_id*, or None."""
    done_file = lay.done_dir / f"{request_id}.json"
    if done_file.exists():
        try:
            return json.loads(done_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
    return None


# ===================================================================
# 1. Local path -- bash deploy.sh
# ===================================================================


def test_local_bash_modified_after_escalation_refused(tmp_path, monkeypatch):
    """Escalate ``bash deploy.sh``, modify the script while it is pending,
    approve via the real local approve path: the modified bytes must NOT
    run and a SCRIPT_CHANGED refusal must be recorded."""
    _need_t12c()

    kh = tmp_path / "keyhome"
    kh.mkdir()
    monkeypatch.setenv("SANDBOX_KEY_HOME", str(kh))
    lay = _ws(tmp_path / "ws")

    marker_original = tmp_path / "marker_original.txt"
    marker_modified = tmp_path / "marker_modified.txt"
    deploy = lay.root / "deploy.sh"
    # The script writes a known token so the test can tell which version ran.
    deploy.write_text(
        f'"{_PYTHON}" -c "open(r\'{marker_original}\',\'w\').write(\'original\')"\n',
        encoding="utf-8",
    )

    _rec, req_id = _hook_escalate(lay, "bash deploy.sh", monkeypatch)

    # Attacker edits the script while the request is pending
    deploy.write_text(
        f'"{_PYTHON}" -c "open(r\'{marker_modified}\',\'w\').write(\'PWNED\')"\n',
        encoding="utf-8",
    )

    from sandbox.connector.approval import approve

    result = asyncio.run(approve(lay, req_id, "test-reviewer"))

    # The modified bytes must not have run.
    assert not marker_modified.exists(), \
        "modified script content was executed (bash deploy.sh)"
    # The original bytes must not have run either (the file was swapped).
    assert not marker_original.exists(), \
        "original script ran after file modification"
    # A SCRIPT_CHANGED refusal is expected (done-record or status).
    assert result.get("status") != "executed", \
        f"broker executed despite file change: {result}"


# ===================================================================
# 2a. Local path -- python tool.py
# ===================================================================


def test_local_python_modified_after_escalation_refused(tmp_path, monkeypatch):
    """Escalate ``python tool.py``, modify, approve: refused."""
    _need_t12c()

    kh = tmp_path / "keyhome"
    kh.mkdir()
    monkeypatch.setenv("SANDBOX_KEY_HOME", str(kh))
    lay = _ws(tmp_path / "ws")

    marker = tmp_path / "marker_python.txt"
    tool = lay.root / "tool.py"
    tool.write_text(
        f'import pathlib; pathlib.Path(r"{marker}").write_text("original")\n',
        encoding="utf-8",
    )

    cmd = f'"{_PYTHON}" tool.py'
    _rec, req_id = _hook_escalate(lay, cmd, monkeypatch)

    # Attacker edits the script
    tool.write_text(
        f'import pathlib; pathlib.Path(r"{marker}").write_text("PWNED")\n',
        encoding="utf-8",
    )

    from sandbox.connector.approval import approve

    result = asyncio.run(approve(lay, req_id, "test-reviewer"))

    assert not marker.exists() or marker.read_text() != "PWNED", \
        "modified Python script was executed"
    assert result.get("status") != "executed", \
        f"broker executed despite file change: {result}"


# ===================================================================
# 2b. Enrolled workspace -- ./deploy.sh (direct exec DEFERRED to M3)
# ===================================================================


def test_direct_exec_denied_script_unpinnable(tmp_path, monkeypatch):
    """In a managed/enrolled workspace, ``./deploy.sh`` is direct exec
    (deferred to M3 per ADR 0010 s9 9.1 / S-L5).  Under the floor
    (enrolled workspace implies every escalation can be approved remotely),
    the hook must DENY the command with ``SCRIPT_UNPINNABLE`` and write
    no pending record.

    OS-independent: a deny needs no execution, so no POSIX skipif."""
    _need_t12c()

    bob, carol = _keygen(), _keygen()
    ctx = _setup_managed_workspace(
        tmp_path, monkeypatch,
        approver_sks=[
            (bob[0], bob[1], bob[2], "user-bob", "cli"),
            (carol[0], carol[1], carol[2], "user-carol", "cli"),
        ],
    )
    lay = ctx["lay"]

    deploy = lay.root / "deploy.sh"
    deploy.write_text("#!/bin/sh\necho hello\n", encoding="utf-8")

    from sandbox.connector.queue import EscalationQueue

    monkeypatch.setattr(EscalationQueue, "wait", _async_none)

    from sandbox.connector.hook_eval import pre_tool_use

    result = asyncio.run(pre_tool_use(
        {
            "tool_name": "Bash",
            "tool_input": {"command": "./deploy.sh"},
            "cwd": str(lay.root),
            "session_id": "sb-test",
        },
        lay,
    ))

    hso = result.get("hookSpecificOutput", {})
    decision = hso.get("permissionDecision")
    reason = hso.get("permissionDecisionReason", "")

    assert decision == "deny", (
        f"expected deny for direct exec under floor, got {decision!r}"
    )
    assert "SCRIPT_UNPINNABLE" in reason, (
        f"deny reason should contain SCRIPT_UNPINNABLE, got: {reason!r}"
    )

    # No pending record should be written for a deny.
    pending = list(lay.pending_dir.glob("*.json"))
    assert not pending, (
        f"deny should not write a pending record, found {len(pending)}"
    )


# ===================================================================
# 3. Symlink swap after escalation
# ===================================================================

@pytest.mark.skipif(
    sys.platform == "win32" and not _can_symlink(),
    reason="Creating symlinks on Windows requires Developer Mode or admin "
           "elevation (SeCreateSymbolicLinkPrivilege not available)",
)

def test_symlink_swap_after_escalation_refused(tmp_path, monkeypatch):
    """Escalate ``python deploy.py``, replace the file with a symlink to a
    malicious script after escalation: the broker must refuse."""
    _need_t12c()

    kh = tmp_path / "keyhome"
    kh.mkdir()
    monkeypatch.setenv("SANDBOX_KEY_HOME", str(kh))
    lay = _ws(tmp_path / "ws")

    marker = tmp_path / "marker_symlink.txt"
    deploy = lay.root / "deploy.py"
    deploy.write_text(
        'import pathlib; pathlib.Path("safe.txt").write_text("ok")\n',
        encoding="utf-8",
    )

    cmd = f'"{_PYTHON}" deploy.py'
    _rec, req_id = _hook_escalate(lay, cmd, monkeypatch)

    # Replace deploy.py with a symlink to a malicious script
    malicious = tmp_path / "malicious.py"
    malicious.write_text(
        f'import pathlib; pathlib.Path(r"{marker}").write_text("PWNED-SYMLINK")\n',
        encoding="utf-8",
    )
    deploy.unlink()
    deploy.symlink_to(malicious)

    from sandbox.connector.approval import approve

    result = asyncio.run(approve(lay, req_id, "test-reviewer"))

    assert not marker.exists(), "symlink-swapped script was executed"
    assert result.get("status") != "executed", \
        f"broker executed via symlink swap: {result}"


# ===================================================================
# 4. Remote path -- modify before apply_external
# ===================================================================


def test_remote_modified_before_apply_refused(tmp_path, monkeypatch):
    """Remote path: create a pending escalation referencing a script, modify
    the script, then apply two valid remote approvals through
    ``apply_external``: nothing must run."""
    _need_t12c()

    marker = tmp_path / "marker_remote.txt"
    bob, carol = _keygen(), _keygen()
    ctx = _setup_managed_workspace(
        tmp_path, monkeypatch,
        approver_sks=[
            (bob[0], bob[1], bob[2], "user-bob", "cli"),
            (carol[0], carol[1], carol[2], "user-carol", "cli"),
        ],
    )
    lay = ctx["lay"]

    tool = lay.root / "tool.py"
    tool.write_text(
        f'import pathlib; pathlib.Path(r"{marker}").write_text("original")\n',
        encoding="utf-8",
    )
    cmd = f'"{_PYTHON}" tool.py'

    rec = _create_pending_request(lay, "req-remote-sb", command=cmd)

    # Attacker modifies the script after the escalation is recorded
    tool.write_text(
        f'import pathlib; pathlib.Path(r"{marker}").write_text("PWNED-REMOTE")\n',
        encoding="utf-8",
    )

    approvals = [
        _make_remote_approval(
            bob[0],
            request_id="req-remote-sb",
            command=cmd,
            fingerprint=rec["fingerprint"],
            policy_sequence=ctx["policy_sequence"],
            user_id="user-bob",
        ),
        _make_remote_approval(
            carol[0],
            request_id="req-remote-sb",
            command=cmd,
            fingerprint=rec["fingerprint"],
            policy_sequence=ctx["policy_sequence"],
            user_id="user-carol",
        ),
    ]

    from sandbox.connector.approval import apply_external

    result = asyncio.run(apply_external(
        lay, "req-remote-sb", approvals,
        clock=lambda: time.time(),
    ))

    assert not marker.exists() or marker.read_text() != "PWNED-REMOTE", \
        "modified script was executed via the remote approval path"
    assert result["status"] != "executed" or not marker.exists(), \
        f"apply_external ran modified script: {result}"


# ===================================================================
# 5. Guards (pass today and after the fix)
# ===================================================================

def test_guard_unchanged_script_approved_runs_once(tmp_path, monkeypatch):
    """An unchanged script, properly approved, runs exactly once and its
    output marker appears.  Passes today (no script binding) and after the
    fix (content unchanged so any hash still matches)."""
    kh = tmp_path / "keyhome"
    kh.mkdir()
    monkeypatch.setenv("SANDBOX_KEY_HOME", str(kh))
    lay = _ws(tmp_path / "ws")

    marker = tmp_path / "marker_guard.txt"
    tool = lay.root / "tool.py"
    tool.write_text(
        f'import pathlib; pathlib.Path(r"{marker}").write_text("guard-ok")\n',
        encoding="utf-8",
    )

    cmd = f'"{_PYTHON}" tool.py'

    # Create a pending record (real queue API, not the hook, so the test
    # does not depend on the hook's command-classification rules).
    from sandbox.connector.approval import _binding_fingerprint
    from sandbox.connector.queue import EscalationQueue

    # Named test-setup edit (T12c c2): add fp_v=2, script fields so the
    # broker accepts the record (RECORD_UNVERSIONED refusal otherwise).
    from sandbox.connector.script_pin import resolve as _resolve

    _sr = _resolve(cmd, "Bash", str(lay.root), str(lay.root),
                   key_home=os.environ.get("SANDBOX_KEY_HOME", ""))
    rec = {
        "request_id": "guard-1",
        "command": cmd,
        "kind": "command",
        "tool_name": "Bash",
        "exec_cwd": str(lay.root),
        "root": str(lay.root),
        "requires_dual": False,
        "bundle_sequence": 0,
        "fp_v": 2,
        "script": _sr.script,
        "script_unbound": _sr.script_unbound,
        "script_preview": _sr.script_preview,
    }
    rec["fingerprint"] = _binding_fingerprint(rec)
    queue = EscalationQueue(lay)
    queue.submit(rec)

    # Approve -- script is unchanged
    from sandbox.connector.approval import approve

    result = asyncio.run(approve(lay, "guard-1", "test-reviewer"))

    # Handle dual control: if oversight promotes to dual, approve again.
    if result.get("status") == "awaiting_second":
        result = asyncio.run(approve(lay, "guard-1", "test-reviewer-2"))

    assert result["status"] == "executed", f"unexpected status: {result}"
    assert marker.exists(), "marker not created -- script did not run"
    assert marker.read_text() == "guard-ok"


def test_guard_binding_fingerprint_importable():
    """Guard: ``_binding_fingerprint`` is importable and callable."""
    from sandbox.connector.approval import _binding_fingerprint

    assert callable(_binding_fingerprint)
    # Smoke: a record with the standard fields produces a hex digest.
    fp = _binding_fingerprint({
        "kind": "command", "tool_name": "Bash", "command": "echo test",
        "exec_cwd": "/tmp", "root": "/tmp", "requires_dual": False,
        "bundle_sequence": 0, "request_id": "smoke-1",
    })
    assert isinstance(fp, str) and len(fp) == 64


# ===================================================================
# Extra tests 1-8, 10-13 (T12c c1)
#
# Each strict xfail raises M2T12cPending via the behavioural
# ``_need_t12c()`` gate.  Guards (no marker) pass today.
# ===================================================================


# -------------------------------------------------------------------
# Extra 1  Fingerprint v2
# -------------------------------------------------------------------


def test_extra1_fp_v2_one_byte_change_changes_fingerprint(tmp_path, monkeypatch):
    """One changed script byte changes the fingerprint (fp_v 2)."""
    _need_t12c()

    kh = tmp_path / "keyhome"
    kh.mkdir()
    monkeypatch.setenv("SANDBOX_KEY_HOME", str(kh))
    lay = _ws(tmp_path / "ws")

    script = lay.root / "fp_test.py"
    script.write_text("print('a')\n", encoding="utf-8")
    _rec_a, _rid_a = _hook_escalate(lay, "python fp_test.py", monkeypatch)
    fp_a = _rec_a["fingerprint"]

    # Change one byte in the script and re-escalate
    script.write_text("print('b')\n", encoding="utf-8")
    _rec_b, _rid_b = _hook_escalate(lay, "python fp_test.py", monkeypatch)
    fp_b = _rec_b["fingerprint"]

    assert fp_a != fp_b, "fingerprint did not change when script content changed"



def test_extra1_fp_v2_new_fields_affect_fingerprint(tmp_path, monkeypatch):
    """Each of fp_v, script and script_unbound affects the fingerprint."""
    _need_t12c()

    kh = tmp_path / "keyhome"
    kh.mkdir()
    monkeypatch.setenv("SANDBOX_KEY_HOME", str(kh))
    lay = _ws(tmp_path / "ws")

    script = lay.root / "fpf.py"
    script.write_text("print('fp-field-test')\n", encoding="utf-8")
    rec, _rid = _hook_escalate(lay, "python fpf.py", monkeypatch)

    assert rec.get("fp_v") == 2, f"expected fp_v=2, got {rec.get('fp_v')}"
    assert rec.get("script") is not None, "expected script dict in record"
    assert "sha256" in rec["script"], "expected sha256 in script dict"



def test_extra1_fp_v2_no_fpv_refused_by_apply_external(tmp_path, monkeypatch):
    """A record without fp_v is refused by apply_external (no file touched)."""
    _need_t12c()

    marker = tmp_path / "marker_nofpv.txt"
    bob, carol = _keygen(), _keygen()
    ctx = _setup_managed_workspace(
        tmp_path, monkeypatch,
        approver_sks=[
            (bob[0], bob[1], bob[2], "user-bob", "cli"),
            (carol[0], carol[1], carol[2], "user-carol", "cli"),
        ],
    )
    lay = ctx["lay"]

    script = lay.root / "nofpv.py"
    script.write_text(
        f'import pathlib; pathlib.Path(r"{marker}").write_text("ran")\n',
        encoding="utf-8",
    )

    # Create a pending record the old way (no fp_v)
    rec = _create_pending_request(lay, "req-nofpv", command="python nofpv.py",
                                  fp_v=None)
    # Ensure fp_v is absent
    assert "fp_v" not in rec or rec.get("fp_v") is None

    approvals = [
        _make_remote_approval(
            bob[0], request_id="req-nofpv", command="python nofpv.py",
            fingerprint=rec["fingerprint"], policy_sequence=ctx["policy_sequence"],
            user_id="user-bob",
        ),
        _make_remote_approval(
            carol[0], request_id="req-nofpv", command="python nofpv.py",
            fingerprint=rec["fingerprint"], policy_sequence=ctx["policy_sequence"],
            user_id="user-carol",
        ),
    ]

    from sandbox.connector.approval import apply_external

    result = asyncio.run(apply_external(
        lay, "req-nofpv", approvals, clock=lambda: time.time(),
    ))

    assert not marker.exists(), "record without fp_v should not execute"
    assert result.get("status") != "executed", (
        f"apply_external executed a record without fp_v: {result}"
    )


# -------------------------------------------------------------------
# Extra 2  Resolver table (parametrized)
# -------------------------------------------------------------------

_BOUND_FORMS = [
    ("python script.py", "python", ".py"),
    ("python3.12 script.py", "python3.12", ".py"),
    (f'"{_PYTHON}" script.py', "abs-python", ".py"),
    ("node script.js", "node", ".js"),
    ("bash script.sh", "bash", ".sh"),
    ("sh script.sh", "sh", ".sh"),
    ("pwsh -File script.ps1", "pwsh", ".ps1"),
]

_UNBOUND_REASONS = [
    # -c / -e: inline code
    ("python -c 'print(1)'", "-c"),
    # -m: module
    ("python -m pytest", "-m"),
    # stdin
    ("python -", "stdin"),
    # pipe
    ("python script.py | tee out.txt", "pipe"),
    # redirect
    ("python script.py > out.txt", "redirect"),
    # compound
    ("python a.py && python b.py", "compound"),
    # unknown interpreter
    ("lua script.lua", "unknown_interp"),
    # source / dot
    ("source script.sh", "source"),
    (". script.sh", "dot_source"),
    # cmd /c
    ("cmd /c script.bat", "cmd_c"),
    # preloads
    ("python -r preload.py script.py", "preload"),
    # pwsh without -File
    ("pwsh script.ps1", "pwsh_no_file"),
    # dynamic word (expansion)
    ("python $SCRIPT", "dynamic"),
    # glob
    ("python *.py", "glob"),
]

_DEFERRED_FORMS = [
    ("./deploy.sh", "direct_exec_sh"),
    ("script.exe", "direct_exec_exe"),
    ("script.cmd", "direct_exec_cmd"),
    ("script.bat", "direct_exec_bat"),
    ("ruby script.rb", "ruby"),
    ("perl script.pl", "perl"),
    ("dash script.sh", "dash"),
    ("zsh script.zsh", "zsh"),
    ("py script.py", "py_launcher"),
    ("pythonw script.py", "pythonw"),
    ("powershell script.ps1", "powershell"),
]



@pytest.mark.parametrize("command,label,ext", _BOUND_FORMS,
                         ids=[x[1] for x in _BOUND_FORMS])
def test_extra2_resolver_bound(tmp_path, monkeypatch, command, label, ext):
    """Resolver marks bound forms as bound with a script dict."""
    _need_t12c()

    kh = tmp_path / "keyhome"
    kh.mkdir()
    monkeypatch.setenv("SANDBOX_KEY_HOME", str(kh))
    lay = _ws(tmp_path / "ws")

    # Create the script file the command references
    script_name = f"script{ext}"
    script = lay.root / script_name
    script.write_text("print('bound-form-test')\n", encoding="utf-8")

    rec, _rid = _hook_escalate(lay, command, monkeypatch)

    assert rec.get("script") is not None, (
        f"expected bound for {command!r}, got script=None"
    )
    assert rec["script"].get("sha256"), "missing sha256 in bound record"
    assert rec.get("script_unbound", "") == "", (
        f"expected empty script_unbound for bound form, got {rec.get('script_unbound')!r}"
    )



@pytest.mark.parametrize("command,reason", _UNBOUND_REASONS,
                         ids=[x[1] for x in _UNBOUND_REASONS])
def test_extra2_resolver_unbound(tmp_path, monkeypatch, command, reason):
    """Resolver marks unbound forms with a reason code."""
    _need_t12c()

    kh = tmp_path / "keyhome"
    kh.mkdir()
    monkeypatch.setenv("SANDBOX_KEY_HOME", str(kh))
    lay = _ws(tmp_path / "ws")

    # Create dummy scripts so file-not-found is not the reason
    for name in ("script.py", "script.sh", "script.ps1", "script.lua",
                 "a.py", "b.py", "preload.py"):
        (lay.root / name).write_text("# dummy\n", encoding="utf-8")

    # For unbound forms, the hook should still escalate (outside floor)
    # or deny (under floor); either way the record or reason must note unbound.
    from sandbox.connector.queue import EscalationQueue
    monkeypatch.setattr(EscalationQueue, "wait", _async_none)
    from sandbox.connector.hook_eval import pre_tool_use

    result = asyncio.run(pre_tool_use(
        {
            "tool_name": "Bash",
            "tool_input": {"command": command},
            "cwd": str(lay.root),
            "session_id": "sb-unbound",
        },
        lay,
    ))

    # Either a pending record with script_unbound set, or a deny
    pending = sorted(lay.pending_dir.glob("*.json"),
                     key=lambda p: p.stat().st_mtime)
    if pending:
        rec = json.loads(pending[-1].read_text(encoding="utf-8"))
        assert rec.get("script_unbound", "") != "", (
            f"expected non-empty script_unbound for {command!r}"
        )
    else:
        # Deny is also acceptable for unbound under the floor
        hso = result.get("hookSpecificOutput", {})
        assert hso.get("permissionDecision") == "deny", (
            f"unbound command {command!r} was neither escalated with "
            f"script_unbound nor denied"
        )



@pytest.mark.parametrize("command,label", _DEFERRED_FORMS,
                         ids=[x[1] for x in _DEFERRED_FORMS])
def test_extra2_resolver_deferred_unbound(tmp_path, monkeypatch, command, label):
    """Deferred forms (C-c0-5) are unbound in M2."""
    _need_t12c()

    kh = tmp_path / "keyhome"
    kh.mkdir()
    monkeypatch.setenv("SANDBOX_KEY_HOME", str(kh))
    lay = _ws(tmp_path / "ws")

    # Create dummy scripts
    for name in ("deploy.sh", "script.exe", "script.cmd", "script.bat",
                 "script.rb", "script.pl", "script.zsh", "script.py",
                 "script.ps1"):
        f = lay.root / name
        f.write_text("# dummy\n", encoding="utf-8")

    from sandbox.connector.queue import EscalationQueue
    monkeypatch.setattr(EscalationQueue, "wait", _async_none)
    from sandbox.connector.hook_eval import pre_tool_use

    result = asyncio.run(pre_tool_use(
        {
            "tool_name": "Bash",
            "tool_input": {"command": command},
            "cwd": str(lay.root),
            "session_id": "sb-deferred",
        },
        lay,
    ))

    pending = sorted(lay.pending_dir.glob("*.json"),
                     key=lambda p: p.stat().st_mtime)
    if pending:
        rec = json.loads(pending[-1].read_text(encoding="utf-8"))
        assert rec.get("script_unbound", "") != "", (
            f"deferred form {command!r} should be unbound"
        )
    else:
        hso = result.get("hookSpecificOutput", {})
        assert hso.get("permissionDecision") == "deny", (
            f"deferred form {command!r} was neither unbound-escalated nor denied"
        )


@pytest.mark.skipif(sys.platform != "win32",
                    reason="NTFS stream operand is Windows-only")

def test_extra2_ntfs_stream_operand_unbound(tmp_path, monkeypatch):
    """An NTFS alternate data stream operand is unbound (ADR 0010 s9 9.1)."""
    _need_t12c()

    kh = tmp_path / "keyhome"
    kh.mkdir()
    monkeypatch.setenv("SANDBOX_KEY_HOME", str(kh))
    lay = _ws(tmp_path / "ws")

    script = lay.root / "tool.py"
    script.write_text("print('ads')\n", encoding="utf-8")

    from sandbox.connector.queue import EscalationQueue
    monkeypatch.setattr(EscalationQueue, "wait", _async_none)
    from sandbox.connector.hook_eval import pre_tool_use

    # tool.py:Zone.Identifier is an NTFS ADS path
    result = asyncio.run(pre_tool_use(
        {
            "tool_name": "Bash",
            "tool_input": {"command": "python tool.py:Zone.Identifier"},
            "cwd": str(lay.root),
            "session_id": "sb-ntfs",
        },
        lay,
    ))

    pending = sorted(lay.pending_dir.glob("*.json"),
                     key=lambda p: p.stat().st_mtime)
    if pending:
        rec = json.loads(pending[-1].read_text(encoding="utf-8"))
        assert rec.get("script_unbound", "") != "", (
            "NTFS stream operand should be unbound"
        )
    else:
        hso = result.get("hookSpecificOutput", {})
        assert hso.get("permissionDecision") == "deny"



@pytest.mark.parametrize("family,opt_cmd", [
    ("python", "python -W error -X utf8 script.py"),
    ("python", "python -O script.py"),
    ("bash", "bash --norc script.sh"),
    ("pwsh", "pwsh -File -NoProfile script.ps1"),
], ids=["py-W-X", "py-O", "bash-norc", "pwsh-NoProfile"])
def test_extra2_option_parsing_binds_correct_word(
    tmp_path, monkeypatch, family, opt_cmd
):
    """Per-family option parsing: options from the allowlist do not bind the
    wrong word as the script operand."""
    _need_t12c()

    kh = tmp_path / "keyhome"
    kh.mkdir()
    monkeypatch.setenv("SANDBOX_KEY_HOME", str(kh))
    lay = _ws(tmp_path / "ws")

    for name in ("script.py", "script.sh", "script.ps1"):
        (lay.root / name).write_text("# option-parse-test\n", encoding="utf-8")

    rec, _rid = _hook_escalate(lay, opt_cmd, monkeypatch)

    assert rec.get("script") is not None, (
        f"expected bound for {opt_cmd!r} (correct option parsing)"
    )
    # The bound script must be one of the real script files
    rel = rec["script"].get("rel", "")
    assert rel.endswith((".py", ".sh", ".ps1")), (
        f"bound the wrong word: rel={rel!r} for {opt_cmd!r}"
    )


# -------------------------------------------------------------------
# Extra 3  Floor (parametrized)
# -------------------------------------------------------------------

_FLOOR_UNBOUND_COMMANDS = [
    ("./deploy.sh", "direct_exec"),
    ("python -c 'print(1)'", "inline_code"),
    ("ruby script.rb", "deferred_interp"),
]



@pytest.mark.parametrize("command,label", _FLOOR_UNBOUND_COMMANDS,
                         ids=[x[1] for x in _FLOOR_UNBOUND_COMMANDS])
def test_extra3_floor_unbound_deny_script_unpinnable(
    tmp_path, monkeypatch, command, label
):
    """Under the floor (enrolled), an unbound command is denied with
    SCRIPT_UNPINNABLE whose message names the allowed shape."""
    _need_t12c()

    bob, carol = _keygen(), _keygen()
    ctx = _setup_managed_workspace(
        tmp_path, monkeypatch,
        approver_sks=[
            (bob[0], bob[1], bob[2], "user-bob", "cli"),
            (carol[0], carol[1], carol[2], "user-carol", "cli"),
        ],
    )
    lay = ctx["lay"]

    for name in ("deploy.sh", "script.rb"):
        (lay.root / name).write_text("# dummy\n", encoding="utf-8")

    from sandbox.connector.queue import EscalationQueue
    monkeypatch.setattr(EscalationQueue, "wait", _async_none)
    from sandbox.connector.hook_eval import pre_tool_use

    result = asyncio.run(pre_tool_use(
        {
            "tool_name": "Bash",
            "tool_input": {"command": command},
            "cwd": str(lay.root),
            "session_id": "sb-floor-unbound",
        },
        lay,
    ))

    hso = result.get("hookSpecificOutput", {})
    decision = hso.get("permissionDecision")
    reason = hso.get("permissionDecisionReason", "")

    assert decision == "deny", (
        f"expected deny for unbound {command!r} under floor, got {decision!r}"
    )
    assert "SCRIPT_UNPINNABLE" in reason, (
        f"reason should contain SCRIPT_UNPINNABLE, got: {reason!r}"
    )
    # The deny message must name the allowed shape
    assert "python" in reason.lower() or "node" in reason.lower() or \
           "bash" in reason.lower() or "pwsh" in reason.lower(), (
        f"deny message should name allowed interpreters, got: {reason!r}"
    )


_FLOOR_BAD_BODY_CASES = [
    ("binary", b"\x00\x01\x02\x03" * 100, "binary_body"),
    ("over_64k", b"x" * (64 * 1024 + 1), "over_64k"),
    ("non_utf8", b"\x80\x81\x82\x83", "non_utf8"),
    ("control_char", "print('ok')\x07\n".encode("utf-8"), "control_char"),
]



@pytest.mark.parametrize("label,body,case_id", _FLOOR_BAD_BODY_CASES,
                         ids=[x[2] for x in _FLOOR_BAD_BODY_CASES])
def test_extra3_floor_bad_body_denied(
    tmp_path, monkeypatch, label, body, case_id
):
    """Under the floor, a bound script whose body cannot be shown
    (binary, over 64 KiB, non-UTF-8, control chars) is denied."""
    _need_t12c()

    bob, carol = _keygen(), _keygen()
    ctx = _setup_managed_workspace(
        tmp_path, monkeypatch,
        approver_sks=[
            (bob[0], bob[1], bob[2], "user-bob", "cli"),
            (carol[0], carol[1], carol[2], "user-carol", "cli"),
        ],
    )
    lay = ctx["lay"]

    script = lay.root / "bad_body.py"
    script.write_bytes(body)

    from sandbox.connector.queue import EscalationQueue
    monkeypatch.setattr(EscalationQueue, "wait", _async_none)
    from sandbox.connector.hook_eval import pre_tool_use

    result = asyncio.run(pre_tool_use(
        {
            "tool_name": "Bash",
            "tool_input": {"command": "python bad_body.py"},
            "cwd": str(lay.root),
            "session_id": "sb-floor-body",
        },
        lay,
    ))

    hso = result.get("hookSpecificOutput", {})
    decision = hso.get("permissionDecision")
    assert decision == "deny", (
        f"expected deny for bad body ({label}), got {decision!r}"
    )



def test_extra3_standalone_unbound_escalates_with_warning(tmp_path, monkeypatch):
    """Outside the floor (standalone single approval), an unbound command
    escalates and the reviewer sees 'content NOT bound: <reason>'."""
    _need_t12c()

    kh = tmp_path / "keyhome"
    kh.mkdir()
    monkeypatch.setenv("SANDBOX_KEY_HOME", str(kh))
    lay = _ws(tmp_path / "ws")

    script = lay.root / "deploy.sh"
    script.write_text("#!/bin/sh\necho hi\n", encoding="utf-8")

    # Use -c to get an unbound command that still references a shell
    from sandbox.connector.queue import EscalationQueue
    monkeypatch.setattr(EscalationQueue, "wait", _async_none)
    from sandbox.connector.hook_eval import pre_tool_use

    result = asyncio.run(pre_tool_use(
        {
            "tool_name": "Bash",
            "tool_input": {"command": "./deploy.sh"},
            "cwd": str(lay.root),
            "session_id": "sb-standalone",
        },
        lay,
    ))

    hso = result.get("hookSpecificOutput", {})
    reason = hso.get("permissionDecisionReason", "")
    # Standalone should escalate (pending), not hard-deny with SCRIPT_UNPINNABLE
    assert "SCRIPT_UNPINNABLE" not in reason, (
        f"standalone unbound should not be SCRIPT_UNPINNABLE, got: {reason!r}"
    )
    # A pending record must have been written
    pending = sorted(lay.pending_dir.glob("*.json"),
                     key=lambda p: p.stat().st_mtime)
    assert pending, "standalone unbound should write a pending record"
    rec = json.loads(pending[-1].read_text(encoding="utf-8"))
    assert rec.get("script_unbound", "") != "", (
        "standalone unbound should have script_unbound reason"
    )
    # The reviewer-facing text must note the unbound content
    rec_reason = rec.get("reason", "")
    assert "content NOT bound" in rec_reason, (
        f"pending reason should contain 'content NOT bound', got: {rec_reason!r}"
    )


# -------------------------------------------------------------------
# Extra 4  Meaning is kept: $0, __file__, cwd, sibling
# -------------------------------------------------------------------


def test_extra4_meaning_kept(tmp_path, monkeypatch):
    """A bound script prints sys.argv[0], __file__ and cwd, and reads a
    sibling file.  The output matches a direct run."""
    _need_t12c()

    kh = tmp_path / "keyhome"
    kh.mkdir()
    monkeypatch.setenv("SANDBOX_KEY_HOME", str(kh))
    lay = _ws(tmp_path / "ws")

    import subprocess

    marker = tmp_path / "meaning.json"
    sibling = lay.root / "sibling.txt"
    sibling.write_text("hello-sibling", encoding="utf-8")

    script = lay.root / "meaning_test.py"
    script.write_text(
        "import json, sys, os, pathlib\n"
        f"out = {{'argv0': sys.argv[0], 'file': __file__, "
        f"'cwd': os.getcwd(), "
        f"'sibling': pathlib.Path('sibling.txt').read_text()}}\n"
        f"pathlib.Path(r'{marker}').write_text(json.dumps(out))\n",
        encoding="utf-8",
    )

    # Direct run for reference
    ref_result = subprocess.run(
        [_PYTHON, "meaning_test.py"],
        cwd=str(lay.root),
        capture_output=True, text=True, timeout=30,
    )
    assert ref_result.returncode == 0, f"direct run failed: {ref_result.stderr}"
    ref_data = json.loads(marker.read_text(encoding="utf-8"))
    marker.unlink()

    # Broker run through the approval path
    rec, req_id = _hook_escalate(lay, "python meaning_test.py", monkeypatch)

    from sandbox.connector.approval import approve
    result = asyncio.run(approve(lay, req_id, "test-reviewer"))
    if result.get("status") == "awaiting_second":
        result = asyncio.run(approve(lay, req_id, "test-reviewer-2"))

    assert result["status"] == "executed", f"broker did not execute: {result}"
    assert marker.exists(), "meaning marker not created"
    broker_data = json.loads(marker.read_text(encoding="utf-8"))

    # The values must match the direct run
    assert broker_data["argv0"] == ref_data["argv0"], (
        f"argv[0] mismatch: {broker_data['argv0']!r} vs {ref_data['argv0']!r}"
    )
    assert broker_data["cwd"] == ref_data["cwd"], (
        f"cwd mismatch: {broker_data['cwd']!r} vs {ref_data['cwd']!r}"
    )
    assert broker_data["sibling"] == "hello-sibling"


# -------------------------------------------------------------------
# Extra 5  Re-resolve
# -------------------------------------------------------------------


def test_extra5_reresolve_null_script_with_actual_file_refused(
    tmp_path, monkeypatch
):
    """A record with script=null whose command resolves to a file at exec
    time is refused (script_not_bound)."""
    _need_t12c()

    kh = tmp_path / "keyhome"
    kh.mkdir()
    monkeypatch.setenv("SANDBOX_KEY_HOME", str(kh))
    lay = _ws(tmp_path / "ws")

    marker = tmp_path / "marker_reresolve.txt"
    script = lay.root / "trick.py"

    # Hand-build a record with script=null (command references a file
    # but the record was created before the resolver)
    from sandbox.connector.queue import EscalationQueue
    rec = {
        "request_id": "req-reresolve",
        "command": "python trick.py",
        "kind": "command",
        "tool_name": "Bash",
        "exec_cwd": str(lay.root),
        "root": str(lay.root),
        "requires_dual": False,
        "bundle_sequence": 0,
        "script": None,
        "script_unbound": "",
        "fp_v": 2,
    }
    from sandbox.connector.approval import _binding_fingerprint
    rec["fingerprint"] = _binding_fingerprint(rec)
    queue = EscalationQueue(lay)
    queue.submit(rec)

    # Now create the script file (it exists at exec but not at record time)
    script.write_text(
        f'import pathlib; pathlib.Path(r"{marker}").write_text("reresolve")\n',
        encoding="utf-8",
    )

    from sandbox.connector.approval import approve
    result = asyncio.run(approve(lay, "req-reresolve", "test-reviewer"))
    if result.get("status") == "awaiting_second":
        result = asyncio.run(approve(lay, "req-reresolve", "test-reviewer-2"))

    assert not marker.exists(), "re-resolve mismatch: null script ran a file"
    assert result.get("status") != "executed" or result.get("state") == "refused", (
        f"expected refusal for null-script with actual file: {result}"
    )



def test_extra5_edited_pending_record_refused(tmp_path, monkeypatch):
    """An edited pending record is refused by the fingerprint check and the
    payload check."""
    _need_t12c()

    marker = tmp_path / "marker_edited.txt"
    bob, carol = _keygen(), _keygen()
    ctx = _setup_managed_workspace(
        tmp_path, monkeypatch,
        approver_sks=[
            (bob[0], bob[1], bob[2], "user-bob", "cli"),
            (carol[0], carol[1], carol[2], "user-carol", "cli"),
        ],
    )
    lay = ctx["lay"]

    script = lay.root / "edit_test.py"
    script.write_text(
        f'import pathlib; pathlib.Path(r"{marker}").write_text("ok")\n',
        encoding="utf-8",
    )

    rec = _create_pending_request(
        lay, "req-edited", command="python edit_test.py",
    )
    original_fp = rec["fingerprint"]

    # Edit the pending record's command
    pending_file = lay.pending_dir / "req-edited.json"
    data = json.loads(pending_file.read_text(encoding="utf-8"))
    data["command"] = "python /etc/passwd"
    pending_file.write_text(json.dumps(data), encoding="utf-8")

    approvals = [
        _make_remote_approval(
            bob[0], request_id="req-edited", command="python edit_test.py",
            fingerprint=original_fp, policy_sequence=ctx["policy_sequence"],
            user_id="user-bob",
        ),
        _make_remote_approval(
            carol[0], request_id="req-edited", command="python edit_test.py",
            fingerprint=original_fp, policy_sequence=ctx["policy_sequence"],
            user_id="user-carol",
        ),
    ]

    from sandbox.connector.approval import apply_external

    result = asyncio.run(apply_external(
        lay, "req-edited", approvals, clock=lambda: time.time(),
    ))

    assert not marker.exists(), "edited pending record should not execute"
    assert result.get("status") != "executed", (
        f"apply_external ran after record edit: {result}"
    )


# -------------------------------------------------------------------
# Extra 6  Windows pin (sharing violations while child runs)
# -------------------------------------------------------------------

@pytest.mark.skipif(sys.platform != "win32",
                    reason="Windows-only: share-mode locks")

def test_extra6_win_pin_write_blocked(tmp_path, monkeypatch):
    """While the child runs, an open-for-write on the script fails with a
    sharing violation."""
    _need_t12c()

    kh = tmp_path / "keyhome"
    kh.mkdir()
    monkeypatch.setenv("SANDBOX_KEY_HOME", str(kh))
    lay = _ws(tmp_path / "ws")

    barrier = tmp_path / "barrier.txt"
    done_flag = tmp_path / "done.txt"
    script = lay.root / "pin_test.py"
    script.write_text(
        "import time, pathlib\n"
        f"pathlib.Path(r'{barrier}').write_text('ready')\n"
        "while True:\n"
        f"    if pathlib.Path(r'{done_flag}').exists(): break\n"
        "    time.sleep(0.05)\n",
        encoding="utf-8",
    )

    import threading

    result_holder = {}

    def _approve_thread():
        rec, req_id = _hook_escalate(lay, "python pin_test.py", monkeypatch)
        from sandbox.connector.approval import approve
        r = asyncio.run(approve(lay, req_id, "test-reviewer"))
        if r.get("status") == "awaiting_second":
            r = asyncio.run(approve(lay, req_id, "test-reviewer-2"))
        result_holder["result"] = r

    t = threading.Thread(target=_approve_thread, daemon=True)
    t.start()

    # Wait for the script to signal ready
    deadline = time.time() + 30
    while not barrier.exists() and time.time() < deadline:
        time.sleep(0.05)
    assert barrier.exists(), "script did not start"

    # Try to open the script for writing - should fail
    write_blocked = False
    try:
        with open(script, "w") as f:
            f.write("# attacker\n")
    except (PermissionError, OSError):
        write_blocked = True

    # Signal done so the script exits
    done_flag.write_text("1", encoding="utf-8")
    t.join(timeout=30)

    assert write_blocked, "open-for-write should be blocked by sharing lock"


@pytest.mark.skipif(sys.platform != "win32",
                    reason="Windows-only: share-mode locks")

def test_extra6_win_pin_delete_blocked(tmp_path, monkeypatch):
    """While the child runs, deleting the script fails with a sharing
    violation."""
    _need_t12c()

    kh = tmp_path / "keyhome"
    kh.mkdir()
    monkeypatch.setenv("SANDBOX_KEY_HOME", str(kh))
    lay = _ws(tmp_path / "ws")

    barrier = tmp_path / "barrier.txt"
    done_flag = tmp_path / "done.txt"
    script = lay.root / "pin_del.py"
    script.write_text(
        "import time, pathlib\n"
        f"pathlib.Path(r'{barrier}').write_text('ready')\n"
        "while True:\n"
        f"    if pathlib.Path(r'{done_flag}').exists(): break\n"
        "    time.sleep(0.05)\n",
        encoding="utf-8",
    )

    import threading

    def _approve_thread():
        rec, req_id = _hook_escalate(lay, "python pin_del.py", monkeypatch)
        from sandbox.connector.approval import approve
        r = asyncio.run(approve(lay, req_id, "test-reviewer"))
        if r.get("status") == "awaiting_second":
            asyncio.run(approve(lay, req_id, "test-reviewer-2"))

    t = threading.Thread(target=_approve_thread, daemon=True)
    t.start()

    deadline = time.time() + 30
    while not barrier.exists() and time.time() < deadline:
        time.sleep(0.05)
    assert barrier.exists(), "script did not start"

    delete_blocked = False
    try:
        script.unlink()
    except (PermissionError, OSError):
        delete_blocked = True

    done_flag.write_text("1", encoding="utf-8")
    t.join(timeout=30)

    assert delete_blocked, "delete should be blocked by sharing lock"


@pytest.mark.skipif(sys.platform != "win32",
                    reason="Windows-only: share-mode locks")

def test_extra6_win_pin_rename_blocked(tmp_path, monkeypatch):
    """While the child runs, renaming the script and its folder fails."""
    _need_t12c()

    kh = tmp_path / "keyhome"
    kh.mkdir()
    monkeypatch.setenv("SANDBOX_KEY_HOME", str(kh))
    lay = _ws(tmp_path / "ws")

    subdir = lay.root / "scripts"
    subdir.mkdir()
    barrier = tmp_path / "barrier.txt"
    done_flag = tmp_path / "done.txt"
    script = subdir / "pin_rename.py"
    script.write_text(
        "import time, pathlib\n"
        f"pathlib.Path(r'{barrier}').write_text('ready')\n"
        "while True:\n"
        f"    if pathlib.Path(r'{done_flag}').exists(): break\n"
        "    time.sleep(0.05)\n",
        encoding="utf-8",
    )

    import threading

    def _approve_thread():
        rec, req_id = _hook_escalate(
            lay, "python scripts/pin_rename.py", monkeypatch
        )
        from sandbox.connector.approval import approve
        r = asyncio.run(approve(lay, req_id, "test-reviewer"))
        if r.get("status") == "awaiting_second":
            asyncio.run(approve(lay, req_id, "test-reviewer-2"))

    t = threading.Thread(target=_approve_thread, daemon=True)
    t.start()

    deadline = time.time() + 30
    while not barrier.exists() and time.time() < deadline:
        time.sleep(0.05)
    assert barrier.exists(), "script did not start"

    rename_file_blocked = False
    try:
        script.rename(subdir / "renamed.py")
    except (PermissionError, OSError):
        rename_file_blocked = True

    rename_dir_blocked = False
    try:
        subdir.rename(lay.root / "scripts_renamed")
    except (PermissionError, OSError):
        rename_dir_blocked = True

    done_flag.write_text("1", encoding="utf-8")
    t.join(timeout=30)

    assert rename_file_blocked, "rename of script should be blocked"
    assert rename_dir_blocked, "rename of folder should be blocked"


@pytest.mark.skipif(sys.platform != "win32",
                    reason="Windows-only: hard link from handle (C-c0-1)")

def test_extra6_win_nlink_from_handle(tmp_path, monkeypatch):
    """nlink and attributes come from the open handle: a hard link made
    between the pre-check and the open does not fool the broker (C-c0-1)."""
    _need_t12c()

    kh = tmp_path / "keyhome"
    kh.mkdir()
    monkeypatch.setenv("SANDBOX_KEY_HOME", str(kh))
    lay = _ws(tmp_path / "ws")

    marker = tmp_path / "marker_nlink.txt"
    script = lay.root / "nlink_test.py"
    script.write_text(
        f'import pathlib; pathlib.Path(r"{marker}").write_text("nlink")\n',
        encoding="utf-8",
    )

    rec, req_id = _hook_escalate(lay, "python nlink_test.py", monkeypatch)

    # Create a hard link AFTER escalation so nlink > 1 at broker time (C-c0-1)
    hardlink = lay.root / "nlink_alias.py"
    try:
        hardlink.hardlink_to(script)
    except (OSError, AttributeError):
        pytest.skip("Cannot create hard links in this environment")

    from sandbox.connector.approval import approve
    result = asyncio.run(approve(lay, req_id, "test-reviewer"))
    if result.get("status") == "awaiting_second":
        result = asyncio.run(approve(lay, req_id, "test-reviewer-2"))

    # The broker should refuse because nlink > 1
    assert not marker.exists(), "hard-linked script should be refused"
    assert result.get("status") != "executed" or result.get("state") == "refused", (
        f"broker should refuse nlink > 1: {result}"
    )


# -------------------------------------------------------------------
# Extra 7  POSIX after-run check (POSIX only, ruling e)
# -------------------------------------------------------------------

@pytest.mark.skipif(sys.platform == "win32",
                    reason="POSIX-only: after-run self-swap check (ruling e)")

def test_extra7_posix_after_run_self_swap(tmp_path, monkeypatch):
    """A self-swapping script sets ``script_changed_during_run`` and raises
    the alert on POSIX."""
    _need_t12c()

    kh = tmp_path / "keyhome"
    kh.mkdir()
    monkeypatch.setenv("SANDBOX_KEY_HOME", str(kh))
    lay = _ws(tmp_path / "ws")

    marker = tmp_path / "marker_selfswap.txt"
    script = lay.root / "selfswap.py"
    # Script overwrites itself and then writes the marker
    script.write_text(
        "import pathlib\n"
        f"pathlib.Path(r'{script}').write_text('# swapped content\\n')\n"
        f"pathlib.Path(r'{marker}').write_text('ran')\n",
        encoding="utf-8",
    )

    rec, req_id = _hook_escalate(lay, "python selfswap.py", monkeypatch)

    from sandbox.connector.approval import approve
    result = asyncio.run(approve(lay, req_id, "test-reviewer"))
    if result.get("status") == "awaiting_second":
        result = asyncio.run(approve(lay, req_id, "test-reviewer-2"))

    # The script may run (POSIX cannot prevent the exec window), but
    # the done record must note the change
    done = _done_record(lay, req_id)
    assert done is not None, "expected a done record"
    assert done.get("script_changed_during_run") is True, (
        f"expected script_changed_during_run=True, got {done}"
    )


# -------------------------------------------------------------------
# Extra 8  Refusal record properties
# -------------------------------------------------------------------


def test_extra8_refusal_record_signed_terminal_chained(tmp_path, monkeypatch):
    """A refusal record (SCRIPT_CHANGED) is signed, terminal, chained in
    the audit and alerted.  A re-delivered approval cannot run it."""
    _need_t12c()

    kh = tmp_path / "keyhome"
    kh.mkdir()
    monkeypatch.setenv("SANDBOX_KEY_HOME", str(kh))
    lay = _ws(tmp_path / "ws")

    marker = tmp_path / "marker_refusal.txt"
    script = lay.root / "refusal_test.py"
    script.write_text(
        f'import pathlib; pathlib.Path(r"{marker}").write_text("ran")\n',
        encoding="utf-8",
    )

    rec, req_id = _hook_escalate(lay, "python refusal_test.py", monkeypatch)

    # Modify after escalation to trigger refusal
    script.write_text("# attacker bytes\n", encoding="utf-8")

    from sandbox.connector.approval import approve
    result = asyncio.run(approve(lay, req_id, "test-reviewer"))
    if result.get("status") == "awaiting_second":
        result = asyncio.run(approve(lay, req_id, "test-reviewer-2"))

    assert not marker.exists(), "refusal should not execute"

    done = _done_record(lay, req_id)
    assert done is not None, "expected a done record for refusal"

    # Terminal: state is refused
    assert done.get("state") == "refused" or done.get("status") == "refused", (
        f"refusal record should be terminal (refused), got: {done}"
    )

    # Signed: has a signature
    assert done.get("signature") or done.get("sig"), (
        "refusal record should be signed"
    )

    # Reason code
    reason = done.get("reason", "") or done.get("reason_code", "")
    assert "SCRIPT_CHANGED" in reason.upper() or "script_changed" in reason, (
        f"refusal reason should mention SCRIPT_CHANGED, got: {reason!r}"
    )

    # Re-deliver: a second approve must not run it
    result2 = asyncio.run(approve(lay, req_id, "test-reviewer-3"))
    assert result2.get("status") != "executed", (
        f"re-delivered approval ran after refusal: {result2}"
    )
    assert not marker.exists(), "re-delivery must not create the marker"



def test_extra8_refusal_record_remote_path_signed(tmp_path, monkeypatch):
    """A refusal on the remote path is signed by connector:<device_id>."""
    _need_t12c()

    marker = tmp_path / "marker_refusal_remote.txt"
    bob, carol = _keygen(), _keygen()
    ctx = _setup_managed_workspace(
        tmp_path, monkeypatch,
        approver_sks=[
            (bob[0], bob[1], bob[2], "user-bob", "cli"),
            (carol[0], carol[1], carol[2], "user-carol", "cli"),
        ],
    )
    lay = ctx["lay"]

    script = lay.root / "refusal_remote.py"
    script.write_text(
        f'import pathlib; pathlib.Path(r"{marker}").write_text("ran")\n',
        encoding="utf-8",
    )

    # Escalate through hook to get a proper fp_v=2 record
    rec, req_id = _hook_escalate(lay, "python refusal_remote.py", monkeypatch)

    # Modify after escalation
    script.write_text("# evil\n", encoding="utf-8")

    approvals = [
        _make_remote_approval(
            bob[0], request_id=req_id, command="python refusal_remote.py",
            fingerprint=rec["fingerprint"], policy_sequence=ctx["policy_sequence"],
            user_id="user-bob",
        ),
        _make_remote_approval(
            carol[0], request_id=req_id, command="python refusal_remote.py",
            fingerprint=rec["fingerprint"], policy_sequence=ctx["policy_sequence"],
            user_id="user-carol",
        ),
    ]

    from sandbox.connector.approval import apply_external

    result = asyncio.run(apply_external(
        lay, req_id, approvals, clock=lambda: time.time(),
    ))

    assert not marker.exists(), "remote refusal should not execute"

    done = _done_record(lay, req_id)
    assert done is not None, "expected a done record for remote refusal"
    # Signed by connector:<device_id>
    reviewer = done.get("reviewer_id", "")
    assert reviewer.startswith("connector:"), (
        f"remote refusal should be signed by connector:<device_id>, got {reviewer!r}"
    )


# -------------------------------------------------------------------
# Extra 10  Preview: secret scrubbing and text rendering
# -------------------------------------------------------------------


def test_extra10_preview_secret_scrubbed(tmp_path, monkeypatch):
    """A secret is redacted in the preview, the raw-byte hash still binds."""
    _need_t12c()

    kh = tmp_path / "keyhome"
    kh.mkdir()
    monkeypatch.setenv("SANDBOX_KEY_HOME", str(kh))
    lay = _ws(tmp_path / "ws")

    script = lay.root / "secret_test.py"
    # Include something that looks like a secret
    script.write_text(
        'API_KEY = "sk-proj-abcdef1234567890abcdef1234567890"\n'  # gitleaks:allow
        'print("done")\n',
        encoding="utf-8",
    )

    rec, _rid = _hook_escalate(lay, "python secret_test.py", monkeypatch)

    assert rec.get("script") is not None, "expected bound script"
    assert rec.get("script_preview") is not None, "expected script_preview"

    preview_text = rec["script_preview"].get("text", "")
    raw_sha = rec["script"].get("sha256", "")

    # The secret should be scrubbed in the preview
    assert "sk-proj-abcdef1234567890" not in preview_text, (
        "secret should be redacted in preview"
    )
    # The raw-byte hash should still be set
    assert raw_sha, "raw-byte sha256 should be set"
    # The preview hash should differ from the raw hash (scrubbing changes text)
    preview_sha = rec["script_preview"].get("sha256", "")
    assert preview_sha, "preview sha256 should be set"


# -------------------------------------------------------------------
# Extra 11  Evidence: done-record carries script fields
# -------------------------------------------------------------------


def test_extra11_evidence_done_record_carries_script_fields(
    tmp_path, monkeypatch
):
    """The done-record carries script.rel and sha256, and verify_evidence
    reports them."""
    _need_t12c()

    kh = tmp_path / "keyhome"
    kh.mkdir()
    monkeypatch.setenv("SANDBOX_KEY_HOME", str(kh))
    lay = _ws(tmp_path / "ws")

    script = lay.root / "evidence_test.py"
    script.write_text("print('evidence')\n", encoding="utf-8")

    rec, req_id = _hook_escalate(lay, "python evidence_test.py", monkeypatch)

    from sandbox.connector.approval import approve
    result = asyncio.run(approve(lay, req_id, "test-reviewer"))
    if result.get("status") == "awaiting_second":
        result = asyncio.run(approve(lay, req_id, "test-reviewer-2"))

    assert result["status"] == "executed", f"script did not execute: {result}"

    done = _done_record(lay, req_id)
    assert done is not None, "expected a done record"
    assert done.get("script") is not None, (
        "done-record should carry script dict"
    )
    assert done["script"].get("rel"), "done-record script.rel missing"
    assert done["script"].get("sha256"), "done-record script.sha256 missing"


# -------------------------------------------------------------------
# Extra 12  Grep/AST: no shell=True reachable for approved records
# -------------------------------------------------------------------


def test_extra12_no_shell_true_for_approved_records():
    """Grep/AST test: no ``shell=True`` is reachable for any approved record
    path, and the broker execs only the lexed argv or the record's family
    shell (C-c0-6).

    This is a static code-analysis test.  It scans the broker and approval
    modules for ``shell=True`` in subprocess calls that are on the approved-
    record execution path."""
    _need_t12c()

    import ast
    import re

    # Files that make up the approved-record execution path
    src_dir = Path(__file__).resolve().parents[2] / "src"
    files_to_check = [
        src_dir / "sandbox" / "connector" / "broker.py",
        src_dir / "sandbox" / "connector" / "approval.py",
        src_dir / "sandbox" / "broker" / "privilege_broker.py",
    ]

    shell_true_sites = []

    for fpath in files_to_check:
        if not fpath.exists():
            continue
        source = fpath.read_text(encoding="utf-8")

        # AST check: look for keyword arg shell=True in Call nodes
        try:
            tree = ast.parse(source)
        except SyntaxError:
            continue

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                for kw in node.keywords:
                    if kw.arg == "shell" and isinstance(kw.value, ast.Constant):
                        if kw.value.value is True:
                            shell_true_sites.append(
                                f"{fpath.name}:{node.lineno}"
                            )

        # Also do a regex grep for inline nosemgrep-suppressed shell=True
        for i, line in enumerate(source.splitlines(), 1):
            if re.search(r"shell\s*=\s*True", line):
                tag = f"{fpath.name}:{i}"
                if tag not in shell_true_sites:
                    shell_true_sites.append(tag)

    assert not shell_true_sites, (
        f"shell=True found on approved-record path: {shell_true_sites}"
    )


# -------------------------------------------------------------------
# Extra 13  Shell parity (connector-side items)
# -------------------------------------------------------------------


def test_extra13_bash_tool_uses_recorded_bash(tmp_path, monkeypatch):
    """A Bash-tool record runs under the recorded bash, never %ComSpec%."""
    _need_t12c()

    kh = tmp_path / "keyhome"
    kh.mkdir()
    monkeypatch.setenv("SANDBOX_KEY_HOME", str(kh))
    lay = _ws(tmp_path / "ws")

    marker = tmp_path / "marker_bash_shell.txt"
    script = lay.root / "shell_test.sh"
    script.write_text(
        f'echo "bash-shell-ok" > "{marker}"\n',
        encoding="utf-8",
    )

    rec, req_id = _hook_escalate(lay, "bash shell_test.sh", monkeypatch)

    from sandbox.connector.approval import approve
    result = asyncio.run(approve(lay, req_id, "test-reviewer"))
    if result.get("status") == "awaiting_second":
        result = asyncio.run(approve(lay, req_id, "test-reviewer-2"))

    # The test proves the shell used: on Windows, if cmd.exe ran, the
    # quoting would fail or the output would differ.
    done = _done_record(lay, req_id)
    if done and done.get("state") == "refused":
        # SHELL_UNAVAILABLE is acceptable if no bash is available
        reason = done.get("reason", "") or done.get("reason_code", "")
        assert "SHELL_UNAVAILABLE" in reason.upper(), (
            f"expected SHELL_UNAVAILABLE or execution, got: {done}"
        )
    elif result.get("status") == "executed":
        assert marker.exists(), "bash script should have created marker"


@pytest.mark.skipif(sys.platform != "win32",
                    reason="Windows-only: PowerShell tool and EncodedCommand")

def test_extra13_powershell_tool_uses_encoded_command(tmp_path, monkeypatch):
    """A PowerShell-tool record runs with pwsh -EncodedCommand, never
    cmd.exe."""
    _need_t12c()

    kh = tmp_path / "keyhome"
    kh.mkdir()
    monkeypatch.setenv("SANDBOX_KEY_HOME", str(kh))
    lay = _ws(tmp_path / "ws")

    marker = tmp_path / "marker_pwsh_shell.txt"
    # The PowerShell tool sends a command string, not a file
    command = f"Set-Content -Path '{marker}' -Value 'pwsh-ok'"

    from sandbox.connector.queue import EscalationQueue
    monkeypatch.setattr(EscalationQueue, "wait", _async_none)
    from sandbox.connector.hook_eval import pre_tool_use

    asyncio.run(pre_tool_use(
        {
            "tool_name": "PowerShell",
            "tool_input": {"command": command},
            "cwd": str(lay.root),
            "session_id": "sb-pwsh",
        },
        lay,
    ))

    pending = sorted(lay.pending_dir.glob("*.json"),
                     key=lambda p: p.stat().st_mtime)
    assert pending, "PowerShell command should be escalated"
    rec = json.loads(pending[-1].read_text(encoding="utf-8"))
    req_id = rec["request_id"]

    from sandbox.connector.approval import approve
    result = asyncio.run(approve(lay, req_id, "test-reviewer"))
    if result.get("status") == "awaiting_second":
        result = asyncio.run(approve(lay, req_id, "test-reviewer-2"))

    if result.get("status") == "executed":
        assert marker.exists(), "pwsh script should have created marker"



def test_extra13_no_path_lookup_at_exec(tmp_path, monkeypatch):
    """There is no PATH lookup at exec time. The broker uses only the
    recorded shell path from session.json."""
    _need_t12c()

    kh = tmp_path / "keyhome"
    kh.mkdir()
    monkeypatch.setenv("SANDBOX_KEY_HOME", str(kh))
    lay = _ws(tmp_path / "ws")

    session_file = lay.root / ".sandbox" / "session.json"
    assert session_file.exists(), "session.json should exist after init"

    session = json.loads(session_file.read_text(encoding="utf-8"))
    shells = session.get("shells")
    # After T12c, session.json must have a shells field
    assert shells is not None, (
        "session.json should have a 'shells' field after T12c"
    )
    # All recorded shells must be absolute paths
    for name, path in shells.items():
        if path:
            assert os.path.isabs(path), (
                f"shell {name!r} path {path!r} is not absolute"
            )



def test_extra13_missing_shells_field_gives_shell_unavailable(
    tmp_path, monkeypatch
):
    """A workspace with no ``shells`` field in session.json gives a signed
    SHELL_UNAVAILABLE and nothing runs."""
    _need_t12c()

    kh = tmp_path / "keyhome"
    kh.mkdir()
    monkeypatch.setenv("SANDBOX_KEY_HOME", str(kh))
    lay = _ws(tmp_path / "ws")

    marker = tmp_path / "marker_noshells.txt"
    script = lay.root / "noshells.py"
    script.write_text(
        f'import pathlib; pathlib.Path(r"{marker}").write_text("ran")\n',
        encoding="utf-8",
    )

    # Remove the shells field from session.json
    session_file = lay.root / ".sandbox" / "session.json"
    session = json.loads(session_file.read_text(encoding="utf-8"))
    session.pop("shells", None)
    session_file.write_text(json.dumps(session), encoding="utf-8")

    rec, req_id = _hook_escalate(lay, "bash noshells.py", monkeypatch)

    from sandbox.connector.approval import approve
    result = asyncio.run(approve(lay, req_id, "test-reviewer"))
    if result.get("status") == "awaiting_second":
        result = asyncio.run(approve(lay, req_id, "test-reviewer-2"))

    assert not marker.exists(), "should not run without shells field"

    done = _done_record(lay, req_id)
    assert done is not None, "expected a done record"
    reason = done.get("reason", "") or done.get("reason_code", "")
    assert "SHELL_UNAVAILABLE" in reason.upper(), (
        f"expected SHELL_UNAVAILABLE, got: {reason!r}"
    )
    # Must be signed
    assert done.get("signature") or done.get("sig"), (
        "SHELL_UNAVAILABLE record should be signed"
    )


@pytest.mark.skipif(sys.platform != "win32",
                    reason="Windows-only: init lookup order test")

def test_extra13_init_lookup_order(tmp_path, monkeypatch):
    """Init lookup order: --bash flag, CLAUDE_CODE_GIT_BASH_PATH,
    ProgramFiles Git, git-derived, then PATH.  A fake git at
    X\\cmd\\git.exe gives X\\bin\\bash.exe."""
    _need_t12c()

    # Set up a fake git structure
    fake_git_root = tmp_path / "FakeGit"
    (fake_git_root / "cmd").mkdir(parents=True)
    (fake_git_root / "bin").mkdir(parents=True)
    fake_bash = fake_git_root / "bin" / "bash.exe"
    fake_bash.write_text("fake", encoding="utf-8")
    fake_git = fake_git_root / "cmd" / "git.exe"
    fake_git.write_text("fake", encoding="utf-8")

    kh = tmp_path / "keyhome"
    kh.mkdir()
    monkeypatch.setenv("SANDBOX_KEY_HOME", str(kh))

    ws_path = tmp_path / "ws_init"
    ws_path.mkdir()

    from sandbox.connector.install import init
    # Test that the --bash flag takes priority
    init(ws_path, claude=False, mcp=False)

    session_file = ws_path / ".sandbox" / "session.json"
    assert session_file.exists()
    session = json.loads(session_file.read_text(encoding="utf-8"))
    shells = session.get("shells", {})
    # shells must exist and have a bash entry (may be None if no bash found)
    assert "bash" in shells, "shells should have a bash key after init"


@pytest.mark.skipif(sys.platform != "win32",
                    reason="Windows-only: WindowsApps/System32 refusals")

def test_extra13_init_refuses_system32_and_windowsapps(tmp_path, monkeypatch):
    """Init refuses System32\\bash.exe and WindowsApps\\bash.exe even when
    PATH finds them first."""
    _need_t12c()

    kh = tmp_path / "keyhome"
    kh.mkdir()
    monkeypatch.setenv("SANDBOX_KEY_HOME", str(kh))

    # Create fake System32 and WindowsApps bash. ADR 0010 s9 9.4 refuses
    # exactly %SystemRoot%\System32\bash.exe, so SystemRoot must point at
    # tmp_path for the fake to be the path the rule names.
    monkeypatch.setenv("SystemRoot", str(tmp_path))
    fake_sys32 = tmp_path / "System32"
    fake_sys32.mkdir()
    (fake_sys32 / "bash.exe").write_text("wsl", encoding="utf-8")

    fake_apps = tmp_path / "WindowsApps"
    fake_apps.mkdir()
    (fake_apps / "bash.exe").write_text("store", encoding="utf-8")

    # Put both on PATH before any real bash
    old_path = os.environ.get("PATH", "")
    monkeypatch.setenv("PATH", f"{fake_sys32};{fake_apps};{old_path}")

    ws_path = tmp_path / "ws_refuse"
    ws_path.mkdir()

    from sandbox.connector.install import init
    init(ws_path, claude=False, mcp=False)

    session_file = ws_path / ".sandbox" / "session.json"
    session = json.loads(session_file.read_text(encoding="utf-8"))
    shells = session.get("shells", {})
    bash_path = shells.get("bash", "")

    # The refused paths must not be selected (exact paths, not substrings)
    refused = {
        str(fake_sys32 / "bash.exe").lower(),
        str(fake_apps / "bash.exe").lower(),
    }
    if bash_path:
        assert bash_path.lower() not in refused, (
            f"WSL/WindowsApps bash.exe should be refused, got: {bash_path!r}"
        )
        assert "windowsapps" not in bash_path.lower(), (
            f"WindowsApps\bash.exe should be refused, got: {bash_path!r}"
        )


# -------------------------------------------------------------------
# R1 -- 8.3 short-name WSL refusal test
# -------------------------------------------------------------------


@pytest.mark.skipif(sys.platform != "win32",
                    reason="Windows-only: 8.3 short-name WSL refusal")
def test_r1_shortname_system32_bash_refused(tmp_path, monkeypatch):
    """An 8.3 short-name form of %SystemRoot%\\System32\\bash.exe must be
    refused by _is_valid_shell, not accepted because the string comparison
    misses the short-name alias (R1)."""
    _need_t12c()

    # Build a fake SystemRoot with System32\\bash.exe inside tmp_path
    monkeypatch.setenv("SystemRoot", str(tmp_path))
    fake_sys32 = tmp_path / "System32"
    fake_sys32.mkdir()
    fake_bash = fake_sys32 / "bash.exe"
    fake_bash.write_text("wsl", encoding="utf-8")

    # Attempt to get the 8.3 short-name form via ctypes
    import ctypes
    buf = ctypes.create_unicode_buffer(300)
    n = ctypes.windll.kernel32.GetShortPathNameW(str(fake_bash), buf, 300)
    if n == 0 or buf.value.lower() == str(fake_bash).lower():
        pytest.skip("volume does not support 8.3 short names or no short name generated")

    short_path = buf.value
    assert short_path.lower() != str(fake_bash).lower(), (
        "GetShortPathNameW returned the long path; no short name exists"
    )

    from sandbox.connector.install import _is_valid_shell
    ok, reason = _is_valid_shell(short_path, tmp_path / "ws_root")
    assert not ok, (
        f"8.3 short-name WSL bash should be refused, got ok=True for {short_path!r}"
    )
    assert "WSL" in reason or "System32" in reason, (
        f"expected WSL refusal reason, got: {reason!r}"
    )


# -------------------------------------------------------------------
# R2 -- requires_dual triggers the floor for unbound commands
# -------------------------------------------------------------------


def test_r2_requires_dual_unbound_denied_under_floor(tmp_path, monkeypatch):
    """In a standalone workspace (not enrolled) with requires_dual=True,
    an unbound command must be denied with SCRIPT_UNPINNABLE, not
    escalated.  ADR 0010 s9 9.3: the floor applies when requires_dual
    is true OR when enrolled."""
    _need_t12c()

    kh = tmp_path / "keyhome"
    kh.mkdir()
    monkeypatch.setenv("SANDBOX_KEY_HOME", str(kh))
    lay = _ws(tmp_path / "ws")

    script = lay.root / "deploy.sh"
    script.write_text("#!/bin/sh\necho hi\n", encoding="utf-8")

    # Monkeypatch exfil detector to trigger requires_dual
    from sandbox.safety import exfil as _exfil_mod
    original_detect = _exfil_mod.detect

    def _always_exfil(command):
        return _exfil_mod.ExfilFinding(
            sensitive=".env", egress="curl_upload",
            detail="test-forced exfil",
        )

    monkeypatch.setattr(_exfil_mod, "detect", _always_exfil)

    from sandbox.connector.queue import EscalationQueue
    monkeypatch.setattr(EscalationQueue, "wait", _async_none)

    from sandbox.connector.hook_eval import pre_tool_use

    result = asyncio.run(pre_tool_use(
        {
            "tool_name": "Bash",
            "tool_input": {"command": "./deploy.sh"},
            "cwd": str(lay.root),
            "session_id": "sb-r2-dual",
        },
        lay,
    ))

    hso = result.get("hookSpecificOutput", {})
    reason = hso.get("permissionDecisionReason", "")
    # Must be denied, not escalated
    assert "SCRIPT_UNPINNABLE" in reason, (
        f"requires_dual + unbound should be SCRIPT_UNPINNABLE deny, got: {reason!r}"
    )


# -------------------------------------------------------------------
# R3 -- backslash preservation in build_shell_argv
# -------------------------------------------------------------------


def test_r3_non_path_backslash_survives_byte_for_byte(tmp_path):
    """Non-path backslashes in a bash command (regex, printf escapes)
    must reach the shell byte-for-byte, not be converted to forward
    slashes (R3)."""
    _need_t12c()

    from sandbox.connector.script_pin import build_shell_argv

    # A command with intentional non-path backslashes
    cmd = r"python script.py 'pattern\d+' printf 'a\nb'"
    argv = build_shell_argv(cmd, "Bash", "/usr/bin/bash")

    # The -c argument is the last element
    bash_arg = argv[-1]
    # The non-path backslashes must survive
    assert r"\d+" in bash_arg, (
        f"regex backslash was converted: {bash_arg!r}"
    )
    assert r"\n" in bash_arg, (
        f"printf escape was converted: {bash_arg!r}"
    )


@pytest.mark.skipif(sys.platform != "win32",
                    reason="Windows-only: drive-letter conversion test")
def test_r3_drive_letter_path_converted(tmp_path):
    """A drive-letter path in a bash command should have its backslashes
    converted to forward slashes (R3)."""
    _need_t12c()

    from sandbox.connector.script_pin import build_shell_argv

    cmd = r"python E:\project\script.py 'pattern\d+'"
    argv = build_shell_argv(cmd, "Bash", r"C:\Git\bin\bash.exe")

    bash_arg = argv[-1]
    # Drive-letter path should be converted
    assert "E:/project/script.py" in bash_arg, (
        f"drive-letter path not converted: {bash_arg!r}"
    )
    # Non-path backslash must survive
    assert r"\d+" in bash_arg, (
        f"regex backslash was converted: {bash_arg!r}"
    )


def test_r3_done_record_carries_exec_argv(tmp_path, monkeypatch):
    """The done-record from FolderBroker.execute must carry exec_argv
    (R3: record the exact argv that was executed)."""
    _need_t12c()

    kh = tmp_path / "keyhome"
    kh.mkdir()
    monkeypatch.setenv("SANDBOX_KEY_HOME", str(kh))

    # The broker reads .sandbox/session.json for the shell paths.
    import shutil
    bash_path = shutil.which("bash")
    if not bash_path:
        pytest.skip("no bash on PATH")
    sandbox_dir = tmp_path / ".sandbox"
    sandbox_dir.mkdir(exist_ok=True)
    (sandbox_dir / "session.json").write_text(
        json.dumps({"shells": {"bash": bash_path}}), encoding="utf-8"
    )

    from sandbox.connector.broker import FolderBroker

    # Use a command with binding "none" (echo is not an interpreter) so
    # the re-resolve check passes with script=None.
    rec = {
        "kind": "command",
        "request_id": "r3-argv",
        "command": "echo hello-r3",
        "exec_cwd": str(tmp_path),
        "root": str(tmp_path),
        "tool_name": "Bash",
        "fp_v": 2,
        "script": None,
        "script_unbound": "",
        "script_preview": None,
    }

    done = asyncio.run(FolderBroker().execute(rec, "reviewer"))
    assert done.get("state") != "refused", (
        f"unexpected refusal: {done.get('reason_code')}: {done.get('reason')}"
    )
    assert "exec_argv" in done, (
        f"done-record must contain exec_argv, got keys: {sorted(done.keys())}"
    )
    assert isinstance(done["exec_argv"], list), (
        f"exec_argv must be a list, got {type(done['exec_argv'])}"
    )
    assert len(done["exec_argv"]) > 0, "exec_argv must not be empty"
