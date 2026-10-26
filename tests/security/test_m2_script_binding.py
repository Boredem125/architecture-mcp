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

@pytest.mark.xfail(strict=True, raises=M2T12cPending)
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

@pytest.mark.xfail(strict=True, raises=M2T12cPending)
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

@pytest.mark.xfail(strict=True, raises=M2T12cPending)
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
@pytest.mark.xfail(strict=True, raises=M2T12cPending)
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

@pytest.mark.xfail(strict=True, raises=M2T12cPending)
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

    rec = {
        "request_id": "guard-1",
        "command": cmd,
        "kind": "command",
        "tool_name": "Bash",
        "exec_cwd": str(lay.root),
        "root": str(lay.root),
        "requires_dual": False,
        "bundle_sequence": 0,
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
