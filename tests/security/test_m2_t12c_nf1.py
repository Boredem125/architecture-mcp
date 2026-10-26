"""T12c NF-1 proof: the hook lexes a Bash-tool command with bash semantics
(``shellwords.lex(..., "bash")``), but ``PrivilegeBroker._execute_approved``
runs the approved string via ``subprocess.run(command, shell=True)``, which on
Windows is ``cmd.exe /c``. cmd.exe and bash split a command differently, so an
approved command can run with a different meaning than the reviewer analysed and
approved. In bash ``foo '&echo x&'`` is one word passed to ``foo``; in cmd.exe
the unquoted ``&`` (single quotes are not cmd quoting) starts a second command.

Affects every approved shell command on Windows, on BOTH decision paths that end
in ``FolderBroker().execute`` -> ``PrivilegeBroker._execute_approved``:
  - local  ``sandbox approve``  (approval.py:199)
  - remote ``apply_external``   (approval.py:884)

Proof is harmless: the hidden second command only writes a marker file into a
private scratch dir. It never launches a real program. The desired (fixed)
behaviour is that the broker runs the command with the same semantics the hook
analysed (bash for a Bash tool, or ``shell=False`` with the lexed argv), so the
hidden cmd.exe second command does NOT run and no marker appears.

Strict xfail with a named local sentinel ``M2T12cNf1Pending``: the test raises it
while the bug is present (marker written by cmd.exe). When NF-1 is fixed the
marker is absent, the body no longer raises, and the strict xfail flips to a
failure so the marker cannot linger.
"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import pytest

from sandbox.connector.broker import FolderBroker
from sandbox.connector.classify import analyse_shell


class M2T12cNf1Pending(Exception):
    """NF-1: broker runs a bash-lexed command through cmd.exe (shell=True)."""


windows_only = pytest.mark.skipif(
    sys.platform != "win32",
    reason="NF-1 is the bash-hook / cmd.exe-broker split; Windows-specific",
)

# One word, single-quoted, so bash passes a literal to the (unknown, escalated)
# command and runs nothing else. The embedded `& ... &` is cmd.exe syntax only.
_SCRATCH = Path(r"E:\caterpillar\jev-os\.cache\tmp")


def _marker_command(marker: Path) -> str:
    # `>` + path only; echo writes the marker. In bash the whole `'...'` is one
    # argument to `nf1-noop` (not allowlisted -> escalates, one segment, no deny).
    return f"nf1-noop '&echo pwned> {marker}&'"


@windows_only
def test_nf1_reviewer_view_is_single_benign_bash_segment(tmp_path):
    """Guard: what the reviewer is shown. The hook's analysis (bash) sees one
    segment, no deny, nothing unresolvable from the hidden `&` -- so a human
    approves what looks like a single ``nf1-noop <arg>`` call."""
    marker = tmp_path / "unused.txt"
    a = analyse_shell(_marker_command(marker), "bash", cwd=str(tmp_path))
    assert a.deny is None
    assert a.segments == 1
    assert a.unresolvable == []


@windows_only
@pytest.mark.xfail(raises=M2T12cNf1Pending, strict=True)
def test_nf1_broker_must_not_run_cmd_split_of_bash_command(tmp_path):
    """Local approve path (approval.py:199 -> FolderBroker.execute)."""
    marker = tmp_path / "nf1_local_marker.txt"
    rec = {
        "kind": "command",
        "request_id": "nf1-local",
        "command": _marker_command(marker),
        "exec_cwd": str(tmp_path),
        "root": str(tmp_path),
    }
    asyncio.run(FolderBroker().execute(rec, "reviewer"))
    if marker.exists():
        raise M2T12cNf1Pending(
            "cmd.exe ran the hidden second command; the broker executed a "
            "different command than the hook analysed (shell=True / cmd.exe)"
        )
    # Fixed behaviour: the broker runs the bash meaning, so no marker.
    assert not marker.exists()


@windows_only
@pytest.mark.xfail(raises=M2T12cNf1Pending, strict=True)
def test_nf1_remote_apply_external_same_broker_split(tmp_path):
    """Remote path (apply_external -> approval.py:884 -> FolderBroker.execute)
    reaches the identical broker primitive, so the split applies there too. We
    exercise the shared choke point directly to keep the proof hermetic (no
    enrollment / signing fixture needed to demonstrate the broker behaviour)."""
    marker = tmp_path / "nf1_remote_marker.txt"
    rec = {
        "kind": "command",
        "request_id": "nf1-remote",
        "command": _marker_command(marker),
        "exec_cwd": str(tmp_path),
        "root": str(tmp_path),
    }
    # apply_external calls exactly this on the claimed record.
    asyncio.run(FolderBroker().execute(rec, "bob"))
    if marker.exists():
        raise M2T12cNf1Pending(
            "remote-approved command split by cmd.exe in the broker (shell=True)"
        )
    assert not marker.exists()
