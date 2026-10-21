"""T2 tests-first: portable process group helper (ee/tests/_portable.py).

The helper provides:
- ``popen_kwargs()`` -> dict with CREATE_NEW_PROCESS_GROUP on nt,
  start_new_session=True elsewhere.
- ``group_terminate(proc)`` and ``group_kill(proc)`` that send signals
  to the whole process group.
- ``symlink_privilege_probe()`` -> (bool, str|None): True if symlinks
  can be created, False with a skip reason string.

RED tests are strict xfail on M2T2Pending.
Guards (pass now) verify platform constants.
"""
from __future__ import annotations

import os
import subprocess
import sys
import time

import pytest

from .m2_pending import M2T2Pending, require_m2

# ---------------------------------------------------------------------------
# Sentinel helper: try to import the portable module
# ---------------------------------------------------------------------------

def _import_portable():
    """Import ee/tests/_portable.py; raise M2T2Pending if absent."""
    try:
        from ee.tests import _portable  # type: ignore[import-untyped]
        return _portable
    except (ImportError, ModuleNotFoundError):
        pass
    # Also try relative
    try:
        from . import _portable  # type: ignore[import-untyped]
        return _portable
    except (ImportError, ModuleNotFoundError):
        raise M2T2Pending("ee/tests/_portable.py not found")


# ===================================================================
# Guards (pass now -- no marker)
# ===================================================================


def test_platform_has_subprocess():
    """Guard: subprocess module is available."""
    assert hasattr(subprocess, "Popen")


def test_platform_signal_constants():
    """Guard: signal module exposes SIGTERM on all platforms."""
    import signal
    assert hasattr(signal, "SIGTERM")


# ===================================================================
# RED: popen_kwargs per OS
# ===================================================================


@pytest.mark.xfail(strict=True, raises=M2T2Pending)
def test_popen_kwargs_on_nt():
    """On Windows, popen_kwargs includes CREATE_NEW_PROCESS_GROUP."""
    mod = _import_portable()
    kw = mod.popen_kwargs()
    if os.name == "nt":
        assert "creationflags" in kw
        assert kw["creationflags"] & subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        assert kw.get("start_new_session") is True


@pytest.mark.xfail(strict=True, raises=M2T2Pending)
def test_popen_kwargs_on_posix():
    """On POSIX, popen_kwargs includes start_new_session=True."""
    mod = _import_portable()
    kw = mod.popen_kwargs()
    if os.name != "nt":
        assert kw.get("start_new_session") is True
    else:
        assert "creationflags" in kw


# ===================================================================
# RED: group_terminate kills child + grandchild
# ===================================================================


@pytest.mark.xfail(strict=True, raises=M2T2Pending)
def test_group_terminate_kills_tree():
    """group_terminate kills a child and its grandchild."""
    mod = _import_portable()
    kw = mod.popen_kwargs()

    # Start a child that spawns a grandchild (both sleep)
    if os.name == "nt":
        # Child starts a grandchild via cmd /c
        child = subprocess.Popen(
            [sys.executable, "-c",
             "import subprocess, sys, time; "
             "subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)']); "
             "time.sleep(60)"],
            **kw,
        )
    else:
        child = subprocess.Popen(
            [sys.executable, "-c",
             "import subprocess, sys, time; "
             "subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)']); "
             "time.sleep(60)"],
            **kw,
        )

    time.sleep(0.5)  # let the grandchild start
    assert child.poll() is None, "child should still be running"

    mod.group_terminate(child)
    # Wait for the child to die
    try:
        child.wait(timeout=5)
    except subprocess.TimeoutExpired:
        child.kill()
        pytest.fail("child did not die after group_terminate")

    assert child.returncode is not None


@pytest.mark.xfail(strict=True, raises=M2T2Pending)
def test_group_kill_terminates():
    """group_kill forcefully kills the process group."""
    mod = _import_portable()
    kw = mod.popen_kwargs()

    child = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(60)"],
        **kw,
    )
    time.sleep(0.3)
    assert child.poll() is None

    mod.group_kill(child)
    try:
        child.wait(timeout=5)
    except subprocess.TimeoutExpired:
        child.kill()
        pytest.fail("child did not die after group_kill")

    assert child.returncode is not None


# ===================================================================
# RED: symlink_privilege_probe returns a bool
# ===================================================================


@pytest.mark.xfail(strict=True, raises=M2T2Pending)
def test_symlink_probe_returns_bool():
    """symlink_privilege_probe returns (bool, reason_or_None)."""
    mod = _import_portable()
    can_create, reason = mod.symlink_privilege_probe()
    assert isinstance(can_create, bool)
    if not can_create:
        assert isinstance(reason, str) and len(reason) > 0
    else:
        assert reason is None
