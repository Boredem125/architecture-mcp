"""T3 tests-first: SEC-33 (icacls missing) and root_exposure domain-group split.

Two Lows from M1:
- SEC-33: ``root_exposure`` returns None when icacls is absent (false
  negative).  After T3 it warns.
- Domain groups: ``root_exposure`` only checks ``Everyone``,
  ``BUILTIN\\Users``, ``Authenticated Users`` and
  ``NT AUTHORITY\\INTERACTIVE``.  It misses domain-local groups such as
  ``ACME\\Domain Users`` or ``ACME\\Domain Computers``.  After T3 it
  flags those too.

Tests monkeypatch ``subprocess.run`` to feed canned icacls output
through the existing parse seam.

RED tests xfail on M2T3Pending.  Guards verify existing behaviour.
"""
from __future__ import annotations

import os
import subprocess
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from tests.m2_pending import M2T3Pending, require_m2


# ---------------------------------------------------------------------------
# Helpers -- fake icacls output
# ---------------------------------------------------------------------------

def _fake_icacls(stdout: str):
    """Return a ``subprocess.run`` replacement that yields *stdout*."""
    def _run(cmd, *, capture_output=True, text=True, timeout=20, **kw):
        result = MagicMock()
        result.stdout = stdout
        result.returncode = 0
        return result
    return _run


_OWNER_ONLY = (
    r"E:\keys OWNER\alice:(OI)(CI)(F)" "\n"
    r"       NT AUTHORITY\SYSTEM:(OI)(CI)(F)" "\n"
    r"       BUILTIN\Administrators:(OI)(CI)(F)" "\n"
)

_DOMAIN_USERS_READ = (
    r"E:\keys OWNER\alice:(OI)(CI)(F)" "\n"
    r"       NT AUTHORITY\SYSTEM:(OI)(CI)(F)" "\n"
    r"       ACME\Domain Users:(OI)(CI)(R)" "\n"
)

_DOMAIN_COMPUTERS_FULL = (
    r"E:\keys OWNER\alice:(OI)(CI)(F)" "\n"
    r"       ACME\Domain Computers:(OI)(CI)(F)" "\n"
)


# ===================================================================
# Guards (pass now)
# ===================================================================


def test_root_exposure_importable():
    """Guard: root_exposure function exists in keyhome."""
    from sandbox.connector.keyhome import root_exposure
    assert callable(root_exposure)


def test_root_exposure_owner_only_no_warning():
    """Guard: owner + SYSTEM + Administrators gives no warning."""
    from sandbox.connector.keyhome import root_exposure

    with tempfile.TemporaryDirectory() as td:
        with patch("sandbox.connector.keyhome._validated_icacls",
                   return_value=Path(r"C:\Windows\System32\icacls.exe")):
            with patch("sandbox.connector.keyhome.os.name", "nt"):
                with patch("subprocess.run", _fake_icacls(_OWNER_ONLY)):
                    result = root_exposure(Path(td))
    assert result is None, (
        f"Owner-only ACL should give no warning, got: {result!r}"
    )


def test_existing_wide_groups_detected():
    """Guard: existing code detects Everyone grant."""
    from sandbox.connector.keyhome import root_exposure

    everyone_output = (
        r"E:\keys Everyone:(OI)(CI)(R)" "\n"
        r"       OWNER\alice:(OI)(CI)(F)" "\n"
    )
    with tempfile.TemporaryDirectory() as td:
        with patch("sandbox.connector.keyhome._validated_icacls",
                   return_value=Path(r"C:\Windows\System32\icacls.exe")):
            with patch("sandbox.connector.keyhome.os.name", "nt"):
                with patch("subprocess.run", _fake_icacls(everyone_output)):
                    result = root_exposure(Path(td))
    assert result is not None and "Everyone" in result


# ===================================================================
# RED: SEC-33 -- root_exposure warns when icacls is missing
# ===================================================================


@pytest.mark.xfail(strict=True, raises=M2T3Pending)
def test_root_exposure_warns_when_icacls_missing():
    """root_exposure warns (not None) when icacls cannot be found."""
    from sandbox.connector.keyhome import root_exposure

    with patch("sandbox.connector.keyhome._validated_icacls", return_value=None):
        with patch("sandbox.connector.keyhome.os.name", "nt"):
            with tempfile.TemporaryDirectory() as td:
                result = root_exposure(Path(td))
                if result is None:
                    raise M2T3Pending(
                        "root_exposure returns None when icacls is missing; "
                        "SEC-33 says it should warn"
                    )
                assert "icacls" in result.lower() or "cannot" in result.lower()


# ===================================================================
# RED: domain-group split -- root_exposure flags domain-local groups
# ===================================================================


@pytest.mark.xfail(strict=True, raises=M2T3Pending)
def test_root_exposure_flags_domain_users():
    r"""root_exposure flags ``ACME\Domain Users`` with read access."""
    from sandbox.connector.keyhome import root_exposure

    with tempfile.TemporaryDirectory() as td:
        with patch("sandbox.connector.keyhome._validated_icacls",
                   return_value=Path(r"C:\Windows\System32\icacls.exe")):
            with patch("sandbox.connector.keyhome.os.name", "nt"):
                with patch("subprocess.run",
                           _fake_icacls(_DOMAIN_USERS_READ)):
                    result = root_exposure(Path(td))
                    if result is None:
                        raise M2T3Pending(
                            "root_exposure does not flag "
                            r"ACME\Domain Users grant"
                        )
                    assert "domain users" in result.lower()


@pytest.mark.xfail(strict=True, raises=M2T3Pending)
def test_root_exposure_flags_domain_computers():
    r"""root_exposure flags ``ACME\Domain Computers`` with full access."""
    from sandbox.connector.keyhome import root_exposure

    with tempfile.TemporaryDirectory() as td:
        with patch("sandbox.connector.keyhome._validated_icacls",
                   return_value=Path(r"C:\Windows\System32\icacls.exe")):
            with patch("sandbox.connector.keyhome.os.name", "nt"):
                with patch("subprocess.run",
                           _fake_icacls(_DOMAIN_COMPUTERS_FULL)):
                    result = root_exposure(Path(td))
                    if result is None:
                        raise M2T3Pending(
                            "root_exposure does not flag "
                            r"ACME\Domain Computers grant"
                        )
                    assert "domain computers" in result.lower()
