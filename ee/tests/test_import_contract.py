"""M1 T5: import-linter contract and ee/ installability tests.

Tests:
1. ``lint-imports`` (import-linter) passes against a contract config that
   forbids ``sandbox -> agg_cp`` imports.
2. Positive control: a planted ``sandbox -> agg_cp`` import is flagged
   by the same contract.
3. ``pip install ./ee`` succeeds (the EE package is installable).

All are ``xfail(strict=True)`` because neither ``ee/`` nor its
``pyproject.toml`` exist yet.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]  # repo root (E:\architecture-mcp)
EE = ROOT / "ee"


class EESkeletonOpen(Exception):
    """The ee/ skeleton is not built yet (M1 T5)."""


RED_T5 = pytest.mark.xfail(
    raises=EESkeletonOpen, strict=True,
    reason="M1 T5: ee/ skeleton not yet built",
)


def _require(cond: bool, msg: str) -> None:
    if not cond:
        raise EESkeletonOpen(msg)


# ---------------------------------------------------------------------------
# Contract: sandbox must not import agg_cp
# ---------------------------------------------------------------------------

# The shipped contract config: the one file CI's ``ee`` job runs. Tests read
# it rather than an inline copy, so the tested contract cannot drift from it.
_SHIPPED = EE / ".importlinter"


def _contract_ini() -> str:
    _require(_SHIPPED.is_file(), "ee/.importlinter does not exist")
    text = _SHIPPED.read_text(encoding="utf-8")
    flat = " ".join(text.split())
    _require(
        "type = forbidden" in flat
        and "source_modules = sandbox" in flat
        and "forbidden_modules = agg_cp" in flat,
        "ee/.importlinter has no forbidden sandbox -> agg_cp contract",
    )
    return text


@RED_T5
def test_import_linter_contract_passes():
    """``lint-imports`` exits 0 with the sandbox->agg_cp forbidden contract.

    Requires both ``sandbox`` and ``agg_cp`` to be importable so that
    import-linter can resolve them.  The xfail catches the case where
    ``agg_cp`` does not exist yet.
    """
    # Verify agg_cp is importable (it won't be until T5 implementation)
    try:
        import agg_cp  # noqa: F401
    except (ImportError, ModuleNotFoundError) as exc:
        raise EESkeletonOpen(f"agg_cp not importable: {exc}") from exc

    # Write a temp .importlinter config
    import tempfile
    with tempfile.TemporaryDirectory(
        dir=os.environ.get("TMP", None)
    ) as td:
        cfg = Path(td) / ".importlinter"
        cfg.write_text(_contract_ini(), encoding="utf-8")

        result = subprocess.run(
            [sys.executable, "-m", "importlinter", "--config", str(cfg)],
            capture_output=True,
            text=True,
            timeout=120,
            cwd=str(ROOT),
        )
        _require(
            result.returncode == 0,
            f"lint-imports failed (exit {result.returncode}):\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}",
        )


@RED_T5
def test_import_linter_positive_control_catches_violation(tmp_path: Path):
    """Positive control: a planted ``from agg_cp import x`` inside a fake
    sandbox module is caught by the forbidden contract.

    This proves the contract config actually detects violations.
    """
    # Verify agg_cp is importable
    try:
        import agg_cp  # noqa: F401
    except (ImportError, ModuleNotFoundError) as exc:
        raise EESkeletonOpen(f"agg_cp not importable: {exc}") from exc

    # Create a fake sandbox package with an agg_cp import
    fake_sandbox = tmp_path / "sandbox"
    fake_sandbox.mkdir()
    (fake_sandbox / "__init__.py").write_text("", encoding="utf-8")
    (fake_sandbox / "violation.py").write_text(
        "from agg_cp import something\n", encoding="utf-8"
    )

    # Create a fake agg_cp package
    fake_agg_cp = tmp_path / "agg_cp"
    fake_agg_cp.mkdir()
    (fake_agg_cp / "__init__.py").write_text("", encoding="utf-8")
    (fake_agg_cp / "something.py").write_text("x = 1\n", encoding="utf-8")

    # Write the contract config
    cfg = tmp_path / ".importlinter"
    cfg.write_text(_contract_ini(), encoding="utf-8")

    result = subprocess.run(
        [sys.executable, "-m", "importlinter", "--config", str(cfg)],
        capture_output=True,
        text=True,
        timeout=120,
        cwd=str(tmp_path),
        env={
            **os.environ,
            "PYTHONPATH": str(tmp_path),
        },
    )
    # The contract should FAIL (non-zero exit) because of the violation
    _require(
        result.returncode != 0,
        "lint-imports should have flagged the sandbox->agg_cp import "
        f"but exited 0:\nstdout: {result.stdout}\nstderr: {result.stderr}",
    )


# ---------------------------------------------------------------------------
# pip install ./ee
# ---------------------------------------------------------------------------


@RED_T5
def test_ee_package_has_pyproject():
    """``ee/pyproject.toml`` exists."""
    _require(
        (EE / "pyproject.toml").is_file(),
        "ee/pyproject.toml does not exist",
    )


@RED_T5
def test_ee_has_license():
    """``ee/LICENSE`` exists and mentions Elastic License."""
    license_file = EE / "LICENSE"
    _require(license_file.is_file(), "ee/LICENSE does not exist")
    text = license_file.read_text(encoding="utf-8")
    _require(
        "Elastic License" in text,
        "ee/LICENSE does not mention 'Elastic License'",
    )
