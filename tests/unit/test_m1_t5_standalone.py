"""M1 T5: connector standalone and import isolation tests.

The connector (``src/sandbox/``) must never import ``agg_cp`` (the EE
control-plane package).  Two complementary checks:

1. **Static grep:** no file under ``src/sandbox/`` contains
   ``import agg_cp`` or ``from agg_cp``.  A positive control plants a
   temporary module with such an import and asserts the scanner catches it.

2. **Runtime isolation:** every ``sandbox`` sub-module imports successfully
   in a subprocess where ``agg_cp`` is unreachable (``-I`` flag, a
   meta-path finder that raises on ``agg_cp``).

These tests guard ADR 0004 rule 4: one-way imports, ``sandbox`` never
imports ``agg_cp``.  They may pass today (``ee/`` does not exist yet);
that is fine -- they are regression guards, not xfail.
"""
from __future__ import annotations

import ast
import os
import pkgutil
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[2] / "src"
PKG = SRC / "sandbox"


# ---------------------------------------------------------------------------
# 1. Static grep: no ``import agg_cp`` / ``from agg_cp`` in src/sandbox
# ---------------------------------------------------------------------------

def _scan_for_agg_cp_imports(root: Path) -> list[tuple[Path, int, str]]:
    """Return ``(file, lineno, line)`` for every ``agg_cp`` import found."""
    hits: list[tuple[Path, int, str]] = []
    for py in root.rglob("*.py"):
        try:
            text = py.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for i, raw in enumerate(text.splitlines(), 1):
            line = raw.strip()
            if line.startswith("#"):
                continue
            # Catch: ``import agg_cp``, ``from agg_cp ...``,
            # ``from agg_cp.x import y``
            if "import agg_cp" in line or "from agg_cp" in line:
                hits.append((py, i, line))
    return hits


def test_no_agg_cp_import_in_sandbox_source():
    """Static: no file under src/sandbox/ references agg_cp."""
    hits = _scan_for_agg_cp_imports(PKG)
    assert hits == [], (
        "Files under src/sandbox/ must not import agg_cp (ADR 0004 rule 4):\n"
        + "\n".join(f"  {f}:{n}: {l}" for f, n, l in hits)
    )


def test_positive_control_planted_import_detected(tmp_path: Path):
    """Positive control: a planted ``from agg_cp import x`` is caught."""
    planted = tmp_path / "fake_module.py"
    planted.write_text("from agg_cp import something\n", encoding="utf-8")
    hits = _scan_for_agg_cp_imports(tmp_path)
    assert len(hits) == 1, "The scanner must find the planted agg_cp import"
    assert hits[0][0] == planted
    assert "agg_cp" in hits[0][2]


def test_positive_control_plain_import_detected(tmp_path: Path):
    """Positive control: ``import agg_cp`` (bare) is also caught."""
    planted = tmp_path / "bare.py"
    planted.write_text("import agg_cp\n", encoding="utf-8")
    hits = _scan_for_agg_cp_imports(tmp_path)
    assert len(hits) == 1


def test_positive_control_comment_is_ignored(tmp_path: Path):
    """A comment mentioning agg_cp is not a false positive."""
    planted = tmp_path / "comment_only.py"
    planted.write_text("# from agg_cp import x  -- just a comment\n", encoding="utf-8")
    hits = _scan_for_agg_cp_imports(tmp_path)
    assert hits == [], "Comments should not be flagged"


# ---------------------------------------------------------------------------
# 2. Runtime isolation: every sandbox module imports without agg_cp
# ---------------------------------------------------------------------------

# Collect all importable sandbox modules at test-collection time.
_SANDBOX_MODULES: list[str] = []
for _info in pkgutil.walk_packages(
    [str(PKG)], prefix="sandbox."
):
    _SANDBOX_MODULES.append(_info.name)

# Sanity: we expect dozens of sub-modules
assert len(_SANDBOX_MODULES) > 20, (
    f"pkgutil found only {len(_SANDBOX_MODULES)} sandbox modules; "
    "something is wrong with the package walk"
)

# A meta-path finder script injected into the subprocess that blocks agg_cp.
_BLOCK_AGG_CP_SCRIPT = textwrap.dedent("""\
    import importlib.abc
    import importlib.machinery
    import sys

    class _BlockAggCp(importlib.abc.MetaPathFinder):
        def find_module(self, fullname, path=None):
            if fullname == "agg_cp" or fullname.startswith("agg_cp."):
                return self
            return None
        def load_module(self, fullname):
            raise ImportError(
                "agg_cp is blocked by the standalone isolation test: " + fullname
            )

    sys.meta_path.insert(0, _BlockAggCp())

    import {module}
    print("OK")
""")


@pytest.mark.parametrize("module", _SANDBOX_MODULES, ids=_SANDBOX_MODULES)
def test_sandbox_module_imports_without_agg_cp(module: str):
    """Each sandbox sub-module must import without agg_cp on sys.path."""
    script = _BLOCK_AGG_CP_SCRIPT.format(module=module)
    result = subprocess.run(
        [sys.executable, "-I", "-c", script],
        capture_output=True,
        text=True,
        timeout=30,
        env={
            **os.environ,
            # Ensure ee/src is NOT on PYTHONPATH even if set globally
            "PYTHONPATH": str(SRC),
        },
    )
    assert result.returncode == 0, (
        f"Importing {module} failed with agg_cp blocked:\n"
        f"  stdout: {result.stdout.strip()}\n"
        f"  stderr: {result.stderr.strip()}"
    )
    assert "OK" in result.stdout
