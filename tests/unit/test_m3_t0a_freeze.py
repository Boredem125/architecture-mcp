"""M3 T0a freeze test: manifest coverage, node-id equality, sentinel imports.

Asserts:
1. ``M3_FROZEN_MANIFEST.sha256`` covers every tracked file under ``tests/``,
   ``ee/tests/`` and ``ee/web/tests/`` plus the four named files
   (``ee/deploy/m2_gate.py``, ``ee/deploy/demo.py``,
   ``docs/control-plane/M2_BASELINE.md``, ``docs/control-plane/M2_DEMO.md``).
2. ``--collect-only`` output equals the three node-id lists, after applying
   the M1/M2 named skip rules (Linux skips, Windows symlink, pg marker).
3. The M3 sentinels import from both trees.
4. ``.github/workflows/tests.yml`` has a ``sha256sum -c`` step on
   ``M3_FROZEN_MANIFEST.sha256`` in all four CI jobs (``pytest``, ``ee``,
   ``ee-web``, ``connector-standalone``).

**New test files added during M3** are handled by the manifest coverage
check: CI's ``sha256sum -c`` will fail if a new tracked file is not in the
manifest, forcing the committer to add it.  The node-id check uses the
frozen lists, so a new M3 test file will fail this test until the node-id
file is updated (the same M2 rule).  The manifest and node-id files are
updated together in the task that adds the test.
"""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
CONTROL = REPO / "docs" / "control-plane"
MANIFEST = CONTROL / "M3_FROZEN_MANIFEST.sha256"
ROOT_NODEIDS = CONTROL / "M3_BASELINE_NODEIDS.txt"
EE_NODEIDS = CONTROL / "M3_BASELINE_EE_NODEIDS.txt"
WEB_NODEIDS = CONTROL / "M3_BASELINE_WEB_NODEIDS.txt"

# The four named files that must also be in the manifest.
NAMED_FILES = {
    "ee/deploy/m2_gate.py",
    "ee/deploy/demo.py",
    "docs/control-plane/M2_BASELINE.md",
    "docs/control-plane/M2_DEMO.md",
}

# The three test directories the manifest covers.
TEST_DIRS = ("tests/", "ee/tests/", "ee/web/tests/")

# True when ee/ is present AND its deps (agg_cp) are importable.  The
# connector-standalone CI job removes ee/ entirely; the pytest job has ee/
# on disk but does NOT install agg_cp, so collect-only on ee/tests/ errors
# with 42 import failures.  Both cases must skip the ee equality checks.
_EE_DIR_EXISTS = (REPO / "ee" / "tests").is_dir()
try:
    import agg_cp as _agg_cp_probe  # noqa: F401

    _EE_AVAILABLE = _EE_DIR_EXISTS
except ImportError:
    _EE_AVAILABLE = False


def _git_ls_files(*globs: str) -> set[str]:
    """Return tracked files matching the given pathspecs."""
    result = subprocess.run(
        ["git", "ls-files", "--", *globs],
        capture_output=True,
        text=True,
        check=True,
        cwd=str(REPO),
    )
    return {l.strip() for l in result.stdout.strip().split("\n") if l.strip()}


def _manifest_paths() -> set[str]:
    """Return the set of file paths listed in the M3 frozen manifest."""
    paths: set[str] = set()
    for line in MANIFEST.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        # Format: <hash>  <path>
        parts = line.split("  ", 1)
        if len(parts) == 2:
            paths.add(parts[1])
    return paths


def _read_nodeids(path: Path) -> list[str]:
    """Read a node-id file and return sorted non-empty lines."""
    return sorted(
        l.strip()
        for l in path.read_text(encoding="utf-8").splitlines()
        if l.strip()
    )


def _collect_only(test_dir: str) -> list[str]:
    """Run ``pytest --collect-only`` and return sorted node ids.

    Raises ``RuntimeError`` on non-zero exit or an ``error`` summary so that
    a collection failure (e.g. import error) is caught immediately instead of
    silently shortening the node-id list.
    """
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "-q",
            "--collect-only",
            "-p",
            "no:logging",
            test_dir,
        ],
        capture_output=True,
        text=True,
        cwd=str(REPO),
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"pytest --collect-only {test_dir} exited {result.returncode}:\n"
            + (result.stderr or "")[:500]
            + "\n"
            + (result.stdout or "")[-500:]
        )
    # Also catch a summary line reporting errors (e.g. "1 error" / "3 errors").
    for line in reversed(result.stdout.splitlines()):
        stripped = line.strip()
        if stripped and ({"error", "errors"} & set(stripped.lower().split())):
            raise RuntimeError(
                f"pytest --collect-only {test_dir} reported errors:\n"
                + result.stdout[-500:]
            )
        # The summary is in the last non-empty lines; stop after the first one.
        if stripped:
            break
    ids = sorted(
        l.strip()
        for l in result.stdout.splitlines()
        if "::" in l and l.strip()
    )
    return ids


def _import_from_path(name: str, filepath: Path):
    """Import a module by absolute file path."""
    spec = importlib.util.spec_from_file_location(name, str(filepath))
    assert spec is not None and spec.loader is not None, (
        f"Cannot load {filepath}"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ---------------------------------------------------------------------------
# 1. Manifest coverage
# ---------------------------------------------------------------------------


class TestManifestCoverage:
    """The M3 frozen manifest covers every tracked test file."""

    def test_manifest_exists(self) -> None:
        assert MANIFEST.is_file(), f"Missing {MANIFEST}"

    def test_manifest_covers_all_tracked_test_files(self) -> None:
        tracked = _git_ls_files(*TEST_DIRS)
        manifest = _manifest_paths()
        missing = tracked - manifest
        assert not missing, (
            f"{len(missing)} tracked test files missing from manifest: "
            + ", ".join(sorted(missing)[:10])
        )

    def test_manifest_covers_named_files(self) -> None:
        manifest = _manifest_paths()
        missing = NAMED_FILES - manifest
        assert not missing, (
            f"Named files missing from manifest: {sorted(missing)}"
        )

    def test_manifest_only_has_test_dir_and_named_files(self) -> None:
        """Every manifest path is under a test dir or is a named file."""
        manifest = _manifest_paths()
        extra = set()
        for p in manifest:
            if p in NAMED_FILES:
                continue
            if any(p.startswith(d) for d in TEST_DIRS):
                continue
            extra.add(p)
        assert not extra, (
            f"{len(extra)} files in manifest not under test dirs or named: "
            + ", ".join(sorted(extra)[:10])
        )


# ---------------------------------------------------------------------------
# 2. Node-id equality (with named skip rules)
# ---------------------------------------------------------------------------


class TestNodeIdEquality:
    """Collect-only output matches the frozen node-id lists."""

    def test_root_nodeids_file_exists(self) -> None:
        assert ROOT_NODEIDS.is_file(), f"Missing {ROOT_NODEIDS}"

    def test_ee_nodeids_file_exists(self) -> None:
        assert EE_NODEIDS.is_file(), f"Missing {EE_NODEIDS}"

    def test_web_nodeids_file_exists(self) -> None:
        assert WEB_NODEIDS.is_file(), f"Missing {WEB_NODEIDS}"

    @pytest.mark.timeout(120)  # nested collection of 2465 tests; 30 s default hit on slow CI runners
    def test_root_collect_only_equals_nodeids(self) -> None:
        expected = _read_nodeids(ROOT_NODEIDS)
        collected = _collect_only("tests/")
        assert len(collected) == len(expected), (
            f"Root collect-only: {len(collected)} vs node-id file: {len(expected)}"
        )
        assert collected == expected, "Root node ids differ from frozen list"

    @pytest.mark.timeout(120)  # nested collection; may take >30 s on slow CI runners
    @pytest.mark.skipif(
        not _EE_AVAILABLE,
        reason="ee/ absent or agg_cp not installed (connector-standalone / pytest job)",
    )
    def test_ee_collect_only_equals_nodeids(self) -> None:
        expected = _read_nodeids(EE_NODEIDS)
        collected = _collect_only("ee/tests/")
        assert len(collected) == len(expected), (
            f"EE collect-only: {len(collected)} vs node-id file: {len(expected)}"
        )
        assert collected == expected, "EE node ids differ from frozen list"

    def test_root_nodeids_count(self) -> None:
        """Smoke check: root count is at least 2438 (M2 baseline)."""
        expected = _read_nodeids(ROOT_NODEIDS)
        assert len(expected) >= 2438, f"Root count {len(expected)} < 2438"

    def test_ee_nodeids_count(self) -> None:
        """Smoke check: ee count is at least 933 (M2 baseline)."""
        expected = _read_nodeids(EE_NODEIDS)
        assert len(expected) >= 933, f"EE count {len(expected)} < 933"

    def test_web_nodeids_count(self) -> None:
        """Web test count is at least 92."""
        expected = _read_nodeids(WEB_NODEIDS)
        assert len(expected) >= 92, f"Web count {len(expected)} < 92"


# ---------------------------------------------------------------------------
# 3. Sentinel imports
# ---------------------------------------------------------------------------


class TestSentinelImports:
    """The M3 sentinel modules import without error."""

    def test_root_m3_pending_imports(self) -> None:
        mod = _import_from_path("m3_pending", REPO / "tests" / "m3_pending.py")
        assert hasattr(mod, "M3T1Pending")
        assert callable(mod.require_m3)

    @pytest.mark.skipif(
        not _EE_DIR_EXISTS,
        reason="ee/ absent (connector-standalone job removes ee/)",
    )
    def test_ee_m3_pending_imports(self) -> None:
        mod = _import_from_path(
            "ee_m3_pending", REPO / "ee" / "tests" / "m3_pending.py"
        )
        assert hasattr(mod, "M3T1Pending")
        assert callable(mod.require_m3)

    def test_root_m2_pending_still_imports(self) -> None:
        """M2 sentinels must still import (existing M2 tests use them)."""
        mod = _import_from_path(
            "m2_pending", REPO / "tests" / "m2_pending.py"
        )
        assert hasattr(mod, "M2T2Pending")
        assert callable(mod.require_m2)


# ---------------------------------------------------------------------------
# 4. CI manifest steps (sha256sum -c on M3_FROZEN_MANIFEST.sha256)
# ---------------------------------------------------------------------------


class TestCIManifestSteps:
    """All four CI jobs check M3_FROZEN_MANIFEST.sha256 with sha256sum -c.

    Parses ``.github/workflows/tests.yml`` via PyYAML (transitive dep via
    uvicorn[standard]) and asserts each job has the right ``sha256sum -c``
    step with the correct ``grep`` filter for its file scope.
    """

    @staticmethod
    def _load_workflow() -> dict:
        import yaml  # transitive via uvicorn[standard] -> PyYAML

        wf_path = REPO / ".github" / "workflows" / "tests.yml"
        return yaml.safe_load(wf_path.read_text(encoding="utf-8"))

    @staticmethod
    def _get_manifest_runs() -> dict[str, list[str]]:
        """Return ``{job_name: [run_strings]}`` for M3 manifest steps."""
        import yaml  # transitive via uvicorn[standard] -> PyYAML

        wf_path = REPO / ".github" / "workflows" / "tests.yml"
        wf = yaml.safe_load(wf_path.read_text(encoding="utf-8"))
        result: dict[str, list[str]] = {}
        for name, job in wf.get("jobs", {}).items():
            hits = []
            for step in job.get("steps", []):
                run = step.get("run", "")
                if "M3_FROZEN_MANIFEST" in run and "sha256sum" in run:
                    hits.append(run)
            if hits:
                result[name] = hits
        return result

    def test_pytest_has_m3_manifest_check(self) -> None:
        """The pytest job must check M3_FROZEN_MANIFEST.sha256 (whole manifest)."""
        runs = self._get_manifest_runs()
        assert "pytest" in runs, (
            "pytest job has no sha256sum -c step for M3_FROZEN_MANIFEST.sha256"
        )

    def test_ee_has_m3_manifest_check(self) -> None:
        """The ee job must check the ee/ half of M3_FROZEN_MANIFEST.sha256."""
        runs = self._get_manifest_runs()
        assert "ee" in runs, (
            "ee job has no sha256sum -c step for M3_FROZEN_MANIFEST.sha256"
        )
        step = runs["ee"][0]
        # Must select ee/ lines (grep '  ee/'), not exclude them (grep -v)
        assert "grep" in step and "ee/" in step, (
            "ee step must filter to ee/ lines with grep"
        )

    def test_ee_web_has_m3_manifest_check(self) -> None:
        """The ee-web job must check the ee/web/ half."""
        runs = self._get_manifest_runs()
        assert "ee-web" in runs, (
            "ee-web job has no sha256sum -c step for M3_FROZEN_MANIFEST.sha256"
        )
        step = runs["ee-web"][0]
        assert "ee/web/" in step, "ee-web step must filter to ee/web/ lines"

    def test_connector_standalone_has_m3_manifest_check(self) -> None:
        """connector-standalone must check the non-ee/ half."""
        runs = self._get_manifest_runs()
        assert "connector-standalone" in runs, (
            "connector-standalone has no sha256sum -c step for "
            "M3_FROZEN_MANIFEST.sha256"
        )
        step = runs["connector-standalone"][0]
        assert "grep -v" in step and "ee/" in step, (
            "connector-standalone step must exclude ee/ lines with grep -v"
        )


# ---------------------------------------------------------------------------
# 5. CI node-id equality steps (ee and web)
# ---------------------------------------------------------------------------


class TestCINodeIdSteps:
    """The ee and ee-web CI jobs check node-id equality against the frozen lists.

    The pytest job cannot check ee node-id equality (agg_cp is not installed),
    so a dedicated step in the ``ee`` job runs collect-only and diffs against
    ``M3_BASELINE_EE_NODEIDS.txt``.  Similarly, the ``ee-web`` job diffs
    vitest output against ``M3_BASELINE_WEB_NODEIDS.txt``.
    """

    @staticmethod
    def _step_names_by_job() -> dict[str, list[str]]:
        """Return ``{job_name: [step_names]}`` from the workflow."""
        import yaml  # transitive via uvicorn[standard] -> PyYAML

        wf_path = REPO / ".github" / "workflows" / "tests.yml"
        wf = yaml.safe_load(wf_path.read_text(encoding="utf-8"))
        result: dict[str, list[str]] = {}
        for name, job in wf.get("jobs", {}).items():
            names = []
            for step in job.get("steps", []):
                step_name = step.get("name", "")
                names.append(step_name)
            result[name] = names
        return result

    def test_ee_has_nodeid_equality_step(self) -> None:
        """The ee job must have a step that diffs against EE node-id file."""
        steps = self._step_names_by_job()
        assert "ee" in steps, "ee job not found"
        ee_steps = steps["ee"]
        assert any("node-id" in s.lower() and "ee" in s.lower() for s in ee_steps), (
            "ee job has no node-id equality step; steps: "
            + ", ".join(ee_steps)
        )

    def test_ee_web_has_nodeid_equality_step(self) -> None:
        """The ee-web job must have a step that diffs against web node-id file."""
        steps = self._step_names_by_job()
        assert "ee-web" in steps, "ee-web job not found"
        web_steps = steps["ee-web"]
        assert any("node-id" in s.lower() and "web" in s.lower() for s in web_steps), (
            "ee-web job has no node-id equality step; steps: "
            + ", ".join(web_steps)
        )
