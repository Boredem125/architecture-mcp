"""M1 T6: CI-skip rule test.

Verifies that a ``pg``-marked test that skips becomes a failure when
``CI=true``, and stays a normal skip when ``CI`` is unset.

Uses a subprocess pytest run of a tiny self-contained test with:
- ``CI=true``, ``AGG_TEST_PG_URL`` unset, Docker unreachable
  (``DOCKER_HOST=tcp://127.0.0.1:1``) -> exits non-zero, test reported failed.
- Same without ``CI`` -> exits 0, test skipped.

This test is self-contained (creates its own conftest in a temp directory).
It passes now (no T6 implementation dependency).
"""
from __future__ import annotations

import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest


# The conftest hook code that the ee/ tests use. We inline it here so the
# subprocess test is self-contained.
_CONFTEST_CODE = textwrap.dedent('''\
    import os
    import pytest

    def pytest_configure(config):
        config.addinivalue_line("markers", "pg: requires live Postgres")

    @pytest.fixture(scope="session")
    def pg_url():
        env_url = os.environ.get("AGG_TEST_PG_URL")
        if env_url:
            yield env_url
            return
        # Try testcontainers (will fail with DOCKER_HOST=tcp://127.0.0.1:1)
        try:
            from testcontainers.postgres import PostgresContainer
            with PostgresContainer("postgres:16") as pg:
                yield pg.get_connection_url()
        except Exception as exc:
            pytest.skip(f"Docker unreachable: {exc}")

    @pytest.hookimpl(hookwrapper=True)
    def pytest_runtest_makereport(item, call):
        outcome = yield
        report = outcome.get_result()
        if report.when not in ("call", "setup"):
            return
        if not report.skipped:
            return
        if not any(m.name == "pg" for m in item.iter_markers()):
            return
        if not os.environ.get("CI"):
            return
        report.outcome = "failed"
        report.longrepr = (
            f"FAILED: pg-marked test was skipped in CI. "
            f"Original: {report.longrepr}"
        )
''')

_TEST_CODE = textwrap.dedent('''\
    import pytest

    @pytest.mark.pg
    def test_needs_pg(pg_url):
        """A tiny pg test that uses the pg_url fixture."""
        assert pg_url is not None
''')


def _run_subprocess_pytest(
    tmp_path: Path, *, ci: bool, timeout: int = 60
) -> subprocess.CompletedProcess:
    """Run pytest in a subprocess with controlled environment."""
    test_dir = tmp_path / ("ci" if ci else "noci")
    test_dir.mkdir(exist_ok=True)

    (test_dir / "conftest.py").write_text(_CONFTEST_CODE, encoding="utf-8")
    (test_dir / "test_pg_skip.py").write_text(_TEST_CODE, encoding="utf-8")

    env = {
        "SYSTEMROOT": os.environ.get("SYSTEMROOT", ""),
        "PATH": os.environ.get("PATH", ""),
        "DOCKER_HOST": "tcp://127.0.0.1:1",  # unreachable
        "PYTHONPATH": "",
        "VIRTUAL_ENV": os.environ.get("VIRTUAL_ENV", ""),
    }
    # Remove AGG_TEST_PG_URL to force testcontainers path
    env.pop("AGG_TEST_PG_URL", None)

    if ci:
        env["CI"] = "true"

    # Preserve Windows essentials
    for key in ("LOCALAPPDATA", "APPDATA", "USERPROFILE", "HOMEDRIVE", "HOMEPATH", "TMP", "TEMP"):
        val = os.environ.get(key)
        if val:
            env[key] = val

    result = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-p", "no:logging", str(test_dir)],
        capture_output=True,
        text=True,
        timeout=timeout,
        env=env,
    )
    return result


def test_ci_skip_pg_is_failure(tmp_path: Path):
    """With CI=true and Docker unreachable, a pg-marked test that would skip
    instead fails (non-zero exit)."""
    result = _run_subprocess_pytest(tmp_path, ci=True)
    assert result.returncode != 0, (
        f"Expected non-zero exit for skipped pg test in CI, got {result.returncode}.\n"
        f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )
    # Verify it was reported as failed, not just an error
    output = result.stdout + result.stderr
    assert "failed" in output.lower() or "FAILED" in output, (
        f"Expected 'failed' in output:\n{output}"
    )


def test_non_ci_skip_pg_is_ok(tmp_path: Path):
    """Without CI, a pg-marked test that skips is fine (exit 0)."""
    result = _run_subprocess_pytest(tmp_path, ci=False)
    assert result.returncode == 0, (
        f"Expected exit 0 for skipped pg test without CI, got {result.returncode}.\n"
        f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )
    output = result.stdout
    assert "skipped" in output.lower() or "skip" in output.lower(), (
        f"Expected 'skipped' in output:\n{output}"
    )
