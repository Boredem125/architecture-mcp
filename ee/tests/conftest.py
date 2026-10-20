"""ee/ test configuration.

Mirrors the root conftest's key-home isolation so ee/ tests that touch
the connector's signing layer do not write the real user directory.

T6 additions:
- ``pg`` marker for tests requiring a live Postgres instance.
- ``pg_url`` session-scoped fixture: uses ``AGG_TEST_PG_URL`` env var
  (CI service container) or starts testcontainers ``postgres:16``
  (pinned by digest); skips if Docker is unreachable.
- CI-skip hook: in CI (``CI=true``), any skipped ``pg`` test is a failure.
"""
from __future__ import annotations

import os
import sys

import pytest

# Ensure src/ is importable (for the sandbox package) when running
# ee/tests in isolation.
_ROOT = os.path.join(os.path.dirname(__file__), "..", "..", "src")
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)


# ---------------------------------------------------------------------------
# pg marker
# ---------------------------------------------------------------------------

def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line(
        "markers",
        "pg: test requires a live Postgres instance (uses pg_url fixture)",
    )


# ---------------------------------------------------------------------------
# pg_url fixture (session scope)
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def pg_url() -> str:
    """Return a postgresql+psycopg:// URL for a live Postgres 16 instance.

    Resolution order:
    1. ``AGG_TEST_PG_URL`` env var (CI service container).
    2. testcontainers ``postgres:16`` pinned by digest.
    3. Skip (Docker unreachable).
    """
    env_url = os.environ.get("AGG_TEST_PG_URL")
    if env_url:
        # Normalise driver prefix for psycopg 3
        if env_url.startswith("postgresql://"):
            env_url = "postgresql+psycopg://" + env_url[len("postgresql://"):]
        elif env_url.startswith("postgres://"):
            env_url = "postgresql+psycopg://" + env_url[len("postgres://"):]
        yield env_url
        return

    # Try testcontainers
    try:
        from testcontainers.community.postgres import PostgresContainer
    except ImportError:
        try:
            from testcontainers.postgres import PostgresContainer  # type: ignore[no-redef]
        except ImportError:
            pytest.skip("testcontainers[postgres] not installed")
            return  # unreachable, keeps type checkers happy

    from .pg_image import PG_IMAGE

    try:
        with PostgresContainer(image=PG_IMAGE, driver="psycopg") as pg:
            url = pg.get_connection_url()
            # Ensure psycopg 3 async driver prefix
            if url.startswith("postgresql://"):
                url = "postgresql+psycopg://" + url[len("postgresql://"):]
            elif url.startswith("postgresql+psycopg2://"):
                url = "postgresql+psycopg://" + url[len("postgresql+psycopg2://"):]
            yield url
    except Exception as exc:
        # Docker unreachable or container failed to start
        pytest.skip(f"Docker unreachable or Postgres container failed: {exc}")


# ---------------------------------------------------------------------------
# CI-skip hook: in CI, skipped pg tests become failures
# ---------------------------------------------------------------------------

@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item: pytest.Item, call: pytest.CallInfo) -> None:  # type: ignore[type-arg]
    outcome = yield
    report = outcome.get_result()

    if report.when != "call" and report.when != "setup":
        return

    # An xfail is reported as skipped; only a real skip counts.
    if not report.skipped or hasattr(report, "wasxfail"):
        return

    # Only act on pg-marked tests
    if not any(m.name == "pg" for m in item.iter_markers()):
        return

    # Only in CI
    if not os.environ.get("CI"):
        return

    # Turn skip into failure
    report.outcome = "failed"
    report.longrepr = (
        f"FAILED: pg-marked test was skipped in CI (CI=true). "
        f"Postgres must be available in CI. Original skip reason: {report.longrepr}"
    )
