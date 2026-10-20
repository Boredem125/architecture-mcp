"""Database engine and Alembic configuration for the control plane.

No module-level mutable state.  The engine is created per-request or
inside the FastAPI lifespan; never at import time.
"""
from __future__ import annotations

from pathlib import Path

from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine


_MIGRATIONS_DIR = str(Path(__file__).resolve().parent / "migrations")


def make_engine(url: str) -> AsyncEngine:
    """Create an async SQLAlchemy 2 engine for *url*.

    Expects ``postgresql+psycopg://`` (psycopg 3).
    """
    return create_async_engine(url)


def alembic_config(url: str) -> Config:
    """Return an Alembic :class:`Config` built in code.

    ``script_location`` points at the packaged ``agg_cp/migrations``
    directory so that ``pip install ./ee`` includes the migration
    scripts in the wheel.
    """
    cfg = Config()
    cfg.set_main_option("script_location", _MIGRATIONS_DIR)
    cfg.set_main_option("sqlalchemy.url", url)
    return cfg


def check_db_ready(db_url: str) -> tuple[bool, str]:
    """Synchronous check: DB reachable **and** schema at Alembic head.

    Returns ``(True, "")`` on success or ``(False, reason)`` with a
    short, non-secret reason string.  Never exposes the URL, password
    or raw exception text in the reason.

    Uses raw ``psycopg`` (sync) so the check works on Windows without
    a ``SelectorEventLoop`` event-loop policy.
    """
    import psycopg  # deferred: not needed at import time

    try:
        cfg = alembic_config(db_url)
        script = ScriptDirectory.from_config(cfg)
        head = script.get_current_head()
    except Exception:
        return False, "migration scripts unavailable"

    # Convert SQLAlchemy URL to libpq conninfo
    conninfo = db_url
    if "+psycopg" in conninfo:
        conninfo = conninfo.replace("+psycopg", "")

    try:
        with psycopg.connect(conninfo, connect_timeout=5) as conn:
            try:
                row = conn.execute(
                    "SELECT version_num FROM alembic_version"
                ).fetchone()
                current = row[0] if row else None
            except psycopg.errors.UndefinedTable:
                current = None
    except Exception:
        return False, "database unreachable"

    if current != head:
        return False, "schema behind migration head"
    return True, ""
