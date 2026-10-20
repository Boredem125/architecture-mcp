"""Alembic environment for agg_cp (async, psycopg 3).

Uses ``create_async_engine`` so the same ``postgresql+psycopg://`` URL
works for both the async application engine and the sync Alembic CLI.
"""
from __future__ import annotations

import asyncio
import sys

from alembic import context
from sqlalchemy import pool
from sqlalchemy.ext.asyncio import create_async_engine

config = context.config
target_metadata = None


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode (emit SQL without connecting)."""
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def _do_run_migrations(connection) -> None:  # type: ignore[no-untyped-def]
    context.configure(connection=connection, target_metadata=target_metadata)
    with context.begin_transaction():
        context.run_migrations()


async def _run_async_migrations() -> None:
    connectable = create_async_engine(
        config.get_main_option("sqlalchemy.url"),
        poolclass=pool.NullPool,
    )
    async with connectable.connect() as connection:
        await connection.run_sync(_do_run_migrations)
    await connectable.dispose()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode (connect to the database).

    On Windows, psycopg 3 requires a ``SelectorEventLoop`` (not the
    default ``ProactorEventLoop``).
    """
    kwargs: dict = {}
    if sys.platform == "win32":
        kwargs["loop_factory"] = asyncio.SelectorEventLoop
    asyncio.run(_run_async_migrations(), **kwargs)


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
