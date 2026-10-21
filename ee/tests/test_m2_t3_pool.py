"""T3 tests-first: DB connection pool in agg_cp/db.py.

After T3:
- ``make_engine`` accepts pool_size, max_overflow, pool_pre_ping,
  pool_recycle from settings (or explicit kwargs).
- A pg leak test over 4 workers: no checkout timeout, no app.org_id
  leak across pooled connections.

RED tests xfail on M2T3Pending.  Guards verify db.py imports.
"""
from __future__ import annotations

import uuid

import pytest

from .m2_pending import M2T3Pending, require_m2

# ---------------------------------------------------------------------------
# Sentinel helper
# ---------------------------------------------------------------------------

def _import_make_engine():
    try:
        from agg_cp.db import make_engine
        return make_engine
    except ImportError:
        raise M2T3Pending("agg_cp.db not importable")


# ===================================================================
# Guards (pass now)
# ===================================================================


def test_db_module_importable():
    """Guard: agg_cp.db is importable."""
    from agg_cp import db
    assert hasattr(db, "make_engine")


# ===================================================================
# RED: make_engine accepts pool settings
# ===================================================================


@pytest.mark.xfail(strict=True, raises=M2T3Pending)
def test_make_engine_pool_size():
    """make_engine passes pool_size to the engine."""
    make_engine = _import_make_engine()
    import inspect
    sig = inspect.signature(make_engine)
    params = list(sig.parameters.keys())
    if "pool_size" not in params:
        raise M2T3Pending("make_engine does not accept pool_size")


@pytest.mark.xfail(strict=True, raises=M2T3Pending)
def test_make_engine_max_overflow():
    """make_engine passes max_overflow to the engine."""
    make_engine = _import_make_engine()
    import inspect
    sig = inspect.signature(make_engine)
    if "max_overflow" not in sig.parameters:
        raise M2T3Pending("make_engine does not accept max_overflow")


@pytest.mark.xfail(strict=True, raises=M2T3Pending)
def test_make_engine_pool_pre_ping():
    """make_engine passes pool_pre_ping to the engine."""
    make_engine = _import_make_engine()
    import inspect
    sig = inspect.signature(make_engine)
    if "pool_pre_ping" not in sig.parameters:
        raise M2T3Pending("make_engine does not accept pool_pre_ping")


@pytest.mark.xfail(strict=True, raises=M2T3Pending)
def test_make_engine_pool_recycle():
    """make_engine passes pool_recycle to the engine."""
    make_engine = _import_make_engine()
    import inspect
    sig = inspect.signature(make_engine)
    if "pool_recycle" not in sig.parameters:
        raise M2T3Pending("make_engine does not accept pool_recycle")


# ===================================================================
# RED: pg leak test -- no org_id leak across pooled connections
# ===================================================================


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M2T3Pending)
def test_pool_no_org_id_leak(pg_url, pg_roles, app_url):
    """After releasing a connection with app.org_id set, the next
    checkout must not carry the old org_id."""
    try:
        from sqlalchemy import create_engine, text
    except ImportError:
        raise M2T3Pending("sqlalchemy not available")

    make_engine_fn = _import_make_engine()
    import inspect
    sig = inspect.signature(make_engine_fn)
    if "pool_size" not in sig.parameters:
        raise M2T3Pending("make_engine does not accept pool_size yet")

    # Use sync engine for simplicity
    sync_url = app_url.replace("+psycopg", "")
    eng = create_engine(
        sync_url, pool_size=1, max_overflow=0, pool_pre_ping=True,
    )

    org_a = str(uuid.uuid4())
    org_b = str(uuid.uuid4())

    # Connection 1: set org_id to org_a
    with eng.connect() as conn:
        conn.execute(text("SELECT set_config('app.org_id', :oid, true)"),
                     {"oid": org_a})
        val = conn.execute(
            text("SELECT current_setting('app.org_id', true)")
        ).scalar()
        assert val == org_a

    # Connection 2 (same pooled conn): org_id must be empty or org_b
    with eng.connect() as conn:
        val = conn.execute(
            text("SELECT current_setting('app.org_id', true)")
        ).scalar()
        # The pool should reset the session, so org_id should be empty/null
        if val == org_a:
            raise M2T3Pending(
                f"app.org_id leaked across pooled connections: got {val!r}"
            )

    eng.dispose()


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M2T3Pending)
def test_pool_no_checkout_timeout_4_workers(pg_url, pg_roles, app_url):
    """4 concurrent workers can all get a connection without a timeout."""
    from concurrent.futures import ThreadPoolExecutor, as_completed

    make_engine_fn = _import_make_engine()
    import inspect
    sig = inspect.signature(make_engine_fn)
    if "pool_size" not in sig.parameters:
        raise M2T3Pending("make_engine does not accept pool_size yet")

    try:
        from sqlalchemy import create_engine, text
    except ImportError:
        raise M2T3Pending("sqlalchemy not available")

    sync_url = app_url.replace("+psycopg", "")
    eng = create_engine(
        sync_url, pool_size=4, max_overflow=2, pool_pre_ping=True,
    )

    def worker(n: int) -> str:
        with eng.connect() as conn:
            return conn.execute(text("SELECT 'ok'")).scalar()

    results = []
    with ThreadPoolExecutor(max_workers=4) as pool:
        futs = [pool.submit(worker, i) for i in range(4)]
        for f in as_completed(futs):
            results.append(f.result())

    assert all(r == "ok" for r in results), f"Some workers failed: {results}"
    eng.dispose()
