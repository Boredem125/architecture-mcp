"""M1 T6 tests-first: Postgres + Alembic harness for ee/.

T6 done-when: Alembic up/down round trip passes; a skipped pg test fails CI.

Design (from the orchestrator):
- ``agg_cp.db.make_engine(url) -> AsyncEngine`` (SQLAlchemy 2 async, psycopg 3)
- ``agg_cp.db.alembic_config(url)`` loads Alembic config from code
- Alembic scripts in ``ee/src/agg_cp/migrations/`` with async ``env.py``
- T6 ships one empty baseline revision; T7 adds tables
- ``/ready`` returns 200 only when DB reachable AND schema at Alembic head;
  503 with a non-secret reason otherwise
- ``/health`` stays 200 without DB

Tests marked ``xfail(strict=True, raises=T6Pending)`` fail before T6 code
exists.  The fix commit removes the decorator.
"""
from __future__ import annotations

import ast
import importlib
import os
import textwrap
from pathlib import Path

import pytest


# ---------------------------------------------------------------------------
# Named exception for the xfail marker (M0 T1b / T5 pattern)
# ---------------------------------------------------------------------------

class T6Pending(Exception):
    """T6 Postgres/Alembic harness is not built yet."""


def _require(cond: bool, msg: str) -> None:
    if not cond:
        raise T6Pending(msg)


RED_T6 = pytest.mark.xfail(
    raises=(T6Pending, ImportError, ModuleNotFoundError),
    strict=True,
    reason="M1 T6: Postgres/Alembic harness not yet built",
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

EE_SRC = Path(__file__).resolve().parents[1] / "src" / "agg_cp"
REPO_ROOT = Path(__file__).resolve().parents[2]


def _import_db():
    """Import agg_cp.db; raises T6Pending / ImportError if missing."""
    try:
        from agg_cp import db
        return db
    except (ImportError, ModuleNotFoundError, AttributeError) as exc:
        raise T6Pending(f"agg_cp.db not importable: {exc}") from exc


def _get_app_with_db(pg_url: str):
    """Return a TestClient wired to a real DB."""
    try:
        from agg_cp.app import create_app
    except (ImportError, ModuleNotFoundError) as exc:
        raise T6Pending(f"agg_cp.app not importable: {exc}") from exc
    try:
        from starlette.testclient import TestClient
    except ImportError as exc:
        raise T6Pending(f"starlette not available: {exc}") from exc

    # create_app must accept settings/db_url; T6 implementation decides shape
    # Try passing db_url as keyword; fall back to a settings object
    try:
        app = create_app(db_url=pg_url)
    except TypeError:
        raise T6Pending(
            "create_app does not accept db_url keyword; "
            "T6 needs create_app(settings) or create_app(db_url=...)"
        )
    return TestClient(app)


# ---------------------------------------------------------------------------
# 2. PG_IMAGE digest matches CI workflow
# ---------------------------------------------------------------------------

@RED_T6
def test_ci_workflow_pg_image_matches():
    """The postgres service image in .github/workflows/tests.yml ee job
    equals PG_IMAGE from ee/tests/pg_image.py."""
    from .pg_image import PG_IMAGE

    workflow = REPO_ROOT / ".github" / "workflows" / "tests.yml"
    _require(workflow.is_file(), f"CI workflow not found: {workflow}")

    text = workflow.read_text(encoding="utf-8")

    # The ee job should have a services: postgres: image: line
    _require(
        "postgres:" in text,
        "No 'postgres:' service found in tests.yml",
    )

    # Extract the image value after 'image:' in the ee job's services block
    # Simple text search: the digest should appear
    digest = PG_IMAGE.split("@")[1] if "@" in PG_IMAGE else PG_IMAGE
    _require(
        digest in text,
        f"PG_IMAGE digest {digest} not found in tests.yml ee job; "
        f"the postgres service must use the pinned image {PG_IMAGE}",
    )


# ---------------------------------------------------------------------------
# 3. Async engine: select 1
# ---------------------------------------------------------------------------

@RED_T6
@pytest.mark.pg
@pytest.mark.asyncio
async def test_make_engine_select_1(pg_url: str):
    """``agg_cp.db.make_engine(url)`` returns an AsyncEngine that can
    execute ``SELECT 1``."""
    db = _import_db()
    engine = db.make_engine(pg_url)
    try:
        from sqlalchemy import text
        async with engine.connect() as conn:
            result = await conn.execute(text("SELECT 1"))
            row = result.scalar()
            _require(row == 1, f"SELECT 1 returned {row}")
    finally:
        await engine.dispose()


# ---------------------------------------------------------------------------
# 4. Alembic
# ---------------------------------------------------------------------------

@RED_T6
@pytest.mark.pg
def test_alembic_config_loadable(pg_url: str):
    """``agg_cp.db.alembic_config(url)`` returns an Alembic Config object
    pointing at the migrations directory."""
    db = _import_db()
    _require(
        hasattr(db, "alembic_config"),
        "agg_cp.db has no alembic_config function",
    )
    cfg = db.alembic_config(pg_url)
    from alembic.config import Config
    _require(
        isinstance(cfg, Config),
        f"alembic_config returned {type(cfg)}, expected alembic.config.Config",
    )


@RED_T6
@pytest.mark.pg
def test_alembic_round_trip(pg_url: str):
    """Alembic up/down round trip: upgrade head, snapshot, downgrade base,
    upgrade head, snapshot equal.

    Generic: covers T7+ revisions unchanged.
    """
    db = _import_db()
    cfg = db.alembic_config(pg_url)

    from alembic import command as alembic_cmd
    from sqlalchemy import create_engine, inspect, text

    # Use sync engine for Alembic commands
    sync_url = pg_url.replace("+psycopg://", "://").replace("postgresql+psycopg://", "postgresql://")
    if "psycopg" in sync_url:
        sync_url = sync_url.replace("+psycopg", "")
    sync_engine = create_engine(pg_url.replace("+psycopg", "+psycopg"))  # psycopg3 works sync too

    # Upgrade to head
    alembic_cmd.upgrade(cfg, "head")

    def _snapshot(eng):
        """Snapshot the public schema: tables, columns, indexes, constraints,
        functions, triggers, policies from pg_catalog/information_schema."""
        insp = inspect(eng)
        snap = {}
        tables = sorted(insp.get_table_names(schema="public"))
        for t in tables:
            cols = sorted(
                [(c["name"], str(c["type"])) for c in insp.get_columns(t, schema="public")]
            )
            indexes = sorted(
                [(i["name"], i["column_names"], i["unique"]) for i in insp.get_indexes(t, schema="public")]
            )
            fks = sorted(
                [
                    (fk["name"], fk["constrained_columns"], fk["referred_table"])
                    for fk in insp.get_foreign_keys(t, schema="public")
                ]
            )
            pk = insp.get_pk_constraint(t, schema="public")
            uqs = sorted(
                [(u["name"], u["column_names"]) for u in insp.get_unique_constraints(t, schema="public")]
            )
            snap[t] = {
                "columns": cols,
                "indexes": indexes,
                "fks": fks,
                "pk": pk,
                "unique_constraints": uqs,
            }

        # Also snapshot functions, triggers, policies from pg_catalog
        with eng.connect() as conn:
            # Functions in public schema
            funcs = conn.execute(text(
                "SELECT routine_name, routine_type "
                "FROM information_schema.routines "
                "WHERE routine_schema = 'public' "
                "ORDER BY routine_name"
            )).fetchall()
            snap["__functions__"] = [(r[0], r[1]) for r in funcs]

            # Triggers
            triggers = conn.execute(text(
                "SELECT trigger_name, event_object_table, action_timing, event_manipulation "
                "FROM information_schema.triggers "
                "WHERE trigger_schema = 'public' "
                "ORDER BY trigger_name, event_object_table"
            )).fetchall()
            snap["__triggers__"] = [(r[0], r[1], r[2], r[3]) for r in triggers]

            # RLS policies
            policies = conn.execute(text(
                "SELECT polname, relname, polcmd, polpermissive, "
                "pg_get_expr(polqual, polrelid), pg_get_expr(polwithcheck, polrelid) "
                "FROM pg_policy JOIN pg_class ON pg_policy.polrelid = pg_class.oid "
                "JOIN pg_namespace ON pg_class.relnamespace = pg_namespace.oid "
                "WHERE nspname = 'public' "
                "ORDER BY relname, polname"
            )).fetchall()
            snap["__policies__"] = [tuple(r) for r in policies]
            # RLS enabled/forced per table (a downgrade+upgrade must restore both)
            rls = conn.execute(text(
                "SELECT relname, relrowsecurity, relforcerowsecurity "
                "FROM pg_class JOIN pg_namespace ON pg_class.relnamespace = pg_namespace.oid "
                "WHERE nspname = 'public' AND relkind = 'r' "
                "ORDER BY relname"
            )).fetchall()
            snap["__rls__"] = [tuple(r) for r in rls]

        return snap

    snap1 = _snapshot(sync_engine)

    # Downgrade to base
    alembic_cmd.downgrade(cfg, "base")

    # After downgrade: only alembic_version or nothing left
    insp = inspect(sync_engine)
    remaining = set(insp.get_table_names(schema="public"))
    _require(
        remaining <= {"alembic_version"},
        f"After downgrade to base, unexpected tables remain: {remaining - {'alembic_version'}}",
    )

    # Upgrade again
    alembic_cmd.upgrade(cfg, "head")
    snap2 = _snapshot(sync_engine)

    _require(
        snap1 == snap2,
        f"Round-trip snapshots differ.\nFirst: {snap1}\nSecond: {snap2}",
    )

    sync_engine.dispose()


@RED_T6
def test_alembic_every_revision_has_downgrade():
    """Every Alembic revision has a non-empty downgrade() body, or is the
    empty baseline (no operations in upgrade either).

    Uses AST/inspect to check, so no DB needed.
    """
    migrations_dir = EE_SRC / "migrations" / "versions"
    _require(
        migrations_dir.is_dir(),
        f"Migrations directory not found: {migrations_dir}",
    )

    version_files = sorted(migrations_dir.glob("*.py"))
    _require(len(version_files) > 0, "No migration files found")

    for vf in version_files:
        source = vf.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(vf))

        upgrade_body = None
        downgrade_body = None

        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                if node.name == "upgrade":
                    upgrade_body = node.body
                elif node.name == "downgrade":
                    downgrade_body = node.body

        _require(
            downgrade_body is not None,
            f"{vf.name}: missing downgrade() function",
        )

        # Check if downgrade body is non-empty (not just `pass`)
        is_pass_only = (
            len(downgrade_body) == 1
            and isinstance(downgrade_body[0], (ast.Pass, ast.Expr))
            and (
                isinstance(downgrade_body[0], ast.Pass)
                or (isinstance(downgrade_body[0], ast.Expr) and isinstance(downgrade_body[0].value, ast.Constant))
            )
        )

        if is_pass_only:
            # Only allowed if this is the empty baseline (upgrade is also empty)
            upgrade_is_empty = (
                upgrade_body is not None
                and len(upgrade_body) == 1
                and isinstance(upgrade_body[0], (ast.Pass, ast.Expr))
                and (
                    isinstance(upgrade_body[0], ast.Pass)
                    or (isinstance(upgrade_body[0], ast.Expr) and isinstance(upgrade_body[0].value, ast.Constant))
                )
            )
            _require(
                upgrade_is_empty,
                f"{vf.name}: downgrade() is empty (pass-only) but upgrade() "
                f"has operations -- every non-baseline revision needs a real downgrade",
            )


# ---------------------------------------------------------------------------
# 5. /ready endpoint
# ---------------------------------------------------------------------------

@RED_T6
@pytest.mark.pg
def test_ready_200_when_db_reachable_and_at_head(pg_url: str):
    """/ready returns 200 {"status": "ok"} when DB reachable AND schema at
    Alembic head."""
    # First, run migrations to head
    db = _import_db()
    cfg = db.alembic_config(pg_url)

    from alembic import command as alembic_cmd
    alembic_cmd.upgrade(cfg, "head")

    client = _get_app_with_db(pg_url)
    resp = client.get("/ready")
    _require(resp.status_code == 200, f"/ready returned {resp.status_code}, expected 200")
    body = resp.json()
    _require(body.get("status") == "ok", f"/ready body: {body}")


@RED_T6
@pytest.mark.pg
def test_ready_503_behind_head(pg_url: str):
    """/ready returns 503 when schema is behind Alembic head."""
    db = _import_db()
    cfg = db.alembic_config(pg_url)

    from alembic import command as alembic_cmd
    # Downgrade to base so schema is behind head
    alembic_cmd.downgrade(cfg, "base")

    client = _get_app_with_db(pg_url)
    resp = client.get("/ready")
    _require(
        resp.status_code == 503,
        f"/ready returned {resp.status_code} when behind head, expected 503",
    )
    body = resp.json()
    _require("status" in body, f"/ready 503 body missing 'status': {body}")
    # Should mention being behind head (non-secret reason)
    body_str = str(body).lower()
    _require(
        "behind" in body_str or "head" in body_str or "migration" in body_str,
        f"/ready 503 body should mention being behind head: {body}",
    )


@RED_T6
def test_ready_503_unreachable_db():
    """/ready returns 503 when DB is unreachable (bad port). Non-pg test."""
    try:
        from agg_cp.app import create_app
    except (ImportError, ModuleNotFoundError) as exc:
        raise T6Pending(f"agg_cp.app not importable: {exc}") from exc
    try:
        from starlette.testclient import TestClient
    except ImportError as exc:
        raise T6Pending(f"starlette not available: {exc}") from exc

    # Use a DB URL pointing to a port that nothing listens on
    bad_url = "postgresql+psycopg://user:pass@127.0.0.1:1/nonexistent"
    try:
        app = create_app(db_url=bad_url)
    except TypeError:
        raise T6Pending("create_app does not accept db_url keyword")

    client = TestClient(app)
    resp = client.get("/ready")
    _require(
        resp.status_code == 503,
        f"/ready returned {resp.status_code} with unreachable DB, expected 503",
    )
    body = resp.json()
    _require("status" in body, f"/ready 503 body missing 'status': {body}")


def test_health_stays_200_without_db():
    """/health stays 200 without any DB configured."""
    try:
        from agg_cp.app import create_app
    except (ImportError, ModuleNotFoundError) as exc:
        pytest.skip(f"agg_cp.app not importable: {exc}")
        return
    try:
        from starlette.testclient import TestClient
    except ImportError as exc:
        pytest.skip(f"starlette not available: {exc}")
        return

    app = create_app()
    client = TestClient(app)
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json().get("status") == "ok"
