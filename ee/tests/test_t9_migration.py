"""T9 migration 0004 tests.

Verifies:
- Unique index on role_bindings (org_id, user_id, scope_type, scope_id, role).
- CHECK constraints refuse bad role / scope_type / environment (+ good values pass).
- Downgrade to 0003 removes the 0004 additions.
"""
from __future__ import annotations

import uuid

import psycopg
import pytest

from .t9_helpers import (
    T9Pending,
    RED_T9,
    require_t9,
    _conninfo,
    ensure_at_head,
    seed_org_with_oidc,
    seed_user,
    unique_slug,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _index_exists(conn, index_name: str) -> bool:
    row = conn.execute(
        "SELECT EXISTS ("
        "  SELECT 1 FROM pg_indexes "
        "  WHERE schemaname = 'public' AND indexname = %s"
        ")",
        [index_name],
    ).fetchone()
    return row[0]


def _unique_index_on_columns(conn, table: str, columns: list[str]) -> bool:
    """Check if a UNIQUE index covering exactly *columns* exists on *table*."""
    rows = conn.execute(
        "SELECT i.relname, ix.indisunique, "
        "  array_agg(a.attname ORDER BY array_position(ix.indkey, a.attnum)) "
        "FROM pg_class t "
        "JOIN pg_index ix ON t.oid = ix.indrelid "
        "JOIN pg_class i ON i.oid = ix.indexrelid "
        "JOIN pg_attribute a ON a.attrelid = t.oid "
        "  AND a.attnum = ANY(ix.indkey) "
        "WHERE t.relname = %s AND ix.indisunique "
        "GROUP BY i.relname, ix.indisunique",
        [table],
    ).fetchall()
    target = sorted(columns)
    for _, is_unique, idx_cols in rows:
        if is_unique and sorted(idx_cols) == target:
            return True
    return False


def _check_constraint_exists_for_column(conn, table: str, column: str) -> bool:
    """Check that at least one CHECK constraint references *column* on *table*."""
    rows = conn.execute(
        "SELECT conname, pg_get_constraintdef(c.oid) "
        "FROM pg_constraint c "
        "JOIN pg_class t ON t.oid = c.conrelid "
        "WHERE t.relname = %s AND c.contype = 'c'",
        [table],
    ).fetchall()
    for _, defn in rows:
        if column in defn:
            return True
    return False


def _head_is_at_least_0004(pg_url: str) -> bool:
    """Return True if alembic head includes 0004."""
    from agg_cp.db import alembic_config
    from alembic.script import ScriptDirectory

    cfg = alembic_config(pg_url)
    script = ScriptDirectory.from_config(cfg)
    head = script.get_current_head()
    return head is not None and head >= "000000000004"


# ===================================================================
# 0004 unique index on role_bindings
# ===================================================================


@RED_T9
@pytest.mark.pg
def test_0004_unique_index_exists(pg_url, app_url, owner_url, pg_roles):
    """0004 adds a unique index on role_bindings (org_id, user_id, scope_type, scope_id, role)."""
    ensure_at_head(pg_url)
    require_t9(
        _head_is_at_least_0004(pg_url),
        "Migration 0004 does not exist yet",
    )
    with psycopg.connect(_conninfo(pg_url)) as conn:
        assert _unique_index_on_columns(
            conn, "role_bindings",
            ["org_id", "user_id", "scope_type", "scope_id", "role"],
        ), "Unique index on role_bindings (org_id, user_id, scope_type, scope_id, role) missing"


# ===================================================================
# CHECK constraints
# ===================================================================


@RED_T9
@pytest.mark.pg
def test_0004_check_constraints_refuse_bad_values(pg_url, app_url, owner_url, pg_roles):
    """CHECK constraints refuse bad role, scope_type, and environment values."""
    ensure_at_head(pg_url)
    require_t9(
        _head_is_at_least_0004(pg_url),
        "Migration 0004 does not exist yet",
    )

    slug = unique_slug("chk")
    org_id = seed_org_with_oidc(owner_url, slug=slug)
    user_id, _ = seed_user(owner_url, org_id)
    conninfo = _conninfo(owner_url)

    with psycopg.connect(conninfo) as conn:
        conn.execute(
            "SELECT set_config('app.org_id', %s, false)", [str(org_id)]
        )

        # Bad role
        with pytest.raises(psycopg.errors.CheckViolation):
            conn.execute(
                "INSERT INTO role_bindings "
                "(id, org_id, user_id, scope_type, scope_id, role, created_at) "
                "VALUES (%s, %s, %s, 'org', %s, 'superadmin', now())",
                [uuid.uuid4(), org_id, user_id, org_id],
            )
        conn.rollback()

        conn.execute(
            "SELECT set_config('app.org_id', %s, false)", [str(org_id)]
        )

        # Bad scope_type
        with pytest.raises(psycopg.errors.CheckViolation):
            conn.execute(
                "INSERT INTO role_bindings "
                "(id, org_id, user_id, scope_type, scope_id, role, created_at) "
                "VALUES (%s, %s, %s, 'team', %s, 'admin', now())",
                [uuid.uuid4(), org_id, user_id, org_id],
            )
        conn.rollback()

        conn.execute(
            "SELECT set_config('app.org_id', %s, false)", [str(org_id)]
        )

        # Bad environment on projects
        with pytest.raises(psycopg.errors.CheckViolation):
            conn.execute(
                "INSERT INTO projects "
                "(id, org_id, name, environment, created_at) "
                "VALUES (%s, %s, 'proj', 'sandbox', now())",
                [uuid.uuid4(), org_id],
            )
        conn.rollback()


@RED_T9
@pytest.mark.pg
def test_0004_check_constraints_good_values_pass(pg_url, app_url, owner_url, pg_roles):
    """Positive control: valid role, scope_type, and environment values pass CHECK constraints."""
    ensure_at_head(pg_url)
    require_t9(
        _head_is_at_least_0004(pg_url),
        "Migration 0004 does not exist yet",
    )

    slug = unique_slug("chkgood")
    org_id = seed_org_with_oidc(owner_url, slug=slug)
    user_id, _ = seed_user(owner_url, org_id)
    conninfo = _conninfo(owner_url)

    with psycopg.connect(conninfo) as conn:
        conn.execute(
            "SELECT set_config('app.org_id', %s, false)", [str(org_id)]
        )
        # Valid roles
        for role in ("admin", "policy_author", "approver", "auditor", "viewer"):
            conn.execute(
                "INSERT INTO role_bindings "
                "(id, org_id, user_id, scope_type, scope_id, role, created_at) "
                "VALUES (%s, %s, %s, 'org', %s, %s, now())",
                [uuid.uuid4(), org_id, user_id, org_id, role],
            )
        # Valid scope_types: project
        proj_id = uuid.uuid4()
        conn.execute(
            "INSERT INTO projects (id, org_id, name, environment, created_at) "
            "VALUES (%s, %s, 'p1', 'dev', now())",
            [proj_id, org_id],
        )
        conn.execute(
            "INSERT INTO role_bindings "
            "(id, org_id, user_id, scope_type, scope_id, role, created_at) "
            "VALUES (%s, %s, %s, 'project', %s, 'viewer', now())",
            [uuid.uuid4(), org_id, user_id, proj_id],
        )
        # Valid environments
        for env in ("dev", "staging", "prod"):
            conn.execute(
                "INSERT INTO projects (id, org_id, name, environment, created_at) "
                "VALUES (%s, %s, %s, %s, now())",
                [uuid.uuid4(), org_id, f"proj-{env}", env],
            )
        conn.commit()


# ===================================================================
# Downgrade from 0004 to 0003
# ===================================================================


@RED_T9
@pytest.mark.pg
def test_0004_downgrade_removes_additions(pg_url, pg_roles):
    """Downgrading from 0004 to 0003 removes the unique index and CHECK constraints."""
    ensure_at_head(pg_url)
    require_t9(
        _head_is_at_least_0004(pg_url),
        "Migration 0004 does not exist yet",
    )

    from agg_cp.db import alembic_config
    from alembic import command as alembic_cmd

    cfg = alembic_config(pg_url)

    # Downgrade to 0003
    alembic_cmd.downgrade(cfg, "000000000003")

    try:
        with psycopg.connect(_conninfo(pg_url)) as conn:
            # Unique index should be gone
            assert not _unique_index_on_columns(
                conn, "role_bindings",
                ["org_id", "user_id", "scope_type", "scope_id", "role"],
            ), "Unique index still exists after downgrade to 0003"

            # CHECK constraints should be gone
            assert not _check_constraint_exists_for_column(
                conn, "role_bindings", "role",
            ), "CHECK constraint on role still exists after downgrade"
            assert not _check_constraint_exists_for_column(
                conn, "role_bindings", "scope_type",
            ), "CHECK constraint on scope_type still exists after downgrade"
            assert not _check_constraint_exists_for_column(
                conn, "projects", "environment",
            ), "CHECK constraint on environment still exists after downgrade"
    finally:
        # Restore to head
        alembic_cmd.upgrade(cfg, "head")
