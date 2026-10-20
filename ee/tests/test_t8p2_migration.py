"""T8 part 2: migration 0003 tests.

Tests that revision 0003 adds the expected schema objects:
- ``web_sessions`` gains ``token_hash``, ``csrf_hash``, ``last_seen_at``, ``revoked_at``
- ``setup_codes`` gains ``used_at``, ``failed_attempts``
- New ``login_transactions`` table with ENABLE+FORCE RLS, org policy, owner agg_owner
- ``agg_app`` SELECT/INSERT/DELETE on ``login_transactions``
- Downgrade to 0002 removes the new columns and table
- Cross-org isolation: agg_app cannot see another org's login_transactions rows
"""
from __future__ import annotations

import uuid

import pytest

from .t8p2_helpers import (
    T8P2Pending,
    RED_T8P2,
    require_t8p2,
    _conninfo,
    ensure_at_head,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _column_exists(conn, table: str, column: str) -> bool:
    row = conn.execute(
        "SELECT EXISTS ("
        "  SELECT 1 FROM information_schema.columns "
        "  WHERE table_schema = 'public' "
        "  AND table_name = %s AND column_name = %s"
        ")",
        [table, column],
    ).fetchone()
    return row[0]


def _table_exists(conn, table: str) -> bool:
    row = conn.execute(
        "SELECT EXISTS ("
        "  SELECT 1 FROM pg_tables "
        "  WHERE schemaname = 'public' AND tablename = %s"
        ")",
        [table],
    ).fetchone()
    return row[0]


# ===================================================================
# 0003 new columns on web_sessions
# ===================================================================


@RED_T8P2
@pytest.mark.pg
def test_web_sessions_has_token_hash(pg_url, app_url, pg_roles):
    """web_sessions has a token_hash column after 0003."""
    import psycopg
    ensure_at_head(pg_url)
    with psycopg.connect(_conninfo(pg_url)) as conn:
        require_t8p2(_column_exists(conn, "web_sessions", "token_hash"),
                      "web_sessions.token_hash column missing")


@RED_T8P2
@pytest.mark.pg
def test_web_sessions_has_csrf_hash(pg_url, app_url, pg_roles):
    """web_sessions has a csrf_hash column after 0003."""
    import psycopg
    ensure_at_head(pg_url)
    with psycopg.connect(_conninfo(pg_url)) as conn:
        require_t8p2(_column_exists(conn, "web_sessions", "csrf_hash"),
                      "web_sessions.csrf_hash column missing")


@RED_T8P2
@pytest.mark.pg
def test_web_sessions_has_last_seen_at(pg_url, app_url, pg_roles):
    """web_sessions has a last_seen_at column after 0003."""
    import psycopg
    ensure_at_head(pg_url)
    with psycopg.connect(_conninfo(pg_url)) as conn:
        require_t8p2(_column_exists(conn, "web_sessions", "last_seen_at"),
                      "web_sessions.last_seen_at column missing")


@RED_T8P2
@pytest.mark.pg
def test_web_sessions_has_revoked_at(pg_url, app_url, pg_roles):
    """web_sessions has a revoked_at column after 0003."""
    import psycopg
    ensure_at_head(pg_url)
    with psycopg.connect(_conninfo(pg_url)) as conn:
        require_t8p2(_column_exists(conn, "web_sessions", "revoked_at"),
                      "web_sessions.revoked_at column missing")


# ===================================================================
# 0003 new columns on setup_codes
# ===================================================================


@RED_T8P2
@pytest.mark.pg
def test_setup_codes_has_used_at(pg_url, app_url, pg_roles):
    """setup_codes has a used_at column after 0003."""
    import psycopg
    ensure_at_head(pg_url)
    with psycopg.connect(_conninfo(pg_url)) as conn:
        require_t8p2(_column_exists(conn, "setup_codes", "used_at"),
                      "setup_codes.used_at column missing")


@RED_T8P2
@pytest.mark.pg
def test_setup_codes_has_failed_attempts(pg_url, app_url, pg_roles):
    """setup_codes has a failed_attempts column after 0003."""
    import psycopg
    ensure_at_head(pg_url)
    with psycopg.connect(_conninfo(pg_url)) as conn:
        require_t8p2(_column_exists(conn, "setup_codes", "failed_attempts"),
                      "setup_codes.failed_attempts column missing")


# ===================================================================
# 0003 new login_transactions table
# ===================================================================


@RED_T8P2
@pytest.mark.pg
def test_login_transactions_table_exists(pg_url, app_url, pg_roles):
    """login_transactions table exists after 0003."""
    import psycopg
    ensure_at_head(pg_url)
    with psycopg.connect(_conninfo(pg_url)) as conn:
        require_t8p2(_table_exists(conn, "login_transactions"),
                      "login_transactions table missing")


@RED_T8P2
@pytest.mark.pg
def test_login_transactions_rls_enabled_forced(pg_url, app_url, pg_roles):
    """login_transactions has RLS ENABLED + FORCED."""
    import psycopg
    ensure_at_head(pg_url)
    with psycopg.connect(_conninfo(pg_url)) as conn:
        require_t8p2(_table_exists(conn, "login_transactions"),
                      "login_transactions table missing")
        row = conn.execute(
            "SELECT relrowsecurity, relforcerowsecurity "
            "FROM pg_class WHERE relname = 'login_transactions'"
        ).fetchone()
        require_t8p2(row is not None, "login_transactions not found in pg_class")
        assert row[0] is True, "login_transactions: RLS not ENABLED"
        assert row[1] is True, "login_transactions: RLS not FORCED"


@RED_T8P2
@pytest.mark.pg
def test_login_transactions_has_policy(pg_url, app_url, pg_roles):
    """login_transactions has at least one RLS policy."""
    import psycopg
    ensure_at_head(pg_url)
    with psycopg.connect(_conninfo(pg_url)) as conn:
        require_t8p2(_table_exists(conn, "login_transactions"),
                      "login_transactions table missing")
        cnt = conn.execute(
            "SELECT count(*) FROM pg_policy p "
            "JOIN pg_class c ON p.polrelid = c.oid "
            "WHERE c.relname = 'login_transactions'"
        ).fetchone()[0]
        assert cnt > 0, "login_transactions: no RLS policies"


@RED_T8P2
@pytest.mark.pg
def test_login_transactions_owner_is_agg_owner(pg_url, app_url, pg_roles):
    """login_transactions is owned by agg_owner."""
    import psycopg
    ensure_at_head(pg_url)
    with psycopg.connect(_conninfo(pg_url)) as conn:
        require_t8p2(_table_exists(conn, "login_transactions"),
                      "login_transactions table missing")
        row = conn.execute(
            "SELECT r.rolname FROM pg_class c "
            "JOIN pg_roles r ON c.relowner = r.oid "
            "WHERE c.relname = 'login_transactions'"
        ).fetchone()
        assert row is not None
        assert row[0] == "agg_owner", (
            f"login_transactions owner is {row[0]}, expected agg_owner"
        )


@RED_T8P2
@pytest.mark.pg
def test_login_transactions_cross_org_isolation(pg_url, app_url, owner_url, pg_roles):
    """agg_app cannot see another org's login_transactions rows."""
    import psycopg
    ensure_at_head(pg_url)

    conninfo_owner = _conninfo(owner_url)
    conninfo_app = _conninfo(app_url)

    # First check that the table exists
    with psycopg.connect(_conninfo(pg_url)) as conn:
        require_t8p2(_table_exists(conn, "login_transactions"),
                      "login_transactions table missing")

    org_a = uuid.uuid4()
    org_b = uuid.uuid4()

    # Seed two orgs
    with psycopg.connect(conninfo_owner) as conn:
        for oid, slug in [(org_a, f"lt-a-{org_a.hex[:8]}"), (org_b, f"lt-b-{org_b.hex[:8]}")]:
            conn.execute(
                "SELECT set_config('app.org_id', %s, false)", [str(oid)]
            )
            conn.execute(
                "INSERT INTO orgs (id, org_id, name, slug, created_at) "
                "VALUES (%s, %s, %s, %s, now())",
                [oid, oid, f"Org {slug}", slug],
            )
            conn.commit()

    # Insert a login_transaction for org A via owner
    txn_id = uuid.uuid4()
    with psycopg.connect(conninfo_owner) as conn:
        conn.execute(
            "SELECT set_config('app.org_id', %s, false)", [str(org_a)]
        )
        conn.execute(
            "INSERT INTO login_transactions "
            "(id, org_id, state_hash, nonce, pkce_verifier, bootstrap, "
            "created_at, expires_at) "
            "VALUES (%s, %s, 'hash1', 'nonce1', 'verifier1', false, now(), "
            "now() + interval '10 min')",
            [txn_id, org_a],
        )
        conn.commit()

    # org B cannot see org A's row
    with psycopg.connect(conninfo_app) as conn:
        conn.execute(
            "SELECT set_config('app.org_id', %s, false)", [str(org_b)]
        )
        cnt = conn.execute(
            "SELECT count(*) FROM login_transactions"
        ).fetchone()[0]
        assert cnt == 0, (
            f"org B sees {cnt} login_transactions rows (should be 0)"
        )

    # org A can see its own row
    with psycopg.connect(conninfo_app) as conn:
        conn.execute(
            "SELECT set_config('app.org_id', %s, false)", [str(org_a)]
        )
        cnt = conn.execute(
            "SELECT count(*) FROM login_transactions"
        ).fetchone()[0]
        assert cnt >= 1, "org A should see its own login_transaction"


# ===================================================================
# Downgrade from 0003 to 0002
# ===================================================================


@RED_T8P2
@pytest.mark.pg
def test_downgrade_0003_removes_login_transactions(pg_url, pg_roles):
    """Downgrading from 0003 to 0002 removes login_transactions and new columns."""
    import psycopg
    ensure_at_head(pg_url)

    from agg_cp.db import alembic_config
    from alembic import command as alembic_cmd
    from alembic.script import ScriptDirectory

    cfg = alembic_config(pg_url)
    script = ScriptDirectory.from_config(cfg)

    # Verify we have at least 3 revisions (0001, 0002, 0003)
    revisions = list(script.walk_revisions())
    require_t8p2(len(revisions) >= 3,
                  f"Expected >= 3 revisions, got {len(revisions)}")

    # Downgrade to 0002
    alembic_cmd.downgrade(cfg, "000000000002")

    try:
        with psycopg.connect(_conninfo(pg_url)) as conn:
            # login_transactions should be gone
            assert not _table_exists(conn, "login_transactions"), (
                "login_transactions still exists after downgrade to 0002"
            )
            # new columns should be gone
            assert not _column_exists(conn, "web_sessions", "token_hash"), (
                "web_sessions.token_hash still exists after downgrade"
            )
            assert not _column_exists(conn, "web_sessions", "csrf_hash"), (
                "web_sessions.csrf_hash still exists after downgrade"
            )
            assert not _column_exists(conn, "web_sessions", "last_seen_at"), (
                "web_sessions.last_seen_at still exists after downgrade"
            )
            assert not _column_exists(conn, "web_sessions", "revoked_at"), (
                "web_sessions.revoked_at still exists after downgrade"
            )
            assert not _column_exists(conn, "setup_codes", "used_at"), (
                "setup_codes.used_at still exists after downgrade"
            )
            assert not _column_exists(conn, "setup_codes", "failed_attempts"), (
                "setup_codes.failed_attempts still exists after downgrade"
            )
    finally:
        # Restore to head
        alembic_cmd.upgrade(cfg, "head")
