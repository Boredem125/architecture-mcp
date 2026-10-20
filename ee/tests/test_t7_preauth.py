"""M1 T7 tests-first: pre-auth function and migration downgrade.

Contract (M1_PLAN D5.2 amendment 3, ADR 0002):

- ``org_login_config(slug text)`` returns ``(org_id, issuer, client_id)``
  for a known slug, nothing for an unknown slug.
- agg_app with no org set can call the function (it is SECURITY DEFINER)
  but cannot SELECT org_oidc_config directly (0 rows via RLS).
- Downgrade of the T7 revision removes its tables, roles' grants and
  the function.

Tests marked RED_T7 are strict xfail before T7 migration code exists.
"""
from __future__ import annotations

import uuid

import pytest

# ---------------------------------------------------------------------------
# Named exception
# ---------------------------------------------------------------------------


class T7Pending(Exception):
    """T7 tables / roles / RLS not built yet."""


def _require(cond: bool, msg: str) -> None:
    if not cond:
        raise T7Pending(msg)


RED_T7 = pytest.mark.xfail(
    raises=(T7Pending,),
    strict=True,
    reason="M1 T7: pre-auth function / migration not yet built",
)

M1_TABLES = frozenset(
    {
        "orgs",
        "org_oidc_config",
        "projects",
        "users",
        "role_bindings",
        "web_sessions",
        "setup_codes",
        "admin_audit",
    }
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _conninfo(url: str) -> str:
    return url.replace("+psycopg", "")


def _ensure_at_head(pg_url: str) -> None:
    from agg_cp.db import alembic_config
    from alembic import command as alembic_cmd

    cfg = alembic_config(pg_url)
    alembic_cmd.upgrade(cfg, "head")


def _check_tables(url: str) -> None:
    import psycopg

    with psycopg.connect(_conninfo(url)) as conn:
        result = conn.execute(
            "SELECT array_agg(tablename) FROM pg_tables "
            "WHERE schemaname = 'public' AND tablename != 'alembic_version'"
        ).fetchone()[0]
        found = set(result) if result else set()
        missing = M1_TABLES - found
        _require(not missing, f"Missing T7 tables: {sorted(missing)}")


# Seed cache
_PA: dict = {}


def _seed_preauth(owner_url: str) -> tuple:
    """Seed one org with OIDC config for pre-auth testing.

    Returns (org_id, slug, issuer, client_id).
    """
    if _PA:
        return _PA["org_id"], _PA["slug"], _PA["issuer"], _PA["client_id"]

    import psycopg

    org_id = uuid.uuid4()
    slug = "preauth-org"
    issuer = "https://idp.example.com/preauth"
    client_id = "client-preauth-123"

    conninfo = _conninfo(owner_url)
    try:
        with psycopg.connect(conninfo) as conn:
            conn.execute(
                "SELECT set_config('app.org_id', %s, false)",
                [str(org_id)],
            )
            conn.execute(
                "INSERT INTO orgs (id, org_id, name, slug, created_at) "
                "VALUES (%s, %s, 'PreauthOrg', %s, now())",
                [org_id, org_id, slug],
            )
            conn.execute(
                "INSERT INTO org_oidc_config "
                "(id, org_id, issuer, client_id, created_at) "
                "VALUES (%s, %s, %s, %s, now())",
                [uuid.uuid4(), org_id, issuer, client_id],
            )
            conn.commit()
    except Exception as exc:
        raise T7Pending(f"Cannot seed preauth data: {exc}") from exc

    _PA.update(org_id=org_id, slug=slug, issuer=issuer, client_id=client_id)
    return org_id, slug, issuer, client_id


# ===================================================================
# 5. Pre-auth function
# ===================================================================


@RED_T7
@pytest.mark.pg
def test_preauth_known_slug(pg_url, app_url, owner_url, pg_roles):
    """agg_app (no org set) calls org_login_config(slug) and gets
    exactly (org_id, issuer, client_id)."""
    _ensure_at_head(pg_url)
    _check_tables(pg_url)
    org_id, slug, issuer, client_id = _seed_preauth(owner_url)

    import psycopg

    with psycopg.connect(_conninfo(app_url)) as conn:
        # Explicitly do NOT set app.org_id
        row = conn.execute(
            "SELECT * FROM org_login_config(%s)", [slug]
        ).fetchone()
        assert row is not None, f"org_login_config('{slug}') returned nothing"
        # The function returns (org_id, issuer, client_id)
        assert str(row[0]) == str(org_id), (
            f"org_id mismatch: {row[0]} != {org_id}"
        )
        assert row[1] == issuer, f"issuer mismatch: {row[1]} != {issuer}"
        assert row[2] == client_id, (
            f"client_id mismatch: {row[2]} != {client_id}"
        )


@RED_T7
@pytest.mark.pg
def test_preauth_unknown_slug(pg_url, app_url, owner_url, pg_roles):
    """org_login_config for an unknown slug returns nothing."""
    _ensure_at_head(pg_url)
    _check_tables(pg_url)
    _seed_preauth(owner_url)  # ensure function exists

    import psycopg

    with psycopg.connect(_conninfo(app_url)) as conn:
        row = conn.execute(
            "SELECT * FROM org_login_config(%s)",
            ["nonexistent-slug-xyz"],
        ).fetchone()
        assert row is None, (
            f"org_login_config('nonexistent-slug-xyz') should return "
            f"nothing, got {row}"
        )


@RED_T7
@pytest.mark.pg
def test_preauth_no_direct_oidc(pg_url, app_url, owner_url, pg_roles):
    """agg_app with no org set cannot SELECT org_oidc_config directly
    (0 rows via RLS)."""
    _ensure_at_head(pg_url)
    _check_tables(pg_url)
    _seed_preauth(owner_url)  # ensure data exists

    import psycopg

    with psycopg.connect(_conninfo(app_url)) as conn:
        # Do NOT set app.org_id
        cnt = conn.execute(
            "SELECT count(*) FROM org_oidc_config"
        ).fetchone()[0]
        assert cnt == 0, (
            f"agg_app with no org set should see 0 rows in "
            f"org_oidc_config, got {cnt}"
        )


# ===================================================================
# 6. Migration downgrade
# ===================================================================


@RED_T7
@pytest.mark.pg
def test_downgrade_removes_objects(pg_url, pg_roles):
    """Downgrading the T7 revision removes its tables, roles' grants,
    and the function."""
    _ensure_at_head(pg_url)
    _check_tables(pg_url)

    from agg_cp.db import alembic_config
    from alembic import command as alembic_cmd
    from alembic.script import ScriptDirectory

    cfg = alembic_config(pg_url)
    script = ScriptDirectory.from_config(cfg)

    revisions = list(script.walk_revisions())
    _require(
        len(revisions) > 1,
        "Only baseline revision exists (T7 migration not added)",
    )

    # Downgrade one step from head to the prior revision
    head_id = script.get_current_head()
    head_rev = script.get_revision(head_id)
    prev_rev = head_rev.down_revision
    _require(prev_rev is not None, "Head revision has no down_revision")

    alembic_cmd.downgrade(cfg, prev_rev)

    import psycopg

    try:
        with psycopg.connect(_conninfo(pg_url)) as conn:
            # Tables should be gone
            result = conn.execute(
                "SELECT array_agg(tablename) FROM pg_tables "
                "WHERE schemaname = 'public' "
                "AND tablename != 'alembic_version'"
            ).fetchone()[0]
            found = set(result) if result else set()
            remaining = found & M1_TABLES
            assert not remaining, (
                f"T7 tables still exist after downgrade: {sorted(remaining)}"
            )

            # Function should be gone
            func_cnt = conn.execute(
                "SELECT count(*) FROM pg_proc p "
                "JOIN pg_namespace n ON p.pronamespace = n.oid "
                "WHERE n.nspname = 'public' "
                "AND p.proname = 'org_login_config'"
            ).fetchone()[0]
            assert func_cnt == 0, (
                "org_login_config still exists after downgrade"
            )

            # agg_app should have no grants on public tables
            grants = conn.execute(
                "SELECT count(*) FROM information_schema.table_privileges "
                "WHERE grantee = 'agg_app' AND table_schema = 'public'"
            ).fetchone()[0]
            assert grants == 0, (
                f"agg_app still has {grants} grants after downgrade"
            )
    finally:
        # Restore to head for any subsequent tests
        alembic_cmd.upgrade(cfg, "head")
