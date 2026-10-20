"""M1 T7 tests-first: RLS catalog, visibility, pooled-connection safety.

Contract (M1_PLAN D5.1-3, ADR 0002 M1 amendments, SEC-07):

- Tables: orgs, org_oidc_config, projects, users, role_bindings,
  web_sessions, setup_codes, admin_audit.
- Roles: agg_owner (owns tables), agg_app (NOSUPERUSER, NOBYPASSRLS),
  agg_worker (NOLOGIN, no grants, reserved).
- Every tenant table: ENABLE + FORCE ROW LEVEL SECURITY.
- Org context: set_config('app.org_id', <uuid>, true) per transaction.
- Policies use NULLIF(current_setting('app.org_id', true), '')::uuid.
- SECURITY DEFINER function org_login_config: prosecdef, search_path
  pg_catalog+pg_temp, no PUBLIC execute, agg_app execute, owner not
  superuser.

Tests marked RED_T7 are strict xfail -- they fail before T7 migration
code exists.  The fix commit removes the decorator.
"""
from __future__ import annotations

import json
import uuid

import pytest

# ---------------------------------------------------------------------------
# Named exception for xfail (T6 pattern)
# ---------------------------------------------------------------------------


class T7Pending(Exception):
    """T7 tables / roles / RLS not built yet."""


def _require(cond: bool, msg: str) -> None:
    if not cond:
        raise T7Pending(msg)



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
    """Strip +psycopg for raw psycopg connect."""
    return url.replace("+psycopg", "")


def _ensure_at_head(pg_url: str) -> None:
    """Run alembic upgrade head (idempotent)."""
    from agg_cp.db import alembic_config
    from alembic import command as alembic_cmd

    cfg = alembic_config(pg_url)
    alembic_cmd.upgrade(cfg, "head")


def _check_tables(url: str) -> None:
    """Raise T7Pending if the 8 M1 tables are not all present."""
    import psycopg

    with psycopg.connect(_conninfo(url)) as conn:
        result = conn.execute(
            "SELECT array_agg(tablename) FROM pg_tables "
            "WHERE schemaname = 'public' AND tablename != 'alembic_version'"
        ).fetchone()[0]
        found = set(result) if result else set()
        missing = M1_TABLES - found
        _require(not missing, f"Missing T7 tables: {sorted(missing)}")


# Module-level seed cache (test-file scope; not production code).
_VIS: dict = {}


def _seed_two_orgs(owner_url: str) -> tuple:
    """Seed 2 orgs with one row in every tenant table via agg_owner.

    Returns (org_a_id, org_b_id).  Cached per module.
    Raises T7Pending if tables / columns are missing.
    """
    if _VIS:
        return _VIS["a"], _VIS["b"]

    import psycopg

    org_a = uuid.uuid4()
    org_b = uuid.uuid4()

    conninfo = _conninfo(owner_url)

    try:
        # Check if data from a prior run already exists (idempotent seeding)
        with psycopg.connect(conninfo) as conn:
            existing_a = conn.execute(
                "SELECT id FROM orgs WHERE slug = 'org-a-rls'",
            ).fetchone()
            existing_b = conn.execute(
                "SELECT id FROM orgs WHERE slug = 'org-b-rls'",
            ).fetchone()
        if existing_a and existing_b:
            _VIS["a"] = existing_a[0]
            _VIS["b"] = existing_b[0]
            return _VIS["a"], _VIS["b"]

        for org_id, slug in [(org_a, "org-a-rls"), (org_b, "org-b-rls")]:
            with psycopg.connect(conninfo) as conn:
                conn.execute(
                    "SELECT set_config('app.org_id', %s, false)",
                    [str(org_id)],
                )
                user_id = uuid.uuid4()
                proj_id = uuid.uuid4()

                conn.execute(
                    "INSERT INTO orgs (id, org_id, name, slug, created_at) "
                    "VALUES (%s, %s, %s, %s, now())",
                    [org_id, org_id, f"Org {slug}", slug],
                )
                conn.execute(
                    "INSERT INTO org_oidc_config "
                    "(id, org_id, issuer, client_id, created_at) "
                    "VALUES (%s, %s, %s, %s, now())",
                    [
                        uuid.uuid4(),
                        org_id,
                        f"https://idp.example.com/{slug}",
                        f"client-{slug}",
                    ],
                )
                conn.execute(
                    "INSERT INTO projects "
                    "(id, org_id, name, environment, created_at) "
                    "VALUES (%s, %s, %s, %s, now())",
                    [proj_id, org_id, "TestProject", "dev"],
                )
                conn.execute(
                    "INSERT INTO users "
                    "(id, org_id, oidc_issuer, oidc_subject, "
                    "email, status, created_at) "
                    "VALUES (%s, %s, %s, %s, %s, %s, now())",
                    [
                        user_id,
                        org_id,
                        f"https://idp/{slug}",
                        f"sub-{slug}",
                        f"u@{slug}.example",
                        "active",
                    ],
                )
                conn.execute(
                    "INSERT INTO role_bindings "
                    "(id, org_id, user_id, scope_type, scope_id, "
                    "role, created_at) "
                    "VALUES (%s, %s, %s, %s, %s, %s, now())",
                    [uuid.uuid4(), org_id, user_id, "org", org_id, "admin"],
                )
                conn.execute(
                    "INSERT INTO web_sessions "
                    "(id, org_id, user_id, token_hash, csrf_hash, "
                    "last_seen_at, created_at, expires_at) "
                    "VALUES (%s, %s, %s, %s, %s, now(), now(), "
                    "now() + interval '1 hour')",
                    [uuid.uuid4(), org_id, user_id,
                     uuid.uuid4().hex, uuid.uuid4().hex],
                )
                conn.execute(
                    "INSERT INTO setup_codes "
                    "(id, org_id, code_hash, created_at, expires_at) "
                    "VALUES (%s, %s, %s, now(), now() + interval '30 min')",
                    [uuid.uuid4(), org_id, f"hash-{slug}"],
                )
                conn.execute(
                    "INSERT INTO admin_audit "
                    "(id, org_id, action, detail) "
                    "VALUES (%s, %s, %s, %s::jsonb)",
                    [
                        uuid.uuid4(),
                        org_id,
                        "test.seed",
                        json.dumps({"seeded": True}),
                    ],
                )
                conn.commit()
    except Exception as exc:
        raise T7Pending(f"Cannot seed orgs: {exc}") from exc

    _VIS["a"] = org_a
    _VIS["b"] = org_b
    return org_a, org_b


# ===================================================================
# Guards (pass now, before T7 code)
# ===================================================================


@pytest.mark.pg
def test_guard_agg_app_connection(app_url):
    """Guard: test connection is agg_app with rolsuper=false,
    rolbypassrls=false.  Passes now (roles created by fixture)."""
    import psycopg

    with psycopg.connect(_conninfo(app_url)) as conn:
        user = conn.execute("SELECT current_user").fetchone()[0]
        assert user == "agg_app", f"Expected agg_app, got {user}"
        row = conn.execute(
            "SELECT rolsuper, rolbypassrls FROM pg_roles "
            "WHERE rolname = 'agg_app'"
        ).fetchone()
        assert row is not None, "agg_app role not found in pg_roles"
        assert row[0] is False, "agg_app must not be superuser"
        assert row[1] is False, "agg_app must not have BYPASSRLS"


@pytest.mark.pg
def test_guard_agg_worker_nologin(pg_url):
    """Guard: agg_worker exists and is NOLOGIN."""
    import psycopg

    with psycopg.connect(_conninfo(pg_url)) as conn:
        row = conn.execute(
            "SELECT rolcanlogin FROM pg_roles WHERE rolname = 'agg_worker'"
        ).fetchone()
        assert row is not None, "agg_worker role not found"
        assert row[0] is False, "agg_worker must be NOLOGIN"


# ===================================================================
# 1. RLS catalog (generic over every table in public)
# ===================================================================


@pytest.mark.pg
def test_rls_enabled_and_forced(pg_url, app_url, pg_roles):
    """Every table in public (except alembic_version) has RLS enabled
    AND forced."""
    _ensure_at_head(pg_url)
    _check_tables(pg_url)

    import psycopg

    with psycopg.connect(_conninfo(app_url)) as conn:
        rows = conn.execute(
            "SELECT relname, relrowsecurity, relforcerowsecurity "
            "FROM pg_class c "
            "JOIN pg_namespace n ON c.relnamespace = n.oid "
            "WHERE n.nspname = 'public' AND c.relkind = 'r' "
            "AND c.relname != 'alembic_version' "
            "ORDER BY relname"
        ).fetchall()
        assert len(rows) >= len(M1_TABLES), (
            f"Expected >= {len(M1_TABLES)} tables, found {len(rows)}"
        )
        for relname, rls_on, rls_forced in rows:
            assert rls_on, f"{relname}: RLS not ENABLED"
            assert rls_forced, f"{relname}: RLS not FORCED"


@pytest.mark.pg
def test_table_owner_is_agg_owner(pg_url, app_url, pg_roles):
    """Every table is owned by agg_owner, not agg_app."""
    _ensure_at_head(pg_url)
    _check_tables(pg_url)

    import psycopg

    with psycopg.connect(_conninfo(app_url)) as conn:
        rows = conn.execute(
            "SELECT c.relname, r.rolname AS owner "
            "FROM pg_class c "
            "JOIN pg_namespace n ON c.relnamespace = n.oid "
            "JOIN pg_roles r ON c.relowner = r.oid "
            "WHERE n.nspname = 'public' AND c.relkind = 'r' "
            "AND c.relname != 'alembic_version' "
            "ORDER BY c.relname"
        ).fetchall()
        for relname, owner in rows:
            assert owner == "agg_owner", (
                f"{relname}: owner is {owner}, expected agg_owner"
            )


@pytest.mark.pg
def test_every_table_has_at_least_one_policy(pg_url, app_url, pg_roles):
    """Every table has at least one RLS policy."""
    _ensure_at_head(pg_url)
    _check_tables(pg_url)

    import psycopg

    with psycopg.connect(_conninfo(app_url)) as conn:
        tables = conn.execute(
            "SELECT tablename FROM pg_tables "
            "WHERE schemaname = 'public' AND tablename != 'alembic_version' "
            "ORDER BY tablename"
        ).fetchall()
        for (tablename,) in tables:
            cnt = conn.execute(
                "SELECT count(*) FROM pg_policy p "
                "JOIN pg_class c ON p.polrelid = c.oid "
                "WHERE c.relname = %s",
                [tablename],
            ).fetchone()[0]
            assert cnt > 0, f"{tablename}: no RLS policies found"


# ===================================================================
# 1b. SECURITY DEFINER function catalog (org_login_config)
# ===================================================================


@pytest.mark.pg
def test_secdef_prosecdef(pg_url, app_url, pg_roles):
    """org_login_config is SECURITY DEFINER."""
    _ensure_at_head(pg_url)
    _check_tables(pg_url)

    import psycopg

    with psycopg.connect(_conninfo(app_url)) as conn:
        row = conn.execute(
            "SELECT prosecdef FROM pg_proc "
            "WHERE proname = 'org_login_config'"
        ).fetchone()
        _require(row is not None, "Function org_login_config not found")
        assert row[0] is True, "org_login_config must be SECURITY DEFINER"


@pytest.mark.pg
def test_secdef_search_path(pg_url, app_url, pg_roles):
    """org_login_config has SET search_path = pg_catalog, pg_temp."""
    _ensure_at_head(pg_url)
    _check_tables(pg_url)

    import psycopg

    with psycopg.connect(_conninfo(app_url)) as conn:
        row = conn.execute(
            "SELECT proconfig FROM pg_proc "
            "WHERE proname = 'org_login_config'"
        ).fetchone()
        _require(row is not None, "Function org_login_config not found")
        config = row[0]
        _require(config is not None, "org_login_config has no proconfig")
        sp_entries = [c for c in config if c.startswith("search_path=")]
        assert len(sp_entries) > 0, "No search_path in proconfig"
        sp_value = sp_entries[0].split("=", 1)[1].replace(" ", "")
        assert sp_value == "pg_catalog,pg_temp", (
            f"search_path is '{sp_value}', expected 'pg_catalog,pg_temp'"
        )


@pytest.mark.pg
def test_secdef_no_public_execute(pg_url, app_url, pg_roles):
    """EXECUTE on org_login_config is revoked from PUBLIC."""
    _ensure_at_head(pg_url)
    _check_tables(pg_url)

    import psycopg

    with psycopg.connect(_conninfo(app_url)) as conn:
        row = conn.execute(
            "SELECT proacl FROM pg_proc "
            "WHERE proname = 'org_login_config'"
        ).fetchone()
        _require(row is not None, "Function org_login_config not found")
        acl = row[0]
        # NULL ACL means default (PUBLIC has EXECUTE) -- must not be NULL
        _require(
            acl is not None,
            "org_login_config has NULL ACL (default = PUBLIC execute)",
        )
        # psycopg 3 returns aclitem[] as a Python list of strings
        acl_list = acl if isinstance(acl, list) else str(acl).strip("{}").split(",")
        # In PG ACL format, PUBLIC execute appears as "=X/owner"
        for entry in acl_list:
            entry = entry.strip()
            if "=" not in entry:
                continue
            grantee, privs_owner = entry.split("=", 1)
            privs = privs_owner.split("/")[0]
            if grantee == "" and "X" in privs:
                pytest.fail(
                    f"PUBLIC still has EXECUTE on org_login_config: {acl}"
                )


@pytest.mark.pg
def test_secdef_agg_app_execute(pg_url, app_url, pg_roles):
    """agg_app has EXECUTE on org_login_config."""
    _ensure_at_head(pg_url)
    _check_tables(pg_url)

    import psycopg

    with psycopg.connect(_conninfo(app_url)) as conn:
        row = conn.execute(
            "SELECT proacl FROM pg_proc "
            "WHERE proname = 'org_login_config'"
        ).fetchone()
        _require(row is not None, "Function org_login_config not found")
        acl = row[0]
        _require(acl is not None, "org_login_config has NULL ACL")
        # psycopg 3 returns aclitem[] as a Python list of strings
        acl_list = acl if isinstance(acl, list) else str(acl).strip("{}").split(",")
        # Look for "agg_app=X/..." in the ACL list
        found = False
        for entry in acl_list:
            entry = entry.strip()
            if entry.startswith("agg_app=") and "X" in entry.split("=")[1].split("/")[0]:
                found = True
                break
        assert found, (
            f"agg_app does not have EXECUTE on org_login_config: {acl}"
        )


@pytest.mark.pg
def test_secdef_owner_not_superuser(pg_url, app_url, pg_roles):
    """Owner of org_login_config is not a superuser."""
    _ensure_at_head(pg_url)
    _check_tables(pg_url)

    import psycopg

    with psycopg.connect(_conninfo(app_url)) as conn:
        row = conn.execute(
            "SELECT r.rolsuper "
            "FROM pg_proc p "
            "JOIN pg_roles r ON p.proowner = r.oid "
            "WHERE p.proname = 'org_login_config'"
        ).fetchone()
        _require(row is not None, "Function org_login_config not found")
        assert row[0] is False, (
            "Owner of org_login_config must not be a superuser"
        )


# ===================================================================
# 2. Zero rows / visibility with positive controls
# ===================================================================


@pytest.mark.pg
def test_visibility_org_a_sees_own(pg_url, app_url, owner_url, pg_roles):
    """Org A with app.org_id set sees only A's rows (count > 0)."""
    _ensure_at_head(pg_url)
    _check_tables(pg_url)
    org_a, _org_b = _seed_two_orgs(owner_url)

    import psycopg

    tables = sorted(M1_TABLES)
    with psycopg.connect(_conninfo(app_url)) as conn:
        conn.execute(
            "SELECT set_config('app.org_id', %s, false)", [str(org_a)]
        )
        for tbl in tables:
            cnt = conn.execute(f"SELECT count(*) FROM {tbl}").fetchone()[0]  # noqa: S608
            assert cnt > 0, (
                f"{tbl}: org A sees 0 rows with org set (positive control)"
            )


@pytest.mark.pg
def test_visibility_org_unset_zero(pg_url, app_url, owner_url, pg_roles):
    """With no org set, agg_app sees 0 rows in every table."""
    _ensure_at_head(pg_url)
    _check_tables(pg_url)
    _seed_two_orgs(owner_url)  # ensure data exists

    import psycopg

    tables = sorted(M1_TABLES)
    with psycopg.connect(_conninfo(app_url)) as conn:
        # Do NOT set app.org_id
        for tbl in tables:
            cnt = conn.execute(f"SELECT count(*) FROM {tbl}").fetchone()[0]  # noqa: S608
            assert cnt == 0, (
                f"{tbl}: org unset should see 0 rows, got {cnt}"
            )


@pytest.mark.pg
def test_visibility_org_empty_zero(pg_url, app_url, owner_url, pg_roles):
    """With org set to '' (empty string), agg_app sees 0 rows (no error)."""
    _ensure_at_head(pg_url)
    _check_tables(pg_url)
    _seed_two_orgs(owner_url)

    import psycopg

    tables = sorted(M1_TABLES)
    with psycopg.connect(_conninfo(app_url)) as conn:
        conn.execute(
            "SELECT set_config('app.org_id', '', false)"
        )
        for tbl in tables:
            cnt = conn.execute(f"SELECT count(*) FROM {tbl}").fetchone()[0]  # noqa: S608
            assert cnt == 0, (
                f"{tbl}: org='' should see 0 rows, got {cnt}"
            )


@pytest.mark.pg
def test_visibility_org_b_never_sees_a(pg_url, app_url, owner_url, pg_roles):
    """Org B never sees org A's rows."""
    _ensure_at_head(pg_url)
    _check_tables(pg_url)
    org_a, org_b = _seed_two_orgs(owner_url)

    import psycopg

    tables = sorted(M1_TABLES)
    with psycopg.connect(_conninfo(app_url)) as conn:
        # Set org to B
        conn.execute(
            "SELECT set_config('app.org_id', %s, false)", [str(org_b)]
        )
        for tbl in tables:
            # B should see its own rows, but none of A's
            rows = conn.execute(
                f"SELECT org_id FROM {tbl}"  # noqa: S608
            ).fetchall()
            for (oid,) in rows:
                assert str(oid) != str(org_a), (
                    f"{tbl}: org B sees org A's row (org_id={oid})"
                )


@pytest.mark.pg
def test_insert_wrong_org_refused(pg_url, app_url, owner_url, pg_roles):
    """INSERT with another org's id is refused by WITH CHECK policy."""
    _ensure_at_head(pg_url)
    _check_tables(pg_url)
    org_a, org_b = _seed_two_orgs(owner_url)

    import psycopg

    with psycopg.connect(_conninfo(app_url)) as conn:
        conn.autocommit = False
        # Set context to org A
        conn.execute(
            "SELECT set_config('app.org_id', %s, true)", [str(org_a)]
        )
        # Try inserting a row with org B's id -- should be refused
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute(
                "INSERT INTO projects "
                "(id, org_id, name, environment, created_at) "
                "VALUES (%s, %s, 'Evil', 'dev', now())",
                [uuid.uuid4(), org_b],
            )
        conn.rollback()


# ===================================================================
# 3. Pooled connection: org context must not leak
# ===================================================================


@pytest.mark.pg
def test_pooled_no_leak(pg_url, app_url, owner_url, pg_roles):
    """A pooled connection does not leak org context between txns.

    One SQLAlchemy engine, pool_size=1.  Transaction 1 sets org A and
    reads.  Transaction 2 on the same backend pid (same pooled conn)
    without setting org sees 0 rows.
    """
    _ensure_at_head(pg_url)
    _check_tables(pg_url)
    org_a, _org_b = _seed_two_orgs(owner_url)

    from sqlalchemy import create_engine, text

    engine = create_engine(app_url, pool_size=1, max_overflow=0)
    try:
        # Txn 1: set org, read, get pid
        with engine.connect() as conn1:
            conn1.execute(
                text("SELECT set_config('app.org_id', :org, true)"),
                {"org": str(org_a)},
            )
            pid1 = conn1.execute(text("SELECT pg_backend_pid()")).scalar()
            cnt1 = conn1.execute(text("SELECT count(*) FROM orgs")).scalar()
            assert cnt1 > 0, "Txn 1 should see org A's rows"
            conn1.commit()

        # Txn 2: no org set, verify same pid, expect 0 rows
        with engine.connect() as conn2:
            pid2 = conn2.execute(text("SELECT pg_backend_pid()")).scalar()
            assert pid1 == pid2, (
                f"Expected same pooled conn: pid {pid1} vs {pid2}"
            )
            cnt2 = conn2.execute(text("SELECT count(*) FROM orgs")).scalar()
            assert cnt2 == 0, (
                f"Txn 2 (no org) should see 0 rows, got {cnt2}"
            )
            conn2.commit()
    finally:
        engine.dispose()
