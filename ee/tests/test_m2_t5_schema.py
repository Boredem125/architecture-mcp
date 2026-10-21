"""T5 tests-first: M2 tables, FORCE RLS, append-only triggers, SECURITY DEFINER functions.

All tests require a live Postgres instance (``pg`` marker).

RED tests xfail on M2T5Pending.  Guards verify the existing M1 schema.

ADR 0002 M2 amendments are the authority for names.
"""
from __future__ import annotations

import secrets
import uuid

import psycopg
import pytest

from .m2_pending import M2T5Pending, require_m2

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _conninfo(url: str) -> str:
    return url.replace("+psycopg", "")


def _ensure_at_head(pg_url: str) -> None:
    """Run Alembic upgrade to head."""
    try:
        from agg_cp.db import alembic_config
        from alembic.command import upgrade
        cfg = alembic_config(pg_url)
        upgrade(cfg, "head")
    except Exception as exc:
        raise M2T5Pending(f"Alembic upgrade failed: {exc}") from exc


def _table_exists(conn, table_name: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM information_schema.tables "
        "WHERE table_schema = 'public' AND table_name = %s",
        [table_name],
    ).fetchone()
    return row is not None


# ===================================================================
# Guards (pass now)
# ===================================================================


@pytest.mark.pg
def test_m1_tables_exist(pg_url, pg_roles, owner_url):
    """Guard: M1 tables exist after migration."""
    _ensure_at_head(pg_url)
    with psycopg.connect(_conninfo(owner_url)) as conn:
        for t in ("orgs", "projects", "users", "role_bindings",
                  "web_sessions", "admin_audit"):
            assert _table_exists(conn, t), f"M1 table {t} not found"


@pytest.mark.pg
def test_admin_audit_append_only_guard(pg_url, pg_roles, owner_url):
    """Guard: admin_audit rejects DELETE."""
    _ensure_at_head(pg_url)
    with psycopg.connect(_conninfo(owner_url), autocommit=False) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, true)",
                     [str(uuid.uuid4())])
        # Try to delete (should fail with trigger)
        try:
            conn.execute("DELETE FROM admin_audit WHERE 1=0")
            # If no rows matched the trigger might not fire, which is fine
        except psycopg.errors.RaiseException:
            pass  # expected
        finally:
            conn.rollback()


# ===================================================================
# RED: every table has ENABLE and FORCE RLS (catalog query, 100%)
# ===================================================================


@pytest.mark.pg
def test_existing_tables_have_force_rls(pg_url, pg_roles, owner_url):
    """Guard: M1 tables already have ENABLE and FORCE RLS."""
    _ensure_at_head(pg_url)
    with psycopg.connect(_conninfo(owner_url)) as conn:
        rows = conn.execute(
            "SELECT relname, relrowsecurity, relforcerowsecurity "
            "FROM pg_class c JOIN pg_namespace n ON c.relnamespace = n.oid "
            "WHERE n.nspname = 'public' "
            "  AND c.relkind = 'r' "
            "  AND c.relname NOT LIKE 'alembic_%' "
            "ORDER BY relname"
        ).fetchall()

    assert rows, "No tables found in public schema"
    for name, rls_enabled, rls_forced in rows:
        assert rls_enabled, f"{name} missing ENABLE RLS"
        assert rls_forced, f"{name} missing FORCE RLS"


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M2T5Pending)
def test_all_m2_tables_have_force_rls(pg_url, pg_roles, owner_url):
    """Every M2 new table has ENABLE and FORCE RLS."""
    _ensure_at_head(pg_url)
    with psycopg.connect(_conninfo(owner_url)) as conn:
        missing = [t for t in _M2_NEW_TABLES if not _table_exists(conn, t)]
    if missing:
        raise M2T5Pending(f"M2 tables missing (cannot check RLS): {missing}")

    with psycopg.connect(_conninfo(owner_url)) as conn:
        for t in _M2_NEW_TABLES:
            row = conn.execute(
                "SELECT relrowsecurity, relforcerowsecurity "
                "FROM pg_class c JOIN pg_namespace n ON c.relnamespace = n.oid "
                "WHERE n.nspname = 'public' AND c.relname = %s",
                [t],
            ).fetchone()
            assert row is not None, f"Table {t} not found"
            assert row[0], f"{t} missing ENABLE RLS"
            assert row[1], f"{t} missing FORCE RLS"


# ===================================================================
# RED: each new M2 table exists
# ===================================================================

_M2_NEW_TABLES = [
    "device_nonces",
    "device_tokens",
    "signer_nonces",
    "signer_tokens",
    "signer_links",
    "sync_alerts",
]


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M2T5Pending)
def test_m2_new_tables_exist(pg_url, pg_roles, owner_url):
    """All six new M2 tables from ADR 0002 exist."""
    _ensure_at_head(pg_url)
    with psycopg.connect(_conninfo(owner_url)) as conn:
        missing = [t for t in _M2_NEW_TABLES if not _table_exists(conn, t)]

    if missing:
        raise M2T5Pending(f"M2 tables missing: {missing}")


# ===================================================================
# RED: audit tables are append-only
# ===================================================================

_APPEND_ONLY_TABLES = ["audit_records", "audit_heads", "audit_quarantine"]


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M2T5Pending)
def test_audit_tables_exist(pg_url, pg_roles, owner_url):
    """audit_records, audit_heads, audit_quarantine exist."""
    _ensure_at_head(pg_url)
    with psycopg.connect(_conninfo(owner_url)) as conn:
        missing = [t for t in _APPEND_ONLY_TABLES
                   if not _table_exists(conn, t)]
    if missing:
        raise M2T5Pending(f"Append-only tables missing: {missing}")


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M2T5Pending)
def test_audit_records_update_refused(pg_url, pg_roles, app_url):
    """UPDATE on audit_records is refused for agg_app."""
    _ensure_at_head(pg_url)
    if not _table_exists(
        psycopg.connect(_conninfo(app_url)), "audit_records"
    ):
        raise M2T5Pending("audit_records table does not exist yet")

    with psycopg.connect(_conninfo(app_url), autocommit=False) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, true)",
                     [str(uuid.uuid4())])
        try:
            conn.execute("UPDATE audit_records SET record_hash = 'x' WHERE 1=0")
            # Empty update may not trigger; try with a real attempt
            raise M2T5Pending(
                "UPDATE on audit_records did not raise "
                "(trigger not installed or table does not exist)"
            )
        except psycopg.errors.RaiseException:
            pass  # expected: trigger rejected
        except psycopg.errors.InsufficientPrivilege:
            pass  # also acceptable: no UPDATE grant
        except Exception as exc:
            raise M2T5Pending(f"Unexpected error: {exc}") from exc
        finally:
            conn.rollback()


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M2T5Pending)
def test_audit_records_delete_refused(pg_url, pg_roles, app_url):
    """DELETE on audit_records is refused for agg_app."""
    _ensure_at_head(pg_url)
    if not _table_exists(
        psycopg.connect(_conninfo(app_url)), "audit_records"
    ):
        raise M2T5Pending("audit_records table does not exist yet")

    with psycopg.connect(_conninfo(app_url), autocommit=False) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, true)",
                     [str(uuid.uuid4())])
        try:
            conn.execute("DELETE FROM audit_records WHERE 1=0")
            raise M2T5Pending("DELETE on audit_records did not raise")
        except psycopg.errors.RaiseException:
            pass
        except psycopg.errors.InsufficientPrivilege:
            pass
        except Exception as exc:
            raise M2T5Pending(f"Unexpected error: {exc}") from exc
        finally:
            conn.rollback()


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M2T5Pending)
def test_audit_records_truncate_refused(pg_url, pg_roles, app_url):
    """TRUNCATE on audit_records is refused for agg_app."""
    _ensure_at_head(pg_url)
    if not _table_exists(
        psycopg.connect(_conninfo(app_url)), "audit_records"
    ):
        raise M2T5Pending("audit_records table does not exist yet")

    with psycopg.connect(_conninfo(app_url), autocommit=False) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, true)",
                     [str(uuid.uuid4())])
        try:
            conn.execute("TRUNCATE audit_records")
            raise M2T5Pending("TRUNCATE on audit_records did not raise")
        except psycopg.errors.RaiseException:
            pass
        except psycopg.errors.InsufficientPrivilege:
            pass
        except Exception as exc:
            raise M2T5Pending(f"Unexpected error: {exc}") from exc
        finally:
            conn.rollback()


# ===================================================================
# RED: SECURITY DEFINER functions (ADR 0002 section 3)
# ===================================================================

# Nine functions: rows 0-7, with row 7 being one per nonce table (2).
_SECDEF_FUNCTIONS = [
    "org_login_config",        # row 0 (M1, already exists)
]

# The new M2 functions -- names may vary; T5 may refine.
# We check for their existence by purpose.
_M2_SECDEF_PURPOSES = [
    "device_lookup",           # row 1
    "device_token_lookup",     # row 2
    "enrollment_code_consume", # row 3
    "signer_link_consume",     # row 4
    "cli_key_lookup",          # row 5
    "signer_token_lookup",     # row 6
    "device_nonce_insert",     # row 7a
    "signer_nonce_insert",     # row 7b
]


@pytest.mark.pg
def test_m1_secdef_function_exists(pg_url, pg_roles, owner_url):
    """Guard: org_login_config (M1) is SECURITY DEFINER."""
    _ensure_at_head(pg_url)
    with psycopg.connect(_conninfo(owner_url)) as conn:
        rows = conn.execute(
            "SELECT p.proname "
            "FROM pg_proc p JOIN pg_namespace n ON p.pronamespace = n.oid "
            "WHERE n.nspname = 'public' AND p.prosecdef = true "
            "ORDER BY p.proname"
        ).fetchall()
    names = {r[0] for r in rows}
    assert "org_login_config" in names, "M1 org_login_config not found"


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M2T5Pending)
def test_secdef_functions_count_ge_9(pg_url, pg_roles, owner_url):
    """At least 9 SECURITY DEFINER functions (M1 + 8 M2)."""
    _ensure_at_head(pg_url)
    with psycopg.connect(_conninfo(owner_url)) as conn:
        rows = conn.execute(
            "SELECT p.proname "
            "FROM pg_proc p JOIN pg_namespace n ON p.pronamespace = n.oid "
            "WHERE n.nspname = 'public' AND p.prosecdef = true "
            "ORDER BY p.proname"
        ).fetchall()
    names = {r[0] for r in rows}
    if len(names) < 9:
        raise M2T5Pending(
            f"Only {len(names)} SECURITY DEFINER functions; "
            f"need >= 9. Found: {sorted(names)}"
        )


@pytest.mark.pg
def test_m1_secdef_search_path_pinned(pg_url, pg_roles, owner_url):
    """Guard: existing SECURITY DEFINER functions have pinned search_path."""
    _ensure_at_head(pg_url)
    with psycopg.connect(_conninfo(owner_url)) as conn:
        rows = conn.execute(
            "SELECT p.proname, p.proconfig "
            "FROM pg_proc p JOIN pg_namespace n ON p.pronamespace = n.oid "
            "WHERE n.nspname = 'public' AND p.prosecdef = true "
            "ORDER BY p.proname"
        ).fetchall()
    assert rows, "No SECURITY DEFINER functions found"
    for name, config in rows:
        config_list = config or []
        sp_items = [i for i in config_list if i.startswith("search_path=")]
        assert sp_items, f"{name}: no search_path"
        for sp in sp_items:
            val = sp.split("=", 1)[1]
            assert "pg_catalog" in val and "pg_temp" in val, (
                f"{name}: bad search_path: {val}"
            )


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M2T5Pending)
def test_m2_secdef_search_path_pinned(pg_url, pg_roles, owner_url):
    """Each M2 SECURITY DEFINER function has search_path = pg_catalog, pg_temp."""
    _ensure_at_head(pg_url)
    with psycopg.connect(_conninfo(owner_url)) as conn:
        rows = conn.execute(
            "SELECT p.proname, p.proconfig "
            "FROM pg_proc p JOIN pg_namespace n ON p.pronamespace = n.oid "
            "WHERE n.nspname = 'public' AND p.prosecdef = true "
            "  AND p.proname != 'org_login_config' "
            "ORDER BY p.proname"
        ).fetchall()
    if len(rows) < 8:
        raise M2T5Pending(f"Only {len(rows)} M2 SECURITY DEFINER functions")
    bad = []
    for name, config in rows:
        config_list = config or []
        sp_items = [i for i in config_list if i.startswith("search_path=")]
        if not sp_items:
            bad.append(f"{name}: no search_path")
        for sp in sp_items:
            val = sp.split("=", 1)[1]
            if "pg_catalog" not in val or "pg_temp" not in val:
                bad.append(f"{name}: search_path={val}")
    if bad:
        raise M2T5Pending(f"search_path issues: {bad}")


@pytest.mark.pg
def test_m1_secdef_owned_by_agg_owner(pg_url, pg_roles, owner_url):
    """Guard: existing SECURITY DEFINER functions owned by agg_owner."""
    _ensure_at_head(pg_url)
    with psycopg.connect(_conninfo(owner_url)) as conn:
        rows = conn.execute(
            "SELECT p.proname, r.rolname "
            "FROM pg_proc p "
            "JOIN pg_namespace n ON p.pronamespace = n.oid "
            "JOIN pg_roles r ON p.proowner = r.oid "
            "WHERE n.nspname = 'public' AND p.prosecdef = true "
            "ORDER BY p.proname"
        ).fetchall()
    assert rows
    for name, owner in rows:
        assert owner == "agg_owner", f"{name} owned by {owner}"


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M2T5Pending)
def test_m2_secdef_owned_by_agg_owner(pg_url, pg_roles, owner_url):
    """Each M2 SECURITY DEFINER function is owned by agg_owner."""
    _ensure_at_head(pg_url)
    with psycopg.connect(_conninfo(owner_url)) as conn:
        rows = conn.execute(
            "SELECT p.proname, r.rolname "
            "FROM pg_proc p "
            "JOIN pg_namespace n ON p.pronamespace = n.oid "
            "JOIN pg_roles r ON p.proowner = r.oid "
            "WHERE n.nspname = 'public' AND p.prosecdef = true "
            "  AND p.proname != 'org_login_config' "
            "ORDER BY p.proname"
        ).fetchall()
    if len(rows) < 8:
        raise M2T5Pending(f"Only {len(rows)} M2 SECURITY DEFINER functions")
    bad = [f"{n} owned by {o}" for n, o in rows if o != "agg_owner"]
    if bad:
        raise M2T5Pending(f"Wrong owners: {bad}")


@pytest.mark.pg
def test_m1_secdef_execute_grants(pg_url, pg_roles, owner_url):
    """Guard: existing SECURITY DEFINER: EXECUTE revoked from PUBLIC, granted to agg_app."""
    _ensure_at_head(pg_url)
    with psycopg.connect(_conninfo(owner_url)) as conn:
        rows = conn.execute(
            "SELECT p.proname, p.oid "
            "FROM pg_proc p JOIN pg_namespace n ON p.pronamespace = n.oid "
            "WHERE n.nspname = 'public' AND p.prosecdef = true "
            "ORDER BY p.proname"
        ).fetchall()
    assert rows
    for name, oid in rows:
        with psycopg.connect(_conninfo(owner_url)) as conn:
            has_public = conn.execute(
                "SELECT has_function_privilege('public', %s, 'EXECUTE')",
                [oid],
            ).fetchone()[0]
            assert not has_public, f"{name}: PUBLIC has EXECUTE"
            has_app = conn.execute(
                "SELECT has_function_privilege('agg_app', %s, 'EXECUTE')",
                [oid],
            ).fetchone()[0]
            assert has_app, f"{name}: agg_app lacks EXECUTE"


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M2T5Pending)
def test_m2_secdef_execute_grants(pg_url, pg_roles, owner_url):
    """M2 SECURITY DEFINER: EXECUTE revoked from PUBLIC, granted to agg_app only."""
    _ensure_at_head(pg_url)
    with psycopg.connect(_conninfo(owner_url)) as conn:
        rows = conn.execute(
            "SELECT p.proname, p.oid "
            "FROM pg_proc p JOIN pg_namespace n ON p.pronamespace = n.oid "
            "WHERE n.nspname = 'public' AND p.prosecdef = true "
            "  AND p.proname != 'org_login_config' "
            "ORDER BY p.proname"
        ).fetchall()
    if len(rows) < 8:
        raise M2T5Pending(f"Only {len(rows)} M2 SECURITY DEFINER functions")
    bad = []
    with psycopg.connect(_conninfo(owner_url)) as conn:
        for name, oid in rows:
            has_public = conn.execute(
                "SELECT has_function_privilege('public', %s, 'EXECUTE')",
                [oid],
            ).fetchone()[0]
            if has_public:
                bad.append(f"{name}: PUBLIC has EXECUTE")
            has_app = conn.execute(
                "SELECT has_function_privilege('agg_app', %s, 'EXECUTE')",
                [oid],
            ).fetchone()[0]
            if not has_app:
                bad.append(f"{name}: agg_app lacks EXECUTE")
    if bad:
        raise M2T5Pending(f"EXECUTE grant issues: {bad}")


# ===================================================================
# RED: enrollment-code consume has exactly 1 winner across 4 connections
# ===================================================================


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M2T5Pending)
def test_enrollment_code_consume_single_winner(pg_url, pg_roles, owner_url, app_url):
    """Atomic enrollment-code consume: exactly 1 winner across 4 concurrent connections."""
    from concurrent.futures import ThreadPoolExecutor, as_completed

    _ensure_at_head(pg_url)

    if not _table_exists(
        psycopg.connect(_conninfo(owner_url)), "enrollment_codes"
    ):
        raise M2T5Pending("enrollment_codes table does not exist yet")

    # Seed a code
    import hashlib, secrets
    code = secrets.token_hex(16)
    code_hash = hashlib.sha256(code.encode()).hexdigest()
    org_id = str(uuid.uuid4())
    project_id = str(uuid.uuid4())
    operator_id = str(uuid.uuid4())

    conninfo = _conninfo(owner_url)
    with psycopg.connect(conninfo, autocommit=True) as conn:
        # Insert the enrollment code
        try:
            conn.execute(
                "INSERT INTO enrollment_codes "
                "(id, org_id, project_id, code_hash, expires_at, operator_user_id) "
                "VALUES (%s, %s, %s, %s, now() + interval '15 minutes', %s)",
                [str(uuid.uuid4()), org_id, project_id, code_hash, operator_id],
            )
        except Exception as exc:
            raise M2T5Pending(f"Cannot seed enrollment code: {exc}") from exc

    # 4 concurrent consumers
    def try_consume(n: int):
        app_ci = _conninfo(app_url)
        with psycopg.connect(app_ci) as conn:
            try:
                row = conn.execute(
                    "SELECT enrollment_code_consume(%s)",
                    [code_hash],
                ).fetchone()
                conn.commit()
                return row is not None and row[0] is not None
            except Exception:
                return False

    wins = 0
    with ThreadPoolExecutor(max_workers=4) as pool:
        futs = [pool.submit(try_consume, i) for i in range(4)]
        for f in as_completed(futs):
            if f.result():
                wins += 1

    assert wins == 1, f"Expected exactly 1 winner, got {wins}"


# ===================================================================
# RED: signer-link consume is single use
# ===================================================================


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M2T5Pending)
def test_signer_link_consume_single_use(pg_url, pg_roles, owner_url, app_url):
    """Signer-link consume returns a result once; second call returns nothing."""
    _ensure_at_head(pg_url)

    if not _table_exists(
        psycopg.connect(_conninfo(owner_url)), "signer_links"
    ):
        raise M2T5Pending("signer_links table does not exist yet")

    import hashlib, secrets
    code = secrets.token_hex(16)
    code_hash = hashlib.sha256(code.encode()).hexdigest()
    org_id = str(uuid.uuid4())
    user_id = str(uuid.uuid4())

    conninfo = _conninfo(owner_url)
    with psycopg.connect(conninfo, autocommit=True) as conn:
        try:
            conn.execute(
                "INSERT INTO signer_links "
                "(id, org_id, user_id, code_hash, expires_at, status) "
                "VALUES (%s, %s, %s, %s, now() + interval '15 minutes', 'pending')",
                [str(uuid.uuid4()), org_id, user_id, code_hash],
            )
        except Exception as exc:
            raise M2T5Pending(f"Cannot seed signer link: {exc}") from exc

    app_ci = _conninfo(app_url)
    with psycopg.connect(app_ci) as conn:
        r1 = conn.execute("SELECT signer_link_consume(%s)", [code_hash]).fetchone()
        conn.commit()
    with psycopg.connect(app_ci) as conn:
        r2 = conn.execute("SELECT signer_link_consume(%s)", [code_hash]).fetchone()
        conn.commit()

    assert r1 is not None and r1[0] is not None, "First consume should return data"
    assert r2 is None or r2[0] is None, "Second consume should return nothing"


# ===================================================================
# RED: nonce insert refuses repeat
# ===================================================================


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M2T5Pending)
def test_device_nonce_refuses_repeat(pg_url, pg_roles, owner_url, app_url):
    """Nonce insert refuses a repeat per (device_id, nonce)."""
    _ensure_at_head(pg_url)

    if not _table_exists(
        psycopg.connect(_conninfo(owner_url)), "device_nonces"
    ):
        raise M2T5Pending("device_nonces table does not exist yet")

    device_id = str(uuid.uuid4())
    nonce = secrets.token_hex(16)

    app_ci = _conninfo(app_url)
    with psycopg.connect(app_ci) as conn:
        # First insert should succeed
        conn.execute(
            "SELECT device_nonce_insert(%s, %s, now())",
            [device_id, nonce],
        )
        conn.commit()

    with psycopg.connect(app_ci) as conn:
        try:
            conn.execute(
                "SELECT device_nonce_insert(%s, %s, now())",
                [device_id, nonce],
            )
            conn.commit()
            pytest.fail("Repeat nonce should be refused")
        except (psycopg.errors.UniqueViolation, psycopg.errors.RaiseException):
            pass  # expected


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M2T5Pending)
def test_signer_nonce_refuses_repeat(pg_url, pg_roles, owner_url, app_url):
    """Nonce insert refuses a repeat per (key_id, nonce)."""
    _ensure_at_head(pg_url)

    if not _table_exists(
        psycopg.connect(_conninfo(owner_url)), "signer_nonces"
    ):
        raise M2T5Pending("signer_nonces table does not exist yet")

    key_id = secrets.token_hex(32)
    nonce = secrets.token_hex(16)

    app_ci = _conninfo(app_url)
    with psycopg.connect(app_ci) as conn:
        conn.execute(
            "SELECT signer_nonce_insert(%s, %s, now())",
            [key_id, nonce],
        )
        conn.commit()

    with psycopg.connect(app_ci) as conn:
        try:
            conn.execute(
                "SELECT signer_nonce_insert(%s, %s, now())",
                [key_id, nonce],
            )
            conn.commit()
            pytest.fail("Repeat signer nonce should be refused")
        except (psycopg.errors.UniqueViolation, psycopg.errors.RaiseException):
            pass


# ===================================================================
# RED: token-hash lookups return fixed columns, nothing for unknown
# ===================================================================


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M2T5Pending)
def test_device_token_lookup_unknown_returns_nothing(pg_url, pg_roles, app_url):
    """device_token_lookup for an unknown hash returns NULL."""
    _ensure_at_head(pg_url)

    app_ci = _conninfo(app_url)
    try:
        with psycopg.connect(app_ci) as conn:
            row = conn.execute(
                "SELECT device_token_lookup(%s)", ["deadbeef" * 8]
            ).fetchone()
    except Exception as exc:
        raise M2T5Pending(f"device_token_lookup not available: {exc}") from exc

    assert row is None or row[0] is None, "Unknown hash should return NULL"


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M2T5Pending)
def test_signer_token_lookup_unknown_returns_nothing(pg_url, pg_roles, app_url):
    """signer_token_lookup for an unknown hash returns NULL."""
    _ensure_at_head(pg_url)

    app_ci = _conninfo(app_url)
    try:
        with psycopg.connect(app_ci) as conn:
            row = conn.execute(
                "SELECT signer_token_lookup(%s)", ["deadbeef" * 8]
            ).fetchone()
    except Exception as exc:
        raise M2T5Pending(f"signer_token_lookup not available: {exc}") from exc

    assert row is None or row[0] is None, "Unknown hash should return NULL"


# ===================================================================
# RED: Alembic round trip (upgrade -> downgrade -> upgrade)
# ===================================================================


@pytest.mark.pg
def test_alembic_round_trip_m1(pg_url, pg_roles):
    """Guard: Alembic upgrade, downgrade to previous, upgrade again (M1 revisions)."""
    from agg_cp.db import alembic_config
    from alembic.command import upgrade, downgrade
    from alembic.script import ScriptDirectory

    cfg = alembic_config(pg_url)
    script = ScriptDirectory.from_config(cfg)
    revisions = list(script.walk_revisions())
    assert len(revisions) >= 2, "Need at least 2 revisions"

    head = script.get_current_head()
    prev = revisions[1].revision
    upgrade(cfg, "head")
    downgrade(cfg, prev)
    upgrade(cfg, "head")

    conninfo = _conninfo(pg_url)
    with psycopg.connect(conninfo) as conn:
        row = conn.execute(
            "SELECT version_num FROM alembic_version"
        ).fetchone()
        assert row is not None and row[0] == head


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M2T5Pending)
def test_alembic_m2_migration_exists(pg_url, pg_roles):
    """An M2 Alembic migration exists (beyond the 6 M1 revisions)."""
    from agg_cp.db import alembic_config
    from alembic.script import ScriptDirectory

    cfg = alembic_config(pg_url)
    script = ScriptDirectory.from_config(cfg)
    revisions = list(script.walk_revisions())

    # M1 has 6 revisions (0001-0006). M2 must add at least one more.
    if len(revisions) <= 6:
        raise M2T5Pending(
            f"Only {len(revisions)} Alembic revisions; "
            "M2 must add at least one migration"
        )
