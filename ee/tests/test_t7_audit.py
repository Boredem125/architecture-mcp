"""M1 T7 tests: admin_audit append-only, hash chain, triggers.

Contract (M1_PLAN D5.3, ADR 0002 amendments 4 and 6, SEC-07):

- ``agg_app`` has INSERT, SELECT only on admin_audit.
- Row triggers reject UPDATE and DELETE for *every* role (including
  agg_owner).
- BEFORE TRUNCATE trigger rejects; TRUNCATE privilege revoked.
- Hash-chained per org (ADR 0002 item 6): a BEFORE INSERT trigger
  computes chain_length, previous_hash, created_at and record_hash,
  overwriting anything the client sent.
- ``record_hash`` = lowercase hex SHA-256 of the UTF-8 text of
  ``admin_audit_canonical(row)`` (a SQL function that builds a jsonb
  object of every column except record_hash, with UUIDs as text and
  timestamps as ``to_char(ts AT TIME ZONE 'UTC',
  'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')``).
- First row per org chains from ``"0" * 64``.
- Python verification reads ``admin_audit_canonical(t)::text`` from
  the database and recomputes SHA-256 (``agg_cp.audit.verify_chain``).
"""
from __future__ import annotations

import concurrent.futures
import hashlib
import json
import uuid

import pytest


# ---------------------------------------------------------------------------
# Named exception (guard checks)
# ---------------------------------------------------------------------------


class T7Pending(Exception):
    """T7 tables / roles / RLS not built yet."""


def _require(cond: bool, msg: str) -> None:
    if not cond:
        raise T7Pending(msg)


GENESIS = "0" * 64  # matches chain.py _GENESIS_HASH


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


def _check_audit_table(url: str) -> None:
    """Raise T7Pending if admin_audit does not exist."""
    import psycopg

    with psycopg.connect(_conninfo(url)) as conn:
        exists = conn.execute(
            "SELECT EXISTS ("
            "  SELECT 1 FROM pg_tables "
            "  WHERE schemaname='public' AND tablename='admin_audit'"
            ")"
        ).fetchone()[0]
        _require(exists, "admin_audit table does not exist")


# Seed cache (module scope)
_SEED: dict = {}


def _seed_org(owner_url: str) -> uuid.UUID:
    """Seed one org and return its id.  Cached per module."""
    if "org" in _SEED:
        return _SEED["org"]

    import psycopg

    org_id = uuid.uuid4()
    conninfo = _conninfo(owner_url)
    try:
        with psycopg.connect(conninfo) as conn:
            conn.execute(
                "SELECT set_config('app.org_id', %s, false)",
                [str(org_id)],
            )
            conn.execute(
                "INSERT INTO orgs (id, org_id, name, slug, created_at) "
                "VALUES (%s, %s, 'AuditOrg', 'audit-org', now())",
                [org_id, org_id],
            )
            conn.commit()
    except Exception as exc:
        raise T7Pending(f"Cannot seed org: {exc}") from exc

    _SEED["org"] = org_id
    return org_id


# ===================================================================
# 4a. UPDATE rejected
# ===================================================================


@pytest.mark.pg
def test_audit_update_rejected_agg_app(pg_url, app_url, owner_url, pg_roles):
    """UPDATE on admin_audit is rejected for agg_app."""
    _ensure_at_head(pg_url)
    _check_audit_table(pg_url)
    org_id = _seed_org(owner_url)

    import psycopg

    with psycopg.connect(_conninfo(app_url)) as conn:
        conn.execute(
            "SELECT set_config('app.org_id', %s, false)", [str(org_id)]
        )
        row_id = uuid.uuid4()
        conn.execute(
            "INSERT INTO admin_audit (id, org_id, action, detail) "
            "VALUES (%s, %s, 'test.update', '{}'::jsonb)",
            [row_id, org_id],
        )
        conn.commit()
        conn.execute(
            "SELECT set_config('app.org_id', %s, false)", [str(org_id)]
        )
        with pytest.raises(
            (psycopg.errors.InsufficientPrivilege, psycopg.errors.RaiseException)
        ):
            conn.execute(
                "UPDATE admin_audit SET action='tampered' WHERE id=%s",
                [row_id],
            )
        conn.rollback()


@pytest.mark.pg
def test_audit_update_rejected_agg_owner(pg_url, owner_url, pg_roles):
    """UPDATE on admin_audit is rejected even for agg_owner."""
    _ensure_at_head(pg_url)
    _check_audit_table(pg_url)
    org_id = _seed_org(owner_url)

    import psycopg

    with psycopg.connect(_conninfo(owner_url)) as conn:
        conn.execute(
            "SELECT set_config('app.org_id', %s, false)", [str(org_id)]
        )
        row_id = uuid.uuid4()
        conn.execute(
            "INSERT INTO admin_audit (id, org_id, action, detail) "
            "VALUES (%s, %s, 'test.update_owner', '{}'::jsonb)",
            [row_id, org_id],
        )
        conn.commit()
        conn.execute(
            "SELECT set_config('app.org_id', %s, false)", [str(org_id)]
        )
        with pytest.raises(psycopg.errors.RaiseException):
            conn.execute(
                "UPDATE admin_audit SET action='tampered' WHERE id=%s",
                [row_id],
            )
        conn.rollback()


# ===================================================================
# 4b. DELETE rejected
# ===================================================================


@pytest.mark.pg
def test_audit_delete_rejected_agg_app(pg_url, app_url, owner_url, pg_roles):
    """DELETE on admin_audit is rejected for agg_app."""
    _ensure_at_head(pg_url)
    _check_audit_table(pg_url)
    org_id = _seed_org(owner_url)

    import psycopg

    with psycopg.connect(_conninfo(app_url)) as conn:
        conn.execute(
            "SELECT set_config('app.org_id', %s, false)", [str(org_id)]
        )
        row_id = uuid.uuid4()
        conn.execute(
            "INSERT INTO admin_audit (id, org_id, action, detail) "
            "VALUES (%s, %s, 'test.delete', '{}'::jsonb)",
            [row_id, org_id],
        )
        conn.commit()
        conn.execute(
            "SELECT set_config('app.org_id', %s, false)", [str(org_id)]
        )
        with pytest.raises(
            (psycopg.errors.InsufficientPrivilege, psycopg.errors.RaiseException)
        ):
            conn.execute(
                "DELETE FROM admin_audit WHERE id=%s", [row_id]
            )
        conn.rollback()


@pytest.mark.pg
def test_audit_delete_rejected_agg_owner(pg_url, owner_url, pg_roles):
    """DELETE on admin_audit is rejected even for agg_owner."""
    _ensure_at_head(pg_url)
    _check_audit_table(pg_url)
    org_id = _seed_org(owner_url)

    import psycopg

    with psycopg.connect(_conninfo(owner_url)) as conn:
        conn.execute(
            "SELECT set_config('app.org_id', %s, false)", [str(org_id)]
        )
        row_id = uuid.uuid4()
        conn.execute(
            "INSERT INTO admin_audit (id, org_id, action, detail) "
            "VALUES (%s, %s, 'test.del_owner', '{}'::jsonb)",
            [row_id, org_id],
        )
        conn.commit()
        conn.execute(
            "SELECT set_config('app.org_id', %s, false)", [str(org_id)]
        )
        with pytest.raises(psycopg.errors.RaiseException):
            conn.execute(
                "DELETE FROM admin_audit WHERE id=%s", [row_id]
            )
        conn.rollback()


# ===================================================================
# 4c. TRUNCATE rejected
# ===================================================================


@pytest.mark.pg
def test_audit_truncate_rejected_agg_app(pg_url, app_url, owner_url, pg_roles):
    """TRUNCATE on admin_audit is rejected for agg_app
    (privilege revoked + trigger)."""
    _ensure_at_head(pg_url)
    _check_audit_table(pg_url)

    import psycopg

    with psycopg.connect(_conninfo(app_url)) as conn:
        with pytest.raises(
            (psycopg.errors.InsufficientPrivilege, psycopg.errors.RaiseException)
        ):
            conn.execute("TRUNCATE admin_audit")
        conn.rollback()


@pytest.mark.pg
def test_audit_truncate_rejected_agg_owner(pg_url, owner_url, pg_roles):
    """TRUNCATE on admin_audit is rejected for agg_owner (trigger)."""
    _ensure_at_head(pg_url)
    _check_audit_table(pg_url)

    import psycopg

    with psycopg.connect(_conninfo(owner_url)) as conn:
        with pytest.raises(psycopg.errors.RaiseException):
            conn.execute("TRUNCATE admin_audit")
        conn.rollback()


# ===================================================================
# 4d. INSERT + SELECT work for agg_app
# ===================================================================


@pytest.mark.pg
def test_audit_insert_select_agg_app(pg_url, app_url, owner_url, pg_roles):
    """agg_app can INSERT and SELECT on admin_audit."""
    _ensure_at_head(pg_url)
    _check_audit_table(pg_url)
    org_id = _seed_org(owner_url)

    import psycopg

    with psycopg.connect(_conninfo(app_url)) as conn:
        conn.execute(
            "SELECT set_config('app.org_id', %s, false)", [str(org_id)]
        )
        row_id = uuid.uuid4()
        conn.execute(
            "INSERT INTO admin_audit (id, org_id, action, detail) "
            "VALUES (%s, %s, 'test.rw', %s::jsonb)",
            [row_id, org_id, json.dumps({"rw": True})],
        )
        conn.commit()
        conn.execute(
            "SELECT set_config('app.org_id', %s, false)", [str(org_id)]
        )
        rows = conn.execute(
            "SELECT id, action FROM admin_audit WHERE id = %s",
            [row_id],
        ).fetchall()
        assert len(rows) == 1, f"Expected 1 row, got {len(rows)}"
        assert rows[0][0] == row_id
        assert rows[0][1] == "test.rw"


# ===================================================================
# 4e. Chain verification (ADR 0002 item 6)
# ===================================================================


@pytest.mark.pg
def test_audit_chain_verifiable(pg_url, app_url, owner_url, pg_roles):
    """Inserting 3 rows per org gives a verifiable hash chain.

    Verification (ADR 0002 item 6):
    1. previous_hash of first row == GENESIS ("0" * 64)
    2. previous_hash of row N == record_hash of row N-1
    3. record_hash of each row == SHA-256 of admin_audit_canonical(row)::text
    """
    _ensure_at_head(pg_url)
    _check_audit_table(pg_url)

    import psycopg

    # Use a fresh org for an isolated chain
    org_id = uuid.uuid4()
    conninfo_owner = _conninfo(owner_url)
    try:
        with psycopg.connect(conninfo_owner) as conn:
            conn.execute(
                "SELECT set_config('app.org_id', %s, false)",
                [str(org_id)],
            )
            conn.execute(
                "INSERT INTO orgs (id, org_id, name, slug, created_at) "
                "VALUES (%s, %s, 'ChainOrg', 'chain-org', now())",
                [org_id, org_id],
            )
            conn.commit()
    except Exception as exc:
        raise T7Pending(f"Cannot seed chain org: {exc}") from exc

    with psycopg.connect(_conninfo(app_url)) as conn:
        conn.execute(
            "SELECT set_config('app.org_id', %s, false)", [str(org_id)]
        )
        for i in range(3):
            conn.execute(
                "INSERT INTO admin_audit (id, org_id, action, detail) "
                "VALUES (%s, %s, %s, %s::jsonb)",
                [
                    uuid.uuid4(),
                    org_id,
                    f"chain.test.{i}",
                    json.dumps({"step": i}),
                ],
            )
        conn.commit()

        conn.execute(
            "SELECT set_config('app.org_id', %s, false)", [str(org_id)]
        )
        rows = conn.execute(
            "SELECT admin_audit_canonical(t)::text AS canonical, "
            "t.chain_length, t.previous_hash, t.record_hash "
            "FROM admin_audit t "
            "WHERE t.org_id = %s ORDER BY t.chain_length",
            [org_id],
        ).fetchall()

    assert len(rows) == 3, f"Expected 3 rows, got {len(rows)}"

    prev_hash = GENESIS
    for canonical, chain_length, previous_hash, record_hash in rows:
        # Check chain link
        assert previous_hash == prev_hash, (
            f"Chain broken at chain_length {chain_length}: "
            f"previous_hash={previous_hash!r}, expected={prev_hash!r}"
        )
        # Recompute record_hash from the DB canonical text
        computed = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        assert record_hash == computed, (
            f"Hash mismatch at chain_length {chain_length}: "
            f"stored={record_hash!r}, computed={computed!r}"
        )
        prev_hash = record_hash


@pytest.mark.pg
def test_audit_chain_flipped_byte(pg_url, app_url, owner_url, pg_roles):
    """Positive control: a flipped byte in a row's detail (done with
    triggers disabled via session_replication_role = replica) makes
    verify_chain return not ok.  Another org's chain still verifies.
    """
    _ensure_at_head(pg_url)
    _check_audit_table(pg_url)

    import psycopg

    from agg_cp.audit import verify_chain

    # Two fresh orgs for isolation
    org_a = uuid.uuid4()
    org_b = uuid.uuid4()
    conninfo_owner = _conninfo(owner_url)

    try:
        for oid, slug in [(org_a, f"flip-a-{org_a}"), (org_b, f"flip-b-{org_b}")]:
            with psycopg.connect(conninfo_owner) as conn:
                conn.execute(
                    "SELECT set_config('app.org_id', %s, false)",
                    [str(oid)],
                )
                conn.execute(
                    "INSERT INTO orgs (id, org_id, name, slug, created_at) "
                    "VALUES (%s, %s, %s, %s, now())",
                    [oid, oid, f"FlipOrg-{slug}", slug],
                )
                conn.commit()
    except Exception as exc:
        raise T7Pending(f"Cannot seed flip orgs: {exc}") from exc

    # Insert one row per org via agg_app
    with psycopg.connect(_conninfo(app_url)) as conn:
        conn.execute(
            "SELECT set_config('app.org_id', %s, false)", [str(org_a)]
        )
        conn.execute(
            "INSERT INTO admin_audit (id, org_id, action, detail) "
            "VALUES (%s, %s, 'flip.original', '{}'::jsonb)",
            [uuid.uuid4(), org_a],
        )
        conn.commit()

    with psycopg.connect(_conninfo(app_url)) as conn:
        conn.execute(
            "SELECT set_config('app.org_id', %s, false)", [str(org_b)]
        )
        conn.execute(
            "INSERT INTO admin_audit (id, org_id, action, detail) "
            "VALUES (%s, %s, 'flip.other', '{}'::jsonb)",
            [uuid.uuid4(), org_b],
        )
        conn.commit()

    # Pre-condition: both chains verify
    with psycopg.connect(_conninfo(app_url)) as conn:
        conn.execute(
            "SELECT set_config('app.org_id', %s, false)", [str(org_a)]
        )
        ok, reason = verify_chain(conn, org_a)
        assert ok, f"Pre-condition: org A chain should be ok: {reason}"

    with psycopg.connect(_conninfo(app_url)) as conn:
        conn.execute(
            "SELECT set_config('app.org_id', %s, false)", [str(org_b)]
        )
        ok, reason = verify_chain(conn, org_b)
        assert ok, f"Pre-condition: org B chain should be ok: {reason}"

    # As superuser, disable triggers and flip a byte in org A's detail
    with psycopg.connect(_conninfo(pg_url)) as conn:
        conn.execute("SET session_replication_role = replica")
        conn.execute(
            "UPDATE admin_audit SET detail = '{\"tampered\": true}'::jsonb "
            "WHERE org_id = %s",
            [org_a],
        )
        conn.commit()
        conn.execute("SET session_replication_role = DEFAULT")

    # Org A's chain should now be broken
    with psycopg.connect(_conninfo(app_url)) as conn:
        conn.execute(
            "SELECT set_config('app.org_id', %s, false)", [str(org_a)]
        )
        ok, reason = verify_chain(conn, org_a)
        assert not ok, (
            "Positive control failed: flipping a byte should break the chain"
        )

    # Org B's chain should still be ok
    with psycopg.connect(_conninfo(app_url)) as conn:
        conn.execute(
            "SELECT set_config('app.org_id', %s, false)", [str(org_b)]
        )
        ok, reason = verify_chain(conn, org_b)
        assert ok, f"Org B's chain should still verify: {reason}"


# ===================================================================
# 4f. Client-supplied chain fields are overwritten (ADR 0002 item 6)
# ===================================================================


@pytest.mark.pg
def test_audit_client_fields_overwritten(pg_url, app_url, owner_url, pg_roles):
    """Client-supplied previous_hash, record_hash and chain_length are
    overwritten by the BEFORE INSERT trigger (ADR 0002 item 6)."""
    _ensure_at_head(pg_url)
    _check_audit_table(pg_url)
    org_id = _seed_org(owner_url)

    import psycopg

    with psycopg.connect(_conninfo(app_url)) as conn:
        conn.execute(
            "SELECT set_config('app.org_id', %s, false)", [str(org_id)]
        )
        row_id = uuid.uuid4()
        conn.execute(
            "INSERT INTO admin_audit "
            "(id, org_id, action, detail, chain_length, previous_hash, record_hash) "
            "VALUES (%s, %s, 'test.overwrite', '{}'::jsonb, 999, 'fakehash', 'fakehash2')",
            [row_id, org_id],
        )
        conn.commit()

        conn.execute(
            "SELECT set_config('app.org_id', %s, false)", [str(org_id)]
        )
        row = conn.execute(
            "SELECT chain_length, previous_hash, record_hash "
            "FROM admin_audit WHERE id = %s",
            [row_id],
        ).fetchone()

        assert row is not None, "Row not found after insert"
        assert row[0] != 999, "chain_length should be overwritten by trigger"
        assert row[1] != "fakehash", (
            "previous_hash should be overwritten by trigger"
        )
        assert row[2] != "fakehash2", (
            "record_hash should be overwritten by trigger"
        )


# ===================================================================
# 4g. Concurrent inserts (ADR 0002 item 6 advisory lock)
# ===================================================================


@pytest.mark.pg
def test_audit_concurrent_inserts(pg_url, app_url, owner_url, pg_roles):
    """2 connections inserting 10 rows each concurrently for the same
    org give chain_length 1..20 with no gaps and verify_chain ok."""
    _ensure_at_head(pg_url)
    _check_audit_table(pg_url)

    import psycopg

    from agg_cp.audit import verify_chain

    # Fresh org for isolation
    org_id = uuid.uuid4()
    slug = f"conc-org-{org_id}"
    conninfo_owner = _conninfo(owner_url)

    try:
        with psycopg.connect(conninfo_owner) as conn:
            conn.execute(
                "SELECT set_config('app.org_id', %s, false)",
                [str(org_id)],
            )
            conn.execute(
                "INSERT INTO orgs (id, org_id, name, slug, created_at) "
                "VALUES (%s, %s, 'ConcOrg', %s, now())",
                [org_id, org_id, slug],
            )
            conn.commit()
    except Exception as exc:
        raise T7Pending(f"Cannot seed conc org: {exc}") from exc

    conninfo_app = _conninfo(app_url)

    def insert_10(worker_id: int) -> None:
        with psycopg.connect(conninfo_app) as conn:
            for i in range(10):
                conn.execute(
                    "SELECT set_config('app.org_id', %s, false)",
                    [str(org_id)],
                )
                conn.execute(
                    "INSERT INTO admin_audit (id, org_id, action, detail) "
                    "VALUES (%s, %s, %s, '{}'::jsonb)",
                    [uuid.uuid4(), org_id, f"conc.{worker_id}.{i}"],
                )
                conn.commit()

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        f1 = executor.submit(insert_10, 0)
        f2 = executor.submit(insert_10, 1)
        f1.result(timeout=30)
        f2.result(timeout=30)

    # Verify chain_lengths are 1..20 with no gaps
    with psycopg.connect(conninfo_app) as conn:
        conn.execute(
            "SELECT set_config('app.org_id', %s, false)", [str(org_id)]
        )
        lengths = conn.execute(
            "SELECT chain_length FROM admin_audit "
            "WHERE org_id = %s ORDER BY chain_length",
            [org_id],
        ).fetchall()
        assert [r[0] for r in lengths] == list(range(1, 21)), (
            f"Expected chain_length 1..20, got {[r[0] for r in lengths]}"
        )

        ok, reason = verify_chain(conn, org_id)
        assert ok, f"Concurrent chain should verify: {reason}"
