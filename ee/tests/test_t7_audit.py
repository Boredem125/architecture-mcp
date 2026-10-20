"""M1 T7 tests-first: admin_audit append-only, hash chain, triggers.

Contract (M1_PLAN D5.3, ADR 0002 amendment 4, SEC-07):

- ``agg_app`` has INSERT, SELECT only on admin_audit.
- Row triggers reject UPDATE and DELETE for *every* role (including
  agg_owner).
- BEFORE TRUNCATE trigger rejects; TRUNCATE privilege revoked.
- Hash-chained per org: each row stores ``previous_hash`` (prior row's
  ``record_hash``) and its own ``record_hash``.  First row per org
  chains from a fixed genesis (``"0" * 64``, matching the connector's
  ``chain.py:_GENESIS_HASH``).
- Hash convention (implied by ADR 0002 reference to ADR 0001 s5 and
  the connector's ``audit.py``):
    record_hash = SHA-256(canonical_json(body))
    body = all columns except {previous_hash, record_hash, chain_length}
    canonical_json = json.dumps(body, separators=(",",":"),
                                sort_keys=True, default=_json_default)
  Type serialisation: UUID -> str, datetime -> isoformat, jsonb -> dict.

Tests marked RED_T7 are strict xfail before T7 migration code exists.
"""
from __future__ import annotations

import hashlib
import json
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
    reason="M1 T7: admin_audit triggers / chain not yet built",
)

GENESIS = "0" * 64  # matches chain.py _GENESIS_HASH
CHAIN_COLS = frozenset({"previous_hash", "record_hash", "chain_length"})


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


def _json_default(obj):
    """JSON serialiser for DB column types."""
    if isinstance(obj, uuid.UUID):
        return str(obj)
    if hasattr(obj, "isoformat"):
        return obj.isoformat()
    raise TypeError(f"Cannot serialise {type(obj)}")


def _compute_record_hash(body: dict) -> str:
    """SHA-256 of canonical JSON of the non-chain body columns."""
    return hashlib.sha256(
        json.dumps(
            body,
            separators=(",", ":"),
            sort_keys=True,
            default=_json_default,
        ).encode("utf-8")
    ).hexdigest()


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


@RED_T7
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
        with pytest.raises(psycopg.errors.RaiseException):
            conn.execute(
                "UPDATE admin_audit SET action='tampered' WHERE id=%s",
                [row_id],
            )
        conn.rollback()


@RED_T7
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


@RED_T7
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
        with pytest.raises(psycopg.errors.RaiseException):
            conn.execute(
                "DELETE FROM admin_audit WHERE id=%s", [row_id]
            )
        conn.rollback()


@RED_T7
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


@RED_T7
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


@RED_T7
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


@RED_T7
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
# 4e. Chain verification
# ===================================================================


@RED_T7
@pytest.mark.pg
def test_audit_chain_verifiable(pg_url, app_url, owner_url, pg_roles):
    """Inserting 3 rows per org gives a verifiable hash chain.

    Verification:
    1. previous_hash of first row == GENESIS ("0" * 64)
    2. previous_hash of row N == record_hash of row N-1
    3. record_hash of each row matches SHA-256 of canonical JSON of
       its non-chain columns (the connector audit.py convention).
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
        cur = conn.execute(
            "SELECT * FROM admin_audit "
            "WHERE org_id = %s ORDER BY chain_length",
            [org_id],
        )
        cols = [d.name for d in cur.description]
        rows = cur.fetchall()

    assert len(rows) == 3, f"Expected 3 rows, got {len(rows)}"

    prev_hash = GENESIS
    for row in rows:
        row_dict = dict(zip(cols, row))
        # Check chain link
        assert row_dict["previous_hash"] == prev_hash, (
            f"Chain broken at chain_length {row_dict.get('chain_length')}: "
            f"previous_hash={row_dict['previous_hash']!r}, expected={prev_hash!r}"
        )
        # Recompute record_hash
        body = {k: v for k, v in row_dict.items() if k not in CHAIN_COLS}
        computed = _compute_record_hash(body)
        assert row_dict["record_hash"] == computed, (
            f"Hash mismatch at chain_length {row_dict.get('chain_length')}: "
            f"stored={row_dict['record_hash']!r}, computed={computed!r}"
        )
        prev_hash = row_dict["record_hash"]


@RED_T7
@pytest.mark.pg
def test_audit_chain_flipped_byte(pg_url, app_url, owner_url, pg_roles):
    """Positive control: a flipped byte in a row's body produces a
    different record_hash, proving content integrity.
    """
    _ensure_at_head(pg_url)
    _check_audit_table(pg_url)

    import psycopg

    # Use a fresh org for isolation
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
                "VALUES (%s, %s, 'FlipOrg', 'flip-org', now())",
                [org_id, org_id],
            )
            conn.commit()
    except Exception as exc:
        raise T7Pending(f"Cannot seed flip org: {exc}") from exc

    with psycopg.connect(_conninfo(app_url)) as conn:
        conn.execute(
            "SELECT set_config('app.org_id', %s, false)", [str(org_id)]
        )
        conn.execute(
            "INSERT INTO admin_audit (id, org_id, action, detail) "
            "VALUES (%s, %s, 'flip.original', '{}'::jsonb)",
            [uuid.uuid4(), org_id],
        )
        conn.commit()

        conn.execute(
            "SELECT set_config('app.org_id', %s, false)", [str(org_id)]
        )
        cur = conn.execute(
            "SELECT * FROM admin_audit "
            "WHERE org_id = %s ORDER BY chain_length LIMIT 1",
            [org_id],
        )
        cols = [d.name for d in cur.description]
        row = cur.fetchone()

    assert row is not None, "No admin_audit row found"
    row_dict = dict(zip(cols, row))

    body = {k: v for k, v in row_dict.items() if k not in CHAIN_COLS}
    stored_hash = row_dict["record_hash"]

    # Verify original hash matches
    original_hash = _compute_record_hash(body)
    assert stored_hash == original_hash, "Pre-condition: original hash must match"

    # Flip one byte in the action field
    tampered_body = dict(body)
    original_action = tampered_body["action"]
    tampered_body["action"] = original_action[:-1] + chr(
        ord(original_action[-1]) ^ 0x01
    )
    tampered_hash = _compute_record_hash(tampered_body)

    assert tampered_hash != stored_hash, (
        "Positive control failed: flipping a byte should change the hash"
    )
