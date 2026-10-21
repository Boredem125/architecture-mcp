"""T6 ee tests-first: registry server half (Postgres).

Covers store_registry_version (verify + store), latest(), second genesis
refused AND alerted (sync_alerts row), and cross-org binding.

Uses the T5 tables via ee conftest fixtures (pg_url, pg_roles, owner_url,
app_url).

RED tests xfail on M2T6Pending.  Guards verify the T5 schema baseline.

Node-id patterns are fixed in M2_BASELINE.md section 5.
"""
from __future__ import annotations

import hashlib
import json
import time
import uuid

import psycopg
import pytest

from .m2_pending import M2T6Pending

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _need(module: str, attr: str) -> None:
    """Raise M2T6Pending if *module*.*attr* is absent."""
    try:
        mod = __import__(module, fromlist=[attr])
    except ImportError:
        raise M2T6Pending(f"{module} not importable")
    if not hasattr(mod, attr):
        raise M2T6Pending(f"{module}.{attr} not found")


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
        raise M2T6Pending(f"Alembic upgrade failed: {exc}") from exc


def _keygen():
    """Return (signing_key, pub_bytes, key_id)."""
    from nacl.signing import SigningKey
    sk = SigningKey.generate()
    pub = bytes(sk.verify_key)
    kid = hashlib.sha256(pub).hexdigest()
    return sk, pub, kid


def _canonical_json(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def _make_registry_payload(
    *,
    org_id: str = "org-1",
    version: int = 1,
    prev_hash: str = "",
    threshold: int = 1,
    admins: list[str] | None = None,
    keys: list[dict] | None = None,
    bundle_signer: dict | None = None,
    expires_at: float | None = None,
):
    if expires_at is None:
        expires_at = time.time() + 7 * 86400
    if admins is None:
        admins = []
    if keys is None:
        keys = []
    if bundle_signer is None:
        _, bpub, bkid = _keygen()
        bundle_signer = {"key_id": bkid, "public_key": bpub.hex(), "alg": "ed25519"}
    return {
        "org_id": org_id,
        "version": version,
        "prev_hash": prev_hash,
        "threshold": threshold,
        "admins": admins,
        "keys": keys,
        "bundle_signer": bundle_signer,
        "expires_at": expires_at,
    }


def _make_key_entry(sk=None, *, user_id="alice", iss="https://idp", sub="alice",
                    kind="cli", roles=None, added_in=1):
    if sk is None:
        sk, pub, kid = _keygen()
    else:
        pub = bytes(sk.verify_key)
        kid = hashlib.sha256(pub).hexdigest()
    return {
        "key_id": kid,
        "public_key": pub.hex(),
        "user_id": user_id,
        "iss": iss,
        "sub": sub,
        "alg": "ed25519",
        "kind": kind,
        "roles": roles or ["admin", "approver"],
        "added_in": added_in,
    }, sk


def _sign_envelope(kind, payload, keys):
    tag = kind.encode("utf-8")
    canonical = _canonical_json(payload)
    msg = tag + b"\x00" + canonical
    sigs = []
    for sk in keys:
        pub = bytes(sk.verify_key)
        kid = hashlib.sha256(pub).hexdigest()
        sig = sk.sign(msg).signature.hex()
        sigs.append({"key_id": kid, "alg": "ed25519", "sig": sig})
    return {
        "kind": kind,
        "sig_v": 1,
        "payload": payload,
        "signatures": sigs,
    }


def _build_genesis(org_id="org-1", admin_sks=None, threshold=1,
                   expires_at=None, bundle_signer=None):
    if admin_sks is None:
        sk1, _, _ = _keygen()
        admin_sks = [sk1]
    keys = []
    admins = []
    for i, sk in enumerate(admin_sks):
        entry, _ = _make_key_entry(
            sk, user_id=f"admin-{i}", iss="https://idp", sub=f"admin-{i}",
            kind="cli", roles=["admin", "approver"], added_in=1
        )
        keys.append(entry)
        admins.append(entry["key_id"])
    if bundle_signer is None:
        _, bpub, bkid = _keygen()
        bundle_signer = {"key_id": bkid, "public_key": bpub.hex(), "alg": "ed25519"}
    payload = _make_registry_payload(
        org_id=org_id,
        version=1,
        prev_hash="",
        threshold=threshold,
        admins=admins,
        keys=keys,
        bundle_signer=bundle_signer,
        expires_at=expires_at or time.time() + 7 * 86400,
    )
    return _sign_envelope("agg/registry/v1", payload, admin_sks), admin_sks


def _create_org(conn, org_id: str, name: str = "Test Org") -> None:
    """Insert an org row (owner connection, set app.org_id first)."""
    slug = org_id[:32].replace("-", "")
    conn.execute(
        "INSERT INTO orgs (id, org_id, name, slug, created_at) "
        "VALUES (%s, %s, %s, %s, now()) ON CONFLICT DO NOTHING",
        [org_id, org_id, name, slug],
    )


# ===================================================================
# Guards (pass now -- T5 schema baseline)
# ===================================================================


@pytest.mark.pg
def test_sync_alerts_table_exists(pg_url, pg_roles, owner_url):
    """Guard: sync_alerts table exists (T5 prerequisite)."""
    _ensure_at_head(pg_url)
    with psycopg.connect(_conninfo(owner_url)) as conn:
        row = conn.execute(
            "SELECT 1 FROM information_schema.tables "
            "WHERE table_schema = 'public' AND table_name = 'sync_alerts'"
        ).fetchone()
    assert row is not None, "sync_alerts table not found -- T5 prerequisite"


@pytest.mark.pg
def test_orgs_table_exists(pg_url, pg_roles, owner_url):
    """Guard: orgs table exists."""
    _ensure_at_head(pg_url)
    with psycopg.connect(_conninfo(owner_url)) as conn:
        row = conn.execute(
            "SELECT 1 FROM information_schema.tables "
            "WHERE table_schema = 'public' AND table_name = 'orgs'"
        ).fetchone()
    assert row is not None


# ===================================================================
# RED: store_registry_version + latest
# ===================================================================


@pytest.mark.pg

def test_store_and_retrieve_genesis(pg_url, pg_roles, app_url, owner_url):
    """store_registry_version stores v1; latest returns it."""
    _need("agg_cp.sync.registry", "store_registry_version")
    from agg_cp.sync.registry import store_registry_version, latest
    _ensure_at_head(pg_url)
    org_id = str(uuid.uuid4())
    sk1, _, kid1 = _keygen()
    genesis, _ = _build_genesis(org_id=org_id, admin_sks=[sk1])

    conninfo = _conninfo(app_url)
    with psycopg.connect(_conninfo(owner_url), autocommit=True) as oconn:
        oconn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        _create_org(oconn, org_id)

    with psycopg.connect(conninfo) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, true)", [org_id])
        version = store_registry_version(conn, org_id, genesis)
        assert version == 1
        result = latest(conn, org_id, after=0)
        assert result is not None
        assert result["payload"]["version"] == 1


@pytest.mark.pg

def test_store_two_versions(pg_url, pg_roles, app_url, owner_url):
    """store_registry_version stores v1 and v2 in sequence."""
    _need("agg_cp.sync.registry", "store_registry_version")
    from agg_cp.sync.registry import store_registry_version, latest
    _ensure_at_head(pg_url)
    org_id = str(uuid.uuid4())
    sk1, _, kid1 = _keygen()
    genesis, sks = _build_genesis(org_id=org_id, admin_sks=[sk1])

    prev_hash = hashlib.sha256(
        genesis["payload"]["org_id"].encode("utf-8") + b":" +
        _canonical_json(genesis["payload"])
    ).hexdigest()
    v2_payload = _make_registry_payload(
        org_id=org_id, version=2, prev_hash=prev_hash, threshold=1,
        admins=genesis["payload"]["admins"],
        keys=genesis["payload"]["keys"],
        bundle_signer=genesis["payload"]["bundle_signer"],
    )
    v2 = _sign_envelope("agg/registry/v1", v2_payload, sks)

    with psycopg.connect(_conninfo(owner_url), autocommit=True) as oconn:
        oconn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        _create_org(oconn, org_id)

    conninfo = _conninfo(app_url)
    with psycopg.connect(conninfo) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, true)", [org_id])
        store_registry_version(conn, org_id, genesis)
        v = store_registry_version(conn, org_id, v2)
        assert v == 2
        result = latest(conn, org_id, after=1)
        assert result is not None
        assert result["payload"]["version"] == 2


# ===================================================================
# RED: threat 22 -- second genesis refused AND alerted
# ===================================================================


@pytest.mark.pg

def test_genesis_alerted(pg_url, pg_roles, app_url, owner_url):
    """A second v1 is refused AND writes a sync_alerts row (threat 22)."""
    _need("agg_cp.sync.registry", "store_registry_version")
    from agg_cp.sync.registry import store_registry_version
    _ensure_at_head(pg_url)
    org_id = str(uuid.uuid4())
    sk1, _, _ = _keygen()
    genesis1, _ = _build_genesis(org_id=org_id, admin_sks=[sk1])
    genesis2, _ = _build_genesis(org_id=org_id, admin_sks=[sk1])

    with psycopg.connect(_conninfo(owner_url), autocommit=True) as oconn:
        oconn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        _create_org(oconn, org_id)

    conninfo = _conninfo(app_url)
    with psycopg.connect(conninfo) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, true)", [org_id])
        store_registry_version(conn, org_id, genesis1)
        # Second genesis must raise
        try:
            store_registry_version(conn, org_id, genesis2)
            raise AssertionError("second genesis was not refused")
        except Exception:
            conn.rollback()

    # Check that a sync_alerts row was written
    with psycopg.connect(_conninfo(owner_url)) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, true)", [org_id])
        row = conn.execute(
            "SELECT 1 FROM sync_alerts WHERE org_id = %s AND kind = 'second_genesis'",
            [org_id],
        ).fetchone()
    assert row is not None, "sync_alerts row for second_genesis not found"


# ===================================================================
# RED: cross-org store refused
# ===================================================================


@pytest.mark.pg

def test_cross_org_store_refused(pg_url, pg_roles, app_url, owner_url):
    """Storing a registry for org-B when app.org_id is org-A is refused (threat 29)."""
    _need("agg_cp.sync.registry", "store_registry_version")
    from agg_cp.sync.registry import store_registry_version
    _ensure_at_head(pg_url)
    org_a = str(uuid.uuid4())
    org_b = str(uuid.uuid4())
    sk1, _, _ = _keygen()
    genesis, _ = _build_genesis(org_id=org_b, admin_sks=[sk1])

    with psycopg.connect(_conninfo(owner_url), autocommit=True) as oconn:
        oconn.execute("SELECT set_config('app.org_id', %s, false)", [org_a])
        _create_org(oconn, org_a)
        oconn.execute("SELECT set_config('app.org_id', %s, false)", [org_b])
        _create_org(oconn, org_b)

    conninfo = _conninfo(app_url)
    with psycopg.connect(conninfo) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, true)", [org_a])
        with pytest.raises(Exception):
            store_registry_version(conn, org_a, genesis)


# ===================================================================
# RED: latest with after= filter
# ===================================================================


@pytest.mark.pg

def test_latest_after_filter(pg_url, pg_roles, app_url, owner_url):
    """latest(conn, org, after=N) returns None when no version > N."""
    _need("agg_cp.sync.registry", "latest")
    from agg_cp.sync.registry import store_registry_version, latest
    _ensure_at_head(pg_url)
    org_id = str(uuid.uuid4())
    sk1, _, _ = _keygen()
    genesis, _ = _build_genesis(org_id=org_id, admin_sks=[sk1])

    with psycopg.connect(_conninfo(owner_url), autocommit=True) as oconn:
        oconn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        _create_org(oconn, org_id)

    conninfo = _conninfo(app_url)
    with psycopg.connect(conninfo) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, true)", [org_id])
        store_registry_version(conn, org_id, genesis)
        # after=1 means "give me version > 1", should be None
        result = latest(conn, org_id, after=1)
        assert result is None
        # after=0 means "give me version > 0", should return v1
        result = latest(conn, org_id, after=0)
        assert result is not None
        assert result["payload"]["version"] == 1


# ===================================================================
# RED: invalid envelope refused by server
# ===================================================================


@pytest.mark.pg

def test_store_bad_sig_refused(pg_url, pg_roles, app_url, owner_url):
    """store_registry_version refuses an envelope with a bad signature."""
    _need("agg_cp.sync.registry", "store_registry_version")
    from agg_cp.sync.registry import store_registry_version
    _ensure_at_head(pg_url)
    org_id = str(uuid.uuid4())
    sk1, _, _ = _keygen()
    genesis, _ = _build_genesis(org_id=org_id, admin_sks=[sk1])
    # Flip a byte in the signature
    sig_hex = genesis["signatures"][0]["sig"]
    sig_bytes = bytes.fromhex(sig_hex)
    flipped = bytes([sig_bytes[0] ^ 0xFF]) + sig_bytes[1:]
    genesis["signatures"][0]["sig"] = flipped.hex()

    with psycopg.connect(_conninfo(owner_url), autocommit=True) as oconn:
        oconn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        _create_org(oconn, org_id)

    conninfo = _conninfo(app_url)
    with psycopg.connect(conninfo) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, true)", [org_id])
        with pytest.raises(Exception):
            store_registry_version(conn, org_id, genesis)
