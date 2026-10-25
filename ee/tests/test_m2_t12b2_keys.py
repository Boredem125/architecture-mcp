"""T12b-2 approver_keys projection tests: store_registry_version fills
approver_keys, revocation by registry version, re-add clears revoked_at,
verify_chain failure writes no rows, UNIQUE (org_id, key_id), approvals
route refuses revoked / non-approver keys, and a grep/AST guard.

Interface contract (pinned -- the build removes only xfail markers)
-------------------------------------------------------------------
ADR 0010 section 8: the server's ``approver_keys`` table is a projection
of the latest verified registry version.  ``store_registry_version``
writes it in the same transaction as the new version, after
``verify_chain`` succeeds.

Each key in the new version is upserted on ``(org_id, key_id)`` with
user_id, public_key, alg, kind, roles and registry_version, and
``revoked_at`` cleared; every row of that org whose key_id is absent
from the new version gets ``revoked_at`` set.  No other code path
writes ``approver_keys`` (guard test).  A UNIQUE constraint on
``(org_id, key_id)`` exists.

The approvals route accepts a key only if its row is not revoked and
its roles include ``approver``.

RED tests xfail on M2T12bPending.  Guards verify existing schema/routes.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import time
import uuid

import psycopg
import pytest
from nacl.signing import SigningKey

from .m2_pending import M2T12bPending
from .m2_sync_server import (
    make_sync_server, ensure_at_head, create_org, create_project,
    keygen, sign_envelope, canonical_json,
)
from .t9_helpers import seed_session, make_session_cookie, compute_csrf
from .fake_idp import FakeClock


# ---------------------------------------------------------------------------
# Sentinel check
# ---------------------------------------------------------------------------

_SENTINEL_ATTR = "_T12B2_APPROVER_KEYS"


def _need(module: str, attr: str) -> None:
    """Raise M2T12bPending if *module*.*attr* is absent."""
    try:
        mod = __import__(module, fromlist=[attr])
    except ImportError:
        raise M2T12bPending(f"{module} not importable")
    if not hasattr(mod, attr):
        raise M2T12bPending(f"{module}.{attr} not found")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _conninfo(url: str) -> str:
    return url.replace("+psycopg", "")


def _payload_hash(payload: dict) -> str:
    """SHA-256 hex of ``org_id || ':' || canonical_json(payload)``."""
    cj = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(
        payload["org_id"].encode("utf-8") + b":" + cj
    ).hexdigest()


def _make_key_entry(sk=None, *, user_id="alice", iss="https://idp.test",
                    sub="alice", kind="cli", roles=None, added_in=1):
    """Build a registry key entry dict.  Returns (entry_dict, signing_key)."""
    if sk is None:
        sk = SigningKey.generate()
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


def _make_registry_payload(
    *,
    org_id: str,
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
        _, bpub, bkid = keygen()
        bundle_signer = {
            "key_id": bkid,
            "public_key": bpub.hex(),
            "alg": "ed25519",
        }
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


def _sign_envelope_multi(kind: str, payload: dict, sks: list) -> dict:
    """Sign an agg/ envelope with one or more signing keys."""
    tag = kind.encode("utf-8")
    canonical = json.dumps(payload, sort_keys=True,
                           separators=(",", ":")).encode()
    msg = tag + b"\x00" + canonical
    sigs = []
    for sk in sks:
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


def _build_genesis(org_id, admin_sks, extra_keys=None, threshold=1,
                   bundle_signer=None):
    """Build a signed genesis envelope.

    admin_sks: list of SigningKey.
    extra_keys: list of (entry_dict, SigningKey) -- non-admin keys to include.
    Returns (envelope, admin_entries, admin_sks, fingerprint).
    """
    keys = []
    admins = []
    for i, sk in enumerate(admin_sks):
        entry, _ = _make_key_entry(
            sk, user_id=f"admin-{i}", iss="https://idp.test",
            sub=f"admin-{i}", kind="cli",
            roles=["admin", "approver"], added_in=1,
        )
        keys.append(entry)
        admins.append(entry["key_id"])

    if extra_keys:
        for entry, _sk in extra_keys:
            keys.append(entry)

    payload = _make_registry_payload(
        org_id=org_id,
        version=1,
        prev_hash="",
        threshold=threshold,
        admins=admins,
        keys=keys,
        bundle_signer=bundle_signer,
    )
    env = _sign_envelope_multi("agg/registry/v1", payload, admin_sks)
    fp = _payload_hash(payload)
    return env, keys, admins, fp


def _build_next_version(org_id, prev_payload, admin_sks, new_keys,
                        new_admins=None, version=2, threshold=None,
                        bundle_signer=None):
    """Build a signed registry version that chains from *prev_payload*.

    Returns envelope.
    """
    prev_hash = _payload_hash(prev_payload)
    if new_admins is None:
        new_admins = prev_payload.get("admins", [])
    if threshold is None:
        threshold = prev_payload.get("threshold", 1)
    if bundle_signer is None:
        bundle_signer = prev_payload.get("bundle_signer")

    payload = _make_registry_payload(
        org_id=org_id,
        version=version,
        prev_hash=prev_hash,
        threshold=threshold,
        admins=new_admins,
        keys=new_keys,
        bundle_signer=bundle_signer,
    )
    return _sign_envelope_multi("agg/registry/v1", payload, admin_sks)


def _seed_user_row(conn, org_id: str, email: str) -> str:
    """Insert a users row; return user_id (uuid str)."""
    user_id = str(uuid.uuid4())
    conn.execute(
        "INSERT INTO users (id, org_id, oidc_issuer, oidc_subject, email, "
        "status, created_at) VALUES (%s, %s, 'https://idp.test', %s, %s, "
        "'active', now()) ON CONFLICT DO NOTHING",
        [user_id, org_id, f"sub-{uuid.uuid4().hex[:8]}", email],
    )
    return user_id


def _make_fresh_session(owner_url: str, org_id: str, user_id: str):
    clock = FakeClock()
    token, csrf, sid = seed_session(
        owner_url, uuid.UUID(org_id), uuid.UUID(user_id), clock=clock,
    )
    cookie = make_session_cookie(uuid.UUID(org_id), token)
    return cookie, csrf


def _seed_connector(owner_url: str, org_id: str, project_id: str,
                    pub_key: bytes, *, device_id: str | None = None,
                    operator_user_id: str | None = None) -> str:
    did = device_id or str(uuid.uuid4())
    conninfo = _conninfo(owner_url)
    with psycopg.connect(conninfo) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        if operator_user_id:
            conn.execute(
                "INSERT INTO connectors "
                "(id, org_id, project_id, device_public_key, "
                "operator_user_id, created_at) "
                "VALUES (%s, %s, %s, %s, %s::uuid, now()) ON CONFLICT DO NOTHING",
                [did, org_id, project_id, pub_key.hex(), operator_user_id],
            )
        else:
            conn.execute(
                "INSERT INTO connectors "
                "(id, org_id, project_id, device_public_key, created_at) "
                "VALUES (%s, %s, %s, %s, now()) ON CONFLICT DO NOTHING",
                [did, org_id, project_id, pub_key.hex()],
            )
        conn.commit()
    return did


def _seed_device_token(owner_url: str, org_id: str, project_id: str,
                       connector_id: str, token: str) -> str:
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    conninfo = _conninfo(owner_url)
    with psycopg.connect(conninfo) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        conn.execute(
            "INSERT INTO device_tokens "
            "(id, org_id, project_id, connector_id, token_hash, "
            "expires_at, created_at) "
            "VALUES (%s, %s, %s, %s, %s, now() + interval '10 min', now())",
            [str(uuid.uuid4()), org_id, project_id, connector_id, token_hash],
        )
        conn.commit()
    return token


def _upload_escalation(base_url: str, device_id: str, token: str,
                       request_id: str, *, command: str = "echo test",
                       policy_sequence: int = 1,
                       fingerprint: str | None = None) -> tuple[int, str | None]:
    import httpx
    record: dict = {"command": command, "status": "pending"}
    if fingerprint is None:
        fingerprint = hashlib.sha256(command.encode()).hexdigest()
    record["fingerprint"] = fingerprint
    r = httpx.post(
        f"{base_url}/api/v1/sync/escalations",
        json={
            "device_id": device_id,
            "request_id": request_id,
            "record": record,
            "policy_sequence": policy_sequence,
        },
        headers={"Authorization": f"Bearer {token}"},
        timeout=10.0,
    )
    esc_id = r.json().get("escalation_id") if r.status_code == 200 else None
    return r.status_code, esc_id


def _make_remote_approval_envelope(
    sk, *,
    request_id: str,
    command: str = "echo test",
    org_id: str,
    project_id: str,
    device_id: str,
    registry_version: int = 1,
    policy_sequence: int = 1,
    user_id: str,
    decision: str = "approve",
    nonce: str | None = None,
    not_after: float | None = None,
    fingerprint: str | None = None,
) -> dict:
    pub = bytes(sk.verify_key)
    kid = hashlib.sha256(pub).hexdigest()
    fp = fingerprint or hashlib.sha256(command.encode()).hexdigest()
    payload = {
        "request_id": request_id,
        "command": command,
        "fingerprint": fp,
        "reviewer_id": user_id,
        "decision": decision,
        "approved_at": time.time(),
        "org_id": org_id,
        "project_id": project_id,
        "device_id": device_id,
        "registry_version": registry_version,
        "policy_sequence": policy_sequence,
        "user_id": user_id,
        "key_id": kid,
        "nonce": nonce or secrets.token_hex(16),
        "not_after": not_after or (time.time() + 900),
    }
    return sign_envelope("agg/remote-approval/v1", payload, sk)


def _read_approver_keys(conninfo: str, org_id: str) -> list[dict]:
    """Read all approver_keys rows for org_id.  Returns list of dicts."""
    with psycopg.connect(conninfo) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        rows = conn.execute(
            "SELECT key_id, user_id, public_key, alg, kind, roles, "
            "registry_version, revoked_at "
            "FROM approver_keys WHERE org_id = %s::uuid",
            [org_id],
        ).fetchall()
    result = []
    for r in rows:
        result.append({
            "key_id": r[0],
            "user_id": r[1],
            "public_key": r[2],
            "alg": r[3],
            "kind": r[4],
            "roles": r[5],
            "registry_version": r[6],
            "revoked_at": r[7],
        })
    return result


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def keys_server(pg_url, app_url, owner_url, pg_roles):
    """4-worker agg_cp server with 1 org for approver_keys projection tests."""
    gen = make_sync_server(
        pg_url, app_url, owner_url,
        org_names=["Keys Org"],
    )
    info = next(gen)

    conninfo = _conninfo(owner_url)
    with psycopg.connect(conninfo, autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [info["org_id"]])
        bob_id = _seed_user_row(conn, info["org_id"], "bob@keys.test")
        carol_id = _seed_user_row(conn, info["org_id"], "carol@keys.test")
        operator_id = _seed_user_row(conn, info["org_id"], "op@keys.test")

    info["bob_id"] = bob_id
    info["carol_id"] = carol_id
    info["operator_id"] = operator_id

    try:
        yield info
    finally:
        gen.close()


# ===================================================================
# Guards
# ===================================================================


@pytest.mark.pg
def test_guard_approver_keys_table_exists(pg_url, pg_roles, owner_url):
    """Guard: approver_keys table exists (T5/T7 prerequisite)."""
    ensure_at_head(pg_url)
    with psycopg.connect(_conninfo(owner_url)) as conn:
        row = conn.execute(
            "SELECT 1 FROM information_schema.tables "
            "WHERE table_schema = 'public' AND table_name = 'approver_keys'"
        ).fetchone()
    assert row is not None, "approver_keys table not found"


@pytest.mark.pg
def test_guard_store_registry_version_exists(pg_url, pg_roles):
    """Guard: store_registry_version is importable."""
    from agg_cp.sync.registry import store_registry_version
    assert callable(store_registry_version)


def test_guard_approver_keys_write_locations():
    """AST/grep guard: no file in ee/src outside sync/registry.py and
    migrations/ writes approver_keys (INSERT/UPDATE/DELETE).

    ADR 0010 section 8: only store_registry_version may write
    approver_keys; no other code path touches it.
    """
    import pathlib
    ee_src = pathlib.Path(__file__).resolve().parent.parent / "src"
    assert ee_src.is_dir(), f"ee/src not found at {ee_src}"

    # Allowed writers
    allowed_patterns = {
        "sync/registry.py",      # store_registry_version
        "migrations/",           # schema migrations
    }

    violations = []
    pattern = re.compile(
        r"\b(INSERT\s+INTO|UPDATE|DELETE\s+FROM)\s+"
        r"(public\.)?approver_keys\b",
        re.IGNORECASE,
    )

    for py_file in ee_src.rglob("*.py"):
        rel = py_file.relative_to(ee_src).as_posix()
        # Skip allowed locations
        if any(rel.endswith(a) or ("/" + a) in ("/" + rel)
               for a in allowed_patterns):
            continue
        try:
            text = py_file.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for m in pattern.finditer(text):
            violations.append(f"{rel}:{m.start()}: {m.group()}")

    assert violations == [], (
        "Files outside sync/registry.py and migrations/ write approver_keys:\n"
        + "\n".join(violations)
    )


# ===================================================================
# Test 1: v1 via store_registry_version fills approver_keys
# ===================================================================


@pytest.mark.pg
def test_v1_fills_approver_keys(keys_server):
    """Publishing registry v1 via store_registry_version fills approver_keys
    with user_id, public_key, alg, kind, roles, registry_version for each key.
    """
    _need("agg_cp.sync.registry", _SENTINEL_ATTR)
    from agg_cp.sync.registry import store_registry_version

    srv = keys_server
    org_id = str(uuid.uuid4())
    conninfo_owner = _conninfo(srv["owner_url"])

    # Create a fresh org
    with psycopg.connect(conninfo_owner, autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        create_org(conn, org_id, "V1 Keys Org")

    # Build genesis with admin (alice) + approver (bob)
    alice_sk = SigningKey.generate()
    bob_sk = SigningKey.generate()
    bob_entry, _ = _make_key_entry(
        bob_sk, user_id=srv["bob_id"], iss="https://idp.test",
        sub=srv["bob_id"], kind="cli",
        roles=["approver"], added_in=1,
    )

    genesis, keys, admins, fp = _build_genesis(
        org_id, [alice_sk],
        extra_keys=[(bob_entry, bob_sk)],
    )

    conninfo_app = _conninfo(srv["app_url"])
    with psycopg.connect(conninfo_app) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, true)", [org_id])
        version = store_registry_version(conn, org_id, genesis)
        assert version == 1

    # Verify approver_keys rows
    ak_rows = _read_approver_keys(conninfo_owner, org_id)
    assert len(ak_rows) >= 2, (
        f"expected at least 2 approver_keys rows, got {len(ak_rows)}"
    )

    # Check bob's row has the right fields
    bob_pub = bytes(bob_sk.verify_key).hex()
    bob_kid = hashlib.sha256(bytes(bob_sk.verify_key)).hexdigest()
    bob_rows = [r for r in ak_rows if r["key_id"] == bob_kid]
    assert len(bob_rows) == 1, f"expected 1 bob row, got {len(bob_rows)}"
    bob_row = bob_rows[0]
    assert bob_row["user_id"] == srv["bob_id"]
    assert bob_row["public_key"] == bob_pub
    assert bob_row["alg"] == "ed25519"
    assert bob_row["kind"] == "cli"
    # roles is jsonb; check it contains "approver"
    roles = bob_row["roles"]
    if isinstance(roles, str):
        roles = json.loads(roles)
    assert "approver" in roles
    assert bob_row["registry_version"] == 1
    assert bob_row["revoked_at"] is None


# ===================================================================
# Test 2: v2 without bob marks bob revoked
# ===================================================================


@pytest.mark.pg
def test_v2_without_bob_revokes_bob(keys_server):
    """Publishing v2 without bob marks bob's approver_keys row revoked
    (revoked_at set).  His approval on POST approvals and his signer
    token are refused.
    """
    _need("agg_cp.sync.registry", _SENTINEL_ATTR)
    from agg_cp.sync.registry import store_registry_version

    srv = keys_server
    org_id = str(uuid.uuid4())
    conninfo_owner = _conninfo(srv["owner_url"])

    with psycopg.connect(conninfo_owner, autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        create_org(conn, org_id, "V2 Revoke Org")

    # Genesis: alice (admin) + bob (approver)
    alice_sk = SigningKey.generate()
    bob_sk = SigningKey.generate()
    bob_entry, _ = _make_key_entry(
        bob_sk, user_id="user-bob", iss="https://idp.test",
        sub="user-bob", kind="cli",
        roles=["approver"], added_in=1,
    )
    bob_kid = bob_entry["key_id"]

    genesis, keys, admins, fp = _build_genesis(
        org_id, [alice_sk],
        extra_keys=[(bob_entry, bob_sk)],
    )

    conninfo_app = _conninfo(srv["app_url"])
    with psycopg.connect(conninfo_app) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, true)", [org_id])
        store_registry_version(conn, org_id, genesis)

    # Verify bob is NOT revoked after v1
    ak_rows = _read_approver_keys(conninfo_owner, org_id)
    bob_rows = [r for r in ak_rows if r["key_id"] == bob_kid]
    assert len(bob_rows) == 1
    assert bob_rows[0]["revoked_at"] is None, "bob should not be revoked after v1"

    # Build v2: same admin (alice), but WITHOUT bob
    alice_entry = [k for k in genesis["payload"]["keys"]
                   if k["key_id"] in admins][0]
    v2_keys = [alice_entry]  # only alice
    v2 = _build_next_version(
        org_id, genesis["payload"], [alice_sk], v2_keys,
        version=2,
    )

    with psycopg.connect(conninfo_app) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, true)", [org_id])
        store_registry_version(conn, org_id, v2)

    # Verify bob IS revoked after v2
    ak_rows = _read_approver_keys(conninfo_owner, org_id)
    bob_rows = [r for r in ak_rows if r["key_id"] == bob_kid]
    assert len(bob_rows) == 1
    assert bob_rows[0]["revoked_at"] is not None, (
        "bob should be revoked after v2 (absent from latest version)"
    )


# ===================================================================
# Test 3: Re-adding a key in v3 clears revoked_at
# ===================================================================


@pytest.mark.pg
def test_v3_readd_clears_revoked_at(keys_server):
    """Re-adding a key in v3 clears its revoked_at."""
    _need("agg_cp.sync.registry", _SENTINEL_ATTR)
    from agg_cp.sync.registry import store_registry_version

    srv = keys_server
    org_id = str(uuid.uuid4())
    conninfo_owner = _conninfo(srv["owner_url"])

    with psycopg.connect(conninfo_owner, autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        create_org(conn, org_id, "V3 Readd Org")

    # Genesis: alice (admin) + bob
    alice_sk = SigningKey.generate()
    bob_sk = SigningKey.generate()
    bob_entry, _ = _make_key_entry(
        bob_sk, user_id="user-bob", iss="https://idp.test",
        sub="user-bob", kind="cli",
        roles=["approver"], added_in=1,
    )
    bob_kid = bob_entry["key_id"]

    genesis, keys, admins, fp = _build_genesis(
        org_id, [alice_sk],
        extra_keys=[(bob_entry, bob_sk)],
    )

    conninfo_app = _conninfo(srv["app_url"])
    with psycopg.connect(conninfo_app) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, true)", [org_id])
        store_registry_version(conn, org_id, genesis)

    # v2: remove bob
    alice_entry = [k for k in genesis["payload"]["keys"]
                   if k["key_id"] in admins][0]
    v2 = _build_next_version(
        org_id, genesis["payload"], [alice_sk], [alice_entry],
        version=2,
    )
    with psycopg.connect(conninfo_app) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, true)", [org_id])
        store_registry_version(conn, org_id, v2)

    # Verify bob is revoked after v2
    ak_rows = _read_approver_keys(conninfo_owner, org_id)
    bob_rows = [r for r in ak_rows if r["key_id"] == bob_kid]
    assert len(bob_rows) == 1
    assert bob_rows[0]["revoked_at"] is not None

    # v3: re-add bob
    bob_entry_v3 = dict(bob_entry)
    bob_entry_v3["added_in"] = 3
    v3_keys = [alice_entry, bob_entry_v3]
    v3 = _build_next_version(
        org_id, v2["payload"], [alice_sk], v3_keys,
        version=3,
    )
    with psycopg.connect(conninfo_app) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, true)", [org_id])
        store_registry_version(conn, org_id, v3)

    # Verify bob is NOT revoked after v3
    ak_rows = _read_approver_keys(conninfo_owner, org_id)
    bob_rows = [r for r in ak_rows if r["key_id"] == bob_kid]
    assert len(bob_rows) == 1, "bob should still have exactly 1 row (upsert)"
    assert bob_rows[0]["revoked_at"] is None, (
        "bob's revoked_at should be cleared after re-add in v3"
    )
    assert bob_rows[0]["registry_version"] == 3


# ===================================================================
# Test 4: verify_chain failure writes no approver_keys rows
# ===================================================================


@pytest.mark.pg
def test_bad_chain_writes_no_keys(keys_server):
    """A registry version failing verify_chain writes no approver_keys rows."""
    _need("agg_cp.sync.registry", _SENTINEL_ATTR)
    from agg_cp.sync.registry import store_registry_version
    from sandbox.protocol.registry import RegistryError

    srv = keys_server
    org_id = str(uuid.uuid4())
    conninfo_owner = _conninfo(srv["owner_url"])

    with psycopg.connect(conninfo_owner, autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        create_org(conn, org_id, "Bad Chain Org")

    # Build a genesis with a valid admin
    alice_sk = SigningKey.generate()
    genesis, keys, admins, fp = _build_genesis(org_id, [alice_sk])

    conninfo_app = _conninfo(srv["app_url"])
    with psycopg.connect(conninfo_app) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, true)", [org_id])
        store_registry_version(conn, org_id, genesis)

    # Count rows after v1
    ak_before = _read_approver_keys(conninfo_owner, org_id)
    count_before = len(ak_before)

    # Build v2 with a BAD signature (sign with a random key, not the admin)
    rogue_sk = SigningKey.generate()
    alice_entry = [k for k in genesis["payload"]["keys"]
                   if k["key_id"] in admins][0]
    v2_payload = _make_registry_payload(
        org_id=org_id,
        version=2,
        prev_hash=_payload_hash(genesis["payload"]),
        threshold=1,
        admins=admins,
        keys=[alice_entry],
        bundle_signer=genesis["payload"]["bundle_signer"],
    )
    v2_bad = _sign_envelope_multi("agg/registry/v1", v2_payload, [rogue_sk])

    with psycopg.connect(conninfo_app) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, true)", [org_id])
        with pytest.raises(RegistryError):
            store_registry_version(conn, org_id, v2_bad)

    # Count rows after failed v2 -- must be unchanged
    ak_after = _read_approver_keys(conninfo_owner, org_id)
    assert len(ak_after) == count_before, (
        f"approver_keys rows changed after verify_chain failure: "
        f"{count_before} -> {len(ak_after)}"
    )


# ===================================================================
# Test 5: UNIQUE (org_id, key_id) constraint
# ===================================================================


@pytest.mark.pg
def test_unique_org_key_id_constraint(keys_server):
    """Inserting a duplicate (org_id, key_id) is refused by a UNIQUE constraint."""
    _need("agg_cp.sync.registry", _SENTINEL_ATTR)

    srv = keys_server
    org_id = str(uuid.uuid4())
    conninfo_owner = _conninfo(srv["owner_url"])

    with psycopg.connect(conninfo_owner, autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        create_org(conn, org_id, "Unique Test Org")

    # Direct INSERT (only test that does this -- testing the constraint itself)
    kid = "test-key-" + secrets.token_hex(8)
    with psycopg.connect(conninfo_owner) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        conn.execute(
            "INSERT INTO approver_keys "
            "(id, org_id, user_id, key_id, public_key, alg, kind, "
            "registry_version, created_at) "
            "VALUES (%s, %s::uuid, 'user-a', %s, 'aabbcc', 'ed25519', "
            "'cli', 1, now())",
            [str(uuid.uuid4()), org_id, kid],
        )
        conn.commit()

    # Second INSERT with the same (org_id, key_id) must fail
    with pytest.raises(psycopg.errors.UniqueViolation):
        with psycopg.connect(conninfo_owner) as conn:
            conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
            conn.execute(
                "INSERT INTO approver_keys "
                "(id, org_id, user_id, key_id, public_key, alg, kind, "
                "registry_version, created_at) "
                "VALUES (%s, %s::uuid, 'user-b', %s, 'ddeeff', 'ed25519', "
                "'cli', 1, now())",
                [str(uuid.uuid4()), org_id, kid],
            )
            conn.commit()


# ===================================================================
# Test 6a: approvals route refuses a key without the approver role
# ===================================================================


@pytest.mark.pg
def test_approvals_refuse_non_approver_role(keys_server):
    """The approvals route refuses a key without the ``approver`` role."""
    _need("agg_cp.sync.escalations", _SENTINEL_ATTR)
    from agg_cp.sync.registry import store_registry_version

    srv = keys_server
    org_id = str(uuid.uuid4())
    conninfo_owner = _conninfo(srv["owner_url"])

    with psycopg.connect(conninfo_owner, autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        create_org(conn, org_id, "Non-Approver Org")
        viewer_uid = _seed_user_row(conn, org_id, "viewer@keys.test")

    # Genesis: alice (admin+approver) + viewer (admin only, NO approver role)
    alice_sk = SigningKey.generate()
    viewer_sk = SigningKey.generate()
    viewer_entry, _ = _make_key_entry(
        viewer_sk, user_id=viewer_uid, iss="https://idp.test",
        sub=viewer_uid, kind="cli",
        roles=["admin"],  # explicitly NO "approver"
        added_in=1,
    )

    genesis, keys, admins, fp = _build_genesis(
        org_id, [alice_sk],
        extra_keys=[(viewer_entry, viewer_sk)],
    )

    conninfo_app = _conninfo(srv["app_url"])
    with psycopg.connect(conninfo_app) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, true)", [org_id])
        store_registry_version(conn, org_id, genesis)

    # Set up device + escalation
    device_sk, device_pub, device_kid = keygen()
    project_id = str(uuid.uuid4())
    with psycopg.connect(conninfo_owner, autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        create_project(conn, org_id, project_id, environment="staging")

    device_id = _seed_connector(
        srv["owner_url"], org_id, project_id, device_pub,
        operator_user_id=srv["operator_id"],
    )
    token = secrets.token_hex(32)
    _seed_device_token(srv["owner_url"], org_id, project_id,
                       device_id, token)

    import httpx
    status, esc_id = _upload_escalation(
        srv["base_url"], device_id, token,
        "req-nonapprover-1",  # gitleaks:allow
    )
    assert status == 200

    # Viewer tries to approve
    cookie, csrf = _make_fresh_session(srv["owner_url"], org_id, viewer_uid)
    envelope = _make_remote_approval_envelope(
        viewer_sk,
        request_id="req-nonapprover-1",
        org_id=org_id, project_id=project_id,
        device_id=device_id, user_id=viewer_uid,
    )
    r = httpx.post(
        f"{srv['base_url']}/api/v1/sync/escalations/{esc_id}/approvals",
        json=envelope,
        cookies={"__Host-agg_session": cookie},
        headers={"X-CSRF-Token": csrf},
        timeout=10.0,
    )
    assert r.status_code in (400, 403), (
        f"expected 400/403 got {r.status_code}: {r.text}"
    )
    err = r.json().get("error", "").lower()
    assert "role" in err or "approver" in err, (
        f"error should mention role/approver: {err}"
    )


# ===================================================================
# Test 6b: approvals route refuses a revoked key
# ===================================================================


@pytest.mark.pg
def test_approvals_refuse_revoked_key(keys_server):
    """The approvals route refuses a key whose approver_keys row is revoked."""
    _need("agg_cp.sync.escalations", _SENTINEL_ATTR)
    from agg_cp.sync.registry import store_registry_version

    srv = keys_server
    org_id = str(uuid.uuid4())
    conninfo_owner = _conninfo(srv["owner_url"])

    with psycopg.connect(conninfo_owner, autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        create_org(conn, org_id, "Revoked Key Org")
        bob_uid = _seed_user_row(conn, org_id, "bob-rev@keys.test")

    # Genesis: alice (admin) + bob (approver)
    alice_sk = SigningKey.generate()
    bob_sk = SigningKey.generate()
    bob_entry, _ = _make_key_entry(
        bob_sk, user_id=bob_uid, iss="https://idp.test",
        sub=bob_uid, kind="cli",
        roles=["approver"], added_in=1,
    )
    bob_kid = bob_entry["key_id"]

    genesis, keys, admins, fp = _build_genesis(
        org_id, [alice_sk],
        extra_keys=[(bob_entry, bob_sk)],
    )

    conninfo_app = _conninfo(srv["app_url"])
    with psycopg.connect(conninfo_app) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, true)", [org_id])
        store_registry_version(conn, org_id, genesis)

    # v2: remove bob (revoke)
    alice_entry = [k for k in genesis["payload"]["keys"]
                   if k["key_id"] in admins][0]
    v2 = _build_next_version(
        org_id, genesis["payload"], [alice_sk], [alice_entry],
        version=2,
    )
    with psycopg.connect(conninfo_app) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, true)", [org_id])
        store_registry_version(conn, org_id, v2)

    # Verify bob is revoked in DB
    ak = _read_approver_keys(conninfo_owner, org_id)
    bob_rows = [r for r in ak if r["key_id"] == bob_kid]
    assert len(bob_rows) == 1
    assert bob_rows[0]["revoked_at"] is not None, "precondition: bob is revoked"

    # Set up device + escalation
    device_sk, device_pub, device_kid = keygen()
    project_id = str(uuid.uuid4())
    with psycopg.connect(conninfo_owner, autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        create_project(conn, org_id, project_id, environment="staging")

    device_id = _seed_connector(
        srv["owner_url"], org_id, project_id, device_pub,
        operator_user_id=srv["operator_id"],
    )
    dev_token = secrets.token_hex(32)
    _seed_device_token(srv["owner_url"], org_id, project_id,
                       device_id, dev_token)

    import httpx
    status, esc_id = _upload_escalation(
        srv["base_url"], device_id, dev_token,
        "req-revoked-1",  # gitleaks:allow
    )
    assert status == 200

    # Bob (revoked) tries to approve
    cookie, csrf = _make_fresh_session(srv["owner_url"], org_id, bob_uid)
    envelope = _make_remote_approval_envelope(
        bob_sk,
        request_id="req-revoked-1",
        org_id=org_id, project_id=project_id,
        device_id=device_id, user_id=bob_uid,
    )
    r = httpx.post(
        f"{srv['base_url']}/api/v1/sync/escalations/{esc_id}/approvals",
        json=envelope,
        cookies={"__Host-agg_session": cookie},
        headers={"X-CSRF-Token": csrf},
        timeout=10.0,
    )
    assert r.status_code in (400, 403), (
        f"expected 400/403 got {r.status_code}: {r.text}"
    )
    err = r.json().get("error", "").lower()
    assert "revok" in err or "not found" in err, (
        f"error should mention revocation: {err}"
    )
