"""T11 ee tests-first: audit upload, checkpoint, quarantine, device_silent,
and audit verify routes through the real agg_cp app with Postgres.

Interface contract (pinned -- the build removes only xfail markers)
-------------------------------------------------------------------
Server routes (agg_cp.sync.audit_upload):

    POST /api/v1/sync/audit
        Auth: device token (Authorization: Bearer <token>).
        Body: {session_id: str, records: [{chain_length, previous_hash,
               record_hash, body: {...}}]}
        Server checks (D3.2):
          - previous_hash == stored head for (connector_id, session_id)
          - chain_length == head + 1
          - Same position + same hash = no-op
          - Same position + different hash = fork -> audit_quarantine row
          - Gap = refused (400)
        200: {server_head: {session_id, chain_length, head_hash}}
        400: gap / chain_broken
        409: fork (quarantined, alert in sync_alerts)

    POST /api/v1/sync/checkpoint
        Auth: device token.
        Body: envelope (agg/audit-head/v1), device-signed.
        payload: {device_id, upload_seq, sessions: [{session_id,
                  chain_length, head_hash}], ts}
        Server checks (D3.3):
          - Signature by the device key
          - upload_seq == last stored + 1 (skip and repeat refused)
          - For each session: chain_length < previous checkpoint's
            chain_length -> truncation alert
          - A session listed earlier but missing later -> session_missing
            alert
        200: {upload_seq: int}
        400: invalid_signature / seq_skip / seq_repeat

    agg_cp.cli.main(["audit", "verify", "--project", <project_id>])
        CLI subcommand (D3.4).  Exit 0 on a clean project; non-zero
        with gap rows on a gap.  No HTTP route for verify.

    agg_cp.sync.audit.sweep_device_silent(conn, now)
        Pure function (D3.5, N6, threat 35).  Scans connectors whose
        last checkpoint is older than 3 x poll (180 s, configurable).
        Inserts a ``device_silent`` alert into sync_alerts.  A periodic
        task calls it, but tests call the function with an injected ``now``.

Schema tables (from 0007_m2_tables.py):
    audit_records: id, org_id, connector_id, session_id, chain_length,
                   previous_hash, record_hash, body, created_at
                   UNIQUE (connector_id, session_id, chain_length)
    audit_heads:   id, org_id, connector_id, upload_seq, session_list,
                   head_hash, signature, created_at
                   UNIQUE (connector_id, upload_seq)
    audit_quarantine: id, org_id, connector_id, kind, detail, created_at
    sync_alerts:   id, org_id, project_id, connector_id, kind, detail,
                   created_at

Uses the T5 tables via ee conftest fixtures (pg_url, pg_roles, owner_url,
app_url).

RED tests xfail on M2T11Pending.  Guards verify the T5 schema baseline.

Node-id patterns follow M2_BASELINE.md section 5:
  32 -> test_session_missing_alert
  35 -> test_device_silent_after_missed_window

Threat coverage (server side): 15 (truncation detected), 16 (fork ->
quarantine, chain intact), 17 (checkpoint replay / skip refused),
18 (verify --project), 32 (session_missing), 35 (device_silent).
"""
from __future__ import annotations

import hashlib
import json
import secrets
import time
import uuid

import psycopg
import pytest
from nacl.signing import SigningKey

from .m2_pending import M2T11Pending
from .m2_sync_server import (
    make_sync_server, ensure_at_head, create_org, create_project,
    keygen, sign_envelope, canonical_json,
)
from .t8p2_helpers import (
    seed_org_with_oidc, seed_user, seed_admin_binding,
    make_test_app,
)
from .t9_helpers import seed_session, make_session_cookie
from .fake_idp import FakeClock


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _need(module: str, attr: str) -> None:
    """Raise M2T11Pending if *module*.*attr* is absent."""
    try:
        mod = __import__(module, fromlist=[attr])
    except ImportError:
        raise M2T11Pending(f"{module} not importable")
    if not hasattr(mod, attr):
        raise M2T11Pending(f"{module}.{attr} not found")


def _conninfo(url: str) -> str:
    return url.replace("+psycopg", "")


def _seed_connector(owner_url: str, org_id: str, project_id: str,
                    pub_key: bytes, *, device_id: str | None = None,
                    ) -> str:
    """Insert a connectors row directly (superuser) and return device_id."""
    did = device_id or str(uuid.uuid4())
    kid = hashlib.sha256(pub_key).hexdigest()
    conninfo = _conninfo(owner_url)
    with psycopg.connect(conninfo) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
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
    """Insert a device_tokens row and return the token."""
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


def _make_audit_record(session_id: str, chain_length: int,
                       previous_hash: str, event: str = "test") -> dict:
    """Build a single audit record with correct record_hash."""
    body = {"event": event, "ts": time.time(), "seq": chain_length}
    body_bytes = json.dumps(body, separators=(",", ":"),
                            sort_keys=True).encode()
    record_hash = hashlib.sha256(body_bytes).hexdigest()
    return {
        "session_id": session_id,
        "chain_length": chain_length,
        "previous_hash": previous_hash,
        "record_hash": record_hash,
        "body": body,
    }


def _make_audit_chain(session_id: str, count: int) -> list[dict]:
    """Build a valid chain of *count* records."""
    records = []
    prev_hash = ""
    for i in range(1, count + 1):
        rec = _make_audit_record(session_id, i, prev_hash)
        records.append(rec)
        prev_hash = rec["record_hash"]
    return records


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def audit_server(pg_url, app_url, owner_url, pg_roles):
    """4-worker agg_cp server with 2 orgs for audit tests."""
    yield from make_sync_server(
        pg_url, app_url, owner_url,
        org_names=["Audit Org", "Evil Org"],
    )


# ===================================================================
# Guards: schema baseline
# ===================================================================


@pytest.mark.pg
def test_guard_audit_records_table_exists(pg_url, pg_roles, owner_url):
    """Guard: audit_records table exists in the schema."""
    ensure_at_head(pg_url)
    with psycopg.connect(_conninfo(owner_url)) as conn:
        row = conn.execute(
            "SELECT 1 FROM information_schema.tables "
            "WHERE table_name = 'audit_records'"
        ).fetchone()
        assert row is not None, "audit_records table missing"


@pytest.mark.pg
def test_guard_audit_heads_table_exists(pg_url, pg_roles, owner_url):
    """Guard: audit_heads table exists in the schema."""
    ensure_at_head(pg_url)
    with psycopg.connect(_conninfo(owner_url)) as conn:
        row = conn.execute(
            "SELECT 1 FROM information_schema.tables "
            "WHERE table_name = 'audit_heads'"
        ).fetchone()
        assert row is not None, "audit_heads table missing"


@pytest.mark.pg
def test_guard_audit_quarantine_table_exists(pg_url, pg_roles, owner_url):
    """Guard: audit_quarantine table exists in the schema."""
    ensure_at_head(pg_url)
    with psycopg.connect(_conninfo(owner_url)) as conn:
        row = conn.execute(
            "SELECT 1 FROM information_schema.tables "
            "WHERE table_name = 'audit_quarantine'"
        ).fetchone()
        assert row is not None, "audit_quarantine table missing"


@pytest.mark.pg
def test_guard_audit_records_append_only(pg_url, pg_roles, owner_url):
    """Guard: audit_records table has append-only triggers (no UPDATE/DELETE)."""
    ensure_at_head(pg_url)
    org_id = str(uuid.uuid4())
    rec_id = str(uuid.uuid4())
    connector_id = str(uuid.uuid4())
    with psycopg.connect(_conninfo(owner_url)) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        # Insert a test row (as agg_owner with matching org_id)
        conn.execute(
            "INSERT INTO audit_records "
            "(id, org_id, connector_id, session_id, chain_length, "
            "previous_hash, record_hash, created_at) "
            "VALUES (%s, %s, %s, 'test', 1, '', 'h1', now())",
            [rec_id, org_id, connector_id],
        )
        conn.commit()

        # UPDATE should fail (trigger)
        with pytest.raises(psycopg.errors.RaiseException,
                           match="UPDATE.*forbidden"):
            conn.execute(
                "UPDATE audit_records SET record_hash = 'tampered' "
                "WHERE id = %s", [rec_id]
            )
        conn.rollback()

        # DELETE should fail (trigger)
        with pytest.raises(psycopg.errors.RaiseException,
                           match="DELETE.*forbidden"):
            conn.execute("DELETE FROM audit_records WHERE id = %s", [rec_id])
        conn.rollback()


@pytest.mark.pg
def test_guard_audit_quarantine_append_only(pg_url, pg_roles, owner_url):
    """Guard: audit_quarantine has append-only triggers."""
    ensure_at_head(pg_url)
    org_id = str(uuid.uuid4())
    q_id = str(uuid.uuid4())
    with psycopg.connect(_conninfo(owner_url)) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        conn.execute(
            "INSERT INTO audit_quarantine "
            "(id, org_id, connector_id, kind, detail, created_at) "
            "VALUES (%s, %s, %s, 'test', '{}'::jsonb, now())",
            [q_id, org_id, str(uuid.uuid4())],
        )
        conn.commit()

        with pytest.raises(psycopg.errors.RaiseException,
                           match="UPDATE.*forbidden"):
            conn.execute(
                "UPDATE audit_quarantine SET kind = 'tampered' "
                "WHERE id = %s", [q_id]
            )
        conn.rollback()


# ===================================================================
# RED: POST /api/v1/sync/audit -- chain continuity (D3.2)
# ===================================================================


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M2T11Pending)
def test_audit_upload_success(audit_server):
    """Upload 3 audit records successfully (D3.2).

    Records for one session are accepted in order and the server
    returns the head.
    """
    _need("agg_cp.sync.audit_upload", "audit_upload_router")
    info = audit_server
    sk, pub, kid = keygen()
    org_id = info["org_id"]
    project_id = str(uuid.uuid4())

    with psycopg.connect(_conninfo(info["owner_url"]), autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        create_project(conn, org_id, project_id)

    device_id = _seed_connector(info["owner_url"], org_id, project_id, pub)
    token = secrets.token_urlsafe(32)
    _seed_device_token(info["owner_url"], org_id, project_id, device_id, token)

    records = _make_audit_chain("sess-1", 3)

    import httpx
    with httpx.Client(base_url=info["base_url"], timeout=10) as client:
        resp = client.post(
            "/api/v1/sync/audit",
            headers={"Authorization": f"Bearer {token}"},
            json={"session_id": "sess-1", "records": records},
        )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["server_head"]["session_id"] == "sess-1"
    assert body["server_head"]["chain_length"] == 3


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M2T11Pending)
def test_audit_upload_fork_quarantined(audit_server):
    """A fork (same position, different hash) is quarantined (D3.2, threat 16).

    Upload 3 records, then upload a different record at chain_length 2.
    The server returns 409 and the record is in audit_quarantine.  The
    original chain is intact.
    """
    _need("agg_cp.sync.audit_upload", "audit_upload_router")
    info = audit_server
    sk, pub, kid = keygen()
    org_id = info["org_id"]
    project_id = str(uuid.uuid4())

    with psycopg.connect(_conninfo(info["owner_url"]), autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        create_project(conn, org_id, project_id)

    device_id = _seed_connector(info["owner_url"], org_id, project_id, pub)
    token = secrets.token_urlsafe(32)
    _seed_device_token(info["owner_url"], org_id, project_id, device_id, token)

    records = _make_audit_chain("sess-fork", 3)

    import httpx
    with httpx.Client(base_url=info["base_url"], timeout=10) as client:
        # Upload original chain
        resp = client.post(
            "/api/v1/sync/audit",
            headers={"Authorization": f"Bearer {token}"},
            json={"session_id": "sess-fork", "records": records},
        )
        assert resp.status_code == 200

        # Upload a forked record at chain_length 2
        forked_rec = _make_audit_record("sess-fork", 2,
                                         records[0]["record_hash"],
                                         event="forked_event")
        forked_rec["record_hash"] = "forked_hash_different"

        resp2 = client.post(
            "/api/v1/sync/audit",
            headers={"Authorization": f"Bearer {token}"},
            json={"session_id": "sess-fork", "records": [forked_rec]},
        )
        assert resp2.status_code == 409, f"Expected 409 fork, got {resp2.status_code}"

    # Verify quarantine entry exists
    with psycopg.connect(_conninfo(info["owner_url"])) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        row = conn.execute(
            "SELECT kind FROM audit_quarantine WHERE connector_id = %s",
            [device_id],
        ).fetchone()
        assert row is not None, "No quarantine entry found"
        assert row[0] == "fork"


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M2T11Pending)
def test_audit_upload_gap_refused(audit_server):
    """A gap in chain_length is refused (D3.2).

    Skip chain_length 1 and upload chain_length 2 directly.
    """
    _need("agg_cp.sync.audit_upload", "audit_upload_router")
    info = audit_server
    sk, pub, kid = keygen()
    org_id = info["org_id"]
    project_id = str(uuid.uuid4())

    with psycopg.connect(_conninfo(info["owner_url"]), autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        create_project(conn, org_id, project_id)

    device_id = _seed_connector(info["owner_url"], org_id, project_id, pub)
    token = secrets.token_urlsafe(32)
    _seed_device_token(info["owner_url"], org_id, project_id, device_id, token)

    # Start at chain_length 2 (gap: missing 1)
    rec = _make_audit_record("sess-gap", 2, "some_hash")

    import httpx
    with httpx.Client(base_url=info["base_url"], timeout=10) as client:
        resp = client.post(
            "/api/v1/sync/audit",
            headers={"Authorization": f"Bearer {token}"},
            json={"session_id": "sess-gap", "records": [rec]},
        )
    assert resp.status_code == 400, f"Expected 400 gap, got {resp.status_code}"


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M2T11Pending)
def test_audit_upload_noop_same_hash(audit_server):
    """Same position + same hash = no-op (D3.2).

    Upload 3 records, then re-upload the same 3.
    """
    _need("agg_cp.sync.audit_upload", "audit_upload_router")
    info = audit_server
    sk, pub, kid = keygen()
    org_id = info["org_id"]
    project_id = str(uuid.uuid4())

    with psycopg.connect(_conninfo(info["owner_url"]), autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        create_project(conn, org_id, project_id)

    device_id = _seed_connector(info["owner_url"], org_id, project_id, pub)
    token = secrets.token_urlsafe(32)
    _seed_device_token(info["owner_url"], org_id, project_id, device_id, token)

    records = _make_audit_chain("sess-noop", 3)

    import httpx
    with httpx.Client(base_url=info["base_url"], timeout=10) as client:
        # Upload
        resp1 = client.post(
            "/api/v1/sync/audit",
            headers={"Authorization": f"Bearer {token}"},
            json={"session_id": "sess-noop", "records": records},
        )
        assert resp1.status_code == 200

        # Re-upload same
        resp2 = client.post(
            "/api/v1/sync/audit",
            headers={"Authorization": f"Bearer {token}"},
            json={"session_id": "sess-noop", "records": records},
        )
        assert resp2.status_code == 200


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M2T11Pending)
def test_audit_upload_cross_org_refused(audit_server):
    """An audit upload for a different org gets 404 / 401 (cross-tenant).

    The device token is bound to org A; the upload must not succeed
    against org B's data.
    """
    _need("agg_cp.sync.audit_upload", "audit_upload_router")
    info = audit_server
    sk, pub, kid = keygen()
    org_id = info["org_id"]
    evil_org_id = info["org_evil"]
    project_id = str(uuid.uuid4())

    with psycopg.connect(_conninfo(info["owner_url"]), autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        create_project(conn, org_id, project_id)

    device_id = _seed_connector(info["owner_url"], org_id, project_id, pub)
    token = secrets.token_urlsafe(32)
    _seed_device_token(info["owner_url"], org_id, project_id, device_id, token)

    records = _make_audit_chain("sess-xorg", 2)

    # Upload using org A's token -- should work
    import httpx
    with httpx.Client(base_url=info["base_url"], timeout=10) as client:
        resp = client.post(
            "/api/v1/sync/audit",
            headers={"Authorization": f"Bearer {token}"},
            json={"session_id": "sess-xorg", "records": records},
        )
        assert resp.status_code == 200

    # Verify that org B cannot see org A's audit_records via RLS
    with psycopg.connect(_conninfo(info["owner_url"])) as conn:
        conn.execute("RESET ROLE")
        conn.execute("SET ROLE agg_app")
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [evil_org_id])
        count = conn.execute(
            "SELECT count(*) FROM audit_records WHERE connector_id = %s",
            [device_id],
        ).fetchone()[0]
        assert count == 0, f"Evil org can see {count} audit_records via RLS"


# ===================================================================
# RED: POST /api/v1/sync/checkpoint (D3.3)
# ===================================================================


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M2T11Pending)
def test_checkpoint_upload_success(audit_server):
    """A valid device-signed checkpoint is accepted (D3.3)."""
    _need("agg_cp.sync.audit_upload", "audit_upload_router")
    info = audit_server
    sk, pub, kid = keygen()
    org_id = info["org_id"]
    project_id = str(uuid.uuid4())

    with psycopg.connect(_conninfo(info["owner_url"]), autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        create_project(conn, org_id, project_id)

    device_id = _seed_connector(info["owner_url"], org_id, project_id, pub)
    token = secrets.token_urlsafe(32)
    _seed_device_token(info["owner_url"], org_id, project_id, device_id, token)

    checkpoint_payload = {
        "device_id": device_id,
        "upload_seq": 1,
        "sessions": [
            {"session_id": "sess-1", "chain_length": 5, "head_hash": "h5"},
        ],
        "ts": time.time(),
    }
    envelope = sign_envelope("agg/audit-head/v1", checkpoint_payload, sk)

    import httpx
    with httpx.Client(base_url=info["base_url"], timeout=10) as client:
        resp = client.post(
            "/api/v1/sync/checkpoint",
            headers={"Authorization": f"Bearer {token}"},
            json=envelope,
        )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["upload_seq"] == 1


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M2T11Pending)
def test_checkpoint_replay_refused_server(audit_server):
    """A replayed checkpoint (same upload_seq) is refused (D3.3, threat 17)."""
    _need("agg_cp.sync.audit_upload", "audit_upload_router")
    info = audit_server
    sk, pub, kid = keygen()
    org_id = info["org_id"]
    project_id = str(uuid.uuid4())

    with psycopg.connect(_conninfo(info["owner_url"]), autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        create_project(conn, org_id, project_id)

    device_id = _seed_connector(info["owner_url"], org_id, project_id, pub)
    token = secrets.token_urlsafe(32)
    _seed_device_token(info["owner_url"], org_id, project_id, device_id, token)

    payload = {
        "device_id": device_id,
        "upload_seq": 1,
        "sessions": [
            {"session_id": "s1", "chain_length": 3, "head_hash": "h3"},
        ],
        "ts": time.time(),
    }
    envelope = sign_envelope("agg/audit-head/v1", payload, sk)

    import httpx
    with httpx.Client(base_url=info["base_url"], timeout=10) as client:
        resp1 = client.post(
            "/api/v1/sync/checkpoint",
            headers={"Authorization": f"Bearer {token}"},
            json=envelope,
        )
        assert resp1.status_code == 200

        resp2 = client.post(
            "/api/v1/sync/checkpoint",
            headers={"Authorization": f"Bearer {token}"},
            json=envelope,
        )
        assert resp2.status_code == 400 or resp2.status_code == 409, (
            f"Expected 400/409 for replay, got {resp2.status_code}"
        )


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M2T11Pending)
def test_checkpoint_skip_refused_server(audit_server):
    """A skipped upload_seq is refused (D3.3, threat 17).

    Send upload_seq=2 without sending upload_seq=1 first.
    """
    _need("agg_cp.sync.audit_upload", "audit_upload_router")
    info = audit_server
    sk, pub, kid = keygen()
    org_id = info["org_id"]
    project_id = str(uuid.uuid4())

    with psycopg.connect(_conninfo(info["owner_url"]), autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        create_project(conn, org_id, project_id)

    device_id = _seed_connector(info["owner_url"], org_id, project_id, pub)
    token = secrets.token_urlsafe(32)
    _seed_device_token(info["owner_url"], org_id, project_id, device_id, token)

    payload = {
        "device_id": device_id,
        "upload_seq": 2,  # skipped 1
        "sessions": [
            {"session_id": "s1", "chain_length": 3, "head_hash": "h3"},
        ],
        "ts": time.time(),
    }
    envelope = sign_envelope("agg/audit-head/v1", payload, sk)

    import httpx
    with httpx.Client(base_url=info["base_url"], timeout=10) as client:
        resp = client.post(
            "/api/v1/sync/checkpoint",
            headers={"Authorization": f"Bearer {token}"},
            json=envelope,
        )
    assert resp.status_code == 400, (
        f"Expected 400 for seq skip, got {resp.status_code}"
    )


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M2T11Pending)
def test_session_missing_alert(audit_server):
    """A session listed in checkpoint 1 but missing in checkpoint 2 raises
    session_missing (D3.3, threat 32).
    """
    _need("agg_cp.sync.audit_upload", "audit_upload_router")
    info = audit_server
    sk, pub, kid = keygen()
    org_id = info["org_id"]
    project_id = str(uuid.uuid4())

    with psycopg.connect(_conninfo(info["owner_url"]), autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        create_project(conn, org_id, project_id)

    device_id = _seed_connector(info["owner_url"], org_id, project_id, pub)
    token = secrets.token_urlsafe(32)
    _seed_device_token(info["owner_url"], org_id, project_id, device_id, token)

    # Checkpoint 1: sessions s1 and s2
    payload1 = {
        "device_id": device_id,
        "upload_seq": 1,
        "sessions": [
            {"session_id": "s1", "chain_length": 3, "head_hash": "h3"},
            {"session_id": "s2", "chain_length": 2, "head_hash": "h2"},
        ],
        "ts": time.time(),
    }
    env1 = sign_envelope("agg/audit-head/v1", payload1, sk)

    # Checkpoint 2: only s1 (s2 missing)
    payload2 = {
        "device_id": device_id,
        "upload_seq": 2,
        "sessions": [
            {"session_id": "s1", "chain_length": 5, "head_hash": "h5"},
        ],
        "ts": time.time(),
    }
    env2 = sign_envelope("agg/audit-head/v1", payload2, sk)

    import httpx
    with httpx.Client(base_url=info["base_url"], timeout=10) as client:
        resp1 = client.post(
            "/api/v1/sync/checkpoint",
            headers={"Authorization": f"Bearer {token}"},
            json=env1,
        )
        assert resp1.status_code == 200

        resp2 = client.post(
            "/api/v1/sync/checkpoint",
            headers={"Authorization": f"Bearer {token}"},
            json=env2,
        )
        # Should succeed but create a session_missing alert
        assert resp2.status_code == 200

    # Verify session_missing alert
    with psycopg.connect(_conninfo(info["owner_url"])) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        row = conn.execute(
            "SELECT kind, detail FROM sync_alerts "
            "WHERE connector_id = %s AND kind = 'session_missing'",
            [device_id],
        ).fetchone()
        assert row is not None, "No session_missing alert found"


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M2T11Pending)
def test_truncation_alert_server(audit_server):
    """A session with chain_length < previous checkpoint raises truncation (D3.3, threat 15)."""
    _need("agg_cp.sync.audit_upload", "audit_upload_router")
    info = audit_server
    sk, pub, kid = keygen()
    org_id = info["org_id"]
    project_id = str(uuid.uuid4())

    with psycopg.connect(_conninfo(info["owner_url"]), autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        create_project(conn, org_id, project_id)

    device_id = _seed_connector(info["owner_url"], org_id, project_id, pub)
    token = secrets.token_urlsafe(32)
    _seed_device_token(info["owner_url"], org_id, project_id, device_id, token)

    # Checkpoint 1: chain_length 5
    payload1 = {
        "device_id": device_id,
        "upload_seq": 1,
        "sessions": [
            {"session_id": "s1", "chain_length": 5, "head_hash": "h5"},
        ],
        "ts": time.time(),
    }
    env1 = sign_envelope("agg/audit-head/v1", payload1, sk)

    # Checkpoint 2: chain_length 3 (truncated!)
    payload2 = {
        "device_id": device_id,
        "upload_seq": 2,
        "sessions": [
            {"session_id": "s1", "chain_length": 3, "head_hash": "h3"},
        ],
        "ts": time.time(),
    }
    env2 = sign_envelope("agg/audit-head/v1", payload2, sk)

    import httpx
    with httpx.Client(base_url=info["base_url"], timeout=10) as client:
        resp1 = client.post(
            "/api/v1/sync/checkpoint",
            headers={"Authorization": f"Bearer {token}"},
            json=env1,
        )
        assert resp1.status_code == 200

        resp2 = client.post(
            "/api/v1/sync/checkpoint",
            headers={"Authorization": f"Bearer {token}"},
            json=env2,
        )
        assert resp2.status_code == 200

    # Verify truncation alert
    with psycopg.connect(_conninfo(info["owner_url"])) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        row = conn.execute(
            "SELECT kind FROM sync_alerts "
            "WHERE connector_id = %s AND kind = 'truncation'",
            [device_id],
        ).fetchone()
        assert row is not None, "No truncation alert found"


# ===================================================================
# RED: device_silent via sweep_device_silent (D3.5, N6, threat 35)
# Server-side only.  Tests call the pure function with injected now.
# ===================================================================


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M2T11Pending)
def test_device_silent_no_alert_before_window(audit_server):
    """No device_silent alert before the checkpoint window expires (D3.5, threat 35).

    Store a checkpoint, then call sweep_device_silent with now = checkpoint_ts + 179 s.
    No alert should be created.
    """
    _need("agg_cp.sync.audit", "sweep_device_silent")
    from agg_cp.sync.audit import sweep_device_silent
    info = audit_server
    sk, pub, kid = keygen()
    org_id = info["org_id"]
    project_id = str(uuid.uuid4())

    with psycopg.connect(_conninfo(info["owner_url"]), autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        create_project(conn, org_id, project_id)

    device_id = _seed_connector(info["owner_url"], org_id, project_id, pub)
    token = secrets.token_urlsafe(32)
    _seed_device_token(info["owner_url"], org_id, project_id, device_id, token)

    # Send checkpoint via the route
    checkpoint_ts = time.time()
    payload = {
        "device_id": device_id,
        "upload_seq": 1,
        "sessions": [{"session_id": "s1", "chain_length": 1, "head_hash": "h1"}],
        "ts": checkpoint_ts,
    }
    envelope = sign_envelope("agg/audit-head/v1", payload, sk)

    import httpx
    with httpx.Client(base_url=info["base_url"], timeout=10) as client:
        resp = client.post(
            "/api/v1/sync/checkpoint",
            headers={"Authorization": f"Bearer {token}"},
            json=envelope,
        )
        assert resp.status_code == 200

    # Sweep at window - 1 s: no alert
    import datetime as dt
    with psycopg.connect(_conninfo(info["owner_url"])) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        now = dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=179)
        sweep_device_silent(conn, now)
        conn.commit()
        row = conn.execute(
            "SELECT count(*) FROM sync_alerts "
            "WHERE connector_id = %s AND kind = 'device_silent'",
            [device_id],
        ).fetchone()
        assert row[0] == 0, "device_silent raised too early"


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M2T11Pending)
def test_device_silent_after_missed_window(audit_server):
    """device_silent alert fires after the checkpoint window (D3.5, N6, threat 35).

    Store a checkpoint, then call sweep_device_silent with now = checkpoint_ts + 181 s.
    Exactly one alert should be created.
    """
    _need("agg_cp.sync.audit", "sweep_device_silent")
    from agg_cp.sync.audit import sweep_device_silent
    info = audit_server
    sk, pub, kid = keygen()
    org_id = info["org_id"]
    project_id = str(uuid.uuid4())

    with psycopg.connect(_conninfo(info["owner_url"]), autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        create_project(conn, org_id, project_id)

    device_id = _seed_connector(info["owner_url"], org_id, project_id, pub)
    token = secrets.token_urlsafe(32)
    _seed_device_token(info["owner_url"], org_id, project_id, device_id, token)

    payload = {
        "device_id": device_id,
        "upload_seq": 1,
        "sessions": [{"session_id": "s1", "chain_length": 1, "head_hash": "h1"}],
        "ts": time.time(),
    }
    envelope = sign_envelope("agg/audit-head/v1", payload, sk)

    import httpx
    with httpx.Client(base_url=info["base_url"], timeout=10) as client:
        resp = client.post(
            "/api/v1/sync/checkpoint",
            headers={"Authorization": f"Bearer {token}"},
            json=envelope,
        )
        assert resp.status_code == 200

    import datetime as dt
    with psycopg.connect(_conninfo(info["owner_url"])) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        now = dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=181)
        sweep_device_silent(conn, now)
        conn.commit()
        row = conn.execute(
            "SELECT count(*) FROM sync_alerts "
            "WHERE connector_id = %s AND kind = 'device_silent'",
            [device_id],
        ).fetchone()
        assert row[0] == 1, "device_silent not raised after missed window"


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M2T11Pending)
def test_device_silent_no_duplicate_on_second_sweep(audit_server):
    """A second sweep does not duplicate the device_silent alert (D3.5, threat 35).

    After the first sweep raises the alert, a second sweep at the same
    or later time must not insert another row.
    """
    _need("agg_cp.sync.audit", "sweep_device_silent")
    from agg_cp.sync.audit import sweep_device_silent
    info = audit_server
    sk, pub, kid = keygen()
    org_id = info["org_id"]
    project_id = str(uuid.uuid4())

    with psycopg.connect(_conninfo(info["owner_url"]), autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        create_project(conn, org_id, project_id)

    device_id = _seed_connector(info["owner_url"], org_id, project_id, pub)
    token = secrets.token_urlsafe(32)
    _seed_device_token(info["owner_url"], org_id, project_id, device_id, token)

    payload = {
        "device_id": device_id,
        "upload_seq": 1,
        "sessions": [{"session_id": "s1", "chain_length": 1, "head_hash": "h1"}],
        "ts": time.time(),
    }
    envelope = sign_envelope("agg/audit-head/v1", payload, sk)

    import httpx
    with httpx.Client(base_url=info["base_url"], timeout=10) as client:
        resp = client.post(
            "/api/v1/sync/checkpoint",
            headers={"Authorization": f"Bearer {token}"},
            json=envelope,
        )
        assert resp.status_code == 200

    import datetime as dt
    with psycopg.connect(_conninfo(info["owner_url"])) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        now = dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=200)
        sweep_device_silent(conn, now)
        conn.commit()
        # Second sweep
        sweep_device_silent(conn, now + dt.timedelta(seconds=60))
        conn.commit()
        count = conn.execute(
            "SELECT count(*) FROM sync_alerts "
            "WHERE connector_id = %s AND kind = 'device_silent'",
            [device_id],
        ).fetchone()[0]
        assert count == 1, f"Expected exactly 1 device_silent, got {count}"


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M2T11Pending)
def test_device_silent_ends_on_fresh_checkpoint(audit_server):
    """A fresh checkpoint after device_silent ends the silent episode (D3.5, threat 35).

    After the alert fires, a new checkpoint resets the window.  A sweep
    within the new window must not raise another alert.
    """
    _need("agg_cp.sync.audit", "sweep_device_silent")
    from agg_cp.sync.audit import sweep_device_silent
    info = audit_server
    sk, pub, kid = keygen()
    org_id = info["org_id"]
    project_id = str(uuid.uuid4())

    with psycopg.connect(_conninfo(info["owner_url"]), autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        create_project(conn, org_id, project_id)

    device_id = _seed_connector(info["owner_url"], org_id, project_id, pub)
    token = secrets.token_urlsafe(32)
    _seed_device_token(info["owner_url"], org_id, project_id, device_id, token)

    # First checkpoint
    payload1 = {
        "device_id": device_id,
        "upload_seq": 1,
        "sessions": [{"session_id": "s1", "chain_length": 1, "head_hash": "h1"}],
        "ts": time.time(),
    }
    env1 = sign_envelope("agg/audit-head/v1", payload1, sk)

    import httpx
    with httpx.Client(base_url=info["base_url"], timeout=10) as client:
        resp1 = client.post(
            "/api/v1/sync/checkpoint",
            headers={"Authorization": f"Bearer {token}"},
            json=env1,
        )
        assert resp1.status_code == 200

    import datetime as dt
    # Sweep after window: alert fires
    with psycopg.connect(_conninfo(info["owner_url"])) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        now = dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=200)
        sweep_device_silent(conn, now)
        conn.commit()

    # Second checkpoint (fresh)
    payload2 = {
        "device_id": device_id,
        "upload_seq": 2,
        "sessions": [{"session_id": "s1", "chain_length": 2, "head_hash": "h2"}],
        "ts": time.time(),
    }
    env2 = sign_envelope("agg/audit-head/v1", payload2, sk)

    with httpx.Client(base_url=info["base_url"], timeout=10) as client:
        resp2 = client.post(
            "/api/v1/sync/checkpoint",
            headers={"Authorization": f"Bearer {token}"},
            json=env2,
        )
        assert resp2.status_code == 200

    # Sweep shortly after the second checkpoint: no new alert
    with psycopg.connect(_conninfo(info["owner_url"])) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        now2 = dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=210)
        sweep_device_silent(conn, now2)
        conn.commit()
        count = conn.execute(
            "SELECT count(*) FROM sync_alerts "
            "WHERE connector_id = %s AND kind = 'device_silent'",
            [device_id],
        ).fetchone()[0]
        assert count == 1, (
            f"Expected 1 device_silent (episode ended by fresh checkpoint), got {count}"
        )


# ===================================================================
# RED: agg-cp audit verify --project (CLI, D3.4, threat 18)
# ===================================================================


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M2T11Pending)
def test_audit_verify_cli_clean_project(audit_server):
    """``agg_cp.cli.main(["audit", "verify", "--project", <id>])`` exits 0
    on a project with a complete, consistent chain (D3.4).
    """
    _need("agg_cp.sync.audit", "verify_project")
    info = audit_server
    sk, pub, kid = keygen()
    org_id = info["org_id"]
    project_id = str(uuid.uuid4())

    with psycopg.connect(_conninfo(info["owner_url"]), autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        create_project(conn, org_id, project_id)

    device_id = _seed_connector(info["owner_url"], org_id, project_id, pub)
    token = secrets.token_urlsafe(32)
    _seed_device_token(info["owner_url"], org_id, project_id, device_id, token)

    # Upload a valid chain
    records = _make_audit_chain("sess-v", 5)

    import httpx
    with httpx.Client(base_url=info["base_url"], timeout=10) as client:
        client.post(
            "/api/v1/sync/audit",
            headers={"Authorization": f"Bearer {token}"},
            json={"session_id": "sess-v", "records": records},
        )

    # CLI verify should exit 0
    import os
    os.environ["AGG_DATABASE_URL"] = info["app_url"]
    from agg_cp.cli import main as cli_main
    rc = cli_main(["audit", "verify", "--project", project_id])
    assert rc == 0, f"audit verify exited {rc} on a clean project"


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M2T11Pending)
def test_audit_verify_cli_detects_gap(audit_server):
    """``agg_cp.cli.main(["audit", "verify", "--project", <id>])`` exits
    non-zero and reports gap rows when the chain has a gap (D3.4, threat 18).
    """
    _need("agg_cp.sync.audit", "verify_project")
    info = audit_server
    sk, pub, kid = keygen()
    org_id = info["org_id"]
    project_id = str(uuid.uuid4())

    with psycopg.connect(_conninfo(info["owner_url"]), autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        create_project(conn, org_id, project_id)

    device_id = _seed_connector(info["owner_url"], org_id, project_id, pub)
    token = secrets.token_urlsafe(32)
    _seed_device_token(info["owner_url"], org_id, project_id, device_id, token)

    # Upload records 1-3
    records_first = _make_audit_chain("sess-gap", 3)

    import httpx
    with httpx.Client(base_url=info["base_url"], timeout=10) as client:
        client.post(
            "/api/v1/sync/audit",
            headers={"Authorization": f"Bearer {token}"},
            json={"session_id": "sess-gap", "records": records_first},
        )

    # Directly insert record 5 (skipping 4) to create a gap
    with psycopg.connect(_conninfo(info["owner_url"])) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        conn.execute(
            "INSERT INTO audit_records "
            "(id, org_id, connector_id, session_id, chain_length, "
            "previous_hash, record_hash, body, created_at) "
            "VALUES (%s, %s, %s, 'sess-gap', 5, 'h4', 'h5', "
            "'{\"event\": \"planted\"}'::jsonb, now())",
            [str(uuid.uuid4()), org_id, device_id],
        )
        conn.commit()

    import os
    os.environ["AGG_DATABASE_URL"] = info["app_url"]
    from agg_cp.cli import main as cli_main
    rc = cli_main(["audit", "verify", "--project", project_id])
    assert rc != 0, f"audit verify exited {rc} (expected non-zero for gap)"


# ===================================================================
# RED: batch limits (ruling 2: all-or-nothing, 1 MiB, 1000 records)
# ===================================================================


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M2T11Pending)
def test_audit_upload_over_1000_records_gives_413(audit_server):
    """A batch with >1000 records is refused with 413 and nothing stored (ruling 2)."""
    _need("agg_cp.sync.audit_upload", "audit_upload_router")
    info = audit_server
    sk, pub, kid = keygen()
    org_id = info["org_id"]
    project_id = str(uuid.uuid4())

    with psycopg.connect(_conninfo(info["owner_url"]), autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        create_project(conn, org_id, project_id)

    device_id = _seed_connector(info["owner_url"], org_id, project_id, pub)
    token = secrets.token_urlsafe(32)
    _seed_device_token(info["owner_url"], org_id, project_id, device_id, token)

    records = _make_audit_chain("sess-cap", 1001)

    import httpx
    with httpx.Client(base_url=info["base_url"], timeout=30) as client:
        resp = client.post(
            "/api/v1/sync/audit",
            headers={"Authorization": f"Bearer {token}"},
            json={"session_id": "sess-cap", "records": records},
        )
    assert resp.status_code == 413, (
        f"Expected 413 for >1000 records, got {resp.status_code}"
    )

    # Nothing stored
    with psycopg.connect(_conninfo(info["owner_url"])) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        count = conn.execute(
            "SELECT count(*) FROM audit_records "
            "WHERE connector_id = %s AND session_id = 'sess-cap'",
            [device_id],
        ).fetchone()[0]
        assert count == 0, f"Expected 0 stored after 413, got {count}"


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M2T11Pending)
def test_audit_upload_bad_record_in_batch_gives_400(audit_server):
    """One bad record in a batch gives 400 and nothing from the batch is stored (ruling 2)."""
    _need("agg_cp.sync.audit_upload", "audit_upload_router")
    info = audit_server
    sk, pub, kid = keygen()
    org_id = info["org_id"]
    project_id = str(uuid.uuid4())

    with psycopg.connect(_conninfo(info["owner_url"]), autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        create_project(conn, org_id, project_id)

    device_id = _seed_connector(info["owner_url"], org_id, project_id, pub)
    token = secrets.token_urlsafe(32)
    _seed_device_token(info["owner_url"], org_id, project_id, device_id, token)

    records = _make_audit_chain("sess-bad", 3)
    # Corrupt the second record's previous_hash (chain break)
    records[1]["previous_hash"] = "wrong_hash"

    import httpx
    with httpx.Client(base_url=info["base_url"], timeout=10) as client:
        resp = client.post(
            "/api/v1/sync/audit",
            headers={"Authorization": f"Bearer {token}"},
            json={"session_id": "sess-bad", "records": records},
        )
    assert resp.status_code == 400, (
        f"Expected 400 for bad record in batch, got {resp.status_code}"
    )

    # Nothing from the batch stored (all-or-nothing)
    with psycopg.connect(_conninfo(info["owner_url"])) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        count = conn.execute(
            "SELECT count(*) FROM audit_records "
            "WHERE connector_id = %s AND session_id = 'sess-bad'",
            [device_id],
        ).fetchone()[0]
        assert count == 0, f"Expected 0 stored after 400, got {count}"


# ===================================================================
# RED: checkpoint signature hardening (ruling 5, threat 17/S11)
# ===================================================================


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M2T11Pending)
def test_checkpoint_bad_signature_refused(audit_server):
    """A checkpoint with a bad signature is refused (400 invalid_signature, ruling 5).

    Nothing is stored.
    """
    _need("agg_cp.sync.audit_upload", "audit_upload_router")
    info = audit_server
    sk, pub, kid = keygen()
    org_id = info["org_id"]
    project_id = str(uuid.uuid4())

    with psycopg.connect(_conninfo(info["owner_url"]), autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        create_project(conn, org_id, project_id)

    device_id = _seed_connector(info["owner_url"], org_id, project_id, pub)
    token = secrets.token_urlsafe(32)
    _seed_device_token(info["owner_url"], org_id, project_id, device_id, token)

    payload = {
        "device_id": device_id,
        "upload_seq": 1,
        "sessions": [{"session_id": "s1", "chain_length": 1, "head_hash": "h1"}],
        "ts": time.time(),
    }
    envelope = sign_envelope("agg/audit-head/v1", payload, sk)
    # Corrupt the signature
    envelope["signatures"][0]["sig"] = "00" * 64

    import httpx
    with httpx.Client(base_url=info["base_url"], timeout=10) as client:
        resp = client.post(
            "/api/v1/sync/checkpoint",
            headers={"Authorization": f"Bearer {token}"},
            json=envelope,
        )
    assert resp.status_code == 400, (
        f"Expected 400 for bad signature, got {resp.status_code}"
    )

    # Nothing stored
    with psycopg.connect(_conninfo(info["owner_url"])) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        count = conn.execute(
            "SELECT count(*) FROM audit_heads WHERE connector_id = %s",
            [device_id],
        ).fetchone()[0]
        assert count == 0, f"Expected 0 stored after bad sig, got {count}"


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M2T11Pending)
def test_checkpoint_signed_by_another_device_refused(audit_server):
    """A checkpoint signed by another device's valid key is refused (ruling 5).

    Device A's token authenticates, but the envelope is signed by device B's key.
    Nothing is stored.
    """
    _need("agg_cp.sync.audit_upload", "audit_upload_router")
    info = audit_server
    sk_a, pub_a, kid_a = keygen()
    sk_b, pub_b, kid_b = keygen()
    org_id = info["org_id"]
    project_id = str(uuid.uuid4())

    with psycopg.connect(_conninfo(info["owner_url"]), autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        create_project(conn, org_id, project_id)

    device_id_a = _seed_connector(info["owner_url"], org_id, project_id, pub_a)
    _seed_connector(info["owner_url"], org_id, project_id, pub_b,
                    device_id=str(uuid.uuid4()))
    token_a = secrets.token_urlsafe(32)
    _seed_device_token(info["owner_url"], org_id, project_id, device_id_a, token_a)

    # Sign with device B's key but claim device A's device_id
    payload = {
        "device_id": device_id_a,
        "upload_seq": 1,
        "sessions": [{"session_id": "s1", "chain_length": 1, "head_hash": "h1"}],
        "ts": time.time(),
    }
    envelope = sign_envelope("agg/audit-head/v1", payload, sk_b)

    import httpx
    with httpx.Client(base_url=info["base_url"], timeout=10) as client:
        resp = client.post(
            "/api/v1/sync/checkpoint",
            headers={"Authorization": f"Bearer {token_a}"},
            json=envelope,
        )
    assert resp.status_code == 400, (
        f"Expected 400 for wrong device key, got {resp.status_code}"
    )


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M2T11Pending)
def test_checkpoint_device_id_mismatch_refused(audit_server):
    """A checkpoint whose device_id differs from the token's device is refused (ruling 5).

    Device A's token authenticates, but the payload claims device B's id.
    Nothing is stored.
    """
    _need("agg_cp.sync.audit_upload", "audit_upload_router")
    info = audit_server
    sk_a, pub_a, kid_a = keygen()
    sk_b, pub_b, kid_b = keygen()
    org_id = info["org_id"]
    project_id_a = str(uuid.uuid4())
    project_id_b = str(uuid.uuid4())

    with psycopg.connect(_conninfo(info["owner_url"]), autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        create_project(conn, org_id, project_id_a, name="proj-a")
        create_project(conn, org_id, project_id_b, name="proj-b")

    device_id_a = _seed_connector(info["owner_url"], org_id, project_id_a, pub_a)
    device_id_b = _seed_connector(info["owner_url"], org_id, project_id_b, pub_b)
    token_a = secrets.token_urlsafe(32)
    _seed_device_token(info["owner_url"], org_id, project_id_a, device_id_a, token_a)

    # Sign correctly with device A's key, but claim device B's id
    payload = {
        "device_id": device_id_b,  # mismatch
        "upload_seq": 1,
        "sessions": [{"session_id": "s1", "chain_length": 1, "head_hash": "h1"}],
        "ts": time.time(),
    }
    envelope = sign_envelope("agg/audit-head/v1", payload, sk_a)

    import httpx
    with httpx.Client(base_url=info["base_url"], timeout=10) as client:
        resp = client.post(
            "/api/v1/sync/checkpoint",
            headers={"Authorization": f"Bearer {token_a}"},
            json=envelope,
        )
    assert resp.status_code == 400, (
        f"Expected 400 for device_id mismatch, got {resp.status_code}"
    )


# ===================================================================
# RED: load test -- gate item 6
# (20 connectors x 200 records, 4 workers, 1 Postgres)
# ===================================================================


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M2T11Pending)
def test_load_20_connectors_200_records(audit_server):
    """Gate item 6: 20 connectors x 200 records, 4 workers, one Postgres.

    Pass condition: 0 lost, 0 duplicated, 0 false forks, 0 pool errors.
    Wall time is recorded.  Runs in every ee CI job (CI fails on a
    skipped pg test); ee/tests/conftest.py is frozen, so no marker.
    """
    _need("agg_cp.sync.audit_upload", "audit_upload_router")
    info = audit_server
    org_id = info["org_id"]

    import httpx
    from concurrent.futures import ThreadPoolExecutor, as_completed

    # Create 20 connectors, each with its own device key and token
    connectors = []
    for i in range(20):
        sk, pub, kid = keygen()
        project_id = str(uuid.uuid4())
        with psycopg.connect(_conninfo(info["owner_url"]), autocommit=True) as conn:
            conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
            create_project(conn, org_id, project_id, name=f"load-{i}")
        device_id = _seed_connector(info["owner_url"], org_id, project_id, pub)
        token = secrets.token_urlsafe(32)
        _seed_device_token(info["owner_url"], org_id, project_id, device_id, token)
        connectors.append({
            "device_id": device_id,
            "token": token,
            "project_id": project_id,
            "records": _make_audit_chain(f"sess-load-{i}", 200),
        })

    errors = []
    start_time = time.monotonic()

    def upload_one(c):
        try:
            with httpx.Client(base_url=info["base_url"], timeout=60) as client:
                resp = client.post(
                    "/api/v1/sync/audit",
                    headers={"Authorization": f"Bearer {c['token']}"},
                    json={"session_id": f"sess-load-{c['device_id'][:8]}",
                          "records": c["records"]},
                )
                if resp.status_code != 200:
                    return {"error": f"status {resp.status_code}",
                            "device": c["device_id"],
                            "body": resp.text}
                return {"ok": True, "device": c["device_id"]}
        except Exception as exc:
            return {"error": str(exc), "device": c["device_id"]}

    with ThreadPoolExecutor(max_workers=20) as pool:
        futures = [pool.submit(upload_one, c) for c in connectors]
        results = [f.result() for f in as_completed(futures)]

    wall_time = time.monotonic() - start_time

    failures = [r for r in results if "error" in r]
    assert len(failures) == 0, (
        f"Load test: {len(failures)} failures in {wall_time:.1f}s: "
        f"{failures[:5]}"
    )

    # Verify: no lost, no duplicated, no false forks
    with psycopg.connect(_conninfo(info["owner_url"])) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])

        # Count total records
        total = conn.execute(
            "SELECT count(*) FROM audit_records WHERE org_id = %s", [org_id]
        ).fetchone()[0]
        expected = 20 * 200
        assert total == expected, (
            f"Lost or duplicated: expected {expected}, got {total}"
        )

        # No false forks (quarantine should be empty for this org)
        quarantine_count = conn.execute(
            "SELECT count(*) FROM audit_quarantine WHERE org_id = %s", [org_id]
        ).fetchone()[0]
        assert quarantine_count == 0, (
            f"False forks: {quarantine_count} quarantine entries"
        )

    # Record wall time for the gate
    print(f"\nLoad test: 20 connectors x 200 records in {wall_time:.1f}s")


# ===================================================================
# RED: revoked device upload refused
# ===================================================================


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M2T11Pending)
def test_audit_upload_revoked_device_401(audit_server):
    """A revoked device's audit upload gets 401 (D1.5)."""
    _need("agg_cp.sync.audit_upload", "audit_upload_router")
    info = audit_server
    sk, pub, kid = keygen()
    org_id = info["org_id"]
    project_id = str(uuid.uuid4())

    with psycopg.connect(_conninfo(info["owner_url"]), autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        create_project(conn, org_id, project_id)

    device_id = _seed_connector(info["owner_url"], org_id, project_id, pub)
    token = secrets.token_urlsafe(32)
    _seed_device_token(info["owner_url"], org_id, project_id, device_id, token)

    # Revoke the device
    with psycopg.connect(_conninfo(info["owner_url"]), autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        conn.execute(
            "UPDATE connectors SET revoked_at = now() WHERE id = %s",
            [device_id],
        )

    records = _make_audit_chain("sess-rev", 2)

    import httpx
    with httpx.Client(base_url=info["base_url"], timeout=10) as client:
        resp = client.post(
            "/api/v1/sync/audit",
            headers={"Authorization": f"Bearer {token}"},
            json={"session_id": "sess-rev", "records": records},
        )
    assert resp.status_code == 401, (
        f"Expected 401 for revoked device, got {resp.status_code}"
    )
