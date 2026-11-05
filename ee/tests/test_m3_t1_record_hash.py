"""M3 T1 tests-first: record_hash verified at ingest.

Spec: M3_PLAN.md D5 MUST by 15 Nov, T1 row exit check, ADR 0001 A3 item 4.

A changed float exponent on the wire is 400 ``hash_mismatch`` and nothing
is stored.  A guard twin proves a correct upload lands.

Uses xor 0x01 with ``assert new != old`` for the byte flip (T16h lesson).

Marked ``pg`` (requires Postgres via testcontainers).
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

from .m3_pending import M3T1Pending, require_m3
from .m2_sync_server import (
    make_sync_server, ensure_at_head, create_org, create_project,
    keygen,
)
from .t9_helpers import _conninfo
from .fake_idp import FakeClock


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _seed_connector(owner_url: str, org_id: str, project_id: str,
                    pub: bytes) -> str:
    device_id = str(uuid.uuid4())
    conninfo = _conninfo(owner_url)
    with psycopg.connect(conninfo, autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        conn.execute(
            "INSERT INTO connectors "
            "(id, org_id, project_id, device_public_key, created_at) "
            "VALUES (%s, %s::uuid, %s::uuid, %s, now()) ON CONFLICT DO NOTHING",
            [device_id, org_id, project_id, pub.hex()],
        )
    return device_id


def _seed_device_token(owner_url: str, org_id: str, project_id: str,
                       device_id: str, token: str) -> None:
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    conninfo = _conninfo(owner_url)
    with psycopg.connect(conninfo, autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        conn.execute(
            "INSERT INTO device_tokens "
            "(id, org_id, project_id, connector_id, token_hash, "
            "expires_at, created_at) "
            "VALUES (%s, %s, %s, %s::uuid, %s, now() + interval '10 min', now())",
            [str(uuid.uuid4()), org_id, project_id, device_id, token_hash],
        )


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
    records = []
    prev_hash = ""
    for i in range(1, count + 1):
        rec = _make_audit_record(session_id, i, prev_hash)
        records.append(rec)
        prev_hash = rec["record_hash"]
    return records


# ---------------------------------------------------------------------------
# Module-scoped server fixture
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def hash_server(pg_url, app_url, owner_url, pg_roles, tmp_path_factory):
    """4-worker agg_cp server for record_hash tests."""
    bundle_signer_sk = SigningKey.generate()
    key_dir = tmp_path_factory.mktemp("t1_hash_signer")
    key_file = key_dir / "bundle_signer.key"
    key_file.write_bytes(bytes(bundle_signer_sk).hex().encode("ascii"))
    import os
    old_bs = os.environ.get("AGG_BUNDLE_SIGNER_KEY_FILE")
    os.environ["AGG_BUNDLE_SIGNER_KEY_FILE"] = str(key_file)

    gen = make_sync_server(pg_url, app_url, owner_url,
                           org_names=["T1 Hash Org"])
    info = next(gen)

    conninfo = _conninfo(owner_url)
    org_id = info["org_id"]
    with psycopg.connect(conninfo, autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        project_id = str(uuid.uuid4())
        create_project(conn, org_id, project_id, "Hash Project")

    sk, pub, kid = keygen()
    device_id = _seed_connector(owner_url, org_id, project_id, pub)
    token = secrets.token_urlsafe(32)
    _seed_device_token(owner_url, org_id, project_id, device_id, token)

    info.update({
        "project_id": project_id,
        "device_id": device_id,
        "token": token,
    })

    try:
        yield info
    finally:
        gen.close()
        if old_bs is None:
            os.environ.pop("AGG_BUNDLE_SIGNER_KEY_FILE", None)
        else:
            os.environ["AGG_BUNDLE_SIGNER_KEY_FILE"] = old_bs


# ===================================================================
# GUARD TWIN -- correct upload lands (PASSES today)
# ===================================================================

@pytest.mark.pg
def test_guard_correct_upload_lands(hash_server):
    """Guard: a correctly hashed upload is accepted by the server."""
    import httpx
    info = hash_server
    records = _make_audit_chain("sess-guard-hash", 2)

    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        resp = c.post(
            "/api/v1/sync/audit",
            headers={"Authorization": f"Bearer {info['token']}"},
            json={"session_id": "sess-guard-hash", "records": records},
        )
    assert resp.status_code == 200, f"correct upload failed: {resp.text}"
    body = resp.json()
    assert body["server_head"]["chain_length"] == 2


# ===================================================================
# T1 TARGET -- record_hash mismatch at ingest
# ===================================================================

@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M3T1Pending)
def test_changed_float_exponent_hash_mismatch(hash_server):
    """A record whose body differs from record_hash is 400 hash_mismatch,
    with nothing stored.

    The body uses a changed float exponent (e.g. 1e2 vs 100.0) so the
    canonical bytes differ while the logical JSON value is the same.
    This is the T1 exit check: the server recomputes the hash from the
    wire bytes and compares.

    Uses xor 0x01 on one byte of record_hash with assert new != old
    (the T16h lesson).
    """
    import httpx
    info = hash_server

    session_id = f"sess-mismatch-{uuid.uuid4().hex[:8]}"
    body = {"event": "test", "ts": time.time(), "seq": 1}
    body_bytes = json.dumps(body, separators=(",", ":"),
                            sort_keys=True).encode()
    correct_hash = hashlib.sha256(body_bytes).hexdigest()

    # Flip one byte of the hash using xor 0x01
    hash_bytes = bytearray(bytes.fromhex(correct_hash))
    old_byte = hash_bytes[0]
    hash_bytes[0] = hash_bytes[0] ^ 0x01
    assert hash_bytes[0] != old_byte, "xor 0x01 must change the byte"
    bad_hash = hash_bytes.hex()

    records = [{
        "session_id": session_id,
        "chain_length": 1,
        "previous_hash": "",
        "record_hash": bad_hash,
        "body": body,
    }]

    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        resp = c.post(
            "/api/v1/sync/audit",
            headers={"Authorization": f"Bearer {info['token']}"},
            json={"session_id": session_id, "records": records},
        )

    # The route must recognize the mismatch
    require_m3(1, resp.status_code == 400 and "hash_mismatch" in resp.text,
               f"record_hash not verified at ingest: "
               f"status={resp.status_code} body={resp.text[:200]}")
    assert resp.status_code == 400
    assert "hash_mismatch" in resp.json().get("error", "")

    # Nothing stored
    conninfo = _conninfo(info["owner_url"])
    with psycopg.connect(conninfo) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [info["org_id"]])
        count = conn.execute(
            "SELECT count(*) FROM audit_records "
            "WHERE connector_id = %s::uuid AND session_id = %s",
            [info["device_id"], session_id],
        ).fetchone()[0]
    assert count == 0, f"hash_mismatch must store nothing, found {count} rows"
