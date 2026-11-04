"""T16g audit upload contract (server side only; security W MEDIUM, 4 Nov).

``POST /api/v1/sync/audit`` (ee/src/agg_cp/sync/audit_upload.py:124-131)
today answers 200 to a body that carries ``session_id`` but no
``records`` key (``records`` defaults to ``[]``) and to ``records: []``.
Nothing is stored, no head is returned for anything, and a connector
that sends the wrong shape (G7-B) is told "ok".  ADR 0001 5.2 / A4.1:
an upload without records is a bad body -> 400 ``bad_body``, nothing
stored.

Both target tests pass since T16g (they were strict xfail until the product
code was built): they assert on the product behaviour, never on a harness
error.  The guard twin proves the harness (real server on pg, real device
token) works.

Fixture style mirrors ``tests/test_m2_t11_audit.py`` (connector +
device-token rows seeded directly, FastAPI app over HTTP on pg).
"""
from __future__ import annotations

import hashlib
import json
import secrets
import time
import uuid

import psycopg
import pytest

from .m2_sync_server import make_sync_server, create_project, keygen


# G7-B contract (HANDOFF 4 Nov, security W): expected change
# ee/src/agg_cp/sync/audit_upload.py:124-131 (records key required and
# non-empty -> else 400 bad_body).

def _conninfo(url: str) -> str:
    return url.replace("+psycopg", "")


def _seed_connector(owner_url: str, org_id: str, project_id: str,
                    pub_key: bytes) -> str:
    did = str(uuid.uuid4())
    with psycopg.connect(_conninfo(owner_url)) as conn:
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
                       connector_id: str) -> str:
    token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    with psycopg.connect(_conninfo(owner_url)) as conn:
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


def _audit_row_counts(owner_url: str, org_id: str, connector_id: str) -> dict:
    """Rows in every audit table for this connector."""
    out = {}
    with psycopg.connect(_conninfo(owner_url), autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        for table in ("audit_records", "audit_heads", "audit_quarantine"):
            out[table] = conn.execute(
                f"SELECT count(*) FROM {table} WHERE connector_id = %s::uuid",
                [connector_id],
            ).fetchone()[0]
    return out


def _device(info):
    """A fresh project + connector + device token.  Returns (token, cid)."""
    _sk, pub, _kid = keygen()
    org_id = info["org_id"]
    project_id = str(uuid.uuid4())
    with psycopg.connect(_conninfo(info["owner_url"]), autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        create_project(conn, org_id, project_id, "T16g audit contract")
    cid = _seed_connector(info["owner_url"], org_id, project_id, pub)
    token = _seed_device_token(info["owner_url"], org_id, project_id, cid)
    return token, cid


def _post_audit(info, token: str, body: dict):
    import httpx
    with httpx.Client(base_url=info["base_url"], timeout=10) as client:
        return client.post(
            "/api/v1/sync/audit",
            headers={"Authorization": f"Bearer {token}"},
            json=body,
        )


def _one_record(session_id: str) -> dict:
    body = {"event": "t16g_contract", "ts": time.time(), "seq": 1}
    rh = hashlib.sha256(json.dumps(
        body, separators=(",", ":"), sort_keys=True).encode()).hexdigest()
    return {"session_id": session_id, "chain_length": 1,
            "previous_hash": "", "record_hash": rh, "body": body}


@pytest.fixture(scope="module")
def contract_server(pg_url, app_url, owner_url, pg_roles):
    yield from make_sync_server(
        pg_url, app_url, owner_url, org_names=["T16g Contract Org"],
    )


@pytest.mark.pg
def test_guard_audit_upload_one_record_is_200(contract_server):
    """Guard twin: a well-formed one-record upload lands (harness works)."""
    info = contract_server
    token, cid = _device(info)
    r = _post_audit(info, token, {"session_id": "guard-sess",
                                  "records": [_one_record("guard-sess")]})
    assert r.status_code == 200, r.text
    assert r.json()["server_head"]["chain_length"] == 1
    counts = _audit_row_counts(info["owner_url"], info["org_id"], cid)
    assert counts["audit_records"] == 1, counts


# G7-B contract (HANDOFF 4 Nov): body with session_id and NO records key
# must be 400 bad_body, nothing stored; expected change
# ee/src/agg_cp/sync/audit_upload.py:124-131.  Today: 200, nothing stored.
@pytest.mark.pg
def test_audit_upload_missing_records_is_400(contract_server):
    info = contract_server
    token, cid = _device(info)
    r = _post_audit(info, token, {"session_id": "missing-records-sess"})
    assert r.status_code == 400, (
        f"missing 'records' must be 400, got {r.status_code} {r.text}"
    )
    assert r.json().get("error") == "bad_body", r.text
    counts = _audit_row_counts(info["owner_url"], info["org_id"], cid)
    assert all(v == 0 for v in counts.values()), counts


# G7-B contract (HANDOFF 4 Nov): records: [] must be 400 bad_body, nothing
# stored; expected change ee/src/agg_cp/sync/audit_upload.py:124-131.
# Today: 200, nothing stored.
@pytest.mark.pg
def test_audit_upload_empty_records_is_400(contract_server):
    info = contract_server
    token, cid = _device(info)
    r = _post_audit(info, token, {"session_id": "empty-records-sess",
                                  "records": []})
    assert r.status_code == 400, (
        f"empty 'records' must be 400, got {r.status_code} {r.text}"
    )
    assert r.json().get("error") == "bad_body", r.text
    counts = _audit_row_counts(info["owner_url"], info["org_id"], cid)
    assert all(v == 0 for v in counts.values()), counts
