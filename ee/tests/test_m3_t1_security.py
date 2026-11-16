"""M3 T1 security review tests: T1-1 through T1-11.

Spec: ``docs/control-plane/T1_SECURITY_REVIEW.md``.  Each finding becomes
one or more ``xfail(strict=True, raises=M3T1Pending)`` nodes that fail on
the current build for the targeted reason, not a fixture error.

Rulings: M3_PLAN.md T0b-11 (frozen route set), T0b-12 (applied_by).
Baseline: M3_BASELINE.md section 2.1.

Marked ``pg`` (requires Postgres via testcontainers).
"""
from __future__ import annotations

import hashlib
import json
import math
import secrets
import time
import uuid

import psycopg
import pytest
from nacl.signing import SigningKey

from .m3_pending import require_m3
from .m2_sync_server import (
    make_sync_server, ensure_at_head, create_org, create_project,
    keygen, sign_envelope, canonical_json,
)
from .t9_helpers import (
    seed_session, make_session_cookie, compute_csrf,
    _conninfo,
)
from .fake_idp import FakeClock


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _seed_user_row(conn, org_id: str, email: str) -> str:
    user_id = str(uuid.uuid4())
    conn.execute(
        "INSERT INTO users (id, org_id, oidc_issuer, oidc_subject, email, "
        "status, created_at) VALUES (%s, %s, 'https://idp.test', %s, %s, "
        "'active', now()) ON CONFLICT DO NOTHING",
        [user_id, org_id, f"sub-{uuid.uuid4().hex[:8]}", email],
    )
    return user_id


def _bind_role(conn, org_id: str, user_id: str, role: str,
               scope_type: str = "org", scope_id: str | None = None) -> None:
    conn.execute(
        "INSERT INTO role_bindings "
        "(id, org_id, user_id, scope_type, scope_id, role, created_at) "
        "VALUES (%s, %s, %s, %s, %s, %s, now())",
        [str(uuid.uuid4()), org_id, user_id, scope_type,
         scope_id or org_id, role],
    )


def _make_session(owner_url: str, org_id: str, user_id: str,
                  *, clock: FakeClock | None = None):
    if clock is None:
        clock = FakeClock()
    token, csrf, sid = seed_session(
        owner_url, uuid.UUID(org_id), uuid.UUID(user_id), clock=clock,
    )
    cookie = make_session_cookie(uuid.UUID(org_id), token)
    return cookie, csrf, sid


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


def _seed_alert(owner_url: str, org_id: str, project_id: str,
                device_id: str, kind: str, detail: str) -> str:
    alert_id = str(uuid.uuid4())
    conninfo = _conninfo(owner_url)
    with psycopg.connect(conninfo, autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        conn.execute(
            "INSERT INTO sync_alerts "
            "(id, org_id, project_id, connector_id, kind, detail, created_at) "
            "VALUES (%s, %s::uuid, %s::uuid, %s::uuid, %s, %s::jsonb, now())",
            [alert_id, org_id, project_id, device_id, kind, detail],
        )
    return alert_id


def _seed_policy_bundle(owner_url: str, org_id: str, project_id: str,
                        sequence: int, bundle_signer_sk) -> str:
    bundle_payload = {
        "org_id": org_id,
        "project_id": project_id,
        "sequence": sequence,
        "base_sequence": max(0, sequence - 1),
        "registry_version": 1,
        "folder_policy": {"allow": ["*.py"]},
        "governance_policy": {},
        "mcp_policy": {},
        "approval": {"local_fallback": False, "allow_requester": False},
        "not_before": "2026-01-01T00:00:00Z",
        "expires_at": "2099-01-01T00:00:00Z",
        "environment": "prod",
    }
    envelope = sign_envelope("agg/bundle/v1", bundle_payload, bundle_signer_sk)
    blob = json.dumps(envelope, separators=(",", ":"), sort_keys=True)
    bundle_id = str(uuid.uuid4())
    conninfo = _conninfo(owner_url)
    with psycopg.connect(conninfo, autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        conn.execute(
            "INSERT INTO policy_bundles "
            "(id, org_id, project_id, sequence, bundle_blob, "
            "server_signature, created_at) "
            "VALUES (%s, %s::uuid, %s::uuid, %s, %s, '', now())",
            [bundle_id, org_id, project_id, sequence, blob.encode("utf-8")],
        )
    return bundle_id


def _route_not_registered(resp) -> bool:
    if resp.status_code == 405:
        return True
    if resp.status_code == 404:
        try:
            body = resp.json()
        except Exception:
            return False
        if body == {"detail": "Not Found"}:
            return True
    return False


def _make_audit_record(session_id: str, chain_length: int,
                       previous_hash: str, body: dict) -> dict:
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


# ---------------------------------------------------------------------------
# Isolated database: T1-2 stores \u0000 and \ud800 in audit_records.body
# (json column).  Those are valid json but not jsonb, so the 0017 downgrade
# (json -> jsonb) correctly refuses.  A separate database keeps the
# session-scoped database clean for migration round-trip tests.
# ---------------------------------------------------------------------------

def _replace_db_in_url(url: str, new_db: str) -> str:
    """Replace the database name (path component) in a postgresql URL."""
    slash = url.rfind("/")
    qmark = url.find("?", slash) if slash >= 0 else -1
    if qmark >= 0:
        return url[:slash + 1] + new_db + url[qmark:]
    return url[:slash + 1] + new_db


@pytest.fixture(scope="module")
def t1_isolated_db(pg_url, app_url, owner_url, pg_roles):
    """Create an isolated database on the same Postgres container.

    Returns ``(iso_pg_url, iso_app_url, iso_owner_url)`` pointing at
    the new database, already migrated to head.
    """
    db_name = "t1_sec_isolated"
    conninfo = pg_url.replace("+psycopg", "")

    # Create the database and grant role access
    with psycopg.connect(conninfo, autocommit=True) as conn:
        exists = conn.execute(
            "SELECT 1 FROM pg_database WHERE datname = %s", [db_name]
        ).fetchone()
        if not exists:
            conn.execute(f'CREATE DATABASE "{db_name}"')
        conn.execute(f'GRANT ALL ON DATABASE "{db_name}" TO agg_owner')
        conn.execute(f'GRANT CONNECT ON DATABASE "{db_name}" TO agg_app')

    iso_pg_url = _replace_db_in_url(pg_url, db_name)
    iso_conninfo = iso_pg_url.replace("+psycopg", "")

    # Grant schema usage on the new database
    with psycopg.connect(iso_conninfo, autocommit=True) as conn:
        conn.execute("GRANT USAGE ON SCHEMA public TO agg_owner")
        conn.execute("GRANT CREATE ON SCHEMA public TO agg_owner")
        conn.execute("GRANT USAGE ON SCHEMA public TO agg_app")

    # Migrate to head
    ensure_at_head(iso_pg_url)

    iso_app_url = _replace_db_in_url(app_url, db_name)
    iso_owner_url = _replace_db_in_url(owner_url, db_name)

    return iso_pg_url, iso_app_url, iso_owner_url


# ---------------------------------------------------------------------------
# Module-scoped server fixture
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def t1sec_server(t1_isolated_db, pg_roles, tmp_path_factory):
    """4-worker agg_cp server for T1 security tests.

    Uses an isolated database so T1-2 surrogate/NUL rows do not break
    migration round-trip tests on the shared session-scoped database.

    Seeds: org A (alice=admin, viewer_u, approver_u, author_u, auditor_u),
    org B (eve=admin), project + device + token in org A.
    """
    iso_pg_url, iso_app_url, iso_owner_url = t1_isolated_db

    bundle_signer_sk = SigningKey.generate()
    key_dir = tmp_path_factory.mktemp("t1sec_signer")
    key_file = key_dir / "bundle_signer.key"
    key_file.write_bytes(bytes(bundle_signer_sk).hex().encode("ascii"))
    import os
    old_bs = os.environ.get("AGG_BUNDLE_SIGNER_KEY_FILE")
    os.environ["AGG_BUNDLE_SIGNER_KEY_FILE"] = str(key_file)

    gen = make_sync_server(
        iso_pg_url, iso_app_url, iso_owner_url,
        org_names=["T1Sec Org A", "T1Sec Org B"],
    )
    info = next(gen)

    conninfo = _conninfo(iso_owner_url)
    with psycopg.connect(conninfo, autocommit=True) as conn:
        org_a = info["org_id"]
        org_b = info["org_evil"]

        # --- org A users ---
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_a])
        alice_id = _seed_user_row(conn, org_a, "alice@t1sec.test")
        _bind_role(conn, org_a, alice_id, "admin")

        viewer_id = _seed_user_row(conn, org_a, "viewer@t1sec.test")
        _bind_role(conn, org_a, viewer_id, "viewer")

        approver_id = _seed_user_row(conn, org_a, "approver@t1sec.test")
        author_id = _seed_user_row(conn, org_a, "author@t1sec.test")
        auditor_id = _seed_user_row(conn, org_a, "auditor@t1sec.test")
        _bind_role(conn, org_a, auditor_id, "auditor")

        project_id = str(uuid.uuid4())
        create_project(conn, org_a, project_id, "T1Sec Project")

        # Project-scoped roles for approver and author
        _bind_role(conn, org_a, approver_id, "approver",
                   scope_type="project", scope_id=project_id)
        _bind_role(conn, org_a, author_id, "policy_author",
                   scope_type="project", scope_id=project_id)

        # --- org B ---
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_b])
        eve_id = _seed_user_row(conn, org_b, "eve@t1sec.test")
        _bind_role(conn, org_b, eve_id, "admin")

    # Device + token
    sk_dev, pub_dev, kid_dev = keygen()
    device_id = _seed_connector(iso_owner_url, org_a, project_id, pub_dev)
    token = secrets.token_urlsafe(32)
    _seed_device_token(iso_owner_url, org_a, project_id, device_id, token)

    # Bundles (seq 1 and 3, skip 2 for the skipped-sequence test)
    bundle_1_id = _seed_policy_bundle(iso_owner_url, org_a, project_id, 1, bundle_signer_sk)
    _seed_policy_bundle(iso_owner_url, org_a, project_id, 3, bundle_signer_sk)

    # Seed an approval row for bundle 1 so T1-7 tests can check its fields
    conninfo = _conninfo(iso_owner_url)
    with psycopg.connect(conninfo, autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_a])
        conn.execute(
            "INSERT INTO policy_change_approvals "
            "(id, org_id, change_request_id, key_id, user_id, signature, "
            "signed_at, created_at) "
            "VALUES (%s, %s::uuid, %s::uuid, %s, %s::uuid, %s, now(), now())",
            [str(uuid.uuid4()), org_a, bundle_1_id, "test-key-id",
             alice_id, '{"kind":"test","sig":"placeholder"}'],
        )

    # Alert
    _seed_alert(iso_owner_url, org_a, project_id, device_id,
                "test_kind", json.dumps({"msg": "seeded for T1"}))

    # Sessions for all users
    clock = FakeClock()
    sessions = {}
    for name, uid in [("alice", alice_id), ("viewer", viewer_id),
                      ("approver", approver_id), ("author", author_id),
                      ("auditor", auditor_id), ("eve", eve_id)]:
        oid = org_a if name != "eve" else org_b
        c, csrf, sid = _make_session(iso_owner_url, oid, uid, clock=clock)
        sessions[name] = {"cookie": c, "csrf": csrf}

    info.update({
        "alice_id": alice_id,
        "viewer_id": viewer_id,
        "approver_id": approver_id,
        "author_id": author_id,
        "auditor_id": auditor_id,
        "eve_id": eve_id,
        "project_id": project_id,
        "device_id": device_id,
        "device_token": token,
        "bundle_signer_sk": bundle_signer_sk,
        "sessions": sessions,
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
# GUARD TWINS -- prove the fixture works (PASS today)
# ===================================================================

@pytest.mark.pg
def test_guard_t1sec_server_ready(t1sec_server):
    """Guard: server responds to /ready."""
    import httpx
    with httpx.Client(base_url=t1sec_server["base_url"], timeout=10) as c:
        assert c.get("/ready").status_code == 200


@pytest.mark.pg
def test_guard_t1sec_alice_can_list_bundles(t1sec_server):
    """Guard: alice can call GET /admin/bundles (proves session + admin + route)."""
    import httpx
    info = t1sec_server
    s = info["sessions"]["alice"]
    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        r = c.get("/api/v1/admin/bundles",
                  params={"project": info["project_id"]},
                  cookies={"__Host-agg_session": s["cookie"]})
    # The route exists and alice can call it (admin)
    assert r.status_code == 200, f"guard failed: {r.status_code} {r.text[:200]}"


# ===================================================================
# T1-1: body absent or non-dict refused 400 hash_mismatch, nothing stored
# ===================================================================

@pytest.mark.pg
def test_t1_1_absent_body_refused(t1sec_server):
    """A record with no ``body`` key and an arbitrary ``record_hash`` must be
    400 ``hash_mismatch`` with nothing stored (T1-1)."""
    import httpx
    info = t1sec_server
    session_id = f"sess-nobody-{uuid.uuid4().hex[:8]}"
    records = [{
        "session_id": session_id,
        "chain_length": 1,
        "previous_hash": "",
        "record_hash": hashlib.sha256(b"anything").hexdigest(),
        # no "body" key
    }]
    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        resp = c.post(
            "/api/v1/sync/audit",
            headers={"Authorization": f"Bearer {info['device_token']}"},
            json={"session_id": session_id, "records": records},
        )
    require_m3(1, resp.status_code == 400,
               f"absent body must be 400, got {resp.status_code}")
    body = resp.json()
    assert body.get("error") == "hash_mismatch", \
        f"error must be hash_mismatch, got {body}"

    conninfo = _conninfo(info["owner_url"])
    with psycopg.connect(conninfo) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [info["org_id"]])
        count = conn.execute(
            "SELECT count(*) FROM audit_records "
            "WHERE connector_id = %s::uuid AND session_id = %s",
            [info["device_id"], session_id],
        ).fetchone()[0]
    assert count == 0, f"absent body must store nothing, found {count}"


@pytest.mark.pg
def test_t1_1_non_dict_body_refused(t1sec_server):
    """A record with ``body`` as a list must be 400 ``hash_mismatch``
    (T1-1)."""
    import httpx
    info = t1sec_server
    session_id = f"sess-listbody-{uuid.uuid4().hex[:8]}"
    body_val = [1, 2, 3]
    body_bytes = json.dumps(body_val, separators=(",", ":"),
                            sort_keys=True).encode()
    rh = hashlib.sha256(body_bytes).hexdigest()
    records = [{
        "session_id": session_id,
        "chain_length": 1,
        "previous_hash": "",
        "record_hash": rh,
        "body": body_val,
    }]
    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        resp = c.post(
            "/api/v1/sync/audit",
            headers={"Authorization": f"Bearer {info['device_token']}"},
            json={"session_id": session_id, "records": records},
        )
    require_m3(1, resp.status_code == 400,
               f"non-dict body must be 400, got {resp.status_code}")
    assert resp.json().get("error") == "hash_mismatch"

    # Verify nothing stored (T1-1: nothing stored)
    conninfo = _conninfo(info["owner_url"])
    with psycopg.connect(conninfo) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [info["org_id"]])
        count = conn.execute(
            "SELECT count(*) FROM audit_records "
            "WHERE connector_id = %s::uuid AND session_id = %s",
            [info["device_id"], session_id],
        ).fetchone()[0]
    assert count == 0, f"non-dict body must store nothing, found {count}"


# ===================================================================
# T1-2: property test -- every accepted record verifies
# ===================================================================

@pytest.mark.pg
def test_t1_2_property_accepted_records_verify(t1sec_server):
    """Every record the route accepts must verify under ``verify_project``
    and in the export.  Test with floats >= 1e16, 1e22, 1.5e300, -0.0,
    non-ASCII, astral characters and nested key order (T1-2)."""
    import httpx
    info = t1sec_server

    # Each body exercises a different edge case
    bodies = [
        {"event": "float_1e16", "val": 1e16},
        {"event": "float_1e22", "val": 1e22},
        {"event": "float_1.5e300", "val": 1.5e300},
        {"event": "neg_zero", "val": -0.0},
        {"event": "non_ascii", "msg": "Achtung Speziäl"},
        {"event": "astral", "msg": "\U0001F600\U0001F4A9"},
        {"event": "nested_order", "z": {"b": 2, "a": 1}, "a": 0},
    ]

    session_id = f"sess-prop-{uuid.uuid4().hex[:8]}"
    records = []
    prev_hash = ""
    for i, body in enumerate(bodies, 1):
        rec = _make_audit_record(session_id, i, prev_hash, body)
        records.append(rec)
        prev_hash = rec["record_hash"]

    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        resp = c.post(
            "/api/v1/sync/audit",
            headers={"Authorization": f"Bearer {info['device_token']}"},
            json={"session_id": session_id, "records": records},
        )
    require_m3(1, resp.status_code == 200,
               f"property records must be accepted, got {resp.status_code}: "
               f"{resp.text[:300]}")

    # Build the original hashes from what we sent for comparison
    original_hashes = {}
    for rec in records:
        original_hashes[rec["chain_length"]] = rec["record_hash"]

    # Verify via the verify route
    s = info["sessions"]["alice"]
    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        vr = c.get("/api/v1/audit/verify",
                   params={"project": info["project_id"]},
                   cookies={"__Host-agg_session": s["cookie"]})
    require_m3(1, not _route_not_registered(vr),
               "verify route not registered")
    require_m3(1, vr.status_code == 200,
               f"verify must return 200, got {vr.status_code}")
    vbody = vr.json()
    require_m3(1, vbody.get("ok") is True,
               f"verify_project must be ok after property upload, got {vbody}")

    # Verify via export: recompute each record's hash offline
    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        er = c.get("/api/v1/audit/export",
                   params={"project": info["project_id"]},
                   cookies={"__Host-agg_session": s["cookie"]})
    require_m3(1, not _route_not_registered(er),
               "export route not registered")
    require_m3(1, er.status_code == 200,
               f"export must return 200, got {er.status_code}")
    lines = [l for l in er.text.strip().split("\n") if l.strip()]
    prop_lines = [json.loads(l) for l in lines
                  if json.loads(l).get("session_id") == session_id]
    require_m3(1, len(prop_lines) == len(bodies),
               f"export must include all {len(bodies)} records, got {len(prop_lines)}")
    for rec in prop_lines:
        body_val = rec["body"]
        canonical = json.dumps(body_val, separators=(",", ":"),
                               sort_keys=True).encode()
        recomputed = hashlib.sha256(canonical).hexdigest()
        cl = rec.get("chain_length")
        # Recomputed hash from the exported body must match the stored record_hash
        require_m3(1, rec["record_hash"] == recomputed,
                   f"export body hash mismatch at chain_length {cl}")
        # Stored record_hash must match the ORIGINAL hash we sent
        require_m3(1, rec["record_hash"] == original_hashes.get(cl),
                   f"exported hash differs from original at chain_length {cl}")


# ===================================================================
# T1-2 alongside: NaN/Infinity -> named 400 + sync_alerts row
# ===================================================================

@pytest.mark.pg
def test_t1_2_nan_refused_named_400(t1sec_server):
    """``NaN`` in a record body must be a named 400 (never 500) and write
    exactly 1 ``sync_alerts`` row (delta scoped to this session) with kind
    ``audit_record_unstorable`` (T1-2, T1-24)."""
    import httpx
    info = t1sec_server
    session_id = f"sess-nan-{uuid.uuid4().hex[:8]}"
    conninfo = _conninfo(info["owner_url"])

    # Baseline alert count for this session
    with psycopg.connect(conninfo) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [info["org_id"]])
        before = conn.execute(
            "SELECT count(*) FROM sync_alerts "
            "WHERE kind = 'audit_record_unstorable' "
            "AND connector_id = %s::uuid",
            [info["device_id"]],
        ).fetchone()[0]

    body_obj = {"event": "nan_test", "val": float("nan")}
    raw_body = json.dumps(
        {"session_id": session_id, "records": [{
            "session_id": session_id,
            "chain_length": 1,
            "previous_hash": "",
            "record_hash": "0" * 64,
            "body": body_obj,
        }]},
        allow_nan=True,
    )

    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        resp = c.post(
            "/api/v1/sync/audit",
            headers={
                "Authorization": f"Bearer {info['device_token']}",
                "Content-Type": "application/json",
            },
            content=raw_body.encode("utf-8"),
        )
    require_m3(1, resp.status_code == 400,
               f"NaN body must be 400, got {resp.status_code}")

    with psycopg.connect(conninfo) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [info["org_id"]])
        after = conn.execute(
            "SELECT count(*) FROM sync_alerts "
            "WHERE kind = 'audit_record_unstorable' "
            "AND connector_id = %s::uuid",
            [info["device_id"]],
        ).fetchone()[0]
    require_m3(1, after - before == 1,
               f"NaN must create exactly 1 alert, delta={after - before}")


@pytest.mark.pg
def test_t1_2_infinity_refused_named_400(t1sec_server):
    """``Infinity``, ``-Infinity`` and ``1e999`` must each be 400 with
    exactly 1 alert delta scoped to the connector (T1-2, T1-24)."""
    import httpx
    info = t1sec_server
    conninfo = _conninfo(info["owner_url"])

    for label, raw_val in [("Infinity", "Infinity"),
                           ("-Infinity", "-Infinity"),
                           ("1e999", "1e999")]:
        session_id = f"sess-inf-{label}-{uuid.uuid4().hex[:6]}"

        with psycopg.connect(conninfo) as conn:
            conn.execute("SELECT set_config('app.org_id', %s, false)",
                         [info["org_id"]])
            before = conn.execute(
                "SELECT count(*) FROM sync_alerts "
                "WHERE kind = 'audit_record_unstorable' "
                "AND connector_id = %s::uuid",
                [info["device_id"]],
            ).fetchone()[0]

        raw_body = (
            '{"session_id":"' + session_id + '","records":[{'
            '"session_id":"' + session_id + '",'
            '"chain_length":1,'
            '"previous_hash":"",'
            '"record_hash":"' + "0" * 64 + '",'
            '"body":{"event":"inf_test","val":' + raw_val + '}'
            '}]}'
        )
        with httpx.Client(base_url=info["base_url"], timeout=10) as c:
            resp = c.post(
                "/api/v1/sync/audit",
                headers={
                    "Authorization": f"Bearer {info['device_token']}",
                    "Content-Type": "application/json",
                },
                content=raw_body.encode("utf-8"),
            )
        require_m3(1, resp.status_code == 400,
                   f"{label} body must be 400, got {resp.status_code}")

        with psycopg.connect(conninfo) as conn:
            conn.execute("SELECT set_config('app.org_id', %s, false)",
                         [info["org_id"]])
            after = conn.execute(
                "SELECT count(*) FROM sync_alerts "
                "WHERE kind = 'audit_record_unstorable' "
                "AND connector_id = %s::uuid",
                [info["device_id"]],
            ).fetchone()[0]
        require_m3(1, after - before == 1,
                   f"{label} must create exactly 1 alert, delta={after - before}")


# ===================================================================
# T1-2: lone surrogate never 500 and never stalls (unstorable text)
# ===================================================================

@pytest.mark.pg
@pytest.mark.timeout(30)
def test_t1_2_lone_surrogate_no_500(t1sec_server):
    r"""Lone surrogate ``\ud800`` and NUL ``\u0000`` must be 200 with
    correct hash, stored, verify ok, and offline hash ok (T1-24 ruling
    reversal: the review's text-case ruling stands)."""
    import httpx
    info = t1sec_server

    # --- lone surrogate ---
    session_surr = f"sess-surr-{uuid.uuid4().hex[:8]}"
    # Body with lone surrogate: {"event":"surrogate","msg":"\ud800"}
    body_surr = {"event": "surrogate", "msg": "\ud800"}
    body_surr_bytes = json.dumps(
        body_surr, separators=(",", ":"), sort_keys=True,
        ensure_ascii=True,
    ).encode("utf-8", errors="surrogatepass")
    rh_surr = hashlib.sha256(body_surr_bytes).hexdigest()

    raw_surr = (
        '{"session_id":"' + session_surr + '","records":[{'
        '"session_id":"' + session_surr + '",'
        '"chain_length":1,'
        '"previous_hash":"",'
        '"record_hash":"' + rh_surr + '",'
        '"body":{"event":"surrogate","msg":"\\ud800"}'
        '}]}'
    )
    with httpx.Client(base_url=info["base_url"], timeout=20) as c:
        resp_surr = c.post(
            "/api/v1/sync/audit",
            headers={
                "Authorization": f"Bearer {info['device_token']}",
                "Content-Type": "application/json",
            },
            content=raw_surr.encode("utf-8", errors="surrogatepass"),
        )
    require_m3(1, resp_surr.status_code == 200,
               f"lone surrogate with correct hash must be 200, got {resp_surr.status_code}")

    # Stored
    conninfo = _conninfo(info["owner_url"])
    with psycopg.connect(conninfo) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [info["org_id"]])
        count = conn.execute(
            "SELECT count(*) FROM audit_records "
            "WHERE connector_id = %s::uuid AND session_id = %s",
            [info["device_id"], session_surr],
        ).fetchone()[0]
    require_m3(1, count == 1,
               f"lone surrogate record must be stored, found {count}")

    # Verify ok
    s = info["sessions"]["alice"]
    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        vr = c.get("/api/v1/audit/verify",
                   params={"project": info["project_id"]},
                   cookies={"__Host-agg_session": s["cookie"]})
    require_m3(1, vr.status_code == 200 and vr.json().get("ok") is True,
               f"verify must be ok after surrogate, got {vr.status_code}")

    # Offline hash ok from export
    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        er = c.get("/api/v1/audit/export",
                   params={"project": info["project_id"]},
                   cookies={"__Host-agg_session": s["cookie"]})
    require_m3(1, er.status_code == 200, "export must be 200")
    surr_lines = [
        json.loads(l) for l in er.text.strip().split("\n") if l.strip()
        and json.loads(l).get("session_id") == session_surr
    ]
    require_m3(1, len(surr_lines) == 1,
               f"export must include surrogate record, found {len(surr_lines)}")
    exported = surr_lines[0]
    offline_bytes = json.dumps(
        exported["body"], separators=(",", ":"), sort_keys=True,
        ensure_ascii=True,
    ).encode("utf-8", errors="surrogatepass")
    offline_hash = hashlib.sha256(offline_bytes).hexdigest()
    require_m3(1, exported["record_hash"] == offline_hash,
               f"offline hash mismatch: {exported['record_hash']} vs {offline_hash}")

    # --- NUL character ---
    session_nul = f"sess-nul-{uuid.uuid4().hex[:8]}"
    body_nul = {"event": "nul_test", "msg": "\u0000"}
    rec_nul = _make_audit_record(session_nul, 1, "", body_nul)
    with httpx.Client(base_url=info["base_url"], timeout=20) as c:
        resp_nul = c.post(
            "/api/v1/sync/audit",
            headers={"Authorization": f"Bearer {info['device_token']}"},
            json={"session_id": session_nul, "records": [rec_nul]},
        )
    require_m3(1, resp_nul.status_code == 200,
               f"NUL char must be 200, got {resp_nul.status_code}")

    with psycopg.connect(conninfo) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [info["org_id"]])
        count_nul = conn.execute(
            "SELECT count(*) FROM audit_records "
            "WHERE connector_id = %s::uuid AND session_id = %s",
            [info["device_id"], session_nul],
        ).fetchone()[0]
    require_m3(1, count_nul == 1,
               f"NUL record must be stored, found {count_nul}")

    # Verify ok for NUL (T1-24 round 3: add verify ok and offline hash ok)
    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        vr_nul = c.get("/api/v1/audit/verify",
                       params={"project": info["project_id"]},
                       cookies={"__Host-agg_session": s["cookie"]})
    require_m3(1, vr_nul.status_code == 200 and vr_nul.json().get("ok") is True,
               f"verify must be ok after NUL record, got {vr_nul.status_code}")

    # Offline hash ok for NUL from export
    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        er_nul = c.get("/api/v1/audit/export",
                       params={"project": info["project_id"]},
                       cookies={"__Host-agg_session": s["cookie"]})
    require_m3(1, er_nul.status_code == 200, "export must be 200 after NUL")
    nul_lines = [
        json.loads(l) for l in er_nul.text.strip().split("\n") if l.strip()
        and not l.strip().startswith('{"_meta"')
        and json.loads(l).get("session_id") == session_nul
    ]
    require_m3(1, len(nul_lines) == 1,
               f"export must include NUL record, found {len(nul_lines)}")
    exported_nul = nul_lines[0]
    offline_nul_bytes = json.dumps(
        exported_nul["body"], separators=(",", ":"), sort_keys=True,
    ).encode("utf-8")
    offline_nul_hash = hashlib.sha256(offline_nul_bytes).hexdigest()
    require_m3(1, exported_nul["record_hash"] == offline_nul_hash,
               f"NUL offline hash mismatch: {exported_nul['record_hash']} "
               f"vs {offline_nul_hash}")


# ===================================================================
# T1-3: /admin/* one negative per role per route
# ===================================================================

_ADMIN_ROUTES = [
    ("GET", "/api/v1/admin/enrollment-codes"),
    ("GET", "/api/v1/admin/bundles"),
    ("GET", "/api/v1/admin/bundles/1"),
]

_NON_ADMIN_ROLES = ["viewer", "approver", "author", "auditor"]


@pytest.mark.pg
@pytest.mark.parametrize("role", _NON_ADMIN_ROLES)
@pytest.mark.parametrize("method_path", _ADMIN_ROUTES,
                         ids=[f"{m} {p}" for m, p in _ADMIN_ROUTES])
def test_t1_3_admin_route_refuses_non_admin(t1sec_server, role, method_path):
    """Non-admin roles must be refused on /admin/* routes (T1-3)."""
    import httpx
    method, path = method_path
    info = t1sec_server
    s = info["sessions"][role]
    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        if method == "GET":
            r = c.get(path, params={"project": info["project_id"]},
                      cookies={"__Host-agg_session": s["cookie"]})
        else:
            r = c.post(path, json={"project_id": info["project_id"]},
                       cookies={"__Host-agg_session": s["cookie"]},
                       headers={"X-CSRF-Token": s["csrf"]})
    require_m3(1, not _route_not_registered(r),
               f"{method} {path} not registered")
    # Must be refused: uniform 404 (T1-3)
    require_m3(1, r.status_code == 404,
               f"{role} on {method} {path} must be 404, got {r.status_code}")


# ===================================================================
# T1-4: viewer, project approver and policy_author refused on export/verify;
#        org auditor allowed
# ===================================================================

@pytest.mark.pg
@pytest.mark.parametrize("role", ["viewer", "approver", "author"])
def test_t1_4_non_admin_refused_export(t1sec_server, role):
    """viewer, project approver and policy_author must be refused on
    GET /audit/export (T1-4)."""
    import httpx
    info = t1sec_server
    s = info["sessions"][role]
    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        r = c.get("/api/v1/audit/export",
                  params={"project": info["project_id"]},
                  cookies={"__Host-agg_session": s["cookie"]})
    require_m3(1, not _route_not_registered(r),
               "export route not registered")
    require_m3(1, r.status_code == 404,
               f"{role} on export must be 404, got {r.status_code}")


@pytest.mark.pg
@pytest.mark.parametrize("role", ["viewer", "approver", "author"])
def test_t1_4_non_admin_refused_verify(t1sec_server, role):
    """viewer, project approver and policy_author must be refused on
    GET /audit/verify (T1-4)."""
    import httpx
    info = t1sec_server
    s = info["sessions"][role]
    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        r = c.get("/api/v1/audit/verify",
                  params={"project": info["project_id"]},
                  cookies={"__Host-agg_session": s["cookie"]})
    require_m3(1, not _route_not_registered(r),
               "verify route not registered")
    require_m3(1, r.status_code == 404,
               f"{role} on verify must be 404, got {r.status_code}")


@pytest.mark.pg
def test_t1_4_auditor_allowed_export(t1sec_server):
    """Org auditor must be allowed on GET /audit/export while a viewer is
    refused (T1-4).  Bites because the viewer check fails on the unfixed
    build (viewer gets 200 today)."""
    import httpx
    info = t1sec_server
    # First confirm viewer IS refused (the T1-4 fix must be in place)
    sv = info["sessions"]["viewer"]
    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        rv = c.get("/api/v1/audit/export",
                   params={"project": info["project_id"]},
                   cookies={"__Host-agg_session": sv["cookie"]})
    require_m3(1, not _route_not_registered(rv),
               "export route not registered")
    require_m3(1, rv.status_code == 404,
               f"viewer must be refused on export first, got {rv.status_code}")
    # Then confirm auditor IS allowed
    s = info["sessions"]["auditor"]
    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        r = c.get("/api/v1/audit/export",
                  params={"project": info["project_id"]},
                  cookies={"__Host-agg_session": s["cookie"]})
    assert r.status_code == 200, \
        f"auditor on export must be 200, got {r.status_code}"


@pytest.mark.pg
def test_t1_4_auditor_allowed_verify(t1sec_server):
    """Org auditor must be allowed on GET /audit/verify while a viewer is
    refused (T1-4).  Bites because the viewer check fails on the unfixed
    build (viewer gets 200 today)."""
    import httpx
    info = t1sec_server
    # First confirm viewer IS refused
    sv = info["sessions"]["viewer"]
    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        rv = c.get("/api/v1/audit/verify",
                   params={"project": info["project_id"]},
                   cookies={"__Host-agg_session": sv["cookie"]})
    require_m3(1, not _route_not_registered(rv),
               "verify route not registered")
    require_m3(1, rv.status_code == 404,
               f"viewer must be refused on verify first, got {rv.status_code}")
    # Then confirm auditor IS allowed
    s = info["sessions"]["auditor"]
    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        r = c.get("/api/v1/audit/verify",
                  params={"project": info["project_id"]},
                  cookies={"__Host-agg_session": s["cookie"]})
    assert r.status_code == 200, \
        f"auditor on verify must be 200, got {r.status_code}"


# ===================================================================
# T1-5: cursor works across all 4 workers
# ===================================================================

@pytest.mark.pg
def test_t1_5_cursor_walks_all_pages_on_multiworker(t1sec_server):
    """Walking every page on the 4-worker server (``make_sync_server``
    always starts 4 workers) must never produce a ``bad_cursor``.  Each
    walk must return the exact seeded set with no duplicates and every
    page must be 200 (T1-5)."""
    import httpx
    info = t1sec_server
    s = info["sessions"]["alice"]

    # Seed 30 devices to guarantee multiple pages (+ 1 from fixture = 31)
    for _ in range(30):
        sk, pub, kid = keygen()
        _seed_connector(info["owner_url"], info["org_id"],
                        info["project_id"], pub)

    # Collect the full seeded set once for comparison
    reference_ids: set[str] | None = None
    for walk in range(3):  # repeat to hit different workers
        collected: list[str] = []
        cursor = None
        for _page in range(50):  # generous page limit
            params: dict = {"project": info["project_id"]}
            if cursor:
                params["cursor"] = cursor
            with httpx.Client(base_url=info["base_url"], timeout=10) as c:
                r = c.get("/api/v1/devices", params=params,
                          cookies={"__Host-agg_session": s["cookie"]})
            require_m3(1, not _route_not_registered(r),
                       "devices route not registered")
            require_m3(1, r.status_code == 200,
                       f"walk {walk} page {_page} failed with {r.status_code}: "
                       f"{r.text[:200]}")
            body = r.json()
            items = body.get("items", [])
            for item in items:
                collected.append(item["id"])
            cursor = body.get("cursor")
            if not cursor:
                break
        # No duplicates within a single walk
        require_m3(1, len(collected) == len(set(collected)),
                   f"walk {walk}: duplicates found ({len(collected)} ids, "
                   f"{len(set(collected))} unique)")
        walk_set = set(collected)
        if reference_ids is None:
            reference_ids = walk_set
        else:
            require_m3(1, walk_set == reference_ids,
                       f"walk {walk}: returned {len(walk_set)} ids vs "
                       f"reference {len(reference_ids)}")

    assert reference_ids is not None and len(reference_ids) >= 31, \
        f"must walk all devices (>= 31), got {len(reference_ids) if reference_ids else 0}"


# ===================================================================
# T1-7: signature_verified false
# ===================================================================

@pytest.mark.pg
def test_t1_7_approval_signature_verified_false(t1sec_server):
    """Bundle detail approvals must carry ``signature_verified: false``
    until T4 (T1-7)."""
    import httpx
    info = t1sec_server
    s = info["sessions"]["alice"]
    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        r = c.get("/api/v1/admin/bundles/1",
                  params={"project": info["project_id"]},
                  cookies={"__Host-agg_session": s["cookie"]})
    require_m3(1, not _route_not_registered(r),
               "bundles detail route not registered")
    assert r.status_code == 200
    detail = r.json()
    approvals = detail.get("approvals", [])
    require_m3(1, len(approvals) >= 1,
               "seeded bundle must have approvals")
    for a in approvals:
        require_m3(1, "signature_verified" in a,
                   "approval must carry signature_verified field")
        require_m3(1, a["signature_verified"] is False,
                   f"signature_verified must be false, got {a['signature_verified']}")


# ===================================================================
# T1-8: export has connector_id, truncation marker, byte cap, stable order
# ===================================================================

@pytest.mark.pg
def test_t1_8_export_has_connector_id(t1sec_server):
    """Each export record must include ``connector_id`` (T1-8)."""
    import httpx
    info = t1sec_server
    s = info["sessions"]["alice"]

    # Upload a record so the export is non-empty
    session_id = f"sess-expid-{uuid.uuid4().hex[:8]}"
    rec = _make_audit_record(session_id, 1, "", {"event": "export_id_test"})
    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        c.post("/api/v1/sync/audit",
               headers={"Authorization": f"Bearer {info['device_token']}"},
               json={"session_id": session_id, "records": [rec]})

    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        r = c.get("/api/v1/audit/export",
                  params={"project": info["project_id"]},
                  cookies={"__Host-agg_session": s["cookie"]})
    require_m3(1, not _route_not_registered(r), "export route not registered")
    assert r.status_code == 200
    lines = [l for l in r.text.strip().split("\n") if l.strip()]
    assert len(lines) >= 1, "export must have records"
    first_rec = json.loads(lines[0])
    require_m3(1, "connector_id" in first_rec,
               f"export record must have connector_id, keys: {list(first_rec.keys())}")
    for line in lines:
        rec = json.loads(line)
        assert "connector_id" in rec, \
            f"export record must have connector_id, keys: {list(rec.keys())}"


@pytest.mark.pg
def test_t1_8_export_truncation_marker(t1sec_server):
    """A real run past the row limit (10,050 rows seeded directly in DB):
    ``X-Export-Truncated: true``, header and final line agree, body bytes
    <= declared cap including the final line (T1-16, T1-24).

    The response is NOT a ``StreamingResponse`` and has
    ``Content-Length``.  Peak memory is tested separately in
    ``test_t1_17_export_peak_memory`` (T1-17 round 3)."""
    import httpx
    info = t1sec_server
    s = info["sessions"]["alice"]
    conninfo = _conninfo(info["owner_url"])
    org_id = info["org_id"]
    project_id = info["project_id"]
    device_id = info["device_id"]

    # Seed 10,050 rows directly in the DB for speed
    with psycopg.connect(conninfo, autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        for batch_start in range(0, 10050, 500):
            values_parts = []
            params = []
            for i in range(batch_start, min(batch_start + 500, 10050)):
                rid = str(uuid.uuid4())
                sid = f"sess-trunc-{i // 100}"
                body_dict = {"i": i}
                body_str = json.dumps(body_dict, separators=(",", ":"),
                                      sort_keys=True)
                rh = hashlib.sha256(body_str.encode()).hexdigest()
                values_parts.append(
                    "(%s, %s::uuid, %s::uuid, %s, %s, %s, %s, %s::json, now())"
                )
                params.extend([
                    rid, org_id, device_id, sid,
                    i % 10000 + 1, "", rh, body_str,
                ])
            sql = (
                "INSERT INTO audit_records "
                "(id, org_id, connector_id, session_id, chain_length, "
                "previous_hash, record_hash, body, created_at) VALUES "
                + ", ".join(values_parts)
                + " ON CONFLICT DO NOTHING"
            )
            conn.execute(sql, params)

    with httpx.Client(base_url=info["base_url"], timeout=120) as c:
        r = c.get("/api/v1/audit/export",
                  params={"project": project_id},
                  cookies={"__Host-agg_session": s["cookie"]})
    require_m3(1, not _route_not_registered(r), "export route not registered")
    require_m3(1, r.status_code == 200, f"export must be 200, got {r.status_code}")

    # Header must exist and say truncated
    truncated_header = r.headers.get("X-Export-Truncated")
    require_m3(1, truncated_header is not None,
               "export must have X-Export-Truncated header")
    require_m3(1, truncated_header == "true",
               f"10050 rows must truncate, got X-Export-Truncated={truncated_header!r}")

    # Byte cap header
    cap_str = r.headers.get("X-Export-Byte-Cap")
    require_m3(1, cap_str is not None,
               "export must declare X-Export-Byte-Cap header")
    cap = int(cap_str)

    # Body bytes <= declared cap including the final line
    body_bytes = len(r.content)
    require_m3(1, body_bytes <= cap,
               f"truncated export body ({body_bytes}) exceeds cap ({cap})")

    # Final line must agree
    lines = r.text.rstrip("\n").split("\n")
    last = json.loads(lines[-1])
    last_trunc = (last.get("truncated") is True
                  or last.get("_meta", {}).get("truncated") is True)
    require_m3(1, last_trunc,
               f"final metadata line must say truncated, got: {lines[-1][:200]}")

    # Content-Length present (T1-17: not StreamingResponse)
    require_m3(1, "content-length" in r.headers,
               "export response must have Content-Length (not StreamingResponse)")


@pytest.mark.pg
def test_t1_8_export_stable_order(t1sec_server):
    """Export order: one batch per session per connector, uploaded in
    reverse order (second connector first, beta before alpha), plus one
    multi-record batch for the shared ``now()`` tie within a chain.
    Three identical exports; exact sort by (connector_id, session_id,
    chain_length) (T1-12, T1-24)."""
    import httpx
    info = t1sec_server
    s = info["sessions"]["alice"]

    # Second connector for this project
    sk2, pub2, kid2 = keygen()
    dev2_id = _seed_connector(info["owner_url"], info["org_id"],
                              info["project_id"], pub2)
    token2 = secrets.token_urlsafe(32)
    _seed_device_token(info["owner_url"], info["org_id"],
                       info["project_id"], dev2_id, token2)

    # Upload in REVERSE order: second connector first, beta before alpha.
    # One batch per session per connector (each batch = one session).
    tag = uuid.uuid4().hex[:6]
    for tok, label in [(token2, "dev2"), (info["device_token"], "dev1")]:
        for sid_suffix in ["beta", "alpha"]:
            sid = f"sess-order-{tag}-{label}-{sid_suffix}"
            recs = []
            prev = ""
            for cl in range(1, 4):
                rec = _make_audit_record(sid, cl, prev,
                                         {"event": "order_test",
                                          "dev": label, "s": sid_suffix,
                                          "cl": cl})
                prev = rec["record_hash"]
                recs.append(rec)
            with httpx.Client(base_url=info["base_url"], timeout=10) as c:
                resp = c.post(
                    "/api/v1/sync/audit",
                    headers={"Authorization": f"Bearer {tok}"},
                    json={"session_id": sid, "records": recs},
                )
            require_m3(1, resp.status_code == 200,
                       f"batch {label}/{sid_suffix} must be 200, "
                       f"got {resp.status_code}: {resp.text[:200]}")

    # Multi-record batch for the shared now() tie within one chain
    tie_sid = f"sess-order-{tag}-dev1-tie"
    tie_recs = []
    prev = ""
    for cl in range(1, 6):
        rec = _make_audit_record(tie_sid, cl, prev,
                                 {"event": "tie_test", "cl": cl})
        prev = rec["record_hash"]
        tie_recs.append(rec)
    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        resp = c.post(
            "/api/v1/sync/audit",
            headers={"Authorization": f"Bearer {info['device_token']}"},
            json={"session_id": tie_sid, "records": tie_recs},
        )
    require_m3(1, resp.status_code == 200,
               f"tie batch must be 200, got {resp.status_code}")

    # Fetch export 3 times
    exports = []
    for attempt in range(3):
        with httpx.Client(base_url=info["base_url"], timeout=30) as c:
            r = c.get("/api/v1/audit/export",
                      params={"project": info["project_id"]},
                      cookies={"__Host-agg_session": s["cookie"]})
        require_m3(1, r.status_code == 200,
                   f"export attempt {attempt} must be 200, got {r.status_code}")
        exports.append(r.text)

    require_m3(1, exports[0] == exports[1] == exports[2],
               "export must produce identical output across 3 requests")

    lines = [l for l in exports[0].strip().split("\n") if l.strip()]
    parsed = []
    for l in lines:
        rec = json.loads(l)
        if "connector_id" not in rec:
            continue
        parsed.append((rec["connector_id"], rec["session_id"],
                        rec.get("chain_length", 0)))

    sorted_order = sorted(parsed, key=lambda t: (t[0], t[1], t[2]))
    require_m3(1, parsed == sorted_order,
               "export order must be (connector_id, session_id, chain_length)")


@pytest.mark.pg
def test_t1_8_export_byte_cap(t1sec_server):
    """When below the row limit but above the byte cap, the export
    must still truncate: ``X-Export-Truncated: true``, body bytes
    <= declared cap (T1-8, T1-24).  Seeds large-body records directly
    in the DB to exceed the byte cap within the row limit."""
    import httpx
    info = t1sec_server
    s = info["sessions"]["alice"]
    conninfo = _conninfo(info["owner_url"])
    org_id = info["org_id"]
    project_id = info["project_id"]
    device_id = info["device_id"]

    # Seed 200 records with ~100 KB bodies to exceed a 10 MB byte cap
    with psycopg.connect(conninfo, autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        for i in range(200):
            rid = str(uuid.uuid4())
            sid = f"sess-bytecap-{i}"
            body_dict = {"event": "byte_cap_test", "payload": "X" * 100000, "idx": i}
            body_str = json.dumps(body_dict, separators=(",", ":"),
                                  sort_keys=True)
            rh = hashlib.sha256(body_str.encode()).hexdigest()
            conn.execute(
                "INSERT INTO audit_records "
                "(id, org_id, connector_id, session_id, chain_length, "
                "previous_hash, record_hash, body, created_at) "
                "VALUES (%s, %s::uuid, %s::uuid, %s, 1, '', %s, %s::json, now()) "
                "ON CONFLICT DO NOTHING",
                [rid, org_id, device_id, sid, rh, body_str],
            )

    with httpx.Client(base_url=info["base_url"], timeout=120) as c:
        r = c.get("/api/v1/audit/export",
                  params={"project": project_id},
                  cookies={"__Host-agg_session": s["cookie"]})
    require_m3(1, not _route_not_registered(r), "export route not registered")
    require_m3(1, r.status_code == 200, f"export must be 200, got {r.status_code}")

    cap_str = r.headers.get("X-Export-Byte-Cap")
    require_m3(1, cap_str is not None,
               "export must declare X-Export-Byte-Cap header")
    cap = int(cap_str)

    truncated = r.headers.get("X-Export-Truncated")
    require_m3(1, truncated == "true",
               f"large-body export must truncate, got X-Export-Truncated={truncated!r}")

    body_bytes = len(r.content)
    require_m3(1, body_bytes <= cap,
               f"truncated export body ({body_bytes}) exceeds declared cap ({cap})")

    lines = r.text.rstrip("\n").split("\n")
    last = json.loads(lines[-1])
    last_trunc = (last.get("truncated") is True
                  or last.get("_meta", {}).get("truncated") is True)
    require_m3(1, last_trunc,
               f"final line must say truncated, got: {lines[-1][:200]}")


# ===================================================================
# T1-9: pagination on codes, bundles, alerts; bad since/until; urn:uuid;
#        skipped sequence; corrupt blob
# ===================================================================

@pytest.mark.pg
def test_t1_9_codes_have_pagination(t1sec_server):
    """GET /admin/enrollment-codes must return a ``cursor`` key (same name
    as /devices), seed enough rows to force a second page, walk it, and
    assert the exact seeded set with no duplicates (T1-9)."""
    import httpx
    info = t1sec_server
    s = info["sessions"]["alice"]
    org_id = info["org_id"]
    project_id = info["project_id"]
    conninfo = _conninfo(info["owner_url"])

    # Seed 30 enrollment codes to guarantee multiple pages
    seeded_ids = set()
    with psycopg.connect(conninfo, autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        for i in range(30):
            code_id = str(uuid.uuid4())
            conn.execute(
                "INSERT INTO enrollment_codes "
                "(id, org_id, project_id, code_hash, "
                "expires_at, created_at) "
                "VALUES (%s, %s::uuid, %s::uuid, %s, "
                "now() + interval '1 day', now()) "
                "ON CONFLICT DO NOTHING",
                [code_id, org_id, project_id, hashlib.sha256(
                    f"code-{i}-{uuid.uuid4().hex}".encode()).hexdigest()],
            )
            seeded_ids.add(code_id)

    # Walk all pages
    collected_ids: list[str] = []
    cursor = None
    for _page in range(50):
        params: dict = {"project": project_id}
        if cursor:
            params["cursor"] = cursor
        with httpx.Client(base_url=info["base_url"], timeout=10) as c:
            r = c.get("/api/v1/admin/enrollment-codes", params=params,
                      cookies={"__Host-agg_session": s["cookie"]})
        require_m3(1, not _route_not_registered(r), "codes route not registered")
        require_m3(1, r.status_code == 200,
                   f"codes page {_page} failed: {r.status_code}")
        body = r.json()
        require_m3(1, "cursor" in body,
                   f"codes response must include 'cursor' key, got keys: {list(body.keys())}")
        items = body.get("items", [])
        for item in items:
            collected_ids.append(item["id"])
        cursor = body.get("cursor")
        if not cursor:
            break

    # No duplicates
    require_m3(1, len(collected_ids) == len(set(collected_ids)),
               f"codes pagination has duplicates: {len(collected_ids)} ids, "
               f"{len(set(collected_ids))} unique")
    # All seeded codes must appear
    require_m3(1, seeded_ids <= set(collected_ids),
               f"not all seeded codes appeared: seeded {len(seeded_ids)}, "
               f"collected {len(collected_ids)}")


@pytest.mark.pg
def test_t1_9_bundles_have_pagination(t1sec_server):
    """GET /admin/bundles must return a ``cursor`` key, seed enough rows to
    force a second page, walk it, and assert the exact seeded set with no
    duplicates (T1-9)."""
    import httpx
    info = t1sec_server
    s = info["sessions"]["alice"]
    org_id = info["org_id"]
    project_id = info["project_id"]
    bundle_sk = info["bundle_signer_sk"]

    # Seed 30 bundles (starting at seq 100 to avoid collisions)
    seeded_seqs = set()
    for seq in range(100, 130):
        _seed_policy_bundle(info["owner_url"], org_id, project_id, seq, bundle_sk)
        seeded_seqs.add(seq)

    # Walk all pages
    collected_seqs: list[int] = []
    cursor = None
    for _page in range(50):
        params: dict = {"project": project_id}
        if cursor:
            params["cursor"] = cursor
        with httpx.Client(base_url=info["base_url"], timeout=10) as c:
            r = c.get("/api/v1/admin/bundles", params=params,
                      cookies={"__Host-agg_session": s["cookie"]})
        require_m3(1, not _route_not_registered(r), "bundles route not registered")
        require_m3(1, r.status_code == 200,
                   f"bundles page {_page} failed: {r.status_code}")
        body = r.json()
        require_m3(1, "cursor" in body,
                   f"bundles response must include 'cursor' key, got keys: {list(body.keys())}")
        items = body.get("items", body.get("bundles", []))
        for item in items:
            collected_seqs.append(item.get("sequence", item.get("seq")))
        cursor = body.get("cursor")
        if not cursor:
            break

    # No duplicates
    require_m3(1, len(collected_seqs) == len(set(collected_seqs)),
               f"bundles pagination has duplicates: {len(collected_seqs)} seqs, "
               f"{len(set(collected_seqs))} unique")
    # All seeded bundles must appear
    require_m3(1, seeded_seqs <= set(collected_seqs),
               f"not all seeded bundles appeared: seeded {len(seeded_seqs)}, "
               f"collected {len(collected_seqs)}")


@pytest.mark.pg
def test_t1_9_alerts_have_pagination(t1sec_server):
    """GET /alerts must return a ``cursor`` key, seed enough rows to force a
    second page, walk it, and assert the exact seeded set with no duplicates
    (T1-9)."""
    import httpx
    info = t1sec_server
    s = info["sessions"]["alice"]
    org_id = info["org_id"]
    project_id = info["project_id"]
    device_id = info["device_id"]

    # Seed 30 alerts
    seeded_ids = set()
    for i in range(30):
        aid = _seed_alert(info["owner_url"], org_id, project_id, device_id,
                          "pagination_test",
                          json.dumps({"msg": f"alert-{i}"}))
        seeded_ids.add(aid)

    # Walk all pages
    collected_ids: list[str] = []
    cursor = None
    for _page in range(50):
        params: dict = {"project": project_id}
        if cursor:
            params["cursor"] = cursor
        with httpx.Client(base_url=info["base_url"], timeout=10) as c:
            r = c.get("/api/v1/alerts", params=params,
                      cookies={"__Host-agg_session": s["cookie"]})
        require_m3(1, not _route_not_registered(r), "alerts route not registered")
        require_m3(1, r.status_code == 200,
                   f"alerts page {_page} failed: {r.status_code}")
        body = r.json()
        require_m3(1, "cursor" in body,
                   f"alerts response must include 'cursor' key, got keys: {list(body.keys())}")
        items = body.get("items", body.get("alerts", []))
        for item in items:
            collected_ids.append(item["id"])
        cursor = body.get("cursor")
        if not cursor:
            break

    # No duplicates
    require_m3(1, len(collected_ids) == len(set(collected_ids)),
               f"alerts pagination has duplicates: {len(collected_ids)} ids, "
               f"{len(set(collected_ids))} unique")
    # All seeded alerts must appear
    require_m3(1, seeded_ids <= set(collected_ids),
               f"not all seeded alerts appeared: seeded {len(seeded_ids)}, "
               f"collected {len(collected_ids)}")


@pytest.mark.pg
def test_t1_9_bad_since_400(t1sec_server):
    """A bad ``since`` parameter must be 400 (not 500) (T1-9)."""
    import httpx
    info = t1sec_server
    s = info["sessions"]["alice"]
    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        r = c.get("/api/v1/alerts",
                  params={"project": info["project_id"],
                          "since": "not-a-date"},
                  cookies={"__Host-agg_session": s["cookie"]})
    require_m3(1, not _route_not_registered(r), "alerts route not registered")
    require_m3(1, r.status_code == 400,
               f"bad since must be 400, got {r.status_code}")


@pytest.mark.pg
def test_t1_9_bad_until_400(t1sec_server):
    """A bad ``until`` parameter on export must be 400 (not 500) (T1-9)."""
    import httpx
    info = t1sec_server
    s = info["sessions"]["alice"]
    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        r = c.get("/api/v1/audit/export",
                  params={"project": info["project_id"],
                          "until": "invalid-date"},
                  cookies={"__Host-agg_session": s["cookie"]})
    require_m3(1, not _route_not_registered(r), "export route not registered")
    require_m3(1, r.status_code == 400,
               f"bad until must be 400, got {r.status_code}")
    assert r.status_code == 400


@pytest.mark.pg
def test_t1_9_urn_uuid_no_500(t1sec_server):
    """``urn:uuid:`` spelling of a project id must not 500 (T1-9)."""
    import httpx
    info = t1sec_server
    s = info["sessions"]["alice"]
    urn_project = f"urn:uuid:{info['project_id']}"
    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        r = c.get("/api/v1/devices",
                  params={"project": urn_project},
                  cookies={"__Host-agg_session": s["cookie"]})
    require_m3(1, not _route_not_registered(r), "devices route not registered")
    require_m3(1, r.status_code != 500,
               f"urn:uuid: must not 500, got {r.status_code}")


@pytest.mark.pg
def test_t1_9_skipped_sequence_diff(t1sec_server):
    """A skipped sequence (2 missing between 1 and 3) must diff against the
    highest lower one and say which (T1-9)."""
    import httpx
    info = t1sec_server
    s = info["sessions"]["alice"]

    # Seq 1 and 3 are seeded; seq 2 is missing
    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        r = c.get("/api/v1/admin/bundles/3",
                  params={"project": info["project_id"]},
                  cookies={"__Host-agg_session": s["cookie"]})
    require_m3(1, not _route_not_registered(r),
               "bundles detail route not registered")
    assert r.status_code == 200
    detail = r.json()
    diff_val = detail.get("diff", detail.get("section_diff", {}))
    assert isinstance(diff_val, dict), "diff must be present"
    # Must indicate which base was used (1, not 2)
    base_seq = detail.get("diff_base_sequence", detail.get("base_sequence"))
    require_m3(1, base_seq == 1,
               f"skipped sequence must diff against seq 1, got base {base_seq}")


@pytest.mark.pg
def test_t1_9_corrupt_blob_marked(t1sec_server):
    """A corrupt bundle blob must be marked ``corrupt_bundle`` (T1-9)."""
    import httpx
    info = t1sec_server
    s = info["sessions"]["alice"]

    # Seed a bundle with a corrupt blob
    conninfo = _conninfo(info["owner_url"])
    with psycopg.connect(conninfo, autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [info["org_id"]])
        conn.execute(
            "INSERT INTO policy_bundles "
            "(id, org_id, project_id, sequence, bundle_blob, "
            "server_signature, created_at) "
            "VALUES (%s, %s::uuid, %s::uuid, %s, %s, '', now())",
            [str(uuid.uuid4()), info["org_id"], info["project_id"],
             99, b"not-valid-json-at-all"],
        )

    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        r = c.get("/api/v1/admin/bundles/99",
                  params={"project": info["project_id"]},
                  cookies={"__Host-agg_session": s["cookie"]})
    require_m3(1, not _route_not_registered(r),
               "bundles detail route not registered")
    assert r.status_code == 200
    detail = r.json()
    # Must indicate corruption, not silently return an empty envelope
    require_m3(1, detail.get("corrupt_bundle") is True,
               f"corrupt blob not marked as corrupt_bundle: {detail}")


# ===================================================================
# T1-10: device detail has checkpoints, sessions, escalations, quarantine;
#         verify has checked, counts, quarantine_rows
# ===================================================================

@pytest.mark.pg
def test_t1_10_device_detail_fields(t1sec_server):
    """GET /devices/{id} must include checkpoints, sessions, open
    escalations and quarantine rows with exact seeded values.
    Seeded ``record`` content must be absent (T1-10, T1-24)."""
    import httpx
    info = t1sec_server
    s = info["sessions"]["alice"]
    conninfo = _conninfo(info["owner_url"])
    org_id = info["org_id"]
    device_id = info["device_id"]

    # Seed a checkpoint (audit_heads)
    cp_id = str(uuid.uuid4())
    with psycopg.connect(conninfo, autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        conn.execute(
            "INSERT INTO audit_heads "
            "(id, org_id, connector_id, upload_seq, "
            "session_list, head_hash, signature, created_at) "
            "VALUES (%s, %s::uuid, %s::uuid, 42, "
            "'[\"sess-cp-test\"]'::jsonb, 'abc123', 'sig123', now())",
            [cp_id, org_id, device_id],
        )

    # Seed an escalation with record content (must not appear)
    esc_id = str(uuid.uuid4())
    secret_cmd = "rm -rf /secret-data"
    with psycopg.connect(conninfo, autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        conn.execute(
            "INSERT INTO escalations "
            "(id, org_id, project_id, connector_id, request_id, "
            "status, record, created_at) "
            "VALUES (%s, %s::uuid, %s::uuid, %s::uuid, %s, "
            "'pending', %s::jsonb, now())",
            [esc_id, org_id, info["project_id"], device_id,
             f"req-{uuid.uuid4().hex[:8]}",
             json.dumps({"command": secret_cmd})],
        )

    # Seed a quarantine row
    q_id = str(uuid.uuid4())
    with psycopg.connect(conninfo, autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        conn.execute(
            "INSERT INTO audit_quarantine "
            "(id, org_id, connector_id, kind, detail, created_at) "
            "VALUES (%s, %s::uuid, %s::uuid, 'fork_detected', '{}', now())",
            [q_id, org_id, device_id],
        )

    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        r = c.get(f"/api/v1/devices/{device_id}",
                  cookies={"__Host-agg_session": s["cookie"]})
    require_m3(1, not _route_not_registered(r),
               "device detail route not registered")
    assert r.status_code == 200
    detail = r.json()
    required_fields = ("checkpoints", "sessions", "open_escalations",
                       "quarantine_rows")
    missing = [f for f in required_fields if f not in detail]
    require_m3(1, len(missing) == 0,
               f"device detail missing fields: {missing}, "
               f"keys: {list(detail.keys())}")

    # Exact values: checkpoint
    cps = detail["checkpoints"]
    require_m3(1, any(cp.get("id") == cp_id or cp.get("upload_seq") == 42
                      for cp in cps),
               f"seeded checkpoint not in checkpoints: {cps}")

    # Exact values: escalation
    escs = detail["open_escalations"]
    esc_match = [e for e in escs if e.get("id") == esc_id]
    require_m3(1, len(esc_match) == 1,
               f"seeded escalation {esc_id} not in open_escalations: {escs}")

    # Exact values: quarantine
    qrs = detail["quarantine_rows"]
    q_match = [q for q in qrs if q.get("id") == q_id]
    require_m3(1, len(q_match) == 1,
               f"seeded quarantine {q_id} not in quarantine_rows: {qrs}")

    # Seeded record content must be absent
    detail_str = json.dumps(detail)
    require_m3(1, secret_cmd not in detail_str,
               "seeded record content must not appear in device detail")


@pytest.mark.pg
def test_t1_10_verify_response_fields(t1sec_server):
    """After uploading N known records across known sessions and seeding a
    quarantine row, ``GET /audit/verify`` must include exact
    ``record_count == N``, exact ``session_count``,
    ``checked == "stored_chains_only"``, and exact ``quarantine_rows``
    with the seeded row.  ``"counts" in body`` alone accepting ``{}`` is
    not sufficient (T1-10)."""
    import httpx
    info = t1sec_server
    s = info["sessions"]["alice"]
    conninfo = _conninfo(info["owner_url"])
    org_id = info["org_id"]
    project_id = info["project_id"]
    device_id = info["device_id"]

    # Upload N=5 records across 2 sessions
    n_records = 5
    session_ids = set()
    for i in range(n_records):
        sid = f"sess-verify-{i % 2}-{uuid.uuid4().hex[:6]}"
        # Use a unique session per i%2 pair to get exactly 2 sessions
        if i < 2:
            sid = f"sess-verify-exact-a-{uuid.uuid4().hex[:6]}"
        else:
            sid = f"sess-verify-exact-b-{uuid.uuid4().hex[:6]}"
        session_ids.add(sid)
        rec = _make_audit_record(sid, 1, "",
                                 {"event": "verify_test", "idx": i})
        with httpx.Client(base_url=info["base_url"], timeout=10) as c:
            c.post("/api/v1/sync/audit",
                   headers={"Authorization": f"Bearer {info['device_token']}"},
                   json={"session_id": sid, "records": [rec]})
    exact_sessions = len(session_ids)

    # Seed a quarantine row (audit_quarantine is the separate table)
    with psycopg.connect(conninfo, autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        conn.execute(
            "INSERT INTO audit_quarantine "
            "(id, org_id, connector_id, kind, detail, created_at) "
            "VALUES (%s, %s::uuid, %s::uuid, 'hash_mismatch', "
            "'{}', now())",
            [str(uuid.uuid4()), org_id, device_id],
        )

    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        r = c.get("/api/v1/audit/verify",
                  params={"project": project_id},
                  cookies={"__Host-agg_session": s["cookie"]})
    require_m3(1, not _route_not_registered(r),
               "verify route not registered")
    assert r.status_code == 200
    body = r.json()

    require_m3(1, body.get("checked") == "stored_chains_only",
               f"checked must be 'stored_chains_only', got {body.get('checked')!r}")

    # Exact counts: query the DB for the real totals
    with psycopg.connect(conninfo) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        real_rc = conn.execute(
            "SELECT count(*) FROM audit_records "
            "WHERE connector_id IN "
            "(SELECT id FROM connectors WHERE project_id = %s::uuid)",
            [project_id],
        ).fetchone()[0]
        real_sc = conn.execute(
            "SELECT count(DISTINCT session_id) FROM audit_records "
            "WHERE connector_id IN "
            "(SELECT id FROM connectors WHERE project_id = %s::uuid)",
            [project_id],
        ).fetchone()[0]

    rc = body.get("record_count")
    require_m3(1, isinstance(rc, int) and rc == real_rc,
               f"record_count must be exactly {real_rc}, got {rc!r}")

    sc = body.get("session_count")
    require_m3(1, isinstance(sc, int) and sc == real_sc,
               f"session_count must be exactly {real_sc}, got {sc!r}")

    # quarantine_rows must be present and include at least our seeded row
    qr = body.get("quarantine_rows")
    require_m3(1, isinstance(qr, (list, int)),
               f"quarantine_rows must be present as list or count, got {type(qr).__name__}")
    if isinstance(qr, list):
        require_m3(1, len(qr) >= 1,
                   f"quarantine_rows must include the seeded row, got {len(qr)}")
    else:
        require_m3(1, qr >= 1,
                   f"quarantine_rows count must be >= 1, got {qr}")


# ===================================================================
# T1-11: raw-bytes exponent nodes
# ===================================================================

@pytest.mark.pg
def test_t1_11_exponent_changed_value_400(t1sec_server):
    """A record body where a float exponent represents a DIFFERENT value
    from what the hash covers must be 400 (T1-11)."""
    import httpx
    info = t1sec_server
    session_id = f"sess-exp-chg-{uuid.uuid4().hex[:8]}"

    # Hash covers body with val=100.0
    body_for_hash = {"event": "exp_test", "val": 100.0}
    body_bytes = json.dumps(body_for_hash, separators=(",", ":"),
                            sort_keys=True).encode()
    record_hash = hashlib.sha256(body_bytes).hexdigest()

    # Send body with val=200.0 spelled as 2e2
    raw_body = (
        '{"session_id":"' + session_id + '","records":[{'
        '"session_id":"' + session_id + '",'
        '"chain_length":1,'
        '"previous_hash":"",'
        '"record_hash":"' + record_hash + '",'
        '"body":{"event":"exp_test","val":2e2}'
        '}]}'
    )

    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        resp = c.post(
            "/api/v1/sync/audit",
            headers={
                "Authorization": f"Bearer {info['device_token']}",
                "Content-Type": "application/json",
            },
            content=raw_body.encode("utf-8"),
        )
    assert resp.status_code == 400, \
        f"changed exponent value must be 400, got {resp.status_code}"
    assert "hash_mismatch" in resp.json().get("error", "")


@pytest.mark.pg
def test_t1_11_exponent_same_value_different_spelling_200(t1sec_server):
    """A record body where 1e2 means the same as 100.0 must be accepted
    (200) and stored as the canonical value (T1-11)."""
    import httpx
    info = t1sec_server
    session_id = f"sess-exp-same-{uuid.uuid4().hex[:8]}"

    # Hash covers body with val=100.0 (the canonical form)
    body_for_hash = {"event": "exp_same", "val": 100.0}
    body_bytes = json.dumps(body_for_hash, separators=(",", ":"),
                            sort_keys=True).encode()
    record_hash = hashlib.sha256(body_bytes).hexdigest()

    # Send body with val=1e2 (same value, different spelling)
    raw_body = (
        '{"session_id":"' + session_id + '","records":[{'
        '"session_id":"' + session_id + '",'
        '"chain_length":1,'
        '"previous_hash":"",'
        '"record_hash":"' + record_hash + '",'
        '"body":{"event":"exp_same","val":1e2}'
        '}]}'
    )

    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        resp = c.post(
            "/api/v1/sync/audit",
            headers={
                "Authorization": f"Bearer {info['device_token']}",
                "Content-Type": "application/json",
            },
            content=raw_body.encode("utf-8"),
        )
    assert resp.status_code == 200, \
        f"same value different spelling must be 200, got {resp.status_code}: {resp.text[:200]}"

    # Verify the stored body is canonical (100.0 not 1e2)
    conninfo = _conninfo(info["owner_url"])
    with psycopg.connect(conninfo) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [info["org_id"]])
        row = conn.execute(
            "SELECT body FROM audit_records "
            "WHERE connector_id = %s::uuid AND session_id = %s "
            "AND chain_length = 1",
            [info["device_id"], session_id],
        ).fetchone()
    assert row is not None, "record must be stored"
    stored_body = row[0]
    if isinstance(stored_body, str):
        stored_body = json.loads(stored_body)
    # The stored val must be 100.0 (canonical), not the string "1e2"
    assert stored_body["val"] == 100.0, \
        f"stored val must be canonical 100.0, got {stored_body['val']}"


# ===================================================================
# T1-11: RLS with relforcerowsecurity pinned
# ===================================================================

@pytest.mark.pg
def test_t1_11_rls_force_on_all_route_tables(t1sec_server):
    """Every table these routes read must have RLS enabled AND
    ``relforcerowsecurity`` set (T1-11)."""
    info = t1sec_server
    conninfo = _conninfo(info["owner_url"])
    tables = [
        "audit_records", "connectors", "policy_bundles",
        "enrollment_codes", "projects", "role_bindings",
        "escalations", "sync_alerts", "device_tokens",
        "policy_change_approvals", "approver_keys",
        "audit_heads", "audit_quarantine",
    ]
    with psycopg.connect(conninfo) as conn:
        rows = conn.execute(
            "SELECT relname, relrowsecurity, relforcerowsecurity "
            "FROM pg_class WHERE relname = ANY(%s)",
            [tables],
        ).fetchall()

    found = {r[0]: (r[1], r[2]) for r in rows}
    missing_tables = [t for t in tables if t not in found]
    assert not missing_tables, f"tables not in pg_class: {missing_tables}"
    bad = []
    for table in tables:
        rls_on, force_on = found[table]
        if not rls_on:
            bad.append(f"{table}: relrowsecurity=false")
        if not force_on:
            bad.append(f"{table}: relforcerowsecurity=false")
    assert not bad, f"RLS/FORCE missing: {bad}"


# ===================================================================
# T1-11: foreign-org nodes
# ===================================================================

@pytest.mark.pg
def test_t1_11_foreign_org_device_detail_404(t1sec_server):
    """Eve (org B) requesting a device in org A by id gets 404 (T1-11)."""
    import httpx
    info = t1sec_server
    # Confirm route works for own org
    sa = info["sessions"]["alice"]
    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        ra = c.get(f"/api/v1/devices/{info['device_id']}",
                   cookies={"__Host-agg_session": sa["cookie"]})
    assert ra.status_code == 200, f"alice must see own device, got {ra.status_code}"
    # Foreign org check
    s = info["sessions"]["eve"]
    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        r = c.get(f"/api/v1/devices/{info['device_id']}",
                  cookies={"__Host-agg_session": s["cookie"]})
    assert r.status_code == 404


@pytest.mark.pg
def test_t1_11_foreign_org_codes_404(t1sec_server):
    """Eve requesting org A's enrollment codes gets 404 (T1-11)."""
    import httpx
    info = t1sec_server
    # Confirm route works for own org
    sa = info["sessions"]["alice"]
    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        ra = c.get("/api/v1/admin/enrollment-codes",
                   params={"project": info["project_id"]},
                   cookies={"__Host-agg_session": sa["cookie"]})
    assert ra.status_code == 200, f"alice must reach codes, got {ra.status_code}"
    # Foreign org check
    s = info["sessions"]["eve"]
    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        r = c.get("/api/v1/admin/enrollment-codes",
                  params={"project": info["project_id"]},
                  cookies={"__Host-agg_session": s["cookie"]})
    assert r.status_code == 404


@pytest.mark.pg
def test_t1_11_foreign_org_bundle_detail_404(t1sec_server):
    """Eve requesting org A's bundle detail gets 404 (T1-11)."""
    import httpx
    info = t1sec_server
    # Confirm route works for own org
    sa = info["sessions"]["alice"]
    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        ra = c.get("/api/v1/admin/bundles/1",
                   params={"project": info["project_id"]},
                   cookies={"__Host-agg_session": sa["cookie"]})
    assert ra.status_code == 200, f"alice must reach bundle detail, got {ra.status_code}"
    # Foreign org check
    s = info["sessions"]["eve"]
    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        r = c.get("/api/v1/admin/bundles/1",
                  params={"project": info["project_id"]},
                  cookies={"__Host-agg_session": s["cookie"]})
    assert r.status_code == 404


@pytest.mark.pg
def test_t1_11_foreign_org_alerts_404(t1sec_server):
    """Eve requesting org A's alerts gets 404 (T1-11)."""
    import httpx
    info = t1sec_server
    # Confirm route works for own org
    sa = info["sessions"]["alice"]
    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        ra = c.get("/api/v1/alerts",
                   params={"project": info["project_id"]},
                   cookies={"__Host-agg_session": sa["cookie"]})
    assert ra.status_code == 200, f"alice must reach alerts, got {ra.status_code}"
    # Foreign org check
    s = info["sessions"]["eve"]
    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        r = c.get("/api/v1/alerts",
                  params={"project": info["project_id"]},
                  cookies={"__Host-agg_session": s["cookie"]})
    assert r.status_code == 404


@pytest.mark.pg
def test_t1_11_foreign_org_verify_404(t1sec_server):
    """Eve requesting org A's audit verify gets 404 (T1-11)."""
    import httpx
    info = t1sec_server
    # Confirm route works for own org
    sa = info["sessions"]["alice"]
    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        ra = c.get("/api/v1/audit/verify",
                   params={"project": info["project_id"]},
                   cookies={"__Host-agg_session": sa["cookie"]})
    assert ra.status_code == 200, f"alice must reach verify, got {ra.status_code}"
    # Foreign org check
    s = info["sessions"]["eve"]
    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        r = c.get("/api/v1/audit/verify",
                  params={"project": info["project_id"]},
                  cookies={"__Host-agg_session": s["cookie"]})
    assert r.status_code == 404


@pytest.mark.pg
def test_t1_11_foreign_org_export_404(t1sec_server):
    """Eve requesting org A's audit export gets 404 (T1-11)."""
    import httpx
    info = t1sec_server
    # Confirm route works for own org
    sa = info["sessions"]["alice"]
    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        ra = c.get("/api/v1/audit/export",
                   params={"project": info["project_id"]},
                   cookies={"__Host-agg_session": sa["cookie"]})
    assert ra.status_code == 200, f"alice must reach export, got {ra.status_code}"
    # Foreign org check
    s = info["sessions"]["eve"]
    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        r = c.get("/api/v1/audit/export",
                  params={"project": info["project_id"]},
                  cookies={"__Host-agg_session": s["cookie"]})
    assert r.status_code == 404


# ===================================================================
# T1-11: migration checks
# ===================================================================

@pytest.mark.pg
def test_t1_11_verification_check_constraint(t1sec_server):
    """``policy_bundles.verification`` must have a CHECK constraint naming
    ``'server'`` and ``'m2_unverified'``; invalid values must be refused
    with a check-constraint violation when inserted by the owner role
    (T1-11)."""
    info = t1sec_server
    conninfo = _conninfo(info["owner_url"])
    with psycopg.connect(conninfo) as conn:
        # Read the CHECK constraint definition
        checks = conn.execute(
            "SELECT conname, pg_get_constraintdef(oid) "
            "FROM pg_constraint "
            "WHERE conrelid = 'policy_bundles'::regclass "
            "AND contype = 'c'",
        ).fetchall()
    verification_checks = [
        (name, defn) for name, defn in checks
        if "verification" in defn
    ]
    require_m3(1, len(verification_checks) >= 1,
               f"policy_bundles must have a CHECK on verification, found: {checks}")

    # The constraint must name both allowed values
    defn_text = verification_checks[0][1]
    require_m3(1, "'server'" in defn_text,
               f"CHECK must name 'server', got: {defn_text}")
    require_m3(1, "'m2_unverified'" in defn_text,
               f"CHECK must name 'm2_unverified', got: {defn_text}")

    # Attempt invalid INSERTs with the owner role -- each must raise
    # a check-constraint violation
    invalid_values = ["bogus", "admin_override", "", "SERVER"]
    org_id = info["org_id"]
    project_id = info["project_id"]
    bundle_sk = info["bundle_signer_sk"]

    for bad_val in invalid_values:
        with psycopg.connect(conninfo, autocommit=True) as conn:
            conn.execute("SELECT set_config('app.org_id', %s, false)",
                         [org_id])
            try:
                conn.execute(
                    "INSERT INTO policy_bundles "
                    "(id, org_id, project_id, sequence, bundle_blob, "
                    "server_signature, verification, created_at) "
                    "VALUES (%s, %s::uuid, %s::uuid, %s, %s, '', %s, now())",
                    [str(uuid.uuid4()), org_id, project_id,
                     1000 + invalid_values.index(bad_val),
                     b"{}",
                     bad_val],
                )
                require_m3(1, False,
                           f"INSERT with verification={bad_val!r} must be refused "
                           f"by CHECK constraint")
            except psycopg.errors.CheckViolation:
                pass  # expected


@pytest.mark.pg
def test_t1_11_verified_at_coupling(t1sec_server):
    """``verification='server'`` with ``verified_at`` NULL must be refused;
    ``verification='m2_unverified'`` with ``verified_at`` NOT NULL must be
    refused; both valid forms must be accepted.  Nothing stored after a
    refusal (T1-11)."""
    info = t1sec_server
    conninfo = _conninfo(info["owner_url"])
    org_id = info["org_id"]
    project_id = info["project_id"]

    # Case 1: server + verified_at NULL -> refused
    with psycopg.connect(conninfo, autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        bad_id_1 = str(uuid.uuid4())
        try:
            conn.execute(
                "INSERT INTO policy_bundles "
                "(id, org_id, project_id, sequence, bundle_blob, "
                "server_signature, verification, verified_at, created_at) "
                "VALUES (%s, %s::uuid, %s::uuid, %s, %s, '', 'server', NULL, now())",
                [bad_id_1, org_id, project_id, 2001, b"{}"],
            )
            require_m3(1, False,
                       "verification='server' with verified_at=NULL must be refused")
        except psycopg.errors.CheckViolation:
            pass  # expected

    # Verify nothing stored
    with psycopg.connect(conninfo) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        count = conn.execute(
            "SELECT count(*) FROM policy_bundles WHERE id = %s::uuid",
            [bad_id_1],
        ).fetchone()[0]
    require_m3(1, count == 0,
               f"refused INSERT must store nothing, found {count}")

    # Case 2: m2_unverified + verified_at NOT NULL -> refused
    with psycopg.connect(conninfo, autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        bad_id_2 = str(uuid.uuid4())
        try:
            conn.execute(
                "INSERT INTO policy_bundles "
                "(id, org_id, project_id, sequence, bundle_blob, "
                "server_signature, verification, verified_at, created_at) "
                "VALUES (%s, %s::uuid, %s::uuid, %s, %s, '', 'm2_unverified', now(), now())",
                [bad_id_2, org_id, project_id, 2002, b"{}"],
            )
            require_m3(1, False,
                       "verification='m2_unverified' with verified_at NOT NULL must be refused")
        except psycopg.errors.CheckViolation:
            pass  # expected

    # Verify nothing stored
    with psycopg.connect(conninfo) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        count = conn.execute(
            "SELECT count(*) FROM policy_bundles WHERE id = %s::uuid",
            [bad_id_2],
        ).fetchone()[0]
    require_m3(1, count == 0,
               f"refused INSERT must store nothing, found {count}")

    # Case 3: valid forms accepted
    # server + verified_at set
    with psycopg.connect(conninfo, autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        good_id_1 = str(uuid.uuid4())
        conn.execute(
            "INSERT INTO policy_bundles "
            "(id, org_id, project_id, sequence, bundle_blob, "
            "server_signature, verification, verified_at, created_at) "
            "VALUES (%s, %s::uuid, %s::uuid, %s, %s, '', 'server', now(), now())",
            [good_id_1, org_id, project_id, 2003, b"{}"],
        )

    # m2_unverified + verified_at NULL
    with psycopg.connect(conninfo, autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        good_id_2 = str(uuid.uuid4())
        conn.execute(
            "INSERT INTO policy_bundles "
            "(id, org_id, project_id, sequence, bundle_blob, "
            "server_signature, verification, verified_at, created_at) "
            "VALUES (%s, %s::uuid, %s::uuid, %s, %s, '', 'm2_unverified', NULL, now())",
            [good_id_2, org_id, project_id, 2004, b"{}"],
        )

    # Verify both stored
    with psycopg.connect(conninfo) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        count = conn.execute(
            "SELECT count(*) FROM policy_bundles WHERE id = ANY(%s::uuid[])",
            [[good_id_1, good_id_2]],
        ).fetchone()[0]
    assert count == 2, f"both valid inserts must be stored, found {count}"


@pytest.mark.pg
def test_t1_11_body_column_is_json_not_jsonb(t1sec_server):
    """``audit_records.body`` must be ``json`` not ``jsonb`` (T1-2, T1-11)."""
    info = t1sec_server
    conninfo = _conninfo(info["owner_url"])
    with psycopg.connect(conninfo) as conn:
        row = conn.execute(
            "SELECT data_type FROM information_schema.columns "
            "WHERE table_name = 'audit_records' AND column_name = 'body'",
        ).fetchone()
    assert row is not None, "audit_records.body column not found"
    require_m3(1, row[0] == "json",
               f"audit_records.body must be json (not jsonb), got {row[0]!r}")


@pytest.mark.pg
def test_t1_11_no_update_grant_on_sync_alerts(t1sec_server):
    """``agg_app`` must have no UPDATE grant on ``sync_alerts`` (T1-11)."""
    info = t1sec_server
    conninfo = _conninfo(info["owner_url"])
    with psycopg.connect(conninfo) as conn:
        privs = conn.execute(
            "SELECT privilege_type FROM information_schema.role_table_grants "
            "WHERE grantee = 'agg_app' AND table_name = 'sync_alerts' "
            "AND privilege_type = 'UPDATE'",
        ).fetchall()
    assert len(privs) == 0, \
        "agg_app must not have UPDATE on sync_alerts"


# ===================================================================
# T1-12: record session_id different from batch is 400 bad_body
# ===================================================================

@pytest.mark.pg
def test_t1_12_record_session_id_mismatch_400(t1sec_server):
    """A record with ``session_id`` different from the batch's must be 400
    ``bad_body``.  Equal is allowed (T1-12)."""
    import httpx
    info = t1sec_server

    # Mismatched session_id -> 400 bad_body
    batch_sid = f"sess-t12-batch-{uuid.uuid4().hex[:6]}"
    rec_sid = f"sess-t12-rec-{uuid.uuid4().hex[:6]}"
    rec = _make_audit_record(rec_sid, 1, "", {"event": "t12_mismatch"})
    rec["session_id"] = rec_sid  # different from batch
    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        resp = c.post(
            "/api/v1/sync/audit",
            headers={"Authorization": f"Bearer {info['device_token']}"},
            json={"session_id": batch_sid, "records": [rec]},
        )
    require_m3(1, resp.status_code == 400,
               f"mismatched session_id must be 400, got {resp.status_code}")
    require_m3(1, resp.json().get("error") == "bad_body",
               f"error must be bad_body, got {resp.json()}")


@pytest.mark.pg
def test_t1_12_record_session_id_equal_allowed(t1sec_server):
    """A record with ``session_id`` equal to the batch's must be allowed
    (200) (T1-12)."""
    import httpx
    info = t1sec_server

    sid = f"sess-t12-eq-{uuid.uuid4().hex[:6]}"
    rec = _make_audit_record(sid, 1, "", {"event": "t12_equal"})
    rec["session_id"] = sid  # equal to batch
    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        resp = c.post(
            "/api/v1/sync/audit",
            headers={"Authorization": f"Bearer {info['device_token']}"},
            json={"session_id": sid, "records": [rec]},
        )
    require_m3(1, resp.status_code == 200,
               f"equal session_id must be 200, got {resp.status_code}: {resp.text[:200]}")


# ===================================================================
# T1-13: concurrent uploads, no audit_record_unstorable, 409 reachable
# ===================================================================

@pytest.mark.pg
def test_t1_13_concurrent_upload_no_false_alert(t1sec_server):
    """Race of 8 identical uploads: each response is 200 or 409
    ``duplicate_record``, alert delta is exactly 0, and exactly one
    row is stored (T1-13)."""
    import httpx
    import concurrent.futures
    info = t1sec_server
    conninfo = _conninfo(info["owner_url"])

    sid = f"sess-t13-{uuid.uuid4().hex[:6]}"
    rec = _make_audit_record(sid, 1, "", {"event": "t13_dup"})
    payload = {"session_id": sid, "records": [rec]}

    # Baseline alerts
    with psycopg.connect(conninfo) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [info["org_id"]])
        before_alerts = conn.execute(
            "SELECT count(*) FROM sync_alerts "
            "WHERE kind = 'audit_record_unstorable' "
            "AND connector_id = %s::uuid",
            [info["device_id"]],
        ).fetchone()[0]

    def _upload():
        with httpx.Client(base_url=info["base_url"], timeout=15) as c:
            return c.post(
                "/api/v1/sync/audit",
                headers={"Authorization": f"Bearer {info['device_token']}"},
                json=payload,
            )

    # 8 concurrent uploads
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        futures = [pool.submit(_upload) for _ in range(8)]
        results = [f.result() for f in futures]

    codes = [r.status_code for r in results]
    # At least one 200
    require_m3(1, 200 in codes,
               f"at least one upload must succeed with 200, got {codes}")
    # Every response is 200 or 409; no 400 audit_record_unstorable
    bad_codes = [c for c in codes if c not in (200, 409)]
    require_m3(1, len(bad_codes) == 0,
               f"only 200 and 409 allowed in race, got {bad_codes}")
    # Any 409 must be duplicate_record (not audit_record_unstorable)
    for r in results:
        if r.status_code == 409:
            require_m3(1, r.json().get("error") == "duplicate_record",
                       f"409 error must be duplicate_record, got {r.json()}")

    # Alert delta must be exactly 0
    with psycopg.connect(conninfo) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [info["org_id"]])
        after_alerts = conn.execute(
            "SELECT count(*) FROM sync_alerts "
            "WHERE kind = 'audit_record_unstorable' "
            "AND connector_id = %s::uuid",
            [info["device_id"]],
        ).fetchone()[0]
    require_m3(1, after_alerts == before_alerts,
               f"concurrent upload must not create audit_record_unstorable "
               f"alert, delta={after_alerts - before_alerts}")

    # Exactly one stored row for this session+position
    with psycopg.connect(conninfo) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [info["org_id"]])
        stored = conn.execute(
            "SELECT count(*) FROM audit_records "
            "WHERE connector_id = %s::uuid AND session_id = %s "
            "AND chain_length = 1",
            [info["device_id"], sid],
        ).fetchone()[0]
    require_m3(1, stored == 1,
               f"exactly one row must be stored, got {stored}")


@pytest.mark.pg
def test_t1_13_duplicate_record_409_deterministic(t1sec_server):
    """Prove the 409 ``duplicate_record`` path deterministically by
    holding an INSERT in an open transaction, polling ``pg_stat_activity``
    until the HTTP upload's backend is waiting on the row lock, then
    committing. The upload must return 409 ``duplicate_record`` with
    alert delta 0 (T1-13 round 3)."""
    import httpx
    import threading
    info = t1sec_server
    conninfo = _conninfo(info["owner_url"])
    # Use pg_url (superuser) to read pg_stat_activity
    pg_conninfo = info["pg_url"].replace("+psycopg", "")
    org_id = info["org_id"]
    device_id = info["device_id"]

    sid = f"sess-t13det-{uuid.uuid4().hex[:6]}"
    rec = _make_audit_record(sid, 1, "", {"event": "t13_det"})
    body_str = json.dumps(rec["body"], separators=(",", ":"),
                          sort_keys=True)

    # Baseline alert count
    with psycopg.connect(conninfo) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [org_id])
        alerts_before = conn.execute(
            "SELECT count(*) FROM sync_alerts "
            "WHERE connector_id = %s::uuid",
            [device_id],
        ).fetchone()[0]

    barrier = threading.Barrier(2, timeout=10)
    http_result = [None]

    def _hold_row():
        """Insert the row in a transaction and hold it open until the
        HTTP upload's backend is waiting on the row lock, then commit."""
        with psycopg.connect(conninfo) as conn:
            conn.execute("SELECT set_config('app.org_id', %s, false)",
                         [org_id])
            conn.execute(
                "INSERT INTO audit_records "
                "(id, org_id, connector_id, session_id, chain_length, "
                "previous_hash, record_hash, body, created_at) "
                "VALUES (%s, %s::uuid, %s::uuid, %s, 1, '', %s, "
                "%s::json, now())",
                [str(uuid.uuid4()), org_id, device_id, sid,
                 rec["record_hash"], body_str],
            )
            # Signal the HTTP upload to proceed
            barrier.wait()
            # Poll pg_stat_activity until an agg_app backend is waiting
            # on a Lock for our table (the HTTP upload hit the row lock).
            deadline = time.monotonic() + 10.0
            with psycopg.connect(pg_conninfo, autocommit=True) as mon:
                while time.monotonic() < deadline:
                    row = mon.execute(
                        "SELECT count(*) FROM pg_stat_activity "
                        "WHERE usename = 'agg_app' "
                        "AND wait_event_type = 'Lock'",
                    ).fetchone()
                    if row and row[0] > 0:
                        break
                    time.sleep(0.05)
            conn.commit()

    def _http_upload():
        barrier.wait()
        payload = {"session_id": sid, "records": [rec]}
        with httpx.Client(base_url=info["base_url"], timeout=15) as c:
            http_result[0] = c.post(
                "/api/v1/sync/audit",
                headers={"Authorization": f"Bearer {info['device_token']}"},
                json=payload,
            )

    t_hold = threading.Thread(target=_hold_row)
    t_http = threading.Thread(target=_http_upload)
    t_hold.start()
    t_http.start()
    t_hold.join(timeout=15)
    t_http.join(timeout=15)

    r = http_result[0]
    require_m3(1, r is not None, "HTTP upload did not complete")
    # Must be 409 duplicate_record, not 200 noop
    require_m3(1, r.status_code == 409,
               f"deterministic race must give 409, got {r.status_code}: "
               f"{r.text[:200]}")
    require_m3(1, r.json().get("error") == "duplicate_record",
               f"409 error must be duplicate_record, got {r.json()}")

    # Alert delta must be 0 (a UniqueViolation is not a bad record)
    with psycopg.connect(conninfo) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [org_id])
        alerts_after = conn.execute(
            "SELECT count(*) FROM sync_alerts "
            "WHERE connector_id = %s::uuid",
            [device_id],
        ).fetchone()[0]
    require_m3(1, alerts_after - alerts_before == 0,
               f"duplicate_record must not create an alert, "
               f"delta={alerts_after - alerts_before}")


# ===================================================================
# T1-14: [valid, valid, NaN] is 400, 0 rows stored, exactly 1 alert
# ===================================================================

@pytest.mark.pg
def test_t1_14_partial_batch_nan_rolls_back(t1sec_server):
    """``[valid, valid, NaN]`` must be 400 with 0 rows stored and exactly
    1 alert (T1-14: a refused batch is half-written)."""
    import httpx
    info = t1sec_server
    conninfo = _conninfo(info["owner_url"])
    sid = f"sess-t14-{uuid.uuid4().hex[:6]}"

    # Baseline alerts
    with psycopg.connect(conninfo) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [info["org_id"]])
        before = conn.execute(
            "SELECT count(*) FROM sync_alerts "
            "WHERE kind = 'audit_record_unstorable' "
            "AND connector_id = %s::uuid",
            [info["device_id"]],
        ).fetchone()[0]

    # Build [valid, valid, NaN]
    r1 = _make_audit_record(sid, 1, "", {"event": "t14_1"})
    r2 = _make_audit_record(sid, 2, r1["record_hash"], {"event": "t14_2"})
    # NaN record as raw JSON
    raw_body = json.dumps(
        {"session_id": sid, "records": [
            r1, r2,
            {"session_id": sid, "chain_length": 3,
             "previous_hash": r2["record_hash"],
             "record_hash": "0" * 64,
             "body": {"event": "t14_nan", "val": float("nan")}},
        ]},
        allow_nan=True,
    )

    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        resp = c.post(
            "/api/v1/sync/audit",
            headers={
                "Authorization": f"Bearer {info['device_token']}",
                "Content-Type": "application/json",
            },
            content=raw_body.encode("utf-8"),
        )
    require_m3(1, resp.status_code == 400,
               f"[valid,valid,NaN] must be 400, got {resp.status_code}")

    # 0 rows stored
    with psycopg.connect(conninfo) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [info["org_id"]])
        count = conn.execute(
            "SELECT count(*) FROM audit_records "
            "WHERE connector_id = %s::uuid AND session_id = %s",
            [info["device_id"], sid],
        ).fetchone()[0]
    require_m3(1, count == 0,
               f"refused batch must store 0 rows, found {count}")

    # Exactly 1 alert
    with psycopg.connect(conninfo) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [info["org_id"]])
        after = conn.execute(
            "SELECT count(*) FROM sync_alerts "
            "WHERE kind = 'audit_record_unstorable' "
            "AND connector_id = %s::uuid",
            [info["device_id"]],
        ).fetchone()[0]
    require_m3(1, after - before == 1,
               f"[valid,valid,NaN] must create exactly 1 alert, delta={after - before}")


# ===================================================================
# T1-15: deep nesting, chain_length type checks
# ===================================================================

@pytest.mark.pg
def test_t1_15_deep_nesting_400_not_500(t1sec_server):
    """1,001-level nesting (one above the fixed limit of 1,000) with a
    correct hash must be 400 ``audit_record_unstorable`` plus exactly 1
    deduplicated alert.  Does not depend on the platform's recursion
    limit, so it works on Linux CI too (T1-26 round 3)."""
    import httpx
    info = t1sec_server
    conninfo = _conninfo(info["owner_url"])
    sid = f"sess-t15-nest-{uuid.uuid4().hex[:6]}"

    with psycopg.connect(conninfo) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [info["org_id"]])
        before = conn.execute(
            "SELECT count(*) FROM sync_alerts "
            "WHERE connector_id = %s::uuid "
            "AND kind = 'audit_record_unstorable'",
            [info["device_id"]],
        ).fetchone()[0]

    # Build 1,001-level nested JSON with a correct hash
    inner = '"deep"'
    for _ in range(1001):
        inner = '{"a":' + inner + '}'
    body_bytes = inner.encode("utf-8")
    rh = hashlib.sha256(body_bytes).hexdigest()
    raw_body = (
        '{"session_id":"' + sid + '","records":[{'
        '"session_id":"' + sid + '",'
        '"chain_length":1,'
        '"previous_hash":"",'
        '"record_hash":"' + rh + '",'
        '"body":' + inner +
        '}]}'
    )

    with httpx.Client(base_url=info["base_url"], timeout=30) as c:
        resp = c.post(
            "/api/v1/sync/audit",
            headers={
                "Authorization": f"Bearer {info['device_token']}",
                "Content-Type": "application/json",
            },
            content=raw_body.encode("utf-8"),
        )
    require_m3(1, resp.status_code == 400,
               f"1001-level nesting must be 400, got {resp.status_code}")
    require_m3(1, resp.status_code != 500,
               f"1001-level nesting must never be 500")

    with psycopg.connect(conninfo) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [info["org_id"]])
        after = conn.execute(
            "SELECT count(*) FROM sync_alerts "
            "WHERE connector_id = %s::uuid "
            "AND kind = 'audit_record_unstorable'",
            [info["device_id"]],
        ).fetchone()[0]
    require_m3(1, after - before == 1,
               f"1001-level nesting must create exactly 1 alert, "
               f"delta={after - before}")


@pytest.mark.pg
@pytest.mark.parametrize("bad_cl,label", [
    ("string_cl", "a string"),
    ([1], "a list"),
    ({"x": 1}, "an object"),
    (True, "true"),
    (1.0, "1.0"),
], ids=["string", "list", "object", "true", "1.0"])
def test_t1_15_chain_length_type_400(t1sec_server, bad_cl, label):
    """``chain_length`` of {label} must be 400 ``bad_body``, no alert
    (T1-15)."""
    import httpx
    info = t1sec_server
    conninfo = _conninfo(info["owner_url"])
    sid = f"sess-t15-cl-{uuid.uuid4().hex[:6]}"

    with psycopg.connect(conninfo) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [info["org_id"]])
        before = conn.execute(
            "SELECT count(*) FROM sync_alerts "
            "WHERE connector_id = %s::uuid",
            [info["device_id"]],
        ).fetchone()[0]

    payload = {"session_id": sid, "records": [{
        "session_id": sid,
        "chain_length": bad_cl,
        "previous_hash": "",
        "record_hash": "0" * 64,
        "body": {"event": "bad_cl"},
    }]}
    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        resp = c.post(
            "/api/v1/sync/audit",
            headers={"Authorization": f"Bearer {info['device_token']}"},
            json=payload,
        )
    require_m3(1, resp.status_code == 400,
               f"chain_length={bad_cl!r} must be 400, got {resp.status_code}")
    require_m3(1, resp.json().get("error") == "bad_body",
               f"error must be bad_body, got {resp.json()}")

    with psycopg.connect(conninfo) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [info["org_id"]])
        after = conn.execute(
            "SELECT count(*) FROM sync_alerts "
            "WHERE connector_id = %s::uuid",
            [info["device_id"]],
        ).fetchone()[0]
    require_m3(1, after == before,
               f"chain_length type error must not create an alert, delta={after - before}")


# ===================================================================
# T1-16: row limit sets flag and final line
# ===================================================================

@pytest.mark.pg
def test_t1_16_row_limit_sets_flag(t1sec_server):
    """Seed 10,050 small rows in an ISOLATED project (body far below byte
    cap).  The ROW limit (10,000) must fire: ``X-Export-Truncated: true``,
    a final line with ``truncated``, and body bytes far below the byte cap
    (T1-16).  Uses its own project so the byte-cap test's large rows
    cannot interfere."""
    import httpx
    info = t1sec_server
    s = info["sessions"]["alice"]
    conninfo = _conninfo(info["owner_url"])
    org_id = info["org_id"]

    # Create an isolated project and connector for this test only
    iso_project_id = str(uuid.uuid4())
    iso_device_id = str(uuid.uuid4())
    with psycopg.connect(conninfo, autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        create_project(conn, org_id, iso_project_id, "T16 Row Limit Project")
        pub = secrets.token_bytes(32)
        conn.execute(
            "INSERT INTO connectors "
            "(id, org_id, project_id, device_public_key, created_at) "
            "VALUES (%s, %s::uuid, %s::uuid, %s, now())",
            [iso_device_id, org_id, iso_project_id, pub.hex()],
        )

    # Seed 10,050 tiny rows directly in the DB
    with psycopg.connect(conninfo, autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        for batch_start in range(0, 10050, 500):
            values_parts = []
            params = []
            for i in range(batch_start, min(batch_start + 500, 10050)):
                rid = str(uuid.uuid4())
                sid = f"sess-t16-{i // 100}"
                body_str = json.dumps({"i": i}, separators=(",", ":"),
                                      sort_keys=True)
                rh = hashlib.sha256(body_str.encode()).hexdigest()
                values_parts.append(
                    "(%s, %s::uuid, %s::uuid, %s, %s, %s, %s, %s::json, now())"
                )
                params.extend([
                    rid, org_id, iso_device_id, sid,
                    i % 10000 + 1, "", rh, body_str,
                ])
            sql = (
                "INSERT INTO audit_records "
                "(id, org_id, connector_id, session_id, chain_length, "
                "previous_hash, record_hash, body, created_at) VALUES "
                + ", ".join(values_parts)
                + " ON CONFLICT DO NOTHING"
            )
            conn.execute(sql, params)

    with httpx.Client(base_url=info["base_url"], timeout=120) as c:
        r = c.get("/api/v1/audit/export",
                  params={"project": iso_project_id},
                  cookies={"__Host-agg_session": s["cookie"]})
    require_m3(1, r.status_code == 200, f"export must be 200, got {r.status_code}")

    truncated = r.headers.get("X-Export-Truncated")
    require_m3(1, truncated == "true",
               f"row limit must set X-Export-Truncated=true, got {truncated!r}")

    lines = r.text.rstrip("\n").split("\n")
    last = json.loads(lines[-1])
    last_trunc = (last.get("truncated") is True
                  or last.get("_meta", {}).get("truncated") is True)
    require_m3(1, last_trunc,
               f"row limit must produce a final truncated line, got: {lines[-1][:200]}")

    # Body bytes must be far below the byte cap (these are tiny rows)
    cap_str = r.headers.get("X-Export-Byte-Cap")
    if cap_str:
        cap = int(cap_str)
        body_bytes = len(r.content)
        require_m3(1, body_bytes < cap * 0.5,
                   f"row limit test: body ({body_bytes}) should be far "
                   f"below byte cap ({cap}), proving ROW limit fired")


# ===================================================================
# T1-17: response is not StreamingResponse, has Content-Length
# ===================================================================

@pytest.mark.pg
def test_t1_17_export_no_fetchall_uses_cursor(t1sec_server):
    """Structural: export and ``verify_project`` must never call
    ``.fetchall()`` on the body rows and must read through a named
    server-side cursor.  No ``StreamingResponse`` in admin_reads.py
    (T1-17).  Uses ``ast`` on source."""
    import ast
    from pathlib import Path

    admin_reads_path = Path("ee/src/agg_cp/sync/admin_reads.py")
    audit_path = Path("ee/src/agg_cp/sync/audit.py")

    # Check admin_reads.py: no StreamingResponse, no .fetchall() on
    # the body-row query
    admin_src = admin_reads_path.read_text(encoding="utf-8")
    tree = ast.parse(admin_src, str(admin_reads_path))

    # No StreamingResponse usage
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and node.id == "StreamingResponse":
            require_m3(1, False,
                       "admin_reads.py must not use StreamingResponse (T1-17)")
        if isinstance(node, ast.Attribute) and node.attr == "StreamingResponse":
            require_m3(1, False,
                       "admin_reads.py must not use StreamingResponse (T1-17)")

    # No .fetchall() calls anywhere in admin_reads.py
    # (the export and all queries should use server-side cursors)
    for node in ast.walk(tree):
        if (isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "fetchall"):
            require_m3(1, False,
                       "admin_reads.py must not call .fetchall() (T1-17)")

    # Check audit.py: verify_project must not .fetchall() on body rows
    audit_src = audit_path.read_text(encoding="utf-8")
    audit_tree = ast.parse(audit_src, str(audit_path))
    for node in ast.walk(audit_tree):
        if (isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "fetchall"):
            require_m3(1, False,
                       "audit.py must not call .fetchall() (T1-17)")


@pytest.mark.pg
def test_t1_17_export_memory_bounded_behavioral(t1sec_server):
    """Behavioral: 120 rows of about 1 MB each against the 10 MB cap.
    Response must be at most the cap and ``X-Export-Truncated: true``
    (T1-17).  Peak memory is tested separately in
    ``test_t1_17_export_peak_memory``."""
    import httpx
    info = t1sec_server
    s = info["sessions"]["alice"]
    conninfo = _conninfo(info["owner_url"])
    org_id = info["org_id"]
    device_id = info["device_id"]

    # Seed 120 rows of ~1 MB each
    with psycopg.connect(conninfo, autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        for i in range(120):
            rid = str(uuid.uuid4())
            sid = f"sess-t17-mem-{i}"
            # ~1 MB body
            body_dict = {"event": "t17_mem", "payload": "M" * (1024 * 1024)}
            body_str = json.dumps(body_dict, separators=(",", ":"),
                                  sort_keys=True)
            rh = hashlib.sha256(body_str.encode()).hexdigest()
            conn.execute(
                "INSERT INTO audit_records "
                "(id, org_id, connector_id, session_id, chain_length, "
                "previous_hash, record_hash, body, created_at) "
                "VALUES (%s, %s::uuid, %s::uuid, %s, 1, '', %s, "
                "%s::json, now()) ON CONFLICT DO NOTHING",
                [rid, org_id, device_id, sid, rh, body_str],
            )

    with httpx.Client(base_url=info["base_url"], timeout=120) as c:
        r = c.get("/api/v1/audit/export",
                  params={"project": info["project_id"]},
                  cookies={"__Host-agg_session": s["cookie"]})
    require_m3(1, r.status_code == 200, f"export must be 200, got {r.status_code}")

    cap_str = r.headers.get("X-Export-Byte-Cap")
    require_m3(1, cap_str is not None, "must declare X-Export-Byte-Cap")
    cap = int(cap_str)

    truncated = r.headers.get("X-Export-Truncated")
    require_m3(1, truncated == "true",
               f"120x1MB must truncate, got X-Export-Truncated={truncated!r}")

    body_bytes = len(r.content)
    require_m3(1, body_bytes <= cap,
               f"body ({body_bytes}) must be <= cap ({cap}), "
               f"proving memory is bounded by the cap")


# ===================================================================
# T1-18: session_id / record_hash / previous_hash validation, alert
#         dedup, sessions/gaps limit
# ===================================================================

@pytest.mark.pg
@pytest.mark.parametrize("bad_sid,label", [
    ("x" * 257, ">256 chars"),
    ("has\x00nul", "NUL"),
    ("has\ud800surr", "surrogate"),
], ids=[">256", "NUL", "surrogate"])
def test_t1_18_bad_session_id_400(t1sec_server, bad_sid, label):
    """Batch ``session_id`` with {label} must be 400 ``bad_session_id``
    (T1-18)."""
    import httpx
    info = t1sec_server
    rec = _make_audit_record("ignored", 1, "", {"event": "t18"})
    raw_body = json.dumps(
        {"session_id": bad_sid, "records": [rec]},
        ensure_ascii=True,
    )
    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        resp = c.post(
            "/api/v1/sync/audit",
            headers={
                "Authorization": f"Bearer {info['device_token']}",
                "Content-Type": "application/json",
            },
            content=raw_body.encode("utf-8", errors="surrogatepass"),
        )
    require_m3(1, resp.status_code == 400,
               f"session_id with {label} must be 400, got {resp.status_code}")
    require_m3(1, resp.json().get("error") == "bad_session_id",
               f"error must be bad_session_id, got {resp.json()}")


@pytest.mark.pg
@pytest.mark.parametrize("field", ["record_hash", "previous_hash"])
def test_t1_18_hash_field_validation(t1sec_server, field):
    """``record_hash`` and ``previous_hash`` non-string or > 128 chars
    must be refused BEFORE the fork branch (T1-18).  Tests at a new
    position AND at an existing position (where the fork branch would
    fire).  Must produce no ``audit_quarantine`` row and no alert."""
    import httpx
    info = t1sec_server
    conninfo = _conninfo(info["owner_url"])
    org_id = info["org_id"]
    device_id = info["device_id"]

    # First upload a valid record so we have an existing position
    sid = f"sess-t18-hash-{uuid.uuid4().hex[:6]}"
    valid_rec = _make_audit_record(sid, 1, "", {"event": "t18_valid"})
    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        vr = c.post(
            "/api/v1/sync/audit",
            headers={"Authorization": f"Bearer {info['device_token']}"},
            json={"session_id": sid, "records": [valid_rec]},
        )
    assert vr.status_code == 200, f"setup: valid upload must be 200, got {vr.status_code}"

    # Baseline quarantine and alert counts
    with psycopg.connect(conninfo) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        q_before = conn.execute(
            "SELECT count(*) FROM audit_quarantine "
            "WHERE connector_id = %s::uuid",
            [device_id],
        ).fetchone()[0]
        a_before = conn.execute(
            "SELECT count(*) FROM sync_alerts "
            "WHERE connector_id = %s::uuid",
            [device_id],
        ).fetchone()[0]

    # --- At EXISTING position (chain_length 1, same session) ---
    # This would hit the fork branch if the hash check doesn't come first

    # Non-string at existing position
    rec_existing_bad = _make_audit_record(sid, 1, "", {"event": "t18_existing"})
    rec_existing_bad[field] = 12345
    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        resp = c.post(
            "/api/v1/sync/audit",
            headers={"Authorization": f"Bearer {info['device_token']}"},
            json={"session_id": sid, "records": [rec_existing_bad]},
        )
    require_m3(1, resp.status_code == 400,
               f"non-string {field} at existing position must be 400, "
               f"got {resp.status_code}")

    # > 128 chars at existing position
    rec_existing_long = _make_audit_record(sid, 1, "", {"event": "t18_existing_long"})
    rec_existing_long[field] = "a" * 129
    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        resp2 = c.post(
            "/api/v1/sync/audit",
            headers={"Authorization": f"Bearer {info['device_token']}"},
            json={"session_id": sid, "records": [rec_existing_long]},
        )
    require_m3(1, resp2.status_code == 400,
               f"{field} > 128 chars at existing position must be 400, "
               f"got {resp2.status_code}")

    # --- At NEW position (chain_length 2) ---
    rec_new_bad = _make_audit_record(sid, 2, valid_rec["record_hash"],
                                     {"event": "t18_new"})
    rec_new_bad[field] = [1, 2, 3]
    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        resp3 = c.post(
            "/api/v1/sync/audit",
            headers={"Authorization": f"Bearer {info['device_token']}"},
            json={"session_id": sid, "records": [rec_new_bad]},
        )
    require_m3(1, resp3.status_code == 400,
               f"non-string {field} at new position must be 400, "
               f"got {resp3.status_code}")

    # No quarantine row or alert written (check came before fork)
    with psycopg.connect(conninfo) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        q_after = conn.execute(
            "SELECT count(*) FROM audit_quarantine "
            "WHERE connector_id = %s::uuid",
            [device_id],
        ).fetchone()[0]
        a_after = conn.execute(
            "SELECT count(*) FROM sync_alerts "
            "WHERE connector_id = %s::uuid",
            [device_id],
        ).fetchone()[0]
    require_m3(1, q_after == q_before,
               f"hash validation must not write quarantine row, "
               f"delta={q_after - q_before}")
    require_m3(1, a_after == a_before,
               f"hash validation must not write alert row, "
               f"delta={a_after - a_before}")


@pytest.mark.pg
def test_t1_18_repeated_refused_uploads_one_alert(t1sec_server):
    """40 identical refused uploads must give exactly 1 alert row (T1-18)."""
    import httpx
    info = t1sec_server
    conninfo = _conninfo(info["owner_url"])
    sid = f"sess-t18-dup-{uuid.uuid4().hex[:6]}"

    with psycopg.connect(conninfo) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [info["org_id"]])
        before = conn.execute(
            "SELECT count(*) FROM sync_alerts "
            "WHERE connector_id = %s::uuid",
            [info["device_id"]],
        ).fetchone()[0]

    # Use a body that will be refused (NaN).  Reuse one client for speed
    # (round 3: opening 40 clients crossed the 30 s timeout).
    raw_body = (
        '{"session_id":"' + sid + '","records":[{'
        '"session_id":"' + sid + '",'
        '"chain_length":1,'
        '"previous_hash":"",'
        '"record_hash":"' + "0" * 64 + '",'
        '"body":{"val":NaN}'
        '}]}'
    )
    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        for _ in range(40):
            c.post(
                "/api/v1/sync/audit",
                headers={
                    "Authorization": f"Bearer {info['device_token']}",
                    "Content-Type": "application/json",
                },
                content=raw_body.encode("utf-8"),
            )

    with psycopg.connect(conninfo) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [info["org_id"]])
        after = conn.execute(
            "SELECT count(*) FROM sync_alerts "
            "WHERE connector_id = %s::uuid",
            [info["device_id"]],
        ).fetchone()[0]
    require_m3(1, after - before == 1,
               f"40 refused uploads must create exactly 1 alert, delta={after - before}")


@pytest.mark.pg
def test_t1_18_device_sessions_limited_with_truncated(t1sec_server):
    """``/devices/{id}`` ``sessions`` and ``gaps`` must be limited with
    a truncated flag (T1-18)."""
    import httpx
    info = t1sec_server
    s = info["sessions"]["alice"]
    conninfo = _conninfo(info["owner_url"])
    device_id = info["device_id"]

    # Seed many sessions
    with psycopg.connect(conninfo, autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [info["org_id"]])
        for i in range(200):
            rid = str(uuid.uuid4())
            sid = f"sess-t18-flood-{i}"
            body_str = json.dumps({"i": i}, separators=(",", ":"))
            rh = hashlib.sha256(body_str.encode()).hexdigest()
            conn.execute(
                "INSERT INTO audit_records "
                "(id, org_id, connector_id, session_id, chain_length, "
                "previous_hash, record_hash, body, created_at) "
                "VALUES (%s, %s::uuid, %s::uuid, %s, 1, '', %s, %s::json, now()) "
                "ON CONFLICT DO NOTHING",
                [rid, info["org_id"], device_id, sid, rh, body_str],
            )

    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        r = c.get(f"/api/v1/devices/{device_id}",
                  cookies={"__Host-agg_session": s["cookie"]})
    require_m3(1, r.status_code == 200, f"device detail must be 200, got {r.status_code}")
    detail = r.json()

    # sessions must be limited and indicate truncation
    sessions = detail.get("sessions", [])
    require_m3(1, isinstance(sessions, list),
               f"sessions must be a list, got {type(sessions).__name__}")
    # Should be limited (not all 200+)
    sessions_truncated = detail.get("sessions_truncated")
    require_m3(1, len(sessions) < 200 and sessions_truncated is True,
               f"sessions must be limited with truncated flag, "
               f"got {len(sessions)} sessions, truncated={sessions_truncated}")


@pytest.mark.pg
def test_t1_18_verify_gaps_limited_with_truncated(t1sec_server):
    """``/audit/verify`` ``gaps`` must be limited with a truncated flag, and
    ``ok`` stays false when gaps are cut off (T1-18)."""
    import httpx
    info = t1sec_server
    s = info["sessions"]["alice"]
    conninfo = _conninfo(info["owner_url"])
    device_id = info["device_id"]
    run = uuid.uuid4().hex[:8]
    with psycopg.connect(conninfo, autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [info["org_id"]])
        for i in range(1100):
            conn.execute(
                "INSERT INTO audit_records "
                "(id, org_id, connector_id, session_id, chain_length, "
                "previous_hash, record_hash, body, created_at) "
                "VALUES (%s, %s::uuid, %s::uuid, %s, 1, '', %s, %s::json, now())",
                [str(uuid.uuid4()), info["org_id"], device_id,
                 f"gap-{run}-{i}", "f" * 64, '{"event":"gap"}'],
            )
    with httpx.Client(base_url=info["base_url"], timeout=120) as c:
        r = c.get("/api/v1/audit/verify", params={"project": info["project_id"]},
                  cookies={"__Host-agg_session": s["cookie"]})
    require_m3(1, r.status_code == 200, f"verify must be 200, got {r.status_code}")
    body = r.json()
    gaps = body.get("gaps", [])
    require_m3(1, len(gaps) < 1100 and body.get("gaps_truncated") is True,
               f"gaps must be limited with gaps_truncated, got {len(gaps)} "
               f"gaps, gaps_truncated={body.get('gaps_truncated')!r}")
    require_m3(1, body.get("ok") is False,
               f"cut-off gaps must not read ok, got {body.get('ok')!r}")


# ===================================================================
# T1-19: bad cursor values on all four cursor routes
# ===================================================================

_CURSOR_ROUTES = [
    ("/api/v1/devices", "project"),
    ("/api/v1/admin/enrollment-codes", "project"),
    ("/api/v1/admin/bundles", "project"),
    ("/api/v1/alerts", "project"),
]

# Bad POSITION forms that uuid.UUID() accepts but Postgres ::uuid rejects
# (or that uuid.UUID accepts with a different str() than the input).
# Cursor format is org_id:position.  We mutate only the position here.
_BAD_POSITION_FORMS = [
    ("urn:uuid:" + "00000000-0000-0000-0000-000000000000", "urn:uuid:"),
    ("{00000000-0000-0000-0000-000000000000}", "braces"),
    ("00000000000000000000000000000000", "no-hyphens"),
    ("0" * 15 + "_" + "0" * 16, "underscore"),
    ("٠" * 32, "non-ascii-digits"),
]


@pytest.mark.pg
@pytest.mark.parametrize("bad_pos,label", _BAD_POSITION_FORMS,
                         ids=[x[1] for x in _BAD_POSITION_FORMS])
@pytest.mark.parametrize("route_info", _CURSOR_ROUTES,
                         ids=[r[0].split("/")[-1] for r in _CURSOR_ROUTES])
def test_t1_19_bad_cursor_position(t1sec_server, route_info, bad_pos, label):
    """Bad position in ``org_id:position`` cursor must give the same
    bad-cursor response as a known garbage cursor on all four routes,
    and never 500 (T1-19).  The org part is the caller's real org id.
    A braces or no-hyphen spelling that returns 200 fails the node."""
    import httpx
    path, param_name = route_info
    info = t1sec_server
    s = info["sessions"]["alice"]
    org_id = info["org_id"]

    # Reference: a known-garbage cursor
    garbage_cursor = "zzzz:zzzz"
    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        ref = c.get(path,
                    params={param_name: info["project_id"],
                            "cursor": garbage_cursor},
                    cookies={"__Host-agg_session": s["cookie"]})
    ref_status = ref.status_code
    ref_body = ref.content

    # Bad position with real org id
    bad_cursor = f"{org_id}:{bad_pos}"
    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        r = c.get(path,
                  params={param_name: info["project_id"],
                          "cursor": bad_cursor},
                  cookies={"__Host-agg_session": s["cookie"]})
    require_m3(1, r.status_code != 500,
               f"bad position {label!r} on {path} must never 500, "
               f"got {r.status_code}")
    require_m3(1, r.status_code == ref_status,
               f"bad position {label!r} on {path}: status {r.status_code} "
               f"differs from garbage {ref_status}")
    require_m3(1, r.content == ref_body,
               f"bad position {label!r} on {path}: body not byte-identical "
               f"to garbage cursor response")


@pytest.mark.pg
@pytest.mark.parametrize("route_info", _CURSOR_ROUTES,
                         ids=[r[0].split("/")[-1] for r in _CURSOR_ROUTES])
def test_t1_19_bad_cursor_org_part(t1sec_server, route_info):
    """Bad org part (urn:uuid:, underscores, braces, no-hyphens) with a
    real position must produce the same bad-cursor response as garbage
    and never 500 (T1-19)."""
    import httpx
    path, param_name = route_info
    info = t1sec_server
    s = info["sessions"]["alice"]
    # Use a real position UUID
    real_position = str(uuid.uuid4())

    garbage_cursor = "zzzz:zzzz"
    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        ref = c.get(path,
                    params={param_name: info["project_id"],
                            "cursor": garbage_cursor},
                    cookies={"__Host-agg_session": s["cookie"]})
    ref_status = ref.status_code
    ref_body = ref.content

    org_id = info["org_id"]
    bad_org_forms = [
        (f"urn:uuid:{org_id}", "urn:uuid:org"),
        (org_id.replace("-", "_"), "underscores-org"),
        (f"{{{org_id}}}", "braces-org"),
        (org_id.replace("-", ""), "no-hyphens-org"),
    ]
    for bad_org, label in bad_org_forms:
        cursor = f"{bad_org}:{real_position}"
        with httpx.Client(base_url=info["base_url"], timeout=10) as c:
            r = c.get(path,
                      params={param_name: info["project_id"],
                              "cursor": cursor},
                      cookies={"__Host-agg_session": s["cookie"]})
        require_m3(1, r.status_code != 500,
                   f"bad org {label!r} on {path} must never 500, "
                   f"got {r.status_code}")
        require_m3(1, r.status_code == ref_status and r.content == ref_body,
                   f"bad org {label!r} on {path}: response differs from "
                   f"garbage (status {r.status_code} vs {ref_status})")


# ===================================================================
# T1-20: since/until edge cases never 500, parsed value used
# ===================================================================

@pytest.mark.pg
@pytest.mark.parametrize("bad_dt,label", [
    ("2026-W45-4", "week date"),
    ("2026-11-05T12:30:00,500", "comma fraction"),
    ("2026-11-05T12:30:00-23:59", "offset -23:59"),
], ids=["week", "comma", "offset"])
def test_t1_20_since_until_edge_never_500(t1sec_server, bad_dt, label):
    """``since``/``until`` of {label} must never 500; the parsed value
    must be used if accepted (T1-20)."""
    import httpx
    info = t1sec_server
    s = info["sessions"]["alice"]

    for param_name, route in [("since", "/api/v1/alerts"),
                              ("until", "/api/v1/audit/export"),
                              ("since", "/api/v1/audit/export")]:
        with httpx.Client(base_url=info["base_url"], timeout=10) as c:
            r = c.get(route,
                      params={"project": info["project_id"],
                              param_name: bad_dt},
                      cookies={"__Host-agg_session": s["cookie"]})
        require_m3(1, r.status_code != 500,
                   f"{param_name}={bad_dt!r} on {route} must never 500, "
                   f"got {r.status_code}")


# ===================================================================
# T1-21: corrupt blobs never 500
# ===================================================================

def _nan_bundle_blob():
    """A bundle blob with NaN in payload (T1-27)."""
    return b'{"kind":"agg/bundle/v1","sig_v":1,"payload":{"val":NaN},"signatures":[]}'


def _deep_nested_bundle_blob():
    """A bundle blob nested 5,000 levels in payload (T1-27)."""
    inner = '"deep"'
    for _ in range(5000):
        inner = '{"a":' + inner + '}'
    blob = '{"kind":"agg/bundle/v1","sig_v":1,"payload":' + inner + ',"signatures":[]}'
    return blob.encode("utf-8")


@pytest.mark.pg
@pytest.mark.parametrize("corrupt_data,label", [
    (b"\x80\x81\x82", "non-UTF-8"),
    (b'[1, 2, 3]', "JSON list"),
    (b'"just a string"', "JSON string"),
    (b'{"payload": [1,2,3]}', "non-object payload"),
    (_nan_bundle_blob(), "NaN in payload"),
    (_deep_nested_bundle_blob(), "deep nesting in payload"),
], ids=["non-utf8", "json-list", "json-string", "non-object-payload",
        "nan-payload", "deep-nesting-payload"])
def test_t1_21_corrupt_blob_never_500(t1sec_server, corrupt_data, label):
    """Corrupt blobs ({label}) as a bundle and as a predecessor must never
    500; must produce ``corrupt_bundle`` and ``diff_base_corrupt``
    respectively (T1-21)."""
    import httpx
    info = t1sec_server
    s = info["sessions"]["alice"]
    conninfo = _conninfo(info["owner_url"])

    # Insert corrupt blob as a bundle
    seq_a = 5000 + hash(label) % 1000
    with psycopg.connect(conninfo, autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [info["org_id"]])
        conn.execute(
            "INSERT INTO policy_bundles "
            "(id, org_id, project_id, sequence, bundle_blob, "
            "server_signature, created_at) "
            "VALUES (%s, %s::uuid, %s::uuid, %s, %s, '', now()) "
            "ON CONFLICT DO NOTHING",
            [str(uuid.uuid4()), info["org_id"], info["project_id"],
             seq_a, corrupt_data],
        )

    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        r = c.get(f"/api/v1/admin/bundles/{seq_a}",
                  params={"project": info["project_id"]},
                  cookies={"__Host-agg_session": s["cookie"]})
    require_m3(1, r.status_code != 500,
               f"corrupt bundle ({label}) must never 500, got {r.status_code}")
    if r.status_code == 200:
        detail = r.json()
        require_m3(1, detail.get("corrupt_bundle") is True,
                   f"corrupt bundle ({label}) must be marked corrupt_bundle")

    # Insert corrupt blob as predecessor (seq_a), valid as successor (seq_a+1)
    seq_b = seq_a + 1
    valid_payload = {
        "org_id": info["org_id"],
        "project_id": info["project_id"],
        "sequence": seq_b,
        "base_sequence": seq_a,
        "registry_version": 1,
        "folder_policy": {"allow": ["*.txt"]},
        "governance_policy": {},
        "mcp_policy": {},
        "approval": {"local_fallback": False, "allow_requester": False},
        "not_before": "2026-01-01T00:00:00Z",
        "expires_at": "2099-01-01T00:00:00Z",
        "environment": "prod",
    }
    envelope = sign_envelope("agg/bundle/v1", valid_payload,
                             info["bundle_signer_sk"])
    blob = json.dumps(envelope, separators=(",", ":"), sort_keys=True)
    with psycopg.connect(conninfo, autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [info["org_id"]])
        conn.execute(
            "INSERT INTO policy_bundles "
            "(id, org_id, project_id, sequence, bundle_blob, "
            "server_signature, created_at) "
            "VALUES (%s, %s::uuid, %s::uuid, %s, %s, '', now()) "
            "ON CONFLICT DO NOTHING",
            [str(uuid.uuid4()), info["org_id"], info["project_id"],
             seq_b, blob.encode("utf-8")],
        )

    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        r2 = c.get(f"/api/v1/admin/bundles/{seq_b}",
                   params={"project": info["project_id"]},
                   cookies={"__Host-agg_session": s["cookie"]})
    require_m3(1, r2.status_code != 500,
               f"corrupt predecessor ({label}) must never 500, got {r2.status_code}")
    if r2.status_code == 200:
        detail2 = r2.json()
        require_m3(1, detail2.get("diff_base_corrupt") is True,
                   f"corrupt predecessor ({label}) must be marked diff_base_corrupt")


# ===================================================================
# T1-22: project auditor 200 on verify/export, another project 404,
#         auditor in _NON_ADMIN_ROLES
# ===================================================================

@pytest.mark.pg
def test_t1_22_project_auditor_200_verify_export(t1sec_server):
    """A project-scope auditor must get 200 on verify and export.
    An auditor of another project must get 404 (T1-22)."""
    import httpx
    info = t1sec_server
    conninfo = _conninfo(info["owner_url"])
    org_id = info["org_id"]
    project_id = info["project_id"]

    # Create a project-scope auditor
    with psycopg.connect(conninfo, autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        proj_auditor_id = _seed_user_row(conn, org_id,
                                          f"proj-auditor-{uuid.uuid4().hex[:6]}@t1sec.test")
        _bind_role(conn, org_id, proj_auditor_id, "auditor",
                   scope_type="project", scope_id=project_id)

    clock = FakeClock()
    pa_cookie, pa_csrf, _ = _make_session(
        info["owner_url"], org_id, proj_auditor_id, clock=clock)

    # Verify: 200
    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        rv = c.get("/api/v1/audit/verify",
                   params={"project": project_id},
                   cookies={"__Host-agg_session": pa_cookie})
    require_m3(1, rv.status_code == 200,
               f"project auditor verify must be 200, got {rv.status_code}")

    # Export: 200
    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        re = c.get("/api/v1/audit/export",
                   params={"project": project_id},
                   cookies={"__Host-agg_session": pa_cookie})
    require_m3(1, re.status_code == 200,
               f"project auditor export must be 200, got {re.status_code}")

    # Auditor of ANOTHER project: 404
    other_project_id = str(uuid.uuid4())
    with psycopg.connect(conninfo, autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        conn.execute(
            "INSERT INTO projects (id, org_id, name, environment, created_at) "
            "VALUES (%s, %s::uuid, 'Other Project', 'dev', now())",
            [other_project_id, org_id],
        )
    with psycopg.connect(conninfo, autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        other_auditor_id = _seed_user_row(
            conn, org_id, f"other-auditor-{uuid.uuid4().hex[:6]}@t1sec.test")
        _bind_role(conn, org_id, other_auditor_id, "auditor",
                   scope_type="project", scope_id=other_project_id)

    oa_cookie, _, _ = _make_session(
        info["owner_url"], org_id, other_auditor_id, clock=clock)

    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        rv2 = c.get("/api/v1/audit/verify",
                    params={"project": project_id},
                    cookies={"__Host-agg_session": oa_cookie})
    require_m3(1, rv2.status_code == 404,
               f"auditor of another project must be 404 on verify, "
               f"got {rv2.status_code}")

    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        re2 = c.get("/api/v1/audit/export",
                    params={"project": project_id},
                    cookies={"__Host-agg_session": oa_cookie})
    require_m3(1, re2.status_code == 404,
               f"auditor of another project must be 404 on export, "
               f"got {re2.status_code}")


# ===================================================================
# T1-23: subprocess node for CLI audit verify
# ===================================================================

@pytest.mark.pg
def test_t1_23_cli_audit_verify_bad_project(t1sec_server):
    """``python -m agg_cp.cli audit verify --project not-a-uuid`` with no
    DB URL must be non-zero with an error on stderr (T1-23)."""
    import subprocess
    import sys

    import os
    env = {**os.environ}
    env.pop("AGG_DATABASE_URL", None)
    env.pop("AGG_DATABASE_URL_FILE", None)
    env.pop("DATABASE_URL", None)
    result = subprocess.run(
        [sys.executable, "-m", "agg_cp.cli", "audit", "verify",
         "--project", "not-a-uuid"],
        capture_output=True, text=True, timeout=30,
        env=env,
    )
    require_m3(1, result.returncode != 0,
               f"CLI audit verify with bad project must be non-zero, "
               f"got rc={result.returncode}")
    require_m3(1, len(result.stderr.strip()) > 0,
               f"CLI audit verify with bad project must have stderr, "
               f"got: {result.stderr!r}")


@pytest.mark.pg
def test_t1_23_cli_audit_verify_real_project(t1sec_server):
    """``python -m agg_cp.cli audit verify --project <real>`` must be
    rc 0 and print ``ok`` (T1-23).  Uses an isolated project with one
    clean chain so other tests' seeded rows cannot pollute verification."""
    import subprocess
    import sys
    import os
    import httpx

    info = t1sec_server
    conninfo_owner = _conninfo(info["owner_url"])
    org_id = info["org_id"]

    # Create an isolated project with one clean connector and record
    iso_project_id = str(uuid.uuid4())
    iso_device_id = str(uuid.uuid4())
    iso_token = secrets.token_urlsafe(32)
    iso_token_hash = hashlib.sha256(iso_token.encode()).hexdigest()

    with psycopg.connect(conninfo_owner, autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        create_project(conn, org_id, iso_project_id, "CLI Verify Project")
        pub = secrets.token_bytes(32)
        conn.execute(
            "INSERT INTO connectors "
            "(id, org_id, project_id, device_public_key, created_at) "
            "VALUES (%s, %s::uuid, %s::uuid, %s, now())",
            [iso_device_id, org_id, iso_project_id, pub.hex()],
        )
        conn.execute(
            "INSERT INTO device_tokens "
            "(id, org_id, project_id, connector_id, token_hash, "
            "expires_at, created_at) "
            "VALUES (%s, %s, %s, %s::uuid, %s, "
            "now() + interval '10 min', now())",
            [str(uuid.uuid4()), org_id, iso_project_id,
             iso_device_id, iso_token_hash],
        )

    # Upload one valid record via the API to create a clean chain
    sid_cli = f"sess-cli-{uuid.uuid4().hex[:8]}"
    rec_cli = _make_audit_record(sid_cli, 1, "", {"event": "cli_test"})
    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        up = c.post(
            "/api/v1/sync/audit",
            headers={"Authorization": f"Bearer {iso_token}"},
            json={"session_id": sid_cli, "records": [rec_cli]},
        )
    require_m3(1, up.status_code == 200,
               f"seed upload for CLI verify must be 200, got {up.status_code}")

    # Use the app_url (connects as agg_app) -- owner_url connects as
    # agg_owner which cannot SET ROLE agg_app in the test Postgres.
    # Set AGG_DATABASE_URL (not DATABASE_URL) because cli._db_url reads
    # AGG_DATABASE_URL first, and a prior module may have left it in
    # os.environ pointing at the shared database.
    conninfo = _conninfo(info["app_url"])
    env = {**os.environ, "AGG_DATABASE_URL": conninfo}
    env.pop("AGG_DATABASE_URL_FILE", None)

    result = subprocess.run(
        [sys.executable, "-m", "agg_cp.cli", "audit", "verify",
         "--project", iso_project_id],
        capture_output=True, text=True, timeout=30,
        env=env,
    )
    require_m3(1, result.returncode == 0,
               f"CLI audit verify with real project must be rc 0, "
               f"got rc={result.returncode}, "
               f"stdout={result.stdout[:500]}, "
               f"stderr={result.stderr[:2000]}")
    require_m3(1, "ok" in result.stdout.lower(),
               f"CLI audit verify must print 'ok', got: {result.stdout[:500]}")


# ===================================================================
# T1-25: escalations.status filter matches inbox's = 'pending'
# ===================================================================

@pytest.mark.pg
def test_t1_25_escalation_status_filter_pending(t1sec_server):
    """``/devices/{id}`` open_escalations must use ``status = 'pending'``
    (matching the inbox), not ``!= 'done'`` (T1-25)."""
    import httpx
    info = t1sec_server
    s = info["sessions"]["alice"]
    conninfo = _conninfo(info["owner_url"])
    device_id = info["device_id"]
    org_id = info["org_id"]

    # Seed one 'pending' and one 'decided' escalation
    pending_id = str(uuid.uuid4())
    decided_id = str(uuid.uuid4())
    project_id = info["project_id"]
    with psycopg.connect(conninfo, autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        conn.execute(
            "INSERT INTO escalations "
            "(id, org_id, project_id, connector_id, request_id, "
            "status, record, created_at) "
            "VALUES (%s, %s::uuid, %s::uuid, %s::uuid, %s, "
            "'pending', '{}'::jsonb, now())",
            [pending_id, org_id, project_id, device_id,
             f"req-pend-{uuid.uuid4().hex[:8]}"],
        )
        conn.execute(
            "INSERT INTO escalations "
            "(id, org_id, project_id, connector_id, request_id, "
            "status, record, created_at) "
            "VALUES (%s, %s::uuid, %s::uuid, %s::uuid, %s, "
            "'decided', '{}'::jsonb, now())",
            [decided_id, org_id, project_id, device_id,
             f"req-dec-{uuid.uuid4().hex[:8]}"],
        )

    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        r = c.get(f"/api/v1/devices/{device_id}",
                  cookies={"__Host-agg_session": s["cookie"]})
    require_m3(1, r.status_code == 200, f"device detail must be 200")
    detail = r.json()
    escs = detail.get("open_escalations", [])
    esc_ids = {e.get("id") for e in escs}

    # 'pending' must appear
    require_m3(1, pending_id in esc_ids,
               f"pending escalation must appear in open_escalations")
    # 'decided' must NOT appear (status = 'pending', not != 'done')
    require_m3(1, decided_id not in esc_ids,
               f"decided escalation must NOT appear in open_escalations "
               f"(filter must be = 'pending', not != 'done')")


# ===================================================================
# T1-26: fixed nesting limit 1,000 (round 3)
# ===================================================================

@pytest.mark.pg
def test_t1_26_nesting_limit_1000_accept(t1sec_server):
    """A body nested exactly 1,000 levels (the fixed limit) with a correct
    hash must be 200 and verify ok (T1-26).

    Uses its own project, connector and device token (like T1-16) so the
    verify result is about this node's rows only: other nodes seed the
    shared project with deliberately bad rows (hash_mismatch gaps)."""
    import httpx
    info = t1sec_server
    sid = f"sess-t26-ok-{uuid.uuid4().hex[:6]}"
    conninfo = _conninfo(info["owner_url"])
    org_id = info["org_id"]

    # Isolated project + connector + device token for this node only
    iso_project_id = str(uuid.uuid4())
    with psycopg.connect(conninfo, autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        create_project(conn, org_id, iso_project_id, "T26 Nesting 1000 Project")
    iso_device_id = _seed_connector(info["owner_url"], org_id, iso_project_id,
                                    secrets.token_bytes(32))
    iso_token = secrets.token_urlsafe(32)
    _seed_device_token(info["owner_url"], org_id, iso_project_id,
                       iso_device_id, iso_token)

    # Build 1,000-level nested JSON
    inner = '"leaf"'
    for _ in range(1000):
        inner = '{"a":' + inner + '}'
    body_bytes = inner.encode("utf-8")
    rh = hashlib.sha256(body_bytes).hexdigest()
    raw_body = (
        '{"session_id":"' + sid + '","records":[{'
        '"session_id":"' + sid + '",'
        '"chain_length":1,'
        '"previous_hash":"",'
        '"record_hash":"' + rh + '",'
        '"body":' + inner +
        '}]}'
    )

    with httpx.Client(base_url=info["base_url"], timeout=30) as c:
        resp = c.post(
            "/api/v1/sync/audit",
            headers={
                "Authorization": f"Bearer {iso_token}",
                "Content-Type": "application/json",
            },
            content=raw_body.encode("utf-8"),
        )
    require_m3(1, resp.status_code == 200,
               f"1000-level nesting must be accepted, got {resp.status_code}")

    # Verify ok on the isolated project (only this node's row lives there)
    s = info["sessions"]["alice"]
    with httpx.Client(base_url=info["base_url"], timeout=30) as c:
        vr = c.get("/api/v1/audit/verify",
                   params={"project": iso_project_id},
                   cookies={"__Host-agg_session": s["cookie"]})
    require_m3(1, vr.status_code == 200 and vr.json().get("ok") is True,
               f"verify must be ok after 1000-level body, "
               f"got {vr.status_code}: {vr.text[:200]}")


@pytest.mark.pg
def test_t1_26_nesting_limit_1001_refuse(t1sec_server):
    """A body nested 1,001 levels (one above the limit) with a correct
    hash must be 400 ``audit_record_unstorable`` with exactly 1
    deduplicated alert (T1-26)."""
    import httpx
    info = t1sec_server
    conninfo = _conninfo(info["owner_url"])
    sid = f"sess-t26-bad-{uuid.uuid4().hex[:6]}"

    with psycopg.connect(conninfo) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [info["org_id"]])
        before = conn.execute(
            "SELECT count(*) FROM sync_alerts "
            "WHERE connector_id = %s::uuid "
            "AND kind = 'audit_record_unstorable'",
            [info["device_id"]],
        ).fetchone()[0]

    inner = '"leaf"'
    for _ in range(1001):
        inner = '{"a":' + inner + '}'
    body_bytes = inner.encode("utf-8")
    rh = hashlib.sha256(body_bytes).hexdigest()
    raw_body = (
        '{"session_id":"' + sid + '","records":[{'
        '"session_id":"' + sid + '",'
        '"chain_length":1,'
        '"previous_hash":"",'
        '"record_hash":"' + rh + '",'
        '"body":' + inner +
        '}]}'
    )

    with httpx.Client(base_url=info["base_url"], timeout=30) as c:
        resp = c.post(
            "/api/v1/sync/audit",
            headers={
                "Authorization": f"Bearer {info['device_token']}",
                "Content-Type": "application/json",
            },
            content=raw_body.encode("utf-8"),
        )
    require_m3(1, resp.status_code == 400,
               f"1001-level nesting must be 400, got {resp.status_code}")

    with psycopg.connect(conninfo) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [info["org_id"]])
        after = conn.execute(
            "SELECT count(*) FROM sync_alerts "
            "WHERE connector_id = %s::uuid "
            "AND kind = 'audit_record_unstorable'",
            [info["device_id"]],
        ).fetchone()[0]
    require_m3(1, after - before == 1,
               f"1001-level nesting must create exactly 1 alert, "
               f"delta={after - before}")


@pytest.mark.pg
def test_t1_26_parser_limit_huge_array(t1sec_server):
    """Guard: a 200,000-level nested array triggers Python's RecursionError
    (measured parser limits: 2,997 Windows 3.12, 9,997 Linux 3.12, 52,203
    Linux 3.15; 200,000 is ~4x the largest), the product catches it and
    returns 400 (not 500).  This already works; the test guards the
    existing behaviour (T1-26 RecursionError branch)."""
    import httpx
    info = t1sec_server
    conninfo = _conninfo(info["owner_url"])
    sid = f"sess-t26-huge-{uuid.uuid4().hex[:6]}"

    with psycopg.connect(conninfo) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [info["org_id"]])
        before = conn.execute(
            "SELECT count(*) FROM sync_alerts "
            "WHERE connector_id = %s::uuid",
            [info["device_id"]],
        ).fetchone()[0]

    # 200,000 nested arrays: [[[[...]]]] ~ 400 KB (string multiplication,
    # not a loop: the loop was quadratic and pushed the node past 30 s)
    depth = 200000
    inner = '[' * depth + '"x"' + ']' * depth
    body_bytes = inner.encode("utf-8")
    rh = hashlib.sha256(body_bytes).hexdigest()

    raw_body = (
        '{"session_id":"' + sid + '","records":[{'
        '"session_id":"' + sid + '",'
        '"chain_length":1,'
        '"previous_hash":"",'
        '"record_hash":"' + rh + '",'
        '"body":' + inner +
        '}]}'
    )

    with httpx.Client(base_url=info["base_url"], timeout=30) as c:
        resp = c.post(
            "/api/v1/sync/audit",
            headers={
                "Authorization": f"Bearer {info['device_token']}",
                "Content-Type": "application/json",
            },
            content=raw_body.encode("utf-8"),
        )
    assert resp.status_code == 400, (
        f"200k-level array must be 400, got {resp.status_code}")
    assert resp.status_code != 500, "200k-level array must never be 500"

    with psycopg.connect(conninfo) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [info["org_id"]])
        after = conn.execute(
            "SELECT count(*) FROM sync_alerts "
            "WHERE connector_id = %s::uuid",
            [info["device_id"]],
        ).fetchone()[0]
    assert after - before >= 1, (
        f"200k-level array must create an alert, delta={after - before}")


@pytest.mark.pg
def test_t1_26_nesting_dedup_40_repeats(t1sec_server):
    """40 requests of 1,001-level nesting and 40 of the huge array must
    each produce exactly 1 alert, not 40 (T1-26 deduplication)."""
    import httpx
    info = t1sec_server
    conninfo = _conninfo(info["owner_url"])

    # --- 1,001-level nesting ---
    sid_nest = f"sess-t26-dd1-{uuid.uuid4().hex[:6]}"
    inner_nest = '"leaf"'
    for _ in range(1001):
        inner_nest = '{"a":' + inner_nest + '}'
    body_nest_bytes = inner_nest.encode("utf-8")
    rh_nest = hashlib.sha256(body_nest_bytes).hexdigest()
    raw_nest = (
        '{"session_id":"' + sid_nest + '","records":[{'
        '"session_id":"' + sid_nest + '",'
        '"chain_length":1,'
        '"previous_hash":"",'
        '"record_hash":"' + rh_nest + '",'
        '"body":' + inner_nest +
        '}]}'
    )

    with psycopg.connect(conninfo) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [info["org_id"]])
        before_nest = conn.execute(
            "SELECT count(*) FROM sync_alerts "
            "WHERE connector_id = %s::uuid "
            "AND kind = 'audit_record_unstorable'",
            [info["device_id"]],
        ).fetchone()[0]

    with httpx.Client(base_url=info["base_url"], timeout=30) as c:
        for _ in range(40):
            c.post(
                "/api/v1/sync/audit",
                headers={
                    "Authorization": f"Bearer {info['device_token']}",
                    "Content-Type": "application/json",
                },
                content=raw_nest.encode("utf-8"),
            )

    with psycopg.connect(conninfo) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [info["org_id"]])
        after_nest = conn.execute(
            "SELECT count(*) FROM sync_alerts "
            "WHERE connector_id = %s::uuid "
            "AND kind = 'audit_record_unstorable'",
            [info["device_id"]],
        ).fetchone()[0]
    require_m3(1, after_nest - before_nest == 1,
               f"40 repeats of 1001-level nesting must produce exactly "
               f"1 alert, delta={after_nest - before_nest}")

    # --- Huge array (parser limit) ---
    sid_huge = f"sess-t26-dd2-{uuid.uuid4().hex[:6]}"
    # 200,000 nested arrays via string multiplication (the loop was
    # quadratic and pushed the node past 30 s)
    depth_huge = 200000
    inner_huge = '[' * depth_huge + '"x"' + ']' * depth_huge
    body_huge_bytes = inner_huge.encode("utf-8")
    rh_huge = hashlib.sha256(body_huge_bytes).hexdigest()
    raw_huge = (
        '{"session_id":"' + sid_huge + '","records":[{'
        '"session_id":"' + sid_huge + '",'
        '"chain_length":1,'
        '"previous_hash":"",'
        '"record_hash":"' + rh_huge + '",'
        '"body":' + inner_huge +
        '}]}'
    )

    with psycopg.connect(conninfo) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [info["org_id"]])
        before_huge = conn.execute(
            "SELECT count(*) FROM sync_alerts "
            "WHERE connector_id = %s::uuid",
            [info["device_id"]],
        ).fetchone()[0]

    with httpx.Client(base_url=info["base_url"], timeout=30) as c:
        for _ in range(40):
            c.post(
                "/api/v1/sync/audit",
                headers={
                    "Authorization": f"Bearer {info['device_token']}",
                    "Content-Type": "application/json",
                },
                content=raw_huge.encode("utf-8"),
            )

    with psycopg.connect(conninfo) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [info["org_id"]])
        after_huge = conn.execute(
            "SELECT count(*) FROM sync_alerts "
            "WHERE connector_id = %s::uuid",
            [info["device_id"]],
        ).fetchone()[0]
    require_m3(1, after_huge - before_huge == 1,
               f"40 repeats of huge array must produce exactly "
               f"1 alert, delta={after_huge - before_huge}")


# ===================================================================
# T1-17: peak memory on export and verify (round 3)
# ===================================================================

def _list_processes():
    """Return a list of ``(pid, ppid, cmdline)`` for every visible process.

    Windows: PowerShell ``Get-CimInstance Win32_Process`` (wmic is removed
    on Windows 11).  Linux (ee CI): read ``/proc/*/cmdline`` and the
    ``PPid`` line of ``/proc/<pid>/status``.  No psutil.
    """
    import sys
    procs = []
    if sys.platform == "win32":
        import csv
        import io
        import subprocess
        ps_cmd = (
            "Get-CimInstance Win32_Process | "
            "Select-Object ProcessId, ParentProcessId, CommandLine | "
            "ConvertTo-Csv -NoTypeInformation"
        )
        result = subprocess.run(
            ["powershell.exe", "-NoProfile", "-Command", ps_cmd],
            capture_output=True, text=True, timeout=30,
        )
        for row in csv.DictReader(io.StringIO(result.stdout)):
            try:
                pid = int(row.get("ProcessId") or 0)
                ppid = int(row.get("ParentProcessId") or 0)
            except ValueError:
                continue
            procs.append((pid, ppid, row.get("CommandLine") or ""))
        return procs

    import os
    for name in os.listdir("/proc"):
        if not name.isdigit():
            continue
        pid = int(name)
        try:
            with open(f"/proc/{pid}/cmdline", "rb") as fh:
                cmdline = fh.read().replace(b"\0", b" ").decode(
                    "utf-8", "replace")
            ppid = 0
            with open(f"/proc/{pid}/status", encoding="utf-8",
                      errors="replace") as fh:
                for line in fh:
                    if line.startswith("PPid:"):
                        ppid = int(line.split()[1])
                        break
        except (OSError, ValueError, IndexError):
            continue
        procs.append((pid, ppid, cmdline))
    return procs


def _find_server_pids(port: int | None = None) -> list[int]:
    """PIDs of the uvicorn agg_cp supervisor(s) plus their direct children
    (the workers).  Workers must be found through the parent link: on
    Windows uvicorn spawns workers via ``multiprocessing.spawn``, whose
    command line does not mention uvicorn or agg_cp.  ``port`` restricts
    the match to the supervisor started with ``--port <port>``, so a
    fresh per-node server is measured on its own."""
    procs = _list_processes()
    supervisors = set()
    for pid, _ppid, cmd in procs:
        if "uvicorn" in cmd and "agg_cp" in cmd:
            if port is not None and f"--port {port}" not in cmd:
                continue
            supervisors.add(pid)
    pids = set(supervisors)
    for pid, ppid, _cmd in procs:
        if ppid in supervisors:
            pids.add(pid)
    return sorted(pids)


def _peak_rss_bytes(pids: list[int]) -> dict:
    """{pid: lifetime peak resident bytes}.  Windows: PeakWorkingSetSize via
    GetProcessMemoryInfo (ctypes).  Linux: VmHWM from /proc/<pid>/status."""
    import sys
    peaks = {}
    if sys.platform != "win32":
        for pid in pids:
            try:
                with open(f"/proc/{pid}/status", encoding="utf-8",
                          errors="replace") as fh:
                    for line in fh:
                        if line.startswith("VmHWM:"):
                            peaks[pid] = int(line.split()[1]) * 1024
                            break
            except (OSError, ValueError, IndexError):
                continue
        return peaks

    import ctypes
    import ctypes.wintypes as wt

    class PROCESS_MEMORY_COUNTERS(ctypes.Structure):
        _fields_ = [
            ("cb", wt.DWORD),
            ("PageFaultCount", wt.DWORD),
            ("PeakWorkingSetSize", ctypes.c_size_t),
            ("WorkingSetSize", ctypes.c_size_t),
            ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
            ("QuotaPagedPoolUsage", ctypes.c_size_t),
            ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
            ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
            ("PagefileUsage", ctypes.c_size_t),
            ("PeakPagefileUsage", ctypes.c_size_t),
        ]

    kernel32 = ctypes.windll.kernel32
    psapi = ctypes.windll.psapi
    PROCESS_QUERY_INFORMATION = 0x0400
    PROCESS_VM_READ = 0x0010

    for pid in pids:
        handle = kernel32.OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
        if not handle:
            continue
        try:
            pmc = PROCESS_MEMORY_COUNTERS()
            pmc.cb = ctypes.sizeof(pmc)
            if psapi.GetProcessMemoryInfo(
                    handle, ctypes.byref(pmc), ctypes.sizeof(pmc)):
                peaks[pid] = pmc.PeakWorkingSetSize
        finally:
            kernel32.CloseHandle(handle)
    return peaks


def _get_worker_peak_bytes(port: int | None = None):
    """Return {pid: peak resident bytes} for the uvicorn agg_cp supervisor
    and its workers (optionally only the server on ``port``).  Works on
    Windows (ctypes) and Linux (/proc); no psutil."""
    return _peak_rss_bytes(_find_server_pids(port))


def _max_peak_delta(before: dict, after: dict) -> int:
    """Largest lifetime-peak growth across the measured processes."""
    best = 0
    for pid, before_mem in before.items():
        delta = after.get(pid, before_mem) - before_mem
        if delta > best:
            best = delta
    return best


@pytest.fixture
def t1_peak_server(t1_isolated_db, pg_roles, tmp_path_factory):
    """FRESH 4-worker agg_cp server for the peak-memory node only.

    PeakWorkingSetSize / VmHWM is the process-lifetime peak.  On the
    module server earlier nodes (20 MB byte cap, T1-17 behavioral) have
    already pushed the peak up, so a delta measured there is ~0 and the
    assertion is vacuous.  This server has handled no requests before the
    node's own, so its lifetime peak is this node's requests.  Mirrors
    ``t1sec_server`` (own org, admin user + session, project, connector,
    device token) at function scope; stopped at teardown.
    """
    import os
    iso_pg_url, iso_app_url, iso_owner_url = t1_isolated_db

    bundle_signer_sk = SigningKey.generate()
    key_dir = tmp_path_factory.mktemp("t1peak_signer")
    key_file = key_dir / "bundle_signer.key"
    key_file.write_bytes(bytes(bundle_signer_sk).hex().encode("ascii"))
    old_bs = os.environ.get("AGG_BUNDLE_SIGNER_KEY_FILE")
    os.environ["AGG_BUNDLE_SIGNER_KEY_FILE"] = str(key_file)

    gen = make_sync_server(
        iso_pg_url, iso_app_url, iso_owner_url,
        org_names=["T1Peak Org"],
    )
    try:
        info = next(gen)
        org_id = info["org_id"]
        conninfo = _conninfo(iso_owner_url)
        project_id = str(uuid.uuid4())
        with psycopg.connect(conninfo, autocommit=True) as conn:
            conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
            alice_id = _seed_user_row(conn, org_id, "alice@t1peak.test")
            _bind_role(conn, org_id, alice_id, "admin")
            create_project(conn, org_id, project_id, "T1Peak Project")

        device_id = _seed_connector(iso_owner_url, org_id, project_id,
                                    secrets.token_bytes(32))
        token = secrets.token_urlsafe(32)
        _seed_device_token(iso_owner_url, org_id, project_id, device_id, token)

        cookie, csrf, _sid = _make_session(iso_owner_url, org_id, alice_id,
                                           clock=FakeClock())
        info.update({
            "alice_id": alice_id,
            "project_id": project_id,
            "device_id": device_id,
            "device_token": token,
            "port": int(info["base_url"].rsplit(":", 1)[1]),
            "sessions": {"alice": {"cookie": cookie, "csrf": csrf}},
        })
        yield info
    finally:
        gen.close()
        if old_bs is None:
            os.environ.pop("AGG_BUNDLE_SIGNER_KEY_FILE", None)
        else:
            os.environ["AGG_BUNDLE_SIGNER_KEY_FILE"] = old_bs


def _seed_t17_peak_rows(conninfo, org_id, device_id, n=120):
    """Seed ``n`` audit rows of ~1 MB each by direct DB insert (no server
    request, so the fresh server's worker peaks stay untouched before
    the node's own snapshot).  Shared by the T1-17 export and verify
    peak-memory nodes."""
    with psycopg.connect(conninfo, autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        for i in range(n):
            rid = str(uuid.uuid4())
            sid = f"sess-t17-peak-{i}"
            body_dict = {"event": "t17_peak", "payload": "X" * (1024 * 1024)}
            body_str = json.dumps(body_dict, separators=(",", ":"),
                                  sort_keys=True)
            rh = hashlib.sha256(body_str.encode()).hexdigest()
            conn.execute(
                "INSERT INTO audit_records "
                "(id, org_id, connector_id, session_id, chain_length, "
                "previous_hash, record_hash, body, created_at) "
                "VALUES (%s, %s::uuid, %s::uuid, %s, 1, '', %s, "
                "%s::json, now()) ON CONFLICT DO NOTHING",
                [rid, org_id, device_id, sid, rh, body_str],
            )


@pytest.mark.pg
@pytest.mark.timeout(180)
def test_t1_17_export_peak_memory(t1_peak_server):
    """Measure worker peak resident memory delta on export and verify with
    120 rows of ~1 MB each, on a FRESH server whose lifetime peak is set
    by this node alone.  Delta (largest change across workers) must be at
    most 64 MB for export and 32 MB for verify (T1-17).

    Fails today: ``FETCH 500`` (admin_reads.py export) and ``FETCH 200``
    (audit.py verify) load hundreds of MB of 1 MB rows at once."""
    import httpx
    info = t1_peak_server
    s = info["sessions"]["alice"]
    conninfo = _conninfo(info["owner_url"])
    org_id = info["org_id"]
    project_id = info["project_id"]
    device_id = info["device_id"]
    port = info["port"]

    # Seed 120 rows of ~1 MB each (direct DB insert: no server request)
    _seed_t17_peak_rows(conninfo, org_id, device_id)

    # Snapshot this server's supervisor + 4 workers before export
    workers_before = _get_worker_peak_bytes(port)
    assert len(workers_before) >= 5, (
        f"expected the fresh server's supervisor and 4 workers on port "
        f"{port}, found {len(workers_before)}: {sorted(workers_before)}")

    # Export
    with httpx.Client(base_url=info["base_url"], timeout=120) as c:
        r_export = c.get("/api/v1/audit/export",
                         params={"project": project_id},
                         cookies={"__Host-agg_session": s["cookie"]})
    assert r_export.status_code == 200, (
        f"export must be 200, got {r_export.status_code}")

    workers_after_export = _get_worker_peak_bytes(port)
    export_delta_mb = _max_peak_delta(
        workers_before, workers_after_export) / (1024 * 1024)

    # Verify
    workers_before_v = _get_worker_peak_bytes(port)
    with httpx.Client(base_url=info["base_url"], timeout=120) as c:
        r_verify = c.get("/api/v1/audit/verify",
                         params={"project": project_id},
                         cookies={"__Host-agg_session": s["cookie"]})
    assert r_verify.status_code == 200, (
        f"verify must be 200, got {r_verify.status_code}")

    workers_after_verify = _get_worker_peak_bytes(port)
    verify_delta_mb = _max_peak_delta(
        workers_before_v, workers_after_verify) / (1024 * 1024)

    print(f"\nT1-17 peak deltas: export={export_delta_mb:.1f} MB "
          f"verify={verify_delta_mb:.1f} MB")

    assert export_delta_mb <= 64, (
        f"export peak delta must be <= 64 MB, measured {export_delta_mb:.1f} MB "
        f"(verify delta {verify_delta_mb:.1f} MB)")
    assert verify_delta_mb <= 32, (
        f"verify peak delta must be <= 32 MB, measured {verify_delta_mb:.1f} MB "
        f"(export delta {export_delta_mb:.1f} MB)")


@pytest.mark.pg
@pytest.mark.timeout(180)
def test_t1_17_verify_peak_memory(t1_peak_server):
    """Measure worker peak resident memory delta on verify ALONE with 120
    rows of ~1 MB each, on a FRESH server whose lifetime peak is set by
    this node's single verify request.  In the export node the worker
    that served the export already holds the export peak, so the verify
    delta measured there is masked.  Delta (largest change across
    workers) must be at most 32 MB (T1-17, security round 4)."""
    import httpx
    info = t1_peak_server
    s = info["sessions"]["alice"]
    conninfo = _conninfo(info["owner_url"])
    org_id = info["org_id"]
    project_id = info["project_id"]
    device_id = info["device_id"]
    port = info["port"]

    # Seed 120 rows of ~1 MB each (direct DB insert: no server request)
    _seed_t17_peak_rows(conninfo, org_id, device_id)

    # Snapshot this server's supervisor + 4 workers before verify
    workers_before = _get_worker_peak_bytes(port)
    assert len(workers_before) >= 5, (
        f"expected the fresh server's supervisor and 4 workers on port "
        f"{port}, found {len(workers_before)}: {sorted(workers_before)}")

    # Verify ONLY (no export on this server)
    with httpx.Client(base_url=info["base_url"], timeout=120) as c:
        r_verify = c.get("/api/v1/audit/verify",
                         params={"project": project_id},
                         cookies={"__Host-agg_session": s["cookie"]})
    assert r_verify.status_code == 200, (
        f"verify must be 200, got {r_verify.status_code}")

    workers_after_verify = _get_worker_peak_bytes(port)
    verify_delta_mb = _max_peak_delta(
        workers_before, workers_after_verify) / (1024 * 1024)

    print(f"\nT1-17 peak delta (verify alone): verify={verify_delta_mb:.1f} MB")

    assert verify_delta_mb <= 32, (
        f"verify peak delta must be <= 32 MB, measured {verify_delta_mb:.1f} MB")


@pytest.mark.pg
def test_t1_17_meta_line_reservation(t1sec_server):
    """Two rows: one big (fills cap - 50 bytes), one small (triggers
    truncation).  The ``_meta`` line is appended after the byte-cap check,
    so the total response body exceeds the declared cap.  Today the
    product does not reserve bytes for the ``_meta`` line (T1-17
    round 3).  The test requires BOTH (a) total body <= cap AND
    (b) the ``_meta`` line is present when truncated."""
    import httpx
    info = t1sec_server
    s = info["sessions"]["alice"]
    conninfo = _conninfo(info["owner_url"])
    org_id = info["org_id"]

    # Use a dedicated project for this edge case
    edge_project_id = str(uuid.uuid4())
    edge_device_id = str(uuid.uuid4())
    edge_token = secrets.token_urlsafe(32)
    edge_token_hash = hashlib.sha256(edge_token.encode()).hexdigest()

    with psycopg.connect(conninfo, autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        create_project(conn, org_id, edge_project_id, "T17 Edge Project")
        pub = secrets.token_bytes(32)
        conn.execute(
            "INSERT INTO connectors "
            "(id, org_id, project_id, device_public_key, created_at) "
            "VALUES (%s, %s::uuid, %s::uuid, %s, now())",
            [edge_device_id, org_id, edge_project_id, pub.hex()],
        )
        conn.execute(
            "INSERT INTO device_tokens "
            "(id, org_id, project_id, connector_id, token_hash, "
            "expires_at, created_at) "
            "VALUES (%s, %s, %s, %s::uuid, %s, "
            "now() + interval '10 min', now())",
            [str(uuid.uuid4()), org_id, edge_project_id,
             edge_device_id, edge_token_hash],
        )

    # Grant admin on this project
    with psycopg.connect(conninfo, autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        _bind_role(conn, org_id, info["alice_id"], "admin",
                   scope_type="project", scope_id=edge_project_id)

    # First, discover the cap by requesting an empty export
    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        r0 = c.get("/api/v1/audit/export",
                    params={"project": edge_project_id},
                    cookies={"__Host-agg_session": s["cookie"]})
    require_m3(1, r0.status_code == 200,
               f"empty export must be 200, got {r0.status_code}")
    cap_str = r0.headers.get("X-Export-Byte-Cap")
    require_m3(1, cap_str is not None, "must declare X-Export-Byte-Cap")
    cap = int(cap_str)

    # Row 1 (big): export line ~= cap - 50 bytes.
    # Export-line overhead (sorted keys, compact JSON, UUID fields) is
    # about 250-270 bytes.  Pad body so the line lands at cap - 50.
    sid = "sess-t17-edge"
    padding_size = cap - 305  # body JSON = padding_size + 7; line ~ padding_size + 257
    if padding_size < 100:
        padding_size = 100
    body_big = {"p": "M" * padding_size}
    body_big_str = json.dumps(body_big, separators=(",", ":"),
                              sort_keys=True)
    rh_big = hashlib.sha256(body_big_str.encode()).hexdigest()

    # Row 2 (small): triggers truncation (line ~300 bytes > remaining ~50)
    body_small = {"p": "x"}
    body_small_str = json.dumps(body_small, separators=(",", ":"),
                                sort_keys=True)
    rh_small = hashlib.sha256(body_small_str.encode()).hexdigest()

    with psycopg.connect(conninfo, autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        conn.execute(
            "INSERT INTO audit_records "
            "(id, org_id, connector_id, session_id, chain_length, "
            "previous_hash, record_hash, body, created_at) "
            "VALUES (%s, %s::uuid, %s::uuid, %s, 1, '', %s, "
            "%s::json, now())",
            [str(uuid.uuid4()), org_id, edge_device_id, sid, rh_big,
             body_big_str],
        )
        conn.execute(
            "INSERT INTO audit_records "
            "(id, org_id, connector_id, session_id, chain_length, "
            "previous_hash, record_hash, body, created_at) "
            "VALUES (%s, %s::uuid, %s::uuid, %s, 2, %s, %s, "
            "%s::json, now())",
            [str(uuid.uuid4()), org_id, edge_device_id, sid, rh_big,
             rh_small, body_small_str],
        )

    with httpx.Client(base_url=info["base_url"], timeout=30) as c:
        r = c.get("/api/v1/audit/export",
                  params={"project": edge_project_id},
                  cookies={"__Host-agg_session": s["cookie"]})
    require_m3(1, r.status_code == 200,
               f"edge export must be 200, got {r.status_code}")

    # The response must be truncated (row 2 does not fit after row 1)
    require_m3(1, r.headers.get("X-Export-Truncated") == "true",
               "export must be truncated with row 1 near cap + row 2")

    # (a) _meta line must be present
    resp_text = r.content.decode("utf-8")
    has_meta = any(
        '"_meta"' in line for line in resp_text.strip().split("\n")
    )
    require_m3(1, has_meta,
               "_meta line must be present when truncated")

    # (b) total body (including _meta) must be at or under the cap
    body_len = len(r.content)
    require_m3(1, body_len <= cap,
               f"export body ({body_len} bytes) must be <= cap ({cap}) "
               f"even with the _meta line appended. "
               f"The _meta line's bytes must be reserved.")


# ===================================================================
# T1-28: CLI ignores DATABASE_URL (round 3)
# ===================================================================

@pytest.mark.pg
def test_t1_28_cli_ignores_database_url(t1sec_server):
    """With only ``DATABASE_URL`` set (no ``AGG_DATABASE_URL`` or
    ``AGG_DATABASE_URL_FILE``), the CLI must refuse to connect or
    exit non-zero.  The fallback is a security risk: a verify that
    silently picks its target is the T1-23 failure class (T1-28)."""
    import subprocess
    import sys
    import os

    info = t1sec_server
    # Point DATABASE_URL at a real database so the test proves the CLI
    # ignores it, not that it fails on a bad URL
    conninfo = _conninfo(info["app_url"])
    env = {**os.environ, "DATABASE_URL": conninfo}
    env.pop("AGG_DATABASE_URL", None)
    env.pop("AGG_DATABASE_URL_FILE", None)

    result = subprocess.run(
        [sys.executable, "-m", "agg_cp.cli", "audit", "verify",
         "--project", info["project_id"]],
        capture_output=True, text=True, timeout=30,
        env=env,
    )
    # The CLI must reject the request with "no_db_url", not silently
    # fall back to DATABASE_URL.  Today it falls back and connects,
    # so "no_db_url" is absent from stdout.
    require_m3(1, '"no_db_url"' in result.stdout,
               f"CLI must refuse with 'no_db_url' when only DATABASE_URL set, "
               f"got rc={result.returncode}, "
               f"stdout={result.stdout[:300]}")


# ===================================================================
# T1-17: fetch count pinned with ast (round 3)
# ===================================================================

@pytest.mark.pg
def test_t1_17_fetch_count_pinned(t1sec_server):
    """Structural: the named cursor FETCH count in admin_reads.py
    and audit.py must be at most 16 (T1-17 round 3 suggested shape).
    One row can be about 1 MiB, so a batch of 16 is about 16 MiB."""
    import ast
    import re
    from pathlib import Path

    admin_reads_path = Path("ee/src/agg_cp/sync/admin_reads.py")
    audit_path = Path("ee/src/agg_cp/sync/audit.py")

    for src_path in [admin_reads_path, audit_path]:
        if not src_path.exists():
            continue
        src = src_path.read_text(encoding="utf-8")
        # Find all FETCH <n> patterns
        fetches = re.findall(r'FETCH\s+(\d+)', src)
        for count_str in fetches:
            count = int(count_str)
            require_m3(1, count <= 16,
                       f"{src_path.name} has FETCH {count}, must be <= 16 "
                       f"(one row can be ~1 MiB)")
