"""T12c c1 extra test 9: server-side script binding fields.

Interface contract (pinned -- the build removes only xfail markers)
-------------------------------------------------------------------
Server routes (agg_cp.sync.escalations, T12c additions):

    POST /api/v1/sync/escalations  (upload)
        A record carrying ``script_rel``, ``script_sha256`` and
        ``preview_sha256`` in the upload body stores them; the
        server keeps ``script`` (rel, sha256, size) and
        ``script_preview`` (text, sha256) as **separate** jsonb
        fields (C-c0-7).  A preview_text over 64 KiB is rejected
        (400 or 413), never truncated.

    POST /api/v1/sync/escalations/{escalation_id}/approvals  (M4)
        The three payload fields ``script_rel``, ``script_sha256``
        and ``preview_sha256`` must equal the stored escalation;
        mismatch -> 400.

    GET  /api/v1/sync/escalations  (list)
    GET  /api/v1/sync/escalations/{escalation_id}  (detail)
        Both carry the ``script`` and ``script_preview`` fields.

RED tests xfail on ``M2T12cPending``.  Guards verify existing
schema/routes.

Sentinel name: M2T12cPending (local, not from ee/tests/m2_pending.py,
because this is a per-task sentinel for T12c).
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

from .m2_sync_server import (
    make_sync_server, ensure_at_head, create_org, create_project,
    keygen, sign_envelope, canonical_json,
)
from .t9_helpers import seed_session, make_session_cookie, compute_csrf
from .fake_idp import FakeClock


# ---------------------------------------------------------------------------
# Sentinel
# ---------------------------------------------------------------------------

class M2T12cPending(Exception):
    """Script content binding (T12c) server features not yet implemented."""


# ---------------------------------------------------------------------------
# Helpers (copied from test_m2_t12b_server.py, kept minimal)
# ---------------------------------------------------------------------------


def _conninfo(url: str) -> str:
    return url.replace("+psycopg", "")


def _seed_user_row(conn, org_id: str, email: str) -> str:
    user_id = str(uuid.uuid4())
    conn.execute(
        "INSERT INTO users (id, org_id, oidc_issuer, oidc_subject, email, "
        "status, created_at) VALUES (%s, %s, 'https://idp', %s, %s, "
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


def _seed_registry_with_keys(owner_url: str, org_id: str,
                             key_entries: list[dict]) -> int:
    conninfo = _conninfo(owner_url)
    with psycopg.connect(conninfo) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        conn.execute(
            "INSERT INTO key_registry_versions "
            "(id, org_id, version, payload, signature, created_at) "
            "VALUES (%s, %s, 1, %s, 'placeholder', now()) "
            "ON CONFLICT DO NOTHING",
            [str(uuid.uuid4()), org_id, json.dumps({"keys": key_entries})],
        )
        for entry in key_entries:
            conn.execute(
                "INSERT INTO approver_keys "
                "(id, org_id, user_id, key_id, public_key, kind, roles, "
                "registry_version, created_at) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s, 1, now()) "
                "ON CONFLICT DO NOTHING",
                [str(uuid.uuid4()), org_id, entry["user_id"],
                 entry["key_id"], entry["public_key"], entry["kind"],
                 json.dumps(entry.get("roles", ["approver"]))],
            )
        conn.commit()
    return 1


def _upload_escalation(base_url: str, device_id: str, token: str,
                       request_id: str, *, command: str = "echo test",
                       policy_sequence: int = 1,
                       fingerprint: str | None = None,
                       record_extra: dict | None = None) -> tuple[int, str | None]:
    """Upload an escalation via device token.  Return (status, escalation_id)."""
    import httpx
    record: dict = {"command": command, "status": "pending"}
    if fingerprint is None:
        fingerprint = hashlib.sha256(command.encode()).hexdigest()
    record["fingerprint"] = fingerprint
    if record_extra:
        record.update(record_extra)
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
    extra_payload: dict | None = None,
) -> dict:
    """Build an agg/remote-approval/v1 envelope."""
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
    if extra_payload:
        payload.update(extra_payload)
    return sign_envelope("agg/remote-approval/v1", payload, sk)


def _need_t12c_server(srv: dict) -> None:
    """Behavioural gate: raise M2T12cPending if the server does not store
    and return the script and script_preview fields.

    Probe: upload an escalation carrying script and script_preview via the
    real server, GET it by id, and check that the response carries the
    script fields with the uploaded sha256.  If pg is unavailable the pg
    skip happens before this gate is reached (the fixture skips).
    """
    import httpx

    device_id, token = _seed_test_connector(srv)
    probe_sha = hashlib.sha256(b"# probe\n").hexdigest()
    probe_preview_sha = hashlib.sha256("# probe\n".encode()).hexdigest()
    probe_req_id = f"probe-t12c-{uuid.uuid4().hex[:8]}"

    status, esc_id = _upload_escalation(
        srv["base_url"], device_id, token, probe_req_id,
        command="python probe.py",
        record_extra={
            "script": {"rel": "probe.py", "sha256": probe_sha, "size": 8},
            "script_preview": {"text": "# probe\n", "sha256": probe_preview_sha},
        },
    )
    if status != 200 or not esc_id:
        raise M2T12cPending(
            f"upload with script fields failed: status={status}"
        )

    cookie, csrf = _make_fresh_session(
        srv["owner_url"], srv["org_id"], srv["bob_id"],
    )
    r = httpx.get(
        f"{srv['base_url']}/api/v1/sync/escalations/{esc_id}",
        cookies={"__Host-agg_session": cookie},
        timeout=10.0,
    )
    if r.status_code != 200:
        raise M2T12cPending(
            f"GET escalation detail returned {r.status_code}"
        )
    data = r.json()
    script = data.get("script")
    if not isinstance(script, dict) or script.get("sha256") != probe_sha:
        raise M2T12cPending(
            f"GET detail does not carry script.sha256={probe_sha!r}; "
            f"got script={script!r}"
        )


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def t12c_server(pg_url, app_url, owner_url, pg_roles):
    """4-worker agg_cp server for T12c server tests."""
    gen = make_sync_server(
        pg_url, app_url, owner_url,
        org_names=["T12c Org"],
    )
    info = next(gen)

    conninfo = _conninfo(owner_url)
    with psycopg.connect(conninfo, autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [info["org_id"]])
        bob_id = _seed_user_row(conn, info["org_id"], "bob@t12c.test")
        carol_id = _seed_user_row(conn, info["org_id"], "carol@t12c.test")

    info["bob_id"] = bob_id
    info["carol_id"] = carol_id

    try:
        yield info
    finally:
        gen.close()


def _seed_test_connector(srv) -> tuple[str, str]:
    """Create connector + device token for testing.  Returns (device_id, token)."""
    sk, pub, kid = keygen()
    project_id = str(uuid.uuid4())
    conninfo = _conninfo(srv["owner_url"])
    with psycopg.connect(conninfo, autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [srv["org_id"]])
        create_project(conn, srv["org_id"], project_id, environment="staging")
    device_id = _seed_connector(srv["owner_url"], srv["org_id"],
                                project_id, pub)
    token = secrets.token_hex(32)
    _seed_device_token(srv["owner_url"], srv["org_id"], project_id,
                       device_id, token)
    return device_id, token


# ===================================================================
# Guards (pass today)
# ===================================================================


@pytest.mark.pg
def test_guard_escalation_upload_still_works(t12c_server):
    """Guard: the escalation upload route still accepts records."""
    srv = t12c_server
    device_id, token = _seed_test_connector(srv)
    status, esc_id = _upload_escalation(
        srv["base_url"], device_id, token, f"guard-{uuid.uuid4().hex[:8]}",
    )
    assert status == 200
    assert esc_id is not None


# ===================================================================
# RED: Extra test 9 -- script fields
# ===================================================================

# 9a: mismatched script_rel/script_sha256/preview_sha256 gives 400

@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M2T12cPending)
def test_mismatched_script_rel_gives_400(t12c_server):
    """An approval whose script_rel does not match the stored escalation
    gets 400."""
    _need_t12c_server(t12c_server)

    srv = t12c_server
    bob_sk, bob_pub, bob_kid = keygen()
    device_id, token = _seed_test_connector(srv)

    script_sha = hashlib.sha256(b"print('hello')\n").hexdigest()
    preview_sha = hashlib.sha256("print('hello')\n".encode()).hexdigest()

    status, esc_id = _upload_escalation(
        srv["base_url"], device_id, token,
        f"req-mismatch-rel-{uuid.uuid4().hex[:8]}",
        command="python test.py",
        record_extra={
            "script": {"rel": "test.py", "sha256": script_sha, "size": 16},
            "script_preview": {"text": "print('hello')\n", "sha256": preview_sha},
        },
    )
    assert status == 200 and esc_id

    # Register bob as an approver
    _seed_registry_with_keys(srv["owner_url"], srv["org_id"], [{
        "user_id": srv["bob_id"], "key_id": bob_kid,
        "public_key": bob_pub.hex(), "kind": "cli",
        "roles": ["approver"],
    }])

    cookie, csrf = _make_fresh_session(
        srv["owner_url"], srv["org_id"], srv["bob_id"],
    )

    # Mismatched script_rel in approval payload
    import httpx
    envelope = _make_remote_approval_envelope(
        bob_sk,
        request_id=f"req-mismatch-rel-{uuid.uuid4().hex[:8]}",
        command="python test.py",
        org_id=srv["org_id"],
        project_id=str(uuid.uuid4()),
        device_id=device_id,
        user_id=srv["bob_id"],
        extra_payload={
            "script_rel": "WRONG.py",
            "script_sha256": script_sha,
            "preview_sha256": preview_sha,
        },
    )
    r = httpx.post(
        f"{srv['base_url']}/api/v1/sync/escalations/{esc_id}/approvals",
        json=envelope,
        cookies={"__Host-agg_session": cookie},
        headers={"X-CSRF-Token": csrf},
        timeout=10.0,
    )
    assert r.status_code == 400, (
        f"mismatched script_rel should give 400, got {r.status_code}"
    )


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M2T12cPending)
def test_mismatched_script_sha256_gives_400(t12c_server):
    """An approval whose script_sha256 does not match gives 400."""
    _need_t12c_server(t12c_server)

    srv = t12c_server
    bob_sk, bob_pub, bob_kid = keygen()
    device_id, token = _seed_test_connector(srv)

    script_sha = hashlib.sha256(b"print('hello')\n").hexdigest()
    preview_sha = hashlib.sha256("print('hello')\n".encode()).hexdigest()

    status, esc_id = _upload_escalation(
        srv["base_url"], device_id, token,
        f"req-mismatch-sha-{uuid.uuid4().hex[:8]}",
        command="python test.py",
        record_extra={
            "script": {"rel": "test.py", "sha256": script_sha, "size": 16},
            "script_preview": {"text": "print('hello')\n", "sha256": preview_sha},
        },
    )
    assert status == 200 and esc_id

    _seed_registry_with_keys(srv["owner_url"], srv["org_id"], [{
        "user_id": srv["bob_id"], "key_id": bob_kid,
        "public_key": bob_pub.hex(), "kind": "cli",
        "roles": ["approver"],
    }])

    cookie, csrf = _make_fresh_session(
        srv["owner_url"], srv["org_id"], srv["bob_id"],
    )

    import httpx
    envelope = _make_remote_approval_envelope(
        bob_sk,
        request_id=f"req-mismatch-sha-{uuid.uuid4().hex[:8]}",
        command="python test.py",
        org_id=srv["org_id"],
        project_id=str(uuid.uuid4()),
        device_id=device_id,
        user_id=srv["bob_id"],
        extra_payload={
            "script_rel": "test.py",
            "script_sha256": "a" * 64,  # wrong hash
            "preview_sha256": preview_sha,
        },
    )
    r = httpx.post(
        f"{srv['base_url']}/api/v1/sync/escalations/{esc_id}/approvals",
        json=envelope,
        cookies={"__Host-agg_session": cookie},
        headers={"X-CSRF-Token": csrf},
        timeout=10.0,
    )
    assert r.status_code == 400, (
        f"mismatched script_sha256 should give 400, got {r.status_code}"
    )


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M2T12cPending)
def test_mismatched_preview_sha256_gives_400(t12c_server):
    """An approval whose preview_sha256 does not match gives 400."""
    _need_t12c_server(t12c_server)

    srv = t12c_server
    bob_sk, bob_pub, bob_kid = keygen()
    device_id, token = _seed_test_connector(srv)

    script_sha = hashlib.sha256(b"print('hello')\n").hexdigest()
    preview_sha = hashlib.sha256("print('hello')\n".encode()).hexdigest()

    status, esc_id = _upload_escalation(
        srv["base_url"], device_id, token,
        f"req-mismatch-psha-{uuid.uuid4().hex[:8]}",
        command="python test.py",
        record_extra={
            "script": {"rel": "test.py", "sha256": script_sha, "size": 16},
            "script_preview": {"text": "print('hello')\n", "sha256": preview_sha},
        },
    )
    assert status == 200 and esc_id

    _seed_registry_with_keys(srv["owner_url"], srv["org_id"], [{
        "user_id": srv["bob_id"], "key_id": bob_kid,
        "public_key": bob_pub.hex(), "kind": "cli",
        "roles": ["approver"],
    }])

    cookie, csrf = _make_fresh_session(
        srv["owner_url"], srv["org_id"], srv["bob_id"],
    )

    import httpx
    envelope = _make_remote_approval_envelope(
        bob_sk,
        request_id=f"req-mismatch-psha-{uuid.uuid4().hex[:8]}",
        command="python test.py",
        org_id=srv["org_id"],
        project_id=str(uuid.uuid4()),
        device_id=device_id,
        user_id=srv["bob_id"],
        extra_payload={
            "script_rel": "test.py",
            "script_sha256": script_sha,
            "preview_sha256": "b" * 64,  # wrong hash
        },
    )
    r = httpx.post(
        f"{srv['base_url']}/api/v1/sync/escalations/{esc_id}/approvals",
        json=envelope,
        cookies={"__Host-agg_session": cookie},
        headers={"X-CSRF-Token": csrf},
        timeout=10.0,
    )
    assert r.status_code == 400, (
        f"mismatched preview_sha256 should give 400, got {r.status_code}"
    )


# 9b: 64 KiB + 1 preview rejected, not truncated

@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M2T12cPending)
def test_oversized_preview_rejected_not_truncated(t12c_server):
    """A preview text over 64 KiB is rejected (400 or 413), never truncated
    (C-c0-7)."""
    _need_t12c_server(t12c_server)

    srv = t12c_server
    device_id, token = _seed_test_connector(srv)

    oversized_text = "x" * (64 * 1024 + 1)
    preview_sha = hashlib.sha256(oversized_text.encode()).hexdigest()
    script_sha = hashlib.sha256(b"x" * (64 * 1024 + 1)).hexdigest()

    status, esc_id = _upload_escalation(
        srv["base_url"], device_id, token,
        f"req-oversize-{uuid.uuid4().hex[:8]}",
        command="python big.py",
        record_extra={
            "script": {"rel": "big.py", "sha256": script_sha, "size": 64 * 1024 + 1},
            "script_preview": {"text": oversized_text, "sha256": preview_sha},
        },
    )
    # Must be rejected, not stored
    assert status in (400, 413), (
        f"oversized preview should be rejected (400 or 413), got {status}"
    )


# 9c: script and script_preview stored as separate jsonb

@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M2T12cPending)
def test_script_fields_stored_separately(t12c_server):
    """The server stores ``script`` and ``script_preview`` as separate jsonb
    fields, not merged."""
    _need_t12c_server(t12c_server)

    srv = t12c_server
    device_id, token = _seed_test_connector(srv)

    body = "print('separate')\n"
    script_sha = hashlib.sha256(body.encode()).hexdigest()
    preview_sha = hashlib.sha256(body.encode()).hexdigest()

    status, esc_id = _upload_escalation(
        srv["base_url"], device_id, token,
        f"req-separate-{uuid.uuid4().hex[:8]}",
        command="python sep.py",
        record_extra={
            "script": {"rel": "sep.py", "sha256": script_sha, "size": len(body)},
            "script_preview": {"text": body, "sha256": preview_sha},
        },
    )
    assert status == 200 and esc_id, (
        f"upload failed: status={status}"
    )

    # Check the raw database row
    conninfo = _conninfo(srv["owner_url"])
    with psycopg.connect(conninfo) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [srv["org_id"]])
        row = conn.execute(
            "SELECT script, script_preview FROM escalations WHERE id = %s",
            [esc_id],
        ).fetchone()

    assert row is not None, "escalation row not found"
    script_col, preview_col = row

    # Both should be non-null and distinct jsonb values
    assert script_col is not None, "script column should be stored"
    assert preview_col is not None, "script_preview column should be stored"

    # Parse them
    if isinstance(script_col, str):
        script_col = json.loads(script_col)
    if isinstance(preview_col, str):
        preview_col = json.loads(preview_col)

    assert "rel" in script_col, "script should have rel field"
    assert "sha256" in script_col, "script should have sha256 field"
    assert "text" in preview_col, "script_preview should have text field"
    assert "sha256" in preview_col, "script_preview should have sha256 field"


# 9d: GET list and GET-by-id carry the fields

@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M2T12cPending)
def test_get_list_carries_script_fields(t12c_server):
    """GET /api/v1/sync/escalations list carries script and script_preview."""
    _need_t12c_server(t12c_server)

    srv = t12c_server
    device_id, token = _seed_test_connector(srv)

    body = "print('list-test')\n"
    script_sha = hashlib.sha256(body.encode()).hexdigest()
    preview_sha = hashlib.sha256(body.encode()).hexdigest()

    status, esc_id = _upload_escalation(
        srv["base_url"], device_id, token,
        f"req-list-{uuid.uuid4().hex[:8]}",
        command="python list.py",
        record_extra={
            "script": {"rel": "list.py", "sha256": script_sha, "size": len(body)},
            "script_preview": {"text": body, "sha256": preview_sha},
        },
    )
    assert status == 200 and esc_id

    cookie, csrf = _make_fresh_session(
        srv["owner_url"], srv["org_id"], srv["bob_id"],
    )

    import httpx
    r = httpx.get(
        f"{srv['base_url']}/api/v1/sync/escalations",
        cookies={"__Host-agg_session": cookie},
        timeout=10.0,
    )
    assert r.status_code == 200
    items = r.json()
    if isinstance(items, dict):
        items = items.get("escalations", items.get("items", []))

    matched = [e for e in items if e.get("escalation_id") == esc_id
               or e.get("id") == esc_id]
    assert matched, f"escalation {esc_id} not found in list"
    esc = matched[0]
    assert "script" in esc, "GET list should carry script field"
    assert "script_preview" in esc, "GET list should carry script_preview field"


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M2T12cPending)
def test_get_detail_carries_script_fields(t12c_server):
    """GET /api/v1/sync/escalations/{id} carries script and script_preview."""
    _need_t12c_server(t12c_server)

    srv = t12c_server
    device_id, token = _seed_test_connector(srv)

    body = "print('detail-test')\n"
    script_sha = hashlib.sha256(body.encode()).hexdigest()
    preview_sha = hashlib.sha256(body.encode()).hexdigest()

    status, esc_id = _upload_escalation(
        srv["base_url"], device_id, token,
        f"req-detail-{uuid.uuid4().hex[:8]}",
        command="python detail.py",
        record_extra={
            "script": {"rel": "detail.py", "sha256": script_sha, "size": len(body)},
            "script_preview": {"text": body, "sha256": preview_sha},
        },
    )
    assert status == 200 and esc_id

    cookie, csrf = _make_fresh_session(
        srv["owner_url"], srv["org_id"], srv["bob_id"],
    )

    import httpx
    r = httpx.get(
        f"{srv['base_url']}/api/v1/sync/escalations/{esc_id}",
        cookies={"__Host-agg_session": cookie},
        timeout=10.0,
    )
    assert r.status_code == 200
    data = r.json()
    assert "script" in data, "GET detail should carry script field"
    assert "script_preview" in data, "GET detail should carry script_preview field"
    assert data["script"]["rel"] == "detail.py"
    assert data["script"]["sha256"] == script_sha
    assert data["script_preview"]["sha256"] == preview_sha
