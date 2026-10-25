"""T12b-2 security review proof tests (security-engineer, 24 Oct 2026).

Each test is a strict xfail that proves an open finding against the
uncommitted T12b-2 build. When the fix lands, the test XPASSes and the
strict marker fails the run: remove the marker then.

R1 (M4 binding, R1c): an escalation row with no stored fingerprint skips the
    fingerprint binding, so an approval with any fingerprint is accepted.
    A missing fingerprint must be refused.
R2 (C5, ADR 0010 s6): the operator self-approval exception reads
    ``allow_requester`` from the escalation ``record`` JSONB, which the DEVICE
    uploads. A device sets it and its operator self-approves. It must come
    from the server's latest signed bundle for the project, never device data.
"""
from __future__ import annotations

import secrets
import uuid

import httpx
import psycopg
import pytest

from .m2_sync_server import create_project, keygen
from .test_m2_t12b_server import (  # noqa: F401 -- t12b_server is a fixture
    _conninfo, _make_fresh_session, _make_remote_approval_envelope,
    _seed_connector, _seed_device_token, _seed_registry_with_keys,
    _upload_escalation, t12b_server,
)


def _setup(srv, *, operator: bool):
    sk, pub, kid = keygen()
    _dsk, dpub, _dkid = keygen()
    project_id = str(uuid.uuid4())
    with psycopg.connect(_conninfo(srv["owner_url"])) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [srv["org_id"]])
        create_project(conn, srv["org_id"], project_id, environment="staging")
        conn.commit()
    approver = srv["operator_id"] if operator else srv["bob_id"]
    _seed_registry_with_keys(srv["owner_url"], srv["org_id"], [
        {"key_id": kid, "public_key": pub.hex(), "user_id": approver,
         "kind": "cli", "roles": ["approver"]},
    ])
    device_id = _seed_connector(
        srv["owner_url"], srv["org_id"], project_id, dpub,
        operator_user_id=srv["operator_id"],
    )
    token = secrets.token_hex(32)
    _seed_device_token(srv["owner_url"], srv["org_id"], project_id,
                       device_id, token)
    return sk, approver, project_id, device_id, token


def _post(srv, esc_id, envelope, user_id):
    cookie, csrf = _make_fresh_session(srv["owner_url"], srv["org_id"], user_id)
    return httpx.post(
        f"{srv['base_url']}/api/v1/sync/escalations/{esc_id}/approvals",
        json=envelope, cookies={"__Host-agg_session": cookie},
        headers={"X-CSRF-Token": csrf}, timeout=10.0,
    )


@pytest.mark.pg
def test_r1_missing_stored_fingerprint_refused(t12b_server):
    srv = t12b_server
    sk, approver, project_id, device_id, token = _setup(srv, operator=False)
    rid = "req-review-nofp-1"
    # Insert escalation directly into DB without a fingerprint (bypasses
    # the upload route's item-6 record validation, which now requires
    # fingerprint). This tests the approval route's R1 defense-in-depth
    # for escalations stored before the validation was added.
    esc_id = str(uuid.uuid4())
    with psycopg.connect(_conninfo(srv["owner_url"])) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [srv["org_id"]])
        conn.execute(
            "INSERT INTO escalations "
            "(id, org_id, project_id, connector_id, "
            "request_id, record, risk, requires_dual, "
            "status, policy_sequence, created_at) "
            "VALUES (%s::uuid, %s::uuid, %s::uuid, %s::uuid, "
            "%s, %s::jsonb, %s, %s, %s, %s, now())",
            [esc_id, srv["org_id"], project_id, device_id,
             rid, '{"command": "echo test", "status": "pending"}',
             "", False, "pending", 1],
        )
        conn.commit()
    env = _make_remote_approval_envelope(
        sk, request_id=rid, org_id=srv["org_id"], project_id=project_id,
        device_id=device_id, user_id=approver, fingerprint="f" * 64,
    )
    r = _post(srv, esc_id, env, approver)
    assert r.status_code in (400, 403), f"accepted unbound: {r.status_code} {r.text}"


@pytest.mark.pg
def test_r2_device_record_allow_requester_ignored(t12b_server):
    srv = t12b_server
    sk, operator, project_id, device_id, token = _setup(srv, operator=True)
    rid = "req-review-allowreq-1"
    fp = "a" * 64
    r = httpx.post(
        f"{srv['base_url']}/api/v1/sync/escalations",
        json={"device_id": device_id, "request_id": rid, "policy_sequence": 1,
              "record": {"command": "echo test", "status": "pending",
                         "fingerprint": fp, "allow_requester": True}},
        headers={"Authorization": f"Bearer {token}"}, timeout=10.0,
    )
    assert r.status_code == 200
    esc_id = r.json()["escalation_id"]
    env = _make_remote_approval_envelope(
        sk, request_id=rid, org_id=srv["org_id"], project_id=project_id,
        device_id=device_id, user_id=operator, fingerprint=fp,
    )
    r = _post(srv, esc_id, env, operator)
    assert r.status_code in (400, 403), (
        f"operator self-approved via device-set allow_requester: "
        f"{r.status_code} {r.text}"
    )
