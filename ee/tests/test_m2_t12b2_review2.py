"""T12b-2 security review round 2 (security-engineer, leader tier, 25 Oct 2026).

Each strict xfail is an open finding: it asserts the safe behaviour and
raises ``T12b2Finding`` while the unsafe behaviour is present.  Any other
error (setup, 500) does not match ``raises=`` and fails the run, so the
markers cannot pass vacuously.  When the fix lands the test XPASSes and the
strict marker fails the run: remove the marker in the fixing change.
Plain tests (no marker) are guards that must stay green.

S1 (Medium, C9 item 8, WYSIWYS): the approver is never shown exec_cwd or
   root, yet the binding fingerprint covers both.  GET detail and the web
   list omit them (the upload stores them in ``record``), the CLI signer no
   longer prints them (T12b-1 did), the inbox columns are always blank.
S4 (Low, M4): the approvals route accepts a key whose approver_keys row is
   revoked (``revoked_at`` set).  The connector refuses it (latest registry),
   so nothing runs, but the server stores and serves it.
S5 (Low, C9 item 3): the upload route checks record.command and
   record.fingerprint by truthiness only; a non-string command (an object)
   is stored and later served to the web inbox, where
   ``renderEscalationText`` calls ``.replace`` on it and the inbox crashes
   for the whole org.
Guards: R1 with the old ``sha256(command)`` fallback value (the existing R1
   proof uses "f"*64, which a fallback would also refuse); R2 NULL operator.
"""
from __future__ import annotations

import hashlib
import secrets
import uuid

import httpx
import psycopg
import pytest

from .m2_sync_server import create_project, keygen
from .test_m2_t12b_server import (  # noqa: F401 -- t12b_server is a fixture
    _conninfo, _make_fresh_session, _make_remote_approval_envelope,
    _seed_connector, _seed_device_token, _seed_registry_with_keys,
    t12b_server,
)


class T12b2Finding(AssertionError):
    """Raised while an open T12b-2 review finding is still exploitable."""


def _setup(srv, *, operator: bool = True):
    sk, pub, kid = keygen()
    _dsk, dpub, _dkid = keygen()
    project_id = str(uuid.uuid4())
    with psycopg.connect(_conninfo(srv["owner_url"])) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [srv["org_id"]])
        create_project(conn, srv["org_id"], project_id, environment="staging")
        conn.commit()
    _seed_registry_with_keys(srv["owner_url"], srv["org_id"], [
        {"key_id": kid, "public_key": pub.hex(), "user_id": srv["bob_id"],
         "kind": "cli", "roles": ["approver"]},
    ])
    device_id = _seed_connector(
        srv["owner_url"], srv["org_id"], project_id, dpub,
        operator_user_id=srv["operator_id"] if operator else None,
    )
    token = secrets.token_hex(32)
    _seed_device_token(srv["owner_url"], srv["org_id"], project_id,
                       device_id, token)
    return sk, kid, project_id, device_id, token


def _upload(srv, token, device_id, rid, record):
    return httpx.post(
        f"{srv['base_url']}/api/v1/sync/escalations",
        json={"device_id": device_id, "request_id": rid,
              "policy_sequence": 1, "record": record},
        headers={"Authorization": f"Bearer {token}"}, timeout=10.0,
    )


def _post(srv, esc_id, envelope, user_id):
    cookie, csrf = _make_fresh_session(srv["owner_url"], srv["org_id"], user_id)
    return httpx.post(
        f"{srv['base_url']}/api/v1/sync/escalations/{esc_id}/approvals",
        json=envelope, cookies={"__Host-agg_session": cookie},
        headers={"X-CSRF-Token": csrf}, timeout=10.0,
    )


def _insert_escalation_without_fingerprint(srv, project_id, device_id, rid):
    esc_id = str(uuid.uuid4())
    with psycopg.connect(_conninfo(srv["owner_url"])) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [srv["org_id"]])
        conn.execute(
            "INSERT INTO escalations "
            "(id, org_id, project_id, connector_id, request_id, record, "
            "risk, requires_dual, status, policy_sequence, created_at) "
            "VALUES (%s::uuid, %s::uuid, %s::uuid, %s::uuid, %s, %s::jsonb, "
            "'', false, 'pending', 1, now())",
            [esc_id, srv["org_id"], project_id, device_id, rid,
             '{"command": "echo test", "status": "pending"}'],
        )
        conn.commit()
    return esc_id


_CWD = "/srv/other-repo"
_ROOT = "/srv/other-repo"


def _record_with_location():
    return {"command": "git push --force", "status": "pending",
            "fingerprint": "c" * 64, "exec_cwd": _CWD, "root": _ROOT,
            "requires_dual": True}


# ---------------------------------------------------------------------------
# S1: the approver never sees exec_cwd or root
# ---------------------------------------------------------------------------

@pytest.mark.pg
def test_s1_detail_shows_exec_cwd_and_root(t12b_server):
    srv = t12b_server
    _sk, _kid, _pid, device_id, token = _setup(srv)
    r = _upload(srv, token, device_id, "req-s1-detail-1", _record_with_location())
    assert r.status_code == 200, r.text
    esc_id = r.json()["escalation_id"]
    cookie, _csrf = _make_fresh_session(srv["owner_url"], srv["org_id"],
                                        srv["bob_id"])
    d = httpx.get(f"{srv['base_url']}/api/v1/sync/escalations/{esc_id}",
                  cookies={"__Host-agg_session": cookie}, timeout=10.0)
    assert d.status_code == 200, d.text
    body = d.json()
    if body.get("exec_cwd") != _CWD or body.get("root") != _ROOT:
        raise T12b2Finding(
            "GET detail omits exec_cwd/root; the signer signs a fingerprint "
            f"over a location it never displayed: {sorted(body)}")


@pytest.mark.pg
def test_s1_web_list_shows_exec_cwd_and_root(t12b_server):
    srv = t12b_server
    _sk, _kid, _pid, device_id, token = _setup(srv)
    r = _upload(srv, token, device_id, "req-s1-list-1", _record_with_location())
    assert r.status_code == 200, r.text
    esc_id = r.json()["escalation_id"]
    cookie, _csrf = _make_fresh_session(srv["owner_url"], srv["org_id"],
                                        srv["bob_id"])
    lst = httpx.get(f"{srv['base_url']}/api/v1/escalations",
                    cookies={"__Host-agg_session": cookie}, timeout=10.0)
    assert lst.status_code == 200, lst.text
    items = [e for e in lst.json()["escalations"] if e["escalation_id"] == esc_id]
    assert len(items) == 1, lst.text
    if items[0].get("exec_cwd") != _CWD or items[0].get("root") != _ROOT:
        raise T12b2Finding(
            "GET /api/v1/escalations omits exec_cwd/root; the inbox CWD and "
            "Root columns are always blank")


# ---------------------------------------------------------------------------
# S4: a revoked approver key still approves on the server
# ---------------------------------------------------------------------------

@pytest.mark.pg
def test_s4_revoked_approver_key_refused(t12b_server):
    srv = t12b_server
    sk, kid, project_id, device_id, token = _setup(srv)
    rid = "req-s4-revoked-1"
    fp = hashlib.sha256(b"echo test").hexdigest()
    r = _upload(srv, token, device_id, rid,
                {"command": "echo test", "status": "pending", "fingerprint": fp})
    assert r.status_code == 200, r.text
    esc_id = r.json()["escalation_id"]
    with psycopg.connect(_conninfo(srv["owner_url"])) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [srv["org_id"]])
        conn.execute("UPDATE approver_keys SET revoked_at = now() "
                     "WHERE org_id = %s AND key_id = %s", [srv["org_id"], kid])
        conn.commit()
    env = _make_remote_approval_envelope(
        sk, request_id=rid, org_id=srv["org_id"], project_id=project_id,
        device_id=device_id, user_id=srv["bob_id"], fingerprint=fp,
    )
    resp = _post(srv, esc_id, env, srv["bob_id"])
    assert resp.status_code != 500, resp.text
    if resp.status_code == 200:
        raise T12b2Finding("approval signed by a revoked approver key was stored")


# ---------------------------------------------------------------------------
# S5: a non-string command is stored and served to the inbox
# ---------------------------------------------------------------------------

@pytest.mark.pg
def test_s5_non_string_command_refused(t12b_server):
    srv = t12b_server
    _sk, _kid, _pid, device_id, token = _setup(srv)
    r = _upload(srv, token, device_id, "req-s5-objcmd-1",
                {"command": {"toString": 1}, "status": "pending",
                 "fingerprint": "d" * 64})
    assert r.status_code != 500, r.text
    if r.status_code == 200:
        raise T12b2Finding(
            "upload stored a non-string record.command; the web inbox calls "
            ".replace on it and crashes for the whole org")


# ---------------------------------------------------------------------------
# Guards (must stay green)
# ---------------------------------------------------------------------------

@pytest.mark.pg
def test_guard_r1_no_sha256_command_fallback(t12b_server):
    """R1: a missing stored fingerprint is refused even when the payload
    carries sha256(command), the value the removed fallback would compute."""
    srv = t12b_server
    sk, _kid, project_id, device_id, _token = _setup(srv)
    rid = "req-guard-r1-1"
    esc_id = _insert_escalation_without_fingerprint(srv, project_id, device_id, rid)
    env = _make_remote_approval_envelope(
        sk, request_id=rid, org_id=srv["org_id"], project_id=project_id,
        device_id=device_id, user_id=srv["bob_id"],
        fingerprint=hashlib.sha256(b"echo test").hexdigest(),
    )
    r = _post(srv, esc_id, env, srv["bob_id"])
    assert r.status_code == 400, r.text
    assert "fingerprint missing" in r.json().get("error", ""), r.text


@pytest.mark.pg
def test_guard_r2_null_operator_refused(t12b_server):
    """R2: a connector with NULL operator_user_id gets no stored approvals."""
    srv = t12b_server
    sk, _kid, project_id, device_id, token = _setup(srv, operator=False)
    rid = "req-guard-r2-1"
    fp = hashlib.sha256(b"echo test").hexdigest()
    r = _upload(srv, token, device_id, rid,
                {"command": "echo test", "status": "pending", "fingerprint": fp})
    assert r.status_code == 200, r.text
    env = _make_remote_approval_envelope(
        sk, request_id=rid, org_id=srv["org_id"], project_id=project_id,
        device_id=device_id, user_id=srv["bob_id"], fingerprint=fp,
    )
    resp = _post(srv, r.json()["escalation_id"], env, srv["bob_id"])
    assert resp.status_code == 403, resp.text
    assert "operator unknown" in resp.json().get("error", ""), resp.text
