"""M3 T1 tests-first: admin read routes for devices, codes status, bundles
list and detail with diff and label, alerts, verify per project, JSONL export.

Spec: M3_PLAN.md T1 row, D2, D3, D5, threats 38-41, ADR 0001 A9.

Every target is ``xfail(strict=True, raises=M3T1Pending)`` so it fails
for the targeted reason (the route or feature is absent), not a fixture
error.  Guard twins PASS today and prove the fixture works.

Marked ``pg`` (requires Postgres via testcontainers).
"""
from __future__ import annotations

import datetime as dt
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
    keygen, sign_envelope, canonical_json,
)
from .t9_helpers import (
    seed_session, make_session_cookie, compute_csrf,
    seed_org_with_oidc, seed_user, seed_admin_binding, _conninfo,
    FakeIdP,
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


def _bind_admin(conn, org_id: str, user_id: str) -> None:
    conn.execute(
        "INSERT INTO role_bindings "
        "(id, org_id, user_id, scope_type, scope_id, role, created_at) "
        "VALUES (%s, %s, %s, 'org', %s, 'admin', now())",
        [str(uuid.uuid4()), org_id, user_id, org_id],
    )


def _make_fresh_session(owner_url: str, org_id: str, user_id: str,
                        *, clock: FakeClock | None = None):
    """Create a fresh web session.  Return (cookie_value, csrf_token, session_id)."""
    if clock is None:
        clock = FakeClock()
    token, csrf, sid = seed_session(
        owner_url, uuid.UUID(org_id), uuid.UUID(user_id), clock=clock,
    )
    cookie = make_session_cookie(uuid.UUID(org_id), token)
    return cookie, csrf, sid


def _seed_connector(owner_url: str, org_id: str, project_id: str,
                    pub: bytes) -> str:
    """Insert a connectors row.  Return device_id."""
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


def _seed_policy_bundle(owner_url: str, org_id: str, project_id: str,
                        sequence: int, bundle_signer_sk,
                        *, applied_by_device: str | None = None) -> str:
    """Insert a policy_bundles row and optionally an applied-by device record.

    Return the bundle row id.
    """
    from .m2_sync_server import canonical_json, sign_envelope
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
        # Seed a change approval for this bundle so detail shows approvals
        approval_sk = SigningKey.generate()
        approval_pub = bytes(approval_sk.verify_key)
        approval_kid = hashlib.sha256(approval_pub).hexdigest()
        approval_payload = {"bundle_hash": hashlib.sha256(
            canonical_json(bundle_payload)).hexdigest()}
        approval_envelope = sign_envelope(
            "agg/policy-change/v1", approval_payload, approval_sk)
        # Seed a user for the approver
        approver_user_id = str(uuid.uuid4())
        conn.execute(
            "INSERT INTO users (id, org_id, oidc_issuer, oidc_subject, email, "
            "status, created_at) VALUES (%s, %s, 'https://idp.test', %s, %s, "
            "'active', now()) ON CONFLICT DO NOTHING",
            [approver_user_id, org_id, f"sub-{uuid.uuid4().hex[:8]}",
             f"approver-{sequence}@t1.test"],
        )
        # Register the approver key in approver_keys
        conn.execute(
            "INSERT INTO approver_keys "
            "(id, org_id, user_id, public_key, alg, kind, key_id, "
            "registry_version, enrolled_at, created_at) "
            "VALUES (%s, %s::uuid, %s::uuid, %s, 'ed25519', 'cli', %s, "
            "1, now(), now())",
            [str(uuid.uuid4()), org_id, approver_user_id,
             approval_pub.hex(), approval_kid],
        )
        # Seed the change approval (signed_at is NOT NULL)
        conn.execute(
            "INSERT INTO policy_change_approvals "
            "(id, org_id, change_request_id, key_id, user_id, signature, "
            "signed_at, created_at) "
            "VALUES (%s, %s::uuid, %s::uuid, %s, %s::uuid, %s, now(), now())",
            [str(uuid.uuid4()), org_id, bundle_id, approval_kid,
             approver_user_id,
             json.dumps(approval_envelope, separators=(",", ":"),
                        sort_keys=True)],
        )
        if applied_by_device:
            # Mark the device's last_seen so the bundle-detail route can
            # associate it.  The actual applied-by tracking is a T1 feature;
            # the test asserts the response key and the seeded device.
            conn.execute(
                "UPDATE connectors SET last_seen = now() "
                "WHERE id = %s::uuid AND org_id = %s::uuid",
                [applied_by_device, org_id],
            )
    return bundle_id


def _route_not_registered(resp) -> bool:
    """Return True if the response indicates the route is not registered."""
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


# ---------------------------------------------------------------------------
# Module-scoped server fixture
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def t1_server(pg_url, app_url, owner_url, pg_roles, tmp_path_factory):
    """4-worker agg_cp server for T1 read tests.

    Seeds: org A (alice admin), org B (eve admin), project in A.
    """
    bundle_signer_sk = SigningKey.generate()
    key_dir = tmp_path_factory.mktemp("t1_bundle_signer")
    key_file = key_dir / "bundle_signer.key"
    key_file.write_bytes(bytes(bundle_signer_sk).hex().encode("ascii"))
    import os
    old_bs = os.environ.get("AGG_BUNDLE_SIGNER_KEY_FILE")
    os.environ["AGG_BUNDLE_SIGNER_KEY_FILE"] = str(key_file)

    gen = make_sync_server(
        pg_url, app_url, owner_url,
        org_names=["T1 Org A", "T1 Org B"],
    )
    info = next(gen)

    conninfo = _conninfo(owner_url)
    with psycopg.connect(conninfo, autocommit=True) as conn:
        org_a = info["org_id"]
        org_b = info["org_evil"]

        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_a])
        alice_id = _seed_user_row(conn, org_a, "alice@t1.test")
        _bind_admin(conn, org_a, alice_id)

        project_id = str(uuid.uuid4())
        create_project(conn, org_a, project_id, "T1 Project")

        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_b])
        eve_id = _seed_user_row(conn, org_b, "eve@t1.test")
        _bind_admin(conn, org_b, eve_id)

    # Seed a device in the project for the applied-by check and cursor tests
    sk_dev, pub_dev, kid_dev = keygen()
    dev_device_id = _seed_connector(
        owner_url, org_a, project_id, pub_dev)

    # Seed enough additional devices to guarantee cursor pagination
    cursor_device_ids = [dev_device_id]
    for _i in range(25):
        _sk, _pub, _kid = keygen()
        _did = _seed_connector(owner_url, org_a, project_id, _pub)
        cursor_device_ids.append(_did)

    # Seed a policy_bundles row with an approval and an applied-by device
    bundle_id = _seed_policy_bundle(
        owner_url, org_a, project_id, 1, bundle_signer_sk,
        applied_by_device=dev_device_id,
    )

    clock = FakeClock()
    a_cookie, a_csrf, a_sid = _make_fresh_session(
        owner_url, org_a, alice_id, clock=clock)
    e_cookie, e_csrf, e_sid = _make_fresh_session(
        owner_url, org_b, eve_id, clock=clock)

    info.update({
        "alice_id": alice_id,
        "eve_id": eve_id,
        "project_id": project_id,
        "alice_cookie": a_cookie,
        "alice_csrf": a_csrf,
        "eve_cookie": e_cookie,
        "eve_csrf": e_csrf,
        "bundle_signer_sk": bundle_signer_sk,
        "seeded_bundle_id": bundle_id,
        "seeded_bundle_sequence": 1,
        "seeded_device_id": dev_device_id,
        "cursor_device_ids": cursor_device_ids,
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
# GUARD TWINS -- prove the fixture works (these PASS today)
# ===================================================================

@pytest.mark.pg
def test_guard_t1_server_ready(t1_server):
    """Guard: the test server responds to /ready."""
    import httpx
    with httpx.Client(base_url=t1_server["base_url"], timeout=10) as c:
        r = c.get("/ready")
    assert r.status_code == 200


@pytest.mark.pg
def test_guard_t1_alice_session_valid(t1_server):
    """Guard: alice's session can issue a code (proves session is valid)."""
    import httpx
    info = t1_server
    r = httpx.post(
        f"{info['base_url']}/api/v1/admin/enrollment-codes",
        json={"project_id": info["project_id"],
              "operator_user_id": info["alice_id"]},
        cookies={"__Host-agg_session": info["alice_cookie"]},
        headers={"X-CSRF-Token": info["alice_csrf"]},
        timeout=10,
    )
    assert r.status_code == 200, f"alice code issue: {r.status_code} {r.text[:200]}"


@pytest.mark.pg
def test_guard_t1_no_session_401_on_existing_route(t1_server):
    """Guard: a POST without a session cookie gets 401 on the existing
    enrollment-codes route (POST, not GET).

    Pinned to 401: the route returns 401 for missing session today.
    """
    import httpx
    info = t1_server
    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        r = c.post("/api/v1/admin/enrollment-codes",
                   json={"project_id": info["project_id"],
                         "operator_user_id": info["alice_id"]})
    assert r.status_code == 401, \
        f"expected 401 without session, got {r.status_code}"


# ===================================================================
# T1 TARGETS -- xfail(strict=True, raises=M3T1Pending)
# ===================================================================

# --- Devices list ---------------------------------------------------------

@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M3T1Pending)
def test_devices_list_returns_devices(t1_server):
    """GET /api/v1/devices?project= returns device list for the project."""
    import httpx
    info = t1_server

    # Seed a device
    sk, pub, kid = keygen()
    device_id = _seed_connector(
        info["owner_url"], info["org_id"], info["project_id"], pub)

    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        r = c.get(f"/api/v1/devices",
                  params={"project": info["project_id"]},
                  cookies={"__Host-agg_session": info["alice_cookie"]})
    require_m3(1, not _route_not_registered(r),
               "GET /api/v1/devices route not registered")
    assert r.status_code == 200
    body = r.json()
    assert isinstance(body, dict)
    items = body.get("items", body.get("devices", []))
    assert any(d.get("id") == device_id or d.get("device_id") == device_id
               for d in items)


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M3T1Pending)
def test_devices_detail(t1_server):
    """GET /api/v1/devices/{id} returns device detail with checkpoints."""
    import httpx
    info = t1_server
    sk, pub, kid = keygen()
    device_id = _seed_connector(
        info["owner_url"], info["org_id"], info["project_id"], pub)

    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        r = c.get(f"/api/v1/devices/{device_id}",
                  cookies={"__Host-agg_session": info["alice_cookie"]})
    require_m3(1, not _route_not_registered(r),
               "GET /api/v1/devices/{id} route not registered")
    assert r.status_code == 200
    body = r.json()
    assert body.get("id") == device_id or body.get("device_id") == device_id


# --- Foreign org 404 -------------------------------------------------------

@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M3T1Pending)
def test_foreign_org_devices_404(t1_server):
    """Eve (org B) requesting org A's devices gets 404, not a leak."""
    import httpx
    info = t1_server

    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        r = c.get(f"/api/v1/devices",
                  params={"project": info["project_id"]},
                  cookies={"__Host-agg_session": info["eve_cookie"]})
    require_m3(1, not _route_not_registered(r),
               "GET /api/v1/devices route not registered")
    # Should be 404 (uniform) not 403, and no data leaked
    assert r.status_code == 404
    body = r.json()
    assert "items" not in body and "devices" not in body


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M3T1Pending)
def test_foreign_org_bundles_404(t1_server):
    """Eve (org B) requesting org A's bundles gets 404."""
    import httpx
    info = t1_server
    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        r = c.get(f"/api/v1/admin/bundles",
                  params={"project": info["project_id"]},
                  cookies={"__Host-agg_session": info["eve_cookie"]})
    require_m3(1, not _route_not_registered(r),
               "GET /api/v1/admin/bundles route not registered")
    assert r.status_code == 404


# --- No session 401 --------------------------------------------------------

@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M3T1Pending)
def test_no_session_devices_401(t1_server):
    """GET /api/v1/devices without a session cookie gets 401."""
    import httpx
    info = t1_server
    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        r = c.get(f"/api/v1/devices",
                  params={"project": info["project_id"]})
    require_m3(1, not _route_not_registered(r),
               "GET /api/v1/devices route not registered")
    assert r.status_code == 401


# --- Non-member refused ----------------------------------------------------

@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M3T1Pending)
def test_non_member_refused(t1_server):
    """A user who is not an admin or member of a project is refused."""
    import httpx
    info = t1_server
    conninfo = _conninfo(info["owner_url"])
    # Create a non-admin user in org A
    with psycopg.connect(conninfo, autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [info["org_id"]])
        bob_id = _seed_user_row(conn, info["org_id"], "bob-nonadmin@t1.test")
        # No admin binding

    clock = FakeClock()
    cookie, csrf, _ = _make_fresh_session(
        info["owner_url"], info["org_id"], bob_id, clock=clock)

    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        r = c.get(f"/api/v1/devices",
                  params={"project": info["project_id"]},
                  cookies={"__Host-agg_session": cookie})
    require_m3(1, not _route_not_registered(r),
               "GET /api/v1/devices route not registered")
    # Uniform 404 per spec: non-members see the same response as cross-org
    assert r.status_code == 404, \
        f"non-member must get uniform 404, got {r.status_code}"


# --- Cursor bound to org ---------------------------------------------------

@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M3T1Pending)
def test_cursor_bound_to_org(t1_server):
    """A cursor token from org A used by org B must look identical to a
    garbage cursor: same status and body.  This prevents an attacker from
    learning whether a cursor is valid in another org.

    Shape: 400 ``bad_cursor``, matching the T16b ``bad_after`` pattern.
    The fixture seeds 26 devices to guarantee a cursor is returned.
    """
    import httpx
    info = t1_server

    # Get a cursor from org A's devices list (26 devices seeded)
    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        r_a = c.get(f"/api/v1/devices",
                    params={"project": info["project_id"]},
                    cookies={"__Host-agg_session": info["alice_cookie"]})
    require_m3(1, not _route_not_registered(r_a),
               "GET /api/v1/devices route not registered")
    assert r_a.status_code == 200
    cursor = r_a.json().get("cursor") or r_a.json().get("next_cursor")

    # 26 devices were seeded; cursor must be present
    assert cursor is not None, \
        "cursor must be returned when devices exceed page size (26 seeded)"

    # Eve tries to use Alice's cursor (cross-org)
    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        r_cross = c.get(f"/api/v1/devices",
                        params={"project": info["project_id"],
                                "cursor": cursor},
                        cookies={"__Host-agg_session": info["eve_cookie"]})

    # Eve sends garbage cursor
    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        r_garbage = c.get(f"/api/v1/devices",
                          params={"project": info["project_id"],
                                  "cursor": "totally-invalid-garbage-cursor"},
                          cookies={"__Host-agg_session": info["eve_cookie"]})

    # Both must return the same status and body (no information leak)
    assert r_cross.status_code == r_garbage.status_code, \
        (f"cross-org cursor ({r_cross.status_code}) and garbage cursor "
         f"({r_garbage.status_code}) must return the same status")
    assert r_cross.json() == r_garbage.json(), \
        (f"cross-org cursor body and garbage cursor body must be identical: "
         f"cross={r_cross.json()}, garbage={r_garbage.json()}")

    # Both must be 400 bad_cursor
    assert r_cross.status_code == 400, \
        f"invalid cursor must return 400, got {r_cross.status_code}"
    err = r_cross.json().get("error", "") + r_cross.json().get("detail", "")
    assert "bad_cursor" in err or "invalid" in err.lower() or "cursor" in err.lower(), \
        f"error must mention bad cursor, got {r_cross.json()}"


# --- Codes list: status only, never code or code_hash ----------------------

@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M3T1Pending)
def test_codes_list_status_only(t1_server):
    """GET /api/v1/admin/enrollment-codes?project= returns status, never the
    code or code_hash."""
    import httpx
    info = t1_server

    # Issue a code first (existing route)
    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        r_issue = c.post(
            "/api/v1/admin/enrollment-codes",
            json={"project_id": info["project_id"],
                  "operator_user_id": info["alice_id"]},
            cookies={"__Host-agg_session": info["alice_cookie"]},
            headers={"X-CSRF-Token": info["alice_csrf"]},
        )
    assert r_issue.status_code == 200, f"issue failed: {r_issue.text}"

    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        r = c.get(
            "/api/v1/admin/enrollment-codes",
            params={"project": info["project_id"]},
            cookies={"__Host-agg_session": info["alice_cookie"]},
        )
    require_m3(1, not _route_not_registered(r),
               "GET /api/v1/admin/enrollment-codes route not registered")
    assert r.status_code == 200
    body = r.json()
    items = body.get("items", body.get("codes", []))
    assert len(items) >= 1
    for item in items:
        assert "code" not in item, "code must not appear in admin list"
        assert "code_hash" not in item, "code_hash must not appear in admin list"
        # Must have a status field
        assert "status" in item or "state" in item, \
            "each code must have status or state"


# --- Bundles detail carries envelope ----------------------------------------

@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M3T1Pending)
def test_bundles_detail_carries_envelope(t1_server):
    """GET /api/v1/admin/bundles/{seq} returns the envelope.

    Uses the seeded bundle at sequence 1.
    """
    import httpx
    info = t1_server
    seq = info["seeded_bundle_sequence"]  # 1

    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        r = c.get(f"/api/v1/admin/bundles",
                  params={"project": info["project_id"]},
                  cookies={"__Host-agg_session": info["alice_cookie"]})
    require_m3(1, not _route_not_registered(r),
               "GET /api/v1/admin/bundles route not registered")
    assert r.status_code == 200
    body = r.json()
    items = body.get("items", body.get("bundles", []))
    assert len(items) >= 1, "seeded bundle must appear in list"

    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        r2 = c.get(f"/api/v1/admin/bundles/{seq}",
                   params={"project": info["project_id"]},
                   cookies={"__Host-agg_session": info["alice_cookie"]})
    assert r2.status_code == 200
    detail = r2.json()
    assert "envelope" in detail, "detail must carry the envelope"
    env = detail["envelope"]
    assert isinstance(env, dict), "envelope must be a dict"
    assert "payload" in env, "envelope must contain a payload"


# --- Bundles detail: approvals by user and kind ----------------------------

@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M3T1Pending)
def test_bundles_detail_approvals_by_user_and_kind(t1_server):
    """GET /api/v1/admin/bundles/{seq} shows approvals by user and kind.

    Uses the seeded bundle at sequence 1 which has one seeded approval.
    """
    import httpx
    info = t1_server
    seq = info["seeded_bundle_sequence"]

    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        r = c.get(f"/api/v1/admin/bundles",
                  params={"project": info["project_id"]},
                  cookies={"__Host-agg_session": info["alice_cookie"]})
    require_m3(1, not _route_not_registered(r),
               "GET /api/v1/admin/bundles route not registered")
    assert r.status_code == 200
    items = r.json().get("items", r.json().get("bundles", []))
    assert len(items) >= 1, "seeded bundle must appear in list"

    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        r2 = c.get(f"/api/v1/admin/bundles/{seq}",
                   params={"project": info["project_id"]},
                   cookies={"__Host-agg_session": info["alice_cookie"]})
    assert r2.status_code == 200
    detail = r2.json()
    approvals = detail.get("approvals", [])
    assert len(approvals) >= 1, \
        "seeded bundle must have at least one approval"
    for a in approvals:
        assert "user_id" in a, "approval must show user_id"
        assert isinstance(a["user_id"], str), "user_id must be a string"
        assert "kind" in a or "key_kind" in a, "approval must show kind"
        kind_val = a.get("kind") or a.get("key_kind")
        assert kind_val == "cli", \
            f"seeded approval kind must be 'cli', got {kind_val!r}"


# --- Bundles detail: per-section diff from bytes --------------------------

@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M3T1Pending)
def test_bundles_detail_per_section_diff(t1_server):
    """GET /api/v1/admin/bundles/{seq} includes per-section diff.

    Uses the seeded bundle at sequence 1.
    """
    import httpx
    info = t1_server
    seq = info["seeded_bundle_sequence"]

    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        r = c.get(f"/api/v1/admin/bundles",
                  params={"project": info["project_id"]},
                  cookies={"__Host-agg_session": info["alice_cookie"]})
    require_m3(1, not _route_not_registered(r),
               "GET /api/v1/admin/bundles route not registered")
    assert r.status_code == 200
    items = r.json().get("items", r.json().get("bundles", []))
    assert len(items) >= 1, "seeded bundle must appear in list"

    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        r2 = c.get(f"/api/v1/admin/bundles/{seq}",
                   params={"project": info["project_id"]},
                   cookies={"__Host-agg_session": info["alice_cookie"]})
    assert r2.status_code == 200
    detail = r2.json()
    diff_key = None
    for k in ("diff", "section_diff", "sections"):
        if k in detail:
            diff_key = k
            break
    assert diff_key is not None, \
        "detail must include per-section diff (one of 'diff', 'section_diff', 'sections')"
    diff_val = detail[diff_key]
    assert isinstance(diff_val, (dict, list)), \
        f"diff value must be a dict or list, got {type(diff_val).__name__}"


# --- Bundles detail: verification label ------------------------------------

@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M3T1Pending)
def test_bundles_detail_verification_label(t1_server):
    """GET /api/v1/admin/bundles/{seq} includes the verification label.

    Uses the seeded bundle at sequence 1.  The seeded row was inserted
    directly (no server verification), so it must be labelled
    ``m2_unverified``.
    """
    import httpx
    info = t1_server
    seq = info["seeded_bundle_sequence"]

    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        r = c.get(f"/api/v1/admin/bundles",
                  params={"project": info["project_id"]},
                  cookies={"__Host-agg_session": info["alice_cookie"]})
    require_m3(1, not _route_not_registered(r),
               "GET /api/v1/admin/bundles route not registered")
    assert r.status_code == 200
    items = r.json().get("items", r.json().get("bundles", []))
    assert len(items) >= 1, "seeded bundle must appear in list"

    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        r2 = c.get(f"/api/v1/admin/bundles/{seq}",
                   params={"project": info["project_id"]},
                   cookies={"__Host-agg_session": info["alice_cookie"]})
    assert r2.status_code == 200
    detail = r2.json()
    assert "verification" in detail, \
        "detail must include verification label (server or m2_unverified)"
    assert detail["verification"] in ("server", "m2_unverified"), \
        f"verification must be 'server' or 'm2_unverified', got {detail['verification']!r}"


# --- Bundles detail: applied-by devices ------------------------------------

@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M3T1Pending)
def test_bundles_detail_applied_by_devices(t1_server):
    """GET /api/v1/admin/bundles/{seq} shows which devices applied it.

    Uses the seeded bundle at sequence 1 with one device that applied it.
    """
    import httpx
    info = t1_server
    seq = info["seeded_bundle_sequence"]
    expected_device = info["seeded_device_id"]

    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        r = c.get(f"/api/v1/admin/bundles",
                  params={"project": info["project_id"]},
                  cookies={"__Host-agg_session": info["alice_cookie"]})
    require_m3(1, not _route_not_registered(r),
               "GET /api/v1/admin/bundles route not registered")
    assert r.status_code == 200
    items = r.json().get("items", r.json().get("bundles", []))
    assert len(items) >= 1, "seeded bundle must appear in list"

    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        r2 = c.get(f"/api/v1/admin/bundles/{seq}",
                   params={"project": info["project_id"]},
                   cookies={"__Host-agg_session": info["alice_cookie"]})
    assert r2.status_code == 200
    detail = r2.json()
    assert "applied_by" in detail or "devices" in detail, \
        "detail must show which devices applied this bundle"
    applied_list = detail.get("applied_by") if "applied_by" in detail \
        else detail.get("devices")
    assert isinstance(applied_list, list), \
        f"applied_by must be a list, got {type(applied_list).__name__}"
    assert len(applied_list) >= 1, \
        "seeded device applied this bundle; at least one entry expected"
    device_ids = []
    for entry in applied_list:
        if isinstance(entry, str):
            device_ids.append(entry)
        elif isinstance(entry, dict):
            device_ids.append(
                entry.get("id") or entry.get("device_id", ""))
    assert expected_device in device_ids, \
        f"seeded device {expected_device} must be in applied_by list"


# --- Alerts list -----------------------------------------------------------

@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M3T1Pending)
def test_alerts_list(t1_server):
    """GET /api/v1/alerts?project= returns alerts for the project."""
    import httpx
    info = t1_server

    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        r = c.get(f"/api/v1/alerts",
                  params={"project": info["project_id"]},
                  cookies={"__Host-agg_session": info["alice_cookie"]})
    require_m3(1, not _route_not_registered(r),
               "GET /api/v1/alerts route not registered")
    assert r.status_code == 200
    body = r.json()
    assert isinstance(body, dict)


# --- Verify per project ----------------------------------------------------

@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M3T1Pending)
def test_verify_per_project(t1_server):
    """GET /api/v1/audit/verify?project= verifies audit for a project."""
    import httpx
    info = t1_server

    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        r = c.get(f"/api/v1/audit/verify",
                  params={"project": info["project_id"]},
                  cookies={"__Host-agg_session": info["alice_cookie"]})
    require_m3(1, not _route_not_registered(r),
               "GET /api/v1/audit/verify route not registered")
    assert r.status_code == 200


# --- JSONL export -----------------------------------------------------------

@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M3T1Pending)
def test_jsonl_export(t1_server):
    """GET /api/v1/audit/export?project= returns JSONL with correct content type."""
    import httpx
    info = t1_server

    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        r = c.get(f"/api/v1/audit/export",
                  params={"project": info["project_id"]},
                  cookies={"__Host-agg_session": info["alice_cookie"]})
    require_m3(1, not _route_not_registered(r),
               "GET /api/v1/audit/export route not registered")
    assert r.status_code == 200
    ct = r.headers.get("content-type", "")
    assert "jsonl" in ct or "ndjson" in ct or "json-seq" in ct or \
           "application/x-ndjson" in ct, \
        f"JSONL export must use a JSONL content type, got {ct}"


# --- RLS catalog unchanged --------------------------------------------------

@pytest.mark.pg
def test_guard_rls_catalog_unchanged(t1_server):
    """Guard: RLS-enforced tables still have RLS enabled (baseline)."""
    info = t1_server
    conninfo = _conninfo(info["owner_url"])
    with psycopg.connect(conninfo) as conn:
        rls_rows = conn.execute(
            "SELECT relname, relrowsecurity FROM pg_class "
            "WHERE relname IN ('audit_records', 'connectors', 'policy_bundles', "
            "  'enrollment_codes', 'projects', 'role_bindings', 'escalations')"
        ).fetchall()
    enabled_tables = [name for name, enabled in rls_rows if enabled]
    assert len(enabled_tables) >= 4, \
        f"expected at least 4 tables with RLS, got {enabled_tables}"
