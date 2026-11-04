"""T16b tests-first: server stores and serves change_approvals (ADR 0001 A1).

Spec (T12B_PLAN.md T16b row, ADR 0001 Amendment A1 (2 Nov)):

  - ``POST /api/v1/admin/bundles`` stores ``change_approvals`` in
    ``policy_change_approvals`` keyed by the bundle row.
  - ``GET /api/v1/sync/bundle?after=<seq>`` returns
    ``{"envelope": ..., "change_approvals": [...]}`` verbatim with the
    approvals beside (not inside) the signed envelope; envelope bytes
    unchanged.
  - A 0-approval loosening is still served (server does not judge in M2)
    but the connector's ``verify_and_apply`` refuses it.
  - E2e: publish a 2-approval loosening and the connector applies it
    through the pull path (mark pg).
  - ADR 0001 A1 item 2: the row served is the LOWEST sequence > after,
    not the newest.
  - ADR 0001 A1 item 1: a malformed approval or a key not in
    ``approver_keys`` makes the publish 400 ``bad_change_approvals``.
    Approvals round-trip verbatim.

All tests are strict xfail.  Sentinel: ``M2T16Pending``.

Marked ``pg`` (requires Postgres via testcontainers).
"""
from __future__ import annotations

import hashlib
import inspect
import json
import os
import secrets
import time
import uuid
from pathlib import Path

import pytest
from nacl.signing import SigningKey

from .m2_pending import M2T16Pending
from .m2_sync_server import (
    make_sync_server, ensure_at_head, create_org, create_project,
    keygen, sign_envelope, canonical_json,
)
from .t9_helpers import seed_session, make_session_cookie, compute_csrf
from .fake_idp import FakeClock


# ---------------------------------------------------------------------------
# _need() guards -- detect product gaps at the top of each test
# ---------------------------------------------------------------------------

def _need_approvals_stored() -> None:
    """Raise M2T16Pending if admin_create_bundle does not INSERT
    into policy_change_approvals."""
    import agg_cp.sync.bundles as mod
    src = inspect.getsource(mod)
    if "INSERT INTO policy_change_approvals" not in src:
        raise M2T16Pending(
            "admin_create_bundle does not store change_approvals "
            "in policy_change_approvals"
        )


def _need_approvals_served() -> None:
    """Raise M2T16Pending if get_bundle does not return
    {"envelope": ..., "change_approvals": [...]}."""
    import agg_cp.sync.bundles as mod
    src = inspect.getsource(mod)
    # Isolate get_bundle function source (between its def and admin_create_bundle)
    start = src.find("async def get_bundle")
    end = src.find("async def admin_create_bundle")
    if start < 0 or end < 0:
        raise M2T16Pending("get_bundle or admin_create_bundle not found in module")
    get_bundle_src = src[start:end]
    if "change_approvals" not in get_bundle_src:
        raise M2T16Pending(
            "get_bundle returns bare envelope, not {envelope, change_approvals}"
        )


def _need_lowest_seq_order() -> None:
    """Raise M2T16Pending if get_bundle ORDER BY is DESC (serves latest)
    instead of ASC (serves lowest > after)."""
    import agg_cp.sync.bundles as mod
    src = inspect.getsource(mod)
    start = src.find("async def get_bundle")
    end = src.find("async def admin_create_bundle")
    if start < 0 or end < 0:
        raise M2T16Pending("get_bundle or admin_create_bundle not found")
    get_bundle_src = src[start:end]
    if "ORDER BY sequence DESC" in get_bundle_src:
        raise M2T16Pending(
            "get_bundle serves latest (ORDER BY DESC), "
            "not lowest > after (ORDER BY ASC)"
        )


def _need_bad_approvals_validation() -> None:
    """Raise M2T16Pending if admin_create_bundle does not validate
    change_approvals (no 'bad_change_approvals' error path)."""
    import agg_cp.sync.bundles as mod
    src = inspect.getsource(mod)
    if "bad_change_approvals" not in src:
        raise M2T16Pending(
            "admin_create_bundle does not validate change_approvals"
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _conninfo(url: str) -> str:
    return url.replace("+psycopg", "")


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
    """Create a fresh web session.  Return (cookie, csrf)."""
    clock = FakeClock()
    token, csrf, sid = seed_session(
        owner_url, uuid.UUID(org_id), uuid.UUID(user_id), clock=clock,
    )
    cookie = make_session_cookie(uuid.UUID(org_id), token)
    return cookie, csrf


def _make_change_approval(sk, bundle_payload: dict) -> dict:
    """Build and sign an agg/policy-change/v1 envelope over the bundle hash."""
    canonical = json.dumps(
        bundle_payload, sort_keys=True, separators=(",", ":")
    ).encode()
    bh = hashlib.sha256(canonical).hexdigest()
    pub = bytes(sk.verify_key)
    kid = hashlib.sha256(pub).hexdigest()
    payload = {
        "bundle_hash": bh,
        "key_id": kid,
        "approved_at": time.time(),
    }
    return sign_envelope("agg/policy-change/v1", payload, sk)


def _post_bundle(srv, cookie, csrf, project_id, bundle_payload,
                 change_approvals):
    """POST /api/v1/admin/bundles. Returns the httpx response."""
    import httpx
    return httpx.post(
        f"{srv['base_url']}/api/v1/admin/bundles",
        cookies={"__Host-agg_session": cookie},
        headers={"X-CSRF-Token": csrf},
        json={
            "project_id": project_id,
            "bundle_payload": bundle_payload,
            "change_approvals": change_approvals,
        },
        timeout=10,
        verify=False,
    )


def _get_bundle(srv, device_token, after=0):
    """GET /api/v1/sync/bundle?after=<seq>.  Returns (status, body_dict)."""
    import httpx
    r = httpx.get(
        f"{srv['base_url']}/api/v1/sync/bundle",
        params={"after": str(after)},
        headers={"Authorization": f"Bearer {device_token}"},
        timeout=10,
        verify=False,
    )
    if r.status_code == 204:
        return 204, {}
    return r.status_code, r.json()


def _route_cli_link(srv, org_id, user_id):
    """Route a CLI key through /signer-links and /signer/link.
    Returns (sk, kid)."""
    import httpx
    cookie, csrf = _make_fresh_session(srv["owner_url"], org_id, user_id)
    r = httpx.post(
        f"{srv['base_url']}/api/v1/signer-links",
        cookies={"__Host-agg_session": cookie},
        headers={"X-CSRF-Token": csrf},
        json={},
        timeout=10,
        verify=False,
    )
    assert r.status_code == 200, f"signer-links failed: {r.status_code} {r.text}"
    code = r.json()["code"]
    sk = SigningKey.generate()
    kid = hashlib.sha256(bytes(sk.verify_key)).hexdigest()
    r2 = httpx.post(
        f"{srv['base_url']}/api/v1/sync/signer/link",
        json={"code": code, "key_id": kid,
              "public_key": bytes(sk.verify_key).hex()},
        timeout=10, verify=False,
    )
    assert r2.status_code == 200, f"link failed: {r2.status_code} {r2.text}"
    return sk, kid


def _issue_code_ready(conn, org_id, project_id, operator_user_id):
    """Seed an enrollment code.  Returns (code, code_hash, code_id)."""
    code = secrets.token_hex(16)
    code_hash = hashlib.sha256(code.encode()).hexdigest()
    code_id = str(uuid.uuid4())
    conn.execute(
        "INSERT INTO enrollment_codes "
        "(id, org_id, project_id, code_hash, code_read_at, expires_at, "
        " operator_user_id) "
        "VALUES (%s, %s, %s, %s, now(), now() + interval '15 minutes', %s)",
        [code_id, org_id, project_id, code_hash, operator_user_id],
    )
    return code, code_hash, code_id


def _enroll_device(srv, conn, org_id, project_id, operator_user_id):
    """Enroll a device.  Returns device_token (str).

    Since T8 the enroll route requires a PoP ``proof`` envelope
    (``agg/device-enroll/v1`` signing code_hash).  Pattern copied from
    ``ee/tests/test_m2_t8_enroll.py::_make_enroll_proof``.
    """
    code, code_hash, code_id = _issue_code_ready(
        conn, org_id, project_id, operator_user_id,
    )
    import httpx
    from nacl.signing import SigningKey as SK
    device_sk = SK.generate()
    device_pub = bytes(device_sk.verify_key)
    device_pub_hex = device_pub.hex()
    device_kid = hashlib.sha256(device_pub).hexdigest()

    # Build PoP proof envelope (T8 requirement)
    proof_payload = {
        "code_hash": code_hash,
        "public_key": device_pub_hex,
        "aud": "test",
        "iat": time.time(),
    }
    proof = sign_envelope("agg/device-enroll/v1", proof_payload, device_sk)

    r = httpx.post(
        f"{srv['base_url']}/api/v1/sync/enroll",
        json={
            "code": code,
            "public_key": device_pub_hex,
            "proof": proof,
        },
        timeout=10, verify=False,
    )
    assert r.status_code == 200, f"enroll failed: {r.status_code} {r.text}"
    device_id = r.json().get("device_id", "")

    # Get a device token via signed assertion (T8 requirement)
    assertion = sign_envelope("agg/device-assert/v1", {
        "device_id": device_id,
        "aud": "test",
        "iat": time.time(),
        "nonce": secrets.token_hex(16),
    }, device_sk)
    r2 = httpx.post(
        f"{srv['base_url']}/api/v1/sync/token",
        json={"device_id": device_id, "assertion": assertion},
        timeout=10, verify=False,
    )
    assert r2.status_code == 200, f"token failed: {r2.status_code} {r2.text}"
    return r2.json()["token"]


def _build_registry(admin_sks, approver_sks=(), *, org_id,
                    bundle_signer_sk=None):
    """Build a signed registry genesis.  Returns ([genesis_env], fingerprint).

    Follows the same contract as
    ``tests.security.test_m2_t12_remote._build_registry`` so the e2e test
    can set up a managed workspace without importing across root boundaries.
    """
    keys = []
    admins = []
    for sk, pub, kid in admin_sks:
        keys.append({
            "key_id": kid, "public_key": pub.hex(),
            "user_id": f"admin-{kid[:8]}", "iss": "https://idp.test",
            "sub": f"admin-{kid[:8]}", "alg": "ed25519", "kind": "cli",
            "roles": ["admin", "approver"], "added_in": 1,
        })
        admins.append(kid)
    for entry in approver_sks:
        sk, pub, kid, uid, kind = entry[:5]
        sub = entry[5] if len(entry) > 5 else uid
        keys.append({
            "key_id": kid, "public_key": pub.hex(),
            "user_id": uid, "iss": "https://idp.test", "sub": sub,
            "alg": "ed25519", "kind": kind, "roles": ["approver"],
            "added_in": 1,
        })
    genesis_payload = {
        "org_id": org_id, "version": 1, "prev_hash": "",
        "threshold": 2 if len(admin_sks) >= 2 else 1,
        "admins": admins, "keys": keys,
        "expires_at": time.time() + 86400,
    }
    if bundle_signer_sk is not None:
        _, bpub, bkid = bundle_signer_sk
        genesis_payload["bundle_signer"] = {
            "key_id": bkid, "public_key": bpub.hex(),
        }
    tag = b"agg/registry/v1"
    canonical = json.dumps(genesis_payload, sort_keys=True,
                           separators=(",", ":")).encode()
    msg = tag + b"\x00" + canonical
    sigs = []
    for sk, pub, kid in admin_sks:
        sig = sk.sign(msg).signature.hex()
        sigs.append({"key_id": kid, "alg": "ed25519", "sig": sig})
    genesis_env = {
        "kind": "agg/registry/v1", "sig_v": 1,
        "payload": genesis_payload, "signatures": sigs,
    }
    fp = hashlib.sha256(
        genesis_payload["org_id"].encode("utf-8") + b":" + canonical
    ).hexdigest()
    return [genesis_env], fp


def _setup_managed_workspace(
    tmp_path, monkeypatch, *, admin_sks=None, approver_sks=None,
    bundle_signer_sk=None, org_id="org-1", project_id="proj-1",
    policy_sequence=1,
):
    """Set up a managed workspace with a pinned registry and a signed bundle.

    Local equivalent of ``tests.security.test_m2_t12_remote._setup_managed_workspace``
    so ee tests do not cross the root boundary.  Returns dict with lay, registry, fp.
    """
    from sandbox.connector.install import init
    from sandbox.connector.layout import FolderLayout

    kh = tmp_path / "keyhome"
    kh.mkdir(exist_ok=True)
    monkeypatch.setenv("SANDBOX_KEY_HOME", str(kh))

    ws = tmp_path / "ws"
    ws.mkdir(parents=True, exist_ok=True)
    init(ws, claude=False, mcp=False)
    lay = FolderLayout(ws)

    ws_id = "a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5"
    (lay.base / "workspace_id").write_text(ws_id, encoding="utf-8")
    kh_ws = kh / ws_id
    kh_ws.mkdir(parents=True, exist_ok=True)
    (kh_ws / "managed").write_text("1", encoding="utf-8")

    sync_dir = lay.root / ".sandbox" / "state" / "sync"
    sync_dir.mkdir(parents=True, exist_ok=True)
    (sync_dir / "managed").write_text("1", encoding="utf-8")

    if admin_sks is None:
        admin_sks = [keygen(), keygen()]
    if approver_sks is None:
        approver_sks = []
    if bundle_signer_sk is None:
        bundle_signer_sk = keygen()

    envelopes, fp = _build_registry(
        admin_sks, approver_sks,
        org_id=org_id, bundle_signer_sk=bundle_signer_sk,
    )
    (sync_dir / "pinned_root.json").write_text(
        json.dumps({"fingerprint": fp}), encoding="utf-8")
    (sync_dir / "registry.json").write_text(
        json.dumps(envelopes), encoding="utf-8")

    # Signed bundle
    bs_sk, bs_pub, bs_kid = bundle_signer_sk
    bundle_payload = {
        "org_id": org_id, "project_id": project_id,
        "sequence": policy_sequence, "base_sequence": 0,
        "registry_version": 1, "environment": "staging",
        "folder_policy": {}, "governance_policy": {}, "mcp_policy": {},
        "approval": {"local_fallback": False, "allow_requester": False},
        "change_approvals": [],
        "issued_at": time.time(), "not_before": time.time() - 60,
        "expires_at": time.time() + 86400,
    }
    bundle_env = sign_envelope("agg/bundle/v1", bundle_payload, bs_sk)
    (sync_dir / "bundle.json").write_text(
        json.dumps(bundle_env), encoding="utf-8")

    device_id_val = "dev-1"
    (sync_dir / "enrollment.json").write_text(json.dumps({
        "device_id": device_id_val, "operator_user_id": "operator-alice",
        "org_id": org_id, "project_id": project_id,
    }), encoding="utf-8")
    (sync_dir / "device_id").write_text(device_id_val, encoding="utf-8")

    connector_sk = SigningKey.generate()
    safe_name = f"connector_{device_id_val}"
    (kh_ws / f"{safe_name}.seed").write_bytes(bytes(connector_sk))
    (kh_ws / f"{safe_name}.pub").write_text(
        bytes(connector_sk.verify_key).hex(), encoding="utf-8")

    # Server-time measurement (required by sync; product reads server_time_state.json)
    (sync_dir / "server_time_state.json").write_text(json.dumps({
        "server_time": time.time(), "local_time": time.time(),
    }), encoding="utf-8")

    # S1: initial high_water.json (so load_verified_state never fails closed
    # on a missing file; matches test_m2_t12_remote._setup_managed_workspace)
    (sync_dir / "high_water.json").write_text(json.dumps({
        "registry_version": 1, "bundle_sequence": policy_sequence,
    }), encoding="utf-8")

    return {
        "lay": lay,
        "registry": envelopes,
        "fingerprint": fp,
        "admin_sks": admin_sks,
        "bundle_signer_sk": bundle_signer_sk,
    }


# ---------------------------------------------------------------------------
# Module-scoped server fixture
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def t16b_server(pg_url, app_url, owner_url, pg_roles, tmp_path_factory):
    """4-worker agg_cp server for T16b tests.

    Seeds: org, project, alice (admin), admin2 (admin), bob (admin, no CLI
    key; the publisher since T16h, ADR 0001 Amendment A2), carol (user).
    Bundle signer key file in env.
    """
    import psycopg

    bundle_signer_sk = SigningKey.generate()
    key_dir = tmp_path_factory.mktemp("t16b_bundle_signer")
    key_file = key_dir / "bundle_signer.key"
    key_file.write_bytes(bytes(bundle_signer_sk).hex().encode("ascii"))
    old_bs = os.environ.get("AGG_BUNDLE_SIGNER_KEY_FILE")
    os.environ["AGG_BUNDLE_SIGNER_KEY_FILE"] = str(key_file)

    gen = make_sync_server(
        pg_url, app_url, owner_url,
        org_names=["T16b Org"],
    )
    info = next(gen)

    conninfo = _conninfo(owner_url)
    with psycopg.connect(conninfo, autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [info["org_id"]])
        alice_id = _seed_user_row(conn, info["org_id"], "alice@t16b.test")
        admin2_id = _seed_user_row(conn, info["org_id"], "admin2@t16b.test")
        bob_id = _seed_user_row(conn, info["org_id"], "bob@t16b.test")
        carol_id = _seed_user_row(conn, info["org_id"], "carol@t16b.test")

        for uid in (alice_id, admin2_id, bob_id):
            conn.execute(
                "INSERT INTO role_bindings "
                "(id, org_id, user_id, scope_type, scope_id, role, created_at) "
                "VALUES (%s, %s, %s, 'org', %s, 'admin', now())",
                [str(uuid.uuid4()), info["org_id"], uid, info["org_id"]],
            )

        project_id = str(uuid.uuid4())
        create_project(conn, info["org_id"], project_id, "T16b Project")

    info["alice_id"] = alice_id
    info["admin2_id"] = admin2_id
    info["bob_id"] = bob_id
    info["carol_id"] = carol_id
    info["project_id"] = project_id
    info["bundle_signer_sk"] = bundle_signer_sk
    info["bundle_signer_pub"] = bytes(bundle_signer_sk.verify_key)

    try:
        yield info
    finally:
        gen.close()
        if old_bs is None:
            os.environ.pop("AGG_BUNDLE_SIGNER_KEY_FILE", None)
        else:
            os.environ["AGG_BUNDLE_SIGNER_KEY_FILE"] = old_bs


# ===================================================================
# T16b-1: POST /admin/bundles stores change_approvals
# ===================================================================


@pytest.mark.pg
def test_post_bundles_stores_change_approvals(t16b_server):
    """POST /admin/bundles with change_approvals stores them in
    policy_change_approvals keyed by the bundle row."""
    _need_approvals_stored()

    import psycopg

    srv = t16b_server
    org_id = srv["org_id"]
    project_id = srv["project_id"]
    alice_id = srv["alice_id"]
    bob_id = srv["bob_id"]  # T16h: publisher is a third admin (ADR 0001 A2)

    bundle_payload = {
        "org_id": org_id,
        "project_id": project_id,
        "sequence": 1,
        "base_sequence": 0,
        "registry_version": 1,
        "environment": "staging",
        "folder_policy": {},
        "governance_policy": {},
        "mcp_policy": {},
        "approval": {"local_fallback": False, "allow_requester": False},
        "change_approvals": [],
        "issued_at": time.time(),
        "not_before": time.time() - 60,
        "expires_at": time.time() + 86400,
    }

    alice_sk, alice_kid = _route_cli_link(srv, org_id, alice_id)
    admin2_sk, admin2_kid = _route_cli_link(srv, org_id, srv["admin2_id"])

    appr1 = _make_change_approval(alice_sk, bundle_payload)
    appr2 = _make_change_approval(admin2_sk, bundle_payload)

    cookie, csrf = _make_fresh_session(srv["owner_url"], org_id, bob_id)
    r = _post_bundle(srv, cookie, csrf, project_id, bundle_payload,
                     [appr1, appr2])
    assert r.status_code == 200, f"publish failed: {r.status_code} {r.text}"

    bundle_id = r.json()["bundle_id"]

    conninfo = _conninfo(srv["owner_url"])
    with psycopg.connect(conninfo, autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [org_id])
        rows = conn.execute(
            "SELECT change_request_id, key_id, signature, user_id "
            "FROM policy_change_approvals "
            "WHERE change_request_id = %s::uuid "
            "ORDER BY key_id",
            [bundle_id],
        ).fetchall()

    assert len(rows) == 2, f"expected 2 approval rows, got {len(rows)}"
    stored_kids = {r[1] for r in rows}
    assert alice_kid in stored_kids
    assert admin2_kid in stored_kids


# ===================================================================
# T16b-2: GET /sync/bundle returns envelope + change_approvals
# ===================================================================


@pytest.mark.pg
def test_get_bundle_returns_envelope_and_approvals(t16b_server):
    """GET /sync/bundle returns {"envelope": ..., "change_approvals": [...]}
    with approvals beside (not inside) the signed envelope."""
    _need_approvals_served()

    import psycopg

    srv = t16b_server
    org_id = srv["org_id"]
    project_id = srv["project_id"]
    alice_id = srv["alice_id"]
    bob_id = srv["bob_id"]  # T16h: publisher is a third admin (ADR 0001 A2)

    alice_sk, alice_kid = _route_cli_link(srv, org_id, alice_id)
    admin2_sk, admin2_kid = _route_cli_link(srv, org_id, srv["admin2_id"])

    bundle_payload = {
        "org_id": org_id,
        "project_id": project_id,
        "sequence": 10,
        "base_sequence": 0,
        "registry_version": 1,
        "environment": "staging",
        "folder_policy": {},
        "governance_policy": {},
        "mcp_policy": {},
        "approval": {"local_fallback": False, "allow_requester": False},
        "change_approvals": [],
        "issued_at": time.time(),
        "not_before": time.time() - 60,
        "expires_at": time.time() + 86400,
    }
    appr1 = _make_change_approval(alice_sk, bundle_payload)
    appr2 = _make_change_approval(admin2_sk, bundle_payload)

    cookie, csrf = _make_fresh_session(srv["owner_url"], org_id, bob_id)
    r = _post_bundle(srv, cookie, csrf, project_id, bundle_payload,
                     [appr1, appr2])
    assert r.status_code == 200, f"publish failed: {r.status_code} {r.text}"

    conninfo = _conninfo(srv["owner_url"])
    with psycopg.connect(conninfo, autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [org_id])
        device_token = _enroll_device(
            srv, conn, org_id, project_id, alice_id,
        )

    status, body = _get_bundle(srv, device_token, after=9)
    assert status == 200, f"expected 200, got {status}"
    assert "envelope" in body, "response must have 'envelope' key"
    assert "change_approvals" in body, "response must have 'change_approvals' key"
    assert isinstance(body["change_approvals"], list)
    assert len(body["change_approvals"]) == 2

    env = body["envelope"]
    assert env.get("kind") == "agg/bundle/v1"
    assert env.get("sig_v") == 1
    assert "signatures" in env


@pytest.mark.pg
def test_get_bundle_envelope_bytes_unchanged(t16b_server):
    """The envelope bytes served by GET /sync/bundle are unchanged from
    what the server signed at publish time."""
    _need_approvals_served()

    import psycopg

    srv = t16b_server
    org_id = srv["org_id"]
    project_id = srv["project_id"]
    alice_id = srv["alice_id"]
    bob_id = srv["bob_id"]  # T16h: publisher is a third admin (ADR 0001 A2)

    bundle_payload = {
        "org_id": org_id,
        "project_id": project_id,
        "sequence": 20,
        "base_sequence": 0,
        "registry_version": 1,
        "environment": "staging",
        "folder_policy": {},
        "governance_policy": {},
        "mcp_policy": {},
        "approval": {"local_fallback": False, "allow_requester": False},
        "change_approvals": [],
        "issued_at": time.time(),
        "not_before": time.time() - 60,
        "expires_at": time.time() + 86400,
    }

    cookie, csrf = _make_fresh_session(srv["owner_url"], org_id, bob_id)
    r = _post_bundle(srv, cookie, csrf, project_id, bundle_payload, [])
    assert r.status_code == 200

    conninfo = _conninfo(srv["owner_url"])
    with psycopg.connect(conninfo, autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [org_id])
        device_token = _enroll_device(srv, conn, org_id, project_id, alice_id)

    status, body = _get_bundle(srv, device_token, after=19)
    assert status == 200
    env = body["envelope"]

    # Re-verify the server signature to confirm envelope is pristine
    from nacl.signing import VerifyKey
    bs_pub = srv["bundle_signer_pub"]
    bs_kid = hashlib.sha256(bs_pub).hexdigest()
    tag = "agg/bundle/v1"
    canonical = json.dumps(env["payload"], sort_keys=True,
                           separators=(",", ":")).encode()
    msg = tag.encode("utf-8") + b"\x00" + canonical
    found = False
    for s in env.get("signatures", []):
        if s.get("key_id") == bs_kid:
            VerifyKey(bs_pub).verify(msg, bytes.fromhex(s["sig"]))
            found = True
    assert found, "envelope signature did not verify"


# ===================================================================
# T16b-3: 0-approval loosening served but connector refuses
# ===================================================================


@pytest.mark.pg
def test_zero_approval_loosening_served_but_connector_refuses(t16b_server):
    """A 0-approval loosening is still served (server does not judge) but
    the connector's verify_and_apply refuses it."""
    _need_approvals_served()

    import psycopg

    srv = t16b_server
    org_id = srv["org_id"]
    project_id = srv["project_id"]
    alice_id = srv["alice_id"]
    bob_id = srv["bob_id"]  # T16h: publisher is a third admin (ADR 0001 A2)

    bundle_payload = {
        "org_id": org_id,
        "project_id": project_id,
        "sequence": 30,
        "base_sequence": 0,
        "registry_version": 1,
        "environment": "staging",
        "folder_policy": {},
        "governance_policy": {},
        "mcp_policy": {},
        "approval": {"local_fallback": False, "allow_requester": False},
        "change_approvals": [],
        "issued_at": time.time(),
        "not_before": time.time() - 60,
        "expires_at": time.time() + 86400,
    }

    cookie, csrf = _make_fresh_session(srv["owner_url"], org_id, bob_id)
    r = _post_bundle(srv, cookie, csrf, project_id, bundle_payload, [])
    assert r.status_code == 200

    conninfo = _conninfo(srv["owner_url"])
    with psycopg.connect(conninfo, autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [org_id])
        device_token = _enroll_device(srv, conn, org_id, project_id, alice_id)

    status, body = _get_bundle(srv, device_token, after=29)
    assert status == 200
    assert body.get("change_approvals") == [] or body.get("change_approvals") is not None

    from sandbox.connector.sync.bundles import verify_and_apply, BundleError
    from sandbox.protocol.registry import verify_chain
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        ws = Path(td) / "ws"

        class FakeMonkey:
            def setenv(self, k, v):
                os.environ[k] = v

        fm = FakeMonkey()
        admin1 = keygen()
        admin2 = keygen()
        bs_pub = srv["bundle_signer_pub"]
        bs_kid = hashlib.sha256(bs_pub).hexdigest()

        ctx = _setup_managed_workspace(
            Path(td), fm,
            admin_sks=[admin1, admin2],
            bundle_signer_sk=(srv["bundle_signer_sk"], bs_pub, bs_kid),
            org_id=org_id,
            project_id=project_id,
            policy_sequence=0,
        )
        lay = ctx["lay"]
        # Remove the seed bundle so this is a first-bundle scenario
        # (last_valid_bundle returns None -> needs 2 approvals)
        seed_bundle = lay.root / ".sandbox" / "state" / "sync" / "bundle.json"
        if seed_bundle.exists():
            seed_bundle.unlink()
        verified_registry = verify_chain(
            ctx["registry"], ctx["fingerprint"],
        )

        with pytest.raises(BundleError, match="need 2 approvals"):
            verify_and_apply(
                lay,
                body["envelope"],
                verified_registry,
                bs_pub,
                body.get("change_approvals", []),
                org_id=org_id,
                project_id=project_id,
            )


# ===================================================================
# T16b-4: ADR 0001 A1 item 2 -- lowest sequence > after, not latest
# ===================================================================


@pytest.mark.pg
def test_get_bundle_serves_lowest_seq_above_after(t16b_server):
    """GET /sync/bundle?after=N returns the bundle with the lowest
    sequence > N, not the newest."""
    _need_lowest_seq_order()

    import psycopg

    srv = t16b_server
    org_id = srv["org_id"]
    project_id = srv["project_id"]
    alice_id = srv["alice_id"]
    bob_id = srv["bob_id"]  # T16h: publisher is a third admin (ADR 0001 A2)

    cookie, csrf = _make_fresh_session(srv["owner_url"], org_id, bob_id)

    for seq in (40, 41):
        bp = {
            "org_id": org_id,
            "project_id": project_id,
            "sequence": seq,
            "base_sequence": seq - 1,
            "registry_version": 1,
            "environment": "staging",
            "folder_policy": {},
            "governance_policy": {},
            "mcp_policy": {},
            "approval": {"local_fallback": False, "allow_requester": False},
            "change_approvals": [],
            "issued_at": time.time(),
            "not_before": time.time() - 60,
            "expires_at": time.time() + 86400,
        }
        r = _post_bundle(srv, cookie, csrf, project_id, bp, [])
        assert r.status_code == 200, f"seq {seq} failed: {r.status_code} {r.text}"

    conninfo = _conninfo(srv["owner_url"])
    with psycopg.connect(conninfo, autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [org_id])
        device_token = _enroll_device(srv, conn, org_id, project_id, alice_id)

    status, body = _get_bundle(srv, device_token, after=39)
    assert status == 200
    env = body["envelope"]
    assert env["payload"]["sequence"] == 40, (
        f"expected seq 40 (lowest > 39), got {env['payload']['sequence']}"
    )


@pytest.mark.pg
def test_get_bundle_204_when_nothing_newer(t16b_server):
    """GET /sync/bundle?after=<latest> returns 204 when nothing is newer."""
    _need_approvals_served()

    import psycopg

    srv = t16b_server
    org_id = srv["org_id"]
    project_id = srv["project_id"]
    alice_id = srv["alice_id"]
    bob_id = srv["bob_id"]  # T16h: publisher is a third admin (ADR 0001 A2)

    cookie, csrf = _make_fresh_session(srv["owner_url"], org_id, bob_id)
    bp = {
        "org_id": org_id,
        "project_id": project_id,
        "sequence": 50,
        "base_sequence": 0,
        "registry_version": 1,
        "environment": "staging",
        "folder_policy": {},
        "governance_policy": {},
        "mcp_policy": {},
        "approval": {"local_fallback": False, "allow_requester": False},
        "change_approvals": [],
        "issued_at": time.time(),
        "not_before": time.time() - 60,
        "expires_at": time.time() + 86400,
    }
    r = _post_bundle(srv, cookie, csrf, project_id, bp, [])
    assert r.status_code == 200

    conninfo = _conninfo(srv["owner_url"])
    with psycopg.connect(conninfo, autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [org_id])
        device_token = _enroll_device(srv, conn, org_id, project_id, alice_id)

    status, body = _get_bundle(srv, device_token, after=50)
    assert status == 204


# ===================================================================
# T16b-5: Approvals round-trip verbatim
# ===================================================================


@pytest.mark.pg
def test_approvals_round_trip_verbatim(t16b_server):
    """Approvals stored then served are byte-identical to what was published."""
    _need_approvals_stored()

    import psycopg

    srv = t16b_server
    org_id = srv["org_id"]
    project_id = srv["project_id"]
    alice_id = srv["alice_id"]
    bob_id = srv["bob_id"]  # T16h: publisher is a third admin (ADR 0001 A2)

    alice_sk, alice_kid = _route_cli_link(srv, org_id, alice_id)
    admin2_sk, admin2_kid = _route_cli_link(srv, org_id, srv["admin2_id"])

    bundle_payload = {
        "org_id": org_id,
        "project_id": project_id,
        "sequence": 60,
        "base_sequence": 0,
        "registry_version": 1,
        "environment": "staging",
        "folder_policy": {},
        "governance_policy": {},
        "mcp_policy": {},
        "approval": {"local_fallback": False, "allow_requester": False},
        "change_approvals": [],
        "issued_at": time.time(),
        "not_before": time.time() - 60,
        "expires_at": time.time() + 86400,
    }
    appr1 = _make_change_approval(alice_sk, bundle_payload)
    appr2 = _make_change_approval(admin2_sk, bundle_payload)

    cookie, csrf = _make_fresh_session(srv["owner_url"], org_id, bob_id)
    r = _post_bundle(srv, cookie, csrf, project_id, bundle_payload,
                     [appr1, appr2])
    assert r.status_code == 200

    conninfo = _conninfo(srv["owner_url"])
    with psycopg.connect(conninfo, autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [org_id])
        device_token = _enroll_device(srv, conn, org_id, project_id, alice_id)

    status, body = _get_bundle(srv, device_token, after=59)
    assert status == 200

    served = body["change_approvals"]
    assert len(served) == 2

    sent_set = {
        json.dumps(a, sort_keys=True, separators=(",", ":"))
        for a in [appr1, appr2]
    }
    served_set = {
        json.dumps(a, sort_keys=True, separators=(",", ":"))
        for a in served
    }
    assert sent_set == served_set, "approvals did not round-trip verbatim"


# ===================================================================
# T16b-6: bad_change_approvals 400 (ADR 0001 A1 item 1)
#
# Pending security confirmation: grouped for easy removal.
# ===================================================================


@pytest.mark.pg
def test_publish_400_malformed_approval(t16b_server):
    """A malformed approval (not an object with a signatures list) makes
    the publish 400 bad_change_approvals and nothing is stored."""
    _need_bad_approvals_validation()

    import psycopg

    srv = t16b_server
    org_id = srv["org_id"]
    project_id = srv["project_id"]
    alice_id = srv["alice_id"]
    bob_id = srv["bob_id"]  # T16h: publisher is a third admin (ADR 0001 A2)

    bundle_payload = {
        "org_id": org_id,
        "project_id": project_id,
        "sequence": 70,
        "base_sequence": 0,
        "registry_version": 1,
        "environment": "staging",
        "folder_policy": {},
        "governance_policy": {},
        "mcp_policy": {},
        "approval": {"local_fallback": False, "allow_requester": False},
        "change_approvals": [],
        "issued_at": time.time(),
        "not_before": time.time() - 60,
        "expires_at": time.time() + 86400,
    }

    conninfo = _conninfo(srv["owner_url"])
    with psycopg.connect(conninfo, autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [org_id])
        # Guard: project exists -- query targets real data, not a vacuous miss
        assert conn.execute(
            "SELECT 1 FROM projects WHERE id = %s::uuid AND org_id = %s::uuid",
            [project_id, org_id],
        ).fetchone() is not None, "guard: project must exist"
        approvals_before = conn.execute(
            "SELECT count(*) FROM policy_change_approvals "
            "WHERE org_id = %s::uuid",
            [org_id],
        ).fetchone()[0]

    cookie, csrf = _make_fresh_session(srv["owner_url"], org_id, bob_id)
    r = _post_bundle(srv, cookie, csrf, project_id, bundle_payload,
                     ["not-an-envelope"])
    assert r.status_code == 400, f"expected 400, got {r.status_code}"
    assert "bad_change_approvals" in r.text

    # ADR 0001 A1 item 1: nothing is stored after a 400
    with psycopg.connect(conninfo, autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [org_id])
        bundle_row = conn.execute(
            "SELECT 1 FROM policy_bundles "
            "WHERE org_id = %s::uuid AND project_id = %s::uuid "
            "AND sequence = %s",
            [org_id, project_id, 70],
        ).fetchone()
        assert bundle_row is None, (
            "rejected publish must not create a policy_bundles row"
        )
        approvals_after = conn.execute(
            "SELECT count(*) FROM policy_change_approvals "
            "WHERE org_id = %s::uuid",
            [org_id],
        ).fetchone()[0]
        assert approvals_after == approvals_before, (
            f"rejected publish must not insert policy_change_approvals "
            f"(before={approvals_before}, after={approvals_after})"
        )


@pytest.mark.pg
def test_publish_400_key_not_in_approver_keys(t16b_server):
    """An approval whose key_id is not in approver_keys makes the
    publish 400 bad_change_approvals and nothing is stored."""
    _need_bad_approvals_validation()

    import psycopg

    srv = t16b_server
    org_id = srv["org_id"]
    project_id = srv["project_id"]
    alice_id = srv["alice_id"]
    bob_id = srv["bob_id"]  # T16h: publisher is a third admin (ADR 0001 A2)

    bundle_payload = {
        "org_id": org_id,
        "project_id": project_id,
        "sequence": 71,
        "base_sequence": 0,
        "registry_version": 1,
        "environment": "staging",
        "folder_policy": {},
        "governance_policy": {},
        "mcp_policy": {},
        "approval": {"local_fallback": False, "allow_requester": False},
        "change_approvals": [],
        "issued_at": time.time(),
        "not_before": time.time() - 60,
        "expires_at": time.time() + 86400,
    }

    conninfo = _conninfo(srv["owner_url"])
    with psycopg.connect(conninfo, autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [org_id])
        # Guard: project exists -- query targets real data, not a vacuous miss
        assert conn.execute(
            "SELECT 1 FROM projects WHERE id = %s::uuid AND org_id = %s::uuid",
            [project_id, org_id],
        ).fetchone() is not None, "guard: project must exist"
        approvals_before = conn.execute(
            "SELECT count(*) FROM policy_change_approvals "
            "WHERE org_id = %s::uuid",
            [org_id],
        ).fetchone()[0]

    rogue_sk = SigningKey.generate()
    appr = _make_change_approval(rogue_sk, bundle_payload)

    cookie, csrf = _make_fresh_session(srv["owner_url"], org_id, bob_id)
    r = _post_bundle(srv, cookie, csrf, project_id, bundle_payload, [appr])
    assert r.status_code == 400, f"expected 400, got {r.status_code}"
    assert "bad_change_approvals" in r.text

    # ADR 0001 A1 item 1: nothing is stored after a 400
    with psycopg.connect(conninfo, autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [org_id])
        bundle_row = conn.execute(
            "SELECT 1 FROM policy_bundles "
            "WHERE org_id = %s::uuid AND project_id = %s::uuid "
            "AND sequence = %s",
            [org_id, project_id, 71],
        ).fetchone()
        assert bundle_row is None, (
            "rejected publish must not create a policy_bundles row"
        )
        approvals_after = conn.execute(
            "SELECT count(*) FROM policy_change_approvals "
            "WHERE org_id = %s::uuid",
            [org_id],
        ).fetchone()[0]
        assert approvals_after == approvals_before, (
            f"rejected publish must not insert policy_change_approvals "
            f"(before={approvals_before}, after={approvals_after})"
        )


@pytest.mark.pg
def test_publish_400_approval_missing_signatures_list(t16b_server):
    """An approval object with no 'signatures' list is 400 and nothing
    is stored."""
    _need_bad_approvals_validation()

    import psycopg

    srv = t16b_server
    org_id = srv["org_id"]
    project_id = srv["project_id"]
    alice_id = srv["alice_id"]
    bob_id = srv["bob_id"]  # T16h: publisher is a third admin (ADR 0001 A2)

    bundle_payload = {
        "org_id": org_id,
        "project_id": project_id,
        "sequence": 72,
        "base_sequence": 0,
        "registry_version": 1,
        "environment": "staging",
        "folder_policy": {},
        "governance_policy": {},
        "mcp_policy": {},
        "approval": {"local_fallback": False, "allow_requester": False},
        "change_approvals": [],
        "issued_at": time.time(),
        "not_before": time.time() - 60,
        "expires_at": time.time() + 86400,
    }

    conninfo = _conninfo(srv["owner_url"])
    with psycopg.connect(conninfo, autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [org_id])
        # Guard: project exists -- query targets real data, not a vacuous miss
        assert conn.execute(
            "SELECT 1 FROM projects WHERE id = %s::uuid AND org_id = %s::uuid",
            [project_id, org_id],
        ).fetchone() is not None, "guard: project must exist"
        approvals_before = conn.execute(
            "SELECT count(*) FROM policy_change_approvals "
            "WHERE org_id = %s::uuid",
            [org_id],
        ).fetchone()[0]

    bad_appr = {"kind": "agg/policy-change/v1", "sig_v": 1,
                "payload": {"bundle_hash": "abc"}}

    cookie, csrf = _make_fresh_session(srv["owner_url"], org_id, bob_id)
    r = _post_bundle(srv, cookie, csrf, project_id, bundle_payload,
                     [bad_appr])
    assert r.status_code == 400, f"expected 400, got {r.status_code}"
    assert "bad_change_approvals" in r.text

    # ADR 0001 A1 item 1: nothing is stored after a 400
    with psycopg.connect(conninfo, autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [org_id])
        bundle_row = conn.execute(
            "SELECT 1 FROM policy_bundles "
            "WHERE org_id = %s::uuid AND project_id = %s::uuid "
            "AND sequence = %s",
            [org_id, project_id, 72],
        ).fetchone()
        assert bundle_row is None, (
            "rejected publish must not create a policy_bundles row"
        )
        approvals_after = conn.execute(
            "SELECT count(*) FROM policy_change_approvals "
            "WHERE org_id = %s::uuid",
            [org_id],
        ).fetchone()[0]
        assert approvals_after == approvals_before, (
            f"rejected publish must not insert policy_change_approvals "
            f"(before={approvals_before}, after={approvals_after})"
        )


# ===================================================================
# T16b-7: e2e -- publish 2-approval loosening, connector applies
#          through the pull path
# ===================================================================


@pytest.mark.pg
def test_e2e_publish_and_connector_applies(t16b_server, tmp_path, monkeypatch):
    """E2e: publish a 2-approval loosening; the connector applies it
    through the pull path (GET /sync/bundle)."""
    # Both server-side (stored+served) and client-side (_fetch_bundle) needed
    _need_approvals_stored()

    import psycopg

    srv = t16b_server
    org_id = srv["org_id"]
    project_id = srv["project_id"]
    alice_id = srv["alice_id"]
    bob_id = srv["bob_id"]  # T16h: publisher is a third admin (ADR 0001 A2)

    alice_sk, alice_kid = _route_cli_link(srv, org_id, alice_id)
    admin2_sk, admin2_kid = _route_cli_link(srv, org_id, srv["admin2_id"])

    # Earlier tests published bundles at seq 1-72 in the same project
    # (module-scoped fixture).  Use seq 79/80 so GET /sync/bundle?after=79
    # returns our bundle, not an earlier one.
    bundle_payload = {
        "org_id": org_id,
        "project_id": project_id,
        "sequence": 80,
        "base_sequence": 79,
        "registry_version": 1,
        "environment": "staging",
        "folder_policy": {},
        "governance_policy": {},
        "mcp_policy": {},
        "approval": {"local_fallback": False, "allow_requester": False},
        "change_approvals": [],
        "issued_at": time.time(),
        "not_before": time.time() - 60,
        "expires_at": time.time() + 86400,
    }
    appr1 = _make_change_approval(alice_sk, bundle_payload)
    appr2 = _make_change_approval(admin2_sk, bundle_payload)

    cookie, csrf = _make_fresh_session(srv["owner_url"], org_id, bob_id)
    r = _post_bundle(srv, cookie, csrf, project_id, bundle_payload,
                     [appr1, appr2])
    assert r.status_code == 200, f"publish failed: {r.status_code} {r.text}"

    bs_pub = srv["bundle_signer_pub"]
    bs_kid = hashlib.sha256(bs_pub).hexdigest()
    bs_entry = (srv["bundle_signer_sk"], bs_pub, bs_kid)

    admin_sks = [
        (alice_sk, bytes(alice_sk.verify_key), alice_kid),
        (admin2_sk, bytes(admin2_sk.verify_key), admin2_kid),
    ]

    # Seed the local workspace at seq 79 so _fetch_bundle requests after=79
    ctx = _setup_managed_workspace(
        tmp_path, monkeypatch,
        admin_sks=admin_sks,
        bundle_signer_sk=bs_entry,
        org_id=org_id,
        project_id=project_id,
        policy_sequence=79,
    )
    lay = ctx["lay"]
    # Keep the seed bundle at sequence 79: load_verified_state needs it.

    from sandbox.connector.sync.process import SyncProcess, run_once
    from sandbox.connector.sync.state import current_sequence

    conninfo = _conninfo(srv["owner_url"])
    with psycopg.connect(conninfo, autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [org_id])
        device_token = _enroll_device(srv, conn, org_id, project_id, alice_id)

    import httpx

    def real_connect(method, url, body=None, headers=None, token=None):
        hdrs = dict(headers or {})
        hdrs.setdefault("Content-Type", "application/json")
        if token:
            hdrs["Authorization"] = f"Bearer {token}"
        data = json.dumps(body).encode() if isinstance(body, dict) else body

        if method == "GET":
            r = httpx.get(url, headers=hdrs, timeout=10, verify=False)
        else:
            r = httpx.request(method, url, content=data, headers=hdrs,
                              timeout=10, verify=False)

        try:
            bd = r.json()
        except Exception:
            bd = {}
        return (r.status_code, bd, dict(r.headers))

    # Read the device key written by _setup_managed_workspace (connector_dev-1.seed)
    kh = Path(os.environ["SANDBOX_KEY_HOME"])
    ws_id = (lay.base / "workspace_id").read_text(encoding="utf-8").strip()
    dev_seed_file = kh / ws_id / "connector_dev-1.seed"
    device_key = dev_seed_file.read_bytes()

    sync = SyncProcess(
        lay, srv["base_url"], device_key, "dev-1",
        connect=real_connect,
    )
    sync._token = device_token
    sync._token_expires = time.monotonic() + 600

    run_once(sync)

    seq = current_sequence(lay)
    assert seq == 80, f"expected sequence 80 after pull, got {seq}"
