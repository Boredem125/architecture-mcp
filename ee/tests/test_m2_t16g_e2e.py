"""T16g tests-first: G7-A bootstrap, G7-B audit upload contract, and
founder-ruled additions (verify_project, registry_version check).

These tests use the REAL ``SyncProcess`` (``run_once``) with its real
``urllib`` transport over HTTP against the real ee sync app (Postgres +
4-worker uvicorn).  NO fake ``_connect``: fakes hid both bugs.

G7-A (HANDOFF 4 Nov, security L)
--------------------------------
Right after ``sandbox enroll`` (no bundle.json) ``_fetch_bundle``
(src/sandbox/connector/sync/process.py:597-601) refuses every bundle with
``no_verified_state`` because ``load_verified_state``
(src/sandbox/connector/sync/verified_state.py:52-55) needs a verified
bundle.  The fix is a separate bootstrap loader used only by
``_fetch_bundle`` (pinned_root + verify_chain(registry.json) + the bundle
signer from that verified registry; org_id from the root-signed genesis ==
enrollment.json org_id; project_id from enrollment.json; high_water with
bundle_sequence == 0; two distinct CLI approvals for the loosening vs the
deny-all base; never a registry/root/key from the server or the bundle).

G7-B (HANDOFF 4 Nov, security L)
--------------------------------
Connector audit upload (src/sandbox/connector/sync/audit_upload.py:176-190)
POSTs one record per request with top-level chain fields; the server
(ee/src/agg_cp/sync/audit_upload.py:124-131) needs
``{"session_id", "records": [...]}`` and stores nothing.
``process.py:795`` swallows every exception with a log line: no
``audit_fork`` on 409, no ``audit_truncation_local`` when the cursor is
ahead of the local chain, no ``audit_upload_failed`` on 4xx/5xx, no
checkpoint after a failed upload.

Founder rulings (4 Nov)
-----------------------
1. ``verify_project`` (ee/src/agg_cp/sync/audit.py:182-183) returns ok on
   zero rows and never recomputes ``record_hash``: both must change.
2. ``verify_and_apply`` step 8 (src/sandbox/connector/sync/bundles.py:501-504)
   checks ``registry_version < 1``; it must refuse anything below the
   verified (pinned) registry version (ADR 0001 A2.5).
3. G7-C (``sandbox status`` quarantine) is a named limit: no test.

All target tests pass since T16g (they were strict xfail until the product
code was built).  Each asserts on the product behaviour, never on a harness
error.  Guard twins (unchanged) prove the harness works.
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import time
import uuid
from pathlib import Path
from typing import Any

import psycopg
import pytest
from nacl.signing import SigningKey

from .m2_sync_server import (
    make_sync_server, create_project, keygen, sign_envelope,
)
from .t9_helpers import seed_session, make_session_cookie
from .fake_idp import FakeClock


# ---------------------------------------------------------------------------
# Marker: only the targeted assertion counts as the expected failure.  A
# fixture, import, transport or server error shows as ERROR/FAIL.
# ---------------------------------------------------------------------------


NO_VS = "no_verified_state"  # today's blanket refusal reason (G7-A)


# ---------------------------------------------------------------------------
# Helpers (copied from t16b/t12b_e2e -- DO NOT import from root tests/)
# ---------------------------------------------------------------------------


def _conninfo(url: str) -> str:
    return url.replace("+psycopg", "")


def _seed_user_row(conn, org_id: str, email: str) -> str:
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


def _route_cli_link(srv, org_id, user_id):
    """Route a CLI key through /signer-links -> /signer/link.  Returns (sk, kid)."""
    import httpx
    cookie, csrf = _make_fresh_session(srv["owner_url"], org_id, user_id)
    r = httpx.post(
        f"{srv['base_url']}/api/v1/signer-links",
        cookies={"__Host-agg_session": cookie},
        headers={"X-CSRF-Token": csrf},
        json={},
        timeout=10,
    )
    assert r.status_code == 200, f"signer-links failed: {r.status_code} {r.text}"
    code = r.json()["code"]
    sk = SigningKey.generate()
    kid = hashlib.sha256(bytes(sk.verify_key)).hexdigest()
    r2 = httpx.post(
        f"{srv['base_url']}/api/v1/sync/signer/link",
        json={"code": code, "key_id": kid,
              "public_key": bytes(sk.verify_key).hex()},
        timeout=10,
    )
    assert r2.status_code == 200, f"link failed: {r2.status_code} {r2.text}"
    return sk, kid


def _issue_code_ready(conn, org_id, project_id, operator_user_id):
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


def _enroll_device(srv, conn, org_id, project_id, operator_user_id,
                   device_sk: SigningKey):
    """Enroll *device_sk* via the routes (T8 PoP) and get a device token.

    Returns ``(device_token, device_id)``.  The same key must be the one
    the SyncProcess signs checkpoints with (the server verifies the
    checkpoint against the enrolled public key)."""
    code, code_hash, code_id = _issue_code_ready(
        conn, org_id, project_id, operator_user_id,
    )
    import httpx

    device_pub_hex = bytes(device_sk.verify_key).hex()

    proof_payload = {
        "code_hash": code_hash,
        "public_key": device_pub_hex,
        "aud": "test",
        "iat": time.time(),
    }
    proof = sign_envelope("agg/device-enroll/v1", proof_payload, device_sk)

    r = httpx.post(
        f"{srv['base_url']}/api/v1/sync/enroll",
        json={"code": code, "public_key": device_pub_hex, "proof": proof},
        timeout=10,
    )
    assert r.status_code == 200, f"enroll failed: {r.status_code} {r.text}"
    device_id = r.json().get("device_id", "")
    assert device_id, f"enroll returned no device_id: {r.text}"

    assertion = sign_envelope("agg/device-assert/v1", {
        "device_id": device_id,
        "aud": "test",
        "iat": time.time(),
        "nonce": secrets.token_hex(16),
    }, device_sk)
    r2 = httpx.post(
        f"{srv['base_url']}/api/v1/sync/token",
        json={"device_id": device_id, "assertion": assertion},
        timeout=10,
    )
    assert r2.status_code == 200, f"token failed: {r2.status_code} {r2.text}"
    return r2.json()["token"], device_id


def _d4_seed_genesis_code(conn, org_id):
    import datetime as dt
    code = secrets.token_urlsafe(24)
    code_hash = hashlib.sha256(code.encode()).hexdigest()
    now = dt.datetime.now(dt.timezone.utc)
    expires_at = now + dt.timedelta(minutes=60)
    conn.execute(
        "INSERT INTO setup_codes "
        "(id, org_id, code_hash, created_at, expires_at, purpose) "
        "VALUES (%s, %s, %s, %s, %s, 'registry_genesis')",
        [str(uuid.uuid4()), org_id, code_hash, now, expires_at],
    )
    return code


def _d4_get_signer_token(base_url, sk, kid):
    import httpx
    nonce = secrets.token_hex(16)
    payload = {"key_id": kid, "nonce": nonce, "aud": base_url, "iat": time.time()}
    tag = b"agg/signer-assert/v1"
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    msg = tag + b"\x00" + canonical
    sig = sk.sign(msg).signature.hex()
    assertion = {
        "kind": "agg/signer-assert/v1", "sig_v": 1,
        "payload": payload,
        "signatures": [{"key_id": kid, "alg": "ed25519", "sig": sig}],
    }
    r = httpx.post(f"{base_url}/api/v1/sync/signer/token",
                   json=assertion, timeout=10)
    assert r.status_code == 200, f"token failed: {r.status_code} {r.text}"
    return r.json()["token"]


def _d4_user_oidc(conn, user_id):
    row = conn.execute(
        "SELECT oidc_issuer, oidc_subject FROM users WHERE id = %s::uuid",
        [user_id],
    ).fetchone()
    assert row is not None, f"user {user_id} not found"
    return row[0], row[1]


def _build_registry(admin_sks, approver_sks=(), *, org_id,
                    bundle_signer_sk=None):
    """Build a signed registry genesis.  Returns ([genesis_env], fingerprint)."""
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


def _bundle_payload(*, org_id, project_id, sequence, base_sequence=0,
                    environment="staging", registry_version=1):
    return {
        "org_id": org_id,
        "project_id": project_id,
        "sequence": sequence,
        "base_sequence": base_sequence,
        "registry_version": registry_version,
        "environment": environment,
        "folder_policy": {},
        "governance_policy": {},
        "mcp_policy": {},
        "approval": {"local_fallback": False, "allow_requester": False},
        "change_approvals": [],
        "issued_at": time.time(),
        "not_before": time.time() - 60,
        "expires_at": time.time() + 86400,
    }


def _build_signed_bundle(bundle_signer_sk, *, org_id, project_id,
                         environment="staging", policy_sequence=1,
                         registry_version=1, base_sequence=0):
    """Build a signed bundle envelope."""
    bs_sk, bs_pub, bs_kid = bundle_signer_sk
    bundle_payload = _bundle_payload(
        org_id=org_id, project_id=project_id, sequence=policy_sequence,
        base_sequence=base_sequence, environment=environment,
        registry_version=registry_version,
    )
    tag = "agg/bundle/v1"
    canonical = json.dumps(bundle_payload, sort_keys=True,
                           separators=(",", ":")).encode()
    msg = tag.encode("utf-8") + b"\x00" + canonical
    sig = bs_sk.sign(msg).signature.hex()
    return {
        "kind": tag,
        "sig_v": 1,
        "payload": bundle_payload,
        "signatures": [{"key_id": bs_kid, "alg": "ed25519", "sig": sig}],
    }


def _setup_managed_workspace(
    tmp_path, monkeypatch, *, admin_sks=None, approver_sks=None,
    bundle_signer_sk=None, org_id="org-1", project_id="proj-1",
    policy_sequence=1, write_bundle=True, registry_envelopes=None,
    registry_fp=None,
):
    """Set up a managed workspace with pinned registry and (optionally)
    a signed bundle.  Returns dict with lay, registry, fp, etc.

    The device key (``connector_sk``) is generated here; ``_bind_device``
    enrols that same key and writes the server's device_id back."""
    from sandbox.connector.install import init
    from sandbox.connector.layout import FolderLayout

    kh = tmp_path / "keyhome"
    kh.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("SANDBOX_KEY_HOME", str(kh))

    ws = tmp_path / "ws"
    ws.mkdir(parents=True, exist_ok=True)
    init(ws, claude=False, mcp=False)
    lay = FolderLayout(ws)

    ws_id = f"t16g-{uuid.uuid4().hex[:24]}"
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

    if registry_envelopes is not None and registry_fp is not None:
        envelopes, fp = registry_envelopes, registry_fp
    else:
        envelopes, fp = _build_registry(
            admin_sks, approver_sks,
            org_id=org_id, bundle_signer_sk=bundle_signer_sk,
        )

    (sync_dir / "pinned_root.json").write_text(
        json.dumps({"fingerprint": fp}), encoding="utf-8")
    (sync_dir / "registry.json").write_text(
        json.dumps(envelopes), encoding="utf-8")

    if write_bundle:
        bundle_env = _build_signed_bundle(
            bundle_signer_sk,
            org_id=org_id,
            project_id=project_id,
            policy_sequence=policy_sequence,
        )
        (sync_dir / "bundle.json").write_text(
            json.dumps(bundle_env), encoding="utf-8")

    device_id_val = f"dev-{uuid.uuid4().hex[:8]}"  # replaced by _bind_device
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

    (sync_dir / "server_time_state.json").write_text(json.dumps({
        "server_time": time.time(), "local_time": time.time(),
    }), encoding="utf-8")

    hw = {"registry_version": 1}
    if write_bundle:
        hw["bundle_sequence"] = policy_sequence
    else:
        hw["bundle_sequence"] = 0
    (sync_dir / "high_water.json").write_text(
        json.dumps(hw), encoding="utf-8")

    return {
        "lay": lay,
        "registry": envelopes,
        "fingerprint": fp,
        "admin_sks": admin_sks,
        "bundle_signer_sk": bundle_signer_sk,
        "device_id": device_id_val,
        "connector_sk": connector_sk,
        "ws_id": ws_id,
        "kh": kh,
        "sync_dir": sync_dir,
    }


def _bind_device(srv, ctx, org_id, project_id, operator_user_id):
    """Enrol the workspace's own device key and write the real device_id
    into enrollment.json / device_id.  Returns the device token."""
    conninfo = _conninfo(srv["owner_url"])
    with psycopg.connect(conninfo, autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        token, device_id = _enroll_device(
            srv, conn, org_id, project_id, operator_user_id,
            ctx["connector_sk"],
        )
    sync_dir = ctx["sync_dir"]
    enrollment = json.loads(
        (sync_dir / "enrollment.json").read_text(encoding="utf-8"))
    enrollment["device_id"] = device_id
    (sync_dir / "enrollment.json").write_text(
        json.dumps(enrollment), encoding="utf-8")
    (sync_dir / "device_id").write_text(device_id, encoding="utf-8")
    ctx["device_id"] = device_id
    return token


def _make_sync_process(srv, ctx, device_token):
    """Instantiate a real SyncProcess with its REAL default transport
    (urllib, loopback http) -- no ``connect=`` seam."""
    from sandbox.connector.sync.process import SyncProcess

    sp = SyncProcess(
        ctx["lay"], srv["base_url"], bytes(ctx["connector_sk"]),
        ctx["device_id"],
    )
    sp._token = device_token
    sp._token_expires = time.monotonic() + 600
    return sp


def _run_cycle(sp):
    from sandbox.connector.sync.process import run_once
    run_once(sp)


def _post_bundle_admin(srv, cookie, csrf, project_id, bundle_payload,
                       change_approvals):
    """POST /api/v1/admin/bundles.  Returns httpx.Response."""
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
    )


def _publish(srv, project_id, bundle_payload, approvals):
    """Publish through BOB's admin session (security W HIGH, 4 Nov): the
    proposer is a third admin with no CLI key, so alice + admin2 are two
    distinct approvers who are both NOT the proposer (ADR 0001 A1.11,
    A2.3).  Publishing as alice would let a fix that forgets to exclude
    the proposer pass."""
    cookie, csrf = _make_fresh_session(
        srv["owner_url"], srv["org_id"], srv["bob_id"])
    r = _post_bundle_admin(srv, cookie, csrf, project_id, bundle_payload,
                           approvals)
    assert r.status_code == 200, f"publish failed: {r.status_code} {r.text}"


def _make_change_approval(sk, bundle_payload):
    """Build a signed agg/policy-change/v1 envelope over the bundle hash."""
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


def _new_project(srv, name="T16g per-test project") -> str:
    """A fresh project: GET /sync/bundle serves the lowest sequence above
    ``after`` per project, so bundles published by one test must not be
    served to another."""
    project_id = str(uuid.uuid4())
    conninfo = _conninfo(srv["owner_url"])
    with psycopg.connect(conninfo, autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [srv["org_id"]])
        create_project(conn, srv["org_id"], project_id, name)
    return project_id


def _admins(srv):
    """Route two fresh CLI keys for alice and admin2; returns the
    ``admin_sks`` triples plus the two signing keys."""
    alice_sk, alice_kid = _route_cli_link(srv, srv["org_id"], srv["alice_id"])
    admin2_sk, admin2_kid = _route_cli_link(srv, srv["org_id"], srv["admin2_id"])
    admin_sks = [
        (alice_sk, bytes(alice_sk.verify_key), alice_kid),
        (admin2_sk, bytes(admin2_sk.verify_key), admin2_kid),
    ]
    return admin_sks, alice_sk, admin2_sk


def _bs_entry(srv):
    bs_pub = srv["bundle_signer_pub"]
    return (srv["bundle_signer_sk"], bs_pub, hashlib.sha256(bs_pub).hexdigest())


def _bundle_refused_reasons(lay) -> list[str]:
    """Reasons of every ``bundle_refused`` record in the local 'sync'
    audit session (what ``_audit_bundle_refused`` writes)."""
    path = lay.audit_dir / "sync" / "records.jsonl"
    out: list[str] = []
    if not path.is_file():
        return out
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        if rec.get("event") == "bundle_refused":
            out.append(str(rec.get("reason", "")))
    return out


def _local_alerts(lay, event: str) -> list[dict]:
    """Alerts in ``.sandbox/logs/alerts.jsonl`` with the given event."""
    from sandbox.connector.alerts import read_alerts
    return [a for a in read_alerts(lay, limit=500) if a.get("event") == event]


def _local_audit_events(lay, event: str) -> list[dict]:
    """Audit records with the given event in every local session."""
    out: list[dict] = []
    if not lay.audit_dir.is_dir():
        return out
    for path in lay.audit_dir.rglob("records.jsonl"):
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                rec = json.loads(line)
            except ValueError:
                continue
            if rec.get("event") == event:
                out.append(rec)
    return out


def _seed_local_audit(lay, session_id: str, n_records: int) -> list[dict]:
    """Append ``n_records`` through the REAL ``FolderAudit`` (real hash
    formula: record_hash = sha256(canonical body)).  Returns the chained
    records as written."""
    from sandbox.connector.audit import FolderAudit
    audit = FolderAudit(lay.audit_dir, session_id=session_id)
    for i in range(1, n_records + 1):
        audit.append({"event": f"t16g_event_{i}", "ts": time.time(),
                      "nonce": uuid.uuid4().hex})
    return _read_local_chain(lay, session_id)


def _read_local_chain(lay, session_id: str) -> list[dict]:
    path = lay.audit_dir / session_id / "records.jsonl"
    return [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines()
            if l.strip()]


def _write_local_chain(lay, session_id: str, records: list[dict]) -> None:
    path = lay.audit_dir / session_id / "records.jsonl"
    path.write_text("".join(json.dumps(r) + "\n" for r in records),
                    encoding="utf-8")


def _set_cursor(ctx, session_id: str, chain_length: int, head_hash: str,
                upload_seq: int | None = None) -> None:
    """Rewrite the real cursor file (format of audit_upload.AuditUploader)."""
    path = ctx["sync_dir"] / "cursor.json"
    try:
        cursor = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        cursor = {"sessions": {}, "upload_seq": 0}
    cursor.setdefault("sessions", {})[session_id] = {
        "chain_length": chain_length, "head_hash": head_hash,
    }
    if upload_seq is not None:
        cursor["upload_seq"] = upload_seq
    path.write_text(json.dumps(cursor), encoding="utf-8")


def _read_cursor(ctx) -> dict:
    return json.loads((ctx["sync_dir"] / "cursor.json").read_text(encoding="utf-8"))


def _server_rows(srv, sql: str, params: list) -> list:
    conninfo = _conninfo(srv["owner_url"])
    with psycopg.connect(conninfo, autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [srv["org_id"]])
        return conn.execute(sql, params).fetchall()


def _real_record_hash(body: dict) -> str:
    """The connector's record_hash formula (sandbox/connector/audit.py)."""
    return hashlib.sha256(
        json.dumps(body, separators=(",", ":"), sort_keys=True).encode("utf-8")
    ).hexdigest()


# ---------------------------------------------------------------------------
# Module-scoped server fixture
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def t16g_server(pg_url, app_url, owner_url, pg_roles, tmp_path_factory):
    """Server for T16g e2e tests.  Seeds org, project, users, registry."""
    bundle_signer_sk = SigningKey.generate()
    key_dir = tmp_path_factory.mktemp("t16g_bundle_signer")
    key_file = key_dir / "bundle_signer.key"
    key_file.write_bytes(bytes(bundle_signer_sk).hex().encode("ascii"))
    old_bs = os.environ.get("AGG_BUNDLE_SIGNER_KEY_FILE")
    os.environ["AGG_BUNDLE_SIGNER_KEY_FILE"] = str(key_file)

    gen = make_sync_server(
        pg_url, app_url, owner_url,
        org_names=["T16g Org"],
    )
    info = next(gen)

    conninfo = _conninfo(owner_url)
    with psycopg.connect(conninfo, autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [info["org_id"]])
        alice_id = _seed_user_row(conn, info["org_id"], "alice@t16g.test")
        admin2_id = _seed_user_row(conn, info["org_id"], "admin2@t16g.test")
        # bob: third admin, publishes every bundle, never holds a CLI key
        bob_id = _seed_user_row(conn, info["org_id"], "bob@t16g.test")

        for uid in (alice_id, admin2_id, bob_id):
            conn.execute(
                "INSERT INTO role_bindings "
                "(id, org_id, user_id, scope_type, scope_id, role, created_at) "
                "VALUES (%s, %s, %s, 'org', %s, 'admin', now())",
                [str(uuid.uuid4()), info["org_id"], uid, info["org_id"]],
            )

        project_id = str(uuid.uuid4())
        create_project(conn, info["org_id"], project_id, "T16g Project")

    info["alice_id"] = alice_id
    info["admin2_id"] = admin2_id
    info["bob_id"] = bob_id
    info["project_id"] = project_id
    info["bundle_signer_sk"] = bundle_signer_sk
    info["bundle_signer_pub"] = bytes(bundle_signer_sk.verify_key)

    # Server-side registry through routes (genesis + v2 with admin2)
    alice_sk, alice_kid = _route_cli_link(info, info["org_id"], alice_id)
    with psycopg.connect(conninfo, autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [info["org_id"]])
        genesis_code = _d4_seed_genesis_code(conn, info["org_id"])
        alice_iss, alice_sub = _d4_user_oidc(conn, alice_id)
    admin1_token = _d4_get_signer_token(info["base_url"], alice_sk, alice_kid)

    bs_pub = info["bundle_signer_pub"]
    bs_kid = hashlib.sha256(bs_pub).hexdigest()

    g_payload = {
        "org_id": info["org_id"], "version": 1, "prev_hash": "",
        "threshold": 1,
        "admins": [alice_kid],
        "keys": [{
            "key_id": alice_kid,
            "public_key": bytes(alice_sk.verify_key).hex(),
            "kind": "cli", "alg": "ed25519",
            "user_id": alice_id,
            "iss": alice_iss,
            "sub": alice_sub,
            "roles": ["admin", "approver"],
            "added_in": 1,
        }],
        "bundle_signer": {"key_id": bs_kid, "public_key": bs_pub.hex()},
        "expires_at": time.time() + 7 * 24 * 3600,
    }
    g_canonical = json.dumps(g_payload, sort_keys=True,
                             separators=(",", ":")).encode()
    g_msg = b"agg/registry/v1\x00" + g_canonical
    g_sig = alice_sk.sign(g_msg).signature.hex()
    g_env = {
        "kind": "agg/registry/v1", "sig_v": 1,
        "payload": g_payload,
        "signatures": [{"key_id": alice_kid, "alg": "ed25519", "sig": g_sig}],
    }

    import httpx
    r = httpx.post(
        f"{info['base_url']}/api/v1/sync/signer/genesis",
        json={"genesis_code": genesis_code, "envelope": g_env},
        headers={"Authorization": f"Bearer {admin1_token}"},
        timeout=15,
    )
    assert r.status_code == 200, f"genesis failed: {r.status_code} {r.text}"

    root_fp = hashlib.sha256(
        info["org_id"].encode("utf-8") + b":" + g_canonical
    ).hexdigest()

    # v2: add admin2 with threshold 2
    admin2_sk, admin2_kid = _route_cli_link(info, info["org_id"], admin2_id)
    with psycopg.connect(conninfo, autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [info["org_id"]])
        admin2_iss, admin2_sub = _d4_user_oidc(conn, admin2_id)

    v2_keys = g_payload["keys"] + [{
        "key_id": admin2_kid,
        "public_key": bytes(admin2_sk.verify_key).hex(),
        "kind": "cli", "alg": "ed25519",
        "user_id": admin2_id,
        "iss": admin2_iss, "sub": admin2_sub,
        "roles": ["admin", "approver"],
        "added_in": 2,
    }]
    v2_payload = {
        "org_id": info["org_id"], "version": 2, "prev_hash": root_fp,
        "threshold": 2,
        "admins": [alice_kid, admin2_kid],
        "keys": v2_keys,
        "bundle_signer": g_payload["bundle_signer"],
        "expires_at": g_payload["expires_at"],
    }
    v2_canonical = json.dumps(v2_payload, sort_keys=True,
                              separators=(",", ":")).encode()
    v2_msg = b"agg/registry/v1\x00" + v2_canonical
    v2_env = {
        "kind": "agg/registry/v1", "sig_v": 1,
        "payload": v2_payload,
        "signatures": [
            {"key_id": alice_kid, "alg": "ed25519",
             "sig": alice_sk.sign(v2_msg).signature.hex()},
            {"key_id": admin2_kid, "alg": "ed25519",
             "sig": admin2_sk.sign(v2_msg).signature.hex()},
        ],
    }
    admin1_confirmed = _d4_get_signer_token(info["base_url"], alice_sk, alice_kid)
    r_v2 = httpx.post(
        f"{info['base_url']}/api/v1/sync/signer/signatures",
        json={"type": "registry", "envelope": v2_env, "org_id": info["org_id"]},
        headers={"Authorization": f"Bearer {admin1_confirmed}"},
        timeout=15,
    )
    assert r_v2.status_code == 200, f"v2 failed: {r_v2.status_code} {r_v2.text}"

    info["root_fp"] = root_fp

    try:
        yield info
    finally:
        gen.close()
        if old_bs is None:
            os.environ.pop("AGG_BUNDLE_SIGNER_KEY_FILE", None)
        else:
            os.environ["AGG_BUNDLE_SIGNER_KEY_FILE"] = old_bs


# ===================================================================
# GUARD TWIN (non-xfail): existing bundle-present path still applies
# ===================================================================


@pytest.mark.pg
def test_guard_bundle_applies_with_existing_bundle(t16g_server, tmp_path, monkeypatch):
    """Guard twin: when a bundle.json already exists, SyncProcess.run_once
    fetches and applies the next bundle normally.  This proves the harness
    (real server, real HTTP, real SyncProcess, real device key) works."""
    from sandbox.connector.sync.state import current_sequence

    srv = t16g_server
    org_id = srv["org_id"]
    project_id = _new_project(srv)
    admin_sks, alice_sk, admin2_sk = _admins(srv)

    payload = _bundle_payload(org_id=org_id, project_id=project_id,
                              sequence=100, base_sequence=99)
    _publish(srv, project_id, payload, [
        _make_change_approval(alice_sk, payload),
        _make_change_approval(admin2_sk, payload),
    ])

    ctx = _setup_managed_workspace(
        tmp_path, monkeypatch, admin_sks=admin_sks,
        bundle_signer_sk=_bs_entry(srv), org_id=org_id,
        project_id=project_id, policy_sequence=99, write_bundle=True,
    )
    token = _bind_device(srv, ctx, org_id, project_id, srv["alice_id"])
    _run_cycle(_make_sync_process(srv, ctx, token))

    seq = current_sequence(ctx["lay"])
    assert seq == 100, f"guard: expected sequence 100, got {seq}"
    assert _bundle_refused_reasons(ctx["lay"]) == []


# ===================================================================
# G7-A: bootstrap -- first bundle right after enroll
# ===================================================================


# G7-A (HANDOFF 4 Nov): bootstrap loader for _fetch_bundle; expected change
# src/sandbox/connector/sync/process.py:597-601 (+ a new loader beside
# verified_state.py:52-55; load_verified_state itself never relaxed).
@pytest.mark.pg
def test_first_bundle_applies_right_after_enroll(t16g_server, tmp_path, monkeypatch):
    """Right after enroll (no bundle.json) run_once must fetch and apply the
    first bundle (seq 1, base 0, two distinct CLI approvals) through the
    bootstrap path, then write high_water.  Today: refused
    ``no_verified_state`` and the sequence stays None."""
    from sandbox.connector.sync.state import current_sequence
    from sandbox.connector.sync.verified_state import load_verified_state

    srv = t16g_server
    org_id = srv["org_id"]
    project_id = _new_project(srv)
    admin_sks, alice_sk, admin2_sk = _admins(srv)

    payload = _bundle_payload(org_id=org_id, project_id=project_id, sequence=1)
    _publish(srv, project_id, payload, [
        _make_change_approval(alice_sk, payload),
        _make_change_approval(admin2_sk, payload),
    ])

    ctx = _setup_managed_workspace(
        tmp_path, monkeypatch, admin_sks=admin_sks,
        bundle_signer_sk=_bs_entry(srv), org_id=org_id,
        project_id=project_id, write_bundle=False,  # the G7-A scenario
    )
    token = _bind_device(srv, ctx, org_id, project_id, srv["alice_id"])
    assert load_verified_state(ctx["lay"]) is None, (
        "before the first bundle, load_verified_state must be None "
        "(decision paths stay closed; the loader is never relaxed)"
    )
    _run_cycle(_make_sync_process(srv, ctx, token))

    seq = current_sequence(ctx["lay"])
    assert seq == 1, (
        f"G7-A: expected sequence 1 after bootstrap, got {seq}; "
        f"bundle_refused reasons={_bundle_refused_reasons(ctx['lay'])}"
    )
    assert (ctx["sync_dir"] / "bundle.json").is_file()
    assert load_verified_state(ctx["lay"]) is not None, (
        "after the first bundle applied, load_verified_state must verify it"
    )
    hw = json.loads((ctx["sync_dir"] / "high_water.json").read_text(encoding="utf-8"))
    assert hw.get("bundle_sequence") == 1, f"high_water not advanced: {hw}"


# G7-A (HANDOFF 4 Nov): first bundle vs the deny-all base needs 2 distinct
# CLI user_ids; expected change src/sandbox/connector/sync/process.py:597-601.
@pytest.mark.pg
def test_first_bundle_one_approval_refused(t16g_server, tmp_path, monkeypatch):
    """A first bundle with only one approval is refused BY THE APPROVAL
    CHECK (the bootstrap path reached verify_and_apply), not by the blanket
    ``no_verified_state``.  Today the audited reason is ``no_verified_state``."""
    from sandbox.connector.sync.state import current_sequence
    from sandbox.connector.sync.verified_state import load_verified_state

    srv = t16g_server
    org_id = srv["org_id"]
    project_id = _new_project(srv)
    admin_sks, alice_sk, admin2_sk = _admins(srv)

    payload = _bundle_payload(org_id=org_id, project_id=project_id, sequence=1)
    _publish(srv, project_id, payload, [_make_change_approval(alice_sk, payload)])

    ctx = _setup_managed_workspace(
        tmp_path, monkeypatch, admin_sks=admin_sks,
        bundle_signer_sk=_bs_entry(srv), org_id=org_id,
        project_id=project_id, write_bundle=False,
    )
    token = _bind_device(srv, ctx, org_id, project_id, srv["alice_id"])
    _run_cycle(_make_sync_process(srv, ctx, token))

    seq = current_sequence(ctx["lay"])
    assert seq is None, f"one approval must not apply, got seq={seq}"
    assert not (ctx["sync_dir"] / "bundle.json").exists()
    assert load_verified_state(ctx["lay"]) is None, "refused: no verified state"
    reasons = _bundle_refused_reasons(ctx["lay"])
    assert reasons, "no bundle_refused audit record"
    assert reasons[-1] != NO_VS and "approvals" in reasons[-1], (
        f"refusal must come from the approval check, got {reasons[-1]!r}"
    )


# G7-A (HANDOFF 4 Nov): environment only from the bundle (absent = prod;
# non-prod is a loosening) -> two approvals; expected change
# src/sandbox/connector/sync/process.py:597-601.
@pytest.mark.pg
def test_first_bundle_nonprod_needs_two(t16g_server, tmp_path, monkeypatch):
    """A first non-prod bundle: one approval -> refused by the approval
    check; two distinct CLI approvals -> applied and the connector reports
    the non-prod environment (gate step 4 N4).

    Note (security W LOW, 4 Nov): with a deny-all base EVERY first bundle
    is a loosening and needs two approvals, so workspace A does not prove
    that the non-prod environment by itself is the loosening; this node
    mirrors gate step 4 N4.  The environment-loosening property is covered
    by the ``_loosened_environment`` tests."""
    from sandbox.connector.sync.state import current_sequence, current_environment
    from sandbox.connector.sync.verified_state import load_verified_state

    srv = t16g_server
    org_id = srv["org_id"]
    admin_sks, alice_sk, admin2_sk = _admins(srv)

    # Workspace A: development, one approval -> refused by the approval check
    proj_a = _new_project(srv)
    pay_a = _bundle_payload(org_id=org_id, project_id=proj_a, sequence=1,
                            environment="development")
    _publish(srv, proj_a, pay_a, [_make_change_approval(alice_sk, pay_a)])
    ctx_a = _setup_managed_workspace(
        tmp_path / "a", monkeypatch, admin_sks=admin_sks,
        bundle_signer_sk=_bs_entry(srv), org_id=org_id,
        project_id=proj_a, write_bundle=False,
    )
    tok_a = _bind_device(srv, ctx_a, org_id, proj_a, srv["alice_id"])
    _run_cycle(_make_sync_process(srv, ctx_a, tok_a))
    assert current_sequence(ctx_a["lay"]) is None
    assert load_verified_state(ctx_a["lay"]) is None, "refused: no verified state"
    assert current_environment(ctx_a["lay"]) == "prod", "no bundle = prod"
    reasons = _bundle_refused_reasons(ctx_a["lay"])
    assert reasons and reasons[-1] != NO_VS and "approvals" in reasons[-1], (
        f"non-prod first bundle with one approval: got {reasons!r}"
    )

    # Workspace B: development, two approvals -> applied, environment set
    proj_b = _new_project(srv)
    pay_b = _bundle_payload(org_id=org_id, project_id=proj_b, sequence=1,
                            environment="development")
    _publish(srv, proj_b, pay_b, [
        _make_change_approval(alice_sk, pay_b),
        _make_change_approval(admin2_sk, pay_b),
    ])
    ctx_b = _setup_managed_workspace(
        tmp_path / "b", monkeypatch, admin_sks=admin_sks,
        bundle_signer_sk=_bs_entry(srv), org_id=org_id,
        project_id=proj_b, write_bundle=False,
    )
    tok_b = _bind_device(srv, ctx_b, org_id, proj_b, srv["alice_id"])
    _run_cycle(_make_sync_process(srv, ctx_b, tok_b))
    assert current_sequence(ctx_b["lay"]) == 1, (
        f"two approvals must apply; reasons={_bundle_refused_reasons(ctx_b['lay'])}"
    )
    assert current_environment(ctx_b["lay"]) == "development"


# G7-A (HANDOFF 4 Nov, ADR 0001 A1.8): high_water > 0 with bundle.json gone
# = state deleted -> refuse (reason ``state_deleted``), stay locked, never
# accept a replay of seq 1; expected change process.py:597-601.
@pytest.mark.pg
def test_state_deleted_old_seq1_replay_refused(t16g_server, tmp_path, monkeypatch):
    """bundle.json deleted after seq 5 applied (high_water 5): the server's
    seq 1 (base 0) must be refused as ``state_deleted``, bundle.json must not
    be recreated.  Today the reason is the blanket ``no_verified_state``."""
    from sandbox.connector.sync.state import current_sequence
    from sandbox.connector.sync.verified_state import load_verified_state

    srv = t16g_server
    org_id = srv["org_id"]
    project_id = _new_project(srv)
    admin_sks, alice_sk, admin2_sk = _admins(srv)

    # The server still serves a valid first bundle (seq 1, two approvals)
    payload = _bundle_payload(org_id=org_id, project_id=project_id, sequence=1)
    _publish(srv, project_id, payload, [
        _make_change_approval(alice_sk, payload),
        _make_change_approval(admin2_sk, payload),
    ])

    ctx = _setup_managed_workspace(
        tmp_path, monkeypatch, admin_sks=admin_sks,
        bundle_signer_sk=_bs_entry(srv), org_id=org_id,
        project_id=project_id, policy_sequence=5, write_bundle=True,
    )
    bundle_path = ctx["sync_dir"] / "bundle.json"
    bundle_path.unlink()
    (ctx["sync_dir"] / "high_water.json").write_text(json.dumps({
        "registry_version": 1, "bundle_sequence": 5,
    }), encoding="utf-8")

    token = _bind_device(srv, ctx, org_id, project_id, srv["alice_id"])
    _run_cycle(_make_sync_process(srv, ctx, token))

    assert current_sequence(ctx["lay"]) is None, "must stay locked"
    assert load_verified_state(ctx["lay"]) is None, "refused: no verified state"
    assert not bundle_path.exists(), "state-deleted: bundle.json must not be recreated"
    reasons = _bundle_refused_reasons(ctx["lay"])
    assert reasons, "no bundle_refused audit record"
    assert reasons[-1] != NO_VS and "state_deleted" in reasons[-1], (
        f"expected a state_deleted refusal (A1.8), got {reasons[-1]!r}"
    )


# G7-A (HANDOFF 4 Nov, ADR 0001 A1.9/A2.2): trust root is the LOCAL
# pinned_root + registry.json; never the server's registry, a re-pin, or
# keys in the bundle; expected change process.py:597-601.
@pytest.mark.pg
def test_bootstrap_ignores_server_registry_and_bundle_keys(t16g_server, tmp_path, monkeypatch):
    """The workspace pins a registry for the SAME org but with other admins
    and another bundle signer.  The server's registry (real admins) does not
    chain from that root and must stay unapplied; the server's bundle
    (signed by the real signer) must be refused on its signature/signer,
    not with the blanket ``no_verified_state``; nothing is re-pinned."""
    from sandbox.connector.sync.state import current_sequence
    from sandbox.connector.sync.verified_state import load_verified_state

    srv = t16g_server
    org_id = srv["org_id"]
    project_id = _new_project(srv)
    _admin_sks, alice_sk, admin2_sk = _admins(srv)

    payload = _bundle_payload(org_id=org_id, project_id=project_id, sequence=1)
    _publish(srv, project_id, payload, [
        _make_change_approval(alice_sk, payload),
        _make_change_approval(admin2_sk, payload),
    ])

    rogue_admins = [keygen(), keygen()]
    rogue_bs = keygen()
    rogue_envelopes, rogue_fp = _build_registry(
        rogue_admins, org_id=org_id, bundle_signer_sk=rogue_bs,
    )
    ctx = _setup_managed_workspace(
        tmp_path, monkeypatch, admin_sks=rogue_admins,
        bundle_signer_sk=rogue_bs, org_id=org_id, project_id=project_id,
        write_bundle=False, registry_envelopes=rogue_envelopes,
        registry_fp=rogue_fp,
    )
    pinned_before = (ctx["sync_dir"] / "pinned_root.json").read_bytes()
    registry_before = (ctx["sync_dir"] / "registry.json").read_bytes()

    token = _bind_device(srv, ctx, org_id, project_id, srv["alice_id"])
    _run_cycle(_make_sync_process(srv, ctx, token))

    assert current_sequence(ctx["lay"]) is None
    assert load_verified_state(ctx["lay"]) is None, "refused: no verified state"
    assert not (ctx["sync_dir"] / "bundle.json").exists()
    assert (ctx["sync_dir"] / "pinned_root.json").read_bytes() == pinned_before, "re-pinned"
    assert (ctx["sync_dir"] / "registry.json").read_bytes() == registry_before, (
        "server registry applied over a root it does not chain from"
    )
    reasons = _bundle_refused_reasons(ctx["lay"])
    assert reasons, "no bundle_refused audit record"
    last = reasons[-1].lower()
    assert reasons[-1] != NO_VS and ("sign" in last or "key" in last), (
        f"refusal must come from the local trust root (signature/signer), got {reasons[-1]!r}"
    )


# G7-A (HANDOFF 4 Nov, F3 limit): org_id from the root-signed genesis ==
# enrollment.json org_id; project_id from enrollment.json; expected change
# process.py:597-601.
@pytest.mark.pg
def test_bootstrap_org_project_mismatch_refused(t16g_server, tmp_path, monkeypatch):
    """(a) enrollment.json org_id differs from the genesis org_id -> refused
    naming the org; (b) enrollment.json project_id differs from the served
    bundle's project_id -> refused naming the project; (c) enrollment.json
    org_id is the empty string -> refused naming the org (the genesis
    org_id must equal a NON-EMPTY enrollment org_id; an empty value must
    not be treated as "no cross-check").  Today all three are the blanket
    ``no_verified_state``."""
    from sandbox.connector.sync.state import current_sequence
    from sandbox.connector.sync.verified_state import load_verified_state

    srv = t16g_server
    org_id = srv["org_id"]
    project_id = _new_project(srv)
    admin_sks, alice_sk, admin2_sk = _admins(srv)

    payload = _bundle_payload(org_id=org_id, project_id=project_id, sequence=1)
    _publish(srv, project_id, payload, [
        _make_change_approval(alice_sk, payload),
        _make_change_approval(admin2_sk, payload),
    ])

    def _tamper(ctx, **fields):
        p = ctx["sync_dir"] / "enrollment.json"
        enrollment = json.loads(p.read_text(encoding="utf-8"))
        enrollment.update(fields)
        p.write_text(json.dumps(enrollment), encoding="utf-8")

    # (a) org mismatch
    ctx_o = _setup_managed_workspace(
        tmp_path / "org", monkeypatch, admin_sks=admin_sks,
        bundle_signer_sk=_bs_entry(srv), org_id=org_id,
        project_id=project_id, write_bundle=False,
    )
    tok_o = _bind_device(srv, ctx_o, org_id, project_id, srv["alice_id"])
    _tamper(ctx_o, org_id=str(uuid.uuid4()))
    _run_cycle(_make_sync_process(srv, ctx_o, tok_o))
    assert current_sequence(ctx_o["lay"]) is None
    assert load_verified_state(ctx_o["lay"]) is None, "refused: no verified state"
    assert not (ctx_o["sync_dir"] / "bundle.json").exists()
    reasons = _bundle_refused_reasons(ctx_o["lay"])
    assert reasons and reasons[-1] != NO_VS and "org" in reasons[-1].lower(), (
        f"org mismatch must be named, got {reasons!r}"
    )

    # (b) project mismatch
    ctx_p = _setup_managed_workspace(
        tmp_path / "proj", monkeypatch, admin_sks=admin_sks,
        bundle_signer_sk=_bs_entry(srv), org_id=org_id,
        project_id=project_id, write_bundle=False,
    )
    tok_p = _bind_device(srv, ctx_p, org_id, project_id, srv["alice_id"])
    _tamper(ctx_p, project_id=str(uuid.uuid4()))
    _run_cycle(_make_sync_process(srv, ctx_p, tok_p))
    assert current_sequence(ctx_p["lay"]) is None
    assert load_verified_state(ctx_p["lay"]) is None, "refused: no verified state"
    assert not (ctx_p["sync_dir"] / "bundle.json").exists()
    reasons = _bundle_refused_reasons(ctx_p["lay"])
    assert reasons and reasons[-1] != NO_VS and "project" in reasons[-1].lower(), (
        f"project mismatch must be named, got {reasons!r}"
    )

    # (c) empty org_id in enrollment.json (security W, 4 Nov)
    ctx_e = _setup_managed_workspace(
        tmp_path / "emptyorg", monkeypatch, admin_sks=admin_sks,
        bundle_signer_sk=_bs_entry(srv), org_id=org_id,
        project_id=project_id, write_bundle=False,
    )
    tok_e = _bind_device(srv, ctx_e, org_id, project_id, srv["alice_id"])
    _tamper(ctx_e, org_id="")
    _run_cycle(_make_sync_process(srv, ctx_e, tok_e))
    assert current_sequence(ctx_e["lay"]) is None
    assert load_verified_state(ctx_e["lay"]) is None, "refused: no verified state"
    assert not (ctx_e["sync_dir"] / "bundle.json").exists()
    reasons = _bundle_refused_reasons(ctx_e["lay"])
    assert reasons and reasons[-1] != NO_VS and "org" in reasons[-1].lower(), (
        f"empty enrollment org_id must be refused naming the org, got {reasons!r}"
    )


# G7-A (HANDOFF 4 Nov, security W MEDIUM; fix-shape "high_water.json
# present with bundle_sequence == 0"): a missing high_water.json with no
# bundle.json is NOT a fresh enrol -- it is refused naming high_water,
# the workspace stays locked and the loader never recreates the file;
# expected change process.py:597-601 (+ the bootstrap loader).
@pytest.mark.pg
def test_bootstrap_missing_high_water_refused(t16g_server, tmp_path, monkeypatch):
    """Both high_water.json and bundle.json gone before the cycle: refused
    with a reason naming ``high_water`` (not the blanket
    ``no_verified_state``), ``is_locked`` stays True, and neither file
    exists after the cycle.  Today the reason is ``no_verified_state``."""
    from sandbox.connector.sync.state import current_sequence, is_locked
    from sandbox.connector.sync.verified_state import load_verified_state

    srv = t16g_server
    org_id = srv["org_id"]
    project_id = _new_project(srv)
    admin_sks, alice_sk, admin2_sk = _admins(srv)

    payload = _bundle_payload(org_id=org_id, project_id=project_id, sequence=1)
    _publish(srv, project_id, payload, [
        _make_change_approval(alice_sk, payload),
        _make_change_approval(admin2_sk, payload),
    ])

    ctx = _setup_managed_workspace(
        tmp_path, monkeypatch, admin_sks=admin_sks,
        bundle_signer_sk=_bs_entry(srv), org_id=org_id,
        project_id=project_id, write_bundle=False,
    )
    hw_path = ctx["sync_dir"] / "high_water.json"
    bundle_path = ctx["sync_dir"] / "bundle.json"
    hw_path.unlink()
    assert not hw_path.exists() and not bundle_path.exists()

    token = _bind_device(srv, ctx, org_id, project_id, srv["alice_id"])
    _run_cycle(_make_sync_process(srv, ctx, token))

    assert current_sequence(ctx["lay"]) is None, "must not apply"
    assert is_locked(ctx["lay"]), "workspace must stay locked"
    assert load_verified_state(ctx["lay"]) is None, "refused: no verified state"
    assert not bundle_path.exists(), "bundle.json must not be written"
    assert not hw_path.exists(), (
        "the loader must never recreate high_water.json (R2-2 precedent)"
    )
    reasons = _bundle_refused_reasons(ctx["lay"])
    assert reasons, "no bundle_refused audit record"
    assert reasons[-1] != NO_VS and "high_water" in reasons[-1], (
        f"expected a refusal naming high_water, got {reasons[-1]!r}"
    )


# G7-A (security L review R2, 4 Nov): "no bundle at all" must mean no
# bytes at bundle.json AND nothing in policy_history/, not "nothing that
# parses".  A garbage bundle.json (or any policy_history/bundle_*.json)
# is a present bundle that does not verify -> refused
# ``bootstrap_bundle_present``, never bootstrapped over; expected change
# src/sandbox/connector/sync/verified_state.py:284-285 + process.py:606.
@pytest.mark.pg
def test_bootstrap_garbage_bundle_json_refused(t16g_server, tmp_path, monkeypatch):
    """(a) bundle.json holds unparseable bytes, policy_history/ empty,
    high_water bundle_sequence 0, server serves a valid seq 1 bundle with
    two approvals: refused with a reason containing
    ``bootstrap_bundle_present`` (not ``no_verified_state``),
    load_verified_state None, bundle.json bytes unchanged, no
    policy_history/bundle_*.json written, high_water unchanged.
    (b) bundle.json absent but one policy_history/bundle_0001.json (any
    bytes) present -> the same refusal.  Today ``last_valid_bundle`` only
    sees bundles that parse, so both fall through to the bootstrap path."""
    from sandbox.connector.sync.state import current_sequence
    from sandbox.connector.sync.verified_state import load_verified_state

    srv = t16g_server
    org_id = srv["org_id"]
    project_id = _new_project(srv)
    admin_sks, alice_sk, admin2_sk = _admins(srv)

    payload = _bundle_payload(org_id=org_id, project_id=project_id, sequence=1)
    _publish(srv, project_id, payload, [
        _make_change_approval(alice_sk, payload),
        _make_change_approval(admin2_sk, payload),
    ])

    garbage = b"{not json"

    def _check(ctx, label, *, bundle_bytes, hist_before):
        hist = ctx["lay"].root / ".sandbox" / "policy_history"
        hw_path = ctx["sync_dir"] / "high_water.json"
        hw_before = hw_path.read_bytes()
        bundle_path = ctx["sync_dir"] / "bundle.json"

        token = _bind_device(srv, ctx, org_id, project_id, srv["alice_id"])
        _run_cycle(_make_sync_process(srv, ctx, token))

        assert current_sequence(ctx["lay"]) is None, f"{label}: must not apply"
        assert load_verified_state(ctx["lay"]) is None, f"{label}: no verified state"
        if bundle_bytes is None:
            assert not bundle_path.exists(), f"{label}: bundle.json must not be written"
        else:
            assert bundle_path.read_bytes() == bundle_bytes, (
                f"{label}: bundle.json bytes changed"
            )
        hist_after = sorted(p.name for p in hist.glob("bundle_*.json")) if hist.is_dir() else []
        assert hist_after == hist_before, (
            f"{label}: policy_history changed {hist_before} -> {hist_after}"
        )
        assert hw_path.read_bytes() == hw_before, f"{label}: high_water changed"
        reasons = _bundle_refused_reasons(ctx["lay"])
        assert reasons, f"{label}: no bundle_refused audit record"
        assert reasons[-1] != NO_VS and "bootstrap_bundle_present" in reasons[-1], (
            f"{label}: expected bootstrap_bundle_present, got {reasons[-1]!r}"
        )

    # (a) garbage bundle.json, empty policy_history
    ctx_a = _setup_managed_workspace(
        tmp_path / "garbage", monkeypatch, admin_sks=admin_sks,
        bundle_signer_sk=_bs_entry(srv), org_id=org_id,
        project_id=project_id, write_bundle=False,
    )
    (ctx_a["sync_dir"] / "bundle.json").write_bytes(garbage)
    hist_a = ctx_a["lay"].root / ".sandbox" / "policy_history"
    hist_a.mkdir(parents=True, exist_ok=True)
    assert list(hist_a.glob("bundle_*.json")) == []
    _check(ctx_a, "garbage bundle.json", bundle_bytes=garbage, hist_before=[])

    # (b) no bundle.json, one policy_history/bundle_0001.json of any bytes
    ctx_b = _setup_managed_workspace(
        tmp_path / "hist", monkeypatch, admin_sks=admin_sks,
        bundle_signer_sk=_bs_entry(srv), org_id=org_id,
        project_id=project_id, write_bundle=False,
    )
    assert not (ctx_b["sync_dir"] / "bundle.json").exists()
    hist_b = ctx_b["lay"].root / ".sandbox" / "policy_history"
    hist_b.mkdir(parents=True, exist_ok=True)
    (hist_b / "bundle_0001.json").write_bytes(garbage)
    _check(ctx_b, "policy_history bundle", bundle_bytes=None,
           hist_before=["bundle_0001.json"])


# ===================================================================
# G7-B: audit upload contract
# ===================================================================


def _audit_workspace(srv, tmp_path, monkeypatch):
    """A managed workspace with a bundle at seq 1 and a bound device."""
    org_id = srv["org_id"]
    project_id = _new_project(srv)
    admin_sks, _a, _b = _admins(srv)
    ctx = _setup_managed_workspace(
        tmp_path, monkeypatch, admin_sks=admin_sks,
        bundle_signer_sk=_bs_entry(srv), org_id=org_id,
        project_id=project_id, policy_sequence=1,
    )
    token = _bind_device(srv, ctx, org_id, project_id, srv["alice_id"])
    return ctx, token


# G7-B (HANDOFF 4 Nov): connector sends {session_id, records:[...]};
# expected change src/sandbox/connector/sync/audit_upload.py:176-190.
@pytest.mark.pg
def test_audit_upload_lands_in_pg(t16g_server, tmp_path, monkeypatch):
    """Three real local records land in audit_records with the same
    chain_length, record_hash and body, and the cursor moves to 3.
    Today the server answers 200 to the per-record body (``records``
    defaults to []) and stores nothing."""
    srv = t16g_server
    ctx, token = _audit_workspace(srv, tmp_path, monkeypatch)

    session_id = "audit-test-sess"
    local = _seed_local_audit(ctx["lay"], session_id, 3)

    _run_cycle(_make_sync_process(srv, ctx, token))

    rows = _server_rows(
        srv,
        "SELECT chain_length, record_hash, body FROM audit_records "
        "WHERE connector_id = %s::uuid AND session_id = %s ORDER BY chain_length",
        [ctx["device_id"], session_id],
    )
    assert len(rows) == 3, f"expected 3 audit rows, got {len(rows)}"
    for i, (cl, rh, body) in enumerate(rows):
        assert cl == local[i]["chain_length"]
        assert rh == local[i]["record_hash"]
        stored = body if isinstance(body, dict) else json.loads(body)
        expected_body = {k: v for k, v in local[i].items()
                         if k not in ("previous_hash", "chain_length", "record_hash")}
        assert stored == expected_body, f"row {i} body differs"
        assert _real_record_hash(stored) == rh
    assert _read_cursor(ctx)["sessions"][session_id]["chain_length"] == 3


# G7-B (HANDOFF 4 Nov, G7-C limit): a 409 fork -> server audit_quarantine +
# sync_alerts 'fork', connector raises ``audit_fork`` (alert + audit record),
# keeps enforcing; expected change audit_upload.py:176-190 + process.py:795.
@pytest.mark.pg
def test_audit_fork_quarantines_and_alerts_both_sides(t16g_server, tmp_path, monkeypatch):
    srv = t16g_server
    ctx, token = _audit_workspace(srv, tmp_path, monkeypatch)
    lay = ctx["lay"]
    session_id = "fork-test-sess"

    _seed_local_audit(lay, session_id, 2)
    _run_cycle(_make_sync_process(srv, ctx, token))

    # Rewrite the session with two different (valid-chain) records and
    # rewind the cursor for that session only (upload_seq kept).
    (lay.audit_dir / session_id / "records.jsonl").unlink()
    _seed_local_audit(lay, session_id, 2)
    _set_cursor(ctx, session_id, 0, "")

    _run_cycle(_make_sync_process(srv, ctx, token))

    quarantine = _server_rows(
        srv,
        "SELECT id FROM audit_quarantine WHERE connector_id = %s::uuid AND kind = 'fork'",
        [ctx["device_id"]],
    )
    assert len(quarantine) >= 1, "expected an audit_quarantine fork row"
    fork_alerts = _server_rows(
        srv,
        "SELECT id FROM sync_alerts WHERE connector_id = %s::uuid AND kind = 'fork'",
        [ctx["device_id"]],
    )
    assert len(fork_alerts) >= 1, "expected a sync_alerts fork row"

    alerts = _local_alerts(lay, "audit_fork")
    assert alerts, "local audit_fork alert not raised"
    assert _local_audit_events(lay, "audit_fork"), "local audit_fork audit record missing"
    # Fork never changes local enforcement
    from sandbox.connector.sync.state import current_sequence
    assert current_sequence(lay) == 1


# G7-B (HANDOFF 4 Nov): the checkpoint is sent even when the upload fails
# (409); the server then sees chain_length 3 < 5 -> 'truncation';
# expected change process.py:765-799 (_upload_audit) + audit_upload.py.
@pytest.mark.pg
def test_truncation_checkpoint_sent_after_fork(t16g_server, tmp_path, monkeypatch):
    """Gate step 7 attack: 5 records uploaded; cut the last 3, append 1
    forged record, rewind the session cursor to 2.  Cycle 2: the forged
    record 3 conflicts (409 fork, quarantined) AND the checkpoint
    (upload_seq 2, chain_length 3) is still sent, so the server records
    'truncation'.  Today: no record ever lands (no fork), and a 409 would
    abort before send_checkpoint."""
    srv = t16g_server
    ctx, token = _audit_workspace(srv, tmp_path, monkeypatch)
    lay = ctx["lay"]
    session_id = "trunc-test-sess"

    _seed_local_audit(lay, session_id, 5)
    _run_cycle(_make_sync_process(srv, ctx, token))

    chain = _read_local_chain(lay, session_id)
    kept = chain[:2]
    _write_local_chain(lay, session_id, kept)
    from sandbox.connector.audit import FolderAudit
    FolderAudit(lay.audit_dir, session_id=session_id).append(
        {"event": "forged_after_cut", "ts": time.time()})
    assert len(_read_local_chain(lay, session_id)) == 3
    _set_cursor(ctx, session_id, 2, kept[-1]["record_hash"])

    _run_cycle(_make_sync_process(srv, ctx, token))

    quarantine = _server_rows(
        srv,
        "SELECT id FROM audit_quarantine WHERE connector_id = %s::uuid AND kind = 'fork'",
        [ctx["device_id"]],
    )
    assert len(quarantine) >= 1, "forged record 3 must be quarantined as a fork"
    heads = _server_rows(
        srv,
        "SELECT upload_seq FROM audit_heads WHERE connector_id = %s::uuid ORDER BY upload_seq",
        [ctx["device_id"]],
    )
    assert [h[0] for h in heads] == [1, 2], (
        f"checkpoint must be sent after the failed upload, got upload_seqs {heads}"
    )
    trunc = _server_rows(
        srv,
        "SELECT detail FROM sync_alerts WHERE connector_id = %s::uuid AND kind = 'truncation'",
        [ctx["device_id"]],
    )
    assert len(trunc) >= 1, "server must record a truncation alert (5 -> 3)"


# G7-B (HANDOFF 4 Nov): cursor > local chain length -> ``audit_truncation_local``
# alert + audit record, immediately; expected change process.py:795 (today
# audit_upload.py:160's AuditUploadError is swallowed).
@pytest.mark.pg
def test_local_truncation_raises_local_alert(t16g_server, tmp_path, monkeypatch):
    srv = t16g_server
    ctx, token = _audit_workspace(srv, tmp_path, monkeypatch)
    lay = ctx["lay"]
    session_id = "local-trunc-sess"

    chain = _seed_local_audit(lay, session_id, 5)
    _set_cursor(ctx, session_id, 5, chain[-1]["record_hash"], upload_seq=0)
    _write_local_chain(lay, session_id, chain[:2])  # local chain cut to 2

    _run_cycle(_make_sync_process(srv, ctx, token))

    alerts = _local_alerts(lay, "audit_truncation_local")
    assert alerts, "audit_truncation_local alert not raised"
    assert any(a.get("session_id") == "sync" or session_id in json.dumps(a)
               for a in alerts)
    assert _local_audit_events(lay, "audit_truncation_local"), (
        "audit_truncation_local audit record missing"
    )


# G7-B (HANDOFF 4 Nov): any 4xx/5xx -> ``audit_upload_failed`` with
# status/reason immediately; cursor moves only after 200; no escalation
# status change; expected change process.py:795 + audit_upload.py.
@pytest.mark.pg
def test_upload_400_raises_audit_upload_failed(t16g_server, tmp_path, monkeypatch):
    """Cursor ahead of the server (chain_length 2, server has nothing):
    the batch starting at record 3 is a gap -> real server 400 ``gap``.
    Today the per-record body gets 200 (``records`` defaults to []), the
    cursor advances to 4 and no alert is raised."""
    srv = t16g_server
    ctx, token = _audit_workspace(srv, tmp_path, monkeypatch)
    lay = ctx["lay"]
    session_id = "upload400-sess"

    chain = _seed_local_audit(lay, session_id, 4)
    _set_cursor(ctx, session_id, 2, chain[1]["record_hash"], upload_seq=0)

    _run_cycle(_make_sync_process(srv, ctx, token))

    alerts = _local_alerts(lay, "audit_upload_failed")
    assert alerts, "audit_upload_failed alert not raised after a server 400"
    assert any("400" in json.dumps(a) for a in alerts), (
        f"alert must carry the HTTP status, got {alerts}"
    )
    assert _read_cursor(ctx)["sessions"][session_id]["chain_length"] == 2, (
        "cursor must move only after a 200"
    )
    changed = _server_rows(
        srv,
        "SELECT id FROM escalations WHERE connector_id = %s::uuid AND status != 'pending'",
        [ctx["device_id"]],
    )
    assert changed == []


# ===================================================================
# Founder ruling 1: verify_project on empty project / recompute hash
# ===================================================================


def _insert_chain_rows(conn, org_id, project_id, connector_id, session_id,
                       rows: list[tuple[int, str, str, dict]]):
    """rows: (chain_length, previous_hash, record_hash, body)."""
    for cl, prev, rh, body in rows:
        conn.execute(
            "INSERT INTO audit_records "
            "(id, org_id, connector_id, session_id, chain_length, "
            "previous_hash, record_hash, body, created_at) "
            "VALUES (%s, %s::uuid, %s::uuid, %s, %s, %s, %s, %s::jsonb, now())",
            [str(uuid.uuid4()), org_id, connector_id, session_id,
             cl, prev, rh, json.dumps(body, sort_keys=True, separators=(",", ":"))],
        )


def _register_connector(conn, org_id, project_id) -> str:
    connector_id = str(uuid.uuid4())
    conn.execute(
        "INSERT INTO connectors (id, org_id, project_id, device_public_key, created_at) "
        "VALUES (%s, %s::uuid, %s::uuid, %s, now())",
        [connector_id, org_id, project_id, "deadbeef" * 8],
    )
    return connector_id


# Founder ruling 1 (4 Nov): zero rows = not ok; recompute record_hash
# (ADR 0001 A4.3); expected change ee/src/agg_cp/sync/audit.py:160-212.
@pytest.mark.pg
def test_verify_project_empty_is_not_vacuous_and_recomputes_hash(t16g_server):
    from agg_cp.sync.audit import verify_project

    srv = t16g_server
    org_id = srv["org_id"]
    conninfo = _conninfo(srv["owner_url"])

    # (1) zero rows -> not ok
    empty_project_id = _new_project(srv, "Empty Project")
    with psycopg.connect(conninfo, autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        ok, gaps = verify_project(conn, empty_project_id)
    assert not ok, "verify_project returned ok=True for a project with zero audit rows"

    # (2) links intact, record 2's content does not match its record_hash
    tampered_project_id = _new_project(srv, "Tampered Project")
    with psycopg.connect(conninfo, autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        connector_id = _register_connector(conn, org_id, tampered_project_id)
        b1 = {"event": "e1"}
        b2 = {"event": "e2"}
        b3 = {"event": "e3"}
        h1 = _real_record_hash(b1)
        h2_bogus = hashlib.sha256(b"not the hash of b2").hexdigest()
        h3 = _real_record_hash(b3)
        _insert_chain_rows(conn, org_id, tampered_project_id, connector_id, "s", [
            (1, "", h1, b1),
            (2, h1, h2_bogus, b2),      # links intact, content/hash mismatch
            (3, h2_bogus, h3, b3),
        ])
        ok, gaps = verify_project(conn, tampered_project_id)
    assert not ok, "verify_project accepted a record whose record_hash is not sha256(body)"
    assert any(g.get("chain_length") == 2 for g in gaps), f"gap must name record 2: {gaps}"


@pytest.mark.pg
def test_guard_verify_project_correct_chain_ok(t16g_server):
    """Guard twin: a correct chain (real record_hash formula) verifies ok."""
    from agg_cp.sync.audit import verify_project

    srv = t16g_server
    org_id = srv["org_id"]
    guard_project_id = _new_project(srv, "Guard Chain Project")
    conninfo = _conninfo(srv["owner_url"])

    with psycopg.connect(conninfo, autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        connector_id = _register_connector(conn, org_id, guard_project_id)
        rows = []
        prev = ""
        for i in range(1, 4):
            body = {"event": f"guard_event_{i}"}
            rh = _real_record_hash(body)
            rows.append((i, prev, rh, body))
            prev = rh
        _insert_chain_rows(conn, org_id, guard_project_id, connector_id,
                           "guard-chain-sess", rows)
        ok, gaps = verify_project(conn, guard_project_id)

    assert ok, f"guard: verify_project should return ok for a correct chain, gaps={gaps}"
    assert gaps == []


# ===================================================================
# Founder ruling 2: registry_version below pinned refused
# ===================================================================


def _registry_v2(srv, admin1, admin2):
    """A two-version registry chain (genesis by admin1; v2 adds admin2)
    with the server's bundle signer.  Returns (chain, genesis_fp)."""
    org_id = srv["org_id"]
    bs_pub = srv["bundle_signer_pub"]
    bs_kid = hashlib.sha256(bs_pub).hexdigest()

    keys_v1 = [{
        "key_id": admin1[2], "public_key": admin1[1].hex(),
        "user_id": "admin1", "iss": "https://idp.test", "sub": "admin1",
        "alg": "ed25519", "kind": "cli", "roles": ["admin", "approver"],
        "added_in": 1,
    }]
    genesis_payload = {
        "org_id": org_id, "version": 1, "prev_hash": "",
        "threshold": 1, "admins": [admin1[2]], "keys": keys_v1,
        "bundle_signer": {"key_id": bs_kid, "public_key": bs_pub.hex()},
        "expires_at": time.time() + 86400,
    }
    g_canonical = json.dumps(genesis_payload, sort_keys=True,
                             separators=(",", ":")).encode()
    g_msg = b"agg/registry/v1\x00" + g_canonical
    genesis_env = {
        "kind": "agg/registry/v1", "sig_v": 1,
        "payload": genesis_payload,
        "signatures": [{"key_id": admin1[2], "alg": "ed25519",
                        "sig": admin1[0].sign(g_msg).signature.hex()}],
    }
    g_fp = hashlib.sha256(org_id.encode("utf-8") + b":" + g_canonical).hexdigest()

    v2_keys = keys_v1 + [{
        "key_id": admin2[2], "public_key": admin2[1].hex(),
        "user_id": "admin2", "iss": "https://idp.test", "sub": "admin2",
        "alg": "ed25519", "kind": "cli", "roles": ["admin", "approver"],
        "added_in": 2,
    }]
    v2_payload = {
        "org_id": org_id, "version": 2, "prev_hash": g_fp,
        "threshold": 2, "admins": [admin1[2], admin2[2]], "keys": v2_keys,
        "bundle_signer": {"key_id": bs_kid, "public_key": bs_pub.hex()},
        "expires_at": time.time() + 86400,
    }
    v2_canonical = json.dumps(v2_payload, sort_keys=True,
                              separators=(",", ":")).encode()
    v2_msg = b"agg/registry/v1\x00" + v2_canonical
    v2_env = {
        "kind": "agg/registry/v1", "sig_v": 1,
        "payload": v2_payload,
        "signatures": [
            {"key_id": admin1[2], "alg": "ed25519",
             "sig": admin1[0].sign(v2_msg).signature.hex()},
            {"key_id": admin2[2], "alg": "ed25519",
             "sig": admin2[0].sign(v2_msg).signature.hex()},
        ],
    }
    return [genesis_env, v2_env], g_fp


# Founder ruling 2 (4 Nov, ADR 0001 A2.5): bundle registry_version must be
# >= the verified registry's version; expected change
# src/sandbox/connector/sync/bundles.py:501-504 (today ``< 1``).
@pytest.mark.pg
def test_bundle_registry_version_below_pinned_refused(t16g_server, tmp_path, monkeypatch):
    """A validly signed bundle with two valid approvals whose
    registry_version (1) is below the VERIFIED registry version (2) is
    refused naming registry_version, even though the unsigned
    high_water.json still says registry_version 1.  Today it applies."""
    from sandbox.connector.sync.bundles import verify_and_apply, BundleError
    from sandbox.connector.sync.state import current_sequence
    from sandbox.protocol.registry import verify_chain

    srv = t16g_server
    org_id = srv["org_id"]
    project_id = srv["project_id"]
    admin1 = keygen()
    admin2 = keygen()
    registry_chain, g_fp = _registry_v2(srv, admin1, admin2)
    verified_registry = verify_chain(registry_chain, g_fp)

    ctx = _setup_managed_workspace(
        tmp_path, monkeypatch, admin_sks=[admin1, admin2],
        bundle_signer_sk=_bs_entry(srv), org_id=org_id,
        project_id=project_id, policy_sequence=1,
        registry_envelopes=registry_chain, registry_fp=g_fp,
    )
    # Security W MEDIUM (4 Nov): high_water.json is left at registry_version
    # 1 (unsigned, device-holder writable) while the VERIFIED chain is at
    # version 2.  The floor must come from the verified registry; a fix
    # that compares only against high_water.registry_version must fail.
    (ctx["sync_dir"] / "high_water.json").write_text(json.dumps({
        "registry_version": 1, "bundle_sequence": 1,
    }), encoding="utf-8")
    lay = ctx["lay"]

    bundle_env = _build_signed_bundle(
        _bs_entry(srv), org_id=org_id, project_id=project_id,
        policy_sequence=2, base_sequence=1,
        registry_version=1,  # BELOW the verified registry version 2
    )
    approvals = [
        _make_change_approval(admin1[0], bundle_env["payload"]),
        _make_change_approval(admin2[0], bundle_env["payload"]),
    ]

    refused_reason = None
    try:
        verify_and_apply(lay, bundle_env, verified_registry,
                         srv["bundle_signer_pub"], approvals,
                         org_id=org_id, project_id=project_id)
    except BundleError as exc:
        refused_reason = str(exc)

    assert refused_reason is not None, (
        f"bundle with registry_version 1 < verified 2 was applied "
        f"(sequence now {current_sequence(lay)})"
    )
    assert "registry_version" in refused_reason, refused_reason
    assert current_sequence(lay) == 1


@pytest.mark.pg
def test_guard_bundle_registry_version_equal_pinned_applies(t16g_server, tmp_path, monkeypatch):
    """Guard twin: registry_version == verified version (2) applies
    (high_water.json at registry_version 1 must not matter)."""
    from sandbox.connector.sync.bundles import verify_and_apply
    from sandbox.connector.sync.state import current_sequence
    from sandbox.protocol.registry import verify_chain

    srv = t16g_server
    org_id = srv["org_id"]
    project_id = srv["project_id"]
    admin1 = keygen()
    admin2 = keygen()
    registry_chain, g_fp = _registry_v2(srv, admin1, admin2)
    verified_registry = verify_chain(registry_chain, g_fp)

    ctx = _setup_managed_workspace(
        tmp_path, monkeypatch, admin_sks=[admin1, admin2],
        bundle_signer_sk=_bs_entry(srv), org_id=org_id,
        project_id=project_id, policy_sequence=1,
        registry_envelopes=registry_chain, registry_fp=g_fp,
    )
    # Security W MEDIUM (4 Nov): high_water.json is left at registry_version
    # 1 (unsigned, device-holder writable) while the VERIFIED chain is at
    # version 2.  The floor must come from the verified registry; a fix
    # that compares only against high_water.registry_version must fail.
    (ctx["sync_dir"] / "high_water.json").write_text(json.dumps({
        "registry_version": 1, "bundle_sequence": 1,
    }), encoding="utf-8")
    lay = ctx["lay"]

    bundle_env = _build_signed_bundle(
        _bs_entry(srv), org_id=org_id, project_id=project_id,
        policy_sequence=2, base_sequence=1, registry_version=2,
    )
    approvals = [
        _make_change_approval(admin1[0], bundle_env["payload"]),
        _make_change_approval(admin2[0], bundle_env["payload"]),
    ]
    verify_and_apply(lay, bundle_env, verified_registry,
                     srv["bundle_signer_pub"], approvals,
                     org_id=org_id, project_id=project_id)
    assert current_sequence(lay) == 2
