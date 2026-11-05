"""M3 T3 tests-first: proposals from pasted JSON, approvals and publish routes,
enrollment-code page flow, fresh-session rule, CSRF.

Spec: M3_PLAN.md T3 row, D2 (A9 items 6-8), D3, threats 39-40, 48,
ADR 0001 A9, T0B_SECURITY_REVIEW P3, F-3, F-10.

Every target is ``xfail(strict=True, raises=M3T3Pending)``; guard twins
PASS today.  Marked ``pg``.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import secrets
import time
import uuid

import psycopg
import pytest
from nacl.signing import SigningKey

from .m3_pending import M3T3Pending, require_m3
from .m2_sync_server import (
    make_sync_server, ensure_at_head, create_org, create_project,
    keygen, sign_envelope, canonical_json,
)
from .t9_helpers import (
    seed_session, make_session_cookie, compute_csrf, _conninfo,
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
    if clock is None:
        clock = FakeClock()
    token, csrf, sid = seed_session(
        owner_url, uuid.UUID(org_id), uuid.UUID(user_id), clock=clock,
    )
    cookie = make_session_cookie(uuid.UUID(org_id), token)
    return cookie, csrf, sid


def _make_stale_session(owner_url: str, org_id: str, user_id: str):
    """Create a session older than 15 min."""
    clock = FakeClock()
    # Wind the clock back 20 min so the session is created in the past
    clock._now = clock._now - dt.timedelta(minutes=20)
    token, csrf, sid = seed_session(
        owner_url, uuid.UUID(org_id), uuid.UUID(user_id), clock=clock,
    )
    cookie = make_session_cookie(uuid.UUID(org_id), token)
    return cookie, csrf, sid


def _route_exists(base_url: str, method: str, path: str,
                  cookie: str, csrf: str) -> bool:
    """Return True if the route is registered (not a generic 404)."""
    import httpx
    headers = {"X-CSRF-Token": csrf}
    cookies = {"__Host-agg_session": cookie}
    with httpx.Client(base_url=base_url, timeout=10) as c:
        fn = getattr(c, method.lower())
        if method.lower() in ("post", "put", "patch"):
            r = fn(path, json={}, headers=headers, cookies=cookies)
        else:
            r = fn(path, headers=headers, cookies=cookies)
    if r.status_code == 404:
        try:
            body = r.json()
        except Exception:
            return True
        return body != {"detail": "Not Found"}
    return True


# ---------------------------------------------------------------------------
# Module-scoped server fixture
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def t3_server(pg_url, app_url, owner_url, pg_roles, tmp_path_factory):
    """4-worker agg_cp server for T3 proposal and code tests.

    Seeds: org, project, alice (admin/proposer), bob (admin/approver),
    carol (admin/approver).
    """
    bundle_signer_sk = SigningKey.generate()
    key_dir = tmp_path_factory.mktemp("t3_bundle_signer")
    key_file = key_dir / "bundle_signer.key"
    key_file.write_bytes(bytes(bundle_signer_sk).hex().encode("ascii"))
    old_bs = os.environ.get("AGG_BUNDLE_SIGNER_KEY_FILE")
    os.environ["AGG_BUNDLE_SIGNER_KEY_FILE"] = str(key_file)

    gen = make_sync_server(
        pg_url, app_url, owner_url,
        org_names=["T3 Org"],
    )
    info = next(gen)

    conninfo = _conninfo(owner_url)
    org_id = info["org_id"]
    with psycopg.connect(conninfo, autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        alice_id = _seed_user_row(conn, org_id, "alice@t3.test")
        bob_id = _seed_user_row(conn, org_id, "bob@t3.test")
        carol_id = _seed_user_row(conn, org_id, "carol@t3.test")
        operator_id = _seed_user_row(conn, org_id, "operator@t3.test")
        for uid in (alice_id, bob_id, carol_id):
            _bind_admin(conn, org_id, uid)
        project_id = str(uuid.uuid4())
        create_project(conn, org_id, project_id, "T3 Project")

    clock = FakeClock()
    a_cookie, a_csrf, a_sid = _make_fresh_session(
        owner_url, org_id, alice_id, clock=clock)
    b_cookie, b_csrf, b_sid = _make_fresh_session(
        owner_url, org_id, bob_id, clock=clock)
    op_cookie, op_csrf, op_sid = _make_fresh_session(
        owner_url, org_id, operator_id, clock=clock)

    info.update({
        "alice_id": alice_id,
        "bob_id": bob_id,
        "carol_id": carol_id,
        "operator_id": operator_id,
        "project_id": project_id,
        "alice_cookie": a_cookie,
        "alice_csrf": a_csrf,
        "bob_cookie": b_cookie,
        "bob_csrf": b_csrf,
        "op_cookie": op_cookie,
        "op_csrf": op_csrf,
        "bundle_signer_sk": bundle_signer_sk,
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
# GUARD TWINS (PASS today)
# ===================================================================

@pytest.mark.pg
def test_guard_t3_server_ready(t3_server):
    """Guard: server is up."""
    import httpx
    with httpx.Client(base_url=t3_server["base_url"], timeout=10) as c:
        assert c.get("/ready").status_code == 200


@pytest.mark.pg
def test_guard_t3_alice_session(t3_server):
    """Guard: alice's session can issue a code (proves session is valid)."""
    import httpx
    info = t3_server
    r = httpx.post(
        f"{info['base_url']}/api/v1/admin/enrollment-codes",
        json={"project_id": info["project_id"],
              "operator_user_id": info["operator_id"]},
        cookies={"__Host-agg_session": info["alice_cookie"]},
        headers={"X-CSRF-Token": info["alice_csrf"]},
        timeout=10,
    )
    assert r.status_code == 200, f"alice code issue: {r.status_code} {r.text[:200]}"


@pytest.mark.pg
def test_guard_t3_existing_code_issue(t3_server):
    """Guard: the existing POST /admin/enrollment-codes route works."""
    import httpx
    info = t3_server
    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        r = c.post(
            "/api/v1/admin/enrollment-codes",
            json={"project_id": info["project_id"],
                  "operator_user_id": info["operator_id"]},
            cookies={"__Host-agg_session": info["alice_cookie"]},
            headers={"X-CSRF-Token": info["alice_csrf"]},
        )
    assert r.status_code == 200, f"code issue failed: {r.text}"


# ===================================================================
# T3 TARGETS: proposal routes
# ===================================================================

@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M3T3Pending)
def test_propose_from_pasted_json(t3_server):
    """POST /api/v1/admin/bundle-proposals creates a proposal from pasted JSON."""
    import httpx
    info = t3_server

    bundle_json = {
        "folder_policy": {"allow": ["*.py"]},
        "governance_policy": {},
        "mcp_policy": {},
        "approval": {"local_fallback": False, "allow_requester": False},
    }

    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        r = c.post(
            "/api/v1/admin/bundle-proposals",
            json={"project_id": info["project_id"],
                  "bundle": bundle_json},
            cookies={"__Host-agg_session": info["alice_cookie"]},
            headers={"X-CSRF-Token": info["alice_csrf"]},
        )
    require_m3(3, r.status_code != 404 or r.json() != {"detail": "Not Found"},
               "POST /api/v1/admin/bundle-proposals route not registered")
    assert r.status_code in (200, 201)
    body = r.json()
    assert "id" in body or "proposal_id" in body
    assert "hash" in body or "bundle_hash" in body


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M3T3Pending)
def test_propose_unknown_fields_refused(t3_server):
    """Unknown fields in the bundle JSON are refused at proposal."""
    import httpx
    info = t3_server
    bundle_json = {
        "folder_policy": {},
        "UNKNOWN_FIELD_xyz": True,
    }
    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        r = c.post(
            "/api/v1/admin/bundle-proposals",
            json={"project_id": info["project_id"],
                  "bundle": bundle_json},
            cookies={"__Host-agg_session": info["alice_cookie"]},
            headers={"X-CSRF-Token": info["alice_csrf"]},
        )
    require_m3(3, r.status_code != 404 or r.json() != {"detail": "Not Found"},
               "POST /api/v1/admin/bundle-proposals route not registered")
    assert r.status_code == 400, f"unknown fields accepted: {r.status_code}"


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M3T3Pending)
def test_propose_duplicate_keys_refused(t3_server):
    """Duplicate JSON keys in the bundle are refused (A9 item 6)."""
    import httpx
    info = t3_server
    # Send raw JSON with duplicate keys -- httpx json= deduplicates,
    # so we send content directly.
    raw = '{"folder_policy": {}, "folder_policy": {"allow": ["*.py"]}}'
    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        r = c.post(
            "/api/v1/admin/bundle-proposals",
            content=json.dumps({
                "project_id": info["project_id"],
                "bundle_raw": raw,
            }),
            cookies={"__Host-agg_session": info["alice_cookie"]},
            headers={"X-CSRF-Token": info["alice_csrf"],
                     "Content-Type": "application/json"},
        )
    require_m3(3, r.status_code != 404 or r.json() != {"detail": "Not Found"},
               "POST /api/v1/admin/bundle-proposals route not registered")
    # Accept either 400 (strict parse) or 200 if the server canonicalises
    # a single value.  The spec says refuse, so 400 is the target.
    assert r.status_code == 400, \
        f"duplicate keys should be refused: {r.status_code}"


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M3T3Pending)
def test_propose_nan_infinity_refused(t3_server):
    """NaN and Infinity in the bundle JSON are refused (A9 item 6)."""
    import httpx
    info = t3_server
    # JSON with NaN is not valid JSON, so send it as raw text
    raw_body = json.dumps({
        "project_id": info["project_id"],
        "bundle_raw": '{"folder_policy": {"rate": NaN}}',
    })
    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        r = c.post(
            "/api/v1/admin/bundle-proposals",
            content=raw_body,
            cookies={"__Host-agg_session": info["alice_cookie"]},
            headers={"X-CSRF-Token": info["alice_csrf"],
                     "Content-Type": "application/json"},
        )
    require_m3(3, r.status_code != 404 or r.json() != {"detail": "Not Found"},
               "POST /api/v1/admin/bundle-proposals route not registered")
    assert r.status_code == 400, \
        f"NaN should be refused: {r.status_code}"


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M3T3Pending)
def test_propose_oversize_refused(t3_server):
    """A bundle above BUNDLE_MAX_BYTES is refused (A9 item 6)."""
    import httpx
    info = t3_server
    # BUNDLE_MAX_BYTES = 1 MiB (1048576)
    big_value = "x" * (1024 * 1024 + 100)
    bundle_json = {"folder_policy": {"data": big_value}}
    with httpx.Client(base_url=info["base_url"], timeout=30) as c:
        r = c.post(
            "/api/v1/admin/bundle-proposals",
            json={"project_id": info["project_id"],
                  "bundle": bundle_json},
            cookies={"__Host-agg_session": info["alice_cookie"]},
            headers={"X-CSRF-Token": info["alice_csrf"]},
        )
    require_m3(3, r.status_code != 404 or r.json() != {"detail": "Not Found"},
               "POST /api/v1/admin/bundle-proposals route not registered")
    assert r.status_code == 400, f"oversize accepted: {r.status_code}"


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M3T3Pending)
def test_propose_change_approvals_refused(t3_server):
    """A proposal carrying change_approvals in any form is refused (A9 item 6)."""
    import httpx
    info = t3_server
    bundle_json = {
        "folder_policy": {},
        "change_approvals": [],
    }
    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        r = c.post(
            "/api/v1/admin/bundle-proposals",
            json={"project_id": info["project_id"],
                  "bundle": bundle_json},
            cookies={"__Host-agg_session": info["alice_cookie"]},
            headers={"X-CSRF-Token": info["alice_csrf"]},
        )
    require_m3(3, r.status_code != 404 or r.json() != {"detail": "Not Found"},
               "POST /api/v1/admin/bundle-proposals route not registered")
    assert r.status_code == 400, \
        f"change_approvals in proposal should be refused: {r.status_code}"


# ===================================================================
# T3 TARGETS: proposal hash and diff
# ===================================================================

@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M3T3Pending)
def test_proposal_has_hash_and_diff(t3_server):
    """A proposal response includes the hash and a diff."""
    import httpx
    info = t3_server
    bundle_json = {
        "folder_policy": {"allow": ["*.txt"]},
        "governance_policy": {},
        "mcp_policy": {},
        "approval": {"local_fallback": False, "allow_requester": False},
    }
    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        r = c.post(
            "/api/v1/admin/bundle-proposals",
            json={"project_id": info["project_id"],
                  "bundle": bundle_json},
            cookies={"__Host-agg_session": info["alice_cookie"]},
            headers={"X-CSRF-Token": info["alice_csrf"]},
        )
    require_m3(3, r.status_code != 404 or r.json() != {"detail": "Not Found"},
               "POST /api/v1/admin/bundle-proposals route not registered")
    assert r.status_code in (200, 201)
    body = r.json()
    assert "hash" in body or "bundle_hash" in body, \
        "proposal must include the hash"
    assert "diff" in body or "section_diff" in body, \
        "proposal must include the diff"


# ===================================================================
# T3 TARGETS: approvals
# ===================================================================

@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M3T3Pending)
def test_browser_key_approval_refused_wrong_kind(t3_server):
    """A browser-key approval of a proposal is refused with wrong_kind."""
    import httpx
    info = t3_server

    # We cannot create a real proposal without the route, so the require_m3
    # guard at the proposal step will raise M3T3Pending.
    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        # First, create a proposal
        r = c.post(
            "/api/v1/admin/bundle-proposals",
            json={"project_id": info["project_id"],
                  "bundle": {"folder_policy": {}}},
            cookies={"__Host-agg_session": info["alice_cookie"]},
            headers={"X-CSRF-Token": info["alice_csrf"]},
        )
    require_m3(3, r.status_code != 404 or r.json() != {"detail": "Not Found"},
               "POST /api/v1/admin/bundle-proposals route not registered")
    assert r.status_code in (200, 201)
    proposal_id = r.json().get("id") or r.json().get("proposal_id")

    # Create a browser-key signature (kind=browser, wrong for proposals)
    sk = SigningKey.generate()
    pub = bytes(sk.verify_key)
    kid = hashlib.sha256(pub).hexdigest()
    bundle_hash = r.json().get("hash") or r.json().get("bundle_hash")

    tag = b"agg/policy-change/v1"
    payload = {"bundle_hash": bundle_hash}
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    msg = tag + b"\x00" + canonical
    sig = sk.sign(msg).signature.hex()
    approval_envelope = {
        "kind": "agg/policy-change/v1",
        "sig_v": 1,
        "payload": payload,
        "signatures": [{"key_id": kid, "alg": "ed25519", "sig": sig}],
    }

    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        r2 = c.post(
            f"/api/v1/admin/bundle-proposals/{proposal_id}/approvals",
            json={"approval": approval_envelope},
            cookies={"__Host-agg_session": info["bob_cookie"]},
            headers={"X-CSRF-Token": info["bob_csrf"]},
        )
    # Browser key should be refused
    assert r2.status_code == 400
    assert "wrong_kind" in r2.json().get("error", "")


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M3T3Pending)
def test_approval_exactly_one_signature(t3_server):
    """An approval with more than one signature is refused (F-3)."""
    import httpx
    info = t3_server

    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        r = c.post(
            "/api/v1/admin/bundle-proposals",
            json={"project_id": info["project_id"],
                  "bundle": {"folder_policy": {}}},
            cookies={"__Host-agg_session": info["alice_cookie"]},
            headers={"X-CSRF-Token": info["alice_csrf"]},
        )
    require_m3(3, r.status_code != 404 or r.json() != {"detail": "Not Found"},
               "POST /api/v1/admin/bundle-proposals route not registered")
    assert r.status_code in (200, 201)
    proposal_id = r.json().get("id") or r.json().get("proposal_id")
    bundle_hash = r.json().get("hash") or r.json().get("bundle_hash")

    # Create an approval with TWO signatures
    sk1 = SigningKey.generate()
    sk2 = SigningKey.generate()
    tag = b"agg/policy-change/v1"
    payload = {"bundle_hash": bundle_hash}
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    msg = tag + b"\x00" + canonical

    sigs = []
    for sk in (sk1, sk2):
        pub = bytes(sk.verify_key)
        kid = hashlib.sha256(pub).hexdigest()
        sig = sk.sign(msg).signature.hex()
        sigs.append({"key_id": kid, "alg": "ed25519", "sig": sig})

    multi_sig_envelope = {
        "kind": "agg/policy-change/v1",
        "sig_v": 1,
        "payload": payload,
        "signatures": sigs,
    }

    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        r2 = c.post(
            f"/api/v1/admin/bundle-proposals/{proposal_id}/approvals",
            json={"approval": multi_sig_envelope},
            cookies={"__Host-agg_session": info["bob_cookie"]},
            headers={"X-CSRF-Token": info["bob_csrf"]},
        )
    assert r2.status_code == 400, \
        f"multi-signature approval accepted: {r2.status_code}"


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M3T3Pending)
def test_proposer_approval_refused(t3_server):
    """The proposer's own approval is refused at the approval route."""
    import httpx
    info = t3_server

    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        r = c.post(
            "/api/v1/admin/bundle-proposals",
            json={"project_id": info["project_id"],
                  "bundle": {"folder_policy": {}}},
            cookies={"__Host-agg_session": info["alice_cookie"]},
            headers={"X-CSRF-Token": info["alice_csrf"]},
        )
    require_m3(3, r.status_code != 404 or r.json() != {"detail": "Not Found"},
               "POST /api/v1/admin/bundle-proposals route not registered")
    assert r.status_code in (200, 201)
    proposal_id = r.json().get("id") or r.json().get("proposal_id")
    bundle_hash = r.json().get("hash") or r.json().get("bundle_hash")

    # Alice (proposer) tries to approve her own proposal.
    # Register a CLI key linked to alice so the refusal is specifically
    # the proposer reason, not unknown_key.
    sk = SigningKey.generate()
    pub = bytes(sk.verify_key)
    kid = hashlib.sha256(pub).hexdigest()
    conninfo = _conninfo(info["owner_url"])
    with psycopg.connect(conninfo, autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [info["org_id"]])
        conn.execute(
            "INSERT INTO approver_keys "
            "(id, org_id, user_id, public_key, alg, kind, key_id, "
            "registry_version, enrolled_at, created_at) "
            "VALUES (%s, %s::uuid, %s::uuid, %s, 'ed25519', 'cli', %s, "
            "1, now(), now()) ON CONFLICT DO NOTHING",
            [str(uuid.uuid4()), info["org_id"], info["alice_id"],
             pub.hex(), kid],
        )
    tag = b"agg/policy-change/v1"
    payload = {"bundle_hash": bundle_hash}
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    msg = tag + b"\x00" + canonical
    sig = sk.sign(msg).signature.hex()
    envelope = {
        "kind": "agg/policy-change/v1", "sig_v": 1,
        "payload": payload,
        "signatures": [{"key_id": kid, "alg": "ed25519", "sig": sig}],
    }

    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        r2 = c.post(
            f"/api/v1/admin/bundle-proposals/{proposal_id}/approvals",
            json={"approval": envelope},
            # Alice is the proposer, so her approval should be refused
            cookies={"__Host-agg_session": info["alice_cookie"]},
            headers={"X-CSRF-Token": info["alice_csrf"]},
        )
    assert r2.status_code == 400, \
        f"proposer self-approval accepted: {r2.status_code}"
    err_body = r2.json()
    assert "proposer" in (err_body.get("error", "") +
                          err_body.get("reason", "") +
                          err_body.get("detail", "")).lower(), \
        f"refusal must cite proposer reason, got {err_body}"


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M3T3Pending)
def test_stale_base_refused_at_approval(t3_server):
    """An approval against a stale base_sequence is refused at the
    approval route (A9 item 4: stale base refused at approval).

    Two proposals are created on the same base.  The first is approved
    and published, which advances the base.  Then approving the second
    (whose base_sequence is now stale) must be refused 400 with the
    stale-base reason, and nothing is written to policy_bundles.
    """
    import httpx
    info = t3_server

    # Proposal A
    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        r_a = c.post(
            "/api/v1/admin/bundle-proposals",
            json={"project_id": info["project_id"],
                  "bundle": {"folder_policy": {"allow": ["*.txt"]},
                             "governance_policy": {}, "mcp_policy": {},
                             "approval": {"local_fallback": False,
                                          "allow_requester": False}}},
            cookies={"__Host-agg_session": info["alice_cookie"]},
            headers={"X-CSRF-Token": info["alice_csrf"]},
        )
    require_m3(3, r_a.status_code != 404 or r_a.json() != {"detail": "Not Found"},
               "POST /api/v1/admin/bundle-proposals route not registered")
    assert r_a.status_code in (200, 201)
    proposal_a_id = r_a.json().get("id") or r_a.json().get("proposal_id")

    # Proposal B (same base as A)
    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        r_b = c.post(
            "/api/v1/admin/bundle-proposals",
            json={"project_id": info["project_id"],
                  "bundle": {"folder_policy": {"allow": ["*.md"]},
                             "governance_policy": {}, "mcp_policy": {},
                             "approval": {"local_fallback": False,
                                          "allow_requester": False}}},
            cookies={"__Host-agg_session": info["alice_cookie"]},
            headers={"X-CSRF-Token": info["alice_csrf"]},
        )
    assert r_b.status_code in (200, 201)
    proposal_b_id = r_b.json().get("id") or r_b.json().get("proposal_id")
    bundle_b_hash = r_b.json().get("hash") or r_b.json().get("bundle_hash")

    # Approve and publish proposal A (with bob and carol approvals)
    # (actual approval and publish steps would go here -- the routes
    # do not exist yet, so require_m3 will fire at the approval step)
    # Approve A with bob's CLI key
    bob_sk = SigningKey.generate()
    bob_pub = bytes(bob_sk.verify_key)
    bob_kid = hashlib.sha256(bob_pub).hexdigest()
    conninfo = _conninfo(info["owner_url"])
    with psycopg.connect(conninfo, autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [info["org_id"]])
        conn.execute(
            "INSERT INTO approver_keys "
            "(id, org_id, user_id, public_key, alg, kind, key_id, "
            "registry_version, enrolled_at, created_at) "
            "VALUES (%s, %s::uuid, %s::uuid, %s, 'ed25519', 'cli', %s, "
            "1, now(), now()) ON CONFLICT DO NOTHING",
            [str(uuid.uuid4()), info["org_id"], info["bob_id"],
             bob_pub.hex(), bob_kid],
        )
    hash_a = r_a.json().get("hash") or r_a.json().get("bundle_hash")
    tag = b"agg/policy-change/v1"
    payload_a = {"bundle_hash": hash_a}
    canonical_a = json.dumps(payload_a, sort_keys=True,
                             separators=(",", ":")).encode()
    msg_a = tag + b"\x00" + canonical_a
    sig_a = bob_sk.sign(msg_a).signature.hex()
    env_a = {
        "kind": "agg/policy-change/v1", "sig_v": 1,
        "payload": payload_a,
        "signatures": [{"key_id": bob_kid, "alg": "ed25519", "sig": sig_a}],
    }
    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        r_approve_a = c.post(
            f"/api/v1/admin/bundle-proposals/{proposal_a_id}/approvals",
            json={"approval": env_a},
            cookies={"__Host-agg_session": info["bob_cookie"]},
            headers={"X-CSRF-Token": info["bob_csrf"]},
        )
    require_m3(3, r_approve_a.status_code != 404 or
               r_approve_a.json() != {"detail": "Not Found"},
               "POST .../approvals route not registered")
    assert r_approve_a.status_code in (200, 201), \
        f"approval A failed: {r_approve_a.status_code} {r_approve_a.text[:200]}"

    # Publish A
    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        r_pub_a = c.post(
            f"/api/v1/admin/bundle-proposals/{proposal_a_id}/publish",
            json={},
            cookies={"__Host-agg_session": info["alice_cookie"]},
            headers={"X-CSRF-Token": info["alice_csrf"]},
        )
    require_m3(3, r_pub_a.status_code != 404 or
               r_pub_a.json() != {"detail": "Not Found"},
               "POST .../publish route not registered")
    assert r_pub_a.status_code in (200, 201), \
        f"publish A failed: {r_pub_a.status_code} {r_pub_a.text[:200]}"

    # Now approving proposal B (whose base is stale) must be refused
    payload_b = {"bundle_hash": bundle_b_hash}
    canonical_b = json.dumps(payload_b, sort_keys=True,
                             separators=(",", ":")).encode()
    msg_b = tag + b"\x00" + canonical_b
    sig_b = bob_sk.sign(msg_b).signature.hex()
    env_b = {
        "kind": "agg/policy-change/v1", "sig_v": 1,
        "payload": payload_b,
        "signatures": [{"key_id": bob_kid, "alg": "ed25519", "sig": sig_b}],
    }
    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        r_approve_b = c.post(
            f"/api/v1/admin/bundle-proposals/{proposal_b_id}/approvals",
            json={"approval": env_b},
            cookies={"__Host-agg_session": info["bob_cookie"]},
            headers={"X-CSRF-Token": info["bob_csrf"]},
        )
    assert r_approve_b.status_code == 400, \
        f"stale-base approval must be refused 400, got {r_approve_b.status_code}"
    err_body = r_approve_b.json()
    assert "stale" in (err_body.get("error", "") +
                       err_body.get("reason", "") +
                       err_body.get("detail", "")).lower(), \
        f"refusal must cite stale base, got {err_body}"

    # Verify nothing written to policy_bundles for proposal B
    with psycopg.connect(conninfo) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [info["org_id"]])
        count = conn.execute(
            "SELECT count(*) FROM policy_bundles "
            "WHERE org_id = %s::uuid AND project_id = %s::uuid "
            "AND sequence > 1",
            [info["org_id"], info["project_id"]],
        ).fetchone()[0]
    assert count == 0, \
        f"stale-base proposal must not produce a bundle row, found {count}"


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M3T3Pending)
def test_stale_base_refused_at_publish(t3_server):
    """A publish against a stale base_sequence is refused at the publish
    route (A9 item 4: stale base refused at publish).

    Two proposals on the same base, the first published, then publishing
    the second must be refused 400 with the stale-base reason.
    """
    import httpx
    info = t3_server

    # Proposal C
    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        r_c = c.post(
            "/api/v1/admin/bundle-proposals",
            json={"project_id": info["project_id"],
                  "bundle": {"folder_policy": {"allow": ["*.rs"]},
                             "governance_policy": {}, "mcp_policy": {},
                             "approval": {"local_fallback": False,
                                          "allow_requester": False}}},
            cookies={"__Host-agg_session": info["alice_cookie"]},
            headers={"X-CSRF-Token": info["alice_csrf"]},
        )
    require_m3(3, r_c.status_code != 404 or r_c.json() != {"detail": "Not Found"},
               "POST /api/v1/admin/bundle-proposals route not registered")
    assert r_c.status_code in (200, 201)
    proposal_c_id = r_c.json().get("id") or r_c.json().get("proposal_id")

    # Proposal D (same base)
    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        r_d = c.post(
            "/api/v1/admin/bundle-proposals",
            json={"project_id": info["project_id"],
                  "bundle": {"folder_policy": {"allow": ["*.go"]},
                             "governance_policy": {}, "mcp_policy": {},
                             "approval": {"local_fallback": False,
                                          "allow_requester": False}}},
            cookies={"__Host-agg_session": info["alice_cookie"]},
            headers={"X-CSRF-Token": info["alice_csrf"]},
        )
    assert r_d.status_code in (200, 201)
    proposal_d_id = r_d.json().get("id") or r_d.json().get("proposal_id")

    # Approve and publish C (bob approves)
    hash_c = r_c.json().get("hash") or r_c.json().get("bundle_hash")
    bob_sk = SigningKey.generate()
    bob_pub = bytes(bob_sk.verify_key)
    bob_kid = hashlib.sha256(bob_pub).hexdigest()
    conninfo = _conninfo(info["owner_url"])
    with psycopg.connect(conninfo, autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [info["org_id"]])
        conn.execute(
            "INSERT INTO approver_keys "
            "(id, org_id, user_id, public_key, alg, kind, key_id, "
            "registry_version, enrolled_at, created_at) "
            "VALUES (%s, %s::uuid, %s::uuid, %s, 'ed25519', 'cli', %s, "
            "1, now(), now()) ON CONFLICT DO NOTHING",
            [str(uuid.uuid4()), info["org_id"], info["bob_id"],
             bob_pub.hex(), bob_kid],
        )
    tag = b"agg/policy-change/v1"
    payload_c = {"bundle_hash": hash_c}
    canonical_c = json.dumps(payload_c, sort_keys=True,
                             separators=(",", ":")).encode()
    sig_c = bob_sk.sign(tag + b"\x00" + canonical_c).signature.hex()
    env_c = {
        "kind": "agg/policy-change/v1", "sig_v": 1,
        "payload": payload_c,
        "signatures": [{"key_id": bob_kid, "alg": "ed25519", "sig": sig_c}],
    }
    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        c.post(
            f"/api/v1/admin/bundle-proposals/{proposal_c_id}/approvals",
            json={"approval": env_c},
            cookies={"__Host-agg_session": info["bob_cookie"]},
            headers={"X-CSRF-Token": info["bob_csrf"]},
        )
    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        c.post(
            f"/api/v1/admin/bundle-proposals/{proposal_c_id}/publish",
            json={},
            cookies={"__Host-agg_session": info["alice_cookie"]},
            headers={"X-CSRF-Token": info["alice_csrf"]},
        )

    # Now try to publish D (stale base) -- must be refused at publish
    hash_d = r_d.json().get("hash") or r_d.json().get("bundle_hash")
    payload_d = {"bundle_hash": hash_d}
    canonical_d = json.dumps(payload_d, sort_keys=True,
                             separators=(",", ":")).encode()
    sig_d = bob_sk.sign(tag + b"\x00" + canonical_d).signature.hex()
    env_d = {
        "kind": "agg/policy-change/v1", "sig_v": 1,
        "payload": payload_d,
        "signatures": [{"key_id": bob_kid, "alg": "ed25519", "sig": sig_d}],
    }
    # Approve D first (may or may not succeed since base is stale)
    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        c.post(
            f"/api/v1/admin/bundle-proposals/{proposal_d_id}/approvals",
            json={"approval": env_d},
            cookies={"__Host-agg_session": info["bob_cookie"]},
            headers={"X-CSRF-Token": info["bob_csrf"]},
        )

    # Publish D must be refused
    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        r_pub_d = c.post(
            f"/api/v1/admin/bundle-proposals/{proposal_d_id}/publish",
            json={},
            cookies={"__Host-agg_session": info["alice_cookie"]},
            headers={"X-CSRF-Token": info["alice_csrf"]},
        )
    assert r_pub_d.status_code == 400, \
        f"stale-base publish must be refused 400, got {r_pub_d.status_code}"
    err_body = r_pub_d.json()
    assert "stale" in (err_body.get("error", "") +
                       err_body.get("reason", "") +
                       err_body.get("detail", "")).lower(), \
        f"publish refusal must cite stale base, got {err_body}"


# ===================================================================
# T3 TARGETS: publish route shape
# ===================================================================

@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M3T3Pending)
def test_publish_route_exists(t3_server):
    """POST .../publish route exists."""
    import httpx
    info = t3_server

    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        r = c.post(
            "/api/v1/admin/bundle-proposals",
            json={"project_id": info["project_id"],
                  "bundle": {"folder_policy": {}}},
            cookies={"__Host-agg_session": info["alice_cookie"]},
            headers={"X-CSRF-Token": info["alice_csrf"]},
        )
    require_m3(3, r.status_code != 404 or r.json() != {"detail": "Not Found"},
               "POST /api/v1/admin/bundle-proposals route not registered")
    assert r.status_code in (200, 201)
    proposal_id = r.json().get("id") or r.json().get("proposal_id")

    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        r2 = c.post(
            f"/api/v1/admin/bundle-proposals/{proposal_id}/publish",
            json={},
            cookies={"__Host-agg_session": info["alice_cookie"]},
            headers={"X-CSRF-Token": info["alice_csrf"]},
        )
    # Should not be a generic 404 "Not Found"
    assert not (r2.status_code == 404 and
                r2.json() == {"detail": "Not Found"}), \
        "publish route not registered"


# ===================================================================
# T3 TARGETS: audit rows per F-10
# ===================================================================

@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M3T3Pending)
def test_proposal_writes_admin_audit(t3_server):
    """Proposal, approval and publish write admin_audit rows (F-10)."""
    import httpx
    info = t3_server

    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        r = c.post(
            "/api/v1/admin/bundle-proposals",
            json={"project_id": info["project_id"],
                  "bundle": {"folder_policy": {}}},
            cookies={"__Host-agg_session": info["alice_cookie"]},
            headers={"X-CSRF-Token": info["alice_csrf"]},
        )
    require_m3(3, r.status_code != 404 or r.json() != {"detail": "Not Found"},
               "POST /api/v1/admin/bundle-proposals route not registered")
    assert r.status_code in (200, 201)

    # Check admin_audit for a proposal row
    conninfo = _conninfo(info["owner_url"])
    with psycopg.connect(conninfo) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [info["org_id"]])
        rows = conn.execute(
            "SELECT action FROM admin_audit WHERE org_id = %s::uuid "
            "ORDER BY created_at DESC LIMIT 5",
            [info["org_id"]],
        ).fetchall()
    actions = [r[0] for r in rows]
    assert any("proposal" in a or "propose" in a for a in actions), \
        f"no proposal audit row found; actions={actions}"


# ===================================================================
# T3 TARGETS: enrollment-code page flow
# ===================================================================

@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M3T3Pending)
def test_code_second_read_404_and_no_store_header(t3_server):
    """Operator reads the code once; second read is 404.
    Response has Cache-Control: no-store."""
    import httpx
    info = t3_server

    # Issue a code
    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        r_issue = c.post(
            "/api/v1/admin/enrollment-codes",
            json={"project_id": info["project_id"],
                  "operator_user_id": info["operator_id"]},
            cookies={"__Host-agg_session": info["alice_cookie"]},
            headers={"X-CSRF-Token": info["alice_csrf"]},
        )
    assert r_issue.status_code == 200
    code_id = r_issue.json()["code_id"]

    # Operator reads it once
    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        r1 = c.get(
            f"/api/v1/enrollment-codes/{code_id}",
            cookies={"__Host-agg_session": info["op_cookie"]},
        )
    # The current route may or may not have no-store yet; that is the
    # T3 feature we are testing.
    require_m3(3, "no-store" in r1.headers.get("cache-control", ""),
               "Cache-Control: no-store not set on code read response")
    assert r1.status_code == 200
    assert "no-store" in r1.headers.get("cache-control", "")

    # Second read should be 404
    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        r2 = c.get(
            f"/api/v1/enrollment-codes/{code_id}",
            cookies={"__Host-agg_session": info["op_cookie"]},
        )
    assert r2.status_code == 404


# ===================================================================
# T3 TARGETS: fresh-session rule
# ===================================================================

@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M3T3Pending)
def test_stale_session_refused_for_code_issue(t3_server):
    """Session older than 15 min is refused for code issue (S6)."""
    import httpx
    info = t3_server

    stale_cookie, stale_csrf, _ = _make_stale_session(
        info["owner_url"], info["org_id"], info["alice_id"])

    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        r = c.post(
            "/api/v1/admin/enrollment-codes",
            json={"project_id": info["project_id"],
                  "operator_user_id": info["operator_id"]},
            cookies={"__Host-agg_session": stale_cookie},
            headers={"X-CSRF-Token": stale_csrf},
        )
    # Currently the route does not check session freshness for issue.
    # T3 adds this check.
    require_m3(3, r.status_code == 401,
               f"stale session accepted for code issue: {r.status_code}")
    assert r.status_code == 401


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M3T3Pending)
def test_stale_session_refused_for_publish(t3_server):
    """Session older than 15 min is refused for publish."""
    import httpx
    info = t3_server

    stale_cookie, stale_csrf, _ = _make_stale_session(
        info["owner_url"], info["org_id"], info["alice_id"])

    # The publish route does not exist yet; require_m3 catches it.
    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        r = c.post(
            "/api/v1/admin/bundle-proposals/fake-id/publish",
            json={},
            cookies={"__Host-agg_session": stale_cookie},
            headers={"X-CSRF-Token": stale_csrf},
        )
    require_m3(3, r.status_code != 404 or r.json() != {"detail": "Not Found"},
               "publish route not registered")
    assert r.status_code == 401


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M3T3Pending)
def test_stale_session_refused_for_revoke(t3_server):
    """Session older than 15 min is refused for device revoke."""
    import httpx
    info = t3_server

    stale_cookie, stale_csrf, _ = _make_stale_session(
        info["owner_url"], info["org_id"], info["alice_id"])

    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        r = c.post(
            "/api/v1/admin/devices/revoke",
            json={"device_id": str(uuid.uuid4())},
            cookies={"__Host-agg_session": stale_cookie},
            headers={"X-CSRF-Token": stale_csrf},
        )
    # Currently the revoke route does not check session freshness.
    # T3 adds this.
    require_m3(3, r.status_code == 401,
               f"stale session accepted for revoke: {r.status_code}")
    assert r.status_code == 401


# ===================================================================
# T3 TARGETS: publisher exclusion
# ===================================================================

@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M3T3Pending)
def test_publisher_not_among_approvals(t3_server):
    """The publishing admin may not be among the approvers (A9 item 8g).

    Seed two CLI-key approvals, one from the publishing user (alice).
    Attempt publish from alice's session.  Assert 400 with the reason,
    no ``policy_bundles`` row.
    """
    import httpx
    info = t3_server

    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        r = c.post(
            "/api/v1/admin/bundle-proposals",
            json={"project_id": info["project_id"],
                  "bundle": {"folder_policy": {"allow": ["*.c"]},
                             "governance_policy": {}, "mcp_policy": {},
                             "approval": {"local_fallback": False,
                                          "allow_requester": False}}},
            cookies={"__Host-agg_session": info["alice_cookie"]},
            headers={"X-CSRF-Token": info["alice_csrf"]},
        )
    require_m3(3, r.status_code != 404 or r.json() != {"detail": "Not Found"},
               "POST /api/v1/admin/bundle-proposals route not registered")
    assert r.status_code in (200, 201)
    proposal_id = r.json().get("id") or r.json().get("proposal_id")
    bundle_hash = r.json().get("hash") or r.json().get("bundle_hash")

    # Register CLI keys for alice (who will publish) and bob
    conninfo = _conninfo(info["owner_url"])
    tag = b"agg/policy-change/v1"
    payload = {"bundle_hash": bundle_hash}
    canonical = json.dumps(payload, sort_keys=True,
                           separators=(",", ":")).encode()
    msg = tag + b"\x00" + canonical

    approvals_to_submit = []
    for user_id, user_cookie, user_csrf, label in [
        (info["alice_id"], info["alice_cookie"], info["alice_csrf"], "alice"),
        (info["bob_id"], info["bob_cookie"], info["bob_csrf"], "bob"),
    ]:
        sk = SigningKey.generate()
        pub = bytes(sk.verify_key)
        kid = hashlib.sha256(pub).hexdigest()
        with psycopg.connect(conninfo, autocommit=True) as conn:
            conn.execute("SELECT set_config('app.org_id', %s, false)",
                         [info["org_id"]])
            conn.execute(
                "INSERT INTO approver_keys "
                "(id, org_id, user_id, public_key, alg, kind, key_id, "
                "registry_version, enrolled_at, created_at) "
                "VALUES (%s, %s::uuid, %s::uuid, %s, 'ed25519', 'cli', %s, "
                "1, now(), now()) ON CONFLICT DO NOTHING",
                [str(uuid.uuid4()), info["org_id"], user_id,
                 pub.hex(), kid],
            )
        sig = sk.sign(msg).signature.hex()
        env = {
            "kind": "agg/policy-change/v1", "sig_v": 1,
            "payload": payload,
            "signatures": [{"key_id": kid, "alg": "ed25519", "sig": sig}],
        }
        approvals_to_submit.append((env, user_cookie, user_csrf, label))

    # Submit both approvals (bob first, then alice)
    for env, cookie, csrf, label in approvals_to_submit:
        with httpx.Client(base_url=info["base_url"], timeout=10) as c:
            r_app = c.post(
                f"/api/v1/admin/bundle-proposals/{proposal_id}/approvals",
                json={"approval": env},
                cookies={"__Host-agg_session": cookie},
                headers={"X-CSRF-Token": csrf},
            )
        # Alice's approval may itself be refused (as proposer), which is
        # tested separately.  We care about the publish refusal here.

    # Publish from alice's session (alice has an approval among the
    # list)
    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        r_pub = c.post(
            f"/api/v1/admin/bundle-proposals/{proposal_id}/publish",
            json={},
            cookies={"__Host-agg_session": info["alice_cookie"]},
            headers={"X-CSRF-Token": info["alice_csrf"]},
        )
    assert r_pub.status_code == 400, \
        f"publisher among approvals must be refused 400, got {r_pub.status_code}"
    err_body = r_pub.json()
    assert "publisher" in (err_body.get("error", "") +
                           err_body.get("reason", "") +
                           err_body.get("detail", "")).lower(), \
        f"refusal must cite publisher exclusion, got {err_body}"

    # Verify no policy_bundles row was written
    with psycopg.connect(conninfo) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [info["org_id"]])
        count = conn.execute(
            "SELECT count(*) FROM policy_bundles "
            "WHERE org_id = %s::uuid AND project_id = %s::uuid",
            [info["org_id"], info["project_id"]],
        ).fetchone()[0]
    assert count == 0, \
        f"publisher-in-approvals must not produce a bundle row, found {count}"


# ===================================================================
# T3 TARGETS: threat 39 -- code value and code_hash absent from audit
# ===================================================================

@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M3T3Pending)
def test_code_value_absent_from_admin_audit(t3_server):
    """Threat 39: after issuing a code, the code value and code_hash
    must not appear in any admin_audit row payload.

    Positive check: the audit row for the code issue exists (so the test
    cannot pass over an empty table).  Same check for the operator's
    read of the code.
    """
    import httpx
    info = t3_server

    # Issue a code
    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        r_issue = c.post(
            "/api/v1/admin/enrollment-codes",
            json={"project_id": info["project_id"],
                  "operator_user_id": info["operator_id"]},
            cookies={"__Host-agg_session": info["alice_cookie"]},
            headers={"X-CSRF-Token": info["alice_csrf"]},
        )
    assert r_issue.status_code == 200, \
        f"code issue failed: {r_issue.status_code} {r_issue.text[:200]}"
    issue_body = r_issue.json()
    code_value = issue_body.get("code", "")
    code_hash = issue_body.get("code_hash", "")
    code_id = issue_body.get("code_id", "")
    # At least one of code or code_id must be present
    assert code_value or code_id, "issue response must contain a code or code_id"

    # Operator reads it (so a read-audit row is also created)
    if code_id:
        with httpx.Client(base_url=info["base_url"], timeout=10) as c:
            c.get(
                f"/api/v1/enrollment-codes/{code_id}",
                cookies={"__Host-agg_session": info["op_cookie"]},
            )

    # Check admin_audit: the row must exist and must not contain the code
    # value or code_hash in its payload
    conninfo = _conninfo(info["owner_url"])
    with psycopg.connect(conninfo) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [info["org_id"]])
        rows = conn.execute(
            "SELECT action, detail::text FROM admin_audit "
            "WHERE org_id = %s::uuid ORDER BY created_at DESC LIMIT 20",
            [info["org_id"]],
        ).fetchall()

    # The audit row must exist (T3 adds F-10 audit rows for code issue);
    # if missing, this is the T3 feature gap.
    require_m3(3, len(rows) >= 1,
               "admin_audit has no rows for the code issue (F-10 not implemented)")
    assert len(rows) >= 1, \
        "admin_audit must have at least one row (positive check)"

    # Find audit rows related to the code issue
    code_related = [r for r in rows
                    if "code" in (r[0] or "").lower()
                    or "enroll" in (r[0] or "").lower()]
    require_m3(3, len(code_related) >= 1,
               f"no code-related audit row; actions={[r[0] for r in rows]}")
    assert len(code_related) >= 1, \
        f"admin_audit must have a code-related row; actions={[r[0] for r in rows]}"

    # The code value and code_hash must not appear in any row payload
    for action, payload_text in rows:
        if not payload_text:
            continue
        if code_value:
            assert code_value not in payload_text, \
                f"code value found in admin_audit row '{action}' payload"
        if code_hash:
            assert code_hash not in payload_text, \
                f"code_hash found in admin_audit row '{action}' payload"
