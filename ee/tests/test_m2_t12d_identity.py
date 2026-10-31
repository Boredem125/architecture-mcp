"""T12d d5 tests-first: identity binding (ADR 0011 A1) bypass tests.

Server bypass tests B1-B11, twins, C1-C3, and E1-E2 end-to-end.
Every new test that requires the d5 build carries
``xfail(strict=True, raises=M2T12dIdentityPending)``.

A1.4 rule 1: no ``store_registry_version`` call and no raw INSERT/UPDATE/DELETE
on ``key_registry_versions``, ``approver_keys``, ``signer_links`` or
``enrollments``.  Allowed seeding: ``users``, ``role_bindings``, ``projects``,
``web_sessions`` (via ``seed_session``), ``setup_codes`` (genesis code).
"""
from __future__ import annotations

import concurrent.futures
import hashlib
import json
import os
import time
import uuid

import psycopg
import pytest
from nacl.signing import SigningKey

from .test_m2_t12d_genesis import (
    _conninfo, _seed_user_row, _grant_role, _make_fresh_session,
    _kid, _get_signer_token_httpx, _seed_genesis_code, _fresh_org,
    _build_genesis_envelope,
)
from .m2_sync_server import (
    make_sync_server, create_org, create_project,
)
from .t9_helpers import seed_session, make_session_cookie, compute_csrf
from .fake_idp import FakeClock


# ---------------------------------------------------------------------------
# Sentinel
# ---------------------------------------------------------------------------

class M2T12dIdentityPending(Exception):
    """T12d d5: identity binding (ADR 0011 A1)."""


# ---------------------------------------------------------------------------
# Module-level bundle-signer pub (set by fixture)
# ---------------------------------------------------------------------------

_IDENTITY_BUNDLE_SIGNER_PUB: bytes | None = None


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def identity_bundle_signer(tmp_path_factory):
    """Module-scoped bundle signer key, sets AGG_BUNDLE_SIGNER_KEY_FILE."""
    global _IDENTITY_BUNDLE_SIGNER_PUB
    key_dir = tmp_path_factory.mktemp("bundle_signer_identity")
    key_file = key_dir / "bundle_signer.key"
    sk = SigningKey.generate()
    key_file.write_bytes(bytes(sk).hex().encode("ascii"))
    old_env = os.environ.get("AGG_BUNDLE_SIGNER_KEY_FILE")
    os.environ["AGG_BUNDLE_SIGNER_KEY_FILE"] = str(key_file)
    _IDENTITY_BUNDLE_SIGNER_PUB = bytes(sk.verify_key)
    yield {
        "key_file": str(key_file),
        "signing_key": sk,
        "public_key_bytes": bytes(sk.verify_key),
        "public_key_hex": bytes(sk.verify_key).hex(),
    }
    _IDENTITY_BUNDLE_SIGNER_PUB = None
    if old_env is None:
        os.environ.pop("AGG_BUNDLE_SIGNER_KEY_FILE", None)
    else:
        os.environ["AGG_BUNDLE_SIGNER_KEY_FILE"] = old_env


@pytest.fixture(scope="module")
def identity_server(pg_url, app_url, owner_url, pg_roles,
                    identity_bundle_signer):
    yield from make_sync_server(
        pg_url, app_url, owner_url,
        org_names=["Identity A", "Identity B"],
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_KEY_ENTRY_FIELDS = (
    "key_id", "public_key", "kind", "alg", "user_id",
    "iss", "sub", "roles", "added_in",
)


def _route_cli_link(srv, org_id, user_id):
    """Web session -> POST /signer-links -> link code -> POST /signer/link.
    Returns (sk, kid)."""
    import httpx
    base = srv["base_url"]
    owner_url = srv["owner_url"]

    cookie, csrf = _make_fresh_session(owner_url, org_id, user_id)
    r = httpx.post(
        f"{base}/api/v1/signer-links",
        cookies={"__Host-agg_session": cookie},
        headers={"X-CSRF-Token": csrf},
        json={},
        timeout=10,
    )
    assert r.status_code == 200, f"signer-links failed: {r.status_code} {r.text}"
    code = r.json()["code"]

    sk = SigningKey.generate()
    kid = _kid(sk)
    r2 = httpx.post(f"{base}/api/v1/sync/signer/link", json={
        "code": code, "key_id": kid,
        "public_key": bytes(sk.verify_key).hex(),
    }, timeout=10)
    assert r2.status_code == 200, f"link failed: {r2.status_code} {r2.text}"
    return sk, kid


def _route_browser_enroll(srv, org_id, user_id):
    """Web session -> POST /signer-links kind=browser.
    Returns (sk, kid)."""
    import httpx
    base = srv["base_url"]
    owner_url = srv["owner_url"]

    sk = SigningKey.generate()
    kid = _kid(sk)
    pub_hex = bytes(sk.verify_key).hex()

    cookie, csrf = _make_fresh_session(owner_url, org_id, user_id)
    r = httpx.post(
        f"{base}/api/v1/signer-links",
        cookies={"__Host-agg_session": cookie},
        headers={"X-CSRF-Token": csrf},
        json={"kind": "browser", "key_id": kid, "public_key": pub_hex},
        timeout=10,
    )
    assert r.status_code in (200, 201), (
        f"browser enroll failed: {r.status_code} {r.text}"
    )
    return sk, kid


def _seed_people(srv, org_id):
    """Seed alice, carol (admin), bob, dave, erin (no binding).
    Returns dict with ids, iss, sub per person."""
    owner_url = srv["owner_url"]
    people = {}
    with psycopg.connect(_conninfo(owner_url), autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        for name, role in [("alice", "admin"), ("carol", "admin"),
                           ("bob", None), ("dave", None), ("erin", None)]:
            uid, iss, sub = _seed_user_row(
                conn, org_id, f"{name}@identity.test",
                sub=f"sub-{name}-{uuid.uuid4().hex[:6]}",
            )
            if role:
                _grant_role(conn, org_id, uid, role)
            people[name] = {"uid": uid, "iss": iss, "sub": sub}
    return people


def _genesis(srv, org_id, people):
    """Run genesis with alice. Returns ctx dict."""
    import httpx
    base = srv["base_url"]
    owner_url = srv["owner_url"]

    alice = people["alice"]
    sk_a, kid_a = _route_cli_link(srv, org_id, alice["uid"])

    # Get pending token
    token_pending = _get_signer_token_httpx(base, sk_a, kid_a)
    assert token_pending is not None

    # Seed genesis code
    with psycopg.connect(_conninfo(owner_url), autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        gcode = _seed_genesis_code(conn, org_id)

    bs_pub = _IDENTITY_BUNDLE_SIGNER_PUB
    env = _build_genesis_envelope(
        sk_a, org_id, user_id=alice["uid"],
        iss=alice["iss"], sub=alice["sub"],
        roles=["admin"],
        bundle_signer_pub=bs_pub,
    )

    r = httpx.post(
        f"{base}/api/v1/sync/signer/genesis",
        json={"genesis_code": gcode, "envelope": env},
        headers={"Authorization": f"Bearer {token_pending}"},
        timeout=15,
    )
    assert r.status_code == 200, f"genesis failed: {r.status_code} {r.text}"

    # Get confirmed token
    token_confirmed = _get_signer_token_httpx(base, sk_a, kid_a)
    assert token_confirmed is not None

    v1 = env
    v1_canonical = json.dumps(v1["payload"], sort_keys=True,
                              separators=(",", ":")).encode()
    fp = hashlib.sha256(
        org_id.encode("utf-8") + b":" + v1_canonical,
    ).hexdigest()

    return {
        "chain": [v1],
        "fp": fp,
        "alice_sk": sk_a,
        "alice_kid": kid_a,
        "alice_token": token_confirmed,
        "bs_pub": bs_pub,
        "org_id": org_id,
        "people": people,
    }


def _entry(sk, uid, iss, sub, *, kind="cli", roles=("approver",), added_in):
    """Build one registry key entry."""
    pub = bytes(sk.verify_key)
    kid = _kid(sk)
    return {
        "key_id": kid,
        "public_key": pub.hex(),
        "kind": kind,
        "alg": "ed25519",
        "user_id": uid,
        "iss": iss,
        "sub": sub,
        "roles": list(roles),
        "added_in": added_in,
    }


def _payload_hash(payload):
    """sha256(org_id + ':' + canonical(payload))."""
    canonical = json.dumps(payload, sort_keys=True,
                           separators=(",", ":")).encode()
    return hashlib.sha256(
        payload["org_id"].encode("utf-8") + b":" + canonical,
    ).hexdigest()


def _next(ctx, *, add=(), drop=(), replace=None, admins=None,
          threshold=None, signers=()):
    """Build vN+1 from ctx.chain[-1]."""
    prev = ctx["chain"][-1]
    prev_payload = prev["payload"]
    prev_hash = _payload_hash(prev_payload)
    version = prev_payload["version"] + 1

    # Build keys: carry minus drop, replace swapped, plus add
    prev_keys = list(prev_payload.get("keys", []))
    drop_ids = {e["key_id"] for e in drop} if drop else set()
    replace_map = {}
    if replace:
        for e in replace:
            replace_map[e["key_id"]] = e

    new_keys = []
    for k in prev_keys:
        if k["key_id"] in drop_ids:
            continue
        if k["key_id"] in replace_map:
            new_keys.append(replace_map[k["key_id"]])
        else:
            new_keys.append(k)
    new_keys.extend(add)

    new_admins = admins if admins is not None else prev_payload.get("admins", [])
    new_threshold = threshold if threshold is not None else prev_payload["threshold"]

    payload = {
        "org_id": prev_payload["org_id"],
        "version": version,
        "prev_hash": prev_hash,
        "threshold": new_threshold,
        "admins": new_admins,
        "keys": new_keys,
        "bundle_signer": prev_payload["bundle_signer"],
        "expires_at": time.time() + 6 * 24 * 3600,
    }

    # Sign
    tag = b"agg/registry/v1"
    canonical = json.dumps(payload, sort_keys=True,
                           separators=(",", ":")).encode()
    msg = tag + b"\x00" + canonical
    sigs = []
    for sk in signers:
        kid = _kid(sk)
        sig = sk.sign(msg).signature.hex()
        sigs.append({"key_id": kid, "alg": "ed25519", "sig": sig})

    return {
        "kind": "agg/registry/v1",
        "sig_v": 1,
        "payload": payload,
        "signatures": sigs,
    }


def _local_ok(ctx, env):
    """Pre-verify that the chain + env is valid under the connector."""
    from sandbox.protocol.registry import verify_chain
    verify_chain(ctx["chain"] + [env], ctx["fp"])


def _post(srv, token, org_id, env):
    """POST to /signatures."""
    import httpx
    r = httpx.post(
        f"{srv['base_url']}/api/v1/sync/signer/signatures",
        json={"type": "registry", "org_id": org_id, "envelope": env},
        headers={"Authorization": f"Bearer {token}"},
        timeout=15,
    )
    return r


def _snap(srv, org_id, kids):
    """Read the five assertion values from the DB."""
    owner_url = srv["owner_url"]
    with psycopg.connect(_conninfo(owner_url), autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        # 1. key_registry_versions count and max version
        row = conn.execute(
            "SELECT count(*), coalesce(max(version), 0) "
            "FROM key_registry_versions WHERE org_id = %s::uuid",
            [org_id],
        ).fetchone()
        ver_count, ver_max = row

        # 2. approver_keys snapshot
        ak_rows = conn.execute(
            "SELECT key_id, user_id, (revoked_at IS NULL) AS active "
            "FROM approver_keys WHERE org_id = %s::uuid ORDER BY key_id",
            [org_id],
        ).fetchall()

        # 3. signer_links status per kid
        link_status = {}
        for kid in kids:
            rows = conn.execute(
                "SELECT status FROM signer_links "
                "WHERE org_id = %s::uuid AND key_id = %s",
                [org_id, kid],
            ).fetchall()
            link_status[kid] = [r[0] for r in rows]

        # 4. admin_audit identity refused count
        refused_count = conn.execute(
            "SELECT count(*) FROM admin_audit "
            "WHERE org_id = %s AND action = 'registry_identity_refused'",
            [org_id],
        ).fetchone()[0]

        # 5. admin_audit registry_version count
        rv_count = conn.execute(
            "SELECT count(*) FROM admin_audit "
            "WHERE org_id = %s AND action = 'registry_version'",
            [org_id],
        ).fetchone()[0]

    return {
        "ver_count": ver_count,
        "ver_max": ver_max,
        "ak_rows": ak_rows,
        "link_status": link_status,
        "refused_count": refused_count,
        "rv_count": rv_count,
    }


def _assert_refused(r, reason_class, kid, snap_before, snap_after):
    """Assert R (refused, identity) as per spec section 0.2."""
    assert r.status_code == 400, f"expected 400, got {r.status_code}: {r.text}"
    body = r.json()
    assert body.get("error") == "identity_unbound", f"body: {body}"
    assert body.get("reason") == reason_class, (
        f"expected reason {reason_class!r}, got {body.get('reason')!r}"
    )
    assert body.get("key_id") == kid, (
        f"expected key_id {kid!r}, got {body.get('key_id')!r}"
    )
    # R items
    assert snap_after["ver_count"] == snap_before["ver_count"]
    assert snap_after["ver_max"] == snap_before["ver_max"]
    assert snap_after["ak_rows"] == snap_before["ak_rows"]
    # R3: link status unchanged (pending)
    if kid in snap_after["link_status"]:
        for s in snap_after["link_status"][kid]:
            assert s == "pending", f"link status for {kid} is {s!r}, expected 'pending'"
    # R4: exactly one new refused row
    assert snap_after["refused_count"] == snap_before["refused_count"] + 1
    # R5: registry_version count unchanged
    assert snap_after["rv_count"] == snap_before["rv_count"]


def _check_d5_accepted(snap_before, snap_after):
    """Raise M2T12dIdentityPending if d5-specific audit is not written.

    Call this from xfail tests BEFORE _assert_accepted so the sentinel
    is raised (caught by the xfail marker) instead of a bare AssertionError.
    When d5 is built, this check passes and the xfail marker is removed.
    """
    if snap_after["rv_count"] != snap_before["rv_count"] + 1:
        raise M2T12dIdentityPending(
            f"d5 audit: admin_audit registry_version row not written "
            f"(rv_count {snap_before['rv_count']} -> {snap_after['rv_count']})"
        )


def _assert_accepted(r, version, snap_before, snap_after, *,
                     added_kids=None, consumed_kids=None):
    """Assert A (accepted) as per spec section 0.2."""
    assert r.status_code == 200, f"expected 200, got {r.status_code}: {r.text}"
    body = r.json()
    assert body.get("version") == version
    assert snap_after["ver_max"] == version
    # No new refused row
    assert snap_after["refused_count"] == snap_before["refused_count"]
    # One new registry_version row
    assert snap_after["rv_count"] == snap_before["rv_count"] + 1


# ---------------------------------------------------------------------------
# Base builders
# ---------------------------------------------------------------------------

def _base_G(srv):
    """Base G: seed people + genesis. Returns ctx."""
    org_id = _fresh_org(srv["owner_url"], "G-" + uuid.uuid4().hex[:6])
    people = _seed_people(srv, org_id)
    ctx = _genesis(srv, org_id, people)
    return ctx


def _base_V2C(srv):
    """Base V2C: G + carol route-linked, v2 adds carol as admin, thr 2."""
    ctx = _base_G(srv)
    org_id = ctx["org_id"]
    carol = ctx["people"]["carol"]

    sk_c, kid_c = _route_cli_link(srv, org_id, carol["uid"])
    e_c = _entry(sk_c, carol["uid"], carol["iss"], carol["sub"],
                 roles=["admin"], added_in=2)

    env = _next(ctx, add=[e_c],
                admins=[ctx["alice_kid"], kid_c],
                threshold=2,
                signers=[ctx["alice_sk"], sk_c])

    _local_ok(ctx, env)

    # Post with carol's pending token
    carol_token = _get_signer_token_httpx(srv["base_url"], sk_c, kid_c)
    assert carol_token is not None
    r = _post(srv, carol_token, org_id, env)
    # Today this succeeds (no identity check yet), or raises our sentinel
    if r.status_code != 200:
        raise M2T12dIdentityPending(
            f"V2C base setup: /signatures returned {r.status_code} {r.text}"
        )

    ctx["chain"].append(env)
    ctx["carol_sk"] = sk_c
    ctx["carol_kid"] = kid_c
    return ctx


def _base_V3B(srv):
    """Base V3B: V2C + bob route-linked, v3 adds bob as approver, thr 2."""
    ctx = _base_V2C(srv)
    org_id = ctx["org_id"]
    bob = ctx["people"]["bob"]

    sk_b, kid_b = _route_cli_link(srv, org_id, bob["uid"])
    e_b = _entry(sk_b, bob["uid"], bob["iss"], bob["sub"],
                 roles=["approver"], added_in=3)

    env = _next(ctx, add=[e_b], threshold=2,
                signers=[ctx["alice_sk"], ctx["carol_sk"]])
    _local_ok(ctx, env)

    token = _get_signer_token_httpx(
        srv["base_url"], ctx["alice_sk"], ctx["alice_kid"])
    r = _post(srv, token, org_id, env)
    if r.status_code != 200:
        raise M2T12dIdentityPending(
            f"V3B base setup: /signatures returned {r.status_code} {r.text}"
        )

    ctx["chain"].append(env)
    ctx["bob_sk"] = sk_b
    ctx["bob_kid"] = kid_b
    return ctx


# ===========================================================================
# B1: unlinked key / invented user
# ===========================================================================

@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M2T12dIdentityPending,
                    reason="d5: B1a identity binding not built")
def test_b1_probe_b_unlinked_key_invented_user(identity_server):
    """B1a: v2 adds an unlinked key with an invented user_id -> R unknown_key."""
    srv = identity_server
    ctx = _base_G(srv)
    org_id = ctx["org_id"]

    sk_x = SigningKey.generate()
    kid_x = _kid(sk_x)
    e_x = _entry(sk_x, f"admin-{kid_x[:8]}", "https://fake", "sub-fake",
                 roles=["admin"], added_in=2)

    env = _next(ctx, add=[e_x],
                admins=[ctx["alice_kid"], kid_x],
                threshold=1,
                signers=[ctx["alice_sk"]])
    _local_ok(ctx, env)

    snap_before = _snap(srv, org_id, [kid_x])
    token = _get_signer_token_httpx(srv["base_url"], ctx["alice_sk"], ctx["alice_kid"])
    r = _post(srv, token, org_id, env)
    snap_after = _snap(srv, org_id, [kid_x])

    if r.status_code == 200:
        raise M2T12dIdentityPending("B1a: server accepted unlinked key")

    _assert_refused(r, "unknown_key", kid_x, snap_before, snap_after)


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M2T12dIdentityPending,
                    reason="d5: B1b identity binding not built")
def test_b1b_own_linked_key_invented_user(identity_server):
    """B1b: alice's linked key K_x with invented ids -> R user_mismatch."""
    srv = identity_server
    ctx = _base_G(srv)
    org_id = ctx["org_id"]
    alice = ctx["people"]["alice"]

    sk_x, kid_x = _route_cli_link(srv, org_id, alice["uid"])
    e_x = _entry(sk_x, f"admin-{kid_x[:8]}", "https://fake", "sub-fake",
                 roles=["admin"], added_in=2)

    env = _next(ctx, add=[e_x],
                admins=[ctx["alice_kid"], kid_x],
                threshold=1,
                signers=[ctx["alice_sk"]])
    _local_ok(ctx, env)

    snap_before = _snap(srv, org_id, [kid_x])
    token = _get_signer_token_httpx(srv["base_url"], ctx["alice_sk"], ctx["alice_kid"])
    r = _post(srv, token, org_id, env)
    snap_after = _snap(srv, org_id, [kid_x])

    if r.status_code == 200:
        raise M2T12dIdentityPending("B1b: server accepted linked key with invented user")

    _assert_refused(r, "user_mismatch", kid_x, snap_before, snap_after)


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M2T12dIdentityPending,
                    reason="d5: B1+ twin A asserts consumption and audit")
def test_b1_twin_carol_route_linked(identity_server):
    """B1+ twin: carol's route-linked key with carol's exact ids -> A."""
    srv = identity_server
    ctx = _base_G(srv)
    org_id = ctx["org_id"]
    carol = ctx["people"]["carol"]

    sk_c, kid_c = _route_cli_link(srv, org_id, carol["uid"])
    e_c = _entry(sk_c, carol["uid"], carol["iss"], carol["sub"],
                 roles=["admin"], added_in=2)

    env = _next(ctx, add=[e_c],
                admins=[ctx["alice_kid"], kid_c],
                threshold=1,
                signers=[ctx["alice_sk"]])
    _local_ok(ctx, env)

    snap_before = _snap(srv, org_id, [kid_c])
    token = _get_signer_token_httpx(srv["base_url"], ctx["alice_sk"], ctx["alice_kid"])
    r = _post(srv, token, org_id, env)
    snap_after = _snap(srv, org_id, [kid_c])

    if r.status_code != 200:
        raise M2T12dIdentityPending(
            f"B1+ twin: expected 200, got {r.status_code}")

    _check_d5_accepted(snap_before, snap_after)
    _assert_accepted(r, 2, snap_before, snap_after,
                     added_kids=[kid_c], consumed_kids=[kid_c])
    # A: consumed link
    if "consumed" not in snap_after["link_status"].get(kid_c, []):
        raise M2T12dIdentityPending("B1+ twin: link not consumed")


# ===========================================================================
# B2: carol ids, unlinked key / alice linked key with carol ids
# ===========================================================================

@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M2T12dIdentityPending,
                    reason="d5: B2a identity binding not built")
def test_b2_carol_ids_unlinked_key(identity_server):
    """B2a: unlinked K_x with carol's user_id/iss/sub -> R unknown_key."""
    srv = identity_server
    ctx = _base_G(srv)
    org_id = ctx["org_id"]
    carol = ctx["people"]["carol"]

    sk_x = SigningKey.generate()
    kid_x = _kid(sk_x)
    e_x = _entry(sk_x, carol["uid"], carol["iss"], carol["sub"],
                 roles=["admin"], added_in=2)

    env = _next(ctx, add=[e_x], threshold=1, signers=[ctx["alice_sk"]])
    _local_ok(ctx, env)

    snap_before = _snap(srv, org_id, [kid_x])
    token = _get_signer_token_httpx(srv["base_url"], ctx["alice_sk"], ctx["alice_kid"])
    r = _post(srv, token, org_id, env)
    snap_after = _snap(srv, org_id, [kid_x])

    if r.status_code == 200:
        raise M2T12dIdentityPending("B2a: server accepted unlinked key with carol ids")

    _assert_refused(r, "unknown_key", kid_x, snap_before, snap_after)


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M2T12dIdentityPending,
                    reason="d5: B2b identity binding not built")
def test_b2b_alice_linked_key_carol_ids(identity_server):
    """B2b: alice's linked K_x labelled with carol's ids -> R user_mismatch."""
    srv = identity_server
    ctx = _base_G(srv)
    org_id = ctx["org_id"]
    carol = ctx["people"]["carol"]
    alice = ctx["people"]["alice"]

    sk_x, kid_x = _route_cli_link(srv, org_id, alice["uid"])
    e_x = _entry(sk_x, carol["uid"], carol["iss"], carol["sub"],
                 roles=["admin"], added_in=2)

    env = _next(ctx, add=[e_x], threshold=1, signers=[ctx["alice_sk"]])
    _local_ok(ctx, env)

    snap_before = _snap(srv, org_id, [kid_x])
    token = _get_signer_token_httpx(srv["base_url"], ctx["alice_sk"], ctx["alice_kid"])
    r = _post(srv, token, org_id, env)
    snap_after = _snap(srv, org_id, [kid_x])

    if r.status_code == 200:
        raise M2T12dIdentityPending("B2b: server accepted alice key with carol ids")

    _assert_refused(r, "user_mismatch", kid_x, snap_before, snap_after)


# ===========================================================================
# B3: carol key with wrong identity fields
# ===========================================================================

@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M2T12dIdentityPending,
                    reason="d5: B3a identity binding not built")
def test_b3_carol_key_bob_user_id(identity_server):
    """B3a: carol's key labelled with bob's user_id/iss/sub -> R user_mismatch."""
    srv = identity_server
    ctx = _base_G(srv)
    org_id = ctx["org_id"]
    carol = ctx["people"]["carol"]
    bob = ctx["people"]["bob"]

    sk_c, kid_c = _route_cli_link(srv, org_id, carol["uid"])
    e_c = _entry(sk_c, bob["uid"], bob["iss"], bob["sub"],
                 roles=["approver"], added_in=2)

    env = _next(ctx, add=[e_c], threshold=1, signers=[ctx["alice_sk"]])
    _local_ok(ctx, env)

    snap_before = _snap(srv, org_id, [kid_c])
    token = _get_signer_token_httpx(srv["base_url"], ctx["alice_sk"], ctx["alice_kid"])
    r = _post(srv, token, org_id, env)
    snap_after = _snap(srv, org_id, [kid_c])

    if r.status_code == 200:
        raise M2T12dIdentityPending("B3a: server accepted carol key with bob ids")

    _assert_refused(r, "user_mismatch", kid_c, snap_before, snap_after)


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M2T12dIdentityPending,
                    reason="d5: B3b identity binding not built")
def test_b3b_carol_key_forged_iss_sub(identity_server):
    """B3b: carol's key with carol's user_id but forged iss/sub -> R identity_mismatch."""
    srv = identity_server
    ctx = _base_G(srv)
    org_id = ctx["org_id"]
    carol = ctx["people"]["carol"]

    sk_c, kid_c = _route_cli_link(srv, org_id, carol["uid"])
    e_c = _entry(sk_c, carol["uid"], "https://idp.test", "sub-forged",
                 roles=["approver"], added_in=2)

    env = _next(ctx, add=[e_c], threshold=1, signers=[ctx["alice_sk"]])
    _local_ok(ctx, env)

    snap_before = _snap(srv, org_id, [kid_c])
    token = _get_signer_token_httpx(srv["base_url"], ctx["alice_sk"], ctx["alice_kid"])
    r = _post(srv, token, org_id, env)
    snap_after = _snap(srv, org_id, [kid_c])

    if r.status_code == 200:
        raise M2T12dIdentityPending("B3b: server accepted forged iss/sub")

    _assert_refused(r, "identity_mismatch", kid_c, snap_before, snap_after)


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M2T12dIdentityPending,
                    reason="d5: B3c identity binding not built")
def test_b3c_user_id_case_variant(identity_server):
    """B3c: carol's key with user_id = upper case -> R user_mismatch."""
    srv = identity_server
    ctx = _base_G(srv)
    org_id = ctx["org_id"]
    carol = ctx["people"]["carol"]

    sk_c, kid_c = _route_cli_link(srv, org_id, carol["uid"])
    e_c = _entry(sk_c, carol["uid"].upper(), carol["iss"], carol["sub"],
                 roles=["approver"], added_in=2)

    env = _next(ctx, add=[e_c], threshold=1, signers=[ctx["alice_sk"]])
    _local_ok(ctx, env)

    snap_before = _snap(srv, org_id, [kid_c])
    token = _get_signer_token_httpx(srv["base_url"], ctx["alice_sk"], ctx["alice_kid"])
    r = _post(srv, token, org_id, env)
    snap_after = _snap(srv, org_id, [kid_c])

    if r.status_code == 200:
        raise M2T12dIdentityPending("B3c: server accepted case-variant user_id")

    _assert_refused(r, "user_mismatch", kid_c, snap_before, snap_after)


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M2T12dIdentityPending,
                    reason="d5: B3d identity binding not built")
def test_b3d_inactive_user(identity_server):
    """B3d: carol links, then disabled; v2 adds K_c honestly -> R user_mismatch."""
    srv = identity_server
    ctx = _base_G(srv)
    org_id = ctx["org_id"]
    carol = ctx["people"]["carol"]

    sk_c, kid_c = _route_cli_link(srv, org_id, carol["uid"])

    # Disable carol
    with psycopg.connect(_conninfo(srv["owner_url"]), autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        conn.execute("UPDATE users SET status='disabled' WHERE id = %s::uuid",
                     [carol["uid"]])

    e_c = _entry(sk_c, carol["uid"], carol["iss"], carol["sub"],
                 roles=["approver"], added_in=2)

    env = _next(ctx, add=[e_c], threshold=1, signers=[ctx["alice_sk"]])
    _local_ok(ctx, env)

    snap_before = _snap(srv, org_id, [kid_c])
    token = _get_signer_token_httpx(srv["base_url"], ctx["alice_sk"], ctx["alice_kid"])
    r = _post(srv, token, org_id, env)
    snap_after = _snap(srv, org_id, [kid_c])

    if r.status_code == 200:
        raise M2T12dIdentityPending("B3d: server accepted disabled user")

    _assert_refused(r, "user_mismatch", kid_c, snap_before, snap_after)


# ===========================================================================
# B4: cross-org
# ===========================================================================

@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M2T12dIdentityPending,
                    reason="d5: B4a identity binding not built")
def test_b4_key_linked_in_other_org(identity_server):
    """B4a: dave_B links in org B; alice's v2 in org A adds that key -> R other_org."""
    srv = identity_server
    ctx_a = _base_G(srv)
    org_a = ctx_a["org_id"]

    # Org B
    org_b = _fresh_org(srv["owner_url"], "B4-OrgB")
    with psycopg.connect(_conninfo(srv["owner_url"]), autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_b])
        dave_uid, dave_iss, dave_sub = _seed_user_row(
            conn, org_b, "dave@b4.test")
        _grant_role(conn, org_b, dave_uid, "admin")

    # Genesis in org B
    people_b = {"dave": {"uid": dave_uid, "iss": dave_iss, "sub": dave_sub}}

    # dave links in org B
    sk_d, kid_d = _route_cli_link(srv, org_b, dave_uid)

    # alice's v2 in org A adds K_d
    e_d = _entry(sk_d, dave_uid, dave_iss, dave_sub,
                 roles=["admin"], added_in=2)

    env = _next(ctx_a, add=[e_d], threshold=1, signers=[ctx_a["alice_sk"]])
    _local_ok(ctx_a, env)

    snap_before = _snap(srv, org_a, [kid_d])
    token = _get_signer_token_httpx(srv["base_url"], ctx_a["alice_sk"], ctx_a["alice_kid"])
    r = _post(srv, token, org_a, env)
    snap_after = _snap(srv, org_a, [kid_d])

    if r.status_code == 200:
        raise M2T12dIdentityPending("B4a: server accepted cross-org key")

    _assert_refused(r, "other_org", kid_d, snap_before, snap_after)


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M2T12dIdentityPending,
                    reason="d5: B4b identity binding not built")
def test_b4b_other_org_user_on_own_org_link(identity_server):
    """B4b: K_c from carol's org-A link, labelled with dave_B's ids -> R user_mismatch."""
    srv = identity_server
    ctx = _base_G(srv)
    org_a = ctx["org_id"]
    carol = ctx["people"]["carol"]

    # Create dave in org B
    org_b = _fresh_org(srv["owner_url"], "B4b-OrgB")
    with psycopg.connect(_conninfo(srv["owner_url"]), autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_b])
        dave_uid, dave_iss, dave_sub = _seed_user_row(
            conn, org_b, "dave@b4b.test")

    sk_c, kid_c = _route_cli_link(srv, org_a, carol["uid"])
    e_c = _entry(sk_c, dave_uid, dave_iss, dave_sub,
                 roles=["approver"], added_in=2)

    env = _next(ctx, add=[e_c], threshold=1, signers=[ctx["alice_sk"]])
    _local_ok(ctx, env)

    snap_before = _snap(srv, org_a, [kid_c])
    token = _get_signer_token_httpx(srv["base_url"], ctx["alice_sk"], ctx["alice_kid"])
    r = _post(srv, token, org_a, env)
    snap_after = _snap(srv, org_a, [kid_c])

    if r.status_code == 200:
        raise M2T12dIdentityPending("B4b: server accepted cross-org user ids")

    _assert_refused(r, "user_mismatch", kid_c, snap_before, snap_after)


@pytest.mark.pg
def test_b4c_other_org_token(identity_server):
    """B4c: dave_B's pending_link token posts org-A v2 -> 404. Plain pass."""
    srv = identity_server
    ctx_a = _base_G(srv)
    org_a = ctx_a["org_id"]

    org_b = _fresh_org(srv["owner_url"], "B4c-OrgB")
    with psycopg.connect(_conninfo(srv["owner_url"]), autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_b])
        dave_uid, dave_iss, dave_sub = _seed_user_row(
            conn, org_b, "dave@b4c.test")
        _grant_role(conn, org_b, dave_uid, "admin")

    # Need genesis in B so dave can get a pending link
    people_b = _seed_people(srv, org_b)
    ctx_b = _genesis(srv, org_b, people_b)

    sk_d, kid_d = _route_cli_link(srv, org_b, dave_uid)
    dave_token = _get_signer_token_httpx(srv["base_url"], sk_d, kid_d)

    e_d = _entry(sk_d, dave_uid, dave_iss, dave_sub,
                 roles=["approver"], added_in=2)
    env = _next(ctx_a, add=[e_d], threshold=1, signers=[ctx_a["alice_sk"]])

    snap_a_before = _snap(srv, org_a, [kid_d])
    snap_b_before = _snap(srv, org_b, [kid_d])
    r = _post(srv, dave_token, org_a, env)
    snap_a_after = _snap(srv, org_a, [kid_d])
    snap_b_after = _snap(srv, org_b, [kid_d])

    assert r.status_code == 404, f"expected 404, got {r.status_code}"
    # Both orgs unchanged
    assert snap_a_after["ver_count"] == snap_a_before["ver_count"]
    assert snap_b_after["ver_count"] == snap_b_before["ver_count"]


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M2T12dIdentityPending,
                    reason="d5: B4+ twin A asserts consumption and audit")
def test_b4_twin_same_org_user(identity_server):
    """B4+ twin: dave (org A) route-links; v2 adds it, approver -> A."""
    srv = identity_server
    ctx = _base_G(srv)
    org_id = ctx["org_id"]
    dave = ctx["people"]["dave"]

    sk_d, kid_d = _route_cli_link(srv, org_id, dave["uid"])
    e_d = _entry(sk_d, dave["uid"], dave["iss"], dave["sub"],
                 roles=["approver"], added_in=2)

    env = _next(ctx, add=[e_d], threshold=1, signers=[ctx["alice_sk"]])
    _local_ok(ctx, env)

    snap_before = _snap(srv, org_id, [kid_d])
    token = _get_signer_token_httpx(srv["base_url"], ctx["alice_sk"], ctx["alice_kid"])
    r = _post(srv, token, org_id, env)
    snap_after = _snap(srv, org_id, [kid_d])

    if r.status_code != 200:
        raise M2T12dIdentityPending(
            f"B4+ twin: expected 200, got {r.status_code}")

    _check_d5_accepted(snap_before, snap_after)
    _assert_accepted(r, 2, snap_before, snap_after)


# ===========================================================================
# B5: admin binding
# ===========================================================================

@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M2T12dIdentityPending,
                    reason="d5: B5a identity binding not built")
def test_b5_new_admin_key_no_binding(identity_server):
    """B5a: bob route-linked, added as admin, no admin role binding -> R not_admin."""
    srv = identity_server
    ctx = _base_V2C(srv)
    org_id = ctx["org_id"]
    bob = ctx["people"]["bob"]

    sk_b, kid_b = _route_cli_link(srv, org_id, bob["uid"])
    e_b = _entry(sk_b, bob["uid"], bob["iss"], bob["sub"],
                 roles=["admin"], added_in=3)

    env = _next(ctx, add=[e_b],
                admins=[ctx["alice_kid"], ctx["carol_kid"], kid_b],
                threshold=2,
                signers=[ctx["alice_sk"], ctx["carol_sk"]])
    _local_ok(ctx, env)

    snap_before = _snap(srv, org_id, [kid_b])
    token = _get_signer_token_httpx(srv["base_url"], ctx["alice_sk"], ctx["alice_kid"])
    r = _post(srv, token, org_id, env)
    snap_after = _snap(srv, org_id, [kid_b])

    if r.status_code == 200:
        raise M2T12dIdentityPending("B5a: server accepted admin without binding")

    _assert_refused(r, "not_admin", kid_b, snap_before, snap_after)


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M2T12dIdentityPending,
                    reason="d5: B5b identity binding not built")
def test_b5b_promotion_no_binding(identity_server):
    """B5b: V3B bob promoted to admin without binding -> R not_admin."""
    srv = identity_server
    ctx = _base_V3B(srv)
    org_id = ctx["org_id"]
    bob = ctx["people"]["bob"]

    # v4: bob in admins list, roles ["admin", "approver"]
    bob_kid = ctx["bob_kid"]
    bob_entry = None
    for k in ctx["chain"][-1]["payload"]["keys"]:
        if k["key_id"] == bob_kid:
            bob_entry = dict(k, roles=["admin", "approver"])
            break
    assert bob_entry is not None

    env = _next(ctx, replace=[bob_entry],
                admins=[ctx["alice_kid"], ctx["carol_kid"], bob_kid],
                threshold=2,
                signers=[ctx["alice_sk"], ctx["carol_sk"]])
    _local_ok(ctx, env)

    snap_before = _snap(srv, org_id, [bob_kid])
    token = _get_signer_token_httpx(srv["base_url"], ctx["alice_sk"], ctx["alice_kid"])
    r = _post(srv, token, org_id, env)
    snap_after = _snap(srv, org_id, [bob_kid])

    if r.status_code == 200:
        raise M2T12dIdentityPending("B5b: server accepted promotion without binding")

    _assert_refused(r, "not_admin", bob_kid, snap_before, snap_after)


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M2T12dIdentityPending,
                    reason="d5: B5c identity binding not built")
def test_b5c_project_scope_admin_only(identity_server):
    """B5c: bob has project-scope admin, not org-scope -> R not_admin."""
    srv = identity_server
    ctx = _base_V2C(srv)
    org_id = ctx["org_id"]
    bob = ctx["people"]["bob"]

    # Create project and grant bob project-scope admin
    project_id = str(uuid.uuid4())
    with psycopg.connect(_conninfo(srv["owner_url"]), autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        create_project(conn, org_id, project_id, name="test-project",
                       environment="staging")
        _grant_role(conn, org_id, bob["uid"], "admin",
                    scope_type="project", scope_id=project_id)

    sk_b, kid_b = _route_cli_link(srv, org_id, bob["uid"])
    e_b = _entry(sk_b, bob["uid"], bob["iss"], bob["sub"],
                 roles=["admin"], added_in=3)

    env = _next(ctx, add=[e_b],
                admins=[ctx["alice_kid"], ctx["carol_kid"], kid_b],
                threshold=2,
                signers=[ctx["alice_sk"], ctx["carol_sk"]])
    _local_ok(ctx, env)

    snap_before = _snap(srv, org_id, [kid_b])
    token = _get_signer_token_httpx(srv["base_url"], ctx["alice_sk"], ctx["alice_kid"])
    r = _post(srv, token, org_id, env)
    snap_after = _snap(srv, org_id, [kid_b])

    if r.status_code == 200:
        raise M2T12dIdentityPending("B5c: server accepted project-scope admin")

    _assert_refused(r, "not_admin", kid_b, snap_before, snap_after)


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M2T12dIdentityPending,
                    reason="d5: B5d identity binding not built")
def test_b5d_admin_role_not_in_admins(identity_server):
    """B5d: bob added with roles=["admin"] but not in admins list -> R not_admin."""
    srv = identity_server
    ctx = _base_V2C(srv)
    org_id = ctx["org_id"]
    bob = ctx["people"]["bob"]

    sk_b, kid_b = _route_cli_link(srv, org_id, bob["uid"])
    e_b = _entry(sk_b, bob["uid"], bob["iss"], bob["sub"],
                 roles=["admin"], added_in=3)

    # Don't add kid_b to admins
    env = _next(ctx, add=[e_b], threshold=2,
                signers=[ctx["alice_sk"], ctx["carol_sk"]])
    _local_ok(ctx, env)

    snap_before = _snap(srv, org_id, [kid_b])
    token = _get_signer_token_httpx(srv["base_url"], ctx["alice_sk"], ctx["alice_kid"])
    r = _post(srv, token, org_id, env)
    snap_after = _snap(srv, org_id, [kid_b])

    if r.status_code == 200:
        raise M2T12dIdentityPending("B5d: server accepted admin role not in admins")

    _assert_refused(r, "not_admin", kid_b, snap_before, snap_after)


# B5 twins

@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M2T12dIdentityPending,
                    reason="d5: B5+a twin A asserts consumption and audit")
def test_b5_twin_org_admin_binding(identity_server):
    """B5+a: grant bob admin first, then B5a's v3 -> A."""
    srv = identity_server
    ctx = _base_V2C(srv)
    org_id = ctx["org_id"]
    bob = ctx["people"]["bob"]

    _grant_role_direct(srv, org_id, bob["uid"], "admin")

    sk_b, kid_b = _route_cli_link(srv, org_id, bob["uid"])
    e_b = _entry(sk_b, bob["uid"], bob["iss"], bob["sub"],
                 roles=["admin"], added_in=3)

    env = _next(ctx, add=[e_b],
                admins=[ctx["alice_kid"], ctx["carol_kid"], kid_b],
                threshold=2,
                signers=[ctx["alice_sk"], ctx["carol_sk"]])
    _local_ok(ctx, env)

    snap_before = _snap(srv, org_id, [kid_b])
    token = _get_signer_token_httpx(srv["base_url"], ctx["alice_sk"], ctx["alice_kid"])
    r = _post(srv, token, org_id, env)
    snap_after = _snap(srv, org_id, [kid_b])

    if r.status_code != 200:
        raise M2T12dIdentityPending(
            f"B5+a twin: expected 200, got {r.status_code}")

    _check_d5_accepted(snap_before, snap_after)
    _assert_accepted(r, 3, snap_before, snap_after)


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M2T12dIdentityPending,
                    reason="d5: B5+b twin A asserts promotion audit")
def test_b5b_twin_promotion_with_binding(identity_server):
    """B5+b: grant bob admin, then promote -> A with detail.promoted."""
    srv = identity_server
    ctx = _base_V3B(srv)
    org_id = ctx["org_id"]
    bob = ctx["people"]["bob"]

    _grant_role_direct(srv, org_id, bob["uid"], "admin")

    bob_kid = ctx["bob_kid"]
    bob_entry = None
    for k in ctx["chain"][-1]["payload"]["keys"]:
        if k["key_id"] == bob_kid:
            bob_entry = dict(k, roles=["admin", "approver"])
            break
    assert bob_entry is not None

    env = _next(ctx, replace=[bob_entry],
                admins=[ctx["alice_kid"], ctx["carol_kid"], bob_kid],
                threshold=2,
                signers=[ctx["alice_sk"], ctx["carol_sk"]])
    _local_ok(ctx, env)

    snap_before = _snap(srv, org_id, [bob_kid])
    token = _get_signer_token_httpx(srv["base_url"], ctx["alice_sk"], ctx["alice_kid"])
    r = _post(srv, token, org_id, env)
    snap_after = _snap(srv, org_id, [bob_kid])

    if r.status_code != 200:
        raise M2T12dIdentityPending(
            f"B5+b twin: expected 200, got {r.status_code}")

    _check_d5_accepted(snap_before, snap_after)
    _assert_accepted(r, 4, snap_before, snap_after)


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M2T12dIdentityPending,
                    reason="d5: B5+c twin approver needs no binding")
def test_b5_twin_approver_needs_no_binding(identity_server):
    """B5+c: bob as approver (no admin binding needed) -> A."""
    srv = identity_server
    ctx = _base_V2C(srv)
    org_id = ctx["org_id"]
    bob = ctx["people"]["bob"]

    sk_b, kid_b = _route_cli_link(srv, org_id, bob["uid"])
    e_b = _entry(sk_b, bob["uid"], bob["iss"], bob["sub"],
                 roles=["approver"], added_in=3)

    env = _next(ctx, add=[e_b], threshold=2,
                signers=[ctx["alice_sk"], ctx["carol_sk"]])
    _local_ok(ctx, env)

    snap_before = _snap(srv, org_id, [kid_b])
    token = _get_signer_token_httpx(srv["base_url"], ctx["alice_sk"], ctx["alice_kid"])
    r = _post(srv, token, org_id, env)
    snap_after = _snap(srv, org_id, [kid_b])

    if r.status_code != 200:
        raise M2T12dIdentityPending(
            f"B5+c twin: expected 200, got {r.status_code}")

    _check_d5_accepted(snap_before, snap_after)
    _assert_accepted(r, 3, snap_before, snap_after)


# ===========================================================================
# Helper for granting roles outside the base builder
# ===========================================================================

def _grant_role_direct(srv, org_id, user_id, role):
    with psycopg.connect(_conninfo(srv["owner_url"]), autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        _grant_role(conn, org_id, user_id, role)


# ===========================================================================
# B6: carried key identity changed
# ===========================================================================

@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M2T12dIdentityPending,
                    reason="d5: B6a identity binding not built")
def test_b6_carried_user_id_changed(identity_server):
    """B6a: v4 replaces bob's user_id with dave's -> R identity_changed."""
    srv = identity_server
    ctx = _base_V3B(srv)
    org_id = ctx["org_id"]
    dave = ctx["people"]["dave"]
    bob_kid = ctx["bob_kid"]

    bob_entry = None
    for k in ctx["chain"][-1]["payload"]["keys"]:
        if k["key_id"] == bob_kid:
            bob_entry = dict(k,
                             user_id=dave["uid"],
                             iss=dave["iss"],
                             sub=dave["sub"])
            break

    env = _next(ctx, replace=[bob_entry], threshold=2,
                signers=[ctx["alice_sk"], ctx["carol_sk"]])
    _local_ok(ctx, env)

    snap_before = _snap(srv, org_id, [bob_kid])
    token = _get_signer_token_httpx(srv["base_url"], ctx["alice_sk"], ctx["alice_kid"])
    r = _post(srv, token, org_id, env)
    snap_after = _snap(srv, org_id, [bob_kid])

    if r.status_code == 200:
        raise M2T12dIdentityPending("B6a: server accepted changed user_id")

    _assert_refused(r, "identity_changed", bob_kid, snap_before, snap_after)


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M2T12dIdentityPending,
                    reason="d5: B6b identity binding not built")
def test_b6b_carried_iss_sub_changed(identity_server):
    """B6b: v4 changes bob's sub -> R identity_changed."""
    srv = identity_server
    ctx = _base_V3B(srv)
    org_id = ctx["org_id"]
    bob_kid = ctx["bob_kid"]

    bob_entry = None
    for k in ctx["chain"][-1]["payload"]["keys"]:
        if k["key_id"] == bob_kid:
            bob_entry = dict(k, sub="sub-forged")
            break

    env = _next(ctx, replace=[bob_entry], threshold=2,
                signers=[ctx["alice_sk"], ctx["carol_sk"]])
    _local_ok(ctx, env)

    snap_before = _snap(srv, org_id, [bob_kid])
    token = _get_signer_token_httpx(srv["base_url"], ctx["alice_sk"], ctx["alice_kid"])
    r = _post(srv, token, org_id, env)
    snap_after = _snap(srv, org_id, [bob_kid])

    if r.status_code == 200:
        raise M2T12dIdentityPending("B6b: server accepted changed sub")

    _assert_refused(r, "identity_changed", bob_kid, snap_before, snap_after)


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M2T12dIdentityPending,
                    reason="d5: B6c identity binding not built")
def test_b6c_carried_kind_changed(identity_server):
    """B6c: v4 changes bob's kind cli -> browser -> R identity_changed."""
    srv = identity_server
    ctx = _base_V3B(srv)
    org_id = ctx["org_id"]
    bob_kid = ctx["bob_kid"]

    bob_entry = None
    for k in ctx["chain"][-1]["payload"]["keys"]:
        if k["key_id"] == bob_kid:
            bob_entry = dict(k, kind="browser")
            break

    env = _next(ctx, replace=[bob_entry], threshold=2,
                signers=[ctx["alice_sk"], ctx["carol_sk"]])
    _local_ok(ctx, env)

    snap_before = _snap(srv, org_id, [bob_kid])
    token = _get_signer_token_httpx(srv["base_url"], ctx["alice_sk"], ctx["alice_kid"])
    r = _post(srv, token, org_id, env)
    snap_after = _snap(srv, org_id, [bob_kid])

    if r.status_code == 200:
        raise M2T12dIdentityPending("B6c: server accepted changed kind")

    _assert_refused(r, "identity_changed", bob_kid, snap_before, snap_after)


@pytest.mark.pg
def test_b6d_carried_public_key_changed_upstream(identity_server):
    """B6d: v4 changes bob's public_key -> verify_chain raises (D0-1).
    Not identity_unbound; no registry_identity_refused row. Plain pass."""
    from sandbox.protocol.registry import RegistryError
    srv = identity_server
    ctx = _base_V3B(srv)
    org_id = ctx["org_id"]
    bob_kid = ctx["bob_kid"]

    other_pub = bytes(SigningKey.generate().verify_key).hex()
    bob_entry = None
    for k in ctx["chain"][-1]["payload"]["keys"]:
        if k["key_id"] == bob_kid:
            bob_entry = dict(k, public_key=other_pub)
            break

    env = _next(ctx, replace=[bob_entry], threshold=2,
                signers=[ctx["alice_sk"], ctx["carol_sk"]])

    # Pre: verify_chain must raise
    with pytest.raises(RegistryError):
        _local_ok(ctx, env)

    snap_before = _snap(srv, org_id, [bob_kid])
    token = _get_signer_token_httpx(srv["base_url"], ctx["alice_sk"], ctx["alice_kid"])
    r = _post(srv, token, org_id, env)
    snap_after = _snap(srv, org_id, [bob_kid])

    assert r.status_code == 400
    body = r.json()
    assert body.get("error") != "identity_unbound"
    # R items 1, 2, 3, 5 hold
    assert snap_after["ver_count"] == snap_before["ver_count"]
    assert snap_after["ak_rows"] == snap_before["ak_rows"]
    assert snap_after["rv_count"] == snap_before["rv_count"]
    # No new registry_identity_refused row
    assert snap_after["refused_count"] == snap_before["refused_count"]


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M2T12dIdentityPending,
                    reason="d5: B6+ twin A with added==[]")
def test_b6_twin_carried_unchanged(identity_server):
    """B6+ twin: v4 only changes expires_at -> A with added==[]."""
    srv = identity_server
    ctx = _base_V3B(srv)
    org_id = ctx["org_id"]

    env = _next(ctx, threshold=2,
                signers=[ctx["alice_sk"], ctx["carol_sk"]])
    _local_ok(ctx, env)

    snap_before = _snap(srv, org_id, [])
    token = _get_signer_token_httpx(srv["base_url"], ctx["alice_sk"], ctx["alice_kid"])
    r = _post(srv, token, org_id, env)
    snap_after = _snap(srv, org_id, [])

    if r.status_code != 200:
        raise M2T12dIdentityPending(
            f"B6+ twin: expected 200, got {r.status_code}")

    _check_d5_accepted(snap_before, snap_after)
    _assert_accepted(r, 4, snap_before, snap_after)


# ===========================================================================
# B7: consumed link re-add
# ===========================================================================

@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M2T12dIdentityPending,
                    reason="d5: B7a identity binding not built")
def test_b7_consumed_link_readd(identity_server):
    """B7a: v4 drops K_b (200); v5 re-adds same K_b -> R unknown_key."""
    srv = identity_server
    ctx = _base_V3B(srv)
    org_id = ctx["org_id"]
    bob_kid = ctx["bob_kid"]

    # v4: drop bob
    bob_entry = None
    for k in ctx["chain"][-1]["payload"]["keys"]:
        if k["key_id"] == bob_kid:
            bob_entry = k
            break

    env_v4 = _next(ctx, drop=[bob_entry], threshold=2,
                   signers=[ctx["alice_sk"], ctx["carol_sk"]])
    _local_ok(ctx, env_v4)
    token = _get_signer_token_httpx(srv["base_url"], ctx["alice_sk"], ctx["alice_kid"])
    r4 = _post(srv, token, org_id, env_v4)
    if r4.status_code != 200:
        raise M2T12dIdentityPending(f"B7a v4 drop failed: {r4.status_code}")
    ctx["chain"].append(env_v4)

    # v5: re-add same K_b
    env_v5 = _next(ctx, add=[bob_entry], threshold=2,
                   signers=[ctx["alice_sk"], ctx["carol_sk"]])
    _local_ok(ctx, env_v5)

    snap_before = _snap(srv, org_id, [bob_kid])
    token = _get_signer_token_httpx(srv["base_url"], ctx["alice_sk"], ctx["alice_kid"])
    r5 = _post(srv, token, org_id, env_v5)
    snap_after = _snap(srv, org_id, [bob_kid])

    if r5.status_code == 200:
        raise M2T12dIdentityPending("B7a: server accepted consumed link re-add")

    _assert_refused(r5, "unknown_key", bob_kid, snap_before, snap_after)


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M2T12dIdentityPending,
                    reason="d5: B7b identity binding not built")
def test_b7b_removed_key_readd_other_user(identity_server):
    """B7b: v4 drops K_b; v5 re-adds K_b with dave's ids -> R unknown_key."""
    srv = identity_server
    ctx = _base_V3B(srv)
    org_id = ctx["org_id"]
    bob_kid = ctx["bob_kid"]
    dave = ctx["people"]["dave"]

    bob_entry = None
    for k in ctx["chain"][-1]["payload"]["keys"]:
        if k["key_id"] == bob_kid:
            bob_entry = k
            break

    env_v4 = _next(ctx, drop=[bob_entry], threshold=2,
                   signers=[ctx["alice_sk"], ctx["carol_sk"]])
    _local_ok(ctx, env_v4)
    token = _get_signer_token_httpx(srv["base_url"], ctx["alice_sk"], ctx["alice_kid"])
    r4 = _post(srv, token, org_id, env_v4)
    if r4.status_code != 200:
        raise M2T12dIdentityPending(f"B7b v4 drop failed: {r4.status_code}")
    ctx["chain"].append(env_v4)

    dave_entry = dict(bob_entry,
                      user_id=dave["uid"], iss=dave["iss"], sub=dave["sub"])
    env_v5 = _next(ctx, add=[dave_entry], threshold=2,
                   signers=[ctx["alice_sk"], ctx["carol_sk"]])

    snap_before = _snap(srv, org_id, [bob_kid])
    token = _get_signer_token_httpx(srv["base_url"], ctx["alice_sk"], ctx["alice_kid"])
    r5 = _post(srv, token, org_id, env_v5)
    snap_after = _snap(srv, org_id, [bob_kid])

    if r5.status_code == 200:
        raise M2T12dIdentityPending("B7b: server accepted re-add with different user")

    _assert_refused(r5, "unknown_key", bob_kid, snap_before, snap_after)


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M2T12dIdentityPending,
                    reason="d5: B7+ twin A asserts fresh link consumption")
def test_b7_twin_fresh_link_readd(identity_server):
    """B7+ twin: v4 drops K_b; bob re-links K_b2; v5 adds K_b2 -> A."""
    srv = identity_server
    ctx = _base_V3B(srv)
    org_id = ctx["org_id"]
    bob = ctx["people"]["bob"]
    bob_kid = ctx["bob_kid"]

    bob_entry = None
    for k in ctx["chain"][-1]["payload"]["keys"]:
        if k["key_id"] == bob_kid:
            bob_entry = k
            break

    env_v4 = _next(ctx, drop=[bob_entry], threshold=2,
                   signers=[ctx["alice_sk"], ctx["carol_sk"]])
    _local_ok(ctx, env_v4)
    token = _get_signer_token_httpx(srv["base_url"], ctx["alice_sk"], ctx["alice_kid"])
    r4 = _post(srv, token, org_id, env_v4)
    if r4.status_code != 200:
        raise M2T12dIdentityPending(f"B7+ v4 drop failed: {r4.status_code}")
    ctx["chain"].append(env_v4)

    sk_b2, kid_b2 = _route_cli_link(srv, org_id, bob["uid"])
    e_b2 = _entry(sk_b2, bob["uid"], bob["iss"], bob["sub"],
                  roles=["approver"], added_in=5)

    env_v5 = _next(ctx, add=[e_b2], threshold=2,
                   signers=[ctx["alice_sk"], ctx["carol_sk"]])
    _local_ok(ctx, env_v5)

    snap_before = _snap(srv, org_id, [kid_b2])
    token = _get_signer_token_httpx(srv["base_url"], ctx["alice_sk"], ctx["alice_kid"])
    r5 = _post(srv, token, org_id, env_v5)
    snap_after = _snap(srv, org_id, [kid_b2])

    if r5.status_code != 200:
        raise M2T12dIdentityPending(
            f"B7+ twin: expected 200, got {r5.status_code}")

    _check_d5_accepted(snap_before, snap_after)
    _assert_accepted(r5, 5, snap_before, snap_after)


# ===========================================================================
# B8: two own keys
# ===========================================================================

@pytest.mark.pg
def test_b8_two_own_keys_threshold2(identity_server):
    """B8a: alice links K_a2; v2 adds it as admin, threshold 2 signed by both.
    verify_chain raises. 400 not identity_unbound. Plain pass."""
    from sandbox.protocol.registry import RegistryError
    srv = identity_server
    ctx = _base_G(srv)
    org_id = ctx["org_id"]
    alice = ctx["people"]["alice"]

    sk_a2, kid_a2 = _route_cli_link(srv, org_id, alice["uid"])
    e_a2 = _entry(sk_a2, alice["uid"], alice["iss"], alice["sub"],
                  roles=["admin"], added_in=2)

    env = _next(ctx, add=[e_a2],
                admins=[ctx["alice_kid"], kid_a2],
                threshold=2,
                signers=[ctx["alice_sk"], sk_a2])

    with pytest.raises(RegistryError, match="from its own admins, got 1"):
        _local_ok(ctx, env)

    snap_before = _snap(srv, org_id, [kid_a2])
    token = _get_signer_token_httpx(srv["base_url"], ctx["alice_sk"], ctx["alice_kid"])
    r = _post(srv, token, org_id, env)
    snap_after = _snap(srv, org_id, [kid_a2])

    assert r.status_code == 400
    body = r.json()
    assert body.get("error") != "identity_unbound"
    assert snap_after["ver_count"] == snap_before["ver_count"]
    assert snap_after["refused_count"] == snap_before["refused_count"]
    # K_a2 link still pending
    for s in snap_after["link_status"].get(kid_a2, []):
        assert s == "pending"


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M2T12dIdentityPending,
                    reason="d5: B8b counts_for_dual assertion needs A blocks")
def test_b8b_two_own_keys_threshold1_not_dual(identity_server):
    """B8b: two alice keys thr 1 -> A; add dave, erin -> A;
    counts_for_dual False for K_d, K_e, K_a2."""
    srv = identity_server
    ctx = _base_G(srv)
    org_id = ctx["org_id"]
    alice = ctx["people"]["alice"]
    dave = ctx["people"]["dave"]
    erin = ctx["people"]["erin"]

    sk_a2, kid_a2 = _route_cli_link(srv, org_id, alice["uid"])
    e_a2 = _entry(sk_a2, alice["uid"], alice["iss"], alice["sub"],
                  roles=["admin"], added_in=2)

    env_v2 = _next(ctx, add=[e_a2],
                   admins=[ctx["alice_kid"], kid_a2],
                   threshold=1,
                   signers=[ctx["alice_sk"]])
    _local_ok(ctx, env_v2)

    snap_v2_before = _snap(srv, org_id, [kid_a2])
    token = _get_signer_token_httpx(srv["base_url"], ctx["alice_sk"], ctx["alice_kid"])
    r2 = _post(srv, token, org_id, env_v2)
    if r2.status_code != 200:
        raise M2T12dIdentityPending(f"B8b v2 failed: {r2.status_code}")
    snap_v2_after = _snap(srv, org_id, [kid_a2])
    _check_d5_accepted(snap_v2_before, snap_v2_after)
    ctx["chain"].append(env_v2)

    # v3: add dave and erin as approvers
    sk_d, kid_d = _route_cli_link(srv, org_id, dave["uid"])
    sk_e, kid_e = _route_cli_link(srv, org_id, erin["uid"])
    e_d = _entry(sk_d, dave["uid"], dave["iss"], dave["sub"],
                 roles=["approver"], added_in=3)
    e_e = _entry(sk_e, erin["uid"], erin["iss"], erin["sub"],
                 roles=["approver"], added_in=3)

    env_v3 = _next(ctx, add=[e_d, e_e], threshold=1,
                   signers=[ctx["alice_sk"], sk_a2])
    _local_ok(ctx, env_v3)

    token = _get_signer_token_httpx(srv["base_url"], ctx["alice_sk"], ctx["alice_kid"])
    r3 = _post(srv, token, org_id, env_v3)
    if r3.status_code != 200:
        raise M2T12dIdentityPending(f"B8b v3 failed: {r3.status_code}")
    ctx["chain"].append(env_v3)

    # GET /registry, verify counts_for_dual
    import httpx
    r_chain = httpx.get(
        f"{srv['base_url']}/api/v1/sync/signer/registry",
        headers={"Authorization": f"Bearer {token}"},
        timeout=10,
    )
    assert r_chain.status_code == 200
    chain = r_chain.json()

    from sandbox.protocol.registry import verify_chain
    fp = ctx["fp"]
    reg = verify_chain(chain, fp)
    assert reg.counts_for_dual(kid_d) is False
    assert reg.counts_for_dual(kid_e) is False
    assert reg.counts_for_dual(kid_a2) is False


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M2T12dIdentityPending,
                    reason="d5: B8+ twin counts_for_dual True for both")
def test_b8_twin_two_people_dual(identity_server):
    """B8+ twin: V2C; dave, erin route-link; v3 adds both signed K_a1+K_c -> A;
    counts_for_dual True for both, False for K_c."""
    srv = identity_server
    ctx = _base_V2C(srv)
    org_id = ctx["org_id"]
    dave = ctx["people"]["dave"]
    erin = ctx["people"]["erin"]

    sk_d, kid_d = _route_cli_link(srv, org_id, dave["uid"])
    sk_e, kid_e = _route_cli_link(srv, org_id, erin["uid"])
    e_d = _entry(sk_d, dave["uid"], dave["iss"], dave["sub"],
                 roles=["approver"], added_in=3)
    e_e = _entry(sk_e, erin["uid"], erin["iss"], erin["sub"],
                 roles=["approver"], added_in=3)

    env = _next(ctx, add=[e_d, e_e], threshold=2,
                signers=[ctx["alice_sk"], ctx["carol_sk"]])
    _local_ok(ctx, env)

    snap_before = _snap(srv, org_id, [kid_d, kid_e])
    token = _get_signer_token_httpx(srv["base_url"], ctx["alice_sk"], ctx["alice_kid"])
    r = _post(srv, token, org_id, env)
    snap_after = _snap(srv, org_id, [kid_d, kid_e])
    if r.status_code != 200:
        raise M2T12dIdentityPending(f"B8+ twin: expected 200, got {r.status_code}")
    _check_d5_accepted(snap_before, snap_after)
    ctx["chain"].append(env)

    import httpx
    r_chain = httpx.get(
        f"{srv['base_url']}/api/v1/sync/signer/registry",
        headers={"Authorization": f"Bearer {token}"},
        timeout=10,
    )
    chain = r_chain.json()
    from sandbox.protocol.registry import verify_chain
    reg = verify_chain(chain, ctx["fp"])
    assert reg.counts_for_dual(kid_d) is True
    assert reg.counts_for_dual(kid_e) is True
    assert reg.counts_for_dual(ctx["carol_kid"]) is False


# ===========================================================================
# B10, B11
# ===========================================================================

@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M2T12dIdentityPending,
                    reason="d5: B10 identity binding not built")
def test_b10_key_linked_by_two_users(identity_server):
    """B10: carol links K_c; bob uses his own code with K_c's pub key;
    v2 adds K_c with carol's ids -> R unknown_key (ruling R-5)."""
    srv = identity_server
    ctx = _base_G(srv)
    org_id = ctx["org_id"]
    carol = ctx["people"]["carol"]
    bob = ctx["people"]["bob"]

    import httpx
    # carol links K_c
    sk_c, kid_c = _route_cli_link(srv, org_id, carol["uid"])
    pub_hex = bytes(sk_c.verify_key).hex()

    # bob gets his own link code and links the same public key
    cookie_b, csrf_b = _make_fresh_session(srv["owner_url"], org_id, bob["uid"])
    r_bob_code = httpx.post(
        f"{srv['base_url']}/api/v1/signer-links",
        cookies={"__Host-agg_session": cookie_b},
        headers={"X-CSRF-Token": csrf_b},
        json={},
        timeout=10,
    )
    assert r_bob_code.status_code == 200
    bob_code = r_bob_code.json()["code"]
    r_bob_link = httpx.post(f"{srv['base_url']}/api/v1/sync/signer/link", json={
        "code": bob_code, "key_id": kid_c, "public_key": pub_hex,
    }, timeout=10)
    # The route may accept this (no proof of possession)

    e_c = _entry(sk_c, carol["uid"], carol["iss"], carol["sub"],
                 roles=["approver"], added_in=2)

    env = _next(ctx, add=[e_c], threshold=1, signers=[ctx["alice_sk"]])
    _local_ok(ctx, env)

    snap_before = _snap(srv, org_id, [kid_c])
    token = _get_signer_token_httpx(srv["base_url"], ctx["alice_sk"], ctx["alice_kid"])
    r = _post(srv, token, org_id, env)
    snap_after = _snap(srv, org_id, [kid_c])

    if r.status_code == 200:
        raise M2T12dIdentityPending("B10: server accepted doubly-linked key")

    _assert_refused(r, "unknown_key", kid_c, snap_before, snap_after)


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M2T12dIdentityPending,
                    reason="d5: B11 browser enroll stale session")
def test_b11_browser_enroll_stale_session(identity_server):
    """B11: stale session (> 15 min) -> 403 session_too_old; no signer_links row."""
    srv = identity_server
    ctx = _base_G(srv)
    org_id = ctx["org_id"]
    bob = ctx["people"]["bob"]

    import httpx
    import datetime as dt
    stale_clock = FakeClock(
        dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=20)
    )
    token, csrf, sid = seed_session(
        srv["owner_url"], uuid.UUID(org_id), uuid.UUID(bob["uid"]),
        clock=stale_clock,
    )
    cookie = make_session_cookie(uuid.UUID(org_id), token)

    sk = SigningKey.generate()
    kid = _kid(sk)
    r = httpx.post(
        f"{srv['base_url']}/api/v1/signer-links",
        cookies={"__Host-agg_session": cookie},
        headers={"X-CSRF-Token": csrf},
        json={"kind": "browser", "key_id": kid,
              "public_key": bytes(sk.verify_key).hex()},
        timeout=10,
    )

    if r.status_code in (200, 201):
        raise M2T12dIdentityPending("B11: stale session accepted for browser enroll")

    if r.status_code != 403:
        raise M2T12dIdentityPending(
            f"B11: expected 403, got {r.status_code}: "
            "d5 browser enroll stale session check not built"
        )
    assert "session_too_old" in r.text

    # No signer_links row
    with psycopg.connect(_conninfo(srv["owner_url"]), autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        cnt = conn.execute(
            "SELECT count(*) FROM signer_links WHERE key_id = %s",
            [kid],
        ).fetchone()[0]
    assert cnt == 0


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M2T12dIdentityPending,
                    reason="d5: B11+ twin kind=browser assertion")
def test_b11_twin_fresh_browser_enroll(identity_server):
    """B11+ twin: fresh browser enroll -> 201; kind=browser, status=pending."""
    srv = identity_server
    ctx = _base_G(srv)
    org_id = ctx["org_id"]
    bob = ctx["people"]["bob"]

    try:
        sk, kid = _route_browser_enroll(srv, org_id, bob["uid"])
    except AssertionError as exc:
        raise M2T12dIdentityPending(
            f"B11+ twin: browser enroll route failed: {exc}"
        ) from exc

    try:
        with psycopg.connect(_conninfo(srv["owner_url"]), autocommit=True) as conn:
            conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
            row = conn.execute(
                "SELECT kind, status FROM signer_links "
                "WHERE org_id = %s::uuid AND key_id = %s",
                [org_id, kid],
            ).fetchone()
    except psycopg.errors.UndefinedColumn:
        raise M2T12dIdentityPending(
            "B11+ twin: signer_links.kind column does not exist "
            "(migration 0016 not applied)"
        )

    if row is None:
        raise M2T12dIdentityPending("B11+ twin: no signer_links row after enroll")

    kind_val, status_val = row
    if kind_val != "browser":
        raise M2T12dIdentityPending(
            f"B11+ twin: kind={kind_val!r}, expected 'browser'")
    assert status_val == "pending"


# ===========================================================================
# C1-C3: candidates
# ===========================================================================

@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M2T12dIdentityPending,
                    reason="d5: C1 candidates kind field")
def test_candidates_lists_browser_and_cli_kind(identity_server):
    """C1: bob browser-enrolls, carol CLI-links; /candidates shows kind."""
    import httpx
    srv = identity_server
    ctx = _base_G(srv)
    org_id = ctx["org_id"]
    bob = ctx["people"]["bob"]
    carol = ctx["people"]["carol"]

    try:
        sk_b, kid_b = _route_browser_enroll(srv, org_id, bob["uid"])
    except AssertionError as exc:
        raise M2T12dIdentityPending(
            f"C1: browser enroll failed (d5 browser kind not built): {exc}"
        ) from exc
    sk_c, kid_c = _route_cli_link(srv, org_id, carol["uid"])

    token = _get_signer_token_httpx(
        srv["base_url"], ctx["alice_sk"], ctx["alice_kid"])
    r = httpx.get(
        f"{srv['base_url']}/api/v1/sync/signer/candidates",
        headers={"Authorization": f"Bearer {token}"},
        timeout=10,
    )
    assert r.status_code == 200
    candidates = r.json()
    kinds = {c["key_id"]: c.get("kind") for c in candidates}

    if kinds.get(kid_b) != "browser":
        raise M2T12dIdentityPending(
            f"C1: bob's kind={kinds.get(kid_b)!r}, expected 'browser'")
    assert kinds.get(kid_c) == "cli"


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M2T12dIdentityPending,
                    reason="d5: C2 candidates exclusion")
def test_candidates_excludes_consumed_and_inactive(identity_server):
    """C2: V2C; dave links then disabled; erin links. Candidates = erin only."""
    import httpx
    srv = identity_server
    ctx = _base_V2C(srv)
    org_id = ctx["org_id"]
    dave = ctx["people"]["dave"]
    erin = ctx["people"]["erin"]

    sk_d, kid_d = _route_cli_link(srv, org_id, dave["uid"])
    # Disable dave
    with psycopg.connect(_conninfo(srv["owner_url"]), autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        conn.execute("UPDATE users SET status='disabled' WHERE id = %s::uuid",
                     [dave["uid"]])

    sk_e, kid_e = _route_cli_link(srv, org_id, erin["uid"])

    token = _get_signer_token_httpx(
        srv["base_url"], ctx["alice_sk"], ctx["alice_kid"])
    r = httpx.get(
        f"{srv['base_url']}/api/v1/sync/signer/candidates",
        headers={"Authorization": f"Bearer {token}"},
        timeout=10,
    )
    assert r.status_code == 200
    candidates = r.json()
    candidate_kids = {c["key_id"] for c in candidates}

    # carol's key (consumed in v2) must not appear
    if ctx["carol_kid"] in candidate_kids:
        raise M2T12dIdentityPending("C2: consumed carol key in candidates")
    # dave's key (inactive) must not appear
    if kid_d in candidate_kids:
        raise M2T12dIdentityPending("C2: disabled dave in candidates")
    # erin must appear
    if kid_e not in candidate_kids:
        raise M2T12dIdentityPending("C2: erin missing from candidates")


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M2T12dIdentityPending,
                    reason="d5: C3 concurrent v2")
def test_concurrent_v2_one_wins(identity_server):
    """C3: two concurrent v2 posts; exactly one wins."""
    import httpx
    srv = identity_server
    ctx = _base_G(srv)
    org_id = ctx["org_id"]
    carol = ctx["people"]["carol"]
    dave = ctx["people"]["dave"]

    _grant_role_direct(srv, org_id, dave["uid"], "admin")

    sk_c, kid_c = _route_cli_link(srv, org_id, carol["uid"])
    sk_d, kid_d = _route_cli_link(srv, org_id, dave["uid"])

    e_c = _entry(sk_c, carol["uid"], carol["iss"], carol["sub"],
                 roles=["admin"], added_in=2)
    e_d = _entry(sk_d, dave["uid"], dave["iss"], dave["sub"],
                 roles=["admin"], added_in=2)

    env_c = _next(ctx, add=[e_c],
                  admins=[ctx["alice_kid"], kid_c],
                  threshold=2,
                  signers=[ctx["alice_sk"], sk_c])
    env_d = _next(ctx, add=[e_d],
                  admins=[ctx["alice_kid"], kid_d],
                  threshold=2,
                  signers=[ctx["alice_sk"], sk_d])

    _local_ok(ctx, env_c)
    _local_ok(ctx, env_d)

    token_a1 = _get_signer_token_httpx(
        srv["base_url"], ctx["alice_sk"], ctx["alice_kid"])
    token_a2 = _get_signer_token_httpx(
        srv["base_url"], ctx["alice_sk"], ctx["alice_kid"])

    def post_env(env, tok):
        return _post(srv, tok, org_id, env)

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as exe:
        f1 = exe.submit(post_env, env_c, token_a1)
        f2 = exe.submit(post_env, env_d, token_a2)
        r1 = f1.result()
        r2 = f2.result()

    statuses = sorted([r1.status_code, r2.status_code])
    if statuses == [200, 200]:
        raise M2T12dIdentityPending("C3: both v2 posts succeeded")
    assert 200 in statuses, f"C3: no winner: {statuses}"
    assert statuses != [500, 500], f"C3: double 500: {statuses}"

    # Exactly one v2 row
    with psycopg.connect(_conninfo(srv["owner_url"]), autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        cnt = conn.execute(
            "SELECT count(*) FROM key_registry_versions "
            "WHERE org_id = %s::uuid AND version = 2",
            [org_id],
        ).fetchone()[0]
    assert cnt == 1

    # Exactly one registry_version audit row (d5 writes this)
    with psycopg.connect(_conninfo(srv["owner_url"]), autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        rv = conn.execute(
            "SELECT count(*) FROM admin_audit "
            "WHERE org_id = %s AND action = 'registry_version'",
            [org_id],
        ).fetchone()[0]
    if rv != 1:
        raise M2T12dIdentityPending(
            f"C3: expected 1 registry_version audit row, got {rv}: "
            "d5 audit not built"
        )


# ===========================================================================
# E1, E2: end to end
# ===========================================================================

@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M2T12dIdentityPending,
                    reason="d5: E1 frozen step 2 route-linked keys")
def test_e2e_frozen_step2_route_linked_keys(identity_server):
    """E1: full frozen step 2 with route-linked keys."""
    import httpx
    srv = identity_server
    ctx = _base_G(srv)
    org_id = ctx["org_id"]
    alice = ctx["people"]["alice"]
    carol = ctx["people"]["carol"]
    bob = ctx["people"]["bob"]

    # V2C: carol CLI-linked, admin, threshold 2
    sk_c, kid_c = _route_cli_link(srv, org_id, carol["uid"])
    e_c = _entry(sk_c, carol["uid"], carol["iss"], carol["sub"],
                 roles=["admin"], added_in=2)
    env_v2 = _next(ctx, add=[e_c],
                   admins=[ctx["alice_kid"], kid_c],
                   threshold=2,
                   signers=[ctx["alice_sk"], sk_c])
    _local_ok(ctx, env_v2)

    carol_token = _get_signer_token_httpx(srv["base_url"], sk_c, kid_c)
    r_v2 = _post(srv, carol_token, org_id, env_v2)
    if r_v2.status_code != 200:
        raise M2T12dIdentityPending(f"E1 v2 failed: {r_v2.status_code}")
    ctx["chain"].append(env_v2)

    # V3: bob browser-enroll, carol second CLI link (approver),
    #     alice second CLI link (approver)
    try:
        sk_b, kid_b = _route_browser_enroll(srv, org_id, bob["uid"])
    except AssertionError as exc:
        raise M2T12dIdentityPending(
            f"E1: browser enroll failed (d5 browser kind not built): {exc}"
        ) from exc
    sk_c2, kid_c2 = _route_cli_link(srv, org_id, carol["uid"])
    sk_a2, kid_a2 = _route_cli_link(srv, org_id, alice["uid"])

    e_b = _entry(sk_b, bob["uid"], bob["iss"], bob["sub"],
                 kind="browser", roles=["approver"], added_in=3)
    e_c2 = _entry(sk_c2, carol["uid"], carol["iss"], carol["sub"],
                  roles=["approver"], added_in=3)
    e_a2 = _entry(sk_a2, alice["uid"], alice["iss"], alice["sub"],
                  roles=["approver"], added_in=3)

    env_v3 = _next(ctx, add=[e_b, e_c2, e_a2], threshold=2,
                   signers=[ctx["alice_sk"], sk_c])
    _local_ok(ctx, env_v3)

    token = _get_signer_token_httpx(srv["base_url"], ctx["alice_sk"], ctx["alice_kid"])
    r_v3 = _post(srv, token, org_id, env_v3)
    if r_v3.status_code != 200:
        raise M2T12dIdentityPending(f"E1 v3 failed: {r_v3.status_code}")
    ctx["chain"].append(env_v3)

    # Verify: GET /signer/registry returns 3 versions
    r_chain = httpx.get(
        f"{srv['base_url']}/api/v1/sync/signer/registry",
        headers={"Authorization": f"Bearer {token}"},
        timeout=10,
    )
    assert r_chain.status_code == 200
    chain = r_chain.json()
    assert len(chain) == 3

    from sandbox.protocol.registry import verify_chain
    reg = verify_chain(chain, ctx["fp"])
    # counts_for_dual: False for K_c (v2, count 1 admin user)
    assert reg.counts_for_dual(kid_c) is False
    # True for bob, carol-approver, alice-approver
    assert reg.counts_for_dual(kid_b) is True
    assert reg.counts_for_dual(kid_c2) is True
    assert reg.counts_for_dual(kid_a2) is True

    # Two registry_version audit rows (v2, v3) -- d5 writes these
    with psycopg.connect(_conninfo(srv["owner_url"]), autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        rv = conn.execute(
            "SELECT count(*) FROM admin_audit "
            "WHERE org_id = %s AND action = 'registry_version'",
            [org_id],
        ).fetchone()[0]
    if rv != 2:
        raise M2T12dIdentityPending(
            f"E1: expected 2 registry_version audit rows, got {rv}: "
            "d5 audit not built"
        )

    # All four added links consumed -- d5 consumption logic
    with psycopg.connect(_conninfo(srv["owner_url"]), autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        for kid in (kid_c, kid_b, kid_c2, kid_a2):
            rows = conn.execute(
                "SELECT status FROM signer_links "
                "WHERE org_id = %s::uuid AND key_id = %s",
                [org_id, kid],
            ).fetchall()
            statuses = [r[0] for r in rows]
            if "consumed" not in statuses:
                raise M2T12dIdentityPending(
                    f"E1: link for {kid} not consumed: {statuses}")

    # /candidates is empty (after consumption)
    r_cand = httpx.get(
        f"{srv['base_url']}/api/v1/sync/signer/candidates",
        headers={"Authorization": f"Bearer {token}"},
        timeout=10,
    )
    if r_cand.status_code == 200:
        cand = r_cand.json()
        if cand != []:
            raise M2T12dIdentityPending(
                f"E1: /candidates not empty after consumption: {cand}"
            )


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M2T12dIdentityPending,
                    reason="d5: E2 probe B refused then honest v2")
def test_e2e_probe_b_refused_at_v2(identity_server):
    """E2: B1a's v2 -> R unknown_key; then honest v2 (B1+) -> A."""
    srv = identity_server
    ctx = _base_G(srv)
    org_id = ctx["org_id"]
    carol = ctx["people"]["carol"]

    # Probe: unlinked key
    sk_x = SigningKey.generate()
    kid_x = _kid(sk_x)
    e_x = _entry(sk_x, f"admin-{kid_x[:8]}", "https://fake", "sub-fake",
                 roles=["admin"], added_in=2)
    env_probe = _next(ctx, add=[e_x], threshold=1,
                      signers=[ctx["alice_sk"]])
    _local_ok(ctx, env_probe)

    token = _get_signer_token_httpx(srv["base_url"], ctx["alice_sk"], ctx["alice_kid"])
    r_probe = _post(srv, token, org_id, env_probe)
    if r_probe.status_code == 200:
        raise M2T12dIdentityPending("E2: probe accepted")
    assert r_probe.status_code == 400

    # Honest v2 (carol route-linked)
    sk_c, kid_c = _route_cli_link(srv, org_id, carol["uid"])
    e_c = _entry(sk_c, carol["uid"], carol["iss"], carol["sub"],
                 roles=["admin"], added_in=2)
    env_honest = _next(ctx, add=[e_c],
                       admins=[ctx["alice_kid"], kid_c],
                       threshold=1,
                       signers=[ctx["alice_sk"]])
    _local_ok(ctx, env_honest)

    token = _get_signer_token_httpx(srv["base_url"], ctx["alice_sk"], ctx["alice_kid"])
    r_honest = _post(srv, token, org_id, env_honest)
    if r_honest.status_code != 200:
        raise M2T12dIdentityPending(
            f"E2: honest v2 failed: {r_honest.status_code}")
    assert r_honest.json().get("version") == 2


# ===========================================================================
# A1.4 static gate: no store_registry_version, no raw writes
# ===========================================================================

def test_a1_4_no_store_registry_version_or_raw_writes():
    """A1.4 rule 1 (spec 7.1): this file must never call
    store_registry_version or write to key_registry_versions,
    approver_keys or signer_links.  AST + text scan."""
    import ast
    import pathlib

    this_file = pathlib.Path(__file__)
    source = this_file.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(this_file))

    forbidden_calls = {"store_registry_version"}
    forbidden_tables = {"key_registry_versions", "approver_keys", "signer_links"}
    dml_patterns = {"INSERT INTO", "UPDATE ", "DELETE FROM"}

    # AST walk: look for calls to store_registry_version
    call_violations = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Name) and func.id in forbidden_calls:
                call_violations.append(f"line {node.lineno}: call {func.id}()")
            elif isinstance(func, ast.Attribute) and func.attr in forbidden_calls:
                call_violations.append(f"line {node.lineno}: call .{func.attr}()")

    # AST walk: look for imports of store_registry_version
    import_violations = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in getattr(node, "names", []):
                if alias.name in forbidden_calls:
                    import_violations.append(
                        f"line {node.lineno}: import {alias.name}")
                if alias.asname and alias.asname in forbidden_calls:
                    import_violations.append(
                        f"line {node.lineno}: import as {alias.asname}")

    # Text scan: look for raw DML on forbidden tables
    raw_write_violations = []
    for i, line in enumerate(source.splitlines(), 1):
        line_upper = line.upper()
        for table in forbidden_tables:
            for dml in dml_patterns:
                if dml in line_upper and table.upper() in line_upper:
                    # Allow SELECT (reads are ok) and comment lines
                    stripped = line.strip()
                    if stripped.startswith("#"):
                        continue
                    if "SELECT" in line_upper and dml not in line_upper:
                        continue
                    raw_write_violations.append(
                        f"line {i}: raw write to {table}: "
                        f"{stripped[:80]}")

    all_violations = call_violations + import_violations + raw_write_violations
    assert not all_violations, (
        f"A1.4 gate violations in {this_file.name}:\n"
        + "\n".join(all_violations)
    )


# ===========================================================================
# B12: bundle_signer pin (F-3 ruling, spec 6)
# ===========================================================================

@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M2T12dIdentityPending,
                    reason="d5: B12a bundle_signer_mismatch not built")
def test_b12a_bundle_signer_rotated_to_admin_key(identity_server):
    """B12a: G; v2 swaps bundle_signer to a fresh test key -> 400
    bundle_signer_mismatch; R items 1,2,5 hold; one new refusal row."""
    srv = identity_server
    ctx = _base_G(srv)
    org_id = ctx["org_id"]

    # Build a fresh bundle signer key (different from server's)
    fresh_bs_sk = SigningKey.generate()
    fresh_bs_kid = hashlib.sha256(bytes(fresh_bs_sk.verify_key)).hexdigest()
    fresh_bs = {
        "key_id": fresh_bs_kid,
        "public_key": bytes(fresh_bs_sk.verify_key).hex(),
        "alg": "ed25519",
    }

    # v2: keep keys, swap bundle_signer
    prev_payload = ctx["chain"][-1]["payload"]
    payload = dict(prev_payload,
                   version=2,
                   prev_hash=_payload_hash(prev_payload),
                   bundle_signer=fresh_bs,
                   expires_at=time.time() + 6 * 24 * 3600)

    tag = b"agg/registry/v1"
    canonical = json.dumps(payload, sort_keys=True,
                           separators=(",", ":")).encode()
    msg = tag + b"\x00" + canonical
    sig = ctx["alice_sk"].sign(msg).signature.hex()

    env = {
        "kind": "agg/registry/v1", "sig_v": 1,
        "payload": payload,
        "signatures": [{"key_id": ctx["alice_kid"], "alg": "ed25519",
                        "sig": sig}],
    }
    _local_ok(ctx, env)

    snap_before = _snap(srv, org_id, [])
    token = _get_signer_token_httpx(
        srv["base_url"], ctx["alice_sk"], ctx["alice_kid"])
    r = _post(srv, token, org_id, env)
    snap_after = _snap(srv, org_id, [])

    if r.status_code == 200:
        raise M2T12dIdentityPending(
            "B12a: server accepted rotated bundle_signer")

    assert r.status_code == 400
    body = r.json()
    assert body.get("error") == "bundle_signer_mismatch", f"body: {body}"
    # R items 1, 2, 5
    assert snap_after["ver_count"] == snap_before["ver_count"]
    assert snap_after["ak_rows"] == snap_before["ak_rows"]
    assert snap_after["rv_count"] == snap_before["rv_count"]
    # Exactly one new refusal row
    assert snap_after["refused_count"] == snap_before["refused_count"] + 1


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M2T12dIdentityPending,
                    reason="d5: B12b bundle_signer_mismatch threshold 2")
def test_b12b_bundle_signer_swap_threshold_2(identity_server):
    """B12b: V2C; v3 swaps bundle_signer; signed K_a1+K_c -> same refusal."""
    srv = identity_server
    ctx = _base_V2C(srv)
    org_id = ctx["org_id"]

    fresh_bs_sk = SigningKey.generate()
    fresh_bs_kid = hashlib.sha256(bytes(fresh_bs_sk.verify_key)).hexdigest()
    fresh_bs = {
        "key_id": fresh_bs_kid,
        "public_key": bytes(fresh_bs_sk.verify_key).hex(),
        "alg": "ed25519",
    }

    prev_payload = ctx["chain"][-1]["payload"]
    payload = dict(prev_payload,
                   version=3,
                   prev_hash=_payload_hash(prev_payload),
                   bundle_signer=fresh_bs,
                   expires_at=time.time() + 6 * 24 * 3600)

    tag = b"agg/registry/v1"
    canonical = json.dumps(payload, sort_keys=True,
                           separators=(",", ":")).encode()
    msg = tag + b"\x00" + canonical
    sigs = []
    for sk_name, sk_val in [("alice", ctx["alice_sk"]),
                            ("carol", ctx["carol_sk"])]:
        kid = _kid(sk_val)
        sig = sk_val.sign(msg).signature.hex()
        sigs.append({"key_id": kid, "alg": "ed25519", "sig": sig})

    env = {
        "kind": "agg/registry/v1", "sig_v": 1,
        "payload": payload,
        "signatures": sigs,
    }
    _local_ok(ctx, env)

    snap_before = _snap(srv, org_id, [])
    token = _get_signer_token_httpx(
        srv["base_url"], ctx["alice_sk"], ctx["alice_kid"])
    r = _post(srv, token, org_id, env)
    snap_after = _snap(srv, org_id, [])

    if r.status_code == 200:
        raise M2T12dIdentityPending(
            "B12b: server accepted rotated bundle_signer at threshold 2")

    assert r.status_code == 400
    body = r.json()
    assert body.get("error") == "bundle_signer_mismatch"
    assert snap_after["ver_count"] == snap_before["ver_count"]
    assert snap_after["ak_rows"] == snap_before["ak_rows"]
    assert snap_after["rv_count"] == snap_before["rv_count"]
    assert snap_after["refused_count"] == snap_before["refused_count"] + 1


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M2T12dIdentityPending,
                    reason="d5: B12c bundle_signer_not_configured")
def test_b12c_bundle_signer_not_configured(identity_server, monkeypatch):
    """B12c: G; AGG_BUNDLE_SIGNER_KEY_FILE unset -> 400
    bundle_signer_not_configured; R 1,2,5 hold; no new refusal row."""
    srv = identity_server
    ctx = _base_G(srv)
    org_id = ctx["org_id"]

    # v2 with bundle_signer unchanged (valid chain), but server has no key
    env = _next(ctx, threshold=1, signers=[ctx["alice_sk"]])
    _local_ok(ctx, env)

    snap_before = _snap(srv, org_id, [])
    token = _get_signer_token_httpx(
        srv["base_url"], ctx["alice_sk"], ctx["alice_kid"])

    # Unset the bundle signer key file for this request
    monkeypatch.delenv("AGG_BUNDLE_SIGNER_KEY_FILE", raising=False)

    r = _post(srv, token, org_id, env)
    snap_after = _snap(srv, org_id, [])

    if r.status_code == 200:
        raise M2T12dIdentityPending(
            "B12c: server accepted v2 without bundle_signer configured")

    assert r.status_code == 400
    body = r.json()
    assert body.get("error") == "bundle_signer_not_configured", f"body: {body}"
    assert snap_after["ver_count"] == snap_before["ver_count"]
    assert snap_after["ak_rows"] == snap_before["ak_rows"]
    assert snap_after["rv_count"] == snap_before["rv_count"]
    # No new refusal row (different from identity refusal)
    assert snap_after["refused_count"] == snap_before["refused_count"]


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M2T12dIdentityPending,
                    reason="d5: B12 twin bundle_signer carried -> A")
def test_b12_twin_bundle_signer_carried(identity_server):
    """B12 twin: G; v2 with bundle_signer unchanged -> accepted."""
    srv = identity_server
    ctx = _base_G(srv)
    org_id = ctx["org_id"]

    env = _next(ctx, threshold=1, signers=[ctx["alice_sk"]])
    _local_ok(ctx, env)

    snap_before = _snap(srv, org_id, [])
    token = _get_signer_token_httpx(
        srv["base_url"], ctx["alice_sk"], ctx["alice_kid"])
    r = _post(srv, token, org_id, env)
    snap_after = _snap(srv, org_id, [])

    if r.status_code != 200:
        raise M2T12dIdentityPending(
            f"B12 twin: expected 200, got {r.status_code}")

    _check_d5_accepted(snap_before, snap_after)
    _assert_accepted(r, 2, snap_before, snap_after)


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M2T12dIdentityPending,
                    reason="d5: B12 twin rotation after server key change")
def test_b12_twin_rotation_after_server_key_change(identity_server, tmp_path):
    """B12 twin: G; monkeypatch server key; v2 carrying new key -> accepted;
    v3 carrying old key -> 400 bundle_signer_mismatch."""
    import os as _os
    srv = identity_server
    ctx = _base_G(srv)
    org_id = ctx["org_id"]

    # Create a new server bundle signer key
    new_bs_sk = SigningKey.generate()
    new_bs_pub = bytes(new_bs_sk.verify_key)
    new_bs_kid = hashlib.sha256(new_bs_pub).hexdigest()
    new_bs = {
        "key_id": new_bs_kid,
        "public_key": new_bs_pub.hex(),
        "alg": "ed25519",
    }

    new_key_file = tmp_path / "new_bundle_signer.key"
    new_key_file.write_bytes(bytes(new_bs_sk).hex().encode("ascii"))

    # v2: bundle_signer = new key (matching the new server config)
    prev_payload = ctx["chain"][-1]["payload"]
    payload_v2 = dict(prev_payload,
                      version=2,
                      prev_hash=_payload_hash(prev_payload),
                      bundle_signer=new_bs,
                      expires_at=time.time() + 6 * 24 * 3600)

    tag = b"agg/registry/v1"
    canonical = json.dumps(payload_v2, sort_keys=True,
                           separators=(",", ":")).encode()
    msg = tag + b"\x00" + canonical
    sig = ctx["alice_sk"].sign(msg).signature.hex()
    env_v2 = {
        "kind": "agg/registry/v1", "sig_v": 1,
        "payload": payload_v2,
        "signatures": [{"key_id": ctx["alice_kid"], "alg": "ed25519",
                        "sig": sig}],
    }
    _local_ok(ctx, env_v2)

    # Switch server to new key
    old_key_file = _os.environ.get("AGG_BUNDLE_SIGNER_KEY_FILE")
    _os.environ["AGG_BUNDLE_SIGNER_KEY_FILE"] = str(new_key_file)
    try:
        snap_before = _snap(srv, org_id, [])
        token = _get_signer_token_httpx(
            srv["base_url"], ctx["alice_sk"], ctx["alice_kid"])
        r_v2 = _post(srv, token, org_id, env_v2)
        snap_after = _snap(srv, org_id, [])

        if r_v2.status_code != 200:
            raise M2T12dIdentityPending(
                f"B12 twin rotation v2: expected 200, got {r_v2.status_code}")

        _check_d5_accepted(snap_before, snap_after)
        ctx["chain"].append(env_v2)

        # v3: carry the OLD bundle_signer -> should be refused
        old_bs = prev_payload["bundle_signer"]
        payload_v3 = dict(payload_v2,
                          version=3,
                          prev_hash=_payload_hash(payload_v2),
                          bundle_signer=old_bs,
                          expires_at=time.time() + 6 * 24 * 3600)
        canonical_v3 = json.dumps(payload_v3, sort_keys=True,
                                  separators=(",", ":")).encode()
        msg_v3 = tag + b"\x00" + canonical_v3
        sig_v3 = ctx["alice_sk"].sign(msg_v3).signature.hex()
        env_v3 = {
            "kind": "agg/registry/v1", "sig_v": 1,
            "payload": payload_v3,
            "signatures": [{"key_id": ctx["alice_kid"], "alg": "ed25519",
                            "sig": sig_v3}],
        }
        _local_ok(ctx, env_v3)

        snap_before_v3 = _snap(srv, org_id, [])
        r_v3 = _post(srv, token, org_id, env_v3)
        snap_after_v3 = _snap(srv, org_id, [])

        if r_v3.status_code == 200:
            raise M2T12dIdentityPending(
                "B12 twin rotation v3: server accepted old bundle_signer")

        assert r_v3.status_code == 400
        body = r_v3.json()
        assert body.get("error") == "bundle_signer_mismatch"
    finally:
        if old_key_file is not None:
            _os.environ["AGG_BUNDLE_SIGNER_KEY_FILE"] = old_key_file
        else:
            _os.environ.pop("AGG_BUNDLE_SIGNER_KEY_FILE", None)
