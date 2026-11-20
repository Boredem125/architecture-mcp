"""M3 T4 tests-first: publish verification, stale base, registry rebuild,
read scope, 410 flag, direct publish under flag, code-issue expires_at,
migration 0019 checks.

Spec: T4_SPEC.md section 3.1.  48 functions, 50 node ids, 6 guards.
Guard twins PASS today.  Marked ``pg``.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import importlib
import importlib.util
import json
import os
import secrets
import time
import uuid
from concurrent.futures import ThreadPoolExecutor

import psycopg
import psycopg.errors
import pytest
from nacl.signing import SigningKey

from .m3_pending import M3T4Pending, require_m3
from .m2_sync_server import (
    make_sync_server, ensure_at_head, create_org, create_project,
    keygen, sign_envelope, canonical_json,
)
from .t9_helpers import (
    seed_session, make_session_cookie, compute_csrf, _conninfo,
)
from .fake_idp import FakeClock


# ---------------------------------------------------------------------------
# Helpers (shared with T3)
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


def _bind_project_admin(conn, org_id: str, user_id: str,
                         project_id: str) -> None:
    conn.execute(
        "INSERT INTO role_bindings "
        "(id, org_id, user_id, scope_type, scope_id, role, created_at) "
        "VALUES (%s, %s, %s, 'project', %s, 'admin', now())",
        [str(uuid.uuid4()), org_id, user_id, project_id],
    )


def _bind_viewer(conn, org_id: str, user_id: str) -> None:
    conn.execute(
        "INSERT INTO role_bindings "
        "(id, org_id, user_id, scope_type, scope_id, role, created_at) "
        "VALUES (%s, %s, %s, 'org', %s, 'viewer', now())",
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


def _make_key_entry(sk, user_id: str, kind: str = "cli",
                    roles: list[str] | None = None,
                    added_in: int = 1) -> dict:
    pub = bytes(sk.verify_key)
    kid = hashlib.sha256(pub).hexdigest()
    return {
        "key_id": kid,
        "public_key": pub.hex(),
        "user_id": user_id,
        "iss": "https://idp.test",
        "sub": f"sub-{user_id[:8]}",
        "alg": "ed25519",
        "kind": kind,
        "roles": roles or ["admin", "approver"],
        "added_in": added_in,
    }


def _payload_hash(payload: dict) -> str:
    cj = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(
        payload["org_id"].encode("utf-8") + b":" + cj
    ).hexdigest()


def _sign_envelope_multi(kind: str, payload: dict, sks: list) -> dict:
    tag = kind.encode("utf-8")
    canonical = json.dumps(payload, sort_keys=True,
                           separators=(",", ":")).encode()
    msg = tag + b"\x00" + canonical
    sigs = []
    for sk in sks:
        pub = bytes(sk.verify_key)
        kid = hashlib.sha256(pub).hexdigest()
        sig = sk.sign(msg).signature.hex()
        sigs.append({"key_id": kid, "alg": "ed25519", "sig": sig})
    return {
        "kind": kind, "sig_v": 1,
        "payload": payload,
        "signatures": sigs,
    }


def _build_registry_chain(org_id, bundle_signer_sk, entries, admin_sks,
                            threshold=2):
    bs_pub = bytes(bundle_signer_sk.verify_key)
    bs_kid = hashlib.sha256(bs_pub).hexdigest()
    admin_kids = [hashlib.sha256(bytes(sk.verify_key)).hexdigest()
                  for sk in admin_sks]
    payload = {
        "org_id": org_id,
        "version": 1,
        "prev_hash": "",
        "threshold": threshold,
        "admins": admin_kids,
        "keys": entries,
        "bundle_signer": {
            "key_id": bs_kid,
            "public_key": bs_pub.hex(),
            "alg": "ed25519",
        },
        "expires_at": time.time() + 7 * 86400,
    }
    genesis = _sign_envelope_multi("agg/registry/v1", payload, admin_sks)
    fp = _payload_hash(payload)
    return [genesis], fp


def _store_chain(owner_url: str, org_id: str, chain: list[dict]) -> None:
    from agg_cp.sync.registry import store_registry_version
    from sandbox.protocol.registry import RegistryError
    conninfo = _conninfo(owner_url)
    for env in chain:
        try:
            with psycopg.connect(conninfo) as conn:
                store_registry_version(conn, org_id, env)
        except RegistryError as exc:
            if "second genesis" in str(exc):
                return
            raise


def _sign_approval(sk, bundle_hash):
    from sandbox.protocol.envelope import canonical_bytes
    a_payload = {"bundle_hash": bundle_hash}
    msg = canonical_bytes("agg/policy-change/v1", a_payload)
    pub = bytes(sk.verify_key)
    kid = hashlib.sha256(pub).hexdigest()
    sig = sk.sign(msg).signature.hex()
    return {
        "kind": "agg/policy-change/v1", "sig_v": 1,
        "payload": a_payload,
        "signatures": [{"key_id": kid, "alg": "ed25519", "sig": sig}],
    }


def _kid(sk):
    return hashlib.sha256(bytes(sk.verify_key)).hexdigest()


def _propose(client, base_url, project_id, bundle, cookie, csrf):
    r = client.post(
        f"{base_url}/api/v1/admin/bundle-proposals",
        json={"project_id": project_id, "bundle": bundle},
        cookies={"__Host-agg_session": cookie},
        headers={"X-CSRF-Token": csrf},
        timeout=10,
    )
    return r


def _approve(client, base_url, proposal_id, envelope, cookie, csrf):
    r = client.post(
        f"{base_url}/api/v1/admin/bundle-proposals/{proposal_id}/approvals",
        json={"approval": envelope},
        cookies={"__Host-agg_session": cookie},
        headers={"X-CSRF-Token": csrf},
        timeout=10,
    )
    return r


def _publish(client, base_url, proposal_id, cookie, csrf):
    r = client.post(
        f"{base_url}/api/v1/admin/bundle-proposals/{proposal_id}/publish",
        json={},
        cookies={"__Host-agg_session": cookie},
        headers={"X-CSRF-Token": csrf},
        timeout=10,
    )
    return r


def _seed_device(conn, org_id, project_id):
    """Seed a connector + device_tokens row.  Returns (device_id, token)."""
    device_id = str(uuid.uuid4())
    sk = SigningKey.generate()
    pub = bytes(sk.verify_key)
    conn.execute(
        "INSERT INTO connectors "
        "(id, org_id, project_id, device_public_key, operator_user_id, created_at) "
        "VALUES (%s, %s::uuid, %s::uuid, %s, NULL, now())",
        [device_id, org_id, project_id, pub.hex()],
    )
    token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    conn.execute(
        "INSERT INTO device_tokens "
        "(id, org_id, project_id, connector_id, token_hash, expires_at, created_at) "
        "VALUES (%s, %s::uuid, %s::uuid, %s::uuid, %s, "
        "now() + interval '10 minutes', now())",
        [str(uuid.uuid4()), org_id, project_id, device_id, token_hash],
    )
    return device_id, token


def _make_bundle_envelope(payload, bundle_signer_sk):
    """Sign a bundle envelope using the bundle_signer key."""
    return _sign_envelope_multi("agg/bundle/v1", payload, [bundle_signer_sk])


def _owner_insert_bundle(conn, org_id, project_id, sequence,
                          bundle_signer_sk, payload,
                          verification="m2_unverified"):
    """Insert a policy_bundles row as owner.  Returns bundle_id."""
    bid = str(uuid.uuid4())
    env = _make_bundle_envelope(payload, bundle_signer_sk)
    blob = json.dumps(env, sort_keys=True, separators=(",", ":")).encode()
    if verification == "server":
        conn.execute(
            "INSERT INTO policy_bundles "
            "(id, org_id, project_id, sequence, bundle_blob, server_signature, "
            "created_at, verification, verified_at) "
            "VALUES (%s, %s::uuid, %s::uuid, %s, %s, '', now(), 'server', now())",
            [bid, org_id, project_id, sequence, blob],
        )
    else:
        conn.execute(
            "INSERT INTO policy_bundles "
            "(id, org_id, project_id, sequence, bundle_blob, server_signature, "
            "created_at) "
            "VALUES (%s, %s::uuid, %s::uuid, %s, %s, '', now())",
            [bid, org_id, project_id, sequence, blob],
        )
    return bid


def _counts(owner_url, org_id, project_id):
    """Return (bundle_count, bundle_keyed_approval_count) for _assert_nothing_written.

    bundle_keyed_approval_count: policy_change_approvals rows whose
    change_request_id is not a policy_change_requests.id, or equals a
    policy_bundles.id, for this org.  Schema 0007 has no FK on
    change_request_id, so the publish route's copied approvals (keyed to
    a bundle id) show up here.
    """
    conninfo = _conninfo(owner_url)
    with psycopg.connect(conninfo) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        bc = conn.execute(
            "SELECT count(*) FROM policy_bundles "
            "WHERE org_id = %s::uuid AND project_id = %s::uuid",
            [org_id, project_id],
        ).fetchone()[0]
        # Approvals whose change_request_id is a bundle id (not a request id)
        bac = conn.execute(
            "SELECT count(*) FROM policy_change_approvals a "
            "WHERE a.org_id = %s::uuid "
            "AND EXISTS (SELECT 1 FROM policy_bundles b "
            "            WHERE b.id = a.change_request_id "
            "            AND b.org_id = %s::uuid "
            "            AND b.project_id = %s::uuid)",
            [org_id, org_id, project_id],
        ).fetchone()[0]
        return (bc, bac)


def _assert_nothing_written(owner_url, org_id, project_id, proposal_id,
                             reason, before_counts):
    """Spec section 3 "Nothing written": no new policy_bundles row for the
    project, no new policy_change_approvals row keyed to a bundle id,
    proposal still open, no bundle_proposal.publish row, exactly one
    bundle_proposal.publish_refused row with that reason.

    before_counts is the tuple from _counts() taken just before publish.
    """
    conninfo = _conninfo(owner_url)
    with psycopg.connect(conninfo) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        bc = conn.execute(
            "SELECT count(*) FROM policy_bundles "
            "WHERE org_id = %s::uuid AND project_id = %s::uuid",
            [org_id, project_id],
        ).fetchone()[0]
        assert bc == before_counts[0], (
            f"new bundle rows: {bc} vs {before_counts[0]}")
        # No new approvals keyed to a bundle id (N4)
        bac = conn.execute(
            "SELECT count(*) FROM policy_change_approvals a "
            "WHERE a.org_id = %s::uuid "
            "AND EXISTS (SELECT 1 FROM policy_bundles b "
            "            WHERE b.id = a.change_request_id "
            "            AND b.org_id = %s::uuid "
            "            AND b.project_id = %s::uuid)",
            [org_id, org_id, project_id],
        ).fetchone()[0]
        assert bac == before_counts[1], (
            f"new bundle-keyed approvals: {bac} vs {before_counts[1]}")
        status = conn.execute(
            "SELECT status FROM policy_change_requests WHERE id = %s::uuid",
            [proposal_id],
        ).fetchone()[0]
        assert status == "open", f"proposal status: {status}"
        pub_row = conn.execute(
            "SELECT count(*) FROM admin_audit "
            "WHERE org_id = %s::uuid "
            "AND action = 'bundle_proposal.publish' "
            "AND detail->>'proposal_id' = %s",
            [org_id, proposal_id],
        ).fetchone()[0]
        assert pub_row == 0, f"unexpected publish audit rows: {pub_row}"
        refused = conn.execute(
            "SELECT count(*) FROM admin_audit "
            "WHERE org_id = %s::uuid "
            "AND action = 'bundle_proposal.publish_refused' "
            "AND detail->>'proposal_id' = %s "
            "AND detail->>'reason' = %s",
            [org_id, proposal_id, reason],
        ).fetchone()[0]
        assert refused == 1, (
            f"expected 1 publish_refused row with reason={reason}, got {refused}")


# ---------------------------------------------------------------------------
# Own-org helper for nodes that need a fresh registry
# ---------------------------------------------------------------------------

def _create_own_org(owner_url, base_url, bundle_signer_sk, entries,
                     admin_sks, threshold=2, users_as_admins=None,
                     project_name="OwnOrg Proj", environment="staging"):
    """Create a fresh org with its own registry chain.

    Returns a dict with org_id, project_id, chain, fp, plus sessions
    for each user named in users_as_admins (list of (name, user_id) pairs).
    """
    conninfo = _conninfo(owner_url)
    org_id = str(uuid.uuid4())
    with psycopg.connect(conninfo, autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        create_org(conn, org_id, f"OwnOrg {org_id[:8]}")
        project_id = str(uuid.uuid4())
        create_project(conn, org_id, project_id, project_name,
                        environment=environment)

        user_map = {}
        if users_as_admins:
            for name, uid in users_as_admins:
                _seed_user_row(conn, org_id, f"{name}@own.test")
                # Need to insert with the given uid
                conn.execute(
                    "INSERT INTO users (id, org_id, oidc_issuer, oidc_subject, "
                    "email, status, created_at) "
                    "VALUES (%s, %s, 'https://idp.test', %s, %s, "
                    "'active', now()) ON CONFLICT DO NOTHING",
                    [uid, org_id, f"sub-{uuid.uuid4().hex[:8]}",
                     f"{name}@own.test"],
                )
                _bind_admin(conn, org_id, uid)
                user_map[name] = uid

    chain, fp = _build_registry_chain(org_id, bundle_signer_sk, entries,
                                       admin_sks, threshold=threshold)
    _store_chain(owner_url, org_id, chain)

    # Register approver_keys for entries
    with psycopg.connect(conninfo, autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        for entry in entries:
            kid = entry["key_id"]
            conn.execute(
                "INSERT INTO approver_keys "
                "(id, org_id, user_id, public_key, alg, kind, key_id, roles, "
                "registry_version, enrolled_at, created_at) "
                "VALUES (%s, %s::uuid, %s::uuid, %s, 'ed25519', %s, %s, "
                "%s::jsonb, 1, now(), now()) ON CONFLICT DO NOTHING",
                [str(uuid.uuid4()), org_id, entry["user_id"],
                 entry["public_key"], entry["kind"], kid,
                 json.dumps(entry.get("roles", []))],
            )

    clock = FakeClock()
    sessions = {}
    if users_as_admins:
        for name, uid in users_as_admins:
            cookie, csrf, _ = _make_fresh_session(owner_url, org_id, uid,
                                                   clock=clock)
            sessions[f"{name}_cookie"] = cookie
            sessions[f"{name}_csrf"] = csrf

    return {
        "org_id": org_id,
        "project_id": project_id,
        "chain": chain,
        "fp": fp,
        "user_map": user_map,
        **sessions,
    }


# ---------------------------------------------------------------------------
# G1 gate helper
# ---------------------------------------------------------------------------

def _g1_gate(rp):
    """G1: fires on the first publish that reaches verification today."""
    try:
        _err = rp.json().get("error", "")
    except Exception:
        _err = ""
    require_m3(4,
               not (rp.status_code == 400 and _err == "verification_pending"),
               "server publish verification (T4)")


# ---------------------------------------------------------------------------
# Module-scoped server fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def t4_server(pg_url, app_url, owner_url, pg_roles, tmp_path_factory):
    """4-worker server for T4 publish verification tests.

    extra_env drops both flag variables so the server has no
    AGG_ALLOW_DIRECT_PUBLISH and no AGG_DEPLOY_PROFILE.

    Fixtures per spec:
    - org admins: alice, bob, carol, dave
    - project-admin pat (project_id only)
    - viewer vic
    - frank: cli key, role approver (no admin)
    - erin: cli key, role viewer
    - enrolled device per project for GET /sync/bundle
    - second org with threshold-1 genesis (single admin) for T0b-7
    """
    bundle_signer_sk = SigningKey.generate()
    key_dir = tmp_path_factory.mktemp("t4_bundle_signer")
    key_file = key_dir / "bundle_signer.key"
    key_file.write_bytes(bytes(bundle_signer_sk).hex().encode("ascii"))
    old_bs = os.environ.get("AGG_BUNDLE_SIGNER_KEY_FILE")
    os.environ["AGG_BUNDLE_SIGNER_KEY_FILE"] = str(key_file)

    gen = make_sync_server(
        pg_url, app_url, owner_url,
        org_names=["T4 Org"],
        extra_env={
            "AGG_ALLOW_DIRECT_PUBLISH": None,
            "AGG_DEPLOY_PROFILE": None,
        },
    )
    info = next(gen)

    conninfo = _conninfo(owner_url)
    org_id = info["org_id"]
    with psycopg.connect(conninfo, autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        alice_id = _seed_user_row(conn, org_id, "alice@t4.test")
        bob_id = _seed_user_row(conn, org_id, "bob@t4.test")
        carol_id = _seed_user_row(conn, org_id, "carol@t4.test")
        dave_id = _seed_user_row(conn, org_id, "dave@t4.test")
        frank_id = _seed_user_row(conn, org_id, "frank@t4.test")
        erin_id = _seed_user_row(conn, org_id, "erin@t4.test")
        pat_id = _seed_user_row(conn, org_id, "pat@t4.test")
        vic_id = _seed_user_row(conn, org_id, "vic@t4.test")

        for uid in (alice_id, bob_id, carol_id, dave_id):
            _bind_admin(conn, org_id, uid)

        project_id = str(uuid.uuid4())
        project2_id = str(uuid.uuid4())
        create_project(conn, org_id, project_id, "T4 Project")
        create_project(conn, org_id, project2_id, "T4 Project 2")
        _bind_project_admin(conn, org_id, pat_id, project_id)
        _bind_viewer(conn, org_id, vic_id)

        # Enrolled device per project for GET /sync/bundle
        dev1_id, dev1_token = _seed_device(conn, org_id, project_id)
        dev2_id, dev2_token = _seed_device(conn, org_id, project2_id)

    alice_sk = SigningKey.generate()
    bob_sk = SigningKey.generate()
    carol_sk = SigningKey.generate()
    dave_sk = SigningKey.generate()
    frank_sk = SigningKey.generate()
    erin_sk = SigningKey.generate()

    entries = [
        _make_key_entry(alice_sk, alice_id, "cli", ["admin", "approver"]),
        _make_key_entry(bob_sk, bob_id, "cli", ["admin", "approver"]),
        _make_key_entry(carol_sk, carol_id, "cli", ["admin", "approver"]),
        _make_key_entry(dave_sk, dave_id, "cli", ["admin", "approver"]),
        _make_key_entry(frank_sk, frank_id, "cli", ["approver"]),
        _make_key_entry(erin_sk, erin_id, "cli", ["viewer"]),
    ]
    chain, fp = _build_registry_chain(org_id, bundle_signer_sk, entries,
                                       [alice_sk, bob_sk], threshold=2)
    _store_chain(owner_url, org_id, chain)

    # Register approver_keys rows for all keys
    with psycopg.connect(conninfo, autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        for sk, uid in [(alice_sk, alice_id), (bob_sk, bob_id),
                        (carol_sk, carol_id), (dave_sk, dave_id),
                        (frank_sk, frank_id), (erin_sk, erin_id)]:
            pub = bytes(sk.verify_key)
            kid = hashlib.sha256(pub).hexdigest()
            conn.execute(
                "INSERT INTO approver_keys "
                "(id, org_id, user_id, public_key, alg, kind, key_id, roles, "
                "registry_version, enrolled_at, created_at) "
                "VALUES (%s, %s::uuid, %s::uuid, %s, 'ed25519', 'cli', %s, "
                "%s::jsonb, 1, now(), now()) ON CONFLICT DO NOTHING",
                [str(uuid.uuid4()), org_id, uid, pub.hex(), kid,
                 json.dumps(entries[[_kid(s) for s in
                    [alice_sk, bob_sk, carol_sk, dave_sk, frank_sk, erin_sk]
                 ].index(kid)].get("roles", []))],
            )

    # Second org: threshold-1 genesis (single admin) for T0b-7
    single_admin_sk = SigningKey.generate()
    single_user2_sk = SigningKey.generate()
    single_org_id = str(uuid.uuid4())
    single_admin_id = str(uuid.uuid4())
    single_user2_id = str(uuid.uuid4())
    single_pub_id = str(uuid.uuid4())  # publisher, not an approver
    with psycopg.connect(conninfo, autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [single_org_id])
        create_org(conn, single_org_id, "T4 Single Admin Org")
        conn.execute(
            "INSERT INTO users (id, org_id, oidc_issuer, oidc_subject, email, "
            "status, created_at) VALUES (%s, %s, 'https://idp.test', %s, %s, "
            "'active', now()) ON CONFLICT DO NOTHING",
            [single_admin_id, single_org_id,
             f"sub-{uuid.uuid4().hex[:8]}", "sadmin@t4.test"],
        )
        conn.execute(
            "INSERT INTO users (id, org_id, oidc_issuer, oidc_subject, email, "
            "status, created_at) VALUES (%s, %s, 'https://idp.test', %s, %s, "
            "'active', now()) ON CONFLICT DO NOTHING",
            [single_user2_id, single_org_id,
             f"sub-{uuid.uuid4().hex[:8]}", "suser2@t4.test"],
        )
        conn.execute(
            "INSERT INTO users (id, org_id, oidc_issuer, oidc_subject, email, "
            "status, created_at) VALUES (%s, %s, 'https://idp.test', %s, %s, "
            "'active', now()) ON CONFLICT DO NOTHING",
            [single_pub_id, single_org_id,
             f"sub-{uuid.uuid4().hex[:8]}", "spub@t4.test"],
        )
        _bind_admin(conn, single_org_id, single_admin_id)
        _bind_admin(conn, single_org_id, single_user2_id)
        _bind_admin(conn, single_org_id, single_pub_id)
        single_proj_id = str(uuid.uuid4())
        create_project(conn, single_org_id, single_proj_id,
                        "T4 Single Proj")

    single_entries = [
        _make_key_entry(single_admin_sk, single_admin_id, "cli",
                        ["admin", "approver"]),
        _make_key_entry(single_user2_sk, single_user2_id, "cli",
                        ["admin", "approver"]),
    ]
    single_chain, single_fp = _build_registry_chain(
        single_org_id, bundle_signer_sk, single_entries,
        [single_admin_sk], threshold=1,
    )
    _store_chain(owner_url, single_org_id, single_chain)

    with psycopg.connect(conninfo, autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [single_org_id])
        for sk, uid in [(single_admin_sk, single_admin_id),
                        (single_user2_sk, single_user2_id)]:
            pub = bytes(sk.verify_key)
            kid = hashlib.sha256(pub).hexdigest()
            conn.execute(
                "INSERT INTO approver_keys "
                "(id, org_id, user_id, public_key, alg, kind, key_id, roles, "
                "registry_version, enrolled_at, created_at) "
                "VALUES (%s, %s::uuid, %s::uuid, %s, 'ed25519', 'cli', %s, "
                "%s::jsonb, 1, now(), now()) ON CONFLICT DO NOTHING",
                [str(uuid.uuid4()), single_org_id, uid, pub.hex(), kid,
                 json.dumps(["admin", "approver"])],
            )
        _seed_device(conn, single_org_id, single_proj_id)

    clock = FakeClock()
    sessions = {}
    for name, uid in [("alice", alice_id), ("bob", bob_id),
                      ("carol", carol_id), ("dave", dave_id),
                      ("frank", frank_id), ("erin", erin_id),
                      ("pat", pat_id), ("vic", vic_id)]:
        cookie, csrf, sid = _make_fresh_session(
            owner_url, org_id, uid, clock=clock)
        sessions[f"{name}_cookie"] = cookie
        sessions[f"{name}_csrf"] = csrf

    # Sessions for single-admin org
    for name, uid in [("sadmin", single_admin_id),
                      ("suser2", single_user2_id),
                      ("spub", single_pub_id)]:
        cookie, csrf, _ = _make_fresh_session(
            owner_url, single_org_id, uid, clock=clock)
        sessions[f"{name}_cookie"] = cookie
        sessions[f"{name}_csrf"] = csrf

    info.update({
        "alice_id": alice_id, "bob_id": bob_id, "carol_id": carol_id,
        "dave_id": dave_id, "frank_id": frank_id, "erin_id": erin_id,
        "pat_id": pat_id, "vic_id": vic_id,
        "project_id": project_id, "project2_id": project2_id,
        "bundle_signer_sk": bundle_signer_sk,
        "alice_sk": alice_sk, "bob_sk": bob_sk, "carol_sk": carol_sk,
        "dave_sk": dave_sk, "frank_sk": frank_sk, "erin_sk": erin_sk,
        "chain_fingerprint": fp,
        "dev1_token": dev1_token, "dev2_token": dev2_token,
        # Single-admin org
        "single_org_id": single_org_id,
        "single_proj_id": single_proj_id,
        "single_admin_id": single_admin_id,
        "single_user2_id": single_user2_id,
        "single_pub_id": single_pub_id,
        "single_admin_sk": single_admin_sk,
        "single_user2_sk": single_user2_sk,
        **sessions,
    })

    try:
        yield info
    finally:
        gen.close()
        if old_bs is None:
            os.environ.pop("AGG_BUNDLE_SIGNER_KEY_FILE", None)
        else:
            os.environ["AGG_BUNDLE_SIGNER_KEY_FILE"] = old_bs


@pytest.fixture(scope="module")
def t4_demo_server(pg_url, app_url, owner_url, pg_roles, tmp_path_factory):
    """Server with AGG_DEPLOY_PROFILE=demo, AGG_ALLOW_DIRECT_PUBLISH=1."""
    bundle_signer_sk = SigningKey.generate()
    key_dir = tmp_path_factory.mktemp("t4_demo_signer")
    key_file = key_dir / "bundle_signer.key"
    key_file.write_bytes(bytes(bundle_signer_sk).hex().encode("ascii"))
    old_bs = os.environ.get("AGG_BUNDLE_SIGNER_KEY_FILE")
    os.environ["AGG_BUNDLE_SIGNER_KEY_FILE"] = str(key_file)

    gen = make_sync_server(
        pg_url, app_url, owner_url,
        org_names=["T4 Demo Org"],
        extra_env={
            "AGG_DEPLOY_PROFILE": "demo",
            "AGG_ALLOW_DIRECT_PUBLISH": "1",
        },
    )
    info = next(gen)

    conninfo = _conninfo(owner_url)
    org_id = info["org_id"]
    with psycopg.connect(conninfo, autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        admin_id = _seed_user_row(conn, org_id, "admin@t4demo.test")
        vic_id = _seed_user_row(conn, org_id, "viewer@t4demo.test")
        _bind_admin(conn, org_id, admin_id)
        _bind_viewer(conn, org_id, vic_id)
        project_id = str(uuid.uuid4())
        create_project(conn, org_id, project_id, "T4 Demo Project")

    clock = FakeClock()
    a_cookie, a_csrf, _ = _make_fresh_session(
        owner_url, org_id, admin_id, clock=clock)
    v_cookie, v_csrf, _ = _make_fresh_session(
        owner_url, org_id, vic_id, clock=clock)

    info.update({
        "admin_id": admin_id, "vic_id": vic_id,
        "project_id": project_id,
        "admin_cookie": a_cookie, "admin_csrf": a_csrf,
        "vic_cookie": v_cookie, "vic_csrf": v_csrf,
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
# Publish verification nodes
# ===================================================================

@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M3T4Pending)
def test_publish_verified_loosening_connector_applies_unchanged(
        t4_server, tmp_path):
    """carol proposes a loosening at base 0, alice and bob approve,
    carol publishes: 201, verification=server, verified_at set;
    GET /sync/bundle returns envelope and exactly two approvals;
    verify_and_apply succeeds; bundle.json bytes equal served envelope."""
    import httpx
    info = t4_server
    with httpx.Client(base_url=info["base_url"], timeout=30) as c:
        proj = str(uuid.uuid4())
        conninfo = _conninfo(info["owner_url"])
        with psycopg.connect(conninfo, autocommit=True) as conn:
            conn.execute("SELECT set_config('app.org_id', %s, false)",
                         [info["org_id"]])
            create_project(conn, info["org_id"], proj, "T4 Pub Test")
            _, dev_token = _seed_device(conn, info["org_id"], proj)

        bundle = {
            "folder_policy": {"shell": {"blocklist_action": "escalate"}},
            "governance_policy": {"clauses": []},
            "mcp_policy": {"servers": []},
            "approval": {"local_fallback": True, "allow_requester": False},
        }
        r = _propose(c, info["base_url"], proj, bundle,
                     info["carol_cookie"], info["carol_csrf"])
        assert r.status_code in (200, 201), (
            f"propose: {r.status_code} {r.text[:200]}")
        pid = r.json().get("id") or r.json().get("proposal_id")
        bh = r.json().get("hash") or r.json().get("bundle_hash")

        # alice approves
        env_a = _sign_approval(info["alice_sk"], bh)
        ra = _approve(c, info["base_url"], pid, env_a,
                      info["alice_cookie"], info["alice_csrf"])
        assert ra.status_code in (200, 201), (
            f"approve alice: {ra.status_code}")

        # bob approves
        env_b = _sign_approval(info["bob_sk"], bh)
        rb = _approve(c, info["base_url"], pid, env_b,
                      info["bob_cookie"], info["bob_csrf"])
        assert rb.status_code in (200, 201), f"approve bob: {rb.status_code}"

        # carol publishes
        rp = _publish(c, info["base_url"], pid,
                      info["carol_cookie"], info["carol_csrf"])
        # G1: publish gate
        _g1_gate(rp)

        assert rp.status_code == 201, (
            f"publish: {rp.status_code} {rp.text[:200]}")
        body = rp.json()
        assert body.get("verification") == "server"

        # Check DB row for verified_at and label
        with psycopg.connect(conninfo) as conn:
            conn.execute("SELECT set_config('app.org_id', %s, false)",
                         [info["org_id"]])
            row = conn.execute(
                "SELECT verification, verified_at FROM policy_bundles "
                "WHERE org_id = %s::uuid AND project_id = %s::uuid "
                "ORDER BY sequence DESC LIMIT 1",
                [info["org_id"], proj],
            ).fetchone()
        assert row is not None
        assert row[0] == "server"
        assert row[1] is not None, "verified_at should be set"

        # GET /sync/bundle with the device token
        rb2 = c.get(
            f"{info['base_url']}/api/v1/sync/bundle",
            params={"after": "0"},
            headers={"Authorization": f"Bearer {dev_token}"},
            timeout=10,
        )
        assert rb2.status_code == 200, (
            f"sync/bundle: {rb2.status_code} {rb2.text[:200]}")
        sb = rb2.json()
        assert "envelope" in sb
        served_env = sb["envelope"]
        served_approvals = sb.get("change_approvals", [])
        # Exactly the two approvals (alice & bob)
        served_kids = sorted(a["signatures"][0]["key_id"]
                             for a in served_approvals
                             if a.get("signatures"))
        expected_kids = sorted([_kid(info["alice_sk"]), _kid(info["bob_sk"])])
        assert served_kids == expected_kids, (
            f"served approvals: {served_kids} != {expected_kids}")

        # Build fresh connector layout and verify
        from sandbox.protocol.registry import verify_chain
        from sandbox.connector.sync.bundles import verify_and_apply
        from sandbox.connector.sync.process import _bundle_signer_pub
        from sandbox.connector.layout import FolderLayout

        with psycopg.connect(conninfo) as conn:
            conn.execute("SELECT set_config('app.org_id', %s, false)",
                         [info["org_id"]])
            chain_rows = conn.execute(
                "SELECT registry_blob FROM key_registry_versions "
                "WHERE org_id = %s::uuid ORDER BY version",
                [info["org_id"]],
            ).fetchall()
            # Read the stored bundle_blob for byte comparison (N3)
            blob_row = conn.execute(
                "SELECT bundle_blob FROM policy_bundles "
                "WHERE org_id = %s::uuid AND project_id = %s::uuid "
                "ORDER BY sequence DESC LIMIT 1",
                [info["org_id"], proj],
            ).fetchone()
        stored_blob = bytes(blob_row[0])
        stored_chain = [json.loads(bytes(r[0])) for r in chain_rows]
        reg = verify_chain(stored_chain, info["chain_fingerprint"])
        bsp = _bundle_signer_pub(reg)

        ws = tmp_path / "layout"
        ws.mkdir()
        sb = ws / ".sandbox"
        sb.mkdir()
        (sb / "state" / "sync").mkdir(parents=True)
        layout = FolderLayout(ws)
        result = verify_and_apply(
            layout, served_env, reg, bsp, served_approvals,
            org_id=info["org_id"], project_id=proj,
        )
        assert result is not None
        bundle_path = ws / ".sandbox" / "state" / "sync" / "bundle.json"
        bundle_bytes = bundle_path.read_bytes()
        # Compare served envelope with stored blob bytes (N3)
        assert bundle_bytes == stored_blob


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M3T4Pending)
def test_publish_tightening_one_approval_201(t4_server):
    """After a server row, a tightening with one approval: 201."""
    import httpx
    info = t4_server
    with httpx.Client(base_url=info["base_url"], timeout=30) as c:
        proj = str(uuid.uuid4())
        conninfo = _conninfo(info["owner_url"])
        with psycopg.connect(conninfo, autocommit=True) as conn:
            conn.execute("SELECT set_config('app.org_id', %s, false)",
                         [info["org_id"]])
            create_project(conn, info["org_id"], proj, "T4 Tight Test",
                           environment="staging")

        # First bundle (loosening from deny-all, needs 2)
        bundle1 = {
            "folder_policy": {"shell": {"blocklist_action": "escalate"}},
            "governance_policy": {"clauses": []},
            "mcp_policy": {"servers": []},
            "approval": {"local_fallback": True, "allow_requester": False},
        }
        r1 = _propose(c, info["base_url"], proj, bundle1,
                       info["carol_cookie"], info["carol_csrf"])
        assert r1.status_code in (200, 201)
        pid1 = r1.json().get("id") or r1.json().get("proposal_id")
        bh1 = r1.json().get("hash") or r1.json().get("bundle_hash")
        ra = _approve(c, info["base_url"], pid1,
                      _sign_approval(info["alice_sk"], bh1),
                      info["alice_cookie"], info["alice_csrf"])
        assert ra.status_code in (200, 201)
        rb = _approve(c, info["base_url"], pid1,
                      _sign_approval(info["bob_sk"], bh1),
                      info["bob_cookie"], info["bob_csrf"])
        assert rb.status_code in (200, 201)
        rp1 = _publish(c, info["base_url"], pid1,
                        info["carol_cookie"], info["carol_csrf"])
        _g1_gate(rp1)
        assert rp1.status_code == 201

        # Tightening (back to deny-all, needs 1)
        bundle2 = {
            "folder_policy": {"shell": {"blocklist_action": "deny"}},
            "governance_policy": {"clauses": []},
            "mcp_policy": {"servers": []},
            "approval": {"local_fallback": False, "allow_requester": False},
        }
        r2 = _propose(c, info["base_url"], proj, bundle2,
                       info["carol_cookie"], info["carol_csrf"])
        assert r2.status_code in (200, 201)
        pid2 = r2.json().get("id") or r2.json().get("proposal_id")
        bh2 = r2.json().get("hash") or r2.json().get("bundle_hash")
        ra2 = _approve(c, info["base_url"], pid2,
                       _sign_approval(info["alice_sk"], bh2),
                       info["alice_cookie"], info["alice_csrf"])
        assert ra2.status_code in (200, 201)
        rp2 = _publish(c, info["base_url"], pid2,
                        info["carol_cookie"], info["carol_csrf"])
        _g1_gate(rp2)
        assert rp2.status_code == 201


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M3T4Pending)
def test_publish_first_bundle_needs_two_even_if_not_loosened(t4_server):
    """Base 0, payload equal to deny-all with prod env, one approval:
    400 approvals_insufficient, nothing written."""
    import httpx
    info = t4_server
    with httpx.Client(base_url=info["base_url"], timeout=30) as c:
        proj = str(uuid.uuid4())
        conninfo = _conninfo(info["owner_url"])
        with psycopg.connect(conninfo, autocommit=True) as conn:
            conn.execute("SELECT set_config('app.org_id', %s, false)",
                         [info["org_id"]])
            create_project(conn, info["org_id"], proj, "T4 First 2",
                           environment="prod")

        bundle = {
            "folder_policy": {"shell": {"blocklist_action": "deny"}},
            "governance_policy": {"clauses": []},
            "mcp_policy": {"servers": []},
            "approval": {"local_fallback": False, "allow_requester": False},
        }
        r = _propose(c, info["base_url"], proj, bundle,
                     info["carol_cookie"], info["carol_csrf"])
        assert r.status_code in (200, 201)
        rj = r.json()
        pid = rj.get("id") or rj.get("proposal_id")
        bh = rj.get("hash") or rj.get("bundle_hash")
        # Verify the proposal is not loosened
        loosened = rj.get("loosened", {})
        assert loosened == {} or loosened is None or not loosened, (
            f"expected no loosening with prod env, got {loosened}")

        ra = _approve(c, info["base_url"], pid,
                      _sign_approval(info["alice_sk"], bh),
                      info["alice_cookie"], info["alice_csrf"])
        assert ra.status_code in (200, 201)

        before = _counts(info["owner_url"], info["org_id"], proj)
        rp = _publish(c, info["base_url"], pid,
                      info["bob_cookie"], info["bob_csrf"])
        _g1_gate(rp)
        assert rp.status_code == 400
        assert rp.json().get("error") == "approvals_insufficient"
        _assert_nothing_written(info["owner_url"], info["org_id"], proj,
                                 pid, "approvals_insufficient", before)


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M3T4Pending)
def test_publish_single_approval_loosening_refused_nothing_written(t4_server):
    """Loosening after a server row, one approval: 400 approvals_insufficient,
    nothing written."""
    import httpx
    info = t4_server
    with httpx.Client(base_url=info["base_url"], timeout=30) as c:
        proj = str(uuid.uuid4())
        conninfo = _conninfo(info["owner_url"])
        with psycopg.connect(conninfo, autocommit=True) as conn:
            conn.execute("SELECT set_config('app.org_id', %s, false)",
                         [info["org_id"]])
            create_project(conn, info["org_id"], proj, "T4 Single Loose")

        # First bundle (deny-all base, needs 2)
        bundle1 = {
            "folder_policy": {"shell": {"blocklist_action": "deny"}},
            "governance_policy": {"clauses": []},
            "mcp_policy": {"servers": []},
            "approval": {"local_fallback": False, "allow_requester": False},
        }
        r1 = _propose(c, info["base_url"], proj, bundle1,
                       info["carol_cookie"], info["carol_csrf"])
        assert r1.status_code in (200, 201)
        pid1 = r1.json().get("id") or r1.json().get("proposal_id")
        bh1 = r1.json().get("hash") or r1.json().get("bundle_hash")
        _approve(c, info["base_url"], pid1,
                 _sign_approval(info["alice_sk"], bh1),
                 info["alice_cookie"], info["alice_csrf"])
        _approve(c, info["base_url"], pid1,
                 _sign_approval(info["bob_sk"], bh1),
                 info["bob_cookie"], info["bob_csrf"])
        rp1 = _publish(c, info["base_url"], pid1,
                        info["carol_cookie"], info["carol_csrf"])
        _g1_gate(rp1)
        assert rp1.status_code == 201

        # Loosening with 1 approval
        bundle2 = {
            "folder_policy": {"shell": {"blocklist_action": "allow"}},
            "governance_policy": {"clauses": []},
            "mcp_policy": {"servers": []},
            "approval": {"local_fallback": True, "allow_requester": True},
        }
        r2 = _propose(c, info["base_url"], proj, bundle2,
                       info["carol_cookie"], info["carol_csrf"])
        assert r2.status_code in (200, 201)
        pid2 = r2.json().get("id") or r2.json().get("proposal_id")
        bh2 = r2.json().get("hash") or r2.json().get("bundle_hash")
        _approve(c, info["base_url"], pid2,
                 _sign_approval(info["alice_sk"], bh2),
                 info["alice_cookie"], info["alice_csrf"])

        before = _counts(info["owner_url"], info["org_id"], proj)
        rp2 = _publish(c, info["base_url"], pid2,
                        info["bob_cookie"], info["bob_csrf"])
        _g1_gate(rp2)
        assert rp2.status_code == 400
        assert rp2.json().get("error") == "approvals_insufficient"
        _assert_nothing_written(info["owner_url"], info["org_id"], proj,
                                 pid2, "approvals_insufficient", before)


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M3T4Pending)
def test_publish_forged_approval_refused_nothing_written(t4_server):
    """Alice valid + owner-inserted bob row with wrong hash sig: 400,
    nothing written."""
    import httpx
    info = t4_server
    with httpx.Client(base_url=info["base_url"], timeout=30) as c:
        proj = str(uuid.uuid4())
        conninfo = _conninfo(info["owner_url"])
        with psycopg.connect(conninfo, autocommit=True) as conn:
            conn.execute("SELECT set_config('app.org_id', %s, false)",
                         [info["org_id"]])
            create_project(conn, info["org_id"], proj, "T4 Forged")
        bundle = {
            "folder_policy": {"shell": {"blocklist_action": "escalate"}},
            "governance_policy": {"clauses": []},
            "mcp_policy": {"servers": []},
            "approval": {"local_fallback": True, "allow_requester": False},
        }
        r = _propose(c, info["base_url"], proj, bundle,
                     info["carol_cookie"], info["carol_csrf"])
        assert r.status_code in (200, 201)
        pid = r.json().get("id") or r.json().get("proposal_id")
        bh = r.json().get("hash") or r.json().get("bundle_hash")
        # alice approves correctly
        ra = _approve(c, info["base_url"], pid,
                      _sign_approval(info["alice_sk"], bh),
                      info["alice_cookie"], info["alice_csrf"])
        assert ra.status_code in (200, 201)
        # owner-insert a forged bob approval (signs a different hash)
        forged = _sign_approval(info["bob_sk"], "0" * 64)
        with psycopg.connect(conninfo, autocommit=True) as conn:
            conn.execute("SELECT set_config('app.org_id', %s, false)",
                         [info["org_id"]])
            conn.execute(
                "INSERT INTO policy_change_approvals "
                "(id, org_id, change_request_id, key_id, user_id, "
                "signature, signed_at, created_at) "
                "VALUES (%s, %s::uuid, %s::uuid, %s, %s::uuid, %s, "
                "now(), now())",
                [str(uuid.uuid4()), info["org_id"], pid,
                 _kid(info["bob_sk"]), info["bob_id"],
                 json.dumps(forged)],
            )
        before = _counts(info["owner_url"], info["org_id"], proj)
        rp = _publish(c, info["base_url"], pid,
                      info["dave_cookie"], info["dave_csrf"])
        _g1_gate(rp)
        assert rp.status_code == 400
        assert rp.json().get("error") == "approvals_insufficient"
        _assert_nothing_written(info["owner_url"], info["org_id"], proj,
                                 pid, "approvals_insufficient", before)


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M3T4Pending)
def test_publish_proposer_resolved_from_registry_refused(t4_server):
    """Owner-inserted approval with carol's (proposer) key, stored user_id=dave:
    400 proposer_in_approvals."""
    import httpx
    info = t4_server
    with httpx.Client(base_url=info["base_url"], timeout=30) as c:
        proj = str(uuid.uuid4())
        conninfo = _conninfo(info["owner_url"])
        with psycopg.connect(conninfo, autocommit=True) as conn:
            conn.execute("SELECT set_config('app.org_id', %s, false)",
                         [info["org_id"]])
            create_project(conn, info["org_id"], proj, "T4 ProposerRes")
        bundle = {
            "folder_policy": {}, "governance_policy": {},
            "mcp_policy": {},
            "approval": {"local_fallback": False, "allow_requester": False},
        }
        r = _propose(c, info["base_url"], proj, bundle,
                     info["carol_cookie"], info["carol_csrf"])
        assert r.status_code in (200, 201)
        pid = r.json().get("id") or r.json().get("proposal_id")
        bh = r.json().get("hash") or r.json().get("bundle_hash")
        # alice approves
        _approve(c, info["base_url"], pid,
                 _sign_approval(info["alice_sk"], bh),
                 info["alice_cookie"], info["alice_csrf"])
        # owner-insert carol's key approval with stored user_id=dave (MUST 4)
        carol_env = _sign_approval(info["carol_sk"], bh)
        with psycopg.connect(conninfo, autocommit=True) as conn:
            conn.execute("SELECT set_config('app.org_id', %s, false)",
                         [info["org_id"]])
            conn.execute(
                "INSERT INTO policy_change_approvals "
                "(id, org_id, change_request_id, key_id, user_id, "
                "signature, signed_at, created_at) "
                "VALUES (%s, %s::uuid, %s::uuid, %s, %s::uuid, %s, "
                "now(), now())",
                [str(uuid.uuid4()), info["org_id"], pid,
                 _kid(info["carol_sk"]), info["dave_id"],
                 json.dumps(carol_env)],
            )
        rp = _publish(c, info["base_url"], pid,
                      info["bob_cookie"], info["bob_csrf"])
        _g1_gate(rp)
        assert rp.status_code == 400
        assert rp.json().get("error") == "proposer_in_approvals"


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M3T4Pending)
def test_publish_publisher_resolved_from_registry_refused(t4_server):
    """Same shape with publisher's key, stored user_id=dave:
    400 publisher_in_approvals."""
    import httpx
    info = t4_server
    with httpx.Client(base_url=info["base_url"], timeout=30) as c:
        proj = str(uuid.uuid4())
        conninfo = _conninfo(info["owner_url"])
        with psycopg.connect(conninfo, autocommit=True) as conn:
            conn.execute("SELECT set_config('app.org_id', %s, false)",
                         [info["org_id"]])
            create_project(conn, info["org_id"], proj, "T4 PublisherRes")
        bundle = {
            "folder_policy": {}, "governance_policy": {},
            "mcp_policy": {},
            "approval": {"local_fallback": False, "allow_requester": False},
        }
        # carol proposes
        r = _propose(c, info["base_url"], proj, bundle,
                     info["carol_cookie"], info["carol_csrf"])
        assert r.status_code in (200, 201)
        pid = r.json().get("id") or r.json().get("proposal_id")
        bh = r.json().get("hash") or r.json().get("bundle_hash")
        # alice approves
        _approve(c, info["base_url"], pid,
                 _sign_approval(info["alice_sk"], bh),
                 info["alice_cookie"], info["alice_csrf"])
        # owner-insert bob's (publisher) key approval with stored
        # user_id=dave (MUST 4)
        bob_env = _sign_approval(info["bob_sk"], bh)
        with psycopg.connect(conninfo, autocommit=True) as conn:
            conn.execute("SELECT set_config('app.org_id', %s, false)",
                         [info["org_id"]])
            conn.execute(
                "INSERT INTO policy_change_approvals "
                "(id, org_id, change_request_id, key_id, user_id, "
                "signature, signed_at, created_at) "
                "VALUES (%s, %s::uuid, %s::uuid, %s, %s::uuid, %s, "
                "now(), now())",
                [str(uuid.uuid4()), info["org_id"], pid,
                 _kid(info["bob_sk"]), info["dave_id"],
                 json.dumps(bob_env)],
            )
        # bob publishes (bob is the publisher)
        rp = _publish(c, info["base_url"], pid,
                      info["bob_cookie"], info["bob_csrf"])
        _g1_gate(rp)
        assert rp.status_code == 400
        assert rp.json().get("error") == "publisher_in_approvals"


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M3T4Pending)
def test_publish_wrong_registry_approval_refused(t4_server):
    """MUST 3: own org; registry v2 drops bob's key; carol proposes under v2;
    alice approves through the route; bob's valid signature owner-inserted
    with user_id bob; bob's approver_keys.revoked_at set back to NULL so a
    projection-reading mutant gets 201. Publish: 400 approvals_insufficient,
    nothing written."""
    import httpx
    info = t4_server

    # Create own org with fresh keys (key_id cross-org check)
    own_alice_sk = SigningKey.generate()
    own_bob_sk = SigningKey.generate()
    own_carol_sk = SigningKey.generate()
    own_alice_id = str(uuid.uuid4())
    own_bob_id = str(uuid.uuid4())
    own_carol_id = str(uuid.uuid4())

    conninfo = _conninfo(info["owner_url"])
    org_id = str(uuid.uuid4())
    with psycopg.connect(conninfo, autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        create_org(conn, org_id, f"WrongReg {org_id[:8]}")
        for uid, email in [(own_alice_id, "wa@wr.test"),
                           (own_bob_id, "wb@wr.test"),
                           (own_carol_id, "wc@wr.test")]:
            conn.execute(
                "INSERT INTO users (id, org_id, oidc_issuer, oidc_subject, "
                "email, status, created_at) "
                "VALUES (%s, %s, 'https://idp.test', %s, %s, "
                "'active', now()) ON CONFLICT DO NOTHING",
                [uid, org_id, f"sub-{uuid.uuid4().hex[:8]}", email],
            )
            _bind_admin(conn, org_id, uid)
        proj = str(uuid.uuid4())
        create_project(conn, org_id, proj, "WR Proj")

    # v1: alice, bob, carol all have cli keys
    v1_entries = [
        _make_key_entry(own_alice_sk, own_alice_id, "cli",
                        ["admin", "approver"]),
        _make_key_entry(own_bob_sk, own_bob_id, "cli",
                        ["admin", "approver"]),
        _make_key_entry(own_carol_sk, own_carol_id, "cli",
                        ["admin", "approver"]),
    ]
    chain_v1, fp = _build_registry_chain(
        org_id, info["bundle_signer_sk"], v1_entries,
        [own_alice_sk, own_bob_sk], threshold=2,
    )
    _store_chain(info["owner_url"], org_id, chain_v1)

    # v2: drop bob's key, keep alice and carol
    v2_entries = [
        _make_key_entry(own_alice_sk, own_alice_id, "cli",
                        ["admin", "approver"], added_in=1),
        _make_key_entry(own_carol_sk, own_carol_id, "cli",
                        ["admin", "approver"], added_in=1),
    ]
    bs_pub = bytes(info["bundle_signer_sk"].verify_key)
    bs_kid = hashlib.sha256(bs_pub).hexdigest()
    admin_kids_v2 = [_kid(own_alice_sk), _kid(own_carol_sk)]
    v2_payload = {
        "org_id": org_id,
        "version": 2,
        "prev_hash": fp,
        "threshold": 2,
        "admins": admin_kids_v2,
        "keys": v2_entries,
        "bundle_signer": {
            "key_id": bs_kid,
            "public_key": bs_pub.hex(),
            "alg": "ed25519",
        },
        "expires_at": time.time() + 7 * 86400,
    }
    # v2 is signed by both prev admins (alice, bob) and new admins (alice, carol)
    # We need sigs from at least threshold prev admins AND threshold new admins
    v2_env = _sign_envelope_multi("agg/registry/v1", v2_payload,
                                   [own_alice_sk, own_bob_sk, own_carol_sk])
    from agg_cp.sync.registry import store_registry_version
    with psycopg.connect(conninfo) as conn:
        store_registry_version(conn, org_id, v2_env)

    # Restore bob's approver_keys.revoked_at to NULL so a projection-reading
    # mutant would see bob as live
    bob_kid = _kid(own_bob_sk)
    with psycopg.connect(conninfo, autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        conn.execute(
            "UPDATE approver_keys SET revoked_at = NULL "
            "WHERE org_id = %s::uuid AND key_id = %s",
            [org_id, bob_kid],
        )

    # Create sessions
    clock = FakeClock()
    a_cookie, a_csrf, _ = _make_fresh_session(
        info["owner_url"], org_id, own_alice_id, clock=clock)
    b_cookie, b_csrf, _ = _make_fresh_session(
        info["owner_url"], org_id, own_bob_id, clock=clock)
    c_cookie, c_csrf, _ = _make_fresh_session(
        info["owner_url"], org_id, own_carol_id, clock=clock)

    with httpx.Client(base_url=info["base_url"], timeout=30) as cl:
        bundle = {
            "folder_policy": {"shell": {"blocklist_action": "escalate"}},
            "governance_policy": {"clauses": []},
            "mcp_policy": {"servers": []},
            "approval": {"local_fallback": True, "allow_requester": False},
        }
        # carol proposes under v2
        r = _propose(cl, info["base_url"], proj, bundle, c_cookie, c_csrf)
        assert r.status_code in (200, 201), (
            f"propose: {r.status_code} {r.text[:200]}")
        rj = r.json()
        pid = rj.get("id") or rj.get("proposal_id")
        bh = rj.get("hash") or rj.get("bundle_hash")
        assert rj.get("registry_version", 0) == 2, (
            f"expected registry_version 2, got {rj.get('registry_version')}")

        # alice approves through the route
        ra = _approve(cl, info["base_url"], pid,
                      _sign_approval(own_alice_sk, bh), a_cookie, a_csrf)
        assert ra.status_code in (200, 201), (
            f"approve alice: {ra.status_code} {ra.text[:200]}")

        # owner-insert bob's valid signature with user_id bob
        bob_env = _sign_approval(own_bob_sk, bh)
        with psycopg.connect(conninfo, autocommit=True) as conn:
            conn.execute("SELECT set_config('app.org_id', %s, false)",
                         [org_id])
            conn.execute(
                "INSERT INTO policy_change_approvals "
                "(id, org_id, change_request_id, key_id, user_id, "
                "signature, signed_at, created_at) "
                "VALUES (%s, %s::uuid, %s::uuid, %s, %s::uuid, %s, "
                "now(), now())",
                [str(uuid.uuid4()), org_id, pid, bob_kid,
                 own_bob_id, json.dumps(bob_env)],
            )

        before = _counts(info["owner_url"], org_id, proj)
        # carol publishes
        rp = _publish(cl, info["base_url"], pid, c_cookie, c_csrf)
        _g1_gate(rp)
        assert rp.status_code == 400
        assert rp.json().get("error") == "approvals_insufficient"
        _assert_nothing_written(info["owner_url"], org_id, proj, pid,
                                 "approvals_insufficient", before)


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M3T4Pending)
def test_publish_counts_for_dual_only_when_two_needed(t4_server, tmp_path):
    """Single-admin org: a loosening with two distinct users' valid approvals
    is 400 approvals_insufficient with dual_filter true; in the same node,
    verify_and_apply with that registry and those approvals accepts
    (server stricter, T0b-7)."""
    import httpx
    info = t4_server

    org_id = info["single_org_id"]
    # Create a fresh project with prod environment for the single-admin org
    conninfo = _conninfo(info["owner_url"])
    proj = str(uuid.uuid4())
    with psycopg.connect(conninfo, autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        create_project(conn, org_id, proj, "DualFilter",
                        environment="prod")

    with httpx.Client(base_url=info["base_url"], timeout=30) as c:
        # Loosening bundle
        bundle = {
            "folder_policy": {"shell": {"blocklist_action": "allow"}},
            "governance_policy": {"clauses": []},
            "mcp_policy": {"servers": []},
            "approval": {"local_fallback": True, "allow_requester": True},
        }
        # spub proposes (not an approver key holder)
        r = _propose(c, info["base_url"], proj, bundle,
                     info["spub_cookie"], info["spub_csrf"])
        assert r.status_code in (200, 201), (
            f"propose: {r.status_code} {r.text[:200]}")
        pid = r.json().get("id") or r.json().get("proposal_id")
        bh = r.json().get("hash") or r.json().get("bundle_hash")

        # sadmin and suser2 approve through the route
        ra1 = _approve(c, info["base_url"], pid,
                       _sign_approval(info["single_admin_sk"], bh),
                       info["sadmin_cookie"], info["sadmin_csrf"])
        assert ra1.status_code in (200, 201), (
            f"approve sadmin: {ra1.status_code} {ra1.text[:200]}")
        ra2 = _approve(c, info["base_url"], pid,
                       _sign_approval(info["single_user2_sk"], bh),
                       info["suser2_cookie"], info["suser2_csrf"])
        assert ra2.status_code in (200, 201), (
            f"approve suser2: {ra2.status_code} {ra2.text[:200]}")

        before = _counts(info["owner_url"], org_id, proj)
        # spub publishes (not an approver, no publisher_in_approvals)
        rp = _publish(c, info["base_url"], pid,
                      info["spub_cookie"], info["spub_csrf"])
        _g1_gate(rp)
        assert rp.status_code == 400
        assert rp.json().get("error") == "approvals_insufficient"
        detail = rp.json().get("detail", "")
        assert "dual_filter" in str(detail), (
            f"expected dual_filter in detail: {detail}")
        _assert_nothing_written(info["owner_url"], org_id, proj, pid,
                                 "approvals_insufficient", before)

    # verify_and_apply with that registry and those approvals accepts
    from sandbox.protocol.registry import verify_chain
    from sandbox.connector.sync.bundles import verify_and_apply
    from sandbox.connector.sync.process import _bundle_signer_pub
    from sandbox.connector.layout import FolderLayout

    with psycopg.connect(conninfo) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        chain_rows = conn.execute(
            "SELECT registry_blob FROM key_registry_versions "
            "WHERE org_id = %s::uuid ORDER BY version",
            [org_id],
        ).fetchall()
    stored_chain = [json.loads(bytes(r[0])) for r in chain_rows]
    genesis_payload = stored_chain[0]["payload"]
    fp = _payload_hash(genesis_payload)
    reg = verify_chain(stored_chain, fp)
    bsp = _bundle_signer_pub(reg)

    # Build a test bundle signed by the bundle signer
    from sandbox.connector.sync.bundles import _bundle_hash
    test_payload = {
        "org_id": org_id,
        "project_id": proj,
        "base_sequence": 0,
        "sequence": 1,
        "registry_version": 1,
        "issued_at": int(time.time()),
        "not_before": int(time.time()),
        "folder_policy": {"shell": {"blocklist_action": "allow"}},
        "governance_policy": {"clauses": []},
        "mcp_policy": {"servers": []},
        "approval": {"local_fallback": True, "allow_requester": True},
    }
    test_env = _make_bundle_envelope(test_payload, info["bundle_signer_sk"])
    # Build approvals
    test_bh = _bundle_hash(test_payload)
    approvals = [
        _sign_approval(info["single_admin_sk"], test_bh),
        _sign_approval(info["single_user2_sk"], test_bh),
    ]

    ws = tmp_path / "dual_layout"
    ws.mkdir()
    sb = ws / ".sandbox"
    sb.mkdir()
    (sb / "state" / "sync").mkdir(parents=True)
    layout = FolderLayout(ws)
    result = verify_and_apply(
        layout, test_env, reg, bsp, approvals,
        org_id=org_id, project_id=proj,
    )
    assert result is not None, "connector should accept with single-admin registry"


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M3T4Pending)
def test_publish_single_admin_key_tightening_201(t4_server):
    """Single-admin org, owner-inserted server row 1, a tightening with one
    approval: 201."""
    import httpx
    info = t4_server

    org_id = info["single_org_id"]
    conninfo = _conninfo(info["owner_url"])

    # Create a fresh project in the single-admin org
    proj = str(uuid.uuid4())
    with psycopg.connect(conninfo, autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        create_project(conn, org_id, proj, "SingleTight",
                        environment="prod")

    # Owner-insert a server row 1 (permissive)
    perm_payload = {
        "org_id": org_id,
        "project_id": proj,
        "base_sequence": 0,
        "sequence": 1,
        "registry_version": 1,
        "issued_at": int(time.time()),
        "not_before": int(time.time()),
        "folder_policy": {"shell": {"blocklist_action": "allow"}},
        "governance_policy": {"clauses": []},
        "mcp_policy": {"servers": []},
        "approval": {"local_fallback": True, "allow_requester": True},
    }
    with psycopg.connect(conninfo, autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        _owner_insert_bundle(conn, org_id, proj, 1,
                              info["bundle_signer_sk"], perm_payload,
                              verification="server")

    with httpx.Client(base_url=info["base_url"], timeout=30) as c:
        # Tightening at base 1
        bundle = {
            "folder_policy": {"shell": {"blocklist_action": "deny"}},
            "governance_policy": {"clauses": []},
            "mcp_policy": {"servers": []},
            "approval": {"local_fallback": False, "allow_requester": False},
        }
        r = _propose(c, info["base_url"], proj, bundle,
                     info["sadmin_cookie"], info["sadmin_csrf"])
        assert r.status_code in (200, 201), (
            f"propose: {r.status_code} {r.text[:200]}")
        pid = r.json().get("id") or r.json().get("proposal_id")
        bh = r.json().get("hash") or r.json().get("bundle_hash")

        ra = _approve(c, info["base_url"], pid,
                      _sign_approval(info["single_user2_sk"], bh),
                      info["suser2_cookie"], info["suser2_csrf"])
        assert ra.status_code in (200, 201)

        rp = _publish(c, info["base_url"], pid,
                      info["sadmin_cookie"], info["sadmin_csrf"])
        _g1_gate(rp)
        assert rp.status_code == 201


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M3T4Pending)
def test_publish_head_m2_row_loosening_needs_two(t4_server):
    """server row 1 permissive, m2_unverified row 2 strict, proposal at
    base 2 loosens vs row 2: one approval 400, two approvals 201."""
    import httpx
    info = t4_server

    proj = str(uuid.uuid4())
    conninfo = _conninfo(info["owner_url"])
    with psycopg.connect(conninfo, autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [info["org_id"]])
        create_project(conn, info["org_id"], proj, "HeadM2",
                        environment="prod")

    # Owner-insert server row 1 (permissive)
    perm_payload = {
        "org_id": info["org_id"], "project_id": proj,
        "base_sequence": 0, "sequence": 1, "registry_version": 1,
        "issued_at": int(time.time()), "not_before": int(time.time()),
        "folder_policy": {"shell": {"blocklist_action": "allow"}},
        "governance_policy": {"clauses": []}, "mcp_policy": {"servers": []},
        "approval": {"local_fallback": True, "allow_requester": True},
    }
    # Owner-insert m2_unverified row 2 (strict)
    strict_payload = {
        "org_id": info["org_id"], "project_id": proj,
        "base_sequence": 1, "sequence": 2, "registry_version": 1,
        "issued_at": int(time.time()), "not_before": int(time.time()),
        "folder_policy": {"shell": {"blocklist_action": "deny"}},
        "governance_policy": {"clauses": []}, "mcp_policy": {"servers": []},
        "approval": {"local_fallback": False, "allow_requester": False},
    }
    with psycopg.connect(conninfo, autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [info["org_id"]])
        _owner_insert_bundle(conn, info["org_id"], proj, 1,
                              info["bundle_signer_sk"], perm_payload,
                              verification="server")
        _owner_insert_bundle(conn, info["org_id"], proj, 2,
                              info["bundle_signer_sk"], strict_payload)

    with httpx.Client(base_url=info["base_url"], timeout=30) as c:
        # Proposal at base 2, loosens vs row 2 (permissive vs strict)
        bundle = {
            "folder_policy": {"shell": {"blocklist_action": "allow"}},
            "governance_policy": {"clauses": []},
            "mcp_policy": {"servers": []},
            "approval": {"local_fallback": True, "allow_requester": True},
        }
        r = _propose(c, info["base_url"], proj, bundle,
                     info["carol_cookie"], info["carol_csrf"])
        assert r.status_code in (200, 201)
        pid = r.json().get("id") or r.json().get("proposal_id")
        bh = r.json().get("hash") or r.json().get("bundle_hash")

        # One approval should be insufficient (loosening vs row 2)
        _approve(c, info["base_url"], pid,
                 _sign_approval(info["alice_sk"], bh),
                 info["alice_cookie"], info["alice_csrf"])
        rp1 = _publish(c, info["base_url"], pid,
                        info["dave_cookie"], info["dave_csrf"])
        _g1_gate(rp1)
        assert rp1.status_code == 400
        assert rp1.json().get("error") == "approvals_insufficient"

        # Add second approval and re-publish (need a fresh proposal)
        r2 = _propose(c, info["base_url"], proj, bundle,
                      info["carol_cookie"], info["carol_csrf"])
        assert r2.status_code in (200, 201)
        pid2 = r2.json().get("id") or r2.json().get("proposal_id")
        bh2 = r2.json().get("hash") or r2.json().get("bundle_hash")
        _approve(c, info["base_url"], pid2,
                 _sign_approval(info["alice_sk"], bh2),
                 info["alice_cookie"], info["alice_csrf"])
        _approve(c, info["base_url"], pid2,
                 _sign_approval(info["bob_sk"], bh2),
                 info["bob_cookie"], info["bob_csrf"])
        rp2 = _publish(c, info["base_url"], pid2,
                        info["dave_cookie"], info["dave_csrf"])
        _g1_gate(rp2)
        assert rp2.status_code == 201


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M3T4Pending)
def test_publish_loosened_against_server_base_only_needs_two(t4_server):
    """MUST 2: server row 1 strict; m2_unverified row 2 permissive;
    proposal at base 2 equal to row 2's sections.
    One approval: 400 and nothing written; two: 201."""
    import httpx
    info = t4_server

    proj = str(uuid.uuid4())
    conninfo = _conninfo(info["owner_url"])
    with psycopg.connect(conninfo, autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [info["org_id"]])
        create_project(conn, info["org_id"], proj, "M2Base",
                        environment="prod")

    # server row 1 (strict)
    strict_payload = {
        "org_id": info["org_id"], "project_id": proj,
        "base_sequence": 0, "sequence": 1, "registry_version": 1,
        "issued_at": int(time.time()), "not_before": int(time.time()),
        "folder_policy": {"shell": {"blocklist_action": "deny"}},
        "governance_policy": {"clauses": []}, "mcp_policy": {"servers": []},
        "approval": {"local_fallback": False, "allow_requester": False},
    }
    # m2_unverified row 2 (permissive) with two valid approvals
    perm_payload = {
        "org_id": info["org_id"], "project_id": proj,
        "base_sequence": 1, "sequence": 2, "registry_version": 1,
        "issued_at": int(time.time()), "not_before": int(time.time()),
        "folder_policy": {"shell": {"blocklist_action": "allow"}},
        "governance_policy": {"clauses": []}, "mcp_policy": {"servers": []},
        "approval": {"local_fallback": True, "allow_requester": True},
    }
    with psycopg.connect(conninfo, autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [info["org_id"]])
        _owner_insert_bundle(conn, info["org_id"], proj, 1,
                              info["bundle_signer_sk"], strict_payload,
                              verification="server")
        bid2 = _owner_insert_bundle(conn, info["org_id"], proj, 2,
                                     info["bundle_signer_sk"], perm_payload)
        # Insert two valid approvals for the m2 row (owner-inserted)
        from sandbox.connector.sync.bundles import _bundle_hash
        perm_bh = _bundle_hash(perm_payload)
        for sk, uid in [(info["alice_sk"], info["alice_id"]),
                        (info["bob_sk"], info["bob_id"])]:
            env = _sign_approval(sk, perm_bh)
            conn.execute(
                "INSERT INTO policy_change_approvals "
                "(id, org_id, change_request_id, key_id, user_id, "
                "signature, signed_at, created_at) "
                "VALUES (%s, %s::uuid, %s::uuid, %s, %s::uuid, %s, "
                "now(), now())",
                [str(uuid.uuid4()), info["org_id"], bid2,
                 _kid(sk), uid, json.dumps(env)],
            )

    with httpx.Client(base_url=info["base_url"], timeout=30) as c:
        # Proposal at base 2 equal to row 2's sections
        bundle = {
            "folder_policy": {"shell": {"blocklist_action": "allow"}},
            "governance_policy": {"clauses": []},
            "mcp_policy": {"servers": []},
            "approval": {"local_fallback": True, "allow_requester": True},
        }
        r = _propose(c, info["base_url"], proj, bundle,
                     info["carol_cookie"], info["carol_csrf"])
        assert r.status_code in (200, 201)
        pid = r.json().get("id") or r.json().get("proposal_id")
        bh = r.json().get("hash") or r.json().get("bundle_hash")

        # One approval
        _approve(c, info["base_url"], pid,
                 _sign_approval(info["alice_sk"], bh),
                 info["alice_cookie"], info["alice_csrf"])
        before = _counts(info["owner_url"], info["org_id"], proj)
        rp1 = _publish(c, info["base_url"], pid,
                        info["dave_cookie"], info["dave_csrf"])
        _g1_gate(rp1)
        assert rp1.status_code == 400
        assert rp1.json().get("error") == "approvals_insufficient"
        _assert_nothing_written(info["owner_url"], info["org_id"], proj,
                                 pid, "approvals_insufficient", before)

        # Fresh proposal with two approvals
        r2 = _propose(c, info["base_url"], proj, bundle,
                      info["carol_cookie"], info["carol_csrf"])
        assert r2.status_code in (200, 201)
        pid2 = r2.json().get("id") or r2.json().get("proposal_id")
        bh2 = r2.json().get("hash") or r2.json().get("bundle_hash")
        _approve(c, info["base_url"], pid2,
                 _sign_approval(info["alice_sk"], bh2),
                 info["alice_cookie"], info["alice_csrf"])
        _approve(c, info["base_url"], pid2,
                 _sign_approval(info["bob_sk"], bh2),
                 info["bob_cookie"], info["bob_csrf"])
        rp2 = _publish(c, info["base_url"], pid2,
                        info["dave_cookie"], info["dave_csrf"])
        _g1_gate(rp2)
        assert rp2.status_code == 201


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M3T4Pending)
def test_publish_first_server_row_after_m2_rows_needs_two(t4_server):
    """Only m2_unverified row 1 (prod, equal to deny-all); tightening at
    base 1 with 1 approval: 400 approvals_insufficient."""
    import httpx
    info = t4_server

    proj = str(uuid.uuid4())
    conninfo = _conninfo(info["owner_url"])
    with psycopg.connect(conninfo, autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [info["org_id"]])
        create_project(conn, info["org_id"], proj, "FirstServer",
                        environment="prod")

    # Owner-insert m2_unverified row 1 equal to deny-all
    deny_all_payload = {
        "org_id": info["org_id"], "project_id": proj,
        "base_sequence": 0, "sequence": 1, "registry_version": 1,
        "issued_at": int(time.time()), "not_before": int(time.time()),
        "folder_policy": {"shell": {"blocklist_action": "deny"}},
        "governance_policy": {"clauses": []}, "mcp_policy": {"servers": []},
        "approval": {"local_fallback": False, "allow_requester": False},
    }
    with psycopg.connect(conninfo, autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [info["org_id"]])
        _owner_insert_bundle(conn, info["org_id"], proj, 1,
                              info["bundle_signer_sk"], deny_all_payload)

    with httpx.Client(base_url=info["base_url"], timeout=30) as c:
        # Tightening at base 1 (same as deny-all, but first server row)
        bundle = {
            "folder_policy": {"shell": {"blocklist_action": "deny"}},
            "governance_policy": {"clauses": []},
            "mcp_policy": {"servers": []},
            "approval": {"local_fallback": False, "allow_requester": False},
        }
        r = _propose(c, info["base_url"], proj, bundle,
                     info["carol_cookie"], info["carol_csrf"])
        assert r.status_code in (200, 201)
        pid = r.json().get("id") or r.json().get("proposal_id")
        bh = r.json().get("hash") or r.json().get("bundle_hash")

        ra = _approve(c, info["base_url"], pid,
                      _sign_approval(info["alice_sk"], bh),
                      info["alice_cookie"], info["alice_csrf"])
        assert ra.status_code in (200, 201)

        rp = _publish(c, info["base_url"], pid,
                      info["bob_cookie"], info["bob_csrf"])
        _g1_gate(rp)
        assert rp.status_code == 400
        assert rp.json().get("error") == "approvals_insufficient"


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M3T4Pending)
def test_publish_copies_only_counted_approvals(t4_server):
    """MUST 1: own org; v1 has eve, v2 drops her; carol proposes under v2;
    alice and bob approve through the route; owner-insert eve's valid signature.
    Publish 201. Served approvals, DB rows and audit approver_user_ids
    equal {alice, bob}; each copied signed_at equals the stored row's."""
    import httpx
    info = t4_server

    # Create own org with fresh keys
    own_alice_sk = SigningKey.generate()
    own_bob_sk = SigningKey.generate()
    own_carol_sk = SigningKey.generate()
    own_eve_sk = SigningKey.generate()
    own_alice_id = str(uuid.uuid4())
    own_bob_id = str(uuid.uuid4())
    own_carol_id = str(uuid.uuid4())
    own_eve_id = str(uuid.uuid4())

    conninfo = _conninfo(info["owner_url"])
    org_id = str(uuid.uuid4())
    with psycopg.connect(conninfo, autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        create_org(conn, org_id, f"Counted {org_id[:8]}")
        for uid, email in [(own_alice_id, "ca@cnt.test"),
                           (own_bob_id, "cb@cnt.test"),
                           (own_carol_id, "cc@cnt.test"),
                           (own_eve_id, "ce@cnt.test")]:
            conn.execute(
                "INSERT INTO users (id, org_id, oidc_issuer, oidc_subject, "
                "email, status, created_at) "
                "VALUES (%s, %s, 'https://idp.test', %s, %s, "
                "'active', now()) ON CONFLICT DO NOTHING",
                [uid, org_id, f"sub-{uuid.uuid4().hex[:8]}", email],
            )
            _bind_admin(conn, org_id, uid)
        proj = str(uuid.uuid4())
        create_project(conn, org_id, proj, "CntProj")
        _seed_device(conn, org_id, proj)

    # v1 entries: alice, bob, carol, eve
    v1_entries = [
        _make_key_entry(own_alice_sk, own_alice_id, "cli",
                        ["admin", "approver"]),
        _make_key_entry(own_bob_sk, own_bob_id, "cli",
                        ["admin", "approver"]),
        _make_key_entry(own_carol_sk, own_carol_id, "cli",
                        ["admin", "approver"]),
        _make_key_entry(own_eve_sk, own_eve_id, "cli",
                        ["admin", "approver"]),
    ]
    chain_v1, fp = _build_registry_chain(
        org_id, info["bundle_signer_sk"], v1_entries,
        [own_alice_sk, own_bob_sk], threshold=2,
    )
    _store_chain(info["owner_url"], org_id, chain_v1)

    # v2: drop eve
    v2_entries = [
        _make_key_entry(own_alice_sk, own_alice_id, "cli",
                        ["admin", "approver"], added_in=1),
        _make_key_entry(own_bob_sk, own_bob_id, "cli",
                        ["admin", "approver"], added_in=1),
        _make_key_entry(own_carol_sk, own_carol_id, "cli",
                        ["admin", "approver"], added_in=1),
    ]
    bs_pub = bytes(info["bundle_signer_sk"].verify_key)
    bs_kid = hashlib.sha256(bs_pub).hexdigest()
    admin_kids_v2 = [_kid(own_alice_sk), _kid(own_bob_sk)]
    v2_payload = {
        "org_id": org_id, "version": 2, "prev_hash": fp,
        "threshold": 2, "admins": admin_kids_v2,
        "keys": v2_entries,
        "bundle_signer": {
            "key_id": bs_kid, "public_key": bs_pub.hex(),
            "alg": "ed25519",
        },
        "expires_at": time.time() + 7 * 86400,
    }
    v2_env = _sign_envelope_multi("agg/registry/v1", v2_payload,
                                   [own_alice_sk, own_bob_sk])
    from agg_cp.sync.registry import store_registry_version
    with psycopg.connect(conninfo) as conn:
        store_registry_version(conn, org_id, v2_env)

    # Keep eve's projection row live
    with psycopg.connect(conninfo, autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        conn.execute(
            "UPDATE approver_keys SET revoked_at = NULL "
            "WHERE org_id = %s::uuid AND key_id = %s",
            [org_id, _kid(own_eve_sk)],
        )

    clock = FakeClock()
    a_cookie, a_csrf, _ = _make_fresh_session(
        info["owner_url"], org_id, own_alice_id, clock=clock)
    b_cookie, b_csrf, _ = _make_fresh_session(
        info["owner_url"], org_id, own_bob_id, clock=clock)
    c_cookie, c_csrf, _ = _make_fresh_session(
        info["owner_url"], org_id, own_carol_id, clock=clock)

    with httpx.Client(base_url=info["base_url"], timeout=30) as cl:
        bundle = {
            "folder_policy": {"shell": {"blocklist_action": "escalate"}},
            "governance_policy": {"clauses": []},
            "mcp_policy": {"servers": []},
            "approval": {"local_fallback": True, "allow_requester": False},
        }
        r = _propose(cl, info["base_url"], proj, bundle, c_cookie, c_csrf)
        assert r.status_code in (200, 201)
        rj = r.json()
        pid = rj.get("id") or rj.get("proposal_id")
        bh = rj.get("hash") or rj.get("bundle_hash")

        # alice and bob approve through the route
        ra = _approve(cl, info["base_url"], pid,
                      _sign_approval(own_alice_sk, bh), a_cookie, a_csrf)
        assert ra.status_code in (200, 201)
        rb = _approve(cl, info["base_url"], pid,
                      _sign_approval(own_bob_sk, bh), b_cookie, b_csrf)
        assert rb.status_code in (200, 201)

        # owner-insert eve's valid signature
        eve_env = _sign_approval(own_eve_sk, bh)
        with psycopg.connect(conninfo, autocommit=True) as conn:
            conn.execute("SELECT set_config('app.org_id', %s, false)",
                         [org_id])
            conn.execute(
                "INSERT INTO policy_change_approvals "
                "(id, org_id, change_request_id, key_id, user_id, "
                "signature, signed_at, created_at) "
                "VALUES (%s, %s::uuid, %s::uuid, %s, %s::uuid, %s, "
                "now(), now())",
                [str(uuid.uuid4()), org_id, pid, _kid(own_eve_sk),
                 own_eve_id, json.dumps(eve_env)],
            )

        rp = _publish(cl, info["base_url"], pid, c_cookie, c_csrf)
        _g1_gate(rp)
        assert rp.status_code == 201
        bundle_id = rp.json().get("bundle_id")

    # Seed a device so we can GET /sync/bundle
    with psycopg.connect(conninfo, autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        _, dev_token = _seed_device(conn, org_id, proj)

    # Check served approvals via GET /sync/bundle
    import httpx
    expected_kids = sorted([_kid(own_alice_sk), _kid(own_bob_sk)])
    with httpx.Client(base_url=info["base_url"], timeout=10) as cl2:
        rb2 = cl2.get(
            f"{info['base_url']}/api/v1/sync/bundle",
            params={"after": "0"},
            headers={"Authorization": f"Bearer {dev_token}"},
        )
        assert rb2.status_code == 200
        served_approvals = rb2.json().get("change_approvals", [])
        served_kids = sorted(
            a["signatures"][0]["key_id"]
            for a in served_approvals if a.get("signatures"))
        assert served_kids == expected_kids, (
            f"served approvals: {served_kids} != {expected_kids}")

    # Policy_change_approvals keyed to the bundle id
    with psycopg.connect(conninfo) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        rows = conn.execute(
            "SELECT key_id, signed_at FROM policy_change_approvals "
            "WHERE change_request_id = %s::uuid ORDER BY key_id",
            [bundle_id],
        ).fetchall()
    copied_kids = sorted(r[0] for r in rows)
    assert copied_kids == expected_kids, (
        f"copied approvals: {copied_kids} != {expected_kids}")

    # Verify signed_at of copied rows matches the proposal's stored rows
    with psycopg.connect(conninfo) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        for kid_val in expected_kids:
            proposal_sa = conn.execute(
                "SELECT signed_at FROM policy_change_approvals "
                "WHERE change_request_id = %s::uuid AND key_id = %s",
                [pid, kid_val],
            ).fetchone()
            bundle_sa = conn.execute(
                "SELECT signed_at FROM policy_change_approvals "
                "WHERE change_request_id = %s::uuid AND key_id = %s",
                [bundle_id, kid_val],
            ).fetchone()
            assert proposal_sa is not None and bundle_sa is not None
            assert proposal_sa[0] == bundle_sa[0], (
                f"signed_at mismatch for {kid_val}")

    # Audit row
    with psycopg.connect(conninfo) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        audit = conn.execute(
            "SELECT detail FROM admin_audit "
            "WHERE org_id = %s::uuid "
            "AND action = 'bundle_proposal.publish' "
            "AND detail->>'proposal_id' = %s",
            [org_id, pid],
        ).fetchone()
    assert audit is not None, "no publish audit row"
    detail = audit[0]  # jsonb returns dict
    approver_ids = detail.get("approver_user_ids", [])
    expected_uids = sorted([own_alice_id, own_bob_id])
    assert sorted(approver_ids) == expected_uids


@pytest.mark.pg
@pytest.mark.parametrize("variant", ["byte_flip", "invalid_json"],
                         ids=["byte_flip", "invalid_json"])
@pytest.mark.xfail(strict=True, raises=M3T4Pending)
def test_publish_registry_invalid_refused_and_audited(t4_server, variant):
    """MUST 6: own org; propose, approve twice, then tamper the stored
    registry version. Publish: 400 registry_invalid, never 500,
    nothing written."""
    import httpx
    info = t4_server

    # Own org with fresh keys
    own_alice_sk = SigningKey.generate()
    own_bob_sk = SigningKey.generate()
    own_carol_sk = SigningKey.generate()
    own_alice_id = str(uuid.uuid4())
    own_bob_id = str(uuid.uuid4())
    own_carol_id = str(uuid.uuid4())

    conninfo = _conninfo(info["owner_url"])
    org_id = str(uuid.uuid4())
    with psycopg.connect(conninfo, autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        create_org(conn, org_id, f"RegInv {org_id[:8]}")
        for uid, email in [(own_alice_id, "ra@ri.test"),
                           (own_bob_id, "rb@ri.test"),
                           (own_carol_id, "rc@ri.test")]:
            conn.execute(
                "INSERT INTO users (id, org_id, oidc_issuer, oidc_subject, "
                "email, status, created_at) "
                "VALUES (%s, %s, 'https://idp.test', %s, %s, "
                "'active', now()) ON CONFLICT DO NOTHING",
                [uid, org_id, f"sub-{uuid.uuid4().hex[:8]}", email],
            )
            _bind_admin(conn, org_id, uid)
        proj = str(uuid.uuid4())
        create_project(conn, org_id, proj, "RegInvProj")

    v1_entries = [
        _make_key_entry(own_alice_sk, own_alice_id, "cli",
                        ["admin", "approver"]),
        _make_key_entry(own_bob_sk, own_bob_id, "cli",
                        ["admin", "approver"]),
        _make_key_entry(own_carol_sk, own_carol_id, "cli",
                        ["admin", "approver"]),
    ]
    chain_v1, fp = _build_registry_chain(
        org_id, info["bundle_signer_sk"], v1_entries,
        [own_alice_sk, own_bob_sk], threshold=2,
    )
    _store_chain(info["owner_url"], org_id, chain_v1)

    clock = FakeClock()
    a_cookie, a_csrf, _ = _make_fresh_session(
        info["owner_url"], org_id, own_alice_id, clock=clock)
    b_cookie, b_csrf, _ = _make_fresh_session(
        info["owner_url"], org_id, own_bob_id, clock=clock)
    c_cookie, c_csrf, _ = _make_fresh_session(
        info["owner_url"], org_id, own_carol_id, clock=clock)

    with httpx.Client(base_url=info["base_url"], timeout=30) as cl:
        bundle = {
            "folder_policy": {"shell": {"blocklist_action": "escalate"}},
            "governance_policy": {"clauses": []},
            "mcp_policy": {"servers": []},
            "approval": {"local_fallback": True, "allow_requester": False},
        }
        r = _propose(cl, info["base_url"], proj, bundle, c_cookie, c_csrf)
        assert r.status_code in (200, 201)
        pid = r.json().get("id") or r.json().get("proposal_id")
        bh = r.json().get("hash") or r.json().get("bundle_hash")

        ra = _approve(cl, info["base_url"], pid,
                      _sign_approval(own_alice_sk, bh), a_cookie, a_csrf)
        assert ra.status_code in (200, 201)
        rb = _approve(cl, info["base_url"], pid,
                      _sign_approval(own_bob_sk, bh), b_cookie, b_csrf)
        assert rb.status_code in (200, 201)

        # Tamper the stored registry
        with psycopg.connect(conninfo, autocommit=True) as conn:
            conn.execute("SELECT set_config('app.org_id', %s, false)",
                         [org_id])
            if variant == "byte_flip":
                conn.execute(
                    "UPDATE key_registry_versions "
                    "SET registry_blob = overlay(registry_blob placing "
                    "E'\\\\x42'::bytea from 5 for 1) "
                    "WHERE org_id = %s::uuid AND version = 1",
                    [org_id],
                )
            else:  # invalid_json
                conn.execute(
                    "UPDATE key_registry_versions "
                    "SET registry_blob = %s "
                    "WHERE org_id = %s::uuid AND version = 1",
                    [b"not json", org_id],
                )

        before = _counts(info["owner_url"], org_id, proj)
        rp = _publish(cl, info["base_url"], pid, c_cookie, c_csrf)
        _g1_gate(rp)
        assert rp.status_code == 400, (
            f"expected 400, got {rp.status_code} (must never be 500)")
        assert rp.status_code != 500
        assert rp.json().get("error") == "registry_invalid"
        _assert_nothing_written(info["owner_url"], org_id, proj, pid,
                                 "registry_invalid", before)


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M3T4Pending)
def test_publish_no_registry_refused(t4_server):
    """Org with no chain, two approvals inserted by owner: 400 no_registry."""
    import httpx
    info = t4_server

    conninfo = _conninfo(info["owner_url"])
    org_id = str(uuid.uuid4())
    proposer_id = str(uuid.uuid4())
    publisher_id = str(uuid.uuid4())
    approver1_id = str(uuid.uuid4())
    approver2_id = str(uuid.uuid4())
    with psycopg.connect(conninfo, autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        create_org(conn, org_id, f"NoReg {org_id[:8]}")
        for uid, email in [(proposer_id, "nrp@nr.test"),
                           (publisher_id, "nrpub@nr.test"),
                           (approver1_id, "nra1@nr.test"),
                           (approver2_id, "nra2@nr.test")]:
            conn.execute(
                "INSERT INTO users (id, org_id, oidc_issuer, oidc_subject, "
                "email, status, created_at) "
                "VALUES (%s, %s, 'https://idp.test', %s, %s, "
                "'active', now()) ON CONFLICT DO NOTHING",
                [uid, org_id, f"sub-{uuid.uuid4().hex[:8]}", email],
            )
            _bind_admin(conn, org_id, uid)
        proj = str(uuid.uuid4())
        create_project(conn, org_id, proj, "NoRegProj")

    # Owner-insert a proposal and two approvals directly
    # (no chain means the approval route would refuse no_registry)
    pid = str(uuid.uuid4())
    fake_sha = "c" * 64
    with psycopg.connect(conninfo, autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        conn.execute(
            "INSERT INTO policy_change_requests "
            "(id, org_id, project_id, proposer_user_id, base_sequence, "
            "base_sha, new_sha, payload, sequence, registry_version, "
            "status, created_at) "
            "VALUES (%s, %s::uuid, %s::uuid, %s::uuid, 0, "
            "%s, %s, %s, 1, 0, 'open', now())",
            [pid, org_id, proj, proposer_id, fake_sha, fake_sha, b'{}'],
        )
        # Approvals with user_ids that are neither proposer nor publisher
        for sk_info, uid in [(info["alice_sk"], approver1_id),
                             (info["bob_sk"], approver2_id)]:
            env = _sign_approval(sk_info, fake_sha)
            conn.execute(
                "INSERT INTO policy_change_approvals "
                "(id, org_id, change_request_id, key_id, user_id, "
                "signature, signed_at, created_at) "
                "VALUES (%s, %s::uuid, %s::uuid, %s, %s::uuid, %s, "
                "now(), now())",
                [str(uuid.uuid4()), org_id, pid, _kid(sk_info),
                 uid, json.dumps(env)],
            )

    clock = FakeClock()
    cookie, csrf, _ = _make_fresh_session(
        info["owner_url"], org_id, publisher_id, clock=clock)

    with httpx.Client(base_url=info["base_url"], timeout=30) as cl:
        rp = _publish(cl, info["base_url"], pid, cookie, csrf)
        _g1_gate(rp)
        assert rp.status_code == 400
        assert rp.json().get("error") == "no_registry"


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M3T4Pending)
def test_publish_registry_version_stale_refused(t4_server):
    """Own org; propose under v1; store v2 keeping all keys; approve twice
    through the route (assert 201); publish: 400 registry_version_stale,
    nothing written."""
    import httpx
    info = t4_server

    # Own org
    own_alice_sk = SigningKey.generate()
    own_bob_sk = SigningKey.generate()
    own_carol_sk = SigningKey.generate()
    own_alice_id = str(uuid.uuid4())
    own_bob_id = str(uuid.uuid4())
    own_carol_id = str(uuid.uuid4())

    conninfo = _conninfo(info["owner_url"])
    org_id = str(uuid.uuid4())
    with psycopg.connect(conninfo, autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        create_org(conn, org_id, f"VerStale {org_id[:8]}")
        for uid, email in [(own_alice_id, "va@vs.test"),
                           (own_bob_id, "vb@vs.test"),
                           (own_carol_id, "vc@vs.test")]:
            conn.execute(
                "INSERT INTO users (id, org_id, oidc_issuer, oidc_subject, "
                "email, status, created_at) "
                "VALUES (%s, %s, 'https://idp.test', %s, %s, "
                "'active', now()) ON CONFLICT DO NOTHING",
                [uid, org_id, f"sub-{uuid.uuid4().hex[:8]}", email],
            )
            _bind_admin(conn, org_id, uid)
        proj = str(uuid.uuid4())
        create_project(conn, org_id, proj, "VSProj")

    v1_entries = [
        _make_key_entry(own_alice_sk, own_alice_id, "cli",
                        ["admin", "approver"]),
        _make_key_entry(own_bob_sk, own_bob_id, "cli",
                        ["admin", "approver"]),
        _make_key_entry(own_carol_sk, own_carol_id, "cli",
                        ["admin", "approver"]),
    ]
    chain_v1, fp = _build_registry_chain(
        org_id, info["bundle_signer_sk"], v1_entries,
        [own_alice_sk, own_bob_sk], threshold=2,
    )
    _store_chain(info["owner_url"], org_id, chain_v1)

    clock = FakeClock()
    a_cookie, a_csrf, _ = _make_fresh_session(
        info["owner_url"], org_id, own_alice_id, clock=clock)
    b_cookie, b_csrf, _ = _make_fresh_session(
        info["owner_url"], org_id, own_bob_id, clock=clock)
    c_cookie, c_csrf, _ = _make_fresh_session(
        info["owner_url"], org_id, own_carol_id, clock=clock)

    with httpx.Client(base_url=info["base_url"], timeout=30) as cl:
        # Propose under v1
        bundle = {
            "folder_policy": {"shell": {"blocklist_action": "escalate"}},
            "governance_policy": {"clauses": []},
            "mcp_policy": {"servers": []},
            "approval": {"local_fallback": True, "allow_requester": False},
        }
        r = _propose(cl, info["base_url"], proj, bundle, c_cookie, c_csrf)
        assert r.status_code in (200, 201)
        pid = r.json().get("id") or r.json().get("proposal_id")
        bh = r.json().get("hash") or r.json().get("bundle_hash")

        # Store v2 keeping all keys
        bs_pub = bytes(info["bundle_signer_sk"].verify_key)
        bs_kid = hashlib.sha256(bs_pub).hexdigest()
        v2_payload = {
            "org_id": org_id, "version": 2, "prev_hash": fp,
            "threshold": 2,
            "admins": [_kid(own_alice_sk), _kid(own_bob_sk)],
            "keys": v1_entries,
            "bundle_signer": {
                "key_id": bs_kid, "public_key": bs_pub.hex(),
                "alg": "ed25519",
            },
            "expires_at": time.time() + 7 * 86400,
        }
        v2_env = _sign_envelope_multi("agg/registry/v1", v2_payload,
                                       [own_alice_sk, own_bob_sk])
        from agg_cp.sync.registry import store_registry_version
        with psycopg.connect(conninfo) as conn:
            store_registry_version(conn, org_id, v2_env)

        # Approve twice through the route (should succeed: keys are still
        # in the registry)
        ra = _approve(cl, info["base_url"], pid,
                      _sign_approval(own_alice_sk, bh), a_cookie, a_csrf)
        assert ra.status_code in (200, 201), (
            f"approve alice: {ra.status_code} {ra.text[:200]}")
        rb = _approve(cl, info["base_url"], pid,
                      _sign_approval(own_bob_sk, bh), b_cookie, b_csrf)
        assert rb.status_code in (200, 201), (
            f"approve bob: {rb.status_code} {rb.text[:200]}")

        before = _counts(info["owner_url"], org_id, proj)
        rp = _publish(cl, info["base_url"], pid, c_cookie, c_csrf)
        _g1_gate(rp)
        assert rp.status_code == 400
        assert rp.json().get("error") == "registry_version_stale"
        _assert_nothing_written(info["owner_url"], org_id, proj, pid,
                                 "registry_version_stale", before)


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M3T4Pending)
def test_publish_signer_not_in_registry_refused(t4_server):
    """Own org whose chain names a different bundle signer: 400
    signer_not_in_registry, nothing written."""
    import httpx
    info = t4_server

    # Own org with a chain whose bundle_signer is NOT the server's key file
    own_alice_sk = SigningKey.generate()
    own_bob_sk = SigningKey.generate()
    own_carol_sk = SigningKey.generate()
    other_signer_sk = SigningKey.generate()  # different from server
    own_alice_id = str(uuid.uuid4())
    own_bob_id = str(uuid.uuid4())
    own_carol_id = str(uuid.uuid4())

    conninfo = _conninfo(info["owner_url"])
    org_id = str(uuid.uuid4())
    with psycopg.connect(conninfo, autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        create_org(conn, org_id, f"SNR {org_id[:8]}")
        for uid, email in [(own_alice_id, "sa@snr.test"),
                           (own_bob_id, "sb@snr.test"),
                           (own_carol_id, "sc@snr.test")]:
            conn.execute(
                "INSERT INTO users (id, org_id, oidc_issuer, oidc_subject, "
                "email, status, created_at) "
                "VALUES (%s, %s, 'https://idp.test', %s, %s, "
                "'active', now()) ON CONFLICT DO NOTHING",
                [uid, org_id, f"sub-{uuid.uuid4().hex[:8]}", email],
            )
            _bind_admin(conn, org_id, uid)
        proj = str(uuid.uuid4())
        create_project(conn, org_id, proj, "SNRProj")

    v1_entries = [
        _make_key_entry(own_alice_sk, own_alice_id, "cli",
                        ["admin", "approver"]),
        _make_key_entry(own_bob_sk, own_bob_id, "cli",
                        ["admin", "approver"]),
        _make_key_entry(own_carol_sk, own_carol_id, "cli",
                        ["admin", "approver"]),
    ]
    # Use other_signer_sk as the bundle signer (not server's key file)
    chain_v1, fp = _build_registry_chain(
        org_id, other_signer_sk, v1_entries,
        [own_alice_sk, own_bob_sk], threshold=2,
    )
    _store_chain(info["owner_url"], org_id, chain_v1)

    clock = FakeClock()
    a_cookie, a_csrf, _ = _make_fresh_session(
        info["owner_url"], org_id, own_alice_id, clock=clock)
    b_cookie, b_csrf, _ = _make_fresh_session(
        info["owner_url"], org_id, own_bob_id, clock=clock)
    c_cookie, c_csrf, _ = _make_fresh_session(
        info["owner_url"], org_id, own_carol_id, clock=clock)

    with httpx.Client(base_url=info["base_url"], timeout=30) as cl:
        bundle = {
            "folder_policy": {"shell": {"blocklist_action": "escalate"}},
            "governance_policy": {"clauses": []},
            "mcp_policy": {"servers": []},
            "approval": {"local_fallback": True, "allow_requester": False},
        }
        r = _propose(cl, info["base_url"], proj, bundle, c_cookie, c_csrf)
        assert r.status_code in (200, 201)
        pid = r.json().get("id") or r.json().get("proposal_id")
        bh = r.json().get("hash") or r.json().get("bundle_hash")

        ra = _approve(cl, info["base_url"], pid,
                      _sign_approval(own_alice_sk, bh), a_cookie, a_csrf)
        assert ra.status_code in (200, 201)
        rb = _approve(cl, info["base_url"], pid,
                      _sign_approval(own_bob_sk, bh), b_cookie, b_csrf)
        assert rb.status_code in (200, 201)

        before = _counts(info["owner_url"], org_id, proj)
        rp = _publish(cl, info["base_url"], pid, c_cookie, c_csrf)
        _g1_gate(rp)
        assert rp.status_code == 400
        assert rp.json().get("error") == "signer_not_in_registry"
        _assert_nothing_written(info["owner_url"], org_id, proj, pid,
                                 "signer_not_in_registry", before)


@pytest.mark.pg
@pytest.mark.parametrize("variant", ["unparseable", "wrong_binding"],
                         ids=["unparseable", "wrong_binding"])
@pytest.mark.xfail(strict=True, raises=M3T4Pending)
def test_publish_base_invalid_refused(t4_server, variant):
    """SHOULD 7, SQ-8: head row not parseable or wrong binding:
    400 base_invalid, nothing written."""
    import httpx
    info = t4_server

    proj = str(uuid.uuid4())
    conninfo = _conninfo(info["owner_url"])
    with psycopg.connect(conninfo, autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [info["org_id"]])
        create_project(conn, info["org_id"], proj, "BaseInv")

    # Insert a valid row 1 first so the propose can reference it
    valid_payload = {
        "org_id": info["org_id"], "project_id": proj,
        "base_sequence": 0, "sequence": 1, "registry_version": 1,
        "issued_at": int(time.time()), "not_before": int(time.time()),
        "folder_policy": {"shell": {"blocklist_action": "deny"}},
        "governance_policy": {"clauses": []}, "mcp_policy": {"servers": []},
        "approval": {"local_fallback": False, "allow_requester": False},
    }
    with psycopg.connect(conninfo, autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [info["org_id"]])
        bid1 = _owner_insert_bundle(conn, info["org_id"], proj, 1,
                                     info["bundle_signer_sk"], valid_payload,
                                     verification="server")

    with httpx.Client(base_url=info["base_url"], timeout=30) as c:
        # Propose at base 1 (valid at propose time)
        bundle = {
            "folder_policy": {"shell": {"blocklist_action": "escalate"}},
            "governance_policy": {"clauses": []},
            "mcp_policy": {"servers": []},
            "approval": {"local_fallback": True, "allow_requester": False},
        }
        r = _propose(c, info["base_url"], proj, bundle,
                     info["carol_cookie"], info["carol_csrf"])
        assert r.status_code in (200, 201)
        pid = r.json().get("id") or r.json().get("proposal_id")
        bh = r.json().get("hash") or r.json().get("bundle_hash")

        # Approve twice
        _approve(c, info["base_url"], pid,
                 _sign_approval(info["alice_sk"], bh),
                 info["alice_cookie"], info["alice_csrf"])
        _approve(c, info["base_url"], pid,
                 _sign_approval(info["bob_sk"], bh),
                 info["bob_cookie"], info["bob_csrf"])

        # Tamper the base row
        with psycopg.connect(conninfo, autocommit=True) as conn:
            conn.execute("SELECT set_config('app.org_id', %s, false)",
                         [info["org_id"]])
            if variant == "unparseable":
                conn.execute(
                    "UPDATE policy_bundles SET bundle_blob = %s "
                    "WHERE id = %s::uuid",
                    [b'\xff\xfe', bid1],
                )
            else:  # wrong_binding
                # Parseable envelope with wrong sequence
                bad_payload = dict(valid_payload)
                bad_payload["sequence"] = 5
                bad_env = _make_bundle_envelope(bad_payload,
                                                 info["bundle_signer_sk"])
                bad_blob = json.dumps(bad_env, sort_keys=True,
                                       separators=(",", ":")).encode()
                conn.execute(
                    "UPDATE policy_bundles SET bundle_blob = %s "
                    "WHERE id = %s::uuid",
                    [bad_blob, bid1],
                )

        before = _counts(info["owner_url"], info["org_id"], proj)
        rp = _publish(c, info["base_url"], pid,
                      info["dave_cookie"], info["dave_csrf"])
        _g1_gate(rp)
        assert rp.status_code == 400
        assert rp.json().get("error") == "base_invalid"
        _assert_nothing_written(info["owner_url"], info["org_id"], proj,
                                 pid, "base_invalid", before)


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M3T4Pending)
def test_publish_not_yet_valid_refused(t4_server):
    """SHOULD 7: owner-inserted proposal with not_before in the future,
    two valid approvals: 400 not_yet_valid, nothing written."""
    import httpx
    info = t4_server

    proj = str(uuid.uuid4())
    conninfo = _conninfo(info["owner_url"])
    with psycopg.connect(conninfo, autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [info["org_id"]])
        create_project(conn, info["org_id"], proj, "NotYet",
                        environment="prod")

    # Build a payload with not_before in the future
    future_payload = {
        "org_id": info["org_id"], "project_id": proj,
        "base_sequence": 0, "sequence": 1, "registry_version": 1,
        "issued_at": int(time.time()),
        "not_before": int(time.time()) + 3600,
        "folder_policy": {"shell": {"blocklist_action": "deny"}},
        "governance_policy": {"clauses": []}, "mcp_policy": {"servers": []},
        "approval": {"local_fallback": False, "allow_requester": False},
    }
    from sandbox.connector.sync.bundles import _bundle_hash
    future_bh = _bundle_hash(future_payload)
    future_sha = hashlib.sha256(
        json.dumps(future_payload, sort_keys=True,
                   separators=(",", ":")).encode()
    ).hexdigest()

    # Owner-insert the proposal
    pid = str(uuid.uuid4())
    with psycopg.connect(conninfo, autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [info["org_id"]])
        conn.execute(
            "INSERT INTO policy_change_requests "
            "(id, org_id, project_id, proposer_user_id, base_sequence, "
            "base_sha, new_sha, payload, sequence, registry_version, "
            "status, created_at) "
            "VALUES (%s, %s::uuid, %s::uuid, %s::uuid, 0, "
            "%s, %s, %s, 1, 1, 'open', now())",
            [pid, info["org_id"], proj, info["carol_id"],
             "0" * 64, future_sha,
             json.dumps(future_payload, sort_keys=True,
                        separators=(",", ":")).encode()],
        )

    with httpx.Client(base_url=info["base_url"], timeout=30) as c:
        # Approve twice through the route
        ra = _approve(c, info["base_url"], pid,
                      _sign_approval(info["alice_sk"], future_bh),
                      info["alice_cookie"], info["alice_csrf"])
        assert ra.status_code in (200, 201)
        rb = _approve(c, info["base_url"], pid,
                      _sign_approval(info["bob_sk"], future_bh),
                      info["bob_cookie"], info["bob_csrf"])
        assert rb.status_code in (200, 201)

        before = _counts(info["owner_url"], info["org_id"], proj)
        rp = _publish(c, info["base_url"], pid,
                      info["dave_cookie"], info["dave_csrf"])
        _g1_gate(rp)
        assert rp.status_code == 400
        assert rp.json().get("error") == "not_yet_valid"
        _assert_nothing_written(info["owner_url"], info["org_id"], proj,
                                 pid, "not_yet_valid", before)


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M3T4Pending)
def test_publish_registry_user_id_canonical_form(t4_server):
    """SHOULD 1: own org; registry entry for carol's key with user_id in
    uppercase. Carol's approval through the route is refused as proposer's.
    Owner-inserted copy (stored user_id dave) makes publish 400
    proposer_in_approvals."""
    import httpx
    info = t4_server

    # Own org with carol's user_id uppercase in the registry
    own_alice_sk = SigningKey.generate()
    own_bob_sk = SigningKey.generate()
    own_carol_sk = SigningKey.generate()
    own_alice_id = str(uuid.uuid4())
    own_bob_id = str(uuid.uuid4())
    own_carol_id = str(uuid.uuid4())
    own_dave_id = str(uuid.uuid4())

    conninfo = _conninfo(info["owner_url"])
    org_id = str(uuid.uuid4())
    with psycopg.connect(conninfo, autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        create_org(conn, org_id, f"Canon {org_id[:8]}")
        for uid, email in [(own_alice_id, "ua@cn.test"),
                           (own_bob_id, "ub@cn.test"),
                           (own_carol_id, "uc@cn.test"),
                           (own_dave_id, "ud@cn.test")]:
            conn.execute(
                "INSERT INTO users (id, org_id, oidc_issuer, oidc_subject, "
                "email, status, created_at) "
                "VALUES (%s, %s, 'https://idp.test', %s, %s, "
                "'active', now()) ON CONFLICT DO NOTHING",
                [uid, org_id, f"sub-{uuid.uuid4().hex[:8]}", email],
            )
            _bind_admin(conn, org_id, uid)
        proj = str(uuid.uuid4())
        create_project(conn, org_id, proj, "CanonProj")

    # Carol's entry has uppercase user_id
    v1_entries = [
        _make_key_entry(own_alice_sk, own_alice_id, "cli",
                        ["admin", "approver"]),
        _make_key_entry(own_bob_sk, own_bob_id, "cli",
                        ["admin", "approver"]),
        _make_key_entry(own_carol_sk, own_carol_id.upper(), "cli",
                        ["admin", "approver"]),
    ]
    chain_v1, fp = _build_registry_chain(
        org_id, info["bundle_signer_sk"], v1_entries,
        [own_alice_sk, own_bob_sk], threshold=2,
    )
    _store_chain(info["owner_url"], org_id, chain_v1)

    clock = FakeClock()
    a_cookie, a_csrf, _ = _make_fresh_session(
        info["owner_url"], org_id, own_alice_id, clock=clock)
    b_cookie, b_csrf, _ = _make_fresh_session(
        info["owner_url"], org_id, own_bob_id, clock=clock)
    c_cookie, c_csrf, _ = _make_fresh_session(
        info["owner_url"], org_id, own_carol_id, clock=clock)

    with httpx.Client(base_url=info["base_url"], timeout=30) as cl:
        bundle = {
            "folder_policy": {"shell": {"blocklist_action": "escalate"}},
            "governance_policy": {"clauses": []},
            "mcp_policy": {"servers": []},
            "approval": {"local_fallback": True, "allow_requester": False},
        }
        # carol proposes
        r = _propose(cl, info["base_url"], proj, bundle, c_cookie, c_csrf)
        assert r.status_code in (200, 201)
        pid = r.json().get("id") or r.json().get("proposal_id")
        bh = r.json().get("hash") or r.json().get("bundle_hash")

        # Carol's approval through the route should be refused
        # (proposer_cannot_approve, uppercase resolved to carol)
        rc = _approve(cl, info["base_url"], pid,
                      _sign_approval(own_carol_sk, bh), c_cookie, c_csrf)
        # G2 gate: depends on publish_verify module for canonical form
        require_m3(
            4,
            importlib.util.find_spec("agg_cp.sync.publish_verify") is not None,
            "publish_verify module missing (T4)",
        )
        assert rc.status_code == 400, (
            f"carol route approval: {rc.status_code} {rc.text[:200]}")
        assert rc.json().get("error") == "proposer_cannot_approve"

        # alice approves
        ra = _approve(cl, info["base_url"], pid,
                      _sign_approval(own_alice_sk, bh), a_cookie, a_csrf)
        assert ra.status_code in (200, 201)

        # Owner-insert carol's approval with stored user_id=dave
        carol_env = _sign_approval(own_carol_sk, bh)
        with psycopg.connect(conninfo, autocommit=True) as conn:
            conn.execute("SELECT set_config('app.org_id', %s, false)",
                         [org_id])
            conn.execute(
                "INSERT INTO policy_change_approvals "
                "(id, org_id, change_request_id, key_id, user_id, "
                "signature, signed_at, created_at) "
                "VALUES (%s, %s::uuid, %s::uuid, %s, %s::uuid, %s, "
                "now(), now())",
                [str(uuid.uuid4()), org_id, pid, _kid(own_carol_sk),
                 own_dave_id, json.dumps(carol_env)],
            )

        rp = _publish(cl, info["base_url"], pid, b_cookie, b_csrf)
        # G2 gate: depends on publish_verify module
        require_m3(
            4,
            importlib.util.find_spec("agg_cp.sync.publish_verify") is not None,
            "publish_verify module missing (T4)",
        )
        assert rp.status_code == 400
        assert rp.json().get("error") == "proposer_in_approvals"


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M3T4Pending)
def test_publish_concurrent_same_base_one_wins(t4_server):
    """Two fully approved proposals on one base, published concurrently:
    exactly one 201 and one 400 stale_base."""
    import httpx
    info = t4_server

    proj = str(uuid.uuid4())
    conninfo = _conninfo(info["owner_url"])
    with psycopg.connect(conninfo, autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [info["org_id"]])
        create_project(conn, info["org_id"], proj, "Concurrent")

    with httpx.Client(base_url=info["base_url"], timeout=30) as c:
        bundle_a = {
            "folder_policy": {"shell": {"blocklist_action": "escalate"}},
            "governance_policy": {"clauses": []},
            "mcp_policy": {"servers": []},
            "approval": {"local_fallback": True, "allow_requester": False},
        }
        bundle_b = {
            "folder_policy": {"shell": {"blocklist_action": "observe"}},
            "governance_policy": {"clauses": []},
            "mcp_policy": {"servers": []},
            "approval": {"local_fallback": True, "allow_requester": False},
        }

        # Proposal A
        ra = _propose(c, info["base_url"], proj, bundle_a,
                      info["carol_cookie"], info["carol_csrf"])
        assert ra.status_code in (200, 201)
        pid_a = ra.json().get("id") or ra.json().get("proposal_id")
        bh_a = ra.json().get("hash") or ra.json().get("bundle_hash")

        # Proposal B
        rb = _propose(c, info["base_url"], proj, bundle_b,
                      info["carol_cookie"], info["carol_csrf"])
        assert rb.status_code in (200, 201)
        pid_b = rb.json().get("id") or rb.json().get("proposal_id")
        bh_b = rb.json().get("hash") or rb.json().get("bundle_hash")

        # Approve both
        for pid, bh in [(pid_a, bh_a), (pid_b, bh_b)]:
            _approve(c, info["base_url"], pid,
                     _sign_approval(info["alice_sk"], bh),
                     info["alice_cookie"], info["alice_csrf"])
            _approve(c, info["base_url"], pid,
                     _sign_approval(info["bob_sk"], bh),
                     info["bob_cookie"], info["bob_csrf"])

    # Publish both concurrently using dave (not an approver on either)
    def do_publish(pid, cookie, csrf):
        with httpx.Client(base_url=info["base_url"], timeout=30) as cl:
            return _publish(cl, info["base_url"], pid, cookie, csrf)

    with ThreadPoolExecutor(max_workers=2) as pool:
        f1 = pool.submit(do_publish, pid_a,
                         info["dave_cookie"], info["dave_csrf"])
        f2 = pool.submit(do_publish, pid_b,
                         info["dave_cookie"], info["dave_csrf"])
        r1 = f1.result()
        r2 = f2.result()

    # G1: at least one must not be verification_pending
    _g1_gate(r1)

    statuses = sorted([r1.status_code, r2.status_code])
    assert statuses == [201, 400], f"expected [201, 400], got {statuses}"

    loser = r1 if r1.status_code == 400 else r2
    assert loser.json().get("error") == "stale_base"

    # Exactly one row at seq 1
    with psycopg.connect(conninfo) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [info["org_id"]])
        cnt = conn.execute(
            "SELECT count(*) FROM policy_bundles "
            "WHERE org_id = %s::uuid AND project_id = %s::uuid "
            "AND sequence = 1",
            [info["org_id"], proj],
        ).fetchone()[0]
    assert cnt == 1


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M3T4Pending)
def test_publish_records_proposal_and_audit_row(t4_server):
    """After 201: proposal published with published_bundle_id, published_by,
    published_at; bundle_proposal.publish audit row names participants."""
    import httpx
    info = t4_server

    proj = str(uuid.uuid4())
    conninfo = _conninfo(info["owner_url"])
    with psycopg.connect(conninfo, autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [info["org_id"]])
        create_project(conn, info["org_id"], proj, "Records")

    with httpx.Client(base_url=info["base_url"], timeout=30) as c:
        bundle = {
            "folder_policy": {"shell": {"blocklist_action": "escalate"}},
            "governance_policy": {"clauses": []},
            "mcp_policy": {"servers": []},
            "approval": {"local_fallback": True, "allow_requester": False},
        }
        r = _propose(c, info["base_url"], proj, bundle,
                     info["carol_cookie"], info["carol_csrf"])
        assert r.status_code in (200, 201)
        pid = r.json().get("id") or r.json().get("proposal_id")
        bh = r.json().get("hash") or r.json().get("bundle_hash")

        _approve(c, info["base_url"], pid,
                 _sign_approval(info["alice_sk"], bh),
                 info["alice_cookie"], info["alice_csrf"])
        _approve(c, info["base_url"], pid,
                 _sign_approval(info["bob_sk"], bh),
                 info["bob_cookie"], info["bob_csrf"])
        rp = _publish(c, info["base_url"], pid,
                      info["dave_cookie"], info["dave_csrf"])
        _g1_gate(rp)
        assert rp.status_code == 201

        resp = rp.json()
        bundle_id = resp.get("bundle_id")

    with psycopg.connect(conninfo) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [info["org_id"]])
        row = conn.execute(
            "SELECT status, published_bundle_id, published_by, published_at "
            "FROM policy_change_requests WHERE id = %s::uuid",
            [pid],
        ).fetchone()
    assert row is not None
    assert row[0] == "published"
    assert str(row[1]) == bundle_id
    assert str(row[2]) == info["dave_id"]
    assert row[3] is not None

    # Audit row
    with psycopg.connect(conninfo) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [info["org_id"]])
        audit = conn.execute(
            "SELECT detail FROM admin_audit "
            "WHERE org_id = %s::uuid "
            "AND action = 'bundle_proposal.publish' "
            "AND detail->>'proposal_id' = %s",
            [info["org_id"], pid],
        ).fetchone()
    assert audit is not None
    detail = audit[0]  # jsonb returns dict
    assert detail.get("bundle_id") == bundle_id
    assert detail.get("bundle_hash") == resp.get("bundle_hash"), (
        f"audit bundle_hash: {detail.get('bundle_hash')} != {resp.get('bundle_hash')}")
    assert detail.get("sequence") == resp.get("sequence"), (
        f"audit sequence: {detail.get('sequence')} != {resp.get('sequence')}")
    assert detail.get("proposer_user_id") == info["carol_id"]
    assert detail.get("publisher_user_id") == info["dave_id"]
    assert isinstance(detail.get("approver_user_ids"), list)
    assert sorted(detail["approver_user_ids"]) == sorted(
        [info["alice_id"], info["bob_id"]])


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M3T4Pending)
def test_publish_refusals_audited_not_found_forbidden_not_open(t4_server):
    """404/403/409 each write a publish_refused audit row."""
    import httpx
    info = t4_server
    conninfo = _conninfo(info["owner_url"])
    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        # 404: random canonical id
        random_id = str(uuid.uuid4())
        r404 = _publish(c, info["base_url"], random_id,
                        info["alice_cookie"], info["alice_csrf"])
        assert r404.status_code == 404

        # 403: viewer vic on a real proposal
        proj = str(uuid.uuid4())
        with psycopg.connect(conninfo, autocommit=True) as conn:
            conn.execute("SELECT set_config('app.org_id', %s, false)",
                         [info["org_id"]])
            create_project(conn, info["org_id"], proj, "T4 Audit Ref")
        rp = _propose(c, info["base_url"], proj, {"folder_policy": {}},
                      info["carol_cookie"], info["carol_csrf"])
        assert rp.status_code in (200, 201)
        pid = rp.json().get("id") or rp.json().get("proposal_id")
        r403 = _publish(c, info["base_url"], pid,
                        info["vic_cookie"], info["vic_csrf"])
        assert r403.status_code == 403

        # 409: published proposal (owner-inserted, addendum A1)
        pub_pid = str(uuid.uuid4())
        bun_id = str(uuid.uuid4())
        with psycopg.connect(conninfo, autocommit=True) as conn:
            conn.execute("SELECT set_config('app.org_id', %s, false)",
                         [info["org_id"]])
            conn.execute(
                "INSERT INTO policy_bundles (id, org_id, project_id, "
                "sequence, bundle_blob, server_signature, created_at) "
                "VALUES (%s, %s::uuid, %s::uuid, 999, %s, '', now())",
                [bun_id, info["org_id"], proj, b'{}'],
            )
            fake_sha = "a" * 64
            conn.execute(
                "INSERT INTO policy_change_requests "
                "(id, org_id, project_id, proposer_user_id, base_sequence, "
                "base_sha, new_sha, payload, sequence, registry_version, "
                "status, published_bundle_id, published_by, published_at, "
                "created_at) "
                "VALUES (%s, %s::uuid, %s::uuid, %s::uuid, 0, "
                "%s, %s, %s, 1, 0, "
                "'published', %s::uuid, %s::uuid, now(), now())",
                [pub_pid, info["org_id"], proj, info["carol_id"],
                 fake_sha, fake_sha, b'{}', bun_id, info["alice_id"]],
            )
        r409 = _publish(c, info["base_url"], pub_pid,
                        info["alice_cookie"], info["alice_csrf"])
        assert r409.status_code == 409

    # G2: gate before audit assertions
    require_m3(
        4,
        importlib.util.find_spec("agg_cp.sync.publish_verify") is not None,
        "publish_verify module missing (T4)",
    )

    # Check audit rows: exactly one per (proposal_id, reason) pair
    with psycopg.connect(conninfo) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [info["org_id"]])
        for exp_pid, exp_reason in [
            (random_id, "not_found"),
            (pid, "forbidden"),
            (pub_pid, "not_open"),
        ]:
            cnt = conn.execute(
                "SELECT count(*) "
                "FROM admin_audit "
                "WHERE org_id = %s::uuid "
                "AND action = 'bundle_proposal.publish_refused' "
                "AND detail->>'reason' = %s "
                "AND detail->>'proposal_id' = %s",
                [info["org_id"], exp_reason, exp_pid],
            ).fetchone()[0]
            assert cnt == 1, (
                f"expected 1 publish_refused row for ({exp_pid}, "
                f"{exp_reason}), got {cnt}")


# ===================================================================
# Migration 0019 nodes (G3 gate)
# ===================================================================

@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M3T4Pending)
def test_published_request_requires_bundle_link(t4_server):
    """Owner INSERT of published request with NULL published_bundle_id
    raises CHECK violation."""
    conninfo = _conninfo(t4_server["owner_url"])
    with psycopg.connect(conninfo) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [t4_server["org_id"]])
        row = conn.execute(
            "SELECT 1 FROM pg_constraint WHERE conname = 'chk_published_link'",
        ).fetchone()
    require_m3(4, row is not None,
               "migration 0019 chk_published_link not present")

    with psycopg.connect(conninfo) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [t4_server["org_id"]])
        with pytest.raises(psycopg.errors.CheckViolation) as exc_info:
            conn.execute(
                "INSERT INTO policy_change_requests "
                "(id, org_id, project_id, proposer_user_id, base_sequence, "
                "base_sha, new_sha, payload, sequence, registry_version, "
                "status, published_bundle_id, published_by, published_at, "
                "created_at) "
                "VALUES (%s, %s::uuid, %s::uuid, %s::uuid, 0, "
                "%s, %s, %s, 1, 0, "
                "'published', NULL, %s::uuid, now(), now())",
                [str(uuid.uuid4()), t4_server["org_id"],
                 t4_server["project_id"], t4_server["alice_id"],
                 "0" * 64, "0" * 64, b'{}', t4_server["alice_id"]],
            )
        assert exc_info.value.diag.constraint_name == "chk_published_link"


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M3T4Pending)
def test_published_request_cannot_be_reopened_or_deleted(t4_server):
    """SHOULD 2: DELETE as agg_app is refused; UPDATE of published row
    raises from the trigger."""
    conninfo = _conninfo(t4_server["owner_url"])
    with psycopg.connect(conninfo) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [t4_server["org_id"]])
        row = conn.execute(
            "SELECT 1 FROM pg_constraint WHERE conname = 'chk_published_link'",
        ).fetchone()
    require_m3(4, row is not None,
               "migration 0019 chk_published_link not present")

    # Test DELETE revoked from agg_app
    app_conninfo = t4_server["app_url"].replace("+psycopg", "")
    with psycopg.connect(app_conninfo) as conn:
        conn.execute("SET ROLE agg_app")
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [t4_server["org_id"]])
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute(
                "DELETE FROM policy_change_requests "
                "WHERE id = %s::uuid",
                [t4_server.get("project_id", str(uuid.uuid4()))],
            )

    # Test UPDATE trigger on published rows
    # Owner-insert a published row for the trigger test
    pub_id = str(uuid.uuid4())
    bun_id = str(uuid.uuid4())
    with psycopg.connect(conninfo, autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [t4_server["org_id"]])
        conn.execute(
            "INSERT INTO policy_bundles "
            "(id, org_id, project_id, sequence, bundle_blob, "
            "server_signature, created_at) "
            "VALUES (%s, %s::uuid, %s::uuid, 998, %s, '', now())",
            [bun_id, t4_server["org_id"], t4_server["project_id"], b'{}'],
        )
        conn.execute(
            "INSERT INTO policy_change_requests "
            "(id, org_id, project_id, proposer_user_id, base_sequence, "
            "base_sha, new_sha, payload, sequence, registry_version, "
            "status, published_bundle_id, published_by, published_at, "
            "created_at) "
            "VALUES (%s, %s::uuid, %s::uuid, %s::uuid, 0, "
            "%s, %s, %s, 1, 0, "
            "'published', %s::uuid, %s::uuid, now(), now())",
            [pub_id, t4_server["org_id"], t4_server["project_id"],
             t4_server["alice_id"], "0" * 64, "0" * 64, b'{}',
             bun_id, t4_server["alice_id"]],
        )

    # As agg_app, UPDATE the published row: should raise from the trigger
    with psycopg.connect(app_conninfo) as conn:
        conn.execute("SET ROLE agg_app")
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [t4_server["org_id"]])
        with pytest.raises(psycopg.errors.RaiseException):
            conn.execute(
                "UPDATE policy_change_requests "
                "SET status = 'open', published_bundle_id = NULL, "
                "published_by = NULL, published_at = NULL "
                "WHERE id = %s::uuid",
                [pub_id],
            )

    # Verify the row is still published
    with psycopg.connect(conninfo) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [t4_server["org_id"]])
        status = conn.execute(
            "SELECT status FROM policy_change_requests WHERE id = %s::uuid",
            [pub_id],
        ).fetchone()[0]
    assert status == "published"


# ===================================================================
# Proposal nodes (G2 gate for non-publish)
# ===================================================================

@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M3T4Pending)
def test_propose_base_row_missing_refused(t4_server):
    """base_sequence > 0 with no row: 400 base_missing, nothing stored."""
    require_m3(
        4,
        importlib.util.find_spec("agg_cp.sync.publish_verify") is not None,
        "publish_verify module missing (T4)",
    )
    import httpx
    info = t4_server
    conninfo = _conninfo(info["owner_url"])
    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        proj = str(uuid.uuid4())
        with psycopg.connect(conninfo, autocommit=True) as conn:
            conn.execute("SELECT set_config('app.org_id', %s, false)",
                         [info["org_id"]])
            create_project(conn, info["org_id"], proj, "T4 BaseMissing")
            # Insert a published request at seq 1 with no bundle row
            fake_bun_id = str(uuid.uuid4())
            fake_sha = "b" * 64
            conn.execute(
                "INSERT INTO policy_change_requests "
                "(id, org_id, project_id, proposer_user_id, base_sequence, "
                "base_sha, new_sha, payload, sequence, registry_version, "
                "status, published_bundle_id, published_by, published_at, "
                "created_at) "
                "VALUES (%s, %s::uuid, %s::uuid, %s::uuid, 0, "
                "%s, %s, %s, 1, 0, "
                "'published', %s::uuid, %s::uuid, now(), now())",
                [str(uuid.uuid4()), info["org_id"], proj, info["carol_id"],
                 fake_sha, fake_sha, b'{}', fake_bun_id, info["alice_id"]],
            )
        # Propose at base_sequence 1 (no bundle row at seq 1).
        # The body has no base_sequence key -- the server derives it from
        # the last published request.
        r = c.post(
            f"{info['base_url']}/api/v1/admin/bundle-proposals",
            json={"project_id": proj, "bundle": {"folder_policy": {}}},
            cookies={"__Host-agg_session": info["carol_cookie"]},
            headers={"X-CSRF-Token": info["carol_csrf"]},
            timeout=10,
        )
    assert r.status_code == 400
    assert r.json().get("error") == "base_missing"
    # No new request row for this project
    with psycopg.connect(conninfo) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [info["org_id"]])
        cnt = conn.execute(
            "SELECT count(*) FROM policy_change_requests "
            "WHERE org_id = %s::uuid AND project_id = %s::uuid "
            "AND status = 'open'",
            [info["org_id"], proj],
        ).fetchone()[0]
    assert cnt == 0


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M3T4Pending)
def test_propose_registry_invalid_refused_and_audited(t4_server):
    """SHOULD: tampered chain gives 400 registry_invalid with audit row;
    no request row for the project."""
    require_m3(
        4,
        importlib.util.find_spec("agg_cp.sync.publish_verify") is not None,
        "publish_verify module missing (T4)",
    )
    import httpx
    info = t4_server

    # Own org with tampered chain
    own_sk = SigningKey.generate()
    own_id = str(uuid.uuid4())
    conninfo = _conninfo(info["owner_url"])
    org_id = str(uuid.uuid4())
    with psycopg.connect(conninfo, autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        create_org(conn, org_id, f"PropRI {org_id[:8]}")
        conn.execute(
            "INSERT INTO users (id, org_id, oidc_issuer, oidc_subject, "
            "email, status, created_at) "
            "VALUES (%s, %s, 'https://idp.test', %s, %s, "
            "'active', now()) ON CONFLICT DO NOTHING",
            [own_id, org_id, f"sub-{uuid.uuid4().hex[:8]}", "pri@pri.test"],
        )
        _bind_admin(conn, org_id, own_id)
        proj = str(uuid.uuid4())
        create_project(conn, org_id, proj, "PropRIProj")

    v1_entries = [
        _make_key_entry(own_sk, own_id, "cli", ["admin", "approver"]),
    ]
    chain_v1, fp = _build_registry_chain(
        org_id, info["bundle_signer_sk"], v1_entries,
        [own_sk], threshold=1,
    )
    _store_chain(info["owner_url"], org_id, chain_v1)

    # Tamper the chain
    with psycopg.connect(conninfo, autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        conn.execute(
            "UPDATE key_registry_versions SET registry_blob = %s "
            "WHERE org_id = %s::uuid AND version = 1",
            [b'not json', org_id],
        )

    clock = FakeClock()
    cookie, csrf, _ = _make_fresh_session(
        info["owner_url"], org_id, own_id, clock=clock)

    with httpx.Client(base_url=info["base_url"], timeout=10) as cl:
        r = _propose(cl, info["base_url"], proj, {"folder_policy": {}},
                     cookie, csrf)
    assert r.status_code == 400
    assert r.json().get("error") == "registry_invalid"

    # Audit row
    with psycopg.connect(conninfo) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        audit = conn.execute(
            "SELECT count(*) FROM admin_audit "
            "WHERE org_id = %s::uuid "
            "AND action = 'bundle_proposal.create_refused'",
            [org_id],
        ).fetchone()[0]
    assert audit >= 1

    # No request row
    with psycopg.connect(conninfo) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        cnt = conn.execute(
            "SELECT count(*) FROM policy_change_requests "
            "WHERE org_id = %s::uuid AND project_id = %s::uuid",
            [org_id, proj],
        ).fetchone()[0]
    assert cnt == 0


# ===================================================================
# Guard twins (PASS today)
# ===================================================================

@pytest.mark.pg
def test_propose_braced_uppercase_real_project_400(t4_server):
    """Guard: {<real id>} and uppercase real id: 400 bad_project_id,
    no proposal row for that project."""
    import httpx
    info = t4_server
    conninfo = _conninfo(info["owner_url"])

    # Count proposals before
    with psycopg.connect(conninfo) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [info["org_id"]])
        before = conn.execute(
            "SELECT count(*) FROM policy_change_requests "
            "WHERE org_id = %s::uuid AND project_id = %s::uuid",
            [info["org_id"], info["project_id"]],
        ).fetchone()[0]

    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        braced = "{" + info["project_id"] + "}"
        r1 = c.post(
            f"{info['base_url']}/api/v1/admin/bundle-proposals",
            json={"project_id": braced, "bundle": {"folder_policy": {}}},
            cookies={"__Host-agg_session": info["alice_cookie"]},
            headers={"X-CSRF-Token": info["alice_csrf"]},
        )
        assert r1.status_code == 400, f"braced id accepted: {r1.status_code}"
        assert r1.json().get("error") == "bad_project_id"

        upper = info["project_id"].upper()
        r2 = c.post(
            f"{info['base_url']}/api/v1/admin/bundle-proposals",
            json={"project_id": upper, "bundle": {"folder_policy": {}}},
            cookies={"__Host-agg_session": info["alice_cookie"]},
            headers={"X-CSRF-Token": info["alice_csrf"]},
        )
        assert r2.status_code == 400, f"uppercase id accepted: {r2.status_code}"
        assert r2.json().get("error") == "bad_project_id"

    # No new proposals
    with psycopg.connect(conninfo) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [info["org_id"]])
        after = conn.execute(
            "SELECT count(*) FROM policy_change_requests "
            "WHERE org_id = %s::uuid AND project_id = %s::uuid",
            [info["org_id"], info["project_id"]],
        ).fetchone()[0]
    assert after == before


@pytest.mark.pg
def test_approve_urn_id_valid_signed_body_404(t4_server):
    """Guard: urn:uuid:<real proposal id> with valid signed body: 404,
    nothing stored."""
    import httpx
    info = t4_server
    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        proj = str(uuid.uuid4())
        conninfo = _conninfo(info["owner_url"])
        with psycopg.connect(conninfo, autocommit=True) as conn:
            conn.execute("SELECT set_config('app.org_id', %s, false)",
                         [info["org_id"]])
            create_project(conn, info["org_id"], proj, "T4 URN Guard")
        rp = _propose(c, info["base_url"], proj, {"folder_policy": {}},
                      info["alice_cookie"], info["alice_csrf"])
        assert rp.status_code in (200, 201)
        pid = rp.json().get("id") or rp.json().get("proposal_id")
        bh = rp.json().get("hash") or rp.json().get("bundle_hash")

        urn_id = f"urn:uuid:{pid}"
        env = _sign_approval(info["bob_sk"], bh)
        r = _approve(c, info["base_url"], urn_id, env,
                     info["bob_cookie"], info["bob_csrf"])
        assert r.status_code == 404, f"urn id accepted: {r.status_code}"

    # No approvals stored for the urn_id
    with psycopg.connect(conninfo) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [info["org_id"]])
        cnt = conn.execute(
            "SELECT count(*) FROM policy_change_approvals "
            "WHERE change_request_id = %s::uuid",
            [pid],
        ).fetchone()[0]
    assert cnt == 0


# ===================================================================
# Proposal detail nodes (SHOULD)
# ===================================================================

@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M3T4Pending)
def test_proposal_detail_reports_approvals_needed(t4_server):
    """Detail reports approvals_needed: 2 for base-0; 1 for tightening
    after a server row; 2 after m2_unverified-only history (prod)."""
    require_m3(
        4,
        importlib.util.find_spec("agg_cp.sync.publish_verify") is not None,
        "publish_verify module missing (T4)",
    )
    import httpx
    info = t4_server
    conninfo = _conninfo(info["owner_url"])

    with httpx.Client(base_url=info["base_url"], timeout=30) as c:
        # Case 1: base-0 proposal, needs 2
        proj1 = str(uuid.uuid4())
        with psycopg.connect(conninfo, autocommit=True) as conn:
            conn.execute("SELECT set_config('app.org_id', %s, false)",
                         [info["org_id"]])
            create_project(conn, info["org_id"], proj1, "AN1")
        r1 = _propose(c, info["base_url"], proj1,
                      {"folder_policy": {"shell": {"blocklist_action": "deny"}}},
                      info["carol_cookie"], info["carol_csrf"])
        assert r1.status_code in (200, 201)
        pid1 = r1.json().get("id") or r1.json().get("proposal_id")
        d1 = c.get(
            f"{info['base_url']}/api/v1/admin/bundle-proposals/{pid1}",
            cookies={"__Host-agg_session": info["alice_cookie"]},
        )
        assert d1.status_code == 200
        assert d1.json().get("approvals_needed") == 2

        # Case 2: tightening after a server row, needs 1
        proj2 = str(uuid.uuid4())
        with psycopg.connect(conninfo, autocommit=True) as conn:
            conn.execute("SELECT set_config('app.org_id', %s, false)",
                         [info["org_id"]])
            create_project(conn, info["org_id"], proj2, "AN2",
                           environment="staging")
        # Publish a first bundle to get a server row
        rp2 = _propose(c, info["base_url"], proj2,
                       {"folder_policy": {"shell": {"blocklist_action": "escalate"}}},
                       info["carol_cookie"], info["carol_csrf"])
        assert rp2.status_code in (200, 201)
        pid2a = rp2.json().get("id") or rp2.json().get("proposal_id")
        bh2a = rp2.json().get("hash") or rp2.json().get("bundle_hash")
        _approve(c, info["base_url"], pid2a,
                 _sign_approval(info["alice_sk"], bh2a),
                 info["alice_cookie"], info["alice_csrf"])
        _approve(c, info["base_url"], pid2a,
                 _sign_approval(info["bob_sk"], bh2a),
                 info["bob_cookie"], info["bob_csrf"])
        rp2pub = _publish(c, info["base_url"], pid2a,
                           info["carol_cookie"], info["carol_csrf"])
        _g1_gate(rp2pub)
        assert rp2pub.status_code == 201

        # Now a tightening
        rp2b = _propose(c, info["base_url"], proj2,
                        {"folder_policy": {"shell": {"blocklist_action": "deny"}}},
                        info["carol_cookie"], info["carol_csrf"])
        assert rp2b.status_code in (200, 201)
        pid2b = rp2b.json().get("id") or rp2b.json().get("proposal_id")
        d2 = c.get(
            f"{info['base_url']}/api/v1/admin/bundle-proposals/{pid2b}",
            cookies={"__Host-agg_session": info["alice_cookie"]},
        )
        assert d2.status_code == 200
        assert d2.json().get("approvals_needed") == 1

        # Case 3: after m2_unverified-only (prod), needs 2
        proj3 = str(uuid.uuid4())
        with psycopg.connect(conninfo, autocommit=True) as conn:
            conn.execute("SELECT set_config('app.org_id', %s, false)",
                         [info["org_id"]])
            create_project(conn, info["org_id"], proj3, "AN3",
                           environment="prod")
            deny_payload = {
                "org_id": info["org_id"], "project_id": proj3,
                "base_sequence": 0, "sequence": 1, "registry_version": 1,
                "issued_at": int(time.time()),
                "not_before": int(time.time()),
                "folder_policy": {"shell": {"blocklist_action": "deny"}},
                "governance_policy": {"clauses": []},
                "mcp_policy": {"servers": []},
                "approval": {"local_fallback": False,
                             "allow_requester": False},
            }
            _owner_insert_bundle(conn, info["org_id"], proj3, 1,
                                  info["bundle_signer_sk"], deny_payload)
        rp3 = _propose(c, info["base_url"], proj3,
                       {"folder_policy": {"shell": {"blocklist_action": "deny"}}},
                       info["carol_cookie"], info["carol_csrf"])
        assert rp3.status_code in (200, 201)
        pid3 = rp3.json().get("id") or rp3.json().get("proposal_id")
        d3 = c.get(
            f"{info['base_url']}/api/v1/admin/bundle-proposals/{pid3}",
            cookies={"__Host-agg_session": info["alice_cookie"]},
        )
        assert d3.status_code == 200
        assert d3.json().get("approvals_needed") == 2


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M3T4Pending)
def test_proposal_detail_base_approvals_are_served_set(t4_server):
    """SHOULD 6: detail base.change_approvals from served set;
    approvals_needed null when loosened raises."""
    require_m3(
        4,
        importlib.util.find_spec("agg_cp.sync.publish_verify") is not None,
        "publish_verify module missing (T4)",
    )
    import httpx
    info = t4_server
    conninfo = _conninfo(info["owner_url"])

    with httpx.Client(base_url=info["base_url"], timeout=30) as c:
        proj = str(uuid.uuid4())
        with psycopg.connect(conninfo, autocommit=True) as conn:
            conn.execute("SELECT set_config('app.org_id', %s, false)",
                         [info["org_id"]])
            create_project(conn, info["org_id"], proj, "BaseAppr")

        # Publish with an extra stored approval (erin, viewer role -- not copied)
        bundle = {
            "folder_policy": {"shell": {"blocklist_action": "escalate"}},
            "governance_policy": {"clauses": []},
            "mcp_policy": {"servers": []},
            "approval": {"local_fallback": True, "allow_requester": False},
        }
        r = _propose(c, info["base_url"], proj, bundle,
                     info["carol_cookie"], info["carol_csrf"])
        assert r.status_code in (200, 201)
        pid = r.json().get("id") or r.json().get("proposal_id")
        bh = r.json().get("hash") or r.json().get("bundle_hash")
        _approve(c, info["base_url"], pid,
                 _sign_approval(info["alice_sk"], bh),
                 info["alice_cookie"], info["alice_csrf"])
        _approve(c, info["base_url"], pid,
                 _sign_approval(info["bob_sk"], bh),
                 info["bob_cookie"], info["bob_csrf"])
        # Owner-insert erin's valid approval (viewer role, dropped at (g))
        erin_env = _sign_approval(info["erin_sk"], bh)
        with psycopg.connect(conninfo, autocommit=True) as conn:
            conn.execute("SELECT set_config('app.org_id', %s, false)",
                         [info["org_id"]])
            conn.execute(
                "INSERT INTO policy_change_approvals "
                "(id, org_id, change_request_id, key_id, user_id, "
                "signature, signed_at, created_at) "
                "VALUES (%s, %s::uuid, %s::uuid, %s, %s::uuid, %s, "
                "now(), now())",
                [str(uuid.uuid4()), info["org_id"], pid,
                 _kid(info["erin_sk"]), info["erin_id"],
                 json.dumps(erin_env)],
            )
        rp = _publish(c, info["base_url"], pid,
                      info["dave_cookie"], info["dave_csrf"])
        _g1_gate(rp)
        assert rp.status_code == 201
        bundle_id = rp.json().get("bundle_id")

        # Propose at base 1
        r2 = _propose(c, info["base_url"], proj,
                      {"folder_policy": {"shell": {"blocklist_action": "deny"}}},
                      info["carol_cookie"], info["carol_csrf"])
        assert r2.status_code in (200, 201)
        pid2 = r2.json().get("id") or r2.json().get("proposal_id")
        d = c.get(
            f"{info['base_url']}/api/v1/admin/bundle-proposals/{pid2}",
            cookies={"__Host-agg_session": info["alice_cookie"]},
        )
        assert d.status_code == 200
        base_approvals = d.json().get("base", {}).get("change_approvals", [])
        # Should match the rows keyed to the base bundle id (alice and bob only)
        with psycopg.connect(conninfo) as conn:
            conn.execute("SELECT set_config('app.org_id', %s, false)",
                         [info["org_id"]])
            db_rows = conn.execute(
                "SELECT key_id FROM policy_change_approvals "
                "WHERE change_request_id = %s::uuid ORDER BY key_id",
                [bundle_id],
            ).fetchall()
        db_kids = sorted(r[0] for r in db_rows)
        served_kids = sorted(
            a.get("key_id") or (a.get("signatures", [{}])[0].get("key_id", ""))
            for a in base_approvals
            if a.get("key_id") or a.get("signatures"))
        assert served_kids == db_kids, (
            f"base approvals: {served_kids} != {db_kids}")

        # Second project: test approvals_needed null when loosened raises
        proj_null = str(uuid.uuid4())
        with psycopg.connect(conninfo, autocommit=True) as conn:
            conn.execute("SELECT set_config('app.org_id', %s, false)",
                         [info["org_id"]])
            create_project(conn, info["org_id"], proj_null, "NullAN",
                           environment="prod")
            # Insert a valid server row 1
            valid_p = {
                "org_id": info["org_id"], "project_id": proj_null,
                "base_sequence": 0, "sequence": 1, "registry_version": 1,
                "issued_at": int(time.time()),
                "not_before": int(time.time()),
                "folder_policy": {"shell": {"blocklist_action": "deny"}},
                "governance_policy": {"clauses": []},
                "mcp_policy": {"servers": []},
                "approval": {"local_fallback": False,
                             "allow_requester": False},
            }
            bid_null = _owner_insert_bundle(
                conn, info["org_id"], proj_null, 1,
                info["bundle_signer_sk"], valid_p,
                verification="server")
        # Propose at base 1
        r_null = _propose(c, info["base_url"], proj_null,
                          {"folder_policy": {"shell": {"blocklist_action": "deny"}}},
                          info["carol_cookie"], info["carol_csrf"])
        assert r_null.status_code in (200, 201)
        pid_null = r_null.json().get("id") or r_null.json().get("proposal_id")
        # Corrupt the base blob so loosened raises
        with psycopg.connect(conninfo, autocommit=True) as conn:
            conn.execute("SELECT set_config('app.org_id', %s, false)",
                         [info["org_id"]])
            # Make governance_policy have clauses as a string instead of a list
            bad_p = dict(valid_p)
            bad_p["governance_policy"] = {"clauses": "not_a_list"}
            bad_env = _make_bundle_envelope(bad_p, info["bundle_signer_sk"])
            bad_blob = json.dumps(bad_env, sort_keys=True,
                                   separators=(",", ":")).encode()
            conn.execute(
                "UPDATE policy_bundles SET bundle_blob = %s "
                "WHERE id = %s::uuid",
                [bad_blob, bid_null],
            )
        d_null = c.get(
            f"{info['base_url']}/api/v1/admin/bundle-proposals/{pid_null}",
            cookies={"__Host-agg_session": info["alice_cookie"]},
        )
        assert d_null.status_code == 200
        assert d_null.json().get("approvals_needed") is None


# ===================================================================
# R4-4 read scope nodes
# ===================================================================

@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M3T4Pending)
def test_proposal_reads_viewer_404(t4_server):
    """vic (viewer): list ?project= 404, detail 404 (byte-equal to
    missing-id 404)."""
    require_m3(
        4,
        importlib.util.find_spec("agg_cp.sync.publish_verify") is not None,
        "publish_verify module missing (T4)",
    )
    import httpx
    info = t4_server
    conninfo = _conninfo(info["owner_url"])

    # Create a proposal for vic to try to read
    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        proj = str(uuid.uuid4())
        with psycopg.connect(conninfo, autocommit=True) as conn:
            conn.execute("SELECT set_config('app.org_id', %s, false)",
                         [info["org_id"]])
            create_project(conn, info["org_id"], proj, "VicRead")
        rp = _propose(c, info["base_url"], proj, {"folder_policy": {}},
                      info["alice_cookie"], info["alice_csrf"])
        assert rp.status_code in (200, 201)
        pid = rp.json().get("id") or rp.json().get("proposal_id")

        # List
        r_list = c.get(
            f"{info['base_url']}/api/v1/admin/bundle-proposals"
            f"?project={proj}",
            cookies={"__Host-agg_session": info["vic_cookie"]},
        )
        assert r_list.status_code == 404

        # Detail
        r_detail = c.get(
            f"{info['base_url']}/api/v1/admin/bundle-proposals/{pid}",
            cookies={"__Host-agg_session": info["vic_cookie"]},
        )
        assert r_detail.status_code == 404

        # Byte-equal to missing-id 404
        random_id = str(uuid.uuid4())
        r_missing = c.get(
            f"{info['base_url']}/api/v1/admin/bundle-proposals/{random_id}",
            cookies={"__Host-agg_session": info["alice_cookie"]},
        )
        assert r_missing.status_code == 404
        assert r_detail.content == r_missing.content


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M3T4Pending)
def test_proposal_reads_other_project_admin_404(t4_server):
    """pat on another project's proposal: list 404, detail 404,
    detail byte-equal to missing-id 404."""
    require_m3(
        4,
        importlib.util.find_spec("agg_cp.sync.publish_verify") is not None,
        "publish_verify module missing (T4)",
    )
    import httpx
    info = t4_server
    conninfo = _conninfo(info["owner_url"])

    # Create a proposal in project2 (pat is admin of project_id only)
    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        rp = _propose(c, info["base_url"], info["project2_id"],
                      {"folder_policy": {}},
                      info["alice_cookie"], info["alice_csrf"])
        assert rp.status_code in (200, 201)
        pid = rp.json().get("id") or rp.json().get("proposal_id")

        r_list = c.get(
            f"{info['base_url']}/api/v1/admin/bundle-proposals"
            f"?project={info['project2_id']}",
            cookies={"__Host-agg_session": info["pat_cookie"]},
        )
        assert r_list.status_code == 404

        r_detail = c.get(
            f"{info['base_url']}/api/v1/admin/bundle-proposals/{pid}",
            cookies={"__Host-agg_session": info["pat_cookie"]},
        )
        assert r_detail.status_code == 404

        # Byte-equal to missing-id 404
        random_id = str(uuid.uuid4())
        r_missing = c.get(
            f"{info['base_url']}/api/v1/admin/bundle-proposals/{random_id}",
            cookies={"__Host-agg_session": info["alice_cookie"]},
        )
        assert r_detail.content == r_missing.content


@pytest.mark.pg
def test_proposal_reads_project_admin_200(t4_server):
    """Guard: pat on own project: 200 both."""
    import httpx
    info = t4_server
    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        # Create a proposal in pat's project
        rp = _propose(c, info["base_url"], info["project_id"],
                      {"folder_policy": {}},
                      info["alice_cookie"], info["alice_csrf"])
        assert rp.status_code in (200, 201)
        pid = rp.json().get("id") or rp.json().get("proposal_id")

        r_list = c.get(
            f"{info['base_url']}/api/v1/admin/bundle-proposals"
            f"?project={info['project_id']}",
            cookies={"__Host-agg_session": info["pat_cookie"]},
        )
        assert r_list.status_code == 200

        r_detail = c.get(
            f"{info['base_url']}/api/v1/admin/bundle-proposals/{pid}",
            cookies={"__Host-agg_session": info["pat_cookie"]},
        )
        assert r_detail.status_code == 200


@pytest.mark.pg
def test_proposal_reads_counting_cli_key_200(t4_server):
    """Guard: frank (approver role, cli key) by signer token and
    by session: 200 both."""
    import httpx
    info = t4_server
    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        # Mint frank's signer token
        iat = int(time.time())
        nonce = secrets.token_hex(16)
        assertion_payload = {
            "key_id": _kid(info["frank_sk"]),
            "iat": iat,
            "nonce": nonce,
        }
        assertion_env = sign_envelope("agg/signer-assert/v1",
                                      assertion_payload, info["frank_sk"])
        r_token = c.post(
            f"{info['base_url']}/api/v1/sync/signer/token",
            json=assertion_env,
        )
        assert r_token.status_code in (200, 201), (
            f"mint frank token: {r_token.status_code} {r_token.text[:200]}")
        frank_token = r_token.json().get("token", "")

        # Create a proposal in pat's project for detail check
        rp = _propose(c, info["base_url"], info["project_id"],
                      {"folder_policy": {}},
                      info["alice_cookie"], info["alice_csrf"])
        assert rp.status_code in (200, 201)
        pid = rp.json().get("id") or rp.json().get("proposal_id")

        # List and detail with token
        r_list_t = c.get(
            f"{info['base_url']}/api/v1/admin/bundle-proposals"
            f"?project={info['project_id']}",
            headers={"Authorization": f"Bearer {frank_token}"},
        )
        assert r_list_t.status_code == 200
        r_detail_t = c.get(
            f"{info['base_url']}/api/v1/admin/bundle-proposals/{pid}",
            headers={"Authorization": f"Bearer {frank_token}"},
        )
        assert r_detail_t.status_code == 200

        # By session: list and detail
        r_list_s = c.get(
            f"{info['base_url']}/api/v1/admin/bundle-proposals"
            f"?project={info['project_id']}",
            cookies={"__Host-agg_session": info["frank_cookie"]},
        )
        assert r_list_s.status_code == 200
        r_detail_s = c.get(
            f"{info['base_url']}/api/v1/admin/bundle-proposals/{pid}",
            cookies={"__Host-agg_session": info["frank_cookie"]},
        )
        assert r_detail_s.status_code == 200


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M3T4Pending)
def test_proposal_reads_non_counting_cli_key_404(t4_server):
    """erin (role viewer) by token: 404."""
    require_m3(
        4,
        importlib.util.find_spec("agg_cp.sync.publish_verify") is not None,
        "publish_verify module missing (T4)",
    )
    import httpx
    info = t4_server
    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        # Mint erin's signer token
        iat = int(time.time())
        nonce = secrets.token_hex(16)
        assertion_payload = {
            "key_id": _kid(info["erin_sk"]),
            "iat": iat,
            "nonce": nonce,
        }
        assertion_env = sign_envelope("agg/signer-assert/v1",
                                      assertion_payload, info["erin_sk"])
        r_token = c.post(
            f"{info['base_url']}/api/v1/sync/signer/token",
            json=assertion_env,
        )
        assert r_token.status_code in (200, 201), (
            f"mint erin token: {r_token.status_code} {r_token.text[:200]}")
        erin_token = r_token.json().get("token", "")

        # List with token: 404
        r_list = c.get(
            f"{info['base_url']}/api/v1/admin/bundle-proposals"
            f"?project={info['project_id']}",
            headers={"Authorization": f"Bearer {erin_token}"},
        )
        assert r_list.status_code == 404

        # Detail with token: 404
        rp = _propose(c, info["base_url"], info["project_id"],
                      {"folder_policy": {}},
                      info["alice_cookie"], info["alice_csrf"])
        assert rp.status_code in (200, 201)
        pid = rp.json().get("id") or rp.json().get("proposal_id")
        r_detail = c.get(
            f"{info['base_url']}/api/v1/admin/bundle-proposals/{pid}",
            headers={"Authorization": f"Bearer {erin_token}"},
        )
        assert r_detail.status_code == 404

        # Also check by session (extra)
        r_list_s = c.get(
            f"{info['base_url']}/api/v1/admin/bundle-proposals"
            f"?project={info['project_id']}",
            cookies={"__Host-agg_session": info["erin_cookie"]},
        )
        assert r_list_s.status_code == 404


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M3T4Pending)
def test_proposal_reads_session_key_not_in_registry_404(t4_server):
    """MUST 11: session caller with live cli row but key absent from
    registry: 404 on list and detail."""
    require_m3(
        4,
        importlib.util.find_spec("agg_cp.sync.publish_verify") is not None,
        "publish_verify module missing (T4)",
    )
    import httpx
    info = t4_server
    conninfo = _conninfo(info["owner_url"])
    extra_sk = SigningKey.generate()
    extra_uid = str(uuid.uuid4())
    with psycopg.connect(conninfo, autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [info["org_id"]])
        conn.execute(
            "INSERT INTO users (id, org_id, oidc_issuer, oidc_subject, email, "
            "status, created_at) VALUES (%s, %s, 'https://idp.test', %s, %s, "
            "'active', now()) ON CONFLICT DO NOTHING",
            [extra_uid, info["org_id"],
             f"sub-{uuid.uuid4().hex[:8]}", "extra@t4.test"],
        )
        pub = bytes(extra_sk.verify_key)
        kid = hashlib.sha256(pub).hexdigest()
        conn.execute(
            "INSERT INTO approver_keys "
            "(id, org_id, user_id, public_key, alg, kind, key_id, roles, "
            "registry_version, enrolled_at, created_at) "
            "VALUES (%s, %s::uuid, %s::uuid, %s, 'ed25519', 'cli', %s, "
            "'[\"approver\"]'::jsonb, 1, now(), now()) ON CONFLICT DO NOTHING",
            [str(uuid.uuid4()), info["org_id"], extra_uid, pub.hex(), kid],
        )
    clock = FakeClock()
    cookie, csrf, _ = _make_fresh_session(info["owner_url"], info["org_id"],
                                           extra_uid, clock=clock)
    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        r_list = c.get(
            f"{info['base_url']}/api/v1/admin/bundle-proposals"
            f"?project={info['project_id']}",
            cookies={"__Host-agg_session": cookie},
        )
        assert r_list.status_code == 404

        # Detail should also be 404
        rp = _propose(c, info["base_url"], info["project_id"],
                      {"folder_policy": {}},
                      info["alice_cookie"], info["alice_csrf"])
        assert rp.status_code in (200, 201)
        pid = rp.json().get("id") or rp.json().get("proposal_id")
        r_detail = c.get(
            f"{info['base_url']}/api/v1/admin/bundle-proposals/{pid}",
            cookies={"__Host-agg_session": cookie},
        )
        assert r_detail.status_code == 404


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M3T4Pending)
def test_proposal_list_without_project_filters_to_readable(t4_server):
    """pat without project= sees only own project's items; with more than
    one page of other projects' rows ahead, page 1 is full."""
    require_m3(
        4,
        importlib.util.find_spec("agg_cp.sync.publish_verify") is not None,
        "publish_verify module missing (T4)",
    )
    import httpx
    info = t4_server
    conninfo = _conninfo(info["owner_url"])

    # Owner-insert 20 proposals in project_id and 21 in project2_id
    with psycopg.connect(conninfo, autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [info["org_id"]])
        for i in range(20):
            sha = hashlib.sha256(f"p1-{i}".encode()).hexdigest()
            conn.execute(
                "INSERT INTO policy_change_requests "
                "(id, org_id, project_id, proposer_user_id, base_sequence, "
                "base_sha, new_sha, payload, sequence, registry_version, "
                "status, created_at) "
                "VALUES (%s, %s::uuid, %s::uuid, %s::uuid, 0, "
                "%s, %s, %s, 1, 0, 'open', now())",
                [str(uuid.uuid4()), info["org_id"], info["project_id"],
                 info["alice_id"], sha, sha, b'{}'],
            )
        for i in range(21):
            sha = hashlib.sha256(f"p2-{i}".encode()).hexdigest()
            conn.execute(
                "INSERT INTO policy_change_requests "
                "(id, org_id, project_id, proposer_user_id, base_sequence, "
                "base_sha, new_sha, payload, sequence, registry_version, "
                "status, created_at) "
                "VALUES (%s, %s::uuid, %s::uuid, %s::uuid, 0, "
                "%s, %s, %s, 1, 0, 'open', now() + make_interval(secs => %s))",
                [str(uuid.uuid4()), info["org_id"], info["project2_id"],
                 info["alice_id"], sha, sha, b'{}', i + 1],
            )

    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        r = c.get(
            f"{info['base_url']}/api/v1/admin/bundle-proposals",
            cookies={"__Host-agg_session": info["pat_cookie"]},
        )
        assert r.status_code == 200
        items = r.json().get("items", [])
        # Every item should be in pat's project
        for item in items:
            assert item.get("project_id") == info["project_id"]
        assert len(items) == 20


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M3T4Pending)
def test_proposal_list_cursor_tie_break_on_id(t4_server):
    """SHOULD: 25 proposals with one created_at: walking next_cursor
    yields all 25, no duplicates."""
    require_m3(
        4,
        importlib.util.find_spec("agg_cp.sync.publish_verify") is not None,
        "publish_verify module missing (T4)",
    )
    import httpx
    info = t4_server
    conninfo = _conninfo(info["owner_url"])

    proj = str(uuid.uuid4())
    fixed_time = "2026-11-18 10:00:00+00"
    with psycopg.connect(conninfo, autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [info["org_id"]])
        create_project(conn, info["org_id"], proj, "CursorTie")
        for i in range(25):
            sha = hashlib.sha256(f"c-{i}".encode()).hexdigest()
            conn.execute(
                "INSERT INTO policy_change_requests "
                "(id, org_id, project_id, proposer_user_id, base_sequence, "
                "base_sha, new_sha, payload, sequence, registry_version, "
                "status, created_at) "
                "VALUES (%s, %s::uuid, %s::uuid, %s::uuid, 0, "
                "%s, %s, %s, 1, 0, 'open', %s::timestamptz)",
                [str(uuid.uuid4()), info["org_id"], proj,
                 info["alice_id"], sha, sha, b'{}', fixed_time],
            )

    collected_ids = []
    cursor = None
    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        for _ in range(10):  # max pages
            params = {"project": proj}
            if cursor:
                params["cursor"] = cursor
            r = c.get(
                f"{info['base_url']}/api/v1/admin/bundle-proposals",
                params=params,
                cookies={"__Host-agg_session": info["alice_cookie"]},
            )
            assert r.status_code == 200
            items = r.json().get("items", [])
            if not items:
                break
            for item in items:
                collected_ids.append(
                    item.get("id") or item.get("proposal_id"))
            cursor = r.json().get("next_cursor")
            if not cursor:
                break

    assert len(collected_ids) == 25, (
        f"expected 25 proposals, got {len(collected_ids)}")
    assert len(collected_ids) == len(set(collected_ids)), (
        f"duplicates found in cursor walk")


# ===================================================================
# 410 / direct publish nodes
# ===================================================================

@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M3T4Pending)
def test_direct_publish_410_without_flag(t4_server):
    """Q3: admin session, CSRF, valid body: 410 direct_publish_gone,
    no row; no cookie: 410."""
    require_m3(
        4,
        importlib.util.find_spec("agg_cp.sync.publish_verify") is not None,
        "publish_verify module missing (T4)",
    )
    import httpx
    info = t4_server
    conninfo = _conninfo(info["owner_url"])

    # Count bundles before
    before = _counts(info["owner_url"], info["org_id"], info["project_id"])

    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        r = c.post(
            f"{info['base_url']}/api/v1/admin/bundles",
            json={"project_id": info["project_id"],
                  "bundle_payload": {}, "change_approvals": []},
            cookies={"__Host-agg_session": info["alice_cookie"]},
            headers={"X-CSRF-Token": info["alice_csrf"]},
        )
        assert r.status_code == 410
        assert r.json().get("error") == "direct_publish_gone"

        # No cookie, no CSRF: also 410
        r2 = c.post(
            f"{info['base_url']}/api/v1/admin/bundles",
            json={"project_id": info["project_id"],
                  "bundle_payload": {}, "change_approvals": []},
        )
        assert r2.status_code == 410
        assert r2.json().get("error") == "direct_publish_gone"

    # No new rows
    after = _counts(info["owner_url"], info["org_id"], info["project_id"])
    assert after == before


@pytest.mark.pg
def test_direct_publish_rows_labelled_m2_unverified(t4_demo_server):
    """Guard: on demo server, direct publish row is m2_unverified,
    verified_at NULL; GET /admin/bundles/{seq} shows the label."""
    import httpx
    info = t4_demo_server
    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        r = c.post(
            f"{info['base_url']}/api/v1/admin/bundles",
            json={"project_id": info["project_id"],
                  "bundle_payload": {"folder_policy": {}},
                  "change_approvals": []},
            cookies={"__Host-agg_session": info["admin_cookie"]},
            headers={"X-CSRF-Token": info["admin_csrf"]},
        )
        assert r.status_code == 200, (
            f"direct publish: {r.status_code} {r.text[:200]}")

        # Check the row label in DB
        conninfo = _conninfo(info["owner_url"])
        with psycopg.connect(conninfo) as conn:
            conn.execute("SELECT set_config('app.org_id', %s, false)",
                         [info["org_id"]])
            row = conn.execute(
                "SELECT verification, verified_at FROM policy_bundles "
                "WHERE org_id = %s::uuid ORDER BY created_at DESC LIMIT 1",
                [info["org_id"]],
            ).fetchone()
        assert row is not None
        assert row[0] == "m2_unverified"
        assert row[1] is None

        # GET /admin/bundles/1 shows the label
        r2 = c.get(
            f"{info['base_url']}/api/v1/admin/bundles/1",
            params={"project": info["project_id"]},
            cookies={"__Host-agg_session": info["admin_cookie"]},
        )
        assert r2.status_code == 200, (
            f"GET bundles/1: {r2.status_code} {r2.text[:200]}")
        assert r2.json().get("verification") == "m2_unverified"


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M3T4Pending)
def test_direct_publish_non_admin_403_under_flag(t4_demo_server):
    """vic under the flag: 403 forbidden, no row."""
    require_m3(
        4,
        importlib.util.find_spec("agg_cp.sync.publish_verify") is not None,
        "publish_verify module missing (T4)",
    )
    import httpx
    info = t4_demo_server
    conninfo = _conninfo(info["owner_url"])
    before = _counts(info["owner_url"], info["org_id"], info["project_id"])

    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        r = c.post(
            f"{info['base_url']}/api/v1/admin/bundles",
            json={"project_id": info["project_id"],
                  "bundle_payload": {"folder_policy": {}},
                  "change_approvals": []},
            cookies={"__Host-agg_session": info["vic_cookie"]},
            headers={"X-CSRF-Token": info["vic_csrf"]},
        )
    assert r.status_code == 403
    assert r.json().get("error") == "forbidden"
    after = _counts(info["owner_url"], info["org_id"], info["project_id"])
    assert after == before


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M3T4Pending)
def test_direct_publish_noncanonical_project_400_under_flag(t4_demo_server):
    """SHOULD 4: braced project id under the flag: 400 bad_project_id,
    no row."""
    require_m3(
        4,
        importlib.util.find_spec("agg_cp.sync.publish_verify") is not None,
        "publish_verify module missing (T4)",
    )
    import httpx
    info = t4_demo_server
    conninfo = _conninfo(info["owner_url"])
    before = _counts(info["owner_url"], info["org_id"], info["project_id"])

    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        braced = "{" + info["project_id"] + "}"
        r = c.post(
            f"{info['base_url']}/api/v1/admin/bundles",
            json={"project_id": braced,
                  "bundle_payload": {"folder_policy": {}},
                  "change_approvals": []},
            cookies={"__Host-agg_session": info["admin_cookie"]},
            headers={"X-CSRF-Token": info["admin_csrf"]},
        )
    assert r.status_code == 400
    assert r.json().get("error") == "bad_project_id"
    after = _counts(info["owner_url"], info["org_id"], info["project_id"])
    assert after == before


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M3T4Pending)
def test_direct_publish_audited_under_flag(t4_demo_server):
    """SHOULD 4: 200 under flag writes one bundle.direct_publish audit row
    naming the bundle id and the user."""
    require_m3(
        4,
        importlib.util.find_spec("agg_cp.sync.publish_verify") is not None,
        "publish_verify module missing (T4)",
    )
    import httpx
    info = t4_demo_server
    conninfo = _conninfo(info["owner_url"])

    # Create a fresh project to avoid collisions with the label guard
    proj2 = str(uuid.uuid4())
    with psycopg.connect(conninfo, autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [info["org_id"]])
        create_project(conn, info["org_id"], proj2, "DemoAudit")

    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        r = c.post(
            f"{info['base_url']}/api/v1/admin/bundles",
            json={"project_id": proj2,
                  "bundle_payload": {"folder_policy": {}},
                  "change_approvals": []},
            cookies={"__Host-agg_session": info["admin_cookie"]},
            headers={"X-CSRF-Token": info["admin_csrf"]},
        )
    assert r.status_code == 200

    # Read the new bundle id from the DB for proj2
    with psycopg.connect(conninfo) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [info["org_id"]])
        brow = conn.execute(
            "SELECT id FROM policy_bundles "
            "WHERE org_id = %s::uuid AND project_id = %s::uuid "
            "ORDER BY created_at DESC LIMIT 1",
            [info["org_id"], proj2],
        ).fetchone()
    assert brow is not None
    new_bundle_id = str(brow[0])

    with psycopg.connect(conninfo) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [info["org_id"]])
        cnt = conn.execute(
            "SELECT count(*) FROM admin_audit "
            "WHERE org_id = %s::uuid "
            "AND action = 'bundle.direct_publish' "
            "AND detail->>'bundle_id' = %s",
            [info["org_id"], new_bundle_id],
        ).fetchone()[0]
    assert cnt == 1, (
        f"expected 1 bundle.direct_publish row for {new_bundle_id}, got {cnt}")
    # Verify admin_id is in the detail
    with psycopg.connect(conninfo) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [info["org_id"]])
        detail_row = conn.execute(
            "SELECT detail FROM admin_audit "
            "WHERE org_id = %s::uuid "
            "AND action = 'bundle.direct_publish' "
            "AND detail->>'bundle_id' = %s",
            [info["org_id"], new_bundle_id],
        ).fetchone()
    assert detail_row is not None
    detail = detail_row[0]
    assert info["admin_id"] in str(detail)


@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M3T4Pending)
def test_direct_publish_rechecked_per_request(t4_demo_server):
    """In-process app built with demo and flag, flag removed by monkeypatch,
    POST: 410."""
    require_m3(
        4,
        importlib.util.find_spec("agg_cp.sync.publish_verify") is not None,
        "publish_verify module missing (T4)",
    )
    import httpx
    info = t4_demo_server

    # Build in-process app with flag set, then remove
    old_profile = os.environ.get("AGG_DEPLOY_PROFILE")
    old_flag = os.environ.get("AGG_ALLOW_DIRECT_PUBLISH")
    try:
        os.environ["AGG_DEPLOY_PROFILE"] = "demo"
        os.environ["AGG_ALLOW_DIRECT_PUBLISH"] = "1"
        from agg_cp.app import create_app
        app = create_app(db_url=info["app_url"])
        # Remove the flag
        os.environ.pop("AGG_ALLOW_DIRECT_PUBLISH", None)
        from starlette.testclient import TestClient
        client = TestClient(app)
        r = client.post(
            "/api/v1/admin/bundles",
            json={"project_id": info["project_id"],
                  "bundle_payload": {}, "change_approvals": []},
        )
        assert r.status_code == 410
    finally:
        if old_profile is not None:
            os.environ["AGG_DEPLOY_PROFILE"] = old_profile
        else:
            os.environ.pop("AGG_DEPLOY_PROFILE", None)
        if old_flag is not None:
            os.environ["AGG_ALLOW_DIRECT_PUBLISH"] = old_flag
        else:
            os.environ.pop("AGG_ALLOW_DIRECT_PUBLISH", None)


# ===================================================================
# Code issue expires_at
# ===================================================================

@pytest.mark.pg
@pytest.mark.xfail(strict=True, raises=M3T4Pending)
def test_code_issue_response_expires_at_is_stored_value(t4_server):
    """Response expires_at equals the row's to the second and is about
    now + 15 min."""
    require_m3(
        4,
        importlib.util.find_spec("agg_cp.sync.publish_verify") is not None,
        "publish_verify module missing (T4)",
    )
    import httpx
    info = t4_server
    conninfo = _conninfo(info["owner_url"])
    with httpx.Client(base_url=info["base_url"], timeout=10) as c:
        r = c.post(
            f"{info['base_url']}/api/v1/admin/enrollment-codes",
            json={"project_id": info["project_id"],
                  "operator_user_id": info["dave_id"]},
            cookies={"__Host-agg_session": info["alice_cookie"]},
            headers={"X-CSRF-Token": info["alice_csrf"]},
        )
    assert r.status_code == 200
    body = r.json()
    resp_expires = body.get("expires_at")
    assert resp_expires is not None, "no expires_at in response"

    from datetime import datetime, timezone
    if isinstance(resp_expires, str):
        exp_dt = datetime.fromisoformat(resp_expires.replace("Z", "+00:00"))
    else:
        exp_dt = datetime.fromtimestamp(resp_expires, tz=timezone.utc)

    # Check it is approximately now + 15 min
    now = datetime.now(tz=timezone.utc)
    diff = (exp_dt - now).total_seconds()
    assert 600 < diff < 1200, f"expires_at diff from now: {diff}s"

    # Check that the response value matches the stored row
    code_id = body.get("id") or body.get("code_id")
    assert code_id is not None, "no code_id in response"
    with psycopg.connect(conninfo) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [info["org_id"]])
        row = conn.execute(
            "SELECT expires_at FROM enrollment_codes "
            "WHERE id = %s::uuid",
            [code_id],
        ).fetchone()
    assert row is not None, f"no enrollment_codes row for {code_id}"
    db_expires = row[0]
    if db_expires.tzinfo is None:
        db_expires = db_expires.replace(tzinfo=timezone.utc)
    assert abs((exp_dt - db_expires).total_seconds()) < 1, (
        f"response != stored: {exp_dt} vs {db_expires}")


# ===================================================================
# A-S1: constraint name pin (guard, pg, no marker, no gate)
# ===================================================================

@pytest.mark.pg
def test_policy_bundles_sequence_constraint_name_pinned(t4_server):
    """Guard (A-S1): pg_constraint holds
    policy_bundles_project_id_sequence_key on policy_bundles, contype='u',
    columns exactly (project_id, sequence) in that order.
    Passes today; bites if a migration renames or drops it."""
    conninfo = _conninfo(t4_server["owner_url"])
    with psycopg.connect(conninfo) as conn:
        row = conn.execute(
            "SELECT contype "
            "FROM pg_constraint "
            "WHERE conname = 'policy_bundles_project_id_sequence_key'",
        ).fetchone()
        assert row is not None, (
            "constraint policy_bundles_project_id_sequence_key not found")
        assert row[0] == "u", f"expected unique constraint, got {row[0]}"

        # Check columns are exactly (project_id, sequence) in that order
        cols = conn.execute(
            "SELECT array_agg(a.attname ORDER BY c.ord) "
            "FROM pg_constraint con "
            "CROSS JOIN LATERAL unnest(con.conkey) WITH ORDINALITY AS c(attnum, ord) "
            "JOIN pg_attribute a ON a.attrelid = con.conrelid "
            "  AND a.attnum = c.attnum "
            "WHERE con.conname = 'policy_bundles_project_id_sequence_key'",
        ).fetchone()
        assert cols is not None and cols[0] is not None
        assert list(cols[0]) == ["project_id", "sequence"], (
            f"expected ['project_id', 'sequence'], got {cols[0]}")
