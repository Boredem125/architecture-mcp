"""T12b-2 security re-review round 2, server side (security-engineer, leader tier).

Each strict xfail is an open finding: it asserts the safe behaviour and
raises ``T12b2R3Finding`` while the unsafe behaviour is present.  Any other
error (setup, 500) does not match ``raises=`` and fails the run, so the
markers cannot pass vacuously.  When the fix lands the test XPASSes and the
strict marker fails the run: remove the marker in the fixing change.

F2 (Medium, A01, revocation): a revoked approver key keeps read access to
   the org's escalations.  ``cli_key_lookup`` skips the revoked
   approver_keys row but falls through to the key's ``signer_links`` row,
   whose status stays 'pending' forever (nothing updates it), so
   ``POST /api/v1/sync/signer/token`` still mints a ``pending_link`` token.
   The escalation routes (``_auth_signer_or_session*``) ignore the token
   scope (F5 says a pending_link token may only reach the link route), so
   ``GET /api/v1/sync/escalations/{id}`` returns the command, cwd, root and
   ids.  The same holds for a linked key that was never put in a registry.
F3 (Low, ADR 0010 s7): GET detail does not return kind, tool_name or
   bundle_sequence, which the binding fingerprint covers and s7 says the
   signer shows.  The stored record has them.
F5 (Low, ADR 0010 s8 open question): the same key_id can be live in two
   orgs, and the pre-auth ``cli_key_lookup`` searches by key_id only with
   LIMIT 1, so the org a signer token is bound to is arbitrary.  Another
   org's admin can publish a victim's public key and break (or steer) the
   victim's signer.  Safe: the second publish is refused, or the token
   route refuses an ambiguous key_id.
F6 (Low, S5 residual): upload validates command and fingerprint types but
   not exec_cwd/root, which are now displayed; a non-string value is stored
   and served, and the web inbox render throws for the whole org.
"""
from __future__ import annotations

import hashlib
import secrets
import time
import uuid

import httpx
import psycopg
import pytest
from nacl.signing import SigningKey

from .m2_sync_server import create_org, create_project, keygen
from .test_m2_t12b2_keys import (  # noqa: F401 -- keys_server is a fixture
    _build_genesis, _build_next_version, _conninfo, _make_fresh_session,
    _make_key_entry, _seed_connector, _seed_device_token, _seed_user_row,
    keys_server,
)


class T12b2R3Finding(AssertionError):
    """Raised while an open T12b-2 round-2 re-review finding is exploitable."""


def _assertion(sk, aud: str) -> dict:
    import json
    pub = bytes(sk.verify_key)
    kid = hashlib.sha256(pub).hexdigest()
    payload = {"key_id": kid, "nonce": secrets.token_hex(16), "aud": aud,
               "iat": time.time()}
    msg = b"agg/signer-assert/v1\x00" + json.dumps(
        payload, sort_keys=True, separators=(",", ":")).encode()
    return {
        "kind": "agg/signer-assert/v1", "sig_v": 1, "payload": payload,
        "signatures": [{"key_id": kid, "alg": "ed25519",
                        "sig": sk.sign(msg).signature.hex()}],
    }


def _mint(srv, sk):
    return httpx.post(f"{srv['base_url']}/api/v1/sync/signer/token",
                      json=_assertion(sk, srv["base_url"]), timeout=10.0)


def _publish(srv, org_id, env):
    from agg_cp.sync.registry import store_registry_version
    with psycopg.connect(_conninfo(srv["app_url"])) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, true)", [org_id])
        store_registry_version(conn, org_id, env)


def _new_org(srv, name):
    org_id = str(uuid.uuid4())
    with psycopg.connect(_conninfo(srv["owner_url"]), autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        create_org(conn, org_id, name)
        bob = _seed_user_row(conn, org_id, f"bob-{org_id[:8]}@r3.test")
        op = _seed_user_row(conn, org_id, f"op-{org_id[:8]}@r3.test")
    return org_id, bob, op


def _seed_consumed_link(srv, org_id, user_id, sk):
    """The row ``signer link --code`` leaves behind (status stays 'pending')."""
    pub = bytes(sk.verify_key)
    with psycopg.connect(_conninfo(srv["owner_url"]), autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        conn.execute(
            "INSERT INTO signer_links (id, org_id, user_id, code_hash, "
            "expires_at, used_at, public_key, key_id, created_at) VALUES "
            "(%s, %s, %s, %s, now() + interval '15 min', now(), %s, %s, now())",
            [str(uuid.uuid4()), org_id, user_id,
             hashlib.sha256(secrets.token_bytes(16)).hexdigest(),
             pub.hex(), hashlib.sha256(pub).hexdigest()],
        )


def _escalation(srv, org_id, operator_id, record):
    _dsk, dpub, _dkid = keygen()
    project_id = str(uuid.uuid4())
    with psycopg.connect(_conninfo(srv["owner_url"]), autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        create_project(conn, org_id, project_id, environment="staging")
    device_id = _seed_connector(srv["owner_url"], org_id, project_id, dpub,
                                operator_user_id=operator_id)
    token = secrets.token_hex(32)
    _seed_device_token(srv["owner_url"], org_id, project_id, device_id, token)
    r = httpx.post(
        f"{srv['base_url']}/api/v1/sync/escalations",
        json={"device_id": device_id, "request_id": f"req-r3-{uuid.uuid4().hex[:8]}",
              "policy_sequence": 1, "record": record},
        headers={"Authorization": f"Bearer {token}"}, timeout=10.0,
    )
    assert r.status_code == 200, r.text
    return r.json()["escalation_id"]


def _detail(srv, esc_id, token):
    return httpx.get(f"{srv['base_url']}/api/v1/sync/escalations/{esc_id}",
                     headers={"Authorization": f"Bearer {token}"}, timeout=10.0)


# ---------------------------------------------------------------------------
# F2: a revoked key still reads escalation detail
# ---------------------------------------------------------------------------

@pytest.mark.pg
def test_f2_revoked_key_cannot_read_escalation_detail(keys_server):
    srv = keys_server
    org_id, bob_uid, op_uid = _new_org(srv, "R3 Revoke Org")
    alice_sk, bob_sk = SigningKey.generate(), SigningKey.generate()
    bob_entry, _ = _make_key_entry(bob_sk, user_id=bob_uid, sub=bob_uid,
                                   roles=["approver"])
    genesis, _keys, admins, _fp = _build_genesis(
        org_id, [alice_sk], extra_keys=[(bob_entry, bob_sk)])
    _publish(srv, org_id, genesis)
    _seed_consumed_link(srv, org_id, bob_uid, bob_sk)
    esc_id = _escalation(srv, org_id, op_uid, {
        "command": "git push --force", "status": "pending",
        "fingerprint": "e" * 64, "exec_cwd": "/srv/r3", "root": "/srv/r3"})

    # Precondition: while bob is live his signer token reads the detail.
    r = _mint(srv, bob_sk)
    assert r.status_code == 200, r.text
    d = _detail(srv, esc_id, r.json()["token"])
    assert d.status_code == 200, d.text

    # v2 removes bob: revoked in the registry and in approver_keys.
    alice_entry = [k for k in genesis["payload"]["keys"] if k["key_id"] in admins][0]
    _publish(srv, org_id, _build_next_version(
        org_id, genesis["payload"], [alice_sk], [alice_entry], version=2))

    r2 = _mint(srv, bob_sk)
    if r2.status_code != 200:
        return  # safe: no token for a revoked key
    d2 = _detail(srv, esc_id, r2.json()["token"])
    assert d2.status_code != 500, d2.text
    if d2.status_code == 200:
        raise T12b2R3Finding(
            "revoked key minted a fresh signer token (signer_links fallback, "
            "pending_link scope ignored) and read escalation detail: "
            f"{sorted(d2.json())}")


# ---------------------------------------------------------------------------
# F3: GET detail omits kind, tool_name, bundle_sequence (ADR 0010 s7)
# ---------------------------------------------------------------------------

@pytest.mark.pg
def test_f3_detail_returns_every_fingerprint_field(keys_server):
    srv = keys_server
    org_id, bob_uid, op_uid = _new_org(srv, "R3 Fields Org")
    alice_sk, bob_sk = SigningKey.generate(), SigningKey.generate()
    bob_entry, _ = _make_key_entry(bob_sk, user_id=bob_uid, sub=bob_uid,
                                   roles=["approver"])
    genesis, *_ = _build_genesis(org_id, [alice_sk],
                                 extra_keys=[(bob_entry, bob_sk)])
    _publish(srv, org_id, genesis)
    esc_id = _escalation(srv, org_id, op_uid, {
        "command": "deploy.sh", "status": "pending", "fingerprint": "f" * 64,
        "kind": "tool_call", "tool_name": "mcp__deploy__run",
        "bundle_sequence": 1, "requires_dual": True,
        "exec_cwd": "/srv/r3", "root": "/srv/r3"})
    r = _mint(srv, bob_sk)
    assert r.status_code == 200, r.text
    d = _detail(srv, esc_id, r.json()["token"])
    assert d.status_code == 200, d.text
    body = d.json()
    missing = [k for k in ("kind", "tool_name", "bundle_sequence") if k not in body]
    if missing:
        raise T12b2R3Finding(
            f"GET detail omits fingerprint-bound fields {missing}; the signer "
            "cannot show them (ADR 0010 s7)")


# ---------------------------------------------------------------------------
# F5: one key_id live in two orgs
# ---------------------------------------------------------------------------

@pytest.mark.pg
def test_f5_key_id_live_in_two_orgs_is_refused(keys_server):
    from sandbox.protocol.registry import RegistryError

    srv = keys_server
    org_a, bob_a, _op_a = _new_org(srv, "R3 Victim Org")
    org_b, eve_b, _op_b = _new_org(srv, "R3 Squatter Org")
    victim_sk = SigningKey.generate()

    entry_a, _ = _make_key_entry(victim_sk, user_id=bob_a, sub=bob_a,
                                 roles=["approver"])
    gen_a, *_ = _build_genesis(org_a, [SigningKey.generate()],
                               extra_keys=[(entry_a, victim_sk)])
    _publish(srv, org_a, gen_a)

    # Org B's admin publishes the victim's PUBLIC key under eve.
    entry_b, _ = _make_key_entry(victim_sk, user_id=eve_b, sub=eve_b,
                                 roles=["approver"])
    gen_b, *_ = _build_genesis(org_b, [SigningKey.generate()],
                               extra_keys=[(entry_b, victim_sk)])
    try:
        _publish(srv, org_b, gen_b)
    except (RegistryError, psycopg.Error):
        return  # safe: a key_id live in another org is refused

    r = _mint(srv, victim_sk)
    assert r.status_code != 500, r.text
    if r.status_code == 200:
        raise T12b2R3Finding(
            "key_id is live in two orgs and the signer token route bound it "
            "to one of them arbitrarily (cli_key_lookup LIMIT 1 by key_id)")


# ---------------------------------------------------------------------------
# F6: non-string exec_cwd / root are stored and served (S5 residual)
# ---------------------------------------------------------------------------

@pytest.mark.pg
def test_f6_non_string_exec_cwd_root_refused(keys_server):
    """S5 checked command and fingerprint only.  exec_cwd and root are now
    displayed too: InboxSection calls renderEscalationText(esc.exec_cwd),
    i.e. ``.replace`` on an object, and the inbox render throws."""
    srv = keys_server
    org_id, _bob, op_uid = _new_org(srv, "R3 Types Org")
    _dsk, dpub, _dkid = keygen()
    project_id = str(uuid.uuid4())
    with psycopg.connect(_conninfo(srv["owner_url"]), autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        create_project(conn, org_id, project_id, environment="staging")
    device_id = _seed_connector(srv["owner_url"], org_id, project_id, dpub,
                                operator_user_id=op_uid)
    token = secrets.token_hex(32)
    _seed_device_token(srv["owner_url"], org_id, project_id, device_id, token)
    r = httpx.post(
        f"{srv['base_url']}/api/v1/sync/escalations",
        json={"device_id": device_id, "request_id": "req-r3-f6-1",
              "policy_sequence": 1,
              "record": {"command": "echo test", "fingerprint": "a" * 64,
                         "exec_cwd": {"toString": 1}, "root": ["x"]}},
        headers={"Authorization": f"Bearer {token}"}, timeout=10.0,
    )
    assert r.status_code != 500, r.text
    if r.status_code == 200:
        raise T12b2R3Finding(
            "upload stored a non-string exec_cwd/root; the web inbox calls "
            ".replace on it and the render throws for the whole org")
