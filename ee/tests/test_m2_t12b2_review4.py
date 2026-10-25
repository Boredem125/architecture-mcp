"""T12b-2 security re-review round 3, server side (security-engineer, leader tier).

Each strict xfail is an open finding: it asserts the safe behaviour and
raises ``T12b2R4Finding`` while the unsafe behaviour is present.  Any other
error (setup, 500) does not match ``raises=`` and fails the run, so the
marker cannot pass vacuously.  When the fix lands the test XPASSes and the
strict marker fails the run: remove the marker in the fixing change.

F7 (Medium, A01 cross-tenant, new in the 0012 fix for F5):
   ``check_key_id_cross_org`` treats any other org's ``signer_links`` row
   with a public_key as a conflict, and ``store_registry_version`` calls it
   for EVERY key in EVERY version.  ``signer_links`` rows are unverified
   claims: ``POST /api/v1/signer-links`` with ``kind=browser`` lets any
   session user insert one with any key_id and public_key (no proof of
   possession, no key_id == sha256(public_key) check, no cross-org check,
   and the row's expiry is ignored by the check).  So a non-admin user in
   org B who knows one key_id in org A's registry (key_ids are in every
   approval record and evidence pack) makes org A's next publish raise, and
   org A cannot publish a version that revokes a DIFFERENT, compromised key
   until it also drops the squatted key.  The refusal message also tells
   org A that the key exists in another tenant.
   Safe: another org's unverified signer_links row never vetoes a signed
   registry publish (the publish check counts only other orgs' live
   approver_keys rows), or the browser link route refuses the row.

The guard ``test_guard_publish_of_key_live_in_other_org_raises`` is the
d0 condition "a test that the publish itself raises": the round-2 F5 proof
returns early on a raise and would also pass if only the token route
refused, so it does not pin the publish check on its own.
"""
from __future__ import annotations

import uuid

import httpx
import psycopg
import pytest
from nacl.signing import SigningKey

from .m2_sync_server import create_org
from .test_m2_t12b2_keys import (  # noqa: F401 -- keys_server is a fixture
    _build_genesis, _build_next_version, _conninfo, _make_fresh_session,
    _make_key_entry, _seed_user_row, keys_server,
)


class T12b2R4Finding(AssertionError):
    """Raised while an open T12b-2 round-3 re-review finding is exploitable."""


def _publish(srv, org_id, env):
    from agg_cp.sync.registry import store_registry_version
    with psycopg.connect(_conninfo(srv["app_url"])) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, true)", [org_id])
        store_registry_version(conn, org_id, env)


def _new_org(srv, name, n_users=1):
    org_id = str(uuid.uuid4())
    with psycopg.connect(_conninfo(srv["owner_url"]), autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        create_org(conn, org_id, name)
        users = [_seed_user_row(conn, org_id, f"u{i}-{org_id[:8]}@r4.test")
                 for i in range(n_users)]
    return org_id, users


def _live_key_ids(srv, org_id):
    with psycopg.connect(_conninfo(srv["owner_url"])) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        rows = conn.execute(
            "SELECT key_id FROM approver_keys WHERE org_id = %s::uuid "
            "AND revoked_at IS NULL", [org_id]).fetchall()
    return {r[0] for r in rows}


@pytest.mark.pg
def test_guard_publish_of_key_live_in_other_org_raises(keys_server):
    """Guard (passes today): the publish itself refuses a key_id that is a
    live approver key in another org's signed registry."""
    from sandbox.protocol.registry import RegistryError

    srv = keys_server
    org_a, (bob_a,) = _new_org(srv, "R4 Guard A")
    org_b, (eve_b,) = _new_org(srv, "R4 Guard B")
    victim = SigningKey.generate()
    entry_a, _ = _make_key_entry(victim, user_id=bob_a, sub=bob_a,
                                 roles=["approver"])
    gen_a, *_ = _build_genesis(org_a, [SigningKey.generate()],
                               extra_keys=[(entry_a, victim)])
    _publish(srv, org_a, gen_a)

    entry_b, _ = _make_key_entry(victim, user_id=eve_b, sub=eve_b,
                                 roles=["approver"])
    gen_b, *_ = _build_genesis(org_b, [SigningKey.generate()],
                               extra_keys=[(entry_b, victim)])
    with pytest.raises(RegistryError):
        _publish(srv, org_b, gen_b)
    assert entry_a["key_id"] not in _live_key_ids(srv, org_b)


@pytest.mark.pg
def test_f7_other_org_browser_link_cannot_block_revocation(keys_server):
    from sandbox.protocol.registry import RegistryError

    srv = keys_server
    org_a, (bob_a, carol_a) = _new_org(srv, "R4 Victim Org", n_users=2)
    org_b, (eve_b,) = _new_org(srv, "R4 Squatter Org")

    alice_sk, bob_sk, carol_sk = (SigningKey.generate() for _ in range(3))
    bob_entry, _ = _make_key_entry(bob_sk, user_id=bob_a, sub=bob_a,
                                   roles=["approver"])
    carol_entry, _ = _make_key_entry(carol_sk, user_id=carol_a, sub=carol_a,
                                     roles=["approver"])
    genesis, keys, admins, _fp = _build_genesis(
        org_a, [alice_sk],
        extra_keys=[(bob_entry, bob_sk), (carol_entry, carol_sk)])
    _publish(srv, org_a, genesis)
    assert carol_entry["key_id"] in _live_key_ids(srv, org_a)

    # Eve, an ordinary session user in org B, posts bob's PUBLIC key as a
    # browser key in her own org.  No admin role, no private key needed.
    cookie, csrf = _make_fresh_session(srv["owner_url"], org_b, eve_b)
    r = httpx.post(
        f"{srv['base_url']}/api/v1/signer-links",
        cookies={"__Host-agg_session": cookie},
        headers={"X-CSRF-Token": csrf},
        json={"public_key": bob_entry["public_key"],
              "key_id": bob_entry["key_id"], "kind": "browser"},
        timeout=10.0,
    )
    assert r.status_code != 500, r.text
    if r.status_code not in (200, 201):
        # Round 4: the browser route now refuses (409).  Keep the publish
        # check live: seed the same unverified row directly, as a link made
        # before bob's key went live in org A (a pre-squat) would leave it.
        assert r.status_code == 409, r.text
        with psycopg.connect(_conninfo(srv["owner_url"]), autocommit=True) as c:
            c.execute("SELECT set_config('app.org_id', %s, false)", [org_b])
            c.execute(
                "INSERT INTO signer_links (id, org_id, user_id, code_hash, "
                "expires_at, used_at, public_key, key_id, created_at) VALUES "
                "(%s, %s, %s, %s, now() + interval '15 min', now(), %s, %s, "
                "now())",
                [str(uuid.uuid4()), org_b, eve_b, uuid.uuid4().hex * 2,
                 bob_entry["public_key"], bob_entry["key_id"]],
            )

    # Org A's admin revokes carol's (say, compromised) key; bob stays.
    alice_entry = [k for k in keys if k["key_id"] in admins][0]
    v2 = _build_next_version(org_a, genesis["payload"], [alice_sk],
                             [alice_entry, bob_entry], version=2)
    try:
        _publish(srv, org_a, v2)
    except (RegistryError, psycopg.Error) as exc:
        still_live = carol_entry["key_id"] in _live_key_ids(srv, org_a)
        raise T12b2R4Finding(
            "org B user's unverified browser link made org A's signed "
            f"revocation publish fail ({exc}); carol's key still live: "
            f"{still_live}")
    assert carol_entry["key_id"] not in _live_key_ids(srv, org_a)
