"""T16h tests-first: the control plane refuses a publish whose approvals
include the publishing admin (ADR 0001 Amendment A2 (4 Nov), M2_DEMO 7.6).

Spec (security L ruling, Amendment A2 item 1):

  - ``POST /api/v1/admin/bundles`` refuses 400 ``proposer_in_approvals``,
    storing nothing, when any element of ``change_approvals`` resolves
    through ``cli_key_lookup`` (Amendment A1 item 1; covers pending
    ``signer_links``) to the publishing session's ``user_id``.
  - A second key held by the same user resolves to the same ``user_id``
    and is refused the same way.
  - A publish by a third admin (no key among the approvals) with two
    other approvers is 200 and stored.

The targets were strict xfail (tests first); they pass since T16h landed
the refusal in ``admin_create_bundle`` (4 Nov 2026).

Fixture style copied from ``test_m2_t16b_change_approvals.py``.
Marked ``pg`` (requires Postgres via testcontainers).
"""
from __future__ import annotations

import os
import time
import uuid

import pytest
from nacl.signing import SigningKey

from .m2_sync_server import make_sync_server, create_project
from .test_m2_t16b_change_approvals import (
    _conninfo, _seed_user_row, _make_fresh_session, _make_change_approval,
    _post_bundle, _route_cli_link,
)


# ---------------------------------------------------------------------------
# Module-scoped server fixture
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def t16h_server(pg_url, app_url, owner_url, pg_roles, tmp_path_factory):
    """4-worker agg_cp server for T16h tests.

    Seeds: org, project, alice (admin), admin2 (admin), bob (admin, never
    links a CLI key).  Bundle signer key file in env.
    """
    import psycopg

    bundle_signer_sk = SigningKey.generate()
    key_dir = tmp_path_factory.mktemp("t16h_bundle_signer")
    key_file = key_dir / "bundle_signer.key"
    key_file.write_bytes(bytes(bundle_signer_sk).hex().encode("ascii"))
    old_bs = os.environ.get("AGG_BUNDLE_SIGNER_KEY_FILE")
    os.environ["AGG_BUNDLE_SIGNER_KEY_FILE"] = str(key_file)

    gen = make_sync_server(
        pg_url, app_url, owner_url,
        org_names=["T16h Org"],
    )
    info = next(gen)

    conninfo = _conninfo(owner_url)
    with psycopg.connect(conninfo, autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [info["org_id"]])
        alice_id = _seed_user_row(conn, info["org_id"], "alice@t16h.test")
        admin2_id = _seed_user_row(conn, info["org_id"], "admin2@t16h.test")
        bob_id = _seed_user_row(conn, info["org_id"], "bob@t16h.test")

        for uid in (alice_id, admin2_id, bob_id):
            conn.execute(
                "INSERT INTO role_bindings "
                "(id, org_id, user_id, scope_type, scope_id, role, created_at) "
                "VALUES (%s, %s, %s, 'org', %s, 'admin', now())",
                [str(uuid.uuid4()), info["org_id"], uid, info["org_id"]],
            )

        project_id = str(uuid.uuid4())
        create_project(conn, info["org_id"], project_id, "T16h Project")

    info["alice_id"] = alice_id
    info["admin2_id"] = admin2_id
    info["bob_id"] = bob_id
    info["project_id"] = project_id

    try:
        yield info
    finally:
        gen.close()
        if old_bs is None:
            os.environ.pop("AGG_BUNDLE_SIGNER_KEY_FILE", None)
        else:
            os.environ["AGG_BUNDLE_SIGNER_KEY_FILE"] = old_bs


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _bundle_payload(org_id, project_id, sequence):
    return {
        "org_id": org_id,
        "project_id": project_id,
        "sequence": sequence,
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


def _counts(srv, sequence):
    """Return (policy_bundles rows at sequence, policy_change_approvals
    rows in the org)."""
    import psycopg
    with psycopg.connect(_conninfo(srv["owner_url"]), autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)",
                     [srv["org_id"]])
        n_bundles = conn.execute(
            "SELECT count(*) FROM policy_bundles "
            "WHERE project_id = %s::uuid AND sequence = %s",
            [srv["project_id"], sequence],
        ).fetchone()[0]
        n_appr = conn.execute(
            "SELECT count(*) FROM policy_change_approvals "
            "WHERE org_id = %s::uuid",
            [srv["org_id"]],
        ).fetchone()[0]
    return n_bundles, n_appr


def _assert_refused_proposer(srv, r, sequence, appr_before):
    assert r.status_code == 400, (
        f"expected 400, got {r.status_code}: {r.text[:200]}"
    )
    assert r.json().get("error") == "proposer_in_approvals", r.text
    n_bundles, n_appr = _counts(srv, sequence)
    assert n_bundles == 0, f"bundle stored at seq {sequence}"
    assert n_appr == appr_before, "policy_change_approvals count changed"


# ===================================================================
# T16h-1: the publishing admin's own key among the approvals is refused
# ===================================================================


@pytest.mark.pg
def test_publish_refuses_proposer_among_approvals(t16h_server):
    """alice publishes; approvals from alice's CLI key + admin2's.
    400 proposer_in_approvals; no bundle row; approvals count unchanged."""
    srv = t16h_server
    org_id, project_id = srv["org_id"], srv["project_id"]
    seq = 101

    alice_sk, _ = _route_cli_link(srv, org_id, srv["alice_id"])
    admin2_sk, _ = _route_cli_link(srv, org_id, srv["admin2_id"])
    bp = _bundle_payload(org_id, project_id, seq)
    approvals = [_make_change_approval(alice_sk, bp),
                 _make_change_approval(admin2_sk, bp)]

    _, appr_before = _counts(srv, seq)
    cookie, csrf = _make_fresh_session(srv["owner_url"], org_id,
                                       srv["alice_id"])
    r = _post_bundle(srv, cookie, csrf, project_id, bp, approvals)
    _assert_refused_proposer(srv, r, seq, appr_before)


# ===================================================================
# T16h-2: a second key held by the publishing admin does not dodge it
# ===================================================================


@pytest.mark.pg
def test_publish_refuses_proposer_via_second_key(t16h_server):
    """alice links two CLI keys (both pending signer_links on the same
    user_id).  Approvals from the SECOND key + admin2; publish by alice.
    Same refusal: cli_key_lookup resolves both keys to alice's user_id."""
    import psycopg

    srv = t16h_server
    org_id, project_id = srv["org_id"], srv["project_id"]
    seq = 102

    _first_sk, first_kid = _route_cli_link(srv, org_id, srv["alice_id"])
    second_sk, second_kid = _route_cli_link(srv, org_id, srv["alice_id"])
    assert first_kid != second_kid

    # Fixture self-check (not the target): both keys resolve to alice.
    with psycopg.connect(_conninfo(srv["owner_url"]), autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        owners = {
            conn.execute("SELECT user_id FROM cli_key_lookup(%s)",
                         [k]).fetchone()[0]
            for k in (first_kid, second_kid)
        }
    assert owners == {srv["alice_id"]}, (
        f"fixture: second key not linked to alice: {owners}"
    )

    admin2_sk, _ = _route_cli_link(srv, org_id, srv["admin2_id"])
    bp = _bundle_payload(org_id, project_id, seq)
    approvals = [_make_change_approval(second_sk, bp),
                 _make_change_approval(admin2_sk, bp)]

    _, appr_before = _counts(srv, seq)
    cookie, csrf = _make_fresh_session(srv["owner_url"], org_id,
                                       srv["alice_id"])
    r = _post_bundle(srv, cookie, csrf, project_id, bp, approvals)
    _assert_refused_proposer(srv, r, seq, appr_before)


# ===================================================================
# GUARD TWIN (non-xfail): a third admin with two other approvers is 200
# ===================================================================


@pytest.mark.pg
def test_guard_publish_by_third_admin_accepts_two_approvers(t16h_server):
    """bob (admin, no CLI key) publishes; alice + admin2 approve.
    200 and the bundle row plus two approval rows are stored."""
    import psycopg

    srv = t16h_server
    org_id, project_id = srv["org_id"], srv["project_id"]
    seq = 103

    alice_sk, alice_kid = _route_cli_link(srv, org_id, srv["alice_id"])
    admin2_sk, admin2_kid = _route_cli_link(srv, org_id, srv["admin2_id"])
    bp = _bundle_payload(org_id, project_id, seq)
    approvals = [_make_change_approval(alice_sk, bp),
                 _make_change_approval(admin2_sk, bp)]

    cookie, csrf = _make_fresh_session(srv["owner_url"], org_id,
                                       srv["bob_id"])
    r = _post_bundle(srv, cookie, csrf, project_id, bp, approvals)
    assert r.status_code == 200, f"publish failed: {r.status_code} {r.text}"
    bundle_id = r.json()["bundle_id"]

    n_bundles, _ = _counts(srv, seq)
    assert n_bundles == 1
    with psycopg.connect(_conninfo(srv["owner_url"]), autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        rows = conn.execute(
            "SELECT key_id FROM policy_change_approvals "
            "WHERE change_request_id = %s::uuid", [bundle_id],
        ).fetchall()
    assert len(rows) == 2, f"expected exactly 2 approval rows, got {len(rows)}"
    assert {row[0] for row in rows} == {alice_kid, admin2_kid}
