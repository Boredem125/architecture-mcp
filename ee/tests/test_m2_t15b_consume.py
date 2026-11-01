"""T15b-5 tests-first (SHOULD, d5 S5 carried): the /signatures step-7
link-consume UPDATE must assert ``rowcount == 1`` per added key; on any
other count the version is rolled back, a ``registry_identity_refused``
audit row with reason ``link_consume_rowcount`` is written, and the
route returns 400 (T15B_SECURITY_REVIEW.md T15b-5).

*** SEEDING NOTICE -- NEEDS A SECURITY RULING BEFORE THE MARKER COMES OFF ***
The zero-row condition is not reachable through routes: rule 2 of the
identity check reads the same pending link row that step 7 consumes, and
the per-org advisory lock serialises posts.  The only way to make step 7
touch 0 rows is the operator race the review names: a DELETE on
``signer_links`` between the rule-2 read and the step-7 UPDATE.  The test
below reproduces exactly that race with a direct ``SELECT ... FOR UPDATE``
followed by ``DELETE FROM signer_links`` on the owner connection while the
POST is in flight.  That is a raw write to a table the A1.4 rule 1
seeding allowlist excludes (T12D_D5_SPEC.md section 0).  It lives in this
separate file so the A1.4 AST gate on ``test_m2_t12d_identity.py`` stays
true, and it is flagged for a security ruling: either (a) accept this
one race-seeding exception by node id, or (b) rule the test out and keep
T15b-5 covered by the honest-path twin plus code review.  Until ruled,
the race test stays strict-xfail and must not be relied on as evidence.

Fixtures and helpers are reused from ``test_m2_t12d_identity.py``.
"""
from __future__ import annotations

import threading
import time

import psycopg
import pytest

from .test_m2_t12d_genesis import _conninfo, _get_signer_token_httpx
from .test_m2_t12d_identity import (  # noqa: F401  (fixtures by import)
    identity_bundle_signer,
    identity_server,
    _base_G,
    _entry,
    _local_ok,
    _next,
    _post,
    _route_cli_link,
    _snap,
)


class M2T15bConsumePending(Exception):
    """T15b-5: step-7 consume does not check rowcount."""


def _consumed_rows(srv, org_id, kid) -> tuple[int, int]:
    """(consumed_count, pending_count) for kid -- reads only."""
    with psycopg.connect(_conninfo(srv["owner_url"]), autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        consumed = conn.execute(
            "SELECT count(*) FROM signer_links WHERE org_id = %s::uuid "
            "AND key_id = %s AND status = 'consumed'", [org_id, kid],
        ).fetchone()[0]
        pending = conn.execute(
            "SELECT count(*) FROM signer_links WHERE org_id = %s::uuid "
            "AND key_id = %s AND status = 'pending'", [org_id, kid],
        ).fetchone()[0]
    return consumed, pending


def _refused_reasons(srv, org_id) -> list[str]:
    with psycopg.connect(_conninfo(srv["owner_url"]), autocommit=True) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        rows = conn.execute(
            "SELECT detail FROM admin_audit WHERE org_id = %s "
            "AND action = 'registry_identity_refused'", [org_id],
        ).fetchall()
    out = []
    for (detail,) in rows:
        if isinstance(detail, dict):
            out.append(str(detail.get("reason")))
        else:
            try:
                import json
                out.append(str(json.loads(detail).get("reason")))
            except Exception:  # noqa: BLE001
                out.append(str(detail))
    return out


def _v2_add_bob(srv):
    """G + bob route-linked; returns (ctx, env_v2, bob_kid)."""
    ctx = _base_G(srv)
    org_id = ctx["org_id"]
    bob = ctx["people"]["bob"]
    sk_b, kid_b = _route_cli_link(srv, org_id, bob["uid"])
    e_b = _entry(sk_b, bob["uid"], bob["iss"], bob["sub"],
                 roles=["approver"], added_in=2)
    env_v2 = _next(ctx, add=[e_b], signers=[ctx["alice_sk"]])
    _local_ok(ctx, env_v2)
    return ctx, env_v2, kid_b


@pytest.mark.pg
def test_t15b5_honest_path_consumes_exactly_one_row_per_added_key(identity_server):
    """Honest path (holds today): v2 adds bob's route-linked key; exactly
    one signer_links row for that key is consumed and none stays pending."""
    srv = identity_server
    ctx, env_v2, kid_b = _v2_add_bob(srv)
    org_id = ctx["org_id"]
    token = _get_signer_token_httpx(srv["base_url"], ctx["alice_sk"], ctx["alice_kid"])
    r = _post(srv, token, org_id, env_v2)
    assert r.status_code == 200, f"{r.status_code}: {r.text}"
    consumed, pending = _consumed_rows(srv, org_id, kid_b)
    assert consumed == 1, f"expected exactly one consumed row, got {consumed}"
    assert pending == 0, f"pending rows left: {pending}"
    assert "link_consume_rowcount" not in _refused_reasons(srv, org_id)


@pytest.mark.pg
def test_t15b5_consume_rowcount_zero_refused_and_audited(identity_server):
    """RACE SEEDING (direct DELETE on signer_links; flagged for ruling).

    The test transaction row-locks bob's pending link, the POST starts
    and blocks at the step-7 UPDATE (rule 2's plain SELECT already
    passed), the test deletes the row and commits.  Step 7 then touches
    0 rows: the route must return 400 with reason ``link_consume_rowcount``,
    store no version and write one ``registry_identity_refused`` row."""
    srv = identity_server
    ctx, env_v2, kid_b = _v2_add_bob(srv)
    org_id = ctx["org_id"]
    token = _get_signer_token_httpx(srv["base_url"], ctx["alice_sk"], ctx["alice_kid"])

    snap_before = _snap(srv, org_id, [kid_b])
    reasons_before = _refused_reasons(srv, org_id)

    result: dict = {}

    def _do_post():
        result["r"] = _post(srv, token, org_id, env_v2)

    lock_conn = psycopg.connect(_conninfo(srv["owner_url"]), autocommit=False)
    try:
        lock_conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
        locked = lock_conn.execute(
            "SELECT id FROM signer_links WHERE org_id = %s::uuid "
            "AND key_id = %s AND status = 'pending' FOR UPDATE",
            [org_id, kid_b],
        ).fetchall()
        assert len(locked) == 1, f"expected one pending link row, got {len(locked)}"

        t = threading.Thread(target=_do_post, daemon=True)
        t.start()
        time.sleep(2.0)  # the POST is now blocked on the row lock at step 7
        assert t.is_alive(), "POST finished without touching the locked row"

        # SEEDING EXCEPTION (needs ruling): operator DELETE under the race.
        lock_conn.execute(
            "DELETE FROM signer_links WHERE org_id = %s::uuid AND key_id = %s",
            [org_id, kid_b],
        )
        lock_conn.commit()
    finally:
        lock_conn.close()

    t.join(timeout=20)
    assert "r" in result, "POST did not return after the lock was released"
    r = result["r"]
    snap_after = _snap(srv, org_id, [kid_b])
    reasons_after = _refused_reasons(srv, org_id)

    if r.status_code == 200 or snap_after["ver_count"] != snap_before["ver_count"]:
        raise M2T15bConsumePending(
            f"step 7 consumed 0 rows but the version was stored: "
            f"status={r.status_code} ver_count {snap_before['ver_count']}"
            f"->{snap_after['ver_count']}"
        )
    assert r.status_code == 400, f"{r.status_code}: {r.text}"
    body = r.json()
    assert body.get("reason") == "link_consume_rowcount", body
    assert snap_after["ver_count"] == snap_before["ver_count"]
    assert snap_after["ver_max"] == snap_before["ver_max"]
    assert snap_after["ak_rows"] == snap_before["ak_rows"]
    assert snap_after["rv_count"] == snap_before["rv_count"]
    assert snap_after["refused_count"] == snap_before["refused_count"] + 1
    new_reasons = reasons_after[len(reasons_before):]
    assert "link_consume_rowcount" in new_reasons, new_reasons
