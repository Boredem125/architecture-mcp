# T12d d5 spec: R2-4 identity binding (ADR 0011 A1) and the d4-review items

Author: security-engineer (leader tier, Opus 5.5), 30 Oct 2026. Read-only on code; this is the only file written.
Inputs: ADR 0011 A1.1-A1.5; `T12B_PLAN.md` d5 row; `T12D_D4_SECURITY_REVIEW.md` round 2 (R2-4) and round 3; `ee/src/agg_cp/sync/signer.py` (link, `/signatures`, genesis, `/candidates`, `/registry`), `ee/src/agg_cp/sync/registry.py`, `ee/src/agg_cp/web/browser_keys.py`, migrations 0002/0007/0012/0015, `src/sandbox/protocol/registry.py`, `src/sandbox/connector/approval.py`, the d4 e2e helpers and the genesis fixtures.
Audience: qa (W) writes every test below without a design call; backend (W) builds section 5 without guessing. Anything not covered here goes to security, not to a guess.

## 0. Conventions (all sections)

- **Tests first, strict xfail.** Each new file defines its own sentinel (`class M2T12dIdentityPending(Exception)` in the ee file; reuse `M2T12dPending` in the CLI file). A bypass test that gets the pre-build answer (usually 200) raises the sentinel before its status assertion; it is marked `@pytest.mark.xfail(strict=True, raises=<sentinel>)`. The marker is removed when the test passes. Column "today" below says which tests carry the marker (`xf`) and which must pass now (`pass`).
- **Pins and twins that hold today are plain tests** (no marker). A twin needs a marker only if it asserts new behaviour (consumption, audit rows, `kind`).
- **A1.4 rule 1 (server tests in section 1 and the e2e in section 2).** No `store_registry_version` call and no raw INSERT/UPDATE/DELETE on `key_registry_versions`, `approver_keys` or `signer_links`. Allowed seeding: `users` (incl. `status`), `role_bindings`, `projects`, `web_sessions` (via `seed_session`), `setup_codes` (genesis code). Reads of any table are allowed. The existing `_create_signer_link` / `_d4_create_signer_link` raw INSERTs are **not** allowed in the new file.
- **One fresh org per test** (`_fresh_org`), so chains never interact.

### 0.1 Fixture and helpers for `ee/tests/test_m2_t12d_identity.py`

Import with relative imports from `.test_m2_t12d_genesis`: `_conninfo`, `_seed_user_row`, `_grant_role`, `_make_fresh_session`, `_kid`, `_get_signer_token_httpx`, `_seed_genesis_code`, `_fresh_org`, `_build_genesis_envelope` (always pass `bundle_signer_pub=` explicitly; that module's global is not set from here). From `.t9_helpers`: `seed_session`, `make_session_cookie`; from `.fake_idp`: `FakeClock`.

| Helper (new, in the identity file) | Exact behaviour |
|---|---|
| fixtures `identity_bundle_signer`, `identity_server` | Copy `bundle_signer_info` and `genesis_server` (`test_m2_t12d_genesis.py:398-440`): set `AGG_BUNDLE_SIGNER_KEY_FILE` before `make_sync_server(..., org_names=["Identity A", "Identity B"])`. |
| `_route_cli_link(srv, org, uid) -> (sk, kid)` | `_make_fresh_session` -> `POST /api/v1/signer-links` (cookie `__Host-agg_session`, header `X-CSRF-Token`, json `{}`) -> 200 `code` -> new `SigningKey` -> `POST /api/v1/sync/signer/link {code, key_id, public_key}` -> 200. |
| `_route_browser_enroll(srv, org, uid) -> (sk, kid)` | `_make_fresh_session` -> `POST /api/v1/signer-links` json `{"kind":"browser","key_id":kid,"public_key":hex}` with the CSRF header -> 201. |
| `_seed_people(srv, org)` | Seeds active users alice, carol (both org-scope `admin` via `_grant_role`), bob, dave, erin (no binding); distinct `sub`; returns ids, iss, sub. |
| `_genesis(srv, org, alice)` -> ctx | `_route_cli_link` for alice -> pending token -> `_seed_genesis_code` -> `_build_genesis_envelope(..., bundle_signer_pub=srv pub)` -> `POST /genesis` 200 -> confirmed token. ctx holds chain `[v1]`, `fp = sha256(org + ":" + canonical(v1.payload))`, keys. |
| `_entry(sk, uid, iss, sub, kind="cli", roles=("approver",), added_in)` | One registry key entry (the 9 `_KEY_ENTRY_FIELDS`). |
| `_next(ctx, *, add=(), drop=(), replace={}, admins=None, threshold=None, signers=())` | Builds vN+1 from `ctx.chain[-1]`: prev keys minus `drop`, entries in `replace` swapped by key_id, plus `add`; `prev_hash` as `registry._payload_hash`; `bundle_signer` and `org_id` carried; `expires_at = now + 6 d`; signed (`agg/registry/v1`) by every key in `signers`. |
| `_post(srv, token, org, env)` | `POST /api/v1/sync/signer/signatures {"type":"registry","org_id":org,"envelope":env}`; token = a fresh `_get_signer_token_httpx` for the poster (10 min TTL). |
| `_local_ok(ctx, env)` | Precondition: `sandbox.protocol.registry.verify_chain(ctx.chain + [env], ctx.fp)` does not raise. Every bypass envelope must pass it, so the server's refusal can only be the identity rule (exceptions: B6d, B8a). |
| `_snap(srv, org, kids)` | Owner connection, `set_config('app.org_id', org)`. Reads the five values listed under **R** and **A** below. |

Bases (each test starts from one, then posts one more version as alice unless stated):
- **G**: `_seed_people` + `_genesis` (v1: alice `K_a1`, roles `["admin"]`, threshold 1).
- **V2C**: G + `_route_cli_link(carol)` -> v2 adds `K_c` (carol ids, roles `["admin"]`), admins `[K_a1, K_c]`, threshold 2, signed `K_a1+K_c`, posted with carol's pending_link token -> 200.
- **V3B**: V2C + `_route_cli_link(bob)` -> v3 adds `K_b` (bob ids, roles `["approver"]`), threshold 2, signed `K_a1+K_c` -> 200.

### 0.2 The two assertion blocks

**R (refused, identity):** status 400; body `{"error":"identity_unbound","reason":<class>,"key_id":<offending kid>}`; and, comparing `_snap` before and after:
1. `key_registry_versions`: `SELECT count(*), coalesce(max(version),0) WHERE org_id` unchanged.
2. `approver_keys`: `SELECT key_id, user_id, revoked_at IS NULL WHERE org_id ORDER BY key_id` unchanged, and no row with `key_id = <offending kid>`.
3. `signer_links`: `SELECT status WHERE org_id AND key_id = <offending kid>` is `'pending'` on every row (when the key was linked).
4. `admin_audit`: exactly one new row with `action = 'registry_identity_refused'`; its `detail` has `reason == <class>`, `key_id == <kid>`, `version == N`, `posted_by == <poster user_id>`, a 64-hex `payload_sha256`, and no `public_key`, `iss` or `sub` field.
5. `admin_audit`: count of `action = 'registry_version'` unchanged.

**A (accepted):** 200 `{"version": N}`; `max(version) == N`; an `approver_keys` row per added kid with `revoked_at IS NULL` and the expected `user_id`; every matched `signer_links` row for an added kid has `status = 'consumed'`; exactly one new `admin_audit` `registry_version` row whose `detail.version == N`, `detail.added` equals the added `{key_id, user_id, roles, kind}` sorted by key_id, and `detail.promoted` lists promotions; no new `registry_identity_refused` row.

## 1. Server bypass tests B1-B11 and twins (`ee/tests/test_m2_t12d_identity.py`)

All `@pytest.mark.pg`. "pre ok" = `_local_ok` asserted first.

| ID | Test function | Base | vN posted (pre ok unless noted) | Expected | Today |
|---|---|---|---|---|---|
| B1a | `test_b1_probe_b_unlinked_key_invented_user` | G | v2 adds `K_x` (generated, never linked) as admin: `user_id="admin-"+kid[:8]`, invented iss/sub; admins `[K_a1,K_x]`, threshold 1, signed `K_a1` | R `unknown_key` | xf |
| B1b | `test_b1b_own_linked_key_invented_user` | G | `K_x` from `_route_cli_link(alice)`, same invented ids as B1a | R `user_mismatch` | xf |
| B1+ | `test_b1_twin_carol_route_linked` | G | v2 adds `K_c` from `_route_cli_link(carol)`, carol's exact ids, admin, threshold 1, signed `K_a1` | A | xf (A asserts consumption and audit) |
| B2a | `test_b2_carol_ids_unlinked_key` | G | v2 adds `K_x` (never linked) with carol's user_id/iss/sub, admin | R `unknown_key` | xf |
| B2b | `test_b2b_alice_linked_key_carol_ids` | G | `K_x` from `_route_cli_link(alice)`, labelled with carol's ids | R `user_mismatch` | xf |
| B3a | `test_b3_carol_key_bob_user_id` | G | `K_c` from carol's route link, labelled with bob's user_id, iss, sub; approver only | R `user_mismatch` | xf |
| B3b | `test_b3b_carol_key_forged_iss_sub` | G | `K_c`, carol's user_id, `iss="https://idp.test"`, `sub="sub-forged"` | R `identity_mismatch` | xf |
| B3c | `test_b3c_user_id_case_variant` | G | `K_c`, `user_id = carol_id.upper()`, carol's iss/sub | R `user_mismatch` (exact string compare; the connector counts strings) | xf |
| B3d | `test_b3d_inactive_user` | G | carol links `K_c`; then fixture `UPDATE users SET status='disabled'` for carol; v2 adds `K_c` honestly | R `user_mismatch` | xf |
| B4a | `test_b4_key_linked_in_other_org` | G in org A; org B with user dave_B | dave_B route-links `K_d` in org B; alice's v2 (org A) adds `K_d` with dave_B's ids | R `other_org` | xf |
| B4b | `test_b4b_other_org_user_on_own_org_link` | G | `K_c` from carol's org-A link, labelled with dave_B's user_id/iss/sub | R `user_mismatch` (ruling R-3) | xf |
| B4c | `test_b4c_other_org_token` | G in A, dave_B linked in B | dave_B's pending_link token posts an org-A v2 (`org_id` A, envelope adds `K_d`) | 404; both orgs' `_snap` unchanged; no `registry_identity_refused` row in A or B | pass |
| B4+ | `test_b4_twin_same_org_user` | G | dave (org A) route-links `K_d`; v2 adds it, approver | A | xf |
| B5a | `test_b5_new_admin_key_no_binding` | V2C | v3 adds `K_b` (bob route link) in `admins` with roles `["admin"]`, threshold 2, signed `K_a1+K_c` | R `not_admin` | xf |
| B5b | `test_b5b_promotion_no_binding` | V3B | v4: `K_b` added to `admins`, roles `["admin","approver"]` (carried, otherwise unchanged) | R `not_admin` | xf |
| B5c | `test_b5c_project_scope_admin_only` | V2C | fixture: `create_project` + `_grant_role(bob,"admin",scope_type="project",scope_id=<project>)`; then B5a's v3 | R `not_admin` | xf |
| B5d | `test_b5d_admin_role_not_in_admins` | V2C | v3 adds `K_b` with roles `["admin"]` but not in `admins` | R `not_admin` | xf |
| B5+a | `test_b5_twin_org_admin_binding` | V2C | `_grant_role(bob,"admin")` first; B5a's v3 | A | xf |
| B5+b | `test_b5b_twin_promotion_with_binding` | V3B | `_grant_role(bob,"admin")`; B5b's v4 | A (`detail.promoted == [{K_b, bob}]`, `added == []`) | xf |
| B5+c | `test_b5_twin_approver_needs_no_binding` | V2C | v3 adds `K_b`, roles `["approver"]`, not in admins, no binding | A | xf |
| B6a | `test_b6_carried_user_id_changed` | V3B | v4 replaces `K_b`'s `user_id` with dave's (iss/sub dave's too) | R `identity_changed` | xf |
| B6b | `test_b6b_carried_iss_sub_changed` | V3B | v4: `K_b` keeps user_id, `sub="sub-forged"` | R `identity_changed` | xf |
| B6c | `test_b6c_carried_kind_changed` | V3B | v4: `K_b` `kind` cli -> browser | R `identity_changed` | xf |
| B6d | `test_b6d_carried_public_key_changed_upstream` | V3B | v4: `K_b` keeps key_id, gets another public key. **pre: `verify_chain` raises** (D0-1) | 400, body not `identity_unbound`; R items 1, 2, 3, 5 hold; **no** new `registry_identity_refused` row | pass |
| B6+ | `test_b6_twin_carried_unchanged` | V3B | v4 changes only `expires_at` | A with `added == []` | xf |
| B7a | `test_b7_consumed_link_readd` | V3B | v4 drops `K_b` (200, A); v5 re-adds the same `K_b` entry | v5: R `unknown_key` (link consumed in v3) | xf |
| B7b | `test_b7b_removed_key_readd_other_user` | V3B | v4 drops `K_b`; v5 re-adds `K_b` labelled with dave's ids | v5: R `unknown_key` | xf |
| B7+ | `test_b7_twin_fresh_link_readd` | V3B | v4 drops `K_b`; bob route-links a fresh `K_b2`; v5 adds it | A | xf |
| B8a | `test_b8_two_own_keys_threshold2` | G | alice route-links `K_a2`; v2 adds it (alice's exact ids, admin), admins `[K_a1,K_a2]`, threshold 2, signed `K_a1+K_a2`. **pre: `verify_chain` raises** ("from its own admins, got 1") | 400 not `identity_unbound`; R items 1, 2, 3, 5; no refusal row; `K_a2` link still `'pending'` | pass |
| B8b | `test_b8b_two_own_keys_threshold1_not_dual` | G | B8a with threshold 1 -> A; dave, erin route-link; v3 adds both (approvers) signed `K_a1+K_a2`, threshold 1 -> A; then `GET /api/v1/sync/signer/registry`, `verify_chain(chain, fp)` | `counts_for_dual` False for `K_d`, `K_e`, `K_a2` | xf (A blocks) |
| B8+ | `test_b8_twin_two_people_dual` | V2C | dave, erin route-link; v3 adds both signed `K_a1+K_c` | A; `counts_for_dual` True for both, False for `K_c` | xf |
| B10 | `test_b10_key_linked_by_two_users` | G | carol route-links `K_c`; bob uses his own link code with `K_c`'s public key (the route accepts it, no proof of possession); v2 adds `K_c` with carol's ids | R `unknown_key` (ruling R-5); twin is B1+ | xf |
| B11 | `test_b11_browser_enroll_stale_session` | G | seed a session with `FakeClock(now - 20 min)` (as `_make_stale_session` in `test_m2_t7_signer.py`); `POST /api/v1/signer-links` kind browser | 403 `session_too_old`; `SELECT count(*) FROM signer_links WHERE key_id` = 0 | xf |
| B11+ | `test_b11_twin_fresh_browser_enroll` | G | `_route_browser_enroll(bob)` | 201; one row, `kind = 'browser'`, `status = 'pending'` | xf (`kind`) |
| C1 | `test_candidates_lists_browser_and_cli_kind` | G | bob browser-enrolls, carol CLI-links; `GET /candidates` with alice's confirmed token | bob's row `kind == "browser"`, carol's `kind == "cli"`, iss/sub = users row | xf |
| C2 | `test_candidates_excludes_consumed_and_inactive` | V2C | dave links then fixture disables dave; erin links | candidates hold erin only (not `K_c`, consumed in v2; not dave, inactive) | xf |
| C3 | `test_concurrent_v2_one_wins` | G | carol and dave (grant dave admin) route-link; v2a adds `K_c`, v2b adds `K_d` (each admin, threshold 2, co-signed by its new key); post both at once (`ThreadPoolExecutor(2)`, two alice tokens) | statuses `[200, 400]`; one v2 row; exactly one of the two links `'consumed'`, the other `'pending'`; one `registry_version` row; no 500 | xf |

B9 has no server row: A1.2 keeps `approvals UNIQUE (escalation_id, user_id)`; B9 is the connector pin P7-P9.

## 2. End to end (`ee/tests/test_m2_t12d_identity.py`, both `xf` until the build)

- **E1 `test_e2e_frozen_step2_route_linked_keys`.** G; carol `_route_cli_link` -> v2 (V2C shape: roles `["admin"]`, threshold 2, signed alice+carol, posted with carol's pending token) -> A. v3 adds bob's key from `_route_browser_enroll` (`kind "browser"`, roles `["approver"]`), carol's second CLI link (approver) and alice's second CLI link (alice-approver), threshold 2, signed `K_a1+K_c` -> A. `GET /signer/registry` returns 3 versions; `verify_chain(chain, fp)`: `counts_for_dual` False for `K_c` (v2, count 1, intended per A1.3), True for bob, carol-approver and alice-approver. Two `registry_version` audit rows (v2, v3); all four added links `'consumed'`; `/candidates` is then `[]`.
- **E2 `test_e2e_probe_b_refused_at_v2`.** G; B1a's v2 through the route -> R `unknown_key`; then the honest v2 (B1+) -> A, so the org is not wedged by the refusal.
- **Existing tests A1.1 turns red (qa inventories, aligns setup, lists by node id for security sign-off; never by loosening A1.1).** Known now:
  - `ee/tests/test_m2_t12b_e2e.py::test_e2e_remote_approval_path`: admin2, bob, carol, alice-approver keys come from `keygen()`; switch each to `_route_cli_link` in that user's seeded session (A1.3).
  - `ee/tests/test_m2_t12b_e2e.py::test_d4_e2e_step2_genesis_v2_v3_through_routes`: v3 labels bob's CLI-linked key `kind "browser"`; take it from `_route_browser_enroll`.
  - grep `sync/signer/signatures` in `test_m2_t12b_e2e.py`, `test_m2_t12d_genesis.py`, `test_m2_t7_signer.py`, `test_t9_routes.py` (`test_t9_routes.py` is frozen; if it breaks, stop and ask security).
- **`ee/deploy/demo.py` step 2** (backend, d4 exit work): every v2 and v3 key from `/api/v1/signer-links` + `sandbox signer link`, or the browser enrollment; no invented ids.

## 3. Connector pins (`tests/security/test_m2_t12d_pins.py`, all plain, all pass today)

Imports: `from tests.security.test_m2_t6_registry import _keygen, _make_key_entry, _make_registry_payload, _sign_envelope, _build_next_version`; `from tests.security.test_m2_t12_remote import _setup_managed_workspace, _create_pending_request, _make_remote_approval` (pattern already used by `test_m2_script_binding.py`). `fp = sha256(org + ":" + canonical(v1.payload))`. Build a two-key-one-user v1 by hand (`_build_genesis` gives each admin its own user_id).

| ID | Test function | Chain or setup | Assertion |
|---|---|---|---|
| P1 | `test_pin_s9_genesis_two_keys_one_user_not_dual` | v1: admins `K_a1,K_a2` both `u-alice`, approver dave, threshold 1, signed by both | `counts_for_dual(K_d)` is False |
| P2 | `test_pin_s9_genesis_two_users_dual` | v1: admins alice `u-alice`, carol `u-carol`, threshold 2, dave, signed by both | `counts_for_dual(K_d)` is True |
| P3 | `test_pin_b8_threshold1_one_user_adds_not_dual` | v1 alice thr 1; v2 adds `K_a2` (`u-alice`, admin) thr 1 signed `K_a1`; v3 adds dave, erin signed `K_a1+K_a2` | chain verifies; False for `K_d`, `K_e`, `K_a2` |
| P4 | `test_pin_b8_twin_two_users_adds_dual` | v2 adds carol thr 2 signed alice+carol; v3 adds dave, erin signed alice+carol | True, True; False for `K_c` |
| P5 | `test_pin_b8_threshold2_one_user_refused` | v2 adds `K_a2` (`u-alice`) thr 2 signed `K_a1+K_a2` | `RegistryError` whose text contains `from its own admins, got 1` |
| P6 | `test_pin_floor_counts_admin_users_not_keys` | P4's v2; v3 admins `[K_a1,K_a2]` (`K_a2` = `u-alice`), carol dropped, thr 2, signed alice+carol | `RegistryError` containing `below floor 2` |
| P7 | `test_pin_b9_two_keys_one_user_awaiting_second` | `_setup_managed_workspace` (default two admins), approvers `bob1`,`bob2` (`user-bob`), carol; approvals from bob1 and bob2 | `status == "awaiting_second"` and `approvals == 1` (strict, unlike `test_same_user_two_keys_counts_once`) |
| P8 | `test_pin_b9_twin_bob1_carol_execute` | same setup; bob1 + carol | `status == "executed"` |
| P9 | `test_pin_b9_twin_bob2_carol_execute` | same setup; bob2 + carol | `status == "executed"` (proves bob2's approval is valid on its own) |
| P10 | `test_g_l5_part1_connector_cannot_tell_one_human_from_two` | probe B: v1 alice thr 1; v2 adds `K_x` admin under `admin-<kid8>`/invented iss, sub, thr 1, signed `K_a1`; v3 thr 2 adds dave, erin signed `K_a1+K_x` | True, True. Docstring: "Named limit G-L5 part 1 (ADR 0011 A1.5). Plain pin: a change in either direction needs an ADR change." |

## 4. d5 item (2) tests

| ID | Node id | What | Today |
|---|---|---|---|
| D2-1 | `tests/security/test_m2_t12d_signer_cli.py::test_f10_sign_registry_threshold_flag` (edit; security approves by this node id) | Add a candidate carol (`u2`, `sub-2`) to `_signreg_tracker(candidates=...)`; invoke with `--add <carol kid> --admin --confirm-key-id <kid> --confirm-identity https://idp sub-2 --threshold 2`; assert exit 0 and payload threshold 2. No other assertion changes. | pass |
| D2-2 | `...::test_d5_threshold_bound_unconditional` (new) | v1 one admin `u1`; `sign-registry --threshold 2 --out v2.json` with no `--add` | exit 1; message names `distinct admin`; `v2.json` not written | xf |
| D2-3 | `...::test_d5_link_token_failure_reason_class` (new, parametrised) | Mock `/signer/token`: (a) HTTP 401 with body `SECRET-BODY-123`; (b) 302 redirect; (c) server `http://example.com` (transport) | exit 1; output contains `(HTTP 401)`, `(redirect refused)`, `(transport refused)` respectively; never `SECRET-BODY-123` | xf |
| D2-4 | `...::test_d5_link_token_log_format_has_no_token_word` (new, static) | `inspect.getsource(_get_link_signer_token)`; AST walk: every `Call` whose func attr is `debug/info/warning/error/exception` has a first-arg string constant without `token` (case-insensitive), and no `exc` argument | xf |
| D2-5 | `...::test_d5_registry_verify_failed_writes_audit` (new) | `_r2_setup_enrolled_workspace` (v3, hwm 3); v4 built like its `_extend` but signed by a stranger key; call `apply_registry_chain(lay, chain)` | status `refused:verify_failed`; exactly one audit event `registry_refused` with `reason_code == "REGISTRY_VERIFY_FAILED"`, `offered_version == 4`, `floor == 3`; `registry.json` unchanged | xf |
| D2-6 | `...::test_d5_registry_rollback_writes_audit` (new) | same setup; offer `chain_v3[:2]` | `refused:rollback`; one `registry_refused` event, `reason_code == "REGISTRY_ROLLBACK"` | xf |
| D2-7 | `...::test_d5_registry_update_no_refusal_audit` (twin) | offer a correctly signed v4 | `updated`; no `registry_refused` event | pass |
| D2-8 | `ee/tests/test_m2_t12d_genesis.py::test_d5_d4_4_unreadable_label` (new, parametrised: missing path; a directory) | run `agg_cp.migrate` as in `test_d4_4_migrate_fails_closed_bad_bundle_key` | exit != 0; stdout has `{"event":"bundle_signer_error","reason":"unreadable"}`; the path string is absent from stdout+stderr | xf |
| D2-9 | `...::test_d5_d4_4_bad_format_label` (new) | key file `not-a-valid-hex-key` | exit != 0; `reason == "bad_format"` exactly; file text absent | pass |
| D2-10 | `...::test_d5_d4_1_signatures_version_shapes` (new, parametrised) | No chain (pending_link token via `_seed_admin_with_link_and_code`, envelope adds own key): `2`->400, `"1"`->400, `"2"`->400, `1.0`->409, `True`->409. With chain (`_do_genesis`, confirmed token): `"2"`->400, `2.0`->400 | every case: `key_registry_versions` count and `approver_keys` rows unchanged; no-chain cases add no `sync_alerts` row. Case `2.0` with chain is `pytest.param(..., marks=xfail(strict=True))` (stored today); the rest pass | mixed |

Audit reader for D2-5..7: copy `_audit_events` from `tests/security/test_m1_t3_pins.py:110` (reads `layout.audit_dir/**/*.jsonl`). The suite runs with `-p no:logging`, so D2-4 is static, not `caplog`.

## 5. Build spec for backend (A1.1)

### 5.1 Where and in what order (`signatures_route`, `type == "registry"` only)

Unchanged first: bearer auth; pending_link own-key rule; org IDOR 404; the D4-1 v1 guard and its `second_genesis` alert. Then, on the `autocommit=False` connection:
1. `set_config('app.org_id', org, true)`; `pg_advisory_xact_lock(hashtext('agg-genesis:' || org))`. Same key as the genesis route (move the string to one constant `_REGISTRY_LOCK_KEY`), so genesis and every later version serialise per org.
2. `version` must be an `int` and not a `bool`, and >= 2; else rollback, 400 `{"error":"invalid_version"}` (ruling R-2). No audit.
3. Load the stored chain (`ORDER BY version`). Empty: rollback, 400 `{"error":"no_chain"}`.
4. Pre-verify: `verify_chain(chain + [env], fp_of(chain[0]))`. Failure: rollback, 400 with the existing body shape. No identity audit (ruling R-1).
4a. Bundle signer pin (F-3 ruling, ADR 0011 A1.1 rule 8), any threshold: `server_pub = _load_bundle_signer_key()` at request time; `None`: rollback, 400 `{"error":"bundle_signer_not_configured"}`, no audit. Else `cur.bundle_signer.public_key == server_pub.hex()` and `cur.bundle_signer.key_id == sha256(server_pub).hexdigest()` (exact strings); mismatch: the step 6 refusal path with `reason "bundle_signer_mismatch"` and `key_id` = offered bundle_signer key_id (or `""`), but the body is 400 `{"error":"bundle_signer_mismatch"}`.
5. A1.1 rules (5.2) against `prev = chain[-1].payload`, `cur = env.payload`. Put them in a new read-only module `ee/src/agg_cp/sync/registry_identity.py`: `check_registry_identity(conn, org_id, prev, cur) -> Refusal | Plan`. It only runs SELECTs.
6. Refusal: `conn.rollback()`; set `app.org_id` again (the transaction-local setting is gone); INSERT `admin_audit (id, org_id, action, detail)` with `action 'registry_identity_refused'`, detail `{version, payload_sha256, reason, key_id, posted_by}`; `conn.commit()`; return 400 `{"error":"identity_unbound","reason":...,"key_id":...}`.
7. Pass: `UPDATE signer_links SET status='consumed' WHERE org_id=%s AND key_id=%s AND user_id=%s AND status='pending' AND used_at IS NOT NULL AND public_key IS NOT NULL` per added key; INSERT `admin_audit` `registry_version`, detail `{version, payload_sha256, posted_by, added:[{key_id,user_id,roles,kind}], promoted:[{key_id,user_id}], removed:[key_id]}`; then `store_registry_version(conn, org, env)`, which re-verifies, writes and commits all three in one transaction. If it raises: rollback (nothing consumed, no audit row), 400 as today.

`payload_sha256 = sha256(json.dumps(payload, sort_keys=True, separators=(",",":")))`, as in genesis. Key ids in responses and audit are public values; never put `public_key`, `iss`, `sub`, tokens or link codes in a body or an audit row.

### 5.2 Matching rules (cur keys in payload order; first failure wins)

A key is **added** if its key_id is not in `prev.keys`, **carried** if it is in both. It **has admin** if its key_id is in `admins` or `"admin"` is in its `roles`.

| # | Applies to | Rule (exact) | Reason |
|---|---|---|---|
| 1 | added | `SELECT check_key_id_cross_org(kid, org)` is true | `other_org` |
| 2 | added | L = `SELECT DISTINCT user_id::text, public_key, kind FROM signer_links WHERE org_id=org AND key_id=kid AND public_key IS NOT NULL AND used_at IS NOT NULL AND status='pending'`; L empty | `unknown_key` |
| 3 | added | L has more than one distinct `user_id` (R-5) | `unknown_key` |
| 4 | added | no row in L with `public_key == e.public_key` and `kind == e.kind` | `unknown_key` |
| 5 | added | `e.user_id != L.user_id` (exact string) | `user_mismatch` |
| 6 | added | `SELECT oidc_issuer, oidc_subject, status FROM users WHERE id = e.user_id::uuid AND org_id = org` is missing or `status != 'active'` | `user_mismatch` |
| 7 | added | `e.iss != oidc_issuer` or `e.sub != oidc_subject` | `identity_mismatch` |
| 8 | added, has admin | no `role_bindings` row with `org_id=org AND user_id=e.user_id AND role='admin' AND scope_type='org' AND scope_id=org` | `not_admin` |
| 9 | carried | any of `user_id, iss, sub, public_key, kind` differs from prev | `identity_changed` |
| 10 | carried | had no admin in prev, has admin in cur (promotion), and rule 8's query finds no row | `not_admin` |

Removed keys and demotions need no check. Several keys per user are allowed (A1.1 rule 7); every count is by `user_id`. Rule 9's `public_key` arm is unreachable while D0-1 holds (B6d); keep it as defence in depth.

### 5.3 `/candidates` and browser enrollment

- `/candidates` returns rows `WHERE sl.org_id = org AND sl.public_key IS NOT NULL AND sl.used_at IS NOT NULL AND sl.status = 'pending' AND u.status = 'active' AND u.org_id = sl.org_id`, with `kind` read from `sl.kind` (not the literal `'cli'`). Confirmed token and org admin only, as today.
- `link_browser_key` writes `kind = 'browser'` and refuses a session older than 15 minutes with 403 `session_too_old` (the same `web_sessions.created_at` check as the CLI path, `signer.py:436-446`). A1.1 relies on "only the user's own fresh web session" (B11).

### 5.4 Migration: needed, `0016`

There is **no pending browser-key enrollment table**: `browser_keys.py:79-90` writes browser keys into `signer_links` with a placeholder `code_hash`, the same row shape as a linked CLI key. A1.1 rule 1 matches `kind`, and today a browser-enrolled key can be published as `kind "cli"`, which gives it registry-signing rights (`may_sign`, cli). So the kind must be a recorded server fact.
- File `ee/src/agg_cp/migrations/versions/0016_signer_links_kind.py`, `revision = "000000000010"`, `down_revision = "00000000000f"`.
- Upgrade: `ALTER TABLE signer_links ADD COLUMN kind text NOT NULL DEFAULT 'cli'`; `ADD CONSTRAINT signer_links_kind_check CHECK (kind IN ('cli','browser'))`; backfill `UPDATE signer_links SET kind='browser' WHERE key_id IS NOT NULL AND code_hash = encode(sha256(convert_to('browser-' || key_id || '-' || id::text, 'UTF8')), 'hex')`.
- Downgrade: drop the constraint, then the column. Grants are table-level (`0007`), so no grant change. No new table.

### 5.5 d5 item (2) build notes

- **D4-6 bound** (`sync_cmds.py` ~1810-1844): replace both bounds with one unconditional check: `threshold <= len({k.user_id for k in new_keys if k.key_id in new_admins})`; drop `max(len(new_keys)+1, 2)`.
- **`_get_link_signer_token`**: return a reason class from {`HTTP <code>`, `redirect refused`, `transport refused`, `unreachable`, `bad response`}; callers raise `ClickException("failed to obtain signer token (<class>)")`; the debug log becomes `"signer auth request failed: %s", <class>`, with no exception text and no word "token".
- **Registry refusal audit**: in `registry_chain.apply_registry_chain`, after deciding `refused:verify_failed` or `refused:rollback` (also `refused:same_version_different_bytes`), call `sandbox.connector.policy_versions.audit(layout, {"event":"registry_refused","reason_code":...,"offered_version":...,"floor":...,"ts":time.time()})`. Best effort: return values and decisions do not change.
- **D4-4 label** (`migrate.py:230-258`): try `open(path,"rb").close()` first; `OSError` -> `unreadable`; then `_load_bundle_signer_key()`; `None` -> `bad_format`. Do not change `bundles._load_bundle_signer_key`.

### 5.6 Do not touch

`src/sandbox/protocol/registry.py` (`verify_chain`, S9 `counts_for_dual`, `_distinct_*`); `src/sandbox/connector/approval.py` (dedup, S9 use); the body of `store_registry_version` (only its caller changes); the genesis route (A1.3; only the shared lock constant); the SQL functions `cli_key_lookup`, `check_key_id_cross_org`, `signer_link_consume`; every file in `M2_FROZEN_MANIFEST.sha256`; any qa test without a security sign-off by node id.

## 6. Stubs, rulings and findings

| ID | Kind | Content |
|---|---|---|
| S-1 | stub (backend) | No pending browser-key enrollment table exists. Ruling: d5 adds `signer_links.kind` (migration 0016) and keeps browser enrollments in `signer_links`; no new table. |
| S-2 | stub (backend) | `/candidates` lists browser enrollments but labels them `cli` (`signer.py:1325-1347`). Fixed by 5.3 (C1). |
| S-3 | stub (backend) | `registry_identity.py` and the lock constant are new. |
| R-1 | ruling | Pre-verify before A1.1, so a `registry_identity_refused` row always means "a version valid under the admin threshold tried to bind an unbound identity" (a real security event, not noise from unsigned posts), and A1.1 is not an oracle for unsigned callers. |
| R-2 | ruling | `version` must be an `int` (not `bool`) for v >= 2. Today `2.0` with a chain is stored (D2-10). |
| R-3 | ruling | No cross-tenant `users` lookup. `other_org` comes only from `check_key_id_cross_org`; a foreign user id on an own-org link is `user_mismatch` (B4b). This avoids a cross-org user-existence oracle. |
| R-4 | ruling | Exact string compare for `user_id`, `iss`, `sub` (B3c): the connector counts strings, so any normalisation on the server would let one user count twice. |
| R-5 | ruling | Stricter than A1.1's text: a key_id that is pending-linked by two users is refused (`unknown_key`). Cost: a user can block another user's enrollment of a key they know; the victim re-links a fresh key. lead-architect notes this in A1 at commit. |
| F-1 | finding, LOW, T15b | `/link` and the browser enrollment take a public key without proof of possession. R-5 makes this fail closed for A1.1; `cli_key_lookup` can still map a doubly-linked key to either user. Fix: the link body is signed by the key (M3 or T15b). |
| F-2 | finding, LOW, T15b | The genesis route checks `role='admin'` without `scope_type='org'` and does not require the link's `kind = 'cli'`. Not a d5 change (A1.3). |
| F-3 | finding, MEDIUM, lead-architect now | `/signatures` does not pin `bundle_signer` for v >= 2 (R1 is genesis-only). At threshold 1 one admin can rotate `bundle_signer` to her own key and sign a loosened policy bundle with no second reviewer. That weakens "loosening needs a second reviewer". Proposed rule: refuse a v >= 2 whose `bundle_signer` differs from the server's configured key (400 `bundle_signer_mismatch`). qa writes B12 only after the lead's ruling. Ruling (lead-architect, 31 Oct): accept, as a variant that also covers threshold 2 and adds an audit row. **Rule:** for `type == "registry"` and v >= 2, as step 4a in 5.1 (after pre-verify, before A1.1, so it is not an oracle for unsigned posts, R-1): load `_load_bundle_signer_key()` at request time; `None` -> rollback, 400 `{"error":"bundle_signer_not_configured"}`, no audit. Otherwise `cur.bundle_signer` must be a dict with `public_key == server_pub.hex()` and `key_id == sha256(server_pub).hexdigest()` (exact strings); else rollback, then commit one `admin_audit` `registry_identity_refused` row with detail `{version, payload_sha256, reason:"bundle_signer_mismatch", key_id:<offered bundle_signer.key_id, or "">, posted_by}`, and return 400 `{"error":"bundle_signer_mismatch"}`. The threshold does not matter: in M2 only the server signs bundles (after its review flow), so a `bundle_signer` the server does not hold skips that flow even with two signers. **Rotation in M2:** the operator first replaces `AGG_BUNDLE_SIGNER_KEY_FILE` and restarts (host access, already inside G-L1); then admins publish vN carrying the new key under the normal threshold. Until vN lands, connectors refuse bundles signed by the new key and keep the last good bundle (fail closed, accepted cost). A bundle signer held outside the server is M3 or later, with its own ADR. The genesis route is not changed (5.6). **B12 tests** (`test_m2_t12d_identity.py`, pg, pre ok, strict xf until built): `test_b12a_bundle_signer_rotated_to_admin_key` (G; v2 keeps the keys, swaps `bundle_signer` to a fresh test key, threshold 1, signed `K_a1` -> 400 `bundle_signer_mismatch`; R items 1, 2, 5 hold; one new refusal row with reason `bundle_signer_mismatch`, version 2 and the offered key_id); `test_b12b_bundle_signer_swap_threshold_2` (V2C; v3 swaps it, signed `K_a1+K_c` -> same refusal); `test_b12c_bundle_signer_not_configured` (G; env unset for the request -> 400 `bundle_signer_not_configured`; R items 1, 2, 5 hold and no new refusal row). Twins: `test_b12_twin_bundle_signer_carried` (B12a setup with `bundle_signer` unchanged -> A, `added == []`) and `test_b12_twin_rotation_after_server_key_change` (G; monkeypatch `AGG_BUNDLE_SIGNER_KEY_FILE` to a new key file; v2 carries the new key -> A; a v3 that carries the old key -> 400 `bundle_signer_mismatch`). Recorded in ADR 0011 A1.1 rule 8. |

## 7. Exit check (T12d d5)

1. Every section 1 test and twin, E1 and E2 pass through the routes, with no `xfail` markers left. The A1.4 grep holds: no `store_registry_version` and no raw `key_registry_versions`, `approver_keys` or `signer_links` writes in `test_m2_t12d_identity.py` (an AST test like D4-8 is welcome).
2. Probe B (B1a, E2) is refused at v2 with `unknown_key`; frozen step 2 (E1) passes with route-linked keys; `demo.py` step 2 links every v2 and v3 key through routes.
3. The pins P1-P10 and D2-1..D2-10 pass. Root (`.venv\Scripts\python -m pytest -q -p no:logging`) and `ee/tests` (pg) suites are green, and every pre-existing test edited for A1.1 is listed by node id with security's sign-off.
4. Semgrep (p/python, p/secrets) gives 0 ERROR on the changed files, and the `sync_cmds.py` logger warning is gone. gitleaks and trivy are clean. CI is green. Security's leader review is APPROVE.
5. G-L4 is removed from `docs/control-plane/HANDOFF.md` (line 73 today) in the d5 commit; G-L5 stays in ADR 0011. F-3 has a lead-architect ruling recorded before the M2 security sign-off.
