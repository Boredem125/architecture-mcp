# T4 tests-first audit, 18 Nov 2026

Reviewer: security-engineer (leader tier). Scope: what each node asserts after its gate, against `T4_SPEC.md` section 3 (Markers, Gates, "Nothing written", Fixtures, tables 3.1-3.4, property rules 1-5) and `T4_SECURITY_REVIEW.md` (MUSTs 1-14, A1-A3). Files: `ee/tests/test_m3_t4_publish_verify.py`, `ee/tests/test_m3_t4_property.py`, `ee/tests/test_m3_t4_static.py`, `tests/security/test_m3_t4_cli.py` (uncommitted). Read: those files, `ee/tests/m3_pending.py`, `ee/tests/m2_sync_server.py`, `ee/src/agg_cp/sync/{proposals,bundles,enroll,signer,registry}.py`, `ee/src/agg_cp/{app,rbac}.py`, migrations 0002, 0007, 0018, `src/sandbox/protocol/registry.py`, `src/sandbox/connector/sync/bundles.py`, `src/sandbox/cli/change_cmds.py`, `.github/workflows/tests.yml`, `.github/scripts/c_tests.py`, root `pyproject.toml`. No pytest run, no server, no container. Two read-only AST scripts ran from the session scratchpad: the test file's own await visitor over `ee/src/agg_cp` plus two mutant snippets, and a count of the admin SQL fragment.

Verdicts: OK (tests the row), WEAK (right branch, misses an assertion in its row), WRONG (a correct build fails it, or it tests another branch than its row, or a guard that survives its named mutant), STUB (does not exercise the claim).

## 1. Cross-cutting findings

1. **24 publish-file nodes and 4 property nodes are stubs.** 16 have the body `require_m3(4, False, ...)`: the gate is a constant, so the measured "xfail at the gate" proves nothing and, with markers removed, they fail forever. 8 more run G2 then `assert False`. 4 property nodes import the module and assert nothing, so they would pass vacuously after the build. The file comments ("For brevity", "Due to file size limits, only signature stubs") say so. Spec 3 says the build removes markers only, so the build cannot finish on these files.
2. **The two marked root CLI nodes fail in CI today.** They gate on `importlib.util.find_spec("agg_cp.sync.publish_verify")`. The root `pytest` job installs only `.` (`pyproject.toml` packages `src/sandbox`). `connector-standalone` runs `rm -rf ee`, and `c_tests.py` selects every `tests/**/test_*.py`. In both jobs `find_spec` on a dotted name whose parent `agg_cp` is missing raises `ModuleNotFoundError`, which `raises=M3T4Pending` does not catch. The local measurement passed only because the dev `.venv` has `agg_cp` installed editable (checked: origin `E:\architecture-mcp\ee\src\agg_cp\__init__.py`). Root T3 nodes gate on a CLI feature, which is the right pattern.
3. **The refusal-code fixture cannot build a registry.** Both pure nodes build a genesis that `verify_chain` refuses: threshold 2 with one admin signature ("genesis needs 2 admin sigs, got 1"), and the `bundle_signer` key id equals a key in `keys` ("collides with a key in keys"). The `sign_and_check` node has the collision too. So 17 nodes raise `RegistryError` in setup on a correct build.
4. **The project environment hides the first-bundle rule.** `create_project` defaults to `environment='staging'`, and the proposal route stamps it into the payload. Against the deny-all base (absent means prod), `_loosened_environment` reports prod-to-staging as a loosening. So every base-0 proposal in this file is a loosening. Nodes that need "not loosened" must create the project with `environment="prod"`.
5. **"Nothing written" is not asserted anywhere.** No node checks the definition in spec section 3. Add one helper and call it from every row that says "nothing written":
   ```python
   def _assert_nothing_written(owner_url, org_id, project_id, proposal_id, reason, before):
       # before = _counts(owner_url, org_id, project_id) taken just before the publish
       with psycopg.connect(_conninfo(owner_url)) as conn:
           conn.execute("SELECT set_config('app.org_id', %s, false)", [org_id])
           assert _counts_on(conn, org_id, project_id) == before   # policy_bundles rows for the project; policy_change_approvals rows whose change_request_id is not a policy_change_requests id
           assert conn.execute("SELECT status FROM policy_change_requests WHERE id=%s::uuid", [proposal_id]).fetchone()[0] == "open"
           assert conn.execute("SELECT count(*) FROM admin_audit WHERE org_id=%s::uuid AND action='bundle_proposal.publish' AND detail->>'proposal_id'=%s", [org_id, proposal_id]).fetchone()[0] == 0
           assert conn.execute("SELECT count(*) FROM admin_audit WHERE org_id=%s::uuid AND action='bundle_proposal.publish_refused' AND detail->>'proposal_id'=%s AND detail->>'reason'=%s", [org_id, proposal_id, reason]).fetchone()[0] == 1
   ```
6. **`admin_audit.detail` is `jsonb`.** psycopg 3 returns it as a `dict`, so `json.loads(row[1])` raises `TypeError`. T3 nodes select `detail::text`. Use `detail->>'key'` in SQL, or use the dict directly.
7. **The `t4_server` fixture against spec "Fixtures":**
   - Missing: an enrolled device per project for `GET /sync/bundle`, needed by the exit node and the route sample. Also missing: the second org with a threshold-1 genesis (T0b-7), and any own-org helper for nodes that store a registry version or tamper with the chain.
   - **dave is bound as an org admin.** The spec lists org admins alice, bob and carol only. This changes no proof as written. dave appears only as a stored `user_id` (a third user, MUST 4, which T3 step 10 still lets through) and as a publisher. No R4-4 read node uses dave. Keep it, and record it in the spec's Fixtures line (lead), or bind dave to nothing and publish as alice or bob. Do not use dave in any read node: as an org admin he would read through the admin path, not the key-holder path.
   - **Own-org nodes need fresh keys.** `store_registry_version` refuses a `key_id` that is live in another org (`check_key_id_cross_org`). So own-org nodes need fresh `SigningKey`s for every user. The bundle signer is not in `keys[]` and may be reused.
   - **Storing v2 revokes dropped keys.** `store_registry_version` marks keys absent from v2 as `revoked_at = now()` in `approver_keys`. MUST 3 needs bob's row live, so after storing v2 the node must run owner SQL `UPDATE approver_keys SET revoked_at = NULL WHERE org_id=... AND key_id=<bob>`.
8. **Missing addendum SHOULD A-S1** (`test_policy_bundles_sequence_constraint_name_pinned`, pg). Without it, the hard-coded name in `test_publish_db_error_mapping` is never checked against `pg_constraint`.

## 2. `ee/tests/test_m3_t4_publish_verify.py` (49 ids)

| node | verdict | reason | fix |
|---|---|---|---|
| `test_publish_verified_loosening_connector_applies_unchanged` | WEAK | Asserts only 201 and `verification`. The exit claim (served envelope, exactly two approvals, `verify_and_apply` succeeds, `bundle.json` bytes equal) is absent | Add: `verified_at IS NOT NULL` and label `server` in the DB; enroll a device for `proj`; `GET /api/v1/sync/bundle?after=0` with the device token; assert its approvals' key_ids are {alice, bob}; build a fresh connector layout under `tmp_path`, get its registry from `verify_chain` over the stored chain (own call), and run `verify_and_apply` with that registry, `_bundle_signer_pub(registry)` and the served envelope plus approvals; assert `bundle.json` bytes equal the served envelope bytes |
| `test_publish_tightening_one_approval_201` | OK | Base 1 is a `server` row with env staging; the second payload tightens; need 1 | none |
| `test_publish_first_bundle_needs_two_even_if_not_loosened` | WRONG | The project is `staging`, so the payload loosens the deny-all base (prod to staging). A mutant that drops `is_first` still gives `approvals_insufficient`. Nothing written is not checked | `create_project(..., environment="prod")`; before publishing, assert the propose response `loosened == {}`; add `_assert_nothing_written(..., "approvals_insufficient")` |
| `test_publish_single_approval_loosening_refused_nothing_written` | WEAK | Right branch; nothing written not checked | Call `_assert_nothing_written` after the second publish |
| `test_publish_forged_approval_refused_nothing_written` | WEAK | Right branch; nothing written not checked | Call `_assert_nothing_written` |
| `test_publish_proposer_resolved_from_registry_refused` | OK | Stored `user_id` dave passes T3 step 10; (g) resolves carol's key to the proposer | none |
| `test_publish_publisher_resolved_from_registry_refused` | OK | Same shape; bob's key resolves to the publisher | none |
| `test_publish_wrong_registry_approval_refused` | WRONG | Shared org, so bob's key is in the registry, and alice plus bob count: a correct build gives 201 | Own org with fresh keys (alice, bob, carol; genesis admins alice and bob, threshold 2). Store v2 with admins [alice, carol] and keys without bob, signed by alice and bob (v1 admins) and carol. Then `UPDATE approver_keys SET revoked_at=NULL` for bob's key. Carol proposes under v2 (assert `registry_version == 2`); alice approves through the route; owner-insert bob's valid signature with `user_id` bob. Publish as carol: 400 `approvals_insufficient`, `_assert_nothing_written` |
| `test_publish_counts_for_dual_only_when_two_needed` | STUB | Constant-false gate | Second org with a threshold-1 genesis (one admin signature, fresh keys). A loosening with two distinct users' valid approvals through the route. Publish: 400 `approvals_insufficient`; assert `"dual_filter"` and `true` in `detail`; `_assert_nothing_written`. In the same node, `verify_and_apply` on a fresh layout, using that org's chain through its own `verify_chain`, a test-signed bundle-signer envelope over the stored payload and the two approvals: no `BundleError` |
| `test_publish_single_admin_key_tightening_201` | STUB | Constant-false gate | Single-admin org. Owner-insert `server` row 1 (`verification='server'`, `verified_at=now()`, blob = envelope signed by the bundle signer over a bound payload at seq 1). Propose a tightening at base 1, one approval, publish: 201 |
| `test_publish_head_m2_row_loosening_needs_two` | STUB | Constant-false gate | `server` row 1 permissive and `m2_unverified` row 2 strict, both owner-inserted and signed by the bundle signer. Proposal at base 2 equal to row 1's sections. One approval: 400 `approvals_insufficient`; add a second: 201 |
| `test_publish_loosened_against_server_base_only_needs_two` | STUB | Constant-false gate (MUST 2) | As spec row: `server` row 1 strict; `m2_unverified` row 2 permissive with two valid stored approvals; proposal at base 2 equal to row 2's sections. One approval: 400 and `_assert_nothing_written`; two: 201 |
| `test_publish_first_server_row_after_m2_rows_needs_two` | STUB | Constant-false gate | Project `environment="prod"`; owner-insert an `m2_unverified` row 1 equal to deny-all; tightening at base 1 with one approval: 400 `approvals_insufficient` |
| `test_publish_copies_only_counted_approvals` | STUB | Constant-false gate (MUST 1) | Own org; v1 has eve, v2 drops her (keep her projection row live as in the wrong-registry fix). Carol proposes under v2; alice and bob approve through the route; owner-insert eve's valid signature. Publish 201. Assert: the served approvals, the `policy_change_approvals` rows keyed to the bundle id, and audit `approver_user_ids` all equal {alice, bob}; each copied `signed_at` equals the stored proposal row's |
| `test_publish_registry_invalid_refused_and_audited[byte_flip]` | STUB | Constant-false gate (MUST 6) | Own org; propose, approve twice, then owner `UPDATE key_registry_versions SET registry_blob=<one byte changed> WHERE version=1`. Publish: 400 `registry_invalid` (assert `!= 500`); `_assert_nothing_written(..., "registry_invalid")` |
| `test_publish_registry_invalid_refused_and_audited[invalid_json]` | STUB | Same | Same with `registry_blob = b'not json'` |
| `test_publish_no_registry_refused` | STUB | Constant-false gate | Org with no chain; owner-insert the proposal and two approval rows (the approval route refuses `no_registry`); publish: 400 `no_registry`, `_assert_nothing_written` |
| `test_publish_registry_version_stale_refused` | STUB | Constant-false gate | Own org; propose under v1; store v2 keeping all keys; approve twice through the route (assert 201); publish: 400 `registry_version_stale`, `_assert_nothing_written` |
| `test_publish_signer_not_in_registry_refused` | STUB | Constant-false gate | Own org whose chain's `bundle_signer` is a fresh key, not the server key file; propose, approve twice; publish: 400 `signer_not_in_registry`, `_assert_nothing_written` |
| `test_publish_base_invalid_refused[unparseable]` | STUB | Constant-false gate | Propose at base 1 over a valid row 1 (propose itself refuses an unparseable base today), then owner `UPDATE policy_bundles SET bundle_blob=b'\xff'` for row 1; approve twice; publish: 400 `base_invalid`, `_assert_nothing_written` |
| `test_publish_base_invalid_refused[wrong_binding]` | STUB | Same | Same, with row 1's blob replaced by a parseable envelope whose payload `sequence` is 5 (or `project_id` another project) |
| `test_publish_not_yet_valid_refused` | STUB | Constant-false gate | Owner-insert a proposal whose payload has `not_before = now + 3600` and `new_sha = _bundle_hash(payload)`; approve twice through the route; publish: 400 `not_yet_valid`, `_assert_nothing_written` |
| `test_publish_registry_user_id_canonical_form` | STUB | G2 then `assert False` | Own org; registry entry for carol's key with `user_id = carol_id.upper()`. Carol proposes. Carol's approval through the route: 400 `proposer_cannot_approve`. Owner-insert carol's approval with stored `user_id` dave, plus alice through the route. Publish as bob: 400 `proposer_in_approvals` |
| `test_publish_concurrent_same_base_one_wins` | STUB | Constant-false gate | Two proposals A and B at the same base, each with two approvals. Publish both from a `ThreadPoolExecutor(2)` with different publishers. Sorted statuses == [201, 400], the 400 is `stale_base`, and `count(*)` of `policy_bundles` at `base+1` == 1. The loser stays `open`, with one `publish_refused` `stale_base` row |
| `test_publish_records_proposal_and_audit_row` | STUB | Constant-false gate | After a 201: the row has `status='published'`, `published_bundle_id` = the response `bundle_id`, `published_by` = the publisher, `published_at` not null. One `bundle_proposal.publish` row whose `detail` has `proposal_id`, `bundle_id`, `sequence`, `bundle_hash` = the response, `proposer_user_id`, `approver_user_ids` = the counted set, `publisher_user_id`, `auth` |
| `test_publish_refusals_audited_not_found_forbidden_not_open` | WRONG | `json.loads(r[1])` on a `jsonb` dict raises `TypeError`. It also counts any matching reason among the org's last 10 rows, not one row per refusal | Select `detail->>'proposal_id', detail->>'reason'`. Assert exactly one row each for (`random_id`, `not_found`), (`pid`, `forbidden`), (`pub_pid`, `not_open`) |
| `test_published_request_requires_bundle_link` | WRONG | Inserts nonexistent columns `bundle_hash`, `bundle_payload` and omits NOT NULL `base_sha`, `new_sha`, `payload`, `sequence`, `registry_version`: `UndefinedColumn`, not `CheckViolation` | Insert with `base_sha`/`new_sha` = 64 hex, `payload=b'{}'`, `base_sequence=0`, `sequence=1`, `registry_version=0`, `status='published'`, `published_bundle_id=NULL`, `published_by`/`published_at` set. Expect `CheckViolation` with `exc.diag.constraint_name == 'chk_published_link'` |
| `test_published_request_cannot_be_reopened_or_deleted` | WRONG | `DELETE ... LIMIT 1` is a Postgres syntax error, not `InsufficientPrivilege`; the UPDATE-trigger half of the row is missing | As `agg_app`: `DELETE FROM policy_change_requests WHERE id=%s::uuid` on a real row expects `InsufficientPrivilege`. Owner-insert a published row; as `agg_app`, `UPDATE ... SET status='open', published_bundle_id=NULL, published_by=NULL, published_at=NULL WHERE id=...` expects `psycopg.errors.RaiseException`; the row is still `published` afterwards |
| `test_propose_base_row_missing_refused` | WRONG | Sends outer key `base_sequence`, which the route refuses as 400 `unknown_fields` before and after T4. Also "nothing stored" is not checked | Drop `base_sequence` from the body (the server derives base 1 from the published request). Assert 400 `base_missing` and no `open` request for `proj` |
| `test_propose_registry_invalid_refused_and_audited` | STUB | G2 then `assert False` | Own org; tamper the stored chain; propose: 400 `registry_invalid`; one `bundle_proposal.create_refused` row; no request row for the project |
| `test_propose_braced_uppercase_real_project_400` (guard) | WEAK | Bites on the `_is_uuid` mutant, but asserts only status 400 | Assert `error == "bad_project_id"` for both, and no `policy_change_requests` row for `project_id` created by the node (count before and after) |
| `test_approve_urn_id_valid_signed_body_404` (guard) | WEAK | Bites (500 under the mutant); "nothing stored" not checked | Assert no `policy_change_approvals` row for `pid` |
| `test_proposal_detail_reports_approvals_needed` | STUB | G2 then `assert False` | Three proposals: base 0 gives `approvals_needed == 2`; a tightening after a `server` row 1 gives 1; after an `m2_unverified`-only history (prod project) gives 2 |
| `test_proposal_detail_base_approvals_are_served_set` | STUB | G2 then `assert False` | Publish with an extra stored approval that is not copied; propose at base 1; detail `base.change_approvals` key_ids == the rows keyed to the base bundle id. Then corrupt the base blob so `loosened` raises: detail `approvals_needed is None` |
| `test_proposal_reads_viewer_404` | WEAK | List only; the detail 404 and byte-equality are missing | Create a proposal in `project_id` (alice); vic `GET .../{pid}` gives 404, and `r.content` equals the missing-id 404 body for a random canonical id |
| `test_proposal_reads_other_project_admin_404` | WEAK | List only, on a project with no proposals; the detail 404 is missing | Create a proposal in `project2_id`; pat list and detail both 404, detail byte-equal to the missing-id 404 |
| `test_proposal_reads_project_admin_200` (guard) | WEAK | List only; the row says 200 on both | Add pat `GET` detail of a proposal in `project_id`: 200 |
| `test_proposal_reads_counting_cli_key_200` (guard) | WEAK | Session list only; the row says signer token and session, 200 on both | Mint frank's signer token through `/api/v1/sync/signer/token` (pattern in `test_m3_t3_security.py` around line 820); list and detail with token and with session: 200 |
| `test_proposal_reads_non_counting_cli_key_404` | WEAK | Uses erin's session; the row says by token, and detail is missing | Mint erin's signer token; list and detail with the token: 404 (keep the session check as an extra) |
| `test_proposal_reads_session_key_not_in_registry_404` | WEAK | List only. Stray `_seed_user_row` call; fixed subject `"sub-extra"` makes the user insert silently no-op on a reused DB | Assert detail 404 too; drop the stray seed; use `f"sub-{uuid.uuid4().hex[:8]}"` |
| `test_proposal_list_without_project_filters_to_readable` | STUB | G2 then `assert False` | Owner-insert 20 proposals in `project_id`, then 21 newer ones in `project2_id`; pat lists without `project=`: every item's `project_id == project_id` and `len(items) == 20` |
| `test_proposal_list_cursor_tie_break_on_id` | STUB | G2 then `assert False` | Fresh project; owner-insert 25 proposals with one `created_at`; walk `next_cursor` as alice; 25 ids collected, all distinct |
| `test_direct_publish_410_without_flag` | WEAK | Missing "no row" and the no-cookie 410 | Count `policy_bundles` for the project before and after (equal); repeat the POST with no cookie and no CSRF: 410 `direct_publish_gone` |
| `test_direct_publish_rows_labelled_m2_unverified` (guard) | WEAK | Missing `GET /admin/bundles/{seq}` shows the label | GET `/api/v1/admin/bundles/1` (session) and assert the label field is `m2_unverified` |
| `test_direct_publish_non_admin_403_under_flag` | WEAK | Status only | Assert `error == "forbidden"` and no new `policy_bundles` row |
| `test_direct_publish_noncanonical_project_400_under_flag` | WEAK | Status only | Assert `error == "bad_project_id"` and no new `policy_bundles` row |
| `test_direct_publish_audited_under_flag` | STUB | G2 then `assert False` | On `t4_demo_server`, a new project (or `bundle_payload.sequence` 2, since the label guard already used seq 1); POST 200; exactly one `bundle.direct_publish` row whose detail names the new bundle id and `admin_id` |
| `test_direct_publish_rechecked_per_request` | STUB | G2 then `assert False` | `monkeypatch.setenv` demo and `1`; `app = create_app(db_url=info["app_url"])`; `monkeypatch.delenv("AGG_ALLOW_DIRECT_PUBLISH")`; POST through `TestClient(app)`: 410 |
| `test_code_issue_response_expires_at_is_stored_value` | WEAK | Checks only "about now + 15 min"; a Python-computed `now + 15 min` passes | `SELECT expires_at FROM enrollment_codes WHERE id = code_id`; assert `abs(response - row) < 1 s`, then keep the now + 15 min window |

## 3. `ee/tests/test_m3_t4_property.py` (5 ids)

| node | verdict | reason | fix |
|---|---|---|---|
| `test_property_server_row_applied_unchanged` | STUB | Loop body is `pass`; ends in an import; passes vacuously after the build | Rule 1: draw the class first, build the candidate for it, carry the label. Earlier rows 0-4, each `m2_unverified` with p = 0.3 and kept only if the reference connector accepts it. For each accept: the reference connector, on a fresh `tmp_path` layout that applied every earlier row through `verify_and_apply` only, with its registry from its own `verify_chain(serialised chain, fp)` (rule 4), applies the server's `sign_and_check` envelope with the `counted` approvals; `bundle.json` bytes equal the envelope. Seeds `range(300 + int(os.environ.get("AGG_T4_PROPERTY_SEEDS", "0")))`; seed and class in every message |
| `test_property_verdicts_equal_all_server_at_head` | STUB | Import only | All-`server` history, connector at the head, R_dual only, P2 classes only. Assert server accepts iff connector accepts. For every server refusal, the test signs an envelope with the bundle-signer key over the same payload and passes the full stored approval list; the connector must refuse (rule 3). Same seed range and env var |
| `test_property_generator_non_vacuous` | STUB | Import only | Over the same seeds: for each P1 and P2 refusal class, at least one candidate refused with that class's expected code; accepted and refused each at least 20% per property; P1 accepted with an `m2_unverified` head at least 30; P1 accepted with copied set smaller than stored set at least 10 (`accept` appends a forged, other-hash or repeat approval with p = 0.4). Use the rule 1 class list and rule 5 domain (UUID user ids, no `expires_at`) |
| `test_property_routes_sample` | STUB | Import only; marked pg but takes no server fixture | Add a server fixture with its own org per seed. Seeds 0-19, up to 3 candidates each; approvals by route; owner-inserted `m2_unverified` rows with p = 0.3. Each 201 is fetched with `GET /sync/bundle` and applied unchanged, and its served approvals equal `verify_publish(...)[1]` for the same input. Each refusal passes `_assert_nothing_written` |
| `test_server_deny_all_matches_connector_literal` | OK | Extracts the only `enforced` dict literal in `verify_and_apply`, compares, and scans `ee/src` for other copies (today `proposals._deny_all_base` would bite) | none |

## 4. `ee/tests/test_m3_t4_static.py` (46 ids)

| node | verdict | reason | fix |
|---|---|---|---|
| `test_create_app_flag_profile_matrix[...refuse]` x9 (pilot/1, pilot/true, ""/1, unset/1, Demo/1, "demo "/1, demo/true, demo/"", demo/0) | OK | G2, then `pytest.raises(RuntimeError)` on `create_app()` | optional: `match="AGG_ALLOW_DIRECT_PUBLISH requires"` |
| `test_create_app_flag_profile_matrix[...build]` x3 (demo/1, unset/unset, pilot/unset) | OK | Guards; re-raise any RuntimeError naming the flag | none |
| `test_uvicorn_factory_exits_with_flag_under_pilot` | WEAK | Any non-zero exit passes (import or PYTHONPATH failure included); the port probe runs only after exit, so it is trivially true; PIPEs never read | Use `out, err = proc.communicate(timeout=15)`; assert `b"AGG_ALLOW_DIRECT_PUBLISH requires AGG_DEPLOY_PROFILE=demo" in err` |
| `test_direct_publish_no_db_before_flag_check` | WEAK | "Within 2 s" is not measured (`TestClient` has no timeout); `os.environ.pop` is not restored; the `MockTransport(app)` fallback is dead code that would `TypeError` | Use `monkeypatch.delenv`; `t0 = time.monotonic()`; `r = TestClient(app).post(...)`; assert `time.monotonic() - t0 < 2` and 410 `direct_publish_gone`; delete the fallback |
| `test_direct_publish_flag_check_is_first_statement` | WRONG | Requires a `Return` inside the first statement, but spec 2.5's form is `try: on = _direct_publish_enabled(...) except RuntimeError: on = False` followed by `if not on: return 410`, so a correct build fails. It also misses `x = await ...` as the first statement | Walk `admin_create_bundle.body` in order up to the first `If` whose body returns `direct_publish_gone` (410). No statement up to and including it may contain `Await`, `With`, `AsyncWith`, or a call to `_conn`/`connect`. One of them must call `_direct_publish_enabled` |
| `test_no_await_inside_transaction_anywhere` | WEAK | Form 2 ends the window at any `.close()` on any receiver, and at an early-return close before the await. Measured: snippets `cur.close()` then `await`, and `if bad: conn.close(); return` then `await`, give 0 violations. Today it does find both live sites (`bundles.py:209->221`, `signer.py:409->423`; counts 70 and 3 match). Docstring says 1 assign site, constant says 3 | Count a close only if `func.value` is `ast.Name` with the site's variable. Ignore closes nested in an `If`/`Try` handler that also returns; only a close at the assignment's statement level or in `finally` ends the window. Fix the docstring to 3 |
| `test_await_guard_flags_synthetic_violation[with]` (guard) | WRONG | Exercises `_scan_synthetic`, a second implementation, not the visitor the real node uses. Measured divergence: the early-close snippet is flagged by `_scan_synthetic` and missed by `_scan_await_violations`, so a mutant of the real visitor survives | Refactor `_scan_await_violations` into `_scan_sources(iterable of (name, source))`; the guard calls it on the snippets: `with` gives 1 violation, autocommit gives 0. Add the two false-negative snippets above, each expecting 1. Delete `_scan_synthetic` |
| `test_await_guard_flags_synthetic_violation[assign]` (guard) | WRONG | Same | Same |
| `test_is_project_admin_single_definition` | WEAK | Counts the fragment with `source.count`, which misses implicitly joined literals: raw 4 vs joined 5 today (measured). A split copy left after the build passes | Count over `ast.Constant` string values (joined); expect exactly 1, inside `rbac.py` |
| `test_server_imports_connector_by_name_only` (guard) | WEAK | Does not see `from sandbox.connector.sync import bundles` (module object through the package) or `importlib.import_module("sandbox.connector.sync.bundles")`; either reaches any connector function | Also fail on `ImportFrom` with module `sandbox.connector.sync` (or `sandbox.connector`) naming `bundles`, `process` or `sync`, and on any string constant equal to either dotted module name |
| `test_verify_and_apply_never_referenced_in_server` (guard) | OK | `Name` and `Attribute` both covered | optional: also fail on the string constant `"verify_and_apply"` |
| `test_publish_route_calls_shared_verifier` | WEAK | The second clause (no `_verify_change_approvals` call anywhere in `proposals.py` outside the approval route) is checked only inside `publish_proposal`; calls are matched only as `ast.Name` | Walk every function in `proposals.py` except `approve_proposal`; refuse `Call`s to `_verify_change_approvals` as `Name` or `Attribute`. Accept `verify_publish`/`sign_and_check` as `Name` or `Attribute` |
| `test_server_counting_roles_match_connector` | OK | Takes the `intersection({...})` set from the connector | none |
| `test_verify_publish_refusal_codes[...]` x16 (all ids) | WRONG | Setup raises `RegistryError` on a correct build: genesis threshold 2 with one signature, and `bundle_signer` key id equal to a key in `keys`. Also `binding_mismatch_sequence` mismatches the row, not `sequence != base+1`, so deleting that clause survives. `match=` on `str(exc)` can match the detail instead of `code` | Registry: two admin cli keys (u1, u2), threshold 2, both sign; a separate bundle-signer key not in `keys`. For `binding_mismatch_sequence`: payload `sequence=3`, `base_sequence=0`, rows the same. Assert `excinfo.value.code == <code>` |
| `test_sign_and_check_wrong_signer_refused` | WRONG | Same `bundle_signer` collision: `verify_chain` raises before `sign_and_check` | Use a separate bundle-signer key in the registry; call `sign_and_check(payload, sk_wrong, registry)`; assert `.code == "signer_not_in_registry"` |
| `test_operator_refusal_ignores_server_rows` (guard) | OK | Bites if either file gains SQL on `policy_bundles` or code reading `allow_requester` | optional: `assert p.exists()` instead of `continue` |
| `test_publish_db_error_mapping` | WEAK | Flags are OR-ed across all handlers. `constraint_name` OR the pinned name is enough. No order check (a generic handler before `UniqueViolation` makes it dead). A tuple handler is not seen. `"500"` is any substring. The `UniqueViolation` handler is not checked for `stale_base` | Find the one `Try` whose handlers include `UniqueViolation`. In it: handler i has a `Compare` between `Attribute(attr="constraint_name")` and `Constant("policy_bundles_project_id_sequence_key")`, and returns `stale_base`; a later handler j > i (type `psycopg.Error`, `DatabaseError` or `Exception`, tuples unpacked) calls `.rollback()`, calls `_audit_refused(..., "internal_error", ...)`, and returns `status_code=500`. Add the A-S1 pg pin |
| `test_server_label_insert_only_in_publish` | WEAK | Counts files where both substrings occur anywhere, not statements; does not check the enclosing function; a second server insert in `proposals.py` is not counted; a `'server'` literal anywhere in `bundles.py` would count it | AST: for each string constant containing `INSERT INTO policy_bundles`, decide whether it or its call's parameters carry `'server'`. Require exactly one, enclosed by `publish_proposal`. Count `UPDATE policy_bundles` and `DELETE FROM policy_bundles` over joined constants (case-insensitive) == 0 |
| `test_direct_publish_uses_shared_body_reader` | OK | Matches the row | optional: assert `admin_create_bundle` calls `_read_body_capped` and makes no `request.json`/`request.body` call |
| `test_compose_override_only_flag_env` | OK | Exact dict equality | none |
| `test_cursor_naive_read_as_utc` | WEAK | The refusal half is vacuous: `except (ValueError, Exception)` catches the test's own `AssertionError`. The tz assertion is skipped when the result is neither a datetime nor a tuple | `with pytest.raises(ValueError)` (lead names the contract; or test through `GET ?cursor=...` for 400 `bad_cursor`) for braced and uppercase ids. Assert the parsed value `== datetime(2026, 11, 18, 10, 0, tzinfo=timezone.utc)` unconditionally |

## 5. `tests/security/test_m3_t4_cli.py` (4 ids)

| node | verdict | reason | fix |
|---|---|---|---|
| `test_cli_deny_all_base_matches_connector_literal` (guard) | WRONG | Imports `DENY_ALL_BASE` and compares it to a dict. Spec item 17 makes it a function, so the build breaks this guard (callable `!=` dict, or `ImportError` if renamed) | Make it an `ast` pin as the row says: parse `change_cmds.py`, take the dict literal returned by the deny-all function, `literal_eval`, compare to the connector literal. Or call it if callable |
| `test_cli_deny_all_base_fresh_per_call` | WRONG | Gate `find_spec("agg_cp.sync.publish_verify")` raises `ModuleNotFoundError` in the root `pytest` and `connector-standalone` jobs (no `agg_cp`), so it is not xfail there today and the gate never opens there | Gate on the CLI feature: `require_m3(4, not isinstance(getattr(change_cmds, "DENY_ALL_BASE", None), dict), ...)`. No `agg_cp` reference in root tests |
| `test_approve_change_esc_in_loosened_error_no_raw_esc` (guard) | WRONG | Tests `_safe_str` alone; removing `_safe_str` at `change_cmds.py:466` (the named mutant) leaves it green | Behavioural: monkeypatch `change_cmds.loosened` to raise `ValueError("\x1b[31mx")`; run `approve-change` through `CliRunner` against a stubbed fetch; assert `"\x1b" not in result.output`. Minimum: AST check that the f-string starting `"loosened error: "` in the approve function wraps its value in a `_safe_str` call |
| `test_propose_bundle_local_key_messages_sanitised` | WRONG | Same ee-module gate as above. The body also passes if the loop variable is renamed from `k` | CLI-feature gate. Behavioural: stub the server response to drop, then alter, a bundle key containing ESC; `CliRunner` `propose-bundle`; no raw ESC in either refusal. Minimum: the f-strings starting `"server dropped section"` and `"server altered"` wrap their value in `_safe_str` |

## 6. Totals

| File | OK | WEAK | WRONG | STUB | Total |
|---|---|---|---|---|---|
| `ee/tests/test_m3_t4_publish_verify.py` | 3 | 16 | 6 | 24 | 49 |
| `ee/tests/test_m3_t4_property.py` | 1 | 0 | 0 | 4 | 5 |
| `ee/tests/test_m3_t4_static.py` | 17 | 9 | 20 | 0 | 46 |
| `tests/security/test_m3_t4_cli.py` | 0 | 0 | 4 | 0 | 4 |
| **All** | **21** | **25** | **30** | **28** | **104** |

## 7. Rows qa must fix, by file

Prerequisites (section 1): the `_assert_nothing_written` helper; a `jsonb`-safe audit read; fixture additions (enrolled device per project, threshold-1 second org, own-org helper with fresh keys, `revoked_at = NULL` reset after v2); prod-environment projects where "not loosened" matters; dave's admin binding recorded in the spec or dropped.

**`ee/tests/test_m3_t4_publish_verify.py`** (46): `test_publish_verified_loosening_connector_applies_unchanged`, `test_publish_first_bundle_needs_two_even_if_not_loosened`, `test_publish_single_approval_loosening_refused_nothing_written`, `test_publish_forged_approval_refused_nothing_written`, `test_publish_wrong_registry_approval_refused`, `test_publish_counts_for_dual_only_when_two_needed`, `test_publish_single_admin_key_tightening_201`, `test_publish_head_m2_row_loosening_needs_two`, `test_publish_loosened_against_server_base_only_needs_two`, `test_publish_first_server_row_after_m2_rows_needs_two`, `test_publish_copies_only_counted_approvals`, `test_publish_registry_invalid_refused_and_audited[byte_flip]`, `[invalid_json]`, `test_publish_no_registry_refused`, `test_publish_registry_version_stale_refused`, `test_publish_signer_not_in_registry_refused`, `test_publish_base_invalid_refused[unparseable]`, `[wrong_binding]`, `test_publish_not_yet_valid_refused`, `test_publish_registry_user_id_canonical_form`, `test_publish_concurrent_same_base_one_wins`, `test_publish_records_proposal_and_audit_row`, `test_publish_refusals_audited_not_found_forbidden_not_open`, `test_published_request_requires_bundle_link`, `test_published_request_cannot_be_reopened_or_deleted`, `test_propose_base_row_missing_refused`, `test_propose_registry_invalid_refused_and_audited`, `test_propose_braced_uppercase_real_project_400`, `test_approve_urn_id_valid_signed_body_404`, `test_proposal_detail_reports_approvals_needed`, `test_proposal_detail_base_approvals_are_served_set`, `test_proposal_reads_viewer_404`, `test_proposal_reads_other_project_admin_404`, `test_proposal_reads_project_admin_200`, `test_proposal_reads_counting_cli_key_200`, `test_proposal_reads_non_counting_cli_key_404`, `test_proposal_reads_session_key_not_in_registry_404`, `test_proposal_list_without_project_filters_to_readable`, `test_proposal_list_cursor_tie_break_on_id`, `test_direct_publish_410_without_flag`, `test_direct_publish_rows_labelled_m2_unverified`, `test_direct_publish_non_admin_403_under_flag`, `test_direct_publish_noncanonical_project_400_under_flag`, `test_direct_publish_audited_under_flag`, `test_direct_publish_rechecked_per_request`, `test_code_issue_response_expires_at_is_stored_value`.

**`ee/tests/test_m3_t4_property.py`** (4): `test_property_server_row_applied_unchanged`, `test_property_verdicts_equal_all_server_at_head`, `test_property_generator_non_vacuous`, `test_property_routes_sample`.

**`ee/tests/test_m3_t4_static.py`** (29 ids): `test_uvicorn_factory_exits_with_flag_under_pilot`, `test_direct_publish_no_db_before_flag_check`, `test_direct_publish_flag_check_is_first_statement`, `test_no_await_inside_transaction_anywhere`, `test_await_guard_flags_synthetic_violation[with]`, `[assign]`, `test_is_project_admin_single_definition`, `test_server_imports_connector_by_name_only`, `test_publish_route_calls_shared_verifier`, `test_verify_publish_refusal_codes[...]` (all 16 ids), `test_sign_and_check_wrong_signer_refused`, `test_publish_db_error_mapping`, `test_server_label_insert_only_in_publish`, `test_cursor_naive_read_as_utc`. Also add the A-S1 pg pin.

**`tests/security/test_m3_t4_cli.py`** (4): `test_cli_deny_all_base_matches_connector_literal`, `test_cli_deny_all_base_fresh_per_call`, `test_approve_change_esc_in_loosened_error_no_raw_esc`, `test_propose_bundle_local_key_messages_sanitised`.

Optional hardening on OK rows (not required): `match=` on the 9 matrix refuse cases; `p.exists()` in the S2 guard; string-constant check in the `verify_and_apply` guard; call check in the shared-reader node.

After the fixes, rerun the read-only measurement: every marked node xfails at a real feature gate (no constant `False`), the root file collects and xfails with `agg_cp` uninstalled, and each guard fails under its named mutant.

# Re-audit, 18 Nov 2026

Reviewer: security-engineer (leader tier). Scope: the 83 nodes marked non-OK above, after qa's fixes, plus defects the fixes introduced. Same verdict scale. Read-only: nothing in the repo was edited except this section. Scratch files lived under `D:\t4tmp\sec` and are removed. No container or process is left running (`docker ps -a` is empty; no python process from these runs).

Method, beyond reading the four files:
- **Gate-off run.** A scratch pytest plugin made each module's `require_m3` a no-op, so the code after every gate ran against today's tree (publish file with `--runxfail`, CLI file). Every publish node then fails on a T4 assertion, except one setup error (`test_proposal_list_without_project_filters_to_readable`).
- **Spec reference.** A scratch `agg_cp.sync.publish_verify`, written from spec 2.1 only, was injected through `sys.modules` for the static and property files (`--runxfail`). Seven reference mutants were run against the property nodes: need always 2, no head rule, head used as base, no first-bundle rule, no dual filter, no exclusions, copy all.
- **CLI mutant.** `change_cmds._safe_str = str`.
- **AST logic.** The static file's own AST logic was run on today's `proposals.py` and `signer.py`, and on two synthetic correct builds.

## R1. `ee/tests/test_m3_t4_publish_verify.py` (46 re-audited)

| node | verdict | one line (fix where not OK) |
|---|---|---|
| `test_publish_verified_loosening_connector_applies_unchanged` | WRONG | Calls `verify_and_apply(str(layout), served_env, served_approvals, reg, bsp)`, but the signature is `(layout, envelope, registry, bundle_signer_pub, change_approvals, *, org_id, project_id)`. A correct build gets a `TypeError`. Also `layout` must be a `FolderLayout`, and `bundle.json` sits at `<ws>/.sandbox/state/sync/bundle.json`. Fix: `ws/.sandbox` made, `FolderLayout(ws)`, `verify_and_apply(layout, served_env, reg, bsp, served_approvals, org_id=info["org_id"], project_id=proj)`, read the file from that path, and compare it with `bytes(bundle_blob)` from `policy_bundles` |
| `test_publish_first_bundle_needs_two_even_if_not_loosened` | OK | prod project, `loosened == {}` from the propose response, nothing written |
| `test_publish_single_approval_loosening_refused_nothing_written` | OK | |
| `test_publish_forged_approval_refused_nothing_written` | OK | |
| `test_publish_wrong_registry_approval_refused` | OK | own org, v2 drops bob, projection reset, `registry_version == 2` asserted; a projection-reading mutant gets 201 |
| `test_publish_counts_for_dual_only_when_two_needed` | WRONG | sadmin proposes and his key's approval is stored, so spec 2.1 (g) resolves it to the proposer: a correct build gives `proposer_in_approvals`. The connector half has the same `verify_and_apply` call error, and it uses `tempfile.mkdtemp`. Fix: spub proposes and publishes; sadmin and suser2 approve through the route, each asserted 201; assert 400 `approvals_insufficient` with `"dual_filter: true"` in `detail`, plus `_assert_nothing_written`; connector half on `FolderLayout(tmp_path/...)` with the keyword call |
| `test_publish_single_admin_key_tightening_201` | WRONG | The project is `staging`, and the route stamps that into the payload. The owner-inserted base row has no `environment`, which means prod, so `loosened` reports prod to staging, need is 2, and one approval gets 400. Fix: `create_project(..., environment="prod")` |
| `test_publish_head_m2_row_loosening_needs_two` | WRONG | Same environment effect: the payload also loosens the server row, so a no-head-rule mutant still gets 400. A9 item 3 is not isolated. Fix: `environment="prod"` |
| `test_publish_loosened_against_server_base_only_needs_two` | WRONG | Same: the payload also loosens head row 2 (environment), so a head-as-base mutant still gets 400. MUST 2 is not isolated. Fix: `environment="prod"` |
| `test_publish_first_server_row_after_m2_rows_needs_two` | OK | |
| `test_publish_copies_only_counted_approvals` | WEAK | The served `change_approvals` (spec row) is not checked: the seeded device token is thrown away. The selected `signed_at` is never compared. Fix: keep the token; `GET /sync/bundle?after=0` key_ids == {alice, bob}; each copied row's `signed_at` == the proposal's stored row for that `key_id` |
| `test_publish_registry_invalid_refused_and_audited[byte_flip]`, `[invalid_json]` | OK | |
| `test_publish_no_registry_refused` | OK | |
| `test_publish_registry_version_stale_refused` | OK | |
| `test_publish_signer_not_in_registry_refused` | OK | |
| `test_publish_base_invalid_refused[unparseable]`, `[wrong_binding]` | OK | |
| `test_publish_not_yet_valid_refused` | OK | |
| `test_publish_registry_user_id_canonical_form` | WEAK | The publish half discriminates: a raw-string compare counts two users and gives 201. The approval-route half of the row is never asserted (`rc` is unused). Fix: after the gate, `rc.status_code == 400` and `error == "proposer_cannot_approve"` |
| `test_publish_concurrent_same_base_one_wins` | OK | |
| `test_publish_records_proposal_and_audit_row` | WEAK | The row says the audit names the hash; `bundle_hash` and `sequence` are not compared. Fix: `detail["bundle_hash"] == resp["bundle_hash"]`, `detail["sequence"] == resp["sequence"]` |
| `test_publish_refusals_audited_not_found_forbidden_not_open` | WEAK | The jsonb read is fixed, but each query filters on `reason` only and takes the newest row. `proposal_id` is selected and never compared, and "one each" is not checked. Fix: `AND detail->>'proposal_id' = %s`, and assert `count(*) == 1` per pair |
| `test_published_request_requires_bundle_link` | OK | |
| `test_published_request_cannot_be_reopened_or_deleted` | OK | |
| `test_propose_base_row_missing_refused` | OK | `_max_sequence` takes published requests into account, so base 1 is derived |
| `test_propose_registry_invalid_refused_and_audited` | OK | (today the route returns 500 on the tampered chain; T4 must make it 400) |
| `test_propose_braced_uppercase_real_project_400` (guard) | OK | |
| `test_approve_urn_id_valid_signed_body_404` (guard) | OK | |
| `test_proposal_detail_reports_approvals_needed` | OK | |
| `test_proposal_detail_base_approvals_are_served_set` | WRONG | No uncopied approval is stored, so the request's set equals the served set and T3's read passes. The node reads `a["signatures"][0]["key_id"]`, but the items today are `{user_id, key_id}`, so a build that keeps that shape gives `[]`. The `approvals_needed: null` half is missing. Fix: before publishing, owner-insert erin's valid approval over `bh` (viewer role, dropped at (g)). Compare `a.get("key_id") or a["signatures"][0]["key_id"]`; served == rows keyed to the bundle id == {alice, bob}. Second project: valid server row 1, propose at base 1, then owner UPDATE that row's blob to a bound envelope with `governance_policy: {"clauses": ["x"]}` (`loosened` raises `AttributeError`, measured); assert `approvals_needed is None` |
| `test_proposal_reads_viewer_404` | OK | |
| `test_proposal_reads_other_project_admin_404` | OK | |
| `test_proposal_reads_project_admin_200` (guard) | OK | |
| `test_proposal_reads_counting_cli_key_200` (guard) | WEAK | The token half sits under `if r_token.status_code in (200, 201)`: it runs today but would skip silently if minting broke. Fix: assert the mint, then list and detail by token and by session |
| `test_proposal_reads_non_counting_cli_key_404` | WEAK | The token and detail halves sit under `if` (the gate-off run shows the token branch runs today). Fix: assert the mint is 200/201 and the propose is 201, then assert unconditionally |
| `test_proposal_reads_session_key_not_in_registry_404` | WEAK | The `approver_keys` row has no `roles`, so a build that reads roles from the projection also returns 404: the MUST 11 mutant survives. Detail sits under `if`. Fix: insert `roles` `'["approver"]'::jsonb`; make the propose unconditional |
| `test_proposal_list_without_project_filters_to_readable` | WRONG | Setup error, measured: `now() + interval '%s seconds'` puts the placeholder inside a literal, giving `IndeterminateDatatype: could not determine data type of parameter $8`. Fix: `now() + make_interval(secs => %s)` with the int `i + 1` (page size is 20, so `len(items) == 20` holds) |
| `test_proposal_list_cursor_tie_break_on_id` | WEAK | Ids go into a `set`, so cross-page duplicates are hidden: an inclusive cursor still reaches 25. Fix: collect a list; `len(ids) == 25 == len(set(ids))` |
| `test_direct_publish_410_without_flag` | OK | |
| `test_direct_publish_rows_labelled_m2_unverified` (guard) | WEAK | `GET /api/v1/admin/bundles/1` has no `?project=`, so the route returns 400 `missing_project` and the label branch never runs. Fix: `params={"project": info["project_id"]}`; assert 200 and `verification == "m2_unverified"` unconditionally |
| `test_direct_publish_non_admin_403_under_flag` | OK | (today 409, not 200: the label guard already holds seq 1; T4's 403 comes first) |
| `test_direct_publish_noncanonical_project_400_under_flag` | OK | |
| `test_direct_publish_audited_under_flag` | WEAK | Passes on any `bundle.direct_publish` row that has either key. Fix: read the new row's id from `policy_bundles` for `proj2`; assert exactly one audit row whose `detail->>'bundle_id'` is that id, with `info["admin_id"]` among the detail values |
| `test_direct_publish_rechecked_per_request` | OK | |
| `test_code_issue_response_expires_at_is_stored_value` | OK | the response has `code_id`, so the stored-row compare runs |

## R2. `ee/tests/test_m3_t4_property.py` (4 re-audited)

Spec-reference statistics over seeds 0-299:
- P1: 72 accepted, all on R_dual. 38 candidates have a server base, all in refusal classes. 0 accepted with need 1. All 28 `accept` candidates drawn on R_single are refused: every candidate is a first bundle, and no R_single key counts for dual.
- P2: 0 candidates with a server base.
- Mutants: need-always-2 gives exactly the correct build's result. The other six are killed.

| node | verdict | one line |
|---|---|---|
| `test_property_server_row_applied_unchanged` | WEAK | Passes against the reference, but every accepted candidate is a first server row. The generator labels every earlier row `m2_unverified` and includes each with p 0.3. Spec: rows 0-4, each `m2_unverified` with p 0.3, else `server`. R_single `accept` never meets its label |
| `test_property_verdicts_equal_all_server_at_head` | WRONG | P2 has no earlier rows at all, so it never tests an all-`server` sequence, and the need-always-2 mutant passes |
| `test_property_generator_non_vacuous` | WRONG | Fails on a correct build: `P1 m2_head accepted 25 < 30` against the reference |
| `test_property_routes_sample` | WRONG | (1) Compares served key_ids (alice, bob of `t4_server`) with the pure verifier's u0/u1 key_ids, which are never equal when both accept. (2) It applies m2 rows to the connector with property-key approvals that the `t4_server` registry does not hold; the `BundleError` is swallowed, so the connector stays empty and refuses the served bundle at base > 0. (3) `environment` is server-owned at propose (400 `server_owned_field`), so about 75% of candidates `continue` silently. (4) Candidate approvals and classes are ignored: alice and bob always approve. (5) `except Exception` wraps the pure call. (6) There is no count of 201s or refusals, so an all-skip run passes after the build |

Fixes:
- **Earlier rows.** `n = randint(0, 4)`. P1 labels each `m2_unverified` with p 0.3, else `server`; P2 labels all `server`. Each row gets two valid R_dual approvals (u0, u1) and goes through the reference connector's `verify_and_apply`; assert each row is accepted. `server_base` is the last `server` row; `head` is the last row when it is m2.
- **`accept`.** Two valid counting approvals. R_single (p 0.25) only when a server base exists and the payload tightens both the base and the head: build it from the base with folder `deny`, approval false/false, the same environment, and the base's clauses and servers. Then one approval, need 1.
- **P2.** Include tightenings, so `single` is accepted by both sides on some seeds. This kills need-always-2.
- **`wrong_kind`.** Use `[sks[1] cli, browser key of u0]`, so only the key kind decides.
- **`head_m2_loosening`.** Make the server base maximal: folder `allow`, clauses `[]`, servers s1-s3 with t1 and t2, approval true/true, environment `dev`.
- **Rule 4.** Pass `json.loads(json.dumps(chain))` to the reference connector's `verify_chain`.
- **Thresholds.** Re-measure with a spec reference and adjust weights; for example, force at least one m2 earlier row for `accept` with p 0.5. Replace the comment at lines 282-287 with the measured numbers.
- **Route sample.**
  - Build the pure input from what the route stored: payload bytes, `new_sha`, the stored approvals with `signed_at`, and the org's stored chain through its own `verify_chain`. Take `server_base` and `head` from the project's rows; proposer and publisher are carol.
  - Compare the verdict, and the counted key_ids with the served ones.
  - Apply m2 rows with alice and bob approvals and assert each applies.
  - Strip `environment` from the body and create the project with the candidate's environment (None means prod).
  - Drive the classes through the stored approvals: one route approval for `single`; owner-inserted forged, other-hash and erin's viewer-role approvals.
  - Catch `PublishRefused` only. Assert at least one 201, at least one refusal, and that every candidate reached publish.
  - Compare `bundle.json` with `bytes(bundle_blob)`.

## R3. `ee/tests/test_m3_t4_static.py` (29 re-audited)

| node | verdict | one line |
|---|---|---|
| `test_uvicorn_factory_exits_with_flag_under_pilot` | OK | `communicate(timeout=15)`, exact refusal text in stderr, reaped in `finally` |
| `test_direct_publish_no_db_before_flag_check` | OK | (optional: assert `error == "direct_publish_gone"`) |
| `test_direct_publish_flag_check_is_first_statement` | WEAK | Any `Return` inside an `If` ends the walk, so `if x: return ...` then `await ...` then `if not on: return 410` passes. Fix: stop only at an `If` that holds the constant `"direct_publish_gone"` or `410` |
| `test_no_await_inside_transaction_anywhere` | WRONG | Form 2 reads only top-level statements, but all three non-autocommit sites are inside `try:` (`signer.py` 409, 744, 1137). Measured today: assign sites 0, and the only violation is `bundles.py 209->221`. `assign_count >= 3` fails on a correct build, and the real `create_link_code_route` violation is invisible. Fix: find assignments at any depth, skipping nested defs. The window is the rest of the assignment's block plus the rest of every enclosing block. It ends at `var.close()` at the assignment's block level, or anywhere inside an enclosing `finally`. Expect `assign_count == 3` |
| `test_await_guard_flags_synthetic_violation[with]` (guard) | OK | |
| `test_await_guard_flags_synthetic_violation[assign]` (guard) | WEAK | No snippet has the real shape, so the visitor's blindness survives. Fix: add `conn = None` / `try: conn = connect(url, autocommit=False)` / `...` / `x = await request.json()` / `finally: if conn: conn.close()`, expecting 1 violation |
| `test_is_project_admin_single_definition` | OK | |
| `test_server_imports_connector_by_name_only` (guard) | OK | |
| `test_publish_route_calls_shared_verifier` | WRONG | The second clause uses `ast.walk` per FunctionDef, which descends into nested defs. `proposals_router` contains `approve_proposal`; measured hit `proposals_router` at `proposals.py:895`. A correct build fails. Fix: walk each function with `_walk_no_inner_funcs` (already in the file) and exempt only `approve_proposal` |
| `test_verify_publish_refusal_codes[...]` x16 | OK | All 16 pass against the reference. With proposer = publisher = u2, a missed check falls through to `proposer_in_approvals`, never to the expected code |
| `test_sign_and_check_wrong_signer_refused` | OK | |
| `test_publish_db_error_mapping` | WEAK | `has_compare` still ORs the `constraint_name` attribute and the pinned constant. Fix: require both inside the same `Compare` |
| `test_server_label_insert_only_in_publish` | WRONG | Measured on synthetic correct builds: an inline `'server'` in the SQL gives 0 matches, because only an exact `"server"` constant counts. A `"server"` parameter gives 2 (`proposals_router` and `publish_proposal`, nested walk). Fix: for each Call whose SQL constant holds `INSERT INTO policy_bundles`, count it as server when the SQL holds `'server'` or a Constant `"server"` is among its args. Attribute it to the innermost function; expect exactly one, in `publish_proposal` |
| `test_cursor_naive_read_as_utc` | WEAK | The `ValueError` contract is not in spec 2.9, so a build whose `_parse_cursor` returns None (and the route returns 400 `bad_cursor`) fails. Fix: accept `ValueError` or a None return, or the lead names the contract in 2.9 |

## R4. `tests/security/test_m3_t4_cli.py` (4 re-audited)

| node | verdict | one line |
|---|---|---|
| `test_cli_deny_all_base_matches_connector_literal` (guard) | OK | Handles a module dict, a function returning a literal, or a callable. A private name (`_deny_all_base`) is not found; the lead names it in item 17 |
| `test_cli_deny_all_base_fresh_per_call` | OK | CLI-feature gate; the file has no `agg_cp` reference |
| `test_approve_change_esc_in_loosened_error_no_raw_esc` (guard) | OK | Behavioural. Measured: fails under the `_safe_str = str` mutant (`'loosened error: \x1b[31m...'`) and passes today |
| `test_propose_bundle_local_key_messages_sanitised` | OK | The gate-off run reaches `server dropped section: \x1b[31mevil` and fails only on the ESC assertion |

## R5. New defects from the fixes

- **N1. Matrix ids.** `_matrix_id` unpacks `pytest.param` objects, so the ids are reprs such as `profile=('pilot', '1', True),flag=(MarkDecorator(...`. All 12 end in `,build` (measured with `--collect-only`), including the 9 refuse cases, and they embed `<class 'tests.m3_pending.M3T4Pending'>`, which depends on import mode. Fix: an explicit `id=` on every case, for example `pilot-1-refuse`. These ids go into `M3_BASELINE.md`.
- **N2. Property import of `t4_server`.** No `test_` name is imported, so nothing is re-collected. But a module-scoped fixture is instantiated per requesting module, so the property module builds its own 4-worker server and orgs. They run one after the other, not at the same time. Acceptable; record it, or move `t4_server` and the helpers to a non-test module (for example `ee/tests/t4_fixtures.py`) that both files import.
- **N3. Bytes comparison.** P1 compares with `_canonical_json_bytes(envelope)`, the connector's own serialiser. That is fine for the pure property. Node 1 and the route sample re-serialise the parsed served JSON, so a server whose stored blob is not the canonical bytes passes. Compare with `bytes(bundle_blob)` instead.
- **N4. `_assert_nothing_written`.** It omits the spec clause "no `policy_change_approvals` row keyed to a bundle id"; 0007 has no FK on `change_request_id`. Fix: `_counts` also returns the count of the org's approvals whose `change_request_id` is not a `policy_change_requests.id`, and the helper asserts it unchanged.
- **N5. Comment honesty.** Property lines 282-287 claim measured numbers ("~44% with m2 head") that the spec reference contradicts (25 accepted with an m2 head). No verifier existed to measure against.
- **N6 (carried, still open). A-S1 pin.** `test_policy_bundles_sequence_constraint_name_pinned` (pg guard) is still absent, so `test_publish_db_error_mapping` pins an unverified name. Add it; the publish file becomes 50 ids, and the lead updates the count.

## R6. Verdict

**NOT READY TO COMMIT TESTS-FIRST.** Still to fix, with the concrete fixes above:
- **Publish file.** WRONG: `test_publish_verified_loosening_connector_applies_unchanged`, `test_publish_counts_for_dual_only_when_two_needed`, `test_publish_single_admin_key_tightening_201`, `test_publish_head_m2_row_loosening_needs_two`, `test_publish_loosened_against_server_base_only_needs_two`, `test_proposal_detail_base_approvals_are_served_set`, `test_proposal_list_without_project_filters_to_readable`. WEAK: `test_publish_copies_only_counted_approvals`, `test_publish_registry_user_id_canonical_form`, `test_publish_records_proposal_and_audit_row`, `test_publish_refusals_audited_not_found_forbidden_not_open`, `test_proposal_reads_counting_cli_key_200`, `test_proposal_reads_non_counting_cli_key_404`, `test_proposal_reads_session_key_not_in_registry_404`, `test_proposal_list_cursor_tie_break_on_id`, `test_direct_publish_rows_labelled_m2_unverified`, `test_direct_publish_audited_under_flag`.
- **Property file.** WRONG: `test_property_verdicts_equal_all_server_at_head`, `test_property_generator_non_vacuous`, `test_property_routes_sample`. WEAK: `test_property_server_row_applied_unchanged`.
- **Static file.** WRONG: `test_no_await_inside_transaction_anywhere`, `test_publish_route_calls_shared_verifier`, `test_server_label_insert_only_in_publish`. WEAK: `test_direct_publish_flag_check_is_first_statement`, `test_await_guard_flags_synthetic_violation[assign]`, `test_publish_db_error_mapping`, `test_cursor_naive_read_as_utc`.
- **Cross-cutting.** N1, N3, N4, N5, N6.

After the fixes, rerun: CI mode (0 failed); `--runxfail` (every marked node raises `M3T4Pending`); the property and pure static nodes against a spec reference (they pass, and need-always-2 is killed); guards under their named mutants.

## R7. Totals after re-audit

| File | OK | WEAK | WRONG | STUB | Total |
|---|---|---|---|---|---|
| `ee/tests/test_m3_t4_publish_verify.py` | 32 | 10 | 7 | 0 | 49 |
| `ee/tests/test_m3_t4_property.py` | 1 | 1 | 3 | 0 | 5 |
| `ee/tests/test_m3_t4_static.py` | 39 | 4 | 3 | 0 | 46 |
| `tests/security/test_m3_t4_cli.py` | 4 | 0 | 0 | 0 | 4 |
| **All** | **76** | **15** | **13** | **0** | **104** |

Of the 83 re-audited nodes: 55 OK, 15 WEAK, 13 WRONG, 0 STUB.

# Third audit, 18 Nov 2026

Reviewer: security-engineer (leader tier). Scope: every row marked WEAK or WRONG in the re-audit, N1-N6, the three spec edits since the re-audit, and defects the fixes introduced. qa's own claims were not used as evidence. Read-only: nothing in the repo was edited except this section. Scratch lived under `D:\t4tmp\sec3` (plus `--basetemp` dirs `D:\t4tmp\sec3_*`) and is removed. No container or process is left running (`docker ps -a` empty before and after).

Method:
- **Gate-off.** A scratch plugin made every `require_m3` a no-op. Publish file with `--runxfail`: 44 failed, 6 passed. Every marked node fails on its first T4 assertion. None fails in setup.
- **Route sample, gate-off with a log.** A plugin wrapped `_approve` and `_publish` and logged the outcome for each proposal.
- **Spec reference.** A scratch `agg_cp.sync.publish_verify`, written from spec 2.1 only, was injected through `sys.modules`. It ran the property nodes and the pure static nodes. Mutants: need-always-2 (a corrected version, see below), no head rule, head as base, no first-bundle rule, no dual filter, no exclusions, copy-kept (copy every approval that survives (g)), copy-raw (copy every stored approval).
- **Generator statistics.** A scratch node reused the module's `_generate_candidate` over seeds 0-299.
- **Static AST nodes.** Each node ran on today's tree, on a synthetic correct build (a copy of `ee/src/agg_cp` with the spec 2.2, 2.5 and 2.7 shapes, using both the inline `'server'` form and the parameter form), and under 6 mutants.
- **CLI.** The file ran as is and under `change_cmds._safe_str = str`.
- **Lint and secrets.** `ruff --select F,B` on the four files. gitleaks `dir` on the four files: no leaks. Semgrep and trivy were not run, because their caches live on C:, which hit 0 MB free during this audit.

## T1. Spec edits

| edit | verdict | note |
|---|---|---|
| `_parse_cursor` returns `(aware UTC datetime, id or None)`; `ValueError` on a bad `\|<id>` or an unparseable time | ACCEPT with one condition | Measured: if an aware input is normalised with `astimezone(timezone.utc)`, `9999-12-31T23:59:59-23:59` and `0001-01-01T00:00:00+23:59` raise `OverflowError`, not `ValueError`, so the route would return 500. The frozen `+23:59` cursor converts fine, and the week date `2026-W47-1T10:00` parses. Condition: 2.9 says an aware time that cannot be converted to UTC also raises `ValueError` (400 `bad_cursor`), and qa adds that assertion to `test_cursor_naive_read_as_utc`. The date-only refusal (`"T"` check) stays |
| CLI `DENY_ALL_BASE` becomes `deny_all_base() -> dict` | ACCEPT | Both CLI deny-all nodes already handle the function form. The file has no `agg_cp` import (one comment only) |
| A-S1 guard `test_policy_bundles_sequence_constraint_name_pinned`; counts 48 functions / 50 ids / 6 guards; ee +101, root +4 | ACCEPT | It passes today. It checks the name, `contype = 'u'` and the column order. Counts measured: publish 50 ids (44 + 6), property 5, static 46, CLI 4. Optional: add `AND conrelid = 'policy_bundles'::regclass` |

## T2. Publish file, previously non-OK rows

| node | verdict | one line |
|---|---|---|
| `test_publish_verified_loosening_connector_applies_unchanged` | OK | Correct `verify_and_apply` call on `FolderLayout`. Compares `bundle.json` with `bytes(bundle_blob)` and the served key_ids with {alice, bob} |
| `test_publish_counts_for_dual_only_when_two_needed` | WRONG (new) | `tmp_path` is used at line 1456 but is not a parameter (ruff F821). On a correct build the connector half raises `NameError`. Fix: add `tmp_path` to the signature. Optional: assert both `"dual_filter"` and `"true"` in `detail` |
| `test_publish_single_admin_key_tightening_201` | OK | prod project |
| `test_publish_head_m2_row_loosening_needs_two` | OK | prod project; only `lo_head` is non-empty |
| `test_publish_loosened_against_server_base_only_needs_two` | OK | prod project; only `lo` is non-empty |
| `test_publish_copies_only_counted_approvals` | OK | Checks the served set, the rows keyed to the bundle id, `signed_at` and the audit set. See N7 for what this row cannot see |
| `test_publish_registry_user_id_canonical_form` | OK | The route half is asserted after G2. Gate-off: today carol gets 403 `not_key_owner` (raw compare) |
| `test_publish_records_proposal_and_audit_row` | OK | |
| `test_publish_refusals_audited_not_found_forbidden_not_open` | OK | `count(*) == 1` per (proposal_id, reason) |
| `test_proposal_detail_base_approvals_are_served_set` | OK | Measured: `loosened` raises `AttributeError` on `clauses: "not_a_list"`. Optional: assert `"approvals_needed" in body` before `is None` |
| `test_proposal_reads_counting_cli_key_200` | OK | |
| `test_proposal_reads_non_counting_cli_key_404` | OK | |
| `test_proposal_reads_session_key_not_in_registry_404` | OK | roles `["approver"]`; detail is unconditional |
| `test_proposal_list_without_project_filters_to_readable` | OK | Gate-off now reaches the project assertion (no setup error) |
| `test_proposal_list_cursor_tie_break_on_id` | OK | |
| `test_direct_publish_rows_labelled_m2_unverified` | OK | passes today with `?project=` |
| `test_direct_publish_audited_under_flag` | OK | |

## T3. Property file

Spec-reference statistics, seeds 0-299:
- P1: 85 accepted (28%), 45 with an m2 head, 39 with a smaller copied set, 60 with a server base, 10 with need 1, 6 on R_single.
- P2: 105 accepted (35%), 21 with need 1 (single 2, forged 6, wrong_kind 3, non_counting_role 4).
- Every refusal class is refused with its own code.

Mutants against the three pure nodes:
- **Killed:** no head rule (P1, seed 7); no first-bundle rule (P1 and P2); head as base, no dual filter, no exclusions, copy-raw (non-vacuity).
- **Killed only once corrected:** need-always-2. My first version of this mutant was wrong. It raised `need` only, which feeds only the dual filter, and every R_dual key counts for dual, so it could not change a verdict. That is likely also why the re-audit recorded need-always-2 as surviving. Corrected to force the final count to 2, P2 kills it at seed 11: on a forged-class tightening the server refuses and the connector accepts.
- **Survives:** copy-kept. See N7.

On qa's claim that need-always-2 "survives on R_dual and is only killed by P1 via R_single": it is wrong. P1 asserts only on accepted candidates, so a mutant that only adds refusals cannot fail P1. P2 kills the real mutant. The re-audit row ("include tightenings so need-always-2 is killed") is met. The dual-filter-only variant is caught by `test_publish_single_admin_key_tightening_201`.

| node | verdict | one line |
|---|---|---|
| `test_property_server_row_applied_unchanged` | WEAK (N7) | Class coverage is now fine (server bases, m2 heads, R_single accepts). It does not assert the copied set's invariants, so copy-kept survives. Fix: N7 |
| `test_property_verdicts_equal_all_server_at_head` | OK | All-`server` histories. Kills the corrected need-always-2 |
| `test_property_generator_non_vacuous` | OK | Every threshold holds against the reference |
| `test_property_routes_sample` | WRONG | See below |

`test_property_routes_sample`, measured on today's server with gates off:
- All 14 `accept` candidates (alice and bob approve through the route, both 201) were refused at publish with 400 `publisher_in_approvals`. bob is the publisher for every class except `publisher_in_approvals`. Step 10 (T3, kept by spec 2.2) refuses a stored approver who is also the publisher.
- So `n_201 >= 1` fails on a correct build ("0 accepted (of 37)").
- Same cause: `wrong_hash` stores bob's row with `user_id` bob, so it gets `publisher_in_approvals` (2 of 2).
- `proposer_in_approvals` and `publisher_in_approvals` never reach (g). The excluded user's route approval is refused (400) first, so these classes end up as `publisher_in_approvals` and `approvals_insufficient`.
- Also:
  - the docstring claims "Honours each candidate's class (expected code per rule 1)", but no code is asserted;
  - `except PublishRefused: pass` around the pure call hides a route-201 / pure-refusal disagreement;
  - the m2-row applies swallow `BundleError`;
  - `if r_prop.status_code not in (200, 201): continue` remains;
  - each candidate gets a fresh project, so no route publish ever runs against a `server` base row.

Fix:
- Publisher dave for every class except `publisher_in_approvals`. dave never approves in the sample.
- `forged` stores the rogue row with `user_id` frank.
- `proposer_in_approvals`: carol proposes, alice approves through the route, and carol's key approval is owner-inserted with `user_id` frank; publish as dave.
- `publisher_in_approvals`: as above, but dave's key approval is owner-inserted with `user_id` frank; dave publishes.
- Assert every propose is 201, and every route approval meant to be stored is 201.
- After every publish, run `verify_publish` on the route-stored input. On 201: pure accepts and the key_ids are equal. On a refusal: `rp.json()["error"] == exc.code ==` the class's expected code. No `except PublishRefused`.
- Assert each m2 row applies.
- The candidates of one seed share one project, so later candidates publish on a `server` base.
- Fix the docstring.

## T4. Static file

| node | verdict | one line |
|---|---|---|
| `test_direct_publish_flag_check_is_first_statement` | OK | Passes on the synthetic spec 2.5 form. Fails under "await before the flag" and "if-return, then await, then the flag" |
| `test_no_await_inside_transaction_anywhere` | WEAK | Today it finds exactly `bundles.py:209->221` and `signer.py:409->423` (with 70, assign 3). On the synthetic fixed build: 0 violations. But form 2 scans only the rest of the assignment's own block, although the docstring says "plus every enclosing block". Measured: `try: conn = connect(url, autocommit=False)` / `except E: return` / `x = await request.json()` gives 0 violations, and so does the same shape under `if`. Fix: the window is the rest of the assignment's block plus the rest of each enclosing block up to the function body. It ends at `var.close()` at any of those levels, or in an enclosing `finally`. Add both snippets to the `[assign]` guard, each expecting 1 |
| `test_await_guard_flags_synthetic_violation[assign]` | OK | The real in-try shape gives 1. It still needs the two snippets above once the visitor is fixed |
| `test_publish_route_calls_shared_verifier` | OK | Passes on the synthetic build (`approve_proposal` is exempt, and nested defs are skipped). Fails under "publish calls `_verify_change_approvals`" |
| `test_publish_db_error_mapping` | OK | Passes on the synthetic build. Fails under "constraint name dropped" and "generic handler without rollback" |
| `test_server_label_insert_only_in_publish` | OK | Passes with `'server'` inline and with it as a parameter. Fails under a second server insert in `admin_create_bundle` |
| `test_cursor_naive_read_as_utc` | OK | Matches the edited 2.9. Add the overflow assertion (T1) |

The pure nodes (16 refusal codes, `sign_and_check`, counting roles) pass against the reference. The matrix ids are now explicit (`refuse-pilot-1` ... `build-pilot-unset`; 46 ids).

## T5. CLI file

Unchanged: 2 passed and 2 xfailed. Under `_safe_str = str`, both ESC nodes fail.

## T6. Cross-cutting

- **N1** closed. **N2** acceptable as recorded. **N3** closed (node 1 and the route sample compare `bytes(bundle_blob)`). **N5** closed for the P1 weights comment: the claims hold against the reference. The route-sample docstring is a new honesty defect (T3). **N6** closed.
- **N4** closed for the spec clause: `_counts` counts approvals keyed to a bundle id of the project. Its docstring also claims "is not a `policy_change_requests.id`", which the SQL does not check. Fix the docstring or add `NOT EXISTS (SELECT 1 FROM policy_change_requests r WHERE r.id = a.change_request_id)`.
- **N7 (new, MUST 1). The copied set's individual-verify and one-per-user filters are untested.**
  - A build that copies every approval surviving (g) passes every T4 node.
  - P1 and P2 cannot see it: the connector ignores extra approvals.
  - `test_publish_copies_only_counted_approvals` cannot see it: eve is dropped at (g), not (h).
  - The route sample compares the build with itself.
  - The effect: the signed audit row's `approver_user_ids` and the served set could name a registered user whose signature is over another hash.
  - Fix, in P1, for each accepted candidate:
    - every counted envelope passes `_verify_change_approvals(payload, [env], registry, is_loosening=False, is_first_bundle=False)`;
    - the counted `canon_user`s are distinct;
    - when `approvals_needed(...)[0] == 2`, every counted key passes `counts_for_dual`;
    - every counted envelope is one of the candidate's stored approvals.
  - In the generator, add a "second key" extra for `accept`: proposer u4, publisher u5, plus approvals by `sks[3]` and `u3_sk2`, so u3 has two keys.
  - Measured: copy-kept survives today. The existing `other_hash` (`sks[2]`) and `repeat` extras then kill it.
- **Environment.** C: reached 0 MB free during this audit (198 MB at the start). The likely cause is Docker Desktop's disk image on C: growing with the two testcontainers Postgres runs. Nothing on C: was deleted. No further pg runs were made after it was noticed.

## T7. Totals after the third audit

| File | OK | WEAK | WRONG | Total |
|---|---|---|---|---|
| `ee/tests/test_m3_t4_publish_verify.py` | 49 | 0 | 1 | 50 |
| `ee/tests/test_m3_t4_property.py` | 3 | 1 | 1 | 5 |
| `ee/tests/test_m3_t4_static.py` | 45 | 1 | 0 | 46 |
| `tests/security/test_m3_t4_cli.py` | 4 | 0 | 0 | 4 |
| **All** | **101** | **2** | **2** | **105** |

## T8. Verdict

**NOT READY TO COMMIT TESTS-FIRST.** Rows still to fix:
1. `test_publish_counts_for_dual_only_when_two_needed`: add `tmp_path` to the signature.
2. `test_property_routes_sample`: the T3 fix list.
3. `test_property_server_row_applied_unchanged`: the N7 assertions and the generator's second-key extra.
4. `test_no_await_inside_transaction_anywhere`: enclosing-block window, plus the two snippets in `[assign]`.
5. Spec edit 1 condition: overflow maps to `ValueError` (lead, 2.9), and qa adds one assertion to `test_cursor_naive_read_as_utc`.

After the fixes, rerun:
- CI mode, and `--runxfail` (every marked node raises `M3T4Pending`);
- ruff F821 clean;
- the property nodes against a spec reference, where copy-kept and the corrected need-always-2 are killed;
- the route sample with gates off on today's server, where the log must show `accept` candidates reaching `verification_pending`, not `publisher_in_approvals`.

# Final check, 18 Nov 2026

Reviewer: security-engineer (leader tier). Scope: the five rows the third audit left open, plus any regression the qa run 5 edits introduced in `ee/tests/test_m3_t4_publish_verify.py`, `test_m3_t4_property.py` and `test_m3_t4_static.py`. `tests/security/test_m3_t4_cli.py` was not touched and was not re-run. qa's claims were not used as evidence. Read-only: nothing in the repo was edited except this section. Scratch lived under `D:\t4tmp\sec4` (plus `--basetemp` dirs `D:\t4tmp\sec4_*`) and is removed. Each pg run's testcontainers Postgres was gone afterwards (`docker ps -a` empty). C: free went from 6.2 GB to 6.0 GB.

Method:
- **Spec-only reference.** A new scratch `agg_cp.sync.publish_verify`, written from spec 2.1 only, was injected through `sys.modules`. 12 mutants were run against P1, P2 and non-vacuity (`--runxfail`).
- **Gates off.** A scratch plugin made `require_m3` a no-op. It was run on the publish file (whole file, reference injected) and on the route sample.
- **Route sample, dry.** A scratch plugin logged every route approval and publish, with the caller's `seed`, `ci`, `cls` and m2-row count, on today's server.
- **Static visitor.** The test file's own `_scan_sources` was run on today's tree, on a synthetic fixed copy of `ee/src/agg_cp` (spec 2.5 and 2.7 shapes), on the file's snippets, and on 8 extra snippets.
- **Lint and scanners** on the three files: ruff, gitleaks `dir`, trivy `fs --scanners secret` (cache on D:), and Semgrep `p/python` + `p/secrets`.

## F1. Open rows

| row | verdict | one line |
|---|---|---|
| Spec 2.9 overflow wording | CONFIRMED | Names both overflow strings, `ValueError`, 400 `bad_cursor`, "never 500". It does not conflict with the frozen `9999-12-31T23:59:59+23:59` (converts to 9999-12-31T00:00:59Z) |
| `test_publish_counts_for_dual_only_when_two_needed` | OK | `tmp_path` is in the signature; ruff F821 is clean on all three files. Gates-off: it fails at `error == "approvals_insufficient"` (got `verification_pending`), not in setup |
| `test_cursor_naive_read_as_utc` | OK | Both overflow strings are under `pytest.raises(ValueError)`. Measured: `astimezone(timezone.utc)` raises `OverflowError` on both, and `OverflowError` is not a `ValueError` subclass, so the naive build fails the node |
| `test_no_await_inside_transaction_anywhere` | OK | Today: with 70, assign 3, exactly `bundles.py:209->221 (with)` and `signer.py:409->423 (assign)`. Synthetic fixed build: 0 violations, counts 70 and 3 |
| `test_await_guard_flags_synthetic_violation[assign]` | OK | Both enclosing-block snippets give 1. The other snippets: autocommit 0, early close on another variable 1, if-return close 1, assign-in-try 1 |
| `test_property_server_row_applied_unchanged` (N7) | WEAK | See F2. The four N7 assertions are present and kill copy-every-survivor, skip-verify and skip-dedupe. A one-per-`key_id` dedupe survives |
| `test_property_routes_sample` | WRONG | Setup is now right. On a correct build the 201 branch reads the wrong bundle and skips the connector history. See F3 |

## F2. Property file, P1/P2/non-vacuity against the reference

Correct reference, seeds 0-299: all three nodes pass.
- **P1.** 85 accepted: 45 with an m2 head, 60 with a server base, 35 with a smaller copied set, 6 on R_single. Extras among the accepted: forged 12, other-hash 13, repeat 9, u3-second-key 4. 215 refused, each class with its own code.
- **P2.** 105 accepted (89 on a server base), 195 refused, each class with its own code.

| mutant | result | first kill |
|---|---|---|
| copy every approval that survives (g) (no (h) filters) | KILLED | P1 seed 16 `single_admin_key`: counted key does not count for dual; also non-vacuity |
| copy every registry-resolved approval (decision on the correct set; copy the (g) survivors) | KILLED | P1 seed 19 `accept`: counted envelope 2 fails individual verify |
| copy every stored approval | KILLED | P1 seed 16; non-vacuity |
| skip per-approval verify (h)(1) | KILLED | P1 seed 19 `accept` (assertion a) |
| skip one-per-user (h)(3) | KILLED | P1 seed 42 `accept`: duplicate `canon_user` (repeat extra) |
| one per `key_id` instead of per user | **SURVIVES** | killed at P1 seed 46 once the fix below is applied |
| need always 2 (corrected) | KILLED | P2 seed 11 `forged` |
| head as base | KILLED | non-vacuity: `loosened_vs_server_base_only` 0 |
| no head rule | KILLED | P1 seed 7 `head_m2_loosening` |
| no first-bundle rule | KILLED | P1 seed 58; P2 seed 103 |
| no dual filter | KILLED | P1 seed 16 (assertion c); non-vacuity |
| no exclusions | KILLED | non-vacuity: `proposer_in_approvals` 0 |

The `u3_second_key` extra appends only `u3_sk2`, so no stored set ever holds two keys of one user, and assertion (b) only sees identical repeats. The third audit asked for "so u3 has two keys". That line named `sks[3]`; it should have said `sks[2]`, u3's first key, and the typo was mine.

**Fix (one line).** In the `u3_second_key` branch, append `_sign_approval(sks[2], stored_hash)` before `_sign_approval(pk["u3_sk2"], stored_hash)`. Proposer and publisher already come from indices 3-5. Measured with the fix (applied through the plugin): the correct reference still passes all three nodes, and the per-`key_id` mutant fails at seed 46.

Note, not blocking: 16 of 22 R_single `accept` draws are refused (need 2). The forced "tightening" sets `clauses: []` and `servers: []`, and dropping a base deny clause is a loosening. P1 asserts only on accepted candidates, so no node is wrong. The re-audit's construction (keep the base's clauses and servers) would make the label honest.

## F3. Route sample

**Dry run on today's server.**
- All 37 candidates over seeds 0-19 reached publish with 400 `verification_pending`, including all 11 `accept` candidates. No candidate was refused with `publisher_in_approvals`.
- All 47 route approvals returned 201.
- `_assert_nothing_written` held for every refusal.
- Gates off with the reference, the first failure is a T4 assertion: `seed=0 ci=0 class=forged: route error=verification_pending != pure code=approvals_insufficient`.

**Defects on a correct build** (from the code; the 201 branch cannot run before the build):
1. **Wrong bundle served.** `GET /sync/bundle` is always called with `after=0`. `get_bundle` serves the lowest `sequence > after` (`bundles.py` around line 157). So once a seed has an m2 row or an earlier 201, the served envelope is not the one just published.
   - Seed 16 (m2 row at 1, `accept` publishes 2): the node gets row 1, which has no approvals keyed to its id. `served [] != pure [alice, bob]` fails.
   - Seeds 7, 13 and 17 (two `accept` in one project): the second compares `bundle.json` of sequence 1 with the blob of sequence 2, which fails.
2. **No connector history.** The fresh layout applies only the m2 rows, never the server rows that earlier candidates of the same seed published. A bundle at `base_sequence = k` is refused (`base_sequence must be 0` or `!= current`).
3. **Accept refusals pass.** In the refusal branch, a refused `accept` candidate passes when the route and the pure verifier agree. They are the same code, so this check is circular. The class label is the only independent oracle, and on a correct build every `accept` (carol proposes, alice and bob approve through the route, dave publishes) is 201.
4. **Docstring.** "dave publishes every class except publisher_in_approvals" is false: dave publishes every candidate.

**Fix:**
- Read `pub_seq = rp.json()["sequence"]`. Call `GET /sync/bundle` with `after=pub_seq - 1`, and assert `served_env["payload"]["sequence"] == pub_seq`.
- Keep a per-seed `history` list in sequence order:
  - each m2 row, applied as today with alice and bob test approvals;
  - after each 201, the `(served_env, served_approvals)` for that sequence.
- On the fresh layout, apply every history item below `pub_seq` in order, asserting each applies. Then apply the new envelope and compare `bundle.json` with `bytes(blob_row[0])` as today.
- In the refusal branch, first `assert expected_code != 201, f"seed=... class=accept refused ({route_error})"`.
- Fix the docstring.
- Optional: assert propose and every stored route approval `== 201` (today `in (200, 201)`).

## F4. Regressions elsewhere in the three files

- Counts: 50 / 5 / 46 collected. Static CI mode: 8 passed, 38 xfailed. Property CI mode: 5 xfailed.
- Publish file, gates off with the reference, `--runxfail`: 44 failed, 6 passed, 0 errors (same as the third audit).
  - Every failure is an `assert` or `AssertionError`, except the two G3 schema nodes (`DID NOT RAISE CheckViolation`, `DID NOT RAISE InsufficientPrivilege`), which are their T4 assertions.
  - No `NameError`, `TypeError` or psycopg error.
- Static file with the reference, `--runxfail`: 26 passed (8 guards, 16 refusal codes, `sign_and_check`, counting roles). 20 failed, all server-side T4 features absent today.
- ruff `F,B`: no F821, F822 or F823. 44 cosmetic findings (29 F401, 6 F841, 4 B007, 2 F541, 1 B904, 1 B905, and 1 F811, which is the intended `t4_server` fixture import).
- gitleaks: no leaks. trivy secret: no findings. Semgrep `p/python` + `p/secrets`: 0 results, 0 errors, 3 files scanned.

**SHOULD, not blocking (await visitor).** Measured on extra snippets:
- **False positives (strict, harmless):** a close in the *enclosing* `finally` followed by an await after that `try` is flagged, with a plain or `if conn is not None:` close. The code checks only the `finalbody` of later `Try` statements. The synthetic fixed build does not hit this.
- **False negatives:**
  - an `await` in the enclosing `try`'s `except` handler or `finally` before the close gives 0;
  - an assignment inside `async for` gives 0, because `_compound_bodies` lacks `AsyncFor` (and `TryStar`).
- **Fix:** when the window climbs out of an enclosing `Try` whose body holds the assignment, add that `Try`'s handler bodies, `orelse` and `finalbody` (up to the close) to the window, and treat a close in that `finalbody` as the end. Add `ast.AsyncFor` and `ast.TryStar` to `_compound_bodies`. Add the three snippets to `[assign]`. Worth folding into the run that fixes F3.

## F5. Totals after the final check

| File | OK | WEAK | WRONG | Total |
|---|---|---|---|---|
| `ee/tests/test_m3_t4_publish_verify.py` | 50 | 0 | 0 | 50 |
| `ee/tests/test_m3_t4_property.py` | 3 | 1 | 1 | 5 |
| `ee/tests/test_m3_t4_static.py` | 46 | 0 | 0 | 46 |
| `tests/security/test_m3_t4_cli.py` (unchanged, third audit) | 4 | 0 | 0 | 4 |
| **All** | **103** | **1** | **1** | **105** |

## F6. Verdict

**NOT READY TO COMMIT TESTS-FIRST.** Rows still to fix:
1. `test_property_routes_sample` (WRONG): the F3 fix list (served sequence, connector history, accept must be 201, docstring).
2. `test_property_server_row_applied_unchanged` (WEAK): the F2 one-line fix (`sks[2]` beside `u3_sk2`).

After the fixes, rerun:
- CI mode, and `--runxfail` (every marked node raises `M3T4Pending`);
- P1, P2 and non-vacuity against a spec reference, where the per-`key_id` dedupe mutant is killed;
- the route sample dry and gates-off on today's server: every candidate reaches `verification_pending`, and the first gates-off failure is a T4 assertion.

The 201 branch can only be exercised by the build. The build's security (L) review must run the route sample and confirm it passes with the served sequence equal to `pub_seq` on seeds 7, 13, 16 and 17.
