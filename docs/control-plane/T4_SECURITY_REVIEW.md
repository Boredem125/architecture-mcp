# Design review, 18 Nov 2026

Reviewer: security-engineer (leader tier). Scope: `docs/control-plane/T4_SPEC.md` (lead, uncommitted) at HEAD `3f4a396`, before any T4 test or code. Read: the spec; `M3_PLAN.md` D2, T4 row, frozen list, server TCB, threats 38-53, rulings S1, S2, T0b-*; ADR 0001 A9 and its 16 Nov addendum; my `T3_SECURITY_REVIEW.md` (sections 1-4, R3-3, R3-4, R3-8, R4-2, R4-4, R4-7); HANDOFF session 21; the code the spec touches (`ee/src/agg_cp/sync/proposals.py`, `sync/bundles.py`, `rbac.py`, `app.py`, `auth.py` `validate_session`, `sync/signer.py`, migrations 0007, 0017, 0018, `src/sandbox/connector/sync/bundles.py`, `sync/process.py` `_bundle_signer_pub` and the bundle apply path, `src/sandbox/protocol/registry.py`, `src/sandbox/cli/change_cmds.py`, `ee/deploy/` compose and Dockerfile); the two `M3T4Pending` nodes in `ee/tests/test_m3_t3_proposals.py`; `ee/tests/m2_sync_server.py`, `ee/tests/conftest.py`, `ee/tests/test_m3_t5_pilot.py` (flag and override nodes). Nothing was edited except this file. No server, container or database was started. One read-only AST scan ran from `E:\caterpillar\jev-os\.cache\tmp\t4_d1\scan_await.py` over the repo `ee/src/agg_cp`.

**Verdict: CONFIRMED WITH CHANGES.** The design weakens none of the five guarded properties. The server only refuses more, the connector TCB is untouched, and the default for direct publish becomes 410. The changes are mostly test-plan precision: four listed nodes do not test what they claim, and several mutants survive the plan as written (section 5). Three are design points: what the copied approval set is (SQ-7), registry-rebuild errors must never 500, and the no-await guard misses a second live site in `sync/signer.py`.

## 1. Measured

| What | Result |
|---|---|
| AST scan, every `with`/`async with` whose context call is `_conn`, `_app_conn`, `connect`, `connection`, `transaction` or `begin`, `ee/src/agg_cp` minus `migrations/` | 70 transaction blocks; one `await` inside: `sync/bundles.py:221` (matches spec 2.7) |
| Same scan, async functions that open a connection by plain assignment and `await` later | `sync/signer.py::create_link_code_route`: `conn = psycopg.connect(url, autocommit=False)` at :409; `validate_session` runs `UPDATE web_sessions SET last_seen_at` (`auth.py:190`) and does not commit; then `body = await request.json()` at :423. **That is the R3-4 class (an await while the session row lock is held), and spec 2.7's `with`-only guard cannot see it.** `signatures_route` (:718/:724) and `genesis_route` (:1110/:1128) are not violations: their connection is autocommit and closed before the await. Read from code; not run against a server. |
| Migration 0017 | Adds `verification text NOT NULL DEFAULT 'm2_unverified'`, `verified_at timestamptz`, `chk_verification_value` and `chk_verified_at_coupling`. Revision `000000000011`. |
| Grants (0007) | `agg_app` has SELECT, INSERT only on `policy_bundles` and `policy_change_approvals`, and full CRUD on `policy_change_requests`. No code or test in the repo UPDATEs or DELETEs any of the three (grep). |
| `Registry` | `_keys` is the latest version's key map plus the synthesised bundle signer, so a key removed in a later version is gone. `counts_for_dual` is true only when the version that added the key had at least 2 admin signers. Registry `user_id` is any non-empty string (not checked as a UUID). |

## 2. The lead's four findings

1. **Migration 0017 already added the labels: AGREE.** Section 1 shows it. T4 keeps the DEFAULT, so publish must name `verification = 'server'` and `verified_at` explicitly, and the coupling CHECK enforces the pair. 0019 adds only the three objects in spec 2.3.
2. **The two `M3T4Pending` nodes need FR-4: AGREE.** I re-traced both nodes against a correct T4. Carol proposes. Carol's co-approval is refused `proposer_cannot_approve` (A9 item 7; the T3 route already does this), so A and C each hold bob's approval only. Publish A or C at base 0 is a first bundle, needs 2, and is refused `approvals_insufficient`. In the approval node, `assert r_pub_a.status_code in (200, 201)` fails. In the publish node, C never publishes, so D is not stale, and D's refusal cites `approvals_insufficient`, not `stale`. **This is my error:** my T3 section 4 ruling (carried into founder row F-1, 16 Nov) said "plus carol co-approving A and C", which A9 item 7 forbids. FR-4 is the minimal correction. Alice co-approves (not the proposer, and not the publisher once carol publishes). Carol publishes, which A9 8(g) allows for the proposer. The co-approval is asserted 201 (my R5 SHOULD), and every existing assertion is kept. Carol is an org admin with a fresh session, so step 6 and the fresh rule pass. Apply "carol publishes" to every publish in both nodes.
3. **The 410 breaks the five frozen M2 modules, and FR-5 is the right fix: AGREE, with conditions (MUST 13).** All five POST to `/admin/bundles` and expect M2 behaviour. Four spawn servers through `make_sync_server`, which copies `os.environ` at `Popen` time, and `test_m2_t9_bundles.py` builds `create_app` in-process. A module-scoped autouse fixture runs before the module's other module-scoped fixtures, so it reaches both forms. Every alternative is broader. Putting the env in `m2_sync_server.py` would arm the flag for every module (T4's own servers drop it, but T1/T3 servers would then hide a 410 regression). Putting it in CI env is global. Five per-file edits would touch five sealed files instead of one. FR-5 does not cover a node that fails *under* the flag because of the new admin check, the capped strict body read or the explicit label. Those are separate changes (founder question FQ-1).
4. **Naive cursor read as UTC instead of 400: AGREE (SQ-4).** R4-2's risk was that the result depended on the database `TimeZone`. Reading the cursor as UTC in Python, before the bind, removes that dependence. Cursors affect paging only, never authorisation. The frozen R4-Q1 node requires 200. No founder row is needed.

**Session-21 `_deny_all_base()` change (`proposals.py:47-55`): fine.** It is behaviour-preserving: a fresh dict per call, and the literal is equal key-for-key to the connector's step-10 literal (`bundles.py:545-550`). Both call sites (:424, :426) only read it (`base_hash`, `loosened`, diff). Spec item 1 moves it to `publish_verify.deny_all_base()` under the `ast` pin, which supersedes it.

## 3. Rulings on SQ-1 to SQ-10

| # | Ruling | Conditions or reason |
|---|---|---|
| SQ-1 flag semantics | **ACCEPT with conditions** | The check runs first in `create_app`, before `if settings.db_url` and before any router. Both literal names stay in `app.py`. `app.py` joins the server TCB (lead's recommendation accepted), because a TCB route now imports `_direct_publish_enabled` from it. The in-process matrix does not prove that the process exits, so MUST 10 adds one subprocess node in the image's ENTRYPOINT form. |
| SQ-2 `compose.override.yml` | **ACCEPT with conditions** | The override sets exactly `services.api.environment` `{AGG_DEPLOY_PROFILE: demo, AGG_ALLOW_DIRECT_PUBLISH: "1"}` and nothing else, pinned by a guard (SHOULD 12). Residual risk: a pilot VM operator who runs bare `docker compose` in `ee/deploy`, or who adds the override after a pilot file, gets the flag (later file wins). If the pilot file comes last, the api refuses to start, which is fail-closed. Carried to T5 as MUSTs (SHOULD 11 here): `pilot.sh` refuses when `COMPOSE_FILE` is set, and `doctor` fails unless the running api shows `AGG_DEPLOY_PROFILE=pilot` and no flag. Today `test_merged_args_exclude_compose_override` passes on the word "exclude" alone, and T5 must harden it. `PILOT.md`: never run bare `docker compose` in `ee/deploy` on a pilot VM. |
| SQ-3 R4-4 for key holders | **ACCEPT with conditions** | The verified registry decides: kind `cli`, a role in `COUNTING_ROLES`, `user_id` equal to the caller. The projection (`approver_keys`, live row) may only narrow, as ADR 0010 s8 requires. Role only, not `counts_for_dual`: a single-admin key may still sign a tightening, so it must be able to read it. Key holders read every project in the org, because the registry is org-wide and they may approve any project. The list filter is in the SQL `WHERE` before `LIMIT`, never a post-filter (a post-filter gives short pages and a cursor past unreadable rows). The detail 404 body is byte-equal to the missing-id 404. MUST 11. |
| SQ-4 naive cursor | **ACCEPT** | One `_parse_cursor` does the parsing, the bound value is an aware `datetime`, and the `|<id>` part must be a canonical UUID or 400 `bad_cursor`. No founder row. |
| SQ-5 missing signer key | **ACCEPT** | A missing key is server misconfiguration, not a client error, and the M2 node already pins 500 `bundle_signer_key_not_configured`. Rollback first, refusal audited, nothing written, and the detail never names the key path. A key file whose public key is not the registry's bundle signer is 400 `signer_not_in_registry` (step j), also with nothing written. |
| SQ-6 order and locks | **ACCEPT with conditions** | Every branch refuses, so the swap changes only which reason is reported. The project `FOR UPDATE` must return a row; None gives 404 `not_found`, audited, and the route never proceeds unlocked. The stale check stays after the project lock: under READ COMMITTED the next statement sees the winner's commit. The lock order is always proposal then project; approvals lock only the proposal, so there is no cycle. `UniqueViolation` maps to `stale_base` only for the `policy_bundles (project_id, sequence)` constraint (`diag.constraint_name`). Any other DB error: rollback, audit `internal_error`, 500. MUST 14. |
| SQ-7 copied set | **ACCEPT with condition (MUST 1)** | Today's `counted` would still hold forged or other-hash approvals, because (g) checks the registry entry only and `_verify_change_approvals` skips bad signatures without saying which. A connector would ignore them, but the served set, the audit row and the T7 pack would then name approvals that do not verify. So: copied = individually verified, one per registry user, dual-filtered when need is 2. |
| SQ-8 head parse, no re-verify | **ACCEPT with condition** | Re-verifying a stored `server` row's signature would refuse every valid row after a bundle-signer rotation. An attacker who can rewrite `policy_bundles` needs the owner role (the app role is INSERT-only) and could write a `server` label directly anyway. Condition: the server base and the head each parse to an envelope with a dict `payload` whose `sequence`, `org_id` and `project_id` equal the row's; otherwise 400 `base_invalid`. |
| SQ-9 property scope | **ACCEPT with conditions (MUST 12)** | Seeded `random` with the seed in every message is fine, and so are 300 seeds per property and the 20-seed route sample. P2's domain restriction is exactly A9's "deliberately stricter" set. As written, the non-vacuity check can be satisfied without the server refusing for the stated reason, and two server-stricter classes are missing. |
| SQ-10 direct route under flag | **ACCEPT** | Demo profile only, label `m2_unverified`, nothing on a laptop reads the label, and the connector verifies every row itself. SHOULD 4 adds the project lock, strict parse, a canonical project id and an audit row. |

## 4. The design against the guarded properties and threats

**STRIDE, T4 elements** (D = DFD element):

| D | Threat | Mitigation in spec | Gap (fix) |
|---|---|---|---|
| Publish route (process) | S: stolen CLI key publishes (S-1 consequence) | Dual control unchanged: proposer and publisher excluded through registry entries | None new; `PILOT.md` line (T14, carried) |
| | T: payload altered between approval and publish | Hash recomputed from stored bytes; the approvals sign the hash | Tamper-only checks have no node (MUST 7) |
| | R: publish or refusal not recorded | `bundle_proposal.publish` and `publish_refused` in chained `admin_audit` | Audit names the counted approvers (MUST 1) |
| | I: refusal detail leaks | `detail` at most 200 chars; connector reasons hold key ids only | None |
| | D: per-project lock held; refusal-row flood | `lock_timeout 10s`; fresh-session or CLI token required before refusal rows | Accepted (in-org, authenticated) |
| | E: non-admin publishes | `is_project_admin` at step 6 | One helper (item 11) |
| `publish_verify` (process) | T: verdict drifts from connector | Import-only, AST pins, property test | MUST 2, 7, 12 |
| `policy_bundles`, `policy_change_approvals` (store) | T: label or approvals changed after insert | App role SELECT, INSERT only; label CHECKs | SHOULD 3 static guard |
| `policy_change_requests` (store) | T: published row re-opened or deleted | `chk_published_link` (0019) | SHOULD 2 (revoke DELETE, trigger on published) |
| Direct route (process) | E: flag on in a pilot | 410 default; start-up refusal; per-request recheck | MUST 10; T5 carries (SQ-2) |
| Proposal reads (process) | I: viewer reads other projects' policy (R4-4, threat 38 inside an org) | `_can_read` | MUST 11 |

**Properties.**
1. *Fail-closed local enforcement:* holds. The connector diff is empty, checked three ways (spec section 4). `verify_and_apply` never runs or is named on the server. The 410 is the default.
2. *Models only add scrutiny:* no model in T4.
3. *Every privileged decision signed and chained:* holds for publish (bundle-signer signature, Ed25519 approvals, chained audit). Direct publish under the demo flag writes no audit row (M2 behaviour). SHOULD 4, or a named demo-only limit.
4. *Dual control means two different humans:* holds with MUST 1 and MUST 3. The `counts_for_dual` filter is from the first commit (T0b-7), and exclusions resolve through the registry entry. Residual (SHOULD 1): registry `user_id` is a free string, so a non-canonical form of the proposer's UUID would slip the string compare. Reaching that needs an admin quorum to sign such an entry.
5. *Hand edits cannot loosen policy:* holds with MUST 2. The base is the last `server` row, `m2_unverified` rows only add need (A9 item 3 security clause), and the labels cannot change after insert.

**Specific checks the brief asked for.**
- *Import-only verification:* the design is right. The name list in 2.1 equals A9 item 1 plus the 5 Nov addition. Add the `ast.Import` form (`import sandbox.connector.sync.bundles as b`) to the alias guard (SHOULD 15).
- *Registry only from the server's own chain:* right. `_verified_registry` must turn every exception in genesis parse, `get_chain` parse or `verify_chain` into the refusal, never a 500. Today `_genesis_fingerprint` (`proposals.py:169-183`) runs outside the `try` (MUST 6).
- *Base selection and stale-base refusal at approve and publish:* right in design. The plan has no node that kills "the m2 head used as the loosening base" (MUST 2).
- *Two-approval counting on `counts_for_dual` keys only:* right. `test_publish_counts_for_dual_only_when_two_needed` and the single-admin tightening node kill both directions of the filter mutant.
- *S2 operator refusal:* unchanged (`escalations.py:998-1012`), and `escalations.py` reads no `policy_bundles` today. T4 is the first task that creates `server` rows, so pin it now (MUST 9).
- *Nothing written on refusal:* right (rollback first, then the audit in its own transaction). Add "no `bundle_proposal.publish` row" to the definition in spec section 3 (SHOULD 17).
- *410 before any DB work or await:* right. The route has no body parameter, and the CSRF dependency does no DB work. Both the in-process unreachable-DB node and the AST first-statement node bite.
- *AST no-await guard over all of `ee/src/agg_cp`:* not complete as specified (MUST 8).
- *R4-4 read scoping:* right with MUST 11.
- *Start-up refusal under the pilot profile:* right in `create_app`. Proven only in-process (MUST 10).
- *Does the property test exercise the exit claim:* mostly. P1 runs the route's own `verify_publish` and `sign_and_check`, and a real `verify_and_apply` on a layout that applied every earlier row, with the server's copied approvals and a bytes-equality check. That is the claim. The gaps are in MUST 12. Spec 2.2 steps 12, 13 and 16 (base SQL, stored-approval parse, the copy) run only in the 20-seed route sample and the named nodes, which is why MUST 1 and MUST 2 are route nodes.

**Threats.** 41 is covered with MUSTs 1-7 and 12. 43 is covered with MUST 10, and T5 carries the compose side. 38 (in-org reads): MUST 11. 40: the detail's `approvals_needed` is labelled the server's word (spec 2.4); the page is never a trust anchor. 48: the CSRF dependency still runs before the 410 and on publish. 42 (T7) and 44/50 (T10) depend on T4's copied set and the label meaning (SHOULD 13, 14). Rows 39, 45-47, 49, 51-53 are not touched by T4.

## 5. Test plan: do the nodes fail today for the stated reason, and what would a mutant get past?

**Nodes that do not test what they claim (fixed by MUSTs).**
- `test_publish_wrong_registry_approval_refused`, as written ("bob approves, registry v2 drops bob's key, publish"), ends in `registry_version_stale`, not `approvals_insufficient`. The proposal was made at v1, and check (d) runs before (h). It duplicates `test_publish_registry_version_stale_refused` and never reaches the wrong-registry branch (MUST 3).
- `test_publish_proposer_resolved_from_registry_refused` and `..._publisher_...`: if the owner-inserted row's stored `user_id` is the publisher or the proposer, today's T3 step-10 check returns a refusal other than `verification_pending`. `require_m3` then passes, and the node fails with an `AssertionError`, which `raises=M3T4Pending` does not catch (MUST 4).
- `test_publish_refusals_audited_not_found_forbidden_not_open`, `test_published_request_requires_bundle_link`, `test_propose_base_row_missing_refused`, the R4-4 read nodes, the cursor, 410 and `expires_at` nodes: the spec names a sentinel only for publish and for pure or static nodes. Without a named gate these fail today with `AssertionError` (MUST 5).
- `test_publish_registry_invalid_refused_and_audited`: if the tamper comes before the proposal, item 5 refuses at propose, and the approvals refuse `no_registry` (MUST 6).

The other listed nodes fail today for the stated reason (publish returns `verification_pending`; the reads return 200; page 2 of the cursor walk is empty; the matrix has no check; the helper has four definitions and five fragments; `publish_verify` is missing). The guards pass today and bite on the named mutants (braced or uppercase id, which Postgres accepts as a uuid, giving 201; urn id, giving 500).

**Mutants the plan as written lets through:**

| Mutant | Survives because | Killed by |
|---|---|---|
| Loosening base = head row of any label (m2 trusted as base) | `head_m2_row_loosening_needs_two` tests the other direction; `first_server_row_after_m2` still needs 2 through `is_first`; P1 and P2 agree with a connector | MUST 2 |
| Copy every stored approval instead of the counted set | Every 201 node stores exactly the counted approvals | MUST 1 |
| Projection instead of registry for approval identity | The wrong-registry node never reaches (h) | MUST 3 |
| Delete any of (e)/(d): hash, size, fields, binding, `sequence == base+1`, `not_before`, `expires_at`, `registry_version` type | Reachable through the routes only by DB tamper | MUST 7 |
| Registry rebuild raises outside the refusal path (500) | No invalid-JSON tamper node | MUST 6 |
| Await under a bare non-autocommit connection | Guard sees `with` only | MUST 8 |
| Escalation approval honours a `server` row's `allow_requester` | No T4 node | MUST 9 |
| Start-up check inside lifespan or a route, process keeps serving | Matrix is in-process | MUST 10 |
| R4-4 session path trusts the projection | `frank` is in both | MUST 11 |
| Non-vacuity met while the server refuses for another reason | Classes counted, not tied to code | MUST 12 |

## 6. MUST (lead folds into the spec before qa starts)

1. **SQ-7 copied set.** After (g), keep only approvals that each pass `_verify_change_approvals(payload, [a], registry, is_loosening=False, is_first_bundle=False)`, one per registry user (lowest `key_id` first). When need is 2, apply the `counts_for_dual` filter. Run the whole-set check on that list and copy exactly it, with `signed_at` taken from the stored row. `approver_user_ids` in the audit row is that list's users. New node `test_publish_copies_only_counted_approvals`: 201 with two valid approvals plus one stored valid signature whose key is not in the current registry (proposal made under that version, row owner-inserted). The served `change_approvals` and the rows keyed to the bundle id equal the two.
2. **Base-rule node** `test_publish_loosened_against_server_base_only_needs_two`: `server` row 1 strict; owner-inserted `m2_unverified` row 2 permissive (signed by the bundle signer, two valid approvals); a proposal at base 2 whose sections equal row 2's (empty against row 2, non-empty against row 1). One approval gives 400 `approvals_insufficient` with nothing written; two give 201.
3. **Rewrite `test_publish_wrong_registry_approval_refused`.** Registry v2 (two admin signatures) drops bob's key. Carol proposes under v2, alice approves through the route, and bob's valid signature over the hash is owner-inserted with `user_id` bob. Bob's `approver_keys` row stays live (`revoked_at IS NULL`), so a projection-reading mutant gets 201. Publish gives 400 `approvals_insufficient`, nothing written.
4. In the two registry-resolution nodes, the owner-inserted row's stored `user_id` is a third user (dave) who is neither proposer nor publisher.
5. Name the gate for every node that fails today. Non-publish route nodes open with `require_m3(4, importlib.util.find_spec("agg_cp.sync.publish_verify") is not None, ...)`. The 0019 node uses `chk_published_link` present in `pg_constraint`. The refusal-audit node gates before its first audit assertion. Guards carry no gate.
6. `_verified_registry` turns every exception in genesis parse, `get_chain` parse and `verify_chain` into the refusal (`registry_invalid` at publish and propose, frozen `no_registry` at approval, "not readable" in reads), never 500. The registry-invalid node runs propose, approve twice, tamper, publish, and gets a second variant whose tamper leaves invalid JSON.
7. A pure node `test_verify_publish_refusal_codes[...]` (no pg) with one case per code: `bad_payload` (duplicate key, NaN), `hash_mismatch`, `too_large`, `unknown_fields`, `change_approvals` present, `binding_mismatch` (org, project, base, `sequence != base+1`), `registry_version_stale` (str, bool, lower), `not_yet_valid`, `expired`, `invalid_bundle` (`loosened` raises). Plus `sign_and_check` with a signing key that is not the registry's bundle signer, giving `signer_not_in_registry`.
8. AST guard (2.7) also flags an `await` in an async function after a non-autocommit connection opened by assignment and before its close. Fix `sync/signer.py::create_link_code_route` in T4 by reading the body before `psycopg.connect` (:409/:423). `sync/signer.py` goes on the T4 touch list (security L). The node's minimum count covers both forms.
9. S2 guard `test_operator_refusal_ignores_server_rows` (static): `sync/escalations.py` and `web/escalations.py` hold no SQL naming `policy_bundles` and read no `allow_requester`. It passes today.
10. `test_uvicorn_factory_exits_with_flag_under_pilot` (static file, subprocess, no pg): `python -m uvicorn agg_cp.app:create_app --factory` with `AGG_DEPLOY_PROFILE=pilot`, `AGG_ALLOW_DIRECT_PUBLISH=1` exits non-zero within 15 s, and nothing answers on its port. The test stops any process it started. `app.py` joins the server TCB list in `M3_PLAN.md:133`.
11. R4-4 as SQ-3: registry decides, projection only narrows, SQL filter before `LIMIT`, byte-equal 404. New node `test_proposal_reads_session_key_not_in_registry_404`: a session caller with a live `cli` projection row whose key is absent from the verified registry gets 404 on list and detail.
12. Property test. (a) Every candidate carries a generator class label. Non-vacuity asserts, per refusal class, at least one candidate refused with that class's expected code. Add the classes "loosened against server base only" and "first server row after m2 rows". P1 also requires at least 30 accepted candidates with an `m2_unverified` head, and at least 10 accepted with a copied set smaller than the stored set. (b) For P2 refusals, the reference connector gets an envelope signed by the test with the bundle-signer key over the same payload, plus the full stored approval list. (c) The reference connector reaches each state only through `verify_and_apply`, and its registry comes from its own `verify_chain` over the serialised chain. (d) User ids are UUID strings, and no payload sets `expires_at` (outside P2's domain).
13. FR-5 measured before the founder signs, on a full scratch tree with the T4 build: (i) with the flag absent, the 410 failures by node id; (ii) with the fixture, the five modules green. Any node still failing (admin check, capped strict read, label) is listed separately and is not covered by FR-5. The fixture matches an exact basename frozenset, restores absent versus value exactly, and is autouse with module scope.
14. Publish locks as SQ-6: the project lock must return a row; `UniqueViolation` maps to `stale_base` only for the `(project_id, sequence)` constraint; any other DB error is a rollback, an audited refusal and 500.

## 7. SHOULD

1. Exclusion and dedupe compare user ids in canonical form (`str(uuid.UUID(x))` when it parses) on both sides, at approval and at publish. Add a node with an uppercase registry `user_id`.
2. 0019 revokes DELETE on `policy_change_requests` from `agg_app` and adds a trigger refusing UPDATE of a `published` row. Nothing deletes or re-opens rows today.
3. A static guard: the only `INSERT INTO policy_bundles` naming `'server'` is in `publish_proposal`, and no `UPDATE` or `DELETE` of `policy_bundles` exists in `ee/src`.
4. Direct route under the flag: take the same `projects ... FOR UPDATE` lock, use `_strict_json_parse`, give 400 for a non-canonical `project_id`, and write an `admin_audit` `bundle.direct_publish` row if the frozen M2 nodes stay green (otherwise a named demo-only limit).
5. One shared capped body reader; `sync/bundles.py` imports it rather than holding a copy.
6. Detail: `base.change_approvals` from the rows keyed to the base bundle id (the served set); `approvals_needed: null` if `loosened` raises.
7. Tamper-only route nodes: `base_invalid` (unparseable head blob) and `not_yet_valid` (owner-inserted proposal).
8. The 20-seed route sample includes owner-inserted `m2_unverified` rows (p = 0.3) and asserts the served approvals equal the pure verifier's copied set for the same input.
9. An env var (for example `AGG_T4_PROPERTY_SEEDS`) for extra local seeds, never set in CI.
10. `PILOT.md`: any registry version change makes every open proposal `registry_version_stale` (re-propose, re-approve).
11. T5 carry (MUST there): `pilot.sh` refuses when `COMPOSE_FILE` is set or the override would load; `doctor` asserts the running api's profile is `pilot` with no flag; harden `test_merged_args_exclude_compose_override`.
12. A guard pinning `compose.override.yml` content to exactly the two `api` env keys.
13. T10 carry: the `pilot.sh upgrade` row check reuses `publish_verify` and the connector functions, with no third copy.
14. T7 carry: the pack names the copied (counted) set and states what the `server` label means.
15. The import guard also refuses `ast.Import` of the two connector modules.
16. The "nothing written" definition adds "no `bundle_proposal.publish` row".

## 8. Founder questions beyond FR-4 and FR-5

- **FQ-1:** If qa's run (MUST 13 ii) shows a frozen M2 node failing under the flag only because of the S-3 admin check or the capped strict read, does the check stay and that node get its own founder row, rather than T4 dropping the check? **Recommend yes.**

FR-4: recommend yes (section 2 item 2). FR-5: recommend yes, with MUST 13.

# Design review addendum, 18 Nov 2026

Scope: the revised `docs/control-plane/T4_SPEC.md` (385 lines), founder rows FR-4, FR-5 and FQ-1 (all yes, `M3_BASELINE.md` rows 82-84), and the lead's four open choices. Nothing was run except reads. I checked how registry `user_id` is formed in `sync/registry_identity.py` and checked the seal file `M3_T0A_MANIFEST.sha256`.

**Verdict: CHANGES (three one-line spec edits, A1-A3 below). Once they are in, the spec is READY FOR TESTS. No further security round is needed; the orchestrator checks the three edits against this text.**

## A. MUSTs 1-14 in the revised spec

| MUST | Carried | Note |
|---|---|---|
| 1 copied set | Yes (2.1 (h), 2.2 step 16, node) | Order changed (choice 1, accepted below) |
| 2 base-rule node | Yes | |
| 3 wrong-registry rewrite | Yes (own org, live projection row) | |
| 4 third-user `user_id` | Yes (dave) | |
| 5 gates | Yes, with one gap | A1 |
| 6 registry rebuild never 500 | Yes (`_genesis_fingerprint` inside the `try`; two tamper variants) | |
| 7 pure refusal codes | Yes (16 cases plus `sign_and_check`) | |
| 8 await guard, signer fix | Yes (both forms; the autocommit exemption is correct for `signatures_route` and `genesis_route`) | A2 (fix mechanics) |
| 9 S2 guard | Yes | |
| 10 subprocess exit, `app.py` TCB | Yes (G2 before the process starts; reaped in `finally`) | |
| 11 R4-4 | Yes (projection narrows; page-1-full node proves filter before `LIMIT`) | |
| 12 property rules | Yes (rules 1-5, thresholds 30 and 10, classes tied to codes) | |
| 13 FR-5 measured first | Yes (3.5 steps 1-5; fixture in the build commit) | |
| 14 locks, DB errors | Yes (project lock with `org_id`, constraint-name mapping, `internal_error` 500) | Choice 4, plus SHOULD A-S1 |

The SHOULD dispositions in 4.5 are accepted, including the carries to T5, T7 and T10.

## B. The lead's four open choices

1. **MUST 1 order, `counts_for_dual` filter before one-per-user: ACCEPT.** With dedupe first, a user whose lowest `key_id` is non-counting would lose their counting key, and the server would understate a real second human. That fails closed, but it is wrong. Filtering first keeps every survivor individually verified and counting, so the server is never laxer than the connector's rule. Dedupe still runs after step (1), so a forged lower key cannot displace a valid one.
2. **SHOULD 1, a registry `user_id` that does not parse as a UUID is dropped at (g): ACCEPT.** The server only refuses more. Server-built registries always carry the DB user UUID: `registry_identity.py:114-126` requires `entry["user_id"]` to equal the linked key's `user_id::text`, and the IdP `sub` lives in its own `sub` field. So an Entra pilot is unaffected. The property domain already uses UUID strings. A dropped entry also cannot trigger an exclusion, which is harmless because it cannot count either.
3. **MUST 8, `create_link_code_route` reads its body through the shared capped reader before `psycopg.connect`, before auth: ACCEPT with condition A2.** A capped read before auth is the same pattern T3 uses on every proposal route, and it bounds an unauthenticated caller at 1 MiB + 64 KiB. Keeping `{}` on parse failure preserves today's behaviour.
4. **MUST 14, constraint name `policy_bundles_project_id_sequence_key`: ACCEPT.** That is Postgres's default `<table>_<columns>_key` name for the unnamed `UNIQUE (project_id, sequence)` in 0007 (37 characters, no truncation), and qa reads and pins the real name from `pg_constraint`. With the project lock held, two route publishes never reach this branch: the loser is refused at step 9. It is reachable only by a demo-flag direct publish racing the route. A wrong name gives a 500 with nothing written, which fails closed. Hence SHOULD A-S1, not a MUST.

## C. Addendum MUSTs

- **A1 (MUST 5 gap).** `test_publish_refusals_audited_not_found_forbidden_not_open` says its response assertions pass today and G2 comes before the first audit assertion. The 409 `not_open` case needs a published proposal. If that proposal comes from a T4 publish, today that publish returns 400 `verification_pending`, and the node fails with an `AssertionError` before G2. Spec text: the published proposal is owner-inserted (status `published` with `published_bundle_id`, `published_by`, `published_at` set and a linked bundle row inserted by the owner), or G1 is applied to the publish that creates it. One of the two, stated in the row.
- **A2 (MUST 8 fix mechanics).** After `_read_body_capped` has consumed `request.stream()`, a later `await request.json()` raises "stream consumed". The route's existing `except Exception: body = {}` would swallow that, and every browser-key link request (`body.get("kind") == "browser"`) would silently take the non-browser path. Spec text: parse the captured bytes with `json.loads` inside the same `try`, never call `request.json()` or `request.body()` after the capped read, and treat a non-dict result as `{}`. The frozen browser-key link nodes (M2 T13) must pass in the build's full ee run. The same rule holds for the direct route under the flag, which already parses the bytes with `_strict_json_parse`.
- **A3 (3.5, FR-4 bullet).** Delete "with the seal entry the row needs". `ee/tests/test_m3_t3_proposals.py` is not in `M3_T0A_MANIFEST.sha256`; only the manifest line is regenerated. A `_SEAL_REPLACED` entry for it would fail `test_replaced_lines_carry_pinned_hash` ("is not a sealed path"). `ee/tests/conftest.py` is sealed (line 7), so FR-5's single entry is right.

## D. Addendum SHOULD

- **A-S1.** A pg guard `test_policy_bundles_sequence_constraint_name_pinned`: the pinned name exists in `pg_constraint` for `policy_bundles`, type `u`, columns exactly `(project_id, sequence)`. A future migration that renames it then fails loudly instead of turning a race into a 500.
