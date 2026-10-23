# Control-plane hand-off (M2 T6-T10 done, 22 Oct 2026)

## Enroll-persistence follow-up (23 Oct 2026): done

1. The tests were committed first in `545c031`.
2. **Client** (`sync/enroll.py`, TCB):
   - It no longer trusts a server `fingerprint` string. The old T8 code did, which broke threat 2.
   - It computes the fingerprint from the genesis it receives and verifies the chain with T6 `verify_chain`.
   - Only then does it persist the managed marker (sync dir and key home), `pinned_root.json`, `registry.json`, device_id and the device key, all through a temp file and rename.
3. **Sync process:** `sync/process.py` `run_once` fetches the new device-token route `GET /api/v1/sync/registry` and persists only a verified chain. The version must be strictly greater; at an equal version the content must be byte-identical.
4. **Server:**
   - The enroll response carries `registry`, the chain for the device's org only.
   - `agg_cp.sync.registry.get_chain` is new.
   - `test_frozen_route_set` gains `_M2_ENROLL_PERSIST_ROUTES` as a named exception.
5. **Security review: APPROVE.**
   - Two LOW items were accepted: the device key gets no explicit 0o600 (its directory is 0o700), and `_stage` uses a predictable `.tmp` name in a user-owned directory.
   - QA added `test_run_once_refuses_equal_version_fork`, checked by bypassing the guard, and made the T10 backoff test deterministic.
   - The builder's test setup edits were ruled clean: the `prev_hash` `org_id:` prefix, and the separate bundle_signer key.
   - Measured: connector 2001 passed, 1 skipped. ee with pg 577 passed, 1 skipped, 2 failed (the known `test_t10_multiworker.py` Windows ReadTimeouts).

**Next:** T11, tests first. T12 must consume `_enforced_approval`.

## M2 T9-T10 status (22 Oct 2026, end of session)

**Final (22 Oct 2026): T9 and T10 were reviewed and committed.** Security round 3 is APPROVE, and F1 is closed under founder ruling A:
1. The approved baseline is the envelope in `.sandbox/policy_history/`, re-verified against the pinned registry on every enforcement (`policy_versions._verified_bundle_payload`). There is no hash-file fallback.
2. A managed workspace always enforces meet(verified bundle or deny-all, local files). The local files are `.sandbox/policy.json` (incl. `environment`) and the governance file; `bundle.json` is never the overlay. A missing, corrupt or bad-signature bundle gives deny-all, plus `bundle_corrupt` and an audit entry. An unmanaged workspace keeps M1 behaviour.
3. Hook wiring (`hook_eval.py` ~264-358): environment, governance, mcp (`SANDBOX DENIED [MCP_POLICY]`), folder. **Approval:** no current decision path reads `local_fallback`/`allow_requester`. The enforced value is exposed as `_enforced_approval` in policy info, and **T12 must consume it.**
4. `tests/security/test_m2_t9_review.py` has 14 tests, all passing on Windows and Linux.

**Named follow-up (security: not a blocker; owner backend-engineer; do it before T11 or as its own task):** no product code writes `.sandbox/state/sync/managed` (or its key-home copy), `pinned_root.json` or `registry.json`. `sync/enroll.py` `enroll()` must persist the managed marker in both places, `pinned_root.json`, `registry.json` and the device key after the fingerprint check. `sync/process.py` `run_once` must persist registry updates. Until then, a real enroll leaves the laptop unmanaged (M1 local enforcement, no loosening path), and the tests hand-write these files. Write the tests first.

Measured before the commit: connector 1964 passed, 1 skipped. ee 569 passed, 1 skipped, 2 failed (the known `test_t10_multiworker.py` Windows ReadTimeouts). lint-imports is clean. Semgrep has 1 LOW audit (`process.py:73`, `urlopen` of a configured URL). gitleaks found 0 leaks in the history.

The history below is the state before round 3.

**Committed and pushed:** `3592a02`, the T9/T10 tests first. In QA, the orchestrator fixed the T9 tests: 2 admins with threshold 2, a distinct key per approval, one key under two user_ids counts once, the bundle signer comes only from the registry, and the property test now has a model, N3, and counters against a vacuous pass. Then `a8a30ae`, the CI ee coverage fix: coverage now measures the uvicorn worker subprocesses, and the total is back to 88%. CI run 39745688470 and security run 39745688584 are green on every job, including ee-windows.

**T9 and T10 are built and UNCOMMITTED. Never stash, reset or checkout them.**
- T10: `src/sandbox/connector/sync/process.py` (new), plus the markers removed from `tests/security/test_m2_t10_sync.py` (21 pass on Windows and Linux). Security round 1 found nothing in T10. It is committed after T9, because `run_once` lazily imports T9's `verify_and_apply`.
- T9 code: `src/sandbox/connector/sync/bundles.py` (new), `sync/state.py`, `protocol/registry.py` (TCB: bundle_signer), `policy_versions.py` (TCB: F1 wiring), `ee/src/agg_cp/sync/bundles.py` (new; `GET /api/v1/sync/bundle`, `POST /api/v1/admin/bundles`), `ee/src/agg_cp/app.py`.
- T9 tests: the markers removed in both T9 files. `tests/security/test_m2_t9_review.py` is new (9 tests). The ee T9 file gains the `_bundle_signer_key_env` setup fixture and `test_admin_create_bundle_no_signer_key_500`. `test_t9_routes.py` gains `_M2_T9_ROUTES` (security named exception, APPROVED). `M2_BASELINE.md` sections 3 and 4 have the rows.
- Measured: connector 1959 passed, 1 skipped. ee 569 passed, 1 skipped, 2 failed (the 2 known `test_t10_multiworker.py` Windows ReadTimeouts). lint-imports is clean. Semgrep has 0 findings, apart from 1 LOW audit on `process.py:73` (`urlopen` of a configured URL, expected). gitleaks has 0 findings. Trivy did not run, because its DB download timed out.

**Security review of T9:** round 1 was CHANGES. Round 2 PASSES F2 (no ephemeral key fallback; 500 `bundle_signer_key_not_configured`), F3 (only the latest version's bundle_signer is trusted; a collision is refused) and F4 (`_meet_mcp` = approved intersect on-disk). **F1 HIGH (N5 at runtime) is still open:**
1. (a) `.sandbox/state/sync/approved_bundle_payload.json` is unsigned and is trusted at enforcement. Fix: re-verify the stored signed envelope against the pinned registry's latest bundle_signer at enforcement, or pin its sha256 in the signed audit chain and check it on read.
2. (c) Fail closed: a missing, unreadable or corrupt approved file must give deny-all, not the disk policy and not a crash (`policy_versions.py` ~453-465).
3. (b) Only `folder_policy` reaches hook decisions. The governance, mcp, approval and environment results sit in `info["bundle_enforced"]`, which no decision path reads (`hook_eval.py:548-556` reads governance from the file path; classify has no mcp_policy; FolderPolicy has no approval fields; the bundle's `environment` is not mapped to `FolderPolicy.environment`).
4. (d) 4 QA tests are vacuous: `test_m2_t9_review.py::test_f1_{governance,mcp,approval,environment}_hand_edit_enforced_unchanged` check only the info dict. They must assert the real `hook_eval` decision.

**Founder ruling (22 Oct 2026): A.** All 5 sections are enforced in T9. Options as offered:
- **A:** wire all 4 sections into the hook decisions in T9. This is a larger TCB change, and it meets the T9 exit check (N5) as written. Orchestrator recommendation.
- **B:** wire environment now; defer governance, mcp and approval to a later task, with an ADR note, xfail tests, and the T9 exit check amended. Security's suggestion. Safe only if no doc claims those sections are centrally enforced.

Items 1, 2 and 4 are code and test fixes either way. Then security round 3, git-ops commits T9 and then T10, and checks CI.

## M2 T7-T8 security review (22 Oct 2026)

**T7 and T8 were reviewed and committed.** security-engineer (worker tier) gave round 1 APPROVE with 2 findings, both fixed, and round 2 APPROVE.
1. MEDIUM: the signer routes opened connections without `SET ROLE agg_app`. Fixed in `ee/src/agg_cp/sync/signer.py` at all 6 `psycopg.connect` sites, matching `enroll.py`.
2. LOW: `check_signer_nonce`, `consume_link_code` and `store_genesis` held in-memory `_store` fakes in a product module. They are deleted, along with `LinkCodeExpired`. QA rewrote 4 ee tests to use the real paths and kept their node ids: `test_signer_nonce_replay_refused` (real `/sync/signer/token`, 409 `nonce_replay`), `test_link_code_single_use` (410), `test_link_code_15_min_expiry` (410) and `test_server_second_genesis_refused` (`agg_cp.sync.registry`, plus a `sync_alerts` row).
3. Items 1-9 in the list below: APPROVE. Every test edit fits an approved class, and none weakens an assertion.
4. Named exception: `test_t9_routes.py::test_frozen_route_set` gains exactly the 10 new routes. The row is in `M2_BASELINE.md` section 3, and the file is added to the `ee` CI `grep -v` list. Known debt, per security: excluded exception files are not hash-checked at all. Pinning each reviewed hash would be stronger. This does not block.
5. Measured locally (Windows, testcontainers Postgres): connector 1888 passed, 1 skipped. ee 556 passed, 1 skipped, 3 failed. The failures are the 2 known `test_t10_multiworker.py` ReadTimeouts and `test_m2_t8_enroll.py::test_4_worker_race_exactly_1_winner`, which failed only while both suites ran at once and passed 2 of 2 runs alone. Semgrep 1.178.0 (Docker, CI rule packs) on the changed files: 0 results. gitleaks 8.30.1: 0 findings. The local `.venv` Semgrep is broken by an opentelemetry `ImportError`, so use the Docker image.

## M2 T6-T8 status (22 Oct 2026, end of session)

**T6 done** at `5a78299` (security round 1 CHANGES, round 2 APPROVE; CI run 39605448447 green; the `ee-windows` job result was not read, so check it). Tests-first are on `main`: T6 `78295e5`, T7 `0d3efa1`, T8 `115597e`.

**T7 and T8: code complete and green locally, UNCOMMITTED in the laptop working tree, NOT security-reviewed.** Never stash, reset or checkout these files. `HANDOFF.md` is staged but not committed (founder: don't commit yet).

**Files:**
- connector (MIT): `src/sandbox/connector/sync/` (`signer.py`, `enroll.py`, `state.py`), `classify.py:64` (`_APPROVER_SUBCOMMANDS` + signer, enroll, unenroll, sync), `hook_eval.py:277-293` (locked-mode deny, a TCB change), `keyhome.py:104,126` (workspace-root registry for the re-enroll fingerprint check);
- server: `ee/src/agg_cp/sync/signer.py`, `ee/src/agg_cp/sync/enroll.py`, `ee/src/agg_cp/app.py` (routers + a `database_url` alias), migration `0008_t8_enrollment_code_cols.py`;
- tests: the 4 T7/T8 test files (markers removed + approved stop-and-ask fixes), `ee/tests/m2_sync_server.py`, `M2_BASELINE.md` rows.

**Measured (local Windows; Linux Docker for the T7/T8 connector files):**
- T7: connector 25 passed (Windows and Linux); ee 32 passed with pg.
- T8: connector 38 passed (Windows and Linux); ee 25 passed with pg.
- Full connector: 1888 passed, 1 skipped (known symlink).
- Full ee: 556 passed, 1 skipped, 3 failed:
  - `ee/tests/test_t9_routes.py::test_frozen_route_set`. Frozen M1 route list; the 10 new routes are extra. **Needs a security named-exception ruling** (add the 10 routes to the frozen set).
  - `test_t10_multiworker.py::test_revoked_session_401_all_workers` and `::test_concurrent_role_grants_idempotent`. Known local-Windows ReadTimeouts (baseline section 4 record 4).
- lint-imports: 1 kept, 0 broken.
- **Not run yet:** Semgrep, gitleaks, CI.

**Design as built (orchestrator rulings this session):**
1. **No identity or time from the client.** There are no `X-User-Id`, `X-Auth-Time` or `X-Org-Id` headers and no body `auth_time` (grep clean). Human routes use `validate_session` (org and user from the cookie; freshness from the server-side session row). Signer routes use only the `/signer/token` bearer. A forged-header 401 test covers each human route.
2. **Enroll:** the PoP is verified before the code is consumed, so a bad proof gives `bad_proof` and the code stays usable. Every code failure gives one uniform 400 `invalid_code` (no oracle). The client sends the code and the server hashes it. There is no RESET ROLE; `SET ROLE agg_app` follows M1 `auth.py:87`.
3. **Codes:** admin `POST /api/v1/admin/enrollment-codes {project_id, operator_user_id}` returns `{code_id, expires_at}` and no code. Operator `GET /api/v1/enrollment-codes/{code_id}` (that operator, fresh session) generates the code in one atomic UPDATE, stores only the hash plus `code_read_at`, and returns the code once. `0008` adds `code_read_at`, makes `code_hash` nullable, adds a column `GRANT UPDATE (code_hash, code_read_at)` to agg_app, and makes the consume guard refuse a NULL hash. Its downgrade marks unissued rows dead (orchestrator fix). Revoke goes through the admin route, with a cross-org 404.
4. **Signer links:** web `POST /api/v1/signer-links` (fresh session) returns the code once and stores only its hash. CLI `POST /api/v1/sync/signer/link` takes code + key_id + public_key. Keys are live only through `approver_keys`; `cli_key_lookup` is unchanged. All 10 new routes declare `x-agg-rbac` through `rbac_route`.

**Security review items (next session, security-engineer, before any commit):**
1. Each new route: auth, org scoping, RBAC role and scope truthful.
2. TCB: `hook_eval.py` locked mode (N7: reads keep the protections and default denies), `keyhome.py` root registry.
3. `0008`: grants, guard, downgrade.
4. Threat 37 subcommand denials.
5. F1, F2 and F5.
6. `signer.py:90` `check_signer_nonce` in-memory store: test-only code in a product module, unused by routes. Remove or move it.
7. `app.py` `database_url` alias.
8. Every test edit beyond markers, by node id. These were approved stop-and-ask: T6 org seeding and `kind`; T7 uuid users, `used_at`, approver_keys seeding, the 12 tests moved to ee, the link split; T8 session cookies, the uniform invalid_code, PoP-first, revoke via the route.
9. The `test_frozen_route_set` named exception.

Then run Semgrep and gitleaks; git-ops commits T7, then T8 (HANDOFF with them), and checks CI including `ee-windows`.

**Process lessons for T9 on:**
1. QA runs new tests against the real routes and the committed schema before the tests-first commit. T7/T8 tests passed as xfail while being wrong: wrong columns, header auth, a test hook in a product API.
2. Builders stop on any mismatch. They never edit committed migrations or frozen files, never pin dependencies to suit tests, and never take identity from the client.

## M2 T1-T5 status (22 Oct 2026)

**Done, each reviewed by security-engineer (worker tier) before its commit:**
1. **T1** `f41af8d`: CI Windows runs the 3 SEC-27/28 ids as passed (embeddable CPython 3.12.10, sha256-pinned). CI checks `M2_FROZEN_MANIFEST.sha256` in two halves.
2. **T2** `435a9df`: `ee/tests/_portable.py`; frozen setup edits in `test_t10_multiworker.py` and `test_m1_t13_review.py`; new `ee-windows` job (non-pg). The `ee` job matrix is Python 3.12 and 3.15 (founder ruling 6).
3. **T3:** `ff5ff38` (code half), `e4c904f` (`_is_windows` Linux fix) and `714f6ea` (Caddy tmpfs root-cert volume). Covers domain groups, SEC-33, the Semgrep chmod removal, the pool, and the CSRF HMAC done independently.
4. **T4** `714f6ea`: Chainguard python `api` image, digest-pinned, Python 3.15, no shell, USER 65532. Local Trivy: 0 HIGH/CRITICAL. `/ready` 200.
5. **T5** `f1d0934`: revision `0007` with 18 tables (FORCE RLS) and 8 SECURITY DEFINER functions. Each function was reviewed (round 1 CHANGES, round 2 APPROVE). CI `ee`: 485 passed, 88% branch coverage.

Records are in `M2_BASELINE.md` section 4, "Build records" (`94043c8`). CI run 39596222149, all green:
- connector: Windows 1772 passed, 0 skipped; Linux 1736 passed, 31 skipped (named list);
- ee: py3.12 and py3.15 495 passed each, 88% branch coverage; ee-windows 318 passed, 177 pg deselected.

**Rules for T6 on (from T1-T5):**
1. QA raises the sentinel only from one feature-absence helper at the top of a test, and writes the final assertions as plain `assert`s. The build then deletes only the markers.
2. Tests never patch global `os` attributes; they patch a module seam instead.
3. QA runs new connector tests on Linux too (Docker `python:3.12`) before the tests-first commit.

**Open:** with Postgres on local Windows, 2 multiworker tests time out (named in the baseline; no gate environment).

**Next action: T6** in a fresh session. T6 covers the envelope, the tags (D5.7: `agg/remote-approval/v1`, `agg/device-enroll/v1`, `agg/signer-assert/v1`, `agg/unenroll/v1` in `sandbox/protocol/domains.py`), the kind matrix, the registry chain and the threshold, on both the connector and the server. Steps:
1. qa-engineer (W) writes the tests first: `tests/security/test_m2_t6_registry.py` and `ee/tests/test_m2_t6_registry.py`, `M2T6Pending`. They cover threats 8, 21-23, 29-31 (registry half) and N8 (a forged signature-count field is refused), with node ids per the `M2_BASELINE.md` section 5 matrix.
2. backend-engineer (W) builds it.
3. security-engineer (W) reviews the diff.
4. git-ops commits.

## M2 T0 status (21 Oct 2026)

**T0b** `031f214`: ADRs 0001, 0002, 0003, 0005 and 0007 amended per D9. security-engineer (claude-opus-5-5) APPROVE WITH CONDITIONS, quoted in ADR 0001. The condition, threat row 37 (the agent runs the sync CLIs, ADR 0001 A1.13; a High today, since `enroll`/`unenroll`/`sync`/`signer` are not in `_APPROVER_SUBCOMMANDS`), is in `M2_PLAN.md` with tests in T7 and T8. **T0a** `c548fd4`: `M2_BASELINE.md`, `M2_FROZEN_MANIFEST.sha256` (116 files, LF blob hashes), node ids (connector 1761, ee 446), demo preset `steal-env` (5 tests pass). CI still checks `M1_FROZEN_MANIFEST.sha256`; switching it to M2 belongs in T1. **Next action:** T1-T5 in a fresh session (T1-T4 depend on T0a, T5 on T0b).

## M2 planning status (21 Oct 2026)

**The M2 plan was APPROVED by the founder on 21 Oct 2026** (`f732d58`): `M2_PLAN.md`, with the reviews in `REVIEW_M2.md`. Security ran 3 rounds and ended at APPROVE WITH CONDITIONS: F1 (bind the un-enroll fields) and F2 (sync never re-pins the root) go into ADR 0001 at T0b, before T5, and land as T8 tests; F3-F5 are demo and scope text. QA: APPROVE. The founder rulings are at the end of the plan: a real second person for the live step, `sandbox watch` off in managed mode, a Chainguard `api` base, no remote approvals on prod in M2, and locked on lost state. **Next action:** T0a (qa, worker tier) and T0b (lead-architect plus security, leader tier) in a fresh session.


## Laptop session status (21 Oct 2026)

**M1 APPROVED by the founder (21 Oct 2026).** Summary and carry-overs: `M1_DONE.md`. **Next action:** M2 (sync) planning in a fresh session: lead-architect drafts `M2_PLAN.md` from the roadmap in `M0_PLAN.md` (M2 sync: connector enrollment, signed policy bundles, audit upload with head checkpoints; ADR 0001 sections 1, 2, 5, 6) plus the `M1_DONE.md` carry-overs (incl. a live two-reviewer dual-control demo step); security-engineer and qa-engineer review; founder approves before any code.

**Done on the laptop (Docker Desktop):** the 4 blocks below ran. Results are in `M1_DEMO.md`: T14 `demo.py` 27 PASS, 0 FAIL on a fresh `down -v`; ZAP 0 High/Medium; `/ready` 200; Keycloak demo profile healthy. Fixes the first real Docker run needed, each signed off by security-engineer: `8b85ede` (Caddy capability, secret ownership, `migrate` reads `AGG_DATABASE_URL_FILE`), `65446a8` (Keycloak built at image-build time, realms split), and the T14 demo fix (bob's real Keycloak `sub` via the admin API, Globex bootstrap, callback status checked before PASS). Records: `16627cc` (gate items 1 and 3 read per founder ruling A in `M1_BASELINE.md`, lead audit of the cloud range, T13 F1/F2 re-review), `edcc8e4` (`.claude/agents/` untracked). Windows needs `127.0.0.1 idp.localhost` in hosts and `demo.py --ca` (README). Open: ee tests not Windows-portable (`os.setsid` in `test_t10_multiworker.py`, symlink privilege in `test_m1_t13_review.py`); CSRF tests compare code with itself (Low).

## Cloud session status (20 Oct 2026, night)

**Next action (laptop, Docker):** run the 4 laptop blocks below in order, fill `docs/control-plane/M1_DEMO.md`, then approve M1 or send back what failed.

**Merged to `main` from the cloud** (each PR green in CI, rebase-merged unless noted):
1. T15 docs `273926d` (#1). T12 web `dd9201e` + `938c089` (#6).
2. T8 part 1: tests `66969c2` (#2), build `eee3ebd` (#4). T8 part 2: tests `74b18b8` (#5, squash: branch had a merge commit), build `b0a708d` (#9).
3. T9: tests `3a0f565` + `2441cae` (#7), build `2a543fa` (#10). T10 `211151a` (#11).
4. T11 compose files `5de6f49` (#3), Keycloak behind Caddy `df75fed` (#8).
5. Wrap-up PR (this commit): T13 review findings F1/F2 fixed (slug can never become a path: `is_valid_slug`, `org_secret_path`, CHECK in revision `0006`), CI `ee` job gains the coverage gate (`--fail-under=85`), `ee/deploy/demo.py` (T14 script; only step 4 run, in the cloud), `M1_DEMO.md` template, `M1_SECURITY_SIGNOFF.md` (T13).

**Security:** every security-sensitive merge had a `security-engineer` diff review and was fixed until signed off (T8 parts 1-2, T9: 2-3 rounds each; T11 twice). T13 hostile review: APPROVE WITH CONDITIONS, no Critical/High; F1 Medium and F2 Low fixed in the wrap-up PR; F3 Low (demo Keycloak `admin/admin` in `compose.yml`, demo profile only) stays as a stated limit.

**Measured here (Linux cloud, native Postgres 16, `CI=true`):** ee suite 412 passed, 0 skipped (incl. the T14 static tests); branch coverage of `ee/src/agg_cp` 87%. The connector suite was not re-run in full here; CI runs it on every PR (green).

**Open items:**
1. Everything that needs Docker (blocks below) is unverified: stack up, `/ready` 200, Trivy, ZAP on the proxy, the Keycloak login, `demo.py` steps 1-3 and 5. `demo.py --step 4` (connector, no Docker) ran in the cloud: 7/7 PASS (listed root 200, unlisted 403, key-home Grep denied by the hook, forged unpinned approval refused).
2. `security / zap-api` (connector API) once reported `zap-10062-pii-disclosure` on #11 and passed on re-run: a content-matching false positive is likely; check the ZAP report if it recurs.
3. Each request opens 1-3 Postgres connections (no pool yet): fine for M1, revisit before load.
4. `claude/cool-mayer-3l0bi1` holds pre-rebase copies of early commits; everything on it is on `main`. Safe to delete.
5. Branch-protection required checks on `main` (founder, unchanged from before).

**Laptop work (Docker machine), exact commands, from the repo root on `main`:**
```
# 1. stack up and ready
cd ee/deploy
docker compose --profile init run --rm init-secrets
(cd ../web && npm ci && npm run build)
docker compose up -d --build
docker compose logs migrate            # migrations ran
curl -sk https://localhost/ready       # expect 200

# 2. scanners (gate item 4)
docker compose build api
trivy image $(docker compose images api -q) --severity HIGH,CRITICAL   # expect 0
(cd ../.. && trivy fs . --severity HIGH,CRITICAL)                       # expect 0
# ZAP baseline on the proxy: the exact docker run line is in ee/deploy/README.md ("ZAP")

# 3. demo stack (Keycloak, orgs acme + globex)
docker compose down
AGG_OIDC_ALLOW_HOSTS=idp.localhost docker compose --profile demo up -d --build
docker compose logs migrate-demo | grep setup_code   # one JSON line
# globex bootstrap: the docker compose run line in ee/deploy/README.md ("Globex")

# 4. T14 demo, all 5 steps, headless
cd ../.. && python ee/deploy/demo.py      # or: --step N
```
Then record each step's result in `docs/control-plane/M1_DEMO.md` (template only, nothing claimed yet).


**Cloud session start (20 Oct 2026, evening):** next task is the **T7 build**. Tests are pushed (`c2dd954`: 27 strict xfail + 2 guards in `ee/tests/test_t7_rls.py`, `test_t7_audit.py`, `test_t7_preauth.py`). A local build attempt was stopped unfinished and is NOT pushed; start from `c2dd954`.

T7 build brief (give it to a `backend-engineer` worker, effort high; security-sensitive, so **no commit before security review**):
1. One Alembic revision after baseline `000000000001`: the 8 M1 tables per ADR 0002; `ENABLE` + `FORCE ROW LEVEL SECURITY` on all; owner `agg_owner`; policies on `NULLIF(current_setting('app.org_id', true), '')::uuid` with USING and WITH CHECK; least-privilege grants to `agg_app` (`admin_audit`: INSERT, SELECT only; TRUNCATE revoked); `agg_worker` nothing. Roles are created outside migrations (deploy init / `pg_roles` test fixture), never with a password in a migration. Full `downgrade()`.
2. `org_login_config(slug text)` returning only `(org_id, issuer, client_id)`: `SECURITY DEFINER`, `SET search_path = pg_catalog, pg_temp`, schema-qualified, EXECUTE revoked from PUBLIC, granted to `agg_app` only, owner `agg_owner`.
3. `admin_audit` per ADR 0002 items 4 and 6 (item 6 = orchestrator ruling: chain computed by a BEFORE INSERT trigger with a per-org advisory xact lock; `admin_audit_canonical(row)` SQL function; client values overwritten; unique `(org_id, chain_length)` and `(org_id, previous_hash)`). Item 6 overrides the hash convention in the test docstrings.
4. `ee/src/agg_cp/audit.py`: `verify_chain(conn, org_id) -> (ok, reason)`, recomputing SHA-256 in Python over `admin_audit_canonical(t)` text, links from 64 zeros.
5. Test edits allowed only in `test_t7_audit.py`: hash helper follows item 6 (keep every assertion); flipped-byte control made real (superuser, `SET session_replication_role = replica`, change one byte of `detail`, `verify_chain` fails, other org still ok); add (a) client-supplied hash fields overwritten, (b) 2 connections x 10 concurrent inserts give chain_length 1..20, chain verifies. New node ids into the T7 list in `M1_BASELINE.md`, marked "added in build per ADR 0002 item 6".
6. Then: orchestrator checks the diff; `security-engineer` (worker tier) reviews against SEC-07 and D5.2-3 (RLS forced everywhere, the SECURITY DEFINER function, trigger functions' search_path, grants, downgrade); then `git-ops` commits the exact file list and watches CI (the `ee` job must show 0 skipped).

**Team rules for a cloud session** (`TEAM.md` and `RESUME.md` are local-only, so they are summarised here; the 8 agent files in `.claude/agents/` and the `.claude/skills/` packs are local-only too (untracked 21 Oct 2026), so a cloud session uses the built-in agent types with these rules in each brief):
- Model tiers: leaders (orchestrator, `lead-architect`, `security-engineer` on design rulings) Opus 5.5 high, spawned with `model: "opus"`; workers (`backend-engineer`, `qa-engineer`, `devops-engineer`, `frontend-engineer`, `security-engineer` on diff reviews) omit `model`, effort high; `support` and `git-ops` omit `model`, effort medium. Pick the cheapest tier that can do the job. The first agent of each tier reports its model id.
- Workers execute the brief; if it is wrong or unclear they stop and ask. Workers never commit; git-ops commits the exact files the orchestrator lists (`git add -- <files>`, commit, `git pull --rebase --autostash origin main`, push). No Co-Authored-By. Never stash, reset or force-push.
- Tests first per task (strict xfail with a named exception), then the build removes only the markers. Frozen files under `tests/` change only with a named sign-off (`M1_FROZEN_MANIFEST.sha256`).
- Postgres tests need Docker. Without Docker they skip locally and **fail under `CI=true`**; then rely on the CI `ee` job (Postgres service) and say so.
- E: drive rules (TMP/TEMP, caches on `E:\caterpillar\jev-os\.cache`) apply only on the founder's Windows laptop.
- Keep token use low: short briefs, fresh agents, batch updates.

**Now (20 Oct 2026, Phase B):** T5 `ee/` skeleton done (`202d6df` tests, `6f0d8ef` build, `4f6c8be` CI fix): ELv2 `ee/LICENSE`, `agg-control-plane`, `ee/.importlinter` (sandbox never imports agg_cp; tests read the shipped file), CI `ee` job, connector-standalone job runs with `ee/` deleted. T6 Postgres/Alembic harness done (`a610562` tests, `8b28514` build, CI green, 42 ee tests incl. pg, 0 skipped): `pg` marker, `pg_url` (AGG_TEST_PG_URL or testcontainers `postgres:16` pinned in `ee/tests/pg_image.py`; a skipped pg test fails CI, xfail excluded), `agg_cp.db` (make_engine, alembic_config, check_db_ready), packaged migrations with empty baseline `000000000001`, round trip snapshots schema + RLS flags + policy exprs, `/ready` 200 only at head else 503 non-secret reason, `agg_cp.clock`, clock and module-state lints. Notes: `/ready` uses its own sync psycopg connection (engine in lifespan unused until T7); Windows tests use SelectorEventLoop (psycopg 3). Docker Desktop is per-user at `C:/Users/Dell/AppData/Local/Programs/DockerDesktop/`, data on `E:/phantom-paper/_docker/wsl` (start it if `docker info` fails). Root suite 1760 passed, 1 skipped. **Next:** T7 (D5.1-3 tables, roles, RLS, admin_audit; security review mandatory).

**Earlier (20 Oct 2026):** M1 Phase A. Pushed and signed off: T4 (`27d1108`, `c632af1`), CI fix (`1fdade7`, SEC-32), T4b (`87abf9a`, SEC-30/31), **T4c** (this commit): M0-era evidence packs verify as `legacy` after key rotation. `evidence.py` (`_canonical_record_hash`, `_check_legacy_key`, dual control per approval strict/legacy, export index uses the same legacy check), `signing._audit_rotation` reuses the shared hash. Tests `tests/security/test_m1_t4c_evidence_legacy.py` (16). Full suite 1668 passed, 1 skipped. e2e on M0 demo copy: before rotation 31 "not rotated" failures; after, OK, 26 legacy, export=verify 26/26. Security signed off (worker tier); orchestrator added the legacy detail to the `signer_is_folder_key` failure message after review (message only). Open: SEC-33 (Medium, `root_exposure` silent when icacls missing); T4c Low 1: `_check_legacy_key` returns on the first matching `key_rotated` event (assumes a key is retired once; continue the loop or document); T4c Low 2: `_canonical_record_hash` uses `ensure_ascii=True`, `_canon` uses False (intentional, add a comment). **Next:** check CI on the T4c commit with gh (`C:\Program Files\GitHub CLI\gh.exe`); remove temp worktrees `git worktree remove E:/caterpillar/jev-os/.cache/tmp/wt-8f52679` and `wt-1339482`; then Phase B (`ee/`) per `M1_PLAN.md`.

**T4 result:** `src/sandbox/protocol/domains.py` (5 active + 4 reserved tags); signed bytes = tag || 0x00 || canonical JSON, `sig_v: 1`; SEC-24 closed (field sets from code; legacy = untagged, 4 code-defined `_HISTORICAL_SIGNED_FIELDS` sets, one kept for frozen Q3 node `test_records_signed_before_fingerprint_was_added_still_verify`). ADR 0007 1.6 closed by orchestrator ruling: `key_rotated` carries `done_at_rotation` {request_id: sha256 of canonical record} inside the chain; `legacy` needs id + hash match, else `unverifiable` (replaces `audit_heads`, which broke frozen `test_evidence.py` counts). `sign_record` no longer re-signs a record that already has a signature (stops laundering). New `tests/security/test_m1_t4_followup.py` (3). Full Windows suite: 1635 passed, 1 skipped. Reviewer note: 36 frozen-manifest mismatches on Windows are CRLF artifacts; no frozen file touched.

**T3 result:** 15 RED tests pass, xfail markers removed. Fixes after review: `_pin_and_audit` audits before the pin and fails closed; `keys.enrol: explicit` enforced at the single pin path (`NotEnrolledError`; enrolled = already pinned, no enrol command until M2); `tool_grants` passes `layout`. New `tests/security/test_m1_t3_followup.py` (12). Frozen `tests/unit/test_evidence.py` exception (3 node ids, counts only, signed off; manifest re-hashed; row in `M1_BASELINE.md`). Full Windows suite: 1610 passed, 1 skipped, 0 failed.

**Verified (pushed, security signed off):** T0c SEC-23 money floor (`bcb81d8`), T0d (`97c2643`), T0e SEC-25 CLI deny (`5ce9df8`), SEC-27/28 hook hardening (`eac889d`..`5595cb4`), T1 `?root=` + SEC-26 (`81adc55`), T0f lexer + git flag allowlist + `.git/**` (`e0041df`, 427-case corpus), T0g runners (`6a7c0e9`), T2 key home (`da58fc3`, pushed before review) plus follow-up (`200c8ab`, signed off). Last full Windows suite: 1583 passed, 1 skipped, 15 xfailed (at `4f33e63`).

**Next 3 steps (1-2 done, 3 in progress):**
1. (Done) T3: the 15 RED tests pass; remove only their xfail markers; full suite green. Label decision (orchestrator): each approval in the evidence pack and `sandbox verify` gets `key_status` = `pinned` | `legacy` (retired pre-M1 key AND under the `key_rotated` chain head) | `unverifiable`. Only pinned/legacy count as verified.
2. Security diff review of T3 (worker tier). Commit + push via git-ops with the exact file list. Update REVIEW_SECURITY: SEC-25 closed (proposer signature), the T2 "retired seed" known limit closed, ADR 0007 section 1.6 done.
3. T4 (domain-tagged signatures, SEC-24 `verify_record` trusts the record's `signed_fields`) **plus ADR 0007 section 1.6**: `legacy` must verify under the `key_rotated` audit head; today `_key_status_for` uses a backdatable timestamp (orchestrator ruling, REVIEW_SECURITY "T3 limits"). Then Phase B (`ee/`) per `M1_PLAN.md`.

**Open conditions not yet in M1_PLAN/M1_BASELINE:**
- `root_exposure` (icacls) misses domain-local groups (`DOMAIN\Domain Users`): fix before multi-user control plane.
- CI "key-home-empty" check (LOCALAPPDATA/HOME at an empty temp dir, assert it stays empty) is not done (devops, `tests.yml`).
- Shell recursion into a dir above the key home is denied only for recognised forms: publish as a limit.
- Docker Desktop is not running and its disk image is on C:. M1 T6/T11/T14 need it on E: (founder).
- Founder: make `tests`, `security`, `image` required checks on `main`. Azure student credits for a VM at T11 (see memory).
- CI state after `200c8ab`/`4f33e63` not re-checked.

**Rules learned (put in every worker brief):**
- Model tiers: see TEAM.md "Model hierarchy". Leaders `model:"opus"`; workers/support/git-ops omit `model`; effort high (workers) / medium (support, git-ops). Verified ids: workers `claude-opus-4-6`, git-ops `claude-sonnet-4-6`.
- Run pytest via Bash (`.venv/Scripts/python -m pytest -q -p no:logging ... | tail -40`) or PowerShell **without** `2>&1` (PS 5.1 turns stderr into errors, output is lost). Exit 1 while tests are red is expected.
- git-ops order: `git add -- <exact files>`, commit, `git pull --rebase --autostash origin main`, push. Never pull before committing.
- Workers never commit security-sensitive work before sign-off; say so explicitly in every brief (a cut-off brief caused the unsigned `da58fc3` push).
- Unfixed Critical findings: keep repro out of public docs/commits; hold all pushes until tests + fix ship together.
- Class C / frozen tests: change only with a named sign-off by node id; re-hash `M1_FROZEN_MANIFEST.sha256` and record the exception in `M1_BASELINE.md`. M0_* files are history; don't edit them.
- E: drive env vars in every shell (`TMP`/`TEMP`/`PIP_CACHE_DIR`/`HF_HOME` under `E:\caterpillar\jev-os\.cache`). No Co-Authored-By. Never stash, reset or force-push.
- Writing a founder quote relayed by another session into the repo can be blocked by the classifier; the main session records those.

**Update (19 Oct, later):** T3 finished, reviewed and committed. SEC-25 closed. The T2 "retired seed" limit and ADR 0007 1.6 stay open until T4.
