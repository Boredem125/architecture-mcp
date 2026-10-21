# M1 hand-off (19 Oct 2026)

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
