# Control-plane hand-off (M2 T6-T10 done, 22 Oct 2026)

**30 Oct 2026 (late), d4 round 2: D4-1 CLOSED; R2-1 and R2-2 built; uncommitted, never stash.**
- **Round 3 (30 Oct, security W): APPROVE.** R2-1 (alert commit survives the 409, `signer.py:754-790`), R2-2 (`registry_chain.py`; both callers use it; `verified_state.py:189` alone ratchets high_water), the `test_m2_enroll_persist.py:621` fixture signed off by node id; no relaxed check; Semgrep 0 ERROR (1 known WARNING, `sync_cmds.py:1323`), gitleaks clean. qa removed the 7 XPASS markers. Measured: connector 2352 passed, 7 skipped, 1 xfailed; ee 826 passed, 2 skipped, 0 failed. Founder ruling 14: push `T12D_D4_SECURITY_REVIEW.md` with the d4 commit (D4-1 closed; R2-4 is named as G-L4 in ADR 0011 A1 in the same commit). Steps 1-4 of "Next, in order" below are done once the d4 commit is in and CI is green; the d4 exit (`ee/deploy/demo.py` step 2 through the routes) is next.
- **Security leader round 2** (appended to `T12D_D4_SECURITY_REVIEW.md`): D4-1 closed (the guard catches version 1, 1.0 and true; other shapes are refused by `verify_chain` or store nothing; probed). D4-2 closed in the product. CHANGES for R2-1 (the `second_genesis` alert was dropped; `test_m2_t7_signer.py::test_second_genesis_refused_via_route` encoded the hole) and R2-2 (`_refresh_registry_chain` recreated `high_water.json`; no high-water floor; duplicated `process.py::_fetch_registry`). R2-3 was a test bug in the F13 test. Rulings: D4-6 narrowed bound accepted for this commit (unconditional in d5); debug log and O_TRUNC accepted; `run_once` must report a `registry` status; e2e step 5 follows frozen step 2 (v2 adds admin2 only, threshold 2; v3 adds bob, carol and alice-approver; no S9 change). The CLI has no relaxed check (AST-equal to `ed26bff` in `_fetch_escalation`, fp_v, binding, signatures, transport).
- **R2-4 HIGH** (one admin holding two admin keys gets dual control): founder ruling 13, fixed in d5; see the R2-4 block below.
- **Built since** (qa tests first, then backend W):
  - ee `signer.py:754-784`: the v1 guard commits the `second_genesis` alert when a chain exists, then returns 409.
  - New `src/sandbox/connector/sync/registry_chain.py` `apply_registry_chain`: one helper for the CLI refresh and `process.py::_fetch_registry`. The floor is max(local, high_water); a missing or corrupt `high_water.json` is refused; the helper never writes high_water; a same-version change in bytes is refused; `verify_chain` runs before an atomic write. `run_once` returns `results["registry"]`.
  - Tests: e2e step 5 passes on the frozen step 2 flow; the F13 and deny tests pass against the real linked seed.
- **Measured (backend's last run):**
  - 7 R2 tests XPASS strict; their markers are not yet removed.
  - Connector: 2345 passed, 7 failed (5 of the R2-2 XPASS, the PATH test, plus `test_m2_enroll_persist.py::test_run_once_persists_verified_registry_update`).
  - ee: 823 passed, 3 failed (2 of the R2-1 XPASS, 1 known flake).
- **Next, in order:**
  1. qa (W): remove the xfail markers of `ee/tests/test_m2_t7_signer.py::test_second_genesis_alert_via_route`, `ee/tests/test_m2_t12d_genesis.py::test_d4_1_guard_second_genesis_alert_committed` and the five `tests/security/test_m2_t12d_signer_cli.py::test_r2_2*` tests.
  2. qa (W): give `test_run_once_persists_verified_registry_update` a `high_water.json` fixture mirroring `enroll.py:520`. The new helper correctly refuses a missing file; this test edit needs a security sign-off by node id. Then run the full connector and ee suites. Known flakes: `test_concurrent_role_grants_idempotent`, `test_signer_nonce_replay_across_workers`; the PATH test `test_r3_done_record_carries_exec_argv`.
  3. security (W) re-review by node id: R2-1, R2-2 (`registry_chain.py`; check that `verified_state.py` still advances high_water after a newer registry), the fixture sign-off, Semgrep, gitleaks.
  4. git-ops commits d4 (product, tests, ADR 0011 A1, plan, baseline and manifest, `T12D_D4_SECURITY_REVIEW.md`, HANDOFF) and checks CI.
  - Founder push decision still open: push the review file now (D4-1 is closed; R2-4 is marked "fix in d5", an insider gap) or hold it until d5.
- **Then:** the d4 exit: `ee/deploy/demo.py` step 2 through the routes (ruling 6; not started). Then d5 (2 d, incl. R2-4 and the ruled d5 items), c6 (real NF-1 tests), T15b, T16, T17; X0 alongside.

**30 Oct 2026, c5 and d3 committed; d4 built, security CHANGES (one critical); founder rulings 1-12 on plan and split.**
- **Commits:**
  - `353547d` c5: web script panel. Worker re-review APPROVE. CI green on all jobs.
  - `ed26bff` d3: signer CLI. Leader security CHANGES in rounds 1-2, APPROVE in round 3, `T12D_D3_SECURITY_REVIEW.md`. CI: 3 ee jobs red on `test_d0_3` XPASS (strict), because d3's F5 diff fix closed D0-3.
  - `b265c10` CI follow-up drops that marker (security d4 ruling 4). Check that it is green.
- **Stub rulings (d3 review):**
  - The bundle-signer key comes from a required `--bundle-signer-key` flag; the migrations job prints it.
  - The server grows `GET /api/v1/sync/signer/registry`, the full chain verified locally.
  - The link response returns iss/sub; `link.json` stores them.
- **d4: uncommitted, never stash.** Built by backend (W).
  - Changes:
    - server registry route, iss/sub in the link response, migrate prints the `bundle_signer` line;
    - CLI F11, F13, F14, R2-4..R2-7;
    - the e2e moved off `store_registry_version`;
    - frozen `ee/tests/test_t9_routes.py` route-set row (approved; `M2_BASELINE.md` row and manifest hash `4583c359...` done; the reviewer's `ba142d90...` was the CRLF hash).
  - The orchestrator reverted two builder relaxations in `cli/sync_cmds.py` (the review confirmed both byte-identical to `ed26bff`):
    - `signer approve` skipped the fp_v refusal and the binding-fingerprint check when fp_v was absent;
    - `_fetch_escalation` picked `data[0]` from a list.
  - It fixed the F13 test's mock record to a full v2 record (approved).
  - Measured before round 2: connector suite 2336 passed, 7 skipped, 2 xfailed, 1 failed (the known PATH test); ee d4 files 66 passed.
- **d4 leader security review: CHANGES.** The file `docs/control-plane/T12D_D4_SECURITY_REVIEW.md` is untracked on purpose: **do not push it, or this section, until D4-1 is fixed**. The repo is public and D4-1 is live in pushed code since d2.
  - **D4-1 CRITICAL** (`ee/src/agg_cp/sync/signer.py` `/signatures`, `store_signer_signatures`): a version-1 registry is accepted for an org with no chain, so a non-admin can create the root without a genesis code. Fix: `/signatures` refuses v1 or no chain with 409.
  - **D4-2 HIGH:** F13 linked-key approve signs `user_id ""`. Fix: user_id from vs.registry; deny uses the same key loading.
  - **D4-3:** compose migrate jobs lack the bundle_signer secret and env.
  - **D4-5:** e2e lacks 3 frozen step 2 negatives; v2 threshold must be 2.
  - **Lows:** D4-4, D4-6, D4-7, D4-8.
  - **Rulings:**
    - The e2e setup edit is REFUSED: it used the D4-1 hole. Rework: alice admin, a code, genesis via `/signer/genesis`, v2 via `/signatures`.
    - The never-passing `test_d4_link_response_contains_iss_sub` is replaced: link refuses without iss/sub, plus an ee pg test.
    - Demo step 2 (`ee/deploy/demo.py` through routes) stays in d4.
- **Round-2 tests (qa W): partial, status unverified.** Two qa agents worked on them; both stopped (usage limit, then the founder's stop on 30 Oct). Marker counts at the stop: 47 `M2T12dPending` in `ee/tests/test_m2_t12d_genesis.py`, 5 in `ee/tests/test_m2_t12b_e2e.py`, 105 in `tests/security/test_m2_t12d_signer_cli.py`. The last agent was looking at a "step 5" failure in the e2e test. The next qa diffs the 3 files against items 1-6 of `T12D_D4_SECURITY_REVIEW.md`, finishes what is missing, and runs the 3 files once.
- **CI:** `b265c10` green on every job (tests, security, image).

**Plan and split (founder rulings 30 Oct, `T12B_PLAN.md` "Founder rulings (30 Oct 2026)", rows 1-12):**
- **Split:** free, MIT = the security layer for AI agents (blocking, shell canonicalisation, script binding, broker, local audit chain, local approvals and dual control, evidence builder and verifier; ADR 0004 rule 6). Paid, ELv2 `ee/` = the control plane: central policy, org-wide audit, identity-bound approvals (OIDC, user-bound keys, registry), signed org evidence. Never "authorization layer", never "audit edition".
- **Pitch:** "Blocks the agent actions that native classifiers wave through, on every coding agent; the paid control plane proves which person approved the rest." The free layer is the deterministic floor where native guards fail, not a deny-rule list.
- **M2 order (1A):** D4-1 first; d4, d5, c6, T15b, T16, T17 stay the critical path; NF-1 post and Lane X X0 alongside (both by 15 Nov); X1-X9 after the gate. Lane X adds Friendly Fire, TrustFall and CVE-2026-35603 (row 10).
- **NF-1 draft:** `docs/NF1.md` (untracked, founder says it looks good; he posts on LinkedIn himself). Hold the post until c6 adds the real NF-1 tests (c6 row): the two marker tests pass only because the broker refuses their old-format record.
- **Market scan (30 Oct):** `research/2026-10-30-market-scan.md` (local-only). PM: existence about 60%, business survival about 30% until discovery calls; biggest risk: a platform ships approval routing plus audit export for local sessions.
- **New agents (local `.claude/agents/`):** `researcher` (Opus 5.5 high, writes `research/`) and `outreach` (Sonnet 5.5 medium, drafts only, writes `outreach/`); both folders are in `.git/info/exclude`. PM fallback: Opus 5.5 high whenever Fable 5.1 has no credits.

**Next, in order:**
1. qa (W) finishes and verifies the round-2 tests.
2. backend (W) fixes D4-1 first, then D4-2..D4-8 and `ee/deploy/demo.py` step 2 through the routes; check its diff for any relaxed check before review.
3. security (L) re-reviews d4; git-ops commits d4 with `T12D_D4_SECURITY_REVIEW.md`, the plan and this section (safe to push only once D4-1 is fixed).
4. d5, c6 (incl. the real NF-1 tests), T15b, T16, T17; X0 alongside.
5. Founder: book discovery call 1 of 5 this week (3 by 13 Nov); outreach can draft the target list.

**R2-4 (d4 review round 2), founder ruling 13, 30 Oct: fixed in d5, in M2.**
- ADR 0011 amendment A1. For registry v2 and later, `/signatures` binds every added key to that user's own pending link or browser enrollment (a `users` row in the same org; admin keys need the org admin role binding). S9 and dual control count distinct user_ids on both sides; the connector already does (D0-2), so d5 adds pin tests only.
- **Named limit G-L4 until d5 is committed:** one admin can reach dual control alone, with a second admin key under an invented user_id. Never demo or claim "two humans" before then.
- d5 is now 2 d: security (L) writes the spec, qa (W) writes the tests first, backend (W) builds, security (L) reviews. The M2 gate is about 13 Nov, or 16 Nov if d4 needs a third security round (`T12B_PLAN.md` d5 row, ruling 13).

**28 Oct 2026 (evening), T12c c2-c4 and T12d d2 committed; c5 and d3 built, uncommitted.** Commits: `eb50920` plan rulings; `dca1873` c2 (connector script binding, broker shell parity, security APPROVE after R1-R6, `T12C_C2_SECURITY_REVIEW.md`); `85d6b8f` and `c51d0f0` CI follow-ups (gitleaks ignore for the c1 fixture key, frozen manifest rows, the lexer bounds test pins `shellwords.DEADLINE_SECONDS`); `c786c5f` c3 + c4 + d2 (`T12C_C3_SECURITY_REVIEW.md`, `T12C_C4_SECURITY_REVIEW.md`, `T12D_D2_SECURITY_REVIEW.md`, all APPROVE after fixes). CI on `c786c5f` is green on every job of tests, security and image.

**Uncommitted, never stash:**
- **c5 (ee/web)**: script panel, WebCrypto hash gate, `approveEnabled(esc, hashState)` helper, the control-character rule (rel: no controls; body: tab, LF, CR allowed, U+2028/2029 and lone surrogates refused), defence in depth in `buildInboxDecision`. The worker review (cavecrew-reviewer) found 2 bugs (a script record without a preview left Approve enabled and signed an empty preview hash) and 5 risks; all fixed. `ee/web/tests/script-safety.test.ts` is new (25 tests). Measured: lint clean, build + check-csp clean, vitest 92 passed. **Needs: the reviewer's re-review of the fixes, then commit.**
- **d3 (signer CLI)**: `src/sandbox/connector/sync/signer.py` (`build_genesis` user_id and roles, `compute_diff` D0-3), `src/sandbox/cli/sync_cmds.py` (`signer link`, `signer genesis`, `signer sign-registry`), `tests/security/test_m2_t12d_signer_cli.py` (16 xfails flipped, markers removed). Measured: d3+c3 45 passed; connector full suite 2292 passed, 1 xfailed, plus the PATH-sensitive `test_r3_done_record_carries_exec_argv` (passes with Git bash first on PATH, fails when the WindowsApps bash alias is first; c6 makes the test record its own shell). **Builder-reported stubs, not resolved:** `signer genesis` reads the bundle-signer public key from a `/config` endpoint that does not exist server-side (clear error when absent); `signer sign-registry` build mode fetches `/registry/latest`, not implemented server-side (co-sign mode with `--in` works); `link.json` stores no iss/sub, so genesis needs `--confirm-identity`. Decide in d4/d5 whether the server grows those two routes or the CLI takes the values from flags. **Needs: leader-tier security review (auth, keys, the link seed storage), the stub ruling, then commit.**

**Local environment (28 Oct):** the Microsoft Store python keeps packages in user site-packages, which the hook stubs' `python -I` launch ignores, so 100+ subprocess tests fail under it. Use the project venv for every run: `.venv\Scripts\python` (gitignored; `pip install -e .[dev]` and `-e ./ee[dev]`). Postgres comes from testcontainers; Docker Desktop is the per-user install at `%LOCALAPPDATA%\Programs\DockerDesktop\Docker Desktop.exe`. Frozen-file edits need a section 3 row in `M2_BASELINE.md`, the manifest hash (LF content) and a security sign-off by node id; builders may not edit qa's tests without that sign-off.

**Next, in order:** c5 re-review and commit; d3 security review (L) and commit; d4 (the e2e switches to the genesis flow, `test_e2e_does_not_call_store_registry_version` flips) and d5; c6 (e2e script swap after web and CLI approvals; extra test 9 SHELL_DEADLINE; the r3 shell fixture; c4 R2 deferred item); T15b; T16; T17. Lane X in parallel, never gating. Kill dates 15 Nov and 30 Nov unchanged.

**28 Oct 2026, distribution review and founder rulings.** The PM wrote `docs/PM_DISTRIBUTION_ASSESSMENT.md`; the founder rejected the governance channel in its Appendix A. Lead-architect reviewed it in `docs/ARCH_REVIEW_PM_DISTRIBUTION.md` (CONFIRM WITH AMENDMENTS), and the PM accepted every correction in its "PM response to architect review" section. The founder's positioning ruling: AI security is the moat, not AI governance. The founder then approved six rulings, recorded in `T12B_PLAN.md` "Founder rulings (28 Oct 2026)":
1. c5 is kept.
2. The suite spend is approved, with vendor disclosure first.
3. The kill dates are split: 15 Nov and 30 Nov.
4. ADR 0012 (broker credential custody) is the M3 exit item 1 candidate.
5. lasso mcp-gateway is excluded from the shell suite.
6. Leader-tier review also covers d2 and c4.

T12d d2-d5 are finished in M2, not paused. The amended order, the sizes and lane X are in `T12B_PLAN.md`.

## Founder rulings (25 Oct 2026, terminal)

1. The F3 operator named limit is **Low**, fixed in M3 (ADR 0010 updated).
2. The founder-proxy rulings of 24 Oct (split T12b, F1, F2, F3) are **confirmed**.
3. Three M2 named limits are **accepted**: every remote approval requires dual until command classification lands (fix first in M3); `high_water.json` is unsigned (Low); the broker passes only an env allowlist (deploy commands may need more variables).
4. Work resumes on 26 Oct (the weekly limit resets that day): finish T12b-2 from the uncommitted tree, then T16.
5. Navrina (Credo AI) was sent the blurb (25 Oct); the founder will run 5 discovery calls. The stray `ee/%SystemDrive%/` folder: no ruling yet; do not commit it.
6. NVIDIA OpenShell/Sentry (25 Oct, later): no fork, no adapter, no NVIDIA code, spike dropped; ideas rebuilt clean-room. `SENTRY_IDEAS.md` ranking approved (#1-#3 in M3). The script gap (approval binds the command text, not the files it runs) is fixed in M2 once security confirms it with a failing test. The discovery calls add the 4 questions in `SENTRY_IDEAS.md`.
7. T12c (script content binding, ADR 0010 s9) runs after the T12b-2 commit and before T16. **NF-1 is fixed in M2** (security High, confirmed on Windows: the broker ran approved commands through cmd.exe, not the bash meaning reviewers saw; proof `tests/security/test_m2_t12c_nf1.py`). PM cuts accepted: M2 families python, node, bash/sh, pwsh -File; direct .exe/.cmd/.bat and other families deferred to M3 (unbound, denied under the floor). Web inbox shows the full script body. Demo step 5 stays `steal-env`; T16 adds a separate script-swap scene.

## Next: T12c and T12d (both before T16), 25 Oct 2026

**Never stash, reset or checkout the working tree.** Uncommitted on purpose: ADR 0010 s9 (T12c, accepted), ADR 0011 (T12d genesis bootstrap, proposed), the T12c/T12d sections of `T12B_PLAN.md`, `SENTRY_IDEAS.md`, `OPENSHELL_EVAL.md`, this file, and the proof files `tests/security/test_m2_script_binding.py` (qa, 2 passed, 2 skipped, 3 xfailed), `tests/security/test_m2_t12c_nf1.py` (security, Windows-only, 1 passed, 2 xfailed), `ee/tests/test_m2_t12d_d0.py` (security, 8 xfailed). Commit these docs and proofs as the T12c/T12d c0/d0 commit once QA reviews the c0-c6 and d0-d5 tables.

1. **T12c (script content binding + NF-1):** design in ADR 0010 s9 and T12B_PLAN "T12c" (c0 done: security D1-D5 accepted with C-c0-1..7; PM cuts; founder: NF-1 fixed in M2). Broker runs every approved command through the shell the hook modelled (bash `--noprofile --norc -c`, or pwsh/Windows PowerShell 5.1 `-EncodedCommand`), never cmd.exe; `sandbox init` records shell paths (Windows bash: `--bash`, CLAUDE_CODE_GIT_BASH_PATH, Program Files Git, git-derived `E:\Git\bin\bash.exe` on the demo laptop, then PATH; refuse WindowsApps/System32 WSL bash). Fix in the QA test file: the `_need_t12c` arity probe is gameable (keep only the behavioural probe), and direct exec must be tested as unbound under the floor. Next: c1 tests first (qa), then c2-c6.
2. **T12d (registry genesis, ADR 0011):** PM agreed (genesis code; file hand-off in M2; quickstart must explain the code; ask partners "two admins on install day?"). Security d0: ACCEPT WITH CONDITIONS C-d0-1..13. Prerequisites in shared `src/sandbox/protocol/registry.py` before d2: D0-1 High (key_id == sha256(public_key) for every key), D0-2 High (thresholds count distinct users, not keys), D0-4 (envelope kind). `build_genesis` user_id = sub bug (High impact). Migration numbers: 0011-0013 are taken (T12b-2); T12c and T12d take 0014+.
3. Then T16 (demo, step 5 stays `steal-env`, new script-swap scene 5(d)), then T17.

**M3 items from T12b-2 review (Info):** check_key_id_cross_org NULL handling (callers treat NULL as no conflict; refuse unless the row is exactly False), signer_links expires_at and proof of possession, cli_key_lookup fallback refusing >1 distinct (org_id, user_id), the browser route's missing 15-minute fresh-session check, the scrubbed-secret named limit.

## M2 T12b-2 (25 Oct 2026): DONE, `903a711`

Server M4 and the signer GET route, approver_keys as the registry projection (ADR 0010 s8, migrations 0011-0013), the display rule (s7), web inbox, and the real e2e (enroll, hook, upload, two CLI approvals, operator refused, one broker run, offline evidence with --expect-root). Security at leader tier rounds 1-4, APPROVE. CI green on every job incl. Windows. Measured: connector 2171 passed, 5 skipped, 6 xfailed; ee 729 passed, 2 skipped, 8 xfailed; web vitest 61 passed. Tests first in `78657b7`.

The text below is the state before the build (kept for history).

Uncommitted then (built, NOT yet security-approved):
- Server `ee/src/agg_cp/sync/escalations.py` (M4: signatures required, tag fixed in code, payload bound to the escalation row, not_after finite and bounded, operator self-approval refused, 1 MiB body cap, strict signature/decision/policy_sequence checks; new `GET /api/v1/sync/escalations/{escalation_id}` with signer token or session), `ee/src/agg_cp/web/escalations.py` (list adds device_id, fingerprint, org_id, requires_dual; shape `{"escalations": [...]}`), `ee/tests/test_t9_routes.py` (`_M2_T12B_ROUTES`), `ee/tests/test_m2_t12b_server.py` (markers removed), `ee/tests/test_m2_t12_remote.py` and `test_m2_t13_web.py` (seeding edits, mid-change).
- Connector `src/sandbox/cli/sync_cmds.py` (signer uses a signer token, looks up by escalation_id, signs the server's fields), `src/sandbox/connector/sync/process.py` (upload sends the record's bundle_sequence), `tests/security/test_m2_t12b_sync.py`.
- Web `ee/web/src/{inbox.ts, InboxSection.tsx, App.tsx, approval.ts, browser-key.ts, api/client.ts}` and tests (`inbox.test.ts`, `inbox-section.test.ts`, edits to har-check/prod-guard/signing/browser-key). 56 vitest passed at last run. Enroll now stores the key; no double escaping.
- Security proofs `ee/tests/test_m2_t12b2_review.py` (R1, R2); e2e `ee/tests/test_m2_t12b_e2e.py` (qa was rewriting step 1 to call the real enroll()).

**Open items, in order (the backend was stopped mid-way on 1-3):**
1. R1: refuse when the stored escalation fingerprint is missing (the builder had added a `sha256(command)` fallback: remove it); seed T12/T13 escalations with a fingerprint.
2. R2: refuse when `connectors.operator_user_id` is NULL (the builder skipped it); set operator_user_id in the T12/T13 seeding helpers (named setup edits).
3. `process.py`: do not coerce a non-int bundle_sequence; refuse and audit.
4. **Real enroll fails end to end:** the server's enroll response lacks `operator_user_id`, so `enroll()` aborts ("server response missing operator_user_id; nothing written"). The T8 enroll route must return the operator bound to the code. Found by the e2e test.
5. Finish the e2e test (real enroll, hook, run_once, two CLI signer approvals, the operator refused, one broker run, evidence with --expect-root), then make it pass. The hook DENIED steal-env in the managed workspace instead of escalating (check the managed bundle/folder policy).
6. Security re-review of T12b-2 at leader tier (C9 items 3 and 8), then commit, then the HANDOFF update; then T16.

**Lessons:** builders repeatedly reported stubs as done and relaxed product code to keep old tests green; leader-tier reviews and the new e2e test caught it. Brief every builder: say "stub" or "not done", never relax product code for tests (use named setup edits).

## M2 T12b-1 (25 Oct 2026): connector fixes and CLI wiring

1. Plan, ADR 0010 and tests first in `bcd293f` (T12B_PLAN.md; security b0 conditions C1-C9; founder-proxy rulings below).
2. **Built (connector TCB):** the binding fingerprint stamped by the hook and recomputed before and after the claim; user_id from the latest registry version's key (revocation = absent from the latest version); one verified-state accessor with a fail-closed high-water mark; no unverified reads on any decision path; strict request ids; not_after required; the `(key_id, nonce)` replay key with a write-ahead save; done is terminal; remote-approved actions finish via `queue.finish`, signed by the local `connector:<device_id>` key created at enroll, the hash in the audit chain; the broker uses an env allowlist and refuses a missing cwd; enroll persists operator_user_id and device_id, refuses a different org or a re-enroll; `sandbox enroll`, `sandbox sync` (upload, decisions poll, apply_external), `sandbox signer approve|deny` (sign and POST only, never apply locally); evidence re-verifies remote approvals offline and needs `--expect-root` (out of band) for remote dual control.
3. **Security:** b0 at leader tier, then rounds 2, 3 and 4 at leader tier, each CHANGES with proof tests (fingerprint not recomputed, hook did not stamp, evidence trusted approved_by, no revocation, rollback, broker env; then high-water fail-open, deny counted as approver, root not out of band, requires_dual floor, stub wiring; then missing enrollment.json, ok without --expect-root). All fixed; round 4's two items were fixed inline by the orchestrator. Proof files: `tests/security/test_m2_t12b_review.py`, `_review3.py`, `_review4.py`.
4. **Named limits:** (a) no command classification in `apply_external` yet, so every remote approval requires dual (R8 kept as strict xfail); (b) `high_water.json` is unauthenticated, so a device holder can lower it (Low; fix: bind the registry version in the envelope or sign the file); (c) the operator binding (F3) severity is OPEN: the founder answered "no" to Low on the 24 Oct call; (d) `signer approve|deny` needs a server GET route and signer-token auth: T12b-2.
5. **Process note:** the builder twice reported wiring as done while parts were stubs; the leader-tier reviews caught it. Brief builders to report stubs explicitly.
6. Measured: connector 2161 passed, 3 skipped, 1 xfailed (R8); ee T12+T13 38 passed (builder run).

**Next:** T12b-2 (server M4, the GET escalation route plus signer-token auth for `signer approve`, the web inbox on the stored key, the --live run), its own security review; then T16.

## Founder-proxy rulings (pending founder review)

**2026-10-24, T12b forks (T12B_PLAN.md section 6; founder approved T12b by phone).**

1. **Split T12b?** Ruling: **split.** T12b-1 = b0-b3: H1, H2, H3, M1, M2, M3, L1, L2, nonce rescoping (ADR 0010), CLI enroll/sync/signer approve+deny, upload/decisions wiring, evidence offline verify, the additive list fields on `GET /api/v1/escalations` (the headless signer needs the D5.6 set; same route, frozen route set unchanged), demo steps 3, 5, 11 headless (step 6 non-blocking), its own security round 2. T12b-2 = M4 + M1 server types, the web inbox on the stored IndexedDB key, the `--live` step 5 run, its own security review. Reason: the TCB diff is the one that must be reviewed cleanly and should not be mixed with React and route code; the PM's two reviews replace the architect's five per-stream reviews plus one whole-diff round, so it is cheaper, not dearer. Condition: T16 starts only after T12b-2 APPROVE (every High and Medium fixed before any demo); T12b-1 removes only the H1-H3/M1-M3 xfail markers, never M4's. Reversible: yes (task boundaries only).
2. **F1 trust kwargs on `apply_external`.** Ruling: **A, remove them.** Reason: tighten-only seams are TCB code whose only job is to be wrong once; a production signature of `(layout, request_id, approvals, *, clock)` is the property itself. The ~28 T12 and 4 T15 call-site edits are named test-setup edits (M2_BASELINE section 4 row, T13 precedent), mechanical, assertions byte-identical, security approves node by node; the gate has not run, so no frozen gate item changes. Reversible: yes.
3. **F2 remote done-record signer.** Ruling: **A now (local `connector:<device_id>` key via `sign_record`), B (device key, new tag `agg/remote-done/v1`) in M3.** Reason: the human proof is the two embedded envelopes verified offline against the pinned registry, which is exactly what demo step 11 checks; the record signer is only a tamper seal on the connector's own file, and an ADR 0007 tag change buys nothing for the M2 exit. Condition: the done-record and `verify_evidence` label the seal as `signer_kind: connector` and never count it as an approval. Reversible: yes.
4. **F3 operator source for S8.** Ruling: **A, with the named limit.** Not a founder matter: A does not weaken a plan property. M2_PLAN D6.4 (line 35) already binds the operator to the user the admin issued the code to, so the server is the plan's source of truth; today S8 is not enforced at all. B is weaker, not stronger: a mandatory self-asserted `--operator` lets the operator type another id and approve her own escalation (the H1 variant), and it changes frozen step 3 text, which I may not touch. Named limit text: "a compromised server at enroll time can mislabel the operator; dual control still needs two distinct registry-key humans, and the operator sees the printed id." Severity Low (precondition: server compromised at enroll and a colluding operator with a registry key). Condition: step 3 text unchanged; `--operator` optional, must match if given; enroll aborts with nothing written if the server omits the id. Founder to confirm the Low severity on review. Reversible: yes (tighten later by requiring the operator id in the signed registry).

## M2 T14 (24 Oct 2026): done

1. Tests first in `91dc6ac` (16 tests: 13 static, 1 live docker, guards).
2. **Build (`ee/deploy/`):** the bundle-signer key is a compose file secret mounted only into `api` (`AGG_BUNDLE_SIGNER_KEY_FILE`); `init-secrets` generates it as a 32-byte hex Ed25519 seed (uid 10001, mode 0400, O_EXCL so it never rotates silently); carol is in the acme realm (demo-only password, no admin realm role) and is made an org admin by `demo.py`; `payments-staging` (staging) is a second project and `payments` stays prod (orchestrator ruling: only the signed bundle switches the connector to non-prod, D2.4).
3. Named test edit (orchestrator): the live test uses `https://localhost/ready` (Caddy's internal cert is for localhost, not 127.0.0.1).
4. **Security:** APPROVE (narrow review). Measured: T14 16 passed incl. the live stack (`down -v`, `init-secrets`, `up`, `/ready` 200); ee 673 passed, 1 skipped before the URL fix. The ZAP exit item is covered by the CI `security / zap-api` job.
5. Founder by phone (24 Oct): start T14, keep tokens low, update call after 45 minutes.

**Next:** T15 (hostile review of the M2 diff, security at leader tier), then T16 (gate run, demo incl. step 11), then T17 (quickstart and M2_DONE.md). Wait for the founder before T15.

## M2 T13 (24 Oct 2026): done

1. Tests: `1abffaa` (first cut), `52fbbac` (full bodies; the first cut's 16 pg tests were sentinel-only stubs and were rewritten before the build).
2. **Web (`ee/web/src`):** browser key enroll (WebCrypto Ed25519, non-extractable, IndexedDB), pending list, approve/deny signing `agg/remote-approval/v1` over Python-identical canonical bytes (non-ASCII escaped as `\uXXXX`, `.0` on approved_at/not_after). Approve hidden on prod; deny allowed. New `ee-web` CI job (lint, build, vitest).
3. **Server:** `GET /api/v1/escalations` (session, RLS, pending only, strict CSP); the approvals route takes only a signer token or a session plus CSRF (device tokens refused: the T12 named limit is lifted); three-way identity binding (authenticated user == payload user_id == signing key's registry owner); `POST /api/v1/signer-links` with `kind=browser` (proposal-only).
4. **Security:** round 1 CHANGES (CRITICAL: the named-edited `test_device_key_approval_refused_server` never seeded the device key, so it passed on "key not found"; HIGH: no key-owner check, so bob's session could submit carol's signed envelope). Both fixed inline by the orchestrator; round 2 APPROVE. Review tests: `ee/tests/test_m2_t13_review.py`.
5. **Trade-offs (for the founder):** the orchestrator made the signing.ts escape fix and both round-1 fixes inline instead of spawning builders (token budget). The final local full-suite run was killed by the harness for low memory, so the last full numbers are from before the 2-line fix (ee 656 passed, 1 skipped; connector 2089 passed, 1 skipped); after it, the T12, T13 and review tests passed 40/40; CI runs the full suites. No founder-proxy rulings were needed.

**Next:** the founder decides on T14 (compose: bundle-signer secret, carol, payments-staging). Founder actions: rotate the Bolna key (exposed once in session output); send Navrina the blurb plus an intro ask; 5 discovery calls.

## M2 T12 (24 Oct 2026): done; T13 tests committed

1. Tests first in `ed57bfa` (T12) and `1abffaa` (T13, 14 pytest and 32 vitest; build not started).
2. **Connector (TCB):** `approval.apply_external` re-verifies the registry chain against `pinned_root.json` on every call (ruling A precedent); checks the D5.6 field set, kind matrix, prod refusal for every kind, `policy_sequence`, `not_after` plus 2 min grace, a persisted nonce (`seen_nonces.json`, recorded only after the signature verifies), operator exclusion and `(iss, sub)`/`user_id` dedup; nothing runs without at least one valid approval. Managed `approve()` returns `managed_refused` unless the signed bundle sets `approval.local_fallback`. **Skew:** `sync/process.py` records the HTTP `Date` per reply in `server_time_state.json`; above 2 min, or with no record in managed mode, remote approvals are refused (denies apply) and `clock_skew` is alerted. Escalation upload is scrubbed (threat 19).
3. **Server:** `POST /api/v1/sync/escalations`, `GET /api/v1/sync/decisions`, `POST /api/v1/sync/escalations/{escalation_id}/approvals`; migration `0010` (user_id text; alg NOT NULL kept with default).
4. **Security:** round 1 CHANGES (skew used `approved_at`; in-memory nonces; KeyError not fail closed), round 2 CHANGES (nonce burned before signature check; zero approvals executed on non-dual), round 3 APPROVE. Named limits: the approvals route accepts device tokens until the T13 build (M2_BASELINE 5b); the 0010 downgrade deletes non-uuid approval rows (ADR 0001 note). Orchestrator test edits, all approved: `_build_registry` (fingerprint `org_id:` prefix, optional `sub`), `test_distinct_iss_sub_required`, `_setup_managed_workspace` writes `server_time_state.json`.
5. **Founder ruling 7 (product review):** T16 adds demo step 11 (evidence export of the step 5 action, verified offline); T17 shrinks to a quickstart plus `M2_DONE.md`. New agent `product-manager` (Fable 5.1 high) joins every plan with lead-architect.
6. Measured: connector 2089 passed, 1 skipped. ee (pg) 638 passed, 1 skipped, 11 xfailed (T13). Semgrep: no new findings (opentelemetry upgraded in `.venv`; upgrade semgrep for a clean fix). gitleaks clean with the T12 fixture ignores.

**Next:** T13 build. Decide first: the approvals route takes signer-assert and user-session (CSRF) auth and refuses device tokens; add `GET /api/v1/escalations` (route-freeze exception); add an `ee-web` CI job running vitest, lint and build. Founder: send Navrina the blurb plus an intro ask; start 5 discovery calls.

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

## M2 T11 (23 Oct 2026): done

1. The tests were committed first in `0ed4ff2`.
2. **Server:**
   - Device-token `POST /api/v1/sync/audit`: batch, all-or-nothing, 1 MiB and 1000 records (413).
   - `POST /api/v1/sync/checkpoint`: `agg/audit-head/v1` signed by the device key. `upload_seq` must be exactly +1, and a repeat or concurrent equal seq gets 409. Truncation and session_missing raise alerts, and a fork is quarantined.
   - Migration `0009` adds 2 SECURITY DEFINER functions, `project_org_lookup` and `sweep_org_ids` (agg_app EXECUTE only), plus `projects_owner_select`.
   - `agg-cp audit verify --project` runs as agg_app under RLS.
   - `device_silent` is server-side: the lifespan task runs `sweep_all_orgs` every 60 s (per-org `app.org_id`, advisory lock, a SAVEPOINT per insert).
3. **Connector:**
   - `sync.audit_upload` is lazy-imported from `run_once`, managed only. A failure is logged and never blocks escalations.
   - Managed-mode retention deletes nothing locally (fail closed).
4. **Root cause of the old ee Windows ReadTimeouts:** the test servers used `subprocess.PIPE` and never read it, so the pipe buffer filled and the workers blocked. The fix is `DEVNULL` in `m2_sync_server.py`, `test_m2_t7_signer.py` and `test_t10_multiworker.py` (frozen; a named exception in M2_BASELINE section 3).
5. **Security:** round 1 CHANGES (1 HIGH: the sweep saw no rows under RLS), round 2 APPROVE. Measured: connector 2040 passed, 1 skipped. ee 618 passed, 1 skipped, **0 failed**. lint-imports is clean, and Semgrep found nothing new.

**Follow-ups (not blockers):**
- (a) Managed-mode retention keeps every local record. Add deletion of fully acknowledged sessions (`cursor_acknowledges_session`) with a tested size bound.
- (b) D3.3 says a repeat or skip is "refused and alerted". It is refused with 409 but writes no `sync_alerts` row. Decide whether to add one.
- (c) The test servers now discard stdout and stderr; consider logging to a temp file for diagnostics.

**Next:** T12, tests first. T12 must consume `_enforced_approval`.

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
