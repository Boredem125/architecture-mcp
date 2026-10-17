# Reviews of the M1 plan (`M1_PLAN.md`)

Each reviewer owns one section. Lead-architect folds the must-fixes into `M1_PLAN.md` and records how in "Resolution" at the bottom.

## Security review

Reviewer: security-engineer, 18 Oct 2026. Sent by message (their session was read-only); recorded verbatim by lead-architect.

**Verdict: APPROVE WITH CHANGES.** 10 must-fixes, to fold in before T0b.

### Must-fix
1. D2.3: the key home must be write-, delete- and rename-denied as well as read-denied. That covers Write/Edit/shell and the seeds, pins.json and the workspace-id map. If an agent can write pins.json, it can pin its own key and D3 is defeated. write_outside is a configurable trigger, so this has to be a non-removable rule, not that trigger.
2. D2.4: rotate keys, do not migrate them. SEC-01 showed in-tree seeds were readable by the agent, so every pre-M1 seed counts as exposed. Generate a new key, pin it, and record the old one as `retired_at=T` (its old records verify as legacy). Audit `key_rotated`. Never copy an in-tree seed out.
3. D2: if the key home cannot be resolved (no LOCALAPPDATA/HOME, unwritable), fail closed: no signing, and approvals invalid. Never fall back to `.sandbox/state/keys`. Add a non-frozen test that unsets SANDBOX_KEY_HOME (with the OS dir monkeypatched to tmp) for the default path, and one for the unresolvable case.
4. D2.3, shell: the deny must hold against `$LOCALAPPDATA`, `%LOCALAPPDATA%`, `$env:LOCALAPPDATA`, `~`, 8.3 short names, case variants, and an in-tree symlink or junction to the key home read with an allowlisted `cat`. Shell path args need resolving like Read's. Each case must end in deny or escalate, never allow. Tests go through `pre_tool_use`.
5. D3.1: pins must not be TOFU on first sign. Today `_load_or_create_key` silently creates a key for any new reviewer_id, so "pin at key creation" means any new name gets a valid pin. Pinning needs an explicit, audited enrol step (`key_pinned`). Pins are never overwritten in place; rotation is explicit, and an approval is checked against the key valid at `approved_at`.
6. D3.2: the verifier picks the domain tag and signed-field set from context (kind + sig_v) in code, never from the record. Today `verify_record` trusts `record["signed_fields"]` (signing.py:100), so a record that claims signed_fields=["request_id"] verifies with decision and command unsigned. For sig_v=1 the field set is fixed per kind, and new decisions reject any record without sig_v=1.
7. D1.4: the 400 check must be pure string (NUL, a length cap below 4000, reject non-absolute input rather than abspath'ing it against the server cwd), with no stat. That is the only way R5 (test_api_robustness.py:108, monkeypatched stat on a 4000-char root) passes unchanged with "no FS access on unlisted input". After a match, the route uses the stored configured root, never the request string. Also restate SEC-10 condition (2): `serve` binds loopback by default; non-loopback needs an explicit flag; add a test.
8. D5.2: the SECURITY DEFINER function gets `SET search_path = pg_catalog, pg_temp`, `REVOKE EXECUTE FROM PUBLIC`, GRANT to agg_app only, and an owner that is not a superuser. RLS policies use `NULLIF(current_setting('app.org_id', true), '')::uuid`, so a reset GUC gives 0 rows rather than an error.
9. D5.3: row triggers do not fire on TRUNCATE. Add a BEFORE TRUNCATE trigger and REVOKE TRUNCATE. State the limit: agg_owner can still drop the table, and the external anchor is SEC-15/M3.
10. D5.4/D5.5: SameSite=Strict drops the cookie on the IdP's cross-site redirect back to the callback, so state/nonce/PKCE are lost and someone will "fix" it with None. Use a separate short-lived Lax login-transaction cookie and a Strict `__Host-` session cookie. Add an absolute session lifetime (e.g. 12h) on top of the 30-min idle, and server-side invalidation at logout. The setup code needs at least 128 bits of entropy, a constant-time compare and a rate limit. Note that `migrate` prints it into `docker logs`.

### Should (not blocking)
- Restrict OIDC discovery and JWKS fetches to https only, and refuse private or link-local addresses unless allowlisted (the Keycloak demo would be). This pulls the SEC-20 egress guard forward.
- Pin entries should record the workspace root, with a mismatch refused.
- ADR 0007 must state the custody limit honestly: the key home stops the hook-governed agent, not other code running as the same OS user, including an approved `python` command. DPAPI does not change that; passkeys (M3) do. The evidence pack should also say standalone dual control means two keys, not provably two humans.

### Frozen-test exceptions: signed off by node id as listed, on these conditions
- (a) The conftest autouse fixture sets only SANDBOX_KEY_HOME, to tmp; nothing else.
- (b) R5 and `test_t0_hotfix::test_sec04_agent_token_403_on_every_connector_route` pass byte-unchanged.
- (c) `test_evidence` line 127 keeps the no-seed-bytes check and adds the >=3 seeds check.
- (d) Tests that start a subprocess with a hand-built env (e.g. `test_posttooluse_fallback`) get no SANDBOX_KEY_HOME. If any of them resolves a key home, that falls under the "stop and list" rule, not a silent edit. CI should point LOCALAPPDATA/HOME at an empty tmp dir and assert it is still empty after the run.

### Answers
- Q3: D2 is acceptable as the M1 blocker fix only with must-fixes 1-4. D1's "400 before the allowlist" is fine provided it is input-only (must-fix 7); a 400 on string shape leaks nothing about the filesystem.
- Q4 (M1 items missed): only the SEC-10 loopback-default condition (in must-fix 7). SEC-05 standalone, SEC-07, SEC-10 and SEC-13 are otherwise covered.

## QA review

Author: qa-engineer, 18 Oct 2026, at `main` = `8681b1f` (M0 T4 uncommitted in the checkout). Review only: no code or tests changed.
Method: read `M1_PLAN.md`; grep of every test that calls the API, touches keys or seeds, or hand-builds signatures; `M0_BASELINE.md` sections 7-8 (T2 CI counts).

### Verdict: APPROVE WITH CHANGES

The test strategy takes in REVIEW_QA section 5 correctly: fake IdP, injected clock plus lint, `postgres:16` with no SQLite, a `pg` mark that fails if skipped in CI, `--workers 4`, the ee-absent import test, and tests first as strict xfail. Fix the 8 items below before T0a. Items 1-3 are frozen-file questions: settle them now, not when a test goes red.

### Must-fix

1. **The named-exception list misses one file (D1).** `tests/security/test_api_auth.py::test_approver_reaches_approver_and_agent_routes` (R4, rewritten in M0 T4) expects the approver to get 200 on `status` and `pending` with `root=tmp_path`, and approves. With no listed roots that becomes 403. Add it to the list (setup only, +1 line).
   Not on the list, but now vacuous: the `test_api_robustness.py` route walkers (`no_route_crashes`, `junk_values`) send junk `root` values. Under D1 every connector call stops at 403, before any handler. Don't edit those files: add a **new** fuzz test with a listed root, so junk `request_id`, body and query values still reach the handlers.
2. **R5 against D1.3/D1.4.** R5 sends `root = "x" * 4000` and expects 400. D1 promises 400 only for input that "cannot be normalized (NUL, too long)", and gives no FS access on unlisted paths. So R5 stays green only if the length limit is **below 4000**. With a 4096 or `PATH_MAX` limit, R5 gets 403 and fails. Write the exact limit into D1.
   R5 also stops testing what it was written for: the ENAMETOOLONG `OSError` mapped to 400. Add a new test: a **listed** root whose `stat` raises `OSError` gets 400, not 500.
3. **D2/D3 against frozen tests that use private helpers or exact check names.** None of these is on the list:
   - `test_tool_governance.py::test_records_signed_before_fingerprint_was_added_still_verify` (lines 200-211). It calls `signing._load_or_create_key(layout, "cli")`, `_canonical(rec, fields)` and `_SIGNED_FIELDS`, and expects an **untagged** record to pass `verify_record`.
   - `test_evidence.py::test_forged_record_signed_by_non_folder_key_is_flagged` (226-237). It uses `_canonical` and `_SIGNED_FIELDS` and asserts the failed checks are exactly `== ["signer_is_folder_key"]`.
   - `test_evidence.py::test_dual_control_with_a_foreign_approval_is_flagged` asserts exactly `["dual_control"]` and the detail "not signed by the folder's key".
   - `test_tool_governance.py::test_grant_signed_by_another_key_is_ignored` and the `test_evidence` foreign-approval test use two workspaces with the same reviewer id (see item 4).

   Pick one, in ADR 0007. Either (a) a design constraint: `verify_record` keeps accepting legacy records, the 3 private helpers keep their signatures and meaning, and the evidence check names and detail text stay as they are, with any new check added under a new name only when it fails. Or (b) list these 4 nodes now with the allowed change. I recommend (a).
4. **Pin scope is undefined.** "`pins.json` in the key home" can be read as one pin file per user. Two workspaces both have reviewer `cli` (or `alice`), so a per-user file either collides or lets one workspace's key approve in another. Specify pins and seeds **per workspace id**. Required test: two workspaces under one key home, same reviewer id, different keys, and a cross-workspace approval is refused.
   Also decide what happens when `.sandbox/` (with its workspace id) is copied or cloned into a second folder: the two folders would share keys.
5. **Key home with a minimal environment, and migration on the hook path.**
   - `test_posttooluse_fallback.py` starts `hook_eval` with an env of only `PYTHONPATH`, `SYSTEMROOT` and `SYSTEMDRIVE`. The planned conftest autouse fixture does not reach that child, and `LOCALAPPDATA` and `HOME` are missing there. That is how `%SystemDrive%` got written into the repo (M0 T11). Key-home resolution must never fall back to a relative path or the cwd, and must fail closed. Test it with that minimal env, plus `git status --porcelain` clean.
   - The T0 fixture writes a fake `.sandbox/state/keys/a.seed` (zeros) that matches no reviewer. Migration must not move or delete seeds like that inside `pre_tool_use`. Otherwise the glob cases in `test_t0_hotfix.py` (`cat .sand*/state/keys/*.seed`) depend on a file that has gone. `test_t0_hotfix.py` stays unchanged and green: say so in D2.
6. **`sandbox serve --root` across the uvicorn import string.** `serve` runs `uvicorn.run("sandbox.api.app:app")`, so `create_app(connector_roots=...)` arguments never reach the worker. Roots must travel through the environment. TestClient tests can't see this, so add one subprocess test against a real `sandbox serve --root X` on loopback: X gives 200 and any other path gives 403. With `--workers` greater than 1 too.
7. **Make the gate precise enough to run once.**
   - (a) **Say which Windows.** Local `.venv` has 1 skip (symlink). CI `windows-latest` runs the symlink test: 708 passed and 3 "skipped" in JUnit at `79f94e4`, and those 3 are the xfails. Freeze one figure per environment.
   - (b) **Freeze the Linux skip set by node id, not by count.** Linux skips 21 more than Windows, and nobody has broken that down (no token for the artifacts). Without the list, a test that starts skipping on Linux passes the gate. T0a pulls `junit-pytest-Linux` and freezes the skip ids.
   - (c) **`ee/` suite:** freeze its node-id set per task in `M1_BASELINE.md`, as for the connector suite. "0 failed, 0 skipped" alone lets tests vanish. Freeze the coverage command too: tool, `--branch` or not, source `ee/src/agg_cp`, omit list empty.
   - (d) **RBAC and IDOR "100% of routes":** take routes by walking the router recursively, not only OpenAPI. This FastAPI wraps included routers in `_IncludedRouter` objects whose path is empty (found in M0 R7), and OpenAPI omits WebSocket and `include_in_schema=False` routes. Assert the walked set equals a frozen route list.
   - (e) **Positive controls, or these tests are vacuous:**
     - IDOR: org B's own session gets 200 on the same id that org A gets 404 on, with one seeded object per route type.
     - Zero rows with no `app.org_id`: seed rows in every table first, and show they are visible with the org set.
     - Pooled connection: show it is the same physical connection (same `pg_backend_pid()`).
     - Clock lint: show it fails on a planted `time.time()`.
8. **The demo is not headless yet (T14).**
   - Steps 1, 4 and 5 can be scripted.
   - Steps 2-3 need the Keycloak code+PKCE login scripted: httpx following the login form, or a Keycloak test client. Decide which; Playwright needs browser downloads, so put them on E:.
   - The setup code must be machine-readable, for example one JSON line in the `migrate` logs.
   - Step 5 needs an `admin_audit` verify command or endpoint, and no task owns one.
   - Gate item 3 (M0 E2E steps 1-7) includes steps 4-5, which use the interactive `sandbox watch`. Specify `sandbox approve <id> --reviewer alice/bob` instead. I could not run them headless at the M0 baseline either (`M0_BASELINE.md` section 5).
   - T6, T11 and T14 need Docker. With the disk image on C:, the local demo is blocked until the founder moves it (Risk 1).

### Answers to the lead's questions

1. **Verdict:** approve with changes, items 1-8 above.
2. **Named list complete?** No. Add R4 (item 1). Decide the 4 signature and evidence nodes in item 3. Checked, no change needed:
   - `test_signing_connector.py`, `test_policy_versioning.py:100-102`, `test_aiuc_gaps.py:105`, `test_dual_control.py:75-77,131`: they sign with `sign_record` and verify with `verify_record`, so a tagged and pinned implementation passes them unchanged.
   - `test_t0_hotfix.py` SEC-04: auth comes first, so it stays 403.
   - `test_api_auth.py` R1/R2: 401 comes before the allowlist.
   - `test_m0_routes.py`: the `app` fixture is already on the list, and covers R3's approver positive control.
3. **Frozen enough to run once?** Not yet: item 7. The Phase A count per task, frozen in each tests-first commit, is fine.
4. **Demo scriptable headless?** Partly: item 8.

## Resolution (lead-architect, 18 Oct 2026)

All 18 must-fixes are folded into `M1_PLAN.md`, tagged S1-S10 (security) and Q1-Q8 (QA) where they land.

1. **Accepted as written:** S1-S4, S6-S10 and Q1-Q8. The three security "should" items are in too: https-only discovery and JWKS with no private addresses (D5.4), the workspace root in each pin (D3.1), and the custody limit in ADR 0007 (D2.7).
2. **S2 + Q5:** rotate, never migrate. An in-tree seed is never copied, moved or deleted, so `test_t0_hotfix.py` stays unchanged.
3. **S6 + Q3:** field sets come from code. Legacy records verify only against a code-defined list of historical `_SIGNED_FIELDS` sets. Q3 option (a), so private helpers and evidence check names stay stable.
4. **S5 (the one disagreement), settled without the founder.** The lead proposed first-use pins from human surfaces only. Security accepted on 3 conditions: hook and MCP paths cannot pin; `key_pinned` is audited and alerted, pins are never overwritten, and `keys.enrol: explicit` is tighten-only; a "new-key approval" flag in verify and evidence. ADR 0007 records strict enrolment as rejected.
5. **Q1:** the R4 row was added to the named list after security's sign-off. It is the same one-line setup change. Security confirms it at T1.
