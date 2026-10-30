# T12d d4 security review -- registry read route, link iss/sub, bundle_signer line, CLI d3 residue

Reviewer: security-engineer (leader tier, Opus 5.5).
Scope: uncommitted d4 diff on top of `ed26bff`: `ee/src/agg_cp/sync/signer.py`, `ee/src/agg_cp/migrate.py`, `src/sandbox/cli/sync_cmds.py`, and the test edits in `tests/security/test_m2_t12d_signer_cli.py`, `ee/tests/test_m2_t12b_e2e.py`, `ee/tests/test_m2_t12d_genesis.py`, `ee/tests/test_m2_t12d_d0.py`, `ee/tests/test_t9_routes.py`. Spec: the d4 row and the T12d exit check in `T12B_PLAN.md`, ADR 0011, rounds 1-3 of `T12D_D3_SECURITY_REVIEW.md`.
Verdict: **CHANGES REQUIRED** (D4-1 CRITICAL, D4-2 HIGH; the rest MEDIUM or LOW).
Read-only review: no product or test file was edited, stashed or reset.

Measured (Windows, `.venv`, Docker pg):
- `tests/security/test_m2_t12d_signer_cli.py`: 63 passed, 1 skipped (the POSIX mode test), 1 xfailed (`test_d4_link_response_contains_iss_sub`).
- `ee/tests/test_m2_t12d_genesis.py`, `test_m2_t12d_d0.py`, `test_t9_routes.py` and `test_m2_t12b_e2e.py`: 66 passed, 0 skipped.

All green, but green does not mean correct here: D4-1 is exercised by a passing test, and D4-2 by a test that checks only the exit code.

Scanners on the 8 changed files:
- Semgrep (p/python, p/secrets): 2 findings, both `insecure-file-permissions` on `os.chmod(signer_dir, 0o700)` in test fixtures (`test_m2_t12d_signer_cli.py:112, :989`). These are false positives: 0o700 is tighter than the rule's suggested 0o644.
- gitleaks dir: no leaks.
- trivy fs (secret scanner): clean.

## What holds

- **Orchestrator reverts are complete.** `git diff ed26bff -- src/sandbox/cli/sync_cmds.py` has no hunk in `_fetch_escalation` (`:293-307`, dict only, any list gives None and "not found") or in the `fp_v` refusal and binding-fingerprint check of `signer_approve` (`:617-623`, `:675-682`). Both are byte-identical to `ed26bff`. The only `signer_approve` change is the key loading (D4-2).
- **No other check is relaxed in the CLI.** R2-4 (the typed set check is now unconditional in both modes), R2-5 (`--add` of an existing key refused), R2-6 (co-sign trust set is `prev_admins | cur_admins`, as in `verify_chain`), R2-7 (`--yes` needs `--confirm-identity`; genesis stores the locally computed root fingerprint, never a server value), F11 (`-` reads stdin) and F14 (`--admin` with more than one `--add` refused) all tighten. Residue in D4-6.
- **`GET /api/v1/sync/signer/registry`** (`ee/src/agg_cp/sync/signer.py:1345-1398`): the org comes only from the token row (`signer_token_lookup`); there is no org parameter, so no IDOR. No Bearer gives 401, a scope error gives 403. It is GET only and writes nothing, so the `pending_link` widening in `check_signer_token_scope` (`:126`) is read-only. `get_chain` also filters `WHERE org_id = %s` (defence in depth under RLS).
- **The RLS `set_config(..., false)` cannot leak across requests.** Every route opens its own `psycopg.connect` and closes it in `finally`; there is no pool in `ee/src` or `ee/deploy` (no `ConnectionPool`, `psycopg_pool` or pgbouncer). The session value dies with the connection. It is the same pattern as `:195`, `:331`, `:354` and the candidates route. Named limit: if a transaction-mode pooler is ever added, every session-level `set_config` in this file must become transaction-local first.
- **`migrate.py` prints no private material.** It prints only `bytes(verify_key).hex()` and its sha256. The seed and the file bytes are never printed, and the swallowed exception is not echoed. It fails closed downstream: without the line the CLI has no `--bundle-signer-key` and refuses, and a wrong key is refused by the genesis route's R1 equality check (`signer.py:1101-1117`).
- **Link `iss`/`sub`**: read from `users` by the consumed link's `user_id` and `org_id`, so it is the code holder's own identity (stub ruling 3).

## Findings

**D4-1 CRITICAL -- `/signatures` accepts a v1 genesis, bypassing the ADR 0011 genesis gate; the moved T12b e2e test depends on it.**
`ee/src/agg_cp/sync/signer.py:697-773` and `store_signer_signatures` (`:359-381`) pass any registry envelope to `store_registry_version`. That function refuses a v1 only when a v1 already exists (`registry.py:58-76`). For an org with no registry, a `pending_link` token posts a self-signed v1 that lists its own key and gets 200. There is:
- no genesis code (ADR 0011 option B, the host-access bootstrap authority);
- no org `admin` role check (step 3);
- no `iss`/`sub`/`user_id` check (step 4);
- no `bundle_signer` equality check (R1). The attacker picks the bundle-signer key and can then sign policy bundles for every connector that pins that root;
- no expiry rule, no single-key rule, no advisory lock and no `admin_audit` row.

That is option A, which ADR 0011 rejected ("any org admin who links a key can race to publish the root first"). It is worse than A, because `POST /api/v1/signer-links` needs only a session (`role="session"`), not admin.
Evidence: `ee/tests/test_m2_t12b_e2e.py:336-362` now does exactly this. The fixture user `alice` has no role binding. The test gets a `pending_link` token and POSTs a three-key genesis to `/signer/signatures` with no genesis code, and asserts 200. It passes.
The hole was latent since d2 (`c786c5f`; the d2 review did not test v1 on `/signatures`). d4 turns it into the tested path.
Fix (backend, tests first by qa):
- In the `/signatures` route, refuse any registry envelope with `payload.version == 1`, and any post for an org with no stored version, with 409 `genesis_only_via_genesis_route`. Keep the `second_genesis` alert for a v1 when v1 exists.
- Do not touch `store_registry_version`; the genesis route uses it.
- ee pg tests: a `pending_link` token and a confirmed token from another org each post a v1 to `/signatures` for an org with no chain. Each gets 409, no `key_registry_versions` row and no `approver_keys` row.

**D4-2 HIGH -- F13 is not closed: an approval made with the linked key carries `user_id ""`.**
`sync_cmds.py:579-593` loads the link key and sets `user_id` from `link.json`, but the value is never used. `_build_and_sign_envelope` (`:404`) takes `user_id` from `vs.registry`, which is None on this path, so `reviewer_id` and `user_id` are `""` and `registry_version` falls back to 1.
The connector refuses it (`approval.py:484-486`, H1 `payload_user_id != registry_user_id`). That fails closed, so no property is weakened. But "a linked key that approves" (the F13 condition for the d4 exit) does not hold.
`test_d4_f13_approve_reads_linked_seed` passes because it checks only the exit code.
Fix:
- Pass the resolved `user_id` into `_build_and_sign_envelope`. Prefer the verified registry entry for `kid` when `vs` is available, and use `link.json` only when there is no workspace.
- Do not drop `vs` when `_load_signer_key` fails. Load the link key and look it up in `vs.registry`.
- Check that `link.json` `key_id` equals the seed's `kid`.
- `signer deny` gets the same key resolution (today it still requires a workspace key).

**D4-3 MEDIUM -- the compose stack never prints the `bundle_signer` line.**
`ee/deploy/compose.yml:123-180`: `migrate` and `migrate-demo` mount only `pg_owner_url` and do not set `AGG_BUNDLE_SIGNER_KEY_FILE`. So `migrate.py:233` skips the line, and the out-of-band source from stub ruling 1 does not exist on the stack the exit check names.
Fix: mount the `bundle_signer_key` secret read-only into the job or jobs that print `genesis_code`, and set the env var there. This widens the holders of the private key only to a one-shot, read-only, no-network-egress container on the same host and operator, which is acceptable.

**D4-4 LOW -- `migrate.py` has its own key parser and fails silently.**
`migrate.py:236-254` copies `bundles._load_bundle_signer_key`.
- Call that function, so the printed key is the server's key by construction.
- When the env var is set but the key cannot be loaded, print `{"event":"bundle_signer_error","reason":"unreadable"|"bad_format"}`, with no path, bytes or exception text, and exit non-zero. Today an operator gets no line and no reason.

**D4-5 MEDIUM -- the T12d exit check is not met.**
- `demo.py` step 2 has no registry flow (ruling 6).
- The d4 e2e (`test_d4_e2e_step2_genesis_v2_v3_through_routes`) covers second genesis, code reuse and a `pending_link` post without its own key. It does not cover the frozen step 2 negatives: a browser-key registry signature refused, a threshold-1 v4 refused (floor) and N1 (a substituted key_id not signed).
- v2 has threshold 1, but frozen step 2 says carol's v2 has threshold 2.
- Link codes and the genesis code are DB inserts, not the web route and `migrate.py`. That is acceptable for an ee test, but not for the demo.

**D4-6 LOW -- d3 residue.**
- R2-7 bound: `sync_cmds.py:1638-1656` allows `threshold <= max(len(keys)+1, 2)`, not `<= distinct admin user_ids` as round 2 asked. The server's `verify_chain` rejects an unmeetable threshold, so this fails closed, but the CLI signs and writes a version that can never be stored. Fix the bound and give `test_f10_sign_registry_threshold_flag` two admins (round 2 instruction).
- The genesis identity block is still printed only without `--yes` (round 1 F12: always print it).
- `_get_link_signer_token` still swallows the reason (`:1166`).
- `root_fingerprint` is written with `write_text`. It sits in a 0700 dir, so this is acceptable, but use the `_write_seed_excl`-style helper with mode 0o600 for symmetry.

**D4-7 LOW -- the link route returns `""` for a missing user row** (`signer.py:631-632`). Return 500 `internal_error` instead. Never hand the CLI an empty identity (ruling 5 makes the CLI refuse it anyway).

**D4-8 LOW -- the grep test is a regex over text** (`test_m2_t12d_genesis.py:1640-1656`). It matches comments (the reason for the 586 rewording) and misses an aliased import (`import ... as s`). Make it an `ast` walk: no `Call` whose func is the name or the attribute `store_registry_version`, and no import of that name.

## Rulings on the test edits

1. **`tests/security/test_m2_t12d_signer_cli.py::test_d4_f13_approve_reads_linked_seed` -- APPROVED** (the fixture change).
   - A list never was a valid GET-by-id response: `_fetch_escalation` returns dicts only, and the restored `fp_v` refusal needs fp_v 2 and a matching `_binding_fingerprint`. A valid v2 record is the only fixture that reaches the seed-location check. The assertions are unchanged.
   - Condition (qa): add assertions on the posted `/approvals` body: `key_id ==` the linked kid, `user_id == "u-f13"`, and a valid signature with the linked public key. They fail today (D4-2) and pass with the fix.
   - Make the test hermetic: `monkeypatch.chdir(tmp_path)`, so `FolderLayout(".")` never sees the repo.
2. **`ee/tests/test_m2_t12b_e2e.py::test_e2e_remote_approval_path` (`:336-362`, `:586`) -- REFUSED as written.**
   - It does not go through the genesis route. It POSTs v1 to `/signer/signatures` with a `pending_link` token, no genesis code and no admin role, which is D4-1.
   - No raw DB write of registry rows: the only INSERTs are users, enrollment codes, role bindings, signer links and setup codes.
   - The `:586` rewording is comment-only and hides no call. It was needed because the regex matches "store_registry_version (ADR" in prose (D4-8).
   - Required: grant alice `admin`. Mint a genesis code. POST a single-key genesis (alice, `--approver` roles, the server's bundle signer) to `/signer/genesis`. Then POST v2 adding bob and carol to `/signatures`, signed as `verify_chain` requires. Reuse the `_d4_*` helpers. The rest of the test is unchanged.
3. **`ee/tests/test_t9_routes.py` (frozen) -- APPROVED.** One line added to `_M2_T12D_ROUTES`, nothing removed; working-tree sha256 `ba142d908b7986a9162a93f728bda732dee07942e3c1bd48139af02a87b0c464` (HEAD `026ee5e3eec1d64e8bc6e563362818a6271d42b6e3c3423760ac3cd0dbd4126c`). M2_BASELINE.md section 3 row:
   `| ee/tests/test_t9_routes.py::test_frozen_route_set | T12d d4 | _M2_T12D_ROUTES adds (GET, /api/v1/sync/signer/registry), nothing removed | security (d4 leader review, APPROVE of this edit; T12D_D4_SECURITY_REVIEW.md) |`
   Update `M2_FROZEN_MANIFEST.sha256` line 35 to `ba142d90...c464`.
4. **`ee/tests/test_m2_t12d_d0.py::test_d0_3_diff_shows_bundle_signer_and_key_field_changes` -- APPROVED** (marker removed).
   - It passes for the right reason: the d3 F5 generic diff renders the `bundle_signer` `public_key`, the roles change and the `expires_at` change, so the hostile diff differs from the no-op diff.
   - The test only checks inequality. The per-field d3 tests (F5) pin each field.
5. **`tests/security/test_m2_t12d_signer_cli.py::test_d4_link_response_contains_iss_sub` -- REPLACE, do not delete.**
   - No ee test asserts that the server's link response carries `iss`/`sub`, so it is not covered elsewhere.
   - CLI test, replacing it: with a 200 response lacking `iss` or `sub`, or with either empty, `signer link` exits 1 with "iss" (or "sub") in the output and writes no `link.json`. The seed may stay: it is reused on re-link, and a server-side `pending_link` binding without local metadata is harmless.
   - Product: link refuses on missing or empty `iss`, `sub`, `org_id` or `user_id` before writing `link.json`.
   - New ee pg test: `POST /signer/link` returns `iss == users.oidc_issuer` and `sub == users.oidc_subject` of the linked user.
6. **Demo step 2 -- stays in d4; it does not move to T16.**
   - The d4 row says "`ee/deploy/demo.py` step 2 headless through routes", and its done-when is "Exit check holds on the compose stack incl. the step 2 negatives".
   - T16 is a one-shot frozen gate run (M2_PLAN freeze rule). Finding that the registry flow fails there would cost the gate.
   - `demo.py` numbers its functions differently from the frozen list (its `step2` is setup plus admin). d4 adds the frozen step 2 registry flow, via the CLI commands or routes only: genesis through `/signer/genesis` with the codes parsed from migrate output, v2, v3, and the frozen negatives. Its placement in `demo.py` is the builder's choice.
   - Moving it needs a lead-architect amendment to T12B_PLAN. Security does not sign the d4 exit without it.

## Required before commit

- D4-1 fixed with tests, and ruling 2 applied (the T12b e2e goes through `/signer/genesis`).
- D4-2 and ruling 1's assertions.
- Ruling 5: the CLI refusal, the ee link test and D4-7.
- D4-3.
- Rulings 3 and 4 may be recorded now.
- D4-4, D4-6 and D4-8 may land in d4 or d5.
- D4-5 and ruling 6 are the d4 exit, not this commit.
- Re-review at worker tier by node id. D4-1 is a new attack class on the genesis gate, so the leader confirms its closure.

## Round 2 (30 Oct 2026)

Reviewer: security-engineer (leader tier, Opus 5.5). Read-only: no product or test file was edited, stashed or reset.
Scope: the uncommitted fix diff on top of `ed26bff` (`ee/src/agg_cp/sync/signer.py`, `ee/src/agg_cp/migrate.py`, `ee/deploy/compose.yml`, `src/sandbox/cli/sync_cmds.py` and the 3 test files), with qa removing XPASS markers in parallel.
Verdict: **CHANGES REQUIRED.** **D4-1 is CLOSED** (this file may be pushed). Three items block the commit:
- R2-1: a frozen-era test is red, and the `/signatures` second-genesis alert is lost.
- R2-2: the new `_refresh_registry_chain` recreates a missing or corrupt high-water mark.
- R2-3: the F13 test cannot pass with a correct product.

Measured (Windows, `.venv`, Docker pg):
- ee d4 files (`test_m2_t12d_genesis.py`, `test_m2_t12b_e2e.py`, `test_t9_routes.py`, `test_m2_t7_signer.py`, `test_m2_t12d_d0.py`): first run 6 failed, 104 passed, 1 xfailed.
  - Five failures were strict-XPASS markers. After qa's marker removal they pass (re-run: 5 passed).
  - **`ee/tests/test_m2_t7_signer.py::test_second_genesis_refused_via_route` still fails** (R2-1).
- `tests/security/test_m2_t12d_signer_cli.py`: 71 passed, 1 skipped (POSIX mode), 1 xfailed (`test_d4_f13_approve_reads_linked_seed`, R2-3).
- Full suites:
  - root `tests`: 2345 passed, 7 skipped, 2 xfailed.
  - `ee/tests`: 2 failed, 821 passed, 2 skipped, 1 xfailed.
    - `test_second_genesis_refused_via_route` failed (R2-1).
    - `test_t10_multiworker.py::test_concurrent_role_grants_idempotent` failed. It passes alone, and the d4 diff does not touch role grants, so it is flaky under load.
  - qa's marker state moved during the run: `test_d4_f13_approve_reads_linked_seed` showed FAILED in one run and XFAIL in another (R2-3).
- Semgrep (p/python, p/secrets) on the 8 changed files: 3 WARNING, 0 ERROR. The CI gate fails on ERROR only.
  - Two are the round-1 `insecure-file-permissions` false positives (`test_m2_t12d_signer_cli.py:112, :989`, 0o700).
  - New: `python-logger-credential-disclosure` at `sync_cmds.py:1378`, the debug log in `_get_link_signer_token`. It logs the exception from a failed token request, so no token exists yet. It is a false positive in substance (item 3).
- gitleaks (dir mode, `.gitleaks.toml`) on the changed files and this file: no leaks.
- trivy fs secret scan: clean.

### Item 1: D4-1 closure -- CLOSED

The guard (`signer.py:754-767`) refuses `type == "registry"` with a truthy envelope whose `payload.version == 1`. Every other shape was traced through the code. For `verify_chain` it was also probed with a pure-Python scratch script:

| Shape | Path | Result |
|---|---|---|
| `version` 1, 1.0 or `true` | The guard fires: Python `==` is True for all three. These are exactly the values `verify_chain` accepts as a genesis (probe: 1.0 and `True` pass its `!= 1` test), so the guard and the gate agree. | 409 `genesis_only_via_genesis_route` |
| `version` `"1"` (string) | The guard does not fire. With no chain, `store_registry_version` builds `chain=[env]` and `verify_chain` refuses ("first envelope must be version 1", `registry.py:159`). With a chain, `"1" <= int` raises TypeError, which is wrapped as RegistryError. | 400, nothing stored |
| `version` >= 2, org with no chain | `chain=[env]`, and `verify_chain` refuses any first version other than 1 (probe confirmed). | 400, nothing stored |
| `type` missing, `"Registry"` or any other value | `store_signer_signatures` dispatches only on `type == "registry"`. | `{"stored": 0}`, nothing stored |
| envelope under another key | Only `body["envelope"]` is read anywhere. | nothing stored |
| envelope `{}` or another falsy value | The guard is skipped, and the org check in `store_registry_version` fails. | 400 |
| envelope or payload not a dict (list, string) | `.get` raises AttributeError before any store. | 500, nothing stored |
| confirmed token from another org | `target_org != info["org_id"]` returns 404. `store_registry_version` also requires payload `org_id` == token org. | 404 |

- `store_registry_version` is the only writer of `key_registry_versions`. Its callers are this route and the genesis route (`signer.py:1229`, behind the ADR 0011 gate).
- Tests: `test_d4_1_signatures_refuses_v1_no_chain`, `test_d4_1_non_admin_cannot_create_root_via_signatures` and `test_d4_1_confirmed_other_org_refuses_v1_no_chain`. Each asserts 409, 403 or 404, and no `key_registry_versions` or `approver_keys` row.
- Gap (qa, d5): no test posts a v2 to an org with no chain, or a string or float version. Add one parametrised test.

### New findings

**R2-1 HIGH (blocks the commit) -- `ee/tests/test_m2_t7_signer.py::test_second_genesis_refused_via_route` is red, and the second-genesis alert is lost on `/signatures`.**
- The test (`:1019-1060`) posts a v1 to `/signatures` and asserts 200 (`:1053`). It encoded the D4-1 hole, so the fix correctly breaks it. The full ee suite stays red until the test changes.
- The guard returns before `store_registry_version`. So a v1 posted when a v1 exists no longer writes the `second_genesis` alert, which round 1 asked to keep (threat 22 detection).
- Fix, product (backend): inside the guard, check for an existing version row first.
  - If one exists, commit the `second_genesis` alert (the same INSERT as `registry.py:66-73`) and return 409.
  - Otherwise return 409 `genesis_only_via_genesis_route`.
- Fix, test (qa; security approves this edit by node id):
  - r1 goes through `/signer/genesis` (reuse the `_d4_*` or `_do_genesis` helpers).
  - r2 posts the same v1 to `/signatures` and asserts 409 plus one `second_genesis` alert row.
  - Add the alert assertion to `test_d4_1_guard_signatures_refuses_v1_when_chain_exists`.

**R2-2 MEDIUM (blocks the commit) -- `_refresh_registry_chain` (`sync_cmds.py:351-452`) recreates a missing or corrupt `high_water.json`.**
- When the file is missing or unparsable, `hwm = {}`, and the function writes `{"registry_version": N, "bundle_sequence": 0}`.
- S1 (`verified_state.py:89-91`) defines a missing or corrupt file as fail closed (no approvals). This code turns that state into a fresh floor and resets the bundle floor to 0.
- Attack, step by step:
  1. Delete `registry.json` and `high_water.json`.
  2. The server, or anything that answers the server URL, serves an older chain that still verifies (v2, before the v3 revocation).
  3. `current_version` is 0, so v2 is persisted, and the high-water mark is recreated at 2.
  4. `load_verified_state` accepts it. The revoked key approves again, and an older bundle sequence is accepted again.
- With an intact `high_water.json`, the rollback is refused downstream (`verified_state.py:93`: 2 < 3 gives None). The hole is the self-healing write.
- The founder's named limit "unsigned high_water.json" covers tampering with the file. It does not cover the product recreating it.
- Fix:
  - The floor is `max(local registry.json version, high_water.registry_version)`. Refuse any chain below it.
  - Refuse when `high_water.json` is missing or corrupt (use `_load_high_water`).
  - Never create or rewrite `high_water.json` here; `load_verified_state` ratchets it through `_save_high_water`.
  - Keep `process.py`'s rule: same version with different bytes is refused.
- Tests (qa, written first):
  - (a) Both files deleted, the server serves v2, and the floor was 3: nothing is written, and `load_verified_state` stays None.
  - (b) `registry.json` deleted, hwm 3, the server serves v2: refused.
  - (c) The server serves v3 over a local v2: persisted, and the next `load_verified_state` ratchets the floor.

**R2-3 MEDIUM (blocks the commit) -- `test_d4_f13_approve_reads_linked_seed` cannot pass with a correct product.** D4-2 itself is CLOSED in the product.
- `:3008-3009` read `envelope["key_id"]` and `envelope["user_id"]`. Both live under `envelope["payload"]`, so the test raises "posted no key_id".
- `:2921-2922` compare against `admin_sk`, a key the test generates itself. `signer link` generates its own seed, so the kids never match.
- Probe: a scratch copy with both lines fixed passes. It reads `payload` and takes the kid from `keyhome/signer/signer.seed` after link. The posted approval carries the linked kid and `user_id == "u-f13"`, and its signature verifies under the linked key.
- Fix (qa):
  - Apply both corrections and remove the strict xfail.
  - Add the same payload assertions to `test_d4_2_deny_reads_linked_seed`, which checks only the exit code.

**R2-4 HIGH, pre-existing, a lead-architect and founder item (does not block the d4 commit; blocks the T12d exit and the M2 security sign-off) -- S9 does not stop one admin from minting dual-eligible keys.**
- How S9 counts: `verify_chain` sets `admin_sigs_at_add[kid]` to the number of distinct previous-admin signers (`registry.py:304-311`). It does not require those signers to be dual-eligible themselves.
- Probe B (one human):
  - v2 adds a second admin key that alice holds, with an invented `user_id`/`iss`/`sub`. Alice alone signs it at threshold 1.
  - v3, signed by both of alice's keys, adds dave and erin.
  - `counts_for_dual` is True for dave and erin. Alice alone reaches dual control, which is threat 30 ("one admin picks the approvers").
- The server does not stop it either:
  - ADR 0011 s5 says "`verify_chain` is the real gate. Who posts only authenticates the org."
  - `/signatures` never checks that an added key matches a real user's signer link or browser enrollment.
  - Live evidence: the e2e v2 (`test_m2_t12b_e2e.py:440-444`) publishes `admin2` with `user_id` `admin-<kid8>`. That is not a `users` row, and the server stores it.
- With a single-key genesis (ADR 0011: threshold 1, one admin), the connector cannot tell a second human from alice's second key. So "two different humans" rests on the server's identity binding.
- Options:
  - (a) Server-side. For v2 and later, every added key must match a consumed signer link or browser-key enrollment of a real org user, with equal `user_id`, `iss`, `sub` and public key. Each added admin must be a different user from the signer. Within G-L1 this binds the registry to OIDC identities.
  - (b) Connector-side: a transitive S9. It conflicts with ADR 0011's single-key genesis, because no key could ever become dual-eligible.
- Recommendation: (a), plus a new named limit G-L4 in ADR 0011 for the connector-only view. This changes a security property, so the founder rules. Builders do not touch S9 or `verify_chain`.

### Item 2: D4-6 threshold bound -- ACCEPTED for this commit, with a condition

- The distinct-admin bound applies only with `--admin --add` (`sync_cmds.py:1885-1899`). Elsewhere the bound is `max(len(keys)+1, 2)`.
- No property is weakened:
  - A threshold that is too high is refused at publish by `verify_chain` (`cur_signer_users < cur_threshold`).
  - The floor rules guard the low side.
  - The cost is that the CLI signs a version the server will refuse.
- Condition (d5): apply `threshold <= distinct admin user_ids of the new payload` unconditionally, drop the `len(keys)+1` bound, and give `test_f10_sign_registry_threshold_flag` two admins.

### Item 3: D4-6 logging and `root_fingerprint` -- ACCEPTED

- **Debug-only log.** It still fails closed: the caller raises "failed to obtain signer token".
  - d5: put a non-secret reason class (the HTTP status, or "transport refused") in the ClickException.
  - d5: drop the word "token" from the log format, which clears the Semgrep warning.
- **`O_TRUNC` for `root_fingerprint`.** Acceptable as is:
  - It is a public value inside the 0700 `signer/` dir, written only after a 200 from genesis.
  - Anyone who can plant a file or symlink there is the same user, who could already read the seed.
  - An exclusive create would break a legitimate re-run after a server-side reset.

### Item 4: `_refresh_registry_chain` -- CHANGES

- **(a) Floor.** See R2-2. The downstream refusal holds only while `high_water.json` is intact, and the function's own write can remove that condition.
- **(b) Silent failures.**
  - No fail-open is added relative to `ed26bff`, where `run_once` never refreshed.
  - An unapplied revocation stays bounded by the registry `expires_at` (7 days, or 72 h with prod), which is the existing design.
  - Required in this commit: add a status to the `run_once` result: `registry: updated | current | fetch_failed | verify_failed | rollback_refused`.
  - d5: write an audit record for `verify_failed` and `rollback_refused`, since a forged or rolled-back chain is a security event.
  - A `high_water.json` that parses as a non-dict makes `hwm.get` raise AttributeError out of `run_once`. That fails closed but aborts the cycle; R2-2's fix removes the path.
- **(c) Duplicate.**
  - It is a near-verbatim copy of `process.py::_fetch_registry` (`:329-399`) and has already drifted: it adds the high-water write and drops the same-version-different-bytes refusal.
  - Required: one shared helper that verifies and persists a fetched chain (for example `sandbox.connector.sync.state.apply_registry_chain(layout, chain) -> status`), called by both `process.py` and `run_once`. Only the transport stays per caller.
  - `process.py` is not in `M2_FROZEN_MANIFEST.sha256`, so it can change.

### Item 5: e2e step 5 -- cause CONFIRMED; S9 and ADR 0011 stay as they are for this test

- **Cause.**
  - The ruling-2 v2 (`test_m2_t12b_e2e.py:458-478`) is signed by admin1 and admin2, but only admin1 is a previous admin, so `prev_signer_users` is 1.
  - bob, carol and alice-approver are therefore added with count 1, and `counts_for_dual` is False for all of them (probe A).
  - The `ed26bff` test used a two-admin, threshold-2 genesis, so its keys counted.
- **A co-signed v3 does not re-ratify.** `admin_sigs_at_add` is set only for keys that are new in that version, so keys already present stay at count 1 (probe A': False, False).
- **Correct under ADR 0011 and frozen step 2.** Probe "Frozen step2": carol's v2 CLI key gives False, and the v3 bob and carol keys give True.
  - v2 adds the second admin only, with `threshold 2`, signed by admin1 and admin2. This also fixes D4-5's v2 threshold point.
  - v3 adds the approver keys (bob, carol, alice-approver), signed by both admins.
  - The admin2 entry must be a seeded user with a signer link, not the invented `admin-<kid8>`.
  - qa makes this test change, approved here by node id: `ee/tests/test_m2_t12b_e2e.py::test_e2e_remote_approval_path`. Then qa removes the xfail. No product change is needed, and S9 stays.
- **The step-5 fallback in M2_PLAN's cut order** has bob and carol approve with their own CLI keys. It fails under S9 when carol's CLI key comes from v2. lead-architect: either add the approver CLI keys in v3 as well, or note that the fallback needs browser keys or keys added in v3. This is not an S9 change.
- **R2-4 stays a separate lead-architect item.** The frozen flow is S9-correct, but S9 does not prove two humans.

### Item 6: relaxed checks in the CLI -- none

- An AST comparison with `ed26bff` shows these functions unchanged: `_fetch_escalation`, `_check_body_hash`, `_check_display_safety`, `_rebuild_envelope`, `_post_approval`, `_get_signer_token`, `_signer_safe_post`, `_check_transport_safety` and `_load_signer_key`.
- The `signer_approve` block from the `fp_v` refusal to the binding-fingerprint check is byte-identical. No list fallback was added.
- Signature checks only tighten (R2-4, R2-5, R2-6 and F14, as in round 1).
- The one new raw `registry.json` writer is `_refresh_registry_chain`. It writes only after `verify_chain` against the pinned root; its floor defect is R2-2.
- New behaviour: `signer approve` and `signer deny` now sign without a verified workspace (link key, `registry_version` 1).
  - Round 1 D4-2 asked for this.
  - The connector re-checks `user_id`, `key_id`, roles and the registry, so it fails closed.
- The server URL now falls back to the `server` in `link.json`. That URL already passed `_signer_safe_post` at link time.
- Pre-existing LOW (d5): approve and deny use plain `urllib`, which follows redirects and keeps the Bearer header. Route them through `_signer_safe_post`.

### Item 7: `demo.py` step 2 -- confirmed untouched

`ee/deploy/demo.py` has no diff. Ruling 6 stands: it is the d4 exit (with D4-5), not this commit.

### Per-finding status

| Finding | Status | Evidence |
|---|---|---|
| D4-1 | **CLOSED** | `signer.py:754-767`; the item 1 table; 3 ee tests |
| D4-2 | CLOSED in the product; the test is OPEN as R2-3 | `sync_cmds.py:700-735`, `:871-899`, `:1312-1319`; probe |
| D4-3 | CLOSED | `compose.yml:142-146`, `:175-178`; `test_d4_3_*` |
| D4-4 | CLOSED, with one LOW (fix the label in d5) | `migrate.py:230-258`. `_load_bundle_signer_key` swallows OSError and returns None, so an unreadable file is reported as `bad_format` and the `except OSError` branch is dead. It still fails closed. |
| D4-5 | OPEN (d4 exit) | demo step 2 and the frozen negatives |
| D4-6 | PARTIAL, accepted | items 2 and 3; R2-4 and R2-7 tightened; the identity block is always printed (`:1488-1497`) |
| D4-7 | CLOSED | `signer.py:631-637`; `test_d4_7_link_missing_user_returns_error` |
| D4-8 | CLOSED | `test_m2_t12d_genesis.py:2147-2195` is now an AST walk |
| Ruling 1 | OPEN | R2-3 |
| Ruling 2 | OPEN | Genesis now goes through `/signer/genesis`, which is right. v2 and v3 must follow frozen step 2 (item 5). |
| Ruling 3 | CLOSED, with a correction | The `M2_BASELINE.md` row is added. The manifest line `4583c359...08e6` is correct: it is the LF hash that CI's Linux checkout sees. Round 1's `ba142d90...c464` was the CRLF hash of the Windows working copy. |
| Ruling 5 | CLOSED | CLI `test_d4_ruling5_link_*` (exit 1, the field is named, no `link.json`, no fresh seed); ee `test_d4_ruling5_link_returns_iss_sub` |
| R2-1, R2-2, R2-3 | OPEN, block the commit | above |
| R2-4 | OPEN, lead-architect and founder | above |

### Required before commit

1. R2-1: the product alert, plus the t7 test rewrite.
2. R2-2: the floor fix, with tests (a)-(c), through the shared helper from item 4(c). Also the `registry` status in the `run_once` result.
3. R2-3: the F13 test corrections, plus payload assertions in the deny test.
4. Item 5: rewrite the e2e to frozen step 2's v2/v3 shape, then remove its xfail.
5. A worker-tier re-review by node id: `test_second_genesis_refused_via_route`, `test_d4_f13_approve_reads_linked_seed`, `test_d4_2_deny_reads_linked_seed`, `test_e2e_remote_approval_path` and the new R2-2 tests. The full root and ee suites must be green.

R2-4 goes to lead-architect now: an ADR 0011 amendment or a named limit G-L4. The founder rules.

## Round 3 (30 Oct 2026)

Reviewer: security-engineer (worker tier, Opus 4.6). Read-only: no product or test file was edited, stashed or reset.
Scope: uncommitted round-2 fixes on top of `ed26bff` (signer.py, sync_cmds.py, process.py, new registry_chain.py, test files), plus the fixture sign-off.
Verdict: **APPROVE** (all items pass; no property weakened).

Measured (from qa): connector 2352 passed, 7 skipped, 1 xfailed; ee 826 passed, 2 skipped, 0 failed.

### R2-1: APPROVE

`signer.py:754-790`. The v1 guard on `/signatures`:
- When a chain exists (`existing is not None`): INSERT `second_genesis` alert, explicit `conn.commit()` at `:786`, then return 409. The `finally` block (`:814-818`) only closes the connection -- no rollback. The alert row survives the 409.
- When no chain exists (`existing is None`): return 409 `genesis_only_via_genesis_route` with no INSERT and no commit. Nothing stored.
- Connection opened `autocommit=False` (`:743`), so the explicit commit is required and sufficient.

Tests (markers removed, both pass):
- `ee/tests/test_m2_t7_signer.py::test_second_genesis_alert_via_route` (`:1053-1094`): creates v1 via `store_registry_version`, posts v1 to `/signatures`, asserts 409, queries `sync_alerts` for `second_genesis` row. Non-vacuous: the test fails without the INSERT.
- `ee/tests/test_m2_t12d_genesis.py::test_d4_1_guard_second_genesis_alert_committed` (`:1664-1695`): same flow via `_do_genesis` helper, asserts 409 + alert row. Non-vacuous.

### R2-2: APPROVE

`src/sandbox/connector/sync/registry_chain.py::apply_registry_chain`:
- Floor = `max(local_version, hwm_version)` (`:95-97`). Both inputs read; the higher one wins.
- `_load_high_water` returns None for missing or corrupt file (`:39-48`). `apply_registry_chain` returns `"refused:missing_hwm"` on None (`:92`). S1 fail-closed preserved.
- No `high_water.json` write anywhere in the module. Only `verified_state.py::_save_high_water` (`:189-207`) ratchets, called from `load_verified_state` (`:98`).
- Same-version-different-bytes returns `"refused:same_version_different_bytes"` (`:121`).
- `verify_chain` runs before the atomic write (`:109-112` before `:135-143`).
- `run_once` (sync_cmds.py:275) stores `results["registry"]` from the helper's status string.
- Both callers (`_refresh_registry_chain` at sync_cmds.py:397, `_fetch_registry` at process.py:353) delegate to `apply_registry_chain`. No second persist path exists outside enrollment.

Tests (markers removed, all pass):
- `test_r2_2a`: floor from hwm=3, registry.json deleted, server serves v2. Asserts no registry.json written, load_verified_state returns None. Real property (floor from hwm blocks rollback even without local file).
- `test_r2_2b`: hwm deleted, local v2, server v3. Asserts hwm not recreated, registry stays v2. Real property (missing hwm = refuse).
- `test_r2_2c`: local v2, hwm=2, server v3. Asserts registry updated to v3, hwm stays at 2 (only load_verified_state ratchets). Real property.
- `test_r2_2_run_once_carries_registry_status`: asserts `"registry"` key in result with a value from the expected set. Non-vacuous (URLError forces fetch_failed).
- `test_r2_2_shared_verify_persist_helper`: asserts hwm unchanged after refresh (same property as r2_2c, framed as shared-helper divergence). Non-vacuous.

### Item 3 (fixture sign-off): APPROVE

`tests/security/test_m2_enroll_persist.py::test_run_once_persists_verified_registry_update` line 621: one line added, `(sync_dir / "high_water.json").write_text(json.dumps({"registry_version": 1, "bundle_sequence": 0}))`. Mirrors `enroll.py:520-524` exactly. No assertion changed. Without this fixture line the test would fail because `apply_registry_chain` now correctly refuses a missing hwm -- the fixture simulates a properly enrolled workspace.

### Item 4 (relaxed-check scan): clean

- No `fp_v` or fingerprint check skipped or weakened.
- No list fallbacks added (all dict-only patterns preserved in `_fetch_escalation`).
- No raw `registry.json` writes outside `registry_chain.py` and `enroll.py`.
- Trust set narrowed (R2-6: `prev_admins | cur_admins`), not widened.
- Exception swallowing: the broad `except Exception` in `_refresh_registry_chain` returns `"fetch_failed"` (network errors), same pattern as prior `ed26bff` code. No security check is bypassed.

### Item 5 (scanners)

- **Semgrep** (p/python, p/secrets) on 5 changed product files: 1 finding, 0 ERROR.
  - `python-logger-credential-disclosure` at `sync_cmds.py:1323-1325` (debug log of a failed token request exception). Same as round 2. False positive: the token does not yet exist when the request fails; the log records the transport error. Accepted in round 2 item 3.
- **gitleaks** (dir mode, `.gitleaks.toml`) filtered to changed files: 0 leaks.
- (87 pre-existing repo-wide findings are outside the changed file set.)
