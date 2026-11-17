# T3 design review (security L), 16 Nov 2026

Scope: `docs/control-plane/T3_SPEC.md` (lead, uncommitted) at HEAD `b509a74`, before backend (W) builds. Inputs read: M3_PLAN T3 row, D2, D3, threats 39/40/41/48, S5, S6; M3_BASELINE rows 39-41/48; ADR 0001 A9; T0B review P3, F-3, F-6, F-10. I read the three frozen test files in full (`ee/tests/test_m3_t3_proposals.py`, `ee/tests/test_m3_t3_csrf_catalog.py`, `tests/security/test_m3_t3_signer.py`) and the code the spec cites: `rbac.py`, `auth.py`, `api.py`, `sync/enroll.py`, `sync/escalations.py`, `sync/signer.py`, `sync/bundles.py`, `sync/registry.py`, migrations 0007/0012, the connector's `bundles.py` and `cli/sync_cmds.py`. Nothing was run against a server and nothing was edited except this file.

Verdict: **CONFIRMED WITH CHANGES.** None of the guarded properties is weakened, provided the MUSTs in section 3 are built. Two of them are new findings: T3-F1 (a non-CLI key can mint a signer token) and T3-F2 (psycopg's `with conn` commits on a refusal return).

## 1. Design points

| # | Point | Verdict | Notes |
|---|---|---|---|
| 1 | One signature, verified at the route by `_verify_change_approvals` (need 1) against `verify_chain(get_chain(org))` | CONFIRMED | `_verify_change_approvals` loops over every signature, so the exactly-one check has to come first (spec 3.5 step 1). Store `user_id` from the registry entry and keep the envelope exactly as verified. |
| 2 | Not a registered `cli` key -> 400 `wrong_kind` (`detail` = `unknown_key` or `kind=<k>`) | CONFIRMED | Key ids are public, so the detail leaks nothing. The projection lookup needs `revoked_at IS NULL` (a revoked key gets 400 `key_revoked`). Step 5 rechecks the kind from the registry entry: an entry whose kind is not `cli` gives `wrong_kind` there too, so a drifted projection cannot let a key through. |
| 3 | Unknown fields, duplicate keys, NaN/Infinity, oversize, `change_approvals`, server-owned fields refused | CONFIRMED | See M-3 to M-5. The frozen nodes need partial bundles to be accepted (`{"folder_policy": {}}` -> 201). That is fine for T3; the T4 property test decides what the connector makes of the missing sections. |
| 4 | CSRF dependency in `rbac_route` that recomputes the token from the cookie and runs before body validation | CONFIRMED WITH CHANGE | Lead's measurement matches the code: `create_project`, `add_project_member`, `add_org_user` and `add_org_member` take Pydantic bodies, so FastAPI returns 422 before the handler's CSRF check. A route-level `Depends` is solved before body params, so `json={}` gets 403. Change (M-1): the Bearer skip applies only to `signer_or_session` routes. On `session` and `admin` routes, CSRF is checked whenever the cookie is present, with or without an `Authorization` header. |
| 5 | Fresh = `now - web_sessions.created_at <= 900 s` on the app clock; 401 `reauth_required`; for code issue, revoke and publish; before id/body parse | CONFIRMED WITH CHANGE | `operator_read_code` skips the check when the row is missing (`if sess_row is not None`). The shared helper must refuse in that case (M-7). Order as in spec 3.2. |
| 6 | `approve-change`: base 0 = deny-all literal; base >= 1 verified before any diff; diff and `loosened` from local bytes; server diff never printed | CONFIRMED WITH CHANGES | The base-0 literal fails in the safe direction: a server that lies "base 0" makes every bundle look loosened, so it needs more approvals, and the connector refuses at step 9 anyway. Order and exit codes: M-10 to M-12. |
| 7 | Code once, `no-store`, never in `admin_audit` | CONFIRMED | `no-store` on every response of the read route (200/401/404). Audit rows hold `code_id` only. The CLI never prints a `code` field (F-2). Also fix the issue response's `expires_at`. |
| 8 | T3/T4 line: publish is a shell (a, c, g, then 400 `verification_pending`), no write to policy tables | CONFIRMED | T0b-10 forbids an unverified write path, and this line respects it. No T3 path may return 2xx from publish (M-9). In T3, (g) may use the stored `user_id` because every path refuses. T4 must recheck against the rebuilt registry entry, as A9 8(g) says. |
| 9 | Migration 0018 | CONFIRMED WITH ADDITIONS | Add `CHECK (octet_length(payload) <= 1048576)` and the same hex CHECK on `base_sha` as on `new_sha`. Keep "no unique constraint on `policy_change_approvals`" only together with the `FOR UPDATE` lock on the request row in every proposal-approval insert, and a QA node that sends two approvals by the same user at the same time. Downgrade loses data; S8 already has `pilot.sh` refuse a downgrade. |

## 2. Rulings

**S-1 (CLI admin authentication): ACCEPTED WITH CONDITIONS.** `issue-code`, `propose-bundle` and `publish` may authenticate with a signer token. The routes for code issue, proposals and publish become `signer_or_session`. Revoke stays session only (`admin`), and there is no CLI revoke in T3. Conditions:
1. The token's scope is `confirmed` and its `key_id` has a live `approver_keys` row in the same org with `kind = 'cli'` (finding T3-F1 below). Otherwise 403. Device, `pending_link` and revoked tokens get 403.
2. Authorisation goes through exactly the same role helper as the session path, keyed on the token's `user_id` (S-3). There is no separate token path.
3. Freshness for a token is `signer_tokens.created_at` within 900 s on the app clock. To be honest about what that means: tokens live 600 s, so the check always passes. What actually proves "fresh" here is key possession: the assertion's `iat` must be within 120 s and its nonce is single-use. The CLI mints a new token for each command and never writes a token to disk. The spec must say this is proof of key possession, not of a recent IdP login.
4. On the approval route, when the caller authenticates with a token, the approval's `key_id` must equal the token's bound key (403 `not_key_owner`). `escalations.py:752` already does this.
5. Every `admin_audit` row for these routes records `auth` (`session` or `signer_token`) and, for tokens, the `key_id`.
6. Named consequence (PILOT.md and ADR): a stolen CLI key can now also issue codes, propose and publish as that admin. Dual control is unchanged, because approvals are counted per registry user and the publisher and proposer are both excluded.

This widens the set of credentials that can do admin writes, which is an identity change. Under TEAM.md it needs an ADR line: the lead adds an "A9 addendum, S-1" to ADR 0001 with the six conditions above. I have not edited the ADR.

**T3-F1 (new, Medium, found reading code).** `cli_key_lookup` (migration 0012) returns status `signer` for any live `approver_keys` row whatever its `kind`. `authenticate_signer` does not check the kind either. So a `browser` key, or any other registry key, can mint a `confirmed` signer token by signing `agg/signer-assert/v1`. A script injected into the inbox page can make the browser key sign that assertion. Today a token like that adds little, because the session already grants the same. Under S-1 it would bypass both CSRF and the fresh-session rule on admin writes. Condition 1 closes this at the T3 routes. A fix in `cli_key_lookup` or the token route belongs in the TCB with tests first; I recommend it for T4 or T9b. The lead should log it in HANDOFF.

**S-2 (`approve-change` trust anchor): ACCEPTED, renamed for consistency.** Use `--expect-fingerprint`, the flag name `enroll` and `sign-registry` already use, rather than `--expect-root`. Resolve the anchor in this order: (a) an enrolled workspace's `load_verified_state` after `_refresh_registry_chain`; (b) `--expect-fingerprint`; (c) the stored `<key_home>/signer/root_fingerprint`, as `sign-registry` reads it (`sync_cmds.py:1557-1570`). Then run `verify_chain` over `GET /api/v1/sync/signer/registry`. With none of the three, refuse with exit 1 through `click.ClickException`. It must **not** be a `required=True` option, because both frozen approve-change nodes assert `exit_code != 2`. `approve-change` never writes the fingerprint file. Named limit: a signer with no workspace has no high-water, so a server can serve a truncated chain. The signer's registry checks are advisory, and the connector's step 8 against its pinned version stays authoritative.

**S-3 (no role check on code issue, revoke, direct bundles): FIX IN T3 for the two `enroll.py` routes; T4 for `admin/bundles`.** Impact: any org member, a viewer included, can issue a code naming themselves as operator for any project. They read it once and enrol a device that then receives that project's bundles and can submit escalations as a managed device (privilege escalation). Any member can also revoke any device (availability).
- Code issue: org admin or admin of `project_id`, using `api.py::_is_project_admin`'s exact SQL moved into one shared helper. 403 `forbidden`, nothing inserted. `operator_user_id` must be an active user of the org, otherwise 404 `operator_not_found`. Project membership for the operator is a SHOULD; add it only if `m2_gate.py` and `demo.py` stay green.
- Revoke: org admin or admin of the device's project. 403, `revoked_at` unchanged.
- `POST /admin/bundles`: add the org-or-project-admin check in the T4 commit that adds the 410, since T4 touches that route anyway.
- Tests first (QA, new nodes, founder approves adding them): `test_code_issue_non_admin_403` (the fixture's operator session has no binding; assert 403 and no new `enrollment_codes` row); `test_code_issue_project_admin_other_project_403`; `test_code_issue_operator_other_org_404`; `test_revoke_non_admin_403` (the device row's `revoked_at` stays NULL); `test_signer_token_browser_key_refused_on_admin_route` (T3-F1). The builder runs the full ee suite. Any frozen node that issues codes or revokes with a non-admin session is reported by id, never relaxed.

## 3. MUSTs the builder needs that the spec lacks

- **M-1 CSRF predicate.** One shared function decides "authenticated by Bearer" (`Authorization` starts with `Bearer `, exactly as `escalations.py:195/237`). The dependency and the handlers use that same function. The dependency skips CSRF only for role `signer_or_session` and only when that predicate is true. Cookie parsing is one shared helper with `validate_session` (`split(".", 1)`, token part). Also cover PUT and PATCH. Return `{"error": "csrf_missing"|"csrf_invalid"}` through an exception handler so clients see one error shape. Side benefit: the check now runs before `validate_session` touches `last_seen_at`, so a forged request no longer extends the idle timer.
- **M-2 Refusals write nothing (T3-F2).** psycopg 3's `with conn:` commits when the block exits normally, so `return err` inside the block commits any earlier write. Every refusal path in the proposal, approval and publish routes calls `conn.rollback()` before it returns. The publish-refusal audit row is written in a new transaction after that rollback.
- **M-3 Strict parse.** The proposal route reads the raw body itself, not `request.json()`, through a capped streaming read: above `BUNDLE_MAX_BYTES + 64 KiB` it stops and returns 413. The duplicate-key hook applies at every depth, in the outer body and in `bundle_raw`. `parse_constant` refuses NaN, Infinity and -Infinity. `RecursionError` and `ValueError` give 400 `bad_json`. The body holds exactly one of `bundle` or `bundle_raw`.
- **M-4** Any exception from `loosened`, the diff or canonicalisation gives 400 `invalid_bundle` with nothing stored, never 500.
- **M-5** Proposal and publish roles: org admin or project admin through the shared helper, for session and for token alike.
- **M-6** At the approval route, step 5 rechecks kind `cli` and a counting role from the registry entry, giving `wrong_kind` or `role_not_counted`. Step 7 stores the canonical envelope exactly as verified.
- **M-7** The fresh-session helper refuses with 401 when `created_at` cannot be read. It uses the injected app clock, the same clock `validate_session` uses.
- **M-8** The proposer is the authenticated user, whether by session or token, and is stored on the row. The body cannot name a proposer.
- **M-9** No T3 code path returns 2xx from publish or writes to `policy_bundles` or copies approvals. I will grep for this in the diff review.
- **M-10 approve-change order.** Resolve the anchor locally first, before any network call. Then mint the token, GET the detail, check hash, fields and sequence, verify the base (base >= 1), print the diff, `loosened` and the approvals needed, run the org and registry checks, confirm, sign, and POST. No POST to `/approvals` happens before every local check has passed. The frozen bad-base half passes only because the anchor check refuses before any network call. Do not reorder that to make anything else pass.
- **M-11** The confirm screen prints org, project, environment, sequence, base_sequence, registry_version and bundle_hash, because the signed hash covers all of them. Every server string goes through `json.dumps(..., ensure_ascii=True)` or `_check_display_safety`.
- **M-12** `propose-bundle` prints a hash as verified only after recomputing `_bundle_hash(bundle)` from the returned `bundle`. A refusal message may quote the server's hash, but labelled as unverified.
- **M-13** CLI credential lookup uses only `--key-file` or the linked key via `key_home_root()`, which is the existing loader. No new key loader and no token cache.
- SHOULD: cap the number of open proposals per project; `approve-change` verifies the base row's own `change_approvals` at need 1 and prints who approved it; T2's re-auth uses `prompt=login` or `max_age=0`, otherwise "fresh" proves an OIDC round trip, not that credentials were re-entered.

## 4. F-1 and F-2 (founder decides every test edit)

**F-1: the lead is right on all three nodes, with one correction.** `test_stale_base_refused_at_approval` asserts that publish A returns 200/201 with one approval, no chain, and keys only in the projection. A9 items 2, 5 and 7 and ruling T0b-10 refuse that in T3, and with one approval T4 refuses it too. In `test_stale_base_refused_at_publish`, C's publish is refused, so D never goes stale and `verification_pending` is returned instead. `test_publisher_not_among_approvals` cannot work while alice is both proposer and publisher, because her approval is refused at the route. Correction: its `count == 0` does not fail in T3, because nothing publishes. It would fail only in T4 or with owner-inserted rows. What I accept:
- **Publisher node, stays T3, setup-only change:** a fresh project inside the node; a server registry chain built through the existing helpers with `cli` keys for alice, bob and carol (`counts_for_dual`, two admin signatures per T0b-6); a carol session; carol proposes, alice and bob approve through the route, alice publishes. This expects 400 with `publisher` in the reason, and `count == 0` holds as written. No assertion changes.
- **Both stale-base nodes, move to `M3T4Pending` with the same chain and carol setup, plus carol co-approving A and C**, so the first bundle has two counting approvals. Every assertion is kept, including publish A's 200/201. Replacing publish A with an owner-inserted row would delete an assertion, and I do not accept that as fixture-only.
- **New T3 coverage (QA, new nodes):** stale base at approval and at publish, made stale by an owner-inserted `m2_unverified` row at max+1 in a fresh project. Spec 3.5 orders the stale check (step 4) before the registry check (step 5), so these nodes need no chain.

**F-2: the lead is right.** D3 and the frozen M2 node `test_admin_code_issue_no_code_in_response` say the issuer never receives the code. A CLI branch that prints a `code` field would show it to the wrong person if a server sent one (threat 39). No fixture-only change exists: removing `code` from the stub makes `code_value in output` impossible to satisfy. I accept an assertion change that is strictly stronger: the stub still returns `code` (standing in for a hostile or regressed server), and the node asserts `code_id` is printed and `code_value` is **not**. Also drop "CSRF and session headers" from its docstring. Until the founder rules, W builds no code-printing branch and reports the node as failing.

**Other test notes for QA (no edits now):** the positive half of `test_approve_change_signs_policy_change_v1` is vacuous (`if captured_posts:`). With an anchor present, its first captured POST would be the token mint, not the approval. QA should add a positive node with a temp key home holding `signer/root_fingerprint`, and a base >= 1 corrupted-base node that asserts no POST to `/approvals`. The OK half of `test_propose_bundle_sends_canonical_and_verifies_hash` passes on a refusal message: its stub hash is computed over the four sections alone, which A9 item 6 makes impossible for the server to return. Fresh sessions in the proposals module are seeded at module start, so a module run longer than 15 minutes fails the late code-issue nodes with 401.

## 5. Review gates still owed

This file confirms the design only. The `t1_frozen_routes.json` signature under T0b-11, my diff review of every server TCB file and the migration, and the Semgrep/gitleaks/trivy runs over the built change all come after W's build.

# Round 1, 16 Nov 2026

Scope: the uncommitted T3 tree at HEAD `b509a74`: `git diff -- ee/src src` (`app.py`, `auth.py`, `rbac.py`, `sync/enroll.py`, `cli/main.py`), new `sync/proposals.py`, `migrations/versions/0018_t3_proposals.py`, `cli/change_cmds.py`; test diffs in `test_m3_t3_proposals.py` and `test_m3_t3_signer.py`; new `test_m3_t3_security.py` and `test_m3_t3_signer_security.py`. Probes and mutations ran on a scratch copy at `E:\caterpillar\jev-os\.cache\tmp\t3_r1` (repo untouched; every server and container stopped).

**Verdict: REJECT, fix forward.** Nothing published in T3 (no `policy_bundles` write, no 2xx from publish: M-9 holds), so no guarded property is broken in the running product today. But the approval route does not verify against the signed registry, `approve-change` signs over an unverified base when the registry is unavailable, and an authenticated user can hang every server worker. The CLI and server also do not interoperate on any route, so the T3 tests pass against stubs whose contract the server does not have.

## R1. Measured

| Run | Result |
|---|---|
| ee `--runxfail` proposals + csrf + security | 54 passed, 8 failed (as the orchestrator measured) |
| Two frozen stale-base nodes, normal mode | 2 FAILED by `AssertionError` (F-a confirmed) |
| root `--runxfail` signer + signer_security | 25 passed, 1 failed (`test_approve_change_diff_from_local_bytes`) |
| Semgrep `p/python` + `p/secrets` on the 12 changed files | 0 findings, 0 errors |
| gitleaks dir (changed files), gitleaks git (284 commits) | no leaks |
| trivy fs secret/misconfig (changed files); vuln HIGH/CRITICAL (repo) | clean; no dependency change in T3 |
| ee regression: `test_t9_routes`, `test_m2_t7_signer`, `test_m2_t8_enroll`, `test_m2_t9_bundles`, `test_m3_t1_*` | 228 passed, 2 failed: `test_frozen_route_set` (the 3 new routes are not in the reviewed file, expected until R3's re-sign) and `test_t1_17_export_peak_memory` (70.2 MB > 64 MB under load; passed alone, 1/1; the export path is not touched by T3) |
| ee T3 files, normal mode | 46 "failed" are XPASS(strict) targets plus the 8 real failures above; marker removal waits for this round's fixes |

Probes (scratch, live server on pg):

| # | Probe | Spec says | Measured |
|---|---|---|---|
| P1 | Approval by a projection-only `cli` key, org with no registry chain | 400 `no_registry` | **201**, row stored |
| P2 | `NaN` inside the `bundle` object | 400, nothing stored | **500, and the row is committed** with `NaN` in the canonical payload bytes |
| P3/P4 | Duplicate key in the outer body / inside the `bundle` object | 400 | **201**, last value wins |
| P5 | `{"folder_policy": {"shell": "x"}}` (`loosened` raises) | 400 `invalid_bundle` (M-4) | **201 with `loosened: {}`** (reported as not loosening) |
| P6 | Approval payload `{"bundle_hash", "note"}` plus an extra body key | 400 | **201** |
| P7 | `signatures: "x"`, `payload: "x"`, body `[1,2]`, non-JSON body | 400 | **500** on all four |
| P8 | Tokens from the real mint route `/api/v1/sync/signer/token` | cli token works on code issue and propose; browser token 403 | browser and cli tokens both mint 200; **both** 403 `key not cli or revoked` on propose; **both** 401 on code issue |
| P9 | `GET /admin/bundle-proposals?project=`, `GET .../{id}` | 200 | **405, 404** (routes not built) |
| P10 | Approval POST with no session and no token | (D3) | 401 `no_session` |
| P11 | Revoke by a project admin | allowed for the device's project | 403 (role check gets `org_id` as the project id) |
| P12 | Four concurrent approvals, same session, non-proposer | one 201, three 409 | reps 0-8 correct; **reps 9-11 ReadTimeout, workers stay hung** |
| P13 | Same, four sessions of one user | one 201 | 8/8 correct; with `FOR UPDATE` removed 4/8 store 2 or 3 |
| C1 | `approve-change --expect-fingerprint`, registry GET 500, base >= 1 with a garbage signature and a permissive payload | exit 1, no POST | **exit 0, approval POSTed** |
| C2 | `issue-code` mint URL; server `code_id` with ESC bytes | `/sync/signer/token`; no raw ESC | posts to **`/api/v1/signer-links`**; **raw ESC printed** |
| C3 | Linked key at `<key_home>/signer/signer.seed` | loaded by the existing loader | **not found** (code reads `signer/signing.key`) |

Mutations: (1) the kind check in `_signer_or_session_auth` removed: the three browser-key "guards" still PASS, so they are vacuous. (2) `FOR UPDATE` removed from the approval route: `test_concurrent_same_user_approval_one_stored` still PASSES (vacuous), and P13 catches it. (3) Publisher exclusion removed: `test_publisher_not_among_approvals` FAILS (it bites).

## R2. Findings

| # | Sev | Finding |
|---|---|---|
| T3-R1-1 | High | Approval route skips spec 3.5 steps 5 and 6 (A9 item 7, M-6). It calls `get_chain` and discards the result, then verifies the signature against `approver_keys.public_key` and stores the projection's `user_id`. P1. No T3 node covers `no_registry` or `not_in_registry`. |
| T3-R1-2 | High | Event-loop self-deadlock. `proposals.py` handlers are `async def` with sync psycopg calls. They `await request.body()`/`request.json()` after `validate_session` has updated `web_sessions` (the row lock is held in the open transaction). A second request with the same session on the same worker blocks the loop on that row lock, so the first request can never resume. Any session holder can hang all four workers (P12). This explains F-e. `escalations.py` reads the body first through `_read_body_capped`; T3 must do the same. |
| T3-R1-3 | High | `approve-change` fails open on the registry. If the GET is non-200, empty or malformed, `reg` stays `None`, and the base signature check (`if reg is not None`) is skipped (C1). Also missing: `_verify_bundle_signer_in_registry`, base `sequence == base_sequence`, base org and project equality, proposal org equality, `registry_version >= Registry.version`, and "own key is a counting `cli` entry" (spec 4, M-10, S-2, P3). |
| T3-R1-4 | High (fail closed, not shippable) | CLI and server do not interoperate, and S-1 is not delivered. (a) `_mint_token` posts `{"assertion": env}` to the session-only `/api/v1/signer-links`, so every token mint gets 401. (b) `_signer_or_session_auth` reads `approver_keys` before `set_config('app.org_id')`, so RLS hides every row and every token gets 403 (P8). (c) The code-issue route is tagged `signer_or_session`, but its handler is session-only, and the audit row hardcodes `auth: session`. (d) `approve-change` sends no token, and it reads `{"chain": [...]}` where the real route returns a bare list behind a signer token. (e) The list and detail routes do not exist (P9). |
| T3-R1-5 | Medium-High | The outer body is parsed with plain `json.loads`: no duplicate-key hook, `NaN` accepted (M-3). P2 commits the row and then the response render raises: a 500 that writes (T3-F2 class). P3, P4. The raw body is read whole, then 400 `too_large`, instead of a capped streaming read with 413. |
| T3-R1-6 | Medium | `loosened` exceptions are swallowed to `{}` on the server (P5; stored in `loosened_fields`) and in `approve-change` (then "approvals needed" can say 1). An error must add scrutiny, never remove it (M-4). |
| T3-R1-7 | Medium | Approval parsing is loose (spec 3.5 (1), (2)). Body keys, envelope keys and payload keys are not exact (P6), `alg` is unchecked, non-list or non-dict shapes and a non-JSON body give 500 (P7). The stored envelope is the client dict, not the strictly validated envelope. |
| T3-R1-8 | Medium | Server base for the diff is wrong for base >= 1. `policy_bundles.bundle_blob` holds the envelope, but `proposals.py` uses `json.loads(blob)` as the payload. A parse failure silently becomes the deny-all base. |
| T3-R1-9 | Medium | CLI M-11, M-12, M-13. The confirm screen prints only "`<section>`: changed": no field values, and no org, project, environment, registry_version or bundle_hash. `issue-code`, `propose-bundle` and `publish` print server strings raw (C2). `propose-bundle` parses non-strictly, accepts a response without `bundle` by hashing what it sent, and does not check that extra keys are server-owned or that sections it did not send are absent. `_load_key_file` is a new loader for a file that does not exist (C3) and bypasses `_load_seed_checked` and the D4-2 `link.json` check. `AGG_KEY_HOME` is an invented override (the real one is `SANDBOX_KEY_HOME`). `base_sequence` is read from the detail's top level, not from the hashed bundle. |
| T3-R1-10 | Low-Medium | Publish: the `proposer_in_approvals` branch is `pass` (spec 3.6). |
| T3-R1-11 | Low | Revoke's role check passes `org_id` as the project id, so project admins are refused (P11). This fails closed but deviates from S-3. |
| T3-R1-12 | Low | `operator_read_code` 401 responses lack `Cache-Control: no-store` (spec 3.3: every response). |
| T3-R1-13 | Low | `_is_project_admin` exists in three copies (S-3 asks for one shared helper). `rbac.py` re-implements `csrf_token_for` and cookie parsing rather than importing them from `auth.py`. I compared them, and they match today (no bypass via a dotless or empty cookie), but they can drift. |
| T3-R1-14 | Low | `auth.require_fresh_signer_token` is dead code with wrong semantics: it takes the latest token for a `key_id` in any org, not the presented token. |
| T3-R1-15 | Low | Migration 0018 re-adds `base_sha`, `new_sha` and `loosened_fields`, which 0007 already has. `IF NOT EXISTS` makes these no-ops, and the `json` type and defaults in the file are misleading. `proposed_by` is D4. The code-issue route awaits `request.json()` before auth (pre-existing; spec 3.3 says auth first). The proposal route does not validate `project_id` as a UUID before the `::uuid` casts, and does not enforce exact body keys. `env_name or "prod"` silently maps a NULL environment to prod. `registry_version` comes from the unverified `chain[-1]`, not from `verify_chain`. |

## R3. Backend deviations

- **D1 (stale base before the projection and proposer checks): ACCEPTED.** Every branch is a refusal that writes nothing, and the ordering leaks nothing an org member cannot already read. The lead updates spec 3.5's order. QA SHOULD change `test_stale_base_at_approval_via_inserted_row` to approve with a non-proposer `cli` key, so the node pins the stale rule and not the ordering.
- **D2 ("no anchor exits 1 only when `AGG_KEY_HOME` is set"; otherwise advisory-only): REJECTED.** It violates S-2 and A9 addendum item 2. The file as I read it refuses whenever no anchor resolves, but resolution falls back to the invoking user's real key home and the registry step fails open (T3-R1-3). Ruling: (1) no anchor means exit 1, unconditionally and before any network call; (2) anchor sources are exactly (a), (b), (c); (3) the key home comes only from `key_home_root()`, with no `AGG_KEY_HOME`; (4) "advisory" names only the missing high-water mark. It never permits proceeding when the registry cannot be fetched or verified.
- **D3 (approval POST authenticated only by its envelope): REJECTED.** Measured (P10): with no session and no token the route returns 401 `no_session`, so the CLI as built cannot approve. A signature-only route would be a preauth write with no org binding from authentication, and it would drop S-1c (approval key == token key), which stops a captured envelope from being forwarded by a different caller. `approve-change` mints a token through the existing `/api/v1/sync/signer/token` helper and sends it on the registry GET, the detail GET and the approval POST.
- **D4 (`proposed_by` beside `proposer_user_id`, read with COALESCE): REJECTED.** Two columns for the proposer split the source of truth for the dual-control exclusion: COALESCE prefers the new column, while M2 rows and any other writer use the old one. Use `proposer_user_id` only and drop `proposed_by` from 0018 and `proposals.py`. It does not even fix F-b, because `proposer_user_id` stays NOT NULL.
- **`require_fresh_signer_token`:** dead code, delete (T3-R1-14). Not checking token age on publish is acceptable only because S-1f makes it a tautology (600 s token life against a 900 s rule). Say so in a comment at the publish route.
- **Frozen routes (T0b-11):** not re-signed, because the diff is not approvable. Entries to add once it is: `POST /api/v1/admin/bundle-proposals` (`signer_or_session`, org); `GET /api/v1/admin/bundle-proposals` and `GET /api/v1/admin/bundle-proposals/{proposal_id}` (not built yet); `POST .../{proposal_id}/approvals` and `POST .../{proposal_id}/publish` (`signer_or_session`, org); and the role change of `POST /api/v1/admin/enrollment-codes` from `admin` to `signer_or_session`, which only becomes true once T3-R1-4c is fixed.

## R4. Orchestrator findings

- **F-a CONFIRMED.** Both nodes fail by `AssertionError` in normal mode (`publish A failed: 400 verification_pending`, and `publish refusal must cite stale base, got verification_pending`). The `require_m3(4, route != 404)` gates never fire, because the routes exist.
- **F-b CONFIRMED.** The three `test_migration_0018_*` nodes omit `proposer_user_id` (NOT NULL since 0007) and turn every exception into "not enforced". D4 does not fix this.
- **F-c CONFIRMED as a test setup bug, plus a product bug behind it.** The tests mint at `/api/v1/signer-links` (the session-only link-code route) with an `{"assertion": ...}` wrapper, so every mint gets 401. The real route is `/api/v1/sync/signer/token` with the bare envelope, and there `cli_key_lookup` resolves test-inserted `approver_keys` rows (P8: 200 for both kinds). The three browser-key guards are vacuous: they take the `else` branch, and they stay green with the kind check removed (mutation 1). With the right route they would still pass only because the product refuses every token (T3-R1-4b), so they need a positive twin.
- **F-d CONFIRMED.** Under S-2 the node must exit 1, because it supplies no anchor. It also reads the invoking user's real key home, so the result depends on the machine. Fixture-only change I accept (founder decides): set `SANDBOX_KEY_HOME` to `tmp_path`; pass `--expect-fingerprint <fp>`; serve a registry chain for that fingerprint (bare list, as the real route) containing the bundle signer and the test key as a `cli` entry with a counting role; and answer the token mint with a token. Every assertion stays as written. The M-10 point stands for `test_approve_change_signs_policy_change_v1`: its bad-base half passes only through the no-anchor refusal, so base verification is covered only by the new node in MUST Q-3, which keeps the anchor and chain valid and corrupts only the base.
- **F-e: a real defect, not a flake.** The node is also vacuous. Its approver is the proposer, so both requests get `proposer_cannot_approve` and `successes <= 1` holds trivially (mutation 2: passes without `FOR UPDATE`). The failure backend saw is the same-session event-loop deadlock (T3-R1-2, P12: ReadTimeout, workers stay hung). With different sessions, the row lock is correct and load-bearing (P13: 8/8 with it, 4/8 double-stored without it).

## R5. Test edits under the 16 Nov founder rows

- **F-1, publisher node:** setup-only and as ruled: fresh project, carol proposes, alice and bob approve through the route, alice publishes. The `count == 0` scope changed to the fresh project, which follows from "fresh project". It bites (mutation 3).
- **F-1, stale-base nodes:** the setup matches the row and every assertion is kept, but the T4 gate is wrong (F-a). Carol's co-approval responses are not asserted (SHOULD: assert 201, so a refusal is not misread later).
- **Chain in the module-scoped `t3_server` fixture rather than in the node:** I accept this as setup. It changes what other frozen nodes run against: every node in the module now runs in an org with a chain, and registry_version is 1, not 0. No frozen assertion depends on the absence of a chain. `test_proposer_approval_refused` still holds by the step 3 order, and the browser-key node still gets `unknown_key`. The consequence is lost coverage: no T3 node exercises the no-chain path, and that is how T3-R1-1 went unnoticed. MUST Q-1 restores it in the security file. `_store_chain` silently skips on "second genesis". That is acceptable only because the org is new per fixture.
- **F-2:** exactly as ruled, stricter. The stub still returns `code`, the node asserts `code_id` printed and `code` not printed, and the docstring is fixed.

## R6. MUSTs

**Backend (W), product:**
1. Approval route: spec 3.5 steps 5 and 6 in full. `verify_chain(get_chain(org), <stored genesis fingerprint>)`; 400 `no_registry` / `not_in_registry`; recheck `cli` kind, counting role, proposer and owner against the entry's `user_id`; `_verify_change_approvals(<stored payload>, [env], registry, is_loosening=False, is_first_bundle=False)` gives 400 `approval_invalid`; store the entry's `user_id`. The projection may only refuse, never accept (T3-R1-1).
2. Read and cap the body before opening any DB connection, using `escalations._read_body_capped` (413 above `BUNDLE_MAX_BYTES + 64 KiB`), in every T3 handler. Never `await` while a transaction is open (T3-R1-2). Then parse strictly: the duplicate-key hook at every depth of the outer body, `parse_constant` refusing NaN and Infinity, exact body keys, `RecursionError`/`ValueError`/`TypeError` give 400 (T3-R1-5).
3. Build the response and every value derived from the bundle before `commit`; nothing that can raise after the commit (P2). M-4: any exception from `loosened`, the diff or canonicalisation gives 400 `invalid_bundle` with nothing stored (T3-R1-6), in both server and CLI.
4. Approval body strictness per spec 3.5 (1) and (2): exact key sets, `payload == {"bundle_hash": h}`, `alg == "ed25519"`, a list of exactly one dict; malformed input is 400, never 500. Store the validated canonical envelope (T3-R1-7).
5. S-1 token path: `set_config('app.org_id', token org)` before the `approver_keys` kind check; implement the token branch in code issue (same role helper, audit `auth` and `key_id`) (T3-R1-4b, c).
6. Build `GET /admin/bundle-proposals?project=` and `GET .../{proposal_id}` per spec 3.4: org-bound cursor, uniform 404, approvals list, `base: {envelope, change_approvals}` (T3-R1-4e).
7. Base for the diff and `loosened` = `envelope["payload"]` of the base row. A row that does not parse gives 400 (or 500 with nothing stored), never the deny-all base. `registry_version` comes from `verify_chain` (T3-R1-8, R1-15).
8. Publish: 400 `proposer_in_approvals` (T3-R1-10). Revoke: role check on the device's project (T3-R1-11). `no-store` on every read-code response (T3-R1-12). One shared `_is_project_admin`, and `rbac.py` importing `csrf_token_for` and the cookie parser from `auth.py` (T3-R1-13). Delete `require_fresh_signer_token` (T3-R1-14).
9. D4: drop `proposed_by`; 0018 adds only the columns 0007 lacks (T3-R1-15).

**Backend (W), CLI (`change_cmds.py`):**
10. Tokens only through the existing `sync_cmds` helpers (`/api/v1/sync/signer/token`). Keys only through `--key-file` or `_load_signer_link_key` (`signer.seed`, D4-2). No new loader and no `AGG_KEY_HOME`. A token is minted for `approve-change` too (D3) (T3-R1-4a, d; T3-R1-9).
11. `approve-change` per M-10 and S-2: no anchor exits 1 before any network call. Registry fetch through `_signer_safe_get` with the token; the bare-list shape; any fetch, shape or verify failure exits 1. Base >= 1: structure, `_verify_signature` with `_bundle_signer_pub(reg)`, `_verify_bundle_signer_in_registry`, sequence, org and project. Then the org check, the `registry_version` check, and the own-key `cli`-with-counting-role check. Only then sign and POST (T3-R1-3).
12. M-11: print org, project, environment, sequence, base_sequence, registry_version, bundle_hash and the per-section old and new values from local bytes, with every server string through `json.dumps(..., ensure_ascii=True)` or `_check_display_safety` (including `issue-code`, `propose-bundle`, `publish`). M-12: strict local parse (duplicate keys, NaN); `bundle` required in the response; the server bundle's extra keys must be server-owned; sections not sent must be absent. Take `base_sequence` from the hashed bundle (T3-R1-9).

**QA (W), tests (new files, not frozen):**
- Q-1. A no-chain org: approval gives 400 `no_registry`. A key that is in `approver_keys` but not in the chain gives 400 `not_in_registry`. A key in the chain with a non-counting role is refused.
- Q-2. Token nodes mint at `/api/v1/sync/signer/token` with the bare envelope. Each browser-key guard gets a positive twin (cli token: code issue 201, propose 201, publish reaches `verification_pending`), so the 403 is shown to be about kind. Fix the three F-c nodes the same way.
- Q-3. CLI: (i) registry GET 500 or empty with an anchor: exit 1, no POST to `/approvals` (C1); (ii) a corrupted base with a valid chain and a matching fingerprint (only the base signature is bad): no POST; (iii) ESC in a server string never reaches the output; (iv) the linked key loads from `signer.seed`; (v) every stub uses the real contracts (mint URL and body, bare-list registry, token header). Use `SANDBOX_KEY_HOME`, never `AGG_KEY_HOME`.
- Q-4. Concurrency: a non-proposer approver; same-session and multi-session variants; exactly one 201, the rest 409, `count == 1`; then a follow-up request succeeds within 10 s (no hung worker).
- Q-5. F-b: insert `proposer_user_id` and every NOT NULL column; catch only `CheckViolation`; assert `exc.diag.constraint_name` names the intended CHECK. `_insert_m2_unverified_bundle` stores an envelope, as real rows do.
- Q-6. P2 to P7 as nodes: NaN in the object commits nothing; duplicate keys outer and inner give 400; the `loosened` exception gives 400; extra approval keys give 400; malformed approvals never 500.
- Q-7. One pg-backed end-to-end through the real CLI against the real server: `issue-code`, `propose-bundle`, `approve-change` twice (two users, chain, anchor), `publish` giving `verification_pending`, with no stubs.

**Founder (test-edit rows, frozen files):**
- FR-1 (F-a). In both stale-base nodes, add a T4 gate right after the first publish: `require_m3(4, not (status == 400 and error == "verification_pending"), "server publish verification (T4)")`. In `_at_publish`, capture publish C's response for this, which is setup only. No assertion is changed or removed.
- FR-2 (F-d). The fixture-only change in R4 F-d (`SANDBOX_KEY_HOME` set to `tmp_path`, `--expect-fingerprint`, a valid bare-list chain stub, a token on mint). No assertion is changed.

**SHOULDs:** D1's node uses a non-proposer key. Assert carol's co-approvals return 201 in the T4 nodes. Set `lock_timeout` and `statement_timeout` on the app role's connections as a backstop for T3-R1-2. Cap open proposals per project (carried). Log in HANDOFF that `operator_read_code`, `admin_create_code` and `admin_revoke_device` await the body before auth (pre-existing) so it is fixed with MUST 2's pattern.

# Round 2, 16 Nov 2026

Scope: the uncommitted T3 tree at HEAD `b509a74` after backend (W) fixed forward and qa (W) fixed and extended the tests: `git diff -- ee/src src`, new `sync/proposals.py`, `migrations/versions/0018_t3_proposals.py`, `cli/change_cmds.py`, the test diffs and the two new security files. Checked against round 1 MUSTs 1-12, rulings D1-D4, ADR 0001 A9 and its 16 Nov addendum, and the 16 Nov founder rows (F-1, F-2, S-1, FR-1, FR-2). Probes and mutations ran on a scratch copy at `E:\caterpillar\jev-os\.cache\tmp\t3_r2` (repo untouched; every server and container stopped). Also reviewed: the `_SEAL_REPLACED` edit in `tests/unit/test_m3_manifest_seal.py` (committed in `b509a74`).

**Verdict: REJECT, fix forward.** Real progress: the P2-P5, P8, P9, P10, P12 and P13 probes now behave as specified, most of P7 does, M-9 holds (no `policy_bundles` write and no 2xx from publish), refusals roll back, and the CLI mints tokens at the real route. Two server defects and two CLI defects remain, and each one weakens a guarded property. (1) The approval route still writes its own signature check instead of calling `_verify_change_approvals`, so a key with no counting role is stored. (2) It never rechecks the caller against the registry owner, so an approval is stored under a registry user who did not authenticate. (3) `propose-bundle` reports a hash as verified when the server added or dropped a policy section. (4) `approve-change`'s org check never runs.

## R2-1. Measured

| Run | Result |
|---|---|
| Semgrep `p/python` + `p/secrets`, 12 changed files | 0 findings, 0 errors |
| gitleaks dir (changed files) and git (284 commits) | no leaks |
| trivy fs secret/misconfig (changed files); vuln HIGH/CRITICAL (repo) | clean; no dependency change |
| ee regression: `test_t9_routes`, `test_m2_t7_signer`, `test_m2_t8_enroll`, `test_m2_t9_bundles`, `test_m3_t1_*` (run from `ee/`) | 228 passed, 2 failed: `test_frozen_route_set` (expected; not re-signed, see R2-6) and `test_t1_17_export_no_fetchall_uses_cursor`. The second reads `ee\src\...` relative to cwd: it fails from `ee/` and passes from the repo root (1/1). It is pre-existing and T3 does not touch it. |
| root `tests/unit/` | 607 passed, 1 skipped, 2 failed: `test_root_collect_only_equals_nodeids` (2751 vs 2734) and `test_ee_collect_only_equals_nodeids`. Both are expected until the node-id lists are regenerated at commit, because of the new T3 files. |
| root `tests/security/` | 2097 passed, 6 skipped, 1 xfailed, 26 failed. 24 of the failures are XPASS(strict) T3 nodes in `test_m3_t3_signer.py` and `test_m3_t3_signer_security.py`, because the markers are still on; that is expected before marker removal. The other 2, `test_t0f_bypass_case[benign-038]` and `test_32kib_worst_case_is_classified_under_100ms[brace_heavy]`, are timing nodes that failed under load and pass in isolation (2/2). T3 does not touch them. |

Server probes (scratch, live 4-worker server on pg, one new org with its own chain):

| # | Probe | Spec | Measured |
|---|---|---|---|
| P0 | Counting `cli` key, non-proposer | 201 | 201 |
| P1b | `cli` key in the chain with `roles: ["viewer"]` | 400 (A9 items 5 and 7, MUST 1) | **201, row stored** |
| P1c | Projection says key KC belongs to caller ud; registry says uc. ud approves with KC | 403 `not_key_owner` | **201, stored as user uc** |
| P2-P5 | NaN, duplicate keys at both levels, `loosened` exception, 5000-deep nesting | 400, nothing stored | 400 on all, 0 rows |
| P2x | `project_id: "not-a-uuid"` on propose | 400 | **500** |
| P6 | Extra key inside the signature dict `{key_id, alg, sig, x}` | 400 | **201, stored** |
| P7 | `key_id` an int | 400 | **500** |
| P7 | sigs a string, payload a string, body a list, non-JSON, extra payload key, extra body key | 400 | 400 on all |
| P8 | Browser token / cli token on code issue, propose, publish, list, revoke | browser 403; cli works; revoke session-only | browser 403/403/403/403, revoke 401; cli 200/201/`verification_pending`/200, revoke 401 |
| P9 | List, detail; `cursor=zzz` | 200, 200; 400 | 200, 200; **unhandled exception (connection reset)** |
| P10 | Approval with no session and no token | 401 | 401 |
| P12 | 4 concurrent approvals, same session, x12 | one 201, three 409 | 12/12 correct, no hang |
| P13 | Same with 4 sessions, x8 | one stored | 8/8 correct |

CLI probes (stubbed httpx, scratch):

| # | Probe | Spec | Measured |
|---|---|---|---|
| C-a | `approve-change`: valid chain for org A, proposal bundle for org B | exit 1, no POST | **exit 0, approval POSTed** (the check is `hasattr(reg, '_org_id')`; `Registry` has no such attribute) |
| C-b1 | `propose-bundle`: the server adds an `approval` section with `allow_requester: true` that was not sent | exit 1 | **exit 0, hash printed as verified** |
| C-b2 | The server drops the `governance_policy` that was sent | exit 1 | **exit 0, printed as verified** |
| C-b3 | The server returns no `bundle` (N3) | exit 1 | **exit 0, prints a hash of the sent sections** |
| C-c | `--key-file`: a raw 32-byte seed ending in a whitespace byte; a 33-byte file (32 bytes plus `\n`) | raw seed loads; 33 bytes refused | **raw seed refused (strip made it 31 bytes); 33-byte file accepted** |
| C-d | `approve-change` with no key | exit 1 with a message | exit 1 through an `AttributeError` traceback |
| C-e | `issue-code` with `--key-file`, mint returns 500 | refuse (spec 4) | **posts without a token** (the server answers 401) |

Mutations:

| Mutation | Nodes | Result |
|---|---|---|
| A: token kind check removed in `proposals._auth` and `enroll._auth_signer_or_session` | `test_signer_token_browser_key_refused_on_admin_route`, `_on_propose`, `_code_issue_403`, `_on_publish` | first three FAIL (they bite); **`_on_publish` PASSES** (it publishes a random proposal id and accepts 404) |
| C1: registry failure fails open (`reg = None`, later checks skipped when `None`) | `test_approve_change_registry_500_exit_1_no_post`, `_registry_empty_list_exit_1`, `_registry_malformed_exit_1` | 500 node FAILS (bites); **empty-list and malformed nodes PASS** (their proposal hash is a placeholder, so the hash check refuses first) |
| B: `_verify_signature(base_env, ...)` removed | `test_approve_change_corrupted_base_valid_chain_no_post` | FAILS (bites). `test_approve_change_corrupted_base_no_post` and frozen `test_approve_change_signs_policy_change_v1` stay green (they refuse earlier). |
| D1: `FOR UPDATE` removed from the approval route | Q-4 same-session and multi-session nodes, 3 runs | 1 of 6 node runs failed. Probe P13 caught it on 4 of 8 reps (2-4 rows stored). The same-session variant cannot catch it, because the `web_sessions` row lock taken by `validate_session` serialises same-session requests. |
| D2: `await asyncio.sleep(0.2)` inside the open transaction (the P12 shape) | Q-4 same-session node, 2 runs | **passed both runs.** Probe P12 caught it on 3 of 12 reps (ReadTimeout). The new `lock_timeout = 10s` frees the workers, so the hang is intermittent. |

## R2-2. Round 1 MUSTs

| MUST | Status |
|---|---|
| 1 Approval verified against the registry | **Partly.** `verify_chain`, `no_registry`, `not_in_registry`, the kind recheck and the proposer recheck are in. Missing: `_verify_change_approvals(<stored payload>, [env], registry, False, False)`, which is replaced by a hand-written `VerifyKey` check (A9 item 1: "No key comparison is written in new code"); the counting-role recheck (P1b); and the owner recheck `entry.user_id == authenticated user` (P1c). `already_approved` is keyed on the projection user, not the registry user. |
| 2 Body capped before the DB; no await in a transaction; strict parse | Done for create, approve and publish (P2-P5, P12). `lock_timeout` and `statement_timeout` added (my SHOULD). Code issue and revoke still `await request.json()` uncapped, before the DB (pre-existing; no deadlock). |
| 3 Response before commit; M-4 | Done on the server (P5 gives 400). `loosened` errors refuse in the CLI. |
| 4 Approval strictness, never 500 | **Partly.** Body, envelope and payload keys are exact. The signature dict keys are not exact (P6 stored), and `key_id` is not type-checked (P7, 500). |
| 5 S-1 token path | Done (P8). `if kid:` makes the kind check conditional; `signer_tokens.key_id` is NOT NULL, so this is Low, but the check must be unconditional. |
| 6 List and detail | Built (P9). A malformed `cursor` or `project` raises instead of returning 400. |
| 7 Base = envelope payload; `registry_version` from `verify_chain` | **Partly.** `blob.get("payload", blob)` falls back to the whole blob. A `verify_chain` failure is swallowed into `registry_version = 0`, which fails closed at the connector's step 8 but hides a broken chain. |
| 8 Publish proposer exclusion, revoke role, no-store, one helper, delete dead code | Exclusion, revoke and no-store are done. `_is_project_admin` still has three copies (`api.py`, `enroll.py`, `proposals.py`). `rbac.py` imports `csrf_token_for` but re-implements the cookie split. `auth.py` keeps an unreachable `return None` after `require_fresh_session`. |
| 9 D4 | Done: `proposed_by` gone. 0018 adds only the columns 0007 lacks. The downgrade does not drop `base_sequence` (Low). |
| 10 CLI keys and tokens | Tokens go to `/api/v1/sync/signer/token` with the bare envelope; no `AGG_KEY_HOME`. The mint is hand-rolled over httpx because the frozen tests patch `httpx.Client` (spec 4); its format matches `_get_signer_token` byte for byte. Accepted. `--key-file` is N2. A failed mint is swallowed in `issue-code`, `propose-bundle` and `publish` (C-e). |
| 11 `approve-change` order and checks | The anchor comes first, a fetch failure exits 1, and base verification works (mutation B bites). **The org check is dead code (C-a).** Anchor source (a), an enrolled workspace, is not implemented; that fails closed. With no key the command dies with a traceback (C-d). |
| 12 Display safety; strict `propose-bundle` | Server strings go through `json.dumps(ensure_ascii=True)`. **`propose-bundle` does not check that added keys are server-owned or that sent sections are present (C-b1, C-b2), and N3 accepts a response with no bundle (C-b3).** `base_sequence` and `sequence` fall back to the detail's top level when the hashed bundle lacks them. |

## R2-3. Backend deviations

- **N1 (the S-1c `not_key_owner` check runs before the proposer check): ACCEPTED.** Both are refusals that write nothing. Binding the key to the authenticated token before judging what the approval means is the better order. The lead updates spec 3.5 (3).
- **N2 (`--key-file` accepts a 64-char hex seed): ACCEPTED WITH CONDITIONS.** The frozen tests write hex, and hex is unambiguous. Conditions: (1) the hex form is exactly 64 characters `[0-9a-fA-F]`, with at most one trailing `\n` or `\r\n` removed; (2) the raw form is exactly 32 bytes and is never stripped (C-c); (3) anything else is refused; (4) the report and the docstring stop saying it "wraps `_load_seed_checked`": it does not call it, and `_load_seed_checked` is imported unused. Call `root_exposure(path.parent)` and print its warning to stderr without refusing, because pytest temp dirs on Windows may inherit wide ACLs.
- **N3 (a response with no `bundle` falls back to the local bytes): REJECTED. MUST 12 stands, and no fixture change is needed.** The frozen node's OK half asserts only `correct_hash in output` and `exit_code != 2`. A refusal that names the server's hash as unverified ("server response has no bundle; unverified server hash ...; refusing", exit 1) passes the node as written. I measured this in scratch: the frozen node and the three qa `propose_bundle` nodes all pass (4/4). The fallback also prints, labelled as verified, a hash that no approver will ever see. Nothing goes to the founder for this.

## R2-4. Test-side findings (qa)

- **(a) Browser-key guards.** `_on_admin_route`, `_on_propose` and `_code_issue_403` bite (mutation A). **`_on_publish` is vacuous:** it publishes a random UUID and accepts 404. It must use a real open proposal in the token's org and assert exactly 403, with a cli-token twin that reaches `verification_pending`. Its docstring ("the token route's kind check refuses browser keys") is false: the token route mints browser tokens (P8, T3-F1).
- **(b) The three CLI nodes.** `_corrupted_base_valid_chain_no_post` bites (mutation B). **`_registry_empty_list_exit_1` and `_registry_malformed_exit_1` do not bite on a fail-open regression** (mutation C1): their proposal hash is `"a"*64` / `"b"*64`, so the hash check refuses whatever the registry does. Give each a real proposal payload and hash at base 0, as in `_registry_500_exit_1_no_post`. Their "passes today: product crashes ..." docstrings are stale.
- **(c) Migration 0018 CHECK nodes: not a MUST.** I read the three rows: each one is otherwise valid and violates exactly one CHECK, so a pass can only come from the intended constraint. SHOULD: assert the exact names (`chk_payload_size`, `chk_base_sha_hex`, `chk_sequence_base_plus_one`) so the nodes stay specific if the row data drifts.
- **(d) Q-4 concurrency: neither node bites reliably.** Without `FOR UPDATE`, the multi-session node failed 1 run in 3. With the P12 shape back, the same-session node passed 2 of 2. Fixes: (i) the multi-session node runs at least 8 fresh proposals and asserts `count == 1` for each (miss rate about 2^-8, going by P13's 4 of 8); (ii) a deterministic node parses `proposals.py` with `ast` and fails if any `await` sits inside a `with _conn(...)` block; (iii) the same-session node either keeps 12+ reps or is documented as a liveness check only.
- **(e) Frozen-file edits.** `test_m3_t3_proposals.py` stays within F-1 and FR-1. The stale-base nodes' `require_m3(3, route...)` gates became `require_m3(4, ...)`; that follows from the move to `M3T4Pending` and changes no assertion. The FR-1 gate sits right after the first publish, and `_at_publish` captures publish C. The publisher node matches the ruling. In `test_m3_t3_signer.py`, F-2 matches the ruling. **FR-2 goes one step past the row:** the detail stub of `test_approve_change_diff_from_local_bytes` also gains top-level `"org_id"` and `"project_id"`. The node passes without them (measured), so they must go. Moving the seed into `<key_home>/signer/signer.seed` while still passing `--key-file` is setup, and I accept it.

## R2-5. Seal-test edit (`b509a74`, `tests/unit/test_m3_manifest_seal.py`)

**APPROVED.** `_SEAL_REPLACED` pins exactly the two founder-row paths. I recomputed both hashes from HEAD with LF normalisation, and they equal the pins (`47b119de...` M2_DEMO.md, `4984851d...` test_m2_t11_audit.py). `test_replaced_lines_carry_pinned_hash` requires each path to have been sealed and the manifest to carry exactly the pinned hash. `test_only_named_paths_are_exempt` pins both sets, so adding a third path needs an edit that review will see. SHOULD (needs a founder row): `ee/tests/test_t9_routes.py` is exempt as a whole file under T0b-11. The routes now live in `t1_frozen_routes.json`, so the test file itself need not change from task to task. Pinning its current hash, as `_SEAL_REPLACED` does, would be tighter than a blanket exemption.

## R2-6. Frozen routes (T0b-11)

Not re-signed, because the diff is not approvable. The entries are unchanged from round 1 R3. All five routes now exist as `signer_or_session`/org, and `POST /api/v1/admin/enrollment-codes` is `signer_or_session` with a working token branch, so those entries become correct once the MUSTs below close.

## R2-7. MUSTs

**Backend (W), server (`sync/proposals.py`):**
1. Approval route: once the registry entry is found, call `_verify_change_approvals(json.loads(<stored payload>), [env], registry, is_loosening=False, is_first_bundle=False)` and map `BundleError` to 400 `approval_invalid`. Delete the hand-written `VerifyKey` check. This also brings in the counting-role rule (P1b).
2. Recheck the owner from the registry entry: `entry.user_id != authenticated user_id` gives 403 `not_key_owner`. Key `already_approved` on the registry `user_id` (P1c).
3. Signature dict keys exactly `{key_id, alg, sig}`; `key_id` and `sig` are strings. Any malformed approval gives 400, never 500 (P6, P7).
4. Validate `project_id` (propose) and the list's `project` and `cursor` before any SQL cast: 400 on bad input, never 500 or a reset connection (P2x, P9).
5. Base row: require a dict envelope with a dict `payload`, else 400 (no `blob.get("payload", blob)` fallback). Make the token kind check unconditional (drop `if kid:`), in `enroll.py` too.

**Backend (W), CLI (`change_cmds.py`):**

6. `approve-change` org check: compare the proposal's `org_id` with `chain[0]["payload"]["org_id"]` of the chain that `verify_chain` accepted, and refuse on a mismatch (C-a). Read `base_sequence`, `sequence`, `registry_version`, `org_id` and `project_id` only from the hashed bundle, as ints and strings (no fallback to the detail's top level, no `TypeError`). With no key configured: `ClickException`, exit 1, before any network call (C-d).
7. `propose-bundle` (MUST 12, N3): `bundle` is required, else exit 1 naming the server hash as unverified. Every key the server added must be in the server-owned set, and every section sent must be present and equal (C-b1 to C-b3). Delete the fallback branch.
8. The N2 conditions in R2-3 (C-c). With a key configured, a failed token mint exits 1 in `issue-code`, `propose-bundle` and `publish`, per spec 4 (C-e).

**QA (W), tests (non-frozen files unless named):**

9. (a) Rewrite `test_signer_token_browser_key_refused_on_publish` against a real proposal: assert exactly 403, add a cli twin, fix the docstring.
10. (b) Real proposal hashes in `_registry_empty_list_exit_1` and `_registry_malformed_exit_1`; drop the stale docstrings. Show each one failing under mutation C1.
11. (d) Q-4: the repeated multi-session node and the `ast` no-await-in-transaction node.
12. New nodes, each failing on today's code and passing after the fix: P1b, P1c, P6, P7 (`key_id` int), P2x, P9 cursor, C-a, C-b1, C-b2, C-b3, C-c, C-d, C-e.
13. (e) Remove the extra `org_id`/`project_id` from the FR-2 stub in `tests/security/test_m3_t3_signer.py`. Removing them is the only way to keep the founder row exact, unless the founder widens FR-2.

**Founder rows:** none new. N3 needs none (R2-3). The seal SHOULD on `test_t9_routes.py` (R2-5) is optional.

**SHOULDs:** one shared `_is_project_admin`; `rbac.py` uses a cookie parser exported from `auth.py`; delete the unreachable lines in `auth.py`; the downgrade drops `base_sequence`; propose refuses (rather than defaulting to 0) when a stored chain fails `verify_chain`; audit every publish refusal (`not_found`, `forbidden` and `not_open` are not audited today); sanitise `BundleError` and `RegistryError` text before the CLI prints it; implement anchor source (a), or record its absence as a named limit in the spec; pin the three CHECK names; make `test_t1_17_export_no_fetchall_uses_cursor` independent of cwd. Carried: cap open proposals per project; code issue and revoke read the body capped and after auth.

# Round 3, 16 Nov 2026

Scope: the uncommitted T3 tree at HEAD `b509a74` after a fresh backend (W) built round 2 MUSTs 1-8 and qa (W) wrote MUSTs 9-13. Checked against R2-7, the round 1 probes, the 16 Nov founder rows and ADR 0001 A9 and its addendum. Probes and mutations ran on a scratch copy at `E:\caterpillar\jev-os\.cache\tmp\t3_r3` (repo untouched; every server and container stopped and removed).

**Verdict: REJECT, fix forward (small).** All of round 2's server MUSTs hold. Every round 1 and round 2 probe now behaves as specified, and every qa node I mutated bites. One new CLI change weakens a guarded property: the `_load_key` fallback turns two local fail-closed refusals into acceptance (R3-2). Three MUSTs are only part done: MUST 4 (UUID forms, cursor), MUST 6 (org and type checks) and display safety on refusal paths. Each fix is a few lines.

## R3-1. Measured

| Run | Result |
|---|---|
| ee `--runxfail`: proposals + csrf | 27 passed, 2 failed (both `M3T4Pending`, FR-1 by design) |
| ee `--runxfail`: `test_m3_t3_security.py`, 8 full runs | 67/0 in 6 runs. Three `httpx.ReadTimeout` in the other 2 runs (1 and 2). This is a harness stall, not a product fault (R3-4). |
| root `--runxfail`: `test_m3_t3_signer.py` + `test_m3_t3_signer_security.py` | 40 passed, 0 failed |
| Semgrep `p/python` + `p/secrets`, 12 changed code and test files | 0 findings, 0 errors |
| gitleaks dir (17 changed files incl. docs); gitleaks git (full history) | no leaks |
| trivy fs secret/misconfig (changed files); vuln HIGH/CRITICAL (repo) | 0 / 0; no dependency change |
| ee regression from the repo root: `test_t9_routes`, `test_m2_t7_signer`, `test_m2_t8_enroll`, `test_m2_t9_bundles`, `test_m3_t1_*` | 229 passed, 1 failed: `test_frozen_route_set` (expected, not re-signed, R3-7) |
| root `tests/unit/` | 607 passed, 1 skipped, 2 failed: node-id equality (root 2758 vs 2734, ee 1224 vs 1157), expected until regeneration |
| root `tests/security/` | 2099 passed, 6 skipped, 1 xfailed, 31 failed. All 31 are T3 XPASS(strict) (13 + 18), because the markers are still on; all 40 pass under `--runxfail`. No lexer timing failure in this run. |

Probes (live 4-worker server on pg; stubbed httpx for the CLI):

| # | Spec | Measured |
|---|---|---|
| R1 P1 (approval in an org with no chain) | 400 `no_registry` | 400 `no_registry` |
| P0 counting `cli` key, non-proposer | 201 | 201 |
| P1b `cli` key with `roles: ["viewer"]` | 400, nothing stored | 400 `approval_invalid`, 0 rows |
| P1c projection owner ud, registry owner uc, caller ud | 403 | 403 `not_key_owner`, 0 rows |
| P2-P5, P2x `not-a-uuid` | 400, nothing stored | 400 on all, 0 rows |
| P6 extra key in the signature dict; P7 `key_id` int and the rest | 400 | 400 on all (P7 int now 400, not 500) |
| P8 browser/cli tokens | browser 403; cli works; revoke session-only | as specified |
| P9 list, detail, `project=zzz`, `cursor=zzz` | 200, 200, 400, 400 | 200, 200, 400, 400 |
| P10, P11 | 401; 403 for a random device | 401; 403 |
| R1 P12 / R2 P12 same session; R1 P13 / R2 P13 multi-session | one 201, rest 409 | R2 P12 12/12 and P13 8/8 correct. The R1 variants now get 400 `no_registry`, because their org has no chain, so the R2 variants replace them. 60+60 stress reps: 118 correct, 2 harness stalls (R3-4) |
| **R3-a** `project_id: "urn:uuid:<uuid>"` on propose and list; `urn:uuid:` proposal id on detail, approve, publish; `cursor=2026-W46-1` | 400/404 | **500 on all six**, nothing written. `{<uuid>}` gets **201, and the braced string is stored as `project_id` in the hashed bundle** |
| C-a org B proposal under an org A chain | exit 1, no POST | exit 1, no POST |
| **R3-b** bundle has no `org_id` (detail top-level `org_id` = chain org); bundle `org_id: ""` | exit 1, no POST | **exit 0, approval POSTed** in both cases |
| **R3-c** bundle `registry_version: "9"` | exit 1 via ClickException | exit 1 through a `TypeError` traceback, no POST |
| **R3-d** bundle key `"\x1b]0;pwned\x07"` | no raw ESC | **raw ESC printed** in `Error: unknown field: ...` |
| C-b1, C-b2, C-b3, C-c, C-d, C-e | refuse | refuse; C-c: raw seed ending in `\t` loads, 33-byte file refused; C-d exits 1 without a traceback; C-e makes no POST |
| R1 C1 (registry 500, corrupted base) | exit 1, no POST | exit 1, no POST |
| **R3-e** linked key, `link.json` `key_id` != seed kid | refuse (D4-2) | existing loader refuses; **`change_cmds._load_key(None)` returns the seed** |
| **R3-f** linked key, `root_exposure()` reports exposure (simulated) | refuse (F4) | **returns the seed** (stderr warning only) |
| **R3-g** `signer.seed` present, `link.json` absent | refuse (existing contract) | **returns the seed** |

## R3-2. Item 2: the `_load_key` fallback. MUST, it weakens D4-2 and F4.

`_load_key(None)` catches every `ClickException` from `_load_signer_link_key()` and then loads `<key_home>/signer/signer.seed` through the `--key-file` path. Measured: R3-e, R3-f and R3-g. The existing loader refuses on three grounds, and the fallback turns all three into acceptance:
- D4-2 tamper detection (`link.json` `key_id` != seed kid);
- F4 key-home exposure (`_load_seed_checked` refuses when `root_exposure()` reports one; the `--key-file` path only warns, by N2);
- the link binding itself (no `link.json`).

The result: a seed that others could have read or replaced still signs approvals that the registry then attributes to this user. That undermines non-repudiation, and with it the "two different humans" property. It also breaks MUST 10 / M-13 ("no new loader"). The only test that needs the fallback is qa's `test_approve_change_linked_key_from_signer_seed`. Its key home is not a real linked key home: it holds a hex seed and no `link.json`, while `signer link` writes 32 raw bytes and `link.json`. Removing the fallback in scratch fails that node alone: root T3 files 39 passed, 1 failed. The frozen FR-2 node passes `--key-file`, so it does not depend on the fallback.

## R3-3. Item 3: the two declined SHOULDs

- **(a) Three `_is_project_admin` copies: ACCEPTED for T3, MUST in T4.** Reason: the SQL in the `api.py`, `enroll.py` and `proposals.py` copies is identical, and `role_bindings` is under org-isolation RLS (0002). The only risk is drift. T4 adds the same check to `POST /admin/bundles`, which would make a fourth copy; revoke's inline two-query form is a fifth. T4 moves all of them into one shared helper, with a test that finds exactly one definition.
- **(b) Propose keeps `registry_version = 0` when the stored chain fails `verify_chain`: ACCEPTED for T3, with reason.** Such a proposal can never be approved or applied. The approval route reruns `verify_chain` and refuses with `no_registry`. `approve-change` refuses `registry_version < Registry.version`. The connector's step 8 refuses a version below its pin. The cost is observability: a tampered or expired chain stays silent at propose. Carried to T4 as a MUST: when the stored chain fails, publish refuses with `registry_invalid` and writes `admin_audit` (A9 item 8(b) rebuilds the registry there anyway). Propose doing the same is a SHOULD in T4.

## R3-4. Item 4: do qa's nodes bite?

Each node was run with `--runxfail` against a mutant of the product code (scratch copy):

| Node(s) | Mutant | Result |
|---|---|---|
| `test_approval_non_counting_role_refused_nothing_stored` (P1b) | `_verify_change_approvals` call removed | FAIL (201): bites |
| `test_approval_projection_registry_owner_mismatch_403` (P1c) | registry owner recheck removed | FAIL (201): bites |
| `test_approval_sig_dict_extra_key_400` (P6) | signature key set made a subset check | FAIL (201): bites |
| `test_approval_key_id_int_400_not_500` (P7) | `isinstance(key_id, str)` removed | FAIL (500): bites |
| `test_propose_bad_project_id_400_not_500` (P2x) | `_is_uuid(project_id)` removed | FAIL (500): bites |
| `test_list_proposals_bad_cursor_never_500`, `_bad_project_never_500` (P9) | cursor parse / project check removed | FAIL (500) each: bite |
| `test_signer_token_browser_key_refused_on_publish` (MUST 9) | token kind check removed in `proposals._auth` | FAIL (400 instead of 403): bites. Real proposal; docstring fixed |
| cli twins `test_signer_token_cli_key_publish_reaches_logic`, `_publish_verification_pending` | every token refused | FAIL (403) each: bite |
| `test_approve_change_registry_500_exit_1_no_post`, `_empty_list_exit_1`, `_malformed_exit_1` (MUST 10) | registry failure fails open (`reg = None`, later checks skipped) | FAIL each: all three bite now |
| `test_no_await_inside_conn_transaction` (MUST 11) | `await asyncio.sleep(0)` inside a `with _conn` block | FAIL (line 488): bites, deterministic |
| `test_concurrent_approval_multi_session_repeated` x8 (MUST 11) | `FOR UPDATE` removed | 6 of 8 reps FAIL (2-4 rows stored): bites |
| `test_concurrent_approval_non_proposer_multi_session` | same | FAIL: bites |
| `test_concurrent_approval_non_proposer_same_session` | same | passes. Expected: the `web_sessions` row lock serialises one session. It is a liveness check only; SHOULD say so in its docstring. |
| `test_migration_0018_check_names_exact` | `chk_base_sha_hex` renamed | FAIL: bites |
| C-a `test_approve_change_other_org_proposal_refused` | org check removed | FAIL: bites |
| C-b1 `_refuses_added_section`, C-b3 `_refuses_missing_bundle` | check removed / old fallback restored | FAIL each: bite |
| C-b2 `_refuses_dropped_section` | dropped-section branch made `continue` | FAIL: bites. My first mutant was equivalent: the next line's `KeyError` still refused. |
| C-c `test_key_file_conditions` | strip-based length test (the R2 code) | FAIL: bites |
| C-d `test_approve_change_no_key_exit_1_no_traceback` | no-key guard removed | FAIL (`AttributeError`): bites |
| C-e `test_issue_code_failed_mint_exit_1_no_post` | a failed mint returns `None` | FAIL (POST seen): bites |
| MUST 13 | | done: the only change since R2 in `test_m3_t3_signer.py` removes the two top-level `org_id`/`project_id` lines from the FR-2 stub |

Gap: `test_approve_change_linked_key_from_signer_seed` encodes the R3-2 fallback (R3-6, Q-8). No node covers R3-a, R3-b, R3-c or R3-d.

**The Q-4 flake and the `httpx.ReadTimeout` are a Windows harness stall, not a T3 hang or race.** Reproduced: 3 ReadTimeouts in 8 full runs of the security file, and 2 in 240 stress reps of P12/P13. To trace it, I instrumented the approval handler in scratch (pid, timestamps at entry, after the body read, after auth, after `FOR UPDATE`, and at 201) and logged the server. In the failing rep, three requests ran normally within 60 ms. The fourth entered the handler on worker pid 17480 **10.48 s later**. That worker had no handler activity at all from 1.2 s before the rep until then, and it picked the request up only when the next rep's request arrived. The handler then ran in 48 ms and correctly returned 409; `stored=1`. In all 240 reps, every handler run took under 0.1 s. There was no `lock_timeout` error and no 500. So the request waited in the accept/read layer of four uvicorn workers sharing one listening socket on Windows, before any T3 code ran. Linux CI and the Linux container deployment do not use this path. The R2 deadlock class is gone: the AST node is green and no handler awaits inside a transaction. No assertion may be relaxed for this. SHOULD (devops W, logged in HANDOFF): a Windows harness fix, and a rule that a ReadTimeout on these nodes is rerun once with the server log on, and counts as a product failure only if the handler trace shows time spent inside the handler.

Found on the way (pre-existing M2, not T3): `sync/bundles.py:221` `POST /api/v1/admin/bundles` awaits `request.json()` inside the transaction, after `validate_session` has locked the session row. That is the T3-R1-2 deadlock class. **T4 MUST:** the 410 path returns before any DB work or await. T4's tests-first extend the AST node to all of `ee/src/agg_cp`.

## R3-5. Item 5: frozen-file edits

- `ee/tests/test_m3_t3_proposals.py`: byte-identical to the R2 snapshot, which I ruled within F-1 and FR-1.
- `tests/security/test_m3_t3_signer.py`: F-2 as ruled (stricter assertion, docstring fixed). FR-2 is now exact: `SANDBOX_KEY_HOME`, `--expect-fingerprint`, a bare-list chain stub and a token on mint, all setup. No assertion is changed.
- `ee/tests/test_m3_t3_csrf_catalog.py`: no diff.

Nothing new for the founder.

## R3-6. MUSTs (round 3)

**Backend (W), CLI (`src/sandbox/cli/change_cmds.py`):**
1. (R3-2) Delete the fallback. `_load_key(None)`: if `key_home_root()` is None or `<kh>/signer/signer.seed` does not exist, return `(None, None)` (no key configured). Otherwise return `_load_signer_link_key()` and let its `ClickException` propagate (exit 1). Fix the module docstring: the `--key-file` path does not call `_load_seed_checked`.
2. (MUST 6 completion: R3-b, R3-c) From the hashed bundle only, with no fallback to the detail's top level: `org_id` and `project_id` must be non-empty `str`; `sequence`, `base_sequence` and `registry_version` must be `int` and not `bool`. Anything else is a `ClickException`. `org_id` must equal `chain[0]["payload"]["org_id"]` unconditionally (no `if prop_org and chain_org`).
3. (MUST 12 completion: R3-d) Every server-derived string in a refusal or exception message goes through `_safe_str` or `_check_display_safety`. That covers bundle keys (`unknown field`, `server added ... key`), `sequence`, and the `BundleError`, `RegistryError` and `loosened` exception text.

**Backend (W), server (`sync/proposals.py`):**
4. (MUST 4 completion: R3-a) Accept only the canonical UUID form (`str(uuid.UUID(s)) == s`, lowercase and hyphenated) for `project_id` (400), the list's `project` (400), and the path `proposal_id` on detail, approve and publish (404). Parse `cursor` to a `datetime` and pass that object to SQL, never the string (400 on failure). Then no non-canonical `project_id` can enter a hashed bundle.

**QA (W), tests (non-frozen files):**
5. (Q-8) Fix the setup of `test_approve_change_linked_key_from_signer_seed` to a real linked key home: 32 raw bytes in `signer.seed` and `link.json` with the matching `key_id`. Assertions unchanged. Add nodes for R3-e (mismatch: exit 1, no POST), R3-f (`root_exposure` monkeypatched: exit 1) and R3-g (no `link.json`: exit 1). Each must fail on today's code.
6. Nodes for R3-a (each form, never 500, nothing stored; braced and uppercase `project_id` refused or stored canonical), R3-b (both cases: exit 1, no POST), R3-c (exit 1, `SystemExit`, no traceback) and R3-d (no raw ESC on approve-change and propose-bundle refusals). Each must fail on today's code.

## R3-7. Frozen routes (T0b-11)

Not signed, because the diff is not approvable. The entries are unchanged from R2-6 and are correct for the routes as built: five proposal routes `signer_or_session`/org, and `POST /api/v1/admin/enrollment-codes` `admin` -> `signer_or_session`. Re-sign after R3-6 closes.

## R3-8. SHOULDs carried

- **T4:** one `_is_project_admin` (MUST in T4, R3-3a); `registry_invalid` refusal and audit at publish (MUST in T4) and at propose (SHOULD) (R3-3b); the `admin/bundles` await-in-transaction fix and an AST guard over all of `ee/src` (MUST in T4, R3-4); base row missing at `base_sequence > 0` should refuse, not fall back to `DENY_ALL_BASE` (create route; fails toward more scrutiny today); audit the publish refusals `not_found`, `forbidden` and `not_open`; drop `env_name or "prod"`.
- **This round if cheap, else T4:** the code-issue response `expires_at` still returns the current time (spec 3.3); `test_concurrent_approval_non_proposer_same_session` docstring says liveness only.
- **T9b:** T3-F1 (`cli_key_lookup` mints tokens for browser keys); code issue and revoke read the body uncapped and before auth, and a non-dict body gives 500.
- **Lead:** anchor source (a), an enrolled workspace, is still unimplemented (fails closed). Record it as a named limit in T3_SPEC section 4, or build it.
- **Devops (W):** the Windows harness stall (R3-4).
- Carried unchanged: cap open proposals per project; the optional seal pin for `test_t9_routes.py` (R2-5).

# Round 4, 17 Nov 2026

Scope: the uncommitted T3 tree at HEAD `b509a74` after backend (W) built R3-6 MUSTs 1-4 (`src/sandbox/cli/change_cmds.py`, `ee/src/agg_cp/sync/proposals.py`) and qa (W) wrote MUSTs 5-6 (`tests/security/test_m3_t3_signer_security.py`: the linked-key setup fix and 9 new nodes; `ee/tests/test_m3_t3_security.py`: 8 new nodes). I diffed both against the round 3 scratch snapshot (checked unmutated against its `.orig` copies). Every other T3 product file, migration 0018 and the three frozen T3 test files are byte-identical to round 3. Probes and mutations ran on a scratch copy at `E:\caterpillar\jev-os\.cache\tmp\t3_r4`, with imports checked to resolve to the scratch tree. Every server and container was stopped and removed by its fixture; at the end `docker ps` was empty and no uvicorn or pytest process was left.

**Verdict: APPROVE.** All four R3-6 product MUSTs hold in the code and under probe. Every round 1-3 probe I reran still behaves as specified. qa's new nodes bite on each fix, with one gap (R4-3, test only). No guarded property is weakened. The routes file is signed (R4-6). Three items stay open, and none is a change to this product diff: one qa cursor node before the commit (R4-3); founder row FR-3, because one `test_t9_routes.py` assertion cannot hold for the S-1 routes (R4-5); and a new authorisation finding on the two GET routes, ruled for T4 unless the founder pulls it into T3 (R4-4).

## R4-1. Measured

| Run | Result |
|---|---|
| root `--runxfail`: `test_m3_t3_signer.py` + `test_m3_t3_signer_security.py` (repo) | 49 passed, 0 failed. Normal mode: 40 XPASS(strict) (markers still on), 9 guards pass |
| ee `--runxfail`: proposals + csrf (repo) | 27 passed, 2 failed, both `M3T4Pending: server publish verification (T4)` (FR-1, by design) |
| ee `--runxfail`: `test_m3_t3_security.py` (repo), one full run | 75 passed, 0 failed (67 old + 8 new). No ReadTimeout in this run |
| ee regression from the repo root: `test_m2_t7_signer`, `test_m2_t8_enroll`, `test_m2_t9_bundles`, `test_m3_t1_*` | 222 passed, 0 failed (646 s) |
| `ee/tests/test_t9_routes.py` with the signed file | 7 passed, 1 failed: `test_reviewed_routes_admin_entries_are_admin` (R4-5) |
| root CLI regression: `test_m2_t12d_signer_cli`, `test_m2_t7_signer`, `test_m2_t8_enroll`, `test_m2_t12d_pins` | 158 passed, 1 skipped |
| Semgrep `p/python` + `p/secrets`, the 12 T3 code and test files | 0 findings, 0 errors, 12 scanned |
| gitleaks dir (the 17 T3 files incl. docs); gitleaks git (284 commits) | no leaks |
| trivy fs secret + misconfig (17 files); vuln HIGH/CRITICAL (repo) | 0 / 0; 0. No dependency change in T3 |

Server probes (live 4-worker server on pg, scratch):

| # | Spec | Measured |
|---|---|---|
| R3-a, the round 3 probe unchanged | 400 / 404, never 500 | urn and braced propose 400; urn list 400; the four round 3 cursors 400; urn detail, approve, publish 404 |
| UUID forms: upper, braced, urn, no hyphens, leading space, trailing newline, mixed case, one Arabic-Indic digit, one underscore. On propose and list, and as the path id on detail, approve (with a valid signed body) and publish | 400 (body, query) / 404 (path); nothing stored | as specified on all 39 requests; the project holds only the setup proposal, and it has 0 approvals |
| Cursor, 32 forms (week dates with and without a time, basic format, offsets from -23:59 to +23:59 and `+00:00:00.5`, `+24:00`, years 1 and 9999, NUL, 4000 extra digits, non-ASCII digit, ordinal dates) | 200 or 400, never 500 | 200 or 400 on all 32 |
| Cursor meaning: three proposals at 12:00, 13:00, 14:00 UTC | the same instant gives the same page | `14:00+00:00`, `19:30+05:30`, naive `14:00`, `2026-W47-1T14:00` and `2026-11-16 14:00` all return the first two; `13:00Z` returns the first |

CLI probes (stubbed httpx, scratch):

| # | Spec | Measured |
|---|---|---|
| R3-b: bundle with no `org_id` (detail top level = chain org); `org_id: ""` | exit 1, no POST | exit 1, no POST |
| R3-c: `registry_version: "9"` | exit 1 through ClickException | exit 1, `SystemExit`, no traceback |
| Types: `sequence` True, `base_sequence` False, `registry_version` True or 1.0, `sequence` "1", `org_id` missing, 5 or "None", `project_id` "" or missing | exit 1, no POST | exit 1 on all 10, no POST |
| R3-d and wider: ESC, BEL, C1 CSI (0x9b) and U+202E in a bundle key, a diff value, `environment`, `project_id`, `org_id`, the approval refusal's `error`/`detail`, the registry genesis `kind`, the base envelope `kind`, the proposal id argument; and in the `issue-code`, `propose-bundle` and `publish` refusals | no raw control character in the output | none in any output |
| R3-e, R3-f, R3-g through `_load_key(None)` | refuse | refused with the existing loader's own message (D4-2 mismatch, F4 exposure, no link metadata) |
| The same three end to end: `approve-change` and `issue-code` with no `--key-file` | exit 1, no network call | exit 1 and zero HTTP calls in all six. `issue-code` does not fall back to an unauthenticated POST |
| `signer.seed` absent, `link.json` present | no key configured | `approve-change` exit 1 "no signing key", zero calls |
| A real linked home (32 raw bytes and a matching `link.json`), exposure check not patched | loads and signs | exit 0, approval POSTed |

## R4-2. R3-6 MUSTs

| MUST | Status |
|---|---|
| 1 Delete the `_load_key` fallback | **Closed.** No key home, or no `signer.seed`: `(None, None)`. Otherwise `_load_signer_link_key()`, and its ClickException propagates. The module docstring is fixed. `key_home_root()` lost its `try`, which is fine, because it returns None on every error. |
| 2 Strict types and an unconditional org check | **Closed.** `_require_str` and `_require_int` read only the hashed bundle and refuse bool. The org comparison is unconditional. `chain_org` cannot be None after a successful `verify_chain`, because the genesis fingerprint is computed over a `str` `org_id`. |
| 3 Sanitise server strings in refusals | **Closed** for every server-derived string. Two messages still print raw keys, `server dropped section: {k}` and `server altered {k}`, but those keys come from the user's own bundle file (SHOULD). |
| 4 Canonical UUID; cursor parsed to a datetime | **Closed.** `_is_canonical_uuid` (`str(uuid.UUID(s)) == s`) guards `project_id`, the list's `project`, and the path id on detail, approve and publish. Approve now checks the id before reading the body; a non-canonical id is 404 before auth, which leaks nothing. The cursor object, not the string, goes to SQL. |
| 5, 6 qa nodes | Done. Bite results in R4-3. The positive linked-key node patches `root_exposure` to None. That is setup only, and I accept it: the refusal has its own node, and my unpatched positive probe passes on this machine. |

**Cursor rule (asked by the orchestrator): ACCEPTED.**
- What makes it safe is the `datetime` object. With the string passed back to SQL, 8 of my 32 forms give 500 (R4-3).
- The "contains `T` or a space" check refuses date-only input (`2026-W46-1`, `2026-11-16`, `20261116`). Contrary to its comment, it does not refuse week dates: `2026-W47-1T14:00` and `20261116T120000` parse and are correct (same page as `14:00Z`). Harmless. Fix the comment (SHOULD).
- Offsets: any offset below 24 h, including fractional seconds, parses aware and compares correctly with `timestamptz`. `+24:00` is 400.
- Naive vs aware: a naive cursor binds as `timestamp`, and Postgres converts it with the session `TimeZone` (`Etc/UTC` in the test container), so here it reads as UTC. Under a non-UTC database `TimeZone`, a hand-made naive cursor shifts the page by that offset. The server only emits aware cursors (`timestamptz.isoformat()`), and this affects paging only, never authorisation. SHOULD (T4): 400 on a naive cursor.
- Extremes: years 1 and 9999 with +/-23:59 give 200, with no overflow in psycopg or Postgres. CPython 3.12's `fromisoformat` accepts a trailing NUL and `12,5`. That is harmless, because only the parsed object reaches SQL.
- The query keeps `org_id =`, so a cursor cannot cross orgs. Rows tied on `created_at` at a page edge can be skipped (SHOULD T4: tie-break on `id`). A hand-typed unencoded `+` decodes to a space and gets 400.

**Code-issue `expires_at` (not done): carry to T4, agreed.** Only the response value is wrong. The stored row is `now() + interval '15 minutes'`, and the read route enforces `expires_at > now()` (`enroll.py:434`, `:501`).

## R4-3. Do the new nodes bite?

Each mutant ran under `--runxfail` on the scratch copy. The baseline was 49/0 root and 11/11 for the selected ee nodes.

| Mutant | Result |
|---|---|
| The R3 fallback restored in `_load_key` | `test_linked_key_mismatched_key_id_exit_1`, `_root_exposure_exit_1`, `_no_link_json_exit_1` FAIL: they bite. `test_approve_change_linked_key_from_signer_seed` passes both ways, as expected |
| Org read from the detail's top level when the bundle lacks it | `test_approve_change_bundle_no_org_id_exit_1`, `_empty_org_id_exit_1` FAIL: they bite. The same with the conditional comparison also restored (the R3 code): both FAIL |
| Org comparison made conditional only; empty string allowed in `_require_str` only | all pass. These are equivalent mutants: `_require_str` and the unconditional comparison each block the attack alone, so this is defence in depth |
| `registry_version` read untyped | `test_approve_change_registry_version_string_exit_1` FAILS: bites |
| bool accepted by `_require_int` | `test_approve_change_bool_in_sequence_exit_1` FAILS: bites |
| `_safe_str` removed from `unknown field` / `server added unknown key` | `test_approve_change_esc_in_bundle_key_no_raw_esc` / `test_propose_bundle_esc_in_server_added_key_no_raw_esc` FAIL: they bite |
| `_safe_str` removed from the `loosened`, registry and base-structure messages | **no node fails.** The product is correct today. The path is reachable: an ESC in the base envelope `kind` reaches the terminal raw under the mutant (my probe). SHOULD (R4-7) |
| `_is_canonical_uuid` made `_is_uuid` everywhere | the 7 UUID nodes FAIL: they bite |
| ... at propose only / list / detail / approve / publish | propose: the urn, braced and uppercase nodes FAIL; each other site: its own urn node FAILS. Every site bites |
| Cursor string passed to SQL instead of the datetime (the R3-6 MUST 4 property) | **no qa node fails.** `test_list_proposals_bad_cursor_format_400` sends `2026-W46-1`, which the `T` rule refuses before SQL. My probe: 8 forms give 500 (`2026-W46-1T10:00`, `2026-W46T10:00`, `9999-12-31T23:59:59+23:59` and others) |
| The `T` rule removed (datetime still passed) | `test_list_proposals_bad_cursor_format_400` FAILS. It pins the `T` rule, which is a choice, not the property |

The braced and uppercase nodes use a random `project_id` that is not in the org. They bite through the expected 400 (the mutant gives 404), but their "accepted and stored canonical" branch can never run (SHOULD). The urn approve node posts `{"approval": {}}`, so it never reaches the round 3 500 path with a valid body. It bites through ordering only; my probe covers the valid body (SHOULD).

## R4-4. New finding (Medium-Low): the proposal GET routes ignore project and role

Found while signing the routes file. `GET /api/v1/admin/bundle-proposals` and `GET .../{proposal_id}` admit any org session, a viewer included, and any confirmed `cli` token in the org, with no project-membership or admin check. Spec 3.4 says exactly this ("org members or a confirmed signer token of the org"), and my design review did not object, so this is my miss, not a build defect. T1 made the same content admin- and project-scoped: `GET /api/v1/admin/bundles` is `admin`/`project`. The detail returns the full proposed bundle and, for base >= 1, the served bundle envelope. So a viewer, or a member with no binding to project B, can read project B's current and proposed policy (blocklists, MCP allowlists, clauses). Measured (scratch): a member with zero `role_bindings` rows gets 200 on the list (1 item) and 200 on the detail (bundle included), while `GET /api/v1/admin/bundles?project=` for the same project gives that member 404. That is STRIDE I, inside one org. It weakens none of the five guarded properties: nothing is written, approval still needs a counting registry key, and the connector stays authoritative.

Ruling: **T4 MUST, tests first.** Reads require org admin, admin of the proposal's project (through the shared helper R3-3a moves into one place), or a caller whose key is a counting `cli` registry entry (approvers must still be able to read what they sign). Viewer and other-project callers get the uniform 404. The founder may pull this into T3 before the commit instead. It is a small handler change plus nodes, and it would need one more security (W) diff check.

## R4-5. `test_t9_routes.py`: founder row FR-3 needed (frozen-file edit)

`test_reviewed_routes_admin_entries_are_admin` requires every reviewed entry under `/admin/` to have role `admin`. The five T3 routes are `/api/v1/admin/bundle-proposals...` with `x-agg-rbac` role `signer_or_session`, as the founder's S-1 row and ADR 0001 A9 addendum item 1 require. Recording them as `admin` would be false, and `test_reviewed_routes_role_scope_match_rbac` would then fail instead (measured both ways in scratch). Renaming the paths would break the frozen T3 tests. No fixture-only change exists. `POST /api/v1/admin/enrollment-codes` (now `signer_or_session`) is in the test's earlier frozen set, and `test_reviewed_routes_no_overlap_with_earlier_frozen` forbids listing it again, so its role change is recorded here, not in the data file. No test pins the roles of earlier routes.

**FR-3 (proposed, founder decides):** in `test_reviewed_routes_admin_entries_are_admin`, allow role `signer_or_session` for exactly these five literal `(METHOD, path)` pairs, written into the test as a frozenset that cites S-1, and keep `admin` required for every other `/admin/` entry. A new `/admin/` route with any other role still fails. This narrows the T1 rule to a named list; nothing else is relaxed. Until FR-3 is applied, the file shows 7 passed / 1 failed.

## R4-6. Frozen routes (T0b-11): signed

**Signed: `ee/tests/fixtures/t1_frozen_routes.json`, 13 entries, sha256 `60988cb24381fa39d2ee7fb16d862fe3408b2b3d97e07c2ea521246ac52eace7`** (LF bytes as written; the earlier signature `0e8bc91e...` is superseded). The eight T1 entries are unchanged. Added, all `task: "T3"`, `role: "signer_or_session"`, `scope: "org"`: `POST /api/v1/admin/bundle-proposals`; `GET /api/v1/admin/bundle-proposals`; `GET /api/v1/admin/bundle-proposals/{proposal_id}`; `POST .../{proposal_id}/approvals`; `POST .../{proposal_id}/publish`. The `_comment` now names both reviews. Checks: each pair is registered, and role and scope equal `x-agg-rbac` (`test_reviewed_routes_role_scope_match_rbac` passes); there is no overlap with the earlier sets; `test_frozen_route_set` passes (exact equality). At the commit: regenerate the manifest line for this file and check that it equals this hash. The lead updates the sha256 cited at `M3_PLAN.md:133`. Gitattributes may write CRLF on checkout; the manifest's LF normalisation must give this hash.

## R4-7. Open items

**Before the T3 commit (test only; no further security round, the orchestrator measures it):**
- **R4-Q1 (qa W, `ee/tests/test_m3_t3_security.py`):** one node: `GET /admin/bundle-proposals?project=<real>` with cursors `2026-W47-1T10:00` and `9999-12-31T23:59:59+23:59` (URL-encoded) asserts 200 for each. Show it failing on the string-to-SQL mutant (R4-3) and passing on today's code.
- **FR-3** (R4-5), then `test_t9_routes.py` 8/8.

**SHOULDs:** a node for an ESC in the base envelope `kind` and in a registry error on `approve-change` (R4-3); point the braced and uppercase nodes at `info['project_id']`, and give the urn approve node a valid signed body; delete the now-unused `proposals._is_uuid`; fix the cursor comment; `_safe_str` on the two local-key messages in `propose-bundle`; the same-session node's docstring says liveness only (carried from R3).

**T4:** R4-4 (MUST); 400 on a naive cursor and an `id` tie-break; the code-issue `expires_at` value; everything in R3-8.

**T9b (from reading, not measured):** the R3-a pattern remains in pre-existing M2 routes. `enroll.py:476` (`GET /enrollment-codes/{code_id}`) and `escalations.py:722` and `:1168` check `uuid.UUID(s)` and then cast with `::uuid`, so a `urn:uuid:` id likely gives 500 there. Apply `_is_canonical_uuid`, tests first.

Nothing else goes to the founder.
