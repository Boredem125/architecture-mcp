# T1 security review: admin reads and `record_hash` at ingest

Reviewer: security-engineer (leader tier). Date: 5 Nov 2026. HEAD `975e2bc` plus the uncommitted T1 build.

Scope: `ee/src/agg_cp/sync/audit_upload.py` (diff), `ee/src/agg_cp/app.py` (diff), new `ee/src/agg_cp/sync/admin_reads.py`, new `ee/src/agg_cp/migrations/versions/0017_t1_verification_column.py`, `ee/tests/test_m3_t1_*.py`. Spec: `M3_PLAN.md` T1 row, "Routes M3 adds", threat 38, D1.3, D2.3, S6.

Verdict: **CHANGES.** T1-1 to T1-11 are MUST before the T1 commit. The findings describe the uncommitted build; keep this file with the commit that carries the fixes. One further item is held out of this public file and reported to the orchestrator; it shares the T1-2 fix.

How this was checked: a running 4-worker build on Postgres 16 with `SET ROLE agg_app`, driven by throwaway probes outside the repo. Results marked "measured" come from those runs. The rest is from reading the code.

Scanners on the four product files: Semgrep `p/python` and `p/secrets`, 0 findings; gitleaks `dir`, no leaks; trivy `fs` (vuln, secret, misconfig; HIGH and CRITICAL), clean.

Tests today: `test_m3_t1_*.py`, `test_m2_t11_audit.py`, `test_m2_t16g_audit_contract.py`, `test_t9_routes.py`: 49 passed, 17 XPASS(strict) (markers still on), 1 failed (`test_frozen_route_set`, see "Frozen route set"). The tests prove less than the exit check says: see T1-11.

## Rulings on the ingest hash (question 1)

**The formula is right and the old ruling's wording is wrong.** "From the wire bytes" cannot be built, and not for the reason the builder gave. The connector hashes `json.dumps(record, separators=(",",":"), sort_keys=True)` (`src/sandbox/connector/audit.py:78`), but sends the batch with `json.dumps(body)` (`sync/process.py:168`), which has default separators and insertion order. Measured on real `FolderAudit` records: the wire bytes never equal the hashed bytes, so a wire-slice check would refuse every honest record. Recomputing from the parsed record before storage is the correct implementation. D5, HANDOFF and ADR 0001 A3 should say "from the received record, before storage". The code comment at `audit_upload.py:300-310` is wrong and must be corrected.

**No honest record gets `hash_mismatch` at ingest.** Measured through the real connector formula and the real route: exponent floats, `-0.0`, large ints, non-ASCII, astral characters, nested key order, repeated keys (last wins on the wire, and the connector never emits them). Scrubbing happens before `append`, so the hash already covers scrubbed text. `_wire` strips the same `CHAIN_FIELDS` that `verify_records_bytes` strips.

**Non-canonical wire forms are not stored.** The server stores `json.dumps` of the parsed value, so `1e2` on the wire is stored as `100.0`, under a hash of `100.0`. That accepts a different spelling of the same value and stores nothing the hash does not cover (measured: 200). A changed value is refused (measured: 400). There is no parser differential because raw wire bytes are never kept. Accepted as is.

**The position after the fork branch is safe.**
- A bad hash at an existing position goes to quarantine plus alert (409, measured), which is the right response to a claimed rewrite.
- The idempotent path ignores `body`: same hash with a different body returns 200 `noop` (measured). Nothing is stored and the stored row stays append-only, so this is safe. Info: T9b could alert on it.
- The fork commit keeps earlier records of the batch, and those passed the hash check.

**The purpose is not met, because the jsonb edge is still there.** See T1-2. The ruling existed because jsonb changes values after the check. An ingest check, from any bytes, cannot fix what storage does afterwards.

## Findings

### T1-1 HIGH (MUST): the ingest check is skipped when `body` is absent

`audit_upload.py:311` guards the check with `if rec_body is not None`. Measured: a record with no `body`, or `body: null`, and an arbitrary `record_hash` is 200 and stored. Non-object bodies (list, string, number) pass ingest and always fail `verify_project`, whose helper accepts objects only. So the T1 exit check does not hold for those records. `verify_project` catches them later, as a permanent red.

Fix: refuse anything that is not a dict with 400 `hash_mismatch`, nothing stored, and compute with `_canonical_record_hash` from `sync/audit.py` so there is one formula. No frozen test uploads a record without a body at a new position (`test_m2_t11_audit.py`, `test_m2_t16g_audit_contract.py` read).

### T1-2 HIGH (MUST): a record can pass ingest and fail `verify_project` forever

`audit_records.body` is `jsonb`, which stores numbers as numeric. Measured on Postgres 16: `1e16`, `1e22`, `1.5e300` come back as integers and `-0.0` as `0.0`, so the recomputed hash differs and `GET /audit/verify` reports `hash_mismatch` for an untampered record. Records are append-only, so it cannot be repaired. The export carries the changed value too, so an offline check fails the same way. Effect: false tamper findings, and a device that can keep its own project red hides a real one among them.

Fix: `ALTER TABLE audit_records ALTER COLUMN body TYPE json USING body::json` (same migration). `json` keeps the text as written. Measured on the migrated schema: the alter succeeds with the no-update trigger on, the trigger still holds, an old row reads back, and exponent floats, `-0.0`, non-ASCII and nested key order all recompute correctly. Nothing queries `body` with jsonb operators. M2 rows already normalised stay as they are; name that in the migration. Downgrade to `jsonb` may refuse rows jsonb cannot hold, which is acceptable.

Alongside: a record body the store refuses must never be a 500. `NaN` and `Infinity` stay invalid in `json`, so refuse them with a named 400 and write a server-side `sync_alerts` row (`audit_record_unstorable`). Today (measured) they are 500.

Add the property as a test: every record the route accepts verifies under `verify_project` and in the export.

### T1-3 HIGH (MUST): `/admin/*` declares admin and enforces any membership

`admin_reads.py:243, 297, 338` declare `role="admin"`, but `_project_in_org` (`:96`) admits `admin, viewer, policy_author, approver, auditor`. Measured: all four non-admin roles get 200 on enrollment-code status, the bundle list and the bundle detail, envelope included. The `x-agg-rbac` metadata is therefore false.

Fix: `_is_project_admin` semantics (`api.py:137`) on all three, uniform 404, one negative node per role per route.

### T1-4 HIGH (MUST): audit bodies reach roles the plan does not intend

`:483` and `:510` are `role="session"`. Measured: a `viewer`, and a project-scope `approver` or `policy_author`, can export every audit body in the project and run verify. Bodies carry commands and targets from every device, and scrubbing can be switched off by policy. The existing `GET /org/audit/verify` allows org admin and auditor only (`api.py:149`, `:834`), so this widens access. An approver needs the escalation in front of them, which the inbox already serves, not the whole project's history.

Fix: export and verify are project admin or org admin or auditor, declared accordingly. `/devices` and `/alerts` may stay at project read roles: hostname, operator id, public key and alert detail are project metadata, and the approve page needs device context.

### T1-5 HIGH (MUST): cursors break across workers

`_CURSOR_KEY = os.urandom(32)` at `:47` is per process. Measured on 4 workers: 22 of 24 fresh requests for page 2 returned 400 `bad_cursor`. `test_cursor_bound_to_org` only asserts the refusal, so it stays green.

Fix: either a key all workers share (never the bundle signer key), or no MAC with a strict UUID parse plus the org compare; RLS and the project filter already bound what a forged position can reach. Keep foreign and garbage identical (that part is correct today). Return a fresh response per request rather than the shared `_BAD_CURSOR` object. New node: walk every page repeatedly on the 4-worker fixture.

### T1-6 HIGH (MUST): `applied_by` states something false

`:408` lists every project device with `last_seen` set as having applied this bundle. Being seen is not applying: a device that refused the bundle would be listed, and so would a revoked one. Also, nothing under `ee/src` or the migrations writes `connectors.last_seen`, so in production the list is always empty and the `last_seen` field in `/devices` is always null, while the test seeds the column by hand. No signed source for "applied" exists today.

Fix: return `applied_by: null` with `applied_by_status: "not_reported"` until a device-signed source lands (lead decides: the checkpoint is the natural place; a T9b row). Do not show `last_seen`, or derive it from `audit_heads`. **`test_bundles_detail_applied_by_devices` asserts the false behaviour, so changing it needs a founder row** (`M3_BASELINE.md` section 2, rule 3).

### T1-7 MEDIUM (MUST): approvals imply a check that did not happen

The plan says "verified approvals by user and kind". `:393` returns stored rows. `user_id` is the server's own `cli_key_lookup` result at publish, not client text, which is good; `kind` comes from `approver_keys`. But M2 publish checks only that the key exists, never the signature (T4 adds that). A page showing "alice, cli" beside an `m2_unverified` bundle reads as a verified approval.

Fix: each approval carries `signature_verified: false` until T4 sets it true for `server` rows. The `verification` label itself is shown as stored and implies nothing further.

### T1-8 MEDIUM (MUST): the export is not usable as evidence

`:542-579`:
- No `connector_id`, while session ids such as `sync` repeat per device, so chains cannot be separated offline (measured).
- `LIMIT 10000` truncates silently, so a partial export looks complete. Add a truthful marker (`X-Export-Truncated` plus a final metadata line) or a continuation.
- The count is bounded but the bytes are not: up to 10,000 rows of up to about 1 MiB each are built in memory. Add a byte cap, and stream for real.
- `ORDER BY created_at` is not stable: a batch shares one `now()`. Tie-break on connector, session, chain length.

Correct already: `no-store`, `application/x-ndjson`, attachment, every line JSON-escaped with `ensure_ascii`, so a device string cannot start a new line. No JSONL injection. The filename comes from the raw parameter, reached only after it parsed and Postgres cast it; normalise it (T1-9).

### T1-9 MEDIUM (MUST): page bounds and error shapes

- `:259` enrollment codes and `:313` bundle list have no limit or cursor. The plan and this file's own docstring require cursor pagination. `:456` alerts stops at 500 with no continuation. `applied_by` and `gaps` are unbounded.
- A bad `since` or `until` (`:449`, `:526`) is a 500 (measured). It must be 400.
- `uuid.UUID` accepts spellings Postgres does not: the `urn:uuid:` form passes the membership check and then 500s on the raw string (measured). `_project_in_org` should return the parsed id, and every later query, and the filename, should use `str(pid)`.
- `_compute_section_diff` assumes `sequence - 1`. Sequences may skip (ADR 0001 A1, "lowest sequence above after"), and a missing predecessor shows every section as new. Use the highest lower sequence and return which one was compared.
- A corrupt blob returns 200 with an empty envelope and a clean-looking diff. Use `corrupt_bundle`, as `bundles.py` does.

### T1-10 MEDIUM (MUST): device detail and verify under-report

`GET /devices/{id}` has none of the plan's checkpoints, sessions, open escalations or quarantine rows (`:212`). A forked device looks healthy, and T8's badge has nothing to read. `GET /audit/verify` returns `ok: true` with a quarantine row present and with a stored chain shorter than the device's signed checkpoint, because it proves stored-chain integrity only (`:504`). Keep `verify_project` semantics, but add to the response `checked: "stored_chains_only"`, record and session counts, and `quarantine_rows`. Comparing heads against the latest checkpoint is a T9b SHOULD.

### T1-11 MEDIUM (MUST): the exit checks are not proven

- `test_changed_float_exponent_hash_mismatch` flips a hash byte on a body with no exponent, sent through `json=`. It would pass with no float handling at all. Add a raw-bytes node: exponent changed against the hash is 400; the same value spelled differently is 200 and stored as the canonical value.
- `test_guard_rls_catalog_unchanged` passes with 4 of 7 tables and never reads `relforcerowsecurity`. Measured by hand: the 11 tables checked, which include every table these routes read, have RLS and FORCE on, `agg_app` has no bypass, and no `app.org_id` means 0 rows. Add a node that pins it.
- `test_devices_detail` claims checkpoints and asserts only the id.
- Foreign-org coverage exists only for devices and bundles. Add `/devices/{id}`, codes, bundle detail, alerts, verify, export.
- Also new: every T1-1 to T1-10 fix. Use a new tests-first file, `ee/tests/test_m3_t1_security.py`, so appending needs no founder row.

## Rulings on migration 0017 (question 2)

Landing the columns now is right: T1 reads the label, and every row is `m2_unverified` until T4 writes something else. Revision chain, RLS and downgrade are fine: no policy DDL, FORCE unchanged, and a full downgrade and upgrade ran clean (measured).

- **CHECK, MUST now.** `verification IN ('server','m2_unverified')`, and `verified_at` set exactly when `server`. One line today; a free-text label is wrong forever after.
- **Label forgery, T4 MUST.** `agg_app` has no UPDATE on `policy_bundles` (measured), so a label cannot be flipped later, but it can INSERT `server` directly and the DB cannot tell. T4 must add: a single writer pinned by an `ast` test, the planned `test_direct_publish_rows_labelled_m2_unverified`, and the rule that the label is the server's statement, not proof. Evidence (T7) re-verifies retained approvals and never trusts the label.
- **`acked_at`:** keep the column so the list can return it, but **remove the GRANT from 0017 (MUST)**. It is unused privilege on a table that was INSERT and SELECT only, and an ack with no actor hides an alert with no record of who did it. T8 grants it alongside `acked_by` and an `admin_audit` row.

## Other items checked, no change

Org scoping under FORCE RLS; uniform 404 for foreign, missing and non-member; foreign and garbage cursor identical; session auth on all eight routes; parameterised SQL (the f-strings hold static clauses only); `code`, `code_hash` and tokens never selected; no command output in audit records (`stdout`/`stderr` do not enter `_audit`); device strings (`hostname`, `session_id`, alert `detail`) only ever returned as JSON, with `nosniff` from Caddy (`ee/deploy/Caddyfile:29`), and S6 binds the page in T2 and T8. Diff sections match the five enforced ones; `expires_at`, `not_before` and `registry_version` sit outside them, and the page should show them (T2 note).

## Frozen route set

`test_frozen_route_set` must keep exact equality, so an unknown route fails and a missing route fails. Requirements for the one founder row:

1. The frozen file gains exactly one set: literal `(METHOD, path)` pairs from one reviewed data file. No wildcard, prefix or regex.
2. Each entry names task, role and scope. The test asserts the entry equals the route's `x-agg-rbac`, so a route cannot quietly weaken its role.
3. The file lists what is registered at that commit, never planned routes, so removing a landed route still fails. Removing a line needs a founder row; entries may not overlap the frozen set.
4. The file joins the server TCB list: security (L) signs each addition. It is appended by the task's tests-first commit and is under the manifest.
5. `test_all_api_routes_declare_rbac` and `test_planted_undeclared_route_detected` stay unchanged. Add planted-extra and planted-removed controls. Any `/admin/` entry must be `admin`, backed by a behavioural negative node (T1-3); metadata alone proved nothing here.

## Round 2 (5 Nov 2026)

Reviewer: security-engineer (leader tier). HEAD `975e2bc` plus the uncommitted T1 fixes.

Verdict: **CHANGES.** T1-12 to T1-25 are MUST before the T1 commit. T1-1, T1-6 and T1-7 hold (tests and reading). T1-3 holds as measured below, and T1-5 and T1-10 hold apart from T1-19, T1-18 and T1-25. T1-2, T1-4, T1-8, T1-9 and T1-11 are partly closed. One item stays out of this public file: see "Held-out item".

How this was checked: a 4-worker build on Postgres 16 with `SET ROLE agg_app`, driven by throwaway probes outside the repo. Everything is measured unless it says "from reading".

Tests: `test_m3_t1_security.py`, `test_m3_t1_admin_reads.py`, `test_m3_t1_record_hash.py`, `test_t9_routes.py`, `test_m2_t11_audit.py`, `test_m2_t16g_audit_contract.py` with `--runxfail`: 126 passed. The backend's count is true. Its "streams" claim is not (T1-17), and the green suite misses every finding below (T1-24).

Scanners on the changed product files, `test_m3_t1_security.py`, `test_t9_routes.py` and the route file: Semgrep `p/python` and `p/secrets`, 0 findings; gitleaks `dir`, no leaks; trivy `fs` (vuln, secret, misconfig; HIGH and CRITICAL), clean.

### Ruling on per-record `session_id` (question 1): revert

**It is a contract change, with no reason to keep it.** ADR 0001 5.2 and A4.1 define `{session_id, records:[{chain_length, previous_hash, record_hash, body}]}`. The connector's `_wire` (`src/sandbox/connector/sync/audit_upload.py`) never sends a record-level `session_id`, and it reads `server_head` as the end of one chain. The only caller is a test written without checking the contract.

What it does not break: the connector id comes from the token, so a batch never reaches another device's chain. Head, gap and fork checks run per record against the named chain (measured: a fork named per record inside a batch for a clean session is 409 plus quarantine).

What it does break:
- It bypasses the batch-level check at `audit_upload.py:135`. A record `session_id` of a number, object, bool, or a string with NUL or a lone surrogate is 500. A list is 200 and stores a chain under a non-string name. `0`, `""`, `[]` and `{}` silently fall back to the batch value.
- `server_head` names only the last chain, while the batch names another.
- The fork commit keeps earlier records of a different chain.
- One request can create 1000 sessions instead of one. Measured: 10,000 sessions from 40 batches, then one `GET /audit/verify` takes 15 s and one `GET /devices/{id}` returns 9 MB.

**T1-12 HIGH (MUST).** Remove `rec_session_id` (`audit_upload.py:177` and every use). A record carrying `session_id` different from the batch is 400 `bad_body`; equal is allowed, because `test_m2_t11_audit.py` and `test_m2_t16g_audit_contract.py` send it equal. If a frozen node disagrees, report its id rather than relax.

Change `test_t1_8_export_stable_order` (`test_m3_t1_security.py:977`, new file, no founder row): one batch per session per connector, uploaded in reverse order (second connector first, `beta` before `alpha`), plus one multi-record batch for the shared `now()` tie within a chain. Keep the three identical exports and the exact sort.

### Findings

**T1-13 HIGH (MUST): `except Exception` at `audit_upload.py:417` labels everything unstorable.** It catches `UniqueViolation`, so the 409 `duplicate_record` branch at `:463` is dead. Measured: 25 rounds of 8 concurrent uploads of the same record gave 9 responses of 400 `audit_record_unstorable`, 9 false alert rows and no 409. A database outage would also read as a bad record (from reading). No body reached this branch in any probe; only the race and `chain_length: true` did. Catch only `psycopg.errors.DataError` and `psycopg.errors.StatementTooComplex`. Everything else keeps its old path.

**T1-14 HIGH (MUST): a refused batch is half written.** `:344` commits the open transaction with the alert. Measured: `[valid, valid, NaN]` is 400 with 2 rows stored and 1 alert, under the comment "All-or-nothing" (`:163`). The rows are valid, so nothing false is stored, but a 400 must store nothing. Use one helper: rollback, re-apply `SET ROLE` and `app.org_id`, insert the alert, commit.

**T1-15 HIGH (MUST): T1-2 "never 500" does not hold.**
- Nesting at or above about 2,990 levels (this Windows Python 3.12 build; the limit is platform-specific) raises `RecursionError` at `:120`, which only catches `ValueError`: 500 for objects and arrays up to the size cap. Catch it, and make it a named 400 plus one alert once the token is known. Add `RecursionError` at `:325` too. The boundary case itself is fine: depth 2,989 was accepted and verify, export and the CLI all read it.
- `chain_length` of a string, list or object is 500 at `:209`; `true` writes a false alert; `1.0` is stored. Refuse anything but a real `int` with 400 `bad_body`.
- A batch `session_id` with NUL or a lone surrogate is 500. See T1-18.
- A number past the parser's digit limit is 400 `invalid_json` with no alert. Named, accepted: the connector cannot produce one.

Measured and correct: `\ud800`, `\udc00`, `\u0000` in values and keys, `1e16`, `1e22`, `1.5e300`, `-0.0`, `1E+2`, `1e-400`, `5e-324`, 30-digit and 4,300-digit integers are all 200. Every accepted record verifies under `verify_project`, under `cli.main`, and offline from the export (60 of 60). `NaN`, `Infinity`, `-Infinity`, `1e999`, `-1e999` are 400 `audit_record_unstorable` with exactly one alert. A later valid upload is accepted in every case.

**Ruling on the text cases.** Storing `\ud800` and `\u0000` is right. `json` holds them, they hash and verify, and refusing them would put back the problem the migration removed. `test_t1_2_lone_surrogate_no_500` says the opposite and passes only for an unrelated reason (T1-24).

**T1-16 HIGH (MUST): the row limit makes the header false.** `admin_reads.py:833` still has a silent `LIMIT 10000`. Measured: a project with 10,050 rows gives 10,000 lines, `X-Export-Truncated: false`, no final line, while verify reports `record_count: 10050`. Either limit firing must set the flag and the final line (fetch one row past the limit).

**T1-17 HIGH (MUST): nothing streams and memory is not bounded.** `StreamingResponse(iter([content]))` at `:881` sends one pre-built string, after `fetchall` at `:835` and `list(_generate())` at `:878`. Measured: 120 rows of 1 MB raise one worker's peak by 243 MB to serve a 9 MB response, with the first byte after the full build. Memory follows the stored rows up to 10,000 times the 1 MiB body cap, not the 10 MB cap. `verify_project` has the same shape (`audit.py:206`): 245 MB on that chain, and the route is new in T1, so a web request now reaches it.

*Header truth.* It is true today only because the body is built first. A header cannot report a cap that fires later in a real stream.

*Ruling, replacing "stream for real" in T1-8.* Buffering is fine if it is bounded by the cap. Read through a named server-side cursor in small batches, stop at the cap, then send a plain `Response` with `Content-Length`. Peak memory is then the cap plus one batch. Delete `StreamingResponse` and the word "streamed" from the docstring (`:14`). Do the same for the rows in `verify_project`: iterate, never `fetchall`.

*The final line, measured.* It appears only when truncated. A device cannot forge it: a body containing `_meta` and newlines, and a `session_id` containing newlines, stayed one escaped line with no top-level `_meta`, header `false`. Reserve its bytes: today the body can pass the declared cap by the line's length when the rows end just under it. SHOULD: emit the final line always, with `truncated`, row and byte counts, because a saved file loses its headers. Continuation is a T8 question for the lead; a truncated export today has no way to the remainder.

**T1-18 MEDIUM (MUST): one device can flood the new reads.**
- Measured: 40 identical refused uploads made 40 alert rows. Alert detail reached 1,000,037 bytes, because the `session_id` has no length limit. One `/alerts` page was 9 MB. Twenty fork rows with an oversized `record_hash` made one `/devices/{id}` response 20 MB. Alert rows stay valid: a project read role sees them, but nothing else leaks.
- Bound the input: batch `session_id` at most 256 characters, no NUL or surrogate, else 400 `bad_session_id`; `record_hash` and `previous_hash` must be strings of at most 128 characters, before the fork branch. No hex rule, because `test_m2_t11_audit.py` forks with a plain string.
- One `audit_record_unstorable` row per connector, session and position, checked before insert. The repeated fork alert is T11 behaviour: log a T9b row.
- `/devices/{id}` `sessions` (`:299`, no `LIMIT`) and `/audit/verify` `gaps` get a limit and a truncated flag (T1-9 named `gaps`).

**T1-19 MEDIUM (MUST): the cursor parse is not strict.** `:73-74` accept whatever `uuid.UUID` accepts, and the comment at `:72` is false. Measured on all four cursor routes: `urn:uuid:`, underscores and non-ASCII digits in the position are 500; braces and no hyphens are 200. Require `str(uuid.UUID(x)) == x` for both parts.

Otherwise T1-5 closes:
- 12 full walks of 46 devices on 4 workers: same order, no duplicates, no `bad_cursor`.
- Foreign and garbage are byte-identical, headers included, with overlapping medians (31 to 41 ms), and neither reaches a project query. Each response is a fresh object.
- A position from another org's row returns only this project's rows, so a forged position reaches nothing outside the filter.
- The token reveals only the caller's own org id and a row id already in the page.

**T1-20 MEDIUM (MUST): `since` and `until`.** `:658`, `:816` and `:819` validate with `fromisoformat`, then send the raw string to Postgres. Measured: `2026-W45-4`, a comma fraction and an offset of `-23:59` are 500. Send the parsed value.

**T1-21 MEDIUM (MUST): corrupt blobs still 500.** Non-UTF-8 (`:558`, outside the `try`), a JSON list or string (`:590`), a non-object `payload`, and the same in the predecessor (`:937`) are 500. So one bad row breaks its own detail and the next sequence's. An unparseable predecessor gives a diff against nothing with no flag. Use one helper returning the payload or `None`, plus `corrupt_bundle` and `diff_base_corrupt`.

**T1-22 MEDIUM (MUST): `auditor`/`project` is not what the route does.** A project-scope auditor is 404 on verify and export (`:147` allows only project `admin`), so the metadata is false in the safe direction. Allow `role IN ('admin','auditor')` at project scope. Add nodes for a project auditor, an auditor of another project (404), and `auditor` in `_NON_ADMIN_ROLES` (T1-3 asked for every role).

Measured role matrix, otherwise correct:
- `/devices`, `/devices/{id}`, `/alerts`: 200 for all five roles at org or project scope.
- `/admin/*`: 200 for org and project admin only, 404 for the other eight.
- `/audit/*`: 200 for org admin, project admin and org auditor.
- 404 for a binding on another project, no binding, and org B. 401 for a signer or device bearer token, either one sent as the cookie, and no credential.

**T1-23 HIGH (MUST, found under question 8): `python -m agg_cp.cli` does nothing and exits 0.** `ee/src/agg_cp/cli.py` has no `__main__` guard. Measured: `audit verify --project not-a-uuid` with no database URL is rc 0 with no output. `cli.main` itself works (rc 1 on the same input; rc 0 and `ok: true` on real projects). So `ee/deploy/demo.py:1527` and `ee/deploy/m2_gate.py:680, 789, 844` have been recording a pass without running a check, and the server-side `audit verify` results in M2's gate runs prove nothing. Both scripts are frozen and need no edit. Add the guard and a subprocess node (bad input is non-zero). Then re-run the gate on a fresh stack and correct `M2_DEMO.md` with what it measures. Not exploitable; it is a verification that fails open.

**T1-24 MEDIUM (MUST): T1-11 is not proven.** Green here means little:
- `test_t1_2_lone_surrogate_no_500` (`:604`) sends a hash of zeros, so its 400 is `hash_mismatch`, and its alert count is project-wide, so another test's row satisfies it. Rewrite with the correct hash: 200, stored, verify ok, offline hash ok. Add `\u0000`.
- NaN and Infinity nodes (`:502`, `:552`) count alerts project-wide with `>= 1`. Assert a delta of exactly 1. Add `-Infinity` and `1e999`.
- `test_t1_8_export_byte_cap` (`:1054`) uploads 120 KB against a 10 MB cap, so its truncated branch never runs. `test_t1_8_export_truncation_marker` (`:955`) checks only that the header exists. Add a real run past the cap and past the row limit, and assert peak memory is bounded.
- `test_t1_10_device_detail_fields` (`:1407`) passes on empty lists. Seed a fork, a checkpoint and an escalation, and assert the values and that no `record` content appears. `test_devices_detail` still asserts only the id; this node carries the claim.
- `test_t1_10_verify_response_fields` (`:1430`) says "exact" and asserts `>=`.
- `test_t1_11_rls_force_on_all_route_tables` (`:1620`) omits `audit_heads` and `audit_quarantine`, which the new device detail reads. Both have RLS and FORCE on by hand (13 tables checked, `agg_app` no bypass).
- New nodes: T1-12 to T1-23, including the race and the half-written batch.
- `test_t9_routes.py::test_reviewed_routes_role_scope_match_rbac` still has an `xfail(strict)` marker whose reason is out of date. Remove it with the rest.
- `t1_server` (`test_m3_t1_admin_reads.py:258`) dropped `applied_by_device=`. Ruling T0b-12 names one test, not this fixture, and the seed is what proves `last_seen` does not produce `applied_by`. Restore it.

**T1-25 LOW (MUST, because the fixes touch every copy): size and duplicates.**
- `admin_reads.py` is 951 lines, with the cursor block four times and the session-and-project head eight times, so each later change lands up to eight times. Use `_page_after` and `_project_for`.
- `audit_upload.py` has the alert insert three times. `:359-364` is a no-op and `:365-391` is dead (`json.loads` of `json.dumps` output cannot fail). Delete both.
- The hash formula is still duplicated at `:320`; T1-1 asked for one formula with `sync/audit.py`. Take one `canonical_record_bytes` with `allow_nan=False` for ingest.
- The comment at `:312-318` still gives the wrong reason; ruling 1 of this file has the right one.
- The `0017` docstring's "none expected from the connector" is false: the connector stores `\u0000` (see "Migration 0017").
- `:309` `status != 'done'` invents a state: nothing under `ee/src` writes `escalations.status` after insert (from reading), and the inbox uses `= 'pending'`. Match the inbox. Whether a decided escalation stays `pending` is a T9b question for the lead; "open" means no more than the inbox's list does.
- SHOULD (T8 row): alerts sort by random UUID, so a new alert can sit on the last page.

### Other questions

**Migration 0017 (question 7): no change beyond the docstring.** Upgrade on populated rows, including a null body: body text unchanged, the no-update, no-delete and no-truncate triggers all present, update and delete refused, `chk_verification_value` and `chk_verified_at_coupling` present and enforced (free text, `server` without a time, a time without `server` all refused), existing bundles `m2_unverified`, `agg_app` has no UPDATE on `sync_alerts`, `policy_bundles` or `audit_records`, RLS and FORCE unchanged. Downgrade and second upgrade ran clean. A downgrade with a `\u0000` row is refused in one transaction: head stays, rows and constraints intact. Named: the downgrade renormalises numbers, and M2 rows normalised by `jsonb` keep showing `hash_mismatch`. A null-body M2 row does too.

**Readers (question 8).** `_canonical_record_hash` gives the same hash from a dict and from text. psycopg returns `json` as a dict, so the `str` branch is a fallback. Nothing outside tests selects `body`: `ee/deploy` has no such read, `m2_gate.py` psql reads only `audit_quarantine` and `sync_alerts` (both still `jsonb`), `evidence.py` reads local files, and `test_m2_t16g_e2e.py:1357` handles both types. Alert inserts with `%s::json` into a `jsonb` column work. See T1-23 for the CLI.

**Device detail (question 6, T1-10).** The new fields are checkpoints, session ids, escalation id and status, and quarantine rows. Escalation `record` is not selected (seeded command text absent). Project scope holds (another project's admin 404, org B 404), and all 13 route tables have RLS and FORCE. Only T1-18 and T1-25 apply.

**`test_devices_list_returns_devices` (T0b-14): sound.** The walk stops at a null cursor, keeps every status check, is bounded at 100 pages and fails closed past that, and the assertion is unchanged.

### Held-out item

It closes for the text cases: records with those values, written by the real `FolderAudit` and sent by the real uploader, were all stored and verify clean. One residual goes to the orchestrator and not into this file.

### Frozen route set, signature (ruling T0b-11)

**Signed: the eight entries of `ee/tests/fixtures/t1_frozen_routes.json`, sha256 `0e8bc91ee95d29b10a28d169b9de82582c44255b4e2132a3db507738559561be`,** on these conditions:

1. Literal pairs from one data file, one set: holds.
2. Task, role and scope per entry; the test asserts role and scope against `x-agg-rbac`: holds. `auditor`/`project` becomes true with T1-22, and the entry does not change.
3. Registered routes only, no overlap, exact equality: holds. Planted-extra and planted-removed controls work.
4. Under the manifest and on the TCB list: **not yet.** Manifest line 9 holds `2e4fe28e...`, not this file's hash, so regenerate it at the commit and check it equals the signed hash. `M3_PLAN.md:133` needs both this file and `sync/admin_reads.py`, which already calls itself server TCB.
5. `test_all_api_routes_declare_rbac` and `test_planted_undeclared_route_detected` unchanged; `/admin/` entries are `admin` with behavioural negatives: holds once `auditor` joins them (T1-22).

A change to any entry needs a new signature.

## Round 3 (9 Nov 2026)

Reviewer: security-engineer (leader tier). HEAD `975e2bc` plus the uncommitted T1 tree after the round 2 build, the `conn.transaction()` reader fix, the `DATABASE_URL` fallback and qa's test changes.

Verdict: **CHANGES.** T1-12, T1-13, T1-14, T1-16, T1-19, T1-20, T1-22 and T1-23 are closed. T1-15, T1-18, T1-21 and T1-24 are closed except for the parts listed below. T1-17 is open in substance: peak memory is unchanged since round 2. T1-25 is partly open. New: T1-26 (MEDIUM, and it turns CI red once the markers go), T1-27 (LOW) and T1-28 (LOW). All open items are MUST before the T1 commit. The `M3T1Pending` markers stay on until round 4.

How this was checked: a 4-worker build on Postgres 16 (testcontainers, `SET ROLE agg_app`, an isolated database), driven by throwaway probes outside the repo. Peak memory is each worker's `PeakWorkingSet64` before and after the request, taking the largest change across the workers (Windows, Python 3.12.10). Linux behaviour was measured in Docker with `python:3.12-slim` (3.12.15), `python:3.15-rc` (3.15.0rc3) and `postgres:16-alpine`. Everything is measured unless it says "from reading".

Scanners on the six changed product files (`sync/audit_upload.py`, `sync/audit.py`, `sync/admin_reads.py`, `app.py`, `cli.py`, migration `0017`): Semgrep `p/python` and `p/secrets`, 0 findings and 0 errors (6 files scanned); gitleaks `dir`, no leaks (also on `test_m3_t1_security.py`); trivy `fs` (vuln, secret, misconfig; HIGH and CRITICAL), clean.

Tests: `test_m3_t1_security.py`, `test_m3_t1_admin_reads.py`, `test_m3_t1_record_hash.py`, `test_t9_routes.py`, `test_m2_t11_audit.py`, `test_m2_t16g_audit_contract.py`, plus the two frozen `test_m2_t16g_e2e.py` `verify_project` nodes, with `--runxfail`:
- With the repo's 30 s per-test timeout, both runs stopped in `test_t1_18_repeated_refused_uploads_one_alert` (see T1-24).
- With `--timeout=120`: 188 passed in 601 s. That node took 54.9 s.

I did not re-run the full ee suite. The orchestrator's count (0 non-T1 failures) is the only figure for it.

### Status of T1-12 to T1-25

| Item | Status | Evidence |
|---|---|---|
| T1-12 record `session_id` | closed | A record `session_id` equal to the batch, `null` or absent gives 200. `"T"`, `0`, `""`, `[]` and `{}` give 400 `bad_body`. `rec_session_id` is always the batch value (`audit_upload.py:233-242`). |
| T1-13 `except Exception` | closed | 25 rounds of 8 concurrent identical uploads: 183 responses of 200 and 17 of 409 `duplicate_record`, exactly one row per session, alert delta 0. Deterministic case (the server backend seen waiting on the row lock in `pg_stat_activity`, then commit): 409 `duplicate_record`, alert delta 0. Only `DataError` and `StatementTooComplex` are caught at `:476-479`. The test node is weak: see T1-24. |
| T1-14 half-written batch | closed | `[valid, valid, X]` for `NaN`, `Infinity` and `1e999`: 400 `audit_record_unstorable` with an alert delta of exactly 1, a repeat adds 0 (deduplicated), and a later valid upload of the two records is 200. qa's node asserts 0 rows after the refusal. The code rolls back before the alert (`:410`, `:483`). It is still two copies, not one helper: see T1-25. |
| T1-15 never 500 | closed except T1-26 | `chain_length` given as `"1"`, `[1]`, `{}`, `true` or `1.0` gives 400 `bad_body` with no alert. `null` gives `missing_chain_length`. `2**70`, `-1` and `0` give `gap`. On Windows, nesting past the parser limit gives a named 400 (3,100 levels, and a 400,000-level array of 800 KB). The largest accepted body depth is 2,976, and verify, export and the CLI all read it (`ok: true`, rc 0). On the Linux images the limit is different: see T1-26. |
| T1-16 row limit | closed | 10,050 rows: 10,000 lines plus the `_meta` line, `X-Export-Truncated: true`, while verify reports `record_count: 10050`. Exactly 10,000 rows: 10,000 lines and `false`. |
| T1-17 streaming and memory | **open (HIGH)** | 120 rows of 1 MB: the export raises one worker's peak by **247.3 MB** (round 2: 243 MB) and verify by **247.4 MB** (round 2: 245 MB). The named cursor is there, but `FETCH 500` (`admin_reads.py:870`) and `FETCH 200` (`audit.py:261`) still pull every row of this project into one batch. The ruling was "the cap plus one batch", and with rows of up to 1 MiB a batch of 500 is up to about 0.5 GB raw, before parsing. The byte cap is also not reserved: rows that end 20 bytes under the cap give a body of 10,000,065 bytes with `Content-Length` 10,000,065, against `X-Export-Byte-Cap: 10000000` (`:896` checks only the row; the `_meta` line is added at `:914-927`). |
| T1-18 flood bounds | closed except the parser path | A session id of 256 characters is accepted. 257 characters, NUL or a lone surrogate give `bad_session_id`. A hash of 129 characters, an int, `null` or a list gives `bad_body` before the fork branch, with no quarantine row. 40 refused NaN uploads give 1 alert. `/devices/{id}` with 300 sessions of 254 characters and 20 fork rows is 33 KB, with 100 sessions and `sessions_truncated: true`. `/alerts` pages at 20. **Open:** the `RecursionError` branch (`audit_upload.py:127-161`) inserts an alert on every request: 40 requests of 19 KB each wrote 40 alerts. Fix it with T1-26. |
| T1-19 cursor parse | closed | 12 full walks of 46 devices on 4 workers gave the same order, no duplicates and no `bad_cursor`. Twelve forms (urn, braces, no hyphens, upper case, underscores, Arabic-Indic digits, foreign org, upper-case org, urn org, three parts, empty position, garbage) are byte-identical to garbage, headers included, on all four routes. |
| T1-20 `since`/`until` | closed | `2026-W45-4`, a comma fraction, `-23:59`, `0001-01-01T00:00:00+23:59`, `9999-12-31T23:59:59.999999-23:59`, a basic-format time and a space before `Z` all give 200 on `/alerts` and on both export parameters. Hour 25, `+24:00` and `x` give 400. The parsed value is sent. |
| T1-21 corrupt blobs | closed except T1-27 | Non-UTF-8, a list, a string, an empty blob, `null`, and a list or string `payload` give 200 with `corrupt_bundle` on the bundle itself, and 200 with `diff_base_corrupt` plus `diff_base_sequence` on the next one. NaN and deep nesting still give 500: see T1-27. |
| T1-22 auditor | closed | Measured on all eight routes: org admin and project admin get 200 everywhere. Org auditor and project auditor get 200 on verify, export, `/devices`, `/devices/{id}` and `/alerts`, and 404 on all three `/admin/*`. An auditor or admin of another project, a user with no binding and an org B admin get 404 everywhere. Viewer, approver and policy author (org or project) get 200 on the three read routes and 404 on the rest. No session gives 401. |
| T1-23 CLI guard | closed | `python -m agg_cp.cli audit verify` with no database URL gives rc 1 and `no_db_url`. With no arguments it gives rc 1. On a real project it gives rc 0 and `ok: true`. With a database and `--project not-a-uuid` it gives rc 1, but through an unhandled `InvalidTextRepresentation` traceback (SHOULD: a named error). The M2 gate re-run and the `M2_DEMO.md` correction are still owed at the commit. |
| T1-24 tests prove the claims | open in part | Bullet by bullet below. |
| T1-25 size and duplicates | open in part | `admin_reads.py` now has `_page_after`, `_project_for` and `_parse_bundle_blob`. The `0017` docstring is corrected. The dead code is gone. Escalations use `= 'pending'`. **Open:** the `audit_record_unstorable` dedup-and-insert block is in the file twice, word for word (`audit_upload.py:410-443` and `:483-516`), plus a third insert with no dedup at `:141-155`. The comment at `:395-401` still gives "would need a streaming JSON parser" as the reason. The reason is in ruling 1 of this file: the connector hashes canonical bytes but sends `json.dumps(body)` with default separators, so the wire bytes never equal the hashed bytes. |

### T1-24, bullet by bullet

1. `test_t1_2_lone_surrogate_no_500` now sends the correct hash and asserts 200, stored, verify `ok` and the offline hash: closed for `\ud800`. For `\u0000` it asserts only 200 and stored. **Open:** add verify `ok` and the offline hash for the NUL record.
2. NaN and Infinity nodes: the alert delta is exactly 1, scoped to the connector, on a fresh session. `-Infinity` and `1e999` were added. Closed.
3. Byte cap and row limit: real runs exist (`test_t1_8_export_byte_cap` with 20 MB, `test_t1_16_row_limit_sets_flag` in its own project, where a body under half the cap proves it was the row limit that fired). **Open:** "assert peak memory is bounded" was not done. `test_t1_17_export_memory_bounded_behavioral` asserts only the response size, while its docstring says it proves "the server does not buffer all 120 MB". That is false: the measured peak is 247 MB. The same claim is in the docstring of `test_t1_8_export_truncation_marker` (`:1048`).
4. `test_t1_10_device_detail_fields` seeds a checkpoint, an escalation and a quarantine row, asserts their values, and checks that the escalation's command text is absent. Closed.
5. `test_t1_10_verify_response_fields` asserts `record_count` and `session_count` exactly. `quarantine_rows >= 1` is acceptable, because the project is shared. Closed.
6. `test_t1_11_rls_force_on_all_route_tables` includes `audit_heads` and `audit_quarantine` and reads `relforcerowsecurity`. Closed.
7. New nodes for T1-12 to T1-23 exist. Three are weak:
   - `test_t1_13_duplicate_record_409_deterministic` sleeps one second and accepts 200 or 409. If the request arrives after the commit, it is a no-op 200 and the node passes without the 409 path ever running. **MUST:** poll `pg_stat_activity` for an `agg_app` backend with `wait_event_type = 'Lock'` before the commit (measured: this works on the first poll loop), then require 409 `duplicate_record` and an alert delta of 0.
   - `test_t1_15_deep_nesting_400_not_500` uses a guard input the probes did not measure (3,100 levels). It fails on Linux CI (T1-26).
   - **MUST:** `test_t1_18_repeated_refused_uploads_one_alert` opens a new `httpx.Client` for each of its 40 uploads. On this laptop that crossed the 30 s `pytest-timeout` in both of my `--runxfail` runs, and the thread-method timeout ends the whole pytest process, so every later node in the run is lost. Reuse one client (as the other loops should), or give the node an explicit timeout.
   - SHOULD: `test_t1_23_cli_audit_verify_bad_project` says "no DB URL" but leaves `AGG_DATABASE_URL` and `AGG_DATABASE_URL_FILE` in the environment. Pop both.
8. The stale `xfail` on `test_t9_routes.py::test_reviewed_routes_role_scope_match_rbac` was removed. Closed.
9. `t1_server` passes `applied_by_device=` again (`test_m3_t1_admin_reads.py:260`). Closed.

No target fails on an unrelated pre-check. The NaN, Infinity, chain-length and hash nodes send a zero hash, but the check they target runs before the hash comparison (from reading, and confirmed by the probe statuses).

### New findings

**T1-26 MEDIUM (MUST): whether a nested body is accepted depends on the platform, and a T1 node fails on Linux CI.** The ingest relies on the JSON parser's recursion limit. Measured largest parse depth: 2,997 on Windows Python 3.12.10, 9,997 on Linux Python 3.12.15 and 52,203 on Linux Python 3.15.0rc3 (the api image runs 3.15). Postgres 16 `json` accepts 9,990 levels and refuses 30,000 with "stack depth limit exceeded", which the `StatementTooComplex` catch turns into a named 400. Effects:
- On the Linux images, a device can store a correctly hashed body nested about 3,000 to 9,990 levels deep. A Windows CLI or an offline verifier on Windows Python cannot parse that export line, so the evidence verifies on one platform and not on another.
- `test_t1_15_deep_nesting_400_not_500` sends 3,100 levels with a zero hash. On both Linux images that request parses, so the route answers 400 `hash_mismatch` with no alert, and the node's "exactly 1 alert" assertion fails on both CI `ee` legs once the marker is removed. This was computed in Docker against the node's exact request body, not run through the route on Linux. The Windows run is green because 3,100 exceeds the Windows limit.

Fix:
- A fixed nesting limit for record bodies, the same on every platform, checked without recursion after the parse. Suggested: 1,000 levels, well under every measured limit, so the export and CLI read it everywhere. Above the limit, return 400 `audit_record_unstorable` with one deduplicated alert per connector, session and position.
- Keep the `RecursionError` branch for requests deeper than the parser allows, and deduplicate its alert per connector.
- All three alert paths, plus the `DataError` path, go through one helper (T1-14, T1-25).
- Tests: a body one level over the limit with a correct hash (400, delta 1); a body exactly at the limit (200, verify `ok`); the 400,000-level array, 800 KB, for the parser path (400, delta 1); 40 repeats of each (delta 1).
- The lead records the limit next to the 1 MiB cap in ADR 0001 A4. The connector should apply the same limit when it writes a record (T9b row in `M3_BASELINE.md` section 5b).

**T1-27 LOW (MUST, same helper as T1-21): NaN, Infinity or deep nesting in a stored bundle blob is still a 500.** `_parse_bundle_blob` (`admin_reads.py:165-168`) uses `json.loads`, which accepts `NaN`, and does not catch `RecursionError`. `JSONResponse` then refuses `NaN` while rendering. Measured: a blob with `NaN` in `payload` gives 500 on its own detail and on the next sequence's detail (the diff carries the value). `NaN` outside `payload` gives 500 on its own detail. A payload nested 5,000 levels gives 500 on both. Such a blob can come from the server itself: publish reads `bundle_payload` with `request.json()`, which accepts `NaN`, then signs and stores it (`bundles.py:221`, `:316-330`, from reading). So it takes an admin with approvals, not a device. Fix: parse with a `parse_constant` that raises, and catch `RecursionError`, both mapping to `corrupt_bundle` and `diff_base_corrupt`. Add the three forms to `test_t1_21_corrupt_blob_never_500`. T4 note for the lead: publish must refuse non-finite numbers.

**T1-28 LOW (MUST): drop the `DATABASE_URL` fallback (`cli.py:31-32`).** See the ruling below.

### Rulings

**`gaps_truncated = len(gaps) >= _MAX_GAPS`: accepted.** Measured on its own project for each case:

| Case | `ok` | gaps | `gaps_truncated` |
|---|---|---|---|
| 999 bad rows | false | 999 | absent |
| exactly 1,000 bad rows | false | 1,000 | true |
| 1,000 bad rows, then a clean record | false | 1,000 | true |
| 1,001 bad rows | false | 1,000 | true |
| 999 bad rows, then one record with two problems | false | 1,000 | true |

The only wrong answer is the exact-cap case where nothing was cut, and it errs in the safe direction: `ok` is already false, and the flag never claims a complete list when gaps were dropped or records went unchecked. In the last case the flag inside `verify_project` would have missed the dropped second gap, and the heuristic catches it. SHOULD: document the field as "gaps reached the cap; later problems may exist or were not checked".

**`DATABASE_URL` fallback: refused (T1-28).**
- Nothing in the product sets it: compose, `demo.py` and `m2_gate.py` use `AGG_DATABASE_URL` or `AGG_DATABASE_URL_FILE`, from reading.
- It is a generic name that other tools set on operator hosts. Measured: with only `DATABASE_URL` set, `audit verify` connects to that database and reports on it.
- A verify that silently picks its target is the T1-23 failure class: a pass recorded against something other than what was meant. A staging copy with the same project ids would even print `ok`.
- The tests already have to blank it.
- Remove it. The two server variables stay the only inputs.

**Founder ruling T0b-15: confirmed.** `git diff ee/tests/test_m2_t11_audit.py` is 6 lines in `test_load_20_connectors_200_records`: a `session_id = f"sess-load-{i}"` local, a `"session_id"` key in the connector dict, and the batch sending `c["session_id"]` instead of `f"sess-load-{c['device_id'][:8]}"`. No assertion changed.

**Frozen route file: `ee/tests/fixtures/t1_frozen_routes.json` still has sha256 `0e8bc91ee95d29b10a28d169b9de82582c44255b4e2132a3db507738559561be`.** The signature stands. Signature condition 4 is still open: manifest line 9 holds `2e4fe28e...`. These also need doing at the commit, or CI's manifest and node-id steps fail:
- The manifest lines for `test_m3_t1_security.py`, `test_m3_t1_admin_reads.py` and `test_m2_t11_audit.py` hold older hashes.
- `M3_BASELINE_EE_NODEIDS.txt` lists 84 of the 144 node ids these four T1 files collect today (60 missing: the round 2 nodes and the `auditor` cases of T1-3).
- `M3_PLAN.md:133` still lacks the route file and `sync/admin_reads.py`.

**Held-out residual: written as a T9b row** in `M3_BASELINE.md` section 5b. It names the effect and the fix, not the reproduction. Two more rows sit beside it: repeated fork alerts (round 2 asked for one; measured, 20 fork attempts wrote 20 quarantine rows and 20 alerts), and the connector's mapping of 409 `duplicate_record` to `audit_fork`, which labels a benign concurrent retry as a fork on the laptop (17 of 200 racing uploads got that 409). All three need a founder row.

### For round 4

Narrow: I re-measure T1-17 (target: an export peak delta of at most 64 MB and a verify peak delta of at most 32 MB on the same 120 x 1 MB project, and body bytes at most the cap at the 20-byte edge), T1-26 (the new nodes in Docker on `python:3.12` and `python:3.15`, through the route), T1-27 and T1-28, and read the diff. Closed items stay closed unless the diff touches them.

Suggested shape for T1-17: fetch a small fixed count, at most 16, because one row can be about 1 MiB. Reserve the `_meta` line's bytes before adding a row. Build the body once as bytes. Pin the fetch counts with an `ast` node, and add a byte-cap edge node (rows ending 20 bytes under the cap; body at most the cap). Correct the two docstrings.

## Round 4 (11 Nov 2026)

Reviewer: security-engineer (leader tier). HEAD `975e2bc` plus the uncommitted T1 tree after the round 3 build (backend: T1-17, T1-25, T1-26, T1-27, T1-28; qa: the round 3 test nodes, the fresh-server peak nodes). Product files last written 10 Nov 14:09-14:32, before every probe quoted here; the test file last written 10 Nov 20:10. Measurements were taken on 11 Nov and finished on 12 Nov (the full-file run and the enroll re-runs); nothing in the tree changed between.

Verdict: **APPROVE.** T1-17, T1-25, T1-26, T1-27 and T1-28 are closed by measurement, the T1-24 bullets are closed by reading the nodes, both builder deviations are accepted, and no MUST remains on the product or the tests. The `M3T1Pending` markers come off. The SHOULDs below are recorded for the lead and qa and are not conditions of this approval.

How this was checked: the round 3 harness (outside the repo) builds the database with the repo's migrations, seeds an org, admin session, project and device token, and starts a fresh 4-worker uvicorn server per leg. Legs: Windows Python 3.12.10 with uvicorn's default HTTP implementation (`httptools` 0.8.0 is installed, so that is what ran) and again with `--http h11`; Docker `t1r4-py312:deps` (Linux, Python 3.12.15, httptools 0.9.0) and `t1r4-py315:deps` (Python 3.15.0rc3) against `postgres:16-alpine`, through the route. qa's exact nodes ran in the same two containers with `AGG_TEST_PG_URL`. Peak memory is each process's lifetime peak (`PeakWorkingSetSize` on Windows, `VmHWM` on Linux) for the supervisor and its children before and after one request on a server that has served nothing else, largest change across the processes; qa's own helpers were used for this so the probe and the nodes measure the same thing. Everything is measured unless it says "from reading". The 10 Nov Windows probe numbers are quoted as such where I reuse them.

Scanners on the six changed product files (`sync/audit.py`, `sync/audit_upload.py`, `sync/admin_reads.py`, `app.py`, `cli.py`, migration `0017`) plus `test_m3_t1_security.py`: Semgrep `p/python` and `p/secrets`, 7 files scanned, 0 findings, 0 errors (one taint rule needed `--timeout 120` on the 4,300-line test file; with the default 5 s it reported a timeout, not a finding); gitleaks `dir`, no leaks (297 KB); trivy `fs` (vuln, secret, misconfig; HIGH and CRITICAL), 0 findings.

Tests, `--runxfail --timeout=600`, Windows, testcontainers Postgres 16: `test_m3_t1_security.py` 125 passed in 315.6 s; `test_m3_t1_admin_reads.py` plus `test_m3_t1_record_hash.py` 22 passed in 30.2 s (20 plus 2 collected). 0 failed. I did not run the full ee suite; that is the orchestrator's gate.

### Status

| Item | Status | Evidence |
|---|---|---|
| T1-17 streaming and memory | closed | Code: `FETCH 16` on both verify cursors (`audit.py`), `FETCH 4` on the export cursor (`admin_reads.py`), each DECLARE/FETCH block inside `with conn.transaction():`, the body built once into a `bytearray` sized at the cap and returned as a `memoryview` slice, `_META_RESERVE` (the widest possible `_meta` line, 89 bytes) subtracted from the cap before each row. Measured on the 120 x 1 MB project, fresh 4-worker server each time: export peak delta 19.4, 20.1, 21.4, 22.2, 23.0 MB (harness, Windows, 5 servers; body 9,439,918 bytes, `Content-Length` equal, 9 rows, `X-Export-Truncated: true`, 568-688 ms); 20.2, 24.3, 24.7 MB (qa's node, Windows, 3 runs); 20.0, 24.8, 25.0, 25.1 MB (qa's node, Linux 3.12, 4 runs); 25.9 MB (Linux 3.15). Verify peak delta 5.6, 8.6, 8.7, 9.0, 9.5 MB (harness, Windows, 5 servers, `ok: true`, `record_count` 120, 6.5-7.9 s); 7.0, 9.6, 10.6 MB (qa's verify-alone node, Windows); 5.9, 10.5, 10.6, 10.7 MB (Linux 3.12); 12.1 MB (Linux 3.15). Round 3 measured 247.3 MB and 247.4 MB. Byte-cap edge, 9 rows of exactly 1,000,000 bytes plus a tenth sized to the case and a small eleventh, on h11 and httptools: rows ending 20 bytes under the budget (cap minus the reserve, 9,999,911) give 10 rows and a body of 9,999,976 bytes; rows ending exactly on the budget give 9,999,996; one byte over gives 9 rows and 9,000,084; round 3's input (rows ending 20 bytes under the cap itself, the one that gave 10,000,065 in round 3) gives 9 rows and 9,000,084; a single row over the budget gives 0 rows and the 78-byte `_meta` line alone with `truncated: true`; three rows plus a small one give 3,000,327 bytes and `false`. In every case `Content-Length` equals the body, the body is at or under 10,000,000, there is no `Transfer-Encoding`, and the row bytes equal the lines computed offline. |
| T1-25 size and duplicates | closed | From reading the diff: one helper `_alert_unstorable(conn, d_org, d_project, d_connector, detail)` behind all four refusal paths (nesting limit, `canonical_record_bytes` returning `None`, `RecursionError`, `DataError`/`StatementTooComplex`); it rolls back, re-applies `SET ROLE agg_app` and the org context (both are needed, because a rollback also reverts a `SET` issued inside the transaction), checks `detail @> key` for the connector and kind, inserts once, commits. The duplicated blocks at the old `:410-443` and `:483-516` and the third insert at `:141-155` are gone. The comment above the hash compare now gives ruling 1 as the reason (the connector hashes canonical bytes but sends default separators). |
| T1-26 nesting limit | closed | `MAX_NESTING_DEPTH = 1000` in `audit.py`, `json_nesting_depth` walks an explicit stack with an early stop at `limit + 1`, checked before the hash compare. Through the route on Windows 3.12.10 (httptools and h11), Linux 3.12.15 and Linux 3.15.0rc3, identical results: 1,000 levels with a correct hash is 200, verify `ok: true` on its own project, the export line parses with depth 1000, `agg-cp audit verify --project` rc 0; 1,001 levels with a correct hash is 400 `audit_record_unstorable` ("body too deeply nested"), alert delta 1, detail `{session_id, chain_length: 1}`; the 200,000-level array (400,003 bytes) is 400 `audit_record_unstorable`, delta 1 across all kinds, detail `{reason: recursion_depth_exceeded, session_id}`, in 620 ms on Windows, 61 ms on Linux 3.12, 102 ms on Linux 3.15; 40 repeats of each give delta 1 (Windows 3.0-3.3 s per 40, Linux 0.9-1.3 s). qa's nodes `test_t1_15_deep_nesting_400_not_500`, `test_t1_26_nesting_limit_1000_accept`, `test_t1_26_nesting_limit_1001_refuse`, `test_t1_26_parser_limit_huge_array` and `test_t1_26_nesting_dedup_40_repeats` pass in both Linux containers with `--runxfail`. The limit no longer depends on the platform parser. |
| T1-27 bundle blobs | closed | `_parse_bundle_blob` parses with a `parse_constant` that raises, catches `RecursionError`, and refuses an envelope deeper than `MAX_NESTING_DEPTH` with the same non-recursive walk. Eight blobs seeded in one project, on Windows h11 and httptools and on both Linux images: a clean one (depth 4) is served; `NaN` inside `payload` is `corrupt_bundle` with an empty envelope and its successor says `diff_base_corrupt` with `diff_base_sequence`; `NaN` outside `payload` the same; a payload nested to depth 999 and one to depth 1000 are served; 1,001 is `corrupt_bundle`; 5,000 is `corrupt_bundle`; the successor of each corrupt one says `diff_base_corrupt`. Every detail is 200; the list is 200 with 8 items. qa's six `test_t1_21_corrupt_blob_never_500` forms pass on both Linux images. The code has not changed since the 10 Nov h11 probe (file written 14:32, probe 20:38); the httptools and Linux runs are new. |
| T1-28 CLI | closed | `_db_url` reads `AGG_DATABASE_URL`, then `AGG_DATABASE_URL_FILE`, nothing else. Measured with the two server variables popped: only `DATABASE_URL` set gives rc 1, `{"ok": false, "reason": "no_db_url"}` on stdout and `agg-cp: error: no_db_url` on stderr; `AGG_DATABASE_URL=""` plus `DATABASE_URL` the same. With a database: `--project not-a-uuid`, `urn:uuid:<id>`, upper case and braces each give rc 1 `bad_project_id` on stdout and `agg-cp: error: bad_project_id` on stderr; an unknown project gives `project_not_found`; the real project rc 0 `ok: true`; the URL file rc 0; no arguments rc 1 with the help; `audit verify` without a target rc 1; `--org not-a-uuid` and an unknown org `org_not_found` rc 1. No case printed a traceback. From reading: the strict UUID parse sits before `_sync_conninfo` and the connect, so a bad id never opens a connection. `python -m agg_cp.cli` now has the `__main__` guard (T1-23); the M2 gate re-run and the `M2_DEMO.md` correction are still owed at the commit, as round 3 said. |
| T1-24 bullets | closed | 1: `test_t1_2_lone_surrogate_no_500` now requires verify `ok` and the offline hash for the NUL record too. 3: the docstrings of `test_t1_8_export_truncation_marker` and `test_t1_17_export_memory_bounded_behavioral` no longer claim bounded memory; the peak claim lives in `test_t1_17_export_peak_memory` and `test_t1_17_verify_peak_memory`, which measure it. 7: `test_t1_13_duplicate_record_409_deterministic` polls `pg_stat_activity` for a backend with `wait_event_type = 'Lock'` before the commit and requires 409 `duplicate_record`; `test_t1_18_repeated_refused_uploads_one_alert` reuses one client (3.2 s for 40 uploads on Windows); `test_t1_23_cli_audit_verify_bad_project` pops `AGG_DATABASE_URL`, `AGG_DATABASE_URL_FILE` and `DATABASE_URL`. |

### Rulings on the two builder deviations

**Deviation 1, accepted: the `RecursionError` alert is keyed `{reason: recursion_depth_exceeded, session_id: <sid>}` with the sid lifted from the raw bytes, not per connector.** Round 3 asked for one row per connector on this path because no record can be read. The builder keys per connector and session instead, so two nodes sharing one connector each see delta 1. Question (b), is the regex lift abusable:
- The connector is taken from the token, never from the body; a body naming another device's session can only key an alert under the sending device. Naming one of its own other sessions merges with that session's parser alert, which the device controls anyway. Nothing is stored on this path, so the sid is informational.
- The lift takes the first `"session_id"` string literal in the bytes. Measured: a sid placed after the deep value is found; a nested `"session_id"` inside a record body is taken before the batch key (`inner-...` recorded, `outer-...` not). That changes which of the device's own labels is recorded and nothing else.
- A lifted value that fails the parsed path's rules (300 characters, NUL, a lone surrogate, a number) or no literal at all gives the reason-only key, and `@>` containment means that key is absorbed by any earlier parser alert of the connector: measured delta 0 in every such case, on all three platforms. An escaped quote lifts as `a"b` and gives one row. The reverse (an existing reason-only row and a new sid-keyed one) inserts, which is the safe direction.
- Flood bound: 40 requests with distinct sids give 40 rows (Windows 3.3 s, Linux about 1 s). That is the same bound as the parsed path, where 20 NaN uploads with distinct sids give 20 rows, and it is tighter than the parsed path's (session, position) key. Round 3 had one row per request here (40 for 40). The device is authenticated, the request is capped at 1 MiB before the parse, and the lift is linear: a 1 MiB body with 200,000 open brackets and an unterminated string costs 350 ms on Windows and 89-102 ms on Linux, with the parser attempt included; many short literals cost 30-72 ms.
- Ruling: acceptable for T1; a per-connector bound would make the parser path stricter than the parsed path for no gain in what an attacker can do. Residual, recorded once: an authenticated device can add one `audit_record_unstorable` row per distinct session id per request on any refusal path. The alert list pages at 20 and device detail truncates sessions at 100 (round 3), so reads stay bounded. SHOULD (lead, not a T1 condition): a per-connector, per-window cap on refusal alerts belongs with the sync rate-limit work (T9b or M4).

**Deviation 2, accepted: `_parse_bundle_blob` refuses envelopes deeper than 1,000.** Round 3 asked only for `parse_constant` and `RecursionError`. A published bundle has depth 4 (measured on the seeded envelopes); the same number as the record limit keeps one figure in the ADR; a 1,000-deep envelope is still served and 1,001 is `corrupt_bundle`, so the diff and the response renderer never recurse on a stored blob. The blob can only come from the server's own publish, so the rule is about what the server will store, not about a device. SHOULD (lead, T4): publish refuses a payload with a non-finite number or deeper than 1,000, so a stored blob can never be marked corrupt by this check.

### Questions a-e

**(a) `memoryview` body under Starlette: sound.** From reading, `Response.render` passes `bytes` and `memoryview` through, `init_headers` takes `len(body)`, and the route sets `Content-Length` to the same value; uvicorn's h11 path joins the data into one `bytes` (one copy) and the httptools path writes the view to the transport. Measured on Windows under both implementations: a full body (3,000,327 bytes), truncated bodies (the six edge cases above), an empty project (200, 0 bytes, `Content-Length: 0`, `X-Export-Truncated: false`, `application/x-ndjson`), a `since` in the future (0 bytes), and 8 concurrent exports of the 120 x 1 MB project (all 200, one distinct sha256, every length equal to its `Content-Length`). `HEAD` is 405, as before. The Linux legs ran the default implementation (httptools) and parsed the export line.

**(b)** Above, under deviation 1.

**(c) T1-18 flood bound after the dedup changes:** identical refused requests give one row on both paths (40 NaN uploads: 1; 40 parser-path uploads: 1); alternating NaN and parser-path requests on one session give 2 rows (the two keys differ); distinct sessions give one row each. Measured on Windows, Linux 3.12 and Linux 3.15. The per-request flood from round 3 is closed; the per-session bound stands, as ruled above.

**(d) `ee/tests/test_m2_t8_enroll.py::test_token_nonce_replay_across_4_workers`: a flake, not a T1 regression.** The failure was a client-side `httpcore.ReadTimeout` at the node's 10 s `httpx` timeout during a 20-minute full ee run; the replay-refused assertion never ran false. `git status` shows no change under `sync/enroll.py` or the token route; `app.py` only appends the admin-reads router. The same node passed in the 9 Nov full ee run on the same enroll code, and passed 3 of 3 runs alone today (19.9 s, 20.3 s, 21.1 s). Condition: the gate's full ee run shows it green. If it recurs there or in CI, it is a qa item on that node's client timeout under load, not a T1 item.

**(e) qa's peak nodes on Linux CI, and the 48 MB reading.** The nodes are sound on Linux: the helpers read `/proc/*/cmdline` and the `PPid` line of `/proc/<pid>/status`, find the supervisor by `--port <port>` and the workers as its children (uvicorn spawns them with `multiprocessing`, so their command lines name neither uvicorn nor agg_cp), and read `VmHWM`. In the Docker containers (own PID namespace, as the CI `ee` job's container) the `>= 5 processes` guard held and the nodes passed 5 of 5 times on 3.12 (export 20.0-25.1 MB, verify alone 5.9-10.7 MB) and once on 3.15 (25.9 MB, 12.1 MB). The CI job runs pytest from the repository root, so the two structural pins' relative paths also resolve there. On the 48 MB: my 17 export readings across Windows and Linux lie in 19.4-25.9 MB, so I could not reproduce it; the handoff's 24-48 MB came from runs inside the full suite. The structural worst case of the new code is about 40 MB: the 10 MB buffer, one `bytes` copy on the h11 join, up to one more copy in the transport buffer when the client reads slowly, and 4 rows in flight at about 2-3 MB each; the pre-fix product was 244-247 MB. A 64 MB threshold sits above that worst case and six times under the old number, so it tells the two apart; 32 MB for verify sits three times above the measured 5.6-12.1 MB. Keep both thresholds and the method; the nodes print the measured deltas, so a CI failure shows its number. If a CI run ever exceeds 64 MB with the 9,439,918-byte body, read that number before touching the threshold.

### Other notes (SHOULD, none a condition)

- `_FETCH_ROWS = 16` and `_EXPORT_FETCH_ROWS = 4` are declared but the SQL carries the literals `FETCH 16` and `FETCH 4`, because the pin (`test_t1_17_fetch_count_pinned`) reads literals. Either the SQL should use the constants and the pin read the assignments, or the constants should go; today they can drift.
- `test_t1_17_fetch_count_pinned` and `test_t1_17_export_no_fetchall_uses_cursor` open `Path("ee/src/agg_cp/sync/...")` relative to the working directory; the pin node `continue`s when the file is missing, so from `ee/` it passes without reading anything. CI runs from the root, so this is not a CI gap. qa should resolve the paths from `__file__` and fail when a file is missing.
- `sync/audit.py` now holds `canonical_record_bytes` (the ingest hash formula), `MAX_NESTING_DEPTH` and `verify_project`. It is not on the server TCB line. The lead should consider adding it (a founder row, since the frozen list changes only by one); I have not edited it in.

### Frozen route file and the commit

`ee/tests/fixtures/t1_frozen_routes.json` still has sha256 `0e8bc91ee95d29b10a28d169b9de82582c44255b4e2132a3db507738559561be`; the signature stands. Signature condition 4 is still open: `M3_FROZEN_MANIFEST.sha256` line 9 holds `2e4fe28e...` and must hold `0e8bc91e...` at the commit. Also measured today: the manifest lines for `test_m3_t1_security.py` (manifest `3d543f27...`, on disk `34221160...`), `test_m3_t1_admin_reads.py` (`8ee9f075...`, on disk `ff685ea2...`) and `test_m2_t11_audit.py` (`89a5e8c7...`, on disk `4984851d...`) are stale; `test_m3_t1_record_hash.py` matches. `M3_BASELINE_EE_NODEIDS.txt` lists 54 of the 125 node ids `test_m3_t1_security.py` collects today (71 missing); `test_m3_t1_admin_reads.py` 20 of 20, `test_m3_t1_record_hash.py` 2 of 2, `test_m2_t11_audit.py` 39 of 39. The marker removal changes the three T1 test files again, so the manifest and node-id lists are regenerated after it, in the Linux `python:3.12` container, as the "Before commit" rule says.

Commit list for T1 (on this approval):
1. qa removes every `M3T1Pending` marker and import from `ee/tests/test_m3_t1_security.py` (29 occurrences today), `ee/tests/test_m3_t1_admin_reads.py` (19) and `ee/tests/test_m3_t1_record_hash.py` (2), and re-runs the three files without `--runxfail`: 125 + 20 + 2 passed, 0 failed, 0 xfailed.
2. The lead adds to ADR 0001 A4 (audit upload), next to the 1 MiB cap: "A record body is refused at ingest when its container nesting exceeds 1,000 levels (400 `audit_record_unstorable`, one deduplicated alert per connector, session and position), the same limit on every platform and checked without recursion, so that every stored record can be read by the export, `agg-cp audit verify` and an offline verifier on any supported Python. The same limit applies to a stored bundle envelope: deeper is `corrupt_bundle`."
3. The lead adds the T9b row in `M3_BASELINE.md` section 5b: the connector applies the 1,000-level limit when it writes a record, before hashing, so no session stalls on a body the server will refuse (round 3 wrote the effect in row 1 of that table; this row names the limit).
4. Signature condition 4: manifest line 9 becomes `0e8bc91e...`; the route file itself is unchanged.
5. `M3_FROZEN_MANIFEST.sha256`, `M3_BASELINE_EE_NODEIDS.txt` and `M3_BASELINE_NODEIDS.txt` regenerated in the Linux container after step 1.
6. Server TCB: `M3_PLAN.md` frozen item 3 now lists `sync/admin_reads.py` and `ee/tests/fixtures/t1_frozen_routes.json` (signed; a change needs a new signature). Edited in this round.
7. Still owed from round 3 at the commit: the M2 gate re-run of `agg-cp audit verify` on a fresh stack and the `M2_DEMO.md` correction under a founder row (T1-23).

Approval: Security (L), 12 Nov 2026: the T1 tree as measured above (product files of 10 Nov 14:09-14:32, test file of 10 Nov 20:10) is approved for commit with the seven steps above; none of the five guarded properties is weakened, and the ingest hash, the nesting limit and the export cap now behave the same on Windows 3.12, Linux 3.12 and Linux 3.15.
