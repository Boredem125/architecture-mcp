# M3 T4 build spec (lead-architect, 18 Nov 2026, HEAD `3f4a396`; revised 18 Nov after the security design review)

Inputs: `M3_PLAN.md` T4 row, D2.2-D2.4, frozen section, server TCB (frozen item 3), threat 41, rulings T0b-7 and T0b-10, QA Q3 and Q6, security S1 and S2; ADR 0001 Amendment A9 and its 16 Nov addendum; `T3_SPEC.md`; `T3_SECURITY_REVIEW.md` R3-3 (a) and (b), R3-4, R3-8, R4-2, R4-4, R4-7; HANDOFF "Carried to T4" (sessions 19 and 21); `M3_BASELINE.md` founder rows F-1, FR-1 and the 18 Nov rows (section 5); `T4_SECURITY_REVIEW.md` "Design review, 18 Nov 2026" (CONFIRMED WITH CHANGES; MUST 1-14, SQ rulings, SHOULD 1-16, FQ-1). Builder: backend (W). Tests first: qa (W). Reviews: security (L) on every server TCB file in section 4, `compose.override.yml` and the property test. Frozen tests are never edited except under a founder row (section 5).

## 1. Scope

| # | Item | Tag | Source |
|---|---|---|---|
| 1 | Publish runs A9 item 8 in full: registry rebuild, base selection, time and version checks, hash and size from stored bytes, `loosened`, exclusions against the registry entry, `counts_for_dual` filter, sign, connector steps 1, 4, 5, insert with `verification='server'`, copied approvals, audit row | MUST | D2.2, A9 items 1-5, 8; S1; T0b-7; T0b-10 |
| 2 | Stale base refused at approval (exists, T3) and at publish, including a concurrent publish on the same base | MUST | A9 item 4, threat 41 |
| 3 | `base_sequence > 0` with no stored row at that sequence is refused at proposal and at publish; no deny-all fallback | MUST | R3-8, HANDOFF s19/s21 |
| 4 | Publish refuses `registry_invalid` when the stored chain fails `verify_chain`, with an audit row | MUST | R3-3 (b) |
| 5 | Proposal refuses `registry_invalid` the same way when a chain exists and fails (no chain stays allowed, `registry_version` 0) | SHOULD | R3-3 (b) |
| 6 | Audit rows for the publish refusals `not_found`, `forbidden`, `not_open` | MUST | R3-8 |
| 7 | Labels: `server` rows written by publish; M2 rows and direct-publish rows stay `m2_unverified`; server logic reads `server` rows only | MUST | D2.3, A9 item 9 |
| 8 | `POST /admin/bundles` returns 410 unless `AGG_ALLOW_DIRECT_PUBLISH=1` with `AGG_DEPLOY_PROFILE=demo`; the 410 returns before any DB work or await; `create_app` refuses to start on any other combination; `compose.override.yml` sets both for the demo stack | MUST | D2.4, A9 item 10, Q3, founder ruling 10, F-9 |
| 9 | Under the flag, `POST /admin/bundles` reads its body before opening a connection and checks org-or-project admin | MUST | R3-4, S-3 (A9 addendum item 3) |
| 10 | AST guard: no `await` inside a DB transaction block, and no `await` after a non-autocommit connection opened by assignment, anywhere in `ee/src/agg_cp` | MUST | R3-4, security MUST 8 |
| 11 | One `is_project_admin` helper for all five call sites, with a one-definition test | MUST | R3-3 (a) |
| 12 | R4-4: proposal list and detail readable only by org admin, admin of the proposal's project, or a caller holding a counting `cli` key in the verified registry; everyone else gets the uniform 404 | MUST | R4-4, FR-3 (17 Nov), security MUST 11 |
| 13 | Naive cursor read as UTC (section 2.9); cursor tie-break on `id` | SHOULD | R4-2, SQ-4 |
| 14 | Code-issue response `expires_at` is the stored value | MUST (carried; spec 3.3 already required it) | T3_SPEC 3.3, R4-2 |
| 15 | Drop `env_name or "prod"` in `create_proposal` | MUST | R3-8 |
| 16 | Test nodes skipped at T3: braced and uppercase forms of a real project id; a valid signed body on the urn approve node; the `_safe_str` path in the `loosened` message (root CLI) | SHOULD | R4-3, R4-7 |
| 17 | Backend tidy: delete unused `proposals._is_uuid`; fix the cursor comment; `_safe_str` on `server dropped section` and `server altered` in `propose-bundle`; CLI `DENY_ALL_BASE` becomes the function `deny_all_base() -> dict` (fresh dict per call) with an `ast` pin; ruff S110 at `proposals.py:643`, E501 at `:702`, `:715`; stale comment `test_m3_t3_proposals.py:548` (FR-4) | SHOULD | R4-2, R4-7, HANDOFF s21, QA-4 |
| 18 | Proposal detail adds `approvals_needed` computed with the server's base rule | SHOULD | lead (the page must not understate a first-bundle-after-upgrade) |
| 19 | Migration 0019: publish-link CHECK and unique on `policy_change_requests`; partial index for the last `server` row; DELETE revoked and published rows immutable | MUST (last clause SHOULD 2) | lead (section 2.3), security SHOULD 2 |
| 20 | The two `M3T4Pending` nodes in `test_m3_t3_proposals.py` pass; their markers come off in the T4 build | MUST | F-1, FR-1, FR-4 |
| 21 | Security (L) reviews the session 21 `_deny_all_base()` change in `proposals.py` | DONE (review section 2: fine; superseded by item 1) | HANDOFF s21 |
| 22 | Copied approvals are the individually verified, dual-filtered, one-per-user set; the audit row names exactly that set | MUST | security MUST 1, SQ-7 |
| 23 | Server base and head rows must parse and bind to their own row, else `base_invalid` | MUST | SQ-8 condition |
| 24 | Registry rebuild never gives 500: every parse or verify error becomes the caller's refusal | MUST | security MUST 6 |
| 25 | `sync/signer.py::create_link_code_route` reads its body before `psycopg.connect` | MUST | security MUST 8 |
| 26 | S2 guard: operator refusal reads no `policy_bundles` row and no `allow_requester` | MUST | security MUST 9 |
| 27 | Start-up refusal proven in a subprocess; `app.py` joins the server TCB | MUST | security MUST 10, SQ-1 |
| 28 | Publish lock and DB-error rules | MUST | security MUST 14, SQ-6 |
| 29 | Security SHOULDs taken in T4 (section 4.5) | SHOULD | `T4_SECURITY_REVIEW.md` section 7 |

**Out of scope.** T3-F1 (`cli_key_lookup` and `authenticate_signer` ignore key kind; T9b). The T9b list: code issue and revoke read the body uncapped and before auth, non-dict body 500; urn-form UUID 500 at `enroll.py:476`, `escalations.py:722`, `:1168`; cap on open proposals per project; seal pin for `test_t9_routes.py`; anchor source (a) for `approve-change`. F-1 (device behind a registry change), F-2 on the connector, F3. Web pages (T2). No new route; `ee/tests/fixtures/t1_frozen_routes.json` does not change. Carries to T5, T7 and T10: section 4.4.

## 2. Design

### 2.1 Shared publish verifier (new `ee/src/agg_cp/sync/publish_verify.py`, server TCB)

Pure functions, no DB, no clock reads (time is a parameter). The publish route and the property test call the same code.

- Imports by name, no alias, `ImportFrom` only (no `import sandbox.connector.sync.bundles`, with or without `as`): `BUNDLE_FIELDS`, `BUNDLE_MAX_BYTES`, `BundleError`, `_bundle_hash`, `_canonical_json_bytes`, `loosened`, `_verify_change_approvals`, `_verify_envelope_structure`, `_verify_signature`, `_verify_bundle_signer_in_registry` from `sandbox.connector.sync.bundles`; `_bundle_signer_pub` from `sandbox.connector.sync.process`. Nothing else from either module. `verify_and_apply` is never imported or referenced in `ee/src`.
- `deny_all_base() -> dict`: a fresh dict equal to the connector's step 10 literal. The only server copy; `proposals.py` imports it and deletes its own `_deny_all_base`.
- `COUNTING_ROLES = frozenset({"policy_author", "approver", "admin"})`: the set literal inside `_verify_change_approvals`; pinned by `ast` (section 3.3).
- `canon_user(x) -> str | None`: `str(uuid.UUID(x))` when `x` is a str that parses, else None (SHOULD 1).
- `class PublishRefused(Exception)` with `code` and `detail`.
- `approvals_needed(payload, server_base, head) -> tuple[int, dict]`. `server_base` is the payload of the last `server` row, or None. `head` is the payload of the max-sequence row when it is not that `server` row, else None. `is_first = server_base is None`; `base = server_base or deny_all_base()`; `lo = loosened(base, payload)`; if `head` is not None, also `lo_head = loosened(head, payload)` (A9 item 3, security clause). Need is 2 when `is_first`, `lo` or `lo_head` is non-empty, else 1. The loosening base is never `head`; `head` only adds need. Any exception from `loosened` raises `PublishRefused("invalid_bundle")`.
- `verify_publish(*, payload_bytes, stored_hash, org_id, project_id, base_sequence, sequence, approvals, registry, server_base, head, proposer_id, publisher_id, now) -> (payload, counted)`. `approvals` is a list of `(envelope, signed_at)` in stored order. In this order:
  - (e) `payload_bytes` parses (duplicate-key hook, no NaN) to a dict, else `bad_payload`; `_bundle_hash(payload) == stored_hash`, else `hash_mismatch`; `len(_canonical_json_bytes(payload)) <= BUNDLE_MAX_BYTES`, else `too_large`; keys within `BUNDLE_FIELDS` and no `change_approvals`, else `unknown_fields`; `org_id`, `project_id`, `base_sequence`, `sequence` equal the row and `sequence == base_sequence + 1`, else `binding_mismatch`.
  - (d) `registry_version` is an int, not bool, and `>= registry.version`, else `registry_version_stale`; `not_before <= now`, else `not_yet_valid`; `expires_at`, if present, `> now`, else `expired`.
  - (f) `need, ... = approvals_needed(...)`.
  - (g) Entry and exclusions. For each stored approval (parsed canonical envelope, exactly one signature): `entry = registry._keys.get(key_id)`. Missing entry, kind not `cli`, no role in `COUNTING_ROLES`, or `canon_user(entry["user_id"])` is None: dropped (the first three would not count on a connector either; the fourth cannot be stored in the `uuid` column, so the server is stricter). `canon_user(entry["user_id"]) == canon_user(proposer_id)`: `proposer_in_approvals`. `== canon_user(publisher_id)`: `publisher_in_approvals`. The exclusions refuse whether or not that approval's signature verifies (stricter).
  - (h) Copied set (security MUST 1, SQ-7), in this order: (1) keep each approval that passes `_verify_change_approvals(payload, [env], registry, is_loosening=False, is_first_bundle=False)` alone; (2) when need is 2, keep only keys with `registry.counts_for_dual(key_id)` (ruling T0b-7, from the first commit); (3) keep one approval per `canon_user` of the registry entry, the lowest `key_id` first. Filtering before dedupe means a user's counting key is never dropped in favour of a non-counting one. (4) `_verify_change_approvals(payload, [envs of the set], registry, is_loosening=bool(lo or lo_head), is_first_bundle=is_first)`; `BundleError` becomes `approvals_insufficient` with the connector's reason plus `dual_filter: true|false` in `detail`.
  - Returns the payload and `counted`: the list from (h)(3), each item `(envelope, signed_at, canon_user, key_id)`. It is exactly what the route copies and what the audit row names.
- `sign_and_check(payload, signing_key, registry) -> envelope`: (i) `bundles._sign_bundle` (the M2 server function, reused); (j) `_verify_envelope_structure(env)`, `pub = _bundle_signer_pub(registry)`, `_verify_signature(env, pub)`, `_verify_bundle_signer_in_registry(registry, pub)`. Any `BundleError` becomes `signer_not_in_registry` (a key file whose public key is not the registry's bundle signer lands here; SQ-5).

### 2.2 Publish route (`proposals.py::publish_proposal`)

Order. Steps 0-8 keep the T3 order so frozen T3 nodes keep their codes (the T3 stale node at publish has no chain, so the stale check stays ahead of the registry rebuild; A9's letters (b) and (c) swap, and every path still refuses; SQ-6 accepted).

0. CSRF dependency (403). 1. Capped body read (ignored). 2. Auth (401, token rules as T3). 3. Fresh session for session callers (401 `reauth_required`). 4. Path id not canonical: 404 `not_found`. 5. `SELECT ... FOR UPDATE` on the proposal in the org; none: 404 `not_found`. 6. `is_project_admin` on the proposal's project, else 403 `forbidden`. 7. Status not `open`: 409 `not_open`. 8. `SELECT 1 FROM projects WHERE id = ... AND org_id = ... FOR UPDATE` (serialises publishes per project). It must return a row; None gives 404 `not_found`, audited, and the route never proceeds unlocked (MUST 14). Lock order is always proposal, then project; approvals lock the proposal only, so there is no cycle.
9. Stale: `base_sequence != _max_sequence(...)` gives 400 `stale_base`. It runs after the project lock: under READ COMMITTED it sees a concurrent winner's commit.
10. Stored exclusions (T3): stored `user_id` equals the publisher (`publisher_in_approvals`) or the proposer (`proposer_in_approvals`), compared in `canon_user` form.
11. Registry: one helper `_verified_registry(conn, org_id)` serves approval, publish, proposal and reads. It turns every exception in the genesis parse (`_genesis_fingerprint` moves inside its `try`), the `get_chain` parse and `verify_chain` into a refusal, never a 500 (MUST 6). Codes: empty chain or no genesis fingerprint, 400 `no_registry`; any other failure, 400 `registry_invalid` at publish and propose; the approval route keeps its frozen `no_registry` for every failure; reads treat any failure as "not readable through a key".
12. Base rows: `server_row` = highest `sequence` with `verification = 'server'` in the project; `head_row` = the row at `base_sequence` when `base_sequence > 0`. `head_row` missing: 400 `base_missing`. Each of `server_row` and `head_row` must parse to an envelope with a dict `payload` whose `sequence`, `org_id` and `project_id` equal the row's columns; otherwise 400 `base_invalid` (SQ-8 condition). The server does not re-verify its own `server` row's signature (a bundle-signer rotation would refuse every valid row). `head` is passed only when `head_row` is not `server_row`.
13. Stored approvals: `SELECT key_id, signature, signed_at FROM policy_change_approvals WHERE change_request_id = <proposal> ORDER BY key_id`; a stored envelope that does not parse is dropped.
14. `verify_publish(...)` with `now` = app clock as int seconds, `proposer_id` from the row, `publisher_id` = authenticated user.
15. Signing key: `_load_bundle_signer_key()`; None: 500 `bundle_signer_key_not_configured` (same as the M2 node), rollback first, audited, nothing written; the detail never names the key path (SQ-5). Then `sign_and_check`.
16. In the same transaction: insert `policy_bundles` (`id`, org, project, `sequence`, `bundle_blob` = canonical envelope bytes, `server_signature`, `created_at`, `verification='server'`, `verified_at=now`; both named explicitly, the 0017 DEFAULT stays); copy each item of `counted` into `policy_change_approvals` with `change_request_id` = the new bundle id, `signature` = the stored canonical text unchanged, `user_id` = its `canon_user`, `key_id`, `signed_at` taken from the stored row; `UPDATE policy_change_requests SET status='published', published_bundle_id, published_by, published_at`; `admin_audit` `bundle_proposal.publish` with `proposal_id`, `bundle_id`, `sequence`, `bundle_hash`, `proposer_user_id`, `approver_user_ids` (the users of `counted`, nothing else), `publisher_user_id`, `auth`, token `key_id`. Commit.
    - `UniqueViolation` whose `diag.constraint_name` is the `policy_bundles (project_id, sequence)` constraint (0007 leaves it unnamed, so Postgres names it `policy_bundles_project_id_sequence_key`; qa reads the name from `pg_constraint` at tests-first and pins it): rollback, 400 `stale_base`, audited.
    - Any other DB error (including any other `UniqueViolation`): rollback, audit `internal_error`, 500 `{"error": "internal_error", "detail": "internal error"}` (MUST 14).
17. 201 `{"bundle_id", "sequence", "bundle_hash", "verification": "server"}`.

Every refusal from step 4 on: `conn.rollback()` first, then `_audit_refused` writes `bundle_proposal.publish_refused` with `reason`, `auth`, token `key_id` and `proposal_id` (null when the path id is not canonical) in its own transaction (items 4, 6). Error body is always `{"error": <code>, "detail": <str, at most 200 chars>}`. The string `verification_pending` leaves the module. No `await` after step 1.

### 2.3 Database: migration `0019_t4_publish.py` (server TCB)

The label columns already exist: migration 0017 (T1) added `verification text NOT NULL DEFAULT 'm2_unverified'`, `verified_at timestamptz`, the value CHECK and the coupling CHECK (`server` exactly when `verified_at` is set), and existing rows took `m2_unverified` then. T4 does not re-add them, and keeps the DEFAULT so owner-inserted test rows and direct-publish rows stay `m2_unverified`. The app role holds only SELECT and INSERT on `policy_bundles` and `policy_change_approvals` (0007), so no label and no copied approval can change after insert. 0019 adds:
- `policy_change_requests` CHECK `chk_published_link`: `(status = 'open' AND published_bundle_id IS NULL AND published_by IS NULL AND published_at IS NULL) OR (status = 'published' AND published_bundle_id IS NOT NULL AND published_by IS NOT NULL AND published_at IS NOT NULL)`. Every stored row today is `open` with NULLs (T3 never published; frozen tests insert only `open`).
- `CREATE UNIQUE INDEX ... ON policy_change_requests (published_bundle_id) WHERE published_bundle_id IS NOT NULL`.
- `CREATE INDEX ... ON policy_bundles (org_id, project_id, sequence DESC) WHERE verification = 'server'`.
- SHOULD 2: `REVOKE DELETE ON policy_change_requests FROM agg_app`, and trigger `trg_published_request_immutable` (BEFORE UPDATE, raises when `OLD.status = 'published'`). Nothing deletes or re-opens a row today (security grep). If the full suite shows a frozen node that does either as `agg_app`, the build stops and reports it to the lead; the frozen node is not edited.
- Revision id `000000000013`, down revision `000000000012`. Downgrade drops exactly these objects and restores the DELETE grant.

### 2.4 Proposal route changes (`create_proposal`, `get_proposal`)

- Environment: `proj[1]` used as stored (0004 makes it NOT NULL and one of `dev`, `staging`, `prod`); the `or "prod"` default goes.
- Base row: `base_sequence > 0` and no `policy_bundles` row at that sequence: rollback, 400 `base_missing`, nothing stored. The deny-all fallback stays only for `base_sequence == 0`.
- Registry: no chain, `registry_version = 0` as today (frozen T3 nodes propose without a chain; such a proposal can never publish). Chain present and `_verified_registry` refuses: 400 `registry_invalid` and an `admin_audit` `bundle_proposal.create_refused` row in its own transaction (SHOULD).
- Detail adds `approvals_needed` from `approvals_needed()` with the server base rule (SHOULD); `null` if it raises (SHOULD 6). The page and the CLI label it as the server's word.
- Detail `base.change_approvals` comes from the `policy_change_approvals` rows keyed to the base bundle id, the served set (SHOULD 6).
- Approval route: proposer and duplicate-user checks compare `canon_user` forms (SHOULD 1).

### 2.5 Direct publish, flag and startup (`app.py`, `sync/bundles.py`, `ee/deploy/compose.override.yml`)

- `app.py` holds the one definition: `_direct_publish_enabled(environ) -> bool`. `AGG_ALLOW_DIRECT_PUBLISH` absent: False. Present with any value (empty included): True only if `AGG_DEPLOY_PROFILE` is exactly `demo` and the flag is exactly `1`; any other combination raises `RuntimeError("AGG_ALLOW_DIRECT_PUBLISH requires AGG_DEPLOY_PROFILE=demo and the value 1")`. `create_app` calls it as its first step, before `if settings.db_url` and before building any router, so `uvicorn --factory` exits before it serves (SQ-1 condition; proven by subprocess, MUST 10). `AGG_DEPLOY_PROFILE` changes nothing else. Both literal names stay in `app.py` (the frozen T5 node reads that file). `app.py` is server TCB from T4.
- `admin_create_bundle`, first statement: `try: on = _direct_publish_enabled(os.environ) except RuntimeError: on = False`; when not `on`, return 410 `{"error": "direct_publish_gone", "detail": "use POST /api/v1/admin/bundle-proposals"}`. No `with`, `await` or DB call precedes it. The route stays registered (frozen route set) and keeps role `admin`; the CSRF dependency still runs first, so the CSRF catalog's 403 holds.
- Under the flag, M2 behaviour with these changes:
  - Body read through the shared capped reader and parsed with `_strict_json_parse`, both imported from `sync/proposals.py` (SHOULD 5; no copy in `sync/bundles.py`), before `with _conn()`. Non-dict JSON is 400 `bad_json`.
  - After session and CSRF, `is_project_admin(conn, user_id, project_id)` or 403 `forbidden`, nothing written (S-3).
  - SHOULD 4: a non-canonical `project_id` gives 400 `bad_project_id`; after the M2 project lookup (so the frozen random-project 403 holds), `SELECT 1 FROM projects ... FOR UPDATE`; one `admin_audit` `bundle.direct_publish` row in the same transaction.
  - The INSERT names `verification = 'm2_unverified'` explicitly.
  - No verification, no fresh-session rule (as M2; SQ-10 accepted; the frozen gate's timing stays as measured).
  - `async def get_bundle` stays above `async def admin_create_bundle`, and the strings `INSERT INTO policy_change_approvals` and `bad_change_approvals` stay in the module (frozen `inspect` checks in `test_m2_t16b_change_approvals.py`).
  - If MUST 13 (ii) shows a frozen M2 node failing only because of the admin check or the capped strict read, the check stays and that node gets its own founder row (FQ-1). If one fails because of a SHOULD 4 piece (canonical id, lock, audit row), that piece comes out and becomes a named demo-only limit in `M3_DEMO.md`; the lead reports it to the founder.
- New `ee/deploy/compose.override.yml`: exactly `services.api.environment` with `AGG_DEPLOY_PROFILE: demo` and `AGG_ALLOW_DIRECT_PUBLISH: "1"`, nothing else, pinned by a guard (SQ-2 condition, SHOULD 12). Compose auto-loads it in `ee/deploy`, so the byte-frozen `m2_gate.py` and `demo.py` get the flag with no edit (F-9). `pilot.sh` (T5) passes `-f` explicitly, and the T5 tests build the merged config from `compose.yml` plus `compose.pilot*.yml` only, so the override never reaches a pilot. The name must not match `compose.pilot*.yml`. Residual risk and its T5 carries: section 4.4.

### 2.6 One admin helper (`rbac.py`, server TCB)

`is_project_admin(conn, user_id, project_id) -> bool` with `api.py::_is_project_admin`'s SQL; `project_id=None` matches org admins only. Replace the definitions in `api.py`, `sync/admin_reads.py`, `sync/enroll.py`, `sync/proposals.py`, and revoke's inline two-query form (`enroll.py:553-581`: look up the device's project, None if absent, then the helper; a non-admin still gets 403 for an unknown device). `_is_project_admin_or_auditor`, `_can_read_project` and the org-admin-only checks are different predicates and stay.

### 2.7 No await under a transaction (all of `ee/src/agg_cp`)

Measured by security (read-only AST scan, 18 Nov): 70 transaction blocks, one `await` inside (`sync/bundles.py:221`); and one assignment-form site, `sync/signer.py::create_link_code_route` (`psycopg.connect(url, autocommit=False)` at :409, `validate_session` writes `last_seen_at` without commit, then `await request.json()` at :423).

The guard flags two forms (MUST 8):
- A `with` or `async with` whose context call is named `_conn`, `_app_conn`, `connect`, `connection`, `transaction` or `begin`, containing an `Await`.
- In an `async def`, an assignment from a call with one of those names that does not pass `autocommit=True`, followed by an `Await` before that name's `.close()` call.

Fixes: section 2.5 removes the first. `create_link_code_route` reads its body through the shared capped reader before `psycopg.connect`. Over the cap gives the reader's 413 before any DB work (the read is now before auth, so it must be capped). A parse failure stays `{}` as today: the route parses the captured bytes with `json.loads` inside the same `try`, treats a non-dict as `{}`, and never calls `request.json()` or `request.body()` after the reader (security addendum A2; the frozen M2 T13 browser-key link nodes must pass in the build's full ee run). Nothing else in the route changes. `sync/signer.py` is on the T4 touch list.

### 2.8 R4-4 read scope (list and detail; MUST 11)

`_can_read(conn, org_id, user_id, token_key_id, project_id)`: true if `is_project_admin(...)`. Else true if the verified registry (2.2 step 11 helper; no or invalid chain means this path is false) has an entry with kind `cli`, a role in `COUNTING_ROLES` and `canon_user(user_id)` equal to the caller's, for the token's bound key (token callers), or for a key of the caller that also has a live `cli` row in `approver_keys` (session callers). The registry decides; the projection only narrows (ADR 0010 s8): a key in the projection but not in the registry gives no read. Role only, not `counts_for_dual` (a single-admin key may still approve a tightening). Key holders read every project in the org, because the registry is org-wide and they may approve any project.
- Detail: not readable gives 404 `not_found`, byte-equal to the missing-id 404. Order unchanged from T3 (canonical-id 404, then auth 401), then the read check 404.
- List: parameter checks first (400 `bad_project`, `bad_cursor`, unchanged). With `project=`: not readable gives 404. Without it: org admins and key holders see the org; project admins see their projects only. The filter is in the SQL `WHERE` (`project_id = ANY(...)`) before `LIMIT`, never a post-filter. A caller with no read right gets 404.

### 2.9 Cursor (SHOULD; SQ-4 accepted)

- Tie-break: order by `created_at DESC, id DESC`. `next_cursor` is `<created_at ISO>|<id>`. A cursor with `|` pages by `(created_at, id) < (c, id)`; one without pages by `created_at < c` as today, so the frozen cursor nodes keep 200.
- One `_parse_cursor` parses every cursor. A naive time is read as UTC in Python (`replace(tzinfo=timezone.utc)`), so the bound value is always an aware `datetime` and the database `TimeZone` no longer matters. The `|<id>` part must be a canonical UUID, else 400 `bad_cursor`. An aware time whose conversion to UTC overflows (`9999-12-31T23:59:59-23:59`, `0001-01-01T00:00:00+23:59`) also raises `ValueError` (400 `bad_cursor`, never 500). The frozen node `test_m3_t3_security.py::test_list_proposals_week_and_extreme_cursors_200` keeps 200. No founder row.

### 2.10 Code issue (`enroll.py`)

`INSERT ... RETURNING expires_at`; the response returns that value's ISO form.

## 3. Test plan (qa, tests first)

**Markers.** Sentinels: `M3T4Pending` in `ee/tests/m3_pending.py` and `tests/m3_pending.py` (both exist). Every node that fails today is committed `@pytest.mark.xfail(strict=True, raises=M3T4Pending)` and reaches a named gate before its first T4-dependent assertion. Nodes marked "guard" pass today, carry no marker and no gate, and must be shown to fail under the named mutant. The build removes markers only.

**Gates (MUST 5).** Each failing node names one:
- **G1, publish:** `require_m3(4, not (r.status_code == 400 and r.json().get("error") == "verification_pending"), ...)` on the first publish response. Used by every node in 3.1 whose first T4-dependent observation is a publish that reaches verification today.
- **G2, module:** first statement `require_m3(4, importlib.util.find_spec("agg_cp.sync.publish_verify") is not None, ...)`. Used by every other failing node: non-publish route nodes (reads, cursor, 410, direct publish under the flag, `expires_at`, propose, detail), pure and static nodes. The refusal-audit node calls it after its response assertions (which pass today) and before its first audit assertion. The subprocess node calls it before it starts any process.
- **G3, schema:** `require_m3(4, <chk_published_link present in pg_constraint>, ...)`. Used by the 0019 nodes.

The "Gate" column below says which. Nodes in the two registry-resolution rows store `user_id` dave (MUST 4), so T3's step 10 passes and G1 fires.

**"Nothing written"** means: no new `policy_bundles` row for the project, no `policy_change_approvals` row keyed to a bundle id, proposal still `open`, no `bundle_proposal.publish` row (SHOULD 16), and one `bundle_proposal.publish_refused` row with that reason.

**Fixtures.** `t4_server` (four workers via `make_sync_server`, `extra_env` drops both flag variables): one org with a genesis chain signed by two admins (threshold 2) holding `cli` keys for alice, bob, carol, dave (roles `admin`, `approver`), frank (no role binding; `cli` key, role `approver`), erin (`cli` key, role `viewer`), and a `bundle_signer` equal to the server's key file; org admins alice, bob, carol, dave (dave only as the third stored `user_id` and as a publisher; never in an R4-4 key-holder read node); project-admin pat for one project only; viewer vic; one enrolled device per project that needs `GET /sync/bundle`. A second org with a threshold-1 genesis (single admin) for T0b-7. Nodes that store a new registry version or tamper with the chain use their own org. `t4_demo_server` sets `AGG_DEPLOY_PROFILE=demo` and `AGG_ALLOW_DIRECT_PUBLISH=1`. Sessions fresh at module start; the module must finish within the 900 s fresh window (T3 lesson); if the larger module does not, qa re-authenticates per node group rather than lengthening the window.

### 3.1 `ee/tests/test_m3_t4_publish_verify.py` (pg; 48 functions, 50 node ids)

| Node | Asserts | Fails today because | Gate |
|---|---|---|---|
| `test_publish_verified_loosening_connector_applies_unchanged` | carol proposes a loosening at base 0, alice and bob approve, carol publishes: 201, `verification` `server`, `verified_at` set; `GET /sync/bundle?after=0` returns the envelope and exactly the two approvals; `verify_and_apply` on a fresh layout with the server's verified registry and `_bundle_signer_pub` succeeds; `bundle.json` bytes equal the served envelope | publish is 400 `verification_pending` | G1 |
| `test_publish_tightening_one_approval_201` | after a server row, a tightening with one approval: 201 | same | G1 |
| `test_publish_first_bundle_needs_two_even_if_not_loosened` | base 0, payload equal to deny-all, one approval: 400 `approvals_insufficient`, nothing written | wrong error code | G1 |
| `test_publish_single_approval_loosening_refused_nothing_written` | loosening after a server row, one approval: 400 `approvals_insufficient`, nothing written | wrong error code | G1 |
| `test_publish_forged_approval_refused_nothing_written` | alice valid plus an owner-inserted bob row with a signature over another hash: 400 `approvals_insufficient`, nothing written | wrong error code | G1 |
| `test_publish_proposer_resolved_from_registry_refused` | owner-inserted approval with carol's (proposer) key and stored `user_id` = dave (MUST 4): 400 `proposer_in_approvals` | T3 checks the stored `user_id` only | G1 |
| `test_publish_publisher_resolved_from_registry_refused` | same shape with the publisher's key, stored `user_id` = dave: 400 `publisher_in_approvals` | same | G1 |
| `test_publish_wrong_registry_approval_refused` (rewritten, MUST 3) | own org; registry v2 (two admin signatures) drops bob's key; carol proposes under v2; alice approves through the route; bob's valid signature over the hash is owner-inserted with `user_id` bob; bob's `approver_keys` row stays live (`revoked_at IS NULL`), so a projection-reading mutant gets 201. Publish: 400 `approvals_insufficient`, nothing written | `verification_pending` | G1 |
| `test_publish_counts_for_dual_only_when_two_needed` | single-admin org: a loosening with two distinct users' valid approvals is 400 `approvals_insufficient` with `dual_filter` true; in the same node, `verify_and_apply` with that registry and those approvals accepts (server stricter, T0b-7) | wrong error code | G1 |
| `test_publish_single_admin_key_tightening_201` | single-admin org, owner-inserted `server` row signed by the bundle signer, a tightening with one approval: 201 | `verification_pending` | G1 |
| `test_publish_head_m2_row_loosening_needs_two` | server row 1 (permissive), owner-inserted `m2_unverified` row 2 (strict), proposal at base 2 that loosens only against row 2: one approval 400 `approvals_insufficient`; two approvals 201 | `verification_pending` | G1 |
| `test_publish_loosened_against_server_base_only_needs_two` (MUST 2) | `server` row 1 strict; owner-inserted `m2_unverified` row 2 permissive (signed by the bundle signer, two valid approvals); a proposal at base 2 whose sections equal row 2's (empty against row 2, non-empty against row 1). One approval: 400 `approvals_insufficient`, nothing written; two: 201 | `verification_pending` | G1 |
| `test_publish_first_server_row_after_m2_rows_needs_two` | only an `m2_unverified` row 1; a tightening at base 1 with one approval: 400 `approvals_insufficient` | wrong error code | G1 |
| `test_publish_copies_only_counted_approvals` (MUST 1) | own org at registry v2, which drops eve's `cli` key from v1; carol proposes under v2; alice and bob approve through the route; eve's valid signature over the hash is owner-inserted. 201; the served `change_approvals`, the rows keyed to the bundle id and the audit row's `approver_user_ids` equal the two; `signed_at` equals the stored rows' | `verification_pending` | G1 |
| `test_publish_registry_invalid_refused_and_audited[byte_flip, invalid_json]` (MUST 6) | own org; propose, approve twice, then tamper one stored registry version by owner SQL (a changed byte; or bytes that are not JSON): publish 400 `registry_invalid`, audit row, nothing written; never 500 | `verification_pending` | G1 |
| `test_publish_no_registry_refused` | org with no chain, two approvals inserted by owner: 400 `no_registry` | `verification_pending` | G1 |
| `test_publish_registry_version_stale_refused` | propose, store registry v2, approve (route passes), publish: 400 `registry_version_stale` | `verification_pending` | G1 |
| `test_publish_signer_not_in_registry_refused` | org whose chain names a different bundle signer: 400 `signer_not_in_registry`, nothing written | `verification_pending` | G1 |
| `test_publish_base_invalid_refused[unparseable, wrong_binding]` (SHOULD 7, SQ-8) | owner-inserted head row whose blob does not parse; or parses with a `sequence` or `project_id` that is not the row's: 400 `base_invalid`, nothing written | `verification_pending` | G1 |
| `test_publish_not_yet_valid_refused` (SHOULD 7) | owner-inserted proposal whose stored payload has `not_before` in the future, two valid approvals: 400 `not_yet_valid`, nothing written | `verification_pending` | G1 |
| `test_publish_registry_user_id_canonical_form` (SHOULD 1) | own org; a registry `cli` key whose `user_id` is carol's UUID in upper case: its approval is refused at the approval route as the proposer's, and an owner-inserted copy (stored `user_id` dave) makes publish 400 `proposer_in_approvals` | the uppercase form slips the string compare | G2 |
| `test_publish_concurrent_same_base_one_wins` | two fully approved proposals on one base, published concurrently: exactly one 201 and one 400 `stale_base`; one row at that sequence | both `verification_pending` | G1 |
| `test_publish_records_proposal_and_audit_row` | after 201: proposal `published` with `published_bundle_id`, `published_by`, `published_at`; `bundle_proposal.publish` row names proposer, approvers, publisher, hash | nothing publishes | G1 |
| `test_publish_refusals_audited_not_found_forbidden_not_open` | random canonical id (404), viewer vic (403), published proposal (409; the proposal is owner-inserted as `published` with a linked bundle row, never created by a T4 publish, security addendum A1): one `publish_refused` row each with reason `not_found`, `forbidden`, `not_open` | no audit on these paths | G2 (before the first audit assertion) |
| `test_published_request_requires_bundle_link` | owner INSERT of a `published` request with NULL `published_bundle_id` raises a CHECK violation | no 0019 | G3 |
| `test_published_request_cannot_be_reopened_or_deleted` (SHOULD 2) | as `agg_app`: DELETE of a request is a permission error; UPDATE of a `published` row raises from the trigger | no 0019 | G3 |
| `test_propose_base_row_missing_refused` | owner inserts a `published` request at sequence 1 linked to a random bundle id and no bundle row: propose gives 400 `base_missing`, nothing stored | falls back to deny-all, 201 | G2 |
| `test_propose_registry_invalid_refused_and_audited` (SHOULD) | tampered chain: propose 400 `registry_invalid`, `bundle_proposal.create_refused` row | 201 with `registry_version` 0 | G2 |
| `test_propose_braced_uppercase_real_project_400` (guard) | `{<real id>}` and the uppercase real id: 400 `bad_project_id`, no proposal row for that project | passes; bites under the `_is_uuid` mutant | none |
| `test_approve_urn_id_valid_signed_body_404` (guard) | `urn:uuid:<real proposal id>` with a valid signed body: 404, nothing stored | passes; bites under the `_is_uuid` mutant at the approval route | none |
| `test_proposal_detail_reports_approvals_needed` (SHOULD) | base-0 proposal 2; tightening after a server row 1; after an `m2_unverified`-only history 2 | no field | G2 |
| `test_proposal_detail_base_approvals_are_served_set` (SHOULD 6) | after a publish with an extra stored approval not copied: detail `base.change_approvals` equals the rows keyed to the base bundle id; a base blob whose payload makes `loosened` raise gives `approvals_needed: null` | detail reads the request's approvals | G2 |
| `test_proposal_reads_viewer_404` | vic: list `?project=` 404, detail 404 (byte-equal to the missing-id 404) | 200 | G2 |
| `test_proposal_reads_other_project_admin_404` | pat on another project's proposal: list 404, detail 404 | 200 | G2 |
| `test_proposal_reads_project_admin_200` (guard) | pat on own project: 200 both | passes | none |
| `test_proposal_reads_counting_cli_key_200` (guard) | frank by signer token and by session: 200 both | passes | none |
| `test_proposal_reads_non_counting_cli_key_404` | erin (role `viewer`) by token: 404 | 200 | G2 |
| `test_proposal_reads_session_key_not_in_registry_404` (MUST 11) | a session caller with a live `cli` row in `approver_keys` whose key is absent from the verified registry: 404 on list and detail | 200 | G2 |
| `test_proposal_list_without_project_filters_to_readable` | pat without `project=` sees only own project's items; with more than one page of other projects' rows ahead of pat's, page 1 is full (filter before `LIMIT`) | sees the org | G2 |
| `test_proposal_list_cursor_tie_break_on_id` (SHOULD) | 25 proposals with one fixed `created_at`: walking `next_cursor` yields all 25, no duplicates | page 2 is empty | G2 |
| `test_direct_publish_410_without_flag` (Q3) | admin session, CSRF, valid body: 410 `direct_publish_gone`, no row; no cookie: 410 | 200 | G2 |
| `test_direct_publish_rows_labelled_m2_unverified` (Q3, guard) | on `t4_demo_server`: 200; row `m2_unverified`, `verified_at` NULL; `GET /admin/bundles/{seq}` shows the label | passes today through the 0017 default; pins it | none |
| `test_direct_publish_non_admin_403_under_flag` | vic under the flag: 403 `forbidden`, no row | 200 | G2 |
| `test_direct_publish_noncanonical_project_400_under_flag` (SHOULD 4) | braced form of a real project id under the flag: 400 `bad_project_id`, no row | 200 | G2 |
| `test_direct_publish_audited_under_flag` (SHOULD 4) | 200 under the flag writes one `bundle.direct_publish` row naming the bundle id and the user | no row | G2 |
| `test_direct_publish_rechecked_per_request` | in-process app built with demo and flag, flag removed by `monkeypatch`, POST: 410 | 200 | G2 |
| `test_code_issue_response_expires_at_is_stored_value` | response `expires_at` equals the row's to the second and is about now + 15 min | returns the current time | G2 |
| `test_policy_bundles_sequence_constraint_name_pinned` (guard; security addendum A-S1) | `pg_constraint` holds `policy_bundles_project_id_sequence_key` on `policy_bundles`, `contype = 'u'`, columns exactly `(project_id, sequence)` in that order | passes; bites if a migration renames or drops it | none |

### 3.2 `ee/tests/test_m3_t4_property.py` (5 nodes; the exit)

Exact statement (T4 row, A9 Consequences): **"a `server` row is applied unchanged by a connector that applied every earlier row, and verdicts are equal over all-`server` sequences at the head."** P1: over any generated sequence, every candidate the server accepts is accepted by a connector that applied every earlier row, with the approvals the server copies, and that connector's `bundle.json` bytes equal the server's envelope. P2: over sequences of only `server` rows and a connector at the head, server accepts if and only if the connector accepts. P2's domain excludes what A9 names as deliberately stricter: every key counts for dual, and no approver is the proposer or the publisher. SQ-9 accepted: seeded `random`, 300 seeds per property, the 20-seed route sample.

Rules (MUST 12):
1. **Class labels.** The generator draws a class first, then builds the candidate to hit it, and every candidate carries its label. P1 classes and expected codes: `accept` (201); `single`, `forged`, `wrong_hash`, `wrong_kind` (browser key), `non_counting_role` (viewer role), `head_m2_loosening`, `single_admin_key` (R_single, need 2), `loosened_vs_server_base_only`, `first_server_after_m2` (all `approvals_insufficient`); `proposer_in_approvals`; `publisher_in_approvals`. P2 classes: `accept`, `single`, `forged`, `wrong_hash`, `wrong_kind`, `non_counting_role`.
2. **Non-vacuity.** Per refusal class, at least one candidate refused with that class's expected code (a refusal for another reason does not count). At least 20% accepted and 20% refused in each property. P1 also needs at least 30 accepted candidates with an `m2_unverified` head, and at least 10 accepted with a copied set smaller than the stored set (the `accept` class appends a forged, other-hash or repeat approval with p = 0.4).
3. **P2 refusals.** For every server refusal, the reference connector gets an envelope the test signs with the bundle-signer key over the same payload, plus the full stored approval list, and must refuse too.
4. **Reference connector.** It reaches each state only through `verify_and_apply`, and its registry comes from its own `verify_chain` over the serialised chain, never the server's `Registry` object.
5. **Domain.** User ids are UUID strings. No payload sets `expires_at` (outside P2's domain).

Generator: `random.Random(seed)`, no new dependency. Seeds 0-299 for P1 and P2 each, the seed and the class in every failure message. `AGG_T4_PROPERTY_SEEDS=<n>` adds seeds 300 to 300+n-1 locally; CI never sets it (SHOULD 9). Keys: users u1-u6 (UUID strings) with one `cli` key each (role `approver`), plus a `browser` key of u1, a `cli` key of u2 with role `viewer`, a second `cli` key of u3. Registries built once per module: R_dual (threshold 2, two admin signatures, all keys at genesis) and R_single (threshold 1); P1 draws R_single for `single_admin_key` and with p = 0.25 for `accept`, P2 uses R_dual only. Earlier rows: 0-4; P1 labels each `m2_unverified` with p = 0.3 (given two valid R_dual approvals and kept only if the reference connector accepts it), and the m2 classes force at least one. Candidate payload: `folder_policy.shell.blocklist_action` in {deny, escalate, observe, allow}; `governance_policy.clauses` a subset of four ids with actions from the same set; `mcp_policy.servers` a subset of {s1, s2, s3} with tools from {t1, t2}; `approval.local_fallback`, `allow_requester` booleans; `environment` absent, `prod`, `staging` or `dev`; each section omitted with p = 0.2. Proposer and publisher from u1-u6 (distinct from approvers except in the two exclusion classes). Times: `issued_at = not_before = 1_700_000_000`; registry `expires_at` far ahead; `registry_version = 1`; server `now` = real time. Each sequence uses a fresh layout under `tmp_path`; a trial apply runs on a copy.

| Node | Asserts | Fails today because | Gate |
|---|---|---|---|
| `test_property_server_row_applied_unchanged` | P1 over 300 seeds | `publish_verify` missing | G2 |
| `test_property_verdicts_equal_all_server_at_head` | P2 over 300 seeds | same | G2 |
| `test_property_generator_non_vacuous` | rule 2 over the same seeds, per class and code | same | G2 |
| `test_property_routes_sample` (pg) | P1 through the real routes: seeds 0-19, up to 3 candidates each, approvals by route, owner-inserted `m2_unverified` rows with p = 0.3 (SHOULD 8); every 201 is served by `GET /sync/bundle` and applied unchanged, and the served approvals equal the pure verifier's copied set for the same input; every refusal writes nothing | publish is `verification_pending` | G1 |
| `test_server_deny_all_matches_connector_literal` (the `ast` pin) | parse `src/sandbox/connector/sync/bundles.py`, take the dict literal assigned to `enforced` in `verify_and_apply`'s no-bundle branch, `ast.literal_eval` it; equals `publish_verify.deny_all_base()`; no other dict literal with that value in `ee/src` | `publish_verify` missing | G2 |

### 3.3 `ee/tests/test_m3_t4_static.py` (no pg; 19 functions, 46 node ids)

| Node | Asserts | Fails today because | Gate |
|---|---|---|---|
| `test_create_app_flag_profile_matrix[...]` (12 cases) | refuses with `RuntimeError`: (pilot, 1), (pilot, true), ("", 1), (unset, 1), (Demo, 1), ("demo ", 1), (demo, true), (demo, ""), (demo, 0); builds: (demo, 1), (unset, unset), (pilot, unset) | no check: the 9 refuse cases fail; the 3 build cases pass and stay as guards | G2 on the 9 |
| `test_uvicorn_factory_exits_with_flag_under_pilot` (MUST 10; subprocess) | `python -m uvicorn agg_cp.app:create_app --factory` (the image's ENTRYPOINT form) on a free port with `AGG_DEPLOY_PROFILE=pilot`, `AGG_ALLOW_DIRECT_PUBLISH=1`: exits non-zero within 15 s, and nothing answers on the port. The node stops and reaps any process it started, in `finally` | the process serves | G2 (before the process starts) |
| `test_direct_publish_no_db_before_flag_check` | `create_app` with an unreachable DB URL, no flag, POST with no cookie: 410 within 2 s | the handler connects first | G2 |
| `test_direct_publish_flag_check_is_first_statement` | AST: first statement of `admin_create_bundle` is the flag check that returns; no `Await` or `With` before it | not present | G2 |
| `test_no_await_inside_transaction_anywhere` | the 2.7 visitor (both forms) over every `.py` under `ee/src/agg_cp` except `migrations/`: zero violations; at least the `with`-block count and the assignment-site count qa measures at tests-first (both written into the node) | `sync/bundles.py:221`, `sync/signer.py:423` | G2 |
| `test_await_guard_flags_synthetic_violation[with, assign]` (guard) | the same visitor flags a two-line `with` snippet and an assignment-then-await snippet, and passes the same with `autocommit=True` | passes | none |
| `test_is_project_admin_single_definition` | exactly one function named `is_project_admin` or `_is_project_admin` in `ee/src/agg_cp`, in `rbac.py`; the joined string fragment `scope_type = 'project' AND scope_id = %s AND role = 'admin'` occurs once | 4 definitions, 5 fragments | G2 |
| `test_server_imports_connector_by_name_only` (guard) | every `ImportFrom` of `sandbox.connector.sync.bundles` or `.process` in `ee/src` has `asname is None` and names within the 2.1 list; no `ast.Import` of either module (SHOULD 15) | passes; bites on an alias or a module import | none |
| `test_verify_and_apply_never_referenced_in_server` (guard) | no `Name` or `Attribute` `verify_and_apply` in `ee/src` | passes | none |
| `test_publish_route_calls_shared_verifier` | AST: `publish_proposal` calls `verify_publish` and `sign_and_check`; neither the route nor `proposals.py` calls `_verify_change_approvals` outside the approval route | not present | G2 |
| `test_server_counting_roles_match_connector` | the set literal in `_verify_change_approvals` equals `publish_verify.COUNTING_ROLES` | missing | G2 |
| `test_verify_publish_refusal_codes[...]` (MUST 7; 16 cases) | `verify_publish` raises `PublishRefused` with: `bad_payload` (duplicate key; NaN), `hash_mismatch`, `too_large`, `unknown_fields` (extra key; `change_approvals` present), `binding_mismatch` (org; project; base; `sequence != base+1`), `registry_version_stale` (str; bool; lower), `not_yet_valid`, `expired`, `invalid_bundle` (`loosened` raises) | missing | G2 |
| `test_sign_and_check_wrong_signer_refused` (MUST 7) | `sign_and_check` with a signing key that is not the registry's bundle signer: `signer_not_in_registry` | missing | G2 |
| `test_operator_refusal_ignores_server_rows` (MUST 9, guard) | `sync/escalations.py` and `web/escalations.py` hold no SQL naming `policy_bundles` and read no `allow_requester` | passes; bites if S2 starts honouring a `server` row | none |
| `test_publish_db_error_mapping` (MUST 14) | AST: in `publish_proposal`, the `UniqueViolation` handler tests `diag.constraint_name` against the pinned constraint name; a later handler for other DB errors calls rollback, `_audit_refused` with `internal_error` and returns 500 | not present | G2 |
| `test_server_label_insert_only_in_publish` (SHOULD 3) | exactly one `INSERT INTO policy_bundles` naming `'server'` in `ee/src`, inside `publish_proposal`; no `UPDATE policy_bundles` or `DELETE FROM policy_bundles` in `ee/src` | no such insert | G2 |
| `test_direct_publish_uses_shared_body_reader` (SHOULD 5) | `sync/bundles.py` defines no capped reader and imports `_read_body_capped` and `_strict_json_parse` from `sync/proposals.py` | copy in place | G2 |
| `test_compose_override_only_flag_env` (SHOULD 12) | `ee/deploy/compose.override.yml` parses to exactly `{services: {api: {environment: {AGG_DEPLOY_PROFILE: demo, AGG_ALLOW_DIRECT_PUBLISH: "1"}}}}` | file missing | G2 |
| `test_cursor_naive_read_as_utc` (SHOULD; SQ-4) | `proposals._parse_cursor("2026-11-18T10:00")` returns `(datetime(2026, 11, 18, 10, 0, tzinfo=timezone.utc), None)`; with `|<canonical uuid>` it returns that id as the second item; a `|<id>` part that is not a canonical UUID (braced, uppercase, urn) and an unparseable time raise `ValueError` (the route maps `ValueError` to 400 `bad_cursor`) | no parser function | G2 |

### 3.4 `tests/security/test_m3_t4_cli.py` (root; 4 nodes)

| Node | Asserts | Fails today because |
|---|---|---|
| `test_cli_deny_all_base_matches_connector_literal` (guard) | `ast` pin of the CLI copy against the connector literal | passes |
| `test_cli_deny_all_base_fresh_per_call` (SHOULD) | `change_cmds` has no module-level `DENY_ALL_BASE` dict; `change_cmds.deny_all_base()` called twice returns equal, distinct objects | module-level dict |
| `test_approve_change_esc_in_loosened_error_no_raw_esc` (guard) | a base payload that makes `loosened` raise with an ESC in the message: output holds no raw ESC | passes; bites without `_safe_str` at `change_cmds.py:466` |
| `test_propose_bundle_local_key_messages_sanitised` (SHOULD) | bundle file key with ESC, stub drops or alters it: no raw ESC in either refusal | raw key printed |

### 3.5 Frozen files, counts and the regression runs

- **FR-4 (founder yes).** In `ee/tests/test_m3_t3_proposals.py::test_stale_base_refused_at_approval` and `::test_stale_base_refused_at_publish`, setup only: alice co-approves instead of carol, the co-approval is asserted 201, and carol publishes every publish instead of alice. The stale `M3T3Pending` comment at about line 548 is fixed. No other assertion changes. qa makes this edit in the tests-first commit (both nodes still raise `M3T4Pending` at publish, so they stay xfail); no seal entry, because `test_m3_t3_proposals.py` is not in `M3_T0A_MANIFEST.sha256` (security addendum A3). The build removes the two markers and the then-unused import (F-1, FR-1).
- Nine frozen ee modules name `/api/v1/admin/bundles`. Four only read it or list it (`test_m3_t1_admin_reads.py`, `test_m3_t1_security.py` use GET; `test_t9_routes.py` lists the route; `test_m3_t3_csrf_catalog.py` expects 403 without CSRF, which the dependency still gives before the 410). Five POST to it and expect M2 behaviour (`test_m2_t9_bundles.py`, `test_m2_t12b_server.py`, `test_m2_t16b_change_approvals.py`, `test_m2_t16g_e2e.py`, `test_m2_t16h_proposer.py`; four spawn servers through `make_sync_server`, which copies `os.environ`, and `test_m2_t9_bundles.py` builds `create_app` in-process). Ruling 10's 410 breaks those five by design.
- **FR-5 measurement (MUST 13), on a full scratch tree with the T4 build, before the fixture lands:**
  1. With the flag absent: run the full ee suite; list the 410 failures by node id.
  2. With the fixture in place: the five modules are green.
  3. Any node still failing under the flag is listed separately by id and cause, and is not covered by FR-5. Cause "S-3 admin check" or "capped strict body read": the check stays and that node gets its own founder row (FQ-1). Cause "SHOULD 4 piece": section 2.5. Any other cause: back to the founder.
  4. If the measured module set is not exactly the five above, it goes back to the founder before the fixture lands.
  5. The fixture: one module-scoped autouse fixture in `ee/tests/conftest.py` that matches an exact basename `frozenset` of the measured modules, sets `AGG_DEPLOY_PROFILE=demo` and `AGG_ALLOW_DIRECT_PUBLISH=1`, and restores each variable exactly (absent stays absent, a value comes back byte-equal). One `_SEAL_REPLACED` entry for `ee/tests/conftest.py` in `tests/unit/test_m3_manifest_seal.py`. No assertion changes. The fixture and the seal entry go in the build commit, not the tests-first commit.
- No edit to `m2_gate.py`, `demo.py` or `t1_frozen_routes.json`.
- W runs each file with `--runxfail` before removing markers, then full root, ee and web suites. Any frozen node that fails is reported by id, never edited.

**Node counts (tests-first commit; 4 new files, manifest +4 lines).** qa fills threat 41's node ids in `M3_BASELINE.md` section 5.

| File | Suite | Functions | Node ids | Of which guards (no marker) |
|---|---|---|---|---|
| `ee/tests/test_m3_t4_publish_verify.py` | ee (pg) | 48 | 50 | 6 |
| `ee/tests/test_m3_t4_property.py` | ee | 5 | 5 | 0 |
| `ee/tests/test_m3_t4_static.py` | ee (no pg) | 19 | 46 | 8 ids (3 matrix build cases, 2 synthetic cases, 3 functions) |
| `tests/security/test_m3_t4_cli.py` | root | 4 | 4 | 2 |
| **Total** | | **76** | **ee +101, root +4** | |

## 4. TCB touch list and security rulings

### 4.1 Touch list

**Server TCB (security L on each diff):** `rbac.py` (helper), `sync/bundles.py` (410, flag path, role check, body before DB, explicit label, SHOULD 4, shared reader import), `sync/enroll.py` (helper, `expires_at`), `sync/admin_reads.py` (helper), `sync/signer.py` (`create_link_code_route` body before connect, MUST 8; already on the list), `sync/proposals.py` (publish, R4-4, cursor, base and environment, refusal audits, `_verified_registry`, shared reader; joined the TCB at T3), new `sync/publish_verify.py` (joins the TCB), `migrations/versions/0019_t4_publish.py`, and `app.py` (startup refusal; joins the server TCB, SQ-1 and MUST 10). `M3_PLAN.md` frozen item 3 does not yet list `app.py`, `sync/proposals.py` or `sync/publish_verify.py`; the lead adds them in the T4 docs commit (this revision edits only this file).

**Reviewed by security L though not TCB:** `ee/deploy/compose.override.yml`, `api.py` (helper only), the property test. **Not TCB:** `src/sandbox/cli/change_cmds.py` (SHOULDs).

**Connector TCB: no diff.** Checked three ways: `git diff --exit-code 3f4a396 -- <the 20 paths in M3_PLAN frozen item 2>` returns 0 at the commit (orchestrator before the commit, security L in the review); the static guards in 3.3 (import by name, no alias, no module import, no `verify_and_apply`); the `connector-standalone` CI job count unchanged.

### 4.2 Security rulings (18 Nov 2026, `T4_SECURITY_REVIEW.md` section 3)

| # | Ruling | Conditions, and where this spec carries them |
|---|---|---|
| SQ-1 flag semantics | ACCEPT with conditions | Check first in `create_app`, before `if settings.db_url` and any router; both names stay in `app.py`; `app.py` joins the server TCB; subprocess node (2.5, 3.3, MUST 10) |
| SQ-2 `compose.override.yml` | ACCEPT with conditions | Exactly the two `api` env keys, pinned (2.5, SHOULD 12 in 3.3). T5 carries: section 4.4 |
| SQ-3 R4-4 for key holders | ACCEPT with conditions | Registry decides, projection narrows, SQL filter before `LIMIT`, byte-equal 404 (2.8, MUST 11) |
| SQ-4 naive cursor | ACCEPT | One `_parse_cursor`, aware bound value, canonical UUID after `|` (2.9). No founder row |
| SQ-5 missing signer key | ACCEPT | Rollback first, audited, nothing written, no key path in detail; wrong key file is `signer_not_in_registry` (2.1, 2.2 step 15) |
| SQ-6 order and locks | ACCEPT with conditions | Project lock must return a row; stale check after the lock; constraint-name mapping; other DB errors 500 audited (2.2 steps 8, 9, 16; MUST 14) |
| SQ-7 copied set | ACCEPT with condition | Individually verified, dual-filtered, one per user (2.1 (h), 2.2 step 16; MUST 1) |
| SQ-8 head parse, no re-verify | ACCEPT with condition | Server base and head bind to their own row, else `base_invalid` (2.2 step 12) |
| SQ-9 property scope | ACCEPT with conditions | Section 3.2 rules 1-5 (MUST 12) |
| SQ-10 direct route under flag | ACCEPT | M2 semantics plus SHOULD 4 (2.5) |

### 4.3 Security MUSTs and where they live

| MUST | Where |
|---|---|
| 1 copied set | 2.1 (h); 2.2 step 16; node `test_publish_copies_only_counted_approvals` |
| 2 base-rule node | node `test_publish_loosened_against_server_base_only_needs_two` |
| 3 wrong-registry rewrite | rewritten row in 3.1 |
| 4 third-user stored `user_id` | the two registry-resolution rows in 3.1 (dave) |
| 5 gates | section 3 "Gates", "Gate" column in every table |
| 6 registry rebuild never 500 | 2.2 step 11; node `test_publish_registry_invalid_refused_and_audited[byte_flip, invalid_json]` |
| 7 pure refusal codes | nodes `test_verify_publish_refusal_codes[...]`, `test_sign_and_check_wrong_signer_refused` |
| 8 await guard, both forms; signer fix | 2.7; nodes `test_no_await_inside_transaction_anywhere`, `test_await_guard_flags_synthetic_violation[with, assign]`; `sync/signer.py` in 4.1 |
| 9 S2 guard | node `test_operator_refusal_ignores_server_rows` |
| 10 subprocess exit; `app.py` in the TCB | node `test_uvicorn_factory_exits_with_flag_under_pilot`; 4.1 |
| 11 R4-4 | 2.8; node `test_proposal_reads_session_key_not_in_registry_404` |
| 12 property rules | 3.2 rules 1-5 |
| 13 FR-5 measured first | 3.5 steps 1-5; section 5 |
| 14 locks and DB errors | 2.2 steps 8 and 16; node `test_publish_db_error_mapping` |

### 4.4 Carried to other tasks

**Carried to T5** (SQ-2; MUSTs there, SHOULD 10 and 11 here):
- `pilot.sh` refuses when `COMPOSE_FILE` is set or when `compose.override.yml` would load.
- `doctor` fails unless the running api shows `AGG_DEPLOY_PROFILE=pilot` and no `AGG_ALLOW_DIRECT_PUBLISH`.
- Harden the override check: today `test_merged_args_exclude_compose_override` passes on the word "exclude" alone. It is frozen, so T5 adds a new node that fails if the override can load; editing the frozen one needs a founder row.
- `PILOT.md`: never run bare `docker compose` in `ee/deploy` on a pilot VM (residual risk: the later file wins, and if the pilot file comes last the api refuses to start, which is fail-closed).
- `PILOT.md`: any registry version change makes every open proposal `registry_version_stale`; re-propose and re-approve (SHOULD 10).

**Carried to T7** (SHOULD 14): the evidence pack names the copied (counted) set and states what the `server` label means.

**Carried to T10** (SHOULD 13): the `pilot.sh upgrade` row check reuses `publish_verify` and the connector functions, with no third copy.

### 4.5 Security SHOULDs (section 7 of the review)

| SHOULD | Disposition | Reason |
|---|---|---|
| 1 canonical user ids | in T4 (2.1, 2.4; node in 3.1) | Closes property 4's residual on both routes for one helper |
| 2 revoke DELETE, published immutable | in T4 (2.3; node in 3.1) | Same migration; nothing deletes or re-opens today |
| 3 static guard on `server` inserts | in T4 (3.3) | One AST node pins the label invariant |
| 4 direct route lock, strict parse, canonical id, audit | in T4 (2.5; two nodes in 3.1), each piece dropped to a named demo-only limit if it breaks a frozen M2 node | Restores property 3 on the demo path without editing frozen tests |
| 5 one shared capped reader | in T4 (2.5, 2.7; node in 3.3) | `sync/bundles.py` and `sync/signer.py` are already touched |
| 6 detail served set; null on raise | in T4 (2.4; node in 3.1) | Detail already changes for item 18 |
| 7 tamper-only route nodes | in T4 (3.1) | Cheap; covers `base_invalid` and `not_yet_valid` at the route |
| 8 route sample with m2 rows, served = pure set | in T4 (3.2) | Ties the route copy to the pure verifier |
| 9 extra local seeds | in T4 (3.2) | One env read; CI unchanged |
| 10 `PILOT.md` registry-change line | carried to T5 | T5 writes `PILOT.md` |
| 11 `pilot.sh` and `doctor` refusals | carried to T5 | T5 owns `pilot.sh` and its tests |
| 12 override content guard | in T4 (3.3) | SQ-2 acceptance depends on it |
| 13 upgrade row check reuses `publish_verify` | carried to T10 | T10 builds `pilot.sh upgrade` row checks |
| 14 pack names counted set | carried to T7 | T7 builds the pack |
| 15 `ast.Import` guard | in T4 (3.3, existing node) | One clause in a guard qa already writes |
| 16 "nothing written" adds no publish row | in T4 (section 3) | Definition only |

After this revision, the lead writes "Addendum (T4)" to ADR 0001 A9: flag semantics, R4-4 read rule, refusal order, the copied set, `base_invalid` binding, `internal_error`.

## 5. Founder rows

Answers from `M3_BASELINE.md` founder table, 18 Nov 2026 (session 21), rows 82-84.

- **FR-4:** In `test_m3_t3_proposals.py::test_stale_base_refused_at_approval` and `::test_stale_base_refused_at_publish`, setup only: alice co-approves instead of carol (the proposer, refused by A9 item 7), asserted 201; carol publishes instead of alice (A9 8(g) lets the proposer publish); the stale `M3T3Pending` comment at about line 548 fixed. **Answer: YES.** Applied in 3.5.
- **FR-5:** Sealed `ee/tests/conftest.py` gains one module-scoped autouse fixture that sets `AGG_DEPLOY_PROFILE=demo` and `AGG_ALLOW_DIRECT_PUBLISH=1` for an exact list of frozen M2 modules that POST `/api/v1/admin/bundles`, restoring the environment exactly, with one `_SEAL_REPLACED` entry and no assertion changed. **Answer: YES ON CONDITION of security MUST 13:** measure on the T4 build first (3.5 steps 1-5); any other module set, or a node still failing under the flag, comes back to the founder.
- **FQ-1:** If a frozen M2 node fails under the flag only because of the S-3 admin check or the capped strict body read, the check stays and that node gets its own founder row; T4 does not drop the check. **Answer: YES.**

## 6. Exit check

From the T4 row: forged, single, proposer, stale-base and wrong-registry approvals refused 400 with nothing written; two-approval counts use only `counts_for_dual` keys from T4's first commit (ruling T0b-7); a verified loosening publishes and the connector applies it unchanged; the property test is the exit (section 3.2, rules 1-5 included).

Plus:
1. The four files in section 3 green with markers removed; the two `M3T4Pending` nodes in `test_m3_t3_proposals.py` pass after FR-4.
2. The FR-5 measurement (3.5) recorded by node id before the fixture lands; any FQ-1 or other founder rows it raises answered before the build commit.
3. Full root, ee and web suites green; connector TCB diff empty; frozen route test green with `t1_frozen_routes.json` unchanged.
4. **Q6:** `m2_gate.py` 88/0/0 and `demo.py` 47/47 on a fresh stack after T4 (`down -v`, init-secrets, `--profile demo up -d --build`, with `compose.override.yml` loaded), one row each in `M3_DEMO.md` section 1; `docker compose exec api env` shows `AGG_DEPLOY_PROFILE=demo`; stack removed after. A FAIL blocks the commit.
5. Security L signs off every diff in 4.1 and the property test.

Named limit 7.1 closes only when this exit holds.
