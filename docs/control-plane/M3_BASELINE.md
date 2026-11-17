# M3 baseline (T0a) and per-task test counts

Author: qa-engineer, 4 Nov 2026. Written before any M3 build commit (freeze rule). Scope and rulings: `docs/control-plane/M3_PLAN.md` (approved 4 Nov 2026; founder rulings 1, 10, 13 at the end). Market check: `docs/COMPETITIVE_CHECK_2026-11-04.md` (local, not committed; cited per ruling 14).

- **Frozen at:** `360f4d5` (M3 plan approved). M2 is done (`M2_DONE.md`, gate approved 4 Nov at `67533cc`).
- **Companions:** `M3_FROZEN_MANIFEST.sha256` (211 tracked files under `tests/`, `ee/tests/`, `ee/web/tests/` plus the four named files, sha256 of the LF git content so `sha256sum -c` passes on the Linux CI checkout), `M3_T0A_MANIFEST.sha256` (203-line seal of the T0a manifest, pinned by `test_m3_manifest_seal.py`), `M3_BASELINE_NODEIDS.txt` (2542 root ids, generated from Linux `python:3.12` with pytest 9.2.0), `M3_BASELINE_EE_NODEIDS.txt` (1026 ee ids), `M3_BASELINE_WEB_NODEIDS.txt` (92 web ids from `vitest run --reporter=json`).

## 1. Scope and rulings pointer

M3 builds the web app a design partner can operate alone, three backend items that ride with it, and the M2 security follow-ups with owners and MUST / SHOULD tags. Full scope: `M3_PLAN.md` sections "Goal", "Tasks", "Frozen for M3" and "Threats added in M3". Founder rulings 1, 10 and 13 (the three that block T0a) are recorded in `M3_PLAN.md` section "Founder rulings" with dates. All 14 founder decisions are ruled there.

## 2. Frozen manifest rules and the CI check per job

### 2.1 Manifest rules

`M3_FROZEN_MANIFEST.sha256` holds the sha256 of the LF content for every tracked file under `tests/`, `ee/tests/` and `ee/web/tests/`, plus four named files: `ee/deploy/m2_gate.py`, `ee/deploy/demo.py`, `docs/control-plane/M2_BASELINE.md`, `docs/control-plane/M2_DEMO.md`. The CRLF-to-LF conversion matches M2's approach: hashes are of the LF git blob content, and `sha256sum -c` runs on the Linux CI checkout where files are already LF on disk. A Windows working copy has CRLF and cannot run `sha256sum -c` directly. Total: 215 entries (118 under `tests/`, 81 under `ee/tests/`, 12 under `ee/web/tests/`, 4 named files; includes the 4 M3 T0a files, 8 earlier tests-first files, 2 T1 tests-first files, and 2 T9a tests-first files).

Changes to frozen files require a founder row in this document's section 3 (named exceptions), the same rule as M2.

**How the manifest grows (one rule, 5 Nov 2026):**

1. **Sealed set.** `M3_T0A_MANIFEST.sha256` is the 203-line manifest as committed at T0a (`c15aba3`). A line in it changes only by a founder row. `tests/unit/test_m3_manifest_seal.py` pins the seal's own sha256 and asserts every sealed line is unchanged in `M3_FROZEN_MANIFEST.sha256`.
2. **Tests-first commit.** A task's tests-first commit adds its new test files, appends their manifest lines and appends their node ids to the node-id lists, in that one commit. Adding lines needs no founder row.
3. **Build commit.** The build may remove only the strict-xfail markers from that task's own new test files, and that same commit updates only those files' manifest lines. Security or the orchestrator checks that the diff of each such file is marker lines only. Any other edit to a committed test file is a frozen change and needs a founder row.
4. **Generation.** Manifest hashes are of LF content. The root node-id list is generated on Linux `python:3.12` with the pytest version CI installs, so the freeze test equals CI.

### 2.2 CI `sha256sum -c` step per job

| CI job | Manifest step | What it checks |
|---|---|---|
| `pytest` (Linux) | `sha256sum -c M3_FROZEN_MANIFEST.sha256 --quiet` | All 203 entries (whole manifest) |
| `ee` (Linux, py3.12 and py3.15) | `grep '  ee/' M3_FROZEN_MANIFEST.sha256 \| sha256sum -c --quiet` | ee/ entries (72 ee/tests/ + 11 ee/web/tests/ + 2 ee/deploy/ + 1 ee/tests/m3_pending.py) |
| `ee-web` (Linux) | `grep '  ee/web/' M3_FROZEN_MANIFEST.sha256 \| sha256sum -c --quiet` | ee/web/ entries (11 test files + m3_pending.ts) |
| `connector-standalone` (Linux) | `grep -v '  ee/' M3_FROZEN_MANIFEST.sha256 \| sha256sum -c --quiet` | Non-ee/ entries (112 tests/ + 4 named files + 2 new T0a files) |

All four jobs now use the M3 manifest (replaces M2). The M2 named exceptions (test_t8p2_session.py, test_t10_multiworker.py, test_m1_t13_review.py, test_t9_routes.py) are in the M3 manifest at their current HEAD hashes with no exclusion, because M3 T0a has no named exceptions. The M2 manifest steps were replaced, not kept alongside, because M3 is a strict superset (all 116 M2 paths are in M3 at their current hashes; the 3 files whose M2 hashes differed are the former M2 named exceptions now frozen at their post-M2 values).

Enforcement test: `TestCIManifestSteps` in `test_m3_t0a_freeze.py` (4 nodes) parses the CI YAML and fails if any job is missing its M3 `sha256sum -c` step.

### 2.3 CI node-id equality steps

| CI job | Step | What it checks |
|---|---|---|
| `ee` (py3.12 only) | `pytest --collect-only` piped through `sort`, `diff` against `M3_BASELINE_EE_NODEIDS.txt` | Collected ee test nodes equal the frozen list |
| `ee-web` | `vitest run --reporter=json`, parsed to `ee/web/tests/<file>::<name>`, `diff` against `M3_BASELINE_WEB_NODEIDS.txt` | Collected web test nodes equal the frozen list |
| `pytest` (Linux) | `test_root_collect_only_equals_nodeids` in `test_m3_t0a_freeze.py` (runs nested `--collect-only tests/`) | Root node IDs equal `M3_BASELINE_NODEIDS.txt` |

The `pytest` job cannot check ee node-id equality because it installs only the root package (`pip install -e ".[dev]"`), not `agg_cp`. The `_EE_AVAILABLE` guard in the freeze test now also checks `import agg_cp` (not just `ee/tests/` on disk), so the ee collect-only test is correctly skipped in the `pytest` and `connector-standalone` jobs.

The ee equality step runs on py3.12 only (`if: matrix.python == '3.12'`). Collection was verified identical on py3.15 (936 vs 936, 0 diff in Docker).

Enforcement test: `TestCINodeIdSteps` in `test_m3_t0a_freeze.py` (2 nodes) parses the CI YAML and fails if the `ee` or `ee-web` jobs are missing their node-id equality steps.

## 3. Node-id lists

| List | File | Count | Source |
|---|---|---|---|
| Root | `M3_BASELINE_NODEIDS.txt` | 2734 | Linux `python:3.12` container, `pytest -q --collect-only -p no:logging tests/`, sorted |
| EE | `M3_BASELINE_EE_NODEIDS.txt` | 1157 | Linux `python:3.12` container, `pytest -q --collect-only -p no:logging ee/tests/`, sorted |
| Web | `M3_BASELINE_WEB_NODEIDS.txt` | 92 | `vitest run --reporter=json` in `ee/web`, paths prefixed `ee/web/tests/` |

Root count: 2734 ids = 2603 at pre-commit + 131 new (130 in `test_m3_t9a_security.py` from T9a rounds 2-5 marker removal plus R5 tests, 1 in `test_m3_manifest_seal.py::TestSealedLinesUnchanged::test_replaced_lines_carry_pinned_hash`). The root node-id file is generated from a Linux `python:3.12` container with `pytest>=9.2.0` to match CI.

EE count: 1157 ids = 1086 at pre-commit + 71 new (71 in `test_m3_t1_security.py` from T1 marker removal plus rounds 3-4 test additions). Generated from Linux `python:3.12` container.

### Founder rows (changes to the frozen list)

| Date | Row | Source |
|---|---|---|
| 5 Nov 2026 | Frozen item 4 allows tags `agg/cp-evidence/v1` (T7), `agg/device-binding/v1` (T9b, F3) and `agg/stop/v1` (T11 only), and the bundle field `approval.require_operator_binding` (T9b, F3). No frozen test file changes. | `M3_PLAN.md` ruling T0b-2 |
| 5 Nov 2026 | `ee/tests/test_t9_routes.py::test_frozen_route_set` gains one set loaded from one reviewed data file of literal routes (`T1_SECURITY_REVIEW.md`, "Frozen route set"). This file is exempt from the seal check; `tests/unit/test_m3_manifest_seal.py` gets one edit to say so. No other sealed line is affected. | `M3_PLAN.md` ruling T0b-11 |
| 5 Nov 2026 | `ee/tests/test_m3_t1_admin_reads.py::test_bundles_detail_applied_by_devices` changes to assert `applied_by: null` with `applied_by_status: "not_reported"`. | `M3_PLAN.md` ruling T0b-12 |
| 5 Nov 2026 | `tests/security/test_m3_t9a_fetch_decisions.py` gets three fixture edits, no assertion changed (`T9A_SECURITY_REVIEW.md` sections 3 T9A-9 and 4): all 41 `{"Date": "Wed, 05 Nov 2026 10:00:00 GMT"}` become a clock-computed `_date_hdr()`; `test_done_request_rows_write_nothing_on_repeat_polls` calls `apply_external` with two approvers; the stub in `test_500_still_uploads_escalations_and_audit_then_raises` returns `{"registry": []}`. | `M3_PLAN.md` ruling T0b-13 |
| 5 Nov 2026 | `ee/tests/test_m3_t1_admin_reads.py::test_devices_list_returns_devices` walks every page with `cursor` until the seeded device is found; the assertion is unchanged. Devices sort by random UUID, so looking at page 1 only depended on test order. | `M3_PLAN.md` ruling T0b-14 |
| 9 Nov 2026 | `ee/tests/test_m2_t11_audit.py::test_load_20_connectors_200_records` sends the same `session_id` in the batch and in its records (`sess-load-{i}`); before, the batch named `sess-load-<device id prefix>` while the records named `sess-load-{i}`. No assertion changed. Security ruling T1-12 refuses a record `session_id` that differs from the batch (400 `bad_body`), so the old fixture was inconsistent with the audit contract (ADR 0001 5.2). Security (L) confirms the diff in T1 round 3. | `M3_PLAN.md` ruling T0b-15 |
| 16 Nov 2026 | T3 F-1 (`T3_SPEC.md`, `T3_SECURITY_REVIEW.md`). `ee/tests/test_m3_t3_proposals.py::test_publisher_not_among_approvals` stays in T3 with setup-only changes: fresh project, a server registry chain with CLI keys for alice, bob and carol, a carol session; carol proposes, alice and bob approve, alice publishes. `test_stale_base_refused_at_approval` and `test_stale_base_refused_at_publish` move to T4 (marker `M3T4Pending`) with the same setup plus carol co-approving, so every assertion is kept, including "publish A returns 200/201". New T3 nodes cover stale base at approval and at publish with an owner-inserted `m2_unverified` row. No assertion relaxed or removed. | Founder yes, 16 Nov 2026 (session 19, security L option) |
| 16 Nov 2026 | T3 F-2. `tests/security/test_m3_t3_signer.py::test_issue_code_sends_project_and_operator` is made stricter: the stub still returns `code`; the node asserts `code_id` is printed and the code value is not. Matches D3, threat 39 and frozen M2 `test_admin_code_issue_no_code_in_response`. | Founder yes, 16 Nov 2026 (session 19) |
| 16 Nov 2026 | T3 S-1 (security property change, ADR 0001 A9 addendum by the lead). Signer tokens may authenticate `signer issue-code`, `propose-bundle` and `publish` only if the token's key is a live `cli` key in the same org, the same role helper as sessions passes, approval `key_id` equals the token key, and audit rows record the auth method and key id. Revoke stays session-only. Token age proves key possession, not a recent login. | Founder yes, 16 Nov 2026 (session 19) |
| 16 Nov 2026 | T3 FR-1 (`T3_SECURITY_REVIEW.md` round 1, F-a). In `ee/tests/test_m3_t3_proposals.py::test_stale_base_refused_at_approval` and `::test_stale_base_refused_at_publish`, a T4 gate goes right after the first publish: `require_m3(4, not (status 400 and error verification_pending), ...)`; `_at_publish` captures publish C's response for it. Setup only, no assertion changed. | Founder yes, 16 Nov 2026 (session 19) |
| 16 Nov 2026 | T3 FR-2 (round 1, F-d). `tests/security/test_m3_t3_signer.py::test_approve_change_diff_from_local_bytes` gets fixture-only changes: `SANDBOX_KEY_HOME` set to `tmp_path`, `--expect-fingerprint` passed, a valid bare-list registry chain stub served, a token returned on mint. No assertion changed. | Founder yes, 16 Nov 2026 (session 19) |
| 17 Nov 2026 | T3 FR-3 (`T3_SECURITY_REVIEW.md` round 4). In `ee/tests/test_t9_routes.py::test_reviewed_routes_admin_entries_are_admin`, allow role `signer_or_session` for exactly the five T3 proposal routes (literal method + path pairs, S-1 cited). Every other `/admin/` entry must stay `admin`. Also ruled: R4-4 (GET proposal list/detail readable by any org member or org cli token) is carried to T4 as a MUST, not fixed in T3. | Founder yes, 17 Nov 2026 (session 20) |
| 16 Nov 2026 | `docs/control-plane/M2_DEMO.md` (sealed line 2) gets two correction notes for finding T1-23: the step 10 server-side `python -m agg_cp.cli audit verify` row (line 101) and the section 6 stack-check row (line 158) recorded a PASS that never ran (no `__main__` guard). The original rows stay; each correction gives the 16 Nov fresh-stack rerun (`m2_gate.py` 88/0/0, `demo.py` 47/0, CLI output `{"org": "acme", "ok": true, "reason": ""}`). The manifest line for this file changes once; `tests/unit/test_m3_manifest_seal.py` pins the new hash for this path only. | Founder yes, 16 Nov 2026 (desktop app) |

### Named skip lists (carried from M2)

| Skip list | Count | Description |
|---|---|---|
| M1 Linux skips (`M1_LINUX_SKIPS.txt`) | 31 | Case-variant, containment, device-prefix/UNC, SEC-27/28 on Linux |
| Windows symlink | 1 | `test_symlink_to_restricted_file_is_restricted` (admin privilege) |
| ee pg marker | ~150 | Tests marked `pg` skip on Windows CI without Docker |
| SEC-27/28 CI Windows | 3 | Need `BARE_PYTHON`; run since M2 T1 with the embeddable CPython |

### Per-job freeze test behaviour

| CI job | Freeze test runs? | Skips in freeze test | Reason |
|---|---|---|---|
| `pytest` (Linux) | Yes (part of full `tests/` suite) | 1: `test_ee_collect_only_equals_nodeids` | `agg_cp` not installed; `_EE_AVAILABLE=False` |
| `pytest` (Windows) | Yes | 0 | Full venv; all deps present |
| `connector-standalone` (Linux) | Yes (in c_tests.py output once tracked) | 2: `test_ee_collect_only_equals_nodeids`, `test_ee_m3_pending_imports` | `ee/` removed; `_EE_DIR_EXISTS=False`, `_EE_AVAILABLE=False` |
| `connector-standalone` (Windows) | Yes | 2 | Same as Linux |
| `ee` (Linux) | No (runs `ee/tests/` only) | n/a | Freeze test is under `tests/` |
| `ee-web` (Linux) | No (runs vitest only) | n/a | Freeze test is Python |

## 4. TCB lists

### 4.1 Connector TCB (20 files)

Diffs only through T7, T9a, T9b, T11; tests first; security L sign-off by node id. T4 imports from `sync/bundles.py` and does not edit it.

1. `src/sandbox/connector/approval.py`
2. `src/sandbox/connector/broker.py`
3. `src/sandbox/connector/hook_eval.py`
4. `src/sandbox/connector/classify.py`
5. `src/sandbox/connector/script_pin.py`
6. `src/sandbox/connector/queue.py`
7. `src/sandbox/connector/signing.py`
8. `src/sandbox/connector/scrub.py`
9. `src/sandbox/connector/keyhome.py`
10. `src/sandbox/connector/evidence.py`
11. `src/sandbox/connector/sync/bundles.py`
12. `src/sandbox/connector/sync/verified_state.py`
13. `src/sandbox/connector/sync/process.py`
14. `src/sandbox/connector/sync/enroll.py`
15. `src/sandbox/connector/sync/state.py`
16. `src/sandbox/connector/sync/audit_upload.py`
17. `src/sandbox/protocol/registry.py`
18. `src/sandbox/protocol/domains.py`
19. `src/sandbox/protocol/envelope.py`
20. `src/sandbox/cli/sync_cmds.py`

### 4.2 Server TCB (11 files)

Security L on every diff.

1. `ee/src/agg_cp/auth.py`
2. `ee/src/agg_cp/rbac.py`
3. `ee/src/agg_cp/db.py`
4. `ee/src/agg_cp/migrations/`
5. `ee/src/agg_cp/sync/escalations.py`
6. `ee/src/agg_cp/sync/bundles.py`
7. `ee/src/agg_cp/sync/registry.py`
8. `ee/src/agg_cp/sync/registry_identity.py`
9. `ee/src/agg_cp/sync/signer.py`
10. `ee/src/agg_cp/sync/enroll.py`
11. `ee/src/agg_cp/sync/audit_upload.py`

## 5. Threats 38-53 with node ids

Node ids are "pending" where no test exists yet. They are fixed at the task's tests-first commit.

| # | Threat | Mitigation | Test task | Node id |
|---|---|---|---|---|
| 38 | Admin reads leak across tenants or by id guessing | FORCE RLS, org scope, uniform 404, cursor tokens bound to org | T1 | `test_m3_t1_admin_reads::test_foreign_org_devices_404`, `::test_foreign_org_bundles_404`, `::test_cursor_bound_to_org`, `::test_no_session_devices_401`, `::test_non_member_refused`, `::test_guard_rls_catalog_unchanged` |
| 39 | Enrollment code shown to the wrong user, logged or cached | Operator-only route, fresh session, shown once, `no-store`, never in `admin_audit` payloads or client storage | T3, T2 | `test_m3_t3_proposals::test_code_second_read_404_and_no_store_header`, `::test_code_value_absent_from_admin_audit`, `test_m3_t1_admin_reads::test_codes_list_status_only` |
| 40 | Page shows one diff, the signer signs another | CLI computes its own diff from the bytes; page and CLI show the proposal hash; an approval has exactly one signature and is verified at the route; `approve-change` verifies the base row and runs `loosened` locally | T3, T2 | `test_m3_t3_proposals::test_proposal_has_hash_and_diff`, `test_m3_t3_signer::test_approve_change_signs_policy_change_v1`, `::test_approve_change_diff_from_local_bytes`, `::test_approval_exactly_one_signature` |
| 41 | Forged, single, proposer, stale-base or wrong-registry approval published | D2.2 with the connector's code; registry from the server's own verified chain; unknown fields refused at proposal; stale base refused at approval and at publish | T4 | `test_m3_t3_proposals::test_propose_unknown_fields_refused`, `::test_proposer_approval_refused`, `::test_stale_base_refused_at_approval`, `::test_stale_base_refused_at_publish`, `::test_publisher_not_among_approvals` (T4 items pending) |
| 42 | Evidence pack passed off as root-verified | Dedicated `evidence_signer_key` and tag; `--expect-root` mandatory; verifier separates root-verified items (registry chain, bundles, change and remote approvals, device checkpoints) from the server's word (audit rows, alerts, ack) | T7 | pending |
| 43 | Pilot started with demo credentials, internal TLS or the direct-publish flag | `pilot.sh` refuses the demo profile; api refuses to start with the flag under pilot | T5 | `test_m3_t5_pilot::TestPilotMergedConfigNoDemo::test_no_demo_service`, `::TestPilotShRefusesDemo::test_pilot_sh_refuses_demo_profile`, `::TestPilotMergedConfigNoDemo::test_no_agg_allow_direct_publish`, `::TestPilotMergedConfigApiProfile::test_api_refuses_to_start_with_direct_publish_under_pilot` |
| 44 | Backup leaks keys or restores a torn state | One encrypted archive of `pg-data` and `secrets/`; key off the VM; T10 before-and-after asserts; upgrade refuses rows a connector would refuse and older signed tags; `restore` needs the recorded sha256; `PILOT.md` lists what a restore rewinds | T5, T10 | pending (T10 items pending) |
| 45 | Download URL carries a bearer | Same-origin cookie plus CSRF header via fetch and blob | T8 | pending |
| 46 | Forged, replayed or flooding stop (T11) | Registry-key signature, `may_sign` row, nonce, 24 h cap, rate limit per key, audited | T11 | pending |
| 47 | Release from quarantine by one person or by the server (T11) | Release is a two-CLI-user loosening bundle naming the stop id | T11 | pending |
| 48 | CSRF on session writes (codes and revoke POSTs check no header today) | `X-CSRF-Token` on every session POST and DELETE; catalog test over `x-agg-rbac` | T3 | `test_m3_t3_csrf_catalog::test_csrf_catalog_is_non_empty_and_includes_named_routes`, `::test_enrollment_codes_no_csrf_403`, `::test_devices_revoke_no_csrf_403`, `::test_untagged_post_delete_routes_in_allowlist` |
| 49 | Script or injected markup rendered in the page; secrets reach the browser | Text rendering with rule 7 escaping; grep test; D1.3 never-rendered list; server strips `stdout`/`stderr` | T2, T8 | pending |
| 50 | Malicious or torn upgrade | Verified release tag signature, not sha256, backup before migrate, downgrade refused, `npm ci --ignore-scripts` | T10 | pending |
| 51 | Keycloak admin exposed on the public name | Secret-file admin password, admin paths unrouted, brute-force protection, own DB role | T5 | `test_m3_t5_pilot::TestKeycloakPilotRealm::test_keycloak_admin_paths_unrouted_on_public_name`, `::test_brute_force_protection_on`, `::test_keycloak_own_postgres_role_and_db` |
| 52 | `doctor` bundle leaks secrets | Redaction list with a planted-secret test | T5 | `test_m3_t5_pilot::TestDoctorRedaction::test_doctor_redaction_planted_fake_secret` |
| 53 | Partner-supplied certificate: private key leaks, or the stack falls back to another issuer | Key is a separate secret mounted by `proxy` only, written by the rotation helper; `auto_https disable_certs` on every listener; PEM private-key rule in `doctor`; ADR 0013 "Partner-supplied certificate path" | T10 | pending |

## 5b. T9b SHOULD rows

Each D5 SHOULD item gets a row here at its tests-first commit with a node id or a named limit wording plus a founder yes row and a pinning test. Empty at T0a.

| Item | Status | Node id or limit | Founder row |
|---|---|---|---|
| Unstorable local audit record stalls its session (from T1 round 3). A record the connector writes but the server refuses (a non-finite number, or nesting above the T1-26 ingest limit) is refused on every cycle: the rest of that session never reaches the server, and the connector raises `audit_upload_failed` once per cycle (the server writes one deduplicated `audit_record_unstorable` alert). Fix on the connector: apply the server's ingest limits when the record is written, before it is hashed, so such a value is never written; the server keeps refusing. | proposed by security (L), 9 Nov 2026; not started | tests-first node to be named at the T9b commit: a record carrying such a value, written through `FolderAudit`, does not stop that session's upload | not approved by the founder (9 Nov 2026, desktop app); **founder yes, 16 Nov 2026 (desktop app): in T9b** |
| Repeated fork attempts write one quarantine row and one `fork` alert each (T1-18; T11 behaviour). Measured: 20 refused fork uploads for one position wrote 20 rows of each. Deduplicate per connector, session and position, the same as `audit_record_unstorable`. | proposed by security (L), 9 Nov 2026; not started | tests-first node to be named at the T9b commit | not approved by the founder (9 Nov 2026, desktop app); **founder yes, 16 Nov 2026 (desktop app): in T9b** |
| The connector maps a 409 `duplicate_record` to `audit_fork` (`src/sandbox/connector/sync/audit_upload.py`, the `status == 409` branch). Two concurrent uploads of the same honest record are labelled a fork on the laptop (measured: 17 of 200 racing uploads got 409 `duplicate_record`). Either the server re-reads after the unique violation and returns the no-op 200 when the stored hash is equal, or the connector tells `duplicate_record` from `fork`. | proposed by security (L), 9 Nov 2026; not started | tests-first node to be named at the T9b commit | founder yes, 9 Nov 2026 (desktop app) |
| Connector-side nesting limit (from T1 round 4, ADR 0001 A4 item 6). The server refuses a record body nested deeper than 1,000 levels (`MAX_NESTING_DEPTH`, `ee/src/agg_cp/sync/audit.py`) and a bundle envelope deeper than 1,000 is `corrupt_bundle`. The connector applies the same 1,000-level limit when it writes a record, before hashing, so no session stalls on a body the server will refuse (row 1 of this table names the effect; this row names the limit). | added by the lead, 12 Nov 2026; not started | tests-first node to be named at the T9b commit: a 1,001-level body written through `FolderAudit` is refused locally with a named alert and the session's upload continues | **founder yes, 16 Nov 2026 (desktop app), with row 1: in T9b** |

## 6. Frozen pilot scenario (`m3_pilot.py` steps 1-9, per Q7)

Steps from M3_PLAN.md Q7. Python + Playwright (Chromium, headless) against the laptop compose stack, pilot profile.

1. `/ready` 200.
2. Admin login through the IdP page.
3. Create project on the page.
4. Issue a code on the page; operator reads it once in a fresh browser context; second read refused.
5. `sandbox enroll --expect-fingerprint <page FP>`.
6. Paste a tightening policy on the Policy page; two approvers `sandbox signer approve-change`; publish from the page; connector escalates within 60 s.
7. `steal-env` preset; escalation in the inbox with context; bob approves with a browser key in the real browser (WebCrypto); carol approves by CLI; marker exists; action ran once.
8. Evidence: page download (T7) or, before T7, `sandbox evidence export` + offline verify.
9. Alerts, audit, quarantine pages show the step-7 records (T8).

**Enforced by:** `test_m3_t6_scenario_static.py` (the only `/api/v1` literal is `/ready`; no `import demo`; no `psql`) and at runtime by Playwright's request log. Output: `results.json` with PASS/FAIL, command, seconds per step; exit 1 on any FAIL.

## 7. Spend

Per founder decision 7: Azure B2s inside the credit; a DNS name (buy a domain if none); Entra free developer tenant. Amounts: [founder].

## 8. T0a exit check

| Check | Result |
|---|---|
| `M3_FROZEN_MANIFEST.sha256` covers all 203 files (112 `tests/` + 72 `ee/tests/` + 11 `ee/web/tests/` + 4 named + 4 new M3 T0a) | PASS |
| Node-id files written (root 2467, ee 936, web 92) | PASS |
| Node-id files equal `--collect-only` output on Linux | PASS (Docker `python:3.12`: root 2467, ee 936, web 92) |
| Node-id equality enforced in CI for all three lists | PASS (`pytest` job: root in freeze test; `ee` job: collect-only diff step; `ee-web` job: vitest diff step) |
| Sentinels import (`tests/m3_pending.py`, `ee/tests/m3_pending.py`, `ee/web/tests/m3_pending.ts`) | PASS |
| CI `sha256sum -c` on M3 manifest in all 4 jobs (pytest, ee, ee-web, connector-standalone) | DONE |
| M2 manifest steps replaced (M3 is strict superset; no named exceptions at T0a) | DONE |
| `npm test` in `ee/web`: 92 passed | PASS |
| Freeze test passes on Linux: `pytest` job 20 passed, 1 skipped (ee collect-only); `connector-standalone` 19 passed, 2 skipped (ee collect-only + ee sentinel) | PASS |
| Freeze test passes on Windows: 21 passed (with pytest >= 9.2.0) | PASS |
| Full Windows suite: 2459 passed, 7 skipped, 1 xfailed, 0 failed | PASS |
| Named exceptions at T0a: none | Confirmed |
| `ee/web/.vitest/` stray deleted and `.vitest/` added to `.gitignore` | DONE |
| Nested pytest leaves no stray files (`.pytest_cache/` is gitignored) | PASS |
