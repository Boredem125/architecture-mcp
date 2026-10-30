# M2 T12b plan: wire the remote approval path and fix the T15 findings

Owner: lead-architect. Status: DRAFT, needs security-engineer and qa-engineer review before any code. Founder approved T12b by phone (24 Oct). Inputs: `M2_SECURITY_SIGNOFF.md` (T15), HANDOFF T12-T14, M2_PLAN D1, D4-D8, M2_BASELINE section 6.

## 1. Goal and exit check
Make a real managed laptop receive web or CLI approvals, verify them in the TCB, and run the action once in the broker, with every T15 High and Medium fixed. Done when all of these hold:
1. Demo steps 3 (enroll), 5 (live dual control: bob 1 of 2, `same_user`, `requester`, `wrong_kind`, carol, then the action runs once in the broker) and 11 (evidence export includes the step 5 done-record, verified offline) pass on the compose stack. The step 5 approvals are made in the web inbox (live) or by the Python browser signer (headless). This is a scripted e2e run, recorded in HANDOFF. It is not the T16 gate.
2. `tests/security/test_m2_t15_hostile.py` passes with every xfail marker removed. The new T12b tests pass. The connector and ee suites are green on Windows and Linux CI, with Semgrep and gitleaks clean.
3. A security diff review (round 2 of T15) on the whole T12b diff returns APPROVE.

## 2. Fix design per finding (TCB: `src/sandbox/connector/approval.py`, `sync/`)
**One verified-state accessor (H2, M2).** New `sync/state.verified_state(layout)` returns a frozen object or None. It holds: the bundle payload from `policy_versions._verified_bundle_payload` (moved to a shared helper, no copy); the registry from `verify_chain(registry.json, pinned_root)`; `device_id`, `project_id` and `operator_user_id` from the enroll record. It returns None if any part fails, and None means: no approvals, denies still apply, prod, deny-all. `current_sequence`, `current_environment` and `_get_enforced_approval` read only this accessor. `last_valid_bundle` is kept for the sticky/locked checks only, and a test greps that no decision path calls it.
- **H1 binding.** Order: validate the id, read the pending record (no claim), then verify each envelope against the record. All of these are required: `payload.request_id == request_id`; `fingerprint` equal to the record's; `command` equal to the uploaded view of the record (`_upload_view(rec)`, the same scrub function the upload uses, so what the human saw is what binds); `device_id` equal to the enrolled device_id; `project_id` equal to the verified bundle's project and the enrolled project; `org_id` equal to the verified registry's org; `payload.key_id == signatures[0].key_id`; exactly one signature; `payload.user_id == registry entry user_id`. Dedup, operator exclusion and the done-record use the registry `user_id`, never the payload's. `reviewer_id` in the payload is ignored for identity.
- **Nonce scope (found while planning; ADR 0010).** Today a verified approval burns its nonce even at 1 of 2, and `awaiting_second` keeps nothing. So the second poll drops bob's re-delivered approval, and dual control can never complete across two polls. Fix: `seen_nonces.json` maps `nonce -> {request_id, not_after}`. The same nonce for the same request is an idempotent re-delivery (counted once). Any other request is a replay and is dropped. Old float-valued entries are treated as replays (fail closed). Entries are pruned after `not_after` plus grace. H1 already blocks cross-request reuse, so this keeps D4.1.
- **H3.** `queue._require_id` runs at the top of `apply_external`. All file access goes through `EscalationQueue` (`get`, `claim`, `release`, `finish`). `_find_pending`, `_claim_pending`, `_finish_external` and `_release_external` are deleted, and so is the flat `.sandbox/pending/` path (one pending dir: `layout.pending_dir`). Approvals are counted before any claim. If there is no valid deny and fewer approvals than required, return with no file touched. After a claim, the record must equal the one that was read, else release and return `changed`.
- **M1.** `not_after` must be a finite int/float, `nonce` a non-empty str of at most 128 chars, `policy_sequence` an int (not bool). Same rule on the server.
- **M2.** The product signature is `apply_external(layout, request_id, approvals, *, clock=None)`. Registry, environment, policy_sequence, operator and enforced approval all come from `verified_state`. `policy_sequence` must equal the verified sequence and the sequence stamped on the record. The hook stamps `bundle_sequence` from the accessor at submit in managed mode, and the upload sends it instead of `policy_version`. Enroll persists `operator_user_id`, `org_id` and `project_id` in `state/sync/enrollment.json` (same temp file and rename, after the fingerprint check). `org_id` must equal the genesis org. The operator id comes from the server (see fork F3). Trust kwargs are removed (fork F1).
- **M3.** Remote decisions end through `EscalationQueue.finish`: scrub, `sign_record`, activity line, `escalations/done`. The done-record carries `remote_approvals` (envelopes), `approved_by` (registry user_ids and key kinds), `environment` and `dual_control_label` (`not_met_adr0003_2.3` for non-prod browser keys, D5.5). Signer: fork F2. A test asserts the record is signed, because `finish` swallows signing errors.
- **M4 (server, `ee/src/agg_cp/sync/escalations.py`).** Require exactly one signature and a registry key row (no `if pub_row`). The tag is the `REMOTE_APPROVAL` constant, and the envelope `kind` must equal it. The payload `request_id`, `device_id`, `project_id` and `policy_sequence` must match the locked escalation row, and `org_id` must match the auth org. M1 types apply. Any mismatch is a 400 and nothing is stored.
- **L1.** If scrub fails, skip that record's upload (and log). **L2.** Type-check each envelope and drop a bad one, so the rest of the batch still applies. **L3.** Stays a named limit (M2_BASELINE 5b).

## 3. Wiring
- **CLI (none exists in `src/sandbox/cli/`).** New `src/sandbox/cli/sync_cmds.py` holds thin click wrappers over the existing library code. `sandbox enroll --server --code --expect-fingerprint [--ca] [--operator]`, `sandbox sync [--once]` (builds `SyncProcess` from the key-home device key and `device_id`, loops `run_once` plus `next_backoff`), `sandbox unenroll --decision FILE`. `sandbox signer link|genesis|sign-registry|approve|deny|unenroll --out` wraps whatever `sync/signer.py` and T7 already provide. Step 2 (T16) needs these, but steps 3, 5 and 11 do not. `classify.py` already protects them (`_APPROVER_SUBCOMMANDS`).
- **Upload.** `_upload_escalations` reads `EscalationQueue(layout).list_pending()`, which is where the hook writes. It sends `_upload_view(rec)`, `fingerprint` and `bundle_sequence`.
- **Decisions.** `_fetch_decisions` groups rows by `request_id`. It drops any id that fails `valid_request_id` or has no local pending record. It rebuilds each envelope as `{kind: REMOTE_APPROVAL (from code), sig_v: 1, payload: signed_payload, signatures: [{key_id, alg: "ed25519", sig}]}` and ignores the server's `user_id` and `kind` columns. Then it calls `asyncio.run(apply_external(layout, rid, envelopes))` and audits each result. The route returns every row each poll; this is fine for M2 because re-delivery is idempotent, and a cursor is a follow-up.
- **Server list.** `GET /api/v1/escalations` adds `device_id`, `fingerprint`, `org_id` and `registry_version` (latest org version): the web needs the full D5.6 set to sign. Same route, no new path.
- **Web inbox (`ee/web/src`).** An inbox view in `App.tsx` lists pending items, with Approve (hidden on prod) and Deny. `approval.ts` takes the stored key from `key-store.loadKey()` and its `key_id`, and never calls `generateBrowserKeyPair`. With no stored key, it shows "link a browser key" and signs nothing.
- **Evidence (step 11).** `export_evidence` adds `registry.json` and `pinned_root.json` to the pack. `verify_evidence` re-verifies each `remote_approvals` envelope offline against that chain and the H1 bindings to its done-record. It reports user_ids, kinds and the non-prod label.

## 4. Tasks (order, owners, tests)
| ID | Task | Owner (tier) | After | Done when |
|---|---|---|---|---|
| b0 | Plan review; forks F1-F3 ruled; ADR 0010 (binding, nonce scope, remote done-record signer, operator source) | lead (L), security (L ruling), qa (W) | - | Security and QA APPROVE; ADR committed |
| b1 | Tests first: `tests/security/test_m2_t12b_remote.py` (H1 field-by-field, two-poll dual control, verified accessor, H3, M1-M3, L1-L2, decisions-to-apply, upload source, CLI via CliRunner, evidence offline), `ee/tests/test_m2_t12b_server.py` (M4, M1, list fields), `ee/web/src/*.test.ts` (stored key used, inbox, no key means no signing). Strict xfail `raises=M2T12bPending`; M2_BASELINE section 4 row | qa (W) | b0 | Committed; the new tests xfail for the stated reason; suites green |
| b2 | Connector TCB: section 2 (H1-H3, M1-M3, L2, nonce, accessor, enroll persist, hook stamp). Removes the T15 markers | backend (W) | b1 | T15 and b1 connector tests pass; full connector suite green; security diff review APPROVE |
| b3 | Connector wiring: CLI, upload, decisions, L1, evidence | backend (W) | b2 | b1 wiring tests pass; suite green; security review |
| b4 | Server: M4, M1, list fields | backend (W) | b1 (parallel with b2) | ee tests pass (pg); security review |
| b5 | Web inbox and stored key | frontend (W) | b1, list contract in section 3 (parallel) | vitest, lint and build pass; strict CSP unchanged |
| b6 | E2E exit check (section 1.1) on the compose stack; security round 2 on the T12b diff; Semgrep, gitleaks; HANDOFF and RESUME update | qa (W), security (W, L if a new attack class), support (S) | b2-b5 | Section 1 holds; git-ops commits each task from the owner's file list |

**Named test-setup edits (b1, each needs security approval):** (1) T12 `_setup_managed_workspace` writes a signed bundle envelope (bundle_signer, with `environment`, `sequence`, `project_id`, `approval`), `enrollment.json` and `device_id`. The approval builder fills the bound fields from the record. `test_managed_approve_allowed_with_local_fallback` depends on this. (2) T12 lines ~436 and ~1856 and T10 ~409 write pending records to `layout.pending_dir`. (3) If F1 = A, the ~28 T12 and 4 T15 `apply_external` call sites drop `registry=`, `environment=`, `policy_sequence=` and `operator_user_id=`, and the state they used is written by the fixture instead. The T15 assertions are not changed. (4) Any T12 nonce test that expects a same-request re-delivery to be refused is restated as "counted once".

## 5. Risks and out of scope
- **Risks.** (a) Nonce rescoping touches replay protection: ADR 0010 and a security L ruling come first. (b) The broker now runs inside `sandbox sync`, so the test must show the command runs with the record's root and cwd, not the daemon's. (c) Approvals older than 15 min expire, so slow dual control gets refused. That is correct by D4.1, and the demo script must say so. (d) Scrub drift between the upload and the binding check: one shared `_upload_view`. (e) A large frozen-test edit (F1 = A): mechanical only, reviewed node by node. (f) The server says `payments-staging` is staging while the connector treats it as prod until the N4 bundle; the e2e run must do step 4's switch first.
- **Out of scope.** L3 (named limit). Server forging of non-prod browser-key approvals (S1, named limit). Remote approvals on prod (N9). A decisions cursor. OS keystore. The T11 retention follow-ups. Demo steps other than 3, 5 and 11 (they belong to T16).

## 6. Forks for the founder-proxy
- **F1, the trust kwargs on `apply_external`.** A: remove them; the fixtures write signed state (named edit 3). B: keep them as tighten-only seams. **Recommend A.** Tighten-only comparisons are more TCB code to get wrong.
- **F2, who signs the remote done-record.** A: a connector-local key `connector:<device_id>` through `sign_record`; the human proof is the embedded envelopes, verified offline. B: the device key with a new tag `agg/remote-done/v1` (an ADR 0007 tag change). C: a local key under the approver's user_id (rejected: it impersonates bob). **Recommend A for M2, B for M3.**
- **F3, the operator binding source (S8; a security property).** A: the server reports it at enroll; it is persisted and printed, and an optional `--operator` flag must match it if given. A compromised server at enroll could mislabel the operator, but dual control still needs two registry humans. This becomes a named limit. B: make `--operator` required, which changes the frozen demo step 3 text (needs a founder ruling in M2_BASELINE). **Recommend A plus the named limit.**

## Security review (b0)
Reviewer: security-engineer (claude-opus-5-5, leader ruling), 24 Oct 2026. Verdict: **APPROVE WITH CONDITIONS.** C1-C9 must be in ADR 0010 and in the b1 tests before b2 starts. Checked in code: shell records have no `fingerprint` (`hook_eval.py:942-964`); the broker runs `record["command"]` in `record["exec_cwd"]` (`broker.py:50-51`); `queue.submit` accepts a caller `request_id` and `claim` does not check `done/` (`queue.py:54`, `:135`); `_save_seen_nonces` swallows write errors (`approval.py:308`); `finish` swallows signing errors (`queue.py:183`).

**Ruling 1 (nonce).** Per-request scope is safe only together with H1 binding and C1-C3. The replay key is **`(key_id, nonce)`, not the nonce alone**: each signer picks its own nonce, so with nonce-only keys a registered approver who reuses carol's nonce under another request poisons her entry and her approval or deny gets dropped. Store `(key_id, nonce) -> {request_id, payload_sha256 (canonical signed payload), not_after (the verified payload value)}`. A re-delivery is idempotent only if request_id and payload_sha256 both match. Any other use of the same `(key_id, nonce)` is a replay and is dropped. Old float entries count as replays.
- **C1 Write-ahead:** persist the nonce file (temp file, fsync, rename) before claiming or executing. If the save fails, nothing executes.
- **C2 Pruning:** prune only after `not_after + grace`, where grace is at least the largest skew `_verify_remote_approval` accepts. Invariant: any envelope that could still pass the expiry check is still remembered.
- **C3 Done is terminal, enforced in the TCB (not only in `_fetch_decisions`).** `apply_external` refuses unless `status(request_id) == "pending"`, so a `done/` or `claimed/` file means no claim. `submit` refuses an id that already exists in any stage. The hook always mints a fresh id from a CSPRNG (never from tool input or a hash). Done-records are never pruned locally.
- Denies: a valid deny bound by H1 is honoured even if its nonce entry conflicts (fail toward deny). Clock rollback by the operator can bring an expired envelope back, but C3 confines it to the same still-pending request.

**Ruling 2 (fix designs).**
- **H1, gap C4:** the fingerprint check is vacuous for shell commands (`"" == ""`), and `exec_cwd`, `root` and `requires_dual` are not bound at all. The hook must stamp, for every kind, `fingerprint = sha256(canonical{kind, tool_name, exact unscrubbed command, exec_cwd, root, requires_dual, bundle_sequence, request_id})`. `apply_external` recomputes it from the record (never trusts a stored value) and refuses an empty one. It compares again on the claimed copy, and the broker executes that same copy. Also required: an active (non-revoked) registry key whose kind is allowed in this environment; `decision` limited to approve or deny; dedup by registry user_id across that user's keys. The required count is never lower than the verified policy, whatever the record says.
- **H1/S8, gap C5:** `operator_user_id` in `enrollment.json` is unsigned, so a hand edit lets the requester count as one of the two approvers. The M4 server route must also refuse an approval from the device's enrolled operator. The residual (hand edit plus a compromised server) is part of the F3 limit below.
- **H2, gap C6:** compute `verified_state` once per decision and pass that snapshot through. No decision path, the hook included, reads `bundle.json`, `registry.json`, `enrollment.json` or `last_valid_bundle`; a grep test enforces this. Rollback (an older genuinely signed bundle, or an older registry prefix): the accessor refuses anything below the high-water sequence or version in `policy_history/` and below the record's stamped `bundle_sequence`. ADR 0010 states the residual (rollback by the operator before submit).
- **H3:** approved as written, plus: resolve the path and require it to stay under `pending_dir.resolve()`, and refuse symlinks and reparse points.
- **M2, gap C7:** `clock=` is a caller-trusted input. In production the clock comes from the D4.3 skew-checked state; the kwarg is a test-only seam that can only tighten. M1, M3, M4, L1 and L2 are approved as written.

**Ruling 3.** F1 = A. **F2 = A, accepted under C8:** the `connector:` user_id prefix is reserved, so the registry rejects it and evidence never counts it as an approver. `verify_evidence` recomputes `approved_by` from the envelopes and fails on any difference. The connector key is loaded before the claim, and if it is unavailable nothing executes, so the remote path never relies on the swallowed signing error. The done-record hash is written to the audit chain. ADR 0010 says this signature proves the record was not altered after it was written; it does not prove who approved. **F3 = A, accepted with C5 and this named limit (exact text):**
> "Operator binding (S8) is trust-on-first-use: the server reports the operator's user_id at enroll and the connector stores it in an unsigned local file. If the server is compromised at enroll time, or the operator hand-edits `enrollment.json` while the server is compromised, the operator can count as one of the two approvers of their own agent's request. Dual control then means two distinct registry humans, not two humans other than the requester. It cannot create an approval that nobody signed. Enroll prints the operator id, and `--operator` must match if it is given. Closed in M3 by an admin-signed device-to-operator binding."

**C9: the b6 round-2 checklist** (each item needs a test or a stated reason):
1. Cross-task replay: approvals for request A, or from another device, project, org or policy sequence, or with another command, cwd or root, applied to B. Each must be refused.
2. Nonce: a `(key_id, nonce)` collision across signers, re-delivery after done, a nonce save failure, the prune and expiry invariant, clock rollback.
3. Server-supplied data: traversal, absolute or overlong ids; the server's `user_id` and `kind` columns ignored; a payload `user_id` or `reviewer_id` that differs from the registry; oversized batches or envelopes (cap them); an unknown request_id.
4. TOCTOU: the pending record edited between read, verify, claim and broker; a crash leaving a file in `claimed/`; a done id resubmitted; two sync processes racing.
5. Unsigned reads: a grep for every decision path; a hand-edited bundle, registry or enrollment; an older signed bundle or registry prefix.
6. CLI through shell forms: `sandbox signer|enroll|unenroll|sync` via `bash -c`, `env`, `python -m sandbox`, the venv console-script path, `python -c` importing `sandbox.cli` or `apply_external`, a script written to a file and then run, `$(...)`, base64 piped to sh. An agent-started `sandbox sync` with a poisoned environment (`PATH`, `BASH_ENV`, `PYTHONPATH`, `LD_PRELOAD`): the broker must use a clean environment and the record's cwd.
7. Enroll: re-enroll over an existing enrollment refused; `org_id` equals the genesis org; fingerprint pinned; `--operator` mismatch refused.
8. Web: the key is a non-extractable CryptoKey and is never regenerated; the signed object is the displayed object; server strings rendered as text; strict CSP unchanged; CSRF on the approve POST; no key means no signature; prod Approve hidden and refused server-side.
9. Evidence: the pack's pinned root is checked against a fingerprint supplied out of band; envelopes are re-verified and re-bound offline; a `connector:` signer is never counted as an approver.
10. Scanners: Semgrep (`.venv`), gitleaks and trivy (`E:\tools`) on the T12b range, with versions and counts recorded.

## T12c: script content binding and broker shell parity (founder rulings 25 Oct 2026; design in ADR 0010 section 9)
Owner: lead-architect. c0 is complete:
- Status 28 Oct (evening): c2 DONE (`dca1873`), c3 and c4 DONE (`c786c5f`), each with a security review file and APPROVE after fixes; c5 built in the uncommitted tree (review fixes done, re-review pending); c6 open. CI green on `c786c5f`.
- The security leader accepted D1-D5, with conditions C-c0-1 to C-c0-7 (written into ADR s9).
- The founder ruled that NF-1 is fixed here.
- The PM cuts are accepted.

QA reviews this table before c1 is committed. T12c is a separate task. It starts after T12b-2 is committed and ends before T16.

**Exit check.**
- An agent that edits or symlink-swaps the script after the escalation gets the broker's refusal on both the local and the remote path: a signed `SCRIPT_CHANGED` done-record plus an alert, and nothing runs.
- An unchanged script runs once, with `$0` and cwd unchanged.
- No approved command runs through cmd.exe. The NF-1 proof tests pass with their markers removed.
- The suites are green on Windows and Linux CI.

Amended 28 Oct 2026 (founder ruling, section "Founder rulings (28 Oct 2026)"; source `docs/ARCH_REVIEW_PM_DISTRIBUTION.md` section 3). Order is the M2 critical-path slot (1' and 1'' run in parallel with 1). Sizes are agent-team working days incl. reviews. T12c's migration is **0015**: the in-tree T12d d2 file already holds 0014.

| Order | ID | Task | Owner (tier) | After | Size (d) | Done when |
|---|---|---|---|---|---|---|
| - | c0 | Plan, ADR 0010 s9, the NF-1 ruling, the PM scope check | lead (L), security (L), qa (W), PM | - | - | DONE 25 Oct: security accepted D1-D5 with C-c0-1 to C-c0-7; founder: NF-1 in T12c; PM cuts accepted; QA review 26 Oct (below) |
| - | c1 | Tests first: `tests/security/test_m2_script_binding.py` (qa); the extras below; `ee/tests/test_m2_t12c_script.py`; `ee/web/tests/script-preview.test.ts`. Strict xfail `raises=M2T12cPending`. `tests/security/test_m2_t12c_nf1.py` already exists (security) | qa (W) | c0 | - | DONE: `d2e758e`, lint fix `1e55f11` |
| 1 | c2 | Connector core: new `connector/script_pin.py` (resolver and pin); `hook_eval.py` (stamping and the floor deny); `approval.py` (fingerprint v2, payload fields, refuse unbound); `broker.py` and `privilege_broker.py` (shell family from `tool_name`, the recorded shell, the argv exec under the pin, no `shell=True`, refusal records and alerts); `install.py` (record `shells` in `session.json`). State 28 Oct: built in the uncommitted tree; locally 505 passed, 2 skipped, 1 failed (`test_extra13_init_refuses_system32_and_windowsapps`, a test-fixture path assertion). Fix it in product code or by a named test edit approved by security, never by weakening it | backend (W), security (L) | c1; T12b-2 committed | 1.5 | c1 connector tests and the NF-1 tests pass with markers removed; full connector suite green on Win and Linux CI; security diff review at L (TCB) APPROVE |
| 2 | c3 | Upload and display: `sync/process.py` (upload fields), `cli/sync_cmds.py` (signer display, body-hash check, payload fields), local `sandbox approve` display | backend (W) | c2 | 1 | Tests pass; security W review |
| 1' | c4 | Server: migration 0015 (`escalations.script` and `script_preview` as separate jsonb fields); upload validation that rejects preview text over 64 KiB, never truncating; a raised request cap; GET list and GET-by-id fields; M4 equality on the three payload fields in the approvals route | backend (W), security (L for the approvals-route equality check, founder 28 Oct) | c1 (in parallel with c2; the files don't overlap) | 1 | ee c1 tests pass (pg); security L APPROVE on the approvals-route check |
| 3' | c5 | Web: script panel in `InboxSection.tsx` (rel, sha256, size, `<pre>` body rendered as text with line numbers); a WebCrypto hash check that gates Approve; payload fields. **Kept (founder 28 Oct; the PM withdrew the pause).** About 80% built in the uncommitted tree. Fallback only if it slips: Approve disabled for script escalations ("approve in the CLI"), never a hash-only approve | frontend (W) | c4 contract | 0.5 | The 6 vitest `it.fails` flip to pass; lint and build pass; strict CSP unchanged; worker-tier review |
| 4 | c6 | E2E: extend `ee/tests/test_m2_t12b_e2e.py` to swap the script after the web and CLI approvals: refused, signed done-record, evidence verifies offline. NF-1 test gap (found drafting `docs/NF1.md`, 30 Oct): the two marker tests in `tests/security/test_m2_t12c_nf1.py` pass only because the broker refuses their old-format record; qa rebuilds them as v2 records run through the broker under the recorded Git bash, adds the corpus round-trip (bash `$BASH_EXECUTION_STRING`, pwsh decoded echo) and the APPROVER_CLI variant from extra test 13, and shows each test red on `dca1873^`. The NF-1 post waits for this. Semgrep, gitleaks; HANDOFF update with both OS results | qa (W), security (W), git-ops | c2-c5 | 1.5 | Exit check holds; the NF-1 tests in `tests/security/test_m2_t12c_nf1.py` pass with markers removed; CI green on Windows and Linux |

**Extra tests (beyond qa's behavioural set):**
1. Fingerprint v2: one changed script byte changes the fingerprint, and so does each of the new fields. A record without `fp_v` is refused by `apply_external`, with no file touched.
2. Resolver table, run on both OSes:
   - bound forms: python, `python3.12`, an absolute interpreter path, node, bash, sh, `pwsh -File`;
   - each unbound reason in 9.1;
   - the deferred forms are unbound, and denied under the floor (C-c0-5): `./x.sh`, `.exe`, `.cmd`, `.bat`, ruby, perl, dash, zsh, `py`, `pythonw`, `powershell`;
   - an NTFS stream operand is unbound;
   - per-family option parsing, so that `-W v` and `-X v` never bind the wrong word.
3. Floor: enrolled, or requires_dual, plus unbound gives a deny with `SCRIPT_UNPINNABLE` whose message names the allowed shape. The same deny covers binary, over-64-KiB, non-UTF-8 and control-character bodies. Standalone single approval escalates and shows "content NOT bound".
4. Meaning is kept: a script prints `$0`, `__file__`, `sys.argv` and cwd, and reads a sibling file. The output is the same as a bash run of the unchanged command. The broker env stays the clean allowlist.
5. Re-resolve: a record with `script` null whose command resolves to a file is refused (`script_not_bound`). An edited pending record is refused by both the fingerprint and the payload check.
6. Windows pin: while the child runs, each of these fails with a sharing violation: an open-for-write, a delete or a rename of the script, and a rename of its folder or of root. The script can still create files in root. The handles are released after normal exit, after a timeout and after an exception. nlink and attributes come from the handle: a test makes a hard link between the pre-check and the open (C-c0-1).
7. POSIX after-run check: a self-swapping script sets `script_changed_during_run` and raises the alert.
8. Refusal record: it is signed (the connector key on the remote path), terminal, chained in the audit and alerted. A re-delivered approval cannot run it.
9. Payload and server: a mismatched `script_rel`, `script_sha256` or `preview_sha256` is refused by the connector and gets 400 from the server. A server-altered body makes the CLI signer exit non-zero and send nothing, and disables Approve on the web. A 64 KiB + 1 preview is rejected, not truncated. `script` and `script_preview` are stored separately (C-c0-7).
10. Preview: a secret is redacted in the preview, the raw-byte hash still binds, and the web renders the body as text, never as HTML.
11. Evidence: the done-record carries `script.rel` and sha256, and `verify_evidence` reports them.
12. A grep or AST test: no `shell=True` is reachable for any approved record, and the broker execs only the lexed argv or the record's family shell (C-c0-6).
13. NF-1, shell parity:
    - a Bash-tool record runs under the recorded bash and a PowerShell-tool record under the recorded pwsh, never `%ComSpec%`;
    - a corpus round-trip is byte-exact (bash prints `$BASH_EXECUTION_STRING`; pwsh echoes the decoded command);
    - the `nf1-noop '&echo pwned> MARKER&'` form and the APPROVER_CLI variant write no MARKER;
    - a missing `shells` field, a missing binary, a path under root or a reparse point each give a signed `SHELL_UNAVAILABLE` and nothing runs;
    - there is no PATH lookup at exec;
    - init lookup order: the `--bash` flag, `CLAUDE_CODE_GIT_BASH_PATH`, `%ProgramFiles%\Git\bin\bash.exe`, the git-derived `<git root>\bin\bash.exe` (a fake git at `X\cmd\git.exe` gives `X\bin\bash.exe`), then PATH;
    - init refuses both `System32\bash.exe` and `...\Microsoft\WindowsApps\bash.exe` even when PATH finds them first (the demo laptop's case);
    - a PowerShell-tool record runs with `pwsh` when present, else System32 `powershell.exe` 5.1, with `-NoProfile -NonInteractive -EncodedCommand`.
9. (added 28 Oct, security sign-off on the CI follow-up) `SHELL_DEADLINE` has no test of its own: feed a crafted slow input with a low monkeypatched `shellwords.DEADLINE_SECONDS` and assert `deny[0] == "SHELL_DEADLINE"`. Lands in c6.

**T16 notes (founder ruling 25 Oct):**
- Demo step 5 stays `steal-env` (curl, binding "none").
- T16 adds a separate bound-script scene, 5(d): bob approves, the agent edits the script, carol approves, and the broker refuses with a signed `SCRIPT_CHANGED` and an alert. The evidence pack holds the refusal and verifies offline.
- T16 must measure and publish how often the agent retries after `SCRIPT_UNPINNABLE`, and whether it gets to the allowed shape.

**Consequences:**
- Tests that run approved commands through the broker need a fixture `session.json` with `shells`.
- Tests that hand-build records for commands that run a script must stamp them through the resolver.
- Each such test edit is named and approved by security.
- Existing workspaces must run `sandbox init` again before the broker will run anything (fail closed, with a clear message).

## T12d: registry genesis bootstrap (design in ADR 0011; blocks T16)
Owner: lead-architect. Status 28 Oct (evening): d0, d1 and d2 DONE (`c786c5f`, `T12D_D2_SECURITY_REVIEW.md` APPROVE after R1-R3); d3 built in the uncommitted tree (16 CLI tests flipped; two server routes `/config` and `/registry/latest` it calls do not exist yet, ruling due in the d3 review); d4 and d5 open. Founder ruling 28 Oct: d2-d5 are finished in M2, not paused (a genesis-only registry holds one key, so no dual control and no revocation; frozen demo steps 2 and 5 need v2 and v3). It started after T12b-2 was committed. The server work (d2) can run in parallel with T12c c2. `cli/sync_cmds.py` is shared with T12c c3, so d3 and c3 run one after the other.

**Exit check.**
- `demo.py` step 2 passes on the compose stack through routes only: genesis, then v2 signed by alice and carol, then v3 signed by both admins.
- It also passes the step 2 negative checks plus the new ones (second genesis, code reuse, a `pending_link` post that does not add its own key).
- The T12b e2e test makes no direct call to `store_registry_version`.

Amended 28 Oct 2026 (same source and conventions as the T12c table).

| Order | ID | Task | Owner (tier) | After | Size (d) | Done when |
|---|---|---|---|---|---|---|
| - | d0 | ADR 0011; security ruling (the B gate, the `pending_link` scope widening, the genesis field checks); QA review; PM check | lead (L), security (L), qa (W), PM | - | - | DONE: security ACCEPT WITH CONDITIONS C-d0-1..13; D0-1, D0-2, D0-4 fixed in `4ef16b6` |
| - | d1 | Tests first (strict xfail `raises=M2T12dPending`; M2_BASELINE row). `ee/tests/test_m2_t12d_genesis.py` (44 tests, pg) and `tests/security/test_m2_t12d_signer_cli.py` (19 tests, CliRunner, mocked HTTP), as listed in the M2_BASELINE section 4 rows | qa (W) | d0 | - | DONE: `a6f09c7` |
| 1'' | d2 | Server: migration 0014 (`setup_codes.purpose`), `migrate.py` genesis code, `POST /api/v1/sync/signer/genesis`, scope rule, `GET /api/v1/sync/signer/candidates`, own-key publish rule in `/signatures` (`ee/src/agg_cp/sync/signer.py`, `registry.py`, `migrate.py`, the migrations file). Built in the uncommitted tree; not yet run on pg | backend (W), security (L, founder 28 Oct) | d1 | 1.5 | The 42 ee genesis tests pass (pg); security L APPROVE |
| 3 | d3 | CLI: `sandbox signer link`, `genesis` and `sign-registry` in `cli/sync_cmds.py` over `connector/sync/signer.py` (byte diff D0-3, typed key_id, N1); fix the `build_genesis` user_id and roles; value-naming confirmation flags | backend (W), security (L) | c3 (shared `cli/sync_cmds.py`), d1 | 2 | The 16 CLI tests pass; full suite green; security APPROVE |
| 5 | d4 | `ee/deploy/demo.py` step 2 headless through routes; move `ee/tests/test_m2_t12b_e2e.py` to the routes and add the grep test that it never calls `store_registry_version`. From the d3 review (`T12D_D3_SECURITY_REVIEW.md` rounds 1-3), each with tests first: server `GET /api/v1/sync/signer/registry` (full chain, org-scoped, read-only for `pending_link`); `iss` and `sub` in the `signer link` response; the migrations job prints the `bundle_signer` public key next to `genesis_code`; F11 (codes from stdin `-`, never argv); F13 (one seed location that `signer approve` reads; must land before d4 exits); R2-4 (an extra `--confirm-key-id` with no added keys refused), R2-5 (`--add` of an existing key refused or confirmed), R2-6 (co-sign trust set no wider than `verify_chain`), R2-7 (local `--threshold` bound; genesis stores the root fingerprint; `--yes` without `--confirm-identity` refused); F14 | qa (W), backend (W) | d2, d3 | 2 | Exit check holds on the compose stack incl. the step 2 negatives; the d3-review items above closed with tests; result recorded in HANDOFF |
| 6 | d5 | **(1) R2-4 identity binding** (d4 review round 2; ADR 0011 amendment A1; founder ruling 13, 30 Oct). Security (L) writes the test spec from A1.4. qa (W) writes the tests first (strict xfail): the server bypass tests B1-B9 with positive twins, run through the routes; the connector pin tests (distinct user_ids in S9 and dual; the G-L5 pin); the e2e and `demo.py` v2 and v3 keys linked through `/signer/link` or browser enrollment, never invented ids. Backend (W) builds A1.1 in `/signatures`: the enrollment match, a `users` row in the same org, `iss`/`sub`, the org admin role binding for new or promoted admin keys, unchanged identity on carried keys, link consumed, `identity_unbound` with a reason class and a refusal audit row; browser keys in `/candidates` if d4 lacks them. S9 and `verify_chain` are untouched. **(2) d4-review items ruled for d5.** The D4-6 distinct-admin bound applies unconditionally (`threshold <= distinct admin user_ids of the new payload`; drop the `len(keys)+1` bound; `test_f10_sign_registry_threshold_flag` gets two admins). A non-secret reason class (HTTP status or "transport refused") goes in the `_get_link_signer_token` ClickException, and the word "token" leaves its log format. Audit records for the registry `verify_failed` and `rollback_refused` statuses. The D4-4 label; the parametrised D4-1 test (v2 with no chain, string or float version). **(3)** Security (L) review (S9's guarantee changes), Semgrep, gitleaks, commit per task | security (L), qa (W), backend (W), git-ops | d2-d4 | 2 (was 0.5: R2-4 +1, the ruled d4 items +0.5) | A1.4 tests and twins pass through the routes; frozen step 2 passes with route-linked keys; probe B refused at v2; root and ee suites green; security L APPROVE; CI green; G-L4 removed from HANDOFF |

## M2 critical path after T12c and T12d (amended 28 Oct 2026)

| Order | ID | Task | Owner (tier) | After | Size (d) | Done when |
|---|---|---|---|---|---|---|
| 7 | T15b | Adversarial review of the T12c and T12d diff (T15 predates both). Includes the d3 round 3 item: the approve/deny paths in `cli/sync_cmds.py` call `urlopen` inline with a plain Authorization header (transport hardening to the `_signer_safe_*` rules; the legacy `_signer_http_get`/`_signer_http_post` helpers are dead code) | security (L) | c6, d5 | 1 | Findings fixed or recorded as named limits |
| 8 | N1 | NF-1 write-up draft (measured, the fix commit linked). Publishing is the founder's outward action | lead (L) | c2 merged, CI green | 0.5 | Draft in docs; founder yes before any post |
| 9 | T16 | Gate run: demo steps 1-11, scene 5(d), the SCRIPT_UNPINNABLE retry measure, `M2_DEMO.md` | qa (W) | T15b | 2.5 | All frozen steps PASS with measured numbers |
| 10 | T17 | One-page quickstart (incl. the genesis code hand-off) and `M2_DONE.md` | lead (L), support (S) | T16 | 1 | Quickstart followed once on a clean checkout; founder approval |

**Critical path:** c2, c3, d3, d4, d5, T15b, T16, T17 = **11 days**, so the M2 gate lands about 12-13 Nov 2026 if nothing slips. c4, d2, c5 and c6 run beside it. Lane X (below) runs in parallel and never gates T16 or T17.

**Re-estimated 30 Oct 2026 (founder rulings 2 and 13).** d5 grows from 0.5 to 2 days (R2-4). c6 is on the path (ruling 2), because it shares `ee/tests/test_m2_t12b_e2e.py` with d4 and d5. From Mon 2 Nov the remaining path is 10 working days:
- d4, the round-2 fixes and demo step 2: about 2;
- d5: 2;
- c6: 1.5;
- T15b: 1;
- T16: 2.5;
- T17: 1.

**So the M2 gate lands about Fri 13 Nov 2026.** If d4 needs a third security round, it moves to Mon 16 Nov. Until d5 is committed, ADR 0011 G-L4 is a named limit: dual control proves two registry user_ids, not two people.

**Paused (founder positioning ruling 28 Oct: AI security is the moat, not AI governance):** the JSONL/OCSF export stays M4 (SENTRY_IDEAS #4); SENTRY_IDEAS #1 (policy advisor) and new AIUC-1 / COMPLIANCE_MAP work are paused. The existing AIUC tests (`tests/unit/test_aiuc_gaps.py` and the pack's AIUC-1 index) stay green; nothing is deleted.

## QA review (c0/d0, 26 Oct 2026)

Reviewer: qa-engineer (W).

**c0-c6**

- (a) Missing: Extra test 12 (grep/AST: no `shell=True` reachable for approved records) is not assigned to any c-row. It fits c1 (static, no implementation needed) or c6 (semgrep). Assign it explicitly.
- (b) Missing: The top-level exit check requires "The NF-1 proof tests pass with their markers removed," but c6's done-when does not name the NF-1 tests. Add "NF-1 markers removed and tests pass" to c6.
- (c) Missing: Extra test 6 (Windows pin sharing-violation) needs elevated privileges or Developer Mode on CI. No skip condition or CI note. If CI lacks the privilege, the test will fail, not skip. Add a `skipif` or a named CI limit.
- (d) Missing: No c-row names who verifies "suites green on Linux CI." c2's security review is Windows-focused (the pin tests). Assign Linux verification to c6 or name it in the exit check owner.
- (e) Untestable as written: Extra test 7 (POSIX after-run self-swapping script) cannot run on Windows CI. If Windows is the only CI runner, mark it POSIX-only or add a Linux CI requirement.

**d0-d5**

- (f) Missing: d1's "two concurrent genesis calls give exactly one v1" requires `pg_advisory_xact_lock`, so it needs a live Postgres instance. d1's done-when says "suites green" but does not say "pg." Add the pg marker or note that this test runs only under the ee pg fixture.
- (g) Missing: d4 does not name the file it moves (`ee/tests/test_m2_t12b_e2e.py`). Name it so git-ops can verify the diff.
- (h) Ordering: d3 is blocked if T12c c3 slips, because both touch `cli/sync_cmds.py`. No fallback is named. Add: "if c3 slips past d3's window, d3 may land first and c3 rebases."
- (i) Missing: d1 CLI tests (`test_m2_t12d_signer_cli.py`) need mocked server responses for `sign-registry --in/--out` chain checks. The done-when should say how the CLI tests avoid a live server (CliRunner with fixtures, or a mock HTTP layer).
- (j) Ordering: d1 says "after d0" but d0's done-when is "APPROVE recorded here" with no date or owner commitment. If the security ruling slips, d1 and everything downstream is blocked with no escalation path named.

**Orchestrator rulings on the QA review (26 Oct 2026; none changes a plan property):**
- (a) Extra test 12 belongs to c1 (static grep/AST test, strict xfail until c2).
- (b) c6 done-when adds: the NF-1 tests in `tests/security/test_m2_t12c_nf1.py` pass with their markers removed.
- (c) The Windows pin tests (extra test 6) need no elevation: share-mode locks and hard links work for a normal user. Only symlink-creating tests carry the existing `_can_symlink` skipif. The `ee-windows` CI job runs them.
- (d) The connector CI job runs on Linux; c6 (qa) records both OS results in HANDOFF.
- (e) Extra test 7 is POSIX-only (`skipif win32`); Windows holds the handles instead (ADR 0010 s9 S-L4).
- (f) The concurrent-genesis test runs only under the ee pg fixture; d1 done-when reads "suites green (pg)".
- (g) d4 moves `ee/tests/test_m2_t12b_e2e.py` to the routes; the grep test lives in `ee/tests/test_m2_t12d_genesis.py`.
- (h) d3 and c3 share `cli/sync_cmds.py`: whichever is ready first lands first; the other rebases on it. Never both at once.
- (i) d1 CLI tests use CliRunner with a mocked HTTP layer (`respx` or `monkeypatch` on the client), never a live server.
- (j) d0 is DONE: the security ruling is recorded in HANDOFF ("Security d0: ACCEPT WITH CONDITIONS C-d0-1..13") and PM agreed. D0-1, D0-2 and D0-4 are fixed in `src/sandbox/protocol/registry.py` before d2; D0-3 in d3 (diff from the bytes); D0-5 in d2 (allowlist scope rule).

## Lane X: cross-tool bypass suite (founder ruling 28 Oct 2026; design in `docs/ARCH_REVIEW_PM_DISTRIBUTION.md` section 4)
Owner: lead-architect. It runs in parallel with the M2 critical path and **never gates T16 or T17**. Security and QA review this section before any lane-X code (TEAM.md step 1).

**Why the existing corpus is not enough.** `tests/security/bypass_corpus.jsonl` (v1, 427 cases) was built with our classifier. 205 of its 427 cases (48%) attack our own CLI or state, and 136 encode our git allowlist. "0 RED" holds by construction. v1 stays frozen as our regression gate and is reported separately with that label, never as a cross-tool number.

| ID | Task | Owner (tier) | Size (d) | Done when |
|---|---|---|---|---|
| X0 | Frozen rule, pre-registered before any run. Contents: a neutral policy spec (denied target actions plus the allowed benign set, translated per tool); scoring (an auto-run of a denied action = bypass; ask or escalate = held; a held benign case = friction; a model refusal or rewrite = excluded and reported, never a win); pinned tool and model versions; OS; N=3 runs per native case; the publication and disclosure rule | lead (L), security (L), qa (W) | 1 | Rule committed with its hash before X8; security and QA sign |
| X1 | Corpus v2 (neutral): re-target cases at canary actions (a canary deploy binary, curl to a local canary server, writes to a canary protected file); map the 205 self-referential cases to each tool's own approval and config surface, or drop them with a reason; grow the pwsh cases | qa (W), security (W) | 2 | v2 schema plus mapping table; v1 untouched |
| X2 | 2026 CVE scenarios as repo fixtures (about 10-15): committed settings with `bypassPermissions` or `disableAllHooks`; workspace-defined hooks; an embedded bare repo with a pre-commit hook under an approved `git commit`; a plugin hook returning allow or rewriting permission files; a symlink escape; the Friendly Fire, TrustFall and CVE-2026-35603 classes (founder ruling 30 Oct, row 10) | security (W) | 2 | Each scenario has a canary oracle |
| X3 | Execution oracle plus per-case workspace reset, on a Linux container and on Windows with Git bash | qa (W) | 1.5 | The oracle detects every canary on a known-bad control |
| X4 | Adapter: our connector (direct hook, deterministic), plus a 20-case sample through real Claude Code | qa (W) | 0.5 | The sample agrees with the hook verdicts |
| X5 | Adapter: Claude Code native permission rules via `claude -p` headless. A 0.5 d spike first: a log-only PreToolUse hook must not change the permission flow and must capture `tool_input` byte for byte | qa (W) | 2.5 | Byte-equality check on every executed case |
| X6 | Adapter: Cursor native command allow/deny list via `cursor-agent` headless. A 0.5 d spike first: headless mode, the permission config, and whether a hook "allow" overrides the list | qa (W) | 2.5 | Same as X5 |
| X7 | Write the lasso exclusion line (below) into the method | lead (S) | 0.25 | In the method section |
| X8 | One run under the frozen rule, Linux and Windows; flakiness and cost recorded | qa (W) | 1.5 | Raw results committed |
| X9 | Results in `docs/BYPASS_SUITE.md`; adversarial fairness review ("would the vendor call this rigged?"); disclosure notes | security (L), lead (L) | 1.5 | Founder yes before publishing |
| | **Total** | | **about 15.25** | |

**Dates (founder ruling 28 Oct).**
- **15 Nov 2026:** X0 frozen rule with its hash; the NF-1 post (N1, founder yes first); corpus v2 plus the X2 CVE scenarios run against the connector only, on Linux and Windows, with our misses listed and each tied to ADR 0012 or a managed-settings install mode; v1 reported separately as the regression gate. This is X0-X4 plus X2, about 7 days of lane X.
- **30 Nov 2026:** X5 and X6 native adapters, the X8 cross-tool run, the X9 fairness review; the 5 discovery calls done.
- **If lane X and the 11-day M2 critical path cannot share the weekly usage limit:** M2 goes first, and 15 Nov keeps only the X0 rule and the NF-1 post.

**Scope rules.**
- **lasso mcp-gateway is excluded** from the shell suite: it proxies MCP traffic and never sees the agent's built-in Bash or PowerShell tool, and it is our M4 upstream (ADR 0006 s7). An MCP sub-suite goes to M4.
- **Vendor disclosure:** any real bypass of Claude Code or Cursor native rules is disclosed to the vendor first. The table is published on time with those rows marked "withheld, disclosed to the vendor on <date>".
- **Approved spend:** $50-150 of API usage plus one Cursor seat. Anything beyond needs the founder's yes.
- **Wording:** competitor cells read "not found in public material", never "No". Our misses are published.

## M3 exit item 1 candidate: ADR 0012 (not written yet)
Separate broker OS identity that holds prod, payment and cluster credentials and re-verifies every signed approval itself; Windows first; about 20 days (ADR and threat model 3, Windows service and custody 9, Linux 4, tests and leader reviews 4). It also moves the device key, pinned root, `high_water.json` and the enrollment markers into broker custody. It needs a security leader ruling before the ADR is accepted. **Precondition:** at least 2 of the 5 discovery calls confirm that credentials sit on developer laptops. The calls also ask the MDM question: "Can your endpoint team push a service to developer laptops, Windows included?" No material claims prevention of a same-user bypass until it ships (M2 limit 4).

## Founder rulings (28 Oct 2026)
Source: the "PM response to architect review, 28 Oct 2026" section in `docs/PM_DISTRIBUTION_ASSESSMENT.md`, and `docs/ARCH_REVIEW_PM_DISTRIBUTION.md`. Founder, verbatim: "approve all six, update T12B_PLAN and RESUME". Standing positioning ruling, same day: AI security is the moat, not AI governance.

| # | Ruling | Where it lands |
|---|---|---|
| 1 | c5 web script panel: keep | T12c table, c5 |
| 2 | Bypass-suite spend approved: $50-150 plus one Cursor seat. Disclose any real native bypass to the vendor first; publish on time with those rows withheld | Lane X scope rules |
| 3 | Kill dates split: 15 Nov = X0 rule with hash, NF-1 post, corpus v2 plus X2 against the connector only with our misses listed, v1 reported separately; 30 Nov = X5/X6, the cross-tool run, the fairness review and the 5 discovery calls. If lane X and the M2 critical path cannot share the weekly limit, M2 first and 15 Nov keeps only the rule and the NF-1 post | Lane X dates |
| 4 | ADR 0012 is M3 exit item 1, if at least 2 of 5 discovery calls confirm credentials on dev laptops; the MDM question is added to the calls | M3 exit item 1 candidate |
| 5 | lasso mcp-gateway excluded from the shell suite; MCP sub-suite in M4 | Lane X scope rules |
| 6 | Leader-tier security review also for T12d d2 (genesis route) and the T12c c4 approvals-route check | T12c c4 and T12d d2 rows |

## Founder rulings (30 Oct 2026)
Source: two product-manager memos (30 Oct) and the orchestrator's compromise. Founder, in chat: "1A, 2 yes".

| # | Ruling | Where it lands |
|---|---|---|
| 1 | Positioning: a security layer for AI agents first (free, MIT); authorization (remote approvals, dual control) and evidence are the paid add-on, never the headline. The paid tier is never called "audit edition" | Pitches, README, T17 quickstart ("security layer (free)" vs "control plane (paid)") |
| 2 | M2 order (option A): D4-1 fixed first; d4, d5, c6, T15b, T16, T17 stay the critical path; the NF-1 post draft (N1, 0.5 d) and the Lane X X0 frozen rule (1 d) run alongside; X1 and X2 after the M2 gate. Kill dates 15 and 30 Nov unchanged | M2 critical path, Lane X |
| 3 | Paid tier = the central store, org-wide evidence export and identity-bound approvals (OIDC, user-bound keys, registry). The local evidence pack, the local audit chain, local approvals and dual control stay MIT (ADR 0004 rule 6) | ADR 0004 |
| 4 | Paid tier name: "control plane" in code and docs; the marketing name waits for the discovery calls | Docs |
| 5 | The first customer may sign a contract with no license-key enforcement (ELv2 plus contract) | ADR 0004 rule 7 deferred |
| 6 | Pricing unit to test first: per enrolled device; per approver seat is tested as the alternative | Discovery calls |
| 7 | The evidence verifier stays MIT, so an auditor or partner can verify without a license | ADR 0004 rule 6 |
| 8 | Discovery calls gain one packaging question: "If the free blocker closed your pentest finding, what would make you pay: central policy, remote dual approval, or signed evidence for incident response?" | Founder's call script |
| 9 | Pitch line (PM, after the 30 Oct market scan): "Blocks the agent actions that native classifiers wave through, on every coding agent; the paid control plane proves which person approved the rest." Lead with the bypass problem, close with the control plane; the free layer never competes on plain deny rules that every platform ships, it is the deterministic floor where native guards fail (disguised scripts, shell parsing, MCP servers, hooks and file tools outside the vendor sandbox, native Windows, the broker outside the agent) | Pitches, NF-1 post, T17 quickstart |
| 10 | Lane X gains the public 2026 attack classes Friendly Fire (disguised script past model-classifier approval), TrustFall (workspace config trusted before review) and CVE-2026-35603 (Windows system-config load path) in the X0 frozen rule and as X2 scenarios; vendor disclosure first as already ruled | Lane X X0, X2 |
| 11 | Discovery calls ask three more questions: (1) "Has anything got past your agents' own deny rules or auto mode, and who found it?" (2) "When an agent action needs a human yes, who must approve it, and has an auditor or incident responder ever asked you to prove who did?" (3) "Would you buy this from a separate vendor, or wait for Anthropic, OpenAI or Defender to ship it, and which budget line pays?" | Founder's call script |
| 12 | Compiling one signed policy into each vendor's native config is deferred: after the M2 gate and only if at least 2 of 5 calls ask for one policy across vendors (at most a Claude Code-only spike in M3). The pre-trust scan of `.mcp.json`, hooks and settings is a small M3 free-layer item, after an overlap check with the settings-tamper checks. M2 stays as ruled in row 2 | M3 candidates |
| 13 | R2-4 (one admin holding two admin keys gets dual control) is fixed in d5 in M2: server-side identity binding for v2+ keys; S9 and dual count distinct user_ids | ADR 0011 amendment A1; the T12d d5 row (2 d); M2 gate about 13 Nov; G-L4 named limit until d5 is committed |
| 14 | `T12D_D4_SECURITY_REVIEW.md` (rounds 1-3) is pushed with the d4 commit, not held until d5: D4-1 is closed, and R2-4 is already public as the G-L4 limit in ADR 0011 A1 | The d4 commit; public repo |
