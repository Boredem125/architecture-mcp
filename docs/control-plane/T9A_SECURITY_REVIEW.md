# T9a security review: `_fetch_decisions` never swallows

Reviewer: security-engineer (leader tier). Date: 5 Nov 2026. HEAD `975e2bc` plus the uncommitted T9a build.

Scope: `src/sandbox/connector/approval.py`, `alerts.py`, `sync/process.py`, new `sync/decision_state.py`, `src/sandbox/cli/connector_cmds.py`. Spec: `T9A_SPEC.md`. The T1 files in `ee/` are a separate review.

Verdict: **CHANGES.** T9A-1 to T9A-10 are MUST before the T9a commit. No finding lets a server, a row or the state file approve or run anything: the verdict path is unchanged (section 1). The build still does not meet its own purpose, because several failures stay silent and the new display and rate-limit code breaks under bad input. The findings describe the uncommitted build; keep this file with the commit that carries the fixes. Three further items (H1, H2, H3) are held out of this public file and reported to the orchestrator.

How this was checked: throwaway probes outside the repo, on the real `_fetch_decisions`, `run_once` and `_default_connect`, a real local HTTP and TLS server, and the real `status` and `alerts` commands. "Measured" means one of those runs. The rest is from reading the code. No compose stack and no `m2_gate.py` run.

Scanners on the five product files: Semgrep `p/python` and `p/secrets`, 0 findings; gitleaks `dir`, no leaks; trivy `fs` (secret, misconfig; HIGH and CRITICAL), clean.

Tests today, Windows, venv Python 3.12:

- `test_m3_t9a_fetch_decisions.py` with `--runxfail`: 46 passed, 3 failed (the three nodes in section 4).
- `tests/security/` without that file: 1854 passed, 6 skipped, 14 xfailed, 2 failed. Both are `test_32kib_worst_case_is_classified_under_100ms` timing nodes, run on a loaded laptop; all 12 of its cases pass alone. Not T9a.
- `tests/unit/`: 606 passed, 1 skipped, 1 failed: `test_ee_collect_only_equals_nodeids`, 1084 against 1083. That list covers `ee/tests/`, which T9a does not touch and a concurrent T1 agent was editing. Not T9a; the T1 owner should check it. `test_root_collect_only_equals_nodeids` passes.

These green runs say little about the new code: see T9A-10.

## 1. The TCB change in `approval.py`: verdicts are identical

**Proved, not by the guard test alone.**

- **AST.** With only the additive statements stripped (`_drop` calls, `refusals` appends, the hint block, the `refuse` kwarg, the two new dict keys), `_verify_remote_approval` is identical to HEAD. `apply_external` differs in one place, and that is the comparison tool itself: it also strips the existing `"reason_code": "CLOCK_SKEW"` from the `clock_skew` audit record, which is unchanged context in the diff.
- **Differential, `apply_external`.** HEAD's file against the working tree, 249 envelope sets (each signed field dropped or set to 12 hostile values and re-signed, 16 structural forms, pairs, a deny) in each of 6 scenarios: normal, over-limit skew, no server time, single-admin registry, prod, corrupt nonces. 1494 cases, 0 differences in status, approvals, queue directories or the nonce file. Not vacuous: on both versions, two approvers give `executed`, one gives `awaiting_second`, the same approver twice gives `awaiting_second`, a deny gives `denied`.
- **Differential, `_verify_remote_approval`.** HEAD, new without `refuse`, new with `refuse`: 211 envelopes, 0 differences in result or `seen_nonces`. All 173 `None` results produced exactly one code, and no success produced a code.
- **Can `refusals` reach a decision?** No. In `apply_external` it is only appended to and returned. The only product caller of `apply_external` is `_fetch_decisions`, which reads it after the verdict, for audit and alert text.
- **`refuse` cannot change control flow.** The one callback in product code appends to a list. The hint block before the `try` cannot raise on values parsed from JSON.
- **Minimum?** Nearly. `_refuse_cb` (`approval.py:783-784`) is `refuse=_per_env_refusals.append` written in four lines. T9A-7 adds what the spec asked for and the build left out.

Any TCB edit from T9A-7 reruns this differential. The probe is `test_diff.py` in the review scratch; a permanent version belongs in the new test file (T9A-10).

## 2. `decision_state.json`

| Question | Answer |
|---|---|
| Read by a decision path? | No. Only `process.py` (after the verdict) and `connector_cmds.py` name it. `approval.py`, `hook_eval.py`, `classify.py`, `verified_state.py`, `bundles.py` do not |
| Can a hand edit approve? | No. Measured: state claiming the request counted leaves it pending, and the guard node passes |
| Can a hand edit hide a refusal from the audit trail? | Not today, but only because of the bug in T9A-4: the audit record is written on every poll. When T9A-4 lands, a pre-seeded key would hide it, so T9A-5 bounds that |
| Can a hand edit hide an alert? | Yes, for good, today. Measured: a `last_alerted` or `hour_start` in the far future stops alerts permanently. T9A-5 |
| Corrupt file means empty? | **No.** T9A-5 |
| Atomic write? | Yes: temp file plus `os.replace`, in the same directory. A fixed temp name means two concurrent writers can lose an update, which means more alerts, not fewer. Accepted |
| Reach | `.sandbox/**` is on the non-removable write-protected list (`classify.py:374-381`), so this is a human or an already-escaped process, not a contained agent |

## 3. Findings

### T9A-1 HIGH (MUST): E12 is not fixed. A real outage and a revoked device stay silent

`_refresh_token` and `_fetch_registry` run first, so `_fetch_decisions` never runs in an outage. Spec section 2 and the cycle shape require recording in `run_once`; `process.py:329-334` records nothing, and `process.py:772-773` still raises a plain `SyncError` with no status or stage (`SyncHTTPError` does not exist).

Measured: 5 cycles with the network down at token, and 5 with a valid token and the network down at registry: 0 alerts, no state file, no `Decisions:` line. HTTP 401 at `/sync/token`: 0 alerts. The 3-cycle counter works only in the one case that does not happen in an outage, a failure at the decisions route alone.

Fix: as spec section 2 and its rows `stage=token`, `at <stage>`. Recording must raise nothing but `SyncError` (`test_server_down_escalated_call_stays_pending`) and must not dereference a `None` layout.

### T9A-2 HIGH (MUST): E1 is not fixed. Garbage on a 200 is still "no decisions"

`process.py:189-192` is unchanged and returns `{}`. `process.py:905` then exempts an empty dict from `decisions_key_missing`. Measured through the real transport: an HTML page on a 200 returns `{}` and produces no alert, no status line and a successful cycle. A captive portal or a broken proxy looks exactly like a quiet server, and `unparseable_body` appears nowhere in the code.

Fix: the marker from spec section 7, a `dict` subclass equal to `{}` (`test_m2_t15b_transport.py`), classified as `unparseable_body`. Delete the `if body:` guard: `{}` is not one of the frozen empty shapes, and the `layout is None` seam is handled separately.

### T9A-3 MEDIUM (MUST): the TLS branch never fires on the real transport

`process.py:841` catches `ssl.SSLCertVerificationError`. urllib wraps it. Measured against a real self-signed TLS server: `_default_connect` raises `URLError` with the certificate error in `.reason`, so it falls to `network_error` and waits 3 cycles. `test_tls_verify_failure_alerts_immediately` passes only because its stub raises the bare exception.

Fix: inside `except OSError`, check `isinstance(getattr(exc, "reason", None), ssl.SSLCertVerificationError)`. Drive the test through `_default_connect`. A TLS failure at token or registry must take the same path (T9A-1).

### T9A-4 HIGH (MUST): section 4 rate limiting is not what was specified

All measured:

| Spec | Build |
|---|---|
| Same key later: no alert, **no audit** | `process.py:618` audits every sighting. 10 polls of one refusal: 20 audit records (with the next row), 1 alert |
| `sync_decision_applied` only on a change of `(status, approvals, reason_codes)` | `process.py:1041` writes every poll. E13 is fixed for done requests and returns for pending ones |
| Malformed key `(kind, code)` survives a 200 | `decision_state.py:196-197` clears `decisions_malformed:` on every 200. 5 polls of one bad body: 5 alerts, so one bad route spends the hourly cap by itself |
| One `decision_alerts_suppressed` per hour | `process.py:1117-1118` writes one every cycle once anything was suppressed, outside the cap. 6 cycles: 18 alerts against the claimed 13 per hour. It is also skipped by the early returns at 931 and 1006 |
| `repeats: n` on re-alert | `mark_realerted` is never called, so `repeats` is never set |
| Request keys clear when the request leaves pending | `clear_request` is never called |
| Order: apply failed, fetch failed, refused, malformed | Malformed first. Measured: 6 bad rows use the cycle's 5 slots, and the real refusal in the same response gets no alert |
| 8 reasons per request, `+n more` | `MAX_REASONS_PER_REQUEST` is unused |

Fix: build section 4 as written. Collect a cycle's alerts, sort by the spec's order, then apply the caps; or process rows first and emit last. Spec section 5's "13 lines per hour" and "first sighting chained" must be true afterwards; add nodes (T9A-10).

### T9A-5 HIGH (MUST): a corrupt state file is not empty, and a future timestamp silences alerts

`decision_state.py:55-61` loads values with no type checks and catches only `OSError, ValueError, KeyError`. `begin_cycle` at `process.py:833` is outside every `try`.

Measured:

- `{"hour_start": "x"}`, `{"entries": []}` and `{"entries": "abc"}`: `_fetch_decisions` raises `TypeError`.
- `{"hour_start": "x"}` through `run_once`: the routes hit are registry only. **Decisions, bundle, escalation upload and audit upload all stop on every cycle until someone deletes the file.** Spec section 4: "Corrupt or missing means empty: more alerts, never fewer."
- `{"entries": []}`, `{"entries": "abc"}`, `{"entries": {"k": 1}}`, `{"net_consecutive": "x"}`: `sandbox status` exits 1 with a traceback on a managed workspace. The readers at `connector_cmds.py:497-503, 510-531, 540-548` have the same gap.
- A pre-seeded entry with `last_alerted` in the far future, or `hour_start` in the far future with a large `alerts_this_hour`: no refusal alert, for good (`decision_state.py:135, 170`: a negative elapsed time never expires).

Fix: validate on load, dropping the whole file on any wrong type, and catch `RecursionError` too. Treat any timestamp later than now as absent. With that, a hand edit can delay a refusal's alert and audit record by at most one re-alert window while the refusal persists. That is the bound after T9A-4; state it as a named limit in spec section 5. Wrap the load and `begin_cycle` so no state failure can reach `run_once`.

### T9A-6 HIGH (MUST): `sandbox status` prints the wrong thing

`connector_cmds.py` parses text keys with `split(":")`, in three separate readers that each open the file.

- **The key id is printed as the code.** `parts[-1]` at 471 and 577 is the key id for `decision_refused:<rid>:<code>:<key_id>`. Measured: `awaiting_second: <64 hex>: ...`. The spec's `key <kid12>` form is the only readable part, and only because the reason follows it.
- **Every refusal prints twice:** 464-476 and again at 571-582.
- **`rid.startswith("req-")` at 526** drops real requests from `--json`: `queue.py:54` mints hex ids.
- **E10 is not fixed.** The loop walks `pending` only, and a claimed record is not pending. Measured: `apply_external` raising after the claim leaves the record in `claimed`, and `sandbox status` does not mention it. The "inspect by hand" text never reaches a user: `process.py:1027-1033` fires the same dedupe key a second time, so it lands only in an audit record. This is the spec's own row: "gone from `sandbox status`".
- **Missing:** `awaiting_second: 1 of 2 counted; a different approver must sign`; `at <stage>` on the network line; `HTTP <n>` on fetch lines.

Fix: store `code`, `rid`, `key_id`, `verified`, `reason` as fields in each entry, and write one reader. Never parse a key. Hold the `HTTP`/`stage` text in the entry too. About 70 of the 122 added lines go.

### T9A-7 MEDIUM (MUST): `approval.py` reason gaps. Additive only, then rerun section 1

Each is a silent or wrong answer on the path this task exists to explain.

- **`nonces_corrupt` drops silently** (`approval.py:818-819`). Measured: no alert and no reason code. Add a `refusals.append` before the `continue`.
- **Every post-signature refusal says `verified: False`** (813-816). `nonce_replay`, `operator_self_approval` and all the binding codes are `verified: yes` in spec table 1. Measured: a genuinely signed approval for the wrong command prints `claimed key ... command_mismatch`. That misleads in the other direction: it reads as a forgery. Mark these from a frozenset of post-signature codes, with the user id from the verified registry entry.
- **`prod_refused` covers three causes** (516). Measured on `staging` with an expired registry: the reason is "Remote approval is not allowed on prod". The spec split the label on the same condition; `registry_expired` and `kind_not_allowed` never fire there. Split the label only, in the existing failed branch.
- **Refusals vanish when the request finishes** (884, 1041-1042, and both `key_unavailable` returns at 962-966). Measured: a forged envelope beside two good ones leaves no trace once the pair executes. Spec section 2 has this row with no exception, and the repudiation row in section 5 relies on it. Add `"refusals": refusals` to those returns. Process them in `_fetch_decisions` for every status.

### T9A-8 MEDIUM (MUST): three `apply_external` outcomes are wrong

- **`pending_record_unreadable` is inverted.** `process.py:1096` tests `queue.status(rid) == "unknown"`, but the unknown case was filtered at 976, and the spec row is "while `queue.status` says pending". Measured: an unreadable pending file gives `not_pending` and no alert. Test `== "pending"`.
- **`invalid_id` is silent.** No branch at 1075-1114 handles it. Measured: no alert. A symlink in the pending directory reaches this. Spec: `decision_refused` / `request_id_refused`.
- **`server_time_write_failed` fails the cycle and cannot dedupe.** Spec: cycle OK. `_note_decisions_failure` at 499 sets `_decisions_failed`, and 895 clears the new key in the same call. Measured: exit-code path taken, and an alert on each of 2 polls. Record the time after clearing, without the failed flag.

### T9A-9 MEDIUM (MUST): delete the `_fetch_registry` guard

`process.py:800-801` is outside the T9a list, and it changes behaviour. At HEAD a non-dict 200 from the registry route raises `AttributeError`, the cycle fails, `--once` exits 1. With the guard the cycle succeeds silently and decisions apply on the existing pinned registry.

It gives a hostile server nothing new, since `{}` and a non-200 already return silently. But it turns a loud failure into a silent one in a task about not swallowing. And it exists for one fixture: measured with the guard removed, the only new failure in the 4 sync test files is `test_500_still_uploads_escalations_and_audit_then_raises`, whose stub at line 1479 returns `(200, [], ...)` for a route that never returns a list. The rule is to report the node id, not change product code. Delete the guard, and change that stub to `{"registry": []}` (section 4). A real alert for a malformed registry reply is a T9b candidate.

### T9A-10 HIGH (MUST): the tests do not cover the spec, which is why this review found these

The file has 49 nodes. These from spec sections 6 and 8 do not exist:

`test_verify_remote_approval_has_no_bare_return_none`, `test_outage_at_registry_counts_toward_three`, `test_revoked_token_route_401_alerts_stage_token`, `test_second_poll_writes_no_alert_or_audit`, `test_realert_after_one_hour_with_repeats`, `test_new_code_on_same_request_alerts`, `test_alert_cap_per_cycle_and_hour_with_one_suppressed_record`, `test_capped_key_fires_in_later_window`, `test_cap_does_not_affect_audit_fork`, `test_corrupt_state_file_means_more_alerts_not_fewer`, `test_apply_raises_after_claim_status_says_inspect_and_no_retry`, `test_nonce_save_failed_alerts`, `test_pending_record_unreadable_alerts`, `test_reason_code_reaches_status_and_alerts[code]`, `test_audit_append_failure_still_alerts`, `test_alerts_disabled_still_audits`, `test_malformed_json` through `_default_connect`, and the planned `ee/tests/test_m3_t9a_e2e.py::test_exit_e2e_carol_admin_key_real_server`.

Weak nodes:

- `test_one_bad_row_good_rows_still_apply` asserts only the malformed alert. It never checks that a good row applied, and with one approver it could not.
- `test_done_request_rows_write_nothing_on_repeat_polls` reads `audit_before` and never compares it.
- `test_tls_verify_failure_alerts_immediately`: see T9A-3.

Also add non-string and hostile values for each row field, and the state-file table from T9A-5. Under `M3_BASELINE.md` 2.1 these go in a new tests-first file, which needs no founder row.

### Lows (fix with the above)

- `process.py:849` puts `str(exc)` in the reason. It is our own text from local config today, but the spec says type name or sentence only.
- 3xx lines carry server text; the spec says none.
- `verify_raised` omits the type name.
- `process.py:510` creates a temp directory per cycle when `layout is None`, on the wrong drive. Use a no-op.

### Follow-up for the lead (not T9a)

The decisions failure no longer stopping later steps needs the ADR 0001 amendment named in spec section 7; it is not written. The `.sandbox/pending` fallback in `apply_external` has no product writer (`queue.status` does not look there, so `_fetch_decisions` now skips such a record, which fails closed). Remove it in a later task, with its misleading comment at 720.

## 4. Report-not-relax nodes

**`test_non_counting_approval_shows_awaiting_second_in_status`, `test_non_counting_approval_shows_in_alerts`: fixture bug.** Confirmed: the stub's `Date: Wed, 05 Nov 2026 10:00:00 GMT` writes a server time that is over 2 minutes off, so the approval is refused with `clock_skew` before dual eligibility is examined. Measured with only the Date changed: both pass, and `not_dual_eligible` shows in both views.

**No product ordering bug.** Skew must stay first. Under a bad clock every approval is refused, whichever other reason it might have, and `valid_approvals.clear()` is what enforces that. The user sees `clock_skew`, fixes the clock, and the next poll shows `not_dual_eligible` as a new key and a new alert. Moving dual counting above the skew clear would change a TCB function to improve a message. Refused.

**Exact edit, no assertion changed.** Add once, and replace all 41 occurrences:

```python
def _date_hdr() -> dict:
    from email.utils import formatdate
    return {"Date": formatdate(usegmt=True)}
```

`{"Date": "Wed, 05 Nov 2026 10:00:00 GMT"}` becomes `_date_hdr()`.

**`test_done_request_rows_write_nothing_on_repeat_polls`: fixture bug, and the suggested fix is wrong.** A non-empty `folder_policy` does not help. `policy_requires_dual` is assigned only `True`, at `approval.py:933` and `940`. Measured: non-empty policy, `requires_dual=False`, one approver gives `awaiting_second`. This is the accepted M2 named limit ("dual-only remote approvals until classify"), not a bug. The fixture must use two approvers:

```python
carol_kid = admin_sks[1][2]
carol_approval = _make_remote_approval(
    admin_sks[1][0], request_id=rid, command="echo done-test",
    fingerprint=fp, user_id=f"admin-{carol_kid[:8]}",
)
asyncio.run(apply_external(lay, rid, [bob_approval, carol_approval],
                           clock=lambda: time.time()))
```

Measured with both edits on a scratch copy: 47 of 49 pass, and the 2 others read `_REPO_ROOT` relative to the scratch path (artefact).

**Date-frozen fixtures elsewhere.** Only this file: 41 occurrences. In the rest of it the Date does not change the outcome today, because no other node counts an approval through `_fetch_decisions`; a new node that does would fail, so replace all 41. `ee/tests/test_m3_t1_*.py` and `test_m3_t3_*.py` and `test_m3_t5_*.py`: no frozen `Date`. The only literals are `not_before: 2026-01-01` and `expires_at: 2099-01-01`, which do not depend on today's date until 2099.

**Process.** The three edits and the T9A-9 stub are beyond marker lines, so `M3_BASELINE.md` 2.1 rule 3 needs a founder row before they land.

## 5. Node-id delta

Confirmed. `tests/unit/test_m1_t5_standalone.py:98-101` builds its parameters from `pkgutil.walk_packages` over `sandbox`, so each new module adds one node: `test_sandbox_module_imports_without_agg_cp[sandbox.connector.sync.decision_state]`. The diff of `M3_BASELINE_NODEIDS.txt` adds exactly that and `test_m3_manifest_seal.py::TestSealedLinesUnchanged::test_only_named_paths_are_exempt`; 2544 lines. New nodes from T9A-10 change it again.

## 6. Spec section 7 and the unmanaged view

Every test row in spec section 7 holds today: those nodes are in the two green runs above, including the `layout=None` seam, the short-key server-down node, `KeyboardInterrupt`, the transport file, the `h2` grep, the hook-import guard, and the `_consecutive_failures` and upload-count nodes.

Three constraints need rechecking after the fixes, because they rest on the fix not yet being made:

- The transport marker (T9A-2) must equal `{}` for `test_m2_t15b_transport.py`.
- Recording at token and registry (T9A-1) must keep `test_server_down_escalated_call_stays_pending` and `test_m2_t11_audit.py`'s counts.
- `_consecutive_failures == 0` while decisions return 200.

The `m2_gate.py` rows were not run (no stack). The gate rows at 600 and 677 read as still safe by inspection: the new kinds and sentences carry no `fork` or `truncat`, and `test_alert_kinds_avoid_gate_substrings` passes. Row 870-876 holds: the JSON adds only `decisions` and `decisions_fetch`.

`sandbox status` for an unmanaged workspace: unchanged. Every new branch is behind `if managed`, the JSON dict has the same keys in the same order, and `test_unmanaged_status_output_unchanged` passes. `KeyboardInterrupt` still escapes: there is no `BaseException` handler, and `test_sync_loop_exits_on_keyboard_interrupt` passes.

## 7. E1-E13

| # | State |
|---|---|
| E1 | **Open**, T9A-2 |
| E2 | Fixed at the decisions route; **open** at token, T9A-1 |
| E3 | Fixed at the decisions route; **open** at token and registry, T9A-1 |
| E4 | Fixed, except `{}`, T9A-2 |
| E5 | Fixed |
| E6 | Partly: H2 |
| E7 | Fixed |
| E8 | Partly: H2, H3 |
| E9 | Fixed |
| E10 | Alert yes; `sandbox status` **no**, T9A-6 |
| E11 | Partly, T9A-7 |
| E12 | **Open**, T9A-1 |
| E13 | Fixed for done and claimed; **returns** for pending, T9A-4 |

## 8. Size

The diff is +640/-36 in `process.py`. Much of it is the spec's own table (48 lines of sentences) and is needed. Delete:

- `connector_cmds.py`: three readers become one (T9A-6).
- `process.py`: the second alert at 1027-1033 (dead: same key); `_classify_row_problem` at 703-728, which re-parses what `_rebuild_decision_envelope` just parsed and is called twice at 965-966 (have the rebuild report its reason); the `mkdtemp` branch at 508-510; the unused `entry` at 589.
- `decision_state.py`: `is_first_sighting`, `get_count` (unused). `mark_realerted`, `clear_request` and `MAX_REASONS_PER_REQUEST` are also unused, but T9A-4 wires them rather than deleting them.
- `approval.py`: `_refuse_cb`, as in section 1.

The fixes add code back, and that is fine. The problem with this diff is not its length. It is that most of it was written without the nodes that would have exercised it.

## 9. Regression run

Hold `m2_gate.py` until T9A-4 lands: dedupe changes the number of `sync` audit records, which is the `m2_gate.py:707-713` row in spec section 7, so a run before it proves little and must be repeated.

# Round 2, 5 Nov 2026

Reviewer: security-engineer (leader tier). HEAD `975e2bc` plus the uncommitted T9a fixes. Backend's report was taken as claims and re-measured with throwaway probes outside the repo. No compose stack and no `m2_gate.py` run.

Verdict: **CHANGES.** R2-1 to R2-14 are MUST before the T9a commit. **R2-1 is a verdict change:** a row that HEAD refuses now counts and executes. Round 1 said the verdict path was unchanged, and that was true of that build. The fix for H1 broke it. Three further items (R2-H1, R2-H2, R2-H3) are held out of this public file and reported to the orchestrator. Hold `m2_gate.py`: R2-3 and R2-7 change which records a cycle writes, so a run now would have to be repeated.

## R1. What was re-measured

| Claim | Measured |
|---|---|
| `M3_T9A_BODIES=1 --runxfail`, the two T9a test files: 134 passed | 134 passed |
| `ee/tests/test_m3_t9a_e2e.py`: 1 passed | 1 passed, run alone. It hit the `pytest-timeout` limit once while the mutation runs loaded the laptop |
| Differential 1494 cases, 0 differences | Reproduced: 6 scenarios, 249 each, 0 differences |
| 211-envelope `_verify_remote_approval`, 0 differ | Reproduced. 173 `None` results, each with exactly one code; no success with a code |

**Does the differential still compare HEAD with the working tree?** Yes. `approval_head.py` hashes equal to `git show HEAD:` (line endings ignored), and `NEW` imports `src\sandbox\connector\approval.py` from the working tree, new changes included.

**What it cannot see:**

- It stops at `apply_external`. `_rebuild_decision_envelope` in `process.py` sits above it, so R2-1 passes with 0 differences.
- The `corrupt_nonce` scenario patches `_load_seen_nonces` only, and the save then succeeds. It never reaches a failed save. I measured that separately (R2-14).
- Its AST strip no longer reduces to HEAD, because of the new label branch and the post-signature loop. I read those residues by hand: both are additive.

`tests/security/` and `tests/unit/` together, Windows, venv Python 3.12: 2558 passed, 7 skipped, 14 xfailed, 39 failed. The failures are named, and none is a product defect:

- 37 are `XPASS(strict)` in `test_m3_t9a_fetch_decisions.py`, because the markers are still on.
- 2 are `test_root_collect_only_equals_nodeids` (2629 against 2603) and `test_ee_collect_only_equals_nodeids` (1136 against 1086), because the node-id lists are not updated. Both must be green at the commit, with the marker removal.

Scanners on the five product files and two test files: Semgrep `p/python` and `p/secrets`, 0 findings, 0 errors; gitleaks `dir`, no leaks; trivy `fs` (secret, misconfig; HIGH and CRITICAL), 0 results.

## R2. Findings

### R2-1 HIGH (MUST): a key id is cleaned into a valid one before the signature check. Verdict change

`process.py:1316` runs `_sanitize_field` on the row's `key_id`, and that value goes into `signatures[0].key_id`. `_verify_remote_approval` then compares it with the signed `payload.key_id`.

Measured through `_fetch_decisions`, two genuine approvers, one row's unsigned `key_id` column altered by adding a NUL, a leading LF or a bidi control:

| Build | Request |
|---|---|
| HEAD | Stays pending |
| Working tree | Executes |

No signature is forged, so the server gains no approval it does not hold. It is still the exact change spec section 0 says security blocks: a value HEAD refuses becomes valid. The `sigs[0]` shape at 1323 is not cleaned, so the two shapes also disagree.

`request_id` is safe: `valid_request_id` uses `fullmatch` and is never cleaned.

Fix: delete 1315-1316. Sanitize for display only, never a value used for lookup or verification. No node covers this: with the clean removed, 234 T9a and sync nodes all still pass. Add a node at the `_fetch_decisions` level (a control character in the key column stays `key_id_mismatch`), and a permanent differential over `_rebuild_decision_envelope` plus `apply_external`.

### R2-2 HIGH (MUST): the key id is stored and shown as server text

Spec section 5: "key id must be hex or prints `invalid`". The build prints what the server sent, up to 12 characters (`process.py:1207-1218`).

- `record["key_id"]` at 702 and `alerts.py:97-100` have no cap. Measured: a 1 MB key id gives a 1 MB audit record, a 1 MB state file and a 1 MB alert line. Spec section 5's "about 5 KB" is false.
- ` ` and ` ` are in neither `_CTRL_CHARS` (`process.py:517`) nor `_LOCAL_CTRL` (`connector_cmds.py:661`). Measured: they reach `sandbox status`, `sandbox alerts` and the audit record.

Fix: one helper. A key id prints and stores only if it is lowercase hex of the expected length, else `invalid`. Add ` `, ` ` and the surrogate range to both sets. Add those to `_TERMINAL_CHARS`, and a size node.

### R2-3 HIGH (MUST): section 4 keys and order are still not as specified

| Spec | Build |
|---|---|
| Unverified refusal key is `(kind, rid, code)`; "a server-chosen key id never makes a new key" | `process.py:669` and 1223 use the key id for every refusal, verified or not |
| Malformed key is `(kind, code)`, "one per cycle with `count`", no row data echoed | 1115-1120 emits one per row and keys and records the server's `request_id` |
| A capped key "stays `alerted: false`, so it fires in a later window" | 707-708 calls `mark_realerted` before the cap check at 714. Measured: a capped re-alert writes nothing, counts as a repeat and resets the timer, so the next cycle stays silent too |
| Order rule | 1278 sorts by event only, so a verified refusal has no priority over unverified ones |

Fix all four. Within `decision_refused`, sort verified first, then not yet alerted. Mark only after the cap check passes. See R2-H2 for what this closes.

After the fix, rewrite spec section 5's repudiation row. Today it says "the first sighting of each key is chained", which H3 made untrue. What holds, and was measured under load: `sync_decision_applied` is never capped and carries the request's reason codes, while the per-key record can move to a later window. Keep the rule "more audit, never less" in that wording.

### R2-4 MEDIUM (MUST): an outcome is marked as recorded before it is recorded

`process.py:776-783` stores `outcome_sig` before the append at 798, and 719-721 marks a key alerted even if the append failed. HEAD rewrote the record on each poll, so a transient failure healed. Now one failed append loses that outcome's record for good. Fix: `_audit_decision_record` returns success; mark only on success. Add a node.

### R2-5 HIGH (MUST): T9A-5 is partly done

Type checks cover the wrong-type forms in Round 1, and every Round 1 form passes. The sentence "no state failure can reach `run_once`" is not true.

Measured over 14 hostile forms of the file:

- Some stop the cycle before decisions, so bundle, escalation and audit upload all stop on every cycle. Others stop it after decisions.
- 2 forms make `sandbox status` exit 1 (`connector_cmds.py:550`).
- 3 forms silence a refusal for good.
- The bounded forms behave as the spec's named limit says: one window, then the refusal fires.

Fix:

- Reject non-finite numbers everywhere on load.
- Validate every field of every entry and drop the file on any wrong type. `decision_state.py:82-89` checks only that the value is a dict.
- Treat every timestamp later than now as absent: `first_seen`, `last_seen` and `last_alerted`, plus the `first_seen` fallback at 173.
- Return the entry from a local in `note` (160). `_evict` can delete the key it just added when the clock has stepped back.
- Wrap the load and `begin_cycle` in `_fetch_decisions` (960-961) and every `DecisionState` call on the alert path, so a failure means an empty state.

Exact values are in R2-H3. Add every form to `test_corrupt_state_file_means_more_alerts_not_fewer`.

### R2-6 MEDIUM (MUST): `executed` and `denied` can be suppressed

`_audit_decision_outcome_deduped` says they never are, and the code has no such branch (`process.py:770-773`). Measured: a pre-seeded `outcome_sig` removes the `sync_decision_applied` record for both, on a request that executed or was denied. Fix: skip the dedupe for those two statuses. Add a node. The named limit in spec section 5 relies on this.

### R2-7 HIGH (MUST): T9A-2 is not as written. An empty 200 is still "no decisions"

`process.py:1056` keeps the `if body:` guard that Round 1 said to delete. Measured through the real transport:

| 200 body | Result |
|---|---|
| HTML, deep JSON | `unparseable_body`, alert: closed |
| Empty body, `{}` | No alert, no status line, successful cycle |

Fix: delete the guard, keeping the `layout is None` seam. Measured on a scratch copy with the guard gone: T9a, `t10`, `t11`, `t12b`, `t15b` and `t16a` files, 234 passed. So nothing frozen in those files needs it. Add a node over the real transport for both bodies.

### R2-8 MEDIUM (MUST): the "non-existent path" exists, inside the package

`process.py:596` points `DecisionState` at `__nonexistent_state__` beside the module, and `save()` runs `mkdir` and writes there. Measured: `src\sandbox\connector\sync\__nonexistent_state__\decision_state.json` exists and is untracked; the test suite rewrites it. In an installed package it would write into site-packages, and every `layout=None` process would share one counter.

Fix: a subclass or flag with `save()` as a no-op and no read. Add a node asserting nothing is written. **Delete that directory and never stage it.**

### R2-9 MEDIUM (MUST): the non-200 reason ends in `: str`

`process.py:1020`: `_REFUSAL_SENTENCES.get(code, type(code).__name__)`. Measured line: `decisions not fetched: HTTP 500 at decisions: http_5xx: str`. Server text is computed and thrown away, and the comment at 1016 saying it goes to the audit record is false. The spec says `(server says: <text>)` for 4xx and 5xx.

`_safe_server_text` also calls `scrub_text` outside any `try` at 563. Measured: a raising scrub leaves `_fetch_decisions` as an exception. The spec says "a scrub failure drops the text".

Fix both. Then `test_server_text_capped_scrubbed_no_controls` and `test_server_text_newlines_stripped` start testing something: today no server text reaches the line at all.

### R2-10 MEDIUM (MUST): T9A-1 is partly done

Outages at token and registry now count, and a 401 at token alerts. Measured gaps:

- A 500 at `/sync/token` says `transport_refused at token: SyncError`. The spec row says `http_5xx`, `HTTP 500 at token`.
- `http.client.HTTPException` at token or registry records nothing: `run_once:314, 322` catch only `ConnectionError, OSError, SyncError`. The spec's `transport_error` row covers those stages.
- `process.py:406-411` classifies by `"401" in str(exc)`, so a host name holding those digits is labelled `token_rejected`.

Fix: `SyncHTTPError(SyncError)` with `.status` and `.stage`, as in the spec's cycle shape. Catch `Exception` in the stage wrapper, record, and re-raise.

### R2-11 MEDIUM (MUST): T9A-8 `invalid_id` is still silent

`process.py:1236-1275` has no branch. Measured: no alert, only a `sync_decision_applied status=invalid_id` record. The other two items of T9A-8 hold: `pending_record_unreadable` alerts, and `server_time_write_failed` leaves the cycle OK and dedupes.

### R2-12 MEDIUM (MUST): T9A-6 is not as written

"Never parse a key" and "one reader" were the fix. `connector_cmds.py:487, 573, 603` parse keys with `split(":")`, three functions walk the entries, and the `_show_decisions_status` docstring claims the opposite. Measured:

- A key id that embeds another request's id places a false refusal line under that request (substring match at 486). R2-3 removes the server's route to this; the parsing stays wrong.
- 645-649: both branches print the same text, so a record claimed by a local approval still in progress reads "apply failed ... it will not run again". That is false. Say `<rid> is claimed; if no run is in progress it will not run again, inspect by hand` unless an `apply_raised` entry exists.
- Status prints `[dual control 0/2]` directly above `1 of 2 counted`. The spec says `[dual control 1/2]`.
- Alert lines omit the spec's `<counted> of 2 counted;`. The status rule "N > 0" is fine: it matches the spec's normal row, "1 of 2, no refusal".
- The network line lacks `at <stage>` when the count is below 3, and the HTTP line says `at decisions` twice.
- The closed items hold: `parts[-1]` is gone, each refusal prints once, hex ids reach `--json`, and a claimed record shows.

Fix as Round 1 wrote it: store `code`, `rid`, `key_id`, `verified`, `reason`, `stage`, `status` in each entry.

### R2-13 MEDIUM (MUST): `sandbox alerts` is sanitized only on some write paths

- `records_cmds.py:87` prints stored fields raw. Measured with `color=True` (a terminal): an ESC in a hand-edited alerts file reaches the output. `sandbox status` strips it on read; `sandbox alerts` does not.
- **Plain `CliRunner` hides this**, because click strips ANSI when the output is not a terminal. Any node asserting the absence of a CSI sequence must pass `color=True`.
- `process.py:1273` echoes the local `reason` text. Measured: an LF in a pending record's `script_unbound` makes a forged line in `sandbox alerts`. Use the sentence from `_REFUSAL_SENTENCES` as the spec says.
- `process.py:1214` puts the registry `user_id` in the line unsanitized. Sanitize it.

Fix on read in `alerts_cmd`. `command` has the same gap at HEAD, so this also closes an older one.

### R2-14 LOW (MUST): remove the `try/except` around `_save_seen_nonces`

`approval.py:853-856`. It is not additive, and T9A-7 was additive only.

Measured, HEAD against the working tree, two approvers and a deny:

| Failure | HEAD | Working tree | Queue, both |
|---|---|---|---|
| `_save_seen_nonces` returns `False` | `nonce_save_failed` | same, plus `reason_code` | Pending, nothing claimed |
| Real I/O failure | `nonce_save_failed` | same, plus `reason_code` | Pending, nothing claimed |
| The function raises | Raises `OSError` | Returns `nonce_save_failed` | Pending, nothing claimed |

So the wrap cannot execute, count or consume anything, and no nonce is left unsaved while a claim proceeds: the failed branch returns first. `test_nonce_failed_save_runs_nothing` still passes.

The wrap's only product effect is the third row, and the product function does not raise: its body is in its own `try`, and a huge `not_after` in the file does not raise either. It exists for a fixture. `test_nonce_save_failed_alerts` and `[nonce_save_failed]` patch in a raising function, and those two are the only nodes that fail without it. A raise would already reach `_fetch_decisions` as `apply_raised`.

Fix: restore HEAD's lines and make both fixtures return `False`, as the product does.

`verified: True` is sound. Those codes are emitted only after `vk.verify`, and the user id comes from `vs.registry` or the verified result, never the payload. `refusals` is still only appended and returned, so no return path carries it into a decision.

### Lows

- `process.py:989` still puts `str(exc)` in the reason. `verify_raised` still omits the type name.
- Reason lines say `awaiting_second` when the request executed or was denied. Use the real status.
- `decisions_malformed` and `server_time_write_failed` keys never clear, so status says "last response malformed" long after recovery. Show an age or use `last_seen`.
- Section 8 deletions not done: `_classify_row_problem` (`process.py:821-846`, now dead), `is_first_sighting`, `get_count`, `_refuse_cb`, the per-loop `_POST_SIG_CODES` (move it to module level).
- T9A-9's alert reads `transport_refused at registry`. Acceptable; `SyncHTTPError` work may name it better.

## R3. Questions asked, answered

| Question | Answer |
|---|---|
| Time write failure stops a cycle? | No. Measured with every write failing: all routes run, the cycle is OK, one `server_time_write_failed`. All four callers catch it, and there are no others |
| Skew data stale without notice? | Not at a 200 from decisions: it alerts. Otherwise as at HEAD, so no new verdict path. Approvals fall to the skew rule either way |
| `_record_stage_failure` raises only `SyncError`, handles `layout=None`? | It raises nothing, inside its own `except Exception`, and it handles `None`. But see R2-8: it writes there |
| T9A-9 still loud, same exit and backoff? | Yes. `run_once` raises `SyncError`, `_consecutive_failures` 1, the same routes hit, on both versions. New: it also alerts |
| Marker on other routes? | Only `_fetch_decisions` reads it. Elsewhere it equals `{}`, exactly as HEAD: bundle audits `malformed_response` (loud), audit upload alerts `server_head_mismatch`. **T9b candidates:** token (garbage 200 leaves the token `None` for 10 minutes, silently) and registry (silent) |
| `test_sync_decision_applied_audit_event` still meaningful? | Yes: it passes on a first outcome, through the real cycle. It does not cover R2-4 or R2-6 |
| `m2_gate.py:707-713` | Not run. Dedupe shrinks `sync`; step 7 takes the first session with 4 or more records and fails loudly if none has. Confirm on the regression run |
| p01, p02, p03, p06, p11 | Closed: no raise on a non-string key id; ESC gone; forged newline gone (no server text at all, R2-9); 300 bad rows give 6 audit records; deep JSON no raise. p02 still shows the uncapped key id (R2-2). 288 row and payload type forms: 0 raised |
| Section 7 frozen risks | Hold after these fixes, on the runs above: the marker equals `{}`, `layout=None`, the short-key node, `KeyboardInterrupt`, `_consecutive_failures`, hook-import, `h2` grep, `test_m2_t15b_transport.py`. `test_m2_t16g_e2e.py` upload nodes were not run here (`ee`, another qa active). Rows at 600, 659, 677, 870-876 hold by reading: no server text reaches a reason today, and R2-9 restores it behind the label, so recheck 677 on the run |
| `sandbox status` unmanaged | Unchanged: new text is behind `if managed`, and `test_unmanaged_status_output_unchanged` passes. The import at `connector_cmds.py:462` runs for OSS but has no network or `ee` import |

## R4. The test file

**The 5 fixture fixes are sound.**

- Deleting the `.sandbox/pending/` copy matches the product, which writes only `lay.pending_dir`.
- Patching `EscalationQueue.claim` is a fair model of the race.
- `[not_dual_eligible]` on single-admin produces the real code; the exit fixture itself is in the e2e.
- A long `not_after` is needed, or the re-alert would hit `approval_expired`, a new key.

`test_apply_raises_after_claim_status_says_inspect_and_no_retry` overstates its name: it asserts the alert only. Measured: 3 polls, 1 broker call, status says inspect. Add those two asserts.

**`T9A_TARGETS`: delete it, with the docstring's "fails on today's build" and the comment block at 160-175.** All 134 pass, so the list now says something false, and no code reads it. A permanent guard belongs in the node, not a list.

**Mutation check.** Each fix reverted on a scratch copy, imported through a plugin (a first attempt with `PYTHONPATH` tested the real tree and was discarded).

| Reverted | Result |
|---|---|
| T9A-1, T9A-2, T9A-3, T9A-4 dedupe and sort, T9A-5 (2), T9A-6 reason cap, T9A-7 (2), T9A-8 (2), T9A-9, H1, H2 recursion, H3 | All bite, 1 to 12 nodes each |
| `clear_request` removed | **134 pass.** `test_clear_request_on_leave_pending` does not test clearing: make it fail by that line alone |
| H2 key-id type check removed | **134 pass.** The sanitizer coerces the value. R2-1 removes that, so it must bite after the fix: recheck |
| R2-1 clean removed, R2-7 guard removed | 234 pass, so neither fix breaks a frozen node, and no node protects either |

## R5. Before the commit

Fix R2-1 to R2-14, add the nodes named above, then rerun: this differential plus the new one, the mutation list, the scanners, full root and `ee` suites. Then security re-reviews by node id, and only then `m2_gate.py` and `demo.py` on a fresh stack. Any TCB edit reruns section 1.

# Round 3, 12 Nov 2026

Reviewer: security (L). Scope: the product diff `975e2bc..81fda66` (`approval.py`, `process.py`, `decision_state.py`, `alerts.py`, `connector_cmds.py`, `records_cmds.py`) plus the working-tree `tests/security/test_m3_t9a_security.py` (untracked) and `tests/security/test_m3_t9a_fetch_decisions.py` (modified). Founder ruling 12 Nov: `81fda66` stays on main and is fixed forward. The six product files in the working tree equal `81fda66` (line endings only). Method: throwaway probes and a mutation copy of `src/` and `tests/` outside the repo. Nothing in the repo was edited except this section. No compose stack and no `m2_gate.py` run.

**Verdict: REJECT (fix forward).** The verdict path inside `approval.py` is unchanged (A). One layer up it is not:

- `_rebuild_envelope` turns 12 row forms that `975e2bc` refuses into executions (R3-1, the same class as R2-1).
- The build brings E13 back in a worse form (R3-2).
- R2-5 is still not done: 10 hand-edited state-file forms stop the cycle before audit upload (R3-3).

Six further MUSTs follow. No finding lets a server or a hand edit forge an approval, count one person twice, or run anything without two genuine signatures.

## A. Section 1 differential, `approval.py` (TCB)

**Measured, `975e2bc` against `81fda66`:**

- **`apply_external`:** 7 scenarios with 244 envelope sets each, 1708 cases in all.
  - Scenarios: normal, skew +600 s, no server time, single-admin registry, prod, corrupt nonce file, expired registry.
  - Envelope sets: each signed field dropped or set to 13 hostile values and re-signed; unsigned tampering; 15 structural forms; signature key-id and signature-value forms; an unknown key; one nonce shared by two keys; pairs; a repeat; a deny.
  - Workspace and key home were restored byte for byte between the two runs.
  - Result: **0 differences** in status, approvals, queue files or nonce keys.
  - Not vacuous: in the normal scenario 46 cases executed, 2 were denied and 196 stayed `awaiting_second`. Skew, no server time, prod, single-admin and expired registry executed nothing. Corrupt nonces still applied the 2 denies.
  - Every `refusals` entry has a string code and a boolean `verified`.
- **`_verify_remote_approval`:** 485 envelopes, each run on `975e2bc`, on the new code without `refuse`, and on the new code with `refuse`.
  - **0 differences** in result or `seen_nonces`.
  - All 193 `None` results carry exactly one code. None of the 292 successes carries a code.
- **Callers.** The only product caller is `process.py:1294`, `asyncio.run(apply_external(...))`, and every test caller also uses `asyncio.run(...)`.
  - Nothing in `src/`, `ee/` or `tests/` uses `iscoroutinefunction` or `AsyncMock` on `apply_external`.
  - Argument errors still raise at call time. Body exceptions still raise when the coroutine is awaited, as before.
  - No exception path changed.

**Ruling (1), `async def` to `def` returning `_impl()`: the product was bent to fit a test.**

- Measured on the mutation copy: restoring `async def` (with `return await _impl()`) makes `TestR2_14::test_r2_14_nonce_save_exception_caught` fail with "apply_external not found", because the node walks `ast.FunctionDef` only.
- The new shape behaves the same (above), but it costs three things: it re-indents the whole TCB function for a test predicate, it flips `inspect.iscoroutinefunction`, and it buries the real T9a lines inside a 350-line diff.
- **The test changes, not the product:**
  - qa widens the predicate to `(ast.FunctionDef, ast.AsyncFunctionDef)`.
  - backend restores `async def apply_external` with HEAD's indentation (R3-9).
- No founder row is needed:
  - M3_BASELINE 2.1 rule 3 governs committed test files, and this file is untracked.
  - The edit changes a type predicate, not an assertion.
  - The orchestrator should confirm this reading of rule 3.

**Ruling (2), `_rebuild_decision_envelope` renamed `_rebuild_envelope`: also bent, and acceptable.**

- The function is private, has no other caller, and its return type changed anyway.
- The R2-1 node it was renamed for is not a guard. Writing the same strip without the literal `_sanitize_field(key_id)` leaves all 165 T9a nodes green.
- qa replaces it with the behavioural node R2-1 asked for (R3-1).

## B. R2-1 to R2-14 and the Lows

| Item | State on `81fda66` |
|---|---|
| R2-1 | Fixed as written. A control character, LF, bidi mark, upper case or leading space in the key column stays pending on both versions. **A new verdict change sits beside it: R3-1** |
| R2-2 | Fixed for display and size: unverified key ids are neither keyed nor stored, and print as `invalid` or 12 hex characters. The three control sets still differ. `_LOCAL_CTRL` (`connector_cmds.py:669`) lacks NBSP, NNBSP and surrogates. `_ALERT_CTRL` (`records_cmds.py:16`) lacks the bidi isolates, LRM, RLM and ALM. SHOULD |
| R2-3 | Unverified key `(kind, rid, code)`: fixed. Mark after cap: fixed. Verified first: fixed and measured, but no node bites (SHOULD). **Malformed key not fixed:** `process.py:1188-1193` still emits one alert per row, keyed by the server's `request_id`, and records that id. The spec says `(kind, code)`, one per cycle with `count`, no row data. MUST, R3-8 |
| R2-4 | Fixed in both places. The outcome path (`process.py:854`) has no node: forcing the mark leaves all 165 green. SHOULD |
| R2-5 | **Not done.** MUST, R3-3 |
| R2-6 | The bypass for a returned `executed` or `denied` (`process.py:834`) is right. The added done-branch re-audit is wrong. MUST, R3-2 |
| R2-7, R2-8, R2-9 | Fixed, and each node bites. Low: a scrub failure also emits a separate `scrub_failed` alert (`process.py:1069`), which is not in the spec |
| R2-10 | `SyncHTTPError` with status and stage: fixed. **Not fixed:** `HTTPException` at token or registry is classed `network_error` (`process.py:438`), so it alerts only on the 3rd cycle; the spec says `transport_error`, immediately, type name only. `process.py:330` still puts `str(exc)` in the message. MUST, R3-6 |
| R2-11 | The real `invalid_id` status alerts (measured: `request_id_refused`), but no node covers it: removing that branch leaves `test_r2_11_invalid_id_alerts` green. The node drives an empty pending file instead, and the build added a pre-check for that case (`process.py:1269-1290`) that the spec does not have. MUST, R3-5 |
| R2-12 | `[dual control 1/2]` and the claimed wording: fixed. **Not as written:** keys are still parsed with `split(":")` in three functions (`connector_cmds.py:483-494`, `564-576`, `603-630`), while the docstring at 593 says "Never parses a key". Measured: the network line lacks `at <stage>` (`network_error, 1 in a row`), and the HTTP line reads `HTTP 500 at decisions: http_5xx at decisions`. MUST, R3-7 |
| R2-13 | Fixed on read, and both nodes bite. The same control-set gap as R2-2 remains |
| R2-14 | `approval.py` matches HEAD, with no wrap: fixed. **The `process.py` inference is unsound.** MUST, R3-4 |
| Lows | Real status: fixed. Malformed keys clear after a clean 200: fixed. `verify_raised (<Type>)`: fixed. `str(exc)` as the sentence for a transport `SyncError` (`process.py:1054`) is still there; the text is code-written today, so Low. Section 8: not done, see E |

### R3-1 HIGH (MUST): `_rebuild_envelope` executes rows that `975e2bc` refuses

`process.py:1505-1517`:

- The H2 "type check" sets a non-string `key_id` or `sig` to `""`. That sends the row into the `signatures[0]` fallback, which HEAD did not take for those rows.
- A non-string `signatures[0].key_id` is dropped in favour of the row's string key id.

Measured with HEAD's frozen `_rebuild_decision_envelope` plus `apply_external`, against the new pair, using two genuine admin approvals:

| Row form (the other row is good) | 975e2bc | 81fda66 |
|---|---|---|
| `key_id` is 42, a list, a dict, `true` or 1.5, with a valid `signatures` list (5 forms) | pending | **executed** |
| `signature` is 42, a list, a dict or `true`, with a valid `signatures` list (4 forms) | pending | **executed** |
| No top-level `signature`; `signatures[0].key_id` is 42, a list or `null`; the row's `key_id` is valid (3 forms) | pending | **executed** |
| `signatures[0]` is not an object | cycle crashes (E8) | pending (intended) |

Nothing is forged: each execution needs two genuine signatures that the server already holds. It is still the change spec section 0 blocks, and the same class as R2-1.

Fix: keep HEAD's truthiness and fallback exactly.

- Decide `need_fallback = not sig or not key_id` on the raw values.
- Pass the raw values to the verifier.
- Refuse the row (`signature_missing`) only where HEAD would have crashed.
- Display already handles non-strings (`_display_key_id`).

Measured: removing the H2 check leaves `TestR4_H2KeyIdCheck::test_r4_h2_key_id_type_check_bites_on_verdict` green, so that node does not bite on the check. It does assert the right verdict, so keep it as a verdict guard.

### R3-2 HIGH (MUST): E13 is back, and worse: every poll of a done request writes `executed`

`process.py:1198-1213` re-audits a done request on every poll whenever the state file remembers `executed` or `denied`, once per row.

- Measured: one request executed through `_fetch_decisions` with two rows, then 10 more polls, gives **21** `sync_decision_applied status=executed` records.
- An honest server serves done rows forever (E13), so this grows without bound, at about 17,000 records per request per day. The chain then reads as repeated executions.
- HEAD wrote one `not_pending` record per request per poll. The spec says a done or claimed request gets no record.

How the tests let it through:

- `test_r2_6_executed_not_suppressed` encodes the wrong premise. It demands a new record on a second poll of a done request, and the build added this branch to pass it.
- `test_done_request_rows_write_nothing_on_repeat_polls` and `test_repeat_poll_audit_comparison` miss it. Their fixtures execute through `apply_external` directly, so no state entry exists when they poll.

Fix:

- Delete the block.
- qa rewrites `test_r2_6` as R2-6 described it: pre-seed a matching `executed` signature on a **pending** request, execute through `_fetch_decisions`, and assert the record is written.
- qa adds the 10-poll node.

### R3-3 HIGH (MUST): R2-5 is still not done

What `_load` still does wrong:

- It checks only that each entry is a dict, and drops future timestamps. It does not validate entry fields.
- It calls `math.isnan` on unbounded integers.
- `_fetch_decisions` still calls `_load_decision_state()` and `begin_cycle()` outside any `try` (`process.py:1025-1026`).

Measured through `run_once`:

- **10 hand-edited forms raise from `_fetch_decisions`.** Bundle, escalation upload and audit upload are then skipped, the file is not rewritten, and this repeats on every cycle until someone deletes the file. The refusal alert is lost as well.
- **3 forms make `sandbox status` exit 1**, 2 of them in `--json` too:
  - `connector_cmds.py:554`: `int(net)` on NaN or Infinity.
  - `connector_cmds.py:471`: a non-string `outcome_sig`.
- **One wrong-typed field (`alerted: "no"`) is accepted** instead of dropping the file.

The forms were re-derived and are held privately (G). The spec section 5 paragraph is the requirement, and as built it does not hold.

Fix as R2-5 wrote it, plus:

- One validated loader, shared by `decision_state.py` and `connector_cmds.py`.
- Every entry field type-checked, with any wrong type dropping the file:
  - counts and repeats: non-negative ints;
  - `alerted`: bool;
  - timestamps: finite reals no later than now;
  - `reason` and `outcome_sig`: strings.
- Large integers converted under a guard.
- `note()` returns its local entry.
- Every state call on the alert path wrapped, so a failure means an empty state.

### R3-4 MEDIUM (MUST): the R2-14 inference mislabels every early failure

`process.py:1297-1308` reports any exception from `apply_external` as `nonce_save_failed` ("nonce persistence failed", no type name) whenever the record is still pending.

- Measured: with `load_verified_state`, `_load_seen_nonces`, `_measure_skew` or `_binding_fingerprint` raising, all four alert `nonce_save_failed`.
- False positives: every raise before the claim.
- False negatives: none, but only because the product's `_save_seen_nonces` never raises (R2-14). The branch is right only for a fixture.
- The spec says `apply_raised (<ExcType>), record is <queue_state>`.

Fix:

- Delete the branch.
- Make `test_nonce_save_failed_alerts` and `[nonce_save_failed]` patch a save that returns `False`, as R2-14 said.

### R3-5 MEDIUM (MUST): the R2-11 pre-check exists for a wrong test

`process.py:1269-1290` reads the pending file before `apply_external`. Both cases below were measured:

| Pending file | Build says |
|---|---|
| Empty | `request_id_refused` ("the pending record is empty") |
| Non-empty but unreadable | `pending_record_unreadable` |

- The spec has one row for both: `decision_apply_failed / pending_record_unreadable`.
- The pre-check's read also follows a symlink.

Fix:

- Delete the pre-check.
- qa drives `test_r2_11_invalid_id_alerts` through a real `invalid_id`, by patching `_validate_request_id` or by using a symlinked pending file.
- qa adds an empty-file node expecting `pending_record_unreadable`.

### R3-6 MEDIUM (MUST): token stage, label and server text

- At token or registry, classify any exception that is neither `OSError` nor `SyncError` as `transport_error`, immediately (spec section 2, `transport_error` row).
- Use `type(exc).__name__` at `process.py:330` (spec section 5, rows I and T).

Detail is in G (R2-H1).

### R3-7 MEDIUM (MUST): R2-12 as written

- Store `code`, `rid`, `key_id`, `verified`, `reason`, `stage` and `status` in each entry.
- Use one reader, and never split a key.
- Add `at <stage>` to the network line.
- Print the HTTP line once: `Decisions: fetch failed: HTTP 500 at decisions: http_5xx`.

### R3-8 MEDIUM (MUST): malformed rows are keyed and recorded per request id

As in the R2-3 row of table B: emit one `decisions_malformed` per code per cycle, with `count` and no `request_id`.

### R3-9 LOW (MUST): restore `async def apply_external`

As in A. Rerun the section 1 differential afterwards.

## C. Mutation list

Method: each fix was reverted on a scratch copy of `src/` and `tests/` (with imports checked to resolve to the copy). The named nodes were then run with `M3_T9A_BODIES=1 --runxfail`.

| Reverted | Result |
|---|---|
| R2-1 literal clean; R2-2 hex-or-invalid; R2-2 NBSP; R2-3 key id in the unverified key (also bites `test_r2_2_key_id_size_bounded`); R2-3 mark before cap; R2-4 alert path; R2-5 `int()` on load (3 nodes); R2-6 bypass; R2-7 guard; R2-8 package path; R2-9 `: str`; R2-9 scrub raise; R2-10 plain `SyncError`; R2-10 `HTTPException` unrecorded; R2-12 dual count; R2-12 claimed wording; R2-13 read sanitize; R2-13 key-id redact; R2-14 wrap back; the three Lows | Each named node fails |
| `ds.clear_request(rid)` removed, nothing else | `TestNewTargets::test_clear_request_on_leave_pending` fails: it now bites on that line alone |
| `async def` restored | `test_r2_14` fails: the product was bent (A) |
| H2 key-id check removed | `TestR4_H2KeyIdCheck::test_r4_h2_key_id_type_check_bites_on_verdict` **passes**: it does not bite (R3-1) |
| R2-1 strip written without the literal | **165 pass**: a grep, not a guard |
| Verified-first sort removed; R2-4 outcome-path mark forced | **165 pass**: no node covers either (SHOULD) |
| R2-11 `invalid_id` branch removed | **Passes**: the node tests the pre-check instead (R3-5) |
| qa guard: `ValueError` dropped from `_load` | `test_r2_5_truncated_json_guard` and `test_r2_5_non_utf8_guard` fail |
| qa guard: `OSError` dropped from `_load` | `test_r2_5_directory_guard` fails |
| qa guard: server text allowed on 3xx | `test_r2_low_3xx_no_server_text_guard` fails |

The four qa guards pass on the build and are not vacuous.

## D. `test_m3_t9a_fetch_decisions.py`, working tree against HEAD

The diff is exactly the three T0b-13 edits plus their helper:

- 41 occurrences of `{"Date": "Wed, 05 Nov 2026 10:00:00 GMT"}` become `_date_hdr()`, and the helper and its import are added.
- `test_done_request_rows_write_nothing_on_repeat_polls` gains carol's approval as the second approver.
- The registry stub in `test_500_still_uploads_escalations_and_audit_then_raises` returns `{"registry": []}`.

No `assert`, `require_m3` or marker line changed.

**The committed file, run against `81fda66`:**

- With `M3_T9A_BODIES=1 --runxfail`: 4 failed, 45 passed. The 4 are exactly the T0b-13 nodes:
  - `test_non_counting_approval_shows_awaiting_second_in_status` and `test_non_counting_approval_shows_in_alerts`: the frozen Date is now 7 days old and is refused as `clock_skew`.
  - `test_500_still_uploads_escalations_and_audit_then_raises`: the later routes are never reached.
  - `test_done_request_rows_write_nothing_on_repeat_polls`.
- In CI mode, this file has 37 failures: **33 `XPASS(strict)` plus those 4**. The 4 fail under their markers because the failure is an AssertionError, not the `raises=M3T9Pending` the markers expect. HANDOFF's "37 XPASS plus 4" double-counts them.

**Node-id delta.** 2543 against 2542 is `test_m1_t5_standalone.py::test_sandbox_module_imports_without_agg_cp[sandbox.connector.sync.decision_state]`, which the new module adds and the committed list lacks.

With the working-tree edits there are 0 failures (H).

## E. Section 8 deletions

| Name | Callers | Tests naming it | Ruling |
|---|---|---|---|
| `_classify_row_problem` (`process.py:885`) | None (dead since R2) | None | Delete. `_safe_json_loads` stays, because `_rebuild_envelope` uses it |
| `is_first_sighting` (`decision_state.py:173`) | None | None | Delete |
| `get_count` (`decision_state.py:232`) | None | None | Delete |
| `_refuse_cb` (`approval.py:779`) | One, at `approval.py:802` | None | Replace it with `refuse=_per_env_refusals.append` and delete it. TCB edit: rerun A |
| `_POST_SIG_CODES` (`approval.py:812`) | Used at 821, and rebuilt per envelope | None | Do not delete. Move it to module level unchanged. TCB edit: rerun A |

`MAX_REASONS_PER_REQUEST` and `mark_realerted` are now used. Keep them.

## F. Scanners

Run on the six product files plus the two test files:

| Scanner | Result |
|---|---|
| Semgrep `p/python` and `p/secrets` (`--metrics=off`) | 0 findings. The first run reported one engine error; the rerun had 0 errors |
| gitleaks `dir` | No leaks |
| trivy `fs` (secret and misconfig; HIGH and CRITICAL) | 0 results |
| ruff `S,B,BLE`, six product files against the same files at `975e2bc` | S110 went from 12 to 15 and S112 from 4 to 3; nothing else changed. The old `_fetch_decisions` pass handlers and `except: continue` are gone. The new S110 are all alert-path or time-write swallows, none on a verdict path: `approval.py:829` (registry user id for a refusal), `process.py:443` (`_record_stage_failure`), and `process.py:963`, `989` and `1553` (server-time writes, accepted in R2's R3 table) |

## G. Held items

R2-H1, R2-H2 and R2-H3 were re-derived against `81fda66`. The details are held privately and reported to the orchestrator.

| Item | Status |
|---|---|
| R2-H1 | Open on one path (R3-6) |
| R2-H2 | Closed in behaviour, but no node guards it (SHOULD, C) |
| R2-H3 | Open (R3-3) |

## H. Runs (Windows, venv Python 3.12)

| Run | Result |
|---|---|
| `M3_T9A_BODIES=1 -p no:logging --runxfail`, both T9a files | **165 passed** in 40 s. No `__nonexistent_state__` was created |
| `tests/` in CI mode | **2573 passed, 7 skipped, 14 xfailed, 66 failed** in 463 s. See the breakdown below |
| `ee/tests/test_m3_t9a_e2e.py --timeout=600` | **1 passed** in 37 s. No container was left behind |
| Builder's "773 connector/approval/sync nodes" | Not reproducible as a set. The 22 connector, approval and sync files total 459 nodes, and all of them pass inside the full run |

The 66 failures in the `tests/` run are all named, and none is a product defect:

- 37 `XPASS(strict)` in `test_m3_t9a_fetch_decisions.py` and 27 in `test_m3_t9a_security.py`: the markers are still on.
- `test_root_collect_only_equals_nodeids`: 2660 collected against 2603 listed. `test_m3_t9a_security.py` has 116 nodes and the list expects 59.
- `test_ee_collect_only_equals_nodeids`: 1157 collected against 1086 listed (T1 work and the e2e).

## Before the commit

1. **qa writes the failing proof nodes first:**
   - R3-1: the 12 row forms stay pending at `_fetch_decisions`, plus a permanent differential that freezes HEAD's rebuild as a fixture.
   - R3-2 through R3-8.
   - Rewrites of `test_r2_6`, `test_r2_11` and the `test_r2_14` predicate.
   - A behavioural replacement for the R2-1 grep.
   - The two SHOULD nodes.
2. **Backend fixes** R3-1 to R3-9 and the section E items.
3. **Security re-reviews** by node id, reruns A, C and F, and probes G again.
4. **Only then** `m2_gate.py` and `demo.py` on a fresh stack.

**Commit list, once approved.**

Markers to remove: the 27 R2 strict-xfail markers in `test_m3_t9a_security.py`, the 37 round 1 markers in `test_m3_t9a_fetch_decisions.py`, and the markers on any new R3 nodes.

The T9a commit carries:

- The fixed product files: `approval.py`, `process.py`, `decision_state.py`, `connector_cmds.py`, `records_cmds.py`, and `alerts.py` if it is touched.
- `tests/security/test_m3_t9a_security.py`.
- `tests/security/test_m3_t9a_fetch_decisions.py`, with the T0b-13 edits and marker removal only.
- `ee/tests/test_m3_t9a_e2e.py`.
- `M3_FROZEN_MANIFEST.sha256`, `M3_BASELINE_NODEIDS.txt` and `M3_BASELINE_EE_NODEIDS.txt`, regenerated on Linux `python:3.12` with the pytest version CI installs.
- `T9A_SPEC.md`, with the section 5 repudiation row rewritten (R2-3).
- This file.

The T1 files go in their own commit. Never stage `src/sandbox/connector/sync/__nonexistent_state__/`; it is absent at this review.

# Round 4, 13 Nov 2026

Reviewer: security (L). Scope: the working-tree product diff against `81fda66` (and against `975e2bc` for `approval.py`) in `approval.py`, `process.py`, `decision_state.py`, `connector_cmds.py`, `records_cmds.py`, plus `tests/security/test_m3_t9a_security.py`, `tests/security/test_m3_t9a_fetch_decisions.py` and `tests/security/fixtures/`. Method: throwaway probes and a mutation copy of `src/` and `tests/` outside the repo (imports checked to resolve to the copy). Nothing in the repo was edited except this section. No container was left running and no `__nonexistent_state__/` appeared.

**Verdict: REJECT (fix forward).** The TCB is clean: the section 1 differential has 0 differences and section 8 is done. No finding forges an approval, counts one person twice, or runs anything without two genuine signatures. But:

- The R3-6 build reclassified every network failure at token and registry as `transport_error` (R4-1), and broke one frozen test (R4-2).
- Four of the builder's choices, and two R2 nodes, were shaped to fit a wrong test rather than the spec (R4-5 to R4-9). Each "deviation" below traces to a fixture, not to a security reason.
- Two held state-file items remain (R4-3, R4-4) and one held terminal item (R4-11); detail is held privately (G).

## A. Section 1 differential, `approval.py` (TCB), `975e2bc` against the working tree

| Run | Cases | Differences | Not vacuous |
|---|---|---|---|
| `apply_external`, 7 scenarios x 244 envelope sets (normal, skew +600 s, no server time, single admin, prod, corrupt nonces, expired registry) | 1708 | **0** in status, approvals, queue files, nonce keys | normal: 46 executed, 2 denied, 196 awaiting; the other six scenarios execute nothing; corrupt nonces still apply the 2 denies. Every `refusals` entry has a string code and a boolean `verified` |
| `_verify_remote_approval`, 485 envelopes, on `975e2bc`, new without `refuse`, new with `refuse` | 485 | **0** in result or `seen_nonces` | 193 `None` results each carry exactly one code; none of the 292 successes carries one |
| Row layer: `975e2bc` rebuild + apply against the new `_rebuild_envelope` + apply | 34 row forms | **0**, apart from the intended one (`signatures[0]` not an object: `975e2bc` crashes the cycle, new stays pending) | 6 forms execute on both; the 12 R3-1 forms stay pending on both |

The diff against `975e2bc` is 151 lines, `async def apply_external` is restored with HEAD's indentation, `_POST_SIG_CODES` is at module level, and `_refuse_cb`, `_classify_row_problem`, `is_first_sighting` and `get_count` are gone. Section 8 is closed.

## B. Items against the code and their nodes

| Item | State |
|---|---|
| R3-1 | Fixed. `_rebuild_envelope` keeps `975e2bc`'s truthiness and fallback on raw values. The 12 forms stay pending, and both mutations bite (9 and 3 nodes) |
| R3-2 | Fixed. The done branch is deleted. Measured: one `executed` record after 10 more polls |
| R3-3 | The 20 held forms no longer stop the cycle or crash `sandbox status`, and the loader is shared. **Not as written:** wrong types are coerced, not dropped (deviation 3, R4-4), and negative counters are accepted (R4-3) |
| R3-4 | **Not as written** (deviation 2, R4-5) |
| R3-5 | **Not as written** (deviation 1, R4-6) |
| R3-6 | The type name at token and `transport_error` for non-OS exceptions: done, and both bite. **Overreach:** OS errors at token and registry are now `transport_error` too (R4-1). It also broke a frozen node (R4-2) |
| R3-7 | Entry fields are stored and the HTTP line is fixed; both bite. **The network line has no stage on cycles 1 and 2** (R4-10). Keys are still split in three readers (`connector_cmds.py:491`, `575`, `613`). That is safe, because request ids exclude `:` and verified key ids are hex, so it is a SHOULD. The docstring "Never parses a key" is still false |
| R3-8 | Fixed: one alert per code per cycle with `count`, and no request id. Bites |
| R3-9 | Fixed. Bites |
| H1 | Closed on token and registry, and the five extra code points are stripped in `sandbox alerts` (each one bites). One pre-existing path is open (R4-11, G) |
| H2 | Closed in behaviour. Its node does not guard verified-first (deviation 4, R4-8) |
| R2-11 | **Bent to the test** (R4-7) |
| R2-6 | The bypass is right, but its node is vacuous (R4-9) |

## C. Deviation rulings

| # | Builder's deviation | Ruling | Why (measured) |
|---|---|---|---|
| 1 | R3-5 pre-check kept for the empty file | **Rejected, R4-6** | Without the pre-check, empty, garbage and directory pending files all give `pending_record_unreadable` through `apply_external`'s own read. The node fails without the pre-check only because the frozen helper `_create_pending_request` writes a second copy to `.sandbox/pending/`, a path no product code writes. With that copy present, the pre-check leaves a valid deny pending where `975e2bc` denies: a verdict change at the fetch layer. The pre-check also reads through a symlink before `apply_external`'s H3 refusal. Its two branches also disagree: one queues the alert for sorting and capping, the other writes it at once |
| 2 | R3-4 narrowed to `OSError` with the record pending | **Rejected, R4-5** | `_save_seen_nonces` never raises, so the branch has no true positive. Measured: `PermissionError` or `FileNotFoundError` from `load_verified_state`, `_load_seen_nonces`, `_measure_skew` or `_binding_fingerprint` all alert `nonce_save_failed` (8 of 8). The narrowing exists because `test_nonce_save_failed_alerts` and `TestReasonCodes[nonce_save_failed]` still make the save raise `OSError` |
| 3 | R3-3 coerces fields and defaults timestamps instead of dropping the file | **Rejected, R4-4** | Spec section 5 says a field of the wrong type drops the file. Section 4 says corrupt means more alerts, never fewer. Measured: 5 wrong-typed forms on an alerted key give 0 alerts, where dropping would alert now. Inside the named bound, but the spec claim is false as built |
| 4 | H2 sort widened: verified > `bad_signature` > `unknown_key` | **Rejected, R4-8** | `test_h2_verified_first_sort` uses a `bad_signature` row as its "verified" refusal. `bad_signature` is unverified: anyone can name a registry key id. Removing verified-first leaves all 211 green; the node bites only on the added rank. No added attacker power, since the server already orders rows, but the product was bent to a wrong test |
| f1 | Frozen `test_f1_short_device_key_raises` regression | **Product fix, R4-2** | Confirmed: 1 failed, 431 passed across the M2 sync, remote, enroll and transport files (I). Section 7 of the spec allows only `SyncError` from step 1, and rows I and T allow code-written text |

## D. MUSTs

Tests first: qa writes or corrects each node below, under the strict-xfail marker, and shows it fails on today's tree for the stated reason. Then backend fixes, and security reruns F and H by node id. `test_m3_t9a_security.py` is untracked, so these edits need no founder row. The frozen f1 node is not edited.

### R4-1 MEDIUM: network failures at token and registry are `transport_error`

`process.py:437-441`: the R3-6 `else` now catches `OSError` too. Measured: `ConnectionRefusedError` at registry alerts `transport_error at registry` on cycle 1, and the counter never moves, against spec section 2 row 1 and E12. `test_outage_at_registry_counts_toward_three` asserts only one alert of any code after three cycles, so it passes.

- **Fix:** before the `else`, add `elif isinstance(exc, OSError): code = "network_error"; immediate = False`. TLS stays first; `URLError`, `ConnectionError` and `TimeoutError` are `OSError`. Prototyped on the copy: 273 passed.
- **Node:** `TestR4_1::test_r4_1_outage_counts_toward_three[token|registry]`. `ConnectionRefusedError` at that stage, with a fresh `SyncProcess` each cycle:
  - after cycles 1 and 2: no `decisions_fetch_failed` alert, and the status line names the stage with `1 in a row` or `2 in a row`;
  - after cycle 3: exactly one alert, `reason_code == "network_error"`, `stage` equal to the stage.
- **Fails today:** cycle 1 writes `transport_error`.
- Also tighten `test_outage_at_registry_counts_toward_three` to assert `network_error`.

### R4-2 MEDIUM: frozen `test_f1_short_device_key_raises` (local key text)

`process.py:917`: `SigningKey(b"short")` raises nacl's `ValueError`. Since R3-6 that becomes `token error: ValueError` plus a `transport_error at token` alert, for a local key problem.

- **Fix:**
  - Add `class SyncLocalKeyError(SyncError)`.
  - In `_refresh_token`, before building the assertion: if `sync.device_key` is not `bytes`/`bytearray` of length 32, raise `SyncLocalKeyError("device key unusable: an Ed25519 seed must be exactly 32 bytes")`.
  - In `run_once`, put `except SyncLocalKeyError: raise` before the token block's transport handlers. No stage failure is recorded and no alert is written.
  - The text is code-written. It names the length only, never key bytes or the nacl message (rows I and T).
  - Prototyped: the frozen node passes, and so do the two T9a files, `test_m2_t16a`, `t10`, `t15b` and `t12b_sync` (273 passed).
- **Nodes:** the frozen node (fails today), plus `TestR4_2::test_r4_2_short_key_is_local_not_transport`. With a managed layout and `b"short"`: `SyncError` matching `32`, no `decisions_fetch_failed` alert, and `short` absent from the message. Fails today: a `transport_error` alert is written.

### R4-3 MEDIUM (H3 residual): counter range

One hand-edited counter form silences a class of alerts and its status line for longer than the named limit's per-edit bound (detail in G).

- **Fix:** every counter is an `int` (not `bool`), `0 <= v <= 2**63`, or the whole file drops. The counters are `net_consecutive`, `alerts_this_hour`, `suppressed_this_hour`, entry `count` and entry `repeats`. This is part of R4-4's rule.
- **Node:** `TestR4_3::test_r4_3_counter_range_drops_file`, with the form from the private note. Three outage cycles at decisions must give exactly one `network_error` alert and the status line. Fails today: 0 alerts and no line.

### R4-4 LOW: a wrong type drops the file (deviation 3)

`decision_state.py:114-205`.

- **Fix:** in `_validate`, any present field of the wrong type raises, and `_load` catches it, giving empty state. The types are:
  - `entries`: a dict of dicts;
  - counters: as R4-3;
  - `alerted`, `verified`: `bool`;
  - `first_seen`, `last_seen`, `last_alerted`, `hour_start`: `int` or `float`, not `bool`;
  - `reason`, `outcome_sig`, `code`, `rid`, `key_id`, `stage`: `str`;
  - `status`: `int` or absent.
- A non-alert entry missing `count`, `alerted`, `first_seen` or `last_seen` also drops the file.
- Non-finite or future timestamps still count as absent (spec).
- Delete the coercion defaults, and correct the docstring of `_load`.
- **Node:** `TestR4_4::test_r4_4_wrong_type_drops_file`. The refusal key's entry is `alerted: true` with `last_alerted` 10 s ago, plus one wrong field. Parametrize over `count: "x"`, `repeats: [1]`, `first_seen: "x"`, `reason: 5`, `code: 5`, `verified: "yes"`, `status: "500"`, and an entry that is a list. The next cycle writes the refusal alert.
- **Fails today:** 0 alerts for the first four forms.

### R4-5 MEDIUM: R3-4 as written (deviation 2)

- **Fix:** delete `process.py:1268-1278`. Every raise becomes `apply_raised (<ExcType>), record is <queue_state>`. `nonce_save_failed` stays on the returned status (`process.py:1351`).
- **Test edits:** qa makes the `boom` in `TestT9A8::test_nonce_save_failed_alerts` and in `TestReasonCodes[nonce_save_failed]` return `False`, as the product does.
- **Node:** `TestR3_4::test_r3_4_load_verified_state_raise` parametrized over `RuntimeError` and `PermissionError`, expecting `apply_raised (PermissionError)`. The `PermissionError` case fails today.

### R4-6 MEDIUM: R3-5 as written (deviation 1)

- **Fix:** delete the pre-check, `process.py:1238-1259`.
- **Test edits:**
  - `test_r3_5_empty_pending_file` deletes `.sandbox/pending/<rid>.json` after `_create_pending_request`, because the product never writes that copy.
  - `TestR3_MutationGuards::test_guard_r2_11_branch` does not test R2-11. Delete it, or rename it and apply the same edit.
- **Node:** `TestR4_6::test_r4_6_fetch_layer_adds_no_verdict`. For each pending-file form (empty, garbage, a directory named `<rid>.json`, an empty canonical file plus a valid `.sandbox/pending/` copy with one valid deny row), compare `_fetch_decisions` against `asyncio.run(apply_external(...))` on an identical copy of the workspace. The queue status must be the same.
- **Fails today:** the last form stays pending under `_fetch_decisions` but is denied by `apply_external`.

### R4-7 MEDIUM: R2-11 bent to the test

`test_r2_11_invalid_id_alerts` patches `_validate_request_id` to return `False`. The product can never return that, and it makes `apply_external` return `{"status": False}`. The build then added a "non-string status" clause and changed the code to `invalid_id`.

- Measured: a real `"invalid_id"` alerts as `invalid_id`, but spec section 2 says `request_id_refused` (as `81fda66` did). Removing the real string match leaves all 211 green.
- **Fix:** delete the non-string clause (`process.py:1379-1381`). A real `invalid_id` gives `decision_refused` / `request_id_refused`, with the reason `<rid> refused: request_id_refused: <S>`.
- **Node:** the existing node, with the patch returning `"invalid_id"` and expecting `request_id_refused`. Fails today.

### R4-8 LOW: H2 sort (deviation 4)

- **Fix:** revert to `0 if a.get("verified") else 1`, and delete `_VERIFIED_SORT` and its comment (`process.py:1409-1417`).
- **Node:** qa rewrites `TestR3_MutationGuards::test_h2_verified_first_sort` with a genuinely verified refusal: a registered admin key with a valid signature over a payload bound to another command, giving `command_mismatch`. Put it last in row order, after 6 malformed rows, 8 `unknown_key` rows and 5 `bad_signature` rows on registered keys. Assert it is the first `decision_refused` alert.
- The rewritten node is a guard: it passes today and on the revert. It must fail when verified-first is removed, and qa shows that bite on a scratch copy. The revert itself needs no failing target: it removes a rank no spec row asks for.

### R4-9 LOW: the R2-6 node is vacuous

`test_r2_6_executed_not_suppressed` seeds `outcome_sig` `executed:2::`, but the product writes `executed:None:[]:None`. Measured: forcing dedupe on `executed` leaves all 211 green.

- **Fix (test only):** seed the exact signature the product computes, on a pending request.
- **Requirement:** the node must fail with `process.py:839` changed to `if True:`.

### R4-10 LOW: R3-7 network line

- Measured: cycles 1 and 2 print `network_error, 1 in a row`, with no stage. Cycle 3 prints `network_error, 3 in a row at decisions` and also `network_error at decisions`. The stage is borrowed from whichever entry has one.
- **Fix:**
  - `note_net_failure(stage)` stores `net_stage`, and `reset_net_counter` clears it.
  - Print exactly `Decisions: fetch failed: network_error at <stage>, <n> in a row` (spec section 2 row 1), and no second line for the same failure.
  - Delete the regex fallback at `connector_cmds.py:631`. `r"HTTP (\\d+)"` matches a literal backslash, and entries now carry `status`.
- **Node:** tighten `TestR3_7::test_r3_7_network_line_has_stage` to one cycle, for both decisions and registry (after R4-1), asserting that exact line. Fails today.

### R4-11 MEDIUM (H1 residual): `str(exc)` in the outer handler

`process.py:371-373`: the outer `except Exception` handler puts `str(exc)` into the `SyncError` text, and `sandbox sync --once` prints it. This is pre-existing at `975e2bc`, but it is the R2-H1 class, and spec section 5 rows I and T say type name only. Detail is in G.

- **Fix:** `raise SyncError(f"sync cycle failed: {type(exc).__name__}") from exc` in that handler. The `(ConnectionError, OSError, SyncError)` handler keeps its code-written text. Prototyped: 273 passed. No frozen node matches that text (grep: only f1, now covered by R4-2).
- **Node:** `TestR3_H1::test_h1_no_esc_in_sync_error_later_stage`, with the form from the private note. Fails today.

## E. SHOULDs

- R3-7: finish key-free reading in `connector_cmds.py:491`, `575`, `613`, or correct the docstring.
- Carried from R2-2: `_LOCAL_CTRL` (`connector_cmds.py`) lacks NBSP, NNBSP, surrogates, U+2028, U+2029, U+200B, U+FEFF and U+00AD. Status lines are code-written today.
- `process.py:1389`: `not_pending` for a request that became claimed or done between the row loop and the apply alerts `request_id_refused`. The spec says none for done or claimed.
- Unguarded, measured with all 211 green under mutation:
  - the verified refusal key keeping its key id (R2-3);
  - `nonce_replay` in `_POST_SIG_CODES` (fail-safe direction).

  Marking `bad_signature`/`unknown_key` as verified does bite (3 nodes).
- Accepted without change: `_fetch_decisions` does not wrap `_load_decision_state()` and `begin_cycle()` (R3-3 text). `_load` catches everything, and none of the 26 forms raised after load.

## F. Mutation list (scratch copy, `M3_T9A_BODIES=1 --runxfail`)

| Reverted or mutated | Result |
|---|---|
| R3-1 H2 coercion back; R3-1 fallback type filter back | 9 and 3 `TestR3_1` forms fail |
| R3-2 done-branch re-audit back | `test_r3_2_execute_then_poll_10_times` fails |
| R3-3: `alerted` non-bool accepted; load wrapper and int guards removed; `outcome_sig` not coerced; `first_seen` default removed; `count` coercion removed | Each named R3-3 node fails (1, 2, 1, 1, 1) |
| R3-4 widened back to any exception | `test_r3_4_load_verified_state_raise` fails |
| R3-4 branch deleted (the R3 fix) | 2 fail: `test_nonce_save_failed_alerts`, `TestReasonCodes[nonce_save_failed]`. These are the `OSError` fixtures (R4-5) |
| R3-5 empty branch back to `request_id_refused` | `test_r3_5_empty_pending_file` fails |
| R3-5 pre-check deleted (the R3 fix) | 2 fail: `test_r3_5_empty_pending_file`, `test_guard_r2_11_branch`. Both are caused by the helper's second copy (R4-6) |
| R3-6: other exception back to `network_error`; `str(exc)` at token | `test_r3_6_http_exception_not_network_error` fails; `test_r3_6_no_str_exc_in_output` and `test_h1_no_esc_in_sync_error` fail |
| R3-6 `str(exc)` at registry | **211 pass**: no node. SHOULD: parametrize the H1 node over token and registry |
| R3-7: stage suffix, entry fields, HTTP double stage | Each named node fails |
| R3-8 per-row malformed with rid | `test_r3_8_malformed_one_per_code_per_cycle` fails |
| R3-9 plain `def` wrapper | `test_r3_9_apply_external_is_async_def` fails |
| H1: U+2028; U+2029, U+200B and U+FEFF; U+00AD | 1, 3 and 1 `TestR3_H1` nodes fail |
| H2 verified-first key removed | **211 pass** (R4-8) |
| H2 `bad_signature` rank removed, verified-first kept | `test_h2_verified_first_sort` fails: it guards the bent rank |
| R2-11 real `"invalid_id"` match removed | **211 pass** (R4-7) |
| R2-11 non-string clause removed | `test_r2_11_invalid_id_alerts` fails: it guards the fake status |
| qa guards: `ValueError` not caught on load; `OSError` not caught; 3xx server text | `test_r2_5_truncated_json_guard` and `test_r2_5_non_utf8_guard` fail; `test_r2_5_directory_guard` fails; `test_r2_low_3xx_no_server_text_guard` fails. Not vacuous |
| R2-1 key id sanitized before verify | `test_r2_1_sanitized_key_id_changes_verdict` fails: the behavioural node bites |
| `test_r4_h2_key_id_type_check_bites_on_verdict`: refusal alerts dropped | Fails: a verdict and alert guard, not vacuous. A non-string key id refused as malformed instead still passes, as intended (either refusal) |
| Section 8: `_POST_SIG_CODES` emptied; `bad_signature`/`unknown_key` marked verified | 1 fails (`test_post_signature_verified_yes`); 3 fail |
| R2-4 alert path; R2-4 outcome path; `clear_request` removed | Each named node fails |
| R2-6 `executed` deduped; R2-3 verified key without key id; `nonce_replay` unverified | **211 pass** (R4-9, E) |

## G. Held items

R2-H1 to R2-H3 were re-derived against the working tree. The details are held privately and reported to the orchestrator.

| Item | Status |
|---|---|
| R2-H1 | Closed on token and registry. Open on one pre-existing path (R4-11) |
| R2-H2 | Closed in behaviour. Its node guards the wrong key (R4-8) |
| R2-H3 | All 20 R3 forms are closed: none stops the cycle or crashes `status`. Two residuals remain (R4-3, R4-4) |

## H. Scanners

Run on the five product files, the two test files and `tests/security/fixtures/`.

| Scanner | Result |
|---|---|
| Semgrep `p/python` and `p/secrets` (`--metrics=off`) | 0 findings. The first run had one per-rule timeout on the test file; the rerun with `--timeout 120` had 0 errors (187 rules, 9 files) |
| gitleaks `dir` (repo config and default) | No leaks |
| trivy `fs` 0.74.0 (secret and misconfig; HIGH and CRITICAL) | 0 secrets. No misconfig targets in the set |
| ruff `S,B,BLE` (`--isolated`) against the same files at `81fda66` | Product files: identical (S110 15, S112 3, BLE001 4, B904 2, S310 1, S311 2), so nothing new. `test_m3_t9a_fetch_decisions.py`: identical. New `test_m3_t9a_security.py`: S101 103, S105 11 (test tokens), BLE001 7, S110 2, all test-only |

## I. Runs (Windows, venv Python 3.12, Git bash)

| Run | Result |
|---|---|
| `M3_T9A_BODIES=1 -p no:logging --runxfail`, both T9a files | **211 passed** in 30 s, matching the orchestrator |
| Both T9a files in CI mode | 107 failed (`XPASS(strict)`: 70 + 37), 104 passed, matching the orchestrator |
| The 21 M2 sync, remote, enroll and transport files in `tests/security/`, plus `test_m1_t5_standalone.py` | 1 failed (`test_f1_short_device_key_raises`, R4-2), 431 passed, 3 skipped, 1 xfailed |
| `ee/tests/test_m3_t9a_e2e.py --timeout=600` | **1 passed** in 39 s. No container was left behind; the three exited containers listed before and after are 9 days and 3 weeks old |
| Security prototype of R4-1, R4-2 and R4-11 on the copy (not a build) | 273 passed: both T9a files, `t16a` (with f1), `t10`, `t15b`, `t12b_sync` |

The full root run was not repeated. The orchestrator's 111 is accounted for: 107 markers, 2 node-id lists, 1 environmental, and 1 f1.

## Before the commit

1. **qa writes or corrects the nodes first:** R4-1 to R4-11, the four test edits (`boom` returns `False`, delete the `.sandbox/pending/` copy, the `"invalid_id"` patch, the R2-6 seed) and the H2 rewrite. Each one is shown failing on today's tree.
2. **Backend fixes** R4-1 to R4-11. No test edits.
3. **Security re-reviews:** reruns A (the R4 fixes touch no TCB file, so a diff check only), F and H by node id, and probes G again.
4. **Then** `m2_gate.py` and `demo.py` on a fresh stack.

**Commit list, once approved.** Markers to remove:

- 26 R2 and 44 R3 strict-xfail markers in `test_m3_t9a_security.py` (70 nodes);
- 37 round 1 markers in `test_m3_t9a_fetch_decisions.py`;
- the markers on the R4 nodes.

The T9a commit carries the same files as the round 3 list. The frozen `test_m2_t16a_sync_cycle.py` is not edited.

# Round 5, 16 Nov 2026

Reviewer: security (L). Scope: the working-tree product diff against `81fda66` in `process.py`, `decision_state.py`, `connector_cmds.py`, `records_cmds.py` and `approval.py`, plus qa's R4 nodes and edits in `tests/security/test_m3_t9a_security.py` and `tests/security/fixtures/`. Method: throwaway probes and a mutation copy of `src/` and `tests/` outside the repo (imports checked to resolve to the copy). Nothing in the repo was edited except this section. No server or container was left running, and no `__nonexistent_state__/` appeared.

**Verdict: APPROVE the product diff.** R4-1 to R4-8, R4-10 and R4-11 are built as written, and each revert fails its named node. The row-layer differential has 0 differences, and `approval.py` is byte-identical to the copy round 4 approved. R2-H1 to R2-H3 are closed (G). No finding forges an approval, counts one person twice, or runs anything without two genuine signatures.

**The commit waits for three test-only edits (R5-1 to R5-3).** No product change and no new build round are needed. R4-9 is still vacuous, and two R4 rules that are built correctly have no node that bites. Security checks the three edits by node id and mutation before the commit.

## A. Differentials

| Run | Cases | Differences |
|---|---|---|
| `approval.py` against the round 4 reviewed copy | byte compare | **identical**, so the section 1 `apply_external` differential (1708 cases, 0 differences in round 4) is not rerun. `records_cmds.py` is identical too |
| `_verify_remote_approval`: `975e2bc`, new without `refuse`, new with `refuse` | 485 | **0**. 193 `None` results each carry exactly one code; none of the 292 successes carries one |
| Row layer: `975e2bc` rebuild + apply against the new `_rebuild_envelope` + apply (`process.py` changed) | 34 row forms | **0**, apart from the intended one (`signatures[0]` not an object: `975e2bc` crashes the cycle, new stays pending). 6 forms execute on both; 27 stay `awaiting_second` on both |

## B. R4 items against the code and their nodes

| Item | Code | Node | Bite (scratch copy) |
|---|---|---|---|
| R4-1 | `OSError` at token and registry gives `network_error`, not immediate. TLS stays first | `TestR4_1[token\|registry]`; `test_outage_at_registry_counts_toward_three` now asserts `network_error` | Branch removed: 3 failed |
| R4-2 | `SyncLocalKeyError` raised before nacl. The text names the length only. Re-raised before the transport handlers | `TestR4_2`; frozen `test_f1_short_device_key_raises` passes | Check removed: both fail. Pass-through removed: `TestR4_2` fails (an alert is written). f1 still passes, as expected, because the class is a `SyncError` |
| R4-3 | Counters are `int`, not `bool`, with `0 <= v <= 2**63`, or the file drops | `TestR4_3` | Negative accepted: fails |
| R4-4 | Any present field of the wrong type drops the file. Non-alert entries missing `count`, `alerted`, `first_seen` or `last_seen` drop it. No coercion is left | `TestR4_4`, 8 forms | Each of 7 type rules reverted fails its form(s). **The non-alert missing-field rule has no node: 234 pass (R5-2)** |
| R4-5 | The inference is deleted. Every raise gives `apply_raised (<Type>), record is <state>`. The `boom` fixtures return `False` | `TestR4_5`, `TestR3_4` | `OSError` inference back: `TestR4_5` fails. Any-exception inference back: both fail. Probe: 12 of 12 `OSError`/`RuntimeError` forms give `apply_raised` |
| R4-6 | The pre-check is deleted | `TestR4_6`, 4 forms; `test_r3_5_empty_pending_file` deletes the second copy | Item 2 below |
| R4-7 | The non-string clause is deleted. A real `invalid_id` gives `decision_refused` / `request_id_refused` | `test_r2_11_invalid_id_alerts`, `test_guard_r2_11_branch` (both with the real `"invalid_id"`) | Bent clause back: 2 fail. Real branch removed: 2 fail. The reason text ends `: invalid_id`, not the sentence (SHOULD 1) |
| R4-8 | Sort is `0 if verified else 1`. `_VERIFIED_SORT` is gone | `test_h2_verified_first_sort`, rewritten | Item 3 below |
| R4-9 | Not done | `test_r2_6_executed_not_suppressed` | **Vacuous (R5-1)** |
| R4-10 | `net_stage` is persisted and cleared on reset. The line is exactly `Decisions: fetch failed: network_error at <stage>, <n> in a row`. The `network_error` entry line is skipped. The regex fallback is deleted | `TestR4_10[decisions\|registry]` | Stage not persisted: 3 fail. Old format: 2 fail. Stage not passed: 3 fail. **Second line allowed back: 234 pass (R5-3)** |
| R4-11 | The outer `except Exception` handler uses the type name | `TestR4_11` | `str(exc)` back: fails |

## C. Rulings on the builder and qa items

| # | Item | Ruling | Why (measured) |
|---|---|---|---|
| 1 | Alerted entries default a missing `count` to 1 and a missing `repeats` to 0, instead of dropping the file | **Accepted** | `count` and `repeats` only feed the alert record and the status display. `should_alert` reads `alerted`, `last_alerted` and `first_seen`. With the refusal key's entry alerted 10 s ago, missing `count`, missing `repeats`, or both give 0 alerts. A valid entry with `count: 1` also gives 0. So the default gives no power a valid edit lacks, and the named-limit bound holds. The R4-4 text named non-alert entries only. A present `count` of the wrong type still drops the file (the `count_str` form bites), and a non-alert entry missing `count` drops it too (measured) |
| 2 | qa's `TestR4_6` rewrite: does it bite? | **Verified** | With the R3-build pre-check restored on the scratch copy, only `[deny_copy]` fails: `_fetch_decisions gave 'pending' but apply_external gave 'done'`. With the `81fda66` pre-check, `[deny_copy]` and `test_r3_5_empty_pending_file` fail. The `empty`, `garbage` and `directory` forms pass with and without the pre-check, as equivalence guards should. Probe: all three give `pending_record_unreadable` through `apply_external`'s own read |
| 3a | `TestR4_ShouldGuards::test_should_verified_refusal_keeps_key_id` | **Bites** | Verified refusal's key id dropped: 1 failed, 233 passed (only this node) |
| 3b | `test_should_nonce_replay_in_post_sig_codes` | **Bites** | `nonce_replay` removed from `_POST_SIG_CODES`: 1 failed, 233 passed. It is a constant check, which is enough for a fail-safe set member |
| 3c | `test_should_registry_stage_str_exc` | **Bites** | `str(exc)` at registry: fails. This closes round 4's "no node" row |
| 3d | R4-8 H2 node (genuine `command_mismatch`, placed last) | **Bites** | Verified-first removed: 1 failed, 233 passed (only this node). Verified-last: fails. The product's sort no longer carries the bent rank |
| 3e | R4-9 R2-6 seed | **Still vacuous: R5-1** | The node seeds `executed:2:[]:None`, but the product stores `executed:None:[]:None` (measured: `apply_external` returns no `approvals` for `executed`). With `process.py` `if status not in ("executed", "denied"):` changed to `if True:`, 234 pass |

## D. MUSTs (test only; no product change)

qa edits; security reruns each named mutation on a scratch copy before the commit. None of these adds or removes a strict-xfail marker.

### R5-1 LOW: the R2-6 node is still vacuous (R4-9 not done)

- **Fix (test only):** in `TestR2_6::test_r2_6_executed_not_suppressed`:
  - seed `"outcome_sig": "executed:None:[]:None"`;
  - correct the comment, which says the request has 2 approvals;
  - after `_fetch_decisions`, assert that `DecisionState(logs_dir)._entries[f"sync_decision_applied:{rid}"]["outcome_sig"]` equals the seed. A future format change then fails the node instead of making it vacuous again.
- **Proof required:** the node passes on the tree and fails with `if True:` at the R2-6 line. Prototyped on the scratch copy: passed unmutated, 1 failed mutated.

### R5-2 LOW: the R4-4 non-alert missing-field rule is unguarded

- **Fix (test only):** add an unmarked guard `TestR4_ShouldGuards::test_r5_2_nonalert_missing_field_drops_file[count|alerted|first_seen|last_seen]`. Use the `TestR4_4` setup: the refusal key's entry is alerted with `last_alerted` 10 s ago. Add a second entry `decision_refused:req-other:unknown_key` = `{"count": 1, "alerted": false, "first_seen": now-5, "last_seen": now-5, "repeats": 0}` with the named field removed. The next cycle must write the refusal alert.
- Keep it outside `TestR4_4`. That function carries the R4 marker, and these are guards that pass today.
- **Proof required:** removing the missing-`count` raise fails `[count]`, and removing the missing-`alerted`/`first_seen`/`last_seen` block fails the other three. Prototyped: 1 and 3 failed.

### R5-3 LOW: the R4-10 "no second line" rule is unguarded

- **Fix (test only):** in `TestR4_10::test_r4_10_network_line_stage_on_early_cycles`, keep the one-cycle check, then run two more outage cycles at the same stage, with a fresh `SyncProcess` each time.
- Assert that the `network_error` lines of `sandbox status` are exactly `["  Decisions: fetch failed: network_error at <stage>, 3 in a row"]`. After cycle 3 a `network_error` entry exists, so the one-cycle check cannot see the duplicate.
- **Proof required:** deleting the `if code == "network_error": continue` skip in `connector_cmds.py` fails both forms. Prototyped: 2 failed.

## E. SHOULDs

1. R4-7 reason text: `<rid> refused: request_id_refused: invalid_id` should end in the sentence, per spec section 2 row 72 and the R4-7 fix text: `_REFUSAL_SENTENCES["request_id_refused"]`. The text is code-written, so there is no security effect. The `record_changed` branch has the same drift.
2. `net_stage` is a new top-level field. It is read as any string, and a non-string is ignored rather than dropping the file. Validate it against `token`, `registry` and `decisions`, and drop the file otherwise, as R4-4 does. Measured: no ESC reaches the terminal (detail held, G).
3. Carried from round 4, unchanged:
   - key-free reading at `connector_cmds.py:491`, `578` and `612`, or correct the docstring;
   - `_LOCAL_CTRL` lacks NBSP, NNBSP, surrogates, U+2028, U+2029, U+200B, U+FEFF and U+00AD;
   - `not_pending` after a claim race alerts `request_id_refused` where the spec says none.
4. `TestR4_1` checks the status line only after cycle 3, and only for `in a row`. R4-10 and R5-3 cover the stage, so this is optional.
5. Information only, no node and no change in power:
   - counter upper bound removed (values above `2**63` give the same rest-of-hour bound as `2**63`);
   - `entries` not a dict keeping the counters.

## F. Mutation list (scratch copy, `M3_T9A_BODIES=1 --runxfail`)

| Reverted or mutated | Result |
|---|---|
| R4-1 `OSError` branch removed | `TestR4_1[token]`, `[registry]` and `test_outage_at_registry_counts_toward_three` fail |
| R4-2 length check removed; `SyncLocalKeyError` pass-through removed | `TestR4_2` and frozen f1 fail; `TestR4_2` fails |
| R4-3 negative counters accepted | `TestR4_3` fails |
| R4-3 upper bound removed | 234 pass (information only, E5) |
| R4-4 list entry skipped; `reason`/`code` coerced; `verified`, `status` popped; `count`, `repeats`, `first_seen` coerced; `alerted` coerced | Each named `TestR4_4` form fails (1, 2, 1, 1, 1, 1, 1); `test_r3_3_alerted_str_drops_file` fails |
| R4-4 non-alert missing `count`; non-alert missing `alerted`/`first_seen`/`last_seen` | **234 pass each (R5-2)**. With the R5-2 prototype: 1 and 3 fail |
| R4-4 `entries` not a dict keeps counters | 234 pass (information only, E5) |
| R4-5 `OSError` inference back; any-exception inference back | `TestR4_5` fails; `TestR4_5` and `TestR3_4` fail |
| R4-6 pre-check back (R3-build form; `81fda66` form) | `[deny_copy]` fails; `[deny_copy]` and `test_r3_5_empty_pending_file` fail |
| R4-7 bent clause back; real branch removed | 2 fail each (`test_r2_11`, `test_guard_r2_11_branch`) |
| R4-8 verified-first removed; verified-last | `test_h2_verified_first_sort` fails (1 of 234); fails |
| R4-9 `executed`/`denied` deduped | **234 pass (R5-1)**. With the R5-1 seed: fails |
| R4-10 stage not persisted; old line format; stage not passed | 3, 2 and 3 fail |
| R4-10 second `network_error` line allowed | **234 pass (R5-3)**. With the R5-3 prototype: 2 fail |
| R4-10 regex fallback back | 234 pass (deleted dead code; no node needed) |
| R4-11 `str(exc)` in the outer handler | `TestR4_11` fails |
| qa SHOULD guards a, b, c | Each fails alone (C 3a to 3c) |
| Round 4 list rerun on this tree: R3-1 (both), R3-2, R3-6 (both), R3-7 entry and HTTP, R3-8, R3-9, H1 strips, qa R2-5 and 3xx guards, R2-1 behavioural, R4-H2 verdict guard, R2-4 (both), `clear_request` | Every one still fails its named node(s), with the same counts as round 4 |

## G. Held items

R2-H1 to R2-H3 were re-derived against the working tree. The details are held privately and reported to the orchestrator.

| Item | Status |
|---|---|
| R2-H1 | **Closed.** The R4-11 path is measured end to end through a real socket and `sandbox sync --once`, and the registry path is now guarded |
| R2-H2 | **Closed and guarded** (C 3d) |
| R2-H3 | **Closed.** The R4-3 and R4-4 forms now drop the file and alert. The bounded forms stay inside the named limit. Item 1 adds no silencing power |

## H. Scanners

Run on the five product files, the two T9a test files and `tests/security/fixtures/` (9 files).

| Scanner | Result |
|---|---|
| Semgrep 1.178.0, `p/python` and `p/secrets`, `--metrics=off --timeout 120`, explicit file targets | 187 rules, 9 files: **0 findings, 0 errors**. A directory target skips `tests/` under Semgrep's default ignore, so the files were named explicitly |
| gitleaks 8.30.1 `dir` (repo config and default) | No leaks |
| trivy `fs` 0.74.0 (secret and misconfig; HIGH and CRITICAL) | 0 secrets, 0 misconfigurations |
| ruff `S,B,BLE` (`--isolated`) against `81fda66`; the security test file against the round 4 copy | Product files are identical to `81fda66` (S110 15, S112 3, BLE001 4, B904 2, S310 1, S311 2), so nothing is new. `test_m3_t9a_fetch_decisions.py` is identical. `test_m3_t9a_security.py` adds S101 +7, S105 +4 and BLE001 +3, all test-only |

## I. Runs (Windows, venv Python 3.12, Git bash)

| Run | Result |
|---|---|
| `M3_T9A_BODIES=1 -p no:logging --runxfail`: both T9a files + frozen `test_m2_t16a_sync_cycle.py` | **256 passed** in 99 s, matching the orchestrator |
| Both T9a files in CI mode (junit, grouped by class and marker reason) | 126 failed, all `XPASS(strict)`: security file 89 = 27 R2 + 42 R3 + 20 R4; fetch_decisions 37 round 1. 108 passed |
| The 22 M1/M2 security files that touch the sync path, plus `test_m1_t5_standalone.py` | **699 passed**, 6 skipped, 1 xfailed. Frozen f1 passes |
| `ee/tests/test_m3_t9a_e2e.py --timeout=600` | **1 passed** in 38 s. The container list is the same before and after: three exited containers, 11 days and 3 weeks old |

The full root run was not repeated. The orchestrator's 128 failures are accounted for: 126 markers (re-measured above) and 2 node-id lists.

## Before the commit

1. **qa makes R5-1 to R5-3** (test only, no marker added or removed). qa runs `M3_T9A_BODIES=1 --runxfail` on both T9a files plus `test_m2_t16a`: expect 260 passed (256 + the 4 R5-2 guards).
2. **Security checks the three by node id** and reruns the three named mutations on a scratch copy. This is a diff check, not a new round.
3. **qa removes the markers**, listed below. Then the full root suite in CI mode should show only the 2 node-id list tests until they are regenerated.
4. **Then** `m2_gate.py` and `demo.py` on a fresh stack, the manifest and both node-id lists, and the commits, as HANDOFF orders.

**Markers to remove** (counted from the file by class and marker reason, and matching the CI-mode `XPASS(strict)` count):

- `test_m3_t9a_security.py`: 89 nodes = 27 R2 + 42 R3 + 20 R4.
  - R2: `TestNewTargets` 1, `TestR2_1` 1, `TestR2_2` 3, `TestR2_3` 2, `TestR2_4` 1, `TestR2_5` 3, `TestR2_6` 1, `TestR2_7` 1, `TestR2_8` 1, `TestR2_9` 2, `TestR2_10` 2, `TestR2_11` 1, `TestR2_12` 2, `TestR2_13` 2, `TestR2_14` 1, `TestR2Lows` 3.
  - R3: `TestR3_1` 12, `TestR3_2` 1, `TestR3_3` 14, `TestR3_4` 1, `TestR3_5` 1, `TestR3_6` 2, `TestR3_7` 3, `TestR3_8` 1, `TestR3_9` 1, `TestR3_H1` 6.
  - R4: `TestR4_1` 2, `TestR4_2` 1, `TestR4_3` 1, `TestR4_4` 8, `TestR4_5` 1, `TestR4_6` 4, `TestR4_10` 2, `TestR4_11` 1.
- `test_m3_t9a_fetch_decisions.py`: 37 round 1 nodes.

The T9a commit carries the same files as the round 3 list. The frozen `test_m2_t16a_sync_cycle.py` is not edited.

## Round 5 diff check, 16 Nov 2026

Reviewer: security (L). This is "Before the commit" step 2, a diff check and not a new round. Method: the security test file was diffed against the round 5 scan copy, and each named mutation was run on a scratch copy of `src/` and `tests/` outside the repo. Imports were checked to resolve to the copy, and the copy was deleted afterwards. Only this section was edited. Nothing was left running.

**Verdict: CLEARED.** R5-1 to R5-3 are built as the round 5 text says, and each named mutation fails exactly its named node(s) and nothing else. The commit can go ahead to step 3 (qa removes the markers).

### Edits by node id

| MUST | Node | Check |
|---|---|---|
| R5-1 | `TestR2_6::test_r2_6_executed_not_suppressed` | Seed is `executed:None:[]:None`. The comment no longer says 2 approvals. After `_fetch_decisions` the node asserts that `DecisionState(logs_dir)._entries["sync_decision_applied:<rid>"]["outcome_sig"]` equals the seed. Strict-xfail marker unchanged |
| R5-2 | `TestR4_ShouldGuards::test_r5_2_nonalert_missing_field_drops_file[count\|alerted\|first_seen\|last_seen]` | 4 forms with no marker. Uses the `TestR4_4` setup: the refusal key's entry is alerted, `last_alerted` 10 s ago. A second entry `decision_refused:req-other:unknown_key` lacks the named field. Asserts the refusal alert is written. The guard sits in `TestR4_ShouldGuards`, outside `TestR4_4` |
| R5-3 | `TestR4_10::test_r4_10_network_line_stage_on_early_cycles[decisions\|registry]` | The one-cycle check is kept. Two more outage cycles follow, each with a fresh `SyncProcess`. The node asserts that the `network_error` lines are exactly `["  Decisions: fetch failed: network_error at <stage>, 3 in a row"]` |

Diff against the round 5 copy: three hunk groups only (lines about 1699 to 1728, 3473 to 3495 and 3593 to 3639). The only `pytest.mark` line added is the R5-2 `parametrize`. Information only, no action needed: the R5-1 comment cites `process.py:834`, but the `outcome_sig` line is now 851. The R5-3 loop copies a dead `if stage != "token":` branch.

### Mutations (scratch copy, `M3_T9A_BODIES=1 -p no:logging --runxfail`, both T9a files, 238 nodes)

| Mutation | Result |
|---|---|
| None (baseline, both T9a files + frozen `test_m2_t16a_sync_cycle.py`) | **260 passed**, matching the orchestrator |
| R5-1: `process.py` `if status not in ("executed", "denied"):` changed to `if True:` | **1 failed**, 237 passed: `TestR2_6::test_r2_6_executed_not_suppressed` |
| R5-2: `decision_state.py` non-alert missing-`count` raise removed | **1 failed**, 237 passed: `[count]` |
| R5-2: `decision_state.py` non-alert missing `alerted`/`first_seen`/`last_seen` block removed | **3 failed**, 235 passed: `[alerted]`, `[first_seen]`, `[last_seen]` |
| R5-3: `connector_cmds.py` `if code == "network_error": continue` deleted | **2 failed**, 236 passed: `TestR4_10[decisions]`, `[registry]` |

### Product and markers

- `git diff --stat -- src`: 5 files, 667+/541-, as in round 5. The five product files are byte-identical to the round 5 scan copy, and their modification times predate the round 5 section. `tests/security/fixtures/` and `test_m3_t9a_fetch_decisions.py` are identical to that copy too.
- Strict-xfail marker lines: 53 (security file) and 27 (fetch_decisions file), the same as the round 5 copy. None was added or removed.
