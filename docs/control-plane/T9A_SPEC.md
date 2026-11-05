# T9a behaviour spec and T5 test review

Security (L), 5 Nov 2026, HEAD `ccd02fe`. qa and backend both build to this file. Paths: `conn/` = `src/sandbox/connector/`.

**Method.** Code read. Measured on the Windows laptop, venv Python 3.12: the T9a bodies with the sentinel neutralised by a scratch plugin; both test files collected through `python -m pytest`, `coverage run -m pytest` and the plain `pytest` entry point; `docker compose -f compose.yml config` on the base file. Docker on the Windows runner comes from the `actions/runner-images` Windows 2025 readme; that `windows-latest` points at that image was not checked. No build, stack or CI run.

**Verdict.** The design below weakens none of the five properties if the section 6 guard nodes land. No wire change. Security (L) blocks a T9a diff that changes any `apply_external` verdict, reads the new state file from a decision path, or echoes row data as fact.

## 1. What the code does today (defect f)

The plan's "two bare returns" and qa's "two `except: pass`" are both incomplete. The two handlers exist (`process.py:513-516`). The silent or cycle-killing exits are:

| # | Line | Trigger | Today |
|---|---|---|---|
| E1 | 188-191 (`_default_connect`) | Unparseable JSON | Becomes `{}`; the fetch cannot tell it from an empty reply |
| E2 | 462-463 | Non-200 | Raises `SyncError`; no alert or audit; bundle, escalation and audit steps skipped |
| E3 | 459 | Network error | Propagates; same effect |
| E4 | 470-477 | Body not list or dict; dict without the key; `null` | Silent return |
| E5 | 473, 483 | `decisions` truthy but not a list | `TypeError` or `AttributeError` kills the cycle |
| E6 | 484 | A row that is not an object | `AttributeError`: one row stops every row and the rest of the cycle |
| E7 | 485-486 | Invalid `request_id` | Silent `continue` |
| E8 | 487-489, 525-541 | Payload or signature unusable | Silent drop; `sigs[0].get` on a non-object raises as in E6 |
| E9 | 513-514 | Audit append fails | `pass` |
| E10 | 515-516 | `apply_external` raises | `pass`; a raise after the claim leaves the record in `claimed`, gone from `sandbox status` |
| E11 | 508-512 | Returned status | Only `status` is kept. `apply_external` has 6 `awaiting_second` exits and `_verify_remote_approval` has 29 `return None` drops, none with a reason code (section 3) |
| E12 | 297, 294 | Outage or revoked token | `_refresh_token` or `_fetch_registry` raises first, so `_fetch_decisions` never runs. A counter inside it would never reach 3 in a real outage |
| E13 | `escalations.py:656-667` | Server serves every approval row forever | Each poll writes one `sync_decision_applied status=not_pending` per finished request (code reading, not measured) |

`SyncProcess` is rebuilt on each `sandbox sync --once`, so any in-memory counter resets there.

## 2. Failure table

New `_ALWAYS` entries (event = kind): `decisions_fetch_failed`, `decisions_malformed`, `decision_refused`, `decision_apply_failed`, `decision_alerts_suppressed`. None contains `fork` or `truncat` (`m2_gate.py:677`).

- Every alert also writes a `FolderAudit(session_id="sync")` record with the same event, `reason_code`, `reason`, and where known `stage`, `status`, `request_id`, `key_id`, `count`. `tool` is `"sync"`, so the alerts line prints `sync`.
- `sandbox alerts` prints `[ts] KIND  sync  <reason>`. The reason column below is that text. `<S>` is the sentence for the code.
- `_fetch_decisions` never raises `Exception`. It must not catch `BaseException` (`test_sync_loop_exits_on_keyboard_interrupt`).
- "Fails" means `sync._decisions_failed` is set: steps 4-6 still run, then `run_once` raises `SyncError` at the end, so `--once` exits 1 and backoff grows as today. "OK" means the cycle counts as a success.
- Nothing here changes a request's state or runs anything.

| Class | Alert kind / `reason_code` | `sandbox status` (managed only) | `sandbox alerts` reason | Cycle | Later rows |
|---|---|---|---|---|---|
| Network (`ConnectionError`, `OSError`, `URLError`, timeout) at token, registry or decisions, cycles 1-2 | None. Log and counter only | `Decisions: fetch failed: network_error at <stage>, <n> in a row` | none | Fails | None read |
| Same, 3rd consecutive cycle, then per section 4 | `decisions_fetch_failed` / `network_error` | same | `decisions not fetched for <n> consecutive cycles: network_error at <stage> (<ExcType>)` | Fails | None |
| TLS verification failure | `decisions_fetch_failed` / `tls_verify_failed`, immediate (adds scrutiny beyond G7-B) | `Decisions: fetch failed: tls_verify_failed at <stage>` | `decisions not fetched: tls_verify_failed at <stage>: <S>` | Fails | None |
| Other exception from the transport (`HTTPException`, `RecursionError`) | `decisions_fetch_failed` / `transport_error`, immediate, type name only | `...: transport_error at <stage>` | `decisions not fetched: transport_error at <stage> (<ExcType>)` | Fails | None |
| `SyncError` from the transport (scheme, redirect URL) | `decisions_fetch_failed` / `transport_refused`, immediate | `...: transport_refused at <stage>` | `decisions not fetched: transport_refused at <stage>: <S>` | Fails | None |
| HTTP 401 on decisions | `decisions_fetch_failed` / `token_rejected`, immediate. Sets `_token_expires = 0`; keeps the token for this cycle | `Decisions: fetch failed: HTTP 401 at decisions: token_rejected` | `decisions not fetched: HTTP 401 at decisions: token_rejected: <S> (server says: <text>)` | Fails | None |
| HTTP 403 on decisions | `decisions_fetch_failed` / `token_forbidden`, immediate. Same expiry reset | same with 403 | same with 403 and `token_forbidden` | Fails | None |
| HTTP 401 or 403 on `/sync/token` (revoked device) | same codes, `stage=token`, recorded in `run_once` | `... at token: ...` | same with `at token` | Stops at step 1, raises as today | None |
| Non-200 from `/sync/token`, other classes | as the matching row below, `stage=token` | as below | as below | Stops, raises as today | None |
| Other 4xx (400, 404, 405, 409, 410, 422, 429) | `decisions_fetch_failed` / `http_4xx`, immediate | `...: HTTP <n> at decisions: http_4xx` | `decisions not fetched: HTTP <n> at decisions: http_4xx (server says: <text>)` | Fails | None |
| 5xx | `decisions_fetch_failed` / `http_5xx`, immediate | same | same | Fails | None |
| 3xx, 1xx, 2xx other than 200 | `decisions_fetch_failed` / `http_3xx` or `unexpected_status`, immediate | same | same, no server text | Fails | None |
| Date state write fails (`_record_server_time`) | `decisions_fetch_failed` / `server_time_write_failed`, immediate | `Decisions: server_time_write_failed` | `<S>` | OK | All process; approvals refuse by the skew rule |
| 200, unparseable body | `decisions_malformed` / `unparseable_body` | `Decisions: last response malformed: <code>` | `decisions response malformed: <code>: <S>` | OK | None |
| 200, JSON scalar | `decisions_malformed` / `not_object_or_list` | same | same | OK | None |
| 200, dict without `decisions` | `decisions_malformed` / `decisions_key_missing` | same | same | OK | None |
| 200, `decisions` not a list, `null` included | `decisions_malformed` / `decisions_not_list` | same | same | OK | None |
| 200, `[]`, bare list, or `{"decisions": []}` | None (frozen shapes) | none | none | OK | n/a |
| Row not an object | `decisions_malformed` / `row_not_object`, one per cycle with `count` | same | `<n> decision row(s) dropped: row_not_object: <S>` | OK | Continue |
| Invalid or wrong-typed `request_id` | `decisions_malformed` / `request_id_invalid`, value never echoed | same | same shape | OK | Continue |
| Payload missing, not an object, bad JSON | `decisions_malformed` / `payload_unusable` | same | same shape | OK | Continue |
| Signature missing; `signatures[0]` not an object (rebuild returns `None`, never raises) | `decisions_malformed` / `signature_missing` | same | same shape | OK | Continue |
| Approval fails verification | `decision_refused` / code from section 3 | Under the request: `      awaiting_second: claimed key <kid12> <code>: <S>` | `<rid> awaiting_second: <counted> of 2 counted; claimed key <kid12> <code>: <S>` | OK | Continue; other envelopes for this request still count |
| Verifies, does not count: `not_dual_eligible`, `same_user`, `same_identity`, `operator_self_approval`, skew, others in section 3 | `decision_refused` / that code | `      awaiting_second: key <kid12> (user <registry user_id>) <code>: <S>` | `<rid> awaiting_second: <counted> of 2 counted; key <kid12> (user <id>) <code>: <S>` | OK | Continue |
| Request-level `awaiting_second` (section 3, table 2) | `decision_refused` / that code | `      awaiting_second: <code>: <S>` | `<rid> awaiting_second: <code>: <S>` | OK | Continue |
| Normal 1 of 2, no refusal | None. `needs_second_approver` in state only | `[dual control 1/2]` plus `      awaiting_second: 1 of 2 counted; a different approver must sign` | none | OK | Continue |
| `apply_external` raises | `decision_apply_failed` / `apply_raised`, type name and `queue_state` | `Decisions: <rid> apply failed (<ExcType>), record is <queue_state>`; if `claimed` add `; it will not run again, inspect by hand` | `<rid> apply failed: apply_raised (<ExcType>), record is <queue_state>` | OK | Continue. Never auto-release or retry a claimed record |
| Returns `nonce_save_failed` or `key_unavailable` | `decision_apply_failed` / that code | `Decisions: <rid> <code>: <S>` | `<rid> apply failed: <code>: <S>` | OK | Continue |
| Pending record unreadable (`not_pending` while `queue.status` says pending) | `decision_apply_failed` / `pending_record_unreadable` | same | same | OK | Continue |
| Returns `changed`, `invalid_id`, or `refused` with a local reason | `decision_refused` / `record_changed`, `request_id_refused`, `script_unbound`, `script_preview_not_shown` | `      <code>: <S>` | `<rid> refused: <code>: <S>` | OK | Continue |
| `not_pending`, local state done or claimed | None, and no audit record (fixes E13) | none | none | OK | Continue |
| `not_pending`, local state unknown | `decision_refused` / `unknown_request`, one per cycle with `count`, no id echoed | none | `<n> decision(s) for requests this device does not hold` | OK | Continue |
| Audit append fails | Alert still attempted; `logging.error` | unchanged | unchanged | OK | Continue |
| Alert write fails or alerts disabled by signed policy | Audit record still written; `logging.error` on failure | unchanged | `Alerts: OFF` if disabled | OK | Continue |
| `layout is None` (seam only; `test_sync_process_run_once_uses_injected_connect`) | None; `logging.warning`. Non-200 still fails the cycle | n/a | n/a | As the class | None |

`sync_decision_applied` stays for every applied outcome, with additive `approvals` and `reason_codes`. It is written on a change of `(status, approvals, reason_codes)`, never capped. `executed` and `denied` are never suppressed. A broker refusal keeps its existing `script_changed` alert with no duplicate.

**Cycle shape (load-bearing):**

```python
try:
    _refresh_token(sync)      # non-200 raises SyncHTTPError(SyncError) with .status, .stage
    _fetch_registry(sync)
    _fetch_decisions(sync)    # never raises Exception; may set sync._decisions_failed
    _fetch_bundle(sync); _upload_escalations(sync); _upload_audit(sync)
    if sync._decisions_failed:
        raise SyncError(...)  # after the audit upload, so a bad route cannot suppress upload
    sync._consecutive_failures = 0
except ...:                   # existing handlers; record a failure from steps 1-2 first
```

## 3. Reason codes

`apply_external` keeps its signature (no new kwargs, F1=A) and returns additive keys: `refusals: [{key_id, code, verified, user_id?}]` and, on request-level exits, `reason_code`. `_verify_remote_approval` gains a keyword `refuse: Callable[[str], None] | None = None`; each `return None` becomes a call through one `_drop(code)` helper. Sentences live in `process.py`, not `approval.py` (`test_h2_grep_no_decision_path_reads_unverified` forbids some literals there).

**Table 1, per envelope (`approval.py`).** `verified` means the signature check passed. Only then may the line name the registry user. Otherwise it says `claimed key` and no user.

| Code | Line | Verified | Sentence |
|---|---|---|---|
| `not_object`, `wrong_tag`, `bad_payload` | 429, 433, 437 | no | The approval envelope is malformed |
| `missing_fields` | 442 | no | The signed payload lacks required fields |
| `signature_count` | 447, 450 | no | An approval must carry exactly one signature |
| `key_id_mismatch` | 455 | no | The payload and signature name different keys |
| `no_registry` | 459 | no | No verified registry is available |
| `unknown_key` | 462 | no | This key is not in the latest pinned registry (unknown or removed) |
| `wrong_key_kind` | 472 | no | Device and bundle-signer keys cannot approve |
| `role_missing` | 477 | no | This key has neither the approver nor the admin role |
| `user_mismatch` | 485 | no | The payload's user differs from the registry entry |
| `bad_decision` | 491 | no | The decision is neither approve nor deny |
| `prod_refused`, `registry_expired`, `kind_not_allowed` | 493-495 (same condition, split for the label only) | no | Remote approval is not allowed on prod / The pinned registry has expired / This key kind may not sign this |
| `policy_sequence_mismatch` | 498 | no | The approval names another policy sequence |
| `not_after_invalid` | 503, 505 | no | The expiry is not a finite number |
| `approval_expired` | 513 | no | The approval expired |
| `nonce_invalid` | 518 | no | The nonce is missing or too long |
| `bad_signature` | 534 | no | The signature does not verify |
| `verify_raised` | 752 | no | The envelope could not be checked (`<ExcType>`) |
| `nonce_replay` | 551 | yes | This nonce was already used for another request or payload |
| `operator_self_approval` | 557 | yes | The device's operator cannot approve their own request |
| `fingerprint_unavailable`, `request_mismatch`, `fingerprint_mismatch`, `command_mismatch`, `device_mismatch`, `project_mismatch`, `org_mismatch` | 566-584 | yes | The approval is bound to a different `<field>` |
| `nonces_corrupt` | 757 | yes | The nonce store is corrupt, so approvals are refused and denies still apply |
| `clock_skew` | 771-784 | yes | Clock skew is over 2 minutes |
| `no_server_time` | 785-788 | yes | No server time has been measured, so approvals are refused |
| `same_user` | 831 | yes | This user already counted, and one person counts once |
| `same_identity` | 841 | yes | This identity already counted |
| `not_dual_eligible` | 849 | yes | The registry version that added this key had fewer than 2 admin signatures, so it cannot count toward dual control |

**Table 2, request level.**

| Code | Line | Sentence |
|---|---|---|
| `no_verified_state`, `no_operator`, `no_device_id` | 678-679 | This device has no verified state, operator or device id, so remote approvals are refused |
| `record_ahead_of_bundle` | 728 | The request is newer than this device's policy |
| `registry_expired` | 824 | The pinned registry has expired |
| `no_approvals_counted` | 874 | No approval counted |

## 4. Rate limit across cycles

State file: `.sandbox/logs/decision_state.json`, written atomically by a new `conn/sync/decision_state.py` with no network imports. It is outside `state/sync/`, so it never enters the trust directory and step 8's deletion of that directory is unaffected.

It is **display and rate-limit state only**. No decision path reads it. Corrupt or missing means empty: more alerts, never fewer. The same logic runs under `--once` and the loop.

| Rule | Value |
|---|---|
| Key, per-request refusal with `verified=true` | `(kind, rid, code, key_id)`, bounded by the signed registry |
| Key, per-request refusal unverified | `(kind, rid, code)`; a server-chosen key id never makes a new key |
| Key, fetch | `(kind, stage, status, code)` |
| Key, malformed or unknown request | `(kind, code)` |
| First sighting | Alert and audit now |
| Same key later | `count += 1`, no alert, no audit |
| Still present after `DECISION_REALERT_SECONDS = 3600` | One alert and audit with `repeats: n`, timer reset |
| Clearing | Fetch keys clear on a 200. Request keys clear when the request leaves pending or its code set changes |
| `DECISION_ALERTS_PER_CYCLE = 5`, `DECISION_ALERTS_PER_HOUR = 12` | Applies to these five kinds only; `audit_fork` and others are untouched. Order within a cycle: apply failed, fetch failed, refused, malformed |
| Over the cap | The key stays `alerted: false`, so it fires in a later window. One `decision_alerts_suppressed` per hour with the count. `sandbox status` still shows every per-request line |
| Size | 256 keys, oldest `last_seen` evicted; 8 reasons per request with `+n more`, `verified=true` first |
| `DECISIONS_NET_ALERT_AFTER = 3` | Persisted here, not on the process object; reset by a decisions 200 |

## 5. What a hostile server can do with this path

| STRIDE | Abuse | Bound |
|---|---|---|
| D | Rotate bad rows or flap status to flood alerts, the chain and the webhook | At most 13 lines per hour, about 5 KB; 13 webhook calls, each bounded by `timeout_seconds`; 256 state keys |
| D | Bury a real alert past `sandbox alerts` default of 20 | **Named limit.** Other kinds keep firing, and the cap sits under the default view for about 90 minutes. After that, use `-n` or the webhook |
| D | Use one bad row to stop every row, or a failing route to stop audit upload | Removed: E5, E6, E8 and the cycle shape above |
| S | Misleading reason text | Server text appears only on non-200, only `detail` or `error` if a string, after a code-written prefix and the label `server says:`. Row data is never echoed |
| S | Forged row naming a real approver | `claimed key <kid12>`, no name; `payload.user_id` is never printed; key id must be hex or prints `invalid` |
| T | Terminal or log injection | Order: cut to 4 KiB, strip C0, C1, DEL and bidi controls, `scrub_text`, cap at 200 characters. A scrub failure drops the text |
| I | Secrets in an alert | No token, header, URL query, device key, or `str(exc)` (type name only, per the T16g LOW ruling). The record uploads back to the server, scrubbed |
| R | Claim nothing was refused | The first sighting of each key is chained, and distinct outcomes are never capped |
| E | Turn an alert into an approval | None: the alert path sits after the verdict and nothing reads the state file to decide |
| Limit | Withhold rows behind a 200 | Undetectable. The request stays pending and fails closed. Existing compromised-server limit |
| Limit | Confusable Unicode inside the 200 characters | Not addressed. The prefix and label are the bound |

A local agent editing the state file can only change what is displayed or rate-limited. `.sandbox/` is already write-protected from the agent, and the chain and the verdict do not depend on the file.

## 6. Guard nodes the build must keep green

In `tests/security/test_m3_t9a_fetch_decisions.py`:

- `test_every_failure_class_leaves_request_pending_and_runs_nothing`, parametrized over section 2: pending set and done count unchanged.
- `test_verify_verdict_identical_with_and_without_refuse`: corpus of good and bad envelopes, both call forms, same result.
- `test_verify_remote_approval_has_no_bare_return_none`: `ast` check that every refusal goes through `_drop`.
- `test_decision_state_not_read_by_decision_paths`: `approval.py`, `hook_eval.py`, `classify.py`, `verified_state.py`, `bundles.py` do not name it.
- `test_hand_edited_decision_state_cannot_approve`: state claiming 2 of 2 counted runs nothing.
- `test_unmanaged_status_output_unchanged`: no `Decisions:` line and no new JSON keys for an OSS workspace.
- `test_alert_kinds_avoid_gate_substrings`: no `fork` or `truncat` in any new kind or sentence.

## 7. Frozen assertions the change could disturb

Builders report the node id and never relax it.

| Where | Risk | Constraint |
|---|---|---|
| `test_m2_t10_sync.py::test_sync_process_run_once_uses_injected_connect` | `layout=None`, body without `decisions` | No alert helper may dereference `None`; must not raise |
| `test_m2_t10_sync.py::test_server_down_escalated_call_stays_pending` | Short key raises in step 1 with a real layout | Recording in `run_once` must not raise anything but `SyncError` |
| `test_m2_t16a_sync_cycle.py::test_sync_loop_exits_on_keyboard_interrupt` | Connect raises `KeyboardInterrupt` | Catch `Exception` only |
| `test_m2_t16a_sync_cycle.py::test_sync_decision_applied_audit_event` | Dedupe | First outcome still written |
| `test_m2_t12b_sync.py::test_run_once_*` | Bare-list body, `payload` and `signatures` row shape; `payload: {}` row | Both shapes stay valid; unknown request not in `applied` |
| `test_m2_t11_audit.py` nodes at 1354, 1432 | `_consecutive_failures == 0` | Unchanged while decisions return 200 |
| `test_m2_t11_audit.py`, `test_m2_t16g_e2e.py` upload nodes | New or fewer `sync` records change uploaded counts | Run them; report any count pin |
| `test_m2_t15b_transport.py` | `_default_connect` return | The marker for E1 is a `dict` subclass that equals `{}` |
| `test_m2_t12b_remote.py::test_h2_grep_no_decision_path_reads_unverified` | New text in `approval.py` | Avoid the forbidden literals |
| `test_m2_t10_sync.py::test_guard_hook_does_not_import_sync_process` | New imports | Hook and `alerts.py` import nothing new from `sync/` |
| `test_m2_t12_remote.py`, `test_m2_t12_review.py` | Additive result keys | `status` and `approvals` unchanged; no equality on the whole dict was found by grep |
| `m2_gate.py:677` | New alert text | No `fork` or `truncat` in code-written text. Server text is echoed on non-200, so this holds in step 6 only while the stopped api's 502 carries no such `detail` |
| `m2_gate.py:600` | `SCRIPT_CHANGED` in `alerts -n 50` | Cap keeps it in view |
| `m2_gate.py:707-713` | Step 7 picks the first session with 4 or more records; dedupe shrinks `sync` | Confirm on the regression run |
| `m2_gate.py:870-876` | Status JSON | Additive top-level keys `decisions`, `decisions_fetch` only |
| `m2_gate.py:659` | Three `--once` during the stop | New `decisions_fetch_failed` alerts (502 at token); the rc is not asserted |
| `demo.py` | No use of `alerts` or `status` found | Not disturbed |
| `test_m3_t0a_freeze.py`, CI ee node-id step | New test files | See the question below |

**Regression run.** T9a is not in the plan's Q6 list, but it changes two TCB files and the 15 Nov gate needs 88/0/0 on the same code. Run `m2_gate.py` and `demo.py` on a fresh stack before the T9a commit.

**Question for the orchestrator.** `test_root_collect_only_equals_nodeids`, `test_manifest_covers_all_tracked_test_files` and the `ee` node-id step all go red the moment these files are tracked, unless the same commit updates `M3_FROZEN_MANIFEST.sha256` and both node-id lists. Marker removal then changes the hash again. The plan says the frozen list changes "only by a founder row", while `M3_BASELINE.md` section 5 says node ids are fixed at each tests-first commit. T1 and T3 hit the same thing. It needs one written rule before the first tests-first commit.

**Follow-ups, not T9a (lead, T9b candidates):** `_fetch_registry` silent on non-200 or an empty chain; `_fetch_bundle` raising still skips escalation and audit upload; `_audit_net_failures` resets per `--once`, so `audit_upload_failed` on network errors never fires there; `run_loop` `except SyncError: pass`; `clock_skew` audit record per poll per request (and it never calls `emit`, despite the D4.3 wording); unbounded `resp.read()`; server sends every row and the connector ignores `cursor`; `approval.py:678` returns before a valid deny can apply when verified state is missing (fails closed, contradicts the comment at 664); no recovery for a stuck `claimed` record. **Docs (lead):** `M3_PLAN.md` D5 and S10 "two bare returns" and the range `448-500` should read `448-516`, per section 1. A short ADR 0001 amendment should record that a decisions failure no longer stops later steps.

## 8. T9a test fixes (`tests/security/test_m3_t9a_fetch_decisions.py`)

**Measured with the sentinel neutralised, on today's code.** 7 of 12 target bodies PASS against the bug: `test_no_bare_return_in_except_paths`, `test_network_error_leaves_alert`, `test_http_403_leaves_alert`, `test_http_404_leaves_alert`, `test_http_500_leaves_alert`, `test_http_502_leaves_alert`, `test_non_counting_approval_shows_awaiting_second_in_status`. Only 5 fail for a real reason.

**File level:**

1. `_need()` becomes `require_m3(9, "decision_refused" in alerts._ALWAYS)`, returning early when env `M3_T9A_BODIES=1`. Before commit, run that env with `--runxfail` and paste the list: every target FAILS on today's code, every guard PASSES.
2. `_read_audit` returns `[]` always: records live in `audit/<session>/records.jsonl` and it only reads top-level files. Replace with `FolderAudit(lay.audit_dir, session_id="sync").list_records(limit=500)`.
3. Add `_assert_one(lay, event, code, status=None, rid=None)`: exactly one alert and one audit record with that event and `reason_code`, no other new decision-kind record. No `bool(alerts)`, no "raised OR evidence", no `"fail" in str(r)`.
4. Rows use the real server shape (`escalations.py:671-689`): `signature`, `key_id`, `signed_payload`, `request_id`, plus one node each for the `sig` and `payload`/`signatures` shapes.
5. Every status and alert assertion goes through `click.testing.CliRunner` on `status_cmd` and `alerts_cmd`, never the queue or a record dump.

| Node | Fix |
|---|---|
| `test_guard_two_bare_except_pass_blocks_exist_today` | **Delete.** It pins the bug (defect a) |
| `test_guard_demo_profile_exists_in_compose` | **Delete.** `c_tests.py` makes this file Class C, `connector-standalone` runs `rm -rf ee`, so it raises `FileNotFoundError` on both OSes (defect b). T5 has the twin |
| `test_no_bare_return_in_except_paths`, `test_no_bare_pass_in_except_paths` | Merge into `test_except_handlers_in_fetch_decisions_record_or_raise`: every handler in `_fetch_decisions` and any helper it factors out must contain a `Raise` or a call to `_decision_alert` or `_note_decisions_failure`. A log plus `return` then fails (defect e) |
| `test_network_error_leaves_alert` | Split: `test_network_error_cycles_1_2_no_alert_status_line`, `test_network_error_third_cycle_alerts_once`, `test_network_counter_survives_new_process` (new `SyncProcess` per cycle), `test_network_counter_reset_by_200`. Assert no raise |
| `test_http_403_leaves_alert` | `_assert_one(..., "decisions_fetch_failed", "token_forbidden", status=403)`; assert `_token_expires == 0` |
| `test_http_404_leaves_alert` | `http_4xx`, status 404 (defect c) |
| `test_http_500_leaves_alert`, `test_http_502_leaves_alert` | `http_5xx` with the status (defect c) |
| `test_malformed_json_leaves_alert` | Its stub returns a string, which the real transport never does for bad JSON. Drive `_default_connect` over a local HTTP server (pattern in `test_m2_t15b_transport.py`), `unparseable_body` |
| `test_non_object_body_leaves_alert` | `not_object_or_list`; parametrize `42`, `"x"`, `true` |
| `test_bad_signature_leaves_alert_and_pending` | Today's key is not in the registry, so it hits `unknown_key`. Split: `test_unknown_key_refused_with_reason` and `test_bad_signature_refused_with_reason` (registry key, signature XOR 0x01 with `assert new != old`). Assert the line says `claimed key` and no user name |
| `test_non_counting_approval_shows_awaiting_second_in_status` | Rewrite per the exit fixture below. Its `user_id="user-carol"` on an admin key is dropped at `user_mismatch`, and `awaiting_second` is the default return, so it never tests counting (defect d) |
| `test_non_counting_approval_shows_in_alerts` | Same fixture; `DECISION_REFUSED`, rid, `awaiting_second`, `not_dual_eligible` in `alerts_cmd` output |
| `test_guard_counting_approval_applies` | Assert `executed` or a named broker state; add the same through `_fetch_decisions` |
| `test_guard_fetch_decisions_function_exists`, `test_guard_sync_process_importable`, `test_guard_sync_error_importable`, `test_guard_apply_external_importable`, `test_guard_process_py_has_fetch_decisions` | Keep or drop; they prove little |

**Exit fixture.** Registry v1 alice admin; v2 adds carol as admin with one prior-admin signature; v3 adds bob as approver signed by alice and carol. Pending `requires_dual`. Carol's key signs with the registry's real user id. A `connect` stub serves the real row shape and the node calls `_fetch_decisions`, not `apply_external`. Assert in order: `apply_external` verdict stays pending; `status_cmd` line holds rid, `awaiting_second`, `not_dual_eligible` and carol's registry id; `alerts_cmd` as above; audit holds both `sync_decision_applied status=awaiting_second` and `decision_refused`.

**New nodes:**

- `test_exit_e2e_carol_admin_key_real_server`, in new `ee/tests/test_m3_t9a_e2e.py` (`pg`, real `SyncProcess` over HTTP): the server posts carol's approval and the connector shows the reason. The plan's test column needs this file added.
- `test_second_poll_writes_no_alert_or_audit`, `test_realert_after_one_hour_with_repeats`, `test_new_code_on_same_request_alerts`, `test_alert_cap_per_cycle_and_hour_with_one_suppressed_record`, `test_capped_key_fires_in_later_window`, `test_cap_does_not_affect_audit_fork`, `test_corrupt_state_file_means_more_alerts_not_fewer`.
- `test_one_bad_row_good_rows_still_apply`, parametrized over `row_not_object`, `request_id_invalid`, `payload_unusable`, `signature_missing`, non-object `signatures[0]`.
- `test_decisions_key_not_list_never_raises`, parametrized over `42`, `"abc"`, `{}`, `null`.
- `test_500_still_uploads_escalations_and_audit_then_raises`: later routes hit, `SyncError`, `_consecutive_failures == 1`.
- `test_revoked_token_route_401_alerts_stage_token`, `test_outage_at_registry_counts_toward_three`, `test_tls_verify_failure_alerts_immediately`.
- `test_apply_external_raises_alert_and_later_requests_apply`, `test_apply_raises_after_claim_status_says_inspect_and_no_retry`, `test_nonce_save_failed_alerts`, `test_pending_record_unreadable_alerts`.
- `test_done_request_rows_write_nothing_on_repeat_polls`, `test_unknown_request_rows_aggregate`.
- Parametrized over table 1 and table 2, each reachable code: `test_reason_code_reaches_status_and_alerts[code]`. Name any code unreachable through `_fetch_decisions` (`wrong_tag`, `no_registry`, `not_object`, `no_approvals_counted`) as direct `_verify_remote_approval` nodes or dead code.
- `test_server_text_capped_scrubbed_no_controls`: planted token-like value, control and bidi characters, 5 KB string. `test_non_string_detail_omitted`. `test_row_user_id_never_printed_when_unverified`. `test_no_token_in_any_record`.
- `test_audit_append_failure_still_alerts`, `test_alerts_disabled_still_audits`.
- Section 6 guards.

## 9. T5 test fixes (`ee/tests/test_m3_t5_pilot.py`)

Reviewed against ADR 0013, D4, S8 and T0B items 16, 17, F-5, F-9. Today 23 targets xfail on one sentinel and no body has run.

**Merged-config handling is wrong in five ways. Measured on the base file:**

1. **Profile filter.** `docker compose config` without `--profile` drops `keycloak`, `migrate-demo` and `init-secrets`. The base file alone passes `test_no_demo_service` and `test_no_admin_admin_credentials`. A pilot Keycloak behind a profile would vanish from every Keycloak assert too.
2. **Long-form volumes.** Output is `{type, source, target}`, so `str(v).split(":")` never yields a path.
3. **File list is guessed.** `glob("compose.pilot*.yml")` is not what `pilot.sh` passes, and T10's partner overlay would merge into the ACME path. F-9 needs proof the auto-loaded override is excluded.
4. **No inputs.** `up` needs a name and IdP settings; a required variable fails `config`, and that becomes `M3T5Pending`.
5. **`yaml`.** Neither pyproject lists PyYAML; on this laptop it comes through `huggingface_hub`. Use `--format json`.

**Ruling.** `pilot.sh up --dry-run --name <n> [idp flags]` (devops) prints the exact `-f` and `--profile` arguments and runs the offline preflight, with no network or side effects. `_merged()` runs that, then `docker compose <args> config --format json` with those inputs. `_adapted()` runs `caddy adapt` from the digest-pinned image over the Caddyfile the merged `proxy` mounts. Agree the seam before the tests-first commit.

**Sentinel.** Use `require_m3(5, _PILOT_SH.exists() and overlay_exists)` as in T1 and T3. After it passes, nothing raises `M3T5Pending`: a failed `config`, a missing realm or Caddyfile is `pytest.fail`. As written, those raises turn a real build failure into an xfail while markers are on. Affected: `_get_merged_pilot_config`, `_get_merged_pilot_config_raw`, `test_api_refuses_to_start_with_direct_publish_under_pilot`, `test_keycloak_admin_paths_unrouted_on_public_name`, `test_brute_force_protection_on`, `test_self_registration_off`, `test_keycloak_own_postgres_role_and_db`, `test_acme_adapted_config_has_no_internal_issuer`. Delete the Docker branch of `_need_pilot_config`.

**Non-vacuity, today.** Split each check into a pure function (`check_merged(cfg) -> list[str]`, `check_adapted`, `check_realm`, `check_ownership`). Add guard twins that PASS now: `test_checker_flags_base_compose` (base config must report `tls internal`, `ca-bundle`, `caddy-root-cert`, `SSL_CERT_FILE`, loopback ports, no profile) and `test_checker_accepts_good_literal`. Also `_assert_shape(cfg)`: `api`, `proxy`, `postgres`, `migrate` present, so an empty `services` cannot pass a loop.

| Node | Problem | Fix |
|---|---|---|
| `test_no_demo_service` | Vacuous (1) | Exact service allowlist from `_merged()`; args hold no `demo` profile |
| `test_no_admin_admin_credentials` | Vacuous (1); second assert redundant; misses `KC_BOOTSTRAP_ADMIN_*` | Parse env of every service; no literal admin password under any name |
| `test_no_tls_internal` | Vacuous (2): always reaches the `else` branch, so the base Caddyfile would pass | Follow `source` of the `/etc/caddy/Caddyfile` mount; assert over `_adapted()` |
| `test_no_agg_allow_direct_publish` | Sound, but passes on empty `services` | `_assert_shape`; the list branch is dead under JSON output |
| `test_init_secrets_ownership_table` | Hard-coded names miss new pilot secrets; passes today, so it is a guard | `ast.literal_eval` the `OWNERSHIP` dict; all 0o400 except exactly `oidc_client_secret` (65534, 30000, 0o440) |
| `test_only_api_and_keycloak_carry_gid_30000` | Subset check, so nobody carrying it passes; hides Keycloak (1); hard-codes the name | Set equality with the merged api and Keycloak service names |
| `test_api_has_deploy_profile_pilot` | `get("api", {})` hides absence; other env types pass | Require `api`; exact `== "pilot"` |
| `test_api_refuses_to_start_with_direct_publish_under_pilot` | Static grep; a comment passes; needs no Docker | Behavioural: `create_app` with the flag under `pilot`, unset, `""`, `Demo`, `"demo "` refuses; exactly `demo` starts |
| `test_api_refuses_flag_when_profile_not_demo` | `a and b and c or d`: any `raise` in `app.py` passes | Merge into the node above; route recheck stays with T4 |
| `test_default_path_api_has_no_ssl_cert_file` | ADR node. Absent `api` passes | Require `api`; also no `ca-bundle` dependency or mount |
| `test_default_path_mounts_no_partner_tls_files` | ADR node. Vacuous: the key is a compose **secret** and the public files sit in `pilot-tls/`; it scans volumes for one string | Check `services.*.secrets`, top-level `secrets`, every volume `source`, for `tls_partner` and `pilot-tls` |
| `test_keycloak_admin_paths_unrouted_on_public_name` | `"/admin" in content` passes a route that proxies it; a correct differently named file fails | Over `_adapted()`: those paths end in a refusal before any proxy handler, on every site including the IdP name (ADR open question 2). Path variants go on the VM exit |
| `test_brute_force_protection_on`, `test_self_registration_off` | Glob `*pilot*realm*` misses `realm-pilot.json`; a demo copy passes | Follow the merged import mount; add `test_pilot_realm_has_no_demo_users_or_localhost_redirects` (the demo realm holds three password users and a `localhost` redirect) |
| `test_keycloak_own_postgres_role_and_db` | `"postgres"` is always present; the conditional reads only the text after the last `GRANT`, which in `00-roles.sh` names `agg_app`, so a correct build can fail and a bad one pass | Static: merged `KC_DB` is postgres, own URL and user, not `agg`. Behavioural, `pg`: `test_keycloak_role_cannot_connect_to_agg`. `00-roles.sh` has no `REVOKE`, so Postgres' default `CONNECT` for `PUBLIC` must be revoked on `agg`, or "no grant on agg" holds only for objects inside it |
| `test_acme_path_refuses_caddy_local_names` | ADR node. Substrings: a comment passes; `\.home\.arpa` fails a correct build; IP and private address absent, though the ADR lists them | `--dry-run` parametrized: `localhost`, `*.localhost`, IP literals, `10.x`, `.local`, `.internal`, `.home.arpa`, private resolution through a dry-run-only flag; named refusal, non-zero; `pilot.example.com` accepted |
| `test_acme_adapted_config_has_no_internal_issuer` | ADR node. Not adapted, against its name and T0B item 17; `auto_https off` passes. Its docstring applies the partner path's `disable_certs` to ACME | Over `_adapted()`: every automation policy issuer is `acme` or `zerossl`, explicit, none `internal`; every subject is the public name. Correct the docstring |
| `test_preflight_never_falls_back_to_tls_internal` | A correct script that checks for the string fails; a bad one using a helper file passes. Docstring forbids a public-CA retry the ADR allows | Behavioural, PATH shims for `docker` and `caddy`, no certificate arrives: non-zero named refusal; no config written with an internal issuer |
| `test_pilot_sh_refuses_demo_profile` | `"demo"` and `"error"` are in any such script | Behavioural: `--profile demo`, `COMPOSE_PROFILES=demo`, `AGG_DEPLOY_PROFILE=demo` each refuse, and no `docker` shim call reaches `up` |
| `test_doctor_redaction_planted_fake_secret` | Plants nothing; `sed` matches "used" | Plant a pg URL with password, setup code, token, PEM block, file under `secrets/`, through shims; assert each absent |
| `test_doctor_redacts_pem_private_key` | A literal in a comment passes | Merge into the node above, multi-line PEM |
| `test_backup_refuses_plaintext` | `"age"` matches "image" and "usage" | Behavioural: no recipient, and a private key given as recipient, refuse; with shims, output starts with the age header and no plaintext file appears |
| `test_backup_key_never_on_vm` | `"public"` matches "public DNS name" | As above; `test_backup_restarts_api_on_every_exit_path` |
| `test_guard_demo_profile_has_keycloak`, `test_guard_demo_has_migrate_demo` | Text checks pass if the service leaves the profile | Parse the file: `profiles == ["demo"]` on each |
| `test_guard_init_secrets_oidc_is_0440` | First `or` branch can never match | Use `check_ownership` |

**Missing nodes (ADR 0013 Decision 2-5, T0B 16, 17, F-5, F-9):**

- `test_no_caddy_root_cert_or_ca_bundle`, `test_proxy_entrypoint_does_not_wait_for_local_root`, `test_proxy_healthcheck_has_no_insecure_flag`.
- `test_pilot_ports_replace_base_loopback`: compose merges port lists, so this is a real trap.
- `test_api_oidc_allow_hosts_is_exactly_idp_host`, `test_caddy_data_mounted_by_proxy_only`, `test_pilot_keeps_hsts_and_headers`.
- `test_keycloak_admin_password_from_secret_file` (0400, exported in the entrypoint, not in env).
- `test_merged_args_exclude_compose_override` and `test_guard_base_compose_has_no_flag_or_profile` (F-9).
- `test_partner_idp_switch_no_keycloak_no_gid_30000_secret_0400_uid_10001` (T0B item 16).
- `test_up_prints_setup_code_once`, `test_web_build_uses_npm_ci_ignore_scripts`, `test_up_named_refusal_when_name_does_not_resolve_here`.
- `test_upgrade_fails_closed_until_release_key_pinned`: T5 ships `upgrade`, but the signature path and key arrive at T10. Until then it must refuse.
- `test_restore_requires_recorded_sha256`.
- `test_pilot_docs_state_internet_facing_and_no_internal_only_claim` (F-5, `docs/PILOT.md`).
- `test_pilot_sh_is_lf_and_executable` and `bash -n`.

**Slice note.** Threat 43 and ADR 0013 item 2 put the start refusal in T5, while the plan's flag row is T4 (30 Nov). Ruling: the `create_app` check ships in T5; the 410 and the per-request recheck stay in T4. `app.py` has neither today.

**`skipif(not _HAS_DOCKER)` is wrong.**

- The docstring's premise fails: the Windows 2025 runner image lists Docker 29.7.2 and Compose 2.40.3, so `which("docker")` is likely true on `ee-windows` and the nodes would run there.
- It also over-gates static nodes, and on Linux a missing binary silently skips the gate; `junit_gate.py` lists skips and does not appear to fail on them (only its first 95 lines were read).
- Ruling: merged, adapted and `pilot.sh` nodes get `skipif(sys.platform == "win32", reason="pilot.sh targets a Linux VM; the ee job covers it")`. On Linux, `docker compose version` failing under `GITHUB_ACTIONS` is `pytest.fail`, and a skip only off CI. Static nodes get no marker.
- `caddy adapt` needs Linux containers, covered by the same rule. Laptop runs of these nodes go through a Linux container, as T0a did.

**`from ee.tests.m3_pending` import.** It works in CI by accident. Measured: `python -m pytest` and `python -m coverage run -m pytest` from the repo root collect it, since the root is on `sys.path`; plain `pytest` fails with `ModuleNotFoundError: No module named 'ee'`. It also loads a second module beside `tests.m3_pending`. Use `from .m3_pending import M3T5Pending, require_m3`, as all T1 and T3 files and every M2 file do.
