# M1 baseline (T0a) and per-task test counts

Author: qa-engineer, 18 Oct 2026. Written before any M1 fix commit (adoption-gate rule).

- **Frozen at:** `8f52679` (M0 done). `tests/`, `src/` and `pyproject.toml` are identical to the M0 gate commit `b87703e` (`git diff --stat` empty).
- **Companions:** `M1_FROZEN_MANIFEST.sha256` (all 61 tracked files under `tests/`, sha256 of the LF git blob), `M1_BASELINE_NODEIDS.txt` (679 ids), `M1_LINUX_SKIPS.txt` (21 ids).

## 1. Baseline figure per environment (Q7a)

| Environment | Collected / run | Passed | Skipped | Deselected | Source |
|---|---|---|---|---|---|
| Local Windows `.venv` | 679 | 678 | 1 (`test_environment_classification.py::test_symlink_to_restricted_file_is_restricted`, symlinks not permitted) | 0 | M0 gate run (`M0_GATE.md`), same tests |
| CI `windows-latest` | 679 | 679 | 0 (the symlink test runs on the hosted runner) | 0 | tests run 18 on `b87703e` (`M0_BASELINE.md` section 8) |
| CI `ubuntu-latest` | 674 | 653 | 21 (`M1_LINUX_SKIPS.txt`) | 5 (the named T12 deselects, `M0_BASELINE.md` section 7) | tests run 18 |

Measured again at `c22d8f4` (baseline + the T0c test file), local Windows: 697 collected, 684 passed, 12 xfailed, 1 skipped, 0 deselected = 679 baseline (678 + 1) + 18 T0c tests (6 + 12). The T0c file has since grown to 22 (section 3).

### Linux skip set (Q7b)
`M1_LINUX_SKIPS.txt` lists 21 node ids. **How it was derived:** the JUnit artifact needs a GitHub token, so I took every `skipif(not Windows)` / `os.name != "nt"` marker in `tests/` and expanded it against `--collect-only`:
- `test_t0_hotfix.py`: 13 (case variants);
- `test_containment.py`: 7 (case, 5 exotic Windows path forms, junction);
- `test_environment_classification.py`: 1 (`test_case_insensitive_on_windows`).

That is 21, equal to the measured Linux skip count (24 JUnit "skipped" at T1b-era runs minus 3 xfails; 21 at tests run 18). The symlink test is not in the list: it runs on Linux. **Open:** confirm by node id from CI. I've asked devops to have `junit_gate.py` print the skipped ids as a notice annotation (public API). Until then the gate compares the Linux skip **count** (21) and this derived set.

## 2. Frozen files and named exceptions

`M1_FROZEN_MANIFEST.sha256` must check OK at the M1 gate, except for these nodes. Each change is fixture or setup only, signed off by security-engineer by node id (`M1_PLAN.md`, Tests). QA checks each diff.

| File / node | Task | Change allowed | Sign-off |
|---|---|---|---|
| `tests/integration/test_api_connector.py` (`client` fixture) | T1 | Fixture lists `tmp_path` and its `empty` subfolder as roots; `test_status_404_without_sandbox` keeps 404 | security (REVIEW_M1) |
| `tests/security/test_dual_control.py::test_api_counts_as_one_reviewer` | T1 | +1 line: `SANDBOX_CONNECTOR_ROOTS` = `layout.root` | security |
| `tests/security/test_api_auth.py::test_approver_reaches_approver_and_agent_routes` | T1 | +1 line, same | security to confirm at T1 |
| `tests/unit/test_oversight.py::test_api_asks_for_a_reason_when_flagged` | T1 | +1 line, same | security |
| `tests/security/test_m0_routes.py` (`app` fixture), `tests/security/test_api_robustness.py::test_security_headers_on_every_response` | T1 | Fixture/setup only; R5 and SEC-04 byte-unchanged | security |
| `tests/unit/test_evidence.py::test_pack_layout_and_no_private_keys`, `::test_pinned_exporter_key`; `tests/conftest.py` (one autouse fixture setting only `SANDBOX_KEY_HOME`) | T2 | Point at the key home; line 127 keeps the no-seed-bytes check and adds >= 3 seeds | security (conditions a-d) |
| T1 landed (signed off: security-engineer): `tests/integration/test_api_connector.py` (`client` fixture), `tests/security/test_api_auth.py` (`client` fixture, because the app is built before the test body; covers R4), `tests/security/test_api_robustness.py` (`client` fixture), `tests/security/test_m0_routes.py` (`app` fixture), `tests/security/test_dual_control.py::test_api_counts_as_one_reviewer`, `tests/unit/test_oversight.py::test_api_asks_for_a_reason_when_flagged` | T1 | Setup lines only: `SANDBOX_CONNECTOR_ROOTS` set to the folder the test uses (connector fixture: `tmp_path` and `tmp_path/empty`). No assertion changed; R5 and SEC-04 byte-unchanged | signed off: security-engineer |
| `tests/security/test_t0_hotfix.py`: `test_sec04_agent_token_403_on_every_connector_route` -> `test_sec08_agent_token_403_on_every_connector_route`; `test_sec04_connector_approve_and_deny_are_covered` -> `test_sec08_connector_approve_and_deny_are_covered` | M1 bookkeeping | Label-only rename, assertions unchanged (SEC-04 was the wrong label; the finding is SEC-08 in `REVIEW_SECURITY.md`). One comment line also changed. Node ids updated in `M1_BASELINE_NODEIDS.txt`; collected count unchanged (1048); file re-hashed in `M1_FROZEN_MANIFEST.sha256` | founder-approved ("rename, u have the permission") |
| T1 fixture re-hashes (`81adc55`): `test_api_connector.py`, `test_api_auth.py`, `test_api_robustness.py`, `test_m0_routes.py`, `test_dual_control.py`, `test_oversight.py` | T1 | Listed in the T1 landed row above; new hashes recorded in `M1_FROZEN_MANIFEST.sha256`. The SEC-27/28 hotfix commits touched no other frozen file | signed off: security-engineer |
| `tests/unit/test_tool_governance.py::test_service_down_adds_no_scrutiny` -> `::test_service_down_escalates_and_is_audited`; `::test_no_governance_policy_changes_nothing` -> `::test_no_governance_policy_still_has_the_money_floor` | T0c | They asserted the SEC-23 fail-open bug (an allowlisted stripe refund not denied with the service down / with no governance policy). Now: service down gives deny + 1 pending + a `governance_unevaluated` audit naming the tool and `no_payments` (SEC-23 bug fix); no governance policy gives deny + 1 pending with MONEY_FLOOR, and the non-money LIST call is still not denied (ADR 0008 behaviour change). Renamed (old->new ids above, updated in `M1_BASELINE_NODEIDS.txt`); file re-hashed in `M1_FROZEN_MANIFEST.sha256` and `M0_C_MANIFEST.sha256` (`6bdebb318a42`); no other line of the file changed; landed with the fix | signed off: security-engineer |
| `tests/security/test_sec27_28_hook_hardening.py::test_mcp_server_matching_origin_starts` (new M1 test, not in the frozen manifest) | SEC-27 hotfix, CI fix | Test bug: the expected origin was the checkout's `src`, but the standalone CI jobs import `sandbox` from site-packages. It now expects `Path(sandbox.__file__).resolve().parents[1]`; assertion unchanged. 28/28 pass on Windows | founder-approved in chat ("Yes. Make both security-test edits ...") |
| `tests/security/test_m1_t2_key_home.py[type_percent_var]` (new M1 test, not in the frozen manifest) | T0f | Moved from RED (strict xfail) to GUARD_CASES, which asserts "never allow". On Linux it already escalates, so the xfail marker failed the run. The T0f lexer makes it escalate on every OS, so the move ships in the T0f commit together with `cat_tilde`. T2 must still deny it outright | founder-approved in chat (same message) |

| `tests/security/test_t0_hotfix.py::test_t0a_guard_plain_allowlisted_still_allow_classify[python -m pytest]` -> `[git log]`; `::test_t0a_guard_plain_allowlisted_still_pass_hook[python -m pytest]` -> `[git log]` | T0g | ADR 0009: `python -m pytest` escalates by default. In `PLAIN`, `"python -m pytest"` became `"git log"` (positive-control count unchanged at 5); the manifest line for `test_t0_hotfix.py` was re-hashed and `M1_BASELINE_NODEIDS.txt` renamed the two ids | security signs off by node id at T0g (founder-approved ADR 0009) |
| `tests/security/bypass_corpus.jsonl` cases `benign-009`, `benign-010` (not in the frozen manifest) | T0g | Moved from class `benign`/`allow` to `benign_unchanged`/`escalate` (workspace runner, ADR 0009); node ids unchanged. T0f per-class counts: benign 17 to 15 and benign_unchanged 8 to 10 in the 242-case corpus (allow 17 to 15) | same |

| `tests/unit/test_evidence.py::test_pack_layout_and_no_private_keys`, `::test_pinned_exporter_key`; `tests/conftest.py` | T2 (D2, ADR 0007) | As on the named list: both tests read seeds from the key home (`SANDBOX_KEY_HOME`), the first asserts it found 3 or more and keeps the no-seed-bytes check; conftest gains one autouse fixture that sets only `SANDBOX_KEY_HOME` to a per-test tmp dir. Manifest lines for both files re-hashed | security signs off by node id at T2 |
| `tests/security/test_m1_t2_key_home.py` (new M1 test, not in the frozen manifest) | T2 | The 18 strict xfail decorators (`RED_T2`) removed by the fix commit; assertions unchanged. 26/26 pass | n/a (the tests-first protocol) |

| `tests/unit/test_evidence.py::test_export_then_verify_passes`, `::test_pack_has_aiuc1_index_tied_to_records`, `::test_alerts_are_in_the_pack` | T3 | `key_pinned` audit + alert from `approve()` adds 2 records, 2 alerts, 1 session ("default"): sessions 2 -> 3, E015.4 audit_records 3 -> 5, alerts count 1 -> 3. Manifest line re-hashed | signed off: security-engineer |

Any other frozen test that fails: stop, list it, security decides.

## 3. New M1 tests, frozen per task (tests-first commits)

Each task's new tests are committed as strict xfail (`raises=<named exception>`) before the fix. The fix commit deletes only the decorator.

| Task | File | Tests | RED now (strict xfail) | Guards (pass now) | Committed |
|---|---|---|---|---|---|
| T0c SEC-23 | `tests/security/test_sec23_money_floor.py` | 22 | 15 | 7 | `c22d8f4`, `9ba777e` |
| T1 D1 | `tests/security/test_m1_t1_root_allowlist.py` | 21 | 0 (fix landed, markers removed) | 21 | tests first `de660f1`; fix in the T1 commit |
| T2 D2 | to come | | | | |
| T3 D3.1 | `tests/security/test_m1_t3_pins.py` | 22 | 15 | 7 | tests first (this commit) |
| T4 D3.2-4, SEC-24 | `tests/security/test_m1_t4_domains.py` | 22 | 15 | 7 | tests first (this commit) |
| T4b SEC-30, SEC-31 | `tests/security/test_m1_t4b_downgrade.py` | 14 | 10 | 4 | tests first (this commit) |
| T4c evidence legacy | `tests/security/test_m1_t4c_evidence_legacy.py` | 16 | 9 | 7 | tests first; +6 follow-ups (dual control per approval, export=verify, shared hash, intact-chain not_covered); suite 1668 passed, 1 skipped |
| T5 `ee/` skeleton | `tests/unit/test_m1_t5_standalone.py` (root) | 92 | 0 | 92 | tests first (this commit) |
| T5 `ee/` skeleton | `ee/tests/test_health.py` (ee) | 6 | 6 | 0 | tests first (this commit) |
| T5 `ee/` skeleton | `ee/tests/test_import_contract.py` (ee) | 4 | 4 | 0 | tests first (this commit) |
| T6 PG/Alembic | `ee/tests/test_t6_pg_harness.py` (ee) | 9 | 8 | 1 | tests first (this commit) |
| T6 clock lint | `ee/tests/test_t6_clock.py` (ee) | 9 | 2 | 7 | tests first (this commit) |
| T6 module-state lint | `ee/tests/test_t6_module_state.py` (ee) | 12 | 0 | 12 | tests first (this commit) |
| T6 CI-skip rule | `ee/tests/test_t6_ci_skip.py` (ee) | 2 | 0 | 2 | tests first (this commit) |

**N** (the Phase A count in the M1 gate) = the sum of this table's "Tests" column once T1-T4 are written; written here before any fix runs.

### T0f: N as it stands at the T0f commit (honest accounting)

- **Frozen tests-first (`84d515b`, before any fix ran):** the corpus of 242 cases plus 4 integrity guards = 246 tests in `tests/security/test_t0f_bypass_suite.py`, 75 strict xfail.
- **Added during security's review, each written failing first against the then-current source, but after the implementation existed:** 15 cases (12 `protected_path`, 3 `benign_unchanged`), then 168 cases (136 `git_flag_matrix`, 32 read-only git positives under `benign`), then 2 more positives (`--no-ext-diff`, `--no-textconv`). The corpus is now 427 cases and the suite file has 431 tests; `RED_TODAY` is empty.
- **`tests/security/test_t0f_lexer.py`: written alongside the implementation, so NOT frozen before the run.** It holds the 12 worst-case 32 KiB timing cases, the review items one by one, and the stale-pattern and `.git/**` tests.
- **Measured at the T0f commit:** full suite 1402 passed, 1 skipped, 16 xfailed; frozen-manifest tests are unchanged; the only edited existing test is `test_m1_t2_key_home.py` (founder-approved move). Per-class numbers: `docs/BYPASS_SUITE.md`.

### T0f corpus as frozen in `84d515b` (D0b as amended in `1f32e6b`)
Corpus size per class: glob_command_word 10, substitution 17, variable_command 12, eval_exec_source 24, interpreter_c 56, newline_continuation 12, quoting_split 20, alias_function 10, protected_path 40, sec25_residual 8, bounds 8, benign 17, benign_unchanged 8 = 242. Expected: 202 deny, 23 escalate (8 of them benign_unchanged), 17 allow. Rule: an unresolvable form with a deny fragment denies, otherwise escalates; the written-then-run / trap / renamed-copy forms escalate. RED today by class: alias_function 4, benign 3 (quoted mentions denied today, a false positive), benign_unchanged 2, bounds 7, glob_command_word 10, interpreter_c 19, newline_continuation 5, protected_path 3, quoting_split 5, sec25_residual 6, substitution 2, variable_command 9 = 75. The two 33 KiB cases run the hook in a child process with a 5 s limit because today's hook does not return within 60 s on them (the D0b.5 DoS). Full suite at this commit, local Windows: 926 passed, 1 skipped, 93 xfailed. Corpus file is `.jsonl` as in the plan; the test file name follows the QA brief (`test_t0f_bypass_suite.py`, not `test_bypass_suite.py`).

### T0g (ADR 0009)

`tests/security/test_t0g_runners.py`: 116 tests. The first 55 were written before the fix (54 failed, 1 positive control passed); 61 more were added in security's review passes, each failing first against the then-current code. Not frozen in the manifest. Connector node ids: 2 renamed, 0 removed.

### T2 (ADR 0007 section 1)

`tests/security/test_m1_t2_keys_extra.py`: 14 tests added with the fix (workspace id, key home inside the workspace or relative refused, `key_rotated` carries the retired key and the audit heads, `sandbox keys purge-legacy`, the agent cannot run `sandbox keys`, Write/Edit and recursive-search-from-above denies, `cd` into the key home). Not frozen in the manifest. Connector node ids: 0 renamed, 0 removed.

### T5 (`ee/` skeleton, ADR 0004)

**Root suite** (`tests/unit/test_m1_t5_standalone.py`): 92 tests, all passing (guards).
- 4 static grep tests: no `import agg_cp` / `from agg_cp` in `src/sandbox/`; 3 positive controls (planted import detected, bare import detected, comment ignored).
- 88 parametrized runtime-isolation tests: one per `sandbox` sub-module, imported in a subprocess with `agg_cp` blocked by a meta-path finder (``-I`` flag, ``PYTHONPATH=src/``).
- Not frozen in the manifest (new file). Connector node ids: 0 renamed, 0 removed.

**`ee/` suite** (`ee/tests/test_health.py`, `ee/tests/test_import_contract.py`): 10 tests, all strict xfail (`raises=EESkeletonOpen`).
- `test_health.py` (6): `/health` 200, JSON, `status` field; `/ready` exists, JSON, `status` field.
- `test_import_contract.py` (4): `lint-imports` contract passes; positive control flags planted violation; `ee/pyproject.toml` exists; `ee/LICENSE` mentions Elastic License.
- Frozen `ee/` node-id list (Q7c):
  ```
  ee/tests/test_health.py::test_health_returns_200
  ee/tests/test_health.py::test_health_returns_json
  ee/tests/test_health.py::test_health_has_status_field
  ee/tests/test_health.py::test_ready_route_exists
  ee/tests/test_health.py::test_ready_returns_json
  ee/tests/test_health.py::test_ready_has_status_field
  ee/tests/test_import_contract.py::test_import_linter_contract_passes
  ee/tests/test_import_contract.py::test_import_linter_positive_control_catches_violation
  ee/tests/test_import_contract.py::test_ee_package_has_pyproject
  ee/tests/test_import_contract.py::test_ee_has_license
  ```

**Full suite at this commit (local Windows):** 1760 passed, 1 skipped (symlink), 0 failed. The 92 T5 root-suite tests are included in the 1760. The 10 ee/ xfail tests are not in the root suite's `testpaths` and ran separately: 10 xfailed.

### T6 (Postgres + Alembic harness)

`ee/tests/test_t6_pg_harness.py`: 9 tests (8 strict xfail, 1 guard).
`ee/tests/test_t6_clock.py`: 9 tests (2 strict xfail, 7 guards/positive controls).
`ee/tests/test_t6_module_state.py`: 12 tests (0 strict xfail, 12 guards/positive controls).
`ee/tests/test_t6_ci_skip.py`: 2 tests (0 strict xfail, 2 guards).
`ee/tests/pg_image.py`: PG_IMAGE constant (digest single source, no tests in this file).
`ee/tests/conftest.py`: pg marker, pg_url fixture, CI-skip hook.

Total T6: 32 new tests (10 strict xfail, 22 guards/passing).
- PG_IMAGE digest: `sha256:ca0bd484cb98bf4b24eb1010e73fb3fcbd6714d240fbc1a10eea5b7dbecb641d`

Frozen `ee/` node-id list (T5 + T6, Q7c):
```
ee/tests/test_health.py::test_health_returns_200
ee/tests/test_health.py::test_health_returns_json
ee/tests/test_health.py::test_health_has_status_field
ee/tests/test_health.py::test_ready_route_exists
ee/tests/test_health.py::test_ready_returns_json
ee/tests/test_health.py::test_ready_has_status_field
ee/tests/test_import_contract.py::test_import_linter_contract_passes
ee/tests/test_import_contract.py::test_import_linter_positive_control_catches_violation
ee/tests/test_import_contract.py::test_ee_package_has_pyproject
ee/tests/test_import_contract.py::test_ee_has_license
ee/tests/test_t6_pg_harness.py::test_ci_workflow_pg_image_matches
ee/tests/test_t6_pg_harness.py::test_make_engine_select_1
ee/tests/test_t6_pg_harness.py::test_alembic_config_loadable
ee/tests/test_t6_pg_harness.py::test_alembic_round_trip
ee/tests/test_t6_pg_harness.py::test_alembic_every_revision_has_downgrade
ee/tests/test_t6_pg_harness.py::test_ready_200_when_db_reachable_and_at_head
ee/tests/test_t6_pg_harness.py::test_ready_503_behind_head
ee/tests/test_t6_pg_harness.py::test_ready_503_unreachable_db
ee/tests/test_t6_pg_harness.py::test_health_stays_200_without_db
ee/tests/test_t6_clock.py::test_no_clock_violations_in_agg_cp
ee/tests/test_t6_clock.py::test_positive_control_time_time_flagged
ee/tests/test_t6_clock.py::test_positive_control_from_datetime_now_flagged
ee/tests/test_t6_clock.py::test_positive_control_time_time_ns_flagged
ee/tests/test_t6_clock.py::test_positive_control_datetime_utcnow_flagged
ee/tests/test_t6_clock.py::test_positive_control_date_today_flagged
ee/tests/test_t6_clock.py::test_positive_control_from_time_import_time_flagged
ee/tests/test_t6_clock.py::test_clock_module_exists
ee/tests/test_t6_clock.py::test_system_clock_returns_utc
ee/tests/test_t6_module_state.py::test_no_module_level_mutable_state_in_agg_cp
ee/tests/test_t6_module_state.py::test_positive_control_empty_dict_flagged
ee/tests/test_t6_module_state.py::test_positive_control_defaultdict_flagged
ee/tests/test_t6_module_state.py::test_positive_control_list_literal_flagged
ee/tests/test_t6_module_state.py::test_positive_control_set_call_flagged
ee/tests/test_t6_module_state.py::test_positive_control_list_comprehension_flagged
ee/tests/test_t6_module_state.py::test_positive_control_tuple_allowed
ee/tests/test_t6_module_state.py::test_positive_control_frozenset_allowed
ee/tests/test_t6_module_state.py::test_positive_control_constant_allowed
ee/tests/test_t6_module_state.py::test_positive_control_collections_deque_flagged
ee/tests/test_t6_module_state.py::test_positive_control_counter_flagged
ee/tests/test_t6_module_state.py::test_positive_control_ordered_dict_flagged
ee/tests/test_t6_ci_skip.py::test_ci_skip_pg_is_failure
ee/tests/test_t6_ci_skip.py::test_non_ci_skip_pg_is_ok
```

**ee/ suite at this commit (local Windows):** 42 collected, 32 passed, 10 xfailed, 0 failed. The 10 xfailed are: 8 from test_t6_pg_harness.py (T6 code not yet built) and 2 from test_t6_clock.py (agg_cp.clock not yet built).

**Root suite at this commit (local Windows):** 1760 passed, 1 skipped (symlink), 0 failed -- unchanged from T5.
