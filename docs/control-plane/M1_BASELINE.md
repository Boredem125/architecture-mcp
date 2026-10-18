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

Any other frozen test that fails: stop, list it, security decides.

## 3. New M1 tests, frozen per task (tests-first commits)

Each task's new tests are committed as strict xfail (`raises=<named exception>`) before the fix. The fix commit deletes only the decorator.

| Task | File | Tests | RED now (strict xfail) | Guards (pass now) | Committed |
|---|---|---|---|---|---|
| T0c SEC-23 | `tests/security/test_sec23_money_floor.py` | 22 | 15 | 7 | `c22d8f4`, `9ba777e` |
| T1 D1 | `tests/security/test_m1_t1_root_allowlist.py` | 21 | 0 (fix landed, markers removed) | 21 | tests first `de660f1`; fix in the T1 commit |
| T2 D2 | to come | | | | |
| T3 D3.1 | to come | | | | |
| T4 D3.2-4, SEC-24 | to come | | | | |

**N** (the Phase A count in the M1 gate) = the sum of this table's "Tests" column once T1-T4 are written; written here before any fix runs.

### T0f corpus (frozen before any fix; D0b as amended in `1f32e6b`)
Corpus size per class: glob_command_word 10, substitution 17, variable_command 12, eval_exec_source 24, interpreter_c 56, newline_continuation 12, quoting_split 20, alias_function 10, protected_path 40, sec25_residual 8, bounds 8, benign 17, benign_unchanged 8 = 242. Expected: 202 deny, 23 escalate (8 of them benign_unchanged), 17 allow. Rule: an unresolvable form with a deny fragment denies, otherwise escalates; the written-then-run / trap / renamed-copy forms escalate. RED today by class: alias_function 4, benign 3 (quoted mentions denied today, a false positive), benign_unchanged 2, bounds 7, glob_command_word 10, interpreter_c 19, newline_continuation 5, protected_path 3, quoting_split 5, sec25_residual 6, substitution 2, variable_command 9 = 75. The two 33 KiB cases run the hook in a child process with a 5 s limit because today's hook does not return within 60 s on them (the D0b.5 DoS). Full suite at this commit, local Windows: 926 passed, 1 skipped, 93 xfailed. Corpus file is `.jsonl` as in the plan; the test file name follows the QA brief (`test_t0f_bypass_suite.py`, not `test_bypass_suite.py`).
