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
| `tests/unit/test_tool_governance.py::test_service_down_adds_no_scrutiny` -> `::test_service_down_escalates_and_is_audited`; `::test_no_governance_policy_changes_nothing` -> `::test_no_governance_policy_still_has_the_money_floor` | T0c | They asserted the SEC-23 fail-open bug (an allowlisted stripe refund not denied with the service down / with no governance policy). Now: service down gives deny + 1 pending + a `governance_unevaluated` audit naming the tool and `no_payments` (SEC-23 bug fix); no governance policy gives deny + 1 pending with MONEY_FLOOR, and the non-money LIST call is still not denied (ADR 0008 behaviour change). Renamed (old->new ids above, updated in `M1_BASELINE_NODEIDS.txt`); file re-hashed in `M1_FROZEN_MANIFEST.sha256` and `M0_C_MANIFEST.sha256` (`6bdebb318a42`); no other line of the file changed; landed with the fix | signed off: security-engineer |

Any other frozen test that fails: stop, list it, security decides.

## 3. New M1 tests, frozen per task (tests-first commits)

Each task's new tests are committed as strict xfail (`raises=<named exception>`) before the fix. The fix commit deletes only the decorator.

| Task | File | Tests | RED now (strict xfail) | Guards (pass now) | Committed |
|---|---|---|---|---|---|
| T0c SEC-23 | `tests/security/test_sec23_money_floor.py` | 22 | 15 | 7 | `c22d8f4`, `9ba777e` |
| T1 D1 | to come | | | | |
| T2 D2 | to come | | | | |
| T3 D3.1 | to come | | | | |
| T4 D3.2-4, SEC-24 | to come | | | | |

**N** (the Phase A count in the M1 gate) = the sum of this table's "Tests" column once T1-T4 are written; written here before any fix runs.
