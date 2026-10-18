# M0 baseline (T1) and frozen gate

Author: qa-engineer, 18 Oct 2026. Written before any M0 deletion (adoption-gate rule: the rule and the test set are frozen before the run).

- **Measured at:** `c411c35` (T0 hotfix `094302e` + `tests/security/test_t0_hotfix.py`), Windows 11, Python 3.12, repo `.venv`.
- **Frozen at (manifest and C list):** `c0d4912`. That is `c411c35` plus exactly one test change, the named exception below.
- Machine-readable companions: `M0_C_MANIFEST.sha256` (52 files at T1; 53 since T12, see section 7) and `M0_C_NODEIDS.txt` (645 node ids).

## 1. Measured counts

Command: `.venv\Scripts\python -m pytest -q -p no:logging --deselect tests/security/test_api_robustness.py::test_no_route_crashes_on_malformed_input`

| Run | Collected | Passed | Failed | Skipped | Deselected | Time |
|---|---|---|---|---|---|---|
| `c411c35`, full suite | 703 | **701** | 0 | **1** | **1** | 54 s |
| After T1b (4 new tests), measured | 707 | **702** (+ 3 xfailed: R3, R7, N1) | 0 | 1 | 1 | 60 s |

- Skip: `tests/unit/test_environment_classification.py::test_symlink_to_restricted_file_is_restricted` (line 250, "symlink creation not permitted").
- Deselected: `tests/security/test_api_robustness.py::test_no_route_crashes_on_malformed_input` (0xC0000005 in the e2b Windows Job Object path; back in the run from T4, with no deselect).
- `--collect-only -q`: 703 items. The junitxml of the run agrees: 701 passed, 1 skipped.
- The T1b run already contains the `c0d4912` env change in `test_posttooluse_fallback.py` (its 3 tests pass), so 702 = 701 + N2.
- 701 = 539 (pre-T0) + 162 (T0 file). Matches the frozen hotfix gate in `REVIEW_QA.md` section 8.

## 2. Classification (703 collected = A 26 + B 32 + C 645)

Founder answer to Q1 (17 Oct 2026): keep `anomaly/` and `audit/sink.py`; delete `rollback/`, `models/{messages,session,security}.py`, `crypto/tokens.py`, `api/websocket.py`. So `test_anomaly_detector.py` (5) and `test_audit_rehydration.py` (4) are C. No test imports `rollback/`, `models/security.py` or `models/session.py` except the A files.

### Class A: whole file deleted in T5 (4 files, 26 tests)
| File | Tests | Why |
|---|---|---|
| `tests/integration/test_pipeline.py` | 8 | imports `pipeline/`, `crypto.tokens`, `models.messages`, `models.session` |
| `tests/unit/test_message_models.py` | 8 | imports `models.messages` |
| `tests/unit/test_policy_engine.py` | 4 | imports `agents.policy_engine` |
| `tests/unit/test_request_evaluator.py` | 6 | imports `agents.request_evaluator` |

Node ids: exactly as listed in `M0_INVENTORY.md` section 2 "Class A node ids", minus the 5 `test_anomaly_detector.py` ids (now C). Verified against `--collect-only`.

`tests/conftest.py`: the `session_token` and `token_issuer` fixtures (lines 11-29) go with `crypto/tokens.py` in T5. Nothing else in conftest may change.

### Class B: files edited function by function (4 files, 32 tests)
| Node id | T4 action |
|---|---|
| `tests/security/test_api_auth.py::test_public_routes_need_no_token` | keep unchanged |
| `…::test_no_token_is_rejected` | rewrite R1 |
| `…::test_wrong_token_is_rejected` | rewrite R2 |
| `…::test_agent_can_submit_but_not_approve` | **delete**; replaced by R3 in `tests/security/test_m0_routes.py` (T1b) |
| `…::test_approver_reaches_approver_and_agent_routes` | rewrite R4 |
| `…::test_agent_cannot_install_or_remove_hooks` | delete (its property is in R7) |
| `…::test_websocket_needs_approver_token` | delete (websocket deleted) |
| `…::test_generated_tokens_differ`, `::test_non_loopback_bind_needs_explicit_tokens`, `::test_same_token_for_both_roles_is_refused` | keep unchanged (3) |
| `tests/security/test_api_robustness.py::test_no_route_crashes_on_malformed_input` | keep unchanged; must pass with no deselect |
| `…::test_schema_valid_bodies_with_junk_values_do_not_crash` | keep unchanged |
| `…::test_spawn_reaches_the_toolkit` | delete |
| `…::test_hook_connect_rejects_a_bad_workspace_without_leaking_paths` | delete |
| `…::test_paths_the_os_cannot_stat_are_a_400` | rewrite R5 (drop only the `/hook/connect` line) |
| `…::test_e2b_template_must_be_allowlisted` | delete |
| `…::test_unconfigured_redis_review_api_is_not_mounted` | delete (its property is in R7) |
| `…::test_security_headers_on_every_response` | rewrite R6 |
| `…::test_unexpected_errors_reveal_nothing` | keep unchanged |
| `tests/integration/test_api_connector.py::test_m1_routes_still_exist` | **delete**; replaced by R7 in `tests/security/test_m0_routes.py` (T1b) |
| `…::{test_status_404_without_sandbox, test_status_returns_triggers, test_pending_reflects_queue, test_approve_runs_and_finishes, test_deny_marks_denied, test_verify_valid_chain}` | keep unchanged (6) |
| `tests/unit/test_recorder_scan.py::{test_detects_created, test_detects_modified, test_detects_deleted, test_same_size_different_content_is_modified, test_ignore_dirs_pruned, test_modified_preserved_to_trash}` | T3: the import line only (6) |

B after M0: 24 kept in place (auth 7, robustness 5, api_connector 6, recorder_scan 6); 8 deleted.

### Class C: byte-identical (48 files, 645 tests)
Per file (tests): integration/test_connector_loop.py 1; integration/test_mcp_tools.py 4; security/test_dual_control.py 11; security/test_injection_detection.py 9; security/test_secret_scanning.py 7; **security/test_t0_hotfix.py 162**; unit/test_activity_log.py 2; unit/test_aiuc_gaps.py 23; unit/test_anomaly_detector.py 5; unit/test_audit.py 5; unit/test_audit_rehydration.py 4; unit/test_broker_cwd.py 4; unit/test_broker_kinds.py 3; unit/test_change_journal.py 5; unit/test_classify.py 15; unit/test_cli_connector.py 3; unit/test_cli_semantic.py 3; unit/test_command_actions.py 10; unit/test_containment.py 14; unit/test_environment_classification.py 69; unit/test_evidence.py 22; unit/test_exfil.py 18; unit/test_folder_audit.py 5; unit/test_folder_recorder.py 5; unit/test_governance.py 9; unit/test_hook_bad_input.py 21; unit/test_hook_eval.py 6; unit/test_hook_eval_m4.py 8; unit/test_identity.py 4; unit/test_install.py 4; unit/test_memory.py 7; unit/test_oversight.py 17; unit/test_path_access_dir.py 4; unit/test_policy.py 4; unit/test_policy_versioning.py 25; unit/test_posttooluse.py 4; unit/test_posttooluse_fallback.py 3; unit/test_queue.py 8; unit/test_redact.py 7; unit/test_risk.py 9; unit/test_semantic.py 27; unit/test_semantic_screen.py 19; unit/test_semantic_trust.py 5; unit/test_signing.py 7; unit/test_signing_connector.py 5; unit/test_student.py 11; unit/test_tool_governance.py 18; unit/test_verify_cmd.py 4.

The full node-id list is `M0_C_NODEIDS.txt` (645 lines, sorted).

**Watch item:** `test_t0_hotfix.py::test_sec04_agent_token_403_on_every_connector_route` is parametrized from the live OpenAPI spec (7 connector routes today). If T4 changes any `/api/v1/connector/*` route, the C node-id set changes and gate check 3 fails. That is intended: connector routes are not in M0's scope.

### Named exception: the one C file changed before the freeze
| File | sha256 (LF blob) | Reason | Sign-off |
|---|---|---|---|
| `tests/unit/test_posttooluse_fallback.py` | `a75f5de64c3130f133738a10529cf75f8aa7cc5f604ad91450b4d0b40e76ab90` | Pass SYSTEMDRIVE to the hook subprocess; stops `%SystemDrive%` cache DBs being written in the repo (T11 root cause); env only, assertions unchanged, nothing in `src` reads it. Committed by devops-engineer in `c0d4912`. | signed off: security-engineer |

The manifest is frozen at `c0d4912`, so it holds this file's post-fix hash. Its node ids (3) and outcomes are unchanged.

## 3. Frozen post-M0 gate (Windows)

**Re-frozen 18 Oct 2026 for T4's `test_ws_refused.py`, before backend's T4 run: 679 collected, 678 passed, 1 skipped (the symlink test), 0 deselected, 0 failed, 0 xfailed, 0 xpassed.** (Previous freeze, for T12: 678 / 677 / 1.) That is the T1 figure (673 / 672, re-derived from the real collected set and equal to `M0_PLAN.md` and `REVIEW_QA.md` section 2) plus the 5 OS-native twins added in T12 (section 7), which run and pass on Windows too.

| Bucket | Tests |
|---|---|
| C, unchanged | 645 |
| A, deleted | -26 |
| B kept in place (incl. R1, R2, R4, R5, R6 rewrites) | 24 |
| B deleted (5 legacy-only + the 2 replaced by R3/R7 + websocket) | -8 |
| New in T1b: R3, R7 (`tests/security/test_m0_routes.py`), N1, N2 (`tests/unit/test_m0_legacy_imports.py`) | 4 |
| New in T12: 5 OS-native twins (`tests/unit/test_outside_paths_native.py`) | 5 |
| New in T4: `tests/security/test_ws_refused.py` (1) | 1 |
| **Total** | **679** |

Reason for the T4 +1: security made T4's sign-off conditional on `tests/security/test_ws_refused.py`, one test. It checks that the auth middleware closes every WebSocket with code 1008 before accepting it, for no token, the agent token and the approver token. It replaces the deleted `test_api_auth.py::test_websocket_needs_approver_token`, so the WebSocket auth property keeps a test after `api/websocket.py` is removed.

Difference in shape from `REVIEW_QA.md` (not in the number): REVIEW_QA counted R3 and R7 as in-place rewrites of `test_agent_can_submit_but_not_approve` and `test_m1_routes_still_exist`. I wrote them as new tests in a new file instead, so the old tests keep guarding the legacy broker until T4 deletes it. T4 therefore **deletes** those 2 functions (B "auth 7" and "api_connector 6" above) rather than rewriting them. 645 + 24 + 4 = 673 either way; T12 adds 5 (678).

Interim expectations (Windows, so each step can be checked):
| After | Collected | Passed | xfailed | Skipped | Deselected |
|---|---|---|---|---|---|
| T1b (measured) | 707 | 702 | 3 (R3, R7, N1) | 1 | 1 |
| T12 (5 twins) | 712 | 707 | 3 | 1 | 1 |
| T3 | 712 | 707 | 3 | 1 | 1 |
| T4 (8 B deleted; R3/R7 decorators removed; + `test_ws_refused.py`) | 705 | 703 | 1 (N1) | 1 | 0 |
| T5 (26 A deleted; N1 decorator removed) | **679** | **678** | 0 | 1 | 0 |

**Linux:** the gate is T2's measured Linux figure plus 1 (`test_ws_refused.py`), with exactly the 5 named deselects in section 7 and nothing else deselected after T4. The twins and `test_ws_refused.py` must pass there. CI `windows-latest` likewise gets +1.

The xfails are `strict=True, raises=LegacyStillPresent`: any other failure fails the run, and a pass fails the run until the decorator is removed. So a legacy route or import left behind cannot hide: the gate requires 0 xfailed.

## 4. Proof that C is unchanged (gate item 1)

1. **Manifest.** `M0_C_MANIFEST.sha256` holds sha256 of the **LF git blob** of each of the 52 tracked files under `tests/` that are not A, not B and not `tests/conftest.py` (48 C test files + 4 `__init__.py`; `test_t0_hotfix.py` included). This checkout uses `core.autocrlf=true`, so Windows working-tree bytes are CRLF and would not match. Check:
   - Linux CI, or any LF checkout: `sha256sum -c docs/control-plane/M0_C_MANIFEST.sha256`
   - Windows (Git Bash), comparing against the committed blobs: `while read -r h p; do [ "$(git show HEAD:"$p" | sha256sum | cut -d' ' -f1)" = "$h" ] || echo "MISMATCH $p"; done < docs/control-plane/M0_C_MANIFEST.sha256` (prints nothing when all match). Measured at freeze: no mismatch. A plain `sha256sum -c` on this Windows checkout reports 35 FAILED, all CRLF-only (expected, not a change).
2. `git diff --stat c0d4912 HEAD -- $(cut -d' ' -f3 docs/control-plane/M0_C_MANIFEST.sha256)` is empty.
3. The C node ids from `--collect-only -q` equal `M0_C_NODEIDS.txt` exactly.
4. In the gate run's `--junitxml`, every id in `M0_C_NODEIDS.txt` is `passed`, except the symlink skip.
5. `git diff c0d4912 HEAD -- tests/conftest.py` removes only the `session_token` and `token_issuer` fixtures; `[tool.pytest.ini_options]` in `pyproject.toml` is unchanged (no new `addopts`, `--deselect`, `-k`, ignore).

Plus `git status --porcelain` shows nothing new after the run.

## 5. End-to-end scenario at baseline (`REVIEW_QA.md` section 4)

Run 18 Oct 2026 at `c411c35` (plus the uncommitted fallback env fix, which touches only a test), fresh venv `E:\caterpillar\jev-os\.cache\tmp\m0-venv` (`pip install E:\architecture-mcp`, no extras), semantic service down.

| Step | Ran | Baseline result |
|---|---|---|
| 1 Setup | yes | Install OK, `pip check` clean. `sandbox --help` lists init, watch, approve, verify, export-evidence, verify-evidence. **It also lists inspect-session, verify-audit, list-sessions** (expected at baseline; must be absent after T4). |
| 2 Demo folder | yes | `demo/live_setup.py --dir …\m0-e2e` creates `gateway-live-demo\invoice-service\`. Hooks are in `.claude\settings.local.json` (not `settings.json` as REVIEW_QA says) and point at `.sandbox\hooks\pretooluse.py`; no `sandbox_hook.py`, no `/api/v1/hook` URL. |
| 3 Deny, fail closed | yes | `preset edit-rules`: DENIED [WRITE_PROTECTED]. `preset write-outside`: DENIED [WRITE_OUTSIDE]. Invalid JSON into the PreToolUse stub: `permissionDecision: deny`, "unreadable hook input (fail-closed)". |
| 4 Escalate and approve | **no** | Needs an interactive `sandbox watch`; not cheap headless. Run at the T9 gate. |
| 5 Dual control | **no** | Same reason. Call demo scene 6 covers "same reviewer refused" (below). |
| 6 API | **no** | Covered by tests (`test_api_connector.py`, SEC-04, R3, R7); a live `sandbox serve` run is left to T9. |
| 7 Evidence | yes | `sandbox verify`: 1/1 chains valid (6 records). `export-evidence` then `verify-evidence`: OK (manifest signature, 9 file hashes, 0 decision records, 1 chain). Negative control (one byte flipped in `records.jsonl`): `verify` exit 1, "record content does not match its record_hash". |
| 8 Call demo, stray files | yes | `demo/call_demo.py --no-pause`: exit 0, scenes 0-12 all ran. Scene 2 ESCALATE (risk 55); scene 4 DENIED WRITE_OUTSIDE and WRITE_PROTECTED; scene 5 injection warning (student, p=0.98); scene 6 "refused: alice already approved this one" (dual control); scene 8 RATE_LIMIT at call 25 (30/60 s); scene 12 evidence "Decisions: 4 {'denied': 2, 'executed': 2} passing all checks: 4". `git status --porcelain` after steps 1-8: no new files in the repo. |

## 6. T1b tests (written before any deletion)

`tests/security/test_m0_routes.py` (R3, R7) and `tests/unit/test_m0_legacy_imports.py` (N1, N2), exactly as `REVIEW_QA.md` section 3 defines them. Each test asserts what holds today with plain asserts, then raises `LegacyStillPresent` for what only holds after T4/T5.

| Test | Status now | Why |
|---|---|---|
| R3 `test_r3_agent_token_cannot_decide_or_read` | xfail (RED) until T4 | `AGENT_ROUTES` is not `()`: broker/request, hook/evaluate, hook/audit and 6 `/e2b/v1` operations are agent-reachable. The parts that hold today pass as plain asserts: agent 403 on approve, deny, pending, audit, status; request still pending; no side-effect file, no done record, no `executed` audit line; agent 403 on every other non-public OpenAPI operation; positive control (approver approves, the command runs). |
| R7 `test_r7_only_health_and_connector_routes_exist` | xfail (RED) until T4 | Legacy paths are mounted (`/api/v1/agents/*`, `/broker/*`, `/hook/*`, `/e2b/v1/*`, `/launch*`, `/hitl-mem/*`, `/ws/events`, …). Plain asserts that hold today: `/health` 200, connector routes in OpenAPI, `/api/v1/hitl/pending` 404 and absent from OpenAPI, agent token cannot reach hook connect/disconnect. Legacy URLs are only requested once no legacy route is mounted (the e2b route crashes the interpreter). |
| N1 `test_n1_no_kept_module_imports_a_deleted_module` | xfail (RED) until T5 | 40 kept-to-deleted import edges in 3 kept modules: `sandbox.api.app` (routes, agents, pipeline, …), `sandbox.connector.recorder` (`launcher.recorder`, fixed by T3), `sandbox.crypto` (`__init__` re-exports `tokens`). |
| N2 `test_n2_connector_entry_points_load_no_legacy_package` | **passes now** | Contrary to REVIEW_QA's "RED until T3/T5": importing `hook_eval`, `mcp_server` and `cli.main` loads no `sandbox.{launcher,executor,pipeline,agents,hitl,containment}`, because `hook_eval` imports `connector.recorder` lazily inside functions. N1 sees that lazy edge. N2 stays a regression guard for the `__init__` edits in T3-T5. |

## 7. T12: Linux-only deselects (named exceptions) and their OS-native twins

On POSIX, 5 Class C tests use hard-coded Windows paths (`C:\Windows\evil.txt`, `C:\Users\dell\.ssh\id_rsa`, …). Those are relative names there, so they resolve inside the test folder and the outside-folder verdicts cannot hold. The C files stay byte-identical (manifest unchanged). `.github/workflows/tests.yml` deselects the 5 on `ubuntu-latest` only (committed by devops in `9731124`); Windows runs them with no deselection. Each is covered on both OSes by a twin in `tests/unit/test_outside_paths_native.py`, which asserts the same verdicts and reasons with an absolute path outside the folder on the running OS (POSIX: `/etc/evil.txt`, `/etc/hosts`, `/home/dell/notes.txt`, `/root/.ssh/id_rsa`; Windows: the originals' `C:\` paths). Each twin first asserts its path is absolute and outside the folder, so it cannot pass vacuously.

| Deselected on Linux only (Class C, unchanged) | Reason | Covered by twin | Sign-off |
|---|---|---|---|
| `tests/unit/test_classify.py::test_write_outside_folder_denied_by_default` | `C:\Windows\evil.txt` is an in-folder relative name on POSIX | `test_native_write_outside_folder_denied_by_default` | signed off: security-engineer |
| `tests/unit/test_classify.py::test_read_outside_folder_observed` | same (`C:\Windows\System32\drivers\etc\hosts`) | `test_native_read_outside_folder_observed` | signed off: security-engineer |
| `tests/unit/test_hook_eval_m4.py::test_read_outside_is_observed_not_blocked` | same | `test_native_read_outside_is_observed_not_blocked` | signed off: security-engineer |
| `tests/unit/test_hook_eval_m4.py::test_write_outside_denied_with_pointer` | same (`C:\Windows\evil.txt`) | `test_native_write_outside_denied_with_pointer` | signed off: security-engineer |
| `tests/unit/test_hook_eval_m4.py::test_risk_upgrades_sensitive_read_from_observe_to_escalate` | same (`C:\Users\dell\notes.txt`, `…\.ssh\id_rsa`) | `test_native_risk_upgrades_sensitive_read_from_observe_to_escalate` | signed off: security-engineer |

Verified on Windows: the 5 twins pass, and with a mutation that makes `classify.is_contained` always return True (every path "inside"), all 5 fail (write allowed, read allowed, no observe record, no deny). I did not run them on Linux locally (no Linux runtime on this box); Linux CI is the first Linux run.

Security sign-off (security-engineer, 18 Oct 2026) for the twin file at sha256 `497e6c72461958b5ed22b6b673891e875fbe7377b081243bb2c35d9acba785ca`, with 2 conditions:
1. The first ubuntu CI run must show all 5 twins **passed** (not skipped or deselected) in both the pytest job and the connector-standalone job; the JUnit counts go here. If any twin fails on Linux, the sign-off lapses and that is a finding, not something to deselect. **Status: met.** tests run 7 on `79f94e4` (https://github.com/Boredem125/architecture-mcp/actions/runs/39064316243), compared with run 6 on `9731124`: every job shows +5 run and +5 passed, 0 failed, and the same skipped count (the twin file has no skip calls), so all 5 twins passed in both ubuntu jobs (and on Windows). Counts are in section 8.
2. The twin file is frozen like Class C: it is added to `M0_C_MANIFEST.sha256` (now 53 lines). It is not counted in the 645 C node ids (`M0_C_NODEIDS.txt` is unchanged); its 5 ids are listed above.

## 8. CI counts measured by T2 (`tests.yml`, Python 3.12)

Source: the `junit_gate.py` notice annotations. JUnit "skipped" includes xfail. "Run" excludes deselected tests. Runs before T4 deselect the e2b crasher in every job; from T4 on nothing is deselected on Windows. Linux also deselects the 5 named tests in section 7.

| Run (commit) | pytest Linux | pytest Windows | connector Linux | connector Windows |
|---|---|---|---|---|
| tests 6 (`9731124`), [39064037272](https://github.com/Boredem125/architecture-mcp/actions/runs/39064037272) | 701 run: 677 passed, 24 skipped | 706 run: 703 passed, 3 skipped | 644 run: 620 passed, 24 skipped | 649 run: 646 passed, 3 skipped |
| tests 7 (`79f94e4`, + T12 twins), [39064316243](https://github.com/Boredem125/architecture-mcp/actions/runs/39064316243) | 706 run: 682 passed, 24 skipped | 711 run: 708 passed, 3 skipped | 649 run: 625 passed, 24 skipped | 654 run: 651 passed, 3 skipped |
| tests 18 (`b87703e`, post-M0: T4, T5, T6 done, no crasher deselect), [39085316526](https://github.com/Boredem125/architecture-mcp/actions/runs/39085316526) | 674 run: 653 passed, 21 skipped | 679 run: 679 passed, 0 skipped | 650 run: 629 passed, 21 skipped | 655 run: 655 passed, 0 skipped |

All runs had 0 failed and 0 errors, and the stray-file check passed on every job. Linux skips 21 more than Windows (24 vs 3, xfail included). I measured that figure; I did not break it down by test, because job logs and JUnit artifacts need a GitHub token. The skip reasons are in the uploaded `junit-pytest-Linux` artifact. The C manifest check (`sha256sum -c`, Linux) passed.

Post-M0 (tests 18): Windows CI ran all 679 with 0 skipped, because the symlink test runs on the hosted runner. On this dev box it is 678 passed and 1 skipped (fresh venv, T6b). Linux runs 674, which is the 679 minus the 5 named T12 deselects.
