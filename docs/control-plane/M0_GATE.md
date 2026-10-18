# M0 gate run (T9)

Author: qa-engineer, 18 Oct 2026. Run once at `b87703e` (M0 code complete; `bfd3539` on top is docs only), against the gate frozen in `M0_PLAN.md` and re-frozen in `M0_BASELINE.md` section 3 (679 / 678 / 1, Windows). Reported as measured.

## Result

| # | Gate item | Result | Evidence |
|---|---|---|---|
| 1 | Tests, no deselect, frozen count | **PASS** | Local Windows `.venv`, `pytest -q -p no:logging` with **no `--deselect`**: **679 collected, 678 passed, 1 skipped (symlink), 0 failed, 0 xfailed, 0 xpassed, 0 deselected**, 52 s. The e2b crasher `test_no_route_crashes_on_malformed_input` ran and **passed**. |
| 1.1 | C manifest | **PASS** | All 53 lines match the committed blobs at HEAD (Windows blob check; CI runs `sha256sum -c` on Linux). |
| 1.2 | C diff | **PASS** | `git diff --stat c0d4912 HEAD` over the 52 T1 C files is empty; the T12 twin file is unchanged since `79f94e4`. |
| 1.3 | C node ids | **PASS** | The C ids in `--collect-only` equal `M0_C_NODEIDS.txt` exactly (645 = 645, none missing, none extra). |
| 1.4 | C outcomes | **PASS** | In the gate junitxml, 644 C ids passed and 1 skipped (the symlink test); none failed or missing. |
| 1.5 | conftest and pytest options | **PASS** | `tests/conftest.py`: only `session_token` and `token_issuer` were removed. `[tool.pytest.ini_options]` is unchanged (testpaths, asyncio_mode, timeout = 30). |
| 1.6 | No stray files | **PASS** | `git status --porcelain` is empty after the suite, the E2E run, `sandbox serve`, the presets and the call demo. |
| 2 | SEC-01 / SEC-02 closed | **PASS (tests); security confirmation PENDING (T8)** | All 162 `test_t0_hotfix.py` cases pass, including approver-CLI deny in any shell segment. There is no `M0_SECURITY_SIGNOFF.md` yet. |
| 3 | CI green | **PASS** | On `b87703e`: tests run 18 (success), security run 63 (success: Semgrep, Gitleaks, Trivy, ZAP), image run 7 (success); same on `bfd3539` (tests 19, security 64, image 8). Source: GitHub Actions public API, which gives conclusions only. Per-OS counts are in `M0_BASELINE.md` section 8: Windows 679 run, 679 passed (the symlink test runs on the hosted runner); Linux 674 run, 653 passed, 21 skipped (679 minus the 5 named T12 deselects). I did not read ZAP's alert list (it needs a token); "green" here is the workflow conclusion. |
| 4 | Connector standalone, fresh E: venv | **PASS, with a deviation** | `pip install E:\architecture-mcp` (no extras) into `E:\…\tmp\m0-gate-venv`: `pip check` clean. `sandbox init` and `status` work. A shell call escalates; it was approved with **`sandbox approve`, not `watch`** (headless). `verify`, `export-evidence` and `verify-evidence` pass. |
| 5 | Demos | **PASS, with a finding (not a regression)** | `call_demo.py --no-pause`: exit 0, scenes 0-12; normalized output identical to the T1 baseline run (only paths and random ids differ). `live_setup.py` and all 9 `try.py` presets ran (table below). |
| 6 | Security sign-off (T8) and founder approval | **PENDING** | Not done at the time of this run. |

## E2E scenario (`REVIEW_QA.md` section 4), at the gate

Fresh venv `m0-gate-venv`; demo folder `E:\caterpillar\jev-os\.cache\tmp\m0-gate-e2e` (new, empty; scripts use `$ErrorActionPreference='Stop'` and check `cd`); semantic (jev-os) service down, as at baseline.

| Step | Result | Same as baseline? |
|---|---|---|
| 1 Setup | Install OK. `sandbox --help` lists init, watch, approve, verify, export-evidence, verify-evidence, and **no longer** lists inspect-session, verify-audit or list-sessions. | Changed as intended (T4) |
| 2 Demo folder | `invoice-service/` created. Hooks in `.claude\settings.local.json` point at `.sandbox\hooks\pretooluse.py`; no `sandbox_hook.py`, no `/api/v1/hook`. | Yes |
| 3 Deny, fail closed | `edit-rules` DENIED [WRITE_PROTECTED]; `write-outside` DENIED [WRITE_OUTSIDE]; invalid JSON into the stub gives `deny` "unreadable hook input (fail-closed)". | Yes |
| 4 Escalate, approve / deny | `leak-customers`: pending, then `sandbox approve --reviewer alice`; the broker ran it outside the agent (curl exit 26, host `.invalid`), and the agent was told "A human approved it". `steal-env`: pending, then `sandbox deny`; the agent was told "a human denied this command"; never ran. | Not run at baseline (needed `watch`); deviation: `approve`/`deny` instead of `watch` |
| 5 Dual control | **Could not run as written.** `move-more-money` (`mcp__stripe__create_transfer`, 9,000,000) is **allowed** with no escalation. Cause: `live_setup.py` puts `stripe` in `network.allow_mcp_servers`, and the money-moving governance clause needs the semantic service, which is down. I re-ran the same preset with the **T1 baseline package** (`m0-venv`, `c411c35`) on a fresh folder: also allowed. So it is **not an M0 regression**. Dual control itself is covered by call-demo scene 6 ("refused: alice already approved this one") and `test_dual_control.py` (11 pass). | Pre-existing behaviour |
| 6 API | Real `sandbox serve --host 127.0.0.1 --port 8765`: `/health` 200; `/api/v1/connector/status?root=<demo>` 200 with the approver token, 403 with the agent token, 401 with no token; `/api/v1/launch` 404. The server was stopped afterwards (port free). | Not run at baseline |
| 7 Evidence | `verify` 1/1 chain valid (11 records). `export-evidence` then `verify-evidence`: OK (manifest signature, 11 file hashes, 2 decision records, 1 chain). One byte flipped in `records.jsonl`: `verify` exit 1, "record content does not match its record_hash". | Yes |
| 8 Call demo, stray files | Scenes 0-12, exit 0. Scene 2 escalate and approve; 3 secret replaced; 4 two denies; 5 injection warning (p=0.98); 6 dual control refusal; 8 RATE_LIMIT at call 25; 9 policy change: alice's self-approval refused, bob approves; 12 "Decisions: 4 {'denied': 2, 'executed': 2} passing all checks: 4". `git status --porcelain` empty. | Yes (normalized diff empty) |

### `try.py` presets (live_setup folder, semantic down)

| Preset | Result |
|---|---|
| edit-rules | DENIED [WRITE_PROTECTED] |
| write-outside | DENIED [WRITE_OUTSIDE] |
| steal-env | escalated; denied with `sandbox deny`; never ran |
| steal-env-python | escalated; denied with `sandbox deny`; never ran |
| leak-customers | escalated; approved by alice; run by the broker (exit 26) |
| print-secrets | escalated; approved by alice; output shows `PAYMENTS_API_KEY=[SECRET_1]` (scrubbed) |
| read-poison | allowed, then the PostToolUse warning (student, p=0.98) |
| move-money | **allowed** (stripe allowlisted; governance needs semantic; same at baseline) |
| move-more-money | **allowed** (same cause; same at baseline) |

## Findings for the lead and security (not M0 regressions)

1. **Money-moving MCP calls are allowed when jev-os is down, in the demo configuration.** `live_setup.py` allowlists the `stripe` MCP server, and the only extra scrutiny for money movement is the governance clause, which runs only when the semantic service is up. In a live demo without jev-os, "move $90,000" goes straight through. This matches the documented design ("models may only add scrutiny"; `M0_INVENTORY.md` section 5). But the demo script and REVIEW_QA step 5 assume an escalation. Options: start jev-os for live demos, or don't allowlist `stripe` in `live_setup.py` (then the network trigger escalates). The decision belongs to the lead and security.
2. Note, not a finding: `pip install .` still installs `PyJWT` and `cryptography`. `pyjwt>=2.14.0` is kept on purpose in `pyproject.toml` as a CVE floor for `mcp`'s `pyjwt[crypto]`, and `cryptography` comes in through that extra. `aiofiles` stays on purpose (`audit/sink.py`).
