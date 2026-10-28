# Architecture review of docs/PM_DISTRIBUTION_ASSESSMENT.md

Author: lead-architect (Opus 5.5). Date: 28 Oct 2026. Status: ruling for the founder. Nothing in T12B_PLAN.md, RESUME.md or HANDOFF.md changes until the founder approves.

**Verdict: CONFIRM WITH AMENDMENTS.**

The direction is right: security is the moat, the bypass suite is the 90-day bet, and the governance items get paused. I confirm keeping c2, c6, extra tests 6 and 7, T16 scene 5(d) and step 11. I confirm pausing the OCSF export, SENTRY #1 and the AIUC-1 work. Four parts are technically wrong and are amended below:
1. **The T12d "happy path only" cut.** It cannot produce a working dual-control registry. It also removes the only way to revoke a key.
2. **The c5 pause.** The panel is mostly built already, it follows a founder ruling, and the fallback costs the same.
3. **The suite effort.** The PM sizes it as "80% built, 2 weeks". It is about 15 working days of new harness work, and the existing corpus is not tool-neutral.
4. **Several moat claims.** They overstate content binding, shell parity and TOCTOU (section 5).

Assumptions (the founder was not available):
- **Agent-team days.** All sizes are in agent-team working days at the 26-28 Oct pace, with leader reviews included.
- **Unverified tree state.** The uncommitted c2, c5 and d2 work in the tree is taken at face value where I did not run it. I ran only the connector T12c and bypass files (see section 1).
- **External tools.** Claude Code and Cursor behaviour is assumed from my knowledge up to mid-2026. Each assumption is checked in a 0.5-day spike before its adapter is built.

## 1. Evidence used

- **Working tree (28 Oct, uncommitted).**
  - c2 is nearly done. `src/sandbox/connector/script_pin.py` is 1061 lines, and there are diffs in broker, approval, hook_eval, install and privilege_broker.
  - I ran `test_m2_script_binding.py`, `test_m2_t12c_nf1.py` and `test_t0f_bypass_suite.py` locally: **505 passed, 2 skipped, 1 failed** (`test_extra13_init_refuses_system32_and_windowsapps`). The failure is a path-assertion issue in the test fixture.
  - d2 server work is in the tree: `ee/src/agg_cp/sync/signer.py` +572, `migrate.py` +118, and migration `0014_setup_codes_purpose.py`. I did not run it (pg).
  - The c5 web panel is in the tree: InboxSection.tsx, inbox.ts and escalation-rules.ts, +140 lines with the WebCrypto hash gate. Vitest was not run by me.
- **Corpus profile** (`tests/security/bypass_corpus.jsonl`, measured):
  - 427 cases: 383 bash, 26 pwsh, 18 cmd.
  - **205 of 427 (48%) target our own CLI or state** (`sandbox approve`, `.sandbox`, `propose`, `state/keys`).
  - 136 are `git_flag_matrix` cases that encode our read-only git allowlist.
  - The expected verdicts are in our vocabulary (deny / escalate / allow under `default_policy()`), checked through `classify()` and our hook.
- **Frozen demo step 2** (M2_BASELINE section 6) needs genesis, v2 (carol admin), v3 (bob and carol browser keys, signed by both admins), the N1 check and a refused threshold-1 v4. Step 5 needs bob and carol in the registry.
- **ADR 0010 s8 consequence.** "The T12b end-to-end test must get its server keys only by publishing signed registry versions, never by direct INSERT."

## 2. PM scope items, one by one

| # | PM item | Technically sound? | What it breaks if done as written | Cost: pause vs finish | Ruling |
|---|---|---|---|---|---|
| 1 | Accelerate T12c c2 (content binding + NF-1) | Yes | Nothing | Finish: about 1.5 d (one failing test, full suites on Windows and Linux, leader-tier TCB review). Pausing would leave 1,800 uncommitted TCB lines and NF-1 (High) open | **Confirm.** First on the critical path |
| 2 | c6 e2e script-swap, incl. extra tests 6 and 7 | Yes, but tests 6 and 7 were never paused in the current plan; only Appendix A paused them. They are already written in c1 (part of the 74) | Nothing | No extra cost; c6 is 1.5 d | **Confirm.** Correct the claim that they prove the "TOCTOU window closed on each OS": POSIX is detected after the run, not prevented (ADR 0010 s9 S-L4) |
| 3 | T16 scene 5(d) + the SCRIPT_UNPINNABLE retry measure | Yes. It is already a founder ruling (25 Oct T16 notes) | Nothing | Inside T16 | **Confirm** |
| 4 | Extend the corpus with 2026 CVE patterns + a cross-tool harness, "small, before T17" | Direction sound; size and placement wrong. The CVE patterns are repo fixtures and scenarios, not command strings. The harness does not exist. Native tools need the LLM in the loop | Placed "before T17", it would block the M2 gate on about 15 d of non-M2 work | About 15 d (section 3) | **Amend.** Separate lane X0-X9, parallel to M2, never gating T16/T17 |
| 5 | T12d happy path only (genesis + second-genesis refusal; candidates route and migrate.py code rules wait) | **No.** Genesis holds exactly one key (ADR 0011 2.4). Without d2 candidates, d3 `sign-registry` and the own-key publish rule, no second human can enter the registry through routes, so dual control (step 5, scene 5(d)) cannot run on a real stack. `migrate.py` emitting the code *is* the genesis code source, so the happy path cannot run without it either | Frozen demo steps 2 and 5; the ADR 0010 s8 no-direct-INSERT rule and the d4 grep test; M2 exit. It also leaves no CLI to publish v2+, so **no key can be revoked** (revocation = absent from the latest version) | Pause: 58 strict xfails (42 ee + 16 CLI) stay RED, d2's 572 built lines go stale, and M2 cannot exit. Finish: about 5.5 d | **Reject.** Finish d2-d5 (section 4) |
| 6 | Step 11 offline evidence verify | Yes. It is a frozen demo step | Nothing | Inside T16 | **Confirm.** Pitch it as tamper detection plus per-approver signatures; the AIUC-1 index stays in the pack |
| 7 | Pause c5 web script panel; ship "approve in CLI" | Sound as a fallback (ADR 0010 s9.5 allows it), but a poor trade. The panel is about 80% built in the tree. The founder ruled on 25 Oct that "Web inbox shows the full script body". The fallback still needs code (disable Approve for script rows) and a rewrite of the 6 `it.fails` tests | Contradicts founder ruling 7 (HANDOFF) | Pause: about 0.5 d of fallback code and test churn. Finish: about 0.5 d (vitest, lint, one worker review) | **Amend: finish c5.** Pausing saves nothing and needs the founder to reverse their ruling (question 1) |
| 8 | Pause JSONL/OCSF export (SENTRY #4) back to M4 | Yes. It was already M4 in SENTRY_IDEAS; only Appendix A pulled it forward | Nothing | 0 | **Confirm** |
| 9 | Pause SENTRY #1 (policy advisor) and the AIUC-1 / COMPLIANCE_MAP updates | Yes, for new mapping work | Do not delete anything: `tests/unit/test_aiuc_gaps.py` and the pack's AIUC-1 index must stay green as c2 adds evidence fields | 0 | **Confirm**, with the existing map tests kept green. STARTUP.md wedge item 4 still sells "AIUC-1-mapped packs"; update it after approval |
| 10 | Pause M3 planning except same-user / custody and Cursor/Codex adapters | Yes | Nothing | 0 | **Confirm.** Same-user is amended in section 5: it becomes the M3 exit item, not just a note. Cursor adapter: M3 (about 5 d). Codex: a 1 d spike first (its hook surface is uncertain) |
| 11 | Leader-tier security review for TCB files only; worker tier for web, routes and migrations | Mostly | The d2 genesis route and the `pending_link` scope rule are identity and keys (ADR 0011; TEAM.md requires security on keys). The c4 approvals-route equality check is part of the signed-field binding | - | **Amend:** leader tier also for d2 (genesis, scope rule) and c4's approvals-route check. Worker tier for c5 web, migrations and demo.py |

## 3. Amended T12c / T12d / T16 / T17 table (order = critical path first)

T12c's migration is **0015**, because the in-tree d2 file has already taken 0014. The c3 and d3 tasks share `cli/sync_cmds.py` and run one after the other (QA ruling h).

| Order | ID | Task | Owner (tier) | After | Size (d) | Done when |
|---|---|---|---|---|---|---|
| 1 | c2 | Finish the connector core in the tree. Fix `test_extra13_init_refuses_system32_and_windowsapps` in product code or by a named test edit approved by security, never by weakening it | backend (W), security (L) | c1 | 1.5 | Markers removed; NF-1 tests pass; connector suite green on Windows and Linux CI; security L APPROVE |
| 1' | c4 | Server: migration 0015, preview cap (reject, never truncate), M4 equality on the 3 payload fields, GET fields | backend (W), security (L for the approvals-route check) | c1 | 1 | ee c1 tests pass (pg) |
| 1'' | d2 | Finish the server in the tree: genesis route, scope rule, candidates, own-key publish, `migrate.py` code rules | backend (W), security (L) | d1 | 1.5 | 42 ee genesis tests pass (pg); security L APPROVE |
| 2 | c3 | Upload fields, CLI signer display and body-hash check, local approve display | backend (W) | c2 | 1 | Tests pass; security W review |
| 3 | d3 | CLI `signer link`, `genesis`, `sign-registry` (byte diff D0-3, typed key_id, N1); fix `build_genesis` user_id and roles | backend (W), security (L) | c3, d1 | 2 | 16 CLI tests pass; full suite green |
| 3' | c5 | Finish the web script panel in the tree | frontend (W) | c4 | 0.5 | 6 vitest flip to pass; lint and build pass; CSP unchanged |
| 4 | c6 | E2E script swap after web and CLI approvals; record both OS results | qa (W), security (W) | c2-c5 | 1.5 | ADR 0010 s9 exit check; CI green |
| 5 | d4 | demo.py step 2 through routes; move `ee/tests/test_m2_t12b_e2e.py` to the routes; grep test | qa (W), backend (W) | d2, d3 | 1.5 | Step 2 PASS incl. negatives on the compose stack |
| 6 | d5 | Semgrep, gitleaks, per-task commits | security (W), git-ops | d2-d4 | 0.5 | CI green |
| 7 | T15b | Adversarial review of the T12c and T12d diff (T15 predates both) | security (L) | c6, d5 | 1 | Findings fixed or named limits |
| 8 | N1 | NF-1 write-up draft (measured, fix commit linked). Publishing is the founder's outward action | lead (L) | c2 merged, CI green | 0.5 | Draft in docs; founder yes before any post |
| 9 | T16 | Gate run: demo steps 1-11, scene 5(d), SCRIPT_UNPINNABLE retry measure, `M2_DEMO.md` | qa (W) | T15b | 2.5 | All frozen steps PASS with measured numbers |
| 10 | T17 | One-page quickstart (incl. the genesis code hand-off) and `M2_DONE.md` | lead (L), support (S) | T16 | 1 | Quickstart followed once on a clean checkout; founder approval |

Critical path: c2, c3, d3, d4, d5, T15b, T16, T17 = **11 d**. That puts the M2 gate at about 12-13 Nov if nothing slips. c4, d2, c5 and c6 run alongside it.

## 4. Bypass-suite task list (lane X, parallel to M2, never gating it)

### Is the corpus ready to run against other tools?

No. The corpus was built to test our classifier, and it would not be fair to other tools as it stands:
- **Self-referential cases.** 48% of the cases attack our own approver CLI and state. They mean nothing to Claude Code native rules or to Cursor.
- **Our allowlist.** The 136 git cases encode our own allowlist design.
- **"0 RED" is by construction.** The corpus grew with the classifier, and every RED was fixed before freezing.
- **Different scoring for each tool.** Our verdicts are deterministic library calls. Native tools can only be driven through the agent, with the model in the loop, and the model may refuse or rewrite a command.

**lasso mcp-gateway is out of category.** It proxies MCP traffic and never sees the agent's built-in Bash or PowerShell tool. Scoring it on a shell corpus would be a strawman, and it is also our M4 upstream (ADR 0006 s7). Exclude it from the shell table with a one-line reason. An MCP sub-suite can come in M4.

**"Cursor hooks" is not a policy.** A Cursor hook is only a delivery mechanism; the native control is Cursor's command allow/deny list. Our connector running as a Cursor hook needs the M3 adapter.

| ID | Task | Owner (tier) | Size (d) | Done when |
|---|---|---|---|---|
| X0 | **Frozen rule, pre-registered before any run**: a neutral policy spec (denied target actions plus the allowed benign set, written once and translated per tool); scoring (an auto-run of a denied action = bypass; ask/escalate = held; a benign case held = friction; a model refusal or rewrite = excluded and reported, never a win); pinned tool and model versions; OS; N=3 runs per native case; publication and disclosure rule | lead (L), security (L), qa (W) | 1 | Rule committed with a hash before X8; security and QA sign |
| X1 | Corpus v2 (neutral). Re-target cases at canary actions: a canary "deploy" binary, curl to a local canary server, writes to a canary protected file. Map the 205 self-referential cases to each tool's own approval and config surface, or drop them with a reason. v1 stays frozen as our regression gate | qa (W), security (W) | 2 | v2 schema plus a mapping table; v1 untouched |
| X2 | 2026 CVE scenarios as repo fixtures: committed settings with `bypassPermissions` / `disableAllHooks`; workspace-defined hooks; an embedded bare repo with a pre-commit hook under an approved `git commit`; a plugin hook returning allow or rewriting permission files; a symlink escape. About 10-15 scenarios | security (W) | 2 | Each scenario has a canary oracle |
| X3 | Execution oracle plus per-case workspace reset, on a Linux container and on Windows with Git bash | qa (W) | 1.5 | The oracle detects every canary on a known-bad control |
| X4 | Adapter for our connector: direct hook (deterministic), plus a 20-case sample through real Claude Code to show the two agree | qa (W) | 0.5 | Sample agrees with the hook verdicts |
| X5 | Adapter for Claude Code native rules. A spike (0.5 d) confirms that a log-only PreToolUse hook does not change the permission flow and captures `tool_input` byte for byte. Then `claude -p` headless with the X0 settings | qa (W) | 2.5 | Byte-equality check on every executed case |
| X6 | Adapter for Cursor's native allow/deny list via `cursor-agent` headless (spike 0.5 d: headless mode, permission config, and whether a hook "allow" overrides the list) | qa (W) | 2.5 | Same as X5 |
| X7 | Write the lasso exclusion line | lead (S) | 0.25 | In the method section |
| X8 | One run per the frozen rule, on Linux and Windows; record flakiness and cost | qa (W) | 1.5 | Raw results committed |
| X9 | Results in `docs/BYPASS_SUITE.md`; adversarial fairness review ("would the vendor call this rigged?"); disclosure notes for any native-rule bypass | security (L), lead (L) | 1.5 | Founder yes before publishing |
| | **Total** | | **about 15.25** | |

Calendar time is about 3 weeks alongside M2. X0-X3 and the X5/X6 spikes can start now; X8 waits for c2 to merge.

### Risk that the published numbers embarrass us

| Risk | Likelihood | Mitigation |
|---|---|---|
| Rigged-suite accusation (our own corpus, half self-referential, 0 RED by construction) | High if v1 is published as the cross-tool table | Publish only v2 cross-tool; report v1 separately as our regression gate |
| Native "ask" ties us on the held metric (Claude Code asks for every command that is not allowlisted) | High | Expected and honest. The pre-execution classifier is not our moat; binding, dual control and the broker are. Add an approval-integrity scene table (swap after approval, replay, self-approval, loosening), with N/A where a tool has no such approval, not "fail" |
| Our own misses on the CVE scenarios: plugin or same-user processes rewriting files (limit 4); git hooks running under an approved `git commit` (S-L2-class, not bound); committed settings disabling our project-level hooks (we install to `.claude/settings.local.json`, not managed settings) | High | Publish them. Tie each to ADR 0012 (section 6) or a managed-settings install mode |
| Windows coverage: only 26 pwsh and 18 cmd cases; Cursor on Windows uses PowerShell; NF-1 means the broker was wrong on Windows until c2 | Medium | Run the shell table on Linux and Windows; publish only after c2 merges; grow pwsh cases in X1 |
| A real bypass in Claude Code or Cursor native rules is a vulnerability | Medium | Coordinated disclosure before publishing those rows (can delay them by weeks) |
| Results go stale (vendors ship weekly) | Certain | Pin and date versions; re-run per release |

## 5. T12d ruling

Pausing d2-d5 is **rejected**. It would leave:
- **58 strict xfails RED**: 42 ee and 16 CLI.
- **A single-key registry**: genesis holds exactly one admin key, so dual control cannot run on a real stack.
- **No revocation or rotation path**: publishing v2+ needs `sign-registry` (d3), and removing a key from the latest version is the only revocation mechanism.
- **Broken frozen demo steps 2 and 5.**
- **A broken ADR 0010 s8 rule**: the e2e test would have to keep its direct INSERT seeding.

The happy path the PM wants already needs the candidates route, `sign-registry` and `migrate.py` emitting the genesis code. The only separable pieces are the code-dedup rules, which are already built in the tree. Finishing costs about 5.5 d, and most of d2 is already written.

## 6. Same-user bypass ruling (M2 limit 4)

### Is a design note enough?

**A note is enough for M2 and for the suite publication. It is not enough for the moat.**
- **The integrity claim stands without a fix.** It covers what two humans approved being what ran (for the one bound file), no self-approval, and no loosening. All of it holds on the governed path.
- **The prevention claim fails without a fix.** "The agent cannot perform the privileged action without approval" fails against any same-user process. A plugin hook, or a script the agent wrote and ran through an approved runner, can call `kubectl` with the user's credentials. Until it ships, every demo must say so, and no material may claim prevention.

### Option chosen: isolated broker identity with credential custody (new ADR 0012; needs a security leader ruling)

1. **A separate broker account.** The broker runs as a separate OS account installed once with admin rights.
   - On Windows: a local service account behind a named pipe, ACL'd to the operator's SID for submit only.
   - On Linux: a systemd service user with a Unix socket, checking the caller with `SO_PEERCRED`.
2. **The broker becomes the enforcement point.** It re-verifies every signed approval itself: pinned root, registry, fingerprint, script pin. The user-space hook becomes the advisory front end.
3. **Prod, payment and cluster credentials live only in broker custody.**
   - The store is readable only by the broker account.
   - Credentials are injected through the env allowlist only into a bound, verified action, and the child runs as the broker identity, so the user cannot read its memory.
   - A same-user bypass can still run commands, but without the credentials it cannot deploy or refund.
4. **Broker custody also covers our own state.** The device key, pinned root, `high_water.json` and the enrollment markers move into broker custody. That closes the unsigned high-water Low limit and the "delete state to go standalone" half of limit 4.

### Rejected options

- **(b) An OS sandbox around the agent.** There is no Windows path, and it is the containment work SENTRY_IDEAS rejected. Recommend Claude Code's sandbox as a compensating control on Linux and macOS.
- **(c) A server-side executor.** Strongest, but it moves execution off the laptop. Revisit it for CI in M4.
- **(d) Short-lived credentials minted per approved action.** Good for STS and Kubernetes, but static secrets stay exposed. M4 add-on to (a).

### Size: L, about 20 d

| Item | Size (d) |
|---|---|
| ADR 0012 and threat model | 3 |
| Windows service and custody | 9 |
| Linux | 4 |
| Tests and leader reviews | 4 |

ADR 0012 is drafted before the suite publishes. The Windows build is **M3 exit item 1**, ahead of the policy advisor, pause and passkeys. Precondition: at least 2 of 5 discovery calls confirm that agents hold prod or payment credentials on laptops.

## 7. What the PM got wrong technically

1. **Shell parity is not a differentiator.** Native agents execute in the shell they parse, so they have no parity gap. NF-1 was our own bug, created by adding a separate broker. Present it as a self-found and fixed finding, not as a moat row.
2. **The TOCTOU window is largely self-created.** Native "ask" runs immediately after the click, so its window is about zero. Ours exists because approvals are asynchronous: the hook returns pending and the agent keeps editing. The real differentiator is that **the reviewer sees and signs the script body, and the broker refuses changed bytes**. Native prompts show `python deploy.py` without its contents.
3. **"What two humans approved is exactly what ran" is overstated.** Only the one file named on the command line is bound. The named limits:
   - S-L1: imports, sourced files and `conftest.py` are not bound;
   - S-L2: runners are not bound;
   - S-L3: interpreters, shells and config or data files are not bound;
   - S-L4: on POSIX a change is detected after the run, not prevented;
   - S-L6: humans sign the scrubbed preview hash.

   The demo line must name the scope: "Only <rel> is bound."
4. **The handle pin is described correctly but is not built yet** (c2 is uncommitted). It covers the file and its folder chain on Windows only.
5. **The signed bundle and meet-drift are not "the direct answer" to the 2026 CVEs.** Those CVEs run repo-controlled config inside the agent host, before or outside the PreToolUse path. Our protected paths stop the agent's tools from rewriting `.claude/settings.json` and `.git/**` mid-session. They do not stop a cloned repo that already ships them. They do not stop a plugin process writing them (limit 4) or a git hook under an approved commit. Expect misses in X2.
6. **The fail-closed row.** Our own hook relies on the same Claude Code `onFailure: block` (2.1.295+) that the PM lists as "partial" for the natives.
7. **"80% built, 2 weeks" for the suite.** The corpus is built for our classifier. The cross-tool harness is 0% built, and the work is about 15 d (section 4).
8. **The competitor "No" cells (Arcade, Runlayer, Vantagate) are unverified.** They come from marketing pages. Mark them "not found in public material", never "No".

## 8. Questions for the founder

1. **c5.** Your 25 Oct ruling says the web inbox shows the full script body, and the panel is about 80% built. Keep it (my ruling), or reverse it and pause it as the PM proposes? The fallback costs the same.
2. **Spend and disclosure.** Do you approve running Claude Code and Cursor headless for the suite? My estimate is $50-150 in API usage plus one Cursor seat. If either native tool shows a real bypass, do you approve reporting it to the vendor (Anthropic or Cursor) before publishing, which can delay those rows?
3. **Kill date.** Can the 15 Nov kill date be split? 15 Nov: the frozen rule published, the NF-1 post, and our own v2 numbers. 30 Nov: the cross-tool table.
4. **Same-user bypass.** Do you accept ADR 0012 (isolated broker identity plus credential custody, about 20 d, one admin install per laptop) as M3 exit item 1, with no prevention claim in any material until it ships?
5. **lasso mcp-gateway.** Can it be excluded from the shell suite as out of category (it is also our M4 upstream), with an MCP sub-suite in M4?

Next steps after approval: security-engineer and qa-engineer review lane X and the section 3 table before any code (TEAM.md workflow step 1). Then the T12B_PLAN, HANDOFF and RESUME updates.
