# ADR 0009: Workspace code runners (`npm run`, `python -m pytest`) escalate by default

Status: Accepted (18 Oct 2026). The default was ruled by security-engineer (`REVIEW_M1.md`, "T0f design sign-off", item 3); recorded by lead-architect, who set the opt-in mechanism to the ADR 0008 pattern. Security confirms the opt-in tests and signs off the changed nodes by id at T0g. M1 T0g.

## Next action

1. **Founder: approved** on 18 Oct 2026, in chat: "ADR 0009 approved as proposed: npm run / pytest escalate by default; opt-in via shell.allow_runners in a two-reviewer approved policy version."
2. **QA, then backend:** T0g against this ADR, tests first. It lands after T0f, because it reuses T0f's resolved words.

## Context

1. **The default allowlist runs agent-written code without a human.** `ShellPolicy.allow_patterns` (`connector/policy.py:31-32`) ships `^(npm|pnpm|yarn) (run|test|ci)\b` and `^python -m pytest\b`. Security's probe: `Write conftest.py` gets no decision, and `python -m pytest -q` gets no decision. Those two default-allowed calls run any code the agent wrote. That code can read keys, run the approver CLI, deploy or move money. `npm` does the same through `package.json` scripts and lifecycle hooks (`install`/`ci` run the root package's `preinstall`/`postinstall`).
2. **Default "allow" must mean that someone judged the action safe.** No one judged agent-written code. So the shipped default breaks "privileged actions escalate".
3. **This is a gap in the policy, not in the lexer.** T0f's lexer resolves the words correctly. The command really is `python -m pytest`, and what it runs is out of reach (`M1_PLAN.md` D0b.6 and the ADR 0007 D2.7 limit).
4. **Existing folders keep the old patterns.** `install.init` writes `default_policy()` to `.sandbox/policy.json` once, and the approved version of a versioned folder contains the two patterns. Changing the code default alone would protect new folders only.
5. **A one-human session memory reopens the bypass.** `sandbox approve <id> --remember prefix` stores `npm run` or `python -m`. After that, `hook_eval` (lines 427-444) upgrades later escalations to allow for the session. So one approval of the first test run would cover every later run of code the agent writes afterwards.

## Options

1. **Keep allowed and document the limit.** No UX change. Rejected by security: it ships a default that is a known two-step bypass. A footnote in `BYPASS_SUITE.md` does not stop it.
2. **Escalate by default, with a change-controlled opt-in** (chosen, security's ruling).
3. **Allow only while the code is unchanged since session start.** Rejected by security for three reasons:
   - **Cost.** The hook would have to hash the whole import closure on every call, inside the 100 ms budget: tests, `conftest.py`, `src`, `pytest.ini`/`pyproject` addopts, plugins, `.pth` files, `node_modules` and lifecycle scripts.
   - **Race.** The hash races the run (TOCTOU).
   - **No real gain.** After the agent's first edit, which is the normal loop, the command escalates anyway. So this is escalation with a bigger TCB and a false sense of safety.

## Decision

1. **Remove both patterns from the shipped default** (`ShellPolicy.allow_patterns`). New folders escalate these commands under `triggers.shell`.
2. **A code-side runner gate covers existing folders and hand edits.** A fixed list in code (`connector/runners.py`, not policy) recognises workspace code runners on T0f's resolved words: basename, case-folded, `.exe`/`.cmd`/`.bat` stripped, `python*`/`py` family. The list:
   - `pytest`: `<python> -m pytest`, `<python> -m py.test`, `pytest`, `py.test`;
   - `npm`, `pnpm`, `yarn`, `bun`: any subcommand except a small read-only set (`--version`, `-v`, `ls`, `list`, `view`, `info`, `outdated`, `config get`, `help`). Bare `yarn` counts as a runner, because it installs and runs lifecycle scripts.
   
   A recognised runner is **never `allow`** from `shell.allow_patterns`, `auto_allow`, `mode`, environment rules or a remembered decision. It is at least `escalate`. A deny from another rule still wins. The list is one-sided: a wrong entry is an extra escalation, never an allow.
3. **The only opt-in is `shell.allow_runners`.** It is a list drawn from `pytest`, `npm`, `pnpm` and `yarn`. The default is `[]`, and unknown values are ignored. An entry allows exactly the forms that used to ship: `<python> -m pytest ...` for `pytest`, and `<pm> run|test ...` for the others (`ci` is never eligible). Each match is still subject to T0f (a resolved, single static segment) and to the taint rule (a tainted session escalates even allowlisted commands, `DETAILS.md`). Other subcommands of an opted-in manager stay escalated.
4. **The opt-in has the ADR 0008 `money_floor` guarantees, by the same code paths:**
   - **Approved version only.** `allow_runners` takes effect only when it is in the approved version of a versioned folder (policy state `approved` or `drift`). An unversioned, missing, corrupt or unparseable policy gives `[]`. `sandbox policy baseline` refuses a non-empty `allow_runners`, as it refuses `money_floor: false`.
   - **No loosening by hand edit or drift.** `allow_runners` joins `_INTERSECT_FIELDS` in `policy_versions.meet()`, so a hand-added entry is drift that changes nothing. `policy.json` stays write-protected for the agent (non-removable `_PROTECT_WRITE_GLOBS`).
   - **Two reviewers.** Adding an entry is listed by `loosened_fields`. It needs `sandbox policy propose` plus `approve-change` by two distinct pinned reviewers (ADR 0007). The approver CLI is denied to the agent (T0e, T0f).
   - **Alert.** An approved change that adds an entry raises the alert `runners_allowed` (`alerts.py`), with the change id and the entries.
   - **Audit.** While the opt-in is on, every runner call it allows is audited `runner_allowed`, with the runner name and the command. `sandbox status` shows the opt-in, and the evidence pack shows whether it was on for each decision period.
   - **Nothing else can set it.** No governance clause, jev-os result, model output or remembered decision sets or extends it.
5. **The approver sees why.** A runner escalation carries the reason code `WORKSPACE_RUNNER`. The prompt says: "runs code in this folder that the agent can change; check `git diff` first", and it lists the files written in this session, taken from the audit.

## Consequences for existing users and demos

1. **Every test or script run escalates after upgrade**, in new and existing folders alike, until a team opts in through two reviewers. This is the accepted cost. The release note, the `init` output and `docs/CONNECTOR.md` (the default allowlist at lines 114-115, and the `--remember prefix` example at line 189) say so and name the opt-in. `sandbox doctor` flags a folder whose `policy.json` still lists the old patterns. It reports that the patterns are now inert; it does not rewrite the file.
2. **`--remember prefix` no longer helps for runners.** Approving `npm run build` with `--remember` covers that one call only. The CLI says so when the request is a runner.
3. **Live demo** (`E:\caterpillar\jev-os\.cache\tmp\agent-gateway`, `LIVE_DEMO.md`). Claude usually runs the tests after an edit, so expect an extra escalation per run. That suits the story ("tests run code the agent wrote; a human decides"). Do not opt the demo folder in. The scripted demos (`demo/call_demo.py`, `demo/live_setup.py`, `demo/try.py`) use neither command, so no change there.
4. **Published numbers.** In `BYPASS_SUITE.md`, the benign allow count drops by 2 (T0f corpus 17 to 15 allow), and the limit text changes from "default-allowed" to "escalated by default; allowed only by an approved two-reviewer opt-in, which re-opens the two-step bypass for the chosen runners".
6. **The pytest opt-in trusts agent-written test code (accepted by security under the two-reviewer opt-in, 18 Oct 2026).** Opting in to `pytest` runs whatever the agent put in `conftest.py`, test modules, `pytest.ini` / `pyproject` `addopts`, and plugins loaded by `-p`, `-o addopts=...`, `--confcutdir` or `--import-mode`; `npm test -- --require x` does the same through the package manager. The opt-in code only narrows the forms: `<python> -m pytest` with the first `-m` being pytest, `<pm> test` or `<pm> run <script>` with no package-manager option before `--`, and no path argument that leaves the governed root. `ci` is never eligible (it fetches remote code and runs lifecycle scripts). What a passing form then executes is the D2.7 limit.
5. **Stated limit.** The gate recognises the listed runners only. A team that allowlists `make`, `tox`, `cargo test`, `go test`, `gradle` or `node script.js` makes the same trade by its own approved change. That is the D2.7 limit ("an approved interpreter runs code we cannot see"), and it is published as such.

## Test impact (frozen tests; security signs off by node id)

Measured by grepping `tests/` and running `pytest --collect-only` at `8d2c80e`. Four frozen nodes assert that these commands are allowed. No frozen test asserts `allow` for `npm`, `pnpm` or `yarn`.

| Node id | Today | Allowed change |
|---|---|---|
| `tests/security/test_t0_hotfix.py::test_t0a_guard_plain_allowlisted_still_allow_classify[python -m pytest]` | asserts `allow` | In `PLAIN`, replace `"python -m pytest"` with `"git log"`. The positive-control count stays 5, and the node id becomes `[git log]` |
| `tests/security/test_t0_hotfix.py::test_t0a_guard_plain_allowlisted_still_pass_hook[python -m pytest]` | asserts it passes the hook, nothing pending | Same one-word change (it is the same `PLAIN` list) |
| `tests/security/test_t0f_bypass_suite.py::test_t0f_bypass_case[benign-009]` (`python -m pytest`) | corpus `benign`, `allow` | Corpus line: class `benign_unchanged`, expected `escalate`, why "workspace runner, ADR 0009". The node id stays the same |
| `tests/security/test_t0f_bypass_suite.py::test_t0f_bypass_case[benign-010]` (`python -m pytest -q tests/unit`) | corpus `benign`, `allow` | Same |

Checked and unchanged:
- `test_t0_hotfix.py::test_t0a_compound_is_not_allowlisted_{classify,hook}[python -m pytest && python deploy.py --prod]` asserts escalate or deny.
- `test_policy_versioning.py::test_meet_and_only_tightens` keeps `allow_patterns[:1]`, which is the `git` pattern.
- `test_memory.py` (`"npm run"` recall) tests storage, not a verdict.

Gate effect:
- The connector count is unchanged: 2 node ids are renamed and 0 are removed.
- QA updates `M1_BASELINE_NODEIDS.txt`, the T0f per-class counts in `M1_BASELINE.md` (benign 17 to 15, benign_unchanged 8 to 10, allow 17 to 15), and `M1_FROZEN_MANIFEST.sha256`, in the T0g tests-first commit.
- The plan said `test_t0_hotfix.py` stays unchanged (T2 done-when). That still holds for every node except the two above.

New tests (new file `tests/security/test_t0g_runners.py`, strict xfail first), all through `pre_tool_use`:
- By default, every runner form escalates with `WORKSPACE_RUNNER`. The forms: `python -m pytest`, `python3 -m pytest`, `py -m pytest`, `pytest`, `npm run x`, `npm test`, `npm ci`, `npm install`, `pnpm test`, `yarn`, `yarn test`, `bun run x`, and `.exe` and case variants.
- An M0-era `policy.json` that still lists the old patterns escalates.
- A hand-added `allow_runners` gives no allow: unversioned, under drift, and when corrupt.
- A remembered `npm run` prefix does not upgrade.
- `auto_allow`, `mode` and environment rules do not allow a runner.
- `baseline` refuses a non-empty `allow_runners`.
- Opting in needs two distinct pinned reviewers and raises `runners_allowed`. An opted-in call is allowed and audited `runner_allowed`. Opting in to `pytest` leaves `npm test` escalated.
- A tainted session escalates even when opted in.
- Positive controls: `git status`, `ls` and `npm --version` stay as today.
