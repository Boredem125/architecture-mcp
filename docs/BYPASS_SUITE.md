# Shell bypass suite (T0f)

What this is: the corpus of shell command lines the connector's `Bash` / `PowerShell` PreToolUse check is tested against, the numbers measured on it, and what it does not cover. The numbers describe this corpus only. A corpus is not a proof.

## Method

- Corpus: `tests/security/bypass_corpus.jsonl`, 427 cases (one per line: id, class, shell, command, expected verdict, why). Test: `tests/security/test_t0f_bypass_suite.py`, one test per case. Each case runs through `classify()` with `default_policy()` and through the real hook (`hook_eval.pre_tool_use`) on a temp folder. Oversize cases run in a child process with a hard timeout.
- Classes come from the GuardFall classes plus SEC-01, SEC-02 and SEC-25. Security added cases after reviewing the parser; the set may only grow.
- Implementation: `src/sandbox/connector/shellwords.py` (a lexer for a static subset, stdlib only, one pass, no bash AST) and `classify.analyse_shell`. Rule: anything outside the subset is never allowed. If the case-folded text (quotes, `\`, `^` and backticks removed) contains a deny fragment (`sandbox`, `.sand`, `sandbo~`, `approve`, `propose`, `state/keys`) the verdict is deny, else escalate. The lexer's bugs can only add escalations, never an allow.
- Bounds (hitting one denies, with a reason code): 32 KiB, nesting 8, 4,096 words, 256 quoted pieces in one word, 100 ms deadline checked per segment and every 1,024 characters.
- Verdict counts below come from `classify()` on each case. Timing is measured on the dev box (Windows 11, Python 3.12) and recorded, not promised.

## Results (commit: the T0f commit; 18 Oct 2026)

All 427 cases meet their expected outcome. `RED_TODAY` is empty (it held 68 ids on the parser as it was before T0f).

| Class | Cases | deny | escalate | allow | Still RED |
|---|---|---|---|---|---|
| glob_command_word | 10 | 10 | 0 | 0 | 0 |
| substitution | 17 | 17 | 0 | 0 | 0 |
| variable_command | 12 | 11 | 1 | 0 | 0 |
| eval_exec_source | 24 | 22 | 2 | 0 | 0 |
| interpreter_c | 56 | 53 | 3 | 0 | 0 |
| newline_continuation | 12 | 12 | 0 | 0 | 0 |
| quoting_split | 20 | 20 | 0 | 0 | 0 |
| alias_function | 10 | 9 | 1 | 0 | 0 |
| protected_path | 52 | 52 | 0 | 0 | 0 |
| sec25_residual | 8 | 8 | 0 | 0 | 0 |
| bounds | 8 | 8 | 0 | 0 | 0 |
| benign (positive controls) | 49 | 0 | 0 | 49 | 0 |
| benign_unchanged | 13 | 0 | 13 | 0 | 0 |
| git_flag_matrix | 136 | 38 | 98 | 0 | 0 |
| **Total** | **427** | **260** | **118** | **49** | **0** |

- False escalations on the positive controls: 0 of 49 (all allowed). The 11 `benign_unchanged` commands stay a plain escalation (not an allow, not an approver-CLI deny).
- In 8 cases (of the first 242) the corpus accepts "escalate or deny" and the classifier denies, because a deny fragment is visible in text it cannot resolve (for example `eval_exec_source-019`, `trap 'sandbox approve req-1' EXIT`). These count as deny above.
- Deny and escalate are both blocked: the hook answers an escalation with a human prompt, never an allow.

### Timing (32 KiB worst-case inputs, `analyse_shell`, best of 3)

Test: `tests/security/test_t0f_lexer.py::test_32kib_worst_case_is_classified_under_100ms` (12 shapes: quote-dense, brace-heavy, many words, many segments, glob arguments, dotted paths, backslashes, one huge word, nested parentheses, nested `bash -c`, PowerShell quotes). On the dev box all finish under 100 ms (largest measured 20 to 25 ms for the quote-dense and nested shapes). A loaded machine can be slower; hitting the 100 ms deadline denies, so slowness fails closed. Oversize input (over 32 KiB) is denied before any scan.

## Second review (security, 18 Oct 2026)

Security's bypass review added 15 cases (12 `protected_path`, 3 `benign_unchanged`), all failing on the first T0f build and now passing: brace ranges (`.{r..t}andbox`), POSIX classes and `^` negation in bracket globs, PowerShell wildcards (no leading-dot rule), attached option values after a letter cluster (`tar -xf.sandbox/x.tar`), a redirect write to `.git/config`, 8.3 aliases (`GIT~1`), and default allow patterns matching `ls/x.sh`. Write to `.git/config`, `GIT~1/hooks/x`, `CLAUDE~1/settings.json` and `MCP~1.JSO` are denied. Reading `.git/config` is still allowed. Glob matching is now our own bash-style translation (`fnmatch` has neither `^` nor `[:alpha:]`); `{a,b}` and `{x..y}` are expanded, and a word with a brace group is unresolvable (denied if a fragment shows, else escalated).

Known gap: `.git/config` is protected for Write/Edit and for shell redirects only; `tee`, `cp` or `git config` writing it are the program's behaviour (see limits).

## Third review: flag allowlist and `.git/**` (security, 18 Oct 2026)

- `git_flag_matrix` (136 cases): each allowlisted git subcommand (`status`, `log`, `diff`, `show`, `branch`) with each write or config flag (`--output`, `-o`, `-O`, `--ext-diff`, `--textconv`, `--no-index`, `-c`, `--git-dir`, `--work-tree`, `-C`, `--exec-path`), `GIT_*=` prefixes, mutating `git branch` and unlisted `git rev-parse` forms (escalate), and writes into `.git/**` (deny). Against the pre-fix source 123 of the 136 fail. The 34 read-only positives (`git status -s`, `git log --oneline -n 5`, `git branch --list`, `git rev-parse --short HEAD`, ...) are in class `benign` and stay allowed.
- Flags on allowlisted git commands are now an allowlist, not a denylist: only known read-only flags pass; `git branch` allows only list forms (positional arguments create a branch); `git rev-parse` only read flags.
- All of `.git/**` is write-protected (Write, Edit, NotebookEdit, shell redirects, and every word of `tee`, `cp`, `mv`, `rm`, `ln`, `dd`, `touch`, `install`, `sed`, `tar` and similar writers, with 8.3 aliases and case resolved). Reading stays allowed. `.git/**` is also a non-removable policy default.
- An allow pattern must be followed by whitespace or the end of the segment, whatever a saved policy.json holds; `sandbox doctor` warns about saved patterns without a boundary (the `npm run` and `python -m pytest` patterns are gone from the defaults since T0g).
- Limit: a program that writes `.git/**` by itself (`git config --local`, `git commit`) is a normal escalation; the allowlist concerns what runs without a human.

## Status wording (SEC-01, SEC-25)

SEC-01 residual closed. SEC-25 residual reduced (denied when a deny fragment is visible, escalated otherwise), open until T3. The lexer cannot close SEC-25: `$'\x70ropose'` escalates, and one human can still approve it. SEC-25 closes cryptographically (T3 pinned proposer, D2 key home, M3 passkeys).

## Limits (out of scope, stated plainly)

- What a resolved program does when it runs: `make`, git aliases and hooks, an approved interpreter (the D2.7 limit), programs that execute their own arguments and are not on the code-carrying list.
- Scripts written earlier in the session. A script the agent wrote is escalated like any unlisted command; it is not read. `python script.py` is an ordinary escalation.
- Workspace code runners (`npm run`, `python -m pytest`) run code the agent can write. Since T0g (ADR 0009) they are escalated by default and allowed only by an approved two-reviewer `shell.allow_runners` opt-in, which re-opens the two-step bypass for the chosen runners. A team that allowlists `make`, `tox`, `cargo test`, `go test` or `node script.js` makes the same trade by its own approved change (the D2.7 limit).
- Shell startup files, `BASH_ENV` set outside the command, PATH shims, renamed copies of the CLI (a copy under another name escalates; it is not denied).
- zsh and fish syntax, and full bash conformance. The only claim is that forms outside the subset are never allowed. Where the lexer disagrees with bash the result is an extra escalation or deny, by construction; this was tested on the corpus, not proved.
- Windows: `Bash` payloads are lexed as bash on every OS with Windows and MSYS path forms normalised (trailing dots and spaces, `\\?\`, `//?/`, UNC, `/cygdrive/x`, `/e/x`, alternate data streams, 8.3 names). `cmd` with any argument and `pwsh` / `powershell` are unresolvable; `-EncodedCommand` and every abbreviation behind `-`, `/` or a Unicode dash is denied.
- The `PreToolUse` hook can only fail closed if Claude Code honours `"onFailure": "block"` (2.1.295 and later). On older versions a hook timeout or crash lets the call proceed (SEC-27 and SEC-28 follow-ups; `sandbox init` warns).
- Numbers describe this corpus only. They are not a coverage or detection rate.

## Workspace runners (T0g, ADR 0009)

`benign-009` and `benign-010` (`python -m pytest`, `python -m pytest -q tests/unit`) moved from `benign` to `benign_unchanged` (expected escalate), so the positive controls are 49 and the plain escalations 13. `tests/security/test_t0g_runners.py` covers 36 runner forms (escalate with `WORKSPACE_RUNNER`), old patterns in saved policies, `auto_allow` and environment rules, remembered decisions, hand-added or drifted `allow_runners`, `baseline` refusal, the two-reviewer opt-in with its alert and pre-allow audit record, `npx`/`dlx`/`bunx` never opt-in, taint, an audit-write failure (denies), and the evidence pack's `runners` section.

### What the runner opt-in trusts (accepted by security, 18 Oct 2026)

With `shell.allow_runners` approved by two reviewers, a pytest run executes agent-written code: `conftest.py`, test modules, `addopts` in `pytest.ini` or `pyproject.toml`, and plugins loaded through `-p`, `-o addopts=...`, `--confcutdir` or `--import-mode`. `npm test -- --require x` does the same through the package manager, and the scripts in `package.json` are agent-writable too. The opt-in only narrows the command line: the first `-m` must be `pytest`; a package manager takes `test` or `run <script>` with no option of its own before `--`; a pytest path argument or `--opt=path` value that resolves outside the governed root loses the opt-in; `ci`, `install`, `exec`, `npx`, `bunx` and `dlx` are never eligible. The numbers above describe the default, where all runners escalate.
