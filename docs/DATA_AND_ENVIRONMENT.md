# Environment and data classification

Two optional fields in `.sandbox/policy.json` make the same tool call stricter depending on
where the folder runs and what data it touches. Both only add scrutiny. Every effect shows up
as a named factor in the risk breakdown (`sandbox explain`), a verdict only moves up
(allow < observe < escalate < deny), and a `deny` is never changed. With neither field set,
the gateway behaves exactly as before.

Code: [`connector/context_rules.py`](../src/sandbox/connector/context_rules.py),
[`safety/classification.py`](../src/sandbox/safety/classification.py), the band in
[`connector/risk.py`](../src/sandbox/connector/risk.py). Tests:
`tests/unit/test_environment_classification.py`.

```json
{
  "environment": "prod",
  "classification": [
    {"pattern": "data/customers/public_sample.csv", "level": "public"},
    {"pattern": "data/customers/**", "level": "restricted"},
    {"pattern": "reports/**", "level": "confidential"},
    {"pattern": "docs/**", "level": "internal"},
    {"pattern": "*.pem", "level": "restricted"}
  ]
}
```

## Environment

`environment` is `dev`, `staging`, `prod` or unset (`null`, the default). `development`,
`stage` and `production` are accepted as aliases. An unrecognised name is read as `prod`, so
a typo never relaxes the policy. When the field is unset, the `SANDBOX_ENV` environment
variable is still read, as it was before.

| | dev | staging | prod |
|---|---|---|---|
| Risk factor `environment` | -5 (existing) | +5 (existing) | +20 (existing) |
| Allowlisted network calls (WebFetch to an allowlisted host, allowlisted MCP server) | allow | **observe** | **observe** |
| Allowlisted shell commands (`git status`, `ls`, `cat`...) | allow | allow | **observe** |
| Critical band (dual control) starts at | 80 | 80 | **70** |

What that means for a default prod folder: every escalated shell command (45 privilege + 10
irreversible + 20 prod = 75) needs **two approvers** instead of one, which is the segregation
of duties the roadmap asked for. An identity with `high` trust (-10) gets back to one approver.
Out-of-folder writes and unknown network hosts already reached the critical band in prod.
Allowlisted commands still run in prod; they are audited (observe), not blocked, because
gating every `ls` behind a human would make the setting unusable.

The `-5` for dev was already in `risk.py` and is kept so existing scores don't move. It can
lower a score, never a verdict set by a rule.

## Data classification

`classification` is an ordered list of glob rules. Levels, lowest to highest: `public`,
`internal`, `confidential`, `restricted`. The **first** matching rule wins, so put a narrow
exception before the broad rule it carves out of. An unrecognised level is read as
`restricted`. A path no rule matches is unclassified and nothing changes.

Patterns:

- `*` stays within one path segment, `**` spans segments (`data/**` also matches `data`).
- A pattern without `/` matches the file name at any depth (`*.pem`), as in `.gitignore`.
- A relative pattern is matched against the path relative to the folder root. Only patterns
  starting with `**/` (or without `/`) also match outside the folder, e.g. `**/.ssh/**`.
- An absolute pattern (`/etc/**`, `C:/vault/**`, `~/.aws/**`) is matched against the absolute
  path.
- `\` and `/` are both accepted. Matching is case-insensitive on Windows. The path is checked
  as written (with `..` collapsed) and with symlinks resolved; the higher level wins.

Which paths a call names:

- **Read / Glob / Grep, Write / Edit / MultiEdit / NotebookEdit:** the target path.
- **Bash / PowerShell:** every token of the command that could be a path (split on spaces,
  pipes, `=`, quotes and `@` stripped). Not a parser.
- **MCP tools and WebFetch:** every string argument that looks like a path.

Effects, by the highest level found:

| Level | Points | Read | Write, shell command, MCP call | Sends the file out |
|---|---|---|---|---|
| public | 0 | - | - | - |
| internal | +5 | - | - | - |
| confidential | +15 | - | at least observe | escalate, **dual control** |
| restricted | +30 | observe in the folder, escalate outside it | at least escalate | escalate, **dual control** |

- "Sends the file out" means a shell command with a network-egress shape (`curl -F/--data`,
  `scp user@host:`, `| curl`, `aws s3 cp`... from `safety/exfil.py`) or an MCP/WebFetch call
  tagged `sends_data`. It adds the same `exfiltration` factor (+45) as the existing exfil check.
- A shell command is scored as a shell command (45 + 10) plus the level. So in practice a
  shell command naming a CONFIDENTIAL file escalates to one approver and one naming a
  RESTRICTED file needs two, even an allowlisted `cat`, since the gateway cannot tell whether
  the command reads, copies or deletes the file. The Read tool is the normal path.
- An escalated in-folder write or read is redirected to `request_path_access`, so a human
  approves it and the sandbox performs it.
- Governance clauses on tool calls can gate on the level: a call naming a classified file gets
  the tag `data_<level>` (one per level present), so a clause with
  `"requires_tool_actions": ["data_confidential", "data_restricted"]` is checked only on those
  calls. The approver also sees `names a RESTRICTED file (...)` in the call's actual actions.

## Limits

- Classification tags **paths**, not content. A RESTRICTED file copied or renamed to an
  untagged path is untagged; a file never written to disk (data in an environment variable,
  a database row) is never seen. It is only as good as the patterns someone writes.
- Paths in shell commands and tool arguments are found by a token scan. Command substitution,
  variables, globs in the command, scripts that open files themselves, and staging through a
  temp file all evade it. Grep or Glob without a path searches the whole folder unclassified.
- Relative paths in MCP arguments are resolved against the folder root; the MCP server may
  resolve them differently.
- Shell-command governance clauses (`requires_actions`) do not get the `data_<level>` tags yet;
  only tool-call clauses do.
- The environment name is whatever the policy file says. Nothing verifies that a folder marked
  `dev` is not connected to production.
- None of this is a certification or a compliance claim. It is a deterministic, testable
  control whose rules and weights are in the code above.
