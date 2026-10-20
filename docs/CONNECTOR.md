# The Folder Connector — Technical Reference

Plug the sandbox into any folder where an agentic AI already runs. Privileged
actions are escalated to a human, executed outside the agent, and their output
fed back into the agent's context so it continues until the work is done.

---

## Quick start

```bash
# 1. Install (editable, with dev deps)
python -m pip install -e ".[dev]"

# 2. Initialize the connector in your project folder
sandbox init .                 # writes .sandbox/, hooks, .mcp.json, settings

# 3. In one terminal, a human watches for escalations
sandbox watch .

# 4. In another, run your agent as normal — it's now mediated
claude                         # codex/cursor/windsurf: MCP tools only, see below
```

Ask the agent to run something privileged (`whoami /priv`, `npm install -g x`).
It appears in the `watch` terminal; press `a` to approve. The agent receives
the output and continues.

---

## Architecture in one picture

```
Agent (Claude Code; Codex / Cursor / Windsurf via MCP only)
  │  tool call
  ├─► PreToolUse hook  ──►  classify (policy)
  │        │                 allow → silent
  │        │                 deny  → blocked, reason to model
  │        │                 observe → allowed + audited
  │        │                 escalate ┐
  │        │                          ▼
  │                       .sandbox/escalations/  (the bus)
  │                          pending/ → claimed/ → done/
  │                          atomic os.replace / os.rename
  │                                    │
  │                          Human approver (sandbox watch)
  │                          [a]pprove / [d]eny / [s]kip
  │                                    │
  │                          Privilege Broker  (runs OUTSIDE the folder)
  │                                    │
  │        ┌───────────────────────────┘
  │        ▼
  │  permissionDecision:"deny"  +  reason = "$ cmd\nexit 0\nSTDOUT: ..."
  │        │  (tool never ran with agent privilege; model gets the result)
  │        ▼
  │  Agent continues its loop
  │
  └─► MCP tools (run_privileged, request_path_access, fetch_url, …)
          same queue, same approver — the tool RESULT is the return channel
```

Both channels — the Claude Code hook and the MCP server — share **one** folder
queue, so a request raised by the hook can be retrieved over MCP and vice
versa (`check_request`).

---

## The `.sandbox/` layout

```
<project>/
├── .mcp.json                    # MCP server registration (Claude Code project scope)
├── .claude/settings.local.json  # merged, marker-tagged, never clobbered
└── .sandbox/
    ├── policy.json              # human-editable per-folder policy
    ├── session.json             # {session_id, root, python, package_src}
    ├── workspace_id             # random 32-hex id; names this workspace's folder in the key home
    ├── hooks/                   # pretooluse.py, posttooluse.py, sessionstart.py
    ├── state/
    │   └── remembered.json      # per-session remembered decisions
    ├── escalations/
    │   ├── pending/<id>.json     # queued, awaiting a human
    │   ├── claimed/<id>.json     # atomically claimed by one approver
    │   ├── done/<id>.json        # decision + captured output
    │   └── out/<id>.txt          # human/grep-friendly text
    ├── audit/
    │   ├── .lock                 # advisory lock for cross-process append
    │   └── <session_id>/records.jsonl
    ├── originals/
    │   ├── index.jsonl           # the change timeline
    │   └── <ab>/<sha256>         # content-addressed file originals
    └── tmp/                      # staging for atomic os.replace (same volume)
```

---

## The policy

`policy.json` is human-editable JSON. The defaults:

```json
{
  "mode": "enforce",
  "fail_mode": "closed",
  "auto_allow": false,
  "triggers": {
    "shell": "escalate",
    "write_outside": "deny",
    "network": "escalate",
    "read_outside": "observe"
  },
  "shell": {
    "allow_patterns": [
      "^git (status|diff|log|show|branch|rev-parse)(\\s|$)",
      "^(ls|dir|pwd|cd|cat|type|echo|which|where)(\\s|$)"
    ]
  },
  "network": { "allow_hosts": ["registry.npmjs.org", "pypi.org", "files.pythonhosted.org"] }
}
```

### The four verdicts

The classifier returns one of four states — not a boolean:

| Verdict | Meaning |
|---|---|
| `allow` | Runs silently, no human, no audit noise |
| `observe` | Runs, but is **audited** — the shippable setting for noisy triggers |
| `escalate` | Blocked pending a human; on approval the sandbox runs it and returns output |
| `deny` | Blocked, cannot be approved; the reason goes back to the model |

### The four triggers

| Trigger | Default | What it gates |
|---|---|---|
| `shell` | `escalate` | Bash / PowerShell not in the allowlist |
| `write_outside` | `deny` | Writes outside the folder (pointer to `request_path_access`) |
| `network` | `escalate` | WebFetch / WebSearch to non-allowlisted hosts |
| `read_outside` | `observe` | Reads outside the folder (audited, not blocked) |

Optional `environment` (`dev` / `staging` / `prod`) and `classification` (glob → level rules)
fields make verdicts stricter by environment and by the data a call touches; both are unset by
default. See [DATA_AND_ENVIRONMENT.md](DATA_AND_ENVIRONMENT.md).

Tune any of them:

```bash
sandbox policy set-trigger read_outside escalate   # maximum paranoia
sandbox policy allow-shell "^docker (ps|logs)\\b"  # let a command run silently
sandbox policy allow-host api.github.com           # allow a network host
```

### Non-removable self-protection

`.sandbox/**` (and `.git/hooks/**`) are re-injected into `write.deny_globs` on
**every** policy load, and `\.sandbox` into `shell.deny_patterns`. An agent
that gets denied cannot edit `policy.json` to free itself — the protection
comes back the next time the policy is read.

---

## The MCP tools

Available to any MCP-speaking agent under the `mcp__sandbox__` prefix (these
are never gated — that would be an infinite regress):

| Tool | Purpose |
|---|---|
| `run_privileged(command, reason)` | Request a privileged shell command; a human approves; you get the output. |
| `request_path_access(path, mode, reason, content)` | Read/write a file OUTSIDE the folder; the sandbox performs it for you. |
| `fetch_url(url, reason)` | Fetch a URL through the sandbox. |
| `check_request(request_id, wait_seconds)` | Retrieve the outcome of any escalation (hook OR MCP origin). |
| `sandbox_status()` | Current policy, triggers, and pending escalations. |

A `run_privileged` call blocks up to 55 s for a human; past that it returns
`{"status": "pending", "request_id": …}` and the agent calls `check_request`.

---

## Remembered decisions

To avoid re-prompting for the same command, a human can remember a decision
for the rest of the session:

```bash
sandbox approve <id> --remember command   # exact command
sandbox approve <id> --remember prefix     # first two tokens (e.g. "git log"; not for test runners, see below)
sandbox approve <id> --remember host       # a network host
sandbox approve <id> --remember dir        # a directory subtree
```

- **Session-scoped only** — the store is wiped when `session_id` changes.
  Persistent grants belong in `policy.json` allowlists (git-diffable).
- **`prefix` requires two tokens.** A one-token prefix like `git` is refused —
  that is exactly how `git push --force` gets silently auto-approved.
- A remembered decision only ever upgrades `escalate → allow`, never the
  reverse. Blocklist and self-protection denials are checked *first*, so memory
  can't resurrect a blocked command.

Clear them: `sandbox policy forget`.

---

## The CLI

```
sandbox init [PATH] [--claude/--no-claude] [--mcp/--no-mcp] [--codex] [--auto-allow]
sandbox watch [PATH] [--reviewer ID] [--once]
sandbox status [PATH] [--json]
sandbox approve <ID> [PATH] [--reason TEXT] [--remember once|command|prefix|host|dir]
sandbox deny <ID> [PATH] [--reason TEXT]
sandbox changes [PATH] [--json]
sandbox restore <REL_PATH> [PATH] [--sha SHA] [--dry-run]
sandbox verify [PATH] [--session ID] [--expect-head SESSION=HASH] [--json]
sandbox seal [PATH]
sandbox policy show|allow-shell PATTERN|allow-host HOST|set-trigger T V|forget [PATH]
sandbox uninstall [PATH] [--keep-data] [--yes]
```

---

## The REST view (optional dashboard surface)

**API authentication.** Every route except `/health`, `/ready` and the
OpenAPI docs needs a bearer token. There are two, with different powers:

| token | env var | can |
|---|---|---|
| agent | `SANDBOX_AGENT_TOKEN` | nothing today: `AGENT_ROUTES` is empty, so it gets 403 on every route (kept so it is never mistaken for "no token") |
| approver | `SANDBOX_APPROVER_TOKEN` | every non-public route: the connector view below, including approve and deny |

`sandbox serve` binds `127.0.0.1` and, if the tokens are unset, generates
them for that run and prints the dashboard URL with the approver token once.
It refuses a non-loopback `--host` unless both are set. Never give an agent
the approver token. WebSocket connections are closed before accept with code
1008: there are no WebSocket routes.

When the API server is running (`sandbox serve` / uvicorn), a thin, read-through
view over the `.sandbox/` of each folder listed with `--root` (next section) is
mounted at `/api/v1/connector`. It holds **no** in-memory state — every call reads
the folder fresh:

```
GET  /api/v1/connector/status?root=…       policy, triggers, pending count
GET  /api/v1/connector/pending?root=…      pending escalations
POST /api/v1/connector/{id}/approve?root=…  claim, run, finish
POST /api/v1/connector/{id}/deny?root=…     claim, deny, finish
GET  /api/v1/connector/changes?root=…      file-change timeline
GET  /api/v1/connector/audit?root=…        audit records (tail)
GET  /api/v1/connector/verify?root=…       chain integrity
```

---

## Which folders the API serves: `sandbox serve --root`

The connector routes only serve folders the operator listed when the server started.

```bash
sandbox serve --root /work/projA --root /work/projB
SANDBOX_CONNECTOR_ROOTS="/work/projA:/work/projB" sandbox serve   # os.pathsep-separated (";" on Windows)
```

- **How roots are listed.** `--root PATH` (repeatable) and `SANDBOX_CONNECTOR_ROOTS` are
  combined. `serve` resolves each `--root` with `realpath` and passes the list to the
  server through that environment variable, so every uvicorn worker sees it. The app reads
  it once at startup and does not re-read it per request.
- **No roots, no service.** With none listed, `serve` prints a warning and every
  `/api/v1/connector/*` call returns 403.
- **Matching.** The `?root=` value is compared as a string, after `normpath` and `normcase`,
  with the listed roots. The request value is never used to touch the filesystem, and after
  a match the server uses its own stored root, not the request string. A subfolder of a
  listed root does not match.
- **Order of checks** (after the bearer-token checks, which come first):
  - 400 if `root` contains a NUL byte, is longer than 1024 characters, or is not an absolute path.
  - 403 if it is not a listed root. The reply does not repeat the path.
  - 400 if the listed root cannot be examined by the OS (`OSError`).
  - 404 if the listed root has no `.sandbox/`.
- This is a limit on which folders the API shows. It is not an access control for the
  folders themselves; the approver token is still what allows approve and deny.

---

## Reviewer keys: the key home

Approval signatures are made with an Ed25519 key per reviewer id. Those seeds, and the
pin file `pins.json`, are kept outside the workspace.

- **Location.** `SANDBOX_KEY_HOME` (must be an absolute path), else
  `%LOCALAPPDATA%\agg\keys` on Windows, `$XDG_DATA_HOME/agg/keys` or
  `~/.local/share/agg/keys` on Linux, `~/Library/Application Support/agg/keys` on macOS.
- **Per workspace.** Each workspace gets a subfolder named by its random id
  (`.sandbox/workspace_id`, written by `sandbox init`, or on first signing if it is missing).
  Reviewer `cli` therefore has a separate key and pin in each workspace. Seed files are
  created with mode 0600. On Linux and macOS the key home (when this tool creates it) and
  the workspace folder are set to mode 0700; on Windows a newly created key home is
  restricted to the current user with `icacls`, best effort. `sandbox keys status` shows
  the workspace folder and warns if the key home is readable by other accounts.
- **Out of the agent's reach.** The hook denies read, write, delete and rename of the key
  home for Read, Grep, Glob, Write, Edit and shell, regardless of the `read_outside` and
  `write_outside` triggers. Paths are compared after resolving symlinks and junctions,
  8.3 names, case, `~` and environment variables. A key home that is inside the workspace,
  or that contains it, is refused.
- **Fails closed.** If the key home cannot be resolved or written, there is no key and so no
  signature. There is no fallback to `.sandbox/state/keys`, the current directory or a relative
  path. `approve` returns `key_unavailable`, the API answers 503 and nothing is approved.
- **Rotation.** Keys from before this layout were stored in `.sandbox/state/keys/`. They are
  treated as exposed. When a reviewer first signs and has no key in the key home, a new key is
  generated there. If an old in-tree seed for that reviewer exists, a `key_rotated` record
  is written to the audit chain first. The old seed is not copied, moved or deleted. Records it signed are shown as `legacy`.
  `sandbox keys purge-legacy` (a human command, denied to the agent) deletes the old seeds.
  There is no other rotate command. A new workspace id also starts new keys; deleting
  `.sandbox/workspace_id` does this, and it is audited as `workspace_id_created`, not prevented.
- **Pins.** The first time a reviewer signs from the approver CLI or the approver-token API,
  its public key is pinned in `pins.json` and audited as `key_pinned`. Approvals are checked
  against the pinned key, not only the key embedded in the record (`approval._valid_for`). The policy flag `keys.enrol:
  explicit` refuses reviewers that are not already pinned.
- **What this does not stop.** The key home stops the agent that the hook governs. It does
  not stop other code running as the same OS user, including a `python` command a human
  approved: that code can read the same files. (Stated limit, ADR 0007.) Two pinned keys are
  also not proof of two different people; one person can pin two reviewer ids, which
  `sandbox verify` flags as a "new-key approval" but does not prevent.

---

## Why the folder is the bus

The connector is **N processes, not one**: a short-lived PreToolUse hook
subprocess per tool call, a long-lived MCP server, one or more `sandbox watch`
approver terminals (maybe over SSH), and optionally the dashboard. None of them
can share an in-memory queue.

So `.sandbox/` itself is the source of truth. Atomic `os.replace` (writes) and
`os.rename` (claiming — the OS guarantees a single winner) give a durable,
lock-free queue that:

- works headless with zero open ports,
- survives an approver restart mid-request,
- and genuinely stores everything the user asked to be "in the folder."

The `wait` loop polls one known `done/<id>.json` filename at 10 Hz — deliberately
not `watchdog`, so it's immune to `ReadDirectoryChangesW` buffer overflow under
heavy `node_modules` churn.

---

## Failure behavior

- **Fail closed.** Any internal hook error exits non-zero and blocks the tool
  rather than silently allowing it.
- **No sandbox found.** The hook stub no-ops (exit 0) so a folder without
  `.sandbox/` is unaffected.
- **Approver offline.** The request stays `pending`; the agent is told to ask
  the user to approve it and call `check_request`. Nothing is lost.
- **Audit write.** A per-folder advisory lock serializes chained appends across
  processes; the chain rehydrates from disk on restart (no fork).

---

## Uninstall

```bash
sandbox uninstall .            # removes hooks from settings + .sandbox/ data
sandbox uninstall . --keep-data # only removes the settings hooks
```

Unrelated hooks in your Claude Code settings (from other tools) are preserved — only the connector's marker-tagged entries are
removed.

---

## Security fixes: upgrade notice: hook hardening (existing users, action required)

The hook launch and PreToolUse failure handling were hardened. Existing installs
are not safe until you do the following:

1. **Install the connector outside the folders it governs.** Code inside a governed
   project can be changed by the agent, so `sandbox init` now refuses an in-project
   install (including an in-project `.venv` or editable install). Either
   `pipx install <path-or-package>`, or an external virtualenv:
   `py -3.12 -m venv E:\tools\agw-venv`, then `E:\tools\agw-venv\Scripts\pip install <path-to-this-repo>`
   (the `sandbox` command is then `E:\tools\agw-venv\Scripts\sandbox`). A repo with
   its own in-project `.venv` cannot govern itself.
2. **Re-run `sandbox init` in each governed folder.** It rewrites the hook command
   (absolute interpreter, `-I`) and adds `"onFailure": "block"` to the PreToolUse hook.
   Hooks need Claude Code 2.1.295 or newer for `onFailure`; `init` warns on older versions.
3. **Check it:** `sandbox doctor <folder>` prints `OK` or `UNSAFE LAYOUT` (exit 1). The
   hook entry in `.claude/settings.local.json` should show an absolute interpreter path,
   `-I`, and `onFailure: block`. Shell commands over 32 KiB are now denied unanalysed.

## Allow patterns need a word boundary (T0f)

Default `shell.allow_patterns` end in `(\s|$)`. Whatever a saved policy holds, the hook only treats a pattern as matching when whitespace or the end of the segment follows the match, so `^ls` no longer allows `ls/x.sh`. Allowlisted `git` commands also accept only known read-only flags, and `.git/**` is never writable by the agent. `sandbox doctor` lists saved patterns without a boundary.

## Test and script runs escalate by default (ADR 0009, T0g)

`python -m pytest`, `pytest`, `py.test`, `npm|pnpm|yarn|bun run|test|ci|install|exec` and bare `yarn` run code the agent can write (a `conftest.py`, a `package.json` script, a lifecycle hook). They are no longer in the default allowlist, and a code-side gate escalates them even if an older `policy.json` still lists the patterns (`sandbox doctor` flags those as inert and never rewrites the file). The approver sees `WORKSPACE_RUNNER`, "runs code in this folder that the agent can change; check `git diff` first", and the files written this session.

- `--remember` does not apply to runners: one approval covers one call.
- `npx`, `bunx`, `pnpm dlx`, `yarn dlx` and `bun` always escalate and cannot be opted in.
- Opt in per team with `shell.allow_runners` (`pytest`, `npm`, `pnpm`, `yarn`): a `sandbox policy propose` and `approve-change` by two distinct reviewers. It is honoured only in the approved version of a versioned folder, `sandbox policy baseline` refuses it, it raises a `runners_allowed` alert, and every run it allows is audited `runner_allowed` before it starts. It allows `<python> -m pytest ...` (first `-m` is pytest, paths inside the governed folder) and `<pm> test` / `<pm> run <script>` (no package-manager option before `--`; `ci` is never eligible) as one static command; a compound command, or a tainted session, still escalates. Opting in re-opens the two-step bypass for the chosen runners: the agent can write the test code the runner executes.
