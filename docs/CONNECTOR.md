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
claude                         # or codex, cursor, windsurf
```

Ask the agent to run something privileged (`whoami /priv`, `npm install -g x`).
It appears in the `watch` terminal; press `a` to approve. The agent receives
the output and continues.

---

## Architecture in one picture

```
Agent (Claude Code / Codex / Cursor / Windsurf)
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
      "^git (status|diff|log|show|branch|rev-parse)\\b",
      "^(npm|pnpm|yarn) (run|test|ci)\\b",
      "^python -m pytest\\b",
      "^(ls|dir|pwd|cd|cat|type|echo|which|where)\\b"
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
sandbox approve <id> --remember prefix     # first two tokens (e.g. "npm run")
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
sandbox verify [PATH]
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
| agent | `SANDBOX_AGENT_TOKEN` | submit broker requests, have hook calls evaluated, use `/e2b/v1` |
| approver | `SANDBOX_APPROVER_TOKEN` | everything, including approve/deny, launch, policies, the dashboard and `/ws/events` |

`sandbox serve` binds `127.0.0.1` and, if the tokens are unset, generates
them for that run and prints the dashboard URL with the approver token once.
It refuses a non-loopback `--host` unless both are set. The launcher gives
jailed agents the agent token only, so an agent can ask for a privileged
command but can't approve it.

When the API server is running (`sandbox serve` / uvicorn), a thin, read-through
view over any folder's `.sandbox/` is mounted at `/api/v1/connector`. It holds
**no** in-memory state — every call reads the folder fresh:

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

Unrelated hooks in your Claude Code settings (including the M1 launcher's
`sandbox_hook`) are preserved — only the connector's marker-tagged entries are
removed.
