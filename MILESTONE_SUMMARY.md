# Enterprise AI Agent Sandbox — Milestones 0-3 Summary

## The Problem

AI agents (Claude Code, Codex, Cursor) running in your project folder have full access to your machine. When they need elevated privileges (install packages, run scripts, access system resources), they either:
- Never get it and fail silently
- Get it and pose a security risk
- Require manual intervention every time

## The Solution: The Folder Connector

Drop a plugin into your project folder. From then on:

1. **Agent runs a command** → Hook intercepts it
2. **Hook decides if it needs privilege** → Uses a policy (allow-patterns, deny-patterns, escalation triggers)
3. **If escalated** → Command goes to a human for approval (in a separate terminal)
4. **Human approves** → Command runs **outside** the agent's context
5. **Output comes back** → Agent gets the result, continues its loop

**The agent never had the privilege itself.** The tool never executed with agent privileges. Output was pasted back via the exact Claude Code hook contract: `permissionDecision:"deny"` with the result in `permissionDecisionReason`.

---

## Milestones 0–3: What We Built

### **Milestone 0: Foundations** ✅
Fixes and primitives, all tested:
- **Path containment** (`src/sandbox/fs/containment.py`) — `resolve_under` / `is_contained` handle normcase, case-insensitivity, symlinks, UNC paths, and NTFS reparse points
- **Audit rehydration** — `HashChain.from_records_file()` recovers chain state from disk on process restart (no fork)
- **Change detection** — `recorder.py` upgraded from set-membership to `dict[str, FileStat]` with hash confirmation (detects in-place edits)
- **Concurrency fix** — `AuditSink.write()` now locked per-session to prevent concurrent corruption

**Tests:** 14 covering containment, audit rehydration, recorder, broker cwd, policy self-protection.

### **Milestone 1: The Loop** ✅
Proves the core hypothesis end-to-end with a real subprocess:
- **PreToolUse hook** (`hook_eval.py`) — Intercepts tool calls, classifies shell commands, escalates to folder queue
- **Folder queue** (`.sandbox/escalations/`) — Atomic file operations (`os.replace`, `os.rename`) coordinate four independent processes (no in-memory state, survives restarts)
- **CLI approval** (`sandbox watch`) — Interactive polling loop: `[a]pprove / [d]eny / [s]kip` prompts, outputs go back to the model
- **Policy engine** — `policy.json` with shell allow/deny patterns, non-removable `.sandbox/**` self-protection
- **Hook stub** (`pretooluse.py`) — Stdlib-only, locates `.sandbox/`, delegates to the hook logic (in-process import → subprocess fallback → fail-closed)
- **Settings merge** — Idempotent, marker-tagged, preserves M1 `sandbox_hook` entry

**Tests:** 6 covering hook eval (escalate → approval → output), queue atomicity, policy self-protection, install idempotency.

**Live verification:** Drove the real hook subprocess with a background approver; the command ran outside the agent and its stdout came back in `permissionDecision:"deny"` with `"Continue with the next step."` — the agent received the result and continued sensibly.

### **Milestone 2: MCP Channel** ✅
Same loop, different surface — works with any agent that speaks MCP (Claude Code, Codex, Cursor, Windsurf):
- **MCP server** (`mcp_server.py`) — Three tools sharing the same folder queue:
  - `run_privileged(command, reason)` — Blocks up to 55s, returns `{status: "executed", stdout, stderr}` or `"pending"`
  - `check_request(request_id, wait_seconds)` — Retrieves outcome from hook **or** MCP origin (cross-channel interop)
  - `sandbox_status()` — Root, triggers, pending escalations
- **.mcp.json writer** — Claude Code project scope, merged non-destructively
- **Codex TOML emitter** — Forward-slash paths (backslashes invalid in TOML basic strings)
- **Entry point** — `sandbox-mcp` command, `mcp>=1.9.0,<2` dependency

**Tests:** 4 covering status listing, run_privileged→output, pending→check_request, hook-request-visible-over-MCP.

**Live verification:** Real stdio handshake, all 3 tools list, sandbox_status returns correct root. Cross-channel interop proven: a hook-raised request is retrievable via the MCP `check_request` tool.

### **Milestone 3: Folder Record** ✅
File-level audit with restorable originals and cross-process safe chained append:
- **FolderRecorder** — Content-addressed blob storage in `.sandbox/originals/by-hash/<ab>/<sha256>`
  - `snapshot_file()` — Called by PreToolUse *before* deciding (preserves original even if agent later modifies)
  - `finalize_file()` — Called by PostToolUse *after* tool runs (detects and logs modifications)
  - Timeline in `originals/index.jsonl` (every snapshot, every edit, deletions)
  - Deduplication by hash, collision-free naming, fast restore
- **FolderAudit** — Cross-process safe chained append without in-memory state
  - Takes advisory lock, reads last chain state from disk, appends record, fsync, releases
  - Multiple processes coordinate via `.sandbox/audit/.lock` and file operations alone
  - `verify_chain()` detects tampering; survives process restarts
- **PostToolUse hook** (`posttooluse.py`) — Finalizes file changes after tool executes
- **CLI commands:**
  - `sandbox changes` — List modified/deleted files with timestamps
  - `sandbox restore REL_PATH` — Restore file from originals store
  - `sandbox verify` — Verify audit chain integrity
  - `sandbox seal` — Seal a session

**Tests:** 10 new (FolderRecorder snapshots/deduplication/finalization/containment; FolderAudit append/chain integrity/concurrent append/verification).

---

## The Architecture at a Glance

```
Agent (Claude Code / Codex / Cursor)
  ↓ tool call
  ├→ PreToolUse hook (stdout JSON)
  │   ├ classify (policy)
  │   ├ allow / deny / escalate
  │   └ escalate → folder queue
  │       ↓
  │   Folder Queue (.sandbox/escalations/)
  │       ├ pending/, claimed/, done/
  │       ├ atomic os.replace (write)
  │       ├ atomic os.rename (claim)
  │       └ deterministic single-winner
  │           ↓
  │       Human Approver (sandbox watch)
  │       [a]pprove / [d]eny / [s]kip
  │           ↓
  │       Privilege Broker (PrivilegeBroker)
  │       runs command outside, captures output
  │           ↓
  │   Output → permissionDecision: "deny"
  │   + permissionDecisionReason: "$ cmd\nexit 0\nstdout: ..."
  │           ↓
  │   Agent reads reason, gets result, continues
  │
  └→ MCP tools (run_privileged, check_request)
      └ same queue, same approver, same output
```

**The crux:** Tool never executes with agent privileges. Output is pasted back. Agent continues.

---

## Status

| Component | Coverage |
|---|---|
| **Suite** | 165 passing (M0: 14, M1: 6, M2: 4, M3: 10, M4: 31, M5: 7, others: 93) |
| **M1 API** | 61 endpoints intact, no regression |
| **Hook stub** | Real subprocess, stdlib-only, fail-closed |
| **Folder queue** | Atomic, race-free, survives restarts |
| **Audit chain** | Tamper-evident, rehydrates on restart |
| **File originals** | Content-addressed, deduplicated, restorable |
| **Cross-process coordination** | File system (no ports, no in-memory state) |

---

### **Milestone 4: The Other Three Triggers + Tuning** ✅
Full escalation coverage and the layer that makes it usable:
- **`classify.py`** — Four-state classifier (`allow | observe | escalate | deny`) covering shell, write, read, network, MCP, and unknown tools. `observe` (audit-but-allow) makes `read_outside` shippable without prompt spam. `mcp__sandbox__*` is never gated; unknown tools default to allow.
- **`memory.py`** — Remembered decisions, session-scoped (wiped on session change). Scopes: `command`, `prefix` (min 2 tokens — refuses one-token `git`), `dir`, `host`. Only upgrades escalate→allow.
- **SessionStart hook** — Injects a sandbox-awareness paragraph (tools + policy) into context; prevents ~5 blocked calls per session.
- **Two new MCP tools** — `request_path_access` (out-of-folder file ops), `fetch_url` (gated network fetch). `FolderBroker` dispatches on record kind.
- **Policy CLI** — `sandbox policy show|allow-shell|allow-host|set-trigger|forget`, `sandbox approve --remember`.

**Tests:** 31 new (classifier table, memory, M4 hook behavior, broker kinds).

### **Milestone 5: Surfaces** ✅
The dashboard view, uninstall, and docs:
- **REST view** (`api/routes/connector.py`) — Thin, read-through window over any folder's `.sandbox/` at `/api/v1/connector`. Holds no in-memory state; every call reads the folder fresh. Status, pending, approve, deny, changes, audit, verify.
- **`sandbox uninstall`** — Removes all three marker-tagged hook entries (preserving unrelated hooks + the M1 `sandbox_hook`); `--keep-data` leaves `.sandbox/`.
- **Docs** — `docs/CONNECTOR.md` (full technical reference), PROJECT_BRIEF updated with the connector path.

**Tests:** 7 new — the first `create_app` + `TestClient` tests in the repo, including an M1 regression guard (asserts `/api/v1/launch` and `/api/v1/hook/*` still exist).

---

## All Milestones Complete

The connector is feature-complete across all planned milestones. **165 passing tests.**
See `docs/CONNECTOR.md` for the full reference.

---

## How It Works in Practice

```bash
# Initialize the sandbox in a folder
sandbox init . --claude --mcp

# In one terminal: watch for escalations
sandbox watch .

# In another: use Claude Code or any agent as normal
claude
```

Agent tries: `npm install -g typescript`
↓
Hook escalates (not in allow-patterns)
↓
Approver sees: `[a]pprove / [d]eny / [s]kip`
↓
Approver presses `a`
↓
Sandbox runs it outside, captures: `added 1 package in 3.1s`
↓
Agent gets: `permissionDecision:"deny"` + `"exit_code: 0, STDOUT: added 1 package…"`
↓
Agent: "TypeScript is now installed. Continue with the next step."
↓
**Loop closes. Agent never had root. Output was authentic.**

---

## Key Design Decisions

1. **The folder is the bus** — Atomic file ops (no in-memory state, no ports, survives restarts)
2. **`deny` carries the output** — Tool never runs in agent; output pasted in reason string
3. **CLI-first approval** — Headless, works over SSH, no browser
4. **Fail-closed** — Internal errors block rather than allow
5. **Non-removable self-protection** — `.sandbox/**` in write denials, re-injected on every load
6. **PreToolUse snapshots** — Preserve originals before the agent's change
7. **PostToolUse finalizes** — Detect and log what actually changed
8. **Cross-channel interop** — Hook and MCP share one queue; a request from either is retrievable from either

---

## Published

- GitHub: https://github.com/Boredem125/architecture-mcp
- Two commits: Initial (M0-M2), Milestone 3 (folder record)
