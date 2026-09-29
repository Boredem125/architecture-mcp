# Agent Governance Gateway

> **An AI agent having a *capability* is not the same as it having *authority*.**
> This system separates the two.

Authorization & governance infrastructure for autonomous AI agents. Drop it into any folder where an agent already runs — Claude Code, ChatGPT Enterprise/Codex, Cursor, Windsurf — and every tool call is answered, and recorded: *who is the agent · what is it trying to do · to what resource · what authority does it have · what policy applies · does it need a human · who approved · what happened · can an examiner prove it.* Privileged actions are escalated to a named human approver, executed outside the agent's context, and the output is fed back so the agent continues.

A private, in-tenant model (e.g. ChatGPT Enterprise on Entra) fixes *data residency*. It does **not** govern what the agent *does* — reading files outside its remit, writing to prod, or being prompt-injected into exfiltrating to an attacker host. That is an **authorization** problem, and it is what this governs.

**For the enterprise framing, start with [docs/BRIEF.md](docs/BRIEF.md); to see it run, [docs/DEMO.md](docs/DEMO.md).**

## Architecture

**The Folder Connector** bridges the sandbox into your project:

- **Claude Code hooks** intercept tool calls, escalate privileged operations to a human approver, and return captured output inside a `deny` decision so the tool never runs with agent privileges
- **MCP server** (`run_privileged`, `check_request`, `sandbox_status`) provides the same loop over the Model Context Protocol — works with Claude Code, Codex, Cursor, Windsurf
- **Folder queue** (`.sandbox/escalations/`) is the bus: atomic file operations (`os.replace`, `os.rename`) coordinate approval across four unrelated processes (hook subprocess, MCP server, approver terminal, dashboard)
- **Policy engine** classifies shell commands, file writes, network requests, and reads — four escalation triggers with human-in-the-loop as the top tier

## Quick Start

```bash
# Install the connector
python -m pip install -e ".[dev]"

# Initialize a folder
sandbox init . --claude --mcp

# In one terminal: watch for escalations
sandbox watch .

# In another: use Claude Code or the MCP tools as normal
# Privileged commands will appear in the `watch` terminal for approval
```

## How It Works

1. **Agent tries to run a command** — Claude Code's PreToolUse hook intercepts it
2. **Hook classifies and escalates** — shell commands not in the allowlist go to the folder queue
3. **Human approves in `sandbox watch`** — the approver executes the command **outside** the agent
4. **Output returns to the model** — wrapped in `permissionDecision:"deny"` with stdout in the reason string
5. **Agent continues** — it received the result, never had privilege itself

The MCP channel works identically: `run_privileged` returns a tool result with captured output.

## Milestones

- ✅ **Milestone 0** — Foundations (bug fixes, path containment, audit rehydration)
- ✅ **Milestone 1** — The loop (PreToolUse hook, folder queue, CLI approval)
- ✅ **Milestone 2** — MCP channel (run_privileged, check_request, sandbox_status)
- ✅ **Milestone 3** — Folder record (restorable originals, chained audit, PostToolUse)
- ✅ **Milestone 4** — Other triggers (full classifier, remembered decisions, SessionStart context)
- ✅ **Milestone 5** — Surfaces (REST routes, uninstall, docs)

**All milestones complete.** See [docs/CONNECTOR.md](docs/CONNECTOR.md) for the full technical reference.

## Testing

```bash
# Run all tests (225 passing)
python -m pytest -q

# Test the loop with a real hook subprocess and background approver
python -m pytest tests/integration/test_connector_loop.py -v

# Test the MCP channel
python -m pytest tests/integration/test_mcp_tools.py -v
```

## Project Structure

```
src/sandbox/
├── connector/           # Folder connector (queue, hooks, policy, MCP)
├── launcher/            # M1 jailed launcher (job objects, jail, shims)
├── audit/               # Chained audit log with tamper detection
├── broker/              # Non-AI privilege executor
├── fs/                  # Path containment and validation
├── agents/              # Multi-agent sandbox orchestrator
├── api/                 # FastAPI routes and WebSocket
└── ...
```

## Intent-aware layer (optional)

Every decision above is rule-based: regex, allowlists and path containment. That's fast and predictable, but it can't tell what text *means*. So a reworded prompt injection sails past the regex, and harmless docs ("this middleware can **act as** a cache") trip it.

The optional semantic layer adds intent, using a local [jev-os](https://github.com/Boredem125/jev-os) service: an open, CPU-only zero-shot model. No data leaves the machine.

- **PostToolUse:** the output of tools that return untrusted content (web pages, files, command output, MCP results) is checked **sentence by sentence** for instructions aimed at the AI. On a hit:
  - the agent is told to treat the content as data;
  - an audit event records the scores, the model and hashes (never the content);
  - the folder is **tainted** for 15 minutes.
- **PreToolUse:** while tainted, shell, network and out-of-folder actions need a human **even when allowlisted**. So a poisoned README followed by an allowlisted `npm run build` (after the agent was told to edit the build script) or a fetch from an allowlisted host still reaches the approver, and the approver sees why (`+20 semantic-taint — Read output looked like instructions to the AI (p=0.99)`).
- **One-way ratchet:** the layer can only add scrutiny. Model-derived risk factors can't be negative (enforced in `RiskAssessment.raise_by`). If the service is down or slow, the gateway behaves exactly as it does without it.

```bash
pip install -e ".[semantic]"
jevos serve --api-key "$JEVOS_API_KEY"     # keep running; loads the model once
sandbox semantic enable .                   # off by default
sandbox semantic status .                   # reachable? tainted?
sandbox semantic clear-taint . --reviewer alice --reason "checked: false positive"   # audited
sandbox semantic trust AGENTS.md --reviewer alice --reason "house rules for agents"  # reviewed file, pinned by hash
```

**Measured** against the current regex detector ([benchmarks/injection](benchmarks/injection/README.md)):

| Dataset | Regex (current) | Semantic layer |
|---|---|---|
| Public deepset test split (held out) | 4/60 caught, 0/56 false alarms | **31/60 caught, 1/56 false alarms** |
| Injections embedded in a README (hand-written) | 7/24 caught, 8/24 false alarms | **15/24 caught, 5/24 false alarms** |

It still misses real attacks. And it can't tell legitimate instructions to AI agents (`AGENTS.md`, `CLAUDE.md`) from malicious ones. For those files, a human reviews once with `sandbox semantic trust`: the file isn't scanned while its content is byte-for-byte what was reviewed, and any edit (say, a pull request that slips in a line) makes it scanned again. That's why it only ever *raises* scrutiny while authorization stays in charge. Costs ~1 s per scanned tool output on a laptop CPU.

## Key Design Decisions

- **The folder is the bus**: Atomic file operations on NTFS coordinate four independent processes (no in-memory state, no open ports, survives restarts)
- **`deny` carries the output**: Tool never executes in the agent; output is pasted back in the reason string
- **CLI-first approval**: Headless, works over SSH, no browser dependency
- **Fail-closed**: Internal errors block rather than silently allow
- **Semantic checks only raise scrutiny**: the intent-aware layer can escalate an allowlisted action, never allow a denied one; if it is unavailable, rules decide alone
- **Non-removable self-protection**: `.sandbox/**` in write denials and `\.sandbox` in shell denials are re-injected on every policy load — agent cannot remove its own constraints

## License

[To be determined]
