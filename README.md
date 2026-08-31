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
# Run all tests (117 passing)
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

## Key Design Decisions

- **The folder is the bus**: Atomic file operations on NTFS coordinate four independent processes (no in-memory state, no open ports, survives restarts)
- **`deny` carries the output**: Tool never executes in the agent; output is pasted back in the reason string
- **CLI-first approval**: Headless, works over SSH, no browser dependency
- **Fail-closed**: Internal errors block rather than silently allow
- **Non-removable self-protection**: `.sandbox/**` in write denials and `\.sandbox` in shell denials are re-injected on every policy load — agent cannot remove its own constraints

## License

[To be determined]
