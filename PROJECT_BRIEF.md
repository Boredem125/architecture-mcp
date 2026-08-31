# AI Agent Sandbox — Project Brief

## The Problem

Today's AI agents are a security nightmare. Whether it's Claude Code running hooks, GPT-4 spawning scripts, or any autonomous agent with file/shell access, you're either:

- **Trusting it completely** — the agent can read anything, write anywhere, run any command
- **Trusting nothing** — you disable everything useful and the agent can't do real work
- **Building custom controls** — each new agent requires custom sandboxing logic

There's no middle ground. No way to let an AI agent do real work while staying in control.

## The Vision

**A zero-trust sandbox where any AI agent or CLI tool can run safely, with human-in-the-loop approval for risky actions.**

Think of it as a security checkpoint for intelligent systems:
- Agent wants to read files? ✅ Allowed (monitored)
- Agent wants to write files? ⚠️ Check policy
- Agent wants to run PowerShell? 🚫 Stop. Get human approval first.

No magic. No trust. Every action logged, reversible, auditable.

## What We're Building

An **enterprise-grade sandbox** where:

1. **You launch real AI agents** — Claude Code, GPT-4 Codex, Ollama, or any CLI — as real processes, not SDK spawns
2. **They run in a jailed environment** — can only touch files in their folder, resources are capped (memory, CPU, process count)
3. **Privileged requests route to a human** — if the agent needs PowerShell access or wants to escape the jail, it can't. The request goes to a human reviewer instead. A human approves or denies. If approved, the command runs outside the jail, the agent gets the result.
4. **Everything is logged forever** — every action, every approval, every file created or deleted. Originals of deleted files are kept. Nothing is lost.
5. **You watch it happen live** — a real-time dashboard shows the agent's work as it runs, with plain-language summaries of what it's doing.

## The Difference

| | Without Sandbox | With Sandbox |
|---|---|---|
| **Trust Model** | All-or-nothing | Zero-trust (deny by default) |
| **Visibility** | After the fact | Real-time streaming |
| **Control Point** | Only at launch | Per-action (escalations only) |
| **Audit Trail** | Logging is optional | Immutable, comprehensive |
| **Recovery** | Restore from backup | Files preserved in-jail, rollback possible |

## Use Cases

- **Code review agents** — Let an AI analyze your codebase without fear it'll alter production files
- **Automation workflows** — Grant DevOps agents elevated access only when explicitly approved
- **Research & data analysis** — Autonomous data agents with read-only defaults, write approval gates
- **Teaching & demo** — Show how AI agents work without worrying about what they access
- **Compliance** — Auditable proof that every AI action was logged and approved

## The Promise

**You stay in control.** The agent does the work. Humans decide what risky actions are allowed. Nothing is ever hidden or irrecoverable.

No more choosing between power and safety. You get both.

---

## Two Ways In

There are two ways to put an agent inside the sandbox:

### 1. The Launcher (agents we start)
We start the CLI ourselves as a real, jailed OS process — resource-capped, filesystem-confined, PowerShell attempts routed to a human broker, streamed live to a dashboard. Good when you want the sandbox to own the whole process lifecycle.

### 2. The Folder Connector (agents you already run) — *the newer, lighter path*
Instead of launching anything, you **drop the connector into a folder** where an agent you already run — Claude Code, Codex, Cursor, Windsurf — is working. From then on:

1. The agent tries a tool call → a hook (or MCP tool) intercepts it
2. A policy decides: allow silently, deny, observe-and-log, or **escalate to a human**
3. On escalation, the command runs **outside** the agent's context, and its **output is pasted back** so the agent continues its loop
4. Every modified/deleted file is preserved (content-addressed, restorable); every decision is in a tamper-evident chained log

The agent **never holds privilege itself**. The whole thing runs headless — no server, no open ports, no browser required. The `.sandbox/` folder *is* the coordination bus, so four independent processes (the hook, the MCP server, the human's approval terminal, the dashboard) all stay in sync through atomic file operations alone.

```bash
sandbox init .          # drop the connector into a folder
sandbox watch .         # a human approves escalations here
claude                  # your agent runs as normal — now mediated
```

**The crux:** for Claude Code, the hook returns `permissionDecision:"deny"` (so the tool never runs with the agent's privileges) while carrying the approved command's real output in the reason field (which the model reads). The tool never executes and the model still gets the result. For MCP-based agents, the tool result *is* the return channel, natively.

See `docs/CONNECTOR.md` for the full technical reference.
