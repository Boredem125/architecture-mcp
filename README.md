# Agent Governance Gateway

**Authorization and runtime governance for AI coding agents.** Every tool call an agent makes (Claude Code, Codex, Cursor, Windsurf) is intercepted, classified and recorded. Risky actions go to a named human, who runs them outside the agent. Everything is signed and audited.

> An AI agent having a *capability* is not the same as it having *authority*.

## What it does

- **Intercepts every tool call** (shell, file, web and MCP) via Claude Code hooks and an MCP server, and returns **allow / observe / escalate / deny** with an itemized, explainable risk score.
- **Keeps the agent unprivileged:** approved commands run in a broker outside the agent. For third-party MCP calls the sandbox can't make itself, a human approves the exact call and the agent's identical retry is allowed once.
- **Dual control:** critical actions (e.g. a command that sends `.env` out) need two approvals by different reviewers with different keys, each signed.
- **Detects intent, not just keywords** (optional, local): a small distilled classifier plus [jev-os](https://github.com/Boredem125/jev-os) zero-shot checks scan what the agent *reads* for prompt injection, sentence by sentence. On a hit, even allowlisted shell and network actions need a human.
- **Governance-as-code:** plain-language clauses ("no moving money without human review") mapped to EU AI Act / GDPR / SR 11-7 references, checked on shell commands and on MCP/WebFetch calls, with a `test` command that measures each clause before you trust it.
- **Governance records:** versioned policies with second-reviewer change control and drift protection, a signed evidence pack for auditors, oversight metrics with approval-fatigue detection, and dev/staging/prod plus data-classification rules.

**Design rule:** models may only *raise* scrutiny. Deterministic rules stay in charge, so a fooled model means an extra approval, never an open door.

## Results (measured, laptop CPU)

Prompt injection in what the agent reads, held-out sets (caught, false alarms):

| Set | Keyword rules (before) | jev-os checks | Shipped (jev-os OR student) |
|---|---|---|---|
| Injections in repo files (600) | 60/309, 39/291 | 86/309, 8/291 | **256/309, 14/291** |
| deepset, genuine attacks | 0/39, 0/56 | 26/39, 1/56 | **31/39, 1/56** |
| neuralchemy (942 texts) | 156/552, 3/390 | 324/552, 86/390 | **525/552, 96/390** |

- Governance on MCP/WebFetch calls: 16/20 violations caught, 0/24 benign calls flagged (frozen test set).
- Red team: 10 of 113 evasive attacks still get through, all plain-sounding instructions with no AI wording. That case is left to the authorization layer.
- Every adoption decision used a rule written before the test run; two candidates that missed their rule were not shipped. Full numbers, method and limits: [the write-up](docs/INTENT_AWARE_AUTHORIZATION.md).

## Security of the gateway itself

CI runs Semgrep, Gitleaks, Trivy and a ZAP API scan on every push, with SARIF upload and a severity gate. Fixed along the way: an unauthenticated HTTP API that let anyone approve and run commands, an endpoint that would pull and run any Docker image, and every real 500 ZAP found. See [SECURITY.md](SECURITY.md).

## Tech

Python 3.12 · FastAPI · MCP · Claude Code hooks · ONNX Runtime · Pydantic · PyNaCl (Ed25519) · pytest (482 tests)

## Quick start

```bash
pip install -e ".[dev]"
sandbox init . --claude --mcp      # connect a folder
sandbox watch .                    # approve escalations in another terminal
```

Useful commands: `sandbox verify` (audit chains), `sandbox explain <id>`, `sandbox oversight`, `sandbox export-evidence --out pack.zip`, `sandbox policy history`.

Optional intent-aware layer: `pip install -e ".[semantic]"`, then `jevos serve` and `sandbox semantic enable .`

## Docs

[Write-up: intent-aware authorization](docs/INTENT_AWARE_AUTHORIZATION.md) · [Full details](docs/DETAILS.md) · [Threat model](docs/THREAT_MODEL.md) · [Governance-as-code](docs/GOVERNANCE.md) · [Evidence pack](docs/EVIDENCE.md) · [Data and environment](docs/DATA_AND_ENVIRONMENT.md) · [Compliance mapping](docs/COMPLIANCE_MAP.md) · [Benchmarks](benchmarks/injection/README.md)

*Compliance mappings show design intent, not certification. No software is "compliant" on its own; organisations are.*

Licensed under [MIT](LICENSE).
