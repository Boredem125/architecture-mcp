# Roadmap

The shipped system (Stage 1) proves the thesis — *capability ≠ authority* — with a working,
tested slice. This roadmap shows the rest of the board. Items are sequenced by leverage, not
difficulty; each is intentionally *not* built yet so the core stays tight and demonstrable.

## Shipped (Stage 1)

- Model-agnostic control plane (Claude Code hooks + MCP), one folder queue, one audit chain
- Agent identity as a first-class object
- Transparent, itemized risk scoring → tiered response (allow / observe / one approver / dual)
- Structured decision explanations + `sandbox explain`
- Cryptographic maker-checker (Ed25519-signed approvals, non-repudiation)
- Restorable file originals + tamper-evident chained audit
- Threat model, TCB, compliance mapping, security posture

## Stage 2 — bank-resonant, moderate cost

- **Environment dimension** (dev / staging / prod → different verdicts) = segregation of duties.
- **Policy-as-code + versioning** (`policy/v1.json … current.json`; `policy_version` already
  bound into signed records — this makes it first-class and diffable).
- **Dual control enforced end-to-end** for `critical` risk (two distinct authenticated approvers;
  the risk engine already flags `requires_dual`).
- **Lightweight data classification** (tag globs PUBLIC / INTERNAL / CONFIDENTIAL / RESTRICTED;
  feed the risk score and drive outbound redaction).
- **`sandbox export-evidence`** — one signed examiner pack (decisions, approvers, policy at
  time-of-action, chain-verify result): "evidence in hours, not weeks."

## Stage 3 — frontier, higher cost

- **Behavioral anomaly detection.** Each action may pass policy while the *pattern* is wrong
  (reads jump from 20 files to 4,000; sudden `~/.ssh` access; 15 new domains). Deviation raises
  the approval threshold. (`src/sandbox/anomaly/*` exists as a starting point.)
- **Approval-fatigue detection.** Track approval rate/latency; when a human is rubber-stamping
  50 approvals in 2 minutes, temporarily raise scrutiny. An underrated, genuinely novel control.
- **Break-glass.** Emergency path when the approval system is unavailable — reason + identity
  required, short expiry, extra audit, mandatory retrospective review. *Not* `--force`.
- **Broker-held capability tokens.** Short-lived, scoped grants the *broker* holds and executes
  against — the agent never receives the capability. (Deliberately deferred over one-shot grant
  tokens for TOCTOU/replay reasons.)
- **Policy simulation / replay.** `sandbox simulate` runs a workflow with nothing dangerous
  executing; `sandbox replay session.json` re-evaluates historical behavior against a new policy
  — a policy-testing framework for the security team.

## Production hardening (cross-cutting)

Custody of signing keys → HSM/smartcard; control plane out of the workspace; approver identity
via SSO/RBAC; audit shipped to a WORM sink. See [TCB.md](TCB.md).
