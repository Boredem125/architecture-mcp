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

## Shipped (Stage 1.5): intent-aware layer

- Optional local semantic checks (jev-os): per-sentence injection scan of untrusted tool
  output, folder taint that escalates allowlisted shell, network and out-of-folder actions,
  model-derived risk factors that can only raise scrutiny, and an audited `clear-taint`
- Command exfiltration detection, actual-actions on the approver panel, trusted-file pinning, and **plain-language governance clauses** with per-clause reliability testing (`docs/GOVERNANCE.md`)
- Benchmark vs the regex detector on public held-out data (`benchmarks/injection`)

## Next for the intent-aware layer

- **Command intent:** "does this command send data somewhere?" on escalated commands, and
  **description vs command mismatch** on the approver panel (Goal 6).
- **Distillation:** a small single-pass model trained on hard cases labelled by a larger LLM
  (PII redacted first) to beat the zero-shot baseline on speed and accuracy.
- **Red-team loop:** generate new injection variants, retrain on the misses, and publish the
  before/after numbers.

## Stage 2 — bank-resonant, moderate cost

- **Environment dimension** (dev / staging / prod → different verdicts) = segregation of duties.
  *Shipped (first cut):* `environment` in `policy.json`; staging audits allowlisted network
  calls, prod audits allowlisted shell and network calls and starts dual control at risk 70
  instead of 80. See [DATA_AND_ENVIRONMENT.md](DATA_AND_ENVIRONMENT.md).
- **Policy-as-code + versioning** (`policy/v1.json … current.json`; `policy_version` is
  already a signed field in done-records but nothing sets it yet — this makes it first-class
  and diffable).
- **Dual control: per-human authentication.** Two approvals by distinct reviewer ids with
  distinct keys are enforced (`connector/approval.py`); binding each id to a real person (SSO,
  smartcard/HSM keys) is what remains.
- **Lightweight data classification** (tag globs PUBLIC / INTERNAL / CONFIDENTIAL / RESTRICTED;
  feed the risk score and drive outbound redaction).
  *Shipped (first cut):* ordered glob rules feed an itemized risk factor and verdict floors;
  sending a CONFIDENTIAL/RESTRICTED file out is dual control; tool-call governance clauses can
  gate on `data_<level>` tags. Path-based only, no content inspection. **Not yet:** outbound
  redaction, and the tags on shell-command clauses.
- **`sandbox export-evidence`**: built. A signed pack of decisions, approvers, dual-control
  approvals, audit chains with their verify results, governance clause hits and the current
  policy files, re-checked offline by `sandbox verify-evidence` ([EVIDENCE.md](EVIDENCE.md)).
  Remaining: the policy at time-of-action, which needs the versioning item above.

## Stage 3 — frontier, higher cost

- **Behavioral anomaly detection.** Each action may pass policy while the *pattern* is wrong
  (reads jump from 20 files to 4,000; sudden `~/.ssh` access; 15 new domains). Deviation raises
  the approval threshold. (`src/sandbox/anomaly/*` exists as a starting point.)
- **Approval-fatigue detection: first version shipped.** `sandbox oversight` reports approval
  rate, decision time, fast approvals, bursts and timeouts per reviewer; a reviewer flagged for
  bursts or mostly-fast approvals must give a reason and needs a second reviewer until the flag
  clears (`connector/oversight.py`, [DETAILS.md](DETAILS.md#oversight-indicators-and-approval-fatigue)).
  What remains: calibrate the thresholds on real reviewer data, sign decision timestamps, and
  measure review time from when a request was shown rather than when it was created.
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
