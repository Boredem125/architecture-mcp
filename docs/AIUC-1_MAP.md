# AIUC-1 mapping

How this gateway's controls line up with [AIUC-1](https://standard.aiuc-1.com), the AI agent standard.

- **Version mapped:** the July 15, 2026 release, which has 51 active requirements. The next release is due October 15, 2026, and this page will go out of date when it lands.
- **What this is:** a self-assessment by the author. It hasn't been audited and isn't a certification.
- **Who gets certified:** AIUC-1 certifies an *organization's agent product*. A tool can't be "AIUC-1 compliant" by itself. This page shows which AIUC-1 controls the gateway could supply evidence for, if an organization running a coding agent (such as Claude Code) adopted it.

**How the statuses work:**

- **Supports:** every core ("should include") control is met by the gateway, and there is evidence in the repo for each one.
- **Partial:** some core or supplemental controls are met. The gap column says what's missing.
- **Not covered:** the gateway doesn't address it. Most of these are organizational processes (policies, vendor reviews, third-party testing) that no runtime tool can supply.

## Summary

| Status | Count | Requirements |
|---|---|---|
| Supports | 2 | C007, C009 |
| Partial | 18 | A003, B001, B002, B005, B006, B007, B008, C001, C002, C005, C006, C008, D003, E004, E009, E010, E013, E015 |
| Not covered | 31 | Everything else (listed per domain below) |

**The strongest matches are the runtime controls:**

- **B006**, unauthorized agent actions: the gateway is a pre-execution authorization hook.
- **D003**, unsafe tool calls: every tool call is classified before it runs.
- **E015**, logging: the logs are tamper-evident and approvals are signed.
- **C007 and C009**, human review and intervention.

The gateway meets several *supplemental* controls that go beyond the core, for example **B006.3** (execution-level safeguards), **D003.4** (human approval) and **E015.4** (tamper-evident logs). In three cases it still misses a *core* control:

- **B006.2:** alerting is local only.
- **D003.2:** no rate limits on the hook path.
- **E015.3:** no log retention or access control on the hook path.

## A. Data & Privacy

| ID | Requirement | Status | What the gateway does (evidence) | Gap |
|---|---|---|---|---|
| A001 | Input data policy | Not covered | — | Organizational policy |
| A002 | Output data policy | Not covered | — | Organizational policy |
| A003 | Limit AI agent data access | Partial | **A003.1:** writes outside the project folder are denied. Paths classified as confidential raise the risk score and need dual control when sent out (`connector/classify.py`, `connector/context_rules.py`). **A003.2:** each call is tied to an agent identity (type, session, operator) on the audit record (`connector/identity.py`). | Reads outside the folder are logged, not blocked, by default. There is no per-role data scoping. |
| A004 | Protect IP & trade secrets | Not covered | Related: a confidential file sent out needs two approvers. | Core control A004.1 is user guidance, which is out of scope |
| A005 | Cross-customer data exposure | Not covered | — | Single-user, local tool |
| A006 | Prevent PII leakage | Not covered | — | Classification uses path patterns only. There's no content inspection and no PII masking in logs. |
| A007 | Prevent IP violations | Not covered | — | — |
| A008 | Credentials & secrets leakage | Not covered | Related: a command that reads a secret file (e.g. `.env`) and sends it out over the network is forced to dual control, whether it uses curl or Python (`safety/exfil.py`). | Core A008.1–A008.3 aren't implemented. A008.5: the `output.scrub_secrets` policy flag exists, but nothing on the hook path reads it, so broker output and logs aren't scrubbed. |

## B. Security

| ID | Requirement | Status | What the gateway does (evidence) | Gap |
|---|---|---|---|---|
| B001 | Third-party adversarial testing | Partial | **B001.1:** adversarial taxonomy organized by attacker goal ([THREAT_MODEL.md](THREAT_MODEL.md)). Internal red team: 10 of 113 evasive attacks got through ([benchmarks/redteam](../benchmarks/redteam/README.md)). | No third-party testing |
| B002 | Detect adversarial input | Partial | **B002.1:** tool output and web content are scanned for prompt injection. A hit warns the agent and "taints" the folder, so shell, network and out-of-folder actions need a human. **B002.2:** each hit is a record in the audit chain (`semantic/scan.py`, `semantic/taint.py`). Held-out results are in the [write-up](INTENT_AWARE_AUTHORIZATION.md). | No alert to a security team. No quarterly review schedule (B002.3). The scan runs after the tool returns, so the model still sees the content, with a warning attached (B002.4). |
| B003 | Public release of technical details | Not covered | — | — |
| B004 | Prevent AI endpoint scraping | Not covered | — | The gateway doesn't expose an AI endpoint |
| B005 | Real-time input filtering | Partial | Supplemental: the detection logic is documented (B005.2), flagged content is logged (B005.4), and filter performance is measured on frozen held-out sets with thresholds set before testing (B005.5). | Core B005.1: the gateway labels and taints rather than removing content before the model reads it |
| B006 | Prevent unauthorized agent actions | Partial | **B006.1:** every tool call is classified before it runs (allow / observe / escalate / deny). Writes outside the folder are denied. Network, WebFetch and MCP calls are gated, with an MCP server allowlist. Approved commands run in a broker outside the agent (`connector/classify.py`, `connector/broker.py`). **B006.3 (supplemental):** pre-execution hooks check calls against a versioned policy, and content the agent reads is scanned for injection. | **B006.2:** escalations show up live in `sandbox watch`, and denials go to the audit chain, but nothing is pushed to an external alert channel. No integrity check on MCP tool definitions. |
| B007 | User access privileges | Partial | **B007.1:** the HTTP API has separate agent and approver tokens, and listens on localhost by default (`api/auth.py`). Dual control requires two different reviewer ids with different signing keys. | Reviewer ids aren't tied to verified people. No quarterly access review (B007.2). |
| B008 | Protect deployment environment | Partial | **B008.1:** API callers must authenticate with a token. **B008.3 (supplemental):** approvals are Ed25519-signed and records are hash-chained. CI runs Semgrep, Gitleaks, Trivy and ZAP. | **B008.2:** no TLS. The gateway relies on localhost-only access. |
| B009 | Limit output over-exposure | Not covered | — | — |
| B010 | Secure patterns in generated code | Not covered | — | Nothing checks the code the agent writes. Semgrep only scans this repo in CI. |

## C. Safety

| ID | Requirement | Status | What the gateway does (evidence) | Gap |
|---|---|---|---|---|
| C001 | AI risk taxonomy | Partial | Risk factors are itemized with weights and bands for actions (privilege, exfiltration, sensitive resource, reversibility, environment) in `connector/risk.py`. [THREAT_MODEL.md](THREAT_MODEL.md) covers attacks. | Covers actions only, not harmful text outputs. The taxonomy has no change-management process (C001.2). |
| C002 | Pre-deployment testing | Partial | For the gateway itself: a test suite, CI security scans (C002.2, C002.3), and adoption gates where the rule and test set are fixed before the run. | Doesn't test the agent across risk categories |
| C003 | Prevent harmful outputs | Not covered | — | Text outputs aren't checked |
| C004 | Prevent out-of-scope outputs | Not covered | — | — |
| C005 | Agent-specific high-risk outputs | Partial | **C005.1:** plain-language governance clauses (e.g. "no moving money without human review") are checked on shell, MCP and WebFetch calls, and can escalate or deny them ([GOVERNANCE.md](GOVERNANCE.md)). **C005.2:** flagged calls go through the approval flow. | Applies to actions, not text. Clause detection is measured: on MCP/WebFetch, 16/20 violations caught and 0/24 benign calls flagged. |
| C006 | Prevent output vulnerabilities | Partial | **C006.2:** tool output that looks like instructions to the AI gets a "treat as data" label, and the folder is tainted. | No output sanitization (C006.1) |
| C007 | Flag high-risk outputs for human review | **Supports** | **C007.1:** high-risk criteria come from the risk bands, triggers and clauses. **C007.2:** detection is automated (classifier, exfiltration check, semantic scan). **C007.3:** escalations go to a review queue (`sandbox watch` / `approve` / `deny`), and critical ones need two signed approvals. | Applies to agent actions, not text outputs |
| C008 | Monitor AI risk categories | Partial | `sandbox oversight` reports approval rate, time to decide and approval-fatigue signals per reviewer. Every decision carries its risk factors. | No ongoing monitoring of outputs across risk categories |
| C009 | Real-time feedback & intervention | **Supports** | **C009.1:** a person approves or denies each escalated action before it runs, and can revert file changes (`sandbox restore`). **C009.2:** oversight metrics support regular review. | — |
| C010 | Third-party testing: harmful outputs | Not covered | — | Third-party process |
| C011 | Third-party testing: out-of-scope | Not covered | — | Third-party process |
| C012 | Third-party testing: customer-defined risk | Not covered | — | Third-party process |

## D. Reliability

| ID | Requirement | Status | What the gateway does (evidence) | Gap |
|---|---|---|---|---|
| D001 | Prevent hallucinated outputs | Not covered | — | — |
| D002 | Third-party testing: hallucinations | Not covered | — | — |
| D003 | Restrict unsafe tool calls | Partial | **D003.1:** every tool call is classified against the policy before it runs, with allowlists and parameter checks such as the target path, host and command (`connector/classify.py`). **D003.3:** observes, denials, escalations and approvals are recorded in the signed audit chain. **D003.4 (supplemental):** human approval, and dual control for critical calls. **D003.5 (supplemental):** `sandbox oversight` shows usage and approval patterns. | **D003.2:** no rate limits or caps on the hook path (only the older API path has per-session request caps). D003.3: plain *allowed* calls aren't recorded in the chain. |
| D004 | Third-party testing: tool calls | Not covered | Internal benchmark only ([benchmarks/tool_calls](../benchmarks/tool_calls/README.md)) | Third-party process |

## E. Accountability

| ID | Requirement | Status | What the gateway does (evidence) | Gap |
|---|---|---|---|---|
| E001 | Failure plan: security breaches | Not covered | — | Organizational process |
| E002 | Failure plan: harmful outputs | Not covered | — | Organizational process |
| E003 | Failure plan: hallucinations | Not covered | — | Organizational process |
| E004 | Assign accountability | Partial | **E004.1:** for the gateway's own policy, every version is recorded. Loosening it needs a second signed reviewer, and a drifted file can't loosen it (`connector/policy_versions.py`, `sandbox policy history`). | Doesn't cover model selection, prompts or other AI system changes. No code signing for models or artefacts (E004.2). |
| E005 | Data storage security | Not covered | — | Documentation |
| E006 | Vendor due diligence | Not covered | — | Organizational process |
| E008 | Review internal processes | Not covered | Oversight and evidence packs could feed a review | No review process |
| E009 | Monitor third-party access | Partial | **E009.1:** MCP and WebFetch calls are classified, and escalations and denials are recorded with the server or host. | Allowlisted MCP calls aren't recorded. No anomaly alerts (E009.2). |
| E010 | AI acceptable use policy | Partial | An organization can write prohibited uses as governance clauses (E010.1). Agent actions are checked against them in real time and blocked or escalated (E010.2, E010.4), and the agent is told the reason (E010.3). | Watches the agent's actions, not what users ask it |
| E011 | Record processing locations | Not covered | Everything, including the semantic model, runs locally | Documentation |
| E012 | Document regulatory compliance | Not covered | [COMPLIANCE_MAP.md](COMPLIANCE_MAP.md) shows design intent, not an organization's compliance record | — |
| E013 | Quality management system | Partial | **E013.2:** change control and approval records for the policy. | No quality objectives or defect tracking (E013.1, E013.3) |
| E015 | Log AI system activity | Partial | **E015.1:** each record holds the agent identity, the action, risk factors, verdict, approver and outcome (`sandbox explain <id>`). **E015.4 (supplemental):** records are hash-chained, `sandbox verify` checks links and contents, and a signed evidence pack can be re-checked offline ([EVIDENCE.md](EVIDENCE.md)). **E015.2 (supplemental):** approval records include the approver id, time and decision. | **E015.3:** no retention policy or log access control on the hook path, and no secret masking (a retention module exists but isn't wired in). No reasoning traces or sub-agent records. |
| E016 | AI disclosure mechanisms | Not covered | — | — |
| E017 | System transparency policy | Not covered | [TCB.md](TCB.md) and the write-up document the gateway, not the AI system | — |

## F. Society

| ID | Requirement | Status | What the gateway does (evidence) | Gap |
|---|---|---|---|---|
| F001 | Prevent AI cyber misuse | Not covered | Related: exfiltration-shaped commands need dual control | The core control is the foundation-model developer's test results |
| F002 | Prevent catastrophic misuse | Not covered | — | — |

## Cheapest gaps to close

Each of these would move a core control from partial toward met:

1. **Alerting** (B006.2, B002.1): send denials and critical escalations to a webhook.
2. **Audit allowed calls** (D003.3, E009.1): record plain allows in the chain, not just observes and escalations.
3. **Secret scrubbing** (A008.5, E015.3): make `output.scrub_secrets` actually scrub broker output and log records.
4. **Rate limits** (D003.2): per-tool and per-session caps on the hook path.
5. **Log retention and access** (E015.3): wire the existing retention module into the hook path.
