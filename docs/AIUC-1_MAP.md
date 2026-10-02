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
| Supports | 5 | B006, C007, C009, D003, E009 |
| Partial | 16 | A003, A008, B001, B002, B005, B007, B008, C001, C002, C005, C006, C008, E004, E010, E013, E015 |
| Not covered | 30 | Everything else (listed per domain below) |

The first version of this mapping (2 supported, 18 partial, 31 not covered) found five gaps in core controls. They were closed on 2 October 2026; see [Gaps closed](#gaps-closed-2-october-2026) below.

**The strongest matches are the runtime controls:**

- **B006**, unauthorized agent actions: the gateway is a pre-execution authorization hook.
- **D003**, unsafe tool calls: every tool call is classified before it runs.
- **E015**, logging: the logs are tamper-evident and approvals are signed.
- **C007 and C009**, human review and intervention.

The gateway also meets several *supplemental* controls that go beyond the core, for example **B006.3** (execution-level safeguards), **D003.4** (human approval) and **E015.4** (tamper-evident logs). The main core control still only partly met is **E015.3**: who can *read* the logs is left to the operating system.

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
| A008 | Credentials & secrets leakage | Partial | **A008.5 (supplemental):** credentials are replaced with placeholders in approved command output (before it is stored or returned to the agent, so it never reaches the conversation history), in audit records and in the activity log (`connector/scrub.py`, `output.scrub_secrets`). Related: a command that reads a secret file (e.g. `.env`) and sends it out over the network is forced to dual control, whether it uses curl or Python (`safety/exfil.py`). | Core A008.1–A008.3 aren't implemented: no checks on user input, on generated code, or on credential storage. Pending escalation records keep the exact command, because the approvers' signatures cover it. |

## B. Security

| ID | Requirement | Status | What the gateway does (evidence) | Gap |
|---|---|---|---|---|
| B001 | Third-party adversarial testing | Partial | **B001.1:** adversarial taxonomy organized by attacker goal ([THREAT_MODEL.md](THREAT_MODEL.md)). Internal red team: 10 of 113 evasive attacks got through ([benchmarks/redteam](../benchmarks/redteam/README.md)). | No third-party testing |
| B002 | Detect adversarial input | Partial | **B002.1:** tool output and web content are scanned for prompt injection. A hit warns the agent, "taints" the folder (so shell, network and out-of-folder actions need a human) and raises an alert (`connector/alerts.py`). **B002.2:** each hit is a record in the audit chain (`semantic/scan.py`, `semantic/taint.py`). Held-out results are in the [write-up](INTENT_AWARE_AUTHORIZATION.md). | No documented response procedure and no quarterly review schedule (B002.2, B002.3). The scan runs after the tool returns, so the model still sees the content, with a warning attached (B002.4). |
| B003 | Public release of technical details | Not covered | — | — |
| B004 | Prevent AI endpoint scraping | Not covered | — | The gateway doesn't expose an AI endpoint |
| B005 | Real-time input filtering | Partial | Supplemental: the detection logic is documented (B005.2), flagged content is logged (B005.4), and filter performance is measured on frozen held-out sets with thresholds set before testing (B005.5). | Core B005.1: the gateway labels and taints rather than removing content before the model reads it |
| B006 | Prevent unauthorized agent actions | **Supports** | **B006.1:** every tool call is classified before it runs (allow / observe / escalate / deny). Writes outside the folder are denied. Network, WebFetch and MCP calls are gated, with an MCP server allowlist. Approved commands run in a broker outside the agent (`connector/classify.py`, `connector/broker.py`). **B006.2:** every call is in the audit chain. Denials, critical or dual-control escalations, injection hits and rate-limit trips raise alerts in `.sandbox/logs/alerts.jsonl` and, if `$SANDBOX_ALERT_WEBHOOK` is set, a JSON POST (`connector/alerts.py`, `sandbox alerts`). **B006.3 (supplemental):** pre-execution hooks check calls against a versioned policy, and content the agent reads is scanned for injection. | No integrity check on MCP tool definitions after approval (B006.3). Webhook delivery is best-effort, with a 2 s timeout, and a failure is noted in the local alert. |
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
| D003 | Restrict unsafe tool calls | **Supports** | **D003.1:** every tool call is classified against the policy before it runs, with allowlists and parameter checks such as the target path, host and command (`connector/classify.py`). **D003.2:** per-class rate limits (by default shell 30, write 60, network 20, total 600 per 60 s). A call over the limit is denied, audited and alerted (`connector/limits.py`, `policy.limits`). **D003.3:** every tool call, including plain allowed ones, is recorded in the hash-chained audit log with the tool, command or target, never file contents (`policy.audit.log_allowed`). **D003.4 (supplemental):** human approval, and dual control for critical calls. **D003.5 (supplemental):** `sandbox oversight` shows usage and approval patterns. | The default limits are untested starting points, not tuned on real workloads. |
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
| E009 | Monitor third-party access | **Supports** | **E009.1:** every MCP and WebFetch call is recorded in the audit chain, allowlisted ones included, with the tool and host. Escalations and denials also go through approval or alerting. | No anomaly detection on third-party access patterns (E009.2). Rate limits cap volume, but they aren't anomaly alerts. |
| E010 | AI acceptable use policy | Partial | An organization can write prohibited uses as governance clauses (E010.1). Agent actions are checked against them in real time and blocked or escalated (E010.2, E010.4), and the agent is told the reason (E010.3). | Watches the agent's actions, not what users ask it |
| E011 | Record processing locations | Not covered | Everything, including the semantic model, runs locally | Documentation |
| E012 | Document regulatory compliance | Not covered | [COMPLIANCE_MAP.md](COMPLIANCE_MAP.md) shows design intent, not an organization's compliance record | — |
| E013 | Quality management system | Partial | **E013.2:** change control and approval records for the policy. | No quality objectives or defect tracking (E013.1, E013.3) |
| E015 | Log AI system activity | Partial | **E015.1:** each record holds the time, agent identity, action, risk factors, verdict, approver and outcome (`sandbox explain <id>`). **E015.3, in part:** retention tiers of standard 90 days, reviewed 1 year and incident 7 years. `sandbox retention` is a dry run by default; `--apply` deletes, never touches the active session, and records each deletion with the deleted chain's head hash (`connector/retention.py`). Credentials are scrubbed from records. The agent can't write to the log directory. **E015.4 (supplemental):** records are hash-chained, `sandbox verify` checks links and contents, and a signed evidence pack can be re-checked offline ([EVIDENCE.md](EVIDENCE.md)). **E015.2 (supplemental):** approval records include the approver id, time and decision. | E015.3: read access to the logs is whatever the operating system allows. There's no log-level access control and no central log store. Retention runs only when a person runs it. No reasoning traces or sub-agent records. |
| E016 | AI disclosure mechanisms | Not covered | — | — |
| E017 | System transparency policy | Not covered | [TCB.md](TCB.md) and the write-up document the gateway, not the AI system | — |

## F. Society

| ID | Requirement | Status | What the gateway does (evidence) | Gap |
|---|---|---|---|---|
| F001 | Prevent AI cyber misuse | Not covered | Related: exfiltration-shaped commands need dual control | The core control is the foundation-model developer's test results |
| F002 | Prevent catastrophic misuse | Not covered | — | — |

## Gaps closed (2 October 2026)

The first version of this mapping listed five gaps in core controls. All five were closed in commit `302fcf4`, with 23 new tests (`tests/unit/test_aiuc_gaps.py`):

| Gap | Control | What changed |
|---|---|---|
| Alerting | B006.2, B002.1 | Denials, critical escalations, injection hits and rate-limit trips are alerts: a local log, plus an optional webhook (`sandbox alerts`) |
| Audit allowed calls | D003.3, E009.1 | Every tool call is in the chain, not only the gated ones |
| Secret scrubbing | A008.5, E015.3 | `output.scrub_secrets` was defined but nothing read it. It now scrubs approved output, audit records and the activity log. |
| Rate limits | D003.2 | Per-class limits on the hook path. A call over the limit is denied. |
| Log retention | E015.3 | `sandbox retention` with three tiers. Deletions are recorded, and the active session is never deleted. |

Each new setting is under the same change control as the rest of the policy. Lowering a limit or lengthening retention counts as tightening. Raising a limit, shortening retention, turning off alerts or logging, or moving the webhook needs a second reviewer.

## Evidence by control

`sandbox export-evidence` writes `aiuc1/controls.json` into the signed pack. For each control above that the gateway produced evidence for, it gives:
- the self-assessed status from this page;
- counts of the audit records, signed decisions and alerts that support it;
- pointers to examples, such as `audit/<session>/records.jsonl#L12`;
- the policy settings behind the control.

A governance platform or a reviewer can go from a control id straight to the records. A test keeps the index from claiming more than this page.

## What would come next

1. **Log read access** (E015.3): ship records to a central store with its own access control, rather than relying on the operating system.
2. **MCP tool-definition integrity** (B006.3): detect when an approved MCP server changes its tool definitions.
3. **Credential checks on input and generated code** (A008.1, A008.2).
4. **A documented response procedure and quarterly detection review** (B002.2, B002.3).
5. **Per-person approver authentication** (B007.1). Today two reviewers means two distinct ids and keys, not proof of two people.
