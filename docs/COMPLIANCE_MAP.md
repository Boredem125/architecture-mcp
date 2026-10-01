# Compliance mapping

Each control mapped to the named obligations an examiner cites. This is not a claim of
certification — it shows the controls were *designed against* these frameworks and where the
evidence lives.

## Control → regulation

| Control (in this repo) | Japan FSA¹ | SR 11-7² | NYDFS Part 500³ | DORA⁴ | ISO 42001⁵ |
|---|---|---|---|---|---|
| Human-in-the-loop escalation for privileged actions | ✓ governance & oversight | ✓ effective challenge | ✓ access controls | ✓ ICT risk mgmt | ✓ human oversight |
| Agent identity bound to a named human operator | ✓ | | ✓ §500.7 access | | ✓ accountability |
| Deny-by-default + least privilege per action | ✓ | | ✓ §500.7 | ✓ | ✓ |
| Transparent, itemized risk scoring | | ✓ model risk rating | | ✓ | ✓ risk assessment |
| Tamper-evident hash-chain audit | ✓ recordkeeping | ✓ documentation | ✓ §500.6 audit trail | ✓ logging | ✓ logging/traceability |
| Ed25519-signed approvals (non-repudiation) | ✓ | | ✓ §500.6 | ✓ | ✓ |
| Segregation of duties / dual control (critical): two distinct signed approvals *(distinct reviewer ids and keys; not proof of two humans)* | ✓ | ✓ independence | ✓ | ✓ | ✓ |
| Prompt-injection / exfiltration containment | | | ✓ §500.2 cybersecurity | ✓ threat mgmt | ✓ security controls |
| Restorable file originals + change timeline | ✓ recordkeeping | ✓ | | ✓ | ✓ |
| Policy change control: versioned policy, changes approved by a second signed reviewer, drift cannot loosen *(distinct reviewer ids and keys; not proof of two humans)* | ✓ | ✓ change control | ✓ | ✓ ICT change mgmt | ✓ |
| Examiner evidence export *(roadmap)* | ✓ | ✓ | ✓ | ✓ | ✓ |

## Where the evidence lives

- **Decisions & approvals:** `.sandbox/escalations/done/<id>.json` (signed) — read with
  `sandbox explain <id>`.
- **Audit chain:** `.sandbox/audit/<session>/records.jsonl` — verify with `sandbox verify`.
- **File changes / originals:** `.sandbox/originals/` — list with `sandbox changes`, revert
  with `sandbox restore`.
- **Policy at time-of-action:** `policy_version` (folder + governance version ids) is on each
  audit record and bound into each signed done-record; the versions themselves, who approved
  them and the signed approvals are in `.sandbox/policy_history/` — read with
  `sandbox policy history` / `sandbox policy diff`.

---

¹ Japan FSA — APPI + Comprehensive Guidelines for Supervision of Financial Instruments
Business Operators (FIEA). ² US Fed/OCC SR 11-7 — model risk management. ³ NYDFS 23 NYCRR
Part 500 — cybersecurity. ⁴ EU DORA — digital operational resilience. ⁵ ISO/IEC 42001 — AI
management systems.

*Scope note: mappings are design intent for a proof-of-work, not an attestation. A formal
control narrative would be produced with the organization's second line of defense.*
