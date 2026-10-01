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
| Environment-aware verdicts (prod: dual control from a lower risk score, allowlisted calls audited) *(the environment is what policy.json says; not verified)* | ✓ | ✓ independence | ✓ §500.7 | ✓ ICT risk mgmt | ✓ |
| Path-based data classification feeding risk and verdicts (classified file sent out → dual control) *(glob patterns, no content inspection)* | ✓ APPI safety management | | ✓ §500.13 asset classification | ✓ Art. 8 information asset classification | ✓ data for AI systems |
| Prompt-injection / exfiltration containment | | | ✓ §500.2 cybersecurity | ✓ threat mgmt | ✓ security controls |
| Restorable file originals + change timeline | ✓ recordkeeping | ✓ | | ✓ | ✓ |
| Examiner evidence export *(roadmap)* | ✓ | ✓ | ✓ | ✓ | ✓ |

## Where the evidence lives

- **Decisions & approvals:** `.sandbox/escalations/done/<id>.json` (signed) — read with
  `sandbox explain <id>`.
- **Audit chain:** `.sandbox/audit/<session>/records.jsonl` — verify with `sandbox verify`.
- **File changes / originals:** `.sandbox/originals/` — list with `sandbox changes`, revert
  with `sandbox restore`.
- **Policy at time-of-action:** `policy_version` is bound into each signed record *(versioning
  is Stage 2 — see [ROADMAP.md](ROADMAP.md))*.

---

¹ Japan FSA — APPI + Comprehensive Guidelines for Supervision of Financial Instruments
Business Operators (FIEA). ² US Fed/OCC SR 11-7 — model risk management. ³ NYDFS 23 NYCRR
Part 500 — cybersecurity. ⁴ EU DORA — digital operational resilience. ⁵ ISO/IEC 42001 — AI
management systems.

*Scope note: mappings are design intent for a proof-of-work, not an attestation. A formal
control narrative would be produced with the organization's second line of defense.*
