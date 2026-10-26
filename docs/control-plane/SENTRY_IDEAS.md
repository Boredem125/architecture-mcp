# Ideas from NVIDIA Sentry and OpenShell, rebuilt in our own code (lead-architect + product-manager, 25 Oct 2026)

**Founder ruling 25 Oct:** no fork, no adapter, no NVIDIA code. We take ideas from public docs and build them clean-room. Nothing here touches M2 (T12b-2, T16, T17). Every item is M3 or later and gets the normal plan, security and QA review first.
**Test for each idea:** does it make runtime authorization or signed evidence stronger, on the runtimes we cover (Windows laptops, Claude Code hooks, MCP)? If it is detection, or it is sandbox or network work, it is out.

## Adopt (ranked)
| # | Idea (source) | Our version | Effort | TCB / security | When |
|---|---|---|---|---|---|
| 1 | Policy advisor (OpenShell) | **Agent proposes a narrow grant; people dual-sign; the proposer never counts.** Repeated escalations of one pattern become a proposed policy change, using our existing signed dual-control change path. The proposing session's operator is excluded by registry user_id. Each proposal carries a **boundary check** (from the OpenShell prover). In M3, the check runs the change against the existing allow and deny rules and the existing test command corpus. Any command whose verdict loosens is shown as a concrete counter-example, and the result is signed into the change record. It is a check, not a proof. A buyer-written invariant language waits for M4 or later, and only if a design partner asks | M | Adds one record type. Proposals can only enter as pending; the loosening rules don't change | M3 |
| 2 | Approved process hashes and execution paths (Sentry, OPA rules) | **Content-bound approvals.** At escalation, hash the script or binary the command runs, bind the hash in the ADR 0010 fingerprint, and recheck it in the broker before it runs. The signer sees the script body (secrets scrubbed, size-capped, in an escaped viewer, because the display rule refuses newlines in fields) or a diff against the last approved version. A binary shows its path, hash and version, because a bare hash is not reviewable by a person. Today the fingerprint covers the command string only (`approval.py:55`), and the display rule pushes multi-line commands into scripts the approver can't see | S-M | Closes a suspected gap: the agent edits `deploy.sh` after approval. Not yet proven by a test; security to confirm | M3, first. If security confirms the gap, the founder decides whether it comes forward |
| 3 | Containment (Sentry) | **Signed pause.** A pause for a device, project or org is tighten-only, so any one active registry key can sign it (principle 2). Unpause needs a normal signed bundle. Local `sandbox pause` too. Each pause and unpause is a chained audit record | S-M | Fails closed. Limits: takes effect at the next hook call or sync poll (no push channel); child processes already running are not killed | M3 |
| 4 | OCSF audit (OpenShell) | **OCSF export of our signed records.** A JSONL export of the existing signed records, with our chain hash, signatures and approver ids as extension fields, so a SIEM or Credo AI can ingest them and our verifier can still check them offline | S | Outside the deny path | JSONL export in M4; SIEM and OTLP integration in M5 |
| 5 | Credential placeholders (OpenShell) | **Credential custody in the broker.** The agent's environment holds no prod or payment secrets. The broker adds them only to an approved, bound action. Real only if the broker runs as a separate OS identity; otherwise the agent's OS user can read the store. Needs a design note on broker isolation first | L | Big gain: today same-user code can bypass the hook (M2 limit 4); without the credential, a bypass can't deploy or refund. Also new attack surface: a secret store | M3 design note, M4 build, only if discovery calls confirm the pain |

**Also folded in (small):** the external audit anchor (SEC-15) stays M3. Signed checkpoints also carry hashes of the connector's own hook and broker files. This is a software-only integrity hint, and we name it as such: it is not attestation.

## Rejected (one line each)
- **Behaviour profiles and deviation detection:** detection, and that is the injection and anomaly market (Verosek, Prisma AIRS, EDR). Rate limits and approval-fatigue checks stay as tighten-only signals.
- **TLS-terminating proxy with OPA:** an LLM and network gateway (Verosek, Palo Alto). M4's MCP proxy covers MCP; OPA was removed in M0 and would grow the TCB.
- **Per-binary egress rules, kernel fs and process limits, hot-reloadable network policy:** this is OS and sandbox work (OpenShell, containers), and none of it runs on a Windows laptop. Our signed bundles already reload.
- **Memory introspection, hardware-attested telemetry, enforcement off the host:** needs a DPU or the kernel. We say plainly that our records are software-signed.
- **SPIFFE workload identity:** not needed while device keys work. Revisit if a design partner asks.

## PM vs architect
- **Agreed:** the five ideas, the ranking, the cuts, the pause limits, and that no claim goes beyond what we measure.
- **Content-bound approvals:** the architect added it. PM agreed to #2 ("what you signed is what ran"), on the condition that the signer sees the script body or a diff, not a bare hash. Adopted.
- **Boundary check scope:** the architect proposed buyer-written invariants. PM objected that an invariant language is a mini policy engine and would eat M3. Settled on PM's cut: M3 shows counter-examples only, from the existing rules and corpus.
- **OCSF timing:** the architect said M5. PM argued buyers ask "what format do I get" in the first demo, and Credo AI ingest depends on it. Settled: the JSONL export moves to M4, the SIEM integration stays M5. The architect kept it out of M3, because M3 already holds the inbox, passkeys and #1-#3.
- **Credential custody:** both put it #5 in build order. The architect rates its security value above OCSF, but only with an isolated broker. PM wants the discovery calls to confirm it first.
- **Prover:** PM proposed a plain-English "this grant allows X" line. The architect wanted counter-examples, because a label is not evidence. Merged into #1: show both.

## Risks
1. **Scope creep into M2:** none of this starts before the M2 gate.
2. **Advisor abuse:** an agent floods reviewers with proposals, or wraps a broad grant in a narrow-sounding one. Mitigations: rate limits, the boundary check, and showing the full diff.
3. **Overclaiming:** "pause" is not a kill switch, a boundary check is not a proof, and checkpoint hashes are not attestation.
4. **Credential store:** wrong custody makes things worse than today. No build without a security design ruling and an ADR.
5. **Platform risk:** NVIDIA may add per-person keys. Vendor-independent offline verification stays our defence.

## Founder rulings (25 Oct 2026, terminal)
1. The ranking is approved; #1-#3 are M3.
2. The script gap is fixed in M2, once security confirms it with a failing test (content binding for the files a command runs, from #2).
3. The 4 questions below are added to the 5 discovery calls.

## Questions for the founder (answered above)
1. Should content-bound approvals (#2) come into M2 as a fix if security confirms the gap, or stay M3 as a named limit?
2. Approve the ranking and the M3 slot for #1-#3?
3. Add these 4 questions to the 5 discovery calls: "When an agent needs a permission it lacks, who decides, and how long does it take?" (#1); "If an agent went wrong at 2am, how would you stop it, and prove afterwards what it did?" (#3, #4); "Where do your agents' credentials live, and who can read them?" (#5); "Do agents run in Linux sandboxes or on developer laptops, Windows included?"
