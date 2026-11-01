# Competitive check, 1 Nov 2026: do we stand out?

Product-manager note for the founder. Input: a pasted landscape (AI-generated, every entry treated as unverified). Method: each named repo or company checked today with one web search or a direct GitHub fetch (11 searches, 3 fetches). Our side comes from the repo as of commit `555f031` plus the uncommitted d5 tree described in RESUME.md. "Not found in public material" is never written as "No". Inferences are marked **View**.

Short answer: yes, on four properties, and not on the ones the pasted list is built around. Details below.

## 1. The pasted entries, verified

Status key: V = verified (primary page read today), P = partially verified (secondary sources or a different owner than pasted), NF = not found.

| Entry as pasted | Status | What was actually found (1 Nov 2026) | Closest overlap with us |
|---|---|---|---|
| openleash/openleash | V | Exists. Apache-2.0, **15 stars**, 305 commits, date not shown. "Local-first authorization layer for AI agents": `authorize()` call, YAML ALLOW/DENY/escalate, PASETO v4.public Ed25519 proof tokens verifiable offline, JSONL audit. Approval is a single owner token. README: no dual control, no script content binding | Offline-verifiable signed proof per action; the exact "authorization layer" phrase we retired |
| wandercom/signet-eval | P | No repo under `wandercom`. `jmcentire/signet-eval` exists (Rust, crates.io): PreToolUse hook and MCP mode, blocks writes to `.signet/` and asks before edits to Claude settings. Read via a directory listing, not the README | Self-protection of its own config, like our protected paths |
| permit0-ai/permit0 | NF | Nothing found. Similar Rust MCP policy projects exist (mcpdome, perso), none by this name | none |
| PlawIO/veto | V | Exists. Apache-2.0, **14 stars**, 403 commits. TS/Python/Rust; block, allow, warn, log, require_approval (callback URL, 30 s timeout, default fail closed); `veto.receipt/1` chain verifiable offline; `veto install claude-code`; an "adversarial analyzer" for rule gaps. No signed approvals, no dual control | Approval routing with fail-closed timeout; offline receipts |
| microsoft/agent-governance-toolkit | P | Real: Microsoft .NET blog posts (21 May 2026) and an MCP extensions package. MIT per secondary sources. Policy evaluated inside the agent runtime before MCP tool calls; scanner plus gateway; OWASP mapping. A competitor (PolicyLayer) argues it is blind to clients that do not embed the SDK | MCP tool-call policy in-process; nothing on shell, approvals or signatures |
| AI-EdgeLabs/Parallax | P | Repo is `agent-defense/parallax` (About links edgelabs.ai). Apache-2.0, **38 stars**, 63 commits. Rust single binary; regex, pattern, Sigma, CEL-like, SQL evaluators; 54 rules; block/redact/detect/allow; Claude Code and Codex CLI hooks; JSONL audit, unsigned. No approvals | Deterministic rule chain on hooks; this is the prompt-injection/DLP lane we do not enter |
| Kisyntra/Agent_Sudo | V | Exists (PyPI `agent-sudo-mcp`, Glama). Local MCP permission gateway with time- and quota-limited delegation tokens. Says itself: not a sandbox, only sees calls routed through it | Scoped "sudo" for tool calls; same bypass limit we name |
| Yut0Miura/agent-tool-policy | NF | Nothing found | none |
| Cerbos | V | OSS PDP plus hosted Cerbos Hub (policy authoring, versioning, distribution). Agent and MCP authorization pages, FastMCP integration, SPIFFE identities, audit of which policy allowed what. No coding-agent (Claude Code, Cursor) material found | Central policy distribution to a local decision point |
| Runlayer | V | $30M Series A, Felicis and Khosla, June 2026, $42M total (company figure). MCP gateway: catalog, approvals, identity-aware policy, agent accounts, on-behalf-of tokens (secondary), audit, SIEM export. Kill switch: not found in public material | Paid control plane with approvals and audit; the money competitor |
| Noma Security | P | Secondary review of its docs (Sep 2026): per-detector monitor/alert/block/mask, plus routing a decision to a human; MCP approval controls; hosted control plane. ">10% Fortune 100" and ISO 42001 evidence: not verified today. Last scan: ~$132M raised | Human routing of a blocked action |
| Operant AI | P | MCP Gateway inside AI Gatekeeper, launched June 2025; "MCP trust zones" with blocking of untrusted servers and tools (vendor and secondary) | MCP server allowlisting |
| NeuralTrust | V | TrustGate is Apache-2.0 LLM/agent gateway with MCP support; TrustGuard, TrustLens, TrustTest; $20M seed June 2026 | LLM gateway: Verosek/Prisma lane, not ours |
| Rein Security | P | $25M A, $35M total (and one article notes the totals do not add up). Sidecar beside the agent, action-level runtime controls, a PDF prompt-injection case. "Dynamic action constraints": phrase not found | Runtime action control at the execution host |
| Permit.io, Oso | not checked today | Known authorization vendors; Permit.io has an "access request MCP" guide. **View:** they sell to app developers, not AppSec | HITL approval primitives |
| Indirect block (Lakera, Prompt Security, CalypsoAI, Straiker, Okta, SailPoint, CyberArk, AWS Cedar/AgentCore, Vercel, ServiceNow, Salesforce) | not checked today | Well-known vendors; the pasted roles are plausible. None was claimed to bind script bytes or do dual control. Straiker and Noma were in the 30 Oct scan | Prompt injection, identity, platform-native controls: adjacent lanes |

Two of the eight OSS names do not exist and two are misattributed. The pasted feature lists were richer than the real READMEs in every case checked.

## 2. What we have that no verified entry claims

| # | Property (where it lives) | Any verified competitor claim? | State on our side |
|---|---|---|---|
| 1 | Approval bound to the exact script bytes the reviewer saw; broker refuses changed bytes; signed done-record verifies offline (ADR 0010, c2-c6) | Offline-verifiable proofs: openleash (PASETO) and veto (receipts). **Binding the script contents: none.** openleash hashes the request body, not the file | Built and committed for one named file. Named limits S-L1 to S-L6 stand: imports, runners, interpreters and config are not bound; POSIX detects after the run. Say "only `<rel>` is bound" |
| 2 | Shell-parity broker: no `shell=True` anywhere, recorded absolute shell path, argv exec, refuse when missing (NF-1, `dca1873`) | None describes a broker that runs approved commands outside the agent at all | Committed. Per the architect (ARCH_REVIEW s7.1) this is a self-found bug fix, not a moat: native agents have no parity gap. Keep it as a credibility story |
| 3 | Dual control counted by distinct server-verified human identities (OIDC issuer and subject, self-scoped enrollment), never by key count (ADR 0011 A1) | openleash: one owner approval. veto: callback, no second person. Runlayer: approvals, identity-aware; two-person rule not found. **None claims dual control** | d5 committed 1 Nov 2026 with the A1.4 tests green and the security leader review APPROVE (G-L4 closed); T15b fixes committed the same day. Claimable, with named limits G-L5 and C-L1 beside it |
| 4 | Connector fails closed against a hostile server: pinned root, registry anti-rollback (`high_water.json`), refusal audit rows, local decision authoritative | Cerbos PDP decides locally but the hostile-Hub case is not discussed in what was read. Others are gateways: the server is the trust root | Committed (d4, `registry_chain.py`); unsigned high-water file is a named Low limit |
| 5 | Pre-registered cross-tool bypass suite with a frozen, hash-committed rule (`89fd959`, Lane X X0) | veto has an adversarial analyzer for its own rules. Nobody publishes a pre-registered cross-tool run with their own misses listed | X0 committed; X1-X9 after the M2 gate. No numbers yet, so no claim yet |

**View:** 1, 3 and 4 together are the control-plane bundle the 30 Oct scan also found unclaimed. Alone, each is copyable in weeks by a funded team; the combination plus published misses is what buys time.

## 3. Where we do not stand out

- Deterministic YAML allow/deny/escalate: openleash, veto, Parallax, Agent_Sudo, Cerbos, AGT. Table stakes.
- A human-approval step with a fail-closed timeout: veto, openleash, Runlayer, Noma. Table stakes.
- Append-only or hash-chained audit, even offline-verifiable: openleash, veto, Parallax. "Verifiable offline" alone no longer differentiates.
- MCP gateway and tool allowlisting: Runlayer, Operant, NeuralTrust, AGT, Noma. We are a hook plus broker first; our M4 MCP proxy will enter a crowded room.
- Claude Code hook enforcement: Parallax, signet-eval, veto, plus dcg at 6.2k stars (30 Oct scan). The free layer's enforcement point is a commodity.

## 4. Sentences for the design-partner call

Say: "When your coding agent needs a human yes, the reviewer sees the exact script that will run, two different people sign it, the broker refuses anything else, and the record verifies offline without us. It stays locked on the laptop even if our server lies."

Retire: "We are an authorization layer with deterministic policy and signed audit for agent actions." openleash (15 stars) describes itself in those exact words, and the founder already banned "authorization layer" on 30 Oct. Also retire any line that counts "approvers" or "keys" instead of "people".

## 5. Study first: Runlayer

Reason: it is the only verified entry with money, named rollout claims and the same paid-tier shape (approvals, identity-bound policy, central audit, SIEM). A buyer comparing our control plane will name it. One afternoon on runlayer.com docs and llms-full.txt answers the two questions that matter: does its approval bind what runs, and can one person approve alone? Read openleash's README for an hour as the design twin of the free layer, not as a threat.

## 6. Recommendation on the M2 path: GO, with two adjustments

Go, because the three properties a buyer can see in a demo (script-bytes binding, two distinct humans, offline verify) are exactly d5, c6 and T16 step 11, which are the remaining M2 critical path. Nothing verified today makes that work redundant.

Adjust:
1. Do not commit a day more to policy syntax, rule packs or the plain audit log. Six verified projects already have them.
2. Put the four-row table from section 2 into the T16 demo script and the T17 quickstart, with the named limits beside each row. The pasted list shows how fast feature claims inflate; our edge is that ours are measured.

Not a reason to stop: no verified entry has traction above 38 stars in the OSS set, and the paid names all sit at the MCP or gateway layer, not at the approved shell or script on a developer laptop.

Open risk (unchanged from 30 Oct): a native vendor shipping approval routing plus audit export. The discovery-call question to ask next: "When an agent action needs a human yes, who must approve it, and has anyone ever asked you to prove who did?" (ruling 11, question 2). Still 0 of 5 calls done.
