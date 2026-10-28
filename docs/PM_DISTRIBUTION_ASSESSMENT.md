# PM assessment: "SaaS depends on distribution, not product" (revised for the security positioning)

Author: product-manager (Fable 5.1). Date: 28 Oct 2026, revised the same day. Status: decision document for the founder. Nothing here is a ruling; the founder decides.

Founder question, verbatim: "is this even a product that would be scaled, saas depends on distribution not on product".

Founder ruling, verbatim, 28 Oct 2026: "i want ai security as moat not ai governance". The first version of this document bet on the compliance channel (AIUC-1 auditors, Credo AI, Drata). The founder rejected governance as the moat and the positioning. That analysis is kept in Appendix A, marked rejected. The sections below replace it.

The premise still holds: in this category distribution beats product for every buyer except one, and the repo's own history shows it (the 5 discovery calls assigned on 24 Oct are still 0 of 5 done while T12b, T12c c1 and T12d d0/d1 shipped). Under a security positioning the buyer, the channel and the artifact change. The need to stop building and start showing does not.

## 1. The security moat, from what is built today

The claim an AppSec engineer can check in a 10-minute demo: **what two named humans approved is exactly what ran, and the agent cannot change it between approval and execution, loosen the policy that required the approval, or count itself as an approver.** Each piece exists in code or in committed tests (`src/sandbox/connector/`, `src/sandbox/protocol/registry.py`, `tests/security/`).

| Property (built or in M2 with tests committed) | Arcade | Runlayer | Vantagate | Claude Code / Cursor native | lasso mcp-gateway | Visible in a 10-min demo? |
|---|---|---|---|---|---|---|
| Approved action runs in a broker outside the agent, clean env allowlist, under the shell the reviewer saw (bash `--noprofile --norc -c` or pwsh `-EncodedCommand`), never cmd.exe (NF-1, ADR 0010 s9) | No (delegated API calls, not local exec) | No (MCP broker, network) | No (returns a decision; the agent runs it) | No (the agent process executes; "ask" is same-user) | No (proxy) | Yes: approve `deploy.sh`, show the process tree and env |
| Script content binding: fingerprint v2 covers `script.sha256`; the broker re-resolves and refuses `SCRIPT_CHANGED` with a signed record; Windows share-mode handle pin during the run (T12c) | No | No | No | No | No | Yes: bob approves, the agent edits the script, carol approves, nothing runs. This is the TOCTOU demo and the strongest single scene |
| Dual control = two distinct registry humans; the operator of the requesting device is excluded; replay keyed by `(key_id, nonce)`; approval bound to request, device, project, org, policy sequence, cwd, root (H1, T12b) | No second human | Not stated | One approver, HMAC, payload destroyed | No (one local click) | No | Yes: `same_user`, `requester`, `wrong_kind` refusals on screen |
| Signed registry chain: `key_id == sha256(public_key)`, thresholds count distinct admin users not keys, genesis once, pinned root, offline verify (ADR 0011, D0-1..D0-5) | Not stated | Not stated | No | No | No | Partly: an AppSec engineer reads it in the evidence verify output, not on a slide |
| Policy change control: loosening needs a second signer; on-disk drift can only tighten (meet) | No | No | No | No (a repo-controlled `.claude/settings.json` could set `bypassPermissions`; PromptArmor showed a plugin hook rewriting permission files) | No | Yes: edit `policy.json` to allow, show the hook still escalates |
| Fail-closed TCB: one verified-state accessor, no decision path reads an unsigned file, grep-tested | Unknown | Unknown | No | Partial (`onFailure: block` is opt-in; Defender reported fail-open after 1 s) | Unknown | Only through the test file |
| 427-case shell bypass corpus with measured results, 0 RED (docs/BYPASS_SUITE.md) | None published | None published | None | None published by the vendor (GuardFall: 10 of 11 OSS agents bypassed) | None published | Yes: run it live |

Where the gap is small, honestly:
1. **Same-user bypass is the hole an AppSec engineer finds in minute three.** M2 named limit 4: code running as the developer's OS user can call the command without going through the hook. The broker-held credential idea (SENTRY_IDEAS #5) that would make a bypass useless is not built and needs an isolated broker identity. Claude Code's OS sandbox and Teleport Beams give containment we do not. The honest demo line is: "we prove what was approved and ran through the governed path; we do not yet stop a same-user process from going around it on a laptop."
2. **Dual control alone is a PAM idea.** Teleport access requests have multi-reviewer approval for humans; Auth0 CIBA does per-action out-of-band approval. The difference is the binding to local execution plus the offline-verifiable per-person signature, not the second human by itself.
3. **Hash-chained audit is Verosek's too.** Our edge is per-approver signatures and the registry chain, which an auditor can verify without us. That is a security property (non-repudiation), and it stays in the pitch as one, not as a compliance feature.
4. **A funded team can copy any single row in 1-3 months** (RESEARCH.md section 2). The moat is the combination plus the published bypass corpus that shows it holds. Keep the corpus growing faster than anyone copies it.

Verdict on the moat: real, narrow, demonstrable. Script content binding and broker shell parity are the two rows nobody we found has, and both are TOCTOU findings that AppSec people recognise without explanation. The NF-1 finding (our own broker ran approved commands through cmd.exe, confirmed on Windows, `tests/security/test_m2_t12c_nf1.py`) is the first publishable finding and it is against ourselves, which buys credibility.

## 2. Who buys AI security here

Primary buyer: the AppSec or platform-security lead at a company with 200 to 2,000 engineers rolling out Claude Code or Cursor with production, database or payment access. Reports to the CISO; owns the pentest budget and the "approved tools" list. Unvalidated: 0 of 5 discovery calls done.

Buying triggers, in the order they are likely to appear in 2026:
1. **A pentest or red-team finding against the agent rollout.** The public record is now thick: Cursor ran workspace-defined Claude hooks without consent (CVE-2026-48124, CVSS 8.5, fixed in 3.0.0); an embedded bare Git repo's pre-commit hook ran under Cursor's agent (CVSS 9.9, April 2026); a malicious Claude Code marketplace plugin auto-approved `curl` and rewrote permission files (PromptArmor); trust-dialog bypass via `permissions.defaultMode: bypassPermissions` in a committed settings file; a symlink sandbox escape (CVE-2026-39861); Check Point's hooks and MCP config RCE (CVE-2025-59536, CVE-2026-21852). Every one of these is "repo-controlled config executed with the user's privileges before or without the consent prompt". Our signed bundle plus meet-drift is the direct answer, and the bypass corpus is the proof.
2. **An incident**: an agent ran a prod command, a refund, or a `DROP`. Nobody can show who approved it. The ask is "show me who approved what and prove the record wasn't edited".
3. **An internal policy**: "no agent production action without a second human". The ask is "how do you enforce that on a developer laptop, Windows included".

What the buyer asks for first: the bypass suite and the TCB document, before any demo. "Which of these bypasses do you stop, which do you not, and what runs as root." We have both (`docs/BYPASS_SUITE.md`, `docs/TCB.md`, `docs/THREAT_MODEL.md`). No competitor in RESEARCH.md publishes either.

Secondary buyers: security-tooling vendors who need a local-execution approval layer to OEM or acquire (CrowdStrike, Palo Alto, SentinelOne, Snyk and Check Point each bought an AI-security startup in 2025-26); red teams, who consume the corpus and will extend it for free if it is public.

Competitor targeting (web, 28 Oct): Arcade sells to platform and engineering teams with security as a supporting line ("which agent took which action, on behalf of which user"); Runlayer leads with security ("protect agents from rogue MCP servers, zero-trust per tool call") and was named to Morgan Stanley's Rising in Cyber 2026 list. Neither sells local-execution approval. The security buyer is contested by Runlayer at the MCP/network layer and uncontested at the local shell/script layer.

## 3. Security-native distribution the founder can reach

| Channel | What it needs | Time to first result | Why it does or does not win |
|---|---|---|---|
| **Public cross-tool bypass suite** | Freeze the rule and the 427-case corpus; run it once against Claude Code native permission rules, Cursor hooks, lasso mcp-gateway and our connector; publish every number, misses included | 2 weeks | Measurable, repeatable, it is the first thing the buyer asks for, it feeds every other channel, and it is our own regression gate. Nobody in RESEARCH.md publishes one |
| Published findings / disclosures | NF-1 write-up (against ourselves) now; later, findings against other tools with coordinated disclosure | 1 week for NF-1; months for third-party CVEs | High credibility, one-shot each, and disclosure against competitors needs legal care a solo founder cannot afford yet |
| CFP talks | WISTP 2027 paper deadline 9 Dec 2026 (scope includes agent hijacking, tool poisoning, MCP); USENIX SAIS '27 deadline 4 Feb 2027; CODASPY 2027 covers authorization for AI agents (deadline not confirmed); practitioner CFPs (BSides, RSAC 2027) not confirmed in this search | Talk in Mar-Jun 2027 | Slow. Worth one submission built on the suite, not as the bet |
| Security newsletters and podcasts | A published suite with results other tools fail | Days after publishing | Free amplification, but only once there is something measured to link |
| OSS connector as the reference implementation of the threat model | Directory listings (mcp.so, claudemarketplaces.com, Cursor third-party hooks page), README rewritten around the threat model and the suite | 2 days to list; months to pull | 0 stars today. Listings alone made Vantagate a $49/month product. Needed, not sufficient |
| Bug-bounty-style challenge | "Get a privileged action past the connector without a valid signed approval"; a public leaderboard | 1 week to set up | Needs an audience the other channels create first |

**The one 90-day bet: the public cross-tool bypass suite, published with the NF-1 finding as its first case study.** It beats the others because it is the only channel where the thing is already 80% built (427 cases, frozen method, measured timing), it answers the buyer's first question, and every other channel (talk, newsletter, disclosure, challenge, OSS pull) is downstream of it. The rule from RESUME.md applies: write the rule and freeze the test set before the run, run once, publish the result whatever it is. If Claude Code's native permission rules pass more of the corpus than expected, publish that too; a suite that only flatters us is marketing, not security.

## 4. Does the verdict change?

Partly. Under the governance positioning the most likely outcome was "feature of someone else's platform" with a bootstrap niche as the realistic good case. Under the security positioning:

- **Standalone niche SaaS gets less likely.** Security buyers consolidate onto platforms they already pay for (CrowdStrike, Microsoft, Palo Alto ship agent hooks inside existing licences). A self-hosted point product from a solo founder has a harder sell to a CISO than to a compliance lead.
- **Acquisition or acqui-hire gets more likely.** Eight AI-security startups were bought in 2025-26 (RESEARCH.md 1g). A published suite that incumbents fail, plus a reference implementation with a clean TCB, is exactly the artifact that gets a founder a conversation with CrowdStrike, Palo Alto, SentinelOne, Snyk, Teleport or StrongDM.
- **"Feature of someone else's platform" stays the base case**, because Anthropic and Cursor are patching the same class of bug and will keep adding native controls.

**Revised single most likely outcome: acquisition-scale or acqui-hire by a security vendor, reached through a published bypass suite and one design partner, with "feature of a platform" as the fallback.** Venture scale is not on the table with the current distribution. The security positioning does not make the company bigger; it makes the exit path clearer and the required proof cheaper (a suite and one AppSec reference, not an auditor and a GRC integration).

## 5. Revised scope

Keep or accelerate (this is the moat):
1. **T12c c2 and c6** (content binding, NF-1 shell parity, the e2e script-swap scene). Accelerate. Extra tests 6 and 7 (Windows handle pin, POSIX after-run self-swap) are now kept, not paused: they are the proof that the TOCTOU window is closed on each OS, and the suite needs them.
2. **T16 scene 5(d)** (bob approves, the agent edits the script, carol approves, the broker refuses with a signed `SCRIPT_CHANGED`). This is the demo. Also the frozen measure of how often the agent retries after `SCRIPT_UNPINNABLE`.
3. **The bypass corpus** (`tests/security/bypass_corpus.jsonl`, `docs/BYPASS_SUITE.md`): extend it with the 2026 public CVE patterns (workspace hooks, Git hooks, settings-file `bypassPermissions`, plugin auto-approve) and a cross-tool harness. New small task, before T17.
4. **T12d happy path** (genesis, second-genesis refusal, CLI `genesis` and `sign-registry`, the D0 findings already fixed). A registry an attacker can bootstrap twice is a security hole, so this stays. The candidates route and the migrate.py code-emission rules wait for the first real install.
5. **Step 11 offline evidence verify.** Kept as a security property (tamper detection, per-approver signature check), described as such, with the AIUC-1 index left in the pack but out of the pitch.

Pause (governance-shaped):
1. T12c c5 web script panel. Ship the plan's "Approve disabled for script escalations, approve in the CLI" fallback. The AppSec buyer approves from a CLI anyway.
2. The JSONL/OCSF evidence export (SENTRY_IDEAS #4). **Demoted back to M4.** Under the security positioning it is a SIEM integration, useful later, not a moat piece. My earlier pull-forward was for the GRC channel and no longer applies.
3. SENTRY_IDEAS #1 (policy advisor) and all AIUC-1 / COMPLIANCE_MAP updates.
4. M3 planning until the calls and the suite run are done, with one exception below.

Bring forward for M3 (the moat's weak flank):
1. **Same-user bypass** (M2 limit 4) and **broker credential custody** (SENTRY_IDEAS #5, needs a security design ruling and an ADR). This is the question every AppSec engineer will ask after the demo. Even a design note with a measured statement of the gap is better than silence.
2. **Cursor and Codex hook adapters** (RESEARCH.md correction to ADR 0006). The suite is only cross-tool if the connector runs on more than Claude Code.

Process: keep the leader-tier security loop for TCB files (`approval.py`, `broker.py`, `privilege_broker.py`, `script_pin.py`, `registry.py`, `hook_eval.py`). One worker-tier review for web, routes and migrations.

## 6. Founder actions, next 2 weeks (not engineering)

1. **Freeze and run the suite.** Write the cross-tool rule (what counts as a pass for a tool that has no "escalate", how "ask" is scored, which version of each tool), freeze the corpus, run once against Claude Code native rules, Cursor hooks, lasso mcp-gateway and the connector. Publish the table in `docs/BYPASS_SUITE.md` and in a post. Misses included.
2. **Publish the NF-1 finding.** "Our broker ran approved commands through cmd.exe on Windows; here is the test, the fix and what reviewers were really approving." Measured numbers only.
3. **Re-target the 5 discovery calls** to AppSec, platform-security and red-team leads. First question: "Has anyone pentested your coding-agent rollout, and what did they find?" Then the four SENTRY_IDEAS questions. Keep the pricing hypothesis unvalidated and say so.
4. **One CFP submission** built on the suite: WISTP 2027 (9 Dec 2026) is confirmed; check BSides and RSAC 2027 dates on their official pages before choosing.
5. **List the connector** on mcp.so, claudemarketplaces.com and the Cursor third-party hooks page, with the README rewritten around the threat model and the suite. Navrina stays a warm contact; the ask shrinks to "which of your customers' security teams would run a public bypass suite".

## 7. Kill criteria (2026)

| Date | Evidence required | If it fails |
|---|---|---|
| 15 Nov 2026 | The cross-tool suite run is published with every number, and the NF-1 post is live. | The founder is still building, not showing. Stop all M3 work until both are done. |
| 30 Nov 2026 | 5 discovery calls done with AppSec or red-team leads. At least 2 of 5 report a pentest finding or incident on their agent rollout, or say they would run the suite. | The security pain is unvalidated at this buyer. Finish T16/T17 only; no M3. |
| 15 Dec 2026 | One external security team has run the suite or opened an issue or PR against the corpus, or one vendor (OEM, partner or acquirer class) has taken a technical call. | Security positioning has not produced distribution either. Package the suite and the MIT connector as the reference implementation, and take the founder's knowledge to an acquirer-class vendor; or stop. |
| 31 Dec 2026 | One named design partner running the compose stack with a non-founder human signing approvals, or a written OEM or partnership intent from a security vendor. Secondary: 25+ stars or 3+ external issues/PRs. | Distribution has beaten the product. The options at 15 Dec apply. |

A date that passes with the evidence present moves the base case from "feature of a platform" to "acquisition with leverage", and the next PM assessment is about who the acquirer-class conversations are with and what one paying design partner is worth.

## Positioning check

Security as the moat keeps us on the wedge (runtime authorization plus signed multi-party evidence, cross-vendor, self-hosted) and off governance. It must not drift into prompt-injection detection or an LLM gateway: the suite tests whether a privileged action can run without a valid signed approval, not whether an injection is detected. Verosek and Prisma AIRS own detection; Credo AI stays complementary and out of the pitch.

## Honesty notes

- No traction: 0 customers, 0 design partners, 0 stars, 1 call (Navrina, 11 Oct), 0 of 5 discovery calls done.
- The bypass numbers describe our corpus only; a corpus is not a proof. Cross-tool numbers do not exist yet and must be published whatever they say.
- The same-user bypass (M2 limit 4) is open. Say it in every demo.
- CVE severities and competitor funding are press and NVD figures, not independently verified.

## Sources

Repo (E:\architecture-mcp): STARTUP.md; RESUME.md; TEAM.md; RESEARCH.md; docs\BYPASS_SUITE.md; docs\TCB.md; docs\THREAT_MODEL.md; docs\BRIEF.md; docs\ROADMAP.md; docs\control-plane\HANDOFF.md; docs\control-plane\T12B_PLAN.md; docs\control-plane\SENTRY_IDEAS.md; docs\adr\0010-remote-approval-binding.md (s9); docs\adr\0011-registry-genesis-bootstrap.md; tests\security\test_m2_t12c_nf1.py; git log a6f09c7 back to c1def07.

Web (read 28 Oct 2026):
- Cursor hook CVE: https://fieldguide.lutrasecurity.com/CVE-2026-48124/ ; https://mondoo.com/vulnerability-intelligence/vulnerability/CVE-2026-48124
- Spring 2026 coding-agent CVEs (Cursor Git hooks, Codex posture): https://codex.danielvaughan.com/2026/05/02/spring-2026-ai-coding-agent-vulnerabilities-cursor-rce-comment-control-codex-cli-defence/
- Claude Code plugin hooks auto-approving commands: https://promptarmor.substack.com/p/hijacking-claude-code-via-injected
- Claude Code CVE roundup (trust dialog, symlink sandbox escape, Check Point findings): https://www.thaicert.or.th/?p=12192 ; https://stack.watch/product/anthropic/
- Unverified "90.5% bypass" claim: https://www.secure.com/news/claude-code-safety-bypass-trusted-channel-injection
- GuardFall shell-bypass note (via RESEARCH.md): https://labs.cloudsecurityalliance.org/research/csa-research-note-guardfall-ai-agent-shell-injection-2026070/
- Arcade positioning: https://arcade.dev/blog/mcp-runtime-gateway ; https://www.hpcwire.com/aiwire/2026/06/16/arcade-secures-60m-to-scale-authorization-and-governance-for-ai-agents/
- Runlayer positioning: https://runlayer.com/blog/mcp-gateway-build-vs-buy ; https://www.tamradar.com/funding-rounds/runlayer-series-a-30m
- Vantagate: https://ai.g2.com/marketplace/tools/vantagate-mcp-server ; https://socket.dev/npm/package/@vantagate/mcp-server
- CFPs: WISTP 2027 (9 Dec 2026) and USENIX SAIS '27 (4 Feb 2027) via https://www.beri.net/events/usenix-sais-2027 and the WISTP call; CODASPY 2027 https://www.beri.net/events/codaspy-2027 ; NDSS 2027 deadline passed (19 Aug 2026) https://www.ndss-symposium.org/ndss2027/submissions/
- Public repo stats: https://github.com/Boredem125/architecture-mcp (0 stars, 0 forks, 28 Oct 2026)

---

# Appendix A: original governance-channel analysis (rejected by founder 28 Oct 2026)

Founder ruling: "i want ai security as moat not ai governance". Kept verbatim for the record; nothing below is current advice.

## A1. Is the premise right here?

### Where distribution dominates

1. **The enforcement point is a commodity.** RESEARCH.md section 1g counts at least 13 vendors and 3 OSS projects on Claude Code, Cursor and Codex hooks. Cursor launched its hooks programme with 8 partners (MintMCP, Oasis, Runlayer, Corridor, Semgrep, Endor, Snyk, 1Password). We are not on that list and have no route onto it. "We enforce shell commands" is table stakes, which RESEARCH.md already concluded on 18 Oct.
2. **The buyer already has a vendor.** CrowdStrike, Microsoft Defender and Palo Alto ship agent hooks inside licences the security team already pays for (RESEARCH.md rows 3-5). A security lead at a fintech will try the thing in the console they already open before they install a self-hosted Postgres stack from a solo founder with a 0-star repo.
3. **Funded competitors are buying distribution, not features.** Arcade raised a $60M Series A in June 2026 (SYN Ventures, Morgan Stanley, Wipro) and its press release leads with "authored the MCP authorization specification adopted by Anthropic" and named users (a top US bank, Prosus, LangChain). Runlayer raised a $30M Series A with 18,000 pre-built connectors and an AWS Marketplace listing. Spec authorship, marketplace listings and bank logos are distribution assets. Neither company's feature list is deeper than ours on signed dual control; both will out-distribute us regardless.
4. **Platform vendors are closing the gap natively.** Claude Code has managed hooks, `allowManagedHooksOnly`, `allowManagedPermissionRulesOnly` and `allowManagedMcpServersOnly`; Codex has `requirements.toml`; GitHub Copilot has org policies (RESEARCH.md section 1f, confirmed by the TrueFoundry and systemprompt.io guides). When Anthropic adds a central approval inbox, the question "why not just use Claude Code's" gets asked in every call.
5. **The OSS connector has zero pull today.** The public repo (github.com/Boredem125/architecture-mcp) shows 0 stars, 0 forks, 0 watchers on 28 Oct 2026. The README is about Claude Code; Codex, Cursor and Windsurf get only the MCP tools. A one-person project called Vantagate reached G2, mcp.so and claudemarketplaces.com with an npm package, Slack approvals and HMAC-signed decisions at $0/$49/$199 a month. Its product is shallower than our connector by a wide margin. It has distribution we do not.

### Where product creates distribution (narrowly)

Product-led pull exists in exactly one place for this company: the evidence pack.

1. **Auditor demand.** AIUC-1 now has Schellman as its first accredited auditor, Drata ships it as a native framework (July 2026), CSA lists it on the STAR Registry (June 2026) and AIUC itself raised $40M in September 2026 to audit frontier models. The CSA note says 250+ Fortune 1000 CISOs are members. None of these parties produces runtime evidence of "two named humans approved this agent action". We do. An auditor who accepts one of our packs in one real audit is worth more than any feature (RESEARCH.md section 3, point 5). That is distribution the product earns, and it is the one channel where our depth is the asset rather than the cost.
2. **GRC ingest.** Credo AI (Navrina, 11 Oct call), Drata and Vanta all hold AIUC-1 policy and controls and need a runtime evidence source. The JSONL/OCSF export (SENTRY_IDEAS.md #4) is the hook for that channel. It is scheduled for M4. It should be the first thing a GRC partner sees, not the fourth milestone.
3. **Design-partner referrals.** Only after one exists. Today there are none.

What does not create distribution: script content binding, registry genesis bootstrap, four-round security reviews, 2,171 connector tests. These make the product correct. Correctness is necessary for the auditor channel and irrelevant to every other channel until a buyer is in the room.

So the honest split: distribution dominates for the security-tooling buyer (which is 4 of the 5 channels), and product depth matters only for the compliance buyer, through one artifact (the pack) and one door (an auditor or GRC platform saying yes).

## A2. Scale verdict

- **Venture-scale SaaS:** unlikely. A solo founder with no distribution, in a category where 13+ funded vendors own the enforcement point, platform vendors own the agent, and acquirers have already consolidated eight startups (RESEARCH.md section 1g, point 5). The unique bundle (signed dual control, non-loosening policy change, AIUC-1-indexed offline pack) is estimated at 1-3 months of work for a funded competitor (RESEARCH.md section 2, plain verdict). A moat of 1-3 months does not raise a Series A.
- **Niche or bootstrap SaaS:** possible, and the realistic good case. 5-20 regulated customers who need the pack for an audit, self-hosted, priced per approver seat or per connector. This case needs one auditor or GRC platform to accept the pack and one design partner to reference. It does not need T12d.
- **Acquisition target:** the upside case, conditional on the same two proofs plus a public evidence spec aligned with the IETF counter-sign draft. Identity/PAM vendors (Okta, Teleport, StrongDM, CyberArk) and GRC platforms are the natural homes because "two humans approved this privileged action" is a PAM idea.
- **Feature of someone else's platform:** the single most likely outcome. Either Anthropic, Cursor or a GRC vendor ships signed multi-party approval and the independent layer becomes a reference implementation and a hiring conversation, or a partner (Credo AI, Verosek, Drata) takes the evidence format and the founder's knowledge.

Why "feature" is most likely: every piece of the wedge is small for a team with distribution, the evidence spec is not published, the OSS has no community, and the founder's calendar for the last week shows engineering only. The way to move the most-likely outcome from "feature" to "niche SaaS" or "acquisition" is not another milestone. It is one auditor sentence and one named design partner, both of which are sales work.

## A3. Distribution the founder can actually reach

| Channel | Status today | Cost to try | Fit with what is built |
|---|---|---|---|
| Credo AI via Navrina | Warm. Blurb and intro ask sent 25 Oct. No reply recorded. | One follow-up email, one call | High: Credo sells to the compliance buyer who needs runtime evidence; AIUC-1 is in their product |
| AIUC-1 auditors (Schellman first) and GRC (Drata, Vanta) | Not contacted | One cold email each; a 30-minute call | High: the pack is the only thing we have that they lack |
| OSS connector and MCP directories (mcp.so, claudemarketplaces.com, Cursor hooks docs) | 0 stars; not listed anywhere | 2 days | Medium: install still needs `sandbox init` on a Windows laptop with Git bash; no 5-minute path yet |
| AI coding tool vendors (Cursor partner list, Anthropic) | No contact; 8 incumbents on Cursor's list | Months, no lever | Low for a solo founder today |
| Discovery calls with fintech security/platform leads | Assigned 24 Oct; 0 of 5 done | Founder's time only | This is the gate for everything else |

**The one bet for the next 90 days: the compliance channel.** Concretely, get one written sentence from an AIUC-1 auditor or from Credo AI/Drata saying the offline-verifiable pack counts as evidence for a named control, and use that sentence to land one design partner. Navrina is the warm door; Schellman is the cold one. Everything built since M0 serves this channel. No other channel values it.

The OSS directory listings are cheap enough to do in parallel but they are not the bet; Vantagate shows that listings alone produce a $49/month product, not a company.

## A4. Scope consequence for M2 and after

The current M2 plan (T12B_PLAN.md T12c c1-c6, T12d d1-d5, then T16, T17) over-invests in depth relative to the distribution evidence, which is zero. Each T12 sub-task carries a leader-tier security review of up to four rounds. That cadence was right for the TCB when the goal was correctness; it is the wrong spend when no buyer has seen the product.

Keep (needed for any demo or auditor conversation):
1. T12c c2, the NF-1 fix. The broker running approved commands through cmd.exe instead of the bash the reviewer saw is a confirmed High and would discredit the "what you approved is what ran" story in the first live demo.
2. T16 with demo step 11 (evidence export, offline verify) and the script-swap scene 5(d). Step 11 is the sales artifact.
3. T17 as a one-page quickstart. A design partner cannot install without it.

Pause (until a design partner or auditor asks):
1. T12c c5, the web script panel with WebCrypto hash gating. The plan already allows "Approve disabled for script escalations, approve in the CLI". Ship that fallback.
2. T12c extra tests 6 and 7 (Windows handle pinning, POSIX after-run self-swap) and the full resolver table. Keep the python/bash happy path and the `SCRIPT_UNPINNABLE` floor.
3. T12d beyond the happy path. Genesis, one second-genesis refusal, the CLI `genesis` and `sign-registry` commands. The 22 field-by-field refusal tests, the candidates route and the migrate.py code-emission rules can wait for the first real install. Today demo step 2 is the only consumer.
4. All M3 planning (SENTRY_IDEAS #1-#3, passkeys, break-glass). Do not plan M3 before the 5 calls are done; the calls decide its content.

Cut from the review process: the four-round leader-tier security loop for non-TCB code (web, server routes, migrations). One worker-tier review is enough there; keep the leader tier for `approval.py`, `broker.py`, `registry.py` and `hook_eval.py`.

Move earlier: the JSONL evidence export (SENTRY_IDEAS #4, currently M4). It is the GRC-partner handshake and it is small (S). It should ship before any M3 feature.

What the founder does in the next 2 weeks that is not engineering, in order:
1. Run the 5 discovery calls (already assigned 24 Oct). Fintech or health security/platform leads running Claude Code or Cursor. Ask the four SENTRY_IDEAS questions plus one: "Who signs off on an agent's production action for your auditor today, and what do they get as proof?"
2. Follow up with Navrina with one ask only: a 30-minute call with one Credo customer, or a yes/no on whether Credo would ingest a JSONL pack.
3. Email Schellman (first accredited AIUC-1 auditor) and Drata's AIUC-1 team: "Would an offline-verifiable pack of signed dual-control approvals count as evidence for controls X and Y? 30 minutes." Attach the pack from demo step 11 once T16 runs.
4. List the connector on mcp.so, claudemarketplaces.com and the Cursor third-party hooks page. Publish one honest post: the NF-1 finding ("our own broker ran approved commands through cmd.exe; here is the fix and the test"). Measured numbers only.
5. Write the pricing hypothesis to test on the calls (per approver seat vs per connector, self-hosted). It is unvalidated; say so on the call.

## A5. Kill criteria (all within 2026)

| Date | Evidence | If it fails |
|---|---|---|
| 15 Nov 2026 | 5 discovery calls done. At least 2 of 5 say an agent action at their company needs a second approver today, or an auditor has asked them to prove who approved agent actions. | The pain is unvalidated. Stop M3 planning. Finish T16/T17 only. |
| 30 Nov 2026 | Credo AI: one customer intro made, or a written yes on ingesting the pack. Or one auditor/GRC call held (Schellman, Drata, Vanta). | The compliance channel is closed to us. Treat the product as a reference implementation; stop the control plane. |
| 15 Dec 2026 | One named design partner has run the compose stack with a non-founder human signing an approval, or one auditor/GRC vendor has said in writing that the pack counts as evidence for a named control. | Distribution has beaten the product. Options: (a) keep the MIT connector as a portfolio piece and seek a role at an acquirer-class vendor; (b) pivot to the evidence format only, as a spec plus verifier offered to Credo/Drata/counter-sign; (c) stop. |
| 31 Dec 2026 | OSS: 25+ stars or 3+ external issues/PRs after listing in 3 directories and one post. | No OSS pull. Do not invest further in the OSS channel; it will not carry the control plane. |

## A6. Positioning check and honesty notes (original)

Everything in M2 stays on the wedge (runtime authorization plus signed multi-party evidence, cross-vendor, self-hosted). SENTRY_IDEAS.md rejected the detection and network-gateway ideas, which keeps us out of Verosek's and Prisma AIRS's lane. Credo AI stays complementary. One warning: Arcade's "we wrote the MCP authorization spec" shows that owning a spec is a distribution act. RESEARCH.md put "own the evidence format" first on the list of things that would make us the default choice, and it has not started.

- No compliance claim is made here. The AIUC-1 map is self-assessed (5 supported, 16 partial, 30 not covered, docs/AIUC-1_MAP.md).
- No traction exists: 0 customers, 0 design partners, 0 stars, 1 call (Navrina, 11 Oct), 0 of 5 discovery calls done.
- Competitor funding figures are press figures, not verified filings.

Original web sources (governance channel): https://drata.com/updates/new-framework-support-aiuc-1 ; https://drata.com/updates/aiuc-1-version-update-july-2026 ; https://siliconangle.com/2026/09/15/ai-agent-certification-startup-aiuc-raises-40m-to-begin-auditing-frontier-models/ ; https://labs.cloudsecurityalliance.org/wp-content/uploads/2026/09/CSA_research_note_third_party_ai_assurance_standards_20260927-csa-styled.pdf ; https://zeltser.com/aiuc-1-cert ; https://www.truefoundry.com/blog/claude-code-governance-building-an-enterprise-usage-policy-from-scratch ; https://systemprompt.io/guides/enterprise-claude-code-managed-settings ; https://www.gravitee.io/corpus/gen-2054/multi-party-authorization/human-in-the-loop-approvals.html ; https://www.pymnts.com/?p=3850692

---

# PM response to architect review, 28 Oct 2026

Input: `docs/ARCH_REVIEW_PM_DISTRIBUTION.md` (lead-architect, CONFIRM WITH AMENDMENTS). The founder has not ruled on its five questions. This section supersedes sections 1, 5 and 7 above where they conflict. Where I accept a correction, the section above is wrong and this one is right.

## 1. Corrections to the moat claims

| Architect correction | PM position | What settles it |
|---|---|---|
| Shell parity is not a differentiator; NF-1 was our own bug | **Accept.** Native agents run in the shell they parsed. The gap existed only because we added a broker. NF-1 goes in the pitch as a self-found, measured, fixed finding, which is still worth publishing, and not as a moat row | `tests/security/test_m2_t12c_nf1.py` docstring: the bug is `subprocess.run(command, shell=True)` in `PrivilegeBroker._execute_approved`, our code |
| The TOCTOU window is mostly self-created by async approvals | **Accept, with one addition.** The window is inherent to any approval by a second human who is not at the keyboard, so every remote-approval product (Vantagate, Auth0 CIBA, Permit, HumanLayer) has it and none we found binds content. That is the row to keep: the reviewer sees and signs the script body and the broker refuses changed bytes | ADR 0010 s9 (fingerprint v2 includes `script_sha256`; `SCRIPT_CHANGED` refusal) |
| Only the one named file is bound; POSIX detects after the run | **Accept.** The demo line names the scope every time: "Only `<rel>` is bound; imports, runners, interpreters and config are not (S-L1 to S-L3); on POSIX a mid-run change is detected after the run, not prevented (S-L4); the human signs the scrubbed preview hash (S-L6)" | ADR 0010 s9 lines 96-101 (S-L1 to S-L6) |
| The handle pin is not built yet | **Accept.** c2 is uncommitted; nothing is claimed until it merges with CI green | Working tree per the architect's section 1 |
| The signed bundle and meet-drift are not the direct answer to the 2026 repo-config CVEs | **Accept.** Protected paths stop our governed tools from rewriting `.claude/settings.json` and `.git/**` mid-session; they do not stop a cloned repo that ships them, a plugin process (limit 4) or a git hook under an approved commit. We expect misses in X2 and publish them | `docs/BYPASS_SUITE.md` protected_path class (52 cases, all mid-session writes through the hook) |
| The fail-closed row relies on the same `onFailure: block` as the natives | **Accept.** The row is removed from the competitor table | `src/sandbox/connector/install.py:85,403,524` (`_MIN_CLAUDE = (2, 1, 295)`, SEC-28) |
| Competitor "No" cells are unverified | **Accept.** They read "not found in public material" from now on | RESEARCH.md convention ("N?") |

**The moat, restated for an AppSec buyer, two sentences:** "When your coding agent needs to run `python deploy.py` against prod, two named people see the script body, sign it with keys that only they hold, and the broker refuses to run anything but those bytes; the requesting developer cannot be one of the signers, and nobody can loosen the policy that required them without a second signature. We do not yet stop a process running as the same OS user from going around the hook; we tell you exactly what is bound and what is not, and we publish the bypass results that show it."

## 2. The suite at about 15 days

The bet holds. Nothing else on the channel list is cheaper or earlier, and every alternative (talk, newsletter, disclosure, OSS pull) still needs the suite as its input. The cost correction changes the date and the first cut, not the bet. One lane-X honesty point I add: the risk table's "our own misses on the CVE scenarios" row is the most valuable row in the whole publication with this buyer. An AppSec lead trusts a vendor that publishes its own misses before anyone else finds them.

**Minimum publishable cut by 15 Nov** (X0 to X4 plus X2, about 7 days of lane X, started now while c2 to c4 run):
1. X0 frozen rule, committed with its hash, signed by security and QA.
2. The NF-1 write-up, with the fix commit linked (N1 in the architect's table; founder yes before any post).
3. Corpus v2 (neutral, canary actions) and the X2 CVE scenarios, run against the connector only, on Linux and Windows, with our misses listed and each miss tied to ADR 0012 or to the managed-settings install mode.
4. v1 reported separately as our own regression gate, labelled "built with the classifier, 48% self-referential", never as a cross-tool number.

**Moves to 30 Nov:** X5 and X6 (native Claude Code and Cursor adapters), X8 the cross-tool run, X9 the fairness review and disclosure notes. Any native row that shows a real bypass is published as "withheld, disclosed to the vendor on `<date>`" rather than holding the table.

Constraint I want the founder to see: lane X and the M2 critical path (11 days to about 12-13 Nov) share one agent team and one weekly usage limit (RESUME.md). If both cannot run, the M2 gate comes first and the 15 Nov cut slips to the cross-tool date. In that case 15 Nov keeps only items 1 and 2 (rule and NF-1 post), which are documents, not builds.

## 3. T12d d2-d5

**Accept.** A registry with one key is not dual control, and no `sign-registry` means no revocation. My "happy path" cut was wrong on the mechanism: the candidates route, `sign-registry` and `migrate.py` emitting the code are the happy path. Restated M2 scope: the architect's section 3 table as written (c2, c4, d2, c3, d3, c5, c6, d4, d5, T15b, N1, T16, T17), gate about 12-13 Nov. Against the kill dates: the 15 Nov date now tests the rule, the NF-1 post and our own v2 numbers (section 2); the 30 Nov date tests the cross-tool table and the 5 calls; 15 Dec and 31 Dec are unchanged.

## 4. c5 web panel

**Withdraw the pause.** The founder ruled on 25 Oct, the panel is about 80% built, and the fallback costs the same 0.5 day plus test churn. Keep c5 at the architect's slot 3'.

## 5. Same-user bypass and the buyer

Yes, we can publish and run the calls with it unfixed, if it is disclosed in the first minute and not the third. With this buyer a named, scoped limit is an asset; a limit they find themselves is a lost deal. The line, when the AppSec lead asks "what stops the agent from just running kubectl without your hook": "Nothing on the same OS user today. We prove the integrity of the governed path: what two people signed is what ran, for the one bound file; no self-approval; no loosening. We do not prevent a same-user process going around the hook. ADR 0012 moves prod and payment credentials into a separate broker identity so a bypass can still run commands but cannot deploy or refund. On Linux and macOS we recommend Claude Code's sandbox as the compensating control. Do your agents hold prod credentials on laptops?" That last question is the ADR 0012 precondition, so the demo and the discovery call do the same job.

Two buyer-side points for ADR 0012:
1. A service account installed once per laptop with admin rights is an MDM rollout, which puts IT in the sale. Add to the 5 calls: "Can your endpoint team push a service to developer laptops, Windows included?" If 2 of 5 say no, option (c) server-side executor for CI moves up and ADR 0012 shrinks.
2. The 20-day size is M3's whole budget for a solo founder on a weekly limit. It is the right exit item only because it turns the suite's worst published miss into a fixed one. No prevention claim in any material until it ships, as the architect says.

## 6. Recommendations on the architect's five questions (plus one)

1. **c5:** keep it; I withdraw the pause.
2. **Spend and disclosure:** approve the $50-150 and one Cursor seat; approve vendor disclosure before publishing any native bypass row, and publish the table on time with those rows marked withheld.
3. **Kill dates:** split them; 15 Nov = frozen rule, NF-1 post, our own v2 numbers incl. misses; 30 Nov = cross-tool table and the 5 calls.
4. **ADR 0012:** accept as M3 exit item 1 with the architect's precondition (2 of 5 calls confirm prod credentials on laptops) plus the MDM question above.
5. **lasso:** exclude from the shell suite with the one-line reason; MCP sub-suite in M4.
6. **Review tiers (architect section 2 row 11):** accept leader tier for d2 (genesis, scope rule) and the c4 approvals-route check; worker tier for c5, migrations and demo.py.
