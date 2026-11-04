# M3 plan, product section (product-manager, 4 Nov 2026)

Status: input for lead-architect to merge into `M3_PLAN.md`. Nothing here is a ruling; the founder decides section 6. Evidence base: the founder's own trial of the M2 control plane on 4 Nov ("did we even build something?"), the 4 Nov clean-clone follow of `QUICKSTART.md` (free layer 6-8 minutes; the paid layer needed a 25-minute script of the follower's own because enrollment codes and bundle publishing are raw route calls), and `ee/web/src` (629 lines: a login card, one inbox table, a project list with members). Customer evidence: none. 0 of 5 discovery calls done, 0 design partners, 1 call (Navrina, 11 Oct). Everything below is unvalidated until the calls land.

## 1. The M3 statement (one paragraph, investor and design partner)

M3 turns the control plane into something a security lead can run as a two-week pilot without us on the call. Today the free security layer (MIT) blocks dangerous coding-agent actions on the developer's machine and works on one laptop; the paid control plane (self-hosted, cross-vendor) adds what a security team needs to roll it out across an org: named people approving from a browser with keys bound to their identity, two different humans for every loosening, a central tamper-evident audit, and evidence that verifies offline. In M2 every piece of that was proven on one Windows laptop (88 of 88 gate checks, 4 Nov 2026) but driving it needed raw API calls and the founder's own scripts. M3 ships the web app and the one-command deployment so a design partner's own admin enrols a device, publishes a policy with two approvals, sees the first agent escalation, approves it with a colleague, and downloads the evidence, all without a terminal on the admin side and without a call to us. Success is measured, not claimed: one named non-founder completes that path from a clean machine, timed, with zero raw route calls.

## 2. The buyer's first week through the web app

Who logs in: the security lead as org admin (alice in the demo), a second admin who publishes policy (carol), one or two approvers (bob), and the developer whose device is enrolled (the operator, who only uses the CLI). Day 1 is admin setup and enrolment; day 2 is the first policy and first approval; days 3-5 are approvals, audit and the evidence pull.

| Rank | Screen or action | What the buyer must see and do | One-line reason |
|---|---|---|---|
| Must | Enrollment codes (admin) | Pick project and operator, issue a code, see it once, see it consumed or expired | Day 1 is blocked without it; today it is `POST /api/v1/admin/enrollment-codes` plus a GET from another session |
| Must | Devices per project | Device id, operator, state (locked, managed), last sync, last audit upload, pinned root fingerprint | The admin cannot tell whether enrolment worked; the 4 Nov follow had to read `sandbox status` on the developer side |
| Must | Bundle publish (admin) | Paste or upload the policy JSON, see the bundle hash and environment, attach two CLI change approvals, publish; the server verifies them (closes named limit 7.1) | Today a 25-minute script; this is backend item (b) and the step where M2 was "not a product" |
| Must | Inbox with context | What exists today, plus: escalation shows approvals counted so far by person and key kind, and why an approval did not count (carol's admin key: server stored it, connector refused it, nobody was told) | The one screen the founder saw; the silent non-counting approval is the "nothing happened" moment |
| Must | One-command deployment | One script on a Linux VM with a real hostname: secrets, Keycloak realm, first admin, genesis code printed once | Backend item (c); a pilot on a partner's VM cannot start with a hosts-file hack and `--ca` |
| Should | Audit per project | Record count, chain head, verify result, quarantine rows, with a download of the org evidence pack | Week-one proof for the security lead; today it is `psql` or the device-side CLI |
| Should | Alerts | `sync_alerts` list: fork, truncation, device silent, bundle refused, with device and time | A pilot that cannot show an alert cannot show the control plane noticed anything |
| Should | Bundle history | Sequence, hash, who published, who approved, when each device applied it | The "prove who loosened what" question; cheap once publish exists |
| Cut | Policy editor, rule packs, syntax help | Paste JSON only | Six verified OSS projects already have policy syntax (COMPETITIVE_CHECK s3); it is not where we win |
| Cut | Hosted multi-tenant service | Self-hosted compose on the partner's VM | Months of work plus license enforcement; the buyer we describe keeps agent logs inside their network |
| Cut | Dashboard, charts, SIEM export | None in M3 | SIEM export is M4; a pilot needs a working path, not a view |
| Cut | Device quarantine actions, remote stop | Read-only state only; the "EDR for AI agents" button stays parked | Needs the ADR 0012 identity work and a call-validated buyer |

## 3. Success metrics and the M3 gate, buyer side

1. **Enrol to approved action without us:** one named person who is not the founder, on a clean machine, follows the quickstart from `compose up` to a dual-approved action and an evidence verify. Pass: done in under 60 minutes, time and name recorded, zero raw HTTP calls and zero scripts of their own.
2. **Raw route calls left in the quickstart:** 0. `m2_gate.py` remains a test driver, not a step a human needs.
3. **Time to first approval:** from escalation upload to the second signature, two people in two browsers, names recorded (this also closes M2 gate item 7, second clause, which is still "[not recorded]"). Publish the number whatever it is.
4. **The founder's own re-run:** the founder repeats the week-one journey and never opens a terminal on the admin side. If the answer to "did we build something?" is still no, M3 is not done.
5. **Outcome, not a gate item:** one named design partner runs the stack for five working days with one approval by their own person. That is the 31 Dec kill criterion; M3 makes it possible, the calls make it happen.

## 4. Scope cuts I insist on, and what they save

1. **No policy authoring UI.** Paste JSON, show the hash. Saves about a week of frontend plus review, and keeps us out of a commodity.
2. **No hosted service.** One command on the partner's Linux VM with their DNS name and certificate. Saves a month, a new threat model and license enforcement. Revisit only if 2 of 5 calls refuse to self-host.
3. **Security follow-ups limited to 7.1 and the five T16g (Low) items.** ADR 0012 (same-user broker identity, about 20 days) waits for its stated precondition: 2 of 5 calls confirm prod credentials on laptops. Saves M3's whole budget from going to one item nobody has asked for yet.
4. **No customer IdP integration work.** Keep the bundled Keycloak and document "point it at your IdP". Build only when a named partner names theirs.
5. **No new free-layer features.** Script families, Cursor and Codex hook adapters and the bypass suite run in Lane X on their own dates, not in M3.

## 5. Three questions for the researcher's market check

1. Do Runlayer, Noma and the native vendors (Claude Code managed settings, Cursor's hooks programme) offer a self-serve pilot today (enrol, set policy, approve in a browser, no vendor call), and what does their first hour look like in steps and minutes? This tells us whether "pilot without us" is table stakes or a lead.
2. For security buyers at 200-2,000-engineer companies, is a self-hosted compose stack on their own VM an acceptable pilot shape, or do pilots in this category start from a hosted tenant or a cloud marketplace listing? Evidence from how Runlayer, Teleport and StrongDM run pilots.
3. What do Indian pre-seed investors writing 1.5-2.5 cr INR cheques into security or devtools expect as evidence at this stage (design partners, paid pilot, OSS pull), and what did comparable agent-security pre-seed rounds in 2025-26 show at the time of raising?

## 6. Open founder decisions

1. Deployment shape for the pilot: one-command self-hosted on the partner's VM (my recommendation) or a hosted tenant we run.
2. Whether the live two-person run (M2 gate item 7, second clause) is done in-house during M3 or waits for the first design partner.
3. The security ride-alongs: 7.1 plus the five T16g items only, ADR 0012 deferred on its precondition. Yes or no.
4. The investor paragraph in section 1: approve the wording, with no number beyond the measured ones.
5. Kill-date coupling: PM_DISTRIBUTION section 7 says 15 Nov without the suite run and NF-1 post means "stop all M3 work". Today's steer says the dates are decided by the calls, not by M3. State which rule binds M3 engineering time.

## Positioning check and risks

Every M3 screen strengthens the paid control plane (central policy, identity-bound approvals, org-wide audit, signed evidence; cross-vendor, self-hosted). The free security layer is untouched except CLI messages that tell the developer why an approval did not count. Nothing here is detection or a gateway; the inbox decides who may approve, not whether a prompt was injected. Never "authorization layer", never "audit edition". Credo AI stays a place our evidence could go, not a competitor.

Platform risk: Anthropic adding a central approval inbox to Claude Code managed settings would make the web app look native in every call; our answer is cross-vendor plus two named humans plus offline verify, and the suite numbers. Sales friction: Docker, Postgres and Keycloak on a security team's VM puts IT in the pilot; the MDM question from the 28 Oct assessment still stands. The one customer question to validate next: "If we sent you a compose file and a one-page quickstart, would your team run a two-week pilot on your own VM with two of your own people as approvers, and who would those two be?"
