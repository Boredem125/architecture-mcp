# ADR 0012: Broker OS identity (same-user bypass): design and measured spike

Status: Proposed (4 Nov 2026, lead-architect, M3 T0b). Design and spike only; the build is M4. Source: founder ruling 28 Oct 2026 ("ADR 0012 M3 exit item 1"), founder decision 2 of 4 Nov 2026 (design ADR plus spike, build M4), founder ruling T0b-4 of 5 Nov 2026 (task T15), `docs/ARCH_REVIEW_PM_DISTRIBUTION.md` section 6, `docs/control-plane/M3_PLAN.md` D7. Security leader ruling, identity and keys: "Security (L), 5 Nov 2026: ADR 0001 Amendment A9, ADR 0012 (design and spike definition only, no build), ADR 0013 including its partner-supplied certificate path (design only, T10's tests and diff review still to come) and ADR 0010 Amendment F3, as edited in this review and its addendum, are approved with S1-S4 as the cited rulings and none of the five guarded properties weakened, and plan edits P1-P9 are confirmed applied in `docs/control-plane/M3_PLAN.md`." Rulings S1-S4 concern M3's server and pilot work and none binds this design; the founder's 28 Oct and 4 Nov rulings do. The founder judges the spike record at gate item 10.

## Next action

1. Lead: freeze the spike numbers below, as ruled by security on 5 Nov 2026, with a hash, before the first run. They are thresholds, not results: Windows behaviour is unmeasured.
2. Security (L) and lead: run the spike as task T15 in the 30 Nov slice. The founder approved it on 5 Nov 2026 (ruling T0b-4): a standard local Windows user for Sp1, a broker account only as a fallback if a virtual service account fails, and one elevation on the founder's laptop, which the founder performs when the numbers are frozen.
3. M4 build precondition, unchanged: at least 2 of 5 discovery calls confirm that agents hold prod or payment credentials on laptops (0 of 5 done today), plus the answers to the MDM question.

## Context: the same-user bypass, stated precisely

**"Outside the agent" today means outside the agent's tool path, not outside its OS identity.** The hook, the queue, `sandbox sync`, the approver and `FolderBroker.execute` all run as the developer's OS user. `approval.py` calls `FolderBroker().execute` in-process on both the local and the remote path, and `broker.py` starts the child with `subprocess.run` under that same token, with only `PrivilegeBroker._clean_env` narrowing the environment. The key home's protection is a hook policy plus a user-only ACL that grants that same user (ADR 0007 1.2, 1.4). `docs/TCB.md` puts this out of scope by construction.

**The bypass.** Code running as the developer's user that does not pass through the agent host's `PreToolUse` hook. Examples: a plugin hook or an MCP server process started by the agent host; a process left running by an earlier allowed or approved command; code an approved command loads (S-L1) or a runner it starts (S-L2); a git hook under an approved commit; and the developer's own shell. Such code can, today:

1. Run any command with the user's credentials, such as `kubectl` or a payment CLI, with no hook call, no approval and no audit record.
2. Read the device key, CLI signer seeds and reviewer seeds in the key home, and so sign as the device or as any human whose CLI key is on this laptop.
3. Write `.sandbox/`: pending records, `session.json` with its shell paths, the local audit chain, the unsigned `high_water.json` and `enrollment.json`, and `pinned_root.json`. A signed bundle or registry that fails verification is refused, but replacing the pinned root changes what it is verified against, so its own registry, bundle and approvals can verify on this laptop. It can also edit the hook config and the installed connector.
4. Delete the markers and state and return to standalone (M2 limit 4, N6). The server sees only `device_silent` after a missed window.
5. Open the memory of the broker and its children, and swap a script on POSIX during a run (S-L4).

**What it cannot do.** Forge the signature of a human whose key is not on this laptop so that it verifies against the real root, or change what the server's chain says. An offline verifier given the real root still sees the difference. A tool call that the hook sees reaches none of the five: the hook denies it. A command the policy allows or a human approves runs as the user, and any code it loads is the bypass above. So the integrity claim stands on the governed path, and the prevention claim fails. **No material may claim prevention until this ships** (architecture review section 6).

## Options

### A. Separate OS user for the broker
A local account owns the custody store, and the broker process runs under it. This gives the boundary, but something must start the process. If the developer's user starts it with a stored password, that password is readable by the bypass, so A alone does not hold. A is the cheapest way to measure what breaks in `FolderBroker.execute`, which is why the spike starts there.

### B. Windows service with a restricted token
A service, installed once with admin rights and started at boot, so nothing in the developer's user holds a secret that starts it. It runs under its own service account, preferably a virtual account (`NT SERVICE\<name>`) with no stored password, and starts each approved child with a restricted token (design item 3). One admin install per laptop is an MDM rollout, which puts IT in the sale.

### C. Named pipe with a caller check
The channel between the hook or CLI and the broker. The pipe's ACL gives the operator's SID submit rights only, first-instance creation stops a squatter, and remote clients are rejected. The server reads the client's process id and SID, and the client checks the server's SID and connects at identification level, so a squatter learns nothing and impersonates no one. **The check identifies an OS user, not a human and not the agent:** any bypass code can connect. So the pipe grants only the right to submit, and each action's authority comes from a signature checked behind it. C over a broker running as the same user changes nothing; it is a transport for B, not an alternative.

### Considered on 28 Oct and not reopened
An OS sandbox around the agent (no Windows path; Claude Code's sandbox is the recommended compensating control on Linux and macOS). A server-side executor (strongest, moves execution off the laptop; revisit for CI, and it moves up if the MDM answer is no). Per-action short-lived credentials (an M4 add-on, since static secrets stay exposed).

## Proposed design (B with C, to be proved by the spike)

1. **Enforcement moves to the broker.** It re-verifies every signed approval itself: pinned root, registry, fingerprint, script pin. The hook becomes the advisory front end and keeps its role on the governed path.
2. **Custody.** Prod, payment and cluster credentials, the device key, the pinned root, `high_water.json` and the enrollment markers move to a store only the broker account can read. Everything else the broker reads to decide is either moved there too or re-verified by signature: `session.json` shell paths (read today at `broker.py` `_read_session`), the bundle, the registry and the audit chain head. The service's own code and interpreter are not writable by the developer's user. A bypass can still run commands, but without those credentials it cannot deploy or refund. Credentials the developer keeps in their own profile stay usable by a bypass; the customer has to move them.
3. **The child must not hold the broker's powers (lead refinement of the 28 Oct text, which ran the child as the broker identity).** Approved commands load code nobody bound (S-L1, S-L2), and the agent can write that code. A child with the full broker token could read the whole store and the device key. So each child gets a restricted token that cannot read the store or the device key and cannot open the broker, runs in a job object that kills it and its descendants when the action ends, and receives only that action's credentials through the env allowlist. Security ruled this a requirement and accepts the change to the 28 Oct text, because it only narrows what a child holds. A child never falls back to the full broker token. Residual: unbound code loaded by an approved action sees that action's credentials.
4. **Human signer keys do not move.** They must stay under the human's control. A CLI signer key on the same laptop as the agent stays readable by same-user code. The rule to state: an approver's key does not sit on a laptop running the agents they approve for. The operator exclusion already covers the operator's own key. In broker mode only registry-verified remote approvals count; a local seed under the user's profile does not, so `approval.local_fallback` has no effect there, whatever the signed bundle says (confirmed by security). **Dependency this creates:** remote approvals are non-prod only (N9), and `local_fallback` is today's only way to approve on prod (A3.3). So until a prod remote-approval path exists (M2 proposal A, a non-goal for M3), nothing that needs a prod approval can run in broker mode, and prod credentials are the reason for custody. The M4 build proposal must solve this first.
5. **Workspace access.** The broker identity needs read and write on the repository. ACL grants, the ownership of files children create, and git's dubious-ownership check are what the spike measures.
6. **Fail closed.** With broker mode on and the service missing, nothing runs. There is no fallback to same-user execution. Standalone OSS use stays exactly as it is today, with this limit stated, and never depends on the service.
7. **Other platforms.** Linux: a systemd service user and a Unix socket with `SO_PEERCRED` (28 Oct). macOS: no design yet. Neither is in the spike.

## Spike definition (Windows laptop, not a build)

**Rules.** The numbers and the action corpus are frozen, with a hash, in the spike record before the first run. It runs once and reports whatever happens (the adoption gate rule). No diff in `src/`, `ee/`, `tests/` or the CI files; the spike's code stays outside the product tree. Fake canary credentials only. On this laptop: E: drive only, the account runs with no profile load so nothing lands on C:, and one script removes everything afterwards.

**What it measures and the exit numbers (lead proposal, changed and accepted by security as thresholds on 5 Nov 2026). Every result below is still to be measured; nothing here says Windows behaves this way.** In particular: whether a restricted child can run these tools at all, whether a virtual account suits this laptop, whether Windows 11 Home's missing policy editors block the setup, and the real latency and C: growth.

| # | Measure | How | Exit |
|---|---|---|---|
| Sp1 | Boundary, not elevated | As a standard local user outside Administrators who owns the workspace, through PowerShell, Python and cmd (3 x 13 = 39 probes): read the device key, read a canary credential, write the pinned root, delete `high_water.json`, open the broker's memory, read a child's environment, signal the broker, squat the pipe, replace the service binary, replace a module or DLL the service loads, change the service config, take ownership, change the store ACL | 0 of 39 succeed |
| Sp2 | Boundary, Administrators member | The same 39 from an unelevated shell of a user in Administrators, then from an elevated shell, counted separately | No exit number; both counts go into the named limit below |
| Sp3 | Child containment | From an approved child under the restricted token: read the device key, read the store, read another action's canary, open the broker's memory, leave a process running after the action ends | 0 of 5 succeed; its own canary is readable |
| Sp4 | Compatibility | A frozen corpus of 20 approved actions through today's broker (python and pwsh scripts, `git status` and `git commit`, npm, `kubectl` against a fake config, the M2 gate's approved action), same-user as the baseline, then under the broker identity with the restricted child token | At least 18 of 20 with no per-command workaround; each failure named with a fix size |
| Sp5 | Script pin | The T12c kernel lock, opened under the broker identity, against the developer's user: write, delete, rename | 3 of 3 refused |
| Sp6 | Files left behind | After each writing action in Sp4: the developer can edit and delete the file, and `git status` works with no `safe.directory` edit | All pass, or the design change that gets there is named |
| Sp7 | Latency | Added time from submit to child start, 100 runs, against a same-session baseline | p95 added at most 500 ms; p50 and p95 reported |
| Sp8 | Install and removal | Scripted install and uninstall, before-and-after listing of accounts, services and ACLs, C: growth | One elevation prompt; at most 5 minutes; removal leaves nothing listed; at most 50 MB on C: |
| Sp9 | Blast radius and size | Node count of frozen tests that assume same-user execution (31 test files name `FolderBroker` today); re-estimate against the 28 Oct "about 20 d" | Reported, no exit number |

**Outcome.** **Go:** Sp1 and Sp3 to Sp8 all pass; the M4 build is proposed, subject to the precondition. **Narrow:** the boundary passes (Sp1, Sp3, Sp5) and Sp4 does not; propose custody with a per-action label for what cannot run under the restricted token. Such an action runs without custody credentials and is labelled unprotected; it never runs with the full broker token. **No-go:** any Sp1 or Sp3 probe succeeds and no fix is named; this ADR is rejected, the no-prevention wording stays, and the server-side executor moves up. The spike runs once: a probe that succeeds stays in the record as a failure, and a retest after a fix is a second, separately reported run, frozen the same way.

**What the spike cannot show.** One laptop on Windows 11 Home is not a managed fleet, MDM is not exercised, Linux is not measured, UAC bypasses are not attempted, and this is not a penetration test.

## Named limits (proposed wording, if built)

- A member of the local Administrators group can do everything this design stops. Same-user code on such an account may not need a prompt, since Microsoft does not treat UAC as a security boundary. So the boundary holds only for a developer account outside Administrators. Many developer laptops are configured the other way; Sp2 gives the counts.
- A bypass can still run commands as the developer and can still use credentials the developer did not move.
- Unbound code in an approved action sees that action's credentials.

## Consequences

- Nothing changes in M3 beyond this document and the spike: no product code, no claim, no change to M2 limit 4. Every demo keeps saying that a same-user process going around the hook is not prevented.
- The build, if approved, is one admin install per laptop, which makes this an IT conversation. The MDM discovery question decides how much of it survives.
- If built, it also closes the `high_water.json` Low limit and the "delete state to go standalone" half of limit 4.
- SENTRY_IDEAS #5 depends on this outcome.

## Security properties affected

If built: local enforcement gains a boundary the hook cannot give, and custody credentials become unreachable from non-elevated same-user code. This document weakens no guarded property, because it changes nothing yet. Its existence is not a mitigation, and no material may present it as one.

## Open questions

1. Ruled by security, 5 Nov 2026: the restricted-token rule (design item 3) is a requirement; the broker identity alone does not suffice.
2. Ruled by security, 5 Nov 2026: the exit numbers stand as changed above (39 probes, 5 containment probes, 18 of 20 under the restricted token), as thresholds until measured.
3. Resolved by the founder, 5 Nov 2026 (ruling T0b-4): the spike is M3_PLAN task T15, owners security (L) and lead, about 2 days (an estimate), 30 Nov slice, measured with no build. Gate item 10 judges its record.
