# ADR 0006: MCP security (inventory, pinning, per-argument policy, proxy)

Status: Proposed (17 Oct 2026, lead-architect). Needs security-engineer and qa-engineer review. Lands in milestone M4 (see `docs/control-plane/M0_PLAN.md`, roadmap).

## Next action

Security-engineer: review the bypass limits in "Security properties affected", item 4, and the hook-vs-proxy rule (Decision 4).

## Context

What the connector does for MCP today (items 1-6 from my own grep, 7-11 from `M0_INVENTORY.md`):

1. **Server-level allowlist only.** `classify.py`: any `mcp__<server>__<tool>` call is `triggers.network` (default escalate) unless `<server>` is in `policy.network.allow_mcp_servers`, then it is allowed silently.
2. **Governance clauses on MCP calls.** `hook_eval._tool_governance` checks clauses against `(tool_name, tool_input)`, but only when the semantic layer is enabled and a governance policy is set. If the service is down, no extra scrutiny (additive by design).
3. **One-time grants.** `connector/tool_grants.py`: an escalated MCP call is approved out of band, and the identical retry (same fingerprint = tool name + canonical args) is allowed once within 15 min, signed by the folder's pinned key.
4. **Output.** PostToolUse runs the optional injection scan on MCP results (`hook_eval._scan_untrusted_output`) and taints the folder on a hit. Audit records are scrubbed (`scrub.scrub_fields`). MCP results going back into the agent's context are not scrubbed.
5. **Claude Code only.** All of this rides on Claude Code hooks. Codex and Cursor get our MCP server (`connector/mcp_server.py`) but no enforcement on their other MCP servers.
6. **No tool-definition tracking.** A server can change a tool's description or schema between sessions (a "rug pull") and nothing notices.

Gaps found by backend-engineer's inventory (`M0_INVENTORY.md`, "MCP governance today"):

7. **Prefix bypass.** `classify.py:120`, `hook_eval.py:452` and `context_rules.py:61` always allow the prefix `mcp__sandbox_` (single underscore). A third-party server named `sandbox_anything` skips the allowlist, governance clauses and context rules. Routed to security; proposed for M0 T0d.
8. **The allowlist trusts a name.** `allow_mcp_servers` matches the server name the client config chose, not what the server is (command, URL, or identity).
9. **Agent-writable MCP and hook config.** `.mcp.json` and `.claude/settings*.json` are not in the non-removable `_PROTECT_WRITE_GLOBS` (`policy.py:22`), so by default an in-folder write to them is allowed. The agent could repoint or add MCP servers or hooks. Routed to security; proposed for M0 T0d.
10. **`deny_tools` is exact match only**: no wildcards per server.
11. **Our own MCP server** (`connector/mcp_server.py`): stdio, no auth, 5 tools, always allowed, and its tool descriptions are never scanned.

Competitor note (RESUME.md): Verosek routes LLM and MCP **network traffic** through a gateway, with per-tool and per-argument access and HMAC receipts. We should not build a network gateway. Our narrow edge: enforcement at the agent's local execution, a broker that runs approved actions outside the agent, non-repudiable per-person signatures with dual control, and policy change control. MCP security must reuse those, not compete on connector count.

## Options

### Enforcement point for MCP
1. **Hooks only (today).** No new process. Claude Code only; cannot filter `tools/list` or scrub results.
2. **Local MCP proxy (stdio and streamable HTTP) in the connector, plus hooks where available.** Works for any MCP client; sees `tools/list`, so it can pin definitions; can scrub results; can hold an escalated call open and forward it after approval. Cost: one more component in the TCB; the agent's MCP config must point at it.
3. **Network gateway (central MCP router).** Verosek's ground; adds latency and a central dependency on the call path. **Rejected** (breaks principle 1 and the positioning).

### Pinning model
1. **Hash per tool definition** (canonical JSON of name, description, inputSchema, annotations). Precise: shows exactly which tool changed.
2. **One hash of the whole `tools/list`.** Simple; any change blocks everything.

## Decision

Option 2 for enforcement, per-tool hashes for pinning.

### 1. `sandbox mcp-proxy` (OSS, MIT)
1. **stdio:** the agent's MCP config runs `sandbox mcp-proxy --server <name> -- <original command>`. The proxy starts the upstream server as its child and relays JSON-RPC.
2. **Streamable HTTP:** the proxy listens on `127.0.0.1:<port>` (random port, per-session token in the URL path) and forwards to the upstream URL. Optional SPKI pin for the upstream TLS cert.
3. `sandbox init --codex` / `--cursor` / `--claude` rewrite each agent's MCP config to go through the proxy, using the existing marker-tagged install pattern (`connector/install.py`), and add those config files to the non-removable write-deny list.
4. Same process model as the MCP server: no in-memory state that matters; queue, audit and policy are in `.sandbox/`.

### 2. Inventory and pinning
0. **Identity is the pin, not the name** (fixes Context item 8). A server is identified by its transport plus launch command hash (stdio) or URL plus optional SPKI pin (HTTP). `allow_mcp_servers` entries become pins; a name match alone no longer allows anything in managed mode. `deny_tools` gains `server/*` wildcards (item 10). Our own server is pinned the same way, its descriptions are scanned like any other, and only the exact prefix `mcp__sandbox__` counts as ours (item 7).
1. On `initialize` and every `tools/list`, the proxy records `{server name, transport, launch command hash or URL, serverInfo name+version, per-tool definition hash}` in `.sandbox/state/mcp_pins.json` (agent-unwritable) and audits it.
2. **First sight of a server:** per policy, `escalate` (default) or `deny`. Approving it pins its current tools.
3. **New tool on a pinned server:** hidden from `tools/list` until approved.
4. **Changed tool definition (rug pull):** the tool is hidden and calls to it are denied, an alert fires, and the diff (old vs new description and schema) goes to the inbox. Re-pinning is a policy change and goes through change control: the second-reviewer rule applies, because accepting a new description can loosen behaviour.
5. **Central inventory (M4, `ee/`):** `sandbox sync` uploads pins; the control plane shows every MCP server and tool per org and project and which connectors use them. Org-approved pins are distributed in the policy bundle (`mcp_policy`, ADR 0001), so a pin approved once applies to every developer in the project.

### 3. Per-server / per-tool / per-argument policy
1. New `mcp` section in the policy (and in the bundle), evaluated by the **same verdict lattice** (allow < observe < escalate < deny) and the same risk scoring and dual-control upgrade (`hook_eval` contextual tiers).
2. Rule shape: `server -> tool -> default verdict + argument rules`. An argument rule is a JSON Pointer path plus one operator: `equals`, `in`, `regex`, `max` (numeric), `host_in` (allowlist), `path_contained` (uses `fs/containment.py`). Example: `stripe / create_refund / amount max 1000 else escalate (dual)`.
3. All matching rules apply; the **strictest verdict wins**. An unknown argument path or a type mismatch is treated as "rule matched" (fail closed), not skipped.
4. Escalated MCP calls use the existing queue as `tool_call` records with the fingerprint. Through the proxy, the approved call is forwarded **by the proxy** with the exact approved arguments (it is the broker for MCP), so no "approve then retry" is needed. Through hooks only, `tool_grants.py` keeps working as today.
5. Approvals are the same signed approvals with user-bound keys (ADR 0003). A tool-definition hash is added to the signed fields, so an approval is bound to the tool as it was described to the approver.

### 4. Hooks and proxy together (Claude Code)
1. If a server is proxied, the proxy is the enforcement point for it. The hook still applies its deny-level checks (`deny_tools`, self-protection) but does not escalate a second time.
2. The hook knows a server is proxied only from the agent-unwritable policy and the installed MCP config it wrote. If the config no longer matches (edited, server pointed directly at upstream), the hook treats the server as unproxied and applies today's rules (escalate by default).

### 5. Scrubbing and audit
1. Args and results: secret scrubbing (`connector/scrub.py`) on audit records always; on results returned to the agent when `output.scrub_secrets` is on. PII scrubbing uses the same classification rules as files, opt-in.
2. **Every proxied MCP call is audited** (minimum `observe`), including allowed ones, into the same per-session hash chain (`connector/audit.py`): server, tool, definition hash, scrubbed args, args hash, result hash, verdict, policy version. MCP calls cross a trust boundary, so "allow = no audit noise" does not apply to them.

### 6. Tool-poisoning text detection
On first sight and on every definition change, the proxy runs the existing injection detector, and the optional semantic layer when enabled, over tool descriptions and schemas. A hit **adds scrutiny only**: the pin needs a human, and the finding is shown on the approval panel. A clean scan never auto-approves a pin. (Product principle 2.)

### 7. Baseline code and PII engine (founder decision, 19 Oct 2026)
1. **Baseline:** build the M4 proxy on [lasso-security/mcp-gateway](https://github.com/lasso-security/mcp-gateway) (MIT, Python; 396 stars and last commit 22 Jan 2026 when checked on 19 Oct 2026). Keep its licence and copyright notice in `NOTICE`. Pin an exact commit; we own fixes from there on (upstream looked inactive when checked).
2. **What we take:** the proxy shell (it reads `mcp.json` / `claude_desktop_config.json`, manages the upstream servers, exposes `get_metadata` / `run_tool`), the plugin interface, and request/response interception.
3. **What we drop or replace:** the Presidio plugin is replaced by [`depii`](https://pypi.org/project/depii/) (`pip install depii`, Apache-2.0, no core dependencies; repo https://github.com/Boredem125/piiredact; API `depii.scan`, `depii.redact`, `Redactor`, `Pseudonymizer`). The `lasso` guardrail plugin calls Lasso's hosted API, so it is never enabled by default (data leaves the customer's infra). `xetrack` tracing is not the audit trail: every proxied call still goes through sections 3 and 5 (policy decision, hash-chained audit, signed approvals).
4. **What stays ours:** per-argument policy, pinning and drift (section 2), escalate/approve with signed dual control, and the evidence pack. The proxy is plumbing; the wedge is authorization plus evidence.
5. **Gates before adoption (rule first, frozen set, one run):** (a) the upstream code is reviewed by security-engineer at the pinned commit, and Trivy/Semgrep/gitleaks are clean; (b) `depii` recall and false-positive rate are measured on a frozen PII corpus, and only those numbers are published; (c) a test proves a proxy crash or a `depii` error fails closed (call refused, not passed through unredacted); (d) SEC-19 (direct upstream bypass) is still handled by the local hooks, since the proxy cannot stop it.
6. **When:** integration lands in M4. Nothing changes in M1.

## Consequences

1. New OSS component (`connector/mcp_proxy/`) in the TCB, with its own fail-closed rule: if the proxy cannot evaluate, it returns a JSON-RPC error, never forwards.
2. Codex and Cursor users get MCP enforcement. Their native shell tools are still not governed (no hooks); we state that limit plainly.
3. Policy gets an `mcp` section; `meet()` and `loosened_fields()` must learn it (tests first).
4. More audit volume from MCP calls; retention settings apply.

## Security properties affected

1. **Rug-pull / tool-description changes:** newly detected and blocked until a human re-pins.
2. **Per-argument authorization:** new, with fail-closed matching.
3. **Non-repudiation for MCP actions:** approvals bound to the exact arguments and the exact tool definition.
4. **Stated limits (for security review):**
   - an agent that can run its own shell can start an upstream MCP server directly and bypass the proxy. On Claude Code the shell is gated by hooks; on Codex/Cursor it is not;
   - a malicious server can return harmful content that scrubbing and detection miss. Detection is a tripwire, not a guarantee (docs/THREAT_MODEL.md, Goal 7);
   - an HTTP upstream we cannot pin can still change behaviour without changing its tool definitions.

## Open questions

1. ~~Default for a never-seen MCP server?~~ **Answered (security):** `escalate`, with `deny` for `prod`.
2. ~~Founder: move the proxy ahead of M4 for a Codex/Cursor partner?~~ **Decided 17 Oct 2026:** no, it stays in M4.
3. ~~Re-pinning needs two reviewers?~~ **Answered (security):** yes, always; a description is model-facing behaviour.
4. QA: we need recorded MCP sessions (stdio and HTTP) as fixtures, including a server that changes a description mid-session.
