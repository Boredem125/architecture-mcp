# M4 backlog (not a plan)

Founder request, 4 Nov 2026. M4 has no plan yet; product-manager and lead-architect plan it after the M3 gate. Nothing here starts before M3 is done unless the founder says so.

## Interception beyond the laptop hook

The policy engine, signed two-person approvals, audit chain, evidence packs and control plane stay the same. Only the way actions are caught changes. Build in this order:

1. **CI and headless coding agents.** Same agents and same buyer as M3, and the closest extension of the hook and broker.
2. **MCP proxy on `lasso-security/mcp-gateway`.** Already decided in ADR 0006 section 7: MIT, pin an exact commit, we own fixes, `depii` replaces Presidio, Lasso's hosted-API plugin stays off by default. Upstream looked inactive on 19 Oct 2026, so recheck the ADR's adoption gates first. The MCP sub-suite also lands here. The 28 Oct exclusion of this gateway covers the shell bypass suite only, because it never sees the agent's built-in shell tool; it does not change this decision.
3. **Production-agent sidecar.** A process beside a production agent that feeds the same decision path. Build only if a paying customer asks.

## What a production sidecar would need

- Interception without a `PreToolUse` hook: an SDK wrapper, an API proxy, or kernel-level tracing (eBPF).
- Container and Kubernetes packaging, with a latency budget.
- Policy rules for database queries and business APIs, since current rules cover shells, files and developer tools.
- An approval model for rare, high-risk actions only, because no person is at a keyboard.
- A freedom-to-operate check by a lawyer before choosing a sidecar design, because patents exist in this area.

## Demand signal

Ask on the discovery calls: "Do you also need this for production agents, or is the coding rollout the urgent problem?" If 2 of 5 say production, the sidecar goes into the M4 plan.
