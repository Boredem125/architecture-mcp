# ADR 0008: A deterministic money floor, on by default (SEC-23)

Status: Accepted (18 Oct 2026). Decided by the main session for M1 T0c; recorded by lead-architect. The opt-out is allowed on security-engineer's conditions (section "Security answer").

## Next action

Backend-engineer: implement T0c against this ADR. Tests first (qa-engineer).

## Context

1. **SEC-23 (High, `M0_SECURITY_SIGNOFF.md`).** `governance/evaluate.py:66-80` tags a call deterministically (`describe_call`, for example money movement), then asks the optional jev-os service whether a clause is violated.
   - When the service is down or errors, `client.ask()` returns `None` and `evaluate` returns `[]`.
   - `hook_eval._tool_governance` also swallows every exception as `([], None)`.
   - So with `stripe` allowlisted (`demo/live_setup.py:45`), a 9,000,000 refund ran with no approval and no record that a money clause went unevaluated.
2. **`FolderPolicy.fail_mode = "closed"`** (`policy.py:239`) is read nowhere. It implies a guarantee the code does not give.
3. **Two fixes come out of SEC-23, and they are of different kinds:**
   - **Bug fix (no ADR needed):** when governance clauses apply and cannot be evaluated, the call escalates (or is denied if a gated clause says `deny`), and `governance_unevaluated` is audited. Test: `service_down`.
   - **New default (this ADR):** an allowlisted call that `describe_call` tags `moves_money` (`safety/tool_actions.py:31`, a code regex, not the model) escalates **even when no governance policy is configured**. This changes documented behaviour. `test_tool_governance.py::test_no_governance_policy_changes_nothing` states the old rule ("no governance policy changes nothing"). That rule no longer holds for money-moving calls.

## Options

1. **Floor on by default, opt-out through change control** (chosen).
2. **Floor off by default; opt-in.** Keeps today's behaviour, but the safe setting is the one nobody turns on. A customer who allowlists a payment MCP server for convenience gets silent money movement, which is what SEC-23 found. Rejected: product principle "fail closed".
3. **Floor only when a governance policy is on.** Ties a deterministic control to an optional, model-backed feature. A folder with no clauses (the common case) gets no floor. Rejected for the same reason.

## Decision

1. **Default on.** A call tagged `moves_money` by the deterministic `describe_call` always escalates (at least), whatever the model says and whether or not a governance policy exists. **Only `money_floor` turns it off.** `allow_mcp_servers`, tool allowlists, `auto_allow`, `mode`, environment rules and governance clauses cannot bypass it. The model can add scrutiny; it cannot clear the floor.
2. **Opt-out:** a folder-policy field `money_floor` (boolean, default `true`) in `.sandbox/policy.json`. It is safe only under these rules:
   - `false` takes effect **only when it is in the approved version of a versioned folder**. Unversioned, missing, corrupt or unparseable gives `true`. `money_floor` joins `_OR_FIELDS` in `policy_versions.meet()`, so `true` wins and a hand edit to `false` is drift that changes nothing.
   - `true` to `false` is listed by `loosened_fields`. It needs `sandbox policy propose` plus `approve-change` by **two distinct pinned reviewers** (ADR 0007), and raises an alert. The approver CLI is denied to the agent (T0e).
   - `policy.json` is write-protected for the agent (non-removable `_PROTECT_WRITE_GLOBS`).
   - It can never be set by a governance clause, by jev-os, or by any model output.
   - While it is `false`, every call evaluated is audited `money_floor_off` with its tag, and `sandbox status` shows it.
3. **`fail_mode`** is honoured as `closed` (the only accepted value), or deleted if nothing reads it after T0c. No `open` value is offered.

## Behaviour change for existing users

1. Folders that allowlist a payment-type MCP server (for example `stripe`) now get an escalation on money-moving calls, where they used to get a silent allow. This is intentional. The release note says so and names the opt-out.
2. Calls that are not money-tagged are unchanged.
3. Shipped defaults (no allowlisted payment server) were already escalating on the network trigger; nothing changes for them.
4. Escalations rise for teams that relied on the allowlist. That cost is accepted: money movement without a human is what the product exists to stop.

## Security answer (opt-out)

Recorded verbatim (18 Oct 2026):

> "Safe, with conditions (security-engineer):
> (1) false takes effect only when it is in the approved version of a versioned folder; unversioned, missing, corrupt or unparseable gives true; meet() treats true as stricter.
> (2) Only money_floor turns the floor off: allow_mcp_servers, tool allowlists, auto_allow, mode, environment rules and governance clauses cannot bypass it, and the money tag comes from code (describe_call), never from the model.
> (3) Turning it off needs two distinct pinned reviewers via approve-change and raises an alert; every call evaluated while it is off is audited as money_floor_off with the tag."

All three conditions are in Decision 1-2, and each needs a test in T0c.

## Consequences

1. `test_no_governance_policy_changes_nothing` changes as a **named, ADR-backed behaviour change**, not a bug fix. Security signs off on the node id. The `service_down` test is a plain bug fix.
2. The deterministic tagger (`describe_call`) becomes part of the enforcement path and therefore the TCB. Its `_MONEY` patterns need tests for false negatives (refund, payout, transfer, charge, invoice pay, and a money verb in the tool name, not only a URL path) and must not depend on jev-os.
3. The evidence pack shows whether the floor was on for each decision period.

## Stated limit

The floor sees only what `describe_call` recognises as money movement. A payment made by a shell script, or by an MCP tool with a misleading name, is caught by the other rules (shell trigger, network trigger, unknown server), not by this floor.
