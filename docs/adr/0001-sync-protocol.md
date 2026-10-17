# ADR 0001: Sync protocol between the connector and the control plane

Status: Proposed (17 Oct 2026, lead-architect). Needs security-engineer and qa-engineer review, then founder approval.

## Next action

Security-engineer: review the "Security properties affected" section and the trust roots in Decision 2 and 3.

## Context

What exists today (all local, all in `.sandbox/`):

1. **Enforcement is local.** The PreToolUse hook (`src/sandbox/connector/hook_eval.py`) classifies every call against the enforced policy and fails closed on any internal error (docs/CONNECTOR.md, "Failure behavior").
2. **Policy has versions and drift protection.** `src/sandbox/connector/policy_versions.py` keeps a content-addressed history, a signed log, change requests that need a different reviewer, and enforces `meet(approved, on_disk)` (the stricter of the two) when the file drifts.
3. **Escalations are a folder queue.** `src/sandbox/connector/queue.py`: `pending/ -> claimed/ -> done/`, with atomic rename for claiming. `src/sandbox/connector/approval.py` is the one approval path for every surface and enforces dual control.
4. **Signatures exist but have no trust anchor.** `src/sandbox/connector/signing.py` embeds the signer's public key in the record and verifies against it. Anyone with any key can make a record that "verifies". Only `tool_grants.py` and the evidence check pin a key. Keys are seeds at `.sandbox/state/keys/<reviewer>.seed`.
5. **The audit is a per-session hash chain.** `src/sandbox/connector/audit.py`. Truncating the last records is not detectable from the file alone (see `verify_records_bytes` docstring); you need a head hash recorded elsewhere.

The control plane must add central policy, a web inbox with real identity, and a central audit store, without becoming a single point of failure for safety. Product principle 1 (STARTUP.md): local enforcement stays authoritative and fails closed; the control plane is never required for a deny.

## Options

### A. Control plane decides every call (remote PDP)
- Plus: one place for policy, simple central audit.
- Minus: every tool call needs the network; latency; the control plane becomes required for safety. If it is down, you either block all work or fail open. Breaks principle 1. **Rejected.**

### B. Local decides; control plane distributes signed policy, collects audit, and returns signed human decisions (pull-based sync)
- Plus: reuses the hook, queue, approval, drift and audit code as-is. Works offline. Deny never needs the network.
- Minus: a sync daemon to build; eventual consistency (a policy change takes up to one poll interval to land); clock and replay handling needed.

### C. Same as B, but push over a persistent channel (WebSocket / NATS)
- Plus: lower latency for approvals.
- Minus: long-lived connections through customer proxies are fragile; NATS is unused today and we are removing it. Can be added later on top of B as a "poke" that triggers a pull.

## Decision

Option B. A new long-lived process, `sandbox sync` (OSS, MIT, part of the connector), runs next to the hook and MCP server. It is the only connector component that talks to the control plane. The hook never makes a network call.

### 1. Enrollment and connector auth
1. An org admin creates a one-time enrollment code in the web UI (single use, 15 min expiry, scoped to one project).
2. `sandbox enroll --server https://cp.example --code XXXX` generates an Ed25519 **device key** locally and sends the public key with the code. The server binds `device_id -> project`.
3. The response carries the org's **trust bundle**: the org root public key fingerprint. The CLI prints the fingerprint and asks the user to confirm it matches the one shown in the web UI (out-of-band check; no silent trust-on-first-use).
4. Every sync call: the device signs a short assertion (device_id, audience, timestamp, nonce) and exchanges it for a 10-minute bearer token (RFC 7523-style `private_key_jwt`). No long-lived shared secret is stored.
5. Device key file: `.sandbox/state/device/` outside what the agent may read (see Security properties, item 4). Revocation: admin revokes the device; the next token exchange fails; local enforcement continues on the last valid policy.

### 2. Policy distribution
1. The control plane publishes a **policy bundle** per project: `{project_id, sequence (monotonic int), folder_policy, governance_policy, mcp_policy, approver_key_registry_version, not_before, expires_at}`.
2. Authority comes from **human signatures, not the server.** A bundle that loosens anything (`policy_versions.loosened_fields` against the previous bundle) must carry two valid approvals by distinct users whose keys are in the key registry (ADR 0003). A tightening-only bundle needs one. The server also signs the bundle for transport integrity, but a compromised server alone cannot loosen policy.
3. The connector verifies, then stores the bundle as the **central approved version** in `.sandbox/policy_history/` (reusing `store()` and the log). Refuse a lower or equal `sequence` (rollback protection). A "revert" is a new, higher sequence.
4. **Enforced policy = meet(central approved, local approved, on-disk file).** This is the existing `meet()` with one more input. A local edit can only tighten. A local loosening change request is refused in managed mode with a pointer to the central inbox.
5. Drift (on-disk differs from approved) is still audited as `policy_drift` and also uploaded as an alert.
6. A bundle past `expires_at` stays enforced (it is the last known good). It is not dropped, because dropping it could loosen. The connector raises a `policy_stale` alert.

### 3. Escalations and approvals
1. `sandbox sync` uploads each new `pending/` record (scrubbed by the same `scrub.py` rules) to the central inbox. Idempotent on `(device_id, request_id)`.
2. Humans approve in the web inbox. Each approval is signed **in the approver's browser** with their user-bound key (ADR 0003) over the same fields as `signing._APPROVAL_FIELDS`, plus `device_id`, `project_id`, `policy_version`, `nonce`, `not_after` (default 15 min).
3. The connector pulls decisions and verifies each approval against the **pinned key registry** (not the embedded key). Then it runs the existing `approval.approve()` path: claim (atomic rename), dual-control check, `FolderBroker.execute`, `finish`. New input: externally signed approvals instead of local seeds. Execution always happens locally, in the broker, never on the server.
4. Dual control needs two approvals whose keys map to two distinct `user_id`s in the registry (not just distinct keys).
5. A deny needs one signed decision. Denying is the safe direction, as today.

### 4. Control plane unreachable
1. Allow, observe and deny decisions: unaffected (local).
2. Escalations: stay `pending` and wait, as today ("Approver offline", docs/CONNECTOR.md). The agent gets the existing "pending, call check_request" reply. No timeout auto-approve, ever.
3. Local approver (`sandbox watch` with a local seed): **off by default in managed mode**, because a local seed is not bound to a person. An admin can enable it per project in policy (`approval.local_fallback: true`); those approvals are tagged `local_unbound` in the audit and evidence pack.
4. Break-glass (ADR 0003): a time-boxed, pre-signed offline grant. Not a bypass flag.

### 5. Audit upload
1. The local chain stays the spool. `sandbox sync` reads `records.jsonl` per session from a cursor file (`.sandbox/state/sync_cursor.json`) and uploads records in order.
2. Server checks continuity per `(device_id, session_id)`: `previous_hash` must equal the stored head, `chain_length` must be head + 1. Same position and same `record_hash` = idempotent no-op. Same position, different hash = **fork alert**, record kept in quarantine, not merged.
3. **Head checkpoints:** every upload batch ends with a device-signed `{session_id, chain_length, head_hash, ts}`. The server stores them, which closes today's tail-truncation gap.
4. Offline: nothing is lost; the cursor waits. Retention (`connector/retention.py`) must not delete records that are not yet uploaded in managed mode.

### 6. Replay protection
1. Approvals are bound to `request_id` (random, single use), `device_id`, `fingerprint`, and expire at `not_after`. A done request cannot be claimed again (the pending file is gone).
2. Bundles: monotonic `sequence`, `not_before`.
3. Token exchange: timestamp within 2 min plus nonce cache on the server.
4. Clock skew: the connector warns if its clock differs from the server by more than 2 min; approvals use server time for `not_after` with a 2 min grace.

## Consequences

1. The connector gains one new module family (`connector/sync/`) and one process. The hook path does not change. Standalone (unenrolled) mode behaves exactly as today.
2. `approval.approve()` needs a second input mode (verified external approvals). This is the riskiest change to a TCB component; security-engineer reviews it.
3. `signing.verify_approval` gains a "verify against pinned registry" variant; the self-verifying form stays for standalone mode and old records.
4. Policy changes land within one poll interval (default 10 s for decisions, 60 s for bundles). Acceptable for the wedge.
5. More state in `.sandbox/` that the agent must not touch (device key, cursor, registry).

## Security properties affected

1. **Fail closed:** unchanged. The control plane is never on the deny path.
2. **Who can loosen policy:** moves from "a second local reviewer id" to "two distinct enrolled humans". The server is not a trust root for loosening.
3. **Non-repudiation of approvals:** improves. Keys are pinned to users through a registry signed by the org root (ADR 0003).
4. **Key exposure (found while writing this):** the classifier allows the agent's `Read` tool anywhere inside the folder (`classify._classify_read`), and only writes to `.sandbox/**` are denied. So today an agent can read `.sandbox/state/keys/*.seed`. Proposal: add a non-removable read-deny for `.sandbox/state/keys/**` and `.sandbox/state/device/**`, the same way write protections are re-injected in `policy._inject_protections`. Security-engineer to confirm and decide whether this is an M0 fix.
5. **Audit completeness:** improves (signed head checkpoints detect truncation).

## Open questions

1. Founder: in managed mode, should a local `sandbox watch` approver be allowed as a fallback at all (default off, proposed above)?
2. Security: is 15 minutes the right default approval lifetime for remote approvals?
3. Security: should the device key move to the OS keystore (Windows DPAPI / macOS Keychain) in M2, or stay a file under a read-denied path?
