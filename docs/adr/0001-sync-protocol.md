# ADR 0001: Sync protocol between the connector and the control plane

Status: Proposed (17 Oct 2026, lead-architect). Amended for M2 (21 Oct 2026, M2 T0b): see "M2 amendments" at the bottom. The M2 plan that this text comes from was reviewed by security-engineer and qa-engineer and approved by the founder on 21 Oct 2026 (`docs/control-plane/M2_PLAN.md`, `REVIEW_M2.md`). Accepted for M2: the security approval is quoted below.

## Next action

Security-engineer: confirm the M2 amendments (S13, N1-N9, F1-F5) and the "Open questions (M2)" at the bottom, in writing.

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

**M2 amendment (21 Oct 2026, M2 T0b):** the "M2 amendments" section at the bottom replaces or amends the items it names in sections 1-6. Where the two differ, the amendment wins.

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

1. ~~Founder: in managed mode, should a local `sandbox watch` approver be allowed as a fallback at all (default off, proposed above)?~~ **Decided 21 Oct 2026 (founder ruling 2):** off by default in managed mode. Turning it on is a signed bundle loosening that needs two CLI approvals (M2 amendment A2.4).
2. ~~Security: is 15 minutes the right default approval lifetime for remote approvals?~~ **Answered (M2 plan D4.1, security approved):** 15 minutes of server time, 2 minutes grace.
3. ~~Security: should the device key move to the OS keystore (Windows DPAPI / macOS Keychain) in M2, or stay a file under a read-denied path?~~ **Answered (security Q3 ruling, 21 Oct 2026):** it stays a file in the key home under the non-removable deny. The OS keystore is deferred, because DPAPI and Keychain do not stop code running as the same user (ADR 0007 limit 1). See M2 amendment A1.6.

## M2 amendments (21 Oct 2026, M2 T0b)

Source: `docs/control-plane/M2_PLAN.md` D1-D8 and the founder rulings of 21 Oct 2026. Reviews: `REVIEW_M2.md` (security S1-S15, N1-N9, final check F1-F5; QA Q1-Q11). The rule ids in brackets point there. Where this section differs from sections 1-6, this section wins.

**Security approval (21 Oct 2026):** APPROVE WITH CONDITIONS. "security-engineer (claude-opus-5-5), 21 Oct 2026: the M2 amendments match M2_PLAN D1-D10 and the founder rulings. S1-S15, N1-N9 and F1-F5 are recorded, and F1 and F2 are normative text in A1.9-A1.10. Approved, on the condition that threat row 37 (agent runs the sync CLIs, A1.13) is in the T0a matrix before the freeze." Row 37 was added to `M2_PLAN.md` "Threats (sync)" at T0b, with tests in T7 and T8.

### A1. Enrollment and connector auth (replaces 1.1-1.5)

1. **Code to a named operator (S8).** An admin issues a code to a named operator user for one project. Only that operator sees it, in a fresh session (`max_age` 15 min). It is single use, valid 15 min, at least 128 bits, stored as a SHA-256 hash and rate-limited. The operator is the device's excluded requester (A3.5).
2. **Enroll with proof of possession (S13).** `sandbox enroll --server URL --code X --expect-fingerprint FP [--ca FILE]` generates an Ed25519 device key in the key home (A1.6). It sends the public key with a proof of possession: the device signs `{code_hash, public_key, aud, iat}` under `agg/device-enroll/v1`. The server consumes the code with one atomic `UPDATE ... WHERE used_at IS NULL RETURNING`. Exactly one of several concurrent requests wins.
3. **Fingerprint out of band (S2; replaces 1.3).** The admin's CLI signer computes and prints the registry root fingerprint locally (ADR 0003 M2 amendments). The operator gets it from the admin out of band, never from the web UI. `sandbox enroll` refuses to run without `--expect-fingerprint`. With no TTY there is no interactive accept. A mismatch aborts and writes nothing.
4. **Token exchange.** The device signs `{device_id, aud, iat, nonce}` under `agg/device-assert/v1`. The server accepts `iat` within 2 min and a nonce unique per `(device_id, nonce)`. It returns an opaque 256-bit token, valid 10 min, stored only as a hash. This replaces the `private_key_jwt` wording in 1.4.
5. **Revocation.** Revocation is checked on every call. A revoked device gets 401 on its next call. The connector alerts `device_revoked` and keeps enforcing its last valid bundle.
6. **Device key custody (answers Q3; replaces the path in 1.5).** The device key lives in the key home (ADR 0007), in `device/` under the workspace id, behind the non-removable deny. Tests cover every tool, rootless Grep/Glob, env-var paths and 8.3 short names. The OS keystore is deferred.
7. **Sticky managed mode (S6).** Enrollment writes a `managed` marker in the key home and in `.sandbox/state/sync/`. If either marker exists while the pinned registry, bundle or cursor is missing or corrupt, the connector keeps its last valid bundle from `policy_history/`. It never falls back to standalone.
8. **`locked` (founder ruling 5, proposal B; N3, N7).** If the last valid bundle is gone too, the workspace goes `locked`. Every call is denied except reads inside the root, and the message says to re-enroll. Locked reads still go through the non-removable protections and the default read denies. Locked lasts until re-enrollment (and see A1.11).
9. **Root pinning (F2).** Only `sandbox enroll --expect-fingerprint` writes a pinned root. `sandbox sync` never re-pins the root, including when the pinned registry has been deleted. Until a pinned root exists, every bundle and every remote approval is refused. A test checks that sync does not re-pin after the pinned registry is deleted.
10. **Leaving managed mode (N2, F1).**
    - The only route is an `agg/unenroll/v1` decision signed by CLI keys of the admin quorum, and audited. There is no local two-reviewer route, because one person can pin two local ids (ADR 0007 limit 2).
    - It travels online, or offline as a file: `sandbox signer unenroll --out FILE` on the admin's machine, then `sandbox unenroll --decision FILE` on the device.
    - **The field set is fixed in code (F1):** `{org_id, project_id, device_id, registry_version, nonce, issued_at, not_after}`. The tag and the field set come from the kind, never from the file (ADR 0007 3.2).
    - The connector verifies the signatures against the admin set and threshold of its **latest pinned registry**. Only `kind=cli` admin keys count, one per user. A `registry_version` higher than the pinned version is refused, because it cannot be checked.
    - `org_id`, `project_id` and `device_id` must equal the device's own. A decision past `not_after` is refused.
    - **Re-enroll always produces a new device_id.** So an old un-enroll file replayed after re-enroll is refused (wrong `device_id`). A T8 test covers this.
    - **Expired registry (security ruling, T0b).** If the pinned registry has expired, `sandbox unenroll --decision` is refused. The operator syncs first to refresh the registry. A decision whose `not_after` is more than 24 h after its `issued_at` is refused, so a signed file cannot be kept for later.
    - **Policy at un-enroll (lead decision, confirmed by security at T0b).** Un-enroll does not loosen by itself. The policy enforced at un-enroll, every section of it (A2.6), becomes the local approved policy. If a section cannot be stored locally, un-enroll fails and changes nothing. Any later loosening goes through local change control.
    - **Order.** The connector writes the local approved policy and the `unenrolled` audit record (with the decision hash) first, then removes both markers. A crash in between leaves the workspace managed.
    - **Open requests.** Pending managed requests are closed as `unenrolled`. No remote approval made before un-enroll counts toward a later local decision.
11. **Re-enroll from `locked` (N3, F4).** With no local approved policy, the base for the first bundle is deny-all (A2.3), so that bundle needs two CLI approvals. The workspace stays `locked` until a bundle with two valid CLI approvals arrives and verifies. Demo step 8 checks this.
12. **CLI signer auth (S13, F5).** `sandbox signer` authenticates like a device: it signs `agg/signer-assert/v1` assertions (`iat` within 2 min, nonce unique per `(key_id, nonce)`) and gets an opaque 10-min token, stored as a hash. The pre-auth key lookup covers registry keys and pending `signer_links` (ADR 0002 M2 amendments). **A token issued to a pending, unconfirmed `signer_links` key may only complete that link.** It cannot read pending payloads, post signatures, or reach any other route. An IDOR test covers this (T7).
13. **The agent may not run the sync CLIs (security, T0b).** `sandbox enroll`, `unenroll`, `sync` and every `sandbox signer` subcommand join the approver-CLI deny (`_APPROVER_SUBCOMMANDS`, ADR 0007 1.6), in standalone and in managed mode. Otherwise an agent could enroll the workspace to a server and root it controls, then loosen policy with keys it made, or use an admin's CLI key on the same machine. Also, `sandbox enroll` refuses a fingerprint that differs from an existing pinned root; the workspace must be un-enrolled first (A1.10). Tests cover each subcommand through the same shell forms as `approve` (T7, T8).

### A2. Policy distribution (replaces 2.1-2.2 and 2.4; 2.3, 2.5 and 2.6 stand as amended here)

1. **Payload.** `{org_id, project_id, sequence, base_sequence, registry_version, environment, folder_policy, governance_policy, mcp_policy, approval{local_fallback, allow_requester}, change_approvals[], issued_at, not_before, expires_at}`. Size cap 1 MiB. Strict parse; unknown fields are refused.
2. **Signature.** The bundle-signer key signs under `agg/bundle/v1`. It is trusted only because the pinned registry lists it (`bundle_signer`). Any key carried in the bundle is ignored. The bundle-signer signature gives no authority to loosen; authority comes from `change_approvals[]`.
3. **Loosening is computed by the connector (S4, N3).** `loosened(enforced, new)` runs against the connector's own enforced policy: its last valid bundle, or for the first bundle the local approved policy at enrollment. If no local approved policy exists, the base is deny-all. A `base_sequence` that differs from the current sequence is refused. A non-empty result needs two `agg/policy-change/v1` approvals over the bundle hash, from two distinct users with `kind=cli` keys and the `policy_author` or `approver` role. Neither may be the proposer. A tightening-only bundle needs one CLI approval. In the demo, a third person (bob, through the API) proposes the step 4 bundles, so the approvals from alice and carol are valid (F3).
4. **Every section has meet and loosened (S5).**
   - `folder_policy`: the existing `meet` and `loosened_fields`.
   - `governance_policy`: a removed clause, or an action weakened from deny to escalate to allow, is loosening.
   - `mcp_policy`: an added server, tool or argument pattern is loosening.
   - `approval.local_fallback` or `approval.allow_requester` going from false to true is loosening. This replaces `dual.allow_requester` in ADR 0003 4.3.
   - A longer registry expiry is loosening.
   - **`environment` is read only from this human-approved field.** Absent means `prod`. Any move away from `prod` is loosening.
   - Any change with no defined order counts as loosening.
   - **`sandbox watch` in managed mode (founder ruling 2; replaces 4.3).** The local approver is off by default. Turning it on means a bundle that sets `approval.local_fallback: true`, which is a loosening and needs two CLI approvals. Those local approvals stay tagged `local_unbound`.
5. **Rollback and downgrade.** Refuse a `sequence` lower than or equal to the current one. Refuse anything other than `sig_v: 1`, an unknown `alg`, an older registry version, and `not_before` in the future. Refuse a bundle or registry for another `org_id` or `project_id`.
6. **Approved base and per-section meet (N5; amends 2.3-2.4).** A verified bundle is stored through `policy_versions.store()` and the signed log. Enforced = `meet(bundle base, local tighten-only overlay, on-disk file)`, applied per section at enforcement time: folder, governance, mcp, approval and environment. A hand edit that loosens any one section has no effect. In managed mode a local change request may only tighten.
7. **Bad or stale bundle (2.6 stands).** An invalid bundle is refused and the last valid one kept (`bundle_rejected`). An expired bundle stays enforced (`policy_stale`). Before the first bundle of a first enrollment, the local approved policy applies (but see A1.11).

### A3. Escalations and approvals: the M2 subset (pulled forward from M3; replaces 3.2-3.4; 3.1 and 3.5 stand)

1. **Upload.** `sandbox sync` uploads new `pending/` records, scrubbed by `scrub.py`, idempotent on `(device_id, request_id)`. The escalation stores the current `policy_sequence`.
2. **Who signs (S1, Q1 ruling).** Approvals and denies come from the CLI signer (`kind=cli`) or the web page (`kind=browser`, WebCrypto Ed25519, non-extractable). The kind matrix is in ADR 0003's M2 amendments. Passkeys stay in M3.
3. **No remote approvals on `prod` in M2 (founder ruling 4, proposal A, N9).** No key kind may make a remote approval on a prod project. The connector reads `environment` from the signed bundle (absent means prod). Prod escalations stay pending unless the signed bundle sets `approval.local_fallback`.
4. **Remote-approval rules (S10).** Tag `agg/remote-approval/v1`. The field set is fixed in code: `_APPROVAL_FIELDS` plus `org_id, project_id, device_id, registry_version, policy_sequence, user_id, key_id, nonce, not_after`. `policy_sequence` replaces `policy_version` in 3.2 and must equal the sequence recorded on the escalation. The key must be in the latest pinned registry with the `approver` role. Device and bundle-signer keys are refused for every human kind. One `user_id` with two keys counts once. The server stores approvals under `SELECT ... FOR UPDATE` with a unique `(escalation_id, user_id)`.
5. **Dual control (S8, S9).** Two valid approvals from distinct `user_id`s with distinct `(iss, sub)`. A key counts toward dual control only if the registry version that added it carried at least 2 admin signatures; otherwise it is labelled `single_admin_registry` and counts for single approvals only. The operator bound at enrollment is the excluded requester, unless the bundle sets `approval.allow_requester`. One approval leaves the request at 1 of 2, and nothing runs.
6. **One path in managed mode (S7).** The connector runs `approval.apply_external(layout, request_id, approvals)`, which reuses the `approve()` path: claim, dual check, `FolderBroker.execute`, finish. It drops every approval that is not a registry-verified `agg/remote-approval/v1`. In managed mode, local `approve()` refuses managed requests unless the signed bundle sets `approval.local_fallback`. A mix of local and remote approvals never meets dual control.
7. **Deny.** A deny needs one valid signed decision. Once the registry expires, or the measured skew passes 2 min, remote approvals are refused and denies still apply.

### A4. Audit upload (amends 5.1 and 5.3; 5.2 stands)

1. **Spool and cursor.** The local chain is the spool. The cursor moves to `.sandbox/state/sync/cursor.json`, under the non-removable deny. Upload is in order, per `(device_id, session_id)`. A gap is refused.
2. **Device checkpoint (S11, S12; replaces 5.3).** `agg/audit-head/v1` over `{device_id, upload_seq, sessions: [{session_id, chain_length, head_hash}], ts}`. It lists every local session since enrollment, uploaded or not. `upload_seq` goes up by exactly 1; a skip or a repeat is refused and alerted. A session's `chain_length` below an earlier checkpoint raises `truncation`. A session listed earlier and missing later raises `session_missing`.
3. **Server head.** Each reply returns the server's head. The connector raises `server_head_mismatch` when the server is behind what it acknowledged. `agg-cp audit verify --project` rechecks every stored checkpoint against the recomputed chains and flags gaps.
4. **`device_silent` (N6).** The server raises it when a device misses its checkpoint window (default 3 x the 60 s poll, configurable). Tested with the injected clock.
5. **Storage.** `audit_records`, `audit_heads` and `audit_quarantine` are append-only, with triggers as on `admin_audit`. In managed mode `retention.py` never deletes past the cursor.

### A5. Replay protection and clocks (amends section 6)

1. Remote approvals are bound by the A3.4 field set and a unique nonce, and expire at `not_after` (15 min of server time, 2 min grace). A done request cannot be claimed again.
2. Device and signer assertions use `iat` plus a nonce table. Bundles use `sequence`, `base_sequence` and `not_before`. Checkpoints use `upload_seq`. Un-enroll decisions use `device_id`, `nonce` and `not_after` (A1.10).
3. **Skew (S15; replaces the warning in 6.4).** The connector measures its skew against the server time in each reply. Above 2 min it refuses remote approvals (denies still apply) and alerts `clock_skew`. Server expiries use the injected clock.

### A6. Protocol envelope and process

1. **Envelope.** `{kind, sig_v: 1, payload, signatures[{key_id, alg: "ed25519", sig}]}`. The signed bytes are `tag || 0x00 || canonical JSON(payload)`. The tag and the field set come from `kind`, in code (SEC-24 rule, ADR 0007 3.2). `key_id` = SHA-256 of the raw public key.
2. **Routes** under `/api/v1/sync`: `POST enroll`, `POST token`, `GET registry?after=`, `GET bundle?after=` (204 if none), `POST escalations`, `GET decisions?cursor=`, `POST audit`, and the signer routes `link`, `pending` and `signatures`. HTTPS only. `--ca` pins a private CA.
3. **`sandbox sync`** is one process and the only network user. It polls decisions every 10 s and the registry and bundles every 60 s. Offline, it backs off exponentially with jitter, capped at 5 min. The hook path is unchanged; a socket guard test proves `pre_tool_use` opens no socket.
4. An unenrolled workspace with no `managed` marker behaves exactly as today.

### A7. Failure modes (adds to section 4)

| Condition | Connector behaviour |
|---|---|
| Server down or network cut | Allow, observe and deny unchanged; escalations stay pending; never an auto-approve; spool waits |
| Bundle invalid, rolled back, wrong project, oversized | Refused; last valid bundle kept; `bundle_rejected` |
| Bundle or registry expired | Bundle stays enforced (`policy_stale`); remote approvals refused once the registry expires |
| Sync state missing or corrupt, marker present | Last valid bundle, else `locked` (A1.7-A1.8); no re-pin by sync (A1.9) |
| Device revoked | Token 401; last valid bundle; `device_revoked` |
| Clock skew over 2 min | Remote approvals refused; `clock_skew` |
| Spool disk full | The hook's existing fail-closed audit rule; sync never deletes the spool |

### A8. Security properties affected (M2)

1. **Who can loosen policy:** two distinct humans with registry-listed CLI keys, checked by the connector against its own base. The server and the bundle-signer key cannot loosen.
2. **Leaving managed mode:** only by an admin-quorum `agg/unenroll/v1`. Deleting local state gives the last valid bundle or `locked`, never standalone.
3. **Remote approvals:** non-prod only in M2. Property 3 above holds for CLI keys. For browser keys it does not: a compromised server can forge non-prod remote approvals and denies through the browser keys of any user who loads its page (M2 plan limit 1). It cannot sign registries, loosen policy, un-enroll, or approve on prod.
4. **Key exposure (property 4 above):** closed for the hook-governed agent by the key home (ADR 0007). The device key is under the same deny.
5. **Stated limits** are M2 plan limits 1-7. In short: dual control proves two IdP identities with two keys, not two non-colluding people; a compromised server can withhold policy, decisions and revocations until expiry; same-user code or the human operator can delete both markers and the state and run standalone, which only `device_silent` later shows; a server that deletes its stored audit tail is not detected server-side until SEC-15; a session created and deleted entirely offline never appears in a checkpoint. No compliance claims.

### Open questions (M2)

1. ~~Security: should `sandbox unenroll --decision` be refused when the pinned registry has expired?~~ **Ruled (security, T0b):** yes, refused; the operator syncs first. A decision may live at most 24 h (A1.10).
2. ~~Security: confirm the lead decision in A1.10 (un-enroll keeps the enforced policy as the local approved policy).~~ **Confirmed (security, T0b),** with three conditions now in A1.10: every section is kept or un-enroll fails, the policy and audit record are written before the markers go, and open managed requests are closed.
