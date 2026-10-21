# M2 plan: sync (enrollment, signed policy bundles, audit upload) plus M1 carry-overs

Status: Revised (21 Oct 2026, lead-architect) after `REVIEW_M2.md`. Security: APPROVE WITH CONDITIONS (S1-S15, Q1 and Q3 rulings). QA: APPROVE WITH CONDITIONS (Q1-Q11). Security re-review (round 2): S13 and N1-N9 are folded in. QA: APPROVE (all closed). See "Review disposition". Founder approved 21 Oct 2026; see "Founder rulings". M1 is done (`9b0d1b0`, `M1_DONE.md`).

## Next action

1. **Founder:** done. The plan is approved and the rulings are recorded at the end.
2. **Security:** confirm the S13 and N1-N9 text when T0b writes the ADRs.
3. **QA:** after approval, run T0a. It freezes the baseline, the threat-to-node-id matrix and the demo preset before any fix commit.

## Goal

1. An enrolled connector syncs with the control plane. It gets signed policy, uploads its audit with signed checkpoints, and takes remote human decisions.
2. A live dual-control approval by two distinct OIDC users, each with their own key, on one critical action, on a non-prod project.
3. Local enforcement stays authoritative. The hook never makes a network call. Offline, with a bad bundle, or with lost sync state, the connector fails closed. It never falls back to a looser policy.
4. Close the M1 carry-overs (`M1_DONE.md` item 6).

## Scope

1. **Enrollment** (ADR 0001 section 1): a connector bound to an org, a project and a named operator; a one-time code; device key with proof of possession; token exchange; revocation; sticky managed mode.
2. **Signed policy bundles** (section 2): the control plane signs. The connector verifies, pins, and computes loosening against its own state. Rollback and downgrade are refused. Loosening needs two humans with CLI keys.
3. **Audit upload** (sections 5, 6): hash-chained records plus device-signed checkpoints. The server checks continuity and flags truncation, fork, replay and missing sessions.
4. **Pulled from M3, as the minimum the live step needs:** a key registry with a local CLI root signer, escalation upload, a minimal web approve page, and remote approvals verified against the pinned registry (ADR 0001 section 3, ADR 0003 sections 3-4).
5. **Carry-overs:** live two-reviewer path; slimmer `api` image; dependency-free Python for SEC-27/28 in CI; `ee/` tests on Windows; the named Lows; a DB connection pool.

## Non-goals (M3 and later)

1. Passkeys, attestation, break-glass (ADR 0003 sections 2, 5). The full inbox and a web policy editor. Policy changes go through the API and the CLI signer.
2. **Remote approvals on `prod` projects, by any key kind.** Prod keeps local enforcement and local approvers until passkeys land in M3. This is proposal A, which security accepts on condition N9 (founder question 4).
3. A push channel, the MCP proxy (M4), org-wide evidence, SIEM export, the external audit anchor (SEC-15), HA Postgres, Cursor and Codex adapters, compliance claims.

## Design decisions (per ADR 0001 section)

### D1. Enrollment and connector auth (ADR 0001 section 1)
1. **Code:** an admin issues a code **to a named operator user** for one project. Only that operator sees it, in a fresh session (`max_age` 15 min). It is single use, valid 15 min, at least 128 bits, stored as a SHA-256 hash and rate-limited. The operator is the device's excluded requester (D6.4).
2. **Enroll:** `sandbox enroll --server URL --code X --expect-fingerprint FP [--ca FILE]` generates an Ed25519 device key in the key home (D1.6). It sends the public key with a proof of possession: the device signs `{code_hash, public_key, aud, iat}` with tag `agg/device-enroll/v1`. The code is consumed by an atomic `UPDATE ... WHERE used_at IS NULL RETURNING`.
3. **Fingerprint out of band (S2):** the admin's CLI signer computes and prints the registry root fingerprint locally (D5.2). The operator gets it from the admin out of band. `sandbox enroll` refuses to run without `--expect-fingerprint`, and with no TTY there is no interactive accept. A mismatch aborts and writes nothing.
4. **Token exchange:** the device signs `{device_id, aud, iat, nonce}` (`agg/device-assert/v1`). The server accepts `iat` within 2 min and a nonce unique per `(device_id, nonce)`. It returns an opaque 256-bit token, valid 10 min, stored as a hash.
5. **Revocation:** a revoked device gets 401 on its next call (revocation is checked on every call). The connector alerts `device_revoked` and keeps enforcing its last valid bundle.
6. **Device key custody (Q3 ruling):** the key lives in the key home (ADR 0007), in `device/` under the workspace id, behind the non-removable deny. The tests cover every tool, rootless Grep/Glob, env-var paths and 8.3 short names. The OS keystore is deferred: DPAPI and Keychain do not stop code running as the same user. Amend ADR 0001 Q3 and ADR 0003 2.4.
7. **Sticky managed mode (S6):** enrollment writes a `managed` marker in the key home and in `.sandbox/state/sync/`. If either marker exists while the pinned registry, bundle or cursor is missing or corrupt, the connector keeps its last valid bundle from `policy_history/`. If that is gone too, it enters `locked` (proposal B): every call except reads inside the root is denied, and the message says to re-enroll. **Locked reads still go through the non-removable protections and the default read denies (N7).** It never falls back to standalone. On re-enroll with no local approved policy, the first bundle's base is deny-all, so it needs 2 CLI approvals (N3, D2.3).
8. **Leaving managed mode (N2):** only through an `agg/unenroll/v1` decision signed by the admin quorum's CLI keys, and audited. It can travel online, or offline as a file: `sandbox signer unenroll --out FILE` on the admin's machine, then `sandbox unenroll --decision FILE` on the device. There is no local two-reviewer route, because one person can pin two local ids (ADR 0007 limit 2).

### D2. Policy distribution (ADR 0001 section 2)
1. **Bundle payload:** `{org_id, project_id, sequence, base_sequence, registry_version, environment, folder_policy, governance_policy, mcp_policy, approval{local_fallback, allow_requester}, change_approvals[], issued_at, not_before, expires_at}`. Size cap 1 MiB, strict parse, unknown fields refused.
2. **Signature:** the bundle-signer key (`agg/bundle/v1`). It is trusted only because the pinned registry lists it. Any key carried in the bundle is ignored.
3. **Loosening, computed by the connector (S4):** `loosened(enforced, new)` runs against the connector's own enforced policy. That is its last valid bundle, or the local approved policy at enrollment for the first bundle. If no local approved policy exists, the base is deny-all (N3). A `base_sequence` that differs from the current sequence is refused. A non-empty result needs two `agg/policy-change/v1` approvals over the bundle hash, from two distinct users with `kind=cli` keys and the `policy_author` or `approver` role. Neither may be the proposer. A tightening-only bundle needs one CLI approval.
4. **Every section has meet and loosened (S5):** `folder_policy` uses the existing `meet`/`loosened_fields`. `governance_policy` treats a removed clause, or an action weakened from deny to escalate to allow, as loosening. `mcp_policy` treats an added server, tool or argument pattern as loosening. `approval.local_fallback` and `allow_requester` going false to true is loosening. A longer registry expiry is loosening. **`environment` is read only from this human-approved field:** absent means `prod`, and any move away from `prod` is loosening. Any change with no defined order counts as loosening. Each section gets its own tests.
5. **Rollback and downgrade:** refuse a sequence lower than or equal to the current one; refuse anything other than `sig_v: 1`, an unknown `alg`, an older registry version, and `not_before` in the future. A bundle or registry for another `org_id` or `project_id` is refused.
6. **Approved base:** a verified bundle is stored through `policy_versions.store()` and the signed log. Enforced = `meet(bundle base, local tighten-only overlay, on-disk file)`. **The meet is applied per section at enforcement time (N5):** folder, governance, mcp, approval and environment. A hand edit that loosens any one section has no effect, and each section has a test. In managed mode a local change request may only tighten (amends ADR 0001 2.4).
7. **Bad or stale bundle:** an invalid bundle is refused and the last valid one kept (`bundle_rejected`). An expired bundle stays enforced (`policy_stale`). Before the first bundle, the local approved policy applies.

### D3. Audit upload (ADR 0001 section 5)
1. The local chain is the spool. The cursor (`.sandbox/state/sync/cursor.json`) sits under the non-removable deny. Upload is in order, per `(device_id, session_id)`.
2. **Server checks:** `previous_hash` = stored head and `chain_length` = head + 1. Same position and same hash is a no-op. Same position with a different hash is a **fork**: the record is quarantined with an alert, never merged. A gap is refused.
3. **Device checkpoint** (`agg/audit-head/v1`): `{device_id, upload_seq, sessions: [{session_id, chain_length, head_hash}], ts}`. It lists **every local session since enrollment, uploaded or not** (S12). `upload_seq` goes up by exactly 1 (S11); a skip or a repeat is refused and alerted. A session's `chain_length` below an earlier checkpoint raises a **truncation** alert. A session listed earlier and missing later raises `session_missing`.
4. **Server head:** each reply returns the server's head, and the connector raises `server_head_mismatch` when it is behind what was acknowledged. `agg-cp audit verify --project` rechecks every stored checkpoint against the recomputed chains and flags gaps.
5. **`device_silent` (N6):** the server raises it when a device misses its checkpoint window (default 3 x the 60 s poll, configurable). It is tested with the injected clock.
6. The tables `audit_records`, `audit_heads` and `audit_quarantine` are append-only, with triggers as on `admin_audit`. In managed mode, `retention.py` never deletes past the cursor.

### D4. Replay protection and clocks (ADR 0001 section 6)
1. Remote approvals are bound by a fixed field set (D5.6) and a unique nonce, and they expire at `not_after` (15 min of server time, 2 min grace). A done request cannot be claimed again.
2. Assertions use `iat` plus the nonce table. Bundles use `sequence` and `not_before`. Checkpoints use `upload_seq`.
3. **Skew (S15):** the connector measures its skew against the server time in each reply. Above 2 min it refuses remote approvals (denies still apply) and alerts `clock_skew`. Server expiries use the injected clock.

### D5. Key hierarchy (ADR 0003 sections 3-4, pulled into M2; Q1 ruling)
1. **Key kinds and what each may sign (S1b).** The connector enforces this matrix, and the server enforces it too:

| Kind | Where the private key lives | May sign |
|---|---|---|
| `cli` (user) | Key home, `sandbox signer` | registry, policy-change, unenroll, signer-assert; remote-approval and deny **non-prod only in M2** (N9) |
| `browser` (user) | WebCrypto, non-extractable, IndexedDB | remote-approval and deny, **non-prod only** |
| `device` | Key home `device/` | device-enroll, device-assert, audit-head |
| `bundle-signer` | Server secret file (`*_FILE`) | bundle |

2. **CLI root signer (S1a, S2):** `sandbox signer` (MIT) runs on the admin's own machine. `signer link --code` binds a new CLI key to a user. The link code is shown in that user's fresh web session, single use, 15 min. The key is only a proposal until a registry version signed by the admins includes it. **Key substitution (N1):** a compromised server could link its own key to bob's `(iss, sub)`. So `signer link` prints the new key_id locally. `sign-registry` lists every added `cli` key_id and needs a typed confirmation of each, which the admin gets from the key's owner out of band. A key_id that is not confirmed is not signed. `signer genesis` builds registry v1 locally from the server-reported `(iss, sub)`, which the admin confirms, then signs it and prints the root fingerprint. `signer sign-registry`, `approve-change`, `approve` and `deny` fetch the payload and **show the canonical payload and a diff computed from the bytes** (keys added or removed with their `(iss, sub)`, threshold, policy sections) before signing. The CLI authenticates with `agg/signer-assert/v1` assertions, the same way devices do.
3. **Registry** (`agg/registry/v1`): `{org_id, version, prev_hash, threshold, admins[], keys[{key_id, user_id, iss, sub, alg, kind, roles, added_in}], bundle_signer, expires_at}`. The verifier works out how many admin signatures added each key by walking the chain. It never reads a count from the entry, and a forged count field is refused (N8). **Genesis is immutable per org:** the server refuses a second v1 and alerts. **Threshold (S3):** each version needs the threshold of both the previous admin set and its own. The threshold never drops below the highest floor reached, and never below 2 once 2 admins exist. A duplicate `(iss, sub)` is refused, and so is one public key under two `user_id`s. Expiry is 7 days, or 72 h with any prod project.
4. **Single-admin keys (S9):** an approver key counts toward dual control only if the version that added it carried at least 2 admin signatures. Otherwise it is labelled `single_admin_registry` and counts for single approvals only. The demo has 2 admins.
5. **Browser keys (Q1 ruling):** allowed in M2 only for remote approvals and denies on non-prod projects. **Proposal A (N9):** in M2 no key kind may make a remote approval on prod. Prod escalations stay pending unless the signed bundle sets `approval.local_fallback`. The connector reads `environment` from the signed bundle. The evidence pack shows `kind`, and non-prod browser-key dual control is labelled as not meeting ADR 0003 2.3, which is amended.
6. **Remote-approval rules (S10):** tag `agg/remote-approval/v1`. The field set is fixed in code: `_APPROVAL_FIELDS` plus `org_id, project_id, device_id, registry_version, policy_sequence, user_id, key_id, nonce, not_after`. `policy_sequence` must equal the sequence recorded on the escalation. The key must be in the **latest** pinned registry with the `approver` role. Device and bundle-signer keys are refused for every human kind. One `user_id` with two keys counts once.
7. **New domain tags** in `sandbox/protocol/domains.py` (ADR 0007 update): `agg/remote-approval/v1`, `agg/device-enroll/v1`, `agg/signer-assert/v1`, `agg/unenroll/v1`.

### D6. Remote decisions (ADR 0001 section 3, the M2 subset)
1. `sandbox sync` uploads new `pending/` records, scrubbed by `scrub.py`, idempotent on `(device_id, request_id)`. The escalation stores the current `policy_sequence`.
2. Approvals come from the CLI signer or the web page. The server stores them under `SELECT ... FOR UPDATE` with a unique `(escalation_id, user_id)`.
3. **One path in managed mode (S7):** the connector runs `approval.apply_external(layout, request_id, approvals)`, which reuses the `approve()` path (claim, dual check, `FolderBroker.execute`, finish). It drops every approval that is not a registry-verified `agg/remote-approval/v1`. In managed mode, local `approve()` refuses managed requests unless the signed bundle sets `approval.local_fallback`. A mix of local and remote approvals never meets dual control.
4. **Dual control:** two valid approvals from distinct `user_id`s with distinct `(iss, sub)`, each counted under D5.4. **The operator bound at enrollment is the excluded requester (S8)** unless the bundle sets `allow_requester`. One approval leaves the request at 1 of 2, and nothing runs.
5. A deny needs one valid signed decision. Once the registry expires, or skew passes 2 min, remote approvals are refused and denies still apply.
6. **Demo preset:** T0a picks a preset that already sets `requires_dual: true` with the semantic service absent, and commits a passing test that pins it. If no such preset exists, QA stops and asks the lead.

### D7. Protocol (`connector/sync/`, MIT; routes under `/api/v1/sync` in `agg_cp`)
1. **Envelope:** `{kind, sig_v: 1, payload, signatures[{key_id, alg: "ed25519", sig}]}`. The signed bytes are `tag || 0x00 || canonical JSON(payload)`. The tag and field set come from `kind` in code (SEC-24 rule). `key_id` = SHA-256 of the raw public key.
2. **Routes:** `POST enroll`, `POST token`, `GET registry?after=`, `GET bundle?after=` (204 if none), `POST escalations`, `GET decisions?cursor=`, `POST audit`, and the signer routes `link`, `pending` and `signatures`. HTTPS only. `--ca` pins a private CA.
3. **`sandbox sync`** is one process and the only network user. It polls decisions every 10 s and the registry and bundles every 60 s. Offline, it backs off exponentially with jitter, capped at 5 min. The hook path is unchanged, and a socket guard proves that `pre_tool_use` opens no socket.
4. An unenrolled workspace with no `managed` marker behaves exactly as today.

### D8. Failure modes

| Condition | Connector behaviour |
|---|---|
| Server down or network cut | Allow, observe and deny unchanged; escalations stay pending; never an auto-approve; spool waits |
| Bundle invalid, rolled back, wrong project, oversized | Refused; last valid bundle kept; `bundle_rejected` |
| Bundle or registry expired | Bundle stays enforced (`policy_stale`); remote approvals refused once the registry expires |
| Sync state missing or corrupt, marker present | Last valid bundle, else `locked` (D1.7) |
| Device revoked | Token 401; last valid bundle; `device_revoked` |
| Clock skew over 2 min | Remote approvals refused; `clock_skew` |
| Spool disk full | The hook's existing fail-closed audit rule; sync never deletes the spool |

### D9. ADR updates (T0b, before code; security approves in writing)
1. **ADR 0001:** D1 (operator binding, proof of possession, key home, sticky mode, un-enroll), D2.3-2.6, D3.3-3.4, the D7 envelope, and the section 3 subset moved into M2. Q3 is answered.
2. **ADR 0002:** new tables `device_nonces`, `device_tokens`, `signer_nonces`, `signer_tokens`, `sync_alerts` and `signer_links`. Every `SECURITY DEFINER` function is listed (D10.6). Pool settings.
3. **ADR 0003:** the registry and CLI root signer move to M2 (D5.2-5.4). Browser keys are non-prod only. 2.3 is amended with the "not met" label; 2.4 is amended (keystore deferred).
4. **ADR 0005:** the new `api` base image, the bundle-signer secret and a Caddy volume holding only the root cert. **ADR 0007:** device key custody and the four new tags.

### D10. Carry-overs and DB
1. **SEC-27/28:** a CI step provides a dependency-free Python (embeddable CPython zip, pinned by sha256), so the 3 named Windows skips run.
2. **`ee/` on Windows:** a portable process group (`CREATE_NEW_PROCESS_GROUP` on Windows, `start_new_session` elsewhere) replaces `os.setsid`. The symlink test checks for the privilege and skips with a named reason. A new `ee` Windows CI job runs the non-`pg` tests.
3. **`api` image:** a digest-pinned Chainguard Python or distroless base (Q5). The target is Trivy 0 HIGH/CRITICAL, fixed or unfixed.
4. **Lows:** the CSRF tests compute the HMAC independently; the Semgrep warnings at `keyhome.py:198,200` are fixed, not suppressed; the SEC-33 and `root_exposure` domain groups are split; Caddy exports only `root.crt` to its own volume, so `ca-bundle` drops `DAC_READ_SEARCH`.
5. **Pool:** `agg_cp/db.py` sets `pool_size`, `max_overflow`, `pool_pre_ping` and `pool_recycle` from settings.
6. **`SECURITY DEFINER` functions (S13):**
   - device lookup by `device_id`;
   - device token hash to `(org, project, connector)`;
   - atomic enrollment-code consume;
   - signer-link consume;
   - **pre-auth CLI-key lookup by `key_id`**, over registry keys plus pending `signer_links`, for `agg/signer-assert/v1`;
   - signer token hash to `(org, user, key_id)`;
   - nonce insert, unique per `(device_id, nonce)` and per `(key_id, nonce)`.

   Signer tokens are opaque, 10 min, and stored as hashes, the same as device tokens. Each gets `search_path` pinned and `EXECUTE` for `agg_app` only, and each has a security review. Every new table has `FORCE ROW LEVEL SECURITY`, with no exemptions.

## Threats (sync)

| # | Threat | Mitigation | Test |
|---|---|---|---|
| 1 | Enrollment code stolen or reused | Operator-bound, single use, 15 min, hashed, atomic consume | Reuse, expiry, brute force, 4-worker race |
| 2 | Rogue server or MITM at enroll | TLS; fingerprint printed by the CLI signer; required `--expect-fingerprint` | Mismatch aborts, nothing written |
| 3 | Device key read by the agent | Key home with non-removable deny | Every tool, rootless Grep/Glob, env paths, 8.3 names |
| 4 | Assertion replay | `iat` 2 min; unique `(device_id, nonce)` | Replay on another worker refused |
| 5 | Cross-tenant device | Token binds org and project; FORCE RLS | Device A on project B gets 404; RLS catalog |
| 6 | Forged bundle | Signer from the pinned registry; tag from code | Foreign key, flipped byte, embedded key |
| 7 | Bundle rollback or replay | `sequence`, `base_sequence`, `not_before` | Equal, lower and stale-base refused |
| 8 | Downgrade | `sig_v: 1`, alg allowlist, fixed field sets | `sig_v` 0, `alg: none`, short field set |
| 9 | Server loosens policy | Connector-computed loosening; 2 CLI approvals | Server-signed and one-approval loosening refused |
| 10 | Freeze (withheld bundle or revocation) | Expiry; registry expiry stops approvals | `policy_stale`; approvals refused |
| 11 | Malformed or huge bundle | 1 MiB cap, strict parse | Fuzz; the hook still decides |
| 12 | Offline used to slip through | No network in the hook; no timeout approve | Server down: escalated call never runs |
| 13 | Forged or replayed remote approval | D5.6 rules, nonce, `not_after` | Unregistered, other request, expired, reused nonce, stale `policy_sequence` |
| 14 | Same user twice | Distinct `user_id` and `(iss, sub)`; one user's keys count once | bob twice, and bob with a second key |
| 15 | Local tail truncated | Device checkpoint with lengths | Truncation alert |
| 16 | Audit fork | Quarantine | Main chain unchanged |
| 17 | Checkpoint replay or skip | `upload_seq` +1 exactly | Repeat and skip refused |
| 18 | Server deletes or rewinds audit | Append-only triggers; head compare; `audit verify` checkpoints | Planted rewind gives `server_head_mismatch` (limit 5) |
| 19 | Secrets in uploads | `scrub.py` before upload | Secret corpus absent from DB rows |
| 20 | Agent edits sync state | Non-removable deny | Write/Edit/shell denied |
| 21 | Server JS signs with browser keys (S1) | Kind matrix; browser keys for non-prod approve/deny only | Browser-key registry, policy-change and prod approval refused |
| 22 | Second genesis, or a server-shown fingerprint (S2) | Immutable v1; fingerprint from the CLI | Second v1 refused and alerted |
| 23 | Registry threshold downgrade or duplicate identity (S3) | Double threshold, floor | Downgrade, admins cut to 1, duplicate `(iss, sub)`, shared key |
| 24 | Older looser bundle replayed as "tightening" (S4) | Connector-side base | Property test over bundle sequences |
| 25 | Loosening via non-folder sections or `environment` (S5) | Per-section loosened; absent means prod | One test per section; prod to non-prod |
| 26 | Delete sync state to fall back to standalone (S6) | Sticky marker; `locked` | Demo step 8 |
| 27 | Local plus remote approval meets dual control (S7) | One path in managed mode | Mix refused |
| 28 | Operator approves own escalation (S8) | Operator bound at enroll | Operator refused |
| 29 | Bundle or registry replayed across project or org | `org_id` and `project_id` checked | Project-B bundle, org-B registry |
| 30 | One admin picks the approvers (S9) | `single_admin_registry` label | Its keys never count for dual control |
| 31 | Device or bundle-signer key used as approver (S10) | Kind matrix | Device-signed approval refused by server and connector |
| 32 | Never-uploaded session deleted (S12) | Session list in each checkpoint | `session_missing` (limit 6) |
| 33 | Server links its own CLI key to another user (N1) | key_id printed locally; typed out-of-band confirmation in `sign-registry` | Substituted key_id not confirmed: not signed |
| 34 | Un-enroll by one person with two local ids (N2) | Only a quorum-signed `agg/unenroll/v1`, online or as a file | Local two-reviewer un-enroll refused; forged decision file refused |
| 35 | Device state wiped by the operator or same-user code (N6) | Server `device_silent` after the missed window | Injected clock: alert raised after the window, not before |
| 36 | Remote approval on prod (N9) | Proposal A: no remote approvals on prod in M2 | CLI-key and browser-key approvals on prod refused; escalation stays pending |

## Tests first

1. **T0a (QA):** freeze at `9b0d1b0` in `M2_BASELINE.md` and `M2_FROZEN_MANIFEST.sha256` (every tracked file under `tests/` and `ee/tests/`). Also freeze the node-id sets, the per-environment named skip lists, the **threat-to-node-id matrix** (node ids fixed now) and the demo preset.
2. **Per task:** QA commits the failing tests first. Each is `pytest.mark.xfail(strict=True, raises=M2T<n>Pending)`, a sentinel in `tests/m2_pending.py` and `ee/tests/m2_pending.py` that a helper raises while the feature is absent. The count goes into `M2_BASELINE.md` in the same commit. The build removes only the markers. Any other test edit: stop and ask QA and security.
3. **Postgres boundary (Q2):** every `tests/**/test_m2_*` file is Postgres-free. It uses a fake server (`tests/m2_fakes.py`) that serves fixtures signed by keys made in the test. The `sync_server` fixture (real `agg_cp`, `--workers 4`, Postgres 16, no SQLite) lives only in `ee/tests/conftest.py`. The connector CI job has no Postgres.
4. **Frozen files:** no connector test changes. The named `ee/` exceptions are `test_t8p2_session.py` (3 CSRF tests made stronger), `test_t10_multiworker.py` and `test_m1_t13_review.py` (setup only). Security signs off by node id. Any other frozen failure: stop, list it, security decides.

## Tasks (in order; one small commit each; git-ops commits every task from the owner's file list)

Tiers: **L** = leader (Opus 5.5, high). **W** = worker (Opus 4.6, high). **S** = support (Sonnet 5.5, medium). Git ops (Sonnet 4.6, medium) do all commits and pushes. Security does diff reviews (W) on every task touching auth, keys, policy, audit or the broker; design rulings go to security at L.

| ID | Title | Owner | Tier | Depends on | Tests first (file; `raises=`) | Exit check |
|---|---|---|---|---|---|---|
| T0a | Freeze baseline, skip lists, threat matrix; pick the demo preset | qa | W | plan approved | `tests/security/test_m2_t0a_demo_preset.py` (passes now; not xfail) | Files committed; the preset is frozen with `requires_dual: true` and its test passes |
| T0b | ADR updates (D9); founder rulings recorded | lead, security | L | plan approved | n/a | ADRs committed; security approval quoted |
| T1 | Dependency-free Python in CI; SEC-27/28 run | devops | W | T0a | none: the 3 named skips must become passes | CI Windows: the 3 ids passed, 0 skipped |
| T2 | `ee/` tests on Windows; `ee` Windows CI job | qa, devops | W | T0a | `ee/tests/test_m2_t2_portable.py`; `M2T2Pending` | 0 failed; skip set = frozen named `pg` list |
| T3 | Lows and DB pool (D10.4-10.5) | backend, devops | W | T0a | `tests/security/test_m2_t3_domain_groups.py`, `ee/tests/test_m2_t3_caddy_ca.py`, `ee/tests/test_m2_t3_pool.py`, the 3 named CSRF nodes; `M2T3Pending` | Domain groups split, as the tests assert; Semgrep 0 warnings in `keyhome.py`; no `DAC_READ_SEARCH`; pool leak test passes on 4 workers |
| T4 | Slim `api` base image | devops | W | T0a, Q5 | `ee/tests/test_m2_t4_image.py` (digest pin, non-root, no shell); `M2T4Pending` | Trivy `api` 0 HIGH/CRITICAL; `/ready` 200 |
| T5 | M2 tables, FORCE RLS, append-only triggers, D10.6 functions | backend | W | T0b | `ee/tests/test_m2_t5_schema.py`; `M2T5Pending` | RLS catalog covers 100% of tables; triggers hold; Alembic round trip; security reviews each function |
| T6 | Envelope, tags, kind matrix, registry chain and threshold (connector and server) | backend | W | T5 | `tests/security/test_m2_t6_registry.py`, `ee/tests/test_m2_t6_registry.py`; `M2T6Pending` | Threats 8, 21-23, 29-31 (registry half) pass; a forged signature-count field is refused (N8) |
| T7 | `sandbox signer` (link, genesis, diff view, sign) and server signer routes | backend | W | T6 | `tests/security/test_m2_t7_signer.py`, `ee/tests/test_m2_t7_signer.py`; `M2T7Pending` | The diff is computed from the bytes; threat 33 passes; stale-login link refused; key live only after quorum; IDOR 404s; signer nonce replay refused |
| T8 | Enroll (operator, PoP, atomic consume), tokens, revocation, sticky mode, un-enroll | backend | W | T6 | `tests/security/test_m2_t8_enroll.py`, `ee/tests/test_m2_t8_enroll.py`; `M2T8Pending` | Threats 1-5, 26, 34 pass; locked reads still hit protections and default read denies (N7); code race on 4 workers: exactly 1 winner |
| T9 | Bundles: per-section loosening, connector base, `environment`, store, overlay | backend | W | T6, T8 | `tests/security/test_m2_t9_bundles.py`, `ee/tests/test_m2_t9_bundles.py`; `M2T9Pending` | Threats 6, 7, 9-11, 24, 25, 29 pass; property test: enforced is never looser than the approved base over random bundle sequences; per-section hand-edit loosening has no effect (N5); deny-all first base needs 2 approvals (N3) |
| T10 | `sandbox sync` process, backoff, state denies, socket guard | backend | W | T8, T9 | `tests/security/test_m2_t10_sync.py`; `M2T10Pending` | Threats 12, 20 pass; backoff grows and caps at 5 min (injected clock) |
| T11 | Audit upload, device checkpoints, quarantine, retention guard, `audit verify --project` | backend | W | T8, T10 | `tests/security/test_m2_t11_audit.py`, `ee/tests/test_m2_t11_audit.py`; `M2T11Pending` | Threats 15-18, 32, 35 pass; load run per gate item 6 |
| T12 | Escalations, decisions, `apply_external` (TCB), managed `approve()` refusal, skew rule | backend | W | T7, T10 | `tests/security/test_m2_t12_remote.py`, `ee/tests/test_m2_t12_remote.py`; `M2T12Pending` | Threats 13, 14, 19, 27, 28, 31, 36 pass, incl. a device-signed approval refused by server and connector; security signs off the TCB change |
| T13 | Web pages: browser key enroll, pending list, approve/deny (WebCrypto Ed25519) | frontend | W | T7, T12 | `ee/web` tests (signed bytes equal the server's canonical bytes); `M2T13Pending` | Build and lint pass; strict CSP; no private key in any request (HAR) |
| T14 | Compose: bundle-signer secret, carol (second admin), `payments-staging` | devops | W | T4, T8 | `ee/tests/test_m2_t14_deploy.py`; `M2T14Pending` | Clean E: checkout up; `/ready` 200; ZAP 0 High incl. `/api/v1/sync` |
| T15 | Hostile review of the M2 diff | security | L | T1-T14 | n/a | `M2_SECURITY_SIGNOFF.md`; each finding resolved or a stated limit |
| T16 | Gate run and demo (`demo.py`, `--live`) | qa | W | T15 | `ee/tests/test_m2_t16_demo_static.py`; `M2T16Pending` | Gate filled with measured numbers; `M2_DEMO.md` |
| T17 | Docs (`CONNECTOR.md` sync and signer, `TCB.md`, README); founder summary | lead (edits: support) | L, S | T16 | n/a | Docs grep clean; `M2_DONE.md` draft; wait for founder |

**Cut order if late:** first T13. Demo step 5 then runs in two terminals, with bob and carol each using `sandbox signer approve` and their own CLI keys, recorded as such. Plain `sandbox approve` is refused in managed mode (S7). Then T3's Lows. T5-T12 are never cut.

## Gate: M2 is done when all of these are true

**Freeze rule:** T0a and the tests-first commits write every node-id set, count, skip list, the threat matrix and the demo steps into `M2_BASELINE.md` and `M2_FROZEN_MANIFEST.sha256` before the first gate run. After that only a founder ruling recorded there can change an item. The gate runs once, and the result is reported whatever it is.

1. **Connector suite:** in each environment (local Windows, CI `windows-latest`, CI Linux), the count = M2 baseline + frozen M2 tests, with 0 failed, 0 xfailed and 0 xpassed. The rows below are in `M2_BASELINE.md`:
   - **0 skipped except that environment's named list.**
   - CI Windows: the named list does not hold the 3 SEC-27/28 ids.
   - The manifest checks OK except the named exceptions.
   - `git status --porcelain` is clean.
2. **`ee/` suite:**
   - CI Linux: node-id set = frozen, 0 failed, 0 skipped.
   - CI Windows: 0 failed, 0 skipped except the named `pg` list.
   - Branch coverage on `ee/src/agg_cp` is at least 85%, with no omit list.
3. **Standalone:** with `ee/` removed, the connector count is unchanged. A fresh venv `pip install .` passes M0 E2E 16/16, **with step 5 dual control exercised** (the frozen preset, two local reviewers).
4. **Scanners on a fresh clone:**
   - Semgrep: 0 ERROR, 0 warnings in `keyhome.py`.
   - Gitleaks 0, Trivy fs 0.
   - Trivy `api` image: 0 HIGH/CRITICAL, fixed or unfixed.
   - ZAP: 0 High, including `/api/v1/sync`.
5. **Threats:** every row in the frozen threat matrix has a passing node id.
6. **Load:** 20 connectors x 200 records, 4 workers, one Postgres. The pass condition is 0 lost, 0 duplicated, 0 false forks and 0 pool errors. A pool error is a checkout timeout, a `PoolTimeout`, or an `app.org_id` leak across connections, which a probe checks per request. Wall time is recorded.
7. **Demo:** `demo.py` on a fresh clone, every step PASS. The `--live` step 5 is run once by two people in two browsers, and their names are recorded.
8. Security sign-off (T15) and founder approval.

## Design-partner demo (T16, `ee/deploy/demo.py`, `M2_DEMO.md`)

Headless by default. Separate httpx sessions log in through Keycloak as different users. CLI signers use separate key homes, and browser signing is played by a Python signer over the same canonical bytes. `--live` pauses at step 5 so two people in two browser profiles click. Each step prints PASS or FAIL, and any FAIL fails the run. Users: alice (admin, operator), carol (admin, approver), bob (approver), eve (Globex).

1. **Fresh stack:** `down -v`, `init-secrets`, `up`. PASS if `/ready` is 200.
2. **Root and registry:**
   - alice links a CLI key and runs `signer genesis`, which creates v1 and prints the fingerprint locally.
   - carol links a CLI key. v2 makes her an admin (threshold 2) and is signed by alice and carol.
   - bob and carol enroll browser keys. v3 is signed by both admins after the diff is shown and each added `cli` key_id is confirmed by typing it.
   - PASS if:
     - v3 verifies offline from the printed fingerprint;
     - a second genesis is refused;
     - a browser-key signature on a registry version is refused;
     - a threshold-1 v4 is refused;
     - a v4 with a substituted, unconfirmed key_id is not signed (N1).
3. **Enroll:** alice issues a code to herself as operator for `payments-staging`. `sandbox enroll --expect-fingerprint <printed FP>`. PASS if enrollment succeeds, code reuse is refused, and a wrong fingerprint aborts with nothing written.
4. **Bundles:**
   - carol publishes a tightening bundle with one CLI approval. PASS if a command that was allowed escalates within 60 s.
   - Then each of these is refused, and the connector stays on the new bundle:
     - a byte-flipped bundle from the test proxy;
     - a replay of the old sequence;
     - a server-signed loosening with no approvals;
     - a one-approval loosening that names an old base;
     - a bundle for project B;
     - a move from `prod` to non-prod with one approval.
   - **Non-prod switch (N4):**
     - Before the switch, a remote approval on `payments-staging` is refused, because an absent `environment` means prod.
     - alice and carol then sign a two-approval bundle that sets `environment: staging`.
     - PASS if the connector reports non-prod after the switch.
5. **LIVE dual control:** the agent runs the frozen preset, and it reaches the inbox.
   - (a) bob approves. PASS if the request is pending at 1 of 2 and the marker file is absent.
   - (c) bob approves again, and bob approves with his second key. PASS if each gets the expected `same_user` refusal.
   - (c) alice approves. PASS if she gets `requester`.
   - (c) a device-signed approval. PASS if it gets `wrong_kind`.
   - (b) carol approves. PASS if the marker exists and the action ran once, in the broker, and the done-record holds two `user_id`s that verify offline against the pinned registry.
6. **Offline fail closed:** stop `api`. PASS if a deny-class call is denied, the critical call stays pending past 3 poll intervals without running, and an allow-class call allows. Restart `api`. PASS if the heads match.
7. **Audit truncation:** as the operator, cut the last 3 records of a session, append 2, and sync. PASS if fork and truncation alerts appear, the records are quarantined, `audit verify --project` passes on the main chain, and alice sees the alert.
8. **Sticky and revoke:**
   - Delete `.sandbox/state/sync/` as the operator. PASS if the connector stays on the last bundle, with no fallback to the looser local policy.
   - Delete `policy_history/` too. PASS if the connector is `locked`.
   - Re-enroll, then alice revokes the device. PASS if the next sync call gets 401 and local enforcement holds.
9. **Tenancy:** PASS if every Acme connector, escalation and audit id gives eve 404.
10. **Persistence:** `down`, then `up`. PASS if the registry, bundles and heads persist and `audit verify` passes.

## Honest limits

1. Browser keys are software keys in a browser profile, with no user verification per signature. **A compromised server can forge non-prod remote approvals and denies through the browser keys of any user who loads its page.** It cannot sign registries, loosen policy, un-enroll, or approve on prod (S1c).
2. Dual control proves two distinct IdP identities with two keys, not two non-colluding people. M2 non-prod dual control does not meet ADR 0003 2.3. Only the `--live` run involves two people.
3. A compromised server can withhold policy, decisions and revocations until `expires_at`, and can block approvals.
4. Key-home keys stop the hook-governed agent, not other code running as the same OS user (ADR 0007 D2.7). Such code, **or the human operator**, can also delete both markers and the state and return to standalone (N6). No local check can catch that. The server raises `device_silent` after a missed checkpoint window (D3.5), but by then the workspace may already be running standalone.
5. A compromised server that deletes the tail of its stored audit is not detected server-side until SEC-15. The connector's head compare catches it only while that connector keeps syncing.
6. A session created and deleted entirely while offline, by same-user code, never appears in a checkpoint.
7. `agg_owner` can still drop the audit tables. No compliance claims; numbers are from the dev laptop and CI only.

## Risks

1. **Scope.** This is M2 plus part of M3 plus the CLI signer. Mitigation: the cut order; T5-T12 first.
2. **`apply_external` and managed `approve()` are TCB changes.** Tests first, security review, and the `approve()` path is reused, not forked.
3. **WebCrypto Ed25519** needs a current browser. The page refuses to sign without it and never falls back to server-side signing.
4. **Chainguard free images are latest-only.** Digest pin plus a rebuild cadence; any remaining HIGH is reported.

## Review disposition

| Finding | Where fixed, or why skipped |
|---|---|
| S1 Critical | D5.1 kind matrix, D5.2 CLI root signer, D5.5; limit 1 rewritten; threat 21 |
| S2 | D1.3, D5.2, D5.3 immutable genesis; threat 22; demo 2-3; old limit 5 removed |
| S3 | D5.3 double threshold, floor, duplicates; threat 23; demo 2 |
| S4 | D2.3 connector-side base, `base_sequence`; threat 24; T9 property test |
| S5 | D2.4 per-section loosening, `environment`; threat 25; demo 4 |
| S6 | D1.7-1.8 sticky mode, `locked`, un-enroll; threat 26; demo 8; limit 4 |
| S7 | D6.3; threat 27; T12 |
| S8 | D1.1, D6.4 operator as requester; threat 28; demo 5 |
| S9 | D5.4 `single_admin_registry`; threat 30; demo has 2 admins |
| S10 | D5.6, D5.1; threats 13, 14, 31 |
| S11 | D3.3 `upload_seq` +1; D3.4 `audit verify` checkpoints; limit 5 |
| S12 | D3.3 session list in checkpoint; threat 32; limit 6 |
| S13 | D10.6 (pre-auth CLI-key lookup over registry plus pending links; signer token and nonce storage), D9.2 `signer_nonces` and `signer_tokens`, D1.2 PoP and atomic consume, D1.4 nonce key; T5, T7, T8 |
| S14 | Threats 21-36; matrix frozen at T0a; demo 4-5 |
| N1 High | D5.2 key_id printed locally and typed confirmation; threat 33; T7; demo 2 |
| N2 | D1.8: local two-reviewer route dropped; offline `agg/unenroll/v1` file (`signer unenroll --out`, `sandbox unenroll --decision`); threat 34; T8 |
| N3 | D1.7, D2.3 deny-all first base; T9 exit check |
| N4 | Demo 4 non-prod switch with two approvals, and a remote approval refused before it |
| N5 | D2.6 per-section meet at enforcement; T9 exit check |
| N6 | Limit 4 names the operator; D3.5 `device_silent`; threat 35; T11 |
| N7 Low | D1.7 locked reads keep the protections; T8 exit check |
| N8 Low | D5.3 the signature count is computed, never read; T6 exit check |
| N9 Low | D5.1 `cli` row non-prod only; D5.5 proposal A; threat 36; T12 |
| Ruling A / B | Recorded as proposals A (D5.5, non-goal 2) and B (D1.7); security accepts on N9, and on N3 plus N7; founder questions 4-5 |
| S15 Low | D4.3 skew refusal; D8 |
| Q1 ruling | D5.1, D5.5, D2.4 `environment`; ADR 0003 2.3 amended (D9.3) |
| Q3 ruling | D1.6; ADR 0001 Q3 and 0003 2.4 amended (D9) |
| QA Q1 | Gate item 1 named skip lists |
| QA Q2 | Tests first item 3 |
| QA Q3 | T3 tests first and exit check |
| QA Q4 | D6.6, T0a exit check |
| QA Q5 | T3 file names |
| QA Q6 | Demo step 5 (a)-(c) |
| QA Q7 | T12 exit check; demo 5 |
| QA Q8 Low | T0a exit check |
| QA Q9 Low | Gate item 6 |
| QA Q10 Low | T10 exit check |
| QA Q11 Low | Cut order. The fallback uses `sandbox signer approve`, not `sandbox approve`, because S7 refuses local approvals in managed mode |

## Founder rulings (21 Oct 2026)

**The founder approved the plan on 21 Oct 2026.** Security's final-check findings F1-F5 (`REVIEW_M2.md`) go into the ADR 0001 text at T0b, before T5.

1. **Live step:** a real second person. Gate item 7 records two names.
2. **`sandbox watch`:** off by default in managed mode. Turning it on is a signed, two-CLI-approval loosening (D2.4).
3. **`api` base image:** Chainguard Python, pinned by digest. T4 records the tag and update policy. The fallback is a Wolfi base built with apko.
4. **Proposal A accepted:** no remote approvals on `prod` projects in M2, for any key kind. Condition N9 applies.
5. **Proposal B accepted:** if the sync state and the last bundle are both lost, the workspace goes `locked` until re-enrollment. Conditions N3 and N7 apply.
