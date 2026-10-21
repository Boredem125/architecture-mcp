# ADR 0003: OIDC login and approver keys bound to people

Status: Accepted (17 Oct 2026). Key-custody choice **decided**: the founder had no preference, so the team recommendation stands (passkeys, option C). Reviewed by security-engineer (`docs/control-plane/REVIEW_SECURITY.md`). Amended for M2 (21 Oct 2026, M2 T0b): the registry and the CLI root signer move into M2, and 2.3 and 2.4 are amended. See "M2 amendments".

## Next action

Backend-engineer (M2 T6, T7): build the registry chain and `sandbox signer` against "M2 amendments", tests first. Passkeys (Decision 2) stay in M3.

## Context

1. Today a reviewer is a string. `approval.default_reviewer()` uses `SANDBOX_REVIEWER` or the OS user. API approvals are all `"api"` (`src/sandbox/api/routes/connector.py`).
2. Keys are seeds created on first use at `.sandbox/state/keys/<reviewer>.seed` (`connector/signing._load_or_create_key`). Anyone who can name a new reviewer id gets a new key, so "two distinct ids and keys" is not "two people" (stated in `connector/approval.py` and docs/TCB.md).
3. `verify_record` / `verify_approval` trust the public key embedded in the record. Only `tool_grants.py` pins the folder's key.
4. The wedge (STARTUP.md) is non-repudiable human approval and dual control that really is two humans. HMAC receipts (Verosek) prove integrity, not who approved.

## Options: where the approver private key lives

| Option | Non-repudiation | Usability | Offline verification by connector | Main risk |
|---|---|---|---|---|
| **A. Server-side key per user (KMS/HSM), server signs after OIDC login** | Weak: the server or its admin can sign as anyone | Best | Yes | Server compromise = forge any approval. Same as today with extra steps. |
| **B. Browser WebCrypto key (Ed25519, non-extractable, in IndexedDB)** | Medium: key never leaves the browser profile; malware in the browser can use it silently | Good; lost if browser data cleared | Yes (plain Ed25519) | No user-verification step per signature |
| **C. WebAuthn passkey; the approval payload hash is the challenge** | Strongest practical: key in a platform authenticator or security key, user verification (PIN/biometric) on every approval | Good (Touch ID, Windows Hello, YubiKey) | Yes: store `authenticatorData`, `clientDataJSON`, signature; verify ES256 or EdDSA | Synced passkeys are copyable by the user's cloud account; ES256 needs P-256 verification in the connector |

## Decision

### 1. Human login: OIDC
1. Authorization code + PKCE against the customer's IdP (Entra ID, Okta, Google, Keycloak). Library: Authlib. Server-side sessions in Postgres, short idle timeout.
2. Identity = `(issuer, subject)`, never email. Roles from `role_bindings` (ADR 0002); optional mapping from IdP group claims. SCIM provisioning later.
3. Sensitive actions (approve, enroll key, change roles) need a fresh login (`max_age`, 15 min default).
4. Bootstrap: the install creates one admin through a one-time setup code printed by the migrations job, then OIDC is required.

### 2. Approver keys: WebAuthn passkeys (Option C) as the default
1. An approver enrolls a passkey after a fresh OIDC login. The connector-side approval payload is the existing `_APPROVAL_FIELDS` plus `device_id`, `project_id`, `policy_version`, `nonce`, `not_after` (ADR 0001). Challenge = SHA-256 of that canonical payload.
2. Accepted algorithms: EdDSA (Ed25519) and ES256. The connector verifies offline from the stored assertion. This adds a P-256 verify dependency (`cryptography`) to the connector; PyNaCl stays for Ed25519.
3. **Device-bound** passkeys (attestation, no sync; PIN or biometric on every approval) are required for `prod` projects and for every dual-control action. Synced passkeys are allowed for non-prod only. (Decided 17 Oct 2026.)
4. **Software Ed25519 keys** (today's format) remain only for: standalone OSS mode (unchanged), CLI approvers, and break-glass. In managed mode they live in the OS keystore (DPAPI or Keychain), never in the workspace. In the registry they are `kind=software`, and the evidence pack shows the kind next to every approval.

### 3. Binding keys to people: the key registry
1. The registry lists `{user_id, oidc issuer+subject, display name, key_id, public_key, alg, kind, roles, enrolled_at}`. It is versioned (monotonic) and has an `expires_at` (default 7 days).
2. Each registry version is signed by the org's **admin quorum** from the previous version (TUF-style root chain): 1 admin signature while the org has one admin, 2 once it has two or more (configurable up, not down below 2). The server cannot add a key on its own.
3. The connector pins the first registry at enrollment (fingerprint check, ADR 0001) and only accepts later versions that chain from it.
4. **Rotation:** enroll the new key (new registry version), then revoke the old one.
5. **Revocation:** a new registry version without the key. Approvals signed before revocation stay valid in history. An offline connector learns of revocation at most at the registry `expires_at`; after that, it refuses remote approvals (denies still work) until it refreshes. Approval lifetime (`not_after`, 15 min) bounds the exposure further.

### 4. Dual control = two distinct humans (as far as we can prove)
A dual-control action needs two valid approvals where:
1. both keys are in the current registry and not revoked,
2. the keys belong to two different `user_id`s with different `(issuer, subject)`,
3. neither user is the requester (the user who enrolled the device), unless policy allows it (`dual.allow_requester: false` default),
4. both approvals cover the same `request_id`, `fingerprint` and `command` (existing `approval._valid_for` check).

**Stated limit:** we prove two distinct IdP identities with two distinct authenticators. We cannot prove they are not one person with two IdP accounts, or two colluding people. That is the IdP's and the customer's control.

### 5. Break-glass
1. Only for when the control plane is down. A user with a `kind=software` or security-key break-glass key in the cached registry signs locally: `sandbox approve <id> --break-glass --reason "..."`.
2. It requires a written reason, works for one request only, raises a local alert immediately, is tagged `break_glass` in the audit, and opens a mandatory review item in the inbox on reconnect.
3. Dual-control actions still need two break-glass approvals from two users. There is no single-person override.

## Consequences

1. The connector's approval verification changes from "embedded key" to "registry key". Old records keep verifying with the old function (the evidence pack labels them `unbound`).
2. The web inbox (frontend) must implement WebAuthn ceremonies; approvals cannot be made by API token alone in managed mode.
3. `approval.default_reviewer()` and on-first-use key creation stay for standalone mode only.
4. The `"api"` reviewer goes away in managed mode.

## Security properties affected

1. **Non-repudiation:** from "some key signed this" to "this enrolled person, with user verification, signed this exact request".
2. **Dual control:** from distinct ids/keys to distinct IdP identities and distinct authenticators.
3. **Trust root:** the admin quorum, not the server. A server compromise can block approvals but cannot forge them or loosen policy.
4. **Key custody:** private keys never reach the server or the workspace in managed mode (except opt-in software break-glass keys, which must be outside the folder, e.g. in the OS keystore).

## Open questions

1. ~~Founder: passkeys instead of "Ed25519 everywhere"?~~ **Decided 17 Oct 2026:** passkeys in managed mode; Ed25519 software keys for standalone, CLI and break-glass only.
2. ~~Founder: synced vs device-bound?~~ **Decided:** device-bound for `prod` and dual control; synced allowed for non-prod.
3. ~~Security: 7-day registry expiry?~~ **Answered:** 7 days default, 72 hours for `prod`, configurable down only.
4. ~~Security: requester-cannot-approve for a solo partner?~~ **Answered:** keep the default; opt in through a signed policy flag that the evidence pack shows.

## M2 amendments (21 Oct 2026, M2 T0b)

Source: `docs/control-plane/M2_PLAN.md` D5 and the founder rulings of 21 Oct 2026; security S1-S3, S9-S10, N1, N8-N9, F5 and the Q1 and Q3 rulings in `REVIEW_M2.md`. Sections 3 and 4 move from M3 into M2 as the minimum the live dual-control step needs. Sections 2 (passkeys) and 5 (break-glass) stay in M3. Where this section differs from the text above, this section wins.

### 1. Key kinds and what each may sign (S1b; Q1 ruling)

The connector enforces this matrix, and the server enforces it too.

| Kind | Where the private key lives | May sign |
|---|---|---|
| `cli` (user) | Key home, `sandbox signer` | registry, policy-change, unenroll, signer-assert; remote-approval and deny **non-prod only in M2** (N9) |
| `browser` (user) | WebCrypto, non-extractable, IndexedDB | remote-approval and deny, **non-prod only** |
| `device` | Key home `device/` (ADR 0007) | device-enroll, device-assert, audit-head |
| `bundle-signer` | Server secret file (`*_FILE`, ADR 0005) | bundle |

Device and bundle-signer keys are refused for every human kind. In M2 the registry `kind` values are `cli` and `browser`; `webauthn` returns with passkeys in M3.

### 2. CLI root signer (S1a, S2, N1; F5)

1. `sandbox signer` (MIT) runs on the admin's own machine. It signs with a key-home key, never a browser key.
2. **Link.** `signer link --code` binds a new CLI key to a user. The link code is shown in that user's fresh web session, is single use and lasts 15 min. `signer link` prints the new `key_id` locally. The key is only a proposal until a registry version signed by the admins includes it.
3. **Pending keys (F5).** A signer token issued to a pending, unconfirmed linked key may only complete that link. It cannot read pending payloads, post signatures, or reach any other route. An IDOR test covers this (T7).
4. **Key substitution (N1).** A compromised server could link its own key to bob's `(iss, sub)`. So `sign-registry` lists every added `cli` key_id and needs a typed confirmation of each one. The admin gets each key_id from the key's owner out of band. A key_id that is not confirmed is not signed.
5. **Genesis.** `signer genesis` builds registry v1 locally from the server-reported `(iss, sub)`, which the admin confirms. It signs v1 and prints the root fingerprint (the fingerprint of v1's signed bytes, which include every v1 admin public key and the threshold; the exact encoding is fixed in code at T6). This is the value the enrolling operator passes to `--expect-fingerprint` (ADR 0001 A1.3). The web UI never shows it as the check value.
6. **Show what is signed.** `signer sign-registry`, `approve-change`, `approve` and `deny` fetch the payload, show the canonical payload and a diff computed from the bytes (keys added or removed with their `(iss, sub)`, threshold, policy sections), then sign.
7. The CLI authenticates with `agg/signer-assert/v1` assertions, the same way devices do (ADR 0001 A1.12).

### 3. Registry (amends section 3; S3, S9, N8)

1. **Payload** (`agg/registry/v1`): `{org_id, version, prev_hash, threshold, admins[], keys[{key_id, public_key, user_id, iss, sub, alg, kind, roles, added_in}], bundle_signer, expires_at}`. The verifier checks that each `key_id` is the SHA-256 of its `public_key`, and `bundle_signer` carries its public key the same way. The envelope carries only `key_id`, so the public key must come from the registry.
2. **Genesis is immutable per org.** The server refuses a second v1 and alerts. The connector pins only through `sandbox enroll --expect-fingerprint` and accepts later versions only if they chain from that v1 (amends 3.3; ADR 0001 A1.9).
3. **Threshold (replaces 3.2).** Each version needs the threshold of both the previous admin set and its own. The threshold never drops below the highest floor reached, and never below 2 once 2 admins exist. Only `kind=cli` admin keys count, one per user.
4. **Identity.** A duplicate `(iss, sub)` is refused. So is one public key under two `user_id`s.
5. **Signature counts are computed (N8).** The verifier works out how many admin signatures added each key by walking the chain. It never reads a count from the entry, and an entry that carries a count field is refused.
6. **Single-admin keys (S9).** An approver key counts toward dual control only if the version that added it carried at least 2 admin signatures. Otherwise it is labelled `single_admin_registry` and counts for single approvals only.
7. **Expiry (amends 3.1 and open question 3).** 7 days, or 72 h if the org has any prod project. Once it expires, remote approvals are refused and denies still apply.

### 4. Dual control (amends section 4)

1. 4.1: "the current registry" means the **latest pinned** registry. The key needs the `approver` role.
2. 4.2: one `user_id` with two keys counts once.
3. 4.3: the requester is the **named operator bound at enrollment** (ADR 0001 A1.1), not the user who issued the code. The flag is `approval.allow_requester` in the signed bundle (was `dual.allow_requester`). Turning it on is a loosening.
4. The remote-approval field set and rules are in ADR 0001 A3.4.

### 5. Browser keys, prod and 2.3 (Q1 ruling; founder ruling 4)

1. **Browser keys** (option B in the table above) are allowed in M2 only for remote approvals and denies on non-prod projects. They come from the web page, which refuses to sign without WebCrypto Ed25519 and never falls back to server-side signing.
2. **No remote approvals on prod in M2, for any key kind** (proposal A, N9). Prod escalations stay pending unless the signed bundle sets `approval.local_fallback`. The connector reads `environment` from the signed bundle; absent means prod.
3. **2.3 amended.** 2.3 requires device-bound passkeys for prod and for every dual-control action. M2 has no passkeys. So M2 makes no remote approvals on prod, and **M2 non-prod dual control does not meet 2.3.** The evidence pack shows the key `kind` next to every approval and labels such a decision as not meeting ADR 0003 2.3. 2.3 itself stands as the M3 target.

### 6. Software key custody (amends 2.4; Q3 ruling)

2.4 said managed-mode software keys live in the OS keystore. That is deferred. CLI signer keys and the device key live in the key home under the non-removable deny (ADR 0007). Reason: DPAPI and Keychain do not stop code running as the same user (ADR 0007 limit 1), so they would not change the M2 threat picture.

### 7. Consequences and security properties (amends both sections above)

1. Consequence 2: in M2 the web page signs with WebCrypto Ed25519 browser keys, non-prod only. WebAuthn ceremonies come in M3.
2. **Security property 3 does not hold for browser keys.** A compromised server serves the page's JS, so it can sign non-prod remote approvals and denies with the browser key of any user who loads the page. It cannot sign registries, loosen policy, un-enroll, or approve on prod, because those need CLI keys or are refused. Passkeys would not close this signing oracle either; the local root signer is the control that matters here.
3. Security property 1 (user verification on every approval) is an M3 property. M2 CLI and browser keys have no per-signature user verification.
4. Dual control proves two distinct IdP identities with two keys, not two non-colluding people (the stated limit in section 4 stands).
