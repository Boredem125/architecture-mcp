# ADR 0003: OIDC login and approver keys bound to people

Status: Accepted (17 Oct 2026). Key-custody choice **decided**: the founder had no preference, so the team recommendation stands (passkeys, option C). Reviewed by security-engineer (`docs/control-plane/REVIEW_SECURITY.md`).

## Next action

Founder: approve or reject "passkeys (WebAuthn) as the main approver key, software Ed25519 only for break-glass/CLI" (Decision 2). This changes the key format from today's Ed25519-only.

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
