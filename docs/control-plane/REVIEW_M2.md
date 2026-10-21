# M2 plan reviews (21 Oct 2026)

Reviews of the `M2_PLAN.md` draft. The founder approves the plan only after the Critical and every High finding are fixed and security-engineer has re-reviewed.

## security-engineer (claude-opus-5-5, leader tier): APPROVE WITH CONDITIONS

The Critical and every High finding must be in `M2_PLAN.md` and the T0b ADR text, followed by a re-review. No T5+ code before then.

1. [Critical] D5.4 / Q1 / limit 3 / threats 9, 13. The claim "a compromised server cannot loosen policy or forge an approval" is false with browser WebCrypto keys. The server serves the JS, so it can sign with any non-extractable IndexedDB key whenever a user loads the page. The registry is org-wide, so a registry version signed by server-controlled JS that adds a server-held key also compromises prod.
   - (a) Registry genesis, every registry version and every loosening `agg/policy-change/v1` approval come only from a local CLI signer. The signer shows the canonical payload and the diff from the bytes, and signs with a key-home key, never a browser key.
   - (b) The connector enforces which signature kinds and roles each key kind may make. Browser keys may make only `agg/remote-approval/v1` and deny.
   - (c) Rewrite limit 3: a compromised server can forge non-prod remote approvals through the browser keys of users who load the page.
2. [High] D1.3 / D5.2 / threat 2. The root fingerprint is checked against the web UI, which the same server serves, so the check is not out of band. Fix: the admin's CLI signer computes and prints the v1 fingerprint locally, and the enrolling operator receives it out of band. v1 is immutable per org: the server refuses and alerts on a second genesis. Add a threat row.
3. [High] D5.1. The plan drops the ADR 0003 3.2 floor of 2 and has no TUF-style double signing. Fix:
   - The threshold never drops below the floor reached, and never below 2 once 2 admins exist.
   - Each version needs the threshold of both the previous admin set and its own.
   - Refuse a duplicate `(iss, sub)` and the same public key under two user_ids.
   - Tests: threshold downgrade, removing admins down to 1, duplicate identity.
4. [High] D2.3 / D2.5. `loosened_fields(base, new)` uses a base the server supplies. The server can name an older, looser bundle as the base and serve it again as "tightening-only". The first bundle has no defined base. Fix:
   - The connector computes loosening against its own enforced policy: its last valid bundle, or for the first bundle the local approved policy at enrollment.
   - Refuse `base_sequence` != the current sequence.
   - The T9 property test covers sequences of bundles.
5. [High] D2.1 / D2.5. `meet` and `loosened_fields` cover only the folder policy. Fix:
   - Define meet and loosened for every bundle section: `governance_policy`, `mcp_policy`, `dual.allow_requester`, `approval.local_fallback`, registry expiry and `prod`. A change with no ordering counts as loosening, and prod to non-prod is a loosening.
   - `prod` is read only from a human-approved signed field.
   - One test per section.
6. [High] D2.5 / D2.7 / D7.4. No rule for leaving managed mode. Deleting the pinned state by hand falls back to standalone and the looser policy. Fix:
   - Managed mode is sticky: missing or corrupt state keeps the last valid bundle or fails closed.
   - Un-enroll only through a signed control-plane decision, or a two-reviewer local loosening, audited.
   - Add a threat row and a demo check.
7. [High] D6.3 / D6.4 (`approval.py:125-133`). A local approval plus a remote approval can meet dual control. Fix:
   - In managed mode, `approve()` refuses managed requests unless the signed policy sets `approval.local_fallback`.
   - `apply_external` drops every approval that is not a registry-verified `agg/remote-approval/v1`.
   - Test that a local and remote mix is refused.
8. [High] D6.4. "Requester = the creator of the enrollment code" excludes the admin, not the developer whose agent raised the request, so the device operator can approve their own escalation. Fix: enrollment binds the device to a named operator user_id (a code issued to a user, or an OIDC login at `sandbox enroll`). That operator is the excluded requester. Demo step 5 checks that the operator is refused.
9. [Medium] D5.1 / demo step 2. With one admin, one person decides which keys are bob and carol. Fix: an approver key counts toward dual control only if the registry version that added it had at least 2 admin signatures. Otherwise label it `single_admin_registry` and state the limit. The demo uses 2 admins.
10. [Medium] D5.6 / D6.3 / D4.1. Remote-approval verification rules are missing. Fix:
    - Require the `approver` role, and verify against the latest pinned registry.
    - Refuse device and bundle-signer keys for every human kind.
    - Add `org_id` and `registry_version` to the fixed field set.
    - Bind to the `policy_sequence` recorded at escalation.
    - Test that one user_id with two keys counts once.
11. [Medium] D3.3 / D3.4 / threat 18. The head compare trusts the head the server reports. Fix:
    - `upload_seq` goes up by exactly +1 per device.
    - `audit verify --project` checks every checkpoint against the recomputed chain and flags gaps.
    - State as a limit: a compromised server deleting the tail is not detected until SEC-15.
12. [Medium] D3.1-3.3. Checkpoints are per session, so deleting a never-uploaded session leaves no trace. Fix: add a device-level commitment (the session set or count in a device-signed checkpoint), or state it as a limit with a test.
13. [Medium] D1.6 / D9.2 / T5. Fix:
    - List every SECURITY DEFINER function: token hash to org, enrollment-code consume, nonce insert. Each one gets a security review.
    - FORCE RLS, with no exemptions, on every new table.
    - Make nonces unique per `(device_id, nonce)`.
    - Consume the code with an atomic `UPDATE ... WHERE used_at IS NULL RETURNING`, tested concurrently on 4 workers.
    - The enroll request carries a device-key proof of possession.
14. [Medium] Threats / gate item 5 / demo. Fix:
    - Add threat rows for findings 1-8, plus bundle and registry replay across projects and orgs.
    - Fix the node ids before the T0a freeze.
    - Demo step 4 adds a one-approval loosening against an old base, and a project-B bundle.
    - Demo step 5 adds bob with a second key, and the operator approving their own request.
15. [Low] D4.3 / D8. Refuse a remote approval when the measured clock skew is above 2 min. Today it only warns.

**Q1 ruling:** browser `kind=software` keys are allowed in M2 only for remote approvals and denies on non-prod projects.
- The connector refuses them for prod, reading the human-signed `prod` field.
- Registry and loosening signatures come from the CLI signer only.
- Evidence shows `kind`.
- ADR 0003 2.3 is amended, and M2 non-prod dual control is labelled as not meeting it.
- Reason: passkeys would not close the server-JS signing oracle either. The local root signer is the fix that matters.

**Q3 ruling:** defer the OS keystore. The device key stays in the key home under the non-removable deny.
- Tests deny every tool on `device/`, including rootless Grep/Glob, env-var paths and 8.3 short names.
- Amend ADR 0001 Q3 and ADR 0003 2.4.
- Reason: DPAPI and Keychain do not stop code that runs as the same user (ADR 0007 limit 1).

## qa-engineer (claude-opus-4-6, worker tier): APPROVE WITH CONDITIONS

1. [High] Gate item 1. Add per-environment "0 skipped except <named list>", as in M1.
2. [High] Gate item 1 / PG boundary. State that every `tests/security/test_m2_t*` file is Postgres-free and that the `sync_server` fixture lives only in `ee/tests/conftest.py`. The connector CI job has no Postgres.
3. [High] T3. Add the SEC-33 / `root_exposure` domain group split to the tests-first item (named file) and to the exit check.
4. [Medium] D6.6. Add the pinned-preset test (`requires_dual: true`) to the T0a exit check.
5. [Medium] T3. Name the test files for the CSRF and Caddy cases.
6. [Medium] Demo step 5 PASS condition. It must check:
   - (a) the marker is absent after the first approval;
   - (b) the marker exists after the second distinct approval;
   - (c) each intermediate refusal (bob again, alice as requester) returned the expected error.
7. [Medium] T12. Add a case where a device key signs a remote approval and the server refuses it.
8. [Low] T0a exit check. Add "dual-control demo preset frozen with `requires_dual: true` and its test committed".
9. [Low] Gate item 6. Define "pool error": timeout, `PoolTimeout`, or `app.org_id` leaking across connections.
10. [Low] T10. Test that the backoff grows and caps at 5 min (injected clock).
11. [Low] Cut order. State the fallback for demo step 5 if T13 is cut: two terminals running `sandbox approve` as different reviewers, recorded as such.

## security-engineer re-review of the 309-line revision: APPROVE WITH CONDITIONS

N1 (High) and S13 must be closed in the plan text before founder approval. N2-N6 must land in the plan or the T0b ADRs before T5.

S1-S12, S14 and S15 are closed. S13 is open: `agg/signer-assert/v1` needs a pre-auth CLI-key lookup by key_id (registry keys plus pending `signer_links`) and signer nonce and token storage. Neither is listed in D10.6 or D9.2.

- N1 [High] D5.2. `signer link` goes through the server, so a compromised server can link its own CLI key to bob's `(iss, sub)`. Fix:
  - `signer link` prints the key_id locally.
  - `sign-registry` shows every added `cli` key_id and needs a typed confirmation of it, obtained out of band.
  - Add a threat row, and a test where a substituted key is not confirmed.
- N2 [Medium] D1.8 route 2. One person can pin two local ids (ADR 0007 limit 2). Fix: drop the local two-reviewer un-enroll, and deliver `agg/unenroll/v1` offline as a file (`signer unenroll --out`, `sandbox unenroll --decision FILE`).
- N3 [Medium] D1.7 / D2.3. If the local approved policy is missing at re-enroll, the base for the first bundle is deny-all, so the bundle needs 2 CLI approvals. Add a test.
- N4 [Medium] Demo 4-5. Add an explicit two-approval bundle that sets `payments-staging` to non-prod before step 5. Check that a remote approval is refused before that bundle lands.
- N5 [Medium] D2.6. Apply the meet per section (folder, governance, mcp, approval, environment) at enforcement time. Test a hand-edit loosening of each section.
- N6 [Medium] Limit 4 / D1.7. Say in limit 4 that the human operator can also delete the state. Add a server `device_silent` alert after a missed checkpoint window, tested with the injected clock.
- N7 [Low] D1.7. Locked reads still pass the non-removable protections and the default read denies.
- N8 [Low] D5.3 / D5.4. The verifier computes `added_with_sigs`, never reads it from the entry. Add a forged-field test.
- N9 [Low] D5.1. Mark the `cli` remote-approval row "non-prod only in M2", and test that a CLI-key approval on prod is refused. Prod escalations stay pending unless the signed bundle sets `approval.local_fallback`.

**Ruling A** (no remote approvals on prod in M2): accept, on condition N9.
**Ruling B** (`locked` until re-enroll): accept, on conditions N3 and N7.

## qa-engineer re-check of the 309-line revision: APPROVE

QA findings 1-11 are all closed. The steps added for the security findings all have named tests-first files, measurable exit checks and an objective PASS/FAIL for each demo step. No new findings.

## security-engineer final check of the 342-line revision: APPROVE WITH CONDITIONS

S13 and N1-N9 are closed. Nothing below blocks founder approval. The two Mediums go into the ADR 0001 text at T0b, before T5, and land as T8 tests. The Lows go into the T0b and T16 text.

- F1 [Medium] D1.8 / threat 34. Fix the `agg/unenroll/v1` field set in code as `{org_id, project_id, device_id, registry_version, nonce, issued_at, not_after}`, verified against the admin threshold of the latest pinned registry. A re-enroll always produces a new device_id. Test that an old file replayed after re-enroll is refused.
- F2 [Medium] D1.7. `sandbox sync` never re-pins the root. Only `sandbox enroll --expect-fingerprint` writes a pinned root. Until then, bundles and remote approvals are refused. Test that sync does not re-pin after the pinned registry is deleted.
- F3 [Low] Demo step 4. Name a third person as proposer (for example bob, through the API), so that the approvals from alice and carol are valid.
- F4 [Low] Demo step 8. After re-enroll from `locked`, check that the workspace stays locked until a bundle with two CLI approvals arrives.
- F5 [Low] D10.6. A token from a pending, unconfirmed `signer_links` key may only complete the link. Add an IDOR test.
