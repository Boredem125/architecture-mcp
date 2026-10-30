# ADR 0011: Registry genesis bootstrap and the first signed versions

Status: proposed (lead-architect, 25 Oct 2026). Amendment A1 (identity binding for v2 and later, R2-4) decided 30 Oct 2026 by founder ruling 13; see the end of this file. It needs a security leader ruling (identity and keys) and a QA review before any code; PM review is needed on two scope questions. It amends ADR 0003 1.4 (bootstrap) and 5 (genesis). It keeps threat 22 (`M2_PLAN.md`: a second genesis, or a fingerprint shown by the server) unchanged.

## Context

Security round 2 on T12b-2 found that a real deployment has no path to its first registry:
- The first admin's CLI key exists only as a `signer_links` row.
- Its token has scope `pending_link`, and `/api/v1/sync/signer/signatures` refuses that scope.
- Nothing writes `approver_keys` except `store_registry_version`, after `verify_chain`.
- The T12b e2e test calls `store_registry_version` directly.

This fails closed, but T16 demo step 2 cannot run on a real stack.

Reading the code turned up more gaps on the same path (lead-architect, 25 Oct). Steps 2b and 2c (v2 and v3, each signed by two admins) need all of them closed:
1. **CLI commands.** The CLI has `sandbox signer approve` and `deny` only. `link`, `genesis` and `sign-registry` exist as library code (`connector/sync/signer.py`) but are not wired into the CLI.
2. **Signature collection.** `/signatures` accepts only a complete envelope, and `signer_pending` returns `[]`. A version that needs two admins has nowhere to collect its second signature.
3. **Key listing.** No route lists the keys waiting to join the registry (pending CLI links and browser keys). So the CLI cannot build v2 or v3 from server-reported `(iss, sub)` and public keys.
4. **`build_genesis` fields.** It writes `user_id = sub` (the IdP subject), not the server's user id. Server-side operator exclusion and connector dedup both key on the registry user_id, so the two would disagree. It also hard-codes the roles `admin` and `approver`.

## Options

- **A. The first admin's linked key may publish v1 while no registry exists.** Simple, but any org admin who links a key can race to publish the root first. That includes a second web admin added before genesis.
- **B. A separate one-time genesis code from the migrations job, plus A's checks.** It reuses the M1 setup-code pattern (ADR 0003 1.4) and table. Only the person holding the install output can publish the root, and only together with an admin web session and a linked CLI key.
- **C. Genesis offline only, with the root loaded by the DB owner or a CLI on the host.** No network route. But it needs host database access in the bootstrap, and it does not fit the compose demo.

**Decision: B.**

## Decision

1. **The genesis code.**
   - **Issued by migrations.** The migrations job already prints the admin setup code. It also prints a genesis code for an org that has no registry version and no live genesis code. The output is one JSON line: `{"event":"genesis_code","org":...,"code":...,"expires_at":...}`.
   - **Storage.** The code is a `setup_codes` row with a new column `purpose` (`admin_bootstrap` | `registry_genesis`; existing rows default to `admin_bootstrap`). It has 192 bits, is stored as sha256, expires after 60 minutes, allows at most 5 failed attempts and is used once. The comparison is constant time.
   - **Re-minting.** Re-running the migrations job mints a new code only while the org has no registry version. That needs host access.
   - **Never shown elsewhere.** The code is never logged anywhere else, never shown in the web UI and never returned by any route.
   - **Holder.** Whoever runs the install (host access to the migrations output). They give it out of band to the first admin, who is often the same person.
2. **The route.** `POST /api/v1/sync/signer/genesis`, with body `{genesis_code, envelope}`.
   - **Scope.** `check_signer_token_scope` lets a `pending_link` token reach `link` and `genesis` only.
   - **Transaction.** Everything runs in one transaction under `pg_advisory_xact_lock(hashtext('agg-genesis:' || org_id))`, in this order. Any failure rolls back everything except the failed-attempt count and the alert.
     1. If any `key_registry_versions` row exists for the org, return 409 `genesis_exists` and commit a `second_genesis` alert (threat 22). The code is not checked.
     2. Find the live `registry_genesis` code with FOR UPDATE and check its expiry. Compare in constant time; on a mismatch, increment the failure count, commit, and return 400 `invalid_code`.
     3. The token's user must hold the org `admin` role binding. The token's key must be that user's pending link, with its public key set.
     4. Check the envelope exactly:
        - `version` 1; `org_id` equal to the token's org; `prev_hash` `""`; `threshold` 1;
        - `admins == [token key_id]`;
        - exactly one key: the token's `key_id` and linked `public_key`, `kind` `cli`, `alg` `ed25519`, `user_id` equal to the server user id of the token's user, `iss` and `sub` equal to that user's OIDC identity, `roles` containing `admin` and only `admin` or `approver`, `added_in` 1;
        - `bundle_signer` equal to the server's configured bundle-signer public key (refused if none is configured);
        - `expires_at` within the expiry rule (7 days, or 72 h with any prod project);
        - exactly one signature, made by the token's key.
     5. Call `store_registry_version`, which runs `verify_chain` and projects `approver_keys` (ADR 0010 s8), so the key's status becomes `signer`. In the same transaction: mark the code used, mark the link consumed, and write an `admin_audit` row `registry_genesis` with user_id, key_id and payload sha256.
     6. Respond with `{version: 1}` only.
   - **The fingerprint (S2).** No route returns or displays the root fingerprint. It comes only from the CLI.
3. **Roles.** The genesis key always gets `admin`. It gets `approver` only with `sandbox signer genesis --approver`. The default is admin only (least privilege), and the demo passes `--approver`. Keys added later carry their roles in their signed registry entries. The projection copies the roles, and the approvals route needs `approver` (ADR 0010 s8).
4. **Identity fields.** `build_genesis` and `sign-registry` take `user_id`, `iss` and `sub` from the server's report for that link. The CLI shows them and the admin confirms them. The registry user_id is the server's user id, never the IdP subject.
5. **Versions after genesis (needed for demo step 2).**
   - **Candidates.** `GET /api/v1/sync/signer/candidates` takes a confirmed token whose key has the `admin` role. It lists the org's pending CLI links and pending browser keys: key_id, public key, user_id, iss, sub and kind. It is org-scoped; other orgs get 404.
   - **Building and signing.** `sandbox signer sign-registry` builds the next version from the latest stored version plus the chosen candidates. It shows the diff, computed from the bytes, and needs a typed confirmation of each added `cli` key_id (N1, existing `confirm_key_ids`). Then it signs. With `--out FILE`, it writes a partial envelope.
   - **The second signer.** `--in FILE` checks that the partial envelope chains from the latest server version and that every signature on it is valid. It shows the same byte diff, adds its own signature, and then writes `--out` or publishes with `--publish`.
   - **Publishing.** `--publish` posts the complete envelope to `/signatures`. `verify_chain` is the real gate. Who posts only authenticates the org, so a `pending_link` token may post a complete registry envelope only if that envelope adds the token's own key (the onboarding case, for example carol co-signing v2). Every other `pending_link` post is 403.
   - **Later.** A server inbox for pending registry versions comes in M3.
6. **Headless demo (`ee/deploy/demo.py`).**
   - `_get_setup_code` also parses `genesis_code`.
   - alice: web session, `POST /api/v1/signer-links`, `sandbox signer link --code` in alice's key home, then `sandbox signer genesis --genesis-code <c> --approver --confirm-identity <iss> <sub> --yes`. The CLI prints the fingerprint, and the demo keeps it for `sandbox enroll --expect-fingerprint` in step 3.
   - carol links her key. alice runs `sign-registry --add <carol kid> --admin --confirm-key-id <kid> --out v2.json`, and carol runs `sign-registry --in v2.json --confirm-key-id <kid> --publish`. v3 works the same way, adding the bob and carol browser keys enrolled by the Python browser signer.
   - **Non-interactive flags.** Every confirmation has a flag that names the exact value, so a script can never skip a key_id check blindly.
   - **Step 2 checks added.** A second genesis gets 409 plus an alert. Reusing the genesis code is refused. A `pending_link` post that does not add its own key gets 403.
   - **The T12b e2e test** stops calling `store_registry_version` and uses these routes. A grep test enforces this.

## Named limits (exact wording)

- **G-L1.** A compromised server, or anyone with the database owner role at install time, can mint a genesis code or publish its own root. The only defence is the root fingerprint that the CLI prints and the operator passes to `sandbox enroll --expect-fingerprint` out of band (S2, unchanged). The genesis code protects against other people while the server is healthy, not against the server.
- **G-L2.** Until the genesis code is used or expires (60 minutes), it is a bearer secret in the migrations job output. Anyone who can read the host's container logs could use it, but only together with an org-admin web session and a linked CLI key.
- **G-L3.** In M2, two admins collect their signatures on a registry version by passing a file between them. The server holds no pending versions until M3.

## Consequences

- One migration adds `setup_codes.purpose`. It takes the next free migration number; T12c's migration is numbered after whichever lands first.
- New server routes: `genesis` and `candidates`. The `pending_link` scope rule changes in `ee/src/agg_cp/sync/signer.py`.
- New CLI commands: `sandbox signer link`, `genesis` and `sign-registry`. `build_genesis` changes its `user_id` and `roles`.
- `demo.py` step 2 runs on the real stack through routes only. The T12b e2e test moves to the routes.
- This blocks T16. It is tracked as task T12d in `T12B_PLAN.md`.

## Amendment A1 (30 Oct 2026): identity binding for registry v2 and later (R2-4)

Decided by the founder on 30 Oct 2026 (in chat): fix R2-4 in M2, as part of T12d d5 (`T12B_PLAN.md`, "Founder rulings (30 Oct 2026)", row 13). R2-4 here is the d4 review's item (`T12D_D4_SECURITY_REVIEW.md`, Round 2), not the d3 review's R2-4.

### Context

- **What the connector already counts.** `verify_chain` counts distinct registry `user_id`s, not key_ids, for thresholds, floors and S9 (D0-2: `_distinct_signer_users`, `_distinct_admin_users`). Approval dedup counts by `user_id`, then by `(iss, sub)` (H1, threat 14), then applies S9.
- **The hole.** A registry entry's `user_id`, `iss` and `sub` are claims written by the admin who signs the version. Nothing ties them to a person. So one admin can add a second admin key that she holds, under an invented `user_id`. She signs the next version with both keys, and every key it adds counts for dual (security probe B; threat 30, "one admin picks the approvers").
- **The server does not stop it.** Section 5 makes `verify_chain` the only gate on `/signatures`. The d4 e2e test stored an `admin2` entry with `user_id` `admin-<kid8>`, which is not a `users` row.
- **The connector alone cannot close it.** With a single-key genesis, it cannot tell a second person from alice's second key.

### Options

- **(a) Server-side identity binding for v2 and later** (security's recommendation). Every added key must come from the named user's own enrollment.
- **(b) A transitive S9 on the connector.** A signer counts only if its own key was added by two admins. Rejected: with section 2's single-key genesis, no key could ever count for dual. It would force a two-admin genesis, which this ADR rejected (the option A race).
- **(c) A named limit only.** Rejected by the founder: fix in M2.

**Decision: (a), plus pin tests on the connector's existing distinct-user counting.**

### A1.1 Server identity binding (registry v2 and later)

Where it runs:
- In `/api/v1/sync/signer/signatures`, for `type == "registry"` with version 2 or later.
- In the same transaction as `store_registry_version`, under the org's registry advisory lock, before anything is stored.
- It compares against the latest stored version, vN-1.

1. **Added keys.** A key is added when its key_id is not in vN-1. It must match exactly one pending enrollment in the token's org, with equal `key_id`, `public_key`, `kind` and `user_id`:
   - for `kind` `cli`: a linked, unconsumed `signer_links` row;
   - for `kind` `browser`: a pending browser-key enrollment.

   Link codes and browser enrollments are self-scoped: only the user's own fresh web session can create them (`POST /api/v1/signer-links`). So the match ties the key to that user's OIDC login. An admin cannot enroll a key for someone else.
2. **The user.** `user_id` must be a `users` row of the same org with status active. `iss` and `sub` must equal that row's OIDC issuer and subject. The registry `user_id` is the server's user id, never the IdP subject (section 4).
3. **Admin role.** Some keys gain the admin role in vN: either the key is new and is in `admins` or carries the `admin` role, or it existed in vN-1 without it (a promotion). For each, the user must hold an org-scope `admin` role binding at publish time.
   - An approver-role key needs only rules 1 and 2. The roles in the registry, signed by the admin threshold, decide. M2 adds no new RBAC rule here.
4. **Carried keys.** A key present in both versions keeps its `user_id`, `iss`, `sub`, `public_key` and `kind`. Changing any of them means removing the key and adding it again.
5. **On success,** in the same transaction:
   - mark each matched link or enrollment consumed;
   - write an `admin_audit` row `registry_version` with the version, the payload sha256 and each added `(key_id, user_id, roles)`.
6. **On refusal:**
   - Return 400 `identity_unbound` with one reason class: `unknown_key`, `user_mismatch`, `identity_mismatch`, `other_org`, `not_admin` or `identity_changed`.
   - Store nothing: no version row, no `approver_keys` row, and the link stays unconsumed.
   - Commit an `admin_audit` row `registry_identity_refused`, the same way as the `second_genesis` alert.
7. **One user, several keys.** A user may hold more than one key, for example a rotation, a second machine or alice's approver key next to her admin key. This is safe because every count is by `user_id`, so two keys of one user count once.

### A1.2 Counting: distinct user_ids, on both sides

- **Connector.**
  - `verify_chain` thresholds, floors and S9 count distinct registry `user_id`s (D0-2, already in the code).
  - Approvals dedup by `user_id`, then by `(iss, sub)`, then S9 decides which keys count for dual.
  - d5 changes no connector logic. It adds pin tests so that a later edit cannot slip back to counting keys. Builders do not touch S9 or `verify_chain`.
- **Server.**
  - The server runs the same `verify_chain`.
  - Approvals stay `UNIQUE (escalation_id, user_id)`, with the server-supplied user id (C9) and key owner equal to that user (ADR 0010 s8).
  - Any count the server shows or exports (inbox progress, evidence) counts distinct `users.id`, never key_ids or approval rows.
  - The connector still decides (local enforcement is authoritative).
- **What this buys.** With an honest server, two dual-eligible `user_id`s are two `users` rows. Each has its own OIDC login, and each enrolled its own key.

### A1.3 Genesis and the frozen demo step 2

- **Genesis (v1) is unchanged.** Section 2 step 4 already binds its one key to the token user's pending link, that user's OIDC identity and the org admin role binding. It is the v1 case of A1.1.
  - Its threshold is 1, so the genesis key is added with count 1 and never counts for dual, even with `--approver`. That is S9 as before.
- **v2 adds admin2 only, with threshold 2.** admin2 is carol in `demo.py` and a seeded `admin2` user in the e2e test.
  - admin2's key is her own pending CLI link, and she holds the org admin role binding.
  - alice (the previous admin, 1 user) and admin2 (the current admin) sign it.
  - admin2's v2 key is added with count 1, so it never counts for dual. This is intended.
- **v3 adds bob, carol and alice-approver.** Each key comes from that user's own pending link or browser enrollment.
  - alice and admin2 sign it: 2 distinct previous admin users, so all three keys count for dual.
  - alice-approver shares alice's `user_id`, so alice still counts once in any approval.
- **The step 5 fallback in the M2_PLAN cut order** (CLI approvals): it uses approver keys added in v3, never admin2's v2 key (d4 review, item 5).
- **Changes for d4 and d5.**
  - The e2e and `demo.py` take every v2 and v3 key from a route link (`/signer/link`, in that user's own seeded session) or a browser enrollment. Test-generated keys with invented ids are no longer used.
  - `/candidates` must list pending browser keys. If d4 lands without them, d5 adds them.

### A1.4 What counts as a bypass test

A test counts toward R2-4 only if it meets all four rules:
1. **Real routes.** It drives the attack through the public routes and the CLI. It makes no direct `store_registry_version` call and no raw write to `key_registry_versions`, `approver_keys`, `signer_links` or browser enrollments. Seeding users, role bindings and sessions through the existing fixtures is allowed.
2. **Refusal and no side effects.** It asserts the status and the reason class. It also asserts that nothing changed: no new version row, no `approver_keys` row, the link is still unconsumed, and the refusal audit row is present.
3. **A positive twin.** The same setup with honest bindings is accepted, so a test cannot pass because its setup is broken.
4. **Tests first.** qa writes it from security's test spec, under strict `xfail(raises=...)` until the build lands. The marker is removed when the test passes.

Minimum set (security may add more):

| ID | Attack | Expected |
|---|---|---|
| B1 | Probe B: v2 adds a second admin key that alice holds, under an invented user_id | refused, `unknown_key` |
| B2 | A real user's ids (carol's), with a key that did not come from carol's link | `unknown_key` |
| B3 | carol's linked key relabelled with bob's user_id, or with another `(iss, sub)` | `user_mismatch` or `identity_mismatch` |
| B4 | A user or link from another org | `other_org` (404 if the token's org differs) |
| B5 | An admin key for a user without the org admin binding (bob), and bob's existing approver key promoted to admin | `not_admin` |
| B6 | A carried key with a changed user_id, `(iss, sub)` or public key | `identity_changed` |
| B7 | A consumed link replayed: a removed key is re-added, or the key is re-added under another user | `unknown_key` |
| B8 | alice links two CLI keys of her own and v2 adds the second as admin. With threshold 2: | `verify_chain` refuses (1 distinct user) |
|  | Same, with threshold 1: | accepted; the keys that a v3 signed by both of her keys adds give `counts_for_dual` False (connector test) |
| B9 | Two approvals from two keys of one user_id | count once; the connector stays `awaiting_second` |
| E2E | The frozen step 2 flow through the routes | passes |
| E2E | Probe B through the routes | refused at v2 |

- **Not a bypass test: the connector-only pin.** Probe B fed straight to `verify_chain` still gives `counts_for_dual` True.
- This is G-L5 part 1. It is a plain passing test, not an xfail, named after the limit, so any change in either direction is visible.

### A1.5 Named limits (exact wording)

- **G-L4 (interim; M2 until d5 is committed).**
  - The control plane does not bind registry keys to users.
  - One admin can add a second admin key under an invented user_id and reach dual control alone (R2-4, threat 30).
  - Until d5 lands, dual control proves two registry user_ids, not two people.
  - No demo, pitch or doc may claim "two humans" before then.
  - G-L4 closes when d5 is committed with the A1.4 tests green and security's leader review APPROVE.
- **G-L5 (after d5).**
  1. **The connector relies on the server.** The connector cannot tell two people from one person's two keys, so it relies on the server's binding. A compromised server can mint dual-eligible keys. This sits inside G-L1, and after genesis the root fingerprint does not help.
  2. **Two user_ids are two IdP identities, not proven two humans.** An org admin who can create a second IdP account, add a `users` row for it and grant it admin can still hold both admin seats. The defences are the customer's IdP identity proofing and the audit trail:
     - every admin role grant and every registry version is an `admin_audit` row naming who did it;
     - the evidence pack lists each approver's `(iss, sub)`.

### Consequences of A1

- **d5 grows.** Security (L) writes the test spec, qa (W) writes the tests first, backend (W) builds A1.1, and security (L) reviews, because the change alters what S9 guarantees.
- **Size.** d5 goes from 0.5 to 2 days: R2-4 adds 1 day, and the d4-review items already ruled for d5 add 0.5.
- **No connector logic change.** S9 and `verify_chain` are untouched.
- **No new table is expected.** If one is needed, it takes the next free migration number.
- **The e2e and `demo.py`** link every v2 and v3 key through the routes.
- **Exit checks.** The T12d exit and the M2 security sign-off require the A1.4 tests and G-L4 removed from HANDOFF.
