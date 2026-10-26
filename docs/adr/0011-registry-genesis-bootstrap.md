# ADR 0011: Registry genesis bootstrap and the first signed versions

Status: proposed (lead-architect, 25 Oct 2026). It needs a security leader ruling (identity and keys) and a QA review before any code; PM review is needed on two scope questions. It amends ADR 0003 1.4 (bootstrap) and 5 (genesis). It keeps threat 22 (`M2_PLAN.md`: a second genesis, or a fingerprint shown by the server) unchanged.

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
