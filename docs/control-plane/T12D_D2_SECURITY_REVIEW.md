# T12d d2 security review -- registry genesis server side

Reviewer: security-engineer (leader tier, Opus 4.6).
Scope: uncommitted d2 diff at main c51d0f0.
Verdict: **CHANGES REQUIRED** (R1 is HIGH).
Scanners: Semgrep clean, gitleaks clean.

## Findings

**R1 HIGH -- bundle_signer not checked against server config.**
`ee/src/agg_cp/sync/signer.py` genesis step 4 (~line 562).
ADR 0011 2.4: "bundle_signer equal to the server's configured bundle-signer public key (refused if none configured)."
Code does structural validation only (format, 32 bytes, kid = sha256(pub)).
The happy-path test passes a random key and succeeds, confirming no server-side match.
Impact: an admin genesis installs an attacker-chosen bundle signer, undermining evidence integrity.
Fix: look up the server's configured bundle-signer public key; compare; refuse if absent.

**R2 MEDIUM -- expires_at upper bound not enforced.**
Same file, genesis step 4 (~line 597). ADR says 7 d / 72 h with prod.
Code only checks `> now()`. May be in verify_chain; if not, enforce the ceiling.

**R3 LOW -- exception messages returned verbatim.**
Genesis 500 handler and store_registry_version 400 handler return `str(exc)`.
Fix: generic messages; log detail server-side.

**R4 INFO -- code lookup by SQL hash match, not constant-time.**
Differs from auth.py's hmac.compare_digest. Not exploitable (SHA-256, 5-attempt cap).

## Test-edit sign-offs (builder edits to d1 QA tests)

- `test_pending_link_refused_on_pending_route`: **APPROVED.** Asserts 403 on /pending plus non-403 on /genesis; stronger than the xfail gate.
- `test_pending_link_allowed_on_signatures_for_own_key`: **APPROVED.** `in (200, 400)` proves scope gate did not fire and rejects 500. Acceptable for a scope-rule test.
- `test_pending_link_refused_on_signatures_for_other_key`: **APPROVED.** Direct 403 assertion.
- `test_migrate_no_genesis_code_after_v1`: **APPROVED.** Inserts a v1 row, asserts no code on second run; stronger than the xfail gate.

## Other review items confirmed

- Genesis: admin-only, org-scoped, code single-use, 60 min expiry, 5-attempt lockout, 409 + second_genesis alert with code untouched, pg_advisory_xact_lock serialises concurrent calls (exactly one v1), no fingerprint in response, admin_audit row written, all 22 envelope refusals enforced server-side, user_id from server identity.
- Pending-link scope: explicit allowlist (link, genesis, signatures), fails closed for unknown/empty/revoked. Own-key check compares token key_id, not a payload field.
- migrate.py: genesis code emitted only when no version and no live genesis code; printed to stdout JSON only; purpose column semantics correct; migration 0014 downgrade safe.
- auth.py: adds purpose filter so admin-bootstrap code lookup does not match genesis codes.

## Re-review (28 Oct 2026)

**R1 FIXED.** signer.py:1088-1106. `_load_bundle_signer_key()` loaded; None -> 400 `bundle_signer_not_configured` (fail closed). Hex public key compared with `!=` (exact equality, not key_id only). Public keys are not secret so constant-time is not required. Tests: `bundle_signer_wrong_key` (parametrized) and `test_genesis_no_bundle_signer_configured_refused` (renames key file). Fixture `bundle_signer_info` is module-scoped, depended on by `genesis_server`, so env var is set before the subprocess; teardown restores. Happy path uses `_SERVER_BUNDLE_SIGNER_PUB` (the server's actual key).

**R2 FIXED.** signer.py:1125-1140. 72 h when `projects.environment = 'prod'` exists for the org, else 7 d. Strict `>` so exactly-at-ceiling passes. Test `expires_at_exceeds_ceiling` uses 7 d + 2 h. Prod detection by `projects.environment` column matches the ADR wording.

**R3 FIXED.** signer.py:1196-1206 returns `envelope_rejected`; 1211-1222 returns `internal_error`. Both log detail server-side via `logging.warning`/`.exception`. Test `test_genesis_verify_chain_error_returns_generic_body` sabotages envelope kind and asserts generic body.

**R4** unchanged (INFO, accepted).

Test-edit sign-offs from round 1 still hold. New test additions (3 tests) are additive, not edits to QA tests.

**Final verdict: APPROVE.**
