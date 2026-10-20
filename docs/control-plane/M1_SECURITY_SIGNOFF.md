# M1 Security Sign-off (T13 Hostile Review)

**Reviewer:** security-engineer (claude-opus-4-6)
**Date:** 2026-10-20
**Scope:** `git diff 8f52679..b40272a` (M0 gate to HEAD on branch `work`)
**Focus areas:** `ee/src/agg_cp/**`, `ee/deploy/**`, `ee/web/**`, `src/sandbox/connector/**` (Phase A)

## Method

Hostile code review of the full M1 diff acting as an attacker. RLS
and audit-chain exploits run against native Postgres 16 at
`AGG_TEST_PG_URL`. Static analysis of auth, RBAC, OIDC, signing,
shell lexer, key home, compose, and CSP. Path-traversal,
TOCTOU, IDOR, CSRF, and privilege-escalation patterns checked
by reading every route and every migration.

## Findings

| ID | Sev | File:line | Attack | Status |
|----|-----|-----------|--------|--------|
| F1 | Medium | `ee/src/agg_cp/auth.py:399` | OIDC secret path traversal: `os.path.join(oidc_secrets_dir, slug)` with no traversal guard; a malicious slug like `../../x` reads an arbitrary file as client_secret. Slug comes from DB (operator-set, no user route), container read-only, but no defence in depth. | Fixed (wrap-up PR, orchestrator): `is_valid_slug` + `org_secret_path` (realpath must stay in the secrets dir), tests in `ee/tests/test_m1_t13_review.py`; not re-reviewed by T13 |
| F2 | Low | `ee/src/agg_cp/migrations/versions/0002_m1_tables.py` (orgs DDL) | No CHECK constraint on `orgs.slug` format; traversal chars (`/`, `..`) are not rejected by the schema. Supports F1. | Fixed (wrap-up PR, orchestrator): CHECK `orgs_slug_format` in revision `0006`, pg test with positive control; not re-reviewed by T13 |
| F3 | Low | `ee/deploy/compose.yml:307-308` | Keycloak admin credentials `admin/admin` in plaintext in git. Demo-profile only, internal network only, but could be copied to production. | Open: stated demo limit (demo profile only) |

## Verified clean

- **RLS (9 tables):** ENABLE+FORCE confirmed on all 9 tables via `pg_class` catalog. `agg_app` has no BYPASSRLS. Empty/unset `app.org_id` yields 0 rows (NULLIF guard). Pooled-connection leakage test: `app.org_id` correctly cleared after commit (transaction-local `true`).
- **admin_audit append-only:** UPDATE, DELETE, TRUNCATE all denied for `agg_app`. Trigger overrides caller-supplied `chain_length`/`previous_hash`/`record_hash` on INSERT. Chain verified in Python after concurrent inserts.
- **SECURITY DEFINER org_login_config:** `search_path = pg_catalog, pg_temp`, schema-qualified refs, EXECUTE revoked from PUBLIC, owned by non-superuser `agg_owner`.
- **OIDC (SEC-13):** alg allowlist checked before key use with kty match; iss exact match (Entra tid GUID-only); aud/azp; constant-time nonce compare; SSRF guard on discovery and JWKS (private/loopback/link-local/reserved blocked); https-only; no redirect following; `jwk`/`jku`/`x5u` header params ignored.
- **Sessions:** `__Host-` prefix, Secure, HttpOnly, SameSite=Strict; SHA-256 stored; idle 30 min + absolute 12 h; server-side revocation; CSRF derived via HMAC (not leaked by knowing CSRF).
- **CSRF:** checked on every state-changing route (POST/DELETE); all GET routes are read-only.
- **RBAC/IDOR:** every `/api/v1` route declares `x-agg-rbac`; cross-org requests get 404 (RLS); cross-project gets 404 (RBAC check). Last-admin protection under advisory lock.
- **Login transaction:** atomic DELETE...RETURNING; PKCE S256; state hash constant-time compare; bootstrap under advisory lock; setup code: SHA-256, constant-time, rate-limited (5 tries), single use, 30 min.
- **Signing (SEC-24):** `verify_record` uses code-defined field sets per `sig_v`, not record-claimed `signed_fields`. Domain tags separate signing contexts. Legacy records verified against historical field sets only.
- **Key home:** fail closed (no fallback to `.sandbox/`); overlap with workspace refused; seeds 0600; shell/Grep/Glob deny covers env vars, `~`, 8.3, symlinks.
- **Compose hardening:** all images pinned by digest, non-root, read-only FS, no-new-privileges, cap_drop ALL, secrets as files, Postgres on internal-only network, no published DB ports.
- **CSP:** `default-src 'self'; script-src 'self'; style-src 'self'` with `frame-ancestors 'none'`, `base-uri 'none'`, `object-src 'none'`. check-csp.mjs validates the dist bundle. No inline script in HTML.
- **OpenAPI/docs:** disabled (`openapi_url=None, docs_url=None, redoc_url=None`).
- **No secrets in git:** `ee/deploy/secrets/.gitignore` covers `*`; no seed/token/password in tracked files; demo realm uses `${AGG_DEMO_OIDC_CLIENT_SECRET}` placeholder.
- **Connector (Phase A):** shell lexer unresolvable forms never `allow`; money floor escalates even when allowlisted; `onFailure: block` in PreToolUse hook; pins on first use from human surfaces only; domain-tagged signatures.
- **Injected clock:** no `time.time()` or `datetime.now()` in `agg_cp` request paths (migrate.py bootstrap uses `datetime.now(tz=utc)` which is acceptable for a one-shot init script).

## Not verified (requires Docker or external tools)

- Trivy scan of the `api` Docker image (no Docker in this environment).
- ZAP baseline scan against the Caddy proxy.
- Live Keycloak demo flow (login, callback, IdP interaction).
- Semgrep registry rules (proxy blocks `semgrep.dev`).
- Gitleaks scan (binary not available; manual grep found no secrets).
- Keycloak network reachability from proxy in demo profile (keycloak is on `internal`, proxy is on `edge`+`idp`; appears unreachable but needs Docker to confirm).

## Stated limits

This review covers the code diff only. It does not constitute a penetration test or a compliance certification. The connector signing key home stops the hook-governed agent, not arbitrary code running as the same OS user (ADR 0007 stated limit). The admin_audit chain can be dropped by `agg_owner` (external anchor is SEC-15, M3).

## Verdict

**APPROVE WITH CONDITIONS.** F1 (Medium) should be fixed before any deployment that allows operator-defined org slugs through a UI or API (add `os.path.commonpath` or a slug-format CHECK); acceptable for M1 demo where slugs come from env vars. F2 and F3 are low-severity hygiene items that do not block the milestone.
