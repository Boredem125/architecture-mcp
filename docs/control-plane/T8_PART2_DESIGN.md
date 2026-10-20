# T8 part 2: login, sessions, CSRF, setup code (design, orchestrator ruling 20 Oct 2026)

Implements M1_PLAN D5.4 (cookies, sessions, CSRF) and D5.5 (bootstrap setup code) on top of T7 tables and T8 part 1 (`agg_cp.oidc`). New module `agg_cp.auth` (routes + dependencies) and `agg_cp.migrate`. Time only from the injected `Clock`; no module-level mutable state.

## Schema (new expand-only revision `0003`, never edits `0002`)
- `web_sessions` gains `token_hash text NOT NULL UNIQUE` (SHA-256 hex of the cookie token; the token itself is never stored), `csrf_hash text NOT NULL`, `last_seen_at timestamptz NOT NULL`, `revoked_at timestamptz NULL`. `expires_at` is the absolute end (created + 12 h).
- `setup_codes` gains `used_at timestamptz NULL`, `failed_attempts int NOT NULL DEFAULT 0`.
- New `login_transactions (id uuid PK, org_id uuid NOT NULL, state_hash text NOT NULL, nonce text NOT NULL, pkce_verifier text NOT NULL, bootstrap bool NOT NULL DEFAULT false, created_at, expires_at)`: ENABLE + FORCE RLS, same org policy as `0002`, owner `agg_owner`, `agg_app` SELECT/INSERT/DELETE. Full `downgrade()`.

## Cookies
- Login transaction: `agg_login`, value `<org_id>.<txn_id>`, `Secure; HttpOnly; SameSite=Lax; Path=/api/v1/auth; Max-Age=600`.
- Session: `__Host-agg_session`, value `<org_id>.<token>` (token = `secrets.token_urlsafe(32)`), `Secure; HttpOnly; SameSite=Strict; Path=/`. Never `SameSite=None`. The org id in a cookie only selects the RLS org; a forged org id finds no row.

## Routes (`/api/v1/auth`)
1. `GET /login?org=<slug>`: `org_login_config(slug)` (unknown slug: 404, same body as any unknown). Fetch discovery (`fetch_discovery`, https + address guard). New transaction: state, nonce, PKCE verifier (S256), 10 min expiry; 302 to the IdP `authorization_endpoint` with `response_type=code`, `scope=openid email profile`, `state`, `nonce`, `code_challenge`, `code_challenge_method=S256`, exact `redirect_uri` (`AGG_PUBLIC_URL` + `/api/v1/auth/callback`).
2. `GET /callback?code&state`: needs `agg_login`; load the transaction in its org and **delete it in the same DB transaction** (single use); refuse if missing, expired, or `state` hash differs (constant-time). Exchange code at `token_endpoint` (client secret from `AGG_OIDC_SECRETS_DIR/<slug>` if present, else public client + PKCE), verify the id_token with `IdTokenVerifier` (nonce from the transaction). Look up `users` by `(iss, sub)` only. Unknown user: refused (403 `not_provisioned`) unless the transaction is `bootstrap` (below). On success: new session row (fresh token, so the id rotates at every login), clear `agg_login`, set the session cookie, `admin_audit` `login`. 302 to `/`.
3. `POST /setup` (JSON `{org, code}`): find the org's live code (unused, unexpired); compare `sha256(code)` with `hmac.compare_digest`; on mismatch increment `failed_attempts`; at 5 failures the code is dead. On match start a `bootstrap` login transaction (like `/login`) and return `{redirect: <authorization URL>}`; the code is marked used only when the bootstrap callback succeeds, and only if the org still has no `admin` binding (else 409). The bootstrap callback creates the user (`status='active'`, email from the token, informational only) and an org-scope `admin` role binding, and writes `admin_audit` `bootstrap_admin`.
4. `POST /logout`: needs a session and CSRF; sets `revoked_at`, clears the cookie, `admin_audit` `logout`. 204.

## Session dependency (`require_session`)
Parse the cookie, set `app.org_id` (transaction-local), load by `token_hash`; refuse if missing, revoked, `now >= expires_at` (12 h absolute) or `now - last_seen_at >= 30 min` (idle); else update `last_seen_at`. Returns `(org_id, user_id, session_id)`. 401 with a non-secret reason.

## CSRF (`require_csrf`)
Every state-changing route (POST/PUT/PATCH/DELETE) except `/setup` and the IdP callback (a GET) needs header `X-CSRF-Token` whose SHA-256 equals the session's `csrf_hash` (constant-time). The token is issued at login and returned by `GET /api/v1/me` (T9). `/setup` is unauthenticated and protected by the code itself, `SameSite` and a JSON content type check (refuse non-`application/json`).

## Setup code (`python -m agg_cp.migrate`)
`alembic upgrade head`, then, if `AGG_BOOTSTRAP_ORG_SLUG` (+ `_NAME`, `_ISSUER`, `_CLIENT_ID`) is set and that org has no `admin` binding and no live code: create org + `org_oidc_config` if missing and a new code (`secrets.token_urlsafe(24)`, 192 bits), store `sha256` only, 30 min expiry, print exactly one JSON line `{"event":"setup_code","org":"<slug>","code":"<code>","expires_at":"<iso>"}` to stdout. Otherwise print nothing about codes. The plaintext code appears only in that line (and so in `docker logs`; documented).

## Rate limit
`/setup` failures are counted per code in the DB (survive restarts and multiple workers). A per-IP limiter is out of scope for M1 (stated limit; the proxy can add one).

## Stated limits
DNS rebinding between the URL check and the connect is the transport's job (`HttpJWKSProvider` doc); login CSRF on `/login` is mitigated by state + nonce bound to the `agg_login` cookie; no JIT provisioning in M1 (users are added by an admin in T9).
