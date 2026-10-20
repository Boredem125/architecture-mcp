# T9: orgs, projects, role bindings, `/me`, RBAC, audit verify (design, orchestrator ruling 20 Oct 2026)

Implements the M1_PLAN T9 row and D5.5 (RBAC) on top of T7 tables and T8 part 2 sessions. New module `agg_cp.api` (routes) and `agg_cp.rbac` (dependency); CLI `agg-cp`. Injected `Clock`, no module-level mutable state, every DB access as `agg_app` with `app.org_id` set transaction-locally.

## CSRF token (changes T8 part 2, ruled 20 Oct)
`csrf_token = base64url_nopad(HMAC-SHA256(key=session_token, msg=b"agg-csrf-v1"))`; `web_sessions.csrf_hash = sha256_hex(csrf_token)`. The server can recompute it from the session cookie, so `GET /me` returns it; the login callback no longer puts it in a 302 body. Knowing the CSRF token does not reveal the session token.

## Schema (revision `0004`, expand-only)
Unique index on `role_bindings (org_id, user_id, scope_type, scope_id, role)` so grants are idempotent (`INSERT ... ON CONFLICT DO NOTHING`). `scope_type` in (`org`, `project`) and `role` in (`admin`, `policy_author`, `approver`, `auditor`, `viewer`) as CHECK constraints; `projects.environment` in (`dev`, `staging`, `prod`). For an org-scope binding, `scope_id = org_id`.

## Roles
`admin` (org scope) can do everything in the org. `admin` (project scope) manages that project's members. `viewer`, `policy_author`, `approver` (project or org scope) can read the project and its members. `auditor` (org scope) can run audit verify. No binding = nothing. DB roles never authorize anything (SEC-15).

## Routes (all under `/api/v1`, all need a session; all non-GET need CSRF)
| Method and path | Requires | Notes |
|---|---|---|
| `GET /me` | session | `{user_id, display_name, org: {id, slug, name}, roles: [{role, scope_type, scope_id}], csrf_token}` |
| `GET /projects` | session | only projects the caller can read |
| `POST /projects` | org `admin` | `{name, environment}` -> 201; audit `project_created` |
| `GET /projects/{id}` | read on project | |
| `GET /projects/{id}/members` | read on project | `[{user_id, display_name, role}]` |
| `POST /projects/{id}/members` | org `admin` or project `admin` | `{user_id, role}`; idempotent; audit `role_granted` |
| `DELETE /projects/{id}/members/{user_id}/{role}` | org `admin` or project `admin` | audit `role_revoked`; 204 |
| `GET /org/users` | org `admin` | |
| `POST /org/users` | org `admin` | `{oidc_subject, email}`; issuer = the org's configured issuer; audit `user_added` |
| `POST /org/members` | org `admin` | `{user_id, role}` org-scope grant; audit `role_granted` |
| `GET /org/audit/verify` | org `auditor` or `admin` | `{ok, reason}` from `audit.verify_chain` |

Rules: an object in another org, or one the caller cannot read, is **404** (never 403, so ids are not an oracle); a caller who can read but not write gets 403. Bodies are validated (unknown fields refused, `role`/`environment` enums, uuids). The last org `admin` cannot be revoked (409).

## RBAC declaration
Every route under `/api` is registered through one helper that records its requirement on the route (`route.openapi_extra["x-agg-rbac"] = {"role": ..., "scope": ...}` or an equivalent attribute). A test walks `app.routes`: every `/api` route except `/api/v1/auth/{login,callback,setup}` declares one, and the walked `(method, path)` set equals the frozen list in the test.

## CLI
`agg-cp audit verify --org <slug>` (console script in `ee/pyproject.toml`): reads `AGG_DATABASE_URL[_FILE]`, resolves the org via `org_login_config`, runs `verify_chain`, prints one JSON line `{"org": ..., "ok": ..., "reason": ...}`, exit 0 if ok else 1.
