# ADR 0002: Postgres data model for the control plane

Status: Accepted (18 Oct 2026) for M1, with the amendments at the bottom. Reviewed by security (SEC-07, `REVIEW_SECURITY.md`; S8-S9, `REVIEW_M1.md`) and QA; the founder approved M1, which builds it. Amended for M2 (21 Oct 2026, M2 T0b): see "M2 amendments".

## Next action

Backend-engineer (M2 T5): build the M2 tables and the `SECURITY DEFINER` functions listed in "M2 amendments", tests first. Security-engineer reviews each function.

## Context

1. No database today. State is files under `.sandbox/` plus in-memory dicts in the API (`src/sandbox/api/app.py` singletons, `_hook_sessions` in `routes/hook.py`, the in-memory stores behind `routes/policies.py` and `routes/security.py`). These differ per worker, so `--workers 4` gives four different views.
2. No tenancy: one server, one token pair (`src/sandbox/api/auth.py`), any `?root=` path (`src/sandbox/api/routes/connector.py`).
3. The target bar is enterprise: multi-tenant orgs, SSO, RBAC, HA-capable (more than one API replica), upgrade path, SIEM export.
4. The connector's on-disk formats already define most record shapes: escalation records (`connector/queue.py`), done-records with signatures (`connector/signing.py`), chained audit records (`connector/audit.py`), policy versions and change requests (`connector/policy_versions.py`), evidence packs (`connector/evidence.py`). The database should store these shapes, not invent new ones.

## Options

### Tenancy
1. **Shared schema, `org_id` on every row, Postgres Row-Level Security (RLS) as a second wall.** One migration path, works with one database. RLS catches a missing `WHERE org_id =` in app code. Cost: every connection must `SET app.org_id`; tests must cover it.
2. **Schema per org.** Strong isolation; migrations run N times; painful at 100+ orgs.
3. **Database per org.** Strongest; heavy for self-hosted (most customers are one org).

### Migration tool
1. **Alembic + SQLAlchemy 2.0 (async, psycopg 3).** Standard for FastAPI/Python, reviewable migration files, offline SQL generation for change-managed customers.
2. Raw SQL files + a small runner. Fewer deps; we re-build what Alembic does.
3. Django ORM/migrations. Wrong framework.

## Decision

Tenancy option 1 (shared schema + RLS). Alembic + SQLAlchemy 2.0 async with psycopg 3. Postgres 16.

### Tables (first cut; all have `id uuid`, `org_id`, `created_at`)

| Group | Table | Key columns / rules |
|---|---|---|
| Tenancy | `orgs` | name, `root_key_fingerprint` (ADR 0003) |
| | `projects` | org_id, name, `environment` (dev/staging/prod) |
| People | `users` | org_id, `oidc_issuer`, `oidc_subject` (unique pair), email, status |
| | `role_bindings` | user_id, scope (org or project_id), role: `admin`, `policy_author`, `approver`, `auditor`, `viewer` |
| | `approver_keys` | user_id, public_key, alg, `kind` (webauthn / software), `registry_version`, `enrolled_at`, `revoked_at`, enrollment signatures |
| | `key_registry_versions` | org_id, version (monotonic), signed registry blob, signatures |
| Devices | `connectors` | project_id, device_public_key, hostname, agent kinds, `last_seen`, `revoked_at` |
| | `enrollment_codes` | project_id, code hash (never the code), expires_at, used_at |
| Policy | `policy_versions` | project_id, kind (folder / governance / mcp), sha256, canonical content, `sequence` |
| | `policy_change_requests` | project_id, base_sha, new_sha, loosened_fields, proposer, status |
| | `policy_change_approvals` | change_request_id, user_id, key_id, signature, signed_at |
| | `policy_bundles` | project_id, sequence (unique per project), bundle blob, server signature |
| Decisions | `escalations` | project_id, connector_id, `request_id` (unique per connector), record jsonb (scrubbed), risk, requires_dual, status |
| | `approvals` | escalation_id, user_id, key_id, decision, signed payload, signature, `nonce` (unique), not_after |
| Audit | `audit_records` | connector_id, session_id, `chain_length`, `previous_hash`, `record_hash`, body jsonb. Unique `(connector_id, session_id, chain_length)` |
| | `audit_heads` | connector_id, session_id, chain_length, head_hash, device signature |
| | `audit_quarantine` | fork/continuity failures, never merged |
| Evidence | `evidence_packs` | project_id or org-wide, time range, manifest sha256, signer key, blob location |
| MCP | `mcp_servers`, `mcp_tool_definitions` | see ADR 0006 |
| Ops | `outbox_events` | for SIEM/webhook export, at-least-once delivery |
| | `admin_audit` | every control-plane admin action (role change, key revoke, device revoke), hash-chained per org |

### Append-only audit
1. The app's DB role gets `INSERT, SELECT` only on `audit_records`, `audit_heads`, `admin_audit`. No `UPDATE`/`DELETE`.
2. A trigger rejects UPDATE/DELETE even for the owner role, except via a separate retention role (retention needs a documented, audited procedure).
3. The server re-checks the chain link on insert (ADR 0001, section 5). The database is a store, not a trust root: offline verification of the original chain still works.

### Multi-worker / HA safety
1. **No in-memory state in the API.** Every request reads Postgres. This fixes the `--workers 4` problem by construction.
2. Claiming an escalation for a decision: `SELECT ... FOR UPDATE` on the escalation row, inside one transaction with the approval insert. Unique `approvals(escalation_id, user_id)` stops double approval by one person.
3. Idempotency: unique keys on `(connector_id, request_id)` and `(connector_id, session_id, chain_length)`; uploads use `INSERT ... ON CONFLICT DO NOTHING` then compare hashes.
4. Background work (outbox to SIEM, bundle builds) uses `SELECT ... FOR UPDATE SKIP LOCKED`, so N replicas are safe without a separate queue. No Redis, no NATS.
5. HA = several stateless API replicas + one Postgres with the customer's own HA (streaming replica / managed Postgres). We do not ship Postgres clustering.

### Upgrade path
1. Alembic migrations run as a one-shot job before the API starts (ADR 0005). The API refuses to start if the schema is behind.
2. Only expand/contract migrations (add column, backfill, switch, drop in a later release), so a rolling upgrade with mixed versions works.
3. Every release ships `alembic upgrade --sql` output so DBAs can review.

## Consequences

1. New deps for the control plane only: SQLAlchemy, Alembic, psycopg. The OSS connector does not import them (ADR 0004).
2. RLS needs a tested middleware that sets `app.org_id` per request; a test must prove a query without it returns nothing.
3. Escalation bodies are stored scrubbed. Raw command output stays on the device unless policy says to upload it.
4. Evidence pack blobs: start in Postgres (`bytea`, packs are small); move to object storage later behind the same table.

## Security properties affected

1. **Tenant isolation:** new property. Two walls (app filter + RLS).
2. **Audit integrity:** central store is append-only by DB permissions and trigger, and chain-checked on insert.
3. **Secrets at rest:** enrollment codes stored as hashes; no private keys in the database (ADR 0003); bearer tokens are short-lived and not stored.
4. **PII:** escalation records can hold commands with personal data. Scrubbing before upload plus a per-project retention setting.

## Open questions

1. Founder: is a single Postgres (customer-run HA) acceptable for the first enterprise design partner, or do they need active-active?
2. Security: should the retention role exist at all in v1, or is audit deletion out of scope until a customer asks?
3. QA: we need a Postgres in CI for these tests (service container). Confirm that is acceptable for CI time.

## M1 amendments (18 Oct 2026)

1. **Tables land with their first user.** M1 migrates `orgs`, `org_oidc_config`, `projects`, `users`, `role_bindings`, `web_sessions`, `setup_codes` and `admin_audit`. The rest arrive in M2/M3 as expand-only migrations, each with its own RLS and IDOR tests.
2. **SEC-07, RLS hardening.**
   - Roles: `agg_owner` owns the tables and runs `migrate`. `agg_app` is not the owner and has no `BYPASSRLS`. `agg_worker` is reserved.
   - Every tenant table has `ENABLE` and `FORCE ROW LEVEL SECURITY`.
   - The org is set with `set_config('app.org_id', ..., true)` inside each request transaction.
   - Policies read `NULLIF(current_setting('app.org_id', true), '')::uuid`, so an unset org gives 0 rows.
3. **Pre-auth org lookup.** One `SECURITY DEFINER` function returns only `(org_id, issuer, client_id)` by slug. It is created with `SET search_path = pg_catalog, pg_temp` and `REVOKE EXECUTE FROM PUBLIC`, `EXECUTE` is granted to `agg_app` only, and its owner is not a superuser.
4. **`admin_audit` is append-only.** Row triggers reject UPDATE and DELETE, a `BEFORE TRUNCATE` trigger rejects truncation, and `TRUNCATE` is revoked. Stated limit: `agg_owner` can still drop the table. The external anchor is SEC-15 (M3). No retention role in v1.
5. **Tests use Postgres 16 only, never SQLite** (CI service container, testcontainers locally). Open question 3 is answered: yes.
6. **`admin_audit` chain is computed by the database** (orchestrator ruling, 20 Oct 2026, M1 T7). A `BEFORE INSERT` row trigger takes `pg_advisory_xact_lock` on the row's org, reads the org's last row, and sets `chain_length` (last + 1, first row 1), `previous_hash` (last `record_hash`, or 64 zeros for the first row), `created_at` (`now()`) and `record_hash`, overwriting anything the client sent. `record_hash` = lowercase hex SHA-256 of the UTF-8 text of `jsonb_build_object(...)::text` over every column except `record_hash` (so `previous_hash` and `chain_length` are bound), with uuids as text and timestamps as `to_char(ts AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')`. One SQL function, `admin_audit_canonical(admin_audit)`, holds this expression; the trigger and `agg-cp audit verify` both use it, and the verifier recomputes SHA-256 in Python. Unique `(org_id, chain_length)` and `(org_id, previous_hash)` make a fork fail. Why: the app role cannot choose hashes or fork the chain, concurrent writers serialise per org, and the text form does not depend on the session time zone. Limit: verification needs the database to rebuild the canonical text; an offline verifier for exported heads comes with SEC-15 (M3).

## M2 amendments (21 Oct 2026, M2 T0b)

Source: `docs/control-plane/M2_PLAN.md` D9.2 and D10.5-10.6; security S13 and F5 in `REVIEW_M2.md`. The protocol rules are in ADR 0001's M2 amendments (A1-A6). T5 may refine column names; the rules below are fixed.

### 1. New tables

| Table | Key columns / rules |
|---|---|
| `device_nonces` | org_id, device_id, nonce, iat. Unique `(device_id, nonce)`. Covers `agg/device-assert/v1` (the enroll proof is single use through the code). Kept at least as long as the 2 min `iat` window. |
| `device_tokens` | org_id, project_id, connector_id, `token_hash` (SHA-256 of an opaque 256-bit token; never the token), expires_at (10 min). Revocation is read from `connectors.revoked_at` on every call. |
| `signer_nonces` | org_id, key_id, nonce, iat. Unique `(key_id, nonce)`. Covers `agg/signer-assert/v1`. |
| `signer_tokens` | org_id, user_id, key_id, `token_hash`, expires_at (10 min), `scope`. **`scope = link` for a token issued to a pending, unconfirmed `signer_links` key: it may only complete that link (F5).** `scope = signer` only for a key in the latest registry. |
| `signer_links` | org_id, user_id, `code_hash` (never the code), expires_at (15 min), used_at, public_key, key_id, status (`pending` until a registry version signed by the admins includes the key). The link code is single use and shown only in that user's fresh web session. |
| `sync_alerts` | org_id, project_id, connector_id (nullable), kind (for example `fork`, `truncation`, `session_missing`, `upload_seq`, `second_genesis`, `device_silent`, and alerts the connector uploads), detail jsonb, created_at. `agg_app` gets `INSERT, SELECT` only (lead choice, T0b). |

Every new table has `ENABLE` and `FORCE ROW LEVEL SECURITY`, with no exemptions, and the same `app.org_id` policy as M1 amendment 2.

### 2. First-cut tables that land in M2, and what changes

These arrive with their first user (M1 amendment 1), each as an expand-only migration with RLS and IDOR tests.

1. `connectors`: adds `operator_user_id`, the named operator bound at enrollment (ADR 0001 A1.1). A re-enroll creates a new row and a new `device_id`; a `device_id` is never reused (F1).
2. `enrollment_codes`: adds `operator_user_id`. Consumed only through the atomic function in section 3.
3. `key_registry_versions`: unique `(org_id, version)`. **Genesis is immutable per org:** a second v1 is refused and raises `second_genesis`. `orgs.root_key_fingerprint` is set once at genesis. It is never shown to an enrolling operator as the check value (ADR 0001 A1.3).
4. `approver_keys`: `kind` takes `cli` or `browser` in M2 (was `webauthn` / `software`). `webauthn` comes back with passkeys in M3.
5. `policy_bundles`, `policy_change_requests`, `policy_change_approvals`: change approvals are over the bundle hash and record the proposer, who may not approve (ADR 0001 A2.3).
6. `escalations`: adds `policy_sequence`, recorded at upload. `approvals`: adds `registry_version` and `kind`; `nonce` unique; unique `(escalation_id, user_id)` as before.
7. `audit_records`, `audit_heads`, `audit_quarantine`: append-only, with row triggers against UPDATE and DELETE, a `BEFORE TRUNCATE` trigger and `TRUNCATE` revoked, as on `admin_audit`. `audit_heads` stores each device checkpoint: connector_id, `upload_seq` (unique per connector), the session list, signature.

### 3. `SECURITY DEFINER` functions (S13; complete list)

These run before `app.org_id` is known, so RLS alone would return 0 rows. Each one returns only the columns listed. Each is created with `SET search_path = pg_catalog, pg_temp`, `REVOKE EXECUTE FROM PUBLIC` and `EXECUTE` granted to `agg_app` only, and is owned by a role that is not a superuser. Each gets its own security review at T5. No other function may be `SECURITY DEFINER` without amending this list.

| # | Function (purpose) | Input | Returns |
|---|---|---|---|
| 0 | Pre-auth org lookup (M1, `org_login_config`) | slug | `(org_id, issuer, client_id)` |
| 1 | Device lookup | `device_id` | `(org_id, project_id, connector_id, public_key, revoked_at)` |
| 2 | Device token lookup | token hash | `(org_id, project_id, connector_id)` for an unexpired token of a connector that is not revoked |
| 3 | Atomic enrollment-code consume | code hash | `(org_id, project_id, operator_user_id)`, by one `UPDATE ... WHERE used_at IS NULL RETURNING`; nothing if used or expired |
| 4 | Signer-link consume | link code hash | `(org_id, user_id)`, single use, the same atomic pattern |
| 5 | Pre-auth CLI-key lookup, for `agg/signer-assert/v1` | `key_id` | `(org_id, user_id, public_key, status)` over registry keys plus pending `signer_links`; `status` tells the token issuer which `scope` to grant (F5) |
| 6 | Signer token lookup | token hash | `(org_id, user_id, key_id, scope)` for an unexpired token |
| 7 | Nonce insert (one function per nonce table) | `(device_id, nonce, iat)` or `(key_id, nonce, iat)` | inserted or refused; unique per `(device_id, nonce)` and per `(key_id, nonce)` |

Tokens (device and signer) are opaque, 10 min, and stored only as SHA-256 hashes.

Row 7 is one function per nonce table, so the list is nine functions in rows 0-7. Each function reads other orgs' rows only through a policy `TO agg_owner` on the tables it touches, limited to the command it needs (`SELECT`, `UPDATE` for a consume, `INSERT` for a nonce), as M1 does for `org_login_config`. `agg_app` never gets such a policy. Function bodies use schema-qualified names. The T5 RLS catalog test lists these owner policies by name and fails on any other.

### 4. Connection pool (D10.5)

1. `agg_cp/db.py` sets `pool_size`, `max_overflow`, `pool_pre_ping` and `pool_recycle` from settings. T3 records the defaults here when it lands them.
2. `app.org_id` stays transaction-local (`set_config(..., true)`, M1 amendment 2), so a pooled connection never carries an org into the next request. The M2 load gate checks this with a per-request probe (gate item 6).

### 5. Security properties affected (M2)

1. **Tenant isolation:** unchanged design; every new table is under FORCE RLS. The pre-auth surface is the functions in section 3, rows 0-7, and nothing else.
2. **Secrets at rest:** enrollment codes, link codes and tokens are stored only as hashes. No private key is stored in the database. The bundle-signer key is a secret file (ADR 0005), not a row.
3. **Audit integrity:** the sync audit tables get the same append-only triggers as `admin_audit`. Stated limit unchanged: `agg_owner` can still drop them until SEC-15.
4. Security property 3 above said bearer tokens are "not stored". In M2 they are stored as hashes, so revocation can be checked on every call.
