# ADR 0002: Postgres data model for the control plane

Status: Accepted (18 Oct 2026) for M1, with the amendments at the bottom. Reviewed by security (SEC-07, `REVIEW_SECURITY.md`; S8-S9, `REVIEW_M1.md`) and QA; the founder approved M1, which builds it.

## Next action

Backend-engineer: check the table list against ADR 0001 messages; flag anything the sync protocol needs that is missing.

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
