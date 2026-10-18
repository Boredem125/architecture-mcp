# ADR 0005: Docker Compose packaging for the self-hosted control plane

Status: Accepted (18 Oct 2026) for M1, with the amendments at the bottom. Owner for implementation: devops-engineer (M1 T11).

## Next action

Devops-engineer: confirm Caddy vs nginx (Decision 2) and the secrets-as-files convention (Decision 3).

## Context

1. Today's `docker-compose.yml` runs `nats`, `redis`, `opa`, `sandbox-api` and `executor`.
   - NATS and OPA are unused by the connector (the connector never imports `sandbox.transport` or `sandbox.policy.opa_client`).
   - Redis is only used by the optional legacy HITL API (`hitl.redis_api` in `src/sandbox/api/app.py`).
   - The executor image runs `python -m sandbox.agents.executor`, which has no `__main__` (`docker/Dockerfile.executor`), so it is likely broken.
2. Tokens are passed as environment variables (`SANDBOX_AGENT_TOKEN`, `SANDBOX_APPROVER_TOKEN`).
3. The buyer is a security or platform team running it in their own network. They want a small, auditable stack, pinned images and a boring upgrade.
4. Enterprise bar: TLS, HA-capable API (several replicas), upgrade path, backups.

## Options

1. **Docker Compose first, Helm chart later.** Fastest path for a design partner; one host; HA by running API replicas behind the proxy against an external Postgres.
2. **Helm chart first.** What larger customers run, but slow to iterate on for a solo founder.
3. **Single all-in-one container (supervisord).** Easiest demo, worst operations story (no independent upgrade, no replicas).

## Decision

Option 1. Helm is a later milestone (M6) once the compose stack is stable.

### 1. Services (`ee/deploy/compose.yml`)
| Service | Image | Notes |
|---|---|---|
| `proxy` | Caddy 2 (pinned digest) | TLS termination, serves the built web inbox, routes `/api` to `api`. Only service with published ports (443, optionally 80 for redirect). |
| `api` | `agg-control-plane` | Stateless FastAPI, `uvicorn --workers N`; scale with `deploy.replicas`. Read-only root FS, non-root user, `no-new-privileges`, healthcheck on `/ready` (checks DB + schema version). |
| `migrate` | same image, `alembic upgrade head` | One-shot. `api` uses `depends_on: condition: service_completed_successfully`. |
| `postgres` | `postgres:16` (pinned) | Optional: customers can point `DATABASE_URL` at their managed Postgres instead. Volume `pg-data`. Not published to the host. |
| `worker` | same image, `agg_cp.worker` | Outbox delivery (SIEM/webhooks), registry and bundle builds. Uses `SKIP LOCKED` (ADR 0002), so it can scale too. |

Removed: `nats`, `opa`, `redis`, `executor`. Networks: `edge` (proxy only) and `internal` (api, worker, postgres; `internal: true`).

### 2. TLS
1. Default: Caddy with customer-provided cert and key files (most enterprise networks have an internal CA).
2. Option: Caddy automatic ACME when the host is internet-reachable.
3. HSTS on; HTTP only redirects.

### 3. Secrets
1. Docker secrets mounted as files; the app reads `*_FILE` variables (`DATABASE_PASSWORD_FILE`, `OIDC_CLIENT_SECRET_FILE`, `SERVER_SIGNING_KEY_FILE`, `LICENSE_FILE`). No secrets in `compose.yml` or in images.
2. `.env` holds non-secret settings only (hostname, OIDC issuer URL, replica count). The repo ships `.env.example`, never `.env`.
3. `sandbox-cp init-secrets` (helper) generates the server signing key and DB password into `./secrets/` with `0600` permissions and prints the next step.
4. Gitleaks and Trivy already run on every push; the deploy directory is in scope.

### 4. Upgrade path
1. Images are tagged by version and pinned by digest in the shipped compose file. No `latest`.
2. Upgrade = `pg_dump` backup (documented, scripted) then `docker compose pull`, `docker compose run --rm migrate`, `docker compose up -d`.
3. Migrations are expand/contract (ADR 0002), so the old API keeps working during the rolling restart.
4. Downgrade = restore the backup. We state this plainly; we do not promise down-migrations.
5. Each release ships its SBOM and a Trivy report; image signing (cosign) in M6.

### 5. Local dev and the existing root `docker-compose.yml`
1. M0 deletes the legacy services from the root `docker-compose.yml` (NATS, OPA, Redis, executor) and the executor Dockerfile. What remains runs the single-folder `sandbox serve` API only, or the file is removed if nothing uses it (decided in the M0 plan).
2. The new stack lives in `ee/deploy/` from M1.

## Consequences

1. Fewer moving parts: 4 to 5 services, one of them optional.
2. Customers who mandate Kubernetes wait for M6.
3. Python deps `nats-py`, `redis`, `fakeredis` can be dropped from `pyproject.toml` once the legacy code is gone (M0).

## Security properties affected

1. **Attack surface:** smaller (no unauthenticated NATS 4222/8222, Redis 6379 or OPA 8181 published on the host, which today's compose does).
2. **Secret handling:** env-var tokens become mounted files.
3. **Network isolation:** Postgres and API not reachable from outside the internal network.

## Open questions

1. Devops: do we keep a root `docker-compose.yml` for the OSS `sandbox serve` at all, or document `pip install` only?
2. Founder: is "Compose now, Helm in M6" acceptable for the first enterprise design partner?

## M1 amendments (18 Oct 2026)

1. **Caddy** is the proxy. It also serves the static `ee/web` bundle under a strict CSP with no inline script (SEC-04 groundwork).
2. **`worker` is deferred to M2,** because M1 has nothing to deliver. M1 services are `proxy`, `api`, `migrate` and `postgres`, plus a `demo` profile with Keycloak (pinned) and two demo orgs.
3. **The setup code is printed by `migrate`** as one JSON line. It therefore appears in `docker logs`; the docs say so, and the code is dead after use or after 30 minutes.
4. The root `docker-compose.yml` from M0 stays for the single-folder `sandbox serve`. The control-plane stack lives in `ee/deploy/`.
