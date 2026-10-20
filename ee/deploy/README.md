# Self-hosted control-plane deployment

## Prerequisites

- Docker Engine 24+ and Docker Compose v2
- (Optional) A built web bundle in `ee/web/dist/`

## Quick start

### 1. Generate secrets (first time only)

```bash
docker compose --profile init run --rm init-secrets
```

This creates random credentials and pre-composed database URLs in
`./secrets/` with mode 0600.

### 2. Start the stack

```bash
docker compose up -d
```

Services: `postgres` (internal only), `migrate` (one-shot), `api`, `proxy` (Caddy, ports 443/80 on 127.0.0.1).

### 3. Read the setup code

```bash
docker compose logs migrate
```

Look for the JSON line:

```json
{"event":"setup_code","org":"<slug>","code":"<code>","expires_at":"..."}
```

Use this code on first login to become the org admin.  The code expires after 30 minutes and is single-use.

### 4. Demo profile (Keycloak)

```bash
docker compose --profile demo up -d
```

Adds a Keycloak instance with two demo realms (Acme, Globex) and three users:

| User  | Realm  | Password              |
|-------|--------|-----------------------|
| alice | acme   | `demo-only-alice-123` |
| bob   | acme   | `demo-only-bob-456`   |
| eve   | globex | `demo-only-eve-789`   |

Keycloak admin: `admin` / `admin` (demo only).

## Open items

### (a) `agg_cp.migrate` module not built (T8 part 2)

The `migrate` service runs `python -m agg_cp.migrate`, which is expected
to run `alembic upgrade head` and print the setup code as one JSON line.
This module does not exist yet; it is T8 part 2.

### (b) Keycloak demo HTTPS routing

The API fetches OIDC discovery and JWKS over HTTPS only (SEC-13).  For the
demo the browser must reach Keycloak for the login redirect and the API
needs HTTPS discovery.  The production-sound approach: Keycloak goes behind
Caddy as a second site block with `tls internal`, and the API trusts
Caddy's internal root CA via `SSL_CERT_FILE`.  This is not wired yet
because the OIDC module (T8) must be built first to distinguish the demo
allowlist from a real configuration.

### (c) Keycloak admin password

Keycloak has no `_FILE` convention for `KEYCLOAK_ADMIN_PASSWORD`.  This is
acceptable because: internal network only, demo profile only.

### (d) Unverified in this commit (needs Docker)

- [ ] Stack starts with `docker compose up -d`
- [ ] `/ready` returns HTTP 200
- [ ] Trivy scan: 0 HIGH/CRITICAL
- [ ] ZAP baseline on the proxy: no High findings
- [ ] Demo login flow through Keycloak
- [ ] Postgres runs correctly with `user: "999:999"` and no `cap_add`
