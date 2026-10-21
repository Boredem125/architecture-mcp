# M1 Demo -- design partner walkthrough

> Measured 21 Oct 2026 on the founder's Windows 11 laptop (Docker Desktop 29.9.1), `main` at `65446a8` plus the T14 demo fix, after `docker compose --profile demo down -v` and a fresh `up --build`. Command: `python ee/deploy/demo.py --ca <Caddy root CA>`. Result: 27 PASS, 0 FAIL, exit 0. Windows needs `127.0.0.1 idp.localhost` in the hosts file and `--ca` (see `ee/deploy/README.md`).

## Command

```bash
cd ee/deploy
python demo.py                  # all 5 steps
python demo.py --step N         # one step
python demo.py --help           # usage
python demo.py --ca /path/to/ca-bundle.crt  # explicit CA bundle
```

## Prerequisites

- Docker Engine 24+ and Docker Compose v2, stack running:
  ```bash
  docker compose --profile init run --rm init-secrets   # first time
  AGG_OIDC_ALLOW_HOSTS=idp.localhost docker compose --profile demo up -d --build
  ```
- Python 3.12+ with `httpx` installed.
- The Caddy root CA must be available (auto-detected from the compose
  `ca-bundle` volume, or passed via `--ca`).

---

## Step 1: /ready check

**What it does:** GETs `https://localhost/ready` through the Caddy proxy
and checks for HTTP 200.

**Result (measured 21 Oct 2026):**

```
PASS: /ready returned 200
```

---

## Step 2: Setup code + admin bootstrap

**What it does:**

1. Reads the setup code from `docker compose logs migrate-demo`.
2. POSTs `/api/v1/auth/setup` with `{org, code}`.
3. Follows the Keycloak authorization redirect.
4. Parses the Keycloak login form (stdlib `html.parser`).
5. Submits alice's demo password (`demo-only-alice-123` from the realm file).
6. Follows the callback, gets `/me` -- confirms alice is admin.
7. Creates project `payments` (prod).
8. Adds bob as an org user, then as approver on the project.

**Result (measured 21 Oct 2026):**

```
PASS: Setup code read from migrate-demo logs (org=acme)
PASS: /auth/setup accepted the setup code and returned redirect URL
PASS: alice logged in via Keycloak (bootstrap admin)
PASS: /me: alice is admin (org=acme)
PASS: Created project 'payments' (id=f47d4267-7cba-44cd-91c2-9e4494795abf)
PASS: Looked up bob's Keycloak sub via admin API (sub=2423516b-08a3-4215-9805-9656f0ef88f0)
PASS: Added bob as org user (id=fe231163-461a-46f7-bd6f-5cd14b64cf2a)
PASS: Added bob as approver on project 'payments'
```

---

## Step 3: bob RBAC + eve org isolation

**What it does:**

- **bob** (Acme, approver): logs in via the normal `/login` flow, sees
  `payments`, gets 403 on a role change (not admin).
- **eve** (Globex): either the org is not bootstrapped (404 on `/login`),
  or she logs in and sees no Acme projects, gets 404 on Acme project ids.

**Result (measured 21 Oct 2026):**

```
PASS: bob logged in via Keycloak
PASS: bob sees project 'payments'
PASS: bob gets 403 on role change (not admin)
PASS: Bootstrapped Globex org
PASS: eve logged in as Globex admin (bootstrap)
PASS: eve (Globex) sees no Acme projects
PASS: eve gets 404 on Acme project id
```

---

## Step 4: Connector checks (no Docker needed)

**What it does (live execution):**

1. Creates a temporary folder and runs `sandbox init` on it.
2. Starts `sandbox serve --root <tmp> --port <free>` as a subprocess with
   per-run agent and approver tokens.
3. HTTP-checks: listed root returns 200, unlisted root returns 403.
4. Pipes a PreToolUse Grep payload (targeting the key home) to
   `python -m sandbox.connector.hook_eval` and asserts it is denied.
5. Generates a fresh Ed25519 key (not enrolled), forges a signed approval,
   and asserts `_is_pinned` returns False and `distinct_approvals` refuses it.

**Run locally (no Docker):**

```bash
python demo.py --step 4
```

**Expected output:**

```
PASS: sandbox init created .sandbox/ in /tmp/sandbox_demo_...
PASS: sandbox serve running on port ...
PASS: listed root -> 200 via connector/status
PASS: unlisted root -> 403 via connector/status
PASS: PreToolUse hook_eval denied Grep for seed bytes (decision=deny, ...)
PASS: forged approval: signature valid but key is not pinned (refused)
PASS: distinct_approvals refuses forged (unpinned) approval
```

**Result (measured 21 Oct 2026):**

```
PASS: sandbox init created .sandbox/ in <temp dir>
PASS: sandbox serve running on port 56388
PASS: listed root -> 200 via connector/status
PASS: unlisted root -> 403 via connector/status
PASS: PreToolUse hook_eval denied Grep for seed bytes (decision=deny, reason starts: SANDBOX DENIED [SANDBOX_PROTECT] (risk 20/100): protected path: key home The .sa)
PASS: forged approval: signature valid but key is not pinned (refused)
PASS: distinct_approvals refuses forged (unpinned) approval
```

---

## Step 5: Persistence + audit verify

**What it does:**

1. `docker compose down` then `docker compose --profile demo up -d`.
2. Waits for `/ready` 200.
3. Runs `agg-cp audit verify --org acme` inside the api container (exit 0).

**Commands:**

```bash
cd ee/deploy
docker compose down
AGG_OIDC_ALLOW_HOSTS=idp.localhost docker compose --profile demo up -d
# wait for /ready
curl -sk https://localhost/ready  # poll until 200
docker compose exec api python -m agg_cp.cli audit verify --org acme
# Expected: {"org":"acme","ok":true,"reason":""}  exit 0
```

**Result (measured 21 Oct 2026):**

```
PASS: docker compose down succeeded
PASS: docker compose --profile demo up -d succeeded
PASS: /ready returned 200 after restart
PASS: agg-cp audit verify --org acme exited 0 (audit chain intact)
```

---

## Summary

| Step | Description | Result |
|------|-------------|--------|
| 1 | /ready 200 | PASS (1/1 checks) |
| 2 | Setup + admin + project + member | PASS (8/8 checks) |
| 3 | bob RBAC + eve isolation | PASS (7/7 checks) |
| 4 | Connector: --root 403, key-home, forged approval | PASS (7/7 checks) |
| 5 | Persistence + audit verify | PASS (4/4 checks) |

Total: 27 PASS, 0 FAIL. A second run on the same database fails at step 2 by design: the setup code is single-use, so a repeat run needs `down -v` first.

## T11 stack checks (same laptop, 21 Oct 2026)

| Check | Result |
|-------|--------|
| Base stack up, migrations, `/ready` | 200 `{"status":"ok"}` after compose fixes in `8b85ede` and `65446a8`: Caddy file capability vs `cap_drop: ALL`, secret ownership per consumer, Keycloak built at image-build time so `read_only` holds. Each fix signed off by security-engineer. |
| Trivy, `api` image (HIGH/CRITICAL) | 44 HIGH, 0 CRITICAL, all in Debian 13.7 base packages with no fixed version (util-linux, ncurses, systemd libs, perl-base). With `--ignore-unfixed`: 0. Python packages: 0. |
| Trivy, filesystem (HIGH/CRITICAL) | 1 CRITICAL: a Stripe `sk_test_` pattern in `demo/__pycache__/call_demo.cpython-312.pyc`, a git-ignored local cache file of the demo script. Tracked files: 0. |
| ZAP baseline on the proxy | 0 High, 0 Medium; 3 Low, 3 Informational (cache-control, storable content, COEP missing, modern web app); 63 rules passed. Run against `https://agg.localhost:8443` on the compose edge network with the proxy temporarily serving that name, because ZAP's Java client sends no SNI for the dotless name `localhost`. |
| Keycloak demo profile | All services healthy; acme issuer `https://idp.localhost/realms/acme` served through Caddy. |

Gate item 4 reads "Trivy 0 HIGH/CRITICAL (fs and `api` image)". As worded it is **not met** (44 unfixed base-image HIGH; 1 CRITICAL in an ignored local file). Founder ruling pending.
