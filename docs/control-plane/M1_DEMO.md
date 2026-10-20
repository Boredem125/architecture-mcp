# M1 Demo -- design partner walkthrough

> Template: fill the "Result" lines on the Docker machine where the demo runs.

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

**Result (fill on the Docker machine):**

```
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

**Result (fill on the Docker machine):**

```
```

---

## Step 3: bob RBAC + eve org isolation

**What it does:**

- **bob** (Acme, approver): logs in via the normal `/login` flow, sees
  `payments`, gets 403 on a role change (not admin).
- **eve** (Globex): either the org is not bootstrapped (404 on `/login`),
  or she logs in and sees no Acme projects, gets 404 on Acme project ids.

**Result (fill on the Docker machine):**

```
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

**Result (fill on the Docker machine):**

```
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

**Result (fill on the Docker machine):**

```
```

---

## Summary

| Step | Description | Result |
|------|-------------|--------|
| 1 | /ready 200 | |
| 2 | Setup + admin + project + member | |
| 3 | bob RBAC + eve isolation | |
| 4 | Connector: --root 403, key-home, forged approval | |
| 5 | Persistence + audit verify | |
