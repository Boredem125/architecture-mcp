# ADR 0004: Open-core split (MIT connector, commercial `ee/` control plane)

Status: Accepted (17 Oct 2026). **Decided:** the founder had no preference, so the team recommendation stands: `ee/` is public in this repo under ELv2.

## Next action

Founder: pick the `ee/` license (Decision 2) and say whether `ee/` source may be public in this repo.

## Context

1. The repo is public and MIT (`LICENSE`). The connector, CLI and local policy engine stay MIT (RESUME.md decision 3).
2. The control plane is the paid product, self-hosted in the customer's infra (STARTUP.md).
3. Today everything is one package, `sandbox`, under `src/sandbox/`. The API server (`src/sandbox/api/`) is part of it and is used by `sandbox serve` (`src/sandbox/cli/main.py`).
4. Rule: never break the OSS connector; it must work standalone (TEAM.md).

## Options

### Where the commercial code lives
1. **Same repo, `ee/` directory, own license (GitLab / PostHog / Cal.com model).** One CI, one PR for protocol changes on both sides, easy for design partners to audit. Source is visible.
2. **Separate private repo.** Source hidden; protocol changes need two PRs and version pinning; harder for security buyers to audit.
3. **Whole repo under BSL / source-available.** Simplest legally, but breaks the MIT promise for the connector. **Rejected.**

### License for `ee/`
1. **Elastic License 2.0 (ELv2):** short, known, forbids offering it as a managed service and circumventing license keys. Not OSI open source.
2. **Custom commercial "EE license" (GitLab-style):** free for dev/test, production needs a subscription. Needs a lawyer.
3. **BSL 1.1 with a change date:** converts to open source after N years. More complex to explain.

## Decision

1. **Same repo, `ee/` directory** (option 1); the source is public (decided).
2. **License: ELv2 for `ee/`** (decided), because it is short and widely understood. A lawyer should read it before the first paid contract.
3. Layout:
   ```
   LICENSE                      MIT (unchanged, covers everything outside ee/)
   src/sandbox/                 MIT: connector, CLI, local engine, sync client (sandbox sync), protocol models
   src/sandbox/protocol/        MIT: sync protocol message schemas + verify functions (shared by both sides)
   ee/LICENSE                   ELv2 (or founder's choice)
   ee/pyproject.toml            separate package: agg-control-plane, depends on the MIT package
   ee/src/agg_cp/               API server, DB models, migrations, OIDC, inbox API, SIEM export
   ee/web/                      web approval inbox (React/Vite)
   ee/deploy/                   compose files (ADR 0005)
   ```
4. **Dependency direction is one-way:** `ee/` imports `sandbox`; `sandbox` never imports `agg_cp`. Enforced by a test that imports every `sandbox` module with `ee/` absent, plus an `import-linter` contract in CI.
5. **The sync client is MIT.** The protocol is documented openly. Anyone could write a compatible server; our value is the product, the identity/key work and the evidence, not a secret wire format.
6. **What is MIT vs `ee/`:**
   - MIT: everything that enforces (hook, classifier, broker, approvals, dual control, audit chain, policy versions, evidence pack builder and verifier, MCP proxy from ADR 0006, `sandbox sync`).
   - `ee/`: everything that is central (multi-tenant server, OIDC, key registry admin, web inbox, org-wide evidence, SIEM export, RBAC, HA).
   - Rule of thumb: **safety stays free**. Nothing that makes a single developer safer moves behind the license.
7. **License key:** a signed JSON file `{customer, org_limit, connector_limit, features, not_after}`, signed with our Ed25519 vendor key, verified offline by the server at start and daily. No phone-home. On expiry: a 30-day grace banner, then new connector and user enrollment stops. **It never stops** policy serving, approvals, audit ingestion or exports. An expired license must not make a customer less safe.
8. The existing `src/sandbox/api/` (legacy dashboard API) is not moved to `ee/`. After M0 it keeps only the local, single-folder connector view used by `sandbox serve` (MIT). The new server starts clean in `ee/` (M1).

## Consequences

1. Two packages to build and version. The connector can ship to PyPI alone.
2. CI must run connector tests with `ee/` removed, to prove standalone still works.
3. Contributors need a CLA or DCO policy for `ee/` (open question).
4. A visible `ee/` means competitors can read it. The moat is cross-vendor independence and evidence trust, not secrecy.

## Security properties affected

1. **Connector TCB:** unchanged; nothing in the enforcement path depends on `ee/` or on a license.
2. **Availability:** license expiry cannot disable enforcement, approvals or audit (stated design rule, test required).

## Open questions

1. ~~Founder: public or private `ee/`?~~ **Decided 17 Oct 2026:** public, in this repo.
2. ~~Founder: ELv2, custom, or BSL?~~ **Decided:** ELv2.
3. Founder: CLA vs DCO for outside contributions to `ee/`?
