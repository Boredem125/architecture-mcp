# Security posture of this project

A tool that governs AI agents is itself a high-value target — the 2025 Claude Code
source-code exposure made enterprises rightly wary of agent-tooling supply chains. This
documents the project's own attack surface, not just the security it provides.

## Design stance

- **Fail closed.** Every hook path exits non-zero and blocks on internal error; a broken
  connector never silently allows.
- **No new network surface.** The connector opens no ports; coordination is the local
  `.sandbox/` folder. The MCP server speaks stdio to its parent agent only.
- **Minimal dependency delta.** One added runtime dependency (`mcp`, pinned `>=1.9.0,<2`);
  everything else was already declared. No `watchdog`, no `filelock`.
- **Stdlib-only hook stubs.** The files written into a user's project
  (`.sandbox/hooks/*.py`) use only the standard library and carry no policy logic —
  the real logic is imported from the installed package.
- **Self-protection is non-removable.** `.sandbox/**` write-deny and `\.sandbox` shell-deny
  are re-injected on every policy load; the control plane cannot be edited via the agent.

## Fixed: unauthenticated HTTP API (1 Oct 2026)

The optional HTTP API (`sandbox serve`) had no authentication and bound
`0.0.0.0` by default. Anyone who could reach it, including a jailed agent,
could submit a command to the privilege broker, approve it with a made-up
reviewer ID, and have it run outside the jail (`shell=True`). Found while
triaging a Semgrep `subprocess-shell-true` note on the broker.

Fix: loopback bind by default; bearer tokens on every route except health
and docs; separate agent and approver tokens, where the agent token can only
reach submit/evaluate routes (see [docs/CONNECTOR.md](docs/CONNECTOR.md)).
Regression tests: `tests/security/test_api_auth.py`. The folder connector
(hooks + MCP over stdio) opens no port and was not affected.

## Fixed: ZAP API-scan findings (1 Oct 2026)

The CI ZAP scan of the API reported 288 low/informational alerts: 255 server
errors, 16 error-disclosure alerts, 10 missing-header alerts and 7
informational ones. Reproduced locally with a fuzzer that walks every
OpenAPI route with malformed path, query and body values: the only crash
site was the Redis-backed review API (`/api/v1/hitl`), mounted but never
configured, so every request to it raised. It is now mounted only with
`HITL_REDIS_API=true` (it needs Redis, and its reviewer authentication is
still a placeholder). Unexpected errors return a fixed body with an error id
and log the traceback server-side ([api/hardening.py](src/sandbox/api/hardening.py)).
Every response, 401/403 included, carries `X-Content-Type-Options`,
`Cross-Origin-Resource-Policy`, `X-Frame-Options`, `Referrer-Policy` and
`Cache-Control: no-store`. Regression test: `tests/security/test_api_robustness.py`.
Unix timestamps in responses are intended data and stay.

## Known trust assumptions

See [docs/TCB.md](docs/TCB.md). In brief: the `.sandbox/` folder is trusted infrastructure,
and for this proof-of-work the approver's signing seed is stored there. Production custody
moves keys to an HSM/smartcard and the control plane out of the workspace.

## Supply chain

- Pinned MCP major version to avoid the 2.x `FastMCP→MCPServer` breaking rename.
- No install-time code execution beyond standard `pip install -e`.
- Tests (183) run offline; no test reaches the network.

## Reporting

This is a personal proof-of-work repository. For a real deployment, security issues would go
through a coordinated-disclosure process with a named owner and SLA.
