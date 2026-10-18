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

> History. The legacy routes named in this section and the next (broker, `hook`, `runtime`, `e2b`, `hitl`, `security`, the launcher and its jail) were removed in M0 (Oct 2026). The API now serves only `/health`, `/ready` and `/api/v1/connector/*`; see [docs/CONNECTOR.md](docs/CONNECTOR.md).

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

The CI ZAP scan of the API first reported 288 low/informational alerts,
255 of them as "A Server Error response code was returned". That count was
wrong: ZAP's response-code rule raises both client-error (4xx) and
server-error (5xx) alerts under one plugin id, and the SARIF converter
labelled them all with the first name it saw. With the converter fixed, the
scan showed 215 client errors (expected 4xx, e.g. 404 for made-up ids), **3
real server errors** and 2 error-disclosure alerts on the same routes.

What crashed, and the fix:

- `/api/v1/hitl/*` (found by a local fuzzer): the Redis-backed review API was
  mounted but never configured, so every request raised. Now mounted only
  with `HITL_REDIS_API=true`.
- `POST /api/v1/hook/connect`, `POST /api/v1/runtime/spawn`: capability names
  were plain strings converted inside the route; an unknown one raised.
  Now typed (`list[ActionType]`) with bounded numbers: a 422, not a 500.
- `POST /e2b/v1/sandboxes`: on a host with Docker, the caller-chosen
  `template` was pulled and run, so an unknown image crashed the route and
  any agent-token holder could make the host run an arbitrary image. Now
  restricted to an allowlist (`E2B_TEMPLATES`, default `python:3.12-slim`).
- `POST /api/v1/security/jit/grant`: an enormous `duration_minutes`
  overflowed the expiry date. Now bounded (max 24 h).
- `POST /api/v1/runtime/spawn` raised `NameError` on **every** call (a
  variable named `docker_sandbox` that didn't exist), so the endpoint had
  never worked. Fixed; `agent_type` is validated before anything is created.
- `POST /api/v1/hook/connect` with an unusable `workspace_root` created a
  session anyway and echoed the OS error, with server paths, to the caller.
  Now a 400 before any session exists; install errors go to the server log.

- Connector routes (`?root=`) and `hook/connect`: on Linux a very long path
  raises "file name too long" instead of "not found", so ZAP's 4,000-character
  values crashed them (Windows just answers "not found", which hid it from
  local testing). Any path the OS can't check is now a 400.

Accepted, by design: `hook/connect` returns the generated hook script (Python
source) so it can be installed; ZAP reports that as source code disclosure.

Also: unexpected errors return a fixed body with an error id and log the
traceback server-side ([api/hardening.py](src/sandbox/api/hardening.py)); every
response, 401/403 included, carries `X-Content-Type-Options`,
`Cross-Origin-Resource-Policy`, `X-Frame-Options`, `Referrer-Policy` and
`Cache-Control: no-store`. Regression tests in
`tests/security/test_api_robustness.py` walk every route with malformed
values and with schema-shaped bodies holding junk values (what ZAP sends).
Unix timestamps in responses are intended data and stay.

**Result (scan of `16ccac1`):** 0 server errors, 0 error or source
disclosures. Open: 255 client-error alerts (expected 4xx, e.g. 404 for
made-up ids), 5 "non-storable content" (intended: `no-store`) and 4 Unix
timestamps (intended data). Each fix round let the scanner reach further
(1 → 8 server errors after `runtime/spawn` started working) before it
reached zero.

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

## Upgrade notice: hook hardening (existing users, action required)

The hook launch and PreToolUse failure handling were hardened. Existing installs
are not safe until you do the following:

1. **Install the connector outside the folders it governs.** Code inside a governed
   project can be changed by the agent, so `sandbox init` now refuses an in-project
   install (including an in-project `.venv` or editable install). Either
   `pipx install <path-or-package>`, or an external virtualenv:
   `py -3.12 -m venv E:\tools\agw-venv`, then `E:\tools\agw-venv\Scripts\pip install <path-to-this-repo>`
   (the `sandbox` command is then `E:\tools\agw-venv\Scripts\sandbox`). A repo with
   its own in-project `.venv` cannot govern itself.
2. **Re-run `sandbox init` in each governed folder.** It rewrites the hook command
   (absolute interpreter, `-I`) and adds `"onFailure": "block"` to the PreToolUse hook.
   Hooks need Claude Code 2.1.295 or newer for `onFailure`; `init` warns on older versions.
3. **Check it:** `sandbox doctor <folder>` prints `OK` or `UNSAFE LAYOUT` (exit 1). The
   hook entry in `.claude/settings.local.json` should show an absolute interpreter path,
   `-I`, and `onFailure: block`. Shell commands over 32 KiB are now denied unanalysed.

## Release note: shell analysis (T0f, existing users)

Shell commands are now lexed against a static subset; anything outside it (expansions, globs in command words, `eval`, interpreters given code, encoded PowerShell, code-carrying tools) is never allowed silently: it is denied when a deny fragment is visible and escalated otherwise. Allowlisted git commands accept only known read-only flags; all of `.git/**` is write-protected. Saved `allow_patterns` such as `^ls` no longer match `ls/x.sh` or `cat.sh`: the hook requires whitespace or the end of the command after the match, so those commands escalate. Run `sandbox doctor <folder>` to list saved patterns that lack a `(\s|$)` boundary and fix them. Details and measured numbers: `docs/BYPASS_SUITE.md`.

## Release note: test and script runs escalate (T0g, ADR 0009, existing users)

`python -m pytest`, `pytest`, `npm|pnpm|yarn|bun run|test|ci|install|exec` and similar now escalate in every folder, new or existing, including folders whose `policy.json` still lists the old allow patterns. They run code the agent can write, so a silent allow let it run anything (keys, the approver CLI, deploys) in two calls. Every test run now needs a human until a team opts in with an approved, two-reviewer change to `shell.allow_runners`. `--remember` does not cover runners. `sandbox doctor` lists the now-inert patterns and does not change `policy.json`. See `docs/CONNECTOR.md`.
