# M0 inventory: legacy code to retire (P1) and MCP governance today (P7)

Author: backend-engineer, 17 Oct 2026, at `main` = `5eae33e`. Planning only: no code was changed.
Method: an AST import graph over every tracked `.py` file (module-level and lazy imports), grep, and reading the files. Line counts come from `wc -l`.

## 0. Baseline test run

| Run | Result |
|---|---|
| `pytest -q -p no:logging` (full suite) | **Aborted** after 108 s. `tests/security/test_api_robustness.py::test_no_route_crashes_on_malformed_input` hit pytest-timeout (30 s), and the faulthandler printed `Windows fatal exception: access violation`. |
| That file alone, `--timeout=300` | Process died with exit `-1073741819` (0xC0000005, native access violation) after 119 s. The test walks every OpenAPI route, legacy ones included. The crash happens while `/e2b/v1/sandboxes` is creating a Windows Job Object (`job_object_created` is the last log line). So this is a crash, not a slow test. |
| Full suite, that one test `--deselect`ed | **539 passed, 1 skipped, 1 deselected, 141.5 s** (skip: `test_environment_classification.py:250`, symlinks not permitted). |
| `--collect-only` | **541 items** (parametrized cases included) in 56 files. RESUME.md's "540 pass + 1 skip" matches 541. |

I also passed `-p no:cacheprovider`, which changes no test counts. CI (`.github/workflows/security.yml`) does not run pytest, so CI never sees this crash.

## 1. Legacy candidates

**Connector dependencies on legacy code are flagged in bold below.** There are three direct edges and three package-`__init__` edges.

| # | Area / paths | LOC | Imported by (non-test) | Routes (`api/app.py`) | Recommendation and risk |
|---|---|---|---|---|---|
| 1 | `src/sandbox/pipeline/` (orchestrator, session_manager) | 818 | `api/app.py:22`, `agents/runtime.py`, `agents/tools.py`, lazily by `routes/hook.py:185`, `routes/e2b.py`, `routes/requests.py` | none of its own | **Delete.** Low risk once the routes in row 9 go. |
| 2 | `src/sandbox/agents/` (9 "agents", runtime, tools, executor). There is no top-level `agents/` directory. | 2,626 | `api/app.py:15` only | `/api/v1/runtime/*` (`routes/agent_runtime.py:34-99`, router at `app.py:164`) | **Delete.** It is the only user of `anthropic`, `openai`, `policy/`, `rollback/`, `anomaly/`. |
| 3 | `src/sandbox/launcher/` (launcher, jail, registry, demo_agent, shims) | 1,070 py + 206 shims | `api/app.py:20-21`; **`connector/recorder.py:18` imports `launcher.recorder`**, and `launcher/__init__.py:1-3` eagerly imports `AppLauncher` → `config`, `executor.isolation`, `jail`. So every connector import loads the launcher today. | `/api/v1/launch*`, `/api/v1/broker/*`, `/api/v1/hitl-mem/*`, `/api/v1/translate` (`routes/launcher.py:96-274`, `app.py:167`) | **Move `launcher/recorder.py` (226) into the connector**, then delete the rest. Medium risk: `connector/recorder.py` and `test_recorder_scan.py` must be repointed in the same commit. |
| 4 | `src/sandbox/executor/` (isolation, subprocess_runner, signature_verifier) | 910 | `agents/executor.py`, `containment/*`, `launcher/launcher.py:23,249` | none | **Delete** with rows 2, 3 and 5. This is the ctypes Job Object code behind the access violation. |
| 5 | `src/sandbox/containment/` (docker_sandbox, process_sandbox) | 729 | `agents/runtime.py`, `agents/tools.py`, `routes/e2b.py:25-26` | none | **Delete.** It is the only user of the `docker` dependency. |
| 6 | `src/sandbox/hitl/` (Redis queue, reviewer, memory orchestrator, api) | 1,141 | `api/app.py:19,152-158`, `routes/hitl.py:1`, `agents/hitl_orchestrator.py` | `/api/v1/hitl/*`, mounted only when `hitl.redis_api` is set (`app.py:152-158`) | **Delete.** It is the only user of `redis`. The connector has its own folder queue. |
| 7 | `src/sandbox/transport/` (NATS), `src/sandbox/policy/` (OPA client), `policies/rego/` (5 files) | 354 + 276 | `transport`: nothing. `policy`: `agents/policy_engine.py` only | none | **Delete.** `nats-py` is used only here. |
| 8 | `src/sandbox/rollback/`, `src/sandbox/anomaly/`, `src/sandbox/translate/` | 859 + 884 + 101 | `agents/*` only; `translate` by `api/app.py:23` | `/api/v1/translate` (row 3) | **Delete.** |
| 9 | Legacy API routes: `agent_runtime` 105, `e2b` 345, `launcher` 278, `hook` 467, `sessions` 82, `requests` 51, `audit` 48, `hitl` 1, `websocket` 76 | 1,453 | `api/app.py:13-14,149-169` | `/e2b/v1/*` (`e2b.py:108-328`), `/api/v1/hook/*` (`hook.py:82-234`, the M1 HTTP hook; it runs every call through the pipeline), `/api/v1/sessions/*`, `/api/v1/requests/`, `/api/v1/audit/sessions/*` (legacy `AuditSink`, not the connector audit), `/ws/events` | **Delete.** Keep `health`, `connector`, `auth`, `hardening`. **Risk:** `AGENT_ROUTES` (`api/auth.py:36-41`) lists only legacy routes (`/broker/request`, `/hook/evaluate`, `/hook/audit`, `/e2b/v1/`). Once they are gone, the agent-token role grants nothing, so decide whether to drop it or keep it for M1 sync. Note also that the agent token today reaches `/e2b/v1/*`, which executes commands. |
| 10 | agents-oauth toy and in-memory admin toys: `routes/agents.py` 99, `policies.py` 56, `security.py` 209, `dashboard.py` 24, `models/security.py` 141 | 529 | `api/app.py:160-163`, `dashboard.py` reads the other routes' dicts | `/api/v1/agents/*` incl. `/oauth2/token` (`agents.py:24-94`), `/api/v1/policies/*`, `/api/v1/security/*` (JIT, RBAC, conditional access, "zero-trust score"), `/api/v1/dashboard/stats` | **Delete.** All state lives in module dicts, and tokens from `/oauth2/token` are never checked by `TokenAuthMiddleware`, so they authorize nothing. The "RBAC/zero-trust" names overclaim, which matters under the honesty rule. |
| 11 | `sandbox_hook.py` (repo root, 86) | 86 | Nothing imports it. It POSTs to `/api/v1/hook/evaluate` and fails closed (`sandbox_hook.py:60-66`). `install.py` and `test_install.py:32-45` only *preserve* it in settings. | none | **Delete** with row 9. Keep `test_install.py`, since it checks that unrelated hooks survive. Update `docs/CONNECTOR.md:297-298`. |
| 12 | `frontend/` (React/Vite) | 2,643 in `src/`, 6,755 tracked | Not Python. Its only API calls are `/dashboard/stats`, `/policies/upload`, `/translate`, `/broker/*`, `/launch/*` and `/ws/events` (`frontend/src/pages/*`, `api/client.ts`). 6 of its 9 pages hold mock data (AgentHub, AuditLog, HITLReview, PolicyCenter, SecurityCenter, Sessions). It never calls `/connector/*`. | n/a | **Delete** (git history keeps it). The M-inbox UI should start fresh against `/connector/*`. Low risk. `security.yml:110` Trivy scans the npm lock, so expect findings to change. |
| 13 | Legacy CLI commands: `inspect-session`, `verify-audit`, `list-sessions` (`cli/main.py:46-104`) | ~60 | They use `api.app.get_session_manager` (an in-memory singleton, so a new process never finds a session) and `audit.sink` | none | **Delete.** Keep `serve`, but its `uvicorn.run("sandbox.api.app:app")` (`main.py:36-43`) stays. |
| 14 | Shared but half-legacy: `audit/sink.py` 315 and `audit/retention.py` 220; `crypto/tokens.py` 120 (JWT); `models/messages.py` 224 and `models/session.py` 114; most of `config.py` (NATS, Redis, OPA, Executor, Containment, Launcher, Translate settings) | ~1,000 | **The connector does not use them directly, but the package `__init__`s pull them in:** `audit/__init__.py:3-5` imports sink and retention (needs `aiofiles`); `crypto/__init__.py:9` imports `tokens` (needs `pyjwt` and `models.session`). `connector/audit.py:15-16` uses `audit.chain` and `models.audit` → `models.enums`, so keep those. | `/api/v1/audit/sessions/*` | **Delete** sink, retention, tokens, messages, session and the dead settings classes, **and edit `audit/__init__.py`, `crypto/__init__.py`, `launcher/__init__.py` in the same commit**, or the connector fails at import time. Medium risk. |
| 15 | Compose and Docker: `docker-compose.yml` `nats` (6-16), `redis` (18-27), `opa` (29-43), `executor` (83-107), env `NATS_URL`/`REDIS_URL`/`OPA_URL` (60-62), `depends_on` (68-71); `docker/Dockerfile.executor` | ~70 | n/a | n/a | **Delete** nats, opa, redis, executor and `Dockerfile.executor`. Keep `sandbox-api` plus `Dockerfile.sandbox` for devops in M-compose. **Executor claim confirmed:** `ENTRYPOINT ["python","-m","sandbox.agents.executor"]` (`Dockerfile.executor:24`), and `agents/executor.py` has no `__main__` or `main()`, so the container imports and exits 0 at once; with `restart: unless-stopped` it loops forever. `Dockerfile.sandbox:25` also runs `--workers 4`, which breaks the in-memory state (known gap). |
| 16 | Stray tracked files: `%SystemDrive%/ProgramData/Microsoft/Windows/Caches/*.db` (4 Windows cache DBs, committed in `69a1603`) | binary | n/a | n/a | **They are still being written.** After my test runs today, `git status` shows 2 tracked DBs deleted and 3 new ones. Something in the suite starts a Windows child process with `SystemDrive` missing from its env (env scrubbing?) and the repo as cwd. Find the spawner (likely a broker, launcher or containment env builder), then `git rm` the files and add a `.gitignore` entry. I left the working tree as it is. |

**Keep (connector core and its real deps):** `connector/`, `cli/` (minus row 13), `broker/privilege_broker.py` (**used by `connector/broker.py:12`**), `audit/chain.py`, `models/audit.py` and `models/enums.py`, `crypto/signing.py`, `fs/containment.py` (`connector/classify.py:36`), `safety/` (its `__init__` also loads injection_detector, secret_scanner and output_scrubber, which `benchmarks/injection` uses), `semantic/`, `governance/`, `api/{app,auth,hardening}.py`, `routes/{health,connector}.py`, `demo/` (no legacy imports beyond the connector's), `benchmarks/`, `examples/`.

## 2. Tests (541 collected)

Revised 17 Oct after the lead's decision that `audit/sink.py` (and so `aiofiles`) stays in M0. `test_audit_rehydration.py` (4) therefore moves from A to C. Note that once `routes/audit.py`, `cli verify-audit` and `agents/audit_agent.py` are gone, `sink` has no non-test caller, so it is kept only for its tests.

| Class | Count | Files |
|---|---|---|
| **A: whole file deleted with its code** | **31** | `integration/test_pipeline.py` 8, `unit/test_message_models.py` 8, `unit/test_request_evaluator.py` 6, `unit/test_policy_engine.py` 4, `unit/test_anomaly_detector.py` 5 (A only if the founder deletes `anomaly/`; otherwise C, and A = 26) |
| **B: file edited, function by function** | **32** | `security/test_api_robustness.py` 9, `security/test_api_auth.py` 10, `integration/test_api_connector.py` 7, `unit/test_recorder_scan.py` 6 |
| **C: unchanged** | **478** | the other 47 files, including `test_audit_rehydration.py`, `test_audit.py`, `test_broker_cwd.py`, `test_install.py`, `test_dual_control.py`, `test_oversight.py` |

The conftest fixtures `session_token` and `token_issuer` (`tests/conftest.py:11-29`, `crypto.tokens`) are used only by A files (`test_pipeline`, `test_message_models`, `test_policy_engine`, `test_request_evaluator`). Delete them with `crypto/tokens.py`.

### Class A node ids (31)
- `tests/integration/test_pipeline.py::TestPipelineEndToEnd::{test_allowed_read_completes, test_disallowed_execute_denied, test_invalid_token_halted, test_session_tracks_requests, test_write_budget_enforcement}`
- `tests/integration/test_pipeline.py::TestSessionLifecycle::{test_create_and_end, test_kill_session, test_validate_ended_session}`
- `tests/unit/test_message_models.py::TestEnums::{test_risk_tier_ordering, test_risk_tier_upgrade}`, `::TestActionRequest::{test_create, test_serialization}`, `::TestMessageEnvelope::test_envelope_creation`, `::TestEnrichedRequest::test_enriched_fields`, `::TestPolicyResult::{test_allow, test_deny}`
- `tests/unit/test_request_evaluator.py::TestRequestEvaluator::{test_read_classified_as_low, test_execute_classified_as_high, test_secret_access_classified_critical, test_missing_token_rejected, test_shell_metacharacters_escalate, test_malformed_json_rejected}`
- `tests/unit/test_policy_engine.py::TestPolicyEngine::{test_allowed_action_passes, test_disallowed_action_denied, test_critical_tier_escalates, test_write_budget_exhausted}`
- `tests/unit/test_anomaly_detector.py::TestSessionBaseline::{test_baseline_not_established_initially, test_baseline_established_by_count, test_baseline_freeze}`, `::TestRateMonitor::{test_no_alert_at_baseline, test_alert_on_spike}`

`test_message_models::TestEnums` tests `models/enums.py`, which stays. The whole file still goes because it imports `models.messages`. QA may want to keep those 2 enum tests by moving them.

### Class B node ids (32), what happens to each
| Node id | Uses | Action |
|---|---|---|
| `tests/security/test_api_robustness.py::test_no_route_crashes_on_malformed_input` | every route | keep (fewer routes; it should stop crashing; verify) |
| `…::test_schema_valid_bodies_with_junk_values_do_not_crash` | every route | keep |
| `…::test_spawn_reaches_the_toolkit` | `/runtime/spawn`, `AgentRuntime` | **delete** |
| `…::test_hook_connect_rejects_a_bad_workspace_without_leaking_paths` | `/hook/connect` | **delete** |
| `…::test_paths_the_os_cannot_stat_are_a_400` | `/hook/connect` (line 151) and connector | **repoint** the hook part at `/connector/status?root=` |
| `…::test_e2b_template_must_be_allowlisted` | `/e2b/v1/sandboxes`, `routes.e2b` import | **delete** |
| `…::test_unconfigured_redis_review_api_is_not_mounted` | asserts `/hitl/*` is absent | passes unchanged but becomes trivial; keep or fold into a "legacy routes are gone" test |
| `…::test_security_headers_on_every_response` | `/broker/pending` (lines 169-170) | **repoint** at a `/connector/*` route |
| `…::test_unexpected_errors_reveal_nothing` | adds its own route | keep unchanged |
| `tests/security/test_api_auth.py::test_public_routes_need_no_token` | `/health`, `/openapi.json` | keep unchanged |
| `…::test_no_token_is_rejected` | `/broker/pending`, `/broker/request` | **repoint** |
| `…::test_wrong_token_is_rejected` | `/broker/pending` | **repoint** |
| `…::test_agent_can_submit_but_not_approve` | `/broker/request`, `/broker/{id}/approve` | **repoint** at `/connector/{id}/approve`. The agent token must still get 403 (security review). |
| `…::test_approver_reaches_approver_and_agent_routes` | `/broker/*` | **repoint**. The "agent routes" half has no target once `AGENT_ROUTES` is empty. |
| `…::test_agent_cannot_install_or_remove_hooks` | `/hook/connect`, `/hook/disconnect` | **delete** (or fold into "agent token gets 403 on every route") |
| `…::test_websocket_needs_approver_token` | `/ws/events` | delete if `websocket.py` goes, keep if it stays |
| `…::test_generated_tokens_differ`, `::test_non_loopback_bind_needs_explicit_tokens`, `::test_same_token_for_both_roles_is_refused` | `api/auth.py` only | keep unchanged (3) |
| `tests/integration/test_api_connector.py::test_m1_routes_still_exist` | asserts `/api/v1/launch` and `/api/v1/hook*` exist (lines 36-39) | **invert** into "legacy routes are gone" |
| `…::{test_status_404_without_sandbox, test_status_returns_triggers, test_pending_reflects_queue, test_approve_runs_and_finishes, test_deny_marks_denied, test_verify_valid_chain}` | `/connector/*` | keep unchanged (6) |
| `tests/unit/test_recorder_scan.py::{test_detects_created, test_detects_modified, test_detects_deleted, test_same_size_different_content_is_modified, test_ignore_dirs_pruned, test_modified_preserved_to_trash}` | `launcher.recorder` | one import line repointed after the move (6) |

B totals: 5 deleted (`spawn`, `hook_connect`, `e2b`, `agent_cannot_install_or_remove_hooks`, plus `websocket` if it goes), 7 repointed, 1 inverted, 6 import-repointed, the rest unchanged.

Expected after M0, before QA adds new tests: 541 - 31 (A) - 5 (B deletions) = **505** collected, or 506 if the websocket stays, or 510/511 if `anomaly/` stays. Then 504 pass + 1 skip, *provided* the route-walker no longer crashes. QA should freeze this number in T1.

## 3. CI, pyproject and docs

| Item | Where | Action |
|---|---|---|
| CI auth smoke test curls `/api/v1/broker/pending` (a launcher route), expecting 401 and 403 | `.github/workflows/security.yml:156-158` | **This breaks when the launcher goes.** Switch to `/api/v1/connector/status?root=.` in the same commit. |
| The ZAP scan walks the full OpenAPI with the approver token, e2b and launch included | `security.yml:127-186` | This may explain the 15-minute ZAP cap in RESUME.md (it spawns sandboxes and processes). That is a hypothesis; re-time it after M0. |
| Deps used only by legacy code | `pyproject.toml:16-17,25-29` | Remove `nats-py` (transport), `redis[hiredis]` (hitl), `docker` (containment), `anthropic` and `openai` (agents/runtime), `aiofiles` (audit.sink, retention, rollback), `pyjwt` (crypto/tokens). `cryptography` and `rich` are imported by nothing (check for transitive needs before removing). Dev: `fakeredis` is imported by nothing. Keep `httpx` (`connector/broker.py`, `semantic/client.py`), `orjson` (`audit/chain.py`), `uvicorn`, `pydantic-settings` (only if `config.py` survives). |
| Project description "3-zone, 9-agent containment pipeline" | `pyproject.toml:8`, `api/app.py:125-130` | Reword. |
| Docs | `SECURITY.md:50-59,87` (runtime/spawn, e2b), `docs/CONNECTOR.md:224-236` (agent token "use `/e2b/v1`", launch, dashboard), `:297-298` (sandbox_hook), `docs/DETAILS.md:76-78` (launcher tree). README, GETTING_STARTED and the other `docs/*.md` have no legacy mentions. `MILESTONE_SUMMARY.md` and `PROJECT_BRIEF.md` are tracked; I did not review them. | Edit these in M0. |

## 4. `/api/v1/connector/*?root=<path>`

- `routes/connector.py:42-58` passes `root` straight to `FolderLayout(root)`, which runs `Path(root).resolve()` (`connector/layout.py:17-19`). The only check is "`<root>/.sandbox/` exists" (404 otherwise, 400 if the path can't be stat'ed).
- Endpoints: status, pending, changes, audit, verify, approve and deny (`connector.py:80-191`). All need the **approver** token (they are not in `AGENT_ROUTES`).
- So an approver-token holder can point the server at **any folder on the server's filesystem that has `.sandbox/`** (other users' repos, `..` paths, UNC paths on Windows). It can read that folder's audit and change journal, and **`/approve` runs that folder's queued command through the broker** (`connector.py:156-171`), recorded as reviewer `"api"`. There is no allowlist of registered roots, and no tenant binding. This is the M1 central-ingestion design point.

## 5. MCP governance today (P7)

| Question | Finding |
|---|---|
| 1. Do the hooks evaluate `mcp__<server>__<tool>`? | **Yes, for Claude Code only.** `install.py:170,187,204` registers the hooks with matcher `"*"`, so MCP calls reach `hook_eval`. The rules, in order (`classify.py:112-143`): `deny_tools` is an **exact-name** deny (`:113`, `policy.py:241`); `mcp__sandbox__*` is always allowed (`:120`); otherwise, if the server is in `network.allow_mcp_servers` (`policy.py:59`, server-level only) it is allowed, else it gets `triggers.network` (escalate by default). Escalated or governed calls go through approve-then-retry: a one-shot grant keyed on the SHA-256 of the canonical `{tool, input}` (`hook_eval.py:485-551`, `tool_grants.py:30-33`), with an Ed25519-signed approval and dual control when the risk is critical. Extra scrutiny: governance clauses on MCP calls (`hook_eval.py:359-366`, `_is_governed_tool` `:450-452`), but **only when the optional semantic/jev-os service is enabled** (`:466-467`); `safety/tool_actions.py:47-97` heuristics (moves_money / sends_data / prod_change from the server and tool names); taint escalation after an injection (`hook_eval.py:843-850`); PostToolUse injection scan of MCP output (`scan_tools` includes `mcp__*`, `policy.py:115`). **There are no per-tool allow rules, no argument constraints except through clauses, and no glob in `deny_tools`.** |
| 2. What `mcp_server.py` exposes | A FastMCP server on **stdio** (`mcp_server.py:80,245`) bound to one folder root (`--root`, then `SANDBOX_CONNECTOR_ROOT`, then a walk-up from cwd, `:27-36`). Five tools: `run_privileged`, `request_path_access`, `fetch_url`, `check_request`, `sandbox_status` (`:117-205`). There is no auth (the trust boundary is the local process). Every tool only *submits* to the folder queue, and a human approves it out of band. It is **always allowed by the hook** (`classify.py:120`), so it is the escalation channel and is not itself gated. Its safety rests on the queue and approval, not the hook. `fetch_url` output is still scanned (`hook_eval.py:878`). |
| 3. Inventory, pinning, description hashing, rug-pull or tool-poisoning checks | **None.** There is no MCP server inventory or registry, no pinning of server command or version, no hashing of tool descriptions or schemas, no detection of changes between sessions, and no scan of tool *descriptions* (only tool *outputs* are scanned, and only with semantic enabled). |
| 4. Non-Claude agents (Codex, Cursor) | **No enforcement on their MCP calls.** `install.py:66-81` only prints a Codex `config.toml` snippet that adds *our* MCP server (an escalation channel the agent may choose to use). There is no hook equivalent for Codex or Cursor, so their calls to other MCP servers, and their shell, are not intercepted. The `codex` and `hermes` entries in `routes/agents.py:16-21` are the toy from row 10. |

**MCP gaps (security-engineer should confirm):**
1. **Prefix bypass.** `classify.py:120`, `hook_eval.py:452` and `context_rules.py:61` treat `mcp__sandbox_` (single underscore) as our own server. A third-party server named `sandbox_anything` therefore gets **always-allow**: no allowlist, no governance, no context rules.
2. **Server-name trust.** The allowlist matches only the *name* in `mcp__<name>__`, which the client config chooses. Anything registered as `sandbox` (or an allowlisted name) inherits that trust.
3. **Config not protected.** `.mcp.json` and `.claude/settings*.json` are not in the non-removable `_PROTECT_WRITE_GLOBS` (`policy.py:22` holds only `.sandbox/**` and `.git/hooks/**`). An in-folder Write/Edit to them is allowed by default. Whether Claude Code then re-prompts the user before loading a new server or hook is unverified.

## 6. Risks and surprises

1. **The suite does not pass as-is on this machine.** The legacy e2b route crashes the interpreter (0xC0000005 in the Job Object code). The green "540" holds only with that test deselected. Deleting e2b, executor and containment is the fix, so M0 should start there and verify it.
2. **The connector imports the launcher today** (`connector/recorder.py:18` and `launcher/__init__.py`), and it pulls legacy deps through the `audit/__init__` and `crypto/__init__` re-exports. Deleting packages without editing those three `__init__` files breaks every connector import.
3. **CI's auth check targets a launcher route** (`security.yml:156-158`), and `AGENT_ROUTES` holds only legacy routes. Both silently change meaning in M0.
4. **MCP prefix bypass** (`mcp__sandbox_*` always allowed) and unprotected `.mcp.json` and `.claude/settings*.json`. These are real gaps in the product core, not legacy; they need ADR 0006 and security review.
5. **Windows cache DBs land in the repo** under `%SystemDrive%/` (committed in `69a1603`, and rewritten by today's test runs). A child process runs without `SystemDrive` in its env and with the repo as cwd. If that is the broker's env, approved commands on customer machines will scatter files the same way.
