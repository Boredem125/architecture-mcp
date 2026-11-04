# M2 Demo -- T16 gate run (frozen steps 1-11, scene 5(d))

> Measured 1 Nov 2026 on the founder's Windows 11 Home laptop (10.0.26300, Docker Desktop 29.9.1, Compose v5.6.0, Python 3.12.10 in `.venv`, Git bash `E:\Git\bin\bash.exe`), working tree on top of `89fd959` with the uncommitted T15b fixes. Every number below is from a fresh stack (`docker compose --profile demo down -v`, `init-secrets`, `--profile demo up -d --build`; 39-126 s to healthy, `/ready` 200). Windows needs `127.0.0.1 idp.localhost` in the hosts file and the Caddy root CA (`docker compose cp proxy:/root-cert/root.crt ee/deploy/.local/caddy-root.crt`).
>
> **Result: not all frozen steps pass.** `demo.py` (T14 steps 1-5, step 2 = frozen step 2 through the routes): 44 PASS, 1 FAIL, exit 1 in 70 s. Gate driver over frozen steps 1-11 and scene 5(d): **69 PASS, 7 FAIL, 5 NOT RUN** in 638 s. The FAILs are listed with their decisive output in section 3; nothing was fixed in product code for this run.

## 1. Commands

```bash
cd ee/deploy
docker compose --profile demo down -v
docker compose --profile init run --rm init-secrets
AGG_OIDC_ALLOW_HOSTS=idp.localhost docker compose --profile demo up -d --build
docker compose cp proxy:/root-cert/root.crt ./.local/caddy-root.crt
cd ../..
.venv\Scripts\python ee/deploy/demo.py --ca ee/deploy/.local/caddy-root.crt      # T14 steps 1-5
# frozen steps 3-11 and 5(d): qa gate driver (scratch, not committed), see section 4
```

`demo.py` covers frozen steps 1 and 2 only. Steps 3-11 and 5(d) have no driver in the repo; the qa gate driver ran them with the connector CLI (`sandbox init|enroll|sync --once|signer approve|export-evidence|alerts|status`), `python -m sandbox.connector.hook_eval` on stdin, and the server routes, retaining the CLI keys `demo.py` step 2 generates.

## 2. Per-step results (gate run, 1 Nov 2026)

| Step | Check (M2_BASELINE.md section 6) | Result | Measured | Command | Elapsed |
|---|---|---|---|---|---|
| 1 | `/ready` 200 on the fresh stack | PASS | HTTP 200 `{"status":"ok"}`; stack healthy 39 s after `up` (126 s on the first build) | `GET https://localhost/ready` | 2.1 s |
| 2 | genesis v1, v2 (threshold 2), v3 through routes; second genesis and code reuse refused; `pending_link` self-key refused | PASS | demo.py step 2: 26/26 PASS, `registry_version=3` | `demo.py --step 2` | 13.1 s |
| 2 | v3 verifies offline from the root fingerprint | PASS | `verify_chain` ok: 3 versions, 6 keys, fp `d926d739…c78a` | `verify_chain(GET /sync/signer/registry, fp)` | 2.2 s |
| 2 | threshold-1 v4 refused | PASS | HTTP 400 `threshold 1 below floor 2 (max admin count reached 2)` | `POST /sync/signer/signatures` | 2.1 s |
| 2 | v4 signed by a non-admin key refused | PASS | HTTP 400 `version 4 needs 2 admin sigs from previous admins, got 1` | same | 2.1 s |
| 2 | browser-key registry signature refused; N1 substituted key_id | NOT RUN | demo.py v3 links no browser key; covered by `ee/tests/test_m2_t12b_e2e.py::test_d4_5_browser_key_signature_refused`, `::test_d4_5_n1_substituted_key_id_refused` | - | - |
| 3 | alice issues a code to herself as operator; `sandbox enroll --expect-fingerprint` | PASS | rc 0, `Enrolled: device_id=a8919d99…`, enrollment.json has `operator_user_id` | `POST /admin/enrollment-codes`, `GET /enrollment-codes/{id}`, `sandbox enroll` | 3.2 s |
| 3 | code reuse refused | PASS | rc 1, `enrollment failed (400): invalid_code`, nothing written | `sandbox enroll` (same code) | 3.4 s |
| 3 | wrong fingerprint aborts with nothing written | PASS | rc 1, `pinned root mismatch … nothing written`; no sync files, no device/connector key | `sandbox enroll --expect-fingerprint 000…0` | 2.8 s |
| 4 | admins publish a staging bundle (two CLI approvals) | PASS | HTTP 200 `sequence 1` | `POST /admin/bundles` | 0.04 s |
| 4 | the connector picks the bundle up within 60 s | **FAIL** | `sandbox sync --once` rc 0, no `bundle.json`; the server serves it (`GET /sync/bundle` HTTP 200 seq 1) but no connector code path requests it (section 3, F-1) | `sandbox sync --once` | 7.0 s |
| 4 | refused: byte-flipped, replay of old sequence, server-signed loosening with no approvals, one-approval loosening, project-B bundle, first bundle with one approval | PASS (6/6) | `BundleError`: `bundle signature verification failed`, `sequence 1 not greater than current 1`, `need 2 approvals … got 0`, `… got 1`, `project_id mismatch`, `need 2 … got 1` | `verify_and_apply` on the served envelopes (driver-fed, see F-1) | <0.1 s |
| 4 | N4: connector reports non-prod after the two-approval `environment: staging` bundle | PASS | `load_verified_state`: `environment=staging sequence=1` | - | - |
| 4 | tightening escalates within 60 s; prod-to-nonprod with one approval; N4 pre-switch refusal | NOT RUN | no bundle transport (F-1); pre-switch case needs a second enrolment | - | - |
| 5 | `steal-env` reaches the inbox | PASS | hook `deny`, pending `requires_dual=True reason_code=EXFIL`; uploaded, `esc_id=a8dcd6a4…` | `hook_eval`; `sandbox sync --once` | 56.1 s + 9.6 s |
| 5(a) | bob approves; pending at 1 of 2, no marker | PASS | rc 0; after sync: pending, 0 done-records (audit `awaiting_second`) | `sandbox signer approve <esc> --yes` | 9.4 s |
| 5(c) | bob approves again | PASS | rc 1, HTTP 409 `duplicate approval for this escalation and user` | same | - |
| 5(c) | bob with his second key | NOT RUN | demo.py v3 links one bob key | - | - |
| 5(c) | alice (operator) approves | PASS | rc 1, `operator self-approval refused` | `sandbox signer approve` (alice key home) | - |
| 5(c) | device-signed approval | PASS | HTTP 403 `device tokens not accepted on this route` | `POST …/approvals` (device key + device Bearer) | 2.1 s |
| 5(b) | carol approves; action ran once in the broker; two `user_id`s verify offline | PASS | rc 0; sync: 1 done-record, `state=executed`, `exec_argv[0]=E:\Git\bin\bash.exe`, `exit_code=6` (curl: DNS failure for collector.invalid); `approved_by` = {bob, carol}, kinds `cli`; 2/2 envelopes verify against the pinned registry | `sandbox sync --once` | 10.6 s |
| 5(d) | `bash deploy.sh` escalates content-bound | PASS | `fp_v=2`, record sha256 = file bytes, preview shown | `hook_eval` | 56.3 s |
| 5(d) | bob approves; agent edits the script; carol approves; broker refuses | PASS | done-record `state=refused reason_code=SCRIPT_CHANGED`, signed, `expected_sha256=ac48250e…`, `actual_sha256=4f2fff64…`; marker absent; re-delivery does not run it | `sandbox signer approve` x2; `sandbox sync --once` x2 | 9.6 s + 7.0 s |
| 5(d) | alert raised | **FAIL** | `alerts.jsonl` holds 9 alerts (4 `shell_escalated`, 3 `denied`, 1 `key_pinned`, 1 `policy_drift`), none for `SCRIPT_CHANGED` (F-2) | `sandbox alerts -n 50` | 0.9 s |
| 5(d) | evidence pack holds the refusal and verifies offline | PASS | `decisions/<rid>.json`: `refused`/`SCRIPT_CHANGED`; pack `ok=True` | `sandbox export-evidence`, `verify_evidence(expected_root=fp)` | - |
| 6 | stop `api`: deny denied, critical pending past 3 poll intervals, allow allows | PASS | Write outside root: `WRITE_OUTSIDE` deny; steal-env pending after 3 x (`sync --once` + 10 s) = 142 s, 0 done-records; Read inside root: allow | `docker compose stop api`; `hook_eval`; `sandbox sync --once` | 142 s |
| 6 | restart: heads match | PARTIAL | `/ready` 18 s after `start api`; `sandbox sync --once` rc 0, no fork/truncation alert. Head compare NOT RUN: the CLI sync has no audit upload or checkpoint (F-3) | `docker compose start api` | 18.2 s |
| 7 | audit truncation: fork + truncation alerts, quarantine, `audit verify --project` | NOT RUN | the CLI sync never uploads audit records (F-3) | - | - |
| 8 | delete `.sandbox/state/sync/`: last bundle, no fallback | PASS | steal-env still escalates (`escalated as request …`), `echo hi` allowed per bundle | `hook_eval` | 56.3 s |
| 8 | delete `policy_history/` too: `locked` | PASS | `SANDBOX DENIED [LOCKED_MODE]: … no valid policy bundle` | `hook_eval` | 1.0 s |
| 8 | `sandbox status` shows locked | **FAIL** | `status --json` keys: `allow_runners, pending, policy_version, root, triggers`; no managed/locked field (F-4) | `sandbox status --json` | 1.4 s |
| 8 | re-enroll; F4 locked until a two-CLI-approval bundle | PASS | re-enroll rc 0 (`device_id=aacf946f…`); still locked; one-approval bundle `need 2 … got 1`; two-approval bundle `applied sequence 3`; `echo hi` allowed after | `sandbox enroll`; `POST /admin/bundles` seq 3; `verify_and_apply` | 3.2 s |
| 8 | alice revokes; 401 on next sync; local enforcement holds | PASS | revoke HTTP 200; `GET /sync/decisions` 401; token mint refused; steal-env still escalated | `POST /admin/devices/revoke` | 2.1 s |
| 9 | eve 404 on every Acme id | PASS 3/4, **FAIL** 1/4 | project id 404, escalation id 404, escalation list empty; `GET /enrollment-codes/<non-uuid>` HTTP **500** (F-5). demo.py step 3: 7/7 PASS | eve session GETs | <0.1 s |
| 10 | `down`, `up`: registry, bundles, heads persist; `audit verify` | PASS 4/6, **FAIL** 2/6 | `/ready` 33 s after `up`; chain 3 versions, same fp; `GET /sync/bundle` seq 2; `python -m agg_cp.cli audit verify --org acme` exit 0; connector sync rc 0. FAIL: `agg-cp audit verify` exit 127 (F-6); bob `/login` after restart `403 not_provisioned` (F-7) | `docker compose --profile demo down; up -d` | 33 s |
| 11 | evidence pack covering the step 5 action, verified with the network cut | PASS | `export-evidence` rc 0; `verify_evidence(expected_root)` `ok=True`; without the root `ok=False remote_root_unverified=True`; `decisions/08448410f81bcf39.json` holds `approved_by` bob+carol with `key_kind` `cli`, `environment: staging` | `sandbox export-evidence --out <dir>` | 1.6 s |
| T16 | SCRIPT_UNPINNABLE retry measure | NOT RUN | needs a live agent session in an enrolled workspace; none was run (section 5) | - | - |

Totals: 69 PASS, 7 FAIL, 5 NOT RUN (one row above counts two sub-checks). `demo.py` standalone: 44 PASS, 1 FAIL (step 5 `agg-cp`, F-6), exit 1, 70 s.

## 3. Failures and findings (not fixed; reported for the owners)

- **F-1 (step 4, connector, blocks the gate).** No connector code path fetches `/api/v1/sync/bundle`: `src/sandbox/cli/sync_cmds.py::run_once` uploads, polls decisions and refreshes the registry only; `src/sandbox/connector/sync/process.py::run_once` has no bundle step either (`BUNDLE_CADENCE` is unused), and `sandbox sync` without `--once` prints `continuous mode not yet implemented`. The server also discards `change_approvals` in `POST /admin/bundles` (`ee/src/agg_cp/sync/bundles.py:181-258`: parsed, never stored) so a pulled bundle could not carry them. For this run the driver fetched the served envelope with the device token and fed it to `sandbox.connector.sync.bundles.verify_and_apply` with locally built `agg/policy-change/v1` approvals; every verifier refusal above is product code, the transport is not.
- **F-2 (scene 5(d)).** The `SCRIPT_CHANGED` refusal writes a signed terminal done-record but raises no alert: `alerts.jsonl` has no entry for it and `sandbox alerts` shows none. Founder ruling 25 Oct asks for "a signed `SCRIPT_CHANGED` and an alert".
- **F-3 (steps 6, 7).** The CLI sync has no audit upload or checkpoint; steps 7 and the step 6 head compare cannot be driven.
- **F-4 (step 8).** `sandbox status --json` has no managed/locked field; the locked state is visible only through the hook's `LOCKED_MODE` deny.
- **F-5 (step 9).** `GET /api/v1/enrollment-codes/{id}` with a non-uuid id returns 500 for a Globex session (expected 404). Not re-tested with a uuid-shaped id after the restart (F-7 blocked eve's login).
- **F-6 (step 10, demo.py).** `demo.py` step 5 runs `agg-cp audit verify` in the `api` container; the Chainguard image has no `agg-cp` entry point: exit 127 `"agg-cp": executable file not found in $PATH`. `python -m agg_cp.cli audit verify --org acme` exits 0.
- **F-7 (step 10, deploy).** After `down`/`up` no demo user can log in: callback `403 not_provisioned`. Keycloak (demo profile) keeps its H2 dev-file DB on tmpfs, so the realm is re-imported with new subjects (alice stored `351b9803…`, Keycloak after restart `9cff068f…`); `users(oidc_issuer, oidc_subject)` no longer matches. Registry, bundles and audit persist.
- **F-8 (server, security, found in run 4).** The operator self-approval rule (`ee/src/agg_cp/sync/escalations.py:998-1035`) reads `allow_requester` from the latest `policy_bundles` row by sequence without checking its change approvals. After an unapproved server-signed seq-2 bundle with `allow_requester: true` (which the connector refuses), alice's approval of her own connector's escalation was accepted (`Approval posted`, HTTP 200). Reproduced in run 5 as the row "FINDING … alice (operator) approval is refused": rc 0, accepted. The connector still needs two valid non-operator approvals, so the action did not run; the server-side guard is bypassable by whoever can call `/admin/bundles`.
- **F-9 (connector, found in run 1).** `sandbox enroll` ignores the cwd: `src/sandbox/connector/sync/enroll.py:418-432` takes the first initialised root from `_discover_workspace_roots()`. With two initialised workspaces in one key home the re-enrol landed in the other workspace. The gate used a separate key home for the negative cases.
- Observation: `counts_for_dual` (D5.3) correctly refuses carol's v2 admin key for remote dual control (v2 carried one prior-admin signature); the gate approves with the v3 approver keys. `demo.py`'s own run 1 also saw the T14 step 5 FAIL (F-6) only.

## 4. How the gate driver differs from a pure CLI run

The driver (qa scratch `m2_gate.py`, kept out of the repo) wraps `demo._link_cli_key` to retain the keys `demo.py` generates, computes the root fingerprint from the served genesis payload, and otherwise uses the CLI and routes. Three things it does that the product does not do by itself, each mirrored from `ee/tests/test_m2_t12b_e2e.py`: it applies the server-published bundle through `verify_and_apply` (F-1); it writes `server_time_state.json` (only `sync/process.py` writes it, the CLI `run_once` does not, and `apply_external` fails closed without it); and it set `escalation_timeout_seconds: 0` in `policy.json`, which the managed hook ignored, so every escalating hook call blocked the full 55 s.

## 5. Not run

- Step 7, the step 6 head compare (F-3); step 4's 60 s pull measure (F-1); 5(c) bob's second key and the browser-key/N1 registry negatives (no browser key in demo.py v3; ee tests cover them); the N4 pre-switch refusal.
- The SCRIPT_UNPINNABLE retry measure (T16 note, 25 Oct): it needs a real agent session driving the hook in an enrolled workspace; no agent run was made in this gate. Recipe for the next run: `sandbox init --claude` on the enrolled workspace, prompt the agent to run `./deploy.sh`, `.\x.cmd` and a `py x.py` form, count PreToolUse `SCRIPT_UNPINNABLE` denies per prompt and whether the agent reaches `bash deploy.sh` or `python x.py`.
- `--live` (two browser profiles) was not run.

## 6. Stack checks

| Check | Result |
|---|---|
| Fresh stack to `/ready` 200 | 126 s first build, 39 s rebuilds (5 fresh stacks this session) |
| `init-secrets` on an existing `secrets/` | skips the 4 existing files (`O_EXCL`), stack still healthy |
| `python -m agg_cp.cli audit verify --org acme` after `down`/`up` | exit 0 |
| Registry chain after `down`/`up` | 3 versions, fingerprint unchanged |

## 7. Security rulings (1 Nov, T16 findings)

Security-engineer (L), read-only code review of sections 2, 3 and 5. Fix node ids are exact; qa writes each named test first (strict xfail), builders fix only the named node.

### 7.1 F-8: server-side operator self-approval guard reads an unapproved bundle. MEDIUM. MUST before the gate (small fix) plus a named limit.

Verified in code:
- `POST /api/v1/admin/bundles` (`ee/src/agg_cp/sync/bundles.py::admin_create_bundle`, 181-258) is any **admin session + CSRF** in the org, not host access. It takes `bundle_payload` as given, signs it with the server key, inserts it at whatever `sequence` the body names, and **drops `change_approvals`** (parsed at line 194, never verified, never stored). There is no loosening check and no base_sequence check. The `policy_change_requests` / `policy_change_approvals` tables from migration 0007 have **no reader or writer** anywhere in `ee/src/agg_cp`: the "ee review flow" does not exist in code. The only approval verification in the product is the connector's `verify_and_apply._verify_change_approvals` (2 distinct CLI registry users for a loosening or a first bundle).
- So every row in `policy_bundles` is one admin's unverified word, and "latest by sequence" (`escalations.py::submit_approval`, lines 998-1035) is exactly that.
- Exploit path: one admin who is also a device's operator (alice in the demo) posts seq N+1 with `approval.allow_requester: true` and no approvals, then approves her own agent's escalation; the server records `Approval posted` 200. With a second real approver the server's inbox and central audit would show 2-of-2 **approved** while the laptop refuses. No path for a non-admin (eve, bob): the route is `role="admin"`. No host access needed.
- Connector: authoritative and holding. `approval.py::_verify_remote_approval` step 10 (lines 555-557) reads `allow_requester` from `_get_enforced_approval` = `_verified_bundle_payload` (pinned root; a loosening needs 2 CLI users). The unapproved bundle can never land there (and today nothing fetches bundles at all, F-1), so alice's approval returns `None` and is not counted; the gate confirmed the action did not run. "Fail-closed local enforcement" and "dual control = two humans" hold on the laptop; they are broken in the control plane's own record, which is what the paid product sells.

Ruling:
- **MUST (gate):** the server guard fails closed in M2. In `submit_approval` replace the bundle read (lines 1004-1030) with `allow_req = False`: operator self-approval is refused server-side unconditionally; `allow_requester` is honoured only by the connector's locally verified bundle. Pure tightening. Test first: `ee/tests/test_m2_t12b_server.py`: after `POST /admin/bundles` seq N+1 with `allow_requester: true` and no `change_approvals`, the operator's approval of her own device's escalation returns 403 `operator self-approval refused`.
- **Full fix (with F-1; lead-architect sizes it):** `admin_create_bundle` verifies `change_approvals` with the connector's rule (bundle_hash binding, CLI registry keys, 2 distinct users for a loosening against the stored previous row or a first bundle, 1 for a tightening) and refuses otherwise; stores them with the row; `GET /sync/bundle` serves them verbatim. Only then may server logic read `policy_bundles` as approved policy.
- **Named limit (exact wording, until the full fix):** "M2: the control plane signs and stores a bundle on one admin's request, retaining and serving its change approvals verbatim, without verifying them. No connector applies such a bundle: the connector verifies two distinct CLI approvals against the pinned registry before any loosening takes effect, and the control plane refuses operator self-approval regardless of the bundle's `allow_requester` flag."
- ~~Superseded 2 Nov 2026:~~ prior wording was "without verifying or retaining its change approvals"; T16b adds server-side retention and serving.

### 7.2 F-9: `sandbox enroll` enrols the first discovered workspace, not the cwd. MEDIUM. MUST (one function).

`enroll.py::_persist_enrollment` (lines 418-432) iterates `_discover_workspace_roots()` from the key home and takes the first `FolderLayout` that exists; the CLI (`sync_cmds.py::enroll`, lines 102-114) never passes a root, unlike `sync` (line 127, `FolderLayout(".")`). Consequence: the managed marker, pinned root, device key, device_id and `operator_user_id` are written into **another** project's tree; that project becomes managed under the wrong project_id and operator, the intended one silently stays unmanaged, and `_check_pinned_root_conflict` may compare against the wrong workspace (key-home confusion across two orgs). Not an attacker escalation (the key home is the user's own) but a silent identity-binding error in enrolment and in the audit. Fix: `enroll()` resolves `FolderLayout(Path.cwd())`, refuses if `.sandbox` is absent, and requires the key-home entry whose `workspace_root` equals the resolved cwd and whose `workspace_id` matches; never iterate, never fall back. Test first: `tests/security/test_m2_enroll_persist.py`: two initialised workspaces in one key home, cwd = the second: the sync dir appears only under cwd; cwd not initialised: `EnrollError`, nothing written anywhere. Named limit if deferred: "`sandbox enroll` writes to the first initialised workspace registered in the key home, not the cwd; keep one initialised workspace per key home until fixed."

### 7.3 F-2: SCRIPT_CHANGED refusal raised no alert. Required: yes. MUST (scene 5(d) is defined with it).

Normative source: ADR 0010 s9, line 83: a refusal "is signed like any done-record ... chained in the audit, and raises the critical alert `script_changed` or `shell_unavailable`"; T12B_PLAN lines 123 and 141 (founder ruling 25 Oct) repeat it. M2_BASELINE section 6 step 5 does not itself list 5(d); the scene came in with T16. Cause: `broker.py::_refusal_record` (lines 48-80) sets no `event`, `alerts._ALWAYS` (lines 24-35) has no refusal kind, nothing emits on the `state == "refused"` path, and the broker has no layout. Fix at one chokepoint: `_refusal_record` sets `event` to `script_changed` or `shell_unavailable`; `alerts._ALWAYS` maps both to themselves; `queue.finish` (queue.py ~162-185, the single place every terminal record is signed, with `self._layout`) calls `alerts.emit(layout, session_id, result)` after signing when `result.get("state") == "refused"`, best-effort like every other emit. That covers the local `approve()` finish (approval.py:217) and both `apply_external` finishes (815, 932). Test first: `tests/security/test_m2_script_binding.py`: after the swap-then-approve scenario, `alerts.read_alerts(layout)` holds one `script_changed` alert naming the request_id, expected and actual sha256, and no command output.

### 7.4 F-5: `GET /enrollment-codes/<non-uuid>` 500. LOW; shape bug, not a leak. MUST (frozen step 9 says 404 on every id).

`enroll.py::operator_read_code` (lines 348-392) passes `code_id` into `%s::uuid`; psycopg raises on a non-uuid and Starlette returns its generic 500 body (no `debug=True` in `ee/src/agg_cp`, so no traceback). The oracle only distinguishes "uuid-shaped" from "not", never existence or tenancy. Fix: after `_validate`, `if not _is_uuid(code_id): return 404 not_found` (reuse `escalations.py::_is_uuid`, line 85). Return 404, not 400, so step 9 stays uniform. Test first: `ee/tests/test_m2_t8_enroll.py`: valid session, `GET /api/v1/enrollment-codes/not-a-uuid` is 404 `{"error":"not_found"}`; no session is still 401. qa should grep the other `{id}` routes with `::uuid` casts for the same shape.

### 7.5 F-1 / F-3 / steps 4 and 7: security consequence only (scope is lead-architect's).

- Can a connector today run on a bundle the review flow never approved? **No.** No connector code path fetches `/sync/bundle`; the only way a bundle lands is `verify_and_apply`, which needs CLI change approvals verified against the pinned registry (2 distinct users for a first bundle or a loosening). Because the server discards `change_approvals`, even a future transport that served today's rows would be refused by every connector, and an enrolled laptop would stay `locked` (F4). Fail-closed holds.
- Is any demo claim currently untrue? **Yes, two.** "The connector picks the bundle up within 60 s" and "policy approved by two reviewers reaches the laptop" are untrue today: nothing reaches the laptop from the control plane; every bundle in this gate was applied by the qa driver calling `verify_and_apply` with locally built approvals. Also untrue in spirit: the server's `policy_bundles` rows are not approved policy (7.1). Under the honesty rule, M2_DONE and the demo script must say so until F-1 lands with approvals stored and served.
- Requirement for whichever scope lead-architect picks: the connector verifier stays authoritative; the server stores and serves `change_approvals` verbatim; the server may additionally verify at publish (closes 7.1 fully). Named limit if deferred: "M2: the control plane signs and stores bundles but does not deliver them, and does not verify or retain change approvals; `sandbox sync` applies no server bundle and uploads no audit records. Every bundle on a laptop was applied locally after two CLI change approvals verified against the pinned registry."

### 7.6 Proposer exclusion (ADR 0001 A2.3) is not visible to the connector. LOW. Named limit, plus a server-side MUST before the gate (4 Nov, security L).

Verified in code: the signed envelope and the `agg/policy-change/v1` approvals carry no proposer; `src/sandbox/connector/sync/bundles.py::_verify_change_approvals` counts distinct CLI registry users with no exclusion; `ee/src/agg_cp/sync/bundles.py::admin_create_bundle` does not compare the publishing admin with the approvers. So "neither may be the proposer" is enforced nowhere today.

Named limit (exact wording): "M2: the connector counts any two distinct CLI approvers against its pinned registry; it cannot see who proposed the bundle, because the signed envelope carries no proposer. Proposer exclusion (ADR 0001 A2.3) is enforced only by the control plane at `POST /api/v1/admin/bundles`, which refuses an approval whose key belongs to the publishing admin (ADR 0001 Amendment A2). Two different humans still approve every loosening on the laptop; the three-person separation of A2.3 depends on the control plane."

MUST before the gate (own tests-first item T16h, not T16g): the publish refusal in ADR 0001 Amendment A2 item 1, with the T16b fixtures moved to a third-admin publisher by node id.

### 7.7 G7-C: no connector quarantine state. LOW. Named limit (founder approved, 4 Nov).

Named limit (exact wording): "Quarantine is a server-side state for forked records (`audit_quarantine`). In M2 the connector does not enter quarantine; it raises a local `audit_fork` alert and keeps enforcing locally. Device-level quarantine is M3." The `m2_gate.py` step 7 status check becomes two asserts: an `audit_quarantine` row exists, and `sandbox alerts` contains `audit_fork`. G7-A and G7-B are blockers fixed in T16g (ADR 0001 Amendment A3).

Unsigned `high_water.json` limit (founder, 25 Oct; Low), one sentence added 4 Nov (security L, T16g review): with the bootstrap loader, a host-level writer who deletes `bundle.json` and `policy_history/` and zeroes `high_water.json` makes the connector re-apply the server's sequence 1 bundle (a rollback to the first approved bundle) instead of locking; this is the same capability the limit already grants (restoring an old `bundle.json` from `policy_history/`), and every such bundle still carries two verified CLI approvals.

