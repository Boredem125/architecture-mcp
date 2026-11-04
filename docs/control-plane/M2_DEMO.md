# M2 Demo -- T16 gate run (frozen steps 1-11, scene 5(d))

> **Result (run 2, 4 Nov 2026, HEAD 8c2d735 + uncommitted m2_gate.py driver fix): all frozen steps pass.** `demo.py` 47 PASS / 0 FAIL, exit 0, 87 s; `m2_gate.py` 88 PASS / 0 FAIL / 0 NOT RUN in 578 s. Stack healthy 52 s after `up -d` on the built stack, 40 s on the recycled one. The driver is `ee/deploy/m2_gate.py` (with the uncommitted fix); the per-step table is section 2.
>
> Run 1 (1 Nov 2026) environment and result, kept as history: measured 1 Nov 2026 on the founder's Windows 11 Home laptop (10.0.26300, Docker Desktop 29.9.1, Compose v5.6.0, Python 3.12.10 in `.venv`, Git bash `E:\Git\bin\bash.exe`), working tree on top of `89fd959` with the uncommitted T15b fixes. Every number below is from a fresh stack (`docker compose --profile demo down -v`, `init-secrets`, `--profile demo up -d --build`; 39-126 s to healthy, `/ready` 200). Windows needs `127.0.0.1 idp.localhost` in the hosts file and the Caddy root CA (`docker compose cp proxy:/root-cert/root.crt ee/deploy/.local/caddy-root.crt`).
>
> **Result, run 1 (1 Nov 2026): not all frozen steps pass.** `demo.py` (T14 steps 1-5, step 2 = frozen step 2 through the routes): 44 PASS, 1 FAIL, exit 1 in 70 s. Gate driver over frozen steps 1-11 and scene 5(d): **69 PASS, 7 FAIL, 5 NOT RUN** in 638 s. The FAILs are listed with their decisive output in section 3; nothing was fixed in product code for this run.

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

## 2. Per-step results (gate run 2, 4 Nov 2026)

Source: `m2_gate.py` results.json (88 checks) and stdout log. Measured detail is trimmed to about 100 characters; seconds are shown where the driver timed the command.

| Step | Check | Result | Measured | Elapsed |
|---|---|---|---|---|
| 1 | /ready is 200 on the fresh stack | PASS | HTTP 200 {"status":"ok"} | 2.11 s |
| 2 | demo.py step 2 completed | PASS | registry_version=3 | 15.96 s |
| 2 | v3 chain verifies offline from the root fingerprint | PASS | versions=3 fp=992074e626d50f4c... keys=8 | 2.15 s |
| 2 | threshold-1 v4 refused | PASS | HTTP 400 {"error":"threshold 1 below floor 2 (max admin count reached 2)"} | 2.11 s |
| 2 | v4 signed by a non-admin (bob) key refused | PASS | HTTP 400 {"error":"version 4 needs 2 admin sigs from previous admins, got 1"} | 2.12 s |
| 2 | browser-key registry signature refused | PASS | HTTP 400 {"error":"version 4 needs 2 admin sigs from previous admins, got 1"} | 2.11 s |
| 2 | N1 substituted key_id refused | PASS | HTTP 400 {"error":"signature verification failed for key 107652fc23dd93d36993ed69ea0c4d493642c2b1c0… | 2.1 s |
| 9 | demo.py step 3 completed | PASS | - | 13.91 s |
| T14-4 | demo.py step 4 completed | PASS | - | 5.73 s |
| 3 | sandbox enroll succeeds | PASS | rc=0 Enrolled: device_id=26281438-3a65-42b8-a605-83e74859fc3d Operator: 7bbe2804-2879-439b-8298-7e2… | 2.95 s |
| 3 | code reuse refused | PASS | rc=1 ync\enroll.py", line 587, in _raise_enroll_error raise EnrollError(f"enrollment failed ({statu… | 2.87 s |
| 3 | wrong fingerprint aborts with nothing written | PASS | rc=1 sync_files=[] keyhome_device_files=[] 0000000000000000000000000000000000000000000000000000', c… | 2.88 s |
| 4 | carol publishes, alice+bob approve bundle seq 1 (environment: staging, escalation_timeout_seconds: 0) via /admin/bundles | PASS | HTTP 200 {"bundle_id":"5008dcbc-bf57-4ae1-acde-e88a6bde216d","sequence":1} | 0.05 s |
| 4 | N4 pre-switch: second enrollment succeeds | PASS | rc=0 Enrolled: device_id=32164998-8c7c-4b64-aa3b-8b56d7c71375 Operator: 7bbe2804-2879-439b-8298-7e2… | 2.86 s |
| 4 | N4 pre-switch: no bundle yet, environment is None (prod default) | PASS | verified_state=None | - |
| 4 | connector picks the published bundle up through `sandbox sync --once` (within 60 s) | PASS | sync rc=0; bundle.json present=True | 14.58 s |
| 4 | server_time_state.json written by sync (no hand-fed write) | PASS | server_time_state.json exists=True | - |
| 4 | connector reports non-prod after the two-approval staging bundle (N4) | PASS | environment=staging sequence=1 | - |
| 4 | server serves the bundle to the device token (GET /sync/bundle) | PASS | seq=1 | - |
| 4 | first bundle with one approval refused | PASS | BundleError: sequence 1 not greater than current 1 | - |
| 4 | byte-flipped bundle refused | PASS | BundleError: bundle signature verification failed for key c3ff5a36ec3571a38ceced0bffbd2be958642d5c8… | - |
| 4 | bundle for another project refused | PASS | BundleError: project_id mismatch: bundle has '1c902e22-a5a9-4a7b-a871-d3d7a21ef9b9', expected '68fa… | - |
| 4 | replay of the same sequence refused (already applied by sync) | PASS | BundleError: sequence 1 not greater than current 1 | - |
| 4 | N4 pre-switch: after sync, second workspace reports staging | PASS | sync rc=0 environment=staging | - |
| 5 | steal-env preset escalates (deny + pending, requires_dual) | PASS | decision=deny requires_dual=True reason_code=EXFIL rid=2e0241a358cc5dd5 | 0.89 s |
| 5 | escalation reaches the server inbox | PASS | sync rc=0 esc_id=2e575c81-c63e-4793-85a1-83d5363178ea | 16.94 s |
| 5a | bob approves (CLI signer) | PASS | rc=0 Fingerprint: f7070dd6d7e143448285283942745408379bd702bece458d49629d966176f7b5 Requires dual: T… | 7.38 s |
| 5a | pending at 1 of 2: no done-record, still pending | PASS | pending=True done=0 | 17.29 s |
| 5c | bob approves again: same_user refusal | PASS | rc=1 uence: 1 Fingerprint: f7070dd6d7e143448285283942745408379bd702bece458d49629d966176f7b5 Require… | 7.46 s |
| 5c | bob approves with his browser key (second key): same_user refusal | PASS | rc=1 uence: 1 Fingerprint: f7070dd6d7e143448285283942745408379bd702bece458d49629d966176f7b5 Require… | 7.32 s |
| 5c | alice (operator) approves: requester refusal | PASS | rc=1 nce: 1 Bundle sequence: 1 Fingerprint: f7070dd6d7e143448285283942745408379bd702bece458d49629d9… | 7.38 s |
| 5c | device-signed approval refused (wrong_kind) | PASS | HTTP 403 {"error":"device tokens not accepted on this route"} | 2.1 s |
| 5b | carol approves (browser signer) | PASS | rc=0 Fingerprint: f7070dd6d7e143448285283942745408379bd702bece458d49629d966176f7b5 Requires dual: T… | 7.38 s |
| 5b | action ran once in the broker (one done-record, state executed) | PASS | sync rc=0 done_records=1 state=executed exit_code=6 exec_argv0=E:\Git\bin\bash.exe | 17.17 s |
| 5b | done-record holds two user_ids (bob, carol) with key kinds | PASS | user_ids=['9894e66b-4b40-432a-9a18-c4b7ce491060', 'db33f6c9-b66c-48a6-8115-33bf85d044b8'] kinds=['b… | - |
| 5b | both approvals verify offline against the pinned registry | PASS | verified=2 of 2 | - |
| 5d | bash deploy.sh escalates content-bound (fp_v 2, script sha256) | PASS | decision=deny fp_v=2 sha_match=True shown=True | 0.66 s |
| 5d | script escalation uploaded | PASS | esc_id=995efa4b-1c66-4b79-b015-a60b82af87f1 | 18.65 s |
| 5d | bob approves the bound script | PASS | rc=0 Files it loads are not. --- script body --- 1 \| #!/bin/sh 2 \| echo deploy-staging --- end --… | 7.14 s |
| 5d | carol approves after the agent edited deploy.sh | PASS | rc=0 Files it loads are not. --- script body --- 1 \| #!/bin/sh 2 \| echo deploy-staging --- end --… | 7.05 s |
| 5d | broker refuses with a signed SCRIPT_CHANGED; swapped bytes never ran | PASS | state=refused reason_code=SCRIPT_CHANGED signed=True marker=False expected=ac48250ebcd2 actual=0bca… | 16.51 s |
| 5d | alert raised for SCRIPT_CHANGED | PASS | [2026-11-04 14:24:38] SCRIPT_CHANGED risk=60 bash deploy.sh SCRIPT_CHANGED: expected sha256=ac48250… | 0.78 s |
| 5d | re-delivery does not run it (refusal terminal) | PASS | marker=False pending=False | 14.33 s |
| 11 | sandbox export-evidence | PASS | rc=0 (s); E013.2 E015 Log AI system activity [partial]: 15 item(s); E015.2, E015.3, E015.4 Verify w… | 1.2 s |
| 11 | evidence verifies offline against the root fingerprint | PASS | ok=True failures=[] | 0.04 s |
| 11 | verify without the root reports remote_root_unverified | PASS | ok=False remote_root_unverified=True | - |
| 11 | pack holds the step 5 done-record with both user_ids and key kinds and the non-prod label | PASS | user_ids_match=True kinds=['cli', 'browser'] environment_label='staging' keys=['approved_at', 'appr… | - |
| 5d | evidence pack holds the SCRIPT_CHANGED refusal | PASS | state=refused reason_code=SCRIPT_CHANGED | - |
| 9 | eve gets 404 on Acme staging project id | PASS | HTTP 404 | 0.03 s |
| 9 | eve gets 404 on Acme escalation id | PASS | HTTP 404 | 0.03 s |
| 9 | eve gets 404 on Acme enrollment code id | PASS | HTTP 404 | 0.03 s |
| 9 | eve's escalation list holds no Acme escalation | PASS | HTTP 200 count=0 | - |
| 6 | docker compose stop api | PASS | Container deploy-api-1 Stopping Container deploy-api-1 Stopped | 2.87 s |
| 6 | deny-class call denied while offline | PASS | decision=deny reason=SANDBOX DENIED [WRITE_OUTSIDE] (risk 70/100): write outside the folder (C:\Win… | 1.21 s |
| 6 | critical call escalates (pending) while offline | PASS | decision=deny rid=1c36ae94dbe79ab3 | 0.91 s |
| 6 | critical call stays pending past 3 poll intervals (3 x 10 s) without running | PASS | pending=True done_before=2 done_after=2 | 47.95 s |
| 6 | allow-class call (Read inside root) allows while offline | PASS | decision='' reason= | 0.87 s |
| 6 | api restarted: sync succeeds, no fork or truncation alert | PASS | ready after 26.7s; sync rc=0; alerts fork/truncation=False | 23.64 s |
| 6 | heads match after restart (audit verify --org acme exits 0) | PASS | rc=0 | 1.44 s |
| 4 | server-signed loosening with no approvals refused by the connector | PASS | BundleError: need 2 approvals from distinct users, got 0 | - |
| 4 | one-approval loosening refused by the connector | PASS | BundleError: need 2 approvals from distinct users, got 1 | - |
| 5c | FINDING: after an unapproved server-signed allow_requester bundle, alice (operator) approval is refused | PASS | rc=1 48e4948506cc699fc7c8c1e3cab2d396b136a834e759bf0073161a543808d3af Requires dual: True Error: se… | 7.45 s |
| 7 | sync after audit mutation (session s-2026-11-04-b32ad2: 7->6 records, cut 3, append 2) | PASS | sync rc=0 output[-300:]= | 19.39 s |
| 7 | fork or truncation alert in sandbox alerts | PASS | fork=True truncation=False alerts[-200:]=it out (curl_upload) [2026-11-04 14:26:56] BUNDLE_REFUSED… | - |
| 7 | sandbox alerts contains audit_fork after audit fork | PASS | audit_fork_alert=True alerts[-200:]=it out (curl_upload) [2026-11-04 14:26:56] BUNDLE_REFUSED need… | - |
| 7 | server audit_quarantine holds a fork row after audit fork | PASS | rc=0 rows=1 first=[{"kind": "fork", "detail": {"session_id": "s-2026-11-04-b32ad2", "forked_hash":… | 1.44 s |
| 7 | audit verify --project passes on main chain (server-side) | PASS | rc=0 | 1.48 s |
| 7 | server-side sync_alerts holds fork or truncation alert | PASS | rc=0 server_fork=True server_trunc=True alerts=[{"kind": "truncation", "detail": {"session_id": "s-… | - |
| 10 | down, up -d, /ready 200 | PASS | down rc=0 up rc=0 ready after 39.9s | 39.93 s |
| 10 | registry chain persists (3 versions, same fingerprint) | PASS | versions=3 | - |
| 10 | bundles persist (GET /sync/bundle serves the latest sequence) | PASS | seq=1 | - |
| 10 | python -m agg_cp.cli audit verify --org acme exits 0 (T16d-1) | PASS | rc=0 | 1.55 s |
| 10 | connector syncs after the restart | PASS | rc=0 | 17.43 s |
| 10 | bob can log in again after the restart (users persist, Keycloak subjects stable) | PASS | callback=200 <!doctype html> <html lang="en"> <head> <meta charset="UTF-8" /> < /me=200 | 4.84 s |
| 8 | sync state deleted: connector stays on the last bundle (steal-env still escalates, no fallback) | PASS | decision=deny reason=SANDBOX: escalated as request d3ddc59e68f3aaf6 — no human decision yet. Ask th… | 55.93 s |
| 8 | sync state deleted: a plain allowed command still follows the bundle (not local policy) | PASS | decision='' reason= | 0.86 s |
| 8 | policy_history deleted too: workspace locked (echo hi denied) | PASS | decision=deny reason=SANDBOX DENIED [LOCKED_MODE]: this workspace is managed but has no valid polic… | 0.83 s |
| 8 | sandbox status reports locked/managed | PASS | status keys=['allow_runners', 'locked', 'managed', 'pending', 'policy_version', 'root', 'triggers']… | 1.04 s |
| 8 | re-enroll succeeds | PASS | rc=0 Enrolled: device_id=f70ae25e-5836-4e13-8a63-3dc42c4cf7c5 Operator: 7bbe2804-2879-439b-8298-7e2… | 2.9 s |
| 8 | F4: still locked after re-enroll until a bundle arrives | PASS | decision=deny reason=SANDBOX DENIED [LOCKED_MODE]: this workspace is managed but has no valid polic… | 0.8 s |
| 8 | carol publishes, alice+bob approve bundle seq 3 (base 0) for the re-enrolled workspace | PASS | HTTP 200 {"bundle_id":"6a22d7a3-7e03-40c3-8a84-1ae0f4405284","sequence":3} | - |
| 8 | F4: a one-approval bundle does not unlock | PASS | BundleError: need 2 approvals from distinct users, got 1 | - |
| 8 | F4: a two-CLI-approval bundle unlocks | PASS | applied sequence 3 | - |
| 8 | unlocked after the two-approval bundle | PASS | decision='' reason= | 0.88 s |
| 8 | alice revokes the device | PASS | HTTP 200 {"revoked_at":"2026-11-04T09:00:01.513107+00:00"} | 2.13 s |
| 8 | next sync call gets 401 | PASS | HTTP 401 {"error":"unauthorized"} | - |
| 8 | revoked device cannot mint a new token | PASS | token=None | - |
| 8 | local enforcement holds after revoke (steal-env still denied/escalated) | PASS | decision=deny reason=SANDBOX: escalated as request 7fa547080c1010f9 — no human decision yet. Ask th… | 1.0 s |

Totals: 88 PASS, 0 FAIL, 0 NOT RUN in 578 s. `demo.py` standalone (steps 1-5): 47 PASS, 0 FAIL, exit 0, 87 s.

### Run 1 (1 Nov) vs run 2 (4 Nov)

Run 1: 69 PASS / 7 FAIL / 5 NOT RUN. What fixed each FAIL: G7-A (no audit chain on the server for a fresh project) by the T16g bootstrap loader; G7-B (CLI sync could not upload audit records, alerts swallowed) by the T16g audit batch contract and never-swallowed alerts; G7-C (no connector quarantine state) by named limit 7.7 and the two new step 7 asserts (an `audit_quarantine` row exists; `sandbox alerts` contains `audit_fork`). Three step 7 driver bugs were fixed in the 4 Nov rerun: the alert kind case (`AUDIT_FORK`), and DB access from inside the `api` container, replaced by `psql` as the compose superuser for the two server-side SELECTs, because RLS hides the rows from the app role without a tenant context.

## 3. Failures and findings

None in run 2.

### Run 1 (1 Nov 2026) failures, kept as history (not fixed in run 1; reported for the owners)

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

The driver `ee/deploy/m2_gate.py` wraps `demo._link_cli_key` to retain the keys `demo.py` generates, computes the root fingerprint from the served genesis payload, and otherwise uses the CLI and the server routes, with `--ca` for TLS and no hand-fed writes to the product's state. In steps 4 and 8 the bundles are published through carol's admin session with alice and bob as approvers (ADR 0001 Amendment A2). Step 7 drives the audit fork and truncation attack through `sandbox sync --once`, then checks `sandbox alerts` for `AUDIT_FORK`, the server `audit_quarantine` fork row and the `sync_alerts` fork and truncation rows through `psql` (compose superuser), and runs `audit verify --project` on the main chain.

Run 1 workarounds that run 2 no longer uses (T16d): no hand-fed bundle application through `verify_and_apply` for the pickup checks and no hand-written `server_time_state.json`; steps 4 and 7 go through `sandbox sync --once` (the "server_time_state.json written by sync (no hand-fed write)" check proves it). Still a driver choice, not a product default: the step 4 bundle carries `escalation_timeout_seconds: 0` so step 5 does not wait for a timeout.

## 5. Not run

None in run 2 (0 NOT RUN).

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

MUST before the gate (own tests-first item T16h, not T16g): the publish refusal in ADR 0001 Amendment A2 item 1, with the T16b fixtures moved to a third-admin publisher by node id. Gate driver step 4 and step 8: carol (org admin) publishes, alice and bob approve (ADR 0001 Amendment A2 item 4).

### 7.7 G7-C: no connector quarantine state. LOW. Named limit (founder approved, 4 Nov).

Named limit (exact wording): "Quarantine is a server-side state for forked records (`audit_quarantine`). In M2 the connector does not enter quarantine; it raises a local `audit_fork` alert and keeps enforcing locally. Device-level quarantine is M3." The `m2_gate.py` step 7 status check becomes two asserts: an `audit_quarantine` row exists, and `sandbox alerts` contains `audit_fork`. G7-A and G7-B are blockers fixed in T16g (ADR 0001 Amendment A3).

Unsigned `high_water.json` limit (founder, 25 Oct; Low), one sentence added 4 Nov (security L, T16g review): with the bootstrap loader, a host-level writer who deletes `bundle.json` and `policy_history/` and zeroes `high_water.json` makes the connector re-apply the server's sequence 1 bundle (a rollback to the first approved bundle) instead of locking; this is the same capability the limit already grants (restoring an old `bundle.json` from `policy_history/`), and every such bundle still carries two verified CLI approvals.

