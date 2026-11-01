# T15b security review: adversarial pass over the T12c and T12d diff

Reviewer: security-engineer (leader tier). Date: 1 Nov 2026.
Scope: every product change under `src/` and `ee/src/` from the commit before T12c c1 to the head of `main` after c6 (23 files, about 5,160 added lines), plus the test-harness edits that security signed by node id (M2_BASELINE section 3, T12D_D5_SPEC section 9.4, the c6 append-only e2e and the rebuilt NF-1 file). Read-only: no product, test or doc file other than this one was changed. No commit identifiers appear in this file on purpose; history is about to be rewritten.

Inputs read first: T12C_C2, T12C_C4, T12D_D2, T12D_D3 (rounds 1-3), T12D_D4 (rounds 1-3) reviews; T12D_D5_SPEC sections 6, 8, 9; ADR 0010 s9; ADR 0011 and amendment A1; M2_BASELINE section 3.

Verdict: **CHANGES**. One HIGH in the script-binding resolver, two MEDIUM. Three items are MUST before the M2 gate (T16); the rest are SHOULD or M3 with named-limit wording.

Scanners (this review): Semgrep p/python + p/secrets on the 23 changed product files: 0 findings. gitleaks dir on `src` and `ee/src`: no leaks (the git-range run could not execute on this Windows checkout; dir mode covers the same bytes). trivy fs secret+misconfig on `src` and `ee/src`: clean. Frozen manifest checked against committed LF bytes of every listed file: only the three pre-existing named exceptions differ; no unsigned edit to a frozen file.

Severity scale: CRITICAL / HIGH / MEDIUM / LOW / INFO. "Gate" = MUST before T16. "SHOULD" = land before T16 if cheap, otherwise M3. "M3" = recorded with a named limit now.

## Findings

### T15b-1 HIGH (Gate): the resolver accepts a workspace file as the interpreter in word 0

File: `src/sandbox/connector/script_pin.py`, `resolve` with `_match_interpreter`.

Word 0 is matched on its base name only. `_base_name` lower-cases the last path segment; the full `word` argument to `_match_interpreter` is unused, and `_is_abs_path` is defined but never called. The resolver therefore reports `binding="bound"` for `tools/python deploy.py`, `./python deploy.py`, `.venv/bin/python deploy.py` and `tools\python.exe deploy.py`, treating each as "python running deploy.py". Behavioural probe in a temp root confirmed all four return `binding="bound"`, `script.rel="deploy.py"`.

Why it matters: S-L3 states the interpreter binary is explicitly not content-bound. The design assumes word 0 is a trusted interpreter resolved off the machine and that only the operand is pinned, hashed and shown. When word 0 is a relative path, the "interpreter" is a file inside the tree, which the agent can author. The broker pins and hashes only the operand, resolves the recorded bash/pwsh, and runs the command through it with `shell=False`; it never resolves or pins word 0. So a command can point at a benign pinned operand while word 0 names an unreviewed in-tree file, and the hook still returns `bound` rather than `SCRIPT_UNPINNABLE`. Under the enrolled/dual floor it escalates and can be approved, with the reviewer shown only the benign operand body. That defeats the T12c property that an approved shell escalation runs only reviewed bytes.

`resolve_shell` validates that the recorded shell (bash/pwsh) is absolute, regular, outside root and not a reparse point. Word 0 of the command gets none of that scrutiny.

Fix (Gate): in `resolve`, treat word 0 as an interpreter only when it is a bare base name (no `/` or `\\`) or an absolute path. A relative path containing a separator returns `binding="unbound"` with a new reason `relative_interpreter`. An absolute path that resolves under root returns `unbound` with `interpreter_under_root`, for the same reason the operand may not be under `.sandbox` or key home. The existing `direct_exec` reason covers `./x.sh`; this closes the interpreter slot it does not reach.

Tests qa writes first (strict xfail until the fix): resolver unit tests that `tools/python deploy.py`, `./python deploy.py`, `.venv/bin/python deploy.py` and `tools\python.exe deploy.py` each return `unbound` with the new reason; a positive twin that bare `python deploy.py` and an absolute interpreter outside root stay `bound`; one broker-level test that a bound record whose word 0 is a relative path is refused, not executed.

### T15b-2 MEDIUM (Gate): approve/deny CLI and connector sync still use raw urlopen with a forwarded Authorization header

This is the d3 round-3 item the task names (`T12D_D3_SECURITY_REVIEW.md` round 3, ruling 2).

File: `src/sandbox/cli/sync_cmds.py`. Six call sites send a Bearer token through `urllib.request.urlopen` with the token in `headers["Authorization"]` (a redirectable header, not an unredirected one) and with no `_check_transport_safety` call: `_get_signer_token`, `_fetch_escalation`, `_fetch_decisions`, `_refresh_registry_chain`, `_post_approval`, and the device-token path via `request_token`/`_get_token`. `signer approve`, `signer deny` and every `sync` cycle use these.

Two gaps:
1. No scheme check. These accept a plain `http://` server to a non-loopback host, so the signer and device Bearer tokens travel in clear text. The `signer link`, `genesis` and `sign-registry` paths were hardened in d3 with `_check_transport_safety`; approve/deny/sync were left on the old path.
2. The token sits in a redirectable header. The module installs `_NoRedirectHandler` globally, so a 3xx now raises instead of being followed; that is the mitigation d3 relied on. But it is a single global guard in front of header-leaking call sites, and the `_safe_urlopen` belt-and-suspenders checks (final-URL compare, 3xx status) live only in the `_signer_safe_*` helpers, not in these six raw calls. If any imported module reinstalls a default opener, these six would forward the header; the hardened paths would stay safe because they also use `add_unredirected_header`.

The legacy helpers `_signer_http_get` and `_signer_http_post` remain dead code (no callers across `src`, `tests`, `ee`). They are the header-forwarding pattern in reusable shape.

Fix (Gate): route the signer-token fetch and the approve/deny POST through `_signer_safe_get`/`_signer_safe_post` (https-except-loopback, no redirect, `add_unredirected_header`, timeouts already present). For the device-token `sync` path add `_check_transport_safety` on the resolved server URL at the top of `run_once`, and move `_fetch_escalation`, `_fetch_decisions` and `_refresh_registry_chain` behind the same no-redirect, unredirected-header transport; the connector daemon `src/sandbox/connector/sync/process.py::_connect` also uses `urllib`, so give it the same scheme and redirect checks. Delete `_signer_http_get` and `_signer_http_post`. `enroll(..., ca=)` exposes a `--ca` flag that is never used (`sync_cmds.py` enroll, `connector/sync/enroll.py`); wire it into an SSL context or drop the option so no operator believes a private CA is pinned.

Why MEDIUM not HIGH: the global no-redirect opener and the loopback-only demo mean no leak is reachable today through shipped flows. This brings token transport up to the rule the rest of the signer CLI already meets and removes the standing exception.

Tests qa writes first: approve/deny against a local server that answers 302 exit non-zero and POST nothing; approve/deny/sync against a non-loopback `http://` URL refuse before any socket; `_signer_http_get`/`_signer_http_post` no longer exist (AST or import check).

### T15b-3 MEDIUM (M3, named limit or fix now): the genesis route checks the admin role without org scope and does not require link kind cli

This is F-2 from `T12D_D5_SPEC.md` section 6.

File: `ee/src/agg_cp/sync/signer.py`, `genesis_route` step 3. The admin check is `SELECT 1 FROM role_bindings WHERE org_id = %s AND user_id = %s AND role = 'admin' LIMIT 1` with no `scope_type = 'org'`. Project-scoped admin bindings exist here: `ee/src/agg_cp/api.py` grants and reads `scope_type = 'project' AND role = 'admin'`. So a user who administers one project in the org, but is not an org admin, passes the genesis admin check and can create the org registry root (v1), choosing its one key and the approver roles, given a genesis code and a pending link. The v2+ path (`registry_identity` rule 8) correctly scopes the admin check to org level; genesis does not. Step 3b checks the token key is the user's pending link but does not assert the link's `kind = 'cli'`, so a browser-kind link can seed the genesis admin key, against A1.3.

`check_registry_identity` rule 8 is the model to match. verify_chain enforces genesis admins are a signing kind with the admin role, but "kind" there is the registry entry kind, not the enrollment `signer_links.kind`.

Decision: F-2 is a real scope-escalation on the genesis authority and is not a d5 change. Preferred fix (small, tightening only): add `AND scope_type = 'org' AND scope_id = %s` to the genesis step-3 admin query and add a step-3b check that the link row `kind = 'cli'` (else `pending_link_required`). If the founder defers, named limit for ADR 0011 s2 / G-L6, exact wording:

> G-L6 (genesis admin scope). The genesis route accepts any `admin` role binding in the org, project-scoped included, and any link kind. A user who administers one project, holds a genesis code and has a pending link can create the org registry root. Until this is fixed, the genesis code (host-access bootstrap, G-L2) is the control that gates who reaches genesis, not the admin scope. No demo, pitch or doc may claim org-admin-only genesis before then.

Recommendation: fix now; three SQL clauses, matches rule 8.

Tests qa writes first: a project-scope admin (not org admin) with a genesis code and a pending CLI link is refused `admin_required`; an org-scope admin accepted (twin); a genesis attempt whose link `kind='browser'` is refused.

### T15b-4 LOW (M3, named limit): link and browser enrollment take a public key with no proof of possession

This is F-1 from `T12D_D5_SPEC.md` section 6, already recorded there and in ADR 0011 A1.1 rule 7.

`POST /api/v1/sync/signer/link` and `link_browser_key` (`ee/src/agg_cp/web/browser_keys.py`) store `public_key` and `key_id` with the check `key_id == sha256(public_key)` but no signature proving the caller holds the private key. A1.1 rule 1 and R-5 make this fail closed for binding a registry key (a key_id pending-linked by two users is refused `unknown_key`), so it cannot forge dual control. Residual: a user who learns another user's public key can create a pending link for it and block that user's own enrollment of the same key (bounded, self-healing: the victim re-links a fresh key).

Decision: keep the existing named limit; no M2 change. Confirm the wording stays in ADR 0011 A1.1 rule 7 ("Proof of possession on `/link` (F-1) removes this in M3 or T15b"). T15b does not fix it; the enrollment denial is bounded. M3: the link/enroll body is signed by the enrolling key over the code, verified before the row is written.

### T15b-5 LOW (SHOULD, d5 S5 carried): step-7 consume UPDATE does not check rowcount

This is S5 from `T12D_D5_SPEC.md` section 9.1.

File: `ee/src/agg_cp/sync/signer.py`, signatures route step 7. For each added key it runs an `UPDATE signer_links SET status='consumed' WHERE org_id=.. AND key_id=.. AND user_id=.. AND status='pending' AND used_at IS NOT NULL AND public_key IS NOT NULL` without asserting `rowcount == 1`. Under the per-org registry advisory lock the only way to touch 0 rows is an operator `DELETE` on `signer_links` between the identity check (rule 2 reads the row) and step 7. Today the version would still store with no consumed row, but A1.1 rule 1 only matches `status='pending'` links and the key is then in vN, so it is no longer "added" and cannot be re-matched; the invariant is held by the lock plus the added-means-not-in-prev rule, not by the UPDATE. Making it explicit removes the reliance on that reasoning.

Fix (SHOULD): if `rowcount != 1` for any added key, roll back the version, commit a `registry_identity_refused` audit row with reason `link_consume_rowcount`, return 400. Fail closed.

Tests qa writes first: with the link row removed under the lock, the post is refused and no version row is written; the honest path consumes exactly one row per added key.

### T15b-6 INFO (no change): verify_chain freezing of carried identity fields vs the connector

This is the d3 round-1 F5 recommendation carried to T15b.

A1.1 rule 9 (`ee/src/agg_cp/sync/registry_identity.py`) freezes `user_id`, `iss`, `sub`, `public_key` and `kind` of a carried key_id server-side; any change is `identity_changed`, nothing stored. Question: should the connector's `verify_chain` (`src/sandbox/protocol/registry.py`) also freeze them, so a connector reading a chain from a compromised server does not accept a relabelled carried key?

Finding: not required for M2. The connector counts dual eligibility by distinct `user_id` (`_distinct_signer_users`), and `_validate_key_entries` now rejects a non-string or empty `user_id`, a `connector:` prefix, and any `key_id != sha256(public_key)` on every version. So a compromised server cannot relabel a carried key's `public_key` without changing its `key_id`, and cannot inject a blank or typed `user_id`. It can relabel the `user_id`/`iss`/`sub` text of a carried key, but that sits inside G-L5 part 1 (an accepted M2 limit: a compromised server can mint dual-eligible keys post-genesis, and the root fingerprint does not help). The server-side rule 9 is the authoritative gate, and the connector already refuses the forgeable fields. Adding per-key carried-field freezing to `verify_chain` is clean M3 defence in depth (track under G-L5); it changes no M2 property and would touch a frozen TCB file, so it needs its own tests-first cycle if the founder wants it in M2.

## Attacker-model passes

### Malicious server against the connector
- Registry: `apply_registry_chain` verifies against the pinned root, refuses below `max(local, high_water)`, refuses a missing/corrupt `high_water.json`, never rewrites it, refuses same-version-different-bytes, writes atomically. The verify-failed branch guards `isinstance(last, dict)`/`isinstance(p, dict)` (d5 M3), so a hostile last envelope with a non-dict payload returns `refused:verify_failed` rather than raising out of `run_once`. Fail-closed holds.
- Escalation detail / decisions: `_rebuild_envelope` fixes the envelope kind in code and ignores the server `user_id` column; `apply_external` recomputes the binding fingerprint and refuses on mismatch, refuses non-empty `script_unbound`, and refuses a script whose preview was not shown. T15b-1 is the gap: a `bound` record whose word 0 is an agent file passes these because the resolver mislabels it.
- Bundles/evidence: unchanged in this diff beyond the registry/approval path; the bundle-signer pin (A1.1 rule 8) is enforced server-side for v2+.
- Approval replay/binding: unchanged from T12b (nonce, not_after, registry-version binding); the new signed fields `script_rel`/`script_sha256`/`preview_sha256` are inside the fingerprint and re-checked by `apply_external` and the server M4 equality check.

### Malicious org admin against the server
- Genesis authority: T15b-3 (project-scope admin reaches genesis). Fix or name-limit.
- v2+ identity binding: `check_registry_identity` enforces rules 1-10, the bundle-signer pin, cross-org refusal, org-scope admin role and carried-field freeze; refusals roll back and audit; counting is by distinct `users.id`. G-L5 part 2 (an admin who can mint a second IdP identity holds both seats) stays the named limit; correct.
- One admin, two keys: closed server-side by rule 1 + R-5 and by distinct-user counting; the connector pin tests guard the counting path.

### Same-OS-user against the broker (ADR 0012 scope)
- Windows: the pin holds the file and its directories open with write/delete sharing denied; a same-user swap after the pin is refused. POSIX: the after-run re-hash sets `script_changed_during_run` but cannot stop the run (S-L4). Both are the accepted M2 limit; ADR 0012 (broker OS identity) is the M3 candidate. No regression.
- The broker runs `shell=False` with the recorded shell only; `shell=True` is gone from both broker paths (NF-1), confirmed by grep and the c6 tests.
- T15b-1 is agent-reachable through the normal hook/approve flow, not only by a separate OS process, so it is a product bug, not an ADR 0012 limit.

### TOCTOU on script pins and approvals
- Hook-to-broker: the broker re-resolves and re-pins from the open handle and compares sha256 and size against the record; a change is `SCRIPT_CHANGED` (the c6 e2e proves the swap is refused with a signed done-record). The re-resolve compares only `rel` between record and re-resolution; sha256+size via the pin is the real gate, so this is sufficient, but a future change to the pin must keep the hash check. Noted, no action.
- Registry: the per-org advisory lock plus `UNIQUE (org_id, version)` serialise concurrent posts; the loser pre-verifies against the longer chain and 400s. Enrollment tables are intentionally unlocked; the consume UPDATE re-asserts `status='pending' AND user_id` — T15b-5 would make the rowcount explicit.

### Token and link-code handling
- Signer/device tokens: T15b-2 (raw urlopen on approve/deny/sync). Otherwise tokens never appear in argv, URLs, logs or exception text; `_get_link_signer_token` classifies failures on the cause type only.
- Link/genesis codes: consumed once (SECURITY DEFINER `signer_link_consume`, `FOR UPDATE` on genesis codes), 5-attempt cap, expiry, sha256 at rest. F11 (codes in argv) is the accepted LOW; `-`/stdin is available. The `/auth/setup` purpose filter keeps the admin-bootstrap consume from eating the genesis code.

### Log and audit leakage
- Server bodies and `admin_audit` rows carry key ids, user ids, roles, kind, sha256, version — never public_key, iss, sub, tokens or codes (confirmed against the d5 route and the refusal branches). The step-4 pre-verify keeps the older `str(exc)` body, which carries key ids and expected kids only.
- `migrate.py` prints only event/reason or the public bundle-signer key material; never the seed, path or exception.
- CLI preview/panel: `_display_script_panel` and `_check_body_hash` refuse control characters in `script.rel` and the body and refuse a body-hash mismatch before signing; the local approve path got the same checks (`connector_cmds.py`). S-L6 (the human signs the scrubbed preview hash, not the raw hash) stays the named limit.

## MUST before the M2 gate (T16), by file and node id

Backend/connector (`backend-engineer`):
1. T15b-1 `src/sandbox/connector/script_pin.py::resolve` (+ `_match_interpreter`): refuse a relative-path or under-root interpreter as word 0; new reasons `relative_interpreter`, `interpreter_under_root`. TCB change — security re-reviews the closure at leader tier.
2. T15b-2 `src/sandbox/cli/sync_cmds.py`: route `_get_signer_token`, `_fetch_escalation`, `_fetch_decisions`, `_refresh_registry_chain`, `_post_approval` and the device-token path through the `_signer_safe_*`/`_check_transport_safety` transport; delete `_signer_http_get` and `_signer_http_post`; fold `src/sandbox/connector/sync/process.py::_connect` into the same scheme+no-redirect rule or add the checks there; wire or drop `--ca` in `sync_cmds.py` enroll and `connector/sync/enroll.py`.
3. T15b-3 `ee/src/agg_cp/sync/signer.py::genesis_route` step 3/3b: scope the admin check to `scope_type='org'` and require link `kind='cli'` — unless the founder takes the G-L6 named limit instead.

SHOULD (land with the MUST set if cheap, else M3):
4. T15b-5 `ee/src/agg_cp/sync/signer.py` signatures route step 7: assert `rowcount == 1` per consumed link; refuse and audit otherwise.

M3 with named limits recorded now (ADR 0011 / HANDOFF):
5. T15b-4 (F-1) proof of possession on link/browser enrollment — keep A1.1 rule 7 wording.
6. T15b-6 connector-side carried-field freeze in `verify_chain` — track under G-L5; INFO, no M2 change.

## Tests qa writes first, per MUST item (strict xfail until the build lands)

- T15b-1: `tests/security/test_m2_script_binding.py` (or a new T15b file): `tools/python deploy.py`, `./python deploy.py`, `.venv/bin/python deploy.py`, `tools\python.exe deploy.py` each resolve `unbound` with the new reason; bare `python deploy.py` and an absolute interpreter outside root stay `bound` (positive twin); a broker test that a bound record whose word 0 is a relative path is refused, not executed.
- T15b-2: `tests/security/test_m2_t12d_signer_cli.py` or `tests/unit/test_cli_connector.py`: approve/deny against a 302 server exit non-zero and POST nothing; approve/deny/sync against a non-loopback `http://` refuse before any socket; `_signer_http_get`/`_signer_http_post` are gone (import/AST check).
- T15b-3: `ee/tests/test_m2_t12d_genesis.py`: a project-scope admin with a genesis code and a CLI link is refused `admin_required`; an org-scope admin accepted (twin); a `kind='browser'` link at genesis refused.
- T15b-5: `ee/tests/test_m2_t12d_identity.py`: a step-7 consume that would touch 0 rows rolls back the version with a `link_consume_rowcount` audit row; the honest path consumes exactly one row per added key.

End of T15b.

## Re-review 1 Nov (fixes)

Reviewer: security-engineer (leader tier). Scope: the uncommitted diff (`script_pin.py`, `sync_cmds.py`, `sync/process.py`, `sync/enroll.py`, `ee/.../signer.py`) plus `tests/security/test_m2_t15b_transport.py`, `ee/tests/test_m2_t15b_consume.py` and the T15b additions to `test_m2_script_binding.py` and `test_m2_t12d_genesis.py`. Read-only; no code touched. Scanners: Semgrep `p/python` + `p/secrets` on the five product files = 0 findings (exit 0); gitleaks 8.30.1 `dir` over the diff and the untracked files = no leaks (history scan already clean). Full-suite counts are the orchestrator's; this verdict assumes they are green.

Verdict: **CHANGES**, two small MUST items with pre-approved text. No further leader round is needed if the diffs match the text below; a worker-tier check of the tests is enough.

### Per item

- **T15b-1 (HIGH): fixed, with one residue.** `resolve` now refuses a separator-bearing word 0 that is not absolute (`relative_interpreter`) and an absolute word 0 under root (`interpreter_under_root`), before the family switch; `Path.resolve()` follows symlinks and junctions, so an outside-root link into the tree is caught. `hook_eval.py:979` denies any `unbound` under the floor, so the new reasons surface as `SCRIPT_UNPINNABLE` (`test_t15b1_floor_in_tree_interpreter_denied_script_unpinnable`); `approval.py:712` refuses a non-empty `script_unbound` at broker re-resolve (`test_t15b1_broker_refuses_bound_record_with_relative_interpreter`). Probe (temp root on E:): `tools/python`, `./python`, `tools\python.exe` (Bash and PowerShell), absolute-under-root all `unbound`; bare `python` and `C:\Windows\System32\cmd.exe` behave as before; UNC `\\srv\share\python.exe` is refused as `relative_interpreter` (fail closed; reason name imprecise but acceptable).
  **Residue (MUST-1):** `_is_abs_path` accepts a drive-relative Windows path. `E:tools\python.exe deploy.py` passes the check, and `Path("E:tools\\python.exe").resolve()` is resolved against the resolver process's per-drive cwd, not `exec_cwd`. Measured: with the process cwd inside root the result is `unbound interpreter_under_root`; with the process cwd elsewhere on the same drive it is `bound`. pwsh spawned by the broker with `cwd=exec_cwd` resolves the same word against `exec_cwd`, so it runs the in-tree file. Narrow (Windows, drive-relative syntax, broker or MCP process started outside root) but it is a TCB fail-open, and the fix is one condition.
- **T15b-2 (MEDIUM): fixed.** `_get_signer_token`, `_fetch_escalation`, `_upload_escalation`, `_fetch_decisions`, `_refresh_registry_chain`, `_post_approval` all go through `_signer_safe_get/_post` (scheme check, `add_unredirected_header`, no-redirect opener, status and final-URL checks); `_check_transport_safety` runs at the top of `run_once` (before `_get_token` -> `request_token`) and before the token fetch in approve/deny; `_signer_http_get/_post` are gone (AST test). `process.py::_default_connect` has its own `_check_url_transport`, unredirected Bearer, private no-redirect opener and final-URL compare, so it does not depend on the global opener. The catch-alls in `_fetch_decisions`, `_refresh_registry_chain` and `_upload_escalation` swallow a redirect refusal, but nothing was forwarded, so that is availability only.
  **Residue (MUST-2):** the `enroll` click command calls `connector/sync/enroll.py::enroll`, which still uses raw `urlopen` (no scheme check, default redirect following, no timeout) and sends the one-time enrollment code in the body. `sandbox enroll --server http://remote` puts the bootstrap secret on the wire in clear; ADR 0001 (line 182) says HTTPS only. No Bearer is involved, so the forwarding issue does not apply, but fail-closed transport must cover the bootstrap secret too.
- **T15b-3 (MEDIUM): fixed.** Step 3 is `role='admin' AND scope_type='org' AND scope_id=<org>` (the registry_identity rule-8 clauses); step 3b requires `kind='cli'`. Both 400 shapes unchanged; tests assert 400 for a project-scope admin and for a browser link, with a passing org-admin/CLI twin. **G-L6 is not needed.** ADR 0011 keeps its org-admin-only genesis claim.
- **T15b-5 (LOW, SHOULD): done.** Step 7 checks `rowcount == 1` per added key, rolls back, re-sets `app.org_id`, writes `registry_identity_refused` with reason `link_consume_rowcount`, commits, returns 400 `identity_unbound`. Same shape as the step-6 refusal. The race test is accepted by node id as previously ruled.

### MUST before commit (by file and node id)

1. `src/sandbox/connector/script_pin.py::_is_abs_path`: the Windows branch must require a separator after the colon. Pre-approved text: `if len(word) >= 3 and word[0].isalpha() and word[1] == ':' and word[2] in ('\\', '/'): return True`. `_is_abs_path` has one caller (the new check in `resolve`), so the effect is exactly: drive-relative word 0 -> `relative_interpreter`, and no remaining dependence on the resolver process cwd for absolute paths. Test (qa): add `<drive>tools\python.exe deploy.py` (drive letter of the tmp root) to `test_t15b1_relative_interpreter_unbound`, run under `monkeypatch.chdir` to a directory outside root on the same drive; expect `unbound relative_interpreter`.
2. `src/sandbox/cli/sync_cmds.py::enroll`: call `_check_transport_safety(server)` before `_enroll(...)`. Test (qa): `sandbox enroll --server http://cp.example --code x --expect-fingerprint y` exits non-zero with the refusal message and opens no socket (same harness as `test_t15b2_http_non_loopback_refused_before_socket`); a loopback `http://127.0.0.1` twin still reaches `_enroll`.

### Ruling on `--ca`

Dropping `--ca` from `sandbox enroll` is **accepted for M2**. An unwired flag is a false claim to the operator; removing it is tightening. The builder's stated reason is not correct as written (`build_opener(HTTPSHandler(context=ctx), _NoRedirect)` keeps the no-redirect handler), but that does not change the decision; wiring and testing private-CA pinning is M3 work. The M1 demo's `ee/deploy/demo.py --ca` is a different program and is unchanged. lead-architect: amend ADR 0001 lines 112 and 182 (`[--ca FILE]`, "`--ca` pins a private CA") and `M2_PLAN.md` lines 36 and 93 with this named limit, exact wording:

> C-L1 (private CA, M2). `sandbox enroll` has no `--ca` option and the connector does not pin a CA. TLS is verified against the operating-system trust store through Python's default SSL context, which also honours `SSL_CERT_FILE`. An operator running the control plane under a private CA must install that CA in the OS store of every connector host or set `SSL_CERT_FILE` for the connector process. Pinning (a per-server CA or key pin, so that a mis-issued public certificate cannot impersonate the control plane) is M3. The M1 demo's `ee/deploy/demo.py --ca` is unrelated and unchanged.

### SHOULD / INFO (not blocking)

- ADR 0010 s9 9.1 says word 0 may be "by absolute path from any location"; the code now requires outside root. lead-architect: change to "by absolute path outside root". Add to S-L3: an absolute interpreter outside root is trusted even where the agent can write (`/tmp`, `%TEMP%`, a UNC share; probe `//srv/share/python deploy.py` is `bound`); the reviewer sees word 0 in the full command line (rule 7) and must judge it. M3 may pin the interpreter path to an allowlist.
- `connector/sync/enroll.py::enroll` and `request_token`: add `timeout=30` to `urlopen` (availability).
- `_is_transport_refusal` matches message prefixes; a wording drift turns a refusal into "escalation not found" (still no POST). Prefer a dedicated exception type in M3.
- Stale comments say "strict xfail": `ee/tests/test_m2_t15b_consume.py` module docstring, `tests/security/test_m2_script_binding.py:2240`, the T15b block header in `ee/tests/test_m2_t12d_genesis.py`. Fix in the same commit.

### T16

T16 may start once MUST-1 and MUST-2 are in the tree with their tests green. Both are additive refusals on surfaces T16 exercises (`sandbox enroll`, the resolver), so T16 work can begin in parallel and must rebase onto them before its own gate.
