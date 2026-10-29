# T12d d3 security review -- signer CLI (link, genesis, sign-registry)

Reviewer: security-engineer (leader tier, Opus 5.5).
Scope: uncommitted d3 diff at main 1eedeb4: `src/sandbox/connector/sync/signer.py`, `src/sandbox/cli/sync_cmds.py` (lines 779-1300), `tests/security/test_m2_t12d_signer_cli.py`. Design: ADR 0011, T12B_PLAN T12d table, server side from d2 (`ee/src/agg_cp/sync/signer.py`, `registry.py`).
Verdict: **CHANGES REQUIRED** (F1 CRITICAL; F2-F6 HIGH).
Scanners on the three files: Semgrep (p/python, p/secrets) no findings; gitleaks dir no leaks; trivy fs secret scanner clean.
Measured: `tests/security/test_m2_t12d_signer_cli.py` 19 passed; with `tests/security/test_m2_script_binding.py` 95 passed, 3 skipped (the 3 skips are platform skips in script_binding: Windows symlink privilege, POSIX-only check, no 8.3 names).

## Method

Read the diff against ADR 0011 s2-s6 and the d2 server routes. Then a behavioural probe with mocked `urlopen` (scratchpad only, no product or test edits): link, genesis, and sign-registry `--in` with an attacker-made partial envelope. Probe results:
- `signer genesis --confirm-identity https://idp anything --yes` exits 0 locally. The bundle-signer key came from a mocked `/config`.
- `sign-registry --in part.json --out out.json --yes` with `/registry/latest` returning 404, `prev_hash` "bogus", envelope kind "x", a zero-filled existing signature and an unconfirmed admin key: exit 0, the diff printed "Genesis registry v2", signed, written.
- The same with `--confirm-key-id deadbeef --publish`: printed "WARNING: unconfirmed key_ids left unsigned", then signed, wrote 2 signatures and **published**.
- Every request went to `http://`, Bearer token included.

## Findings

**F1 CRITICAL -- N1 typed key_id confirmation is a no-op; the CLI signs and publishes unconfirmed keys.**
`src/sandbox/cli/sync_cmds.py:1126-1142` (co-sign) and `:1241-1251` (build).
- With no `--confirm-key-id`, no check runs at all.
- With a wrong one, it prints a warning and signs anyway. One signature covers the whole payload, so "left unsigned" is false. The output tells the human the opposite of what happened.
- In co-sign mode, "added" is every key in the payload, not the delta from the latest version.
- With `--yes`, no human check is left at all.

The file hand-off between two admins (G-L3) is exactly where a tampered `v2.json` arrives. Breaking N1 there breaks "dual control means two different humans" for registry changes.

Required fix:
- Compute added = key_ids in the new payload that are absent from the **verified** latest version (F2).
- Refuse, with a non-zero exit and nothing written or posted, unless the `--confirm-key-id` set equals the added set exactly. Every kind counts (cli and browser). An extra or missing value is a refusal.
- Check `key_id == sha256(public_key)` locally for each added key, so the typed id binds the public key.
- Remove the "left unsigned" wording.

**F2 HIGH -- co-sign mode fails open and checks no chain and no signatures.**
`sync_cmds.py:873-883` (`_signer_http_get` returns None on any error), `:1105-1156`.
- When latest is missing (the route does not exist, the server is down, or the response does not parse), the diff falls back to the genesis view and signing goes on.
- Nothing checks `version == latest+1`, `prev_hash`, `org_id` against the link org, the partial's `kind` and `sig_v`, or any existing signature.
- `kind` is overwritten with REGISTRY. Signatures from the file are copied without being verified. The own key may already be among them.
- The comment "Verify existing signatures are valid (chain check)" has no code under it.

ADR 0011 s5 requires all of this. Required fix:
- Fetch the chain (stub ruling 2) and verify it with `verify_chain`.
- Refuse on any fetch, parse or verify error.
- Check the partial chains from the verified latest.
- Verify every existing signature over `canonical_bytes(REGISTRY, payload)` with a key the rules allow.
- Refuse a wrong `kind`, a wrong `sig_v`, or the own key_id already present.

**F3 HIGH -- the bundle-signer trust root is trust-on-first-use from the same server.**
`sync_cmds.py:1003-1020`.
- Genesis reads `bundle_signer_public_key` from `link.json` (an unauthenticated local file; link never writes this field) or from `/config` with the server's own token.
- The server's R1 check compares the key against itself, so it adds nothing against a compromised server.
- Impact beyond G-L1: a compromised server gets the honest admin to sign a root that names an attacker bundle signer. The fingerprint the CLI prints covers that key, so `enroll --expect-fingerprint` passes, and the attacker signs policy bundles for every connector.
- Today G-L1 is detected because a server-made root has a different fingerprint. TOFU removes that detection.

Fix: stub ruling 1.

**F4 HIGH -- the registry admin seed is written without key-home hardening.**
`sync_cmds.py:794-806`.
- `link_dir.mkdir(...)` and `seed_path.write_bytes(...)` use default modes. On POSIX with umask 022 that means a 0755 directory and a **0644 private key** (any local user can read the org-admin registry key).
- On Windows the directory gets inherited ACLs. `_secure_new_root` is not called when this call creates the key home.
- There is no `root_exposure` check, no `O_EXCL`, and no length check on load (`:864`).
- The rest of the key home uses umask 0o077 and mode 0o700 (`keyhome.py:247-262`).

Required fix:
- Add a keyhome helper for the signer directory with the same 0o700 / `_secure_new_root` rules.
- Write the seed with `os.open(O_WRONLY|O_CREAT|O_EXCL, 0o600)`.
- On load, refuse when `root_exposure` reports exposure or the length is not 32.
- Positive: the seed is never printed or sent; only the public key and key_id leave the machine.

**F5 HIGH -- the D0-3 diff is incomplete, so identity rewrites are invisible.**
`src/sandbox/connector/sync/signer.py:126-180`.
- For an existing key, only `public_key` and `roles` changes are shown. Changes to `user_id`, `iss`, `sub`, `kind`, `alg` and `added_in` are silent, and `verify_chain` does not freeze them.
- Example: relabeling a second key of alice as `user_id=bob` makes one human count as two under D0-2. The co-signer sees nothing.
- Added keys show no `roles`, `iss` or `sub`, so the human cannot confirm who is being added (ADR 0011 s4).
- `bundle_signer` is shown by its attacker-chosen `key_id` label only. A changed `public_key` under the same label prints "X -> X".
- Unknown top-level fields are never shown.

Required fix:
- Make the diff generic: every top-level field and every key-entry field that differs is shown old -> new. Added keys print every field.
- `bundle_signer` shows `public_key`. Refuse to sign when `key_id != sha256(public_key)` for the bundle signer or any key.
- Add one test per field.
- Recommended for T15b, as an ADR question: `verify_chain` freezes `user_id`, `iss`, `sub` and `kind` of an existing key_id.

**F6 HIGH -- two QA tests were weakened without a sign-off (TEAM rule; the d1 contract "the build removes only xfail markers").**
- `test_genesis_prints_fingerprint`: HEAD ended with an unconditional `raise M2T12dPending("genesis CLI command not implemented to verify output")`. The build replaced it with `assert "--genesis-code" in help`. The CLI output is never checked.
- `test_sign_registry_checks_chain_from_latest_version`: HEAD ended with `raise M2T12dPending("sign-registry chain validation not testable yet")`. It is now `assert "--in" in help`, which passes while F2 is live.

**Sign-off refused for both.** QA (W) replaces them with CliRunner tests over a mocked `urlopen`:
- Genesis: the printed fingerprint equals `sha256(org_id:canonical(payload))` of the envelope actually posted.
- Co-sign: missing latest, bad `prev_hash`, wrong version, wrong kind, an invalid existing signature, and an own duplicate signature each exit non-zero, write no `--out` and post nothing.

Not a builder weakening, but now passing while the behaviour is broken: `test_genesis_confirm_identity_mismatch_exits_nonzero`, `test_sign_registry_unconfirmed_key_left_unsigned` and `test_confirmation_flags_name_exact_values` are help-text checks. QA adds behavioural tests for F1, F3, F4 (POSIX mode test; Windows ACL via `root_exposure`), F5, F7 and F9.

`test_genesis_user_id_is_server_id_not_sub` (now passes `user_id=`): **APPROVED**. HEAD's comment anticipated the parameter, and the assertions are kept.

**F7 MEDIUM -- token transport: http accepted, redirects forward the Bearer token.**
`sync_cmds.py:815-822, 873-900`.
- Any `http://` server is accepted, and so is any server read from `link.json`.
- `urllib` follows redirects on GET (`/config`, `/registry/latest`, `/candidates`) and copies the `Authorization` header to the new host.

Required fix:
- One shared helper. It requires https, except for loopback hosts (the compose demo).
- It uses an opener with no redirect handler and treats any 3xx as an error.
- It sets `Authorization` with `add_unredirected_header`.
- It turns `URLError` and JSON errors into `ClickException` (no tracebacks; still fail closed).

The token is never put in argv, URLs or output (confirmed). The same pattern exists in the older approve/sync paths (`:174-203`, `:293-340`), and `enroll(..., ca=)` accepts `--ca` but never uses it (`connector/sync/enroll.py:67`). Recorded for T15b; out of d3 scope.

**F8 MEDIUM -- build mode computes `prev_hash` without the org prefix.**
`sync_cmds.py:1177-1181`: `sha256(canonical(prev))`, while `registry._payload_hash` is `sha256(org_id + ":" + canonical(prev))`. Every build-mode version fails `verify_chain`. This fails closed, but d4 cannot pass. Fix: expose and use `payload_hash` from `sandbox.protocol.registry`.

**F9 MEDIUM -- the genesis identity confirmation is a tautology.**
`sync_cmds.py:975-1000`. When `link.json` has no `iss` or `sub` (always, today), they are taken from `--confirm-identity` and then compared with themselves. Only the server's step 4 check stops a wrong identity. Fix: stub ruling 3.

**F10 MEDIUM -- `sign-registry` cannot change `threshold`.**
Build mode copies `threshold`, so it stays 1 forever. "v2 and v3 signed by two admins" is then cosmetic: a single confirmed admin can publish alone. Fix: `--threshold N` in build mode, shown in the diff, with 1 <= N <= the number of distinct admin users (D0-2) checked locally.

**F11 LOW -- one-time codes in argv** (`--code`, `--genesis-code`): they land in shell history and process listings. The ADR demo uses argv, so keep it, but also accept `-` (stdin) or a prompt with `hide_input`. Document in the quickstart.

**F12 LOW -- genesis hygiene.**
- Refuse an empty `org_id` or `user_id` locally. `build_genesis` still falls back to `sub` when `user_id` is None; the CLI must never reach that path.
- Always print org, user, iss, sub, key_id, roles and bundle key_id, even with `--yes`.
- `_get_link_signer_token` swallows the error reason.
- Duplicated assertion code: use `create_signer_assertion` and `compute_key_id`.
- `expires_at` is fixed at 7 days, so the server's 72 h rule refuses genesis for an org with a prod project. Add `--expires-in`, capped locally.
- After a 200 from genesis, store the v1 envelope and the fingerprint in the signer directory (stub ruling 2 uses them).

**F13 LOW -- split key location.**
`link` writes `<key home>/signer/signer.seed`, but `signer approve` reads `<key home>/<ws_id>/*.seed` (`:449-469`). A linked key cannot approve. Pick one location (the F4 helper) before d4.

**F14 LOW -- `--admin` gives admin plus approver to every `--add` in the run.** Make roles per key, or refuse `--admin` together with more than one `--add`.

## What is signed versus what the server stores

- Both modes sign `canonical_bytes(REGISTRY, payload)` over the same dict that `compute_diff` renders, so the display and the signature agree (good).
- The CLI posts `{type: "registry", envelope, org_id}`. The server takes the token's org, runs `store_signer_signatures` and then `verify_chain`, and stores the envelope as posted.
- In co-sign mode, the posted envelope carries file signatures that were never verified, and a rewritten `kind` (F2).

## Link seed storage (`link.json`)

- **Contents:** server, key_id, org_id, user_id. No secrets: the link code is not stored, so the file cannot replay it, and the server consumes the code once (`_db_consume_signer_link`).
- **Integrity:** the file is not protected. Anyone who can write it can also read the seed, so this is acceptable once F4 lands. It must never become a source for trust roots (F3).
- **Writes:** only after a 200 response; the seed is written before the request (harmless).

## Genesis flow

- Own key only: the envelope is built from the linked seed. Good.
- A second genesis gets the server's 409 plus an alert. The CLI surfaces the 409 as an error. Good.
- Identity: F9. Trust root: F3.

## Stub rulings

1. **`/config` bundle-signer key: the CLI takes it from a flag; no `/config` route is the source.**
   - `signer genesis --bundle-signer-key <64-hex public key>`, required. The `link.json` and `/config` fallbacks are deleted.
   - The CLI computes and shows the key_id. With `--yes` the flag is itself the value-naming confirmation.
   - Out-of-band source: the migrations job (d4, `migrate.py`) prints `{"event":"bundle_signer","key_id":...,"public_key":...}` next to the `genesis_code` line, derived from `AGG_BUNDLE_SIGNER_KEY_FILE`. It is a public value, the channel and holder are the same as G-L2, and the demo parses it like `genesis_code`.
   - The server's R1 equality check stays.
   - Reason: a server-supplied trust root defeats the S2 fingerprint (F3). ADR 0011 makes host access the bootstrap authority, so the key comes from the host.
   - ADR 0011 gets a one-line amendment under s2.4 or s6.
2. **`/registry/latest`: the server grows a read route in d4, and the CLI verifies it against a pinned fingerprint.**
   - `GET /api/v1/sync/signer/registry` returns the org's full stored chain verbatim (`get_chain`). It is org-scoped (other orgs get 404) and allowed for confirmed signer tokens and, read-only, for `pending_link` tokens (carol co-signs v2 before her key is in the registry). Add it to the d2 allowlist with d2-style tests.
   - The CLI runs `verify_chain(chain, fp)`. `fp` is `--expect-fingerprint <fp>` or the root fingerprint that `signer genesis` stored locally (F12). Carol gets it out of band, as the same value every `enroll` uses.
   - Any error exits non-zero before signing. Build mode and co-sign mode both use only the verified latest.
   - Reason: ADR 0011 s5 requires a chain check. A latest that is not verified is server-trusted input to a signature. A full chain, not latest only, is what `verify_chain` needs.
3. **iss/sub: the server's link response grows them (d4, `POST /api/v1/sync/signer/link`).**
   - It returns `iss` and `sub` of the link's user (the same OIDC identity genesis step 4 checks). The CLI stores them in `link.json` and always shows org, user_id, iss and sub.
   - `--confirm-identity <iss> <sub>` must equal the stored values. If `link.json` lacks them, refuse and tell the operator to re-link. The flag is never the source.
   - Until the server change lands, genesis refuses instead of self-confirming.
   - Reason: ADR 0011 s4 says the identity fields come from the server's report and the admin confirms them. Returning the code holder's own identity discloses nothing new.

## Required before commit

- F1-F6 and F8-F10 fixed in d3. F7 fixed for the new commands.
- The stub rulings: the CLI half in d3, the server half (migrate line, registry read route, link response) in d4 with tests.
- QA's behavioural tests per F6.
- Re-review at worker tier against this list, by node id.
- F11-F14 may land in d3 or be recorded in HANDOFF as d4 items.

## Round 2 (29 Oct 2026)

Reviewer: security-engineer (leader tier, Opus 5.5). Scope: the uncommitted tree after the backend rewrite (`sync_cmds.py` from line 779, `compute_diff`) and the qa rewrite of the test file. Read-only on code and tests.
Verdict: **CHANGES REQUIRED** (two HIGH, one MEDIUM; the rest LOW).
Scanners on the three files: Semgrep (p/python, p/secrets) 0 findings; gitleaks dir no leaks; trivy fs secret clean.

### Closed in code
- F1: both modes compare the typed set with the added set and check `sha256(public_key) == key_id` per added key (`:1426-1446`, `:1542-1562`). Residual R2-4.
- F2: `verify_chain(chain, fp)` against `--expect-fingerprint` runs before any use; any fetch, parse or verify error exits 1; kind, sig_v, version, org_id and prev_hash are checked against the verified latest; every existing signature is verified; own duplicate refused; kind no longer overwritten. Residual R2-5.
- F3: `--bundle-signer-key` required, no `/config` call anywhere in the file.
- F5: generic top-level and per-field key diff, bundle_signer shows public_key (server `verify_chain` also checks the bundle_signer key_id, `registry.py:343`).
- F6: the two weakened tests are behavioural now; the removed `test_genesis_confirm_identity_mismatch_exits_nonzero` was a help-text check and is superseded by `test_f9_genesis_refuses_identity_mismatch`. Kept HEAD tests are byte-identical apart from the removed xfail markers. `_detect_unknown_option` cannot mask: it raises M2T12dPending with no xfail marker left, so the test fails.
- F8: `_payload_hash`; `test_f8_build_mode_passes_verify_chain` runs the real `verify_chain`.
- F9: iss/sub only from `link.json` (server response); the flag is only compared.
- F7 loopback detection: exact hostname match (`localhost`, `127.0.0.1`, `::1`); `localhost.evil.com` and `127.0.0.1@evil.com` are refused. The userinfo/backslash parser differentials (`evil.com\@127.0.0.1`) pass the check but fail at getaddrinfo (probed), so no bypass. Authorization uses `add_unredirected_header` and is not forwarded (probed with a real local 302).

### Open
**R2-1 HIGH -- Windows seed write is text mode** (`sync_cmds.py:906-917`). `os.open` without `O_BINARY` turns each 0x0A into CRLF. Probed: a 32-byte seed with one 0x0A is 33 bytes on disk and `_load_seed_checked` refuses it. About 12 % of Windows links (1-(255/256)^32) leave a key the server has as a pending link and no later command can load. Fix: `flags |= getattr(os, "O_BINARY", 0)`; also call `root_exposure(link_dir)` before writing a new seed (a pre-existing, non-fresh `signer/` dir with a broad ACL gets the seed written, then every load refuses). Test (Windows): link with `SigningKey.generate` patched to a seed holding 0x0A, then genesis loads it.

**R2-2 HIGH -- 23 of 49 tests fail on Linux** (ubuntu CI is in `tests.yml`). Run in the `ee-test` container, umask 022: 23 failed, 26 passed. `_make_key_home` and the inline fixtures `mkdir` the signer dir 0755, so the product correctly refuses with "key home exposure" and every positive control exits 1. Some refusal tests pass on Linux for that wrong reason (`test_f4_seed_load_refuses_wrong_length` accepts "key"). Fix (qa, fixtures only): chmod the signer dir 0o700 and the seed 0o600; tighten each refusal assertion to its own reason ("length", "redirect", "prev_hash", ...). `test_f4_seed_file_mode_posix` must assert, not skip, when link fails.

**R2-3 MEDIUM -- F7 redirects are still followed; `signer link` has no transport check.** `_safe_urlopen` (`:802`) uses the default opener, so the 3xx branch is dead code. Probed with real servers: GET and POST to A, 302 to B, both return B's JSON; the POST becomes a GET and the CLI would print "Published: version=..." while nothing was published (https->http downgrade allowed too). `test_f7_redirect_refused` mocks `urlopen` to raise a 302 HTTPError, which real urllib never does, and passes on "token" because `_get_link_signer_token` swallows the reason. `signer_link` (`:949-1000`) posts the one-time link code with plain `urlopen` to any http host. Fix: one opener built with a redirect handler that refuses every 3xx; route link through `_signer_safe_post`; test against a local `HTTPServer` that returns 302.

**R2-4 LOW -- F1 edges.** The set check runs only when keys are added, so `--confirm-key-id X` with no adds is not refused (round 1: an extra value is a refusal); make it unconditional. Build mode `--add` of a key_id already in latest appends a second entry with new roles and no typed confirmation (`:1489`); refuse it.

**R2-5 LOW -- F2 trusted set too wide** (`:1370-1384`). Existing signatures are accepted from any key in latest or in the partial, incl. non-admins and keys the partial itself adds. Use `prev_admins | cur_admins` as `verify_chain` does, and print the verified signers (key_id, user_id).

**R2-6 LOW -- F10 has no local bound** (`:1517`). Check 1 <= N <= distinct admin users. `test_f10_sign_registry_threshold_flag` pins threshold 2 with one admin; give it two admins.

**R2-7 LOW -- F12/F14 residue.** Genesis never writes `signer/root_fingerprint`, so the stored-fingerprint fallback is dead (only `--expect-fingerprint` works). The identity block prints only without `--yes`, and `--yes` without `--confirm-identity` confirms nothing: require `--confirm-identity` with `--yes`. `_get_link_signer_token` still swallows the reason. F14 not done.

### F11 and F13 deferral
Accepted for d4, as round 1 allowed. Neither weakens a product property: F11 is argv exposure of one-time codes the server consumes once; F13 fails closed (a linked key cannot approve). Conditions: both rows go in HANDOFF and the T12B_PLAN d4 table with tests, and F13 lands before the d4 exit (the d4/T16 flow needs a linked key that approves). R2-4 to R2-7 may join them in d4; R2-1 to R2-3 are fixed in d3.

### Measured
- `tests/security/test_m2_t12d_signer_cli.py`: Windows 48 passed, 1 skipped (POSIX mode test); Linux container 23 failed, 26 passed.
- Full `tests/` on Windows (.venv): 2322 passed, 7 skipped, 1 xfailed, 0 failed (the PATH-sensitive `test_r3_done_record_carries_exec_argv` passed this run).

## Round 3 (29 Oct 2026)

Reviewer: security-engineer (worker tier, Opus 4.6). Scope: closure check on R2-1, R2-2, R2-3 only; two rulings.
Verdict: **APPROVE** for d3 commit.
Measured by orchestrator: 52 passed 1 skipped (Windows), 53 passed (Linux ee-test, umask 022).

### R2-1 CLOSED
`_write_seed_excl` (sync_cmds.py:947-949) adds `O_BINARY` via `getattr`. `signer_link` (sync_cmds.py:1011-1017) calls `root_exposure(link_dir)` before writing a new seed, refusing on exposure. Test `test_r2_1_seed_with_newline_bytes_roundtrips` (test file line 2417) injects a seed with 0x0A and 0x0D, asserts 32-byte roundtrip and genesis load. Verified.

### R2-2 CLOSED
`_make_key_home` fixture (test file line 108-113) chmod's signer dir 0o700 and seed 0o600 on POSIX. Each refusal test asserts its own reason string: `test_f4_seed_load_refuses_wrong_length` asserts "length" or "32" (line 1014), not a generic keyword that exposure refusal would match. `test_f4_seed_file_mode_posix` uses `pytest.fail` on link failure (line 948-949), not skip. 53 passed on Linux confirms the fixtures are correct.

### R2-3 CLOSED
`_NoRedirectHandler.redirect_request` (sync_cmds.py:810-814) raises `HTTPError` on every 3xx. Installed globally at import (line 825-827). The `http_error_30x` aliases were correctly removed (different signature). `_safe_urlopen` adds belt-and-suspenders checks (status 300-399 and geturl mismatch). `signer_link` (line 1029) uses `_signer_safe_post`. The 307 test (`test_r2_3_redirect_307_real_server`, line 2564) uses two real `HTTPServer` instances; 307 preserves POST method and body, so if the redirect were followed the spy would see the POST with Authorization. Assertions `spy_cls.requests == []` and `spy_cls.auth_headers == []` (lines 2608-2613) prove neither body nor Authorization reached the target. The 302 test provides equivalent coverage. `test_r2_3_link_non_loopback_http_refuses` confirms transport check fires before any network call. No test edits weaken anything: the three new tests are additive, the fixture chmod is tightening.

### Ruling 1: process-wide install_opener
Acceptable for d3. Reason: (a) all 8 `urllib.request.urlopen` call sites in sync_cmds.py (lines 199, 301, 319, 332, 481, 837, 1087, 1101) benefit from the redirect refusal, including the 5 legacy approve/deny calls that use `headers["Authorization"]` instead of `add_unredirected_header`; (b) the module is a CLI entrypoint, not a library imported by other HTTP-using code; (c) a module-local opener would leave those 5 legacy calls unprotected. If sync_cmds is ever imported as a library, revisit.

### Ruling 2: legacy _signer_http_get / _signer_http_post
Currently dead code (zero callers; lines 1080-1107). The approve/deny paths use inline `urlopen` calls with `headers["Authorization"]` (lines 199, 301, 319, 332, 481). These are protected by the global opener against redirects but still use the forwarded header form. Migrate the approve/deny paths to `_signer_safe_get`/`_signer_safe_post` and delete the dead helpers in **T15b** (the transport hardening task round 1 already recorded for those paths). Not d4: d4 is registry-focused and T15b already owns the approve/sync transport scope.
