# T12c c3 security review (worker tier)

Reviewer: security-engineer (Opus 4.6 W). Date: 28 Oct 2026. Scope: sync_cmds.py, connector_cmds.py, test_m2_t12c_c3.py, test_m2_t12b2_review3.py, test_m2_t12b2_review4.py (uncommitted tree at c51d0f0).

## Verdict: CHANGES

### Findings

**R1 (HIGH) script.rel and preview body not in `_check_display_safety`.**
File: `src/sandbox/cli/sync_cmds.py:599-610`. The S2 control-char check covers 11 fields but not `script.rel` or `script_preview.text`. A compromised server can inject bidi controls in `script.rel`, displaying a misleading filename that the signer then approves. ADR 0010 s7 requires refusal on approve. Fix: add `"Script file": rel` (and optionally body text) to the `_check_display_safety` dict, or call it separately in `_display_script_panel` before rendering.

**R2 (MEDIUM) connector_cmds local path has no control-char check.**
File: `src/sandbox/cli/connector_cmds.py:470-500`. `_display_local_script_panel` renders `script.rel` and preview body without any control-char check. The hook refuses controls at write time, but hand-edited records bypass that. Fix: import or duplicate `_has_control_chars` and refuse before `approve()`.

### Test classification (14 tests)

**Behavioural (3):** `test_upload_body_includes_script_metadata`, `test_upload_body_includes_unbound_metadata`, `test_sync_upload_carries_script_in_body`.

**Source-inspection only (11):** `test_signer_approve_shows_script_rel_and_sha256`, `test_signer_approve_shows_body_with_line_numbers`, `test_signer_approve_shows_content_not_bound_for_unbound`, `test_signer_approve_refuses_on_body_hash_mismatch`, `test_signer_approve_refuses_on_preview_sha256_mismatch`, `test_build_and_sign_envelope_includes_script_fields`, `test_local_approve_shows_script_panel`, `test_local_approve_runs_body_hash_check`, `test_signer_approve_bound_script_shows_body_and_signs`, `test_signer_approve_tampered_body_exits_nonzero`, `test_signer_approve_unbound_shows_warning`. Each uses `inspect.getsource` and pattern-matches strings. Not acceptable as a gate. Replacement: use CliRunner with a mocked HTTP layer (signer) or mocked `EscalationQueue` (local), real records with script fields, assert on `result.output` content and `result.exit_code`; for hash mismatch, supply a record whose `script_preview.sha256` differs from `sha256(text)` and assert exit_code != 0.

### Test-setup edit sign-offs

- `test_m2_t12b2_review3.py::test_f1_signer_approve_checks_every_displayed_field`: APPROVED. Adds fp_v=2, script=None, script_unbound="", script_preview=None to fixture. No assertions changed.
- `test_m2_t12b2_review4.py::test_f8_signer_approve_shows_kind_tool_bundle_sequence`: APPROVED. Same fields. No assertions changed.
- `test_m2_t12b2_review4.py::test_guard_signer_approve_refuses_fingerprint_mismatch`: APPROVED. Same fields added to both `real` and `shown` dicts. No assertions changed.

### Environment note

`test_r3_done_record_carries_exec_argv` depends on `shutil.which("bash")` which resolves differently per PATH order (Git bash vs WindowsApps). Yes, the test should record its own known bash path in the session.json fixture for c6, removing the PATH dependency.

## Re-review (28 Oct 2026)

Scope: updated sync_cmds.py, connector_cmds.py, rewritten test_m2_t12c_c3.py (26 tests).

**R1: FIXED.** `_check_display_safety` now includes "Script file" (script.rel). Body text uses a separate `_check_body_display_safety` (sync_cmds.py:56-64) that allows TAB/LF/CR and refuses all other C0, DEL, C1 and bidi. Both checks run before body-hash, fingerprint and signing. Deny still allowed.

**R2: FIXED.** connector_cmds.py `_display_local_script_panel` checks rel via `_has_control_chars_local` and body via `_has_body_control_chars_local` (lines 510-525), raising SystemExit(1) before `approve()`. Pending record unchanged on disk.

**(a) Body allowance rule: CONFIRMED.** ADR 0010 s9.5 says "In the body only, tab, LF and CR are rendered as layout; the hook has already refused any other control." The implementation (`_BODY_CONTROL_CODEPOINTS = _CONTROL_CODEPOINTS - {0x09, 0x0A, 0x0D}`) matches exactly. The body is hash-bound, not field-equality bound, so layout characters do not weaken the binding.

**(b) No path signs or runs with a refused rel or body.** Signer: control-char check (line ~627-650) raises ClickException before body-hash, fingerprint and sign+post. Local: `_display_local_script_panel` raises SystemExit(1) before `_check_local_body_hash` and `approve()`. Verified by inspection and by TestR1/TestR2/TestMultilineBodyAllowed tests.

**(c) Tests: all 26 behavioural.** Zero `inspect.getsource`, zero `M2T12cC3Pending`. All use CliRunner with FakeSyncServer or real EscalationQueue records, asserting on exit_code and output. Review3/review4 setup edits: still APPROVED (no assertion changes).

### Verdict: APPROVE
