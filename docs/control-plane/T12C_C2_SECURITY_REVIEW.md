# T12c c2 security review (leader tier)

**Scope:** uncommitted diff under `src/` and `tests/` at HEAD eb50920 (branch main).
**Files:** `src/sandbox/connector/script_pin.py` (new), `broker.py`, `hook_eval.py`, `approval.py`, `install.py`, `mcp_server.py`, `src/sandbox/broker/privilege_broker.py`; 15 test files (named test-setup edits and xfail flips).
**Design authority:** ADR 0010 section 9 (9.1--9.6, C-c0-1 to C-c0-7), T12B_PLAN T12c table.
**Scanners:** Semgrep 320 rules 0 findings; gitleaks 0 findings on all changed files.
**Reviewer:** security-engineer (Opus 4.6, leader tier).
**Date:** 28 Oct 2026.

## Verdict: APPROVE

The TCB is sound: pin-and-verify from the open handle, shell=True removed from every approved-record path, recorded shells with no PATH lookup at exec, fingerprint v2 covers all new fields, refusal records are signed and chained. Six findings below, all Medium or Low; none enables a concrete content bypass.

---

## Findings

### R1 Medium -- install.py:178-183 -- WSL bash refusal bypassed by 8.3 short names

**Issue.** `_is_valid_shell` compares the candidate path to `%SystemRoot%\System32\bash.exe` (the WSL launcher) using string equality after `.lower()`. It does not resolve 8.3 short names first. If `shutil.which("bash")` returns a short-name path (e.g. `C:\WINDOW~1\System32\bash.exe`), the comparison fails, `_is_valid_shell` returns True, and `_resolve_bash` records WSL bash (via `os.path.realpath(c)`, which expands the short name *after* the check).

**Failing input.** PATH contains `C:\WINDOW~1\System32`; WSL is legacy (real file, not a reparse point).

**Impact.** The broker runs through WSL bash instead of Git Bash. WSL's filesystem semantics differ (mounts under `/mnt/`), so the script path the pin verified on the Windows filesystem may resolve differently under WSL, potentially running a different file.

**Fix.** Resolve the candidate to its long-name form before the WSL comparison:
```python
resolved_path = os.path.realpath(path).lower().replace("/", "\\")
```
and compare `resolved_path` instead of `path_lower`. Alternatively, resolve once at the top of `_is_valid_shell` and use the resolved form for every check.

---

### R2 Medium -- hook_eval.py:976 -- floor omits requires_dual check

**Issue.** The code sets `_under_floor = _is_enrolled`. ADR 0010 s9 9.3 says "The floor applies when requires_dual is true, or when the workspace is enrolled." The `requires_dual` branch is missing. In a standalone workspace with dual control (e.g. an exfil-classified command), an unbound command escalates instead of being denied. The reviewer sees "content NOT bound" but can still approve; the script is not pinned.

**Failing input.** `requires_dual=True`, workspace not enrolled, command `./deploy.sh` (direct exec, unbound). The hook escalates instead of denying.

**Impact.** Medium. In standalone dual-control without enrollment, an unbound command can run bytes that were modified between the two approvals. The command string itself is fingerprinted, but the referenced file is not. The deny message at line 989 already says "enrolled or dual-control", contradicting the code.

**Fix.** Either add `or result.requires_dual` to the floor condition, or update ADR 0010 s9 9.3 to match the code and remove "or dual-control" from the deny message. The comment at hook_eval.py:972-975 explains a rationale (standalone dual-control is local), so this may be intentional. The security leader or founder should rule which is correct.

---

### R3 Medium -- script_pin.py:1046-1061 -- backslash-to-forward-slash conversion not byte-for-byte

**Issue.** `build_shell_argv` on Windows converts every backslash to a forward slash for MSYS bash (`bash_cmd.replace('\\', '/')`). ADR 0010 s9 9.4 requires the command to reach the shell byte for byte and says "If a class of command cannot round-trip on an OS, the broker refuses that class there; it never guesses." The conversion is a guess that all backslashes are path separators. A command containing intentional backslashes (regex patterns, escape sequences in arguments) is silently modified.

**Failing input.** `python script.py "pattern\\d+"` becomes `python script.py "pattern//d+"` under MSYS bash.

**Impact.** Medium for correctness; Low for security. The pin verifies the script file hash from the handle, so the script content is unchanged. Only literal backslash characters in the *command string arguments* are affected, not in the script body. A corpus round-trip test (ADR requirement) should catch any semantic change.

**Fix.** Limit the conversion to drive-letter prefixes only (the existing regex), and do not apply the blanket `replace('\\', '/')`. Or: refuse commands whose non-drive-letter portions contain backslashes when running under MSYS bash (fail-closed, as the ADR says).

---

### R4 Low -- script_pin.py:676 -- _win_open_handle default share_delete=True

**Issue.** The default parameter `share_delete=True` means a caller who forgets `share_delete=False` gets FILE_SHARE_READ | FILE_SHARE_DELETE, allowing other processes to delete or rename the file while pinned. All three current callers (root dir, intermediate dirs, file) correctly pass `share_delete=False`, so no weakness exists today.

**Fix.** Change the default to `share_delete=False` so the secure behavior is the default.

---

### R5 Low -- script_pin.py:718-729 -- open_osfhandle / CloseHandle contract violation

**Issue.** `_win_read_from_handle` calls `msvcrt.open_osfhandle(handle, ...)`, which per CRT documentation transfers handle ownership to the CRT. Later, `pin.release()` calls `CloseHandle` on the same handle, violating the CRT contract (the handle should be closed via `_close(fd)`). This is undefined behavior. In practice, the fd is never reused and the double-close is benign, but a CRT update could change this.

**Fix.** After `_win_read_from_handle` returns, do not call `CloseHandle` on that handle. Instead, track the CRT fd in the pin and close it via `os.close(fd)` in `release()`. Or: avoid `open_osfhandle` entirely by using `ReadFile` through ctypes.

---

### R6 Low -- hook_eval.py:989-990 -- deny message says "enrolled or dual-control" but code checks only enrolled

**Issue.** A consequence of R2. The deny message mentions dual-control, but the floor condition does not check `requires_dual`. If R2 is fixed, this is moot. If R2 is intentional (standalone dual-control is not under the floor), the message should say "enrolled" only.

**Fix.** Align the message with the actual floor condition.

---

## Review by item

### 1. TCB correctness

**Pin (Windows).** `pin_script` opens root, each intermediate directory and the file with `FILE_FLAG_OPEN_REPARSE_POINT`. The file handle uses `FILE_SHARE_READ` only (no write, no delete). Attributes (nlinks, reparse flag) are read from the open handle via `GetFileInformationByHandle` (C-c0-1). Content is read from the handle. Hash is compared against the record's expected hash. Reparse points and nlinks > 1 are refused. Directories are opened without `FILE_SHARE_DELETE`, preventing renames. Correct.

**Pin (POSIX).** `O_NOFOLLOW` walk with `dir_fd` from root. `fstat` on the file fd checks regular file and nlink 1. Content is read from a `dup(fd)`. Hash verified. Correct.

**POSIX after-run check.** Re-hashes after the child exits (while the pin fd is still open), sets `script_changed_during_run` on mismatch. The S-L4 limit is correctly implemented.

**TOCTOU between hook hash and broker pin.** The broker re-hashes from the pinned handle and compares with the record's expected hash. Any modification between hook and broker is caught.

**Symlink and reparse handling.** Windows: `FILE_FLAG_OPEN_REPARSE_POINT` plus attribute check. POSIX: `O_NOFOLLOW` on every component. The resolver also walks path components checking for symlinks and reparse points (`_check_path_safety`). Correct.

**NTFS alternate streams.** `_has_ntfs_stream` detects stream names and returns unbound. The S-L7 limit documentation is correct (interpreters read the default stream).

**Re-resolve.** The broker runs the resolver again on the command. It checks that `script` is null/non-null consistently with the record, and that `rel` matches. Content changes are caught by the pin's hash check. Correct.

**SCRIPT_UNPINNABLE floor.** Enrolled workspaces deny unbound commands at the hook. `apply_external` refuses records with non-empty `script_unbound` or unshown previews. Correct (with the R2 caveat about requires_dual).

### 2. Shell parity (NF-1)

`grep -rn 'shell=True' src/sandbox/connector/ src/sandbox/broker/` returns zero matches. `shell=False` is explicit at broker.py:235 and privilege_broker.py:391 (the old path's fallback). The recorded shell path from session.json is the only shell used -- no PATH lookup at exec time (`resolve_shell` checks `session.get("shells")`). `SHELL_UNAVAILABLE` is returned when the shells field is absent or the path fails validation. `pwsh -EncodedCommand` correctly encodes UTF-16LE and base64. Correct.

### 3. Fingerprint v2

`_binding_fingerprint` in approval.py now includes `fp_v`, `script`, `script_unbound` and `preview_sha256` in the canonical JSON object (sort_keys=True, separators=(",",":")). The preview's hash is covered, not its text. `tool_name` (which determines the shell family) was already covered. A record without `fp_v` produces a different fingerprint, so `apply_external`'s recompute will not match and the approval is dropped. The broker also explicitly refuses records with `fp_v != 2` (RECORD_UNVERSIONED). Correct.

### 4. Refusal records

`_refusal_record` in broker.py builds a dict with `state="refused"`, `decision="refused"`, the reason code, and expected/actual hashes when applicable. Both `approve()` and `apply_external()` in approval.py call `queue.finish(request_id, result)` before checking `broker_state`, so the refusal is written, signed and chained in the audit. The status "refused" is returned, and a re-delivered approval gets "not_pending" (the record is already finished). Correct.

### 5. Named test-setup edits

All 15 test files add the same setup-only pattern: `"tool_name": "Bash", "fp_v": 2, "script": None, "script_unbound": "", "script_preview": None`. No assertion is relaxed. The `_create_pending_request` helper in test_m2_t12_remote.py now uses `_binding_fingerprint` instead of manual JSON construction (reducing drift risk) and accepts `fp_v=None` for old-style tests.

**test_extra3_standalone_unbound_escalates_with_warning**: assertions are strengthened (checks `"SCRIPT_UNPINNABLE" not in reason`, asserts pending records exist unconditionally, adds `"content NOT bound"` assertion).

**test_extra13_init_refuses_system32_and_windowsapps**: sets `SystemRoot=tmp_path` so the fake `tmp_path\System32\bash.exe` is the exact path install.py's refusal rule names. Assertions switch from substring (`"System32" not in path`) to exact-path comparison against a refused set. This is **stronger**: it tests the actual WSL refusal code path, not a side effect. A substring rule in install.py would over-refuse legitimate paths (e.g. a Git bash under a directory named System32); the exact-path approach matches the ADR.

**test_extra6_win_nlink_from_handle**: reorders operations so the hard link is created AFTER escalation (not before), which is the actual attack timing (C-c0-1: hard link between pre-check and open). This is **stronger**.

### 6. Hostile AppSec 10-minute read

**Windows short names (8.3).** See R1. The path comparison in `_is_valid_shell` should resolve short names first.

**Case sensitivity.** NTFS is case-insensitive. The resolver and pin use `Path.resolve()` and string comparison. A case mismatch between hook and broker (e.g. `Deploy.py` vs `deploy.py`) would cause a false-positive refusal (fail-safe), not a bypass.

**Long paths (>260 chars).** `CreateFileW` without `\\?\` prefix may fail on very long paths. The error is caught and results in a refusal (fail-closed). Not a bypass.

**UNC paths.** `_check_path_safety` checks `resolved.relative_to(root_resolved)`. A UNC path would fail this check and return "outside_root". Not a bypass.

**Environment.** `PrivilegeBroker._clean_env()` provides the clean environment. The broker passes only `SANDBOX_KEY_HOME` from `os.environ`. The subprocess runs with `env=clean_env`. Correct.

**cwd.** The subprocess runs with `cwd=exec_cwd`, which is from the record (covered by the fingerprint). Cannot be changed without breaking the fingerprint.

**$0 meaning.** The command is passed to `bash -c`, so `$0` is "bash" (standard bash -c behavior). For python, `sys.argv[0]` is set from the command line, which is not rewritten. `__file__` is set by the interpreter. The test `test_extra4_meaning_kept` verifies this.

---

## Re-review (28 Oct 2026)

Builder fixes for R1--R6. Re-reviewed the same five files plus `tests/unit/test_environment_classification.py`.

### R1 FIXED -- install.py:159-163

`_is_valid_shell` now calls `os.path.realpath(path)` before the WSL/WindowsApps comparison, and likewise resolves `SystemRoot` and `LOCALAPPDATA` via `realpath`. The resolved string is lowered and backslash-normalised. Test `test_r1_shortname_system32_bash_refused` uses `GetShortPathNameW` to obtain the actual 8.3 alias, skips cleanly when the volume has no short names.

**(a) realpath on a WindowsApps app-execution alias.** `os.path.realpath` (Python 3.12, uses `GetFinalPathNameByHandleW`) returns the original path when the reparse target is not a standard path. The resolved string still contains `windowsapps` and still ends in `bash.exe`, so the substring check `"windowsapps" in resolved and resolved.endswith("bash.exe")` catches it. If `realpath` somehow strips the `windowsapps` component, the reparse-point check at install.py:175-180 (`GetFileAttributesW` flag `0x400`) still catches the alias. Both checks must be bypassed; no exception path returns `ok=True`.

**(a cont.) realpath on a path that does not exist.** The function returns `(False, "not a file")` at line 148 before reaching `realpath`. No issue.

**(a cont.) exception path returning ok=True.** Traced every branch: steps 1-2 return False explicitly; step 3 (`relative_to` exception) falls through to the WSL check (safe: "not under root" is the correct default); step 5 reparse exception falls through to step 6 (symlink check) and step 7 (stat/S_ISREG), both of which return False on anything abnormal; step 7 `stat` exception returns False. No path reaches `return True, ""` unless every check passes.

### R2 FIXED -- hook_eval.py:353-354

Floor condition is now `_under_floor = _is_enrolled or result.requires_dual`. The old comment explaining why requires_dual was excluded has been deleted. The deny message at line 366 ("enrolled or dual-control") is now accurate. Test `test_r2_requires_dual_unbound_denied_under_floor` monkeypatches exfil detection to trigger `requires_dual` in a standalone workspace, runs `./deploy.sh`, and asserts `SCRIPT_UNPINNABLE`.

**(d) legitimate standalone flows and T16 demo.** In the T16 demo the dual-control triggers are exfil commands (`curl -F`, `scp`). These are classified as binding `"none"` by the resolver (not interpreters), so the floor check (`binding == "unbound"`) does not fire. Bound forms (`python deploy.py` with the file present) also pass. Only interpreter commands in unbound form (e.g. `python -c "..."`, `./deploy.sh`) with `requires_dual` are denied, which is the ADR's intent: they cannot be content-verified, so they must not run under dual control. No T16 regression.

**test_classification_factor_is_itemized (tests/unit/test_environment_classification.py:337).** The edit writes `tool.py` (one line: `print('x')`) before `decide()` is called. The command `python tool.py data/customers/a.csv` on RESTRICTED data triggers `requires_dual`, which under the floor requires the script to be bindable. Without the file, the resolver returns `file_not_found` (unbound), and the hook denies `SCRIPT_UNPINNABLE` before risk scoring, causing `KeyError: 'risk'`. With the file present, the script binds, the hook escalates, and risk factors are itemized as before. This is setup-only; the assertions at lines 340-342 (`f["points"] == 30`, `"RESTRICTED" in f["detail"]`, `rec["risk"]["score"] == plain.score + 30`) are unchanged. The floor deny for a `requires_dual` command whose script is missing is the **intended ADR behaviour**: if the script cannot be bound, it cannot be content-verified, and the floor denies it. This is not a regression; the test was under-specified (it assumed the script need not exist).

### R3 FIXED -- script_pin.py:1071-1085

`build_shell_argv` now uses a `_DRIVE_TOKEN` regex that matches only whitespace-delimited tokens beginning with `[A-Za-z]:\\`. The blanket `replace('\\', '/')` is removed. Backslashes outside drive-letter tokens survive byte-for-byte. `done["exec_argv"]` records the actual argv.

**(b) consistency with bash tokenisation.**
- `E:\a b\x.py` inside double quotes: the regex matches up to the first space (`"E:\a`), leaving `b\x.py"`. Inside bash double quotes, `\x` is literal (bash only escapes `\$`, `` \` ``, `\"`, `\\`, `\newline`). Python receives `E:/a b\x.py`, which maps back to `E:\a b\x.py` on Windows. Same file.
- `--file=E:\x.py` (glued to option): the regex does not match (no whitespace before the drive letter). Backslashes are not converted. In unquoted bash, `\x` becomes `x`, making the argument `--file=E:x.py`. This changes the meaning, but the resolver never binds an option-glued path (the script operand is always a separate word), so no pinned file is affected.
- UNC path `\\server\share\x.py`: not matched (no drive letter). Backslashes eaten by bash. UNC paths are always outside root (unbound), so not security-relevant.
- Token ending in backslash `E:\project\`: matched and converted to `E:/project/`. Correct.

**Can the conversion change which file bash opens vs. what the resolver pinned?** No. The script operand in a bound command is always a separate word after the interpreter and options. The regex matches it (starts after whitespace, begins with a drive letter). The converted forward-slash form maps back to the same Windows path under MSYS bash. Arguments to the script (which may contain unconverted backslashes) do not affect which file is opened.

### R4 FIXED -- script_pin.py:676

Default changed to `share_delete=False`. All callers now use the secure default.

### R5 FIXED -- script_pin.py:718-739

`_win_read_from_handle` now uses `ReadFile` through ctypes into a `create_string_buffer(size)`. No `open_osfhandle`; the handle stays owned by ScriptPin; `pin.release()` calls `CloseHandle` without conflict.

**(c) short reads.** `ReadFile` can return fewer bytes than requested. The code returns `buf.raw[:bytes_read.value]`. If `bytes_read.value < size`, the hash is computed on partial content, which mismatches the expected hash, causing a `SCRIPT_CHANGED` refusal. This is fail-safe. On local NTFS with the file pinned (no concurrent writes, size known from the handle), a short read should not occur.

**(c) files over one buffer.** The buffer is sized to `file_size` from `_win_handle_info` (line 854), so it fits the entire file. For a script of any reasonable size (the preview limit is 64 KiB; scripts beyond that are unshowable under the floor), one allocation suffices.

**(c) handle info before read.** `_win_handle_info(fh)` is called at line 854; `_win_read_from_handle(fh, file_size)` at line 868. The file_size from the handle info is passed to the read. Since the pin denies write sharing, the size cannot change between these calls.

### R6 FIXED (moot)

R2 fixed the floor condition to include `requires_dual`. The deny message "enrolled or dual-control" is now accurate.

### Final verdict: APPROVE

All six findings are fixed. No new findings. The TCB is sound.

---

**28 Oct 2026 -- CI follow-up (test_t0f_lexer).** Setup-only confirmed: monkeypatch pins DEADLINE_SECONDS to 60.0; assertion unchanged. No product change is correct (both codes are fail-closed denies; the race is environmental). Gap: no test asserts SHELL_DEADLINE itself; recommend a c6 extra test with a crafted slow input and a low deadline.
