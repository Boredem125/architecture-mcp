# M1 hand-off (19 Oct 2026)

**Now:** M1 Phase A, T4 done (tests `27d1108` + fix, pushed together; security signed off, worker tier). Next: T4b (SEC-30 reject untagged legacy signatures for new decisions in `_valid_for`/`verify_proposal`/`verify_entry`; SEC-31 sign the evidence manifest with the EVIDENCE tag), then Phase B (`ee/`) per `M1_PLAN.md`.

**T4 result:** `src/sandbox/protocol/domains.py` (5 active + 4 reserved tags); signed bytes = tag || 0x00 || canonical JSON, `sig_v: 1`; SEC-24 closed (field sets from code; legacy = untagged, 4 code-defined `_HISTORICAL_SIGNED_FIELDS` sets, one kept for frozen Q3 node `test_records_signed_before_fingerprint_was_added_still_verify`). ADR 0007 1.6 closed by orchestrator ruling: `key_rotated` carries `done_at_rotation` {request_id: sha256 of canonical record} inside the chain; `legacy` needs id + hash match, else `unverifiable` (replaces `audit_heads`, which broke frozen `test_evidence.py` counts). `sign_record` no longer re-signs a record that already has a signature (stops laundering). New `tests/security/test_m1_t4_followup.py` (3). Full Windows suite: 1635 passed, 1 skipped. Reviewer note: 36 frozen-manifest mismatches on Windows are CRLF artifacts; no frozen file touched.

**T3 result:** 15 RED tests pass, xfail markers removed. Fixes after review: `_pin_and_audit` audits before the pin and fails closed; `keys.enrol: explicit` enforced at the single pin path (`NotEnrolledError`; enrolled = already pinned, no enrol command until M2); `tool_grants` passes `layout`. New `tests/security/test_m1_t3_followup.py` (12). Frozen `tests/unit/test_evidence.py` exception (3 node ids, counts only, signed off; manifest re-hashed; row in `M1_BASELINE.md`). Full Windows suite: 1610 passed, 1 skipped, 0 failed.

**Verified (pushed, security signed off):** T0c SEC-23 money floor (`bcb81d8`), T0d (`97c2643`), T0e SEC-25 CLI deny (`5ce9df8`), SEC-27/28 hook hardening (`eac889d`..`5595cb4`), T1 `?root=` + SEC-26 (`81adc55`), T0f lexer + git flag allowlist + `.git/**` (`e0041df`, 427-case corpus), T0g runners (`6a7c0e9`), T2 key home (`da58fc3`, pushed before review) plus follow-up (`200c8ab`, signed off). Last full Windows suite: 1583 passed, 1 skipped, 15 xfailed (at `4f33e63`).

**Next 3 steps (1-2 done, 3 in progress):**
1. (Done) T3: the 15 RED tests pass; remove only their xfail markers; full suite green. Label decision (orchestrator): each approval in the evidence pack and `sandbox verify` gets `key_status` = `pinned` | `legacy` (retired pre-M1 key AND under the `key_rotated` chain head) | `unverifiable`. Only pinned/legacy count as verified.
2. Security diff review of T3 (worker tier). Commit + push via git-ops with the exact file list. Update REVIEW_SECURITY: SEC-25 closed (proposer signature), the T2 "retired seed" known limit closed, ADR 0007 section 1.6 done.
3. T4 (domain-tagged signatures, SEC-24 `verify_record` trusts the record's `signed_fields`) **plus ADR 0007 section 1.6**: `legacy` must verify under the `key_rotated` audit head; today `_key_status_for` uses a backdatable timestamp (orchestrator ruling, REVIEW_SECURITY "T3 limits"). Then Phase B (`ee/`) per `M1_PLAN.md`.

**Open conditions not yet in M1_PLAN/M1_BASELINE:**
- `root_exposure` (icacls) misses domain-local groups (`DOMAIN\Domain Users`): fix before multi-user control plane.
- CI "key-home-empty" check (LOCALAPPDATA/HOME at an empty temp dir, assert it stays empty) is not done (devops, `tests.yml`).
- Shell recursion into a dir above the key home is denied only for recognised forms: publish as a limit.
- Docker Desktop is not running and its disk image is on C:. M1 T6/T11/T14 need it on E: (founder).
- Founder: make `tests`, `security`, `image` required checks on `main`. Azure student credits for a VM at T11 (see memory).
- CI state after `200c8ab`/`4f33e63` not re-checked.

**Rules learned (put in every worker brief):**
- Model tiers: see TEAM.md "Model hierarchy". Leaders `model:"opus"`; workers/support/git-ops omit `model`; effort high (workers) / medium (support, git-ops). Verified ids: workers `claude-opus-4-6`, git-ops `claude-sonnet-4-6`.
- Run pytest via Bash (`.venv/Scripts/python -m pytest -q -p no:logging ... | tail -40`) or PowerShell **without** `2>&1` (PS 5.1 turns stderr into errors, output is lost). Exit 1 while tests are red is expected.
- git-ops order: `git add -- <exact files>`, commit, `git pull --rebase --autostash origin main`, push. Never pull before committing.
- Workers never commit security-sensitive work before sign-off; say so explicitly in every brief (a cut-off brief caused the unsigned `da58fc3` push).
- Unfixed Critical findings: keep repro out of public docs/commits; hold all pushes until tests + fix ship together.
- Class C / frozen tests: change only with a named sign-off by node id; re-hash `M1_FROZEN_MANIFEST.sha256` and record the exception in `M1_BASELINE.md`. M0_* files are history; don't edit them.
- E: drive env vars in every shell (`TMP`/`TEMP`/`PIP_CACHE_DIR`/`HF_HOME` under `E:\caterpillar\jev-os\.cache`). No Co-Authored-By. Never stash, reset or force-push.
- Writing a founder quote relayed by another session into the repo can be blocked by the classifier; the main session records those.

**Update (19 Oct, later):** T3 finished, reviewed and committed. SEC-25 closed. The T2 "retired seed" limit and ADR 0007 1.6 stay open until T4.
