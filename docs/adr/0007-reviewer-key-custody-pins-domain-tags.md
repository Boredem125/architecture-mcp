# ADR 0007: Reviewer key custody, pinned keys and domain-tagged signatures (standalone mode)

Status: Accepted (18 Oct 2026). Approved by security-engineer on two conditions, both recorded below (Decision 1.6 and 2.7). M1 T0b. Implements `M1_PLAN.md` D2 and D3; settles SEC-05 (standalone half), SEC-24 and the T0-hotfix key residual.

## Next action

Backend-engineer: build T2-T4 against this ADR, tests first (qa-engineer).

## Context

1. **Seeds live inside the workspace.** `signing._seed_path` puts them at `.sandbox/state/keys/<reviewer>.seed`. The T0 hotfix denies Read, and Grep/Glob that name `.sandbox`, but a Grep or Glob with no path (or `path: "."`) searches the whole folder and can return seed bytes. Security called this an M1 blocker (t0-hotfix notes). Before T0, SEC-01 showed the agent could `cat` them, so every pre-M1 seed must be treated as exposed.
2. **Signatures have no trust anchor.** `verify_record` and `verify_approval` check against the public key embedded in the record (`signing.py:88-128`). Anyone who can write the queue can add "approvals" made with fresh keys (SEC-05).
3. **The verifier trusts the record's field list.** `verify_record` signs and verifies over `record["signed_fields"]` (`signing.py:100`). A record claiming `["request_id"]` verifies with `decision` and `command` unsigned (SEC-24).
4. **No domain separation.** An approval signature and a grant or policy-change signature are made over plain canonical JSON. Where field sets overlap, one kind can be replayed as another.
5. **Keys are created silently.** `_load_or_create_key` makes a key for any new `reviewer_id` on first use.

## Options

### Key custody
1. **Key home outside every workspace** (per-user OS data dir, override `SANDBOX_KEY_HOME`), plus a non-removable deny on it. Cheap; fixes rootless search by construction.
2. Keep keys in the tree and deny rootless Grep/Glob. Breaks ordinary search. And shell `grep -r` (escalates) would show seed bytes to a human who approves a harmless-looking search, and through them to the agent. **Rejected.**
3. OS keystore (DPAPI / Keychain) now. Platform work on three OSes; planned for M2 (ADR 0001 Q3). Same-user code can still use the key, so it does not change the M1 threat picture. **Deferred.**

### Pinning
1. **Strict explicit enrolment** (`sandbox keys enrol` before any signature). **Rejected** (settled with security, 18 Oct 2026). It would not stop one approver pinning two ids either. About 11 frozen test files sign with ad-hoc reviewer ids.
2. **Pin on first use, from human surfaces only, made visible** (chosen).

## Decision

### 1. Key home
1. Location: `SANDBOX_KEY_HOME`; default `%LOCALAPPDATA%\agg\keys` (Windows), `~/.local/share/agg/keys` (Linux), `~/Library/Application Support/agg/keys` (macOS).
2. One subfolder per **workspace id** (random, written at `init` into `.sandbox/`). Seeds and `pins.json` are per workspace id, so reviewer `cli` in two workspaces has two keys and two pins. Files 0600; user-only ACL on Windows.
3. **Fail closed.** If the key home cannot be resolved or written, there is no signing and every approval is invalid. Never fall back to `.sandbox/state/keys`, the cwd or a relative path.
4. **Non-removable deny for read, write, delete and rename** on the key home, for Read, Grep, Glob, Write, Edit and shell, re-injected like `_PROTECT_WRITE_GLOBS`. It does not use the configurable `read_outside` / `write_outside` triggers. Shell path arguments are resolved like Read's, so `$LOCALAPPDATA`, `%LOCALAPPDATA%`, `$env:LOCALAPPDATA`, `~`, 8.3 short names, case variants and in-tree symlinks or junctions all end in deny or escalate, never allow.
5. **Rotate, never migrate.** On first use after upgrade, a new key is generated in the key home and pinned. The old public key is recorded with `retired_at`, and `key_rotated` is audited. In-tree seeds are never copied, moved or deleted: they stay in place, retired, under the existing in-tree deny. **Retired is not inert until T3:** a rootless Grep or Glob can still read a retired seed, and until pins (T3) and Decision 1.6 (T3/T4) land, a verifier does not yet refuse approvals signed by it. See Stated limits 4.
6. **Retired seeds cannot backdate history (security condition a).** A retired in-tree seed stays readable to a rootless Grep, so anyone holding it could forge backdated legacy records. Legacy (untagged) records therefore verify **only if they are covered by the audit-chain head recorded in the `key_rotated` event**; anything else is reported as `unverifiable`, never `legacy`. A human-run `sandbox keys purge-legacy` (approver CLI, so T0e-denied to the agent, audited) deletes retired in-tree seeds when the operator chooses.

### 2. Pins
1. `pins.json` records `reviewer_id`, public key, workspace root, `pinned_at` and `retired_at`. Entries are never overwritten in place; rotation is explicit.
2. A pin is written **only** by the approver CLI / approver-token API signing path. The `hook_eval` and `mcp_server` paths cannot create a pin (tested).
3. Every new pin is audited `key_pinned`, raises an alert, and is shown in `sandbox watch` and `status`.
4. Policy flag `keys.enrol: explicit` refuses unenrolled ids. It is tighten-only; turning it off is a loosening change under change control.
5. Approvals, dual control (`_valid_for`, `distinct_approvals`), tool grants and `policy approve-change` verify against the pin valid at the approval's `approved_at`, not the embedded key. A workspace-root mismatch is refused. Unpinned or mismatched means invalid, plus an alert.
6. `sandbox verify` and the evidence pack flag any dual-control decision whose pin was created after the request was queued as **"new-key approval"**.
7. **The approver-token API signs and pins only its fixed reviewer id**, never an id the client supplies (security condition b).

### 3. Domain-tagged signatures
1. Signed bytes = `tag || 0x00 || canonical JSON`. Tags live in `src/sandbox/protocol/domains.py` (MIT):
   - in use: `agg/approval/v1`, `agg/record/v1`, `agg/grant/v1`, `agg/policy-change/v1`, `agg/evidence/v1`;
   - reserved: `agg/registry/v1`, `agg/bundle/v1`, `agg/device-assert/v1`, `agg/audit-head/v1`.
2. Records carry `sig_v: 1`. **The verifier takes the tag and the signed-field set from its own context (kind and `sig_v`), in code, never from the record.** The field set is fixed per kind (SEC-24).
3. **No downgrade.** New decisions (dual control, grants, policy change) reject anything without `sig_v: 1` and a pinned key. Untagged records still verify for history only, labelled `legacy` in `sandbox verify` and the evidence pack. They verify only against a code-defined list of historical `_SIGNED_FIELDS` sets, never against a subset the record claims.
4. **Compatibility.** `_load_or_create_key`, `_canonical` and `_SIGNED_FIELDS` keep their signatures and meaning. Evidence check names and detail texts stay as they are (`signer_is_folder_key`, `dual_control`, "not signed by the folder's key"); new checks get new names.

## Consequences

1. A grep for **live** key bytes inside a workspace finds nothing: current keys are not there. Until `sandbox keys purge-legacy` runs, retired pre-M1 seeds stay in `.sandbox/state/keys/`. They are useless for new decisions and cannot forge history past the `key_rotated` head (Decision 1.6).
2. Upgrading rotates every reviewer key. A dual approval that is half done at upgrade time must be re-approved. Old records show as `legacy`. Both go in the release note.
3. Tests set `SANDBOX_KEY_HOME` per test (one conftest autouse fixture, signed off by security), so no test writes the real user directory on C:. CI points `LOCALAPPDATA`/`HOME` at an empty temp dir and asserts it is still empty after the run.
4. M3's registry verification (ADR 0003) reuses the same tags and the "field set from context" rule.

## Security properties affected

1. **Key confidentiality against the agent:** improves from "denied per tool, leaks through rootless search" to "not in the workspace, denied for every tool".
2. **Approval authenticity (standalone):** improves from "some key signed this" to "a key pinned for this reviewer in this workspace, from a human surface, signed this exact kind of record".
3. **Signature integrity:** the SEC-24 field-subset forgery and cross-kind replay are closed.

## Stated limits

1. **Same-user code.** The key home stops the hook-governed agent. It does not stop other code running as the same OS user, including a `python` command a human approved. DPAPI does not change that; passkeys (M3) do.
2. **Not provably two humans.** Standalone dual control means two pinned keys from human surfaces. One person can pin two ids. The "new-key approval" flag makes that visible; it does not prevent it. The evidence pack says so.
3. **Key home on C:.** On Windows the default key home is on C:. The founder's dev box sets `SANDBOX_KEY_HOME` on E:.
4. **Retired seeds until T3/T4.** Until pinned keys (T3) and the 1.6 legacy rule (T3/T4) are in, a retired in-tree seed that someone read could still sign records that verify against its embedded public key. `sandbox keys purge-legacy` removes them; run it after upgrading. This limit closes when T3/T4 land.
5. **A deleted `.sandbox/workspace_id`** starts a new key folder (new keys, no pins). It is audited as `workspace_id_created`; it is not prevented.
