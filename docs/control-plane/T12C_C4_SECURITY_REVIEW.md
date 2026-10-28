# T12c c4 Security Review (server side)

**Reviewer:** senior-security (leader tier, Opus 4.6)
**Commit base:** c51d0f0 (main) + uncommitted working tree
**Verdict:** CHANGES (one Medium must be fixed before commit)

## Findings

**R1 (Medium)** `ee/src/agg_cp/sync/escalations.py:440` --
Non-string `text` in `script_preview` bypasses the 64 KiB check.
`isinstance(preview_text, str)` is False for a JSON array or object,
so the size guard is skipped and the full dict is stored (up to the 1 MiB
body cap). Failing input: `{"script_preview": {"text": ["x"] * 70000, "sha256": "..."}}`.
**Fix:** reject with 400 when `text` is not a string (or absent).

**R2 (Low)** `ee/src/agg_cp/sync/escalations.py:1046-1083` --
M4 script equality runs before Ed25519 signature verification (line 1092).
An unauthenticated caller can probe stored hash values via distinct error
messages. Values are already visible in the authenticated GET responses,
so the information gain is minimal. Consistent with the existing M4
binding pattern (request_id, command, etc. are also pre-signature).
No code change required; note for c6 hardening.

**R3 (Info)** --
M4 binding checks (including T12c script equality) fire on the deny path.
The denier sees the required values in the GET response and can construct
a matching payload. Consistent with pre-existing behaviour. The web
approval path has no separate submission route (web uses the sync
approvals endpoint), so the check applies uniformly.

## Positive confirmations

- None vs "" vs missing key: `payload.get("script_rel", "")` defaults
  to `""`, matching `expected_script_rel = ""` when stored script is
  None. `str(None)` = `"None"` fails closed against `""`. Correct.
- 64 KiB boundary (for strings): `> 65536` accepts exactly 65536 bytes,
  rejects 65537. Measured in UTF-8 bytes. Correct.
- Upload: script and script_preview sourced only from `record` dict
  fields (lines 432-447), never a second location.
- GET list and detail: RLS-scoped (`set_config('app.org_id', ...)`),
  pending_link refused by `_auth_signer_or_session`, fields returned
  as stored.
- Migration 0015: revision 00000000000f chains to 00000000000e (0014);
  downgrade drops both columns; nullable DEFAULT NULL, no data loss.
- No second approval can change stored values: the equality check
  compares against the escalation row, not prior approvals.
- No cross-org id leak in error messages (RLS returns empty, not errors).
- Hostile: JSON depth bounded by 1 MiB body cap; script.rel stored
  as-is (server never interprets); path traversal / control chars are
  a c5 web rendering concern, out of scope here.

## Route-set sign-off

`test_t9_routes.py` adds `_M2_T12C_ROUTES` (GET /api/v1/sync/escalations)
and `_M2_T12D_ROUTES` (POST genesis, GET candidates). No routes removed.
The T12c route addition is **approved** for M2_BASELINE section 3.
The T12d routes are d2 scope, reviewed separately.

## Assumptions (founder unavailable)

- The deny-path M4 binding (R3) is accepted as the current design;
  a deny-exemption would be a separate ADR amendment.
- R2 (pre-signature binding check ordering) is deferred to c6 hardening,
  not blocking c4.

## Resolution (28 Oct 2026)

**R1 FIXED.** Non-string `text` now returns 400 before the size check;
test `test_non_string_preview_text_rejected` covers the case (9 passed on pg).
R2 deferred to c6; R3 accepted as current design.

**Final verdict: APPROVE.**
