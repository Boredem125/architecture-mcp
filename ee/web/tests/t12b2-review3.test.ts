/**
 * T12b-2 security re-review round 2, web proof (security-engineer, leader tier).
 *
 * ``it.fails`` is vitest's strict xfail: the test passes only while the
 * assertion inside fails.  When the fix lands the body passes, ``it.fails``
 * reports a failure, and the fixing change must turn it into ``it``.
 *
 * F4 (Low, ADR 0010 s7): renderEscalationText deletes NUL (U+0000) instead
 *   of showing it escaped like every other C0 control.  Approve is disabled
 *   for such a row (hasUnsafeControlChars includes NUL), but the Deny view
 *   shows a value that is not the one being denied, and two different server
 *   values ("rm -rf /" and "rm \0-rf /") render identically.  The fix must
 *   also change the inbox-section test that pins the stripping
 *   ("strips null bytes so displayed text matches signed text"), whose
 *   rationale is inverted: stripping makes the display differ from the
 *   signed bytes.
 */
import { describe, it, expect } from "vitest";

import { renderEscalationText, hasUnsafeControlChars } from "../src/inbox";

describe("T12b-2 re-review F4: NUL is shown, not deleted", () => {
  it("guard: a NUL marks the row unsafe (Approve disabled)", () => {
    expect(hasUnsafeControlChars("rm \x00-rf /")).toBe(true);
  });

  it("renderEscalationText shows U+0000 visibly", () => {
    const shown = renderEscalationText("rm \x00-rf /");
    expect(shown).not.toBe(renderEscalationText("rm -rf /"));
    expect(shown).toMatch(/0000/);
  });
});
