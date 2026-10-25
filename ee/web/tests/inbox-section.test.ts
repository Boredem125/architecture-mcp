/**
 * T12b-2: InboxSection component-logic tests.
 *
 * No DOM environment (vitest runs in node), so these test the logic
 * paths the component uses: text-only rendering, approve hidden on
 * prod, and no-key error.
 */
import { describe, it, expect } from "vitest";

import { renderEscalationText, buildInboxApproval, buildInboxDeny } from "../src/inbox";
import type { InboxEscalation } from "../src/inbox";
import { canApprove, canDeny } from "../src/escalation-rules";

function makeSampleEscalation(overrides?: Partial<InboxEscalation>): InboxEscalation {
  return {
    escalation_id: "esc-sec-1",
    request_id: "req-sec-1",
    command: "echo component-test",
    fingerprint: "fp1",
    device_id: "dev-sec-1",
    project_id: "proj-sec-1",
    org_id: "org-sec-1",
    policy_sequence: 1,
    requires_dual: true,
    environment: "staging",
    status: "pending",
    ...overrides,
  };
}

describe("InboxSection logic: text-only rendering", () => {
  it("preserves literal server text (React JSX escapes at render, not here)", () => {
    const esc = makeSampleEscalation({
      command: '<img src=x onerror="alert(1)">',
      project_id: "<b>evil</b>",
      environment: '"><script>x</script>',
    });
    // renderEscalationText returns raw text (null-stripped only);
    // React {text} in JSX prevents element creation.
    expect(renderEscalationText(esc.command)).toBe('<img src=x onerror="alert(1)">');
    expect(renderEscalationText(esc.project_id)).toBe("<b>evil</b>");
    expect(renderEscalationText(esc.environment)).toBe('"><script>x</script>');
  });

  it("shows NUL as [U+0000] so two values differing by NUL render differently", () => {
    const esc = makeSampleEscalation({ command: "rm \x00-rf /" });
    const text = renderEscalationText(esc.command);
    // F4 fix: NUL is shown escaped, not stripped, so the Deny view
    // distinguishes "rm \0-rf /" from "rm -rf /".  Approve is disabled
    // for this row (hasUnsafeControlChars returns true).
    expect(text).toBe("rm [U+0000]-rf /");
    expect(text).not.toContain("\x00");
    expect(text).not.toBe(renderEscalationText("rm -rf /"));
  });
});

describe("InboxSection logic: Approve hidden on prod", () => {
  it("canApprove returns false for prod, canDeny returns true", () => {
    const esc = makeSampleEscalation({ environment: "prod" });
    expect(canApprove({ environment: esc.environment, status: esc.status })).toBe(false);
    expect(canDeny({ environment: esc.environment, status: esc.status })).toBe(true);
  });

  it("canApprove returns false for absent environment", () => {
    const esc = makeSampleEscalation({ environment: undefined as unknown as string });
    expect(canApprove({ environment: esc.environment, status: esc.status })).toBe(false);
  });
});

describe("InboxSection logic: no key = error", () => {
  it("buildInboxApproval rejects when no key is stored", async () => {
    const esc = makeSampleEscalation();
    await expect(
      buildInboxApproval(esc, {
        keyId: "no-such-key",
        userId: "user-1",
        csrfToken: "csrf-1",
      }),
    ).rejects.toThrow(/no.*key|key.*not.*found/i);
  });

  it("buildInboxDeny rejects when no key is stored", async () => {
    const esc = makeSampleEscalation();
    await expect(
      buildInboxDeny(esc, {
        keyId: "no-such-key",
        userId: "user-1",
        csrfToken: "csrf-1",
      }),
    ).rejects.toThrow(/no.*key|key.*not.*found/i);
  });
});
