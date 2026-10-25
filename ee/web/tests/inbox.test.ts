/**
 * T12b-2 tests-first: web approval inbox.
 *
 * C9 item 8: the pending list renders server text as text (no HTML
 * injection); Approve signs with the key loaded from IndexedDB (never a
 * freshly generated key; if no key, no signature and an error); the
 * signed object equals the displayed request; Approve is hidden/refused
 * on prod; CSRF header on approve.
 *
 * RED: these tests fail because the inbox module does not exist yet.
 * The existing modules (key-store, signing, approval, escalation-rules)
 * are reused; the inbox module wires them together.
 */
import { describe, it, expect, vi, beforeEach } from "vitest";

import {
  renderEscalationText,
  buildInboxApproval,
  buildInboxDeny,
  type InboxEscalation,
} from "../src/inbox";

// Existing modules used by the inbox
import { storeKey } from "../src/key-store";
import { generateBrowserKeyPair, exportPublicKey, computeKeyId, buildKeyLinkRequest } from "../src/browser-key";
import { canApprove } from "../src/escalation-rules";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Build a sample escalation object as the server would return it. */
function makeSampleEscalation(overrides?: Partial<InboxEscalation>): InboxEscalation {
  return {
    escalation_id: "esc-inbox-1",
    request_id: "req-inbox-1",
    command: "echo inbox-test",
    fingerprint: "abc123",
    device_id: "dev-inbox-1",
    project_id: "proj-inbox-1",
    org_id: "org-inbox-1",
    policy_sequence: 1,
    requires_dual: true,
    environment: "staging",
    status: "pending",
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// C9 item 8: server text rendered as text (no HTML injection)
// ---------------------------------------------------------------------------

describe("inbox: server text rendered as text (no dangerouslySetInnerHTML)", () => {
  it("literal text is preserved unchanged (React escapes at render)", () => {
    const esc = makeSampleEscalation({
      command: '<script>alert("xss")</script>',
    });
    const rendered = renderEscalationText(esc.command);
    // The raw literal text is returned (React JSX {text} escapes it)
    expect(rendered).toBe('<script>alert("xss")</script>');
  });

  it("HTML in request_id is preserved as literal text", () => {
    const esc = makeSampleEscalation({
      request_id: '<img src=x onerror="alert(1)">',
    });
    const rendered = renderEscalationText(esc.request_id);
    // The literal string is present; no element is created because
    // this text is rendered via JSX {text}, not innerHTML.
    expect(rendered).toBe('<img src=x onerror="alert(1)">');
  });

  it("special characters in fingerprint are preserved as literal text", () => {
    const esc = makeSampleEscalation({
      fingerprint: '"><svg/onload=alert(1)>',
    });
    const rendered = renderEscalationText(esc.fingerprint);
    expect(rendered).toBe('"><svg/onload=alert(1)>');
  });

  it("null bytes in command are shown escaped as [U+0000]", () => {
    const esc = makeSampleEscalation({
      command: "echo \x00test",
    });
    const rendered = renderEscalationText(esc.command);
    // F4 fix: NUL is shown visibly, not stripped, so two values
    // differing only by NUL render differently in the Deny view.
    expect(rendered).not.toContain("\x00");
    expect(rendered).toBe("echo [U+0000]test");
  });
});

// ---------------------------------------------------------------------------
// C9 item 8: Approve signs with stored key (never freshly generated)
// ---------------------------------------------------------------------------

describe("inbox: Approve uses stored key from IndexedDB", () => {
  beforeEach(() => {
    // Clear any in-memory key store state between tests
  });

  it("buildInboxApproval uses loadKey, not generateBrowserKeyPair", async () => {
    // Store a key first
    const keyPair = await generateBrowserKeyPair();
    const rawPub = await exportPublicKey(keyPair.publicKey);
    const keyId = await computeKeyId(rawPub);
    await storeKey(keyId, keyPair);

    const esc = makeSampleEscalation();
    const result = await buildInboxApproval(esc, {
      keyId,
      userId: "user-bob",
      csrfToken: "csrf-abc",
    });

    // The result must use the stored key's key_id
    expect(result.body.signatures[0].key_id).toBe(keyId);
    // The signature must be non-empty (signed with the stored key)
    expect(result.body.signatures[0].sig.length).toBeGreaterThan(0);
  });

  it("buildInboxApproval fails when no stored key exists", async () => {
    const esc = makeSampleEscalation();
    // Use a key_id that was never stored
    await expect(
      buildInboxApproval(esc, {
        keyId: "nonexistent-key-id",
        userId: "user-bob",
        csrfToken: "csrf-abc",
      }),
    ).rejects.toThrow(/no.*key|key.*not.*found|missing.*key/i);
  });

  it("enroll (buildKeyLinkRequest) then approve works without manual storeKey", async () => {
    // buildKeyLinkRequest now stores the key internally
    const linkReq = await buildKeyLinkRequest("csrf-enroll");
    const enrolledKeyId = linkReq.body.key_id as string;

    const esc = makeSampleEscalation();
    const result = await buildInboxApproval(esc, {
      keyId: enrolledKeyId,
      userId: "user-enroll",
      csrfToken: "csrf-approve",
    });

    expect(result.body.signatures[0].key_id).toBe(enrolledKeyId);
    expect(result.body.signatures[0].sig.length).toBeGreaterThan(0);
    expect(result.body.payload.decision).toBe("approve");
  });

  it("buildInboxApproval never calls generateBrowserKeyPair", async () => {
    // Spy on generateBrowserKeyPair to ensure it is never called
    const spy = vi.spyOn(
      await import("../src/browser-key"),
      "generateBrowserKeyPair",
    );

    const keyPair = await generateBrowserKeyPair();
    spy.mockClear(); // clear the call from setup
    const rawPub = await exportPublicKey(keyPair.publicKey);
    const keyId = await computeKeyId(rawPub);
    await storeKey(keyId, keyPair);

    const esc = makeSampleEscalation();
    await buildInboxApproval(esc, {
      keyId,
      userId: "user-bob",
      csrfToken: "csrf-abc",
    });

    expect(spy).not.toHaveBeenCalled();
    spy.mockRestore();
  });
});

// ---------------------------------------------------------------------------
// C9 item 8: the signed object equals the displayed request
// ---------------------------------------------------------------------------

describe("inbox: signed object equals displayed request", () => {
  it("the signed payload contains exactly the displayed fields", async () => {
    const keyPair = await generateBrowserKeyPair();
    const rawPub = await exportPublicKey(keyPair.publicKey);
    const keyId = await computeKeyId(rawPub);
    await storeKey(keyId, keyPair);

    const esc = makeSampleEscalation({
      request_id: "req-sign-match-1",
      command: "echo sign-match",
      org_id: "org-sign-match",
      project_id: "proj-sign-match",
      device_id: "dev-sign-match",
      policy_sequence: 7,
    });

    const result = await buildInboxApproval(esc, {
      keyId,
      userId: "user-bob",
      csrfToken: "csrf-abc",
    });

    const payload = result.body.payload;
    // The signed payload must match the displayed escalation
    expect(payload.request_id).toBe(esc.request_id);
    expect(payload.command).toBe(esc.command);
    expect(payload.org_id).toBe(esc.org_id);
    expect(payload.project_id).toBe(esc.project_id);
    expect(payload.device_id).toBe(esc.device_id);
    expect(payload.policy_sequence).toBe(esc.policy_sequence);
    expect(payload.decision).toBe("approve");
  });

  it("the signed deny payload also matches the displayed escalation", async () => {
    const keyPair = await generateBrowserKeyPair();
    const rawPub = await exportPublicKey(keyPair.publicKey);
    const keyId = await computeKeyId(rawPub);
    await storeKey(keyId, keyPair);

    const esc = makeSampleEscalation({
      request_id: "req-deny-match-1",
      command: "echo deny-match",
    });

    const result = await buildInboxDeny(esc, {
      keyId,
      userId: "user-bob",
      csrfToken: "csrf-abc",
    });

    const payload = result.body.payload;
    expect(payload.request_id).toBe(esc.request_id);
    expect(payload.command).toBe(esc.command);
    expect(payload.decision).toBe("deny");
  });
});

// ---------------------------------------------------------------------------
// C9 item 8: Approve hidden/refused on prod
// ---------------------------------------------------------------------------

describe("inbox: Approve hidden on prod", () => {
  it("canApprove returns false for prod (existing rule)", () => {
    const esc = makeSampleEscalation({ environment: "prod" });
    expect(canApprove({ environment: esc.environment, status: esc.status })).toBe(false);
  });

  it("buildInboxApproval refuses prod escalations", async () => {
    const keyPair = await generateBrowserKeyPair();
    const rawPub = await exportPublicKey(keyPair.publicKey);
    const keyId = await computeKeyId(rawPub);
    await storeKey(keyId, keyPair);

    const esc = makeSampleEscalation({ environment: "prod" });
    await expect(
      buildInboxApproval(esc, {
        keyId,
        userId: "user-bob",
        csrfToken: "csrf-abc",
      }),
    ).rejects.toThrow(/prod|not.*allowed|refused/i);
  });

  it("buildInboxApproval refuses absent environment (treated as prod)", async () => {
    const keyPair = await generateBrowserKeyPair();
    const rawPub = await exportPublicKey(keyPair.publicKey);
    const keyId = await computeKeyId(rawPub);
    await storeKey(keyId, keyPair);

    const esc = makeSampleEscalation({ environment: undefined as unknown as string });
    await expect(
      buildInboxApproval(esc, {
        keyId,
        userId: "user-bob",
        csrfToken: "csrf-abc",
      }),
    ).rejects.toThrow(/prod|not.*allowed|refused/i);
  });

  it("buildInboxDeny allowed on prod", async () => {
    const keyPair = await generateBrowserKeyPair();
    const rawPub = await exportPublicKey(keyPair.publicKey);
    const keyId = await computeKeyId(rawPub);
    await storeKey(keyId, keyPair);

    const esc = makeSampleEscalation({ environment: "prod" });
    // Deny is allowed on prod, so this should not throw
    const result = await buildInboxDeny(esc, {
      keyId,
      userId: "user-bob",
      csrfToken: "csrf-abc",
    });
    expect(result.body.payload.decision).toBe("deny");
  });
});

// ---------------------------------------------------------------------------
// C9 item 8: CSRF header on approve
// ---------------------------------------------------------------------------

describe("inbox: CSRF header on approve POST", () => {
  it("buildInboxApproval includes X-CSRF-Token header", async () => {
    const keyPair = await generateBrowserKeyPair();
    const rawPub = await exportPublicKey(keyPair.publicKey);
    const keyId = await computeKeyId(rawPub);
    await storeKey(keyId, keyPair);

    const esc = makeSampleEscalation();
    const result = await buildInboxApproval(esc, {
      keyId,
      userId: "user-bob",
      csrfToken: "csrf-test-token",
    });

    expect(result.headers["X-CSRF-Token"]).toBe("csrf-test-token");
  });

  it("buildInboxDeny also includes X-CSRF-Token header", async () => {
    const keyPair = await generateBrowserKeyPair();
    const rawPub = await exportPublicKey(keyPair.publicKey);
    const keyId = await computeKeyId(rawPub);
    await storeKey(keyId, keyPair);

    const esc = makeSampleEscalation();
    const result = await buildInboxDeny(esc, {
      keyId,
      userId: "user-bob",
      csrfToken: "csrf-deny-token",
    });

    expect(result.headers["X-CSRF-Token"]).toBe("csrf-deny-token");
  });

  it("CSRF token must not be empty", async () => {
    const keyPair = await generateBrowserKeyPair();
    const rawPub = await exportPublicKey(keyPair.publicKey);
    const keyId = await computeKeyId(rawPub);
    await storeKey(keyId, keyPair);

    const esc = makeSampleEscalation();
    await expect(
      buildInboxApproval(esc, {
        keyId,
        userId: "user-bob",
        csrfToken: "",
      }),
    ).rejects.toThrow(/csrf|token.*required|missing/i);
  });
});
