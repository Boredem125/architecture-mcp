/**
 * T12c c5 review: control-character safety and approve-enabled tests
 * for script.rel, script_preview.text, and the approveEnabled helper
 * (ADR 0010 s7, s9.5).
 *
 * All tests are behavioural, using real InboxEscalation objects.
 */
import { describe, it, expect } from "vitest";

import {
  renderEscalationText,
  buildInboxApproval,
  escalationHasUnsafeField,
  approveEnabled,
  type InboxEscalation,
} from "../src/inbox";
import { canDeny } from "../src/escalation-rules";
import {
  generateBrowserKeyPair,
  exportPublicKey,
  computeKeyId,
} from "../src/browser-key";
import { storeKey } from "../src/key-store";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeEsc(overrides?: Partial<InboxEscalation>): InboxEscalation {
  return {
    escalation_id: "esc-safe-1",
    request_id: "req-safe-1",
    command: "python deploy.py",
    fingerprint: "a".repeat(64),
    device_id: "dev-1",
    project_id: "proj-1",
    org_id: "org-1",
    policy_sequence: 1,
    requires_dual: true,
    environment: "staging",
    status: "pending",
    ...(overrides ?? {}),
  } as InboxEscalation;
}

async function storedKeyId(): Promise<string> {
  const kp = await generateBrowserKeyPair();
  const kid = await computeKeyId(await exportPublicKey(kp.publicKey));
  await storeKey(kid, kp);
  return kid;
}

async function sha256Hex(text: string): Promise<string> {
  const buf = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(text),
  );
  return Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

// ---------------------------------------------------------------------------
// approveEnabled: U+202E in rel disables Approve, Deny stays
// ---------------------------------------------------------------------------

describe("T12c script safety: approveEnabled with control chars in rel", () => {
  it("script.rel containing U+202E (RLO) disables Approve via approveEnabled", () => {
    const esc = makeEsc({
      script: {
        rel: "deploy‮.py",
        sha256: "b".repeat(64),
        size: 100,
      },
    });
    expect(approveEnabled(esc, "na")).toBe(false);
  });

  it("Deny stays allowed when rel has U+202E", () => {
    const esc = makeEsc({
      script: {
        rel: "deploy‮.py",
        sha256: "b".repeat(64),
        size: 100,
      },
    });
    expect(canDeny({ environment: esc.environment, status: esc.status })).toBe(
      true,
    );
  });

  it("script.rel containing U+0009 (tab) disables Approve", () => {
    const esc = makeEsc({
      script: {
        rel: "deploy\t.py",
        sha256: "b".repeat(64),
        size: 100,
      },
    });
    // In rel, nothing is allowed -- not even tab (ADR 0010 s7).
    expect(approveEnabled(esc, "na")).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// approveEnabled: various control chars in rel (C1, DEL, bidi)
// ---------------------------------------------------------------------------

describe("T12c script safety: bidi, C1 and DEL in rel", () => {
  it.each([
    ["U+0085 (NEL, C1)", "\u0085"],
    ["U+2066 (LRI, bidi)", "⁦"],
    ["U+061C (ALM, bidi)", "؜"],
    ["U+202A (LRE, bidi)", "‪"],
    ["U+007F (DEL)", "\u007F"],
    ["U+0080 (C1 start)", "\u0080"],
    ["U+009F (C1 end)", "\u009F"],
  ])("rel containing %s disables Approve", (_name, ch) => {
    const esc = makeEsc({
      script: {
        rel: `deploy${ch}.py`,
        sha256: "b".repeat(64),
        size: 100,
      },
    });
    expect(approveEnabled(esc, "na")).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// approveEnabled: control chars in body
// ---------------------------------------------------------------------------

describe("T12c script safety: control chars in body", () => {
  it.each([
    ["U+0001 (SOH, C0)", "\u0001"],
    ["U+0085 (NEL, C1)", "\u0085"],
    ["U+2066 (LRI, bidi)", "⁦"],
    ["U+061C (ALM, bidi)", "؜"],
    ["U+202A (LRE, bidi)", "‪"],
  ])("body containing %s disables Approve", (_name, ch) => {
    const body = `print('hi')\n${ch}bad\n`;
    const esc = makeEsc({
      script: { rel: "deploy.py", sha256: "c".repeat(64), size: 100 },
      script_preview: { text: body, sha256: "d".repeat(64) },
    });
    expect(escalationHasUnsafeField(esc)).toBe(true);
    expect(approveEnabled(esc, "match")).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// body with LF, CRLF and tab keeps Approve enabled
// ---------------------------------------------------------------------------

describe("T12c script safety: allowed chars in body", () => {
  it("body with LF, CRLF and tab keeps Approve enabled when hash matches", async () => {
    const body = "import os\r\nprint('hello')\n\texit(0)\n";
    const bodyHash = await sha256Hex(body);
    const esc = makeEsc({
      script: { rel: "deploy.py", sha256: "c".repeat(64), size: 100 },
      script_preview: { text: body, sha256: bodyHash },
    });
    expect(escalationHasUnsafeField(esc)).toBe(false);
    expect(approveEnabled(esc, "match")).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// script present with script_preview null
// ---------------------------------------------------------------------------

describe("T12c script safety: script without preview", () => {
  it("script present with script_preview null disables Approve", () => {
    const esc = makeEsc({
      script: { rel: "deploy.py", sha256: "b".repeat(64), size: 100 },
    });
    expect(approveEnabled(esc, "na")).toBe(false);
  });

  it("script present with script_preview null: buildInboxApproval throws", async () => {
    const keyId = await storedKeyId();
    const esc = makeEsc({
      script: { rel: "deploy.py", sha256: "b".repeat(64), size: 100 },
    });
    await expect(
      buildInboxApproval(esc, {
        keyId,
        userId: "user-bob",
        csrfToken: "c",
      }),
    ).rejects.toThrow(/preview.*missing|script.*preview/i);
  });
});

// ---------------------------------------------------------------------------
// uppercase server hash fails closed
// ---------------------------------------------------------------------------

describe("T12c script safety: server hash validation", () => {
  it("uppercase server sha256 causes buildInboxApproval to throw", async () => {
    const keyId = await storedKeyId();
    const body = "print('test')\n";
    const correctHash = await sha256Hex(body);
    const upperHash = correctHash.toUpperCase();

    const esc = makeEsc({
      script: { rel: "deploy.py", sha256: "c".repeat(64), size: 100 },
      script_preview: { text: body, sha256: upperHash },
    });
    await expect(
      buildInboxApproval(esc, {
        keyId,
        userId: "user-bob",
        csrfToken: "c",
      }),
    ).rejects.toThrow(/invalid.*hash.*format|hash.*format/i);
  });
});

// ---------------------------------------------------------------------------
// hash state "pending" disables Approve
// ---------------------------------------------------------------------------

describe("T12c script safety: hash state pending", () => {
  it("hash state 'pending' disables Approve", () => {
    const esc = makeEsc();
    expect(approveEnabled(esc, "pending")).toBe(false);
  });

  it("hash state 'match' on clean esc allows Approve", () => {
    const esc = makeEsc();
    expect(approveEnabled(esc, "match")).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Rendered output: escaped control chars visible as text
// ---------------------------------------------------------------------------

describe("T12c script safety: escaped rendering", () => {
  it("rendered body shows U+0001 escaped as [U+0001], never the raw byte", () => {
    const body = "print('hi')\n\u0001bad\n";
    const rendered = renderEscalationText(body, { body: true });
    expect(rendered).toContain("[U+0001]");
    // eslint-disable-next-line no-control-regex
    expect(rendered).not.toMatch(/\u0001/);
  });

  it("rendered body shows U+0085 (NEL) escaped as [U+0085]", () => {
    const body = "line1\n\u0085line2\n";
    const rendered = renderEscalationText(body, { body: true });
    expect(rendered).toContain("[U+0085]");
  });

  it("line numbers assert exact '1  import os' prefix", () => {
    const body = "import os\nprint('hello')\nexit(0)";
    const rendered = renderEscalationText(body, { body: true });
    const lines = rendered.split("\n");
    expect(lines[0]).toBe("1  import os");
    expect(lines[1]).toBe("2  print('hello')");
    expect(lines[2]).toBe("3  exit(0)");
  });
});

// ---------------------------------------------------------------------------
// buildInboxApproval: defence in depth (unsafe field throws)
// ---------------------------------------------------------------------------

describe("T12c script safety: buildInboxApproval defence in depth", () => {
  it("buildInboxApproval throws for approve when field has unsafe chars", async () => {
    const keyId = await storedKeyId();
    const esc = makeEsc({
      command: "python deploy‮.py",
    });
    await expect(
      buildInboxApproval(esc, {
        keyId,
        userId: "user-bob",
        csrfToken: "c",
      }),
    ).rejects.toThrow(/unsafe.*control/i);
  });
});
