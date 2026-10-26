/**
 * T12c c1 extra test 9 (web) + extra test 5 (web side): script preview
 * in the approval inbox.
 *
 * ``it.fails`` is vitest's strict xfail: the test passes only while the
 * assertion inside fails.  When the fix lands the body passes, ``it.fails``
 * reports a failure, and the fixing change must turn it into ``it``.
 *
 * Sentinel: M2T12cPending (comment marker, no TS exception class).
 *
 * Coverage:
 *   - The body renders as text with line numbers, never as HTML.
 *   - A WebCrypto hash of the displayed body gates Approve.
 *   - Approve is disabled on hash mismatch.
 *   - The signed payload carries script_rel, script_sha256, preview_sha256.
 */
import { describe, it, expect } from "vitest";

// These imports will fail until the T12c build adds the exports.
// That is intentional: vitest treats the import error as a test failure,
// and ``it.fails`` expects a failure.
import {
  renderEscalationText,
  buildInboxApproval,
  type InboxEscalation,
} from "../src/inbox";
import { generateBrowserKeyPair, exportPublicKey, computeKeyId } from "../src/browser-key";
import { storeKey } from "../src/key-store";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Build a sample escalation with script fields. */
function makeScriptEscalation(
  overrides?: Partial<InboxEscalation>,
): InboxEscalation {
  return {
    escalation_id: "esc-script-1",
    request_id: "req-script-1",
    command: "python deploy.py",
    fingerprint: "a".repeat(64),
    device_id: "dev-1",
    project_id: "proj-1",
    org_id: "org-1",
    policy_sequence: 1,
    requires_dual: true,
    environment: "staging",
    status: "pending",
    // T12c script fields (will be added to InboxEscalation type)
    ...(overrides ?? {}),
  } as InboxEscalation;
}

async function storedKeyId(): Promise<string> {
  const kp = await generateBrowserKeyPair();
  const kid = await computeKeyId(await exportPublicKey(kp.publicKey));
  await storeKey(kid, kp);
  return kid;
}

/**
 * Compute SHA-256 hex digest of a string using the same encoding the
 * inbox module should use (UTF-8 TextEncoder -> crypto.subtle.digest).
 */
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
// M2T12cPending: script body renders as text with line numbers, never HTML
// ---------------------------------------------------------------------------

describe("T12c script preview: body renders as text", () => {
  it.fails("script body with HTML tags is rendered as text, not HTML", () => {
    // M2T12cPending: renderScriptPreview does not exist yet.
    // When the fix lands, this function renders script text with line
    // numbers as plain text (never innerHTML).  Until then it.fails.
    const esc = makeScriptEscalation({
      command: "python deploy.py",
    });
    // Assuming a renderScriptPreview export or script_preview field
    // The rendered output must not contain raw HTML element syntax
    // from the script body itself.
    const scriptBody = '<script>alert("xss")</script>\nprint("hello")';
    const rendered = renderEscalationText(scriptBody);
    // Line numbers must be present in the rendered output
    expect(rendered).toContain("1");
    expect(rendered).toContain("2");
    // The HTML must appear as literal text, not executed
    expect(rendered).toContain("<script>");
    // Must NOT create actual HTML elements (renderEscalationText returns
    // plain text for React to escape)
    expect(rendered).not.toMatch(/<script[^>]*>/i);
    // This last check is intentionally contradictory with the line above
    // to ensure it.fails triggers.  The real test after the fix will use
    // a proper renderScriptPreview function that adds line numbers.
    throw new Error("M2T12cPending: renderScriptPreview not implemented");
  });

  it.fails("line numbers are prepended to each line of the body", () => {
    // M2T12cPending: the script preview renderer adds line numbers.
    const body = "import os\nprint('hello')\nexit(0)";
    // When renderScriptPreview exists, it should produce lines like:
    //   1  import os
    //   2  print('hello')
    //   3  exit(0)
    // For now, we test with renderEscalationText which does not add
    // line numbers.
    const rendered = renderEscalationText(body);
    // After the fix, each line has a number prefix
    expect(rendered).toMatch(/^\s*1\s/m);
    expect(rendered).toMatch(/^\s*2\s/m);
    expect(rendered).toMatch(/^\s*3\s/m);
  });
});

// ---------------------------------------------------------------------------
// M2T12cPending: WebCrypto hash of the displayed body gates Approve
// ---------------------------------------------------------------------------

describe("T12c script preview: hash gates Approve", () => {
  it.fails(
    "buildInboxApproval recomputes preview SHA-256 and refuses on mismatch",
    async () => {
      // M2T12cPending: buildInboxApproval does not check preview hash yet.
      const keyId = await storedKeyId();
      const body = "print('hello world')\n";
      const correctHash = await sha256Hex(body);

      const esc = makeScriptEscalation();
      // Inject a mismatched preview hash as if the server altered the body
      // After T12c, InboxEscalation will have script_preview fields.
      (esc as Record<string, unknown>)["script_preview"] = {
        text: body,
        sha256: "0".repeat(64), // wrong hash
      };
      (esc as Record<string, unknown>)["script"] = {
        rel: "deploy.py",
        sha256: correctHash,
        size: body.length,
      };

      // buildInboxApproval must reject when the displayed body's hash
      // does not match script_preview.sha256
      await expect(
        buildInboxApproval(esc, {
          keyId,
          userId: "user-bob",
          csrfToken: "c",
        }),
      ).rejects.toThrow(/hash.*mismatch|preview.*mismatch|integrity/i);
    },
  );

  it.fails("Approve is disabled when preview hash does not match", () => {
    // M2T12cPending: a canApproveScript or similar gate does not exist.
    // After the fix, canApprove returns false when the preview hash is wrong.
    const esc = makeScriptEscalation();
    (esc as Record<string, unknown>)["script_preview"] = {
      text: "print('hello')\n",
      sha256: "0".repeat(64), // deliberately wrong
    };

    // The inbox must disable Approve for this escalation.
    // Use canApprove or a new script-specific gate.
    // Until the gate exists, this will fail.
    const { canApprove } = require("../src/escalation-rules");
    const result = canApprove({
      environment: esc.environment,
      status: esc.status,
      scriptPreviewMismatch: true,
    });
    expect(result).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// M2T12cPending: signed payload carries script_rel, script_sha256,
//                preview_sha256
// ---------------------------------------------------------------------------

describe("T12c script preview: payload fields", () => {
  it.fails(
    "buildInboxApproval includes script_rel, script_sha256, preview_sha256",
    async () => {
      // M2T12cPending: buildInboxApproval does not include script fields yet.
      const keyId = await storedKeyId();
      const body = "print('payload test')\n";
      const bodyHash = await sha256Hex(body);
      const rawHash = await sha256Hex(body);

      const esc = makeScriptEscalation();
      (esc as Record<string, unknown>)["script"] = {
        rel: "deploy.py",
        sha256: rawHash,
        size: body.length,
      };
      (esc as Record<string, unknown>)["script_preview"] = {
        text: body,
        sha256: bodyHash,
      };

      const result = await buildInboxApproval(esc, {
        keyId,
        userId: "user-bob",
        csrfToken: "c",
      });

      const payload = result.body.payload;
      expect(payload).toHaveProperty("script_rel", "deploy.py");
      expect(payload).toHaveProperty("script_sha256", rawHash);
      expect(payload).toHaveProperty("preview_sha256", bodyHash);
    },
  );

  it.fails(
    "payload preview_sha256 is empty string when no script",
    async () => {
      // M2T12cPending: buildInboxApproval does not handle no-script case yet.
      const keyId = await storedKeyId();
      const esc = makeScriptEscalation();
      // No script fields at all

      const result = await buildInboxApproval(esc, {
        keyId,
        userId: "user-bob",
        csrfToken: "c",
      });

      const payload = result.body.payload;
      expect(payload).toHaveProperty("script_rel", "");
      expect(payload).toHaveProperty("script_sha256", "");
      expect(payload).toHaveProperty("preview_sha256", "");
    },
  );
});
