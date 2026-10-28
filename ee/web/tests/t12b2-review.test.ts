/**
 * T12b-2 security review round 2, web proofs (security-engineer, leader tier).
 *
 * ``it.fails`` is vitest's strict xfail: the test passes only while the
 * assertion inside fails.  When the fix lands the body passes, ``it.fails``
 * reports a failure, and the fixing change must turn it into ``it``.
 *
 * S3 (Medium, functional, fails closed): buildInboxApproval/buildInboxDeny
 *   sign a payload without ``reviewer_id`` and ``registry_version``.  Both
 *   the server (escalations.py required_fields) and the connector
 *   (approval.py _REMOTE_APPROVAL_FIELDS) require the D5.6 field set, so
 *   every web approval and deny is refused with 400.  The web inbox path
 *   cannot complete.
 * S2-web (Low, WYSIWYS): renderEscalationText keeps Unicode bidi controls
 *   (U+202E RIGHT-TO-LEFT OVERRIDE etc.), so the displayed command can read
 *   differently from the signed one.
 */
import { describe, it, expect } from "vitest";

import { buildInboxApproval, buildInboxDeny, renderEscalationText } from "../src/inbox";
import type { InboxEscalation } from "../src/inbox";
import { generateBrowserKeyPair, exportPublicKey, computeKeyId } from "../src/browser-key";
import { storeKey } from "../src/key-store";

const D56_FIELDS = [
  "request_id", "command", "fingerprint", "reviewer_id", "decision",
  "approved_at", "org_id", "project_id", "device_id", "registry_version",
  "policy_sequence", "user_id", "key_id", "nonce", "not_after",
  // T12c additions (ADR 0010 s9.5): always present, "" when no script.
  "script_rel", "script_sha256", "preview_sha256",
];

function esc(): InboxEscalation {
  return {
    escalation_id: "esc-r2-1",
    request_id: "req-r2-1",
    command: "echo hello",
    fingerprint: "a".repeat(64),
    device_id: "dev-1",
    project_id: "proj-1",
    org_id: "org-1",
    policy_sequence: 1,
    requires_dual: true,
    environment: "staging",
    status: "pending",
  };
}

async function storedKeyId(): Promise<string> {
  const kp = await generateBrowserKeyPair();
  const kid = await computeKeyId(await exportPublicKey(kp.publicKey));
  await storeKey(kid, kp);
  return kid;
}

describe("T12b-2 review S3: the signed payload carries the D5.6 field set", () => {
  it("approve payload has every field the server and connector require", async () => {
    const keyId = await storedKeyId();
    const r = await buildInboxApproval(esc(), { keyId, userId: "user-bob", csrfToken: "c" });
    expect(Object.keys(r.body.payload).sort()).toEqual([...D56_FIELDS].sort());
  });

  it("deny payload has every field the server and connector require", async () => {
    const keyId = await storedKeyId();
    const r = await buildInboxDeny(esc(), { keyId, userId: "user-bob", csrfToken: "c" });
    expect(Object.keys(r.body.payload).sort()).toEqual([...D56_FIELDS].sort());
  });
});

describe("T12b-2 review S2-web: bidi controls are not displayed raw", () => {
  it("renderEscalationText neutralises U+202E and other bidi controls", () => {
    const shown = renderEscalationText("echo safe ‮fdm- mr‬");
    expect(/[‪-‮⁦-⁩]/.test(shown)).toBe(false);
  });
});
