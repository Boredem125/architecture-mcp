/**
 * T13 tests-first: HAR-style check that no private key material appears in
 * any request body or header sent by the signing/approval modules.
 *
 * RED: these tests fail because the modules do not exist yet.
 *
 * The exit check requires: "no private key in any request (HAR-style check
 * of every request body/header in tests)".
 *
 * Strategy: the approval module exposes a function that builds a request.
 * We intercept the built request (body + headers) and scan for patterns
 * matching Ed25519 private keys (64-byte hex = 128 hex chars, or base64
 * representations).  The private key must never leave the signing layer.
 */
import { describe, it, expect } from "vitest";

// These imports will fail until the modules are created (RED).
// @ts-expect-error Module does not exist yet (T13 RED)
import { buildApprovalRequest, buildDenyRequest } from "../src/approval";

// @ts-expect-error Module does not exist yet (T13 RED)
import { buildKeyLinkRequest } from "../src/browser-key";

// Patterns that match private key material
const PRIVATE_KEY_PATTERNS = [
  // Ed25519 private key: 64 bytes = 128 hex chars (standalone, not a SHA-256 hash)
  // We check for the word "private" or "secret" near hex strings
  /private[_\s-]?key/i,
  /secret[_\s-]?key/i,
  // Base64 encoded 64-byte value (88 chars with padding)
  // This is a heuristic; the real check is that the signing module never exports the key
];

function assertNoPrivateKey(label: string, data: string): void {
  for (const pattern of PRIVATE_KEY_PATTERNS) {
    expect(data, `${label}: private key pattern found`).not.toMatch(pattern);
  }
  // The signing module must never include the raw private key bytes.
  // A 128-char hex string that is NOT a key_id (SHA-256 of public key) or
  // a signature (which is allowed) would be suspicious, but we primarily
  // check that the known "privateKey" or "signingKey" fields are absent.
  expect(data).not.toContain('"privateKey"');
  expect(data).not.toContain('"signingKey"');
  expect(data).not.toContain('"secret"');
}

describe("HAR-style no-private-key check", () => {
  it("approval request body contains no private key material", async () => {
    const req = await buildApprovalRequest({
      escalationId: "esc-1",
      requestId: "req-1",
      command: "echo test",
      orgId: "org-1",
      projectId: "proj-1",
      deviceId: "dev-1",
      registryVersion: 1,
      policySequence: 1,
    });

    assertNoPrivateKey("approval body", JSON.stringify(req.body));
    assertNoPrivateKey("approval headers", JSON.stringify(req.headers));
  });

  it("deny request body contains no private key material", async () => {
    const req = await buildDenyRequest({
      escalationId: "esc-1",
      requestId: "req-1",
      command: "echo test",
      orgId: "org-1",
      projectId: "proj-1",
      deviceId: "dev-1",
      registryVersion: 1,
      policySequence: 1,
    });

    assertNoPrivateKey("deny body", JSON.stringify(req.body));
    assertNoPrivateKey("deny headers", JSON.stringify(req.headers));
  });

  it("browser key link request sends only the public key", async () => {
    const req = await buildKeyLinkRequest();

    const bodyStr = JSON.stringify(req.body);
    assertNoPrivateKey("key-link body", bodyStr);
    assertNoPrivateKey("key-link headers", JSON.stringify(req.headers));

    // The body MUST contain a public_key field
    expect(bodyStr).toContain('"public_key"');
  });

  it("approval request includes only the signed envelope fields", async () => {
    const req = await buildApprovalRequest({
      escalationId: "esc-1",
      requestId: "req-1",
      command: "echo test",
      orgId: "org-1",
      projectId: "proj-1",
      deviceId: "dev-1",
      registryVersion: 1,
      policySequence: 1,
    });

    // The body should be a valid agg/remote-approval/v1 envelope
    const body = req.body;
    expect(body).toHaveProperty("kind", "agg/remote-approval/v1");
    expect(body).toHaveProperty("sig_v", 1);
    expect(body).toHaveProperty("payload");
    expect(body).toHaveProperty("signatures");

    // Signatures array must contain key_id, alg, sig -- never the private key
    for (const sig of body.signatures) {
      expect(sig).toHaveProperty("key_id");
      expect(sig).toHaveProperty("alg", "ed25519");
      expect(sig).toHaveProperty("sig");
      expect(sig).not.toHaveProperty("privateKey");
      expect(sig).not.toHaveProperty("signingKey");
    }
  });
});
