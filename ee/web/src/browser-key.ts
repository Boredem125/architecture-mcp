/**
 * Browser key generation and management (D5.1, D5.2).
 *
 * Keys are WebCrypto Ed25519, non-extractable private key, stored in
 * IndexedDB.  The binding mirrors the T7 signer-link flow: the user
 * generates a key pair, submits the public key to POST /api/v1/signer-links
 * with kind=browser, and an admin includes it in a registry version.
 *
 * The private key MUST be non-extractable.  The public key IS extractable
 * (needed for key_id computation and server submission).
 */

/**
 * Generate an Ed25519 key pair.
 *
 * - Private key: non-extractable, usages = ["sign"]
 * - Public key: extractable, usages = ["verify"]
 */
export async function generateBrowserKeyPair(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey(
    "Ed25519",
    false, // extractable = false (private key non-extractable)
    ["sign", "verify"],
  ) as Promise<CryptoKeyPair>;
}

/**
 * Export the raw bytes of an Ed25519 public key (32 bytes).
 */
export async function exportPublicKey(
  publicKey: CryptoKey,
): Promise<ArrayBuffer> {
  return crypto.subtle.exportKey("raw", publicKey);
}

/** Convert an ArrayBuffer to a lowercase hex string. */
function bufToHex(buf: ArrayBuffer): string {
  return Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * Compute the key_id: SHA-256 hex digest of the raw public key bytes.
 * Matches the Python connector's ``sha256(raw_public_key).hex()``.
 */
export async function computeKeyId(
  raw: ArrayBuffer,
): Promise<string> {
  const hash = await crypto.subtle.digest("SHA-256", raw);
  return bufToHex(hash);
}

/**
 * Build the request for POST /api/v1/signer-links (kind=browser).
 *
 * Returns the body and headers.  The caller supplies the CSRF token
 * from the session.  The private key never appears in the request.
 */
export async function buildKeyLinkRequest(
  csrfToken?: string,
): Promise<{
  body: Record<string, unknown>;
  headers: Record<string, string>;
}> {
  const keyPair = await generateBrowserKeyPair();
  const raw = await exportPublicKey(keyPair.publicKey);
  const keyId = await computeKeyId(raw);
  const publicKeyHex = bufToHex(raw);

  return {
    body: {
      public_key: publicKeyHex,
      key_id: keyId,
      kind: "browser",
    },
    headers: {
      "Content-Type": "application/json",
      "X-CSRF-Token": csrfToken ?? "",
    },
  };
}
