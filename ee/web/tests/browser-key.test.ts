/**
 * T13 tests-first: browser key generation and IndexedDB storage.
 *
 * RED: these tests fail because the modules do not exist yet.
 *
 * D5.1: browser keys are WebCrypto Ed25519, non-extractable, stored in
 * IndexedDB.  The binding mirrors the T7 signer link flow: the user
 * generates a key pair, submits the public key to the server, and an
 * admin includes it in a registry version.
 *
 * The private key MUST be non-extractable (CryptoKey.extractable === false).
 * The public key IS extractable (needed for the key_id and for submission).
 *
 * Note: these tests run in a Node environment (vitest).  WebCrypto is
 * available in Node 19+ but IndexedDB is not.  The IndexedDB tests use
 * the storage module's interface and mock the actual IDB calls.
 */
import { describe, it, expect } from "vitest";

// @ts-expect-error Module does not exist yet (T13 RED)
import { generateBrowserKeyPair, exportPublicKey, computeKeyId } from "../src/browser-key";

// @ts-expect-error Module does not exist yet (T13 RED)
import { storeKey, loadKey, KEY_STORE_NAME } from "../src/key-store";

describe("generateBrowserKeyPair", () => {
  it("generates an Ed25519 key pair", async () => {
    const keyPair = await generateBrowserKeyPair();
    expect(keyPair).toHaveProperty("publicKey");
    expect(keyPair).toHaveProperty("privateKey");
  });

  it("private key is non-extractable", async () => {
    const keyPair = await generateBrowserKeyPair();
    expect(keyPair.privateKey.extractable).toBe(false);
  });

  it("public key is extractable", async () => {
    const keyPair = await generateBrowserKeyPair();
    expect(keyPair.publicKey.extractable).toBe(true);
  });

  it("key algorithm is Ed25519", async () => {
    const keyPair = await generateBrowserKeyPair();
    expect(keyPair.privateKey.algorithm.name).toBe("Ed25519");
    expect(keyPair.publicKey.algorithm.name).toBe("Ed25519");
  });

  it("private key usages include sign only", async () => {
    const keyPair = await generateBrowserKeyPair();
    expect(keyPair.privateKey.usages).toContain("sign");
    expect(keyPair.privateKey.usages).not.toContain("verify");
  });
});

describe("exportPublicKey", () => {
  it("exports public key as raw bytes (32 bytes for Ed25519)", async () => {
    const keyPair = await generateBrowserKeyPair();
    const raw = await exportPublicKey(keyPair.publicKey);
    // Ed25519 public key is 32 bytes
    expect(raw.byteLength).toBe(32);
  });
});

describe("computeKeyId", () => {
  it("computes SHA-256 hex digest of the raw public key", async () => {
    const keyPair = await generateBrowserKeyPair();
    const raw = await exportPublicKey(keyPair.publicKey);
    const keyId = await computeKeyId(raw);
    // SHA-256 hex is 64 chars
    expect(keyId).toHaveLength(64);
    expect(keyId).toMatch(/^[0-9a-f]{64}$/);
  });
});

describe("key store (IndexedDB interface)", () => {
  it("KEY_STORE_NAME is defined", () => {
    expect(typeof KEY_STORE_NAME).toBe("string");
    expect(KEY_STORE_NAME.length).toBeGreaterThan(0);
  });

  it("storeKey and loadKey are callable", () => {
    expect(typeof storeKey).toBe("function");
    expect(typeof loadKey).toBe("function");
  });
});
