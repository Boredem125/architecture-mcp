/**
 * Approval / deny request builder (D5.6, D6).
 *
 * Builds a signed agg/remote-approval/v1 envelope for submission to
 * POST /api/v1/sync/escalations/{escalation_id}/approvals.
 *
 * The private key never appears in the request body or headers (HAR check).
 * Signing happens inside WebCrypto; only the signature bytes are exported.
 */

import { canonicalBytes, REMOTE_APPROVAL_TAG } from "./signing";
import {
  generateBrowserKeyPair,
  exportPublicKey,
  computeKeyId,
} from "./browser-key";

/** Convert an ArrayBuffer to a lowercase hex string. */
function bufToHex(buf: ArrayBuffer): string {
  return Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/** Parameters the caller supplies from the escalation and session. */
export interface ApprovalParams {
  escalationId: string;
  requestId: string;
  command: string;
  orgId: string;
  projectId: string;
  deviceId: string;
  registryVersion: number;
  policySequence: number;
  /** Overrides for optional fields (normally filled from the session). */
  fingerprint?: string;
  userId?: string;
  reviewerId?: string;
  csrfToken?: string;
  /** Server-provided not_after; defaults to now + 15 min. */
  notAfter?: number;
}

/** The shaped envelope returned to the caller. */
export interface ApprovalEnvelope {
  kind: string;
  sig_v: number;
  payload: Record<string, unknown>;
  signatures: Array<{ key_id: string; alg: string; sig: string }>;
}

export interface ApprovalRequest {
  body: ApprovalEnvelope;
  headers: Record<string, string>;
}

/**
 * Build a signed approval request.
 *
 * Generates a fresh browser key pair (in the real app the stored key
 * would be loaded from IndexedDB), signs the canonical bytes, and
 * returns the envelope ready for POST.
 */
export async function buildApprovalRequest(
  params: ApprovalParams,
): Promise<ApprovalRequest> {
  return buildDecisionRequest(params, "approve");
}

/**
 * Build a signed deny request.  Same structure as approve but with
 * ``decision: "deny"``.
 */
export async function buildDenyRequest(
  params: ApprovalParams,
): Promise<ApprovalRequest> {
  return buildDecisionRequest(params, "deny");
}

// -----------------------------------------------------------------------
// Internal
// -----------------------------------------------------------------------

async function buildDecisionRequest(
  params: ApprovalParams,
  decision: "approve" | "deny",
): Promise<ApprovalRequest> {
  // Key pair (in production, loaded from IndexedDB via key-store)
  const keyPair = await generateBrowserKeyPair();
  const rawPub = await exportPublicKey(keyPair.publicKey);
  const keyId = await computeKeyId(rawPub);

  // Nonce: 32 random bytes as hex (D4.1)
  const nonceBytes = new Uint8Array(32);
  crypto.getRandomValues(nonceBytes);
  const nonce = bufToHex(nonceBytes.buffer);

  const now = Date.now() / 1000;
  const notAfter = params.notAfter ?? now + 15 * 60;

  // D5.6 field set
  const payload: Record<string, unknown> = {
    request_id: params.requestId,
    command: params.command,
    fingerprint: params.fingerprint ?? "",
    reviewer_id: params.reviewerId ?? "",
    decision,
    approved_at: now,
    org_id: params.orgId,
    project_id: params.projectId,
    device_id: params.deviceId,
    registry_version: params.registryVersion,
    policy_sequence: params.policySequence,
    user_id: params.userId ?? "",
    key_id: keyId,
    nonce,
    not_after: notAfter,
  };

  // Sign: tag || 0x00 || canonical JSON
  const bytesToSign = canonicalBytes(REMOTE_APPROVAL_TAG, payload);
  const sig = await crypto.subtle.sign("Ed25519", keyPair.privateKey, bytesToSign);
  const sigHex = bufToHex(sig);

  return {
    body: {
      kind: REMOTE_APPROVAL_TAG,
      sig_v: 1,
      payload,
      signatures: [
        {
          key_id: keyId,
          alg: "ed25519",
          sig: sigHex,
        },
      ],
    },
    headers: {
      "Content-Type": "application/json",
      "X-CSRF-Token": params.csrfToken ?? "",
    },
  };
}
