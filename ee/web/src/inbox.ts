/**
 * Approval inbox module (T12b-2, C9 item 8).
 *
 * - renderEscalationText: HTML-escapes server text for safe display.
 * - buildInboxApproval: signs approve with stored key from IndexedDB,
 *   refuses prod/absent environment, refuses empty CSRF.
 * - buildInboxDeny: signs deny with stored key, allowed on prod.
 * - InboxEscalation: type for server escalation objects.
 *
 * The private key is LOADED from IndexedDB via key-store.ts.
 * No key is ever generated in the approve/deny path.
 */

import { loadKey } from "./key-store";
import { exportPublicKey, computeKeyId } from "./browser-key";
import { canonicalBytes, REMOTE_APPROVAL_TAG } from "./signing";
import { canApprove } from "./escalation-rules";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** Shape of an escalation as returned by GET /api/v1/escalations. */
export interface InboxEscalation {
  escalation_id: string;
  request_id: string;
  command: string;
  fingerprint: string;
  device_id: string;
  project_id: string;
  org_id: string;
  policy_sequence: number;
  requires_dual: boolean;
  environment: string;
  status: string;
  /** Working directory the command executes in (server may omit). */
  exec_cwd?: string;
  /** Project root (server may omit). */
  root?: string;
  /** Registry version at escalation time (server may omit). */
  registry_version?: number | null;
  /** Fingerprint kind (backend adds in T12b-2; may be absent on older servers). */
  kind?: string;
  /** Tool name from the hook (backend adds in T12b-2; may be absent). */
  tool_name?: string;
  /** Bundle sequence at escalation time (backend adds in T12b-2; may be absent). */
  bundle_sequence?: number | null;
}

/** Options the caller supplies from the session state. */
export interface InboxSignOpts {
  keyId: string;
  userId: string;
  csrfToken: string;
}

/** The signed envelope returned to the caller, ready for POST. */
export interface InboxDecisionResult {
  body: {
    kind: string;
    sig_v: number;
    payload: Record<string, unknown>;
    signatures: Array<{ key_id: string; alg: string; sig: string }>;
  };
  headers: Record<string, string>;
}

// ---------------------------------------------------------------------------
// Text sanitiser (C9 item 8: no dangerouslySetInnerHTML; S2-web bidi)
// ---------------------------------------------------------------------------

/**
 * Regex matching C0 controls (U+0000-001F, NUL included), DEL (U+007F),
 * C1 controls (U+0080-009F), and Unicode bidi/direction controls
 * (U+061C, U+200E, U+200F, U+202A-202E, U+2066-2069).
 *
 * F4 fix: NUL is shown as [U+0000], not stripped, so ``rm \0-rf /``
 * and ``rm -rf /`` render differently in the Deny view.
 */
const _UNSAFE_DISPLAY_RE =
  // eslint-disable-next-line no-control-regex
  /[\u0000-\u001f\u007f\u0080-\u009f؜‎‏‪-‮⁦-⁩]/g;

/**
 * Regex for *detecting* any unsafe control character (includes NUL).
 * Used by ``hasUnsafeControlChars`` to flag rows where displayed text
 * would differ from the raw signed value.
 */
const _UNSAFE_DETECT_RE =
  // eslint-disable-next-line no-control-regex
  /[\u0000-\u001f\u007f\u0080-\u009f؜‎‏‪-‮⁦-⁩]/;

/**
 * Sanitise server text for display as React text content.
 *
 * React already escapes text rendered via ``{text}`` in JSX, so no
 * manual HTML entity escaping is needed.  All C0/C1 controls (NUL
 * included), DEL, and Unicode bidi controls are escaped as
 * ``[U+XXXX]`` so the human reviewer sees exactly what the text
 * contains.  F4 fix: NUL is shown as ``[U+0000]``, not stripped,
 * so two server values differing only by a NUL byte render
 * differently in the Deny view.
 */
export function renderEscalationText(text: string): string {
  return text.replace(
    _UNSAFE_DISPLAY_RE,
    (ch) => `[U+${ch.codePointAt(0)!.toString(16).toUpperCase().padStart(4, "0")}]`,
  );
}

/**
 * Return ``true`` when *text* contains any C0/C1 control, DEL, or
 * Unicode bidi control character.  The caller should disable Approve
 * for escalation rows where any displayed field tests positive (S2-web):
 * the escaped display would not match the raw signed value.
 */
export function hasUnsafeControlChars(text: string): boolean {
  return _UNSAFE_DETECT_RE.test(text);
}

/**
 * F3 fix: ONE helper that checks every displayed-or-signed string field
 * of an escalation for unsafe control characters.  InboxSection uses
 * only this helper; Approve is disabled when it returns ``true``.
 *
 * Covers: command, project_id, environment, fingerprint, device_id,
 * request_id, org_id, escalation_id, exec_cwd, root, kind, tool_name.
 * Numeric and boolean fields are skipped (they are not strings).
 */
export function escalationHasUnsafeField(esc: InboxEscalation): boolean {
  const s = (v: string | number | boolean | null | undefined): boolean =>
    typeof v === "string" && hasUnsafeControlChars(v);
  return (
    s(esc.command) ||
    s(esc.project_id) ||
    s(esc.environment) ||
    s(esc.fingerprint) ||
    s(esc.device_id) ||
    s(esc.request_id) ||
    s(esc.org_id) ||
    s(esc.escalation_id) ||
    s(esc.exec_cwd) ||
    s(esc.root) ||
    s(esc.kind) ||
    s(esc.tool_name)
  );
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/** Convert an ArrayBuffer to a lowercase hex string. */
function bufToHex(buf: ArrayBuffer): string {
  return Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * Load the stored key from IndexedDB and return it with its computed
 * key_id.  Throws if no key is found for the given keyId.
 */
async function requireStoredKey(
  keyId: string,
): Promise<{ keyPair: CryptoKeyPair; keyId: string }> {
  const keyPair = await loadKey(keyId);
  if (!keyPair) {
    throw new Error(`No key found for key_id: ${keyId}`);
  }
  return { keyPair, keyId };
}

/**
 * Build and sign a decision envelope.
 *
 * Uses the stored key from IndexedDB (never generates a new key).
 * Validates CSRF token is non-empty.
 * For "approve", refuses prod or absent environment.
 */
async function buildInboxDecision(
  esc: InboxEscalation,
  opts: InboxSignOpts,
  decision: "approve" | "deny",
): Promise<InboxDecisionResult> {
  // Validate CSRF token
  if (!opts.csrfToken) {
    throw new Error("CSRF token required");
  }

  // For approve: refuse prod and absent environment
  if (decision === "approve") {
    if (!canApprove({ environment: esc.environment, status: esc.status || "pending" })) {
      throw new Error("Approve not allowed on prod or absent environment");
    }
  }

  // Load stored key (never generate)
  const { keyPair } = await requireStoredKey(opts.keyId);

  const rawPub = await exportPublicKey(keyPair.publicKey);
  const computedKeyId = await computeKeyId(rawPub);

  // Nonce: 32 random bytes as hex
  const nonceBytes = new Uint8Array(32);
  crypto.getRandomValues(nonceBytes);
  const nonce = bufToHex(nonceBytes.buffer);

  const now = Date.now() / 1000;
  const notAfter = now + 15 * 60;

  // Build the D5.6 payload: every field in _REMOTE_APPROVAL_FIELDS
  // (connector approval.py) and the server's required_fields
  // (escalations.py).  reviewer_id = the session user who is deciding;
  // registry_version comes from the server escalation data.
  const payload: Record<string, unknown> = {
    request_id: esc.request_id,
    command: esc.command,
    fingerprint: esc.fingerprint ?? "",
    reviewer_id: opts.userId,
    decision,
    approved_at: now,
    org_id: esc.org_id,
    project_id: esc.project_id,
    device_id: esc.device_id,
    registry_version: esc.registry_version ?? null,
    policy_sequence: esc.policy_sequence,
    user_id: opts.userId,
    key_id: computedKeyId,
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
          key_id: computedKeyId,
          alg: "ed25519",
          sig: sigHex,
        },
      ],
    },
    headers: {
      "Content-Type": "application/json",
      "X-CSRF-Token": opts.csrfToken,
    },
  };
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Build a signed approval for the given escalation.
 *
 * Uses the key stored in IndexedDB (never generates a new key).
 * Refuses prod or absent environment.  Refuses empty CSRF token.
 */
export async function buildInboxApproval(
  esc: InboxEscalation,
  opts: InboxSignOpts,
): Promise<InboxDecisionResult> {
  return buildInboxDecision(esc, opts, "approve");
}

/**
 * Build a signed deny for the given escalation.
 *
 * Uses the key stored in IndexedDB (never generates a new key).
 * Deny is allowed on prod.  Refuses empty CSRF token.
 */
export async function buildInboxDeny(
  esc: InboxEscalation,
  opts: InboxSignOpts,
): Promise<InboxDecisionResult> {
  return buildInboxDecision(esc, opts, "deny");
}
