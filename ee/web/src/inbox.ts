/**
 * Approval inbox module (T12b-2, C9 item 8; T12c c5 review fixes).
 *
 * - renderEscalationText: escapes server text for safe display.
 * - buildInboxApproval: signs approve with stored key from IndexedDB,
 *   refuses prod/absent environment, refuses empty CSRF, verifies
 *   preview hash with WebCrypto, refuses unsafe fields (defence in
 *   depth) and script without preview.
 * - buildInboxDeny: signs deny with stored key, allowed on prod.
 * - approveEnabled: pure helper the component uses.
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
  /** T12c: script metadata (rel, sha256, size, family). Separate from preview. */
  script?: {
    rel: string;
    sha256: string;
    size: number;
    family?: string;
  } | null;
  /** T12c: script preview body and its hash, stored separately on the server. */
  script_preview?: {
    text: string;
    sha256: string;
  } | null;
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

/**
 * Hash verification state for the script preview (T12c c5 review).
 * - ``"na"``: no script preview, hash check not applicable.
 * - ``"pending"``: WebCrypto hash computation in progress.
 * - ``"match"``: computed hash matches server hash.
 * - ``"mismatch"``: computed hash does not match server hash.
 */
export type HashState = "na" | "pending" | "match" | "mismatch";

// ---------------------------------------------------------------------------
// Text sanitiser (C9 item 8: no dangerouslySetInnerHTML; S2-web bidi)
// ---------------------------------------------------------------------------
//
// Regex character classes built via new RegExp() to avoid literal
// invisible characters in the source (U+2028/U+2029 would be
// interpreted as line terminators inside a regex literal).
//
// U+FEFF stays allowed (ADR 0010 s7 named limit).

// Character ranges shared across all four regexes.
const _DEL = "\u007f";
const _C1 = "\u0080-\u009f";
const _SURROGATES = "\uD800-\uDFFF";
const _BIDI = "؜‎‏‪-‮⁦-⁩";

/** Field (non-body) regex: all C0, DEL, C1, surrogates, bidi. */
const _UNSAFE_DISPLAY_RE = new RegExp(
  "[" +
    "\u0000-\u001f" + _DEL + _C1 + _SURROGATES + _BIDI +
  "]",
  "g",
);

/**
 * Body regex: excludes tab (U+0009) and LF (U+000A); includes
 * CR (U+000D) because the caller normalises CRLF first.
 * Also matches U+2028 (LS) and U+2029 (PS).
 */
const _UNSAFE_SCRIPT_BODY_RE = new RegExp(
  "[" +
    "\u0000-\u0008\u000b-\u001f" + _DEL + _C1 + _SURROGATES +
    String.fromCharCode(0x2028, 0x2029) + _BIDI +
  "]",
  "g",
);

/** Field detection (no /g): same class as display. */
const _UNSAFE_DETECT_RE = new RegExp(
  "[" +
    "\u0000-\u001f" + _DEL + _C1 + _SURROGATES + _BIDI +
  "]",
);

/** Body detection (no /g): same class as body. */
const _UNSAFE_BODY_DETECT_RE = new RegExp(
  "[" +
    "\u0000-\u0008\u000b-\u001f" + _DEL + _C1 + _SURROGATES +
    String.fromCharCode(0x2028, 0x2029) + _BIDI +
  "]",
);

/** Lowercase hex SHA-256 hash pattern (item 4: fail closed on
 *  non-hex or uppercase server values). */
const _VALID_SHA256_HEX = /^[0-9a-f]{64}$/;

/** Escape a single code point as ``[U+XXXX]``. */
function _escapeCodePoint(ch: string): string {
  return `[U+${ch.codePointAt(0)!.toString(16).toUpperCase().padStart(4, "0")}]`;
}

/**
 * Sanitise server text for display as React text content.
 *
 * **Non-body mode** (default): all C0/C1 controls (NUL included),
 * DEL, surrogates and Unicode bidi controls are escaped as
 * ``[U+XXXX]``.
 *
 * **Body mode** (``opts.body === true``): treated as a script
 * preview body (ADR 0010 s9.5).  CRLF renders as a line break;
 * lone CR is escaped as ``[U+000D]``.  Tab and LF are rendered as
 * layout; all other C0/C1/DEL/surrogates/bidi/LS/PS controls are
 * escaped.  Each line is prepended with its line number.  A tab in
 * a single-line body stays a tab (it is allowed).  The output is
 * plain text; React JSX ``{text}`` renders it safely.
 */
export function renderEscalationText(
  text: string,
  opts?: { body?: boolean },
): string {
  if (opts?.body) {
    // Body mode: CRLF -> LF (line break), then escape lone CR and
    // other unsafe body chars, then split on LF and add line numbers.
    const normalized = text.replace(/\r\n/g, "\n");
    const escaped = normalized.replace(_UNSAFE_SCRIPT_BODY_RE, _escapeCodePoint);
    const lines = escaped.split("\n");
    const width = String(lines.length).length;
    return lines
      .map((line, i) => `${String(i + 1).padStart(width)}  ${line}`)
      .join("\n");
  }
  // Non-body: escape all C0/C1 controls, DEL, surrogates and bidi.
  return text.replace(_UNSAFE_DISPLAY_RE, _escapeCodePoint);
}

/**
 * Return ``true`` when *text* contains any C0/C1 control, DEL,
 * surrogate, or Unicode bidi control character.  The caller should
 * disable Approve for escalation rows where any displayed field
 * tests positive (S2-web): the escaped display would not match the
 * raw signed value.
 */
export function hasUnsafeControlChars(text: string): boolean {
  return _UNSAFE_DETECT_RE.test(text);
}

/**
 * F3 fix: ONE helper that checks every displayed-or-signed string
 * field of an escalation for unsafe control characters.
 * ``approveEnabled`` uses this; Approve is disabled when it returns
 * ``true``.
 *
 * Covers: command, project_id, environment, fingerprint, device_id,
 * request_id, org_id, escalation_id, exec_cwd, root, kind,
 * tool_name, script.rel (ADR 0010 s7: in rel nothing is allowed),
 * and script_preview.text (tab/LF allowed after CRLF normalisation;
 * all other controls unsafe, including lone CR, LS and PS).
 * Numeric and boolean fields are skipped (they are not strings).
 */
export function escalationHasUnsafeField(esc: InboxEscalation): boolean {
  const s = (v: string | number | boolean | null | undefined): boolean =>
    typeof v === "string" && hasUnsafeControlChars(v);
  if (
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
  ) {
    return true;
  }
  // ADR 0010 s7: in rel nothing is allowed (all C0/DEL/C1/bidi/surrogates).
  if (esc.script?.rel != null && hasUnsafeControlChars(esc.script.rel)) {
    return true;
  }
  // ADR 0010 s9.5: in body, tab/LF allowed; CRLF is a line break (ok);
  // lone CR, C0 (rest), DEL, C1, bidi, surrogates, LS and PS are unsafe.
  if (esc.script_preview?.text != null) {
    const normalized = esc.script_preview.text.replace(/\r\n/g, "\n");
    if (_UNSAFE_BODY_DETECT_RE.test(normalized)) {
      return true;
    }
  }
  return false;
}

// ---------------------------------------------------------------------------
// Approve-enabled helper (T12c c5 review)
// ---------------------------------------------------------------------------

/**
 * Pure function: whether Approve is enabled for this escalation and
 * hash state.  The component and tests both use this; it makes the
 * gate testable without a DOM.
 */
export function approveEnabled(
  esc: InboxEscalation,
  hashState: HashState,
): boolean {
  // Environment / status / preview-mismatch gate.
  if (
    !canApprove({
      environment: esc.environment,
      status: esc.status,
      scriptPreviewMismatch: hashState === "mismatch",
    })
  ) {
    return false;
  }
  // Unsafe control chars in any displayed-or-signed field.
  if (escalationHasUnsafeField(esc)) return false;
  // Script present but preview missing or incomplete (bug 1 UI side).
  if (esc.script != null && !esc.script_preview?.sha256) return false;
  // Hash still computing (item 3).
  if (hashState === "pending") return false;
  return true;
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
 * For "approve": refuses prod or absent environment; refuses unsafe
 * fields (defence in depth, bug 2); refuses script without preview
 * (bug 1); verifies preview hash with WebCrypto (T12c, ADR 0010
 * s9.5); validates server hash format (item 4).
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

    // Defence in depth (bug 2): refuse if any field has unsafe
    // control chars.  The UI disables Approve, but the signer must
    // also refuse independently.
    if (escalationHasUnsafeField(esc)) {
      throw new Error(
        "Approve refused: escalation contains unsafe control characters",
      );
    }

    // Bug 1: a script record without a preview is malformed; refuse
    // approve.  Deny is still allowed (it only stops an action).
    if (
      esc.script != null &&
      (esc.script_preview?.text == null || !esc.script_preview?.sha256)
    ) {
      throw new Error(
        "Approve refused: script present but preview missing or incomplete",
      );
    }
  }

  // T12c: script preview integrity check (ADR 0010 s9.5).
  // Recompute SHA-256 of the displayed body with WebCrypto and refuse
  // to sign on a mismatch.  Only for approve: deny can always proceed.
  //
  // NOTE (item 5): preview_sha256 and script_sha256 may legitimately
  // differ.  The preview can be redacted by the server scrubber, so
  // its hash binds the displayed text, while script.sha256 binds the
  // raw file bytes.  No equality check between them.
  let previewSha256 = "";
  if (esc.script_preview != null && esc.script_preview.text != null) {
    const previewBytes = new TextEncoder().encode(esc.script_preview.text);
    const hashBuf = await crypto.subtle.digest("SHA-256", previewBytes);
    previewSha256 = bufToHex(hashBuf);
    if (decision === "approve") {
      // Item 4: validate server hash format before comparing.
      // A non-hex or uppercase server hash fails closed.
      if (!_VALID_SHA256_HEX.test(esc.script_preview.sha256)) {
        throw new Error(
          "Script preview integrity check failed: invalid server hash format",
        );
      }
      if (previewSha256 !== esc.script_preview.sha256) {
        throw new Error(
          "Script preview integrity check failed: preview hash mismatch",
        );
      }
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
  // (connector approval.py) and the server required_fields
  // (escalations.py).  reviewer_id = the session user who is deciding;
  // registry_version comes from the server escalation data.
  // T12c adds script_rel, script_sha256 and preview_sha256 (always
  // present, "" when no script; ADR 0010 s9.5).
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
    script_rel: esc.script?.rel ?? "",
    script_sha256: esc.script?.sha256 ?? "",
    preview_sha256: previewSha256,
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
