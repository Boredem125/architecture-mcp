/**
 * Approval inbox section (T12b-2; T12c c5 review fixes).
 *
 * Renders: browser key status, pending escalations list (text-only via
 * renderEscalationText), Approve/Deny buttons.  Approve hidden on prod
 * or absent environment.  All POSTs carry X-CSRF-Token.
 */

import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useState, useEffect, useCallback, useMemo } from "react";
import { fetchEscalations, postDecision } from "./api/client";
import {
  renderEscalationText,
  buildInboxApproval,
  buildInboxDeny,
  approveEnabled,
} from "./inbox";
import type { InboxEscalation, HashState } from "./inbox";
import { canDeny } from "./escalation-rules";
import { loadKey } from "./key-store";
import { buildKeyLinkRequest } from "./browser-key";

// ---------------------------------------------------------------------------
// Script preview hash helper (T12c, ADR 0010 s9.5)
// ---------------------------------------------------------------------------

/** Compute SHA-256 hex of a string via WebCrypto (UTF-8 encoded). */
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
// Browser key status
// ---------------------------------------------------------------------------

/** Scan IndexedDB / memStore for any stored key_id. */
async function findStoredKeyId(): Promise<string | null> {
  // In the real browser this would list IndexedDB keys; for now we check
  // localStorage for the last enrolled key_id (set during the link flow).
  if (typeof localStorage !== "undefined") {
    return localStorage.getItem("agg_browser_key_id");
  }
  return null;
}

function BrowserKeyStatus({
  keyId,
  onEnrolled,
  csrfToken,
}: {
  keyId: string | null;
  onEnrolled: (id: string) => void;
  csrfToken: string;
}) {
  const [enrolling, setEnrolling] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleEnroll = useCallback(async () => {
    setEnrolling(true);
    setError(null);
    try {
      const req = await buildKeyLinkRequest(csrfToken);
      const res = await fetch("/api/v1/signer-links", {
        method: "POST",
        credentials: "same-origin",
        headers: req.headers,
        body: JSON.stringify(req.body),
      });
      if (!res.ok) {
        throw new Error(`Enroll failed: ${res.status}`);
      }
      const newKeyId = req.body.key_id as string;
      if (typeof localStorage !== "undefined") {
        localStorage.setItem("agg_browser_key_id", newKeyId);
      }
      onEnrolled(newKeyId);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setEnrolling(false);
    }
  }, [csrfToken, onEnrolled]);

  if (keyId) {
    return (
      <div data-testid="key-status">
        Browser key: {keyId.slice(0, 16)}...
      </div>
    );
  }

  return (
    <div data-testid="key-status">
      <span>No browser key enrolled.</span>
      <button
        type="button"
        onClick={handleEnroll}
        disabled={enrolling}
      >
        {enrolling ? "Enrolling..." : "Enroll browser key"}
      </button>
      {error && <span data-testid="key-error">{error}</span>}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Single escalation row
// ---------------------------------------------------------------------------

function EscalationRow({
  esc,
  keyId,
  csrfToken,
  userId,
}: {
  esc: InboxEscalation;
  keyId: string | null;
  csrfToken: string;
  userId: string;
}) {
  const queryClient = useQueryClient();
  const [status, setStatus] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  // T12c c5 review: hash state starts "pending" (Approve disabled)
  // until the WebCrypto result resolves.  A cancel flag prevents a
  // stale promise from clearing a mismatch (item 3).
  const previewText = esc.script_preview?.text ?? null;
  const previewSha = esc.script_preview?.sha256 ?? null;

  const [hashState, setHashState] = useState<HashState>(
    previewText != null && previewSha ? "pending" : "na",
  );

  useEffect(() => {
    if (previewText != null && previewSha) {
      setHashState("pending");
      let cancelled = false;
      sha256Hex(previewText).then((computed) => {
        if (!cancelled) {
          setHashState(computed === previewSha ? "match" : "mismatch");
        }
      });
      return () => {
        cancelled = true;
      };
    }
    setHashState("na");
    return undefined;
  }, [previewText, previewSha]);

  // useMemo: rendered body text depends only on previewText (item 7).
  const renderedBody = useMemo(
    () =>
      previewText != null
        ? renderEscalationText(previewText, { body: true })
        : null,
    [previewText],
  );

  // T12c c5 review: one pure helper gates Approve.
  const showApprove = approveEnabled(esc, hashState);
  const showDeny = canDeny({
    environment: esc.environment,
    status: esc.status,
  });

  const handleDecision = useCallback(
    async (decision: "approve" | "deny") => {
      if (!keyId) {
        setStatus("Error: no browser key enrolled");
        return;
      }
      setBusy(true);
      setStatus(null);
      try {
        const loaded = await loadKey(keyId);
        if (!loaded) {
          setStatus("Error: key not found in store");
          return;
        }
        const builder =
          decision === "approve" ? buildInboxApproval : buildInboxDeny;
        const result = await builder(esc, {
          keyId,
          userId,
          csrfToken,
        });
        const resp = await postDecision(esc.escalation_id, result);
        setStatus(`${decision}: ${resp.status} ${resp.detail}`);
        queryClient.invalidateQueries({ queryKey: ["escalations"] });
      } catch (e) {
        setStatus(
          `Error: ${e instanceof Error ? e.message : String(e)}`,
        );
      } finally {
        setBusy(false);
      }
    },
    [esc, keyId, csrfToken, userId, queryClient],
  );

  return (
    <tr data-testid="escalation-row">
      <td>{renderEscalationText(esc.project_id)}</td>
      <td>{renderEscalationText(esc.environment)}</td>
      <td>{renderEscalationText(esc.command)}</td>
      <td>{renderEscalationText(esc.device_id)}</td>
      <td>{esc.exec_cwd ? renderEscalationText(esc.exec_cwd) : ""}</td>
      <td>{esc.root ? renderEscalationText(esc.root) : ""}</td>
      <td>{esc.requires_dual ? "dual" : "single"}</td>
      <td data-testid="esc-details">
        <details>
          <summary>binding</summary>
          <dl>
            <dt>escalation_id</dt>
            <dd>{renderEscalationText(esc.escalation_id)}</dd>
            <dt>request_id</dt>
            <dd>{renderEscalationText(esc.request_id)}</dd>
            <dt>org_id</dt>
            <dd>{renderEscalationText(esc.org_id)}</dd>
            <dt>fingerprint</dt>
            <dd>{renderEscalationText(esc.fingerprint)}</dd>
            {esc.kind != null && (
              <>
                <dt>kind</dt>
                <dd>{renderEscalationText(esc.kind)}</dd>
              </>
            )}
            {esc.tool_name != null && (
              <>
                <dt>tool_name</dt>
                <dd>{renderEscalationText(esc.tool_name)}</dd>
              </>
            )}
            {esc.bundle_sequence != null && (
              <>
                <dt>bundle_sequence</dt>
                <dd>{String(esc.bundle_sequence)}</dd>
              </>
            )}
          </dl>
        </details>
      </td>
      {/* T12c: script panel (ADR 0010 s9.5) */}
      <td data-testid="script-panel">
        {esc.script != null && (
          <details>
            <summary>script: {renderEscalationText(esc.script.rel)}</summary>
            <dl>
              <dt>rel</dt>
              <dd>{renderEscalationText(esc.script.rel)}</dd>
              <dt>sha256</dt>
              <dd>{esc.script.sha256}</dd>
              <dt>size</dt>
              <dd>{String(esc.script.size)}</dd>
              {esc.script.family != null && (
                <>
                  <dt>family</dt>
                  <dd>{esc.script.family}</dd>
                </>
              )}
            </dl>
            <p>Only {renderEscalationText(esc.script.rel)} is bound. Files it loads are not.</p>
            {renderedBody != null ? (
              <pre data-testid="script-body">{renderedBody}</pre>
            ) : (
              <p>approve in the CLI</p>
            )}
            {hashState === "mismatch" && (
              <p data-testid="hash-mismatch">approve in the CLI</p>
            )}
          </details>
        )}
      </td>
      <td>
        {showApprove && (
          <button
            type="button"
            data-testid="approve-btn"
            disabled={busy}
            onClick={() => handleDecision("approve")}
          >
            Approve
          </button>
        )}
        {!showApprove && esc.script != null && hashState === "mismatch" && (
          <span data-testid="cli-fallback">approve in the CLI</span>
        )}
        {showDeny && (
          <button
            type="button"
            data-testid="deny-btn"
            disabled={busy}
            onClick={() => handleDecision("deny")}
          >
            Deny
          </button>
        )}
      </td>
      <td data-testid="row-status">{status}</td>
    </tr>
  );
}

// ---------------------------------------------------------------------------
// Inbox section (exported for App.tsx)
// ---------------------------------------------------------------------------

export default function InboxSection({
  csrfToken,
  userId,
}: {
  csrfToken: string;
  userId: string;
}) {
  const [keyId, setKeyId] = useState<string | null>(null);

  useEffect(() => {
    findStoredKeyId().then(setKeyId);
  }, []);

  const { data, isLoading, error } = useQuery<InboxEscalation[], Error>({
    queryKey: ["escalations"],
    queryFn: fetchEscalations,
    refetchInterval: 5000,
  });

  return (
    <section data-testid="inbox-section">
      <h2>Approval Inbox</h2>
      <BrowserKeyStatus
        keyId={keyId}
        onEnrolled={setKeyId}
        csrfToken={csrfToken}
      />
      {isLoading && <p>Loading escalations...</p>}
      {error && <p data-testid="inbox-error">{error.message}</p>}
      {data && data.length === 0 && <p>No pending escalations.</p>}
      {data && data.length > 0 && (
        <table>
          <thead>
            <tr>
              <th>Project</th>
              <th>Environment</th>
              <th>Command</th>
              <th>Device</th>
              <th>CWD</th>
              <th>Root</th>
              <th>Control</th>
              <th>Details</th>
              <th>Script</th>
              <th>Actions</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            {data.map((esc) => (
              <EscalationRow
                key={esc.escalation_id}
                esc={esc}
                keyId={keyId}
                csrfToken={csrfToken}
                userId={userId}
              />
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}
