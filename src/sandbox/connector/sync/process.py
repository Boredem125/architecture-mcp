"""Sandbox sync process: polls the control plane, backs off on failure (D7, D8).

This module is the **only** connector component that talks to the network.
The hook path (hook_eval) must never import it -- a guard test enforces this.

Design invariants (ADR 0001, M2 amendments A6-A7, STARTUP.md principle 1):
  - Local enforcement stays authoritative and fails closed.
  - The control plane is never required for a deny.
  - Escalations stay pending when the server is unreachable;
    no timeout auto-approve, ever.
  - The real default transport uses ``urllib.request`` with TLS verification on.
  - No socket is opened at import time.
"""
from __future__ import annotations

import json
import random
import time
from typing import Any, Callable

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: Base poll interval in seconds (decisions every 10 s).
BASE_INTERVAL: float = 10.0

#: Maximum backoff cap in seconds (5 minutes).
MAX_BACKOFF: float = 300.0

#: Bundle/registry poll cadence in seconds.
BUNDLE_CADENCE: float = 60.0


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def escalation_upload_body(
    rec: dict, device_id: str, layout=None,
) -> dict | None:
    """Build the ``{device_id, request_id, record, policy_sequence}`` body
    for ``POST /api/v1/sync/escalations`` from a flat pending record.

    Returns *None* (and logs + audits) when ``bundle_sequence`` is not an
    ``int`` (``bool`` is not ``int`` either).  Both ``run_once`` (CLI)
    and ``SyncProcess._upload_escalations`` use this so the validation
    and body shape stay in one place.
    """
    rid = rec.get("request_id", "")
    raw_seq = rec.get("bundle_sequence")
    if raw_seq is None:
        import logging as _log
        _log.getLogger("sandbox.sync.upload").warning(
            "rejected escalation %s: bundle_sequence absent", rid,
        )
        if layout is not None:
            try:
                from sandbox.connector.audit import FolderAudit
                audit_dir = layout.root / ".sandbox" / "audit"
                fa = FolderAudit(audit_dir)
                fa.append({
                    "event": "upload_rejected",
                    "request_id": rid,
                    "reason": "bundle_sequence absent",
                    "ts": __import__("time").time(),
                })
            except Exception:  # noqa: BLE001
                pass
        return None
    if isinstance(raw_seq, bool) or not isinstance(raw_seq, int):
        import logging as _log
        _log.getLogger("sandbox.sync.upload").warning(
            "rejected escalation %s: bundle_sequence not int (%r)",
            rid, type(raw_seq).__name__,
        )
        if layout is not None:
            try:
                from sandbox.connector.audit import FolderAudit
                audit_dir = layout.root / ".sandbox" / "audit"
                fa = FolderAudit(audit_dir)
                fa.append({
                    "event": "upload_rejected",
                    "request_id": rid,
                    "reason": f"bundle_sequence not int ({type(raw_seq).__name__})",
                    "ts": time.time(),
                })
            except Exception:  # noqa: BLE001
                pass
        return None
    return {
        "device_id": device_id,
        "request_id": rid,
        "record": rec,
        "policy_sequence": raw_seq,
    }


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class SyncError(Exception):
    """Raised when a sync cycle encounters a non-recoverable error."""


_LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1", "[::1]"})


def _check_url_transport(url: str) -> None:
    """T15b-2: refuse ``http://`` to a non-loopback host and any scheme
    other than http/https.  Raises :class:`SyncError` (no token text)."""
    from urllib.parse import urlparse

    parsed = urlparse(url)
    if parsed.scheme == "https":
        return
    if parsed.scheme == "http":
        host = (parsed.hostname or "").lower()
        if host in _LOOPBACK_HOSTS:
            return
        raise SyncError(f"refusing http:// to non-loopback host {host}; use https")
    raise SyncError(f"unsupported scheme: {parsed.scheme}")


# ---------------------------------------------------------------------------
# Default transport (urllib, TLS on, no socket at import time)
# ---------------------------------------------------------------------------


def _default_connect(
    method: str,
    url: str,
    body: bytes | dict | None = None,
    headers: dict[str, str] | None = None,
    token: str | None = None,
) -> tuple[int, dict, dict]:
    """HTTP transport using ``urllib.request``.  Imported lazily so no
    socket is opened at module import time.

    Uses a per-call ``build_opener(_NoRedirect).open(req, ...)`` so no
    global state is mutated and the opener cannot be replaced by another
    module.  The final-URL check remains as a belt-and-suspenders guard.
    """
    import urllib.request
    import urllib.error

    # T15b-2: https only, except loopback; refused before any socket.
    # The message never carries the token.
    _check_url_transport(url)

    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D102
            raise urllib.error.HTTPError(
                req.full_url, code, "redirect refused", headers, fp,
            )

    opener = urllib.request.build_opener(_NoRedirect)

    hdrs = dict(headers or {})
    hdrs.setdefault("Content-Type", "application/json")

    data: bytes | None = None
    if body is not None:
        data = json.dumps(body).encode() if isinstance(body, dict) else body

    req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
    if token:
        # Unredirected: never forwarded even if a redirect were followed.
        req.add_unredirected_header("Authorization", f"Bearer {token}")

    try:
        with opener.open(req, timeout=30) as resp:
            resp_body = resp.read()
            status = resp.status
            resp_headers = {k: v for k, v in resp.getheaders()}
            final_url = resp.geturl()
    except urllib.error.HTTPError as exc:
        resp_body = exc.read()
        status = exc.code
        resp_headers = {k: v for k, v in exc.headers.items()}
        final_url = url
    if final_url != url:
        raise SyncError("redirect refused: final URL differs from request URL")

    try:
        body_dict = json.loads(resp_body) if resp_body else {}
    except (json.JSONDecodeError, ValueError):
        body_dict = {}

    return (status, body_dict, resp_headers)


# ---------------------------------------------------------------------------
# SyncProcess
# ---------------------------------------------------------------------------


class SyncProcess:
    """One sync daemon instance, polling the control plane.

    Constructor seams (for testing without real I/O):

    *clock*
        ``() -> float``.  Default ``time.monotonic``.
    *connect*
        ``(method, url, body?, headers?, token?) -> (status, body_dict, headers_dict)``.
        Default: the real ``urllib.request`` transport.

    Neither seam changes security behaviour: they select the time source and
    transport, not the policy, keys, or decision logic.
    """

    def __init__(
        self,
        layout: Any,
        server_url: str,
        device_key: bytes,
        device_id: str,
        *,
        clock: Callable[[], float] | None = None,
        connect: Callable[..., tuple[int, dict, dict]] | None = None,
    ) -> None:
        self.layout = layout
        self.server_url = server_url.rstrip("/")
        self.device_key = device_key
        self.device_id = device_id

        self._clock: Callable[[], float] = clock or time.monotonic
        self._connect: Callable[..., tuple[int, dict, dict]] = connect or _default_connect

        #: Count of consecutive poll failures (drives backoff).
        self._consecutive_failures: int = 0

        #: Bearer token for server auth (refreshed by run_once).
        self._token: str | None = None
        self._token_expires: float = 0.0

        #: Escalations the server accepted (2xx) in the last cycle.
        self.uploaded_count: int = 0


# ---------------------------------------------------------------------------
# next_backoff
# ---------------------------------------------------------------------------


def next_backoff(sync: SyncProcess) -> float:
    """Return the delay (seconds) until the next poll.

    On success (``_consecutive_failures == 0``) the delay is the base
    interval (10 s) plus a small jitter.

    On failure the delay doubles each time with jitter, capped at 300 s
    (5 min).  This prevents thundering-herd retries from many connectors.
    """
    if sync._consecutive_failures == 0:
        # Base interval with small jitter
        return BASE_INTERVAL + random.uniform(0, 2)

    # Exponential backoff: base * 2^failures, capped
    raw = BASE_INTERVAL * (2 ** sync._consecutive_failures)
    capped = min(raw, MAX_BACKOFF)
    # Add jitter: uniform between 50% and 100% of the capped value
    jittered = capped * random.uniform(0.5, 1.0)
    return min(jittered, MAX_BACKOFF)


# ---------------------------------------------------------------------------
# run_once
# ---------------------------------------------------------------------------


def run_once(sync: SyncProcess) -> None:
    """Execute one poll cycle.

    Steps:
      1. Refresh the bearer token if expired.
      2. Fetch pending decisions from the server.
      3. (On the 60 s cadence) fetch registry and bundles -- via a lazy
         import of ``sandbox.connector.sync.bundles.verify_and_apply``.
      4. Upload pending escalations and audit records.

    On any transport or server error the cycle is abandoned: the failure
    counter increments and the caller uses ``next_backoff`` for the delay.

    **Critical invariant (D8, threat 12):** pending escalations are never
    auto-approved.  If the server is down, escalations stay pending.
    """
    try:
        # ---- 1. Token refresh ----
        _refresh_token(sync)

        # ---- 2. Fetch and persist registry updates (D4-1 step-5: before decisions) ----
        _fetch_registry(sync)

        # ---- 3. Fetch decisions and apply through apply_external ----
        _fetch_decisions(sync)

        # ---- 4. Fetch and verify next bundle (ADR 0001 A1) ----
        _fetch_bundle(sync)

        # ---- 5. Upload pending escalations ----
        _upload_escalations(sync)

        # ---- 6. Upload audit records and checkpoint (managed only, T11) ----
        _upload_audit(sync)

        # Success: reset failure counter
        sync._consecutive_failures = 0

    except (ConnectionError, OSError, SyncError) as exc:
        sync._consecutive_failures += 1
        raise SyncError(f"sync cycle failed: {exc}") from exc
    except Exception as exc:
        sync._consecutive_failures += 1
        raise SyncError(f"sync cycle failed: {exc}") from exc


# ---------------------------------------------------------------------------
# run_loop
# ---------------------------------------------------------------------------


def run_loop(sync: SyncProcess) -> None:
    """Run ``run_once`` in a loop with backoff, exiting on KeyboardInterrupt.

    This is what ``sandbox sync`` (without ``--once``) calls.  The loop
    runs ``run_once`` followed by ``time.sleep(next_backoff(sync))``.
    A ``SyncError`` from ``run_once`` is caught and the loop continues
    (the backoff will increase).  ``KeyboardInterrupt`` exits cleanly.
    """
    try:
        while True:
            try:
                run_once(sync)
            except SyncError:
                pass  # backoff handles retries
            time.sleep(next_backoff(sync))
    except KeyboardInterrupt:
        return  # clean exit


# ---------------------------------------------------------------------------
# Internal helpers (never auto-approve, never modify pending status)
# ---------------------------------------------------------------------------


def _record_server_time(sync: SyncProcess, resp_headers: dict) -> None:
    """Record the server time from an HTTP Date header (F1, D4.3).

    The state is written to ``server_time_state.json`` through
    ``sync.state.write_server_time_state``, atomic temp-file + rename.
    ``apply_external`` reads it to compute measured skew.
    """
    if sync.layout is None:
        return
    import time as _time

    date_str = resp_headers.get("Date") or resp_headers.get("date")
    if not date_str:
        return
    try:
        from email.utils import parsedate_to_datetime

        dt = parsedate_to_datetime(date_str)
        server_time = dt.timestamp()
    except Exception:
        return

    from sandbox.connector.sync.state import write_server_time_state

    write_server_time_state(sync.layout, server_time, _time.time())


def _refresh_token(sync: SyncProcess) -> None:
    """Exchange the device key for a short-lived bearer token.

    Builds a ``DEVICE_ASSERT`` envelope (aud, iat, nonce, signed with the
    device key) exactly as ``enroll.request_token`` does, so the server's
    ``POST /api/v1/sync/token`` accepts it.
    """
    now = sync._clock()
    if sync._token and now < sync._token_expires:
        return  # still valid

    import secrets as _secrets
    from nacl.signing import SigningKey
    from sandbox.protocol.domains import DEVICE_ASSERT
    from sandbox.protocol.envelope import sign_envelope

    sk = SigningKey(sync.device_key)
    assertion_payload = {
        "device_id": sync.device_id,
        "aud": sync.server_url,
        # Wall clock: the server checks iat freshness; sync._clock is
        # monotonic (backoff and expiry only) and must not go on the wire.
        "iat": time.time(),
        "nonce": _secrets.token_hex(16),
    }
    assertion = sign_envelope(DEVICE_ASSERT, assertion_payload, [sk])

    url = f"{sync.server_url}/api/v1/sync/token"
    status, body, hdrs = sync._connect(
        "POST", url,
        body={"device_id": sync.device_id, "assertion": assertion},
        token=None,
    )
    if status != 200:
        raise SyncError(f"token refresh failed: HTTP {status}")

    _record_server_time(sync, hdrs)

    sync._token = body.get("token")
    expires_in = body.get("expires_in", 600)
    sync._token_expires = now + expires_in


def _fetch_registry(sync: SyncProcess) -> None:
    """Fetch a registry update from the server and persist if verified.

    Delegates to the shared ``apply_registry_chain`` helper (R2-2) for
    verification, anti-rollback and atomic persistence.  Only the
    transport stays here.
    """
    if sync.layout is None:
        return

    # Fetch from server
    url = f"{sync.server_url}/api/v1/sync/registry"
    status, body, hdrs = sync._connect("GET", url, token=sync._token)
    if status != 200:
        return

    _record_server_time(sync, hdrs)

    new_chain = body.get("registry")
    if not new_chain or not isinstance(new_chain, list):
        return

    # Delegate to shared verify-and-persist helper (R2-2)
    from sandbox.connector.sync.registry_chain import apply_registry_chain
    apply_registry_chain(sync.layout, new_chain)


def _fetch_decisions(sync: SyncProcess) -> None:
    """Poll for decisions (approvals/denies) from the server.

    Downloads decisions from the server, groups them by request_id, and
    applies them through the existing ``apply_external`` path.  Pending
    escalations are **never** auto-approved here.  The approval path
    (``apply_external``) verifies signatures against the pinned registry.
    """
    import asyncio

    url = f"{sync.server_url}/api/v1/sync/decisions"
    status, body, hdrs = sync._connect(
        "GET", url, token=sync._token,
    )
    if status != 200:
        raise SyncError(f"decisions fetch failed: HTTP {status}")

    _record_server_time(sync, hdrs)

    # Process decisions if the layout is available.
    # Accept both {"decisions": [...]} (new API shape) and a bare list
    # (backward compat with existing callers).
    if isinstance(body, list):
        decisions = body
    elif isinstance(body, dict):
        decisions = body.get("decisions", [])
    else:
        decisions = []
    if not decisions or sync.layout is None:
        return

    # Group decisions by request_id and rebuild envelopes
    from sandbox.connector.queue import valid_request_id

    decisions_by_request: dict[str, list[dict]] = {}
    for row in decisions:
        rid = row.get("request_id", "")
        if not valid_request_id(rid):
            continue
        envelope = _rebuild_decision_envelope(row)
        if envelope is not None:
            decisions_by_request.setdefault(rid, []).append(envelope)

    if not decisions_by_request:
        return

    # Apply decisions through the existing apply_external path
    from sandbox.connector.approval import apply_external

    for rid, envelopes in decisions_by_request.items():
        try:
            result = asyncio.run(apply_external(
                sync.layout, rid, envelopes,
                clock=lambda: time.time(),
            ))
            # Audit the outcome
            try:
                from sandbox.connector.audit import FolderAudit
                audit = FolderAudit(sync.layout.audit_dir, session_id="sync")
                audit.append({
                    "event": "sync_decision_applied",
                    "request_id": rid,
                    "status": result.get("status", "unknown"),
                    "ts": time.time(),
                })
            except Exception:  # noqa: BLE001
                pass
        except Exception:  # noqa: BLE001
            pass


def _rebuild_decision_envelope(row: dict) -> dict | None:
    """Rebuild an agg/remote-approval/v1 envelope from a server decision row.

    The kind is fixed in code (never trust the server's kind column).
    The server's user_id column is ignored (comes from the registry).
    """
    payload = row.get("signed_payload") or row.get("payload")
    if isinstance(payload, str):
        try:
            payload = json.loads(payload)
        except (json.JSONDecodeError, ValueError):
            return None
    if not isinstance(payload, dict):
        return None
    sig = row.get("sig") or row.get("signature") or ""
    key_id = row.get("key_id") or payload.get("key_id", "")
    if not sig or not key_id:
        sigs = row.get("signatures", [])
        if isinstance(sigs, list) and sigs:
            sig = sigs[0].get("sig", "")
            key_id = sigs[0].get("key_id", key_id)
    if not sig:
        return None
    return {
        "kind": "agg/remote-approval/v1",  # fixed in code
        "sig_v": 1,
        "payload": payload,
        "signatures": [{"key_id": key_id, "alg": "ed25519", "sig": sig}],
    }


def _fetch_bundle(sync: SyncProcess) -> None:
    """Fetch the next policy bundle from the server and apply if valid.

    ``GET /api/v1/sync/bundle?after=<current_sequence>`` (ADR 0001 A1):
      - 204: nothing to do.
      - 200: ``verify_and_apply`` with the served approvals.
      - Any ``BundleError``: audited as ``bundle_refused`` with an alert,
        never applied.

    The verifier is authoritative: trust comes from the pinned registry,
    not the server.  A server error (5xx) never auto-approves.
    """
    if sync.layout is None:
        return

    from sandbox.connector.sync.state import current_sequence as _cur_seq

    cur = _cur_seq(sync.layout)
    after = cur if cur is not None else 0

    url = f"{sync.server_url}/api/v1/sync/bundle?after={after}"
    status, body, hdrs = sync._connect("GET", url, token=sync._token)

    _record_server_time(sync, hdrs)

    if status == 204:
        return  # nothing to do

    if status != 200:
        raise SyncError(f"bundle fetch failed: HTTP {status}")

    # F7: a 200 without a valid envelope dict is a malformed response;
    # audit bundle_refused with reason malformed_response, never apply.
    if not isinstance(body, dict):
        _audit_bundle_refused(sync, "malformed_response")
        return

    envelope = body.get("envelope")
    change_approvals = body.get("change_approvals", [])
    if not envelope or not isinstance(envelope, dict):
        _audit_bundle_refused(sync, "malformed_response")
        return

    # Lazy imports: verify_and_apply is the existing TCB path
    from sandbox.connector.sync.bundles import BundleError, verify_and_apply
    from sandbox.connector.sync.state import last_valid_bundle
    from sandbox.connector.sync.verified_state import (
        BootstrapError, _any_bundle_file, load_bootstrap_state,
        load_verified_state,
    )

    vs = load_verified_state(sync.layout)
    bootstrap = None
    if vs is not None:
        registry = vs.registry
        org_id = vs.org_id
        project_id = vs.project_id
    elif _any_bundle_file(sync.layout) or last_valid_bundle(sync.layout) is not None:
        # A bundle file exists (even unparseable) but does not verify:
        # never bootstrap over it (security R2).  The reason names the
        # bootstrap refusal so a garbage bundle.json is distinguishable
        # from a missing trust root.
        _audit_bundle_refused(
            sync, "bootstrap_refused: bootstrap_bundle_present (no_verified_state)",
        )
        return
    else:
        # T16g G7-A: no bundle at all (right after enroll, or re-enroll
        # from locked).  The separate bootstrap loader verifies the local
        # trust root; load_verified_state itself is never relaxed.
        try:
            bootstrap = load_bootstrap_state(sync.layout)
        except BootstrapError as exc:
            _audit_bundle_refused(sync, f"bootstrap_refused: {exc.reason}")
            return
        payload = envelope.get("payload")
        seq = payload.get("sequence") if isinstance(payload, dict) else None
        if not isinstance(seq, int) or isinstance(seq, bool) or seq < 1:
            _audit_bundle_refused(
                sync, "bootstrap_refused: sequence must be an int >= 1 "
                "for the first bundle",
            )
            return
        registry = bootstrap.registry
        org_id = bootstrap.org_id
        project_id = bootstrap.project_id

    try:
        result = verify_and_apply(
            sync.layout,
            envelope,
            registry,
            _bundle_signer_pub(registry),
            change_approvals,
            org_id=org_id,
            project_id=project_id,
        )
    except BundleError as exc:
        _audit_bundle_refused(sync, str(exc.reason))
        return

    if bootstrap is not None:
        # First bundle applied: ratchet the high-water mark now (the
        # verified-state accessor would do it on its next call anyway).
        from sandbox.connector.sync.verified_state import _save_high_water
        sync_dir = sync.layout.root / ".sandbox" / "state" / "sync"
        _save_high_water(sync_dir, bootstrap.registry_version, result.sequence)

def _bundle_signer_pub(registry) -> bytes:
    """Return the bundle signer public key from the VERIFIED registry.

    ``verify_chain`` synthesizes the ``bundle-signer`` entry from the
    latest version's ``bundle_signer`` field only (registry.py F3/R6) and
    has already checked its hex, length and key_id.  Never re-read
    ``registry.json`` from disk here (verified_state.py rule).  Raises
    ``BundleError`` if the verified registry carries no bundle signer.
    """
    from sandbox.connector.sync.bundles import BundleError

    keys = getattr(registry, "_keys", None)
    if not isinstance(keys, dict):
        raise BundleError("verified registry has no key map")
    # R3-1: keys[] does not reserve "__bundle_signer__", so require exactly
    # one match; an ambiguous registry is refused, never guessed.
    matches = [
        entry for entry in keys.values()
        if isinstance(entry, dict)
        and entry.get("kind") == "bundle-signer"
        and entry.get("user_id") == "__bundle_signer__"
    ]
    if len(matches) != 1:
        raise BundleError("no unique bundle_signer key in verified registry")
    pub = matches[0].get("public_key")
    if isinstance(pub, (bytes, bytearray)):
        return bytes(pub)
    if isinstance(pub, str):
        try:
            return bytes.fromhex(pub)
        except ValueError:
            pass
    raise BundleError("bundle_signer key has invalid public_key")


def _audit_bundle_refused(sync: SyncProcess, reason: str) -> None:
    """Write a ``bundle_refused`` audit event and raise an alert."""
    record = {
        "event": "bundle_refused",
        "reason": reason,
        "ts": time.time(),
    }
    try:
        from sandbox.connector.audit import FolderAudit
        audit = FolderAudit(sync.layout.audit_dir, session_id="sync")
        audit.append(record)
    except Exception:  # noqa: BLE001
        pass

    # Alert through the existing alerts path (best effort)
    try:
        from sandbox.connector.alerts import emit
        emit(sync.layout, "sync", record)
    except Exception:  # noqa: BLE001
        pass


def _upload_escalations(sync: SyncProcess) -> None:
    """Upload new pending escalation records to the server, scrubbed (threat 19).

    **Never** modifies the status of any pending escalation.  The status
    can only change through the approval path after receiving and verifying
    a signed human decision.

    Records are scrubbed of secrets before upload (D6.1, threat 19).
    The local pending record is unchanged; only the uploaded copy is scrubbed.
    """
    if sync.layout is None:
        return

    sync.uploaded_count = 0
    # The queue's own pending dir (EscalationQueue writes here), not a
    # second location: T16a made this the only upload path.
    pending_dir = sync.layout.pending_dir
    if not pending_dir.is_dir():
        return

    for f in pending_dir.iterdir():
        if not f.name.endswith(".json"):
            continue
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue

        # Queue records carry no status field: pending/ means pending.
        if data.get("status", "pending") != "pending":
            continue

        # Scrub secrets before upload (threat 19)
        upload_data = dict(data)
        try:
            from sandbox.connector.scrub import OUTPUT_FIELDS, scrub_text

            # R4-1: also stdout/stderr, as HEAD's CLI upload did.
            _fields = ("command", "reason", "target", "described_as",
                       *OUTPUT_FIELDS)

            for key in _fields:
                val = upload_data.get(key)
                if isinstance(val, str) and val:
                    upload_data[key] = scrub_text(val)
            # Scrub inside nested record if present
            rec = upload_data.get("record")
            if isinstance(rec, dict):
                rec = dict(rec)
                for key in _fields:
                    val = rec.get(key)
                    if isinstance(val, str) and val:
                        rec[key] = scrub_text(val)
                upload_data["record"] = rec
        except Exception:  # noqa: BLE001 -- scrub failure: skip record (L1 rule)
            continue

        # Validate request_id before uploading (H3 defense in depth)
        rid = upload_data.get("request_id", "")
        try:
            from sandbox.connector.queue import valid_request_id
            if not valid_request_id(rid):
                continue
        except Exception:  # noqa: BLE001
            continue

        # bundle_sequence must be an int; reject otherwise (no coercion)
        body = escalation_upload_body(upload_data, sync.device_id,
                                      layout=sync.layout)
        if body is None:
            continue

        # Upload (idempotent on server side)
        url = f"{sync.server_url}/api/v1/sync/escalations"
        try:
            status, _, _ = sync._connect(
                "POST", url,
                body=body,
                token=sync._token,
            )
        except Exception:
            # Upload failure does not change escalation status
            continue
        if 200 <= status < 300:
            sync.uploaded_count += 1


# Alias for tests (threat 19 coverage)
_upload_escalations_scrubbed = _upload_escalations


#: Consecutive cycles with a network error on the audit step before
#: ``audit_upload_failed`` is raised (security L ruling, 4 Nov 2026).
AUDIT_NETWORK_ALERT_AFTER: int = 3


def _upload_audit(sync: SyncProcess) -> None:
    """Upload audit records and send a checkpoint (D3, T11; T16g G7-B).

    Only runs in managed mode.  Lazy-imports ``audit_upload`` so the
    hook never loads it (socket guard).

    Nothing is swallowed: every failure becomes a local alert AND a local
    audit record (session ``sync``) in this cycle: ``audit_fork`` (409),
    ``audit_truncation_local`` (cursor past the local chain),
    ``server_head_mismatch``, ``audit_upload_failed`` with the HTTP status
    on any other 4xx/5xx; a network error is alerted after
    ``AUDIT_NETWORK_ALERT_AFTER`` consecutive cycles.  The checkpoint is
    sent even when the upload failed.  None of this blocks the cycle,
    changes an escalation status or loosens enforcement.
    """
    if sync.layout is None:
        return

    # Only upload in managed mode
    from sandbox.connector.sync.state import is_managed
    if not is_managed(sync.layout):
        return

    from sandbox.connector.sync.audit_upload import (
        AuditUploader, AuditUploadError, send_checkpoint, upload_records,
    )

    import logging
    _log = logging.getLogger(__name__)

    errors: list[dict] = []
    net_error: Exception | None = None

    uploader = AuditUploader(sync.layout, sync.device_id, sync.device_key)
    try:
        result = upload_records(uploader, sync._connect, sync._token, sync.server_url)
        errors.extend(result.get("errors", []))
    except AuditUploadError as exc:
        errors.extend(exc.errors)
    except (ConnectionError, OSError) as exc:  # URLError is an OSError
        net_error = exc
    except Exception as exc:  # noqa: BLE001 -- never swallow
        errors.append({"kind": "audit_upload_failed", "status": None,
                       "session_id": None,
                       "reason": f"upload error: {type(exc).__name__}"})

    # The checkpoint goes even when the upload failed (A4.2).
    try:
        send_checkpoint(uploader, sync._connect, sync._token, sync.server_url)
    except AuditUploadError as exc:
        for e in exc.errors:
            errors.append({"kind": "audit_upload_failed",
                           "status": e.get("status"), "session_id": None,
                           "reason": f"checkpoint: {e.get('reason', '')}"})
    except (ConnectionError, OSError) as exc:
        net_error = net_error or exc
    except Exception as exc:  # noqa: BLE001
        errors.append({"kind": "audit_upload_failed", "status": None,
                       "session_id": None,
                       "reason": f"checkpoint error: {type(exc).__name__}"})

    if net_error is not None:
        n = getattr(sync, "_audit_net_failures", 0) + 1
        sync._audit_net_failures = n
        _log.error("audit upload network error (%d consecutive): %s", n, net_error)
        if n >= AUDIT_NETWORK_ALERT_AFTER:
            errors.append({"kind": "audit_upload_failed", "status": None,
                           "session_id": None,
                           "reason": f"network error for {n} consecutive "
                                     f"cycles: {type(net_error).__name__}"})
    else:
        sync._audit_net_failures = 0

    for e in errors:
        _audit_sync_alert(sync, e)


def _audit_sync_alert(sync: SyncProcess, error: dict) -> None:
    """Write the local audit record and raise the alert for one audit
    upload failure.  Best effort on each half; never raises."""
    kind = str(error.get("kind") or "audit_upload_failed")
    record = {
        "event": kind,
        "reason": str(error.get("reason") or ""),
        "status": error.get("status"),
        "audit_session_id": error.get("session_id"),
        "ts": time.time(),
    }
    try:
        from sandbox.connector.audit import FolderAudit
        FolderAudit(sync.layout.audit_dir, session_id="sync").append(record)
    except Exception:  # noqa: BLE001
        pass
    try:
        from sandbox.connector.alerts import emit
        emit(sync.layout, "sync", record)
    except Exception:  # noqa: BLE001
        pass
