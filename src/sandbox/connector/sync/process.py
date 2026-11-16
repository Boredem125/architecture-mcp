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
from pathlib import Path
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


class SyncHTTPError(SyncError):
    """A SyncError with an HTTP status code and stage (R2-10)."""

    def __init__(self, message: str, *, status: int = 0, stage: str = "") -> None:
        super().__init__(message)
        self.status = status
        self.stage = stage


class SyncLocalKeyError(SyncError):
    """Raised when the local device key is unusable (R4-2).

    Not a transport or network error: the key is a local configuration
    problem.  No stage failure is recorded and no alert is written.
    """


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
    except (json.JSONDecodeError, ValueError, RecursionError):
        # T9A-2: a dict subclass that equals {} but is distinguishable,
        # so _fetch_decisions can classify it as unparseable_body.
        body_dict = _UnparseableBody()

    return (status, body_dict, resp_headers)


class _UnparseableBody(dict):
    """Marker for an unparseable response body (T9A-2).

    Equals ``{}`` for backward compatibility (frozen test
    ``test_m2_t15b_transport.py``), but carries ``_unparseable``
    so ``_fetch_decisions`` can tell it apart from a real empty dict.
    """
    _unparseable = True


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

        #: T9a: set by _fetch_decisions when it fails; run_once raises after
        #: later steps (bundle, escalations, audit) have run.
        self._decisions_failed: bool = False
        self._decisions_fail_reason: str = ""


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
        try:
            _refresh_token(sync)
        except SyncLocalKeyError:
            # R4-2: local key problem -- no stage failure, no alert.
            raise
        except (ConnectionError, OSError, SyncError) as exc:
            # T9A-1: record the failure at stage=token for alerting
            _record_stage_failure(sync, "token", exc)
            raise
        except Exception as exc:
            # R2-10: http.client.HTTPException and other non-OS exceptions
            _record_stage_failure(sync, "token", exc)
            raise SyncError(f"token error: {type(exc).__name__}") from exc

        # ---- 2. Fetch and persist registry updates (D4-1 step-5: before decisions) ----
        try:
            _fetch_registry(sync)
        except (ConnectionError, OSError, SyncError) as exc:
            # T9A-1: record the failure at stage=registry for alerting
            _record_stage_failure(sync, "registry", exc)
            raise
        except Exception as exc:
            # R2-10: http.client.HTTPException and other non-OS exceptions
            _record_stage_failure(sync, "registry", exc)
            raise SyncError(f"registry error: {type(exc).__name__}") from exc

        # ---- 3. Fetch decisions and apply through apply_external ----
        # T9a: _fetch_decisions never raises Exception.  It sets
        # sync._decisions_failed on failure; run_once raises AFTER later
        # steps so a bad route cannot suppress upload.
        sync._decisions_failed = False
        _fetch_decisions(sync)

        # ---- 4. Fetch and verify next bundle (ADR 0001 A1) ----
        _fetch_bundle(sync)

        # ---- 5. Upload pending escalations ----
        _upload_escalations(sync)

        # ---- 6. Upload audit records and checkpoint (managed only, T11) ----
        _upload_audit(sync)

        # T9a: if decisions failed, raise now (after upload steps ran).
        # The outer except handler increments _consecutive_failures.
        if sync._decisions_failed:
            raise SyncError("decisions fetch failed (after later steps ran)")

        # Success: reset failure counter
        sync._consecutive_failures = 0

    except (ConnectionError, OSError, SyncError) as exc:
        sync._consecutive_failures += 1
        raise SyncError(f"sync cycle failed: {exc}") from exc
    except Exception as exc:
        sync._consecutive_failures += 1
        raise SyncError(f"sync cycle failed: {type(exc).__name__}") from exc


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


def _record_stage_failure(sync: SyncProcess, stage: str, exc: Exception) -> None:
    """Record a transport failure at token or registry stage (T9A-1).

    Uses the decision state's network counter so outages at any stage
    count toward the 3-cycle threshold.  Never raises anything but
    ``SyncError`` (frozen test: ``test_server_down_escalated_call_stays_pending``).
    """
    import ssl
    try:
        ds = _load_decision_state(sync)
        # Classify the error
        reason = getattr(exc, "reason", None)
        if isinstance(reason, ssl.SSLCertVerificationError) or isinstance(exc, ssl.SSLCertVerificationError):
            code = "tls_verify_failed"
            immediate = True
        elif isinstance(exc, SyncHTTPError):
            # R2-10: use the HTTP status to classify, not string matching
            http_status = exc.status
            if http_status == 401:
                code = "token_rejected"
            elif http_status == 403:
                code = "token_forbidden"
            elif 400 <= http_status < 500:
                code = "http_4xx"
            elif 500 <= http_status < 600:
                code = "http_5xx"
            else:
                code = "transport_refused"
            immediate = True
        elif isinstance(exc, SyncError):
            code = "transport_refused"
            immediate = True
        elif isinstance(exc, OSError):
            # R4-1: OSError at token/registry is network_error (3-cycle counter),
            # not transport_error.  URLError, ConnectionError and TimeoutError
            # are all OSError subclasses; TLS stays first.
            code = "network_error"
            immediate = False
        else:
            # R3-6: non-OS/non-SyncError at token/registry is transport_error,
            # immediate (not network_error with 3-cycle counter).
            code = "transport_error"
            immediate = True
        _note_decisions_failure(sync, ds, code, stage,
                                exc_type=type(exc).__name__, immediate=immediate)
        ds.save()
    except Exception:  # noqa: BLE001 -- never raise non-SyncError from here
        pass


def _record_server_time(sync: SyncProcess, resp_headers: dict) -> None:
    """Record the server time from an HTTP Date header (F1, D4.3).

    The state is written to ``server_time_state.json`` through
    ``sync.state.write_server_time_state``, atomic temp-file + rename.
    ``apply_external`` reads it to compute measured skew.

    Raises on write failure so the caller (e.g., ``_record_decisions_server_time``)
    can alert.  Callers outside the decisions path catch it silently.
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


# ---------------------------------------------------------------------------
# T9a: decision alert and state helpers
# ---------------------------------------------------------------------------

# T9A-4: alert priority order (spec section 4)
_ALERT_ORDER = {
    "decision_apply_failed": 0,
    "decisions_fetch_failed": 1,
    "decision_refused": 2,
    "decisions_malformed": 3,
}

#: Refusal code -> human-readable sentence (spec section 3).
#: Sentences live in process.py, not approval.py.
_REFUSAL_SENTENCES: dict[str, str] = {
    "not_object": "The approval envelope is malformed",
    "wrong_tag": "The approval envelope is malformed",
    "bad_payload": "The approval envelope is malformed",
    "missing_fields": "The signed payload lacks required fields",
    "signature_count": "An approval must carry exactly one signature",
    "key_id_mismatch": "The payload and signature name different keys",
    "no_registry": "No verified registry is available",
    "unknown_key": "This key is not in the latest pinned registry (unknown or removed)",
    "wrong_key_kind": "Device and bundle-signer keys cannot approve",
    "role_missing": "This key has neither the approver nor the admin role",
    "user_mismatch": "The payload user differs from the registry entry",
    "bad_decision": "The decision is neither approve nor deny",
    "prod_refused": "Remote approval is not allowed on prod",
    "registry_expired": "The pinned registry has expired",
    "kind_not_allowed": "This key kind may not sign this",
    "policy_sequence_mismatch": "The approval names another policy sequence",
    "not_after_invalid": "The expiry is not a finite number",
    "approval_expired": "The approval expired",
    "nonce_invalid": "The nonce is missing or too long",
    "bad_signature": "The signature does not verify",
    "verify_raised": "The envelope could not be checked",
    "nonce_replay": "This nonce was already used for another request or payload",
    "operator_self_approval": "The device operator cannot approve their own request",
    "fingerprint_unavailable": "The binding fingerprint is unavailable",
    "request_mismatch": "The approval is bound to a different request",
    "fingerprint_mismatch": "The approval is bound to a different fingerprint",
    "command_mismatch": "The approval is bound to a different command",
    "device_mismatch": "The approval is bound to a different device",
    "project_mismatch": "The approval is bound to a different project",
    "org_mismatch": "The approval is bound to a different org",
    "nonces_corrupt": "The nonce store is corrupt, so approvals are refused and denies still apply",
    "clock_skew": "Clock skew is over 2 minutes",
    "no_server_time": "No server time has been measured, so approvals are refused",
    "same_user": "This user already counted, and one person counts once",
    "same_identity": "This identity already counted",
    "not_dual_eligible": "The registry version that added this key had fewer than 2 admin signatures, so it cannot count toward dual control",
    "no_verified_state": "This device has no verified state, operator or device id, so remote approvals are refused",
    "record_ahead_of_bundle": "The request is newer than this device policy",
    "no_approvals_counted": "No approval counted",
    "unknown_request": "This device does not hold this request",
    "record_changed": "The pending record changed between read and claim",
    "script_unbound": "The script content is not bound",
    "script_preview_not_shown": "The script preview was not shown before approval",
    "request_id_refused": "The request was refused",
}

# C0 (including TAB, LF, CR), C1 controls (including NBSP U+00A0),
# DEL, bidi controls, surrogates.
# Spec section 5: strip all C0, C1, DEL, NBSP, NNBSP and bidi from untrusted text.
_CTRL_CHARS = frozenset(
    set(range(0x00, 0x20))       # All C0 including TAB(09), LF(0A), CR(0D)
    | set(range(0x80, 0xA1))     # C1 including NBSP (U+00A0)
    | {0x7F}                     # DEL
    | {0x202A, 0x202B, 0x202C, 0x202D, 0x202E}  # bidi
    | {0x2066, 0x2067, 0x2068, 0x2069}            # bidi isolates
    | {0x200E, 0x200F}                             # LRM / RLM
    | {0x061C}                                     # ALM
    | {0x202F}                                     # NNBSP
    | set(range(0xD800, 0xE000))                   # surrogates
)
_SERVER_TEXT_CAP = 200
_SERVER_TEXT_RAW_CAP = 4096
_KEY_ID_EXPECTED_LENGTH = 64  # hex-encoded Ed25519 public key = 32 bytes = 64 hex chars


def _valid_hex_key_id(kid: str) -> bool:
    """Return True if kid is lowercase hex of the expected length."""
    if not isinstance(kid, str):
        return False
    if len(kid) != _KEY_ID_EXPECTED_LENGTH:
        return False
    try:
        int(kid, 16)
    except ValueError:
        return False
    return kid == kid.lower()


def _display_key_id(kid: str) -> str:
    """Return a safe display form of a key_id: hex or 'invalid'.

    Spec section 5: key id must be hex or prints 'invalid'.
    Truncates valid hex to 12 chars for display.
    """
    if _valid_hex_key_id(kid):
        return kid[:12]
    return "invalid"


def _sanitize_field(value: object) -> str:
    """Sanitize untrusted text: strip C0, C1, DEL and bidi controls (H1).

    Used on every server text, row field, or state value before it is
    stored, displayed or alerted.  A non-string value is coerced.
    """
    if not isinstance(value, str):
        if value is None:
            return ""
        value = str(value)
    return "".join(c for c in value if ord(c) not in _CTRL_CHARS)


def _safe_server_text(body: object) -> str:
    """Extract, sanitize and cap server error text from a response body.

    Order: cut to 4 KiB, strip C0/C1/DEL/bidi controls, scrub_text, cap 200.
    A scrub failure drops the text entirely.  Only ``detail`` or ``error``
    string fields are used.  Spec section 5 (T threat).
    """
    text = ""
    if isinstance(body, dict):
        candidate = body.get("detail") or body.get("error")
        if isinstance(candidate, str):
            text = candidate
    if not text:
        return ""
    # Cut to raw cap first
    text = text[:_SERVER_TEXT_RAW_CAP]
    # Truncate at the first newline/CR to prevent fake-log-line injection
    for _sep in ("\n", "\r"):
        idx = text.find(_sep)
        if idx >= 0:
            text = text[:idx]
    # Strip remaining control chars
    text = "".join(c for c in text if ord(c) not in _CTRL_CHARS)
    # Scrub secrets: import is safe (same package); a scrub failure drops text (R2-9)
    from sandbox.connector.scrub import scrub_text as _scrub_fn
    scrubbed = _scrub_fn(text)
    text = scrubbed if isinstance(scrubbed, str) else ""
    # Cap at 200
    return text[:_SERVER_TEXT_CAP]


def _record_decisions_server_time(sync: SyncProcess, hdrs: dict, ds) -> None:
    """Record server time, alerting on failure (T9a).

    Wraps ``_record_server_time`` so that an exception triggers a
    ``decisions_fetch_failed`` / ``server_time_write_failed`` alert
    through ``_decision_alert``.  Never raises.  The cycle continues:
    approvals refuse by the skew rule.
    """
    try:
        _record_server_time(sync, hdrs)
    except Exception:  # noqa: BLE001
        # Record the time failure alert. _note_decisions_failure does not
        # set _decisions_failed for this code (T9A-8).
        _note_decisions_failure(sync, ds, "server_time_write_failed", "decisions",
                                immediate=True,
                                sentence="server time state write failed")


def _load_decision_state(sync: SyncProcess):
    """Load or create the decision state for this cycle.

    Never raises: a corrupt state file means empty (T9A-5).
    When ``layout`` is None, returns a no-op stub that writes nothing (R2-8).
    """
    from sandbox.connector.sync.decision_state import DecisionState, NullDecisionState
    if sync.layout is None:
        return NullDecisionState()
    logs_dir = sync.layout.root / ".sandbox" / "logs"
    return DecisionState(logs_dir)


def _note_decisions_failure(
    sync: SyncProcess,
    ds,
    code: str,
    stage: str,
    *,
    exc_type: str = "",
    immediate: bool = False,
    sentence: str = "",
) -> None:
    """Record a transport-level decisions failure.

    Network errors (code ``network_error``) use a 3-cycle counter before
    alerting.  TLS, transport, SyncError and HTTP errors alert immediately.
    Sets ``sync._decisions_failed``.
    """
    import logging
    _log = logging.getLogger(__name__)

    # server_time_write_failed must not fail the cycle (T9A-8):
    # approvals refuse by the skew rule, cycle continues OK.
    if code != "server_time_write_failed":
        sync._decisions_failed = True

    if code == "network_error" and not immediate:
        count = ds.note_net_failure(stage)
        _log.info("decisions fetch network_error at %s (%d in a row)", stage, count)
        from sandbox.connector.sync.decision_state import DECISIONS_NET_ALERT_AFTER
        if count < DECISIONS_NET_ALERT_AFTER:
            return
        _decision_alert(
            sync, ds, "decisions_fetch_failed", code,
            reason=f"decisions not fetched for {count} consecutive cycles: "
                   f"network_error at {stage} ({exc_type})",
            stage=stage, count=count,
        )
    else:
        desc = sentence if sentence else exc_type
        reason = f"decisions not fetched: {code} at {stage}"
        if desc:
            reason += f": {desc}"
        _decision_alert(
            sync, ds, "decisions_fetch_failed", code,
            reason=reason, stage=stage,
        )


def _decision_alert(
    sync: SyncProcess,
    ds,
    event: str,
    code: str,
    *,
    reason: str = "",
    stage: str = "",
    status_code: int | None = None,
    rid: str = "",
    key_id: str = "",
    count: int = 0,
    queue_state: str = "",
    verified: bool = False,
) -> None:
    """Write a decision alert and an audit record (T9a, spec section 2).

    Respects dedupe, per-cycle and per-hour caps from the decision state.
    The alert path sits after the verdict; nothing reads the state file
    to decide.
    """
    # Build dedupe key
    if rid and key_id:
        dedupe_key = (event, rid, code, key_id)
    elif rid:
        dedupe_key = (event, rid, code)
    elif stage:
        dedupe_key = (event, stage, str(status_code or ""), code)
    else:
        dedupe_key = (event, code)

    entry = ds.note(dedupe_key, reason=reason, code=code, rid=rid,
                     key_id=key_id, stage=stage, status=status_code,
                     verified=verified)

    # Decide whether to alert (T9A-4: same key later = no alert, no audit)
    should = ds.should_alert(dedupe_key)
    is_realert = entry.get("alerted", False) and should

    if not should:
        # Same key, not yet past re-alert window: no alert, no audit (T9A-4)
        return

    record = {
        "event": event,
        "reason_code": code,
        "reason": reason,
        "tool": "sync",
        "ts": time.time(),
    }
    if stage:
        record["stage"] = stage
    if status_code is not None:
        record["status"] = status_code
    if rid:
        record["request_id"] = rid
    if key_id:
        record["key_id"] = _sanitize_field(key_id)
    if count:
        record["count"] = count
    if queue_state:
        record["queue_state"] = queue_state
    repeats = ds.get_repeats(dedupe_key)
    # A re-alert that is about to be written adds 1 (mark_realerted runs after)
    if is_realert:
        repeats += 1
    if repeats > 0:
        record["repeats"] = repeats

    # H3: bound both audit and alert writes per cycle (spec section 4)
    # R2-3: cap check BEFORE mark_realerted so a capped re-alert does not
    # reset last_alerted (which would silence the next window too).
    if not ds.may_alert():
        ds.record_suppressed()
        return

    # R2-4: audit and alert: only mark alerted on successful write
    ok = _audit_decision_record(sync, record)
    _emit_decision_alert(sync, record)
    if ok:
        if is_realert:
            ds.mark_realerted(dedupe_key)
        ds.mark_alerted(dedupe_key)
        ds.record_alert()


def _audit_decision_record(sync: SyncProcess, record: dict) -> bool:
    """Write an audit record for a decision event. Returns True on success."""
    if sync.layout is None:
        return True
    try:
        from sandbox.connector.audit import FolderAudit
        fa = FolderAudit(sync.layout.audit_dir, session_id="sync")
        fa.append(record)
        return True
    except Exception:  # noqa: BLE001
        import logging
        logging.getLogger(__name__).error("decision audit append failed")
        return False


def _emit_decision_alert(sync: SyncProcess, record: dict) -> None:
    """Write a decision alert through the alerts path."""
    if sync.layout is None:
        return
    try:
        from sandbox.connector.alerts import emit
        emit(sync.layout, "sync", record)
    except Exception:  # noqa: BLE001
        import logging
        logging.getLogger(__name__).error("decision alert emit failed")


def _audit_decision_outcome_deduped(sync: SyncProcess, ds, rid: str, result: dict) -> None:
    """Audit the outcome of ``apply_external``, deduped by (status, approvals, reason_codes).

    ``sync_decision_applied`` is written only on a change (T9A-4).
    ``executed`` and ``denied`` are never suppressed.  Never raises.
    """
    if sync.layout is None:
        return
    status = result.get("status", "unknown")

    # Build outcome signature for dedupe
    approvals_count = result.get("approvals")
    refusals = result.get("refusals", [])
    reason_codes = sorted({r.get("code", "") for r in refusals if r.get("code")})
    reason_code = result.get("reason_code")

    outcome_key = f"sync_decision_applied:{rid}"
    outcome_sig = f"{status}:{approvals_count}:{reason_codes}:{reason_code}"

    # Check if outcome changed since last record
    entry = ds._entries.get(outcome_key)
    # R2-6: executed and denied are never suppressed by dedupe
    if status not in ("executed", "denied"):
        if entry is not None and entry.get("outcome_sig") == outcome_sig:
            # No change: skip audit (T9A-4)
            return

    record = {
        "event": "sync_decision_applied",
        "request_id": rid,
        "status": status,
        "ts": time.time(),
    }
    if approvals_count is not None:
        record["approvals"] = approvals_count
    if reason_codes:
        record["reason_codes"] = reason_codes
    if reason_code:
        record["reason_code"] = reason_code

    # R2-4: write the audit record FIRST; only mark as recorded on success
    ok = _audit_decision_record(sync, record)
    if ok:
        ds._entries[outcome_key] = {
            "outcome_sig": outcome_sig,
            "last_seen": time.time(),
            "count": 1,
            "alerted": True,
            "first_seen": time.time(),
            "repeats": 0,
        }


def _emit_suppression_alert(sync: SyncProcess, ds) -> None:
    """Emit a single decision_alerts_suppressed alert per hour (T9A-4)."""
    suppression_key = ("decision_alerts_suppressed", "cap_exceeded")
    if not ds.should_alert(suppression_key):
        return
    count = ds.suppressed_this_hour
    record = {
        "event": "decision_alerts_suppressed",
        "reason_code": "cap_exceeded",
        "reason": f"{count} decision alert(s) suppressed this hour",
        "tool": "sync",
        "ts": time.time(),
        "count": count,
    }
    _audit_decision_record(sync, record)
    _emit_decision_alert(sync, record)
    ds.note(suppression_key)
    ds.mark_alerted(suppression_key)


def _safe_json_loads(text: str):
    """Parse JSON, returning None on failure (no exception).

    Catches ``RecursionError`` for deeply nested payloads (H2).
    """
    try:
        return json.loads(text)
    except (json.JSONDecodeError, ValueError, RecursionError):
        return None


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

    # R4-2: validate device key before nacl touches it.  A bad key is a
    # local configuration problem, not a transport error.
    if not isinstance(sync.device_key, (bytes, bytearray)) or len(sync.device_key) != 32:
        raise SyncLocalKeyError(
            "device key unusable: an Ed25519 seed must be exactly 32 bytes")

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
        raise SyncHTTPError(f"token refresh failed: HTTP {status}",
                            status=status, stage="token")

    try:
        _record_server_time(sync, hdrs)
    except Exception:  # noqa: BLE001 -- write failure: skew rule applies
        pass

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

    try:
        _record_server_time(sync, hdrs)
    except Exception:  # noqa: BLE001 -- write failure: skew rule applies
        pass

    # T9A-9: a non-dict 200 is a loud failure (not silently swallowed)
    if not isinstance(body, dict):
        raise SyncError("registry response is not an object")
    new_chain = body.get("registry")
    if not new_chain or not isinstance(new_chain, list):
        return

    # Delegate to shared verify-and-persist helper (R2-2)
    from sandbox.connector.sync.registry_chain import apply_registry_chain
    apply_registry_chain(sync.layout, new_chain)


def _fetch_decisions(sync: SyncProcess) -> None:
    """Poll for decisions (approvals/denies) from the server (T9a).

    **Never raises Exception.**  Must not catch BaseException.  On any
    failure, sets ``sync._decisions_failed`` so ``run_once`` raises
    *after* later steps (bundle, escalations, audit upload) have run.

    Downloads decisions from the server, groups them by request_id, and
    applies them through the existing ``apply_external`` path.  Pending
    escalations are **never** auto-approved here.  The approval path
    (``apply_external``) verifies signatures against the pinned registry.

    Spec: T9A_SPEC.md sections 1-5.
    """
    import asyncio
    import logging
    import ssl

    _log = logging.getLogger(__name__)

    # Load persisted decision state (dedupe and caps).
    ds = _load_decision_state(sync)
    ds.begin_cycle()

    # -- Transport --
    url = f"{sync.server_url}/api/v1/sync/decisions"
    try:
        status, body, hdrs = sync._connect(
            "GET", url, token=sync._token,
        )
    except ssl.SSLCertVerificationError as exc:
        _note_decisions_failure(sync, ds, "tls_verify_failed", "decisions",
                                exc_type=type(exc).__name__, immediate=True)
        ds.save()
        return
    except (ConnectionError, OSError) as exc:
        # T9A-3: urllib wraps SSLCertVerificationError in URLError
        reason = getattr(exc, "reason", None)
        if isinstance(reason, ssl.SSLCertVerificationError):
            _note_decisions_failure(sync, ds, "tls_verify_failed", "decisions",
                                    exc_type=type(reason).__name__, immediate=True)
            ds.save()
            return
        _note_decisions_failure(sync, ds, "network_error", "decisions",
                                exc_type=type(exc).__name__)
        ds.save()
        return
    except SyncError as exc:
        _note_decisions_failure(sync, ds, "transport_refused", "decisions",
                                exc_type=type(exc).__name__, immediate=True,
                                sentence=str(exc))
        ds.save()
        return
    except Exception as exc:  # noqa: BLE001
        _note_decisions_failure(sync, ds, "transport_error", "decisions",
                                exc_type=type(exc).__name__, immediate=True)
        ds.save()
        return

    # -- Non-200 --
    if status != 200:
        try:
            server_text = _safe_server_text(body)
        except Exception:  # noqa: BLE001 -- scrub failure drops text
            server_text = ""
            _note_decisions_failure(
                sync, ds, "scrub_failed", "decisions",
                immediate=True, sentence="server text scrub failed",
            )
        if status == 401:
            code = "token_rejected"
            sync._token_expires = 0
        elif status == 403:
            code = "token_forbidden"
            sync._token_expires = 0
        elif 400 <= status < 500:
            code = "http_4xx"
        elif 500 <= status < 600:
            code = "http_5xx"
        elif 300 <= status < 400:
            code = "http_3xx"
        else:
            code = "unexpected_status"
        # R2-9: server text included for 4xx and 5xx as "(server says: <text>)",
        # never for 3xx. The sentence is from _REFUSAL_SENTENCES, not type(code).__name__.
        sentence = _REFUSAL_SENTENCES.get(code, code)
        reason = f"decisions not fetched: HTTP {status} at decisions: {sentence}"
        if server_text and 400 <= status < 600:
            reason += f" (server says: {server_text})"
        _decision_alert(
            sync, ds, "decisions_fetch_failed", code,
            reason=reason,
            stage="decisions", status_code=status,
        )
        sync._decisions_failed = True
        ds.save()
        return

    # -- 200: record server time --
    _record_decisions_server_time(sync, hdrs, ds)

    # Success on transport -> reset network counter
    ds.reset_net_counter()

    # T9A-2: detect unparseable body from _default_connect
    if getattr(body, "_unparseable", False):
        _decision_alert(
            sync, ds, "decisions_malformed", "unparseable_body",
            reason="decisions response malformed: unparseable_body: "
                   "the response body is not valid JSON",
        )
        ds.save()
        return

    ds.clear_fetch_keys()

    # -- Parse body --
    _SENTINEL = object()
    if isinstance(body, list):
        decisions = body
    elif isinstance(body, dict):
        decisions = body.get("decisions", _SENTINEL)
        if decisions is _SENTINEL:
            # R2-7: dict without "decisions" key always alerts (no body guard).
            # An empty {} is not one of the frozen empty shapes.
            _decision_alert(
                    sync, ds, "decisions_malformed", "decisions_key_missing",
                    reason="decisions response malformed: decisions_key_missing: "
                           "the response dict has no decisions key",
                )
            ds.save()
            return
        if not isinstance(decisions, list):
            # decisions key present but not a list (null, int, str, dict)
            _decision_alert(
                sync, ds, "decisions_malformed", "decisions_not_list",
                reason="decisions response malformed: decisions_not_list: "
                       "the decisions field is not a list",
            )
            ds.save()
            return
    else:
        _decision_alert(
            sync, ds, "decisions_malformed", "not_object_or_list",
            reason="decisions response malformed: not_object_or_list: "
                   "the response body is neither a dict nor a list",
        )
        ds.save()
        return

    if not decisions or sync.layout is None:
        if sync.layout is None and decisions:
            _log.warning("_fetch_decisions: layout is None, skipping %d decisions",
                         len(decisions))
        # R2 Low: empty decisions on a 200 means no malformed rows; clear stale entries
        ds.clear_malformed_keys()
        ds.save()
        return

    # -- Process rows --
    from sandbox.connector.queue import EscalationQueue, valid_request_id

    queue = EscalationQueue(sync.layout)
    bad_row_count = 0
    bad_rid_count = 0
    unknown_request_count = 0
    malformed_counts: dict[str, int] = {}  # R3-8: one alert per code per cycle
    decisions_by_request: dict[str, list[dict]] = {}
    pending_alerts: list[dict] = []  # Collected alerts, sorted and capped

    for row in decisions:
        if not isinstance(row, dict):
            bad_row_count += 1
            continue

        rid = row.get("request_id")
        if not isinstance(rid, str) or not valid_request_id(rid):
            bad_rid_count += 1
            continue

        # Validate envelope structure before checking local state:
        # a malformed row is classified by its structural problem, not
        # by whether the device holds the request.
        envelope, rebuild_reason = _rebuild_envelope(row)
        if envelope is None:
            # R3-8: count per code, one alert per code at end of cycle
            malformed_counts[rebuild_reason] = malformed_counts.get(rebuild_reason, 0) + 1
            continue

        # Check local state: done or claimed -> silent skip (fixes E13)
        local_status = queue.status(rid)
        if local_status == "done":
            continue
        if local_status == "claimed":
            continue
        if local_status == "unknown":
            unknown_request_count += 1
            continue

        decisions_by_request.setdefault(rid, []).append(envelope)

    # R3-8: one alert per malformed code per cycle, with count
    for mcode, mcount in sorted(malformed_counts.items()):
        pending_alerts.append({
            "event": "decisions_malformed", "code": mcode,
            "reason": f"{mcount} decision row(s) dropped: {mcode}: "
                      "the row has an unusable payload or signature",
            "count": mcount,
        })

    if bad_row_count > 0:
        pending_alerts.append({
            "event": "decisions_malformed", "code": "row_not_object",
            "reason": f"{bad_row_count} decision row(s) dropped: row_not_object: "
                      "the row is not an object",
            "count": bad_row_count,
        })

    if bad_rid_count > 0:
        pending_alerts.append({
            "event": "decisions_malformed", "code": "request_id_invalid",
            "reason": f"{bad_rid_count} decision row(s) dropped: request_id_invalid: "
                      "the row has an invalid or missing request_id",
            "count": bad_rid_count,
        })

    if unknown_request_count > 0:
        pending_alerts.append({
            "event": "decision_refused", "code": "unknown_request",
            "reason": f"{unknown_request_count} decision(s) for requests this "
                      "device does not hold",
            "count": unknown_request_count,
        })

    if not decisions_by_request:
        # Still emit collected alerts (malformed rows, bad rids, unknown requests)
        if pending_alerts:
            pending_alerts.sort(key=lambda a: _ALERT_ORDER.get(a.get("event", ""), 9))
            for pa in pending_alerts:
                _decision_alert(
                    sync, ds, pa["event"], pa["code"],
                    reason=pa.get("reason", ""), rid=pa.get("rid", ""),
                    key_id=pa.get("key_id", ""), count=pa.get("count", 0),
                )
            if ds.suppressed_this_hour > 0:
                _emit_suppression_alert(sync, ds)
        # R2 Low: clear malformed keys if this cycle had none
        if not any(pa.get("event") == "decisions_malformed" for pa in pending_alerts):
            ds.clear_malformed_keys()
        ds.save()
        return

    # -- Apply decisions --
    from sandbox.connector.approval import apply_external
    rids_to_clear: list[str] = []

    for rid, envelopes in decisions_by_request.items():
        # R4-6: no pre-check of the pending file.  apply_external's own
        # read is the single authority on the file's state.
        try:
            result = asyncio.run(apply_external(
                sync.layout, rid, envelopes,
                clock=lambda: time.time(),
            ))
        except Exception as exc:  # noqa: BLE001
            q_status = queue.status(rid)
            # R4-5: every raise -> apply_raised with the exception type
            # and record queue state.  nonce_save_failed stays on the
            # returned status (process.py ~1351).
            msg = (f"{rid} apply failed: apply_raised ({type(exc).__name__}), "
                   f"record is {q_status}")
            if q_status == "claimed":
                msg += "; it will not run again, inspect by hand"
            _decision_alert(
                sync, ds, "decision_apply_failed", "apply_raised",
                reason=msg, rid=rid, queue_state=q_status,
            )
            continue

        result_status = result.get("status", "unknown")
        result_refusals = result.get("refusals", [])
        result_reason_code = result.get("reason_code")

        # Audit the outcome only on a change of (status, approvals, reason_codes)
        _audit_decision_outcome_deduped(sync, ds, rid, result)

        # Defer clear_request to after refusal alerts are processed
        # so that clear_request does not remove keys that refusal alerts
        # are about to recreate via ds.note().
        if result_status in ("executed", "denied", "not_pending"):
            rids_to_clear.append(rid)

        # Handle refusals from the verification step
        for ref in result_refusals:
            ref_code = ref.get("code", "unknown")
            ref_kid_raw = ref.get("key_id", "")
            ref_verified = ref.get("verified", False)
            ref_uid = ref.get("user_id")
            kid_display = _display_key_id(ref_kid_raw) if isinstance(ref_kid_raw, str) else "invalid"

            # R2 Low: use real status, not always "awaiting_second"
            display_status = result_status

            # R2 Low: verify_raised includes the exception type name
            sentence = _REFUSAL_SENTENCES.get(ref_code, "refused")
            exc_type = ref.get("exc_type")
            if ref_code == "verify_raised" and exc_type:
                sentence = f"{sentence} ({exc_type})"

            if ref_verified and ref_uid:
                reason_line = (f"{rid} {display_status}: key {kid_display} "
                               f"(user {ref_uid}) {ref_code}: "
                               f"{sentence}")
            else:
                reason_line = (f"{rid} {display_status}: claimed key "
                               f"{kid_display} {ref_code}: "
                               f"{sentence}")

            # R2-3: unverified refusal key is (kind, rid, code) -- no key_id
            if ref_verified:
                pa_key_id = ref_kid_raw
            else:
                pa_key_id = ""

            pending_alerts.append({
                "event": "decision_refused", "code": ref_code,
                "reason": reason_line, "rid": rid,
                "key_id": pa_key_id,
                "verified": ref_verified,
            })

        # Handle request-level reason codes
        if result_reason_code and result_status == "awaiting_second":
            pending_alerts.append({
                "event": "decision_refused", "code": result_reason_code,
                "reason": f"{rid} awaiting_second: {result_reason_code}: "
                          f"{_REFUSAL_SENTENCES.get(result_reason_code, 'refused')}",
                "rid": rid,
            })

        # Handle apply failures returned as status
        if result_status == "nonce_save_failed":
            pending_alerts.append({
                "event": "decision_apply_failed", "code": "nonce_save_failed",
                "reason": f"{rid} apply failed: nonce_save_failed: "
                          "nonce persistence failed, nothing executes",
                "rid": rid,
            })
        elif result_status == "key_unavailable":
            pending_alerts.append({
                "event": "decision_apply_failed", "code": "key_unavailable",
                "reason": f"{rid} apply failed: key_unavailable: "
                          f"{result.get('reason', 'connector key not available')}",
                "rid": rid,
            })
        elif result_status == "changed":
            pending_alerts.append({
                "event": "decision_refused", "code": "record_changed",
                "reason": f"{rid} refused: record_changed: "
                          "the pending record changed between read and claim",
                "rid": rid,
            })
        elif result_status == "not_pending" and queue.status(rid) == "pending":
            # T9A-8: pending_record_unreadable: queue says pending but apply says not
            pending_alerts.append({
                "event": "decision_apply_failed", "code": "pending_record_unreadable",
                "reason": f"{rid} apply failed: pending_record_unreadable",
                "rid": rid,
            })
        elif result_status == "invalid_id":
            # R4-7: a real "invalid_id" -> decision_refused / request_id_refused
            pending_alerts.append({
                "event": "decision_refused", "code": "request_id_refused",
                "reason": f"{rid} refused: request_id_refused: {result_status}",
                "rid": rid,
            })
        elif result_status == "not_pending":
            pending_alerts.append({
                "event": "decision_refused", "code": "request_id_refused",
                "reason": f"{rid} refused: not_pending: "
                          f"{_REFUSAL_SENTENCES.get('request_id_refused', 'refused')}",
                "rid": rid,
            })
        elif result_status == "refused":
            reason_text = result.get("reason", "")
            rc = result_reason_code or "request_id_refused"
            if "script_unbound" in reason_text:
                rc = "script_unbound"
            elif "script preview" in reason_text:
                rc = "script_preview_not_shown"
            pending_alerts.append({
                "event": "decision_refused", "code": rc,
                "reason": f"{rid} refused: {rc}: {reason_text}",
                "rid": rid,
            })

    # T9A-4: sort collected alerts by spec order; within decision_refused,
    # verified first (H2, R4-8).
    pending_alerts.sort(key=lambda a: (
        _ALERT_ORDER.get(a["event"], 9),
        0 if a.get("verified") else 1,
    ))

    # T9A-6: count refusals per (rid, code) for status display.
    # The alert dedupe key may collapse multiple refusals into one
    # alert (R2-3: unverified refusals share a key), but the status
    # display needs to know the total count for "+n more" truncation.
    # Only create indexed entries when count > 1 (to avoid doubling
    # single refusals with the dedup entry).
    _refusal_counts: dict[str, int] = {}  # "rid:code" -> count
    _refusal_reasons: dict[str, list[str]] = {}  # "rid:code" -> reasons
    for pa in pending_alerts:
        if pa.get("event") == "decision_refused" and pa.get("rid"):
            _rk = f"{pa['rid']}:{pa['code']}"
            _refusal_counts[_rk] = _refusal_counts.get(_rk, 0) + 1
            _refusal_reasons.setdefault(_rk, []).append(pa.get("reason", ""))
    for _rk, _cnt in _refusal_counts.items():
        if _cnt > 1:
            _parts = _rk.split(":", 1)
            _rid_k, _code_k = _parts[0], _parts[1] if len(_parts) > 1 else ""
            for idx in range(_cnt):
                _reason = _refusal_reasons[_rk][idx] if idx < len(_refusal_reasons[_rk]) else ""
                ds.note(
                    ("decision_refused", _rid_k, _code_k, str(idx)),
                    reason=_reason,
                )

    for pa in pending_alerts:
        _decision_alert(
            sync, ds, pa["event"], pa["code"],
            reason=pa.get("reason", ""), rid=pa.get("rid", ""),
            key_id=pa.get("key_id", ""), queue_state=pa.get("queue_state", ""),
            count=pa.get("count", 0), verified=pa.get("verified", False),
        )

    # T9A-4: clear request keys after refusal alerts are processed
    # so clear_request does not remove keys that alerts just created.
    for rid in rids_to_clear:
        ds.clear_request(rid)

    # R2 Low: clear malformed keys only when this cycle had no malformed rows.
    # If the same bad row repeats, the key persists and dedup suppresses.
    has_malformed = any(pa.get("event") == "decisions_malformed" for pa in pending_alerts)
    if not has_malformed:
        ds.clear_malformed_keys()

    # Emit suppression alert if needed (at most once per hour)
    if ds.suppressed_this_hour > 0:
        _emit_suppression_alert(sync, ds)

    ds.save()


def _rebuild_envelope(row: dict) -> tuple[dict | None, str]:
    """Rebuild an agg/remote-approval/v1 envelope from a server decision row.

    Returns ``(envelope, "")`` on success, ``(None, reason_code)`` on failure.
    The kind is fixed in code (never trust the server's kind column).
    The server's user_id column is ignored (comes from the registry).
    No try/except: JSON parse uses ``_safe_json_loads``.

    R3-1: keep 975e2bc truthiness and fallback exactly.
    - ``need_fallback = not sig or not key_id`` on the RAW values.
    - Pass raw values to the verifier (non-strings stay as-is).
    - Refuse the row (signature_missing) only where 975e2bc would have
      crashed (``signatures[0]`` not an object).
    """
    payload = row.get("signed_payload") or row.get("payload")
    if isinstance(payload, str):
        payload = _safe_json_loads(payload)
        if payload is None:
            return None, "payload_unusable"
    if not isinstance(payload, dict):
        return None, "payload_unusable"
    # R3-1: use 975e2bc's exact truthiness logic on RAW values.
    # ``or ""`` coerces None to "", keeping 975e2bc behaviour.
    sig = row.get("sig") or row.get("signature") or ""
    key_id = row.get("key_id") or payload.get("key_id", "")
    # R3-1: decide need_fallback on the raw values, before any type check.
    # 975e2bc: ``if not sig or not key_id:`` on these exact values.
    if not sig or not key_id:
        sigs = row.get("signatures", [])
        if isinstance(sigs, list) and sigs:
            s0 = sigs[0]
            if not isinstance(s0, dict):
                # 975e2bc: sigs[0].get() would crash -> signature_missing
                return None, "signature_missing"
            sig = s0.get("sig", "")
            key_id = s0.get("key_id", key_id)
    # R3-1: after fallback, 975e2bc checked ``if not sig: return None``.
    if not sig:
        return None, "signature_missing"
    # R2-1: do NOT sanitize key_id before sig check.  The raw value
    # reaches _verify_remote_approval so a control-char mismatch stays
    # a mismatch.  Sanitize for display only, never for lookup.
    return {
        "kind": "agg/remote-approval/v1",  # fixed in code
        "sig_v": 1,
        "payload": payload,
        "signatures": [{"key_id": key_id, "alg": "ed25519", "sig": sig}],
    }, ""


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

    try:
        _record_server_time(sync, hdrs)
    except Exception:  # noqa: BLE001 -- write failure: skew rule applies
        pass

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
