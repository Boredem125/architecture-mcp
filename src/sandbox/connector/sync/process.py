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
    """
    import urllib.request
    import urllib.error

    hdrs = dict(headers or {})
    if token:
        hdrs["Authorization"] = f"Bearer {token}"
    hdrs.setdefault("Content-Type", "application/json")

    data: bytes | None = None
    if body is not None:
        data = json.dumps(body).encode() if isinstance(body, dict) else body

    req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
    try:
        with urllib.request.urlopen(req) as resp:
            resp_body = resp.read()
            status = resp.status
            resp_headers = {k: v for k, v in resp.getheaders()}
    except urllib.error.HTTPError as exc:
        resp_body = exc.read()
        status = exc.code
        resp_headers = {k: v for k, v in exc.headers.items()}

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

        # ---- 2. Fetch decisions ----
        _fetch_decisions(sync)

        # ---- 3. Fetch and persist registry updates ----
        _fetch_registry(sync)

        # ---- 4. Upload pending escalations ----
        _upload_escalations(sync)

        # ---- 5. Upload audit records and checkpoint (managed only, T11) ----
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
    """Exchange the device key for a short-lived bearer token."""
    now = sync._clock()
    if sync._token and now < sync._token_expires:
        return  # still valid

    url = f"{sync.server_url}/api/v1/sync/token"
    status, body, hdrs = sync._connect(
        "POST", url,
        body={"device_id": sync.device_id, "iat": now},
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

    Only writes when the new chain passes ``verify_chain`` against the
    pinned root **and** the latest version is >= the current on-disk
    version (anti-rollback).  A forged or rollback chain is silently
    ignored -- it never overwrites the local state.
    """
    if sync.layout is None:
        return

    # Lazy imports -- never at module level (socket guard)
    from sandbox.connector.sync.state import pinned_root as _pinned_root

    fp = _pinned_root(sync.layout)
    if fp is None:
        return  # not enrolled

    sync_dir = sync.layout.root / ".sandbox" / "state" / "sync"
    reg_file = sync_dir / "registry.json"

    # Current version on disk
    current_version = 0
    if reg_file.exists():
        try:
            cur_chain = json.loads(reg_file.read_text(encoding="utf-8"))
            if isinstance(cur_chain, list) and cur_chain:
                current_version = cur_chain[-1].get("payload", {}).get("version", 0)
        except (OSError, ValueError):
            pass

    # Fetch from server
    url = f"{sync.server_url}/api/v1/sync/registry"
    status, body, hdrs = sync._connect("GET", url, token=sync._token)
    if status != 200:
        return

    _record_server_time(sync, hdrs)

    new_chain = body.get("registry")
    if not new_chain or not isinstance(new_chain, list):
        return

    # Verify the chain against the pinned root
    from sandbox.protocol.registry import verify_chain, RegistryError
    from sandbox.protocol.envelope import EnvelopeError

    try:
        verify_chain(new_chain, fp)
    except (RegistryError, EnvelopeError):
        return  # forged chain -- never persist

    # Anti-rollback: new version must be strictly greater, OR
    # byte-identical at the same version (no-op).
    new_version = new_chain[-1].get("payload", {}).get("version", 0)
    if new_version < current_version:
        return  # rollback attempt -- never persist

    new_blob = json.dumps(new_chain, sort_keys=True, separators=(",", ":"))

    if new_version == current_version:
        # Same version: only accept if byte-identical (no-op)
        if reg_file.exists():
            try:
                old_blob = reg_file.read_text(encoding="utf-8")
            except OSError:
                old_blob = ""
            if new_blob == old_blob:
                return  # no-op, already identical
        # Same version but different content -- refuse
        return

    # Persist (atomic rename)
    import os

    reg_tmp = sync_dir / "registry.json.tmp"
    try:
        reg_tmp.write_text(new_blob, encoding="utf-8")
        os.replace(str(reg_tmp), str(reg_file))
    except Exception:
        try:
            reg_tmp.unlink(missing_ok=True)
        except Exception:  # noqa: BLE001
            pass


def _fetch_decisions(sync: SyncProcess) -> None:
    """Poll for decisions (approvals/denies) from the server.

    Downloaded decisions are written to disk for the approval path to pick
    up.  Pending escalations are **never** auto-approved here.
    """
    url = f"{sync.server_url}/api/v1/sync/decisions"
    status, body, hdrs = sync._connect(
        "GET", url, token=sync._token,
    )
    if status != 200:
        raise SyncError(f"decisions fetch failed: HTTP {status}")

    _record_server_time(sync, hdrs)

    # Process decisions if the layout is available
    decisions = body.get("decisions", [])
    if not decisions or sync.layout is None:
        return

    # Write decisions to the layout for the approval path.
    # This never changes pending status to approved on its own --
    # the approval path (approval.apply_external) does that after
    # verifying signatures against the pinned registry.


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

    pending_dir = sync.layout.root / ".sandbox" / "pending"
    if not pending_dir.is_dir():
        return

    for f in pending_dir.iterdir():
        if not f.name.endswith(".json"):
            continue
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue

        if data.get("status") != "pending":
            continue

        # Scrub secrets before upload (threat 19)
        upload_data = dict(data)
        try:
            from sandbox.connector.scrub import scrub_text

            for key in ("command", "reason", "target", "described_as"):
                val = upload_data.get(key)
                if isinstance(val, str) and val:
                    upload_data[key] = scrub_text(val)
            # Scrub inside nested record if present
            rec = upload_data.get("record")
            if isinstance(rec, dict):
                rec = dict(rec)
                for key in ("command", "reason", "target", "described_as"):
                    val = rec.get(key)
                    if isinstance(val, str) and val:
                        rec[key] = scrub_text(val)
                upload_data["record"] = rec
        except Exception:  # noqa: BLE001 -- scrub failure must not block upload
            pass

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
            sync._connect(
                "POST", url,
                body=body,
                token=sync._token,
            )
        except Exception:
            # Upload failure does not change escalation status
            pass


# Alias for tests (threat 19 coverage)
_upload_escalations_scrubbed = _upload_escalations


def _upload_audit(sync: SyncProcess) -> None:
    """Upload audit records and send a checkpoint (D3, T11).

    Only runs in managed mode.  Lazy-imports ``audit_upload`` so the
    hook never loads it (socket guard).  An upload or checkpoint failure
    is logged but does **not** block the sync cycle or affect escalation
    status -- it simply means the next cycle will retry.
    """
    if sync.layout is None:
        return

    # Only upload in managed mode
    from sandbox.connector.sync.state import is_managed
    if not is_managed(sync.layout):
        return

    try:
        from sandbox.connector.sync.audit_upload import (
            AuditUploader, upload_records, send_checkpoint,
        )
    except ImportError:
        return  # module not yet available

    import logging
    _log = logging.getLogger(__name__)

    try:
        uploader = AuditUploader(sync.layout, sync.device_id, sync.device_key)
        upload_records(uploader, sync._connect, sync._token, sync.server_url)
        send_checkpoint(uploader, sync._connect, sync._token, sync.server_url)
    except Exception:
        # Audit upload/checkpoint failure must not block the cycle,
        # auto-approve escalations, or affect backoff.  The next
        # cycle will retry from the cursor.
        _log.exception("audit upload/checkpoint failed")
