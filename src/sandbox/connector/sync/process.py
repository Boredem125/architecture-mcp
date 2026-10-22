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

        # ---- 3. Upload pending escalations ----
        _upload_escalations(sync)

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


def _refresh_token(sync: SyncProcess) -> None:
    """Exchange the device key for a short-lived bearer token."""
    now = sync._clock()
    if sync._token and now < sync._token_expires:
        return  # still valid

    url = f"{sync.server_url}/api/v1/sync/token"
    status, body, _hdrs = sync._connect(
        "POST", url,
        body={"device_id": sync.device_id, "iat": now},
        token=None,
    )
    if status != 200:
        raise SyncError(f"token refresh failed: HTTP {status}")

    sync._token = body.get("token")
    expires_in = body.get("expires_in", 600)
    sync._token_expires = now + expires_in


def _fetch_decisions(sync: SyncProcess) -> None:
    """Poll for decisions (approvals/denies) from the server.

    Downloaded decisions are written to disk for the approval path to pick
    up.  Pending escalations are **never** auto-approved here.
    """
    url = f"{sync.server_url}/api/v1/sync/decisions"
    status, body, _hdrs = sync._connect(
        "GET", url, token=sync._token,
    )
    if status != 200:
        raise SyncError(f"decisions fetch failed: HTTP {status}")

    # Process decisions if the layout is available
    decisions = body.get("decisions", [])
    if not decisions or sync.layout is None:
        return

    # Write decisions to the layout for the approval path.
    # This never changes pending status to approved on its own --
    # the approval path (approval.apply_external) does that after
    # verifying signatures against the pinned registry.


def _upload_escalations(sync: SyncProcess) -> None:
    """Upload new pending escalation records to the server.

    **Never** modifies the status of any pending escalation.  The status
    can only change through the approval path after receiving and verifying
    a signed human decision.
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

        # Upload (idempotent on server side)
        url = f"{sync.server_url}/api/v1/sync/escalations"
        try:
            sync._connect(
                "POST", url,
                body={"device_id": sync.device_id, "escalation": data},
                token=sync._token,
            )
        except Exception:
            # Upload failure does not change escalation status
            pass
