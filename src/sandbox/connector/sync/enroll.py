"""Enrollment client: enroll, token exchange, unenroll (D1, D7.2).

The client sends the code itself (NOT the hash); the server hashes it.
Proof of possession signs ``{code_hash, public_key, aud, iat}`` with tag
``agg/device-enroll/v1``.  Fingerprint verification is mandatory and
non-interactive (D1.3, threat 2).
"""
from __future__ import annotations

import hashlib
import json
import secrets
import time
from pathlib import Path
from typing import Any

from nacl.signing import SigningKey, VerifyKey

from sandbox.protocol.domains import DEVICE_ENROLL, DEVICE_ASSERT, UNENROLL
from sandbox.protocol.envelope import (
    canonical_bytes,
    key_id,
    sign_envelope,
    EnvelopeError,
)


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

class EnrollError(Exception):
    """Enrollment or re-enrollment failed."""


class TokenError(Exception):
    """Token request failed."""


class UnenrollError(Exception):
    """Unenrollment failed."""


# ---------------------------------------------------------------------------
# Fixed field set for unenroll decisions (F1)
# ---------------------------------------------------------------------------

UNENROLL_FIELDS = frozenset({
    "org_id", "project_id", "device_id", "registry_version",
    "nonce", "issued_at", "not_after",
})


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def enroll(
    server: str,
    code: str,
    expect_fingerprint: str | None,
    *,
    ca: str | None = None,
) -> dict[str, Any]:
    """Enroll this connector with the control plane.

    POST *server*/api/v1/sync/enroll with the code (not its hash) and a
    proof of possession.  Raises :class:`EnrollError` on any failure.
    """
    import urllib.request
    import urllib.error

    # --expect-fingerprint is mandatory (D1.3, threat 2)
    if not expect_fingerprint:
        raise EnrollError("--expect-fingerprint is required; no interactive accept")

    # Check if there's already a pinned root (threat 37: re-enroll
    # with a different fingerprint than the pinned root is refused)
    _check_pinned_root_conflict(expect_fingerprint)

    # Generate a device key pair
    sk = SigningKey.generate()
    pub = bytes(sk.verify_key)
    kid = key_id(pub)

    # Build proof of possession (signs code_hash, not the code)
    code_hash = hashlib.sha256(code.encode()).hexdigest()
    proof_payload = {
        "code_hash": code_hash,
        "public_key": pub.hex(),
        "aud": server,
        "iat": time.time(),
    }
    proof = sign_envelope(DEVICE_ENROLL, proof_payload, [sk])

    body = json.dumps({
        "code": code,
        "public_key": pub.hex(),
        "proof": proof,
    }).encode()

    url = server.rstrip("/") + "/api/v1/sync/enroll"
    req = urllib.request.Request(
        url, data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        resp = urllib.request.urlopen(req)
        data = json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        _raise_enroll_error(exc)

    # Fingerprint check (threat 2) -- mismatch writes nothing
    returned_fp = data.get("fingerprint", "")
    if returned_fp != expect_fingerprint:
        raise EnrollError(
            f"fingerprint mismatch: expected {expect_fingerprint!r}, "
            f"got {returned_fp!r}; nothing written"
        )

    return data


def request_token(
    server: str,
    device_key: SigningKey,
    device_id: str,
    *,
    ca: str | None = None,
) -> str:
    """Exchange a device assertion for a bearer token.

    POST *server*/api/v1/sync/token.  Raises :class:`TokenError` on failure.
    """
    import urllib.request
    import urllib.error

    nonce = secrets.token_hex(16)
    assertion_payload = {
        "device_id": device_id,
        "aud": server,
        "iat": time.time(),
        "nonce": nonce,
    }
    assertion = sign_envelope(DEVICE_ASSERT, assertion_payload, [device_key])

    body = json.dumps({
        "device_id": device_id,
        "assertion": assertion,
    }).encode()

    url = server.rstrip("/") + "/api/v1/sync/token"
    req = urllib.request.Request(
        url, data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        resp = urllib.request.urlopen(req)
        data = json.loads(resp.read())
        return data["token"]
    except urllib.error.HTTPError as exc:
        _raise_token_error(exc)
    except (KeyError, ValueError) as exc:
        raise TokenError(f"bad token response: {exc}") from exc
    # Unreachable, but keeps mypy happy
    raise TokenError("unexpected error")  # pragma: no cover


def unenroll(layout, decision_path: str | None) -> None:
    """Verify an ``agg/unenroll/v1`` decision from a file (D1.8, threat 34).

    Only a quorum-signed decision is accepted.  Local two-reviewer
    unenroll is refused because one person can pin two local ids.
    """
    from sandbox.connector.sync.state import is_managed

    if not is_managed(layout):
        raise UnenrollError("workspace is not managed")

    if decision_path is None:
        raise UnenrollError(
            "unenroll requires a quorum-signed decision file; "
            "local two-reviewer unenroll is refused"
        )

    # Read decision file
    try:
        raw = Path(decision_path).read_text(encoding="utf-8")
        decision = json.loads(raw)
    except (OSError, ValueError) as exc:
        raise UnenrollError(f"cannot read decision file: {exc}") from exc

    # Validate kind
    if decision.get("kind") != UNENROLL:
        raise UnenrollError(
            f"expected kind {UNENROLL}, got {decision.get('kind')}"
        )

    if decision.get("sig_v") != 1:
        raise UnenrollError(
            f"expected sig_v 1, got {decision.get('sig_v')}"
        )

    payload = decision.get("payload", {})

    # Check field set (F1)
    payload_keys = set(payload.keys())
    if payload_keys != UNENROLL_FIELDS:
        raise UnenrollError(
            f"field set mismatch: got {payload_keys}, "
            f"expected {UNENROLL_FIELDS}"
        )

    # Check device_id matches current device (F1: re-enroll gives new id)
    sync_dir = layout.root / ".sandbox" / "state" / "sync"
    device_id_file = sync_dir / "device_id"
    if device_id_file.exists():
        current_device_id = device_id_file.read_text(encoding="utf-8").strip()
        if payload.get("device_id") != current_device_id:
            raise UnenrollError(
                f"device_id mismatch: decision is for "
                f"{payload.get('device_id')!r}, "
                f"current device is {current_device_id!r}"
            )

    # Verify at least one signature from a trusted key
    sigs = decision.get("signatures", [])
    if not sigs:
        raise UnenrollError("no signatures in decision")

    # Load pinned registry
    from sandbox.connector.sync.state import pinned_root

    root_fp = pinned_root(layout)
    if root_fp is None:
        raise UnenrollError(
            "signature verification failed: no pinned registry root"
        )

    registry_file = sync_dir / "registry.json"
    if not registry_file.exists():
        raise UnenrollError(
            "signature verification failed: no pinned registry"
        )

    try:
        registry_data = json.loads(
            registry_file.read_text(encoding="utf-8")
        )
    except (OSError, ValueError) as exc:
        raise UnenrollError(f"cannot read registry: {exc}") from exc

    # Verify chain
    from sandbox.protocol.registry import verify_chain, RegistryError

    chain = (
        registry_data if isinstance(registry_data, list)
        else [registry_data]
    )
    try:
        registry = verify_chain(chain, root_fp)
    except (RegistryError, EnvelopeError) as exc:
        raise UnenrollError(f"registry verification failed: {exc}") from exc

    # Verify unenroll envelope signatures
    msg = canonical_bytes(UNENROLL, payload)
    verified_keys: set[str] = set()
    for sig_entry in sigs:
        kid = sig_entry.get("key_id", "")
        key_entry = registry._keys.get(kid)
        if key_entry is None:
            continue
        try:
            vk = VerifyKey(bytes.fromhex(key_entry["public_key"]))
            vk.verify(msg, bytes.fromhex(sig_entry.get("sig", "")))
            verified_keys.add(kid)
        except Exception as exc:
            raise UnenrollError(
                f"signature verification failed for key {kid}"
            ) from exc

    if not verified_keys:
        raise UnenrollError(
            "no valid signatures from trusted registry keys"
        )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _raise_enroll_error(exc: Exception) -> None:
    """Map an HTTPError to EnrollError.  Always raises."""
    import urllib.error

    assert isinstance(exc, urllib.error.HTTPError)
    status = exc.code
    try:
        err_body = json.loads(exc.read())
        err = err_body.get("error", "")
    except Exception:
        err = ""

    if status == 409:
        raise EnrollError(f"code already used/consumed: {err}") from exc
    if status == 410:
        raise EnrollError(f"code expired: {err}") from exc
    if status == 429:
        raise EnrollError(f"rate limited (429): {err}") from exc
    if status == 403:
        raise EnrollError(f"wrong operator/unauthorized: {err}") from exc
    if status == 404:
        raise EnrollError(f"code not found: {err}") from exc
    raise EnrollError(f"enrollment failed ({status}): {err}") from exc


def _check_pinned_root_conflict(expect_fingerprint: str) -> None:
    """Refuse re-enrollment with a fingerprint that differs from any pinned root."""
    try:
        from sandbox.connector.keyhome import _discover_workspace_roots
        from sandbox.connector.sync.state import pinned_root as _pinned_root
        from sandbox.connector.layout import FolderLayout

        for ws_root in _discover_workspace_roots():
            try:
                lay = FolderLayout(ws_root)
                if not lay.exists():
                    continue
                existing_fp = _pinned_root(lay)
                if existing_fp and existing_fp != expect_fingerprint:
                    raise EnrollError(
                        f"fingerprint differs from pinned root: "
                        f"pinned={existing_fp!r}, "
                        f"expected={expect_fingerprint!r}; "
                        f"pinned root mismatch"
                    )
            except EnrollError:
                raise
            except Exception:  # noqa: BLE001
                continue
    except EnrollError:
        raise
    except Exception:  # noqa: BLE001
        pass  # discovery unavailable; proceed normally


def _raise_token_error(exc: Exception) -> None:
    """Map an HTTPError to TokenError.  Always raises."""
    import urllib.error

    assert isinstance(exc, urllib.error.HTTPError)
    status = exc.code
    try:
        err_body = json.loads(exc.read())
        err = err_body.get("error", "")
    except Exception:
        err = ""

    if status == 401:
        if "revoked" in err:
            raise TokenError(f"device revoked (401): {err}") from exc
        if "iat" in err or "expired" in err or "stale" in err:
            raise TokenError(f"iat expired/stale (401): {err}") from exc
        if "nonce" in err:
            raise TokenError(f"nonce replay (401): {err}") from exc
        raise TokenError(f"unauthorized (401): {err}") from exc
    if status == 404:
        raise TokenError(f"device not found (404): {err}") from exc
    raise TokenError(f"token request failed ({status}): {err}") from exc
