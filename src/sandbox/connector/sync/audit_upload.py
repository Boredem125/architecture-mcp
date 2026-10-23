"""Client-side audit upload: reads the local audit chain spool and
uploads records to the control plane in order (D3, T11).

This module is lazy-imported from ``sync.process.run_once``.
The hook must never import it -- a guard test enforces this.

Design invariants:
  - The cursor (``.sandbox/state/sync/cursor.json``) tracks
    ``(session_id, chain_length)`` per session.
  - Records are uploaded in chain_length order per session.
  - The cursor sits under the non-removable deny (threat 20).
  - ``upload_seq`` increments by exactly 1 per checkpoint (S11).
  - Every local session since enrollment is listed in the checkpoint (S12).
  - A fork from the server (409) raises ``AuditUploadError``.
"""
from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any, Callable


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class AuditUploadError(Exception):
    """Non-recoverable error during audit upload."""


# ---------------------------------------------------------------------------
# AuditUploader
# ---------------------------------------------------------------------------


class AuditUploader:
    """Holds the layout, device identity and upload state.

    Parameters
    ----------
    layout : FolderLayout
        The workspace layout (provides ``audit_dir`` and state paths).
    device_id : str
        The enrolled device id.
    device_key : bytes
        The 32-byte Ed25519 signing key seed.
    """

    def __init__(self, layout: Any, device_id: str, device_key: bytes) -> None:
        self.layout = layout
        self.device_id = device_id
        self._device_key = device_key

        # Lazily initialised state
        self._cursor: dict | None = None
        # Track acknowledged server heads per session for verify_head
        self._acked_heads: dict[str, dict] = {}
        # Tracks all known session ids across the lifetime (for S12)
        self._known_sessions: set[str] = set()

    # -- cursor persistence ------------------------------------------------

    @property
    def _cursor_path(self) -> Path:
        return self.layout.root / ".sandbox" / "state" / "sync" / "cursor.json"

    def _load_cursor(self) -> dict:
        if self._cursor is not None:
            return self._cursor
        try:
            self._cursor = json.loads(
                self._cursor_path.read_text(encoding="utf-8"),
            )
        except (OSError, ValueError):
            self._cursor = {"sessions": {}, "upload_seq": 0}
        # Initialise known sessions from cursor
        for sid in self._cursor.get("sessions", {}):
            self._known_sessions.add(sid)
        return self._cursor

    def _save_cursor(self) -> None:
        cursor = self._load_cursor()
        p = self._cursor_path
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_suffix(".tmp")
        tmp.write_text(json.dumps(cursor), encoding="utf-8")
        import os
        os.replace(str(tmp), str(p))

    # -- signing -----------------------------------------------------------

    def _sign_envelope(self, kind: str, payload: dict) -> dict:
        """Sign an ``agg`` protocol envelope with the device key."""
        from nacl.signing import SigningKey

        sk = SigningKey(self._device_key[:32])
        tag = kind.encode("utf-8")
        canonical = json.dumps(
            payload, sort_keys=True, separators=(",", ":"),
        ).encode()
        msg = tag + b"\x00" + canonical
        pub = bytes(sk.verify_key)
        kid = hashlib.sha256(pub).hexdigest()
        sig = sk.sign(msg).signature.hex()
        return {
            "kind": kind,
            "sig_v": 1,
            "payload": payload,
            "signatures": [{"key_id": kid, "alg": "ed25519", "sig": sig}],
        }


# ---------------------------------------------------------------------------
# upload_records
# ---------------------------------------------------------------------------


def upload_records(
    uploader: AuditUploader,
    connect: Callable[..., tuple[int, dict, dict]],
    token: str,
    server_url: str,
) -> dict:
    """Upload pending audit records for all local sessions.

    Returns a dict with ``uploaded`` count and the last ``server_head``.
    """
    from sandbox.connector.audit import session_ids, verify_records_bytes

    cursor = uploader._load_cursor()
    sessions = cursor.setdefault("sessions", {})
    audit_dir = uploader.layout.audit_dir

    total_uploaded = 0
    last_server_head: dict | None = None

    # Discover all local sessions
    local_sessions = session_ids(audit_dir)
    for sid in local_sessions:
        uploader._known_sessions.add(sid)

    for sid in local_sessions:
        records_file = audit_dir / sid / "records.jsonl"
        if not records_file.exists():
            continue

        # Load all records
        all_records = []
        with open(records_file, encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    try:
                        all_records.append(json.loads(line))
                    except (ValueError, json.JSONDecodeError):
                        continue

        # Determine where to resume
        sess_cursor = sessions.get(sid, {})
        cursor_length = sess_cursor.get("chain_length", 0)

        # Truncation check: local records fewer than cursor says
        if len(all_records) < cursor_length:
            raise AuditUploadError(
                f"truncation detected for session {sid}: "
                f"local has {len(all_records)} records but cursor at {cursor_length}"
            )

        # Filter to records after the cursor
        pending = [r for r in all_records if r.get("chain_length", 0) > cursor_length]
        # Sort by chain_length
        pending.sort(key=lambda r: r.get("chain_length", 0))

        for rec in pending:
            # Build the upload body
            body = {
                "session_id": sid,
                "chain_length": rec["chain_length"],
                "previous_hash": rec["previous_hash"],
                "record_hash": rec["record_hash"],
                "body": {
                    k: v for k, v in rec.items()
                    if k not in ("previous_hash", "chain_length", "record_hash")
                },
            }

            url = f"{server_url.rstrip('/')}/api/v1/sync/audit"
            status, resp_body, _hdrs = connect(
                "POST", url, body=body, token=token,
            )

            if status == 401:
                raise AuditUploadError(
                    f"device revoked or unauthorized (401): "
                    f"{resp_body.get('error', 'unknown')}"
                )
            if status == 404:
                raise AuditUploadError(
                    f"not found (404): {resp_body.get('error', 'unknown')}"
                )
            if status == 409:
                raise AuditUploadError(
                    f"fork/quarantine (409): {resp_body.get('error', 'unknown')}"
                )
            if status == 400:
                raise AuditUploadError(
                    f"gap or chain error (400): {resp_body.get('error', 'unknown')}"
                )
            if status == 413:
                raise AuditUploadError(
                    f"batch too large (413): {resp_body.get('error', 'unknown')}"
                )
            if status < 200 or status >= 300:
                raise AuditUploadError(
                    f"upload failed ({status}): {resp_body.get('error', 'unknown')}"
                )

            # Update cursor
            sessions[sid] = {
                "chain_length": rec["chain_length"],
                "head_hash": rec["record_hash"],
            }
            uploader._save_cursor()

            # Track server head for verify_head
            server_head = resp_body.get("server_head")
            if server_head:
                uploader._acked_heads[sid] = server_head
                last_server_head = server_head

            total_uploaded += 1

    return {"uploaded": total_uploaded, "server_head": last_server_head}


# ---------------------------------------------------------------------------
# send_checkpoint
# ---------------------------------------------------------------------------


def send_checkpoint(
    uploader: AuditUploader,
    connect: Callable[..., tuple[int, dict, dict]],
    token: str,
    server_url: str,
) -> dict:
    """Send a device-signed checkpoint listing every local session (S12).

    Returns the server's acknowledged ``upload_seq``.
    """
    from sandbox.connector.audit import session_ids

    cursor = uploader._load_cursor()
    audit_dir = uploader.layout.audit_dir

    # Discover all local sessions and merge with known sessions
    local_sessions = session_ids(audit_dir)
    for sid in local_sessions:
        uploader._known_sessions.add(sid)
    # Also include sessions from the cursor (even if dir was deleted)
    for sid in cursor.get("sessions", {}):
        uploader._known_sessions.add(sid)

    # Build session list
    sessions_list = []
    for sid in sorted(uploader._known_sessions):
        records_file = audit_dir / sid / "records.jsonl"
        if records_file.exists():
            # Read the actual chain to get current length and head
            chain_length = 0
            head_hash = ""
            with open(records_file, encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        try:
                            rec = json.loads(line)
                            chain_length = rec.get("chain_length", chain_length)
                            head_hash = rec.get("record_hash", head_hash)
                        except (ValueError, json.JSONDecodeError):
                            continue
            sessions_list.append({
                "session_id": sid,
                "chain_length": chain_length,
                "head_hash": head_hash,
            })
        else:
            # Session was deleted locally but we still report it (S12)
            sess_cursor = cursor.get("sessions", {}).get(sid, {})
            sessions_list.append({
                "session_id": sid,
                "chain_length": sess_cursor.get("chain_length", 0),
                "head_hash": sess_cursor.get("head_hash", ""),
            })

    # Increment upload_seq
    upload_seq = cursor.get("upload_seq", 0) + 1

    payload = {
        "device_id": uploader.device_id,
        "upload_seq": upload_seq,
        "sessions": sessions_list,
        "ts": time.time(),
    }

    envelope = uploader._sign_envelope("agg/audit-head/v1", payload)

    url = f"{server_url.rstrip('/')}/api/v1/sync/checkpoint"
    status, resp_body, _hdrs = connect(
        "POST", url, body=envelope, token=token,
    )

    if status == 400:
        error = resp_body.get("error", "unknown")
        raise AuditUploadError(
            f"checkpoint refused (400): {error}"
        )
    if status == 401:
        raise AuditUploadError("checkpoint unauthorized (401)")
    if status < 200 or status >= 300:
        raise AuditUploadError(
            f"checkpoint failed ({status}): {resp_body.get('error', 'unknown')}"
        )

    # Persist the new upload_seq
    cursor["upload_seq"] = upload_seq
    uploader._save_cursor()

    return {"upload_seq": upload_seq}


# ---------------------------------------------------------------------------
# verify_head
# ---------------------------------------------------------------------------


def verify_head(uploader: AuditUploader, server_head: dict) -> None:
    """Raise if the server's head is behind what was acknowledged (D3.4, threat 18).

    ``server_head`` is ``{session_id, chain_length, head_hash}``.
    """
    sid = server_head.get("session_id", "")
    acked = uploader._acked_heads.get(sid)
    if acked is None:
        return  # nothing acknowledged yet for this session

    acked_length = acked.get("chain_length", 0)
    server_length = server_head.get("chain_length", 0)

    if server_length < acked_length:
        raise AuditUploadError(
            f"server_head_mismatch: server head for {sid} is at "
            f"chain_length {server_length} but we acknowledged {acked_length} "
            f"(server rewound/deleted audit records)"
        )
