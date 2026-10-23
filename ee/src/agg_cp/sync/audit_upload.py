"""Server-side audit upload routes (D3, T11).

POST /api/v1/sync/audit    -- device token auth, batch upload
POST /api/v1/sync/checkpoint -- device token auth, signed checkpoint

Connections ``SET ROLE agg_app`` like enroll.py/signer.py/bundles.py.
Auth pattern matches GET /api/v1/sync/registry and /sync/bundle.
"""
from __future__ import annotations

import hashlib
import json
import uuid
from typing import Any

import psycopg
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from ..rbac import rbac_route


def _conninfo(url: str) -> str:
    return url.replace("+psycopg", "")


_MAX_RECORDS = 1000
_MAX_BODY_BYTES = 1_048_576  # 1 MiB


def audit_upload_router(db_url: str, clock=None) -> APIRouter:
    """Build the audit upload router."""
    conninfo = _conninfo(db_url)
    router = APIRouter()

    def _conn():
        c = psycopg.connect(conninfo)
        c.execute("SET ROLE agg_app")
        return c

    def _device_token_lookup(conn, token: str):
        """Look up a device token via SECURITY DEFINER function.

        Returns (org_id, project_id, connector_id) or None.
        """
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        row = conn.execute(
            "SELECT * FROM device_token_lookup(%s)",
            [token_hash],
        ).fetchone()
        return row

    def _get_device_public_key(conn, connector_id: str) -> str | None:
        """Look up the device public key for a connector."""
        row = conn.execute(
            "SELECT * FROM device_lookup(%s::uuid)",
            [connector_id],
        ).fetchone()
        if row is None:
            return None
        # device_lookup returns (org_id, project_id, connector_id, public_key, revoked_at)
        return row[3]  # public_key (hex)

    def _verify_envelope_signature(
        envelope: dict, expected_pub_hex: str,
    ) -> bool:
        """Verify an agg protocol envelope signature against the expected public key."""
        try:
            from nacl.signing import VerifyKey

            kind = envelope.get("kind", "")
            payload = envelope.get("payload", {})
            sigs = envelope.get("signatures", [])
            if not sigs:
                return False

            sig_entry = sigs[0]
            expected_kid = hashlib.sha256(
                bytes.fromhex(expected_pub_hex),
            ).hexdigest()

            if sig_entry.get("key_id") != expected_kid:
                return False

            tag = kind.encode("utf-8")
            canonical = json.dumps(
                payload, sort_keys=True, separators=(",", ":"),
            ).encode()
            msg = tag + b"\x00" + canonical

            vk = VerifyKey(bytes.fromhex(expected_pub_hex))
            sig_bytes = bytes.fromhex(sig_entry["sig"])
            vk.verify(msg, sig_bytes)
            return True
        except Exception:
            return False

    # -----------------------------------------------------------------
    # POST /api/v1/sync/audit (device token auth)
    # -----------------------------------------------------------------
    @rbac_route(
        router, "post", "/api/v1/sync/audit",
        role="device", scope="project",
    )
    async def upload_audit_records(request: Request) -> JSONResponse:
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        token = auth[7:]

        # Read raw body for size check
        raw_body = await request.body()
        if len(raw_body) > _MAX_BODY_BYTES:
            return JSONResponse(
                {"error": "body_too_large"},
                status_code=413,
            )

        try:
            body = json.loads(raw_body)
        except (ValueError, json.JSONDecodeError):
            return JSONResponse({"error": "invalid_json"}, status_code=400)

        session_id = body.get("session_id", "")
        records = body.get("records", [])

        if not session_id or not isinstance(records, list):
            return JSONResponse(
                {"error": "missing_session_id_or_records"},
                status_code=400,
            )

        if len(records) > _MAX_RECORDS:
            return JSONResponse(
                {"error": "too_many_records"},
                status_code=413,
            )

        with _conn() as conn:
            device = _device_token_lookup(conn, token)
            if device is None:
                return JSONResponse(
                    {"error": "unauthorized"}, status_code=401,
                )
            d_org, d_project, d_connector = (
                str(device[0]), str(device[1]), str(device[2]),
            )

            # Set org context for RLS
            conn.execute(
                "SELECT set_config('app.org_id', %s, true)",
                [d_org],
            )

            # All-or-nothing: process in a transaction
            try:
                last_head: dict = {}
                for rec in records:
                    chain_length = rec.get("chain_length")
                    previous_hash = rec.get("previous_hash", "")
                    record_hash = rec.get("record_hash", "")
                    rec_body = rec.get("body")

                    if chain_length is None:
                        conn.rollback()
                        return JSONResponse(
                            {"error": "missing_chain_length"},
                            status_code=400,
                        )

                    # Get current head for this session
                    head_row = conn.execute(
                        "SELECT chain_length, record_hash FROM audit_records "
                        "WHERE connector_id = %s::uuid "
                        "  AND session_id = %s "
                        "ORDER BY chain_length DESC LIMIT 1",
                        [d_connector, session_id],
                    ).fetchone()

                    current_length = head_row[0] if head_row else 0
                    current_hash = head_row[1] if head_row else ""

                    # Same position, same hash = no-op
                    if chain_length == current_length and record_hash == current_hash:
                        last_head = {
                            "session_id": session_id,
                            "chain_length": current_length,
                            "head_hash": current_hash,
                            "noop": True,
                        }
                        continue

                    # Same position, different hash = fork -> quarantine
                    if chain_length <= current_length:
                        # Check if the existing record at this position has a
                        # different hash
                        existing = conn.execute(
                            "SELECT record_hash FROM audit_records "
                            "WHERE connector_id = %s::uuid "
                            "  AND session_id = %s "
                            "  AND chain_length = %s",
                            [d_connector, session_id, chain_length],
                        ).fetchone()
                        if existing and existing[0] != record_hash:
                            # Fork detected -- quarantine
                            conn.execute(
                                "INSERT INTO audit_quarantine "
                                "(id, org_id, connector_id, kind, detail, "
                                "created_at) "
                                "VALUES (%s, %s::uuid, %s::uuid, 'fork', "
                                "%s::jsonb, now())",
                                [
                                    str(uuid.uuid4()), d_org, d_connector,
                                    json.dumps({
                                        "session_id": session_id,
                                        "chain_length": chain_length,
                                        "existing_hash": existing[0],
                                        "forked_hash": record_hash,
                                    }),
                                ],
                            )
                            # Insert alert
                            conn.execute(
                                "INSERT INTO sync_alerts "
                                "(id, org_id, project_id, connector_id, "
                                "kind, detail, created_at) "
                                "VALUES (%s, %s::uuid, %s::uuid, %s::uuid, "
                                "'fork', %s::jsonb, now())",
                                [
                                    str(uuid.uuid4()), d_org, d_project,
                                    d_connector,
                                    json.dumps({
                                        "session_id": session_id,
                                        "chain_length": chain_length,
                                    }),
                                ],
                            )
                            conn.commit()
                            return JSONResponse(
                                {"error": "fork", "detail": "quarantined"},
                                status_code=409,
                            )
                        elif existing and existing[0] == record_hash:
                            # Same position, same hash = no-op
                            last_head = {
                                "session_id": session_id,
                                "chain_length": chain_length,
                                "head_hash": record_hash,
                                "noop": True,
                            }
                            continue
                        else:
                            # No existing record at this position but
                            # chain_length <= current: gap or out of order
                            conn.rollback()
                            return JSONResponse(
                                {"error": "gap"},
                                status_code=400,
                            )

                    # Gap check: chain_length must be exactly current + 1
                    if chain_length != current_length + 1:
                        conn.rollback()
                        return JSONResponse(
                            {"error": "gap"},
                            status_code=400,
                        )

                    # previous_hash must match current head
                    if previous_hash != current_hash:
                        conn.rollback()
                        return JSONResponse(
                            {"error": "chain_broken",
                             "detail": "previous_hash mismatch"},
                            status_code=400,
                        )

                    # Insert the record
                    conn.execute(
                        "INSERT INTO audit_records "
                        "(id, org_id, connector_id, session_id, "
                        "chain_length, previous_hash, record_hash, "
                        "body, created_at) "
                        "VALUES (%s, %s::uuid, %s::uuid, %s, %s, %s, %s, "
                        "%s::jsonb, now())",
                        [
                            str(uuid.uuid4()), d_org, d_connector,
                            session_id, chain_length, previous_hash,
                            record_hash,
                            json.dumps(rec_body) if rec_body else None,
                        ],
                    )

                    last_head = {
                        "session_id": session_id,
                        "chain_length": chain_length,
                        "head_hash": record_hash,
                    }

                conn.commit()
            except psycopg.errors.UniqueViolation:
                conn.rollback()
                # Unique violation on (connector_id, session_id, chain_length)
                # means the record already exists -- treat as no-op if hash
                # matches, fork otherwise.
                return JSONResponse(
                    {"error": "duplicate_record"},
                    status_code=409,
                )
            except Exception:
                conn.rollback()
                raise

        return JSONResponse(
            {"server_head": last_head},
            status_code=200,
        )

    # -----------------------------------------------------------------
    # POST /api/v1/sync/checkpoint (device token auth)
    # -----------------------------------------------------------------
    @rbac_route(
        router, "post", "/api/v1/sync/checkpoint",
        role="device", scope="project",
    )
    async def upload_checkpoint(request: Request) -> JSONResponse:
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        token = auth[7:]

        body = await request.json()

        with _conn() as conn:
            device = _device_token_lookup(conn, token)
            if device is None:
                return JSONResponse(
                    {"error": "unauthorized"}, status_code=401,
                )
            d_org, d_project, d_connector = (
                str(device[0]), str(device[1]), str(device[2]),
            )

            # Set org context for RLS
            conn.execute(
                "SELECT set_config('app.org_id', %s, true)",
                [d_org],
            )

            # Validate envelope structure
            kind = body.get("kind", "")
            if kind != "agg/audit-head/v1":
                return JSONResponse(
                    {"error": "invalid_kind"},
                    status_code=400,
                )

            payload = body.get("payload", {})
            payload_device_id = payload.get("device_id", "")

            # Device ID from payload must match token's device
            if payload_device_id != d_connector:
                return JSONResponse(
                    {"error": "device_id_mismatch"},
                    status_code=400,
                )

            # Verify signature against the device's registered public key
            pub_hex = _get_device_public_key(conn, d_connector)
            if pub_hex is None:
                return JSONResponse(
                    {"error": "device_not_found"},
                    status_code=400,
                )

            if not _verify_envelope_signature(body, pub_hex):
                return JSONResponse(
                    {"error": "invalid_signature"},
                    status_code=400,
                )

            upload_seq = payload.get("upload_seq", 0)
            sessions = payload.get("sessions", [])

            # Check upload_seq: must be last stored + 1
            last_seq_row = conn.execute(
                "SELECT upload_seq FROM audit_heads "
                "WHERE connector_id = %s::uuid "
                "ORDER BY upload_seq DESC LIMIT 1",
                [d_connector],
            ).fetchone()
            last_seq = last_seq_row[0] if last_seq_row else 0

            if upload_seq == last_seq:
                return JSONResponse(
                    {"error": "seq_repeat"},
                    status_code=409,
                )
            if upload_seq != last_seq + 1:
                return JSONResponse(
                    {"error": "seq_skip"},
                    status_code=400,
                )

            # Get previous checkpoint's session list for comparison
            prev_sessions: dict[str, int] = {}
            if last_seq > 0:
                prev_row = conn.execute(
                    "SELECT session_list FROM audit_heads "
                    "WHERE connector_id = %s::uuid "
                    "  AND upload_seq = %s",
                    [d_connector, last_seq],
                ).fetchone()
                if prev_row and prev_row[0]:
                    prev_list = prev_row[0]
                    if isinstance(prev_list, str):
                        prev_list = json.loads(prev_list)
                    for s in prev_list:
                        prev_sessions[s["session_id"]] = s.get("chain_length", 0)

            # Check for session_missing and truncation
            current_session_ids = {s["session_id"] for s in sessions}
            for prev_sid, prev_length in prev_sessions.items():
                if prev_sid not in current_session_ids:
                    # Session missing alert (threat 32)
                    conn.execute(
                        "INSERT INTO sync_alerts "
                        "(id, org_id, project_id, connector_id, "
                        "kind, detail, created_at) "
                        "VALUES (%s, %s::uuid, %s::uuid, %s::uuid, "
                        "'session_missing', %s::jsonb, now())",
                        [
                            str(uuid.uuid4()), d_org, d_project,
                            d_connector,
                            json.dumps({"session_id": prev_sid}),
                        ],
                    )

            for sess in sessions:
                sid = sess["session_id"]
                cl = sess.get("chain_length", 0)
                prev_cl = prev_sessions.get(sid)
                if prev_cl is not None and cl < prev_cl:
                    # Truncation alert (threat 15)
                    conn.execute(
                        "INSERT INTO sync_alerts "
                        "(id, org_id, project_id, connector_id, "
                        "kind, detail, created_at) "
                        "VALUES (%s, %s::uuid, %s::uuid, %s::uuid, "
                        "'truncation', %s::jsonb, now())",
                        [
                            str(uuid.uuid4()), d_org, d_project,
                            d_connector,
                            json.dumps({
                                "session_id": sid,
                                "previous_length": prev_cl,
                                "current_length": cl,
                            }),
                        ],
                    )

            # Compute a head hash from the session list
            session_blob = json.dumps(
                sessions, sort_keys=True, separators=(",", ":"),
            ).encode()
            head_hash = hashlib.sha256(session_blob).hexdigest()

            # Store the checkpoint
            try:
                conn.execute(
                    "INSERT INTO audit_heads "
                    "(id, org_id, connector_id, upload_seq, session_list, "
                    "head_hash, signature, created_at) "
                    "VALUES (%s, %s::uuid, %s::uuid, %s, %s::jsonb, %s, "
                    "%s, now())",
                    [
                        str(uuid.uuid4()), d_org, d_connector,
                        upload_seq,
                        json.dumps(sessions),
                        head_hash,
                        body.get("signatures", [{}])[0].get("sig", ""),
                    ],
                )
                conn.commit()
            except psycopg.errors.UniqueViolation:
                conn.rollback()
                return JSONResponse(
                    {"error": "seq_conflict"},
                    status_code=409,
                )

        return JSONResponse(
            {"upload_seq": upload_seq},
            status_code=200,
        )

    return router
