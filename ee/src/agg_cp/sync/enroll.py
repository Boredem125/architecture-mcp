"""Server-side enrollment routes (D1, D7.2).

POST /api/v1/sync/enroll       -- consume code, verify PoP, create device
POST /api/v1/sync/token        -- device assertion -> bearer token
POST /api/v1/admin/enrollment-codes  -- admin issues code (org from session)
GET  /api/v1/enrollment-codes/{id}   -- operator reads code once (session)
POST /api/v1/admin/devices/revoke    -- revoke a device (session)

Sync routes (enroll, token) are unauthenticated (device-key PoP).
Admin and operator routes go through ``validate_session``.

Uses the T5 SECURITY DEFINER functions:
  enrollment_code_consume, device_lookup, device_nonce_insert.
"""
from __future__ import annotations

import hashlib
import secrets
import uuid
from datetime import datetime, timezone
from typing import Any

import psycopg
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from sandbox.protocol.domains import DEVICE_ENROLL, DEVICE_ASSERT
from sandbox.protocol.envelope import canonical_bytes

from ..rbac import rbac_route

# Token lifetime in seconds (10 min)
TOKEN_LIFETIME = 600
# IAT tolerance in seconds (2 min)
IAT_TOLERANCE = 120
# Session max_age for operator code read (15 min)
SESSION_MAX_AGE = 900


def _conninfo(url: str) -> str:
    return url.replace("+psycopg", "")


def enroll_router(db_url: str, clock=None) -> APIRouter:
    """Build the enrollment router."""
    conninfo = _conninfo(db_url)
    router = APIRouter()

    def _get_clock():
        if clock is not None:
            return clock
        from agg_cp.clock import SystemClock
        return SystemClock()

    def _conn():
        c = psycopg.connect(conninfo)
        c.execute("SET ROLE agg_app")
        return c

    def _validate(conn, request):
        """Validate session; returns (session_tuple, None) or (None, err)."""
        from agg_cp.auth import validate_session
        return validate_session(conn, request, _get_clock())

    # -----------------------------------------------------------------
    # POST /api/v1/sync/enroll  (unauthenticated -- device-key PoP)
    # -----------------------------------------------------------------
    @rbac_route(router, "post", "/api/v1/sync/enroll",
                role="preauth", scope="enrollment-code+pop")
    async def sync_enroll(request: Request) -> JSONResponse:
        body = await request.json()
        code_raw = body.get("code", "")
        public_key_hex = body.get("public_key", "")
        proof = body.get("proof", {})

        if not code_raw or not public_key_hex or not proof:
            return JSONResponse(
                {"error": "missing code, public_key or proof"},
                status_code=400,
            )

        code_hash = hashlib.sha256(code_raw.encode()).hexdigest()

        pop_payload = proof.get("payload", {})
        if pop_payload.get("code_hash") != code_hash:
            return JSONResponse(
                {"error": "bad_proof", "detail": "code_hash mismatch"},
                status_code=400,
            )

        if pop_payload.get("public_key") != public_key_hex:
            return JSONResponse(
                {"error": "bad_proof", "detail": "public_key mismatch"},
                status_code=400,
            )

        if proof.get("kind") != DEVICE_ENROLL:
            return JSONResponse(
                {"error": "bad_proof", "detail": "wrong kind"},
                status_code=400,
            )

        if proof.get("sig_v") != 1:
            return JSONResponse(
                {"error": "bad_proof", "detail": "wrong sig_v"},
                status_code=400,
            )

        sigs = proof.get("signatures", [])
        if not sigs:
            return JSONResponse(
                {"error": "bad_proof", "detail": "no signatures"},
                status_code=400,
            )

        msg = canonical_bytes(DEVICE_ENROLL, pop_payload)
        try:
            from nacl.signing import VerifyKey
            vk = VerifyKey(bytes.fromhex(public_key_hex))
            vk.verify(msg, bytes.fromhex(sigs[0].get("sig", "")))
        except Exception:
            return JSONResponse(
                {"error": "bad_proof", "detail": "signature verification failed"},
                status_code=400,
            )

        # Atomic code consume via SECURITY DEFINER function.
        # PoP is verified first (above) so a bad proof never consumes.
        with _conn() as conn:
            row = conn.execute(
                "SELECT * FROM enrollment_code_consume(%s)",
                [code_hash],
            ).fetchone()

            if row is None:
                # Uniform refusal: no oracle for code guessing (D1.1)
                conn.rollback()
                return JSONResponse(
                    {"error": "invalid_code"}, status_code=400,
                )

            org_id = str(row[0])
            project_id = str(row[1])
            operator_user_id = str(row[2]) if row[2] else None

            device_id = str(uuid.uuid4())
            conn.execute(
                "SELECT set_config('app.org_id', %s, true)",
                [org_id],
            )
            conn.execute(
                "INSERT INTO connectors "
                "(id, org_id, project_id, device_public_key, "
                " operator_user_id, created_at) "
                "VALUES (%s, %s::uuid, %s::uuid, %s, %s::uuid, now())",
                [device_id, org_id, project_id, public_key_hex,
                 operator_user_id],
            )

            # Read the registry chain for this org (ruling d)
            from agg_cp.sync.registry import get_chain
            registry_chain = get_chain(conn, org_id)

            conn.commit()

        return JSONResponse({
            "device_id": device_id,
            "org_id": org_id,
            "project_id": project_id,
            "registry": registry_chain,
        })

    # -----------------------------------------------------------------
    # POST /api/v1/sync/token  (unauthenticated -- device assertion)
    # -----------------------------------------------------------------
    @rbac_route(router, "post", "/api/v1/sync/token",
                role="preauth", scope="device-assertion")
    async def sync_token(request: Request) -> JSONResponse:
        body = await request.json()
        device_id = body.get("device_id", "")
        assertion = body.get("assertion", {})

        if not device_id or not assertion:
            return JSONResponse(
                {"error": "missing device_id or assertion"},
                status_code=400,
            )

        with _conn() as conn:
            row = conn.execute(
                "SELECT * FROM device_lookup(%s::uuid)",
                [device_id],
            ).fetchone()

            if row is None:
                return JSONResponse(
                    {"error": "not_found"}, status_code=404,
                )

            dev_org = str(row[0])
            dev_project = str(row[1])
            dev_connector = str(row[2])
            dev_pub_key = row[3]
            dev_revoked = row[4]

            if dev_revoked is not None:
                return JSONResponse(
                    {"error": "device_revoked"}, status_code=401,
                )

            a_payload = assertion.get("payload", {})
            a_iat = a_payload.get("iat", 0)
            a_nonce = a_payload.get("nonce", "")

            now_dt = _get_clock().now()
            now_ts = now_dt.timestamp()
            if abs(now_ts - a_iat) > IAT_TOLERANCE:
                return JSONResponse(
                    {"error": "iat_expired"}, status_code=401,
                )

            if assertion.get("kind") != DEVICE_ASSERT:
                return JSONResponse(
                    {"error": "wrong_kind"}, status_code=400,
                )

            sigs = assertion.get("signatures", [])
            if not sigs:
                return JSONResponse(
                    {"error": "no_signatures"}, status_code=400,
                )

            msg = canonical_bytes(DEVICE_ASSERT, a_payload)
            try:
                from nacl.signing import VerifyKey
                vk = VerifyKey(bytes.fromhex(dev_pub_key))
                vk.verify(msg, bytes.fromhex(sigs[0].get("sig", "")))
            except Exception:
                return JSONResponse(
                    {"error": "bad_signature"}, status_code=401,
                )

            iat_ts = datetime.fromtimestamp(a_iat, tz=timezone.utc)
            try:
                conn.execute(
                    "SELECT device_nonce_insert(%s::uuid, %s, %s::timestamptz)",
                    [device_id, a_nonce, iat_ts],
                )
                conn.commit()
            except psycopg.errors.UniqueViolation:
                conn.rollback()
                return JSONResponse(
                    {"error": "nonce_replay"}, status_code=401,
                )
            except Exception:
                conn.rollback()
                return JSONResponse(
                    {"error": "nonce_replay"}, status_code=401,
                )

            raw_token = secrets.token_hex(32)
            token_hash = hashlib.sha256(raw_token.encode()).hexdigest()

            conn.execute(
                "SELECT set_config('app.org_id', %s, true)",
                [dev_org],
            )
            conn.execute(
                "INSERT INTO device_tokens "
                "(id, org_id, project_id, connector_id, token_hash, "
                " expires_at, created_at) "
                "VALUES (%s, %s::uuid, %s::uuid, %s::uuid, %s, "
                " now() + interval '10 minutes', now())",
                [str(uuid.uuid4()), dev_org, dev_project, dev_connector,
                 token_hash],
            )
            conn.commit()

        return JSONResponse({
            "token": raw_token,
            "expires_in": TOKEN_LIFETIME,
        })

    # -----------------------------------------------------------------
    # POST /api/v1/admin/enrollment-codes  (session auth, admin role)
    # -----------------------------------------------------------------
    @rbac_route(router, "post", "/api/v1/admin/enrollment-codes",
                role="admin", scope="org")
    async def admin_create_code(request: Request) -> JSONResponse:
        body = await request.json()
        project_id = body.get("project_id", "")
        operator_user_id = body.get("operator_user_id", "")

        if not project_id or not operator_user_id:
            return JSONResponse(
                {"error": "missing project_id or operator_user_id"},
                status_code=400,
            )

        with _conn() as conn:
            session, err = _validate(conn, request)
            if err is not None:
                return err
            org_id, user_id, _, _, _ = session

            proj_row = conn.execute(
                "SELECT id FROM projects "
                "WHERE id = %s::uuid AND org_id = %s::uuid",
                [project_id, str(org_id)],
            ).fetchone()
            if proj_row is None:
                return JSONResponse(
                    {"error": "project_not_found"}, status_code=404,
                )

            code_id = str(uuid.uuid4())
            conn.execute(
                "INSERT INTO enrollment_codes "
                "(id, org_id, project_id, expires_at, operator_user_id) "
                "VALUES (%s, %s::uuid, %s::uuid, "
                " now() + interval '15 minutes', %s::uuid)",
                [code_id, str(org_id), project_id, operator_user_id],
            )
            conn.commit()

        return JSONResponse({
            "code_id": code_id,
            "expires_at": _get_clock().now().isoformat(),
        })

    # -----------------------------------------------------------------
    # GET /api/v1/enrollment-codes/{code_id}  (session auth, operator)
    # -----------------------------------------------------------------
    @rbac_route(router, "get", "/api/v1/enrollment-codes/{code_id}",
                role="session", scope="operator")
    async def operator_read_code(
        code_id: str, request: Request,
    ) -> JSONResponse:
        with _conn() as conn:
            session, err = _validate(conn, request)
            if err is not None:
                return err
            org_id, user_id, session_id, _, _ = session

            # Check session freshness: the session must have been created
            # within 15 min (D1.1 max_age rule for operator code read).
            sess_row = conn.execute(
                "SELECT created_at FROM web_sessions WHERE id = %s",
                [str(session_id)],
            ).fetchone()
            if sess_row is not None:
                created_at = sess_row[0]
                now = _get_clock().now()
                age = (now - created_at).total_seconds()
                if age > SESSION_MAX_AGE:
                    return JSONResponse(
                        {"error": "reauth_required"}, status_code=401,
                    )

            # Generate code; atomic UPDATE stores only the hash
            code = secrets.token_hex(16)
            code_hash = hashlib.sha256(code.encode()).hexdigest()

            row = conn.execute(
                "UPDATE enrollment_codes "
                "SET code_hash = %s, code_read_at = now() "
                "WHERE id = %s::uuid "
                "  AND operator_user_id = %s::uuid "
                "  AND code_read_at IS NULL "
                "  AND expires_at > now() "
                "RETURNING id",
                [code_hash, code_id, str(user_id)],
            ).fetchone()

            if row is None:
                conn.rollback()
                return JSONResponse(
                    {"error": "not_found"}, status_code=404,
                )
            conn.commit()

        return JSONResponse({"code": code})

    # -----------------------------------------------------------------
    # POST /api/v1/admin/devices/revoke  (session auth, admin role)
    # -----------------------------------------------------------------
    @rbac_route(router, "post", "/api/v1/admin/devices/revoke",
                role="admin", scope="org")
    async def admin_revoke_device(request: Request) -> JSONResponse:
        body = await request.json()
        device_id = body.get("device_id", "")

        if not device_id:
            return JSONResponse(
                {"error": "missing device_id"}, status_code=400,
            )

        with _conn() as conn:
            session, err = _validate(conn, request)
            if err is not None:
                return err
            org_id, user_id, _, _, _ = session

            result = conn.execute(
                "UPDATE connectors SET revoked_at = now() "
                "WHERE id = %s::uuid AND revoked_at IS NULL "
                "  AND org_id = %s::uuid "
                "RETURNING id",
                [device_id, str(org_id)],
            ).fetchone()
            conn.commit()

        if result is None:
            return JSONResponse(
                {"error": "not_found_or_already_revoked"},
                status_code=404,
            )

        return JSONResponse({
            "revoked_at": _get_clock().now().isoformat(),
        })

    # -----------------------------------------------------------------
    # GET /api/v1/sync/registry  (device token auth, same-org only)
    # -----------------------------------------------------------------

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

    @rbac_route(router, "get", "/api/v1/sync/registry",
                role="device", scope="project")
    async def get_registry(request: Request) -> JSONResponse:
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        token = auth[7:]

        with _conn() as conn:
            device = _device_token_lookup(conn, token)
            if device is None:
                return JSONResponse(
                    {"error": "unauthorized"}, status_code=401,
                )
            d_org = str(device[0])

            from agg_cp.sync.registry import get_chain

            registry_chain = get_chain(conn, d_org)

        return JSONResponse({"registry": registry_chain})

    return router
