"""Server-side policy bundle routes (D2, D7.2).

GET  /api/v1/sync/bundle?after=<seq>    -- device token auth
POST /api/v1/admin/bundles               -- admin session + CSRF

The bundle-signer private key is read from a server secret file
(``AGG_BUNDLE_SIGNER_KEY_FILE``, D5.1).  The server signs bundles;
the connector validates loosening and CLI approvals (D2.3).

Connections ``SET ROLE agg_app`` like enroll.py/signer.py.
"""
from __future__ import annotations

import hashlib
import json
import os
import uuid
from typing import Any

import psycopg
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from sandbox.protocol.domains import BUNDLE
from sandbox.protocol.envelope import canonical_bytes, key_id as _key_id

from ..rbac import rbac_route


def _conninfo(url: str) -> str:
    return url.replace("+psycopg", "")


def _load_bundle_signer_key():
    """Load the Ed25519 bundle-signer private key from a secret file.

    Reads ``AGG_BUNDLE_SIGNER_KEY_FILE`` (path to a 32-byte hex-encoded
    or raw seed file).  Returns a ``nacl.signing.SigningKey`` or None.
    """
    key_file = os.environ.get("AGG_BUNDLE_SIGNER_KEY_FILE")
    if not key_file:
        return None
    try:
        from nacl.signing import SigningKey
        raw = open(key_file, "rb").read().strip()
        # Try hex first (64 chars = 32 bytes)
        if len(raw) >= 64:
            try:
                seed = bytes.fromhex(raw[:64].decode("ascii"))
                return SigningKey(seed)
            except (ValueError, UnicodeDecodeError):
                pass
        # Raw 32 bytes
        if len(raw) == 32:
            return SigningKey(raw)
        return None
    except (OSError, Exception):
        return None


def _sign_bundle(payload: dict, signing_key) -> dict:
    """Sign a bundle payload and return the envelope."""
    from sandbox.crypto.signing import sign_message

    msg = canonical_bytes(BUNDLE, payload)
    pub = bytes(signing_key.verify_key)
    kid = _key_id(pub)
    sig = sign_message(msg, signing_key)
    return {
        "kind": "agg/bundle/v1",
        "sig_v": 1,
        "payload": payload,
        "signatures": [{"key_id": kid, "alg": "ed25519", "sig": sig}],
    }


def bundle_router(db_url: str, clock=None) -> APIRouter:
    """Build the bundle router."""
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
        from agg_cp.auth import validate_session
        return validate_session(conn, request, _get_clock())

    def _check_csrf(request, csrf_hash: str) -> bool:
        """Check X-CSRF-Token header against stored hash."""
        import hmac as _hmac
        csrf_token = request.headers.get("X-CSRF-Token", "")
        if not csrf_token:
            return False
        computed = hashlib.sha256(csrf_token.encode()).hexdigest()
        return _hmac.compare_digest(computed, csrf_hash)

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

    # -----------------------------------------------------------------
    # GET /api/v1/sync/bundle?after=<seq>  (device token auth)
    # ADR 0001 A1 item 2: lowest sequence > after, not latest.
    # Returns {"envelope": ..., "change_approvals": [...]}.
    # -----------------------------------------------------------------
    @rbac_route(router, "get", "/api/v1/sync/bundle",
                role="device", scope="project")
    async def get_bundle(request: Request) -> JSONResponse:
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        token = auth[7:]

        after_str = request.query_params.get("after", "0")
        try:
            after = int(after_str)
        except (ValueError, TypeError):
            return JSONResponse({"error": "bad_after"}, status_code=400)
        # Sequences are positive BIGINTs; out-of-range values would 500 in pg.
        if after < 0 or after > 2**63 - 1:
            return JSONResponse({"error": "bad_after"}, status_code=400)

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

            # ADR 0001 A1 item 2: serve the lowest sequence > after
            row = conn.execute(
                "SELECT id, bundle_blob FROM policy_bundles "
                "WHERE org_id = %s::uuid AND project_id = %s::uuid "
                "  AND sequence > %s "
                "ORDER BY sequence ASC LIMIT 1",
                [d_org, d_project, after],
            ).fetchone()

            if row is None:
                return JSONResponse(content="", status_code=204)

            bundle_row_id = str(row[0])
            blob = row[1]
            if isinstance(blob, memoryview):
                blob = bytes(blob)
            if isinstance(blob, bytes):
                blob = blob.decode("utf-8")

            try:
                envelope = json.loads(blob)
            except (ValueError, TypeError):
                return JSONResponse(
                    {"error": "corrupt_bundle"}, status_code=500,
                )

            # ADR 0001 A1: serve change_approvals beside the envelope
            approval_rows = conn.execute(
                "SELECT signature FROM policy_change_approvals "
                "WHERE change_request_id = %s::uuid AND org_id = %s::uuid "
                "ORDER BY key_id",
                [bundle_row_id, d_org],
            ).fetchall()

            change_approvals = []
            for ar in approval_rows:
                sig_text = ar[0]
                try:
                    change_approvals.append(json.loads(sig_text))
                except (ValueError, TypeError):
                    change_approvals.append(sig_text)

        return JSONResponse(
            {"envelope": envelope, "change_approvals": change_approvals},
            status_code=200,
        )

    # -----------------------------------------------------------------
    # POST /api/v1/admin/bundles  (admin session + CSRF)
    # -----------------------------------------------------------------
    @rbac_route(router, "post", "/api/v1/admin/bundles",
                role="admin", scope="org")
    async def admin_create_bundle(request: Request) -> JSONResponse:
        with _conn() as conn:
            session, err = _validate(conn, request)
            if err is not None:
                return err
            org_id, user_id, session_id, session_token, csrf_hash = session

            # CSRF check
            if not _check_csrf(request, csrf_hash):
                return JSONResponse(
                    {"error": "csrf_invalid"}, status_code=403,
                )

            body = await request.json()
            project_id = body.get("project_id", "")
            bundle_payload = body.get("bundle_payload", {})
            change_approvals = body.get("change_approvals", [])

            if not project_id:
                return JSONResponse(
                    {"error": "missing project_id"}, status_code=400,
                )

            # Check project exists and belongs to org
            proj_row = conn.execute(
                "SELECT id FROM projects "
                "WHERE id = %s::uuid AND org_id = %s::uuid",
                [project_id, str(org_id)],
            ).fetchone()
            if proj_row is None:
                return JSONResponse(
                    {"error": "project_not_found"}, status_code=404,
                )

            # Set org_id on the bundle payload
            bundle_payload["org_id"] = str(org_id)

            # ---- ADR 0001 A1 item 1: validate change_approvals ----
            # Each element must be a dict with a "signatures" list,
            # and each signature's key_id must exist in approver_keys.
            # On failure: 400 bad_change_approvals, nothing stored.
            validated_approvals: list[tuple[str, str, str]] = []
            if not isinstance(change_approvals, list):
                return JSONResponse(
                    {"error": "bad_change_approvals",
                     "detail": "change_approvals must be a list"},
                    status_code=400,
                )
            for idx, appr in enumerate(change_approvals):
                if not isinstance(appr, dict):
                    return JSONResponse(
                        {"error": "bad_change_approvals",
                         "detail": f"approval[{idx}] is not an object"},
                        status_code=400,
                    )
                sigs = appr.get("signatures")
                if not isinstance(sigs, list) or len(sigs) == 0:
                    return JSONResponse(
                        {"error": "bad_change_approvals",
                         "detail": f"approval[{idx}] missing signatures list"},
                        status_code=400,
                    )
                kid = sigs[0].get("key_id", "") if isinstance(sigs[0], dict) else ""
                if not kid:
                    return JSONResponse(
                        {"error": "bad_change_approvals",
                         "detail": f"approval[{idx}] signature has no key_id"},
                        status_code=400,
                    )
                # Look up key_id via cli_key_lookup (checks both
                # approver_keys and pending signer_links).
                key_row = conn.execute(
                    "SELECT org_id, user_id FROM cli_key_lookup(%s)",
                    [kid],
                ).fetchone()
                if key_row is None or str(key_row[0]) != str(org_id):
                    return JSONResponse(
                        {"error": "bad_change_approvals",
                         "detail": f"approval[{idx}] key_id not in approver_keys"},
                        status_code=400,
                    )
                appr_user_id = str(key_row[1])
                # ADR 0001 A2 item 1: the publishing admin may not be
                # among the approvers (any of their keys, incl. pending
                # signer_links, resolves to the same user_id).
                if appr_user_id == str(user_id):
                    return JSONResponse(
                        {"error": "proposer_in_approvals",
                         "detail": f"approval[{idx}] key belongs to the "
                                   "publishing admin"},
                        status_code=400,
                    )
                appr_json = json.dumps(
                    appr, sort_keys=True, separators=(",", ":"),
                )
                validated_approvals.append((kid, appr_user_id, appr_json))

            # Load bundle signer key (D5.1: server secret file only)
            signer_key = _load_bundle_signer_key()
            if signer_key is None:
                return JSONResponse(
                    {"error": "bundle_signer_key_not_configured"},
                    status_code=500,
                )

            # Sign the bundle
            envelope = _sign_bundle(bundle_payload, signer_key)
            blob = json.dumps(
                envelope, sort_keys=True, separators=(",", ":"),
            ).encode()
            sig = envelope["signatures"][0]["sig"]

            sequence = bundle_payload.get("sequence", 1)
            bundle_id = str(uuid.uuid4())

            try:
                conn.execute(
                    "INSERT INTO policy_bundles "
                    "(id, org_id, project_id, sequence, bundle_blob, "
                    "server_signature, created_at) "
                    "VALUES (%s, %s::uuid, %s::uuid, %s, %s, %s, now())",
                    [bundle_id, str(org_id), project_id, sequence,
                     blob, sig],
                )

                # ADR 0001 A1 item 1: store each approval in the
                # same transaction as the bundle insert.
                for kid, appr_uid, appr_json in validated_approvals:
                    conn.execute(
                        "INSERT INTO policy_change_approvals "
                        "(id, org_id, change_request_id, user_id, key_id, "
                        "signature, signed_at, created_at) "
                        "VALUES (%s, %s::uuid, %s::uuid, %s::uuid, %s, "
                        "%s, now(), now())",
                        [str(uuid.uuid4()), str(org_id), bundle_id,
                         appr_uid, kid, appr_json],
                    )

                conn.commit()
            except psycopg.errors.UniqueViolation:
                conn.rollback()
                return JSONResponse(
                    {"error": "sequence_conflict"}, status_code=409,
                )

        return JSONResponse({
            "bundle_id": bundle_id,
            "sequence": sequence,
        })

    return router
