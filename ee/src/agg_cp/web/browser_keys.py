"""Browser key enrollment via POST /api/v1/signer-links with kind=browser.

T7 semantics: the key is proposal-only (pending) until a registry version
includes it.  The signer-links route in ``agg_cp.sync.signer`` dispatches
here when ``body.kind == "browser"``.
"""
from __future__ import annotations

import hashlib
import hmac as _hmac
import uuid

from fastapi.responses import JSONResponse


def link_browser_key(
    conn,
    request,
    clock,
    *,
    org_id,
    user_id,
    session_id,
    csrf_hash,
    body: dict,
) -> JSONResponse:
    """Handle browser key enrollment.

    Validates CSRF, then creates a pending signer_links entry with the
    supplied public_key and key_id.  Returns 200/201 on success.
    """
    from ..auth import _sha256_hex

    # CSRF check (session writes require it)
    csrf_header = request.headers.get("x-csrf-token")
    if not csrf_header:
        return JSONResponse({"error": "csrf_missing"}, status_code=403)
    csrf_token_hash = _sha256_hex(csrf_header)
    if not _hmac.compare_digest(csrf_hash, csrf_token_hash):
        return JSONResponse({"error": "csrf_invalid"}, status_code=403)

    public_key = body.get("public_key", "")
    key_id = body.get("key_id", "")

    if not public_key or not key_id:
        return JSONResponse(
            {"error": "public_key and key_id required"}, status_code=400,
        )

    # F7(b): key_id must equal sha256(public_key)
    try:
        expected_kid = hashlib.sha256(
            bytes.fromhex(public_key)
        ).hexdigest()
    except (ValueError, TypeError):
        return JSONResponse(
            {"error": "public_key must be valid hex"}, status_code=400,
        )
    if key_id != expected_kid:
        return JSONResponse(
            {"error": "key_id must equal sha256(public_key)"},
            status_code=400,
        )

    # F7(b): cross-org check -- refuse if key_id is already a live
    # approver key in another org (uses SECURITY DEFINER function).
    cross_org = conn.execute(
        "SELECT check_key_id_cross_org(%s, %s::uuid)",
        [key_id, str(org_id)],
    ).fetchone()
    if cross_org and cross_org[0]:
        return JSONResponse(
            {"error": "key_id cannot be registered"}, status_code=409,
        )

    # Create a pending signer_links entry with the key data directly
    # (no code flow for browser keys -- the session IS the identity proof)
    link_id = str(uuid.uuid4())
    # Use a placeholder code_hash (browser keys bypass the code flow)
    code_hash = hashlib.sha256(
        f"browser-{key_id}-{link_id}".encode()
    ).hexdigest()

    conn.execute(
        "INSERT INTO signer_links "
        "(id, org_id, user_id, code_hash, key_id, public_key, "
        "expires_at, used_at, status, created_at) "
        "VALUES (%s, %s::uuid, %s::uuid, %s, %s, %s, "
        "now() + interval '15 minutes', now(), 'pending', now())",
        [link_id, str(org_id), str(user_id), code_hash,
         key_id, public_key],
    )
    conn.commit()

    return JSONResponse(
        {"key_id": key_id, "status": "pending"},
        status_code=201,
    )
