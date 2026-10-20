"""Audit chain verification for admin_audit.

``verify_chain`` reads rows from the database using the
``admin_audit_canonical(t)`` SQL function (ADR 0002 item 6) and
recomputes SHA-256 in Python, checking links from 64 zeros.

T9 wraps this in the ``agg-cp audit verify`` CLI command.
"""
from __future__ import annotations

import hashlib
import uuid as _uuid

GENESIS_HASH: str = "0" * 64


def verify_chain(
    conn,  # psycopg sync connection
    org_id: _uuid.UUID | str,
) -> tuple[bool, str]:
    """Verify the admin_audit hash chain for *org_id*.

    Parameters
    ----------
    conn
        A ``psycopg`` **sync** connection with SELECT access on
        ``admin_audit``.  If RLS is in effect the caller must have
        set ``app.org_id`` on the connection.
    org_id
        The organisation whose chain to verify.

    Returns
    -------
    tuple[bool, str]
        ``(True, "")`` when the chain is valid;
        ``(False, reason)`` otherwise.
    """
    rows = conn.execute(
        "SELECT admin_audit_canonical(t)::text AS canonical, "
        "t.chain_length, t.previous_hash, t.record_hash "
        "FROM admin_audit t "
        "WHERE t.org_id = %s "
        "ORDER BY t.chain_length",
        [org_id],
    ).fetchall()

    if not rows:
        return True, ""

    prev_hash = GENESIS_HASH
    for i, (canonical, chain_length, previous_hash, record_hash) in enumerate(
        rows
    ):
        expected_length = i + 1
        if chain_length != expected_length:
            return False, (
                f"chain_length gap at position {expected_length}: "
                f"expected {expected_length}, got {chain_length}"
            )
        if previous_hash != prev_hash:
            return False, (
                f"previous_hash mismatch at chain_length {chain_length}: "
                f"expected {prev_hash!r}, got {previous_hash!r}"
            )
        computed = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        if record_hash != computed:
            return False, (
                f"record_hash mismatch at chain_length {chain_length}: "
                f"stored {record_hash!r}, computed {computed!r}"
            )
        prev_hash = record_hash

    return True, ""
