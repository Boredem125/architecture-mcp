"""Server-side audit verification and device_silent sweep (D3.4, D3.5, T11).

``sweep_all_orgs(conn, now)`` iterates orgs via the SECURITY DEFINER
``sweep_org_ids()`` function, sets ``app.org_id`` per org, and calls
``sweep_device_silent`` under RLS.  Safe with ``--workers 4`` via
``pg_try_advisory_xact_lock``.

``sweep_device_silent(conn, now)`` scans connectors under the current
``app.org_id`` context.  Each insert uses a SAVEPOINT so one failure
does not abort the transaction for the rest (item 5).

``verify_project(conn, project_id)`` rechecks every stored chain and
flags gaps.  Called from the CLI subcommand ``agg-cp audit verify --project``.
"""
from __future__ import annotations

import datetime as dt
import json
import logging
import uuid
from typing import Any

_log = logging.getLogger(__name__)

# Default silent window: 3 x 60 s poll = 180 s
_DEFAULT_SILENT_WINDOW_S = 180


def sweep_all_orgs(
    conn: Any,
    now: dt.datetime,
    *,
    window_s: int = _DEFAULT_SILENT_WINDOW_S,
) -> int:
    """Iterate all orgs via ``sweep_org_ids()`` and sweep each under RLS.

    Sets ``app.org_id`` (transaction-local) per org so that FORCE RLS
    on ``audit_heads``, ``sync_alerts`` and ``connectors`` is satisfied.
    The advisory lock is acquired once for the whole sweep.

    Returns the total count of new alerts inserted across all orgs.
    """
    # Advisory lock prevents duplicate sweeps across concurrent workers.
    got_lock = conn.execute(
        "SELECT pg_try_advisory_xact_lock(1634297715)"
    ).fetchone()
    if not got_lock or not got_lock[0]:
        return 0

    # Get org_ids via SECURITY DEFINER function (bypasses RLS)
    org_ids = [
        str(row[0])
        for row in list(conn.execute("SELECT sweep_org_ids()"))
    ]

    total = 0
    for org_id in org_ids:
        try:
            conn.execute("SAVEPOINT sweep_org")
            conn.execute(
                "SELECT set_config('app.org_id', %s, true)", [org_id],
            )
            total += sweep_device_silent(conn, now, window_s=window_s)
            conn.execute("RELEASE SAVEPOINT sweep_org")
        except Exception:
            _log.exception("sweep_device_silent error for org %s", org_id)
            try:
                conn.execute("ROLLBACK TO SAVEPOINT sweep_org")
            except Exception:
                pass
    return total


def sweep_device_silent(
    conn: Any,
    now: dt.datetime,
    *,
    window_s: int = _DEFAULT_SILENT_WINDOW_S,
) -> int:
    """Scan connectors whose last checkpoint is older than *window_s*.

    Expects ``app.org_id`` to be set (called from ``sweep_all_orgs``
    or directly in tests with the org context set).

    Each insert uses a SAVEPOINT so one failure does not abort the
    transaction for the rest (item 5).

    Returns the count of new alerts inserted.
    """
    threshold = now - dt.timedelta(seconds=window_s)

    rows = list(conn.execute(
        """
        SELECT
            h.connector_id,
            h.org_id,
            c.project_id,
            h.max_created
        FROM (
            SELECT connector_id, org_id, MAX(created_at) AS max_created
            FROM audit_heads
            GROUP BY connector_id, org_id
        ) h
        JOIN connectors c ON c.id = h.connector_id
        WHERE h.max_created < %s
          AND c.revoked_at IS NULL
          AND NOT EXISTS (
              SELECT 1 FROM sync_alerts sa
              WHERE sa.connector_id = h.connector_id
                AND sa.kind = 'device_silent'
                AND sa.created_at > h.max_created
          )
        """,
        [threshold],
    ))

    count = 0
    for row in rows:
        connector_id, org_id, project_id, max_created = row
        try:
            conn.execute("SAVEPOINT sweep_alert")
            conn.execute(
                "INSERT INTO sync_alerts "
                "(id, org_id, project_id, connector_id, kind, detail, "
                "created_at) "
                "VALUES (%s, %s::uuid, %s::uuid, %s::uuid, "
                "'device_silent', %s::jsonb, %s)",
                [
                    str(uuid.uuid4()),
                    str(org_id),
                    str(project_id),
                    str(connector_id),
                    json.dumps({
                        "last_checkpoint": max_created.isoformat()
                        if hasattr(max_created, "isoformat")
                        else str(max_created),
                        "threshold_s": window_s,
                    }),
                    now,
                ],
            )
            conn.execute("RELEASE SAVEPOINT sweep_alert")
            count += 1
        except Exception:
            # Roll back the savepoint so the transaction stays usable
            try:
                conn.execute("ROLLBACK TO SAVEPOINT sweep_alert")
            except Exception:
                pass

    return count


def canonical_record_bytes(body: Any) -> bytes | None:
    """Canonical JSON bytes of a record body.

    Shared with ``sync/audit_upload.py`` (ingest) and the export/verify
    paths so there is exactly one formula (T1-25).  Returns ``None``
    when the body is unusable (non-dict, unserializable).

    Uses ``allow_nan=False`` so that ``NaN`` / ``Infinity`` raise
    ``ValueError`` rather than producing invalid JSON text.
    """
    if isinstance(body, (str, bytes)):
        try:
            body = json.loads(body)
        except (ValueError, TypeError):
            return None
    if not isinstance(body, dict):
        return None
    try:
        return json.dumps(
            body, separators=(",", ":"), sort_keys=True,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, RecursionError):
        return None


# T1-26: fixed nesting limit for record bodies, the same on every
# platform.  Python's JSON parser limit is 2,997 levels on Windows 3.12,
# 9,997 on Linux 3.12 and 52,203 on Linux 3.15 (measured, review round 3),
# so a body accepted on one platform could be unreadable on another.
# 1,000 is well under every measured limit; export and the CLI read it
# everywhere.  Recorded next to the 1 MiB cap in ADR 0001 A4.
MAX_NESTING_DEPTH = 1000


def json_nesting_depth(obj: Any, *, limit: int | None = None) -> int:
    """Return the container nesting depth of a parsed JSON value.

    A scalar is depth 0, ``{}`` or ``[]`` is depth 1, ``{"a": [1]}`` is
    depth 2.  Walks an explicit stack, never recursing, so the answer
    does not depend on the interpreter's recursion limit (T1-26).
    When *limit* is given the walk stops as soon as a depth above it
    is seen and returns ``limit + 1``.
    """
    if not isinstance(obj, (dict, list)):
        return 0
    max_depth = 0
    stack: list[tuple[Any, int]] = [(obj, 1)]
    while stack:
        node, depth = stack.pop()
        if depth > max_depth:
            max_depth = depth
            if limit is not None and max_depth > limit:
                return limit + 1
        children = node.values() if isinstance(node, dict) else node
        for child in children:
            if isinstance(child, (dict, list)):
                stack.append((child, depth + 1))
    return max_depth


def _canonical_record_hash(body: Any) -> str | None:
    """``sha256(canonical JSON body)``: the connector's record_hash formula
    (``sandbox/connector/audit.py``).  ``None`` if the body is unusable."""
    import hashlib

    raw = canonical_record_bytes(body)
    if raw is None:
        return None
    return hashlib.sha256(raw).hexdigest()


_MAX_GAPS = 1000  # T1-18: bound gaps list; ok stays False when truncated

# T1-17: rows per FETCH on the named cursors.  One record body can be
# about 1 MiB, so this bounds the per-request working set to roughly
# _FETCH_ROWS MiB of result plus one row being checked.  Pinned at
# most 16 by test_t1_17_fetch_count_pinned.
_FETCH_ROWS = 16  # literal 'FETCH 16' below so the pin sees it


def verify_project(
    conn: Any, project_id: str,
) -> tuple[bool, list[dict]]:
    """Verify all audit chains for a project (ADR 0001 A4.3).

    Returns ``(ok, gaps)`` where ``gaps`` is a list of dicts describing
    each problem found, capped at ``_MAX_GAPS``.
    ``ok`` is True only when at least one record is stored for the
    project, every chain is intact: lengths contiguous from 1,
    ``previous_hash`` links match, and every ``record_hash`` equals
    ``sha256(canonical body)`` (founder ruling 1, 4 Nov 2026: a project
    with zero rows is NOT ok, and content is rechecked, not just the
    links).  ``ok`` stays False when gaps were cut off (T1-18).

    Iterates through a named server-side cursor, ``_FETCH_ROWS`` rows
    per FETCH, one row alive at a time; never ``fetchall`` (T1-17).
    The cursor block runs inside ``conn.transaction()`` so
    that DECLARE works on both autocommit and non-autocommit connections
    (psycopg 3 creates a savepoint when a transaction is already open).
    """
    gaps: list[dict] = []
    gaps_truncated = False
    has_any_pair = False

    # conn.transaction() starts a real BEGIN on autocommit connections
    # and a SAVEPOINT on non-autocommit connections (already in a tx).
    # DECLARE CURSOR requires an open transaction block.
    with conn.transaction():
        # Use a server-side cursor for pairs (T1-17)
        pair_cursor_name = f"vp_pairs_{uuid.uuid4().hex[:8]}"
        conn.execute(
            f"DECLARE {pair_cursor_name} CURSOR FOR "
            "SELECT DISTINCT ar.connector_id, ar.session_id "
            "FROM audit_records ar "
            "JOIN connectors c ON c.id = ar.connector_id "
            "WHERE c.project_id = %s::uuid "
            "ORDER BY ar.connector_id, ar.session_id",
            [project_id],
        )

        while True:
            batch = list(conn.execute(
                f"FETCH 16 FROM {pair_cursor_name}"
            ))
            if not batch:
                break
            has_any_pair = True

            for connector_id, session_id in batch:
                if gaps_truncated:
                    break

                # Iterate records through a server-side cursor (T1-17)
                rec_cursor_name = f"vp_recs_{uuid.uuid4().hex[:8]}"
                conn.execute(
                    f"DECLARE {rec_cursor_name} CURSOR FOR "
                    "SELECT chain_length, previous_hash, record_hash, body "
                    "FROM audit_records "
                    "WHERE connector_id = %s::uuid AND session_id = %s "
                    "ORDER BY chain_length",
                    [str(connector_id), session_id],
                )

                expected_length = 1
                expected_prev = ""

                while True:
                    # Iterate the FETCH result directly: psycopg builds
                    # each row (and parses its json body) only when the
                    # row is reached, so one body is alive at a time
                    # on the Python side (T1-17).
                    rec_cur = conn.execute(
                        f"FETCH 16 FROM {rec_cursor_name}"
                    )
                    if rec_cur.rowcount == 0:
                        rec_cur.close()
                        break
                    for rec_length, prev_hash, rec_hash, body in rec_cur:
                        if len(gaps) >= _MAX_GAPS:
                            gaps_truncated = True
                            break

                        # Content check: record_hash must be the hash of the body
                        if _canonical_record_hash(body) != rec_hash:
                            gaps.append({
                                "connector_id": str(connector_id),
                                "session_id": session_id,
                                "chain_length": rec_length,
                                "type": "hash_mismatch",
                            })

                        if rec_length != expected_length:
                            if len(gaps) < _MAX_GAPS:
                                gaps.append({
                                    "connector_id": str(connector_id),
                                    "session_id": session_id,
                                    "expected_length": expected_length,
                                    "found_length": rec_length,
                                    "type": "gap",
                                })
                            expected_length = rec_length + 1
                            expected_prev = rec_hash
                            continue

                        if prev_hash != expected_prev:
                            if len(gaps) < _MAX_GAPS:
                                gaps.append({
                                    "connector_id": str(connector_id),
                                    "session_id": session_id,
                                    "chain_length": rec_length,
                                    "type": "chain_broken",
                                })

                        expected_length = rec_length + 1
                        expected_prev = rec_hash

                    # Release this batch before the next FETCH so two
                    # batches are never alive at once (T1-17).
                    body = None
                    rec_cur.close()
                    rec_cur = None

                    if gaps_truncated:
                        break

                conn.execute(f"CLOSE {rec_cursor_name}")

            if gaps_truncated:
                break

        conn.execute(f"CLOSE {pair_cursor_name}")

    if not has_any_pair:
        return False, [{
            "project_id": str(project_id),
            "type": "no_records",
        }]

    # ok stays False when gaps were truncated (T1-18)
    ok = len(gaps) == 0 and not gaps_truncated
    return ok, gaps
