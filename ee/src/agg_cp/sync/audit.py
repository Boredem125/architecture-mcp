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
        for row in conn.execute("SELECT sweep_org_ids()").fetchall()
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

    rows = conn.execute(
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
    ).fetchall()

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


def verify_project(conn: Any, project_id: str) -> tuple[bool, list[dict]]:
    """Verify all audit chains for a project.

    Returns ``(ok, gaps)`` where ``gaps`` is a list of dicts describing
    each gap found.  ``ok`` is True when no gaps are found.
    """
    pairs = conn.execute(
        """
        SELECT DISTINCT ar.connector_id, ar.session_id
        FROM audit_records ar
        JOIN connectors c ON c.id = ar.connector_id
        WHERE c.project_id = %s::uuid
        ORDER BY ar.connector_id, ar.session_id
        """,
        [project_id],
    ).fetchall()

    gaps: list[dict] = []

    for connector_id, session_id in pairs:
        records = conn.execute(
            "SELECT chain_length, previous_hash, record_hash "
            "FROM audit_records "
            "WHERE connector_id = %s::uuid AND session_id = %s "
            "ORDER BY chain_length",
            [str(connector_id), session_id],
        ).fetchall()

        if not records:
            continue

        expected_length = 1
        expected_prev = ""

        for rec_length, prev_hash, rec_hash in records:
            if rec_length != expected_length:
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
                gaps.append({
                    "connector_id": str(connector_id),
                    "session_id": session_id,
                    "chain_length": rec_length,
                    "type": "chain_broken",
                })

            expected_length = rec_length + 1
            expected_prev = rec_hash

    return len(gaps) == 0, gaps
