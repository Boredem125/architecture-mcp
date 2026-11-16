"""CLI entry point for agg-cp.

Console script: ``agg-cp = "agg_cp.cli:main"`` in ``pyproject.toml``.

Current commands:

    agg-cp audit verify --org <slug>

No module-level mutable state.  DB URL is read from
``AGG_DATABASE_URL`` or ``AGG_DATABASE_URL_FILE``.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import uuid
from pathlib import Path


def _db_url() -> str | None:
    """Resolve the DB URL from the two server variables only:
    ``AGG_DATABASE_URL``, then ``AGG_DATABASE_URL_FILE``.

    T1-28: there is no ``DATABASE_URL`` fallback.  It is a generic name
    other tools set on operator hosts, and a verify that silently picks
    its target records a pass against something other than what was
    meant.  With neither variable set the command exits 1 with
    ``no_db_url``.
    """
    url = os.environ.get("AGG_DATABASE_URL")
    if url is None:
        url_file = os.environ.get("AGG_DATABASE_URL_FILE")
        if url_file:
            url = Path(url_file).read_text(encoding="utf-8").strip()
    return url or None


def _fail(out: dict) -> int:
    """Print a failure: the JSON result on stdout (the machine-readable
    contract) and a one-line named reason on stderr.  Returns 1."""
    print(json.dumps(out), flush=True)
    print(f"agg-cp: error: {out.get('reason', 'failed')}",
          file=sys.stderr, flush=True)
    return 1


def _cmd_audit_verify(args: argparse.Namespace) -> int:
    """Run ``audit verify --org <slug>``."""
    import psycopg

    from agg_cp.auth import _app_conn, _sync_conninfo
    from agg_cp.audit import verify_chain

    db = _db_url()
    if not db:
        return _fail({"org": args.org, "ok": False, "reason": "no_db_url"})

    conninfo = _sync_conninfo(db)

    # Resolve org slug -> org_id via org_login_config
    with _app_conn(conninfo) as conn:
        row = conn.execute(
            "SELECT org_id FROM org_login_config(%s)", [args.org],
        ).fetchone()
        if row is None:
            return _fail({
                "org": args.org, "ok": False, "reason": "org_not_found",
            })
        org_id = row[0]

    # Verify the audit chain
    with _app_conn(conninfo) as conn:
        conn.execute(
            "SELECT set_config('app.org_id', %s, true)", [str(org_id)],
        )
        ok, reason = verify_chain(conn, org_id)
        conn.commit()

    print(
        json.dumps({"org": args.org, "ok": ok, "reason": reason}),
        flush=True,
    )
    return 0 if ok else 1


def _cmd_audit_verify_project(args: argparse.Namespace) -> int:
    """Run ``audit verify --project <id>``.

    Connects as agg_app (the configured URL), calls
    ``project_org_lookup`` (migration 0009 SECURITY DEFINER) to resolve
    the org_id, sets ``app.org_id`` for RLS, then runs
    ``verify_project`` under RLS.
    """
    import psycopg

    from agg_cp.auth import _app_conn, _sync_conninfo
    from agg_cp.sync.audit import verify_project, _MAX_GAPS

    db = _db_url()
    if not db:
        return _fail({"project": args.project, "ok": False,
                      "reason": "no_db_url"})

    # T1-23: a project id that is not a UUID is a named error, not an
    # InvalidTextRepresentation traceback from the ``::uuid`` cast.
    # Strict parse: the canonical spelling only.
    try:
        project_uuid = uuid.UUID(args.project)
    except (ValueError, AttributeError, TypeError):
        project_uuid = None
    if project_uuid is None or str(project_uuid) != args.project:
        return _fail({"project": args.project, "ok": False,
                      "reason": "bad_project_id"})

    conninfo = _sync_conninfo(db)

    with _app_conn(conninfo) as conn:
        # Resolve project_id -> org_id via SECURITY DEFINER function
        row = conn.execute(
            "SELECT project_org_lookup(%s::uuid)", [args.project],
        ).fetchone()
        if row is None or row[0] is None:
            return _fail({"project": args.project, "ok": False,
                          "reason": "project_not_found"})
        org_id = str(row[0])

        # Set RLS context
        conn.execute(
            "SELECT set_config('app.org_id', %s, true)", [org_id],
        )
        ok, gaps = verify_project(conn, args.project)
        gaps_truncated = len(gaps) >= _MAX_GAPS
        conn.commit()

    out: dict = {"project": args.project, "ok": ok, "gaps": gaps}
    if gaps_truncated:
        out["gaps_truncated"] = True
    print(json.dumps(out), flush=True)
    return 0 if ok else 1


def main(argv: list[str] | None = None) -> int:
    """Entry point for the ``agg-cp`` console script.

    Returns 0 on success, non-zero on failure.
    """
    parser = argparse.ArgumentParser(prog="agg-cp")
    sub = parser.add_subparsers(dest="command")

    audit_parser = sub.add_parser("audit")
    audit_sub = audit_parser.add_subparsers(dest="audit_command")
    verify_parser = audit_sub.add_parser("verify")
    verify_parser.add_argument("--org", required=False)
    verify_parser.add_argument("--project", required=False)

    args = parser.parse_args(argv)

    if args.command == "audit" and getattr(args, "audit_command", None) == "verify":
        if getattr(args, "project", None):
            return _cmd_audit_verify_project(args)
        if getattr(args, "org", None):
            return _cmd_audit_verify(args)
        return _fail({"ok": False, "reason": "specify --org or --project"})

    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
