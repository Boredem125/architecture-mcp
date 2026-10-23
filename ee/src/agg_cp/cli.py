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
from pathlib import Path


def _db_url() -> str | None:
    """Resolve the DB URL from environment variables."""
    url = os.environ.get("AGG_DATABASE_URL")
    if url is None:
        url_file = os.environ.get("AGG_DATABASE_URL_FILE")
        if url_file:
            url = Path(url_file).read_text(encoding="utf-8").strip()
    return url


def _cmd_audit_verify(args: argparse.Namespace) -> int:
    """Run ``audit verify --org <slug>``."""
    import psycopg

    from agg_cp.auth import _app_conn, _sync_conninfo
    from agg_cp.audit import verify_chain

    db = _db_url()
    if not db:
        print(
            json.dumps({"org": args.org, "ok": False, "reason": "no_db_url"}),
            flush=True,
        )
        return 1

    conninfo = _sync_conninfo(db)

    # Resolve org slug -> org_id via org_login_config
    with _app_conn(conninfo) as conn:
        row = conn.execute(
            "SELECT org_id FROM org_login_config(%s)", [args.org],
        ).fetchone()
        if row is None:
            print(
                json.dumps({
                    "org": args.org,
                    "ok": False,
                    "reason": "org_not_found",
                }),
                flush=True,
            )
            return 1
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
    from agg_cp.sync.audit import verify_project

    db = _db_url()
    if not db:
        print(
            json.dumps({"project": args.project, "ok": False,
                        "reason": "no_db_url"}),
            flush=True,
        )
        return 1

    conninfo = _sync_conninfo(db)

    with _app_conn(conninfo) as conn:
        # Resolve project_id -> org_id via SECURITY DEFINER function
        row = conn.execute(
            "SELECT project_org_lookup(%s::uuid)", [args.project],
        ).fetchone()
        if row is None or row[0] is None:
            print(
                json.dumps({"project": args.project, "ok": False,
                            "reason": "project_not_found"}),
                flush=True,
            )
            return 1
        org_id = str(row[0])

        # Set RLS context
        conn.execute(
            "SELECT set_config('app.org_id', %s, true)", [org_id],
        )
        ok, gaps = verify_project(conn, args.project)
        conn.commit()

    print(
        json.dumps({"project": args.project, "ok": ok,
                     "gaps": gaps}),
        flush=True,
    )
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
        print(json.dumps({"ok": False, "reason": "specify --org or --project"}),
              flush=True)
        return 1

    parser.print_help()
    return 1
