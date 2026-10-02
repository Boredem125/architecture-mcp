"""`sandbox export-evidence` / `sandbox verify-evidence` (logic in connector/evidence.py)."""
from __future__ import annotations

import click


@click.command("export-evidence")
@click.argument("path", default=".")
@click.option("--out", required=True, help="New or empty directory, or a new .zip file.")
@click.option("--since", default=None, help="Only decisions at or after this ISO 8601 date/time (UTC if no zone).")
@click.option("--until", default=None, help="Only decisions at or before this ISO 8601 date/time (UTC if no zone).")
def export_evidence_cmd(path: str, out: str, since: str | None, until: str | None) -> None:
    """Write a signed evidence pack: decisions, approvals, audit chains, policies."""
    from sandbox.connector.evidence import EvidenceError, export_evidence
    from sandbox.connector.layout import FolderLayout

    layout = FolderLayout.discover(path)
    if layout is None:
        click.echo("No .sandbox/ found.")
        raise SystemExit(1)
    try:
        s = export_evidence(layout, out, since, until)
    except EvidenceError as exc:
        raise click.ClickException(str(exc)) from exc

    d, a = s["decisions"], s["audit"]
    click.echo(f"Evidence pack written to {s['out']} ({s['file_count']} files).")
    click.echo(f"  Decisions: {d['total']}  {d['by_outcome']}  passing all checks: {d['passing_all_checks']}")
    click.echo(f"  Audit: {a['sessions']} session(s), {a['records']} records, "
               f"chains {'all valid' if a['all_chains_valid'] else 'NOT all valid'}")
    if s.get("alerts", {}).get("count"):
        click.echo(f"  Alerts: {s['alerts']['count']}")
    click.echo(f"  Exporter public key: {s['exporter_public_key']}")
    au = s.get("aiuc1") or {}
    if au.get("by_requirement"):
        click.echo(f"  AIUC-1 evidence (release {au['release']}, self-assessed, details in {au['file']}):")
        for req, r in au["by_requirement"].items():
            seen = f"{r['evidence_items']} item(s)" if r["evidence_items"] else "configured, no events yet"
            click.echo(f"    {req} {r['title']} [{r['self_assessed_status']}]: "
                       f"{seen}; {', '.join(r['controls'])}")
    for note in s["notes"]:
        click.echo(f"  Note: {note}")
    if s["failed_checks"]:
        click.echo(f"  {len(s['failed_checks'])} failed check(s), listed in summary.json:")
        for f in s["failed_checks"]:
            click.echo(f"    {f['file']}: {f['check']}: {f['detail']}")
    click.echo("Verify with: sandbox verify-evidence <pack> --exporter-key <key above>")


@click.command("verify-evidence")
@click.argument("pack")
@click.option("--exporter-key", default=None,
              help="Expected exporter public key (hex), obtained out of band. Recommended.")
def verify_evidence_cmd(pack: str, exporter_key: str | None) -> None:
    """Re-verify an evidence pack offline; exit 1 on any failure."""
    from sandbox.connector.evidence import EvidenceError, verify_evidence

    try:
        r = verify_evidence(pack, exporter_key)
    except EvidenceError as exc:
        click.echo(f"FAILED: {exc}")
        raise SystemExit(1) from exc

    click.echo(f"Pack: {pack}  (exported {r.get('created_at')} from {r.get('source_root')})")
    click.echo(f"Exporter key: {r['exporter_public_key']}"
               + ("" if exporter_key else "  (not pinned: pass --exporter-key to check it)"))
    if r["ok"]:
        click.echo(f"OK: manifest signature, {r['files']} file hashes, {r['decisions']} decision record(s) "
                   f"and {r['sessions']} audit chain(s) verified.")
        return
    click.echo(f"FAILED: {len(r['failures'])} problem(s):")
    for f in r["failures"]:
        click.echo(f"  {f}")
    raise SystemExit(1)
