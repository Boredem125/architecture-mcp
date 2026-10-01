"""`sandbox oversight`: oversight indicators and approval-fatigue flags.

Heavy imports stay inside the command body per house convention.
"""
from __future__ import annotations

import re

import click

_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400}


def parse_since(value: str, now: float) -> float:
    """'30m', '24h', '7d', '90s' (ago), or an ISO date/time (local time)."""
    from datetime import datetime

    m = re.fullmatch(r"\s*(\d+(?:\.\d+)?)\s*([smhd])\s*", value or "")
    if m:
        return now - float(m.group(1)) * _UNITS[m.group(2)]
    try:
        return datetime.fromisoformat(value.strip()).timestamp()
    except ValueError:
        raise click.BadParameter("use a duration like 30m, 24h, 7d or an ISO date like 2026-09-01")


def _fmt(v, suffix: str = "") -> str:
    return "-" if v is None else f"{v:g}{suffix}"


def _pct(v) -> str:
    return "-" if v is None else f"{v:.0%}"


@click.command("oversight")
@click.argument("path", default=".")
@click.option("--json", "as_json", is_flag=True, help="Emit JSON.")
@click.option("--since", default=None, help="Only decisions since then: 30m, 24h, 7d, or an ISO date.")
def oversight_cmd(path: str, as_json: bool, since: str | None) -> None:
    """Oversight indicators per reviewer: approval rate, decision time, fast approvals, bursts."""
    import json
    import time

    from sandbox.connector.layout import FolderLayout
    from sandbox.connector.oversight import compute_metrics

    layout = FolderLayout.discover(path)
    if layout is None:
        click.echo("No .sandbox/ found.")
        raise SystemExit(1)
    now = time.time()
    since_ts = parse_since(since, now) if since else None
    m = compute_metrics(layout, since=since_ts, now=now)
    if as_json:
        click.echo(json.dumps(m, indent=2))
        return

    t = m["thresholds"]
    req = m["requests"]
    when = time.strftime("%Y-%m-%d %H:%M", time.localtime(since_ts)) if since_ts else "all records"
    click.echo(f"Oversight indicators for {m['root']} ({when})")
    click.echo("Indicators only: they do not show that oversight was effective or ineffective.\n")
    click.echo(f"Requests: {req['decided']} decided ({req['approved']} approved, {req['denied']} denied), "
               f"{req['pending']} pending, {req['timed_out']} pending past the "
               f"{m['escalation_timeout_seconds']:g} s timeout (share {_pct(req['timeout_share'])}), "
               f"{req['decided_after_timeout']} decided after it")
    click.echo(f"Fast = approved under {t['fast_seconds']:g} s after the request was created; "
               f"burst = {t['burst_approvals']} approvals within {t['window_minutes']:g} min.\n")

    header = f"{'reviewer':<16}{'appr':>6}{'deny':>6}{'rate':>7}{'median':>9}{'p90':>9}{'fast':>7}{'bursts':>8}{'events':>8}  now"
    click.echo(header)
    click.echo("-" * len(header))

    def row(name: str, r: dict, now_flag: str) -> None:
        d = r["decision_seconds"]
        click.echo(f"{name[:15]:<16}{r['approvals']:>6}{r['denials']:>6}{_pct(r['approval_rate']):>7}"
                   f"{_fmt(d['median'], 's'):>9}{_fmt(d['p90'], 's'):>9}{r['fast_approvals']:>7}"
                   f"{r['bursts']:>8}{r['fatigue_events']:>8}  {now_flag}")

    for name, r in m["reviewers"].items():
        row(name, r, "FLAGGED" if r["flagged_now"] else "")
    row("(all)", m["overall"], "")
    for name, r in m["reviewers"].items():
        if r["flagged_now"]:
            click.echo(f"\n{name} is flagged for approval fatigue: {'; '.join(r['flagged_reasons'])}")
    if not t["enabled"]:
        click.echo("\nFatigue detection is off (policy oversight.enabled = false).")
