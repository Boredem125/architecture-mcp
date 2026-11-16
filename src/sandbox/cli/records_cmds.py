"""`sandbox retention` and `sandbox alerts`.

Heavy imports stay inside the command bodies per house convention.
"""
from __future__ import annotations

import re
import time

import click


# R2-13: control characters to strip from untrusted alert fields before display.
# Mirrors _LOCAL_CTRL in connector_cmds.py and _CTRL_CHARS in process.py.
_ALERT_CTRL = frozenset(
    set(range(0x00, 0x20))       # C0 including TAB, LF, CR
    | set(range(0x80, 0xA1))     # C1 including NBSP
    | {0x7F}                     # DEL
    | {0x202A, 0x202B, 0x202C, 0x202D, 0x202E}  # bidi
    | {0x2066, 0x2067, 0x2068, 0x2069}            # bidi isolates
    | {0x200E, 0x200F}                             # LRM / RLM
    | {0x061C}                                     # ALM
    | {0x202F}                                     # NNBSP
    | set(range(0xD800, 0xE000))                   # surrogates
    | {0x2028}                                     # LINE SEPARATOR
    | {0x2029}                                     # PARAGRAPH SEPARATOR
    | {0x200B}                                     # ZERO WIDTH SPACE
    | {0xFEFF}                                     # BOM
    | {0x00AD}                                     # SOFT HYPHEN
)

_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")


def _sanitize_alert_field(text: str) -> str:
    """Strip control chars from untrusted alert field for display (R2-13)."""
    if not isinstance(text, str):
        return "" if text is None else str(text)
    return "".join(c for c in text if ord(c) not in _ALERT_CTRL)


def _sanitize_alert_record(record: dict) -> dict:
    """Sanitize all string fields in an alert record for display (R2-13).

    Non-hex key_id values are redacted from both the key_id field and
    anywhere they appear in the reason text."""
    out = {}
    for k, v in record.items():
        if isinstance(v, str):
            out[k] = _sanitize_alert_field(v)
        else:
            out[k] = v
    # Redact non-hex key_id from reason text
    kid = record.get("key_id")
    if isinstance(kid, str) and kid and not _HEX_RE.match(kid):
        safe_kid = "invalid"
        out["key_id"] = safe_kid
        reason = out.get("reason", "")
        if isinstance(reason, str) and kid in reason:
            out["reason"] = reason.replace(kid, safe_kid)
    return out


def _layout(path: str):
    from sandbox.connector.layout import FolderLayout

    layout = FolderLayout.discover(path)
    if layout is None:
        click.echo("No .sandbox/ found. Run `sandbox init` first.")
        raise SystemExit(1)
    return layout


def _date(ts: float) -> str:
    return time.strftime("%Y-%m-%d", time.localtime(ts))


@click.command("retention")
@click.argument("path", default=".", type=click.Path(exists=True, file_okay=False))
@click.option("--apply", "do_apply", is_flag=True,
              help="Delete expired sessions (default: only list them). Each deletion is recorded.")
@click.option("--reviewer", default=None, help="Who is applying it (default: $SANDBOX_REVIEWER or your OS user).")
@click.option("--json", "as_json", is_flag=True, help="Machine-readable output.")
def retention_cmd(path: str, do_apply: bool, reviewer: str | None, as_json: bool) -> None:
    """Audit-log retention: list (or delete) sessions past their retention period."""
    import json

    from sandbox.connector import retention
    from sandbox.connector.approval import default_reviewer
    from sandbox.connector.policy_versions import enforced_policy

    layout = _layout(path)
    audit_policy = enforced_policy(layout)[0].audit
    rows = retention.plan(layout, audit_policy)
    removed = retention.apply(layout, rows, reviewer or default_reviewer()) if do_apply else []
    if as_json:
        click.echo(json.dumps({"sessions": rows, "removed": removed}, indent=2))
        return
    if not rows:
        click.echo("No audit sessions.")
        return
    click.echo(f"Retention: standard {audit_policy.retention_days}d, reviewed "
               f"{audit_policy.retention_days_reviewed}d, incident {audit_policy.retention_days_incident}d")
    for r in rows:
        status = "ACTIVE" if r["active"] else ("EXPIRED" if r["expired"] else "kept")
        if r["session_id"] in removed:
            status = "DELETED"
        click.echo(f"  {r['session_id']:<28} {r['tier']:<9} last {_date(r['last_activity'])}  "
                   f"until {_date(r['expires'])}  {status}")
    expired = [r for r in rows if r["expired"] and not r["active"]]
    if expired and not do_apply:
        click.echo(f"{len(expired)} expired. Take an evidence pack first if needed "
                   "(`sandbox export-evidence`), then run with --apply.")


@click.command("alerts")
@click.argument("path", default=".", type=click.Path(exists=True, file_okay=False))
@click.option("-n", "--lines", default=20, show_default=True, help="How many recent alerts to show.")
def alerts_cmd(path: str, lines: int) -> None:
    """Recent alerts: denials, critical escalations, injection hits, rate limits."""
    import os

    from sandbox.connector.alerts import read_alerts
    from sandbox.connector.policy_versions import enforced_policy

    layout = _layout(path)
    rows = read_alerts(layout, lines)
    policy = enforced_policy(layout)[0].alerts
    hook = "set" if os.environ.get(policy.webhook_url_env) else "not set"
    click.echo(f"Alerts: {'on' if policy.enabled else 'OFF'}; webhook ${policy.webhook_url_env} {hook}")
    if not rows:
        click.echo("No alerts.")
        return
    for a in rows:
        a = _sanitize_alert_record(a)
        stamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(a.get("ts", 0)))
        risk = f" risk={a['risk_score']}" if a.get("risk_score") is not None else ""
        sent = f"  [{a['webhook']}]" if a.get("webhook") else ""
        click.echo(f"[{stamp}] {str(a.get('kind', '?')).upper():<10}{risk}  "
                   f"{a.get('command') or a.get('tool') or ''}  {a.get('reason') or ''}{sent}")
