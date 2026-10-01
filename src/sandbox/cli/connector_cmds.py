"""Folder-connector CLI commands, registered onto the main `cli` group.

Heavy imports stay inside command bodies per house convention.
"""
from __future__ import annotations

import click


def register(cli: click.Group) -> None:
    """Attach the connector commands to *cli*."""
    cli.add_command(init_cmd)
    cli.add_command(watch_cmd)
    cli.add_command(approve_cmd)
    cli.add_command(deny_cmd)
    cli.add_command(status_cmd)
    cli.add_command(changes_cmd)
    cli.add_command(restore_cmd)
    cli.add_command(verify_cmd)
    cli.add_command(seal_cmd)
    cli.add_command(policy_group)
    cli.add_command(uninstall_cmd)
    cli.add_command(explain_cmd)
    cli.add_command(logs_cmd)
    cli.add_command(semantic_group)
    cli.add_command(governance_group)


@click.group("governance")
def governance_group() -> None:
    """Plain-language governance clauses evaluated at runtime."""


@governance_group.command("use")
@click.argument("policy_file")
@click.option("--path", "folder", default=".")
def governance_use_cmd(policy_file: str, folder: str) -> None:
    """Point this folder at a governance policy JSON (evaluated on escalated commands)."""
    from sandbox.connector.policy import load_policy, save_policy
    from sandbox.governance.policy import load as gov_load

    layout = _semantic_layout(folder)
    gov = gov_load(policy_file)  # validate before saving the path
    policy = load_policy(layout.policy_file)
    policy.semantic.governance_policy = str(policy_file)
    save_policy(policy, layout.policy_file)
    click.echo(f"Using governance policy '{gov.name}' with {len(gov.clauses)} clauses.")
    if not policy.semantic.enabled:
        click.echo("Note: run `sandbox semantic enable` and `jevos serve` for it to take effect.")


@governance_group.command("list")
@click.argument("path", default=".")
def governance_list_cmd(path: str) -> None:
    """Show the clauses in the folder's governance policy."""
    from sandbox.connector.policy import load_policy
    from sandbox.governance.policy import load as gov_load

    layout = _semantic_layout(path)
    ref = load_policy(layout.policy_file).semantic.governance_policy
    if not ref:
        click.echo("No governance policy set. Use `sandbox governance use <file>`.")
        return
    gov = gov_load(ref)
    click.echo(f"{gov.name}  ({len(gov.clauses)} clauses)")
    for c in gov.clauses:
        click.echo(f"  [{c.id}] {c.title}  -> {c.action}")
        click.echo(f"      check: {c.check}")
        if c.requires_actions:
            click.echo(f"      only when the command does: {', '.join(c.requires_actions)}")
        if c.requires_tool_actions:
            click.echo(f"      tool calls, only when the call: {', '.join(c.requires_tool_actions)}")
        else:
            click.echo("      not applied to tool calls (no requires_tool_actions)")
        if c.framework_refs:
            click.echo(f"      maps to: {', '.join(c.framework_refs)}")


@governance_group.command("test")
@click.argument("path", default=".")
@click.option("--policy", "policy_file", default=None, help="Test this policy file instead of the folder's.")
def governance_test_cmd(path: str, policy_file: str | None) -> None:
    """Measure each clause against its own example cases (needs `jevos serve`)."""
    from sandbox.connector.policy import load_policy
    from sandbox.governance.policy import example_policy_path
    from sandbox.governance.policy import load as gov_load
    from sandbox.semantic.client import SemanticClient

    layout = _semantic_layout(path)
    sem = load_policy(layout.policy_file).semantic
    ref = policy_file or sem.governance_policy or str(example_policy_path())
    gov = gov_load(ref)
    client = SemanticClient.from_policy(sem)
    if client.ask("probe", {"p": {"type": "noul", "instructions": "probe"}}) is None:
        raise click.ClickException("jev-os service not reachable — start it with `jevos serve`.")

    click.echo(f"{gov.name}\n")
    total_ok = total = 0
    for c in gov.clauses:
        rows = [(t, True) for t in c.examples_violating] + [(t, False) for t in c.examples_allowed]
        if not rows:
            click.echo(f"  [{c.id}] no examples")
            continue
        ok = 0
        misses = []
        for text, should_fire in rows:
            res = client.ask(text, {c.id: c.question()})
            fired = res is not None and res.scores[c.id] >= c.threshold
            ok += fired == should_fire
            if fired != should_fire:
                misses.append(("missed" if should_fire else "false-alarm", text))
        total_ok += ok
        total += len(rows)
        flag = "" if ok == len(rows) else "   <-- needs calibration"
        click.echo(f"  [{c.id}] {ok}/{len(rows)} examples correct{flag}")
        for kind, text in misses:
            click.echo(f"        {kind}: {text}")
    click.echo(f"\nOverall: {total_ok}/{total} example cases correct.")


@click.group("semantic")
def semantic_group() -> None:
    """Intent-aware checks via a local jev-os service (optional)."""


def _semantic_layout(path: str):
    from sandbox.connector.layout import FolderLayout

    layout = FolderLayout.discover(path)
    if layout is None:
        click.echo("No .sandbox/ found here or above. Run `sandbox init` first.")
        raise SystemExit(1)
    return layout


@semantic_group.command("status")
@click.argument("path", default=".")
def semantic_status_cmd(path: str) -> None:
    """Show whether the layer is on, whether jev-os answers, and any taint."""
    import datetime as _dt

    from sandbox.connector.policy import load_policy
    from sandbox.semantic import taint
    from sandbox.semantic.checks import INJECTION_CHECKS
    from sandbox.semantic.client import SemanticClient

    layout = _semantic_layout(path)
    sem = load_policy(layout.policy_file).semantic
    click.echo(f"Enabled:  {sem.enabled}")
    click.echo(f"Service:  {sem.url}  (key from ${sem.api_key_env})")
    probe = SemanticClient.from_policy(sem).ask("Run the tests before opening a pull request.", INJECTION_CHECKS)
    click.echo(f"Reachable: {'yes, ' + probe.model if probe else 'no (checks are skipped; rules still apply)'}")
    from sandbox.semantic.trust import file_sha256

    for t in sem.trusted_files:
        ok = file_sha256(layout.root / t.path) == t.sha256
        click.echo(f"Trusted:  {t.path} ({'unchanged' if ok else 'CHANGED since review — scanned again'}; "
                   f"reviewed by {t.reviewer})")
    state = taint.read(layout.state_dir)
    if not state:
        click.echo("Taint:    none")
        return
    until = _dt.datetime.fromtimestamp(state["until"]).strftime("%H:%M:%S")
    click.echo(f"Taint:    ACTIVE until {until} — shell, network and out-of-folder actions need approval")
    for ev in state["events"][-5:]:
        click.echo(f"  - {ev.get('tool')}: {ev.get('top_check')} p={ev.get('top_score')} "
                   f"(segment {ev.get('segment_index')}/{ev.get('segment_count')}, sha {str(ev.get('text_sha256'))[:12]})")


@semantic_group.command("enable")
@click.argument("path", default=".")
@click.option("--url", default=None, help="jev-os service URL (default http://127.0.0.1:8321).")
def semantic_enable_cmd(path: str, url: str | None) -> None:
    """Turn the semantic layer on for this folder."""
    from sandbox.connector.policy import load_policy, save_policy

    layout = _semantic_layout(path)
    policy = load_policy(layout.policy_file)
    policy.semantic.enabled = True
    if url:
        policy.semantic.url = url
    save_policy(policy, layout.policy_file)
    click.echo(f"Semantic layer enabled ({policy.semantic.url}). Start the service with `jevos serve`.")


@semantic_group.command("disable")
@click.argument("path", default=".")
def semantic_disable_cmd(path: str) -> None:
    """Turn the semantic layer off (rules keep working as before)."""
    from sandbox.connector.policy import load_policy, save_policy

    layout = _semantic_layout(path)
    policy = load_policy(layout.policy_file)
    policy.semantic.enabled = False
    save_policy(policy, layout.policy_file)
    click.echo("Semantic layer disabled.")


def _audit_folder(layout, record: dict) -> None:
    import json as _json

    from sandbox.connector.audit import FolderAudit

    try:
        session_id = _json.loads(layout.session_file.read_text(encoding="utf-8")).get("session_id", "")
    except (OSError, ValueError):
        session_id = ""
    FolderAudit(layout.audit_dir, session_id).append(record)


@semantic_group.command("trust")
@click.argument("file")
@click.option("--path", "folder", default=".", help="Sandboxed folder (default: here).")
@click.option("--reviewer", required=True, help="Who reviewed the file's content.")
@click.option("--reason", required=True, help="Why its instructions are legitimate.")
def semantic_trust_cmd(file: str, folder: str, reviewer: str, reason: str) -> None:
    """Skip the injection scan for FILE while its content is unchanged (audited)."""
    from sandbox.connector.policy import load_policy, save_policy
    from sandbox.semantic.trust import trust

    layout = _semantic_layout(folder)
    policy = load_policy(layout.policy_file)
    try:
        entry = trust(layout.root, policy, file, reviewer, reason)
    except ValueError as e:
        raise click.ClickException(str(e)) from e
    save_policy(policy, layout.policy_file)
    _audit_folder(layout, {"event": "semantic_trust_added", **entry.model_dump()})
    click.echo(f"Trusted {entry.path} at sha256 {entry.sha256[:12]}… — any edit makes it scanned again.")


@semantic_group.command("untrust")
@click.argument("file")
@click.option("--path", "folder", default=".", help="Sandboxed folder (default: here).")
def semantic_untrust_cmd(file: str, folder: str) -> None:
    """Scan FILE again like any other content."""
    from sandbox.connector.policy import load_policy, save_policy
    from sandbox.semantic.trust import untrust

    layout = _semantic_layout(folder)
    policy = load_policy(layout.policy_file)
    if untrust(layout.root, policy, file):
        save_policy(policy, layout.policy_file)
        _audit_folder(layout, {"event": "semantic_trust_removed", "path": file})
        click.echo(f"{file} is scanned again.")
    else:
        click.echo(f"{file} was not trusted.")


@semantic_group.command("clear-taint")
@click.argument("path", default=".")
@click.option("--reviewer", required=True, help="Who reviewed the flagged content (recorded in the audit).")
@click.option("--reason", required=True, help="Why it is safe to continue.")
def semantic_clear_taint_cmd(path: str, reviewer: str, reason: str) -> None:
    """End a taint after a human reviewed the flagged content (audited)."""
    import json as _json

    from sandbox.connector.audit import FolderAudit
    from sandbox.semantic import taint

    layout = _semantic_layout(path)
    state = taint.read(layout.state_dir)
    if not state:
        click.echo("No active taint.")
        return
    try:
        session_id = _json.loads(layout.session_file.read_text(encoding="utf-8")).get("session_id", "")
    except (OSError, ValueError):
        session_id = ""
    FolderAudit(layout.audit_dir, session_id).append({
        "event": "taint_cleared", "reviewer": reviewer, "reason": reason,
        "taint_events": state.get("events", []),
    })
    taint.clear(layout.state_dir)
    click.echo(f"Taint cleared by {reviewer} (recorded in the audit chain).")


@click.command("init")
@click.argument("path", default=".")
@click.option("--claude/--no-claude", default=True, help="Merge Claude Code settings hook.")
@click.option("--mcp/--no-mcp", default=True, help="Write .mcp.json for the MCP channel.")
@click.option("--codex", is_flag=True, help="Print a Codex ~/.codex/config.toml snippet.")
@click.option("--auto-allow", is_flag=True, help="Let the connector emit allow decisions (bypasses Claude Code's own prompt).")
def init_cmd(path: str, claude: bool, mcp: bool, codex: bool, auto_allow: bool) -> None:
    """Initialize the sandbox connector in a folder."""
    from sandbox.connector.install import init

    result = init(path, claude=claude, mcp=mcp, codex=codex, auto_allow=auto_allow)
    click.echo(f"Sandbox connector initialized in {result['root']}")
    click.echo(f"  session:  {result['session_id']}")
    click.echo(f"  policy:   {result['policy']}")
    click.echo(f"  hook:     {result['stub']}")
    if result["settings"]:
        click.echo(f"  settings: {result['settings']}")
    if result["mcp_json"]:
        click.echo(f"  mcp:      {result['mcp_json']}")
    if result["codex_snippet"]:
        click.echo("\nAdd this to ~/.codex/config.toml:\n")
        click.echo(result["codex_snippet"])
    click.echo("\nRun `sandbox watch` in another terminal to approve escalations.")


@click.command("status")
@click.argument("path", default=".")
@click.option("--json", "as_json", is_flag=True, help="Emit JSON.")
def status_cmd(path: str, as_json: bool) -> None:
    """Show connector status and pending escalations."""
    import json as _json

    from sandbox.connector.layout import FolderLayout
    from sandbox.connector.policy import load_policy
    from sandbox.connector.queue import EscalationQueue

    layout = FolderLayout.discover(path)
    if layout is None:
        click.echo("No .sandbox/ found here or above. Run `sandbox init` first.")
        raise SystemExit(1)

    policy = load_policy(layout.policy_file)
    queue = EscalationQueue(layout)
    pending = queue.list_pending()

    if as_json:
        click.echo(_json.dumps({
            "root": str(layout.root),
            "triggers": policy.triggers.model_dump(),
            "pending": pending,
        }, indent=2))
        return

    click.echo(f"Root:     {layout.root}")
    click.echo(f"Triggers: {policy.triggers.model_dump()}")
    click.echo(f"Pending:  {len(pending)}")
    for rec in pending:
        click.echo(f"  [{rec['request_id']}] {rec.get('command', '')}")


@click.command("approve")
@click.argument("request_id")
@click.argument("path", default=".")
@click.option("--reason", default="", help="Note recorded with the approval.")
@click.option(
    "--remember",
    type=click.Choice(["once", "command", "prefix", "host", "dir"]),
    default="once",
    help="Remember this decision for the rest of the session.",
)
def approve_cmd(request_id: str, path: str, reason: str, remember: str) -> None:
    """Approve a pending escalation and run it."""
    import asyncio

    from sandbox.connector.broker import FolderBroker
    from sandbox.connector.layout import FolderLayout
    from sandbox.connector.queue import EscalationQueue

    layout = FolderLayout.discover(path)
    if layout is None:
        click.echo("No .sandbox/ found.")
        raise SystemExit(1)

    queue = EscalationQueue(layout)
    rec = queue.claim(request_id, "cli")
    if rec is None:
        click.echo(f"Could not claim {request_id} (already taken or not pending).")
        raise SystemExit(1)

    _remember_decision(layout, rec, remember)

    broker = FolderBroker()
    result = asyncio.run(broker.execute(rec, "cli", reason))
    queue.finish(request_id, result)
    if rec.get("kind") == "tool_call":
        click.echo(f"Approved {request_id}: the agent may retry this exact call once.")
    else:
        click.echo(f"Approved and executed {request_id} (exit {result.get('exit_code')}).")


def _remember_decision(layout, rec: dict, scope: str) -> None:
    """Record a remembered decision from an approved escalation record."""
    if scope == "once":
        return
    import json as _json

    from sandbox.connector.memory import DecisionMemory

    session = {}
    try:
        session = _json.loads(layout.session_file.read_text(encoding="utf-8"))
    except (OSError, _json.JSONDecodeError):
        pass

    command = rec.get("command", "")
    value = command
    if scope == "prefix":
        value = " ".join(command.split()[:2])
    elif scope == "dir":
        value = rec.get("path", "") or rec.get("exec_cwd", "")
    elif scope == "host":
        value = rec.get("url", "")
        try:
            from urllib.parse import urlparse

            value = urlparse(value).hostname or value
        except ValueError:
            pass

    if not value:
        return
    try:
        DecisionMemory(layout.remembered, session.get("session_id", "")).remember(
            scope, value, trigger=(rec.get("trigger") or [""])[0]
        )
        click.echo(f"  (remembered: {scope} → {value})")
    except ValueError as e:
        click.echo(f"  (not remembered: {e})")


@click.command("deny")
@click.argument("request_id")
@click.argument("path", default=".")
@click.option("--reason", default="", help="Why it was denied (goes back to the model).")
def deny_cmd(request_id: str, path: str, reason: str) -> None:
    """Deny a pending escalation."""
    from sandbox.connector.broker import FolderBroker
    from sandbox.connector.layout import FolderLayout
    from sandbox.connector.queue import EscalationQueue

    layout = FolderLayout.discover(path)
    if layout is None:
        click.echo("No .sandbox/ found.")
        raise SystemExit(1)

    queue = EscalationQueue(layout)
    rec = queue.claim(request_id, "cli")
    if rec is None:
        click.echo(f"Could not claim {request_id}.")
        raise SystemExit(1)

    queue.finish(request_id, FolderBroker.denial(rec, "cli", reason))
    click.echo(f"Denied {request_id}.")


@click.command("watch")
@click.argument("path", default=".")
@click.option("--reviewer", default="cli", help="Reviewer id recorded on decisions.")
@click.option("--once", is_flag=True, help="Drain the current queue and exit.")
def watch_cmd(path: str, reviewer: str, once: bool) -> None:
    """Interactively approve/deny escalations as they arrive."""
    import asyncio
    import time

    from sandbox.connector.broker import FolderBroker
    from sandbox.connector.layout import FolderLayout
    from sandbox.connector.queue import EscalationQueue

    layout = FolderLayout.discover(path)
    if layout is None:
        click.echo("No .sandbox/ found. Run `sandbox init` first.")
        raise SystemExit(1)

    queue = EscalationQueue(layout)
    broker = FolderBroker()
    click.echo(f"Watching {layout.root} for escalations (Ctrl-C to stop)...")

    def handle(rec: dict) -> None:
        rid = rec["request_id"]
        ident = rec.get("identity", {})
        risk = rec.get("risk", {})
        click.echo("\n" + "=" * 60)
        click.echo(f"Request : {rid}")
        if ident:
            click.echo(f"Agent   : {ident.get('agent_type','?')}"
                       f"({ident.get('model') or '?'})/{ident.get('user') or '?'}"
                       f"  trust={ident.get('trust_level','?')}")
        click.echo(f"Trigger : {', '.join(rec.get('trigger', []))}"
                   f"  [{rec.get('reason_code','')}]")
        if risk:
            band = risk.get("band", "?").upper()
            dual = "  *** DUAL CONTROL ***" if rec.get("requires_dual") else ""
            click.echo(f"Risk    : {risk.get('score','?')}/100 -> {band}{dual}")
        click.echo(f"Command : {rec.get('command', '')}")
        click.echo(f"Agent says: {rec.get('described_as') or '(no description)'}")
        actions = rec.get("actual_actions") or []
        if actions:
            click.echo("Actually: " + "; ".join(a["label"] for a in actions))
        click.echo(f"          (use `sandbox explain {rid}` for the full breakdown)")
        choice = click.prompt("[a]pprove / [d]eny / [s]kip", default="s").strip().lower()
        if choice == "a":
            claimed = queue.claim(rid, reviewer)
            if claimed is None:
                click.echo("  (already taken)")
                return
            result = asyncio.run(broker.execute(claimed, reviewer))
            queue.finish(rid, result)
            click.echo(f"  approved — exit {result.get('exit_code')}")
        elif choice == "d":
            note = click.prompt("  reason", default="denied by reviewer")
            claimed = queue.claim(rid, reviewer)
            if claimed is None:
                click.echo("  (already taken)")
                return
            queue.finish(rid, FolderBroker.denial(claimed, reviewer, note))
            click.echo("  denied")
        else:
            click.echo("  skipped (left pending)")

    try:
        while True:
            for rec in queue.list_pending():
                handle(rec)
            if once:
                break
            time.sleep(0.5)
    except KeyboardInterrupt:
        click.echo("\nStopped.")


@click.command("changes")
@click.argument("path", default=".")
@click.option("--json", "as_json", is_flag=True, help="Emit JSON.")
def changes_cmd(path: str, as_json: bool) -> None:
    """List modified and deleted files in the sandbox."""
    import json as _json

    from sandbox.connector.layout import FolderLayout

    layout = FolderLayout.discover(path)
    if layout is None:
        click.echo("No .sandbox/ found.")
        raise SystemExit(1)

    changes = []
    index_file = layout.originals_dir / "index.jsonl"
    if index_file.exists():
        try:
            with open(index_file, encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        try:
                            changes.append(_json.loads(line))
                        except _json.JSONDecodeError:
                            pass
        except OSError:
            pass

    # The human-readable change journal (one file per modification).
    journal = sorted(layout.changes_dir.glob("*.txt")) if layout.changes_dir.exists() else []

    if as_json:
        click.echo(_json.dumps({
            "root": str(layout.root),
            "changes": changes,
            "journal": [p.name for p in journal],
        }, indent=2))
        return

    click.echo(f"Changes in {layout.root}:")
    if journal:
        click.echo(f"\nReadable change journal ({len(journal)} entries) "
                   f"at {layout.changes_dir}:")
        for p in journal:
            # Show the header lines (File / Action) from each entry.
            try:
                head = p.read_text(encoding="utf-8").splitlines()
                summary = next((l for l in head if l.startswith("File")), p.name)
                action = next((l for l in head if l.startswith("Action")), "")
                click.echo(f"  {p.name}: {summary.replace('File    : ', '')}"
                           f"  ({action.replace('Action  : ', '')})")
            except OSError:
                click.echo(f"  {p.name}")
        click.echo(f"\n  Open any file above to see the diff + old-version pointer,")
        click.echo(f"  or run `sandbox restore <file>` to revert.")
    elif changes:
        for rec in changes:
            click.echo(f"  [{rec.get('verdict','?')}] {rec.get('rel_path','?')} "
                       f"({rec.get('timestamp','')})")
    else:
        click.echo("  (no file modifications recorded yet)")


@click.command("restore")
@click.argument("rel_path")
@click.argument("path", default=".")
@click.option("--sha", default="", help="Restore to specific hash (default: latest).")
@click.option("--dry-run", is_flag=True, help="Show what would be restored, don't do it.")
def restore_cmd(rel_path: str, path: str, sha: str, dry_run: bool) -> None:
    """Restore a file from the originals store."""
    from pathlib import Path

    from sandbox.connector.layout import FolderLayout

    layout = FolderLayout.discover(path)
    if layout is None:
        click.echo("No .sandbox/ found.")
        raise SystemExit(1)

    # Find the original
    abs_path = (Path(layout.root) / rel_path).resolve()
    if not str(abs_path).startswith(str(Path(layout.root).resolve())):
        click.echo(f"Path {rel_path} is outside the root.")
        raise SystemExit(1)

    # Search originals index for this file
    target_sha = sha
    index_file = layout.originals_dir / "index.jsonl"
    if not target_sha and index_file.exists():
        try:
            import json

            with open(index_file, encoding="utf-8") as f:
                for line in reversed(list(f)):
                    if line.strip():
                        try:
                            rec = json.loads(line)
                            if rec.get("rel_path") == rel_path and rec.get("verdict") != "deleted":
                                target_sha = rec.get("sha256", "")
                                if target_sha:
                                    break
                        except json.JSONDecodeError:
                            pass
        except OSError:
            pass

    if not target_sha:
        click.echo(f"No snapshot found for {rel_path}")
        raise SystemExit(1)

    # Locate the original file
    original_path = layout.originals_dir / target_sha[:2] / target_sha[2:]
    if not original_path.exists():
        click.echo(f"Original not found: {original_path}")
        raise SystemExit(1)

    if dry_run:
        click.echo(f"Would restore {rel_path} from {target_sha}")
        return

    try:
        abs_path.parent.mkdir(parents=True, exist_ok=True)
        abs_path.write_bytes(original_path.read_bytes())
        click.echo(f"Restored {rel_path} from {target_sha}")
    except OSError as e:
        click.echo(f"Restore failed: {e}")
        raise SystemExit(1)


@click.command("verify")
@click.argument("path", default=".")
def verify_cmd(path: str) -> None:
    """Verify the integrity of the audit chain."""
    from sandbox.connector.audit import FolderAudit
    from sandbox.connector.layout import FolderLayout

    layout = FolderLayout.discover(path)
    if layout is None:
        click.echo("No .sandbox/ found.")
        raise SystemExit(1)

    audit = FolderAudit(layout.audit_dir)
    valid, msg = audit.verify_chain()
    if valid:
        click.echo(f"✓ Audit chain valid: {msg}")
    else:
        click.echo(f"✗ Audit chain broken: {msg}")
        raise SystemExit(1)


@click.command("seal")
@click.argument("path", default=".")
def seal_cmd(path: str) -> None:
    """Seal the current session's audit log."""
    import json

    from sandbox.connector.layout import FolderLayout

    layout = FolderLayout.discover(path)
    if layout is None:
        click.echo("No .sandbox/ found.")
        raise SystemExit(1)

    session = {}
    try:
        session = json.loads(layout.session_file.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        pass

    session_id = session.get("session_id", "")
    if not session_id:
        click.echo("No session to seal.")
        raise SystemExit(1)

    from sandbox.connector.audit import FolderAudit

    audit = FolderAudit(layout.audit_dir, session_id)
    seal_record = {
        "timestamp": __import__("time").strftime("%Y-%m-%dT%H:%M:%SZ", __import__("time").gmtime()),
        "session_id": session_id,
        "event": "session_sealed",
        "reason": "User-initiated seal",
    }
    audit.append(seal_record)
    click.echo(f"Sealed session {session_id}")


# ---------------------------------------------------------------------------
# sandbox policy * — view and tune the folder policy
# ---------------------------------------------------------------------------

@click.command("logs")
@click.argument("path", default=".")
@click.option("-n", "--lines", default=40, help="How many recent lines to show.")
def logs_cmd(path: str, lines: int) -> None:
    """Show the human-readable activity log (every escalation + decision)."""
    from sandbox.connector.layout import FolderLayout

    layout = FolderLayout.discover(path)
    if layout is None:
        click.echo("No .sandbox/ found.")
        raise SystemExit(1)

    log_file = layout.logs_dir / "activity.log"
    if not log_file.exists():
        click.echo(f"No activity yet. (log will appear at {log_file})")
        return

    try:
        content = log_file.read_text(encoding="utf-8").splitlines()
    except OSError as e:
        click.echo(f"Could not read log: {e}")
        raise SystemExit(1)

    for line in content[-lines:]:
        click.echo(line)
    click.echo(f"\n({len(content)} total lines — full log at {log_file})")
    click.echo("For the signed, tamper-evident record use `sandbox verify` / "
               "`sandbox explain <id>`.")


@click.command("explain")
@click.argument("request_id")
@click.argument("path", default=".")
@click.option("--json", "as_json", is_flag=True, help="Emit the raw record as JSON.")
def explain_cmd(request_id: str, path: str, as_json: bool) -> None:
    """Explain a decision: identity, risk factors, verdict, approver, outcome."""
    import json as _json

    from sandbox.connector.layout import FolderLayout
    from sandbox.connector.queue import EscalationQueue

    layout = FolderLayout.discover(path)
    if layout is None:
        click.echo("No .sandbox/ found.")
        raise SystemExit(1)

    queue = EscalationQueue(layout)
    rec = queue.get(request_id)
    if rec is None:
        click.echo(f"No record for {request_id}.")
        raise SystemExit(1)

    if as_json:
        click.echo(_json.dumps(rec, indent=2))
        return

    ident = rec.get("identity", {})
    risk = rec.get("risk", {})
    status = queue.status(request_id)

    click.echo(f"REQUEST: {request_id}   [{status}]")
    click.echo(f"Agent:     {ident.get('agent_type','?')} "
               f"(model {ident.get('model') or '?'}, trust {ident.get('trust_level','?')})")
    click.echo(f"Operator:  {ident.get('user') or '?'}   project {ident.get('project') or '?'}")
    click.echo(f"Action:    {rec.get('command') or rec.get('path') or rec.get('url') or '?'}")
    if rec.get("described_as"):
        click.echo(f"Agent says: {rec['described_as']}")
    actions = rec.get("actual_actions") or []
    if actions:
        click.echo("Actually:  " + "; ".join(a["label"] for a in actions)
                   + "  (compare with what the agent says above)")
    click.echo(f"Trigger:   {', '.join(rec.get('trigger', []))}   "
               f"reason_code {rec.get('reason_code','?')}")
    if risk:
        click.echo(f"Risk:      {risk.get('score','?')}/100 -> {risk.get('band','?').upper()}"
                   + ("   [DUAL CONTROL]" if rec.get("requires_dual") else ""))
        for f in sorted(risk.get("factors", []), key=lambda x: -abs(x.get("points", 0))):
            sign = "+" if f.get("points", 0) >= 0 else ""
            click.echo(f"           {sign}{f.get('points'):>3}  {f.get('name')}"
                       + (f" - {f.get('detail')}" if f.get("detail") else ""))
    decision = rec.get("decision") or rec.get("state")
    if decision:
        click.echo(f"Decision:  {decision}   by {rec.get('reviewer_id') or '(pending)'}")
    if rec.get("exit_code") is not None:
        click.echo(f"Outcome:   exit {rec.get('exit_code')}")
    if rec.get("signature"):
        click.echo(f"Signature: {rec['signature'][:32]}... (Ed25519, verifiable)")


@click.command("uninstall")
@click.argument("path", default=".")
@click.option("--keep-data", is_flag=True, help="Leave .sandbox/ data in place (only remove hooks).")
@click.option("--yes", is_flag=True, help="Skip the confirmation prompt.")
def uninstall_cmd(path: str, keep_data: bool, yes: bool) -> None:
    """Remove the connector from a folder (hooks + optionally data)."""
    from sandbox.connector.install import uninstall

    if not keep_data and not yes:
        click.confirm(
            f"This removes the connector hooks AND all .sandbox/ data in {path}. Continue?",
            abort=True,
        )

    result = uninstall(path, keep_data=keep_data)
    click.echo(f"Uninstalled connector from {result['root']}")
    click.echo(f"  settings entry removed: {result['settings_entry_removed']}")
    click.echo(f"  data removed:           {result['data_removed']}")
    if keep_data:
        click.echo("  (.sandbox/ data kept - remove manually if desired)")


@click.group("policy")
def policy_group() -> None:
    """View and tune the folder policy."""


def _load_layout_policy(path: str):
    from sandbox.connector.layout import FolderLayout
    from sandbox.connector.policy import load_policy

    layout = FolderLayout.discover(path)
    if layout is None:
        click.echo("No .sandbox/ found. Run `sandbox init` first.")
        raise SystemExit(1)
    return layout, load_policy(layout.policy_file)


@policy_group.command("show")
@click.argument("path", default=".")
def policy_show(path: str) -> None:
    """Print the current policy as JSON."""
    import json as _json

    _layout, policy = _load_layout_policy(path)
    click.echo(_json.dumps(policy.model_dump(), indent=2))


@policy_group.command("allow-shell")
@click.argument("pattern")
@click.argument("path", default=".")
def policy_allow_shell(pattern: str, path: str) -> None:
    """Add a shell allow-pattern (regex) so matching commands run silently."""
    from sandbox.connector.policy import save_policy

    layout, policy = _load_layout_policy(path)
    if pattern not in policy.shell.allow_patterns:
        policy.shell.allow_patterns.append(pattern)
        save_policy(policy, layout.policy_file)
        click.echo(f"Added shell allow-pattern: {pattern}")
    else:
        click.echo("Pattern already present.")


@policy_group.command("allow-host")
@click.argument("host")
@click.argument("path", default=".")
def policy_allow_host(host: str, path: str) -> None:
    """Add a network host to the allowlist (WebFetch to it runs silently)."""
    from sandbox.connector.policy import save_policy

    layout, policy = _load_layout_policy(path)
    if host not in policy.network.allow_hosts:
        policy.network.allow_hosts.append(host)
        save_policy(policy, layout.policy_file)
        click.echo(f"Added allowed host: {host}")
    else:
        click.echo("Host already allowed.")


@policy_group.command("set-trigger")
@click.argument("trigger", type=click.Choice(["shell", "write_outside", "network", "read_outside"]))
@click.argument("verdict", type=click.Choice(["allow", "observe", "escalate", "deny"]))
@click.argument("path", default=".")
def policy_set_trigger(trigger: str, verdict: str, path: str) -> None:
    """Set a trigger's verdict (e.g. `policy set-trigger read_outside escalate`)."""
    from sandbox.connector.policy import save_policy

    layout, policy = _load_layout_policy(path)
    setattr(policy.triggers, trigger, verdict)
    save_policy(policy, layout.policy_file)
    click.echo(f"Set trigger {trigger} = {verdict}")


@policy_group.command("forget")
@click.argument("path", default=".")
def policy_forget(path: str) -> None:
    """Clear all remembered (session-scoped) decisions."""
    import json as _json

    from sandbox.connector.layout import FolderLayout
    from sandbox.connector.memory import DecisionMemory

    layout = FolderLayout.discover(path)
    if layout is None:
        click.echo("No .sandbox/ found.")
        raise SystemExit(1)

    session = {}
    try:
        session = _json.loads(layout.session_file.read_text(encoding="utf-8"))
    except (OSError, _json.JSONDecodeError):
        pass

    memory = DecisionMemory(layout.remembered, session.get("session_id", ""))
    memory.forget_all()
    click.echo("Cleared remembered decisions.")
