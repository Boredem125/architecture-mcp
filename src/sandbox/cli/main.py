from __future__ import annotations

import click
import uvicorn


@click.group()
def cli() -> None:
    """AI Agent Sandbox Security System — CLI management."""
    pass


# Folder-connector commands (init / watch / approve / deny / status).
from sandbox.cli.connector_cmds import register as _register_connector

_register_connector(cli)


@cli.command()
@click.option("--host", default="0.0.0.0", help="Bind host")
@click.option("--port", default=8000, type=int, help="Bind port")
@click.option("--reload", is_flag=True, help="Enable auto-reload")
@click.option("--workers", default=1, type=int, help="Number of workers")
def serve(host: str, port: int, reload: bool, workers: int) -> None:
    """Start the sandbox API server."""
    uvicorn.run(
        "sandbox.api.app:app",
        host=host,
        port=port,
        reload=reload,
        workers=workers,
        log_level="info",
    )


@cli.command()
@click.argument("session_id")
def inspect_session(session_id: str) -> None:
    """Inspect a session's current state."""
    from sandbox.api.app import get_session_manager

    sm = get_session_manager()
    session = sm.get_session(session_id)
    if session is None:
        click.echo(f"Session {session_id} not found.")
        return

    click.echo(f"Session ID:    {session.session_id}")
    click.echo(f"Agent ID:      {session.agent_id}")
    click.echo(f"Active:        {session.is_active}")
    click.echo(f"Killed:        {session.is_killed}")
    click.echo(f"Started:       {session.started_at.isoformat()}")
    click.echo(f"Expires:       {session.expires_at.isoformat() if session.expires_at else 'N/A'}")
    click.echo(f"Requests:      {session.total_requests}")
    click.echo(f"Writes:        {session.write_count}")
    click.echo(f"Executes:      {session.execute_count}")
    click.echo(f"Denies:        {session.deny_count}")
    click.echo(f"HITL reviews:  {session.hitl_count}")


@cli.command()
@click.argument("session_id")
def verify_audit(session_id: str) -> None:
    """Verify the audit chain integrity for a session."""
    import asyncio
    from sandbox.audit.sink import AuditSink

    async def _verify() -> bool:
        sink = AuditSink(log_dir="./audit_logs")
        return await sink.verify_chain(session_id)

    result = asyncio.run(_verify())
    if result:
        click.echo(f"Audit chain for session {session_id}: VALID")
    else:
        click.echo(f"Audit chain for session {session_id}: INVALID — investigate immediately")


@cli.command()
def list_sessions() -> None:
    """List all active sessions."""
    from sandbox.api.app import get_session_manager

    sm = get_session_manager()
    sessions = sm.get_active_sessions()
    if not sessions:
        click.echo("No active sessions.")
        return

    for s in sessions:
        click.echo(
            f"  {s.session_id}  agent={s.agent_id}  "
            f"requests={s.total_requests}  started={s.started_at.isoformat()}"
        )


if __name__ == "__main__":
    cli()
