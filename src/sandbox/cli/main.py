from __future__ import annotations

import os

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
@click.option("--host", default="127.0.0.1", help="Bind host (non-loopback needs both API tokens set)")
@click.option("--port", default=8000, type=int, help="Bind port")
@click.option("--reload", is_flag=True, help="Enable auto-reload")
@click.option("--workers", default=1, type=int, help="Number of workers")
def serve(host: str, port: int, reload: bool, workers: int) -> None:
    """Start the sandbox API server."""
    from sandbox.api.auth import APPROVER_ENV, check_bind, ensure_tokens

    check_bind(host)
    generated = not os.environ.get(APPROVER_ENV)
    _, approver = ensure_tokens()
    if generated:
        # Shown once, on the operator's console (like Jupyter's token); never logged.
        click.echo(f"Approver token generated for this run. Dashboard: http://{host}:{port}/?token={approver}")
    uvicorn.run(
        "sandbox.api.app:app",
        host=host,
        port=port,
        reload=reload,
        workers=workers,
        log_level="info",
    )


if __name__ == "__main__":
    cli()
