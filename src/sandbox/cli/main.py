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

# Sync commands (enroll / sync / unenroll / signer approve|deny).
from sandbox.cli.sync_cmds import register as _register_sync

_register_sync(cli)


@cli.command()
@click.option("--host", default="127.0.0.1", help="Bind host (non-loopback needs both API tokens set)")
@click.option("--port", default=8000, type=int, help="Bind port")
@click.option("--reload", is_flag=True, help="Enable auto-reload")
@click.option("--workers", default=1, type=int, help="Number of workers")
@click.option("--root", "roots", multiple=True, type=click.Path(file_okay=False),
              help="A project folder the connector API may serve (repeatable; or "
                   "SANDBOX_CONNECTOR_ROOTS). With none, every connector call is refused (403).")
def serve(host: str, port: int, reload: bool, workers: int, roots: tuple[str, ...]) -> None:
    """Start the sandbox API server."""
    # Do not import sandbox.api.app here: it builds the app at import time and would
    # read the roots before they are set below (every connector call would be 403).
    ROOTS_ENV = "SANDBOX_CONNECTOR_ROOTS"  # same value as sandbox.api.app.ROOTS_ENV
    from sandbox.api.auth import APPROVER_ENV, check_bind, ensure_tokens

    # Through the environment, because uvicorn starts the app by import string
    # (and workers are separate processes).
    configured = [r for r in os.environ.get(ROOTS_ENV, "").split(os.pathsep) if r.strip()]
    configured += [os.path.realpath(r) for r in roots]
    if configured:
        os.environ[ROOTS_ENV] = os.pathsep.join(dict.fromkeys(configured))
    else:
        click.echo(f"Warning: no project folder is served; every connector call will be refused. "
                   f"Pass --root PATH or set {ROOTS_ENV}.", err=True)

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
