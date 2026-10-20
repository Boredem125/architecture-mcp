#!/usr/bin/env python3
"""ee/deploy/init-secrets.sh -- Generate random secrets for the compose stack.

Writes secret files into /opt/secrets/ (mounted from ./secrets/) with
mode 0600.  Refuses to overwrite existing files.

Also generates pre-composed database URL files (pg_owner_url, pg_app_url)
so that services can point AGG_DATABASE_URL_FILE directly at a secret
without shell interpolation at runtime.

Run via the init-secrets compose service:
    docker compose --profile init run --rm init-secrets
"""
from __future__ import annotations

import os
import secrets
import stat
import sys
from pathlib import Path

SECRETS_DIR = Path("/opt/secrets")

# Secret names -- plain random tokens
SECRET_FILES = [
    "pg_superuser_password",
    "pg_owner_password",
    "pg_app_password",
    "oidc_client_secret",
    "server_signing_key",
]

# Composed URL template -- host is the compose service name
_PG_URL_TEMPLATE = "postgresql+psycopg://{user}:{password}@postgres:5432/agg"


def _write_secret(path: Path, value: str) -> bool:
    """Write *value* to *path* with mode 0600.  Returns False if skipped.

    Uses O_CREAT|O_EXCL so the create-and-set-mode is atomic -- no
    window where the file exists with a permissive mode.
    """
    try:
        fd = os.open(
            str(path),
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
    except FileExistsError:
        print(f"SKIP: {path.name} already exists (not overwriting).")
        return False
    try:
        os.write(fd, value.encode("utf-8"))
    finally:
        os.close(fd)
    print(f"  OK: {path.name}")
    return True


def main() -> int:
    if not SECRETS_DIR.is_dir():
        print(f"ERROR: secrets directory {SECRETS_DIR} does not exist.", file=sys.stderr)
        return 1

    any_skipped = False

    # --- plain random secrets ---
    passwords: dict[str, str] = {}
    for name in SECRET_FILES:
        value = secrets.token_urlsafe(32)
        path = SECRETS_DIR / name
        if not _write_secret(path, value):
            any_skipped = True
            # Read existing value so composed URLs can still be built
            value = path.read_text(encoding="utf-8").strip()
        passwords[name] = value

    # --- composed database URLs ---
    owner_url = _PG_URL_TEMPLATE.format(
        user="agg_owner", password=passwords["pg_owner_password"],
    )
    if not _write_secret(SECRETS_DIR / "pg_owner_url", owner_url):
        any_skipped = True

    app_url = _PG_URL_TEMPLATE.format(
        user="agg_app", password=passwords["pg_app_password"],
    )
    if not _write_secret(SECRETS_DIR / "pg_app_url", app_url):
        any_skipped = True

    if any_skipped:
        print("\nSome secrets already existed and were not overwritten.")
    else:
        print("\nAll secrets generated.")

    print(
        "\nNext steps:\n"
        "  1. docker compose up -d\n"
        "  2. docker compose logs migrate   # read the one-time setup code\n"
        "  3. Open https://localhost in a browser and enter the setup code.\n"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
