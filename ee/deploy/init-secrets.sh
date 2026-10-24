#!/usr/bin/env python3
"""ee/deploy/init-secrets.sh -- Generate random secrets for the compose stack.

Writes secret files into /opt/secrets/ (mounted from ./secrets/).
Each file is chowned to the uid:gid of the service(s) that consume it
and set to 0400 (single consumer) or 0440 (shared via group).
Refuses to overwrite existing files.

Also generates pre-composed database URL files (pg_owner_url, pg_app_url)
so that services can point AGG_DATABASE_URL_FILE directly at a secret
without shell interpolation at runtime.

Requires CAP_CHOWN and CAP_DAC_OVERRIDE (the container runs as root with
cap_drop ALL + cap_add CHOWN, DAC_OVERRIDE; DAC_OVERRIDE lets it create
files in a secrets/ dir owned by the host user on native Linux).  Root is needed because non-root ambient capabilities
are not reliably delivered on all Docker runtimes (e.g. Docker Desktop).

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
    "bundle_signer_key",
]

# Secrets that require hex-encoded 32-byte Ed25519 seeds
# (not URL-safe tokens).  bundles.py reads hex or raw-32.
_HEX_SEED_SECRETS = {"bundle_signer_key"}

# ---------------------------------------------------------------------------
# Per-consumer ownership table.
#
# Each secret is owned by the uid:gid of its consumer service and set to
# the most restrictive mode that still allows access:
#   0o400  -- single consumer (owner-read only)
#   0o440  -- shared via a common gid (owner-read + group-read)
#
# Shared gid 30000 is added to api and keycloak via group_add in
# compose.yml so both can read oidc_client_secret.
#
#   secret                  uid:gid       mode  consumer(s)
#   ─────────────────────── ───────────── ──── ─────────────────
#   pg_superuser_password   999:999       0400 postgres
#   pg_owner_password       999:999       0400 postgres (00-roles.sh)
#   pg_app_password         999:999       0400 postgres (00-roles.sh)
#   pg_owner_url            10001:10001   0400 migrate, migrate-demo
#   pg_app_url              10001:10001   0400 api
#   oidc_client_secret      65534:30000   0440 api + keycloak (shared gid)
#   server_signing_key      10001:10001   0400 api
# ---------------------------------------------------------------------------
OWNERSHIP: dict[str, tuple[int, int, int]] = {
    "pg_superuser_password": (999,   999,   0o400),
    "pg_owner_password":     (999,   999,   0o400),
    "pg_app_password":       (999,   999,   0o400),
    "pg_owner_url":          (10001, 10001, 0o400),
    "pg_app_url":            (10001, 10001, 0o400),
    "oidc_client_secret":    (65534, 30000, 0o440),
    "server_signing_key":    (10001, 10001, 0o400),
    "bundle_signer_key":     (10001, 10001, 0o400),
}

# Composed URL template -- host is the compose service name
_PG_URL_TEMPLATE = "postgresql+psycopg://{user}:{password}@postgres:5432/agg"


def _write_secret(path: Path, value: str) -> bool:
    """Write *value* to *path* with per-consumer ownership.

    Uses O_CREAT|O_EXCL so the create-and-set-mode is atomic -- no
    window where the file exists with a permissive mode.  Then sets
    the target mode (via fchmod while still owner) and ownership
    (via fchown, requires CAP_CHOWN).

    Returns False if the file already exists (not overwritten).
    """
    uid, gid, mode = OWNERSHIP[path.name]
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
        # Set target mode while we still own the file (root created it),
        # then transfer ownership.  fchown only needs CAP_CHOWN.
        os.fchmod(fd, mode)
        os.fchown(fd, uid, gid)
    finally:
        os.close(fd)
    print(f"  OK: {path.name} (uid={uid}, gid={gid}, mode={oct(mode)})")
    return True


def main() -> int:
    if not SECRETS_DIR.is_dir():
        print(f"ERROR: secrets directory {SECRETS_DIR} does not exist.", file=sys.stderr)
        return 1

    any_skipped = False

    # --- plain random secrets ---
    passwords: dict[str, str] = {}
    for name in SECRET_FILES:
        if name in _HEX_SEED_SECRETS:
            value = secrets.token_hex(32)  # 64 hex chars = 32-byte Ed25519 seed
        else:
            value = secrets.token_urlsafe(32)
        path = SECRETS_DIR / name
        if not _write_secret(path, value):
            any_skipped = True
            # Read existing value so composed URLs can still be built.
            # If the file has restricted ownership from a previous run,
            # this may fail -- delete and regenerate in that case.
            try:
                value = path.read_text(encoding="utf-8").strip()
            except PermissionError:
                print(
                    f"ERROR: {path.name} exists but is unreadable. "
                    f"Delete secrets/* (except .gitignore) and re-run.",
                    file=sys.stderr,
                )
                return 1
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
