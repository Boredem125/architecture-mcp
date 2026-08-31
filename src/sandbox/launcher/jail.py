"""Filesystem jail for launched CLI apps.

Two modes:
- Enforced: NTFS ACLs + dedicated user restrict access to jail folder only.
  Requires one-time admin setup.
- Monitored: cwd=jail + Job Object, with a filesystem watcher flagging
  out-of-jail access. Weaker but works without admin.
"""
from __future__ import annotations

import os
import platform
import uuid
from enum import StrEnum
from pathlib import Path

import structlog

logger = structlog.get_logger(__name__)


class JailMode(StrEnum):
    ENFORCED = "enforced"
    MONITORED = "monitored"


class JailManager:
    """Creates and manages jailed working directories."""

    def __init__(
        self,
        jail_root: str = "./jails",
        jail_user: str = "",
        enforce: bool = False,
    ) -> None:
        self._jail_root = Path(jail_root).resolve()
        self._jail_user = jail_user
        self._enforce = enforce and bool(jail_user)

    @property
    def mode(self) -> JailMode:
        return JailMode.ENFORCED if self._enforce else JailMode.MONITORED

    def create_jail(self, session_id: str) -> Path:
        """Create a jail directory for the given session."""
        jail_dir = self._jail_root / session_id
        jail_dir.mkdir(parents=True, exist_ok=True)

        sandbox_logs = jail_dir / ".sandbox_logs"
        sandbox_logs.mkdir(exist_ok=True)

        broker_out = jail_dir / "broker_out"
        broker_out.mkdir(exist_ok=True)

        trash = jail_dir / ".trash"
        trash.mkdir(exist_ok=True)

        if self._enforce and platform.system() == "Windows":
            self._apply_ntfs_acl(jail_dir)

        logger.info(
            "jail.created",
            session_id=session_id,
            path=str(jail_dir),
            mode=self.mode,
        )
        return jail_dir

    def validate_path(self, jail_dir: Path, target: str) -> bool:
        """Check if target path is within the jail boundary."""
        from sandbox.fs.containment import is_contained

        return is_contained(jail_dir, target)

    def destroy_jail(self, session_id: str) -> None:
        """Remove a jail directory (best-effort)."""
        jail_dir = self._jail_root / session_id
        if jail_dir.exists():
            import shutil
            try:
                shutil.rmtree(jail_dir)
                logger.info("jail.destroyed", session_id=session_id)
            except OSError as e:
                logger.warning(
                    "jail.destroy_failed",
                    session_id=session_id,
                    error=str(e),
                )

    def generate_setup_script(self) -> str:
        """Generate a PowerShell script for one-time admin setup of the jail user + ACLs."""
        if not self._jail_user:
            return "# No jail user configured. Set LAUNCHER_JAIL_USER first."

        return f"""# Run this ONCE as Administrator to set up the jail user.
# This creates a low-privilege local user and grants it access only to the jail root.

$user = "{self._jail_user}"
$jailRoot = "{self._jail_root}"

# Create the local user (no password expiry, cannot change password)
if (-not (Get-LocalUser -Name $user -ErrorAction SilentlyContinue)) {{
    $pwd = ConvertTo-SecureString -String ([System.Guid]::NewGuid().ToString()) -AsPlainText -Force
    New-LocalUser -Name $user -Password $pwd -PasswordNeverExpires -UserMayNotChangePassword
    Write-Host "Created user: $user"
}} else {{
    Write-Host "User already exists: $user"
}}

# Ensure jail root exists
New-Item -ItemType Directory -Force -Path $jailRoot | Out-Null

# Set NTFS ACL: only $user + SYSTEM + Administrators have access
$acl = Get-Acl $jailRoot
$acl.SetAccessRuleProtection($true, $false)  # disable inheritance
$acl.Access | ForEach-Object {{ $acl.RemoveAccessRule($_) }} | Out-Null
$acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
    $user, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")))
$acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
    "SYSTEM", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")))
$acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
    "Administrators", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")))
Set-Acl $jailRoot $acl
Write-Host "ACL set on $jailRoot — only $user, SYSTEM, and Administrators have access."
Write-Host "Done. Set LAUNCHER_ENFORCE_JAIL=true and LAUNCHER_JAIL_USER=$user to enable enforced mode."
"""

    def _apply_ntfs_acl(self, jail_dir: Path) -> None:
        """Apply restrictive NTFS ACLs to the jail directory (Windows only)."""
        import subprocess
        try:
            subprocess.run(
                [
                    "icacls", str(jail_dir),
                    "/grant:r", f"{self._jail_user}:(OI)(CI)F",
                    "/grant:r", "SYSTEM:(OI)(CI)F",
                    "/grant:r", "Administrators:(OI)(CI)F",
                    "/inheritance:r",
                ],
                capture_output=True,
                text=True,
                check=True,
                timeout=30,
            )
            logger.info("jail.acl_applied", path=str(jail_dir), user=self._jail_user)
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            logger.warning(
                "jail.acl_failed",
                path=str(jail_dir),
                error=str(e),
            )
