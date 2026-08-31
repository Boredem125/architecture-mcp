"""App-type to launch-command registry.

Maps each supported CLI app to its executable and default arguments.
Commands are overridable via LauncherSettings.app_commands.
"""
from __future__ import annotations

import shutil
from dataclasses import dataclass

import structlog

logger = structlog.get_logger(__name__)


@dataclass(slots=True, frozen=True)
class AppEntry:
    app_type: str
    display_name: str
    executable: str
    default_args: list[str]
    needs_api_key: bool = False
    api_key_env: str = ""


_BUILTIN_APPS: dict[str, AppEntry] = {
    "claude-code": AppEntry(
        app_type="claude-code",
        display_name="Claude Code",
        executable="claude",
        default_args=[],
    ),
    "codex": AppEntry(
        app_type="codex",
        display_name="OpenAI Codex CLI",
        executable="codex",
        default_args=[],
        needs_api_key=True,
        api_key_env="OPENAI_API_KEY",
    ),
    "ollama": AppEntry(
        app_type="ollama",
        display_name="Ollama",
        executable="ollama",
        default_args=["run", "llama3"],
    ),
    "antigravity": AppEntry(
        app_type="antigravity",
        display_name="Antigravity",
        executable="antigravity",
        default_args=[],
        needs_api_key=True,
        api_key_env="ANTIGRAVITY_API_KEY",
    ),
    "hermes": AppEntry(
        app_type="hermes",
        display_name="Hermes",
        executable="hermes",
        default_args=[],
        needs_api_key=True,
        api_key_env="HERMES_API_KEY",
    ),
    "openclaw": AppEntry(
        app_type="openclaw",
        display_name="OpenClaw",
        executable="openclaw",
        default_args=[],
        needs_api_key=True,
        api_key_env="OPENCLAW_API_KEY",
    ),
}


class AppRegistry:
    """Resolves app types to launch commands, with config overrides."""

    def __init__(self, overrides: dict[str, str] | None = None) -> None:
        self._overrides = overrides or {}

    def resolve(self, app_type: str) -> AppEntry:
        entry = _BUILTIN_APPS.get(app_type)
        if entry is None:
            raise ValueError(
                f"Unknown app type {app_type!r}. "
                f"Available: {', '.join(sorted(_BUILTIN_APPS))}"
            )

        override_cmd = self._overrides.get(app_type)
        if override_cmd:
            parts = override_cmd.split()
            return AppEntry(
                app_type=entry.app_type,
                display_name=entry.display_name,
                executable=parts[0],
                default_args=parts[1:],
                needs_api_key=entry.needs_api_key,
                api_key_env=entry.api_key_env,
            )
        return entry

    @staticmethod
    def _which(executable: str) -> str | None:
        """Resolve an executable, trying Windows launcher suffixes too.

        Node/npm CLIs (claude, codex, …) install as ``name.cmd`` on Windows,
        which a bare ``shutil.which('name')`` can miss depending on PATHEXT.
        """
        found = shutil.which(executable)
        if found:
            return found
        for suffix in (".cmd", ".exe", ".bat", ".ps1"):
            found = shutil.which(executable + suffix)
            if found:
                return found
        return None

    def find_executable(self, app_type: str) -> str | None:
        """Return the full path to the executable, or None if not found."""
        entry = self.resolve(app_type)
        return self._which(entry.executable)

    def list_available(self) -> list[AppEntry]:
        """Return entries for all apps whose executables are on PATH."""
        available = []
        for app_type in sorted(_BUILTIN_APPS):
            entry = self.resolve(app_type)
            if self._which(entry.executable):
                available.append(entry)
        return available

    def list_all(self) -> list[AppEntry]:
        return [self.resolve(t) for t in sorted(_BUILTIN_APPS)]

    def register_custom(
        self,
        app_type: str,
        display_name: str,
        executable: str,
        default_args: list[str] | None = None,
    ) -> None:
        _BUILTIN_APPS[app_type] = AppEntry(
            app_type=app_type,
            display_name=display_name,
            executable=executable,
            default_args=default_args or [],
        )
