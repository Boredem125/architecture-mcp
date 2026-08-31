"""Command blocklist per AGENT_04 spec.

Maintains a library of dangerous command patterns and detects
obfuscation techniques used to bypass simple string matching.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path


# ---------------------------------------------------------------------------
# Blocklist entry definition
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class _BlocklistEntry:
    """A single blocklist rule with pattern and explanation."""

    pattern: re.Pattern[str]
    reason: str
    category: str


# ---------------------------------------------------------------------------
# Built-in blocklist patterns
# ---------------------------------------------------------------------------

_BUILTIN_ENTRIES: list[_BlocklistEntry] = [
    # Destructive filesystem operations
    _BlocklistEntry(
        pattern=re.compile(r"rm\s+(-[a-zA-Z]*f[a-zA-Z]*\s+)?(-[a-zA-Z]*r[a-zA-Z]*\s+)?/\s*$|rm\s+-[a-zA-Z]*r[a-zA-Z]*f[a-zA-Z]*\s+/\s*$|rm\s+-rf\s+/", re.IGNORECASE),
        reason="Recursive forced deletion of root filesystem",
        category="filesystem_destruction",
    ),
    _BlocklistEntry(
        pattern=re.compile(r"\bformat\s+[A-Za-z]:", re.IGNORECASE),
        reason="Disk format command",
        category="filesystem_destruction",
    ),
    _BlocklistEntry(
        pattern=re.compile(r"\bmkfs\b", re.IGNORECASE),
        reason="Filesystem creation (destructive to existing data)",
        category="filesystem_destruction",
    ),
    _BlocklistEntry(
        pattern=re.compile(r"\bdd\s+if=/dev/(zero|urandom|random)\b", re.IGNORECASE),
        reason="Low-level disk overwrite with dd",
        category="filesystem_destruction",
    ),

    # SQL destruction
    _BlocklistEntry(
        pattern=re.compile(r"\bDROP\s+(TABLE|DATABASE|SCHEMA)\b", re.IGNORECASE),
        reason="SQL DROP command (destructive)",
        category="sql_destruction",
    ),
    _BlocklistEntry(
        pattern=re.compile(r"\bTRUNCATE\s+TABLE\b", re.IGNORECASE),
        reason="SQL TRUNCATE command (destructive)",
        category="sql_destruction",
    ),

    # Remote code execution / download-and-execute
    _BlocklistEntry(
        pattern=re.compile(r"\bcurl\b.*\|\s*\b(ba)?sh\b", re.IGNORECASE),
        reason="Download and execute via curl pipe to shell",
        category="remote_code_execution",
    ),
    _BlocklistEntry(
        pattern=re.compile(r"\bwget\b.*\|\s*\b(ba)?sh\b", re.IGNORECASE),
        reason="Download and execute via wget pipe to shell",
        category="remote_code_execution",
    ),
    _BlocklistEntry(
        pattern=re.compile(
            r"\bcurl\b.*-[a-zA-Z]*o[a-zA-Z]*\s+\S+.*&&.*\b(ba)?sh\b",
            re.IGNORECASE,
        ),
        reason="Download-then-execute pattern",
        category="remote_code_execution",
    ),

    # Reverse shells
    _BlocklistEntry(
        pattern=re.compile(
            r"\bbash\s+-i\s+>&\s*/dev/tcp/",
            re.IGNORECASE,
        ),
        reason="Bash reverse shell via /dev/tcp",
        category="reverse_shell",
    ),
    _BlocklistEntry(
        pattern=re.compile(
            r"\bnc\s+(-[a-zA-Z]*e[a-zA-Z]*\s+|--exec\s+)",
            re.IGNORECASE,
        ),
        reason="Netcat reverse shell with exec",
        category="reverse_shell",
    ),
    _BlocklistEntry(
        pattern=re.compile(
            r"\bpython[23]?\s+-c\s+.*socket.*connect",
            re.IGNORECASE,
        ),
        reason="Python reverse shell",
        category="reverse_shell",
    ),
    _BlocklistEntry(
        pattern=re.compile(
            r"\bperl\s+-e\s+.*socket.*INET",
            re.IGNORECASE,
        ),
        reason="Perl reverse shell",
        category="reverse_shell",
    ),

    # Base64 decode piping
    _BlocklistEntry(
        pattern=re.compile(
            r"\bbase64\s+(-d|--decode)\b.*\|\s*\b(ba)?sh\b",
            re.IGNORECASE,
        ),
        reason="Base64 decode piped to shell execution",
        category="obfuscated_execution",
    ),
    _BlocklistEntry(
        pattern=re.compile(
            r"\becho\b.*\|\s*base64\s+(-d|--decode)\b.*\|\s*\b(ba)?sh\b",
            re.IGNORECASE,
        ),
        reason="Echo + base64 decode piped to shell",
        category="obfuscated_execution",
    ),

    # Dangerous permissions
    _BlocklistEntry(
        pattern=re.compile(r"\bchmod\s+777\b", re.IGNORECASE),
        reason="World-writable permissions (chmod 777)",
        category="dangerous_permissions",
    ),

    # Fork bombs
    _BlocklistEntry(
        pattern=re.compile(r":\(\)\s*\{\s*:\|\s*:&\s*\}\s*;?\s*:"),
        reason="Bash fork bomb",
        category="denial_of_service",
    ),
    _BlocklistEntry(
        pattern=re.compile(r"\bfork\b.*\bwhile\s+true\b|\bwhile\s+true.*\bfork\b", re.IGNORECASE),
        reason="Fork bomb pattern",
        category="denial_of_service",
    ),
]


# ---------------------------------------------------------------------------
# Obfuscation detection patterns
# ---------------------------------------------------------------------------

_OBFUSCATION_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # $() command substitution used to build commands dynamically
    (
        re.compile(r"\$\([^)]+\)"),
        "Command substitution via $() detected",
    ),
    # Backtick substitution
    (
        re.compile(r"`[^`]+`"),
        "Backtick command substitution detected",
    ),
    # Heredoc injection (<<EOF or <<'EOF' followed by suspicious content)
    (
        re.compile(r"<<-?\s*['\"]?\w+['\"]?", re.IGNORECASE),
        "Heredoc injection detected",
    ),
    # Base64 encoded command reconstruction
    (
        re.compile(
            r"\$\(echo\s+[A-Za-z0-9+/=]+\s*\|\s*base64\s+(-d|--decode)\)",
            re.IGNORECASE,
        ),
        "Base64-encoded command reconstruction detected",
    ),
    # Variable-based command building (e.g., a=r; b=m; $a$b)
    (
        re.compile(r"\$[a-zA-Z_]\w*\$[a-zA-Z_]\w*"),
        "Variable-based command concatenation detected",
    ),
    # eval with variable expansion
    (
        re.compile(r"\beval\s+", re.IGNORECASE),
        "eval-based execution detected",
    ),
]


class CommandBlocklist:
    """Checks commands against a blocklist of dangerous patterns.

    Combines a built-in library of dangerous command patterns with
    obfuscation detection.  Additional patterns can be loaded from
    an external JSON file.
    """

    def __init__(self) -> None:
        self._entries: list[_BlocklistEntry] = list(_BUILTIN_ENTRIES)
        self._custom_entries: list[_BlocklistEntry] = []

    def check(self, command: str, parameters: dict[str, object] | None = None) -> tuple[bool, str]:
        """Check whether *command* matches any blocklist pattern.

        Args:
            command: The command string to evaluate.
            parameters: Optional parameter dict.  Parameter values are
                also scanned for embedded dangerous patterns.

        Returns:
            A 2-tuple ``(is_blocked, reason)``.  When the command is
            allowed, *reason* is an empty string.
        """
        # Normalise the command for matching.
        full_text = command
        if parameters:
            # Flatten parameter values into the search text.
            param_values = " ".join(str(v) for v in parameters.values())
            full_text = f"{command} {param_values}"

        # 1. Check direct blocklist patterns.
        for entry in self._all_entries:
            if entry.pattern.search(full_text):
                return (True, f"[{entry.category}] {entry.reason}")

        # 2. Check obfuscation techniques.
        obfuscation_reason = self._check_obfuscation(full_text)
        if obfuscation_reason:
            return (True, f"[obfuscation] {obfuscation_reason}")

        return (False, "")

    def reload(self, blocklist_path: str) -> None:
        """Reload custom blocklist entries from *blocklist_path*.

        The file should be JSON with a top-level ``"patterns"`` array,
        each element an object with ``"regex"``, ``"reason"``, and
        optional ``"category"`` keys.

        Raises:
            FileNotFoundError: If the path does not exist.
            ValueError: If the JSON is malformed or entries are invalid.
        """
        path = Path(blocklist_path)
        raw = path.read_text(encoding="utf-8")
        data = json.loads(raw)

        patterns_list = data.get("patterns")
        if not isinstance(patterns_list, list):
            raise ValueError(
                f"Expected 'patterns' array in {blocklist_path}, "
                f"got {type(patterns_list).__name__}"
            )

        new_entries: list[_BlocklistEntry] = []
        for idx, entry_data in enumerate(patterns_list):
            regex_str = entry_data.get("regex")
            reason = entry_data.get("reason", "Custom blocklist match")
            category = entry_data.get("category", "custom")

            if not regex_str or not isinstance(regex_str, str):
                raise ValueError(
                    f"Entry {idx} in {blocklist_path} missing valid 'regex' field"
                )

            try:
                compiled = re.compile(regex_str, re.IGNORECASE)
            except re.error as exc:
                raise ValueError(
                    f"Invalid regex in entry {idx} of {blocklist_path}: {exc}"
                ) from exc

            new_entries.append(
                _BlocklistEntry(pattern=compiled, reason=reason, category=category)
            )

        self._custom_entries = new_entries

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    @property
    def _all_entries(self) -> list[_BlocklistEntry]:
        """Combined built-in and custom entries."""
        return self._entries + self._custom_entries

    @staticmethod
    def _check_obfuscation(text: str) -> str:
        """Return a reason string if obfuscation is detected, else empty."""
        for pattern, reason in _OBFUSCATION_PATTERNS:
            if pattern.search(text):
                return reason
        return ""
