"""Per-folder policy model, load/save, and the shipped defaults.

``FolderPolicy`` is a plain pydantic ``BaseModel`` (file-driven), distinct
from the process-level ``BaseSettings`` classes in ``sandbox.config``.

The load-bearing security property lives in :func:`load_policy`: the entries
that protect ``.sandbox/`` from the agent are re-injected on every load, so
an agent that gets denied cannot simply edit ``policy.json`` to allow itself.
"""
from __future__ import annotations

import json
from pathlib import Path

from pydantic import BaseModel, Field

# Verdicts a trigger can carry — a four-state enum, not a boolean. `observe`
# (audit-but-allow) is what makes the noisy triggers shippable.
VERDICTS = ("allow", "observe", "escalate", "deny")

# Non-removable protections re-injected on every load.
_PROTECT_WRITE_GLOBS = (".sandbox/**", ".git/hooks/**")
_PROTECT_SHELL_PATTERNS = (r"\.sandbox",)


class ShellPolicy(BaseModel):
    allow_patterns: list[str] = Field(
        default_factory=lambda: [
            r"^git (status|diff|log|show|branch|rev-parse)\b",
            r"^(npm|pnpm|yarn) (run|test|ci)\b",
            r"^python -m pytest\b",
            r"^(ls|dir|pwd|cd|cat|type|echo|which|where)\b",
        ]
    )
    deny_patterns: list[str] = Field(default_factory=list)
    blocklist_action: str = "deny"
    exec_timeout_seconds: int = 120


class ReadPolicy(BaseModel):
    allow_prefixes: list[str] = Field(default_factory=list)
    deny_globs: list[str] = Field(default_factory=list)


class WritePolicy(BaseModel):
    allow_prefixes: list[str] = Field(default_factory=list)
    deny_globs: list[str] = Field(default_factory=list)


class NetworkPolicy(BaseModel):
    allow_hosts: list[str] = Field(
        default_factory=lambda: [
            "registry.npmjs.org",
            "pypi.org",
            "files.pythonhosted.org",
        ]
    )
    allow_search: bool = False
    allow_mcp_servers: list[str] = Field(default_factory=list)


class ScanPolicy(BaseModel):
    ignore_dirs: list[str] = Field(
        default_factory=lambda: [
            ".git", "node_modules", ".venv", "venv", "__pycache__",
            ".pytest_cache", ".mypy_cache", ".ruff_cache", "dist", "build",
            "target", ".next", ".sandbox", ".sandbox_logs", ".trash",
            "broker_out",
        ]
    )
    max_file_bytes: int = 10 * 1024 * 1024
    preserve_originals: bool = True


class OutputPolicy(BaseModel):
    max_chars: int = 20000
    scrub_secrets: bool = True


class TrustedFile(BaseModel):
    """A file a human reviewed; trusted only while its content hash still matches."""

    path: str  # relative to the folder root, forward slashes
    sha256: str
    reviewer: str
    reason: str
    approved_at: float


class SemanticPolicy(BaseModel):
    """Intent-aware checks via a local jev-os service (``jevos serve``).

    Off by default. The layer can only add scrutiny: if the service is down or
    slow, the gateway behaves exactly as it does without it.
    """

    enabled: bool = False
    url: str = "http://127.0.0.1:8321"
    # Name of the env var holding the jev-os API key — never the key itself,
    # since policy.json lives in the workspace.
    api_key_env: str = "JEVOS_API_KEY"
    # Whole-call budget. Output is scored sentence by sentence, which took
    # ~2 s for a short README on a laptop CPU, so this is generous.
    timeout_seconds: float = 8.0
    threshold: float = 0.5
    # Optional fast screen: a second service (e.g. the xsmall model) scores
    # every sentence first, and only those at or above screen_threshold are
    # re-scored by the main service. Empty = off. If the screen fails, the
    # main service scores everything, as without it.
    screen_url: str = ""
    # Recall-oriented: a sentence dropped here never reaches the main model.
    screen_threshold: float = 0.2
    # Tools whose *output* is untrusted content to scan (fnmatch patterns).
    scan_tools: list[str] = Field(
        default_factory=lambda: ["WebFetch", "WebSearch", "Read", "Bash", "PowerShell", "mcp__*"]
    )
    max_scan_chars: int = 6000
    # After an injection is seen, these triggers need a human even if allowlisted.
    taint_ttl_seconds: int = 900
    taint_escalates: list[str] = Field(default_factory=lambda: ["shell", "network", "write_outside"])
    # Reviewed instruction files (e.g. AGENTS.md) that are not scanned while
    # their content is byte-for-byte what the reviewer approved.
    trusted_files: list[TrustedFile] = Field(default_factory=list)
    # Path to a governance policy (plain-language clauses); empty = none.
    # Evaluated on escalated shell commands; clauses only raise scrutiny.
    governance_policy: str = ""


class TriggerPolicy(BaseModel):
    shell: str = "escalate"
    write_outside: str = "deny"
    network: str = "escalate"
    read_outside: str = "observe"


class FolderPolicy(BaseModel):
    version: int = 1
    mode: str = "enforce"
    auto_allow: bool = False
    fail_mode: str = "closed"
    escalation_timeout_seconds: int = 300
    unknown_tool_action: str = "allow"
    deny_tools: list[str] = Field(default_factory=list)

    triggers: TriggerPolicy = Field(default_factory=TriggerPolicy)
    shell: ShellPolicy = Field(default_factory=ShellPolicy)
    read: ReadPolicy = Field(default_factory=ReadPolicy)
    write: WritePolicy = Field(default_factory=WritePolicy)
    network: NetworkPolicy = Field(default_factory=NetworkPolicy)
    scan: ScanPolicy = Field(default_factory=ScanPolicy)
    output: OutputPolicy = Field(default_factory=OutputPolicy)
    semantic: SemanticPolicy = Field(default_factory=SemanticPolicy)

    def _inject_protections(self) -> None:
        """Ensure the self-protection rules are present (non-removable)."""
        for g in _PROTECT_WRITE_GLOBS:
            if g not in self.write.deny_globs:
                self.write.deny_globs.append(g)
        for p in _PROTECT_SHELL_PATTERNS:
            if p not in self.shell.deny_patterns:
                self.shell.deny_patterns.append(p)


def default_policy() -> FolderPolicy:
    p = FolderPolicy()
    p._inject_protections()
    return p


def load_policy(path: str | Path) -> FolderPolicy:
    """Load policy from *path*, re-injecting the non-removable protections.

    A missing or malformed file yields the safe defaults rather than raising —
    the hook's fail-closed behavior is a separate, later gate.
    """
    p = Path(path)
    if not p.exists():
        return default_policy()
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        policy = FolderPolicy.model_validate(data)
    except (json.JSONDecodeError, ValueError):
        return default_policy()
    policy._inject_protections()
    return policy


def save_policy(policy: FolderPolicy, path: str | Path) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    policy._inject_protections()
    p.write_text(
        json.dumps(policy.model_dump(), indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
