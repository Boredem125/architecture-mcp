"""The escalation classifier — one function, all four triggers.

Given a tool call and the folder policy, return a four-state ``Verdict``:
``allow | observe | escalate | deny``. ``observe`` (audit-but-allow) is what
makes the noisy triggers (reads outside the folder) shippable without drowning
the human in prompts.

The classifier is pure and importable so it can be unit-tested table-driven,
independent of the hook plumbing. It never performs the escalation itself —
it only decides.

Trigger map (from the plan):

| Tool                              | Rule                                              |
|-----------------------------------|---------------------------------------------------|
| Bash, PowerShell                  | blocklist→deny, .sandbox→deny, allow_patterns→    |
|                                   | allow, else triggers.shell                        |
| Write/Edit/MultiEdit/NotebookEdit | deny_globs→deny, not contained→triggers.          |
|                                   | write_outside, contained→allow                    |
| Read/Glob/Grep                    | not contained & not allow_prefix→triggers.        |
|                                   | read_outside, else allow                          |
| WebFetch/WebSearch                | host in allow_hosts→allow, else triggers.network  |
| mcp__sandbox__*                   | always allow (never gate the escalation channel)  |
| mcp__*                            | triggers.network unless allowlisted               |
| anything else                     | unknown_tool_action (default allow)               |
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

from sandbox.connector.layout import FolderLayout
from sandbox.connector.policy import FolderPolicy
from sandbox.fs.containment import is_contained

_SHELL_TOOLS = {"Bash", "PowerShell"}
_WRITE_TOOLS = {"Write", "Edit", "MultiEdit", "NotebookEdit"}
_READ_TOOLS = {"Read", "Glob", "Grep"}
_NETWORK_TOOLS = {"WebFetch", "WebSearch"}


@dataclass
class Classification:
    """The classifier's verdict for one tool call."""

    verdict: str  # allow | observe | escalate | deny
    trigger: str  # shell | write_outside | read_outside | network | "" (allow)
    reason: str = ""
    reason_code: str = ""  # machine-readable: BLOCKLIST, SHELL, WRITE_OUTSIDE, ...
    # Payload the hook needs to act — e.g. the command to escalate, the target
    # path to snapshot, the URL to fetch.
    command: str = ""
    target_path: str = ""
    host: str = ""
    host_allowlisted: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)
    # Filled by the hook after risk scoring (kept here so it travels together).
    risk: dict[str, Any] = field(default_factory=dict)
    requires_dual: bool = False


def _shell_target_path(tool_input: dict[str, Any]) -> str:
    return tool_input.get("command", "") or ""


def _extract_target_path(tool_name: str, tool_input: dict[str, Any]) -> str:
    """Best-effort extraction of the file path a tool acts on."""
    for key in ("file_path", "path", "notebook_path"):
        if key in tool_input and tool_input[key]:
            return str(tool_input[key])
    if tool_name == "Glob":
        # Glob's `path` (dir to search) is the containment-relevant field.
        return str(tool_input.get("path", "") or "")
    return ""


def _extract_host(tool_input: dict[str, Any]) -> str:
    url = tool_input.get("url", "") or ""
    if not url:
        return ""
    try:
        parsed = urlparse(url if "://" in url else f"https://{url}")
        return parsed.hostname or ""
    except ValueError:
        return ""


def _host_allowed(host: str, allow_hosts: list[str]) -> bool:
    """Match host against allow_hosts, honoring a leading-dot suffix wildcard."""
    host = host.lower()
    for allowed in allow_hosts:
        a = allowed.lower().lstrip(".")
        if host == a or host.endswith("." + a):
            return True
    return False


def classify(
    tool_name: str,
    tool_input: dict[str, Any],
    policy: FolderPolicy,
    layout: FolderLayout,
    *,
    cwd: str | None = None,
    blocklist: Any = None,
) -> Classification:
    """Classify one tool call. Pure — decides, never acts."""
    base = cwd or str(layout.root)

    # Explicit tool denial always wins.
    if tool_name in policy.deny_tools:
        return Classification(
            "deny", "", reason=f"Tool {tool_name} is denied by policy.",
            reason_code="DENY_TOOL",
        )

    # The escalation channel is never gated — an infinite regress otherwise.
    if tool_name.startswith("mcp__sandbox__") or tool_name.startswith("mcp__sandbox_"):
        return Classification("allow", "", reason="sandbox MCP tool", reason_code="ALLOW")

    if tool_name in _SHELL_TOOLS:
        return _classify_shell(tool_input, policy, blocklist)

    if tool_name in _WRITE_TOOLS:
        return _classify_write(tool_name, tool_input, policy, layout, base)

    if tool_name in _READ_TOOLS:
        return _classify_read(tool_name, tool_input, policy, layout, base)

    if tool_name in _NETWORK_TOOLS:
        return _classify_network(tool_name, tool_input, policy)

    # Any other MCP tool → treat as network unless allowlisted.
    if tool_name.startswith("mcp__"):
        server = tool_name.split("__", 2)[1] if "__" in tool_name else ""
        if server in policy.network.allow_mcp_servers:
            return Classification("allow", "", reason=f"allowlisted MCP server {server}")
        return Classification(
            policy.triggers.network, "network",
            reason=f"MCP tool {tool_name} (server not allowlisted)",
        )

    # Unknown tool — default allow (TodoWrite, Task, AskUserQuestion, etc.).
    return Classification(
        policy.unknown_tool_action, "",
        reason=f"unknown tool {tool_name} → {policy.unknown_tool_action}",
    )


def _classify_shell(
    tool_input: dict[str, Any], policy: FolderPolicy, blocklist: Any
) -> Classification:
    command = _shell_target_path(tool_input)

    # 1. Hard blocklist (destructive commands that can never be approved).
    if blocklist is not None:
        try:
            blocked, why = blocklist.check(command)
            if blocked:
                return Classification(
                    "deny", "shell", reason=f"blocklisted: {why}",
                    reason_code="BLOCKLIST", command=command,
                )
        except Exception:  # noqa: BLE001 — blocklist must never crash the hook
            pass

    # 2. Self-protection deny patterns (.sandbox etc., re-injected each load).
    for pat in policy.shell.deny_patterns:
        if re.search(pat, command):
            return Classification(
                "deny", "shell",
                reason=f"command touches a protected path (pattern {pat!r})",
                reason_code="SANDBOX_PROTECT", command=command,
            )

    # 3. Allowlisted safe commands run silently.
    for pat in policy.shell.allow_patterns:
        if re.search(pat, command):
            return Classification("allow", "shell", reason="allowlisted",
                                  reason_code="ALLOW", command=command)

    # 4. Everything else → the configured shell trigger (default escalate).
    return Classification(
        policy.triggers.shell, "shell",
        reason="shell command requires approval",
        reason_code="SHELL", command=command,
    )


def _classify_write(
    tool_name: str,
    tool_input: dict[str, Any],
    policy: FolderPolicy,
    layout: FolderLayout,
    base: str,
) -> Classification:
    target = _extract_target_path(tool_name, tool_input)
    if not target:
        return Classification("allow", "", reason="no target path", metadata={"tool": tool_name})

    # deny_globs (includes the non-removable .sandbox/** and .git/hooks/**).
    denied_glob = _match_deny_glob(target, layout, policy.write.deny_globs, base)
    if denied_glob:
        return Classification(
            "deny", "write_outside",
            reason=f"write to protected path (glob {denied_glob!r})",
            reason_code="WRITE_PROTECTED", target_path=target,
        )

    if is_contained(layout.root, target, base=base):
        return Classification(
            "allow", "", reason="write inside folder",
            reason_code="ALLOW", target_path=target,
        )

    # Out-of-folder write → the configured trigger, with the pointer.
    verdict = policy.triggers.write_outside
    reason = (
        f"write outside the folder ({target}). "
        "Use the sandbox MCP tool request_path_access to have the sandbox "
        "perform the write on your behalf."
    )
    return Classification(verdict, "write_outside", reason=reason,
                          reason_code="WRITE_OUTSIDE", target_path=target)


def _classify_read(
    tool_name: str,
    tool_input: dict[str, Any],
    policy: FolderPolicy,
    layout: FolderLayout,
    base: str,
) -> Classification:
    target = _extract_target_path(tool_name, tool_input)
    if not target:
        # Grep/Glob without an explicit path search the folder — fine.
        return Classification("allow", "", reason="in-folder search")

    if is_contained(layout.root, target, base=base):
        return Classification("allow", "", reason="read inside folder", target_path=target)

    # Check read allow_prefixes (e.g. a shared monorepo sibling).
    for prefix in policy.read.allow_prefixes:
        if is_contained(prefix, target, base=base) or _normstarts(target, prefix):
            return Classification(
                "allow", "", reason=f"read under allowed prefix {prefix}",
                target_path=target,
            )

    verdict = policy.triggers.read_outside
    return Classification(
        verdict, "read_outside",
        reason=f"read outside the folder ({target})",
        reason_code="READ_OUTSIDE", target_path=target,
    )


def _classify_network(
    tool_name: str, tool_input: dict[str, Any], policy: FolderPolicy
) -> Classification:
    if tool_name == "WebSearch":
        if policy.network.allow_search:
            return Classification("allow", "", reason="search allowed", reason_code="ALLOW")
        return Classification(
            policy.triggers.network, "network", reason="web search requires approval",
            reason_code="NETWORK",
        )

    host = _extract_host(tool_input)
    if host and _host_allowed(host, policy.network.allow_hosts):
        return Classification("allow", "", reason=f"host {host} allowlisted",
                              reason_code="ALLOW", host=host, host_allowlisted=True)

    return Classification(
        policy.triggers.network, "network",
        reason=f"network access to {host or 'unknown host'} requires approval",
        reason_code="NETWORK", host=host,
        metadata={"url": tool_input.get("url", "")},
    )


def _match_deny_glob(
    target: str, layout: FolderLayout, deny_globs: list[str], base: str
) -> str | None:
    """Return the first deny glob that matches *target* (relative to root)."""
    from fnmatch import fnmatch
    from pathlib import Path

    # Compute a path relative to root for glob matching, if possible.
    try:
        abs_target = Path(target)
        if not abs_target.is_absolute():
            abs_target = Path(base) / abs_target
        abs_target = abs_target.resolve(strict=False)
        rel = abs_target.relative_to(Path(layout.root).resolve(strict=False))
        rel_str = str(rel).replace("\\", "/")
    except (ValueError, OSError):
        rel_str = target.replace("\\", "/")

    for glob in deny_globs:
        g = glob.replace("\\", "/")
        # fnmatch doesn't treat ** specially; approximate by also trying a
        # prefix match for a trailing /** pattern.
        if fnmatch(rel_str, g):
            return glob
        if g.endswith("/**"):
            base_g = g[:-3]
            if rel_str == base_g or rel_str.startswith(base_g + "/"):
                return glob
    return None


def _normstarts(target: str, prefix: str) -> bool:
    import os

    return os.path.normcase(os.path.abspath(target)).startswith(
        os.path.normcase(os.path.abspath(prefix))
    )
