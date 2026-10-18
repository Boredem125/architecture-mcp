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
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from sandbox.connector.layout import FolderLayout
from sandbox.connector.policy import FolderPolicy
from sandbox.fs.containment import is_contained

SANDBOX_MCP_PREFIX = "mcp__sandbox__"

# Non-removable protections enforced here in code, whatever policy.json says
# (a hand-edited policy can omit deny_globs / deny_patterns entirely).
# Path component sequences, matched against shell words after quote removal,
# glob matching and case folding, so `.sand*`, `.sand''box` and `.SANDBOX` all
# hit `.sandbox`. They are never matched by regex on the command string.
_PROTECTED_SEQS: tuple[tuple[str, ...], ...] = ((".sandbox",), (".git", "hooks"))
# Never readable by the agent: reviewer signing seeds (and, later, device keys).
_KEY_SEQS: tuple[tuple[str, ...], ...] = (
    (".sandbox", "state", "keys"), (".sandbox", "state", "device"),
)
# Agent configuration: writing these could add an MCP server, rename one to
# borrow the sandbox's trust, or switch the hooks off.
_AGENT_CONFIG_GLOBS = (".mcp.json", ".claude/settings*.json")
# Approver CLI subcommands: approvals come from a human's terminal only.
_APPROVER_SUBCOMMANDS = frozenset(
    {"approve", "deny", "watch", "grant", "serve", "approve-change"}
)
# `2>&1`, `>/dev/null`: redirects that do not write to a file.
_BENIGN_REDIRECT_RE = re.compile(
    r"[012]?>>?&[012-](?![\w./\\~$-])|[012]?>>?\s*(?:/dev/null|nul|\$null)(?![\w./\-])", re.I
)
_SHORT_NAME_RE = re.compile(r"sandbo~\d+")  # 8.3 alias of .sandbox on NTFS

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
    # Exact prefix only: a server named "sandbox_evil" is a third-party server.
    if tool_name.startswith(SANDBOX_MCP_PREFIX):
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

    # 2a/2b. Non-removable, in code: a word that names (or globs onto) a
    # protected path, or any segment that runs the approver CLI (approvals
    # come from a human's terminal, never the agent's shell, not even escalated).
    denied = shell_deny_reason(command)
    if denied:
        return Classification(
            "deny", "shell", reason=denied[1], reason_code=denied[0], command=command,
        )

    # 2c. Self-protection deny patterns (.sandbox etc., re-injected each load).
    for pat in policy.shell.deny_patterns:
        if re.search(pat, command):
            return Classification(
                "deny", "shell",
                reason=f"command touches a protected path (pattern {pat!r})",
                reason_code="SANDBOX_PROTECT", command=command,
            )

    # 3. Allowlisted safe commands run silently, but only when the whole
    # command is safe: no substitution, redirect or expansion, and every
    # `;` `&&` `||` `|` `&` newline separated segment matches the allowlist.
    # An anchored pattern like ^ls\b would otherwise allow `ls && deploy`.
    if command_allowlisted(command, policy.shell.allow_patterns):
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

    # Non-removable, in code: .sandbox/**, .git/hooks/** and the agent config files.
    protected = _protected_write(target, layout, base)
    if protected:
        return Classification(
            "deny", "write_outside",
            reason=f"write to protected path ({protected})",
            reason_code="WRITE_PROTECTED", target_path=target,
        )

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
    # Non-removable: signing seeds are never readable, and .sandbox/ is never
    # searched (a Grep or Glob there reaches the seeds).
    keys_hit = _reads_keys(tool_name, tool_input, target, layout, base)
    if keys_hit:
        return Classification(
            "deny", "read_outside", reason=f"protected path: {keys_hit}",
            reason_code="SANDBOX_PROTECT", target_path=target,
        )
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


# ---------------------------------------------------------------------------
# Shell parsing and protected-path helpers (T0a-T0e)
# ---------------------------------------------------------------------------

def _scan(command: str, *, strip_benign: bool = False) -> tuple[list[tuple[str, list[str]]], bool]:
    """Split a shell command into ``(raw segment, words)`` pairs.

    Segments are separated by ``; & | ( )``, backticks and newlines outside
    quotes; quotes are removed from words. The second value is ``unsafe``: the
    command has a substitution, expansion, redirect or an unbalanced quote, so
    the words alone do not say what will run. Conservative by design.
    """
    if strip_benign:
        command = _BENIGN_REDIRECT_RE.sub(" ", command)
    segments: list[tuple[str, list[str]]] = []
    words: list[str] = []
    cur: list[str] = []
    in_word = False
    unsafe = False
    quote = ""
    start = 0
    n = len(command)
    i = 0

    def flush_word() -> None:
        nonlocal in_word
        if in_word:
            words.append("".join(cur))
            cur.clear()
            in_word = False

    def flush_segment(end: int) -> None:
        nonlocal words
        flush_word()
        if words:
            segments.append((command[start:end].strip(), words))
            words = []

    while i < n:
        c = command[i]
        nxt = command[i + 1] if i + 1 < n else ""
        if quote:
            if c == quote:
                quote = ""
            elif quote == '"' and c == "\\" and nxt in ('"', "\\", "$", "`"):
                cur.append(nxt)
                i += 1
            else:
                if quote == '"' and (c == "`" or (c == "$" and nxt and not nxt.isspace())):
                    unsafe = True
                cur.append(c)
        elif c in ("'", '"'):
            quote = c
            in_word = True
        elif c in "\r\n;|&()":
            flush_segment(i)
            start = i + 1
        elif c == "`":
            unsafe = True
            flush_segment(i)
            start = i + 1
        elif c == "$":
            if nxt and not nxt.isspace():
                unsafe = True  # $VAR, ${...}, $(...), $'...'
            cur.append(c)
            in_word = True
        elif c in "<>":
            unsafe = True  # redirect or heredoc: writes or reads a file
            flush_word()
        elif c.isspace():
            flush_word()
        else:
            cur.append(c)
            in_word = True
        i += 1
    if quote:
        unsafe = True
    flush_segment(n)
    return segments, unsafe


def command_allowlisted(command: str, allow_patterns: list[str]) -> bool:
    """True only if the *whole* command is safe to run silently.

    No substitution/redirect/expansion, and every segment of a chained command
    matches an allow pattern. Anything unparsable is not allowlisted.
    """
    try:
        segments, unsafe = _scan(command, strip_benign=True)
    except Exception:  # noqa: BLE001 — fail closed
        return False
    if unsafe or not segments:
        return False
    for raw, _words in segments:
        if not any(re.search(pat, raw) for pat in allow_patterns):
            return False
    return True


def _norm_component(c: str) -> str:
    """Casefold and strip what NTFS ignores (ADS suffix, trailing dots/spaces)."""
    c = c.casefold()
    if ":" in c:
        c = c.split(":", 1)[0]
    if c not in (".", ".."):
        c = c.rstrip(". ")
    return c


def _comp_match(pattern: str, name: str, *, dot_rule: bool = True) -> bool:
    """Does the shell glob component *pattern* match path component *name*?

    A leading dot needs an explicit leading dot in the pattern (as in bash),
    unless ``dot_rule`` is off. Both sides are already case-folded.
    """
    if pattern == name:
        return True
    if name == ".sandbox" and _SHORT_NAME_RE.fullmatch(pattern):
        return True
    if any(ch in pattern for ch in "*?["):
        if dot_rule and name.startswith(".") and not pattern.startswith("."):
            return False
        return fnmatchcase(name, pattern)
    return False


def _seq_hit(
    comps: list[str], seqs: tuple[tuple[str, ...], ...], *, dot_rule: bool = True
) -> tuple[str, ...] | None:
    for seq in seqs:
        for i in range(len(comps) - len(seq) + 1):
            if all(_comp_match(comps[i + k], seq[k], dot_rule=dot_rule) for k in range(len(seq))):
                return seq
    return None


def _brace_expand(s: str) -> list[str]:
    """Expand every ``{a,b}`` group; raises ValueError past 256 results."""
    out = [s]
    while True:
        nxt: list[str] = []
        changed = False
        for item in out:
            m = re.search(r"\{([^{}]*,[^{}]*)\}", item)
            if m:
                changed = True
                nxt.extend(item[:m.start()] + alt + item[m.end():] for alt in m.group(1).split(","))
            else:
                nxt.append(item)
        out = list(dict.fromkeys(nxt))
        if len(out) > 256:
            raise ValueError("brace expansion too large")
        if not changed:
            return out


def _fold_dots(comps: list[str]) -> list[str]:
    """Drop `.` components and fold `x/..` lexically (a leading `..` stays)."""
    out: list[str] = []
    for c in comps:
        if c == ".":
            continue
        if c == ".." and out and out[-1] != "..":
            out.pop()
        else:
            out.append(c)
    return out


def _word_components(word: str) -> list[list[str]]:
    """Candidate component lists for one shell word (several readings of it)."""
    cands = {word}
    cands.update(p for p in re.split(r"[=@,:]", word) if p)  # --opt=path, f=@path
    readings: list[list[str]] = []
    for cand in cands:
        for variant in (cand.replace("\\", "/"), cand.replace("\\", "").replace("^", "")):
            for expanded in _brace_expand(variant):
                readings.append(_fold_dots([_norm_component(c) for c in expanded.split("/") if c]))
    return readings


def _shell_protected_path(command: str, _depth: int = 0) -> str | None:
    """Name the protected path a shell word names or globs onto, else None."""
    try:
        segments, _unsafe = _scan(command)
        for _raw, words in segments:
            for w in words:
                if _depth < 3 and any(ch.isspace() for ch in w):
                    sub = _shell_protected_path(w, _depth + 1)  # sh -c "..."
                    if sub:
                        return sub
                for comps in _word_components(w):
                    keys = _seq_hit(comps, _KEY_SEQS, dot_rule=False)
                    if keys:
                        return "/".join(keys)
                    seq = _seq_hit(comps, _PROTECTED_SEQS)
                    if seq:
                        return "/".join(seq)
    except Exception as exc:  # noqa: BLE001 — fail closed
        return f"unparsable command ({type(exc).__name__})"
    return None


def _is_sandbox_cli(words: list[str], j: int) -> bool:
    """Is words[j] the sandbox CLI (binary, script path or ``-m`` module)?"""
    w = words[j]
    for cand in (w, w.replace("\\", "").replace("^", "")):
        comps = [c.casefold() for c in re.split(r"[\\/]", cand) if c]
        base = comps[-1] if comps else ""
        for ext in (".exe", ".cmd", ".bat", ".ps1"):
            if base.endswith(ext):
                base = base[: -len(ext)]
        if base == "sandbox":
            return True
        if base.endswith(".py") and "sandbox" in comps[:-1]:
            return True  # python src/sandbox/cli/main.py
        # `-m sandbox.cli`, `-Im sandbox`, `-msandbox`
        m = re.fullmatch(r"-[A-Za-z]*m(.*)", cand, re.S)
        if m and m.group(1).casefold().split(".")[0] == "sandbox":
            return True
        if j > 0 and re.fullmatch(r"-[A-Za-z]*m", words[j - 1].replace("^", "")):
            if base.split(".")[0] == "sandbox":
                return True
    return False


def _approver_cli_use(command: str, _depth: int = 0) -> str | None:
    """The approver subcommand a segment runs (approve, deny, ...), else None.

    Looks at every segment, whatever precedes the CLI (`env X=1`, a path, `uv
    run`, `python -m sandbox.cli.main`); a hit anywhere in the segment counts.
    """
    segments, _unsafe = _scan(command)
    for _raw, words in segments:
        for j, w in enumerate(words):
            if _depth < 3 and any(ch.isspace() for ch in w):
                sub = _approver_cli_use(w, _depth + 1)
                if sub:
                    return sub
            if _is_sandbox_cli(words, j):
                seen_policy = False
                for rest in words[j + 1:]:
                    for cand in (rest, rest.replace("\\", "").replace("^", "")):
                        low = cand.casefold()
                        if low in _APPROVER_SUBCOMMANDS:
                            return low
                        # SEC-25: `policy propose` is half of a two-person change;
                        # the agent must not file it under a name of its choosing.
                        if low == "propose" and seen_policy:
                            return "policy propose"
                        if low == "policy":
                            seen_policy = True
    return None


def shell_deny_reason(command: str) -> tuple[str, str] | None:
    """Non-removable shell denies: ``(reason_code, reason)`` or None."""
    hit = _shell_protected_path(command)
    if hit:
        return "SANDBOX_PROTECT", f"command touches a protected path ({hit})"
    try:
        sub = _approver_cli_use(command)
    except Exception as exc:  # noqa: BLE001 — fail closed
        return "APPROVER_CLI", f"unparsable command (approver CLI check: {type(exc).__name__})"
    if sub is not None:
        return "APPROVER_CLI", f"the agent may not run the sandbox approver CLI ({sub})"
    return None


def _rel_components(layout: FolderLayout, target: str, base: str) -> list[str] | None:
    """Normalized components of *target* relative to the folder root, or None."""
    try:
        p = Path(target)
        if not p.is_absolute():
            p = Path(base) / p
        rel = p.resolve(strict=False).relative_to(Path(layout.root).resolve(strict=False))
    except (ValueError, OSError):
        return None
    return [_norm_component(c) for c in rel.parts]


def _raw_components(target: str) -> list[str]:
    return [_norm_component(c) for c in re.split(r"[\\/]", target) if c]


def _protected_write(target: str, layout: FolderLayout, base: str) -> str:
    """Label of the protected path a Write/Edit target hits, else ''."""
    rel = _rel_components(layout, target, base)
    for comps in (rel, _fold_dots(_raw_components(target))):
        if comps is None:
            continue
        seq = _seq_hit(comps, _PROTECTED_SEQS)
        if seq:
            return "/".join(seq)
        # Agent config at any depth: a session started in a package directory
        # of a monorepo reads that directory's own config.
        if comps and comps[-1] == ".mcp.json":
            return ".mcp.json"
        if len(comps) >= 2 and comps[-2] == ".claude" and fnmatchcase(comps[-1], "settings*.json"):
            return ".claude/settings*.json"
    return ""


def _reads_keys(
    tool_name: str, tool_input: dict[str, Any], target: str, layout: FolderLayout, base: str
) -> str:
    """Label of the protected path a read-class call reaches, else ''.

    Read: the signing seeds. Grep/Glob: any search rooted in `.sandbox/`
    (which contains them), by path or by pattern.
    """
    comps_list: list[list[str]] = []
    if target:
        rel = _rel_components(layout, target, base)
        if rel is not None:
            comps_list.append(rel)
        comps_list.append(_raw_components(target))
    if tool_name == "Read":
        for comps in comps_list:
            seq = _seq_hit(comps, _KEY_SEQS, dot_rule=False)
            if seq:
                return "/".join(seq)
        return ""
    pat = tool_input.get("pattern") if tool_name == "Glob" else tool_input.get("glob")
    if isinstance(pat, str) and pat:
        try:
            expanded = _brace_expand(pat)
        except ValueError:
            return ".sandbox (pattern too large to check)"
        comps_list.extend(_fold_dots(_raw_components(e)) for e in expanded)
    for comps in comps_list:
        if _seq_hit(comps, ((".sandbox",),)):
            return ".sandbox"
    return ""
