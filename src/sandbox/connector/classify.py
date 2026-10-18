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
import string
import time
from dataclasses import dataclass, field
from functools import lru_cache
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from sandbox.connector.layout import FolderLayout
from sandbox.connector import runners, shellwords
from sandbox.connector.policy import _PROTECT_SHELL_PATTERNS, FolderPolicy
from sandbox.fs.containment import is_contained

SANDBOX_MCP_PREFIX = "mcp__sandbox__"

# Non-removable protections enforced here in code, whatever policy.json says
# (a hand-edited policy can omit deny_globs / deny_patterns entirely).
# Path component sequences, matched against shell words after quote removal,
# glob matching and case folding, so `.sand*`, `.sand''box` and `.SANDBOX` all
# hit `.sandbox`. They are never matched by regex on the command string.
_PROTECTED_SEQS: tuple[tuple[str, ...], ...] = ((".sandbox",), (".git", "hooks"))
# Paths the agent may read but not write: `git status` runs core.fsmonitor from .git/config,
# and hooks, attributes, refs and objects steer git too.
_WRITE_ONLY_SEQS: tuple[tuple[str, ...], ...] = ((".git",),)  # all of .git/**: reads stay allowed
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
        return _classify_shell(tool_input, policy, blocklist,
                               "pwsh" if tool_name == "PowerShell" else "bash",
                               root=str(layout.root), cwd=base)

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
    tool_input: dict[str, Any], policy: FolderPolicy, blocklist: Any, shell: str = "bash",
    root: str = "", cwd: str = "",
) -> Classification:
    command = _shell_target_path(tool_input)

    # 0. Bounds first, before anything scans the text (D0b.5): an oversize or NUL
    # command is denied unlexed, and the blocklist regexes never see it.
    bound = _command_bound(command)
    if bound:
        return Classification("deny", "shell", reason=bound[1], reason_code=bound[0], command="")

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
    # Outside the static subset (shellwords.py) a command is never allowed: denied
    # when a deny fragment is visible, else escalated below.
    analysis = analyse_shell(command, shell)
    if analysis.deny:
        return Classification(
            "deny", "shell", reason=analysis.deny[1], reason_code=analysis.deny[0], command=command,
        )

    # 2c. Deny patterns from the policy. The built-in self-protection pattern
    # (`\.sandbox`, re-injected each load) is skipped: it matched quoted prose
    # too (`echo "the .sandbox folder"`), and 2a now checks the same thing on the
    # lexed words, including globs, quote splits and attached option values.
    for pat in policy.shell.deny_patterns:
        if pat in _PROTECT_SHELL_PATTERNS:
            continue
        if re.search(pat, command):
            return Classification(
                "deny", "shell",
                reason=f"command touches a protected path (pattern {pat!r})",
                reason_code="SANDBOX_PROTECT", command=command,
            )

    # 2d. Workspace code runners (ADR 0009): `python -m pytest`, `npm run` ... run code the
    # agent can write. Never allowed by allow_patterns, whatever a saved policy holds; the
    # only way through is an approved `shell.allow_runners` entry (the hook passes it empty
    # unless the folder's approved version carries it) and a single static segment.
    if analysis.runners:
        hits = runners.blocked(analysis.runners, getattr(policy.shell, "allow_runners", []))
        try:  # an opted-in pytest run whose paths leave the governed root loses the opt-in
            if not hits and root and any(h.name == "pytest" and runners.paths_outside(h, root, cwd or root)
                                         for h in analysis.runners):
                hits = [h for h in analysis.runners if h.name == "pytest"]
        except Exception:  # noqa: BLE001 — fail closed
            hits = list(analysis.runners)
        names = sorted({h.name for h in analysis.runners})
        if hits or analysis.unresolvable or analysis.segments != 1 or _scan(command, strip_benign=True)[1]:
            return Classification(
                "deny" if policy.triggers.shell == "deny" else "escalate", "shell",
                reason=(f"runs code in this folder that the agent can change ({', '.join(names)}); "
                        "check `git diff` first"),
                reason_code="WORKSPACE_RUNNER", command=command,
                metadata={"runners": names},
            )
        return Classification(
            "allow", "shell", reason=f"workspace runner allowed by an approved opt-in ({', '.join(names)})",
            reason_code="RUNNER_ALLOWED", command=command, metadata={"runner_allowed": names},
        )

    # 2e. Unresolvable: always a human, whatever triggers.shell says. The reason
    # code and text tell the approver the command could not be analysed.
    if analysis.unresolvable:
        why = ", ".join(analysis.unresolvable)
        return Classification(
            "escalate", "shell",
            reason=f"the command could not be analysed statically ({why}); read it before approving",
            reason_code="SHELL_UNRESOLVABLE", command=command,
            metadata={"unresolvable": list(analysis.unresolvable)},
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
    for raw, words in segments:
        if not any(_allow_match(pat, raw) for pat in allow_patterns):
            return False
        if not _flags_ok(words):
            return False
    return True


_GIT_LONG = frozenset((
    "patch no-patch stat shortstat numstat summary oneline name-only name-status graph decorate "
    "no-decorate abbrev-commit no-abbrev-commit no-color color all merges no-merges first-parent "
    "follow reverse cached staged check relative-date raw topo-order date-order abbrev full-history "
    "dirstat word-diff color-words ignore-space-change ignore-all-space minimal patience histogram "
    "no-renames find-renames left-right boundary source stat-width unified pretty format date since "
    "until after before author committer grep max-count skip diff-filter no-pager no-ext-diff no-textconv").split())
_GIT_STATUS_LONG = frozenset((
    "short branch porcelain long ignored untracked-files show-stash ahead-behind no-ahead-behind "
    "column no-column ignore-submodules renames no-renames").split())
_GIT_BRANCH_LONG = frozenset(
    "list all remotes verbose show-current contains no-contains merged no-merged sort format "
    "points-at column".split())
_GIT_BRANCH_LIST = frozenset("list contains no-contains merged no-merged show-current points-at".split())
_GIT_REVPARSE_LONG = frozenset((
    "short abbrev-ref show-toplevel is-inside-work-tree verify symbolic-full-name show-prefix "
    "show-cdup git-dir absolute-git-dir is-bare-repository quiet").split())
_GIT_SEP_VALUE = frozenset((
    "-n", "-U", "-S", "-G", "--max-count", "--skip", "--since", "--until", "--author", "--committer",
    "--grep", "--diff-filter", "--after", "--before", "--contains", "--no-contains", "--merged",
    "--no-merged", "--points-at", "--sort"))
_GIT_SHORT = re.compile(r"-(?:[pusbwzarvq]+|\d+|n\d*|U\d+|[SG].+|u(?:no|normal|all))")


def _git_flags_ok(sub: str, args: list[str]) -> bool:
    """Only known read-only flags pass for an allowlisted git subcommand (D0b / T0f).
    Anything else, including --output, -o, -O, --ext-diff, --textconv, --no-index, -c,
    --git-dir, --work-tree, -C and --exec-path, is not allowed silently."""
    long_ok = {"status": _GIT_STATUS_LONG, "branch": _GIT_BRANCH_LONG,
               "rev-parse": _GIT_REVPARSE_LONG}.get(sub, _GIT_LONG)
    skip_value = False
    positional = False
    listing = False
    only_paths = False
    for a in args:
        if skip_value:
            skip_value = False
            continue
        if only_paths or not a.startswith("-") or a == "-":
            positional = True
            continue
        if a == "--":
            only_paths = True
            continue
        if a.startswith("--"):
            name = a[2:].split("=", 1)[0]
            if name not in long_ok:
                return False
            if name in _GIT_BRANCH_LIST:
                listing = True
            if "=" not in a and a in _GIT_SEP_VALUE:
                skip_value = True
            continue
        if sub == "branch" and a in ("-a", "-r", "-v", "-vv"):
            continue
        if sub == "rev-parse" or sub == "branch":
            return False
        if a in _GIT_SEP_VALUE:
            skip_value = True
            continue
        if not _GIT_SHORT.fullmatch(a):
            return False
    if sub == "branch" and positional and not listing:
        return False  # `git branch name` creates a branch
    return True


_PLAIN_CMDS = frozenset("ls dir pwd cd cat type echo which where".split())


def _flags_ok(words: list[str]) -> bool:
    """The words of one allowlisted segment carry no write or config flag."""
    if not words:
        return False
    first = words[0]
    if re.match(r"[A-Za-z_][A-Za-z0-9_]*\+?=", first):
        return False  # GIT_EXTERNAL_DIFF=x git diff, PATH=... ls
    names = shellwords.bases(first)
    if "git" in names:
        if len(words) < 2:
            return True
        return _git_flags_ok(words[1], words[2:])
    if names & _PLAIN_CMDS:
        # No flag of these commands writes a file; redirects and `tee` are caught earlier
        # (a redirect makes the command unsafe, and the target is a checked path).
        return not any(w.startswith("--output") for w in words[1:])
    return True


def _allow_match(pat: str, raw: str) -> bool:
    """The pattern matches and the match ends at whitespace or the end of the segment,
    or at the end of a match that itself ends in whitespace. A saved `^ls\\b` pattern
    therefore no longer allows `ls/x.sh` or `cat.sh` (fail closed: the command escalates)."""
    m = re.search(pat, raw)
    if not m:
        return False
    end = m.end()
    return end >= len(raw) or raw[end].isspace() or (end > m.start() and raw[end - 1].isspace())


def allow_pattern_gaps(patterns: list[str]) -> list[str]:
    """Allow patterns with no ``(\\s|$)`` boundary or end anchor. They still work, but the
    code now requires a whitespace boundary after the match; `sandbox doctor` lists them."""
    return [p for p in patterns
            if "(\\s|$)" not in p and not p.endswith(("$", "\\s", "\\s+", " ", ".*"))]


def _norm_component(c: str) -> str:
    """Casefold and strip what NTFS ignores (ADS suffix, trailing dots/spaces)."""
    c = c.casefold()
    if ":" in c and "[:" not in c:  # `[[:alpha:]]` is a glob class, not a stream
        c = c.split(":", 1)[0]
    if c not in (".", ".."):
        c = c.rstrip(". ")
    return c


_POSIX_CLASSES = {
    "alpha": "a-zA-Z", "digit": "0-9", "alnum": "a-zA-Z0-9", "upper": "a-zA-Z", "lower": "a-zA-Z",
    "space": " \\t\\n\\r\\f\\v", "blank": " \\t", "punct": re.escape(string.punctuation),
    "xdigit": "0-9a-fA-F", "word": "\\w", "cntrl": "\\x00-\\x1f\\x7f", "graph": "\\x21-\\x7e",
    "print": "\\x20-\\x7e",
}  # upper/lower are widened to alpha: the names compared are case-folded (NTFS ignores case)


@lru_cache(maxsize=4096)
def _glob_regex(pattern: str) -> re.Pattern[str]:
    """Translate one bash glob component: * ? [..] with ! or ^ negation, ranges and
    POSIX classes. Python's fnmatch has neither ``^`` nor ``[:alpha:]``."""
    out: list[str] = []
    n, i = len(pattern), 0
    while i < n:
        c = pattern[i]
        if c == "*":
            if not out or out[-1] != ".*":
                out.append(".*")
        elif c == "?":
            out.append(".")
        elif c == "[":
            j, neg, items, first = i + 1, False, [], True
            if j < n and pattern[j] in "!^":
                neg, j = True, j + 1
            while j < n and (pattern[j] != "]" or first):
                first = False
                if pattern.startswith("[:", j):
                    k = pattern.find(":]", j + 2)
                    if k > 0 and pattern[j + 2:k] in _POSIX_CLASSES:
                        items.append(_POSIX_CLASSES[pattern[j + 2:k]])
                        j = k + 2
                        continue
                if j + 2 < n and pattern[j + 1] == "-" and pattern[j + 2] != "]":
                    items.append(re.escape(pattern[j]) + "-" + re.escape(pattern[j + 2]))
                    j += 3
                    continue
                items.append(re.escape(pattern[j]))
                j += 1
            if j >= n:  # no closing bracket: a literal [
                out.append(re.escape("["))
            else:
                out.append("[" + ("^" if neg else "") + "".join(items) + "]")
                i = j
        else:
            out.append(re.escape(c))
        i += 1
    try:
        return re.compile("".join(out), re.I | re.S)
    except re.error:
        return re.compile(".*", re.S)  # unreadable bracket: assume it can match


_ALIAS_RE = re.compile(r"([^~./\\]{1,6})~[0-9]+(\.[^.~]{0,3})?")


def _alias_of(pattern: str, name: str) -> bool:
    """Is *pattern* an NTFS 8.3 short name (``GIT~1``, ``SANDBO~1``, ``MCP~1.JSO``) that
    could alias the long component *name*?"""
    m = _ALIAS_RE.fullmatch(pattern)
    if not m:
        return False
    stem = name.lstrip(".")
    base, _, ext = stem.rpartition(".") if "." in stem else (stem, "", "")
    if m.group(1) != base.replace(".", "")[:6]:
        return False
    return m.group(2) is None or ext.startswith(m.group(2)[1:])


def _comp_match(pattern: str, name: str, *, dot_rule: bool = True) -> bool:
    """Does the shell glob component *pattern* match path component *name*?

    A leading dot needs an explicit leading dot in the pattern (as in bash),
    unless ``dot_rule`` is off (PowerShell and cmd wildcards have no such rule).
    Both sides are already case-folded.
    """
    if pattern == name:
        return True
    if "~" in pattern and _alias_of(pattern, name):
        return True
    if any(ch in pattern for ch in "*?["):
        if dot_rule and name.startswith(".") and not pattern.startswith("."):
            return False
        return _glob_regex(pattern).fullmatch(name) is not None
    return False


def _seq_hit(
    comps: list[str], seqs: tuple[tuple[str, ...], ...], *, dot_rule: bool = True
) -> tuple[str, ...] | None:
    for seq in seqs:
        for i in range(len(comps) - len(seq) + 1):
            if all(_comp_match(comps[i + k], seq[k], dot_rule=dot_rule) for k in range(len(seq))):
                return seq
    return None


_BRACE_RE = re.compile(r"\{([^{}]*)\}")
_RANGE_RE = re.compile(r"(-?[0-9]+|[A-Za-z])\.\.(-?[0-9]+|[A-Za-z])(?:\.\.(-?[0-9]+))?")


def _brace_alts(inner: str) -> list[str] | None:
    """Alternatives of one brace group (``a,b`` or a ``x..y[..step]`` range), else None."""
    if "," in inner:
        return inner.split(",")
    m = _RANGE_RE.fullmatch(inner)
    if not m:
        return None
    lo, hi, step = m.group(1), m.group(2), abs(int(m.group(3) or 1)) or 1
    if lo.lstrip("-").isdigit() and hi.lstrip("-").isdigit():
        x, y = int(lo), int(hi)
        if abs(y - x) // step + 1 > 256:
            raise ValueError("brace expansion too large")
        seq = range(x, y + 1, step) if x <= y else range(x, y - 1, -step)
        return [str(v) for v in seq]
    if lo.isalpha() and hi.isalpha() and len(lo) == len(hi) == 1:
        x, y = ord(lo), ord(hi)
        seq = range(x, y + 1, step) if x <= y else range(x, y - 1, -step)
        return [chr(v) for v in seq]
    return None


def _brace_expand(s: str) -> list[str]:
    """Expand every ``{a,b}`` and ``{x..y}`` group; raises ValueError past 256 results."""
    out = [s]
    while True:
        nxt: list[str] = []
        changed = False
        for item in out:
            for m in _BRACE_RE.finditer(item):
                alts = _brace_alts(m.group(1))
                if alts is not None:
                    changed = True
                    nxt.extend(item[:m.start()] + alt + item[m.end():] for alt in alts)
                    break
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
    for c in list(cands):  # -C.sandbox, -xf.sandbox/x.tar, -pO.sandbox/x
        m = re.match(r"-[A-Za-z]+", c)
        if m:
            cands.update(c[i:] for i in range(2, m.end() + 1))
    readings: list[list[str]] = []
    for cand in cands:
        for variant in (cand.replace("\\", "/"), cand.replace("\\", "").replace("^", "")):
            for expanded in _brace_expand(variant):
                readings.append(_fold_dots([_norm_component(c) for c in expanded.split("/") if c]))
    return readings


_WRITER_CMDS = frozenset(
    "tee cp mv install dd ln rm rmdir touch truncate mkdir rsync chmod chown unlink shred "
    "sed gsed patch tar unzip".split())


def _write_hit(comps: list[str], dot_rule: bool = True) -> str | None:
    """The write-only git path (config, config.worktree, info/attributes, a submodule's
    config) these components name, else None."""
    seq = _seq_hit(comps, _WRITE_ONLY_SEQS, dot_rule=dot_rule)
    if seq:
        return "/".join(seq)
    for i in range(len(comps) - 3):
        if (_comp_match(comps[i], ".git", dot_rule=dot_rule) and comps[i + 1] == "modules"
                and comps[-1] == "config"):
            return ".git/modules/*/config"
    return None


def _fd_dup(op: str, target: shellwords.Word) -> bool:
    """`2>&1`, `>&-`: a descriptor, not a path."""
    return op.endswith("&") and (target.raw.isdigit() or target.raw == "-"
                                 or (target.raw[:-1].isdigit() and target.raw.endswith("-")))


def _may_name_protected(w: shellwords.Word) -> bool:
    """Cheap prefilter. Without a ``* ? [`` glob, a word can only name a protected
    component by spelling it, and every protected name starts with a dot (or is the
    8.3 alias ``sandbo~N``, caught by the ``~`` test), so a word without a dot and
    the letters of a protected name cannot hit."""
    if "~" in w.raw or any(ch in w.raw for ch in "*?[") or ("{" in w.raw and ".." in w.raw):
        return True
    if "." not in w.raw:
        return False
    letters = set(w.raw.casefold().translate(_PATH_FOLD))
    return _SANDBOX_LETTERS <= letters or _GIT_HOOKS_LETTERS <= letters


_SANDBOX_LETTERS = frozenset("sandbo")
_GIT_HOOKS_LETTERS = frozenset("git")  # .git/hooks, .git/config


_PATH_FOLD = str.maketrans("", "", "'\"\\^`")


def _seg_path_hit(seg: shellwords.Segment, deadline: float, dot_rule: bool = True) -> str | None:
    """The protected path a word or redirect target of the segment names or globs onto.
    A redirect that writes also may not name the write-only paths (``.git/config``)."""
    targets = [(t, op.startswith((">", "&>"))) for op, t in seg.redirs if not _fd_dup(op, t)]
    # `git log --output=.git/config` writes the file: every word of a git segment may.
    names = shellwords.bases(seg.words[0].raw) if seg.words else set()
    writer = bool(names & _WRITER_CMDS) or "git" in names  # tee/cp/mv/...: every word may be a target
    for w, writes in [(w, writer) for w in seg.words] + targets:
        shellwords.check_deadline(deadline)
        if not _may_name_protected(w):
            continue
        for comps in _word_components(w.raw):
            keys = _seq_hit(comps, _KEY_SEQS, dot_rule=False)
            if keys:
                return "/".join(keys)
            seq = _seq_hit(comps, _PROTECTED_SEQS, dot_rule=dot_rule)
            if seq:
                return "/".join(seq)
            if writes:
                hit = _write_hit(comps, dot_rule)
                if hit:
                    return hit
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


def _seg_approver(seg: shellwords.Segment) -> str | None:
    """The approver subcommand a segment runs (approve, deny, ...), else None.

    Whatever precedes the CLI (`env X=1`, a path, `uv run`, `python -m
    sandbox.cli.main`), a hit anywhere in the segment counts. An argument that
    cannot be resolved (a glob, a variable) after the CLI is a deny: it could
    spell any subcommand.
    """
    raws = [w.raw for w in seg.words]
    for j in range(len(raws)):
        # Cheap prefilter: the CLI is named `sandbox` (any path, any case) or is a
        # `-m` flag cluster such as `-Im`; any other word cannot be it.
        if not raws[j].startswith("-") and "sandbo" not in raws[j].casefold().translate(_PATH_FOLD):
            continue
        if not _is_sandbox_cli(raws, j):
            continue
        seen_policy = False
        for rest in seg.words[j + 1:]:
            if rest.glob or rest.dyn:
                return "unresolved argument"
            for cand in (rest.raw, rest.raw.replace("\\", "").replace("^", "")):
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


_CODE_CHARS = frozenset(" \t\r\n;&|()<>`$")
_MAX_RECURSE = 3


@dataclass
class ShellAnalysis:
    deny: tuple[str, str] | None = None  # (reason_code, reason)
    unresolvable: list[str] = field(default_factory=list)
    runners: list[runners.RunnerHit] = field(default_factory=list)  # workspace code runners (ADR 0009)
    segments: int = 0


def _command_bound(command: str) -> tuple[str, str] | None:
    if "\x00" in command:
        return "BAD_INPUT", "SANDBOX DENIED: the command contains a NUL byte"
    if len(command.encode("utf-8", "surrogatepass")) > shellwords.MAX_BYTES:
        return "COMMAND_TOO_LARGE", (
            f"shell command exceeds {shellwords.MAX_BYTES // 1024} KiB and was not analysed; "
            "use the Write tool for large content")
    return None


def _writes_file(seg: shellwords.Segment) -> bool:
    return (any(op.startswith((">", "&>")) and not _fd_dup(op, t) for op, t in seg.redirs)
            or bool(seg.words and "tee" in shellwords.bases(seg.words[0].raw)))


def _analyse(command: str, shell: str, deadline: float, depth: int, dot_rule: bool = True,
             info: dict[str, Any] | None = None) -> tuple[tuple[str, str] | None, set[str]]:
    lexed = shellwords.lex(command, shell, deadline)
    reasons = set(lexed.reasons)
    segs = lexed.segments
    if info is not None:  # top level only: the runner gate (ADR 0009) reads the resolved words
        info["segments"] = len(segs)
        try:
            info["runners"] = runners.runner_hits(segs)
        except Exception:  # noqa: BLE001 — fail closed: an unrecognisable runner never opts in
            info["runners"] = [runners.RunnerHit("unresolved", None)]
    seg_reasons: list[list[str]] = []
    for seg in segs:
        shellwords.check_deadline(deadline)
        if shellwords.encoded_command(seg):
            return ("ENCODED_COMMAND",
                    "an encoded PowerShell command cannot be reviewed by a human"), reasons
        r = shellwords.segment_reasons(seg)
        seg_reasons.append(r)
        reasons.update(r)
    for seg in segs:
        hit = _seg_path_hit(seg, deadline, dot_rule)
        if hit:
            return ("SANDBOX_PROTECT", f"command touches a protected path ({hit})"), reasons
    for seg in segs:
        sub = _seg_approver(seg)
        if sub:
            return ("APPROVER_CLI",
                    f"the agent may not run the sandbox approver CLI ({sub})"), reasons
    # Strings handed to a program that runs them, or written to a file that may be
    # run later, are read again as a command line of their own (depth 3).
    for seg, r in zip(segs, seg_reasons):
        if not (r or _writes_file(seg)):
            continue
        for w in seg.words[1:]:
            if not _CODE_CHARS.intersection(w.raw):
                continue
            if depth >= _MAX_RECURSE:
                reasons.add("nesting_depth")
                continue
            try:
                deny, inner = _analyse(w.raw, "bash", deadline, depth + 1, dot_rule)
            except shellwords.LexError:
                reasons.add("inner_lex_error")
                continue
            if deny:
                return deny, reasons
            reasons.update(inner)
    return None, reasons


def analyse_shell(command: str, shell: str = "bash") -> ShellAnalysis:
    """Static analysis of one shell command line (D0b). Never raises.

    ``deny`` is set for a protected path, the approver CLI, an encoded PowerShell
    command, a bound or a lexer error, and for an unresolvable command that shows a
    deny fragment. Otherwise ``unresolvable`` lists why the command may never be
    allowed (the caller escalates), or is empty for a command in the static subset.
    """
    bound = _command_bound(command)
    if bound:
        return ShellAnalysis(deny=bound)
    info: dict[str, Any] = {}
    try:
        deny, reasons = _analyse(command, shell, time.monotonic() + shellwords.DEADLINE_SECONDS, 0,
                                 dot_rule=shell != "pwsh", info=info)
    except shellwords.Bound as exc:
        return ShellAnalysis(deny=(exc.code, f"SANDBOX DENIED: {exc}"))
    except shellwords.LexError as exc:
        return ShellAnalysis(deny=("SHELL_LEXER_ERROR",
                                   f"SANDBOX DENIED: the command does not lex ({exc})"))
    except ValueError as exc:  # brace expansion past 256 results
        return ShellAnalysis(deny=("SANDBOX_PROTECT", "command touches a protected path "
                                   f"(unparsable command ({type(exc).__name__}))"))
    except Exception as exc:  # noqa: BLE001 — fail closed
        return ShellAnalysis(deny=("SHELL_ANALYSIS_ERROR",
                                   f"SANDBOX DENIED: analysis failed ({type(exc).__name__})"))
    names = sorted(reasons)
    if deny is None and reasons:
        frag = shellwords.fragment(command)
        if frag:
            deny = ("SHELL_UNRESOLVABLE", "the command could not be analysed statically "
                    f"({', '.join(names)}) and contains {frag!r}")
    return ShellAnalysis(deny=deny, unresolvable=names, runners=info.get("runners", []),
                         segments=info.get("segments", 0))


def shell_deny_reason(command: str, shell: str = "bash") -> tuple[str, str] | None:
    """Non-removable shell denies: ``(reason_code, reason)`` or None."""
    return analyse_shell(command, shell).deny


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
        hit = _write_hit(comps)
        if hit:
            return hit
        # Agent config at any depth: a session started in a package directory
        # of a monorepo reads that directory's own config.
        if comps and (comps[-1] == ".mcp.json" or _alias_of(comps[-1], ".mcp.json")):
            return ".mcp.json"
        if len(comps) >= 2 and (comps[-2] == ".claude" or _alias_of(comps[-2], ".claude")) and (
                fnmatchcase(comps[-1], "settings*.json") or
                re.fullmatch(r"settin~[0-9]+\.jso", comps[-1])):
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
