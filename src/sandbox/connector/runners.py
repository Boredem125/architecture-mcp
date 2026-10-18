"""Workspace code runners (ADR 0009, M1 T0g).

``python -m pytest`` and ``npm run`` run code the agent can write: a ``conftest.py``, a
``package.json`` script, a lifecycle hook. Allowing them silently is a two-step bypass of every
other rule, so the classifier recognises them here, in code, on the words T0f's lexer resolved.
A recognised runner is never allowed by ``shell.allow_patterns``, ``auto_allow``, environment
rules or a remembered decision; it escalates with the reason code ``WORKSPACE_RUNNER``.

The only opt-in is ``shell.allow_runners`` in an approved, two-reviewer policy version, and it
allows exactly the forms that used to ship: ``<python> -m pytest`` / ``pytest`` / ``py.test`` for
``pytest``, and ``<pm> run|test|ci`` for ``npm``, ``pnpm`` and ``yarn``. ``npx``, ``bunx``,
``pnpm dlx``, ``yarn dlx``, ``bun`` and every other subcommand can never be opted in.

The list is one-sided: a wrong entry is an extra escalation, never an allow.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from sandbox.connector import shellwords

# Values `shell.allow_runners` may hold. Anything else is dropped.
OPT_IN_NAMES = ("pytest", "npm", "pnpm", "yarn")

_PYTHON = re.compile(r"(python|pythonw|pypy|py)[0-9.]*")
_MANAGERS = frozenset({"npm", "pnpm", "yarn", "bun"})
_ALWAYS = frozenset({"npx", "bunx"})  # run packages fetched at call time: never opt-in
_READ_ONLY = frozenset({"--version", "-v", "-V", "ls", "list", "view", "info", "outdated", "help"})
_OPT_IN_SUBCOMMANDS = frozenset({"run", "test"})  # `ci` fetches remote code: never opt-in


@dataclass(frozen=True)
class RunnerHit:
    name: str  # what the segment runs: pytest, npm, pnpm, yarn, bun, npx, bunx
    opt_in: str | None  # the `allow_runners` entry that would allow it, or None (never eligible)
    args: tuple[str, ...] = ()  # the segment's arguments, for the path check below


# Interpreter flags that take no value, and flags that take one (separate or attached).
_PY_PLAIN = frozenset("BuOEsSIqvbdRx")
_PY_VALUE = frozenset("WX")


def _pytest_module(args: list[str]) -> bool:
    """The interpreter's FIRST `-m` is `pytest` / `py.test`, with only value-less interpreter flags
    (-B -u -O -I ...) and `-W x` / `-X opt` before it. Anything else (a script, `-c`, another
    module, a later `-m`) is no pytest runner and gets no opt-in."""
    k = 0
    while k < len(args):
        a = args[k]
        m = re.fullmatch(r"-([A-Za-z]*)m(.*)", a, re.S)
        if m and set(m.group(1)) <= _PY_PLAIN:
            mod = (m.group(2) or (args[k + 1] if k + 1 < len(args) else "")).casefold()
            return mod in ("pytest", "py.test")
        if a[:1] == "-" and len(a) > 1 and a[1] in _PY_VALUE:
            k += 1 if len(a) > 2 else 2  # -Wignore, or -W ignore
            continue
        if a[:1] == "-" and len(a) > 1 and a[1] != "-" and set(a[1:]) <= _PY_PLAIN:
            k += 1
            continue
        return False
    return False


def _plain_form(name: str, args: list[str]) -> bool:
    """`<pm> test`, `<pm> ci`, `<pm> run <script>`, then optionally `-- <args>`; no option of the
    package manager itself (--prefix, --script-shell, --userconfig, -C, --workspace ...)."""
    head = args[:args.index("--")] if "--" in args else args
    if not head or head[0].casefold() not in _OPT_IN_SUBCOMMANDS:
        return False
    if head[0].casefold() == "run":
        return len(head) == 2 and not head[1].startswith("-")
    return len(head) == 1


def detect(seg: shellwords.Segment) -> RunnerHit | None:
    """The runner one lexed segment runs, else None."""
    if not seg.words:
        return None
    names = shellwords.bases(seg.words[0].raw)
    args = [w.raw for w in seg.words[1:]]
    if names & {"pytest", "py.test"}:
        return RunnerHit("pytest", "pytest", tuple(args))
    if any(_PYTHON.fullmatch(n) for n in names) and _pytest_module(args):
        return RunnerHit("pytest", "pytest", tuple(args))
    if names & _ALWAYS:
        return RunnerHit(sorted(names & _ALWAYS)[0], None)
    mgr = sorted(names & _MANAGERS)
    if mgr:
        name = mgr[0]
        first = args[0].casefold() if args else ""
        if first in _READ_ONLY or (first == "config" and args[1:2] == ["get"]):
            return None
        if name == "bun":
            return RunnerHit(name, None)
        opt = name if _plain_form(name, args) else None
        return RunnerHit(name, opt)  # bare `yarn` (no args) lands here too: it installs
    return None


def runner_hits(segments: list[shellwords.Segment]) -> list[RunnerHit]:
    return [h for h in (detect(s) for s in segments) if h is not None]


def blocked(hits: list[RunnerHit], allow_runners: list[str]) -> list[RunnerHit]:
    """The hits the opt-in does not cover."""
    allowed = {a for a in allow_runners if a in OPT_IN_NAMES}
    return [h for h in hits if h.opt_in is None or h.opt_in not in allowed]


_SAMPLES = ("python -m pytest", "python -m pytest -q", "pytest", "py.test", "npm run build", "npm test",
            "npm ci", "pnpm test", "pnpm run x", "yarn test", "yarn run x", "yarn", "bun test")


def stale_patterns(patterns: list[str]) -> list[tuple[str, str]]:
    """Saved allow patterns that name a workspace runner: ``(pattern, sample command)``.
    They are inert since ADR 0009; `sandbox doctor` lists them and never rewrites policy.json."""
    out: list[tuple[str, str]] = []
    for pat in patterns:
        try:
            sample = next((s for s in _SAMPLES if re.search(pat, s)), None)
        except re.error:
            sample = None
        if sample:
            out.append((pat, sample))
    return out


def _path_like(value: str) -> bool:
    return any(c in value for c in "/\\") or value[:1] in (".", "~") or value[1:2] == ":"


def paths_outside(hit: RunnerHit, root: str, cwd: str) -> bool:
    """True if a path-like argument of a pytest run (a positional path, a `--opt=path` value, a
    node id's file part) resolves outside the governed root. Such a run loses the opt-in."""
    from sandbox.fs.containment import is_contained

    for a in hit.args:
        value = a.split("=", 1)[1] if a.startswith("-") and "=" in a else ("" if a.startswith("-") else a)
        value = value.split("::", 1)[0]
        if value and _path_like(value) and not is_contained(root, value, base=cwd):
            return True
    return False
