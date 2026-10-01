"""Lightweight data classification: glob rules that tag paths with a level.

A folder policy can list ordered rules such as::

    "classification": [
      {"pattern": "data/public/**",   "level": "public"},
      {"pattern": "data/customers/**", "level": "restricted"},
      {"pattern": "*.pem",            "level": "restricted"},
      {"pattern": "reports/**",       "level": "confidential"}
    ]

Levels, lowest to highest: ``public < internal < confidential < restricted``.
The **first** rule whose pattern matches wins, so a narrow exception goes
before the broad rule it carves out of. A path no rule matches is unclassified
(``None``), which has no effect: an empty rule list is today's behaviour.

Pattern syntax (``/`` as the separator on every OS; ``\\`` is accepted too):

* ``*`` matches within one path segment, ``?`` one character, ``[abc]`` a set.
* ``**`` matches any number of segments, including none: ``data/**`` matches
  ``data`` itself and everything under it.
* A pattern **without** a ``/`` matches the file name at any depth
  (``*.pem`` is the same as ``**/*.pem``), as in ``.gitignore``.
* A **relative** pattern is matched against the path relative to the folder
  root, so it only tags files inside the folder, except that a pattern
  starting with ``**/`` (or one without a ``/``) also matches anywhere outside
  it, e.g. ``**/.ssh/**`` tags ``~/.ssh/id_rsa``.
* An **absolute** pattern (``/etc/**``, ``C:/secrets/**``, ``~/.aws/**``) is
  matched against the absolute path.

Matching is case-insensitive on Windows and case-sensitive elsewhere. A path is
checked both as written (normalised) and with symlinks resolved, and the higher
level wins, so a link to a RESTRICTED file is RESTRICTED.

Limits: this tags paths, it does not inspect content. A RESTRICTED file copied
to an untagged name is untagged, and the result is only as good as the patterns
someone writes. Paths are found in shell commands and tool arguments by a
best-effort token scan, not a parser.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Iterable

LEVELS = ("public", "internal", "confidential", "restricted")
_RANK = {lvl: i for i, lvl in enumerate(LEVELS)}

_CASE_INSENSITIVE = os.name == "nt"


def rank(level: str | None) -> int:
    """Order of a level; -1 for unclassified."""
    return _RANK.get((level or "").lower(), -1)


def at_least(level: str | None, floor: str) -> bool:
    return rank(level) >= rank(floor)


@dataclass(frozen=True)
class PathClass:
    """The level a path was tagged with, and why."""

    path: str      # the path as found (tool argument / command token)
    level: str     # public | internal | confidential | restricted
    pattern: str   # the rule that matched

    def detail(self) -> str:
        return f"{self.path} is {self.level.upper()} (rule {self.pattern!r})"


# ---------------------------------------------------------------------------
# glob -> regex
# ---------------------------------------------------------------------------

def _is_absolute_pattern(pattern: str) -> bool:
    return pattern.startswith(("/", "~")) or bool(re.match(r"^[A-Za-z]:/", pattern))


@lru_cache(maxsize=512)
def _compile(pattern: str) -> tuple[re.Pattern[str], bool, bool]:
    """(regex, is_absolute, matches_anywhere) for one glob pattern."""
    pat = pattern.strip().replace("\\", "/")
    absolute = _is_absolute_pattern(pat)
    if pat.startswith("~"):
        pat = os.path.expanduser(pat).replace("\\", "/")
    if pat.endswith("/") and pat != "/":
        pat += "**"
    if not absolute and "/" not in pat:
        pat = "**/" + pat
    anywhere = not absolute and pat.startswith("**/")

    tail_any = pat.endswith("/**")
    if tail_any:
        pat = pat[:-3]

    out: list[str] = []
    i, n = 0, len(pat)
    while i < n:
        c = pat[i]
        if pat.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
        elif pat.startswith("**", i):
            out.append(".*")
            i += 2
        elif c == "*":
            out.append("[^/]*")
            i += 1
        elif c == "?":
            out.append("[^/]")
            i += 1
        elif c == "[":
            j = pat.find("]", i + 1)
            if j == -1:
                out.append(re.escape(c))
                i += 1
            else:
                body = pat[i + 1:j]
                if body.startswith("!"):
                    body = "^" + body[1:]
                out.append("[" + body.replace("\\", "\\\\") + "]")
                i = j + 1
        else:
            out.append(re.escape(c))
            i += 1
    regex = "".join(out) + ("(?:/.*)?" if tail_any else "")
    flags = re.IGNORECASE if _CASE_INSENSITIVE else 0
    return re.compile(regex, flags), absolute, anywhere


def _rule_fields(rule: Any) -> tuple[str, str]:
    if isinstance(rule, dict):
        return str(rule.get("pattern", "")), str(rule.get("level", ""))
    if isinstance(rule, (tuple, list)):
        return str(rule[0]), str(rule[1])
    return str(getattr(rule, "pattern", "")), str(getattr(rule, "level", ""))


# ---------------------------------------------------------------------------
# path normalisation
# ---------------------------------------------------------------------------

def _posix(p: str) -> str:
    return p.replace("\\", "/")


def _forms(path: str, root: Path, base: str | None) -> list[tuple[str | None, str]]:
    """(path relative to root or None, absolute path) as written and resolved."""
    raw = path.strip().strip("'\"")
    if raw.lower().startswith("file://"):
        raw = raw[7:]
    raw = os.path.expanduser(raw)
    p = Path(raw)
    if not p.is_absolute():
        p = Path(base or root) / p
    candidates = [Path(os.path.normpath(str(p)))]
    try:
        resolved = p.resolve(strict=False)
        if resolved not in candidates:
            candidates.append(resolved)
    except (OSError, RuntimeError, ValueError):
        pass

    roots = [Path(os.path.normpath(str(root)))]
    try:
        r = Path(root).resolve(strict=False)
        if r not in roots:
            roots.append(r)
    except (OSError, RuntimeError, ValueError):
        pass

    out: list[tuple[str | None, str]] = []
    for cand in candidates:
        rel: str | None = None
        c = os.path.normcase(str(cand))
        for r in roots:
            rr = os.path.normcase(str(r))
            if c == rr:
                rel = ""
                break
            prefix = rr.rstrip("\\/") + os.sep
            if c.startswith(prefix):
                # normcase can change the length (rare Unicode); then use its form.
                same_len = len(c) == len(str(cand))
                rel = _posix((str(cand) if same_len else c)[len(prefix):])
                break
        out.append((rel, _posix(str(cand))))
    return out


# ---------------------------------------------------------------------------
# public API
# ---------------------------------------------------------------------------

def classify_path(
    path: str, root: str | Path, rules: Iterable[Any], *, base: str | None = None
) -> PathClass | None:
    """The level of one path under the ordered *rules*; ``None`` if untagged.

    Relative paths are resolved against *base* (the call's cwd), else *root*.
    """
    rules = list(rules or [])
    if not rules or not path or not str(path).strip():
        return None
    try:
        forms = _forms(str(path), Path(root), base)
    except (OSError, ValueError, TypeError):
        return None

    best: PathClass | None = None
    for rel, absolute in forms:
        for rule in rules:
            pattern, level = _rule_fields(rule)
            if not pattern or rank(level) < 0:
                continue
            regex, is_abs, anywhere = _compile(pattern)
            hit = False
            if is_abs:
                hit = bool(regex.fullmatch(absolute))
            elif rel is not None:
                hit = rel != "" and bool(regex.fullmatch(rel))
            elif anywhere:
                hit = bool(regex.fullmatch(absolute))
            if hit:
                found = PathClass(path=str(path), level=level.lower(), pattern=pattern)
                if best is None or rank(found.level) > rank(best.level):
                    best = found
                break  # first matching rule wins for this form
    return best


def highest(
    paths: Iterable[str], root: str | Path, rules: Iterable[Any], *, base: str | None = None
) -> tuple[PathClass | None, list[PathClass]]:
    """The highest-level match among *paths*, and every match found."""
    rules = list(rules or [])
    if not rules:
        return None, []
    found: list[PathClass] = []
    seen: set[str] = set()
    for p in paths:
        if not p or p in seen:
            continue
        seen.add(p)
        m = classify_path(p, root, rules, base=base)
        if m is not None:
            found.append(m)
    best = max(found, key=lambda m: rank(m.level), default=None)
    return best, found


_TOKEN_SPLIT = re.compile(r"[\s|;&<>()=,`]+")


def command_paths(command: str, limit: int = 64) -> list[str]:
    """Path-like tokens in a shell command (best effort, not a parser)."""
    out: list[str] = []
    for tok in _TOKEN_SPLIT.split(command or ""):
        tok = tok.strip().strip("'\"").lstrip("@")
        if not tok or tok.startswith(("-", "$")) or "://" in tok:
            continue
        out.append(tok)
        if len(out) >= limit:
            break
    return out


def argument_paths(value: Any, limit: int = 64) -> list[str]:
    """String values in tool arguments that could be file paths (best effort)."""
    out: list[str] = []

    def walk(v: Any) -> None:
        if len(out) >= limit:
            return
        if isinstance(v, str):
            s = v.strip()
            if (s and len(s) < 1024 and "\n" not in s
                    and ("/" in s or "\\" in s or "." in s)
                    and ("://" not in s or s.lower().startswith("file://"))):
                out.append(s)
        elif isinstance(v, dict):
            for item in v.values():
                walk(item)
        elif isinstance(v, (list, tuple)):
            for item in v:
                walk(item)

    walk(value)
    return out
