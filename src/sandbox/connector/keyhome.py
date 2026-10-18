"""Key home: where reviewer signing seeds live, outside every workspace (ADR 0007 section 1).

Seeds (and later the pin file) sit in a per-user directory, one subfolder per
workspace id: ``SANDBOX_KEY_HOME``, else ``%LOCALAPPDATA%\\agg\\keys`` (Windows),
``$XDG_DATA_HOME/agg/keys`` or ``~/.local/share/agg/keys`` (Linux),
``~/Library/Application Support/agg/keys`` (macOS).

Fail closed: if the key home cannot be resolved or written there is no key, hence no
signature (:class:`KeyHomeError`). There is no fallback to ``.sandbox/state/keys``, the
cwd or any relative path. A key home that sits inside the workspace, or contains it, is
refused too: a rootless Grep or Glob could then reach the seeds.

:func:`touches` is the path test behind the non-removable read/write/delete/rename deny
(classify.py). It resolves symlinks and junctions, 8.3 names, case, ``~`` and
environment variables, so a path that ends up in the key home is recognised however it
is spelled.
"""
from __future__ import annotations

import os
import re
import sys
import time
from fnmatch import fnmatchcase
from pathlib import Path

WORKSPACE_ID_FILE = "workspace_id"
_ID_RE = re.compile(r"^[0-9a-f]{32}$")
_GLOB_CHARS = "*?["
_DRIVE_RE = re.compile(r"^[A-Za-z]:")


class KeyHomeError(RuntimeError):
    """The key home is unusable: no signing, no valid approval."""


def key_home_root() -> Path | None:
    """The configured key home (absolute), or None when it cannot be resolved."""
    try:
        override = os.environ.get("SANDBOX_KEY_HOME")
        if override:
            p = Path(override)
            return p if p.is_absolute() else None
        if os.name == "nt":
            base = os.environ.get("LOCALAPPDATA")
            if not base or not Path(base).is_absolute():
                return None
            return Path(base) / "agg" / "keys"
        xdg = os.environ.get("XDG_DATA_HOME")
        if sys.platform == "darwin":
            home = Path.home()
            return home / "Library" / "Application Support" / "agg" / "keys" if home.is_absolute() else None
        if xdg and Path(xdg).is_absolute():
            return Path(xdg) / "agg" / "keys"
        home = Path.home()
        return home / ".local" / "share" / "agg" / "keys" if home.is_absolute() else None
    except Exception:  # noqa: BLE001 - no home directory
        return None


def _new_workspace_id() -> str:
    return os.urandom(16).hex()


def workspace_id(layout, *, create: bool = True) -> str:
    """The workspace's random id (``.sandbox/workspace_id``). Created on first use for
    workspaces initialised before M1. An unreadable or malformed id fails closed."""
    path = layout.base / WORKSPACE_ID_FILE
    try:
        text = path.read_text(encoding="utf-8").strip()
    except FileNotFoundError:
        text = ""
    except OSError as exc:
        raise KeyHomeError(f"cannot read the workspace id: {exc}") from exc
    if text:
        if not _ID_RE.match(text):
            raise KeyHomeError("the workspace id file is malformed")
        return text
    if not create:
        raise KeyHomeError("this workspace has no id yet")
    try:
        layout.base.mkdir(parents=True, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(_new_workspace_id() + "\n")
    except FileExistsError:
        pass
    except OSError as exc:
        raise KeyHomeError(f"cannot write the workspace id: {exc}") from exc
    return workspace_id(layout, create=False)


def _secure_new_root(root: Path) -> None:
    """Windows: make a key home directory we just created user-only (best effort)."""
    if os.name != "nt":
        return
    try:
        import getpass
        import subprocess

        system_root = os.environ.get("SYSTEMROOT") or r"C:\Windows"
        icacls = Path(system_root) / "System32" / "icacls.exe"
        user = getpass.getuser()
        if not icacls.is_file() or not user:
            return
        ok = subprocess.run([str(icacls), str(root), "/grant:r", f"{user}:(OI)(CI)F"],
                            capture_output=True, timeout=20, check=False).returncode == 0
        if ok:
            subprocess.run([str(icacls), str(root), "/inheritance:r"],
                           capture_output=True, timeout=20, check=False)
    except Exception:  # noqa: BLE001 - hardening is additive
        pass


def _inside(child: Path, parent: Path) -> bool:
    try:
        c, p = _comps(os.path.realpath(child)), _comps(os.path.realpath(parent))
    except (OSError, ValueError):
        return True  # unresolvable: treat as overlapping, fail closed
    return c[:len(p)] == p


def workspace_key_dir(layout, *, create: bool = True) -> Path:
    """``<key home>/<workspace id>``; raises :class:`KeyHomeError` when unusable."""
    root = key_home_root()
    if root is None:
        raise KeyHomeError("the key home cannot be resolved (set SANDBOX_KEY_HOME to an absolute path)")
    if _inside(root, layout.root) or _inside(layout.root, root):
        raise KeyHomeError("the key home overlaps the workspace; refusing to keep keys there")
    wsid = workspace_id(layout, create=create)
    d = root / wsid
    if create:
        try:
            fresh = not root.exists()
            d.mkdir(parents=True, exist_ok=True)
            if fresh:
                _secure_new_root(root)
            if os.name != "nt":
                os.chmod(d, 0o700)
        except OSError as exc:
            raise KeyHomeError(f"the key home is not writable: {exc}") from exc
    return d


# --- path test for the deny ----------------------------------------------------------------

def _norm(c: str) -> str:
    c = c.casefold()
    if c not in (".", ".."):
        c = c.rstrip(". ")
    return c


def _comps(path: str) -> list[str]:
    """Normalised components: case-folded, separators unified, ``.``/``..`` folded."""
    p = path.replace("\\", "/")
    for prefix in ("//?/", "//./"):
        if p.startswith(prefix):
            p = p[len(prefix):]
    out: list[str] = []
    for c in p.split("/"):
        if not c or c == ".":
            continue
        if c == ".." and out and out[-1] != "..":
            out.pop()
        else:
            out.append(_norm(c))
    return out


_ROOTS_CACHE: dict[str, tuple[float, list[list[str]]]] = {}
_ROOTS_TTL = 2.0  # seconds: a long-lived server notices a changed key home or link soon


def protected_roots() -> list[list[str]]:
    """Component lists of the key home as spelled and as the OS resolves it."""
    root = key_home_root()
    if root is None:
        return []
    now = time.monotonic()
    hit = _ROOTS_CACHE.get(str(root))
    if hit and now - hit[0] < _ROOTS_TTL:
        return hit[1]
    forms = _roots_uncached(root)
    _ROOTS_CACHE.clear()
    _ROOTS_CACHE[str(root)] = (now, forms)
    return forms


def _roots_uncached(root: Path) -> list[list[str]]:
    forms = [_comps(str(root))]
    try:
        real = _comps(os.path.realpath(root))
        if real not in forms:
            forms.append(real)
    except (OSError, ValueError):
        pass
    return forms


def warm(base: str) -> None:
    """Pay the first-lookup cost (a cold disk, an antivirus scan) before a latency budget starts."""
    try:
        if protected_roots():
            os.path.realpath(base or ".")
    except Exception:  # noqa: BLE001
        pass


def _expand(cand: str) -> list[str]:
    outs = [cand]
    try:
        e = re.sub(r"\$env:([A-Za-z_][A-Za-z0-9_]*)", lambda m: os.environ.get(m.group(1), m.group(0)), cand,
                   flags=re.I)
        e = os.path.expandvars(e)
        if e.startswith("~"):
            e = os.path.expanduser(e)
        if e != cand:
            outs.append(e)
    except Exception:  # noqa: BLE001
        pass
    return outs


def _is_abs(p: str) -> bool:
    return p.startswith("/") or bool(_DRIVE_RE.match(p))


def _match(pat: str, name: str) -> bool:
    if any(ch in pat for ch in _GLOB_CHARS):
        return fnmatchcase(name, pat)
    return pat == name


def _reading_comps(cand: str, base: str, resolve: bool = True) -> list[list[str]]:
    p = cand.replace("\\", "/")
    parts = [c for c in p.split("/")]
    g = next((i for i, c in enumerate(parts) if any(ch in c for ch in _GLOB_CHARS)), len(parts))
    literal = "/".join(parts[:g]) or ("/" if p.startswith("/") else "")
    rest = [_norm(c) for c in parts[g:] if c and c != "."]
    if not literal:
        literal = "."
    joined = literal if _is_abs(literal) else os.path.join(base or ".", literal)
    forms: list[list[str]] = [_comps(joined) + rest]
    if not resolve:
        return forms
    try:
        real = _comps(os.path.realpath(joined)) + rest
        if real != forms[0]:
            forms.append(real)
    except (OSError, ValueError):
        pass
    return forms


def touches(text: str, base: str, *, search: bool = False, resolve: bool = True) -> str:
    """Does the path ``text`` (quotes already removed; globs allowed) name the key home?

    Returns ``"inside"`` for the key home or anything under it, ``"ancestor"`` for a
    directory that contains it and ``search`` is set (a recursive search from there
    would reach the seeds), else ``""``. Symlinks and junctions, 8.3 names, case,
    ``~`` and environment variables are resolved first. ``resolve=False`` skips the
    filesystem lookups (symlinks, junctions, 8.3 names): a lexical test only.
    """
    roots = protected_roots()
    if not roots or not text:
        return ""
    for cand in _expand(text):
        for full in _reading_comps(cand, base, resolve):
            for root in roots:
                n = min(len(full), len(root))
                if all(_match(full[i], root[i]) for i in range(n)):
                    if len(full) >= len(root):
                        return "inside"
                    if search:
                        return "ancestor"
    return ""
