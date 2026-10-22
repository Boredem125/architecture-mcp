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


def _is_windows() -> bool:
    """Platform seam: tests patch this instead of ``os.name`` (which breaks ``Path`` on Linux)."""
    return os.name == "nt"


class NotEnrolledError(KeyHomeError):
    """The reviewer is not enrolled and keys.enrol is set to explicit (ADR 0007 2.4)."""


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


def workspace_id(layout, *, create: bool = True, audit: bool = True) -> str:
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
    new_id = _new_workspace_id()
    if audit:  # a missing id means a new key folder: a deleted id must leave a trace
        _audit_id_created(layout, new_id)
    try:
        layout.base.mkdir(parents=True, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(new_id + "\n")
    except FileExistsError:
        pass
    except OSError as exc:
        raise KeyHomeError(f"cannot write the workspace id: {exc}") from exc
    # Record workspace root in the key home so enroll() can discover it.
    _register_workspace_root(new_id, layout.root if hasattr(layout, 'root') else layout.base.parent)
    return workspace_id(layout, create=False)


def _audit_id_created(layout, new_id: str) -> None:
    import json
    import time

    from sandbox.connector.audit import FolderAudit

    try:
        session_id = json.loads(layout.session_file.read_text(encoding="utf-8")).get("session_id", "")
    except (OSError, ValueError, AttributeError):
        session_id = ""
    try:
        FolderAudit(layout.audit_dir, session_id).append(
            {"event": "workspace_id_created", "ts": time.time(), "workspace_id": new_id,
             "note": "a new id means a new key folder; reviewer keys start over for this workspace"})
    except Exception as exc:  # noqa: BLE001
        raise KeyHomeError(f"cannot record workspace_id_created in the audit chain: {exc}") from exc


def _register_workspace_root(ws_id: str, root: Path) -> None:
    """Write the workspace root path to the key home so enroll() can discover it."""
    try:
        kh = key_home_root()
        if kh is None:
            return
        d = kh / ws_id
        d.mkdir(parents=True, exist_ok=True)
        root_file = d / "workspace_root"
        if not root_file.exists():
            root_file.write_text(str(root), encoding="utf-8")
    except Exception:  # noqa: BLE001 - best effort
        pass


def _discover_workspace_roots() -> list[Path]:
    """Return workspace root paths registered in the key home."""
    try:
        kh = key_home_root()
        if kh is None or not kh.exists():
            return []
        roots: list[Path] = []
        for d in kh.iterdir():
            if not d.is_dir() or not _ID_RE.match(d.name):
                continue
            root_file = d / "workspace_root"
            if root_file.exists():
                try:
                    text = root_file.read_text(encoding="utf-8").strip()
                    if text:
                        roots.append(Path(text))
                except OSError:
                    pass
        return roots
    except Exception:  # noqa: BLE001
        return []


def _validated_icacls() -> Path | None:
    """Return a validated absolute path to icacls.exe, or None.

    Breaks the Semgrep taint chain: SYSTEMROOT is validated to be an absolute
    Windows-style path with no traversal before use.
    """
    raw = os.environ.get("SYSTEMROOT") or r"C:\Windows"
    p = Path(raw)
    if not p.is_absolute() or ".." in p.parts:
        p = Path(r"C:\Windows")
    icacls = p / "System32" / "icacls.exe"
    return icacls if icacls.is_file() else None


def root_exposure(root: Path) -> str | None:
    """Why `root` is readable by other accounts, or None when it is not.

    Returns a warning string when the directory is too open **or** when the
    check itself cannot run (SEC-33: no silent false negative).  Returns
    ``None`` only when the ACL is verified safe.
    """
    try:
        if not root.exists():
            return None
        if not _is_windows():
            mode = root.stat().st_mode & 0o077
            return f"mode {oct(root.stat().st_mode & 0o777)} lets group or others in" if mode else None
        import subprocess

        icacls = _validated_icacls()
        if icacls is None:
            return "icacls is not available; cannot verify ACL permissions"
        out = subprocess.run([str(icacls), str(root)], capture_output=True, text=True, timeout=20).stdout
        wide = ("Everyone", r"BUILTIN\Users", "Authenticated Users", r"NT AUTHORITY\INTERACTIVE")
        hits: list[str] = [w for w in wide if w.lower() in out.lower()]
        # Domain-local broad groups: any <DOMAIN>\Domain Users etc.
        _DOMAIN_BROAD = ("Domain Users", "Domain Computers", "Domain Guests")
        for dg in _DOMAIN_BROAD:
            if dg.lower() in out.lower():
                hits.append(dg)
        return f"the ACL grants access to {', '.join(hits)}" if hits else None
    except Exception:  # noqa: BLE001
        return "ACL check failed; cannot verify permissions"


def _secure_new_root(root: Path) -> None:
    """Windows: make a key home directory we just created user-only (best effort)."""
    if not _is_windows():
        return
    try:
        import getpass
        import subprocess

        icacls = _validated_icacls()
        user = getpass.getuser()
        if icacls is None or not user:
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
            if not _is_windows():
                # Create owner-only directories without a separate chmod:
                # set a restrictive umask so mkdir's mode argument takes
                # full effect (0o700 & ~0o077 == 0o700).
                saved = os.umask(0o077)
                try:
                    d.mkdir(mode=0o700, parents=True, exist_ok=True)
                finally:
                    os.umask(saved)
            else:
                d.mkdir(parents=True, exist_ok=True)
            if fresh:
                _secure_new_root(root)
        except OSError as exc:
            raise KeyHomeError(f"the key home is not writable: {exc}") from exc
    return d


# --- path test for the deny ----------------------------------------------------------------

def _norm(c: str) -> str:
    c = c.casefold()
    if c not in (".", ".."):
        c = c.rstrip(". ")
    return c


def strip_device(path: str) -> str:
    """Separators unified to ``/`` and the Windows device prefixes removed: the UNC form
    (backslash-backslash-?-backslash-UNC-backslash host) becomes ``//host``; the
    ``?``, ``.`` and NT ``??`` prefixes are dropped. Done before any glob split: the
    ``?`` in a prefix is not a glob."""
    p = path.replace("\\", "/")
    low = p.lower()
    for prefix in ("//?/unc/", "//./unc/", "/??/unc/"):
        if low.startswith(prefix):
            return "//" + p[len(prefix):]
    for prefix in ("//?/", "//./", "/??/"):
        if p.startswith(prefix):
            return p[len(prefix):]
    return p


def is_network_path(path: str) -> bool:
    """A UNC path. Never looked up: a dead host blocks for many seconds."""
    return os.name == "nt" and strip_device(path).startswith("//")


def _comps(path: str) -> list[str]:
    """Normalised components: case-folded, separators unified, ``.``/``..`` folded."""
    p = strip_device(path)
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
    p = strip_device(cand)
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
    if is_network_path(text):
        resolve = False
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


# --- pin management (ADR 0007 section 2) -------------------------------------------

import json as _json
from typing import Any as _Any

PINS_FILE = "pins.json"


def _pins_path(layout) -> Path:
    """``<key home>/<workspace id>/pins.json``. Raises KeyHomeError if no key home."""
    return workspace_key_dir(layout, create=True) / PINS_FILE


def read_pins(layout) -> dict[str, _Any]:
    """All pin entries for this workspace, keyed by reviewer id."""
    try:
        p = _pins_path(layout)
    except KeyHomeError:
        return {}
    try:
        return _json.loads(p.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}
    except (OSError, ValueError):
        return {}


def write_pin(layout, reviewer_id: str, public_key_hex: str) -> bool:
    """Pin *reviewer_id* to *public_key_hex* if not already pinned.

    Returns True if a new pin was written, False if the reviewer was already
    pinned (existing pin is never overwritten -- ADR 0007 2.1).
    """
    pins = read_pins(layout)
    if reviewer_id in pins:
        return False
    pins[reviewer_id] = {
        "public_key": public_key_hex,
        "workspace_root": str(layout.root),
        "pinned_at": time.time(),
        "retired_at": None,
    }
    p = _pins_path(layout)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(_json.dumps(pins, indent=2), encoding="utf-8")
    return True


def get_pinned_key(layout, reviewer_id: str) -> str | None:
    """The hex public key pinned for *reviewer_id*, or None if unpinned."""
    pins = read_pins(layout)
    entry = pins.get(reviewer_id)
    if entry is None:
        return None
    if entry.get("retired_at"):
        return None  # retired pins are not valid for new approvals
    return entry.get("public_key")


def pin_entry(layout, reviewer_id: str) -> dict[str, _Any] | None:
    """The full pin entry for *reviewer_id*, or None."""
    return read_pins(layout).get(reviewer_id)
