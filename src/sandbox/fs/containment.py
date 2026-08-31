"""The one true path-containment primitive.

Three copies of a prefix-compare containment check existed in the codebase
(``launcher/jail.py``, ``agents/tools.py``, ``containment/process_sandbox.py``),
each subtly wrong. This module replaces all of them.

Why a bare ``str.startswith`` / ``Path.is_relative_to`` is not enough:

* **Prefix aliasing** — ``C:\\jail\\abc`` is *not* inside ``C:\\jail\\ab``, but
  ``startswith`` on the string says it is. Comparison must be path-component
  aware.
* **Case-insensitive volumes** — on NTFS ``E:\\Proj`` and ``e:\\proj`` are the
  same directory, so comparison must go through ``os.path.normcase``.
* **Symlinks / junctions** — ``Path.resolve()`` only follows a reparse point
  when the path exists. For a target that does not exist yet (a file about to
  be created), we must walk the existing ancestor chain and reject any symlink
  or junction on the way, or an attacker pre-creates ``jail\\link -> C:\\`` and
  writes ``jail\\link\\evil``.
* **Exotic Windows paths** — UNC (``\\\\server\\share``), device namespaces
  (``\\\\?\\``, ``\\\\.\\``), NTFS alternate data streams (``file.txt:evil``),
  and drive-relative paths (``C:foo``, which resolves against the *current*
  directory of drive C:, not our root) all escape naive checks.

The public surface is deliberately tiny:

* ``resolve_under(root, target, *, base=None)`` → resolved ``Path`` or ``None``
* ``is_contained(root, target, *, base=None)`` → ``bool``
* ``has_reparse_point(root, resolved)`` → ``bool``
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

_WINDOWS = sys.platform == "win32"


class ContainmentError(ValueError):
    """Raised for structurally invalid paths (device/UNC/ADS/drive-relative)."""


def _normcase(p: Path) -> str:
    return os.path.normcase(str(p))


def _has_alternate_data_stream(raw: str) -> bool:
    """Detect an NTFS alternate data stream like ``file.txt:evil``.

    A drive letter (``C:\\...`` or ``C:foo``) legitimately contains a colon in
    position 1, so only colons *after* an optional ``X:`` drive prefix count.
    """
    if not _WINDOWS:
        return False
    rest = raw
    if len(raw) >= 2 and raw[1] == ":" and raw[0].isalpha():
        rest = raw[2:]  # strip the drive letter
    return ":" in rest


def _is_drive_relative(raw: str) -> bool:
    """``C:foo`` — a path relative to drive C:'s *current* directory.

    ``C:\\foo`` and ``C:/foo`` are absolute and fine; ``C:foo`` is the danger.
    """
    if not _WINDOWS:
        return False
    return (
        len(raw) >= 2
        and raw[1] == ":"
        and raw[0].isalpha()
        and (len(raw) == 2 or raw[2] not in ("\\", "/"))
    )


def _is_device_or_unc(raw: str) -> bool:
    """``\\\\?\\``, ``\\\\.\\`` device namespaces and ``\\\\server\\share`` UNC."""
    if not _WINDOWS:
        return False
    norm = raw.replace("/", "\\")
    return norm.startswith("\\\\")


def _reject_structural(raw: str) -> None:
    if _is_device_or_unc(raw):
        raise ContainmentError(f"UNC/device paths are not allowed: {raw!r}")
    if _is_drive_relative(raw):
        raise ContainmentError(f"Drive-relative paths are not allowed: {raw!r}")
    if _has_alternate_data_stream(raw):
        raise ContainmentError(f"Alternate data streams are not allowed: {raw!r}")


def has_reparse_point(root: Path, resolved: Path) -> bool:
    """True if any component from *root* down to *resolved* is a reparse point.

    ``Path.resolve`` collapses symlinks/junctions only for existing paths, so a
    non-existent target under a symlinked ancestor can slip through. We walk
    every existing ancestor between root and target and check for a reparse tag.
    """
    try:
        root_resolved = root.resolve(strict=False)
    except OSError:
        return True  # cannot resolve the root → treat as unsafe

    # Everything from resolved up to (and including) root_resolved.
    chain: list[Path] = [resolved]
    chain.extend(resolved.parents)

    for part in chain:
        if _normcase(part) == _normcase(root_resolved):
            break
        if not part.exists():
            continue
        try:
            if part.is_symlink():
                return True
            if _WINDOWS:
                # Junctions are reparse points but not symlinks; st_reparse_tag
                # is exposed via stat on 3.12+.
                st = part.stat(follow_symlinks=False)
                if getattr(st, "st_reparse_tag", 0):
                    return True
        except OSError:
            return True
    return False


def resolve_under(
    root: str | os.PathLike[str],
    target: str | os.PathLike[str],
    *,
    base: str | os.PathLike[str] | None = None,
) -> Path | None:
    """Resolve *target* and return it iff it lands inside *root*.

    Parameters
    ----------
    root:
        The containment boundary.
    target:
        A path from the agent — may be absolute or relative, may not exist yet.
    base:
        Directory that a *relative* target is joined against. Defaults to
        *root*. (For a tool call, this is usually the agent's cwd.)

    Returns
    -------
    Path | None
        The fully resolved absolute path when contained, else ``None``.
        Structurally invalid paths (UNC/device/ADS/drive-relative) also
        return ``None`` rather than raising, so callers can treat "unsafe"
        uniformly; use the lower-level checks if you need the distinction.
    """
    raw = os.fspath(target)
    try:
        _reject_structural(raw)
    except ContainmentError:
        return None

    root_path = Path(root)
    base_path = Path(base) if base is not None else root_path

    try:
        candidate = Path(raw)
        if not candidate.is_absolute():
            candidate = base_path / candidate
        resolved = candidate.resolve(strict=False)
        root_resolved = root_path.resolve(strict=False)
    except (OSError, ValueError):
        return None

    # Component-aware, case-normalized containment.
    resolved_nc = _normcase(resolved)
    root_nc = _normcase(root_resolved)
    if resolved_nc != root_nc:
        prefix = root_nc if root_nc.endswith(os.sep) else root_nc + os.sep
        if not resolved_nc.startswith(prefix):
            return None

    if has_reparse_point(root_resolved, resolved):
        return None

    return resolved


def is_contained(
    root: str | os.PathLike[str],
    target: str | os.PathLike[str],
    *,
    base: str | os.PathLike[str] | None = None,
) -> bool:
    """True iff *target* resolves to a path inside *root*."""
    return resolve_under(root, target, base=base) is not None
