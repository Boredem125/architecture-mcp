"""Reviewed files that skip the injection scan, pinned to their content hash.

Legitimate instructions to agents (AGENTS.md, CLAUDE.md, CONTRIBUTING.md)
read like injections to a zero-shot model, and it can't tell them apart from
malicious ones. A human can: once reviewed, a file is trusted while its content
is unchanged. Any edit (say, a pull request that slips a line into AGENTS.md)
changes the hash, and the file is scanned again.

The list lives in policy.json inside `.sandbox/`, which the agent cannot write.
"""
from __future__ import annotations

import hashlib
import time
from pathlib import Path

from sandbox.connector.policy import FolderPolicy, TrustedFile


def file_sha256(path: str | Path) -> str | None:
    try:
        return hashlib.sha256(Path(path).read_bytes()).hexdigest()
    except OSError:
        return None


def rel_key(root: str | Path, path: str | Path) -> str | None:
    """Path relative to the folder root with forward slashes, or None if outside it."""
    try:
        p = Path(path)
        if not p.is_absolute():
            p = Path(root) / p
        return p.resolve().relative_to(Path(root).resolve()).as_posix()
    except (ValueError, OSError):
        return None


def is_trusted(root: str | Path, policy: FolderPolicy, path: str | Path) -> bool:
    key = rel_key(root, path)
    if key is None:
        return False
    entry = next((t for t in policy.semantic.trusted_files if t.path == key), None)
    if entry is None:
        return False
    current = file_sha256(Path(root) / key)
    return current is not None and current == entry.sha256


def trust(root: str | Path, policy: FolderPolicy, path: str | Path, reviewer: str, reason: str) -> TrustedFile:
    key = rel_key(root, path)
    if key is None:
        raise ValueError(f"{path} is outside the folder")
    sha = file_sha256(Path(root) / key)
    if sha is None:
        raise ValueError(f"cannot read {path}")
    entry = TrustedFile(path=key, sha256=sha, reviewer=reviewer, reason=reason, approved_at=time.time())
    policy.semantic.trusted_files = [t for t in policy.semantic.trusted_files if t.path != key] + [entry]
    return entry


def untrust(root: str | Path, policy: FolderPolicy, path: str | Path) -> bool:
    key = rel_key(root, path)
    before = len(policy.semantic.trusted_files)
    policy.semantic.trusted_files = [t for t in policy.semantic.trusted_files if t.path != key]
    return len(policy.semantic.trusted_files) < before
