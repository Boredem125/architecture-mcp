"""A small content-hash cache of injection-scan results.

Agents re-read the same files constantly, and each scan is ~0.2-0.8 s. Caching
by content hash makes a repeat scan of unchanged content free. The cache is
keyed by the text hash AND a fingerprint of the checks/model/threshold, so
changing any of those invalidates old entries automatically.

Correctness note: a cached "no finding" persists for the TTL, so if the model
or checks change, bump the fingerprint (they are part of the key) or let the
TTL expire. Within one deployment the model is fixed, so this is safe and only
speeds up repeated reads.
"""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

CACHE_FILE = "scan_cache.json"
MAX_ENTRIES = 2000


def _path(state_dir: Path) -> Path:
    return Path(state_dir) / CACHE_FILE


def _load(state_dir: Path) -> dict[str, Any]:
    try:
        return json.loads(_path(state_dir).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def get(state_dir: Path, key: str, ttl_seconds: int, now: float | None = None) -> tuple[bool, Any]:
    """(hit, value). value is the stored finding dict or None. Miss → (False, None)."""
    now = time.time() if now is None else now
    entry = _load(state_dir).get(key)
    if entry is None or float(entry.get("at", 0)) + ttl_seconds <= now:
        return False, None
    return True, entry.get("finding")


def put(state_dir: Path, key: str, finding: Any, now: float | None = None) -> None:
    now = time.time() if now is None else now
    data = _load(state_dir)
    data[key] = {"at": now, "finding": finding}
    if len(data) > MAX_ENTRIES:  # drop the oldest half
        for k in sorted(data, key=lambda k: data[k].get("at", 0))[: len(data) // 2]:
            del data[k]
    p = _path(state_dir)
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_suffix(".tmp")
        tmp.write_text(json.dumps(data), encoding="utf-8")
        tmp.replace(p)
    except OSError:
        pass


def key_for(text: str, checks: dict, threshold: float) -> str:
    import hashlib

    sig = json.dumps({"c": checks, "t": threshold}, sort_keys=True)
    return hashlib.sha256((sig + "\0" + text).encode("utf-8", "replace")).hexdigest()
