"""SHA-256 hash chain for tamper-evident audit logging.

Provides a linked chain of cryptographic hashes so that any mutation
of a prior record (insertion, deletion, or modification) is detectable.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import orjson

# Genesis constant -- a fixed starting point that anchors every chain.
_GENESIS_HASH = "0" * 64


class HashChain:
    """Append-only SHA-256 hash chain.

    Each link is the SHA-256 digest of ``previous_chain_hash || data``.
    Verification walks the chain from genesis and recomputes every link,
    failing on the first mismatch.
    """

    def __init__(
        self,
        previous_hash: str = _GENESIS_HASH,
        chain_length: int = 0,
    ) -> None:
        """Create a chain, optionally seeded from a persisted tail.

        ``previous_hash`` / ``chain_length`` let a fresh process resume an
        existing on-disk chain instead of restarting from genesis (which
        would silently fork the chain and fail verification). The seeded
        prefix is not re-materialized in ``_records`` — only new appends are
        tracked there — but ``chain_length`` reflects the true total.
        """
        self._previous_hash: str = previous_hash
        self._records: list[tuple[bytes, str]] = []  # (data, chain_hash)
        self._seeded_length: int = chain_length

    @classmethod
    def from_records_file(cls, path: str | Path) -> HashChain:
        """Rehydrate a chain from a ``records.jsonl`` file.

        Seeds from the last non-blank, JSON-parseable line's ``record_hash``.
        A torn final line (partial write) is tolerated: it is skipped and the
        previous valid record becomes the seed.
        """
        p = Path(path)
        if not p.exists():
            return cls()

        last_hash = _GENESIS_HASH
        count = 0
        with p.open("rb") as fh:
            for raw in fh:
                line = raw.strip()
                if not line:
                    continue
                try:
                    obj = orjson.loads(line)
                except orjson.JSONDecodeError:
                    # Torn/partial line (only ever the last one in practice).
                    continue
                h = obj.get("record_hash")
                if not h:
                    continue
                last_hash = h
                count += 1
        return cls(previous_hash=last_hash, chain_length=count)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def add(self, data: bytes) -> str:
        """Append *data* to the chain and return the new chain hash."""
        chain_hash = self._compute(self._previous_hash, data)
        self._records.append((data, chain_hash))
        self._previous_hash = chain_hash
        return chain_hash

    def verify(self, records: list[tuple[bytes, str]]) -> bool:
        """Verify *records* form a valid chain from genesis.

        Parameters
        ----------
        records:
            Sequence of ``(data, expected_chain_hash)`` tuples in append
            order.  Typically comes from the persisted log.

        Returns
        -------
        bool
            ``True`` when every recomputed hash matches its expected value.
        """
        previous = _GENESIS_HASH
        for data, expected_hash in records:
            computed = self._compute(previous, data)
            if computed != expected_hash:
                return False
            previous = computed
        return True

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def current_hash(self) -> str:
        """The most recent chain hash, or genesis if the chain is empty."""
        return self._previous_hash

    @property
    def chain_length(self) -> int:
        """Total records in the chain (seeded prefix + new appends)."""
        return self._seeded_length + len(self._records)

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    @staticmethod
    def _compute(previous_hash: str, data: bytes) -> str:
        """SHA-256( previous_hash_bytes || data )."""
        h = hashlib.sha256()
        h.update(previous_hash.encode("utf-8"))
        h.update(data)
        return h.hexdigest()
