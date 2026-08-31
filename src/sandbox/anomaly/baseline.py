"""Session baseline model for behavioral anomaly detection.

Captures the "normal" behavior of an agent session during its initial
window so that later requests can be compared against the established
baseline.  Once the baseline is frozen it becomes immutable — preventing
an attacker from gradually shifting what is considered normal.
"""

from __future__ import annotations

import math
import statistics
from collections import Counter
from dataclasses import dataclass, field


@dataclass
class _ActionRecord:
    """Internal record of a single action during the baseline window."""

    action_type: str
    timestamp: float
    target_resource: str


class SessionBaseline:
    """Builds and freezes a behavioral baseline for one agent session.

    Parameters
    ----------
    window_requests:
        Number of requests required before the baseline *may* be
        considered established.
    window_seconds:
        Elapsed seconds after the first update before the baseline *may*
        be considered established.
    """

    def __init__(
        self,
        window_requests: int = 10,
        window_seconds: float = 120.0,
    ) -> None:
        self._window_requests = window_requests
        self._window_seconds = window_seconds

        # Mutable collection phase
        self._records: list[_ActionRecord] = []
        self._action_counter: Counter[str] = Counter()
        self._resources: set[str] = set()
        self._first_ts: float | None = None
        self._last_ts: float | None = None

        # Frozen flag
        self._frozen: bool = False

        # Cached computed values (populated on freeze)
        self._rate_mean: float = 0.0
        self._rate_std: float = 0.0
        self._action_distribution: dict[str, float] = {}
        self._semantic_centroid: list[float] | None = None

    # ------------------------------------------------------------------
    # Collection API
    # ------------------------------------------------------------------

    def update(
        self,
        action_type: str,
        timestamp: float,
        target_resource: str = "",
    ) -> None:
        """Record a new action during the baseline window.

        Raises
        ------
        RuntimeError
            If the baseline has already been frozen.
        """
        if self._frozen:
            raise RuntimeError(
                "Cannot update a frozen baseline — call update() only "
                "before freeze()."
            )

        if self._first_ts is None:
            self._first_ts = timestamp

        self._last_ts = timestamp
        self._records.append(
            _ActionRecord(
                action_type=action_type,
                timestamp=timestamp,
                target_resource=target_resource,
            )
        )
        self._action_counter[action_type] += 1
        if target_resource:
            self._resources.add(target_resource)

    def is_established(self) -> bool:
        """Return *True* when enough data has been collected.

        The baseline is established when **either** ``window_requests``
        actions have been recorded **or** ``window_seconds`` have elapsed
        since the first action.
        """
        if not self._records:
            return False

        count_ok = len(self._records) >= self._window_requests

        assert self._first_ts is not None  # guaranteed by len > 0
        assert self._last_ts is not None
        time_ok = (self._last_ts - self._first_ts) >= self._window_seconds

        return count_ok or time_ok

    def freeze(self) -> None:
        """Lock the baseline so no further updates are accepted.

        Computes and caches the statistical summaries that downstream
        detectors rely on.

        Raises
        ------
        RuntimeError
            If there are fewer than 2 records (not enough data for
            meaningful statistics).
        """
        if self._frozen:
            return  # idempotent

        if len(self._records) < 2:
            raise RuntimeError(
                "Cannot freeze a baseline with fewer than 2 recorded "
                "actions — not enough data for meaningful statistics."
            )

        self._frozen = True
        self._compute_rate_stats()
        self._compute_action_distribution()
        # Semantic centroid left as placeholder for embedding integration.
        self._semantic_centroid = None

    # ------------------------------------------------------------------
    # Properties (only meaningful after freeze)
    # ------------------------------------------------------------------

    def _require_frozen(self) -> None:
        if not self._frozen:
            raise RuntimeError(
                "Baseline must be frozen before reading computed "
                "properties. Call freeze() first."
            )

    @property
    def rate_mean(self) -> float:
        """Mean requests per minute during the baseline window."""
        self._require_frozen()
        return self._rate_mean

    @property
    def rate_std(self) -> float:
        """Standard deviation of per-minute request rate."""
        self._require_frozen()
        return self._rate_std

    @property
    def action_distribution(self) -> dict[str, float]:
        """Normalized probability distribution of action types."""
        self._require_frozen()
        return dict(self._action_distribution)  # defensive copy

    @property
    def resource_set(self) -> set[str]:
        """Set of target resources contacted during the baseline window."""
        self._require_frozen()
        return set(self._resources)  # defensive copy

    @property
    def semantic_centroid(self) -> list[float] | None:
        """Placeholder for embedding-based semantic centroid.

        Returns *None* until an embedding provider is wired in.
        """
        self._require_frozen()
        return self._semantic_centroid

    @property
    def frozen(self) -> bool:
        """Whether the baseline has been frozen."""
        return self._frozen

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _compute_rate_stats(self) -> None:
        """Compute mean and std of requests/minute using 60-s buckets."""
        assert self._first_ts is not None
        assert self._last_ts is not None

        span = self._last_ts - self._first_ts
        if span <= 0:
            # All requests at the exact same timestamp — degenerate case.
            self._rate_mean = float(len(self._records))
            self._rate_std = 0.0
            return

        # Partition timestamps into 60-second buckets.
        bucket_size = 60.0
        num_buckets = max(1, math.ceil(span / bucket_size))
        buckets: list[int] = [0] * num_buckets

        for rec in self._records:
            idx = min(
                int((rec.timestamp - self._first_ts) / bucket_size),
                num_buckets - 1,
            )
            buckets[idx] += 1

        self._rate_mean = statistics.mean(buckets)
        if len(buckets) >= 2:
            self._rate_std = statistics.stdev(buckets)
        else:
            self._rate_std = 0.0

    def _compute_action_distribution(self) -> None:
        """Normalize action counts into a probability distribution."""
        total = sum(self._action_counter.values())
        if total == 0:
            self._action_distribution = {}
            return

        self._action_distribution = {
            action: count / total
            for action, count in self._action_counter.items()
        }
