"""Request rate monitoring for agent sessions.

Tracks the rate of incoming requests using a sliding timestamp window
and compares against a baseline mean/std to flag anomalous spikes that
may indicate runaway loops, prompt injection, or denial-of-service
style resource exhaustion.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class RateStatus:
    """Snapshot of current rate relative to the baseline."""

    current_rate: float     # requests/minute in the last window
    baseline_mean: float    # mean requests/minute from baseline
    baseline_std: float     # std deviation from baseline
    sigma_distance: float   # how many sigma above the mean
    alert: bool             # True when sigma_distance >= alert_sigma
    kill: bool              # True when sigma_distance >= kill_sigma


class RateMonitor:
    """Sliding-window rate monitor with sigma-based alerting.

    Parameters
    ----------
    alert_sigma:
        Number of standard deviations above the baseline mean at which
        an alert is raised.
    kill_sigma:
        Number of standard deviations above the baseline mean at which
        an immediate session kill is recommended.
    """

    # Maximum age (seconds) of timestamps kept in the sliding window.
    _MAX_WINDOW_AGE: float = 300.0  # 5 minutes

    def __init__(
        self,
        alert_sigma: float = 2.0,
        kill_sigma: float = 4.0,
    ) -> None:
        if kill_sigma < alert_sigma:
            raise ValueError(
                f"kill_sigma ({kill_sigma}) must be >= alert_sigma "
                f"({alert_sigma})"
            )

        self._alert_sigma = alert_sigma
        self._kill_sigma = kill_sigma

        self._timestamps: deque[float] = deque()
        self._baseline_mean: float | None = None
        self._baseline_std: float | None = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def record_request(self, timestamp: float) -> None:
        """Record a request timestamp and evict stale entries."""
        self._timestamps.append(timestamp)
        self._evict(timestamp)

    def set_baseline(self, mean: float, std: float) -> None:
        """Set baseline rate statistics (from a frozen SessionBaseline).

        Parameters
        ----------
        mean:
            Mean requests per minute during the baseline window.
        std:
            Standard deviation of per-minute request rate during the
            baseline window.
        """
        if mean < 0:
            raise ValueError(f"Baseline mean must be non-negative, got {mean}")
        if std < 0:
            raise ValueError(f"Baseline std must be non-negative, got {std}")

        self._baseline_mean = mean
        self._baseline_std = std

    def current_rate(self, window_seconds: float = 60.0) -> float:
        """Return the current request rate (requests/minute) in the last *window_seconds*.

        Parameters
        ----------
        window_seconds:
            Look-back window in seconds.  Defaults to 60 (one minute).
        """
        if not self._timestamps:
            return 0.0

        now = self._timestamps[-1]
        cutoff = now - window_seconds
        count = sum(1 for ts in self._timestamps if ts > cutoff)

        # Normalize to requests per minute
        if window_seconds <= 0:
            return 0.0
        return count * (60.0 / window_seconds)

    def check(self) -> RateStatus:
        """Evaluate the current rate against the baseline.

        Returns
        -------
        RateStatus
            Snapshot with alert/kill booleans set based on sigma
            thresholds.

        Raises
        ------
        RuntimeError
            If no baseline has been set via :meth:`set_baseline`.
        """
        if self._baseline_mean is None or self._baseline_std is None:
            raise RuntimeError(
                "Baseline not set — call set_baseline() before check()."
            )

        rate = self.current_rate()

        # Compute sigma distance
        if self._baseline_std > 0:
            sigma = (rate - self._baseline_mean) / self._baseline_std
        else:
            # With zero std, any deviation is infinite sigma.  Use a
            # large sentinel when rate exceeds the mean.
            if rate > self._baseline_mean:
                sigma = float("inf")
            else:
                sigma = 0.0

        return RateStatus(
            current_rate=rate,
            baseline_mean=self._baseline_mean,
            baseline_std=self._baseline_std,
            sigma_distance=sigma,
            alert=sigma >= self._alert_sigma,
            kill=sigma >= self._kill_sigma,
        )

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _evict(self, now: float) -> None:
        """Remove timestamps older than ``_MAX_WINDOW_AGE`` seconds."""
        cutoff = now - self._MAX_WINDOW_AGE
        while self._timestamps and self._timestamps[0] < cutoff:
            self._timestamps.popleft()
