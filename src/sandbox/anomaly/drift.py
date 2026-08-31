"""Behavioral drift detection for agent sessions.

Compares live session activity against a frozen :class:`SessionBaseline`
to detect anomalous behavior that may indicate prompt injection,
privilege escalation, or other adversarial manipulation of the agent.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass, field

from sandbox.models.enums import AnomalyType

from .baseline import SessionBaseline


# ------------------------------------------------------------------
# Data structures
# ------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class DriftSignal:
    """One specific signal contributing to overall drift score."""

    signal_type: AnomalyType
    score: float  # 0.0 – 1.0
    evidence: str


@dataclass(frozen=True, slots=True)
class DriftScore:
    """Aggregate drift assessment for a single request."""

    overall_score: float  # 0.0 – 1.0
    signals: list[DriftSignal]
    recommended_action: str  # "none" | "upgrade_tier" | "hitl_escalate" | "kill_switch"


# ------------------------------------------------------------------
# Detector
# ------------------------------------------------------------------

class DriftDetector:
    """Score behavioural drift of an agent session relative to its baseline.

    Parameters
    ----------
    baseline:
        A **frozen** :class:`SessionBaseline`.
    hitl_threshold:
        Drift score at or above which a human-in-the-loop escalation is
        recommended.
    kill_threshold:
        Drift score at or above which an immediate session kill is
        recommended.
    """

    # Tuning knobs
    _KL_WEIGHT: float = 0.30
    _RESOURCE_WEIGHT: float = 0.25
    _PATH_TRAVERSAL_WEIGHT: float = 0.20
    _POLICY_PROBE_WEIGHT: float = 0.15
    _SCOPE_WEIGHT: float = 0.10

    def __init__(
        self,
        baseline: SessionBaseline,
        hitl_threshold: float = 0.7,
        kill_threshold: float = 0.95,
    ) -> None:
        if not baseline.frozen:
            raise ValueError("DriftDetector requires a frozen baseline.")

        self._baseline = baseline
        self._hitl_threshold = hitl_threshold
        self._kill_threshold = kill_threshold

        # Running session-level state
        self._session_action_counter: Counter[str] = Counter()
        self._session_total: int = 0
        self._consecutive_denies: int = 0
        self._last_deny_action: str | None = None
        self._previous_resources: list[str] = []

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def score_request(
        self,
        action_type: str,
        target_resource: str,
        session_state: dict,
    ) -> DriftScore:
        """Score a single incoming request for behavioural drift.

        Parameters
        ----------
        action_type:
            The ``ActionType`` value of the request.
        target_resource:
            The resource being targeted (file path, URL, secret name …).
        session_state:
            Dictionary carrying at least ``"last_decision"`` (the
            :class:`PolicyDecision` string of the most recent request).
            Additional keys are ignored today but reserved for future
            signal functions.

        Returns
        -------
        DriftScore
            Composite score plus per-signal breakdown and a recommended
            action string.
        """
        # Update internal running counters
        self._session_total += 1
        self._session_action_counter[action_type] += 1

        signals: list[DriftSignal] = []

        # 1 — Action distribution shift (KL divergence)
        sig = self._check_action_distribution()
        if sig is not None:
            signals.append(sig)

        # 2 — New resource outside known set
        sig = self._check_new_resource(target_resource)
        if sig is not None:
            signals.append(sig)

        # 3 — Path traversal patterns
        sig = self._check_path_traversal(target_resource)
        if sig is not None:
            signals.append(sig)

        # 4 — Policy probe (consecutive DENY'd requests)
        sig = self._check_policy_probe(action_type, session_state)
        if sig is not None:
            signals.append(sig)

        # 5 — Scope broadening
        sig = self._check_scope_broadening(target_resource)
        if sig is not None:
            signals.append(sig)

        # Track resource history for scope broadening
        if target_resource:
            self._previous_resources.append(target_resource)

        overall = self._aggregate(signals)
        action = self.get_recommended_action(
            DriftScore(
                overall_score=overall,
                signals=signals,
                recommended_action="",  # placeholder, computed below
            )
        )

        return DriftScore(
            overall_score=overall,
            signals=signals,
            recommended_action=action,
        )

    def get_recommended_action(self, score: DriftScore) -> str:
        """Map an aggregate drift score to a recommended action string.

        Returns
        -------
        str
            One of ``"none"``, ``"upgrade_tier"``,
            ``"hitl_escalate"``, or ``"kill_switch"``.
        """
        if score.overall_score >= self._kill_threshold:
            return "kill_switch"
        if score.overall_score >= self._hitl_threshold:
            return "hitl_escalate"
        if score.overall_score >= self._hitl_threshold * 0.5:
            return "upgrade_tier"
        return "none"

    # ------------------------------------------------------------------
    # Signal functions
    # ------------------------------------------------------------------

    def _check_action_distribution(self) -> DriftSignal | None:
        """KL divergence between baseline and current action distribution."""
        if self._session_total < 2:
            return None

        baseline_dist = self._baseline.action_distribution
        if not baseline_dist:
            return None

        # Build current distribution
        current_dist: dict[str, float] = {
            k: v / self._session_total
            for k, v in self._session_action_counter.items()
        }

        kl = self._kl_divergence(baseline_dist, current_dist)

        # Normalize KL to 0–1 via sigmoid-like mapping.  KL >= 2 maps
        # to ~0.96 which is past kill threshold for this signal alone.
        score = 1.0 - 1.0 / (1.0 + kl)

        if score < 0.05:
            return None

        return DriftSignal(
            signal_type=AnomalyType.ACTION_DRIFT,
            score=score,
            evidence=(
                f"KL divergence {kl:.3f} between baseline and current "
                f"action distribution (score={score:.2f})"
            ),
        )

    def _check_new_resource(self, target_resource: str) -> DriftSignal | None:
        """Flag resources not seen during the baseline window."""
        if not target_resource:
            return None

        known = self._baseline.resource_set
        if not known:
            return None  # baseline had no resources — can't compare

        if target_resource in known:
            return None

        # Score escalates with the fraction of session requests hitting
        # unknown resources.
        unknown_count = sum(
            1 for r in self._previous_resources if r not in known
        )
        # +1 for the current request
        unknown_count += 1
        ratio = unknown_count / max(self._session_total, 1)
        score = min(ratio * 1.5, 1.0)  # amplify slightly

        return DriftSignal(
            signal_type=AnomalyType.RESOURCE_DRIFT,
            score=score,
            evidence=(
                f"Resource '{target_resource}' not in baseline set of "
                f"{len(known)} resources ({unknown_count} unknown so far)"
            ),
        )

    def _check_path_traversal(self, target_resource: str) -> DriftSignal | None:
        """Detect ``../`` patterns or gradual directory climbing."""
        if not target_resource:
            return None

        # Explicit traversal sequences
        traversal_pattern = re.compile(r"(\.\.[/\\])")
        matches = traversal_pattern.findall(target_resource)
        if matches:
            depth = len(matches)
            score = min(0.5 + depth * 0.15, 1.0)
            return DriftSignal(
                signal_type=AnomalyType.PATH_TRAVERSAL,
                score=score,
                evidence=(
                    f"Path traversal detected: {depth} '../' segment(s) "
                    f"in '{target_resource}'"
                ),
            )

        # Gradual directory climbing across successive requests
        if len(self._previous_resources) >= 2:
            prev = self._previous_resources[-1]
            if self._is_parent_path(target_resource, prev):
                # Count how many consecutive requests have climbed
                climb_streak = 1
                for i in range(
                    len(self._previous_resources) - 1, 0, -1
                ):
                    if self._is_parent_path(
                        self._previous_resources[i],
                        self._previous_resources[i - 1],
                    ):
                        climb_streak += 1
                    else:
                        break
                if climb_streak >= 2:
                    score = min(0.3 + climb_streak * 0.2, 1.0)
                    return DriftSignal(
                        signal_type=AnomalyType.PATH_TRAVERSAL,
                        score=score,
                        evidence=(
                            f"Gradual directory climbing detected: "
                            f"{climb_streak} consecutive requests moving "
                            f"toward parent directories"
                        ),
                    )

        return None

    def _check_policy_probe(
        self,
        action_type: str,
        session_state: dict,
    ) -> DriftSignal | None:
        """Detect consecutive similar DENY'd requests (policy probing)."""
        last_decision = session_state.get("last_decision", "")

        if last_decision == "DENY":
            if action_type == self._last_deny_action:
                self._consecutive_denies += 1
            else:
                self._consecutive_denies = 1
                self._last_deny_action = action_type
        else:
            self._consecutive_denies = 0
            self._last_deny_action = None

        if self._consecutive_denies >= 3:
            score = min(0.5 + (self._consecutive_denies - 3) * 0.15, 1.0)
            return DriftSignal(
                signal_type=AnomalyType.POLICY_PROBE,
                score=score,
                evidence=(
                    f"{self._consecutive_denies} consecutive DENY'd "
                    f"'{self._last_deny_action}' requests — possible "
                    f"policy probing"
                ),
            )

        return None

    def _check_scope_broadening(
        self,
        target_resource: str,
    ) -> DriftSignal | None:
        """Detect each request being slightly more permissive than the last.

        Heuristic: resource paths that are strictly shorter (closer to
        root) or that target a broader wildcard / higher-privilege
        resource.
        """
        if not target_resource or len(self._previous_resources) < 2:
            return None

        broadening_count = 0
        for i in range(1, len(self._previous_resources)):
            curr = self._previous_resources[i]
            prev = self._previous_resources[i - 1]
            if self._is_broader(curr, prev):
                broadening_count += 1

        # Check current request against last recorded
        if self._is_broader(
            target_resource, self._previous_resources[-1]
        ):
            broadening_count += 1

        recent_window = min(len(self._previous_resources), 5)
        if recent_window == 0:
            return None

        ratio = broadening_count / recent_window
        if ratio < 0.5:
            return None

        score = min(ratio, 1.0)
        return DriftSignal(
            signal_type=AnomalyType.ACTION_DRIFT,
            score=score,
            evidence=(
                f"Scope broadening: {broadening_count} of last "
                f"{recent_window} requests moved toward broader access"
            ),
        )

    # ------------------------------------------------------------------
    # Aggregation
    # ------------------------------------------------------------------

    def _aggregate(self, signals: list[DriftSignal]) -> float:
        """Weighted aggregation of individual signal scores.

        Signals are weighted by type.  If multiple signals of the same
        type exist the maximum is taken before weighting.
        """
        weight_map: dict[AnomalyType, float] = {
            AnomalyType.ACTION_DRIFT: self._KL_WEIGHT,
            AnomalyType.RESOURCE_DRIFT: self._RESOURCE_WEIGHT,
            AnomalyType.PATH_TRAVERSAL: self._PATH_TRAVERSAL_WEIGHT,
            AnomalyType.POLICY_PROBE: self._POLICY_PROBE_WEIGHT,
        }

        if not signals:
            return 0.0

        # Group by type, take max score per type
        per_type: dict[AnomalyType, float] = {}
        for sig in signals:
            existing = per_type.get(sig.signal_type, 0.0)
            per_type[sig.signal_type] = max(existing, sig.score)

        weighted_sum = 0.0
        weight_sum = 0.0
        for anomaly_type, score in per_type.items():
            w = weight_map.get(anomaly_type, self._SCOPE_WEIGHT)
            weighted_sum += w * score
            weight_sum += w

        if weight_sum == 0.0:
            return 0.0

        # Normalize to 0–1
        return min(weighted_sum / weight_sum, 1.0)

    # ------------------------------------------------------------------
    # Utility helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _kl_divergence(
        p: dict[str, float],
        q: dict[str, float],
    ) -> float:
        """Compute KL(P || Q) with smoothing to avoid log(0).

        Uses additive (Laplace) smoothing: unseen categories in *Q* get
        a small epsilon probability mass.
        """
        epsilon = 1e-10
        all_keys = set(p) | set(q)

        kl = 0.0
        for key in all_keys:
            p_val = p.get(key, epsilon)
            q_val = q.get(key, epsilon)
            if p_val > 0:
                kl += p_val * math.log(p_val / q_val)

        return max(kl, 0.0)

    @staticmethod
    def _is_parent_path(resource: str, reference: str) -> bool:
        """Return *True* if *resource* is a parent directory of *reference*."""
        # Normalize separators
        r = resource.replace("\\", "/").rstrip("/")
        ref = reference.replace("\\", "/").rstrip("/")
        # A parent path is shorter and is a prefix of the child
        return len(r) < len(ref) and ref.startswith(r + "/")

    @staticmethod
    def _is_broader(current: str, previous: str) -> bool:
        """Heuristic: *current* targets a broader scope than *previous*.

        Broader means: shorter normalized path (closer to root), or
        contains wildcard characters where *previous* did not.
        """
        c = current.replace("\\", "/").rstrip("/")
        p = previous.replace("\\", "/").rstrip("/")

        # Wildcard expansion
        if ("*" in c or "?" in c) and "*" not in p and "?" not in p:
            return True

        # Shorter path = closer to root = broader
        c_depth = c.count("/")
        p_depth = p.count("/")
        if c_depth < p_depth:
            return True

        return False
