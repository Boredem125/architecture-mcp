from __future__ import annotations

import time

import structlog

from sandbox.agents.base import BaseAgent
from sandbox.anomaly.baseline import SessionBaseline
from sandbox.anomaly.drift import DriftDetector
from sandbox.anomaly.rate_monitor import RateMonitor
from sandbox.config import AnomalySettings
from sandbox.models.enums import AnomalyType, RiskTier
from sandbox.models.messages import AnomalySignal, KillSwitchEvent, MessageEnvelope

logger = structlog.get_logger()


class AnomalyDetectorAgent(BaseAgent):
    """A06 — Zone 2. Behavioral monitoring + kill switch.

    Watches entire session as a continuous stream. Catches threats that look
    legitimate request-by-request but are anomalous as a sequence.
    Stateful — maintains session baselines and event streams.
    """

    agent_name = "anomaly-detector"
    agent_version = "1.0.0"
    zone = 2
    pipeline_step = 6

    def __init__(self, settings: AnomalySettings | None = None) -> None:
        super().__init__()
        self._settings = settings or AnomalySettings()
        self._baselines: dict[str, SessionBaseline] = {}
        self._drift_detectors: dict[str, DriftDetector] = {}
        self._rate_monitors: dict[str, RateMonitor] = {}
        self._deny_history: dict[str, list[dict]] = {}

    async def process(self, envelope: MessageEnvelope) -> MessageEnvelope | None:
        payload = envelope.payload
        session_id = envelope.session_id
        request_id = envelope.request_id
        event_type = payload.get("event_type", "request")

        if event_type == "session_start":
            self._init_session(session_id)
            return None

        if event_type == "session_end":
            self._cleanup_session(session_id)
            return None

        if event_type == "deny":
            self._record_deny(session_id, payload)

        now = time.time()
        action_type = payload.get("action_type", "READ")
        target = payload.get("parameters", {}).get("path", "")

        baseline = self._baselines.get(session_id)
        if baseline is None:
            self._init_session(session_id)
            baseline = self._baselines[session_id]

        if not baseline.is_established():
            baseline.update(action_type, now, target)
            if baseline.is_established():
                baseline.freeze()
                rate_monitor = self._rate_monitors[session_id]
                rate_monitor.set_baseline(baseline.rate_mean, baseline.rate_std)
                drift_detector = DriftDetector(
                    baseline,
                    hitl_threshold=self._settings.drift_score_hitl_threshold,
                    kill_threshold=self._settings.drift_score_kill_threshold,
                )
                self._drift_detectors[session_id] = drift_detector
            return None

        rate_monitor = self._rate_monitors[session_id]
        rate_monitor.record_request(now)
        rate_status = rate_monitor.check()

        if rate_status.kill:
            logger.critical("kill_switch_rate", session_id=session_id, rate=rate_status.current_rate)
            return self._kill_switch(session_id, request_id, "Pipeline saturation attack detected")

        if rate_status.alert:
            logger.warning("rate_alert", session_id=session_id, rate=rate_status.current_rate)

        drift_detector = self._drift_detectors.get(session_id)
        if drift_detector is not None:
            session_state = {
                "action_type": action_type,
                "target_resource": target,
                "deny_history": self._deny_history.get(session_id, []),
            }
            drift_score = drift_detector.score_request(action_type, target, session_state)
            action = drift_detector.get_recommended_action(drift_score)

            if action == "kill_switch":
                logger.critical(
                    "kill_switch_drift",
                    session_id=session_id,
                    score=drift_score.overall_score,
                )
                return self._kill_switch(
                    session_id, request_id,
                    f"Sustained behavioral drift: score={drift_score.overall_score:.3f}"
                )

            if action == "hitl_escalate":
                signal = AnomalySignal(
                    session_id=session_id,
                    anomaly_type=AnomalyType.ACTION_DRIFT,
                    evidence_summary=f"Drift score {drift_score.overall_score:.3f}",
                    anomaly_score=drift_score.overall_score,
                    recommended_action="hitl_escalate",
                )
                logger.warning("anomaly_escalation", session_id=session_id, score=drift_score.overall_score)
                return self.create_envelope(
                    session_id=session_id,
                    request_id=request_id,
                    recipient="hitl-orchestrator",
                    payload=signal.model_dump(),
                )

            if action == "upgrade_tier":
                signal = AnomalySignal(
                    session_id=session_id,
                    anomaly_type=AnomalyType.ACTION_DRIFT,
                    evidence_summary=f"Tier upgrade recommended: score={drift_score.overall_score:.3f}",
                    anomaly_score=drift_score.overall_score,
                    recommended_action="upgrade_tier",
                )
                return self.create_envelope(
                    session_id=session_id,
                    request_id=request_id,
                    recipient="request-evaluator",
                    payload=signal.model_dump(),
                )

        return None

    def _init_session(self, session_id: str) -> None:
        self._baselines[session_id] = SessionBaseline(
            window_requests=self._settings.baseline_window_requests,
            window_seconds=self._settings.baseline_window_seconds,
        )
        self._rate_monitors[session_id] = RateMonitor(
            alert_sigma=self._settings.rate_alert_sigma,
            kill_sigma=self._settings.rate_kill_sigma,
        )
        self._deny_history[session_id] = []

    def _cleanup_session(self, session_id: str) -> None:
        self._baselines.pop(session_id, None)
        self._drift_detectors.pop(session_id, None)
        self._rate_monitors.pop(session_id, None)
        self._deny_history.pop(session_id, None)

    def _record_deny(self, session_id: str, payload: dict) -> None:
        history = self._deny_history.setdefault(session_id, [])
        history.append({
            "action_type": payload.get("action_type"),
            "parameters": payload.get("parameters", {}),
            "timestamp": time.time(),
        })

    def _kill_switch(
        self, session_id: str, request_id: str, reason: str
    ) -> MessageEnvelope:
        event = KillSwitchEvent(
            session_id=session_id,
            reason=reason,
            evidence={"triggered_by": self.agent_name},
        )
        return self.create_envelope(
            session_id=session_id,
            request_id=request_id,
            recipient="session-manager",
            payload={"kill_switch": True, **event.model_dump()},
        )
