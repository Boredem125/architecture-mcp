from __future__ import annotations

from pydantic import Field
from pydantic_settings import BaseSettings


class AuditSettings(BaseSettings):
    model_config = {"env_prefix": "AUDIT_"}
    log_dir: str = "./audit_logs"
    worm_endpoint: str | None = None
    chain_verify_interval_seconds: int = 300
    sink_heartbeat_seconds: int = 30
    write_latency_alert_ms: int = 500


class AnomalySettings(BaseSettings):
    model_config = {"env_prefix": "ANOMALY_"}
    baseline_window_requests: int = 10
    baseline_window_seconds: int = 120
    rate_alert_sigma: float = 2.0
    rate_kill_sigma: float = 4.0
    drift_score_hitl_threshold: float = 0.7
    drift_score_kill_threshold: float = 0.95
    policy_probe_threshold: int = 3


class SandboxConfig(BaseSettings):
    """Root configuration aggregating all subsystem settings."""

    model_config = {"env_prefix": "SANDBOX_"}

    environment: str = Field(default="development")
    log_level: str = Field(default="INFO")
    api_host: str = Field(default="127.0.0.1")
    api_port: int = Field(default=8000)

    audit: AuditSettings = Field(default_factory=AuditSettings)
    anomaly: AnomalySettings = Field(default_factory=AnomalySettings)
