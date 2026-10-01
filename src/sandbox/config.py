from __future__ import annotations

from pydantic import Field
from pydantic_settings import BaseSettings


class NATSSettings(BaseSettings):
    model_config = {"env_prefix": "NATS_"}
    url: str = "nats://localhost:4222"
    max_reconnect_attempts: int = 10
    reconnect_time_wait_seconds: float = 2.0


class RedisSettings(BaseSettings):
    model_config = {"env_prefix": "REDIS_"}
    url: str = "redis://localhost:6379/0"
    hitl_db: int = 1
    session_db: int = 2


class OPASettings(BaseSettings):
    model_config = {"env_prefix": "OPA_"}
    url: str = "http://localhost:8181"
    policy_path: str = "/v1/data/sandbox"
    bundle_path: str = "policies/rego"


class AuditSettings(BaseSettings):
    model_config = {"env_prefix": "AUDIT_"}
    log_dir: str = "./audit_logs"
    worm_endpoint: str | None = None
    chain_verify_interval_seconds: int = 300
    sink_heartbeat_seconds: int = 30
    write_latency_alert_ms: int = 500


class SessionSettings(BaseSettings):
    model_config = {"env_prefix": "SESSION_"}
    default_ttl_seconds: int = 1800
    max_ttl_seconds: int = 3600
    max_writes_per_session: int = 100
    max_requests_per_minute: int = 60
    capability_token_ttl_seconds: int = 900


class HITLSettings(BaseSettings):
    model_config = {"env_prefix": "HITL_"}
    high_timeout_seconds: int = 600
    critical_timeout_seconds: int = 300
    critical_irreversible_timeout_seconds: int = 180
    timeout_alert_threshold_pct: float = 5.0
    # Mount the Redis-backed review API (/api/v1/hitl). Off by default: it needs
    # a Redis server and its reviewer authentication is still a placeholder.
    # Unconfigured, every request to it crashed (HTTP 500).
    redis_api: bool = False


class ExecutorSettings(BaseSettings):
    model_config = {"env_prefix": "EXECUTOR_"}
    read_timeout_seconds: int = 30
    write_timeout_seconds: int = 30
    execute_timeout_seconds: int = 120
    max_memory_mb: int = 512
    max_pids: int = 32
    max_cpu_cores: int = 1
    sigterm_grace_seconds: int = 5


class AnomalySettings(BaseSettings):
    model_config = {"env_prefix": "ANOMALY_"}
    baseline_window_requests: int = 10
    baseline_window_seconds: int = 120
    rate_alert_sigma: float = 2.0
    rate_kill_sigma: float = 4.0
    drift_score_hitl_threshold: float = 0.7
    drift_score_kill_threshold: float = 0.95
    policy_probe_threshold: int = 3


class SnapshotSettings(BaseSettings):
    model_config = {"env_prefix": "SNAPSHOT_"}
    storage_dir: str = "./snapshots"
    max_session_size_bytes: int = 2 * 1024 * 1024 * 1024  # 2GB
    post_session_retention_seconds: int = 7200


class ContainmentSettings(BaseSettings):
    model_config = {"env_prefix": "CONTAINMENT_"}
    enable_docker: bool = True
    base_image: str = "python:3.12-slim"
    workspace_mount_root: str = "./workspaces"
    default_network: str = "none"
    pool_size: int = 0
    container_user: str = "1000:1000"
    read_only_rootfs: bool = True
    tmpfs_size_mb: int = 64


class LauncherSettings(BaseSettings):
    model_config = {"env_prefix": "LAUNCHER_"}
    jail_root: str = "./jails"
    jail_user: str = ""
    enforce_jail: bool = False
    shim_dir: str = "./shims"
    app_commands: dict[str, str] = Field(default_factory=dict)
    default_timeout: int = 3600
    max_memory_mb: int = 1024
    max_pids: int = 64


class TranslateSettings(BaseSettings):
    model_config = {"env_prefix": "TRANSLATE_"}
    provider: str = "template"
    xai_api_key: str = ""
    model: str = "grok-2"
    fallback_provider: str = "template"


class SandboxConfig(BaseSettings):
    """Root configuration aggregating all subsystem settings."""

    model_config = {"env_prefix": "SANDBOX_"}

    environment: str = Field(default="development")
    log_level: str = Field(default="INFO")
    api_host: str = Field(default="127.0.0.1")
    api_port: int = Field(default=8000)

    nats: NATSSettings = Field(default_factory=NATSSettings)
    redis: RedisSettings = Field(default_factory=RedisSettings)
    opa: OPASettings = Field(default_factory=OPASettings)
    audit: AuditSettings = Field(default_factory=AuditSettings)
    session: SessionSettings = Field(default_factory=SessionSettings)
    hitl: HITLSettings = Field(default_factory=HITLSettings)
    executor: ExecutorSettings = Field(default_factory=ExecutorSettings)
    anomaly: AnomalySettings = Field(default_factory=AnomalySettings)
    snapshot: SnapshotSettings = Field(default_factory=SnapshotSettings)
    containment: ContainmentSettings = Field(default_factory=ContainmentSettings)
    launcher: LauncherSettings = Field(default_factory=LauncherSettings)
    translate: TranslateSettings = Field(default_factory=TranslateSettings)
