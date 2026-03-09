"""
Arkshield Configuration System

Centralized configuration management for all platform components.
Supports YAML configuration files with environment variable overrides.
"""

import os
import yaml
import logging
from dataclasses import dataclass, field
from typing import Dict, Any, Optional, List
from pathlib import Path

logger = logging.getLogger("arkshield.config")

DEFAULT_CONFIG_PATH = Path.home() / ".arkshield" / "config.yaml"


@dataclass
class AgentConfig:
    """Configuration for the endpoint agent."""
    agent_id: str = ""
    hostname: str = ""
    scan_interval: float = 5.0          # seconds between monitor cycles
    telemetry_batch_size: int = 100     # events per batch
    telemetry_flush_interval: float = 2.0  # seconds
    max_memory_mb: int = 256            # max agent memory usage
    max_cpu_percent: float = 5.0        # max CPU usage target
    offline_buffer_size: int = 10000    # events to buffer when offline
    log_level: str = "INFO"
    enabled_monitors: List[str] = field(default_factory=lambda: [
        "process", "filesystem", "network", "memory",
        "persistence", "integrity"
    ])


@dataclass
class TelemetryConfig:
    """Configuration for the telemetry pipeline."""
    pipeline_workers: int = 4
    normalization_enabled: bool = True
    enrichment_enabled: bool = True
    correlation_enabled: bool = True
    correlation_window_sec: int = 300    # 5-minute correlation window
    deduplication_window_sec: int = 60
    max_events_per_second: int = 10000
    storage_backend: str = "sqlite"      # sqlite, postgresql, or file
    storage_path: str = ""


@dataclass
class AIConfig:
    """Configuration for the AI analysis engine."""
    anomaly_detection_enabled: bool = True
    malware_classification_enabled: bool = True
    network_analysis_enabled: bool = True
    risk_scoring_enabled: bool = True
    threat_prediction_enabled: bool = True
    model_update_interval_hours: int = 24
    anomaly_threshold: float = 0.75      # anomaly score threshold
    min_training_samples: int = 100      # minimum samples before model trains
    behavioral_baseline_days: int = 14   # days to build baseline
    false_positive_learning: bool = True


@dataclass
class ResponseConfig:
    """Configuration for autonomous incident response."""
    autonomy_level: int = 2               # 0=alert, 1=suggest, 2=confirm, 3=auto, 4=predictive
    response_timeout_sec: int = 30        # timeout for human confirmation at level 2
    auto_quarantine: bool = True
    auto_isolate: bool = False            # network isolation requires explicit enable
    auto_kill_process: bool = True
    preserve_evidence: bool = True        # collect evidence before response
    max_concurrent_responses: int = 5
    playbook_directory: str = ""


@dataclass
class APIConfig:
    """Configuration for the API server."""
    host: str = "127.0.0.1"
    port: int = 8443
    enable_ssl: bool = True
    cors_origins: List[str] = field(default_factory=lambda: ["http://localhost:3000"])
    jwt_secret: str = ""
    jwt_expiry_minutes: int = 60
    rate_limit_per_minute: int = 100
    enable_websocket: bool = True
    api_key_header: str = "X-API-Key"


@dataclass
class DashboardConfig:
    """Configuration for the security dashboard."""
    host: str = "127.0.0.1"
    port: int = 3000
    refresh_interval_sec: int = 5
    max_alerts_displayed: int = 100
    enable_3d_visualization: bool = True
    theme: str = "dark"


@dataclass
class SecurityConfig:
    """Configuration for enterprise security features."""
    encryption_algorithm: str = "AES-256-GCM"
    key_rotation_days: int = 90
    audit_logging_enabled: bool = True
    zero_trust_enabled: bool = True
    rbac_enabled: bool = True
    mfa_required: bool = False
    session_timeout_minutes: int = 30
    max_failed_logins: int = 5
    lockout_duration_minutes: int = 15


@dataclass
class PlatformConfig:
    """Master configuration for the entire Arkshield platform."""
    agent: AgentConfig = field(default_factory=AgentConfig)
    telemetry: TelemetryConfig = field(default_factory=TelemetryConfig)
    ai: AIConfig = field(default_factory=AIConfig)
    response: ResponseConfig = field(default_factory=ResponseConfig)
    api: APIConfig = field(default_factory=APIConfig)
    dashboard: DashboardConfig = field(default_factory=DashboardConfig)
    security: SecurityConfig = field(default_factory=SecurityConfig)

    @classmethod
    def from_yaml(cls, path: str) -> "PlatformConfig":
        """Load configuration from a YAML file."""
        config = cls()
        filepath = Path(path)
        if filepath.exists():
            with open(filepath, "r") as f:
                data = yaml.safe_load(f) or {}
            config._apply_dict(data)
        config._apply_env_overrides()
        return config

    @classmethod
    def default(cls) -> "PlatformConfig":
        """Create default configuration."""
        import socket
        import uuid
        import secrets
        config = cls()
        config.agent.hostname = socket.gethostname()
        config.agent.agent_id = str(uuid.uuid4())
        base_dir = Path.home() / ".arkshield"
        config.telemetry.storage_path = str(base_dir / "data")
        config.response.playbook_directory = str(base_dir / "playbooks")
        
        # Auto-generate JWT secret for development (warn user to persist it)
        if not config.api.jwt_secret:
            config.api.jwt_secret = secrets.token_urlsafe(32)
            logger.warning(
                "Auto-generated JWT secret for development. "
                "For production, set NEXUS_API_JWT_SECRET environment variable "
                "or save config to ~/.arkshield/config.yaml"
            )
        
        return config

    def _apply_dict(self, data: Dict[str, Any]):
        """Apply a dictionary of configuration values."""
        for section_name, section_data in data.items():
            if hasattr(self, section_name) and isinstance(section_data, dict):
                section = getattr(self, section_name)
                for key, value in section_data.items():
                    if hasattr(section, key):
                        setattr(section, key, value)

    def _apply_env_overrides(self):
        """Apply environment variable overrides (NEXUS_ prefix)."""
        prefix = "NEXUS_"
        for key, value in os.environ.items():
            if key.startswith(prefix):
                parts = key[len(prefix):].lower().split("_", 1)
                if len(parts) == 2:
                    section_name, field_name = parts
                    if hasattr(self, section_name):
                        section = getattr(self, section_name)
                        if hasattr(section, field_name):
                            current = getattr(section, field_name)
                            try:
                                if isinstance(current, bool):
                                    setattr(section, field_name, value.lower() in ("true", "1", "yes"))
                                elif isinstance(current, int):
                                    setattr(section, field_name, int(value))
                                elif isinstance(current, float):
                                    setattr(section, field_name, float(value))
                                else:
                                    setattr(section, field_name, value)
                            except (ValueError, TypeError):
                                logger.warning(f"Invalid env override {key}={value}")

    def to_yaml(self, path: str):
        """Save configuration to a YAML file."""
        from dataclasses import asdict
        filepath = Path(path)
        filepath.parent.mkdir(parents=True, exist_ok=True)
        with open(filepath, "w") as f:
            yaml.dump(asdict(self), f, default_flow_style=False, sort_keys=False)
        logger.info(f"Configuration saved to {filepath}")

    def validate(self) -> List[str]:
        """Validate configuration and return list of issues."""
        issues = []
        warnings = []
        
        # Critical validation errors
        if not self.agent.agent_id:
            issues.append("Agent ID is not set")
        if self.agent.scan_interval < 1.0:
            issues.append("Scan interval too low (minimum 1 second)")
        if self.agent.max_memory_mb < 64:
            issues.append("Max memory too low (minimum 64 MB)")
        if self.response.autonomy_level not in range(5):
            issues.append("Invalid autonomy level (must be 0-4)")
        if self.api.port < 1 or self.api.port > 65535:
            issues.append("Invalid API port")
        
        # Production warnings (not blocking for dev)
        if not self.api.jwt_secret:
            warnings.append("JWT secret not set - auto-generating for development")
        if self.api.enable_ssl and self.api.host == "0.0.0.0":
            warnings.append("SSL enabled with wildcard host - consider specific interface")
        if self.response.autonomy_level >= 3 and not self.response.preserve_evidence:
            warnings.append("High autonomy without evidence preservation may limit forensics")
        
        # Log warnings separately (non-blocking)
        for warning in warnings:
            logger.info(f"Config notice: {warning}")
            
        return issues
