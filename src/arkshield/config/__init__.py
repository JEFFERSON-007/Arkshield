"""
Arkshield Configuration System

Provides centralized configuration management and high-level environment
variable bindings for all Arkshield platform services, endpoints, and runtime engines.
"""

import os
from pathlib import Path
from typing import Optional

from arkshield.config.settings import (
    PlatformConfig,
    AgentConfig,
    TelemetryConfig,
    AIConfig,
    ResponseConfig,
    APIConfig,
    DashboardConfig,
    SecurityConfig,
)

# Standard Environment Variable Keys
ENV_DB_PATH = "ARKSHIELD_DB_PATH"
ENV_LOG_LEVEL = "ARKSHIELD_LOG_LEVEL"
ENV_API_HOST = "ARKSHIELD_API_HOST"
ENV_API_PORT = "ARKSHIELD_API_PORT"
ENV_API_KEY = "ARKSHIELD_API_KEY"
ENV_AUTONOMY_LEVEL = "ARKSHIELD_AUTONOMY_LEVEL"
ENV_CONFIG_PATH = "ARKSHIELD_CONFIG_PATH"

DEFAULT_API_KEY = "arkshield-dev-key-2026"
DEFAULT_DB_FILENAME = "sentinel.db"


def get_db_path(default_storage_path: Optional[str] = None) -> str:
    """Return the absolute path to the active Arkshield SQLite database."""
    env_path = os.environ.get(ENV_DB_PATH)
    if env_path:
        return str(Path(env_path).resolve())

    if default_storage_path:
        return str(Path(default_storage_path) / DEFAULT_DB_FILENAME)

    # Standard default in ~/.arkshield/data/sentinel.db
    base_dir = Path.home() / ".arkshield" / "data"
    return str((base_dir / DEFAULT_DB_FILENAME).resolve())


def get_log_level() -> str:
    """Return the configured logging level string (e.g., 'INFO', 'DEBUG', 'WARNING')."""
    return os.environ.get(ENV_LOG_LEVEL, "INFO").upper()


def get_api_host() -> str:
    """Return the bind host for the API server."""
    return os.environ.get(ENV_API_HOST, "127.0.0.1")


def get_api_port() -> int:
    """Return the bind port for the API server."""
    val = os.environ.get(ENV_API_PORT)
    if val:
        try:
            return int(val)
        except ValueError:
            pass
    return 8000


def get_api_key() -> str:
    """Return the expected API key for authentication."""
    return os.environ.get(ENV_API_KEY, DEFAULT_API_KEY)


def get_autonomy_level() -> int:
    """Return the autonomous response level (0=alert, 1=suggest, 2=confirm, 3=auto, 4=predictive)."""
    val = os.environ.get(ENV_AUTONOMY_LEVEL)
    if val:
        try:
            level = int(val)
            if 0 <= level <= 4:
                return level
        except ValueError:
            pass
    return 2


def get_platform_config(config_path: Optional[str] = None) -> PlatformConfig:
    """Load and return PlatformConfig with environment variable overrides applied."""
    resolved_path = config_path or os.environ.get(ENV_CONFIG_PATH)
    if resolved_path and Path(resolved_path).exists():
        return PlatformConfig.from_yaml(resolved_path)
    return PlatformConfig.default()


__all__ = [
    "PlatformConfig",
    "AgentConfig",
    "TelemetryConfig",
    "AIConfig",
    "ResponseConfig",
    "APIConfig",
    "DashboardConfig",
    "SecurityConfig",
    "get_db_path",
    "get_log_level",
    "get_api_host",
    "get_api_port",
    "get_api_key",
    "get_autonomy_level",
    "get_platform_config",
    "ENV_DB_PATH",
    "ENV_LOG_LEVEL",
    "ENV_API_HOST",
    "ENV_API_PORT",
    "ENV_API_KEY",
    "ENV_AUTONOMY_LEVEL",
    "ENV_CONFIG_PATH",
    "DEFAULT_API_KEY",
]
