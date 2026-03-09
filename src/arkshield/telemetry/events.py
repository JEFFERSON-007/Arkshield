"""
Arkshield — Telemetry Event Models

Unified event schema based on OCSF (Open Cybersecurity Schema Framework).
All security events are normalized into these structures.
"""

import uuid
import time
import json
import socket
import platform
from dataclasses import dataclass, field, asdict
from typing import Dict, Any, Optional, List
from enum import Enum, IntEnum
from datetime import datetime, timezone


class EventClass(str, Enum):
    """Top-level event classification."""
    PROCESS_ACTIVITY = "process_activity"
    FILE_ACTIVITY = "file_activity"
    NETWORK_ACTIVITY = "network_activity"
    MEMORY_ACTIVITY = "memory_activity"
    REGISTRY_ACTIVITY = "registry_activity"
    AUTHENTICATION = "authentication"
    SYSTEM_ACTIVITY = "system_activity"
    PERSISTENCE_ACTIVITY = "persistence_activity"
    INTEGRITY_CHECK = "integrity_check"
    THREAT_DETECTION = "threat_detection"
    RESPONSE_ACTION = "response_action"
    AGENT_STATUS = "agent_status"


class EventType(str, Enum):
    """Specific event types within each class."""
    # Process events
    PROCESS_LAUNCH = "process_launch"
    PROCESS_TERMINATE = "process_terminate"
    PROCESS_INJECTION = "process_injection"
    PROCESS_PRIVILEGE_CHANGE = "process_privilege_change"
    PROCESS_ANOMALY = "process_anomaly"

    # File events
    FILE_CREATE = "file_create"
    FILE_MODIFY = "file_modify"
    FILE_DELETE = "file_delete"
    FILE_RENAME = "file_rename"
    FILE_PERMISSION_CHANGE = "file_permission_change"
    FILE_ENTROPY_HIGH = "file_entropy_high"

    # Network events
    NETWORK_CONNECTION = "network_connection"
    NETWORK_LISTEN = "network_listen"
    NETWORK_DNS_QUERY = "network_dns_query"
    NETWORK_BEACON = "network_beacon"
    NETWORK_LATERAL_MOVEMENT = "network_lateral_movement"
    NETWORK_DATA_EXFILTRATION = "network_data_exfiltration"

    # Memory events
    MEMORY_INJECTION = "memory_injection"
    MEMORY_SHELLCODE = "memory_shellcode"
    MEMORY_SUSPICIOUS_ALLOC = "memory_suspicious_alloc"

    # Registry events (Windows)
    REGISTRY_CREATE = "registry_create"
    REGISTRY_MODIFY = "registry_modify"
    REGISTRY_DELETE = "registry_delete"

    # Persistence events
    PERSISTENCE_NEW = "persistence_new"
    PERSISTENCE_MODIFIED = "persistence_modified"
    PERSISTENCE_REMOVED = "persistence_removed"

    # Integrity events
    INTEGRITY_PASS = "integrity_pass"
    INTEGRITY_FAIL = "integrity_fail"
    INTEGRITY_DRIFT = "integrity_drift"

    # Threat detection events
    THREAT_MALWARE = "threat_malware"
    THREAT_ANOMALY = "threat_anomaly"
    THREAT_EXPLOIT = "threat_exploit"
    THREAT_RANSOMWARE = "threat_ransomware"
    THREAT_C2_COMMUNICATION = "threat_c2_communication"
    THREAT_INSIDER = "threat_insider"

    # Response action events
    RESPONSE_PROCESS_KILLED = "response_process_killed"
    RESPONSE_FILE_QUARANTINED = "response_file_quarantined"
    RESPONSE_HOST_ISOLATED = "response_host_isolated"
    RESPONSE_RULE_UPDATED = "response_rule_updated"

    # Agent events
    AGENT_START = "agent_start"
    AGENT_STOP = "agent_stop"
    AGENT_HEARTBEAT = "agent_heartbeat"
    AGENT_CONFIG_UPDATE = "agent_config_update"


class Severity(IntEnum):
    """Event severity levels."""
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class AlertStatus(str, Enum):
    """Alert lifecycle states."""
    NEW = "new"
    ACKNOWLEDGED = "acknowledged"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"
    SUPPRESSED = "suppressed"


@dataclass
class ProcessInfo:
    """Information about a process."""
    pid: int = 0
    name: str = ""
    path: str = ""
    cmd_line: str = ""
    hash_sha256: str = ""
    parent_pid: int = 0
    parent_name: str = ""
    user: str = ""
    integrity_level: str = ""
    start_time: float = 0.0
    cpu_percent: float = 0.0
    memory_mb: float = 0.0
    thread_count: int = 0
    open_files_count: int = 0
    network_connections: int = 0


@dataclass
class FileInfo:
    """Information about a file."""
    path: str = ""
    name: str = ""
    size_bytes: int = 0
    hash_sha256: str = ""
    hash_md5: str = ""
    created: float = 0.0
    modified: float = 0.0
    owner: str = ""
    permissions: str = ""
    entropy: float = 0.0
    is_executable: bool = False
    is_signed: bool = False
    signer: str = ""


@dataclass
class NetworkInfo:
    """Information about a network connection."""
    local_ip: str = ""
    local_port: int = 0
    remote_ip: str = ""
    remote_port: int = 0
    protocol: str = ""
    direction: str = ""  # inbound, outbound
    bytes_sent: int = 0
    bytes_received: int = 0
    pid: int = 0
    process_name: str = ""
    dns_query: str = ""
    tls_version: str = ""
    ja3_hash: str = ""
    status: str = ""  # established, listening, etc.


@dataclass
class MITREMapping:
    """MITRE ATT&CK technique mapping."""
    tactic: str = ""
    technique_id: str = ""
    technique_name: str = ""
    subtechnique_id: str = ""
    subtechnique_name: str = ""


@dataclass
class ThreatIntel:
    """Threat intelligence enrichment data."""
    matched_iocs: List[str] = field(default_factory=list)
    risk_score: float = 0.0
    threat_actor: str = ""
    campaign: str = ""
    malware_family: str = ""
    confidence: float = 0.0


@dataclass
class SourceInfo:
    """Source identification for events."""
    agent_id: str = ""
    hostname: str = ""
    os_type: str = ""
    os_version: str = ""
    ip_address: str = ""
    org_id: str = ""
    agent_version: str = ""

    @classmethod
    def from_local(cls, agent_id: str) -> "SourceInfo":
        """Create source info from local system."""
        return cls(
            agent_id=agent_id,
            hostname=socket.gethostname(),
            os_type=platform.system().lower(),
            os_version=platform.version(),
            ip_address=_get_local_ip(),
            agent_version="1.0.0"
        )


@dataclass
class SecurityEvent:
    """
    Universal security event — the fundamental unit of telemetry.
    All monitor modules produce SecurityEvents.
    """
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    event_class: str = EventClass.SYSTEM_ACTIVITY.value
    event_type: str = EventType.AGENT_HEARTBEAT.value
    severity: int = Severity.INFO.value
    description: str = ""

    # Source identification
    source: SourceInfo = field(default_factory=SourceInfo)

    # Event-specific data
    process: Optional[ProcessInfo] = None
    file: Optional[FileInfo] = None
    network: Optional[NetworkInfo] = None
    mitre: Optional[MITREMapping] = None
    threat_intel: Optional[ThreatIntel] = None

    # Additional context
    metadata: Dict[str, Any] = field(default_factory=dict)
    raw_data: str = ""
    tags: List[str] = field(default_factory=list)

    # Analysis results (filled by AI engine)
    anomaly_score: float = 0.0
    risk_score: float = 0.0
    is_threat: bool = False
    threat_category: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary, removing None values."""
        data = asdict(self)
        return {k: v for k, v in data.items() if v is not None}

    def to_json(self) -> str:
        """Serialize to JSON string."""
        return json.dumps(self.to_dict(), default=str)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SecurityEvent":
        """Deserialize from dictionary."""
        event = cls()
        for key, value in data.items():
            if hasattr(event, key):
                if key == "source" and isinstance(value, dict):
                    setattr(event, key, SourceInfo(**value))
                elif key == "process" and isinstance(value, dict):
                    setattr(event, key, ProcessInfo(**value))
                elif key == "file" and isinstance(value, dict):
                    setattr(event, key, FileInfo(**value))
                elif key == "network" and isinstance(value, dict):
                    setattr(event, key, NetworkInfo(**value))
                elif key == "mitre" and isinstance(value, dict):
                    setattr(event, key, MITREMapping(**value))
                elif key == "threat_intel" and isinstance(value, dict):
                    setattr(event, key, ThreatIntel(**value))
                else:
                    setattr(event, key, value)
        return event


@dataclass
class Alert:
    """Security alert generated from one or more correlated events."""
    alert_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = ""
    title: str = ""
    description: str = ""
    severity: int = Severity.MEDIUM.value
    status: str = AlertStatus.NEW.value
    category: str = ""

    # Related events
    event_ids: List[str] = field(default_factory=list)
    source_events: List[SecurityEvent] = field(default_factory=list)

    # Analysis
    risk_score: float = 0.0
    confidence: float = 0.0
    mitre: Optional[MITREMapping] = None
    threat_intel: Optional[ThreatIntel] = None

    # Response
    assigned_to: str = ""
    response_actions: List[str] = field(default_factory=list)
    resolution_notes: str = ""

    # Context
    affected_hosts: List[str] = field(default_factory=list)
    affected_users: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Alert":
        """Deserialize from dictionary, handling nested objects and lists."""
        alert = cls()
        for key, value in data.items():
            if hasattr(alert, key) and value is not None:
                if key == "mitre" and isinstance(value, dict):
                    setattr(alert, key, MITREMapping(**value))
                elif key == "threat_intel" and isinstance(value, dict):
                    setattr(alert, key, ThreatIntel(**value))
                elif key == "source_events" and isinstance(value, list):
                    events = [SecurityEvent.from_dict(e) if isinstance(e, dict) else e for e in value]
                    setattr(alert, key, events)
                else:
                    setattr(alert, key, value)
        return alert

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        data = asdict(self)
        return {k: v for k, v in data.items() if v is not None}

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), default=str)


@dataclass
class AgentHeartbeat:
    """Agent health and status report."""
    agent_id: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    hostname: str = ""
    status: str = "healthy"
    uptime_seconds: float = 0.0
    events_sent: int = 0
    events_queued: int = 0
    cpu_usage_percent: float = 0.0
    memory_usage_mb: float = 0.0
    monitors_active: List[str] = field(default_factory=list)
    last_detection_time: str = ""
    agent_version: str = "1.0.0"
    platform_connected: bool = True


def _get_local_ip() -> str:
    """Get the local IP address."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"
