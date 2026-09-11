from typing import List, Dict, Any, Optional
from pydantic import BaseModel

class AgentStatus(BaseModel):
    id: str
    status: str
    version: str
    monitors: List[str]
    uptime_seconds: int

class Stats(BaseModel):
    events_processed: int
    alerts_generated: int
    threats_detected: int
    security_score: float

class SystemSettingUpdate(BaseModel):
    setting: str
    value: Any

class AutoPrioritizeRequest(BaseModel):
    window_hours: int = 24
    alert_limit: int = 200
    include_resolved: bool = False
    max_results: int = 100

class ThreatHuntQueryRequest(BaseModel):
    query: str = ""
    event_class: str = ""
    event_type: str = ""
    min_risk_score: float = 0.0
    max_risk_score: float = 100.0
    min_anomaly_score: float = 0.0
    is_threat: Optional[bool] = None
    tags: List[str] = []
    attack_pattern: str = ""
    limit: int = 200

class ThreatHuntSaveRequest(BaseModel):
    name: str
    description: str = ""
    query: ThreatHuntQueryRequest

class SandboxAnalyzeRequest(BaseModel):
    file_path: str
    profile: str = "default"

class MalwareClassifyRequest(BaseModel):
    report_id: str = ""
    hash_sha256: str = ""
    file_name: str = ""
    extension: str = ""
    entropy: float = 0.0
    suspicious_strings: List[str] = []
    observed_behaviors: List[str] = []

class IntegrityWatchRequest(BaseModel):
    file_path: str
    criticality: str = "medium"
    notes: str = ""

class RansomwareSimulateRequest(BaseModel):
    target_label: str = "lab-sample"
    simulated_files: int = 50
    encryption_rate_per_minute: int = 120
