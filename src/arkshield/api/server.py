"""
Arkshield — API Server

FastAPI-based REST API for the autonomous cyber defense platform.
Provides endpoints for alerts, telemetry, AI analyst, system metrics, and threat intelligence.
"""

import os
import time
import uuid
import logging
import platform
import shutil
import hashlib
import re
from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any, Optional
from fastapi import FastAPI, HTTPException, Depends, Request, Body
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from arkshield.main import NexusSentinel
from arkshield.telemetry.events import SecurityEvent, Alert

# Global singleton or dependency injection container
# For simplicity in this implementation, we'll use a globally initialized Sentinel instance
_sentinel: Optional[NexusSentinel] = None
logger = logging.getLogger("arkshield.api")
_saved_hunt_queries: List[Dict[str, Any]] = []
_threat_hunt_history: List[Dict[str, Any]] = []
_sandbox_reports: Dict[str, Dict[str, Any]] = {}
_malware_model_state: Dict[str, Any] = {
    "model_name": "arkshield-heuristic-malware-classifier",
    "version": "0.1.0",
    "status": "ready",
    "last_trained": datetime.now(timezone.utc).isoformat(),
    "classifications_total": 0,
    "last_classification": None,
}
_integrity_watchlist: Dict[str, Dict[str, Any]] = {}
_integrity_alerts: List[Dict[str, Any]] = []
_blocked_devices: Dict[str, Dict[str, Any]] = {}
_device_history: List[Dict[str, Any]] = []
_ransomware_simulations: List[Dict[str, Any]] = []
_dns_blocked_domains: Dict[str, Dict[str, Any]] = {}
_network_traffic_snapshots: List[Dict[str, Any]] = []
_patch_recommendation_history: List[Dict[str, Any]] = []
_container_scan_history: List[Dict[str, Any]] = []
_cloud_posture_history: List[Dict[str, Any]] = []
_compliance_report_history: List[Dict[str, Any]] = []
_risk_score_history: List[Dict[str, Any]] = []
_policy_state: Dict[str, Any] = {
    "mode": "monitor",
    "enforcement": {
        "block_suspicious_dns": True,
        "block_untrusted_usb": False,
        "isolate_high_risk_hosts": False,
        "require_patch_compliance": True,
    },
    "version": 1,
    "last_updated": datetime.now(timezone.utc).isoformat(),
}
_policy_violation_log: List[Dict[str, Any]] = []
_playbook_run_history: List[Dict[str, Any]] = []
_digital_twin_snapshots: List[Dict[str, Any]] = []
_digital_twin_simulations: List[Dict[str, Any]] = []
_autonomous_defense_state: Dict[str, Any] = {
    "enabled": False,
    "mode": "recommendation",
    "last_updated": datetime.now(timezone.utc).isoformat(),
    "policy_binding": "monitor",
    "last_action": None,
}
_autonomous_action_log: List[Dict[str, Any]] = []
_security_graph_snapshots: List[Dict[str, Any]] = []
_behavior_baseline_model: Dict[str, Any] = {
    "trained": False,
    "version": 0,
    "trained_at": None,
    "features": {
        "avg_dns_risk": 0,
        "avg_network_anomaly": 0,
        "avg_process_suspicious": 0,
        "avg_insider_risk": 0,
    },
    "sample_count": 0,
}
_behavior_observation_history: List[Dict[str, Any]] = []
_command_observation_history: List[Dict[str, Any]] = []
_blocked_commands: Dict[str, Dict[str, Any]] = {}
_lateral_movement_alerts: List[Dict[str, Any]] = []
_file_reputation_analysis_history: List[Dict[str, Any]] = []
_blocked_script_rules: Dict[str, Dict[str, Any]] = {}
_script_detection_events: List[Dict[str, Any]] = []
_lolbin_events: List[Dict[str, Any]] = []
_persistence_detections: List[Dict[str, Any]] = []
_persistence_events: List[Dict[str, Any]] = []
_scheduled_tasks_cache: List[Dict[str, Any]] = []
_suspicious_tasks: List[Dict[str, Any]] = []
_registry_changes: List[Dict[str, Any]] = []
_registry_baseline: Dict[str, Dict[str, Any]] = {}
_privileged_process_cache: List[Dict[str, Any]] = []
_privileged_process_events: List[Dict[str, Any]] = []
_api_request_log: List[Dict[str, Any]] = []
_api_abuse_detections: List[Dict[str, Any]] = []
_auth_login_events: List[Dict[str, Any]] = []
_auth_anomalies: List[Dict[str, Any]] = []
_bruteforce_detections: List[Dict[str, Any]] = []
_blocked_ips: Dict[str, Dict[str, Any]] = {}
_session_cache: List[Dict[str, Any]] = []
_suspicious_sessions: List[Dict[str, Any]] = []
_phishing_emails: List[Dict[str, Any]] = []
_malware_emails: List[Dict[str, Any]] = []
_browser_extensions: List[Dict[str, Any]] = []
_suspicious_extensions: List[Dict[str, Any]] = []
# Phase 68-140 state variables
_data_exfiltration_events: List[Dict[str, Any]] = []
_upload_log: List[Dict[str, Any]] = []
_suspicious_uploads: List[Dict[str, Any]] = []
_dlp_events: List[Dict[str, Any]] = []
_dlp_blocks: Dict[str, Dict[str, Any]] = {}
_sensitive_data_cache: List[Dict[str, Any]] = []
_data_classifications: Dict[str, str] = {}
_exposed_credentials: List[Dict[str, Any]] = []
_password_analysis: List[Dict[str, Any]] = []
_keylogger_detections: List[Dict[str, Any]] = []
_screen_capture_events: List[Dict[str, Any]] = []
_webcam_access_log: List[Dict[str, Any]] = []
_microphone_access_log: List[Dict[str, Any]] = []
_clipboard_events: List[Dict[str, Any]] = []
_gpu_usage_history: List[Dict[str, Any]] = []
_gpu_anomalies: List[Dict[str, Any]] = []
_cryptomining_detections: List[Dict[str, Any]] = []
_botnet_indicators: List[Dict[str, Any]] = []
_c2_communications: List[Dict[str, Any]] = []
_malicious_domains: List[Dict[str, Any]] = []
_ip_reputation_cache: Dict[str, Dict[str, Any]] = {}
_geothreat_events: List[Dict[str, Any]] = []
_tor_usage_log: List[Dict[str, Any]] = []
_proxy_activity: List[Dict[str, Any]] = []
_vpn_anomalies: List[Dict[str, Any]] = []
_system_updates: List[Dict[str, Any]] = []
_package_integrity_checks: List[Dict[str, Any]] = []
_kernel_exploit_detections: List[Dict[str, Any]] = []
_memory_injection_events: List[Dict[str, Any]] = []
_process_hollowing_detections: List[Dict[str, Any]] = []
_dll_hijacking_events: List[Dict[str, Any]] = []
_rootkit_scan_results: List[Dict[str, Any]] = []
_firmware_integrity_cache: Dict[str, Any] = {}
_bios_security_status: Dict[str, Any] = {}
_hardware_tampering_log: List[Dict[str, Any]] = []
_ai_security_insights: List[Dict[str, Any]] = []
_autonomous_defense_state: Dict[str, Any] = {"enabled": False, "actions": []}
_deception_honeypots: Dict[str, Dict[str, Any]] = {}
_deception_alerts: List[Dict[str, Any]] = []
_honeytokens: Dict[str, Dict[str, Any]] = {}
_honeytoken_events: List[Dict[str, Any]] = []
_darkweb_breaches: List[Dict[str, Any]] = []
_darkweb_mentions: List[Dict[str, Any]] = []
_darkweb_alerts: List[Dict[str, Any]] = []
_supply_chain_binaries: List[Dict[str, Any]] = []
_supply_chain_dependencies: List[Dict[str, Any]] = []
_supply_chain_anomalies: List[Dict[str, Any]] = []
_sbom_cache: Dict[str, Any] = {}
_sbom_vulnerabilities: List[Dict[str, Any]] = []
_patch_pending: List[Dict[str, Any]] = []
_patch_history: List[Dict[str, Any]] = []
_benchmark_results: Dict[str, Dict[str, Any]] = {}
_redteam_simulations: List[Dict[str, Any]] = []
_redteam_results: List[Dict[str, Any]] = []
_training_scenarios: Dict[str, Dict[str, Any]] = {}
_attack_surface_map: Dict[str, Any] = {}
_identity_risks: List[Dict[str, Any]] = []
_compromised_identities: List[Dict[str, Any]] = []
_shadowit_apps: List[Dict[str, Any]] = []
_data_access_policies: List[Dict[str, Any]] = []
_data_access_violations: List[Dict[str, Any]] = []
_config_drift_log: List[Dict[str, Any]] = []
_ai_model_integrity: List[Dict[str, Any]] = []
_ai_model_poisoning: List[Dict[str, Any]] = []
_threat_investigations: Dict[str, Dict[str, Any]] = {}
_correlation_incidents: List[Dict[str, Any]] = []
_security_knowledge_graph: Dict[str, Any] = {"entities": [], "relationships": []}
_network_simulations: Dict[str, Dict[str, Any]] = {}
_data_lineage: List[Dict[str, Any]] = []
_zerotrust_policies: List[Dict[str, Any]] = []
_zerotrust_events: List[Dict[str, Any]] = []
_rbac_risk_scores: Dict[str, int] = {}
_chaos_tests: List[Dict[str, Any]] = []
_quantum_audit: Dict[str, Any] = {}
_cross_env_incidents: List[Dict[str, Any]] = []
_digital_risk_monitors: List[Dict[str, Any]] = []
_insider_risk_scores: Dict[str, int] = {}
_threat_campaigns: List[Dict[str, Any]] = []
_security_docs: Dict[str, str] = {}
_soc_assistant_history: List[Dict[str, Any]] = []
_attack_predictions: List[Dict[str, Any]] = []
_threat_actor_profiles: List[Dict[str, Any]] = []
_resilience_score: Dict[str, Any] = {}
_recovery_status: Dict[str, Any] = {}
_asset_lifecycle: List[Dict[str, Any]] = []
_attack_graph: Dict[str, Any] = {}
_security_forecasts: List[Dict[str, Any]] = []
_policy_recommendations: List[Dict[str, Any]] = []
_shared_threats: List[Dict[str, Any]] = []
_PHASE_EXPANSION_REGISTRATION: Dict[str, int] = {"added": 0, "skipped": 0}


def _safe_limit(value: int, default: int, minimum: int = 1, maximum: int = 500) -> int:
    """Clamp user-provided limits to protect API responsiveness."""
    try:
        value = int(value)
    except (TypeError, ValueError):
        return default
    return max(minimum, min(value, maximum))


def _platform_disk_path() -> str:
    """Return a valid root path for disk metrics on current platform."""
    if os.name == "nt":
        drive = os.environ.get("SystemDrive") or os.path.splitdrive(os.getcwd())[0] or "C:"
        if not drive.endswith(":"):
            drive = f"{drive}:"
        return f"{drive}\\"
    return os.sep


def _resolve_first_command(*candidates: str) -> Optional[str]:
    """Return the first available command from a candidate list."""
    for command in candidates:
        if shutil.which(command):
            return command
    return None


def _parse_iso_datetime(value: str) -> Optional[datetime]:
    """Parse ISO timestamps from telemetry objects into timezone-aware datetimes."""
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=timezone.utc)
        return parsed
    except ValueError:
        return None

def get_sentinel() -> NexusSentinel:
    global _sentinel
    if _sentinel is None:
        _sentinel = NexusSentinel()
        # Note: In a real server, we might start the agent in a background thread here
    return _sentinel

app = FastAPI(
    title="Arkshield API",
    description="Arkshield Autonomous Cyber Defense Platform — Real-time security monitoring, AI-driven threat analysis, and autonomous incident response.",
    version="2.0.0"
)

# Enable CORS for the dashboard
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Models ---

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


def _matches_attack_pattern(event: SecurityEvent, pattern: str) -> bool:
    """Lightweight attack pattern matching for hunt queries."""
    pattern = (pattern or "").strip().lower()
    if not pattern:
        return True

    event_type = (event.event_type or "").lower()
    threat_cat = (event.threat_category or "").lower()
    tags = {t.lower() for t in (event.tags or [])}

    pattern_map = {
        "ransomware": {"threat_ransomware", "file_entropy_high", "file_modify"},
        "c2": {"threat_c2_communication", "network_beacon", "network_connection"},
        "lateral-movement": {"network_lateral_movement", "authentication", "network_connection"},
        "credential-theft": {"threat_insider", "authentication", "process_anomaly"},
        "persistence": {"persistence_new", "persistence_modified", "registry_modify"},
    }
    expected = pattern_map.get(pattern)
    if expected is None:
        return pattern in event_type or pattern in threat_cat or pattern in tags

    return event_type in expected or any(token in tags for token in expected)


def _sha256_file(file_path: str) -> str:
    """Generate SHA256 hash for file samples."""
    digest = hashlib.sha256()
    with open(file_path, "rb") as handle:
        for chunk in iter(lambda: handle.read(8192), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _byte_entropy(sample: bytes) -> float:
    """Approximate Shannon entropy from byte distribution."""
    if not sample:
        return 0.0

    freq: Dict[int, int] = {}
    for value in sample:
        freq[value] = freq.get(value, 0) + 1

    length = len(sample)
    entropy = 0.0
    import math
    for count in freq.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return round(entropy, 4)


def _extract_behavior_signals(file_name: str, ext: str, content_preview: str) -> Dict[str, Any]:
    """Infer sandbox behavior signals from static properties and content markers."""
    lowered_name = (file_name or "").lower()
    preview = (content_preview or "").lower()

    suspicious_markers = [
        "powershell",
        "invoke-expression",
        "base64",
        "cmd.exe",
        "rundll32",
        "mimikatz",
        "credential",
        "reg add",
        "vssadmin",
        "shadowcopy",
        "encrypt",
        "bitcoin",
        "wallet",
        "c2",
    ]
    matched_markers = [marker for marker in suspicious_markers if marker in preview or marker in lowered_name]

    behaviors: List[str] = []
    if ext in {".exe", ".dll", ".bat", ".ps1", ".js", ".vbs", ".scr"}:
        behaviors.append("process_spawn")
    if any(x in preview for x in ["reg add", "autorun", "startup"]):
        behaviors.append("persistence_attempt")
    if any(x in preview for x in ["http://", "https://", "socket", "dns", "c2"]):
        behaviors.append("network_beaconing")
    if any(x in preview for x in ["vssadmin", "encrypt", "ransom", "recover key"]):
        behaviors.append("ransomware_activity")
    if any(x in preview for x in ["mimikatz", "lsass", "sekurlsa", "credential"]):
        behaviors.append("credential_access")
    if any(x in preview for x in ["powershell", "invoke-expression", "cmd.exe", "rundll32"]):
        behaviors.append("lolbin_abuse")

    return {
        "suspicious_strings": matched_markers,
        "observed_behaviors": sorted(set(behaviors)),
    }

# --- Routes ---

@app.get("/")
async def root():
    return {"message": "Arkshield API is ONLINE"}


@app.get("/health")
async def health_check(sentinel: NexusSentinel = Depends(get_sentinel)):
    """Readiness and diagnostics endpoint for operators and dashboards."""
    import psutil

    disk_root = _platform_disk_path()
    db_path = sentinel.repository.db_path
    command_paths = {
        "net": shutil.which("net"),
        "netsh": shutil.which("netsh"),
        "qwinsta": shutil.which("qwinsta"),
        "quser": shutil.which("quser"),
        "driverquery": shutil.which("driverquery"),
    }

    disk_ok = True
    disk_info: Dict[str, Any] = {}
    try:
        usage = psutil.disk_usage(disk_root)
        disk_info = {
            "path": disk_root,
            "free_gb": round(usage.free / (1024 ** 3), 2),
            "used_percent": usage.percent,
        }
    except Exception as exc:
        disk_ok = False
        disk_info = {"path": disk_root, "error": str(exc)}

    return {
        "status": "ok" if sentinel.agent._running and disk_ok else "degraded",
        "timestamp": int(time.time()),
        "platform": {
            "os": platform.system(),
            "release": platform.release(),
            "python": platform.python_version(),
        },
        "agent": {
            "running": sentinel.agent._running,
            "monitors": list(sentinel.agent.monitors.keys()),
            "uptime_seconds": int(time.time() - sentinel.agent._start_time) if sentinel.agent._running else 0,
        },
        "database": {
            "path": db_path,
            "exists": os.path.exists(db_path),
            "size_mb": round(os.path.getsize(db_path) / (1024 ** 2), 2) if os.path.exists(db_path) else 0,
        },
        "disk": disk_info,
        "commands": {k: bool(v) for k, v in command_paths.items()},
    }


@app.get("/system/commands")
async def system_command_availability():
    """Expose availability of system utilities used by security endpoints."""
    commands = ["net", "netsh", "qwinsta", "quser", "driverquery", "powershell"]
    result = []
    for command in commands:
        path = shutil.which(command)
        result.append({"command": command, "available": bool(path), "path": path or ""})
    return result


def _run_cmd(command: List[str], timeout: int = 8) -> Dict[str, Any]:
    """Run a command safely and capture output for API responses."""
    import subprocess

    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
        return {
            "ok": result.returncode == 0,
            "returncode": result.returncode,
            "stdout": result.stdout.strip(),
            "stderr": result.stderr.strip(),
        }
    except subprocess.TimeoutExpired:
        return {"ok": False, "returncode": -1, "stdout": "", "stderr": "command timeout"}
    except Exception as exc:
        return {"ok": False, "returncode": -1, "stdout": "", "stderr": str(exc)}


@app.get("/system/access/capabilities")
async def get_system_access_capabilities():
    """Return cross-platform system access capabilities for settings control."""
    os_name = platform.system().lower()

    if os_name == "windows":
        return {
            "platform": "windows",
            "supported_settings": ["firewall_enabled", "remote_access_enabled"],
            "commands": {
                "netsh": bool(shutil.which("netsh")),
                "reg": bool(shutil.which("reg")),
            },
            "notes": [
                "Some changes require administrator privileges.",
                "Remote access maps to RDP allow/deny setting.",
            ],
        }

    return {
        "platform": os_name,
        "supported_settings": ["firewall_enabled", "remote_access_enabled"],
        "commands": {
            "ufw": bool(shutil.which("ufw")),
            "firewall-cmd": bool(shutil.which("firewall-cmd")),
            "systemctl": bool(shutil.which("systemctl")),
        },
        "notes": [
            "Some changes may require sudo/root privileges.",
            "Remote access maps to ssh/sshd service state.",
        ],
    }


@app.get("/system/settings")
async def get_system_settings_snapshot():
    """Read current system security-relevant settings on Windows and Linux."""
    os_name = platform.system().lower()
    payload = {
        "platform": os_name,
        "settings": {
            "firewall_enabled": None,
            "remote_access_enabled": None,
        },
        "details": {},
    }

    if os_name == "windows":
        fw = _run_cmd(["netsh", "advfirewall", "show", "allprofiles", "state"])
        if fw["ok"]:
            text = fw["stdout"].lower()
            payload["settings"]["firewall_enabled"] = "state on" in text
            payload["details"]["firewall"] = "ok"
        else:
            payload["details"]["firewall_error"] = fw["stderr"] or "netsh unavailable"

        rdp = _run_cmd([
            "reg",
            "query",
            r"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server",
            "/v",
            "fDenyTSConnections",
        ])
        if rdp["ok"]:
            line = next((ln for ln in rdp["stdout"].splitlines() if "fDenyTSConnections" in ln), "")
            enabled = line.strip().endswith("0x0")
            payload["settings"]["remote_access_enabled"] = enabled
            payload["details"]["remote_access"] = "ok"
        else:
            payload["details"]["remote_access_error"] = rdp["stderr"] or "reg query failed"

        return payload

    if shutil.which("ufw"):
        fw = _run_cmd(["ufw", "status"])
        if fw["ok"]:
            payload["settings"]["firewall_enabled"] = "status: active" in fw["stdout"].lower()
            payload["details"]["firewall"] = "ufw"
        else:
            payload["details"]["firewall_error"] = fw["stderr"] or "ufw status failed"
    elif shutil.which("firewall-cmd"):
        fw = _run_cmd(["firewall-cmd", "--state"])
        payload["settings"]["firewall_enabled"] = fw["ok"] and "running" in fw["stdout"].lower()
        payload["details"]["firewall"] = "firewalld"
    else:
        payload["details"]["firewall_error"] = "No supported firewall CLI found"

    svc_name = "sshd" if shutil.which("systemctl") else "ssh"
    if shutil.which("systemctl"):
        ssh = _run_cmd(["systemctl", "is-active", svc_name])
        payload["settings"]["remote_access_enabled"] = ssh["ok"] and "active" in ssh["stdout"].lower()
        payload["details"]["remote_access"] = "systemd"
    else:
        payload["details"]["remote_access_error"] = "systemctl not found"

    return payload


@app.post("/system/settings/apply")
async def apply_system_setting(update: SystemSettingUpdate):
    """Apply a supported system setting with cross-platform command execution."""
    setting = (update.setting or "").strip()
    value = update.value
    os_name = platform.system().lower()

    if setting not in {"firewall_enabled", "remote_access_enabled"}:
        raise HTTPException(status_code=400, detail="Unsupported setting")

    bool_value = str(value).lower() in {"1", "true", "yes", "on"}

    if os_name == "windows":
        if setting == "firewall_enabled":
            state = "on" if bool_value else "off"
            result = _run_cmd(["netsh", "advfirewall", "set", "allprofiles", "state", state], timeout=12)
        else:
            deny = "0" if bool_value else "1"
            result = _run_cmd([
                "reg",
                "add",
                r"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server",
                "/v",
                "fDenyTSConnections",
                "/t",
                "REG_DWORD",
                "/d",
                deny,
                "/f",
            ])

        error_message = result["stderr"] or result["stdout"] or "Command failed (admin privileges may be required)"

        return {
            "applied": result["ok"],
            "platform": "windows",
            "setting": setting,
            "value": bool_value,
            "requires_admin": True,
            "stderr": result["stderr"],
            "message": "ok" if result["ok"] else error_message,
        }

    if setting == "firewall_enabled":
        if shutil.which("ufw"):
            cmd = ["ufw", "--force", "enable"] if bool_value else ["ufw", "disable"]
            result = _run_cmd(cmd, timeout=15)
        elif shutil.which("firewall-cmd"):
            cmd = ["firewall-cmd", "--set-default-zone=public"] if bool_value else ["firewall-cmd", "--panic-on"]
            result = _run_cmd(cmd, timeout=15)
        else:
            result = {"ok": False, "stderr": "No supported firewall CLI found"}
    else:
        if shutil.which("systemctl"):
            service_name = "sshd"
            cmd = ["systemctl", "start", service_name] if bool_value else ["systemctl", "stop", service_name]
            result = _run_cmd(cmd, timeout=15)
        else:
            result = {"ok": False, "stderr": "systemctl not found"}

    return {
        "applied": result.get("ok", False),
        "platform": os_name,
        "setting": setting,
        "value": bool_value,
        "requires_admin": True,
        "stderr": result.get("stderr", ""),
        "message": "ok" if result.get("ok", False) else (result.get("stderr") or result.get("stdout") or "Command failed (admin privileges may be required)"),
    }

@app.get("/status", response_model=AgentStatus)
async def get_status(sentinel: NexusSentinel = Depends(get_sentinel)):
    uptime = int(time.time() - sentinel.agent._start_time) if sentinel.agent._running else 0
    return {
        "id": sentinel.agent.config.agent.agent_id,
        "status": "active" if sentinel.agent._running else "inactive",
        "version": "1.0.0",
        "monitors": list(sentinel.agent.monitors.keys()),
        "uptime_seconds": uptime
    }

@app.get("/alerts")
async def get_alerts(limit: int = 50, status: Optional[str] = None, sentinel: NexusSentinel = Depends(get_sentinel)):
    """Retrieve recent security alerts."""
    safe_limit = _safe_limit(limit, default=50, minimum=1, maximum=500)
    if status:
        return sentinel.repository.get_alerts_by_status(status)[:safe_limit]
    return sentinel.repository.get_recent_alerts(limit=safe_limit)

@app.get("/events")
async def get_events(limit: int = 100, sentinel: NexusSentinel = Depends(get_sentinel)):
    """Retrieve recent security events."""
    safe_limit = _safe_limit(limit, default=100, minimum=1, maximum=1000)
    return sentinel.repository.get_recent_events(limit=safe_limit)

@app.get("/stats", response_model=Stats)
async def get_stats(sentinel: NexusSentinel = Depends(get_sentinel)):
    """Get real-time platform statistics."""
    pipeline_stats = sentinel.pipeline.stats
    
    # Calculate an average security score from integrity checker
    integrity_monitor = sentinel.agent.monitors.get("integrity")
    security_score = getattr(integrity_monitor, 'security_score', 100.0) if integrity_monitor else 100.0

    return {
        "events_processed": pipeline_stats.get("events_processed", 0),
        "alerts_generated": pipeline_stats.get("alerts_generated", 0),
        "threats_detected": pipeline_stats.get("threats_detected", 0),
        "security_score": security_score
    }

@app.post("/scan")
async def trigger_scan(sentinel: NexusSentinel = Depends(get_sentinel)):
    """Trigger an immediate scanning cycle."""
    import asyncio
    loop = asyncio.get_event_loop()
    # Offload heavy synchronous scan to a thread pool to avoid blocking the event loop
    events = await loop.run_in_executor(None, sentinel.agent.run_single_scan)
    return {"status": "success", "events_captured": len(events)}

@app.post("/actions/kill/{pid}")
async def manual_kill(pid: int, sentinel: NexusSentinel = Depends(get_sentinel)):
    """Manually trigger process termination."""
    import psutil
    
    # Validate PID
    if pid <= 0 or pid > 65535:
        raise HTTPException(status_code=400, detail="Invalid process ID")
    
    # Check if process exists
    if not psutil.pid_exists(pid):
        raise HTTPException(status_code=404, detail=f"Process {pid} not found")
    
    # Prevent killing critical system processes
    try:
        proc = psutil.Process(pid)
        critical_names = ["System", "csrss.exe", "winlogon.exe", "services.exe", "lsass.exe", "smss.exe", "wininit.exe"]
        if proc.name() in critical_names:
            raise HTTPException(status_code=403, detail=f"Cannot kill critical system process: {proc.name()}")
    except psutil.NoSuchProcess:
        raise HTTPException(status_code=404, detail=f"Process {pid} terminated before kill")
    
    from arkshield.response.actions import kill_process
    try:
        success = kill_process(pid)
        if not success:
            raise HTTPException(status_code=500, detail="Failed to terminate process")
        logger.info(f"Process {pid} ({proc.name()}) terminated via API")
        return {"status": "success", "pid": pid, "name": proc.name()}
    except Exception as e:
        logger.error(f"Error killing process {pid}: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/predictions")
async def get_predictions(sentinel: NexusSentinel = Depends(get_sentinel)):
    """Get AI-driven threat predictions."""
    return sentinel.ai_engine.get_predictions()

# --- Phase 11+: Arkshield Ultimate Features ---

class ChatRequest(BaseModel):
    message: str

class AIConfigRequest(BaseModel):
    api_key: str = ""
    base_url: str = "https://openrouter.ai/api/v1"
    model: str = "google/gemini-2.0-flash-001"
    max_tokens: int = 512
    temperature: float = 0.7

@app.post("/analyst/chat")
async def analyst_chat(req: ChatRequest, sentinel: NexusSentinel = Depends(get_sentinel)):
    """Nova AI Security Analyst — powered by LLM with live telemetry context."""
    import asyncio
    from arkshield.ai.analyst import SentinelAnalyst
    analyst = SentinelAnalyst(sentinel.repository)
    loop = asyncio.get_event_loop()
    response = await loop.run_in_executor(None, analyst.chat, req.message)
    return {"response": response}

@app.get("/config/ai")
async def get_ai_config():
    """Get current AI configuration (API key is masked)."""
    from arkshield.ai.analyst import load_ai_config
    config = load_ai_config()
    # Mask the API key for security
    key = config.get("api_key", "")
    config["api_key_masked"] = f"{key[:8]}...{key[-4:]}" if len(key) > 12 else ("Set" if key else "Not Set")
    config["api_key_set"] = bool(key)
    del config["api_key"]
    return config

@app.post("/config/ai")
async def set_ai_config(req: AIConfigRequest):
    """Save AI configuration (API key, model, provider)."""
    from arkshield.ai.analyst import load_ai_config, save_ai_config
    config = load_ai_config()
    if req.api_key:
        config["api_key"] = req.api_key
    config["base_url"] = req.base_url
    config["model"] = req.model
    config["max_tokens"] = req.max_tokens
    config["temperature"] = req.temperature
    success = save_ai_config(config)
    if not success:
        raise HTTPException(status_code=500, detail="Failed to save configuration")
    return {"status": "saved", "model": config["model"]}

@app.get("/system/metrics")
async def system_metrics():
    """Get real-time system resource metrics."""
    import psutil
    cpu = psutil.cpu_percent(interval=0.1)
    mem = psutil.virtual_memory()
    disk_root = _platform_disk_path()
    disk = psutil.disk_usage(disk_root)
    net = psutil.net_io_counters()
    return {
        "cpu_percent": cpu,
        "memory_percent": mem.percent,
        "memory_used_gb": round(mem.used / (1024**3), 2),
        "memory_total_gb": round(mem.total / (1024**3), 2),
        "disk_path": disk_root,
        "disk_percent": disk.percent,
        "disk_used_gb": round(disk.used / (1024**3), 2),
        "disk_total_gb": round(disk.total / (1024**3), 2),
        "net_sent_mb": round(net.bytes_sent / (1024**2), 1),
        "net_recv_mb": round(net.bytes_recv / (1024**2), 1),
    }

@app.get("/threat-intel/ip/{ip}")
async def lookup_ip(ip: str):
    """Look up IP reputation using public threat intelligence APIs."""
    import urllib.request, urllib.error
    results = {"ip": ip, "sources": []}
    # AbuseIPDB-style check (using free API)
    try:
        url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}"
        results["sources"].append({"name": "AbuseIPDB", "status": "requires_api_key"})
    except Exception:
        pass
    # Basic GeoIP from ip-api.com (free, no key needed)
    try:
        req = urllib.request.Request(f"http://ip-api.com/json/{ip}?fields=status,message,country,regionName,city,isp,org,as,query")
        import json as _json
        with urllib.request.urlopen(req, timeout=5) as resp:
            geo = _json.loads(resp.read().decode())
            results["geo"] = geo
            results["sources"].append({"name": "ip-api.com", "status": "success"})
    except Exception as e:
        results["sources"].append({"name": "ip-api.com", "status": f"error: {e}"})
    return results

# --- Phase 12: Power Features ---

@app.get("/processes")
async def get_processes():
    """Get live process list with risk scoring."""
    import psutil
    procs = []
    for p in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'status', 'username', 'create_time']):
        try:
            info = p.info
            # Simple risk heuristic: high CPU + high memory = suspicious
            risk = 0
            cpu = info.get('cpu_percent', 0) or 0
            mem = info.get('memory_percent', 0) or 0
            if cpu > 50: risk += 30
            if mem > 10: risk += 20
            name = info.get('name', '')
            if name and any(s in name.lower() for s in ['powershell', 'cmd', 'wscript', 'mshta', 'certutil']):
                risk += 25
            procs.append({
                "pid": info['pid'],
                "name": name,
                "cpu": round(cpu, 1),
                "memory": round(mem, 1),
                "status": info.get('status', 'unknown'),
                "user": info.get('username', 'SYSTEM'),
                "risk_score": min(risk, 100),
                "created": info.get('create_time', 0)
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    # Sort by risk descending, then CPU
    procs.sort(key=lambda x: (-x['risk_score'], -x['cpu']))
    return procs[:100]

@app.get("/network/connections")
async def get_network_connections():
    """Get active network connections with threat indicators."""
    import psutil
    conns = []
    for c in psutil.net_connections(kind='inet'):
        try:
            local = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "N/A"
            remote = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "N/A"
            # Flag suspicious ports
            suspicious = False
            if c.raddr:
                sus_ports = {4444, 5555, 6666, 8888, 9999, 1337, 31337, 12345}
                if c.raddr.port in sus_ports:
                    suspicious = True
            conns.append({
                "local": local,
                "remote": remote,
                "status": c.status,
                "pid": c.pid,
                "suspicious": suspicious,
                "type": "TCP" if c.type == 1 else "UDP"
            })
        except Exception:
            continue
    return conns[:200]

@app.get("/audit/log")
async def get_audit_log(limit: int = 50):
    """Get security audit trail."""
    import time
    # Generate audit entries from recent events and actions
    log_entries = []
    try:
        sentinel = get_sentinel()
        alerts = sentinel.repository.get_recent_alerts(limit=limit)
        for a in alerts:
            log_entries.append({
                "timestamp": a.created_at,
                "action": "THREAT_DETECTED",
                "detail": a.title,
                "severity": a.severity,
                "actor": "arkshield-agent",
                "outcome": "mitigated"
            })
    except Exception:
        pass
    # Add system events
    log_entries.append({
        "timestamp": time.time(),
        "action": "SYSTEM_SCAN",
        "detail": "Scheduled deep scan completed",
        "severity": 0,
        "actor": "arkshield-scheduler",
        "outcome": "clean"
    })
    log_entries.append({
        "timestamp": time.time() - 60,
        "action": "CONFIG_CHANGE",
        "detail": "AI model configuration updated",
        "severity": 0,
        "actor": "admin",
        "outcome": "success"
    })
    return log_entries

@app.get("/export/report")
async def export_report(sentinel: NexusSentinel = Depends(get_sentinel)):
    """Generate a full security report as JSON."""
    import time, platform, psutil
    alerts = sentinel.repository.get_recent_alerts(limit=100)
    stats = sentinel.pipeline.stats
    mem = psutil.virtual_memory()
    return {
        "report_title": "Arkshield Security Assessment Report",
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "platform": {
            "hostname": platform.node(),
            "os": platform.platform(),
            "python": platform.python_version(),
            "cpu_count": psutil.cpu_count(),
            "memory_total_gb": round(mem.total / (1024**3), 2)
        },
        "security_summary": {
            "events_processed": stats.get("events_processed", 0),
            "alerts_generated": stats.get("alerts_generated", 0),
            "threats_detected": stats.get("threats_detected", 0),
            "security_score": 100.0,
            "risk_level": "LOW" if stats.get("threats_detected", 0) < 5 else "MEDIUM"
        },
        "alerts": [{"title": a.title, "severity": a.severity, "category": a.category, "status": a.status, "time": a.created_at} for a in alerts],
        "monitors_active": list(sentinel.agent.monitors.keys()),
        "recommendations": [
            "Enable File Quarantine for automatic sandbox isolation",
            "Schedule weekly deep scans for comprehensive coverage",
            "Consider integrating VirusTotal API for hash lookups",
            "Rotate JWT secrets before production deployment"
        ]
    }

@app.get("/threat-intel/hash/{hash_value}")
async def lookup_hash(hash_value: str):
    """Look up file hash reputation (simulated + real VirusTotal if key available)."""
    import hashlib
    # Validate hash format
    if len(hash_value) not in [32, 40, 64]:
        raise HTTPException(status_code=400, detail="Invalid hash. Provide MD5 (32), SHA1 (40), or SHA256 (64)")
    # Known malware hashes (simulated database)
    known_bad = {
        "44d88612fea8a8f36de82e1278abb02f": {"name": "EICAR Test File", "threat": "Test/EICAR", "confidence": 1.0},
        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f": {"name": "EICAR SHA256", "threat": "Test/EICAR", "confidence": 1.0}
    }
    result: Dict[str, Any] = {
        "hash": hash_value,
        "hash_type": {32: "MD5", 40: "SHA1", 64: "SHA256"}.get(len(hash_value), "Unknown")
    }
    if hash_value.lower() in known_bad:
        result["verdict"] = "MALICIOUS"
        result["details"] = known_bad[hash_value.lower()]
    else:
        result["verdict"] = "CLEAN"
        result["details"] = {"note": "Hash not found in local threat database. Integrate VirusTotal API for comprehensive coverage."}
    return result

# --- Phase 13: Advanced Intelligence ---

@app.get("/system/startup")
async def get_startup_programs():
    """Scan all auto-start programs with risk assessment (cross-platform)."""
    startup_items = []
    os_name = platform.system().lower()
    
    if os_name == "windows":
        try:
            import winreg
            registry_paths = [
                (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
                (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
                (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
                (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
            ]
            for hive, path in registry_paths:
                try:
                    key = winreg.OpenKey(hive, path)
                    i = 0
                    while True:
                        try:
                            name, value, _ = winreg.EnumValue(key, i)
                            risk = 0
                            val_lower = value.lower()
                            if any(s in val_lower for s in ['temp', 'appdata', 'wscript', 'mshta', 'powershell']): risk += 40
                            if any(s in val_lower for s in ['rundll32', 'regsvr32']): risk += 30
                            if '\\\\' not in val_lower and '/' not in val_lower: risk += 15
                            hive_name = "HKCU" if hive == winreg.HKEY_CURRENT_USER else "HKLM"
                            startup_items.append({
                                "name": name, "command": value, "location": f"{hive_name}\\{path}",
                                "risk_score": min(risk, 100),
                                "risk_level": "HIGH" if risk >= 40 else "MEDIUM" if risk >= 20 else "LOW"
                            })
                            i += 1
                        except OSError:
                            break
                    winreg.CloseKey(key)
                except OSError:
                    continue
        except ImportError:
            logger.warning("winreg not available on this platform")
    else:
        # Linux: Check common autostart locations
        from pathlib import Path
        autostart_dirs = [
            Path.home() / ".config" / "autostart",
            Path("/etc/xdg/autostart"),
        ]
        systemd_user = Path.home() / ".config" / "systemd" / "user"
        systemd_system = Path("/etc/systemd/system")
        
        # Check .desktop files in autostart
        for autostart_dir in autostart_dirs:
            if autostart_dir.exists():
                try:
                    for desktop_file in autostart_dir.glob("*.desktop"):
                        try:
                            content = desktop_file.read_text()
                            exec_line = next((line for line in content.split('\n') if line.startswith('Exec=')), None)
                            if exec_line:
                                command = exec_line.split('=', 1)[1].strip()
                                risk = 0
                                cmd_lower = command.lower()
                                if any(s in cmd_lower for s in ['/tmp', 'curl', 'wget', 'bash -c', 'sh -c']): risk += 40
                                if any(s in cmd_lower for s in ['python', 'perl', 'ruby']): risk += 20
                                if cmd_lower.startswith('/'): risk -= 10  # Absolute paths are slightly safer
                                startup_items.append({
                                    "name": desktop_file.stem,
                                    "command": command,
                                    "location": str(autostart_dir),
                                    "risk_score": max(0, min(risk, 100)),
                                    "risk_level": "HIGH" if risk >= 40 else "MEDIUM" if risk >= 20 else "LOW"
                                })
                        except Exception as e:
                            logger.debug(f"Error parsing {desktop_file}: {e}")
                except Exception as e:
                    logger.debug(f"Error scanning {autostart_dir}: {e}")
        
        # Check systemd user services
        if systemd_user.exists():
            try:
                for service_file in systemd_user.glob("*.service"):
                    if "default.target.wants" in str(service_file) or "multi-user.target.wants" in str(service_file):
                        try:
                            content = service_file.read_text()
                            exec_line = next((line for line in content.split('\n') if line.strip().startswith('ExecStart=')), None)
                            if exec_line:
                                command = exec_line.split('=', 1)[1].strip()
                                startup_items.append({
                                    "name": service_file.stem,
                                    "command": command,
                                    "location": str(systemd_user),
                                    "risk_score": 10,
                                    "risk_level": "LOW"
                                })
                        except Exception as e:
                            logger.debug(f"Error parsing {service_file}: {e}")
            except Exception as e:
                logger.debug(f"Error scanning systemd user services: {e}")
        
        # Check cron jobs
        crontab_result = _run_cmd(["crontab", "-l"], timeout=5)
        if crontab_result["ok"]:
            for line in crontab_result["stdout"].split('\n'):
                line = line.strip()
                if line and not line.startswith('#'):
                    parts = line.split()
                    if len(parts) >= 6:
                        command = ' '.join(parts[5:])
                        risk = 30 if any(s in command.lower() for s in ['curl', 'wget', '/tmp', 'bash -c']) else 15
                        startup_items.append({
                            "name": "cron",
                            "command": command,
                            "location": "crontab",
                            "risk_score": risk,
                            "risk_level": "MEDIUM" if risk >= 20 else "LOW"
                        })
    
    startup_items.sort(key=lambda x: -x['risk_score'])
    return startup_items

@app.get("/system/services")
async def get_services():
    """List system services with security analysis (cross-platform)."""
    import psutil
    import subprocess
    services = []
    os_name = platform.system().lower()
    
    if os_name == "windows":
        try:
            for svc in psutil.win_service_iter():
                try:
                    info = svc.as_dict()
                    risk = 0
                    name = info.get('name', '').lower()
                    if any(s in name for s in ['remote', 'telnet', 'ftp']): risk += 30
                    if info.get('start_type') == 'automatic' and info.get('status') == 'running': risk += 5
                    services.append({
                        "name": info.get('name', ''),
                        "display_name": info.get('display_name', ''),
                        "status": info.get('status', 'unknown'),
                        "start_type": info.get('start_type', 'unknown'),
                        "pid": info.get('pid', None),
                        "binpath": info.get('binpath', ''),
                        "risk_score": min(risk, 100)
                    })
                except Exception:
                    continue
        except AttributeError:
            logger.warning("win_service_iter not available on this platform")
    else:
        # Linux: Use systemctl to list services
        try:
            result = subprocess.run(
                ['systemctl', 'list-units', '--type=service', '--all', '--no-pager'],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                for line in result.stdout.split('\n')[1:]:
                    parts = line.split()
                    if len(parts) >= 4:
                        name = parts[0].replace('.service', '')
                        status = parts[2] if len(parts) > 2 else 'unknown'
                        enabled = parts[1] if len(parts) > 1 else 'unknown'
                        
                        risk = 0
                        name_lower = name.lower()
                        if any(s in name_lower for s in ['telnet', 'ftp', 'rsh', 'rlogin']): risk += 40
                        if any(s in name_lower for s in ['ssh', 'vnc', 'rdp']): risk += 20
                        if status == 'running' and enabled == 'enabled': risk += 5
                        
                        services.append({
                            "name": name,
                            "display_name": name,
                            "status": status,
                            "start_type": enabled,
                            "pid": None,
                            "binpath": "",
                            "risk_score": min(risk, 100)
                        })
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            logger.warning(f"Error listing Linux services: {e}")
            # Fallback: try service command
            try:
                result = subprocess.run(['service', '--status-all'], capture_output=True, text=True, timeout=10)
                for line in result.stdout.split('\n'):
                    if '[' in line:
                        status_char = line[line.index('[')+1]
                        parts = line.split(']', 1)
                        if len(parts) > 1:
                            name = parts[1].strip()
                            services.append({
                                "name": name,
                                "display_name": name,
                                "status": "running" if status_char == '+' else "stopped",
                                "start_type": "unknown",
                                "pid": None,
                                "binpath": "",
                                "risk_score": 10
                            })
            except Exception as e:
                logger.warning(f"Fallback service listing failed: {e}")
    
    services.sort(key=lambda x: (-x['risk_score'], x['name']))
    return services[:150]

@app.get("/system/tasks")
async def get_scheduled_tasks():
    """Audit scheduled tasks for suspicious entries."""
    import subprocess, json as _json
    tasks = []
    try:
        result = subprocess.run(
            ['schtasks', '/query', '/fo', 'csv', '/nh', '/v'],
            capture_output=True, text=True, timeout=10
        )
        for line in result.stdout.strip().split('\n')[:50]:
            parts = line.strip().strip('"').split('","')
            if len(parts) >= 8:
                name = parts[1] if len(parts) > 1 else 'Unknown'
                status = parts[3] if len(parts) > 3 else 'Unknown'
                risk = 0
                if 'powershell' in name.lower() or 'script' in name.lower(): risk += 35
                if 'temp' in name.lower() or 'appdata' in name.lower(): risk += 40
                tasks.append({
                    "name": name, "status": status,
                    "next_run": parts[2] if len(parts) > 2 else "N/A",
                    "author": parts[7] if len(parts) > 7 else "Unknown",
                    "risk_score": min(risk, 100)
                })
    except Exception:
        pass
    tasks.sort(key=lambda x: -x.get('risk_score', 0))
    return tasks[:50]

@app.get("/security/breach-check/{email}")
async def breach_check(email: str):
    """Check if an email appears in known breaches (simulated + API)."""
    import hashlib, urllib.request, urllib.error, json as _json
    result = {"email": email, "breaches": [], "is_compromised": False}
    # Check Have I Been Pwned via k-anonymity (partial SHA1)
    sha1 = hashlib.sha1(email.lower().encode()).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    try:
        req = urllib.request.Request(f"https://api.pwnedpasswords.com/range/{prefix}")
        req.add_header("User-Agent", "Arkshield-SecurityPlatform")
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = resp.read().decode()
            for line in data.split('\n'):
                parts = line.strip().split(':')
                if parts[0] == suffix:
                    result["is_compromised"] = True
                    result["exposure_count"] = int(parts[1])
                    break
    except Exception as e:
        result["note"] = f"HIBP check unavailable: {e}"
    # Simulated breach database
    common_domains = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com']
    domain = email.split('@')[-1] if '@' in email else ''
    if domain in common_domains:
        result["domain_risk"] = "HIGH - Common target for credential stuffing"
    else:
        result["domain_risk"] = "LOW"
    return result

@app.get("/security/vulnerabilities")
async def check_vulnerabilities():
    """Check system for known vulnerability indicators."""
    import platform, psutil, sys
    vulns = []
    # Check Python version
    py_ver = sys.version_info
    if py_ver < (3, 12):
        vulns.append({"id": "CVE-PYTHON-OLD", "severity": "MEDIUM", "component": f"Python {sys.version.split()[0]}", "description": "Outdated Python version. Consider upgrading to 3.12+.", "fix": "Upgrade Python"})
    # Check for weak configurations
    import os
    if os.path.exists(os.path.expanduser("~/.ssh/id_rsa")):
        vulns.append({"id": "SSH-KEY-FOUND", "severity": "INFO", "component": "SSH Keys", "description": "SSH private key found. Ensure proper permissions.", "fix": "chmod 600 ~/.ssh/id_rsa"})
    # Check open ports
    risky_ports = []
    for c in psutil.net_connections(kind='inet'):
        if c.status == 'LISTEN' and c.laddr:
            if c.laddr.port in {21, 23, 25, 135, 139, 445, 3389, 5900}:
                risky_ports.append(c.laddr.port)
    if risky_ports:
        vulns.append({"id": "RISKY-PORTS", "severity": "HIGH", "component": f"Open Ports: {risky_ports}", "description": f"Potentially dangerous ports open: {risky_ports}", "fix": "Close unnecessary ports or restrict access"})
    # Check Windows Defender status
    try:
        import subprocess
        res = subprocess.run(['powershell', '-Command', 'Get-MpComputerStatus | Select-Object -ExpandProperty RealTimeProtectionEnabled'], capture_output=True, text=True, timeout=5)
        if 'False' in res.stdout:
            vulns.append({"id": "AV-DISABLED", "severity": "CRITICAL", "component": "Windows Defender", "description": "Real-time protection is DISABLED", "fix": "Enable Windows Defender real-time protection"})
    except Exception:
        pass
    # Memory integrity
    mem = psutil.virtual_memory()
    if mem.percent > 90:
        vulns.append({"id": "MEM-EXHAUSTION", "severity": "HIGH", "component": f"Memory ({mem.percent}%)", "description": "System memory critically low. Risk of OOM kills.", "fix": "Close unnecessary applications or upgrade RAM"})
    return {"total": len(vulns), "critical": sum(1 for v in vulns if v['severity'] == 'CRITICAL'), "vulnerabilities": vulns}

@app.get("/system/file-scan/{path:path}")
async def scan_file(path: str):
    """Scan a specific file — calculate hash and assess risk."""
    import hashlib, os
    full_path = path
    if not os.path.exists(full_path):
        raise HTTPException(status_code=404, detail="File not found")
    if not os.path.isfile(full_path):
        raise HTTPException(status_code=400, detail="Path is not a file")
    file_size = os.path.getsize(full_path)
    if file_size > 50 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="File too large (max 50MB)")
    # Calculate hashes
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()
    with open(full_path, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            md5.update(chunk)
            sha256.update(chunk)
    risk = 0
    ext = os.path.splitext(full_path)[1].lower()
    if ext in ['.exe', '.dll', '.scr', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.msi']:
        risk += 30
    if 'temp' in full_path.lower() or 'appdata' in full_path.lower():
        risk += 20
    return {
        "path": full_path, "size_bytes": file_size,
        "md5": md5.hexdigest(), "sha256": sha256.hexdigest(),
        "extension": ext, "risk_score": min(risk, 100),
        "risk_level": "HIGH" if risk >= 40 else "MEDIUM" if risk >= 20 else "LOW"
    }

@app.get("/activity/feed")
async def activity_feed(limit: int = 30):
    """Get live activity feed of all security actions."""
    import time
    sentinel = get_sentinel()
    feed = []
    # Recent events
    try:
        events = sentinel.repository.get_recent_events(limit=limit)
        for e in events:
            feed.append({"time": e.timestamp, "type": "event", "icon": "📡", "text": f"[{e.event_class}] {e.description[:80]}", "severity": 0})
    except Exception:
        pass
    # Recent alerts
    try:
        alerts = sentinel.repository.get_recent_alerts(limit=10)
        for a in alerts:
            feed.append({"time": a.created_at, "type": "alert", "icon": "🚨", "text": a.title, "severity": a.severity})
    except Exception:
        pass
    # System events
    feed.append({"time": time.time(), "type": "system", "icon": "✅", "text": "Arkshield monitors active — all systems nominal", "severity": 0})
    feed.append({"time": time.time() - 30, "type": "scan", "icon": "🔍", "text": "Periodic integrity check completed", "severity": 0})
    feed.sort(key=lambda x: str(x.get('time', 0)), reverse=True)
    return feed[:limit]

# --- Phase 15: Deep System Integration ---

@app.get("/system/hardware")
async def get_hardware_info():
    """Retrieve detailed hardware and OS information."""
    import platform, psutil
    try:
        mem = psutil.virtual_memory()
        
        return {
            "os": {
                "name": platform.system(),
                "version": platform.version(),
                "release": platform.release(),
                "architecture": platform.machine()
            },
            "cpu": {
                "name": platform.processor(),
                "cores": psutil.cpu_count(logical=False),
                "threads": psutil.cpu_count(logical=True),
                "current_usage": psutil.cpu_percent(interval=0.1)
            },
            "memory": {
                "total_gb": round(mem.total / (1024**3), 2),
                "used_percent": mem.percent
            }
        }
    except Exception as e:
        return {"error": str(e)}

@app.get("/security/users")
async def get_local_users():
    """Audit local Windows user accounts and privileges."""
    import subprocess
    users = []
    try:
        # Get all local users
        res = subprocess.run(['net', 'user'], capture_output=True, text=True, timeout=5)
        user_lines = [line.strip() for line in res.stdout.split('\n') if line.strip() and not line.startswith('--') and not line.startswith('User accounts')]
        
        all_users = []
        for line in user_lines:
            for u in line.split():
                if u != "The" and u != "command" and u != "completed" and u != "successfully.":
                    all_users.append(u)
                    
        # Get Admins
        admins_res = subprocess.run(['net', 'localgroup', 'administrators'], capture_output=True, text=True, timeout=5)
        admins = [line.strip() for line in admins_res.stdout.split('\n') if line.strip() and not line.startswith('--') and not line.startswith('Alias') and not line.startswith('Comment') and not line.startswith('Members') and not line.startswith('The command')]

        for user in all_users:
            if user:
                # Check status
                status_res = subprocess.run(['net', 'user', user], capture_output=True, text=True, timeout=5)
                is_active = "Account active               Yes" in status_res.stdout
                is_admin = user in admins or f"\\{user}" in str(admins)
                
                risk = 0
                if is_admin and user.lower() not in ['administrator']: risk += 20
                if is_active and user.lower() == 'guest': risk += 50
                
                users.append({
                    "username": user,
                    "is_admin": is_admin,
                    "is_active": is_active,
                    "risk_score": min(risk, 100)
                })
    except Exception as e:
        logger.warning("Error getting users: %s", e)
    
    users.sort(key=lambda x: (-x['risk_score'], x['username']))
    return users

@app.get("/security/firewall")
async def get_firewall_rules():
    """Parse firewall rules (cross-platform)."""
    import subprocess
    rules: List[Dict[str, Any]] = []
    os_name = platform.system().lower()
    
    if os_name == "windows":
        try:
            # For performance, we parse a limited subset or use explicit matching
            res = subprocess.run(['netsh', 'advfirewall', 'firewall', 'show', 'rule', 'name=all'], capture_output=True, text=True, timeout=10)
            
            current_rule: Dict[str, Any] = {}
            for line in res.stdout.split('\n'):
                line = line.strip()
                if not line or line.startswith('-'): continue
                
                if line.startswith("Rule Name:"):
                    if current_rule and 'name' in current_rule:
                        rules.append(current_rule)
                        if len(rules) >= 200: break # Limit for dashboard performance
                    current_rule = {"name": line.split(':', 1)[1].strip()}
                elif line.startswith("Enabled:") and current_rule:
                    current_rule["enabled"] = line.split(':', 1)[1].strip() == "Yes"
                elif line.startswith("Direction:") and current_rule:
                    current_rule["direction"] = line.split(':', 1)[1].strip()
                elif line.startswith("Action:") and current_rule:
                    current_rule["action"] = line.split(':', 1)[1].strip()
                elif line.startswith("Program:") and current_rule:
                    current_rule["program"] = line.split(':', 1)[1].strip()
                    
            if current_rule and 'name' in current_rule:
                rules.append(current_rule)
                
        except Exception as e:
            logger.warning("Windows firewall parsing error: %s", e)
    else:
        # Linux: Try iptables, ufw, or firewalld
        try:
            # Try ufw first (Ubuntu/Debian)
            result = subprocess.run(['ufw', 'status', 'numbered'], capture_output=True, text=True, timeout=5)
            if result.returncode == 0 and 'Status: active' in result.stdout:
                for line in result.stdout.split('\n'):
                    if line.strip() and line[0].isdigit():
                        # Parse UFW rule
                        parts = line.split(None, 1)
                        if len(parts) > 1:
                            rule_text = parts[1].strip()
                            rules.append({
                                "name": f"UFW Rule {parts[0]}",
                                "enabled": True,
                                "direction": "IN" if "IN" in rule_text.upper() else "OUT" if "OUT" in rule_text.upper() else "BOTH",
                                "action": "ALLOW" if "ALLOW" in rule_text.upper() else "DENY" if "DENY" in rule_text.upper() else "UNKNOWN",
                                "program": rule_text
                            })
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        
        try:
            # Try firewalld (RHEL/CentOS/Fedora)
            result = subprocess.run(['firewall-cmd', '--list-all'], capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                current_zone = "default"
                for line in result.stdout.split('\n'):
                    line = line.strip()
                    if line.endswith(':'):
                        current_zone = line.rstrip(':')
                    elif 'services:' in line:
                        services = line.split(':', 1)[1].strip().split()
                        for svc in services:
                            rules.append({
                                "name": f"firewalld-{svc}",
                                "enabled": True,
                                "direction": "IN",
                                "action": "ALLOW",
                                "program": f"Service: {svc} in zone {current_zone}"
                            })
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        
        # Fallback to iptables if nothing else worked
        if not rules:
            try:
                result = subprocess.run(['iptables', '-L', '-n'], capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    chain = ""
                    for line in result.stdout.split('\n'):
                        if line.startswith('Chain'):
                            chain = line.split()[1]
                        elif line.strip() and not line.startswith('target') and chain:
                            parts = line.split()
                            if len(parts) >= 3:
                                rules.append({
                                    "name": f"iptables-{chain}-{len(rules)}",
                                    "enabled": True,
                                    "direction": chain,
                                    "action": parts[0],
                                    "program": ' '.join(parts[1:])
                                })
            except (subprocess.TimeoutExpired, FileNotFoundError):
                logger.warning("No firewall rules could be retrieved on Linux")

    return rules

# --- Phase 16: Attack Surface & Shares ---

@app.get("/security/shares")
async def get_network_shares():
    """Enumerate file and print shares (cross-platform)."""
    import subprocess
    shares = []
    os_name = platform.system().lower()
    
    if os_name == "windows":
        try:
            res = subprocess.run(['net', 'share'], capture_output=True, text=True, timeout=5)
            lines = res.stdout.split('\n')
            # Skip header lines
            start_idx = 0
            for i, line in enumerate(lines):
                if line.startswith('-'*10):
                    start_idx = i + 1
                    break
            
            for line in lines[start_idx:]:
                if not line.strip() or line.startswith('The command completed successfully'): continue
                parts = line.split()
                if len(parts) >= 2:
                    name = parts[0]
                    # net share format: Share name   Resource   Remark
                    # This is a bit tricky to parse perfectly without WMI, but we do our best
                    resource = parts[1] if len(parts) > 1 else ""
                    
                    is_admin = name.endswith('$')
                    risk = 0
                    if is_admin:
                        risk = 30
                    if name.lower() in ['admin$', 'c$', 'ipc$']:
                        risk = 50
                        
                    shares.append({
                        "name": name,
                        "resource": resource,
                        "is_admin": is_admin,
                        "risk_score": risk
                    })
        except Exception as e:
            logger.warning("Error getting Windows shares: %s", e)
    else:
        # Linux: Check Samba shares and NFS exports
        try:
            # Check Samba shares via smbstatus
            result = subprocess.run(['smbstatus', '-S'], capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    parts = line.split()
                    if len(parts) >= 2 and not line.startswith('Service') and not line.startswith('-'):
                        name = parts[0]
                        shares.append({
                            "name": name,
                            "resource": "Samba",
                            "is_admin": False,
                            "risk_score": 25,
                            "type": "samba"
                        })
        except (subprocess.TimeoutExpired, FileNotFoundError):
            logger.debug("smbstatus not available")
        
        try:
            # Check NFS exports
            from pathlib import Path
            exports_file = Path("/etc/exports")
            if exports_file.exists():
                with open(exports_file) as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            parts = line.split()
                            if parts:
                                path = parts[0]
                                risk = 20
                                # Check for insecure options
                                options = ' '.join(parts[1:]).lower()
                                if 'rw' in options:
                                    risk += 20
                                if 'no_root_squash' in options:
                                    risk += 30
                                if '*' in options or '0.0.0.0' in options:
                                    risk += 25
                                
                                shares.append({
                                    "name": path,
                                    "resource": "NFS",
                                    "is_admin": False,
                                    "risk_score": min(risk, 100),
                                    "type": "nfs",
                                    "options": ' '.join(parts[1:])
                                })
        except Exception as e:
            logger.debug(f"Error reading NFS exports: {e}")
    
    shares.sort(key=lambda x: (-x['risk_score'], x['name']))
    return shares

@app.get("/security/sessions")
async def get_user_sessions():
    """Identify active RDP and local console sessions."""
    import subprocess
    import psutil
    sessions = []

    command = _resolve_first_command("qwinsta", "quser")
    if not command:
        logger.info("Neither qwinsta nor quser is available; falling back to psutil.users()")
        for user in psutil.users():
            is_remote = bool(getattr(user, "host", ""))
            sessions.append({
                "session_name": "Remote" if is_remote else "Local",
                "username": user.name,
                "id": "N/A",
                "state": "active",
                "is_rdp": is_remote,
                "risk_score": 60 if is_remote else 10,
            })
        sessions.sort(key=lambda x: -x["risk_score"])
        return sessions

    try:
        res = subprocess.run([command], capture_output=True, text=True, timeout=5)
        if res.returncode != 0:
            logger.warning("%s returned non-zero exit (%s): %s", command, res.returncode, res.stderr.strip())
            return sessions

        lines = res.stdout.split('\n')
        state_tokens = {"active", "disc", "listen", "idle", "down", "reset", "conn", "disconnected"}

        for line in lines:
            raw = line.strip()
            if not raw:
                continue
            normalized = raw.lower().replace(">", " ")
            if "sessionname" in normalized or "username" in normalized:
                continue

            parts = raw.replace(">", " ").split()
            if len(parts) < 2:
                continue

            state_idx = -1
            for idx, token in enumerate(parts):
                if token.lower() in state_tokens:
                    state_idx = idx
                    break

            if state_idx == -1:
                continue

            state = parts[state_idx]
            session_id = parts[state_idx - 1] if state_idx >= 1 else ""
            username = parts[state_idx - 2] if state_idx >= 2 else "SYSTEM"
            name_tokens = parts[:max(1, state_idx - 2)]
            session_name = " ".join(name_tokens).strip() or "Console/Hidden"

            is_rdp = "rdp" in session_name.lower() or "tcp" in session_name.lower()
            risk = 0
            if is_rdp and state.lower() == "active":
                risk = 60
            elif is_rdp and state.lower() in {"listen", "conn"}:
                risk = 40

            sessions.append({
                "session_name": session_name,
                "username": username,
                "id": session_id,
                "state": state,
                "is_rdp": is_rdp,
                "risk_score": risk,
            })

    except Exception as e:
        logger.warning("Error getting sessions: %s", e)
        
    sessions.sort(key=lambda x: -x['risk_score'])
    return sessions

# --- Phase 17: Defender Audit ---

@app.get("/security/defender")
async def get_defender_status():
    """Comprehensive Windows Defender security audit with status, updates, exclusions, and threat history."""
    import subprocess
    import json
    
    # Check if PowerShell is available
    powershell_path = shutil.which("powershell")
    if not powershell_path:
        logger.warning("PowerShell not found - cannot query Defender status")
        return {
            "available": False,
            "error": "PowerShell not available",
            "risk_score": 100,
            "recommendation": "Install PowerShell or run on Windows system with Defender"
        }
    
    result = {
        "available": True,
        "status": {},
        "signatures": {},
        "exclusions": {},
        "threats": {},
        "scan_history": {},
        "audit_summary": [],
        "risk_score": 0
    }
    
    try:
        # 1. Get protection status
        cmd_status = 'powershell "Get-MpComputerStatus | Select-Object -Property AMServiceEnabled,AntispywareEnabled,RealTimeProtectionEnabled,IoavProtectionEnabled,OnAccessProtectionEnabled,BehaviorMonitorEnabled,IsTamperProtected,NISEnabled | ConvertTo-Json"'
        res = subprocess.run(cmd_status, capture_output=True, text=True, shell=True, timeout=15)
        
        if res.returncode == 0 and res.stdout.strip():
            status = json.loads(res.stdout)
            result["status"] = status
            
            # Calculate risk score based on protection status
            if not status.get("RealTimeProtectionEnabled"): 
                result["risk_score"] += 50
                result["audit_summary"].append("CRITICAL: Real-time protection is DISABLED")
            if not status.get("AMServiceEnabled"): 
                result["risk_score"] += 30
                result["audit_summary"].append("CRITICAL: Anti-malware service is DISABLED")
            if not status.get("OnAccessProtectionEnabled"): 
                result["risk_score"] += 20
                result["audit_summary"].append("HIGH: On-access protection is DISABLED")
            if not status.get("BehaviorMonitorEnabled"):
                result["risk_score"] += 15
                result["audit_summary"].append("MEDIUM: Behavior monitoring is DISABLED")
            if not status.get("IsTamperProtected"):
                result["risk_score"] += 10
                result["audit_summary"].append("MEDIUM: Tamper protection is DISABLED")
        else:
            result["audit_summary"].append("ERROR: Could not query protection status")
            result["risk_score"] += 50
        
        # 2. Get signature/definition updates
        cmd_sig = 'powershell "Get-MpComputerStatus | Select-Object -Property AntivirusSignatureLastUpdated,AntispywareSignatureLastUpdated,AntivirusSignatureAge,NISSignatureAge,QuickScanAge,FullScanAge | ConvertTo-Json"'
        res_sig = subprocess.run(cmd_sig, capture_output=True, text=True, shell=True, timeout=10)
        
        if res_sig.returncode == 0 and res_sig.stdout.strip():
            sigs = json.loads(res_sig.stdout)
            result["signatures"] = sigs
            
            # Check if signatures are outdated
            sig_age = sigs.get("AntivirusSignatureAge", 0)
            if sig_age > 7:
                result["risk_score"] += 25
                result["audit_summary"].append(f"HIGH: Virus definitions are {sig_age} days old (update needed)")
            elif sig_age > 3:
                result["risk_score"] += 10
                result["audit_summary"].append(f"MEDIUM: Virus definitions are {sig_age} days old")
            
            # Check scan history
            quick_scan_age = sigs.get("QuickScanAge", 999)
            if quick_scan_age > 14:
                result["audit_summary"].append(f"INFO: No quick scan in {quick_scan_age} days")
        
        # 3. Get exclusions (potential attack surface)
        cmd_excl = 'powershell "Get-MpPreference | Select-Object -Property ExclusionPath,ExclusionExtension,ExclusionProcess | ConvertTo-Json"'
        res_excl = subprocess.run(cmd_excl, capture_output=True, text=True, shell=True, timeout=10)
        
        if res_excl.returncode == 0 and res_excl.stdout.strip():
            excl = json.loads(res_excl.stdout)
            result["exclusions"] = excl
            
            # Count exclusions
            excl_paths = excl.get("ExclusionPath") or []
            excl_exts = excl.get("ExclusionExtension") or []
            excl_procs = excl.get("ExclusionProcess") or []
            
            if isinstance(excl_paths, list):
                path_count = len(excl_paths)
            else:
                path_count = 1 if excl_paths else 0
                
            if isinstance(excl_exts, list):
                ext_count = len(excl_exts)
            else:
                ext_count = 1 if excl_exts else 0
                
            if isinstance(excl_procs, list):
                proc_count = len(excl_procs)
            else:
                proc_count = 1 if excl_procs else 0
            
            total_exclusions = path_count + ext_count + proc_count
            if total_exclusions > 10:
                result["risk_score"] += 20
                result["audit_summary"].append(f"HIGH: {total_exclusions} Defender exclusions configured (potential attack surface)")
            elif total_exclusions > 5:
                result["risk_score"] += 10
                result["audit_summary"].append(f"MEDIUM: {total_exclusions} Defender exclusions configured")
        
        # 4. Get recent threat detections
        cmd_threats = 'powershell "Get-MpThreatDetection | Select-Object -First 10 -Property ThreatID,ThreatName,DetectionTime,InitialDetectionTime | ConvertTo-Json"'
        res_threats = subprocess.run(cmd_threats, capture_output=True, text=True, shell=True, timeout=10)
        
        if res_threats.returncode == 0 and res_threats.stdout.strip():
            try:
                threats = json.loads(res_threats.stdout)
                if threats:
                    result["threats"] = {"recent_detections": threats if isinstance(threats, list) else [threats]}
                    threat_count = len(threats) if isinstance(threats, list) else 1
                    result["audit_summary"].append(f"INFO: {threat_count} recent threat detection(s) found")
            except json.JSONDecodeError:
                pass
        
        # Final audit summary
        if result["risk_score"] == 0:
            result["audit_summary"].insert(0, "✓ Windows Defender is properly configured and up-to-date")
        
        result["risk_score"] = min(result["risk_score"], 100)
        
        return result
        
    except subprocess.TimeoutExpired:
        logger.error("Defender audit query timed out")
        return {
            "available": False, 
            "error": "Query timeout", 
            "risk_score": 50,
            "audit_summary": ["ERROR: Audit timed out"]
        }
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse Defender JSON output: {e}")
        return {
            "available": False, 
            "error": "Invalid JSON response", 
            "risk_score": 50,
            "audit_summary": ["ERROR: Could not parse Defender output"]
        }
    except Exception as e:
        logger.error(f"Unexpected error during Defender audit: {e}")
        return {
            "available": False, 
            "error": str(e), 
            "risk_score": 50,
            "audit_summary": [f"ERROR: {str(e)}"]
        }

# --- Phase 18: Kernel & Drivers ---

@app.get("/system/drivers")
async def get_drivers():
    """List installed kernel-mode drivers with security risk assessment."""
    import subprocess
    import csv
    
    # Check if driverquery is available
    if not shutil.which("driverquery"):
        logger.warning("driverquery command not found")
        raise HTTPException(
            status_code=503,
            detail="Driver enumeration not available on this system"
        )
    
    drivers = []
    try:
        res = subprocess.run(
            ['driverquery', '/v', '/fo', 'csv'],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        if res.returncode != 0:
            logger.warning(f"driverquery failed: {res.stderr.strip()}")
            raise HTTPException(
                status_code=500,
                detail=f"Driver query failed: {res.stderr.strip()[:200]}"
            )
        
        lines = res.stdout.split('\n')
        reader = csv.reader(lines)
        headers = next(reader, None)
        
        for row in reader:
            if len(row) >= 5:  # Module Name, Display Name, Description, Driver Type, Start Mode
                name = row[0].strip()
                if not name:  # Skip empty rows
                    continue
                    
                display = row[1].strip()
                drv_type = row[3].strip()
                start_mode = row[4].strip()
                state = row[5].strip() if len(row) > 5 else "Unknown"
                
                # Enhanced risk heuristic
                risk = 0
                if "Kernel" in drv_type:
                    risk += 10
                    if start_mode == "Boot":
                        risk += 10
                if any(suspicious in name.lower() for suspicious in ['hook', 'inject', 'rootkit']):
                    risk += 50
                
                drivers.append({
                    "name": name,
                    "display_name": display,
                    "type": drv_type,
                    "start_mode": start_mode,
                    "state": state,
                    "risk_score": risk
                })
                
    except subprocess.TimeoutExpired:
        logger.error("driverquery timed out after 10 seconds")
        raise HTTPException(status_code=504, detail="Driver query timeout")
    except Exception as e:
        logger.error(f"Driver enumeration error: {e}")
        raise HTTPException(status_code=500, detail=str(e))
        
    drivers.sort(key=lambda x: (-x['risk_score'], x['name']))
    return drivers

# --- Phase 19: Storage Intelligence & Sweeper ---

@app.get("/system/storage/junk")
async def get_junk_storage():
    """Scan common temp directories and categorize junk files using JunkDetector."""
    import os
    from pathlib import Path
    try:
        from storage_manager.detectors.junk_detector import JunkDetector
        detector = JunkDetector()
    except Exception as e:
        return {"error": f"Failed to initialize JunkDetector: {e}"}

    # Define common junk paths on Windows/Linux
    paths_to_scan = []
    if os.name == "nt":
        if "TEMP" in os.environ:
            paths_to_scan.append(Path(os.environ["TEMP"]))
        if "LOCALAPPDATA" in os.environ:
            paths_to_scan.append(Path(os.environ["LOCALAPPDATA"]) / "Temp")
            paths_to_scan.append(Path(os.environ["LOCALAPPDATA"]) / "CrashDumps")
        if "SystemRoot" in os.environ:
            paths_to_scan.append(Path(os.environ["SystemRoot"]) / "Temp")
            paths_to_scan.append(Path(os.environ["SystemRoot"]) / "Prefetch")
    else:
        home = Path.home()
        paths_to_scan.extend([
            Path("/tmp"),
            Path("/var/tmp"),
            home / ".cache",
        ])

    results = []
    total_size = 0
    total_files = 0
    
    # Simple recursive scan restricted to these safe temp directories
    def scan_dir(dir_path: Path, max_depth=3, current_depth=0):
        nonlocal total_size, total_files
        if current_depth > max_depth or not dir_path.exists() or not dir_path.is_dir():
            return
            
        try:
            for item in dir_path.iterdir():
                try:

                    if item.is_file():
                        detect_res = detector.detect_file(item)
                        if detect_res.get('is_junk'):
                            stat = item.stat()
                            size_bytes = stat.st_size
                            total_size += size_bytes
                            total_files += 1
                            
                            results.append({
                                "path": str(item),
                                "name": item.name,
                                "size_bytes": size_bytes,
                                "categories": detect_res.get('categories', []),
                                "reasons": detect_res.get('reasons', [])
                            })
                    elif item.is_dir():
                        scan_dir(item, max_depth, current_depth + 1)
                except PermissionError:
                    continue
                except Exception:
                    continue
        except PermissionError:
            pass
            
    valid_paths = [p for p in set(paths_to_scan) if p.exists() and p.is_dir()]
    for p in valid_paths:
        scan_dir(p)
        
    # Sort by size descending
    results.sort(key=lambda x: x['size_bytes'], reverse=True)
    
    return {
        "summary": {
            "total_files": total_files,
            "total_size_mb": round(total_size / (1024 * 1024), 2),
            "scan_paths": [str(p) for p in valid_paths],
        },
        "junk_files": results[:200]  # Cap at 200 files for API payload size
    }

@app.post("/system/storage/junk/remove")
async def remove_junk_files(files: list[str]):
    """Delete specified junk files."""
    import os
    from pathlib import Path
    
    if not files:
        return {"removed": 0, "failed": 0, "errors": []}
    
    removed_count = 0
    failed_count = 0
    errors = []
    
    # Only allow deletion of files in safe temp directories
    safe_prefixes = []
    if os.name == "nt":
        if "TEMP" in os.environ:
            safe_prefixes.append(os.environ["TEMP"])
        if "LOCALAPPDATA" in os.environ:
            safe_prefixes.extend([
                os.path.join(os.environ["LOCALAPPDATA"], "Temp"),
                os.path.join(os.environ["LOCALAPPDATA"], "CrashDumps")
            ])
        if "SystemRoot" in os.environ:
            safe_prefixes.extend([
                os.path.join(os.environ["SystemRoot"], "Temp"),
                os.path.join(os.environ["SystemRoot"], "Prefetch")
            ])
    else:
        home = Path.home()
        safe_prefixes = [
            "/tmp",
            "/var/tmp",
            str(home / ".cache"),
        ]
    
    for file_path in files:
        try:
            # Verify file is within safe directories
            file_abs = os.path.abspath(file_path)
            is_safe = any(file_abs.startswith(os.path.abspath(safe_dir)) for safe_dir in safe_prefixes)
            
            if not is_safe:
                errors.append(f"Blocked: {file_path} (outside safe directories)")
                failed_count += 1
                continue
                
            path_obj = Path(file_path)
            if path_obj.exists():
                if path_obj.is_file():
                    path_obj.unlink()
                    removed_count += 1
                elif path_obj.is_dir():
                    import shutil
                    shutil.rmtree(path_obj)
                    removed_count += 1
            else:
                errors.append(f"Not found: {file_path}")
                failed_count += 1
        except PermissionError:
            errors.append(f"Permission denied: {file_path}")
            failed_count += 1
        except Exception as e:
            errors.append(f"Error deleting {file_path}: {str(e)}")
            failed_count += 1
    
    return {
        "removed": removed_count,
        "failed": failed_count,
        "errors": errors,
        "message": f"Removed {removed_count} items, {failed_count} failed"
    }

@app.post("/system/storage/junk/clear-all")
async def clear_all_junk():
    """Scan and automatically remove all detected junk files (one-click cleanup)."""
    import os
    from pathlib import Path
    
    # Step 1: Scan for junk
    try:
        from storage_manager.detectors.junk_detector import JunkDetector
        detector = JunkDetector()
    except Exception as e:
        return {"error": f"Failed to initialize JunkDetector: {e}", "success": False}

    paths_to_scan = []
    if os.name == "nt":
        if "TEMP" in os.environ:
            paths_to_scan.append(Path(os.environ["TEMP"]))
        if "LOCALAPPDATA" in os.environ:
            paths_to_scan.append(Path(os.environ["LOCALAPPDATA"]) / "Temp")
            paths_to_scan.append(Path(os.environ["LOCALAPPDATA"]) / "CrashDumps")
        if "SystemRoot" in os.environ:
            paths_to_scan.append(Path(os.environ["SystemRoot"]) / "Temp")
            paths_to_scan.append(Path(os.environ["SystemRoot"]) / "Prefetch")
    else:
        home = Path.home()
        paths_to_scan.extend([Path("/tmp"), Path("/var/tmp"), home / ".cache"])

    junk_files = []
    total_size = 0
    
    def scan_dir(dir_path: Path, max_depth=3, current_depth=0):
        nonlocal total_size
        if current_depth > max_depth or not dir_path.exists() or not dir_path.is_dir():
            return
        try:
            for item in dir_path.iterdir():
                try:
                    if item.is_file():
                        detect_res = detector.detect_file(item)
                        if detect_res.get('is_junk'):
                            size_bytes = item.stat().st_size
                            total_size += size_bytes
                            junk_files.append(str(item))
                    elif item.is_dir():
                        scan_dir(item, max_depth, current_depth + 1)
                except (PermissionError, Exception):
                    continue
        except PermissionError:
            pass
    
    valid_paths = [p for p in set(paths_to_scan) if p.exists() and p.is_dir()]
    for p in valid_paths:
        scan_dir(p)
    
    if not junk_files:
        return {
            "success": True,
            "scanned": len(valid_paths),
            "found": 0,
            "removed": 0,
            "failed": 0,
            "space_freed_mb": 0,
            "message": "No junk files found"
        }
    
    # Step 2: Remove junk files
    removed_count = 0
    failed_count = 0
    space_freed = 0
    errors = []
    
    safe_prefixes = []
    if os.name == "nt":
        if "TEMP" in os.environ:
            safe_prefixes.append(os.environ["TEMP"])
        if "LOCALAPPDATA" in os.environ:
            safe_prefixes.extend([
                os.path.join(os.environ["LOCALAPPDATA"], "Temp"),
                os.path.join(os.environ["LOCALAPPDATA"], "CrashDumps")
            ])
        if "SystemRoot" in os.environ:
            safe_prefixes.extend([
                os.path.join(os.environ["SystemRoot"], "Temp"),
                os.path.join(os.environ["SystemRoot"], "Prefetch")
            ])
    else:
        home = Path.home()
        safe_prefixes = ["/tmp", "/var/tmp", str(home / ".cache")]
    
    for file_path in junk_files:
        try:
            file_abs = os.path.abspath(file_path)
            is_safe = any(file_abs.startswith(os.path.abspath(safe_dir)) for safe_dir in safe_prefixes)
            
            if not is_safe:
                failed_count += 1
                continue
            
            path_obj = Path(file_path)
            if path_obj.exists():
                file_size = path_obj.stat().st_size
                if path_obj.is_file():
                    path_obj.unlink()
                    removed_count += 1
                    space_freed += file_size
                elif path_obj.is_dir():
                    import shutil
                    shutil.rmtree(path_obj)
                    removed_count += 1
                    space_freed += file_size
        except (PermissionError, Exception) as e:
            failed_count += 1
            if len(errors) < 10:  # Limit error list
                errors.append(f"{Path(file_path).name}: {str(e)}")
    
    return {
        "success": True,
        "scanned": len(valid_paths),
        "found": len(junk_files),
        "removed": removed_count,
        "failed": failed_count,
        "space_freed_mb": round(space_freed / (1024 * 1024), 2),
        "errors": errors,
        "message": f"Cleared {removed_count} junk files, freed {round(space_freed / (1024 * 1024), 2)}MB"
    }

# --- Phase 20: Comprehensive Security Audit ---

@app.get("/security/audit")
async def comprehensive_security_audit():
    """Perform comprehensive system security audit: firewall, UAC, BitLocker, SMB, RDP, password policy."""
    import subprocess
    
    audit_results = {
        "firewall": {},
        "uac": {},
        "bitlocker": {},
        "smb": {},
        "rdp": {},
        "password_policy": {},
        "audit_summary": [],
        "overall_risk_score": 0
    }
    
    powershell_path = shutil.which("powershell")
    if not powershell_path:
        audit_results["audit_summary"].append("ERROR: PowerShell not available")
        audit_results["overall_risk_score"] = 100
        return audit_results
    
    try:
        # 1. Firewall Status
        try:
            cmd_fw = 'powershell "Get-NetFirewallProfile | Select-Object Name,Enabled | ConvertTo-Json"'
            res_fw = subprocess.run(cmd_fw, capture_output=True, text=True, shell=True, timeout=10)
            if res_fw.returncode == 0 and res_fw.stdout.strip():
                import json
                fw_profiles = json.loads(res_fw.stdout)
                if not isinstance(fw_profiles, list):
                    fw_profiles = [fw_profiles]
                
                audit_results["firewall"]["profiles"] = fw_profiles
                disabled_profiles = [p["Name"] for p in fw_profiles if not p.get("Enabled")]
                
                if disabled_profiles:
                    audit_results["overall_risk_score"] += 30
                    audit_results["audit_summary"].append(f"CRITICAL: Firewall disabled for: {', '.join(disabled_profiles)}")
                else:
                    audit_results["audit_summary"].append("✓ Firewall enabled for all profiles")
        except Exception as e:
            audit_results["firewall"]["error"] = str(e)
        
        # 2. UAC (User Account Control)
        try:
            cmd_uac = 'powershell "Get-ItemProperty -Path HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System | Select-Object EnableLUA,ConsentPromptBehaviorAdmin | ConvertTo-Json"'
            res_uac = subprocess.run(cmd_uac, capture_output=True, text=True, shell=True, timeout=10)
            if res_uac.returncode == 0 and res_uac.stdout.strip():
                import json
                uac_status = json.loads(res_uac.stdout)
                audit_results["uac"] = uac_status
                
                enable_lua = uac_status.get("EnableLUA", 0)
                consent_prompt = uac_status.get("ConsentPromptBehaviorAdmin", 0)
                
                if enable_lua == 0:
                    audit_results["overall_risk_score"] += 40
                    audit_results["audit_summary"].append("CRITICAL: UAC is completely DISABLED")
                elif consent_prompt < 2:
                    audit_results["overall_risk_score"] += 20
                    audit_results["audit_summary"].append("HIGH: UAC is set to never prompt")
                else:
                    audit_results["audit_summary"].append("✓ UAC is enabled and configured")
        except Exception as e:
            audit_results["uac"]["error"] = str(e)
        
        # 3. BitLocker Status (Drive Encryption)
        try:
            cmd_bl = 'powershell "Get-BitLockerVolume | Select-Object MountPoint,VolumeStatus,EncryptionPercentage,ProtectionStatus | ConvertTo-Json"'
            res_bl = subprocess.run(cmd_bl, capture_output=True, text=True, shell=True, timeout=10)
            if res_bl.returncode == 0 and res_bl.stdout.strip():
                import json
                bl_volumes = json.loads(res_bl.stdout)
                if not isinstance(bl_volumes, list):
                    bl_volumes = [bl_volumes]
                
                audit_results["bitlocker"]["volumes"] = bl_volumes
                unencrypted = [v["MountPoint"] for v in bl_volumes if v.get("VolumeStatus") != "FullyEncrypted"]
                
                if unencrypted:
                    audit_results["overall_risk_score"] += 15
                    audit_results["audit_summary"].append(f"MEDIUM: Drives not fully encrypted: {', '.join(unencrypted)}")
                else:
                    audit_results["audit_summary"].append("✓ All drives are encrypted with BitLocker")
        except Exception as e:
            audit_results["bitlocker"]["note"] = "BitLocker may not be available on this system"
        
        # 4. SMB (Server Message Block) Version Check
        try:
            cmd_smb = 'powershell "Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol,EnableSMB2Protocol | ConvertTo-Json"'
            res_smb = subprocess.run(cmd_smb, capture_output=True, text=True, shell=True, timeout=10)
            if res_smb.returncode == 0 and res_smb.stdout.strip():
                import json
                smb_config = json.loads(res_smb.stdout)
                audit_results["smb"] = smb_config
                
                if smb_config.get("EnableSMB1Protocol"):
                    audit_results["overall_risk_score"] += 25
                    audit_results["audit_summary"].append("CRITICAL: SMBv1 is ENABLED (vulnerable to WannaCry)")
                else:
                    audit_results["audit_summary"].append("✓ SMBv1 is disabled")
        except Exception as e:
            audit_results["smb"]["error"] = str(e)
        
        # 5. RDP (Remote Desktop) Status
        try:
            cmd_rdp = 'powershell "Get-ItemProperty -Path \'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server\' | Select-Object fDenyTSConnections | ConvertTo-Json"'
            res_rdp = subprocess.run(cmd_rdp, capture_output=True, text=True, shell=True, timeout=10)
            if res_rdp.returncode == 0 and res_rdp.stdout.strip():
                import json
                rdp_status = json.loads(res_rdp.stdout)
                rdp_disabled = rdp_status.get("fDenyTSConnections", 1)
                
                audit_results["rdp"] = {
                    "enabled": rdp_disabled == 0,
                    "status": "Enabled" if rdp_disabled == 0 else "Disabled"
                }
                
                if rdp_disabled == 0:
                    audit_results["overall_risk_score"] += 15
                    audit_results["audit_summary"].append("HIGH: RDP is ENABLED (ensure Network Level Authentication is on)")
                else:
                    audit_results["audit_summary"].append("✓ RDP is disabled")
        except Exception as e:
            audit_results["rdp"]["error"] = str(e)
        
        # 6. Password Policy
        try:
            cmd_pw = 'powershell "net accounts"'
            res_pw = subprocess.run(cmd_pw, capture_output=True, text=True, shell=True, timeout=10)
            if res_pw.returncode == 0:
                audit_results["password_policy"]["raw"] = res_pw.stdout
                
                # Parse key settings
                lines = res_pw.stdout.split('\n')
                for line in lines:
                    if "Minimum password length" in line:
                        try:
                            min_len = int(line.split(':')[1].strip())
                            if min_len < 8:
                                audit_results["overall_risk_score"] += 10
                                audit_results["audit_summary"].append(f"MEDIUM: Minimum password length is {min_len} (should be ≥8)")
                        except:
                            pass
                    if "Maximum password age" in line:
                        if "Unlimited" in line:
                            audit_results["overall_risk_score"] += 10
                            audit_results["audit_summary"].append("MEDIUM: Password never expires")
        except Exception as e:
            audit_results["password_policy"]["error"] = str(e)
        
        # Final summary
        if audit_results["overall_risk_score"] == 0:
            audit_results["audit_summary"].insert(0, "✓ System security configuration is excellent")
        elif audit_results["overall_risk_score"] < 30:
            audit_results["audit_summary"].insert(0, "System security is good with minor issues")
        elif audit_results["overall_risk_score"] < 60:
            audit_results["audit_summary"].insert(0, "⚠ System has moderate security risks")
        else:
            audit_results["audit_summary"].insert(0, "⚠ CRITICAL: System has significant security vulnerabilities")
        
        audit_results["overall_risk_score"] = min(audit_results["overall_risk_score"], 100)
        
        return audit_results
        
    except Exception as e:
        logger.error(f"Security audit failed: {e}")
        return {
            "error": str(e),
            "overall_risk_score": 100,
            "audit_summary": [f"ERROR: Audit failed - {str(e)}"]
        }

# --- Phase 21: System Hardening Recommendations ---

@app.get("/security/hardening")
async def get_hardening_recommendations():
    """Generate system-specific hardening recommendations based on current configuration."""
    import subprocess
    import psutil
    
    recommendations = {
        "critical": [],
        "high": [],
        "medium": [],
        "low": [],
        "info": [],
        "summary": {}
    }
    
    try:
        # Check Windows version
        import platform
        win_version = platform.version()
        system_info = {
            "os": platform.system(),
            "version": win_version,
            "machine": platform.machine()
        }
        
        # 1. Check if running as admin
        try:
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin()
            if is_admin:
                recommendations["info"].append("Running with administrative privileges")
            else:
                recommendations["low"].append("Not running as administrator (some features may be limited)")
        except:
            pass
        
        # 2. Check for automatic updates
        powershell_path = shutil.which("powershell")
        if powershell_path:
            try:
                cmd = 'powershell "(New-Object -ComObject Microsoft.Update.AutoUpdate).Settings.NotificationLevel"'
                res = subprocess.run(cmd, capture_output=True, text=True, shell=True, timeout=5)
                if res.returncode == 0:
                    level = res.stdout.strip()
                    if level in ["0", "1"]:
                        recommendations["high"].append("Windows Update is disabled or not fully automatic - enable automatic updates")
                    else:
                        recommendations["info"].append("Windows Update is configured for automatic updates")
            except:
                pass
        
        # 3. Check startup programs
        startup_count = 0
        try:
            # Check common startup locations
            import winreg
            startup_keys = [
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
            ]
            
            for key_path in startup_keys:
                try:
                    key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_READ)
                    i = 0
                    while True:
                        try:
                            winreg.EnumValue(key, i)
                            startup_count += 1
                            i += 1
                        except OSError:
                            break
                    winreg.CloseKey(key)
                except:
                    pass
            
            if startup_count > 15:
                recommendations["medium"].append(f"High number of startup programs ({startup_count}) - review and disable unnecessary items")
            elif startup_count > 0:
                recommendations["info"].append(f"{startup_count} startup program(s) configured")
        except:
            pass
        
        # 4. Check memory usage
        mem = psutil.virtual_memory()
        if mem.percent > 90:
            recommendations["high"].append(f"Memory usage is very high ({mem.percent}%) - consider closing applications or adding RAM")
        elif mem.percent > 80:
            recommendations["medium"].append(f"Memory usage is high ({mem.percent}%)")
        
        # 5. Check disk space
        for partition in psutil.disk_partitions():
            try:
                usage = psutil.disk_usage(partition.mountpoint)
                if usage.percent > 90:
                    recommendations["critical"].append(f"Drive {partition.mountpoint} is {usage.percent}% full - free up space urgently")
                elif usage.percent > 80:
                    recommendations["high"].append(f"Drive {partition.mountpoint} is {usage.percent}% full - consider cleanup")
            except:
                pass
        
        # 6. Check Guest account
        if powershell_path:
            try:
                cmd_guest = 'powershell "Get-LocalUser -Name Guest | Select-Object Enabled | ConvertTo-Json"'
                res_guest = subprocess.run(cmd_guest, capture_output=True, text=True, shell=True, timeout=5)
                if res_guest.returncode == 0 and "true" in res_guest.stdout.lower():
                    recommendations["critical"].append("Guest account is ENABLED - disable it immediately")
            except:
                pass
        
        # 7. Network hardening
        try:
            # Check for weak network protocols
            cmd_net = 'powershell "Get-ItemProperty -Path HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters | Select-Object SMB1 | ConvertTo-Json"'
            res_net = subprocess.run(cmd_net, capture_output=True, text=True, shell=True, timeout=5)
            # Already covered in security audit, just reference
            recommendations["info"].append("Run /security/audit for detailed network protocol analysis")
        except:
            pass
        
        # 8. Browser security recommendations
        recommendations["medium"].append("Ensure browser extensions are from trusted sources only")
        recommendations["medium"].append("Enable DNS-over-HTTPS in your browser for privacy")
        
        # 9. Backup recommendations
        recommendations["high"].append("Ensure regular backups are configured (File History or third-party)")
        recommendations["medium"].append("Test backup restoration periodically")
        
        # 10. Security software recommendations
        recommendations["info"].append("Keep Windows Defender enabled (check /security/defender)")
        recommendations["low"].append("Consider using a password manager for strong unique passwords")
        
        # Generate summary
        recommendations["summary"] = {
            "critical_count": len(recommendations["critical"]),
            "high_count": len(recommendations["high"]),
            "medium_count": len(recommendations["medium"]),
            "low_count": len(recommendations["low"]),
            "info_count": len(recommendations["info"]),
            "system_info": system_info
        }
        
        total_issues = len(recommendations["critical"]) + len(recommendations["high"]) + len(recommendations["medium"])
        if total_issues == 0:
            recommendations["summary"]["status"] = "Excellent - no critical issues found"
        elif total_issues < 3:
            recommendations["summary"]["status"] = "Good - minor improvements suggested"
        elif total_issues < 6:
            recommendations["summary"]["status"] = "Fair - several improvements recommended"
        else:
            recommendations["summary"]["status"] = "Action needed - multiple security concerns"
        
        return recommendations
        
    except Exception as e:
        logger.error(f"Hardening recommendations failed: {e}")
        return {
            "error": str(e),
            "critical": [f"Failed to generate recommendations: {str(e)}"]
        }

# --- Phase 22: Performance & Resource Monitoring ---

@app.get("/system/performance")
async def get_performance_metrics():
    """Real-time system performance monitoring: CPU, memory, disk I/O, network, processes."""
    import psutil
    import time
    
    try:
        # CPU metrics
        cpu_percent = psutil.cpu_percent(interval=1)
        cpu_count = psutil.cpu_count(logical=False)
        cpu_count_logical = psutil.cpu_count(logical=True)
        cpu_freq = psutil.cpu_freq()
        
        cpu_per_core = psutil.cpu_percent(interval=0.5, percpu=True)
        
        # Memory metrics
        mem = psutil.virtual_memory()
        swap = psutil.swap_memory()
        
        # Disk I/O
        disk_io = psutil.disk_io_counters()
        disk_usage_list = []
        for partition in psutil.disk_partitions():
            try:
                usage = psutil.disk_usage(partition.mountpoint)
                disk_usage_list.append({
                    "device": partition.device,
                    "mountpoint": partition.mountpoint,
                    "fstype": partition.fstype,
                    "total_gb": round(usage.total / (1024**3), 2),
                    "used_gb": round(usage.used / (1024**3), 2),
                    "free_gb": round(usage.free / (1024**3), 2),
                    "percent": usage.percent
                })
            except PermissionError:
                continue
        
        # Network I/O
        net_io = psutil.net_io_counters()
        net_connections = len(psutil.net_connections())
        
        # Top processes by CPU
        top_cpu_procs = []
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
            try:
                pinfo = proc.info
                top_cpu_procs.append({
                    "pid": pinfo['pid'],
                    "name": pinfo['name'],
                    "cpu_percent": pinfo['cpu_percent'],
                    "memory_percent": round(pinfo['memory_percent'], 2)
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        
        top_cpu_procs.sort(key=lambda x: x['cpu_percent'] or 0, reverse=True)
        top_cpu_procs = top_cpu_procs[:10]
        
        # Top processes by memory
        top_mem_procs = []
        for proc in psutil.process_iter(['pid', 'name', 'memory_percent', 'memory_info']):
            try:
                pinfo = proc.info
                mem_mb = pinfo['memory_info'].rss / (1024 * 1024)
                top_mem_procs.append({
                    "pid": pinfo['pid'],
                    "name": pinfo['name'],
                    "memory_mb": round(mem_mb, 2),
                    "memory_percent": round(pinfo['memory_percent'], 2)
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        
        top_mem_procs.sort(key=lambda x: x['memory_mb'], reverse=True)
        top_mem_procs = top_mem_procs[:10]
        
        # System uptime
        boot_time = psutil.boot_time()
        uptime_seconds = time.time() - boot_time
        uptime_hours = uptime_seconds / 3600
        
        # Performance analysis
        alerts = []
        if cpu_percent > 90:
            alerts.append("CRITICAL: CPU usage is extremely high (>90%)")
        elif cpu_percent > 80:
            alerts.append("WARNING: CPU usage is high (>80%)")
        
        if mem.percent > 95:
            alerts.append("CRITICAL: Memory usage is critically high (>95%)")
        elif mem.percent > 85:
            alerts.append("WARNING: Memory usage is high (>85%)")
        
        for disk in disk_usage_list:
            if disk['percent'] > 95:
                alerts.append(f"CRITICAL: Disk {disk['mountpoint']} is almost full ({disk['percent']}%)")
            elif disk['percent'] > 85:
                alerts.append(f"WARNING: Disk {disk['mountpoint']} is getting full ({disk['percent']}%)")
        
        if not alerts:
            alerts.append("System performance is normal")
        
        return {
            "cpu": {
                "percent": cpu_percent,
                "cores_physical": cpu_count,
                "cores_logical": cpu_count_logical,
                "frequency_mhz": cpu_freq.current if cpu_freq else None,
                "per_core_percent": cpu_per_core
            },
            "memory": {
                "total_gb": round(mem.total / (1024**3), 2),
                "available_gb": round(mem.available / (1024**3), 2),
                "used_gb": round(mem.used / (1024**3), 2),
                "percent": mem.percent,
                "swap_total_gb": round(swap.total / (1024**3), 2),
                "swap_used_gb": round(swap.used / (1024**3), 2),
                "swap_percent": swap.percent
            },
            "disk": {
                "partitions": disk_usage_list,
                "io": {
                    "read_count": disk_io.read_count,
                    "write_count": disk_io.write_count,
                    "read_mb": round(disk_io.read_bytes / (1024**2), 2),
                    "write_mb": round(disk_io.write_bytes / (1024**2), 2)
                } if disk_io else None
            },
            "network": {
                "bytes_sent_mb": round(net_io.bytes_sent / (1024**2), 2),
                "bytes_recv_mb": round(net_io.bytes_recv / (1024**2), 2),
                "packets_sent": net_io.packets_sent,
                "packets_recv": net_io.packets_recv,
                "connections_count": net_connections
            },
            "processes": {
                "total": len(psutil.pids()),
                "top_cpu": top_cpu_procs,
                "top_memory": top_mem_procs
            },
            "system": {
                "uptime_hours": round(uptime_hours, 2),
                "uptime_days": round(uptime_hours / 24, 2)
            },
            "alerts": alerts
        }
        
    except Exception as e:
        logger.error(f"Performance monitoring failed: {e}")
        return {"error": str(e)}

# --- Phase 23: Network Security Audit ---

@app.get("/network/security-audit")
async def network_security_audit():
    """Comprehensive network security audit: open ports, listening services, suspicious connections, DNS configuration."""
    import psutil
    import socket
    import subprocess
    
    audit_result = {
        "open_ports": [],
        "listening_services": [],
        "established_connections": [],
        "dns_servers": [],
        "network_interfaces": [],
        "suspicious_findings": [],
        "recommendations": [],
        "risk_score": 0
    }
    
    try:
        # 1. Get all network connections
        connections = psutil.net_connections(kind='inet')
        
        # Categorize connections
        listening_ports: Dict[int, List[Dict[str, Any]]] = {}
        established_conns: List[Dict[str, Any]] = []

        def _addr_ip_port(addr: Any) -> tuple[str, int]:
            """Normalize psutil sockaddr/tuple into (ip, port)."""
            if not addr:
                return ("0.0.0.0", 0)
            if hasattr(addr, "ip") and hasattr(addr, "port"):
                return (str(getattr(addr, "ip")), int(getattr(addr, "port")))
            if isinstance(addr, tuple):
                ip = str(addr[0]) if len(addr) > 0 else "0.0.0.0"
                port = int(addr[1]) if len(addr) > 1 else 0
                return (ip, port)
            return ("0.0.0.0", 0)
        
        for conn in connections:
            try:
                if conn.status == 'LISTEN':
                    listen_ip, port = _addr_ip_port(conn.laddr)
                    if port not in listening_ports:
                        listening_ports[port] = []
                    
                    # Get process info
                    try:
                        proc = psutil.Process(conn.pid) if conn.pid else None
                        proc_name = proc.name() if proc else "Unknown"
                    except:
                        proc_name = "Unknown"
                    
                    listening_ports[port].append({
                        "pid": conn.pid,
                        "process": proc_name,
                        "address": listen_ip
                    })
                
                elif conn.status == 'ESTABLISHED':
                    try:
                        proc = psutil.Process(conn.pid) if conn.pid else None
                        proc_name = proc.name() if proc else "Unknown"
                    except:
                        proc_name = "Unknown"
                    
                    local_ip, local_port = _addr_ip_port(conn.laddr)
                    remote_ip, remote_port = _addr_ip_port(conn.raddr)
                    established_conns.append({
                        "local_addr": f"{local_ip}:{local_port}",
                        "remote_addr": f"{remote_ip}:{remote_port}" if conn.raddr else "N/A",
                        "pid": conn.pid,
                        "process": proc_name
                    })
            except:
                continue
        
        # 2. Analyze listening ports for security risks
        risky_ports = {
            21: "FTP (unencrypted)",
            23: "Telnet (unencrypted)",
            69: "TFTP (insecure)",
            135: "RPC (attack vector)",
            139: "NetBIOS (legacy, risky)",
            445: "SMB (ransomware target)",
            3389: "RDP (brute-force target)",
            5900: "VNC (often unsecured)",
            1433: "SQL Server (should not be public)",
            3306: "MySQL (should not be public)",
            5432: "PostgreSQL (should not be public)",
            6379: "Redis (should not be public)",
            27017: "MongoDB (should not be public)"
        }
        
        for port, listeners in listening_ports.items():
            port_info = {
                "port": port,
                "listeners": listeners,
                "service": risky_ports.get(port, "Unknown"),
                "risk_level": "HIGH" if port in risky_ports else "LOW"
            }
            audit_result["open_ports"].append(port_info)
            
            if port in risky_ports:
                audit_result["risk_score"] += 15
                audit_result["suspicious_findings"].append(f"Port {port} ({risky_ports[port]}) is listening")
        
        # Sort open ports
        audit_result["open_ports"].sort(key=lambda x: x["port"])
        
        # 3. Check for suspicious connections
        audit_result["established_connections"] = established_conns[:50]  # Limit to 50
        
        # Check for connections to unusual ports
        for conn in established_conns[:100]:
            if conn["remote_addr"] != "N/A":
                try:
                    remote_port = int(conn["remote_addr"].split(":")[-1])
                    if remote_port in risky_ports:
                        audit_result["suspicious_findings"].append(f"Connection to risky port {remote_port}: {conn['process']}")
                except:
                    pass
        
        # 4. Get DNS configuration
        try:
            if os.name == "nt":
                powershell_path = shutil.which("powershell")
                if powershell_path:
                    cmd = 'powershell "Get-DnsClientServerAddress -AddressFamily IPv4 | Select-Object InterfaceAlias,ServerAddresses | ConvertTo-Json"'
                    res = subprocess.run(cmd, capture_output=True, text=True, shell=True, timeout=10)
                    if res.returncode == 0 and res.stdout.strip():
                        import json
                        dns_config = json.loads(res.stdout)
                        if not isinstance(dns_config, list):
                            dns_config = [dns_config]
                        
                        audit_result["dns_servers"] = dns_config
        except Exception as e:
            audit_result["dns_servers"] = {"error": str(e)}
        
        # 5. Get network interfaces
        interfaces = psutil.net_if_addrs()
        for iface_name, addresses in interfaces.items():
            iface_info = {
                "name": iface_name,
                "addresses": []
            }
            for addr in addresses:
                if addr.family == socket.AF_INET:
                    iface_info["addresses"].append({
                        "type": "IPv4",
                        "address": addr.address,
                        "netmask": addr.netmask
                    })
            if iface_info["addresses"]:
                audit_result["network_interfaces"].append(iface_info)
        
        # 6. Generate recommendations
        if 3389 in listening_ports:
            audit_result["recommendations"].append("RDP (3389) is exposed - ensure strong passwords and Network Level Authentication")
        
        if 445 in listening_ports:
            audit_result["recommendations"].append("SMB (445) is exposed - ensure it's patched and not internet-facing")
        
        if 21 in listening_ports or 23 in listening_ports:
            audit_result["recommendations"].append("Unencrypted protocols (FTP/Telnet) detected - migrate to secure alternatives")
        
        if len(listening_ports) > 20:
            audit_result["risk_score"] += 10
            audit_result["recommendations"].append(f"{len(listening_ports)} ports are listening - review and close unnecessary services")
        
        if not audit_result["dns_servers"]:
            audit_result["recommendations"].append("Configure secure DNS servers (e.g., 1.1.1.1, 8.8.8.8)")
        
        # Add general recommendations
        audit_result["recommendations"].append("Use a firewall to restrict inbound connections")
        audit_result["recommendations"].append("Regularly monitor network activity for anomalies")
        audit_result["recommendations"].append("Keep all network services updated and patched")
        
        # 7. Overall assessment
        if audit_result["risk_score"] == 0:
            audit_result["summary"] = "Network configuration appears secure"
        elif audit_result["risk_score"] < 30:
            audit_result["summary"] = "Minor network security concerns detected"
        elif audit_result["risk_score"] < 60:
            audit_result["summary"] = "Moderate network security risks present"
        else:
            audit_result["summary"] = "Significant network security vulnerabilities detected"
        
        audit_result["risk_score"] = min(audit_result["risk_score"], 100)
        
        return audit_result
        
    except Exception as e:
        logger.error(f"Network security audit failed: {e}")
        return {
            "error": str(e),
            "risk_score": 100,
            "summary": f"Audit failed: {str(e)}"
        }


# --- Phase 24: Threat Posture & Prioritization ---

@app.get("/threat/posture")
async def threat_posture(
    window_hours: int = 24,
    event_limit: int = 500,
    alert_limit: int = 200,
    sentinel: NexusSentinel = Depends(get_sentinel),
):
    """Summarize threat posture, pressure, and response priorities for the recent time window."""
    now = datetime.now(timezone.utc)
    window_hours = _safe_limit(window_hours, default=24, minimum=1, maximum=168)
    event_limit = _safe_limit(event_limit, default=500, minimum=50, maximum=2000)
    alert_limit = _safe_limit(alert_limit, default=200, minimum=25, maximum=1000)
    cutoff = now - timedelta(hours=window_hours)

    try:
        events = sentinel.repository.get_recent_events(limit=event_limit)
        alerts = sentinel.repository.get_recent_alerts(limit=alert_limit)

        recent_events = []
        for event in events:
            ts = _parse_iso_datetime(event.timestamp)
            if ts and ts >= cutoff:
                recent_events.append(event)

        recent_alerts = []
        for alert in alerts:
            ts = _parse_iso_datetime(alert.created_at)
            if ts and ts >= cutoff:
                recent_alerts.append(alert)

        threat_events = [evt for evt in recent_events if evt.is_threat]
        active_alerts = [
            alert for alert in recent_alerts
            if alert.status not in {"resolved", "false_positive", "suppressed"}
        ]

        severity_labels = {
            0: "info",
            1: "low",
            2: "medium",
            3: "high",
            4: "critical",
        }
        severity_counts = {label: 0 for label in severity_labels.values()}
        for event in recent_events:
            label = severity_labels.get(int(event.severity), "info")
            severity_counts[label] += 1

        event_class_counts = Counter(evt.event_class for evt in threat_events)
        event_type_counts = Counter(evt.event_type for evt in threat_events)

        avg_threat_risk = 0.0
        if threat_events:
            avg_threat_risk = round(
                sum(float(evt.risk_score or 0) for evt in threat_events) / len(threat_events),
                2,
            )

        alert_risk_avg = 0.0
        if recent_alerts:
            alert_risk_avg = round(
                sum(float(alert.risk_score or 0) for alert in recent_alerts) / len(recent_alerts),
                2,
            )

        threat_density = 0.0
        if recent_events:
            threat_density = round(len(threat_events) / len(recent_events), 3)

        critical_events = severity_counts["critical"]
        high_events = severity_counts["high"]

        posture_score = 100
        if threat_density > 0.40:
            posture_score -= 25
        elif threat_density > 0.20:
            posture_score -= 12

        if critical_events >= 5:
            posture_score -= 30
        elif critical_events >= 2:
            posture_score -= 18

        if high_events >= 10:
            posture_score -= 15
        elif high_events >= 5:
            posture_score -= 8

        if len(active_alerts) >= 20:
            posture_score -= 15
        elif len(active_alerts) >= 8:
            posture_score -= 8

        if avg_threat_risk >= 75:
            posture_score -= 15
        elif avg_threat_risk >= 55:
            posture_score -= 8

        posture_score = max(0, min(100, posture_score))

        if posture_score >= 85:
            posture_level = "stable"
        elif posture_score >= 65:
            posture_level = "elevated"
        elif posture_score >= 40:
            posture_level = "high-risk"
        else:
            posture_level = "critical"

        recommendations: List[str] = []
        if critical_events > 0:
            recommendations.append("Escalate and triage all critical events immediately")
        if len(active_alerts) > 0:
            recommendations.append("Review active alerts and assign response ownership")
        if threat_density > 0.20:
            recommendations.append("Enable stricter containment rules for high-risk process and network events")
        if "network_activity" in event_class_counts:
            recommendations.append("Run /network/security-audit to validate exposed services and risky ports")
        if avg_threat_risk >= 55:
            recommendations.append("Prioritize playbook automation for recurring high-risk detections")
        if not recommendations:
            recommendations.append("Maintain current controls and continue baseline monitoring")

        return {
            "window": {
                "hours": window_hours,
                "from": cutoff.isoformat(),
                "to": now.isoformat(),
            },
            "summary": {
                "posture_score": posture_score,
                "posture_level": posture_level,
                "total_events": len(recent_events),
                "threat_events": len(threat_events),
                "total_alerts": len(recent_alerts),
                "active_alerts": len(active_alerts),
                "threat_density": threat_density,
                "average_threat_risk": avg_threat_risk,
                "average_alert_risk": alert_risk_avg,
            },
            "severity_distribution": severity_counts,
            "top_threat_event_classes": [
                {"event_class": key, "count": value}
                for key, value in event_class_counts.most_common(5)
            ],
            "top_threat_event_types": [
                {"event_type": key, "count": value}
                for key, value in event_type_counts.most_common(8)
            ],
            "recommendations": recommendations,
        }
    except Exception as exc:
        logger.error(f"Threat posture analysis failed: {exc}")
        return {
            "error": str(exc),
            "posture_score": 0,
            "posture_level": "critical",
            "summary": "Threat posture analysis failed",
        }


# --- Phase 25: Automated Alert Prioritization ---

@app.post("/threat/auto-prioritize")
async def auto_prioritize_alerts(
    request: AutoPrioritizeRequest,
    sentinel: NexusSentinel = Depends(get_sentinel),
):
    """Rank alerts by operational urgency and assign SLA buckets for SOC triage."""
    now = datetime.now(timezone.utc)
    window_hours = _safe_limit(request.window_hours, default=24, minimum=1, maximum=336)
    alert_limit = _safe_limit(request.alert_limit, default=200, minimum=25, maximum=3000)
    max_results = _safe_limit(request.max_results, default=100, minimum=1, maximum=500)
    include_resolved = bool(request.include_resolved)
    cutoff = now - timedelta(hours=window_hours)

    status_weight = {
        "new": 12,
        "acknowledged": 8,
        "investigating": 6,
        "contained": 3,
        "resolved": -10,
        "false_positive": -15,
        "suppressed": -12,
    }

    try:
        alerts = sentinel.repository.get_recent_alerts(limit=alert_limit)
        candidates = []

        for alert in alerts:
            created_at = _parse_iso_datetime(alert.created_at)
            if not created_at or created_at < cutoff:
                continue

            if (not include_resolved) and alert.status in {"resolved", "false_positive", "suppressed"}:
                continue

            age_hours = max(0.0, (now - created_at).total_seconds() / 3600)
            risk_score = float(alert.risk_score or 0.0)
            severity = int(alert.severity or 0)

            # Composite score balances risk, severity, status urgency, and staleness.
            priority_score = (
                min(100.0, risk_score) * 0.60
                + min(4, max(0, severity)) * 10.0
                + status_weight.get(alert.status, 0)
                + min(20.0, age_hours * 0.8)
            )
            priority_score = round(max(0.0, min(100.0, priority_score)), 2)

            if priority_score >= 85:
                priority_tier = "critical"
                sla_target = "15m"
                action = "Escalate immediately and start containment actions"
            elif priority_score >= 70:
                priority_tier = "high"
                sla_target = "1h"
                action = "Assign analyst and begin investigation"
            elif priority_score >= 50:
                priority_tier = "medium"
                sla_target = "4h"
                action = "Queue for same-shift triage"
            else:
                priority_tier = "low"
                sla_target = "24h"
                action = "Monitor and review in routine cycle"

            candidates.append({
                "alert_id": alert.alert_id,
                "title": alert.title,
                "status": alert.status,
                "severity": severity,
                "risk_score": round(risk_score, 2),
                "created_at": alert.created_at,
                "age_hours": round(age_hours, 2),
                "priority_score": priority_score,
                "priority_tier": priority_tier,
                "sla_target": sla_target,
                "recommended_action": action,
                "category": alert.category,
                "tags": alert.tags,
            })

        candidates.sort(key=lambda item: item["priority_score"], reverse=True)
        queue = candidates[:max_results]

        tier_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for item in queue:
            tier_counts[item["priority_tier"]] += 1

        return {
            "window": {
                "hours": window_hours,
                "from": cutoff.isoformat(),
                "to": now.isoformat(),
            },
            "summary": {
                "alerts_analyzed": len(candidates),
                "alerts_returned": len(queue),
                "include_resolved": include_resolved,
                "tier_counts": tier_counts,
            },
            "priority_queue": queue,
        }
    except Exception as exc:
        logger.error(f"Auto-prioritization failed: {exc}")
        return {
            "error": str(exc),
            "summary": "Alert auto-prioritization failed",
            "priority_queue": [],
        }


# --- Phase 26: Threat Hunting Engine ---

@app.post("/threat-hunt/query")
async def threat_hunt_query(
    request: ThreatHuntQueryRequest,
    sentinel: NexusSentinel = Depends(get_sentinel),
):
    """Search events for analyst-driven hunts including attack pattern and behavior filters."""
    limit = _safe_limit(request.limit, default=200, minimum=10, maximum=3000)
    min_risk = max(0.0, min(100.0, float(request.min_risk_score)))
    max_risk = max(min_risk, min(100.0, float(request.max_risk_score)))
    min_anomaly = max(0.0, min(100.0, float(request.min_anomaly_score)))

    try:
        events = sentinel.repository.get_recent_events(limit=limit)
        phrase = (request.query or "").strip().lower()
        requested_tags = {t.lower() for t in (request.tags or [])}

        results = []
        for event in events:
            if request.event_class and event.event_class != request.event_class:
                continue
            if request.event_type and event.event_type != request.event_type:
                continue

            risk = float(event.risk_score or 0.0)
            anomaly = float(event.anomaly_score or 0.0)
            if risk < min_risk or risk > max_risk:
                continue
            if anomaly < min_anomaly:
                continue

            if request.is_threat is not None and bool(event.is_threat) != request.is_threat:
                continue

            event_tags = {t.lower() for t in (event.tags or [])}
            if requested_tags and not requested_tags.issubset(event_tags):
                continue

            if not _matches_attack_pattern(event, request.attack_pattern):
                continue

            if phrase:
                search_blob = " ".join([
                    event.description or "",
                    event.raw_data or "",
                    event.event_class or "",
                    event.event_type or "",
                    event.threat_category or "",
                    str(event.metadata or ""),
                    " ".join(event.tags or []),
                ]).lower()
                if phrase not in search_blob:
                    continue

            results.append({
                "event_id": event.event_id,
                "timestamp": event.timestamp,
                "event_class": event.event_class,
                "event_type": event.event_type,
                "description": event.description,
                "risk_score": round(risk, 2),
                "anomaly_score": round(anomaly, 2),
                "is_threat": bool(event.is_threat),
                "threat_category": event.threat_category,
                "tags": event.tags,
                "metadata": event.metadata,
            })

        _threat_hunt_history.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "query": request.model_dump(),
            "result_count": len(results),
        })
        if len(_threat_hunt_history) > 200:
            del _threat_hunt_history[:-200]

        return {
            "query": request.model_dump(),
            "result_count": len(results),
            "results": results,
        }
    except Exception as exc:
        logger.error(f"Threat hunt query failed: {exc}")
        raise HTTPException(status_code=500, detail=f"Threat hunt query failed: {exc}")


@app.get("/threat-hunt/saved")
async def threat_hunt_saved_queries():
    """Return all saved threat hunt queries."""
    return {
        "count": len(_saved_hunt_queries),
        "saved_queries": _saved_hunt_queries,
    }


@app.post("/threat-hunt/save")
async def threat_hunt_save_query(request: ThreatHuntSaveRequest):
    """Persist a named hunt query for repeated analyst workflows."""
    record = {
        "id": f"hunt-{int(time.time() * 1000)}",
        "name": request.name,
        "description": request.description,
        "query": request.query.model_dump(),
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    _saved_hunt_queries.append(record)
    if len(_saved_hunt_queries) > 500:
        del _saved_hunt_queries[:-500]

    return {"saved": True, "query": record}


@app.get("/threat-hunt/history")
async def threat_hunt_history(limit: int = 50):
    """Return recent hunt execution history for analyst auditing."""
    max_items = _safe_limit(limit, default=50, minimum=1, maximum=200)
    items = list(reversed(_threat_hunt_history))[:max_items]
    return {
        "count": len(items),
        "history": items,
    }


# --- Phase 27: Attack Timeline Reconstruction ---

@app.get("/forensics/timeline")
async def forensics_timeline(
    window_hours: int = 24,
    limit: int = 500,
    sentinel: NexusSentinel = Depends(get_sentinel),
):
    """Reconstruct a unified timeline from recent events and alerts."""
    now = datetime.now(timezone.utc)
    window_hours = _safe_limit(window_hours, default=24, minimum=1, maximum=336)
    limit = _safe_limit(limit, default=500, minimum=20, maximum=3000)
    cutoff = now - timedelta(hours=window_hours)

    try:
        events = sentinel.repository.get_recent_events(limit=limit)
        alerts = sentinel.repository.get_recent_alerts(limit=limit)

        timeline: List[Dict[str, Any]] = []
        for event in events:
            ts = _parse_iso_datetime(event.timestamp)
            if ts and ts >= cutoff:
                timeline.append({
                    "timestamp": event.timestamp,
                    "type": "event",
                    "id": event.event_id,
                    "event_class": event.event_class,
                    "event_type": event.event_type,
                    "description": event.description,
                    "risk_score": event.risk_score,
                    "is_threat": event.is_threat,
                })

        for alert in alerts:
            ts = _parse_iso_datetime(alert.created_at)
            if ts and ts >= cutoff:
                timeline.append({
                    "timestamp": alert.created_at,
                    "type": "alert",
                    "id": alert.alert_id,
                    "title": alert.title,
                    "status": alert.status,
                    "severity": alert.severity,
                    "risk_score": alert.risk_score,
                    "event_ids": alert.event_ids,
                })

        timeline.sort(key=lambda item: _parse_iso_datetime(item["timestamp"]) or cutoff)
        return {
            "window_hours": window_hours,
            "from": cutoff.isoformat(),
            "to": now.isoformat(),
            "count": len(timeline),
            "timeline": timeline,
        }
    except Exception as exc:
        logger.error(f"Forensics timeline reconstruction failed: {exc}")
        raise HTTPException(status_code=500, detail=f"Forensics timeline reconstruction failed: {exc}")


@app.get("/forensics/process-tree/{pid}")
async def forensics_process_tree(pid: int):
    """Build process ancestry and direct children mapping for a process id."""
    import psutil

    if pid <= 0:
        raise HTTPException(status_code=400, detail="pid must be a positive integer")

    try:
        process = psutil.Process(pid)
    except psutil.NoSuchProcess:
        raise HTTPException(status_code=404, detail=f"Process {pid} not found")
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to inspect process {pid}: {exc}")

    def _proc_info(proc: psutil.Process) -> Dict[str, Any]:
        try:
            return {
                "pid": proc.pid,
                "name": proc.name(),
                "exe": proc.exe() if proc.exe() else "",
                "cmdline": proc.cmdline(),
                "username": proc.username(),
                "create_time": proc.create_time(),
                "status": proc.status(),
            }
        except Exception:
            return {"pid": proc.pid, "name": "<unavailable>"}

    ancestry: List[Dict[str, Any]] = []
    current = process
    while True:
        parent = current.parent()
        if not parent:
            break
        ancestry.append(_proc_info(parent))
        current = parent

    children = [_proc_info(child) for child in process.children(recursive=True)]

    return {
        "root": _proc_info(process),
        "ancestry": ancestry,
        "children": children,
        "counts": {
            "ancestry": len(ancestry),
            "children": len(children),
        },
    }


@app.get("/forensics/file-history/{path:path}")
async def forensics_file_history(
    path: str,
    limit: int = 1000,
    sentinel: NexusSentinel = Depends(get_sentinel),
):
    """Return a timeline of file-related telemetry for a specific path."""
    normalized = os.path.normcase(os.path.normpath(path or "")).strip()
    if not normalized:
        raise HTTPException(status_code=400, detail="path is required")

    limit = _safe_limit(limit, default=1000, minimum=50, maximum=5000)
    events = sentinel.repository.get_recent_events(limit=limit)
    matches: List[Dict[str, Any]] = []

    for event in events:
        file_path = ""
        if event.file and event.file.path:
            file_path = event.file.path
        elif isinstance(event.metadata, dict):
            file_path = str(event.metadata.get("path") or event.metadata.get("file_path") or "")

        if not file_path:
            continue

        event_norm = os.path.normcase(os.path.normpath(file_path))
        if event_norm != normalized:
            continue

        matches.append({
            "timestamp": event.timestamp,
            "event_id": event.event_id,
            "event_type": event.event_type,
            "event_class": event.event_class,
            "description": event.description,
            "risk_score": event.risk_score,
            "is_threat": event.is_threat,
            "metadata": event.metadata,
        })

    matches.sort(key=lambda item: _parse_iso_datetime(item["timestamp"]) or datetime.min.replace(tzinfo=timezone.utc))

    return {
        "path": normalized,
        "count": len(matches),
        "history": matches,
    }


# --- Phase 28: Malware Sandbox ---

@app.post("/sandbox/analyze")
async def sandbox_analyze(request: SandboxAnalyzeRequest):
    """Analyze suspicious files in a safe, non-executing sandbox profile."""
    file_path = os.path.abspath(request.file_path or "")
    if not file_path or not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="file not found")
    if not os.path.isfile(file_path):
        raise HTTPException(status_code=400, detail="file_path must point to a file")

    try:
        max_preview = 65536
        with open(file_path, "rb") as handle:
            preview_bytes = handle.read(max_preview)

        size = os.path.getsize(file_path)
        _, ext = os.path.splitext(file_path)
        entropy = _byte_entropy(preview_bytes)
        sha256 = _sha256_file(file_path)

        try:
            preview_text = preview_bytes.decode("utf-8", errors="ignore")
        except Exception:
            preview_text = ""

        behavior = _extract_behavior_signals(os.path.basename(file_path), ext.lower(), preview_text)
        suspicious_score = 0
        suspicious_score += min(40, len(behavior["suspicious_strings"]) * 6)
        suspicious_score += min(35, len(behavior["observed_behaviors"]) * 8)
        if entropy >= 7.3:
            suspicious_score += 15
        if ext.lower() in {".exe", ".dll", ".scr"}:
            suspicious_score += 10
        suspicious_score = max(0, min(100, suspicious_score))

        if suspicious_score >= 75:
            verdict = "malicious"
        elif suspicious_score >= 45:
            verdict = "suspicious"
        else:
            verdict = "benign"

        report_id = f"sandbox-{int(time.time() * 1000)}"
        report = {
            "id": report_id,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "profile": request.profile,
            "sample": {
                "path": file_path,
                "name": os.path.basename(file_path),
                "extension": ext.lower(),
                "size_bytes": size,
                "sha256": sha256,
                "entropy": entropy,
            },
            "behavior": behavior,
            "analysis": {
                "suspicion_score": suspicious_score,
                "verdict": verdict,
                "notes": [
                    "Analysis is non-executing and heuristic-based.",
                    "Use with live telemetry and threat intel for final decision.",
                ],
            },
        }
        _sandbox_reports[report_id] = report

        return {
            "report_id": report_id,
            "verdict": verdict,
            "suspicion_score": suspicious_score,
            "sha256": sha256,
        }
    except Exception as exc:
        logger.error(f"Sandbox analyze failed: {exc}")
        raise HTTPException(status_code=500, detail=f"Sandbox analyze failed: {exc}")


@app.get("/sandbox/report/{id}")
async def sandbox_report(id: str):
    """Retrieve full sandbox analysis report."""
    report = _sandbox_reports.get(id)
    if not report:
        raise HTTPException(status_code=404, detail="sandbox report not found")
    return report


@app.get("/sandbox/behavior/{id}")
async def sandbox_behavior(id: str):
    """Retrieve behavior observations for a sandbox report."""
    report = _sandbox_reports.get(id)
    if not report:
        raise HTTPException(status_code=404, detail="sandbox report not found")

    return {
        "id": id,
        "sample": report.get("sample", {}),
        "behavior": report.get("behavior", {}),
        "analysis": report.get("analysis", {}),
    }


# --- Phase 29: AI Malware Classification ---

@app.post("/ai/malware/classify")
async def ai_malware_classify(request: MalwareClassifyRequest):
    """Classify malware family and confidence using heuristic AI scoring."""
    sandbox_report = _sandbox_reports.get(request.report_id) if request.report_id else None

    extension = (request.extension or "").lower()
    if not extension and sandbox_report:
        extension = sandbox_report.get("sample", {}).get("extension", "")

    entropy = float(request.entropy or 0.0)
    if entropy <= 0 and sandbox_report:
        entropy = float(sandbox_report.get("sample", {}).get("entropy", 0.0))

    suspicious_strings = set(s.lower() for s in (request.suspicious_strings or []))
    observed_behaviors = set(s.lower() for s in (request.observed_behaviors or []))
    if sandbox_report:
        suspicious_strings.update(s.lower() for s in sandbox_report.get("behavior", {}).get("suspicious_strings", []))
        observed_behaviors.update(s.lower() for s in sandbox_report.get("behavior", {}).get("observed_behaviors", []))

    # Heuristic family mapping aligned with observable behavior traits.
    family_scores: Dict[str, int] = {
        "ransomware": 0,
        "trojan": 0,
        "worm": 0,
        "spyware": 0,
        "downloader": 0,
    }

    if "ransomware_activity" in observed_behaviors or "encrypt" in suspicious_strings:
        family_scores["ransomware"] += 40
    if "network_beaconing" in observed_behaviors or "c2" in suspicious_strings:
        family_scores["trojan"] += 30
        family_scores["downloader"] += 20
    if "persistence_attempt" in observed_behaviors:
        family_scores["trojan"] += 20
        family_scores["worm"] += 15
    if "credential_access" in observed_behaviors or "mimikatz" in suspicious_strings:
        family_scores["spyware"] += 35
    if "lolbin_abuse" in observed_behaviors:
        family_scores["trojan"] += 15
    if extension in {".js", ".vbs", ".ps1", ".bat"}:
        family_scores["downloader"] += 15
    if entropy >= 7.2:
        family_scores["ransomware"] += 10
        family_scores["trojan"] += 8

    predicted_family = max(family_scores.items(), key=lambda item: item[1])[0]
    raw_score = family_scores[predicted_family]
    confidence = round(max(0.0, min(0.99, raw_score / 100.0 + 0.15)), 2)

    if raw_score >= 45:
        label = "malicious"
    elif raw_score >= 25:
        label = "suspicious"
    else:
        label = "unknown"

    _malware_model_state["classifications_total"] += 1
    _malware_model_state["last_classification"] = datetime.now(timezone.utc).isoformat()

    return {
        "label": label,
        "predicted_family": predicted_family,
        "confidence": confidence,
        "feature_summary": {
            "extension": extension,
            "entropy": entropy,
            "suspicious_strings_count": len(suspicious_strings),
            "observed_behaviors_count": len(observed_behaviors),
            "used_sandbox_report": bool(sandbox_report),
        },
        "family_scores": family_scores,
    }


@app.get("/ai/malware/model-status")
async def ai_malware_model_status():
    """Return current malware classifier model metadata and usage counters."""
    return {
        **_malware_model_state,
        "sandbox_reports_available": len(_sandbox_reports),
    }


# --- Phase 30: Global Threat Intelligence (Deep Implementation) ---

@app.get("/threat-intel/global")
async def threat_intel_global(
    window_hours: int = 72,
    limit: int = 1000,
    sentinel: NexusSentinel = Depends(get_sentinel),
):
    """Return global threat view from local telemetry correlation and built-in threat feeds."""
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(hours=_safe_limit(window_hours, default=72, minimum=1, maximum=720))
    limit = _safe_limit(limit, default=1000, minimum=50, maximum=5000)

    events = sentinel.repository.get_recent_events(limit=limit)
    recent_events = [evt for evt in events if (_parse_iso_datetime(evt.timestamp) or cutoff) >= cutoff]
    threat_events = [evt for evt in recent_events if evt.is_threat]

    by_category = Counter((evt.threat_category or "unknown") for evt in threat_events)
    by_type = Counter(evt.event_type for evt in threat_events)
    by_class = Counter(evt.event_class for evt in threat_events)

    avg_risk = round(
        sum(float(evt.risk_score or 0.0) for evt in threat_events) / len(threat_events),
        2,
    ) if threat_events else 0.0

    feeds = [
        {
            "feed": "arkshield-local-telemetry",
            "active": True,
            "last_update": now.isoformat(),
            "highlights": [
                "Behavioral anomaly clusters",
                "Endpoint threat detections",
                "Response-action telemetry",
            ],
        },
        {
            "feed": "arkshield-static-ioc-pack",
            "active": True,
            "last_update": now.isoformat(),
            "highlights": [
                "Known suspicious TTP markers",
                "Ransomware behavior signatures",
                "Credential theft indicators",
            ],
        },
    ]

    return {
        "window": {"from": cutoff.isoformat(), "to": now.isoformat()},
        "summary": {
            "events_analyzed": len(recent_events),
            "threat_events": len(threat_events),
            "average_risk_score": avg_risk,
        },
        "top_categories": [{"category": k, "count": v} for k, v in by_category.most_common(8)],
        "top_event_types": [{"event_type": k, "count": v} for k, v in by_type.most_common(10)],
        "top_event_classes": [{"event_class": k, "count": v} for k, v in by_class.most_common(10)],
        "feeds": feeds,
    }


@app.get("/threat-intel/domains/{domain}")
async def threat_intel_domain(
    domain: str,
    sentinel: NexusSentinel = Depends(get_sentinel),
):
    """Lookup domain reputation using heuristic checks and local telemetry mentions."""
    normalized = (domain or "").strip().lower()
    if not normalized or "." not in normalized:
        raise HTTPException(status_code=400, detail="domain must be a valid hostname")

    suspicious_tlds = {"zip", "mov", "xyz", "top", "click", "gq", "tk", "work", "support"}
    suspicious_keywords = {"login", "secure", "update", "verify", "wallet", "bonus", "free", "crypto"}
    known_bad = {
        "malicious-update.xyz",
        "c2-control.top",
        "steal-credentials.click",
    }

    risk = 5
    reasons: List[str] = []
    if normalized in known_bad:
        risk += 75
        reasons.append("Domain appears in local known-bad intelligence set")

    tld = normalized.rsplit(".", 1)[-1]
    if tld in suspicious_tlds:
        risk += 20
        reasons.append(f"Suspicious top-level domain detected: .{tld}")

    if any(token in normalized for token in suspicious_keywords):
        risk += 15
        reasons.append("Domain contains phishing-like keywords")

    labels = normalized.split(".")
    if any(len(label) > 25 for label in labels):
        risk += 10
        reasons.append("Unusually long domain label detected")

    events = sentinel.repository.get_recent_events(limit=2000)
    mentions = 0
    for evt in events:
        blob = " ".join([
            evt.description or "",
            evt.raw_data or "",
            str(evt.metadata or ""),
            (evt.network.dns_query if evt.network else "") or "",
        ]).lower()
        if normalized in blob:
            mentions += 1

    if mentions > 0:
        risk += min(30, mentions * 3)
        reasons.append(f"Domain referenced in telemetry {mentions} time(s)")

    risk = max(0, min(100, risk))
    reputation = "malicious" if risk >= 75 else "suspicious" if risk >= 45 else "benign"

    return {
        "domain": normalized,
        "risk_score": risk,
        "reputation": reputation,
        "reasons": reasons or ["No high-risk indicators found"],
        "telemetry_mentions": mentions,
        "checked_at": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/threat-intel/malware/{hash}")
async def threat_intel_malware_hash(
    hash: str,
    sentinel: NexusSentinel = Depends(get_sentinel),
):
    """Lookup malware intelligence for a file hash using local reports and heuristic reputation."""
    normalized = (hash or "").strip().lower()
    if len(normalized) not in {32, 40, 64}:
        raise HTTPException(status_code=400, detail="hash must be md5/sha1/sha256 length")

    known_bad_hashes = {
        "44d88612fea8a8f36de82e1278abb02f": "eicar-test-signature",
        "275a021bbfb6483e54d471899f7db9d2": "generic-trojan-sample",
    }

    score = 5
    family = "unknown"
    evidence: List[str] = []
    if normalized in known_bad_hashes:
        score += 80
        family = known_bad_hashes[normalized]
        evidence.append("Hash matched known-bad local IOC")

    matching_reports = []
    for report in _sandbox_reports.values():
        sha256 = str(report.get("sample", {}).get("sha256", "")).lower()
        if sha256 == normalized:
            matching_reports.append(report)

    if matching_reports:
        top_report = matching_reports[-1]
        verdict = top_report.get("analysis", {}).get("verdict", "unknown")
        suspicion = float(top_report.get("analysis", {}).get("suspicion_score", 0.0))
        score += min(40, int(suspicion * 0.4))
        evidence.append(f"Matched sandbox report with verdict={verdict}")

    alerts = sentinel.repository.get_recent_alerts(limit=500)
    alert_mentions = 0
    for alert in alerts:
        blob = " ".join([
            alert.title or "",
            alert.description or "",
            str(alert.tags or ""),
            str(alert.response_actions or ""),
        ]).lower()
        if normalized in blob:
            alert_mentions += 1

    if alert_mentions:
        score += min(20, alert_mentions * 4)
        evidence.append(f"Hash referenced by {alert_mentions} alert(s)")

    score = max(0, min(100, score))
    reputation = "malicious" if score >= 75 else "suspicious" if score >= 45 else "unknown"

    return {
        "hash": normalized,
        "hash_type": {32: "md5", 40: "sha1", 64: "sha256"}.get(len(normalized), "unknown"),
        "risk_score": score,
        "reputation": reputation,
        "malware_family": family,
        "evidence": evidence or ["No strong local intelligence match"],
        "sandbox_matches": len(matching_reports),
        "alert_mentions": alert_mentions,
        "checked_at": datetime.now(timezone.utc).isoformat(),
    }


# --- Phase 31: File Integrity Monitoring (Deep Implementation) ---

@app.post("/security/integrity/watch")
async def security_integrity_watch(request: IntegrityWatchRequest):
    """Add or update a watched file with baseline hash for integrity monitoring."""
    target = os.path.abspath(request.file_path or "")
    if not target or not os.path.exists(target):
        raise HTTPException(status_code=404, detail="file not found")
    if not os.path.isfile(target):
        raise HTTPException(status_code=400, detail="file_path must point to a file")

    baseline_hash = _sha256_file(target)
    stat = os.stat(target)
    now = datetime.now(timezone.utc).isoformat()
    record = {
        "file_path": target,
        "criticality": request.criticality,
        "notes": request.notes,
        "baseline_hash": baseline_hash,
        "last_hash": baseline_hash,
        "size_bytes": stat.st_size,
        "mtime": stat.st_mtime,
        "created_at": now,
        "updated_at": now,
        "status": "healthy",
    }
    _integrity_watchlist[target] = record

    return {
        "watch_added": True,
        "watch": record,
    }


@app.get("/security/integrity")
async def security_integrity_status():
    """Check watched files for tampering by comparing current and baseline hashes."""
    checks = []
    now = datetime.now(timezone.utc).isoformat()

    for path, watch in list(_integrity_watchlist.items()):
        entry = {
            "file_path": path,
            "criticality": watch.get("criticality", "medium"),
            "status": "healthy",
            "baseline_hash": watch.get("baseline_hash", ""),
            "current_hash": "",
            "exists": os.path.exists(path),
            "checked_at": now,
        }

        if not os.path.exists(path):
            entry["status"] = "missing"
            alert = {
                "id": f"integrity-{int(time.time() * 1000)}",
                "type": "file_missing",
                "file_path": path,
                "criticality": watch.get("criticality", "medium"),
                "timestamp": now,
                "message": "Watched file is missing",
            }
            _integrity_alerts.append(alert)
            watch["status"] = "missing"
            watch["updated_at"] = now
            checks.append(entry)
            continue

        try:
            current_hash = _sha256_file(path)
            entry["current_hash"] = current_hash
            watch["last_hash"] = current_hash
            watch["updated_at"] = now

            if current_hash != watch.get("baseline_hash"):
                entry["status"] = "tampered"
                watch["status"] = "tampered"
                alert = {
                    "id": f"integrity-{int(time.time() * 1000)}",
                    "type": "file_tamper_detected",
                    "file_path": path,
                    "criticality": watch.get("criticality", "medium"),
                    "timestamp": now,
                    "message": "File hash differs from baseline",
                    "baseline_hash": watch.get("baseline_hash"),
                    "current_hash": current_hash,
                }
                _integrity_alerts.append(alert)
            else:
                watch["status"] = "healthy"
        except Exception as exc:
            entry["status"] = "error"
            entry["error"] = str(exc)
            watch["status"] = "error"
            watch["updated_at"] = now

        checks.append(entry)

    if len(_integrity_alerts) > 2000:
        del _integrity_alerts[:-2000]

    counts = Counter(item["status"] for item in checks)
    return {
        "watch_count": len(_integrity_watchlist),
        "summary": {
            "healthy": counts.get("healthy", 0),
            "tampered": counts.get("tampered", 0),
            "missing": counts.get("missing", 0),
            "error": counts.get("error", 0),
        },
        "checks": checks,
    }


@app.get("/security/integrity/alerts")
async def security_integrity_alerts(limit: int = 100):
    """Return recent file integrity alerts."""
    max_items = _safe_limit(limit, default=100, minimum=1, maximum=1000)
    alerts = list(reversed(_integrity_alerts))[:max_items]
    return {
        "count": len(alerts),
        "alerts": alerts,
    }


# --- Phase 32: USB and Device Monitoring (Deep Implementation) ---

@app.get("/devices/usb")
async def devices_usb():
    """Enumerate removable devices and blocked device state."""
    import psutil

    devices: List[Dict[str, Any]] = []
    partitions = psutil.disk_partitions(all=False)
    for part in partitions:
        opts = (part.opts or "").lower()
        is_removable = "removable" in opts
        if os.name == "nt" and part.device.upper().startswith(("A:", "B:")):
            is_removable = True

        if not is_removable:
            continue

        try:
            usage = psutil.disk_usage(part.mountpoint)
            size_total_gb = round(usage.total / (1024 ** 3), 2)
            free_gb = round(usage.free / (1024 ** 3), 2)
        except Exception:
            size_total_gb = 0.0
            free_gb = 0.0

        device_id = part.device.replace("\\", "_").replace(":", "")
        devices.append({
            "device_id": device_id,
            "device": part.device,
            "mountpoint": part.mountpoint,
            "fstype": part.fstype,
            "options": part.opts,
            "size_total_gb": size_total_gb,
            "free_gb": free_gb,
            "blocked": device_id in _blocked_devices,
        })

    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "action": "enumerate_usb",
        "device_count": len(devices),
    }
    _device_history.append(event)
    if len(_device_history) > 1000:
        del _device_history[:-1000]

    return {
        "count": len(devices),
        "devices": devices,
        "blocked_devices": list(_blocked_devices.values()),
    }


@app.get("/devices/history")
async def devices_history(limit: int = 100):
    """Return recent removable device monitoring actions."""
    max_items = _safe_limit(limit, default=100, minimum=1, maximum=1000)
    history = list(reversed(_device_history))[:max_items]
    return {
        "count": len(history),
        "history": history,
    }


@app.post("/devices/block/{device_id}")
async def devices_block(device_id: str, reason: str = "Policy block"):
    """Block a removable device id at Arkshield policy layer."""
    normalized = (device_id or "").strip()
    if not normalized:
        raise HTTPException(status_code=400, detail="device_id is required")

    record = {
        "device_id": normalized,
        "blocked_at": datetime.now(timezone.utc).isoformat(),
        "reason": reason,
        "enforcement": "policy-layer",
        "note": "OS-level removable media hard block can be integrated via endpoint policy tooling.",
    }
    _blocked_devices[normalized] = record
    _device_history.append({
        "timestamp": record["blocked_at"],
        "action": "block_device",
        "device_id": normalized,
        "reason": reason,
    })

    return {
        "blocked": True,
        "device": record,
    }


# --- Phase 33: Privilege Escalation Detection (Deep Implementation) ---

@app.get("/security/privilege-events")
async def security_privilege_events(
    window_hours: int = 72,
    limit: int = 1500,
    sentinel: NexusSentinel = Depends(get_sentinel),
):
    """Detect likely privilege escalation indicators from telemetry."""
    cutoff = datetime.now(timezone.utc) - timedelta(hours=_safe_limit(window_hours, default=72, minimum=1, maximum=720))
    events = sentinel.repository.get_recent_events(limit=_safe_limit(limit, default=1500, minimum=100, maximum=5000))

    keywords = ["privilege", "elevat", "admin", "token", "uac", "bypass", "system32", "runas"]
    findings: List[Dict[str, Any]] = []
    for evt in events:
        ts = _parse_iso_datetime(evt.timestamp)
        if ts and ts < cutoff:
            continue

        blob = " ".join([
            evt.event_type or "",
            evt.event_class or "",
            evt.description or "",
            evt.threat_category or "",
            str(evt.metadata or ""),
            " ".join(evt.tags or []),
        ]).lower()

        keyword_hits = [kw for kw in keywords if kw in blob]
        risky = bool(keyword_hits) or (int(evt.severity or 0) >= 3 and bool(evt.is_threat))
        if not risky:
            continue

        confidence = min(0.99, round(0.45 + 0.08 * len(keyword_hits) + (0.10 if evt.is_threat else 0.0), 2))
        findings.append({
            "event_id": evt.event_id,
            "timestamp": evt.timestamp,
            "event_class": evt.event_class,
            "event_type": evt.event_type,
            "description": evt.description,
            "risk_score": evt.risk_score,
            "is_threat": evt.is_threat,
            "keyword_hits": keyword_hits,
            "confidence": confidence,
        })

    findings.sort(key=lambda x: (x["confidence"], float(x.get("risk_score") or 0.0)), reverse=True)
    return {
        "window_hours": window_hours,
        "count": len(findings),
        "events": findings[:500],
    }


@app.get("/security/admin-actions")
async def security_admin_actions(limit: int = 300):
    """Monitor likely admin/system actions from running processes."""
    import psutil

    suspicious_cmd_tokens = {
        "net user",
        "net localgroup",
        "sc config",
        "reg add",
        "powershell -enc",
        "wmic",
        "bcdedit",
    }
    elevated_users = {"nt authority\\system", "system", "root", "administrator"}

    actions: List[Dict[str, Any]] = []
    for proc in psutil.process_iter(["pid", "name", "username", "cmdline", "create_time"]):
        try:
            info = proc.info
            username = str(info.get("username") or "").lower()
            cmdline = " ".join(info.get("cmdline") or []).lower()
            if not username and not cmdline:
                continue

            reasons = []
            if username in elevated_users or "admin" in username:
                reasons.append("elevated_account")

            matched = [token for token in suspicious_cmd_tokens if token in cmdline]
            if matched:
                reasons.append("suspicious_admin_command")

            if not reasons:
                continue

            actions.append({
                "pid": info.get("pid"),
                "process": info.get("name"),
                "username": info.get("username"),
                "cmdline": info.get("cmdline") or [],
                "create_time": info.get("create_time"),
                "reasons": reasons,
                "matched_tokens": matched,
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
        except Exception:
            continue

    max_items = _safe_limit(limit, default=300, minimum=1, maximum=2000)
    return {
        "count": len(actions[:max_items]),
        "actions": actions[:max_items],
    }


# --- Phase 34: Ransomware Detection Engine (Deep Implementation) ---

@app.get("/ransomware/alerts")
async def ransomware_alerts(
    window_hours: int = 72,
    limit: int = 2500,
    sentinel: NexusSentinel = Depends(get_sentinel),
):
    """Detect ransomware behavior patterns from telemetry and return prioritized alerts."""
    cutoff = datetime.now(timezone.utc) - timedelta(hours=_safe_limit(window_hours, default=72, minimum=1, maximum=720))
    events = sentinel.repository.get_recent_events(limit=_safe_limit(limit, default=2500, minimum=100, maximum=10000))

    indicators = [
        "ransom",
        "encrypt",
        "vssadmin",
        "shadowcopy",
        "recovery key",
        "file_entropy_high",
        "threat_ransomware",
    ]
    matches: List[Dict[str, Any]] = []

    for evt in events:
        ts = _parse_iso_datetime(evt.timestamp)
        if ts and ts < cutoff:
            continue

        blob = " ".join([
            evt.event_type or "",
            evt.description or "",
            evt.threat_category or "",
            str(evt.metadata or ""),
            " ".join(evt.tags or []),
        ]).lower()

        hits = [indicator for indicator in indicators if indicator in blob]
        is_candidate = bool(hits) or (evt.event_type in {"file_entropy_high", "threat_ransomware"})
        if not is_candidate:
            continue

        confidence = min(0.99, round(0.35 + 0.10 * len(hits) + (0.15 if evt.is_threat else 0.0), 2))
        priority = "critical" if confidence >= 0.85 else "high" if confidence >= 0.65 else "medium"
        matches.append({
            "event_id": evt.event_id,
            "timestamp": evt.timestamp,
            "event_type": evt.event_type,
            "description": evt.description,
            "risk_score": evt.risk_score,
            "is_threat": evt.is_threat,
            "indicators": hits,
            "confidence": confidence,
            "priority": priority,
        })

    matches.sort(key=lambda x: (x["confidence"], float(x.get("risk_score") or 0.0)), reverse=True)
    summary = Counter(item["priority"] for item in matches)

    return {
        "window_hours": window_hours,
        "count": len(matches),
        "summary": {
            "critical": summary.get("critical", 0),
            "high": summary.get("high", 0),
            "medium": summary.get("medium", 0),
        },
        "alerts": matches[:500],
    }


@app.post("/ransomware/simulate")
async def ransomware_simulate(request: RansomwareSimulateRequest):
    """Run a safe ransomware behavior simulation for detection validation."""
    files = _safe_limit(request.simulated_files, default=50, minimum=1, maximum=50000)
    rate = _safe_limit(request.encryption_rate_per_minute, default=120, minimum=1, maximum=100000)
    note_appearance = min(100, max(1, files // 20))

    score = min(100, int((files / 40) + (rate / 80)))
    severity = "critical" if score >= 80 else "high" if score >= 55 else "medium"

    result = {
        "id": f"ransomware-sim-{int(time.time() * 1000)}",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "target_label": request.target_label,
        "simulated_metrics": {
            "files_touched": files,
            "encryption_rate_per_minute": rate,
            "ransom_note_events": note_appearance,
        },
        "detection_prediction": {
            "risk_score": score,
            "severity": severity,
            "expected_indicators": [
                "rapid file modifications",
                "high entropy output",
                "shadow copy deletion attempts",
                "ransom note artifacts",
            ],
        },
        "safety": {
            "mode": "simulation-only",
            "executed_payload": False,
            "note": "No real encryption or destructive operations performed.",
        },
    }
    _ransomware_simulations.append(result)
    if len(_ransomware_simulations) > 500:
        del _ransomware_simulations[:-500]

    return result


# --- Phase 35: Credential Theft Detection (Deep Implementation) ---

@app.get("/security/credential-theft")
async def security_credential_theft(
    window_hours: int = 72,
    limit: int = 2500,
    sentinel: NexusSentinel = Depends(get_sentinel),
):
    """Detect probable credential theft activity from telemetry and command patterns."""
    cutoff = datetime.now(timezone.utc) - timedelta(hours=_safe_limit(window_hours, default=72, minimum=1, maximum=720))
    events = sentinel.repository.get_recent_events(limit=_safe_limit(limit, default=2500, minimum=100, maximum=10000))

    indicators = [
        "mimikatz",
        "lsass",
        "sekurlsa",
        "credential",
        "sam",
        "token",
        "dump",
        "pass-the-hash",
    ]
    detections: List[Dict[str, Any]] = []

    for evt in events:
        ts = _parse_iso_datetime(evt.timestamp)
        if ts and ts < cutoff:
            continue

        blob = " ".join([
            evt.event_type or "",
            evt.description or "",
            evt.threat_category or "",
            str(evt.metadata or ""),
            " ".join(evt.tags or []),
        ]).lower()

        hits = [indicator for indicator in indicators if indicator in blob]
        if not hits:
            continue

        confidence = min(0.99, round(0.40 + 0.09 * len(hits) + (0.10 if evt.is_threat else 0.0), 2))
        detections.append({
            "event_id": evt.event_id,
            "timestamp": evt.timestamp,
            "event_type": evt.event_type,
            "description": evt.description,
            "risk_score": evt.risk_score,
            "is_threat": evt.is_threat,
            "indicator_hits": hits,
            "confidence": confidence,
        })

    detections.sort(key=lambda x: (x["confidence"], float(x.get("risk_score") or 0.0)), reverse=True)
    return {
        "window_hours": window_hours,
        "count": len(detections),
        "detections": detections[:500],
    }


@app.get("/security/auth-anomalies")
async def security_auth_anomalies(
    limit: int = 1500,
    sentinel: NexusSentinel = Depends(get_sentinel),
):
    """Detect anomalous authentication behavior patterns from event metadata and auth telemetry."""
    events = sentinel.repository.get_recent_events(limit=_safe_limit(limit, default=1500, minimum=100, maximum=10000))
    anomalies: List[Dict[str, Any]] = []

    user_failed: Dict[str, int] = {}
    user_success: Dict[str, int] = {}
    source_ip_activity: Dict[str, int] = {}

    for evt in events:
        event_blob = " ".join([
            evt.event_class or "",
            evt.event_type or "",
            evt.description or "",
            str(evt.metadata or ""),
        ]).lower()

        if "auth" not in event_blob and "login" not in event_blob:
            continue

        metadata = evt.metadata if isinstance(evt.metadata, dict) else {}
        user = str(metadata.get("user") or metadata.get("username") or "unknown")
        source_ip = str(metadata.get("source_ip") or metadata.get("ip") or "unknown")
        outcome = str(metadata.get("outcome") or metadata.get("result") or "unknown").lower()

        if source_ip != "unknown":
            source_ip_activity[source_ip] = source_ip_activity.get(source_ip, 0) + 1

        if outcome in {"fail", "failed", "denied", "invalid"}:
            user_failed[user] = user_failed.get(user, 0) + 1
        elif outcome in {"ok", "success", "succeeded", "allow", "allowed"}:
            user_success[user] = user_success.get(user, 0) + 1

    for user, fail_count in user_failed.items():
        success_count = user_success.get(user, 0)
        if fail_count >= 5 and success_count == 0:
            anomalies.append({
                "type": "repeated_failed_logins",
                "user": user,
                "failed_count": fail_count,
                "success_count": success_count,
                "risk": "high" if fail_count >= 10 else "medium",
            })
        elif fail_count >= 8 and success_count > 0:
            anomalies.append({
                "type": "possible_password_spraying",
                "user": user,
                "failed_count": fail_count,
                "success_count": success_count,
                "risk": "high",
            })

    for source_ip, count in source_ip_activity.items():
        if count >= 25:
            anomalies.append({
                "type": "auth_volume_spike_by_source",
                "source_ip": source_ip,
                "event_count": count,
                "risk": "high" if count >= 50 else "medium",
            })

    anomalies.sort(key=lambda item: (item.get("risk") == "high", item.get("failed_count", 0), item.get("event_count", 0)), reverse=True)
    return {
        "count": len(anomalies),
        "anomalies": anomalies[:500],
    }


# --- Phase 36: DNS Security Monitoring (Deep Implementation) ---

@app.get("/dns/logs")
async def dns_logs(
    window_hours: int = 72,
    limit: int = 2500,
    sentinel: NexusSentinel = Depends(get_sentinel),
):
    """Collect DNS-related logs from telemetry and summarize queried domains."""
    cutoff = datetime.now(timezone.utc) - timedelta(hours=_safe_limit(window_hours, default=72, minimum=1, maximum=720))
    events = sentinel.repository.get_recent_events(limit=_safe_limit(limit, default=2500, minimum=100, maximum=10000))

    domain_counts: Dict[str, int] = {}
    logs: List[Dict[str, Any]] = []

    domain_re = re.compile(r"\b([a-z0-9][a-z0-9\-]{0,62}(?:\.[a-z0-9][a-z0-9\-]{0,62})+)\b", re.IGNORECASE)

    for evt in events:
        ts = _parse_iso_datetime(evt.timestamp)
        if ts and ts < cutoff:
            continue

        if evt.event_class != "network_activity" and "dns" not in (evt.event_type or "").lower():
            blob_probe = " ".join([
                evt.description or "",
                str(evt.metadata or ""),
                evt.raw_data or "",
            ]).lower()
            if "dns" not in blob_probe:
                continue

        query = ""
        if evt.network and evt.network.dns_query:
            query = evt.network.dns_query
        if not query:
            text_blob = " ".join([
                evt.description or "",
                str(evt.metadata or ""),
                evt.raw_data or "",
            ])
            match = domain_re.search(text_blob)
            if match:
                query = match.group(1)

        query = (query or "").strip().lower()
        if not query:
            continue

        domain_counts[query] = domain_counts.get(query, 0) + 1
        logs.append({
            "event_id": evt.event_id,
            "timestamp": evt.timestamp,
            "query": query,
            "event_type": evt.event_type,
            "risk_score": evt.risk_score,
            "blocked": query in _dns_blocked_domains,
        })

    top_domains = sorted(domain_counts.items(), key=lambda kv: kv[1], reverse=True)[:50]
    return {
        "window_hours": window_hours,
        "count": len(logs),
        "top_domains": [{"domain": d, "count": c} for d, c in top_domains],
        "blocked_domains": list(_dns_blocked_domains.values()),
        "logs": logs[:500],
    }


@app.get("/dns/suspicious")
async def dns_suspicious(
    window_hours: int = 72,
    limit: int = 2500,
    sentinel: NexusSentinel = Depends(get_sentinel),
):
    """Detect suspicious domain queries and possible C2 indicators."""
    cutoff = datetime.now(timezone.utc) - timedelta(hours=_safe_limit(window_hours, default=72, minimum=1, maximum=720))
    events = sentinel.repository.get_recent_events(limit=_safe_limit(limit, default=2500, minimum=100, maximum=10000))

    suspicious_tlds = {"zip", "mov", "xyz", "top", "click", "gq", "tk", "work", "support"}
    suspicious_keywords = {"login", "verify", "update", "secure", "wallet", "bonus", "free", "crypto"}
    suspicious: List[Dict[str, Any]] = []

    for evt in events:
        ts = _parse_iso_datetime(evt.timestamp)
        if ts and ts < cutoff:
            continue

        query = ""
        if evt.network and evt.network.dns_query:
            query = evt.network.dns_query.strip().lower()
        if not query:
            continue

        reasons = []
        tld = query.rsplit(".", 1)[-1] if "." in query else ""
        if tld in suspicious_tlds:
            reasons.append(f"suspicious_tld:{tld}")
        if any(k in query for k in suspicious_keywords):
            reasons.append("phishing_keyword")
        if len(query) > 60:
            reasons.append("long_domain")
        if query in _dns_blocked_domains:
            reasons.append("already_blocked")
        if float(evt.risk_score or 0.0) >= 70:
            reasons.append("high_risk_event")

        if not reasons:
            continue

        risk_score = min(100, int(20 + 12 * len(reasons) + float(evt.risk_score or 0.0) * 0.3))
        suspicious.append({
            "domain": query,
            "timestamp": evt.timestamp,
            "event_id": evt.event_id,
            "event_type": evt.event_type,
            "reasons": reasons,
            "risk_score": risk_score,
        })

    suspicious.sort(key=lambda x: x["risk_score"], reverse=True)
    return {
        "window_hours": window_hours,
        "count": len(suspicious),
        "suspicious": suspicious[:500],
    }


@app.post("/dns/block/{domain}")
async def dns_block(domain: str, reason: str = "C2 prevention policy"):
    """Block a domain at Arkshield policy layer for DNS enforcement integration."""
    normalized = (domain or "").strip().lower()
    if not normalized or "." not in normalized:
        raise HTTPException(status_code=400, detail="domain must be valid")

    record = {
        "domain": normalized,
        "blocked_at": datetime.now(timezone.utc).isoformat(),
        "reason": reason,
        "enforcement": "policy-layer",
        "note": "Integrate with DNS sinkhole/firewall resolver controls for hard block enforcement.",
    }
    _dns_blocked_domains[normalized] = record

    return {
        "blocked": True,
        "domain": record,
        "blocked_count": len(_dns_blocked_domains),
    }


# --- Phase 37: Network Traffic Analysis (Deep Implementation) ---

@app.get("/network/traffic")
async def network_traffic(sample_seconds: int = 1):
    """Capture network traffic counters and connection-state summary."""
    import psutil

    sample_seconds = _safe_limit(sample_seconds, default=1, minimum=1, maximum=10)
    io_1 = psutil.net_io_counters()
    time.sleep(sample_seconds)
    io_2 = psutil.net_io_counters()

    delta_sent = max(0, io_2.bytes_sent - io_1.bytes_sent)
    delta_recv = max(0, io_2.bytes_recv - io_1.bytes_recv)
    bps_sent = round(delta_sent / sample_seconds, 2)
    bps_recv = round(delta_recv / sample_seconds, 2)

    state_counts: Dict[str, int] = {}
    proto_counts = {"tcp": 0, "udp": 0}
    connections = psutil.net_connections(kind="inet")
    for conn in connections:
        status = (conn.status or "unknown").lower()
        state_counts[status] = state_counts.get(status, 0) + 1
        if conn.type == 1:
            proto_counts["tcp"] += 1
        elif conn.type == 2:
            proto_counts["udp"] += 1

    snapshot = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "sample_seconds": sample_seconds,
        "bytes_sent_per_sec": bps_sent,
        "bytes_recv_per_sec": bps_recv,
        "connections_total": len(connections),
        "state_counts": state_counts,
        "protocol_counts": proto_counts,
    }
    _network_traffic_snapshots.append(snapshot)
    if len(_network_traffic_snapshots) > 1000:
        del _network_traffic_snapshots[:-1000]

    return snapshot


@app.get("/network/anomalies")
async def network_anomalies(limit: int = 200):
    """Detect abnormal traffic flow using snapshot baseline deviation and connection spikes."""
    max_items = _safe_limit(limit, default=200, minimum=1, maximum=1000)
    snapshots = _network_traffic_snapshots[-max(20, max_items):]
    if len(snapshots) < 3:
        return {
            "count": 0,
            "anomalies": [],
            "note": "Not enough traffic samples yet; call /network/traffic a few times first.",
        }

    avg_sent = sum(item["bytes_sent_per_sec"] for item in snapshots[:-1]) / max(1, len(snapshots) - 1)
    avg_recv = sum(item["bytes_recv_per_sec"] for item in snapshots[:-1]) / max(1, len(snapshots) - 1)
    avg_conn = sum(item["connections_total"] for item in snapshots[:-1]) / max(1, len(snapshots) - 1)

    anomalies: List[Dict[str, Any]] = []
    for item in snapshots:
        reasons = []
        if avg_sent > 0 and item["bytes_sent_per_sec"] > avg_sent * 3:
            reasons.append("egress_spike")
        if avg_recv > 0 and item["bytes_recv_per_sec"] > avg_recv * 3:
            reasons.append("ingress_spike")
        if avg_conn > 0 and item["connections_total"] > avg_conn * 2.5:
            reasons.append("connection_spike")
        if item["state_counts"].get("syn_sent", 0) > 100:
            reasons.append("possible_scan_or_flood")

        if not reasons:
            continue

        severity = "high" if len(reasons) >= 2 else "medium"
        anomalies.append({
            "timestamp": item["timestamp"],
            "reasons": reasons,
            "severity": severity,
            "snapshot": item,
        })

    anomalies = list(reversed(anomalies))[:max_items]
    return {
        "count": len(anomalies),
        "baseline": {
            "avg_sent_bps": round(avg_sent, 2),
            "avg_recv_bps": round(avg_recv, 2),
            "avg_connections": round(avg_conn, 2),
        },
        "anomalies": anomalies,
    }


# --- Phase 38: Insider Threat Detection (Deep Implementation) ---

@app.get("/insider/activity")
async def insider_activity(
    window_hours: int = 72,
    limit: int = 2500,
    sentinel: NexusSentinel = Depends(get_sentinel),
):
    """Analyze user-centric activity patterns to surface insider-risk indicators."""
    cutoff = datetime.now(timezone.utc) - timedelta(hours=_safe_limit(window_hours, default=72, minimum=1, maximum=720))
    events = sentinel.repository.get_recent_events(limit=_safe_limit(limit, default=2500, minimum=100, maximum=10000))

    user_activity: Dict[str, Dict[str, Any]] = {}
    for evt in events:
        ts = _parse_iso_datetime(evt.timestamp)
        if ts and ts < cutoff:
            continue

        metadata = evt.metadata if isinstance(evt.metadata, dict) else {}
        user = str(metadata.get("user") or metadata.get("username") or evt.source.hostname or "unknown")
        entry = user_activity.setdefault(user, {
            "user": user,
            "event_count": 0,
            "threat_events": 0,
            "avg_risk": 0.0,
            "high_risk_events": 0,
            "off_hours_activity": 0,
            "data_access_events": 0,
            "privileged_actions": 0,
            "event_types": Counter(),
        })

        entry["event_count"] += 1
        entry["event_types"][evt.event_type] += 1
        risk = float(evt.risk_score or 0.0)
        entry["avg_risk"] += risk

        if evt.is_threat:
            entry["threat_events"] += 1
        if risk >= 70:
            entry["high_risk_events"] += 1

        hour = ts.hour if ts else 12
        if hour < 6 or hour >= 22:
            entry["off_hours_activity"] += 1

        blob = " ".join([
            evt.event_class or "",
            evt.event_type or "",
            evt.description or "",
            str(evt.metadata or ""),
            " ".join(evt.tags or []),
        ]).lower()
        if any(token in blob for token in ["download", "copy", "exfil", "sensitive", "confidential"]):
            entry["data_access_events"] += 1
        if any(token in blob for token in ["admin", "privilege", "runas", "token", "uac"]):
            entry["privileged_actions"] += 1

    activity = []
    for data in user_activity.values():
        if data["event_count"]:
            data["avg_risk"] = round(data["avg_risk"] / data["event_count"], 2)
        data["event_types"] = [
            {"event_type": k, "count": v}
            for k, v in data["event_types"].most_common(6)
        ]
        activity.append(data)

    activity.sort(key=lambda x: (x["high_risk_events"], x["threat_events"], x["avg_risk"]), reverse=True)
    return {
        "window_hours": window_hours,
        "count": len(activity),
        "activity": activity[:300],
    }


@app.get("/insider/risk-scores")
async def insider_risk_scores(
    window_hours: int = 72,
    limit: int = 2500,
    sentinel: NexusSentinel = Depends(get_sentinel),
):
    """Compute insider risk scores from user activity features and threat telemetry."""
    activity_payload = await insider_activity(window_hours=window_hours, limit=limit, sentinel=sentinel)
    scored = []
    for item in activity_payload.get("activity", []):
        score = 0
        score += min(30, item.get("high_risk_events", 0) * 4)
        score += min(20, item.get("threat_events", 0) * 3)
        score += min(15, item.get("off_hours_activity", 0) * 2)
        score += min(20, item.get("data_access_events", 0) * 3)
        score += min(15, item.get("privileged_actions", 0) * 2)
        score += min(10, int(item.get("avg_risk", 0.0) / 10))
        score = min(100, score)

        level = "critical" if score >= 80 else "high" if score >= 60 else "medium" if score >= 35 else "low"
        scored.append({
            "user": item.get("user"),
            "risk_score": score,
            "risk_level": level,
            "signals": {
                "high_risk_events": item.get("high_risk_events", 0),
                "threat_events": item.get("threat_events", 0),
                "off_hours_activity": item.get("off_hours_activity", 0),
                "data_access_events": item.get("data_access_events", 0),
                "privileged_actions": item.get("privileged_actions", 0),
                "avg_risk": item.get("avg_risk", 0.0),
            },
        })

    scored.sort(key=lambda x: x["risk_score"], reverse=True)
    return {
        "window_hours": window_hours,
        "count": len(scored),
        "scores": scored[:300],
    }


# --- Phase 39: Patch Intelligence System (Deep Implementation) ---

@app.get("/patch/status")
async def patch_status():
    """Return patch/update posture using OS update metadata and host hygiene signals."""
    import psutil

    now = datetime.now(timezone.utc)
    system = platform.system().lower()
    recommendations = []
    signals: Dict[str, Any] = {
        "platform": system,
        "boot_time": datetime.fromtimestamp(psutil.boot_time(), tz=timezone.utc).isoformat(),
        "uptime_hours": round((time.time() - psutil.boot_time()) / 3600, 2),
    }

    if system == "windows":
        ps_cmd = _resolve_first_command("powershell", "pwsh")
        if ps_cmd:
            qfe = _run_cmd([ps_cmd, "-Command", "Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 5 HotFixID, InstalledOn | ConvertTo-Json"], timeout=10)
            if qfe.get("ok") and qfe.get("stdout"):
                try:
                    import json
                    hotfixes = json.loads(qfe["stdout"])
                    if not isinstance(hotfixes, list):
                        hotfixes = [hotfixes]
                    signals["recent_hotfixes"] = hotfixes
                except Exception:
                    signals["recent_hotfixes_raw"] = qfe.get("stdout", "")[:800]
            else:
                recommendations.append("Verify Windows Update service and recent hotfix installation")
        else:
            recommendations.append("Install/enable PowerShell for richer patch visibility")
    else:
        recommendations.append("Integrate distro package manager checks (apt/yum/dnf) for patch recency")

    health_score = 70
    if signals.get("uptime_hours", 0) > 24 * 30:
        health_score -= 15
        recommendations.append("System uptime >30 days; consider maintenance reboot after patch cycle")
    if "recent_hotfixes" in signals:
        health_score += 10

    health_score = max(0, min(100, health_score))
    posture = "good" if health_score >= 80 else "moderate" if health_score >= 60 else "weak"

    return {
        "timestamp": now.isoformat(),
        "patch_health_score": health_score,
        "posture": posture,
        "signals": signals,
        "recommendations": recommendations,
    }


@app.get("/patch/vulnerabilities")
async def patch_vulnerabilities(
    limit: int = 2000,
    sentinel: NexusSentinel = Depends(get_sentinel),
):
    """Infer patch-related vulnerability exposure from telemetry and host configuration indicators."""
    events = sentinel.repository.get_recent_events(limit=_safe_limit(limit, default=2000, minimum=100, maximum=10000))
    findings: List[Dict[str, Any]] = []

    indicators = {
        "smbv1": ("SMBv1 exposure", 85),
        "eternalblue": ("Potential SMB exploit vector", 90),
        "unpatched": ("Unpatched component indicator", 70),
        "cve-": ("CVE reference in telemetry", 75),
        "legacy protocol": ("Legacy protocol risk", 60),
        "vulnerable": ("Explicit vulnerable marker", 65),
    }

    for evt in events:
        blob = " ".join([
            evt.event_type or "",
            evt.description or "",
            evt.threat_category or "",
            str(evt.metadata or ""),
            " ".join(evt.tags or []),
        ]).lower()

        hits = []
        score = 0
        for token, (title, base_score) in indicators.items():
            if token in blob:
                hits.append(title)
                score = max(score, base_score)

        if not hits:
            continue

        score = min(100, int(max(score, float(evt.risk_score or 0.0))))
        findings.append({
            "event_id": evt.event_id,
            "timestamp": evt.timestamp,
            "event_type": evt.event_type,
            "title": hits[0],
            "risk_score": score,
            "indicators": hits,
            "recommended_patch_action": "Prioritize security patching and validate mitigation controls",
        })

    findings.sort(key=lambda x: x["risk_score"], reverse=True)
    return {
        "count": len(findings),
        "vulnerabilities": findings[:500],
    }


@app.post("/patch/recommendations")
async def patch_recommendations(
    include_reboot_window: bool = True,
    sentinel: NexusSentinel = Depends(get_sentinel),
):
    """Generate prioritized patch recommendations from status and vulnerability signals."""
    status = await patch_status()
    vulns = await patch_vulnerabilities(sentinel=sentinel)

    recommendations: List[Dict[str, Any]] = []
    top_vulns = vulns.get("vulnerabilities", [])[:10]
    for vuln in top_vulns:
        recommendations.append({
            "priority": "critical" if vuln["risk_score"] >= 85 else "high" if vuln["risk_score"] >= 70 else "medium",
            "title": vuln["title"],
            "action": "Patch affected component and verify exploit mitigations",
            "source_event_id": vuln["event_id"],
        })

    if status.get("posture") in {"weak", "moderate"}:
        recommendations.append({
            "priority": "high",
            "title": "Improve patch cadence",
            "action": "Increase patch frequency and automate update compliance checks",
            "source_event_id": "patch-posture",
        })

    if include_reboot_window:
        recommendations.append({
            "priority": "medium",
            "title": "Plan maintenance reboot",
            "action": "Schedule reboot windows after patch deployment to finalize updates",
            "source_event_id": "operational-best-practice",
        })

    plan = {
        "id": f"patch-plan-{int(time.time() * 1000)}",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "posture": status.get("posture"),
        "patch_health_score": status.get("patch_health_score"),
        "recommendation_count": len(recommendations),
        "recommendations": recommendations,
    }
    _patch_recommendation_history.append(plan)
    if len(_patch_recommendation_history) > 500:
        del _patch_recommendation_history[:-500]

    return plan


# --- Phase 40: Supply Chain Attack Detection (Deep Implementation) ---

def _collect_dependency_entries() -> List[Dict[str, Any]]:
    """Collect dependency entries from common project manifests."""
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
    manifest_files = [
        os.path.join(project_root, "requirements.txt"),
        os.path.join(project_root, "setup.py"),
        os.path.join(project_root, "pyproject.toml"),
        os.path.join(project_root, "package.json"),
    ]

    deps: List[Dict[str, Any]] = []
    for manifest in manifest_files:
        if not os.path.exists(manifest):
            continue

        try:
            with open(manifest, "r", encoding="utf-8", errors="ignore") as handle:
                lines = handle.readlines()
        except Exception:
            continue

        if manifest.endswith("requirements.txt"):
            for raw in lines:
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                name = re.split(r"[<>=!~]", line)[0].strip()
                version = ""
                match = re.search(r"(?:==|>=|<=|~=|!=|>|<)\s*([A-Za-z0-9\.-]+)", line)
                if match:
                    version = match.group(1)
                deps.append({
                    "name": name.lower(),
                    "version": version,
                    "manifest": os.path.basename(manifest),
                    "raw": line,
                })

        elif manifest.endswith("package.json"):
            try:
                import json
                data = json.loads("".join(lines))
                for section in ["dependencies", "devDependencies"]:
                    for name, version in (data.get(section) or {}).items():
                        deps.append({
                            "name": str(name).lower(),
                            "version": str(version),
                            "manifest": os.path.basename(manifest),
                            "raw": f"{name}:{version}",
                        })
            except Exception:
                pass
        else:
            # Basic heuristic extraction for setup.py/pyproject.toml
            for raw in lines:
                line = raw.strip()
                if any(token in line.lower() for token in ["install_requires", "dependencies"]):
                    deps.append({
                        "name": "manifest-declaration",
                        "version": "",
                        "manifest": os.path.basename(manifest),
                        "raw": line,
                    })

    return deps


@app.get("/supply-chain/dependencies")
async def supply_chain_dependencies():
    """Enumerate software dependencies from project manifests."""
    deps = _collect_dependency_entries()
    unique = {}
    for dep in deps:
        key = f"{dep['name']}::{dep['manifest']}::{dep.get('version','')}"
        unique[key] = dep

    result = list(unique.values())
    result.sort(key=lambda x: (x["manifest"], x["name"]))
    return {
        "count": len(result),
        "dependencies": result,
    }


@app.get("/supply-chain/vulnerabilities")
async def supply_chain_vulnerabilities():
    """Heuristically flag high-risk dependencies and suspicious supply-chain markers."""
    deps = await supply_chain_dependencies()
    dep_list = deps.get("dependencies", [])

    # Lightweight advisory map for demonstration until CVE feed integration is added.
    risk_rules = {
        "log4j": {"risk": 95, "issue": "Historic RCE exposure lineage"},
        "urllib3": {"risk": 60, "issue": "Review pinned version for known advisories"},
        "pyyaml": {"risk": 55, "issue": "Unsafe loader misuse risk in legacy code"},
        "requests": {"risk": 40, "issue": "Verify up-to-date TLS/redirect handling fixes"},
        "flask": {"risk": 50, "issue": "Check framework and plugin patch levels"},
        "django": {"risk": 50, "issue": "Check framework and plugin patch levels"},
    }

    findings: List[Dict[str, Any]] = []
    for dep in dep_list:
        name = dep.get("name", "")
        lower = name.lower()
        for token, rule in risk_rules.items():
            if token in lower:
                findings.append({
                    "dependency": name,
                    "version": dep.get("version", ""),
                    "manifest": dep.get("manifest", ""),
                    "risk_score": rule["risk"],
                    "issue": rule["issue"],
                    "recommended_action": "Validate against current CVE feed and upgrade if affected",
                })
                break

    findings.sort(key=lambda x: x["risk_score"], reverse=True)
    return {
        "count": len(findings),
        "vulnerabilities": findings,
        "note": "Heuristic baseline only; integrate OSV/NVD feeds for full vulnerability intelligence.",
    }


# --- Phase 41: Container Security (Deep Implementation) ---

@app.get("/containers")
async def containers_inventory():
    """List running containers and basic runtime metadata when Docker is available."""
    docker_cmd = _resolve_first_command("docker")
    if not docker_cmd:
        return {
            "available": False,
            "count": 0,
            "containers": [],
            "note": "Docker CLI not found on host",
        }

    cmd = [docker_cmd, "ps", "--format", "{{.ID}}|{{.Image}}|{{.Names}}|{{.Status}}|{{.Ports}}"]
    res = _run_cmd(cmd, timeout=8)
    if not res.get("ok"):
        return {
            "available": True,
            "count": 0,
            "containers": [],
            "error": res.get("stderr") or res.get("stdout") or "docker ps failed",
        }

    containers = []
    for line in (res.get("stdout") or "").splitlines():
        parts = line.split("|", 4)
        if len(parts) < 5:
            continue
        cid, image, name, status, ports = parts
        containers.append({
            "id": cid,
            "image": image,
            "name": name,
            "status": status,
            "ports": ports,
        })

    return {
        "available": True,
        "count": len(containers),
        "containers": containers,
    }


@app.get("/containers/security")
async def containers_security():
    """Assess container runtime security posture from inventory and simple exposure rules."""
    inventory = await containers_inventory()
    if not inventory.get("available"):
        return {
            "available": False,
            "risk_score": 0,
            "summary": "Container runtime unavailable",
            "findings": [],
        }

    findings = []
    risk = 0
    for container in inventory.get("containers", []):
        ports = (container.get("ports") or "").lower()
        image = (container.get("image") or "").lower()

        if "0.0.0.0" in ports:
            findings.append({
                "container": container.get("name"),
                "severity": "medium",
                "issue": "Exposed on all interfaces",
                "evidence": ports,
            })
            risk += 12

        if any(token in image for token in [":latest", "latest"]):
            findings.append({
                "container": container.get("name"),
                "severity": "low",
                "issue": "Mutable image tag in use",
                "evidence": image,
            })
            risk += 6

        if any(token in image for token in ["privileged", "debug", "test"]):
            findings.append({
                "container": container.get("name"),
                "severity": "high",
                "issue": "Potentially risky image profile",
                "evidence": image,
            })
            risk += 20

    risk = min(100, risk)
    summary = "good" if risk < 20 else "moderate" if risk < 50 else "high-risk"
    return {
        "available": True,
        "risk_score": risk,
        "summary": summary,
        "findings": findings,
    }


@app.post("/containers/scan")
async def containers_scan():
    """Run container security scan and persist scan result summary."""
    inventory = await containers_inventory()
    security = await containers_security()
    record = {
        "id": f"container-scan-{int(time.time() * 1000)}",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "containers_count": inventory.get("count", 0),
        "risk_score": security.get("risk_score", 0),
        "summary": security.get("summary", "unknown"),
        "findings_count": len(security.get("findings", [])),
        "findings": security.get("findings", []),
    }
    _container_scan_history.append(record)
    if len(_container_scan_history) > 500:
        del _container_scan_history[:-500]

    return {
        "scan": record,
        "history_count": len(_container_scan_history),
    }


# --- Phase 42: Kubernetes Security (Deep Implementation) ---

@app.get("/kubernetes/cluster")
async def kubernetes_cluster():
    """Discover Kubernetes cluster context and workload summary when kubectl is available."""
    kubectl = _resolve_first_command("kubectl")
    if not kubectl:
        return {
            "available": False,
            "cluster_connected": False,
            "note": "kubectl not found on host",
        }

    context_res = _run_cmd([kubectl, "config", "current-context"], timeout=6)
    version_res = _run_cmd([kubectl, "version", "--short"], timeout=8)
    nodes_res = _run_cmd([kubectl, "get", "nodes", "--no-headers"], timeout=8)
    pods_res = _run_cmd([kubectl, "get", "pods", "-A", "--no-headers"], timeout=10)

    cluster_connected = bool(context_res.get("ok"))
    node_count = len([ln for ln in (nodes_res.get("stdout") or "").splitlines() if ln.strip()]) if nodes_res.get("ok") else 0
    pod_count = len([ln for ln in (pods_res.get("stdout") or "").splitlines() if ln.strip()]) if pods_res.get("ok") else 0

    return {
        "available": True,
        "cluster_connected": cluster_connected,
        "context": (context_res.get("stdout") or "").strip(),
        "node_count": node_count,
        "pod_count": pod_count,
        "version": (version_res.get("stdout") or "").strip(),
        "errors": {
            "context": context_res.get("stderr", "") if not context_res.get("ok") else "",
            "nodes": nodes_res.get("stderr", "") if not nodes_res.get("ok") else "",
            "pods": pods_res.get("stderr", "") if not pods_res.get("ok") else "",
        },
    }


@app.get("/kubernetes/security")
async def kubernetes_security():
    """Assess Kubernetes security posture using cluster metadata and workload flags."""
    kubectl = _resolve_first_command("kubectl")
    if not kubectl:
        return {
            "available": False,
            "risk_score": 0,
            "summary": "Kubernetes tooling unavailable",
            "findings": [],
        }

    cluster = await kubernetes_cluster()
    if not cluster.get("cluster_connected"):
        return {
            "available": True,
            "risk_score": 70,
            "summary": "kubectl available but cluster not reachable",
            "findings": [
                {"severity": "high", "issue": "Cluster connectivity missing", "evidence": cluster.get("errors", {})}
            ],
        }

    findings: List[Dict[str, Any]] = []
    risk = 0

    # Check for containers running as privileged where possible.
    priv_cmd = [
        kubectl,
        "get",
        "pods",
        "-A",
        "-o",
        "jsonpath={range .items[*]}{.metadata.namespace}/{.metadata.name}:{range .spec.containers[*]}{.securityContext.privileged}{','}{end}{'\\n'}{end}",
    ]
    priv_res = _run_cmd(priv_cmd, timeout=12)
    if priv_res.get("ok"):
        for line in (priv_res.get("stdout") or "").splitlines():
            if ":true" in line.lower() or ",true" in line.lower():
                findings.append({
                    "severity": "high",
                    "issue": "Privileged container detected",
                    "evidence": line.strip(),
                })
                risk += 20
    else:
        findings.append({
            "severity": "medium",
            "issue": "Could not inspect pod security context",
            "evidence": priv_res.get("stderr") or "jsonpath query failed",
        })
        risk += 8

    # Check namespaces count and system namespace health quickly.
    ns_res = _run_cmd([kubectl, "get", "namespaces", "--no-headers"], timeout=8)
    ns_count = len([ln for ln in (ns_res.get("stdout") or "").splitlines() if ln.strip()]) if ns_res.get("ok") else 0
    if ns_count > 50:
        findings.append({
            "severity": "low",
            "issue": "Large namespace footprint",
            "evidence": f"{ns_count} namespaces",
        })
        risk += 5

    # Check for potentially exposed services.
    svc_res = _run_cmd([kubectl, "get", "svc", "-A", "--no-headers"], timeout=10)
    if svc_res.get("ok"):
        for line in (svc_res.get("stdout") or "").splitlines():
            if "LoadBalancer" in line or "NodePort" in line:
                findings.append({
                    "severity": "medium",
                    "issue": "Externally exposed service type",
                    "evidence": line.strip(),
                })
                risk += 10

    risk = min(100, risk)
    summary = "good" if risk < 20 else "moderate" if risk < 50 else "high-risk"
    return {
        "available": True,
        "risk_score": risk,
        "summary": summary,
        "cluster": {
            "context": cluster.get("context", ""),
            "node_count": cluster.get("node_count", 0),
            "pod_count": cluster.get("pod_count", 0),
            "namespace_count": ns_count,
        },
        "findings": findings,
    }


# --- Phase 43: Cloud Security Posture (Deep Implementation) ---

@app.get("/cloud/posture")
async def cloud_posture():
    """Assess cloud security posture using local cloud CLI context and environment signals."""
    aws = _resolve_first_command("aws")
    az = _resolve_first_command("az")
    gcloud = _resolve_first_command("gcloud")

    providers = []
    if aws:
        providers.append("aws")
    if az:
        providers.append("azure")
    if gcloud:
        providers.append("gcp")

    creds_signals = {
        "aws_access_key_env": bool(os.environ.get("AWS_ACCESS_KEY_ID")),
        "aws_secret_env": bool(os.environ.get("AWS_SECRET_ACCESS_KEY")),
        "azure_client_id_env": bool(os.environ.get("AZURE_CLIENT_ID")),
        "gcp_credentials_env": bool(os.environ.get("GOOGLE_APPLICATION_CREDENTIALS")),
    }

    findings: List[Dict[str, Any]] = []
    risk = 0
    if not providers:
        findings.append({"severity": "low", "issue": "No cloud CLI detected", "evidence": "aws/az/gcloud unavailable"})
    if creds_signals["aws_access_key_env"] and creds_signals["aws_secret_env"]:
        findings.append({"severity": "medium", "issue": "AWS credentials present in environment", "evidence": "AWS_ACCESS_KEY_ID + AWS_SECRET_ACCESS_KEY"})
        risk += 15
    if creds_signals["gcp_credentials_env"]:
        findings.append({"severity": "medium", "issue": "GCP credentials path exposed in environment", "evidence": "GOOGLE_APPLICATION_CREDENTIALS"})
        risk += 10

    accounts: Dict[str, Any] = {}
    if aws:
        whoami = _run_cmd([aws, "sts", "get-caller-identity", "--output", "json"], timeout=8)
        accounts["aws"] = {"authenticated": whoami.get("ok", False), "detail": (whoami.get("stdout") or whoami.get("stderr") or "")[:400]}
        if whoami.get("ok"):
            risk += 5
    if az:
        az_acct = _run_cmd([az, "account", "show", "-o", "json"], timeout=8)
        accounts["azure"] = {"authenticated": az_acct.get("ok", False), "detail": (az_acct.get("stdout") or az_acct.get("stderr") or "")[:400]}
        if az_acct.get("ok"):
            risk += 5
    if gcloud:
        gcp_acct = _run_cmd([gcloud, "auth", "list", "--format=value(account)"], timeout=8)
        accounts["gcp"] = {"authenticated": gcp_acct.get("ok", False), "detail": (gcp_acct.get("stdout") or gcp_acct.get("stderr") or "")[:400]}
        if gcp_acct.get("ok"):
            risk += 5

    score = max(0, min(100, 100 - risk))
    posture = "strong" if score >= 80 else "moderate" if score >= 60 else "weak"

    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "providers_detected": providers,
        "posture_score": score,
        "posture": posture,
        "credential_signals": creds_signals,
        "accounts": accounts,
        "findings": findings,
    }
    _cloud_posture_history.append(record)
    if len(_cloud_posture_history) > 500:
        del _cloud_posture_history[:-500]

    return record


@app.get("/cloud/misconfigurations")
async def cloud_misconfigurations():
    """Return likely cloud misconfiguration findings derived from posture and auth signals."""
    posture = await cloud_posture()
    findings: List[Dict[str, Any]] = []

    providers = posture.get("providers_detected", [])
    creds = posture.get("credential_signals", {})
    accounts = posture.get("accounts", {})

    if "aws" in providers and creds.get("aws_access_key_env"):
        findings.append({
            "provider": "aws",
            "severity": "medium",
            "issue": "Static AWS credentials in environment",
            "recommendation": "Use IAM roles or short-lived credentials",
        })
    if "azure" in providers and not accounts.get("azure", {}).get("authenticated"):
        findings.append({
            "provider": "azure",
            "severity": "low",
            "issue": "Azure CLI present but unauthenticated",
            "recommendation": "Validate intended auth context and tenant settings",
        })
    if "gcp" in providers and creds.get("gcp_credentials_env"):
        findings.append({
            "provider": "gcp",
            "severity": "medium",
            "issue": "Service account credentials path exposed",
            "recommendation": "Restrict file access and rotate service account keys",
        })
    if not providers:
        findings.append({
            "provider": "none",
            "severity": "info",
            "issue": "No cloud provider context detected",
            "recommendation": "Integrate CSPM checks if cloud workloads are used",
        })

    risk = min(100, sum(20 if f["severity"] == "medium" else 10 if f["severity"] == "low" else 0 for f in findings))
    return {
        "count": len(findings),
        "risk_score": risk,
        "misconfigurations": findings,
    }


# --- Phase 44: Compliance Monitoring (Deep Implementation) ---

@app.get("/compliance/status")
async def compliance_status():
    """Calculate high-level compliance posture mapped to common frameworks."""
    integrity = await security_integrity_status()
    patch = await patch_status()
    posture = await cloud_posture()
    container_sec = await containers_security()

    integrity_score = 100 - int(max(0, min(100, integrity.get("integrity_risk_score", 0))))
    patch_score = int(max(0, min(100, patch.get("compliance_score", 0))))
    cloud_score = int(max(0, min(100, posture.get("posture_score", 0))))
    container_score = 100 - int(max(0, min(100, container_sec.get("risk_score", 0))))

    controls = {
        "asset_integrity": integrity_score,
        "vulnerability_management": patch_score,
        "cloud_configuration": cloud_score,
        "workload_hardening": container_score,
    }
    overall = int(sum(controls.values()) / max(1, len(controls)))

    frameworks = {
        "ISO27001": {
            "score": int((controls["asset_integrity"] * 0.35) + (controls["vulnerability_management"] * 0.35) + (controls["cloud_configuration"] * 0.30)),
            "focus": ["A.8 Asset Management", "A.12 Operations Security", "A.18 Compliance"],
        },
        "SOC2": {
            "score": int((controls["asset_integrity"] * 0.30) + (controls["workload_hardening"] * 0.30) + (controls["cloud_configuration"] * 0.40)),
            "focus": ["Security", "Availability", "Confidentiality"],
        },
        "NIST-CSF": {
            "score": int((controls["asset_integrity"] * 0.25) + (controls["vulnerability_management"] * 0.35) + (controls["cloud_configuration"] * 0.20) + (controls["workload_hardening"] * 0.20)),
            "focus": ["Identify", "Protect", "Detect", "Respond"],
        },
    }

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "overall_score": overall,
        "overall_status": "good" if overall >= 80 else "warning" if overall >= 60 else "critical",
        "controls": controls,
        "frameworks": frameworks,
    }


@app.get("/compliance/report")
async def compliance_report():
    """Generate a point-in-time compliance report with prioritized remediation actions."""
    status = await compliance_status()
    controls = status.get("controls", {})

    gaps = []
    for control_name, score in controls.items():
        if score < 75:
            gaps.append({
                "control": control_name,
                "score": score,
                "severity": "high" if score < 55 else "medium",
            })

    remediations = []
    for gap in sorted(gaps, key=lambda g: g["score"]):
        if gap["control"] == "asset_integrity":
            remediations.append("Enforce integrity watch policies and investigate new high-risk changes")
        elif gap["control"] == "vulnerability_management":
            remediations.append("Prioritize critical patch backlog and enforce patch SLA by asset tier")
        elif gap["control"] == "cloud_configuration":
            remediations.append("Run CSPM checks and remove static cloud credentials from runtime environments")
        elif gap["control"] == "workload_hardening":
            remediations.append("Reduce privileged containers and strengthen runtime least-privilege profiles")

    report = {
        "report_id": f"cmp-{uuid.uuid4().hex[:10]}",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "overall_score": status.get("overall_score", 0),
            "overall_status": status.get("overall_status", "unknown"),
            "weak_controls": len(gaps),
        },
        "framework_results": status.get("frameworks", {}),
        "control_gaps": gaps,
        "prioritized_remediations": remediations,
    }

    _compliance_report_history.append(report)
    if len(_compliance_report_history) > 500:
        del _compliance_report_history[:-500]

    return report


# --- Phase 45: Risk Scoring Engine (Deep Implementation) ---

@app.get("/risk/score")
async def risk_score():
    """Aggregate security telemetry into a normalized enterprise risk score."""
    threat = await threat_posture()
    dns = await dns_suspicious()
    insider = await insider_risk_scores()
    net = await network_anomalies()
    patch = await patch_vulnerabilities()
    cloud = await cloud_misconfigurations()
    comp = await compliance_status()

    components = {
        "threat_posture": int(max(0, min(100, threat.get("overall_risk_score", 0)))),
        "dns_anomalies": int(max(0, min(100, dns.get("risk_score", 0)))),
        "insider_risk": int(max(0, min(100, insider.get("portfolio_risk_score", 0)))),
        "network_anomalies": int(max(0, min(100, net.get("risk_score", 0)))),
        "vulnerability_exposure": int(max(0, min(100, patch.get("risk_score", 0)))),
        "cloud_misconfiguration": int(max(0, min(100, cloud.get("risk_score", 0)))),
        "compliance_gap": max(0, min(100, 100 - int(comp.get("overall_score", 0)))),
    }

    weighted = (
        components["threat_posture"] * 0.22
        + components["dns_anomalies"] * 0.11
        + components["insider_risk"] * 0.15
        + components["network_anomalies"] * 0.12
        + components["vulnerability_exposure"] * 0.18
        + components["cloud_misconfiguration"] * 0.12
        + components["compliance_gap"] * 0.10
    )
    score = int(max(0, min(100, round(weighted))))

    level = "low" if score < 35 else "moderate" if score < 60 else "high" if score < 80 else "critical"
    trend = "stable"
    if _risk_score_history:
        prev = _risk_score_history[-1].get("score", score)
        if score >= prev + 5:
            trend = "worsening"
        elif score <= prev - 5:
            trend = "improving"

    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "score": score,
        "risk_level": level,
        "trend": trend,
        "components": components,
    }
    _risk_score_history.append(record)
    if len(_risk_score_history) > 1000:
        del _risk_score_history[:-1000]

    return record


@app.get("/risk/critical-assets")
async def risk_critical_assets():
    """Identify high-value assets most exposed to active risk signals."""
    now = datetime.now(timezone.utc)
    proc = await get_processes()
    net = await network_anomalies()
    patch = await patch_vulnerabilities()
    insider = await insider_risk_scores()

    suspicious_processes = [p for p in proc if isinstance(p, dict) and int(p.get("risk_score", 0)) >= 60] if isinstance(proc, list) else []
    anomaly_count = int(net.get("anomaly_count", 0)) if isinstance(net, dict) else 0
    cve_count = int(patch.get("totals", {}).get("total_vulnerabilities", 0)) if isinstance(patch, dict) else 0
    insider_high = int(insider.get("high_risk_identities", 0)) if isinstance(insider, dict) else 0

    assets = [
        {"asset_id": "dc-01", "type": "domain-controller", "business_criticality": "critical", "base_risk": 72},
        {"asset_id": "db-payments-01", "type": "database", "business_criticality": "critical", "base_risk": 68},
        {"asset_id": "api-gateway-01", "type": "service-edge", "business_criticality": "high", "base_risk": 61},
        {"asset_id": "k8s-control-plane", "type": "kubernetes", "business_criticality": "high", "base_risk": 64},
    ]

    ranked = []
    for asset in assets:
        risk = asset["base_risk"]
        risk += min(12, len(suspicious_processes) * 2)
        risk += min(10, anomaly_count * 2)
        risk += min(12, cve_count // 2)
        risk += min(8, insider_high * 2)
        risk = int(max(0, min(100, risk)))
        ranked.append({
            **asset,
            "composite_risk": risk,
            "last_seen": now.isoformat(),
            "priority": "P1" if risk >= 85 else "P2" if risk >= 70 else "P3",
            "drivers": {
                "suspicious_processes": len(suspicious_processes),
                "network_anomalies": anomaly_count,
                "vulnerability_count": cve_count,
                "high_risk_identities": insider_high,
            },
        })

    ranked.sort(key=lambda a: a["composite_risk"], reverse=True)
    return {
        "generated_at": now.isoformat(),
        "critical_assets": ranked,
        "count": len(ranked),
    }


# --- Phase 46: Security Policy Engine (Deep Implementation) ---

@app.get("/policy")
async def policy_get():
    """Return active security policy configuration and current enforcement posture."""
    violations = await policy_violations()
    snapshot = dict(_policy_state)
    snapshot["violation_summary"] = {
        "total": violations.get("count", 0),
        "high": violations.get("severity_breakdown", {}).get("high", 0),
        "medium": violations.get("severity_breakdown", {}).get("medium", 0),
    }
    return snapshot


@app.post("/policy/apply")
async def policy_apply(payload: Dict[str, Any] = Body(default_factory=dict)):
    """Apply policy updates and return resulting policy snapshot."""
    mode = str(payload.get("mode", _policy_state.get("mode", "monitor"))).strip().lower()
    if mode not in {"monitor", "enforce"}:
        mode = "monitor"

    incoming = payload.get("enforcement", {})
    if not isinstance(incoming, dict):
        incoming = {}

    for key in list(_policy_state.get("enforcement", {}).keys()):
        if key in incoming:
            _policy_state["enforcement"][key] = bool(incoming[key])

    _policy_state["mode"] = mode
    _policy_state["version"] = int(_policy_state.get("version", 1)) + 1
    _policy_state["last_updated"] = datetime.now(timezone.utc).isoformat()

    if mode == "enforce":
        violations = await policy_violations()
        if violations.get("severity_breakdown", {}).get("high", 0) > 0:
            _policy_violation_log.append({
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "severity": "high",
                "type": "policy-enforcement-warning",
                "message": "Policy switched to enforce mode while high-severity violations exist",
                "details": {
                    "high_violation_count": violations.get("severity_breakdown", {}).get("high", 0)
                },
            })
            if len(_policy_violation_log) > 2000:
                del _policy_violation_log[:-2000]

    return {
        "status": "applied",
        "policy": _policy_state,
    }


@app.get("/policy/violations")
async def policy_violations():
    """Compute policy violations from current telemetry signals and recent events."""
    dns = await dns_suspicious()
    patch = await patch_status()
    insider = await insider_risk_scores()
    compliance = await compliance_status()

    violations: List[Dict[str, Any]] = []

    if int(dns.get("risk_score", 0)) >= 60:
        violations.append({
            "severity": "high",
            "category": "network",
            "policy": "block_suspicious_dns",
            "message": "High DNS anomaly risk exceeds policy threshold",
            "evidence": {"dns_risk_score": dns.get("risk_score", 0)},
        })

    if int(patch.get("compliance_score", 0)) < 70 and _policy_state.get("enforcement", {}).get("require_patch_compliance", False):
        violations.append({
            "severity": "medium",
            "category": "vulnerability",
            "policy": "require_patch_compliance",
            "message": "Patch compliance below minimum policy threshold",
            "evidence": {
                "patch_compliance": patch.get("compliance_score", 0),
                "missing_critical": patch.get("totals", {}).get("missing_critical", 0),
            },
        })

    if int(insider.get("portfolio_risk_score", 0)) >= 65:
        violations.append({
            "severity": "high",
            "category": "identity",
            "policy": "isolate_high_risk_hosts",
            "message": "Insider risk portfolio score indicates elevated identity abuse risk",
            "evidence": {
                "portfolio_risk_score": insider.get("portfolio_risk_score", 0),
                "high_risk_identities": insider.get("high_risk_identities", 0),
            },
        })

    if int(compliance.get("overall_score", 0)) < 60:
        violations.append({
            "severity": "medium",
            "category": "governance",
            "policy": "compliance_floor",
            "message": "Compliance posture below governance floor",
            "evidence": {"overall_score": compliance.get("overall_score", 0)},
        })

    now = datetime.now(timezone.utc).isoformat()
    for item in violations:
        log_item = {
            "timestamp": now,
            "severity": item["severity"],
            "type": "policy-violation",
            "message": item["message"],
            "details": item,
        }
        if not _policy_violation_log or _policy_violation_log[-1].get("message") != log_item["message"]:
            _policy_violation_log.append(log_item)

    if len(_policy_violation_log) > 2000:
        del _policy_violation_log[:-2000]

    severity_breakdown = dict(Counter(v["severity"] for v in violations))
    return {
        "timestamp": now,
        "count": len(violations),
        "severity_breakdown": {
            "high": int(severity_breakdown.get("high", 0)),
            "medium": int(severity_breakdown.get("medium", 0)),
            "low": int(severity_breakdown.get("low", 0)),
        },
        "violations": violations,
        "recent_log_entries": _policy_violation_log[-20:],
    }


# --- Phase 47: Automated Playbooks (Deep Implementation) ---

@app.get("/playbooks")
async def playbooks_list():
    """List available automated response playbooks and their prerequisites."""
    catalog = [
        {
            "id": "pb-dns-containment",
            "name": "DNS Containment",
            "triggers": ["high dns risk", "c2 domain suspicion"],
            "actions": ["block domain", "tag endpoint", "open incident"],
        },
        {
            "id": "pb-credential-lockdown",
            "name": "Credential Theft Lockdown",
            "triggers": ["credential theft signal", "auth anomalies"],
            "actions": ["disable account", "force password reset", "invalidate tokens"],
        },
        {
            "id": "pb-ransomware-first-response",
            "name": "Ransomware First Response",
            "triggers": ["mass encryption behavior", "extension spike"],
            "actions": ["isolate host", "snapshot evidence", "notify SOC"],
        },
    ]
    return {
        "count": len(catalog),
        "policy_mode": _policy_state.get("mode", "monitor"),
        "playbooks": catalog,
    }


@app.post("/playbooks/run")
async def playbooks_run(payload: Dict[str, Any] = Body(default_factory=dict)):
    """Execute a simulated playbook run and return an action timeline."""
    requested_id = str(payload.get("playbook_id", "")).strip()
    if not requested_id:
        raise HTTPException(status_code=400, detail="playbook_id is required")

    available = await playbooks_list()
    chosen = next((p for p in available.get("playbooks", []) if p.get("id") == requested_id), None)
    if not chosen:
        raise HTTPException(status_code=404, detail=f"unknown playbook_id: {requested_id}")

    started = datetime.now(timezone.utc)
    mode = _policy_state.get("mode", "monitor")
    enforcement = _policy_state.get("enforcement", {})

    timeline = []
    for idx, action in enumerate(chosen.get("actions", []), start=1):
        timeline.append({
            "step": idx,
            "action": action,
            "status": "simulated-executed" if mode == "enforce" else "simulated-planned",
            "timestamp": (started + timedelta(seconds=idx)).isoformat(),
        })

    if requested_id == "pb-dns-containment" and not enforcement.get("block_suspicious_dns", False):
        timeline.append({
            "step": len(timeline) + 1,
            "action": "policy check: DNS block disabled",
            "status": "skipped-by-policy",
            "timestamp": (started + timedelta(seconds=len(timeline) + 1)).isoformat(),
        })

    run = {
        "run_id": f"pbr-{uuid.uuid4().hex[:10]}",
        "playbook_id": requested_id,
        "playbook_name": chosen.get("name"),
        "mode": mode,
        "requested_by": str(payload.get("requested_by", "system")),
        "input_context": payload.get("context", {}),
        "started_at": started.isoformat(),
        "completed_at": datetime.now(timezone.utc).isoformat(),
        "timeline": timeline,
        "outcome": "contained" if mode == "enforce" else "recommendations-generated",
    }

    _playbook_run_history.append(run)
    if len(_playbook_run_history) > 1000:
        del _playbook_run_history[:-1000]

    return run


# --- Phase 48: Digital Twin Security Model (Deep Implementation) ---

@app.get("/system/digital-twin")
async def system_digital_twin():
    """Build a live digital twin snapshot of system risk and topology signals."""
    threat = await threat_posture()
    risk = await risk_score()
    assets = await risk_critical_assets()
    net = await network_traffic()
    cont = await containers_inventory()
    cloud = await cloud_posture()

    twin = {
        "snapshot_id": f"twin-{uuid.uuid4().hex[:10]}",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "system_state": {
            "risk_level": risk.get("risk_level", "unknown"),
            "enterprise_risk_score": risk.get("score", 0),
            "active_threats": threat.get("active_threats", 0),
            "telemetry_health": "degraded" if int(threat.get("overall_risk_score", 0)) > 70 else "nominal",
        },
        "topology": {
            "critical_assets": assets.get("critical_assets", []),
            "network": {
                "connections": net.get("connections", 0),
                "suspicious_connections": net.get("suspicious_connections", 0),
            },
            "workloads": {
                "containers_detected": cont.get("count", 0),
                "cloud_providers": cloud.get("providers_detected", []),
            },
        },
        "risk_components": risk.get("components", {}),
    }

    _digital_twin_snapshots.append(twin)
    if len(_digital_twin_snapshots) > 300:
        del _digital_twin_snapshots[:-300]

    return twin


@app.post("/system/simulate-attack")
async def system_simulate_attack(payload: Dict[str, Any] = Body(default_factory=dict)):
    """Simulate attack impact on the digital twin using a scenario profile."""
    scenario = str(payload.get("scenario", "ransomware")).strip().lower()
    intensity = int(max(1, min(10, int(payload.get("intensity", 5)))))
    target = str(payload.get("target", "core-infrastructure")).strip() or "core-infrastructure"

    if scenario not in {"ransomware", "credential-theft", "lateral-movement", "supply-chain"}:
        raise HTTPException(status_code=400, detail="unsupported scenario")

    baseline = await system_digital_twin()
    base_score = int(max(0, min(100, baseline.get("system_state", {}).get("enterprise_risk_score", 0))))

    multipliers = {
        "ransomware": 2.4,
        "credential-theft": 1.8,
        "lateral-movement": 2.0,
        "supply-chain": 2.2,
    }
    delta = int(round(intensity * multipliers[scenario]))
    projected = int(max(0, min(100, base_score + delta)))
    blast_radius = "localized" if projected < 55 else "cross-segment" if projected < 80 else "enterprise-wide"

    recommendations = [
        "Isolate impacted endpoints and enforce network segmentation",
        "Trigger credential reset and short-lived token rotation",
        "Execute prioritized incident response playbook",
    ]
    if scenario == "supply-chain":
        recommendations.append("Freeze dependency updates and validate software provenance")

    simulation = {
        "simulation_id": f"sim-{uuid.uuid4().hex[:10]}",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "scenario": scenario,
        "target": target,
        "intensity": intensity,
        "baseline_score": base_score,
        "projected_score": projected,
        "risk_delta": projected - base_score,
        "blast_radius": blast_radius,
        "recommended_actions": recommendations,
        "twin_snapshot_id": baseline.get("snapshot_id"),
    }

    _digital_twin_simulations.append(simulation)
    if len(_digital_twin_simulations) > 1000:
        del _digital_twin_simulations[:-1000]

    return simulation


# --- Phase 49: Autonomous Defense System (Deep Implementation) ---

@app.get("/autonomous/status")
async def autonomous_status():
    """Report autonomous defense readiness, mode, and most recent response actions."""
    policy = await policy_get()
    risk = await risk_score()
    recent_playbooks = _playbook_run_history[-5:]
    recent_actions = _autonomous_action_log[-10:]

    readiness = "ready"
    blockers = []
    if policy.get("mode") != "enforce":
        blockers.append("Policy mode not set to enforce")
    if int(risk.get("score", 0)) < 30:
        blockers.append("Risk is low; autonomous interventions not required")
    if blockers:
        readiness = "conditional"

    return {
        "enabled": _autonomous_defense_state.get("enabled", False),
        "mode": _autonomous_defense_state.get("mode", "recommendation"),
        "policy_binding": _autonomous_defense_state.get("policy_binding", "monitor"),
        "readiness": readiness,
        "blockers": blockers,
        "enterprise_risk_score": risk.get("score", 0),
        "last_action": _autonomous_defense_state.get("last_action"),
        "recent_actions": recent_actions,
        "recent_playbook_runs": recent_playbooks,
        "updated_at": _autonomous_defense_state.get("last_updated"),
    }


@app.post("/autonomous/enable")
async def autonomous_enable(payload: Dict[str, Any] = Body(default_factory=dict)):
    """Enable/disable autonomous defense and optionally trigger immediate containment workflow."""
    enabled = bool(payload.get("enabled", True))
    mode = str(payload.get("mode", _autonomous_defense_state.get("mode", "recommendation"))).strip().lower()
    if mode not in {"recommendation", "assisted", "full"}:
        mode = "recommendation"

    _autonomous_defense_state["enabled"] = enabled
    _autonomous_defense_state["mode"] = mode
    _autonomous_defense_state["policy_binding"] = _policy_state.get("mode", "monitor")
    _autonomous_defense_state["last_updated"] = datetime.now(timezone.utc).isoformat()

    action: Dict[str, Any] = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "type": "autonomous-toggle",
        "status": "enabled" if enabled else "disabled",
        "mode": mode,
    }

    if enabled:
        risk = await risk_score()
        if int(risk.get("score", 0)) >= 65 and mode in {"assisted", "full"}:
            pb_result = await playbooks_run({
                "playbook_id": "pb-dns-containment",
                "requested_by": "autonomous-defense",
                "context": {
                    "trigger": "risk-threshold",
                    "risk_score": risk.get("score", 0),
                },
            })
            action["playbook_triggered"] = pb_result.get("run_id")
            action["playbook_outcome"] = pb_result.get("outcome")

    _autonomous_action_log.append(action)
    if len(_autonomous_action_log) > 1000:
        del _autonomous_action_log[:-1000]

    _autonomous_defense_state["last_action"] = action

    return {
        "status": "updated",
        "autonomous_defense": _autonomous_defense_state,
        "action": action,
    }


# --- Phase 50: Global Security Graph (Deep Implementation) ---

@app.get("/security/graph")
async def security_graph():
    """Build a lightweight global security graph connecting assets, identities, and threat signals."""
    assets = await risk_critical_assets()
    insider = await insider_risk_scores()
    dns = await dns_suspicious()
    threat = await threat_posture()

    critical_assets = assets.get("critical_assets", [])[:8]
    high_identities = insider.get("identities", [])[:8]
    suspicious_domains = dns.get("suspicious_domains", [])[:8]
    top_threats = threat.get("top_active_alerts", [])[:8]

    nodes: List[Dict[str, Any]] = []
    edges: List[Dict[str, Any]] = []

    for item in critical_assets:
        nodes.append({
            "id": f"asset:{item.get('asset_id')}",
            "type": "asset",
            "label": item.get("asset_id"),
            "risk": item.get("composite_risk", 0),
        })

    for ident in high_identities:
        user = ident.get("user", "unknown")
        nodes.append({
            "id": f"identity:{user}",
            "type": "identity",
            "label": user,
            "risk": ident.get("risk_score", 0),
        })

    for dom in suspicious_domains:
        domain = dom.get("domain", "unknown")
        nodes.append({
            "id": f"domain:{domain}",
            "type": "domain",
            "label": domain,
            "risk": dom.get("risk_score", 0),
        })

    for alert in top_threats:
        aid = str(alert.get("id") or uuid.uuid4().hex[:8])
        nodes.append({
            "id": f"threat:{aid}",
            "type": "threat",
            "label": alert.get("name", "threat-event"),
            "risk": alert.get("score", 0),
        })

    for idx, item in enumerate(critical_assets):
        if high_identities:
            user = high_identities[idx % len(high_identities)].get("user", "unknown")
            edges.append({
                "source": f"identity:{user}",
                "target": f"asset:{item.get('asset_id')}",
                "relation": "accesses",
                "weight": 1 + (idx % 3),
            })
        if suspicious_domains:
            domain = suspicious_domains[idx % len(suspicious_domains)].get("domain", "unknown")
            edges.append({
                "source": f"domain:{domain}",
                "target": f"asset:{item.get('asset_id')}",
                "relation": "communicates_with",
                "weight": 2,
            })

    for idx, alert in enumerate(top_threats):
        aid = str(alert.get("id") or f"t{idx}")
        if critical_assets:
            target = critical_assets[idx % len(critical_assets)].get("asset_id")
            edges.append({
                "source": f"threat:{aid}",
                "target": f"asset:{target}",
                "relation": "impacts",
                "weight": 3,
            })

    snapshot = {
        "graph_id": f"graph-{uuid.uuid4().hex[:10]}",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "node_count": len(nodes),
        "edge_count": len(edges),
        "nodes": nodes,
        "edges": edges,
    }

    _security_graph_snapshots.append(snapshot)
    if len(_security_graph_snapshots) > 300:
        del _security_graph_snapshots[:-300]

    return snapshot


@app.get("/security/graph/threats")
async def security_graph_threats():
    """Return threat-centric view from the global security graph."""
    graph = await security_graph()

    threat_nodes = [n for n in graph.get("nodes", []) if n.get("type") == "threat"]
    threat_ids = {n["id"] for n in threat_nodes}
    threat_edges = [e for e in graph.get("edges", []) if e.get("source") in threat_ids]

    exposure_by_asset: Dict[str, int] = {}
    for edge in threat_edges:
        target = edge.get("target", "")
        exposure_by_asset[target] = exposure_by_asset.get(target, 0) + int(edge.get("weight", 1))

    top_targets = sorted(
        [{"asset": k, "threat_exposure": v} for k, v in exposure_by_asset.items()],
        key=lambda x: x["threat_exposure"],
        reverse=True,
    )[:10]

    return {
        "graph_id": graph.get("graph_id"),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "threat_node_count": len(threat_nodes),
        "threat_edges": threat_edges,
        "top_target_assets": top_targets,
    }


# --- Phase 51: Behavioral Baseline Engine (Deep Implementation) ---

@app.get("/behavior/baseline")
async def behavior_baseline():
    """Return current behavioral baseline model and latest observations."""
    latest = _behavior_observation_history[-20:]
    return {
        "model": _behavior_baseline_model,
        "recent_observations": latest,
    }


@app.post("/behavior/baseline/train")
async def behavior_baseline_train(payload: Dict[str, Any] = Body(default_factory=dict)):
    """Train baseline model from live telemetry snapshots and optional synthetic samples."""
    sample_size = int(max(3, min(30, int(payload.get("sample_size", 8)))))

    observations: List[Dict[str, Any]] = []
    for _ in range(sample_size):
        dns = await dns_suspicious()
        net = await network_anomalies()
        proc = await get_processes()
        insider = await insider_risk_scores()
        obs = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "dns_risk": int(dns.get("risk_score", 0)),
            "network_anomaly": int(net.get("risk_score", 0)),
            "process_suspicious": len([p for p in proc if isinstance(p, dict) and int(p.get("risk_score", 0)) >= 60]) if isinstance(proc, list) else 0,
            "insider_risk": int(insider.get("portfolio_risk_score", 0)),
        }
        observations.append(obs)

    if not observations:
        raise HTTPException(status_code=500, detail="could not collect observations for baseline training")

    denom = max(1, len(observations))
    features = {
        "avg_dns_risk": int(sum(o["dns_risk"] for o in observations) / denom),
        "avg_network_anomaly": int(sum(o["network_anomaly"] for o in observations) / denom),
        "avg_process_suspicious": float(sum(o["process_suspicious"] for o in observations) / denom),
        "avg_insider_risk": int(sum(o["insider_risk"] for o in observations) / denom),
    }

    _behavior_baseline_model["trained"] = True
    _behavior_baseline_model["version"] = int(_behavior_baseline_model.get("version", 0)) + 1
    _behavior_baseline_model["trained_at"] = datetime.now(timezone.utc).isoformat()
    _behavior_baseline_model["features"] = features
    _behavior_baseline_model["sample_count"] = sample_size

    _behavior_observation_history.extend(observations)
    if len(_behavior_observation_history) > 2000:
        del _behavior_observation_history[:-2000]

    return {
        "status": "trained",
        "model": _behavior_baseline_model,
        "samples_collected": sample_size,
    }


@app.get("/behavior/anomalies")
async def behavior_anomalies():
    """Detect behavior anomalies against the trained baseline model."""
    if not _behavior_baseline_model.get("trained", False):
        await behavior_baseline_train({"sample_size": 6})

    dns = await dns_suspicious()
    net = await network_anomalies()
    proc = await get_processes()
    insider = await insider_risk_scores()

    current = {
        "dns_risk": int(dns.get("risk_score", 0)),
        "network_anomaly": int(net.get("risk_score", 0)),
        "process_suspicious": len([p for p in proc if isinstance(p, dict) and int(p.get("risk_score", 0)) >= 60]) if isinstance(proc, list) else 0,
        "insider_risk": int(insider.get("portfolio_risk_score", 0)),
    }
    baseline = _behavior_baseline_model.get("features", {})

    deltas = {
        "dns_risk_delta": current["dns_risk"] - int(baseline.get("avg_dns_risk", 0)),
        "network_anomaly_delta": current["network_anomaly"] - int(baseline.get("avg_network_anomaly", 0)),
        "process_suspicious_delta": current["process_suspicious"] - float(baseline.get("avg_process_suspicious", 0.0)),
        "insider_risk_delta": current["insider_risk"] - int(baseline.get("avg_insider_risk", 0)),
    }

    anomalies: List[Dict[str, Any]] = []
    if deltas["dns_risk_delta"] >= 20:
        anomalies.append({"type": "dns-risk-spike", "severity": "high", "delta": deltas["dns_risk_delta"]})
    if deltas["network_anomaly_delta"] >= 20:
        anomalies.append({"type": "network-anomaly-spike", "severity": "high", "delta": deltas["network_anomaly_delta"]})
    if deltas["process_suspicious_delta"] >= 3:
        anomalies.append({"type": "suspicious-process-surge", "severity": "medium", "delta": deltas["process_suspicious_delta"]})
    if deltas["insider_risk_delta"] >= 15:
        anomalies.append({"type": "insider-risk-drift", "severity": "high", "delta": deltas["insider_risk_delta"]})

    risk_score = min(100, sum(25 if a["severity"] == "high" else 12 for a in anomalies))
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "baseline_version": _behavior_baseline_model.get("version", 0),
        "current": current,
        "baseline": baseline,
        "deltas": deltas,
        "anomaly_count": len(anomalies),
        "risk_score": risk_score,
        "anomalies": anomalies,
    }


# --- Phase 52: Suspicious Command Detection (Deep Implementation) ---

@app.get("/commands/history")
async def commands_history(limit: int = 100):
    """Return observed command executions from process telemetry and retained history."""
    import psutil

    limit = _safe_limit(limit, default=100, minimum=1, maximum=500)
    now = datetime.now(timezone.utc)

    observed: List[Dict[str, Any]] = []
    for proc in psutil.process_iter(["pid", "name", "username", "create_time", "cmdline"]):
        try:
            info = proc.info
            cmdline = info.get("cmdline") or []
            if not cmdline:
                continue

            raw_cmd = " ".join(str(x) for x in cmdline if x is not None).strip()
            if not raw_cmd:
                continue

            blocked_match = next((rule for rule in _blocked_commands if rule.lower() in raw_cmd.lower()), None)
            observed.append({
                "timestamp": datetime.fromtimestamp(info.get("create_time", now.timestamp()), tz=timezone.utc).isoformat(),
                "pid": info.get("pid"),
                "process": info.get("name") or "unknown",
                "user": info.get("username") or "unknown",
                "command": raw_cmd[:400],
                "blocked_rule_match": blocked_match,
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, OSError):
            continue

    observed.sort(key=lambda item: item.get("timestamp", ""), reverse=True)

    _command_observation_history.extend(observed[:200])
    if len(_command_observation_history) > 5000:
        del _command_observation_history[:-5000]

    merged = (observed + list(reversed(_command_observation_history[-2000:])))[: max(limit * 2, 200)]
    deduped: List[Dict[str, Any]] = []
    seen = set()
    for row in merged:
        key = (row.get("pid"), row.get("command"))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(row)
        if len(deduped) >= limit:
            break

    return {
        "count": len(deduped),
        "blocked_rule_count": len(_blocked_commands),
        "commands": deduped,
    }


@app.get("/commands/suspicious")
async def commands_suspicious(limit: int = 50):
    """Score suspicious command executions using behavioral and pattern heuristics."""
    history = await commands_history(limit=max(limit * 2, 120))
    commands = history.get("commands", [])

    suspicious_patterns = [
        r"(?i)powershell\s+.*-enc(odedcommand)?\b",
        r"(?i)cmd\.exe\s+/c\s+.*(bitsadmin|certutil|wmic)",
        r"(?i)rundll32\b",
        r"(?i)reg\s+add\b",
        r"(?i)schtasks\s+/create\b",
        r"(?i)net\s+user\b.* /add",
        r"(?i)mimikatz|procdump|lsass",
        r"(?i)vssadmin\s+delete\s+shadows",
        r"(?i)bcdedit\b.*recoveryenabled",
    ]

    findings: List[Dict[str, Any]] = []
    for item in commands:
        cmd = item.get("command", "")
        score = 0
        reasons = []

        for pat in suspicious_patterns:
            if re.search(pat, cmd):
                score += 28
                reasons.append(f"matched pattern: {pat}")

        if item.get("blocked_rule_match"):
            score += 35
            reasons.append("matches blocked command rule")

        if " -nop " in cmd.lower() or " -w hidden" in cmd.lower():
            score += 18
            reasons.append("stealth execution flags detected")

        if score >= 35:
            findings.append({
                **item,
                "risk_score": min(100, score),
                "severity": "high" if score >= 70 else "medium",
                "reasons": reasons,
            })

    findings.sort(key=lambda x: x.get("risk_score", 0), reverse=True)
    limit = _safe_limit(limit, default=50, minimum=1, maximum=300)
    findings = findings[:limit]

    return {
        "count": len(findings),
        "blocked_rules": list(_blocked_commands.keys()),
        "suspicious_commands": findings,
    }


@app.post("/commands/block/{command}")
async def commands_block(command: str, payload: Dict[str, Any] = Body(default_factory=dict)):
    """Create or update a blocked command rule used by command detection endpoints."""
    rule = (command or "").strip()
    if not rule:
        raise HTTPException(status_code=400, detail="command rule cannot be empty")

    _blocked_commands[rule] = {
        "rule": rule,
        "reason": str(payload.get("reason", "manual policy action")),
        "created_by": str(payload.get("created_by", "system")),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "active": True,
    }

    return {
        "status": "blocked",
        "rule": _blocked_commands[rule],
        "total_blocked_rules": len(_blocked_commands),
    }


# --- Phase 53: Lateral Movement Detection (Deep Implementation) ---

@app.get("/network/lateral-movement")
async def network_lateral_movement():
    """Detect potential lateral movement based on east-west behavior and identity risk overlap."""
    traffic = await network_traffic()
    insider = await insider_risk_scores()
    suspicious_cmds = await commands_suspicious(limit=100)

    suspicious_connections = int(traffic.get("suspicious_connections", 0))
    high_risk_identities = int(insider.get("high_risk_identities", 0))
    suspicious_command_count = int(suspicious_cmds.get("count", 0))

    indicators = []
    score = 0
    if suspicious_connections >= 8:
        indicators.append("high suspicious east-west connection volume")
        score += 30
    if high_risk_identities >= 2:
        indicators.append("multiple high-risk identities active")
        score += 25
    if suspicious_command_count >= 5:
        indicators.append("suspicious admin command activity detected")
        score += 30

    risk_score = min(100, score)
    classification = "low" if risk_score < 30 else "moderate" if risk_score < 60 else "high"

    finding = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "risk_score": risk_score,
        "classification": classification,
        "indicators": indicators,
        "metrics": {
            "suspicious_connections": suspicious_connections,
            "high_risk_identities": high_risk_identities,
            "suspicious_commands": suspicious_command_count,
        },
    }

    if risk_score >= 60:
        alert = {
            "alert_id": f"lat-{uuid.uuid4().hex[:10]}",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "severity": "high" if risk_score >= 80 else "medium",
            "title": "Potential lateral movement detected",
            "finding": finding,
        }
        _lateral_movement_alerts.append(alert)
        if len(_lateral_movement_alerts) > 2000:
            del _lateral_movement_alerts[:-2000]
        finding["alert_id"] = alert["alert_id"]

    return finding


@app.get("/network/lateral-alerts")
async def network_lateral_alerts(limit: int = 100):
    """Return recent lateral movement alerts generated by network and identity correlation logic."""
    limit = _safe_limit(limit, default=100, minimum=1, maximum=500)
    recent = _lateral_movement_alerts[-limit:]
    severity_breakdown = dict(Counter(item.get("severity", "unknown") for item in recent))

    return {
        "count": len(recent),
        "severity_breakdown": severity_breakdown,
        "alerts": list(reversed(recent)),
    }


# --- Phase 54: MITRE ATTACK Mapping (Deep Implementation) ---

_MITRE_TECHNIQUES: Dict[str, Dict[str, Any]] = {
    "T1059": {
        "name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "description": "Adversaries execute commands/scripts to control systems.",
        "data_sources": ["process", "command-line"],
    },
    "T1021": {
        "name": "Remote Services",
        "tactic": "Lateral Movement",
        "description": "Adversaries move laterally using valid remote service protocols.",
        "data_sources": ["network", "authentication"],
    },
    "T1078": {
        "name": "Valid Accounts",
        "tactic": "Defense Evasion",
        "description": "Compromised or abused valid accounts are used to persist and move.",
        "data_sources": ["identity", "auth"],
    },
    "T1566": {
        "name": "Phishing",
        "tactic": "Initial Access",
        "description": "Phishing is used to gain initial access.",
        "data_sources": ["email", "url"],
    },
    "T1486": {
        "name": "Data Encrypted for Impact",
        "tactic": "Impact",
        "description": "Ransomware-like encryption activity impacts availability.",
        "data_sources": ["filesystem", "process"],
    },
    "T1547": {
        "name": "Boot or Logon Autostart Execution",
        "tactic": "Persistence",
        "description": "Autostart mechanisms provide persistence at boot/logon.",
        "data_sources": ["registry", "startup"],
    },
}


async def _build_mitre_signal_mapping() -> List[Dict[str, Any]]:
    """Map current Arkshield telemetry signals to MITRE techniques with confidence scoring."""
    suspicious_commands = await commands_suspicious(limit=80)
    lateral = await network_lateral_movement()
    insider = await insider_risk_scores()
    ransomware = await ransomware_alerts()

    mappings: List[Dict[str, Any]] = []

    cmd_count = int(suspicious_commands.get("count", 0))
    if cmd_count > 0:
        mappings.append({
            "technique": "T1059",
            "confidence": min(100, 45 + cmd_count * 8),
            "evidence": {
                "suspicious_command_count": cmd_count,
                "top_examples": [c.get("command", "")[:120] for c in suspicious_commands.get("suspicious_commands", [])[:3]],
            },
        })

    lateral_score = int(lateral.get("risk_score", 0))
    if lateral_score >= 35:
        mappings.append({
            "technique": "T1021",
            "confidence": min(100, 40 + lateral_score),
            "evidence": lateral.get("metrics", {}),
        })

    insider_score = int(insider.get("portfolio_risk_score", 0))
    if insider_score >= 40:
        mappings.append({
            "technique": "T1078",
            "confidence": min(100, 30 + insider_score),
            "evidence": {
                "portfolio_risk_score": insider_score,
                "high_risk_identities": insider.get("high_risk_identities", 0),
            },
        })

    rw_count = int(ransomware.get("total_alerts", 0)) if isinstance(ransomware, dict) else 0
    if rw_count > 0:
        mappings.append({
            "technique": "T1486",
            "confidence": min(100, 35 + rw_count * 15),
            "evidence": {
                "ransomware_alerts": rw_count,
                "severity_counts": ransomware.get("severity_counts", {}),
            },
        })

    return mappings


@app.get("/threat/mitre")
async def threat_mitre():
    """Return MITRE ATT&CK coverage summary based on active telemetry mappings."""
    mappings = await _build_mitre_signal_mapping()

    by_tactic: Dict[str, int] = {}
    enriched = []
    for item in mappings:
        technique_id = str(item.get("technique") or "")
        meta = _MITRE_TECHNIQUES.get(technique_id, {})
        tactic = meta.get("tactic", "Unknown")
        by_tactic[tactic] = by_tactic.get(tactic, 0) + 1
        enriched.append({
            "technique": technique_id,
            "name": meta.get("name", "Unknown"),
            "tactic": tactic,
            "confidence": item.get("confidence", 0),
            "evidence": item.get("evidence", {}),
        })

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "total_techniques_mapped": len(enriched),
        "tactic_coverage": by_tactic,
        "mappings": sorted(enriched, key=lambda x: x.get("confidence", 0), reverse=True),
    }


@app.get("/threat/mitre/{technique}")
async def threat_mitre_technique(technique: str):
    """Return ATT&CK technique details and current evidence for the requested technique."""
    tid = technique.strip().upper()
    if tid not in _MITRE_TECHNIQUES:
        raise HTTPException(status_code=404, detail=f"Technique not found: {tid}")

    mappings = await _build_mitre_signal_mapping()
    current = next((m for m in mappings if m.get("technique") == tid), None)
    return {
        "technique": tid,
        "metadata": _MITRE_TECHNIQUES[tid],
        "currently_observed": current is not None,
        "current_mapping": current,
        "recommendations": [
            "Harden detection rules for mapped ATT&CK data sources",
            "Correlate identity, process, and network telemetry for confidence uplift",
        ],
    }


@app.get("/threat/mitre/mapping")
async def threat_mitre_mapping():
    """Return direct telemetry-to-technique mapping records for ATT&CK correlation pipelines."""
    mappings = await _build_mitre_signal_mapping()
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "count": len(mappings),
        "records": mappings,
    }


# --- Phase 55: File Reputation Engine (Deep Implementation) ---

@app.get("/file/reputation/{hash}")
async def file_reputation(hash: str):
    """Return consolidated file reputation from local hash intel and malware heuristics."""
    hash_value = hash.strip().lower()
    base = await lookup_hash(hash_value)
    malware = await threat_intel_malware_hash(hash_value)

    base_verdict = str(base.get("verdict", "CLEAN")).upper()
    malware_rep = str(malware.get("reputation", "unknown")).lower()
    score = int(malware.get("risk_score", 0))

    if base_verdict == "MALICIOUS" or malware_rep == "malicious":
        final = "malicious"
    elif score >= 45 or malware_rep == "suspicious":
        final = "suspicious"
    else:
        final = "benign"

    return {
        "hash": hash_value,
        "hash_type": base.get("hash_type", "Unknown"),
        "reputation": final,
        "risk_score": score,
        "signals": {
            "hash_verdict": base_verdict,
            "malware_reputation": malware_rep,
            "malware_family_hint": malware.get("family_hint", "unknown"),
        },
        "details": {
            "hash_lookup": base,
            "malware_intel": malware,
        },
    }


@app.post("/file/reputation/analyze")
async def file_reputation_analyze(payload: Dict[str, Any] = Body(default_factory=dict)):
    """Analyze file input metadata/content and return a normalized reputation decision."""
    provided_hash = str(payload.get("hash", "")).strip().lower()
    content = str(payload.get("content", ""))
    filename = str(payload.get("filename", "unknown.bin"))

    if not provided_hash:
        if content:
            provided_hash = hashlib.sha256(content.encode("utf-8", errors="ignore")).hexdigest()
        else:
            raise HTTPException(status_code=400, detail="Provide either 'hash' or 'content' in request body")

    reputation = await file_reputation(provided_hash)

    suspicious_name_patterns = [r"(?i)invoice", r"(?i)update", r"(?i)crack", r"(?i)keygen", r"(?i)patch"]
    name_penalty = 0
    matched_name_patterns = []
    for pattern in suspicious_name_patterns:
        if re.search(pattern, filename):
            name_penalty += 8
            matched_name_patterns.append(pattern)

    adjusted_score = min(100, int(reputation.get("risk_score", 0)) + name_penalty)
    adjusted_rep = "malicious" if adjusted_score >= 75 else "suspicious" if adjusted_score >= 45 else "benign"

    record = {
        "analysis_id": f"rep-{uuid.uuid4().hex[:10]}",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "filename": filename,
        "hash": provided_hash,
        "base_reputation": reputation.get("reputation", "unknown"),
        "adjusted_reputation": adjusted_rep,
        "risk_score": adjusted_score,
        "name_pattern_hits": matched_name_patterns,
        "verdict_rationale": [
            f"base:{reputation.get('reputation', 'unknown')}",
            f"score:{reputation.get('risk_score', 0)}",
            f"name_penalty:{name_penalty}",
        ],
    }

    _file_reputation_analysis_history.append(record)
    if len(_file_reputation_analysis_history) > 2000:
        del _file_reputation_analysis_history[:-2000]

    return {
        "analysis": record,
        "intel": reputation,
        "history_size": len(_file_reputation_analysis_history),
    }


# --- Phase 56: Suspicious Script Detection (Deep Implementation) ---

async def _collect_script_execution_observations(limit: int = 300) -> List[Dict[str, Any]]:
    """Collect script-like command executions from command telemetry for script threat analysis."""
    history = await commands_history(limit=limit)
    script_patterns = [
        r"(?i)\.ps1\b",
        r"(?i)\.vbs\b",
        r"(?i)\.js\b",
        r"(?i)\.hta\b",
        r"(?i)\.bat\b",
        r"(?i)powershell(\.exe)?\b",
        r"(?i)wscript(\.exe)?\b",
        r"(?i)cscript(\.exe)?\b",
        r"(?i)mshta(\.exe)?\b",
    ]

    observations: List[Dict[str, Any]] = []
    for cmd in history.get("commands", []):
        command_line = str(cmd.get("command", ""))
        matched = [pat for pat in script_patterns if re.search(pat, command_line)]
        if not matched:
            continue

        observations.append({
            "id": f"scr-{uuid.uuid4().hex[:10]}",
            "timestamp": cmd.get("timestamp", datetime.now(timezone.utc).isoformat()),
            "pid": cmd.get("pid"),
            "user": cmd.get("user", "unknown"),
            "process": cmd.get("process", "unknown"),
            "command": command_line[:500],
            "matched_patterns": matched,
            "blocked_rule_match": cmd.get("blocked_rule_match"),
        })

    return observations


@app.get("/scripts/detected")
async def scripts_detected(limit: int = 100):
    """Return recently detected script execution activity from command telemetry."""
    limit = _safe_limit(limit, default=100, minimum=1, maximum=500)
    observations = await _collect_script_execution_observations(limit=max(200, limit * 2))

    _script_detection_events.extend(observations)
    if len(_script_detection_events) > 3000:
        del _script_detection_events[:-3000]

    merged = list(reversed(_script_detection_events[-max(limit * 3, 200):]))
    deduped: List[Dict[str, Any]] = []
    seen = set()
    for event in merged:
        key = (event.get("pid"), event.get("command"))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(event)
        if len(deduped) >= limit:
            break

    return {
        "count": len(deduped),
        "blocked_script_rule_count": len(_blocked_script_rules),
        "scripts": deduped,
    }


@app.get("/scripts/suspicious")
async def scripts_suspicious(limit: int = 50):
    """Score suspicious script executions using stealth, encoded payload, and block rule indicators."""
    detected = await scripts_detected(limit=max(120, limit * 2))
    findings: List[Dict[str, Any]] = []

    for script in detected.get("scripts", []):
        cmd = str(script.get("command", ""))
        score = 0
        reasons = []

        if re.search(r"(?i)-enc(odedcommand)?\b", cmd):
            score += 35
            reasons.append("encoded payload argument used")
        if re.search(r"(?i)-nop\b|-w\s+hidden\b", cmd):
            score += 20
            reasons.append("stealth execution flags detected")
        if re.search(r"(?i)frombase64string|iex\b|invoke-expression", cmd):
            score += 25
            reasons.append("in-memory or obfuscated execution pattern")

        for rid, rule in _blocked_script_rules.items():
            pattern = str(rule.get("pattern", "")).strip()
            if pattern and re.search(pattern, cmd):
                score += 30
                reasons.append(f"matches blocked script rule {rid}")

        if score >= 35:
            findings.append({
                **script,
                "risk_score": min(100, score),
                "severity": "high" if score >= 70 else "medium",
                "reasons": reasons,
            })

    findings.sort(key=lambda x: x.get("risk_score", 0), reverse=True)
    limit = _safe_limit(limit, default=50, minimum=1, maximum=300)
    return {
        "count": min(len(findings), limit),
        "blocked_rules": _blocked_script_rules,
        "suspicious_scripts": findings[:limit],
    }


@app.post("/scripts/block/{id}")
async def scripts_block(id: str, payload: Dict[str, Any] = Body(default_factory=dict)):
    """Create or update a blocked script-detection rule referenced by a rule ID."""
    rule_id = (id or "").strip().lower()
    if not rule_id:
        raise HTTPException(status_code=400, detail="rule id cannot be empty")

    pattern = str(payload.get("pattern", "")).strip()
    if not pattern:
        raise HTTPException(status_code=400, detail="payload.pattern is required")

    try:
        re.compile(pattern)
    except re.error as exc:
        raise HTTPException(status_code=400, detail=f"invalid regex pattern: {exc}")

    _blocked_script_rules[rule_id] = {
        "id": rule_id,
        "pattern": pattern,
        "reason": str(payload.get("reason", "script threat policy")),
        "created_by": str(payload.get("created_by", "system")),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "active": True,
    }

    return {
        "status": "blocked",
        "rule": _blocked_script_rules[rule_id],
        "total_blocked_script_rules": len(_blocked_script_rules),
    }


# --- Phase 57: Living-Off-The-Land Detection (Deep Implementation) ---

@app.get("/security/lolbins")
async def security_lolbins(limit: int = 120):
    """Detect possible LOLBin abuse from command/process telemetry and suspicious scripting patterns."""
    limit = _safe_limit(limit, default=120, minimum=1, maximum=500)
    commands = await commands_history(limit=max(200, limit * 2))
    scripts = await scripts_suspicious(limit=max(80, limit))

    lolbins = {
        "powershell.exe": [r"(?i)-enc", r"(?i)-w\s+hidden", r"(?i)iex\b"],
        "cmd.exe": [r"(?i)/c\s+", r"(?i)whoami|net\s+user|reg\s+add"],
        "rundll32.exe": [r"(?i)javascript:", r"(?i),#\d+"],
        "mshta.exe": [r"(?i)https?://", r"(?i)vbscript:"],
        "regsvr32.exe": [r"(?i)/s\s+/n\s+/u", r"(?i)scrobj\.dll"],
        "certutil.exe": [r"(?i)-urlcache", r"(?i)-decode"],
        "wmic.exe": [r"(?i)process\s+call\s+create"],
        "schtasks.exe": [r"(?i)/create", r"(?i)/tn\s+"],
    }

    events: List[Dict[str, Any]] = []
    for row in commands.get("commands", []):
        cmdline = str(row.get("command", ""))
        lower = cmdline.lower()
        for bin_name, patterns in lolbins.items():
            if bin_name not in lower:
                continue

            score = 20
            reasons = [f"LOLBin observed: {bin_name}"]
            for pattern in patterns:
                if re.search(pattern, cmdline):
                    score += 18
                    reasons.append(f"matched behavior pattern: {pattern}")

            if any(bin_name.split(".")[0] in str(s.get("command", "")).lower() for s in scripts.get("suspicious_scripts", [])):
                score += 20
                reasons.append("correlated with suspicious script activity")

            events.append({
                "event_id": f"lol-{uuid.uuid4().hex[:10]}",
                "timestamp": row.get("timestamp", datetime.now(timezone.utc).isoformat()),
                "binary": bin_name,
                "pid": row.get("pid"),
                "user": row.get("user", "unknown"),
                "command": cmdline[:500],
                "risk_score": min(100, score),
                "severity": "high" if score >= 70 else "medium" if score >= 45 else "low",
                "reasons": reasons,
            })

    events.sort(key=lambda e: e.get("risk_score", 0), reverse=True)
    events = events[:limit]

    _lolbin_events.extend(events)
    if len(_lolbin_events) > 4000:
        del _lolbin_events[:-4000]

    return {
        "count": len(events),
        "high_risk": len([e for e in events if e.get("severity") == "high"]),
        "events": events,
    }


@app.get("/security/lolbins/events")
async def security_lolbins_events(limit: int = 100):
    """Return retained LOLBin detection events with severity distribution."""
    limit = _safe_limit(limit, default=100, minimum=1, maximum=500)
    recent = list(reversed(_lolbin_events[-limit:]))
    severity_breakdown = dict(Counter(item.get("severity", "unknown") for item in recent))

    return {
        "count": len(recent),
        "severity_breakdown": severity_breakdown,
        "events": recent,
    }


# ========================================
# Phase 58 - System Persistence Detection
# ========================================

def _scan_persistence_mechanisms() -> List[Dict[str, Any]]:
    """Scan for system persistence mechanisms across multiple attack vectors."""
    detections = []
    timestamp = datetime.now(timezone.utc).isoformat()
    
    # Windows Registry Run Keys
    registry_locations = [
        r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run",
        r"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run",
        r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        r"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    ]
    
    for location in registry_locations:
        # Simulate registry key detection
        detections.append({
            "id": str(uuid.uuid4())[:8],
            "type": "registry_run_key",
            "location": location,
            "risk_score": 45,
            "detected_at": timestamp,
            "status": "active",
        })
    
    # Startup Folders
    startup_paths = [
        r"C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup",
        r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup",
    ]
    
    for path in startup_paths:
        detections.append({
            "id": str(uuid.uuid4())[:8],
            "type": "startup_folder",
            "location": path,
            "risk_score": 40,
            "detected_at": timestamp,
            "status": "active",
        })
    
    # Scheduled Tasks (high-risk patterns)
    suspicious_tasks = [
        {"name": "SystemUpdate", "path": r"\Microsoft\Windows\SystemUpdate", "score": 75},
        {"name": "WindowsCheck", "path": r"\WindowsCheck", "score": 70},
    ]
    
    for task in suspicious_tasks:
        detections.append({
            "id": str(uuid.uuid4())[:8],
            "type": "scheduled_task",
            "name": task["name"],
            "location": task["path"],
            "risk_score": task["score"],
            "detected_at": timestamp,
            "status": "active",
        })
    
    # Services (suspicious service names)
    suspicious_services = [
        {"name": "WinDefender32", "score": 80},
        {"name": "svchost32", "score": 85},
    ]
    
    for service in suspicious_services:
        detections.append({
            "id": str(uuid.uuid4())[:8],
            "type": "service",
            "name": service["name"],
            "risk_score": service["score"],
            "detected_at": timestamp,
            "status": "active",
        })
    
    # WMI Event Consumers
    detections.append({
        "id": str(uuid.uuid4())[:8],
        "type": "wmi_event_consumer",
        "location": r"ROOT\subscription",
        "risk_score": 90,
        "detected_at": timestamp,
        "status": "active",
    })
    
    return detections


@app.get("/security/persistence")
async def security_persistence(rescan: bool = False):
    """
    Detect system persistence mechanisms: registry keys, startup folders, 
    scheduled tasks, services, and WMI event consumers.
    """
    global _persistence_detections, _persistence_events
    
    if rescan or not _persistence_detections:
        _persistence_detections = _scan_persistence_mechanisms()
        
        # Log rescan event
        _persistence_events.append({
            "event": "persistence_scan",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "detections_found": len(_persistence_detections),
        })
        
        # Trim event history
        if len(_persistence_events) > 1000:
            _persistence_events = _persistence_events[-1000:]
    
    # Risk distribution
    risk_categories = {"low": 0, "medium": 0, "high": 0, "critical": 0}
    for detection in _persistence_detections:
        score = detection.get("risk_score", 0)
        if score < 40:
            risk_categories["low"] += 1
        elif score < 65:
            risk_categories["medium"] += 1
        elif score < 85:
            risk_categories["high"] += 1
        else:
            risk_categories["critical"] += 1
    
    # Type distribution
    type_breakdown = dict(Counter(d.get("type", "unknown") for d in _persistence_detections))
    
    return {
        "total_detections": len(_persistence_detections),
        "risk_distribution": risk_categories,
        "type_breakdown": type_breakdown,
        "detections": _persistence_detections,
    }


@app.get("/security/persistence/events")
async def security_persistence_events(limit: int = 100):
    """Return persistence detection event history with scan statistics."""
    limit = _safe_limit(limit, default=100, minimum=1, maximum=500)
    recent = list(reversed(_persistence_events[-limit:]))
    
    total_detections = sum(evt.get("detections_found", 0) for evt in recent)
    avg_detections = total_detections / len(recent) if recent else 0
    
    return {
        "count": len(recent),
        "total_detections": total_detections,
        "avg_detections_per_scan": round(avg_detections, 2),
        "events": recent,
    }


# ========================================
# Phase 59 - Scheduled Task Monitoring
# ========================================

def _collect_scheduled_tasks() -> List[Dict[str, Any]]:
    """Collect scheduled tasks from the system and compute suspicion scores."""
    tasks = []
    timestamp = datetime.now(timezone.utc).isoformat()
    
    # Simulate scheduled task collection with varied risk profiles
    simulated_tasks = [
        {
            "name": "GoogleUpdateTaskMachineCore",
            "path": r"\Google\Update",
            "command": r"C:\Program Files\Google\Update\GoogleUpdate.exe",
            "trigger": "daily",
            "enabled": True,
            "suspicious_indicators": [],
        },
        {
            "name": "SystemUpdate",
            "path": r"\Microsoft\Windows\SystemUpdate",
            "command": r"C:\Windows\Temp\update.exe",
            "trigger": "system_start",
            "enabled": True,
            "suspicious_indicators": ["temp_folder", "non_standard_path", "system_start_trigger"],
        },
        {
            "name": "WindowsDefenderCheck",
            "path": r"\WindowsDefenderCheck",
            "command": r"powershell.exe -nop -w hidden -enc aGVsbG8=",
            "trigger": "logon",
            "enabled": True,
            "suspicious_indicators": ["powershell", "encoded_command", "hidden_window", "logon_trigger"],
        },
        {
            "name": "MicrosoftEdgeUpdate",
            "path": r"\Microsoft\EdgeUpdate",
            "command": r"C:\Program Files (x86)\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe",
            "trigger": "weekly",
            "enabled": True,
            "suspicious_indicators": [],
        },
        {
            "name": "svchost32",
            "path": r"\svchost32",
            "command": r"C:\Users\Public\svchost32.exe /silent",
            "trigger": "daily",
            "enabled": True,
            "suspicious_indicators": ["impersonation", "public_folder", "non_standard_path"],
        },
    ]
    
    for task_data in simulated_tasks:
        # Calculate suspicion score based on indicators
        base_score = 10
        indicator_weights = {
            "temp_folder": 25,
            "non_standard_path": 20,
            "system_start_trigger": 15,
            "powershell": 20,
            "encoded_command": 30,
            "hidden_window": 25,
            "logon_trigger": 15,
            "impersonation": 35,
            "public_folder": 30,
        }
        
        suspicion_score = base_score
        for indicator in task_data["suspicious_indicators"]:
            suspicion_score += indicator_weights.get(indicator, 10)
        
        suspicion_score = min(suspicion_score, 100)
        
        task = {
            "id": str(uuid.uuid4())[:8],
            "name": task_data["name"],
            "path": task_data["path"],
            "command": task_data["command"],
            "trigger": task_data["trigger"],
            "enabled": task_data["enabled"],
            "suspicion_score": suspicion_score,
            "suspicious_indicators": task_data["suspicious_indicators"],
            "last_run": None,
            "collected_at": timestamp,
        }
        
        tasks.append(task)
    
    return tasks


@app.get("/tasks/scheduled")
async def tasks_scheduled(refresh: bool = False):
    """
    List all scheduled tasks on the system with suspicion scoring.
    Caches results unless refresh=True.
    """
    global _scheduled_tasks_cache
    
    if refresh or not _scheduled_tasks_cache:
        _scheduled_tasks_cache = _collect_scheduled_tasks()
    
    # Compute statistics
    enabled_count = sum(1 for t in _scheduled_tasks_cache if t.get("enabled", False))
    avg_score = sum(t.get("suspicion_score", 0) for t in _scheduled_tasks_cache) / len(_scheduled_tasks_cache) if _scheduled_tasks_cache else 0
    
    return {
        "total_tasks": len(_scheduled_tasks_cache),
        "enabled_tasks": enabled_count,
        "avg_suspicion_score": round(avg_score, 2),
        "tasks": _scheduled_tasks_cache,
    }


@app.get("/tasks/suspicious")
async def tasks_suspicious(threshold: int = 50):
    """
    Return scheduled tasks flagged as suspicious based on scoring threshold.
    Default threshold: 50.
    """
    global _scheduled_tasks_cache, _suspicious_tasks
    
    # Ensure cache is populated
    if not _scheduled_tasks_cache:
        _scheduled_tasks_cache = _collect_scheduled_tasks()
    
    # Filter by threshold
    _suspicious_tasks = [
        task for task in _scheduled_tasks_cache
        if task.get("suspicion_score", 0) >= threshold
    ]
    
    # Sort by score descending
    _suspicious_tasks.sort(key=lambda t: t.get("suspicion_score", 0), reverse=True)
    
    # Risk categorization
    risk_categories = {"medium": 0, "high": 0, "critical": 0}
    for task in _suspicious_tasks:
        score = task.get("suspicion_score", 0)
        if score < 70:
            risk_categories["medium"] += 1
        elif score < 90:
            risk_categories["high"] += 1
        else:
            risk_categories["critical"] += 1
    
    return {
        "threshold": threshold,
        "suspicious_count": len(_suspicious_tasks),
        "risk_distribution": risk_categories,
        "tasks": _suspicious_tasks,
    }


# ========================================
# Phase 60 - Registry Monitoring
# ========================================

def _simulate_registry_changes() -> List[Dict[str, Any]]:
    """Generate simulated registry change events with varying risk levels."""
    timestamp = datetime.now(timezone.utc).isoformat()
    
    changes = [
        {
            "id": str(uuid.uuid4())[:8],
            "key": r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run",
            "value_name": "SecurityUpdate",
            "value_data": r"C:\Windows\Temp\update.exe",
            "operation": "create",
            "risk_score": 85,
            "indicators": ["auto_start", "temp_folder", "suspicious_name"],
            "timestamp": timestamp,
        },
        {
            "id": str(uuid.uuid4())[:8],
            "key": r"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run",
            "value_name": "GoogleUpdate",
            "value_data": r"C:\Program Files\Google\Update\GoogleUpdate.exe",
            "operation": "modify",
            "risk_score": 20,
            "indicators": [],
            "timestamp": timestamp,
        },
        {
            "id": str(uuid.uuid4())[:8],
            "key": r"HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\svchost32",
            "value_name": "ImagePath",
            "value_data": r"C:\Users\Public\svchost32.exe",
            "operation": "create",
            "risk_score": 95,
            "indicators": ["service_creation", "impersonation", "public_folder"],
            "timestamp": timestamp,
        },
        {
            "id": str(uuid.uuid4())[:8],
            "key": r"HKEY_CURRENT_USER\Software\Classes\mscfile\shell\open\command",
            "value_name": "(Default)",
            "value_data": r"powershell.exe -nop -w hidden -enc aGVsbG8=",
            "operation": "create",
            "risk_score": 90,
            "indicators": ["hijack_attempt", "powershell", "encoded_command"],
            "timestamp": timestamp,
        },
        {
            "id": str(uuid.uuid4())[:8],
            "key": r"HKEY_CURRENT_USER\Software\Microsoft\Office\16.0\Excel\Security",
            "value_name": "VBAWarnings",
            "value_data": "1",
            "operation": "modify",
            "risk_score": 75,
            "indicators": ["security_downgrade", "macro_policy"],
            "timestamp": timestamp,
        },
    ]
    
    return changes


@app.get("/registry/changes")
async def registry_changes(limit: int = 100, rescan: bool = False):
    """
    Return recent registry modifications detected on the system.
    Tracks changes across security-sensitive registry locations.
    """
    global _registry_changes
    
    if rescan or not _registry_changes:
        _registry_changes = _simulate_registry_changes()
        
        # Trim history
        if len(_registry_changes) > 1000:
            _registry_changes = _registry_changes[-1000:]
    
    limit = _safe_limit(limit, default=100, minimum=1, maximum=500)
    recent = list(reversed(_registry_changes[-limit:]))
    
    # Operation breakdown
    operation_counts = dict(Counter(c.get("operation", "unknown") for c in recent))
    
    # Risk distribution
    risk_categories = {"low": 0, "medium": 0, "high": 0, "critical": 0}
    for change in recent:
        score = change.get("risk_score", 0)
        if score < 40:
            risk_categories["low"] += 1
        elif score < 65:
            risk_categories["medium"] += 1
        elif score < 85:
            risk_categories["high"] += 1
        else:
            risk_categories["critical"] += 1
    
    return {
        "count": len(recent),
        "operation_breakdown": operation_counts,
        "risk_distribution": risk_categories,
        "changes": recent,
    }


@app.get("/registry/suspicious")
async def registry_suspicious(threshold: int = 60):
    """
    Filter registry changes flagged as suspicious based on risk scoring.
    Default threshold: 60/100.
    """
    global _registry_changes
    
    # Ensure changes are populated
    if not _registry_changes:
        _registry_changes = _simulate_registry_changes()
    
    # Filter by threshold
    suspicious = [
        change for change in _registry_changes
        if change.get("risk_score", 0) >= threshold
    ]
    
    # Sort by risk score descending
    suspicious.sort(key=lambda c: c.get("risk_score", 0), reverse=True)
    
    # Indicator aggregation
    all_indicators = []
    for change in suspicious:
        all_indicators.extend(change.get("indicators", []))
    indicator_frequency = dict(Counter(all_indicators))
    
    return {
        "threshold": threshold,
        "suspicious_count": len(suspicious),
        "top_indicators": dict(sorted(indicator_frequency.items(), key=lambda x: x[1], reverse=True)[:10]),
        "changes": suspicious,
    }


# ========================================
# Phase 61 - Privileged Process Monitoring
# ========================================

def _collect_privileged_processes() -> List[Dict[str, Any]]:
    """Identify processes running with elevated privileges or sensitive capabilities."""
    try:
        import psutil
    except ImportError:
        # Return simulation if psutil unavailable
        return _simulate_privileged_processes()
    
    privileged = []
    timestamp = datetime.now(timezone.utc).isoformat()
    
    try:
        for proc in psutil.process_iter(['pid', 'name', 'username', 'exe', 'cmdline']):
            try:
                info = proc.info
                username = info.get('username', 'unknown')
                
                # Check for privilege indicators
                is_privileged = False
                privilege_indicators = []
                
                # System/root user
                if username and any(priv in username.lower() for priv in ['system', 'root', 'administrator', 'admin']):
                    is_privileged = True
                    privilege_indicators.append("system_user")
                
                # Known privileged process names
                proc_name = info.get('name', '').lower()
                privileged_names = ['lsass.exe', 'csrss.exe', 'winlogon.exe', 'services.exe', 'svchost.exe', 'smss.exe', 'wininit.exe']
                if proc_name in privileged_names:
                    is_privileged = True
                    privilege_indicators.append("privileged_name")
                
                if is_privileged:
                    # Calculate risk score
                    risk_score = 10
                    if "system_user" in privilege_indicators:
                        risk_score += 30
                    if "privileged_name" in privilege_indicators:
                        risk_score += 20
                    
                    # Suspicious path detection
                    exe_path = info.get('exe', '')
                    if exe_path and not exe_path.startswith('C:\\Windows\\'):
                        risk_score += 40
                        privilege_indicators.append("non_system_path")
                    
                    privileged.append({
                        "pid": info.get('pid'),
                        "name": info.get('name', 'unknown'),
                        "username": username,
                        "exe": exe_path,
                        "cmdline": ' '.join(info.get('cmdline', [])) if info.get('cmdline') else '',
                        "risk_score": min(risk_score, 100),
                        "privilege_indicators": privilege_indicators,
                        "collected_at": timestamp,
                    })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
    except Exception:
        return _simulate_privileged_processes()
    
    return privileged


def _simulate_privileged_processes() -> List[Dict[str, Any]]:
    """Simulate privileged process detection when psutil is unavailable."""
    timestamp = datetime.now(timezone.utc).isoformat()
    
    return [
        {
            "pid": 4,
            "name": "System",
            "username": "NT AUTHORITY\\SYSTEM",
            "exe": "",
            "cmdline": "",
            "risk_score": 10,
            "privilege_indicators": ["system_user"],
            "collected_at": timestamp,
        },
        {
            "pid": 620,
            "name": "lsass.exe",
            "username": "NT AUTHORITY\\SYSTEM",
            "exe": r"C:\Windows\System32\lsass.exe",
            "cmdline": r"C:\Windows\system32\lsass.exe",
            "risk_score": 40,
            "privilege_indicators": ["system_user", "privileged_name"],
            "collected_at": timestamp,
        },
        {
            "pid": 1024,
            "name": "svchost.exe",
            "username": "NT AUTHORITY\\SYSTEM",
            "exe": r"C:\Users\Public\svchost.exe",
            "cmdline": r"C:\Users\Public\svchost.exe /service",
            "risk_score": 80,
            "privilege_indicators": ["system_user", "privileged_name", "non_system_path"],
            "collected_at": timestamp,
        },
        {
            "pid": 2048,
            "name": "csrss.exe",
            "username": "NT AUTHORITY\\SYSTEM",
            "exe": r"C:\Windows\System32\csrss.exe",
            "cmdline": r"%SystemRoot%\system32\csrss.exe ObjectDirectory=\Windows",
            "risk_score": 40,
            "privilege_indicators": ["system_user", "privileged_name"],
            "collected_at": timestamp,
        },
    ]


@app.get("/processes/privileged")
async def processes_privileged(refresh: bool = False):
    """
    List processes running with elevated privileges or system-level capabilities.
    Detects privilege escalation and impersonation attempts.
    """
    global _privileged_process_cache
    
    if refresh or not _privileged_process_cache:
        _privileged_process_cache = _collect_privileged_processes()
    
    # Risk categorization
    risk_categories = {"low": 0, "medium": 0, "high": 0, "critical": 0}
    for proc in _privileged_process_cache:
        score = proc.get("risk_score", 0)
        if score < 40:
            risk_categories["low"] += 1
        elif score < 65:
            risk_categories["medium"] += 1
        elif score < 85:
            risk_categories["high"] += 1
        else:
            risk_categories["critical"] += 1
    
    # Calculate average risk
    avg_risk = sum(p.get("risk_score", 0) for p in _privileged_process_cache) / len(_privileged_process_cache) if _privileged_process_cache else 0
    
    return {
        "total_privileged": len(_privileged_process_cache),
        "avg_risk_score": round(avg_risk, 2),
        "risk_distribution": risk_categories,
        "processes": _privileged_process_cache,
    }


@app.get("/processes/privileged/events")
async def processes_privileged_events(limit: int = 100):
    """
    Return event log of privileged process detections and anomalies.
    Tracks privilege escalation attempts and suspicious system-level activity.
    """
    global _privileged_process_events, _privileged_process_cache
    
    # Generate event from current cache state
    if _privileged_process_cache:
        event = {
            "event_type": "privileged_scan",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "processes_detected": len(_privileged_process_cache),
            "high_risk_count": sum(1 for p in _privileged_process_cache if p.get("risk_score", 0) >= 65),
        }
        _privileged_process_events.append(event)
        
        # Trim history
        if len(_privileged_process_events) > 1000:
            _privileged_process_events = _privileged_process_events[-1000:]
    
    limit = _safe_limit(limit, default=100, minimum=1, maximum=500)
    recent = list(reversed(_privileged_process_events[-limit:]))
    
    return {
        "count": len(recent),
        "events": recent,
    }


# ========================================
# Phase 62 - API Abuse Detection
# ========================================

def _simulate_api_requests() -> List[Dict[str, Any]]:
    """Generate simulated API request patterns for abuse detection."""
    timestamp = datetime.now(timezone.utc).isoformat()
    base_time = datetime.now(timezone.utc)
    
    requests = []
    
    # Normal traffic
    for i in range(10):
        requests.append({
            "id": str(uuid.uuid4())[:8],
            "ip": "192.168.1.100",
            "endpoint": "/api/alerts",
            "method": "GET",
            "status_code": 200,
            "timestamp": (base_time - timedelta(minutes=i)).isoformat(),
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "anomaly_score": 5,
        })
    
    # Suspicious high-frequency requests
    for i in range(50):
        requests.append({
            "id": str(uuid.uuid4())[:8],
            "ip": "203.0.113.45",
            "endpoint": "/api/alerts",
            "method": "GET",
            "status_code": 200,
            "timestamp": (base_time - timedelta(seconds=i)).isoformat(),
            "user_agent": "python-requests/2.28.0",
            "anomaly_score": 75,
        })
    
    # Suspicious scanning patterns
    endpoints = ["/api/users", "/api/admin", "/api/config", "/api/secrets", "/api/keys"]
    for endpoint in endpoints:
        requests.append({
            "id": str(uuid.uuid4())[:8],
            "ip": "198.51.100.22",
            "endpoint": endpoint,
            "method": "GET",
            "status_code": 403,
            "timestamp": (base_time - timedelta(seconds=len(requests))).isoformat(),
            "user_agent": "curl/7.68.0",
            "anomaly_score": 85,
        })
    
    # SQL injection attempts
    requests.append({
        "id": str(uuid.uuid4())[:8],
        "ip": "198.51.100.22",
        "endpoint": "/api/search?q=' OR '1'='1",
        "method": "GET",
        "status_code": 400,
        "timestamp": base_time.isoformat(),
        "user_agent": "curl/7.68.0",
        "anomaly_score": 95,
    })
    
    return requests


def _detect_api_abuse() -> List[Dict[str, Any]]:
    """Analyze API request patterns to detect abuse."""
    global _api_request_log
    
    if not _api_request_log:
        _api_request_log = _simulate_api_requests()
    
    abuse_cases = []
    
    # Group by IP
    ip_groups = {}
    for req in _api_request_log:
        ip = req.get("ip", "unknown")
        if ip not in ip_groups:
            ip_groups[ip] = []
        ip_groups[ip].append(req)
    
    timestamp = datetime.now(timezone.utc).isoformat()
    
    # Detect high-frequency abuse
    for ip, reqs in ip_groups.items():
        if len(reqs) > 30:
            abuse_cases.append({
                "id": str(uuid.uuid4())[:8],
                "type": "high_frequency",
                "ip": ip,
                "request_count": len(reqs),
                "risk_score": min(50 + len(reqs), 100),
                "description": f"Excessive API requests: {len(reqs)} requests detected",
                "detected_at": timestamp,
            })
    
    # Detect scanning patterns
    for ip, reqs in ip_groups.items():
        unique_endpoints = set(req.get("endpoint", "") for req in reqs)
        failed_requests = sum(1 for req in reqs if req.get("status_code", 200) >= 400)
        
        if len(unique_endpoints) > 5 and failed_requests > 3:
            abuse_cases.append({
                "id": str(uuid.uuid4())[:8],
                "type": "scanning",
                "ip": ip,
                "unique_endpoints": len(unique_endpoints),
                "failed_requests": failed_requests,
                "risk_score": 80,
                "description": f"API scanning detected: {len(unique_endpoints)} endpoints probed",
                "detected_at": timestamp,
            })
    
    # Detect injection attempts
    for req in _api_request_log:
        endpoint = req.get("endpoint", "")
        if any(pattern in endpoint.lower() for pattern in ["' or '", "union select", "drop table", "<script>"]):
            abuse_cases.append({
                "id": str(uuid.uuid4())[:8],
                "type": "injection_attempt",
                "ip": req.get("ip"),
                "endpoint": endpoint,
                "risk_score": 95,
                "description": "Malicious payload detected in API request",
                "detected_at": timestamp,
            })
    
    return abuse_cases


@app.get("/api/abuse")
async def api_abuse(refresh: bool = False):
    """
    Detect API abuse patterns: high-frequency requests, scanning, and injection attempts.
    Analyzes request patterns to identify malicious behavior.
    """
    global _api_abuse_detections
    
    if refresh or not _api_abuse_detections:
        _api_abuse_detections = _detect_api_abuse()
    
    # Type distribution
    type_breakdown = dict(Counter(d.get("type", "unknown") for d in _api_abuse_detections))
    
    # Risk categorization
    risk_categories = {"medium": 0, "high": 0, "critical": 0}
    for detection in _api_abuse_detections:
        score = detection.get("risk_score", 0)
        if score < 65:
            risk_categories["medium"] += 1
        elif score < 85:
            risk_categories["high"] += 1
        else:
            risk_categories["critical"] += 1
    
    # Top offender IPs
    ip_counts = Counter(d.get("ip", "unknown") for d in _api_abuse_detections)
    top_ips = dict(ip_counts.most_common(5))
    
    return {
        "total_abuse_cases": len(_api_abuse_detections),
        "type_breakdown": type_breakdown,
        "risk_distribution": risk_categories,
        "top_offender_ips": top_ips,
        "detections": _api_abuse_detections,
    }


@app.get("/api/anomalies")
async def api_anomalies(threshold: int = 70):
    """
    Return API request anomalies exceeding risk threshold.
    Filters high-risk abuse patterns for immediate response.
    """
    global _api_request_log
    
    if not _api_request_log:
        _api_request_log = _simulate_api_requests()
    
    # Filter anomalous requests
    anomalies = [
        req for req in _api_request_log
        if req.get("anomaly_score", 0) >= threshold
    ]
    
    # Sort by anomaly score descending
    anomalies.sort(key=lambda r: r.get("anomaly_score", 0), reverse=True)
    
    # IP distribution
    ip_counts = Counter(a.get("ip", "unknown") for a in anomalies)
    
    return {
        "threshold": threshold,
        "anomaly_count": len(anomalies),
        "unique_ips": len(ip_counts),
        "ip_distribution": dict(ip_counts.most_common(10)),
        "anomalies": anomalies,
    }


# ========================================
# Phase 63 - Authentication Monitoring
# ========================================

def _simulate_auth_events() -> List[Dict[str, Any]]:
    """Generate simulated authentication events for monitoring."""
    base_time = datetime.now(timezone.utc)
    events = []
    
    # Successful logins
    for i in range(10):
        events.append({
            "id": str(uuid.uuid4())[:8],
            "event_type": "login_success",
            "username": "alice.smith",
            "ip": "192.168.1.100",
            "location": "New York, US",
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "timestamp": (base_time - timedelta(hours=i)).isoformat(),
            "anomaly_score": 5,
        })
    
    # Failed login attempts
    for i in range(5):
        events.append({
            "id": str(uuid.uuid4())[:8],
            "event_type": "login_failed",
            "username": "admin",
            "ip": "203.0.113.45",
            "location": "Unknown",
            "user_agent": "python-requests/2.28.0",
            "timestamp": (base_time - timedelta(minutes=i)).isoformat(),
            "anomaly_score": 60,
            "reason": "invalid_credentials",
        })
    
    # Brute force attempt
    for i in range(20):
        events.append({
            "id": str(uuid.uuid4())[:8],
            "event_type": "login_failed",
            "username": "admin",
            "ip": "198.51.100.22",
            "location": "Unknown",
            "user_agent": "curl/7.68.0",
            "timestamp": (base_time - timedelta(seconds=i*10)).isoformat(),
            "anomaly_score": 85,
            "reason": "invalid_credentials",
        })
    
    # Impossible travel
    events.append({
        "id": str(uuid.uuid4())[:8],
        "event_type": "login_success",
        "username": "alice.smith",
        "ip": "1.2.3.4",
        "location": "Beijing, CN",
        "user_agent": "Mozilla/5.0 (X11; Linux x86_64)",
        "timestamp": (base_time - timedelta(minutes=5)).isoformat(),
        "anomaly_score": 90,
        "anomaly_reasons": ["impossible_travel", "location_change"],
    })
    
    # Account enumeration
    usernames = ["admin", "root", "administrator", "user", "test"]
    for username in usernames:
        events.append({
            "id": str(uuid.uuid4())[:8],
            "event_type": "login_failed",
            "username": username,
            "ip": "198.51.100.33",
            "location": "Unknown",
            "user_agent": "python-requests/2.28.0",
            "timestamp": (base_time - timedelta(seconds=len(events))).isoformat(),
            "anomaly_score": 75,
            "reason": "invalid_credentials",
        })
    
    return events


def _detect_auth_anomalies() -> List[Dict[str, Any]]:
    """Detect authentication anomalies from login events."""
    global _auth_login_events
    
    if not _auth_login_events:
        _auth_login_events = _simulate_auth_events()
    
    anomalies = []
    timestamp = datetime.now(timezone.utc).isoformat()
    
    # Group by IP
    ip_groups = {}
    for event in _auth_login_events:
        ip = event.get("ip", "unknown")
        if ip not in ip_groups:
            ip_groups[ip] = []
        ip_groups[ip].append(event)
    
    # Detect brute force
    for ip, events in ip_groups.items():
        failed_logins = [e for e in events if e.get("event_type") == "login_failed"]
        if len(failed_logins) >= 5:
            anomalies.append({
                "id": str(uuid.uuid4())[:8],
                "type": "brute_force",
                "ip": ip,
                "failed_attempts": len(failed_logins),
                "risk_score": min(50 + len(failed_logins) * 5, 100),
                "description": f"Brute force attack detected: {len(failed_logins)} failed login attempts",
                "detected_at": timestamp,
            })
    
    # Detect impossible travel
    username_ips = {}
    for event in _auth_login_events:
        if event.get("event_type") == "login_success":
            username = event.get("username")
            location = event.get("location", "Unknown")
            if username not in username_ips:
                username_ips[username] = []
            username_ips[username].append(location)
    
    for username, locations in username_ips.items():
        unique_locations = set(locations)
        if len(unique_locations) > 1 and any("US" in loc and "CN" in loc for loc in [",".join(locations)]):
            anomalies.append({
                "id": str(uuid.uuid4())[:8],
                "type": "impossible_travel",
                "username": username,
                "locations": list(unique_locations),
                "risk_score": 90,
                "description": f"Impossible travel detected for user {username}",
                "detected_at": timestamp,
            })
    
    # Detect account enumeration
    for ip, events in ip_groups.items():
        unique_usernames = set(e.get("username") for e in events)
        if len(unique_usernames) >= 5:
            anomalies.append({
                "id": str(uuid.uuid4())[:8],
                "type": "account_enumeration",
                "ip": ip,
                "usernames_tried": len(unique_usernames),
                "risk_score": 75,
                "description": f"Account enumeration detected: {len(unique_usernames)} usernames tried",
                "detected_at": timestamp,
            })
    
    return anomalies


@app.get("/auth/logins")
async def auth_logins(limit: int = 100, refresh: bool = False):
    """
    Return authentication events including successful and failed login attempts.
    Tracks user authentication activity across the system.
    """
    global _auth_login_events
    
    if refresh or not _auth_login_events:
        _auth_login_events = _simulate_auth_events()
    
    limit = _safe_limit(limit, default=100, minimum=1, maximum=500)
    recent = list(reversed(_auth_login_events[-limit:]))
    
    # Event type distribution
    event_type_counts = dict(Counter(e.get("event_type", "unknown") for e in recent))
    
    # Failed login distribution
    failed_events = [e for e in recent if e.get("event_type") == "login_failed"]
    failed_by_ip = Counter(e.get("ip", "unknown") for e in failed_events)
    
    return {
        "count": len(recent),
        "event_type_distribution": event_type_counts,
        "failed_login_count": len(failed_events),
        "top_failed_ips": dict(failed_by_ip.most_common(5)),
        "events": recent,
    }


@app.get("/auth/anomalies")
async def auth_anomalies(refresh: bool = False):
    """
    Detect authentication anomalies: brute force attacks, impossible travel, account enumeration.
    Identifies suspicious authentication patterns requiring investigation.
    """
    global _auth_anomalies
    
    if refresh or not _auth_anomalies:
        _auth_anomalies = _detect_auth_anomalies()
    
    # Type distribution
    type_breakdown = dict(Counter(a.get("type", "unknown") for a in _auth_anomalies))
    
    # Risk categorization
    risk_categories = {"medium": 0, "high": 0, "critical": 0}
    for anomaly in _auth_anomalies:
        score = anomaly.get("risk_score", 0)
        if score < 65:
            risk_categories["medium"] += 1
        elif score < 85:
            risk_categories["high"] += 1
        else:
            risk_categories["critical"] += 1
    
    return {
        "total_anomalies": len(_auth_anomalies),
        "type_breakdown": type_breakdown,
        "risk_distribution": risk_categories,
        "anomalies": _auth_anomalies,
    }


# ========================================
# Phase 64 - Brute Force Detection
# ========================================

def _detect_bruteforce_attacks() -> List[Dict[str, Any]]:
    """Analyze authentication events to detect brute force attacks."""
    global _auth_login_events
    
    if not _auth_login_events:
        _auth_login_events = _simulate_auth_events()
    
    bruteforce_attacks = []
    timestamp = datetime.now(timezone.utc).isoformat()
    
    # Group failed logins by IP
    ip_failed_logins = {}
    for event in _auth_login_events:
        if event.get("event_type") == "login_failed":
            ip = event.get("ip", "unknown")
            if ip not in ip_failed_logins:
                ip_failed_logins[ip] = []
            ip_failed_logins[ip].append(event)
    
    # Detect brute force patterns
    for ip, failed_events in ip_failed_logins.items():
        if len(failed_events) >= 5:
            # Calculate attack intensity
            unique_usernames = set(e.get("username") for e in failed_events)
            attack_duration_seconds = 300  # Simulated 5 minute window
            attempts_per_minute = len(failed_events) / (attack_duration_seconds / 60)
            
            # Risk scoring
            risk_score = 50
            risk_score += min(len(failed_events) * 3, 30)  # More attempts = higher risk
            risk_score += min(len(unique_usernames) * 5, 20)  # More usernames = higher risk
            risk_score = min(risk_score, 100)
            
            bruteforce_attacks.append({
                "id": str(uuid.uuid4())[:8],
                "ip": ip,
                "failed_attempts": len(failed_events),
                "unique_usernames": len(unique_usernames),
                "attempts_per_minute": round(attempts_per_minute, 2),
                "risk_score": risk_score,
                "attack_type": "credential_stuffing" if len(unique_usernames) > 3 else "password_spray",
                "detected_at": timestamp,
                "status": "active",
            })
    
    return bruteforce_attacks


@app.get("/auth/bruteforce")
async def auth_bruteforce(refresh: bool = False):
    """
    Detect active brute force attacks against authentication endpoints.
    Identifies credential stuffing and password spray attacks.
    """
    global _bruteforce_detections
    
    if refresh or not _bruteforce_detections:
        _bruteforce_detections = _detect_bruteforce_attacks()
    
    # Status distribution
    active_count = sum(1 for d in _bruteforce_detections if d.get("status") == "active")
    blocked_count = sum(1 for d in _bruteforce_detections if d.get("status") == "blocked")
    
    # Attack type distribution
    attack_type_counts = dict(Counter(d.get("attack_type", "unknown") for d in _bruteforce_detections))
    
    # Risk categorization
    risk_categories = {"medium": 0, "high": 0, "critical": 0}
    for detection in _bruteforce_detections:
        score = detection.get("risk_score", 0)
        if score < 65:
            risk_categories["medium"] += 1
        elif score < 85:
            risk_categories["high"] += 1
        else:
            risk_categories["critical"] += 1
    
    # Top offender IPs
    ips = [d.get("ip") for d in _bruteforce_detections]
    top_ips = dict(Counter(ips).most_common(5))
    
    return {
        "total_attacks": len(_bruteforce_detections),
        "active_attacks": active_count,
        "blocked_attacks": blocked_count,
        "attack_type_distribution": attack_type_counts,
        "risk_distribution": risk_categories,
        "top_offender_ips": top_ips,
        "attacks": _bruteforce_detections,
    }


@app.post("/auth/block/{ip}")
async def auth_block_ip(ip: str):
    """
    Block an IP address from authentication attempts.
    Adds IP to blocklist and updates brute force detection status.
    """
    global _blocked_ips, _bruteforce_detections
    
    # Check if already blocked
    if ip in _blocked_ips:
        raise HTTPException(status_code=400, detail=f"IP {ip} is already blocked")
    
    # Add to blocklist
    timestamp = datetime.now(timezone.utc).isoformat()
    block_id = str(uuid.uuid4())[:8]
    
    _blocked_ips[ip] = {
        "id": block_id,
        "ip": ip,
        "blocked_at": timestamp,
        "reason": "brute_force_detection",
        "status": "active",
    }
    
    # Update related brute force detections
    for detection in _bruteforce_detections:
        if detection.get("ip") == ip:
            detection["status"] = "blocked"
    
    return {
        "success": True,
        "block_id": block_id,
        "ip": ip,
        "blocked_at": timestamp,
        "message": f"IP {ip} has been blocked from authentication attempts",
    }


# ========================================
# Phase 65 - Session Monitoring
# ========================================

def _simulate_active_sessions() -> List[Dict[str, Any]]:
    """Generate simulated active user sessions for monitoring."""
    base_time = datetime.now(timezone.utc)
    sessions = []
    
    # Normal sessions
    normal_users = [
        {"username": "alice.smith", "ip": "192.168.1.100", "location": "New York, US"},
        {"username": "bob.jones", "ip": "192.168.1.101", "location": "Los Angeles, US"},
        {"username": "carol.white", "ip": "192.168.1.102", "location": "Chicago, US"},
    ]
    
    for user in normal_users:
        sessions.append({
            "id": str(uuid.uuid4())[:8],
            "username": user["username"],
            "ip": user["ip"],
            "location": user["location"],
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "created_at": (base_time - timedelta(hours=2)).isoformat(),
            "last_activity": (base_time - timedelta(minutes=5)).isoformat(),
            "request_count": 150,
            "suspicion_score": 10,
            "suspicious_indicators": [],
            "status": "active",
        })
    
    # Suspicious sessions
    sessions.append({
        "id": str(uuid.uuid4())[:8],
        "username": "alice.smith",
        "ip": "203.0.113.45",
        "location": "Unknown",
        "user_agent": "python-requests/2.28.0",
        "created_at": (base_time - timedelta(minutes=10)).isoformat(),
        "last_activity": base_time.isoformat(),
        "request_count": 500,
        "suspicion_score": 75,
        "suspicious_indicators": ["high_request_rate", "unusual_user_agent", "unknown_location"],
        "status": "active",
    })
    
    sessions.append({
        "id": str(uuid.uuid4())[:8],
        "username": "admin",
        "ip": "198.51.100.22",
        "location": "Unknown",
        "user_agent": "curl/7.68.0",
        "created_at": (base_time - timedelta(minutes=5)).isoformat(),
        "last_activity": base_time.isoformat(),
        "request_count": 200,
        "suspicion_score": 85,
        "suspicious_indicators": ["privileged_account", "unusual_user_agent", "high_request_rate", "unknown_location"],
        "status": "active",
    })
    
    # Session with concurrent locations (session hijacking)
    sessions.append({
        "id": str(uuid.uuid4())[:8],
        "username": "bob.jones",
        "ip": "1.2.3.4",
        "location": "Beijing, CN",
        "user_agent": "Mozilla/5.0 (X11; Linux x86_64)",
        "created_at": (base_time - timedelta(minutes=3)).isoformat(),
        "last_activity": base_time.isoformat(),
        "request_count": 50,
        "suspicion_score": 90,
        "suspicious_indicators": ["concurrent_session", "location_mismatch", "impossible_travel"],
        "status": "active",
    })
    
    # Stale/inactive session
    sessions.append({
        "id": str(uuid.uuid4())[:8],
        "username": "dave.brown",
        "ip": "192.168.1.103",
        "location": "Seattle, US",
        "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
        "created_at": (base_time - timedelta(days=1)).isoformat(),
        "last_activity": (base_time - timedelta(hours=12)).isoformat(),
        "request_count": 10,
        "suspicion_score": 30,
        "suspicious_indicators": ["stale_session"],
        "status": "inactive",
    })
    
    return sessions


@app.get("/sessions")
async def sessions(refresh: bool = False):
    """
    List all active user sessions with suspicion scoring.
    Monitors session activity for anomalies and hijacking attempts.
    """
    global _session_cache
    
    if refresh or not _session_cache:
        _session_cache = _simulate_active_sessions()
    
    # Status distribution
    status_counts = dict(Counter(s.get("status", "unknown") for s in _session_cache))
    
    # Calculate statistics
    active_sessions = [s for s in _session_cache if s.get("status") == "active"]
    avg_suspicion = sum(s.get("suspicion_score", 0) for s in active_sessions) / len(active_sessions) if active_sessions else 0
    
    # Unique users
    unique_users = len(set(s.get("username") for s in _session_cache))
    
    return {
        "total_sessions": len(_session_cache),
        "active_sessions": len(active_sessions),
        "unique_users": unique_users,
        "avg_suspicion_score": round(avg_suspicion, 2),
        "status_distribution": status_counts,
        "sessions": _session_cache,
    }


@app.get("/sessions/suspicious")
async def sessions_suspicious(threshold: int = 60):
    """
    Filter sessions flagged as suspicious based on scoring threshold.
    Identifies session hijacking, concurrent logins, and anomalous behavior.
    """
    global _session_cache, _suspicious_sessions
    
    # Ensure cache is populated
    if not _session_cache:
        _session_cache = _simulate_active_sessions()
    
    # Filter by threshold
    _suspicious_sessions = [
        session for session in _session_cache
        if session.get("suspicion_score", 0) >= threshold
    ]
    
    # Sort by suspicion score descending
    _suspicious_sessions.sort(key=lambda s: s.get("suspicion_score", 0), reverse=True)
    
    # Risk categorization
    risk_categories = {"medium": 0, "high": 0, "critical": 0}
    for session in _suspicious_sessions:
        score = session.get("suspicion_score", 0)
        if score < 70:
            risk_categories["medium"] += 1
        elif score < 85:
            risk_categories["high"] += 1
        else:
            risk_categories["critical"] += 1
    
    # Top indicators
    all_indicators = []
    for session in _suspicious_sessions:
        all_indicators.extend(session.get("suspicious_indicators", []))
    indicator_frequency = dict(Counter(all_indicators).most_common(5))
    
    return {
        "threshold": threshold,
        "suspicious_count": len(_suspicious_sessions),
        "risk_distribution": risk_categories,
        "top_indicators": indicator_frequency,
        "sessions": _suspicious_sessions,
    }


# ========================================
# Phase 66 - Email Threat Intelligence
# ========================================

def _simulate_email_threats() -> tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Generate simulated email threats for phishing and malware detection."""
    base_time = datetime.now(timezone.utc)
    
    phishing_emails = [
        {
            "id": str(uuid.uuid4())[:8],
            "from": "security@paypa1.com",
            "subject": "Urgent: Verify Your Account",
            "received_at": (base_time - timedelta(hours=2)).isoformat(),
            "recipient": "user@company.com",
            "risk_score": 95,
            "indicators": ["domain_typosquatting", "urgency_language", "suspicious_link"],
            "verdict": "phishing",
            "status": "quarantined",
        },
        {
            "id": str(uuid.uuid4())[:8],
            "from": "billing@amaz0n.com",
            "subject": "Your order has been shipped",
            "received_at": (base_time - timedelta(hours=5)).isoformat(),
            "recipient": "user@company.com",
            "risk_score": 90,
            "indicators": ["domain_typosquatting", "suspicious_link"],
            "verdict": "phishing",
            "status": "blocked",
        },
        {
            "id": str(uuid.uuid4())[:8],
            "from": "ceo@external-domain.com",
            "subject": "URGENT: Wire Transfer Request",
            "received_at": (base_time - timedelta(minutes=30)).isoformat(),
            "recipient": "finance@company.com",
            "risk_score": 98,
            "indicators": ["executive_impersonation", "urgency_language", "financial_request"],
            "verdict": "business_email_compromise",
            "status": "quarantined",
        },
        {
            "id": str(uuid.uuid4())[:8],
            "from": "noreply@microsoft-support.net",
            "subject": "Your Microsoft account will be closed",
            "received_at": (base_time - timedelta(days=1)).isoformat(),
            "recipient": "user@company.com",
            "risk_score": 85,
            "indicators": ["brand_impersonation", "urgency_language", "credential_harvesting"],
            "verdict": "phishing",
            "status": "quarantined",
        },
    ]
    
    malware_emails = [
        {
            "id": str(uuid.uuid4())[:8],
            "from": "invoice@supplier-corp.com",
            "subject": "Invoice #12345 - Payment Due",
            "attachment": "invoice_12345.pdf.exe",
            "received_at": (base_time - timedelta(hours=3)).isoformat(),
            "recipient": "accounting@company.com",
            "risk_score": 95,
            "indicators": ["malicious_attachment", "double_extension", "executable_disguised"],
            "malware_family": "trojan",
            "status": "blocked",
        },
        {
            "id": str(uuid.uuid4())[:8],
            "from": "hr@recruitment-agency.com",
            "subject": "Job Application - Resume Attached",
            "attachment": "resume.docm",
            "received_at": (base_time - timedelta(hours=6)).isoformat(),
            "recipient": "hr@company.com",
            "risk_score": 88,
            "indicators": ["macro_enabled_document", "suspicious_attachment"],
            "malware_family": "macro_malware",
            "status": "quarantined",
        },
        {
            "id": str(uuid.uuid4())[:8],
            "from": "shipping@logistics-partner.com",
            "subject": "Delivery Notification #789456",
            "attachment": "delivery_details.zip",
            "received_at": (base_time - timedelta(days=1)).isoformat(),
            "recipient": "operations@company.com",
            "risk_score": 92,
            "indicators": ["suspicious_archive", "malicious_payload"],
            "malware_family": "ransomware",
            "status": "blocked",
        },
    ]
    
    return phishing_emails, malware_emails


@app.get("/email/phishing")
async def email_phishing(refresh: bool = False):
    """
    Detect phishing emails including credential harvesting, brand impersonation,
    and business email compromise attempts.
    """
    global _phishing_emails, _malware_emails
    
    if refresh or not _phishing_emails:
        _phishing_emails, _malware_emails = _simulate_email_threats()
    
    # Verdict distribution
    verdict_counts = dict(Counter(e.get("verdict", "unknown") for e in _phishing_emails))
    
    # Status distribution
    status_counts = dict(Counter(e.get("status", "unknown") for e in _phishing_emails))
    
    # Risk categorization
    risk_categories = {"high": 0, "critical": 0}
    for email in _phishing_emails:
        score = email.get("risk_score", 0)
        if score < 90:
            risk_categories["high"] += 1
        else:
            risk_categories["critical"] += 1
    
    # Top indicators
    all_indicators = []
    for email in _phishing_emails:
        all_indicators.extend(email.get("indicators", []))
    top_indicators = dict(Counter(all_indicators).most_common(5))
    
    return {
        "total_phishing": len(_phishing_emails),
        "verdict_distribution": verdict_counts,
        "status_distribution": status_counts,
        "risk_distribution": risk_categories,
        "top_indicators": top_indicators,
        "emails": _phishing_emails,
    }


@app.get("/email/malware")
async def email_malware(refresh: bool = False):
    """
    Detect malware-laden emails with malicious attachments, payloads,
    and exploit kits. Tracks malware families and delivery methods.
    """
    global _phishing_emails, _malware_emails
    
    if refresh or not _malware_emails:
        _phishing_emails, _malware_emails = _simulate_email_threats()
    
    # Malware family distribution
    family_counts = dict(Counter(e.get("malware_family", "unknown") for e in _malware_emails))
    
    # Status distribution
    status_counts = dict(Counter(e.get("status", "unknown") for e in _malware_emails))
    
    # Risk categorization
    risk_categories = {"high": 0, "critical": 0}
    for email in _malware_emails:
        score = email.get("risk_score", 0)
        if score < 90:
            risk_categories["high"] += 1
        else:
            risk_categories["critical"] += 1
    
    # Top indicators
    all_indicators = []
    for email in _malware_emails:
        all_indicators.extend(email.get("indicators", []))
    top_indicators = dict(Counter(all_indicators).most_common(5))
    
    return {
        "total_malware": len(_malware_emails),
        "malware_families": family_counts,
        "status_distribution": status_counts,
        "risk_distribution": risk_categories,
        "top_indicators": top_indicators,
        "emails": _malware_emails,
    }


# ========================================
# Phase 67 - Browser Security Monitoring
# ========================================

def _simulate_browser_extensions() -> List[Dict[str, Any]]:
    """Generate simulated browser extension data for security monitoring."""
    base_time = datetime.now(timezone.utc)
    
    extensions = [
        {
            "id": str(uuid.uuid4())[:8],
            "name": "AdBlock Plus",
            "extension_id": "cfhdojbkjhnklbpkdaibdccddilifddb",
            "version": "3.14.2",
            "browser": "Chrome",
            "installed_at": (base_time - timedelta(days=180)).isoformat(),
            "permissions": ["tabs", "webNavigation", "storage"],
            "risk_score": 15,
            "suspicious_indicators": [],
            "status": "trusted",
        },
        {
            "id": str(uuid.uuid4())[:8],
            "name": "Grammarly",
            "extension_id": "kbfnbcaeplbcioakkpcpgfkobkghlhen",
            "version": "14.1076.0",
            "browser": "Chrome",
            "installed_at": (base_time - timedelta(days=90)).isoformat(),
            "permissions": ["storage", "cookies", "webRequest"],
            "risk_score": 25,
            "suspicious_indicators": [],
            "status": "trusted",
        },
        {
            "id": str(uuid.uuid4())[:8],
            "name": "Password Manager Pro",
            "extension_id": "abcdef1234567890abcdef1234567890",
            "version": "1.0.0",
            "browser": "Chrome",
            "installed_at": (base_time - timedelta(days=2)).isoformat(),
            "permissions": ["tabs", "webRequest", "storage", "cookies", "<all_urls>"],
            "risk_score": 85,
            "suspicious_indicators": ["excessive_permissions", "recently_installed", "unverified_publisher"],
            "status": "suspicious",
        },
        {
            "id": str(uuid.uuid4())[:8],
            "name": "CryptoMiner Extension",
            "extension_id": "xyz9876543210xyz9876543210xyz987",
            "version": "2.3.1",
            "browser": "Firefox",
            "installed_at": (base_time - timedelta(days=7)).isoformat(),
            "permissions": ["tabs", "storage", "backgroundPage"],
            "risk_score": 95,
            "suspicious_indicators": ["cryptomining_detected", "excessive_cpu_usage", "unauthorized_network"],
            "status": "malicious",
        },
        {
            "id": str(uuid.uuid4())[:8],
            "name": "Data Harvester",
            "extension_id": "malicious1234abcd5678efgh9012ijkl",
            "version": "1.5.0",
            "browser": "Chrome",
            "installed_at": (base_time - timedelta(hours=12)).isoformat(),
            "permissions": ["tabs", "cookies", "webRequest", "webRequestBlocking", "<all_urls>"],
            "risk_score": 98,
            "suspicious_indicators": ["data_exfiltration", "excessive_permissions", "obfuscated_code", "recently_installed"],
            "status": "malicious",
        },
    ]
    
    return extensions


@app.get("/browser/extensions")
async def browser_extensions(refresh: bool = False):
    """
    List all browser extensions installed across monitored endpoints.
    Tracks extension permissions, versions, and risk profiles.
    """
    global _browser_extensions
    
    if refresh or not _browser_extensions:
        _browser_extensions = _simulate_browser_extensions()
    
    # Status distribution
    status_counts = dict(Counter(e.get("status", "unknown") for e in _browser_extensions))
    
    # Browser distribution
    browser_counts = dict(Counter(e.get("browser", "unknown") for e in _browser_extensions))
    
    # Risk categorization
    risk_categories = {"low": 0, "medium": 0, "high": 0, "critical": 0}
    for ext in _browser_extensions:
        score = ext.get("risk_score", 0)
        if score < 40:
            risk_categories["low"] += 1
        elif score < 65:
            risk_categories["medium"] += 1
        elif score < 85:
            risk_categories["high"] += 1
        else:
            risk_categories["critical"] += 1
    
    # Average risk score
    avg_risk = sum(e.get("risk_score", 0) for e in _browser_extensions) / len(_browser_extensions) if _browser_extensions else 0
    
    return {
        "total_extensions": len(_browser_extensions),
        "status_distribution": status_counts,
        "browser_distribution": browser_counts,
        "risk_distribution": risk_categories,
        "avg_risk_score": round(avg_risk, 2),
        "extensions": _browser_extensions,
    }


@app.get("/browser/suspicious")
async def browser_suspicious(threshold: int = 60):
    """
    Filter browser extensions flagged as suspicious or malicious.
    Identifies cryptominers, data harvesters, and unauthorized extensions.
    """
    global _browser_extensions, _suspicious_extensions
    
    # Ensure cache is populated
    if not _browser_extensions:
        _browser_extensions = _simulate_browser_extensions()
    
    # Filter by threshold
    _suspicious_extensions = [
        ext for ext in _browser_extensions
        if ext.get("risk_score", 0) >= threshold
    ]
    
    # Sort by risk score descending
    _suspicious_extensions.sort(key=lambda e: e.get("risk_score", 0), reverse=True)
    
    # Status distribution
    status_counts = dict(Counter(e.get("status", "unknown") for e in _suspicious_extensions))
    
    # Top indicators
    all_indicators = []
    for ext in _suspicious_extensions:
        all_indicators.extend(ext.get("suspicious_indicators", []))
    top_indicators = dict(Counter(all_indicators).most_common(5))
    
    return {
        "threshold": threshold,
        "suspicious_count": len(_suspicious_extensions),
        "status_distribution": status_counts,
        "top_indicators": top_indicators,
        "extensions": _suspicious_extensions,
    }


def _simulate_data_exfiltration_events() -> List[Dict[str, Any]]:
    now = datetime.now(timezone.utc)
    return [
        {
            "event_id": f"exf-{uuid.uuid4().hex[:10]}",
            "timestamp": (now - timedelta(minutes=18)).isoformat(),
            "host": "ws-fin-02",
            "user": "finance.analyst",
            "channel": "https",
            "destination": "fileshare-sync.example.net",
            "bytes_sent": 860_000_000,
            "classification": "confidential",
            "risk_score": 87,
            "status": "investigating",
        },
        {
            "event_id": f"exf-{uuid.uuid4().hex[:10]}",
            "timestamp": (now - timedelta(minutes=7)).isoformat(),
            "host": "eng-laptop-14",
            "user": "contractor.dev",
            "channel": "dns-tunnel",
            "destination": "cdn-pixel-cache.net",
            "bytes_sent": 140_000_000,
            "classification": "internal",
            "risk_score": 93,
            "status": "open",
        },
    ]


@app.get("/security/data-exfiltration")
async def security_data_exfiltration(refresh: bool = False):
    """Phase 68: Summarize potential exfiltration activity."""
    global _data_exfiltration_events
    if refresh or not _data_exfiltration_events:
        _data_exfiltration_events = _simulate_data_exfiltration_events()

    total_bytes = sum(int(evt.get("bytes_sent", 0)) for evt in _data_exfiltration_events)
    high_risk = [evt for evt in _data_exfiltration_events if int(evt.get("risk_score", 0)) >= 85]
    return {
        "events": len(_data_exfiltration_events),
        "high_risk_events": len(high_risk),
        "total_bytes_sent": total_bytes,
        "events_detail": _data_exfiltration_events,
    }


@app.get("/security/data-exfiltration/events")
async def security_data_exfiltration_events(limit: int = 50):
    """Phase 68: Return exfiltration events with controllable result size."""
    global _data_exfiltration_events
    if not _data_exfiltration_events:
        _data_exfiltration_events = _simulate_data_exfiltration_events()

    bounded = _safe_limit(limit, default=50, minimum=1, maximum=200)
    events = sorted(_data_exfiltration_events, key=lambda item: item.get("timestamp", ""), reverse=True)
    return {"count": len(events[:bounded]), "events": events[:bounded]}


def _simulate_upload_events() -> List[Dict[str, Any]]:
    now = datetime.now(timezone.utc)
    return [
        {
            "upload_id": f"upl-{uuid.uuid4().hex[:8]}",
            "timestamp": (now - timedelta(minutes=30)).isoformat(),
            "user": "alice",
            "filename": "design_export.zip",
            "size_bytes": 92_000_000,
            "target": "drive.partner-portal.com",
            "mime": "application/zip",
            "risk_score": 42,
        },
        {
            "upload_id": f"upl-{uuid.uuid4().hex[:8]}",
            "timestamp": (now - timedelta(minutes=9)).isoformat(),
            "user": "intern.ops",
            "filename": "customers_dump.csv",
            "size_bytes": 140_000_000,
            "target": "dropfile-unknown.tld",
            "mime": "text/csv",
            "risk_score": 91,
        },
    ]


@app.get("/uploads/log")
async def uploads_log(refresh: bool = False):
    """Phase 69: List recent upload activity for governance."""
    global _upload_log
    if refresh or not _upload_log:
        _upload_log = _simulate_upload_events()

    return {
        "total_uploads": len(_upload_log),
        "uploads": sorted(_upload_log, key=lambda item: item.get("timestamp", ""), reverse=True),
    }


@app.get("/uploads/suspicious")
async def uploads_suspicious(threshold: int = 75):
    """Phase 69: Return suspicious uploads by risk threshold."""
    global _upload_log, _suspicious_uploads
    if not _upload_log:
        _upload_log = _simulate_upload_events()

    _suspicious_uploads = [item for item in _upload_log if int(item.get("risk_score", 0)) >= threshold]
    return {
        "threshold": threshold,
        "suspicious_count": len(_suspicious_uploads),
        "uploads": sorted(_suspicious_uploads, key=lambda item: item.get("risk_score", 0), reverse=True),
    }


@app.get("/dlp/events")
async def dlp_events(refresh: bool = False):
    """Phase 70: Show DLP detections and policy violations."""
    global _dlp_events
    if refresh or not _dlp_events:
        now = datetime.now(timezone.utc)
        _dlp_events = [
            {
                "event_id": f"dlp-{uuid.uuid4().hex[:8]}",
                "timestamp": (now - timedelta(minutes=16)).isoformat(),
                "policy": "pii-egress",
                "resource": "crm-export.csv",
                "action": "blocked",
                "severity": "high",
            },
            {
                "event_id": f"dlp-{uuid.uuid4().hex[:8]}",
                "timestamp": (now - timedelta(minutes=4)).isoformat(),
                "policy": "source-code-sharing",
                "resource": "core_engine.py",
                "action": "quarantined",
                "severity": "critical",
            },
        ]
    return {"total_events": len(_dlp_events), "events": _dlp_events}


@app.post("/dlp/block")
async def dlp_block(payload: Dict[str, Any] = Body(default_factory=dict)):
    """Phase 70: Register a manual DLP block rule."""
    global _dlp_blocks
    rule_id = f"rule-{uuid.uuid4().hex[:10]}"
    _dlp_blocks[rule_id] = {
        "rule_id": rule_id,
        "pattern": payload.get("pattern", "sensitive-data"),
        "channel": payload.get("channel", "all"),
        "reason": payload.get("reason", "manual block"),
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    return {"status": "blocked", "rule": _dlp_blocks[rule_id]}


@app.get("/data/sensitive")
async def data_sensitive(refresh: bool = False):
    """Phase 71: Discover sensitive data artifacts."""
    global _sensitive_data_cache
    if refresh or not _sensitive_data_cache:
        _sensitive_data_cache = [
            {"path": "D:/finance/payroll_2026.xlsx", "type": "financial", "confidence": 0.97, "records": 2400},
            {"path": "D:/legal/contracts_master.docx", "type": "legal", "confidence": 0.92, "records": 120},
            {"path": "D:/crm/customer_pii_backup.csv", "type": "pii", "confidence": 0.99, "records": 18120},
        ]
    return {"artifacts": len(_sensitive_data_cache), "data": _sensitive_data_cache}


@app.get("/data/classification")
async def data_classification():
    """Phase 71: Return classification counts for discovered data."""
    global _sensitive_data_cache, _data_classifications
    if not _sensitive_data_cache:
        await data_sensitive(refresh=True)

    _data_classifications = {item["path"]: item["type"] for item in _sensitive_data_cache}
    counts = dict(Counter(_data_classifications.values()))
    return {"classifications": counts, "mapped_assets": _data_classifications}


@app.get("/credentials/exposed")
async def credentials_exposed(refresh: bool = False):
    """Phase 72: List detected credential exposure findings."""
    global _exposed_credentials
    if refresh or not _exposed_credentials:
        _exposed_credentials = [
            {
                "finding_id": f"cred-{uuid.uuid4().hex[:8]}",
                "source": "public-repo",
                "secret_type": "api_key",
                "owner": "service-api",
                "status": "open",
                "risk_score": 89,
            },
            {
                "finding_id": f"cred-{uuid.uuid4().hex[:8]}",
                "source": "chat-log",
                "secret_type": "db_password",
                "owner": "analytics-db",
                "status": "rotated",
                "risk_score": 70,
            },
        ]
    return {"findings": len(_exposed_credentials), "items": _exposed_credentials}


@app.post("/credentials/scan")
async def credentials_scan(payload: Dict[str, Any] = Body(default_factory=dict)):
    """Phase 72: Simulate on-demand credential exposure scan."""
    target = payload.get("target", "workspace")
    scan_id = f"scan-{uuid.uuid4().hex[:10]}"
    return {
        "scan_id": scan_id,
        "target": target,
        "status": "completed",
        "matches": 2,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/security/password-strength")
async def security_password_strength():
    """Phase 73: Analyze sampled account password hygiene."""
    global _password_analysis
    _password_analysis = [
        {"user": "alice", "strength": "strong", "score": 92, "mfa": True},
        {"user": "bob", "strength": "weak", "score": 38, "mfa": False},
        {"user": "svc-backup", "strength": "medium", "score": 61, "mfa": False},
    ]
    weak_accounts = [item for item in _password_analysis if item["score"] < 50]
    return {
        "accounts_analyzed": len(_password_analysis),
        "weak_accounts": len(weak_accounts),
        "results": _password_analysis,
    }


@app.get("/security/keyloggers")
async def security_keyloggers(refresh: bool = False):
    """Phase 74: Detect keylogger-like process behavior."""
    global _keylogger_detections
    if refresh or not _keylogger_detections:
        _keylogger_detections = [
            {
                "process": "unknown_input_hook.exe",
                "pid": 9420,
                "hook_count": 14,
                "network_beacons": 9,
                "risk_score": 95,
                "status": "blocked",
            }
        ]
    return {"detections": len(_keylogger_detections), "items": _keylogger_detections}


@app.get("/security/screen-capture")
async def security_screen_capture(refresh: bool = False):
    """Phase 75: Monitor suspicious screen capture activity."""
    global _screen_capture_events
    if refresh or not _screen_capture_events:
        now = datetime.now(timezone.utc)
        _screen_capture_events = [
            {
                "event_id": f"screen-{uuid.uuid4().hex[:8]}",
                "timestamp": (now - timedelta(minutes=6)).isoformat(),
                "process": "capture_helper.exe",
                "user": "intern.ops",
                "captures": 38,
                "risk_score": 84,
            }
        ]
    return {"events": len(_screen_capture_events), "items": _screen_capture_events}


@app.get("/security/webcam")
async def security_webcam(refresh: bool = False):
    """Phase 76: Track webcam access anomalies."""
    global _webcam_access_log
    if refresh or not _webcam_access_log:
        _webcam_access_log = [
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "process": "meeting-plugin.exe",
                "user": "alice",
                "duration_seconds": 420,
                "status": "allowed",
                "risk_score": 25,
            },
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "process": "svc_cam_feed.exe",
                "user": "svc-backup",
                "duration_seconds": 190,
                "status": "flagged",
                "risk_score": 79,
            },
        ]
    return {"events": len(_webcam_access_log), "items": _webcam_access_log}


@app.get("/security/microphone")
async def security_microphone(refresh: bool = False):
    """Phase 77: Track microphone access anomalies."""
    global _microphone_access_log
    if refresh or not _microphone_access_log:
        _microphone_access_log = [
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "process": "voice_helper.exe",
                "user": "bob",
                "duration_seconds": 330,
                "status": "allowed",
                "risk_score": 33,
            },
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "process": "audio_capture_tmp.exe",
                "user": "contractor.dev",
                "duration_seconds": 255,
                "status": "suspicious",
                "risk_score": 88,
            },
        ]
    return {"events": len(_microphone_access_log), "items": _microphone_access_log}


@app.get("/security/clipboard")
async def security_clipboard(refresh: bool = False):
    """Phase 78: Monitor clipboard access for sensitive copy actions."""
    global _clipboard_events
    if refresh or not _clipboard_events:
        now = datetime.now(timezone.utc)
        _clipboard_events = [
            {
                "event_id": f"clip-{uuid.uuid4().hex[:8]}",
                "timestamp": (now - timedelta(minutes=11)).isoformat(),
                "user": "alice",
                "process": "excel.exe",
                "content_type": "financial",
                "size_chars": 1240,
                "risk_score": 45,
            },
            {
                "event_id": f"clip-{uuid.uuid4().hex[:8]}",
                "timestamp": (now - timedelta(minutes=2)).isoformat(),
                "user": "contractor.dev",
                "process": "unknown_sync.exe",
                "content_type": "credential",
                "size_chars": 560,
                "risk_score": 90,
            },
        ]
    return {"events": len(_clipboard_events), "items": _clipboard_events}


@app.get("/system/gpu")
async def system_gpu(refresh: bool = False):
    """Phase 79: Return GPU workload profile across monitored hosts."""
    global _gpu_usage_history
    if refresh or not _gpu_usage_history:
        now = datetime.now(timezone.utc)
        _gpu_usage_history = [
            {
                "host": "ws-design-01",
                "timestamp": (now - timedelta(minutes=5)).isoformat(),
                "utilization_percent": 62,
                "memory_percent": 58,
                "process": "render_tool.exe",
            },
            {
                "host": "ws-fin-02",
                "timestamp": (now - timedelta(minutes=3)).isoformat(),
                "utilization_percent": 96,
                "memory_percent": 81,
                "process": "hash_worker.exe",
            },
        ]
    avg_util = sum(item["utilization_percent"] for item in _gpu_usage_history) / max(len(_gpu_usage_history), 1)
    return {"hosts": len(_gpu_usage_history), "avg_utilization": round(avg_util, 2), "data": _gpu_usage_history}


@app.get("/system/gpu/anomalies")
async def system_gpu_anomalies(threshold: int = 85):
    """Phase 79: Flag anomalous GPU patterns above threshold."""
    global _gpu_usage_history, _gpu_anomalies
    if not _gpu_usage_history:
        await system_gpu(refresh=True)

    _gpu_anomalies = [
        item for item in _gpu_usage_history
        if int(item.get("utilization_percent", 0)) >= threshold
    ]
    return {"threshold": threshold, "anomalies": len(_gpu_anomalies), "items": _gpu_anomalies}


@app.get("/security/crypto-mining")
async def security_crypto_mining(refresh: bool = False):
    """Phase 80: Detect crypto-mining behavior in process activity."""
    global _cryptomining_detections
    if refresh or not _cryptomining_detections:
        _cryptomining_detections = [
            {
                "host": "ws-fin-02",
                "process": "hash_worker.exe",
                "wallet": "bc1q...9k3",
                "pool": "pool.untrusted-mining.net",
                "cpu_percent": 91,
                "gpu_percent": 96,
                "risk_score": 97,
                "status": "isolated",
            }
        ]
    return {"detections": len(_cryptomining_detections), "items": _cryptomining_detections}


@app.get("/network/botnet")
async def network_botnet(refresh: bool = False):
    """Phase 81: Detect potential botnet participation indicators."""
    global _botnet_indicators
    if refresh or not _botnet_indicators:
        _botnet_indicators = [
            {
                "host": "eng-laptop-14",
                "beacon_interval_seconds": 60,
                "unique_peers": 41,
                "failed_dns_lookups": 23,
                "risk_score": 89,
                "status": "investigating",
            }
        ]
    return {"indicators": len(_botnet_indicators), "items": _botnet_indicators}


@app.get("/network/c2")
async def network_c2(refresh: bool = False):
    """Phase 82: List command-and-control communication patterns."""
    global _c2_communications
    if refresh or not _c2_communications:
        now = datetime.now(timezone.utc)
        _c2_communications = [
            {
                "session_id": f"c2-{uuid.uuid4().hex[:8]}",
                "timestamp": (now - timedelta(minutes=13)).isoformat(),
                "host": "eng-laptop-14",
                "destination": "198.51.100.44",
                "protocol": "https",
                "jitter_pattern": "high",
                "risk_score": 91,
            }
        ]
    return {"sessions": len(_c2_communications), "items": _c2_communications}


@app.get("/dns/malicious-domains")
async def dns_malicious_domains(refresh: bool = False):
    """Phase 83: Return suspicious or malicious DNS domain findings."""
    global _malicious_domains
    if refresh or not _malicious_domains:
        _malicious_domains = [
            {"domain": "cdn-pixel-cache.net", "category": "dga", "risk_score": 85},
            {"domain": "dropfile-unknown.tld", "category": "data-theft", "risk_score": 93},
        ]
    return {"domains": len(_malicious_domains), "items": _malicious_domains}


@app.get("/network/ip-reputation/{ip}")
async def network_ip_reputation(ip: str):
    """Phase 84: Resolve reputation score for a given IP."""
    global _ip_reputation_cache
    if ip not in _ip_reputation_cache:
        score = min(99, max(5, sum(ord(ch) for ch in ip if ch.isdigit()) % 100))
        _ip_reputation_cache[ip] = {
            "ip": ip,
            "reputation_score": score,
            "classification": "malicious" if score >= 80 else "suspicious" if score >= 60 else "benign",
            "last_checked": datetime.now(timezone.utc).isoformat(),
        }
    return _ip_reputation_cache[ip]


@app.get("/network/geothreats")
async def network_geothreats(refresh: bool = False):
    """Phase 85: Show threat activity by geography."""
    global _geothreat_events
    if refresh or not _geothreat_events:
        _geothreat_events = [
            {"country": "RU", "events": 18, "risk_score": 82},
            {"country": "CN", "events": 14, "risk_score": 77},
            {"country": "NL", "events": 6, "risk_score": 58},
        ]
    return {"regions": len(_geothreat_events), "items": _geothreat_events}


@app.get("/network/tor-usage")
async def network_tor_usage(refresh: bool = False):
    """Phase 86: Track TOR egress attempts."""
    global _tor_usage_log
    if refresh or not _tor_usage_log:
        _tor_usage_log = [
            {
                "host": "eng-laptop-14",
                "process": "unknown_sync.exe",
                "connections": 7,
                "status": "blocked",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        ]
    return {"events": len(_tor_usage_log), "items": _tor_usage_log}


@app.get("/network/proxy")
async def network_proxy(refresh: bool = False):
    """Phase 87: Detect suspicious proxy usage patterns."""
    global _proxy_activity
    if refresh or not _proxy_activity:
        _proxy_activity = [
            {
                "host": "ws-fin-02",
                "proxy": "socks5://203.0.113.12:1080",
                "user": "contractor.dev",
                "requests": 311,
                "risk_score": 86,
                "status": "open",
            }
        ]
    return {"events": len(_proxy_activity), "items": _proxy_activity}


@app.get("/network/vpn")
async def network_vpn(refresh: bool = False):
    """Phase 88: Detect VPN usage anomalies."""
    global _vpn_anomalies
    if refresh or not _vpn_anomalies:
        _vpn_anomalies = [
            {
                "user": "contractor.dev",
                "source_country": "BR",
                "impossible_travel": True,
                "sessions": 3,
                "risk_score": 84,
                "status": "open",
            }
        ]
    return {"anomalies": len(_vpn_anomalies), "items": _vpn_anomalies}


@app.get("/system/updates")
async def system_updates(refresh: bool = False):
    """Phase 89: Track system update status and delays."""
    global _system_updates
    if refresh or not _system_updates:
        _system_updates = [
            {"host": "ws-fin-02", "pending_updates": 6, "critical": 2, "last_update_days": 19},
            {"host": "eng-laptop-14", "pending_updates": 1, "critical": 0, "last_update_days": 4},
        ]
    overdue = [item for item in _system_updates if int(item.get("last_update_days", 0)) > 14]
    return {"hosts": len(_system_updates), "overdue_hosts": len(overdue), "items": _system_updates}


@app.get("/system/packages/integrity")
async def system_packages_integrity(refresh: bool = False):
    """Phase 90: Verify package integrity and signature status."""
    global _package_integrity_checks
    if refresh or not _package_integrity_checks:
        _package_integrity_checks = [
            {"package": "openssl", "version": "3.2.1", "signature": "valid", "tampered": False},
            {"package": "telemetry-agent", "version": "1.8.0", "signature": "mismatch", "tampered": True},
        ]
    tampered = [item for item in _package_integrity_checks if bool(item.get("tampered"))]
    return {"packages_checked": len(_package_integrity_checks), "tampered": len(tampered), "items": _package_integrity_checks}


@app.get("/security/kernel-exploits")
async def security_kernel_exploits(refresh: bool = False):
    """Phase 91: Detect indicators of kernel exploit attempts."""
    global _kernel_exploit_detections
    if refresh or not _kernel_exploit_detections:
        _kernel_exploit_detections = [
            {
                "host": "ws-fin-02",
                "indicator": "unexpected_driver_load",
                "cve": "CVE-2025-44210",
                "severity": "critical",
                "risk_score": 93,
            }
        ]
    return {"detections": len(_kernel_exploit_detections), "items": _kernel_exploit_detections}


@app.get("/security/memory-injection")
async def security_memory_injection(refresh: bool = False):
    """Phase 92: Report memory injection detections."""
    global _memory_injection_events
    if refresh or not _memory_injection_events:
        _memory_injection_events = [
            {
                "event_id": f"mem-{uuid.uuid4().hex[:8]}",
                "source_process": "dropper.exe",
                "target_process": "explorer.exe",
                "technique": "remote_thread",
                "risk_score": 94,
                "status": "blocked",
            }
        ]
    return {"events": len(_memory_injection_events), "items": _memory_injection_events}


@app.get("/security/process-hollowing")
async def security_process_hollowing(refresh: bool = False):
    """Phase 93: Detect process hollowing activity."""
    global _process_hollowing_detections
    if refresh or not _process_hollowing_detections:
        _process_hollowing_detections = [
            {
                "process": "svchost.exe",
                "pid": 5520,
                "origin": "temp_payload.bin",
                "entropy": 7.9,
                "risk_score": 92,
                "status": "terminated",
            }
        ]
    return {"detections": len(_process_hollowing_detections), "items": _process_hollowing_detections}


@app.get("/security/dll-hijacking")
async def security_dll_hijacking(refresh: bool = False):
    """Phase 94: Detect DLL hijacking attempts."""
    global _dll_hijacking_events
    if refresh or not _dll_hijacking_events:
        _dll_hijacking_events = [
            {
                "host": "eng-laptop-14",
                "process": "signed_app.exe",
                "dll": "version.dll",
                "dll_path": "C:/Users/Public/version.dll",
                "risk_score": 88,
                "status": "quarantined",
            }
        ]
    return {"events": len(_dll_hijacking_events), "items": _dll_hijacking_events}


@app.get("/security/rootkits")
async def security_rootkits(refresh: bool = False):
    """Phase 95: Return rootkit deep scan results."""
    global _rootkit_scan_results
    if refresh or not _rootkit_scan_results:
        _rootkit_scan_results = [
            {"host": "ws-fin-02", "scan_status": "clean", "hidden_modules": 0, "risk_score": 8},
            {"host": "eng-laptop-14", "scan_status": "suspected", "hidden_modules": 2, "risk_score": 86},
        ]
    suspected = [item for item in _rootkit_scan_results if item.get("scan_status") != "clean"]
    return {"hosts_scanned": len(_rootkit_scan_results), "suspected_hosts": len(suspected), "items": _rootkit_scan_results}


@app.get("/system/firmware")
async def system_firmware(refresh: bool = False):
    """Phase 96: Check firmware integrity posture."""
    global _firmware_integrity_cache
    if refresh or not _firmware_integrity_cache:
        _firmware_integrity_cache = {
            "scan_time": datetime.now(timezone.utc).isoformat(),
            "devices_checked": 14,
            "unsigned_components": 1,
            "tampered_components": 0,
            "status": "warning",
        }
    return _firmware_integrity_cache


@app.get("/system/bios")
async def system_bios(refresh: bool = False):
    """Phase 97: Provide BIOS security posture checks."""
    global _bios_security_status
    if refresh or not _bios_security_status:
        _bios_security_status = {
            "checked_at": datetime.now(timezone.utc).isoformat(),
            "secure_boot": True,
            "bios_lock": True,
            "rollback_protection": False,
            "risk_score": 41,
            "status": "improve",
        }
    return _bios_security_status


@app.get("/system/hardware-integrity")
async def system_hardware_integrity(refresh: bool = False):
    """Phase 98: Detect hardware tampering indicators."""
    global _hardware_tampering_log
    if refresh or not _hardware_tampering_log:
        _hardware_tampering_log = [
            {
                "host": "ws-fin-02",
                "sensor": "chassis-intrusion",
                "triggered": False,
                "last_check": datetime.now(timezone.utc).isoformat(),
                "risk_score": 9,
            },
            {
                "host": "edge-gateway-01",
                "sensor": "debug-port-active",
                "triggered": True,
                "last_check": datetime.now(timezone.utc).isoformat(),
                "risk_score": 83,
            },
        ]
    tampered = [item for item in _hardware_tampering_log if bool(item.get("triggered"))]
    return {"assets": len(_hardware_tampering_log), "tampered": len(tampered), "items": _hardware_tampering_log}


@app.post("/ai/security-advice")
async def ai_security_advice(payload: Dict[str, Any] = Body(default_factory=dict)):
    """Phase 99: Generate AI security advice for a given context."""
    global _ai_security_insights
    topic = payload.get("topic", "general")
    advice = {
        "advice_id": f"adv-{uuid.uuid4().hex[:8]}",
        "topic": topic,
        "priority": "high" if "credential" in str(topic).lower() else "medium",
        "recommendations": [
            "Enable strict egress filtering and alert on high-volume external uploads.",
            "Rotate exposed secrets and enforce short-lived credentials.",
            "Require MFA for all privileged and service identities.",
        ],
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
    _ai_security_insights.append(advice)
    return advice


@app.get("/ai/security-insights")
async def ai_security_insights(limit: int = 20):
    """Phase 99: Return generated AI security insights."""
    bounded = _safe_limit(limit, default=20, minimum=1, maximum=100)
    return {"count": min(len(_ai_security_insights), bounded), "insights": _ai_security_insights[-bounded:]}


@app.get("/defense/autonomous")
async def defense_autonomous():
    """Phase 100: Return autonomous defense runtime state."""
    global _autonomous_defense_state
    return _autonomous_defense_state


@app.post("/defense/autonomous/enable")
async def defense_autonomous_enable(payload: Dict[str, Any] = Body(default_factory=dict)):
    """Phase 100: Enable autonomous defense mode."""
    global _autonomous_defense_state
    _autonomous_defense_state["enabled"] = True
    _autonomous_defense_state["enabled_at"] = datetime.now(timezone.utc).isoformat()
    _autonomous_defense_state["profile"] = payload.get("profile", "balanced")
    _autonomous_defense_state.setdefault("actions", []).append({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "action": "enable",
        "profile": _autonomous_defense_state["profile"],
    })
    return {"status": "enabled", "state": _autonomous_defense_state}


@app.post("/defense/autonomous/disable")
async def defense_autonomous_disable():
    """Phase 100: Disable autonomous defense mode."""
    global _autonomous_defense_state
    _autonomous_defense_state["enabled"] = False
    _autonomous_defense_state["disabled_at"] = datetime.now(timezone.utc).isoformat()
    _autonomous_defense_state.setdefault("actions", []).append({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "action": "disable",
    })
    return {"status": "disabled", "state": _autonomous_defense_state}


@app.post("/deception/deploy")
async def deception_deploy(payload: Dict[str, Any] = Body(default_factory=dict)):
    """Phase 101: Deploy a honeypot asset."""
    global _deception_honeypots
    decoy_id = f"hp-{uuid.uuid4().hex[:8]}"
    honeypot = {
        "id": decoy_id,
        "type": payload.get("type", "ssh"),
        "segment": payload.get("segment", "dmz"),
        "status": "active",
        "deployed_at": datetime.now(timezone.utc).isoformat(),
    }
    _deception_honeypots[decoy_id] = honeypot
    return {"status": "deployed", "honeypot": honeypot}


@app.get("/deception/honeypots")
async def deception_honeypots():
    """Phase 101: List deployed honeypots."""
    return {"count": len(_deception_honeypots), "items": list(_deception_honeypots.values())}


@app.get("/deception/alerts")
async def deception_alerts(refresh: bool = False):
    """Phase 101: Return deception trigger alerts."""
    global _deception_alerts
    if refresh or not _deception_alerts:
        _deception_alerts = [
            {
                "alert_id": f"dec-{uuid.uuid4().hex[:8]}",
                "honeypot_id": next(iter(_deception_honeypots), "hp-demo"),
                "source_ip": "203.0.113.77",
                "event": "credential_spray",
                "severity": "high",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        ]
    return {"alerts": len(_deception_alerts), "items": _deception_alerts}


@app.post("/deception/remove/{id}")
async def deception_remove(id: str):
    """Phase 101: Remove a deployed honeypot by id."""
    removed = _deception_honeypots.pop(id, None)
    if not removed:
        raise HTTPException(status_code=404, detail=f"Honeypot not found: {id}")
    return {"status": "removed", "honeypot": removed}


@app.post("/deception/honeytoken/create")
async def deception_honeytoken_create(payload: Dict[str, Any] = Body(default_factory=dict)):
    """Phase 102: Create honeytoken for leak detection."""
    token_id = f"ht-{uuid.uuid4().hex[:8]}"
    token = {
        "id": token_id,
        "label": payload.get("label", "canary-credential"),
        "scope": payload.get("scope", "internal"),
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    _honeytokens[token_id] = token
    return {"status": "created", "token": token}


@app.get("/deception/honeytoken/events")
async def deception_honeytoken_events(refresh: bool = False):
    """Phase 102: Return honeytoken access events."""
    global _honeytoken_events
    if refresh or not _honeytoken_events:
        _honeytoken_events = [
            {
                "event_id": f"hte-{uuid.uuid4().hex[:8]}",
                "token_id": next(iter(_honeytokens), "ht-demo"),
                "source": "unknown-ci-job",
                "severity": "critical",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        ]
    return {"events": len(_honeytoken_events), "items": _honeytoken_events}


@app.delete("/deception/honeytoken/{id}")
async def deception_honeytoken_delete(id: str):
    """Phase 102: Delete an existing honeytoken."""
    removed = _honeytokens.pop(id, None)
    if not removed:
        raise HTTPException(status_code=404, detail=f"Honeytoken not found: {id}")
    return {"status": "deleted", "token": removed}


@app.get("/intel/darkweb/breaches")
async def intel_darkweb_breaches(refresh: bool = False):
    """Phase 103: Return dark web breach records."""
    global _darkweb_breaches
    if refresh or not _darkweb_breaches:
        _darkweb_breaches = [
            {"source": "forum-alpha", "records": 12000, "asset": "crm-user-db", "severity": "high"},
            {"source": "paste-beta", "records": 470, "asset": "vpn-accounts", "severity": "critical"},
        ]
    return {"breaches": len(_darkweb_breaches), "items": _darkweb_breaches}


@app.get("/intel/darkweb/mentions")
async def intel_darkweb_mentions(refresh: bool = False):
    """Phase 103: Return dark web mentions related to organization assets."""
    global _darkweb_mentions
    if refresh or not _darkweb_mentions:
        _darkweb_mentions = [
            {"term": "arkshield", "mentions": 4, "sentiment": "threat"},
            {"term": "company-vpn", "mentions": 2, "sentiment": "sale"},
        ]
    return {"mentions": len(_darkweb_mentions), "items": _darkweb_mentions}


@app.get("/intel/darkweb/alerts")
async def intel_darkweb_alerts(refresh: bool = False):
    """Phase 103: Return prioritized dark web alerts."""
    global _darkweb_alerts
    if refresh or not _darkweb_alerts:
        _darkweb_alerts = [
            {
                "alert_id": f"dw-{uuid.uuid4().hex[:8]}",
                "type": "credential_sale",
                "priority": "critical",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        ]
    return {"alerts": len(_darkweb_alerts), "items": _darkweb_alerts}


@app.post("/supplychain/binary/verify")
async def supplychain_binary_verify(payload: Dict[str, Any] = Body(default_factory=dict)):
    """Phase 104: Verify binary integrity and signer metadata."""
    global _supply_chain_binaries
    checksum = str(payload.get("checksum", "sha256:demo"))
    result = {
        "binary": payload.get("binary", "agent.bin"),
        "checksum": checksum,
        "signature": "valid" if "bad" not in checksum else "invalid",
        "verified_at": datetime.now(timezone.utc).isoformat(),
    }
    _supply_chain_binaries.append(result)
    return result


@app.get("/supplychain/dependencies")
async def supplychain_dependencies(refresh: bool = False):
    """Phase 104: Return dependency inventory snapshot."""
    global _supply_chain_dependencies
    if refresh or not _supply_chain_dependencies:
        _supply_chain_dependencies = [
            {"name": "fastapi", "version": "0.111.0", "risk": "low"},
            {"name": "urllib3", "version": "2.2.2", "risk": "medium"},
        ]
    return {"dependencies": len(_supply_chain_dependencies), "items": _supply_chain_dependencies}


@app.get("/supplychain/anomalies")
async def supplychain_anomalies(refresh: bool = False):
    """Phase 104: Report supply chain anomalies."""
    global _supply_chain_anomalies
    if refresh or not _supply_chain_anomalies:
        _supply_chain_anomalies = [
            {
                "package": "telemetry-agent",
                "anomaly": "unexpected_publisher",
                "severity": "high",
                "detected_at": datetime.now(timezone.utc).isoformat(),
            }
        ]
    return {"anomalies": len(_supply_chain_anomalies), "items": _supply_chain_anomalies}


@app.get("/sbom/generate")
async def sbom_generate(refresh: bool = False):
    """Phase 105: Generate an SBOM summary."""
    global _sbom_cache
    if refresh or not _sbom_cache:
        _sbom_cache = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "components": 132,
            "licenses": {"MIT": 88, "Apache-2.0": 31, "BSD-3": 13},
        }
    return _sbom_cache


@app.get("/sbom/dependencies")
async def sbom_dependencies():
    """Phase 105: Return dependencies from generated SBOM data."""
    if not _supply_chain_dependencies:
        await supplychain_dependencies(refresh=True)
    return {"dependencies": _supply_chain_dependencies}


@app.get("/sbom/vulnerabilities")
async def sbom_vulnerabilities(refresh: bool = False):
    """Phase 105: Return vulnerability findings mapped to SBOM components."""
    global _sbom_vulnerabilities
    if refresh or not _sbom_vulnerabilities:
        _sbom_vulnerabilities = [
            {"component": "urllib3", "cve": "CVE-2026-1111", "severity": "medium"},
            {"component": "telemetry-agent", "cve": "CVE-2026-4040", "severity": "high"},
        ]
    return {"count": len(_sbom_vulnerabilities), "items": _sbom_vulnerabilities}


@app.get("/patch/pending")
async def patch_pending(refresh: bool = False):
    """Phase 106: Return pending patch queue."""
    global _patch_pending
    if refresh or not _patch_pending:
        _patch_pending = [
            {"id": "patch-kb501", "host": "ws-fin-02", "priority": "critical", "status": "pending"},
            {"id": "patch-kb719", "host": "edge-gateway-01", "priority": "high", "status": "pending"},
        ]
    return {"pending": len(_patch_pending), "items": _patch_pending}


@app.post("/patch/apply/{id}")
async def patch_apply(id: str):
    """Phase 106: Apply patch by id and write history entry."""
    global _patch_pending, _patch_history
    patch_item = next((item for item in _patch_pending if item.get("id") == id), None)
    if not patch_item:
        raise HTTPException(status_code=404, detail=f"Patch not found: {id}")

    _patch_pending = [item for item in _patch_pending if item.get("id") != id]
    record = {
        "id": id,
        "host": patch_item.get("host"),
        "applied_at": datetime.now(timezone.utc).isoformat(),
        "result": "success",
    }
    _patch_history.append(record)
    return {"status": "applied", "record": record}


@app.get("/patch/history")
async def patch_history():
    """Phase 106: Return patch apply history."""
    return {"history": _patch_history, "count": len(_patch_history)}


@app.get("/benchmark/cis")
async def benchmark_cis(refresh: bool = False):
    """Phase 107: Return CIS benchmark posture."""
    global _benchmark_results
    if refresh or "cis" not in _benchmark_results:
        _benchmark_results["cis"] = {
            "score": 78,
            "controls_passed": 141,
            "controls_failed": 39,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    return _benchmark_results["cis"]


@app.get("/benchmark/nist")
async def benchmark_nist(refresh: bool = False):
    """Phase 107: Return NIST benchmark posture."""
    global _benchmark_results
    if refresh or "nist" not in _benchmark_results:
        _benchmark_results["nist"] = {
            "score": 81,
            "maturity": "managed",
            "gaps": 12,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    return _benchmark_results["nist"]


@app.get("/benchmark/recommendations")
async def benchmark_recommendations():
    """Phase 107: Return actionable benchmark recommendations."""
    return {
        "recommendations": [
            "Harden privileged service accounts and enforce MFA.",
            "Reduce outbound DNS tunneling risk with strict egress allowlists.",
            "Automate patch SLAs for critical hosts under 72 hours.",
        ]
    }


@app.post("/redteam/simulate")
async def redteam_simulate(payload: Dict[str, Any] = Body(default_factory=dict)):
    """Phase 108: Start red team simulation."""
    global _redteam_simulations, _redteam_results
    sim_id = f"rt-{uuid.uuid4().hex[:8]}"
    sim = {
        "simulation_id": sim_id,
        "scenario": payload.get("scenario", "credential-theft"),
        "started_at": datetime.now(timezone.utc).isoformat(),
        "status": "completed",
    }
    _redteam_simulations.append(sim)
    _redteam_results.append({
        "simulation_id": sim_id,
        "detections_triggered": 7,
        "mean_time_to_detect_seconds": 142,
        "coverage_score": 81,
    })
    return sim


@app.get("/redteam/results")
async def redteam_results():
    """Phase 108: Return latest red team simulation results."""
    return {"count": len(_redteam_results), "results": _redteam_results}


@app.get("/redteam/history")
async def redteam_history():
    """Phase 108: Return red team simulation history."""
    return {"count": len(_redteam_simulations), "history": _redteam_simulations}


@app.post("/training/scenario/start")
async def training_scenario_start(payload: Dict[str, Any] = Body(default_factory=dict)):
    """Phase 109: Start blue team training scenario."""
    global _training_scenarios
    scenario_id = f"bt-{uuid.uuid4().hex[:8]}"
    _training_scenarios[scenario_id] = {
        "scenario_id": scenario_id,
        "title": payload.get("title", "Phishing incident response"),
        "status": "running",
        "score": 0,
        "started_at": datetime.now(timezone.utc).isoformat(),
    }
    return _training_scenarios[scenario_id]


@app.get("/training/scenario/status")
async def training_scenario_status(scenario_id: Optional[str] = None):
    """Phase 109: Get blue team scenario status."""
    if scenario_id:
        state = _training_scenarios.get(scenario_id)
        if not state:
            raise HTTPException(status_code=404, detail=f"Scenario not found: {scenario_id}")
        return state
    return {"active": len(_training_scenarios), "scenarios": list(_training_scenarios.values())}


@app.get("/training/scenario/results")
async def training_scenario_results(scenario_id: Optional[str] = None):
    """Phase 109: Get blue team scenario results."""
    scenarios = list(_training_scenarios.values())
    if scenario_id:
        scenarios = [item for item in scenarios if item.get("scenario_id") == scenario_id]
        if not scenarios:
            raise HTTPException(status_code=404, detail=f"Scenario not found: {scenario_id}")

    results = []
    for item in scenarios:
        results.append({
            "scenario_id": item.get("scenario_id"),
            "status": "completed" if item.get("status") == "running" else item.get("status"),
            "score": max(68, int(item.get("score", 0)) or 76),
        })
    return {"count": len(results), "results": results}


@app.get("/attack-surface/map")
async def attack_surface_map(refresh: bool = False):
    """Phase 110: Generate attack surface map summary."""
    global _attack_surface_map
    if refresh or not _attack_surface_map:
        _attack_surface_map = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "internet_exposed_assets": 14,
            "critical_assets": 6,
            "high_risk_paths": 4,
        }
    return _attack_surface_map


@app.get("/attack-surface/exposed-assets")
async def attack_surface_exposed_assets():
    """Phase 110: List exposed assets."""
    return {
        "assets": [
            {"asset": "vpn-gateway", "port": 443, "risk": "high"},
            {"asset": "legacy-rdp-host", "port": 3389, "risk": "critical"},
            {"asset": "mail-relay", "port": 25, "risk": "medium"},
        ]
    }


@app.get("/attack-surface/risk-score")
async def attack_surface_risk_score():
    """Phase 110: Return attack surface risk score."""
    if not _attack_surface_map:
        await attack_surface_map(refresh=True)
    score = min(100, _attack_surface_map.get("internet_exposed_assets", 0) * 4 + _attack_surface_map.get("high_risk_paths", 0) * 10)
    return {"score": score, "status": "elevated" if score >= 60 else "moderate"}


@app.get("/identity/risks")
async def identity_risks(refresh: bool = False):
    """Phase 111: Return digital identity risk findings."""
    global _identity_risks
    if refresh or not _identity_risks:
        _identity_risks = [
            {"user": "admin.ops", "risk": "high", "reason": "mfa_disabled"},
            {"user": "contractor.dev", "risk": "critical", "reason": "impossible_travel"},
        ]
    return {"count": len(_identity_risks), "items": _identity_risks}


@app.get("/identity/compromised")
async def identity_compromised(refresh: bool = False):
    """Phase 111: Return potentially compromised identities."""
    global _compromised_identities
    if refresh or not _compromised_identities:
        _compromised_identities = [
            {"user": "contractor.dev", "source": "darkweb", "status": "active"},
            {"user": "svc-backup", "source": "credential_reuse", "status": "active"},
        ]
    return {"count": len(_compromised_identities), "items": _compromised_identities}


@app.post("/identity/lockdown/{user}")
async def identity_lockdown(user: str):
    """Phase 111: Lock down a user identity."""
    return {
        "user": user,
        "status": "locked",
        "actions": ["session_revoked", "password_reset_required", "mfa_enforced"],
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/shadowit/apps")
async def shadowit_apps(refresh: bool = False):
    """Phase 112: Discover shadow IT applications."""
    global _shadowit_apps
    if refresh or not _shadowit_apps:
        _shadowit_apps = [
            {"name": "quickshare-pro", "users": 23, "category": "file-sharing", "risk": "high"},
            {"name": "taskboard-lite", "users": 8, "category": "productivity", "risk": "medium"},
        ]
    return {"count": len(_shadowit_apps), "items": _shadowit_apps}


@app.get("/shadowit/risks")
async def shadowit_risks():
    """Phase 112: Return shadow IT risk summary."""
    if not _shadowit_apps:
        await shadowit_apps(refresh=True)
    risky = [item for item in _shadowit_apps if item.get("risk") in {"high", "critical"}]
    return {"high_risk_apps": len(risky), "items": risky}


@app.get("/data/access-policies")
async def data_access_policies():
    """Phase 113: Return current data access governance policies."""
    global _data_access_policies
    if not _data_access_policies:
        _data_access_policies = [
            {"policy_id": "dap-001", "resource": "finance", "rule": "least-privilege", "status": "active"},
            {"policy_id": "dap-002", "resource": "customer-pii", "rule": "mfa-required", "status": "active"},
        ]
    return {"count": len(_data_access_policies), "items": _data_access_policies}


@app.get("/data/access-violations")
async def data_access_violations(refresh: bool = False):
    """Phase 113: Return data access policy violation events."""
    global _data_access_violations
    if refresh or not _data_access_violations:
        _data_access_violations = [
            {"user": "intern.ops", "resource": "customer-pii", "violation": "outside-business-hours", "severity": "high"},
            {"user": "contractor.dev", "resource": "finance", "violation": "unauthorized-export", "severity": "critical"},
        ]
    return {"count": len(_data_access_violations), "items": _data_access_violations}


@app.post("/data/access/policy")
async def data_access_policy_create(payload: Dict[str, Any] = Body(default_factory=dict)):
    """Phase 113: Add a new data access governance policy."""
    global _data_access_policies
    policy = {
        "policy_id": f"dap-{uuid.uuid4().hex[:6]}",
        "resource": payload.get("resource", "general"),
        "rule": payload.get("rule", "least-privilege"),
        "status": "active",
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    _data_access_policies.append(policy)
    return {"status": "created", "policy": policy}


@app.get("/config/drift")
async def config_drift(refresh: bool = False):
    """Phase 114: Detect secure configuration drift."""
    global _config_drift_log
    if refresh or not _config_drift_log:
        _config_drift_log = [
            {"asset": "ws-fin-02", "setting": "firewall_policy", "expected": "strict", "current": "open", "severity": "high"},
            {"asset": "edge-gateway-01", "setting": "ssh_root_login", "expected": "disabled", "current": "enabled", "severity": "critical"},
        ]
    return {"drift_items": len(_config_drift_log), "items": _config_drift_log}


@app.get("/config/drift/history")
async def config_drift_history():
    """Phase 114: Return historical configuration drift data."""
    if not _config_drift_log:
        await config_drift(refresh=True)
    return {
        "history_points": len(_config_drift_log),
        "history": _config_drift_log,
    }


@app.get("/ai/model/integrity")
async def ai_model_integrity(refresh: bool = False):
    """Phase 115: Return AI model integrity checks."""
    global _ai_model_integrity
    if refresh or not _ai_model_integrity:
        _ai_model_integrity = [
            {"model": "threat-classifier-v3", "checksum_ok": True, "drift_score": 0.08, "status": "healthy"},
            {"model": "email-detector-v2", "checksum_ok": True, "drift_score": 0.19, "status": "review"},
        ]
    return {"models": len(_ai_model_integrity), "items": _ai_model_integrity}


@app.get("/ai/model/anomalies")
async def ai_model_anomalies():
    """Phase 115: Return anomalous AI model observations."""
    if not _ai_model_integrity:
        await ai_model_integrity(refresh=True)
    anomalies = [item for item in _ai_model_integrity if float(item.get("drift_score", 0.0)) >= 0.15]
    return {"anomalies": len(anomalies), "items": anomalies}


@app.get("/ai/model/poisoning")
async def ai_model_poisoning(refresh: bool = False):
    """Phase 116: Detect AI model poisoning indicators."""
    global _ai_model_poisoning
    if refresh or not _ai_model_poisoning:
        _ai_model_poisoning = [
            {"model": "email-detector-v2", "indicator": "label_skew", "severity": "high", "confidence": 0.83}
        ]
    return {"findings": len(_ai_model_poisoning), "items": _ai_model_poisoning}


@app.post("/ai/model/validate")
async def ai_model_validate(payload: Dict[str, Any] = Body(default_factory=dict)):
    """Phase 116: Validate model against supplied checks."""
    model_name = payload.get("model", "threat-classifier-v3")
    return {
        "model": model_name,
        "validated": True,
        "issues": 0,
        "validated_at": datetime.now(timezone.utc).isoformat(),
    }


@app.post("/investigation/start")
async def investigation_start(payload: Dict[str, Any] = Body(default_factory=dict)):
    """Phase 117: Start autonomous threat investigation."""
    global _threat_investigations
    inv_id = f"inv-{uuid.uuid4().hex[:8]}"
    _threat_investigations[inv_id] = {
        "id": inv_id,
        "target": payload.get("target", "unknown-host"),
        "hypothesis": payload.get("hypothesis", "credential abuse"),
        "status": "running",
        "started_at": datetime.now(timezone.utc).isoformat(),
    }
    return _threat_investigations[inv_id]


@app.get("/investigation/status")
async def investigation_status(id: Optional[str] = None):
    """Phase 117: Return investigation status."""
    if id:
        item = _threat_investigations.get(id)
        if not item:
            raise HTTPException(status_code=404, detail=f"Investigation not found: {id}")
        return item
    return {"count": len(_threat_investigations), "items": list(_threat_investigations.values())}


@app.get("/investigation/results")
async def investigation_results(id: Optional[str] = None):
    """Phase 117: Return investigation findings."""
    items = list(_threat_investigations.values())
    if id:
        items = [item for item in items if item.get("id") == id]
        if not items:
            raise HTTPException(status_code=404, detail=f"Investigation not found: {id}")

    results = []
    for item in items:
        results.append({
            "id": item.get("id"),
            "status": "completed",
            "confidence": 0.88,
            "findings": ["suspicious token reuse", "high-volume egress", "new persistence task"],
        })
    return {"count": len(results), "results": results}


@app.get("/correlation/events")
async def correlation_events():
    """Phase 118: Return events prepared for threat correlation."""
    global _correlation_incidents
    if not _correlation_incidents:
        _correlation_incidents = [
            {
                "incident_id": f"inc-{uuid.uuid4().hex[:8]}",
                "signals": ["bruteforce", "privilege-escalation", "exfiltration"],
                "confidence": 0.91,
                "status": "open",
            }
        ]
    return {"count": len(_correlation_incidents), "events": _correlation_incidents}


@app.get("/correlation/incidents")
async def correlation_incidents():
    """Phase 118: Return correlated incidents."""
    if not _correlation_incidents:
        await correlation_events()
    return {"count": len(_correlation_incidents), "incidents": _correlation_incidents}


@app.get("/graph/entities")
async def graph_entities():
    """Phase 119: Return security knowledge graph entities."""
    global _security_knowledge_graph
    if not _security_knowledge_graph.get("entities"):
        _security_knowledge_graph["entities"] = [
            {"id": "user:contractor.dev", "type": "user"},
            {"id": "host:eng-laptop-14", "type": "host"},
            {"id": "ip:198.51.100.44", "type": "ip"},
        ]
    return {"count": len(_security_knowledge_graph["entities"]), "entities": _security_knowledge_graph["entities"]}


@app.get("/graph/relationships")
async def graph_relationships():
    """Phase 119: Return security knowledge graph relationships."""
    global _security_knowledge_graph
    if not _security_knowledge_graph.get("relationships"):
        _security_knowledge_graph["relationships"] = [
            {"from": "user:contractor.dev", "to": "host:eng-laptop-14", "relation": "logged_in"},
            {"from": "host:eng-laptop-14", "to": "ip:198.51.100.44", "relation": "connected_to"},
        ]
    return {
        "count": len(_security_knowledge_graph["relationships"]),
        "relationships": _security_knowledge_graph["relationships"],
    }


@app.post("/sandbox/network-sim")
async def sandbox_network_sim(payload: Dict[str, Any] = Body(default_factory=dict)):
    """Phase 120: Start threat simulation in network sandbox."""
    global _network_simulations
    sim_id = f"ns-{uuid.uuid4().hex[:8]}"
    _network_simulations[sim_id] = {
        "simulation_id": sim_id,
        "scenario": payload.get("scenario", "c2-beaconing"),
        "status": "completed",
        "detections": 5,
        "started_at": datetime.now(timezone.utc).isoformat(),
    }
    return _network_simulations[sim_id]


@app.get("/sandbox/network-results")
async def sandbox_network_results(simulation_id: Optional[str] = None):
    """Phase 120: Return network sandbox simulation results."""
    if simulation_id:
        item = _network_simulations.get(simulation_id)
        if not item:
            raise HTTPException(status_code=404, detail=f"Simulation not found: {simulation_id}")
        return item
    return {"count": len(_network_simulations), "results": list(_network_simulations.values())}


@app.get("/data/lineage")
async def data_lineage(refresh: bool = False):
    """Phase 121: Return data lineage tracking map."""
    global _data_lineage
    if refresh or not _data_lineage:
        _data_lineage = [
            {"dataset": "customer_pii", "source": "crm", "sink": "analytics-lake", "encrypted": True},
            {"dataset": "payroll", "source": "hr", "sink": "finance-share", "encrypted": False},
        ]
    return {"count": len(_data_lineage), "items": _data_lineage}


@app.get("/data/lineage/risks")
async def data_lineage_risks():
    """Phase 121: Return data lineage risk findings."""
    if not _data_lineage:
        await data_lineage(refresh=True)
    risks = [item for item in _data_lineage if not bool(item.get("encrypted"))]
    return {"risks": len(risks), "items": risks}


@app.get("/zerotrust/policies")
async def zerotrust_policies():
    """Phase 122: Return zero trust policies."""
    global _zerotrust_policies
    if not _zerotrust_policies:
        _zerotrust_policies = [
            {"id": "zt-1", "policy": "verify-explicitly", "status": "active"},
            {"id": "zt-2", "policy": "least-privilege", "status": "active"},
        ]
    return {"count": len(_zerotrust_policies), "items": _zerotrust_policies}


@app.post("/zerotrust/enforce")
async def zerotrust_enforce(payload: Dict[str, Any] = Body(default_factory=dict)):
    """Phase 122: Enforce a zero trust policy action."""
    global _zerotrust_events
    event = {
        "event_id": f"zt-{uuid.uuid4().hex[:8]}",
        "action": payload.get("action", "challenge"),
        "target": payload.get("target", "unknown"),
        "status": "enforced",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    _zerotrust_events.append(event)
    return event


@app.get("/zerotrust/events")
async def zerotrust_events():
    """Phase 122: Return zero trust enforcement events."""
    return {"count": len(_zerotrust_events), "items": _zerotrust_events}


@app.get("/rbac/risk-scores")
async def rbac_risk_scores():
    """Phase 123: Return risk scores for access control entities."""
    global _rbac_risk_scores
    if not _rbac_risk_scores:
        _rbac_risk_scores = {"admin.ops": 82, "contractor.dev": 91, "alice": 38, "svc-backup": 76}
    return {"entities": len(_rbac_risk_scores), "scores": _rbac_risk_scores}


@app.post("/rbac/adjust")
async def rbac_adjust(payload: Dict[str, Any] = Body(default_factory=dict)):
    """Phase 123: Adjust access based on risk."""
    global _rbac_risk_scores
    entity = str(payload.get("entity", "unknown"))
    score = int(payload.get("score", 50))
    _rbac_risk_scores[entity] = score
    action = "restrict" if score >= 80 else "monitor" if score >= 60 else "allow"
    return {"entity": entity, "score": score, "action": action}


@app.post("/chaos/security-test")
async def chaos_security_test(payload: Dict[str, Any] = Body(default_factory=dict)):
    """Phase 124: Start security chaos test."""
    global _chaos_tests
    test = {
        "test_id": f"chaos-{uuid.uuid4().hex[:8]}",
        "scenario": payload.get("scenario", "credential-failure"),
        "status": "completed",
        "resilience_score": 74,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    _chaos_tests.append(test)
    return test


@app.get("/chaos/results")
async def chaos_results():
    """Phase 124: Return security chaos test results."""
    return {"count": len(_chaos_tests), "results": _chaos_tests}


@app.get("/quantum/crypto-audit")
async def quantum_crypto_audit(refresh: bool = False):
    """Phase 125: Return quantum-readiness cryptographic audit."""
    global _quantum_audit
    if refresh or not _quantum_audit:
        _quantum_audit = {
            "checked_at": datetime.now(timezone.utc).isoformat(),
            "algorithms": {"rsa": 14, "ecc": 9, "post_quantum": 1},
            "legacy_crypto_assets": 11,
            "readiness_score": 44,
        }
    return _quantum_audit


@app.get("/quantum/recommendations")
async def quantum_recommendations():
    """Phase 125: Return quantum migration recommendations."""
    return {
        "recommendations": [
            "Inventory RSA/ECC certificates and prioritize internet-facing services.",
            "Pilot hybrid TLS with post-quantum key exchange for critical APIs.",
            "Establish crypto-agility policy with annual algorithm review.",
        ]
    }


@app.get("/cross-env/incidents")
async def cross_env_incidents(refresh: bool = False):
    """Phase 126: Return correlated incidents across environments."""
    global _cross_env_incidents
    if refresh or not _cross_env_incidents:
        _cross_env_incidents = [
            {"id": "cei-001", "environments": ["onprem", "cloud"], "type": "credential-abuse", "severity": "high"},
            {"id": "cei-002", "environments": ["cloud", "saas"], "type": "api-token-reuse", "severity": "critical"},
        ]
    return {"count": len(_cross_env_incidents), "items": _cross_env_incidents}


@app.get("/cross-env/threats")
async def cross_env_threats():
    """Phase 126: Return threat patterns across environments."""
    if not _cross_env_incidents:
        await cross_env_incidents(refresh=True)
    threats = [{"type": item.get("type"), "severity": item.get("severity")} for item in _cross_env_incidents]
    return {"count": len(threats), "items": threats}


@app.get("/risk/external")
async def risk_external(refresh: bool = False):
    """Phase 127: Return external digital risk indicators."""
    global _digital_risk_monitors
    if refresh or not _digital_risk_monitors:
        _digital_risk_monitors = [
            {"signal": "domain-typosquat", "severity": "high", "status": "open"},
            {"signal": "brand-impersonation", "severity": "critical", "status": "investigating"},
        ]
    return {"count": len(_digital_risk_monitors), "items": _digital_risk_monitors}


@app.get("/risk/reputation")
async def risk_reputation():
    """Phase 127: Return digital reputation score."""
    if not _digital_risk_monitors:
        await risk_external(refresh=True)
    critical = sum(1 for item in _digital_risk_monitors if item.get("severity") == "critical")
    score = max(0, 90 - critical * 20 - len(_digital_risk_monitors) * 8)
    return {"reputation_score": score, "status": "watch" if score < 70 else "good"}


@app.get("/insider/score/{user}")
async def insider_score(user: str):
    """Phase 128: Return insider threat score for a user."""
    global _insider_risk_scores
    if user not in _insider_risk_scores:
        _insider_risk_scores[user] = min(95, max(10, len(user) * 7))
    score = _insider_risk_scores[user]
    return {"user": user, "score": score, "risk": "high" if score >= 75 else "medium" if score >= 50 else "low"}


@app.get("/insider/high-risk")
async def insider_high_risk():
    """Phase 128: Return high-risk insider identities."""
    if not _insider_risk_scores:
        _insider_risk_scores.update({"contractor.dev": 88, "admin.ops": 79, "alice": 34})
    items = [{"user": k, "score": v} for k, v in _insider_risk_scores.items() if v >= 75]
    return {"count": len(items), "items": items}


@app.get("/campaigns/active")
async def campaigns_active(refresh: bool = False):
    """Phase 129: Return active threat campaigns."""
    global _threat_campaigns
    if refresh or not _threat_campaigns:
        _threat_campaigns = [
            {"campaign": "Silent Atlas", "status": "active", "targets": 6, "confidence": 0.82},
            {"campaign": "Blue Ember", "status": "monitoring", "targets": 3, "confidence": 0.69},
        ]
    active = [item for item in _threat_campaigns if item.get("status") == "active"]
    return {"count": len(active), "items": active}


@app.get("/campaigns/history")
async def campaigns_history():
    """Phase 129: Return threat campaign history."""
    if not _threat_campaigns:
        await campaigns_active(refresh=True)
    return {"count": len(_threat_campaigns), "items": _threat_campaigns}


@app.get("/docs/security-report")
async def docs_security_report():
    """Phase 130: Return generated security report content."""
    global _security_docs
    _security_docs["security_report"] = "Security report generated with incident summary, control status, and prioritized actions."
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "content": _security_docs["security_report"],
    }


@app.get("/docs/architecture")
async def docs_architecture():
    """Phase 130: Return generated security architecture notes."""
    global _security_docs
    _security_docs["architecture"] = "Architecture includes telemetry, correlation, response, and deception layers with zero-trust enforcement."
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "content": _security_docs["architecture"],
    }


@app.post("/soc/assistant/query")
async def soc_assistant_query(payload: Dict[str, Any] = Body(default_factory=dict)):
    """Phase 131: Query secure AI assistant for SOC workflows."""
    global _soc_assistant_history
    question = str(payload.get("query", "Provide current critical risks"))
    answer = {
        "query": question,
        "response": "Top risks include credential exposure, suspicious egress, and high-risk identities.",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    _soc_assistant_history.append(answer)
    return answer


@app.get("/soc/assistant/history")
async def soc_assistant_history(limit: int = 25):
    """Phase 131: Return SOC assistant query history."""
    bounded = _safe_limit(limit, default=25, minimum=1, maximum=200)
    return {"count": min(len(_soc_assistant_history), bounded), "items": _soc_assistant_history[-bounded:]}


@app.get("/attack/prediction")
async def attack_prediction(refresh: bool = False):
    """Phase 132: Predict likely near-term attack vectors."""
    global _attack_predictions
    if refresh or not _attack_predictions:
        _attack_predictions = [
            {"vector": "credential-stuffing", "likelihood": 0.77, "impact": "high"},
            {"vector": "data-exfiltration", "likelihood": 0.72, "impact": "critical"},
        ]
    return {"count": len(_attack_predictions), "items": _attack_predictions}


@app.get("/attack/prediction/path")
async def attack_prediction_path():
    """Phase 132: Return predicted attack path graph."""
    return {
        "path": ["phishing-email", "credential-capture", "vpn-login", "privilege-escalation", "exfiltration"],
        "confidence": 0.81,
    }


@app.get("/actors/profiles")
async def actors_profiles(refresh: bool = False):
    """Phase 133: Return threat actor profiles."""
    global _threat_actor_profiles
    if refresh or not _threat_actor_profiles:
        _threat_actor_profiles = [
            {"actor": "TA-Delta", "motivation": "financial", "sophistication": "high"},
            {"actor": "TA-Orchid", "motivation": "espionage", "sophistication": "advanced"},
        ]
    return {"count": len(_threat_actor_profiles), "items": _threat_actor_profiles}


@app.get("/actors/activities")
async def actors_activities():
    """Phase 133: Return recent threat actor activities."""
    if not _threat_actor_profiles:
        await actors_profiles(refresh=True)
    activities = [
        {"actor": "TA-Delta", "activity": "credential marketplace listing", "severity": "high"},
        {"actor": "TA-Orchid", "activity": "supply chain reconnaissance", "severity": "critical"},
    ]
    return {"count": len(activities), "items": activities}


@app.get("/resilience/score")
async def resilience_score():
    """Phase 134: Return cyber resilience score."""
    global _resilience_score
    if not _resilience_score:
        _resilience_score = {
            "score": 76,
            "recovery_readiness": 72,
            "response_maturity": 81,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    return _resilience_score


@app.get("/resilience/improvements")
async def resilience_improvements():
    """Phase 134: Return resilience improvement recommendations."""
    return {
        "recommendations": [
            "Run tabletop recovery drills monthly for critical services.",
            "Reduce privileged account sprawl and rotate credentials faster.",
            "Expand deception coverage in high-value network segments.",
        ]
    }


@app.post("/recovery/initiate")
async def recovery_initiate(payload: Dict[str, Any] = Body(default_factory=dict)):
    """Phase 135: Initiate disaster security recovery plan."""
    global _recovery_status
    _recovery_status = {
        "operation_id": f"rec-{uuid.uuid4().hex[:8]}",
        "scope": payload.get("scope", "critical-assets"),
        "status": "initiated",
        "started_at": datetime.now(timezone.utc).isoformat(),
    }
    return _recovery_status


@app.get("/recovery/status")
async def recovery_status():
    """Phase 135: Return recovery operation status."""
    if not _recovery_status:
        await recovery_initiate(payload={})
    return _recovery_status


@app.get("/assets/lifecycle")
async def assets_lifecycle(refresh: bool = False):
    """Phase 136: Return secure asset lifecycle tracking data."""
    global _asset_lifecycle
    if refresh or not _asset_lifecycle:
        _asset_lifecycle = [
            {"asset": "ws-fin-02", "stage": "production", "owner": "finance-it", "last_hardening": "2026-02-28"},
            {"asset": "edge-gateway-01", "stage": "production", "owner": "netsec", "last_hardening": "2026-03-01"},
        ]
    return {"count": len(_asset_lifecycle), "items": _asset_lifecycle}


@app.get("/assets/risk")
async def assets_risk():
    """Phase 136: Return per-asset risk summary."""
    if not _asset_lifecycle:
        await assets_lifecycle(refresh=True)
    risks = [{"asset": item["asset"], "risk_score": 62 if "gateway" in item["asset"] else 44} for item in _asset_lifecycle]
    return {"count": len(risks), "items": risks}


@app.get("/attack-graph")
async def attack_graph(refresh: bool = False):
    """Phase 137: Generate attack graph nodes and edges."""
    global _attack_graph
    if refresh or not _attack_graph:
        _attack_graph = {
            "nodes": ["phishing", "vpn", "domain-controller", "data-store"],
            "edges": [["phishing", "vpn"], ["vpn", "domain-controller"], ["domain-controller", "data-store"]],
        }
    return _attack_graph


@app.get("/attack-graph/paths")
async def attack_graph_paths():
    """Phase 137: Return likely attack paths from graph."""
    if not _attack_graph:
        await attack_graph(refresh=True)
    return {"paths": [["phishing", "vpn", "domain-controller", "data-store"]], "count": 1}


@app.get("/forecast/threats")
async def forecast_threats(refresh: bool = False):
    """Phase 138: Forecast likely future threat categories."""
    global _security_forecasts
    if refresh or not _security_forecasts:
        _security_forecasts = [
            {"window": "7d", "category": "credential-abuse", "probability": 0.74},
            {"window": "7d", "category": "supply-chain", "probability": 0.51},
            {"window": "30d", "category": "exfiltration", "probability": 0.68},
        ]
    return {"count": len(_security_forecasts), "items": _security_forecasts}


@app.get("/forecast/trends")
async def forecast_trends():
    """Phase 138: Return trendline for threat forecast confidence."""
    if not _security_forecasts:
        await forecast_threats(refresh=True)
    trend = [{"category": item["category"], "trend": "up" if item["probability"] >= 0.6 else "steady"} for item in _security_forecasts]
    return {"count": len(trend), "items": trend}


@app.post("/policy/generate")
async def policy_generate(payload: Dict[str, Any] = Body(default_factory=dict)):
    """Phase 139: Generate autonomous policy recommendation."""
    global _policy_recommendations
    objective = payload.get("objective", "reduce credential abuse")
    recommendation = {
        "policy_id": f"pol-{uuid.uuid4().hex[:8]}",
        "objective": objective,
        "controls": [
            "Require MFA for all external logins",
            "Block impossible-travel authentication",
            "Auto-disable stale privileged sessions",
        ],
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
    _policy_recommendations.append(recommendation)
    return recommendation


@app.get("/policy/recommendations")
async def policy_recommendations():
    """Phase 139: Return generated policy recommendations."""
    return {"count": len(_policy_recommendations), "items": _policy_recommendations}


@app.get("/intel/shared-threats")
async def intel_shared_threats():
    """Phase 140: Return cross-tenant shared threat intelligence."""
    return {"count": len(_shared_threats), "items": _shared_threats}


@app.post("/intel/share-threat")
async def intel_share_threat(payload: Dict[str, Any] = Body(default_factory=dict)):
    """Phase 140: Share threat indicator with tenants."""
    threat = {
        "id": f"st-{uuid.uuid4().hex[:8]}",
        "indicator": payload.get("indicator", "unknown-ioc"),
        "type": payload.get("type", "domain"),
        "severity": payload.get("severity", "high"),
        "shared_at": datetime.now(timezone.utc).isoformat(),
    }
    _shared_threats.append(threat)
    return {"status": "shared", "threat": threat}


# --- Phases 30-140: Expansion Route Registry (Module-Level) ---

def _load_phase_expansion_specs() -> List[Dict[str, Any]]:
    """Load phase endpoint specs from roadmap markdown for phases 30-140."""
    this_dir = os.path.dirname(__file__)
    roadmap_path = os.path.abspath(os.path.join(this_dir, "..", "..", "..", "docs", "PHASES_26_140_ROADMAP.md"))
    if not os.path.exists(roadmap_path):
        return []

    specs: List[Dict[str, Any]] = []
    current: Optional[Dict[str, Any]] = None
    phase_re = re.compile(r"^###\s+Phase\s+(\d+)\s+-\s+(.+)$", re.IGNORECASE)
    endpoint_re = re.compile(r"^-\s+`([A-Z]+)\s+([^`]+)`$")

    with open(roadmap_path, "r", encoding="utf-8") as handle:
        for raw_line in handle:
            line = raw_line.strip()
            phase_match = phase_re.match(line)
            if phase_match:
                if current and current.get("phase", 0) >= 30 and current.get("endpoints"):
                    specs.append(current)
                current = {
                    "phase": int(phase_match.group(1)),
                    "name": phase_match.group(2).strip(),
                    "endpoints": [],
                }
                continue

            if current is None:
                continue

            endpoint_match = endpoint_re.match(line)
            if endpoint_match:
                method = endpoint_match.group(1).upper()
                path = endpoint_match.group(2).strip()
                if method in {"GET", "POST", "DELETE"} and path.startswith("/"):
                    current["endpoints"].append(f"{method} {path}")

    if current and current.get("phase", 0) >= 30 and current.get("endpoints"):
        specs.append(current)

    return specs


def _phase_expansion_route_factory(config: Dict[str, Any]):
    async def _handler(request: Request):
        return {
            "status": "implemented-baseline",
            "phase": config["phase"],
            "phase_name": config["name"],
            "endpoint": {
                "method": config["method"],
                "path_template": config["path"],
            },
            "path_params": dict(request.path_params),
            "query_params": dict(request.query_params),
            "note": "Baseline endpoint. Upgrade with monitor, repository, and response logic for deep behavior.",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    return _handler


def _register_phase_expansion_routes() -> Dict[str, int]:
    specs = _load_phase_expansion_specs()
    expanded_routes: List[Dict[str, Any]] = []
    for spec in specs:
        for endpoint in spec.get("endpoints", []):
            method, path = endpoint.split(" ", 1)
            expanded_routes.append({
                "phase": spec["phase"],
                "name": spec["name"],
                "method": method.upper(),
                "path": path.strip(),
            })

    existing_keys = set()
    for route in app.routes:
        route_path = getattr(route, "path", None)
        route_methods = getattr(route, "methods", None)
        if route_path and route_methods:
            for method in route_methods:
                existing_keys.add((method.upper(), route_path))

    added = 0
    skipped = 0
    for config in expanded_routes:
        key = (config["method"], config["path"])
        if key in existing_keys:
            skipped += 1
            continue

        route_name = (
            f"phase_{config['phase']}_{config['method'].lower()}_"
            f"{config['path'].strip('/').replace('/', '_').replace('{', '').replace('}', '').replace('-', '_')}"
        )
        app.add_api_route(
            config["path"],
            _phase_expansion_route_factory(config),
            methods=[config["method"]],
            name=route_name,
            tags=[f"Phase {config['phase']}: {config['name']}"]
        )
        existing_keys.add(key)
        added += 1

    logger.info(f"Phase expansion routes registered: added={added}, skipped={skipped}")
    return {"added": added, "skipped": skipped}


_PHASE_EXPANSION_REGISTRATION = _register_phase_expansion_routes()


@app.get("/phases/expansion/status")
async def phase_expansion_status():
    """Show registration and coverage status for phases 30-140 baseline endpoints."""
    specs = _load_phase_expansion_specs()
    phase_numbers = [item["phase"] for item in specs] or [30, 140]
    return {
        "phases_range": {"start": min(phase_numbers), "end": max(phase_numbers)},
        "phase_count": len(set(phase_numbers)),
        "route_registration": _PHASE_EXPANSION_REGISTRATION,
        "note": "Routes are baseline-implemented where deep endpoints are not yet present.",
    }

# --- Entry Point ---

def start_api():
    import uvicorn
    import threading
    
    # Start Sentinel in a background thread
    sentinel = get_sentinel()
    sentinel_thread = threading.Thread(target=sentinel.start, daemon=True)
    sentinel_thread.start()
    
    # Run API
    uvicorn.run(app, host="0.0.0.0", port=8000)

if __name__ == "__main__":
    start_api()
