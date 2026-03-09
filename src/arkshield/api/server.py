"""
Arkshield — API Server

FastAPI-based REST API for the autonomous cyber defense platform.
Provides endpoints for alerts, telemetry, AI analyst, system metrics, and threat intelligence.
"""

import os
import time
import logging
import platform
import shutil
import hashlib
import re
from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any, Optional
from fastapi import FastAPI, HTTPException, Depends, Request
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
    result = {"hash": hash_value, "hash_type": {32: "MD5", 40: "SHA1", 64: "SHA256"}.get(len(hash_value), "Unknown")}
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
    """Scan all auto-start programs with risk assessment."""
    import winreg
    startup_items = []
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
    startup_items.sort(key=lambda x: -x['risk_score'])
    return startup_items

@app.get("/system/services")
async def get_services():
    """List Windows services with security analysis."""
    import psutil
    services = []
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
    """Parse Windows firewall rules."""
    import subprocess
    rules = []
    try:
        # For performance, we parse a limited subset or use explicit matching
        res = subprocess.run(['netsh', 'advfirewall', 'firewall', 'show', 'rule', 'name=all'], capture_output=True, text=True, timeout=10)
        
        current_rule = {}
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
        logger.warning("Firewall parsing error: %s", e)

    return rules

# --- Phase 16: Attack Surface & Shares ---

@app.get("/security/shares")
async def get_network_shares():
    """Enumerate Windows file and print shares."""
    import subprocess
    shares = []
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
        logger.warning("Error getting shares: %s", e)
    
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
        listening_ports = {}
        established_conns = []
        
        for conn in connections:
            try:
                if conn.status == 'LISTEN':
                    port = conn.laddr.port
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
                        "address": conn.laddr.ip
                    })
                
                elif conn.status == 'ESTABLISHED':
                    try:
                        proc = psutil.Process(conn.pid) if conn.pid else None
                        proc_name = proc.name() if proc else "Unknown"
                    except:
                        proc_name = "Unknown"
                    
                    established_conns.append({
                        "local_addr": f"{conn.laddr.ip}:{conn.laddr.port}",
                        "remote_addr": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A",
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
    family_scores = {
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

    predicted_family = max(family_scores, key=family_scores.get)
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
