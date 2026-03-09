"""
Arkshield — Process Monitor

Continuous monitoring of process activity including:
- Process creation and termination
- Process tree tracking (parent-child relationships)
- Command line analysis for suspicious patterns
- Privilege escalation detection
- Anomalous process behavior detection
- LOLBin usage detection
"""

import time
import hashlib
import logging
from pathlib import Path
from typing import Dict, Set, Optional, List
from datetime import datetime, timezone

import psutil

from arkshield.agent.core import MonitorBase, EventBus
from arkshield.config.settings import AgentConfig
from arkshield.telemetry.events import (
    SecurityEvent, EventClass, EventType, Severity,
    ProcessInfo, MITREMapping
)

logger = logging.getLogger("arkshield.monitor.process")

# Suspicious process patterns (LOLBins and common attack tools - cross-platform)
SUSPICIOUS_PROCESSES = {
    # Windows LOLBins
    "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe",
    "mshta.exe", "regsvr32.exe", "rundll32.exe", "certutil.exe",
    "bitsadmin.exe", "msiexec.exe", "wmic.exe", "installutil.exe",
    "regasm.exe", "msbuild.exe", "cmstp.exe", "msxsl.exe",
    "forfiles.exe", "pcalua.exe", "bash.exe", "scriptrunner.exe",
    # Linux LOLBins and suspicious tools
    "bash", "sh", "dash", "zsh", "ksh", "csh", "tcsh",
    "python", "python2", "python3", "perl", "ruby", "php",
    "nc", "netcat", "ncat", "socat", "telnet",
    "wget", "curl", "lynx", "w3m",
    "nmap", "masscan", "nikto", "sqlmap",
    "msfconsole", "metasploit", "msfvenom",
    "john", "hashcat", "hydra", "medusa",
    "tcpdump", "wireshark", "tshark",
    "dd", "shred", "base64", "base32",
    "openssl", "gpg", "ssh", "sshpass",
    "docker", "kubectl", "podman",
    "strace", "ltrace", "gdb", "gdbserver"
}

# Suspicious parent-child relationships (cross-platform)
SUSPICIOUS_PARENT_CHILD = {
    # Windows
    ("winword.exe", "powershell.exe"),
    ("winword.exe", "cmd.exe"),
    ("excel.exe", "powershell.exe"),
    ("excel.exe", "cmd.exe"),
    ("outlook.exe", "powershell.exe"),
    ("svchost.exe", "cmd.exe"),
    ("explorer.exe", "mshta.exe"),
    ("services.exe", "cmd.exe"),
    ("wmiprvse.exe", "powershell.exe"),
    # Linux
    ("apache2", "bash"),
    ("httpd", "bash"),
    ("nginx", "bash"),
    ("sshd", "nc"),
    ("sshd", "netcat"),
    ("cron", "curl"),
    ("cron", "wget"),
    ("systemd", "bash"),
    ("gnome-shell", "bash"),
    ("firefox", "bash"),
    ("chrome", "bash"),
}

# Suspicious command-line patterns (cross-platform)
SUSPICIOUS_CMD_PATTERNS = [
    # Windows PowerShell
    "-encodedcommand", "-enc ", "-e ", "hidden",
    "bypass", "downloadstring", "downloadfile", "invoke-expression",
    "iex(", "invoke-webrequest", "net.webclient", "start-bitstransfer",
    "reflection.assembly", "frombase64string", "convertto-securestring",
    "mimikatz", "sekurlsa", "kerberos::", "lsadump::",
    "whoami /priv", "net user", "net localgroup",
    "reg save", "reg export", "comsvcs.dll", "minidump",
    "-nop ", "-noni", "-noprofile", "-windowstyle hidden",
    "vssadmin delete", "wbadmin delete", "bcdedit /set",
    "shadowcopy delete", "catalog -quiet",
    # Linux/Unix shells
    "bash -i", "sh -i", "/dev/tcp", "/dev/udp",
    "nc -l", "nc -lvp", "netcat -l",
    "wget http", "curl http", "curl -o",
    "chmod +x", "chmod 777",
    "base64 -d", "echo | base64",
    "/tmp/.", "cd /tmp", "cd /var/tmp",
    "nohup ", "disown", "screen -", "tmux ",
    "python -c", "perl -e", "ruby -e", "php -r",
    "eval(", "exec(", "system(",
    "iptables -F", "iptables -X",
    "useradd", "adduser", "usermod -aG sudo",
    "passwd ", "chpasswd",
    "/etc/shadow", "/etc/passwd",
    "ssh-keygen", "authorized_keys",
    "crontab -", "at now",
    "sudo su", "sudo -i", "su -",
    "docker run", "docker exec",
    "rev ", "socat ", "reverse shell", "bind shell"
]


class ProcessMonitor(MonitorBase):
    """
    Monitors all process activity on the endpoint.

    Detects:
    - New process creation with suspicious characteristics
    - Unusual parent-child process relationships
    - LOLBin abuse
    - Suspicious command-line arguments
    - Privilege escalation attempts
    - Process injection indicators
    """

    def __init__(self, event_bus: EventBus, config: AgentConfig):
        super().__init__("process", event_bus, config)
        self._known_pids: Dict[int, Dict] = {}
        self._process_history: List[Dict] = []
        self._baseline_processes: Set[str] = set()
        self._alert_cooldown: Dict[str, float] = {}  # prevent alert flooding
        self._initialized = False

    def collect(self):
        """Collect process telemetry."""
        current_pids = {}

        for proc in psutil.process_iter([
            'pid', 'name', 'exe', 'cmdline', 'ppid', 'username',
            'status', 'create_time', 'cpu_percent', 'memory_info',
            'num_threads'
        ]):
            try:
                info = proc.info
                pid = info['pid']
                current_pids[pid] = info

                # Detect new processes
                if pid not in self._known_pids:
                    self._handle_new_process(info, proc)

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        # Detect terminated processes
        terminated = set(self._known_pids.keys()) - set(current_pids.keys())
        for pid in terminated:
            self._handle_process_exit(pid)

        # Update known processes
        if not self._initialized:
            # First run — build baseline
            self._baseline_processes = {
                info.get('name', '').lower() for info in current_pids.values()
            }
            self._initialized = True

        self._known_pids = current_pids

    def _handle_new_process(self, info: Dict, proc: psutil.Process):
        """Handle a newly detected process."""
        name = (info.get('name') or '').lower()
        exe = info.get('exe') or ''
        cmdline_list = info.get('cmdline') or []
        cmdline = ' '.join(cmdline_list) if cmdline_list else ''
        ppid = info.get('ppid', 0)
        pid = info['pid']
        username = info.get('username', '')

        # Get parent name
        parent_name = ''
        try:
            if ppid:
                parent = psutil.Process(ppid)
                parent_name = parent.name().lower()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

        # Build process info
        proc_info = ProcessInfo(
            pid=pid,
            name=info.get('name', ''),
            path=exe,
            cmd_line=cmdline,
            parent_pid=ppid,
            parent_name=parent_name,
            user=username,
            start_time=info.get('create_time', 0),
            thread_count=info.get('num_threads', 0),
        )

        # Calculate file hash for executables
        if exe and Path(exe).exists():
            try:
                proc_info.hash_sha256 = self._hash_file(exe)
            except Exception:
                pass

        # Memory usage
        mem_info = info.get('memory_info')
        if mem_info:
            proc_info.memory_mb = mem_info.rss / (1024 * 1024)

        # Connection count
        try:
            conns = proc.net_connections()
            proc_info.network_connections = len(conns)
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            pass

        # Determine severity and generate events
        severity = Severity.INFO
        event_type = EventType.PROCESS_LAUNCH
        tags = []
        mitre = None
        description = f"Process started: {info.get('name', '')} (PID {pid})"

        # Check for suspicious patterns
        is_suspicious = False

        # Check LOLBin usage
        if name in SUSPICIOUS_PROCESSES:
            severity = max(severity, Severity.MEDIUM)
            tags.append("lolbin")
            is_suspicious = True
            mitre = MITREMapping(
                tactic="execution",
                technique_id="T1059",
                technique_name="Command and Scripting Interpreter"
            )

        # Check suspicious parent-child
        if (parent_name, name) in SUSPICIOUS_PARENT_CHILD:
            severity = max(severity, Severity.HIGH)
            tags.append("suspicious_parent_child")
            is_suspicious = True
            description = f"Suspicious process chain: {parent_name} → {name}"
            mitre = MITREMapping(
                tactic="execution",
                technique_id="T1059",
                technique_name="Command and Scripting Interpreter"
            )

        # Check command-line patterns
        cmd_lower = cmdline.lower()
        matched_patterns = []
        for pattern in SUSPICIOUS_CMD_PATTERNS:
            if pattern.lower() in cmd_lower:
                matched_patterns.append(pattern)

        if matched_patterns:
            severity = max(severity, Severity.HIGH)
            tags.append("suspicious_cmdline")
            is_suspicious = True
            description = f"Suspicious command line detected in {name}: {', '.join(matched_patterns[:3])}"

        # Check for encoded commands (common evasion)
        if '-enc' in cmd_lower or 'encodedcommand' in cmd_lower:
            severity = max(severity, Severity.HIGH)
            tags.append("encoded_command")
            is_suspicious = True
            mitre = MITREMapping(
                tactic="defense_evasion",
                technique_id="T1027",
                technique_name="Obfuscated Files or Information"
            )

        # Check for new/unusual process (not in baseline)
        if self._initialized and name not in self._baseline_processes and name:
            tags.append("new_process")
            if not is_suspicious:
                severity = max(severity, Severity.LOW)

        # Rate-limit alerts per process name
        alert_key = f"{name}:{event_type}"
        now = time.time()
        if alert_key in self._alert_cooldown:
            if now - self._alert_cooldown[alert_key] < 60:  # 60s cooldown
                if severity <= Severity.MEDIUM:
                    return
        self._alert_cooldown[alert_key] = now

        # Emit the event
        self.emit_event(SecurityEvent(
            event_class=EventClass.PROCESS_ACTIVITY.value,
            event_type=event_type.value,
            severity=severity.value,
            description=description,
            process=proc_info,
            mitre=mitre,
            tags=tags,
            is_threat=is_suspicious and severity >= Severity.HIGH,
            risk_score=self._calculate_risk_score(severity, tags, proc_info),
            metadata={
                "matched_patterns": matched_patterns[:5] if matched_patterns else [],
                "is_baseline": name in self._baseline_processes,
            }
        ))

        # Track in history
        self._process_history.append({
            "pid": pid,
            "name": name,
            "cmdline": cmdline[:500],
            "parent": parent_name,
            "time": now,
            "severity": severity.value,
        })
        # Keep history bounded
        if len(self._process_history) > 1000:
            self._process_history = self._process_history[-500:]

    def _handle_process_exit(self, pid: int):
        """Handle a process that has terminated."""
        info = self._known_pids.get(pid, {})
        name = info.get('name', f'PID-{pid}')

        self.emit_event(SecurityEvent(
            event_class=EventClass.PROCESS_ACTIVITY.value,
            event_type=EventType.PROCESS_TERMINATE.value,
            severity=Severity.INFO.value,
            description=f"Process terminated: {name} (PID {pid})",
            process=ProcessInfo(pid=pid, name=name),
        ))

    def _calculate_risk_score(self, severity: Severity, tags: List[str], proc: ProcessInfo) -> float:
        """Calculate a risk score from 0-100."""
        score = 0.0
        score += severity.value * 15  # 0-60 from severity
        score += len(tags) * 5       # 0-25 from tags
        if proc.network_connections > 5:
            score += 10
        if proc.memory_mb > 500:
            score += 5
        return min(score, 100.0)

    def _hash_file(self, filepath: str) -> str:
        """Calculate SHA256 hash of a file."""
        sha256 = hashlib.sha256()
        try:
            with open(filepath, 'rb') as f:
                for chunk in iter(lambda: f.read(8192), b''):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except (IOError, PermissionError):
            return ""

    def get_process_tree(self, pid: int) -> Dict:
        """Get the full process tree for a given PID."""
        tree = {"pid": pid, "children": []}
        try:
            proc = psutil.Process(pid)
            tree["name"] = proc.name()
            tree["cmdline"] = ' '.join(proc.cmdline() or [])
            for child in proc.children(recursive=True):
                tree["children"].append({
                    "pid": child.pid,
                    "name": child.name(),
                    "cmdline": ' '.join(child.cmdline() or []),
                })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
        return tree

    def get_process_history(self) -> List[Dict]:
        """Get recent process creation history."""
        return list(self._process_history)
