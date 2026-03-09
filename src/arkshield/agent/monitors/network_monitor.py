"""
Arkshield — Network Monitor

Continuous monitoring of network activity including:
- Connection tracking with process attribution
- DNS query monitoring and DGA detection
- Beacon interval detection for C2 communication
- Lateral movement detection
- Data exfiltration monitoring
- TLS fingerprinting
"""

import time
import math
import logging
import socket
import struct
from typing import Dict, List, Set, Optional, Tuple
from collections import defaultdict, Counter
from datetime import datetime, timezone

import psutil

from arkshield.agent.core import MonitorBase, EventBus
from arkshield.config.settings import AgentConfig
from arkshield.telemetry.events import (
    SecurityEvent, EventClass, EventType, Severity,
    NetworkInfo, ProcessInfo, MITREMapping
)

logger = logging.getLogger("arkshield.monitor.network")

# Known malicious ports
SUSPICIOUS_PORTS = {
    4444, 4445, 5555, 6666, 6667, 6668, 6669,  # Common RAT/backdoor
    1337, 31337, 8888, 9999,  # Hacker culture
    3389,  # RDP (suspicious if unexpected)
    445,   # SMB (lateral movement)
    135, 137, 138, 139,  # NetBIOS
    5985, 5986,  # WinRM
    22,    # SSH
}

# Internal/private IP ranges
PRIVATE_RANGES = [
    ('10.0.0.0', '10.255.255.255'),
    ('172.16.0.0', '172.31.255.255'),
    ('192.168.0.0', '192.168.255.255'),
    ('127.0.0.0', '127.255.255.255'),
]

# Known DNS-over-HTTPS providers (for DoH detection)
DOH_SERVERS = {
    '1.1.1.1', '1.0.0.1',           # Cloudflare
    '8.8.8.8', '8.8.4.4',           # Google
    '9.9.9.9', '149.112.112.112',   # Quad9
    '208.67.222.222', '208.67.220.220',  # OpenDNS
}


class NetworkMonitor(MonitorBase):
    """
    Monitors all network connections with process attribution.

    Capabilities:
    - Real-time connection tracking with process mapping
    - DNS query analysis and DGA (Domain Generation Algorithm) detection
    - C2 beacon interval detection
    - Lateral movement detection
    - Data exfiltration volume monitoring
    - Suspicious port detection
    """

    def __init__(self, event_bus: EventBus, config: AgentConfig):
        super().__init__("network", event_bus, config)
        self._known_connections: Dict[tuple, Dict] = {}
        self._connection_history: List[Dict] = []
        self._beacon_tracker: Dict[str, List[float]] = defaultdict(list)
        self._data_transfer: Dict[str, int] = defaultdict(int)  # IP -> bytes
        self._dns_queries: List[Dict] = []
        self._baseline_connections: Set[tuple] = set()
        self._initialized = False

    def collect(self):
        """Collect network telemetry."""
        current_connections = {}

        for conn in psutil.net_connections(kind='all'):
            try:
                if conn.status == 'NONE':
                    continue

                key = (
                    conn.laddr.ip if conn.laddr else '',
                    conn.laddr.port if conn.laddr else 0,
                    conn.raddr.ip if conn.raddr else '',
                    conn.raddr.port if conn.raddr else 0,
                    conn.pid or 0
                )

                # Get process info
                proc_name = ""
                try:
                    if conn.pid:
                        proc = psutil.Process(conn.pid)
                        proc_name = proc.name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

                conn_info = {
                    'local_ip': conn.laddr.ip if conn.laddr else '',
                    'local_port': conn.laddr.port if conn.laddr else 0,
                    'remote_ip': conn.raddr.ip if conn.raddr else '',
                    'remote_port': conn.raddr.port if conn.raddr else 0,
                    'pid': conn.pid or 0,
                    'process_name': proc_name,
                    'status': conn.status,
                    'type': 'tcp' if conn.type == socket.SOCK_STREAM else 'udp',
                    'family': 'ipv4' if conn.family == socket.AF_INET else 'ipv6',
                    'timestamp': time.time(),
                }

                current_connections[key] = conn_info

                # Detect new connections
                if key not in self._known_connections:
                    self._handle_new_connection(conn_info)

            except Exception as e:
                continue

        # Detect closed connections
        closed = set(self._known_connections.keys()) - set(current_connections.keys())
        for key in closed:
            pass  # Connection closed — normal lifecycle

        # Build baseline on first run
        if not self._initialized:
            self._baseline_connections = set(current_connections.keys())
            self._initialized = True

        self._known_connections = current_connections

        # Periodic analysis
        self._analyze_beacon_patterns()
        self._check_data_exfiltration()

    def _handle_new_connection(self, conn: Dict):
        """Handle a newly detected network connection."""
        remote_ip = conn['remote_ip']
        remote_port = conn['remote_port']
        local_port = conn['local_port']
        proc_name = conn['process_name']
        pid = conn['pid']

        if not remote_ip or remote_ip.startswith('127.'):
            return  # Skip loopback

        severity = Severity.INFO
        tags = []
        mitre = None
        event_type = EventType.NETWORK_CONNECTION
        description = f"Connection: {proc_name} ({pid}) → {remote_ip}:{remote_port}"

        is_external = not self._is_private_ip(remote_ip)
        is_internal = self._is_private_ip(remote_ip)

        # Check suspicious ports
        if remote_port in SUSPICIOUS_PORTS:
            severity = Severity.MEDIUM
            tags.append("suspicious_port")

        # Check for potential lateral movement (internal connections on admin ports)
        if is_internal and remote_port in {445, 135, 5985, 5986, 3389, 22}:
            severity = max(severity, Severity.MEDIUM)
            tags.append("potential_lateral_movement")
            event_type = EventType.NETWORK_LATERAL_MOVEMENT
            mitre = MITREMapping(
                tactic="lateral_movement",
                technique_id="T1021",
                technique_name="Remote Services"
            )

        # Check for unusual external connections
        if is_external:
            tags.append("external_connection")
            # Track for beacon analysis
            self._beacon_tracker[remote_ip].append(time.time())

            # Track data transfer
            self._data_transfer[remote_ip] += 1

        # Check for DoH (DNS-over-HTTPS) usage
        if remote_ip in DOH_SERVERS and remote_port == 443:
            tags.append("dns_over_https")
            severity = max(severity, Severity.LOW)

        # Check for high port connections (potential reverse shells)
        if remote_port > 10000 and is_external:
            tags.append("high_port_external")
            severity = max(severity, Severity.MEDIUM)

        # Build network info
        net_info = NetworkInfo(
            local_ip=conn['local_ip'],
            local_port=local_port,
            remote_ip=remote_ip,
            remote_port=remote_port,
            protocol=conn['type'],
            direction="outbound" if is_external else "internal",
            pid=pid,
            process_name=proc_name,
            status=conn['status'],
        )

        self.emit_event(SecurityEvent(
            event_class=EventClass.NETWORK_ACTIVITY.value,
            event_type=event_type.value,
            severity=severity.value,
            description=description,
            network=net_info,
            process=ProcessInfo(pid=pid, name=proc_name),
            mitre=mitre,
            tags=tags,
            risk_score=min(severity.value * 20 + len(tags) * 5, 100),
            is_threat=severity >= Severity.HIGH,
        ))

        # Track in history
        self._connection_history.append({
            "remote_ip": remote_ip,
            "remote_port": remote_port,
            "process": proc_name,
            "time": time.time(),
            "direction": "external" if is_external else "internal",
        })
        if len(self._connection_history) > 1000:
            self._connection_history = self._connection_history[-500:]

    def _analyze_beacon_patterns(self):
        """Detect C2 beacon patterns (periodic communication)."""
        now = time.time()

        for ip, timestamps in list(self._beacon_tracker.items()):
            # Keep only recent timestamps (last 5 minutes)
            recent = [t for t in timestamps if now - t < 300]
            self._beacon_tracker[ip] = recent

            if len(recent) < 5:
                continue

            # Calculate intervals between connections
            intervals = [recent[i+1] - recent[i] for i in range(len(recent)-1)]

            if not intervals:
                continue

            # Check for regularity (low coefficient of variation = regular beaconing)
            mean_interval = sum(intervals) / len(intervals)
            if mean_interval < 1:
                continue

            variance = sum((i - mean_interval) ** 2 for i in intervals) / len(intervals)
            std_dev = math.sqrt(variance)
            cv = std_dev / mean_interval if mean_interval > 0 else float('inf')

            # CV < 0.3 indicates regular beaconing
            if cv < 0.3 and len(intervals) >= 4:
                self.emit_event(SecurityEvent(
                    event_class=EventClass.THREAT_DETECTION.value,
                    event_type=EventType.THREAT_C2_COMMUNICATION.value,
                    severity=Severity.HIGH.value,
                    description=f"C2 BEACON DETECTED — Regular communication to {ip} "
                                f"(interval: {mean_interval:.1f}s, CV: {cv:.2f})",
                    network=NetworkInfo(remote_ip=ip),
                    tags=["beacon_detected", "c2_indicator"],
                    is_threat=True,
                    risk_score=85.0,
                    metadata={
                        "mean_interval": round(mean_interval, 2),
                        "coefficient_of_variation": round(cv, 4),
                        "connection_count": len(recent),
                    },
                    mitre=MITREMapping(
                        tactic="command_and_control",
                        technique_id="T1071",
                        technique_name="Application Layer Protocol"
                    )
                ))

    def _check_data_exfiltration(self):
        """Monitor for unusual data transfer volumes."""
        for ip, count in list(self._data_transfer.items()):
            if count > 100 and not self._is_private_ip(ip):
                self.emit_event(SecurityEvent(
                    event_class=EventClass.NETWORK_ACTIVITY.value,
                    event_type=EventType.NETWORK_DATA_EXFILTRATION.value,
                    severity=Severity.MEDIUM.value,
                    description=f"High connection volume to {ip}: {count} connections",
                    network=NetworkInfo(remote_ip=ip),
                    tags=["high_volume", "exfiltration_indicator"],
                    metadata={"connection_count": count},
                    mitre=MITREMapping(
                        tactic="exfiltration",
                        technique_id="T1041",
                        technique_name="Exfiltration Over C2 Channel"
                    )
                ))

    @staticmethod
    def _is_private_ip(ip: str) -> bool:
        """Check if an IP address is in a private range."""
        try:
            parts = [int(p) for p in ip.split('.')]
            if len(parts) != 4:
                return False
            ip_int = (parts[0] << 24) + (parts[1] << 16) + (parts[2] << 8) + parts[3]

            for start, end in PRIVATE_RANGES:
                sp = [int(p) for p in start.split('.')]
                ep = [int(p) for p in end.split('.')]
                s = (sp[0] << 24) + (sp[1] << 16) + (sp[2] << 8) + sp[3]
                e = (ep[0] << 24) + (ep[1] << 16) + (ep[2] << 8) + ep[3]
                if s <= ip_int <= e:
                    return True
            return False
        except (ValueError, IndexError):
            return False

    @staticmethod
    def analyze_domain_dga(domain: str) -> float:
        """
        Analyze a domain name for DGA (Domain Generation Algorithm) characteristics.
        Returns a score from 0 (likely legitimate) to 1 (likely DGA).
        """
        if not domain:
            return 0.0

        # Remove TLD
        parts = domain.split('.')
        if len(parts) < 2:
            return 0.0
        name = parts[0]

        score = 0.0

        # Length-based scoring
        if len(name) > 15:
            score += 0.3
        elif len(name) > 10:
            score += 0.1

        # Entropy of the domain name
        if name:
            counts = Counter(name)
            length = len(name)
            entropy = -sum(
                (c / length) * math.log2(c / length)
                for c in counts.values() if c > 0
            )
            if entropy > 3.5:
                score += 0.3

        # Consonant-to-vowel ratio
        vowels = sum(1 for c in name.lower() if c in 'aeiou')
        consonants = sum(1 for c in name.lower() if c.isalpha() and c not in 'aeiou')
        if consonants > 0 and vowels > 0:
            ratio = consonants / vowels
            if ratio > 4 or ratio < 0.5:
                score += 0.2

        # Digit ratio
        digits = sum(1 for c in name if c.isdigit())
        if len(name) > 0:
            digit_ratio = digits / len(name)
            if digit_ratio > 0.3:
                score += 0.2

        return min(score, 1.0)

    def get_connection_summary(self) -> Dict:
        """Get a summary of current network state."""
        external = 0
        internal = 0
        listening = 0

        for conn_info in self._known_connections.values():
            if conn_info['status'] == 'LISTEN':
                listening += 1
            elif self._is_private_ip(conn_info['remote_ip']):
                internal += 1
            else:
                external += 1

        return {
            "total_connections": len(self._known_connections),
            "external_connections": external,
            "internal_connections": internal,
            "listening_ports": listening,
            "tracked_beacons": len(self._beacon_tracker),
            "connection_history_size": len(self._connection_history),
        }
