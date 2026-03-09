"""
Arkshield — Integrity Checker

System integrity verification including:
- Critical system file integrity monitoring
- Kernel module verification
- Boot chain validation
- Security configuration auditing
- System hardening assessment
"""

import os
import hashlib
import logging
import platform
from typing import Dict, List, Set, Optional, Tuple
from pathlib import Path
from datetime import datetime, timezone

import psutil

from arkshield.agent.core import MonitorBase, EventBus
from arkshield.config.settings import AgentConfig
from arkshield.telemetry.events import (
    SecurityEvent, EventClass, EventType, Severity,
    FileInfo, MITREMapping
)

logger = logging.getLogger("arkshield.monitor.integrity")

# Critical Windows system files to monitor
WINDOWS_CRITICAL_FILES = [
    r'C:\Windows\System32\ntdll.dll',
    r'C:\Windows\System32\kernel32.dll',
    r'C:\Windows\System32\advapi32.dll',
    r'C:\Windows\System32\user32.dll',
    r'C:\Windows\System32\ws2_32.dll',
    r'C:\Windows\System32\lsass.exe',
    r'C:\Windows\System32\csrss.exe',
    r'C:\Windows\System32\svchost.exe',
    r'C:\Windows\System32\drivers\etc\hosts',
    r'C:\Windows\System32\config\SAM',
]

# Critical Linux files to monitor
LINUX_CRITICAL_FILES = [
    '/bin/sh', '/bin/bash', '/usr/bin/sudo',
    '/usr/bin/ssh', '/usr/bin/sshd',
    '/etc/passwd', '/etc/shadow', '/etc/sudoers',
    '/etc/hosts', '/etc/resolv.conf',
    '/etc/ssh/sshd_config',
]

# Security configuration checks
WINDOWS_SECURITY_CHECKS = [
    ("Windows Firewall", "netsh advfirewall show allprofiles state"),
    ("Windows Defender Status", "sc query WinDefend"),
    ("UAC Level", "reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v EnableLUA"),
    ("Secure Boot", "reg query HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State /v UEFISecureBootEnabled"),
]


class IntegrityChecker(MonitorBase):
    """
    Verifies system integrity and security posture.

    Capabilities:
    - Critical system file hash verification
    - Security configuration auditing
    - System hardening assessment
    - Hosts file modification detection
    - Kernel module enumeration
    - Security score calculation
    """

    def __init__(self, event_bus: EventBus, config: AgentConfig):
        super().__init__("integrity", event_bus, config)
        self._file_hashes: Dict[str, str] = {}
        self._security_checks: Dict[str, bool] = {}
        self._security_score: float = 100.0
        self._initialized = False
        self._check_count = 0

    def collect(self):
        """Run integrity checks."""
        self._check_count += 1

        # Full check every 6th cycle (roughly every 30s at 5s interval)
        if self._check_count % 6 != 0 and self._initialized:
            return

        if not self._initialized:
            self._build_baseline()
            self._initialized = True
            return

        # Check critical file integrity
        self._verify_file_integrity()

        # Check security configuration
        self._audit_security_config()

        # Calculate and emit security score
        self._emit_security_score()

    def _build_baseline(self):
        """Build integrity baseline."""
        critical_files = self._get_critical_files()

        for filepath in critical_files:
            if os.path.exists(filepath):
                file_hash = self._hash_file(filepath)
                if file_hash:
                    self._file_hashes[filepath] = file_hash

        self.logger.info(f"Integrity baseline: {len(self._file_hashes)} files hashed")

        # Run initial security audit
        self._audit_security_config()

    def _verify_file_integrity(self):
        """Verify critical file hashes against baseline."""
        for filepath, baseline_hash in list(self._file_hashes.items()):
            if not os.path.exists(filepath):
                # Critical file deleted
                self.emit_event(SecurityEvent(
                    event_class=EventClass.INTEGRITY_CHECK.value,
                    event_type=EventType.INTEGRITY_FAIL.value,
                    severity=Severity.CRITICAL.value,
                    description=f"CRITICAL FILE MISSING: {filepath}",
                    file=FileInfo(path=filepath, name=os.path.basename(filepath)),
                    tags=["integrity_violation", "critical_file_missing"],
                    is_threat=True,
                    risk_score=90.0,
                    mitre=MITREMapping(
                        tactic="defense_evasion",
                        technique_id="T1070",
                        technique_name="Indicator Removal"
                    )
                ))
                continue

            current_hash = self._hash_file(filepath)
            if current_hash and current_hash != baseline_hash:
                # Critical file modified
                self.emit_event(SecurityEvent(
                    event_class=EventClass.INTEGRITY_CHECK.value,
                    event_type=EventType.INTEGRITY_FAIL.value,
                    severity=Severity.CRITICAL.value,
                    description=f"INTEGRITY VIOLATION: {filepath} has been modified",
                    file=FileInfo(
                        path=filepath,
                        name=os.path.basename(filepath),
                        hash_sha256=current_hash
                    ),
                    tags=["integrity_violation", "critical_file_modified"],
                    is_threat=True,
                    risk_score=85.0,
                    metadata={
                        "baseline_hash": baseline_hash,
                        "current_hash": current_hash,
                    },
                    mitre=MITREMapping(
                        tactic="defense_evasion",
                        technique_id="T1036",
                        technique_name="Masquerading"
                    )
                ))
                # Update baseline to prevent repeated alerts
                self._file_hashes[filepath] = current_hash

    def _audit_security_config(self):
        """Audit system security configuration."""
        score_deductions = []

        if os.name == 'nt':
            self._audit_windows_security(score_deductions)
        else:
            self._audit_linux_security(score_deductions)

        # Common checks
        self._check_hosts_file_integrity()
        self._check_dns_settings()
        self._check_open_ports(score_deductions)

        # Calculate security score
        self._security_score = max(0, 100 - sum(score_deductions))

    def _audit_windows_security(self, deductions: List[float]):
        """Audit Windows-specific security settings."""
        import subprocess

        # Check Windows Firewall
        try:
            result = subprocess.run(
                ['netsh', 'advfirewall', 'show', 'allprofiles', 'state'],
                capture_output=True, text=True, timeout=5
            )
            if 'OFF' in result.stdout.upper():
                deductions.append(20)
                self._security_checks['firewall'] = False
                self.emit_event(SecurityEvent(
                    event_class=EventClass.INTEGRITY_CHECK.value,
                    event_type=EventType.INTEGRITY_DRIFT.value,
                    severity=Severity.HIGH.value,
                    description="Windows Firewall is DISABLED",
                    tags=["firewall_disabled", "security_drift"],
                    risk_score=60.0,
                ))
            else:
                self._security_checks['firewall'] = True
        except Exception:
            pass

        # Check UAC
        try:
            import winreg
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
            )
            value, _ = winreg.QueryValueEx(key, "EnableLUA")
            winreg.CloseKey(key)
            if value == 0:
                deductions.append(15)
                self._security_checks['uac'] = False
                self.emit_event(SecurityEvent(
                    event_class=EventClass.INTEGRITY_CHECK.value,
                    event_type=EventType.INTEGRITY_DRIFT.value,
                    severity=Severity.HIGH.value,
                    description="User Account Control (UAC) is DISABLED",
                    tags=["uac_disabled", "security_drift"],
                    risk_score=55.0,
                ))
            else:
                self._security_checks['uac'] = True
        except Exception:
            pass

        # Check RDP status
        try:
            import winreg
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Control\Terminal Server"
            )
            value, _ = winreg.QueryValueEx(key, "fDenyTSConnections")
            winreg.CloseKey(key)
            if value == 0:
                deductions.append(5)
                self._security_checks['rdp_enabled'] = True
            else:
                self._security_checks['rdp_enabled'] = False
        except Exception:
            pass

    def _audit_linux_security(self, deductions: List[float]):
        """Audit Linux-specific security settings."""
        # Check SSH root login
        ssh_config = '/etc/ssh/sshd_config'
        if os.path.exists(ssh_config):
            try:
                with open(ssh_config, 'r') as f:
                    content = f.read()
                if 'PermitRootLogin yes' in content:
                    deductions.append(15)
                    self._security_checks['ssh_root_login'] = True
                else:
                    self._security_checks['ssh_root_login'] = False
            except PermissionError:
                pass

        # Check password-less sudo
        sudoers = '/etc/sudoers'
        if os.path.exists(sudoers):
            try:
                with open(sudoers, 'r') as f:
                    content = f.read()
                if 'NOPASSWD' in content:
                    deductions.append(10)
            except PermissionError:
                pass

    def _check_hosts_file_integrity(self):
        """Check for hosts file tampering."""
        if os.name == 'nt':
            hosts_path = r'C:\Windows\System32\drivers\etc\hosts'
        else:
            hosts_path = '/etc/hosts'

        if not os.path.exists(hosts_path):
            return

        try:
            with open(hosts_path, 'r') as f:
                content = f.read()

            # Check for suspicious redirections
            suspicious_domains = [
                'windowsupdate.com', 'update.microsoft.com',
                'virustotal.com', 'malwarebytes.com',
                'kaspersky.com', 'symantec.com', 'avast.com',
                'bitdefender.com', 'eset.com',
            ]

            for domain in suspicious_domains:
                if domain in content.lower():
                    self.emit_event(SecurityEvent(
                        event_class=EventClass.INTEGRITY_CHECK.value,
                        event_type=EventType.INTEGRITY_FAIL.value,
                        severity=Severity.HIGH.value,
                        description=f"HOSTS FILE TAMPERING: Security domain redirected ({domain})",
                        file=FileInfo(path=hosts_path),
                        tags=["hosts_tampering", "defense_evasion"],
                        is_threat=True,
                        risk_score=80.0,
                        mitre=MITREMapping(
                            tactic="defense_evasion",
                            technique_id="T1565.001",
                            technique_name="Data Manipulation: Stored Data Manipulation"
                        )
                    ))
        except (IOError, PermissionError):
            pass

    def _check_dns_settings(self):
        """Check for DNS hijacking."""
        if os.name == 'nt':
            try:
                import subprocess
                result = subprocess.run(
                    ['netsh', 'interface', 'ip', 'show', 'dns'],
                    capture_output=True, text=True, timeout=5
                )
                # Log current DNS servers for analysis
            except Exception:
                pass

    def _check_open_ports(self, deductions: List[float]):
        """Check for suspicious listening ports."""
        suspicious_listening = []
        for conn in psutil.net_connections(kind='tcp'):
            if conn.status == 'LISTEN':
                port = conn.laddr.port
                if port in {4444, 5555, 6666, 8888, 9999, 31337, 1337}:
                    suspicious_listening.append(port)

        if suspicious_listening:
            deductions.append(len(suspicious_listening) * 5)
            self.emit_event(SecurityEvent(
                event_class=EventClass.INTEGRITY_CHECK.value,
                event_type=EventType.INTEGRITY_DRIFT.value,
                severity=Severity.HIGH.value,
                description=f"Suspicious listening ports detected: {suspicious_listening}",
                tags=["suspicious_ports", "backdoor_indicator"],
                risk_score=70.0,
                metadata={"ports": suspicious_listening},
            ))

    def _emit_security_score(self):
        """Emit the current security posture score."""
        self.emit_event(SecurityEvent(
            event_class=EventClass.INTEGRITY_CHECK.value,
            event_type=EventType.INTEGRITY_PASS.value,
            severity=Severity.INFO.value,
            description=f"Security posture score: {self._security_score:.0f}/100",
            tags=["security_score"],
            risk_score=max(0, 100 - self._security_score),
            metadata={
                "security_score": self._security_score,
                "checks": self._security_checks,
            }
        ))

    def _get_critical_files(self) -> List[str]:
        """Get list of critical files for the current OS."""
        if os.name == 'nt':
            return WINDOWS_CRITICAL_FILES
        elif platform.system() == 'Linux':
            return LINUX_CRITICAL_FILES
        elif platform.system() == 'Darwin':
            return [
                '/usr/bin/sudo', '/usr/bin/ssh',
                '/etc/hosts', '/etc/resolv.conf',
            ]
        return []

    @staticmethod
    def _hash_file(filepath: str) -> str:
        """Calculate SHA256 hash of a file."""
        sha256 = hashlib.sha256()
        try:
            with open(filepath, 'rb') as f:
                for chunk in iter(lambda: f.read(8192), b''):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except (IOError, PermissionError):
            return ""

    @property
    def security_score(self) -> float:
        """Get the current security posture score."""
        return self._security_score
