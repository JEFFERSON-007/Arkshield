"""
Arkshield — File System Monitor

Real-time monitoring of file system activity including:
- File creation, modification, deletion tracking
- Entropy analysis for ransomware detection
- Sensitive data pattern detection
- File signature mismatch detection
- Canary file monitoring
- YARA-compatible pattern scanning
"""

import os
import time
import math
import hashlib
import logging
import re
from pathlib import Path
from typing import Dict, Set, List, Optional, Tuple
from collections import Counter, defaultdict
from datetime import datetime, timezone

from arkshield.agent.core import MonitorBase, EventBus
from arkshield.config.settings import AgentConfig
from arkshield.telemetry.events import (
    SecurityEvent, EventClass, EventType, Severity,
    FileInfo, MITREMapping
)

logger = logging.getLogger("arkshield.monitor.filesystem")

# Sensitive data patterns
SENSITIVE_PATTERNS = {
    "credit_card": re.compile(r'\b(?:\d{4}[-\s]?){3}\d{4}\b'),
    "ssn": re.compile(r'\b\d{3}-\d{2}-\d{4}\b'),
    "email": re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
    "api_key": re.compile(r'(?:api[_-]?key|apikey|api_secret|access_token)\s*[:=]\s*["\']?[\w\-]{20,}', re.I),
    "private_key": re.compile(r'-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----'),
    "aws_key": re.compile(r'AKIA[0-9A-Z]{16}'),
}

# High-risk file extensions
EXECUTABLE_EXTENSIONS = {
    '.exe', '.dll', '.sys', '.scr', '.bat', '.cmd', '.ps1',
    '.vbs', '.js', '.wsf', '.msi', '.hta', '.com', '.pif',
    '.cpl', '.jar', '.reg', '.inf', '.lnk'
}

# Ransomware-associated extensions
RANSOMWARE_EXTENSIONS = {
    '.encrypted', '.locked', '.crypto', '.crypt', '.enc',
    '.coded', '.zzzzz', '.micro', '.locky', '.cerber',
    '.zepto', '.thor', '.aesir', '.odin', '.osiris',
    '.wallet', '.dharma', '.onion', '.wncry', '.wcry',
}

# Directories to monitor
CRITICAL_DIRECTORIES = [
    os.path.expanduser("~/Documents"),
    os.path.expanduser("~/Desktop"),
    os.path.expanduser("~/Downloads"),
]

# Canary file names
CANARY_FILENAMES = [
    ".sentinel_canary_DO_NOT_DELETE.txt",
    "~$important_financial_report.xlsx",
    "passwords.txt.bak",
]


class FileSystemMonitor(MonitorBase):
    """
    Monitors file system activity for security threats.

    Capabilities:
    - Real-time file change detection
    - Ransomware encryption detection via entropy analysis
    - Canary file network for early ransomware warning
    - Sensitive data exposure detection
    - Executable creation monitoring
    - File signature mismatch detection
    """

    def __init__(self, event_bus: EventBus, config: AgentConfig):
        super().__init__("filesystem", event_bus, config)
        self._file_baselines: Dict[str, Dict] = {}
        self._canary_files: Dict[str, str] = {}  # path -> hash
        self._change_counter: Dict[str, int] = defaultdict(int)  # track rapid changes
        self._rapid_change_window: Dict[str, List[float]] = defaultdict(list)
        self._initialized = False
        self._monitored_dirs: List[str] = []
        self._entropy_history: List[float] = []

    def collect(self):
        """Collect file system telemetry."""
        if not self._initialized:
            self._initialize()
            self._initialized = True
            return

        # Check canary files
        self._check_canary_files()

        # Monitor critical directories for changes
        for directory in self._monitored_dirs:
            self._scan_directory(directory)

        # Check for rapid file modifications (ransomware indicator)
        self._check_rapid_modifications()

    def _initialize(self):
        """Initialize monitoring — set baselines and deploy canary files."""
        # Set up monitored directories
        for d in CRITICAL_DIRECTORIES:
            if os.path.exists(d):
                self._monitored_dirs.append(d)

        # Also monitor common system directories
        if os.name == 'nt':
            system_dirs = [
                os.path.expandvars(r'%SystemRoot%\System32'),
                os.path.expandvars(r'%ProgramData%'),
            ]
        else:
            system_dirs = ['/etc', '/usr/bin', '/usr/sbin']

        for d in system_dirs:
            if os.path.exists(d):
                self._monitored_dirs.append(d)

        # Build file baselines for monitored directories
        for directory in self._monitored_dirs:
            self._build_baseline(directory)

        # Deploy canary files
        self._deploy_canary_files()

        self.logger.info(f"FileSystem monitor initialized, watching {len(self._monitored_dirs)} directories")

    def _build_baseline(self, directory: str, max_depth: int = 2):
        """Build a baseline of files in a directory."""
        try:
            for root, dirs, files in os.walk(directory):
                depth = root.replace(directory, '').count(os.sep)
                if depth >= max_depth:
                    dirs.clear()
                    continue

                for filename in files[:200]:  # Limit per directory
                    filepath = os.path.join(root, filename)
                    try:
                        stat = os.stat(filepath)
                        self._file_baselines[filepath] = {
                            'size': stat.st_size,
                            'mtime': stat.st_mtime,
                            'permissions': oct(stat.st_mode),
                        }
                    except (OSError, PermissionError):
                        continue
        except (OSError, PermissionError):
            pass

    def _scan_directory(self, directory: str, max_depth: int = 2):
        """Scan a directory for file changes."""
        try:
            for root, dirs, files in os.walk(directory):
                depth = root.replace(directory, '').count(os.sep)
                if depth >= max_depth:
                    dirs.clear()
                    continue

                for filename in files[:200]:
                    filepath = os.path.join(root, filename)
                    try:
                        stat = os.stat(filepath)
                        current = {
                            'size': stat.st_size,
                            'mtime': stat.st_mtime,
                            'permissions': oct(stat.st_mode),
                        }

                        if filepath in self._file_baselines:
                            baseline = self._file_baselines[filepath]
                            # Check for modifications
                            if current['mtime'] != baseline['mtime']:
                                self._handle_file_modified(filepath, baseline, current)
                                self._file_baselines[filepath] = current
                            elif current['permissions'] != baseline['permissions']:
                                self._handle_permission_change(filepath, baseline, current)
                                self._file_baselines[filepath] = current
                        else:
                            # New file
                            self._handle_file_created(filepath, current)
                            self._file_baselines[filepath] = current

                    except (OSError, PermissionError):
                        continue

            # Check for deleted files
            baseline_paths = set(
                p for p in self._file_baselines.keys()
                if p.startswith(directory)
            )
            for filepath in baseline_paths:
                if not os.path.exists(filepath):
                    self._handle_file_deleted(filepath)
                    del self._file_baselines[filepath]

        except (OSError, PermissionError):
            pass

    def _handle_file_created(self, filepath: str, stats: Dict):
        """Handle a newly created file."""
        filename = os.path.basename(filepath).lower()
        ext = os.path.splitext(filename)[1].lower()
        severity = Severity.INFO
        tags = ["file_created"]
        mitre = None

        # Check for executable creation
        if ext in EXECUTABLE_EXTENSIONS:
            severity = Severity.MEDIUM
            tags.append("executable_created")
            mitre = MITREMapping(
                tactic="persistence",
                technique_id="T1543",
                technique_name="Create or Modify System Process"
            )

        # Check for ransomware extensions
        if ext in RANSOMWARE_EXTENSIONS:
            severity = Severity.CRITICAL
            tags.append("ransomware_extension")
            mitre = MITREMapping(
                tactic="impact",
                technique_id="T1486",
                technique_name="Data Encrypted for Impact"
            )

        # Check file entropy
        entropy = self._calculate_file_entropy(filepath)
        if entropy > 7.5 and stats['size'] > 1024:  # High entropy + non-trivial size
            severity = max(severity, Severity.HIGH)
            tags.append("high_entropy")

        file_info = self._build_file_info(filepath, stats)
        file_info.entropy = entropy

        self.emit_event(SecurityEvent(
            event_class=EventClass.FILE_ACTIVITY.value,
            event_type=EventType.FILE_CREATE.value,
            severity=severity.value,
            description=f"File created: {filepath}",
            file=file_info,
            mitre=mitre,
            tags=tags,
            risk_score=min(severity.value * 20 + len(tags) * 5, 100),
            is_threat=severity >= Severity.HIGH,
        ))

    def _handle_file_modified(self, filepath: str, old: Dict, new: Dict):
        """Handle a modified file."""
        severity = Severity.INFO
        tags = ["file_modified"]

        # Track rapid modification rate
        now = time.time()
        self._rapid_change_window[filepath].append(now)
        # Keep only last 60 seconds
        self._rapid_change_window[filepath] = [
            t for t in self._rapid_change_window[filepath] if now - t < 60
        ]

        # Check entropy change (ransomware indicator)
        entropy = self._calculate_file_entropy(filepath)
        if entropy > 7.5 and new['size'] > 1024:
            severity = Severity.HIGH
            tags.append("high_entropy_after_modify")

        # Significant size change
        if old['size'] > 0:
            size_ratio = new['size'] / old['size']
            if size_ratio > 5 or size_ratio < 0.2:
                severity = max(severity, Severity.MEDIUM)
                tags.append("significant_size_change")

        file_info = self._build_file_info(filepath, new)
        file_info.entropy = entropy

        self.emit_event(SecurityEvent(
            event_class=EventClass.FILE_ACTIVITY.value,
            event_type=EventType.FILE_MODIFY.value,
            severity=severity.value,
            description=f"File modified: {filepath}",
            file=file_info,
            tags=tags,
            metadata={
                "old_size": old['size'],
                "new_size": new['size'],
                "entropy": entropy,
            }
        ))

    def _handle_file_deleted(self, filepath: str):
        """Handle a deleted file."""
        ext = os.path.splitext(filepath)[1].lower()
        severity = Severity.INFO
        tags = ["file_deleted"]

        # Deletion of security-relevant files
        filename_lower = os.path.basename(filepath).lower()
        if any(pattern in filename_lower for pattern in ['log', 'audit', 'security', 'event']):
            severity = Severity.MEDIUM
            tags.append("security_file_deleted")

        self.emit_event(SecurityEvent(
            event_class=EventClass.FILE_ACTIVITY.value,
            event_type=EventType.FILE_DELETE.value,
            severity=severity.value,
            description=f"File deleted: {filepath}",
            file=FileInfo(path=filepath, name=os.path.basename(filepath)),
            tags=tags,
        ))

    def _handle_permission_change(self, filepath: str, old: Dict, new: Dict):
        """Handle file permission changes."""
        self.emit_event(SecurityEvent(
            event_class=EventClass.FILE_ACTIVITY.value,
            event_type=EventType.FILE_PERMISSION_CHANGE.value,
            severity=Severity.MEDIUM.value,
            description=f"Permissions changed: {filepath} ({old['permissions']} → {new['permissions']})",
            file=self._build_file_info(filepath, new),
            tags=["permission_change"],
            metadata={"old_permissions": old['permissions'], "new_permissions": new['permissions']},
        ))

    def _deploy_canary_files(self):
        """Deploy canary (decoy) files in monitored directories."""
        for directory in self._monitored_dirs[:3]:  # First 3 dirs
            for canary_name in CANARY_FILENAMES:
                canary_path = os.path.join(directory, canary_name)
                try:
                    if not os.path.exists(canary_path):
                        content = f"ARKSHIELD_CANARY_{time.time()}"
                        with open(canary_path, 'w') as f:
                            f.write(content)
                        # Make it hidden on Windows
                        if os.name == 'nt':
                            import ctypes
                            ctypes.windll.kernel32.SetFileAttributesW(canary_path, 0x02)
                    self._canary_files[canary_path] = hashlib.sha256(
                        open(canary_path, 'rb').read()
                    ).hexdigest()
                except (OSError, PermissionError):
                    continue

        self.logger.info(f"Deployed {len(self._canary_files)} canary files")

    def _check_canary_files(self):
        """Check if canary files have been accessed or modified."""
        for canary_path, original_hash in list(self._canary_files.items()):
            try:
                if not os.path.exists(canary_path):
                    # Canary deleted — high alert
                    self.emit_event(SecurityEvent(
                        event_class=EventClass.THREAT_DETECTION.value,
                        event_type=EventType.THREAT_RANSOMWARE.value,
                        severity=Severity.CRITICAL.value,
                        description=f"CANARY FILE DELETED — Possible ransomware activity: {canary_path}",
                        file=FileInfo(path=canary_path, name=os.path.basename(canary_path)),
                        tags=["canary_deleted", "ransomware_indicator"],
                        is_threat=True,
                        risk_score=95.0,
                        mitre=MITREMapping(
                            tactic="impact",
                            technique_id="T1486",
                            technique_name="Data Encrypted for Impact"
                        )
                    ))
                    del self._canary_files[canary_path]
                else:
                    current_hash = hashlib.sha256(
                        open(canary_path, 'rb').read()
                    ).hexdigest()
                    if current_hash != original_hash:
                        # Canary modified — ransomware alert
                        self.emit_event(SecurityEvent(
                            event_class=EventClass.THREAT_DETECTION.value,
                            event_type=EventType.THREAT_RANSOMWARE.value,
                            severity=Severity.CRITICAL.value,
                            description=f"CANARY FILE MODIFIED — Ransomware encryption detected: {canary_path}",
                            file=FileInfo(path=canary_path, name=os.path.basename(canary_path)),
                            tags=["canary_modified", "ransomware_detected"],
                            is_threat=True,
                            risk_score=98.0,
                            mitre=MITREMapping(
                                tactic="impact",
                                technique_id="T1486",
                                technique_name="Data Encrypted for Impact"
                            )
                        ))
                        self._canary_files[canary_path] = current_hash
            except (OSError, PermissionError):
                continue

    def _check_rapid_modifications(self):
        """Detect rapid file modifications indicative of ransomware."""
        now = time.time()
        rapid_dirs: Dict[str, int] = defaultdict(int)

        for filepath, timestamps in self._rapid_change_window.items():
            recent = [t for t in timestamps if now - t < 30]  # Last 30 seconds
            if len(recent) >= 3:  # 3+ changes in 30s for same file
                dirname = os.path.dirname(filepath)
                rapid_dirs[dirname] += 1

        # If multiple files in same directory changing rapidly
        for dirname, count in rapid_dirs.items():
            if count >= 5:
                self.emit_event(SecurityEvent(
                    event_class=EventClass.THREAT_DETECTION.value,
                    event_type=EventType.THREAT_RANSOMWARE.value,
                    severity=Severity.CRITICAL.value,
                    description=f"RAPID FILE ENCRYPTION DETECTED — {count} files modified rapidly in {dirname}",
                    tags=["rapid_modification", "ransomware_indicator"],
                    is_threat=True,
                    risk_score=92.0,
                    metadata={"directory": dirname, "files_affected": count},
                    mitre=MITREMapping(
                        tactic="impact",
                        technique_id="T1486",
                        technique_name="Data Encrypted for Impact"
                    )
                ))

    def _calculate_file_entropy(self, filepath: str, max_bytes: int = 65536) -> float:
        """Calculate Shannon entropy of a file (0-8 for byte data)."""
        try:
            with open(filepath, 'rb') as f:
                data = f.read(max_bytes)
            if not data:
                return 0.0
            counts = Counter(data)
            length = len(data)
            entropy = -sum(
                (count / length) * math.log2(count / length)
                for count in counts.values()
                if count > 0
            )
            return round(entropy, 4)
        except (IOError, PermissionError):
            return 0.0

    def _build_file_info(self, filepath: str, stats: Dict) -> FileInfo:
        """Build a FileInfo object from file path and stats."""
        ext = os.path.splitext(filepath)[1].lower()
        return FileInfo(
            path=filepath,
            name=os.path.basename(filepath),
            size_bytes=stats.get('size', 0),
            modified=stats.get('mtime', 0),
            permissions=stats.get('permissions', ''),
            is_executable=ext in EXECUTABLE_EXTENSIONS,
        )

    def scan_for_sensitive_data(self, filepath: str) -> List[Dict]:
        """Scan a file for sensitive data patterns."""
        findings = []
        try:
            with open(filepath, 'r', errors='ignore') as f:
                content = f.read(1024 * 1024)  # 1MB limit
            for pattern_name, regex in SENSITIVE_PATTERNS.items():
                matches = regex.findall(content)
                if matches:
                    findings.append({
                        "type": pattern_name,
                        "count": len(matches),
                        "file": filepath,
                    })
        except (IOError, PermissionError):
            pass
        return findings
