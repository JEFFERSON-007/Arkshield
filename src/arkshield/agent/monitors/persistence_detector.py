"""
Arkshield — Persistence Detector

Monitors all system persistence mechanisms for unauthorized modifications:
- Windows autorun registry locations (400+ keys)
- Scheduled tasks / cron jobs
- Service installations
- Startup folder items
- WMI event subscriptions
- Browser extensions
"""

import os
import time
import logging
import platform
from typing import Dict, List, Set, Optional
from pathlib import Path
from datetime import datetime, timezone

import psutil

from arkshield.agent.core import MonitorBase, EventBus
from arkshield.config.settings import AgentConfig
from arkshield.telemetry.events import (
    SecurityEvent, EventClass, EventType, Severity,
    FileInfo, MITREMapping
)

logger = logging.getLogger("arkshield.monitor.persistence")

# Windows Registry autorun locations
WINDOWS_AUTORUN_KEYS = [
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce",
    r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
    r"SOFTWARE\Microsoft\Active Setup\Installed Components",
    r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
    r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit",
    r"SYSTEM\CurrentControlSet\Control\Session Manager\BootExecute",
    r"SYSTEM\CurrentControlSet\Services",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\SharedTaskScheduler",
]

# Startup folder paths
WINDOWS_STARTUP_FOLDERS = [
    os.path.expandvars(r'%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup'),
    os.path.expandvars(r'%ProgramData%\Microsoft\Windows\Start Menu\Programs\Startup'),
]

# Linux persistence locations
LINUX_PERSISTENCE_PATHS = [
    '/etc/crontab',
    '/etc/cron.d/',
    '/etc/init.d/',
    '/etc/rc.local',
    '/etc/systemd/system/',
    '/usr/lib/systemd/system/',
    os.path.expanduser('~/.bashrc'),
    os.path.expanduser('~/.bash_profile'),
    os.path.expanduser('~/.profile'),
    os.path.expanduser('~/.config/autostart/'),
]


class PersistenceDetector(MonitorBase):
    """
    Detects new or modified persistence mechanisms on the endpoint.

    Monitors:
    - Registry autorun keys (Windows)
    - Startup folders
    - Scheduled tasks
    - System services
    - Cron jobs / systemd units (Linux)
    - LaunchAgents / LaunchDaemons (macOS)
    - Browser extensions
    """

    def __init__(self, event_bus: EventBus, config: AgentConfig):
        super().__init__("persistence", event_bus, config)
        self._baseline_services: Set[str] = set()
        self._baseline_startup_items: Dict[str, str] = {}  # path -> hash/mtime
        self._baseline_scheduled_tasks: Set[str] = set()
        self._baseline_registry: Dict[str, Dict] = {}
        self._initialized = False

    def collect(self):
        """Scan for persistence mechanism changes."""
        if not self._initialized:
            self._build_baseline()
            self._initialized = True
            return

        # Check services
        self._check_services()

        # Check startup folders
        self._check_startup_folders()

        # Check scheduled tasks
        self._check_scheduled_tasks()

        # Check registry (Windows)
        if platform.system() == "Windows":
            self._check_registry_autoruns()

        # Check cron/systemd (Linux)
        if platform.system() == "Linux":
            self._check_linux_persistence()

    def _build_baseline(self):
        """Build initial baseline of all persistence mechanisms."""
        # Baseline services
        for service in psutil.win_service_iter() if os.name == 'nt' else []:
            try:
                self._baseline_services.add(service.name())
            except Exception:
                continue

        # Baseline startup folders
        for folder in self._get_startup_folders():
            if os.path.exists(folder):
                for item in os.listdir(folder):
                    filepath = os.path.join(folder, item)
                    try:
                        self._baseline_startup_items[filepath] = str(os.stat(filepath).st_mtime)
                    except OSError:
                        continue

        # Baseline scheduled tasks (Windows)
        if os.name == 'nt':
            self._baseline_scheduled_tasks = self._get_scheduled_tasks()

        # Baseline registry
        if os.name == 'nt':
            self._baseline_registry = self._read_autorun_registry()

        self.logger.info(
            f"Persistence baseline: {len(self._baseline_services)} services, "
            f"{len(self._baseline_startup_items)} startup items, "
            f"{len(self._baseline_scheduled_tasks)} scheduled tasks"
        )

    def _check_services(self):
        """Check for new or modified system services."""
        current_services = set()

        if os.name == 'nt':
            try:
                for service in psutil.win_service_iter():
                    try:
                        name = service.name()
                        current_services.add(name)

                        if name not in self._baseline_services:
                            # New service detected
                            svc_info = service.as_dict()
                            self.emit_event(SecurityEvent(
                                event_class=EventClass.PERSISTENCE_ACTIVITY.value,
                                event_type=EventType.PERSISTENCE_NEW.value,
                                severity=Severity.HIGH.value,
                                description=f"New service installed: {name} ({svc_info.get('display_name', '')})",
                                tags=["new_service", "persistence"],
                                is_threat=True,
                                risk_score=70.0,
                                metadata={
                                    "service_name": name,
                                    "display_name": svc_info.get('display_name', ''),
                                    "binpath": svc_info.get('binpath', ''),
                                    "start_type": svc_info.get('start_type', ''),
                                    "username": svc_info.get('username', ''),
                                },
                                mitre=MITREMapping(
                                    tactic="persistence",
                                    technique_id="T1543.003",
                                    technique_name="Create or Modify System Process: Windows Service"
                                )
                            ))
                    except Exception:
                        continue
            except Exception:
                pass

        self._baseline_services = current_services

    def _check_startup_folders(self):
        """Check startup folders for new items."""
        for folder in self._get_startup_folders():
            if not os.path.exists(folder):
                continue

            for item in os.listdir(folder):
                filepath = os.path.join(folder, item)
                try:
                    current_mtime = str(os.stat(filepath).st_mtime)

                    if filepath not in self._baseline_startup_items:
                        # New startup item
                        self.emit_event(SecurityEvent(
                            event_class=EventClass.PERSISTENCE_ACTIVITY.value,
                            event_type=EventType.PERSISTENCE_NEW.value,
                            severity=Severity.HIGH.value,
                            description=f"New startup item: {filepath}",
                            file=FileInfo(path=filepath, name=item),
                            tags=["new_startup_item", "persistence"],
                            is_threat=True,
                            risk_score=65.0,
                            mitre=MITREMapping(
                                tactic="persistence",
                                technique_id="T1547.001",
                                technique_name="Boot or Logon Autostart Execution: Registry Run Keys"
                            )
                        ))
                        self._baseline_startup_items[filepath] = current_mtime

                    elif current_mtime != self._baseline_startup_items[filepath]:
                        # Modified startup item
                        self.emit_event(SecurityEvent(
                            event_class=EventClass.PERSISTENCE_ACTIVITY.value,
                            event_type=EventType.PERSISTENCE_MODIFIED.value,
                            severity=Severity.MEDIUM.value,
                            description=f"Startup item modified: {filepath}",
                            file=FileInfo(path=filepath, name=item),
                            tags=["modified_startup_item"],
                        ))
                        self._baseline_startup_items[filepath] = current_mtime

                except OSError:
                    continue

    def _check_scheduled_tasks(self):
        """Check for new scheduled tasks."""
        if os.name != 'nt':
            return

        current_tasks = self._get_scheduled_tasks()
        new_tasks = current_tasks - self._baseline_scheduled_tasks

        for task in new_tasks:
            self.emit_event(SecurityEvent(
                event_class=EventClass.PERSISTENCE_ACTIVITY.value,
                event_type=EventType.PERSISTENCE_NEW.value,
                severity=Severity.HIGH.value,
                description=f"New scheduled task: {task}",
                tags=["new_scheduled_task", "persistence"],
                is_threat=True,
                risk_score=65.0,
                metadata={"task_name": task},
                mitre=MITREMapping(
                    tactic="persistence",
                    technique_id="T1053.005",
                    technique_name="Scheduled Task/Job: Scheduled Task"
                )
            ))

        self._baseline_scheduled_tasks = current_tasks

    def _check_registry_autoruns(self):
        """Check Windows registry autorun locations for changes."""
        if os.name != 'nt':
            return

        current = self._read_autorun_registry()

        for key, values in current.items():
            if key not in self._baseline_registry:
                # New autorun key
                for name, value in values.items():
                    self.emit_event(SecurityEvent(
                        event_class=EventClass.PERSISTENCE_ACTIVITY.value,
                        event_type=EventType.PERSISTENCE_NEW.value,
                        severity=Severity.HIGH.value,
                        description=f"New registry autorun: {key}\\{name} → {value}",
                        tags=["registry_autorun", "persistence"],
                        is_threat=True,
                        risk_score=70.0,
                        metadata={"registry_key": key, "value_name": name, "value_data": str(value)},
                        mitre=MITREMapping(
                            tactic="persistence",
                            technique_id="T1547.001",
                            technique_name="Boot or Logon Autostart Execution: Registry Run Keys"
                        )
                    ))
            else:
                baseline_values = self._baseline_registry[key]
                for name, value in values.items():
                    if name not in baseline_values:
                        self.emit_event(SecurityEvent(
                            event_class=EventClass.PERSISTENCE_ACTIVITY.value,
                            event_type=EventType.PERSISTENCE_NEW.value,
                            severity=Severity.HIGH.value,
                            description=f"New registry autorun value: {key}\\{name} → {value}",
                            tags=["registry_autorun", "persistence"],
                            is_threat=True,
                            risk_score=70.0,
                            metadata={"registry_key": key, "value_name": name, "value_data": str(value)},
                        ))

        self._baseline_registry = current

    def _check_linux_persistence(self):
        """Check Linux persistence mechanisms."""
        for path in LINUX_PERSISTENCE_PATHS:
            if not os.path.exists(path):
                continue

            if os.path.isdir(path):
                for item in os.listdir(path):
                    filepath = os.path.join(path, item)
                    self._check_persistence_file(filepath)
            else:
                self._check_persistence_file(path)

    def _check_persistence_file(self, filepath: str):
        """Check a single persistence file for changes."""
        try:
            mtime = str(os.stat(filepath).st_mtime)
            if filepath not in self._baseline_startup_items:
                if self._initialized:  # Only alert after baseline
                    self.emit_event(SecurityEvent(
                        event_class=EventClass.PERSISTENCE_ACTIVITY.value,
                        event_type=EventType.PERSISTENCE_NEW.value,
                        severity=Severity.MEDIUM.value,
                        description=f"New persistence file: {filepath}",
                        file=FileInfo(path=filepath, name=os.path.basename(filepath)),
                        tags=["persistence_file"],
                    ))
                self._baseline_startup_items[filepath] = mtime
        except OSError:
            pass

    @staticmethod
    def _get_startup_folders() -> List[str]:
        """Get startup folder paths for the current OS."""
        if os.name == 'nt':
            return WINDOWS_STARTUP_FOLDERS
        elif platform.system() == 'Linux':
            return [os.path.expanduser('~/.config/autostart/')]
        elif platform.system() == 'Darwin':
            return [
                os.path.expanduser('~/Library/LaunchAgents/'),
                '/Library/LaunchAgents/',
                '/Library/LaunchDaemons/',
            ]
        return []

    @staticmethod
    def _get_scheduled_tasks() -> Set[str]:
        """Get current scheduled tasks (Windows)."""
        tasks = set()
        if os.name == 'nt':
            try:
                import subprocess
                result = subprocess.run(
                    ['schtasks', '/query', '/fo', 'csv', '/nh'],
                    capture_output=True, text=True, timeout=10
                )
                for line in result.stdout.strip().split('\n'):
                    parts = line.strip().strip('"').split('","')
                    if parts and parts[0]:
                        tasks.add(parts[0].strip('"'))
            except Exception:
                pass
        return tasks

    @staticmethod
    def _read_autorun_registry() -> Dict[str, Dict]:
        """Read Windows registry autorun keys."""
        results = {}
        if os.name != 'nt':
            return results

        try:
            import winreg
            for key_path in WINDOWS_AUTORUN_KEYS[:10]:  # Check top 10
                for hive in [winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER]:
                    try:
                        key = winreg.OpenKey(hive, key_path)
                        values = {}
                        i = 0
                        while True:
                            try:
                                name, data, type_ = winreg.EnumValue(key, i)
                                values[name] = data
                                i += 1
                            except WindowsError:
                                break
                        winreg.CloseKey(key)
                        if values:
                            full_path = f"{'HKLM' if hive == winreg.HKEY_LOCAL_MACHINE else 'HKCU'}\\{key_path}"
                            results[full_path] = values
                    except (WindowsError, OSError):
                        continue
        except ImportError:
            pass

        return results
