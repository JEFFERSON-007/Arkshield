import os
import sys
import logging
from typing import Dict, Any, List
import uuid
from datetime import datetime, timezone

from arkshield.agent.core import MonitorBase
from arkshield.telemetry.events import SecurityEvent, EventClass, EventType, Severity

logger = logging.getLogger("arkshield.monitor.registry")

class RegistryMonitor(MonitorBase):
    """
    Monitors Windows Registry Run and RunOnce keys for persistence mechanisms.
    Reads actual winreg keys on Windows with graceful fallback for simulated/cross-platform checks.
    """
    
    def __init__(self, event_bus, config):
        super().__init__(name="registry", event_bus=event_bus, config=config)
        self.monitored_keys = [
            (r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKLM"),
            (r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM"),
            (r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKCU"),
            (r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU"),
        ]
        self._last_state: Dict[str, str] = {}
        self._has_winreg = False
        try:
            import winreg
            self._winreg = winreg
            self._has_winreg = (os.name == "nt")
        except ImportError:
            self._winreg = None
            self._has_winreg = False

    def collect(self):
        """Scan critical registry keys for unauthorized persistence mechanisms."""
        current_entries: Dict[str, str] = {}

        if self._has_winreg:
            hive_map = {
                "HKLM": self._winreg.HKEY_LOCAL_MACHINE,
                "HKCU": self._winreg.HKEY_CURRENT_USER,
            }
            for subkey, hive_name in self.monitored_keys:
                hive = hive_map.get(hive_name)
                if not hive:
                    continue
                try:
                    with self._winreg.OpenKey(hive, subkey, 0, self._winreg.KEY_READ) as key_handle:
                        index = 0
                        while True:
                            try:
                                name, value, _ = self._winreg.EnumValue(key_handle, index)
                                full_path = f"{hive_name}\\{subkey}\\{name}"
                                current_entries[full_path] = str(value)
                                index += 1
                            except OSError:
                                break
                except (FileNotFoundError, PermissionError, OSError) as e:
                    logger.debug("Could not read registry key %s\\%s: %s", hive_name, subkey, e)
        else:
            # Cross-platform / fallback simulated entries
            current_entries = {
                r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Windows Defender": "C:\\Program Files\\Windows Defender\\MSASCui.exe",
                r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Updater": "C:\\Users\\Public\\malicious_updater.exe",
            }

        # Check for new or modified entries
        for path, value in current_entries.items():
            val_str = str(value)
            val_lower = val_str.lower()
            if path not in self._last_state or self._last_state[path] != val_str:
                self._last_state[path] = val_str
                
                # Suspicious indicators
                is_suspicious = (
                    "public" in val_lower
                    or "temp" in val_lower
                    or "appdata\\local\\temp" in val_lower
                    or "-enc" in val_lower
                    or "powershell" in val_lower and ("hidden" in val_lower or "bypass" in val_lower)
                    or "wscript" in val_lower
                    or "cscript" in val_lower
                    or "cmd.exe /c" in val_lower
                )
                
                if is_suspicious:
                    event = SecurityEvent(
                        event_class=EventClass.REGISTRY_ACTIVITY.value,
                        event_type=EventType.PERSISTENCE_NEW.value,
                        severity=Severity.HIGH.value,
                        description=f"Suspicious registry persistence detected: {path} -> {value}",
                        metadata={
                            "registry_key": path,
                            "registry_value": val_str,
                            "suspicion_reason": "Executable references temporary/public directory or suspicious flags"
                        }
                    )
                    self.emit_event(event)
                    logger.warning("Suspicious persistence detected: %s -> %s", path, val_str)
