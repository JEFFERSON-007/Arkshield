import logging
from typing import Dict, Any, List
import uuid
from datetime import datetime, timezone

from arkshield.agent.core import MonitorBase
from arkshield.telemetry.events import SecurityEvent, EventClass, EventType, Severity

class RegistryMonitor(MonitorBase):
    """
    Monitors Windows Registry for persistence mechanisms.
    """
    
    def __init__(self, event_bus, config):
        super().__init__(name="registry", event_bus=event_bus, config=config)
        self.monitored_keys = [
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        ]
        self._last_state = {}

    def collect(self):
        """Scan critical registry keys for unauthorized persistence mechanisms."""
        # For cross-platform compatibility and demonstration, we simulate registry scanning.
        # In a real environment, this would use the `winreg` module on Windows.
        
        # Simulated registry changes to demonstrate the monitor
        simulated_registry_entries = {
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Windows Defender": "C:\\Program Files\\Windows Defender\\MSASCui.exe",
            r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Updater": "C:\\Users\\Public\\malicious_updater.exe"  # Suspicious
        }
        
        for key in self.monitored_keys:
            # We mock the subkeys found in this registry key
            # Normally we would enumerate the values here
            pass
            
        for path, value in simulated_registry_entries.items():
            if path not in self._last_state or self._last_state[path] != value:
                # We have a new or modified registry key
                self._last_state[path] = value
                
                # Simple heuristic for demonstration: paths in Public or Temp are suspicious
                is_suspicious = "Public" in value or "Temp" in value
                
                if is_suspicious:
                    event = SecurityEvent(
                        event_class=EventClass.SYSTEM.value,
                        event_type=EventType.PERSISTENCE_DETECTED.value,
                        severity=Severity.HIGH.value,
                        description=f"Suspicious registry persistence detected: {path} -> {value}",
                        metadata={
                            "registry_key": path,
                            "registry_value": value,
                            "suspicion_reason": "Executable located in public/temp directory"
                        }
                    )
                    self.emit_event(event)
