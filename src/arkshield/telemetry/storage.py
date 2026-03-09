"""
Arkshield — Telemetry Storage Writer

Integrates the telemetry pipeline with the data repository.
"""

import logging
from typing import Optional
from arkshield.telemetry.events import SecurityEvent, Alert
from arkshield.data.repository import DataRepository

logger = logging.getLogger("arkshield.telemetry.storage")

class StorageWriter:
    def __init__(self, repository: DataRepository):
        self.repository = repository

    def handle_event(self, event: SecurityEvent):
        """Write event to persistent storage."""
        self.repository.save_event(event)

    def handle_alert(self, alert: Alert):
        """Write alert to persistent storage."""
        self.repository.save_alert(alert)
