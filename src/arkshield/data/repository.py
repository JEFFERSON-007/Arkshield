"""
Arkshield — Data Repository

SQLites-based storage layer for security events, alerts, and agent status.
Provides a persistent record for forensics and long-term analysis.
"""

import sqlite3
import json
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone

from arkshield.telemetry.events import SecurityEvent, Alert

logger = logging.getLogger("arkshield.data.repository")

class DataRepository:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self._init_db()

    def _get_connection(self):
        return sqlite3.connect(self.db_path)

    def _init_db(self):
        """Initialize the database schema."""
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            # Events table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS events (
                    event_id TEXT PRIMARY KEY,
                    timestamp TEXT,
                    event_class TEXT,
                    event_type TEXT,
                    severity INTEGER,
                    is_threat BOOLEAN,
                    risk_score REAL,
                    data TEXT
                )
            ''')
            
            # Alerts table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS alerts (
                    alert_id TEXT PRIMARY KEY,
                    created_at TEXT,
                    title TEXT,
                    severity INTEGER,
                    status TEXT,
                    risk_score REAL,
                    event_ids TEXT,
                    data TEXT
                )
            ''')
            
            # Create indexes
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_events_class ON events(event_class)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status)')
            
            conn.commit()

    def save_event(self, event: SecurityEvent):
        """Save a security event to the database."""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO events (event_id, timestamp, event_class, event_type, severity, is_threat, risk_score, data)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    event.event_id,
                    event.timestamp,
                    event.event_class,
                    event.event_type,
                    event.severity,
                    event.is_threat,
                    event.risk_score,
                    json.dumps(event.to_dict())
                ))
                conn.commit()
        except Exception as e:
            logger.error(f"Failed to save event {event.event_id}: {e}")

    def save_alert(self, alert: Alert):
        """Save a security alert to the database."""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO alerts (alert_id, created_at, title, severity, status, risk_score, event_ids, data)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    alert.alert_id,
                    alert.created_at,
                    alert.title,
                    alert.severity,
                    alert.status,
                    alert.risk_score,
                    json.dumps(alert.event_ids),
                    json.dumps(alert.to_dict())
                ))
                conn.commit()
        except Exception as e:
            logger.error(f"Failed to save alert {alert.alert_id}: {e}")

    def get_recent_events(self, limit: int = 100) -> List[SecurityEvent]:
        """Retrieve recent events."""
        events = []
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT data FROM events ORDER BY timestamp DESC LIMIT ?', (limit,))
                for row in cursor.fetchall():
                    events.append(SecurityEvent.from_dict(json.loads(row[0])))
        except Exception as e:
            logger.error(f"Failed to retrieve events: {e}")
        return events

    def get_recent_alerts(self, limit: int = 50) -> List[Alert]:
        """Retrieve recent alerts."""
        alerts = []
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT data FROM alerts ORDER BY created_at DESC LIMIT ?', (limit,))
                for row in cursor.fetchall():
                    alerts.append(Alert.from_dict(json.loads(row[0])))
        except Exception as e:
            logger.error(f"Failed to retrieve alerts: {e}")
        return alerts

    def get_alerts_by_status(self, status: str) -> List[Alert]:
        """Retrieve alerts by status."""
        alerts = []
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT data FROM alerts WHERE status = ? ORDER BY created_at DESC', (status,))
                for row in cursor.fetchall():
                    alerts.append(Alert.from_dict(json.loads(row[0])))
        except Exception as e:
            logger.error(f"Failed to retrieve alerts: {e}")
        return alerts
