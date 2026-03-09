"""
Arkshield — Telemetry Pipeline

Event processing pipeline with:
- Event normalization
- Enrichment with threat intelligence
- Temporal correlation
- Real-Time detection rule evaluation
- Storage dispatch
"""

import time
import logging
import threading
from typing import Dict, List, Optional, Callable, Any
from collections import deque, defaultdict
from datetime import datetime, timezone

from arkshield.telemetry.events import (
    SecurityEvent, Alert, EventClass, EventType, Severity, AlertStatus,
    MITREMapping, ThreatIntel
)

logger = logging.getLogger("arkshield.telemetry.pipeline")


class EventNormalizer:
    """Normalize events into a consistent schema."""

    def normalize(self, event: SecurityEvent) -> SecurityEvent:
        """Ensure all event fields are properly formatted."""
        if not event.event_id:
            import uuid
            event.event_id = str(uuid.uuid4())
        if not event.timestamp:
            event.timestamp = datetime.now(timezone.utc).isoformat()

        # Ensure severity is valid
        if event.severity not in range(5):
            event.severity = Severity.INFO.value

        # Normalize tags to lowercase
        event.tags = [t.lower().strip() for t in event.tags]

        return event


class EventEnricher:
    """Enrich events with additional context and threat intelligence."""

    def __init__(self):
        self._ioc_database: Dict[str, Dict] = {}
        self._known_malicious_ips: set = set()
        self._known_malicious_hashes: set = set()
        self._mitre_technique_map: Dict[str, str] = self._build_mitre_map()

    def enrich(self, event: SecurityEvent) -> SecurityEvent:
        """Enrich an event with threat intelligence."""
        matched_iocs = []

        # Check network IOCs
        if event.network:
            if event.network.remote_ip in self._known_malicious_ips:
                matched_iocs.append(f"ip:{event.network.remote_ip}")
                event.severity = max(event.severity, Severity.HIGH.value)
                event.is_threat = True

        # Check file hash IOCs
        if event.file and event.file.hash_sha256:
            if event.file.hash_sha256 in self._known_malicious_hashes:
                matched_iocs.append(f"hash:{event.file.hash_sha256}")
                event.severity = max(event.severity, Severity.CRITICAL.value)
                event.is_threat = True

        # Apply threat intel enrichment
        if matched_iocs:
            event.threat_intel = ThreatIntel(
                matched_iocs=matched_iocs,
                risk_score=min(len(matched_iocs) * 30, 100),
                confidence=0.95,
            )

        return event

    def add_ioc(self, ioc_type: str, value: str, metadata: Dict = None):
        """Add an Indicator of Compromise to the database."""
        self._ioc_database[f"{ioc_type}:{value}"] = metadata or {}
        if ioc_type == "ip":
            self._known_malicious_ips.add(value)
        elif ioc_type == "hash":
            self._known_malicious_hashes.add(value)

    def _build_mitre_map(self) -> Dict[str, str]:
        """Build a map of common MITRE ATT&CK techniques."""
        return {
            "T1059": "Command and Scripting Interpreter",
            "T1055": "Process Injection",
            "T1486": "Data Encrypted for Impact",
            "T1071": "Application Layer Protocol",
            "T1041": "Exfiltration Over C2 Channel",
            "T1021": "Remote Services",
            "T1547": "Boot or Logon Autostart Execution",
            "T1053": "Scheduled Task/Job",
            "T1543": "Create or Modify System Process",
            "T1027": "Obfuscated Files or Information",
            "T1036": "Masquerading",
            "T1070": "Indicator Removal",
            "T1565": "Data Manipulation",
        }


class EventCorrelator:
    """Correlate events across time and sources to detect attack patterns."""

    def __init__(self, correlation_window: int = 300):
        self._window_seconds = correlation_window
        self._event_buffer: deque = deque(maxlen=10000)
        self._correlation_rules: List[Dict] = self._build_rules()
        self._active_correlations: Dict[str, List[SecurityEvent]] = defaultdict(list)
        self._generated_alerts: List[Alert] = []

    def correlate(self, event: SecurityEvent) -> Optional[Alert]:
        """Process an event through correlation rules."""
        self._event_buffer.append(event)
        self._clean_expired_events()

        # Check each correlation rule
        for rule in self._correlation_rules:
            alert = self._evaluate_rule(rule, event)
            if alert:
                self._generated_alerts.append(alert)
                return alert

        return None

    def _evaluate_rule(self, rule: Dict, trigger_event: SecurityEvent) -> Optional[Alert]:
        """Evaluate a correlation rule against the event buffer."""
        rule_name = rule['name']
        conditions = rule['conditions']
        window = rule.get('window', self._window_seconds)

        # Check if trigger event matches the rule's trigger condition
        trigger_cond = conditions[-1]  # Last condition is typically the trigger
        if not self._event_matches(trigger_event, trigger_cond):
            return None

        # Check if preceding conditions are satisfied in the time window
        now_ts = time.time()
        matched_events = [trigger_event]

        for cond in conditions[:-1]:
            found = False
            for buffered_event in reversed(list(self._event_buffer)):
                try:
                    event_ts = datetime.fromisoformat(
                        buffered_event.timestamp.replace('Z', '+00:00')
                    ).timestamp()
                except (ValueError, AttributeError):
                    event_ts = now_ts

                if now_ts - event_ts > window:
                    break

                if self._event_matches(buffered_event, cond):
                    matched_events.append(buffered_event)
                    found = True
                    break

            if not found:
                return None

        # All conditions met — generate alert
        return Alert(
            title=rule['alert_title'],
            description=rule.get('description', ''),
            severity=rule.get('severity', Severity.HIGH.value),
            category=rule.get('category', 'correlation'),
            event_ids=[e.event_id for e in matched_events],
            source_events=matched_events,
            risk_score=rule.get('risk_score', 75.0),
            confidence=rule.get('confidence', 0.85),
            tags=rule.get('tags', []),
            mitre=MITREMapping(**rule['mitre']) if 'mitre' in rule else None,
        )

    @staticmethod
    def _event_matches(event: SecurityEvent, condition: Dict) -> bool:
        """Check if an event matches a condition."""
        for key, value in condition.items():
            if key == 'event_class' and event.event_class != value:
                return False
            if key == 'event_type' and event.event_type != value:
                return False
            if key == 'min_severity' and event.severity < value:
                return False
            if key == 'has_tag':
                if value not in event.tags:
                    return False
            if key == 'is_threat' and event.is_threat != value:
                return False
        return True

    def _clean_expired_events(self):
        """Remove events outside the correlation window."""
        now = time.time()
        while self._event_buffer:
            oldest = self._event_buffer[0]
            try:
                event_ts = datetime.fromisoformat(
                    oldest.timestamp.replace('Z', '+00:00')
                ).timestamp()
            except (ValueError, AttributeError):
                event_ts = now
            if now - event_ts > self._window_seconds:
                self._event_buffer.popleft()
            else:
                break

    def _build_rules(self) -> List[Dict]:
        """Build default correlation rules."""
        return [
            {
                'name': 'ransomware_attack_chain',
                'alert_title': 'RANSOMWARE ATTACK CHAIN DETECTED',
                'description': 'Multiple ransomware indicators detected in rapid succession',
                'severity': Severity.CRITICAL.value,
                'risk_score': 95.0,
                'confidence': 0.92,
                'category': 'ransomware',
                'tags': ['ransomware', 'attack_chain'],
                'window': 120,
                'mitre': {'tactic': 'impact', 'technique_id': 'T1486', 'technique_name': 'Data Encrypted for Impact'},
                'conditions': [
                    {'event_class': EventClass.FILE_ACTIVITY.value, 'has_tag': 'high_entropy'},
                    {'event_class': EventClass.THREAT_DETECTION.value, 'has_tag': 'ransomware_indicator'},
                ]
            },
            {
                'name': 'lateral_movement_chain',
                'alert_title': 'LATERAL MOVEMENT DETECTED',
                'description': 'Credential access followed by remote service usage',
                'severity': Severity.HIGH.value,
                'risk_score': 80.0,
                'confidence': 0.85,
                'category': 'lateral_movement',
                'tags': ['lateral_movement', 'attack_progression'],
                'window': 300,
                'mitre': {'tactic': 'lateral_movement', 'technique_id': 'T1021', 'technique_name': 'Remote Services'},
                'conditions': [
                    {'event_class': EventClass.PROCESS_ACTIVITY.value, 'has_tag': 'suspicious_cmdline'},
                    {'event_class': EventClass.NETWORK_ACTIVITY.value, 'has_tag': 'potential_lateral_movement'},
                ]
            },
            {
                'name': 'c2_with_execution',
                'alert_title': 'COMMAND & CONTROL WITH CODE EXECUTION',
                'description': 'C2 beacon detected alongside suspicious process execution',
                'severity': Severity.CRITICAL.value,
                'risk_score': 90.0,
                'confidence': 0.88,
                'category': 'c2',
                'tags': ['c2', 'code_execution'],
                'window': 180,
                'mitre': {'tactic': 'command_and_control', 'technique_id': 'T1071', 'technique_name': 'Application Layer Protocol'},
                'conditions': [
                    {'event_class': EventClass.THREAT_DETECTION.value, 'has_tag': 'beacon_detected'},
                    {'event_class': EventClass.PROCESS_ACTIVITY.value, 'has_tag': 'encoded_command'},
                ]
            },
            {
                'name': 'persistence_with_malware',
                'alert_title': 'MALWARE PERSISTENCE ESTABLISHED',
                'description': 'New persistence mechanism created after threat detection',
                'severity': Severity.HIGH.value,
                'risk_score': 82.0,
                'confidence': 0.80,
                'category': 'persistence',
                'tags': ['persistence', 'malware'],
                'window': 600,
                'mitre': {'tactic': 'persistence', 'technique_id': 'T1547', 'technique_name': 'Boot or Logon Autostart Execution'},
                'conditions': [
                    {'event_class': EventClass.PROCESS_ACTIVITY.value, 'is_threat': True},
                    {'event_class': EventClass.PERSISTENCE_ACTIVITY.value, 'has_tag': 'persistence'},
                ]
            },
        ]

    def get_recent_alerts(self) -> List[Alert]:
        """Get recently generated alerts."""
        return list(self._generated_alerts[-50:])


class TelemetryPipeline:
    """
    Main telemetry processing pipeline.
    Events flow: Normalize → Enrich → Correlate → Detect → Store
    """

    def __init__(self):
        self.normalizer = EventNormalizer()
        self.enricher = EventEnricher()
        self.correlator = EventCorrelator()
        self._detection_rules: List[Dict] = self._build_detection_rules()
        self._processed_events: deque = deque(maxlen=50000)
        self._alerts: List[Alert] = []
        self._stats = {
            "events_processed": 0,
            "alerts_generated": 0,
            "threats_detected": 0,
        }
        self._subscribers: List[Callable] = []

    def process_event(self, event: SecurityEvent) -> Optional[Alert]:
        """Process a single event through the full pipeline."""
        # Stage 1: Normalize
        event = self.normalizer.normalize(event)

        # Stage 2: Enrich
        event = self.enricher.enrich(event)

        # Stage 3: Rule-based detection
        alert_from_rules = self._evaluate_detection_rules(event)

        # Stage 4: Correlate
        alert_from_correlation = self.correlator.correlate(event)

        # Stage 5: Store
        self._processed_events.append(event)
        self._stats["events_processed"] += 1

        if event.is_threat:
            self._stats["threats_detected"] += 1

        # Select highest-severity alert
        alert = alert_from_correlation or alert_from_rules
        if alert:
            self._alerts.append(alert)
            self._stats["alerts_generated"] += 1
            # Notify subscribers
            for callback in self._subscribers:
                try:
                    callback(alert)
                except Exception as e:
                    logger.error(f"Alert subscriber error: {e}")

        return alert

    def subscribe_alerts(self, callback: Callable):
        """Subscribe to alert notifications."""
        self._subscribers.append(callback)

    def _evaluate_detection_rules(self, event: SecurityEvent) -> Optional[Alert]:
        """Evaluate detection rules against a single event."""
        for rule in self._detection_rules:
            if self._matches_rule(event, rule):
                return Alert(
                    title=rule['title'],
                    description=rule.get('description', ''),
                    severity=rule.get('severity', Severity.HIGH.value),
                    category=rule.get('category', 'detection'),
                    event_ids=[event.event_id],
                    source_events=[event],
                    risk_score=event.risk_score or rule.get('risk_score', 50.0),
                    confidence=rule.get('confidence', 0.8),
                    tags=rule.get('tags', []),
                )
        return None

    @staticmethod
    def _matches_rule(event: SecurityEvent, rule: Dict) -> bool:
        """Check if an event matches a detection rule."""
        conditions = rule.get('conditions', {})
        for key, value in conditions.items():
            if key == 'min_severity' and event.severity < value:
                return False
            if key == 'event_class' and event.event_class != value:
                return False
            if key == 'is_threat' and event.is_threat != value:
                return False
            if key == 'has_tag':
                if isinstance(value, list):
                    if not any(t in event.tags for t in value):
                        return False
                elif value not in event.tags:
                    return False
            if key == 'min_risk_score' and event.risk_score < value:
                return False
        return True

    def _build_detection_rules(self) -> List[Dict]:
        """Build single-event detection rules."""
        return [
            {
                'title': 'Critical Threat Detected',
                'severity': Severity.CRITICAL.value,
                'category': 'threat',
                'tags': ['critical_threat'],
                'risk_score': 90.0,
                'confidence': 0.9,
                'conditions': {'min_severity': Severity.CRITICAL.value, 'is_threat': True},
            },
            {
                'title': 'Ransomware Activity Detected',
                'severity': Severity.CRITICAL.value,
                'category': 'ransomware',
                'tags': ['ransomware'],
                'risk_score': 95.0,
                'confidence': 0.92,
                'conditions': {'has_tag': ['canary_deleted', 'canary_modified', 'ransomware_detected']},
            },
            {
                'title': 'C2 Beacon Communication',
                'severity': Severity.HIGH.value,
                'category': 'c2',
                'tags': ['c2'],
                'risk_score': 85.0,
                'conditions': {'has_tag': 'beacon_detected'},
            },
            {
                'title': 'System Integrity Violation',
                'severity': Severity.CRITICAL.value,
                'category': 'integrity',
                'tags': ['integrity'],
                'risk_score': 88.0,
                'conditions': {'has_tag': ['integrity_violation', 'critical_file_modified']},
            },
        ]

    @property
    def stats(self) -> Dict[str, int]:
        return dict(self._stats)

    @property
    def alerts(self) -> List[Alert]:
        return list(self._alerts)

    def get_recent_events(self, count: int = 100) -> List[SecurityEvent]:
        return list(self._processed_events)[-count:]

    def get_threat_events(self) -> List[SecurityEvent]:
        return [e for e in self._processed_events if e.is_threat]
