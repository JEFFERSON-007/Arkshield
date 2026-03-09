"""
Arkshield — Response Orchestrator

The decision-making component that matches alerts to response actions and playbooks.
"""

import logging
from typing import Dict, Any, Optional

from arkshield.telemetry.events import Alert, Severity
from arkshield.response.playbook_engine import PlaybookEngine
from arkshield.response.actions import kill_process, quarantine_file

logger = logging.getLogger("arkshield.response.orchestrator")

class ResponseOrchestrator:
    def __init__(self, playbook_engine: PlaybookEngine, autonomy_level: int = 2):
        self.playbook_engine = playbook_engine
        self.autonomy_level = autonomy_level

    def handle_alert(self, alert: Alert):
        """Analyze alert and initiate appropriate response."""
        logger.info(f"Orchestrating response for alert: {alert.title} (Severity: {alert.severity})")

        # Context extraction for parameters
        context = {
            "alert_id": alert.alert_id,
        }
        
        # Merge context from associated events
        if alert.source_events:
            primary_event = alert.source_events[0]
            if primary_event.process:
                context["pid"] = primary_event.process.pid
                context["process_name"] = primary_event.process.name
            if primary_event.file:
                context["filepath"] = primary_event.file.path
            if primary_event.network:
                context["remote_ip"] = primary_event.network.remote_ip

        # Basic logic: match category to playbooks
        if "ransomware" in alert.category.lower() or "ransomware" in alert.tags:
            self._trigger_response("ransomware_response", alert, context)
        elif alert.severity >= Severity.HIGH.value:
            # Default response for high severity threats
            if "pid" in context:
                logger.info(f"Mitigating high severity process threat: PID {context['pid']}")
                kill_process(context["pid"])

    def _trigger_response(self, playbook_name: str, alert: Alert, context: Dict[str, Any]):
        """Trigger an autonomous or semi-autonomous response."""
        if self.autonomy_level >= 3:
            # Autonomous mode
            logger.info(f"Triggering AUTONOMOUS response: {playbook_name}")
            self.playbook_engine.execute_playbook(playbook_name, alert, context)
        elif self.autonomy_level >= 2:
            # Semi-autonomous (would wait for user input in full version)
            logger.info(f"Semi-autonomous defense triggered for: {playbook_name}")
            # For demo/MVP, we'll execute but log as semi-autonomous
            self.playbook_engine.execute_playbook(playbook_name, alert, context)
        else:
            logger.info(f"Manual response required for {playbook_name}. Alerting only.")
