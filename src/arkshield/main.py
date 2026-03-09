"""
Arkshield — Main Platform Entry Point

Ties together the agent, telemetry pipeline, AI engine,
data platform, and autonomous response system.
"""

import sys
import os
import signal
import time
import logging
from typing import Optional

from arkshield.config.settings import PlatformConfig
from arkshield.agent.core import NexusSentinelAgent
from arkshield.telemetry.pipeline import TelemetryPipeline
from arkshield.ai.engine import AISecurityEngine
from arkshield.data.repository import DataRepository
from arkshield.telemetry.storage import StorageWriter
from arkshield.response.orchestrator import ResponseOrchestrator
from arkshield.response.playbook_engine import PlaybookEngine
from arkshield.security.deception import DeceptionManager

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("arkshield.log")
    ]
)

logger = logging.getLogger("arkshield.main")

class NexusSentinel:
    def __init__(self, config_path: Optional[str] = None):
        self.config = PlatformConfig.from_yaml(config_path) if config_path else PlatformConfig.default()
        
        # Validate configuration
        validation_issues = self.config.validate()
        if validation_issues:
            logger.error("Configuration validation failed:")
            for issue in validation_issues:
                logger.error(f"  - {issue}")
            raise ValueError("Invalid configuration - cannot start platform")
        
        # 1. Initialize Data Platform
        self.repository = DataRepository(os.path.join(self.config.telemetry.storage_path, "sentinel.db"))
        self.storage_writer = StorageWriter(self.repository)

        # 2. Initialize AI Engine
        self.ai_engine = AISecurityEngine()

        # 3. Initialize Response System
        self.playbook_engine = PlaybookEngine(self.config.response.playbook_directory)
        self.response_orchestrator = ResponseOrchestrator(
            self.playbook_engine, 
            autonomy_level=self.config.response.autonomy_level
        )

        # 4. Initialize Telemetry Pipeline
        self.pipeline = TelemetryPipeline()
        self.pipeline.subscribe_alerts(self.response_orchestrator.handle_alert)
        self.pipeline.subscribe_alerts(self.storage_writer.handle_alert)

        # 5. Initialize Agent
        self.agent = NexusSentinelAgent(self.config)
        self.agent.register_all_monitors()
        # 6. Initialize Deception & Anti-Tamper
        self.deception = DeceptionManager(self.agent.config.agent.agent_id)
        
        self.agent.event_bus.subscribe_all(self._on_agent_event)

        self._running = False

    def _on_agent_event(self, event):
        """Callback for events from the agent's internal bus."""
        # Process through AI Engine
        analyzed_event = self.ai_engine.analyze_event(event)
        
        # Flow into Telemetry Pipeline
        self.pipeline.process_event(analyzed_event)
        
        # Persistent storage
        self.storage_writer.handle_event(analyzed_event)

    def start(self):
        self._running = True
        logger.info("Initializing Arkshield Autonomous Cyber Defense Ecosystem...")
        self.agent.start()
        self.deception.start_self_healing()
        self.deception.deploy_honey_pot()
        self.deception.plant_honey_credentials()
        logger.info("Platform is ACTIVE and monitoring for threats.")

    def stop(self):
        self._running = False
        self.agent.stop()
        self.deception.stop()
        logger.info("Arkshield platform stopped.")

def main():
    sentinel = NexusSentinel()
    
    def signal_handler(sig, frame):
        logger.info("Shutdown signal received...")
        sentinel.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    sentinel.start()

    # Keep main thread alive
    while True:
        time.sleep(1)

if __name__ == "__main__":
    main()
