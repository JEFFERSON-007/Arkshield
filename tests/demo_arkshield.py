"""
Arkshield — Platform Demo and Verification

Simulates a threat to verify the full platform integration:
Agent -> Pipeline -> AI Engine -> Response Orchestrator -> Action
"""

import os
import sys
import time
import threading
import logging
import psutil
from typing import List

# Ensure arkshield is in the path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from arkshield.main import NexusSentinel
from arkshield.telemetry.events import SecurityEvent, EventClass, EventType, Severity, ProcessInfo, FileInfo

def simulate_threat(sentinel: NexusSentinel):
    """Inject a simulated ransomware threat directly into the event bus."""
    logger = logging.getLogger("demo_threat")
    logger.info("Injecting simulated ransomware threat event...")
    
    # Create a dummy process
    import subprocess
    dummy_proc = subprocess.Popen(["cmd.exe", "/c", "timeout 120"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    pid = dummy_proc.pid
    
    # Simulate a ransomware event for this pid
    event = SecurityEvent(
        event_class=EventClass.THREAT_DETECTION.value,
        event_type=EventType.THREAT_RANSOMWARE.value,
        severity=Severity.CRITICAL.value,
        description="Ransomware-like activity detected: Rapid encryption on canary folder.",
        is_threat=True,
        risk_score=95.0,
        tags=["ransomware_detected", "canary_modified"],
        process=ProcessInfo(
            pid=pid,
            name="cmd.exe",
            cpu_percent=1.0,
            memory_mb=10.0,
            thread_count=1,
            network_connections=0,
            parent_name="NexusSentinelDemo"
        ),
        file=FileInfo(
            path="C:\\Users\\Public\\Canary\\SecretData.docx",
            name="SecretData.docx"
        )
    )
    
    # Emit to the event bus
    sentinel.agent.event_bus.publish(event)
    
    logger.info(f"Threat event injected for PID {pid}. Waiting for orchestrator response...")
    
    # Give the orchestrator and playbook engine time to react
    time.sleep(2)
    
    # Verify the process was killed
    if not psutil.pid_exists(pid):
        logger.info(f"VERIFICATION SUCCESS: Process {pid} was successfully terminated by the response orchestrator.")
    else:
        logger.error(f"VERIFICATION FAILURE: Process {pid} is still running.")
        dummy_proc.kill()

def main():
    logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(name)s: %(message)s')
    
    sentinel = NexusSentinel()
    
    # Start sentinel in a separate thread so we can interact with it
    sentinel_thread = threading.Thread(target=sentinel.start, daemon=True)
    sentinel_thread.start()
    
    time.sleep(3) # Wait for monitors to initialize
    
    try:
        simulate_threat(sentinel)
    except Exception as e:
        print(f"Error during simulation: {e}")
    finally:
        sentinel.stop()

if __name__ == "__main__":
    main()
