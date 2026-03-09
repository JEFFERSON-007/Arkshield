"""
Arkshield — Core Agent

The central agent coordinator that manages all monitoring modules,
telemetry dispatch, and real-time threat response for the endpoint.
"""

import asyncio
import logging
import time
import signal
import threading
from typing import Dict, List, Optional, Any, Callable
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from arkshield.config.settings import PlatformConfig, AgentConfig
from arkshield.telemetry.events import (
    SecurityEvent, EventClass, EventType, Severity,
    SourceInfo, AgentHeartbeat
)

logger = logging.getLogger("arkshield.agent")


class EventBus:
    """
    Internal event bus for inter-module communication.
    Allows monitors to publish events and consumers to subscribe.
    """

    def __init__(self, max_queue_size: int = 10000):
        self._subscribers: Dict[str, List[Callable]] = {}
        self._queue: deque = deque(maxlen=max_queue_size)
        self._lock = threading.Lock()
        self._stats = {"published": 0, "delivered": 0, "dropped": 0}

    def subscribe(self, event_class: str, callback: Callable):
        """Subscribe to events of a specific class."""
        with self._lock:
            if event_class not in self._subscribers:
                self._subscribers[event_class] = []
            self._subscribers[event_class].append(callback)
            logger.debug(f"Subscriber registered for {event_class}")

    def subscribe_all(self, callback: Callable):
        """Subscribe to all events."""
        self.subscribe("*", callback)

    def publish(self, event: SecurityEvent):
        """Publish an event to all relevant subscribers."""
        self._stats["published"] += 1
        self._queue.append(event)

        with self._lock:
            subscribers = list(self._subscribers.get(event.event_class, []))
            subscribers.extend(self._subscribers.get("*", []))

        for callback in subscribers:
            try:
                callback(event)
                self._stats["delivered"] += 1
            except Exception as e:
                logger.error(f"Event delivery error: {e}")
                self._stats["dropped"] += 1

    @property
    def stats(self) -> Dict[str, int]:
        return dict(self._stats)

    @property
    def queue_size(self) -> int:
        return len(self._queue)

    def get_recent_events(self, count: int = 100) -> List[SecurityEvent]:
        """Get the most recent events from the queue."""
        return list(self._queue)[-count:]


class MonitorBase:
    """
    Base class for all endpoint monitoring modules.
    Provides standard lifecycle management and event publishing.
    """

    def __init__(self, name: str, event_bus: EventBus, config: AgentConfig):
        self.name = name
        self.event_bus = event_bus
        self.config = config
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._stats = {"events_generated": 0, "errors": 0, "cycles": 0}
        self.logger = logging.getLogger(f"arkshield.monitor.{name}")

    def start(self):
        """Start the monitor in a background thread."""
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._run_loop, daemon=True, name=f"monitor-{self.name}")
        self._thread.start()
        self.logger.info(f"Monitor [{self.name}] started")

    def stop(self):
        """Stop the monitor."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=5.0)
        self.logger.info(f"Monitor [{self.name}] stopped")

    def _run_loop(self):
        """Main monitoring loop."""
        while self._running:
            try:
                self.collect()
                self._stats["cycles"] += 1
            except Exception as e:
                self.logger.error(f"Monitor [{self.name}] error: {e}")
                self._stats["errors"] += 1
            time.sleep(self.config.scan_interval)

    def collect(self):
        """Override in subclasses to collect telemetry data."""
        raise NotImplementedError

    def emit_event(self, event: SecurityEvent):
        """Publish a security event."""
        if not event.source.agent_id:
            event.source = SourceInfo.from_local(self.config.agent_id)
        self.event_bus.publish(event)
        self._stats["events_generated"] += 1

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def stats(self) -> Dict[str, int]:
        return dict(self._stats)


class NexusSentinelAgent:
    """
    The core Arkshield endpoint agent.

    Coordinates all monitoring modules, manages event flow,
    and provides the foundation for autonomous defense.
    """

    def __init__(self, config: Optional[PlatformConfig] = None):
        self.config = config or PlatformConfig.default()
        self.event_bus = EventBus(max_queue_size=self.config.agent.offline_buffer_size)
        self.monitors: Dict[str, MonitorBase] = {}
        self._running = False
        self._start_time = 0.0
        self._events_sent = 0
        self._executor = ThreadPoolExecutor(max_workers=4)

        # Validate configuration
        issues = self.config.validate()
        if issues:
            for issue in issues:
                logger.warning(f"Config issue: {issue}")

        logger.info(f"Agent initialized | ID: {self.config.agent.agent_id} | Host: {self.config.agent.hostname}")

    def register_monitor(self, monitor: MonitorBase):
        """Register a monitoring module."""
        self.monitors[monitor.name] = monitor
        logger.info(f"Monitor registered: {monitor.name}")

    def register_all_monitors(self):
        """Register all available monitoring modules."""
        from arkshield.agent.monitors.process_monitor import ProcessMonitor
        from arkshield.agent.monitors.filesystem_monitor import FileSystemMonitor
        from arkshield.agent.monitors.network_monitor import NetworkMonitor
        from arkshield.agent.monitors.memory_scanner import MemoryScanner
        from arkshield.agent.monitors.persistence_detector import PersistenceDetector
        from arkshield.agent.monitors.integrity_checker import IntegrityChecker

        monitor_map = {
            "process": ProcessMonitor,
            "filesystem": FileSystemMonitor,
            "network": NetworkMonitor,
            "memory": MemoryScanner,
            "persistence": PersistenceDetector,
            "integrity": IntegrityChecker,
        }

        for name in self.config.agent.enabled_monitors:
            if name in monitor_map:
                monitor = monitor_map[name](self.event_bus, self.config.agent)
                self.register_monitor(monitor)
            else:
                logger.warning(f"Unknown monitor: {name}")

    def start(self):
        """Start the agent and all registered monitors."""
        if self._running:
            logger.warning("Agent is already running")
            return

        self._running = True
        self._start_time = time.time()

        # Emit agent start event
        self.event_bus.publish(SecurityEvent(
            event_class=EventClass.AGENT_STATUS.value,
            event_type=EventType.AGENT_START.value,
            severity=Severity.INFO.value,
            description=f"Arkshield agent started on {self.config.agent.hostname}",
            source=SourceInfo.from_local(self.config.agent.agent_id)
        ))

        # Start all monitors
        for name, monitor in self.monitors.items():
            if name in self.config.agent.enabled_monitors:
                monitor.start()

        # Start heartbeat
        self._heartbeat_thread = threading.Thread(
            target=self._heartbeat_loop, daemon=True, name="agent-heartbeat"
        )
        self._heartbeat_thread.start()

        logger.info(f"Agent started with {len(self.monitors)} monitors")

    def stop(self):
        """Stop the agent gracefully."""
        self._running = False

        # Stop all monitors
        for name, monitor in self.monitors.items():
            monitor.stop()

        # Emit agent stop event
        self.event_bus.publish(SecurityEvent(
            event_class=EventClass.AGENT_STATUS.value,
            event_type=EventType.AGENT_STOP.value,
            severity=Severity.INFO.value,
            description=f"Arkshield agent stopped on {self.config.agent.hostname}",
            source=SourceInfo.from_local(self.config.agent.agent_id)
        ))

        self._executor.shutdown(wait=False)
        logger.info("Agent stopped")

    def _heartbeat_loop(self):
        """Send periodic heartbeat events."""
        while self._running:
            heartbeat = self._build_heartbeat()
            self.event_bus.publish(SecurityEvent(
                event_class=EventClass.AGENT_STATUS.value,
                event_type=EventType.AGENT_HEARTBEAT.value,
                severity=Severity.INFO.value,
                description="Agent heartbeat",
                source=SourceInfo.from_local(self.config.agent.agent_id),
                metadata={
                    "uptime": heartbeat.uptime_seconds,
                    "events_sent": heartbeat.events_sent,
                    "cpu_usage": heartbeat.cpu_usage_percent,
                    "memory_usage_mb": heartbeat.memory_usage_mb,
                    "monitors_active": heartbeat.monitors_active,
                    "queue_size": self.event_bus.queue_size,
                }
            ))
            time.sleep(30)  # heartbeat every 30 seconds

    def _build_heartbeat(self) -> AgentHeartbeat:
        """Build a heartbeat status report."""
        import psutil
        process = psutil.Process()
        return AgentHeartbeat(
            agent_id=self.config.agent.agent_id,
            hostname=self.config.agent.hostname,
            status="healthy" if self._running else "stopped",
            uptime_seconds=time.time() - self._start_time,
            events_sent=self.event_bus.stats["published"],
            events_queued=self.event_bus.queue_size,
            cpu_usage_percent=process.cpu_percent(),
            memory_usage_mb=process.memory_info().rss / (1024 * 1024),
            monitors_active=[n for n, m in self.monitors.items() if m.is_running],
        )

    def get_status(self) -> Dict[str, Any]:
        """Get comprehensive agent status."""
        return {
            "agent_id": self.config.agent.agent_id,
            "hostname": self.config.agent.hostname,
            "running": self._running,
            "uptime_seconds": time.time() - self._start_time if self._running else 0,
            "monitors": {
                name: {
                    "running": m.is_running,
                    "stats": m.stats
                }
                for name, m in self.monitors.items()
            },
            "event_bus": self.event_bus.stats,
            "queue_size": self.event_bus.queue_size,
        }

    def run_single_scan(self) -> List[SecurityEvent]:
        """Run a single scan cycle across all monitors and return events."""
        events_before = self.event_bus.queue_size
        for name, monitor in self.monitors.items():
            try:
                monitor.collect()
            except Exception as e:
                logger.error(f"Single scan error in {name}: {e}")
        new_events = list(self.event_bus._queue)[events_before:]
        return new_events
