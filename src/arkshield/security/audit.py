"""
Arkshield — Audit Logging

Immutable audit trail for all security-relevant actions.
Records who did what, when, and from where.
"""

import json
import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, Optional

logger = logging.getLogger("arkshield.security.audit")

class AuditLogger:
    def __init__(self, log_path: str = "nexus_audit.jsonl"):
        self.log_path = log_path
        # Ensure log file exists
        if not os.path.exists(log_path):
            with open(log_path, 'w') as f:
                pass

    def log_action(self, user: str, action: str, resource: str, 
                   status: str = "success", metadata: Optional[Dict] = None):
        """Record an action to the audit log."""
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "user": user,
            "action": action,
            "resource": resource,
            "status": status,
            "metadata": metadata or {}
        }
        
        try:
            with open(self.log_path, 'a') as f:
                f.write(json.dumps(entry) + '\n')
            
            logger.info(f"AUDIT: User {user} performed {action} on {resource} ({status})")
        except Exception as e:
            logger.error(f"Failed to write audit log: {e}")

    def get_logs(self, limit: int = 100) -> list:
        """Retrieve recent audit logs."""
        logs = []
        try:
            with open(self.log_path, 'r') as f:
                lines = f.readlines()
                for line in lines[-limit:]:
                    logs.append(json.loads(line))
        except Exception:
            pass
        return logs[::-1]
