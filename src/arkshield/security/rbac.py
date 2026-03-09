"""
Arkshield — RBAC (Role-Based Access Control)

Enforces security policies and access controls for the platform.
Uses a zero-trust model where every action requires authorization.
"""

import enum
import logging
from typing import Dict, List, Set, Optional
from datetime import datetime, timezone

logger = logging.getLogger("arkshield.security.rbac")

class Role(enum.Enum):
    ADMIN = "admin"           # Full access
    OPERATOR = "operator"     # Can view and acknowledge alerts, run playbooks
    ANALYST = "analyst"       # Can view alerts and telemetry
    AUDITOR = "auditor"       # Can view audit logs only

class Permission(enum.Enum):
    VIEW_ALERTS = "view_alerts"
    ACK_ALERTS = "ack_alerts"
    RUN_PLAYBOOK = "run_playbook"
    MANAGE_AGENT = "manage_agent"
    VIEW_AUDIT = "view_audit"
    MANAGE_USERS = "manage_users"

ROLE_PERMISSIONS = {
    Role.ADMIN: set(Permission),
    Role.OPERATOR: {
        Permission.VIEW_ALERTS, 
        Permission.ACK_ALERTS, 
        Permission.RUN_PLAYBOOK,
        Permission.VIEW_AUDIT
    },
    Role.ANALYST: {
        Permission.VIEW_ALERTS,
        Permission.VIEW_AUDIT
    },
    Role.AUDITOR: {
        Permission.VIEW_AUDIT
    }
}

class RBACManager:
    """Manages users, roles, and permission enforcement."""
    
    def __init__(self):
        self._users: Dict[str, Role] = {}
        # Default admin/system user
        self._users["system"] = Role.ADMIN
        self._users["admin"] = Role.ADMIN

    def add_user(self, username: str, role: Role):
        self._users[username] = role
        logger.info(f"User {username} added with role {role.value}")

    def is_authorized(self, username: str, permission: Permission) -> bool:
        """Check if a user has the required permission."""
        role = self._users.get(username)
        if not role:
            return False
        
        return permission in ROLE_PERMISSIONS.get(role, set())

    def get_user_role(self, username: str) -> Optional[Role]:
        return self._users.get(username)
