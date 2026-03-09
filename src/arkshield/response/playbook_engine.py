"""
Arkshield — Playbook Engine

Executes multi-step YAML-based security playbooks.
"""

import yaml
import logging
from typing import Dict, Any, List, Optional
from pathlib import Path

from arkshield.response.actions import kill_process, quarantine_file, block_ip, isolate_host
from arkshield.telemetry.events import Alert, SecurityEvent

logger = logging.getLogger("arkshield.response.playbook_engine")

class PlaybookEngine:
    def __init__(self, playbook_dir: str):
        self.playbook_dir = Path(playbook_dir)
        self.playbook_dir.mkdir(parents=True, exist_ok=True)
        self._action_map = {
            "kill_process": kill_process,
            "quarantine_file": quarantine_file,
            "block_ip": block_ip,
            "isolate_host": isolate_host,
        }

    def execute_playbook(self, playbook_name: str, alert: Alert, context: Dict[str, Any]) -> bool:
        """Load and execute a named playbook."""
        playbook_path = self.playbook_dir / f"{playbook_name}.yaml"
        if not playbook_path.exists():
            logger.error(f"Playbook {playbook_name} not found at {playbook_path}")
            return False

        try:
            with open(playbook_path, 'r') as f:
                playbook_data = yaml.safe_load(f)
            
            steps = playbook_data.get('steps', [])
            logger.info(f"Executing playbook {playbook_name} with {len(steps)} steps")
            
            for step in steps:
                action_name = step.get('action')
                params = step.get('params', {})
                
                # Resolve parameters from context
                resolved_params = self._resolve_params(params, context)
                
                if action_name in self._action_map:
                    action_func = self._action_map[action_name]
                    logger.info(f"Executing step: {action_name} with {resolved_params}")
                    result = action_func(**resolved_params)
                    if not result and step.get('critical', True):
                        logger.error(f"Critical step {action_name} failed. Aborting playbook.")
                        return False
                else:
                    logger.warning(f"Unknown action {action_name} in playbook {playbook_name}")
            
            return True
        except Exception as e:
            logger.error(f"Failed to execute playbook {playbook_name}: {e}")
            return False

    def _resolve_params(self, params: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """Resolve dynamic parameters like {pid} from the context."""
        resolved = {}
        for k, v in params.items():
            if isinstance(v, str) and v.startswith("{") and v.endswith("}"):
                key = v[1:-1]
                resolved[k] = context.get(key, v)
            else:
                resolved[k] = v
        return resolved
