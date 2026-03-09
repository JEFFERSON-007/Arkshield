"""
Arkshield — Response Actions

Concrete implementation of remediation and defense actions.
"""

import os
import signal
import shutil
import logging
import psutil
import subprocess
from pathlib import Path
from typing import List, Optional

logger = logging.getLogger("arkshield.response.actions")

def kill_process(pid: int) -> bool:
    """Terminate a process by PID."""
    try:
        process = psutil.Process(pid)
        process.terminate()
        # Wait for termination
        gone, alive = psutil.wait_procs([process], timeout=3)
        if alive:
            process.kill()
        logger.info(f"Successfully killed process {pid}")
        return True
    except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
        logger.error(f"Failed to kill process {pid}: {e}")
        return False

def quarantine_file(filepath: str, quarantine_dir: str) -> Optional[str]:
    """Move a file to a secure quarantine directory and remove permissions."""
    try:
        path = Path(filepath)
        if not path.exists():
            return None
        
        Path(quarantine_dir).mkdir(parents=True, exist_ok=True)
        target = Path(quarantine_dir) / f"{path.name}.{int(os.time.time())}.quarantine"
        
        # Copy and delete to preserve metadata if possible
        shutil.move(str(path), str(target))
        
        # Remove all permissions
        os.chmod(str(target), 0o000)
        
        logger.info(f"Quarantined file {filepath} to {target}")
        return str(target)
    except Exception as e:
        logger.error(f"Failed to quarantine file {filepath}: {e}")
        return None

def isolate_host() -> bool:
    """Isolate the host from the network (simulated for safety in this version)."""
    # In a real implementation, this would use WFP (Windows Filtering Platform)
    # or iptables (Linux) to block all non-Sentinel traffic.
    logger.warning("HOST ISOLATION TRIGGERED - Platform communication maintained only.")
    return True

def block_ip(remote_ip: str) -> bool:
    """Block a specific remote IP address."""
    try:
        if os.name == 'nt':
            # Add Windows Firewall rule
            cmd = f'netsh advfirewall firewall add rule name="Sentinel-Block-{remote_ip}" dir=out action=block remoteip={remote_ip}'
            subprocess.run(cmd, shell=True, check=True)
        else:
            # Add iptables rule
            cmd = f'iptables -A OUTPUT -d {remote_ip} -j DROP'
            subprocess.run(cmd, shell=True, check=True)
        logger.info(f"Blocked IP address {remote_ip}")
        return True
    except Exception as e:
        logger.error(f"Failed to block IP {remote_ip}: {e}")
        return False
