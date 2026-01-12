""" Utility functions for storage manager."""

import os
from pathlib import Path
from typing import Optional

def human_size(n: int) -> str:
    """Convert bytes to human-readable format."""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if n < 1024.0:
            return f"{n:3.1f}{unit}"
        n /= 1024.0
    return f"{n:.1f}PB"

def is_protected_path(path: Path) -> bool:
    """Check if path is in a protected system directory."""
    import platform
    
    protected_patterns_windows = {
        'windows', 'system32', 'winsxs', 'program files', 'programdata',
        'boot', 'recovery', '$recycle.bin'
    }
    
    protected_patterns_unix = {
        '/bin', '/sbin', '/usr/bin', '/usr/sbin', '/etc', '/var', 
        '/boot', '/sys', '/proc', '/dev'
    }
    
    path_str = str(path).lower()
    
    patterns = protected_patterns_windows if platform.system() == 'Windows' else protected_patterns_unix
    
    for pattern in patterns:
        if pattern in path_str:
            return True
    return False

def get_config_dir() -> Path:
    """Get configuration directory."""
    config_dir = Path.home() / '.storage_manager'
    config_dir.mkdir(parents=True, exist_ok=True)
    return config_dir

def format_age(days: int) -> str:
    """Format age in days to human-readable string."""
    if days < 30:
        return f"{days} days"
    elif days < 365:
        months = days // 30
        return f"{months} month{'s' if months > 1 else ''}"
    else:
        years = days // 365
        return f"{years} year{'s' if years > 1 else ''}"
