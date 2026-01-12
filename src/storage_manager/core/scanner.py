"""Storage scanner - scans filesystem and collects statistics."""

import os
from pathlib import Path
from typing import Dict, List, Set, Optional
from collections import defaultdict
import logging

from ..detectors import JunkDetector
from ..utils import is_protected_path

class StorageScanner:
    """Scans filesystem and analyzes storage usage."""
    
    def __init__(self, logger: logging.Logger, include_hidden: bool = False,
                 exclude_patterns: Optional[Set[str]] = None, limit: Optional[int] = None):
        self.logger = logger
        self.include_hidden = include_hidden
        self.exclude_patterns = exclude_patterns or set()
        self.limit = limit
        self.junk_detector = JunkDetector()
    
    def should_exclude(self, path: Path) -> bool:
        """Check if path should be excluded."""
        if is_protected_path(path):
            return True
        
        path_str = str(path).lower()
        for pattern in self.exclude_patterns:
            if pattern.lower() in path_str:
                return True
        
        if not self.include_hidden and path.name.startswith('.'):
            return True
        
        return False
    
    def scan(self, root: Path) -> Dict:
        """
        Scan directory and return statistics.
        
        Returns:
            Dict with total_files, total_size, junk_stats, etc.
        """
        results = {
            'total_files': 0,
            'total_size': 0,
            'junk_stats': defaultdict(lambda: {'count': 0, 'size': 0}),
            'errors': []
        }
        
        count = 0
        
        for dirpath, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
            current_path = Path(dirpath)
            
            # Exclude directories
            if self.should_exclude(current_path):
                dirnames[:] = []
                continue
            
            # Filter hidden dirs
            if not self.include_hidden:
                dirnames[:] = [d for d in dirnames if not d.startswith('.')]
            
            # Filter excluded dirs
            dirnames[:] = [d for d in dirnames if not self.should_exclude(current_path / d)]
            
            for name in filenames:
                if self.limit and count >= self.limit:
                    return results
                
                try:
                    path = current_path / name
                    
                    if self.should_exclude(path):
                        continue
                    
                    stat_info = path.stat()
                    size = stat_info.st_size
                    
                    results['total_files'] += 1
                    results['total_size'] += size
                    count += 1
                    
                    # Detect if junk
                    junk_info = self.junk_detector.detect_file(path)
                    if junk_info['is_junk']:
                        for category in junk_info['categories']:
                            results['junk_stats'][category]['count'] += 1
                            results['junk_stats'][category]['size'] += size
                
                except Exception as e:
                    self.logger.debug(f"Error scanning {path}: {e}")
                    results['errors'].append(str(path))
        
        return results
