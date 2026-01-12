"""Storage cleaner - removes junk files safely."""

import os
from pathlib import Path
from typing import Dict, List, Set, Optional
import logging

try:
    from send2trash import send2trash
    HAS_SEND2TRASH = True
except ImportError:
    HAS_SEND2TRASH = False

from ..detectors import JunkDetector
from ..utils import is_protected_path

class StorageCleaner:
    """Cleans junk files from filesystem."""
    
    def __init__(self, logger: logging.Logger, dry_run: bool = False,
                 categories: Optional[List[str]] = None,
                 exclude_patterns: Optional[Set[str]] = None,
                 include_hidden: bool = False):
        self.logger = logger
        self.dry_run = dry_run
        self.categories = categories
        self.exclude_patterns = exclude_patterns or set()
        self.include_hidden = include_hidden
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
    
    def find_junk_files(self, root: Path) -> List[Dict]:
        """Scan and find all junk files."""
        junk_files = []
        
        for dirpath, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
            current_path = Path(dirpath)
            
            # Check if entire directory is junk
            dir_junk_info = self.junk_detector.detect_directory(current_path, self.categories)
            if dir_junk_info['is_junk']:
                # Add entire directory
                total_size = sum(f.stat().st_size for f in current_path.rglob('*') if f.is_file())
                junk_files.append({
                    'path': str(current_path),
                    'size': total_size,
                    'is_directory': True,
                    'categories': [dir_junk_info['category']],
                    'reason': dir_junk_info['reason']
                })
                dirnames[:] = []  # Don't descend into junk directory
                continue
            
            # Exclude paths
            if self.should_exclude(current_path):
                dirnames[:] = []
                continue
            
            # Filter directories
            if not self.include_hidden:
                dirnames[:] = [d for d in dirnames if not d.startswith('.')]
            dirnames[:] = [d for d in dirnames if not self.should_exclude(current_path / d)]
            
            # Check files
            for name in filenames:
                try:
                    path = current_path / name
                    
                    if self.should_exclude(path):
                        continue
                    
                    junk_info = self.junk_detector.detect_file(path, self.categories)
                    if junk_info['is_junk']:
                        stat = path.stat()
                        junk_files.append({
                            'path': str(path),
                            'size': stat.st_size,
                            'is_directory': False,
                            'categories': junk_info['categories'],
                            'reasons': junk_info['reasons']
                        })
                
                except Exception as e:
                    self.logger.debug(f"Error checking {path}: {e}")
        
        return junk_files
    
    def cleanup_files(self, files: List[Dict]) -> Dict:
        """Clean up list of files."""
        summary = {
            'total_processed': 0,
            'total_failed': 0,
            'space_freed': 0,
            'failed_files': []
        }
        
        for file_info in files:
            path = Path(file_info['path'])
            
            if not path.exists():
                continue
            
            # Protected check
            if is_protected_path(path):
                self.logger.warning(f"PROTECTED: Skipping {path}")
                summary['total_failed'] += 1
                continue
            
            try:
                if self.dry_run:
                    self.logger.info(f"[DRY-RUN] Would delete: {path}")
                    summary['total_processed'] += 1
                    summary['space_freed'] += file_info['size']
                else:
                    if HAS_SEND2TRASH:
                        send2trash(str(path))
                        self.logger.info(f"Moved to trash: {path}")
                    else:
                        if file_info.get('is_directory'):
                            import shutil
                            shutil.rmtree(path)
                        else:
                            path.unlink()
                        self.logger.info(f"Deleted: {path}")
                    
                    summary['total_processed'] += 1
                    summary['space_freed'] += file_info['size']
            
            except Exception as e:
                self.logger.error(f"Failed to delete {path}: {e}")
                summary['total_failed'] += 1
                summary['failed_files'].append({'path': str(path), 'error': str(e)})
        
        return summary
