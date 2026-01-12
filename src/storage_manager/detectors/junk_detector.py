"""Intelligent junk file detector."""

import json
import fnmatch
from pathlib import Path
from typing import Dict, List, Set, Optional
from datetime import datetime
import logging

class JunkDetector:
    """Intelligent junk file detection engine."""
    
    def __init__(self, patterns_file: Optional[Path] = None):
        """Initialize junk detector with patterns."""
        self.logger = logging.getLogger(__name__)
        
        # Load patterns
        if patterns_file is None:
            patterns_file = Path(__file__).parent.parent / 'data' / 'junk_patterns.json'
        
        with open(patterns_file, 'r') as f:
            self.patterns = json.load(f)
        
        self.categories = list(self.patterns.keys())
    
    def detect_file(self, file_path: Path, check_categories: Optional[List[str]] = None) -> Dict:
        """
        Detect if file is junk and categorize it.
        
        Returns:
            Dict with 'is_junk', 'categories', and 'reasons'
        """
        if not file_path.exists() or not file_path.is_file():
            return {'is_junk': False, 'categories': [], 'reasons': []}
        
        categories_to_check = check_categories or self.categories
        matched_categories = []
        reasons = []
        
        try:
            stat = file_path.stat()
            file_age_days = (datetime.now().timestamp() - stat.st_mtime) / 86400
            file_size_mb = stat.st_size / (1024 * 1024)
            
            for category in categories_to_check:
                if category not in self.patterns:
                    continue
                
                pattern = self.patterns[category]
                matched = False
                reason = None
                
                # Check extensions
                if 'extensions' in pattern:
                    for ext in pattern['extensions']:
                        if ext.endswith('.*'):
                            # Pattern like .log.*
                            base_ext = ext.replace('.*', '')
                            if file_path.suffix.startswith(base_ext):
                                matched = True
                                reason = f"Extension matches {ext}"
                                break
                        elif file_path.suffix.lower() == ext.lower():
                            matched = True
                            reason = f"Extension is {ext}"
                            break
                
                # Check filenames patterns
                if not matched and 'filenames' in pattern:
                    for filename_pattern in pattern['filenames']:
                        if fnmatch.fnmatch(file_path.name, filename_pattern):
                            matched = True
                            reason = f"Filename matches pattern {filename_pattern}"
                            break
                
                # Check if in junk directories
                if not matched and 'directories' in pattern:
                    path_str = str(file_path)
                    for dir_name in pattern['directories']:
                        if dir_name in path_str:
                            matched = True
                            reason = f"In junk directory: {dir_name}"
                            break
                
                # Apply age threshold
                if matched and 'age_threshold_days' in pattern:
                    if file_age_days < pattern['age_threshold_days']:
                        matched = False
                        reason = None
                    else:
                        reason += f" and older than {pattern['age_threshold_days']} days"
                
                # Apply size threshold
                if matched and 'min_size_mb' in pattern:
                    if file_size_mb < pattern['min_size_mb']:
                        matched = False
                        reason = None
                    else:
                        reason += f" and larger than {pattern['min_size_mb']}MB"
                
                if matched:
                    matched_categories.append(category)
                    reasons.append(reason)
        
        except Exception as e:
            self.logger.debug(f"Error detecting junk for {file_path}: {e}")
        
        return {
            'is_junk': len(matched_categories) > 0,
            'categories': matched_categories,
            'reasons': reasons
        }
    
    def detect_directory(self, dir_path: Path, check_categories: Optional[List[str]] = None) -> Dict:
        """
        Check if entire directory is junk.
        
        Returns:
            Dict with 'is_junk', 'category', and 'reason'
        """
        if not dir_path.exists() or not dir_path.is_dir():
            return {'is_junk': False, 'category': None, 'reason': None}
        
        categories_to_check = check_categories or self.categories
        
        for category in categories_to_check:
            if category not in self.patterns:
                continue
            
            pattern = self.patterns[category]
            
            if 'directories' in pattern:
                dir_name = dir_path.name
                for junk_dir in pattern['directories']:
                    if junk_dir == dir_name or junk_dir in str(dir_path):
                        return {
                            'is_junk': True,
                            'category': category,
                            'reason': f"Directory matches junk pattern: {junk_dir}"
                        }
        
        return {'is_junk': False, 'category': None, 'reason': None}
    
    def get_category_description(self, category: str) -> str:
        """Get description for a junk category."""
        if category in self.patterns:
            return self.patterns[category].get('description', category)
        return category
    
    def list_categories(self) -> List[Dict[str, str]]:
        """List all available junk categories with descriptions."""
        return [
            {
                'name': category,
                'description': self.get_category_description(category)
            }
            for category in self.categories
        ]
