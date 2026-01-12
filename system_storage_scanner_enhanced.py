from __future__ import annotations
import os
import sys
import argparse
import hashlib
import json
import platform
import uuid
import logging
import time
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Optional, Set
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import psutil
except ImportError:
    print("Missing dependency: psutil. Install with: pip install psutil")
    raise

try:
    from tqdm import tqdm
except ImportError:
    print("Missing dependency: tqdm. Install with: pip install tqdm")
    raise

try:
    from colorama import init, Fore, Style
    init(autoreset=True)
except ImportError:
    print("Missing dependency: colorama. Install with: pip install colorama")
    raise

IS_WINDOWS = platform.system() == "Windows"

# ----------------- Constants -----------------

DEFAULT_HARMFUL_EXT = {
    '.exe', '.dll', '.scr', '.bat', '.cmd', '.com',
    '.js', '.vbs', '.ps1', '.msi', '.apk', '.jar', '.sh', '.py'
}
DEFAULT_JUNK_PATTERNS = {'.tmp', '.log', '.cache', '__pycache__', 'thumbs.db', '~', '.DS_Store'}

# System directories to exclude by default
DEFAULT_SYSTEM_EXCLUDES_WINDOWS = {
    'Windows', 'System32', 'WinSxS', 'ProgramData', '$Recycle.Bin',
    'System Volume Information', 'Recovery'
}
DEFAULT_SYSTEM_EXCLUDES_UNIX = {
    '/proc', '/sys', '/dev', '/run', '/tmp', '/var/run', '/var/lock'
}

# File categories by extension
FILE_CATEGORIES = {
    'documents': {'.pdf', '.doc', '.docx', '.txt', '.odt', '.rtf', '.tex', '.wpd', '.xls', '.xlsx', '.ppt', '.pptx'},
    'images': {'.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg', '.ico', '.tiff', '.webp', '.heic', '.raw'},
    'videos': {'.mp4', '.avi', '.mkv', '.mov', '.wmv', '.flv', '.webm', '.m4v', '.mpg', '.mpeg'},
    'audio': {'.mp3', '.wav', '.flac', '.aac', '.ogg', '.wma', '.m4a', '.opus'},
    'archives': {'.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.xz', '.iso', '.dmg'},
    'code': {'.py', '.java', '.cpp', '.c', '.h', '.js', '.ts', '.html', '.css', '.php', '.rb', '.go', '.rs', '.swift'},
    'executables': {'.exe', '.dll', '.so', '.dylib', '.app', '.msi'},
    'databases': {'.db', '.sqlite', '.mdb', '.sql', '.dbf'},
}

# ----------------- Helpers -----------------

def human_size(n: int) -> str:
    """Convert bytes to human-readable format."""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if n < 1024.0:
            return f"{n:3.1f}{unit}"
        n /= 1024.0
    return f"{n:.1f}PB"

def compute_hash(path: Path, chunk_size: int = 4 * 1024 * 1024) -> Optional[str]:
    """Compute SHA-256 hash in streaming mode."""
    try:
        h = hashlib.sha256()
        with path.open('rb') as f:
            while chunk := f.read(chunk_size):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None

def setup_logging(verbose: bool = False, log_file: Optional[Path] = None) -> logging.Logger:
    """Setup logging configuration."""
    logger = logging.getLogger('SystemScanner')
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    
    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.DEBUG if verbose else logging.WARNING)
    console_formatter = logging.Formatter('%(levelname)s: %(message)s')
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)
    
    # File handler
    if log_file:
        file_handler = logging.FileHandler(log_file, encoding='utf-8')
        file_handler.setLevel(logging.DEBUG)
        file_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)
    
    return logger

def categorize_file(path: Path) -> str:
    """Categorize file by extension."""
    ext = path.suffix.lower()
    for category, extensions in FILE_CATEGORIES.items():
        if ext in extensions:
            return category
    return 'other'

# ----------------- Scanner -----------------

class Scanner:
    def __init__(self, logger: logging.Logger, include_hidden: bool = True, 
                 exclude_patterns: Optional[Set[str]] = None,
                 exclude_system: bool = True, max_depth: Optional[int] = None,
                 min_size: Optional[int] = None, max_size: Optional[int] = None,
                 age_days: Optional[int] = None, limit: Optional[int] = None):
        self.logger = logger
        self.include_hidden = include_hidden
        self.exclude_patterns = exclude_patterns or set()
        self.exclude_system = exclude_system
        self.max_depth = max_depth
        self.min_size = min_size
        self.max_size = max_size
        self.age_days = age_days
        self.limit = limit
        self.errors = []
        
        # Setup system exclusions
        if exclude_system:
            if IS_WINDOWS:
                self.exclude_patterns.update(DEFAULT_SYSTEM_EXCLUDES_WINDOWS)
            else:
                self.exclude_patterns.update(DEFAULT_SYSTEM_EXCLUDES_UNIX)
    
    def should_exclude(self, path: Path) -> bool:
        """Check if path should be excluded."""
        path_str = str(path).lower()
        for pattern in self.exclude_patterns:
            if pattern.lower() in path_str:
                return True
        return False
    
    def scan_path(self, root: Path) -> List[Dict]:
        """Recursively scan a path and collect file metadata."""
        entries = []
        count = 0
        
        # Count total files for progress bar (estimate)
        self.logger.info(f"Counting files in {root}...")
        total_estimate = sum(1 for _ in root.rglob('*') if _.is_file()) if root.exists() else 0
        
        with tqdm(desc=f"Scanning {root.name}", unit=" files", colour="cyan") as pbar:
            for dirpath, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
                current_path = Path(dirpath)
                
                # Check depth
                if self.max_depth is not None:
                    depth = len(current_path.relative_to(root).parts)
                    if depth > self.max_depth:
                        dirnames[:] = []
                        continue
                
                # Exclude directories
                if self.should_exclude(current_path):
                    dirnames[:] = []
                    continue
                
                # Filter hidden directories
                if not self.include_hidden:
                    dirnames[:] = [d for d in dirnames if not d.startswith('.')]
                    filenames = [f for f in filenames if not f.startswith('.')]
                
                # Filter excluded directories
                dirnames[:] = [d for d in dirnames if not self.should_exclude(current_path / d)]
                
                for name in filenames:
                    try:
                        path = current_path / name
                        
                        # Skip excluded files
                        if self.should_exclude(path):
                            continue
                        
                        stat_info = path.stat()
                        size = stat_info.st_size
                        
                        # Size filters
                        if self.min_size is not None and size < self.min_size:
                            continue
                        if self.max_size is not None and size > self.max_size:
                            continue
                        
                        # Age filter
                        if self.age_days is not None:
                            age = (datetime.now().timestamp() - stat_info.st_mtime) / 86400
                            if age > self.age_days:
                                continue
                        
                        meta = {
                            "path": str(path),
                            "size": size,
                            "is_file": True,
                            "is_dir": False,
                            "permissions": oct(stat_info.st_mode)[-3:],
                            "modified": stat_info.st_mtime,
                            "category": categorize_file(path),
                        }
                        entries.append(meta)
                        count += 1
                        pbar.update(1)
                        
                        if self.limit and count >= self.limit:
                            self.logger.info(f"Reached limit of {self.limit} files")
                            return entries
                            
                    except PermissionError as e:
                        self.logger.warning(f"Permission denied: {path}")
                        self.errors.append({"path": str(path), "error": "Permission denied"})
                    except Exception as e:
                        self.logger.debug(f"Error accessing {path}: {e}")
                        self.errors.append({"path": str(path), "error": str(e)})
        
        return entries

# ----------------- Analyzer -----------------

class Analyzer:
    def __init__(self, logger: logging.Logger, large_threshold: int = 100 * 1024 * 1024, 
                 top_n: int = 20, harmful_ext=None, junk_patterns=None, 
                 compute_hashes: bool = True, threads: int = 4, old_days: int = 365):
        self.logger = logger
        self.large_threshold = large_threshold
        self.top_n = top_n
        self.harmful_ext = harmful_ext or DEFAULT_HARMFUL_EXT
        self.junk_patterns = junk_patterns or DEFAULT_JUNK_PATTERNS
        self.compute_hashes = compute_hashes
        self.threads = threads
        self.old_days = old_days

    def classify_file(self, meta: Dict) -> List[str]:
        """Classify file based on various criteria."""
        tags = []
        path = Path(meta['path'])
        ext = path.suffix.lower()
        size = meta.get('size', 0)

        try:
            # Large file check
            if size >= self.large_threshold:
                tags.append('large')
            
            # Potentially harmful check
            if ext in self.harmful_ext:
                tags.append('potentially_harmful')
            
            # Executable permission check (Unix)
            if not IS_WINDOWS and 'x' in meta.get('permissions', ''):
                tags.append('potentially_harmful')
            
            # Junk pattern check
            name = path.name.lower()
            for p in self.junk_patterns:
                if name.endswith(p) or p in name:
                    tags.append('junk')
                    break
            
            # Old file check
            if 'modified' in meta:
                age_days = (datetime.now().timestamp() - meta['modified']) / 86400
                if age_days > self.old_days:
                    tags.append('old')
            
            # Shebang check
            if size > 0 and size < 1024:  # Only check small text files
                try:
                    with path.open('rb') as f:
                        start = f.read(128)
                        if start.startswith(b'#!'):
                            tags.append('potentially_harmful')
                except Exception:
                    pass
                    
        except Exception as e:
            self.logger.debug(f"Error classifying {path}: {e}")
        
        return list(set(tags))

    def compute_hash_batch(self, files: List[Dict]) -> Dict[str, List[str]]:
        """Compute hashes for multiple files using thread pool."""
        hash_map = {}
        
        if not self.compute_hashes or not files:
            return hash_map
        
        self.logger.info(f"Computing hashes for {len(files)} files...")
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_path = {
                executor.submit(compute_hash, Path(meta['path'])): meta['path']
                for meta in files if meta.get('size', 0) > 0
            }
            
            with tqdm(total=len(future_to_path), desc="Hashing files", unit=" files", colour="yellow") as pbar:
                for future in as_completed(future_to_path):
                    path = future_to_path[future]
                    try:
                        h = future.result()
                        if h:
                            hash_map.setdefault(h, []).append(path)
                    except Exception as e:
                        self.logger.debug(f"Error hashing {path}: {e}")
                    pbar.update(1)
        
        return hash_map

    def analyze(self, files: List[Dict]) -> Dict:
        """Analyze collected files."""
        self.logger.info("Analyzing files...")
        
        results = {
            'total_files': 0,
            'total_size': 0,
            'large_files': [],
            'potentially_harmful': [],
            'junk': [],
            'old_files': [],
            'duplicates': [],
            'category_stats': defaultdict(lambda: {'count': 0, 'size': 0}),
            'extension_stats': defaultdict(lambda: {'count': 0, 'size': 0}),
            'errors': []
        }
        
        # Analyze each file
        for meta in tqdm(files, desc="Classifying files", unit=" files", colour="green"):
            results['total_files'] += 1
            size = meta.get('size', 0) or 0
            results['total_size'] += size
            
            # Category stats
            category = meta.get('category', 'other')
            results['category_stats'][category]['count'] += 1
            results['category_stats'][category]['size'] += size
            
            # Extension stats
            ext = Path(meta['path']).suffix.lower() or 'no_extension'
            results['extension_stats'][ext]['count'] += 1
            results['extension_stats'][ext]['size'] += size
            
            # Classify
            tags = self.classify_file(meta)
            
            if 'large' in tags:
                results['large_files'].append(meta)
            if 'potentially_harmful' in tags:
                results['potentially_harmful'].append({'path': meta['path'], 'reason': 'heuristic'})
            if 'junk' in tags:
                results['junk'].append({'path': meta['path'], 'reason': 'pattern'})
            if 'old' in tags:
                results['old_files'].append({
                    'path': meta['path'],
                    'age_days': int((datetime.now().timestamp() - meta['modified']) / 86400)
                })
        
        # Compute hashes for duplicate detection
        hash_map = self.compute_hash_batch(files)
        
        # Find duplicates
        for h, paths in hash_map.items():
            if len(paths) > 1:
                # Calculate total wasted space
                size = next((f['size'] for f in files if f['path'] == paths[0]), 0)
                results['duplicates'].append({
                    'paths': paths,
                    'size': size,
                    'wasted_space': size * (len(paths) - 1)
                })
        
        # Sort large files
        results['large_files'] = sorted(
            results['large_files'],
            key=lambda x: x.get('size', 0),
            reverse=True
        )[:self.top_n]
        
        # Sort duplicates by wasted space
        results['duplicates'] = sorted(
            results['duplicates'],
            key=lambda x: x.get('wasted_space', 0),
            reverse=True
        )[:self.top_n]
        
        # Sort old files by age
        results['old_files'] = sorted(
            results['old_files'],
            key=lambda x: x.get('age_days', 0),
            reverse=True
        )[:self.top_n]
        
        return results

# ----------------- Reporter -----------------

class Reporter:
    def __init__(self, run_id: str, out_dir: Path, logger: logging.Logger):
        self.run_id = run_id
        self.out_dir = out_dir
        self.logger = logger
        self.out_dir.mkdir(parents=True, exist_ok=True)

    def write_json(self, payload: Dict) -> Path:
        """Write JSON report."""
        p = self.out_dir / f"scan_report_{self.run_id}.json"
        with p.open('w', encoding='utf-8') as f:
            json.dump(payload, f, indent=2, default=str)
        return p
    
    def write_csv(self, payload: Dict) -> Path:
        """Write CSV summary."""
        p = self.out_dir / f"scan_summary_{self.run_id}.csv"
        with p.open('w', encoding='utf-8') as f:
            f.write("Category,Count,Total Size (Bytes),Total Size (Human)\n")
            for cat, stats in payload.get('statistics', {}).get('category_stats', {}).items():
                f.write(f"{cat},{stats['count']},{stats['size']},{human_size(stats['size'])}\n")
        return p

    def console_summary(self, payload: Dict, scanned_paths: List[str], duration: float):
        """Print colorful console summary."""
        print(f"\n{Fore.CYAN}{'=' * 60}")
        print(f"{Fore.CYAN}{'SCAN SUMMARY':^60}")
        print(f"{Fore.CYAN}{'=' * 60}{Style.RESET_ALL}\n")
        
        # Basic info
        print(f"{Fore.YELLOW}Run ID:{Style.RESET_ALL} {self.run_id}")
        print(f"{Fore.YELLOW}Duration:{Style.RESET_ALL} {duration:.2f} seconds")
        print(f"{Fore.YELLOW}Scanned paths:{Style.RESET_ALL} {', '.join(scanned_paths)}\n")
        
        # Statistics
        stats = payload.get('statistics', {})
        print(f"{Fore.GREEN}📊 Statistics:")
        print(f"  Total files: {Fore.WHITE}{stats.get('total_files', 0):,}{Style.RESET_ALL}")
        print(f"  Total size: {Fore.WHITE}{human_size(stats.get('total_size', 0))}{Style.RESET_ALL}\n")
        
        # Category breakdown
        print(f"{Fore.GREEN}📁 File Categories:")
        for cat, cat_stats in sorted(stats.get('category_stats', {}).items(), 
                                      key=lambda x: x[1]['size'], reverse=True)[:5]:
            percentage = (cat_stats['size'] / stats.get('total_size', 1)) * 100
            print(f"  {cat.capitalize():15} {cat_stats['count']:>6,} files  "
                  f"{human_size(cat_stats['size']):>10}  ({percentage:>5.1f}%)")
        
        # Findings
        findings = payload.get('findings', {})
        print(f"\n{Fore.RED}🔍 Findings:")
        print(f"  Large files: {Fore.WHITE}{len(findings.get('large_files', []))}{Style.RESET_ALL}")
        print(f"  Duplicate groups: {Fore.WHITE}{len(findings.get('duplicates', []))}{Style.RESET_ALL}")
        
        # Calculate wasted space
        wasted_space = sum(d.get('wasted_space', 0) for d in findings.get('duplicates', []))
        if wasted_space > 0:
            print(f"  {Fore.RED}Wasted space from duplicates: {human_size(wasted_space)}{Style.RESET_ALL}")
        
        print(f"  Potentially harmful: {Fore.WHITE}{len(findings.get('potentially_harmful', []))}{Style.RESET_ALL}")
        print(f"  Junk items: {Fore.WHITE}{len(findings.get('junk', []))}{Style.RESET_ALL}")
        print(f"  Old files (>{self.run_id[0:3]} days): {Fore.WHITE}{len(findings.get('old_files', []))}{Style.RESET_ALL}")
        
        # Recommendations
        recs = payload.get('recommendations', [])
        if recs:
            print(f"\n{Fore.MAGENTA}💡 Recommendations:")
            for rec in recs:
                print(f"  • {rec}")
        
        print(f"\n{Fore.CYAN}{'=' * 60}{Style.RESET_ALL}\n")

    def generate_recommendations(self, payload: Dict) -> List[str]:
        """Generate recommendations based on findings."""
        recs = []
        findings = payload.get('findings', {})
        stats = payload.get('statistics', {})
        
        # Duplicates recommendation
        duplicates = findings.get('duplicates', [])
        if duplicates:
            wasted = sum(d.get('wasted_space', 0) for d in duplicates)
            recs.append(f"Found {len(duplicates)} duplicate file groups wasting {human_size(wasted)}. "
                       "Consider removing duplicates.")
        
        # Large files recommendation
        large_files = findings.get('large_files', [])
        if large_files:
            recs.append(f"Found {len(large_files)} large files. Review if all are necessary.")
        
        # Junk files recommendation
        junk = findings.get('junk', [])
        if len(junk) > 10:
            recs.append(f"Found {len(junk)} junk/temporary files. Consider cleaning up.")
        
        # Old files recommendation
        old_files = findings.get('old_files', [])
        if len(old_files) > 20:
            recs.append(f"Found {len(old_files)} files older than a year. Consider archiving.")
        
        return recs

# ----------------- CLI -----------------

def main():
    parser = argparse.ArgumentParser(
        description='Enhanced System Storage Scanner + Reporter',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    # Scan targets
    parser.add_argument('--scan', nargs='*', help='paths or mountpoints to scan (if omitted, interactive)')
    parser.add_argument('--no-hidden', action='store_true', help='do not include hidden files')
    parser.add_argument('--limit', type=int, default=None, help='maximum files to collect per path')
    
    # Filters
    parser.add_argument('--exclude', action='append', default=[], help='exclude paths matching pattern')
    parser.add_argument('--exclude-system', action='store_true', default=True, help='exclude system directories')
    parser.add_argument('--max-depth', type=int, default=None, help='maximum scan depth')
    parser.add_argument('--min-size', type=int, default=None, help='minimum file size in bytes')
    parser.add_argument('--max-size', type=int, default=None, help='maximum file size in bytes')
    parser.add_argument('--age-days', type=int, default=None, help='only include files modified in last N days')
    
    # Analysis
    parser.add_argument('--large-threshold', type=int, default=100*1024*1024, help='large file threshold in bytes')
    parser.add_argument('--top', type=int, default=20, help='top N items to report')
    parser.add_argument('--no-hash', action='store_true', help='do not compute file hashes (faster)')
    parser.add_argument('--threads', type=int, default=4, help='number of threads for hash computation')
    parser.add_argument('--old-days', type=int, default=365, help='days threshold for old files')
    
    # Output
    parser.add_argument('--report-json', type=str, default=None, help='write JSON report to this directory')
    parser.add_argument('--output-format', choices=['json', 'csv', 'both'], default='json', 
                       help='output format')
    parser.add_argument('--verbose', action='store_true', help='enable detailed logging')
    parser.add_argument('--log-file', type=str, default=None, help='write detailed log to file')
    
    args = parser.parse_args()
    
    # Setup logging
    log_file = Path(args.log_file) if args.log_file else None
    logger = setup_logging(verbose=args.verbose, log_file=log_file)
    
    logger.info("Starting System Storage Scanner")
    start_time = time.time()
    
    # Determine targets
    targets = []
    if args.scan:
        targets = [Path(p) for p in args.scan]
    else:
        # Interactive drive selection
        parts = psutil.disk_partitions(all=False)
        print(f"\n{Fore.CYAN}Detected partitions / mount points:{Style.RESET_ALL}")
        for i, p in enumerate(parts):
            usage = psutil.disk_usage(p.mountpoint)
            print(f"[{i}] {Fore.GREEN}{p.mountpoint:<20}{Style.RESET_ALL} "
                  f"dev:{p.device:<15} fstype:{p.fstype:<10} "
                  f"size:{human_size(usage.total)}")
        sel = input(f"\n{Fore.YELLOW}Enter drive(s)/path(s) to scan (comma separated indices or paths): {Style.RESET_ALL}").split(',')
        for s in sel:
            s = s.strip()
            if s.isdigit() and int(s) < len(parts):
                targets.append(Path(parts[int(s)].mountpoint))
            else:
                targets.append(Path(s))
    
    # Scan
    scanner = Scanner(
        logger=logger,
        include_hidden=(not args.no_hidden),
        exclude_patterns=set(args.exclude),
        exclude_system=args.exclude_system,
        max_depth=args.max_depth,
        min_size=args.min_size,
        max_size=args.max_size,
        age_days=args.age_days,
        limit=args.limit
    )
    
    all_files = []
    for t in targets:
        if not t.exists():
            logger.error(f"Path does not exist: {t}")
            print(f"{Fore.RED}✗ Path does not exist: {t}{Style.RESET_ALL}")
            continue
        print(f"\n{Fore.CYAN}Scanning: {t}{Style.RESET_ALL}")
        files = scanner.scan_path(t)
        print(f"{Fore.GREEN}✓ Collected {len(files):,} entries from {t}{Style.RESET_ALL}")
        all_files.extend(files)
    
    if not all_files:
        logger.error("No files found to analyze")
        print(f"{Fore.RED}✗ No files found to analyze{Style.RESET_ALL}")
        return
    
    # Analyze
    run_id = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '-' + uuid.uuid4().hex[:8]
    analyzer = Analyzer(
        logger=logger,
        large_threshold=args.large_threshold,
        top_n=args.top,
        compute_hashes=not args.no_hash,
        threads=args.threads,
        old_days=args.old_days
    )
    
    results = analyzer.analyze(all_files)
    
    # Build payload
    duration = time.time() - start_time
    
    payload = {
        'run_id': run_id,
        'scan_metadata': {
            'start_time': datetime.fromtimestamp(start_time, timezone.utc).isoformat(),
            'end_time': datetime.now(timezone.utc).isoformat(),
            'duration_seconds': duration,
            'scanned_paths': [str(p) for p in targets],
            'excluded_patterns': list(args.exclude),
            'filters': {
                'max_depth': args.max_depth,
                'min_size': args.min_size,
                'max_size': args.max_size,
                'age_days': args.age_days,
            }
        },
        'statistics': {
            'total_files': results['total_files'],
            'total_size': results['total_size'],
            'category_stats': dict(results['category_stats']),
            'extension_stats': dict(results['extension_stats']),
        },
        'findings': {
            'large_files': results['large_files'],
            'duplicates': results['duplicates'],
            'potentially_harmful': results['potentially_harmful'],
            'junk': results['junk'],
            'old_files': results['old_files'],
        },
        'errors': scanner.errors + results.get('errors', [])
    }
    
    # Generate recommendations
    out_dir = Path(args.report_json) if args.report_json else Path.cwd() / 'scan_reports'
    reporter = Reporter(run_id, out_dir, logger)
    payload['recommendations'] = reporter.generate_recommendations(payload)
    
    # Write reports
    if args.output_format in ['json', 'both']:
        report_path = reporter.write_json(payload)
        print(f"\n{Fore.GREEN}✓ JSON report written to: {report_path}{Style.RESET_ALL}")
    
    if args.output_format in ['csv', 'both']:
        csv_path = reporter.write_csv(payload)
        print(f"{Fore.GREEN}✓ CSV summary written to: {csv_path}{Style.RESET_ALL}")
    
    # Console summary
    reporter.console_summary(payload, [str(p) for p in targets], duration)
    
    logger.info(f"Scan completed in {duration:.2f} seconds")

if __name__ == '__main__':
    main()
