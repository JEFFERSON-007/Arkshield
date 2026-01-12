"""Storage Manager - Professional storage analysis and cleanup utility."""

__version__ = "2.0.0"
__author__ = "Storage Manager Team"

from .core.scanner import StorageScanner
from .core.cleaner import StorageCleaner

__all__ = ['StorageScanner', 'StorageCleaner']
