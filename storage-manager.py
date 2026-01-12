#!/usr/bin/env python3
"""Standalone script to run storage manager."""

import sys
from pathlib import Path

# Add src to path for development
sys.path.insert(0, str(Path(__file__).parent / 'src'))

from storage_manager.cli import main

if __name__ == '__main__':
    main()
