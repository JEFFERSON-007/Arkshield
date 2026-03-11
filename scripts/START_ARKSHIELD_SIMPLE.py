#!/usr/bin/env python3
"""
Simple startup script for Arkshield Security Platform
Ensures all dependencies are available and starts the server
"""

import sys
import os
import subprocess

def main():
    print("\n" + "=" * 70)
    print("  🛡️  ARKSHIELD SECURITY PLATFORM - STARTUP")
    print("=" * 70)
    
    # Check Python version
    print(f"\n[✓] Python version: {sys.version.split()[0]}")
    
    if sys.version_info < (3, 8):
        print("\n[✗] ERROR: Python 3.8 or higher required")
        sys.exit(1)
    
    # Check/Install dependencies
    print("\n[⚙] Checking dependencies...")
    required_packages = ["fastapi", "uvicorn", "psutil"]
    
    try:
        import fastapi
        import uvicorn
        import psutil
        print("[✓] All dependencies installed")
    except ImportError as e:
        print(f"[!] Installing missing dependencies...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-q"] + required_packages)
    
    # Set the working directory
    script_dir = os.path.dirname(os.path.abspath(__file__))
    os.chdir(script_dir)
    sys.path.insert(0, os.path.join(script_dir, "src"))
    
    print("\n[⚙] Starting Arkshield Server...")
    print("=" * 70)
    
    # Import and run the server
    try:
        from arkshield.api.server import app, start_api
        start_api()
    except KeyboardInterrupt:
        print("\n\n[!] Shutting down Arkshield...")
        print("=" * 70)
        sys.exit(0)
    except Exception as e:
        print(f"\n[✗] ERROR: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
