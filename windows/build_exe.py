"""
ArkShield Windows Executable Builder
Creates standalone .exe file using PyInstaller
"""

import PyInstaller.__main__
import os
import sys
from pathlib import Path

# Get project directory
PROJECT_DIR = Path(__file__).parent.parent
WINDOWS_DIR = Path(__file__).parent
BUILD_DIR = WINDOWS_DIR / "build"
DIST_DIR = WINDOWS_DIR / "dist"

# Icon path (create one or leave default)
ICON_PATH = WINDOWS_DIR / "arkshield.ico"

print("=" * 60)
print("  Building ArkShield Windows Executable")
print("=" * 60)

# PyInstaller options
pyinstaller_args = [
    str(WINDOWS_DIR / "arkshield_app.py"),  # Main script
    "--name=ArkShield",                      # Output name
    "--onefile",                             # Single executable
    "--windowed",                            # No console window
    "--clean",                               # Clean build
    f"--distpath={DIST_DIR}",               # Output directory
    f"--workpath={BUILD_DIR}",              # Build directory
    "--noconfirm",                           # Overwrite without asking
    
    # Add data files
    f"--add-data={PROJECT_DIR / 'src'};src",
    f"--add-data={PROJECT_DIR / 'src/arkshield/api/dashboard.html'};src/arkshield/api",
    f"--add-data={PROJECT_DIR / 'src/arkshield/config/ai_config.json'};src/arkshield/config",
    f"--add-data={PROJECT_DIR / 'src/storage_manager/data/junk_patterns.json'};src/storage_manager/data",
    
    # Hidden imports
    "--hidden-import=uvicorn",
    "--hidden-import=uvicorn.logging",
    "--hidden-import=uvicorn.loops",
    "--hidden-import=uvicorn.loops.auto",
    "--hidden-import=uvicorn.protocols",
    "--hidden-import=uvicorn.protocols.http",
    "--hidden-import=uvicorn.protocols.http.auto",
    "--hidden-import=uvicorn.protocols.websockets",
    "--hidden-import=uvicorn.protocols.websockets.auto",
    "--hidden-import=uvicorn.lifespan",
    "--hidden-import=uvicorn.lifespan.on",
    "--hidden-import=fastapi",
    "--hidden-import=psutil",
    "--hidden-import=winreg",
    "--hidden-import=pydantic",
    "--hidden-import=starlette",
    
    # Optimization
    "--optimize=2",
]

# Add icon if it exists
if ICON_PATH.exists():
    pyinstaller_args.append(f"--icon={ICON_PATH}")

print("\n[1/3] Running PyInstaller...")
print(f"  Input:  {WINDOWS_DIR / 'arkshield_app.py'}")
print(f"  Output: {DIST_DIR / 'ArkShield.exe'}")
print(f"  Build:  {BUILD_DIR}")

try:
    PyInstaller.__main__.run(pyinstaller_args)
    
    print("\n[2/3] Build completed successfully!")
    print(f"\n[3/3] Executable location:")
    print(f"  → {DIST_DIR / 'ArkShield.exe'}")
    print(f"  Size: {(DIST_DIR / 'ArkShield.exe').stat().st_size / (1024*1024):.1f} MB")
    
    print("\n" + "=" * 60)
    print("  ✅ Build Complete!")
    print("=" * 60)
    print(f"\nTo run: {DIST_DIR / 'ArkShield.exe'}")
    print("\nTo distribute:")
    print(f"  1. Copy {DIST_DIR / 'ArkShield.exe'} to target system")
    print("  2. Double-click to launch")
    print("  3. No installation required!")
    
except Exception as e:
    print(f"\n❌ Build failed: {e}")
    sys.exit(1)
