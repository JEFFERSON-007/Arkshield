"""
ArkShield Windows EXE Builder (Simplified)
Creates a standalone executable without complex dependencies
"""

import subprocess
import os
import sys
from pathlib import Path

def build_exe():
    """Build ArkShield.exe using PyInstaller"""
    
    # Get directory paths
    windows_dir = Path(__file__).parent
    root_dir = windows_dir.parent
    app_script = windows_dir / "arkshield_app.py"
    build_dir = windows_dir / "build"
    dist_dir = windows_dir / "dist"
    
    print("=" * 70)
    print("  ArkShield Windows EXE Builder")
    print("=" * 70)
    print()
    
    # Verify app script exists
    if not app_script.exists():
        print(f"❌ Error: {app_script} not found!")
        sys.exit(1)
    
    print(f"[1/3] Building ArkShield.exe...")
    print(f"  Input:  {app_script}")
    print(f"  Output: {dist_dir / 'ArkShield.exe'}")
    print()
    
    # Build command - use python -m PyInstaller to ensure it works
    cmd = [
        sys.executable,
        "-m",
        "PyInstaller",
        str(app_script),
        "--name=ArkShield",
        "--onefile",
        "--windowed",
        "--clean",
        "--noconfirm",
        f"--distpath={dist_dir}",
        f"--workpath={build_dir}",
        "--icon=NONE",  # Use default icon
        "--hidden-import=uvicorn",
        "--hidden-import=fastapi",
        "--hidden-import=psutil",
        "--hidden-import=pydantic",
        # Exclude unnecessary packages to reduce size and avoid errors
        "--exclude-module=matplotlib",
        "--exclude-module=tkinter",
        "--exclude-module=PIL",
        "--exclude-module=numpy",
        "--exclude-module=pandas",
        "--exclude-module=scipy",
        "--exclude-module=pytest",
        "--exclude-module=setuptools",
    ]
    
    try:
        result = subprocess.run(cmd, text=True, timeout=300)
        
        if result.returncode != 0:
            print("❌ Build failed!")
            sys.exit(1)
        
        print("✅ Build successful!")
        print()
        
        # Check if exe exists
        exe_path = dist_dir / "ArkShield.exe"
        if exe_path.exists():
            exe_size = exe_path.stat().st_size / (1024 * 1024)
            print(f"[2/3] Verifying executable...")
            print(f"  ✓ ArkShield.exe created ({exe_size:.1f} MB)")
            print()
            
            print(f"[3/3] Installation instructions...")
            print()
            print("=" * 70)
            print("  BUILD COMPLETE!")
            print("=" * 70)
            print()
            print("📍 Executable location:")
            print(f"  → {exe_path}")
            print()
            print("🚀 How to use:")
            print()
            print("  Option 1: Run directly")
            print(f"    {exe_path}")
            print()
            print("  Option 2: Create shortcut on Desktop")
            print(f"    Right-click ArkShield.exe → Send to → Desktop (create shortcut)")
            print()
            print("  Option 3: Add to PATH (system-wide access)")
            print(f"    Copy to: C:\\Program Files\\ArkShield\\")
            print(f"    Then run: arkshield")
            print()
            print("  Option 4: Pin to Start Menu")
            print(f"    Right-click ArkShield.exe → Pin to Start")
            print()
            print("=" * 70)
            print()
            
        else:
            print(f"❌ Error: {exe_path} was not created!")
            sys.exit(1)
            
    except subprocess.TimeoutExpired:
        print("❌ Build timed out!")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Build error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    build_exe()
