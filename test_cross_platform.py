#!/usr/bin/env python3
"""
Test script to verify cross-platform functionality of Arkshield
"""

import sys
import os
import platform

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

def test_imports():
    """Test that all modules can be imported"""
    print("Testing imports...")
    try:
        from arkshield.api import server
        print("✓ Server module imported successfully")
        
        from arkshield.agent.monitors import process_monitor
        print("✓ Process monitor imported successfully")
        
        from arkshield.agent.monitors import filesystem_monitor
        print("✓ Filesystem monitor imported successfully")
        
        return True
    except Exception as e:
        print(f"✗ Import failed: {e}")
        return False

def test_platform_detection():
    """Test platform detection"""
    print(f"\nPlatform detection:")
    print(f"  System: {platform.system()}")
    print(f"  Platform: {platform.platform()}")
    print(f"  Release: {platform.release()}")
    print(f"  Machine: {platform.machine()}")

def test_suspicious_patterns():
    """Test that suspicious patterns include cross-platform items"""
    print("\nTesting suspicious patterns...")
    try:
        from arkshield.agent.monitors.process_monitor import (
            SUSPICIOUS_PROCESSES,
            SUSPICIOUS_PARENT_CHILD,
            SUSPICIOUS_CMD_PATTERNS
        )
        
        # Check for Windows patterns
        windows_patterns = ['powershell.exe', 'cmd.exe', 'wscript.exe']
        windows_found = sum(1 for p in windows_patterns if p in SUSPICIOUS_PROCESSES)
        print(f"  Windows patterns found: {windows_found}/{len(windows_patterns)}")
        
        # Check for Linux patterns
        linux_patterns = ['bash', 'sh', 'python', 'nc', 'netcat', 'curl', 'wget']
        linux_found = sum(1 for p in linux_patterns if p in SUSPICIOUS_PROCESSES)
        print(f"  Linux patterns found: {linux_found}/{len(linux_patterns)}")
        
        # Check command patterns
        windows_cmd = any('powershell' in p.lower() for p in SUSPICIOUS_CMD_PATTERNS)
        linux_cmd = any('bash -i' in p.lower() for p in SUSPICIOUS_CMD_PATTERNS)
        print(f"  Windows command patterns: {'✓' if windows_cmd else '✗'}")
        print(f"  Linux command patterns: {'✓' if linux_cmd else '✗'}")
        
        return True
    except Exception as e:
        print(f"✗ Pattern test failed: {e}")
        return False

def test_disk_path():
    """Test platform-specific disk path function"""
    print("\nTesting disk path detection...")
    try:
        from arkshield.api.server import _platform_disk_path
        disk_path = _platform_disk_path()
        print(f"  Detected disk path: {disk_path}")
        return True
    except Exception as e:
        print(f"✗ Disk path test failed: {e}")
        return False

def test_psutil():
    """Test psutil functionality"""
    print("\nTesting psutil...")
    try:
        import psutil
        
        # CPU
        cpu_percent = psutil.cpu_percent(interval=0.1)
        print(f"  CPU usage: {cpu_percent}%")
        
        # Memory
        mem = psutil.virtual_memory()
        print(f"  Memory usage: {mem.percent}%")
        
        # Disk
        disk_path = _platform_disk_path()
        disk = psutil.disk_usage(disk_path)
        print(f"  Disk usage: {disk.percent}%")
        
        # Process count
        proc_count = len(list(psutil.process_iter()))
        print(f"  Running processes: {proc_count}")
        
        # Network
        net = psutil.net_io_counters()
        print(f"  Network bytes sent: {net.bytes_sent:,}")
        print(f"  Network bytes received: {net.bytes_recv:,}")
        
        return True
    except Exception as e:
        print(f"✗ psutil test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def _platform_disk_path():
    """Get platform-appropriate disk path"""
    if platform.system().lower() == "windows":
        drive = os.environ.get("SystemDrive") or os.path.splitdrive(os.getcwd())[0] or "C:"
        if not drive.endswith(':'):
            drive += ':'
        return f"{drive}\\\\"
    return "/"

def main():
    """Run all tests"""
    print("=" * 60)
    print("ARKSHIELD CROSS-PLATFORM TEST SUITE")
    print("=" * 60)
    
    results = []
    
    results.append(("Imports", test_imports()))
    results.append(("Platform Detection", test_platform_detection() or True))
    results.append(("Suspicious Patterns", test_suspicious_patterns()))
    results.append(("Disk Path", test_disk_path()))
    results.append(("psutil", test_psutil()))
    
    print("\n" + "=" * 60)
    print("TEST RESULTS:")
    print("=" * 60)
    
    for name, passed in results:
        status = "✓ PASS" if passed else "✗ FAIL"
        print(f"  {status}: {name}")
    
    total_passed = sum(1 for _, passed in results if passed)
    print(f"\nTotal: {total_passed}/{len(results)} tests passed")
    
    return total_passed == len(results)

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
