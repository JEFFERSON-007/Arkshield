#!/usr/bin/env python3
"""
API endpoint test - Verify key endpoints work on current platform
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

import asyncio
from arkshield.api.server import (
    get_startup_programs,
    get_services,
    get_firewall_rules,
    get_network_shares,
    get_user_accounts,
    get_system_info,
)

async def test_endpoints():
    """Test key cross-platform endpoints"""
    print("=" * 60)
    print("ARKSHIELD API ENDPOINT TEST")
    print("=" * 60)
    
    tests = []
    
    # Test startup programs
    print("\n1. Testing /system/startup...")
    try:
        result = await get_startup_programs()
        print(f"   ✓ Found {len(result)} startup items")
        if result:
            print(f"   Sample: {result[0].get('name', 'N/A')}")
        tests.append(("Startup Programs", True))
    except Exception as e:
        print(f"   ✗ Error: {e}")
        tests.append(("Startup Programs", False))
    
    # Test services
    print("\n2. Testing /system/services...")
    try:
        result = await get_services()
        print(f"   ✓ Found {len(result)} services")
        if result:
            print(f"   Sample: {result[0].get('name', 'N/A')}")
        tests.append(("Services", True))
    except Exception as e:
        print(f"   ✗ Error: {e}")
        tests.append(("Services", False))
    
    # Test firewall rules
    print("\n3. Testing /security/firewall...")
    try:
        result = await get_firewall_rules()
        print(f"   ✓ Found {len(result)} firewall rules")
        if result:
            print(f"   Sample: {result[0].get('name', 'N/A')}")
        tests.append(("Firewall Rules", True))
    except Exception as e:
        print(f"   ✗ Error: {e}")
        tests.append(("Firewall Rules", False))
    
    # Test network shares
    print("\n4. Testing /security/shares...")
    try:
        result = await get_network_shares()
        print(f"   ✓ Found {len(result)} network shares")
        if result:
            print(f"   Sample: {result[0].get('name', 'N/A')}")
        tests.append(("Network Shares", True))
    except Exception as e:
        print(f"   ✗ Error: {e}")
        tests.append(("Network Shares", False))
    
    # Test user accounts
    print("\n5. Testing /security/users...")
    try:
        result = await get_user_accounts()
        print(f"   ✓ Found {len(result)} user accounts")
        if result:
            print(f"   Sample: {result[0].get('username', 'N/A')}")
        tests.append(("User Accounts", True))
    except Exception as e:
        print(f"   ✗ Error: {e}")
        tests.append(("User Accounts", False))
    
    # Test system info
    print("\n6. Testing /system/info...")
    try:
        result = await get_system_info()
        print(f"   ✓ System: {result.get('os', 'N/A')}")
        print(f"   ✓ Hostname: {result.get('hostname', 'N/A')}")
        tests.append(("System Info", True))
    except Exception as e:
        print(f"   ✗ Error: {e}")
        tests.append(("System Info", False))
    
    # Summary
    print("\n" + "=" * 60)
    print("TEST SUMMARY:")
    print("=" * 60)
    for name, passed in tests:
        status = "✓ PASS" if passed else "✗ FAIL"
        print(f"  {status}: {name}")
    
    passed_count = sum(1 for _, p in tests if p)
    print(f"\nTotal: {passed_count}/{len(tests)} endpoints working")
    
    return passed_count == len(tests)

if __name__ == "__main__":
    success = asyncio.run(test_endpoints())
    sys.exit(0 if success else 1)
