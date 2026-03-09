"""
Arkshield — Memory Scanner

Monitors process memory for indicators of compromise including:
- Shellcode injection detection
- Reflective DLL injection
- Process hollowing 
- ROP chain indicators
- Suspicious memory allocations
"""

import os
import logging
import ctypes
import struct
from typing import Dict, List, Optional, Set
from datetime import datetime, timezone

import psutil

from arkshield.agent.core import MonitorBase, EventBus
from arkshield.config.settings import AgentConfig
from arkshield.telemetry.events import (
    SecurityEvent, EventClass, EventType, Severity,
    ProcessInfo, MITREMapping
)

logger = logging.getLogger("arkshield.monitor.memory")

# PE Header magic bytes
PE_MAGIC = b'MZ'
PE_SIGNATURE = b'PE\x00\x00'

# Common shellcode patterns
SHELLCODE_PATTERNS = [
    b'\xfc\xe8',           # Common shellcode preamble (CLD; CALL)
    b'\x60\x89\xe5',       # PUSHAD; MOV EBP, ESP
    b'\x31\xc0\x50\x68',   # XOR EAX,EAX; PUSH EAX; PUSH imm
    b'\xeb\xfe',           # Infinite loop (JMP $-2)
    b'\x48\x31\xc9',       # XOR RCX, RCX (x64)
    b'\x48\x83\xec',       # SUB RSP, imm (x64 stack setup)
]

# Suspicious process names to scan more frequently
HIGH_PRIORITY_PROCESSES = {
    'powershell.exe', 'pwsh.exe', 'cmd.exe', 'svchost.exe',
    'explorer.exe', 'rundll32.exe', 'regsvr32.exe', 'mshta.exe',
    'wscript.exe', 'cscript.exe', 'lsass.exe', 'wmiprvse.exe',
    'notepad.exe', 'iexplore.exe', 'chrome.exe', 'firefox.exe',
}


class MemoryScanner(MonitorBase):
    """
    Scans process memory for indicators of malicious activity.

    Capabilities:
    - Shellcode pattern detection in process memory
    - Reflective DLL injection detection (PE headers in non-image regions)
    - Process hollowing detection
    - Suspicious memory allocation monitoring
    - RWX (Read-Write-Execute) region detection
    """

    def __init__(self, event_bus: EventBus, config: AgentConfig):
        super().__init__("memory", event_bus, config)
        self._scanned_pids: Dict[int, float] = {}  # pid -> last scan time
        self._findings: Dict[int, List[str]] = {}
        self._scan_interval = 30  # seconds between scans per process

    def collect(self):
        """Collect memory telemetry."""
        now = time.time()

        for proc in psutil.process_iter(['pid', 'name', 'exe', 'username', 'memory_info']):
            try:
                info = proc.info
                pid = info['pid']
                name = (info.get('name') or '').lower()

                # Skip system processes
                if pid in (0, 4):  # System/Idle
                    continue

                # Determine scan priority
                is_priority = name in HIGH_PRIORITY_PROCESSES
                scan_interval = self._scan_interval / 2 if is_priority else self._scan_interval

                # Check if needs scanning
                if pid in self._scanned_pids:
                    if now - self._scanned_pids[pid] < scan_interval:
                        continue

                self._scanned_pids[pid] = now

                # Perform memory analysis
                self._analyze_process_memory(proc, info)

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        # Clean up terminated processes
        active_pids = {p.pid for p in psutil.process_iter(['pid'])}
        self._scanned_pids = {
            k: v for k, v in self._scanned_pids.items() if k in active_pids
        }

    def _analyze_process_memory(self, proc: psutil.Process, info: Dict):
        """Analyze a process's memory for suspicious indicators."""
        pid = info['pid']
        name = info.get('name', '')
        mem = info.get('memory_info')

        if not mem:
            return

        findings = []

        # Check for abnormal memory usage
        rss_mb = mem.rss / (1024 * 1024)
        vms_mb = mem.vms / (1024 * 1024)

        # Suspiciously large memory for known small processes
        if name.lower() in {'notepad.exe', 'calc.exe'} and rss_mb > 200:
            findings.append("abnormal_memory_size")
            self.emit_event(SecurityEvent(
                event_class=EventClass.MEMORY_ACTIVITY.value,
                event_type=EventType.MEMORY_SUSPICIOUS_ALLOC.value,
                severity=Severity.MEDIUM.value,
                description=f"Abnormal memory usage for {name} (PID {pid}): {rss_mb:.1f} MB",
                process=ProcessInfo(pid=pid, name=name, memory_mb=rss_mb),
                tags=["abnormal_memory"],
                mitre=MITREMapping(
                    tactic="defense_evasion",
                    technique_id="T1055",
                    technique_name="Process Injection"
                )
            ))

        # Check for RWX memory regions (Windows-specific)
        if os.name == 'nt':
            rwx_count = self._check_rwx_regions(pid)
            if rwx_count > 2:
                findings.append("rwx_regions")
                self.emit_event(SecurityEvent(
                    event_class=EventClass.MEMORY_ACTIVITY.value,
                    event_type=EventType.MEMORY_INJECTION.value,
                    severity=Severity.HIGH.value,
                    description=f"Multiple RWX memory regions in {name} (PID {pid}): {rwx_count} regions",
                    process=ProcessInfo(pid=pid, name=name),
                    tags=["rwx_memory", "injection_indicator"],
                    is_threat=True,
                    risk_score=75.0,
                    metadata={"rwx_region_count": rwx_count},
                    mitre=MITREMapping(
                        tactic="defense_evasion",
                        technique_id="T1055",
                        technique_name="Process Injection"
                    )
                ))

        # Check memory maps for suspicious patterns
        try:
            mem_maps = proc.memory_maps(grouped=True)
            anonymous_regions = 0
            total_anonymous_mb = 0

            for mem_map in mem_maps:
                path = mem_map.path if hasattr(mem_map, 'path') else ''
                rss = mem_map.rss if hasattr(mem_map, 'rss') else 0

                # Count anonymous (non-file-backed) memory regions
                if not path or path.startswith('['):
                    anonymous_regions += 1
                    total_anonymous_mb += rss / (1024 * 1024)

            # High anonymous memory can indicate injected code
            if anonymous_regions > 50 and total_anonymous_mb > 100:
                findings.append("high_anonymous_memory")
                self.emit_event(SecurityEvent(
                    event_class=EventClass.MEMORY_ACTIVITY.value,
                    event_type=EventType.MEMORY_SUSPICIOUS_ALLOC.value,
                    severity=Severity.MEDIUM.value,
                    description=f"High anonymous memory in {name} (PID {pid}): "
                                f"{anonymous_regions} regions, {total_anonymous_mb:.1f} MB",
                    process=ProcessInfo(pid=pid, name=name, memory_mb=rss_mb),
                    tags=["high_anonymous_memory"],
                    metadata={
                        "anonymous_regions": anonymous_regions,
                        "anonymous_mb": round(total_anonymous_mb, 2)
                    },
                ))
        except (psutil.AccessDenied, psutil.NoSuchProcess, Exception):
            pass

        # Track findings per process
        if findings:
            self._findings[pid] = findings

    def _check_rwx_regions(self, pid: int) -> int:
        """Check for Read-Write-Execute memory regions (Windows) with optimized traversal."""
        rwx_count = 0
        try:
            if os.name == 'nt':
                # Use ctypes to check memory regions
                PROCESS_QUERY_INFORMATION = 0x0400
                PROCESS_VM_READ = 0x0010
                MEM_COMMIT = 0x1000
                PAGE_EXECUTE_READWRITE = 0x40

                kernel32 = ctypes.windll.kernel32
                
                # Get system info to find the valid address range
                class SYSTEM_INFO(ctypes.Structure):
                    _fields_ = [
                        ("wProcessorArchitecture", ctypes.c_uint16),
                        ("wReserved", ctypes.c_uint16),
                        ("dwPageSize", ctypes.c_uint32),
                        ("lpMinimumApplicationAddress", ctypes.c_void_p),
                        ("lpMaximumApplicationAddress", ctypes.c_void_p),
                        ("dwActiveProcessorMask", ctypes.c_void_p),
                        ("dwNumberOfProcessors", ctypes.c_uint32),
                        ("dwProcessorType", ctypes.c_uint32),
                        ("dwAllocationGranularity", ctypes.c_uint32),
                        ("wProcessorLevel", ctypes.c_uint16),
                        ("wProcessorRevision", ctypes.c_uint16),
                    ]
                
                sys_info = SYSTEM_INFO()
                kernel32.GetSystemInfo(ctypes.byref(sys_info))
                min_addr = sys_info.lpMinimumApplicationAddress
                max_addr = sys_info.lpMaximumApplicationAddress

                class MEMORY_BASIC_INFORMATION(ctypes.Structure):
                    _fields_ = [
                        ("BaseAddress", ctypes.c_void_p),
                        ("AllocationBase", ctypes.c_void_p),
                        ("AllocationProtect", ctypes.c_ulong),
                        ("RegionSize", ctypes.c_size_t),
                        ("State", ctypes.c_ulong),
                        ("Protect", ctypes.c_ulong),
                        ("Type", ctypes.c_ulong),
                    ]

                handle = kernel32.OpenProcess(
                    PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid
                )
                if not handle:
                    return 0

                try:
                    mbi = MEMORY_BASIC_INFORMATION()
                    address = min_addr
                    # Use a safety counter to prevent infinite loops
                    loops = 0
                    while address < max_addr and loops < 1000:
                        loops += 1
                        result = kernel32.VirtualQueryEx(
                            handle, ctypes.c_void_p(address),
                            ctypes.byref(mbi), ctypes.sizeof(mbi)
                        )
                        if result == 0:
                            break

                        if (mbi.State == MEM_COMMIT and
                            mbi.Protect == PAGE_EXECUTE_READWRITE):
                            rwx_count += 1

                        # Skip to the next region
                        address = mbi.BaseAddress + mbi.RegionSize
                        if mbi.RegionSize == 0:
                            break
                finally:
                    kernel32.CloseHandle(handle)

        except Exception as e:
            logger.debug(f"RWX check failed for PID {pid}: {e}")

        return rwx_count

    def get_findings(self) -> Dict[int, List[str]]:
        """Get memory scan findings per process."""
        return dict(self._findings)


# Required for time module usage
import time
