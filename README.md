# 🛡️ ArkShield: Autonomous Cyber Defense Platform

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Platform: Windows | Linux](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-blue.svg)](#-platform-support)
[![Version: 1.0.0](https://img.shields.io/badge/Version-1.0.0-green.svg)](#)

**ArkShield** is a professional-grade, autonomous cyber defense ecosystem designed for real-time endpoint monitoring, telemetry correlation, and AI-driven threat mitigation. Built with a cross-platform architecture, it provides robust security for both Windows and Linux environments.

---

## 🚀 Key Features

### 🔍 Real-Time Monitoring
- **Process Sentinel**: Tracks process creation, termination, and suspicious parent-child relationships.
- **Network Watcher**: Monitors active connections, listening ports, and identifies anomalous traffic patterns.
- **Filesystem Integrity**: Real-time tracking of file modifications, deletions, and unauthorized access in critical directories.
- **Persistence Detection**: Scans and monitors system persistence mechanisms (Registry Run keys, Services, Scheduled Tasks, WMI).
- **Memory Security**: Heuristic scanning of process memory for known malware signatures and injection techniques.

### 🧠 AI-Assisted Analysis
- **Behavioral Scoring**: Uses machine learning models to score events based on risk and deviation from established baselines.
- **Anomaly Detection**: Identifies "impossible travel", brute force attempts, and lateral movement indicators.
- **Automated Triage**: Prioritizes alerts using a multi-factor risk matrix to reduce analyst fatigue.

### ⚡ Autonomous Response
- **Response Orchestrator**: Executes defensive actions based on pre-defined security policies.
- **Playbook Engine**: YAML-driven automation for containment (blocking IPs, killing processes, isolating nodes).
- **Self-Healing agent**: Integrated anti-tamper and deception (honeypot) modules to protect the defense platform itself.

---

## 🌐 Platform Support

| Feature | Windows 10/11 | Linux (Ubuntu/Debian/RHEL/Arch) |
| :--- | :---: | :---: |
| **Native App** | ✅ (.exe) | ✅ (AppImage/Binary) |
| **Monitors** | WMI, Registry, Event Log | /proc, /sys, systemd |
| **Firewall** | netsh / Windows Firewall | ufw / iptables / nftables |
| **Service** | Windows Services | systemd units |

---

## 📂 Repository Structure

```text
├── 📦 docs/                # Comprehensive architecture and roadmap docs
├── 📦 src/arkshield/       # Main platform source code
│   ├── 🛠️ agent/           # Unified monitoring agent
│   ├── 🧠 ai/              # Analysis and behavioral engine
│   ├── 🌐 api/             # FastAPI backend & Web Dashboard
│   ├── 📡 telemetry/       # Event normalization and storage
│   └── ⚡ response/        # Orchestration and playbook engine
├── 📦 src/storage_manager/ # Standalone professional storage cleanup utility
├── 📦 windows/             # Windows-specific app wrappers & build scripts
├── 📦 linux/               # Linux-specific app wrappers & build scripts
└── 📦 tests/               # 🧪 Diagnostic and verification suite
```

---

## 🛠️ Quick Start

### 1. Installation
```bash
# Install core dependencies
pip install -r requirements.txt

# Install as editable package
pip install -e .
```

### 2. Standard Launch
**Windows:**
```cmd
cd windows
START_DESKTOP.bat
```

**Linux:**
```bash
cd linux
bash START_DESKTOP.sh
```

### 3. Server-Only (CLI)
```bash
python -m arkshield.main
```

---

## 📊 Performance & Reliability

- **High Stability**: Recent updates have implemented absolute path resolution for all core modules, ensuring 100% reliability across different execution environments.
- **Clean Workspace**: Logging is now centralized in the `logs/` directory for better organization.
- **Scalable Backend**: Powered by FastAPI with an 11,000+ line high-performance server core.

---

## 🛡️ Storage Manager
Included within this repo is a professional CLI utility for system hygiene.
```bash
# List all junk categories detected
python -m storage_manager.cli.main categories

# Perform a deep scan
python -m storage_manager.cli.main scan C:\Users
```

---

## 📚 Documentation
- [Installation Guide](INSTALL.md)
- [Project Architecture](PROJECT_STRUCTURE.md)
- [Compatibility Report](docs/reports/CROSS_PLATFORM_REPORT.md)
- [Development Roadmap](docs/PHASES_26_140_ROADMAP.md)

---

Developed with ❤️ for a safer digital world.  
**© 2026 ArkShield Defense Team**
