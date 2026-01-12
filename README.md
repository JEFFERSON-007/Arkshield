# Arkshield

Arkshield is an autonomous cybersecurity platform with endpoint monitoring, telemetry correlation, AI-assisted analysis, and automated response playbooks.

This repository also includes a standalone storage cleanup utility (`storage-manager.py` and `src/storage_manager/`) used for system hygiene workflows.

## Project Layout

```text
src/arkshield/
	agent/        Endpoint monitors (process, filesystem, memory, network, persistence)
	telemetry/    Event pipeline and storage
	ai/           Behavioral analytics and scoring
	api/          FastAPI server and dashboard
	response/     Playbook engine and response orchestration
	security/     RBAC, audit, deception, threat intel
	main.py       Main platform entry point

src/storage_manager/
	CLI + scanning, detection, and cleanup utilities
```

## Quick Start

### 1. Install

```bash
pip install -r requirements.txt
pip install -e .
```

### 2. Run Arkshield

```bash
python -m arkshield.main
```

### 3. Arkshield Demo

```bash
python tests/demo_arkshield.py
```

### 4. Storage Manager (Optional)

```bash
python storage-manager.py --help
python storage-manager.py scan .
python storage-manager.py clean . --dry-run
```

## Dashboard

The dashboard UI is located at `src/arkshield/api/dashboard.html` and connects to the local API server.

## Docs

Detailed architecture and design docs are under `docs/`.
