# Arkshield

Arkshield is an autonomous cyber defense platform for endpoint monitoring, telemetry correlation, AI-assisted threat analysis, and automated response playbooks.

This repository also includes a standalone storage cleanup utility (`storage-manager.py` and `src/storage_manager/`) for system hygiene workflows.

## Core Features

- Endpoint monitoring across process, filesystem, network, memory, integrity, and persistence surfaces.
- Telemetry pipeline and threat correlation across attack stages.
- AI analysis engine for anomaly scoring and behavioral detection.
- Automated response orchestration with YAML playbooks.
- FastAPI API server and dashboard UI.
- Security controls including RBAC, audit logging, deception, and threat intel modules.

## Repository Structure

```text
src/arkshield/
  agent/            Endpoint monitors
  telemetry/        Event normalization and storage
  ai/               Analysis and scoring
  data/             Repository/data access layer
  api/              FastAPI server + dashboard assets
  response/         Actions, orchestration, and playbook engine
  security/         RBAC, audit, deception, threat intel
  main.py           Platform entry point

src/storage_manager/
  CLI + scan/clean engine and junk detectors
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

### 3. Run Demo

```bash
python tests/demo_arkshield.py
```

### 4. Optional: Storage Manager

```bash
python storage-manager.py --help
python storage-manager.py scan .
python storage-manager.py clean . --dry-run
```

## Dashboard

Dashboard frontend file: `src/arkshield/api/dashboard.html`

## Documentation

Architecture and platform design docs are in `docs/`.
