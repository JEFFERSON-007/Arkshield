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

## API Highlight

- `GET /threat/posture` (Phase 24): Aggregates recent events and alerts into a posture score, threat density, severity distribution, and prioritized recommendations.
- `POST /threat/auto-prioritize` (Phase 25): Produces an SLA-ready priority queue for alerts using risk, severity, status, and age.
- `POST /threat-hunt/query` + related endpoints (Phase 26): Analyst-driven hunting with advanced filtering and saved query workflows.
- `GET /forensics/timeline` + related endpoints (Phase 27): Attack timeline reconstruction, process ancestry, and file history.
- `POST /sandbox/analyze` + related endpoints (Phase 28): Safe, non-executing malware sandbox with behavior-oriented reporting.
- `POST /ai/malware/classify` + `GET /ai/malware/model-status` (Phase 29): Heuristic malware family classification and model runtime health.
- Phases 30-140 are now exposed as baseline API routes via the expansion registry. Check `GET /phases/expansion/status` for coverage details.

## Documentation

Architecture and platform design docs are in `docs/`.
Extended roadmap for Phases 26-140 is in `docs/PHASES_26_140_ROADMAP.md`.
