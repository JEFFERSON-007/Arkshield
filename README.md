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
- `GET /threat-intel/global` + domain/hash lookups (Phase 30): Global threat intelligence with telemetry-driven reputation scoring.
- `GET /security/integrity` + watch/alerts endpoints (Phase 31): File integrity monitoring with baseline hash tamper detection.
- `GET /devices/usb` + device history/block endpoints (Phase 32): Removable device tracking with policy-layer block controls.
- `GET /security/privilege-events` + `GET /security/admin-actions` (Phase 33): Privilege escalation indicators and admin action monitoring.
- `GET /ransomware/alerts` + `POST /ransomware/simulate` (Phase 34): Ransomware behavior detection and safe simulation workflows.
- `GET /security/credential-theft` + `GET /security/auth-anomalies` (Phase 35): Credential theft signal detection and authentication anomaly analytics.
- `GET /dns/logs` + `GET /dns/suspicious` + `POST /dns/block/{domain}` (Phase 36): DNS monitoring, suspicious-domain detection, and policy-layer blocking.
- `GET /network/traffic` + `GET /network/anomalies` (Phase 37): Traffic sampling with baseline-driven anomaly detection.
- `GET /insider/activity` + `GET /insider/risk-scores` (Phase 38): User-centric behavioral analytics and insider risk scoring.
- `GET /patch/status` + `GET /patch/vulnerabilities` + `POST /patch/recommendations` (Phase 39): Patch posture analysis, vulnerability signals, and prioritized remediation plans.
- `GET /supply-chain/dependencies` + `GET /supply-chain/vulnerabilities` (Phase 40): Dependency inventory and heuristic supply-chain vulnerability detection.
- `GET /containers` + `GET /containers/security` + `POST /containers/scan` (Phase 41): Container runtime inventory and security posture scans.
- `GET /kubernetes/cluster` + `GET /kubernetes/security` (Phase 42): Kubernetes cluster discovery and workload security posture checks.
- `GET /cloud/posture` + `GET /cloud/misconfigurations` (Phase 43): Cloud CLI-context posture analysis and misconfiguration detection.
- `GET /compliance/status` + `GET /compliance/report` (Phase 44): Framework-aligned compliance posture and remediation-focused report generation.
- `GET /risk/score` + `GET /risk/critical-assets` (Phase 45): Cross-domain enterprise risk scoring and critical asset prioritization.
- `GET /policy` + `POST /policy/apply` + `GET /policy/violations` (Phase 46): Runtime security policy management and telemetry-driven policy violation tracking.
- `GET /playbooks` + `POST /playbooks/run` (Phase 47): Automated response playbook catalog and simulated execution timelines.
- `GET /system/digital-twin` + `POST /system/simulate-attack` (Phase 48): Digital twin state snapshots with scenario-driven attack impact simulation.
- `GET /autonomous/status` + `POST /autonomous/enable` (Phase 49): Autonomous defense readiness, control mode, and risk-triggered response execution.
- `GET /security/graph` + `GET /security/graph/threats` (Phase 50): Global security graph of identities, assets, threat nodes, and exposure paths.
- `GET /behavior/baseline` + `POST /behavior/baseline/train` + `GET /behavior/anomalies` (Phase 51): Baseline training from telemetry and anomaly drift detection.
- Phases 52-140 are exposed as baseline API routes via the expansion registry. Check `GET /phases/expansion/status` for coverage details.

## Documentation

Architecture and platform design docs are in `docs/`.
Extended roadmap for Phases 26-140 is in `docs/PHASES_26_140_ROADMAP.md`.
