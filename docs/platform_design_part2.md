# ARKSHIELD — Part 2: Enterprise Architecture & Data Pipeline

## SECTION 5 — Full Enterprise Architecture

### 5.1 Architecture Tiers

```
┌───────────────────────────────────────────────────────────────────┐
│                        TIER 1: EDGE LAYER                         │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐            │
│  │ Windows  │ │  Linux   │ │  macOS   │ │  Cloud   │            │
│  │  Agent   │ │  Agent   │ │  Agent   │ │  Agent   │            │
│  └────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬─────┘            │
│       │             │             │             │                  │
│  ┌────┴─────────────┴─────────────┴─────────────┴────┐           │
│  │          Edge Telemetry Aggregators                │           │
│  │   (Regional pre-processing & filtering)           │           │
│  └──────────────────────┬────────────────────────────┘           │
└─────────────────────────┼────────────────────────────────────────┘
                          │
┌─────────────────────────┼────────────────────────────────────────┐
│                   TIER 2: INGESTION LAYER                        │
│  ┌──────────────────────┴────────────────────────────┐           │
│  │           Apache Kafka Cluster                     │           │
│  │   (Event streaming — partitioned by org/region)    │           │
│  └──────────┬────────────┬────────────┬──────────────┘           │
│             │            │            │                           │
│  ┌──────────▼──┐ ┌───────▼──────┐ ┌──▼──────────────┐           │
│  │ Normalizer  │ │  Enrichment  │ │  Schema          │           │
│  │ Service     │ │  Service     │ │  Validator       │           │
│  └──────────┬──┘ └───────┬──────┘ └──┬──────────────┘           │
│             └────────────┼───────────┘                           │
└──────────────────────────┼───────────────────────────────────────┘
                           │
┌──────────────────────────┼───────────────────────────────────────┐
│                   TIER 3: ANALYSIS LAYER                         │
│  ┌───────────────────────┴──────────────────────────┐            │
│  │         Real-Time Stream Processing               │            │
│  │   (Apache Flink / custom Rust stream processors) │            │
│  └──────┬──────────┬──────────┬─────────────────────┘            │
│         │          │          │                                    │
│  ┌──────▼────┐ ┌───▼──────┐ ┌▼────────────┐                     │
│  │ Behavioral│ │ Anomaly  │ │ Correlation │                      │
│  │ Analysis  │ │ Detect   │ │ Engine      │                      │
│  │ Engine    │ │ Engine   │ │ (Graph)     │                      │
│  └──────┬────┘ └───┬──────┘ └┬────────────┘                     │
│         └──────────┼─────────┘                                    │
└────────────────────┼─────────────────────────────────────────────┘
                     │
┌────────────────────┼─────────────────────────────────────────────┐
│              TIER 4: INTELLIGENCE LAYER                          │
│  ┌─────────────────┴────────────────────────────────┐            │
│  │          AI Threat Intelligence Engine             │            │
│  │  ┌────────────┐ ┌────────────┐ ┌──────────────┐  │            │
│  │  │ ML Model   │ │ Threat     │ │ Kill Chain   │  │            │
│  │  │ Ensemble   │ │ Intel Feed │ │ Predictor    │  │            │
│  │  │ Manager    │ │ Aggregator │ │              │  │            │
│  │  └────────────┘ └────────────┘ └──────────────┘  │            │
│  └─────────────────┬────────────────────────────────┘            │
└────────────────────┼─────────────────────────────────────────────┘
                     │
┌────────────────────┼─────────────────────────────────────────────┐
│              TIER 5: ACTION LAYER                                │
│  ┌─────────────────┴────────────────────────────────┐            │
│  │       Autonomous Defense Engine                   │            │
│  │  ┌────────────┐ ┌────────────┐ ┌──────────────┐  │            │
│  │  │ Response   │ │ Playbook   │ │ Rollback     │  │            │
│  │  │ Orchestr.  │ │ Engine     │ │ Manager      │  │            │
│  │  └────────────┘ └────────────┘ └──────────────┘  │            │
│  └─────────────────┬────────────────────────────────┘            │
└────────────────────┼─────────────────────────────────────────────┘
                     │
┌────────────────────┼─────────────────────────────────────────────┐
│              TIER 6: DATA & PRESENTATION LAYER                   │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌───────────────────┐   │
│  │PostgreSQL│ │ Cassandra│ │  Redis   │ │  Object Storage   │   │
│  │(Config,  │ │(Time-    │ │(Real-    │ │  (PCAP, Binary    │   │
│  │ Users)   │ │ series)  │ │ time)    │ │   Artifacts)      │   │
│  └──────────┘ └──────────┘ └──────────┘ └───────────────────┘   │
│  ┌──────────────────────────────────────────────────────────┐    │
│  │              Security Dashboard (React + WebGL)           │    │
│  │         API Gateway (GraphQL + REST + WebSocket)          │    │
│  └──────────────────────────────────────────────────────────┘    │
└──────────────────────────────────────────────────────────────────┘
```

### 5.2 Component Details

#### Endpoint Agents
- **Deployment**: Lightweight agents (<50MB RAM, <2% CPU) installed via MDM, GPO, or package managers
- **Languages**: Core in Rust (performance-critical paths), Python (ML inference), C (kernel modules)
- **Capabilities**: File monitoring, process tracing, network capture, memory scanning, registry monitoring (Windows), kernel event tracing
- **Local AI**: Embedded TinyML models for edge inference — immediate threat classification without cloud roundtrip
- **Offline mode**: Full protection capability when disconnected from the platform, with event queuing and sync on reconnection

#### Distributed Telemetry Collectors
- **Regional aggregators**: Deployed in each network segment/region to pre-process and compress telemetry
- **Protocol support**: gRPC (primary), MQTT (IoT/edge), HTTP/2 (fallback)
- **Filtering**: Configurable event filtering and sampling to manage bandwidth while preserving security-critical events
- **Buffering**: Local event buffers (RocksDB) for resilience during network outages

#### Microservices Security Platform
- **Service mesh**: Istio-based with mTLS for all inter-service communication
- **Services**: 20+ microservices including Normalizer, Enrichment, Correlation, Alert Manager, Response Orchestrator, Policy Engine, RBAC, Audit Logger
- **Deployment**: Kubernetes with auto-scaling based on event throughput
- **Languages**: Go (API services), Rust (data processing), Python (ML services)

#### AI Analysis Engines
- **Model serving**: NVIDIA Triton Inference Server for GPU-accelerated model serving
- **Model types**: Behavioral anomaly detection, malware classification, network threat detection, NLP for log analysis
- **Training pipeline**: Apache Airflow-orchestrated training pipelines with MLflow experiment tracking
- **Federated learning**: Privacy-preserving model updates across customer deployments using secure aggregation

#### Threat Intelligence Platform
- **Feed aggregation**: STIX/TAXII, MISP, commercial feeds (VirusTotal, Recorded Future, Mandiant)
- **Enrichment**: Automated IOC enrichment with WHOIS, passive DNS, sandbox analysis
- **Custom intelligence**: Organization-specific threat intelligence from internal telemetry
- **Sharing**: Bi-directional threat intelligence sharing with ISACs and trusted partners

#### Incident Response Automation
- **SOAR integration**: Built-in Security Orchestration, Automation, and Response engine
- **Playbooks**: YAML-defined response playbooks with conditional logic, parallel execution, and human approval gates
- **Evidence collection**: Automated forensic artifact collection (memory dumps, disk images, network captures)
- **Case management**: Integrated case tracking with evidence chain-of-custody management

#### Analytics and Visualization
- **Real-time dashboards**: WebSocket-driven dashboards with sub-second update latency
- **Threat hunting**: Jupyter-integrated threat hunting workbench with custom query language
- **Reporting**: Automated compliance reporting (SOC 2, ISO 27001, HIPAA, PCI DSS, NIST CSF)
- **3D visualization**: WebGL-powered network topology and attack path visualization

---

## SECTION 6 — Endpoint Agent Design

### 6.1 Agent Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                   ARKSHIELD AGENT                       │
│                                                              │
│  ┌─────────────────────────────────────────────────────┐    │
│  │              USER-SPACE MODULES                      │    │
│  │                                                      │    │
│  │  ┌──────────────┐  ┌──────────────┐  ┌───────────┐  │    │
│  │  │ File System  │  │   Process    │  │  Network  │  │    │
│  │  │  Monitor     │  │   Monitor    │  │  Monitor  │  │    │
│  │  └──────────────┘  └──────────────┘  └───────────┘  │    │
│  │                                                      │    │
│  │  ┌──────────────┐  ┌──────────────┐  ┌───────────┐  │    │
│  │  │   Memory     │  │  Startup     │  │  Script   │  │    │
│  │  │   Scanner    │  │  Persistence │  │  Analyzer │  │    │
│  │  └──────────────┘  └──────────────┘  └───────────┘  │    │
│  │                                                      │    │
│  │  ┌──────────────┐  ┌──────────────┐  ┌───────────┐  │    │
│  │  │  Threat      │  │  Telemetry   │  │  Local    │  │    │
│  │  │  Response    │  │  Dispatcher  │  │  AI       │  │    │
│  │  └──────────────┘  └──────────────┘  └───────────┘  │    │
│  └─────────────────────────────────────────────────────┘    │
│                                                              │
│  ┌─────────────────────────────────────────────────────┐    │
│  │              KERNEL-SPACE MODULES                    │    │
│  │                                                      │    │
│  │  ┌──────────────┐  ┌──────────────┐  ┌───────────┐  │    │
│  │  │  Syscall     │  │   Rootkit    │  │  Kernel   │  │    │
│  │  │  Tracer      │  │   Detector   │  │  Integrity│  │    │
│  │  └──────────────┘  └──────────────┘  └───────────┘  │    │
│  │                                                      │    │
│  │  ┌──────────────┐  ┌──────────────┐                  │    │
│  │  │  Firmware    │  │  Driver      │                  │    │
│  │  │  Integrity   │  │  Monitor     │                  │    │
│  │  └──────────────┘  └──────────────┘                  │    │
│  └─────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────┘
```

### 6.2 Module Specifications

#### File System Monitor
- **Technology**: Windows — Minifilter driver (like Microsoft's WdFilter); Linux — fanotify + inotify; macOS — Endpoint Security Framework
- **Capabilities**:
  - Real-time monitoring of file create, modify, delete, rename, permission changes
  - Content inspection for sensitive data patterns (SSN, credit cards, API keys) via streaming regex
  - File entropy calculation for ransomware detection (high-entropy writes indicate encryption)
  - YARA rule scanning on file creation/modification events
  - Software Bill of Materials tracking for installed applications
- **Performance**: <1ms overhead per file operation, event batching for high-throughput directories

#### Memory Scanner
- **Technology**: Process memory access via ReadProcessMemory (Windows), /proc/pid/mem (Linux), mach_vm_read (macOS)
- **Capabilities**:
  - Periodic and triggered memory scanning for known shellcode patterns
  - Detection of reflective DLL injection via PE header scanning in non-image memory regions
  - Process hollowing detection by comparing in-memory images to on-disk binaries
  - ROP chain detection via stack analysis for return addresses pointing to non-standard locations
  - Heap spray detection via entropy analysis of large heap allocations
- **Frequency**: Background scan every 30 seconds for critical processes, event-triggered for suspicious processes

#### Process Monitor
- **Technology**: ETW (Event Tracing for Windows), eBPF (Linux), Endpoint Security Framework (macOS)
- **Capabilities**:
  - Complete process tree tracking (parent-child relationships, command lines, environment variables)
  - Process behavior profiling (system calls, API calls, resource usage patterns)
  - Privilege escalation detection (token manipulation, impersonation, setuid changes)
  - Process injection detection (APC injection, thread hijacking, atom bombing)
  - Anomalous process execution detection (unusual parent-child relationships, rare binaries)
- **Data**: Full process lifecycle events cached locally for 24 hours for correlation

#### System Call Tracer
- **Technology**: ETW on Windows, eBPF/seccomp-bpf on Linux, dtrace on macOS
- **Capabilities**:
  - Selective syscall tracing based on risk profiles (file, network, process, registry syscalls)
  - Syscall sequence analysis for exploit detection (unusual sequences indicating ROP/JOP exploitation)
  - Frequency analysis for resource abuse detection (excessive file operations, network connections)
  - Cross-reference with process behavior models to identify deviations
- **Performance**: eBPF programs execute in kernel space with <5μs overhead per syscall

#### Network Monitor
- **Technology**: WFP (Windows Filtering Platform), eBPF/TC (Linux), Network Extension Framework (macOS)
- **Capabilities**:
  - All network connections tracked with process attribution (which process opened which connection)
  - DNS query monitoring and analysis (DGA detection, DNS tunneling detection)
  - TLS certificate inspection (JA3/JA3S fingerprinting, certificate anomaly detection)
  - HTTP/HTTPS metadata extraction (URLs, headers, response codes) without breaking encryption
  - Beacon detection (periodic communication patterns indicating C2 channels)
  - Lateral movement detection (unusual SMB, WMI, WinRM, SSH connections between internal hosts)
- **Data**: Connection metadata stored for 7 days, full packet capture configurable for forensic events

#### Startup Persistence Detection
- **Technology**: Registry monitoring (Windows), systemd/init.d monitoring (Linux), LaunchAgent/Daemon monitoring (macOS)
- **Capabilities**:
  - Monitoring of all persistence mechanisms (400+ Windows persistence locations, Linux cron/systemd, macOS launchd)
  - Baseline comparison for new persistence entries
  - Known-good persistence whitelist with automated learning
  - Scheduled task monitoring and analysis
  - WMI event subscription monitoring (Windows)
  - Browser extension persistence tracking

#### Rootkit Detection
- **Capabilities**:
  - Cross-view detection: Comparing kernel-reported data with user-space queries to find hidden processes, files, and network connections
  - DKOM (Direct Kernel Object Manipulation) detection via kernel object integrity checking
  - SSDT (System Service Descriptor Table) hook detection on Windows
  - IDT (Interrupt Descriptor Table) integrity verification
  - Inline hooking detection for critical kernel functions
  - eBPF program enumeration and verification on Linux

#### Kernel Integrity Checks
- **Capabilities**:
  - Code integrity verification of loaded kernel modules/drivers
  - Kernel memory read-only section verification
  - Secure Boot chain validation
  - Hypervisor integrity checks (when running in VMs)
  - Kernel configuration audit (ASLR, DEP, SMEP, SMAP verification)

#### Firmware Integrity Checks
- **Capabilities**:
  - UEFI firmware hash verification against known-good baselines
  - SPI flash content verification
  - ME/AMT firmware state monitoring (Intel platforms)
  - BMC firmware integrity (server platforms)
  - TPM-based measured boot log analysis

---

## SECTION 7 — Telemetry and Data Collection Pipeline

### 7.1 Pipeline Architecture

```
Endpoints (100K+)
      │
      ▼
┌──────────────────────────────────────────────────────┐
│              INGESTION TIER                           │
│                                                       │
│  ┌─────────────┐     ┌─────────────┐                 │
│  │   gRPC      │     │   MQTT      │                 │
│  │   Receivers │     │   Bridge    │                 │
│  │   (x20)     │     │   (x5)     │                 │
│  └──────┬──────┘     └──────┬──────┘                 │
│         └─────────┬─────────┘                        │
│                   ▼                                   │
│  ┌──────────────────────────────┐                    │
│  │    Event Gateway             │                    │
│  │    - Authentication          │                    │
│  │    - Rate limiting           │                    │
│  │    - Schema validation       │                    │
│  │    - Deduplication           │                    │
│  └──────────────┬───────────────┘                    │
└─────────────────┼────────────────────────────────────┘
                  ▼
┌──────────────────────────────────────────────────────┐
│              STREAMING TIER (Apache Kafka)            │
│                                                       │
│  Topics:                                              │
│  ├── raw-events.{os-type}.{region}                   │
│  ├── normalized-events                                │
│  ├── enriched-events                                  │
│  ├── correlated-events                                │
│  ├── alerts                                           │
│  ├── threat-intel-updates                             │
│  └── response-commands                                │
│                                                       │
│  Throughput: 2M+ events/sec                           │
│  Retention: 72 hours (raw), 30 days (enriched)       │
└──────────────────┬───────────────────────────────────┘
                   ▼
┌──────────────────────────────────────────────────────┐
│            PROCESSING TIER                            │
│                                                       │
│  ┌──────────────┐  ┌──────────────┐  ┌────────────┐ │
│  │  Normalizer  │  │  Enrichment  │  │ Correlator │ │
│  │  Service     │  │  Service     │  │ Service    │ │
│  │              │  │              │  │            │ │
│  │ - Field      │  │ - GeoIP      │  │ - Temporal │ │
│  │   mapping    │  │ - Threat     │  │   linking  │ │
│  │ - Schema     │  │   intel IOC  │  │ - Entity   │ │
│  │   enforcement│  │ - Asset CMDB │  │   grouping │ │
│  │ - Timestamp  │  │ - User/ID   │  │ - Attack   │ │
│  │   alignment  │  │   resolution │  │   chain    │ │
│  │ - Data type  │  │ - Vuln state │  │   matching │ │
│  │   coercion   │  │              │  │            │ │
│  └──────────────┘  └──────────────┘  └────────────┘ │
│                                                       │
│  ┌──────────────────────────────────────────────────┐│
│  │         Real-Time Detection Engine                ││
│  │  - Streaming rule evaluation (Sigma rules)       ││
│  │  - ML model inference (behavioral anomaly)       ││
│  │  - Threshold and frequency alerts                ││
│  │  - Complex event processing (multi-event rules)  ││
│  └──────────────────────────────────────────────────┘│
└──────────────────────────────────────────────────────┘
```

### 7.2 Scale Targets

| Metric | Target |
|--------|--------|
| Event ingestion rate | 2M+ events/second |
| Daily event volume | 100B+ events/day |
| Event normalization latency | <100ms p99 |
| Enrichment latency | <200ms p99 |
| Detection rule evaluation | <500ms p99 |
| ML inference latency | <50ms p99 |
| Data retention (hot) | 30 days |
| Data retention (warm) | 1 year |
| Data retention (cold) | 7 years |

### 7.3 Event Schema (Unified format — OCSF-based)

```json
{
  "event_id": "uuid-v7",
  "timestamp": "2026-03-04T10:00:00.000Z",
  "event_class": "process_activity",
  "event_type": "process_launch",
  "severity": 3,
  "source": {
    "agent_id": "agent-uuid",
    "hostname": "workstation-42",
    "os": "windows",
    "os_version": "11.24H2",
    "ip": "10.0.1.42",
    "org_id": "org-uuid"
  },
  "actor": {
    "process": {
      "pid": 4532,
      "name": "powershell.exe",
      "path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
      "cmd_line": "powershell -enc SQBFAFgA...",
      "hash": {"sha256": "abc123..."},
      "parent_pid": 1204,
      "parent_name": "cmd.exe",
      "user": "DOMAIN\\jdoe",
      "integrity_level": "high"
    }
  },
  "target": {},
  "enrichment": {
    "geo": {"country": "US", "city": "San Francisco"},
    "threat_intel": {"matched_iocs": [], "risk_score": 72},
    "mitre_attack": {"tactic": "execution", "technique": "T1059.001"}
  },
  "raw": "base64-encoded-raw-event"
}
```

---

## SECTION 8 — Event-Driven System Architecture

### 8.1 Event Bus Design

**Primary: Apache Kafka** — Chosen for durability, ordering guarantees, replay capability, and proven scale at billions of events/day.

**Secondary: NATS** — Used for lightweight real-time command-and-control messages between the platform and agents (low-latency, fire-and-forget acceptable).

**Tertiary: RabbitMQ** — Used for task queuing where exactly-once processing semantics are critical (incident response workflow tasks, report generation).

### 8.2 Kafka Topology

```
PRODUCERS                    KAFKA CLUSTER                 CONSUMERS
─────────                    ─────────────                 ─────────

Endpoint Agents ──►  raw-events.windows.us-east  ──► Normalizer Service
                     raw-events.linux.us-east         (Consumer Group: normalizers)
                     raw-events.macos.us-east
                     raw-events.cloud.us-east

Normalizer      ──►  normalized-events           ──► Enrichment Service
                                                      (Consumer Group: enrichers)

Enrichment      ──►  enriched-events             ──► Correlation Engine
                                                      ML Analysis Engine
                                                      Storage Writer
                                                      (3 Consumer Groups)

Correlation     ──►  correlated-alerts           ──► Alert Manager
                                                      Response Orchestrator
                                                      Dashboard (WebSocket)

ML Engine       ──►  ml-detections               ──► Alert Manager

Alert Manager   ──►  notifications               ──► Email/Slack/PagerDuty/Webhook

Response Orch.  ──►  response-commands           ──► Agent Command Router ──► Agents (via NATS)

Threat Intel    ──►  threat-intel-updates         ──► Enrichment Service
Platform                                              Agent Config Manager
```

### 8.3 Processing Guarantees

| Pipeline Stage | Delivery Guarantee | Rationale |
|---|---|---|
| Agent → Kafka | At-least-once | Agent-side buffering with acknowledgment; duplicates handled by deduplication service |
| Normalization | Exactly-once | Kafka transactions ensure idempotent processing |
| Enrichment | At-least-once | Enrichment is idempotent by design |
| Correlation | At-least-once | Stateful processing with checkpointing via Flink |
| Alert Generation | Exactly-once | Critical — no duplicate alerts via dedup window |
| Response Commands | At-most-once with confirmation | Agent confirms execution; re-issue if no confirmation within timeout |

### 8.4 NATS Command & Control

```
NATS Subjects:
├── agent.{org_id}.{agent_id}.command     (Platform → Agent: response commands)
├── agent.{org_id}.{agent_id}.status      (Agent → Platform: health/status)
├── agent.{org_id}.{agent_id}.config      (Platform → Agent: config updates)
├── agent.{org_id}.broadcast.{region}     (Platform → All agents: mass updates)
└── agent.{org_id}.{agent_id}.upgrade     (Platform → Agent: agent upgrades)
```

- **Latency target**: <10ms for command delivery
- **Use case**: Immediate response commands (kill process, isolate host, update detection rules)
- **Security**: TLS + JWT authentication per agent, subject-level authorization
