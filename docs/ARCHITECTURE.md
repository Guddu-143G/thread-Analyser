# Threat Analyser - System Architecture & Component Design

This document details the architectural layout, component boundaries, security models, data flows, and scaling characteristics of the **Threat Analyser** platform.

---

## 1. System Decomposition

```
+-------------------------------------------------------------------------------+
|                            SOC Web Console (Frontend)                         |
|   React 18 + Vite SPA | Tailwind Dark SOC Design System | Axios + JWT Auth    |
|   21 Modular SecOps Pages | Live Console | AI SOC Consensus | PQC Mesh View   |
+---------------------------------------+---------------------------------------+
                                        | HTTP REST / WebSocket (Nginx Proxy)
                                        v
+-------------------------------------------------------------------------------+
|                             FastAPI Backend Gateway                           |
|   - 34 Modular REST Routes (Auth, Ingest, Alerts, PQC, TPM, BLE, Chaos, etc.) |
|   - Multi-Tenant RBAC & Organization Scoping                                  |
|   - NIST FIPS 203/204 Post-Quantum Hybrid Transport Layer                     |
|   - Redis Pub/Sub WebSocket Broadcaster                                       |
+-------------------+-------------------+-------------------+-------------------+
                    |                   |                   |
                    v                   v                   v
        +-------------------+   +---------------+   +-------------------+
        |  PostgreSQL DB    |   | Redis Broker  |   |  Celery Workers   |
        |  SQLAlchemy 2.0   |   | & Pub/Sub     |   |  Async Ingestion  |
        |  Multi-tenant RLS |   | Event Bus     |   |  & Detection      |
        +-------------------+   +---------------+   +---------+---------+
                                                              |
                                                              v
+-------------------------------------------------------------------------------+
|                          Detection & Intelligence Engine                      |
|   - OCSF v1.1.0 Multi-Format Normalizer (Syslog, CEF, JSON, Key-Value)        |
|   - Sigma Rule Compiler (In-Memory Abstract Syntax Matcher)                   |
|   - IOC Threat Intel Matcher (IP, Domain, File Hash, Process)                 |
|   - ML Anomaly Detector (Shannon Entropy & Feature Clustering)                |
|   - Self-Healing GART (Generative Adversarial Red Teaming Loop)               |
|   - Multi-Stage Security Correlation Engine                                   |
|   - Tamper-Evident Merkle & Private ZK-Rollup Threat Ledger                   |
+-------------------------------------------------------------------------------+
```

---

## 2. Directory Layout & Layer Responsibilities

### `frontend/`
- **Purpose**: All client-side User Interface assets and state management.
- **Key Modules**:
  - `src/pages/`: 21 distinct operations pages covering Incident Triage, Threat Intel, Rule authoring, TPM attestation, BLE monitoring, SBOM inventory, AI SOC consensus, and PQC mesh.
  - `src/components/`: Reusable high-fidelity widgets including `Sidebar`, `LiveConsole`, `SeverityBadge`, and `StatCard`.
  - `src/api/client.js`: Centralized Axios instance with JWT refresh and Bearer token interceptor.
  - `src/context/AuthContext.jsx`: Tenant organization and user credential lifecycle state.
  - `nginx.conf` & `Dockerfile`: Multi-stage static compilation served via Nginx reverse proxy.

### `backend/`
- **Purpose**: All server-side business logic, APIs, database persistence, asynchronous queues, and security pipelines.
- **Key Modules**:
  - `app/api/routes/`: Modular endpoints handling authentication, telemetry push, alert triage, compliance, chaos testing, digital twins, and ZK-rollups.
  - `app/core/`: Application settings (`config.py`), database session lifecycle (`db.py`), password hashing & JWT handling (`security.py`), and request dependencies (`deps.py`).
  - `app/models/`: SQLAlchemy schema models strictly partitioned by `organization_id`.
  - `app/detection/`: The core detection pipeline including `parser.py` (OCSF normalization), `sigma_compiler.py`, `correlator.py`, and `anomaly_detector.py`.
  - `app/workers/`: Celery asynchronous worker and Celery beat tasks.
  - `tests/`: Organized into `unit/` and `e2e/` with central test runner `run_all_tests.py`.

### `agent/`
- **Purpose**: Lightweight host/endpoint telemetry forwarders and sensors installed on monitored infrastructure.
- **Key Modules**:
  - `ta_agent.py`: Python log forwarder with SQLite WAL offline queue ensuring zero log loss during network disconnects.
  - `hci_monitor.go`: Bluetooth Low Energy / HCI RF packet collector.
  - `ebpf/`: Rust / eBPF kernel event probes.

### `scripts/`
- **Purpose**: Tooling and attack scenario generation for testing and demonstrations.
- **Key Modules**:
  - `threat_generator.py`: Synthetic telemetry generator for SSH brute force, credential dumping, obfuscated PowerShell, privilege escalation, and C2 traffic.
  - `sandbox-ingest.ps1` & `sandbox-ingest.sh`: One-click ingestion launchers.

### `docs/`
- **Purpose**: System specifications, PRD, and operational design documents.

---

## 3. Data Flow & Detection Pipeline

1. **Ingest**: Logs arrive via file upload (`POST /api/ingest/upload`) or endpoint API push (`POST /api/ingest/push`). The endpoint performs immediate validation and enqueues a Celery task, returning `202 Accepted`.
2. **OCSF Normalization**: `app/detection/parser.py` extracts standard schema fields (`src_ip`, `dest_ip`, `user`, `process`, `event_type`, `ocsf`) regardless of input dialect (Syslog, CEF, JSON, Windows Events).
3. **IOC Matching**: Events are queried against platform-wide and tenant-specific Threat Indicators (IPs, domains, hashes, process names).
4. **Sigma Evaluation**: Enabled declarative Sigma rules and sliding-window frequency rules are evaluated in-memory.
5. **Correlation & Anomaly Scoring**: Multi-stage attacks (e.g., failed login followed by suspicious process spawn) are elevated to high-priority Compound Incidents.
6. **Alert Dispatch**: Verified threats generate `Alert` records and broadcast real-time notifications over Redis WebSocket channels to connected SOC analyst consoles.
