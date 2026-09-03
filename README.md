# Threat Analyser

A multi-tenant SaaS platform for detecting security threats on personal devices and within organizations — ingest logs, match against threat intelligence (IOCs), evaluate against configurable Sigma detection rules, and triage alerts from a real-time SOC console.

---

## Architecture Overview

```
threat analyser/
├── frontend/                                # React + Vite + Tailwind CSS SOC Console
│   ├── src/
│   │   ├── api/                             # Axios client & JWT interceptors
│   │   ├── components/                      # SOC UI components (Sidebar, LiveConsole, Badges)
│   │   ├── context/                         # AuthContext (JWT session management)
│   │   ├── pages/                           # 21 Security & SOC Console Pages
│   │   ├── styles/                          # Tailwind tokens & dark SOC theme
│   │   ├── App.jsx                          # Main routing tree
│   │   └── main.jsx                         # React entrypoint
│   ├── Dockerfile                           # Production Nginx container build
│   └── nginx.conf                           # Reverse proxy configuration
│
├── backend/                                 # FastAPI + SQLAlchemy + Celery + Python 3.11 Backend
│   ├── app/
│   │   ├── api/routes/                      # 34 modular FastAPI route controllers
│   │   ├── core/                            # Configuration, DB engine, JWT auth, KMS
│   │   ├── models/                          # Multi-tenant SQLAlchemy database models
│   │   ├── schemas/                         # Pydantic serialization schemas
│   │   ├── detection/                       # OCSF parser, Sigma compiler, GART engine, Correlator
│   │   ├── workers/                         # Celery app & async ingestion background workers
│   │   ├── analytics/                       # Threat hunting & FHE analytics
│   │   ├── audit/                           # Merkle tree & ZK-Rollup tamper-evident ledgers
│   │   ├── chaos/                           # Chaos engineering engine
│   │   ├── deception/                       # Honey-tokens & ephemeral honeynet
│   │   ├── enclave/                         # Confidential computing enclave sanitizer
│   │   ├── forensics/                       # Time-travel flight recorder forensics
│   │   ├── security/                        # Post-Quantum NIST FIPS 203/204 hybrid crypto & KMS
│   │   ├── main.py                          # FastAPI application factory
│   │   └── seed.py                          # Database seed script for built-in rules & IOCs
│   ├── tests/                               # Consolidated Test Suites
│   │   ├── unit/                            # Unit tests for parsers, sigma, ML, KMS, ledgers
│   │   ├── e2e/                             # End-to-end integration & version tests (v2 - v15)
│   │   └── run_all_tests.py                 # Central unit test runner
│   ├── Dockerfile                           # Python 3.11 API & Worker container
│   ├── entrypoint.sh                        # Database bootstrap script
│   └── requirements.txt                     # Backend dependencies
│
├── agent/                                   # Endpoint Telemetry Forwarders & Sensors
│   ├── ebpf/                                # Rust / eBPF kernel probes
│   ├── hci_monitor.go                       # Bluetooth Low Energy / HCI interface sensor
│   ├── ta_agent.py                          # Zero-loss WAL-buffered log forwarder
│   └── README.md                            # Agent deployment guide
│
├── scripts/                                 # Simulation, Ingestion & Tooling
│   ├── threat_generator.py                  # Synthetic enterprise attack generator
│   ├── sandbox-ingest.ps1                   # PowerShell one-click simulation launcher
│   └── sandbox-ingest.sh                    # Bash one-click simulation launcher
│
├── docs/                                    # Technical & Product Documentation
│   ├── PRD.md                               # Product Requirements Document
│   └── ARCHITECTURE.md                      # System Architecture & Data Flow Guide
│
├── docker-compose.yml                       # Full stack Docker composition (DB, Redis, API, Worker, Beat, Frontend)
├── README.md                                # Master project documentation
├── run.md                                   # Operational handbook
└── .env.example                             # Environment variable template
```

---

## Tech Stack

- **Backend**: FastAPI (Python 3.11), PostgreSQL (or Neon Serverless Postgres), SQLAlchemy 2.0
- **Async Processing**: Celery + Redis (log parsing and detection never block the API)
- **Frontend**: React 18, Vite, Tailwind CSS ("SOC Console" dark theme)
- **Deployment**: Docker Compose (Postgres, Redis, API, Celery worker, Celery beat, frontend/nginx)

---

## Quick Start (Docker Compose)

Requires Docker and Docker Compose.

```bash
cp .env.example .env
docker compose up --build -d
```

Then open:
- **App**: http://localhost — register an org, log in, and use the console
- **API docs**: http://localhost:8000/docs (FastAPI's interactive Swagger UI)
- **Health check**: http://localhost:8000/api/health

On first boot, the backend automatically creates the database schema and seeds 5 built-in detection rules plus sample threat indicators.

---

## Quick Simulation Demo

1. Register an account at `http://localhost` (creates your tenant organization).
2. Go to **Log Upload** → click **"Run sample log demo"** or run:
   ```powershell
   .\scripts\sandbox-ingest.ps1
   ```
3. Check **Alerts**, **Dashboard**, **Live Telemetry**, and **AI SOC Consensus** to view real-time detection, correlation, and response actions.

---

## Testing

```powershell
# Run all backend unit tests
python backend/tests/run_all_tests.py

# Run live E2E verification test suites (requires backend on localhost:8000)
python backend/tests/e2e/test_v15_pqc_mesh.py
```
