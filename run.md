# Threat Analyser - Operations & Running Guide

This guide provides instructions for starting, developing, testing, and simulating threats on the Threat Analyser multi-tenant SaaS security platform.

---

## 1. Quick Start with Docker Compose (Recommended)

Start all services (PostgreSQL, Redis, FastAPI Backend, Celery Ingestion Worker, Celery Beat, Frontend Nginx):

```bash
# Copy and configure environment variables
cp .env.example .env

# Build and start all containers in detached mode
docker compose up --build -d

# Check real-time logs
docker compose logs -f

# View logs for a specific service
docker compose logs -f backend
docker compose logs -f worker
docker compose logs -f frontend

# Stop and tear down all containers
docker compose down
```

Access the application:
- **SOC Console (Frontend)**: http://localhost
- **Interactive OpenAPI Documentation (Backend)**: http://localhost:8000/docs
- **Health Check Endpoint**: http://localhost:8000/api/health

---

## 2. Local Development (Without Docker)

### Prerequisites:
- Local PostgreSQL instance running on `localhost:5432`
- Local Redis instance running on `localhost:6379`
- Python 3.11+
- Node.js 18+

### Backend (FastAPI + SQLAlchemy)

```powershell
cd backend
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

### Celery Worker & Beat (Async Ingestion & Task Scheduling)

```powershell
cd backend
.venv\Scripts\activate
celery -A app.workers.celery_app worker --loglevel=info
celery -A app.workers.celery_app beat --loglevel=info
```

### Frontend (React + Vite + Tailwind CSS)

```powershell
cd frontend
npm install
npm run dev
```
Frontend development server will run on `http://localhost:5173`.

---

## 3. Threat Simulation & Attack Generators

Simulate enterprise multi-stage cyber attacks against the OCSF & Sigma detection pipeline:

```powershell
# Using PowerShell one-click launcher
.\scripts\sandbox-ingest.ps1

# Or running the threat generator directly with specific attack vectors:
python scripts/threat_generator.py --attack-type all
python scripts/threat_generator.py --attack-type ssh_brute_force
python scripts/threat_generator.py --attack-type credential_dump
python scripts/threat_generator.py --attack-type powershell_obfuscated
python scripts/threat_generator.py --attack-type sudo_escalation
python scripts/threat_generator.py --attack-type c2_traffic
```

---

## 4. Test Suites

### Unit Tests
Run the consolidated unit tests across all detection and security modules:

```powershell
python backend/tests/run_all_tests.py
```

Or run individual unit test suites:
```powershell
python backend/tests/unit/test_v20_modules.py
python backend/tests/unit/test_v19_modules.py
python backend/tests/unit/test_v18_modules.py
python backend/tests/unit/test_v17_modules.py
python backend/tests/unit/test_v16_modules.py
python backend/tests/unit/test_v2_modules.py
python -m unittest backend/tests/unit/test_v4_all.py
python -m unittest backend/tests/unit/test_v5_all.py
python -m unittest backend/tests/unit/test_v6_all.py
python -m unittest backend/tests/unit/test_v7_all.py
```

### End-to-End & Feature Tests (Requires Live Backend on port 8000)
```powershell
python backend/tests/e2e/test_v20_edge_mesh.py
python backend/tests/e2e/test_v19_fleet_control.py
python backend/tests/e2e/test_v18_live_response.py
python backend/tests/e2e/test_v17_neon_mesh.py
python backend/tests/e2e/test_v16_defense_mesh.py
python backend/tests/e2e/test_v15_pqc_mesh.py
python backend/tests/e2e/test_v14_sovereign.py
python backend/tests/e2e/test_v13_ai_soc.py
python backend/tests/e2e/test_v12_realtime_ws.py
python backend/tests/e2e/test_v11_neon_auth.py
python backend/tests/e2e/test_soc_features.py
python backend/tests/e2e/test_e2e_simulation.py
```

---

## 5. Endpoint Agent Deployment

The lightweight host agent is located in `agent/`:
```powershell
# Run the Python log forwarder with zero-loss SQLite WAL buffer
python agent/ta_agent.py --server http://localhost:8000 --api-key <YOUR_DEVICE_KEY> --watch /var/log/*.log
```
