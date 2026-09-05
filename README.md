# 🛡️ Threat Analyser

An enterprise-grade, multi-tenant Software-as-a-Service (SaaS) platform engineered to detect, analyze, and mitigate security threats across user devices and organizational networks. It enables teams to ingest security telemetry, match events against threat intelligence (IOCs), evaluate patterns against configurable detection rules, and triage active alerts from a single dark-themed console.

---

## 🏗️ Platform Stack & System Architecture

Threat Analyser is designed to handle high-throughput log ingestion asynchronously. The HTTP ingestion path is decoupled from the resource-heavy parsing and matching pipelines, ensuring that client applications or forwarders never block.

### Modern Technical Stack
* **Backend Framework**: `FastAPI` (Python 3.11) utilizing asynchronous concurrent endpoints.
* **Relational Storage**: `PostgreSQL` backed by `SQLAlchemy` ORM, featuring native multi-tenant data isolation.
* **Asynchronous Execution**: `Celery` workers coupled with a high-speed `Redis` message broker.
* **Security Operations Center Console**: `React` + `Vite` + `Tailwind CSS` ("SOC Console" dark theme).
* **Local Orchestration**: `Docker Compose` bundling Postgres, Redis, API Nodes, Celery Workers, Celery Beat, and the Nginx Frontend.

### High-Level Architectural Flow
The diagram below maps the dynamic flow of telemetry from edge client devices, through the FastAPI and Redis ingestion buffer, into the Celery parsing worker clusters, and up to the live SOC analyst dashboard. For the comprehensive, deep-dive system architecture specification spanning v1.0 through v30.0, refer to **[System Architecture Guide (architecture.md)](./architecture.md)**.

![Threat Analyser System Architecture](threat-analyser-architecture.png)

---

## ⚡ How Ingest & Detection Works

The threat detection pipeline processes telemetry through an asynchronous, 11-stage event processing fabric to guarantee that security incidents are normalized, evaluated, triaged, and mitigated within milliseconds of ingestion. For the full phase-by-phase technical walkthrough, mathematical formulas, and latency benchmarks, refer to **[Detection Pipeline Flow (detection-pipeline-flow.md)](./detection-pipeline-flow.md)**.

![Detection Pipeline Flow](detection-pipeline-flow.png)

1. **Ingest (Payload Receipt)**: Logs are submitted via authenticated file uploads (`POST /api/ingest/upload`) or via a lightweight device agent push (`POST /api/ingest/push` with the `X-API-Key` header). The API endpoint validates headers, enqueues the payload to Redis, and instantly returns an HTTP `202 Accepted` response.
2. **Parse & Normalize**: Asynchronous Celery tasks process raw logs (supporting JSON, Common Event Format [CEF], key-value structures, and classic free-text syslog). The engine normalizes properties into a high-fidelity **Open Cybersecurity Schema Framework (OCSF)** event envelope (capturing `src_ip`, `dst_ip`, `user`, `process`, and `event_type`).
3. **IOC Match**: Normalized fields are matched in real time against known Threat Intelligence Indicators (global resources and tenant-specific IOCs) to flag blacklisted IPs, malicious domains, file hashes, or unauthorized system processes.
4. **Rule Engine**: The engine evaluates active correlation and frequency rules. Threshold rules (e.g., *"5+ failed login attempts from a single IP address within 5 minutes"*) utilize localized historical database lookbacks to ensure that bursts split across multiple uploads are caught.
5. **Pluggable Anomaly Hook**: A modular interface hook defines a pluggable, self-training machine learning anomaly evaluator. This allows advanced ML scoring models (such as unsupervised Isolation Forests) to assess and score logs in parallel without altering the surrounding ingestion pipeline.
6. **Alert Dispatch**: Any matched threat intelligence indicator or triggered correlation rule compiles an alarm event with granular evidence. This is pushed instantly via WebSocket connections to render on the analyst dashboard.

---

## 🔒 Multi-Tenancy & Security Hardening

Security and strict isolation are at the core of Threat Analyser's multi-tenant architecture:

* **Symmetric Tenant Isolation**: Every query and database record is strictly scoped and isolated by a unique `org_id`. Pre-seeded out-of-the-box assets (built-in rules, global threat indicators) use `org_id = NULL`—allowing tenant viewers to read but preventing them from modifying or deleting shared global structures.
* **Cryptographic Credential Safeguards**: User passwords are encrypted with industry-standard `bcrypt`. Device credentials and agent keys are generated as random high-entropy tokens and stored as strong SHA-256 hashes (the plaintext secret is displayed exactly once upon creation).
* **Forensic Audit Ledgers**: Every state-changing operational action—including logins, role modifications, rule creations, IOC edits, and alert status transitions (Acknowledge, Resolve, Mark False Positive)—is persistently written to an append-only system audit log to meet SOC 2, ISO 27001, and GDPR compliance standards.
* **Production Preparedness Guide**: The local Docker Compose stack is optimized for seamless deployment. Before exposing the platform to production traffic, you must:
  * Replace the placeholder `SECRET_KEY` in environment variables.
  * Restrict CORS origin domains to trusted system URLs.
  * Establish TLS/mTLS termination at Nginx or a cloud load balancer.
  * Transition Postgres and Redis containers to managed, high-availability cloud services (e.g., AWS RDS, Neon, or ElastiCache) to secure database backups and automatic failover boundaries.

---

## 🛠️ Extending the Platform

Threat Analyser's modular design is built to grow alongside your infrastructure's security requirements:

* **Incorporate Machine Learning**: Implement your custom anomaly scoring model directly inside the modular `AnomalyDetector.score()` interface in `app/detection/anomaly.py`—the ingestion pipeline is pre-configured to evaluate and store its outputs.
* **Add Custom Log Parsers**: Extend the core parser class to support proprietary, vendor-specific network device formats or custom application logs by defining new regular expression sets.
* **轻量级 Native Agents**: Construct custom telemetry forwarders that stream local logs over the agent push endpoint (`/api/ingest/push`). A background agent script merely needs to make a POST request with newline-delimited text payloads and include its verified `X-API-Key` header.
* **Enterprise Cloud Deployment**: Run identical system container images in production (on platforms like AWS EKS, ECS, or Google Cloud Run) simply by pointing the environment variables `DATABASE_URL` and `REDIS_URL` to your managed cloud infrastructure.

---

## 🚀 Quick Start & Log Demo Playbook

Deploying the complete platform takes only a single terminal command. On initial boot, the system automatically builds the relational database, compiles multi-tenant tables, and seeds **5 built-in detection rules** (covering SSH brute-forcing, repeated failed sudo runs, encoded PowerShell execution, known credential-dumping utility signatures, and port-scan networks) along with **5 sample threat indicators**.

### 1. Launch the Stack
Make sure you have Docker and Docker Compose installed, then execute:
```bash
docker-compose up --build
```

Once the containers are running, navigate to:
* **SaaS Dashboard App**: `http://localhost` (Register your tenant organization, configure admin credentials, and access the SOC console).
* **Interactive API Reference**: `http://localhost:8000/docs` (Explore FastAPI's autogenerated Swagger UI and test endpoints directly).

### 2. Verify Ingestion & Alerts in Under a Minute
1. Navigate to `http://localhost` and register an administrative user to automatically spin up your isolated organization workspace.
2. In the sidebar menu, click on **Log Upload**.
3. Click the **"Run sample log demo"** button. This will instantly send a bundled, multi-format log sample simulating a multi-stage intrusion attempt (including SSH brute-forcing, credential dumping, and an encoded PowerShell callback).
4. Within seconds, check the **Alerts** or **Dashboard** tabs. You will observe active alerts displaying high-fidelity forensic evidence and mapped threat rules compiled asynchronously by the Celery background workers.
