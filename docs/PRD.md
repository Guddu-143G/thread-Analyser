# Threat Analyser — Product Requirements Document

## 1. Overview
Threat Analyser is a multi-tenant SaaS platform that detects security threats on personal
devices and within organizations by ingesting logs, matching them against threat
intelligence (IOCs), and evaluating them against configurable detection rules. It gives
security teams (and individuals) a single console to see risk in near real time and
triage alerts.

**Non-goals (MVP):** this is not an EDR/antivirus agent, not a network packet-capture
appliance, and does not perform automated remediation. It is a detection & alerting
layer over log data the user/org already has (auth logs, syslog, cloud audit logs,
EDR/AV exports, etc).

## 2. Problem Statement
Individuals and small/mid-size orgs generate huge volumes of log data (auth attempts,
process execution, network connections, cloud audit trails) but lack an affordable,
easy-to-deploy way to correlate that data against known threat indicators and behavioral
rules. Existing SIEM tooling is expensive, complex to operate, and overkill for smaller
teams or personal use.

## 3. Personas
- **Priya, SOC Analyst (org)** — triages alerts daily, needs fast filtering, clear
  severity, and audit trail.
- **Dev, Security-conscious individual** — wants to upload/forward logs from a personal
  laptop/router and get alerted on suspicious activity without running a SOC.
- **Alex, Org Admin** — manages users, devices, and org-wide threat intel/rules,
  cares about RBAC and multi-tenancy isolation.

## 4. Functional Requirements
1. **Auth & Multi-tenancy**: email/password signup, JWT sessions, org-scoped data
   isolation, roles (admin / analyst / viewer).
2. **Device management**: register devices/endpoints under an org or personal account;
   each device gets an API key for log ingestion.
3. **Log ingestion**: accept logs via (a) authenticated file upload, (b) device
   API-key push endpoint. Support JSON, syslog, CEF, and generic key-value formats.
   Ingestion is asynchronous (queued) so the API never blocks on parsing.
4. **Normalization**: parse raw log lines into a common event schema (timestamp, source
   IP, dest IP, user, process, event type, raw message) regardless of input format.
5. **IOC matching**: maintain a threat-intel table (malicious IPs, domains, file
   hashes, known-bad process names) — global (platform-curated) + org-specific
   (user-imported via CSV). Every ingested event is checked against active IOCs.
6. **Rule engine**: Sigma-inspired declarative rules supporting (a) direct field-match
   rules and (b) threshold/frequency rules (e.g. "5+ failed logins from one IP in
   5 minutes"). Ships with built-in rules (brute force, failed sudo spam, encoded
   PowerShell, known-malware process names, port-scan pattern).
7. **Alerts**: any IOC match or rule trigger creates an Alert with severity, evidence
   (matched event(s)), and status (open/ack/resolved/false-positive). Analysts can
   triage, comment, and change status; every change is audit-logged.
8. **Dashboard**: org-wide risk overview — alert counts by severity/time, top offending
   devices/IPs, ingestion volume, open vs resolved trend.
9. **Extensibility hook**: a pluggable `anomaly_detector` interface in the detection
   pipeline, stubbed in MVP, intended for a future statistical/ML-based scorer without
   changing the ingestion contract.

## 5. Non-Functional Requirements
- **Isolation**: strict org_id scoping on every query; no cross-tenant data leakage.
- **Async processing**: ingestion/detection run on a Celery worker queue (Redis
  broker) so bursts of log uploads don't degrade API latency.
- **Auditability**: all state-changing actions (login, alert status change, rule
  edit, IOC import) written to an append-only audit log.
- **Deployability**: single `docker-compose up` brings up the full stack (Postgres,
  Redis, API, worker, scheduler, frontend, reverse proxy) — this is the SaaS-style
  deployment target for MVP; a cloud (k8s/managed DB) deployment is a documented
  follow-on, not required for v1.
- **Secrets**: no secrets committed; all via `.env`, documented in `.env.example`.

## 6. High-Level Architecture
```
┌─────────────┐      ┌──────────────────┐      ┌───────────────┐
│  Frontend    │─────▶│   FastAPI (API)   │─────▶│  PostgreSQL   │
│ React/Vite   │      │  auth, CRUD,      │      │  (multi-      │
│ (nginx)      │      │  ingestion intake │      │   tenant)     │
└─────────────┘      └────────┬──────────┘      └───────────────┘
                               │ enqueue
                               ▼
                      ┌──────────────────┐
                      │   Redis (broker)  │
                      └────────┬──────────┘
                               ▼
                      ┌──────────────────────────┐
                      │  Celery worker            │
                      │  parse → normalize →      │
                      │  IOC match → rule engine  │───▶ Alerts table
                      │  → (future) anomaly score │
                      └──────────────────────────┘
                               ▲
                      ┌────────┴──────────┐
                      │ Celery beat        │  (periodic: threat-intel
                      │ (scheduler)        │   refresh, rule sweep)
                      └────────────────────┘
```
Reverse proxy (nginx) terminates one entrypoint, routes `/api/*` to FastAPI and
everything else to the built frontend — this is the shape a real SaaS deployment
(behind a load balancer/TLS terminator) would take.

## 7. Data Model (core tables)
- `organizations` (id, name, plan, created_at)
- `users` (id, org_id, email, hashed_password, role, created_at)
- `devices` (id, org_id, name, api_key_hash, platform, last_seen)
- `threat_indicators` (id, org_id nullable[global if null], type[ip/domain/hash/process], value, severity, source)
- `rules` (id, org_id nullable[global if null], name, description, definition JSON, severity, enabled)
- `log_events` (id, org_id, device_id, ts, event_type, src_ip, dest_ip, user, process, raw, normalized JSON)
- `alerts` (id, org_id, device_id, rule_id/ioc_id, severity, status, title, evidence JSON, created_at, resolved_at)
- `audit_log` (id, org_id, actor_user_id, action, target, meta JSON, created_at)

## 8. API Surface (summary)
- `POST /api/auth/register`, `POST /api/auth/login`, `GET /api/auth/me`
- `GET/POST /api/orgs/*` (admin)
- `GET/POST/DELETE /api/devices`, `POST /api/devices/{id}/rotate-key`
- `POST /api/ingest/upload` (analyst, multipart file), `POST /api/ingest/push` (device API key)
- `GET/POST/DELETE /api/ioc`, `POST /api/ioc/import-csv`
- `GET/POST/PUT/DELETE /api/rules`
- `GET /api/alerts`, `PATCH /api/alerts/{id}` (status/comment)
- `GET /api/dashboard/stats`

## 9. Milestones
1. **M1 — Core platform**: auth, multi-tenancy, device mgmt (this build)
2. **M2 — Detection pipeline**: ingestion, parser, IOC matcher, rule engine, alerts (this build)
3. **M3 — Console UI**: dashboard, alert triage, rule/IOC management (this build)
4. **M4 — Deployment**: Docker Compose stack, seed data, docs (this build)
5. **M5 (future)**: ML anomaly scoring, native lightweight agents for endpoints,
   SSO/SAML, managed cloud deployment (Terraform/k8s), billing/plans.

## 10. Risks
| Risk | Impact | Mitigation |
|---|---|---|
| Cross-tenant data leakage | Critical — trust-breaking for a security product | Org-scoping enforced at query layer + tests for isolation |
| High-volume ingestion overwhelming sync API | Availability | Async Celery pipeline; ingestion endpoint only validates+enqueues |
| Rule/IOC false positives eroding trust | Alert fatigue, churn | Severity tiers, false-positive status + feedback loop for tuning |
| Log format diversity breaking parser | Missed detections | Format auto-detection + fallback generic key-value/regex extraction |
| Secrets/API keys leaking | Compromise of ingestion channel | Hashed API keys at rest, rotation endpoint, never returned after creation |
| Single-node deployment (MVP) scaling ceiling | Limits SaaS growth | Documented path to managed Postgres/Redis + horizontal API/worker scaling |
