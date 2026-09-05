"""
Seeds global (org_id=None) built-in detection rules and a small set of sample
threat indicators. Safe to run multiple times (checks for existing names/values).
"""
from app.core.db import SessionLocal, Base, engine
from app.models.models import Rule, ThreatIndicator

BUILT_IN_RULES = [
    {
        "name": "SSH Brute Force",
        "description": "5+ failed auth attempts from a single source IP within 5 minutes.",
        "severity": "high",
        "definition": {
            "type": "threshold",
            "conditions": [{"field": "event_type", "op": "eq", "value": "auth_failure"}],
            "group_by": "src_ip",
            "count": 5,
            "window_seconds": 300,
        },
    },
    {
        "name": "Repeated Failed Sudo",
        "description": "3+ sudo/privilege-escalation attempts from the same user in 10 minutes.",
        "severity": "medium",
        "definition": {
            "type": "threshold",
            "conditions": [{"field": "event_type", "op": "eq", "value": "privilege_use"}],
            "group_by": "user",
            "count": 3,
            "window_seconds": 600,
        },
    },
    {
        "name": "Encoded PowerShell Execution",
        "description": "Detects base64-encoded PowerShell command execution, a common obfuscation technique.",
        "severity": "high",
        "definition": {
            "type": "match",
            "logic": "or",
            "conditions": [
                {"field": "raw", "op": "regex", "value": r"powershell.*-enc(odedcommand)?\s"},
                {"field": "raw", "op": "regex", "value": r"powershell.*-e\s+[A-Za-z0-9+/=]{20,}"},
            ],
        },
    },
    {
        "name": "Known Credential-Dumping Tool",
        "description": "Process name matches a known credential-dumping tool (e.g. mimikatz).",
        "severity": "critical",
        "definition": {
            "type": "match",
            "conditions": [{"field": "process", "op": "contains", "value": "mimikatz"}],
        },
    },
    {
        "name": "Port Scan Pattern",
        "description": "10+ connection-refused/reset events from a single source IP within 2 minutes.",
        "severity": "medium",
        "definition": {
            "type": "threshold",
            "conditions": [{"field": "event_type", "op": "eq", "value": "network_error"}],
            "group_by": "src_ip",
            "count": 10,
            "window_seconds": 120,
        },
    },
    {
        "name": "Sigma: Suspicious C2 High-Port Network Activity",
        "description": "Detects outbound connection attempts targeting suspicious non-standard ports (4444, 9001, 1337, 31337).",
        "severity": "high",
        "definition": {
            "type": "sigma",
            "title": "Suspicious C2 High-Port Network Activity",
            "level": "high",
            "logsource": {"category": "network_activity"},
            "detection": {
                "selection": {
                    "destinationport": [4444, 9001, 1337, 31337, 8888]
                },
                "condition": "selection"
            }
        },
    },
]

SAMPLE_IOCS = [
    {"type": "ip", "value": "185.220.101.1", "severity": "high", "description": "Known Tor exit node used in attacks (sample)."},
    {"type": "ip", "value": "45.155.205.233", "severity": "critical", "description": "Known C2 infrastructure (sample)."},
    {"type": "domain", "value": "malicious-update.example", "severity": "high", "description": "Known phishing/malware domain (sample)."},
    {"type": "process", "value": "mimikatz.exe", "severity": "critical", "description": "Credential dumping tool."},
    {"type": "hash", "value": "44d88612fea8a8f36de82e1278abb02f", "severity": "high", "description": "EICAR test file hash (sample)."},
]


from sqlalchemy import text

def run_seed():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        # V17 Schema migrations for existing tables
        alter_statements = [
            "ALTER TABLE devices ADD COLUMN IF NOT EXISTS hostname VARCHAR(255);",
            "ALTER TABLE devices ADD COLUMN IF NOT EXISTS agent_version VARCHAR(50) DEFAULT '17.0.0';",
            "ALTER TABLE devices ADD COLUMN IF NOT EXISTS os_name VARCHAR(100) DEFAULT 'Linux';",
            "ALTER TABLE devices ADD COLUMN IF NOT EXISTS os_version VARCHAR(100) DEFAULT '6.5.0';",
            "ALTER TABLE devices ADD COLUMN IF NOT EXISTS status VARCHAR(50) DEFAULT 'active';",
            "ALTER TABLE devices ADD COLUMN IF NOT EXISTS public_ip VARCHAR(45) DEFAULT '127.0.0.1';",
            "ALTER TABLE devices ADD COLUMN IF NOT EXISTS last_latitude REAL;",
            "ALTER TABLE devices ADD COLUMN IF NOT EXISTS last_longitude REAL;",
            "ALTER TABLE devices ADD COLUMN IF NOT EXISTS last_location_desc VARCHAR(255);",
            "CREATE TABLE IF NOT EXISTS mobile_forensic_sessions (session_id VARCHAR PRIMARY KEY, org_id VARCHAR NOT NULL, analyst_id VARCHAR NOT NULL, device_name VARCHAR(100) NOT NULL, device_model VARCHAR(50) NOT NULL, serial_number VARCHAR(100) NOT NULL, udid VARCHAR(100) NOT NULL, os_name VARCHAR(50) NOT NULL, os_version VARCHAR(30) NOT NULL, connection_type VARCHAR(20) DEFAULT 'USB', passcode_type VARCHAR(20) DEFAULT 'PIN_4', max_estimated_entropy REAL DEFAULT 0.0, created_at TIMESTAMP, completed_at TIMESTAMP, status VARCHAR(30) DEFAULT 'RUNNING');",
            "CREATE TABLE IF NOT EXISTS passcode_guess_attempts (attempt_id SERIAL PRIMARY KEY, session_id VARCHAR NOT NULL, org_id VARCHAR NOT NULL, attempt_index INT NOT NULL, passcode_attempt_hash VARCHAR(64) NOT NULL, pattern_path JSON, is_successful BOOLEAN DEFAULT FALSE, response_latency_ms INT DEFAULT 50, response_code VARCHAR(30) DEFAULT 'REJECTED', timestamp TIMESTAMP);",
            "CREATE TABLE IF NOT EXISTS devices_audit_ledger (ledger_id VARCHAR PRIMARY KEY, device_id VARCHAR NOT NULL, org_id VARCHAR NOT NULL, hostname VARCHAR(255) NOT NULL, ip_address VARCHAR(45) NOT NULL, system_status VARCHAR(50) NOT NULL DEFAULT 'active', operation_type VARCHAR(10) NOT NULL DEFAULT 'INSERT', transaction_timestamp TIMESTAMP, parent_hash VARCHAR(64), record_hash VARCHAR(64) NOT NULL);",
            "CREATE TABLE IF NOT EXISTS audit_ledger (sequence_id SERIAL PRIMARY KEY, org_id VARCHAR NOT NULL, device_id VARCHAR, event_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP, action VARCHAR(100) NOT NULL, actor_email VARCHAR(255) NOT NULL, ip_address VARCHAR(45) NOT NULL, mac_address VARCHAR(17) NOT NULL, payload_hash VARCHAR(64) NOT NULL, previous_record_hash VARCHAR(64), current_ledger_hash VARCHAR(64) UNIQUE NOT NULL);",
            "CREATE TABLE IF NOT EXISTS mitre_technique_mappings (id VARCHAR PRIMARY KEY, technique_id VARCHAR(30) NOT NULL, technique_name VARCHAR(255) NOT NULL, tactic_id VARCHAR(30) NOT NULL, tactic_name VARCHAR(100) NOT NULL, ocsf_class_id INT NOT NULL DEFAULT 4001, severity_weight REAL NOT NULL DEFAULT 70.0, detection_rule JSON, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);",
            "CREATE TABLE IF NOT EXISTS ingestion_metrics (id VARCHAR PRIMARY KEY, org_id VARCHAR NOT NULL, window_start TIMESTAMP DEFAULT CURRENT_TIMESTAMP, window_end TIMESTAMP DEFAULT CURRENT_TIMESTAMP, events_ingested INT DEFAULT 0, events_dropped INT DEFAULT 0, eps_rate REAL DEFAULT 0.0, avg_latency_ms REAL DEFAULT 0.0, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);",
            "CREATE TABLE IF NOT EXISTS mitre_alerts (alert_id VARCHAR PRIMARY KEY, org_id VARCHAR NOT NULL, device_id VARCHAR, source_ip VARCHAR(45), destination_ip VARCHAR(45), technique_id VARCHAR(30) NOT NULL, tactic_id VARCHAR(30) NOT NULL, anomaly_score REAL DEFAULT 0.0, mitre_weight REAL DEFAULT 0.0, asset_criticality REAL DEFAULT 0.0, intel_confidence REAL DEFAULT 0.0, priority_score REAL DEFAULT 0.0, priority_level VARCHAR(20) DEFAULT 'LOW', payload_summary TEXT, raw_event_data JSON, parent_alert_hash VARCHAR(64), alert_hash VARCHAR(64) NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);",
            "CREATE TABLE IF NOT EXISTS ai_threat_summaries (summary_id VARCHAR PRIMARY KEY, alert_id VARCHAR NOT NULL, org_id VARCHAR NOT NULL, sanitized_input TEXT NOT NULL, model_used VARCHAR(50) DEFAULT 'gemini-1.5-flash-shielded', executive_summary TEXT NOT NULL, threat_actor_attribution VARCHAR(100), actionable_remediation TEXT NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);",
            "CREATE TABLE IF NOT EXISTS provenance_nodes (id VARCHAR PRIMARY KEY, org_id VARCHAR NOT NULL, device_id VARCHAR NOT NULL, node_type VARCHAR(50) NOT NULL, entity_key VARCHAR(255) NOT NULL, name VARCHAR(255) DEFAULT '', node_metadata JSON DEFAULT '{}', created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);",
            "CREATE TABLE IF NOT EXISTS provenance_edges (id VARCHAR PRIMARY KEY, org_id VARCHAR NOT NULL, source_node_id VARCHAR NOT NULL, target_node_id VARCHAR NOT NULL, relation_type VARCHAR(50) NOT NULL, edge_weight REAL DEFAULT 1.0, edge_hash_sha256 VARCHAR(64), metadata_json JSON DEFAULT '{}', timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP);",
            "CREATE TABLE IF NOT EXISTS soar_playbooks (id VARCHAR PRIMARY KEY, org_id VARCHAR NOT NULL, name VARCHAR(255) NOT NULL, is_active BOOLEAN DEFAULT TRUE, playbook_yaml TEXT NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);",
            "CREATE TABLE IF NOT EXISTS soar_execution_logs (id VARCHAR PRIMARY KEY, org_id VARCHAR NOT NULL, playbook_id VARCHAR NOT NULL, device_id VARCHAR NOT NULL, status VARCHAR(50) DEFAULT 'IN_PROGRESS', execution_dag_trace JSON DEFAULT '{}', started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, completed_at TIMESTAMP);",
            "CREATE TABLE IF NOT EXISTS tpm_ledger_signatures (id VARCHAR PRIMARY KEY, org_id VARCHAR NOT NULL, block_start_id VARCHAR NOT NULL, block_end_id VARCHAR NOT NULL, merkle_root_hash VARCHAR(64) NOT NULL, pcr_composite_digest VARCHAR(64), tpm_hardware_signature VARCHAR(512) NOT NULL, attested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);"
        ]
        for stmt in alter_statements:
            try:
                db.execute(text(stmt))
            except Exception:
                pass
        db.commit()

        existing_rule_names = {r.name for r in db.query(Rule).filter(Rule.org_id.is_(None)).all()}
        for r in BUILT_IN_RULES:
            if r["name"] not in existing_rule_names:
                db.add(Rule(org_id=None, **r))

        existing_ioc_values = {i.value for i in db.query(ThreatIndicator).filter(ThreatIndicator.org_id.is_(None)).all()}
        for ioc in SAMPLE_IOCS:
            if ioc["value"] not in existing_ioc_values:
                db.add(ThreatIndicator(org_id=None, source="platform_curated", **ioc))

        db.commit()
        print("Seed complete.")
    finally:
        db.close()


if __name__ == "__main__":
    run_seed()
