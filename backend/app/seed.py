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
            "ALTER TABLE devices ADD COLUMN IF NOT EXISTS last_location_desc VARCHAR(255);"
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
