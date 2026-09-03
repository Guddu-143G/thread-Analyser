import os
import sys
import json
import logging

# Add backend root directory to path
backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)


from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.db import Base
from app.models.models import Rule, LogEvent, Alert, TenantTechnologyInventory
from app.detection.pipeline import process_log_batch

logging.basicConfig(level=logging.INFO)

def main():
    print("=== Testing v8.0 Sovereign Upgrade Pipeline ===")
    
    # 1. Setup in-memory SQLite DB
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    db = Session()
    
    org_id = "org_test"
    device_id = "device_test"
    
    # Add a Sigma rule for BlueBorne (Class 6001)
    sigma_def = {
        "type": "sigma",
        "detection": {
            "selection": {
                "ocsf_class_uid": 6001
            },
            "condition": "selection"
        }
    }
    
    rule = Rule(
        org_id=org_id,
        name="Potential BlueBorne (L2CAP Payload Overflow)",
        definition=sigma_def,
        severity="critical"
    )
    db.add(rule)
    db.commit()

    # 2. Test Tech Stack Extraction (Task-08-A)
    fastapi_log = '{"ts": "2026-09-02T12:00:00Z", "class_uid": 1007, "process": {"name": "uvicorn", "cmd_line": "uvicorn app.main:app --host 0.0.0.0 --port 8000"}, "device": {"hostname": "edge-node-1"}}'
    
    print("\n[+] Ingesting FastAPI Process Boot Log...")
    res = process_log_batch(db, org_id, device_id, fastapi_log)
    print(f"Ingest Result: {res}")
    
    inv = db.query(TenantTechnologyInventory).filter_by(org_id=org_id).first()
    if inv:
        print(f"[SUCCESS] Tech Stack Detected: {inv.technology} on port {inv.detected_port} (Confidence: {inv.confidence})")
    else:
        print("[FAIL] Tech Stack Extractor failed to detect FastAPI.")

    # 3. Test Bluetooth Module Attack Prevention (Task-08-B/C)
    bluetooth_payload = {
      "metadata": {
        "version": "1.2.0-custom",
        "product": {
          "vendor": "ThreatAnalyser",
          "name": "Edge Agent Core",
          "version": "8.0.0"
        },
        "tenant_uid": org_id
      },
      "category_uid": 6,
      "class_uid": 6001,
      "severity_id": 5, 
      "time": 1788209718536,
      "rf_activity": {
        "interface": "hci0",
        "protocol": "L2CAP",
        "event_type": "CONNECTION_REQUEST",
        "peer_mac": "00:1A:7D:DA:71:11",
        "packet_length": 65535, 
        "payload_entropy": 7.91,
        "anomalous_fields": ["packet_length", "payload_entropy"]
      }
    }
    
    print("\n[+] Ingesting Bluetooth HCI Anomalous Packet (BlueBorne)...")
    res2 = process_log_batch(db, org_id, device_id, json.dumps(bluetooth_payload))
    print(f"Ingest Result: {res2}")
    
    alert = db.query(Alert).filter_by(rule_id=rule.id).first()
    if alert:
        print(f"[SUCCESS] Sigma Compiler caught BlueBorne exploit: '{alert.title}'")
    else:
        print("[FAIL] Sigma rule failed to trigger on Class 6001 event.")
        
    print("\n=== v8.0 Pipeline Test Complete ===")

if __name__ == "__main__":
    main()
