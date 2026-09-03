import os
import sys

backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from app.detection.correlator import SecurityCorrelationEngine



def test_lateral_movement_correlation():
    engine = SecurityCorrelationEngine(tenant_id="test-org-alpha", sliding_window_minutes=60)
    hostname = "srv-production-01"

    # Step 1: Authentication failure alert (OCSF 3002)
    auth_alert = {
        "id": "alert-101",
        "title": "Failed SSH Password for root",
        "severity": "medium",
        "device_id": hostname,
        "evidence": {
            "src_ip": "192.168.1.50",
            "ocsf": {
                "class_uid": 3002,
                "category_uid": 3,
                "device": {"hostname": hostname}
            }
        }
    }
    cases_1 = engine.ingest_alert(auth_alert)
    assert len(cases_1) == 0  # Single event shouldn't trigger compound incident yet

    # Step 2: Suspicious process execution (OCSF 1007)
    proc_alert = {
        "id": "alert-102",
        "title": "Suspicious PowerShell Base64 Encoded Execution",
        "severity": "high",
        "device_id": hostname,
        "evidence": {
            "src_ip": "192.168.1.50",
            "ocsf": {
                "class_uid": 1007,
                "category_uid": 1,
                "device": {"hostname": hostname}
            }
        }
    }
    cases_2 = engine.ingest_alert(proc_alert)
    assert len(cases_2) >= 1
    compound_case = cases_2[0]
    assert compound_case["severity"] == "critical"
    assert "TA0008 - Lateral Movement" in compound_case["mitre_tactic"]
    assert "Lateral Movement & Compromise Sequence" in compound_case["title"]
    assert compound_case["evidence"]["correlated_asset"] == hostname
    assert "alert-101" in compound_case["evidence"]["child_alert_ids"]
    assert "alert-102" in compound_case["evidence"]["child_alert_ids"]


def test_c2_beaconing_correlation():
    engine = SecurityCorrelationEngine(tenant_id="test-org-alpha", sliding_window_minutes=60)
    hostname = "desktop-fin-04"

    # Step 1: Process activity (OCSF 1007)
    proc_alert = {
        "id": "alert-201",
        "title": "Suspicious Process Spawned",
        "severity": "medium",
        "device_id": hostname,
        "evidence": {
            "ocsf": {
                "class_uid": 1007,
                "device": {"hostname": hostname}
            }
        }
    }
    engine.ingest_alert(proc_alert)

    # Step 2: Outbound network activity (OCSF 4001)
    net_alert = {
        "id": "alert-202",
        "title": "Outbound High-Port TCP Egress",
        "severity": "high",
        "device_id": hostname,
        "evidence": {
            "ocsf": {
                "class_uid": 4001,
                "device": {"hostname": hostname}
            }
        }
    }
    cases = engine.ingest_alert(net_alert)
    assert len(cases) >= 1
    assert "TA0011 - Command and Control" in cases[0]["mitre_tactic"]
