import urllib.request
import urllib.error
import urllib.parse
import json
import sys
import uuid
import time

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

BASE_URL = "http://localhost:8000"

def make_req(endpoint, method="GET", body=None, params=None, token=None):
    url = f"{BASE_URL}{endpoint}"
    if params:
        url += "?" + urllib.parse.urlencode(params)
    data = json.dumps(body).encode("utf-8") if body else None
    headers = {"Content-Type": "application/json"} if body else {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req) as res:
            res_body = res.read().decode("utf-8")
            return res.status, json.loads(res_body) if res_body else {}
    except urllib.error.HTTPError as e:
        err_body = e.read().decode("utf-8")
        try:
            parsed = json.loads(err_body)
            return e.code, parsed
        except Exception:
            return e.code, {"error": err_body}
    except Exception as e:
        return 500, {"error": str(e)}

def run_test():
    print("--- [V17.0 Sovereign Neon Serverless & Real-Time Security Mesh Verification Suite] ---\n")

    # 1. Login
    print("1. Authenticating test analyst session...")
    login_status, login_data = make_req("/api/auth/login", method="POST", body={
        "email": "analyst@acme.corp",
        "password": "SecurePassword123!"
    })
    assert login_status == 200, f"Login failed: {login_data}"
    token = login_data["access_token"]
    print(f"   [+] Authentication successful. Token obtained: {token[:20]}...")

    # 2. Neon Serverless & RLS Status
    print("\n2. Testing Neon Serverless & Row-Level Security (RLS) Status (OCSF Mesh Core)...")
    neon_status, neon_data = make_req("/api/v17/neon/branch-status", token=token)
    assert neon_status == 200, f"Neon status failed: {neon_data}"
    print(f"   [+] Database Core: {neon_data['database_core']}")
    print(f"   [+] Active Serverless Branch: {neon_data['branch']}")
    print(f"   [+] RLS Enabled: {neon_data['rls_enabled']}")
    print(f"   [+] Enforced RLS Policies: {len(neon_data['rls_policies'])} policies active")
    print(f"   [+] System Integrity: {neon_data['system_integrity']}")
    assert neon_data["rls_enabled"] is True

    # 3. Real-Time Device Telemetry & Impossible Travel Evaluator
    print("\n3. Testing Real-Time Device Telemetry & Impossible Travel (OCSF 5001)...")
    dev_uid = f"v17-node-{uuid.uuid4().hex[:8]}"
    
    # Step A: Ingest nominal telemetry in London
    tel1_status, tel1_data = make_req("/api/v17/devices/telemetry", method="POST", body={
        "device_id": dev_uid,
        "hostname": f"{dev_uid}.corp.internal",
        "public_ip": "185.190.140.2",
        "latitude": 51.5074,
        "longitude": -0.1278,
        "location_desc": "London, United Kingdom",
        "cpu_usage": 14.5,
        "memory_usage": 32.0,
        "disk_usage": 45.0,
        "battery": 98.0,
        "processes": 135,
        "ports": 16
    }, token=token)
    assert tel1_status == 200, f"Telemetry 1 failed: {tel1_data}"
    print(f"   [+] Initial Heartbeat Recorded: Device={tel1_data['device_id']} | Status={tel1_data['status']}")
    print(f"   [+] Location: {tel1_data['location']} | Battery: {tel1_data['battery_pct']}% | Ports: {tel1_data['listening_port_count']}")
    assert tel1_data["impossible_travel"] is False

    # Step B: Teleport check to Tokyo (>9500 km instantaneously)
    tel2_status, tel2_data = make_req("/api/v17/devices/telemetry", method="POST", body={
        "device_id": dev_uid,
        "hostname": f"{dev_uid}.corp.internal",
        "public_ip": "133.242.18.1",
        "latitude": 35.6762,
        "longitude": 139.6503,
        "location_desc": "Tokyo, Japan",
        "cpu_usage": 85.0,
        "memory_usage": 70.0,
        "disk_usage": 46.0,
        "battery": 82.0,
        "processes": 190,
        "ports": 24
    }, token=token)
    assert tel2_status == 200, f"Telemetry 2 failed: {tel2_data}"
    print(f"   [+] Anomaly Check: Impossible Travel Detected = {tel2_data['impossible_travel']}")
    print(f"   [+] Distance: {tel2_data['distance_km']} km | Speed: {tel2_data['calculated_speed_kmh']} km/h")
    print(f"   [+] Updated Device Status: {tel2_data['status']}")
    assert tel2_data["impossible_travel"] is True
    assert tel2_data["status"] == "compromised"

    # Step C: Query enrolled devices & heartbeat series
    devs_status, devs_list = make_req("/api/v17/devices", token=token)
    assert devs_status == 200
    assert any(d["id"] == dev_uid for d in devs_list)
    print(f"   [+] Total Enrolled Fleet Devices in Neon: {len(devs_list)}")

    hb_status, hb_list = make_req(f"/api/v17/devices/{dev_uid}/heartbeats", token=token)
    assert hb_status == 200
    assert len(hb_list) >= 2
    print(f"   [+] Retrieved Time-Series Heartbeats for {dev_uid}: {len(hb_list)} events")

    # 4. Serverless Email Security & Automated Quarantine (OCSF 4009)
    print("\n4. Testing Serverless Email Security & Automated Quarantine (OCSF 4009)...")
    email_status, email_data = make_req("/api/v17/email/audit", method="POST", body={
        "sender": "executive-security@microsoft-auth-verify.top",
        "recipient": "cfo@acme.corp",
        "subject": "URGENT ACTION: Immediate wire transfer and verify password",
        "body": "Your corporate mailbox is scheduled for termination. Verify password and update bank details: https://verify-office365-security.com/login.php",
        "sender_ip": "198.51.100.99",
        "spf_override": "FAIL"
    }, token=token)
    assert email_status == 200, f"Email audit failed: {email_data}"
    print(f"   [+] Email Scan ID: {email_data['scan_id']}")
    print(f"   [+] SPF Status: {email_data['spf_status']} | DKIM: {email_data['dkim_status']}")
    print(f"   [+] Spam Linguistic Score: {email_data['spam_text_score']} | Risk Score: {email_data['risk_score']}")
    print(f"   [+] Phishing Detected: {email_data['is_phishing']}")
    print(f"   [+] Automated Action Taken: {email_data['action_taken']}")
    print(f"   [+] Harvested URLs: {email_data['urls_harvested']}")
    assert email_data["is_phishing"] is True
    assert email_data["action_taken"] == "quarantined"

    # 5. Non-Destructive URL Sandbox & Redirect Chain Tracing (OCSF 4002)
    print("\n5. Testing Safe Multi-Tier URL Sandboxing & Dynamic Redirect Tracing (OCSF 4002)...")
    url_target = "https://verify-office365-security.com/login.php?user=cfo@acme.corp"
    url_status, url_data = make_req("/api/v17/url/audit", method="POST", body={
        "url": url_target
    }, token=token)
    assert url_status == 200, f"URL audit failed: {url_data}"
    print(f"   [+] URL Scan ID: {url_data['scan_id']}")
    print(f"   [+] URL Hash: {url_data['url_hash'][:32]}...")
    print(f"   [+] Domain: {url_data['domain']} | Reputation Score: {url_data['reputation_score']}")
    print(f"   [+] Malicious Status: {url_data['malicious']}")
    print(f"   [+] Headless Sandbox Triggered: {url_data['headless_sandbox_triggered']}")
    print(f"   [+] Dynamic Redirect Chain Hops: {len(url_data['redirect_chain'])}")
    print(f"   [+] Safe Snapshot Render Path: {url_data['screenshot']}")
    assert url_data["malicious"] is True
    assert len(url_data["redirect_chain"]) >= 1

    # 6. Explainable ML Anomaly Tracking & Triage Workflow (OCSF 2004)
    print("\n6. Testing Explainable ML Anomaly Tracking & Analyst Triage Workflow (OCSF 2004)...")
    anom_status, anom_data = make_req("/api/v17/anomalies/track", method="POST", body={
        "event_class": 2004,
        "raw_payload": "powershell.exe -NoP -NonI -W Hidden -Enc SUVYIChOZXctT2JqZWN0IE5ldC5XZWJDbGllbnQp",
        "score": 0.94,
        "metrics": {
            "entropy": 7.95,
            "rare_process_ratio": 0.92,
            "obfuscation_flag": True,
            "token_count": 84
        },
        "reasons": [
            "High Base64 Shannon Entropy (> 7.5)",
            "PowerShell hidden execution arguments (-NoP -W Hidden)",
            "Direct in-memory code execution invocation"
        ],
        "model_version": "IsolationForest-v2.1"
    }, token=token)
    assert anom_status == 200, f"Anomaly track failed: {anom_data}"
    print(f"   [+] Anomaly Alert ID: {anom_data['alert_id']}")
    print(f"   [+] ML Model Version: {anom_data['model_version']} (Score: {anom_data['score']})")
    print(f"   [+] Initial Triage Status: {anom_data['triage_status']}")
    print(f"   [+] Explainable Attribution Reasons: {len(anom_data['reasons'])} factors logged")
    assert anom_data["is_anomaly"] is True

    # Update triage status
    triage_status, triage_data = make_req(f"/api/v17/anomalies/{anom_data['alert_id']}/triage", method="PATCH", body={
        "triage_status": "investigating"
    }, token=token)
    assert triage_status == 200
    print(f"   [+] Updated Triage Status: {triage_data['triage_status']}")
    assert triage_data["triage_status"] == "investigating"

    print("\n[OK] ALL VERSION 17.0 SOVEREIGN NEON MESH DEFENSE TESTS PASSED PERFECTLY!")

if __name__ == "__main__":
    run_test()
