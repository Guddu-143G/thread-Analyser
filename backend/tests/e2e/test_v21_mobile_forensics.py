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
    print("--- [V21.0 Physical Mobile Security & Forensics Mesh Verification Suite] ---\n")

    # 1. Login
    print("1. Authenticating SOC forensic analyst...")
    login_status, login_data = make_req("/api/auth/login", method="POST", body={
        "email": "analyst@acme.corp",
        "password": "SecurePassword123!"
    })
    assert login_status == 200, f"Login failed: {login_data}"
    token = login_data["access_token"]
    print(f"   [+] Authentication successful. Token: {token[:20]}...")

    # 2. Check Forensic Engine Status
    print("\n2. Checking V21 Mobile Forensics Engine Status...")
    status_code, status_data = make_req("/api/v21/forensics/status", token=token)
    assert status_code == 200, f"Status check failed: {status_data}"
    print(f"   [+] Status: {status_data['status']}")
    print(f"   [+] Version: {status_data['engine_version']}")
    print(f"   [+] OCSF Mapping: {status_data['ocsf_class_mapping']}")
    print(f"   [+] HID Driver: {status_data['hid_emulation_driver']}")
    print(f"   [+] Supported Vectors: {len(status_data['supported_vectors'])} vectors")
    assert "OCSF 3002" in status_data["ocsf_class_mapping"]

    # 3. Probe Physical USB Device Descriptors
    print("\n3. Probing connected physical USB endpoint...")
    probe_code, probe_data = make_req("/api/v21/forensics/device/discover", method="POST", body={
        "usb_port_path": "/dev/bus/usb/001/004",
        "probe_protocol": "AUTO"
    }, token=token)
    assert probe_code == 200, f"Device probe failed: {probe_data}"
    print(f"   [+] Detected Device: {probe_data['manufacturer']} {probe_data['model']}")
    print(f"   [+] Serial: {probe_data['serial_number']}")
    print(f"   [+] UDID: {probe_data['udid']}")
    print(f"   [+] OS: {probe_data['os_name']} {probe_data['os_version']}")
    print(f"   [+] Protocol: {probe_data['connection_type']}")

    # 4. Initialize Forensic Session (Pattern 3x3 Grid)
    print("\n4. Initializing Physical Mobile Forensic Session (Android 3x3 Pattern)...")
    sess_code, sess_data = make_req("/api/v21/forensics/sessions/start", method="POST", body={
        "device_name": probe_data["manufacturer"],
        "device_model": probe_data["model"],
        "serial_number": probe_data["serial_number"],
        "udid": probe_data["udid"],
        "os_name": probe_data["os_name"],
        "os_version": probe_data["os_version"],
        "connection_type": "USB_OTG_HID",
        "passcode_type": "PATTERN",
        "target_mock_passcode": "01258"
    }, token=token)
    assert sess_code == 200, f"Session initialization failed: {sess_data}"
    session_id = sess_data["session_id"]
    print(f"   [+] Session Created: {session_id}")
    print(f"   [+] Initial Shannon Entropy: {sess_data['max_estimated_entropy']} bits")
    print(f"   [+] Status: {sess_data['status']}")

    # 5. Execute Single Guess Attempt
    print("\n5. Executing single step passcode/pattern guess...")
    att_code, att_data = make_req(f"/api/v21/forensics/sessions/{session_id}/attempt", method="POST", body={
        "candidate_passcode": "01478",
        "pattern_path": [0, 1, 4, 7, 8],
        "passcode_type": "PATTERN"
    }, token=token)
    assert att_code == 200, f"Single attempt failed: {att_data}"
    print(f"   [+] Attempt #{att_data['attempt_index']} Response: {att_data['response_code']}")
    print(f"   [+] SHA-256 Hash: {att_data['candidate_hash']}")
    print(f"   [+] Latency: {att_data['latency_ms']}ms")
    print(f"   [+] Entropy: {att_data['entropy']} bits")

    # 6. Run Batch Automated Audit
    print("\n6. Running Automated Batch Audit Loop...")
    batch_code, batch_data = make_req(f"/api/v21/forensics/sessions/{session_id}/run-audit", method="POST", body={
        "max_attempts": 10,
        "target_secret_override": "01258"
    }, token=token)
    assert batch_code == 200, f"Batch audit failed: {batch_data}"
    print(f"   [+] Total Attempts Processed: {batch_data['total_attempts_run']}")
    print(f"   [+] Device Unlocked: {batch_data['is_unlocked']}")
    print(f"   [+] Final Status: {batch_data['status']}")

    # 7. Fetch Session Attempts History
    print("\n7. Inspecting Session Audit Logs & SHA-256 Hashes...")
    log_code, log_data = make_req(f"/api/v21/forensics/sessions/{session_id}/attempts", token=token)
    assert log_code == 200, f"Attempts log fetch failed: {log_data}"
    print(f"   [+] Retrieved {len(log_data)} historical attempt records.")
    for idx, att in enumerate(log_data[:3]):
        print(f"       #{att['attempt_index']}: Code={att['response_code']}, Hash={att['candidate_hash'][:24]}..., Latency={att['latency_ms']}ms")

    # 8. Terminate Session
    print("\n8. Terminating Forensic Auditing Session...")
    term_code, term_data = make_req(f"/api/v21/forensics/sessions/{session_id}/stop", method="POST", token=token)
    assert term_code == 200, f"Session termination failed: {term_data}"
    print(f"   [+] Session Terminated: {term_data.get('message')}")

    print("\n=========================================================================")
    print(">>> ALL V21.0 MOBILE FORENSICS & USB-HID AUDITING E2E TESTS PASSED <<<")
    print("=========================================================================\n")

if __name__ == "__main__":
    run_test()
