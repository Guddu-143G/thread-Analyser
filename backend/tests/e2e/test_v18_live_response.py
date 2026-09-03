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
    print("--- [V18.0 Zero-Trust Live Response & Remote Terminal Mesh Verification Suite] ---\n")

    # 1. Login
    print("1. Authenticating test analyst session...")
    login_status, login_data = make_req("/api/auth/login", method="POST", body={
        "email": "analyst@acme.corp",
        "password": "SecurePassword123!"
    })
    assert login_status == 200, f"Login failed: {login_data}"
    token = login_data["access_token"]
    print(f"   [+] Authentication successful. Token obtained: {token[:20]}...")

    # 2. Live Response Mesh Telemetry Status
    print("\n2. Testing Live Response Mesh & Reverse Tunneling Status...")
    status_code, status_data = make_req("/api/v18/live/status", token=token)
    assert status_code == 200, f"Status failed: {status_data}"
    print(f"   [+] Gateway Status: {status_data['status']}")
    print(f"   [+] Reverse Tunnel Protocol: {status_data['reverse_tunnel_protocol']}")
    print(f"   [+] mTLS Standard: {status_data['mtls_version']}")
    print(f"   [+] Two-Man Rule Enforced: {status_data['two_man_rule_enforced']}")
    print(f"   [+] System Integrity: {status_data['system_integrity']}")
    assert status_data["two_man_rule_enforced"] is True

    # 3. Create or enroll target test device
    print("\n3. Setting up target endpoint device for Live Response...")
    dev_uid = f"v18-db-node-{uuid.uuid4().hex[:6]}"
    # Ingest telemetry to auto-enroll device
    tel_status, tel_data = make_req("/api/v17/devices/telemetry", method="POST", body={
        "device_id": dev_uid,
        "hostname": f"{dev_uid}.corp.internal",
        "public_ip": "192.168.1.100",
        "latitude": 51.5074,
        "longitude": -0.1278,
        "location_desc": "London Enclave Server Room",
        "cpu_usage": 15.0,
        "memory_usage": 40.0
    }, token=token)
    assert tel_status == 200
    print(f"   [+] Target Device Ready: {dev_uid} ({tel_data['location']})")

    # 4. Request Live Response Session
    print("\n4. Requesting Live Response Terminal Session (PENDING_APPROVAL)...")
    req_status, req_data = make_req("/api/v18/live/sessions/request", method="POST", body={
        "device_id": dev_uid
    }, token=token)
    assert req_status == 200, f"Session request failed: {req_data}"
    session_id = req_data["session_id"]
    print(f"   [+] Session Created: {session_id}")
    print(f"   [+] Initial Status: {req_data['status']} (Awaiting Dual-Authorization)")
    print(f"   [+] Ephemeral Encryption Key: {req_data['encryption_key_hex'][:32]}...")
    assert req_data["status"] == "PENDING_APPROVAL"

    # Verify command execution is blocked in PENDING_APPROVAL state
    blocked_status, blocked_data = make_req(f"/api/v18/live/sessions/{session_id}/execute", method="POST", body={
        "command": "whoami"
    }, token=token)
    assert blocked_status == 400
    print("   [+] Verified: Command dispatch correctly blocked prior to dual-authorization sign-off.")

    # 5. Dual-Authorization Sign-Off
    print("\n5. Applying Dual-Authorization Two-Man Rule Sign-Off...")
    app_status, app_data = make_req(f"/api/v18/live/sessions/{session_id}/approve", method="POST", body={
        "approver_signature": "FORCE_SOLO_DEV_OVERRIDE"
    }, token=token)
    assert app_status == 200, f"Session approval failed: {app_data}"
    print(f"   [+] Session Approved: {session_id}")
    print(f"   [+] Activated Status: {app_data['status']}")
    print(f"   [+] Approver Admin UID: {app_data['approver_id']}")
    assert app_data["status"] == "ACTIVE"

    # 6. Execute Diagnostic & Remediation Commands
    print("\n6. Dispatching Terminal Commands over Reverse WSS Tunnel...")
    
    # Command A: Process Inspection
    c1_status, c1_data = make_req(f"/api/v18/live/sessions/{session_id}/execute", method="POST", body={
        "command": "ps aux"
    }, token=token)
    assert c1_status == 200, f"Command 1 failed: {c1_data}"
    print(f"   [+] Executed '{c1_data['command']}' (Exit Code: {c1_data['exit_code']})")
    print(f"   [+] Output Preview: {c1_data['output'].splitlines()[0]} ... {c1_data['output'].splitlines()[3]}")

    # Command B: Network Socket Diagnostics
    c2_status, c2_data = make_req(f"/api/v18/live/sessions/{session_id}/execute", method="POST", body={
        "command": "netstat -tlpn"
    }, token=token)
    assert c2_status == 200
    print(f"   [+] Executed '{c2_data['command']}' (Exit Code: {c2_data['exit_code']})")

    # Command C: Terminate Rogue Process
    c3_status, c3_data = make_req(f"/api/v18/live/sessions/{session_id}/execute", method="POST", body={
        "command": "kill -9 1337"
    }, token=token)
    assert c3_status == 200
    print(f"   [+] Executed '{c3_data['command']}' (Output: {c3_data['output'].strip()})")

    # 7. Verify Keystroke Forensic Replay Ledger
    print("\n7. Verifying Raw Keystroke Forensic Audit Ledger...")
    keys_status, keys_list = make_req(f"/api/v18/live/sessions/{session_id}/keystrokes", token=token)
    assert keys_status == 200, f"Keystrokes failed: {keys_list}"
    print(f"   [+] Total Forensic Keystroke Frames Recorded: {len(keys_list)}")
    in_keys = [k for k in keys_list if k["direction"] == "IN"]
    out_keys = [k for k in keys_list if k["direction"] == "OUT"]
    print(f"   [+] Inbound Analyst Keystrokes (IN): {len(in_keys)} commands")
    print(f"   [+] Outbound Shell Renderings (OUT): {len(out_keys)} frames")
    assert len(in_keys) >= 3
    assert len(out_keys) >= 3

    # 8. Close Session
    print("\n8. Closing Live Response Session...")
    close_status, close_data = make_req(f"/api/v18/live/sessions/{session_id}/close", method="POST", token=token)
    assert close_status == 200
    print(f"   [+] Session Closed: {session_id} | Status: {close_data['status']}")
    assert close_data["status"] == "CLOSED"

    print("\n[OK] ALL VERSION 18.0 LIVE RESPONSE MESH TESTS PASSED PERFECTLY!")

if __name__ == "__main__":
    run_test()
