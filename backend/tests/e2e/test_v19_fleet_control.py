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
    print("--- [V19.0 Interactive Fleet C2, Remote OSQuery & GIS Mesh Verification Suite] ---\n")

    # 1. Login
    print("1. Authenticating test analyst session...")
    login_status, login_data = make_req("/api/auth/login", method="POST", body={
        "email": "analyst@acme.corp",
        "password": "SecurePassword123!"
    })
    assert login_status == 200, f"Login failed: {login_data}"
    token = login_data["access_token"]
    print(f"   [+] Authentication successful. Token obtained: {token[:20]}...")

    # 2. Fleet Mesh Status
    print("\n2. Querying Fleet Command & Control Mesh Status...")
    status_code, status_data = make_req("/api/v19/fleet/status", token=token)
    assert status_code == 200, f"Status failed: {status_data}"
    print(f"   [+] Mesh Status: {status_data['mesh_status']}")
    print(f"   [+] Multi-Channel Socket: {status_data['multi_channel_socket_version']}")
    print(f"   [+] OSQuery Evaluator: {status_data['osquery_evaluator_version']}")
    print(f"   [+] GIS Map Engine: {status_data['gis_map_engine']}")
    print(f"   [+] System Integrity: {status_data['system_integrity']}")

    # 3. Setup test endpoint device
    print("\n3. Enrolling and verifying test fleet endpoint...")
    dev_uid = f"v19-fleet-node-{uuid.uuid4().hex[:6]}"
    tel_status, tel_data = make_req("/api/v17/devices/telemetry", method="POST", body={
        "device_id": dev_uid,
        "hostname": f"{dev_uid}.corp.internal",
        "public_ip": "198.51.100.42",
        "latitude": 35.6762,
        "longitude": 139.6503,
        "location_desc": "Tokyo Enterprise Data Center",
        "cpu_usage": 22.0,
        "memory_usage": 45.0
    }, token=token)
    assert tel_status == 200
    print(f"   [+] Target Fleet Node Active: {dev_uid} ({tel_data['location']})")

    # 4. Dispatch Distributed Osquery-style SQL
    print("\n4. Dispatching Osquery-style SQL Query across Fleet...")
    q_status, q_data = make_req("/api/v19/fleet/query/dispatch", method="POST", body={
        "sql_statement": "SELECT pid, name, cpu_usage, username FROM processes WHERE cpu_usage > 50;",
        "target_filter": {"device_id": dev_uid}
    }, token=token)
    assert q_status == 200, f"Query dispatch failed: {q_data}"
    query_run_id = q_data["query_run_id"]
    print(f"   [+] Query Run ID: {query_run_id}")
    print(f"   [+] SQL Dispatched: {q_data['sql_statement']}")
    print(f"   [+] Execution Status: {q_data['status']}")
    assert q_data["status"] == "COMPLETED"

    # Query results
    res_status, res_list = make_req(f"/api/v19/fleet/query/runs/{query_run_id}/results", token=token)
    assert res_status == 200
    assert len(res_list) >= 1
    device_results = res_list[0]["returned_data"]
    print(f"   [+] Returned Tabular Rows Count: {len(device_results)}")
    print(f"   [+] Top Matched Threat Process: {device_results[0]['name']} (PID: {device_results[0]['pid']} | CPU: {device_results[0]['cpu_usage']}%)")
    assert device_results[0]["name"] == "crypto_miner"

    # 5. Remote Process Kill Switch
    print("\n5. Executing One-Click Process Kill Switch (SIGKILL)...")
    kill_status, kill_data = make_req("/api/v19/fleet/actions/dispatch", method="POST", body={
        "device_id": dev_uid,
        "action_type": "KILL_PROCESS",
        "target_parameters": {"pid": 1337, "process_name": "crypto_miner"}
    }, token=token)
    assert kill_status == 200, f"Process kill failed: {kill_data}"
    print(f"   [+] Action ID: {kill_data['action_id']}")
    print(f"   [+] Action Type: {kill_data['action_type']}")
    print(f"   [+] Status: {kill_data['execution_status']}")
    assert kill_data["execution_status"] == "SUCCESS"

    # 6. Remote Host Isolation
    print("\n6. Applying eBPF Host Isolation...")
    iso_status, iso_data = make_req("/api/v19/fleet/actions/dispatch", method="POST", body={
        "device_id": dev_uid,
        "action_type": "ISOLATE_HOST",
        "target_parameters": {"reason": "Malicious process execution confirmed"}
    }, token=token)
    assert iso_status == 200
    print(f"   [+] Host Isolation Applied. Action: {iso_data['action_type']} | Status: {iso_data['execution_status']}")

    # 7. Remote Visual File System Exploration
    print("\n7. Exploring Remote File System (/var/log)...")
    file_status, file_items = make_req("/api/v19/fleet/files/explore", method="POST", body={
        "device_id": dev_uid,
        "path": "/var/log"
    }, token=token)
    assert file_status == 200
    print(f"   [+] Retrieved Remote Directory Entries: {len(file_items)} items")
    filenames = [f["name"] for f in file_items]
    print(f"   [+] Directory Items: {filenames}")
    assert "auth.log" in filenames

    # 8. Remote File Transfer Audit
    print("\n8. Recording Remote File Transfer & SHA-256 Cryptographic Hash...")
    trans_status, trans_data = make_req("/api/v19/fleet/files/transfer", method="POST", body={
        "device_id": dev_uid,
        "direction": "DOWNLOAD",
        "local_file_path": "/var/log/auth.log",
        "file_content": "Aug 20 18:22:04 host sshd[2048]: Accepted publickey for root from 10.0.4.12"
    }, token=token)
    assert trans_status == 200
    print(f"   [+] Transfer ID: {trans_data['transfer_id']}")
    print(f"   [+] File SHA-256 Hash: {trans_data['sha256_hash'][:32]}...")
    print(f"   [+] Secure Storage Target: {trans_data['server_storage_url']}")

    # 9. Real-Time Fleet GIS Map & Latency Telemetry
    print("\n9. Testing Real-Time Fleet GIS Map & Presence Coordinates...")
    map_status, map_devices = make_req("/api/v19/fleet/map", token=token)
    assert map_status == 200
    print(f"   [+] Total Live Mapped Fleet Nodes: {len(map_devices)}")
    matched_dev = next((d for d in map_devices if d["device_id"] == dev_uid), None)
    assert matched_dev is not None
    print(f"   [+] Device {matched_dev['hostname']} Pin: ({matched_dev['latitude']}, {matched_dev['longitude']}) - {matched_dev['location_desc']}")
    print(f"   [+] RTT Latency: {matched_dev['rtt_latency_ms']} ms (Health: {matched_dev['latency_status'].upper()})")

    print("\n[OK] ALL VERSION 19.0 FLEET COMMAND & CONTROL MESH TESTS PASSED PERFECTLY!")

if __name__ == "__main__":
    run_test()
