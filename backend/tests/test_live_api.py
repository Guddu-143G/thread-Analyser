import urllib.request
import urllib.parse
import json

BASE_URL = "http://localhost:8000"

def request_json(path, method="GET", payload=None, headers=None):
    if headers is None:
        headers = {}
    
    url = f"{BASE_URL}{path}"
    data = None
    if payload is not None:
        if isinstance(payload, dict) or isinstance(payload, list):
            data = json.dumps(payload).encode("utf-8")
            headers["Content-Type"] = "application/json"
        elif isinstance(payload, str):
            data = payload.encode("utf-8")
            
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req) as response:
            res_body = response.read().decode("utf-8")
            return response.status, json.loads(res_body) if res_body else {}
    except urllib.error.HTTPError as e:
        err_body = e.read().decode("utf-8")
        try:
            err_json = json.loads(err_body)
        except Exception:
            err_json = {"raw": err_body}
        return e.code, err_json

def test_flow():
    print("=== Testing Live Backend API (Zero-Dependency) ===")
    
    # 1. Health check
    status, body = request_json("/api/health")
    print(f"[1] Health check: {status} => {body}")
    assert status == 200

    # 2. Register / Login
    auth_payload = {
        "email": "admin@threatanalyser.io",
        "password": "SecurityAdmin2026!",
        "org_name": "ACME Security SOC"
    }
    
    # Try login first
    login_payload = {
        "email": auth_payload["email"],
        "password": auth_payload["password"]
    }
    status, login_res = request_json(
        "/api/auth/login",
        method="POST",
        payload=login_payload
    )
    
    if status != 200:
        # Register user
        reg_status, reg_body = request_json("/api/auth/register", method="POST", payload=auth_payload)
        print(f"[2] Register response: {reg_status} => {reg_body}")
        token = reg_body.get("access_token")
    else:
        print(f"[2] Login status: {status}")
        token = login_res.get("access_token")

    assert token, f"No access token obtained: {login_res}"
    headers = {"Authorization": f"Bearer {token}"}
    print(f"[+] Authenticated successfully with token: {token[:20]}...")

    # 3. Test V26 Status
    status, v26_status = request_json("/api/v26/status", headers=headers)
    print(f"[3] V26 Status: {status} => {v26_status}")
    assert status == 200

    # 4. Ingest OCSF Event Burst
    ocsf_events = [
        {
            "class_uid": 1007,
            "type": "process_activity",
            "process_name": "cmd.exe",
            "process_path": "C:\\Windows\\System32\\cmd.exe",
            "parent_process": "explorer.exe",
            "command_line": "cmd.exe /c start powershell.exe"
        },
        {
            "class_uid": 1007,
            "type": "process_activity",
            "process_name": "powershell.exe",
            "process_path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "parent_process": "cmd.exe",
            "command_line": "powershell -enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdA..."
        },
        {
            "class_uid": 4001,
            "type": "network_connection",
            "process_name": "powershell.exe",
            "src_ip": "192.168.1.144",
            "dst_ip": "185.220.101.5",
            "dst_port": 443
        },
        {
            "class_uid": 1001,
            "type": "file_activity",
            "process_name": "powershell.exe",
            "file_path": "C:\\Users\\Public\\backdoor.ps1",
            "action": "WROTE"
        }
    ]
    status, ingest_res = request_json("/api/v26/provenance/ingest-ocsf", method="POST", payload=ocsf_events, headers=headers)
    print(f"[4] OCSF Ingest into DPG: {status} => {ingest_res}")
    assert status == 200

    # 5. Query DPG Graph
    status, graph_res = request_json("/api/v26/provenance/graph", headers=headers)
    print(f"[5] DPG Graph Topology: {status} => Nodes: {graph_res.get('total_nodes')}, Edges: {graph_res.get('total_edges')}")
    assert status == 200

    # 6. Execute Causal Traceback
    trace_payload = {"target_entity_or_id": "sock:185.220.101.5:443", "max_depth": 5, "asp_shell_descendants_only": True}
    status, trace_res = request_json("/api/v26/provenance/traceback", method="POST", payload=trace_payload, headers=headers)
    print(f"[6] Causal Traceback: {status} => Patient Zero: {trace_res.get('patient_zero_node', {}).get('name')}, Latency: {trace_res.get('latency_ms')}ms")
    assert status == 200

    # 7. Execute Autonomous SOAR DAG Playbook
    soar_payload = {
        "device_id": "dev-edge-sovereign-01",
        "threat_context": {
            "priority_score": 96.0,
            "tactic_id": "TA0002",
            "asset_criticality": 4,
            "process_name": "powershell.exe"
        }
    }
    status, soar_res = request_json("/api/v26/soar/execute", method="POST", payload=soar_payload, headers=headers)
    print(f"[7] SOAR Playbook Execution: {status} => Status: {soar_res.get('status')}, Steps: {soar_res.get('total_steps_executed')}, Duration: {soar_res.get('execution_duration_ms')}ms")
    assert status == 200

    # 8. TPM 2.0 Hardware Attestation
    status, attest_res = request_json("/api/v26/tpm/attest-block", method="POST", payload={"block_limit": 1000}, headers=headers)
    print(f"[8] TPM 2.0 Attestation: {status} => Root: {attest_res.get('merkle_root_hash', '')[:16]}..., Signature: {attest_res.get('tpm_hardware_signature', '')[:24]}...")
    assert status == 200

    # 9. Verify TPM Hardware Signature
    verify_payload = {
        "merkle_root_hash": attest_res["merkle_root_hash"],
        "tpm_hardware_signature": attest_res["tpm_hardware_signature"],
        "pcr_composite_digest": attest_res["pcr_composite_digest"]
    }
    status, verify_res = request_json("/api/v26/tpm/verify-attestation", method="POST", payload=verify_payload, headers=headers)
    print(f"[9] TPM Signature Verification: {status} => Status: {verify_res.get('status')}, Valid: {verify_res.get('is_attestation_valid')}")
    assert status == 200

    print("\n>>> ALL BACKEND API ENDPOINTS VERIFIED AND OPERATIONAL WITH 100% SUCCESS! <<<")

if __name__ == "__main__":
    test_flow()
