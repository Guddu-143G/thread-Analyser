"""
Version 30.0 End-to-End Integration Test Suite.
Validates:
1. GSDT Engine & Autonomous Cyber Range status (/api/v30/status)
2. Zero-PII Cryptographic "Safe-Clone" Digital Twin Topology (/api/v30/topology, /api/v30/clone-twin)
3. Carrier-Scale Traffic Ingestion Benchmark (1,000,000+ EPS with eBPF XDP bypass metrics) (/api/v30/simulate-carrier-burst)
4. Generative Adversarial Agent Network (GAAN) Simulation Trigger (/api/v30/trigger-scenario, /api/v1/range/trigger)
5. GAAN Simulation Sessions History (/api/v30/sessions)
6. Cryptographic Merkle-Chain Simulation Execution Ledger (/api/v30/ledger)
"""

import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

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
    print("=" * 75)
    print("--- [V30.0 Generative Security Digital Twin & Cyber Range E2E Suite] ---")
    print("=" * 75)

    # 1. Authenticate Analyst
    print("\n[1] Authenticating SOC security analyst...")
    login_status, login_data = make_req("/api/auth/login", method="POST", body={
        "email": "analyst@acme.corp",
        "password": "SecurePassword123!"
    })

    token = None
    if login_status == 200 and "access_token" in login_data:
        token = login_data["access_token"]
        print("    [+] Successfully obtained JWT Bearer token.")
    else:
        print(f"    [*] Note: Login returned {login_status}. Proceeding with unauthenticated demo routing.")

    # 2. Query V30 Status
    print("\n[2] Checking V30 GSDT & Autonomous Cyber Range Status (/api/v30/status)...")
    status_code, status_data = make_req("/api/v30/status", method="GET", token=token)
    assert status_code == 200, f"Expected 200, got {status_code}: {status_data}"
    assert status_data["version"] == "v30.0", f"Unexpected version: {status_data}"
    assert status_data["zero_pii_compliance_mode"] == "HMAC-SHA-256-SAFE-CLONE"
    assert status_data["carrier_scale_eps_capacity"] == 1000000
    print(f"    [+] V30 Cyber Range Online! Version: {status_data['version']}, Supported: {status_data['supported_scenarios']}")

    # 3. Query Digital Twin Topology
    print("\n[3] Querying Cloned Digital Twin Topology (/api/v30/topology)...")
    top_code, top_data = make_req("/api/v30/topology", method="GET", token=token)
    assert top_code == 200, f"Expected 200, got {top_code}: {top_data}"
    assert top_data["zero_pii_sanitized"] is True
    assert top_data["anonymization_algorithm"] == "HMAC-SHA-256"
    assert top_data["total_assets"] >= 5
    print(f"    [+] Topology Verified: {top_data['total_assets']} assets, zero-PII sanitized via HMAC-SHA-256.")
    sample_node = top_data["nodes"][0]
    print(f"    [+] Sample Node: '{sample_node['name']}' | Hostname Hash: {sample_node['hostname_hash'][:24]}...")

    # 4. Refresh Safe-Clone Digital Twin
    print("\n[4] Triggering Safe-Clone Digital Twin Refresh (/api/v30/clone-twin)...")
    clone_code, clone_data = make_req("/api/v30/clone-twin", method="POST", token=token)
    assert clone_code == 200, f"Expected 200, got {clone_code}: {clone_data}"
    assert clone_data["total_assets"] >= 5
    print(f"    [+] Safe-Clone refreshed {clone_data['total_assets']} Zero-PII nodes successfully.")

    # 5. Benchmark Carrier Burst Ingestion (1,000,000+ EPS)
    print("\n[5] Benchmarking Carrier-Scale Ingestion (1,000,000+ EPS with eBPF XDP)...")
    burst_code, burst_data = make_req("/api/v30/simulate-carrier-burst", method="POST", token=token, body={
        "eps_target": 1000000,
        "duration_seconds": 5,
        "packet_type": "NETFLOW_OCSF"
    })
    assert burst_code == 200, f"Expected 200, got {burst_code}: {burst_data}"
    assert burst_data["status"] == "BURST_COMPLETED"
    assert burst_data["ebpf_xdp_bypass_active"] is True
    assert burst_data["eps_achieved"] >= 950000
    print(f"    [+] Burst Achieved: {burst_data['eps_achieved']:,} EPS ({burst_data['total_packets_transmitted']:,} total packets).")
    print(f"    [+] eBPF XDP Bypass Latency: {burst_data['kernel_bypass_latency_us']} µs | Ring Buffer Util: {burst_data['ring_buffer_utilization_pct']}%.")

    # 6. Trigger GAAN APT29 CozyBear Emulation
    print("\n[6] Triggering GAAN Autonomous Cyber Range Scenario (/api/v30/trigger-scenario)...")
    trig_code, trig_data = make_req("/api/v30/trigger-scenario", method="POST", token=token, body={
        "scenario_name": "APT29_COZYBEAR",
        "red_agent_model": "local-mistral-7b-v1",
        "blue_agent_model": "local-mistral-7b-v1",
        "async_execution": True
    })
    assert trig_code == 200, f"Expected 200, got {trig_code}: {trig_data}"
    session_id = trig_data["session_id"]
    print(f"    [+] GAAN Simulation Triggered! Session ID: {session_id} | Steps: {trig_data['steps_count']}")

    # 7. Query GAAN Sessions & Ledger
    print("\n[7] Querying GAAN Sessions Registry (/api/v30/sessions)...")
    time.sleep(1.5)  # Allow background execution steps to register
    sess_code, sess_data = make_req("/api/v30/sessions", method="GET", token=token)
    assert sess_code == 200, f"Expected 200, got {sess_code}: {sess_data}"
    assert len(sess_data) >= 1
    print(f"    [+] Sessions Registered: {len(sess_data)} session(s). Latest Status: {sess_data[0]['status']}")

    print("\n[8] Querying Cryptographic Merkle-Chain Simulation Ledger (/api/v30/ledger)...")
    ledg_code, ledg_data = make_req("/api/v30/ledger", method="GET", token=token)
    assert ledg_code == 200, f"Expected 200, got {ledg_code}: {ledg_data}"
    print(f"    [+] Ledger Records: {len(ledg_data)} entries retrieved.")
    if ledg_data:
        entry = ledg_data[0]
        print(f"    [+] Step #{entry['step_index']}: {entry['mitre_tactic_id']} • {entry['mitre_technique_id']} | Merkle Hash: {entry['current_ledger_hash'][:24]}...")

    # 8. Test V1 Alias Compatibility
    print("\n[9] Verifying V1 Compatibility Alias (/api/v1/range/status)...")
    v1_code, v1_data = make_req("/api/v1/range/status", method="GET", token=token)
    assert v1_code == 200, f"Expected 200, got {v1_code}: {v1_data}"
    assert v1_data["version"] == "v30.0"
    print("    [+] V1 Alias Endpoint verified successfully.")

    print("\n" + "=" * 75)
    print(">>> ALL V30 END-TO-END CYBER RANGE TESTS PASSED WITH 100% SUCCESS! <<<")
    print("=" * 75)


if __name__ == "__main__":
    run_test()
