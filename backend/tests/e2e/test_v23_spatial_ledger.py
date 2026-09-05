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
    print("--- [V23.0 Spatial-Temporal UEBA, eBPF RASP & Merkle Ledger Verification Suite] ---\n")

    # 1. Login
    print("1. Authenticating SOC security analyst...")
    login_status, login_data = make_req("/api/auth/login", method="POST", body={
        "email": "analyst@acme.corp",
        "password": "SecurePassword123!"
    })
    assert login_status == 200, f"Login failed: {login_data}"
    token = login_data["access_token"]
    print(f"   [+] Authentication successful. Token: {token[:20]}...")

    # Ensure ledger is healed before running tests
    make_req("/api/v23/ledger/heal", method="POST", token=token)

    # 2. Check V23 Global Status
    print("\n2. Checking V23 Spatial-Ledger Engine Global Status...")
    status_code, status_data = make_req("/api/v23/status", token=token)
    assert status_code == 200, f"Status check failed: {status_data}"
    print(f"   [+] Engine Version: {status_data['version']}")
    print(f"   [+] GNN Core: {status_data['gnn_model_type']}")
    print(f"   [+] eBPF Driver: {status_data['ebpf_driver_type']}")
    print(f"   [+] Side-Channel Mode: {status_data['side_channel_mode']}")
    print(f"   [+] Ledger State: {status_data['ledger_integrity_state']}")
    print(f"   [+] Active Nodes: {status_data['gnn_active_nodes']} | Edges: {status_data['gnn_active_edges']}")

    # 3. Ingest Entity Interaction into GNN
    print("\n3. Ingesting Entity Interaction into Spatial-Temporal GNN Core...")
    ingest_code, ingest_data = make_req("/api/v23/gnn/events/ingest", method="POST", body={
        "event_type": "auth",
        "source_entity": "sec_operator",
        "target_entity": "srv-enclave-primary"
    }, token=token)
    assert ingest_code == 200, f"GNN ingest failed: {ingest_data}"
    print(f"   [+] Graph Entities: {ingest_data['total_nodes_in_graph']} nodes, {ingest_data['total_edges_in_graph']} edges")

    # 4. Fetch GNN Topology & PyG Tensor Shapes
    print("\n4. Fetching PyG Tensor Shapes & Graph Topology...")
    topo_code, topo_data = make_req("/api/v23/gnn/topology", token=token)
    assert topo_code == 200, f"GNN topology failed: {topo_data}"
    print(f"   [+] PyG Shapes: {topo_data['pyg_tensor_shapes']}")
    print(f"   [+] Node Sample: {len(topo_data['nodes'])} active nodes")
    print(f"   [+] Mean Anomaly Score: {topo_data['mean_anomaly_score']}")

    # 5. Run GNN Anomaly Inference
    print("\n5. Running Topological Anomaly Inference...")
    inf_code, inf_data = make_req("/api/v23/gnn/anomaly/score", method="POST", token=token)
    assert inf_code == 200, f"GNN anomaly inference failed: {inf_data}"
    print(f"   [+] Mean Anomaly Score: {inf_data['mean_anomaly_score']}")
    print(f"   [+] Max Anomaly Peak: {inf_data['max_anomaly_score']}")
    print(f"   [+] Is Anomalous: {inf_data['is_anomalous']}")

    # 6. Check eBPF CO-RE LSM RASP Status
    print("\n6. Checking eBPF CO-RE LSM Coprocessor Status...")
    rasp_code, rasp_data = make_req("/api/v23/rasp/status", token=token)
    assert rasp_code == 200, f"RASP status failed: {rasp_data}"
    print(f"   [+] Driver: {rasp_data['driver']}")
    print(f"   [+] Relocation: {rasp_data['relocation_type']}")
    print(f"   [+] Hook: {rasp_data['kernel_hook']}")
    print(f"   [+] Blocked Bounds: {rasp_data['blocked_paths']}")

    # 7. Update eBPF Map Policy
    print("\n7. Updating Dynamic BPF Policy Map for UID 1000...")
    policy_code, policy_data = make_req("/api/v23/rasp/policy", method="POST", body={
        "uid": 1000,
        "enforce_kill": True
    }, token=token)
    assert policy_code == 200, f"Policy update failed: {policy_data}"
    print(f"   [+] Policy Committed: UID 1000 set to {policy_data['policy_mode']}")

    # 8. Simulate Execution Intercept Under Kernel LSM
    print("\n8. Simulating Binary Execution Intercept Under Kernel LSM...")
    sim_code, sim_data = make_req("/api/v23/rasp/simulate-execution", method="POST", body={
        "uid": 1000,
        "binary_path": "/dev/shm/dropper",
        "command_args": "-e /bin/sh"
    }, token=token)
    assert sim_code == 200, f"Execution simulation failed: {sim_data}"
    print(f"   [+] Action: {sim_data['action']}")
    print(f"   [+] Exit Code: {sim_data['exit_code']}")
    print(f"   [+] Reason: {sim_data['reason']}")
    assert sim_data["action"] == "BLOCKED_EPERM"

    # 9. Generate SEP Power Traces
    print("\n9. Sampling SEP Side-Channel Power Consumption Traces...")
    trace_code, trace_data = make_req("/api/v23/side-channel/traces/generate", method="POST", body={
        "num_traces": 40,
        "key_length": 8,
        "target_key_hex": "5345435245543233",
        "noise_level": 0.25
    }, token=token)
    assert trace_code == 200, f"Trace generation failed: {trace_data}"
    print(f"   [+] Generated {trace_data['traces_generated_count']} traces | Mean Power: {trace_data['power_consumption_mean_mw']} mW")

    # 10. Run Correlation Power Analysis (CPA)
    print("\n10. Executing Correlation Power Analysis (Pearson Correlation)...")
    cpa_code, cpa_data = make_req("/api/v23/side-channel/cpa/analyze", method="POST", body={
        "num_traces": 50,
        "key_length": 8,
        "target_key_hex": "5345435245543233"
    }, token=token)
    assert cpa_code == 200, f"CPA failed: {cpa_data}"
    print(f"   [+] Recovered Key Text: {cpa_data['recovered_key_text']}")
    print(f"   [+] Recovered Key Hex: {cpa_data['recovered_key_hex']}")
    print(f"   [+] Peak Pearson Correlation: {cpa_data['max_correlation_peak']}")
    print(f"   [+] Status: {cpa_data['status']}")

    # 11. Append Blocks to Temporal Merkle Ledger
    print("\n11. Appending Cryptographic Block to Neon SQL Merkle Ledger...")
    test_device_id = str(uuid.uuid4())

    # Ensure clean starting chain state
    make_req("/api/v23/ledger/heal", method="POST", token=token)

    # Append Block 1 (Enrolls Device)
    app_code, app_data = make_req("/api/v23/ledger/append", method="POST", body={
        "device_id": test_device_id,
        "hostname": "srv-enclave-primary",
        "ip_address": "10.0.10.50",
        "system_status": "active",
        "operation_type": "INSERT"
    }, token=token)
    assert app_code == 200, f"Ledger append failed: {app_data}"
    ledger_id_1 = app_data["ledger_id"]
    print(f"   [+] Block 1 Appended: {ledger_id_1[:8]} | Hash: {app_data['record_hash'][:16]}...")

    # Append Block 2 (Updates Device)
    app2_code, app2_data = make_req("/api/v23/ledger/append", method="POST", body={
        "device_id": test_device_id,
        "hostname": "srv-enclave-primary-isolated",
        "ip_address": "10.0.10.50",
        "system_status": "isolated",
        "operation_type": "UPDATE"
    }, token=token)
    assert app2_code == 200, f"Ledger append 2 failed: {app2_data}"
    ledger_id_2 = app2_data["ledger_id"]
    print(f"   [+] Block 2 Appended: {ledger_id_2[:8]} | Parent: {app2_data['parent_hash'][:16]}...")
    assert app2_data["parent_hash"] == app_data["record_hash"]

    # 12. Fetch Ledger Records
    print("\n12. Fetching Merkle Ledger Records...")
    list_code, list_data = make_req("/api/v23/ledger/records", params={"limit": 10}, token=token)
    assert list_code == 200, f"Ledger list failed: {list_data}"
    print(f"   [+] Total Ledger Blocks Retrieved: {len(list_data)}")

    # 13. Verify Ledger Cryptographic Chain
    print("\n13. Cryptographically Verifying Full SQL Merkle Chain...")
    ver_code, ver_data = make_req("/api/v23/ledger/verify", token=token)
    assert ver_code == 200, f"Ledger verification failed: {ver_data}"
    print(f"   [+] Integrity Valid: {ver_data['is_valid']}")
    print(f"   [+] Chain Status: {ver_data['chain_status']}")
    print(f"   [+] Blocks Verified: {ver_data['verified_blocks']}")
    assert ver_data["is_valid"] is True

    # 14. Demonstrate DBA Tamper Detection
    print("\n14. Simulating Rogue DBA SQL Update (Tamper Test)...")
    tamp_code, tamp_data = make_req("/api/v23/ledger/tamper-simulation", method="POST", params={
        "ledger_id": ledger_id_1
    }, token=token)
    assert tamp_code == 200, f"Tamper test call failed: {tamp_data}"
    print(f"   [+] Tamper Injected into Block: {ledger_id_1[:8]} -> {tamp_data['status']}")

    print("\n15. Re-Verifying Ledger to Detect Broken Cryptographic Chain...")
    ver2_code, ver2_data = make_req("/api/v23/ledger/verify", token=token)
    assert ver2_code == 200, f"Second verification failed: {ver2_data}"
    print(f"   [+] Integrity Valid: {ver2_data['is_valid']}")
    print(f"   [+] Chain Status: {ver2_data['chain_status']}")
    print(f"   [+] Tampered Blocks Count: {ver2_data['tampered_blocks_count']}")
    assert ver2_data["is_valid"] is False
    assert ver2_data["chain_status"] == "TAMPERING_DETECTED"
    assert ver2_data["tampered_blocks_count"] >= 1

    # Heal ledger on completion
    make_req("/api/v23/ledger/heal", method="POST", token=token)

    print("\n=======================================================")
    print("ALL 15 E2E TESTS PASSED FOR V23 SPATIAL-TEMPORAL LEDGER!")
    print("=======================================================")

if __name__ == "__main__":
    run_test()
