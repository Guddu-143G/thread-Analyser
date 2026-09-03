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
    print("--- [V14.0 Quantum-Safe Sovereign Edge & Zero-Trust Verification Suite] ---")

    # 1. Authenticate Analyst Session
    print("\n1. Authenticating test analyst session...")
    test_email = "sovereign_analyst_v14@soc.corp.internal"
    test_password = "MasterPassword123!"

    make_req("/api/auth/register", method="POST", body={
        "org_name": "V14 Sovereign Zero-Trust Mesh Org",
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

    # 2. Continuous STRIDE-as-Code Threat Modeler
    print("\n2. Evaluating Continuous STRIDE-as-Code Threat Modeler...")
    stride_status, stride_data = make_req("/api/sovereign/threat-model", token=token)
    assert stride_status == 200, f"STRIDE evaluation failed: {stride_data}"
    print(f"   [✓] Architecture Health Score: {stride_data['architecture_health_score']}%")
    print(f"   [✓] Total STRIDE Threats Identified: {stride_data['total_threats_identified']}")
    print(f"   [✓] Topology Elements: {stride_data['total_nodes']} nodes, {stride_data['total_edges']} conduits")
    print("   [✓] STRIDE Classification Breakdown:")
    for cat, count in stride_data["stride_breakdown"].items():
        print(f"       - {cat}: {count} threats")
    assert stride_data["total_threats_identified"] >= 3, "Expected multiple STRIDE threat classifications"

    # 3. Zero-Knowledge Private Set Intersection (ZK-PSI)
    print("\n3. Executing Diffie-Hellman Zero-Knowledge PSI Cooperative Threat Hunter (2^255 - 19)...")
    org_a_iocs = ["185.220.101.5", "d41d8cd98f00b204e9800998ecf8427e", "apt29-c2-beacon.darknet.org", "mimikatz_x64.dll", "198.51.100.44"]
    org_b_iocs = ["185.220.101.5", "legit-azure-login.microsoft.com", "apt29-c2-beacon.darknet.org", "system_update_patch_99.bin"]
    
    zk_status, zk_data = make_req("/api/sovereign/zk-psi/match", method="POST", body={
        "party_a_name": "Defense Infrastructure Corp",
        "party_a_indicators": org_a_iocs,
        "party_b_name": "Financial Cloud Operations",
        "party_b_indicators": org_b_iocs
    }, token=token)

    assert zk_status == 200, f"ZK-PSI failed: {zk_data}"
    print(f"   [✓] Protocol: {zk_data['protocol']}")
    print(f"   [✓] Prime Field: {zk_data['prime_field']}")
    print(f"   [✓] Intersecting IOCs Found (X ∩ Y): {zk_data['intersection_matches_count']}")
    print(f"   [✓] Information Leakage (Unmatched Items): {zk_data['information_leakage_bytes']} Bytes")
    print(f"   [✓] Zero-Knowledge Proof Valid: {zk_data['zero_knowledge_proof_valid']}")
    assert zk_data["intersection_matches_count"] == 2, "Expected exactly 2 intersecting IOCs"
    matched_names = [m["indicator"] for m in zk_data["matched_indicators"]]
    assert "185.220.101.5" in matched_names and "apt29-c2-beacon.darknet.org" in matched_names

    # 4. Merkle Mountain Range (MMR) Cryptographic Audit Ledger
    print("\n4. Testing Merkle Mountain Range (MMR) Tamper-Resistant Proof of Order...")
    mmr_status, mmr_data = make_req("/api/sovereign/mmr/peaks", token=token)
    assert mmr_status == 200, f"MMR peaks failed: {mmr_data}"
    print(f"   [✓] Master MMR Root Peak Hash: {mmr_data['root_hash']}")
    print(f"   [✓] Total Sealed Audit Leaves: {mmr_data['total_audit_leaves']}")
    print(f"   [✓] Active Mountain Peaks: {mmr_data['peak_count']}")

    # Verify inclusion proof for leaf 0
    proof_status, proof_data = make_req("/api/sovereign/mmr/verify-proof", method="POST", body={
        "leaf_index": 0,
        "claimed_root": mmr_data["root_hash"]
    }, token=token)
    assert proof_status == 200, f"MMR verify proof failed: {proof_data}"
    print(f"   [✓] Leaf #0 Verification: {proof_data['cryptographic_proof_status']}")
    print(f"   [✓] Leaf Hash: {proof_data['leaf_hash']}")
    print(f"   [✓] Action Verified: {proof_data['entry_payload']['action']}")
    assert proof_data["cryptographic_proof_status"] == "VALID_TAMPER_EVIDENT"

    # 5. WebAssembly (Wasm) Sandboxed Client Detection Hub
    print("\n5. Testing WebAssembly (Wasm) Sandboxed Edge Detection Modules...")
    wasm_status, wasm_list = make_req("/api/sovereign/wasm/plugins", token=token)
    assert wasm_status == 200
    assert len(wasm_list) >= 3
    print(f"   [✓] Active Verified Wasm Plugins in Registry: {len(wasm_list)}")

    # Deploy new plugin
    dep_status, dep_data = make_req("/api/sovereign/wasm/deploy-plugin", method="POST", body={
        "name": "Heuristic Memory Scanner",
        "version": "1.2.0",
        "allowed_capabilities": ["read_proc_names", "parse_ocsf_json", "sigma_evaluate"]
    }, token=token)
    assert dep_status == 200
    print(f"   [✓] Deployed Wasm Plugin: {dep_data['name']} (v{dep_data['version']}) | SHA: {dep_data['wasm_sha256'][:16]}...")
    print(f"   [✓] Syscalls Granted: {dep_data['syscalls_granted']} (Hardware Memory Sandbox Bound)")

    # Execute Sandboxed Test
    exec_status, exec_data = make_req("/api/sovereign/wasm/execute-test", method="POST", body={
        "plugin_id": "wasm-sigma-engine-v2",
        "sample_payload": "powershell.exe -ExecutionPolicy Bypass -Command whoami /priv"
    }, token=token)
    assert exec_status == 200
    print(f"   [✓] Sandboxed Execution Latency: {exec_data['execution_latency_microseconds']} µs")
    print(f"   [✓] Host Violations Detected: {exec_data['host_isolation_violation_count']}")
    print(f"   [✓] Detection Triggered in Wasm: {exec_data['detection_triggered']}")
    assert exec_data["detection_triggered"] is True

    # 6. Physical Airspace SDR RF & BGP Route Leak Telemetry
    print("\n6. Testing Physical Airspace SDR & BGP Route Leak Telemetry...")
    sdr_status, sdr_data = make_req("/api/sovereign/sdr-rf/telemetry", token=token)
    assert sdr_status == 200
    print(f"   [✓] SDR Center Frequency: {sdr_data['center_frequency_mhz']} MHz ({sdr_data['spectrum_band']})")
    print(f"   [✓] SDR SNR: {sdr_data['signal_to_noise_ratio_db']} dB | IQ Sample Entropy: {sdr_data['iq_sample_entropy']}/8.0")
    print(f"   [✓] SDR Frontend: {sdr_data['hardware_sdr_frontend']}")

    bgp_status, bgp_data = make_req("/api/sovereign/bgp/route-leak", token=token)
    assert bgp_status == 200
    print(f"   [✓] BGP Origin AS: AS{bgp_data['origin_as']} ({bgp_data['origin_as_name']})")
    print(f"   [✓] BGP Observed Path: {bgp_data['observed_as_path']}")
    print(f"   [✓] BGP RPKI Validation: {bgp_data['mitigation_action']}")
    assert bgp_data["hijack_detected"] is False

    print("\n>>> ALL V14.0 QUANTUM-SAFE SOVEREIGN EDGE & ZERO-TRUST TESTS PASSED SUCCESSFULLY! <<<")

if __name__ == "__main__":
    run_test()
