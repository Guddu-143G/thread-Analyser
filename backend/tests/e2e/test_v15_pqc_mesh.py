import urllib.request
import urllib.error
import urllib.parse
import json
import sys

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
    print("--- [V15.0 Zero-Trust Physical & Quantum Mesh Verification Suite] ---")

    # 1. Authenticate Analyst Session
    print("\n1. Authenticating test analyst session...")
    test_email = "pqc_vanguard_v15@soc.corp.internal"
    test_password = "MasterPassword123!"

    make_req("/api/auth/register", method="POST", body={
        "org_name": "V15 Post-Quantum Vanguard Mesh Org",
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

    # 2. NIST FIPS 203/204 Hybrid Post-Quantum Key Encapsulation & Transport
    print("\n2. Testing NIST FIPS 203/204 Post-Quantum Hybrid Handshake & Double-Encrypted Envelopes...")
    pqc_status, pqc_data = make_req("/api/v15/pqc/handshake", method="POST", body={
        "node_id": "soc-edge-enclave-01"
    }, token=token)
    assert pqc_status == 200, f"PQC Handshake failed: {pqc_data}"
    print(f"   [+] Handshake Status: {pqc_data['handshake_status']}")
    print(f"   [+] KEM Standard: {pqc_data['pqc_metadata']['kem_standard']}")
    print(f"   [+] Signature Standard: {pqc_data['pqc_metadata']['signature_standard']}")
    print(f"   [+] ML-KEM-1024 Public Key: {pqc_data['ml_kem_1024_public_key'][:32]}...")
    print(f"   [+] ML-DSA-87 Verify Key: {pqc_data['ml_dsa_87_verify_key'][:32]}...")

    # Wrap envelope
    raw_telemetry = {"event": "PROCESS_SPAWN", "user": "root", "cmd": "/bin/sh -c reverse_shell"}
    env_status, env_data = make_req("/api/v15/pqc/envelope", method="POST", body={
        "raw_payload": raw_telemetry
    }, token=token)
    assert env_status == 200, f"Envelope wrapping failed: {env_data}"
    print(f"   [+] Post-Quantum Security Posture: {env_data['security_posture']}")
    print(f"   [+] Encapsulated Key Hex: {env_data['encapsulated_key_hex'][:32]}...")
    print(f"   [+] Agent Signature Hex: {env_data['agent_signature_hex'][:32]}...")

    # Unwrap envelope
    unwrap_status, unwrap_data = make_req("/api/v15/pqc/unwrap", method="POST", body=env_data, token=token)
    assert unwrap_status == 200, f"Envelope unwrapping failed: {unwrap_data}"
    print(f"   [+] PQC Verification: {unwrap_data['pqc_verification_status']}")
    print(f"   [+] Quantum Safe Verified: {unwrap_data['quantum_safe']}")

    # 3. CPU PMU Hardware Side-Channel Telemetry & Attack Simulation
    print("\n3. Testing CPU Performance Monitoring Unit (PMU) & Side-Channel Monitor (OCSF 6002)...")
    pmu_status, pmu_data = make_req("/api/v15/pmu/metrics", token=token)
    assert pmu_status == 200, f"PMU metrics failed: {pmu_data}"
    print(f"   [+] OCSF Class: {pmu_data['metadata']['class_name']} (Class {pmu_data['metadata']['class_uid']})")
    print(f"   [+] Nominal Cache Miss Ratio: {pmu_data['hardware_metrics']['cache_miss_ratio']}")

    # Simulate Flush+Reload cache timing attack
    sim_status, sim_data = make_req("/api/v15/pmu/simulate-attack", method="POST", body={
        "attack_type": "flush_reload"
    }, token=token)
    assert sim_status == 200
    print(f"   [+] Simulated Attack Triggered: {sim_data['attack_analysis']['detected_pattern']}")
    print(f"   [+] Anomaly Cache Miss Ratio: {sim_data['hardware_metrics']['cache_miss_ratio']} (Severity {sim_data['severity_id']})")
    print(f"   [+] Mitigation Response: {sim_data['attack_analysis']['action_taken']}")
    assert sim_data["severity_id"] == 5
    assert sim_data["hardware_metrics"]["cache_miss_ratio"] > 0.70

    # 4. Self-Healing Generative Adversarial Red Teaming (GART) Arena
    print("\n4. Testing Closed-Loop Generative Adversarial Red Teaming (GART) Engine...")
    gart_status, gart_data = make_req("/api/v15/gart/run-loop", method="POST", body={
        "seed_id": "SEED-01"
    }, token=token)
    assert gart_status == 200, f"GART run failed: {gart_data}"
    print(f"   [+] Target Seed Attack: {gart_data['seed_attack']['name']}")
    print(f"   [+] Mutations Evaluated: {gart_data['mutations_tested']}")
    print(f"   [+] Evasion Bypasses Discovered: {gart_data['evasions_discovered']}")
    if gart_data["synthesized_patch"]:
        print(f"   [+] Synthesized Patch ID: {gart_data['synthesized_patch']['patch_id']}")
        print(f"   [+] Resilience Score: {gart_data['synthesized_patch']['resilience_score']}%")
        print(f"   [+] Countered Evasion: {gart_data['synthesized_patch']['evasion_technique']}")

    patch_status, patch_list = make_req("/api/v15/gart/patches", token=token)
    assert patch_status == 200
    assert len(patch_list) >= 1
    print(f"   [+] Total Active Synthesized Sigma Hot Patches: {len(patch_list)}")

    # 5. Private ZK-Rollup Sovereign Threat Ledger
    print("\n5. Testing Decentralized Zero-Knowledge Sovereign Threat Rollup Ledger...")
    rollup_status, rollup_data = make_req("/api/v15/zk-rollup/state", token=token)
    assert rollup_status == 200, f"ZK-Rollup state failed: {rollup_data}"
    print(f"   [+] Master ZK State Root: {rollup_data['current_state_root']}")
    print(f"   [+] Total Sealed Batches: {rollup_data['total_sealed_batches']}")
    print(f"   [+] ZK Proof System: {rollup_data['zk_proof_system']}")

    # Commit new blinded threat
    commit_status, commit_data = make_req("/api/v15/zk-rollup/commit-threat", method="POST", body={
        "indicator": "198.51.100.99",
        "indicator_type": "ipv4",
        "confidence": 0.99
    }, token=token)
    assert commit_status == 200, f"Commit threat failed: {commit_data}"
    print(f"   [+] Committed Blinded Hash: {commit_data['blinded_hash'][:32]}...")
    print(f"   [+] Active Batch ID: {commit_data['active_batch_id']}")

    print("\n>>> ALL V15.0 ZERO-TRUST PHYSICAL & QUANTUM MESH TESTS PASSED SUCCESSFULLY! <<<")

if __name__ == "__main__":
    run_test()
