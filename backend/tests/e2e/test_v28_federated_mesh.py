"""
Version 28.0 End-to-End Integration Test Suite
Validates:
1. Sovereign Federated Learning Mesh Runtime Health (/api/v28/status)
2. Global Shared Anomaly Baseline Model State (/api/v28/global-model)
3. Zero-Knowledge Tenant Parameter Weight Upload (/api/v28/submit-weights)
4. Federated Averaging (FedAvg) Consolidation & Differential Privacy (/api/v28/aggregate)
5. Neon Serverless Consensus Audit Ledger (/api/v28/runs)
6. Multi-Tenant Collaborative Peer Simulation (/api/v28/simulate-mesh)
"""

import sys
import json
import urllib.request
import urllib.error
import urllib.parse
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
    print("--- [V28.0 Federated Learning & Collaborative Threat Mesh Suite] ---\n")

    # 1. Authenticate Analyst
    print("1. Authenticating SOC security analyst...")
    login_status, login_data = make_req("/api/auth/login", method="POST", body={
        "email": "analyst@acme.corp",
        "password": "SecurePassword123!"
    })
    if login_status != 200:
        reg_status, reg_data = make_req("/api/auth/register", method="POST", body={
            "org_name": "Acme Defense Global",
            "email": "analyst@acme.corp",
            "password": "SecurePassword123!"
        })
        login_status, login_data = make_req("/api/auth/login", method="POST", body={
            "email": "analyst@acme.corp",
            "password": "SecurePassword123!"
        })

    token = login_data.get("access_token")
    assert token, "Could not acquire auth token"
    print("   [+] Authenticated successfully with JWT bearer token\n")

    # 2. Check Federation Status
    print("2. Checking Sovereign Federation Mesh Status (/api/v28/status)...")
    st_status, st_data = make_req("/api/v28/status", method="GET")
    assert st_status == 200, f"Status check failed: {st_data}"
    assert st_data.get("mesh_status") == "ACTIVE_FEDERATION_CHANNEL"
    assert st_data.get("differential_privacy_epsilon") == 1.2
    assert "Ring-LWE" in st_data.get("homomorphic_encryption_scheme")
    print(f"   [+] Mesh Status: {st_data.get('mesh_status')}")
    print(f"   [+] Active Peer Nodes: {st_data.get('active_peers_count')}")
    print(f"   [+] Differential Privacy: ε = {st_data.get('differential_privacy_epsilon')}")
    print(f"   [+] Encryption Scheme: {st_data.get('homomorphic_encryption_scheme')}\n")

    # 3. Retrieve Global Shared Model
    print("3. Querying active Global Shared Model Baseline (/api/v28/global-model)...")
    gm_status, gm_data = make_req("/api/v28/global-model", method="GET")
    assert gm_status == 200, f"Global model fetch failed: {gm_data}"
    assert gm_data.get("model_name") == "global_anomaly_forest"
    initial_version = gm_data.get("version_id", 1)
    print(f"   [+] Global Model ID: {gm_data.get('id')}")
    print(f"   [+] Version Epoch: v{initial_version}")
    print(f"   [+] Model State: {gm_data.get('model_state')}\n")

    # 4. Submit Local Tenant Parameter Weights
    print("4. Extracting and uploading local tenant parameter weights (/api/v28/submit-weights)...")
    sub_status, sub_data = make_req("/api/v28/submit-weights", method="POST", body={
        "sample_count": 180
    }, token=token)
    assert sub_status == 200, f"Weight submission failed: {sub_data}"
    assert sub_data.get("status") == "SUBMITTED"
    assert "checksum_signature" in sub_data
    print(f"   [+] Client Update ID: {sub_data.get('id')}")
    print(f"   [+] Local Sample Count: {sub_data.get('local_sample_count')}")
    print(f"   [+] Checksum Digest: {sub_data.get('checksum_signature')[:16]}...\n")

    # 5. Trigger FedAvg Consensus Aggregation
    print("5. Triggering Federated Averaging (FedAvg) Consensus Aggregation (/api/v28/aggregate)...")
    agg_status, agg_data = make_req("/api/v28/aggregate", method="POST", body={
        "model_name": "global_anomaly_forest",
        "min_clients": 2,
        "dp_epsilon": 1.2
    })
    assert agg_status == 200, f"Aggregation failed: {agg_data}"
    assert agg_data.get("status") == "CONSOLIDATED"
    assert "signature_proof" in agg_data
    assert agg_data.get("aggregated_loss") >= 0.0
    print(f"   [+] Consensus Status: {agg_data.get('status')}")
    print(f"   [+] Active Tenants Aggregated: {agg_data.get('active_client_count')}")
    print(f"   [+] Total Samples Ingested: {agg_data.get('total_samples')}")
    print(f"   [+] Consolidated Loss: {agg_data.get('aggregated_loss')}")
    print(f"   [+] Cryptographic Proof: {agg_data.get('signature_proof')[:32]}...\n")

    # 6. List Historical Federation Runs
    print("6. Inspecting SQL Consensus Ledger Audit Trail (/api/v28/runs)...")
    runs_status, runs_data = make_req("/api/v28/runs", method="GET")
    assert runs_status == 200, f"Runs fetch failed: {runs_data}"
    assert len(runs_data) >= 1
    print(f"   [+] Found {len(runs_data)} cryptographic consensus runs in ledger\n")

    # 7. Simulate Multi-Tenant Mesh Burst
    print("7. Simulating multi-tenant collaborative learning burst (/api/v28/simulate-mesh)...")
    sim_status, sim_data = make_req("/api/v28/simulate-mesh", method="POST", params={"peers_count": 4}, token=token)
    assert sim_status == 200, f"Simulation failed: {sim_data}"
    assert sim_data.get("status") == "CONSOLIDATED"
    assert sim_data.get("active_peers") == 4
    print(f"   [+] Simulation Succeeded: Aggregated {sim_data.get('active_peers')} nodes into Epoch v{sim_data.get('total_epochs_trained')}")
    print(f"   [+] Collective Samples: {sim_data.get('total_samples')}")
    print(f"   [+] Cryptographic Proof: {sim_data.get('signature_proof')[:32]}...\n")

    print("=" * 70)
    print("ALL VERSION 28.0 FEDERATED LEARNING MESH TESTS PASSED (100%)")
    print("=" * 70)


if __name__ == "__main__":
    try:
        run_test()
    except AssertionError as ae:
        print(f"\n[!] TEST ASSERTION FAILURE: {ae}")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] TEST EXECUTION ERROR: {e}")
        sys.exit(1)
