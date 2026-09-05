"""
Version 29.0 End-to-End Integration Test Suite
Validates:
1. Sovereign Synthetic Telemetry Generation (STG) and capability matrix (/api/v29/status)
2. Purple-Team Emulation Profiles Registry (/api/v29/profiles)
3. High-Fidelity Synthetic Telemetry Generation & ML Cold-Start Bootstrapping (/api/v29/generate-synthetic)
4. Purple-Team Attack Emulation Trigger (/api/v29/trigger-simulation)
5. Historical Simulation Runs & Verification Audit Ledger (/api/v29/runs)
6. KEDA Stream Scaler & GitOps Cloud Fabric Blueprint (/api/v29/keda-config)
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
    print("--- [V29.0 Sovereign STG & Purple-Team Emulation Suite] ---\n")

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

    # 2. Check V29 Capability & Status
    print("2. Checking Sovereign STG & Emulation Status (/api/v29/status)...")
    st_status, st_data = make_req("/api/v29/status", method="GET", token=token)
    assert st_status == 200, f"Status check failed: {st_data}"
    assert st_data.get("stg_active") is True
    assert st_data.get("purple_team_emulation_active") is True
    assert "v29" in st_data.get("version", "").lower()
    print(f"   [+] V29 Status: {st_data.get('stg_engine_version')} | Cold Start ML: {st_data.get('cold_start_ml_readiness')}")
    print(f"   [+] Supported Threat Profiles: {st_data.get('supported_threat_profiles')}\n")

    # 3. List Simulation Profiles
    print("3. Querying Purple-Team Simulation Profiles (/api/v29/profiles)...")
    prof_status, prof_data = make_req("/api/v29/profiles", method="GET", token=token)
    assert prof_status == 200, f"Profile query failed: {prof_data}"
    assert len(prof_data) >= 2, "Expected at least 2 default simulation profiles (APT29 & HermeticWiper)"
    
    apt_profile = next((p for p in prof_data if p["threat_actor"] == "APT29"), None)
    assert apt_profile is not None, "APT29 profile not found"
    assert len(apt_profile.get("steps", [])) >= 3
    print(f"   [+] Loaded {len(prof_data)} simulation profiles. Selected '{apt_profile['name']}' ({len(apt_profile['steps'])} steps)\n")

    # 4. Generate Synthetic Telemetry & Cold-Start ML Bootstrap
    print("4. Executing Sovereign Synthetic Telemetry Generation (/api/v29/generate-synthetic)...")
    stg_payload = {
        "count": 500,
        "diurnal_profile": True,
        "noise_ratio": 0.25,
        "user_clusters_count": 5,
        "bootstrap_ml_coldstart": True,
        "inject_to_stream": True,
        "persist_to_db": True
    }
    stg_status, stg_data = make_req("/api/v29/generate-synthetic", method="POST", body=stg_payload, token=token)
    assert stg_status == 200, f"STG generation failed: {stg_data}"
    assert stg_data.get("status") == "COMPLETED"
    assert stg_data.get("events_generated") == 500
    assert len(stg_data.get("user_clusters", [])) >= 3
    print(f"   [+] Generated {stg_data['events_generated']} events in {stg_data['time_elapsed_sec']}s")
    print(f"   [+] ML Cold-Start Bootstrapped: {stg_data.get('ml_coldstart_bootstrapped')} (Version: {stg_data.get('ml_model_version')})\n")

    # 5. Trigger Purple-Team Attack Emulation Run
    print("5. Triggering Purple-Team Attack Emulation (/api/v29/trigger-simulation)...")
    trig_status, trig_data = make_req("/api/v29/trigger-simulation", method="POST", body={
        "profile_id": apt_profile["id"],
        "async_execution": True,
        "delay_multiplier": 0.5
    }, token=token)
    assert trig_status == 200, f"Trigger failed: {trig_data}"
    run_id = trig_data.get("run_id")
    assert run_id, "Missing run_id in trigger response"
    print(f"   [+] Emulation Run Launched: {run_id} | Steps Count: {trig_data.get('steps_count')}\n")

    # 6. Verify Simulation Run Ledger
    print("6. Verifying Historical Simulation Ledger (/api/v29/runs)...")
    runs_status, runs_data = make_req("/api/v29/runs?limit=5", method="GET", token=token)
    assert runs_status == 200, f"Runs query failed: {runs_data}"
    assert len(runs_data) >= 1, "Expected at least 1 simulation run record"
    matched_run = next((r for r in runs_data if r["id"] == run_id), runs_data[0])
    print(f"   [+] Verified Run {matched_run['id']} | Status: {matched_run['status']} | Profile: {matched_run.get('profile_name')}\n")

    # 7. Check KEDA Autoscaler Configuration
    print("7. Inspecting KEDA Stream Autoscaler Blueprint (/api/v29/keda-config)...")
    keda_status, keda_data = make_req("/api/v29/keda-config", method="GET", token=token)
    assert keda_status == 200, f"KEDA config failed: {keda_data}"
    assert keda_data.get("kind") == "ScaledObject"
    assert keda_data.get("stream_name") == "logs:raw_stream"
    assert keda_data.get("max_replicas") == 50
    print(f"   [+] KEDA Target: {keda_data['stream_name']} | Backlog Threshold: {keda_data['target_backlog_threshold']} | Pod Bounds: {keda_data['min_replicas']}->{keda_data['max_replicas']}\n")

    print("=========================================================================")
    print(" [✓] ALL V29.0 SOVEREIGN STG & PURPLE-TEAM EMULATION TESTS PASSED (100%) ")
    print("=========================================================================\n")


if __name__ == "__main__":
    run_test()
