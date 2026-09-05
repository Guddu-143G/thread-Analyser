"""
Version 27.0 End-to-End Integration Test Suite
Validates:
1. V27 ML Engine Health & Runtime Status (/api/v27/status)
2. Tenant ML Model Bootstrapping & Retrieval (/api/v27/models)
3. Real-Time Telemetry Scoring (Benign vs Malicious Anomaly Detection) (/api/v27/score)
4. Self-Training Multi-Tenant ML Pipeline Execution (/api/v27/train)
5. Statistical Feature Baseline Distributions (/api/v27/baselines)
6. Training Run Execution Audit Trail (/api/v27/runs)
7. Multi-Event Telemetry Simulation Stream (/api/v27/simulate-telemetry)
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
    print("--- [V27.0 ML Anomaly Engine & Multi-Tenant Pipeline Suite] ---\n")

    # 1. Login or Register
    print("1. Authenticating SOC security analyst...")
    login_status, login_data = make_req("/api/auth/login", method="POST", body={
        "email": "analyst@acme.corp",
        "password": "SecurePassword123!"
    })
    if login_status != 200:
        print("   User not found, registering analyst@acme.corp...")
        reg_status, reg_data = make_req("/api/auth/register", method="POST", body={
            "org_name": "Acme Defense Global",
            "email": "analyst@acme.corp",
            "password": "SecurePassword123!"
        })
        assert reg_status == 200, f"Registration failed: {reg_data}"
        login_status, login_data = make_req("/api/auth/login", method="POST", body={
            "email": "analyst@acme.corp",
            "password": "SecurePassword123!"
        })

    token = login_data.get("access_token")
    assert token, "Could not acquire auth token"
    print("   [+] Authenticated successfully with JWT bearer token\n")

    # 2. Check ML Engine Status
    print("2. Checking ML Anomaly Engine runtime status (/api/v27/status)...")
    st_status, st_data = make_req("/api/v27/status", method="GET")
    assert st_status == 200, f"Status check failed: {st_data}"
    assert st_data.get("engine") == "SecurityAnomalyDetector"
    assert st_data.get("total_features") == 10
    print(f"   [+] Engine Version: {st_data.get('version')}")
    print(f"   [+] Sklearn Available: {st_data.get('sklearn_available')}")
    print(f"   [+] Features Tracked: {st_data.get('total_features')} dimensions\n")

    # 3. Retrieve or Bootstrap Tenant ML Model
    print("3. Retrieving active tenant ML model (/api/v27/models)...")
    m_status, m_data = make_req("/api/v27/models", method="GET", token=token)
    assert m_status == 200, f"Model fetch failed: {m_data}"
    assert m_data.get("algorithm") == "IsolationForest"
    assert m_data.get("status") == "ACTIVE"
    print(f"   [+] Model ID: {m_data.get('id')}")
    print(f"   [+] Training Samples: {m_data.get('training_samples_count')}")
    print(f"   [+] Baselines Count: {len(m_data.get('baselines', []))}\n")

    # 4. Score Benign Telemetry Event
    print("4. Scoring normal enterprise baseline telemetry event (/api/v27/score)...")
    benign_event = {
        "request_rate_1m": 22.0,
        "request_rate_5m": 98.0,
        "failed_auth_count": 0,
        "payload_entropy": 2.8,
        "unusual_port_flag": 0,
        "geo_distance_km": 35.0,
        "packet_size_variance": 130.0,
        "token_anomaly_score": 0.03,
        "session_duration_sec": 310.0,
        "concurrent_sessions": 1
    }
    b_status, b_data = make_req("/api/v27/score", method="POST", body=benign_event, token=token)
    assert b_status == 200, f"Scoring failed: {b_data}"
    assert b_data.get("is_anomaly") is False
    assert b_data.get("anomaly_score") < 0.65
    print(f"   [+] Benign Telemetry Score: {b_data.get('anomaly_score')} (Severity: {b_data.get('severity')})")
    print(f"   [+] Classification: Is Anomaly = {b_data.get('is_anomaly')}\n")

    # 5. Score Malicious Exfiltration Anomaly Event
    print("5. Scoring high-deviation brute force / exfiltration attack event (/api/v27/score)...")
    malicious_event = {
        "request_rate_1m": 260.0,
        "request_rate_5m": 980.0,
        "failed_auth_count": 32,
        "payload_entropy": 7.8,
        "unusual_port_flag": 1,
        "geo_distance_km": 8800.0,
        "packet_size_variance": 2200.0,
        "token_anomaly_score": 0.95,
        "session_duration_sec": 8.0,
        "concurrent_sessions": 18
    }
    m_score_status, m_score_data = make_req("/api/v27/score", method="POST", body=malicious_event, token=token)
    assert m_score_status == 200, f"Malicious scoring failed: {m_score_data}"
    assert m_score_data.get("is_anomaly") is True
    assert m_score_data.get("anomaly_score") >= 0.65
    print(f"   [+] Malicious Anomaly Score: {m_score_data.get('anomaly_score')} (Severity: {m_score_data.get('severity')})")
    print(f"   [+] Top Contributing Feature: {m_score_data.get('top_contributing_features', [{}])[0].get('feature')} (Z: {m_score_data.get('top_contributing_features', [{}])[0].get('z_score')}σ)")
    print(f"   [+] PCA 2D Projected Coordinates: {m_score_data.get('pca_coordinates')}\n")

    # 6. Trigger Pipeline Retraining
    print("6. Triggering self-training pipeline retraining (/api/v27/train)...")
    train_status, train_data = make_req("/api/v27/train", method="POST", body={
        "lookback_days": 30,
        "contamination": 0.05,
        "n_estimators": 80,
        "include_synthetic": True
    }, token=token)
    assert train_status == 200, f"Retraining failed: {train_data}"
    assert train_data.get("status") == "SUCCESS"
    print(f"   [+] Retraining Succeeded in {train_data.get('duration_sec')}s using {train_data.get('samples_used')} samples\n")

    # 7. Check Feature Baselines
    print("7. Inspecting feature baseline calibrations (/api/v27/baselines)...")
    base_status, base_data = make_req("/api/v27/baselines", method="GET", token=token)
    assert base_status == 200, f"Baselines fetch failed: {base_data}"
    assert len(base_data) == 10
    print(f"   [+] Loaded {len(base_data)} feature baseline metrics with dynamic weights\n")

    # 8. Check Historical Model Runs
    print("8. Listing historical model training runs (/api/v27/runs)...")
    runs_status, runs_data = make_req("/api/v27/runs", method="GET", token=token)
    assert runs_status == 200, f"Runs fetch failed: {runs_data}"
    assert len(runs_data) >= 1
    print(f"   [+] Found {len(runs_data)} execution run records in audit log\n")

    # 9. Simulate Telemetry Burst
    print("9. Simulating live telemetry stream burst (/api/v27/simulate-telemetry)...")
    sim_status, sim_data = make_req("/api/v27/simulate-telemetry", method="POST", params={"count": 10}, token=token)
    assert sim_status == 200, f"Simulation failed: {sim_data}"
    assert sim_data.get("count") == 10
    print(f"   [+] Successfully streamed and scored {sim_data.get('count')} live events\n")

    print("=" * 70)
    print("ALL VERSION 27.0 ML ANOMALY ENGINE TESTS PASSED (100%)")
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
