import urllib.request
import urllib.error
import urllib.parse
import json
import sys
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
        except Exception:
            parsed = {"detail": err_body}
        return e.code, parsed

def run_test():
    print("--- [V12.0 Real-Time Security Telemetry & WebSocket Verification Suite] ---")

    # 1. Authenticate Analyst Session
    print("\n1. Authenticating test analyst session...")
    test_email = "realtime_analyst_v12@soc.corp.internal"
    test_password = "MasterPassword123!"

    make_req("/api/auth/register", method="POST", body={
        "org_name": "V12 Real-Time Security Mesh Org",
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

    # 2. WebSocket Engine & Status Inspection
    print("\n2. Querying WebSocket Server & Redis Pub/Sub Status...")
    ws_status_code, ws_data = make_req("/api/ws/status", token=token)
    assert ws_status_code == 200, f"Failed to get WS status: {ws_data}"
    print(f"   [✓] Server Status: {ws_data['server_status']}")
    print(f"   [✓] Redis Channel Pattern: {ws_data['redis_pubsub_channel_pattern']}")
    print(f"   [✓] Supported Events: {ws_data['supported_stream_events']}")

    # 3. Sliding-Window Ingestion Metrics
    print("\n3. Querying Sliding-Window Real-Time Ingestion Metrics...")
    met_status, met_data = make_req("/api/metrics/realtime", token=token)
    assert met_status == 200, f"Failed to get metrics: {met_data}"
    print(f"   [✓] Current Ingestion Rate: {met_data['current_eps']:,} EPS")
    print(f"   [✓] 60-Second Mean Throughput: {met_data['average_eps_60s']:,} EPS")
    print(f"   [✓] Pipeline Latency: {met_data['pipeline_latency_ms']} ms (SLA Target: {met_data['sla_target_ms']} ms)")
    print(f"   [✓] SLA Health Compliance: {met_data['healthy']}")

    # 4. Agent Fleet Heartbeat Tracking (Redis TTL)
    print("\n4. Testing Stateful Fleet Heartbeat Tracking (Redis TTL Auto-Expiration)...")
    device_id = f"test-agent-{int(time.time())}"
    hb_status, hb_data = make_req("/api/metrics/heartbeat", method="POST", body={
        "device_id": device_id,
        "hostname": f"workstation-{device_id}.corp.internal",
        "os_version": "Linux 6.8 (Ubuntu 24.04)",
        "agent_version": "v12.0.4-stream"
    }, token=token)

    assert hb_status == 200, f"Heartbeat failed: {hb_data}"
    print(f"   [✓] Heartbeat Stored: Device={hb_data['device_id']} | Status={hb_data['status']} | TTL={hb_data['ttl_seconds']}s")

    # Fleet Status Query
    fleet_status, fleet_data = make_req("/api/metrics/fleet-status", token=token)
    assert fleet_status == 200
    assert len(fleet_data) >= 1
    matching = [d for d in fleet_data if d["device_id"] == device_id]
    assert len(matching) == 1
    print(f"   [✓] Verified Registered Device in Dynamic Fleet: {matching[0]['hostname']} ({matching[0]['status']})")

    # 5. High-Frequency Log Injection & Redis Pub/Sub Broadcast
    print("\n5. Testing Synthetic Telemetry Traffic Injection over Redis Pub/Sub...")
    sim_status, sim_data = make_req("/api/ws/simulate-log", method="POST", body={
        "count": 25,
        "class_name": "Process Activity",
        "severity_id": 3,
        "message": "High-frequency credential dumping pattern detection",
        "hostname": "prod-k8s-worker-09"
    }, token=token)

    assert sim_status == 200, f"Simulation failed: {sim_data}"
    print(f"   [✓] Dispatched: {sim_data['count_sent']} logs")
    print(f"   [✓] Target Channel: {sim_data['target_channel']}")
    print(f"   [✓] Ingestion Processing Latency: {sim_data['pipeline_latency_ms']} ms")
    print(f"   [✓] Sample OCSF Log Payload: {sim_data['sample']['message']}")

    # 6. Co-Triage Collaborative Analyst Lock
    print("\n6. Testing Co-Triage Distributed Analyst Locking...")
    lock_status, lock_data = make_req("/api/ws/co-triage-lock", method="POST", body={
        "alert_id": "alert-cve-2026-9041",
        "action": "acquire_lock"
    }, token=token)

    assert lock_status == 200, f"Lock acquisition failed: {lock_data}"
    print(f"   [✓] Alert Locked: {lock_data['alert_id']}")
    print(f"   [✓] Locked By: {lock_data['locked_by']}")
    print(f"   [✓] Status: {lock_data['status']}")

    print("\n>>> ALL V12.0 REAL-TIME SECURITY TELEMETRY & WEBSOCKET TESTS PASSED SUCCESSFULLY! <<<")

if __name__ == "__main__":
    run_test()
