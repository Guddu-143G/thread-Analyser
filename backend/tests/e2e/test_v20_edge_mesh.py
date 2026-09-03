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
    print("--- [V20.0 Dynamic Edge Remediation & Adaptive GPS Mesh Verification Suite] ---\n")

    # 1. Login
    print("1. Authenticating test analyst session...")
    login_status, login_data = make_req("/api/auth/login", method="POST", body={
        "email": "analyst@acme.corp",
        "password": "SecurePassword123!"
    })
    assert login_status == 200, f"Login failed: {login_data}"
    token = login_data["access_token"]
    print(f"   [+] Authentication successful. Token: {token[:20]}...")

    # 2. Check Edge Mesh Status
    print("\n2. Checking Edge Remediation & Spatial Mesh Status...")
    status_code, status_data = make_req("/api/v20/edge/status", token=token)
    assert status_code == 200, f"Status failed: {status_data}"
    print(f"   [+] Mesh Status: {status_data['status']}")
    print(f"   [+] Adaptive GPS Engine: {status_data['adaptive_gps_engine_version']}")
    print(f"   [+] OCSF Mapping: {status_data['ocsf_class_mapping']}")
    print(f"   [+] PTY Multiplexer: {status_data['pty_multiplexer_version']}")
    print(f"   [+] System Integrity: {status_data['system_integrity']}")

    # 3. Setup test endpoint device
    print("\n3. Enrolling and verifying test endpoint for geospatial tracking...")
    dev_uid = f"v20-edge-node-{uuid.uuid4().hex[:6]}"
    tel_status, tel_data = make_req("/api/v17/devices/telemetry", method="POST", body={
        "device_id": dev_uid,
        "hostname": f"{dev_uid}.edge.corp",
        "public_ip": "198.51.100.88",
        "latitude": 37.7749,
        "longitude": -122.4194,
        "location_desc": "San Francisco Headquarters",
        "cpu_usage": 18.0,
        "memory_usage": 32.0
    }, token=token)
    assert tel_status == 200
    print(f"   [+] Edge Node Active: {dev_uid}")

    # 4. Configure Geofence Boundary
    print("\n4. Configuring Geofence Boundary (Center: San Francisco, Radius: 20km)...")
    geo_status, geo_data = make_req("/api/v20/edge/gps/geofence", method="POST", body={
        "device_id": dev_uid,
        "center_latitude": 37.7749,
        "center_longitude": -122.4194,
        "radius_meters": 20000.0
    }, token=token)
    assert geo_status == 200, f"Geofence config failed: {geo_data}"
    print(f"   [+] Geofence Active: {geo_data['radius_meters']}m around ({geo_data['center_latitude']}, {geo_data['center_longitude']})")

    # 5. Ingest Active Transit GPS Telemetry
    print("\n5. Ingesting GPS Telemetry in Active Transit (speed=12.5 m/s)...")
    gps1_status, gps1_data = make_req("/api/v20/edge/gps/ingest", method="POST", body={
        "device_id": dev_uid,
        "latitude": 37.7833,
        "longitude": -122.4167,
        "speed_mps": 12.5,
        "battery_level": 85,
        "power_source": "BATTERY"
    }, token=token)
    assert gps1_status == 200, f"GPS ingest failed: {gps1_data}"
    print(f"   [+] Tracking State: {gps1_data['tracking_state']}")
    print(f"   [+] Polling Interval: {gps1_data['polling_interval_seconds']}s")
    assert gps1_data["tracking_state"] == "ACTIVE_TRANSIT"
    assert gps1_data["polling_interval_seconds"] == 10

    # 6. Ingest Low Battery GPS Telemetry
    print("\n6. Ingesting GPS Telemetry under Critical Low Battery (15% without AC)...")
    gps2_status, gps2_data = make_req("/api/v20/edge/gps/ingest", method="POST", body={
        "device_id": dev_uid,
        "latitude": 37.7850,
        "longitude": -122.4100,
        "speed_mps": 1.2,
        "battery_level": 15,
        "power_source": "BATTERY"
    }, token=token)
    assert gps2_status == 200
    print(f"   [+] Tracking State: {gps2_data['tracking_state']}")
    print(f"   [+] Throttled Interval: {gps2_data['polling_interval_seconds']}s (30 mins)")
    assert gps2_data["tracking_state"] == "LOW_POWER"
    assert gps2_data["polling_interval_seconds"] == 1800

    # 7. Ingest Geofence Boundary Breach
    print("\n7. Ingesting GPS Telemetry during Geofence Boundary Breach (San Jose, 67km away)...")
    gps3_status, gps3_data = make_req("/api/v20/edge/gps/ingest", method="POST", body={
        "device_id": dev_uid,
        "latitude": 37.3382,
        "longitude": -121.8863,
        "speed_mps": 0.0,
        "battery_level": 15,
        "power_source": "BATTERY"
    }, token=token)
    assert gps3_status == 200
    print(f"   [+] Boundary Alert: {gps3_data['tracking_state']}")
    print(f"   [+] Aggressive Fallback Interval: {gps3_data['polling_interval_seconds']}s")
    print(f"   [+] OCSF Class: {gps3_data['ocsf_class_uid']} (Severity: {gps3_data['ocsf_severity']})")
    assert gps3_data["tracking_state"] == "GEOFENCE_BREACH"
    assert gps3_data["polling_interval_seconds"] == 5
    assert gps3_data["ocsf_severity"] == 3

    # 8. Query Location History & Spatial Trail
    print("\n8. Querying Historical Geographic Breadcrumb Trail...")
    hist_status, hist_data = make_req(f"/api/v20/edge/gps/{dev_uid}/history", token=token)
    assert hist_status == 200
    assert len(hist_data) >= 3
    print(f"   [+] Retrieved Geographic Logs: {len(hist_data)} entries")
    print(f"   [+] Latest Log State: {hist_data[0]['tracking_state']} ({hist_data[0]['latitude']}, {hist_data[0]['longitude']})")

    # 9. Test PTY Pseudoterminal Stream Logging
    print("\n9. Recording PTY Command Execution Sub-Session Stream...")
    sess_status, sess_data = make_req("/api/v18/live/sessions/request", method="POST", body={
        "device_id": dev_uid
    }, token=token)
    assert sess_status == 200, f"Session request failed: {sess_data}"
    test_session_id = sess_data["session_id"]
    print(f"   [+] Attached Live Response Session: {test_session_id}")

    stream_status, stream_data = make_req("/api/v20/edge/terminal/streams", method="POST", body={
        "session_id": test_session_id,
        "command_input": "systemctl status threat-agent --no-pager",
        "command_output_summary": "● threat-agent.service - Active (running) since Thu 2026-09-04",
        "exit_code": 0
    }, token=token)
    assert stream_status == 200, f"Stream recording failed: {stream_data}"
    print(f"   [+] Stream Command ID: {stream_data['command_id']}")
    print(f"   [+] Command: {stream_data['command_input']}")

    # 10. Query Terminal Stream
    stream_list_status, stream_list = make_req(f"/api/v20/edge/terminal/streams/{test_session_id}", token=token)
    assert stream_list_status == 200
    assert len(stream_list) >= 1
    print(f"   [+] Retrieved PTY Streams for Session: {len(stream_list)} commands")
    print(f"   [+] Recorded Command: {stream_list[0]['command_input']} (Exit Code: {stream_list[0]['exit_code']})")

    print("\n[OK] ALL VERSION 20.0 DYNAMIC EDGE REMEDIATION & ADAPTIVE GPS MESH TESTS PASSED PERFECTLY!")

if __name__ == "__main__":
    run_test()
