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
    print("--- [V16.0 Autonomous Real-Time Tracking, URL Sandbox & Email Mesh Verification Suite] ---")

    # 1. Authenticate Analyst Session
    print("\n1. Authenticating test analyst session...")
    test_email = "v16_vanguard_analyst@soc.corp.internal"
    test_password = "VanguardPassword123!"

    make_req("/api/auth/register", method="POST", body={
        "org_name": "V16 Sovereign Vanguard Real-Time Mesh Org",
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

    # 2. Unified Real-Time Device Tracking & Geolocation Telemetry (OCSF Class 5001)
    print("\n2. Testing Real-Time Device Heartbeat & Geolocation Resolution (OCSF 5001)...")
    hb_status, hb_data = make_req("/api/v16/heartbeat", method="POST", body={
        "device_uid": "dev_laptop_v16_01",
        "hostname": "win-laptop-v16-01",
        "device_type": "laptop",
        "os_name": "Windows 11 Pro",
        "os_version": "10.0.22631",
        "public_ip": "185.190.140.2",  # London
        "cpu_load_percent": 24.2,
        "memory_used_mb": 6144.0,
        "active_tcp_sockets": 18
    }, token=token)

    assert hb_status == 200, f"Heartbeat failed: {hb_data}"
    print(f"   [+] Heartbeat Status: {hb_data['status']}")
    print(f"   [+] Geolocation: {hb_data['location']['city']}, {hb_data['location']['country']} (ISP: {hb_data['location']['isp']})")
    print(f"   [+] OCSF Class: {hb_data['ocsf_5001']['class_uid']} ({hb_data['ocsf_5001']['metadata']['product']['name']})")
    assert hb_data["location"]["city"] == "London"
    assert hb_data["ocsf_5001"]["class_uid"] == 5001

    # Fetch Geo-Fleet
    fleet_status, fleet_nodes = make_req("/api/v16/devices/geo-fleet", token=token)
    assert fleet_status == 200
    print(f"   [+] Active Fleet Nodes Count: {len(fleet_nodes)}")
    assert len(fleet_nodes) >= 1

    # 3. Impossible Travel Anomaly Evaluation
    print("\n3. Testing Impossible Travel Anomaly Evaluation & Simulator...")
    sim_status, sim_data = make_req("/api/v16/impossible-travel/simulate", method="POST", body={
        "device_uid": "dev_laptop_v16_01",
        "hostname": "win-laptop-v16-01",
        "origin_ip": "185.190.140.2",       # London
        "destination_ip": "203.0.113.88",     # Tokyo
        "time_delta_minutes": 10.0
    }, token=token)

    assert sim_status == 200, f"Simulation failed: {sim_data}"
    print(f"   [+] Impossible Travel Route: {sim_data['origin']} -> {sim_data['destination']}")
    print(f"   [+] Distance: {sim_data['distance_km']} km in {sim_data['time_delta_minutes']} mins")
    print(f"   [+] Calculated Velocity: {sim_data['velocity_kmh']} km/h (Anomaly Threshold: >800 km/h)")
    assert sim_data["velocity_kmh"] > 800.0

    # Retrieve Impossible Travel Alerts
    travel_alerts_status, travel_alerts = make_req("/api/v16/impossible-travel/alerts", token=token)
    assert travel_alerts_status == 200
    print(f"   [+] Recorded Impossible Travel Alerts: {len(travel_alerts)}")
    assert len(travel_alerts) >= 1

    # 4. Serverless Email Security Engine (OCSF Class 4009)
    print("\n4. Testing Serverless Email Security & Phishing/Spam Classifier (OCSF 4009)...")
    sample_phish_eml = """From: "CEO John Doe" <urgent-payroll@support-update-corp.xyz>
To: accounting@corp.internal
Subject: URGENT ACTION: Immediate Wire Transfer Confirmation
Date: Fri, 04 Sep 2026 01:00:00 +0000
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=support-update-corp.xyz; s=default; bh=invalid; b=bad
Content-Type: text/plain; charset="utf-8"

Dear Finance Team,
Please execute an urgent wire transfer of $85,000 for invoice attached.
Click here to verify password and confirm routing details immediately:
https://verify-office365-security.com/login.php
"""

    mail_status, mail_data = make_req("/api/v16/email/scan", method="POST", body={
        "raw_eml": sample_phish_eml,
        "sender_ip": "185.220.101.5"  # Suspicious IP
    }, token=token)

    assert mail_status == 200, f"Email scan failed: {mail_data}"
    print(f"   [+] Email Scan Status: {mail_data['status']}")
    print(f"   [+] SPF Status: {mail_data['spf_status']} | DKIM: {mail_data['dkim_status']} | DMARC: {mail_data['dmarc_status']}")
    print(f"   [+] Spam & Phishing Risk Score: {mail_data['risk_score']*100:.1f}% (Severity: {mail_data['severity']})")
    print(f"   [+] Phishing Detected: {mail_data['is_phishing_or_spam']}")
    print(f"   [+] URLs Extracted: {mail_data['urls_found']}")
    print(f"   [+] OCSF Class: {mail_data['ocsf_4009']['class_uid']} ({mail_data['ocsf_4009']['metadata']['product']['name']})")
    assert mail_data["is_phishing_or_spam"] is True
    assert mail_data["risk_score"] >= 0.50
    assert mail_data["ocsf_4009"]["class_uid"] == 4009

    # 5. Non-Destructive URL Safety & Remote Headless Sandbox (OCSF Class 4002)
    print("\n5. Testing 3-Tier URL Safety Inspection & Ephemeral Remote Sandbox (OCSF 4002)...")
    url_status, url_data = make_req("/api/v16/url/scan", method="POST", body={
        "url": "https://verify-office365-security.com/verify-login?auth=true",
        "force_sandbox": True
    }, token=token)

    assert url_status == 200, f"URL scan failed: {url_data}"
    print(f"   [+] URL Scan Status: {url_data['status']}")
    print(f"   [+] Inspection Tier: {url_data['tier_matched']}")
    print(f"   [+] Malicious Verdict: {url_data['is_malicious']} (Severity: {url_data['severity']})")
    print(f"   [+] Detection Rationale: {url_data['detection_reason']}")
    print(f"   [+] Ephemeral Sandbox Render Path: {url_data['sandbox_screenshot_path']}")
    print(f"   [+] OCSF Class: {url_data['ocsf_4002']['class_uid']} ({url_data['ocsf_4002']['metadata']['product']['name']})")
    assert url_data["is_malicious"] is True
    assert url_data["emulation_triggered"] is True
    assert url_data["ocsf_4002"]["class_uid"] == 4002

    # Verify SVG preview renderer endpoint
    render_url = f"{BASE_URL}{url_data['sandbox_screenshot_path']}"
    req = urllib.request.Request(render_url)
    with urllib.request.urlopen(req) as res:
        svg_content = res.read().decode("utf-8")
        assert "<svg" in svg_content
        assert "THREAT ANALYSER V16 REMOTE SANDBOX" in svg_content
        print(f"   [+] Safe Visual Snapshot Rendered ({len(svg_content)} bytes SVG delivered safely without client JS execution)")

    # 6. Aggregate Real-Time V16 Mesh Telemetry
    print("\n6. Validating Unified V16 Matrix Telemetry...")
    stats_status, stats_data = make_req("/api/v16/stats", token=token)
    assert stats_status == 200
    print(f"   [+] Mesh Integrity: {stats_data['mesh_integrity_score']}")
    print(f"   [+] Active Tracked Devices: {stats_data['active_devices_count']}")
    print(f"   [+] Impossible Travel Alerts: {stats_data['impossible_travel_alerts_count']}")
    print(f"   [+] Scanned Email Trajectory: {stats_data['emails_scanned_count']}")
    print(f"   [+] URL Inspections Conducted: {stats_data['urls_inspected_count']}")

    print("\n[OK] ALL VERSION 16.0 SOVEREIGN MESH DEFENSE TESTS PASSED PERFECTLY!")


if __name__ == "__main__":
    run_test()
