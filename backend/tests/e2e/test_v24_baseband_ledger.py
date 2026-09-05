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
    print("--- [V24.0 Baseband IMEI, Adaptive GPS & Cryptographic Merkle Ledger Verification Suite] ---\n")

    # 1. Login
    print("1. Authenticating SOC security analyst...")
    login_status, login_data = make_req("/api/auth/login", method="POST", body={
        "email": "analyst@acme.corp",
        "password": "SecurePassword123!"
    })
    assert login_status == 200, f"Login failed: {login_data}"
    token = login_data["access_token"]
    print(f"   [+] Authentication successful. Token: {token[:20]}...")

    # Ensure clean ledger state
    make_req("/api/v24/ledger/heal", method="POST", token=token)

    # 2. Check V24 Global Status
    print("\n2. Checking V24 Baseband & Merkle Ledger Engine Status...")

    status_code, status_data = make_req("/api/v24/status", token=token)
    assert status_code == 200, f"Status check failed: {status_data}"
    print(f"   [+] Engine Version: {status_data['version']}")
    print(f"   [+] System Integrity: {status_data['system_integrity']}")
    print(f"   [+] Baseband Modem Layer: {status_data['modem_layer']}")
    print(f"   [+] GPS Scheduler Engine: {status_data['gps_engine']}")
    print(f"   [+] Network Auditor Mode: {status_data['network_auditor_mode']}")
    print(f"   [+] Total Audit Blocks: {status_data['total_audit_blocks']}")

    # 3. Baseband Modem AT Command Probe (AT+CGSN)
    print("\n3. Probing Baseband Modem via AT+CGSN for IMEI Extraction...")
    probe_code, probe_data = make_req("/api/v24/baseband/modem/probe", method="POST", body={
        "serial_port": "/dev/smd0",
        "at_command": "AT+CGSN"
    }, token=token)
    assert probe_code == 200, f"Modem probe failed: {probe_data}"
    print(f"   [+] Valid Response: {probe_data['valid']}")
    print(f"   [+] Command Executed: {probe_data['command_executed']}")
    print(f"   [+] Extracted IMEI: {probe_data['imei']}")
    print(f"   [+] Status: {probe_data['status']}")
    print(f"   [+] Access Tech: {probe_data['access_technology']}")

    # 4. Cellular Network 3-Tower Timing Advance Multilateration
    print("\n4. Executing 3-Tower Cellular Multilateration (No-GPS Location Resolution)...")
    tri_code, tri_data = make_req("/api/v24/baseband/cellular/triangulate", method="POST", body={
        "imei": "864201047192834",
        "towers": [
            {"cell_id": 40121, "lac": 1204, "latitude": 37.7749, "longitude": -122.4194, "timing_advance": 4},
            {"cell_id": 40122, "lac": 1204, "latitude": 37.7812, "longitude": -122.4089, "timing_advance": 6},
            {"cell_id": 40123, "lac": 1204, "latitude": 37.7688, "longitude": -122.4255, "timing_advance": 5}
        ]
    }, token=token)
    assert tri_code == 200, f"Triangulation failed: {tri_data}"
    print(f"   [+] Resolved Latitude: {tri_data['latitude']:.6f}")
    print(f"   [+] Resolved Longitude: {tri_data['longitude']:.6f}")
    print(f"   [+] Accuracy Radius: ±{tri_data['accuracy_radius_meters']} meters")
    print(f"   [+] Method: {tri_data['triangulation_algorithm']}")

    # 5. GSMA/CEIR Stolen Device Blacklisting
    print("\n5. Publishing IMEI to GSMA Device Registry & CEIR Blacklist...")
    ceir_code, ceir_data = make_req("/api/v24/baseband/ceir/blacklist", method="POST", body={
        "imei": "864201047192834",
        "action": "BLACKLIST",
        "reason": "Enterprise Asset Stolen / Compromised"
    }, token=token)
    assert ceir_code == 200, f"CEIR Blacklist failed: {ceir_data}"
    print(f"   [+] CEIR Status: {ceir_data['ceir_list_status']}")
    print(f"   [+] Transceiver Blocked: {ceir_data['global_blocking_active']}")
    print(f"   [+] GSMA Status: {ceir_data['gsma_device_status']}")

    # 6. Adaptive GPS Scheduler Evaluation (Transit State)
    print("\n6. Evaluating Adaptive GPS Scheduler Dynamic Throttling Engine...")
    gps_code, gps_data = make_req("/api/v24/gps/evaluate", method="POST", body={
        "current_latitude": 37.7750,
        "current_longitude": -122.4190,
        "battery_percentage": 92.0,
        "geofence_center_lat": 37.7749,
        "geofence_center_lon": -122.4194,
        "geofence_radius_meters": 500.0,
        "simulated_speed_kmh": 40.0
    }, token=token)
    assert gps_code == 200, f"GPS evaluation failed: {gps_data}"
    print(f"   [+] Scheduler State: {gps_data['state']}")
    print(f"   [+] Next Scheduled Interval: {gps_data['next_scheduled_interval']}s")
    print(f"   [+] Speed: {gps_data['speed_kmh']} km/h | Geofence Dist: {gps_data['distance_to_center_m']}m")
    print(f"   [+] Outside Geofence: {gps_data['outside_geofence']}")

    # 7. Network Interface (IP/MAC) Scanning & OCSF Class 5001 Normalization
    print("\n7. Auditing Network Interface (IP/MAC) Configuration...")
    net_code, net_data = make_req("/api/v24/network/scan", method="POST", body={
        "interface_name": "wlan0",
        "ip_address": "192.168.1.144",
        "mac_address": "00:0a:95:9d:68:16",
        "gateway_ip": "192.168.1.1",
        "gateway_mac": "a0:04:cb:11:ff:dd"
    }, token=token)
    assert net_code == 200, f"Network scan failed: {net_data}"
    print(f"   [+] Audited Interface: {net_data['interface_name']}")
    print(f"   [+] IP / MAC: {net_data['ip_address']} / {net_data['mac_address']}")
    print(f"   [+] Gateway Router: {net_data['gateway_vendor']} ({net_data['gateway_mac']})")
    print(f"   [+] Status: {net_data['status']}")

    # 8. Simulate ARP Cache Poisoning / Gateway BSSID Redirection Attack
    print("\n8. Simulating ARP Cache Poisoning (Gateway BSSID Redirection Attack)...")
    arp_code, arp_data = make_req("/api/v24/network/simulate-arp-mitm", method="POST", body={
        "interface_name": "wlan0",
        "rogue_gateway_mac": "de:ad:be:ef:13:37"
    }, token=token)
    assert arp_code == 200, f"ARP MITM simulation failed: {arp_data}"
    assert arp_data["is_mitm_detected"] is True, "Failed to detect ARP MITM mutation"
    print(f"   [+] ARP MITM Detected: {arp_data['is_mitm_detected']}")
    print(f"   [+] Status: {arp_data['status']}")
    print(f"   [+] Threat Alert: {arp_data['mitm_threat_reason']}")

    # 9. Append Cryptographic Blocks to Neon Merkle Audit Ledger
    print("\n9. Appending Cryptographically Chained Blocks to Merkle Ledger...")
    actions = [
        "BASEBAND_IMEI_EXTRACTED",
        "CELLULAR_MULTILATERATION_RESOLVED",
        "GEOFENCE_TRANSIT_ENTERED",
        "ARP_GATEWAY_INTEGRITY_VERIFIED"
    ]
    for act in actions:
        app_code, app_data = make_req("/api/v24/ledger/append", method="POST", body={
            "action": act,
            "actor_email": "soc-analyst@enterprise.internal",
            "ip_address": "10.200.4.15",
            "mac_address": "00:1A:2B:3C:4D:5E"
        }, token=token)
        assert app_code == 200, f"Append to ledger failed: {app_data}"
        print(f"   [+] Chained Block #{app_data['sequence_id']}: {app_data['action']} | Hash: {app_data['current_ledger_hash'][:16]}...")

    # 10. Query Ledger Records
    print("\n10. Querying Multi-Tenant Merkle Audit Ledger Records...")
    rec_code, rec_data = make_req("/api/v24/ledger/records", params={"limit": 10}, token=token)
    assert rec_code == 200, f"Fetch records failed: {rec_data}"
    print(f"   [+] Total Ledger Blocks Retrieved: {len(rec_data)}")

    # 11. Run Recursive Merkle Integrity Verification Query
    print("\n11. Running Recursive Cryptographic Hash Chain Integrity Verification...")
    ver_code, ver_data = make_req("/api/v24/ledger/verify", token=token)
    assert ver_code == 200, f"Verification failed: {ver_data}"
    assert ver_data["is_valid"] is True, "Ledger integrity check failed on clean chain"
    print(f"   [+] Ledger Cryptographically Valid: {ver_data['is_valid']}")
    print(f"   [+] Chain Status: {ver_data['chain_status']}")
    print(f"   [+] Total Blocks Evaluated: {ver_data['total_records']}")

    # 12. Simulate Rogue DBA Tampering & Detect Immediate Cryptographic Break
    print("\n12. Simulating Rogue PostgreSQL DBA Tampering & Verifying Immediate Chain Break...")
    tamper_code, tamper_data = make_req("/api/v24/ledger/simulate-tamper", method="POST", body={
        "sequence_id": rec_data[0]["sequence_id"] if rec_data else 1
    }, token=token)
    assert tamper_code == 200, f"Tamper simulation failed: {tamper_data}"
    print(f"   [+] DBA Tamper Injected: Sequence #{tamper_data.get('tampered_sequence_id')} modified directly in DB")

    # Re-verify to prove the chain broke
    ver_break_code, ver_break_data = make_req("/api/v24/ledger/verify", token=token)
    assert ver_break_code == 200, f"Re-verification failed: {ver_break_data}"
    assert ver_break_data["is_valid"] is False, "Cryptographic verifier failed to detect rogue DBA tamper!"
    print(f"   [+] TAMPER DETECTED: is_valid = {ver_break_data['is_valid']}")
    print(f"   [+] Tampered Blocks Count: {ver_break_data['tampered_blocks_count']}")
    print(f"   [+] Chain Status: {ver_break_data['chain_status']}")

    # Clean up and heal ledger
    make_req("/api/v24/ledger/heal", method="POST", token=token)

    print("\n==========================================================================")
    print(">>> ALL V24.0 BASEBAND, GPS SCHEDULER & MERKLE LEDGER TESTS PASSED (100%) <<<")
    print("==========================================================================")


if __name__ == "__main__":
    try:
        run_test()
    except AssertionError as e:
        print(f"\n[!] TEST FAILED: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] UNEXPECTED ERROR: {e}")
        sys.exit(1)
