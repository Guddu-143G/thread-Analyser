"""
Unit Test Suite for Version 24 Modules:
- Physical Baseband Modem AT Parser & 3-Tower Multilateration (modem_interface.py)
- Adaptive GPS Scheduler Engine (gps_scheduler.py)
- Real-Time Network Interface & ARP Auditor (network_auditor.py)
- Neon Merkle Cryptographic Audit Ledger (audit_ledger_service.py)
"""
import math
import sys
import os

backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from app.forensic.modem_interface import BasebandModemInterface
from app.agent.gps_scheduler import AdaptiveGPSEngine
from app.detection.network_auditor import NetworkInterfaceAuditor
from app.services.audit_ledger_service import NeonAuditLedgerManager

# -------------------------------------------------------------
# 1. Baseband Modem & 3-Tower Multilateration Tests
# -------------------------------------------------------------
def test_modem_at_cgsn_parsing():
    raw_response = "+CGSN: 864201047192834\r\nOK"
    res = BasebandModemInterface.parse_at_cgsn_response(raw_response)
    assert res["valid"] is True
    assert res["imei"] == "864201047192834"
    assert res["tac"] == "86420104"
    assert res["status"] == "SILICON_IMEI_EXTRACTED"

def test_modem_at_creg_parsing():
    raw_response = '+CREG: 2,1,"1204","40121",7\r\nOK'
    res = BasebandModemInterface.parse_at_creg_response(raw_response)
    assert res["valid"] is True
    assert res["stat_code"] == 1
    assert res["is_registered"] is True
    assert res["access_technology"] == "E-UTRAN (LTE 4G)"

def test_modem_at_cops_parsing():
    raw_response = '+COPS: 0,0,"T-Mobile USA",7\r\nOK'
    res = BasebandModemInterface.parse_at_cops_response(raw_response)
    assert res["valid"] is True
    assert res["operator_name"] == "T-Mobile USA"
    assert res["plmn_mcc_mnc"] == "310-260"

def test_3_tower_multilateration_accuracy():
    towers = [
        {"cid": "40121", "lac": "1204", "tower_lat": 37.7749, "tower_lon": -122.4194, "timing_advance": 4},
        {"cid": "40122", "lac": "1204", "tower_lat": 37.7812, "tower_lon": -122.4089, "timing_advance": 6},
        {"cid": "40123", "lac": "1204", "tower_lat": 37.7688, "tower_lon": -122.4255, "timing_advance": 5},
    ]
    result = BasebandModemInterface.calculate_multilateration(towers)
    assert result["towers_used_count"] == 3
    assert result["accuracy_radius_meters"] <= 120.0
    assert 37.76 < result["latitude"] < 37.79
    assert -122.43 < result["longitude"] < -122.40
    assert result["triangulation_algorithm"] == "U_TDOA_WEIGHTED_CENTROID_MULTILATERATION"

def test_gsma_ceir_blacklist_workflow():
    imei = "864201047192834"
    
    # Blacklist device
    res_block = BasebandModemInterface.evaluate_gsma_ceir_status(imei, is_stolen=True)
    assert res_block["global_blocking_active"] is True
    assert res_block["ceir_list_status"] == "BLACKLISTED"
    
    # Whitelist device
    res_clean = BasebandModemInterface.evaluate_gsma_ceir_status(imei, is_stolen=False)
    assert res_clean["global_blocking_active"] is False
    assert res_clean["ceir_list_status"] == "WHITELISTED"

def test_carrier_hlr_vlr_query():
    imei = "864201047192834"
    hlr = BasebandModemInterface.query_carrier_hlr_vlr(imei, "Jio 4G")
    assert hlr["imei"] == imei
    assert hlr["carrier"] == "Jio 4G"
    assert hlr["hlr_status"] == "ACTIVE_SUBSCRIPTION"
    assert "last_tower_registered" in hlr

def test_ocsf_baseband_event_builder():
    event = BasebandModemInterface.build_ocsf_baseband_event(
        tenant_uid="org-v24-test",
        device_uid="dev-phone-01",
        imei="864201047192834",
        triangulation={"latitude": 37.775, "longitude": -122.419, "accuracy_radius_meters": 48.0, "triangulation_algorithm": "U_TDOA"},
        carrier_info={"operator_name": "T-Mobile USA"}
    )
    assert event["metadata"]["class_uid"] == 5020
    assert event["metadata"]["class_name"] == "CELLULAR_BASEBAND_TELEMETRY"
    assert event["device"]["imei"] == "864201047192834"

# -------------------------------------------------------------
# 2. Adaptive GPS Scheduler Tests
# -------------------------------------------------------------
def test_haversine_distance_calculation():
    engine = AdaptiveGPSEngine(geofence_center=(37.7749, -122.4194), geofence_radius_meters=500.0)
    dist = engine.haversine_distance(37.7749, -122.4194, 37.7755, -122.4188)
    assert 50.0 < dist < 120.0

def test_gps_scheduler_stationary_state():
    engine = AdaptiveGPSEngine(geofence_center=(37.7749, -122.4194), geofence_radius_meters=1000.0)
    interval, metrics = engine.update_location_and_get_interval(
        current_lat=37.7750,
        current_lon=-122.4193,
        battery_pct=90.0,
        simulated_speed_kmh=1.0
    )
    assert metrics["state"] == "STATIONARY"
    assert interval == 300
    assert metrics["outside_geofence"] is False

def test_gps_scheduler_transit_state():
    engine = AdaptiveGPSEngine(geofence_center=(37.7749, -122.4194), geofence_radius_meters=5000.0)
    interval, metrics = engine.update_location_and_get_interval(
        current_lat=37.7750,
        current_lon=-122.4193,
        battery_pct=85.0,
        simulated_speed_kmh=45.0
    )
    assert metrics["state"] == "TRANSIT"
    assert interval == 15

def test_gps_scheduler_outside_geofence():
    engine = AdaptiveGPSEngine(geofence_center=(37.7749, -122.4194), geofence_radius_meters=200.0)
    interval, metrics = engine.update_location_and_get_interval(
        current_lat=37.8100,
        current_lon=-122.4100,
        battery_pct=80.0,
        simulated_speed_kmh=15.0
    )
    assert metrics["state"] == "OUTSIDE_GEOFENCE"
    assert interval == 10
    assert metrics["outside_geofence"] is True

def test_gps_scheduler_critical_battery_override():
    engine = AdaptiveGPSEngine(geofence_center=(37.7749, -122.4194), geofence_radius_meters=1000.0)
    interval, metrics = engine.update_location_and_get_interval(
        current_lat=37.7750,
        current_lon=-122.4193,
        battery_pct=15.0,
        simulated_speed_kmh=5.0
    )
    assert metrics["state"] == "CRITICAL_POWER"
    assert interval == 1800

# -------------------------------------------------------------
# 3. Network Interface & ARP MITM Detection Tests
# -------------------------------------------------------------
def test_network_interface_scan():
    auditor = NetworkInterfaceAuditor()
    audit = auditor.audit_interface(
        interface_name="wlan0",
        local_ip="192.168.1.144",
        mac_address="00:0a:95:9d:68:16",
        gateway_ip="192.168.1.1",
        gateway_mac="a0:04:cb:11:ff:dd"
    )
    assert audit["is_mitm_detected"] is False
    assert audit["gateway_vendor"] == "Netgear"
    assert audit["status"] == "NORMAL_NETWORK_PROFILE"

    ocsf_event = NetworkInterfaceAuditor.build_ocsf_5001_inventory_event(
        tenant_uid="org-v24-test",
        device_uid="dev-station-01",
        hostname="secops-laptop",
        audit_result=audit
    )
    assert ocsf_event["metadata"]["class_uid"] == 5001
    assert ocsf_event["metadata"]["class_name"] == "DEVICE_INVENTORY_INFO"

def test_arp_mitm_gateway_mutation_detection():
    auditor = NetworkInterfaceAuditor()
    # Baseline
    auditor.audit_interface("wlan0", "192.168.1.144", "00:0a:95:9d:68:16", "192.168.1.1", "a0:04:cb:11:ff:dd")
    
    # Mutate gateway MAC (BSSID) on static IP
    detection = auditor.simulate_arp_mitm_attack(
        interface_name="wlan0",
        rogue_gateway_mac="de:ad:be:ef:13:37"
    )
    assert detection["is_mitm_detected"] is True
    assert detection["status"] == "CRITICAL_MITM_ALERT"
    assert "ARP CACHE POISONING DETECTED" in detection["mitm_threat_reason"]

# -------------------------------------------------------------
# 4. Neon Merkle Cryptographic Audit Ledger Tests
# -------------------------------------------------------------
def test_merkle_payload_hash_calculation():
    manager = NeonAuditLedgerManager()
    h = manager.calculate_payload_hash(
        action="DEVICE_ISOLATION_TRIGGERED",
        actor_email="admin@test.com",
        ip_address="10.0.0.1",
        mac_address="00:11:22:33:44:55"
    )
    assert len(h) == 64
    h2 = manager.calculate_payload_hash(
        action="DEVICE_ISOLATION_TRIGGERED",
        actor_email="admin@test.com",
        ip_address="10.0.0.1",
        mac_address="00:11:22:33:44:55"
    )
    assert h == h2

def test_merkle_ledger_block_hash_chain():
    manager = NeonAuditLedgerManager()
    prev_hash = "0000000000000000000000000000000000000000000000000000000000000000"
    payload_hash = manager.calculate_payload_hash("ACTION_1", "user@test.com", "1.1.1.1", "00:00:00:00:00:01")
    block_1_hash = manager.calculate_block_hash(payload_hash, prev_hash)
    assert len(block_1_hash) == 64

    payload_2 = manager.calculate_payload_hash("ACTION_2", "user@test.com", "1.1.1.1", "00:00:00:00:00:01")
    block_2_hash = manager.calculate_block_hash(payload_2, block_1_hash)
    assert block_2_hash != block_1_hash

if __name__ == "__main__":
    tests = [
        test_modem_at_cgsn_parsing,
        test_modem_at_creg_parsing,
        test_modem_at_cops_parsing,
        test_3_tower_multilateration_accuracy,
        test_gsma_ceir_blacklist_workflow,
        test_carrier_hlr_vlr_query,
        test_ocsf_baseband_event_builder,
        test_haversine_distance_calculation,
        test_gps_scheduler_stationary_state,
        test_gps_scheduler_transit_state,
        test_gps_scheduler_outside_geofence,
        test_gps_scheduler_critical_battery_override,
        test_network_interface_scan,
        test_arp_mitm_gateway_mutation_detection,
        test_merkle_payload_hash_calculation,
        test_merkle_ledger_block_hash_chain,
    ]
    for t in tests:
        t()
        print(f"  [+] {t.__name__} passed")
    print("\n[OK] All V24 Unit Tests Passed (100%)")
