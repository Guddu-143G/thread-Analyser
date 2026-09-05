"""
Version 24: Real-Time Network Interface (MAC/IP) & ARP Poisoning Auditor.
Monitors local network adapter configurations, detects ARP cache poisoning / gateway BSSID mutation (MITM),
and formats network telemetry into standard OCSF Class 5001 (Device Inventory Info).
"""

import time
import re
from typing import Dict, Any, List, Optional

KNOWN_ROUTER_OUIS = {
    "a0:04:cb": "Netgear",
    "00:14:bf": "Cisco-Linksys",
    "f4:f2:6d": "TP-Link",
    "00:18:e7": "Aruba Networks",
    "28:6c:07": "Ubiquiti Networks"
}

class NetworkInterfaceAuditor:
    """
    Continuous network adapter auditor tracking IP/MAC mutations and flagging ARP poisoning threats.
    """
    def __init__(self):
        # Maps interface name (e.g., "wlan0") -> baseline gateway information
        self.gateway_baselines: Dict[str, Dict[str, str]] = {
            "wlan0": {
                "gateway_ip": "192.168.1.1",
                "gateway_mac": "a0:04:cb:11:ff:dd"
            },
            "eth0": {
                "gateway_ip": "10.0.0.1",
                "gateway_mac": "00:18:e7:22:aa:bb"
            }
        }
        self.audit_history: List[Dict[str, Any]] = []

    def audit_interface(
        self,
        interface_name: str,
        local_ip: str,
        mac_address: str,
        gateway_ip: str,
        gateway_mac: str,
        subnet_mask: str = "255.255.255.0",
        dns_servers: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Audits a network interface state. Checks for ARP poisoning / Gateway MAC alterations and MAC spoofing.
        """
        dns = dns_servers or ["1.1.1.1", "8.8.8.8"]
        normalized_mac = mac_address.lower().strip()
        normalized_gw_mac = gateway_mac.lower().strip()

        # 1. ARP Poisoning / Gateway Mismatch Check
        baseline = self.gateway_baselines.get(interface_name)
        is_mitm_detected = False
        mitm_reason = None

        if baseline:
            # If gateway IP is the same but gateway MAC altered unexpectedly -> ARP Poisoning MITM indicator
            if baseline["gateway_ip"] == gateway_ip and baseline["gateway_mac"] != normalized_gw_mac:
                is_mitm_detected = True
                mitm_reason = (
                    f"ARP CACHE POISONING DETECTED: Gateway {gateway_ip} MAC mutated from "
                    f"{baseline['gateway_mac']} to rogue {normalized_gw_mac}."
                )
        else:
            # Seed baseline on first discovery
            self.gateway_baselines[interface_name] = {
                "gateway_ip": gateway_ip,
                "gateway_mac": normalized_gw_mac
            }

        # 2. MAC Spoofing / Randomized MAC check (Locally administered bit check: 2nd least significant bit of 1st byte)
        is_randomized_mac = False
        try:
            first_byte = int(normalized_mac.split(":")[0], 16)
            is_randomized_mac = bool(first_byte & 0b00000010)
        except Exception:
            pass

        vendor_prefix = ":".join(normalized_gw_mac.split(":")[:3])
        gateway_vendor = KNOWN_ROUTER_OUIS.get(vendor_prefix, "Generic IEEE Router")

        result = {
            "interface_name": interface_name,
            "ip_address": local_ip,
            "mac_address": normalized_mac,
            "subnet_mask": subnet_mask,
            "gateway_ip": gateway_ip,
            "gateway_mac": normalized_gw_mac,
            "gateway_vendor": gateway_vendor,
            "dns_servers": dns,
            "is_mitm_detected": is_mitm_detected,
            "mitm_threat_reason": mitm_reason,
            "is_randomized_mac": is_randomized_mac,
            "baseline_gateway_mac": baseline["gateway_mac"] if baseline else normalized_gw_mac,
            "status": "CRITICAL_MITM_ALERT" if is_mitm_detected else "NORMAL_NETWORK_PROFILE",
            "timestamp": int(time.time())
        }
        self.audit_history.append(result)
        return result

    def simulate_arp_mitm_attack(
        self,
        interface_name: str = "wlan0",
        rogue_gateway_mac: str = "de:ad:be:ef:13:37"
    ) -> Dict[str, Any]:
        """
        Simulates an active ARP spoofing injection by forcing an unapproved gateway MAC mutation.
        """
        baseline = self.gateway_baselines.get(interface_name, {
            "gateway_ip": "192.168.1.1",
            "gateway_mac": "a0:04:cb:11:ff:dd"
        })

        return self.audit_interface(
            interface_name=interface_name,
            local_ip="192.168.1.144",
            mac_address="00:0a:95:9d:68:16",
            gateway_ip=baseline["gateway_ip"],
            gateway_mac=rogue_gateway_mac,
            subnet_mask="255.255.255.0",
            dns_servers=["1.1.1.1", "8.8.8.8"]
        )

    @classmethod
    def build_ocsf_5001_inventory_event(
        cls,
        tenant_uid: str,
        device_uid: str,
        hostname: str,
        audit_result: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Formats network interface state into OCSF Class 5001 (Device Inventory Info)."""
        return {
            "metadata": {
                "version": "1.2.0",
                "class_uid": 5001,
                "class_name": "DEVICE_INVENTORY_INFO"
            },
            "category_uid": 5,
            "severity_id": 4 if audit_result.get("is_mitm_detected") else 1,
            "time": int(time.time() * 1000),
            "tenant_uid": tenant_uid,
            "device": {
                "uid": device_uid,
                "hostname": hostname
            },
            "network_interfaces": [
                {
                    "name": audit_result.get("interface_name"),
                    "mac": audit_result.get("mac_address"),
                    "ip": audit_result.get("ip_address"),
                    "subnet_mask": audit_result.get("subnet_mask"),
                    "gateway_ip": audit_result.get("gateway_ip"),
                    "gateway_mac": audit_result.get("gateway_mac"),
                    "dns_servers": audit_result.get("dns_servers", [])
                }
            ],
            "security_alerts": [
                audit_result.get("mitm_threat_reason")
            ] if audit_result.get("is_mitm_detected") else []
        }
