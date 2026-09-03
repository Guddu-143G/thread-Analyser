import math
import time
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Tuple

class DeviceTrackingMonitor:
    """
    V16.0 Unified Real-Time Device Tracking & Geolocation Telemetry Engine (OCSF Class 5001 / 4001).
    Processes live heartbeat state vectors, maps network geometry, and computes
    Haversine impossible travel anomaly metrics across successive timestamps.
    """

    # Earth radius in kilometers
    EARTH_RADIUS_KM = 6371.0
    IMPOSSIBLE_SPEED_KMH_THRESHOLD = 800.0  # Commercial flight speed ceiling threshold

    # Well-known enterprise geolocation hubs for IP simulation/mapping
    KNOWN_GEO_HUBS = {
        "185.190.140.2": {"city": "London", "country": "United Kingdom", "lat": 51.5074, "lon": -0.1278, "isp": "Enterprise Telecom UK", "asn": 12345},
        "198.51.100.54": {"city": "New York", "country": "United States", "lat": 40.7128, "lon": -74.0060, "isp": "US East Fiber Core", "asn": 34567},
        "203.0.113.88": {"city": "Tokyo", "country": "Japan", "lat": 35.6762, "lon": 139.6503, "isp": "Nippon Global Transit", "asn": 45678},
        "194.67.210.15": {"city": "Frankfurt", "country": "Germany", "lat": 50.1109, "lon": 8.6821, "isp": "DE-CIX Backbone", "asn": 56789},
        "139.130.4.5": {"city": "Sydney", "country": "Australia", "lat": -33.8688, "lon": 151.2093, "isp": "Telstra Global", "asn": 67890},
        "104.244.42.1": {"city": "San Francisco", "country": "United States", "lat": 37.7749, "lon": -122.4194, "isp": "Pacific Gateway", "asn": 78901},
        "185.220.101.5": {"city": "Amsterdam", "country": "Netherlands", "lat": 52.3676, "lon": 4.9041, "isp": "Tor Exit Node Network", "asn": 99999},
    }

    def __init__(self):
        pass

    @staticmethod
    def haversine_distance(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
        """
        Calculates Great Circle distance between two points on the Earth surface in kilometers.
        """
        d_lat = math.radians(lat2 - lat1)
        d_lon = math.radians(lon2 - lon1)
        a = (
            math.sin(d_lat / 2) ** 2
            + math.cos(math.radians(lat1))
            * math.cos(math.radians(lat2))
            * math.sin(d_lon / 2) ** 2
        )
        c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
        return DeviceTrackingMonitor.EARTH_RADIUS_KM * c

    def resolve_geolocation(self, ip: str, provided_lat: Optional[float] = None, provided_lon: Optional[float] = None) -> Dict[str, Any]:
        """
        Resolves IP to geographic coordinates, ISP, and ASN.
        Grounds known IP addresses to precise nodes, or derives realistic coordinates.
        """
        if ip in self.KNOWN_GEO_HUBS:
            info = self.KNOWN_GEO_HUBS[ip].copy()
            if provided_lat is not None and provided_lon is not None:
                info["lat"] = provided_lat
                info["lon"] = provided_lon
            return info

        if provided_lat is not None and provided_lon is not None:
            return {
                "city": "Remote Node",
                "country": "Corporate Grid",
                "lat": provided_lat,
                "lon": provided_lon,
                "isp": "Enterprise Mesh ISP",
                "asn": 65001,
            }

        # Deterministic hash fallback for arbitrary IPs
        ip_hash = hash(ip) % 1000
        lat = 30.0 + (ip_hash % 30) * (1 if ip_hash % 2 == 0 else -1)
        lon = -100.0 + (ip_hash % 150)
        return {
            "city": f"Edge-Zone-{abs(ip_hash) % 50}",
            "country": "Enterprise VPN",
            "lat": round(lat, 4),
            "lon": round(lon, 4),
            "isp": "Secure Cloud Transit",
            "asn": 10000 + (abs(ip_hash) % 50000),
        }

    def evaluate_impossible_travel(
        self,
        prev_lat: float,
        prev_lon: float,
        prev_time: datetime,
        curr_lat: float,
        curr_lon: float,
        curr_time: datetime,
    ) -> Tuple[bool, float, float, float]:
        """
        Evaluates whether movement between two check-ins violates physical travel constraints.
        Returns: (is_impossible, distance_km, time_diff_minutes, velocity_kmh)
        """
        distance_km = self.haversine_distance(prev_lat, prev_lon, curr_lat, curr_lon)
        time_diff_sec = abs((curr_time - prev_time).total_seconds())
        time_diff_minutes = max(time_diff_sec / 60.0, 0.01)
        time_diff_hours = time_diff_sec / 3600.0

        if time_diff_hours <= 0:
            velocity_kmh = distance_km * 3600.0  # instant jump
        else:
            velocity_kmh = distance_km / time_diff_hours

        # Impossible if distance > 100km and velocity > threshold
        is_impossible = (distance_km > 100.0) and (velocity_kmh > self.IMPOSSIBLE_SPEED_KMH_THRESHOLD)
        return is_impossible, round(distance_km, 2), round(time_diff_minutes, 2), round(velocity_kmh, 2)

    def normalize_to_ocsf_5001(
        self,
        tenant_id: str,
        device_uid: str,
        hostname: str,
        device_type: str,
        os_name: str,
        os_version: str,
        public_ip: str,
        geo_info: Dict[str, Any],
        cpu_load: float,
        memory_mb: float,
    ) -> Dict[str, Any]:
        """
        Normalizes telemetry state vector to OCSF Class 5001 (Device Inventory Info).
        """
        return {
            "metadata": {
                "version": "1.2.0",
                "product": {
                    "vendor": "ThreatAnalyser",
                    "name": "CollectorAgent",
                    "version": "16.0.0",
                },
                "tenant_uid": tenant_id,
                "class_uid": 5001,
            },
            "category_uid": 5,  # Discovery
            "class_uid": 5001,  # Device Inventory Info
            "severity_id": 1,   # Informational
            "time": int(time.time() * 1000),
            "device": {
                "uid": device_uid,
                "hostname": hostname,
                "type_id": 3 if "laptop" in device_type.lower() else (1 if "server" in device_type.lower() else 2),
                "os": {
                    "name": os_name,
                    "version": os_version,
                },
                "ip": public_ip,
                "metrics": {
                    "cpu_load_percent": cpu_load,
                    "memory_used_mb": memory_mb,
                }
            },
            "location": {
                "desc": f"{geo_info.get('city', 'Unknown')}, {geo_info.get('country', 'Unknown')}",
                "latitude": geo_info.get("lat", 0.0),
                "longitude": geo_info.get("lon", 0.0),
                "asn": geo_info.get("asn", 0),
                "isp": geo_info.get("isp", "Unknown ISP"),
            },
            "status_id": 1,  # Active
        }


global_device_monitor = DeviceTrackingMonitor()
