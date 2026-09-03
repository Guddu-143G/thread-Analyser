import math
import datetime
from typing import Dict, Any, Tuple, Optional
from sqlalchemy.orm import Session
from app.models.models import Device, DeviceHeartbeat

class RealTimeDeviceTracker:
    """
    Ingests and tracks client agent state, computes impossible travel metrics,
    and logs detailed heartbeat variables directly to Neon serverless database.
    """
    def __init__(self, db: Session, org_id: str):
        self.db = db
        self.org_id = org_id

    @staticmethod
    def calculate_haversine_distance(coord1: Tuple[float, float], coord2: Tuple[float, float]) -> float:
        """Computes the great-circle distance between two points in kilometers."""
        lat1, lon1 = coord1
        lat2, lon2 = coord2
        
        r = 6371.0 # Earth's radius in km
        d_lat = math.radians(lat2 - lat1)
        d_lon = math.radians(lon2 - lon1)
        
        a = (math.sin(d_lat / 2) ** 2 + 
             math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) * math.sin(d_lon / 2) ** 2)
        c = 2 * math.asin(math.sqrt(max(0.0, min(1.0, a))))
        return r * c

    def update_device_telemetry(self, device_uid: str, telemetry: Dict[str, Any]) -> Dict[str, Any]:
        """Processes a device heartbeat vector, checks physical travel limits, and saves to Neon."""
        device = self.db.query(Device).filter(Device.id == device_uid, Device.org_id == self.org_id).first()
        if not device:
            # Check by hostname or name if UID not found
            device = self.db.query(Device).filter(Device.name == device_uid, Device.org_id == self.org_id).first()
            if not device:
                # Auto-enroll device in current tenant organization
                device = Device(
                    id=device_uid,
                    org_id=self.org_id,
                    name=telemetry.get("hostname", f"node-{device_uid[:8]}"),
                    hostname=telemetry.get("hostname", f"node-{device_uid[:8]}.corp.internal"),
                    agent_version=telemetry.get("agent_version", "17.0.0"),
                    os_name=telemetry.get("os_name", "Linux"),
                    os_version=telemetry.get("os_version", "6.5.0"),
                    api_key_hash="v17_auto_enrolled_hash",
                    platform=telemetry.get("os_name", "linux")
                )
                self.db.add(device)
                self.db.flush()

        incoming_ip = telemetry.get("public_ip", "185.190.140.2")
        incoming_lat = float(telemetry.get("latitude", 51.5074)) # default London
        incoming_lon = float(telemetry.get("longitude", -0.1278))
        location_desc = telemetry.get("location_desc", "London, United Kingdom")

        impossible_travel = False
        calculated_speed = 0.0
        distance_km = 0.0
        time_now = datetime.datetime.utcnow()

        # Evaluate impossible travel if last location was valid
        if device.last_latitude is not None and device.last_longitude is not None and device.last_seen is not None:
            last_coords = (float(device.last_latitude), float(device.last_longitude))
            new_coords = (incoming_lat, incoming_lon)
            
            distance_km = self.calculate_haversine_distance(last_coords, new_coords)
            time_delta_hours = max((time_now - device.last_seen).total_seconds() / 3600.0, 0.0001)

            calculated_speed = distance_km / time_delta_hours
            # Alert if traveling speed exceeds 950 km/h over significant distance (> 50 km)
            if distance_km > 50.0 and calculated_speed > 950.0:
                impossible_travel = True

        # Update device table
        device.public_ip = incoming_ip
        device.last_latitude = incoming_lat
        device.last_longitude = incoming_lon
        device.last_location_desc = location_desc
        device.last_seen = time_now
        device.status = "compromised" if impossible_travel else "active"

        # Write detailed heartbeat log row to Neon database
        heartbeat = DeviceHeartbeat(
            device_id=device.id,
            org_id=self.org_id,
            timestamp=time_now,
            cpu_usage_pct=float(telemetry.get("cpu_usage", 5.0)),
            memory_usage_pct=float(telemetry.get("memory_usage", 22.0)),
            disk_usage_pct=float(telemetry.get("disk_usage", 45.0)),
            battery_pct=float(telemetry.get("battery", 100.0)),
            active_process_count=int(telemetry.get("processes", 120)),
            listening_port_count=int(telemetry.get("ports", 15)),
            reported_ip=incoming_ip,
            impossible_travel_triggered=impossible_travel
        )

        self.db.add(heartbeat)
        self.db.commit()
        self.db.refresh(heartbeat)

        return {
            "device_id": str(device.id),
            "status": device.status,
            "impossible_travel": impossible_travel,
            "calculated_speed_kmh": round(calculated_speed, 2),
            "distance_km": round(distance_km, 2),
            "heartbeat_id": str(heartbeat.id),
            "public_ip": incoming_ip,
            "location": location_desc,
            "battery_pct": heartbeat.battery_pct,
            "cpu_usage_pct": heartbeat.cpu_usage_pct,
            "memory_usage_pct": heartbeat.memory_usage_pct,
            "disk_usage_pct": heartbeat.disk_usage_pct,
            "active_process_count": heartbeat.active_process_count,
            "listening_port_count": heartbeat.listening_port_count
        }
