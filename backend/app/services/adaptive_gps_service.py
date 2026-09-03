import os
import time
import math
import json
import logging
from typing import Dict, Any, Tuple, List, Optional
from sqlalchemy.orm import Session
from app.models.models import DeviceLocationLog, Device, LiveTerminalStream, LiveResponseSession

try:
    import redis
    def get_redis_client():
        redis_url = os.getenv("REDIS_URL", "redis://redis:6379/0")
        try:
            return redis.Redis.from_url(redis_url, decode_responses=True, socket_connect_timeout=1)
        except Exception:
            return None
except Exception:
    def get_redis_client():
        return None

logger = logging.getLogger("adaptive_gps")

class AdaptiveGPSEngine:
    """
    Executes client-side and edge adaptive GPS throttling to minimize battery drain,
    optimize database storage, and flag anomalous geofence violations.
    Conforms to OCSF Class 5005 (Geospatial Location Activity).
    """
    def __init__(
        self,
        device_id: str,
        org_id: str,
        geofence_center: Tuple[float, float] = (37.7749, -122.4194),
        geofence_radius_meters: float = 50000.0
    ):
        self.device_id = device_id
        self.org_id = org_id
        self.geofence_center = geofence_center  # (latitude, longitude)
        self.geofence_radius_meters = geofence_radius_meters
        
        # State tracking
        self.last_position: Optional[Tuple[float, float]] = None
        self.last_timestamp: float = 0.0
        self.consecutive_stationary_count: int = 0

    def calculate_distance_meters(self, pos1: Tuple[float, float], pos2: Tuple[float, float]) -> float:
        """Haversine formula to compute geodesic distance in meters between two GPS coordinates."""
        lat1, lon1 = math.radians(pos1[0]), math.radians(pos1[1])
        lat2, lon2 = math.radians(pos2[0]), math.radians(pos2[1])
        
        dlat = lat2 - lat1
        dlon = lon2 - lon1
        
        a = math.sin(dlat / 2)**2 + math.cos(lat1) * math.cos(lat2) * math.sin(dlon / 2)**2
        c = 2 * math.asin(math.sqrt(max(0.0, min(1.0, a))))
        r = 6371000.0  # Earth mean radius in meters
        return c * r

    def get_adaptive_interval(
        self,
        current_pos: Tuple[float, float],
        battery_level: int,
        has_ac_power: bool,
        speed_override: Optional[float] = None
    ) -> Tuple[int, str]:
        """
        Determines the optimal GPS polling interval (in seconds) based on 
        movement velocity, battery limits, and geofencing coordinates.
        """
        current_time = time.time()
        
        # 1. Check Geofence Boundary breach
        distance_from_center = self.calculate_distance_meters(current_pos, self.geofence_center)
        if distance_from_center > self.geofence_radius_meters:
            # Force aggressive 5-second tracking upon boundary violation
            return 5, "GEOFENCE_BREACH"
            
        # 2. Check Speed/Velocity
        if speed_override is not None and speed_override >= 0.0:
            speed = speed_override
        elif self.last_timestamp > 0.0 and self.last_position is not None:
            delta_time = current_time - self.last_timestamp
            delta_dist = self.calculate_distance_meters(current_pos, self.last_position)
            speed = delta_dist / max(delta_time, 1.0)
        else:
            speed = 0.0

        # Update historical state
        self.last_position = current_pos
        self.last_timestamp = current_time
        
        # 3. Evaluate stationary state
        if speed < 1.0:
            self.consecutive_stationary_count += 1
        else:
            self.consecutive_stationary_count = 0

        # 4. Check battery limits (critical threshold: <=20% on battery)
        if battery_level <= 20 and not has_ac_power:
            return 1800, "LOW_POWER"  # 30-minute interval to preserve battery

        # 5. Evaluate movement thresholds
        if self.consecutive_stationary_count > 4:
            # Device is idle
            return 900, "STATIONARY"  # 15-minute interval
        elif speed >= 5.0:
            # Fast movement (driving / vehicle transit)
            return 10, "ACTIVE_TRANSIT"  # 10-second interval
        else:
            # Standard active movement
            return 60, "STANDARD_MOTION"  # 1-minute interval

    def build_ocsf_event(
        self,
        lat: float,
        lon: float,
        battery: int,
        has_ac_power: bool,
        speed_override: Optional[float] = None,
        altitude: Optional[float] = None,
        horizontal_accuracy: Optional[float] = None
    ) -> Dict[str, Any]:
        """Maps geographic measurements to standard OCSF Class 5005 format."""
        current_pos = (lat, lon)
        interval, tracking_state = self.get_adaptive_interval(current_pos, battery, has_ac_power, speed_override)
        
        return {
            "metadata": {
                "version": "1.2.0",
                "class_uid": 5005,  # Location Activity Event
                "product": {
                    "vendor": "ThreatAnalyser",
                    "name": "AdaptiveGPSEngine",
                    "version": "20.0.0"
                }
            },
            "category_uid": 5,  # Discovery / Geospatial
            "severity_id": 3 if tracking_state == "GEOFENCE_BREACH" else 1,
            "time": int(time.time() * 1000),
            "location_activity": {
                "latitude": lat,
                "longitude": lon,
                "altitude": altitude,
                "horizontal_accuracy": horizontal_accuracy,
                "device_id": self.device_id,
                "org_id": self.org_id,
                "tracking_state": tracking_state,
                "polling_interval_seconds": interval,
                "battery_level": battery,
                "power_source": "AC" if has_ac_power else "BATTERY"
            }
        }


class AdaptiveLocationTracker:
    """
    Central server-side coordinator for receiving, evaluating, persisting,
    and streaming adaptive GPS telemetry with Redis Pub/Sub integration.
    """
    _engines: Dict[str, AdaptiveGPSEngine] = {}
    _geofences: Dict[str, Tuple[float, float, float]] = {}  # device_id -> (lat, lon, radius)

    @classmethod
    def get_or_create_engine(
        cls,
        device_id: str,
        org_id: str,
        center_lat: float = 37.7749,
        center_lon: float = -122.4194,
        radius_meters: float = 50000.0
    ) -> AdaptiveGPSEngine:
        if device_id in cls._geofences:
            clat, clon, crad = cls._geofences[device_id]
            center_lat, center_lon, radius_meters = clat, clon, crad

        if device_id not in cls._engines:
            cls._engines[device_id] = AdaptiveGPSEngine(
                device_id=device_id,
                org_id=org_id,
                geofence_center=(center_lat, center_lon),
                geofence_radius_meters=radius_meters
            )
        return cls._engines[device_id]

    @classmethod
    def set_geofence(cls, device_id: str, org_id: str, center_lat: float, center_lon: float, radius_meters: float):
        cls._geofences[device_id] = (center_lat, center_lon, radius_meters)
        if device_id in cls._engines:
            cls._engines[device_id].geofence_center = (center_lat, center_lon)
            cls._engines[device_id].geofence_radius_meters = radius_meters
        else:
            cls.get_or_create_engine(device_id, org_id, center_lat, center_lon, radius_meters)

    @classmethod
    def get_geofence(cls, device_id: str) -> Optional[Tuple[float, float, float]]:
        return cls._geofences.get(device_id)

    @classmethod
    def ingest_location(
        cls,
        db: Session,
        org_id: str,
        device_id: str,
        latitude: float,
        longitude: float,
        altitude: Optional[float] = None,
        speed_mps: float = 0.0,
        horizontal_accuracy: Optional[float] = None,
        battery_level: int = 100,
        power_source: str = "BATTERY"
    ) -> Tuple[DeviceLocationLog, Dict[str, Any]]:
        has_ac_power = (power_source.upper() == "AC")
        engine = cls.get_or_create_engine(device_id, org_id)
        
        # Calculate state and interval
        ocsf_event = engine.build_ocsf_event(
            lat=latitude,
            lon=longitude,
            battery=battery_level,
            has_ac_power=has_ac_power,
            speed_override=speed_mps,
            altitude=altitude,
            horizontal_accuracy=horizontal_accuracy
        )
        
        loc_data = ocsf_event["location_activity"]
        tracking_state = loc_data["tracking_state"]
        interval = loc_data["polling_interval_seconds"]

        # Persist log
        log_entry = DeviceLocationLog(
            org_id=org_id,
            device_id=device_id,
            latitude=latitude,
            longitude=longitude,
            altitude=altitude,
            speed_mps=speed_mps,
            horizontal_accuracy=horizontal_accuracy,
            battery_level=battery_level,
            power_source=power_source.upper(),
            tracking_state=tracking_state,
            polling_interval_seconds=interval
        )
        db.add(log_entry)

        # Update Device state
        dev = db.query(Device).filter(Device.id == device_id, Device.org_id == org_id).first()
        if dev:
            dev.last_latitude = latitude
            dev.last_longitude = longitude
            dev.last_location_desc = f"Adaptive Track: {tracking_state} ({latitude:.4f}, {longitude:.4f})"
        
        db.commit()
        db.refresh(log_entry)

        # Broadcast over Redis Pub/Sub topic: tenant:{org_id}:device:{device_id}:gps
        try:
            r = get_redis_client()
            if r:
                channel = f"threat-analyser:tenant:{org_id}:device:{device_id}:gps"
                payload = json.dumps({
                    "log_id": log_entry.log_id,
                    "device_id": device_id,
                    "latitude": latitude,
                    "longitude": longitude,
                    "tracking_state": tracking_state,
                    "polling_interval_seconds": interval,
                    "battery_level": battery_level,
                    "power_source": power_source.upper(),
                    "tracked_at": log_entry.tracked_at.isoformat() if log_entry.tracked_at else None
                })
                r.publish(channel, payload)
        except Exception as e:
            logger.warning(f"Redis Pub/Sub broadcast error: {e}")

        return log_entry, ocsf_event

    @classmethod
    def get_device_history(cls, db: Session, org_id: str, device_id: str, limit: int = 50) -> List[DeviceLocationLog]:
        return (
            db.query(DeviceLocationLog)
            .filter(DeviceLocationLog.org_id == org_id, DeviceLocationLog.device_id == device_id)
            .order_by(DeviceLocationLog.tracked_at.desc())
            .limit(limit)
            .all()
        )


class TerminalStreamManager:
    """
    Manages granular PTY and asciicast execution logs for remote live response sub-sessions.
    """
    @classmethod
    def record_stream_chunk(
        cls,
        db: Session,
        org_id: str,
        session_id: str,
        command_input: str,
        command_output_summary: Optional[str] = None,
        exit_code: int = 0
    ) -> LiveTerminalStream:
        stream_entry = LiveTerminalStream(
            org_id=org_id,
            session_id=session_id,
            command_input=command_input,
            command_output_summary=command_output_summary or "",
            exit_code=exit_code
        )
        db.add(stream_entry)
        db.commit()
        db.refresh(stream_entry)
        return stream_entry

    @classmethod
    def get_session_streams(cls, db: Session, org_id: str, session_id: str) -> List[LiveTerminalStream]:
        return (
            db.query(LiveTerminalStream)
            .filter(LiveTerminalStream.org_id == org_id, LiveTerminalStream.session_id == session_id)
            .order_by(LiveTerminalStream.executed_at.asc())
            .all()
        )
