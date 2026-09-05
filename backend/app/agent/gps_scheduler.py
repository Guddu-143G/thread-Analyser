"""
Version 24: Adaptive GPS Scheduler Engine.
Dynamically throttles GPS polling intervals based on velocity vectors,
geofence radius breaches, and critical battery constraints (< 20%).
"""

import time
import math
from typing import Dict, Any, Tuple, Optional

class AdaptiveGPSEngine:
    """
    Adaptive GPS Tracking Scheduler. Calculates physical velocity, checks 
    geofence coordinates, and throttles GPS polling intervals to conserve energy.
    """
    def __init__(self, geofence_center: Tuple[float, float] = (37.7749, -122.4194), geofence_radius_meters: float = 20000.0):
        self.geofence_center = geofence_center
        self.geofence_radius = geofence_radius_meters
        
        # State tracking
        self.last_lat: Optional[float] = None
        self.last_lon: Optional[float] = None
        self.last_time: Optional[float] = None
        self.current_interval = 60 # Default to 60 seconds
        
    def haversine_distance(self, lat1: float, lon1: float, lat2: float, lon2: float) -> float:
        """Calculates distance between two coordinates in meters using Haversine Formula."""
        R = 6371000.0 # Earth's radius in meters
        phi_1 = math.radians(lat1)
        phi_2 = math.radians(lat2)
        delta_phi = math.radians(lat2 - lat1)
        delta_lambda = math.radians(lon2 - lon1)
        
        a = math.sin(delta_phi / 2.0)**2 + \
            math.cos(phi_1) * math.cos(phi_2) * math.sin(delta_lambda / 2.0)**2
        c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
        return R * c

    def update_location_and_get_interval(
        self,
        current_lat: float,
        current_lon: float,
        battery_pct: float,
        custom_timestamp: Optional[float] = None,
        simulated_speed_kmh: Optional[float] = None
    ) -> Tuple[int, Dict[str, Any]]:
        now = custom_timestamp if custom_timestamp is not None else time.time()
        speed_mps = 0.0
        
        # 1. Geofence Check
        distance_to_center = self.haversine_distance(
            current_lat, current_lon, 
            self.geofence_center[0], self.geofence_center[1]
        )
        is_outside_geofence = distance_to_center > self.geofence_radius
        
        # 2. Velocity calculation
        if simulated_speed_kmh is not None:
            speed_mps = simulated_speed_kmh / 3.6
        elif self.last_lat is not None and self.last_lon is not None and self.last_time is not None:
            time_delta = now - self.last_time
            if time_delta > 0:
                dist = self.haversine_distance(self.last_lat, self.last_lon, current_lat, current_lon)
                speed_mps = dist / time_delta
                
        # 3. Dynamic Throttling Decision Logic
        if battery_pct < 20.0:
            # Critical power state overrides tracking fidelity unless actively fleeing outside geofence
            self.current_interval = 300 if is_outside_geofence else 1800
            state = "CRITICAL_POWER"
        elif is_outside_geofence:
            # High-alert tracking: Outside authorized territorial boundaries
            self.current_interval = 10 if speed_mps > 2.0 else 30
            state = "OUTSIDE_GEOFENCE"
        elif speed_mps > 3.0:
            # Moving in vehicles: Escalated coordinates reporting
            self.current_interval = 15
            state = "TRANSIT"
        else:
            # Stationary and safe
            self.current_interval = 300
            state = "STATIONARY"
            
        # Update trackers
        self.last_lat = current_lat
        self.last_lon = current_lon
        self.last_time = now
        
        metrics = {
            "state": state,
            "speed_mps": round(speed_mps, 2),
            "speed_kmh": round(speed_mps * 3.6, 2),
            "distance_to_center_m": round(distance_to_center, 2),
            "outside_geofence": is_outside_geofence,
            "battery_pct": round(battery_pct, 1),
            "next_scheduled_interval": self.current_interval
        }
        return self.current_interval, metrics
