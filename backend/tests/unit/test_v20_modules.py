import unittest
import sys
import os
import time

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from app.services.adaptive_gps_service import AdaptiveGPSEngine, TerminalStreamManager
from app.core.db import SessionLocal
from app.models.models import Organization, Device, LiveResponseSession, User

class TestV20AdaptiveGPSMesh(unittest.TestCase):
    def setUp(self):
        self.device_id = "test-device-v20-001"
        self.org_id = "test-org-v20-001"
        # Geofence center in San Francisco, 25km radius
        self.engine = AdaptiveGPSEngine(
            device_id=self.device_id,
            org_id=self.org_id,
            geofence_center=(37.7749, -122.4194),
            geofence_radius_meters=25000.0
        )

    def test_01_haversine_distance_computation(self):
        # San Francisco (37.7749, -122.4194) to Oakland (37.8044, -122.2712) ~ 13.5 km
        sf = (37.7749, -122.4194)
        oakland = (37.8044, -122.2712)
        dist = self.engine.calculate_distance_meters(sf, oakland)
        self.assertTrue(12000 < dist < 15000, f"Distance {dist}m is not between 12km and 15km")

    def test_02_adaptive_intervals_state_transitions(self):
        sf = (37.7749, -122.4194)

        # 1. Active Transit State (Speed = 15.0 m/s ~ 54 km/h)
        interval, state = self.engine.get_adaptive_interval(
            current_pos=sf,
            battery_level=80,
            has_ac_power=False,
            speed_override=15.0
        )
        self.assertEqual(state, "ACTIVE_TRANSIT")
        self.assertEqual(interval, 10)

        # 2. Stationary State (Speed = 0.2 m/s, multiple consecutive stationary readings)
        for _ in range(6):
            interval, state = self.engine.get_adaptive_interval(
                current_pos=sf,
                battery_level=80,
                has_ac_power=False,
                speed_override=0.2
            )
        self.assertEqual(state, "STATIONARY")
        self.assertEqual(interval, 900)

        # 3. Low Power Override (Battery <= 20% on Battery Power)
        interval, state = self.engine.get_adaptive_interval(
            current_pos=sf,
            battery_level=15,
            has_ac_power=False,
            speed_override=2.0
        )
        self.assertEqual(state, "LOW_POWER")
        self.assertEqual(interval, 1800)

        # 4. Low Power Override with AC power plugged in (Should NOT throttle to 1800s)
        interval, state = self.engine.get_adaptive_interval(
            current_pos=sf,
            battery_level=15,
            has_ac_power=True,
            speed_override=2.0
        )
        self.assertNotEqual(state, "LOW_POWER")
        self.assertEqual(state, "STANDARD_MOTION")
        self.assertEqual(interval, 60)

        # 5. Geofence Boundary Breach (Device moves to San Jose ~ 67km away, breaching 25km radius)
        san_jose = (37.3382, -121.8863)
        interval, state = self.engine.get_adaptive_interval(
            current_pos=san_jose,
            battery_level=15,
            has_ac_power=False,
            speed_override=0.0
        )
        self.assertEqual(state, "GEOFENCE_BREACH")
        self.assertEqual(interval, 5)

    def test_03_ocsf_5005_payload_generation(self):
        event = self.engine.build_ocsf_event(
            lat=37.7749,
            lon=-122.4194,
            battery=90,
            has_ac_power=True,
            speed_override=8.0,
            altitude=15.5,
            horizontal_accuracy=3.2
        )

        self.assertEqual(event["metadata"]["class_uid"], 5005)
        self.assertEqual(event["metadata"]["version"], "1.2.0")
        self.assertEqual(event["location_activity"]["device_id"], self.device_id)
        self.assertEqual(event["location_activity"]["tracking_state"], "ACTIVE_TRANSIT")
        self.assertEqual(event["location_activity"]["polling_interval_seconds"], 10)
        self.assertEqual(event["location_activity"]["power_source"], "AC")
        self.assertEqual(event["location_activity"]["horizontal_accuracy"], 3.2)


if __name__ == "__main__":
    unittest.main()
