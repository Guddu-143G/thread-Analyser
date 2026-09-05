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

from app.detection.forensics import MobileDeviceDetector, MOBILE_VENDOR_IDS
from app.services.mobile_forensics_service import (
    MobileForensicAuditEngine,
    PasscodeThrottleController,
    COMMON_PATTERNS
)
from app.core.db import SessionLocal, Base, engine
from app.models.models import Organization, User, MobileForensicSession, PasscodeGuessAttempt

class TestV21MobileForensicsMesh(unittest.TestCase):
    def setUp(self):
        Base.metadata.create_all(bind=engine)
        self.db = SessionLocal()
        self.test_org_id = "test-org-v21-001"
        self.test_user_id = "test-user-v21-001"

        # Ensure test organization and user exist
        org = self.db.query(Organization).filter(Organization.id == self.test_org_id).first()
        if not org:
            org = Organization(id=self.test_org_id, name="V21 Forensic Org")
            self.db.add(org)
            self.db.commit()

        user = self.db.query(User).filter(User.id == self.test_user_id).first()
        if not user:
            user = User(
                id=self.test_user_id,
                org_id=self.test_org_id,
                email="forensic_analyst_v21@threatanalyser.io",
                hashed_password="mock_hashed_pw"
            )
            self.db.add(user)
            self.db.commit()

    def tearDown(self):
        self.db.close()

    def test_01_shannon_entropy_calculation(self):
        # 1. PIN_4: 4 digits, Alphabet size = 10 -> H = 4 * log2(10) ≈ 13.29 bits
        entropy_pin4 = MobileForensicAuditEngine.calculate_passcode_entropy("1234", "PIN_4")
        self.assertAlmostEqual(entropy_pin4, 13.29, places=1)

        # 2. PIN_6: 6 digits -> H = 6 * log2(10) ≈ 19.93 bits
        entropy_pin6 = MobileForensicAuditEngine.calculate_passcode_entropy("123456", "PIN_6")
        self.assertAlmostEqual(entropy_pin6, 19.93, places=1)

        # 3. 3x3 Android Gesture Pattern: 5 nodes -> Permutations P(9, 5) = 15120 -> log2(15120) ≈ 13.88 bits
        entropy_pattern = MobileForensicAuditEngine.calculate_passcode_entropy("0,1,2,5,8", "PATTERN")
        self.assertAlmostEqual(entropy_pattern, 13.88, places=1)

        # 4. Alphanumeric: "Admin!1" -> 7 chars, upper(26)+lower(26)+digit(10)+symbol(32)=94 -> 7 * log2(94) ≈ 45.88 bits
        entropy_alpha = MobileForensicAuditEngine.calculate_passcode_entropy("Admin!1", "ALPHANUMERIC")
        self.assertTrue(entropy_alpha > 35.0, f"Entropy {entropy_alpha} should be > 35 bits")

    def test_02_usb_device_detection_descriptors(self):
        # Test Google Pixel USB probe
        pixel_info = MobileDeviceDetector.probe_usb_port("/dev/bus/usb/001/004")
        self.assertEqual(pixel_info["manufacturer"], "Google")
        self.assertEqual(pixel_info["os_name"], "Android")
        self.assertTrue(pixel_info["serial_number"].startswith("G8P9"))
        self.assertEqual(pixel_info["connection_type"], "USB_OTG_HID")

        # Test Apple iPhone USB probe
        iphone_info = MobileDeviceDetector.probe_usb_port("/dev/bus/usb/002/001")
        self.assertEqual(iphone_info["manufacturer"], "Apple")
        self.assertEqual(iphone_info["os_name"], "iOS")
        self.assertTrue(iphone_info["serial_number"].startswith("F2LN"))

    def test_03_ocsf_3002_event_schema(self):
        event = MobileDeviceDetector.build_ocsf_forensic_auth_event(
            tenant_uid="org-test-123",
            device_uid="G8P9X0214872X",
            target_udid="00008101-001C34A90A2E001A",
            attempt_index=12,
            passcode_type="PATTERN",
            is_successful=True,
            entropy=13.88,
            pattern_coords=[0, 1, 2, 5, 8],
            speed_gps=3.5,
            cooldown_sec=0.0
        )

        self.assertEqual(event["metadata"]["class_uid"], 3002)
        self.assertEqual(event["metadata"]["class_name"], "Authentication")
        self.assertEqual(event["category_uid"], 3)
        self.assertEqual(event["auth_protocol"], "USB_HID_EMULATION")
        self.assertEqual(event["status"], "SUCCESS")
        self.assertEqual(event["forensics_metadata"]["shannon_entropy"], 13.88)
        self.assertEqual(event["forensics_metadata"]["current_pattern_coords"], [0, 1, 2, 5, 8])

    def test_04_passcode_throttle_controller_lockout(self):
        controller = PasscodeThrottleController()
        sess_id = "test-session-lockout-001"

        self.assertFalse(controller.is_locked_out(sess_id))
        self.assertEqual(controller.get_remaining_cooldown(sess_id), 0.0)

        # Trigger 2-second cooldown
        controller.trigger_cooldown(sess_id, duration_sec=2.0)
        self.assertTrue(controller.is_locked_out(sess_id))
        self.assertTrue(controller.get_remaining_cooldown(sess_id) > 0.0)

        # Wait for expiry
        time.sleep(2.1)
        self.assertFalse(controller.is_locked_out(sess_id))
        self.assertEqual(controller.get_remaining_cooldown(sess_id), 0.0)

    def test_05_database_session_and_attempt_execution(self):
        session_obj = MobileForensicSession(
            org_id=self.test_org_id,
            analyst_id=self.test_user_id,
            device_name="Google",
            device_model="Pixel 8 Pro",
            serial_number="G8P9UNITTEST01",
            udid="00008101-UNITTEST01",
            os_name="Android",
            os_version="14",
            connection_type="USB_OTG_HID",
            passcode_type="PIN_4",
            max_estimated_entropy=13.29,
            status="RUNNING"
        )
        self.db.add(session_obj)
        self.db.commit()
        self.db.refresh(session_obj)

        # Execute incorrect attempt
        attempt1, ocsf1 = MobileForensicAuditEngine.execute_audit_attempt(
            db=self.db,
            session_obj=session_obj,
            attempt_index=1,
            candidate="0000",
            target_secret="1994"
        )
        self.assertFalse(attempt1.is_successful)
        self.assertEqual(attempt1.response_code, "REJECTED")
        self.assertIsNotNone(attempt1.passcode_attempt_hash)

        # Execute correct attempt
        attempt2, ocsf2 = MobileForensicAuditEngine.execute_audit_attempt(
            db=self.db,
            session_obj=session_obj,
            attempt_index=2,
            candidate="1994",
            target_secret="1994"
        )
        self.assertTrue(attempt2.is_successful)
        self.assertEqual(attempt2.response_code, "SUCCESS")
        self.assertEqual(session_obj.status, "COMPLETED")

        # Clean up
        self.db.delete(attempt1)
        self.db.delete(attempt2)
        self.db.delete(session_obj)
        self.db.commit()


if __name__ == "__main__":
    unittest.main()
