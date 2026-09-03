import unittest
import sys
import os
import uuid
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
from app.models.models import Organization, User, Device, LiveResponseSession, LiveResponseCommand, TerminalKeystroke
from app.services.live_response_service import LiveResponseOrchestrator

class TestV18LiveResponseModules(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.engine = create_engine("sqlite:///:memory:", echo=False)
        Base.metadata.create_all(cls.engine)
        cls.SessionLocal = sessionmaker(bind=cls.engine)

    def setUp(self):
        self.db = self.SessionLocal()
        self.org_id = str(uuid.uuid4())
        org = Organization(id=self.org_id, name="V18 Test Org")
        self.db.add(org)

        uid_suffix = uuid.uuid4().hex[:6]
        self.analyst_id = str(uuid.uuid4())
        analyst = User(id=self.analyst_id, org_id=self.org_id, email=f"analyst-{uid_suffix}@acme.corp", hashed_password="pw")
        self.db.add(analyst)

        self.approver_id = str(uuid.uuid4())
        approver = User(id=self.approver_id, org_id=self.org_id, email=f"admin-{uid_suffix}@acme.corp", hashed_password="pw")
        self.db.add(approver)

        self.device_id = str(uuid.uuid4())
        device = Device(
            id=self.device_id,
            org_id=self.org_id,
            name=f"prod-db-{uid_suffix}",
            hostname=f"db-{uid_suffix}.corp.internal",
            public_ip="192.168.1.50",
            api_key_hash="hash_dev_01"
        )
        self.db.add(device)
        self.db.commit()

    def tearDown(self):
        self.db.close()

    def test_session_creation_and_two_man_rule_enforcement(self):
        orch = LiveResponseOrchestrator(db=self.db, org_id=self.org_id)

        # 1. Request session
        session = orch.create_session_request(
            analyst_id=self.analyst_id,
            device_id=self.device_id
        )
        self.assertEqual(session.status, "PENDING_APPROVAL")
        self.assertIsNotNone(session.auth_token_hash)
        self.assertIsNotNone(session.encryption_key_hex)
        self.assertIsNone(session.approver_id)

        # 2. Verify self-approval is rejected (Two-Man Rule Violation)
        with self.assertRaises(ValueError) as ctx:
            orch.approve_session(session.session_id, approver_id=self.analyst_id)
        self.assertIn("Two-Man Rule Violation", str(ctx.exception))

        # 3. Verify approval by secondary admin succeeds
        active_session = orch.approve_session(session.session_id, approver_id=self.approver_id)
        self.assertEqual(active_session.status, "ACTIVE")
        self.assertEqual(active_session.approver_id, self.approver_id)

    def test_command_dispatch_and_keystroke_logging(self):
        orch = LiveResponseOrchestrator(db=self.db, org_id=self.org_id)

        # Create & approve session
        session = orch.create_session_request(analyst_id=self.analyst_id, device_id=self.device_id)
        orch.approve_session(session.session_id, approver_id=self.approver_id)

        # 1. Dispatch diagnostic command
        res = orch.dispatch_command(
            session_id=session.session_id,
            command_string="ps aux",
            executed_by=self.analyst_id
        )
        self.assertEqual(res["command"], "ps aux")
        self.assertEqual(res["exit_code"], 0)
        self.assertIn("threat-agent-daemon", res["output"])

        # 2. Dispatch remediation kill command
        res_kill = orch.dispatch_command(
            session_id=session.session_id,
            command_string="kill -9 1337",
            executed_by=self.analyst_id
        )
        self.assertEqual(res_kill["exit_code"], 0)
        self.assertIn("SIGKILL", res_kill["output"])

        # 3. Verify keystrokes ledger contains both IN and OUT events
        keystrokes = orch.get_session_keystrokes(session.session_id)
        self.assertGreaterEqual(len(keystrokes), 4)
        
        directions = [k["direction"] for k in keystrokes]
        self.assertIn("IN", directions)
        self.assertIn("OUT", directions)

        # 4. Verify DB commands
        cmds = self.db.query(LiveResponseCommand).filter(LiveResponseCommand.session_id == session.session_id).all()
        self.assertEqual(len(cmds), 2)
        self.assertIsNotNone(cmds[0].raw_output_compressed)

    def test_session_rejection_and_closure(self):
        orch = LiveResponseOrchestrator(db=self.db, org_id=self.org_id)

        # 1. Reject session
        session1 = orch.create_session_request(analyst_id=self.analyst_id, device_id=self.device_id)
        rejected = orch.reject_session(session1.session_id, approver_id=self.approver_id, reason="Untrusted IP context")
        self.assertEqual(rejected.status, "REJECTED")
        self.assertIsNotNone(rejected.closed_at)

        # Cannot execute commands on rejected session
        with self.assertRaises(ValueError):
            orch.dispatch_command(session1.session_id, "whoami", self.analyst_id)

        # 2. Close active session
        session2 = orch.create_session_request(analyst_id=self.analyst_id, device_id=self.device_id)
        orch.approve_session(session2.session_id, approver_id=self.approver_id)
        closed = orch.close_session(session2.session_id)
        self.assertEqual(closed.status, "CLOSED")
        self.assertIsNotNone(closed.closed_at)


if __name__ == "__main__":
    unittest.main()
