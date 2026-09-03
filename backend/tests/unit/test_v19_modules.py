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
from app.models.models import (
    Organization,
    User,
    Device,
    LiveQueryRun,
    LiveQueryResult,
    RemoteFileTransfer,
    FleetActionLog
)
from app.services.fleet_c2_service import (
    FleetQueryEngine,
    FleetActionManager,
    FleetMapService
)

class TestV19FleetModules(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.engine = create_engine("sqlite:///:memory:", echo=False)
        Base.metadata.create_all(cls.engine)
        cls.SessionLocal = sessionmaker(bind=cls.engine)

    def setUp(self):
        self.db = self.SessionLocal()
        self.org_id = str(uuid.uuid4())
        org = Organization(id=self.org_id, name="V19 Test Org")
        self.db.add(org)

        uid_suffix = uuid.uuid4().hex[:6]
        self.analyst_id = str(uuid.uuid4())
        analyst = User(id=self.analyst_id, org_id=self.org_id, email=f"analyst-{uid_suffix}@acme.corp", hashed_password="pw")
        self.db.add(analyst)

        self.device_id = str(uuid.uuid4())
        self.device = Device(
            id=self.device_id,
            org_id=self.org_id,
            name=f"prod-k8s-node-{uid_suffix}",
            hostname=f"k8s-{uid_suffix}.corp.internal",
            public_ip="185.190.140.2",
            os_name="Linux",
            os_version="6.5.0",
            last_latitude=51.5074,
            last_longitude=-0.1278,
            last_location_desc="London Enclave",
            api_key_hash="hash_dev_01"
        )
        self.db.add(self.device)
        self.db.commit()

    def tearDown(self):
        self.db.close()

    def test_osquery_style_evaluation(self):
        engine = FleetQueryEngine(db=self.db, org_id=self.org_id)

        # 1. Query rogue processes with high CPU
        proc_rows = engine.execute_query_on_device("SELECT * FROM processes WHERE cpu_usage > 50;", self.device)
        self.assertEqual(len(proc_rows), 1)
        self.assertEqual(proc_rows[0]["name"], "crypto_miner")
        self.assertEqual(proc_rows[0]["pid"], 1337)

        # 2. Query listening network sockets
        port_rows = engine.execute_query_on_device("SELECT * FROM listening_ports WHERE state = 'LISTEN';", self.device)
        self.assertGreaterEqual(len(port_rows), 3)
        ports = [p["port"] for p in port_rows]
        self.assertIn(22, ports)
        self.assertIn(80, ports)

        # 3. Query system info
        sys_rows = engine.execute_query_on_device("SELECT * FROM system_info;", self.device)
        self.assertEqual(len(sys_rows), 1)
        self.assertEqual(sys_rows[0]["os_name"], "Linux")

        # 4. Dispatch query across fleet and persist to DB
        run = engine.dispatch_fleet_query(
            sql_statement="SELECT pid, name, cpu_usage FROM processes WHERE cpu_usage > 10;",
            analyst_id=self.analyst_id
        )
        self.assertEqual(run.status, "COMPLETED")
        self.assertEqual(len(run.results), 1)
        self.assertEqual(run.results[0].device_id, self.device_id)

    def test_fleet_action_manager_kill_and_isolate(self):
        manager = FleetActionManager(db=self.db, org_id=self.org_id)

        # 1. Kill Rogue Process
        action = manager.kill_process(
            device_id=self.device_id,
            pid=1337,
            process_name="crypto_miner",
            analyst_id=self.analyst_id
        )
        self.assertEqual(action.action_type, "KILL_PROCESS")
        self.assertEqual(action.execution_status, "SUCCESS")
        self.assertEqual(action.target_parameters["pid"], 1337)

        # 2. Apply Host Isolation
        iso_action = manager.isolate_host(
            device_id=self.device_id,
            isolate=True,
            analyst_id=self.analyst_id
        )
        self.assertEqual(iso_action.action_type, "ISOLATE_HOST")
        self.assertEqual(self.device.status, "quarantined")

        # 3. Verify directory exploration
        files = manager.explore_directory(device_id=self.device_id, path="/var/log")
        self.assertGreaterEqual(len(files), 2)
        filenames = [f["name"] for f in files]
        self.assertIn("auth.log", filenames)

        # 4. Record Remote File Transfer
        transfer = manager.record_file_transfer(
            device_id=self.device_id,
            analyst_id=self.analyst_id,
            direction="DOWNLOAD",
            local_file_path="/var/log/auth.log",
            file_content="Log line: Failed password for root from 185.220.101.5 port 4444"
        )
        self.assertEqual(transfer.transfer_direction, "DOWNLOAD")
        self.assertIsNotNone(transfer.sha256_hash)
        self.assertIn("neon://storage", transfer.server_storage_url)

    def test_fleet_map_service(self):
        map_service = FleetMapService(db=self.db, org_id=self.org_id)
        devices = map_service.get_fleet_map_devices()
        self.assertEqual(len(devices), 1)
        d = devices[0]
        self.assertEqual(d["device_id"], self.device_id)
        self.assertEqual(d["latitude"], 51.5074)
        self.assertEqual(d["longitude"], -0.1278)
        self.assertIn(d["latency_status"], ["green", "amber", "red"])


if __name__ == "__main__":
    unittest.main()
