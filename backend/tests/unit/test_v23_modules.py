import unittest
import sys
import os
import numpy as np

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from app.detection.gnn_ueba import HeterogeneousGNNFeatureExtractor
from app.agent.coprocessor_core import PortableCOREFiler, core_rasp_controller
from app.agent.side_channel_audit import SideChannelAuditor
from app.services.temporal_ledger_service import MerkleTemporalLedgerManager, GENESIS_PARENT_HASH
from app.core.db import SessionLocal, Base, engine
from app.models.models import Organization, User, DeviceAuditLedger

class TestV23SpatialLedgerCore(unittest.TestCase):
    def setUp(self):
        Base.metadata.create_all(bind=engine)
        self.db = SessionLocal()
        self.test_org_id = "test-org-v23-unit-001"
        self.test_user_id = "test-user-v23-unit-001"

        # Ensure test organization and user exist
        org = self.db.query(Organization).filter(Organization.id == self.test_org_id).first()
        if not org:
            org = Organization(id=self.test_org_id, name="V23 Spatial Unit Org")
            self.db.add(org)
            self.db.commit()

        user = self.db.query(User).filter(User.id == self.test_user_id).first()
        if not user:
            user = User(
                id=self.test_user_id,
                org_id=self.test_org_id,
                email="spatial_unit_v23@threatanalyser.io",
                hashed_password="mock_hashed_pw"
            )
            self.db.add(user)
            self.db.commit()

    def tearDown(self):
        self.db.close()

    # -------------------------------------------------------------
    # 1. GNN Spatial-Temporal Feature Extractor & UEBA Tests
    # -------------------------------------------------------------
    def test_01_gnn_ocsf_parser_and_pyg_tensors(self):
        extractor = HeterogeneousGNNFeatureExtractor()

        # OCSF 3002: Authentication Event
        ocsf_auth = {
            "metadata": {"class_uid": 3002, "tenant_uid": "acme"},
            "user": {"name": "svc_admin"},
            "device": {"hostname": "srv-prod-auth01"},
            "time": 1718000000
        }
        src_id, dst_id, edge_type = extractor.parse_ocsf_to_graph(ocsf_auth)
        self.assertGreaterEqual(src_id, 0)
        self.assertGreaterEqual(dst_id, 0)
        self.assertEqual(edge_type, 0)  # AUTHENTICATED_TO

        # OCSF 1007: Process Spawn
        ocsf_proc = {
            "metadata": {"class_uid": 1007, "tenant_uid": "acme"},
            "device": {"hostname": "srv-prod-auth01"},
            "process": {"name": "lsass.exe"},
            "time": 1718000001
        }
        src2, dst2, edge2 = extractor.parse_ocsf_to_graph(ocsf_proc)
        self.assertEqual(edge2, 1)  # SPAWNED_PROCESS

        # PyG Tensor Extraction
        x, edge_index, edge_attr = extractor.get_pyg_tensors()
        self.assertEqual(x.shape[0], len(extractor.node_mapping))
        self.assertEqual(x.shape[1], 8)
        self.assertEqual(edge_index.shape[0], 2)
        self.assertEqual(edge_index.shape[1], 2)
        self.assertEqual(len(edge_attr), 2)

        # Anomaly scoring
        anomaly_summary = extractor.compute_graph_anomaly_score()
        self.assertIn("mean_anomaly_score", anomaly_summary)
        self.assertIn("max_anomaly_score", anomaly_summary)
        self.assertIn("is_anomalous", anomaly_summary)
        self.assertEqual(anomaly_summary["total_nodes"], len(extractor.node_mapping))

    # -------------------------------------------------------------
    # 2. Portable eBPF CO-RE LSM RASP Controller Tests
    # -------------------------------------------------------------
    def test_02_ebpf_core_btf_and_policy_enforcement(self):
        controller = core_rasp_controller

        # Check BTF initialization
        status = controller.initialize_core_rasp()
        self.assertIn("status", status)
        self.assertIn("relocation_type", status)
        self.assertIn("libbpf CO-RE", status["relocation_type"])

        # Update dynamic policy map for UID 1001 (enforce kill)
        policy_res = controller.update_block_policy(uid=1001, enforce_kill=True)
        self.assertEqual(policy_res["policy_mode"], "ENFORCE_BLOCK")
        self.assertTrue(policy_res["enforce_kill"])

        # Simulation 1: Blocked execution for restricted path /dev/shm
        eval_blocked = controller.evaluate_execution_interception(
            uid=1000,
            binary_path="/dev/shm/malicious_payload",
            command_args="-e /bin/sh"
        )
        self.assertEqual(eval_blocked["action"], "BLOCKED_EPERM")
        self.assertEqual(eval_blocked["errno"], "EPERM (Operation Not Permitted)")
        self.assertTrue(eval_blocked["latency_microseconds"] > 0)

        # Simulation 2: Allowed execution for root /usr/bin/ls
        eval_allowed = controller.evaluate_execution_interception(
            uid=0,
            binary_path="/usr/bin/ls",
            command_args="-la"
        )
        self.assertEqual(eval_allowed["action"], "PERMITTED")
        self.assertIsNone(eval_allowed["errno"])

    # -------------------------------------------------------------
    # 3. SEP Side-Channel CPA & DPA Power Cryptanalysis Tests
    # -------------------------------------------------------------
    def test_03_side_channel_trace_and_cpa_analysis(self):
        auditor = SideChannelAuditor(key_length=8)
        num_traces = 50
        key_len = 8

        # Target secret key: "SECRET23"
        target_key = np.array([0x53, 0x45, 0x43, 0x52, 0x45, 0x54, 0x32, 0x33], dtype=np.uint8)
        inputs = np.random.randint(0, 256, (num_traces, key_len), dtype=np.uint8)

        # Generate traces
        traces = auditor.generate_power_traces(inputs, target_key=target_key, noise_level=0.2)
        self.assertEqual(traces.shape[0], num_traces)
        self.assertEqual(traces.shape[1], key_len)

        # Run CPA Key Correlation
        analysis = auditor.correlate_key_candidates(inputs, traces, num_candidates=256)
        self.assertIn("recovered_key_hex", analysis)
        self.assertIn("recovered_key_text", analysis)
        self.assertIn("max_correlation_peak", analysis)
        self.assertEqual(len(analysis["correlation_matrix"]), key_len)
        self.assertTrue(analysis["max_correlation_peak"] > 0.4)

    # -------------------------------------------------------------
    # 4. Neon SQL Merkle-Chained Temporal Ledger Tests
    # -------------------------------------------------------------
    def test_04_merkle_temporal_ledger_integrity_and_tamper_detection(self):
        # 1. Clean previous test entries if any
        self.db.query(DeviceAuditLedger).filter(DeviceAuditLedger.org_id == self.test_org_id).delete()
        self.db.commit()

        # 2. Append 3 sequentially linked ledger blocks
        entry1 = MerkleTemporalLedgerManager.append_audit_entry(
            db=self.db,
            org_id=self.test_org_id,
            device_id="dev-sec-alpha",
            hostname="enclave-node-alpha",
            ip_address="10.10.1.5",
            system_status="active",
            operation_type="INSERT"
        )
        self.assertEqual(entry1.parent_hash, GENESIS_PARENT_HASH)
        self.assertIsNotNone(entry1.record_hash)

        entry2 = MerkleTemporalLedgerManager.append_audit_entry(
            db=self.db,
            org_id=self.test_org_id,
            device_id="dev-sec-alpha",
            hostname="enclave-node-alpha-v2",
            ip_address="10.10.1.5",
            system_status="active",
            operation_type="UPDATE"
        )
        self.assertEqual(entry2.parent_hash, entry1.record_hash)

        entry3 = MerkleTemporalLedgerManager.append_audit_entry(
            db=self.db,
            org_id=self.test_org_id,
            device_id="dev-sec-beta",
            hostname="enclave-node-beta",
            ip_address="10.10.1.6",
            system_status="isolated",
            operation_type="INSERT"
        )
        self.assertEqual(entry3.parent_hash, entry2.record_hash)

        # 3. Verify valid ledger chain
        verify_valid = MerkleTemporalLedgerManager.verify_ledger_integrity(self.db, self.test_org_id)
        self.assertTrue(verify_valid["is_valid"])
        self.assertEqual(verify_valid["chain_status"], "CRYPTOGRAPHICALLY_VERIFIED_TAMPER_FREE")
        self.assertEqual(verify_valid["verified_blocks"], 3)
        self.assertEqual(verify_valid["tampered_blocks_count"], 0)

        # 4. Simulate Rogue DBA Tamper on block 2
        tamper_res = MerkleTemporalLedgerManager.simulate_dba_tampering(
            db=self.db,
            org_id=self.test_org_id,
            target_ledger_id=entry2.ledger_id
        )
        self.assertEqual(tamper_res["status"], "TAMPERING_INJECTED")

        # 5. Re-verify -> Must catch the broken chain
        verify_tampered = MerkleTemporalLedgerManager.verify_ledger_integrity(self.db, self.test_org_id)
        self.assertFalse(verify_tampered["is_valid"])
        self.assertEqual(verify_tampered["chain_status"], "TAMPERING_DETECTED")
        self.assertGreaterEqual(verify_tampered["tampered_blocks_count"], 1)

if __name__ == "__main__":
    unittest.main()
