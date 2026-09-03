"""
Unit Test Suite for Version 6.0 Advanced Vanguard Capabilities:
- Fully Homomorphic Encryption (FHE) Analytics-In-Use
- Ephemeral Polymorphic VPC Honeynet Fleet
- Autonomous Threat Hunting Multi-Agent Consensus
- Self-Healing Cloud Containment Mesh
"""
import os
import sys
import unittest

backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from app.analytics.fhe_engine import FHEAnalyticsEngine
from app.deception.honeynet import EphemeralHoneynetManager
from app.hunting.agent_consensus import ConsensusVerificationEngine
from app.soar.healing_mesh import CloudContainmentMeshController



class TestV6AdvancedVanguard(unittest.TestCase):

    def test_01_fhe_homomorphic_addition(self):
        """Test encryption and addition directly in ciphertext space without plaintext exposure."""
        fhe = FHEAnalyticsEngine(tenant_id="tenant-alpha")
        # Metric: severities [4, 3, 5] -> sum 12
        metrics = [4, 3, 5]
        ciphertexts = [fhe.encrypt_security_metric(m)["ciphertext_b64"] for m in metrics]

        agg_res = fhe.compute_homomorphic_sum(ciphertexts)
        self.assertTrue(agg_res["homomorphic_math_verified"])
        self.assertEqual(agg_res["decrypted_aggregate_sum"], 12)
        print("[+] test_01_fhe_homomorphic_addition passed!")

    def test_02_polymorphic_honeynet(self):
        """Test ephemeral honeypot container creation and probe engagement."""
        mgr = EphemeralHoneynetManager(tenant_id="tenant-beta")
        decoy = mgr.deploy_polymorphic_decoy("HTTP_WEB_PORTAL")
        self.assertTrue(decoy["name"].startswith("decoy-"))
        self.assertEqual(decoy["status"], "RUNNING_ACTIVE")

        trip_res = mgr.trip_honeypot(decoy["decoy_id"], attacker_ip="10.0.14.88")
        self.assertTrue(trip_res["success"])
        self.assertEqual(trip_res["alert_severity"], "CRITICAL")
        print("[+] test_02_polymorphic_honeynet passed!")

    def test_03_multi_agent_consensus(self):
        """Test cooperative threat hunting consensus voting across persona agents."""
        engine = ConsensusVerificationEngine()
        malicious_event = {
            "class_uid": 1007,
            "process": {"cmd_line": "powershell.exe -EncodedCommand SQBFAFgA..."},
            "network_activity": {"dst_endpoint": {"ip": "185.220.101.5", "port": 4444}},
            "raw_unstructured": "powershell -enc ... to 185.220.101.5:4444",
        }

        res = engine.evaluate_event_consensus(malicious_event)
        self.assertTrue(res["consensus_reached"])
        self.assertEqual(res["promotion_verdict"], "PROMOTED_TO_TRIAGE_CONSOLE")
        self.assertGreaterEqual(res["alert_votes_count"], 2)
        print("[+] test_03_multi_agent_consensus passed!")

    def test_04_cloud_mesh_lockdown(self):
        """Test multi-layer self-healing cloud containment (Security Group + IAM)."""
        controller = CloudContainmentMeshController(tenant_id="tenant-gamma")
        res = controller.execute_full_cloud_mesh_lockdown(
            target_resource="i-088f12a0c441",
            resource_type="EC2_INSTANCE"
        )
        self.assertEqual(res["mesh_status"], "SELF_HEALED_QUARANTINED")
        self.assertEqual(res["layers_enforced"], 2)
        print("[+] test_04_cloud_mesh_lockdown passed!")


if __name__ == "__main__":
    unittest.main()
