"""
Unit Test Suite for Version 5.0 Advanced Capabilities:
- Confidential Computing & Hardware Enclave PII Sanitizer
- Cryptographic Searchable Symmetric Encryption (SSE) Archive
- Active Deception & Honey-Token Controller
- System Call Provenance DAG & Patient Zero Backtracing
- Automated Breach & Attack Simulation (BAS) Loop
"""
import os
import sys
import unittest

backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from app.enclave.processor import EnclaveLogProcessor
from app.storage.searchable_archive import SearchableArchiveEngine
from app.deception.honey_tokens import HoneyTokenController
from app.detection.provenance_graph import ProvenanceGraphEngine
from app.simulation.bas_engine import BreachAttackSimulator



class TestV5AdvancedCapabilities(unittest.TestCase):

    def test_01_enclave_pii_sanitization(self):
        """Test in-memory decryption and PII masking inside secure enclave processor."""
        proc = EnclaveLogProcessor(tenant_id="tenant-alpha")
        key = os.urandom(32)
        raw_log = "User admin@corp.io logged in from 10.0.0.1 with Authorization Bearer eyJhbGciOi... secret=pass123"
        encrypted_blob = EnclaveLogProcessor.encrypt_test_payload(raw_log, key)

        result = proc.sanitize_and_normalize(encrypted_blob, key)
        self.assertEqual(result["status"], "SANITIZED_INSIDE_ENCLAVE")
        self.assertIn("[MASKED_EMAIL]", result["raw_unstructured"])
        self.assertNotIn("admin@corp.io", result["raw_unstructured"])
        self.assertTrue(result["metadata"]["confidential_computing"])
        print("[+] test_01_enclave_pii_sanitization passed!")

    def test_02_searchable_symmetric_encryption(self):
        """Test token generation and zero-bulk-decryption search over encrypted archives."""
        master_key = b"0" * 32
        engine = SearchableArchiveEngine(master_key)

        raw_logs = [
            "User root logged in via SSH from 192.168.1.50",
            "Outbound beacon to 185.220.101.5 on port 4444",
            "Powershell encoded command executed by service_account",
        ]

        blob, dek, s_index = engine.encrypt_log_payload(raw_logs)
        self.assertTrue(len(s_index) > 0)

        # Search for IP indicator
        res = engine.search_encrypted_archive(blob, dek, s_index, "185.220.101.5")
        self.assertEqual(res["matched_indices_count"], 1)
        self.assertEqual(res["matched_records"][0]["line_index"], 1)
        self.assertIn("185.220.101.5", res["matched_records"][0]["content"])

        # Search for non-existent keyword
        res_none = engine.search_encrypted_archive(blob, dek, s_index, "clean_string_xyz")
        self.assertEqual(res_none["matched_indices_count"], 0)
        print("[+] test_02_searchable_symmetric_encryption passed!")

    def test_03_active_deception_honey_tokens(self):
        """Test lifecycle of managed honey-tokens and breach tripping."""
        ctrl = HoneyTokenController(tenant_id="tenant-beta")
        aws_token = ctrl.generate_decoy_aws_credentials("AWS Prod Decoy")
        self.assertTrue(aws_token["aws_access_key_id"].startswith("AKIA"))

        trip_result = ctrl.trip_honey_token(aws_token["token_uid"], attacker_ip="45.155.205.233")
        self.assertTrue(trip_result["success"])
        self.assertEqual(trip_result["alert_severity"], "CRITICAL")
        self.assertTrue(trip_result["zero_false_positive_guarantee"])
        print("[+] test_03_active_deception_honey_tokens passed!")

    def test_04_provenance_dag_patient_zero(self):
        """Test graph stitching and backwards traversal to Patient Zero."""
        engine = ProvenanceGraphEngine()
        engine.add_node("entry_exploit", "session", {"ip": "1.2.3.4"})
        engine.add_node("proc_100", "process", {"pid": "100", "name": "nginx"})
        engine.add_edge("entry_exploit", "proc_100", "triggers")
        engine.add_execution_event("100", "200", "bash", "-c revshell")
        engine.add_execution_event("200", "300", "powershell.exe", "-enc")

        trace = engine.trace_patient_zero("proc_300")
        self.assertEqual(trace[0]["id"], "proc_300")
        self.assertEqual(trace[-1]["id"], "entry_exploit")
        print("[+] test_04_provenance_dag_patient_zero passed!")

    def test_05_breach_attack_simulation(self):
        """Test atomic red-team adversary simulation against detection pipeline."""
        result = BreachAttackSimulator.execute_atomic_simulation(
            suite_id="T1059.001",
            tenant_id="tenant-alpha",
        )
        self.assertTrue(result["detection_triggered"])
        self.assertEqual(result["status"], "VALIDATED_PASS")
        self.assertTrue(result["latency_ms"] < 100.0)
        print("[+] test_05_breach_attack_simulation passed!")


if __name__ == "__main__":
    unittest.main()
