"""
Unit test suite for Threat Analyser Version 7.0 Vanguard Modules:
- Post-Quantum Cryptography (PQCHybridNegotiator)
- Self-Supervised Graph Neural Network (GNNProvenanceClassifier)
- Autonomous Threat Twin (AutonomousThreatTwinEngine)
- Incident Time-Travel Forensics (ForensicFlightRecorder)
- Decentralized zk-SMPC Threat Exchange (ZeroKnowledgeThreatExchange)
"""
import os
import sys
import unittest

backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from app.security.pqc_middleware import PQCHybridNegotiator
from app.detection.gnn_provenance import GNNProvenanceClassifier, SecurityProvenanceGraph
from app.simulation.threat_twin import AutonomousThreatTwinEngine
from app.forensics.time_travel import ForensicFlightRecorder
from app.security.zk_smpc import ZeroKnowledgeThreatExchange



class TestV7Vanguard(unittest.TestCase):

    def test_01_pqc_hybrid_roundtrip(self):
        negotiator = PQCHybridNegotiator(tenant_id="tenant_pqc_99")
        pub, priv = negotiator.generate_server_kem_keypair()
        self.assertTrue(len(pub) > 100)
        self.assertTrue(len(priv) > 100)

        ciphertext, client_secret = negotiator.encapsulate_client_secret(pub)
        server_derived_key = negotiator.decapsulate_session_key(ciphertext, priv)
        self.assertEqual(client_secret, server_derived_key)

        sample_log = '{"ocsf_class": "PROCESS_ACTIVITY", "cmd": "kyber_agent.exe", "host": "prod-01"}'
        enc = negotiator.encrypt_log_payload_pqc(sample_log, client_secret)
        self.assertIn("pqc_encrypted_payload", enc)

        dec = negotiator.decrypt_log_payload_pqc(enc["pqc_encrypted_payload"], server_derived_key)
        self.assertEqual(dec, sample_log)
        print("[+] test_01_pqc_hybrid_roundtrip passed!")

    def test_02_gnn_provenance_anomaly(self):
        sample_events = [
            {"source": "cmd.exe", "target": "powershell.exe", "source_label": "Process", "target_label": "Process", "relationship": "spawns"},
            {"source": "powershell.exe", "target": "185.220.101.5:4444", "source_label": "Process", "target_label": "Socket", "relationship": "connects_outbound"},
        ]
        result = GNNProvenanceClassifier.analyze_incident_telemetry(sample_events)
        self.assertTrue(result["is_structural_threat"])
        self.assertGreaterEqual(result["path_anomaly_score"], 0.70)
        self.assertEqual(result["structural_verdict"], "ANOMALOUS_LATERAL_PATH")
        print("[+] test_02_gnn_provenance_anomaly passed!")

    def test_03_threat_twin_cyber_range(self):
        engine = AutonomousThreatTwinEngine(tenant_id="tenant_twin_01")
        topo = engine.get_digital_twin_topology()
        self.assertGreaterEqual(len(topo["virtual_nodes"]), 3)

        sim = engine.simulate_twin_attack("twin_vec_kerberoast", active_rules=["DETECT_KERBEROAST_ANOMALY"])
        self.assertEqual(sim["detection_verdict"], "DETECTED_AND_BLOCKED")
        self.assertGreaterEqual(sim["resilience_score"], 90)

        gaps = engine.evaluate_all_twin_gaps()
        self.assertGreater(gaps["overall_resilience_percentage"], 0)
        print("[+] test_03_threat_twin_cyber_range passed!")

    def test_04_forensics_time_travel_flight_recorder(self):
        timeline = ForensicFlightRecorder.get_incident_timeline(device_id="srv-web-01", alert_id="ALT-12345")
        self.assertEqual(timeline["device_id"], "srv-web-01")
        self.assertGreaterEqual(len(timeline["timeline_frames"]), 4)
        self.assertEqual(timeline["patient_zero_sequence_id"], 3)
        print("[+] test_04_forensics_time_travel_flight_recorder passed!")

    def test_05_zk_smpc_threat_exchange(self):
        exchange = ZeroKnowledgeThreatExchange(tenant_id="tenant_bank_01")
        proof_res = exchange.generate_ioc_presence_proof("185.220.101.5", confidence_score=0.98)
        self.assertEqual(proof_res["status"], "PROOF_GENERATED")
        self.assertIn("proof_bundle", proof_res)

        verify_res = exchange.verify_mesh_proof(proof_res["proof_bundle"], local_ioc_candidate="185.220.101.5")
        self.assertTrue(verify_res["valid"])
        self.assertTrue(verify_res["candidate_match"])
        print("[+] test_05_zk_smpc_threat_exchange passed!")


if __name__ == "__main__":
    unittest.main()
