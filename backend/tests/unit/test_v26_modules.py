"""
Version 26.0 Unit Test Suite
Validates:
1. In-Memory Data Provenance Graph (DPG), Semantic Information-Gain Decay & Causal Traceback
2. Autonomous SOAR Playbook YAML Parsing, Trigger Condition Evaluation & DAG Execution
3. Hardware-Attested (TPM 2.0) Merkle Tree Compilation, PCR Quoting & Attestation Verification
"""

import sys
import os
import unittest

backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from app.detection.provenance_tracker import (
    DataProvenanceGraph,
    ProvenanceNodeType,
    ProvenanceRelationType
)
from app.services.soar_engine import (
    SOARWorkflowEngine,
    DEFAULT_ACTIVE_CONTAINMENT_PLAYBOOK_YAML
)
from app.detection.merkle_signer import (
    TPMMerkleTree,
    TPMHardwareAttestationEngine
)


# =========================================================================
# 1. DPG GRAPH & CAUSAL TRACEBACK TESTS
# =========================================================================

def test_provenance_node_and_edge_creation():
    dpg = DataProvenanceGraph(org_id="test_org_v26")
    p1 = dpg.add_node(ProvenanceNodeType.PROCESS, "proc:/bin/bash", "bash")
    p2 = dpg.add_node(ProvenanceNodeType.PROCESS, "proc:/usr/bin/curl", "curl")
    sock = dpg.add_node(ProvenanceNodeType.SOCKET, "sock:198.51.100.2:443", "198.51.100.2:443")

    assert len(dpg.nodes) == 3
    assert p1["name"] == "bash"
    assert sock["node_type"] == ProvenanceNodeType.SOCKET

    e1 = dpg.add_edge(p1["id"], p2["id"], ProvenanceRelationType.SPAWNED, 1.0)
    e2 = dpg.add_edge(p2["id"], sock["id"], ProvenanceRelationType.CONNECTED_TO, 1.0)

    assert len(dpg.edges) == 2
    assert len(e1["edge_hash_sha256"]) == 64
    assert e1["relation_type"] == ProvenanceRelationType.SPAWNED
    assert e2["relation_type"] == ProvenanceRelationType.CONNECTED_TO
    print("    [+] test_provenance_node_and_edge_creation passed")


def test_semantic_decay_pruning():
    dpg = DataProvenanceGraph(org_id="test_org_v26")
    p_normal = dpg.add_node(ProvenanceNodeType.PROCESS, "proc:/usr/bin/app", "app")
    p_noise = dpg.add_node(ProvenanceNodeType.PROCESS, "proc:/usr/sbin/cron", "cron")
    f_noise = dpg.add_node(ProvenanceNodeType.FILE, "file:/etc/ld.so.cache", "ld.so.cache")

    e_normal = dpg.add_edge(p_normal["id"], p_noise["id"], ProvenanceRelationType.SPAWNED, 1.0)
    e_noise = dpg.add_edge(p_noise["id"], f_noise["id"], ProvenanceRelationType.READ, 0.08)

    assert len(dpg.edges) == 2

    # Apply decay pruning
    pruned_count = dpg.apply_decay_pruning(min_weight_threshold=0.05, decay_factor=0.5)
    assert pruned_count >= 1
    assert len(dpg.edges) == 1
    assert dpg.edges[0]["id"] == e_normal["id"]
    print("    [+] test_semantic_decay_pruning passed")


def test_causal_traceback_patient_zero():
    dpg = DataProvenanceGraph(org_id="test_org_v26")
    # Build 3-hop attack chain: sshd -> bash -> python3 -> c2_socket
    n_sshd = dpg.add_node(ProvenanceNodeType.PROCESS, "proc:/usr/sbin/sshd", "sshd")
    n_bash = dpg.add_node(ProvenanceNodeType.PROCESS, "proc:/bin/bash", "bash")
    n_py = dpg.add_node(ProvenanceNodeType.PROCESS, "proc:/usr/bin/python3", "python3")
    n_sock = dpg.add_node(ProvenanceNodeType.SOCKET, "sock:185.220.101.5:443", "185.220.101.5:443")

    dpg.add_edge(n_sshd["id"], n_bash["id"], ProvenanceRelationType.SPAWNED, 1.0)
    dpg.add_edge(n_bash["id"], n_py["id"], ProvenanceRelationType.EXECUTED, 1.0)
    dpg.add_edge(n_py["id"], n_sock["id"], ProvenanceRelationType.CONNECTED_TO, 1.0)

    trace = dpg.causal_traceback(n_sock["id"], max_depth=5)
    assert trace["status"] == "CAUSAL_TRACE_RESOLVED"
    assert trace["patient_zero_node"]["name"] == "sshd"
    assert trace["depth"] == 3
    assert trace["latency_ms"] < 50.0
    print("    [+] test_causal_traceback_patient_zero passed")


def test_ocsf_event_ingestion_to_dpg():
    dpg = DataProvenanceGraph(org_id="test_org_v26")
    ocsf_proc = {
        "class_uid": 1007,
        "type": "process_activity",
        "process_name": "mimikatz.exe",
        "process_path": "C:\\temp\\mimikatz.exe",
        "parent_process": "cmd.exe",
        "command_line": "mimikatz.exe privilege::debug sekurlsa::logonpasswords"
    }
    edges = dpg.ingest_ocsf_event(ocsf_proc, device_id="dev-test-01")
    assert len(edges) == 1
    assert edges[0]["source_name"] == "cmd.exe"
    assert edges[0]["target_name"] == "mimikatz.exe"
    assert edges[0]["relation_type"] == ProvenanceRelationType.SPAWNED
    print("    [+] test_ocsf_event_ingestion_to_dpg passed")


# =========================================================================
# 2. SOAR PLAYBOOK ENGINE TESTS
# =========================================================================

def test_soar_playbook_yaml_parsing():
    parsed = SOARWorkflowEngine.parse_playbook_yaml(DEFAULT_ACTIVE_CONTAINMENT_PLAYBOOK_YAML)
    assert parsed["id"] == "playbook_active_containment_v1"
    assert "steps" in parsed["remediation_dag"]
    assert len(parsed["remediation_dag"]["steps"]) == 4
    print("    [+] test_soar_playbook_yaml_parsing passed")


def test_soar_trigger_condition_evaluation():
    playbook_spec = SOARWorkflowEngine.parse_playbook_yaml(DEFAULT_ACTIVE_CONTAINMENT_PLAYBOOK_YAML)

    # High risk execution event -> Should trigger
    high_risk_ctx = {"priority_score": 92.0, "tactic_id": "TA0002", "asset_criticality": 4}
    assert SOARWorkflowEngine.evaluate_trigger_conditions(playbook_spec, high_risk_ctx) is True

    # Low risk event -> Should not trigger
    low_risk_ctx = {"priority_score": 40.0, "tactic_id": "TA0002", "asset_criticality": 4}
    assert SOARWorkflowEngine.evaluate_trigger_conditions(playbook_spec, low_risk_ctx) is False

    # Disallowed tactic -> Should not trigger
    wrong_tactic_ctx = {"priority_score": 95.0, "tactic_id": "TA0043", "asset_criticality": 4}
    assert SOARWorkflowEngine.evaluate_trigger_conditions(playbook_spec, wrong_tactic_ctx) is False
    print("    [+] test_soar_trigger_condition_evaluation passed")


def test_soar_dag_execution_all_steps():
    playbook_spec = SOARWorkflowEngine.parse_playbook_yaml(DEFAULT_ACTIVE_CONTAINMENT_PLAYBOOK_YAML)
    threat_ctx = {
        "priority_score": 95.0,
        "tactic_id": "TA0002",
        "asset_criticality": 5,
        "process_name": "malicious_script.ps1"
    }

    exec_res = SOARWorkflowEngine.execute_playbook_dag(
        playbook_spec=playbook_spec,
        device_id="dev-sec-node-09",
        threat_context=threat_ctx
    )

    assert exec_res["status"] == "SUCCESS"
    assert exec_res["total_steps_executed"] == 4
    step_names = [s["name"] for s in exec_res["steps_executed"]]
    assert "Isolate Host Network" in step_names
    assert "Kill Process Lineage" in step_names
    assert "Inject Decoy Honey-Tokens" in step_names
    assert "Capture Forensic Dump" in step_names
    print("    [+] test_soar_dag_execution_all_steps passed")


# =========================================================================
# 3. TPM 2.0 HARDWARE MERKLE ATTESTATION TESTS
# =========================================================================

def test_merkle_tree_root_calculation():
    leaves = [
        {"alert_id": "a1", "technique": "T1059", "score": 90.0},
        {"alert_id": "a2", "technique": "T1190", "score": 85.0},
        {"alert_id": "a3", "technique": "T1078", "score": 70.0},
        {"alert_id": "a4", "technique": "T1486", "score": 100.0}
    ]
    tree = TPMMerkleTree.build_merkle_tree(leaves)
    assert tree["total_leaves"] == 4
    assert len(tree["root_hash"]) == 64
    assert len(tree["layers"]) == 3
    print("    [+] test_merkle_tree_root_calculation passed")


def test_merkle_tree_odd_leaves():
    leaves = [
        {"alert_id": "a1", "score": 80.0},
        {"alert_id": "a2", "score": 85.0},
        {"alert_id": "a3", "score": 90.0}
    ]
    tree = TPMMerkleTree.build_merkle_tree(leaves)
    assert tree["total_leaves"] == 3
    assert len(tree["root_hash"]) == 64
    print("    [+] test_merkle_tree_odd_leaves passed")


def test_tpm2_hardware_signing_and_pcr_attestation():
    root_hash = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
    org_id = "test_org_v26"

    attestation = TPMHardwareAttestationEngine.sign_merkle_root(root_hash, org_id)
    assert attestation["merkle_root_hash"] == root_hash
    assert attestation["tpm_hardware_signature"].startswith("TPM2_SIG_RSA2048_")
    assert len(attestation["pcr_composite_digest"]) == 64

    # Verification Success
    verify_res = TPMHardwareAttestationEngine.verify_hardware_attestation(
        merkle_root_hash=root_hash,
        tpm_signature=attestation["tpm_hardware_signature"],
        org_id=org_id,
        pcr_composite_digest=attestation["pcr_composite_digest"]
    )
    assert verify_res["is_attestation_valid"] is True
    assert verify_res["status"] == "HARDWARE_VERIFIED_TAMPER_PROOF"
    print("    [+] test_tpm2_hardware_signing_and_pcr_attestation passed")


def test_tpm2_signature_tamper_detection():
    root_hash = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
    org_id = "test_org_v26"
    attestation = TPMHardwareAttestationEngine.sign_merkle_root(root_hash, org_id)

    # Simulate DBA altering root hash
    tampered_root = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    verify_res = TPMHardwareAttestationEngine.verify_hardware_attestation(
        merkle_root_hash=tampered_root,
        tpm_signature=attestation["tpm_hardware_signature"],
        org_id=org_id,
        pcr_composite_digest=attestation["pcr_composite_digest"]
    )
    assert verify_res["is_attestation_valid"] is False
    assert verify_res["status"] == "TPM_SIGNATURE_MISMATCH_TAMPER_DETECTED"
    print("    [+] test_tpm2_signature_tamper_detection passed")


if __name__ == "__main__":
    print("=== [V26.0 Unit Test Suite - Provenance Graph, SOAR Engine & TPM 2.0] ===")
    test_provenance_node_and_edge_creation()
    test_semantic_decay_pruning()
    test_causal_traceback_patient_zero()
    test_ocsf_event_ingestion_to_dpg()
    test_soar_playbook_yaml_parsing()
    test_soar_trigger_condition_evaluation()
    test_soar_dag_execution_all_steps()
    test_merkle_tree_root_calculation()
    test_merkle_tree_odd_leaves()
    test_tpm2_hardware_signing_and_pcr_attestation()
    test_tpm2_signature_tamper_detection()
    print("\n>>> ALL V26.0 UNIT TESTS PASSED WITH 100% PRECISION! <<<")
