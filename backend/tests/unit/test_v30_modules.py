"""
Unit Test Suite for Version 30: Generative Security Digital Twin (GSDT) & Autonomous Cyber Range (ACR).
Tests Zero-PII HMAC Pseudonymization, Cryptographic Merkle-Chain Hash Chaining,
GAAN Adversarial Scenarios, and Carrier-Scale eBPF XDP Burst Benchmarking.
"""

import hashlib
import json
from datetime import datetime
from uuid import uuid4

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.db import Base
from app.models.models import (
    GAANSession,
    Organization,
    SimulationExecutionLedger,
    TwinNode,
    TwinRelationship,
    User,
)
from app.schemas.schemas import (
    CarrierBurstRequest,
    CarrierBurstResponse,
    GAANSessionResponse,
    SimulationExecutionLedgerResponse,
    TriggerScenarioRequest,
    TriggerScenarioResponse,
    TwinNodeResponse,
    TwinTopologyResponse,
    V30StatusResponse,
)
from app.services.cyber_range import (
    DEFAULT_TWIN_NODES,
    SCENARIO_DEFINITIONS,
    SimulationStep,
    SyntheticRangeController,
    hmac_pseudonymize,
)


def get_test_db():
    """Instantiate isolated in-memory SQLite session for testing."""
    engine = create_engine("sqlite:///:memory:", echo=False)
    Base.metadata.create_all(bind=engine)
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    db = TestingSessionLocal()

    org = Organization(id="test_org_v30", name="V30 Test Org")
    db.add(org)
    user = User(
        id="test_user_v30",
        org_id=org.id,
        email="ciso@v30.test",
        hashed_password="mock_hashed_pw"
    )
    db.add(user)
    db.commit()
    return db


def test_hmac_pseudonymization_zero_pii():
    """Verify deterministic HMAC-SHA-256 pseudonymization hides raw hostnames, IPs, and MACs."""
    raw_ip = "10.200.0.1"
    raw_host = "dc01.corp.internal"
    raw_mac = "00:1A:2B:3C:4D:5E"
    salt_a = "tenant-salt-alpha"
    salt_b = "tenant-salt-beta"

    hash_a = hmac_pseudonymize(raw_ip, salt_a)
    hash_a2 = hmac_pseudonymize(raw_ip, salt_a)
    hash_b = hmac_pseudonymize(raw_ip, salt_b)

    # Determinism check
    assert hash_a == hash_a2
    assert len(hash_a) == 64
    assert hash_a != raw_ip

    # Multi-tenant isolation check (different salt = completely different hash)
    assert hash_a != hash_b

    # Hostname & MAC check
    host_hash = hmac_pseudonymize(raw_host, salt_a)
    mac_hash = hmac_pseudonymize(raw_mac, salt_a)
    assert len(host_hash) == 64
    assert len(mac_hash) == 64
    assert host_hash != mac_hash


def test_synthetic_range_controller_merkle_chaining():
    """Verify cryptographic Merkle-Chain hash computation across successive execution steps."""
    controller = SyntheticRangeController(tenant_id="tenant-merkle-test")
    initial_hash = "0000000000000000000000000000000000000000000000000000000000000000"
    assert controller.last_step_hash == initial_hash

    payload_step1 = '{"step": 1, "tactic": "TA0001"}'
    hash_1 = controller.generate_merkle_hash(step_index=1, payload=payload_step1, previous_hash=initial_hash)
    assert len(hash_1) == 64
    assert hash_1 != initial_hash

    payload_step2 = '{"step": 2, "tactic": "TA0002"}'
    hash_2 = controller.generate_merkle_hash(step_index=2, payload=payload_step2, previous_hash=hash_1)
    assert len(hash_2) == 64
    assert hash_2 != hash_1

    # Verify tampering detection: re-calculating hash_2 with corrupted hash_1 yields different hash
    corrupted_hash_1 = hash_1[:-1] + "f"
    hasher = hashlib.sha256()
    hasher.update(f"2{corrupted_hash_1}{payload_step2}".encode("utf-8"))
    tampered_hash_2 = hasher.hexdigest()
    assert tampered_hash_2 != hash_2


def test_scenario_definitions_integrity():
    """Verify pre-defined GAAN scenario libraries for APT29 and HermeticWiper."""
    assert "APT29_COZYBEAR" in SCENARIO_DEFINITIONS
    assert "HERMETIC_WIPER" in SCENARIO_DEFINITIONS

    apt_steps = SCENARIO_DEFINITIONS["APT29_COZYBEAR"]
    assert len(apt_steps) == 5
    for s in apt_steps:
        assert "step_index" in s
        assert s["tactic_id"].startswith("TA")
        assert s["technique_id"].startswith("T")
        assert "raw_log_template" in s
        assert len(s["raw_log_template"]) > 20
        # Verify valid JSON parse
        parsed = json.loads(s["raw_log_template"].replace("[TENANT_ID]", "tenant-1").replace("[DEVICE_ID]", "dev-1"))
        assert "metadata" in parsed

    wiper_steps = SCENARIO_DEFINITIONS["HERMETIC_WIPER"]
    assert len(wiper_steps) == 4
    assert wiper_steps[0]["tactic_id"] == "TA0002"


def test_carrier_burst_simulation_benchmark():
    """Verify carrier-grade 1,000,000+ EPS transmission benchmark and eBPF XDP telemetry."""
    controller = SyntheticRangeController(tenant_id="tenant-carrier-test")
    burst = controller.simulate_carrier_scale_burst(eps_target=1000000, duration_seconds=5)

    assert burst["status"] == "BURST_COMPLETED"
    assert burst["eps_achieved"] >= 950000
    assert burst["total_packets_transmitted"] >= 4500000
    assert burst["ebpf_xdp_bypass_active"] is True
    assert burst["ring_buffer_utilization_pct"] > 0
    assert burst["kernel_bypass_latency_us"] < 10.0
    assert burst["pipeline_drop_rate"] == 0.0


def test_twin_models_and_db_persistence():
    """Verify SQLite persistence for TwinNode, TwinRelationship, GAANSession, and SimulationExecutionLedger."""
    db = get_test_db()
    org_id = "test_org_v30"

    # 1. Create Nodes
    node1 = TwinNode(
        id=str(uuid4()),
        org_id=org_id,
        name="Domain Controller",
        asset_type="DOMAIN_CONTROLLER",
        hostname_hash="1111111111111111111111111111111111111111111111111111111111111111",
        ip_address_hash="2222222222222222222222222222222222222222222222222222222222222222",
        mac_address_hash="3333333333333333333333333333333333333333333333333333333333333333",
        os_version="Windows Server 2022",
        criticality_id=5,
        status="SAFE"
    )
    node2 = TwinNode(
        id=str(uuid4()),
        org_id=org_id,
        name="Database Primary",
        asset_type="DATABASE_SERVER",
        hostname_hash="4444444444444444444444444444444444444444444444444444444444444444",
        ip_address_hash="5555555555555555555555555555555555555555555555555555555555555555",
        mac_address_hash="6666666666666666666666666666666666666666666666666666666666666666",
        os_version="Ubuntu 22.04 LTS",
        criticality_id=4,
        status="SAFE"
    )
    db.add(node1)
    db.add(node2)
    db.commit()

    # 2. Create Relationship
    rel = TwinRelationship(
        id=str(uuid4()),
        org_id=org_id,
        source_node_id=node1.id,
        target_node_id=node2.id,
        relationship_type="AD_MEMBER"
    )
    db.add(rel)
    db.commit()

    assert len(node1.source_relationships) == 1
    assert node1.source_relationships[0].target_node_id == node2.id

    # 3. Create GAAN Session
    session = GAANSession(
        id=str(uuid4()),
        org_id=org_id,
        scenario_name="APT29_COZYBEAR",
        status="RUNNING",
        red_agent_model="local-mistral-7b-v1",
        blue_agent_model="local-mistral-7b-v1",
        red_score=15,
        blue_score=25
    )
    db.add(session)
    db.commit()

    # 4. Create Ledger Entry
    ledger = SimulationExecutionLedger(
        id=str(uuid4()),
        org_id=org_id,
        session_id=session.id,
        step_index=1,
        mitre_tactic_id="TA0001",
        mitre_technique_id="T1190",
        agent_action_description="Exploitation of Public-Facing App",
        simulated_ocsf_payload={"class_uid": 3002, "msg": "test"},
        is_detected=True,
        remediation_triggered="Network isolation",
        previous_step_hash="0000000000000000000000000000000000000000000000000000000000000000",
        current_ledger_hash="abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdef"
    )
    db.add(ledger)
    db.commit()

    assert len(session.steps) == 1
    assert session.steps[0].mitre_tactic_id == "TA0001"
    assert session.steps[0].is_detected is True


def test_v30_pydantic_schemas_serialization():
    """Verify serialization of all V30 schemas."""
    status_resp = V30StatusResponse(
        gsdt_engine_version="v30.0-gsdt-range",
        cyber_range_active=True,
        gaan_agents_active=True,
        supported_scenarios=["APT29_COZYBEAR", "HERMETIC_WIPER"],
        carrier_scale_eps_capacity=1000000,
        zero_pii_compliance_mode="HMAC-SHA-256-SAFE-CLONE",
        version="v30.0"
    )
    assert status_resp.version == "v30.0"
    assert len(status_resp.supported_scenarios) == 2

    burst_resp = CarrierBurstResponse(
        status="BURST_COMPLETED",
        eps_achieved=1012400,
        total_packets_transmitted=5062000,
        ebpf_xdp_bypass_active=True,
        ring_buffer_utilization_pct=54.2,
        kernel_bypass_latency_us=2.4,
        duration_seconds=5,
        pipeline_drop_rate=0.0
    )
    assert burst_resp.eps_achieved == 1012400
    assert burst_resp.ebpf_xdp_bypass_active is True
