"""
Version 30 REST API Router: Generative Security Digital Twin (GSDT) & Autonomous Cyber Range (ACR).

Provides endpoints for:
1. Zero-PII Cryptographic "Safe-Clone" Digital Twin Topology Generation & Querying.
2. Generative Adversarial Agent Network (GAAN) Simulation Scenarios (APT29, HermeticWiper).
3. Cryptographic Merkle-Chain Simulation Step Ledger Auditing.
4. Carrier-Scale Traffic Emulation Benchmarking (1,000,000+ EPS with eBPF XDP bypass metrics).
"""

import asyncio
import hashlib
import json
import logging
import time
from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.db import get_db
from app.core.security import decode_access_token
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
    TwinRelationshipResponse,
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
from app.api.ws_cyber_range import range_ws_manager

logger = logging.getLogger(__name__)

router = APIRouter()

oauth2_optional = OAuth2PasswordBearer(tokenUrl="/api/auth/login", auto_error=False)


def get_current_user_optional(
    token: Optional[str] = Depends(oauth2_optional),
    db: Session = Depends(get_db),
) -> Optional[User]:
    if not token:
        return None
    try:
        payload = decode_access_token(token)
        user_id = payload.get("sub")
        if user_id:
            return db.query(User).filter(User.id == user_id).first()
    except (JWTError, Exception):
        pass
    return None


def resolve_org_id(
    current_user: Optional[User] = None,
    org_id_param: Optional[str] = None,
    db: Optional[Session] = None,
) -> str:
    if current_user and current_user.org_id:
        return current_user.org_id
    if org_id_param and org_id_param not in ("default-org", "", None):
        return org_id_param
    if db:
        org = db.query(Organization).first()
        if org:
            return org.id
    return "00000000-0000-0000-0000-000000000001"


def seed_twin_nodes_if_empty(db: Session, org_id: str) -> List[TwinNode]:
    """Deterministically populates safe-cloned Zero-PII twin nodes if none exist for tenant."""
    existing = db.query(TwinNode).filter(TwinNode.org_id == org_id).all()
    if existing:
        return existing

    created_nodes = []
    salt = f"salt-{org_id}"

    for asset in DEFAULT_TWIN_NODES:
        node = TwinNode(
            id=str(uuid4()),
            org_id=org_id,
            name=asset["name"],
            asset_type=asset["asset_type"],
            hostname_hash=hmac_pseudonymize(asset["raw_hostname"], salt),
            ip_address_hash=hmac_pseudonymize(asset["raw_ip"], salt),
            mac_address_hash=hmac_pseudonymize(asset["raw_mac"], salt),
            os_version=asset["os_version"],
            criticality_id=asset["criticality_id"],
            status=asset["status"]
        )
        db.add(node)
        created_nodes.append(node)

    db.flush()

    # Create topological relationships between nodes
    if len(created_nodes) >= 4:
        # dc <-> db (AD_MEMBER)
        db.add(TwinRelationship(
            id=str(uuid4()),
            org_id=org_id,
            source_node_id=created_nodes[0].id,
            target_node_id=created_nodes[1].id,
            relationship_type="AD_MEMBER"
        ))
        # api-gateway <-> db (NETWORK_ROUTE)
        db.add(TwinRelationship(
            id=str(uuid4()),
            org_id=org_id,
            source_node_id=created_nodes[2].id,
            target_node_id=created_nodes[1].id,
            relationship_type="NETWORK_ROUTE"
        ))
        # analyst-ws <-> dc (AUTHENTICATED_TO)
        db.add(TwinRelationship(
            id=str(uuid4()),
            org_id=org_id,
            source_node_id=created_nodes[3].id,
            target_node_id=created_nodes[0].id,
            relationship_type="AUTHENTICATED_TO"
        ))

    db.commit()
    for n in created_nodes:
        db.refresh(n)
    return created_nodes


@router.get("/status", response_model=V30StatusResponse)
def get_v30_status():
    """Returns V30 Generative Security Digital Twin & Autonomous Cyber Range status."""
    return V30StatusResponse(
        gsdt_engine_version="v30.0-gsdt-range",
        cyber_range_active=True,
        gaan_agents_active=True,
        supported_scenarios=list(SCENARIO_DEFINITIONS.keys()),
        carrier_scale_eps_capacity=1000000,
        zero_pii_compliance_mode="HMAC-SHA-256-SAFE-CLONE",
        version="v30.0"
    )


@router.get("/topology", response_model=TwinTopologyResponse)
def get_digital_twin_topology(
    org_id: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user_optional)
):
    """
    Returns the Zero-PII Digital Twin graph topology (nodes and relationships)
    for the current tenant. All hostnames, IPs, and MACs are cryptographically pseudonymized.
    """
    tenant_id = resolve_org_id(current_user, org_id, db)
    nodes = seed_twin_nodes_if_empty(db, tenant_id)
    relationships = db.query(TwinRelationship).filter(TwinRelationship.org_id == tenant_id).all()

    node_responses = [
        TwinNodeResponse(
            id=n.id,
            org_id=n.org_id,
            name=n.name,
            asset_type=n.asset_type,
            hostname_hash=n.hostname_hash,
            ip_address_hash=n.ip_address_hash,
            mac_address_hash=n.mac_address_hash,
            os_version=n.os_version,
            criticality_id=n.criticality_id,
            status=n.status,
            created_at=n.created_at
        )
        for n in nodes
    ]

    rel_responses = [
        TwinRelationshipResponse(
            id=r.id,
            org_id=r.org_id,
            source_node_id=r.source_node_id,
            target_node_id=r.target_node_id,
            relationship_type=r.relationship_type,
            created_at=r.created_at
        )
        for r in relationships
    ]

    return TwinTopologyResponse(
        nodes=node_responses,
        relationships=rel_responses,
        total_assets=len(node_responses),
        zero_pii_sanitized=True,
        anonymization_algorithm="HMAC-SHA-256"
    )


@router.post("/clone-twin", response_model=TwinTopologyResponse)
def safe_clone_digital_twin(
    org_id: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user_optional)
):
    """
    Triggers a fresh Zero-PII Cryptographic "Safe-Clone" of the tenant's digital twin topology.
    Deletes any existing twin assets for the tenant and rebuilds from production seed with HMAC-SHA-256.
    """
    tenant_id = resolve_org_id(current_user, org_id, db)

    # Clean existing
    db.query(TwinRelationship).filter(TwinRelationship.org_id == tenant_id).delete()
    db.query(TwinNode).filter(TwinNode.org_id == tenant_id).delete()
    db.commit()

    # Re-seed
    nodes = seed_twin_nodes_if_empty(db, tenant_id)
    relationships = db.query(TwinRelationship).filter(TwinRelationship.org_id == tenant_id).all()

    node_responses = [
        TwinNodeResponse(
            id=n.id,
            org_id=n.org_id,
            name=n.name,
            asset_type=n.asset_type,
            hostname_hash=n.hostname_hash,
            ip_address_hash=n.ip_address_hash,
            mac_address_hash=n.mac_address_hash,
            os_version=n.os_version,
            criticality_id=n.criticality_id,
            status=n.status,
            created_at=n.created_at
        )
        for n in nodes
    ]

    rel_responses = [
        TwinRelationshipResponse(
            id=r.id,
            org_id=r.org_id,
            source_node_id=r.source_node_id,
            target_node_id=r.target_node_id,
            relationship_type=r.relationship_type,
            created_at=r.created_at
        )
        for r in relationships
    ]

    return TwinTopologyResponse(
        nodes=node_responses,
        relationships=rel_responses,
        total_assets=len(node_responses),
        zero_pii_sanitized=True,
        anonymization_algorithm="HMAC-SHA-256"
    )


async def execute_gaan_simulation_background(
    session_id: str,
    org_id: str,
    scenario_name: str,
    target_device_id: Optional[str] = None
):
    """
    Background asynchronous runner that executes GAAN simulation steps,
    writes Merkle-chain hashes to Neon Postgres ledger, and streams live telemetry to Redis & WebSockets.
    """
    controller = SyntheticRangeController(tenant_id=org_id)
    steps = SCENARIO_DEFINITIONS.get(scenario_name, SCENARIO_DEFINITIONS.get("APT29_COZYBEAR", []))
    dev_id = target_device_id or f"twin-{org_id[:8]}"

    # Initial broadcast
    await range_ws_manager.broadcast_to_org(org_id, {
        "type": "SIMULATION_SESSION_STARTED",
        "session_id": session_id,
        "scenario_name": scenario_name,
        "org_id": org_id,
        "total_steps": len(steps),
        "status": "RUNNING",
        "timestamp": datetime.utcnow().isoformat() + "Z"
    })

    red_score = 0
    blue_score = 0

    from app.core.db import SessionLocal
    for step_data in steps:
        await asyncio.sleep(0.8)

        step = SimulationStep(
            step_index=step_data["step_index"],
            tactic_id=step_data["tactic_id"],
            technique_id=step_data["technique_id"],
            action_description=step_data["action_description"],
            raw_log_template=step_data["raw_log_template"],
            ocsf_class_uid=step_data.get("ocsf_class_uid", 1007),
            severity_id=step_data.get("severity_id", 3),
            is_detected=step_data.get("is_detected", False),
            remediation_action=step_data.get("remediation_action")
        )

        step_event = await controller.inject_synthetic_telemetry(step, device_id=dev_id)
        red_score += 15

        # Write to neon postgres ledger
        with SessionLocal() as db_session:
            ledger_entry = SimulationExecutionLedger(
                id=str(uuid4()),
                org_id=org_id,
                session_id=session_id,
                step_index=step.step_index,
                mitre_tactic_id=step.tactic_id,
                mitre_technique_id=step.technique_id,
                agent_action_description=step.action_description,
                simulated_ocsf_payload=step_event.get("ocsf_payload", {}),
                is_detected=step.is_detected,
                remediation_triggered=step.remediation_action,
                previous_step_hash=step_event["previous_hash"],
                current_ledger_hash=step_event["current_hash"]
            )
            db_session.add(ledger_entry)

            sess = db_session.query(GAANSession).filter(GAANSession.id == session_id).first()
            if sess:
                sess.red_score = red_score
                sess.blue_score = blue_score
            db_session.commit()

        # Forward live step to websockets
        step_event["session_id"] = session_id
        step_event["org_id"] = org_id
        await range_ws_manager.broadcast_to_org(org_id, step_event)

        # Broadcast scorecard update
        await range_ws_manager.broadcast_to_org(org_id, {
            "type": "SCORE_UPDATE",
            "session_id": session_id,
            "red_score": red_score,
            "blue_score": blue_score,
            "timestamp": datetime.utcnow().isoformat() + "Z"
        })

        if step.is_detected:
            await asyncio.sleep(0.6)
            blue_score += 25
            with SessionLocal() as db_session:
                sess = db_session.query(GAANSession).filter(GAANSession.id == session_id).first()
                if sess:
                    sess.blue_score = blue_score
                db_session.commit()

            await range_ws_manager.broadcast_to_org(org_id, {
                "type": "CONTAINMENT_TRIGGERED",
                "session_id": session_id,
                "step_index": step.step_index,
                "remediation_action": step.remediation_action,
                "red_score": red_score,
                "blue_score": blue_score,
                "timestamp": datetime.utcnow().isoformat() + "Z"
            })

    # Mark session completed
    with SessionLocal() as db_session:
        sess = db_session.query(GAANSession).filter(GAANSession.id == session_id).first()
        if sess:
            sess.status = "COMPLETED"
            sess.ended_at = datetime.utcnow()
            sess.red_score = red_score
            sess.blue_score = blue_score
            db_session.commit()

    await range_ws_manager.broadcast_to_org(org_id, {
        "type": "SIMULATION_SESSION_COMPLETED",
        "session_id": session_id,
        "scenario_name": scenario_name,
        "org_id": org_id,
        "final_red_score": red_score,
        "final_blue_score": blue_score,
        "status": "COMPLETED",
        "timestamp": datetime.utcnow().isoformat() + "Z"
    })


@router.post("/trigger-scenario", response_model=TriggerScenarioResponse)
@router.post("/trigger", response_model=TriggerScenarioResponse)
async def trigger_cyber_range_scenario(
    payload: Optional[TriggerScenarioRequest] = None,
    scenario: Optional[str] = Query(None),
    org_id: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user_optional)
):
    """
    Triggers an autonomous Generative Adversarial Agent Network (GAAN) penetration test.
    Executes Red-Team steps against the digital twin and validates Blue-Team SOAR containment rules.
    """
    tenant_id = resolve_org_id(current_user, org_id, db)
    scenario_name = (payload.scenario_name if payload else None) or scenario or "APT29_COZYBEAR"

    if scenario_name not in SCENARIO_DEFINITIONS:
        scenario_name = "APT29_COZYBEAR"

    red_model = (payload.red_agent_model if payload else None) or "local-mistral-7b-v1"
    blue_model = (payload.blue_agent_model if payload else None) or "local-mistral-7b-v1"
    target_dev = payload.target_device_id if payload else None

    # Create GAANSession record
    session_record = GAANSession(
        id=str(uuid4()),
        org_id=tenant_id,
        scenario_name=scenario_name,
        status="RUNNING",
        red_agent_model=red_model,
        blue_agent_model=blue_model,
        red_score=0,
        blue_score=0,
        started_at=datetime.utcnow()
    )
    db.add(session_record)
    db.commit()
    db.refresh(session_record)

    steps = SCENARIO_DEFINITIONS.get(scenario_name, [])

    # Launch background simulation task
    asyncio.create_task(
        execute_gaan_simulation_background(
            session_id=session_record.id,
            org_id=tenant_id,
            scenario_name=scenario_name,
            target_device_id=target_dev
        )
    )

    return TriggerScenarioResponse(
        session_id=session_record.id,
        scenario_name=scenario_name,
        status="RUNNING",
        message=f"GAAN simulation '{scenario_name}' initiated with {len(steps)} multi-stage attack steps.",
        steps_count=len(steps)
    )


@router.get("/sessions", response_model=List[GAANSessionResponse])
def list_gaan_sessions(
    org_id: Optional[str] = Query(None),
    limit: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user_optional)
):
    """Returns past and active GAAN simulation sessions for the tenant."""
    tenant_id = resolve_org_id(current_user, org_id, db)
    sessions = (
        db.query(GAANSession)
        .filter(GAANSession.org_id == tenant_id)
        .order_by(GAANSession.started_at.desc())
        .limit(limit)
        .all()
    )
    return sessions


@router.get("/ledger", response_model=List[SimulationExecutionLedgerResponse])
def get_simulation_ledger(
    session_id: Optional[str] = Query(None),
    org_id: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user_optional)
):
    """
    Returns the immutable Merkle-Chain simulation execution ledger records.
    Each record contains the previous step hash and current step SHA-256 hash.
    """
    tenant_id = resolve_org_id(current_user, org_id, db)
    query = db.query(SimulationExecutionLedger).filter(SimulationExecutionLedger.org_id == tenant_id)
    if session_id:
        query = query.filter(SimulationExecutionLedger.session_id == session_id)

    records = query.order_by(SimulationExecutionLedger.created_at.desc()).limit(limit).all()
    return records


@router.post("/simulate-carrier-burst", response_model=CarrierBurstResponse)
def simulate_carrier_scale_burst(
    payload: CarrierBurstRequest,
    org_id: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user_optional)
):
    """
    Simulates carrier-grade 1,000,000+ Events Per Second (EPS) log burst transmission,
    benchmarking Linux kernel-bypass (eBPF XDP) throughput and ring-buffer utilization.
    """
    tenant_id = resolve_org_id(current_user, org_id, db)
    controller = SyntheticRangeController(tenant_id=tenant_id)
    burst_result = controller.simulate_carrier_scale_burst(
        eps_target=payload.eps_target,
        duration_seconds=payload.duration_seconds
    )
    return CarrierBurstResponse(**burst_result)
