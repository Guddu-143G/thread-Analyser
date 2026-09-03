"""
API Routes for Autonomous Multi-Agent Threat Hunting Consensus (v6.0).
"""
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.db import get_db
from app.core.deps import get_current_user
from app.models.models import User
from app.hunting.agent_consensus import ConsensusVerificationEngine
from app.security.ledger import CryptographicAuditLedger

router = APIRouter(prefix="/api/hunting", tags=["hunting"])


class EvaluateEventRequest(BaseModel):
    event: Dict[str, Any]
    consensus_threshold: Optional[float] = 0.70


@router.get("/agents")
def list_hunting_agents(user: User = Depends(get_current_user)):
    """Returns persona AI threat hunting agents and focus areas."""
    engine = ConsensusVerificationEngine()
    return {"agents": engine.list_agents()}


@router.post("/evaluate")
def evaluate_event_consensus(
    payload: EvaluateEventRequest,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """
    Collects individual votes from Intrusion, Network, and Crypto AI agents
    and computes mathematical consensus.
    """
    engine = ConsensusVerificationEngine()
    res = engine.evaluate_event_consensus(payload.event, payload.consensus_threshold or 0.70)

    if res.get("consensus_reached"):
        CryptographicAuditLedger.append_audit_log(
            db=db,
            org_id=user.org_id,
            actor_user_id=user.id,
            action="multi_agent_consensus_alert_promoted",
            target="threat_hunting_pipeline",
            meta={
                "consensus_score": res.get("consensus_score"),
                "alert_votes": res.get("alert_votes_count"),
            },
        )
    return res


@router.post("/auto-hunt-sample")
def run_sample_autonomous_hunt(
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """
    Runs autonomous threat hunt sweep over realistic multi-stage intrusion telemetry.
    """
    engine = ConsensusVerificationEngine()
    sample_events = [
        {
            "class_uid": 1007,
            "process": {"cmd_line": "powershell.exe -NonI -W Hidden -EncodedCommand SQBFAFgA..."},
            "raw_unstructured": "powershell.exe -enc ... user=admin",
        },
        {
            "class_uid": 4001,
            "network_activity": {"dst_endpoint": {"ip": "185.220.101.5", "port": 4444}},
            "raw_unstructured": "Outbound TCP to 185.220.101.5:4444",
        },
        {
            "class_uid": 1001,
            "raw_unstructured": "sshd[102]: Accepted publickey for deploy from 192.168.1.5",
        },
    ]

    results = []
    for ev in sample_events:
        results.append(engine.evaluate_event_consensus(ev))

    return {
        "sweep_timestamp": "2026-09-01T00:00:00Z",
        "events_audited": len(sample_events),
        "promoted_incidents": sum(1 for r in results if r["consensus_reached"]),
        "evaluations": results,
    }
