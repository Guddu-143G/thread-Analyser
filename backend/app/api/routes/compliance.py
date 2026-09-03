"""
API Routes for Zero-Knowledge Compliance Attestations (zk-SNARKs - v4.0).
"""
from typing import Any, Dict
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.db import get_db
from app.core.deps import get_current_user
from app.models.models import User
from app.security.zkp_compliance import ZKComplianceAttestor
from app.security.ledger import CryptographicAuditLedger

router = APIRouter(prefix="/api/compliance", tags=["compliance"])


class ZKVerifyRequest(BaseModel):
    proof_bundle: Dict[str, Any]


@router.post("/zkp/generate")
def generate_zk_compliance_proof(
    sla_minutes: int = Query(default=15, ge=1, le=1440),
    time_window_days: int = Query(default=90, ge=1, le=365),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """
    Generates a succinct zero-knowledge proof (π) for SOC 2 Type II / ISO 27001
    compliance demonstrating SLA satisfaction without exposing raw logs.
    """
    proof = ZKComplianceAttestor.generate_sla_zk_proof(
        db=db,
        org_id=user.org_id,
        sla_minutes=sla_minutes,
        time_window_days=time_window_days,
    )

    CryptographicAuditLedger.append_audit_log(
        db=db,
        org_id=user.org_id,
        actor_user_id=user.id,
        action="zk_compliance_proof_generated",
        target=proof.get("public_inputs", {}).get("circuit_id", "zk-circuit"),
        meta={
            "sla_minutes": sla_minutes,
            "merkle_root": proof.get("public_inputs", {}).get("merkle_ledger_root_commitment"),
        },
    )

    return proof


@router.post("/zkp/verify")
def verify_zk_compliance_proof(
    payload: ZKVerifyRequest,
    user: User = Depends(get_current_user),
):
    """
    External Auditor Verification Endpoint:
    Mathematically verifies proof polynomial without accessing any tenant private database.
    """
    result = ZKComplianceAttestor.verify_sla_zk_proof(payload.proof_bundle)
    return result
