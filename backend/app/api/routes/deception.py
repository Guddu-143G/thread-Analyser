"""
API Routes for Active Defense & Managed Honey-Tokens (v5.0).
"""
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.db import get_db
from app.core.deps import get_current_user
from app.models.models import User
from app.deception.honey_tokens import HoneyTokenController
from app.security.ledger import CryptographicAuditLedger

router = APIRouter(prefix="/api/deception", tags=["deception"])


class GenerateDecoyRequest(BaseModel):
    type: str  # "AWS_IAM_KEY" | "WINDOWS_REGISTRY" | "SSH_CANARY_KEY"
    label: Optional[str] = "Production Decoy"


class TripDecoyRequest(BaseModel):
    token_uid: str
    attacker_ip: Optional[str] = "185.220.101.5"


@router.get("/tokens")
def list_honey_tokens(user: User = Depends(get_current_user)):
    """Returns all active and deployed canary decoy tokens for the tenant."""
    ctrl = HoneyTokenController(user.org_id)
    return {
        "active_tokens": ctrl.list_tokens(),
        "total_deployed": len(ctrl.list_tokens()),
    }


@router.post("/tokens/generate")
def generate_honey_token(
    payload: GenerateDecoyRequest,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """
    Generates and registers a new decoy token (AWS key, Registry key, SSH canary).
    """
    ctrl = HoneyTokenController(user.org_id)
    if payload.type == "AWS_IAM_KEY":
        token_record = ctrl.generate_decoy_aws_credentials(payload.label or "AWS Canary")
    elif payload.type == "WINDOWS_REGISTRY":
        token_record = ctrl.generate_windows_registry_decoy()
    elif payload.type == "SSH_CANARY_KEY":
        token_record = ctrl.generate_ssh_canary_key()
    else:
        raise HTTPException(status_code=400, detail="Invalid decoy token type.")

    CryptographicAuditLedger.append_audit_log(
        db=db,
        org_id=user.org_id,
        actor_user_id=user.id,
        action="honey_token_deployed",
        target=token_record["token_uid"],
        meta={"type": payload.type, "identifier": token_record.get("decoy_identifier")},
    )

    return token_record


@router.post("/tokens/trip")
def trip_honey_token(
    payload: TripDecoyRequest,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """
    Simulates adversary interaction with a canary token, triggering instant zero-false-positive SOAR response.
    """
    ctrl = HoneyTokenController(user.org_id)
    result = ctrl.trip_honey_token(
        token_uid=payload.token_uid,
        attacker_ip=payload.attacker_ip or "185.220.101.5",
    )

    if not result.get("success"):
        raise HTTPException(status_code=404, detail=result.get("error"))

    CryptographicAuditLedger.append_audit_log(
        db=db,
        org_id=user.org_id,
        actor_user_id=user.id,
        action="honey_token_tripped_breach",
        target=payload.token_uid,
        meta={"attacker_ip": payload.attacker_ip, "severity": "CRITICAL"},
    )

    return result


@router.post("/targeted-deploy")
def deploy_targeted_stack_decoy(
    payload: dict,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """
    Proactively deploys a targeted canary token tailored specifically to a detected tech stack.
    """
    technology = payload.get("technology", "PostgreSQL")
    hostname = payload.get("hostname", "prod-app-01")

    ctrl = HoneyTokenController(user.org_id)
    token_record = ctrl.generate_targeted_tech_decoy(technology=technology, hostname=hostname)

    CryptographicAuditLedger.append_audit_log(
        db=db,
        org_id=user.org_id,
        actor_user_id=user.id,
        action="targeted_tech_decoy_deployed",
        target=token_record["token_uid"],
        meta={"technology": technology, "identifier": token_record["decoy_identifier"]},
    )

    return {
        "status": "SUCCESS",
        "message": f"Successfully deployed targeted {technology} honey-token decoy ({token_record['type']}) on {hostname}.",
        "decoy": token_record,
    }

