"""
API Routes for Ephemeral Polymorphic VPC Honeynet Fleet (v6.0).
"""
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.db import get_db
from app.core.deps import get_current_user
from app.models.models import User
from app.deception.honeynet import EphemeralHoneynetManager
from app.security.ledger import CryptographicAuditLedger

router = APIRouter(prefix="/api/honeynet", tags=["honeynet"])


class DeployDecoyRequest(BaseModel):
    profile_type: Optional[str] = "HTTP_WEB_PORTAL"  # "HTTP_WEB_PORTAL" | "CACHE_DATASTORE" | "DATABASE_REPLICA" | "API_GATEWAY"


class TripHoneypotRequest(BaseModel):
    decoy_id: str
    attacker_ip: Optional[str] = "10.0.14.88"


@router.get("/list")
def list_honeynet_fleet(user: User = Depends(get_current_user)):
    """Returns active polymorphic containerized honeypots deployed in VPC."""
    mgr = EphemeralHoneynetManager(tenant_id=user.org_id)
    return {
        "active_honeypots": mgr.list_active_honeypots(),
        "total_deployed": len(mgr.list_active_honeypots()),
    }


@router.post("/deploy")
def deploy_polymorphic_honeypot(
    payload: DeployDecoyRequest,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Dynamically spawns a polymorphic honeypot container in VPC."""
    mgr = EphemeralHoneynetManager(tenant_id=user.org_id)
    decoy = mgr.deploy_polymorphic_decoy(payload.profile_type)

    CryptographicAuditLedger.append_audit_log(
        db=db,
        org_id=user.org_id,
        actor_user_id=user.id,
        action="polymorphic_honeypot_deployed",
        target=decoy["decoy_id"],
        meta={"name": decoy["name"], "port": decoy["port"], "type": decoy["type"]},
    )
    return decoy


@router.post("/trip")
def trip_honeypot_probe(
    payload: TripHoneypotRequest,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """
    Simulates adversary port scan or probe against honeypot, triggering zero-false-positive lockdown.
    """
    mgr = EphemeralHoneynetManager(tenant_id=user.org_id)
    result = mgr.trip_honeypot(payload.decoy_id, payload.attacker_ip or "10.0.14.88")

    if not result.get("success"):
        raise HTTPException(status_code=404, detail=result.get("error"))

    CryptographicAuditLedger.append_audit_log(
        db=db,
        org_id=user.org_id,
        actor_user_id=user.id,
        action="honeypot_probe_engaged",
        target=payload.decoy_id,
        meta={"attacker_ip": payload.attacker_ip, "severity": "CRITICAL"},
    )
    return result
