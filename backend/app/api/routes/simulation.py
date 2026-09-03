"""
API Routes for Automated Breach & Attack Simulation (BAS) Engine (v5.0).
"""
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.db import get_db
from app.core.deps import get_current_user
from app.models.models import User
from app.simulation.bas_engine import BreachAttackSimulator
from app.security.ledger import CryptographicAuditLedger

router = APIRouter(prefix="/api/simulation", tags=["simulation"])


class RunSimulationRequest(BaseModel):
    suite_id: str  # e.g. "T1059.001", "T1110.001", "T1003.001"


@router.get("/suites")
def list_simulation_suites(user: User = Depends(get_current_user)):
    """Returns available Atomic Red Team simulation test suites."""
    return BreachAttackSimulator.list_simulation_suites()


@router.get("/history")
def list_simulation_history(
    limit: int = Query(default=10, ge=1, le=50),
    user: User = Depends(get_current_user),
):
    """Returns historical BAS test runs and validation verdicts."""
    return BreachAttackSimulator.list_history(limit)


@router.post("/run")
def execute_simulation(
    payload: RunSimulationRequest,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """
    Executes an atomic adversary simulation against the detection pipeline and checks SLA response.
    """
    result = BreachAttackSimulator.execute_atomic_simulation(
        suite_id=payload.suite_id,
        tenant_id=user.org_id,
        actor_email=user.email,
    )

    CryptographicAuditLedger.append_audit_log(
        db=db,
        org_id=user.org_id,
        actor_user_id=user.id,
        action="bas_atomic_simulation_executed",
        target=payload.suite_id,
        meta={
            "suite_name": result.get("suite_name"),
            "latency_ms": result.get("latency_ms"),
            "status": result.get("status"),
        },
    )

    return result
