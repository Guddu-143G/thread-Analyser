from fastapi import APIRouter, Depends
from typing import Any, Dict, List, Optional
from pydantic import BaseModel
from app.core.deps import get_current_user
from app.models.models import User
from app.simulation.threat_twin import AutonomousThreatTwinEngine

router = APIRouter(prefix="/api/twin", tags=["Autonomous Threat Twin"])


class TwinSimulateRequest(BaseModel):
    vector_id: str
    active_rules: Optional[List[str]] = None


@router.get("/topology")
def get_twin_topology(current_user: User = Depends(get_current_user)) -> Dict[str, Any]:
    """Returns digital twin topology and simulated attack vectors."""
    engine = AutonomousThreatTwinEngine(tenant_id=str(current_user.org_id))
    topology = engine.get_digital_twin_topology()
    topology["available_vectors"] = AutonomousThreatTwinEngine.AVAILABLE_ATTACK_VECTORS
    return topology


@router.post("/simulate-attack")
def simulate_twin_attack(request: TwinSimulateRequest, current_user: User = Depends(get_current_user)) -> Dict[str, Any]:
    """Executes safe sandboxed attack simulation against digital twin."""
    engine = AutonomousThreatTwinEngine(tenant_id=str(current_user.org_id))
    return engine.simulate_twin_attack(request.vector_id, request.active_rules)


@router.get("/coverage-gaps")
def evaluate_twin_coverage_gaps(current_user: User = Depends(get_current_user)) -> Dict[str, Any]:
    """Batch evaluates all cyber range vectors to detect SIEM rule gaps."""
    engine = AutonomousThreatTwinEngine(tenant_id=str(current_user.org_id))
    return engine.evaluate_all_twin_gaps()
