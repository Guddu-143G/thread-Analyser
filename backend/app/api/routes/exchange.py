from fastapi import APIRouter, Depends
from typing import Any, Dict, Optional
from pydantic import BaseModel
from app.core.deps import get_current_user
from app.models.models import User
from app.security.zk_smpc import ZeroKnowledgeThreatExchange

router = APIRouter(prefix="/api/exchange", tags=["Decentralized zk-SMPC Threat Intelligence"])


class ProveIOCRequest(BaseModel):
    ioc_value: str
    confidence_score: Optional[float] = 0.95


class VerifyProofRequest(BaseModel):
    proof_bundle: Dict[str, Any]
    candidate_ioc: Optional[str] = None


@router.get("/certified-threats")
def get_certified_threat_feed(current_user: User = Depends(get_current_user)) -> Dict[str, Any]:
    """Returns active decentralized zk-SMPC certified threat exchange indicators."""
    return ZeroKnowledgeThreatExchange.get_certified_threat_feed()


@router.post("/prove-ioc")
def prove_ioc_presence(request: ProveIOCRequest, current_user: User = Depends(get_current_user)) -> Dict[str, Any]:
    """Generates zero-knowledge presence proof for an observed threat indicator."""
    exchange = ZeroKnowledgeThreatExchange(tenant_id=str(current_user.org_id))
    return exchange.generate_ioc_presence_proof(request.ioc_value, request.confidence_score or 0.95)


@router.post("/verify-proof")
def verify_peer_proof(request: VerifyProofRequest, current_user: User = Depends(get_current_user)) -> Dict[str, Any]:
    """Verifies cryptographic validity of a peer's zk-SMPC threat proof."""
    exchange = ZeroKnowledgeThreatExchange(tenant_id=str(current_user.org_id))
    return exchange.verify_mesh_proof(request.proof_bundle, request.candidate_ioc)
