"""
API Routes for Fully Homomorphic Encryption (FHE) Analytics-In-Use (v6.0).
"""
from typing import Any, Dict, List
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.db import get_db
from app.core.deps import get_current_user
from app.models.models import User
from app.analytics.fhe_engine import FHEAnalyticsEngine
from app.security.ledger import CryptographicAuditLedger

router = APIRouter(prefix="/api/fhe", tags=["fhe"])


class EncryptMetricRequest(BaseModel):
    value: int
    metric_name: str = "severity_score"


class HomomorphicSumRequest(BaseModel):
    ciphertexts: List[str]


@router.post("/encrypt")
def encrypt_fhe_metric(
    payload: EncryptMetricRequest,
    user: User = Depends(get_current_user),
):
    """Homomorphically encrypts an integer security metric."""
    engine = FHEAnalyticsEngine(tenant_id=user.org_id)
    return engine.encrypt_security_metric(payload.value, payload.metric_name)


@router.post("/aggregate")
def compute_fhe_aggregate(
    payload: HomomorphicSumRequest,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """
    Computes homomorphic sum over ciphertexts directly in ciphertext space.
    """
    engine = FHEAnalyticsEngine(tenant_id=user.org_id)
    res = engine.compute_homomorphic_sum(payload.ciphertexts)

    CryptographicAuditLedger.append_audit_log(
        db=db,
        org_id=user.org_id,
        actor_user_id=user.id,
        action="fhe_homomorphic_sum_computed",
        target="ciphertext_analytics_stream",
        meta={"records_count": len(payload.ciphertexts)},
    )
    return res


@router.get("/demo-stats")
def get_fhe_demo_stats(user: User = Depends(get_current_user)):
    """
    Demonstrates live homomorphic addition of sample security event counts.
    """
    engine = FHEAnalyticsEngine(tenant_id=user.org_id)
    sample_metrics = [12, 45, 88, 5, 23]
    encrypted_list = [engine.encrypt_security_metric(m)["ciphertext_b64"] for m in sample_metrics]

    agg_result = engine.compute_homomorphic_sum(encrypted_list)
    return {
        "raw_sample_metrics": sample_metrics,
        "raw_expected_sum": sum(sample_metrics),
        "encrypted_ciphertexts_count": len(encrypted_list),
        "fhe_aggregation": agg_result,
    }
