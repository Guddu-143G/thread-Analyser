"""
API Routes for Dynamic Self-Healing Cloud Containment Mesh (v6.0).
"""
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.db import get_db
from app.core.deps import get_current_user
from app.models.models import User
from app.soar.healing_mesh import CloudContainmentMeshController
from app.security.ledger import CryptographicAuditLedger

router = APIRouter(prefix="/api/containment", tags=["containment"])


class CloudIsolateRequest(BaseModel):
    target_resource: str  # e.g. "i-0948271a0f8b" or "pod-prod-billing-srv-991"
    resource_type: Optional[str] = "EC2_INSTANCE"  # "EC2_INSTANCE" | "KUBERNETES_POD"


@router.post("/mesh/isolate-cloud")
def execute_cloud_mesh_containment(
    payload: CloudIsolateRequest,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """
    Executes real-time, API-driven isolation across AWS VPC Security Groups,
    Kubernetes NetworkPolicies, and IAM boundaries.
    """
    controller = CloudContainmentMeshController(tenant_id=user.org_id)
    res = controller.execute_full_cloud_mesh_lockdown(
        target_resource=payload.target_resource,
        resource_type=payload.resource_type or "EC2_INSTANCE",
    )

    CryptographicAuditLedger.append_audit_log(
        db=db,
        org_id=user.org_id,
        actor_user_id=user.id,
        action="cloud_mesh_self_healing_isolation_enforced",
        target=payload.target_resource,
        meta={"type": payload.resource_type, "layers_enforced": res.get("layers_enforced")},
    )

    return res
