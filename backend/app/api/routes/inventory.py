from typing import List
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.db import get_db
from app.core.deps import get_current_user
from app.models.models import User, TenantTechnologyInventory
from app.schemas.schemas import TechnologyInventoryOut

router = APIRouter(prefix="/api/inventory", tags=["inventory"])

@router.get("", response_model=List[TechnologyInventoryOut])
def get_inventory(
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user)
):
    """
    Returns the real-time extracted technology inventory for the tenant.
    """
    inventory = (
        db.query(TenantTechnologyInventory)
        .filter(TenantTechnologyInventory.org_id == user.org_id)
        .order_by(TenantTechnologyInventory.first_seen.desc())
        .all()
    )
    return inventory
