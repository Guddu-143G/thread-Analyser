from typing import Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.core.db import get_db
from app.core.deps import get_current_user
from app.models.models import AuditLog, User
from app.schemas.schemas import AuditLogOut, AuditVerificationResult
from app.security.ledger import CryptographicAuditLedger

router = APIRouter(prefix="/api/audit-logs", tags=["audit-logs"])


@router.get("", response_model=list[AuditLogOut])
def list_audit_logs(
    action: Optional[str] = Query(default=None),
    limit: int = Query(default=100, le=500),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    q = db.query(AuditLog).filter(AuditLog.org_id == user.org_id)
    if action:
        q = q.filter(AuditLog.action == action)
    return q.order_by(AuditLog.created_at.desc()).offset(offset).limit(limit).all()


@router.get("/verify", response_model=AuditVerificationResult)
def verify_audit_ledger(
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    records = (
        db.query(AuditLog)
        .filter(AuditLog.org_id == user.org_id)
        .order_by(AuditLog.created_at.asc())
        .all()
    )
    res = CryptographicAuditLedger.verify_chain(records)
    return AuditVerificationResult(
        valid=res["valid"],
        records_verified=res["records_verified"],
        latest_seal=res["latest_seal"],
        message=res["message"],
        tampered_index=res.get("tampered_index"),
        expected_seal=res.get("expected_seal"),
        stored_seal=res.get("stored_seal"),
    )
