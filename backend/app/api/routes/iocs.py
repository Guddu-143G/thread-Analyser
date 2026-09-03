import csv
import io

from fastapi import APIRouter, Depends, HTTPException, UploadFile, File
from sqlalchemy.orm import Session

from app.core.db import get_db
from app.core.deps import get_current_user, require_role
from app.models.models import ThreatIndicator, User, Role
from app.schemas.schemas import IOCCreate, IOCOut
from app.security.ledger import CryptographicAuditLedger

router = APIRouter(prefix="/api/ioc", tags=["threat-intel"])


@router.get("", response_model=list[IOCOut])
def list_iocs(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    return (
        db.query(ThreatIndicator)
        .filter((ThreatIndicator.org_id == user.org_id) | (ThreatIndicator.org_id.is_(None)))
        .order_by(ThreatIndicator.created_at.desc())
        .all()
    )


@router.post("", response_model=IOCOut)
def create_ioc(
    payload: IOCCreate,
    db: Session = Depends(get_db),
    user: User = Depends(require_role(Role.admin, Role.analyst)),
):
    ioc = ThreatIndicator(
        org_id=user.org_id,
        type=payload.type,
        value=payload.value,
        severity=payload.severity,
        source="manual",
        description=payload.description,
    )
    db.add(ioc)
    db.commit()
    db.refresh(ioc)

    CryptographicAuditLedger.append_audit_log(
        db=db,
        org_id=user.org_id,
        actor_user_id=user.id,
        action="ioc_created",
        target=payload.value,
        meta={"type": payload.type, "severity": payload.severity},
    )

    return ioc


@router.post("/import-csv")
def import_csv(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    user: User = Depends(require_role(Role.admin, Role.analyst)),
):
    """Expects CSV columns: type,value,severity,description (header row required)."""
    content = file.file.read().decode("utf-8", errors="ignore")
    reader = csv.DictReader(io.StringIO(content))
    required = {"type", "value"}
    if not reader.fieldnames or not required.issubset({f.strip() for f in reader.fieldnames}):
        raise HTTPException(status_code=400, detail="CSV must have at least 'type' and 'value' columns")

    count = 0
    for row in reader:
        if not row.get("type") or not row.get("value"):
            continue
        ioc = ThreatIndicator(
            org_id=user.org_id,
            type=row["type"].strip(),
            value=row["value"].strip(),
            severity=(row.get("severity") or "medium").strip(),
            source="csv_import",
            description=(row.get("description") or "").strip() or None,
        )
        db.add(ioc)
        count += 1

    db.commit()

    CryptographicAuditLedger.append_audit_log(
        db=db,
        org_id=user.org_id,
        actor_user_id=user.id,
        action="ioc_csv_import",
        target="batch",
        meta={"count": count},
    )

    return {"imported": count}


@router.delete("/{ioc_id}")
def delete_ioc(
    ioc_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(require_role(Role.admin, Role.analyst)),
):
    ioc = (
        db.query(ThreatIndicator)
        .filter(ThreatIndicator.id == ioc_id, ThreatIndicator.org_id == user.org_id)
        .first()
    )
    if not ioc:
        raise HTTPException(status_code=404, detail="IOC not found or not editable (global IOCs are read-only)")
    
    val = ioc.value
    db.delete(ioc)
    db.commit()

    CryptographicAuditLedger.append_audit_log(
        db=db,
        org_id=user.org_id,
        actor_user_id=user.id,
        action="ioc_deleted",
        target=ioc_id,
        meta={"value": val},
    )

    return {"status": "deleted"}
