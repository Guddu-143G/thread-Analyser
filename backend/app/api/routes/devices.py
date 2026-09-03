from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.db import get_db
from app.core.deps import get_current_user, require_role
from app.core.security import generate_api_key, hash_api_key
from app.models.models import Device, User, Role
from app.schemas.schemas import DeviceCreate, DeviceOut, DeviceCreatedOut
from app.security.ledger import CryptographicAuditLedger

router = APIRouter(prefix="/api/devices", tags=["devices"])


@router.get("", response_model=list[DeviceOut])
def list_devices(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    return db.query(Device).filter(Device.org_id == user.org_id).all()


@router.post("", response_model=DeviceCreatedOut)
def create_device(
    payload: DeviceCreate,
    db: Session = Depends(get_db),
    user: User = Depends(require_role(Role.admin, Role.analyst)),
):
    api_key = generate_api_key()
    device = Device(
        org_id=user.org_id,
        name=payload.name,
        platform=payload.platform or "unknown",
        api_key_hash=hash_api_key(api_key),
    )
    db.add(device)
    db.commit()
    db.refresh(device)

    CryptographicAuditLedger.append_audit_log(
        db=db,
        org_id=user.org_id,
        actor_user_id=user.id,
        action="device_created",
        target=device.id,
        meta={"name": device.name, "platform": device.platform},
    )

    return DeviceCreatedOut(
        id=device.id,
        name=device.name,
        platform=device.platform,
        last_seen=device.last_seen,
        created_at=device.created_at,
        api_key=api_key,
    )


@router.post("/{device_id}/rotate-key", response_model=DeviceCreatedOut)
def rotate_key(
    device_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(require_role(Role.admin, Role.analyst)),
):
    device = db.query(Device).filter(Device.id == device_id, Device.org_id == user.org_id).first()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    new_key = generate_api_key()
    device.api_key_hash = hash_api_key(new_key)
    db.commit()
    db.refresh(device)

    CryptographicAuditLedger.append_audit_log(
        db=db,
        org_id=user.org_id,
        actor_user_id=user.id,
        action="device_key_rotated",
        target=device.id,
        meta={"name": device.name},
    )

    return DeviceCreatedOut(
        id=device.id,
        name=device.name,
        platform=device.platform,
        last_seen=device.last_seen,
        created_at=device.created_at,
        api_key=new_key,
    )


@router.delete("/{device_id}")
def delete_device(
    device_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(require_role(Role.admin)),
):
    device = db.query(Device).filter(Device.id == device_id, Device.org_id == user.org_id).first()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    
    device_name = device.name
    db.delete(device)
    db.commit()

    CryptographicAuditLedger.append_audit_log(
        db=db,
        org_id=user.org_id,
        actor_user_id=user.id,
        action="device_deleted",
        target=device_id,
        meta={"name": device_name},
    )

    return {"status": "deleted"}
