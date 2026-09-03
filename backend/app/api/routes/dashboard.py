from sqlalchemy import func
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.db import get_db
from app.core.deps import get_current_user
from app.models.models import Alert, LogEvent, User, AlertStatus
from app.schemas.schemas import DashboardStats

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])


@router.get("/stats", response_model=DashboardStats)
def stats(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    org_id = user.org_id

    total_events = db.query(func.count(LogEvent.id)).filter(LogEvent.org_id == org_id).scalar() or 0
    total_alerts = db.query(func.count(Alert.id)).filter(Alert.org_id == org_id).scalar() or 0
    open_alerts = (
        db.query(func.count(Alert.id))
        .filter(Alert.org_id == org_id, Alert.status == AlertStatus.open)
        .scalar()
        or 0
    )

    sev_rows = (
        db.query(Alert.severity, func.count(Alert.id))
        .filter(Alert.org_id == org_id)
        .group_by(Alert.severity)
        .all()
    )
    alerts_by_severity = {sev.value if hasattr(sev, "value") else sev: cnt for sev, cnt in sev_rows}

    top_devices_rows = (
        db.query(Alert.device_id, func.count(Alert.id).label("cnt"))
        .filter(Alert.org_id == org_id, Alert.device_id.isnot(None))
        .group_by(Alert.device_id)
        .order_by(func.count(Alert.id).desc())
        .limit(5)
        .all()
    )
    top_devices = [{"device_id": d, "alert_count": c} for d, c in top_devices_rows]

    top_ip_rows = (
        db.query(LogEvent.src_ip, func.count(LogEvent.id).label("cnt"))
        .filter(LogEvent.org_id == org_id, LogEvent.src_ip.isnot(None))
        .group_by(LogEvent.src_ip)
        .order_by(func.count(LogEvent.id).desc())
        .limit(5)
        .all()
    )
    top_source_ips = [{"ip": ip, "event_count": c} for ip, c in top_ip_rows]

    return DashboardStats(
        total_events=total_events,
        total_alerts=total_alerts,
        open_alerts=open_alerts,
        alerts_by_severity=alerts_by_severity,
        top_devices=top_devices,
        top_source_ips=top_source_ips,
    )
