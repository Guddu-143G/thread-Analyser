from typing import Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.core.db import get_db
from app.core.deps import get_current_user
from app.models.models import LogEvent, User
from app.schemas.schemas import LogEventOut

router = APIRouter(prefix="/api/events", tags=["events"])


@router.get("", response_model=list[LogEventOut])
def list_events(
    search: Optional[str] = Query(default=None),
    event_type: Optional[str] = Query(default=None),
    src_ip: Optional[str] = Query(default=None),
    user_name: Optional[str] = Query(default=None, alias="user"),
    device_id: Optional[str] = Query(default=None),
    limit: int = Query(default=50, le=500),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    q = db.query(LogEvent).filter(LogEvent.org_id == user.org_id)

    if event_type:
        q = q.filter(LogEvent.event_type == event_type)
    if src_ip:
        q = q.filter(LogEvent.src_ip == src_ip)
    if user_name:
        q = q.filter(LogEvent.user == user_name)
    if device_id:
        q = q.filter(LogEvent.device_id == device_id)
    if search:
        search_pattern = f"%{search}%"
        q = q.filter(
            (LogEvent.raw.ilike(search_pattern))
            | (LogEvent.process.ilike(search_pattern))
            | (LogEvent.user.ilike(search_pattern))
            | (LogEvent.src_ip.ilike(search_pattern))
            | (LogEvent.dest_ip.ilike(search_pattern))
            | (LogEvent.event_type.ilike(search_pattern))
        )

    return q.order_by(LogEvent.ts.desc()).offset(offset).limit(limit).all()
