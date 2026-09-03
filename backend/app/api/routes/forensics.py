from fastapi import APIRouter, Depends, Query
from typing import Any, Dict, Optional
from app.core.deps import get_current_user
from app.models.models import User
from app.forensics.time_travel import ForensicFlightRecorder

router = APIRouter(prefix="/api/forensics", tags=["Incident Time-Travel Forensics"])


@router.get("/timeline/{device_id}")
def get_device_forensic_timeline(
    device_id: str,
    alert_id: Optional[str] = Query(None),
    current_user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    """Retrieves deterministic timestamp-ordered mutation frames for incident flight recorder."""
    return ForensicFlightRecorder.get_incident_timeline(device_id=device_id, alert_id=alert_id)


@router.get("/replay/{alert_id}")
def get_alert_replay_frames(
    alert_id: str,
    device_id: Optional[str] = Query("srv-ecommerce-01"),
    current_user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    """Retrieves replay frames for a specific alert."""
    return ForensicFlightRecorder.get_incident_timeline(device_id=device_id or "srv-ecommerce-01", alert_id=alert_id)
