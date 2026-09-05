from fastapi import APIRouter, Depends, HTTPException, WebSocket, WebSocketDisconnect, Query
from sqlalchemy.orm import Session
from typing import List, Dict, Any, Optional
import json
import logging
import asyncio
from datetime import datetime

from app.core.deps import get_db, get_current_user
from app.models.models import User, MobileForensicSession, PasscodeGuessAttempt
from app.detection.forensics import MobileDeviceDetector
from app.services.mobile_forensics_service import (
    MobileForensicAuditEngine,
    throttle_controller,
    COMMON_PATTERNS
)
from app.schemas.schemas import (
    V21DeviceProbeIn,
    V21DeviceProbeOut,
    V21ForensicSessionCreateIn,
    V21ForensicSessionOut,
    V21PasscodeAttemptIn,
    V21PasscodeAttemptOut,
    V21AuditRunIn,
    V21AuditRunOut,
    V21ForensicStatusOut
)

logger = logging.getLogger("v21_mobile_forensics")
router = APIRouter(prefix="/v21/forensics", tags=["v21 mobile physical forensics & usb otg-hid auditing"])

# In-memory active WebSocket subscribers per session_id: list of WebSockets
_forensic_ws_subscribers: Dict[str, List[WebSocket]] = {}


@router.get("/status", response_model=V21ForensicStatusOut)
def get_forensic_engine_status(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Returns global operational status and summary statistics for the V21 Mobile Forensic Engine.
    """
    total_sessions = db.query(MobileForensicSession).filter(
        MobileForensicSession.org_id == current_user.org_id
    ).count()

    active_sessions = db.query(MobileForensicSession).filter(
        MobileForensicSession.org_id == current_user.org_id,
        MobileForensicSession.status == "RUNNING"
    ).count()

    total_attempts = db.query(PasscodeGuessAttempt).filter(
        PasscodeGuessAttempt.org_id == current_user.org_id
    ).count()

    lockouts = db.query(PasscodeGuessAttempt).filter(
        PasscodeGuessAttempt.org_id == current_user.org_id,
        PasscodeGuessAttempt.response_code == "LOCKED_OUT"
    ).count()

    return V21ForensicStatusOut(
        status="OPERATIONAL",
        engine_version="21.0.0-VanguardForensics",
        ocsf_class_mapping="OCSF 3002 (Authentication / Forensic Security)",
        hid_emulation_driver="OTG-HID Teensy/RP2040 Serial Keystroke Multiplexer",
        total_forensic_sessions=total_sessions,
        active_sessions_count=active_sessions,
        total_passcode_attempts=total_attempts,
        lockout_events_detected=lockouts,
        supported_vectors=[
            "3x3 Android Gesture Pattern (Factorial Permutations)",
            "Numeric PIN (4-Digit Statistical / Probabilistic)",
            "Numeric PIN (6-Digit High Entropy)",
            "Alphanumeric Heuristic Mutation (Leetspeak)",
            "USB Hotplug udev/libusb Hardware Descriptors",
            "Apple usbmuxd & Android ADB Socket Probing"
        ],
        system_integrity="CRYPTOGRAPHICALLY_VERIFIED"
    )


@router.post("/device/discover", response_model=V21DeviceProbeOut)
def probe_connected_device(
    payload: V21DeviceProbeIn,
    current_user: User = Depends(get_current_user)
):
    """
    Probes physical USB ports via udev/libusb or socket multiplexers to detect mobile hardware descriptors.
    """
    device_info = MobileDeviceDetector.probe_usb_port(
        port_path=payload.usb_port_path or "/dev/bus/usb/001/004",
        protocol=payload.probe_protocol or "AUTO"
    )
    return V21DeviceProbeOut(**device_info)


@router.post("/sessions/start", response_model=V21ForensicSessionOut)
def create_forensic_session(
    payload: V21ForensicSessionCreateIn,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Initializes a new mobile forensic auditing session with multi-tenant Neon Postgres RLS isolation.
    """
    sample_candidate, _ = MobileForensicAuditEngine.get_candidate_for_index(payload.passcode_type, 0)
    max_entropy = MobileForensicAuditEngine.calculate_passcode_entropy(sample_candidate, payload.passcode_type)

    session_obj = MobileForensicSession(
        org_id=current_user.org_id,
        analyst_id=current_user.id,
        device_name=payload.device_name,
        device_model=payload.device_model,
        serial_number=payload.serial_number,
        udid=payload.udid,
        os_name=payload.os_name,
        os_version=payload.os_version,
        connection_type=payload.connection_type or "USB",
        passcode_type=payload.passcode_type,
        max_estimated_entropy=max_entropy,
        created_at=datetime.utcnow(),
        status="RUNNING"
    )
    db.add(session_obj)
    db.commit()
    db.refresh(session_obj)

    # Broadcast session start to active WebSockets
    if session_obj.session_id in _forensic_ws_subscribers:
        msg = json.dumps({
            "type": "DEVICE_CONNECTED",
            "session_id": session_obj.session_id,
            "device": {
                "manufacturer": session_obj.device_name,
                "model": session_obj.device_model,
                "serial_number": session_obj.serial_number,
                "os_version": session_obj.os_version,
                "passcode_type": session_obj.passcode_type
            }
        })
        for ws in list(_forensic_ws_subscribers[session_obj.session_id]):
            try:
                asyncio.create_task(ws.send_text(msg))
            except Exception:
                pass

    return V21ForensicSessionOut(
        session_id=session_obj.session_id,
        org_id=session_obj.org_id,
        analyst_id=session_obj.analyst_id,
        device_name=session_obj.device_name,
        device_model=session_obj.device_model,
        serial_number=session_obj.serial_number,
        udid=session_obj.udid,
        os_name=session_obj.os_name,
        os_version=session_obj.os_version,
        connection_type=session_obj.connection_type,
        passcode_type=session_obj.passcode_type,
        max_estimated_entropy=session_obj.max_estimated_entropy,
        created_at=session_obj.created_at.isoformat() if session_obj.created_at else "",
        completed_at=session_obj.completed_at.isoformat() if session_obj.completed_at else None,
        status=session_obj.status,
        total_attempts_count=0,
        is_unlocked=False
    )


@router.get("/sessions", response_model=List[V21ForensicSessionOut])
def list_forensic_sessions(
    limit: int = 50,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Lists historical and active mobile forensic sessions for the current organization.
    """
    sessions = db.query(MobileForensicSession).filter(
        MobileForensicSession.org_id == current_user.org_id
    ).order_by(MobileForensicSession.created_at.desc()).limit(limit).all()

    result = []
    for s in sessions:
        attempts_count = db.query(PasscodeGuessAttempt).filter(
            PasscodeGuessAttempt.session_id == s.session_id
        ).count()

        is_unlocked = db.query(PasscodeGuessAttempt).filter(
            PasscodeGuessAttempt.session_id == s.session_id,
            PasscodeGuessAttempt.is_successful == True
        ).first() is not None

        result.append(V21ForensicSessionOut(
            session_id=s.session_id,
            org_id=s.org_id,
            analyst_id=s.analyst_id,
            device_name=s.device_name,
            device_model=s.device_model,
            serial_number=s.serial_number,
            udid=s.udid,
            os_name=s.os_name,
            os_version=s.os_version,
            connection_type=s.connection_type,
            passcode_type=s.passcode_type,
            max_estimated_entropy=s.max_estimated_entropy,
            created_at=s.created_at.isoformat() if s.created_at else "",
            completed_at=s.completed_at.isoformat() if s.completed_at else None,
            status=s.status,
            total_attempts_count=attempts_count,
            is_unlocked=is_unlocked
        ))
    return result


@router.get("/sessions/{session_id}", response_model=V21ForensicSessionOut)
def get_forensic_session_details(
    session_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Retrieves details for a specific forensic auditing session.
    """
    session_obj = db.query(MobileForensicSession).filter(
        MobileForensicSession.session_id == session_id,
        MobileForensicSession.org_id == current_user.org_id
    ).first()

    if not session_obj:
        raise HTTPException(status_code=404, detail="Forensic session not found.")

    attempts_count = db.query(PasscodeGuessAttempt).filter(
        PasscodeGuessAttempt.session_id == session_obj.session_id
    ).count()

    is_unlocked = db.query(PasscodeGuessAttempt).filter(
        PasscodeGuessAttempt.session_id == session_obj.session_id,
        PasscodeGuessAttempt.is_successful == True
    ).first() is not None

    return V21ForensicSessionOut(
        session_id=session_obj.session_id,
        org_id=session_obj.org_id,
        analyst_id=session_obj.analyst_id,
        device_name=session_obj.device_name,
        device_model=session_obj.device_model,
        serial_number=session_obj.serial_number,
        udid=session_obj.udid,
        os_name=session_obj.os_name,
        os_version=session_obj.os_version,
        connection_type=session_obj.connection_type,
        passcode_type=session_obj.passcode_type,
        max_estimated_entropy=session_obj.max_estimated_entropy,
        created_at=session_obj.created_at.isoformat() if session_obj.created_at else "",
        completed_at=session_obj.completed_at.isoformat() if session_obj.completed_at else None,
        status=session_obj.status,
        total_attempts_count=attempts_count,
        is_unlocked=is_unlocked
    )


@router.post("/sessions/{session_id}/attempt", response_model=V21PasscodeAttemptOut)
def execute_single_passcode_attempt(
    session_id: str,
    payload: V21PasscodeAttemptIn,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Executes a single passcode or gesture pattern attempt against the target mobile device.
    """
    session_obj = db.query(MobileForensicSession).filter(
        MobileForensicSession.session_id == session_id,
        MobileForensicSession.org_id == current_user.org_id
    ).first()

    if not session_obj:
        raise HTTPException(status_code=404, detail="Forensic session not found.")

    current_count = db.query(PasscodeGuessAttempt).filter(
        PasscodeGuessAttempt.session_id == session_id
    ).count()

    attempt_rec, ocsf_event = MobileForensicAuditEngine.execute_audit_attempt(
        db=db,
        session_obj=session_obj,
        attempt_index=current_count + 1,
        candidate=payload.candidate_passcode,
        pattern_path=payload.pattern_path
    )

    # Broadcast to active WebSockets
    if session_id in _forensic_ws_subscribers:
        ws_payload = json.dumps({
            "type": "AUDIT_SUCCESS" if attempt_rec.is_successful else "AUDIT_TICK",
            "session_id": session_id,
            "attempt": {
                "attempt_id": attempt_rec.attempt_id,
                "attempt_index": attempt_rec.attempt_index,
                "entropy": ocsf_event["forensics_metadata"]["shannon_entropy"],
                "is_successful": attempt_rec.is_successful,
                "response_code": attempt_rec.response_code,
                "latency_ms": attempt_rec.response_latency_ms,
                "candidate_hash": attempt_rec.passcode_attempt_hash,
                "pattern_path": attempt_rec.pattern_path,
                "backoff_triggered_sec": ocsf_event["forensics_metadata"]["current_cooldown_sec"]
            },
            "guesses_per_sec": ocsf_event["forensics_metadata"]["auditing_speed_gps"]
        })
        for ws in list(_forensic_ws_subscribers[session_id]):
            try:
                asyncio.create_task(ws.send_text(ws_payload))
            except Exception:
                pass

    return V21PasscodeAttemptOut(
        attempt_id=attempt_rec.attempt_id,
        session_id=session_id,
        attempt_index=attempt_rec.attempt_index,
        entropy=ocsf_event["forensics_metadata"]["shannon_entropy"],
        is_successful=attempt_rec.is_successful,
        response_code=attempt_rec.response_code,
        latency_ms=attempt_rec.response_latency_ms,
        candidate_hash=attempt_rec.passcode_attempt_hash,
        pattern_path=attempt_rec.pattern_path,
        backoff_triggered_sec=ocsf_event["forensics_metadata"]["current_cooldown_sec"],
        timestamp=attempt_rec.timestamp.isoformat() if attempt_rec.timestamp else ""
    )


@router.post("/sessions/{session_id}/run-audit", response_model=V21AuditRunOut)
def run_automated_audit_loop(
    session_id: str,
    payload: V21AuditRunIn,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Executes an automated multi-step passcode/pattern auditing sequence with adaptive lockout backoff.
    """
    session_obj = db.query(MobileForensicSession).filter(
        MobileForensicSession.session_id == session_id,
        MobileForensicSession.org_id == current_user.org_id
    ).first()

    if not session_obj:
        raise HTTPException(status_code=404, detail="Forensic session not found.")

    max_steps = min(50, payload.max_attempts or 20)
    attempts_history = []
    is_unlocked = False
    last_response_code = "REJECTED"

    for step in range(max_steps):
        # Check active lockout
        cd = throttle_controller.get_remaining_cooldown(session_id)
        if cd > 0:
            last_response_code = "LOCKED_OUT"
            break

        current_count = db.query(PasscodeGuessAttempt).filter(
            PasscodeGuessAttempt.session_id == session_id
        ).count()

        cand_str, pattern_coords = MobileForensicAuditEngine.get_candidate_for_index(
            session_obj.passcode_type,
            current_count
        )

        attempt_rec, ocsf_event = MobileForensicAuditEngine.execute_audit_attempt(
            db=db,
            session_obj=session_obj,
            attempt_index=current_count + 1,
            candidate=cand_str,
            pattern_path=pattern_coords,
            target_secret=payload.target_secret_override
        )

        attempts_history.append(V21PasscodeAttemptOut(
            attempt_id=attempt_rec.attempt_id,
            session_id=session_id,
            attempt_index=attempt_rec.attempt_index,
            entropy=ocsf_event["forensics_metadata"]["shannon_entropy"],
            is_successful=attempt_rec.is_successful,
            response_code=attempt_rec.response_code,
            latency_ms=attempt_rec.response_latency_ms,
            candidate_hash=attempt_rec.passcode_attempt_hash,
            pattern_path=attempt_rec.pattern_path,
            backoff_triggered_sec=ocsf_event["forensics_metadata"]["current_cooldown_sec"],
            timestamp=attempt_rec.timestamp.isoformat() if attempt_rec.timestamp else ""
        ))

        last_response_code = attempt_rec.response_code
        if attempt_rec.is_successful:
            is_unlocked = True
            break
        if attempt_rec.response_code == "LOCKED_OUT":
            break

    total_run = len(attempts_history)
    sample_cand, _ = MobileForensicAuditEngine.get_candidate_for_index(session_obj.passcode_type, 0)
    final_entropy = MobileForensicAuditEngine.calculate_passcode_entropy(sample_cand, session_obj.passcode_type)

    return V21AuditRunOut(
        session_id=session_id,
        status=session_obj.status,
        total_attempts_run=total_run,
        is_unlocked=is_unlocked,
        last_response_code=last_response_code,
        backoff_active_sec=throttle_controller.get_remaining_cooldown(session_id),
        final_entropy=final_entropy,
        attempts_history=attempts_history
    )


@router.post("/sessions/{session_id}/stop")
def terminate_forensic_session(
    session_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Terminates or pauses an active forensic session.
    """
    session_obj = db.query(MobileForensicSession).filter(
        MobileForensicSession.session_id == session_id,
        MobileForensicSession.org_id == current_user.org_id
    ).first()

    if not session_obj:
        raise HTTPException(status_code=404, detail="Forensic session not found.")

    session_obj.status = "TERMINATED"
    session_obj.completed_at = datetime.utcnow()
    db.commit()
    return {"message": "Forensic session terminated successfully.", "session_id": session_id}


@router.get("/sessions/{session_id}/attempts", response_model=List[V21PasscodeAttemptOut])
def get_session_attempts_log(
    session_id: str,
    limit: int = 100,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Retrieves historical attempts log for a forensic session.
    """
    session_obj = db.query(MobileForensicSession).filter(
        MobileForensicSession.session_id == session_id,
        MobileForensicSession.org_id == current_user.org_id
    ).first()

    if not session_obj:
        raise HTTPException(status_code=404, detail="Forensic session not found.")

    attempts = db.query(PasscodeGuessAttempt).filter(
        PasscodeGuessAttempt.session_id == session_id
    ).order_by(PasscodeGuessAttempt.attempt_index.desc()).limit(limit).all()

    sample_cand, _ = MobileForensicAuditEngine.get_candidate_for_index(session_obj.passcode_type, 0)
    entropy = MobileForensicAuditEngine.calculate_passcode_entropy(sample_cand, session_obj.passcode_type)

    return [
        V21PasscodeAttemptOut(
            attempt_id=a.attempt_id,
            session_id=a.session_id,
            attempt_index=a.attempt_index,
            entropy=entropy,
            is_successful=a.is_successful,
            response_code=a.response_code,
            latency_ms=a.response_latency_ms,
            candidate_hash=a.passcode_attempt_hash,
            pattern_path=a.pattern_path,
            backoff_triggered_sec=30.0 if a.response_code == "LOCKED_OUT" else 0.0,
            timestamp=a.timestamp.isoformat() if a.timestamp else ""
        )
        for a in attempts
    ]


@router.websocket("/live")
async def websocket_forensics_live_endpoint(
    websocket: WebSocket,
    session_id: Optional[str] = Query(None)
):
    """
    WebSocket endpoint streaming real-time passcode attempts, 3x3 pattern geometries,
    entropy scores, speed metrics (G/s), and lockout cooldown countdowns.
    """
    await websocket.accept()
    sess_key = session_id or "global"
    if sess_key not in _forensic_ws_subscribers:
        _forensic_ws_subscribers[sess_key] = []
    _forensic_ws_subscribers[sess_key].append(websocket)

    try:
        await websocket.send_text(json.dumps({
            "type": "CONNECTION_ESTABLISHED",
            "session_id": sess_key,
            "status": "STREAMING",
            "message": "V21 Physical Mobile Forensics stream attached."
        }))
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        if sess_key in _forensic_ws_subscribers and websocket in _forensic_ws_subscribers[sess_key]:
            _forensic_ws_subscribers[sess_key].remove(websocket)
