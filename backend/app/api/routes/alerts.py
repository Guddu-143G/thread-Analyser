from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.core.db import get_db
from app.core.deps import get_current_user, require_role
from app.models.models import Alert, User, AlertStatus, Role
from app.schemas.schemas import AlertOut, AlertUpdate, MitigateRequest, MitigateResponse
from app.security.ledger import CryptographicAuditLedger

router = APIRouter(prefix="/api/alerts", tags=["alerts"])


@router.get("", response_model=list[AlertOut])
def list_alerts(
    status: str | None = Query(default=None),
    severity: str | None = Query(default=None),
    device_id: str | None = Query(default=None),
    search: str | None = Query(default=None),
    limit: int = Query(default=100, le=500),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    q = db.query(Alert).filter(Alert.org_id == user.org_id)
    if status:
        q = q.filter(Alert.status == status)
    if severity:
        q = q.filter(Alert.severity == severity)
    if device_id:
        q = q.filter(Alert.device_id == device_id)
    if search:
        search_pattern = f"%{search}%"
        q = q.filter(
            (Alert.title.ilike(search_pattern))
            | (Alert.description.ilike(search_pattern))
        )
    return q.order_by(Alert.created_at.desc()).limit(limit).all()


@router.get("/{alert_id}", response_model=AlertOut)
def get_alert(alert_id: str, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    alert = db.query(Alert).filter(Alert.id == alert_id, Alert.org_id == user.org_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert


@router.patch("/{alert_id}", response_model=AlertOut)
def update_alert(
    alert_id: str,
    payload: AlertUpdate,
    db: Session = Depends(get_db),
    user: User = Depends(require_role(Role.admin, Role.analyst)),
):
    alert = db.query(Alert).filter(Alert.id == alert_id, Alert.org_id == user.org_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    old_status = alert.status.value if hasattr(alert.status, "value") else str(alert.status)

    if payload.status:
        alert.status = payload.status
        if payload.status in (AlertStatus.resolved.value, AlertStatus.false_positive.value):
            alert.resolved_at = datetime.utcnow()

    audit_meta = {
        "old_status": old_status,
        "new_status": payload.status,
    }
    if payload.comment:
        audit_meta["comment"] = payload.comment
        # Append comment to alert evidence
        current_evidence = dict(alert.evidence or {})
        comments_list = current_evidence.get("triage_comments", [])
        comments_list.append({
            "user": user.email,
            "status": payload.status,
            "comment": payload.comment,
            "timestamp": datetime.utcnow().isoformat(),
        })
        current_evidence["triage_comments"] = comments_list
        alert.evidence = current_evidence

    db.commit()
    db.refresh(alert)

    CryptographicAuditLedger.append_audit_log(
        db=db,
        org_id=user.org_id,
        actor_user_id=user.id,
        action="alert_triage_transition",
        target=alert_id,
        meta=audit_meta,
    )

    return alert


@router.post("/{alert_id}/mitigate", response_model=MitigateResponse)
def trigger_mitigation(
    alert_id: str,
    payload: MitigateRequest,
    db: Session = Depends(get_db),
    user: User = Depends(require_role(Role.admin, Role.analyst)),
):
    alert = db.query(Alert).filter(Alert.id == alert_id, Alert.org_id == user.org_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    action_name = payload.action
    target_target = payload.target or alert.device_id or "target-host"

    # Orchestration execution record
    now = datetime.utcnow()
    current_evidence = dict(alert.evidence or {})
    mitigations = current_evidence.get("soar_mitigations", [])
    mitigations.append({
        "action": action_name,
        "target": target_target,
        "analyst": user.email,
        "timestamp": now.isoformat(),
        "status": "Dispatched",
        "comment": payload.comment,
    })
    current_evidence["soar_mitigations"] = mitigations
    alert.evidence = current_evidence

    # Automatically acknowledge alert if open
    if alert.status == AlertStatus.open:
        alert.status = AlertStatus.acknowledged

    db.commit()
    db.refresh(alert)

    CryptographicAuditLedger.append_audit_log(
        db=db,
        org_id=user.org_id,
        actor_user_id=user.id,
        action="soar_mitigation_triggered",
        target=f"{alert_id}:{action_name}",
        meta={"action": action_name, "target": target_target, "comment": payload.comment},
    )

    return MitigateResponse(
        status="Success",
        message=f"Mitigation '{action_name}' successfully dispatched for {target_target}.",
        alert_id=alert_id,
        action=action_name,
        mitigated_at=now,
    )


@router.post("/{alert_id}/ai-synthesize")
def synthesize_ai_playbook(
    alert_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """
    Cognitive Playbook Synthesizer:
    Evaluates the alert's telemetry, context, and MITRE mapping to dynamically
    generate a tailored multi-step containment JSON playbook.
    """
    from app.detection.ai_soar import AISoarOrchestrator

    alert = db.query(Alert).filter(Alert.id == alert_id, Alert.org_id == user.org_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    alert_dict = {
        "id": alert.id,
        "title": alert.title,
        "description": alert.description,
        "severity": alert.severity,
        "device_id": alert.device_id,
        "evidence": alert.evidence or {},
    }

    playbook = AISoarOrchestrator.synthesize_response_playbook(alert_dict)
    return playbook


@router.post("/{alert_id}/ai-execute")
def execute_ai_playbook(
    alert_id: str,
    payload: dict,
    db: Session = Depends(get_db),
    user: User = Depends(require_role(Role.admin, Role.analyst)),
):
    """
    Executes the dynamically synthesized cognitive playbook steps.
    """
    alert = db.query(Alert).filter(Alert.id == alert_id, Alert.org_id == user.org_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    now = datetime.utcnow()
    steps = payload.get("orchestrated_actions", [])
    signature = payload.get("playbook_signature", "unsigned")

    current_evidence = dict(alert.evidence or {})
    mitigations = current_evidence.get("soar_mitigations", [])

    for s in steps:
        mitigations.append({
            "action": s.get("action"),
            "target": s.get("target"),
            "step": s.get("step"),
            "analyst": f"AI-SOAR-Agent ({user.email})",
            "timestamp": now.isoformat(),
            "status": "Dispatched_Auto",
            "command": s.get("command_preview"),
            "signature": signature,
        })

    current_evidence["soar_mitigations"] = mitigations
    alert.evidence = current_evidence
    alert.status = AlertStatus.acknowledged

    db.commit()
    db.refresh(alert)

    CryptographicAuditLedger.append_audit_log(
        db=db,
        org_id=user.org_id,
        actor_user_id=user.id,
        action="ai_soar_playbook_executed",
        target=alert_id,
        meta={
            "steps_count": len(steps),
            "signature": signature,
            "risk_mitigation_score": payload.get("risk_mitigation_score"),
        },
    )

    return {
        "status": "Success",
        "message": f"Dispatched {len(steps)} AI-synthesized containment actions for alert {alert_id}.",
        "steps_executed": len(steps),
        "executed_at": now.isoformat(),
    }


@router.get("/{alert_id}/provenance")
def get_alert_provenance_dag(
    alert_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """
    Security Graph Analytics:
    Builds the system call provenance DAG for this incident and traces Patient Zero.
    """
    from app.detection.provenance_graph import ProvenanceGraphEngine

    alert = db.query(Alert).filter(Alert.id == alert_id, Alert.org_id == user.org_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    alert_dict = {
        "id": alert.id,
        "title": alert.title,
        "description": alert.description,
        "severity": alert.severity,
        "device_id": alert.device_id,
        "evidence": alert.evidence or {},
    }

    graph = ProvenanceGraphEngine.build_synthetic_provenance_for_alert(alert_dict)
    return graph


