from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.db import get_db
from app.core.deps import get_current_user, require_role
from app.models.models import Rule, User, Role
from app.schemas.schemas import RuleCreate, RuleUpdate, RuleOut
from app.security.ledger import CryptographicAuditLedger

router = APIRouter(prefix="/api/rules", tags=["rules"])


@router.get("", response_model=list[RuleOut])
def list_rules(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    return (
        db.query(Rule)
        .filter((Rule.org_id == user.org_id) | (Rule.org_id.is_(None)))
        .order_by(Rule.created_at.desc())
        .all()
    )


@router.post("", response_model=RuleOut)
def create_rule(
    payload: RuleCreate,
    db: Session = Depends(get_db),
    user: User = Depends(require_role(Role.admin, Role.analyst)),
):
    rule = Rule(
        org_id=user.org_id,
        name=payload.name,
        description=payload.description,
        definition=payload.definition,
        severity=payload.severity,
        enabled=payload.enabled,
    )
    db.add(rule)
    db.commit()
    db.refresh(rule)

    CryptographicAuditLedger.append_audit_log(
        db=db,
        org_id=user.org_id,
        actor_user_id=user.id,
        action="rule_created",
        target=rule.id,
        meta={"name": payload.name, "severity": payload.severity},
    )

    return rule


@router.put("/{rule_id}", response_model=RuleOut)
def update_rule(
    rule_id: str,
    payload: RuleUpdate,
    db: Session = Depends(get_db),
    user: User = Depends(require_role(Role.admin, Role.analyst)),
):
    rule = db.query(Rule).filter(Rule.id == rule_id, Rule.org_id == user.org_id).first()
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found or not editable (built-in rules are read-only)")

    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(rule, field, value)

    db.commit()
    db.refresh(rule)

    CryptographicAuditLedger.append_audit_log(
        db=db,
        org_id=user.org_id,
        actor_user_id=user.id,
        action="rule_updated",
        target=rule_id,
        meta=payload.model_dump(exclude_unset=True),
    )

    return rule


@router.delete("/{rule_id}")
def delete_rule(
    rule_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(require_role(Role.admin)),
):
    rule = db.query(Rule).filter(Rule.id == rule_id, Rule.org_id == user.org_id).first()
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found or not editable")
    
    rule_name = rule.name
    db.delete(rule)
    db.commit()

    CryptographicAuditLedger.append_audit_log(
        db=db,
        org_id=user.org_id,
        actor_user_id=user.id,
        action="rule_deleted",
        target=rule_id,
        meta={"name": rule_name},
    )

    return {"status": "deleted"}
