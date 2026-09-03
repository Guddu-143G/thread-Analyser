import logging
from typing import List
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.core.db import get_db
from app.core.deps import get_current_user
from app.models.models import User, TenantChaosSimulation
from app.schemas.schemas import (
    ChaosInjectRequest,
    ChaosInjectResponse,
    ChaosSimulationOut,
    ResilienceReportOut,
    DefectTaxonomyItem,
    BugVersionProfileOut
)
from app.chaos.fault_injector import SecurityFaultInjector
from app.chaos.reporter import SecurityResilienceReporter
from app.chaos.bug_versioning import BugVersioningEngine, DEFECT_TAXONOMY_REGISTRY

router = APIRouter(prefix="/api/chaos", tags=["Security Chaos Engineering (v10)"])
logger = logging.getLogger("api.chaos")


@router.get("/taxonomy", response_model=List[DefectTaxonomyItem])
def get_defect_taxonomy(current_user: User = Depends(get_current_user)):
    """
    Returns the Enterprise Security Defect Taxonomy across all 5 classes.
    """
    return DEFECT_TAXONOMY_REGISTRY


@router.get("/version-profiles", response_model=List[BugVersionProfileOut])
def get_versioned_vulnerabilities(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Returns vulnerability profiles dynamically matched to the tenant's detected tech stack.
    """
    engine = BugVersioningEngine(tenant_uid=current_user.org_id, db=db)
    return engine.get_version_profiles()


@router.post("/inject", response_model=ChaosInjectResponse)
def inject_fault_simulation(
    req: ChaosInjectRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Triggers a synthetic defect simulation (CWE-639, CWE-120, CWE-119, CWE-1039, CWE-89, etc.),
    evaluates detection loop response time, and commits an audit record.
    """
    injector = SecurityFaultInjector(tenant_uid=current_user.org_id, db=db)
    result = injector.execute_simulation(
        bug_variety=req.bug_variety,
        target_org_id=req.target_org_id,
        target_mac=req.target_mac,
        baseline_rate_eps=req.baseline_rate_eps
    )
    return result


@router.get("/history", response_model=List[ChaosSimulationOut])
def get_simulation_history(
    limit: int = Query(50, le=200),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Returns the historical log of chaos simulations executed for the tenant.
    """
    sims = db.query(TenantChaosSimulation).filter(
        TenantChaosSimulation.org_id == current_user.org_id
    ).order_by(TenantChaosSimulation.injected_at.desc()).limit(limit).all()
    return sims


@router.get("/report", response_model=ResilienceReportOut)
def get_resilience_report(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Compiles and generates the Model Security Resilience Report,
    calculating the Defensive Coverage Index (DCI) and providing audit-ready Markdown.
    """
    reporter = SecurityResilienceReporter(tenant_uid=current_user.org_id, db=db)
    report = reporter.compile_model_report()
    return report
