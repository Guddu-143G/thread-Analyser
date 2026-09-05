"""
Version 29 REST API Router: Sovereign Synthetic Telemetry Generation & Purple-Team Threat Emulation.

Provides endpoints for:
1. Synthetic OCSF Telemetry Generation with diurnal temporal curves & noise injection.
2. ML Cold-Start Bootstrapping for tenant Isolation Forest baselines.
3. Purple-Team Attack Profile Management and Execution Triggers.
4. Historical Simulation Run Auditing.
5. KEDA & GitOps Multi-Tenant Deployment Configuration Extraction.
"""

import asyncio
import json
import logging
import time
from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.db import get_db
from app.core.deps import get_current_user
from app.models.models import LogEvent, Organization, SimulationProfile, SimulationRun, SimulationStep, User
from app.schemas.schemas import (
    KedaScaleConfigResponse,
    SimulationProfileCreate,
    SimulationProfileResponse,
    SimulationRunResponse,
    SimulationStepCreate,
    SimulationStepResponse,
    SimulationTriggerRequest,
    SimulationTriggerResponse,
    SyntheticGenerationRequest,
    SyntheticGenerationResponse,
    V29StatusResponse,
)
from app.detection.synthetic_generator import MOCK_USER_CLUSTERS, sovereign_stg_generator
from app.api.ws_simulation import emulation_broker

logger = logging.getLogger(__name__)

router = APIRouter()


def seed_default_simulation_profiles(db: Session):
    """Auto-seeds global pre-configured Purple-Team emulation profiles if they do not exist."""
    try:
        existing_apt = db.query(SimulationProfile).filter(SimulationProfile.threat_actor == "APT29").first()
        if not existing_apt:
            apt_profile = SimulationProfile(
                id=str(uuid4()),
                org_id=None,
                name="APT29 (CozyBear) Spy Path",
                description="Simulates covert initial access, obfuscated PowerShell execution, LSASS credential dumping, and high-entropy exfiltration.",
                threat_actor="APT29",
                is_active=True
            )
            db.add(apt_profile)
            db.flush()

            steps_apt = [
                SimulationStep(
                    profile_id=apt_profile.id,
                    step_order=1,
                    delay_seconds=2,
                    ocsf_class_uid=3002,
                    mock_log_payload={
                        "metadata": {"class_name": "AUTHENTICATION", "class_uid": 3002, "version": "1.2.0"},
                        "category_uid": 3,
                        "severity_id": 1,
                        "message": "sshd: Accepted publickey for external_admin from 185.190.140.2 port 48120 ssh2",
                        "src_endpoint": {"ip": "185.190.140.2", "port": 48120},
                        "actor": {"user": {"name": "external_admin"}}
                    }
                ),
                SimulationStep(
                    profile_id=apt_profile.id,
                    step_order=2,
                    delay_seconds=3,
                    ocsf_class_uid=1007,
                    mock_log_payload={
                        "metadata": {"class_name": "PROCESS_ACTIVITY", "class_uid": 1007, "version": "1.2.0"},
                        "category_uid": 1,
                        "severity_id": 3,
                        "message": "powershell.exe -EncodedCommand IAAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAFMAeQBzAHQAZQBtAC4ATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAAp...",
                        "process": {"name": "powershell.exe", "cmd_line": "powershell.exe -EncodedCommand IAAgACgATgBlAHcALQBP..."}
                    }
                ),
                SimulationStep(
                    profile_id=apt_profile.id,
                    step_order=3,
                    delay_seconds=4,
                    ocsf_class_uid=1007,
                    mock_log_payload={
                        "metadata": {"class_name": "PROCESS_ACTIVITY", "class_uid": 1007, "version": "1.2.0"},
                        "category_uid": 1,
                        "severity_id": 4,
                        "message": "lsass.exe read access by unknown process (mimikatz.exe)",
                        "process": {"name": "mimikatz.exe", "cmd_line": "privilege::debug sekurlsa::logonpasswords"}
                    }
                ),
                SimulationStep(
                    profile_id=apt_profile.id,
                    step_order=4,
                    delay_seconds=3,
                    ocsf_class_uid=4001,
                    mock_log_payload={
                        "metadata": {"class_name": "NETWORK_ACTIVITY", "class_uid": 4001, "version": "1.2.0"},
                        "category_uid": 4,
                        "severity_id": 4,
                        "message": "High-entropy bulk outbound transfer (84.2 MB) to un-flagged C2 IP 185.190.140.2:4444",
                        "dst_endpoint": {"ip": "185.190.140.2", "port": 4444},
                        "traffic": {"bytes": 88289120}
                    }
                )
            ]
            for s in steps_apt:
                db.add(s)

        existing_wiper = db.query(SimulationProfile).filter(SimulationProfile.threat_actor == "HermeticWiper").first()
        if not existing_wiper:
            wiper_profile = SimulationProfile(
                id=str(uuid4()),
                org_id=None,
                name="HermeticWiper Ransomware Path",
                description="Simulates rapid execution via weaponized attachment, registry persistence, and high-frequency destructive encryption activity.",
                threat_actor="HermeticWiper",
                is_active=True
            )
            db.add(wiper_profile)
            db.flush()

            steps_wiper = [
                SimulationStep(
                    profile_id=wiper_profile.id,
                    step_order=1,
                    delay_seconds=2,
                    ocsf_class_uid=1007,
                    mock_log_payload={
                        "metadata": {"class_name": "PROCESS_ACTIVITY", "class_uid": 1007, "version": "1.2.0"},
                        "category_uid": 1,
                        "severity_id": 2,
                        "message": "AcroRd32.exe spawned cmd.exe /c start vssadmin.exe delete shadows /all /quiet",
                        "process": {"name": "cmd.exe", "cmd_line": "cmd.exe /c start vssadmin.exe delete shadows /all /quiet"}
                    }
                ),
                SimulationStep(
                    profile_id=wiper_profile.id,
                    step_order=2,
                    delay_seconds=3,
                    ocsf_class_uid=1001,
                    mock_log_payload={
                        "metadata": {"class_name": "FILE_ACTIVITY", "class_uid": 1001, "version": "1.2.0"},
                        "category_uid": 1,
                        "severity_id": 3,
                        "message": "Registry Key Created: HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\HermeticService",
                        "file": {"name": "HermeticService.exe", "path": "C:\\Windows\\System32\\HermeticService.exe"}
                    }
                ),
                SimulationStep(
                    profile_id=wiper_profile.id,
                    step_order=3,
                    delay_seconds=4,
                    ocsf_class_uid=1001,
                    mock_log_payload={
                        "metadata": {"class_name": "FILE_ACTIVITY", "class_uid": 1001, "version": "1.2.0"},
                        "category_uid": 1,
                        "severity_id": 4,
                        "message": "High-frequency file modification (1,480 files/sec) replacing file headers with encrypted payloads",
                        "file": {"path": "C:\\Users\\Public\\Documents\\*", "activity_id": 2}
                    }
                )
            ]
            for s in steps_wiper:
                db.add(s)

        db.commit()
    except Exception as e:
        db.rollback()
        logger.warning(f"Error seeding default simulation profiles: {e}")


@router.get("/status", response_model=V29StatusResponse)
def get_v29_status(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Retrieves capability matrix, active emulation profiles, and KEDA autoscaling status."""
    seed_default_simulation_profiles(db)
    profiles = db.query(SimulationProfile).filter(
        (SimulationProfile.org_id.is_(None)) | (SimulationProfile.org_id == current_user.org_id)
    ).all()
    profile_names = [p.name for p in profiles]

    return V29StatusResponse(
        stg_engine_version="v29.0-sovereign-stg",
        stg_active=True,
        purple_team_emulation_active=True,
        supported_threat_profiles=profile_names,
        keda_autoscaling_enabled=True,
        cold_start_ml_readiness="READY",
        redis_stream_backlog=0,
        version="v29.0"
    )


@router.get("/profiles", response_model=List[SimulationProfileResponse])
def list_simulation_profiles(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Lists all available Purple-Team emulation profiles (global pre-seeded + tenant custom)."""
    seed_default_simulation_profiles(db)
    profiles = (
        db.query(SimulationProfile)
        .filter(
            (SimulationProfile.org_id.is_(None)) | (SimulationProfile.org_id == current_user.org_id)
        )
        .order_by(SimulationProfile.created_at.asc())
        .all()
    )
    return profiles


@router.post("/profiles", response_model=SimulationProfileResponse)
def create_simulation_profile(
    payload: SimulationProfileCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Creates a custom Purple-Team attack simulation scenario for the current tenant."""
    profile = SimulationProfile(
        id=str(uuid4()),
        org_id=current_user.org_id,
        name=payload.name,
        description=payload.description,
        threat_actor=payload.threat_actor,
        is_active=payload.is_active
    )
    db.add(profile)
    db.flush()

    for idx, s in enumerate(payload.steps, 1):
        step_rec = SimulationStep(
            id=str(uuid4()),
            profile_id=profile.id,
            step_order=s.step_order or idx,
            delay_seconds=s.delay_seconds,
            ocsf_class_uid=s.ocsf_class_uid,
            mock_log_payload=s.mock_log_payload
        )
        db.add(step_rec)

    db.commit()
    db.refresh(profile)
    return profile


@router.post("/trigger-simulation", response_model=SimulationTriggerResponse)
async def trigger_purple_team_simulation(
    payload: SimulationTriggerRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Triggers an automated Purple-Team threat emulation scenario.
    Asynchronously streams OCSF logs into Redis and executes real-time pipeline dry-run.
    """
    seed_default_simulation_profiles(db)
    profile = db.query(SimulationProfile).filter(
        (SimulationProfile.id == payload.profile_id) | (SimulationProfile.threat_actor == payload.profile_id)
    ).first()

    if not profile:
        raise HTTPException(status_code=404, detail="Simulation profile not found")

    run_id = f"sim-run-{uuid4().hex[:8]}"
    run_record = SimulationRun(
        id=run_id,
        org_id=current_user.org_id,
        profile_id=profile.id,
        started_at=datetime.utcnow(),
        status="RUNNING",
        alerts_triggered_count=0,
        triggered_alert_ids=[],
        details={"initiated_by": current_user.email, "profile_name": profile.name}
    )
    db.add(run_record)
    db.commit()

    steps_data = [
        {
            "step_order": s.step_order,
            "delay_seconds": s.delay_seconds,
            "ocsf_class_uid": s.ocsf_class_uid,
            "mock_log_payload": s.mock_log_payload
        }
        for s in profile.steps
    ]

    # Run emulation asynchronously via broker
    asyncio.create_task(
        emulation_broker.run_simulation_task(
            org_id=current_user.org_id,
            profile_id=profile.id,
            profile_name=profile.name,
            steps=steps_data,
            delay_multiplier=payload.delay_multiplier,
            run_id=run_id
        )
    )

    return SimulationTriggerResponse(
        run_id=run_id,
        profile_id=profile.id,
        profile_name=profile.name,
        status="TRIGGERED",
        steps_count=len(steps_data),
        message=f"Simulation '{profile.name}' initiated with {len(steps_data)} attack steps."
    )


@router.get("/runs", response_model=List[SimulationRunResponse])
def list_simulation_runs(
    limit: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Returns historical Purple-Team simulation execution logs for the tenant."""
    runs = (
        db.query(SimulationRun)
        .filter(SimulationRun.org_id == current_user.org_id)
        .order_by(SimulationRun.started_at.desc())
        .limit(limit)
        .all()
    )

    results = []
    for r in runs:
        item = SimulationRunResponse(
            id=r.id,
            org_id=r.org_id,
            profile_id=r.profile_id,
            started_at=r.started_at,
            completed_at=r.completed_at,
            status=r.status,
            alerts_triggered_count=r.alerts_triggered_count,
            triggered_alert_ids=r.triggered_alert_ids or [],
            details=r.details or {},
            profile_name=r.profile.name if r.profile else "Unknown Profile"
        )
        results.append(item)
    return results


@router.post("/generate-synthetic", response_model=SyntheticGenerationResponse)
async def generate_synthetic_telemetry(
    payload: SyntheticGenerationRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Generates high-fidelity sovereign synthetic OCSF telemetry events,
    incorporating diurnal temporal curves, user identity clustering, and background noise.
    Optionally bootstraps tenant ML Isolation Forest baseline.
    """
    t0 = time.time()
    events = sovereign_stg_generator.generate_events(
        count=payload.count,
        org_id=current_user.org_id,
        diurnal=payload.diurnal_profile,
        noise_ratio=payload.noise_ratio
    )

    persisted_count = 0
    if payload.persist_to_db:
        # Batch insert a representative sample (up to 500) into database LogEvent table
        sample_to_insert = events[:500]
        db_logs = []
        for e in sample_to_insert:
            log_entry = LogEvent(
                id=e["id"],
                org_id=current_user.org_id,
                ts=e["ts"],
                event_type=e.get("event_type", "synthetic_stg"),
                process=e.get("process"),
                raw=e.get("raw", ""),
                normalized=e.get("normalized", {})
            )
            db_logs.append(log_entry)
        try:
            db.bulk_save_objects(db_logs)
            db.commit()
            persisted_count = len(db_logs)
        except Exception as ex:
            db.rollback()
            logger.warning(f"Failed to persist batch synthetic logs: {ex}")

    streamed_count = 0
    if payload.inject_to_stream:
        streamed_count = await sovereign_stg_generator.stream_to_redis(
            events=events[:1000],
            org_id=current_user.org_id,
            redis_url=settings.REDIS_URL
        )

    ml_bootstrap_res = {}
    if payload.bootstrap_ml_coldstart:
        ml_bootstrap_res = sovereign_stg_generator.bootstrap_ml_coldstart(
            events=events,
            org_id=current_user.org_id
        )

    time_elapsed = time.time() - t0
    user_cluster_names = [u["username"] for u in MOCK_USER_CLUSTERS[:payload.user_clusters_count]]

    # Sample top 5 events for preview
    sample_preview = [
        {
            "id": e["id"],
            "timestamp": e["timestamp"],
            "event_type": e["event_type"],
            "raw": e["raw"],
            "ocsf_class": e.get("normalized", {}).get("ocsf", {}).get("metadata", {}).get("class_name", "UNKNOWN")
        }
        for e in events[:5]
    ]

    return SyntheticGenerationResponse(
        status="COMPLETED",
        org_id=current_user.org_id,
        events_generated=len(events),
        events_persisted=persisted_count,
        events_streamed=streamed_count,
        ml_coldstart_bootstrapped=ml_bootstrap_res.get("fitted", False),
        ml_model_version=ml_bootstrap_res.get("model_version"),
        diurnal_curve_applied=payload.diurnal_profile,
        user_clusters=user_cluster_names,
        time_elapsed_sec=round(time_elapsed, 3),
        sample_events=sample_preview
    )


@router.get("/keda-config", response_model=KedaScaleConfigResponse)
def get_keda_scale_config(current_user: User = Depends(get_current_user)):
    """Exports production-grade KEDA Redis stream ScaledObject and GitOps deployment blueprints."""
    return KedaScaleConfigResponse(
        api_version="keda.sh/v1alpha1",
        kind="ScaledObject",
        metadata_name="celery-worker-scaler",
        stream_name="logs:raw_stream",
        target_backlog_threshold=10000,
        min_replicas=2,
        max_replicas=50,
        redis_host="redis://redis:6379/0",
        argocd_sync_wave=2,
        gitops_status="HEALTHY_SYNCED"
    )
