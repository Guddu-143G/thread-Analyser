import time
import logging
from typing import Dict, Any, List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session

from app.core.db import get_db
from app.core.deps import get_current_user
from app.models.models import User, MLModel, MLModelRun, MLFeatureBaseline

from app.schemas.schemas import (
    V27TelemetryEventIn,
    V27AnomalyScoreOut,
    V27ModelTrainIn,
    V27ModelTrainOut,
    V27FeatureBaselineOut,
    V27ModelDetailsOut,
    V27FeatureContribution
)
from app.detection.anomaly_pipeline import ml_manager, SKLEARN_AVAILABLE, NUMERIC_FEATURES
from app.tasks.ml_training import train_tenant_model_sync, retrain_tenant_model_task, generate_synthetic_telemetry_batch

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/status", summary="V27 ML Engine Health and Status")
def get_v27_status():
    """Returns runtime status of the ML Anomaly Engine."""
    return {
        "engine": "SecurityAnomalyDetector",
        "version": "v27.0",
        "sklearn_available": SKLEARN_AVAILABLE,
        "features_tracked": NUMERIC_FEATURES,
        "total_features": len(NUMERIC_FEATURES),
        "cached_models_count": len(ml_manager._cache),
        "cache_capacity": ml_manager.cache_capacity,
        "supported_algorithms": ["IsolationForest", "RobustScaler", "PCA-2D", "Z-Score-Heuristics"]
    }


@router.get("/models", response_model=V27ModelDetailsOut, summary="Get Active ML Model for Tenant")
def get_tenant_model(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Retrieve details, baselines, and execution history for the tenant's ML model."""
    org_id = current_user.org_id
    model_record = db.query(MLModel).filter(MLModel.org_id == org_id).first()

    # If no model record exists yet in DB, train/bootstrap cold-start model
    if not model_record:
        try:
            train_res = train_tenant_model_sync(org_id=org_id, db=db)
            model_record = db.query(MLModel).filter(MLModel.org_id == org_id).first()
        except Exception as e:
            logger.error(f"Error bootstrapping model for org {org_id}: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to bootstrap initial ML model: {str(e)}"
            )

    # Fetch baselines
    baselines = db.query(MLFeatureBaseline).filter(MLFeatureBaseline.model_id == model_record.id).all()
    baseline_outs = [
        V27FeatureBaselineOut(
            id=b.id,
            model_id=b.model_id,
            feature_name=b.feature_name,
            mean_value=b.mean_value,
            std_value=b.std_value,
            min_value=b.min_value,
            max_value=b.max_value,
            importance_weight=b.importance_weight,
            calculated_at=b.calculated_at.isoformat() if b.calculated_at else ""
        )
        for b in baselines
    ]

    # Fetch recent runs
    recent_runs = (
        db.query(MLModelRun)
        .filter(MLModelRun.model_id == model_record.id)
        .order_by(MLModelRun.started_at.desc())
        .limit(10)
        .all()
    )
    run_list = [
        {
            "id": r.id,
            "run_type": r.run_type,
            "status": r.status,
            "samples_used": r.samples_used,
            "training_duration_sec": r.training_duration_sec,
            "started_at": r.started_at.isoformat() if r.started_at else "",
            "completed_at": r.completed_at.isoformat() if r.completed_at else ""
        }
        for r in recent_runs
    ]

    return V27ModelDetailsOut(
        id=model_record.id,
        org_id=model_record.org_id,
        algorithm=model_record.algorithm,
        version=model_record.version,
        contamination=model_record.contamination,
        training_samples_count=model_record.training_samples_count,
        model_artifact_path=model_record.model_artifact_path,
        status=model_record.status,
        metrics=model_record.metrics or {},
        created_at=model_record.created_at.isoformat() if model_record.created_at else "",
        updated_at=model_record.updated_at.isoformat() if model_record.updated_at else "",
        baselines=baseline_outs,
        recent_runs=run_list
    )


@router.post("/train", response_model=V27ModelTrainOut, summary="Trigger ML Model Training / Retraining")
def train_model(
    payload: V27ModelTrainIn,
    async_mode: bool = Query(False, description="Run training as an asynchronous Celery task"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Trigger tenant model retraining on historical & synthetic telemetry."""
    org_id = current_user.org_id

    if async_mode:
        try:
            task = retrain_tenant_model_task.delay(
                org_id=org_id,
                lookback_days=payload.lookback_days,
                contamination=payload.contamination,
                n_estimators=payload.n_estimators,
                include_synthetic=payload.include_synthetic
            )
            return V27ModelTrainOut(
                task_id=task.id,
                status="PENDING",
                org_id=org_id,
                model_id="",
                samples_used=0,
                duration_sec=0.0,
                version="v27.0-isolation-forest",
                metrics={"task_dispatched": True},
                trained_at=""
            )
        except Exception as e:
            logger.warning(f"Async Celery dispatch failed, falling back to synchronous training: {e}")

    # Synchronous training
    try:
        res = train_tenant_model_sync(
            org_id=org_id,
            lookback_days=payload.lookback_days,
            contamination=payload.contamination,
            n_estimators=payload.n_estimators,
            include_synthetic=payload.include_synthetic,
            db=db
        )
        return V27ModelTrainOut(
            task_id=None,
            status=res["status"],
            org_id=res["org_id"],
            model_id=res["model_id"],
            samples_used=res["samples_used"],
            duration_sec=res["duration_sec"],
            version=res["version"],
            metrics=res["metrics"],
            trained_at=res["trained_at"]
        )
    except Exception as e:
        logger.exception(f"Training failed for org {org_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Model training failed: {str(e)}"
        )


@router.post("/score", response_model=V27AnomalyScoreOut, summary="Evaluate Telemetry Event in Real-Time")
def score_telemetry(
    event: V27TelemetryEventIn,
    current_user: User = Depends(get_current_user)
):
    """Score a single telemetry event and compute deviation contributions and PCA projection."""
    org_id = current_user.org_id
    event_dict = event.model_dump()
    result = ml_manager.evaluate_telemetry(org_id, event_dict)

    return V27AnomalyScoreOut(
        is_anomaly=result["is_anomaly"],
        anomaly_score=result["anomaly_score"],
        severity=result["severity"],
        decision_boundary=result["decision_boundary"],
        top_contributing_features=[
            V27FeatureContribution(**fc) for fc in result["top_contributing_features"]
        ],
        pca_coordinates=result["pca_coordinates"],
        detector_version=result["detector_version"],
        model_fitted=result["model_fitted"],
        evaluated_at=result["evaluated_at"],
        org_id=org_id
    )


@router.get("/baselines", response_model=List[V27FeatureBaselineOut], summary="List Feature Baselines")
def get_baselines(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get active baseline distribution parameters for all features."""
    org_id = current_user.org_id
    baselines = db.query(MLFeatureBaseline).filter(MLFeatureBaseline.org_id == org_id).all()
    return [
        V27FeatureBaselineOut(
            id=b.id,
            model_id=b.model_id,
            feature_name=b.feature_name,
            mean_value=b.mean_value,
            std_value=b.std_value,
            min_value=b.min_value,
            max_value=b.max_value,
            importance_weight=b.importance_weight,
            calculated_at=b.calculated_at.isoformat() if b.calculated_at else ""
        )
        for b in baselines
    ]


@router.get("/runs", summary="List ML Model Training Runs")
def get_runs(
    current_user: User = Depends(get_current_user),
    limit: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db)
):
    """List historical model training runs and timing logs."""
    org_id = current_user.org_id
    runs = (
        db.query(MLModelRun)
        .filter(MLModelRun.org_id == org_id)
        .order_by(MLModelRun.started_at.desc())
        .limit(limit)
        .all()
    )
    return [
        {
            "id": r.id,
            "model_id": r.model_id,
            "run_type": r.run_type,
            "status": r.status,
            "samples_used": r.samples_used,
            "training_duration_sec": r.training_duration_sec,
            "loss_or_score": r.loss_or_score,
            "run_log": r.run_log,
            "started_at": r.started_at.isoformat() if r.started_at else "",
            "completed_at": r.completed_at.isoformat() if r.completed_at else ""
        }
        for r in runs
    ]


@router.post("/simulate-telemetry", summary="Simulate Telemetry Stream for Testing")
def simulate_telemetry(
    count: int = Query(10, ge=1, le=50),
    current_user: User = Depends(get_current_user)
):
    """Generate a sequence of scored synthetic events for real-time dashboard testing."""
    org_id = current_user.org_id
    batch = generate_synthetic_telemetry_batch(count=count)
    results = []
    for evt in batch:
        scored = ml_manager.evaluate_telemetry(org_id, evt)
        results.append({
            "raw_event": evt,
            "evaluation": scored
        })
    return {"count": len(results), "events": results}
