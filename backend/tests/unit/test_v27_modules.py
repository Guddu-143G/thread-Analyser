import os
import shutil
import numpy as np
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.db import Base
from app.models.models import Organization, User, MLModel, MLModelRun, MLFeatureBaseline
from app.detection.anomaly_pipeline import (
    SecurityAnomalyDetector,
    MultiTenantMLManager,
    NUMERIC_FEATURES,
    SKLEARN_AVAILABLE
)
from app.tasks.ml_training import train_tenant_model_sync, generate_synthetic_telemetry_batch


def get_test_db():
    """Helper to instantiate an isolated in-memory SQLite session for testing."""
    engine = create_engine("sqlite:///:memory:", echo=False)
    Base.metadata.create_all(bind=engine)
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    db = TestingSessionLocal()

    org = Organization(id="test_org_v27", name="V27 Test Org")
    db.add(org)
    user = User(
        id="test_user_v27",
        org_id=org.id,
        email="analyst@v27.test",
        hashed_password="mock_hashed_pw"
    )
    db.add(user)
    db.commit()
    return db


def test_feature_extraction_and_dimensions():
    """Verify that SecurityAnomalyDetector extracts the expected 10-dimensional feature vector."""
    detector = SecurityAnomalyDetector()
    sample_event = {
        "request_rate_1m": 25.0,
        "request_rate_5m": 110.0,
        "failed_auth_count": 2,
        "payload_entropy": 3.4,
        "unusual_port_flag": 1,
        "geo_distance_km": 150.0,
        "packet_size_variance": 210.0,
        "token_anomaly_score": 0.12,
        "session_duration_sec": 400.0,
        "concurrent_sessions": 2
    }

    vec = detector.extract_features(sample_event)
    assert isinstance(vec, np.ndarray)
    assert len(vec) == 10
    assert vec[0] == 25.0
    assert vec[4] == 1.0


def test_anomaly_detector_fit_and_score():
    """Verify training and scoring divergence between benign and malicious telemetry."""
    detector = SecurityAnomalyDetector(contamination=0.05, n_estimators=50)

    # Benign training data
    benign_training = generate_synthetic_telemetry_batch(count=100)
    detector.fit(benign_training)
    assert detector.is_fitted is True
    assert detector.training_samples_count >= 100

    # Score Benign Event
    benign_event = {
        "request_rate_1m": 20.0,
        "request_rate_5m": 95.0,
        "failed_auth_count": 0,
        "payload_entropy": 2.8,
        "unusual_port_flag": 0,
        "geo_distance_km": 40.0,
        "packet_size_variance": 140.0,
        "token_anomaly_score": 0.04,
        "session_duration_sec": 300.0,
        "concurrent_sessions": 1
    }
    benign_result = detector.score(benign_event)
    assert "anomaly_score" in benign_result
    assert "severity" in benign_result
    assert benign_result["anomaly_score"] < 0.65

    # Score Severe Malicious Exfil / Anomaly Event
    malicious_event = {
        "request_rate_1m": 280.0,
        "request_rate_5m": 1150.0,
        "failed_auth_count": 45,
        "payload_entropy": 7.9,
        "unusual_port_flag": 1,
        "geo_distance_km": 9500.0,
        "packet_size_variance": 2800.0,
        "token_anomaly_score": 0.98,
        "session_duration_sec": 5.0,
        "concurrent_sessions": 25
    }
    malicious_result = detector.score(malicious_event)
    assert malicious_result["anomaly_score"] >= 0.65
    assert malicious_result["is_anomaly"] is True
    assert len(malicious_result["top_contributing_features"]) > 0


def test_multitenant_ml_manager_isolation():
    """Verify tenant isolation, LRU caching, and model persistence to disk."""
    temp_storage = os.path.join(os.path.dirname(__file__), "temp_ml_models_test")
    os.makedirs(temp_storage, exist_ok=True)
    try:
        manager = MultiTenantMLManager(cache_capacity=5, storage_dir=temp_storage)

        # Organization 1
        org1_detector = manager.get_tenant_detector("tenant_alpha")
        assert org1_detector is not None

        # Score for tenant alpha
        res_alpha = manager.evaluate_telemetry("tenant_alpha", {"request_rate_1m": 20.0})
        assert res_alpha["org_id"] == "tenant_alpha"

        # Save to disk
        saved_path = manager.save_tenant_detector("tenant_alpha", org1_detector)
        assert os.path.exists(saved_path)

        # Organization 2
        org2_detector = manager.get_tenant_detector("tenant_beta")
        assert org2_detector is not None
        assert "tenant_alpha" in manager._cache
        assert "tenant_beta" in manager._cache

        meta = manager.get_model_metadata("tenant_alpha")
        assert meta["org_id"] == "tenant_alpha"
        assert meta["model_file_exists"] is True
    finally:
        shutil.rmtree(temp_storage, ignore_errors=True)


def test_training_pipeline_database_sync():
    """Verify train_tenant_model_sync creates database records and baseline entries."""
    db = get_test_db()
    try:
        res = train_tenant_model_sync(
            org_id="test_org_v27",
            lookback_days=30,
            contamination=0.05,
            n_estimators=50,
            include_synthetic=True,
            db=db
        )

        assert res["status"] == "SUCCESS"
        assert res["org_id"] == "test_org_v27"
        assert res["samples_used"] >= 100

        # Query DB to ensure records were written
        model_record = db.query(MLModel).filter(MLModel.org_id == "test_org_v27").first()
        assert model_record is not None
        assert model_record.algorithm == "IsolationForest"
        assert model_record.status == "ACTIVE"

        runs = db.query(MLModelRun).filter(MLModelRun.model_id == model_record.id).all()
        assert len(runs) >= 1
        assert runs[0].status == "SUCCESS"

        baselines = db.query(MLFeatureBaseline).filter(MLFeatureBaseline.model_id == model_record.id).all()
        assert len(baselines) == 10
        feature_names = {b.feature_name for b in baselines}
        assert feature_names == set(NUMERIC_FEATURES)
    finally:
        db.close()


if __name__ == "__main__":
    test_feature_extraction_and_dimensions()
    test_anomaly_detector_fit_and_score()
    test_multitenant_ml_manager_isolation()
    test_training_pipeline_database_sync()
    print("All V27 unit tests passed!")
