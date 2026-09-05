import json
import hashlib
import numpy as np
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.db import Base
from app.models.models import Organization, User, FederatedModel, FederatedClientUpdate, FederationRun
from app.detection.anomaly_pipeline import SecurityAnomalyDetector
from app.detection.federated_aggregator import (
    FederatedAggregator,
    extract_model_parameters
)


def get_test_db():
    """Helper to instantiate an isolated in-memory SQLite session for testing."""
    engine = create_engine("sqlite:///:memory:", echo=False)
    Base.metadata.create_all(bind=engine)
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    db = TestingSessionLocal()

    org = Organization(id="test_org_v28", name="V28 Test Org")
    db.add(org)
    user = User(
        id="test_user_v28",
        org_id=org.id,
        email="analyst@v28.test",
        hashed_password="mock_hashed_pw"
    )
    db.add(user)
    db.commit()
    return db


def test_parameter_extraction_and_checksum():
    """Verify that model parameters are correctly extracted into a standardized vector with SHA-256 digest."""
    detector = SecurityAnomalyDetector()
    detector.feature_means = {f: 10.0 for f in detector.feature_names}
    detector.feature_stds = {f: 2.5 for f in detector.feature_names}

    extracted = extract_model_parameters(detector)
    assert "weights" in extracted
    assert "checksum_signature" in extracted
    assert len(extracted["weights"]) == 30  # 10 means + 10 stds + 10 estimator weights

    # Verify checksum matches weights payload
    serialized = json.dumps(extracted["weights"]).encode("utf-8")
    expected_checksum = hashlib.sha256(serialized).hexdigest()
    assert extracted["checksum_signature"] == expected_checksum


def test_differential_privacy_laplace_noise():
    """Verify differential privacy noise perturbation bounds with epsilon = 1.2."""
    aggregator = FederatedAggregator(min_clients=3, dp_epsilon=1.2)
    base_weights = np.ones(30, dtype=np.float64) * 5.0
    dp_weights = aggregator.apply_differential_privacy(base_weights)

    assert dp_weights.shape == base_weights.shape
    assert not np.array_equal(dp_weights, base_weights)
    # The perturbed weights should remain within reasonable standard deviation bounds of Laplace distribution
    diff = np.abs(dp_weights - base_weights)
    assert np.mean(diff) < 2.0


def test_federated_averaging_consolidation():
    """Verify weighted FedAvg consolidation across multiple tenant updates."""
    aggregator = FederatedAggregator(min_clients=2, dp_epsilon=1.2)

    client_updates = [
        {
            "org_id": "tenant_1",
            "sample_count": 100,
            "weights": [1.0] * 30,
            "checksum_signature": "mock_sig_1"
        },
        {
            "org_id": "tenant_2",
            "sample_count": 300,
            "weights": [3.0] * 30,
            "checksum_signature": "mock_sig_2"
        }
    ]

    result = aggregator.aggregate_parameters(client_updates)
    assert result["status"] == "CONSOLIDATED"
    assert result["total_participating_tenants"] == 2
    assert result["total_samples_trained"] == 400
    assert "aggregated_loss" in result
    assert "signature_proof" in result
    assert len(result["global_weights"]) == 30


def test_min_clients_constraint():
    """Verify that FedAvg aborts if minimum participating clients threshold is not met."""
    aggregator = FederatedAggregator(min_clients=3, dp_epsilon=1.2)
    single_update = [
        {
            "org_id": "tenant_solo",
            "sample_count": 50,
            "weights": [1.0] * 30
        }
    ]

    try:
        aggregator.aggregate_parameters(single_update)
        assert False, "Should have raised ValueError for insufficient clients"
    except ValueError as e:
        assert "Minimum participating tenants" in str(e)


def test_database_persistence_and_lineage():
    """Verify storing FederatedModel, FederatedClientUpdate, and FederationRun in SQL database."""
    db = get_test_db()
    try:
        # 1. Create Global Model
        global_model = FederatedModel(
            model_name="global_anomaly_forest",
            version_id=1,
            org_id=None,
            model_state="ACTIVE",
            global_parameters_hex=json.dumps([0.5] * 30),
            total_epochs_trained=1,
            metrics={"test": True}
        )
        db.add(global_model)
        db.commit()
        db.refresh(global_model)

        # 2. Add Client Update
        client_update = FederatedClientUpdate(
            org_id="test_org_v28",
            model_id=global_model.id,
            local_sample_count=180,
            parameter_weights_hex=json.dumps([0.6] * 30),
            checksum_signature="a1b2c3d4e5f67890",
        )
        db.add(client_update)
        db.commit()

        # 3. Add Federation Run
        fed_run = FederationRun(
            global_model_id=global_model.id,
            active_client_count=3,
            aggregated_loss=0.0345,
            signature_proof="FED_PROOF_TEST_12345",
            run_metadata={"global_epoch": 1}
        )
        db.add(fed_run)
        db.commit()

        # Query and assert relationships
        queried_model = db.query(FederatedModel).filter(FederatedModel.id == global_model.id).first()
        assert queried_model is not None
        assert len(queried_model.client_updates) == 1
        assert len(queried_model.runs) == 1
        assert queried_model.runs[0].signature_proof == "FED_PROOF_TEST_12345"
    finally:
        db.close()


if __name__ == "__main__":
    test_parameter_extraction_and_checksum()
    test_differential_privacy_laplace_noise()
    test_federated_averaging_consolidation()
    test_min_clients_constraint()
    test_database_persistence_and_lineage()
    print("All V28 unit tests passed!")
