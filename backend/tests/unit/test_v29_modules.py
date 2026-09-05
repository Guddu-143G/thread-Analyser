import json
from datetime import datetime
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.db import Base
from app.models.models import Organization, User, SimulationProfile, SimulationStep, SimulationRun
from app.schemas.schemas import (
    SimulationProfileCreate,
    SimulationProfileResponse,
    SimulationStepCreate,
    SimulationStepResponse,
    SimulationRunResponse,
    SyntheticGenerationRequest,
    KedaScaleConfigResponse,
    V29StatusResponse
)
from app.detection.synthetic_generator import (
    SovereignSyntheticGenerator,
    sovereign_stg_generator,
    MOCK_USER_CLUSTERS
)
from app.api.routes.v29_simulation_stg import seed_default_simulation_profiles


def get_test_db():
    """Helper to instantiate an isolated in-memory SQLite session for testing."""
    engine = create_engine("sqlite:///:memory:", echo=False)
    Base.metadata.create_all(bind=engine)
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    db = TestingSessionLocal()

    org = Organization(id="test_org_v29", name="V29 Test Org")
    db.add(org)
    user = User(
        id="test_user_v29",
        org_id=org.id,
        email="analyst@v29.test",
        hashed_password="mock_hashed_pw"
    )
    db.add(user)
    db.commit()
    return db


def test_sovereign_stg_event_generation():
    """Verify high-fidelity synthetic telemetry generation with diurnal temporal distributions."""
    generator = SovereignSyntheticGenerator(seed=42)
    events = generator.generate_events(count=200, org_id="tenant_alpha", diurnal=True, noise_ratio=0.2)

    assert len(events) == 200
    for e in events:
        assert "id" in e
        assert e["org_id"] == "tenant_alpha"
        assert "normalized" in e
        assert "ocsf" in e["normalized"]
        ocsf = e["normalized"]["ocsf"]
        assert ocsf["metadata"]["version"] == "1.2.0"
        assert ocsf["metadata"]["class_uid"] in [1001, 1007, 3002, 4001, 6003]

    # Verify timestamps are chronologically ordered
    timestamps = [e["ts"] for e in events]
    assert timestamps == sorted(timestamps)


def test_sovereign_stg_noise_injection():
    """Verify background benign noise injection generates DNS lookups."""
    generator = SovereignSyntheticGenerator(seed=101)
    events = generator.generate_events(count=50, org_id="tenant_alpha", diurnal=False, noise_ratio=1.0)

    assert len(events) == 50
    for e in events:
        assert e["event_type"] == "dns_query"
        assert e["normalized"]["ocsf"]["metadata"]["class_uid"] == 6003


def test_sovereign_stg_ml_coldstart_bootstrapping():
    """Verify zero-data cold start bootstrapping trains Isolation Forest baselines."""
    generator = SovereignSyntheticGenerator(seed=777)
    events = generator.generate_events(count=150, org_id="tenant_coldstart", diurnal=True, noise_ratio=0.1)

    result = generator.bootstrap_ml_coldstart(events=events, org_id="tenant_coldstart")
    assert result["status"] in ["BOOTSTRAPPED_READY", "SKLEARN_UNAVAILABLE"]
    assert result["samples_trained"] == 150
    if result.get("fitted"):
        assert len(result["mean_features"]) > 0
        assert len(result["std_features"]) > 0


def test_simulation_profile_seeding_and_db_models():
    """Verify database models and pre-seeded purple-team simulation profiles."""
    db = get_test_db()
    seed_default_simulation_profiles(db)

    profiles = db.query(SimulationProfile).all()
    assert len(profiles) >= 2

    apt_profile = db.query(SimulationProfile).filter(SimulationProfile.threat_actor == "APT29").first()
    assert apt_profile is not None
    assert "CozyBear" in apt_profile.name
    assert len(apt_profile.steps) == 4

    wiper_profile = db.query(SimulationProfile).filter(SimulationProfile.threat_actor == "HermeticWiper").first()
    assert wiper_profile is not None
    assert "Ransomware" in wiper_profile.name
    assert len(wiper_profile.steps) == 3

    # Test creating a SimulationRun record
    run = SimulationRun(
        id="sim-run-unit-01",
        org_id="test_org_v29",
        profile_id=apt_profile.id,
        status="COMPLETED",
        alerts_triggered_count=4,
        details={"test_metric": 100}
    )
    db.add(run)
    db.commit()

    saved_run = db.query(SimulationRun).filter(SimulationRun.id == "sim-run-unit-01").first()
    assert saved_run is not None
    assert saved_run.profile.threat_actor == "APT29"
    assert saved_run.alerts_triggered_count == 4


def test_pydantic_v29_schemas():
    """Verify Pydantic v2 schemas serialization and validation for V29."""
    req = SyntheticGenerationRequest(
        count=1000,
        diurnal_profile=True,
        noise_ratio=0.25,
        bootstrap_ml_coldstart=True
    )
    assert req.count == 1000

    keda = KedaScaleConfigResponse()
    assert keda.min_replicas == 2
    assert keda.max_replicas == 50
    assert keda.target_backlog_threshold == 10000

    status_resp = V29StatusResponse(
        stg_engine_version="v29.0-sovereign-stg",
        stg_active=True,
        purple_team_emulation_active=True,
        supported_threat_profiles=["APT29 (CozyBear) Spy Path", "HermeticWiper Ransomware Path"],
        keda_autoscaling_enabled=True,
        cold_start_ml_readiness="READY",
        redis_stream_backlog=0,
        version="v29.0"
    )
    assert status_resp.version == "v29.0"
    assert len(status_resp.supported_threat_profiles) == 2
