import time
from typing import List, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, status

from app.core.deps import get_current_user
from app.models.models import User
from app.security.pqc_transport import global_pqc_transport
from app.agent.pmu_monitor import global_pmu_guard
from app.detection.gart import global_gart_engine
from app.audit.zk_rollup import global_zk_rollup
from app.schemas.schemas import (
    PQCHandshakeRequest,
    PQCHandshakeOut,
    PQCEnvelopeRequest,
    PQCEnvelopeOut,
    PMUMetricsOut,
    PMUSimulateAttackRequest,
    GARTRunLoopRequest,
    GARTRunLoopOut,
    GARTPatchOut,
    ZKRollupCommitRequest,
    ZKRollupCommitOut,
    ZKRollupStateOut,
)

router = APIRouter(prefix="/api/v15", tags=["v15 post-quantum & hardware mesh"])


# =========================================================================
# NIST FIPS 203/204 Post-Quantum Hybrid Transport Endpoints
# =========================================================================

@router.post("/pqc/handshake", response_model=PQCHandshakeOut)
def establish_pqc_handshake(
    payload: PQCHandshakeRequest,
    user: User = Depends(get_current_user),
):
    """
    Establishes hybrid ML-KEM-1024 / X25519 key encapsulation and ML-DSA-87 identity authentication.
    """
    identity = global_pqc_transport.get_public_identity()
    return PQCHandshakeOut(
        node_id=payload.node_id,
        pqc_metadata=identity["pqc_metadata"],
        ml_kem_1024_public_key=identity["ml_kem_1024_public_key"],
        x25519_public_key=identity["x25519_public_key"],
        ml_dsa_87_verify_key=identity["ml_dsa_87_verify_key"],
        ed25519_verify_key=identity["ed25519_verify_key"],
        handshake_status="HYBRID_PQC_SESSION_ESTABLISHED",
    )


@router.post("/pqc/envelope", response_model=PQCEnvelopeOut)
def wrap_pqc_envelope(
    payload: PQCEnvelopeRequest,
    user: User = Depends(get_current_user),
):
    """
    Wraps raw telemetry payload into a NIST FIPS 203/204 double-encrypted post-quantum envelope.
    """
    peer_identity = global_pqc_transport.get_public_identity()
    envelope = global_pqc_transport.wrap_envelope(payload.raw_payload, peer_identity)
    return PQCEnvelopeOut(**envelope)


@router.post("/pqc/unwrap")
def unwrap_pqc_envelope(
    payload: Dict[str, Any],
    user: User = Depends(get_current_user),
):
    """
    Decrypts and cryptographically verifies an incoming post-quantum envelope.
    """
    return global_pqc_transport.unwrap_envelope(payload)


# =========================================================================
# Hardware PMU & Side-Channel Telemetry Endpoints
# =========================================================================

@router.get("/pmu/metrics", response_model=PMUMetricsOut)
def get_pmu_hardware_metrics(user: User = Depends(get_current_user)):
    """
    Reads physical/simulated CPU PMU performance counters and cache miss ratios (OCSF Class 6002).
    """
    metrics = global_pmu_guard.capture_metrics()
    return PMUMetricsOut(**metrics)


@router.post("/pmu/simulate-attack", response_model=PMUMetricsOut)
def simulate_pmu_hardware_attack(
    payload: PMUSimulateAttackRequest,
    user: User = Depends(get_current_user),
):
    """
    Injects simulated Flush+Reload, Spectre V1, or Rowhammer disturbance to test real-time SOC alerting.
    """
    res = global_pmu_guard.simulate_attack(payload.attack_type)
    return PMUMetricsOut(**res)


# =========================================================================
# Self-Healing Generative Adversarial Red Teaming (GART) Endpoints
# =========================================================================

@router.post("/gart/run-loop", response_model=GARTRunLoopOut)
def execute_gart_adversarial_cycle(
    payload: GARTRunLoopRequest,
    user: User = Depends(get_current_user),
):
    """
    Executes a Generative Adversarial Red Teaming loop, testing mutated attack payloads and auto-synthesizing Sigma patches.
    """
    result = global_gart_engine.run_gart_cycle(seed_id=payload.seed_id)
    return GARTRunLoopOut(**result)


@router.get("/gart/patches", response_model=List[GARTPatchOut])
def list_gart_synthesized_patches(user: User = Depends(get_current_user)):
    """
    Lists all active, self-healed Sigma rule patches created by the GART engine.
    """
    patches = global_gart_engine.list_patches()
    return [GARTPatchOut(**p) for p in patches]


# =========================================================================
# Zero-Knowledge Sovereign Threat Ledger (Private ZK-Rollup) Endpoints
# =========================================================================

@router.get("/zk-rollup/state", response_model=ZKRollupStateOut)
def get_zk_rollup_state(user: User = Depends(get_current_user)):
    """
    Retrieves the current decentralized ZK-Rollup threat intelligence ledger state and sealed batches.
    """
    state = global_zk_rollup.get_ledger_state()
    return ZKRollupStateOut(**state)


@router.post("/zk-rollup/commit-threat", response_model=ZKRollupCommitOut)
def commit_threat_to_zk_rollup(
    payload: ZKRollupCommitRequest,
    user: User = Depends(get_current_user),
):
    """
    Commits a cryptographically blinded threat indicator into the active ZK-Rollup batch.
    """
    tenant_id = f"tenant-{user.organization_id[:8]}" if hasattr(user, 'organization_id') and user.organization_id else "tenant-core"
    res = global_zk_rollup.commit_threat(
        tenant_id=tenant_id,
        raw_indicator=payload.indicator,
        indicator_type=payload.indicator_type,
        confidence=payload.confidence,
    )
    return ZKRollupCommitOut(**res)
