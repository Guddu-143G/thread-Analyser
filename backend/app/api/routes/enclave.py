"""
API Routes for Confidential Computing & Secure Enclave Ingestion (v5.0).
"""
from typing import Any, Dict
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.db import get_db
from app.core.deps import get_current_user
from app.models.models import User
from app.enclave.processor import EnclaveLogProcessor
from app.security.ledger import CryptographicAuditLedger

router = APIRouter(prefix="/api/enclave", tags=["enclave"])


class EnclaveProcessRequest(BaseModel):
    sample_log: str


@router.get("/status")
def get_enclave_status(user: User = Depends(get_current_user)):
    """Returns hardware attestation state, MRENCLAVE hash, and memory isolation mode."""
    proc = EnclaveLogProcessor(tenant_id=user.org_id)
    return proc.get_enclave_attestation_status()


@router.post("/process")
def process_log_in_enclave(
    payload: EnclaveProcessRequest,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """
    Simulates / executes hardware-enclave decryption, PII sanitization, and OCSF parsing.
    """
    import os
    proc = EnclaveLogProcessor(tenant_id=user.org_id)
    simulated_key = os.urandom(32)

    # Encrypt with AES-GCM before entering enclave
    encrypted_blob = EnclaveLogProcessor.encrypt_test_payload(payload.sample_log, simulated_key)

    # Process strictly inside secure memory boundary
    result = proc.sanitize_and_normalize(encrypted_blob, simulated_key)

    CryptographicAuditLedger.append_audit_log(
        db=db,
        org_id=user.org_id,
        actor_user_id=user.id,
        action="enclave_secure_log_processed",
        target="enclave_memory_prm",
        meta={"mrenclave": proc.enclave_attestation_mrenclave},
    )

    return result
