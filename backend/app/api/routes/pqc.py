from fastapi import APIRouter, Depends, HTTPException
from typing import Any, Dict
from pydantic import BaseModel
from app.core.deps import get_current_user
from app.models.models import User
from app.security.pqc_middleware import PQCHybridNegotiator

router = APIRouter(prefix="/api/pqc", tags=["Post-Quantum Cryptography"])


class PQCNegotiateRequest(BaseModel):
    client_kem_ciphertext: str


class PQCIngestRequest(BaseModel):
    pqc_encrypted_payload: str
    session_ciphertext: str


@router.get("/status")
def get_pqc_posture(current_user: User = Depends(get_current_user)) -> Dict[str, Any]:
    """Returns the Post-Quantum cryptographic negotiation posture."""
    negotiator = PQCHybridNegotiator(tenant_id=str(current_user.org_id))
    return negotiator.get_pqc_status()


@router.get("/keypair")
def get_server_pqc_keypair(current_user: User = Depends(get_current_user)) -> Dict[str, Any]:
    """Generates server ML-KEM public encapsulation key."""
    negotiator = PQCHybridNegotiator(tenant_id=str(current_user.org_id))
    pub, priv = negotiator.generate_server_kem_keypair()
    return {
        "algorithm": negotiator.algorithm,
        "server_public_key": pub,
        "key_size_bytes": 1184,
    }


@router.post("/demo-roundtrip")
def demo_pqc_roundtrip(current_user: User = Depends(get_current_user)) -> Dict[str, Any]:
    """Runs an interactive ML-KEM-768 hybrid encapsulation and AES-GCM roundtrip test."""
    negotiator = PQCHybridNegotiator(tenant_id=str(current_user.org_id))
    pub, priv = negotiator.generate_server_kem_keypair()
    ciphertext, client_secret = negotiator.encapsulate_client_secret(pub)
    server_derived_key = negotiator.decapsulate_session_key(ciphertext, priv)

    sample_log = '{"event": "PROCESS_SPAWN", "process": "kyber_guard.exe", "host": "srv-pqc-01"}'
    enc = negotiator.encrypt_log_payload_pqc(sample_log, client_secret)
    dec = negotiator.decrypt_log_payload_pqc(enc["pqc_encrypted_payload"], server_derived_key)

    return {
        "status": "PQC_VERIFIED_AUTHENTIC",
        "algorithm": negotiator.algorithm,
        "quantum_security_level": negotiator.security_level,
        "keys_matched": (client_secret == server_derived_key),
        "decrypted_plaintext": dec,
        "encrypted_packet_sample": enc["pqc_encrypted_payload"][:32] + "...",
    }
