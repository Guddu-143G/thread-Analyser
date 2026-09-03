"""
API Routes for Software Bill of Materials (SBOM) & Runtime Binary Attestation (v6.0).
"""
import hashlib
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.db import get_db
from app.core.deps import get_current_user
from app.models.models import User
from app.models.sbom import TenantSBOM
from app.detection.attestor import RuntimeAttestationMonitor
from app.security.ledger import CryptographicAuditLedger

router = APIRouter(prefix="/api/sbom", tags=["sbom"])


class CycloneDXComponent(BaseModel):
    name: str
    version: str
    sha256: str
    license: Optional[str] = "Apache-2.0"


class UploadSBOMRequest(BaseModel):
    bom_format: Optional[str] = "CycloneDX"
    spec_version: Optional[str] = "1.5"
    components: List[CycloneDXComponent]


class VerifyProcessRequest(BaseModel):
    process_name: str
    binary_hash: str


@router.get("")
def list_tenant_sbom_components(
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Returns all whitelisted software supply-chain components in the tenant's SBOM."""
    components = db.query(TenantSBOM).filter(TenantSBOM.org_id == user.org_id).all()
    return {
        "total_components": len(components),
        "components": [
            {
                "id": str(c.id),
                "name": c.component_name,
                "version": c.version,
                "sha256_hash": c.sha256_hash,
                "license_type": c.license_type,
                "created_at": c.created_at.isoformat() if c.created_at else None,
            }
            for c in components
        ],
    }


@router.post("/upload")
def upload_cyclonedx_sbom(
    payload: UploadSBOMRequest,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """
    Ingests a CycloneDX / SPDX SBOM JSON document and registers whitelisted SHA-256 hashes.
    """
    added_count = 0
    for comp in payload.components:
        clean_hash = comp.sha256.strip().lower()
        existing = db.query(TenantSBOM).filter(
            TenantSBOM.org_id == user.org_id,
            TenantSBOM.sha256_hash == clean_hash
        ).first()

        if not existing:
            new_entry = TenantSBOM(
                org_id=user.org_id,
                component_name=comp.name,
                version=comp.version,
                sha256_hash=clean_hash,
                license_type=comp.license or "Proprietary",
            )
            db.add(new_entry)
            added_count += 1

    db.commit()

    CryptographicAuditLedger.append_audit_log(
        db=db,
        org_id=user.org_id,
        actor_user_id=user.id,
        action="sbom_cyclonedx_ingested",
        target=f"{added_count}_components",
        meta={"format": payload.bom_format, "components_count": len(payload.components)},
    )

    return {
        "status": "SUCCESS",
        "message": f"Successfully ingested {added_count} new software supply-chain components into SBOM whitelist.",
        "total_processed": len(payload.components),
    }


@router.post("/verify")
def verify_running_binary(
    payload: VerifyProcessRequest,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """
    Checks if a running binary or shared library intercepted via eBPF matches the authorized SBOM.
    """
    monitor = RuntimeAttestationMonitor(db=db, org_id=user.org_id)
    res = monitor.verify_process_integrity(payload.binary_hash, payload.process_name)

    if res and res.get("status") == "UNAUTHORIZED_BINARY_DRIFT":
        CryptographicAuditLedger.append_audit_log(
            db=db,
            org_id=user.org_id,
            actor_user_id=user.id,
            action="sbom_unauthorized_drift_detected",
            target=payload.process_name,
            meta={"hash": payload.binary_hash, "severity": "CRITICAL"},
        )
    return res
