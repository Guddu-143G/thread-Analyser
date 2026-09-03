"""
Runtime Binary Attestation & SBOM Integrity Monitor (v6.0).

Cross-references executing binary hashes and shared libraries intercepted via eBPF
against the tenant's authorized CycloneDX / SPDX SBOM supply chain whitelist.
Flags unauthorized binary drift and software supply-chain backdoor injections.
"""
from typing import Any, Dict, List, Optional
from sqlalchemy.orm import Session
from app.models.sbom import TenantSBOM


class RuntimeAttestationMonitor:
    """
    Verifies running process binaries against the uploaded Software Bill of Materials.
    """

    def __init__(self, db: Session, org_id: str):
        self.db = db
        self.org_id = org_id

    def verify_process_integrity(
        self,
        running_binary_hash: str,
        process_name: str
    ) -> Optional[Dict[str, Any]]:
        """
        Checks if the running binary hash is whitelisted in the tenant's SBOM registry.
        """
        clean_hash = running_binary_hash.strip().lower()
        record = self.db.query(TenantSBOM).filter(
            TenantSBOM.org_id == self.org_id,
            TenantSBOM.sha256_hash == clean_hash
        ).first()

        if not record:
            return {
                "status": "UNAUTHORIZED_BINARY_DRIFT",
                "risk_score": 1.0,
                "process_name": process_name,
                "binary_hash": running_binary_hash,
                "severity": "CRITICAL",
                "description": f"Running process '{process_name}' with SHA-256 '{running_binary_hash[:16]}...' is missing from the authorized SBOM whitelist.",
                "remediation": "Trigger automated K8s container eviction or host isolation.",
            }

        return {
            "status": "ATTESTED_VALID",
            "component_name": record.component_name,
            "version": record.version,
            "license_type": record.license_type,
            "binary_hash": record.sha256_hash,
            "description": f"Binary matched authorized SBOM component '{record.component_name}' v{record.version}.",
        }

    def batch_verify(self, telemetry_batch: List[Dict[str, str]]) -> Dict[str, Any]:
        """
        Audits a list of active processes on an endpoint against the SBOM.
        """
        results = []
        drift_count = 0

        for item in telemetry_batch:
            res = self.verify_process_integrity(
                running_binary_hash=item.get("hash", ""),
                process_name=item.get("name", "unknown")
            )
            if res:
                if res.get("status") == "UNAUTHORIZED_BINARY_DRIFT":
                    drift_count += 1
                results.append(res)

        return {
            "total_processes_audited": len(telemetry_batch),
            "authorized_count": len(telemetry_batch) - drift_count,
            "drift_anomalies_detected": drift_count,
            "attestation_verdict": "FAILED_DRIFT_DETECTED" if drift_count > 0 else "ALL_COMPONENTS_ATTESTED",
            "audit_details": results,
        }
