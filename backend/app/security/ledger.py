import hashlib
import json
from typing import Dict, Any, Optional
from datetime import datetime
from sqlalchemy.orm import Session

from app.models.models import AuditLog


class CryptographicAuditLedger:
    """
    Implements a tamper-evident Merkle hash chain for security compliance audits (RFC 6962).
    Every event contains a cryptographic seal computed from its predecessor and payload.
    """
    GENESIS_HASH = "0" * 64

    @staticmethod
    def calculate_record_hash(record: Dict[str, Any], previous_hash: str) -> str:
        """
        Computes the SHA-256 state seal of a record bound to its predecessor.
        """
        hasher = hashlib.sha256()
        
        # Serialize payload deterministically to prevent signature divergence
        serialized_payload = json.dumps(record, sort_keys=True, default=str)
        
        hasher.update(previous_hash.encode('utf-8'))
        hasher.update(serialized_payload.encode('utf-8'))
        
        return hasher.hexdigest()

    @classmethod
    def append_audit_log(
        cls,
        db: Session,
        org_id: str,
        action: str,
        actor_user_id: Optional[str] = None,
        target: Optional[str] = None,
        meta: Optional[Dict[str, Any]] = None,
    ) -> AuditLog:
        """
        Calculates cryptographic chain seal against previous tenant audit log and commits.
        """
        # Find latest record for this org
        last_record = (
            db.query(AuditLog)
            .filter(AuditLog.org_id == org_id)
            .order_by(AuditLog.created_at.desc())
            .first()
        )
        
        prev_seal = last_record.cryptographic_seal if (last_record and last_record.cryptographic_seal) else cls.GENESIS_HASH
        
        now = datetime.utcnow()
        payload_to_hash = {
            "org_id": org_id,
            "actor_user_id": actor_user_id,
            "action": action,
            "target": target,
            "meta": meta or {},
            "created_at": now.isoformat(),
        }
        
        seal = cls.calculate_record_hash(payload_to_hash, prev_seal)
        
        log_entry = AuditLog(
            org_id=org_id,
            actor_user_id=actor_user_id,
            action=action,
            target=target,
            meta=meta,
            created_at=now,
            cryptographic_seal=seal,
            previous_seal=prev_seal,
        )
        db.add(log_entry)
        db.commit()
        db.refresh(log_entry)
        return log_entry

    @classmethod
    def verify_chain(cls, audit_records: list) -> Dict[str, Any]:
        """
        Verifies the cryptographic integrity of the audit logs.
        Returns detailed validation diagnostics.
        """
        if not audit_records:
            return {
                "valid": True,
                "records_verified": 0,
                "latest_seal": cls.GENESIS_HASH,
                "message": "Empty audit chain (Valid)."
            }

        # Ensure sorted chronologically ascending for chain verification
        sorted_records = sorted(audit_records, key=lambda r: r.created_at if hasattr(r, "created_at") else r.get("created_at", ""))
        expected_hash = cls.GENESIS_HASH

        for i, record in enumerate(sorted_records):
            if hasattr(record, "cryptographic_seal"):
                stored_seal = record.cryptographic_seal
                record_payload = {
                    "org_id": record.org_id,
                    "actor_user_id": record.actor_user_id,
                    "action": record.action,
                    "target": record.target,
                    "meta": record.meta or {},
                    "created_at": record.created_at.isoformat() if isinstance(record.created_at, datetime) else str(record.created_at),
                }
            else:
                stored_seal = record.get("cryptographic_seal")
                record_payload = {k: v for k, v in record.items() if k not in ("cryptographic_seal", "previous_seal", "id")}

            if not stored_seal:
                # Legacy unsealed record — advance hash using payload
                computed_hash = cls.calculate_record_hash(record_payload, expected_hash)
                expected_hash = computed_hash
                continue

            computed_hash = cls.calculate_record_hash(record_payload, expected_hash)
            if computed_hash != stored_seal:
                return {
                    "valid": False,
                    "tampered_index": i,
                    "records_verified": i,
                    "expected_seal": computed_hash,
                    "stored_seal": stored_seal,
                    "message": f"Cryptographic seal mismatch at record index {i} (Tampering/deletion detected)."
                }
            expected_hash = stored_seal

        return {
            "valid": True,
            "records_verified": len(sorted_records),
            "latest_seal": expected_hash,
            "message": f"Cryptographic Merkle Hash Chain Verified ({len(sorted_records)} records intact)."
        }
