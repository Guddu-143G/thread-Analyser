"""
Version 24: Neon PostgreSQL Merkle-Chained Audit Ledger Service.
Manages append-only cryptographic hash chaining for audit logs and runs recursive integrity validation.
"""

import hashlib
from datetime import datetime
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session
from sqlalchemy import text
from app.models.models import AuditLedger

GENESIS_HASH = "0000000000000000000000000000000000000000000000000000000000000000"

class NeonAuditLedgerManager:
    """
    Cryptographic Merkle hash-chaining manager for multi-tenant immutable audit trails.
    """

    @staticmethod
    def calculate_payload_hash(
        action: str,
        actor_email: str,
        ip_address: str,
        mac_address: str
    ) -> str:
        """Computes SHA-256 digest of record payload contents."""
        raw = f"{action or ''}|{actor_email or ''}|{ip_address or ''}|{mac_address or ''}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    @staticmethod
    def calculate_block_hash(payload_hash: str, previous_hash: str) -> str:
        """Computes SHA-256 digest linking payload hash with the parent block hash."""
        combined = f"{payload_hash}{previous_hash}"
        return hashlib.sha256(combined.encode("utf-8")).hexdigest()

    calculate_ledger_hash = calculate_block_hash

    @classmethod
    def append_audit_record(
        cls,
        db: Session,
        org_id: str,
        action: str,
        actor_email: str,
        ip_address: str,
        mac_address: str,
        device_id: Optional[str] = None
    ) -> AuditLedger:
        """
        Appends a new audit record into the ledger with automated cryptographic parent-hash chaining.
        """
        last_record = db.query(AuditLedger).filter(
            AuditLedger.org_id == org_id
        ).order_by(AuditLedger.sequence_id.desc()).first()

        prev_hash = last_record.current_ledger_hash if last_record else GENESIS_HASH
        payload_hash = cls.calculate_payload_hash(
            action=action,
            actor_email=actor_email,
            ip_address=ip_address,
            mac_address=mac_address
        )
        current_hash = cls.calculate_block_hash(payload_hash, prev_hash)

        record = AuditLedger(
            org_id=org_id,
            device_id=device_id,
            action=action,
            actor_email=actor_email,
            ip_address=ip_address,
            mac_address=mac_address,
            payload_hash=payload_hash,
            previous_record_hash=prev_hash,
            current_ledger_hash=current_hash,
            event_timestamp=datetime.utcnow()
        )
        db.add(record)
        db.commit()
        db.refresh(record)
        return record

    @classmethod
    def verify_ledger_integrity(cls, db: Session, org_id: str) -> Dict[str, Any]:
        """
        Validates the entire cryptographic Merkle chain for the given tenant from Genesis to tip.
        """
        records = db.query(AuditLedger).filter(
            AuditLedger.org_id == org_id
        ).order_by(AuditLedger.sequence_id.asc()).all()

        if not records:
            return {
                "total_records": 0,
                "is_valid": True,
                "chain_status": "EMPTY_GENESIS",
                "verified_blocks": 0,
                "tampered_blocks_count": 0,
                "tampered_details": []
            }

        expected_prev_hash = GENESIS_HASH
        tampered_details = []

        for idx, rec in enumerate(records):
            # 1. Check parent pointer continuity
            if rec.previous_record_hash != expected_prev_hash:
                tampered_details.append({
                    "sequence_id": rec.sequence_id,
                    "error_type": "BROKEN_PARENT_LINK",
                    "expected_parent_hash": expected_prev_hash,
                    "actual_previous_hash": rec.previous_record_hash,
                    "timestamp": rec.event_timestamp.isoformat() if rec.event_timestamp else ""
                })

            # 2. Recalculate payload hash & current block hash
            calc_payload_hash = cls.calculate_payload_hash(
                action=rec.action,
                actor_email=rec.actor_email,
                ip_address=rec.ip_address,
                mac_address=rec.mac_address
            )
            calc_block_hash = cls.calculate_block_hash(calc_payload_hash, rec.previous_record_hash)

            if calc_block_hash != rec.current_ledger_hash or calc_payload_hash != rec.payload_hash:
                tampered_details.append({
                    "sequence_id": rec.sequence_id,
                    "error_type": "RECORD_CONTENT_TAMPERED",
                    "stored_hash": rec.current_ledger_hash,
                    "recomputed_hash": calc_block_hash,
                    "timestamp": rec.event_timestamp.isoformat() if rec.event_timestamp else ""
                })

            # Advance expected parent hash
            expected_prev_hash = rec.current_ledger_hash

        is_valid = (len(tampered_details) == 0)
        return {
            "total_records": len(records),
            "is_valid": is_valid,
            "chain_status": "CRYPTOGRAPHICALLY_VERIFIED_TAMPER_FREE" if is_valid else "TAMPERING_DETECTED",
            "verified_blocks": len(records) - len(tampered_details),
            "tampered_blocks_count": len(tampered_details),
            "genesis_hash": records[0].previous_record_hash if records else GENESIS_HASH,
            "latest_tip_hash": records[-1].current_ledger_hash if records else GENESIS_HASH,
            "tampered_details": tampered_details
        }

    @classmethod
    def simulate_dba_tamper(
        cls,
        db: Session,
        org_id: str,
        target_sequence_id: Optional[int] = None,
        tampered_action: str = "UNAUTHORIZED_ADMIN_ROLE_GRANT"
    ) -> Dict[str, Any]:
        """
        Simulates direct SQL mutation by a rogue DBA without recomputing cryptographic hashes.
        """
        query = db.query(AuditLedger).filter(AuditLedger.org_id == org_id)
        if target_sequence_id:
            record = query.filter(AuditLedger.sequence_id == target_sequence_id).first()
        else:
            record = query.order_by(AuditLedger.sequence_id.desc()).first()

        if not record:
            return {
                "status": "TAMPER_FAILED_NO_RECORDS",
                "error": "No records found in tenant ledger."
            }

        original_action = record.action
        record.action = tampered_action
        db.commit()

        return {
            "status": "TAMPERING_INJECTED",
            "tampered_sequence_id": record.sequence_id,
            "original_action": original_action,
            "mutated_action": tampered_action,
            "stored_hash_unaltered": record.current_ledger_hash,
            "description": "SQL row modified directly without hash recomputation. Cryptographic chain verification will detect discrepancy."
        }

    @classmethod
    def heal_or_recompute_chain(cls, db: Session, org_id: str) -> Dict[str, Any]:
        """
        Recomputes payload and block hashes for all records in the tenant's ledger to restore valid Merkle chain.
        """
        records = db.query(AuditLedger).filter(
            AuditLedger.org_id == org_id
        ).order_by(AuditLedger.sequence_id.asc()).all()

        prev_hash = GENESIS_HASH
        healed_count = 0

        for rec in records:
            p_hash = cls.calculate_payload_hash(
                action=rec.action,
                actor_email=rec.actor_email,
                ip_address=rec.ip_address,
                mac_address=rec.mac_address
            )
            b_hash = cls.calculate_block_hash(p_hash, prev_hash)
            rec.previous_record_hash = prev_hash
            rec.payload_hash = p_hash
            rec.current_ledger_hash = b_hash
            prev_hash = b_hash
            healed_count += 1

        db.commit()
        return {"status": "LEDGER_HEALED", "total_healed": healed_count}

