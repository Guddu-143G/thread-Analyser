"""
Version 23: Merkle-Chained Neon SQL Temporal Ledger Service
Manages Append-Only Cryptographic Hash Chaining and Real-Time Tamper Verification.
"""

import hashlib
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple
from sqlalchemy.orm import Session
from app.models.models import DeviceAuditLedger, Device

GENESIS_PARENT_HASH = "0000000000000000000000000000000000000000000000000000000000000000"

class MerkleTemporalLedgerManager:
    """
    Implements cryptographic Merkle hash-chaining on Neon PostgreSQL temporal tables,
    turning the SQL audit log into a tamper-evident cryptographic blockchain ledger.
    """

    @staticmethod
    def calculate_record_hash(
        device_id: str,
        org_id: str,
        hostname: str,
        ip_address: str,
        system_status: str,
        operation_type: str,
        parent_hash: str
    ) -> str:
        """Computes deterministic SHA-256 hash across canonical record payload and parent hash."""
        canonical_str = f"{device_id}|{org_id}|{hostname}|{ip_address}|{system_status}|{operation_type}|{parent_hash}"
        return hashlib.sha256(canonical_str.encode("utf-8")).hexdigest()

    @classmethod
    def _get_ordered_records(cls, db: Session, org_id: str) -> List[DeviceAuditLedger]:
        """
        Retrieves all records for the org, reconstructing the chain order by following parent_hash links.
        """
        records = db.query(DeviceAuditLedger).filter(
            DeviceAuditLedger.org_id == org_id
        ).order_by(DeviceAuditLedger.transaction_timestamp.asc(), DeviceAuditLedger.ledger_id.asc()).all()

        if not records:
            return []

        by_parent = {}
        for r in records:
            by_parent[r.parent_hash] = r

        ordered = []
        visited = set()
        curr_parent = GENESIS_PARENT_HASH

        while curr_parent in by_parent and curr_parent not in visited:
            rec = by_parent[curr_parent]
            ordered.append(rec)
            visited.add(curr_parent)
            curr_parent = rec.record_hash

        for r in records:
            if r not in ordered:
                ordered.append(r)

        return ordered

    @classmethod
    def append_audit_entry(
        cls,
        db: Session,
        org_id: str,
        device_id: str,
        hostname: str,
        ip_address: str,
        system_status: str = "active",
        operation_type: str = "INSERT"
    ) -> DeviceAuditLedger:
        """
        Appends a new chronological ledger entry, linking to the previous record's hash.
        """
        ordered = cls._get_ordered_records(db, org_id)
        last_entry = ordered[-1] if ordered else None

        parent_hash = last_entry.record_hash if last_entry else GENESIS_PARENT_HASH
        record_hash = cls.calculate_record_hash(
            device_id=device_id,
            org_id=org_id,
            hostname=hostname,
            ip_address=ip_address,
            system_status=system_status,
            operation_type=operation_type,
            parent_hash=parent_hash
        )

        entry = DeviceAuditLedger(
            org_id=org_id,
            device_id=device_id,
            hostname=hostname,
            ip_address=ip_address,
            system_status=system_status,
            operation_type=operation_type,
            transaction_timestamp=datetime.utcnow(),
            parent_hash=parent_hash,
            record_hash=record_hash
        )
        db.add(entry)
        db.commit()
        db.refresh(entry)
        return entry

    @classmethod
    def verify_ledger_integrity(cls, db: Session, org_id: str) -> Dict[str, Any]:
        """
        Traverses the entire cryptographic ledger chain chronologically from Genesis.
        Validates parent pointers and recalculates SHA-256 digests to detect any DBA tampering.
        """
        records = cls._get_ordered_records(db, org_id)

        if not records:
            return {
                "total_records": 0,
                "is_valid": True,
                "chain_status": "EMPTY_GENESIS",
                "verified_blocks": 0,
                "tampered_blocks_count": 0,
                "tampered_details": []
            }

        expected_parent_hash = GENESIS_PARENT_HASH
        tampered_details = []

        for idx, rec in enumerate(records):
            # 1. Check parent pointer continuity
            if rec.parent_hash != expected_parent_hash:
                tampered_details.append({
                    "block_index": idx,
                    "ledger_id": rec.ledger_id,
                    "device_id": rec.device_id,
                    "error": "BROKEN_PARENT_LINK",
                    "expected_parent_hash": expected_parent_hash,
                    "actual_parent_hash": rec.parent_hash,
                    "timestamp": rec.transaction_timestamp.isoformat() if rec.transaction_timestamp else ""
                })

            # 2. Recalculate record digest from raw fields
            recomputed_hash = cls.calculate_record_hash(
                device_id=rec.device_id,
                org_id=rec.org_id,
                hostname=rec.hostname,
                ip_address=rec.ip_address,
                system_status=rec.system_status,
                operation_type=rec.operation_type,
                parent_hash=rec.parent_hash
            )

            if recomputed_hash != rec.record_hash:
                tampered_details.append({
                    "block_index": idx,
                    "ledger_id": rec.ledger_id,
                    "device_id": rec.device_id,
                    "error": "PAYLOAD_TAMPERED_HASH_MISMATCH",
                    "recomputed_hash": recomputed_hash,
                    "stored_hash": rec.record_hash,
                    "timestamp": rec.transaction_timestamp.isoformat() if rec.transaction_timestamp else ""
                })

            # Advance expected parent hash to current record hash
            expected_parent_hash = rec.record_hash

        is_valid = (len(tampered_details) == 0)
        return {
            "total_records": len(records),
            "is_valid": is_valid,
            "chain_status": "CRYPTOGRAPHICALLY_VERIFIED_TAMPER_FREE" if is_valid else "TAMPERING_DETECTED",
            "verified_blocks": len(records) - len(tampered_details),
            "tampered_blocks_count": len(tampered_details),
            "genesis_hash": records[0].parent_hash if records else GENESIS_PARENT_HASH,
            "latest_root_hash": records[-1].record_hash if records else GENESIS_PARENT_HASH,
            "tampered_details": tampered_details
        }

    @classmethod
    def simulate_dba_tampering(cls, db: Session, org_id: str, target_ledger_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Demonstrates security capabilities by deliberately altering an intermediate record's payload
        without updating its cryptographic hash, proving immediate detection by the verification algorithm.
        """
        query = db.query(DeviceAuditLedger).filter(DeviceAuditLedger.org_id == org_id)
        if target_ledger_id:
            record = query.filter(DeviceAuditLedger.ledger_id == target_ledger_id).first()
        else:
            record = query.order_by(DeviceAuditLedger.transaction_timestamp.desc()).first()

        if not record:
            return {"status": "FAILED", "message": "No ledger records found to simulate tampering."}

        original_status = record.system_status
        record.system_status = "COMPROMISED_ROOTKIT_TAMPERED"
        db.commit()

        return {
            "status": "TAMPERING_INJECTED",
            "tampered_ledger_id": record.ledger_id,
            "device_id": record.device_id,
            "original_status": original_status,
            "tampered_status": record.system_status,
            "message": "Record was modified directly in SQL table. Cryptographic chain integrity will now fail verification."
        }

    @classmethod
    def heal_ledger(cls, db: Session, org_id: str) -> Dict[str, Any]:
        """
        Recomputes parent and record hashes for all records in the tenant's ledger to restore valid Merkle chain.
        """
        records = cls._get_ordered_records(db, org_id)

        parent_hash = GENESIS_PARENT_HASH
        for rec in records:
            if rec.system_status == "COMPROMISED_ROOTKIT_TAMPERED":
                rec.system_status = "active"
            rec.parent_hash = parent_hash
            rec.record_hash = cls.calculate_record_hash(
                device_id=rec.device_id,
                org_id=rec.org_id,
                hostname=rec.hostname,
                ip_address=rec.ip_address,
                system_status=rec.system_status,
                operation_type=rec.operation_type,
                parent_hash=parent_hash
            )
            parent_hash = rec.record_hash

        db.commit()
        return {"status": "LEDGER_HEALED", "total_records": len(records)}

