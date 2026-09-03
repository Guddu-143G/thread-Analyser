import os
import sys
import datetime

backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from app.security.ledger import CryptographicAuditLedger



def test_audit_ledger_valid_chain():
    # Construct sequence of records
    records = []
    prev_seal = CryptographicAuditLedger.GENESIS_HASH

    for i in range(5):
        payload = {
            "org_id": "test-org-1",
            "actor_user_id": "user-admin",
            "action": f"test_action_{i}",
            "target": f"target_{i}",
            "meta": {"iteration": i},
            "created_at": datetime.datetime(2026, 9, 1, 12, i, 0).isoformat(),
        }
        seal = CryptographicAuditLedger.calculate_record_hash(payload, prev_seal)
        records.append({**payload, "cryptographic_seal": seal, "previous_seal": prev_seal})
        prev_seal = seal

    result = CryptographicAuditLedger.verify_chain(records)
    assert result["valid"] is True
    assert result["records_verified"] == 5
    assert result["latest_seal"] == prev_seal


def test_audit_ledger_tamper_detection():
    # Construct sequence of records
    records = []
    prev_seal = CryptographicAuditLedger.GENESIS_HASH

    for i in range(5):
        payload = {
            "org_id": "test-org-1",
            "actor_user_id": "user-admin",
            "action": f"test_action_{i}",
            "target": f"target_{i}",
            "meta": {"iteration": i},
            "created_at": datetime.datetime(2026, 9, 1, 12, i, 0).isoformat(),
        }
        seal = CryptographicAuditLedger.calculate_record_hash(payload, prev_seal)
        records.append({**payload, "cryptographic_seal": seal, "previous_seal": prev_seal})
        prev_seal = seal

    # Tamper with record index 2
    records[2]["action"] = "malicious_unauthorized_action"

    result = CryptographicAuditLedger.verify_chain(records)
    assert result["valid"] is False
    assert result["tampered_index"] == 2
    assert "Cryptographic seal mismatch" in result["message"]
