import sys
import os
import argparse

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from sqlalchemy.orm import Session

from app.core.db import SessionLocal
from app.models.models import AuditLog, Organization
from app.security.ledger import CryptographicAuditLedger



def verify_org_ledger(db: Session, org_id: str):
    records = (
        db.query(AuditLog)
        .filter(AuditLog.org_id == org_id)
        .order_by(AuditLog.created_at.asc())
        .all()
    )
    result = CryptographicAuditLedger.verify_chain(records)
    print(f"\n========================================================")
    print(f" Cryptographic Audit Ledger Audit: Org {org_id}")
    print(f"========================================================")
    print(f" Status           : {'[PASSED] SECURE & INTACT' if result['valid'] else '[FAILED] TAMPERING DETECTED'}")
    print(f" Records Verified : {result['records_verified']}")
    print(f" Latest Seal Hash : {result['latest_seal']}")
    print(f" Diagnostics      : {result['message']}")
    if not result["valid"]:
        print(f" Tampered Index   : {result.get('tampered_index')}")
        print(f" Expected Seal    : {result.get('expected_seal')}")
        print(f" Stored Seal      : {result.get('stored_seal')}")
    print(f"========================================================\n")
    return result["valid"]


def main():
    parser = argparse.ArgumentParser(description="Verify Threat Analyser Cryptographic Audit Ledger")
    parser.add_argument("--org-id", type=str, default=None, help="Target Organization UUID (or all if omitted)")
    args = parser.parse_args()

    db = SessionLocal()
    try:
        if args.org_id:
            valid = verify_org_ledger(db, args.org_id)
            sys.exit(0 if valid else 1)
        else:
            orgs = db.query(Organization).all()
            all_valid = True
            if not orgs:
                print("No organizations found in database.")
                sys.exit(0)
            for o in orgs:
                if not verify_org_ledger(db, o.id):
                    all_valid = False
            sys.exit(0 if all_valid else 1)
    finally:
        db.close()


if __name__ == "__main__":
    main()
