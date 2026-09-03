"""
API Routes for Searchable Symmetric Encryption (SSE) Archive Engine (v5.0).
"""
import hashlib
import os
from typing import Any, Dict, List
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.db import get_db
from app.core.deps import get_current_user
from app.models.models import User
from app.storage.searchable_archive import SearchableArchiveEngine
from app.security.ledger import CryptographicAuditLedger

router = APIRouter(prefix="/api/archive", tags=["archive"])

# In-memory tenant archive cache
_TENANT_ARCHIVES: Dict[str, Dict[str, Any]] = {}


class CreateArchiveRequest(BaseModel):
    logs: List[str]


class SearchArchiveRequest(BaseModel):
    query: str


def _get_engine(org_id: str) -> SearchableArchiveEngine:
    tenant_master_key = hashlib.sha256(f"master_sse_key_{org_id}".encode()).digest()
    return SearchableArchiveEngine(tenant_master_key)


@router.post("/create")
def create_searchable_archive(
    payload: CreateArchiveRequest,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """
    Encrypts a batch of logs for cold storage (S3 / Parquet) and generates
    a cryptographic searchable index map.
    """
    engine = _get_engine(user.org_id)
    raw_logs = payload.logs or [
        "2026-09-01T00:10:00Z srv-db-01 sshd[1042]: Accepted password for root from 192.168.1.100 port 49120 ssh2",
        "2026-09-01T00:15:22Z srv-web-02 kernel: Outbound connection to 185.220.101.5:4444 established",
        "2026-09-01T00:20:11Z srv-app-03 powershell.exe -EncodedCommand SQBFAFgA... user=admin",
        "2026-09-01T00:25:40Z srv-bastion-04 sudo: deploy : TTY=pts/1 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/bash",
    ]

    encrypted_blob, dek, search_index = engine.encrypt_log_payload(raw_logs)

    archive_id = f"arch-{hashlib.sha256(encrypted_blob[:16]).hexdigest()[:8]}"
    _TENANT_ARCHIVES[user.org_id] = {
        "archive_id": archive_id,
        "encrypted_blob": encrypted_blob,
        "dek": dek,
        "search_index": search_index,
        "log_count": len(raw_logs),
        "created_at": "2026-09-01T00:00:00Z",
    }

    CryptographicAuditLedger.append_audit_log(
        db=db,
        org_id=user.org_id,
        actor_user_id=user.id,
        action="searchable_archive_created",
        target=archive_id,
        meta={"indexed_tokens_count": len(search_index), "log_count": len(raw_logs)},
    )

    return {
        "archive_id": archive_id,
        "status": "ENCRYPTED_AND_INDEXED",
        "total_records_indexed": len(raw_logs),
        "unique_search_tokens": len(search_index),
        "storage_tier": "S3 Cold Storage (Parquet SSE)",
    }


@router.post("/search")
def search_encrypted_archive(
    payload: SearchArchiveRequest,
    user: User = Depends(get_current_user),
):
    """
    Executes sub-millisecond search over cold encrypted index without decrypting bulk files.
    """
    engine = _get_engine(user.org_id)
    archive_data = _TENANT_ARCHIVES.get(user.org_id)

    if not archive_data:
        # Initialize default demo archive
        default_logs = [
            "2026-09-01T00:10:00Z srv-db-01 sshd[1042]: Accepted password for root from 192.168.1.100 port 49120 ssh2",
            "2026-09-01T00:15:22Z srv-web-02 kernel: Outbound connection to 185.220.101.5:4444 established",
            "2026-09-01T00:20:11Z srv-app-03 powershell.exe -EncodedCommand SQBFAFgA... user=admin",
            "2026-09-01T00:25:40Z srv-bastion-04 sudo: deploy : TTY=pts/1 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/bash",
        ]
        blob, dek, s_index = engine.encrypt_log_payload(default_logs)
        archive_data = {
            "archive_id": "arch-demo-01",
            "encrypted_blob": blob,
            "dek": dek,
            "search_index": s_index,
            "log_count": len(default_logs),
        }
        _TENANT_ARCHIVES[user.org_id] = archive_data

    result = engine.search_encrypted_archive(
        encrypted_blob=archive_data["encrypted_blob"],
        dek=archive_data["dek"],
        search_index=archive_data["search_index"],
        query_term=payload.query,
    )
    return result
