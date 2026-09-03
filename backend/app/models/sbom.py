"""
Tenant Software Bill of Materials (SBOM) Model (v6.0).
"""
import uuid
from sqlalchemy import Column, String, DateTime, Index
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func
from app.core.db import Base


class TenantSBOM(Base):
    """
    Stores tenant-authorized CycloneDX/SPDX software supply chain components and SHA-256 binary hashes.
    """
    __tablename__ = "tenant_sbom"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id = Column(String(100), nullable=False, index=True)
    component_name = Column(String(255), nullable=False)
    version = Column(String(50), nullable=False)
    sha256_hash = Column(String(64), nullable=False, index=True)
    license_type = Column(String(100), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    __table_args__ = (
        Index("idx_sbom_org_hash", "org_id", "sha256_hash"),
    )
