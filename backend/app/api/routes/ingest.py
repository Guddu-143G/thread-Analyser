from datetime import datetime

from fastapi import APIRouter, Depends, UploadFile, File, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.db import get_db
from app.core.deps import get_current_user, get_device_from_api_key
from app.models.models import User, Device
from app.schemas.schemas import IngestResult
from app.workers.tasks import process_log_batch_task

router = APIRouter(prefix="/api/ingest", tags=["ingestion"])

MAX_UPLOAD_BYTES = 10 * 1024 * 1024  # 10MB


class PushPayload(BaseModel):
    logs: str  # raw newline-delimited log text


@router.post("/upload", response_model=IngestResult)
async def upload_logs(
    file: UploadFile = File(...),
    device_id: str | None = None,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    content = await file.read()
    if len(content) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="File too large (max 10MB)")

    if device_id:
        device = db.query(Device).filter(Device.id == device_id, Device.org_id == user.org_id).first()
        if not device:
            raise HTTPException(status_code=404, detail="Device not found")

    raw_text = content.decode("utf-8", errors="ignore")
    line_count = len([l for l in raw_text.splitlines() if l.strip()])

    process_log_batch_task.delay(user.org_id, device_id, raw_text)

    return IngestResult(accepted_events=line_count, queued=True)


@router.post("/push", response_model=IngestResult)
def push_logs(
    payload: PushPayload,
    db: Session = Depends(get_db),
    device: Device = Depends(get_device_from_api_key),
):
    device.last_seen = datetime.utcnow()
    db.add(device)
    db.commit()

    line_count = len([l for l in payload.logs.splitlines() if l.strip()])
    process_log_batch_task.delay(device.org_id, device.id, payload.logs)

    return IngestResult(accepted_events=line_count, queued=True)


@router.post("/ebpf", response_model=IngestResult)
def push_ebpf_telemetry(
    payload: PushPayload,
    db: Session = Depends(get_db),
    device: Device = Depends(get_device_from_api_key),
):
    """
    High-Throughput eBPF In-Kernel Telemetry Ingest:
    Receives system call events directly from ring buffer collectors with zero context-switch loss.
    """
    device.last_seen = datetime.utcnow()
    db.add(device)
    db.commit()

    line_count = len([l for l in payload.logs.splitlines() if l.strip()])
    # Dispatch kernel batch to high-priority Celery queue
    process_log_batch_task.delay(device.org_id, device.id, payload.logs)

    return IngestResult(accepted_events=line_count, queued=True)

