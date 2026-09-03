import logging

from app.workers.celery_app import celery_app
from app.core.db import SessionLocal
from app.detection.pipeline import process_log_batch

logger = logging.getLogger(__name__)


@celery_app.task(name="process_log_batch_task", bind=True, max_retries=3)
def process_log_batch_task(self, org_id: str, device_id: str | None, raw_text: str):
    db = SessionLocal()
    try:
        result = process_log_batch(db, org_id, device_id, raw_text)
        logger.info("Processed log batch for org=%s: %s", org_id, result)
        return result
    except Exception as exc:  # noqa: BLE001
        db.rollback()
        logger.exception("Log batch processing failed for org=%s", org_id)
        raise self.retry(exc=exc, countdown=5)
    finally:
        db.close()


@celery_app.task(name="refresh_threat_intel_task")
def refresh_threat_intel_task():
    """
    Periodic hook (wired via Celery beat) for pulling updates into the global
    threat_indicators table from external feeds. MVP is a no-op placeholder —
    org-specific IOC import happens synchronously via the CSV import endpoint.
    """
    logger.info("Threat intel refresh tick (no external feed configured in MVP).")
    return {"status": "noop"}
