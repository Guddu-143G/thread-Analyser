from celery import Celery

from app.core.config import settings

celery_app = Celery(
    "threat_analyser",
    broker=settings.REDIS_URL,
    backend=settings.REDIS_URL,
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
)

celery_app.autodiscover_tasks(["app.workers"])

celery_app.conf.beat_schedule = {
    "refresh-threat-intel-hourly": {
        "task": "refresh_threat_intel_task",
        "schedule": 3600.0,
    },
}
