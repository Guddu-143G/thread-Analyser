import os
try:
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

    is_serverless = bool(os.environ.get("VERCEL") or os.environ.get("AWS_LAMBDA_FUNCTION_NAME"))
    if not is_serverless:
        celery_app.autodiscover_tasks(["app.workers", "app.tasks"])

    celery_app.conf.beat_schedule = {
        "refresh-threat-intel-hourly": {
            "task": "refresh_threat_intel_task",
            "schedule": 3600.0,
        },
    }
except Exception:
    class DummyCelery:
        def task(self, *args, **kwargs):
            def decorator(fn):
                return fn
            return decorator
    celery_app = DummyCelery()


