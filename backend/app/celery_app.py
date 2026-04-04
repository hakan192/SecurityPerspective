import os

from celery import Celery
from celery.schedules import crontab

celery_app = Celery(
    "security_perspective",
    broker=os.getenv("CELERY_BROKER_URL", "redis://redis:6379/0"),
    backend=os.getenv("CELERY_RESULT_BACKEND", "redis://redis:6379/1"),
)

celery_app.conf.task_default_queue = "default"
celery_app.conf.beat_schedule = {
    "scheduled-fortiweb-collection": {
        "task": "app.tasks.collect_fortiweb_config",
        "schedule": crontab(minute="*/30"),
        "args": (),
    }
}

celery_app.autodiscover_tasks(["app"])
