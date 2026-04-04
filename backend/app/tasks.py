import datetime as dt
import os

from .celery_app import celery_app


@celery_app.task(name="app.tasks.collect_fortiweb_config")
def collect_fortiweb_config() -> dict:
    """Placeholder FortiWeb collection task for container wiring validation."""
    return {
        "collected_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "fortiweb_base_url": os.getenv("FORTIWEB_BASE_URL", "not-configured"),
        "status": "queued-and-executed",
    }
