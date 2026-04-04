from celery import Celery

from app.core.config import settings

celery_app = Celery(
    'security_perspective',
    broker=settings.redis_url,
    backend=settings.redis_url,
    include=['app.tasks.tasks'],
)

celery_app.conf.beat_schedule = {
    'collect-fortiweb-config-every-30-mins': {
        'task': 'app.tasks.tasks.collect_and_parse_snapshot',
        'schedule': 1800.0,
    }
}
