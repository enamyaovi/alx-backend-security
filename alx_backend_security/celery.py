import os
from celery import Celery

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'alx_backend_security.settings')

app = Celery(
    'alx_backend_security',
    broker="redis://127.0.0.1:6379/1",
    backend="redis://127.0.0.1:6379/2"
)

# Load celery config from Django settings with CELERY_ prefix
app.config_from_object('django.conf:settings', namespace='CELERY')

# Auto-discover tasks from all apps
app.autodiscover_tasks()

# Optional configs
app.conf.update(
    result_expires=3600,  # 1 hour
)
