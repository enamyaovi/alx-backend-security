from celery import shared_task
from django.core.cache import cache
from django.utils import timezone
from datetime import timedelta
from ip_tracking.models import SuspiciousIP, RequestLog

@shared_task
def save_request_log(ip_address, path, country, city):
    """Save request logs asynchronously to DB."""
    RequestLog.objects.create(
        ip_address=ip_address,
        path=path,
        country=country,
        city=city,
    )

@shared_task
def detect_anomalies():
    """
    Check for IPs exceeding 100 requests/hour on sensitive paths.
    """
    # Look at the previous hour
    prev_hour = (timezone.now() - timedelta(hours=1)).strftime("%Y%m%d%H")

    pattern = f"hits:*:{prev_hour}"

    try:
        keys = cache.iter_keys(pattern) # type: ignore
    except AttributeError:
        keys = []

    for key in keys:
        count = cache.get(key) or 0
        if count > 100:
            # Extract the IP from the key format hits:<ip>:<hour>
            parts = key.split(":")
            ip = parts[1] if len(parts) >= 3 else "unknown"
            reason = f"Exceeded {count} requests in hour {prev_hour}"
            SuspiciousIP.objects.get_or_create(ip_address=ip, reason=reason)
