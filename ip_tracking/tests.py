import pytest
from django.test import RequestFactory
from django.http import HttpResponse
from django.core.cache import cache
from django.utils import timezone
from ip_tracking.models import BlockedIP, RequestLog, SuspiciousIP
from ip_tracking.middleware import IPLoggingMiddleware
from ip_tracking.tasks import detect_anomalies
from datetime import timedelta

# Fixtures
@pytest.fixture
def rf():
    return RequestFactory()


@pytest.fixture(autouse=True)
def clear_cache_and_db():
    """Ensure cache and DB are clean before each test."""
    cache.clear()
    yield
    cache.clear()
    BlockedIP.objects.all().delete()
    RequestLog.objects.all().delete()
    SuspiciousIP.objects.all().delete()


def get_response_ok(_request):
    return HttpResponse("OK")


# Middleware Tests
@pytest.mark.django_db
def test_allows_non_blocked_ip_and_caches_geolocation(rf):
    request = rf.get("/login")
    request.META["REMOTE_ADDR"] = "1.2.3.4"
    request.geolocation = {"country_name": "Ghana", "city": "Accra"}

    middleware = IPLoggingMiddleware(get_response_ok)
    response = middleware(request)
    assert response.status_code == 200

    # Subsequent request should use cached geolocation
    request2 = rf.get("/login")
    request2.META["REMOTE_ADDR"] = "1.2.3.4"
    middleware(request2)
    assert cache.get("geo:1.2.3.4") == {"country_name": "Ghana", "city": "Accra"}


@pytest.mark.django_db
def test_blocks_blacklisted_ip(rf):
    BlockedIP.objects.create(ip_address="9.9.9.9")

    request = rf.get("/login")
    request.META["REMOTE_ADDR"] = "9.9.9.9"
    request.geolocation = {"country_name": "Unknown", "city": "Unknown"}

    middleware = IPLoggingMiddleware(get_response_ok)
    response = middleware(request)
    assert response.status_code == 403
    assert b"403 Forbidden" in response.content


@pytest.mark.django_db
def test_handles_missing_geolocation(rf):
    request = rf.get("/login")
    request.META["REMOTE_ADDR"] = "5.6.7.8"

    middleware = IPLoggingMiddleware(get_response_ok)
    response = middleware(request)
    assert response.status_code == 200


@pytest.mark.django_db
def test_sensitive_path_increments_cache(rf):
    request = rf.get("/login")
    request.META["REMOTE_ADDR"] = "2.3.4.5"
    request.geolocation = {"country_name": "Ghana", "city": "Accra"}

    middleware = IPLoggingMiddleware(get_response_ok)
    middleware(request)

    keys = [k for k in cache.keys("hits:2.3.4.5:*") if k.startswith("hits:2.3.4.5:")] # type: ignore
    assert keys
    # The counter should start at 1
    assert cache.get(keys[0]) == 1


@pytest.mark.django_db
def test_request_logged_to_db(rf):
    request = rf.get("/login")
    request.META["REMOTE_ADDR"] = "3.3.3.3"
    request.geolocation = {"country_name": "Ghana", "city": "Accra"}

    middleware = IPLoggingMiddleware(get_response_ok)
    middleware(request)

    log = RequestLog.objects.last()
    assert log.ip_address == "3.3.3.3" # type: ignore
    assert log.country == "Ghana" # type: ignore
    assert log.city == "Accra" # type: ignore


# Celery Task Test
@pytest.mark.django_db
def test_detect_anomalies_flags_suspicious_ip():
    # Prepare cache: simulate >100 requests in previous hour
    prev_hour = (timezone.now() - timedelta(hours=1)).strftime("%Y%m%d%H")
    ip = "7.8.9.10"
    key = f"hits:{ip}:{prev_hour}"
    cache.set(key, 150, timeout=3600)

    # Run task synchronously
    detect_anomalies()

    # Check if SuspiciousIP entry was created
    suspicious = SuspiciousIP.objects.filter(ip_address=ip).first()
    assert suspicious is not None
    assert "Exceeded" in suspicious.reason
