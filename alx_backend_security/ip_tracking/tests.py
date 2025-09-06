import pytest
from django.test import RequestFactory
from django.http import HttpResponse
from django.core.cache import cache
from ip_tracking.models import BlockedIP
from ip_tracking.middleware import TrackIPMiddleware


@pytest.fixture
def rf():
    return RequestFactory()


@pytest.fixture(autouse=True)
def clear_cache():
    """Ensure cache is cleared before each test."""
    cache.clear()
    yield
    cache.clear()


def get_response_ok(_request):
    return HttpResponse("OK")


@pytest.mark.django_db
def test_allows_non_blocked_ip_and_caches_geolocation(rf):
    request = rf.get("/some-path/")
    request.META["REMOTE_ADDR"] = "1.2.3.4"
    request.geolocation = {"country_name": "Ghana", "city": "Accra"}

    middleware = TrackIPMiddleware(get_response_ok)

    response = middleware(request)
    assert response.status_code == 200

    request2 = rf.get("/some-path/")
    request2.META["REMOTE_ADDR"] = "1.2.3.4"
    middleware(request2)
    assert cache.get("geo:1.2.3.4") == {"country_name": "Ghana", "city": "Accra"}


@pytest.mark.django_db
def test_blocks_blacklisted_ip(rf):
    BlockedIP.objects.create(ip_address="9.9.9.9")

    request = rf.get("/blocked/")
    request.META["REMOTE_ADDR"] = "9.9.9.9"
    request.geolocation = {"country_name": "Unknown", "city": "Unknown"}

    middleware = TrackIPMiddleware(get_response_ok)

    response = middleware(request)
    assert response.status_code == 403
    assert b"403 Forbidden" in response.content


@pytest.mark.django_db
def test_handles_missing_geolocation(rf):
    request = rf.get("/no-geo/")
    request.META["REMOTE_ADDR"] = "5.6.7.8"

    middleware = TrackIPMiddleware(get_response_ok)

    response = middleware(request)
    assert response.status_code == 200
