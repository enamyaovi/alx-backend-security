from typing import Any
import logging
from django.http import HttpResponseForbidden
from django.core.cache import cache
from django.db import IntegrityError
from django.utils import timezone
from ip_tracking.models import BlockedIP, RequestLog
# from ip_tracking.tasks import save_request_log


# Logger configuration
logger = logging.getLogger(__name__)
file_handler = logging.FileHandler("ip_logs.log", mode="a", encoding="utf-8")
formatter = logging.Formatter(
    "{asctime} - {levelname} - {message}",
    style="{",
    datefmt="%Y-%m-%d %H:%M",
)
file_handler.setFormatter(formatter)
file_handler.setLevel(logging.INFO)
logger.addHandler(file_handler)
logger.setLevel(logging.INFO)


class  IPLoggingMiddleware:
    """
    Middleware to track, cache geolocation, block IPs,
    and count sensitive path hits."""

    CACHE_TIMEOUT = 60 * 60 * 24  # 24 hours
    SENSITIVE_PATHS = ["/admin", "/login"]

    def __init__(self, get_response) -> None:
        self.get_response = get_response

    def __call__(self, request: Any, *args: Any, **kwargs: Any) -> Any:
        client_ip = self._get_client_ip(request)
        if not client_ip:
            logger.warning(f"No IP found. Request path: {request.path}")
            return self.get_response(request)

        # Blocking blacklisted IP
        if BlockedIP.objects.filter(ip_address=client_ip).exists():
            logger.critical(f"Blocked IP {client_ip} tried to access {request.path}")
            return HttpResponseForbidden("403 Forbidden")


        # Sensitive path counting and caching to redis
        for sensitive in self.SENSITIVE_PATHS:
            if request.path.startswith(sensitive):
                hour = timezone.now().strftime("%Y%m%d%H")  # current hour
                key = f"hits:{client_ip}:{hour}"
                try:
                    if cache.add(key, 1, timeout=3600):  # create if missing
                        pass
                    else:
                        cache.incr(key)  # increment
                except Exception as e:
                        logger.warning(f"Failed to increment counter for {client_ip}: {e}")
                break

        # Geolocation caching for 24 hours
        cache_key = f"geo:{client_ip}"
        cached_location = cache.get(cache_key)

        # geolocation is attached to request object from the middleware in IPGeolocationMiddleware
        if cached_location:
            request.geolocation = cached_location
        elif hasattr(request, "geolocation") and request.geolocation:
            cache.set(cache_key, request.geolocation, self.CACHE_TIMEOUT)


        response = self.get_response(request)

        # Logging request to log file and to DB
        if hasattr(request, "geolocation") and request.geolocation:
            country = request.geolocation.get("country_name", "Unknown Country")
            city = request.geolocation.get("city", "Unknown City")
            logger.info(
                f"IP {client_ip} hit path '{request.path}' "
                f"from {country} - {city}"
            )
            try:
                RequestLog.objects.create(
                    ip_address=client_ip,
                    path=request.path,
                    country=country,
                    city=city)
            except IntegrityError:
                pass 

        return response

    def _get_client_ip(self, request) -> str | None:
        """Extract client IP from request headers."""
        x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
        if x_forwarded_for:
            return x_forwarded_for.split(",")[0].strip()
        return request.META.get("REMOTE_ADDR")
