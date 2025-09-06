from django.db import models


class RequestLog(models.Model):
    """
    Log entry for an IP address accessing a view.

    Stores IP address, path accessed, timestamp, and optional
    geolocation details (country and city).
    """

    ip_address = models.GenericIPAddressField(
        verbose_name="IP address tracked"
    )
    timestamp = models.DateTimeField(
        verbose_name="Time address was tracked",
        auto_now_add=True
    )
    path = models.CharField(
        verbose_name="Path accessed by the IP",
        max_length=500
    )
    country = models.CharField(
        verbose_name="Country of the IP",
        max_length=200
    )
    city = models.CharField(
        verbose_name="City of the IP",
        max_length=250
    )

    class Meta:
        verbose_name = "Request Log"
        verbose_name_plural = "Request Logs"
        ordering = ["-timestamp"]

    def __str__(self) -> str:
        return f"{self.ip_address} accessed {self.path} at {self.timestamp}"


class BlockedIP(models.Model):
    """
    Store blocked IP addresses.
    """

    ip_address = models.GenericIPAddressField(
        verbose_name="Blocked IP address",
        unique=True
    )

    class Meta:
        verbose_name = "Blocked IP"
        verbose_name_plural = "Blocked IPs"

    def __str__(self) -> str:
        return self.ip_address


class SuspiciousIP(models.Model):
    """
    Store suspicious IP addresses flagged by anomaly detection.
    """

    ip_address = models.GenericIPAddressField(
        verbose_name="Suspicious IP address"
    )
    reason = models.CharField(
        verbose_name="Reason flagged",
        max_length=200
    )
    flagged_at = models.DateTimeField(
        auto_now_add=True
    )

    class Meta:
        verbose_name = "Suspicious IP"
        verbose_name_plural = "Suspicious IPs"
        ordering = ["-flagged_at"]

    def __str__(self) -> str:
        return f"{self.ip_address} - {self.reason}"
