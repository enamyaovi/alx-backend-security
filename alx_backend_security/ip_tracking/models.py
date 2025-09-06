from django.db import models

# Create your models here.
class RequestLog(models.Model):
    """ A model to log IP addresses that access views"""

    ip_address = models.GenericIPAddressField(
        verbose_name= 'IP Address tracked'
    )

    timestamp = models.DateTimeField(
        verbose_name='Time address was tracked',
        auto_now_add=True
    )

    path = models.CharField(
        verbose_name='the path accessed by the IP'
    )

    country = models.CharField(
        verbose_name='Country of the IP',
        max_length= 200
    )

    city = models.CharField(
        verbose_name='City of the IP',
        max_length=250
    )

    def __str__(self) -> str:
        return f"{self.ip_address} at sensitive path: {self.path}"
    

class BlockedIP(models.Model):
    """ A model for storing blocked IP addresses"""

    ip_address = models.GenericIPAddressField(
        verbose_name='A blocked IP address'
    )

class SuspiciousIP(models.Model):

    ip_address = models.GenericIPAddressField()

    reason = models.CharField(max_length=200)