from typing import Any
import ipaddress
from django.core.management.base import BaseCommand, CommandParser, CommandError
from ip_tracking.models import BlockedIP


class Command(BaseCommand):
    help = "Blocks or unblocks IPs from accessing views by blacklisting"

    def add_arguments(self, parser: CommandParser) -> None:
        group = parser.add_mutually_exclusive_group(required=True)
        group.add_argument(
            "-b", "--block",
            type=str,
            help="The IP address to be blocked"
        )
        group.add_argument(
            "-u", "--unblock",
            type=str,
            help="The IP address to be unblocked"
        )

    def handle(self, *args: Any, **options: Any) -> None:
        block = options.get("block")
        unblock = options.get("unblock")

        if block:
            # Validate IP
            try:
                ipaddress.ip_address(block)
            except ValueError:
                raise CommandError(f"Invalid IP address: {block}")

            obj, created = BlockedIP.objects.get_or_create(ip_address=block)
            if created:
                self.stdout.write(self.style.SUCCESS(f"IP {block} has been blocked."))
            else:
                self.stdout.write(self.style.WARNING(f"IP {block} was already blocked."))

        if unblock:
            # Validate IP
            try:
                ipaddress.ip_address(unblock)
            except ValueError:
                raise CommandError(f"Invalid IP address: {unblock}")

            deleted, _ = BlockedIP.objects.filter(ip_address=unblock).delete()
            if deleted:
                self.stdout.write(self.style.SUCCESS(f"IP {unblock} has been unblocked."))
            else:
                self.stdout.write(self.style.WARNING(f"IP {unblock} was not blocked."))
