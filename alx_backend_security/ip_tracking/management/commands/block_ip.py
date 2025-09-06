from typing import Any
from django.core.management.base import BaseCommand, CommandParser
from ip_tracking.models import BlockedIP


class Command(BaseCommand):
    help = "Blocks or unblocks IPs from accessing views"

    def add_arguments(self, parser: CommandParser) -> None:
        parser.add_argument('-b', '--block', type=str, help='The IP address to be blocked')
        parser.add_argument('-u', '--unblock', type=str, help='The IP address to be unblocked')

    def handle(self, *args: Any, **options: Any) -> str | None:
        block = options.get('block')
        unblock = options.get('unblock')

        # Handle blocking
        if block:
            obj, created = BlockedIP.objects.get_or_create(ip_address=block)
            if created:
                self.stdout.write(self.style.SUCCESS(f"IP: {block} has been blocked"))
            else:
                self.stdout.write(self.style.WARNING(f"IP: {block} is already blocked"))

        # Handle unblocking
        if unblock:
            deleted, _ = BlockedIP.objects.filter(ip_address=unblock).delete()
            if deleted:
                self.stdout.write(self.style.SUCCESS(f"IP: {unblock} has been unblocked"))
            else:
                self.stdout.write(self.style.WARNING(f"IP: {unblock} was not blocked"))

        if not block and not unblock:
            self.stdout.write(self.style.ERROR("Please provide an --block or --unblock option."))
