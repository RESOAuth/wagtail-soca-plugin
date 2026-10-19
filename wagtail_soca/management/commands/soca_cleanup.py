from django.core.management.base import BaseCommand
from django.utils import timezone

from wagtail_soca.models import ClaimInspection, LoginTransaction


class Command(BaseCommand):
    help = "Delete expired SOCA transactions and claim inspections; run regularly (for example hourly)."

    def handle(self, **options):
        count, _ = LoginTransaction.objects.filter(expires_at__lte=timezone.now()).delete()
        self.stdout.write(f"Deleted {count} expired SOCA transactions.")
        count, _ = ClaimInspection.objects.filter(expires_at__lte=timezone.now()).delete()
        self.stdout.write(f"Deleted {count} expired SOCA claim inspections.")
