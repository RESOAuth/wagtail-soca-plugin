from django.core.management.base import BaseCommand, CommandError

from wagtail_soca.config import get_config
from wagtail_soca.diagnostics import check_connection
from wagtail_soca.errors import SocaError


class Command(BaseCommand):
    help = "Validate discovery and the publicly reachable CIMD document and signing key."

    def handle(self, **options):
        try:
            discovery = check_connection(get_config())
        except SocaError as exc:
            raise CommandError(str(exc)) from exc
        self.stdout.write(
            self.style.SUCCESS("Discovery, client metadata and public key validated.")
        )
        if discovery.get("client_id_metadata_document_supported") is not True:
            self.stdout.write("Provider CIMD support is unconfirmed; complete a real login test.")
        self.stdout.write("Document checks do not establish a successful provider login.")
