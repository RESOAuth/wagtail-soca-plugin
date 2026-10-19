"""Bind the existing local admin to the address its real identity provider will verify."""

import os
import sys
import uuid
from pathlib import Path

import django
from django.core.validators import validate_email


def main():
    if len(sys.argv) != 2:
        raise SystemExit("Usage: python -m demo.account your-email@example.com")
    email = sys.argv[1].strip().lower()
    validate_email(email)
    if not email.isascii():
        raise SystemExit("Use an ASCII email address.")
    os.environ["DJANGO_SETTINGS_MODULE"] = "demo.settings"
    django.setup()
    from django.contrib.auth import get_user_model

    from wagtail_soca.config import ADMIN_FIELDS, get_values
    from wagtail_soca.models import SocaSettings

    users = get_user_model().objects
    if users.filter(email__iexact=email).exclude(username="admin").exists():
        raise SystemExit("Another local account already uses this email.")
    if users.filter(username="admin").update(email=email) != 1:
        raise SystemExit("The local admin account is missing.")
    Path("/data/admin-email").write_text(email)
    values = get_values()
    values["ALLOW_EMAILS"] = list(dict.fromkeys([*values.get("ALLOW_EMAILS", []), email]))
    SocaSettings.objects.update_or_create(
        pk=1,
        defaults={
            "values": {name: value for name, value in values.items() if name in ADMIN_FIELDS},
            "revision": uuid.uuid4(),
            "updated_by": users.get(username="admin"),
        },
    )
    print("Configured the local administrator and its admission rule. Changes apply immediately.")


if __name__ == "__main__":
    main()
