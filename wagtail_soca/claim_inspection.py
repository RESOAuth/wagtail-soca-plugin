"""Explicit, one-shot inspection of validated claims, separate from application logs."""

import base64
import hashlib
import json
import uuid
from datetime import timedelta

from cryptography.fernet import Fernet, InvalidToken
from django.conf import settings
from django.utils import timezone

from .config import canonical
from .models import ClaimInspection

LIFETIME = timedelta(minutes=10)
# Unknown claims remain discoverable by name, but their values may be secrets.
VISIBLE_CLAIMS = frozenset(
    "iss sub aud exp iat nbf auth_time acr amr email email_verified name given_name "
    "middle_name family_name nickname preferred_username profile picture website locale "
    "zoneinfo updated_at".split()
)


def cipher():
    key = hashlib.sha256(
        b"wagtail-soca/claim-inspection/v1\0" + settings.SECRET_KEY.encode()
    ).digest()
    return Fernet(base64.urlsafe_b64encode(key))


def redact(claims):
    result = {}
    for name, value in claims.items():
        safe = name in VISIBLE_CLAIMS
        if isinstance(value, str):
            value = value[:1000]
        elif isinstance(value, list) and all(isinstance(item, str) for item in value):
            value = [item[:1000] for item in value[:20]]
        elif value is not None and type(value) not in (bool, int, float):
            safe = False
        result[name[:128]] = value if safe else "[redacted]"
    return result


def current():
    ClaimInspection.objects.filter(expires_at__lte=timezone.now()).delete()
    return ClaimInspection.objects.filter(pk=1).first()


def pending():
    row = current()
    return row if row and not row.payload else None


def arm():
    ClaimInspection.objects.update_or_create(
        pk=1,
        defaults={
            "revision": uuid.uuid4(),
            "expires_at": timezone.now() + LIFETIME,
            "captured_at": None,
            "payload": "",
        },
    )


def clear():
    ClaimInspection.objects.all().delete()


def capture(row, inspection, user):
    now = timezone.now()
    report = {
        "local_user_id": str(user.pk),
        "id_token": redact(inspection.get("id_token", {})),
        "userinfo": redact(inspection.get("userinfo", {})),
        "userinfo_status": inspection.get("userinfo_status", "unavailable"),
    }
    # Revision + conditional update prevents concurrent callbacks or old captures from
    # overwriting a newer arm/clear or an already captured result.
    ClaimInspection.objects.filter(
        pk=1, revision=row.revision, payload="", expires_at__gt=now
    ).update(
        payload=cipher().encrypt(canonical(report).encode()).decode(),
        captured_at=now,
        expires_at=now + LIFETIME,
    )


def display():
    row = current()
    if row is None:
        return None, ""
    if not row.payload:
        return row, ""
    try:
        report = json.loads(cipher().decrypt(row.payload.encode(), ttl=600))
    except (InvalidToken, ValueError):
        ClaimInspection.objects.filter(pk=1, revision=row.revision).delete()
        return None, ""
    return row, json.dumps(report, indent=2, ensure_ascii=True)
