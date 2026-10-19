import uuid

from django.conf import settings
from django.db import models


class LoginTransaction(models.Model):
    # Only digests and authenticated ciphertext persist in the database.
    state_digest = models.CharField(max_length=64, primary_key=True)
    browser_digest = models.CharField(max_length=64)
    payload = models.TextField()
    expires_at = models.DateTimeField(db_index=True)
    consumed = models.BooleanField(default=False)


class SocaSettings(models.Model):
    """One application-wide configuration; private keys never enter this table."""

    id = models.PositiveSmallIntegerField(primary_key=True, default=1, editable=False)
    values = models.JSONField(default=dict)
    revision = models.UUIDField(default=uuid.uuid4, editable=False)
    updated_at = models.DateTimeField(auto_now=True)
    updated_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL, related_name="+"
    )

    class Meta:
        verbose_name = "SOCA settings"
        verbose_name_plural = "SOCA settings"


class ClaimInspection(models.Model):
    """One explicitly armed, short-lived diagnostic; never contains a raw token."""

    id = models.PositiveSmallIntegerField(primary_key=True, default=1, editable=False)
    revision = models.UUIDField(default=uuid.uuid4, editable=False)
    expires_at = models.DateTimeField()
    captured_at = models.DateTimeField(null=True, blank=True)
    payload = models.TextField(blank=True)
