"""Conservative profile defaults, never identity or permission mapping."""

import re
import unicodedata

from django.core.exceptions import FieldDoesNotExist, ValidationError
from django.db import IntegrityError, models, transaction
from django.db.models import Q

from .config import digest

PROFILE_CLAIMS = ("given_name", "family_name", "name", "preferred_username")


def profile_text(value):
    if not isinstance(value, str) or len(value) > 4096:
        return ""
    value = unicodedata.normalize("NFC", " ".join(value.split()))
    if any(unicodedata.category(char).startswith("C") or char in "<>" for char in value):
        return ""
    return value


def fill_names(user, claims):
    """Fill only truly blank name fields, with conditional writes preserving local edits."""
    given = profile_text(claims.get("given_name"))
    family = profile_text(claims.get("family_name"))
    if (
        not given
        and not family
        and not (getattr(user, "first_name", "") or getattr(user, "last_name", ""))
    ):
        # Do not guess how to split a full name into culturally specific name parts.
        given = profile_text(claims.get("name"))
    for name, value in (("first_name", given), ("last_name", family)):
        if not value or getattr(user, name, "") not in (None, ""):
            continue
        if name in (user.USERNAME_FIELD, user.get_email_field_name()):
            continue
        try:
            field = user._meta.get_field(name)
            if not isinstance(field, models.CharField) or field.unique:
                continue
            value = field.clean(value[: field.max_length] if field.max_length else value, user)
        except (FieldDoesNotExist, ValidationError):
            continue
        query = (
            type(user)
            ._default_manager.filter(pk=user.pk)
            .filter(Q(**{name: ""}) | Q(**{name + "__isnull": True}))
        )
        try:
            with transaction.atomic():
                updated = query.update(**{name: value})
        except IntegrityError:
            # Optional profile defaults must not break sign-in on custom constraints.
            continue
        if updated:
            setattr(user, name, value)
    return user


def set_new_username(user, email, claims):
    """Only new accounts: validated preferred username, then readable email-derived fallback."""
    name = user.USERNAME_FIELD
    if name == user.get_email_field_name():
        return
    field = user._meta.get_field(name)
    original = getattr(user, name)
    local = re.sub(r"[^\w.@+-]", "_", email.rsplit("@", 1)[0]).strip("._-") or "user"
    suffix = "_" + digest(email)[:12]
    candidates = (
        profile_text(claims.get("preferred_username")),
        local[: field.max_length - len(suffix)] + suffix,
    )
    for candidate in candidates:
        candidate = user.normalize_username(candidate)
        if not candidate or candidate.lower().startswith("soca_"):
            continue
        try:
            field.clean(candidate, user)
        except ValidationError:
            continue
        if (
            type(user)
            ._default_manager.filter(**{name + "__iexact": candidate})
            .exclude(pk=user.pk)
            .exists()
        ):
            continue
        try:
            # Database uniqueness remains authoritative if another creation races this check.
            with transaction.atomic():
                setattr(user, name, candidate)
                user.save(update_fields=[name])
            return
        except IntegrityError:
            setattr(user, name, original)
    # The initial deterministic soca_ identifier remains a safe final fallback.
