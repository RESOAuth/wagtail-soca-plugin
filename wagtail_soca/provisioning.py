"""Opt-in, group-scoped provisioning after verified-email admission."""

import logging

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.core.exceptions import FieldDoesNotExist, ValidationError
from django.db import IntegrityError, models, transaction

from .config import digest
from .errors import SocaError
from .profiles import set_new_username

logger = logging.getLogger(__name__)


class _ConcurrentEmailCreation(Exception):
    pass


def eligible_groups():
    return Group.objects.filter(
        permissions__content_type__app_label="wagtailadmin",
        permissions__codename="access_admin",
    ).distinct()


def matching_users(email):
    model = get_user_model()
    return list(
        model._default_manager.filter(**{model.get_email_field_name() + "__iexact": email})[:2]
    )


def eligible_user(matches):
    if len(matches) != 1:
        raise SocaError("account_missing_or_ambiguous")
    user = matches[0]
    if not user.is_active or not user.has_perm("wagtailadmin.access_admin"):
        raise SocaError("account_ineligible")
    return user


def provisioning_fields(email):
    model = get_user_model()
    email_name = model.get_email_field_name()
    try:
        username = model._meta.get_field(model.USERNAME_FIELD)
        email_field = model._meta.get_field(email_name)
        for name in ("groups", "password", "is_active", "is_staff", "is_superuser"):
            model._meta.get_field(name)
        if (
            not isinstance(username, models.CharField)
            or not username.unique
            or not username.max_length
            or set(model.REQUIRED_FIELDS) - {email_name}
        ):
            raise SocaError("unsupported_provisioning_user_model")
        # Stable, unique identifiers make simultaneous first logins converge on one account.
        identifier = email if model.USERNAME_FIELD == email_name else "soca_" + digest(email)
        if model.USERNAME_FIELD != email_name:
            if username.max_length < 37:
                raise SocaError("unsupported_provisioning_user_model")
            identifier = identifier[: username.max_length]
        username.clean(identifier, None)
        email_field.clean(email, None)
    except (FieldDoesNotExist, ValidationError) as exc:
        raise SocaError("unsupported_provisioning_user_model") from exc
    return {email_name: email, model.USERNAME_FIELD: identifier}


def create_user(config, email, claims):
    fields = provisioning_fields(email)
    group = eligible_groups().filter(pk=config.new_user_group).first()
    if group is None:
        raise SocaError("new_user_group_ineligible")
    model = get_user_model()
    try:
        with transaction.atomic():
            # Write first: no SQLite read-to-write transaction upgrade during concurrent logins.
            user = model(**fields, is_active=True, is_staff=False, is_superuser=False)
            user.set_unusable_password()
            user.save(force_insert=True)
            # The deterministic insertion serializes same-email plugin creators even
            # when their eventual preferred usernames differ. Recheck before renaming.
            if len(matching_users(email)) != 1:
                raise _ConcurrentEmailCreation
            if not eligible_groups().filter(pk=group.pk).exists():
                raise SocaError("new_user_group_ineligible")
            user.groups.add(group)
            set_new_username(user, email, claims)
            user = eligible_user(matching_users(email))
            # Re-read after writes/signals; unsafe custom defaults must roll back.
            if user.is_staff or user.is_superuser or user.has_usable_password():
                raise SocaError("unsafe_provisioned_account")
            transaction.on_commit(
                lambda: logger.info("SOCA account created for local user %s", user.pk)
            )
            return user
    except (IntegrityError, _ConcurrentEmailCreation) as exc:
        # A concurrent callback may have won the unique-username insert. Reuse only an
        # unambiguous, eligible email match; never attach to a different-email collision.
        matches = matching_users(email)
        if len(matches) == 1:
            return eligible_user(matches)
        raise SocaError("account_creation_conflict") from exc
