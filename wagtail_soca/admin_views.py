import logging
import uuid

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied
from django.db import IntegrityError, transaction
from django.http import HttpResponseRedirect
from django.shortcuts import render
from django.urls import reverse
from django.utils import timezone
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.http import require_http_methods

from . import claim_inspection
from .config import get_config, get_values
from .diagnostics import check_connection
from .errors import SocaError
from .forms import SocaSettingsForm
from .models import SocaSettings

logger = logging.getLogger("wagtail_soca")


def save_settings(form, user):
    revision = form.cleaned_data["revision"]
    changes = {
        "values": form.to_settings(),
        "revision": uuid.uuid4(),
        "updated_by": user,
        "updated_at": timezone.now(),
    }
    if revision is None:
        try:
            with transaction.atomic():
                SocaSettings.objects.create(pk=1, **changes)
        except IntegrityError:
            return False
    elif SocaSettings.objects.filter(pk=1, revision=revision).update(**changes) != 1:
        return False
    logger.info("SOCA settings saved by local user %s", user.pk)
    return True


@never_cache
@require_http_methods(["GET", "POST"])
@csrf_protect
@login_required(login_url="wagtailadmin_login")
def settings_view(request):
    if not request.user.is_active or not request.user.is_superuser:
        raise PermissionDenied
    stored = SocaSettings.objects.filter(pk=1).first()
    values = get_values()
    form = SocaSettingsForm(values=values, revision=stored.revision if stored else None)
    if request.method == "POST":
        action = request.POST.get("action", "save")
        if action in ("inspect_arm", "inspect_clear"):
            if action == "inspect_arm":
                claim_inspection.arm()
                messages.success(
                    request,
                    "Claim inspector armed for the next successful SSO login on this installation. It expires in 10 minutes.",
                )
            else:
                claim_inspection.clear()
                messages.success(request, "Claim inspection cleared and disabled.")
            return HttpResponseRedirect(reverse("wagtail_soca_settings") + "#claim-inspector")
        if action == "check":
            try:
                discovery = check_connection(get_config())
            except SocaError as exc:
                messages.error(
                    request,
                    f"Connection check failed ({exc}). Check the saved provider and metadata settings. Enable SSO before checking publication.",
                )
            else:
                messages.success(
                    request,
                    "Provider discovery, client metadata and public key validated. Complete an SSO login to test authentication.",
                )
                if discovery.get("client_id_metadata_document_supported") is not True:
                    messages.warning(
                        request,
                        "The provider does not advertise the standard CIMD support field; verify acceptance with a real login.",
                    )
            return HttpResponseRedirect(reverse("wagtail_soca_settings") + "#connection-check")
        if action != "save":
            raise PermissionDenied
        form = SocaSettingsForm(request.POST, values=values)
        if form.is_valid():
            if save_settings(form, request.user):
                messages.success(
                    request,
                    "SOCA settings saved. Changes apply immediately; pending SSO logins must start again.",
                )
                return HttpResponseRedirect(reverse("wagtail_soca_settings"))
            form.add_error(
                None,
                "Another administrator changed these settings. Reload the page before saving again.",
            )
    try:
        config = get_config(values=values, require_enabled=False)
        configuration_error = ""
    except SocaError as exc:
        config, configuration_error = None, str(exc)
    inspection, inspection_json = claim_inspection.display()
    return render(
        request,
        "wagtail_soca/settings.html",
        {
            "form": form,
            "config": config,
            "configuration_error": configuration_error,
            "sso_enabled": values.get("ENABLED", False),
            "admission_empty": not values.get("ALLOW_EMAILS") and not values.get("ALLOW_DOMAINS"),
            "updated_at": stored.updated_at if stored else None,
            "account_url": reverse("wagtailusers_users:edit", args=[request.user.pk]),
            "account_email": getattr(request.user, request.user.get_email_field_name()),
            "callback_url": config.url("callback") if config else "",
            "inspection": inspection,
            "inspection_json": inspection_json,
        },
        status=200 if not form.is_bound or not form.errors else 400,
    )
