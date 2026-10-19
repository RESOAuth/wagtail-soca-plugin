import logging

from django.contrib.auth import login as django_login
from django.http import Http404, HttpResponseRedirect, JsonResponse
from django.shortcuts import render
from django.urls import reverse
from django.utils.http import url_has_allowed_host_and_scheme
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_GET

from . import claim_inspection, protocol, transactions
from .config import enabled, get_config
from .errors import SocaError

logger = logging.getLogger("wagtail_soca")


def failure(request, error):
    logger.warning("SOCA login refused: %s", str(error))
    response = render(request, "wagtail_soca/error.html", status=403)
    response["Referrer-Policy"] = "no-referrer"
    return response


@require_GET
def metadata(request):
    if not enabled():
        raise Http404
    response = JsonResponse(get_config().document())
    response["Cache-Control"] = "public, max-age=300"
    return response


@require_GET
def jwks(request):
    if not enabled():
        raise Http404
    response = JsonResponse({"keys": [get_config().public_key]})
    response["Cache-Control"] = "public, max-age=300"
    return response


def safe_destination(value):
    # Only local absolute paths; never an arbitrary origin, even if it is in ALLOWED_HOSTS.
    if (
        value.startswith("/")
        and not value.startswith("//")
        and url_has_allowed_host_and_scheme(value, allowed_hosts=set(), require_https=True)
    ):
        return value
    return reverse("wagtailadmin_home")


@require_GET
@never_cache
def start(request):
    try:
        config = get_config()
        destination = safe_destination(request.GET.get("next", ""))
        state, payload = transactions.begin(request, config, protocol.discover(config), destination)
        response = HttpResponseRedirect(protocol.authorization_url(config, state, payload))
        response["Referrer-Policy"] = "no-referrer"
        return response
    except SocaError as exc:
        return failure(request, exc)


@require_GET
@never_cache
def callback(request):
    try:
        config = get_config()
        for name in ("state", "code", "iss", "error"):
            if len(request.GET.getlist(name)) > 1:
                raise SocaError("duplicate_callback_parameter")
        payload = transactions.consume(request, config, request.GET.get("state"))
        issuer = request.GET.get("iss")
        if (
            issuer is not None
            or payload["discovery"].get("authorization_response_iss_parameter_supported")
        ) and issuer != config.issuer:
            raise SocaError("response_issuer_mismatch")
        code = request.GET.get("code", "")
        if "error" in request.GET or not 1 <= len(code) <= 4096 or not code.isascii():
            raise SocaError("authorization_refused")
        pending = claim_inspection.pending()
        inspection = {} if pending else None
        claims = protocol.exchange(config, payload, code, inspection=inspection)
        user = protocol.resolve_user(config, claims)
        django_login(request, user, backend="django.contrib.auth.backends.ModelBackend")
        if pending:
            claim_inspection.capture(pending, inspection, user)
        logger.info("SOCA login accepted for local user %s", user.pk)
        response = HttpResponseRedirect(safe_destination(payload["destination"]))
        response["Referrer-Policy"] = "no-referrer"
        return response
    except SocaError as exc:
        return failure(request, exc)
