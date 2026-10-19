import base64
import hashlib
import json
import secrets
import time
from datetime import timedelta

from cryptography.fernet import Fernet, InvalidToken
from django.conf import settings
from django.utils import timezone

from .config import canonical, digest
from .errors import SocaError
from .models import LoginTransaction


def cipher():
    key = hashlib.sha256(b"wagtail-soca/transactions/v1\0" + settings.SECRET_KEY.encode()).digest()
    return Fernet(base64.urlsafe_b64encode(key))


def begin(request, config, discovery, destination):
    # This secret lives only in a server-side Django session. It binds the callback to its browser.
    browser = request.session.get("soca_browser")
    if not browser:
        browser = secrets.token_urlsafe(32)
        request.session["soca_browser"] = browser
    state = secrets.token_urlsafe(32)
    payload = {
        "nonce": secrets.token_urlsafe(32),
        "verifier": secrets.token_urlsafe(64),
        "started": int(time.time()),
        "discovery": discovery,
        "fingerprint": config.fingerprint,
        "destination": destination,
    }
    LoginTransaction.objects.create(
        state_digest=digest(state),
        browser_digest=digest(browser),
        payload=cipher().encrypt(canonical(payload).encode()).decode(),
        expires_at=timezone.now() + timedelta(minutes=10),
    )
    return state, payload


def consume(request, config, state):
    if not isinstance(state, str) or len(state) != 43:
        raise SocaError("invalid_state")
    browser = request.session.get("soca_browser", "")
    if not browser:
        raise SocaError("browser_mismatch")
    query = LoginTransaction.objects.filter(
        state_digest=digest(state),
        browser_digest=digest(browser),
        expires_at__gt=timezone.now(),
        consumed=False,
    )
    row = query.first()
    # A conditional UPDATE is an atomic one-time claim, including across workers on SQLite.
    if row is None or query.update(consumed=True) != 1:
        raise SocaError("transaction_unavailable")
    try:
        payload = json.loads(cipher().decrypt(row.payload.encode(), ttl=600))
    except (InvalidToken, ValueError) as exc:
        raise SocaError("transaction_invalid") from exc
    if payload["fingerprint"] != config.fingerprint:
        raise SocaError("configuration_changed")
    return payload
