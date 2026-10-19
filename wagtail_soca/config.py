import base64
import hashlib
import json
from dataclasses import dataclass, field
from urllib.parse import urlsplit

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from django.conf import settings
from django.core.exceptions import ValidationError
from django.core.validators import validate_email
from django.urls import NoReverseMatch, reverse

from .errors import SocaError
from .http import validate_url


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


ADMIN_FIELDS = (
    "ENABLED",
    "ISSUER",
    "METADATA_PROXY",
    "ID_TOKEN_ALG",
    "ASSERTION_AUDIENCE",
    "ALLOW_EMAILS",
    "ALLOW_DOMAINS",
    "DENY_EMAILS",
    "DENY_DOMAINS",
    "CREATE_USERS",
    "NEW_USER_GROUP",
)


def get_values(*, use_database=True):
    values = dict(getattr(settings, "SOCA", {}))
    if use_database:
        from .models import SocaSettings

        stored = SocaSettings.objects.filter(pk=1).first()
        if stored:
            values.update(
                {name: value for name, value in stored.values.items() if name in ADMIN_FIELDS}
            )
            values["REVISION"] = str(stored.revision)
    return values


def enabled(*, use_database=True):
    return get_values(use_database=use_database).get("ENABLED", False) is True


@dataclass(frozen=True)
class Config:
    base_url: str
    issuer: str
    private_key: ec.EllipticCurvePrivateKey = field(repr=False)
    public_key: dict
    id_token_alg: str
    assertion_audience: str
    allow_emails: tuple
    allow_domains: tuple
    deny_emails: tuple
    deny_domains: tuple
    metadata_proxy: str | None = None
    revision: str = ""
    create_users: bool = False
    new_user_group: int | None = None

    def url(self, name):
        return self.base_url + reverse("wagtail_soca:" + name)

    @property
    def client_id(self):
        if self.metadata_proxy:
            encoded = (
                base64.urlsafe_b64encode(canonical(self.metadata()).encode()).rstrip(b"=").decode()
            )
            return self.metadata_proxy.replace("%s", encoded)
        return self.url("metadata")

    @property
    def fingerprint(self):
        return digest(
            canonical(
                {
                    "document": self.document(),
                    "public_key": self.public_key,
                    "issuer": self.issuer,
                    "revision": self.revision,
                    "assertion_audience": self.assertion_audience,
                    "provisioning": [self.create_users, self.new_user_group],
                    "policy": [
                        self.allow_emails,
                        self.allow_domains,
                        self.deny_emails,
                        self.deny_domains,
                    ],
                }
            )
        )

    def metadata(self):
        document = {
            "client_name": "Wagtail SOCA",
            "client_uri": self.base_url + "/",
            "redirect_uris": [self.url("callback")],
            "grant_types": ["authorization_code"],
            "response_types": ["code"],
            "scope": "openid email profile",
            "application_type": "web",
            "token_endpoint_auth_method": "private_key_jwt",
            "token_endpoint_auth_signing_alg": "ES256",
            "id_token_signed_response_alg": self.id_token_alg,
        }
        if self.metadata_proxy:
            document["jwks"] = {"keys": [self.public_key]}
        else:
            document["jwks_uri"] = self.url("jwks")
        return document

    def document(self):
        return {"client_id": self.client_id, **self.metadata()}


def get_config(*, values=None, require_enabled=True, use_database=True):
    values = get_values(use_database=use_database) if values is None else values
    if require_enabled and values.get("ENABLED", False) is not True:
        raise SocaError("disabled")
    try:
        base_url = values["BASE_URL"]
        parsed = validate_url(base_url)
        if parsed.path or parsed.query or "?" in base_url:
            raise SocaError("base_url_requires_origin")
        issuer = values.get("ISSUER", "https://auth.resoauth.cloud")
        if validate_url(issuer).query or "?" in issuer:
            raise SocaError("issuer_query")
        proxy = values.get("METADATA_PROXY")
        if proxy is not None:
            if not isinstance(proxy, str) or proxy.count("%s") != 1:
                raise SocaError("invalid_metadata_proxy")
            parsed_proxy = urlsplit(proxy)
            if (
                "%s" not in parsed_proxy.path
                or "%s" in parsed_proxy.netloc
                or "%s" in parsed_proxy.query
            ):
                raise SocaError("invalid_metadata_proxy")
            validate_url(proxy.replace("%s", "e30"))
        pem = values["PRIVATE_KEY"]
        if not isinstance(pem, str):
            raise SocaError("invalid_private_key")
        key = serialization.load_pem_private_key(pem.encode(), password=None)
        if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(
            key.curve, ec.SECP256R1
        ):
            raise SocaError("key_requires_p256")
        public = json.loads(jwt.algorithms.ECAlgorithm.to_jwk(key.public_key()))
        public.update(kid=digest(canonical(public)), use="sig", alg="ES256")
        algorithm = values.get("ID_TOKEN_ALG", "ES256")
        audience = values.get("ASSERTION_AUDIENCE", "issuer")
        if algorithm not in ("ES256", "RS256") or audience not in ("issuer", "token_endpoint"):
            raise SocaError("invalid_algorithm_or_audience")
        policy = {}
        create_users = values.get("CREATE_USERS", False)
        new_user_group = values.get("NEW_USER_GROUP")
        if type(create_users) is not bool or (
            new_user_group is not None and (type(new_user_group) is not int or new_user_group < 1)
        ):
            raise SocaError("invalid_provisioning_configuration")
        if create_users and new_user_group is None:
            raise SocaError("new_user_group_required")
        for name in ("ALLOW_EMAILS", "ALLOW_DOMAINS", "DENY_EMAILS", "DENY_DOMAINS"):
            entries = values.get(name, [])
            if not isinstance(entries, (tuple, list)) or any(
                not isinstance(x, str) for x in entries
            ):
                raise SocaError("invalid_policy")
            normalized = tuple(x.lower() for x in entries)
            for entry in normalized:
                validate_email(entry if name.endswith("EMAILS") else "policy@" + entry)
                if not entry.isascii() or entry != entry.strip() or "*" in entry:
                    raise SocaError("invalid_policy")
            policy[name.lower()] = normalized
        if settings.SESSION_ENGINE == "django.contrib.sessions.backends.signed_cookies":
            raise SocaError("server_side_sessions_required")
        if "django.contrib.auth.backends.ModelBackend" not in settings.AUTHENTICATION_BACKENDS:
            raise SocaError("model_backend_required")
        if (
            not settings.SESSION_COOKIE_SECURE
            or not settings.SESSION_COOKIE_HTTPONLY
            or settings.SESSION_COOKIE_SAMESITE != "Lax"
        ):
            raise SocaError("secure_lax_session_cookie_required")
        config = Config(
            base_url,
            issuer,
            key,
            public,
            algorithm,
            audience,
            metadata_proxy=proxy,
            revision=values.get("REVISION", ""),
            create_users=create_users,
            new_user_group=new_user_group,
            **policy,
        )
        config.document()  # Verify the public URL namespace is installed during system checks.
        validate_url(config.client_id)
        return config
    except (KeyError, TypeError, ValueError, ValidationError, NoReverseMatch) as exc:
        raise SocaError("invalid_configuration") from exc
