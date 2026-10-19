import base64
import hashlib
import hmac
import re
import secrets
import time
from urllib.parse import parse_qs, urlencode, urlsplit

import jwt
from django.core.exceptions import ValidationError
from django.core.validators import validate_email

from . import http
from .errors import SocaError
from .profiles import PROFILE_CLAIMS, fill_names, profile_text
from .provisioning import create_user, eligible_user, matching_users


def b64(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def discover(config):
    document = http.request_json(config.issuer.rstrip("/") + "/.well-known/openid-configuration")
    if document.get("issuer") != config.issuer:
        raise SocaError("issuer_mismatch")
    for name in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
        http.validate_url(document.get(name))
    if "userinfo_endpoint" in document:
        http.validate_url(document["userinfo_endpoint"])
    required = {
        "response_types_supported": "code",
        "code_challenge_methods_supported": "S256",
        "token_endpoint_auth_methods_supported": "private_key_jwt",
        "token_endpoint_auth_signing_alg_values_supported": "ES256",
        "id_token_signing_alg_values_supported": config.id_token_alg,
    }
    for name, value in required.items():
        if not isinstance(document.get(name), list) or value not in document[name]:
            raise SocaError("provider_capability")
    subjects = document.get("subject_types_supported")
    if not isinstance(subjects, list) or not any(x in ("public", "pairwise") for x in subjects):
        raise SocaError("provider_subjects")
    if (
        "client_id_metadata_document_supported" in document
        and document["client_id_metadata_document_supported"] is not True
    ):
        raise SocaError("cimd_unsupported")
    if (
        "authorization_response_iss_parameter_supported" in document
        and type(document["authorization_response_iss_parameter_supported"]) is not bool
    ):
        raise SocaError("invalid_issuer_support")
    for name, wanted in {
        "response_modes_supported": ["query"],
        "grant_types_supported": ["authorization_code"],
        "scopes_supported": ["openid", "email", "profile"],
    }.items():
        if name in document and (
            not isinstance(document[name], list) or any(x not in document[name] for x in wanted)
        ):
            raise SocaError("provider_capability")
    query = parse_qs(urlsplit(document["authorization_endpoint"]).query, keep_blank_values=True)
    if set(query).intersection(
        {
            "client_id",
            "redirect_uri",
            "response_type",
            "response_mode",
            "scope",
            "state",
            "nonce",
            "code_challenge",
            "code_challenge_method",
        }
    ):
        raise SocaError("reserved_authorization_query")
    return document


def authorization_url(config, state, payload):
    endpoint = payload["discovery"]["authorization_endpoint"]
    params = {
        "response_type": "code",
        "response_mode": "query",
        "client_id": config.client_id,
        "redirect_uri": config.url("callback"),
        "scope": "openid email profile",
        "state": state,
        "nonce": payload["nonce"],
        "code_challenge": b64(hashlib.sha256(payload["verifier"].encode()).digest()),
        "code_challenge_method": "S256",
    }
    return endpoint + ("&" if "?" in endpoint else "?") + urlencode(params)


def assertion(config, discovery):
    now = int(time.time())
    audience = (
        config.issuer if config.assertion_audience == "issuer" else discovery["token_endpoint"]
    )
    return jwt.encode(
        {
            "iss": config.client_id,
            "sub": config.client_id,
            "aud": audience,
            "iat": now,
            "exp": now + 60,
            "jti": secrets.token_urlsafe(32),
        },
        config.private_key,
        algorithm="ES256",
        headers={"kid": config.public_key["kid"]},
    )


def verify_id_token(config, payload, token, *, access_token="", code=""):
    if not isinstance(token, str) or len(token) > 32768:
        raise SocaError("invalid_id_token")
    try:
        header = jwt.get_unverified_header(token)
        if (
            header.get("alg") != config.id_token_alg
            or not isinstance(header.get("kid"), str)
            or not 1 <= len(header["kid"]) <= 200
            or any(x in header for x in ("crit", "jku", "jwk", "x5u", "b64"))
            or header.get("typ", "JWT") != "JWT"
        ):
            raise SocaError("invalid_jwt_header")
        # Fetch fresh keys for each login; there is no stale cache or unknown-kid retry storm.
        keys = http.request_json(payload["discovery"]["jwks_uri"]).get("keys")
        if not isinstance(keys, list) or not 1 <= len(keys) <= 50:
            raise SocaError("invalid_provider_keys")
        matches = [x for x in keys if isinstance(x, dict) and x.get("kid") == header["kid"]]
        if len(matches) != 1:
            raise SocaError("ambiguous_provider_key")
        key = matches[0]
        expected_type = "EC" if config.id_token_alg == "ES256" else "RSA"  # noqa: S105 - algorithm name
        if (
            key.get("kty") != expected_type
            or key.get("alg", config.id_token_alg) != config.id_token_alg
            or key.get("use", "sig") != "sig"
            or (
                "key_ops" in key
                and (not isinstance(key["key_ops"], list) or "verify" not in key["key_ops"])
            )
            or any(x in key for x in ("d", "p", "q", "dp", "dq", "qi", "oth", "k"))
            or (expected_type == "EC" and key.get("crv") != "P-256")
        ):
            raise SocaError("invalid_provider_key")
        public_key = jwt.PyJWK.from_dict(key, algorithm=config.id_token_alg).key
        if expected_type == "RSA" and public_key.key_size < 2048:
            raise SocaError("weak_provider_key")
        claims = jwt.decode(
            token,
            public_key,
            algorithms=[config.id_token_alg],
            issuer=config.issuer,
            audience=config.client_id,
            leeway=60,
            options={"require": ["iss", "sub", "aud", "exp", "iat", "nonce"]},
        )
    except (jwt.PyJWTError, ValueError, TypeError, KeyError, OverflowError) as exc:
        raise SocaError("id_token_validation") from exc
    now = int(time.time())
    for name in ("exp", "iat", "nbf", "auth_time"):
        if name in claims and type(claims[name]) is not int:
            raise SocaError("invalid_claim_time")
    if claims["iat"] < payload["started"] - 60 or not 0 < claims["exp"] - claims["iat"] <= 86400:
        raise SocaError("invalid_token_age")
    if "nbf" in claims and claims["nbf"] >= claims["exp"]:
        raise SocaError("invalid_claim_time")
    if "auth_time" in claims and not 0 < claims["auth_time"] <= min(now, claims["iat"]) + 60:
        raise SocaError("invalid_claim_time")
    if not isinstance(claims["sub"], str) or not re.fullmatch(r"[\x20-\x7e]{1,255}", claims["sub"]):
        raise SocaError("invalid_subject")
    audience = claims["aud"]
    if not isinstance(audience, (str, list)) or not audience:
        raise SocaError("invalid_audience")
    if (isinstance(audience, list) and len(audience) > 1 and "azp" not in claims) or claims.get(
        "azp", config.client_id
    ) != config.client_id:
        raise SocaError("invalid_authorized_party")
    if (
        not isinstance(claims["nonce"], str)
        or not claims["nonce"].isascii()
        or not hmac.compare_digest(claims["nonce"], payload["nonce"])
    ):
        raise SocaError("nonce_mismatch")
    for name, value in (("at_hash", access_token), ("c_hash", code)):
        if name in claims and (
            not isinstance(claims[name], str)
            or not claims[name].isascii()
            or not value
            or not hmac.compare_digest(
                claims[name], b64(hashlib.sha256(value.encode("ascii")).digest()[:16])
            )
        ):
            raise SocaError("token_hash_mismatch")
    return claims


def exchange(config, payload, code, *, inspection=None):
    discovery = payload["discovery"]
    response = http.request_json(
        discovery["token_endpoint"],
        form={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": config.url("callback"),
            "client_id": config.client_id,
            "code_verifier": payload["verifier"],
            "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            "client_assertion": assertion(config, discovery),
        },
    )
    if "error" in response:
        raise SocaError("token_endpoint_error")
    access = response.get("access_token", "")
    if not isinstance(access, str) or not access.isascii():
        raise SocaError("invalid_access_token")
    claims = verify_id_token(
        config, payload, response.get("id_token"), access_token=access, code=code
    )
    if inspection is not None:
        inspection["id_token"] = dict(claims)
    needs_email = "email" not in claims or "email_verified" not in claims
    can_fetch_info = (
        access
        and "userinfo_endpoint" in discovery
        and str(response.get("token_type", "")).lower() == "bearer"
    )
    info = None
    info_status = "unavailable"
    needs_profile = any(
        not profile_text(claims.get(name))
        for name in ("given_name", "family_name", "preferred_username")
    )
    if needs_email and not can_fetch_info:
        raise SocaError("verified_email_required")
    if can_fetch_info and (needs_email or needs_profile or inspection is not None):
        try:
            info = http.request_json(discovery["userinfo_endpoint"], bearer=access)
            if info.get("sub") != claims["sub"]:
                raise SocaError("userinfo_subject_mismatch")
            for name in ("email", "email_verified"):
                if (
                    name in claims
                    and name in info
                    and (type(info[name]) is not type(claims[name]) or info[name] != claims[name])
                ):
                    raise SocaError("userinfo_email_mismatch")
            info_status = "subject matched"
        except SocaError as exc:
            if needs_email:
                raise
            info = None
            info_status = str(exc)
    if needs_email:
        if info is None:
            raise SocaError("verified_email_required")
        for name in ("email", "email_verified"):
            if name not in info:
                raise SocaError("userinfo_email_mismatch")
            claims[name] = info[name]
    if info is not None:
        for name in PROFILE_CLAIMS:
            if not profile_text(claims.get(name)) and profile_text(info.get(name)):
                claims[name] = info[name]
    if inspection is not None:
        inspection["userinfo_status"] = info_status
        if info is not None:
            inspection["userinfo"] = info
    return claims


def resolve_user(config, claims):
    email = claims.get("email")
    if (
        claims.get("email_verified") is not True
        or not isinstance(email, str)
        or not email.isascii()
    ):
        raise SocaError("verified_email_required")
    try:
        validate_email(email)
    except ValidationError as exc:
        raise SocaError("invalid_email") from exc
    email = email.lower()
    domain = email.rsplit("@", 1)[1]
    if email in config.deny_emails or domain in config.deny_domains:
        raise SocaError("admission_denied")
    if email not in config.allow_emails and domain not in config.allow_domains:
        raise SocaError("admission_denied")
    matches = matching_users(email)
    if not matches and config.create_users:
        user = create_user(config, email, claims)
    else:
        user = eligible_user(matches)
    return fill_names(user, claims)
